"""
Local HTTP proxy server.

Intercepts the user's browser traffic and forwards everything through
the Apps Script relay (MITM-decrypts HTTPS locally, forwards requests
as JSON to script.google.com fronted through www.google.com).
"""

import asyncio
import ipaddress
import logging
import re
import socket
import ssl
import time
from urllib.parse import urlparse

try:
    import certifi
except Exception:  # optional dependency fallback
    certifi = None

import contextlib

from constants import (
    CACHE_MAX_MB,
    CACHE_TTL_MAX,
    CACHE_TTL_STATIC_LONG,
    CACHE_TTL_STATIC_MED,
    CLIENT_IDLE_TIMEOUT,
    GOOGLE_DIRECT_ALLOW_EXACT,
    GOOGLE_DIRECT_ALLOW_SUFFIXES,
    GOOGLE_DIRECT_EXACT_EXCLUDE,
    GOOGLE_DIRECT_SUFFIX_EXCLUDE,
    GOOGLE_OWNED_EXACT,
    GOOGLE_OWNED_SUFFIXES,
    LARGE_FILE_EXTS,
    MAX_HEADER_BYTES,
    MAX_REQUEST_BODY_BYTES,
    SNI_REWRITE_SUFFIXES,
    STATIC_EXTS,
    TCP_CONNECT_TIMEOUT,
    TRACE_HOST_SUFFIXES,
    UNCACHEABLE_HEADER_NAMES,
)
from domain_fronter import DomainFronter
from protocol_policy import (
    SOCKS5_CMD_CONNECT,
    SOCKS5_CMD_UDP_ASSOCIATE,
    ProtocolPolicy,
)
from routing_policy import RouteDecision, RouteResult, RoutingPolicy
from worker_ws_transport import WorkerWebSocketTransport

log = logging.getLogger("Proxy")

_X_API_GRAPHQL_RE = re.compile(r"/i/api/graphql/[^/]+/[^?]+\?variables=")
_MAX_AGE_RE = re.compile(r"max-age=(\d+)")
_CONTENT_TYPE_RE = re.compile(r"content-type:\s*([^\r\n]+)")


def _is_ip_literal(host: str) -> bool:
    """True for IPv4/IPv6 literals (strips brackets around IPv6)."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False

async def _run_bidirectional(*coros) -> None:
    """Run tunnel pipes and cancel the peer when either side finishes.

    Waiting for both directions forever is a common source of stale tunnel tasks
    on Windows when one half of a TCP connection closes cleanly.
    """
    tasks = [asyncio.create_task(coro) for coro in coros]
    try:
        _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class ResponseCache:
    """Simple LRU response cache — avoids repeated relay calls."""

    def __init__(self, max_mb: int = 50):
        self._store: dict[str, tuple[bytes, float]] = {}
        self._size = 0
        self._max = max_mb * 1024 * 1024
        self.hits = 0
        self.misses = 0

    def get(self, url: str) -> bytes | None:
        entry = self._store.get(url)
        if not entry:
            self.misses += 1
            return None
        raw, expires = entry
        if time.time() > expires:
            self._size -= len(raw)
            del self._store[url]
            self.misses += 1
            return None
        self.hits += 1
        return raw

    def put(self, url: str, raw_response: bytes, ttl: int = 300):
        size = len(raw_response)
        if size > self._max // 4 or size == 0:
            return
        # Evict oldest to make room
        while self._size + size > self._max and self._store:
            oldest = next(iter(self._store))
            self._size -= len(self._store[oldest][0])
            del self._store[oldest]
        if url in self._store:
            self._size -= len(self._store[url][0])
        self._store[url] = (raw_response, time.time() + ttl)
        self._size += size

    @staticmethod
    def parse_ttl(raw_response: bytes, url: str) -> int:
        """Determine cache TTL from response headers and URL."""
        hdr_end = raw_response.find(b"\r\n\r\n")
        if hdr_end < 0:
            return 0
        hdr = raw_response[:hdr_end].decode(errors="replace").lower()

        # Don't cache errors or non-200
        if b"HTTP/1.1 200" not in raw_response[:20]:
            return 0
        if "no-store" in hdr or "private" in hdr or "set-cookie:" in hdr:
            return 0

        # Explicit max-age
        m = _MAX_AGE_RE.search(hdr)
        if m:
            return min(int(m.group(1)), CACHE_TTL_MAX)

        # Heuristic by content type / extension
        path = url.split("?")[0].lower()
        if path.endswith(STATIC_EXTS):
            return CACHE_TTL_STATIC_LONG

        ct_m = _CONTENT_TYPE_RE.search(hdr)
        ct = ct_m.group(1) if ct_m else ""
        if "image/" in ct or "font/" in ct:
            return CACHE_TTL_STATIC_LONG
        if "text/css" in ct or "javascript" in ct:
            return CACHE_TTL_STATIC_MED
        if "text/html" in ct:
            return 0

        return 0


class ProxyServer:
    # Pulled from constants.py so users can override any subset via config.
    _GOOGLE_DIRECT_EXACT_EXCLUDE  = GOOGLE_DIRECT_EXACT_EXCLUDE
    _GOOGLE_DIRECT_SUFFIX_EXCLUDE = GOOGLE_DIRECT_SUFFIX_EXCLUDE
    _GOOGLE_DIRECT_ALLOW_EXACT    = GOOGLE_DIRECT_ALLOW_EXACT
    _GOOGLE_DIRECT_ALLOW_SUFFIXES = GOOGLE_DIRECT_ALLOW_SUFFIXES
    _TRACE_HOST_SUFFIXES          = TRACE_HOST_SUFFIXES
    _DOWNLOAD_DEFAULT_EXTS        = tuple(sorted(LARGE_FILE_EXTS))
    _DOWNLOAD_ACCEPT_MARKERS      = (
        "application/octet-stream",
        "application/zip",
        "application/x-bittorrent",
        "video/",
        "audio/",
    )

    def __init__(self, config: dict):
        self.host = config.get("listen_host", "127.0.0.1")
        self.port = config.get("listen_port", 8080)
        self.socks_enabled = config.get("socks5_enabled", True)
        self.socks_host = config.get("socks5_host", self.host)
        self.socks_port = config.get("socks5_port", 1080)
        if self.socks_enabled and self.socks_host == self.host \
                and int(self.socks_port) == int(self.port):
            raise ValueError(
                f"listen_port and socks5_port must differ on the same host "
                f"(both set to {self.port} on {self.host}). "
                f"Change one of them in config.json."
            )
        self.fronter = DomainFronter(config)
        self.protocol_policy = ProtocolPolicy(config)
        self.mitm = None
        self.worker_ws_transport = (
            WorkerWebSocketTransport(config)
            if self.protocol_policy.worker_websocket_tcp_enabled
            else None
        )
        self._cache = ResponseCache(max_mb=CACHE_MAX_MB)
        self._servers: list[asyncio.base_events.Server] = []
        self._client_tasks: set[asyncio.Task] = set()
        self._tcp_connect_timeout = self._cfg_float(
            config, "tcp_connect_timeout", TCP_CONNECT_TIMEOUT, minimum=1.0,
        )
        self._download_min_size = self._cfg_int(
            config, "chunked_download_min_size", 5 * 1024 * 1024, minimum=0,
        )
        self._download_chunk_size = self._cfg_int(
            config, "chunked_download_chunk_size", 512 * 1024, minimum=64 * 1024,
        )
        self._download_max_parallel = self._cfg_int(
            config, "chunked_download_max_parallel", 8, minimum=1,
        )
        self._download_max_chunks = self._cfg_int(
            config, "chunked_download_max_chunks", 256, minimum=1,
        )
        self._download_extensions, self._download_any_extension = (
            self._normalize_download_extensions(
                config.get(
                    "chunked_download_extensions",
                    list(self._DOWNLOAD_DEFAULT_EXTS),
                )
            )
        )
        self._privacy_log_mode = str(
            config.get("privacy_log_mode", "host")
        ).strip().lower()
        if self._privacy_log_mode not in {"host", "full", "off"}:
            self._privacy_log_mode = "host"
        self._relay_on_geoip_lookup_failure = bool(
            config.get("relay_on_geoip_lookup_failure", False)
        )
        self._geoip_resolve_timeout = self._cfg_float(
            config, "geoip_resolve_timeout", 2.0, minimum=0.2,
        )
        self._routing_cache_ttl = self._cfg_float(
            config, "routing_cache_ttl", 300.0, minimum=1.0,
        )
        self._routing_cache: dict[tuple[str, int, str, str, bool], tuple[float, RouteResult]] = {}
        self._routing_cache_max = 4096

        # hosts override — DNS fake-map: domain/suffix → IP
        # Checked before any real DNS lookup; supports exact and suffix matching.
        self._hosts: dict[str, str] = config.get("hosts", {})
        configured_direct_exclude = config.get("direct_google_exclude", [])
        self._direct_google_exclude = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_EXACT_EXCLUDE) +
                list(configured_direct_exclude)
            )
        }
        configured_direct_allow = config.get("direct_google_allow", [])
        self._direct_google_allow = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_ALLOW_EXACT) +
                list(configured_direct_allow)
            )
        }

        # ── Per-host policy ────────────────────────────────────────
        # block_hosts  — refuse traffic entirely (close or 403)
        # bypass_hosts — route directly (no MITM, no relay)
        # Both accept exact hostnames and leading-dot suffix patterns,
        # e.g. ".local" matches any *.local domain.
        self._block_hosts  = self._load_host_rules(config.get("block_hosts", []))
        self._bypass_hosts = self._load_host_rules(config.get("bypass_hosts", []))

        # Route YouTube through the relay when requested; the Google frontend
        # IP can enforce SafeSearch on the SNI-rewrite path.
        if config.get("youtube_via_relay", False):
            self._SNI_REWRITE_SUFFIXES = tuple(
                s for s in SNI_REWRITE_SUFFIXES
                if s not in self._YOUTUBE_SNI_SUFFIXES
            )
            log.info("youtube_via_relay enabled — YouTube routed through relay")
        else:
            self._SNI_REWRITE_SUFFIXES = SNI_REWRITE_SUFFIXES
        self.routing_policy = RoutingPolicy(
            config,
            google_owned_exact=GOOGLE_OWNED_EXACT,
            google_owned_suffixes=GOOGLE_OWNED_SUFFIXES,
            google_allow_exact=self._direct_google_allow,
            google_allow_suffixes=self._GOOGLE_DIRECT_ALLOW_SUFFIXES,
            google_exclude_exact=self._direct_google_exclude,
            google_exclude_suffixes=self._GOOGLE_DIRECT_SUFFIX_EXCLUDE,
            sni_rewrite_suffixes=self._SNI_REWRITE_SUFFIXES,
        )
        if self.routing_policy.geoip_warning:
            log.warning("Routing GeoIP warning: %s", self.routing_policy.geoip_warning)

        try:
            from mitm import MITMCertManager
            self.mitm = MITMCertManager()
        except ImportError as exc:
            log.error("Apps Script relay requires the 'cryptography' package.")
            log.error("Run: pip install cryptography")
            raise SystemExit(1) from exc

        if self.protocol_policy.udp_mode != "disabled":
            log.warning(
                "UDP mode is set to %s, but no UDP carrier is wired yet; "
                "SOCKS5 UDP is fail-closed to prevent leaks.",
                self.protocol_policy.udp_mode,
            )
        if self.protocol_policy.quic_mode == "block":
            log.info("QUIC/UDP policy: block unless an encapsulated carrier is implemented")
        if self.protocol_policy.tcp_relay_mode in {
            "worker_websocket",
            "worker_ws",
            "websocket",
        }:
            log.warning(
                "tcp_relay_mode=%s is ignored in google-relay-only mode; "
                "raw TCP remains fail-closed.",
                self.protocol_policy.tcp_relay_mode,
            )

    # ── Host-policy helpers ───────────────────────────────────────

    @staticmethod
    def _cfg_int(config: dict, key: str, default: int, *, minimum: int = 1) -> int:
        try:
            value = int(config.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(minimum, value)

    @staticmethod
    def _cfg_float(config: dict, key: str, default: float,
                   *, minimum: float = 0.1) -> float:
        try:
            value = float(config.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(minimum, value)

    @classmethod
    def _normalize_download_extensions(cls, raw) -> tuple[tuple[str, ...], bool]:
        values = raw if isinstance(raw, (list, tuple)) else cls._DOWNLOAD_DEFAULT_EXTS
        normalized: list[str] = []
        any_extension = False
        seen: set[str] = set()
        for item in values:
            ext = str(item).strip().lower()
            if not ext:
                continue
            if ext in {"*", ".*"}:
                any_extension = True
                continue
            if not ext.startswith("."):
                ext = "." + ext
            if ext not in seen:
                seen.add(ext)
                normalized.append(ext)
        if not normalized and not any_extension:
            normalized = list(cls._DOWNLOAD_DEFAULT_EXTS)
        return tuple(normalized), any_extension

    def _track_current_task(self) -> asyncio.Task | None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        return task

    def _untrack_task(self, task: asyncio.Task | None) -> None:
        if task is not None:
            self._client_tasks.discard(task)

    @staticmethod
    def _load_host_rules(raw) -> tuple[set[str], tuple[str, ...]]:
        """Accept a list of host strings; return (exact_set, suffix_tuple).

        A rule starting with '.' (e.g. ".internal") is a suffix rule.
        Everything else is treated as an exact match. Case-insensitive.
        """
        exact: set[str] = set()
        suffixes: list[str] = []
        for item in raw or []:
            h = str(item).strip().lower().rstrip(".")
            if not h:
                continue
            if h.startswith("."):
                suffixes.append(h)
            else:
                exact.add(h)
        return exact, tuple(suffixes)

    @staticmethod
    def _host_matches_rules(host: str,
                            rules: tuple[set[str], tuple[str, ...]]) -> bool:
        exact, suffixes = rules
        h = host.lower().rstrip(".")
        if h in exact:
            return True
        return any(h.endswith(s) for s in suffixes)

    def _is_blocked(self, host: str) -> bool:
        return self._host_matches_rules(host, self._block_hosts)

    def _is_bypassed(self, host: str) -> bool:
        return self._host_matches_rules(host, self._bypass_hosts)

    @staticmethod
    def _header_value(headers: dict | None, name: str) -> str:
        if not headers:
            return ""
        name_lower = name.lower()
        return next((str(v) for k, v in headers.items() if k.lower() == name_lower), "")

    def _log_url(self, url: str) -> str:
        if self._privacy_log_mode == "off":
            return "-"
        if self._privacy_log_mode == "full":
            return url
        parsed = urlparse(url if "://" in url else f"http://{url}")
        if not parsed.hostname:
            return "-"
        if parsed.port:
            return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
        return f"{parsed.scheme}://{parsed.hostname}"

    @staticmethod
    def _url_host_port_scheme(url: str, headers: dict | None = None,
                              lowered: dict[str, str] | None = None) -> tuple[str, int, str]:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        scheme = parsed.scheme or "http"
        host = parsed.hostname or ""
        if not host:
            host_header = ""
            if lowered:
                host_header = lowered.get("host", "")
            elif headers:
                for key, value in headers.items():
                    if key.lower() == "host":
                        host_header = str(value)
                        break
            host = host_header.rsplit(":", 1)[0] if host_header else ""
        port = parsed.port or (443 if scheme == "https" else 80)
        return host.lower().rstrip("."), port, scheme

    async def _route_for_host(
        self,
        host: str,
        port: int,
        *,
        scheme: str,
        protocol: str = "tcp",
        is_websocket: bool = False,
        resolve_geo: bool = True,
    ) -> RouteResult:
        key = (host.lower().rstrip("."), int(port), scheme, protocol, is_websocket)
        now = time.time()
        cached = self._routing_cache.get(key)
        if cached and cached[0] > now:
            return cached[1]

        result = self.routing_policy.decide_host(
            host,
            port,
            scheme=scheme,
            protocol=protocol,
            is_websocket=is_websocket,
        )
        if (
            resolve_geo
            and result.decision == RouteDecision.RELAY_REQUIRED
            and self.routing_policy.iran_geoip_enabled
            and self.routing_policy.iran_networks
            and not _is_ip_literal(host)
            and not self.routing_policy.is_google_owned(host)
        ):
            try:
                ips = await self._resolve_host_ips(host, port)
            except Exception as exc:
                if not self._relay_on_geoip_lookup_failure:
                    result = RouteResult(
                        RouteDecision.FAIL_CLOSED_COMPAT,
                        "geoip dns lookup failed",
                    )
                    log.warning(
                        "Route decision %s for %s:%d (%s)",
                        result.decision.value, host, port, result.reason,
                    )
                else:
                    log.debug("GeoIP lookup failed for %s:%d: %s", host, port, exc)
            else:
                if any(self.routing_policy.is_iran_destination(ip) for ip in ips):
                    result = RouteResult(RouteDecision.IR_DIRECT, "iran geoip destination")

        if len(self._routing_cache) > self._routing_cache_max:
            expired = [k for k, (exp, _) in self._routing_cache.items() if exp <= now]
            for k in expired:
                self._routing_cache.pop(k, None)
            if len(self._routing_cache) > self._routing_cache_max:
                oldest = next(iter(self._routing_cache))
                self._routing_cache.pop(oldest, None)
        self._routing_cache[key] = (now + self._routing_cache_ttl, result)
        return result

    async def _resolve_host_ips(self, host: str, port: int) -> list[str]:
        lookup_target = host.strip("[]")
        if _is_ip_literal(lookup_target):
            return [lookup_target]
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(self._geoip_resolve_timeout):
            infos = await loop.getaddrinfo(
                lookup_target,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        ips: list[str] = []
        seen: set[str] = set()
        for _family, _type, _proto, _canon, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips

    def _cache_allowed(self, method: str, url: str,
                       headers: dict | None, body: bytes,
                       lowered: dict[str, str] | None = None) -> bool:
        if method != "GET" or body:
            return False
        if lowered:
            for name in UNCACHEABLE_HEADER_NAMES:
                if lowered.get(name):
                    return False
        else:
            for name in UNCACHEABLE_HEADER_NAMES:
                if self._header_value(headers, name):
                    return False
        return self.fronter._is_static_asset_url(url)

    @classmethod
    def _should_trace_host(cls, host: str) -> bool:
        h = host.lower().rstrip(".")
        return any(
            token == h or token in h or h.endswith("." + token)
            for token in cls._TRACE_HOST_SUFFIXES
        )

    def _log_response_summary(self, url: str, response: bytes):
        status, headers, body = self.fronter._split_raw_response(response)
        host = (urlparse(url).hostname or "").lower()

        if status >= 300 or self._should_trace_host(host):
            server = headers.get("server", "") or "-"
            cf_ray = headers.get("cf-ray", "") or "-"
            content_type = headers.get("content-type", "") or "-"
            body_len = len(body)

            body_hint = "-"
            rate_limited = False

            # Handle text-like responses (HTML, plain text, JSON…)
            if ("text" in content_type.lower() or "json" in content_type.lower()) and body:
                sample = body[:1200].decode(errors="replace").lower()

                # --- Structured HTML title extraction ---
                if "<title>" in sample and "</title>" in sample:
                    title = sample.split("<title>", 1)[1].split("</title>", 1)[0]
                    body_hint = title.strip()[:120] or "-"

                # --- Known content patterns ---
                elif "captcha" in sample:
                    body_hint = "captcha"
                elif "turnstile" in sample:
                    body_hint = "turnstile"
                elif "loading" in sample:
                    body_hint = "loading"

                # --- Rate-limit / quota markers ---
                rate_limit_markers = (
                    "too many",
                    "rate limit",
                    "quota",
                    "quota exceeded",
                    "request limit",
                    "دفعات زیاد",
                    "بیش از حد",
                    "سرویس در طول یک روز",
                )

                if any(m in sample for m in rate_limit_markers):
                    rate_limited = True
                    body_hint = "quota_exceeded"

            log_msg = "RESP <- %s status=%s type=%s len=%s server=%s hint=%s"
            log_args = (
                host or self._log_url(url),
                status,
                content_type,
                body_len,
                server,
                body_hint if cf_ray == "-" else f"{body_hint} cf-ray",
            )

            if rate_limited:
                log.warning("RATE LIMIT detected! " + log_msg, *log_args)
            else:
                log.info(log_msg, *log_args)

    async def start(self):
        # Detect and handle port conflicts with automatic fallback
        http_srv = None
        socks_srv = None
        original_port = self.port
        original_socks_port = self.socks_port
        
        # Try to start HTTP server with port auto-detection
        max_port_attempts = 10
        for attempt in range(max_port_attempts):
            try:
                http_srv = await asyncio.start_server(self._on_client, self.host, self.port)
                break
            except OSError as e:
                if e.errno == 98 or e.errno == 10048:  # Address already in use
                    if attempt < max_port_attempts - 1:
                        self.port = int(self.port) + 1
                        log.warning(
                            "Port %d is busy, trying port %d (attempt %d/%d)...",
                            original_port if attempt == 0 else self.port - 1,
                            self.port,
                            attempt + 1,
                            max_port_attempts
                        )
                    else:
                        log.error("Could not find an available port after %d attempts", max_port_attempts)
                        raise
                else:
                    raise
        
        if self.socks_enabled:
            for attempt in range(max_port_attempts):
                try:
                    socks_srv = await asyncio.start_server(
                        self._on_socks_client, self.socks_host, self.socks_port
                    )
                    break
                except OSError as e:
                    if e.errno == 98 or e.errno == 10048:
                        if attempt < max_port_attempts - 1:
                            self.socks_port = int(self.socks_port) + 1
                            log.warning(
                                "SOCKS5 port %d is busy, trying port %d (attempt %d/%d)...",
                                original_socks_port if attempt == 0 else self.socks_port - 1,
                                self.socks_port,
                                attempt + 1,
                                max_port_attempts
                            )
                        else:
                            log.error("Could not find an available SOCKS5 port after %d attempts", max_port_attempts)
                            if http_srv:
                                http_srv.close()
                                await http_srv.wait_closed()
                            raise
                    else:
                        raise
        
        self._servers = [s for s in (http_srv, socks_srv) if s]

        # Report actual ports if they changed from config
        if self.port != original_port:
            log.info("HTTP proxy port changed from %d to %d due to conflict", original_port, self.port)
        if self.socks_enabled and self.socks_port != original_socks_port:
            log.info("SOCKS5 proxy port changed from %d to %d due to conflict", original_socks_port, self.socks_port)

        log.info(
            "HTTP proxy listening on %s:%d",
            self.host, self.port,
        )
        if socks_srv:
            log.info(
                "SOCKS5 proxy listening on %s:%d",
                self.socks_host, self.socks_port,
            )

        try:
            async with http_srv:
                if socks_srv:
                    async with socks_srv:
                        await asyncio.gather(
                            http_srv.serve_forever(),
                            socks_srv.serve_forever(),
                        )
                else:
                    await http_srv.serve_forever()
        except asyncio.CancelledError:
            raise

    async def stop(self):
        """Shut down all listeners and release relay resources."""
        for srv in self._servers:
            with contextlib.suppress(Exception):
                srv.close()
        for srv in self._servers:
            with contextlib.suppress(Exception):
                await srv.wait_closed()
        self._servers = []

        current = asyncio.current_task()
        client_tasks = [task for task in self._client_tasks if task is not current]
        for task in client_tasks:
            task.cancel()
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)
        self._client_tasks.clear()

        try:
            await self.fronter.close()
        except Exception as exc:
            log.debug("fronter.close: %s", exc)

    # ── client handler ────────────────────────────────────────────

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        task = self._track_current_task()
        try:
            async with asyncio.timeout(30):
                first_line = await reader.readline()
            if not first_line:
                return

            # Read remaining headers
            header_parts = [first_line]
            total_hdr_len = len(first_line)
            while True:
                async with asyncio.timeout(10):
                    line = await reader.readline()
                header_parts.append(line)
                total_hdr_len += len(line)
                if total_hdr_len > MAX_HEADER_BYTES:
                    log.warning("Request header block exceeds cap — closing")
                    return
                if line in (b"\r\n", b"\n", b""):
                    break
            header_block = b"".join(header_parts)

            for raw_line in header_parts[1:]:
                name, sep, value = raw_line.partition(b":")
                if sep and name.strip().lower() == b"transfer-encoding":
                    encodings = [
                        t.strip().lower()
                        for t in value.decode(errors="replace").split(",")
                        if t.strip()
                    ]
                    if any(t != "identity" for t in encodings):
                        log.warning("Unsupported Transfer-Encoding on client request")
                        writer.write(
                            b"HTTP/1.1 501 Not Implemented\r\n"
                            b"Connection: close\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                        return
                    break

            request_line = first_line.decode(errors="replace").strip()
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                writer.write(
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

            method = parts[0].upper()

            if method == "CONNECT":
                await self._do_connect(parts[1], reader, writer)
            else:
                await self._do_http(header_block, reader, writer)

        except asyncio.CancelledError:
            pass
        except TimeoutError:
            log.debug("Timeout: %s", addr)
        except Exception as e:
            log.error("Error (%s): %s", addr, e)
        finally:
            self._untrack_task(task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _on_socks_client(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        task = self._track_current_task()
        try:
            async with asyncio.timeout(15):
                header = await reader.readexactly(2)
            ver, nmethods = header[0], header[1]
            if ver != 5:
                return

            async with asyncio.timeout(10):
                methods = await reader.readexactly(nmethods)
            if 0x00 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return

            writer.write(b"\x05\x00")
            await writer.drain()

            async with asyncio.timeout(15):
                req = await reader.readexactly(4)
            ver, cmd, _rsv, atyp = req
            if ver != 5:
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            decision = self.protocol_policy.socks_command_decision(cmd)
            if cmd == SOCKS5_CMD_UDP_ASSOCIATE:
                log.warning("SOCKS5 UDP ASSOCIATE refused: %s", decision.reason)
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            if cmd != SOCKS5_CMD_CONNECT:
                log.warning("SOCKS5 command %d refused: %s", cmd, decision.reason)
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            if atyp == 0x01:
                async with asyncio.timeout(10):
                    raw = await reader.readexactly(4)
                host = socket.inet_ntoa(raw)
            elif atyp == 0x03:
                async with asyncio.timeout(10):
                    ln = (await reader.readexactly(1))[0]
                async with asyncio.timeout(10):
                    host_raw = await reader.readexactly(ln)
                host = host_raw.decode(errors="replace")
            elif atyp == 0x04:
                async with asyncio.timeout(10):
                    raw = await reader.readexactly(16)
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            async with asyncio.timeout(10):
                port_raw = await reader.readexactly(2)
            port = int.from_bytes(port_raw, "big")

            reject_reason = self._tunnel_reject_reason(host, port)
            if reject_reason:
                log.warning("SOCKS5 CONNECT refused → %s:%d (%s)", host, port, reject_reason)
                writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            log.info("SOCKS5 CONNECT → %s:%d", host, port)

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await self._handle_target_tunnel(host, port, reader, writer)

        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            pass
        except TimeoutError:
            log.debug("SOCKS5 timeout: %s", addr)
        except Exception as e:
            log.error("SOCKS5 error (%s): %s", addr, e)
        finally:
            self._untrack_task(task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── CONNECT (HTTPS tunnelling) ────────────────────────────────

    async def _do_connect(self, target: str, reader, writer):
        host, _, port_str = target.rpartition(":")
        try:
            port = int(port_str) if port_str else 443
        except ValueError:
            log.warning("CONNECT invalid target: %r", target)
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return
        if not host:
            host, port = target, 443

        reject_reason = self._tunnel_reject_reason(host, port)
        if reject_reason:
            log.warning("CONNECT refused → %s:%d (%s)", host, port, reject_reason)
            body = f"Tunnel refused: {reject_reason}\n".encode()
            writer.write(
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Connection: close\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            )
            await writer.drain()
            return

        log.info("CONNECT → %s:%d", host, port)

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        await self._handle_target_tunnel(host, port, reader, writer)

    def _tunnel_reject_reason(self, host: str, port: int) -> str | None:
        """Return a fail-closed reason before acknowledging CONNECT/SOCKS."""
        if self._is_blocked(host):
            return "matches block_hosts"
        if self._is_bypassed(host):
            return None
        decision = self.protocol_policy.tcp_decision(host, port)
        if port in (80, 443) or decision.allow_direct or decision.allow_relay:
            return None
        return decision.reason

    async def _handle_target_tunnel(self, host: str, port: int,
                                    reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter):
        """Route a target connection through the Apps Script relay."""
        # ── Block / bypass policy ─────────────────────────────────
        if self._is_blocked(host):
            log.warning("BLOCKED → %s:%d (matches block_hosts)", host, port)
            try:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            return

        if self._is_bypassed(host):
            log.info("Bypass tunnel → %s:%d (matches bypass_hosts)", host, port)
            await self._do_direct_tunnel(host, port, reader, writer)
            return

        scheme = "https" if port == 443 else "http"
        route = await self._route_for_host(host, port, scheme=scheme)
        log.info(
            "Route %s -> %s:%d (%s)",
            route.decision.value, host, port, route.reason,
        )

        if route.decision == RouteDecision.IR_DIRECT:
            await self._do_direct_tunnel(host, port, reader, writer)
            return

        if route.decision == RouteDecision.GOOGLE_FRONTED_DIRECT:
            override_ip = self._sni_rewrite_ip(host)
            if override_ip:
                log.info(
                    "Google fronted tunnel -> %s via %s (SNI: %s)",
                    host, override_ip, self.fronter.sni_host,
                )
                await self._do_sni_rewrite_tunnel(
                    host, port, reader, writer, connect_ip=override_ip,
                )
            else:
                await self._do_direct_tunnel(host, port, reader, writer)
            return

        if route.decision == RouteDecision.RELAY_REQUIRED:
            if route.reason == "tcp relay via worker websocket":
                if await self._do_worker_ws_tcp_tunnel(host, port, reader, writer):
                    return
            if _is_ip_literal(host) and self.worker_ws_transport and self.worker_ws_transport.enabled:
                log.info("IP literal -> TCP tunnel -> %s:%d", host, port)
                if await self._do_worker_ws_tcp_tunnel(host, port, reader, writer):
                    return
            if port == 443:
                await self._do_mitm_connect(host, port, reader, writer)
            elif port == 80:
                await self._do_plain_http_tunnel(host, port, reader, writer)
            return

        log.warning(
            "Blocked compatible fallback -> %s:%d (%s)",
            host, port, route.reason,
        )

    async def _do_worker_ws_tcp_tunnel(self, host: str, port: int,
                                       reader: asyncio.StreamReader,
                                       writer: asyncio.StreamWriter) -> bool:
        if self.worker_ws_transport and self.worker_ws_transport.enabled:
            log.info("Worker WebSocket TCP tunnel -> %s:%d", host, port)
            ok = await self.worker_ws_transport.tunnel(host, port, reader, writer)
            if not ok:
                log.warning("Worker WebSocket TCP tunnel failed for %s:%d", host, port)
            return ok
        return False

    # ── Hosts override (fake DNS) ─────────────────────────────────

    # Built-in list of domains that must be reached via Google's frontend IP
    # with SNI rewritten to `front_domain` (default: www.google.com).
    # Source: constants.SNI_REWRITE_SUFFIXES.
    # When youtube_via_relay is enabled the YouTube suffixes are removed so
    # YouTube goes through the Apps Script relay instead.
    _YOUTUBE_SNI_SUFFIXES = frozenset({
        "youtube.com", "youtu.be", "youtube-nocookie.com",
    })
    _SNI_REWRITE_SUFFIXES = SNI_REWRITE_SUFFIXES

    def _sni_rewrite_ip(self, host: str) -> str | None:
        """Return the IP to SNI-rewrite `host` through, or None.

        Order of precedence:
          1. Explicit entry in config `hosts` map (exact or suffix match).
          2. Built-in `_SNI_REWRITE_SUFFIXES` → mapped to config `google_ip`.
        """
        ip = self._hosts_ip(host)
        if ip:
            return ip
        h = host.lower().rstrip(".")
        for suffix in self._SNI_REWRITE_SUFFIXES:
            if h == suffix or h.endswith("." + suffix):
                return self.fronter.connect_host  # configured google_ip
        return None

    def _hosts_ip(self, host: str) -> str | None:
        """Return override IP for host if defined in config 'hosts', else None.

        Supports exact match and suffix match (e.g. 'youtube.com' matches
        'www.youtube.com', 'm.youtube.com', etc.).
        """
        h = host.lower().rstrip(".")
        if h in self._hosts:
            return self._hosts[h]
        # suffix match: check every parent label
        parts = h.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._hosts:
                return self._hosts[parent]
        return None

    # ── Google domain detection ───────────────────────────────────

    # Google-owned domains that may use the raw direct-tunnel shortcut.
    # YouTube/googlevideo SNIs are blocked; they go through
    # _do_sni_rewrite_tunnel via the hosts map instead.
    # Source: constants.GOOGLE_OWNED_SUFFIXES / GOOGLE_OWNED_EXACT.

    async def _open_tcp_connection(self, target: str, port: int,
                                   timeout: float = 10.0):
        """Connect with IPv4-first resolution and clearer failure reporting."""
        errors: list[str] = []
        loop = asyncio.get_running_loop()

        # Strip IPv6 brackets (CONNECT may deliver "[::1]" as the hostname).
        # ipaddress.ip_address() rejects the bracketed form, which would
        # otherwise force a DNS lookup for an IP literal and fail.
        lookup_target = target.strip()
        if lookup_target.startswith("[") and lookup_target.endswith("]"):
            lookup_target = lookup_target[1:-1]

        try:
            ipaddress.ip_address(lookup_target)
            candidates = [(0, lookup_target)]
        except ValueError:
            try:
                async with asyncio.timeout(timeout):
                    infos = await loop.getaddrinfo(
                        lookup_target,
                        port,
                        family=socket.AF_UNSPEC,
                        type=socket.SOCK_STREAM,
                    )
            except Exception as exc:
                raise OSError(f"dns lookup failed for {lookup_target}: {exc!r}") from exc

            candidates = []
            seen = set()
            for family, _type, _proto, _canon, sockaddr in infos:
                ip = sockaddr[0]
                key = (family, ip)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((family, ip))

            candidates.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)

        for family, ip in candidates:
            try:
                async with asyncio.timeout(timeout):
                    return await asyncio.open_connection(ip, port, family=family or 0)
            except Exception as exc:
                fam = "ipv4" if family == socket.AF_INET else (
                    "ipv6" if family == socket.AF_INET6 else "auto"
                )
                errors.append(f"{ip} ({fam}): {exc!r}")

        raise OSError("; ".join(errors) or f"connect failed for {target}:{port}")

    # ── Direct tunnel (no MITM) ───────────────────────────────────

    async def _do_direct_tunnel(self, host: str, port: int,
                                reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter,
                                connect_ip: str | None = None,
                                timeout: float | None = None):
        """Pipe raw TLS bytes directly to the target server.

        connect_ip overrides DNS: the TCP connection goes to that IP
        while the browser's TLS (SNI=host) is piped through unchanged.
        Without an override we connect to the real hostname so browser-safe
        Google properties (Gemini assets, Play, Accounts, etc.) use their
        normal edge instead of being forced onto the fronting IP.
        """
        target_ip = connect_ip or host
        effective_timeout = (
            self._tcp_connect_timeout if timeout is None else float(timeout)
        )
        try:
            r_remote, w_remote = await self._open_tcp_connection(
                target_ip, port, timeout=effective_timeout,
            )
        except Exception as e:
            log.error("Direct tunnel connect failed (%s via %s): %s",
                      host, target_ip, e)
            return False

        async def pipe(src, dst, label):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as e:
                log.debug("Pipe %s ended: %s", label, e)
            finally:
                # Half-close rather than hard-close so the other direction
                # can still flush final bytes (important for TLS close_notify).
                try:
                    if not dst.is_closing() and dst.can_write_eof():
                        dst.write_eof()
                except Exception:
                    with contextlib.suppress(Exception):
                        dst.close()

        await _run_bidirectional(
            pipe(reader, w_remote, f"client→{host}"),
            pipe(r_remote, writer, f"{host}→client"),
        )
        return True

    # ── SNI-rewrite tunnel ────────────────────────────────────────

    async def _do_sni_rewrite_tunnel(self, host: str, port: int, reader, writer,
                                     connect_ip: str | None = None):
        """MITM-decrypt TLS from browser, then re-encrypt toward connect_ip
        using SNI=front_domain (e.g. www.google.com).

        The ISP only ever sees SNI=www.google.com in the outgoing handshake,
        hiding the blocked hostname (e.g. www.youtube.com).
        """
        target_ip = connect_ip or self.fronter.connect_host
        sni_out   = self.fronter.sni_host  # e.g. "www.google.com"

        # Step 1: MITM — accept TLS from the browser
        ssl_ctx_server = self.mitm.get_server_context(host)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol  = transport.get_protocol()
        try:
            new_transport = await loop.start_tls(
                transport, protocol, ssl_ctx_server, server_side=True,
            )
        except Exception as e:
            log.debug("SNI-rewrite TLS accept failed (%s): %s", host, e)
            return
        writer._transport = new_transport

        # Step 2: open outgoing TLS to target IP with the safe SNI
        ssl_ctx_client = ssl.create_default_context()
        if certifi is not None:
            with contextlib.suppress(Exception):
                ssl_ctx_client.load_verify_locations(cafile=certifi.where())
        if not self.fronter.verify_ssl:
            ssl_ctx_client.check_hostname = False
            ssl_ctx_client.verify_mode = ssl.CERT_NONE
        try:
            async with asyncio.timeout(self._tcp_connect_timeout):
                r_out, w_out = await asyncio.open_connection(
                    target_ip, port,
                    ssl=ssl_ctx_client,
                    server_hostname=sni_out,
                )
        except Exception as e:
            log.error("SNI-rewrite outbound connect failed (%s via %s): %s",
                      host, target_ip, e)
            return

        async def pipe(src, dst, label):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as exc:
                log.debug("Pipe %s ended: %s", label, exc)
            finally:
                try:
                    if not dst.is_closing() and dst.can_write_eof():
                        dst.write_eof()
                except Exception:
                    with contextlib.suppress(Exception):
                        dst.close()

        await _run_bidirectional(
            pipe(reader, w_out, f"client→{host}"),
            pipe(r_out, writer, f"{host}→client"),
        )

    async def _direct_http_request(
        self,
        method: str,
        url: str,
        headers: dict,
        body: bytes,
    ) -> bytes:
        """Send a single HTTP(S) request directly, avoiding relay quota."""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return self._compat_error_response(501, "direct HTTP(S) only")
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if scheme == "https":
            reader, writer = await self._open_direct_https_request_connection(
                parsed.hostname, port,
            )
        else:
            reader, writer = await self._open_tcp_connection(
                parsed.hostname, port, timeout=self._tcp_connect_timeout,
            )
        try:
            skip = {
                "connection",
                "proxy-connection",
                "proxy-authorization",
                "keep-alive",
                "transfer-encoding",
                "content-length",
            }
            lines = [
                f"{method.upper()} {path} HTTP/1.1",
                f"Host: {parsed.netloc}",
            ]
            for key, value in headers.items():
                kl = key.lower()
                if kl not in skip and kl != "host":
                    lines.append(f"{key}: {value}")
            lines.append("Connection: close")
            if body:
                lines.append(f"Content-Length: {len(body)}")
            request = "\r\n".join(lines) + "\r\n\r\n"
            writer.write(request.encode() + body)
            await writer.drain()

            chunks: list[bytes] = []
            total = 0
            cap = self.fronter._max_response_body_bytes
            while True:
                async with asyncio.timeout(30):
                    chunk = await reader.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    return self._compat_error_response(502, "direct response exceeds cap")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _open_direct_https_request_connection(
        self,
        host: str,
        port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        connect_target = self._sni_rewrite_ip(host) or host
        server_hostname = self.fronter.sni_host if connect_target != host else host
        ssl_ctx = ssl.create_default_context()
        if certifi is not None:
            with contextlib.suppress(Exception):
                ssl_ctx.load_verify_locations(cafile=certifi.where())
        if not self.fronter.verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        async with asyncio.timeout(self._tcp_connect_timeout):
            return await asyncio.open_connection(
                connect_target,
                port,
                ssl=ssl_ctx,
                server_hostname=server_hostname,
            )

    @staticmethod
    def _compat_error_response(status: int, message: str) -> bytes:
        reason = {
            403: "Forbidden",
            501: "Not Implemented",
            502: "Bad Gateway",
        }.get(status, "Error")
        body = message.encode()
        return (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Connection: close\r\n"
            "Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
        ).encode() + body

    # ── MITM CONNECT (apps_script mode) ───────────────────────────

    async def _do_plain_http_tunnel(self, host: str, port: int, reader, writer):
        """Handle plain HTTP over SOCKS5 in apps_script mode."""
        log.info("Plain HTTP relay → %s:%d", host, port)
        await self._relay_http_stream(host, port, reader, writer)

    async def _do_mitm_connect(self, host: str, port: int, reader, writer):
        """Intercept TLS, decrypt HTTP, and relay through Apps Script."""
        ssl_ctx = self.mitm.get_server_context(host)

        # Upgrade the existing connection to TLS (we are the server)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()

        try:
            new_transport = await loop.start_tls(
                transport, protocol, ssl_ctx, server_side=True,
            )
        except Exception as e:
            # TLS handshake failed. Common causes:
            #   • Telegram Desktop / MTProto over port 443 sends obfuscated
            #     non-TLS bytes — we literally cannot decrypt these, and
            #     since the target IP is blocked we can't direct-tunnel
            #     either. Telegram will rotate to another DC on its own;
            #     failing fast here lets that happen sooner.
            #   • Client CONNECTs but never speaks TLS (some probes).
            if _is_ip_literal(host) and port == 443:
                log.info(
                    "Non-TLS traffic on %s:%d (likely Telegram MTProto / "
                    "obfuscated protocol). This DC appears blocked; the "
                    "client should rotate to another endpoint shortly.",
                    host, port,
                )
            elif port != 443:
                log.debug(
                    "TLS handshake skipped for %s:%d (non-HTTPS): %s",
                    host, port, e,
                )
            else:
                log.debug("TLS handshake failed for %s: %s", host, e)
            # Close the client side so it fails fast and can retry, rather
            # than hanging on a half-open connection.
            try:
                if not writer.is_closing():
                    writer.close()
            except Exception:
                pass
            return

        # Update writer to use the new TLS transport
        writer._transport = new_transport

        await self._relay_http_stream(host, port, reader, writer)

    async def _relay_http_stream(self, host: str, port: int, reader, writer):
        """Read decrypted/origin-form HTTP requests and relay them."""
        # Read and relay HTTP requests from the browser (now decrypted)
        while True:
            try:
                async with asyncio.timeout(CLIENT_IDLE_TIMEOUT):
                    first_line = await reader.readline()
                if not first_line:
                    break

                header_parts = [first_line]
                total_hdr_len = len(first_line)
                oversized_headers = False
                while True:
                    async with asyncio.timeout(10):
                        line = await reader.readline()
                    header_parts.append(line)
                    total_hdr_len += len(line)
                    if total_hdr_len > MAX_HEADER_BYTES:
                        oversized_headers = True
                        break
                    if line in (b"\r\n", b"\n", b""):
                        break
                header_block = b"".join(header_parts)

                # Reject truncated / oversized header blocks cleanly rather
                # than forwarding a half-parsed request to the relay — doing
                # so would send malformed JSON payloads to Apps Script and
                # leave the client hanging until its own timeout fires.
                if oversized_headers:
                    log.warning(
                        "MITM header block exceeds %d bytes — closing (%s)",
                        MAX_HEADER_BYTES, host,
                    )
                    try:
                        writer.write(
                            b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                            b"Connection: close\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                    except Exception:
                        pass
                    break

                header_lines = header_block.split(b"\r\n")

                body = b""
                length = 0
                has_bad_te = False
                headers = {}
                lowered_headers: dict[str, str] = {}
                for raw_line in header_lines[1:]:
                    name, sep, value = raw_line.partition(b":")
                    if not sep:
                        continue
                    lname = name.strip().lower()
                    if lname == b"content-length":
                        try:
                            length = int(value.strip())
                        except ValueError:
                            pass
                    elif lname == b"transfer-encoding":
                        encodings = [
                            t.strip().lower()
                            for t in value.decode(errors="replace").split(",")
                            if t.strip()
                        ]
                        if any(t != "identity" for t in encodings):
                            has_bad_te = True
                    ks = name.decode(errors="replace").strip()
                    vs = value.decode(errors="replace").strip()
                    headers[ks] = vs
                    lowered_headers[lname.decode(errors="replace")] = vs

                if has_bad_te:
                    log.warning("Unsupported Transfer-Encoding → %s:%d", host, port)
                    writer.write(
                        b"HTTP/1.1 501 Not Implemented\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    break
                if length > MAX_REQUEST_BODY_BYTES:
                    raise ValueError(f"Request body too large: {length} bytes")
                if length > 0:
                    body = await reader.readexactly(length)

                request_line = header_lines[0].decode(errors="replace").strip()
                parts = request_line.split(" ", 2)
                if len(parts) < 2:
                    writer.write(
                        b"HTTP/1.1 400 Bad Request\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    break

                method = parts[0].upper()
                path = parts[1]

                if (host.endswith("x.com") or host.endswith("twitter.com")) and \
                   _X_API_GRAPHQL_RE.match(path):
                    path = path.split("&")[0]

                # MITM traffic arrives as origin-form paths; SOCKS/plain HTTP can
                # also send absolute-form requests. Normalize both to full URLs.
                if path.startswith("http://") or path.startswith("https://"):
                    url = path
                elif port == 443:
                    url = f"https://{host}{path}"
                elif port == 80:
                    url = f"http://{host}{path}"
                else:
                    url = f"http://{host}:{port}{path}"

                log_url = self._log_url(url)
                log.info("MITM -> %s %s", method, log_url)

                # ── CORS: extract relevant request headers ─────────────
                origin = lowered_headers.get("origin", "")
                acr_method = lowered_headers.get("access-control-request-method", "")
                acr_headers = lowered_headers.get("access-control-request-headers", "")

                # CORS preflight — respond directly. Apps Script's
                # UrlFetchApp does not support the OPTIONS method, so
                # forwarding preflights would always fail and break every
                # cross-origin fetch/XHR the browser runs through us.
                if method == "OPTIONS" and acr_method:
                    log.debug(
                        "CORS preflight -> %s (responding locally)",
                        log_url,
                    )
                    writer.write(self._cors_preflight_response(
                        origin, acr_method, acr_headers,
                    ))
                    await writer.drain()
                    continue

                request_host, request_port, request_scheme = self._url_host_port_scheme(
                    url, headers, lowered_headers,
                )
                is_ws = (
                    lowered_headers.get("upgrade", "") == "websocket"
                    or "websocket" in lowered_headers.get("connection", "")
                )
                route = await self._route_for_host(
                    request_host or host,
                    request_port,
                    scheme=request_scheme,
                    is_websocket=is_ws,
                )
                if route.decision == RouteDecision.FAIL_CLOSED_COMPAT:
                    log.warning(
                        "Route %s -> %s (%s)",
                        route.decision.value,
                        request_host or host,
                        route.reason,
                    )
                    writer.write(self._compat_error_response(501, route.reason))
                    await writer.drain()
                    continue
                if route.decision in {
                    RouteDecision.IR_DIRECT,
                    RouteDecision.GOOGLE_FRONTED_DIRECT,
                }:
                    try:
                        response = await self._direct_http_request(method, url, headers, body)
                    except Exception as e:
                        log.error("Direct request failed (%s): %s", log_url, e)
                        response = self._compat_error_response(502, f"Direct failed: {e}")
                    writer.write(response)
                    await writer.drain()
                    continue
                try:
                    if await self._maybe_stream_download(method, url, headers, body, writer, lowered_headers):
                        continue
                except Exception as e:
                    log.error("Stream download failed (%s): %s", log_url, e)
                    response = self._compat_error_response(502, f"Stream failed: {e}")
                    writer.write(response)
                    await writer.drain()
                    continue

                cacheable = self._cache_allowed(method, url, headers, body, lowered_headers)
                response = None
                if cacheable:
                    response = self._cache.get(url)
                    if response:
                        log.debug("Cache HIT: %s", log_url)

                if response is None:
                    try:
                        response = await self._relay_smart(method, url, headers, body, lowered_headers)
                    except Exception as e:
                        log.error("Relay error (%s): %s", log_url, e)
                        err_body = f"Relay error: {e}".encode()
                        response = (
                            b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Content-Length: " + str(len(err_body)).encode() + b"\r\n"
                            b"\r\n" + err_body
                        )

                    if cacheable and response:
                        ttl = ResponseCache.parse_ttl(response, url)
                        if ttl > 0:
                            self._cache.put(url, response, ttl)
                            log.debug("Cached (%ds): %s", ttl, log_url)

                # Inject permissive CORS headers whenever the browser sent
                # an Origin (cross-origin XHR / fetch). Without this, the
                # browser blocks the response even though the relay fetched
                # it successfully.
                if origin and response:
                    response = self._inject_cors_headers(response, origin)

                self._log_response_summary(url, response)

                writer.write(response)
                await writer.drain()

            except TimeoutError:
                break
            except asyncio.IncompleteReadError:
                break
            except ConnectionError:
                break
            except Exception as e:
                log.error("MITM handler error (%s): %s", host, e)
                break

    # ── CORS helpers ──────────────────────────────────────────────

    @staticmethod
    def _cors_preflight_response(origin: str, acr_method: str,
                                 acr_headers: str) -> bytes:
        """Build a 204 response that satisfies a CORS preflight locally.

        Apps Script's UrlFetchApp does not support OPTIONS, so we have to
        answer preflights here instead of forwarding them.
        """
        allow_origin = origin or "*"
        allow_methods = (
            f"{acr_method}, GET, POST, PUT, DELETE, PATCH, OPTIONS"
            if acr_method else
            "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        )
        allow_headers = acr_headers or "*"
        lines = [
            "HTTP/1.1 204 No Content",
            f"Access-Control-Allow-Origin: {allow_origin}",
            f"Access-Control-Allow-Methods: {allow_methods}",
            f"Access-Control-Allow-Headers: {allow_headers}",
        ]
        if origin:
            lines.append("Access-Control-Allow-Credentials: true")
        lines += [
            "Access-Control-Max-Age: 86400",
            "Vary: Origin",
            "Content-Length: 0",
            "",
            "",
        ]
        return "\r\n".join(lines).encode()

    @staticmethod
    def _inject_cors_headers(response: bytes, origin: str) -> bytes:
        """Strip existing Access-Control-* headers and add permissive ones.

        Keeps the body untouched; only rewrites the header block. Using
        the exact browser-supplied Origin (rather than "*") is required
        when the request is credentialed (cookies, Authorization).
        """
        sep = b"\r\n\r\n"
        if sep not in response:
            return response
        header_section, body = response.split(sep, 1)
        lines = header_section.decode(errors="replace").split("\r\n")
        lines = [ln for ln in lines
                 if not ln.lower().startswith("access-control-")]
        allow_origin = origin or "*"
        lines += [
            f"Access-Control-Allow-Origin: {allow_origin}",
            "Access-Control-Allow-Credentials: true",
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS",
            "Access-Control-Allow-Headers: *",
            "Access-Control-Expose-Headers: *",
            "Vary: Origin",
        ]
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

    async def _relay_smart(self, method, url, headers, body,
                           lowered: dict[str, str] | None = None):
        """Choose optimal relay strategy based on request type."""
        if method == "GET" and not body:
            if lowered and "range" in lowered:
                return await self.fronter.relay(
                    method, url, headers, body
                )
            if not lowered and headers:
                for k in headers:
                    if k.lower() == "range":
                        return await self.fronter.relay(
                            method, url, headers, body
                        )
            if self._is_likely_download(url, headers, lowered):
                return await self.fronter.relay_parallel(
                    method,
                    url,
                    headers,
                    body,
                    chunk_size=self._download_chunk_size,
                    max_parallel=self._download_max_parallel,
                    max_chunks=self._download_max_chunks,
                    min_size=self._download_min_size,
                )
        return await self.fronter.relay(method, url, headers, body)

    def _is_likely_download(self, url: str, headers: dict,
                            lowered: dict[str, str] | None = None) -> bool:
        path = url.split("?")[0].lower()
        if self._download_any_extension:
            return True
        if path.endswith(self._download_extensions):
            return True
        accept = (lowered or {}).get("accept", "") if lowered else self._header_value(headers, "accept").lower()
        return bool(any(marker in accept for marker in self._DOWNLOAD_ACCEPT_MARKERS))

    async def _maybe_stream_download(self, method: str, url: str,
                                     headers: dict | None, body: bytes,
                                     writer,
                                     lowered: dict[str, str] | None = None) -> bool:
        if method != "GET" or body:
            return False
        if lowered:
            if "range" in lowered:
                return False
        elif headers:
            for key in headers:
                if key.lower() == "range":
                    return False
        effective_headers = headers or {}
        if not self._is_likely_download(url, effective_headers, lowered):
            return False
        if not self.fronter.stream_download_allowed(url):
            return False
        return await self.fronter.stream_parallel_download(
            url,
            effective_headers,
            writer,
            chunk_size=self._download_chunk_size,
            max_parallel=self._download_max_parallel,
            max_chunks=self._download_max_chunks,
            min_size=self._download_min_size,
        )

    # ── Plain HTTP forwarding ─────────────────────────────────────

    async def _do_http(self, header_block: bytes, reader, writer):
        header_lines = header_block.split(b"\r\n")

        body = b""
        length = 0
        has_bad_te = False
        headers = {}
        lowered_headers: dict[str, str] = {}
        for raw_line in header_lines[1:]:
            name, sep, value = raw_line.partition(b":")
            if not sep:
                continue
            lname = name.strip().lower()
            if lname == b"content-length":
                try:
                    length = int(value.strip())
                except ValueError:
                    pass
            elif lname == b"transfer-encoding":
                encodings = [
                    t.strip().lower()
                    for t in value.decode(errors="replace").split(",")
                    if t.strip()
                ]
                if any(t != "identity" for t in encodings):
                    has_bad_te = True
            ks = name.decode(errors="replace").strip()
            vs = value.decode(errors="replace").strip()
            headers[ks] = vs
            lowered_headers[lname.decode(errors="replace")] = vs

        if has_bad_te:
            log.warning("Unsupported Transfer-Encoding on plain HTTP request")
            writer.write(
                b"HTTP/1.1 501 Not Implemented\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return
        if length > MAX_REQUEST_BODY_BYTES:
            writer.write(
                b"HTTP/1.1 413 Content Too Large\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return
        if length > 0:
            body = await reader.readexactly(length)

        first_line = header_lines[0].decode(errors="replace")
        parts = first_line.strip().split(" ", 2)
        method = parts[0].upper() if parts else "GET"
        url = parts[1] if len(parts) > 1 else "/"

        log_target = url
        if not (url.startswith("http://") or url.startswith("https://")):
            host = lowered_headers.get("host", "")
            if host:
                log_target = f"http://{host}{url}"
        log_url = self._log_url(log_target)
        log.info("HTTP -> %s %s", method, log_url)

        # ── CORS preflight over plain HTTP ─────────────────────────────
        origin = lowered_headers.get("origin", "")
        acr_method = lowered_headers.get("access-control-request-method", "")
        acr_headers = lowered_headers.get("access-control-request-headers", "")
        if method == "OPTIONS" and acr_method:
            log.debug(
                "CORS preflight (HTTP) -> %s (responding locally)",
                log_url,
            )
            writer.write(self._cors_preflight_response(
                origin, acr_method, acr_headers,
            ))
            await writer.drain()
            return

        request_host, request_port, request_scheme = self._url_host_port_scheme(
            log_target, headers, lowered_headers,
        )
        is_ws = (
            lowered_headers.get("upgrade", "") == "websocket"
            or "websocket" in lowered_headers.get("connection", "")
        )
        route = await self._route_for_host(
            request_host,
            request_port,
            scheme=request_scheme,
            is_websocket=is_ws,
        )
        log.info(
            "Route %s -> %s:%d (%s)",
            route.decision.value,
            request_host or "-",
            request_port,
            route.reason,
        )
        if route.decision == RouteDecision.FAIL_CLOSED_COMPAT:
            writer.write(self._compat_error_response(501, route.reason))
            await writer.drain()
            return
        if route.decision in {
            RouteDecision.IR_DIRECT,
            RouteDecision.GOOGLE_FRONTED_DIRECT,
        }:
            try:
                response = await self._direct_http_request(method, log_target, headers, body)
            except Exception as e:
                log.error("Direct request failed (%s): %s", log_url, e)
                response = self._compat_error_response(502, f"Direct failed: {e}")
            writer.write(response)
            await writer.drain()
            return

        try:
            if await self._maybe_stream_download(method, log_target, headers, body, writer, lowered_headers):
                return
        except Exception as e:
            log.error("Stream download failed (%s): %s", log_url, e)
            writer.write(self._compat_error_response(502, f"Stream failed: {e}"))
            await writer.drain()
            return

        cacheable = self._cache_allowed(method, log_target, headers, body, lowered_headers)
        response = None
        if cacheable:
            response = self._cache.get(log_target)
            if response:
                log.debug("Cache HIT (HTTP): %s", log_url)

        if response is None:
            try:
                response = await self._relay_smart(method, log_target, headers, body, lowered_headers)
            except Exception as e:
                log.error("Relay error (%s): %s", log_url, e)
                err_body = f"Relay error: {e}".encode()
                response = (
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(err_body)).encode() + b"\r\n"
                    b"\r\n" + err_body
                )
            if cacheable and response:
                ttl = ResponseCache.parse_ttl(response, log_target)
                if ttl > 0:
                    self._cache.put(log_target, response, ttl)
        if origin and response:
            response = self._inject_cors_headers(response, origin)

        self._log_response_summary(log_target, response)

        writer.write(response)
        await writer.drain()
