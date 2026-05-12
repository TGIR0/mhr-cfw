"""
Local HTTP proxy server with MITM interception, CORS rewrites,
direct‑tunnel shortcuts, and smart relay‑vs‑stream download selection.

All browser traffic is forwarded through the Apps Script relay or
directly piped when safe (Google properties, local bypass rules, etc.).
"""

import asyncio
import json
import logging
import os
import re
import socket
import ssl
import time
import ipaddress
from urllib.parse import urlparse

try:
    import certifi
except ImportError:
    certifi = None

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

# ماژول‌های جدید
try:
    from doh_fronted import resolve as doh_resolve, init as doh_init
    HAS_DO = True
except ImportError:
    HAS_DO = False

try:
    from tachyon_relay import HybridRelay
    HAS_TACHYON = True
except ImportError:
    HAS_TACHYON = False

log = logging.getLogger("Proxy")

_EXCLUDE_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "exclude_cache.json"
)

# ---------------------------------------------------------------------------
# Tiny helpers
# ---------------------------------------------------------------------------
def _is_ip_literal(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False

def _parse_content_length(header_block: bytes) -> int:
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep:
            continue
        if name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0

def _has_unsupported_transfer_encoding(header_block: bytes) -> bool:
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep:
            continue
        if name.strip().lower() != b"transfer-encoding":
            continue
        encodings = [
            token.strip().lower()
            for token in value.decode(errors="replace").split(",")
            if token.strip()
        ]
        return any(token != "identity" for token in encodings)
    return False

# ---------------------------------------------------------------------------
# Simple LRU response cache
# ---------------------------------------------------------------------------
class ResponseCache:
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
        hdr_end = raw_response.find(b"\r\n\r\n")
        if hdr_end < 0:
            return 0
        hdr = raw_response[:hdr_end].decode(errors="replace").lower()
        if b"HTTP/1.1 200" not in raw_response[:20]:
            return 0
        if "no-store" in hdr or "private" in hdr or "set-cookie:" in hdr:
            return 0
        m = re.search(r"max-age=(\d+)", hdr)
        if m:
            return min(int(m.group(1)), CACHE_TTL_MAX)
        path = url.split("?")[0].lower()
        for ext in STATIC_EXTS:
            if path.endswith(ext):
                return CACHE_TTL_STATIC_LONG
        ct_m = re.search(r"content-type:\s*([^\r\n]+)", hdr)
        ct = ct_m.group(1) if ct_m else ""
        if "image/" in ct or "font/" in ct:
            return CACHE_TTL_STATIC_LONG
        if "text/css" in ct or "javascript" in ct:
            return CACHE_TTL_STATIC_MED
        if "text/html" in ct or "application/json" in ct:
            return 0
        return 0

# ---------------------------------------------------------------------------
# Main proxy server
# ---------------------------------------------------------------------------
class ProxyServer:
    _GOOGLE_DIRECT_EXACT_EXCLUDE = GOOGLE_DIRECT_EXACT_EXCLUDE
    _GOOGLE_DIRECT_SUFFIX_EXCLUDE = GOOGLE_DIRECT_SUFFIX_EXCLUDE
    _GOOGLE_DIRECT_ALLOW_EXACT = GOOGLE_DIRECT_ALLOW_EXACT
    _GOOGLE_DIRECT_ALLOW_SUFFIXES = GOOGLE_DIRECT_ALLOW_SUFFIXES
    _TRACE_HOST_SUFFIXES = TRACE_HOST_SUFFIXES
    _DOWNLOAD_DEFAULT_EXTS = tuple(sorted(LARGE_FILE_EXTS))
    _DOWNLOAD_ACCEPT_MARKERS = (
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

        from smart_router import CloudflareDetector, DependencyResolver
        self._cf_detector = CloudflareDetector()
        self._dependency_resolver = DependencyResolver
        self._direct_fail_until: dict[str, float] = {}
        self._servers: list[asyncio.base_events.Server] = []
        self._client_tasks: set[asyncio.Task] = set()

        self._tcp_connect_timeout = self._cfg_float(
            config, "tcp_connect_timeout", TCP_CONNECT_TIMEOUT, minimum=1.0
        )
        self._download_min_size = self._cfg_int(
            config, "chunked_download_min_size", 5 * 1024 * 1024, minimum=0
        )
        self._download_chunk_size = self._cfg_int(
            config, "chunked_download_chunk_size", 512 * 1024, minimum=64 * 1024
        )
        self._download_max_parallel = self._cfg_int(
            config, "chunked_download_max_parallel", 8, minimum=1
        )
        self._download_max_chunks = self._cfg_int(
            config, "chunked_download_max_chunks", 256, minimum=1
        )
        self._download_extensions, self._download_any_extension = (
            self._normalize_download_extensions(
                config.get(
                    "chunked_download_extensions",
                    list(self._DOWNLOAD_DEFAULT_EXTS),
                )
            )
        )
        self._hosts: dict[str, str] = config.get("hosts", {})

        configured_direct_exclude = config.get("direct_google_exclude", [])
        self._direct_google_exclude = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_EXACT_EXCLUDE)
                + list(configured_direct_exclude)
            )
        }
        self._load_exclude_cache()

        configured_direct_allow = config.get("direct_google_allow", [])
        self._direct_google_allow = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_ALLOW_EXACT)
                + list(configured_direct_allow)
            )
        }
        self._block_hosts = self._load_host_rules(config.get("block_hosts", []))
        self._bypass_hosts = self._load_host_rules(config.get("bypass_hosts", []))

        if config.get("youtube_via_relay", False):
            self._SNI_REWRITE_SUFFIXES = tuple(
                s for s in SNI_REWRITE_SUFFIXES if s not in self._YOUTUBE_SNI_SUFFIXES
            )
        else:
            self._SNI_REWRITE_SUFFIXES = SNI_REWRITE_SUFFIXES

        try:
            from mitm import MITMCertManager
            self.mitm = MITMCertManager()
        except ImportError:
            log.error("Apps Script relay requires the 'cryptography' package.")
            log.error("Run: pip install cryptography")
            raise SystemExit(1)

        # ═══ انتخاب موتور رله ═══
        worker_host = config.get("worker_host")
        if config.get("mode") == "websocket" and worker_host:
            if HAS_TACHYON:
                self.fronter = HybridRelay(config)
                log.info("Relay: Tachyon (KCP-ready, fallback JSON-RPC)")
            else:
                log.warning("tachyon_relay not found, fallback to Apps Script")
                self.fronter = DomainFronter(config)
        else:
            self.fronter = DomainFronter(config)
            log.info("Relay: Apps Script (quota-based)")

        self._cache = ResponseCache(CACHE_MAX_MB)

        # ═══ راه‌اندازی DoH Fronted ═══
        if HAS_DO:
            doh_init(
                google_ip=config.get("google_ip", "216.239.38.120"),
                sni=config.get("front_domain", "www.google.com"),
                proxy_addr="127.0.0.1",
                proxy_port=config.get("socks5_port", 1080),
            )
            log.info("DoH Fronted فعال شد (بدون نیاز به DNS خارجی)")

            # ⚡ Prefetch DNS برای دامنه‌های پرکاربرد
            try:
                from domain_map import DOMAIN_DEPENDENCIES
                all_domains = list(DOMAIN_DEPENDENCIES.keys())
                asyncio.create_task(self._prefetch_dns(all_domains))
            except Exception as e:
                log.debug("DNS prefetch skipped: %s", e)

    # ── کش Exclude ─────────────────────────────────────────────
    def _load_exclude_cache(self):
        try:
            if os.path.exists(_EXCLUDE_CACHE_FILE):
                with open(_EXCLUDE_CACHE_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for host in data:
                        self._direct_google_exclude.add(
                            str(host).strip().lower().rstrip(".")
                        )
                log.debug("Loaded %d excluded domains", len(data))
        except Exception as e:
            log.warning("Exclude cache: %s", e)

    def _save_exclude_cache(self):
        try:
            with open(_EXCLUDE_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(list(self._direct_google_exclude), f, indent=2)
        except Exception as e:
            log.warning("Save exclude cache: %s", e)

    def _add_excluded_host(self, host: str):
        self._direct_google_exclude.add(host)
        self._save_exclude_cache()

    # ── helpers ────────────────────────────────────────────────
    @staticmethod
    def _cfg_int(config: dict, key: str, default: int, *, minimum: int = 1) -> int:
        try:
            return max(minimum, int(config.get(key, default)))
        except (TypeError, ValueError):
            return max(minimum, default)

    @staticmethod
    def _cfg_float(
        config: dict, key: str, default: float, *, minimum: float = 0.1
    ) -> float:
        try:
            return max(minimum, float(config.get(key, default)))
        except (TypeError, ValueError):
            return max(minimum, default)

    @classmethod
    def _normalize_download_extensions(cls, raw) -> tuple[tuple[str, ...], bool]:
        values = (
            raw if isinstance(raw, (list, tuple)) else cls._DOWNLOAD_DEFAULT_EXTS
        )
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

    # ── task tracking ──────────────────────────────────────────
    def _track_current_task(self) -> asyncio.Task | None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        return task

    def _untrack_task(self, task: asyncio.Task | None) -> None:
        if task is not None:
            self._client_tasks.discard(task)

    # ── host policy rules ──────────────────────────────────────────
    @staticmethod
    def _load_host_rules(raw) -> tuple[set[str], tuple[str, ...]]:
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
    def _host_matches_rules(
        host: str, rules: tuple[set[str], tuple[str, ...]]
    ) -> bool:
        exact, suffixes = rules
        h = host.lower().rstrip(".")
        if h in exact:
            return True
        return any(h.endswith(s) for s in suffixes)

    def _is_blocked(self, host: str) -> bool:
        return self._host_matches_rules(host, self._block_hosts)

    def _is_bypassed(self, host: str) -> bool:
        return self._host_matches_rules(host, self._bypass_hosts)

    # ── header helpers ─────────────────────────────────────────────
    @staticmethod
    def _header_value(headers: dict | None, name: str) -> str:
        if not headers:
            return ""
        for key, value in headers.items():
            if key.lower() == name:
                return str(value)
        return ""

    def _cache_allowed(
        self, method: str, url: str, headers: dict | None, body: bytes
    ) -> bool:
        if method.upper() != "GET" or body:
            return False
        for name in UNCACHEABLE_HEADER_NAMES:
            if self._header_value(headers, name):
                return False
        return self.fronter._is_static_asset_url(url)

    # ── response tracing ───────────────────────────────────────────
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
        if status < 300 and not self._should_trace_host(host):
            return
        location = headers.get("location", "") or "-"
        server = headers.get("server", "") or "-"
        cf_ray = headers.get("cf-ray", "") or "-"
        content_type = headers.get("content-type", "") or "-"
        body_len = len(body)
        body_hint = "-"
        rate_limited = False
        if ("text" in content_type.lower() or "json" in content_type.lower()) and body:
            sample = body[:1200].decode(errors="replace").lower()
            if "<title>" in sample and "</title>" in sample:
                body_hint = (
                    sample.split("<title>", 1)[1].split("</title>", 1)[0].strip()[:120]
                    or "-"
                )
            elif "captcha" in sample:
                body_hint = "captcha"
            elif "turnstile" in sample:
                body_hint = "turnstile"
            elif "loading" in sample:
                body_hint = "loading"
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
        log_msg = (
            "RESP ← %s status=%s type=%s len=%s server=%s location=%s cf-ray=%s hint=%s"
        )
        log_args = (
            host or url[:60],
            status,
            content_type,
            body_len,
            server,
            location,
            cf_ray,
            body_hint,
        )
        if status in (403, 502, 503) and host:
            if self._cf_detector.is_behind_cloudflare(host, headers):
                if self._cf_detector.is_blocked_by_cf(status, body_hint):
                    self._add_excluded_host(host)
                    for dep in self._dependency_resolver.get_dependencies(host):
                        self._add_excluded_host(dep)
                    log.info("SmartRouter: %s و وابستگی‌هایش به relay منتقل شدند", host)
        if rate_limited:
            log.warning("RATE LIMIT! " + log_msg, *log_args)
        else:
            log.info(log_msg, *log_args)

    # ── start / stop ──────────────────────────────────────────────
    async def start(self):
        http_srv = await asyncio.start_server(self._on_client, self.host, self.port)
        socks_srv = None
        if self.socks_enabled:
            try:
                socks_srv = await asyncio.start_server(
                    self._on_socks_client, self.socks_host, self.socks_port
                )
            except OSError as e:
                log.error(
                    "SOCKS5 listener failed on %s:%d: %s",
                    self.socks_host,
                    self.socks_port,
                    e,
                )
        self._servers = [s for s in (http_srv, socks_srv) if s]
        log.info("HTTP proxy listening on %s:%d", self.host, self.port)
        if socks_srv:
            log.info("SOCKS5 proxy listening on %s:%d", self.socks_host, self.socks_port)
        try:
            async with http_srv:
                if socks_srv:
                    async with socks_srv:
                        await asyncio.gather(
                            http_srv.serve_forever(), socks_srv.serve_forever()
                        )
                else:
                    await http_srv.serve_forever()
        except asyncio.CancelledError:
            raise

    async def stop(self):
        for srv in self._servers:
            try:
                srv.close()
            except Exception:
                pass
        for srv in self._servers:
            try:
                await srv.wait_closed()
            except Exception:
                pass
        self._servers = []
        current = asyncio.current_task()
        client_tasks = [t for t in self._client_tasks if t is not current]
        for t in client_tasks:
            t.cancel()
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)
        self._client_tasks.clear()
        try:
            await self.fronter.close()
        except Exception as exc:
            log.debug("fronter.close: %s", exc)

    # ── Dashboard ────────────────────────────────────────────────
    async def _handle_dashboard(self, writer):
        try:
            stats = self.fronter.stats_snapshot()
            body = json.dumps(
                {
                    "status": "running",
                    "cache_hits": self._cache.hits,
                    "cache_misses": self._cache.misses,
                    "per_site": stats.get("per_site", [])[:10],
                    "blacklisted_scripts": stats.get("blacklisted_scripts", []),
                }
            )
            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode()
            writer.write(response)
            await writer.drain()
        except Exception as e:
            log.error("Dashboard error: %s", e)
            writer.write(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
            await writer.drain()

    # ── HTTP / SOCKS5 client handlers ──────────────────────────────
    async def _on_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        addr = writer.get_extra_info("peername")
        task = self._track_current_task()
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not first_line:
                return
            header_block = first_line
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                header_block += line
                if len(header_block) > MAX_HEADER_BYTES:
                    log.warning("Header block too large – closing")
                    return
                if line in (b"\r\n", b"\n", b""):
                    break
            if _has_unsupported_transfer_encoding(header_block):
                writer.write(
                    b"HTTP/1.1 501 Not Implemented\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return
            request_line = first_line.decode(errors="replace").strip()
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return
            method = parts[0].upper()
            path = parts[1] if len(parts) > 1 else "/"
            if method == "GET" and path == "/dashboard":
                await self._handle_dashboard(writer)
                return
            if method == "CONNECT":
                await self._do_connect(parts[1], reader, writer)
            else:
                await self._do_http(header_block, reader, writer)
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
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

    async def _on_socks_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        addr = writer.get_extra_info("peername")
        task = self._track_current_task()
        try:
            header = await asyncio.wait_for(reader.readexactly(2), timeout=15)
            ver, nmethods = header[0], header[1]
            if ver != 5:
                return
            methods = await asyncio.wait_for(
                reader.readexactly(nmethods), timeout=10
            )
            if 0x00 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()
            req = await asyncio.wait_for(reader.readexactly(4), timeout=15)
            ver, cmd, _rsv, atyp = req
            if ver != 5 or cmd != 0x01:
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            if atyp == 0x01:
                raw = await asyncio.wait_for(reader.readexactly(4), timeout=10)
                host = socket.inet_ntoa(raw)
            elif atyp == 0x03:
                ln = (await asyncio.wait_for(reader.readexactly(1), timeout=10))[0]
                host = (
                    await asyncio.wait_for(reader.readexactly(ln), timeout=10)
                ).decode()
            elif atyp == 0x04:
                raw = await asyncio.wait_for(reader.readexactly(16), timeout=10)
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            port_raw = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            port = int.from_bytes(port_raw, "big")
            log.info("SOCKS5 CONNECT → %s:%d", host, port)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await self._handle_target_tunnel(host, port, reader, writer)
        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
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

    # ── CONNECT / tunneling ──────────────────────────────────────
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
        log.info("CONNECT → %s:%d", host, port)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._handle_target_tunnel(host, port, reader, writer)

    async def _handle_target_tunnel(
        self, host: str, port: int, reader, writer
    ):
        if self._is_blocked(host):
            log.warning("BLOCKED → %s:%d", host, port)
            try:
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
            except Exception:
                pass
            return
        if self._is_bypassed(host):
            log.info("Bypass tunnel → %s:%d", host, port)
            await self._do_direct_tunnel(host, port, reader, writer)
            return
        if _is_ip_literal(host):
            if not self._direct_temporarily_disabled(host):
                log.info("Direct tunnel → %s:%d (IP literal)", host, port)
                if await self._do_direct_tunnel(
                    host, port, reader, writer, timeout=4.0
                ):
                    return
                self._remember_direct_failure(host, ttl=300)
                if port not in (80, 443):
                    log.warning("Direct tunnel failed for %s:%d", host, port)
                    return
                log.warning(
                    "Direct tunnel fallback → %s:%d (switching to relay)",
                    host,
                    port,
                )
            else:
                log.info(
                    "Relay fallback → %s:%d (direct temporarily disabled)",
                    host,
                    port,
                )
            if port == 443:
                await self._do_mitm_connect(host, port, reader, writer)
            elif port == 80:
                await self._do_plain_http_tunnel(host, port, reader, writer)
            return
        override_ip = self._sni_rewrite_ip(host)
        if override_ip:
            log.info(
                "SNI-rewrite tunnel → %s via %s (SNI: %s)",
                host,
                override_ip,
                self.fronter.sni_host,
            )
            await self._do_sni_rewrite_tunnel(
                host, port, reader, writer, connect_ip=override_ip
            )
        elif self._is_google_domain(host):
            if self._direct_temporarily_disabled(host):
                log.info(
                    "Relay fallback → %s (direct tunnel temporarily disabled)",
                    host,
                )
                if port == 443:
                    await self._do_mitm_connect(host, port, reader, writer)
                else:
                    await self._do_plain_http_tunnel(host, port, reader, writer)
                return
            log.info("Direct tunnel → %s (Google domain, skipping relay)", host)
            if await self._do_direct_tunnel(host, port, reader, writer):
                return
            self._remember_direct_failure(host)
            log.warning(
                "Direct tunnel fallback → %s (switching to relay)", host
            )
            if port == 443:
                await self._do_mitm_connect(host, port, reader, writer)
            else:
                await self._do_plain_http_tunnel(host, port, reader, writer)
        elif port == 443:
            await self._do_mitm_connect(host, port, reader, writer)
        elif port == 80:
            await self._do_plain_http_tunnel(host, port, reader, writer)
        else:
            log.info("Direct tunnel → %s:%d (non-HTTP port)", host, port)
            if not await self._do_direct_tunnel(host, port, reader, writer):
                log.warning("Direct tunnel failed for %s:%d", host, port)

    # ── hosts override (fake DNS) ──────────────────────────────
    _YOUTUBE_SNI_SUFFIXES = frozenset(
        {"youtube.com", "youtu.be", "youtube-nocookie.com"}
    )
    _SNI_REWRITE_SUFFIXES = SNI_REWRITE_SUFFIXES

    def _sni_rewrite_ip(self, host: str) -> str | None:
        ip = self._hosts_ip(host)
        if ip:
            return ip
        h = host.lower().rstrip(".")
        for suffix in self._SNI_REWRITE_SUFFIXES:
            if h == suffix or h.endswith("." + suffix):
                return self.fronter.connect_host
        return None

    def _hosts_ip(self, host: str) -> str | None:
        h = host.lower().rstrip(".")
        if h in self._hosts:
            return self._hosts[h]
        parts = h.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._hosts:
                return self._hosts[parent]
        return None

    # ── Google domain detection ─────────────────────────────────
    _GOOGLE_OWNED_SUFFIXES = GOOGLE_OWNED_SUFFIXES
    _GOOGLE_OWNED_EXACT = GOOGLE_OWNED_EXACT

    def _is_google_domain(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        if self._is_direct_google_excluded(h):
            return False
        if not self._is_google_owned_domain(h):
            return False
        return self._is_direct_google_allowed(h)

    def _is_google_owned_domain(self, host: str) -> bool:
        if host in self._GOOGLE_OWNED_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in self._GOOGLE_OWNED_SUFFIXES)

    def _is_direct_google_excluded(self, host: str) -> bool:
        if host in self._direct_google_exclude:
            return True
        for suffix in self._GOOGLE_DIRECT_SUFFIX_EXCLUDE:
            if host.endswith(suffix):
                return True
        for token in self._direct_google_exclude:
            if token.startswith(".") and host.endswith(token):
                return True
        return False

    def _is_direct_google_allowed(self, host: str) -> bool:
        if host in self._direct_google_allow:
            return True
        for suffix in self._GOOGLE_DIRECT_ALLOW_SUFFIXES:
            if host.endswith(suffix):
                return True
        for token in self._direct_google_allow:
            if token.startswith(".") and host.endswith(token):
                return True
        return False

    def _direct_temporarily_disabled(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        now = time.time()
        disabled = False
        for key in self._direct_failure_keys(h):
            until = self._direct_fail_until.get(key, 0)
            if until > now:
                disabled = True
            else:
                self._direct_fail_until.pop(key, None)
        return disabled

    def _remember_direct_failure(self, host: str, ttl: int = 600):
        until = time.time() + ttl
        for key in self._direct_failure_keys(host.lower().rstrip(".")):
            self._direct_fail_until[key] = until

    @staticmethod
    def _direct_failure_keys(host: str) -> tuple[str, ...]:
        keys = [host]
        if host.endswith(".google.com") or host == "google.com":
            keys.append("*.google.com")
        if host.endswith(".googleapis.com") or host == "googleapis.com":
            keys.append("*.googleapis.com")
        if host.endswith(".gstatic.com") or host == "gstatic.com":
            keys.append("*.gstatic.com")
        if (
            host.endswith(".googleusercontent.com")
            or host == "googleusercontent.com"
        ):
            keys.append("*.googleusercontent.com")
        return tuple(dict.fromkeys(keys))

    # ── TCP connection helper (DoH Fronted) ────────────────────────
    async def _open_tcp_connection(self, target: str, port: int, timeout: float = 10.0):
        # اگر IP literal هست، مستقیماً وصل شو
        if _is_ip_literal(target):
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout,
                )
            except Exception as e:
                raise OSError(f"connect failed for {target}:{port}: {e}") from e

        # برای hostname از DoH استفاده کن
        if HAS_DO:
            ips = await doh_resolve(target)
            if ips:
                for ip_addr in ips:
                    try:
                        return await asyncio.wait_for(
                            asyncio.open_connection(ip_addr, port),
                            timeout=timeout,
                        )
                    except Exception:
                        continue

        # Fallback to system DNS
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(target, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
            for family, _, _, _, sockaddr in infos:
                try:
                    return await asyncio.wait_for(
                        asyncio.open_connection(sockaddr[0], port, family=family),
                        timeout=timeout,
                    )
                except Exception:
                    continue
        except Exception as e:
            raise OSError(f"DNS failed for {target}: {e}") from e
        raise OSError(f"connect failed for {target}:{port}")

    # ── Direct tunnel ──────────────────────────────────────────
    async def _do_direct_tunnel(
        self,
        host,
        port,
        reader,
        writer,
        connect_ip: str | None = None,
        timeout: float | None = None,
    ):
        target_ip = connect_ip or host
        effective_timeout = (
            self._tcp_connect_timeout if timeout is None else float(timeout)
        )
        try:
            r_remote, w_remote = await self._open_tcp_connection(
                target_ip, port, timeout=effective_timeout
            )
        except Exception as e:
            log.error(
                "Direct tunnel connect failed (%s via %s): %s",
                host,
                target_ip,
                e,
            )
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
                try:
                    if not dst.is_closing() and dst.can_write_eof():
                        dst.write_eof()
                except Exception:
                    try:
                        dst.close()
                    except Exception:
                        pass

        await asyncio.gather(
            pipe(reader, w_remote, f"client→{host}"),
            pipe(r_remote, writer, f"{host}→client"),
        )
        return True

    # ── SNI-rewrite tunnel ─────────────────────────────────────
    async def _do_sni_rewrite_tunnel(
        self, host, port, reader, writer, connect_ip=None
    ):
        target_ip = connect_ip or self.fronter.connect_host
        sni_out = self.fronter.sni_host
        ssl_ctx_server = self.mitm.get_server_context(host)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        try:
            new_transport = await loop.start_tls(
                transport, protocol, ssl_ctx_server, server_side=True
            )
        except Exception as e:
            log.debug("SNI-rewrite TLS accept failed (%s): %s", host, e)
            return
        writer._transport = new_transport
        ssl_ctx_client = ssl.create_default_context()
        if certifi is not None:
            try:
                ssl_ctx_client.load_verify_locations(cafile=certifi.where())
            except Exception:
                pass
        if not self.fronter.verify_ssl:
            ssl_ctx_client.check_hostname = False
            ssl_ctx_client.verify_mode = ssl.CERT_NONE
        try:
            r_out, w_out = await asyncio.wait_for(
                asyncio.open_connection(
                    target_ip, port, ssl=ssl_ctx_client, server_hostname=sni_out
                ),
                timeout=self._tcp_connect_timeout,
            )
        except Exception as e:
            log.error(
                "SNI-rewrite outbound connect failed (%s via %s): %s",
                host,
                target_ip,
                e,
            )
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
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            pipe(reader, w_out, f"client→{host}"),
            pipe(r_out, writer, f"{host}→client"),
        )

    # ── MITM CONNECT ──────────────────────────────────────────
    async def _do_plain_http_tunnel(self, host, port, reader, writer):
        log.info("Plain HTTP relay → %s:%d", host, port)
        await self._relay_http_stream(host, port, reader, writer)

    async def _do_mitm_connect(self, host, port, reader, writer):
        ssl_ctx = self.mitm.get_server_context(host)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        try:
            new_transport = await loop.start_tls(
                transport, protocol, ssl_ctx, server_side=True
            )
        except Exception as e:
            if _is_ip_literal(host) and port == 443:
                log.info(
                    "Non-TLS traffic on %s:%d (likely MTProto) – forwarding directly",
                    host,
                    port,
                )
                await self._do_direct_tunnel(host, port, reader, writer)
            elif port != 443:
                log.debug(
                    "TLS skipped for %s:%d (non-HTTPS): %s", host, port, e
                )
                await self._do_direct_tunnel(host, port, reader, writer)
            else:
                log.debug("TLS handshake failed for %s: %s", host, e)
            return
        writer._transport = new_transport
        await self._relay_http_stream(host, port, reader, writer)

    async def _relay_http_stream(self, host, port, reader, writer):
        while True:
            try:
                first_line = await asyncio.wait_for(
                    reader.readline(), timeout=CLIENT_IDLE_TIMEOUT
                )
                if not first_line:
                    break
                header_block = first_line
                oversized_headers = False
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=10)
                    header_block += line
                    if len(header_block) > MAX_HEADER_BYTES:
                        oversized_headers = True
                        break
                    if line in (b"\r\n", b"\n", b""):
                        break
                if oversized_headers:
                    log.warning(
                        "MITM header block too large – closing (%s)", host
                    )
                    try:
                        writer.write(
                            b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                            b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                    except Exception:
                        pass
                    break
                body = b""
                if _has_unsupported_transfer_encoding(header_block):
                    writer.write(
                        b"HTTP/1.1 501 Not Implemented\r\n"
                        b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    break
                length = _parse_content_length(header_block)
                if length > MAX_REQUEST_BODY_BYTES:
                    raise ValueError(f"Request body too large: {length} bytes")
                if length > 0:
                    body = await reader.readexactly(length)
                request_line = first_line.decode(errors="replace").strip()
                parts = request_line.split(" ", 2)
                if len(parts) < 2:
                    break
                method = parts[0]
                path_val = parts[1]
                headers = {}
                for raw_line in header_block.split(b"\r\n")[1:]:
                    if b":" in raw_line:
                        k, v = (
                            raw_line.decode(errors="replace").split(":", 1)
                        )
                        headers[k.strip()] = v.strip()
                if host in ("x.com", "twitter.com") and re.match(
                    r"/i/api/graphql/[^/]+/[^?]+\?variables=", path_val
                ):
                    path_val = path_val.split("&")[0]
                if path_val.startswith("http://") or path_val.startswith(
                    "https://"
                ):
                    url = path_val
                elif port == 443:
                    url = f"https://{host}{path_val}"
                elif port == 80:
                    url = f"http://{host}{path_val}"
                else:
                    url = f"http://{host}:{port}{path_val}"
                log.info("MITM → %s %s", method, url)
                origin = self._header_value(headers, "origin")
                acr_method = self._header_value(
                    headers, "access-control-request-method"
                )
                acr_headers = self._header_value(
                    headers, "access-control-request-headers"
                )
                if method.upper() == "OPTIONS" and acr_method:
                    log.debug(
                        "CORS preflight → %s", url[:60]
                    )
                    writer.write(
                        self._cors_preflight_response(
                            origin, acr_method, acr_headers
                        )
                    )
                    await writer.drain()
                    continue

                # Stream download path
                if (
                    method.upper() == "GET"
                    and not body
                    and self._is_likely_download(url, headers)
                    and self.fronter.stream_download_allowed(url)
                ):
                    if await self.fronter.stream_parallel_download(
                        url,
                        headers,
                        writer,
                        chunk_size=self._download_chunk_size,
                        max_parallel=self._download_max_parallel,
                        max_chunks=self._download_max_chunks,
                        min_size=self._download_min_size,
                    ):
                        continue

                response = None
                if self._cache_allowed(method, url, headers, body):
                    response = self._cache.get(url)
                    if response:
                        log.debug("Cache HIT: %s", url[:60])
                if response is None:
                    try:
                        response = await self._relay_smart(
                            method, url, headers, body
                        )
                    except Exception as e:
                        log.error(
                            "Relay error (%s): %s", url[:60], e
                        )
                        err_body = f"Relay error: {e}".encode()
                        response = (
                            b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Content-Type: text/html\r\n"
                            b"Content-Length: "
                            + str(len(err_body)).encode()
                            + b"\r\n\r\n"
                            + err_body
                        )
                    if (
                        self._cache_allowed(method, url, headers, body)
                        and response
                    ):
                        ttl = ResponseCache.parse_ttl(response, url)
                        if ttl > 0:
                            self._cache.put(url, response, ttl)
                            log.debug(
                                "Cached (%ds): %s", ttl, url[:60]
                            )
                if origin and response:
                    response = self._inject_cors_headers(
                        response, origin
                    )
                self._log_response_summary(url, response)
                writer.write(response)
                await writer.drain()
                if (
                    "text/html"
                    in (headers.get("content-type", "").lower() or "")
                    and response
                ):
                    asyncio.create_task(
                        self._predictive_prefetch(response, url)
                    )
            except asyncio.TimeoutError:
                break
            except (ConnectionError, asyncio.IncompleteReadError):
                break
            except Exception as e:
                log.error("MITM handler error (%s): %s", host, e)
                break

    # ── Plain HTTP ────────────────────────────────────────
    async def _do_http(self, header_block: bytes, reader, writer):
        body = b""
        if _has_unsupported_transfer_encoding(header_block):
            writer.write(
                b"HTTP/1.1 501 Not Implemented\r\n"
                b"Connection: close\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return
        length = _parse_content_length(header_block)
        if length > MAX_REQUEST_BODY_BYTES:
            writer.write(b"HTTP/1.1 413 Content Too Large\r\n\r\n")
            await writer.drain()
            return
        if length > 0:
            body = await reader.readexactly(length)
        first_line = header_block.split(b"\r\n")[0].decode(errors="replace")
        log.info("HTTP → %s", first_line)
        parts = first_line.strip().split(" ", 2)
        method = parts[0] if parts else "GET"
        url_str = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for raw_line in header_block.split(b"\r\n")[1:]:
            if b":" in raw_line:
                k, v = raw_line.decode(errors="replace").split(":", 1)
                headers[k.strip()] = v.strip()
        origin = self._header_value(headers, "origin")
        acr_method = self._header_value(
            headers, "access-control-request-method"
        )
        acr_headers = self._header_value(
            headers, "access-control-request-headers"
        )
        if method.upper() == "OPTIONS" and acr_method:
            log.debug("CORS preflight (HTTP) → %s", url_str[:60])
            writer.write(
                self._cors_preflight_response(
                    origin, acr_method, acr_headers
                )
            )
            await writer.drain()
            return
        if (
            method.upper() == "GET"
            and not body
            and self._is_likely_download(url_str, headers)
            and self.fronter.stream_download_allowed(url_str)
        ):
            if await self.fronter.stream_parallel_download(
                url_str,
                headers,
                writer,
                chunk_size=self._download_chunk_size,
                max_parallel=self._download_max_parallel,
                max_chunks=self._download_max_chunks,
                min_size=self._download_min_size,
            ):
                return
        response = None
        if self._cache_allowed(method, url_str, headers, body):
            response = self._cache.get(url_str)
            if response:
                log.debug("Cache HIT (HTTP): %s", url_str[:60])
        if response is None:
            response = await self._relay_smart(
                method, url_str, headers, body
            )
            if (
                self._cache_allowed(method, url_str, headers, body)
                and response
            ):
                ttl = ResponseCache.parse_ttl(response, url_str)
                if ttl > 0:
                    self._cache.put(url_str, response, ttl)
        if origin and response:
            response = self._inject_cors_headers(response, origin)
        self._log_response_summary(url_str, response)
        writer.write(response)
        await writer.drain()

    # ── CORS helpers ─────────────────────────────────────────────
    @staticmethod
    def _cors_preflight_response(
        origin: str, acr_method: str, acr_headers: str
    ) -> bytes:
        allow_origin = origin or "*"
        allow_methods = (
            f"{acr_method}, GET, POST, PUT, DELETE, PATCH, OPTIONS"
            if acr_method
            else "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        )
        allow_headers = acr_headers or "*"
        return (
            f"HTTP/1.1 204 No Content\r\n"
            f"Access-Control-Allow-Origin: {allow_origin}\r\n"
            f"Access-Control-Allow-Methods: {allow_methods}\r\n"
            f"Access-Control-Allow-Headers: {allow_headers}\r\n"
            "Access-Control-Allow-Credentials: true\r\n"
            "Access-Control-Max-Age: 86400\r\n"
            "Vary: Origin\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ).encode()

    @staticmethod
    def _inject_cors_headers(response: bytes, origin: str) -> bytes:
        sep = b"\r\n\r\n"
        if sep not in response:
            return response
        header_section, body = response.split(sep, 1)
        lines = header_section.decode(errors="replace").split("\r\n")
        lines = [
            ln
            for ln in lines
            if not ln.lower().startswith("access-control-")
        ]
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

    # ── Predictive Resource Push ──────────────────────────────────
    async def _predictive_prefetch(self, response: bytes, base_url: str):
        try:
            body = (
                response.split(b"\r\n\r\n", 1)[1]
                if b"\r\n\r\n" in response
                else b""
            )
            text = body.decode(errors="replace").lower()
            resources = set()
            for pat in [
                r'src="(https?://[^"]+)"',
                r'href="(https?://[^"]+)"',
                r"src='(https?://[^']+)'",
                r"href='(https?://[^']+)'",
            ]:
                for match in re.findall(pat, text):
                    if any(
                        match.endswith(ext)
                        for ext in (".css", ".js", ".png", ".jpg", ".woff2")
                    ):
                        resources.add(match)
            for res in list(resources)[:5]:
                asyncio.create_task(
                    self.fronter.relay("GET", res, {}, b"")
                )
                log.debug("Pre-fetch: %s", res[:60])
        except Exception:
            pass

    # ── Smart relay (handles downloads & normal requests) ──────────
    async def _relay_smart(self, method, url, headers, body):
        if method == "GET" and not body:
            if headers and any(
                k.lower() == "range" for k in headers
            ):
                return await self.fronter.relay(
                    method, url, headers, body
                )
            if self._is_likely_download(url, headers):
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

    def _is_likely_download(self, url: str, headers: dict) -> bool:
        path = url.split("?")[0].lower()
        if self._download_any_extension:
            return True
        for ext in self._download_extensions:
            if path.endswith(ext):
                return True
        accept = self._header_value(headers, "accept").lower()
        return any(
            marker in accept for marker in self._DOWNLOAD_ACCEPT_MARKERS
        )

    # ── DNS Prefetch (DoH) ─────────────────────────────────────
    async def _prefetch_dns(self, domains: list[str]):
        """پیش‌واکشی DNS برای دامنه‌های پرکاربرد در پس‌زمینه."""
        from doh_fronted import resolve as doh_resolve
        await asyncio.gather(
            *[doh_resolve(d) for d in domains],
            return_exceptions=True,
        )
        log.debug("Prefetched %d domains via DoH", len(domains))