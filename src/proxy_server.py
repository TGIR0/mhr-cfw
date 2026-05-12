"""
Local HTTP proxy server with MITM interception, CORS rewrites,
direct-tunnel shortcuts, and smart relay-vs-stream download selection.

All browser traffic is forwarded through the Apps Script relay or
directly piped when safe (Google properties, local bypass rules, etc.).
"""

import asyncio
import json
import logging
import os
import socket
import time
from urllib.parse import urlparse

from constants import (
    CACHE_MAX_MB,
    CLIENT_IDLE_TIMEOUT,
    GOOGLE_DIRECT_EXACT_EXCLUDE,
    GOOGLE_DIRECT_ALLOW_EXACT,
    GOOGLE_OWNED_EXACT,
    GOOGLE_OWNED_SUFFIXES,
    LARGE_FILE_EXTS,
    MAX_HEADER_BYTES,
    MAX_REQUEST_BODY_BYTES,
    SNI_REWRITE_SUFFIXES,
    TCP_CONNECT_TIMEOUT,
    TRACE_HOST_SUFFIXES,
    UNCACHEABLE_HEADER_NAMES,
)
from domain_fronter import DomainFronter

# -- New modular imports --
from helpers import (
    is_ip_literal,
    parse_content_length,
    has_unsupported_transfer_encoding,
    cors_preflight_response,
    inject_cors_headers,
)
from cache import ResponseCache
from routing import HostRouter
from tunnel import (
    direct_tunnel,
    sni_rewrite_tunnel,
    mitm_connect,
    open_tcp_connection as tcp_connect,
)

# Optional modules
try:
    from doh_fronted import resolve as doh_resolve, init as doh_init
    HAS_DOH = True
except ImportError:
    HAS_DOH = False

try:
    from tachyon_relay import HybridRelay
    HAS_TACHYON = True
except ImportError:
    HAS_TACHYON = False

log = logging.getLogger("Proxy")

_EXCLUDE_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "exclude_cache.json"
)


class ProxyServer:
    _TRACE_HOST_SUFFIXES = TRACE_HOST_SUFFIXES
    _DOWNLOAD_DEFAULT_EXTS = tuple(sorted(LARGE_FILE_EXTS))

    def __init__(self, config: dict):
        self.host = config.get("listen_host", "127.0.0.1")
        self.port = config.get("listen_port", 8080)
        self.socks_enabled = config.get("socks5_enabled", True)
        self.socks_host = config.get("socks5_host", self.host)
        self.socks_port = config.get("socks5_port", 1080)

        from smart_router import CloudflareDetector, DependencyResolver
        self._cf_detector = CloudflareDetector()
        self._dependency_resolver = DependencyResolver
        self._servers = []
        self._client_tasks = set()

        self._tcp_connect_timeout = float(
            config.get("tcp_connect_timeout", TCP_CONNECT_TIMEOUT)
        )

        # Exclude/Allow
        configured_exclude = config.get("direct_google_exclude", [])
        direct_exclude = {
            h.lower().rstrip(".")
            for h in (list(GOOGLE_DIRECT_EXACT_EXCLUDE) + list(configured_exclude))
        }
        self._load_exclude_cache(direct_exclude)

        configured_allow = config.get("direct_google_allow", [])
        self._direct_google_allow = {
            h.lower().rstrip(".")
            for h in (list(GOOGLE_DIRECT_ALLOW_EXACT) + list(configured_allow))
        }

        self._block_hosts = self._load_host_rules(config.get("block_hosts", []))
        self._bypass_hosts = self._load_host_rules(config.get("bypass_hosts", []))

        # SNI
        if config.get("youtube_via_relay", False):
            self._sni_suffixes = tuple(
                s for s in SNI_REWRITE_SUFFIXES
                if s not in frozenset({"youtube.com", "youtu.be", "youtube-nocookie.com"})
            )
        else:
            self._sni_suffixes = SNI_REWRITE_SUFFIXES

        # MITM
        try:
            from mitm import MITMCertManager
            self.mitm = MITMCertManager()
        except ImportError:
            log.error("Need cryptography package")
            raise SystemExit(1)

        # Relay engine
        worker_host = config.get("worker_host")
        if config.get("mode") == "websocket" and worker_host and HAS_TACHYON:
            self.fronter = HybridRelay(config)
            log.info("Relay: Tachyon (KCP-ready)")
        else:
            self.fronter = DomainFronter(config)
            log.info("Relay: Apps Script (quota-based)")

        self._cache = ResponseCache(CACHE_MAX_MB)

        # Router
        self._router = HostRouter(
            self._direct_google_exclude, self._direct_google_allow,
            config.get("hosts", {}), self.fronter
        )

        # DoH
        if HAS_DOH:
            doh_init(
                config.get("google_ip", "216.239.38.120"),
                config.get("front_domain", "www.google.com"),
            )
            log.info("DoH Fronted activated")

    # ---------- Exclude cache ----------
    def _load_exclude_cache(self, direct_exclude):
        self._direct_google_exclude = direct_exclude
        try:
            if os.path.exists(_EXCLUDE_CACHE_FILE):
                with open(_EXCLUDE_CACHE_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for host in data:
                        self._direct_google_exclude.add(
                            str(host).strip().lower().rstrip(".")
                        )
                log.debug("Loaded %d excluded domains from cache", len(data))
        except Exception as e:
            log.warning("Exclude cache load error: %s", e)

    def _save_exclude_cache(self):
        try:
            with open(_EXCLUDE_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(list(self._direct_google_exclude), f, indent=2)
        except Exception as e:
            log.warning("Save exclude cache: %s", e)

    def _add_excluded_host(self, host: str):
        self._direct_google_exclude.add(host)
        self._save_exclude_cache()

    # ---------- Host rules ----------
    @staticmethod
    def _load_host_rules(raw):
        exact, suffixes = set(), []
        for h in (raw or []):
            h = str(h).strip().lower().rstrip(".")
            if not h:
                continue
            if h.startswith("."):
                suffixes.append(h)
            else:
                exact.add(h)
        return exact, tuple(suffixes)

    def _is_blocked(self, host):
        host = host.lower().rstrip(".")
        return host in self._block_hosts[0] or any(
            host.endswith(s) for s in self._block_hosts[1]
        )

    def _is_bypassed(self, host):
        host = host.lower().rstrip(".")
        return host in self._bypass_hosts[0] or any(
            host.endswith(s) for s in self._bypass_hosts[1]
        )

    # ---------- Start / Stop ----------
    async def start(self):
        http_srv = await asyncio.start_server(self._on_client, self.host, self.port)
        socks_srv = None
        if self.socks_enabled:
            try:
                socks_srv = await asyncio.start_server(
                    self._on_socks_client, self.socks_host, self.socks_port
                )
            except OSError as e:
                log.error("SOCKS5 failed: %s", e)
        self._servers = [s for s in (http_srv, socks_srv) if s]
        log.info("HTTP on %s:%d", self.host, self.port)
        if socks_srv:
            log.info("SOCKS5 on %s:%d", self.socks_host, self.socks_port)
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
            srv.close()
            await srv.wait_closed()
        for t in list(self._client_tasks):
            t.cancel()
        try:
            await self.fronter.close()
        except Exception as exc:
            log.debug("fronter.close: %s", exc)

    # ---------- Client handlers ----------
    async def _on_client(self, reader, writer):
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not first_line:
                return
            header_block = first_line
            while True:
                line = await reader.readline()
                header_block += line
                if len(header_block) > MAX_HEADER_BYTES or line in (b"\r\n", b""):
                    break
            if has_unsupported_transfer_encoding(header_block):
                writer.write(b"HTTP/1.1 501 Not Implemented\r\n\r\n")
                await writer.drain()
                return
            request_line = first_line.decode(errors="replace").strip()
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return
            method, path = parts[0].upper(), parts[1]
            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                host, port_str = path.split(":")
                port = int(port_str or 443)
                await self._handle_target_tunnel(host, port, reader, writer)
            else:
                await self._do_http(header_block, reader, writer)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log.error("HTTP handler error: %s", e)
        finally:
            writer.close()

    async def _on_socks_client(self, reader, writer):
        try:
            # SOCKS5 handshake
            header = await asyncio.wait_for(reader.readexactly(2), timeout=15)
            ver, nmethods = header[0], header[1]
            if ver != 5:
                return
            methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=10)
            if 0x00 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()
            req = await asyncio.wait_for(reader.readexactly(4), timeout=15)
            ver, cmd, _, atyp = req
            if ver != 5 or cmd != 0x01:
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            host = None
            if atyp == 0x01:  # IPv4
                raw = await asyncio.wait_for(reader.readexactly(4), timeout=10)
                host = socket.inet_ntoa(raw)
            elif atyp == 0x03:  # Domain
                ln = (await asyncio.wait_for(reader.readexactly(1), timeout=10))[0]
                host = (await asyncio.wait_for(reader.readexactly(ln), timeout=10)).decode()
            elif atyp == 0x04:  # IPv6
                raw = await asyncio.wait_for(reader.readexactly(16), timeout=10)
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            port_raw = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            port = int.from_bytes(port_raw, "big")
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            log.info("SOCKS5 CONNECT -> %s:%d", host, port)
            await self._handle_target_tunnel(host, port, reader, writer)
        except Exception as e:
            log.debug("SOCKS5 error: %s", e)
        finally:
            writer.close()

    # ---------- Tunneling ----------
    async def _handle_target_tunnel(self, host, port, reader, writer):
        if self._is_blocked(host):
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        if self._is_bypassed(host):
            await direct_tunnel(host, port, reader, writer, self._tcp_connect_timeout)
            return
        if is_ip_literal(host):
            if not self._router.is_direct_disabled(host):
                if await direct_tunnel(host, port, reader, writer, timeout=4.0):
                    return
                self._router.remember_failure(host)
            if port == 443:
                await mitm_connect(host, port, reader, writer, self.mitm, self.fronter, self._relay_http_stream)
            elif port == 80:
                await self._do_plain_http_tunnel(host, port, reader, writer)
            return
        override_ip = self._router.sni_rewrite_ip(host)
        if override_ip:
            await sni_rewrite_tunnel(host, port, reader, writer, self.mitm, self.fronter, connect_ip=override_ip)
        elif self._router.is_google_domain(host):
            if self._router.is_direct_disabled(host):
                if port == 443:
                    await mitm_connect(host, port, reader, writer, self.mitm, self.fronter, self._relay_http_stream)
                else:
                    await self._do_plain_http_tunnel(host, port, reader, writer)
                return
            if await direct_tunnel(host, port, reader, writer):
                return
            self._router.remember_failure(host)
            if port == 443:
                await mitm_connect(host, port, reader, writer, self.mitm, self.fronter, self._relay_http_stream)
            else:
                await self._do_plain_http_tunnel(host, port, reader, writer)
        elif port == 443:
            await mitm_connect(host, port, reader, writer, self.mitm, self.fronter, self._relay_http_stream)
        elif port == 80:
            await self._do_plain_http_tunnel(host, port, reader, writer)
        else:
            await direct_tunnel(host, port, reader, writer)

    async def _do_plain_http_tunnel(self, host, port, reader, writer):
        await self._relay_http_stream(host, port, reader, writer)

    async def _relay_http_stream(self, host, port, reader, writer):
        while True:
            try:
                first_line = await asyncio.wait_for(reader.readline(), timeout=CLIENT_IDLE_TIMEOUT)
                if not first_line:
                    break
                header_block = first_line
                while True:
                    line = await reader.readline()
                    header_block += line
                    if len(header_block) > MAX_HEADER_BYTES or line in (b"\r\n", b""):
                        break
                if has_unsupported_transfer_encoding(header_block):
                    writer.write(b"HTTP/1.1 501\r\n\r\n")
                    await writer.drain()
                    continue
                length = parse_content_length(header_block)
                body = b""
                if length and length < MAX_REQUEST_BODY_BYTES:
                    body = await reader.readexactly(length)
                request_line = first_line.decode(errors="replace").strip()
                parts = request_line.split(" ", 2)
                if len(parts) < 2:
                    break
                method, path_val = parts[0], parts[1]
                headers = {}
                for line in header_block.split(b"\r\n")[1:]:
                    if b":" in line:
                        k, v = line.decode(errors="replace").split(":", 1)
                        headers[k.strip()] = v.strip()
                url = path_val
                if not path_val.startswith("http"):
                    scheme = "https" if port == 443 else "http"
                    url = f"{scheme}://{host}{path_val}"
                log.info("MITM -> %s %s", method, url)
                response = await self._relay_smart(method, url, headers, body)
                origin = headers.get("Origin", headers.get("origin", ""))
                if origin:
                    response = inject_cors_headers(response, origin)
                writer.write(response)
                await writer.drain()
            except (asyncio.TimeoutError, ConnectionError):
                break
            except Exception as e:
                log.error("MITM stream error: %s", e)
                break

    async def _do_http(self, header_block, reader, writer):
        try:
            if has_unsupported_transfer_encoding(header_block):
                writer.write(b"HTTP/1.1 501\r\n\r\n")
                return
            length = parse_content_length(header_block)
            body = b""
            if length and length < MAX_REQUEST_BODY_BYTES:
                body = await reader.readexactly(length)
            first_line = header_block.split(b"\r\n")[0].decode(errors="replace")
            parts = first_line.strip().split(" ", 2)
            method = parts[0] if parts else "GET"
            url_str = parts[1] if len(parts) > 1 else "/"
            headers = {}
            for line in header_block.split(b"\r\n")[1:]:
                if b":" in line:
                    k, v = line.decode(errors="replace").split(":", 1)
                    headers[k.strip()] = v.strip()
            response = await self._relay_smart(method, url_str, headers, body)
            origin = headers.get("Origin", headers.get("origin", ""))
            if origin:
                response = inject_cors_headers(response, origin)
            writer.write(response)
            await writer.drain()
        except Exception as e:
            log.error("HTTP error: %s", e)
            writer.write(b"HTTP/1.1 502\r\n\r\n")

    def _header_value(self, headers, name):
        if not headers:
            return ""
        for k, v in headers.items():
            if k.lower() == name:
                return str(v)
        return ""

    async def _relay_smart(self, method, url, headers, body):
        return await self.fronter.relay(method, url, headers, body)

    def stats_snapshot(self):
        return self.fronter.stats_snapshot()