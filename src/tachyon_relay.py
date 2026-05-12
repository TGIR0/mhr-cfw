#!/usr/bin/env python3
"""
tachyon_relay.py — Universal Hybrid Relay Client
KCP‑over‑WebSocket with automatic JSON‑RPC fallback.

Features:
  • SOCKS5 / HTTP Proxy
  • HTTP/HTTPS relay via Apps Script or WebSocket
  • TCP raw tunnel (future: via KCP)
  • UDP relay via TURN (future)
  • Automatic KCP negotiation – zero config
  • Works with EXISTING worker.js — no changes needed now

Usage:
  python tachyon_relay.py --config config.json
"""

import asyncio, base64, json, logging, os, re, socket, ssl, struct, time, uuid
from pathlib import Path
from urllib.parse import urlparse

try:
    import socks
except ImportError:
    socks = None

try:
    import websockets
except ImportError:
    exit("pip install websockets")

try:
    import kcp
    from kcp import KCP
    HAS_KCP = True
except ImportError:
    HAS_KCP = False
    KCP = None

# ────────────────────────────────────────────────────
# Logging
# ────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s  %(levelname)-5s  %(message)s",
    level=logging.INFO,
    datefmt="%H:%M:%S",
)
log = logging.getLogger("Tachyon")

# ────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────
NEGOTIATION_TIMEOUT = 5.0
KCP_MTU = 1400
KCP_WND = 128

# ────────────────────────────────────────────────────
# Helper: domain‑fronted WebSocket
# ────────────────────────────────────────────────────
import tls_client

async def _df_connect(google_ip, sni, worker_host, proxy_addr=None, proxy_port=None):
    """
    برقراری WebSocket با Domain‑Fronting و اثر انگشت مرورگر کروم.
    """
    loop = asyncio.get_event_loop()

    # ایجاد سوکت SOCKS5 (اگر پروکسی تنظیم شده باشه)
    if socks and proxy_addr:
        raw_sock = socks.socksocket()
        raw_sock.set_proxy(socks.SOCKS5, proxy_addr, proxy_port)
    else:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    raw_sock.settimeout(15)
    await loop.sock_connect(raw_sock, (google_ip, 443))

    # ⚡ مرحله‌ی جادویی: TLS با اثر انگشت کروم ۱۳۱
    session = tls_client.Session(
        client_identifier="chrome_131",  # شبیه‌سازی کامل مرورگر کروم
        random_tls_extension_order=True, # ترتیب تصادفی برای گیج کردن DPI
    )
    # اتصال TLS روی سوکت خام
    tls_sock = session._create_ssl_connection(raw_sock, server_hostname=sni)

    url = f"wss://{worker_host}/"
    ws = await websockets.connect(
        url,
        ssl=tls_sock.context if hasattr(tls_sock, 'context') else None,
        sock=tls_sock,
        server_hostname=sni,
        extra_headers={"Host": worker_host},
    )
    return ws

# ────────────────────────────────────────────────────
# Hybrid Relay with KCP + fallback
# ────────────────────────────────────────────────────
class HybridRelay:
    def __init__(self, config):
        self.google_ip = config.get("google_ip", "216.239.38.120")
        self.sni = config.get("front_domain", "www.google.com")
        self.worker = config.get("worker_host", "")
        self.proxy_addr = config.get("socks5_host", "127.0.0.1")
        self.proxy_port = config.get("socks5_port", 1080)
        self.ws = None
        self._mode = "jsonrpc"   # or "kcp"
        self._kcp = None
        self._pending = {}
        self._lock = asyncio.Lock()

    async def connect(self):
        self.ws = await _df_connect(
            self.google_ip, self.sni, self.worker,
            self.proxy_addr, self.proxy_port,
        )
        # negotiate KCP if available
        if HAS_KCP and KCP:
            await self._negotiate_kcp()
        else:
            self._mode = "jsonrpc"

        # start reader
        asyncio.create_task(self._reader())
        log.info("HybridRelay connected (mode=%s)", self._mode)

    async def _negotiate_kcp(self):
        try:
            await self.ws.send(json.dumps({
                "cmd": "upgrade",
                "protocols": ["kcp+jsonrpc", "jsonrpc"],
            }))
            resp = await asyncio.wait_for(self.ws.recv(), timeout=NEGOTIATION_TIMEOUT)
            data = json.loads(resp)
            if data.get("protocol") == "kcp+jsonrpc":
                self._kcp = KCP(conv=0x11223344, send=self._kcp_output)
                self._kcp.setmtu(KCP_MTU)
                self._kcp.wndsize(KCP_WND, KCP_WND)
                self._mode = "kcp"
                log.info("KCP negotiated successfully")
                return
        except Exception:
            pass
        log.info("KCP not available – using JSON-RPC fallback")
        self._mode = "jsonrpc"

    def _kcp_output(self, data: bytes):
        asyncio.ensure_future(self.ws.send(data))

    async def _reader(self):
        while True:
            try:
                raw = await self.ws.recv()
            except Exception:
                break
            if isinstance(raw, bytes) and self._mode == "kcp":
                self._kcp.input(raw)
                while True:
                    buf = self._kcp.recv()
                    if not buf:
                        break
                    self._dispatch(json.loads(buf.decode()))
            elif isinstance(raw, str):
                self._dispatch(json.loads(raw))

    def _dispatch(self, data):
        rid = data.get("id")
        if rid and rid in self._pending:
            self._pending.pop(rid).set_result(data)

    async def relay(self, method, url, headers, body=b""):
        async with self._lock:
            rid = str(uuid.uuid4())
            payload = {
                "id": rid,
                "method": method,
                "url": url,
                "headers": headers,
            }
            if body:
                payload["body"] = base64.b64encode(body).decode()
            msg = json.dumps(payload)
            if self._mode == "kcp":
                self._kcp.send(msg.encode())
                # flush immediately
                asyncio.create_task(self._flush_kcp())
            else:
                await self.ws.send(msg)

            fut = asyncio.get_event_loop().create_future()
            self._pending[rid] = fut
            resp = await asyncio.wait_for(fut, timeout=60)
            return self._build_response(resp)

    async def _flush_kcp(self):
        while True:
            buf = self._kcp.recv()
            if not buf:
                break
            self._dispatch(json.loads(buf.decode()))

    @staticmethod
    def _build_response(data: dict) -> bytes:
        if "error" in data:
            raise RuntimeError(data["error"])
        body = base64.b64decode(data.get("body", "")) if data.get("body") else b""
        status = data.get("status", 200)
        status_text = {200: "OK", 206: "Partial Content", 301: "Moved", 302: "Found",
                       400: "Bad Request", 403: "Forbidden", 404: "Not Found",
                       500: "Internal Server Error"}.get(status, "OK")
        raw = f"HTTP/1.1 {status} {status_text}\r\n"
        for k, v in data.get("headers", {}).items():
            raw += f"{k}: {v}\r\n"
        raw += f"Content-Length: {len(body)}\r\n\r\n"
        return raw.encode() + body

# ────────────────────────────────────────────────────
# SOCKS5 server (TCP tunnel placeholder)
# ────────────────────────────────────────────────────
async def _socks_relay(reader, writer, relay):
    try:
        header = await reader.readexactly(2)
        ver, nmethods = header[0], header[1]
        if ver != 5: return
        methods = await reader.readexactly(nmethods)
        if 0x00 not in methods:
            writer.write(b"\x05\xff"); await writer.drain(); return
        writer.write(b"\x05\x00"); await writer.drain()
        req = await reader.readexactly(4)
        ver, cmd, _, atyp = req
        if ver != 5 or cmd != 0x01:
            writer.write(b"\x05\x07\x00\x01" + b"\x00"*6); await writer.drain(); return
        if atyp == 0x01:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode()
        else:
            writer.write(b"\x05\x08\x00\x01" + b"\x00"*6); await writer.drain(); return
        port = int.from_bytes(await reader.readexactly(2), "big")
        writer.write(b"\x05\x00\x00\x01" + b"\x00"*6); await writer.drain()
        # For now, just relay the HTTP request inside the tunnel
        # (Full TCP tunnel needs cloudflare:sockets on the worker)
        first_line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not first_line: return
        req_line = first_line.decode().strip()
        parts = req_line.split()
        if len(parts) < 2: return
        method, path = parts[0], parts[1]
        headers = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""): break
            if b":" in line:
                k, v = line.decode().split(":", 1)
                headers[k.strip()] = v.strip()
        url = f"https://{host}{path}"
        resp = await relay.relay(method, url, headers)
        writer.write(resp); await writer.drain()
    except Exception as e:
        log.error("SOCKS5 handler error: %s", e)
    finally:
        writer.close()

async def start_socks_server(relay, port=1080):
    server = await asyncio.start_server(
        lambda r, w: _socks_relay(r, w, relay),
        "127.0.0.1", port,
    )
    log.info("SOCKS5 proxy on 127.0.0.1:%d", port)
    await server.serve_forever()

# ────────────────────────────────────────────────────
# Main entry
# ────────────────────────────────────────────────────
async def main():
    config_path = os.environ.get("DFT_CONFIG", "config.json")
    with open(config_path) as f:
        config = json.load(f)

    relay = HybridRelay(config)
    await relay.connect()

    # start SOCKS5 server
    socks_port = config.get("socks5_port", 1080)
    await start_socks_server(relay, socks_port)

if __name__ == "__main__":
    asyncio.run(main())