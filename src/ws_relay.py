# ws_relay.py
import asyncio
import json
import base64
import ssl
import socket
import uuid
import logging
import time

try:
    import socks
except ImportError:
    socks = None

try:
    import websockets
except ImportError:
    websockets = None

log = logging.getLogger("WSRelay")

class WebSocketRelay:
    def __init__(self, config: dict):
        self.google_ip = config.get("google_ip", "216.239.38.120")
        self.sni = config.get("front_domain", "www.google.com")
        self.worker_host = config.get("worker_host")
        self.proxy_addr = config.get("proxy_addr", "127.0.0.1")
        self.proxy_port = config.get("proxy_port", 10808)
        self.websocket = None
        self._lock = asyncio.Lock()
        self._req_counter = 0
        self._pending: dict[str, asyncio.Future] = {}
        self._connected = False
        self._bg_reader: asyncio.Task | None = None

    async def connect(self):
        if self._connected and self.websocket:
            try:
                await self.websocket.ping()
                return
            except Exception:
                await self._close_ws()
        if socks is None or websockets is None:
            raise ImportError("PySocks and websockets required")
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, self.proxy_addr, self.proxy_port)
        s.settimeout(30)
        await asyncio.get_event_loop().sock_connect(s, (self.google_ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(s, server_hostname=self.sni)
        self.websocket = await websockets.connect(
            f"wss://{self.worker_host}/",
            ssl=ctx,
            sock=ssock,
            server_hostname=self.sni,
            extra_headers={"Host": self.worker_host}
        )
        self._connected = True
        self._bg_reader = asyncio.create_task(self._reader_loop())
        log.info("WebSocket connected to %s via %s", self.worker_host, self.google_ip)

    async def _close_ws(self):
        self._connected = False
        if self._bg_reader:
            self._bg_reader.cancel()
            self._bg_reader = None
        if self.websocket:
            try:
                await self.websocket.close()
            except Exception:
                pass
            self.websocket = None

    async def _reader_loop(self):
        try:
            while self._connected:
                msg = await self.websocket.recv()
                data = json.loads(msg)
                rid = data.get("id")
                if rid and rid in self._pending:
                    self._pending[rid].set_result(data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.warning("WebSocket reader ended: %s", e)
        finally:
            self._connected = False

    async def relay(self, method: str, url: str, headers: dict, body: bytes = b"") -> bytes:
        async with self._lock:
            if not self._connected:
                await self.connect()
            rid = str(uuid.uuid4())
            payload = {
                "id": rid,
                "method": method,
                "url": url,
                "headers": headers or {},
                "body": base64.b64encode(body).decode() if body else None,
            }
            future = asyncio.get_event_loop().create_future()
            self._pending[rid] = future
            try:
                await asyncio.wait_for(self.websocket.send(json.dumps(payload)), timeout=10)
                resp_data = await asyncio.wait_for(future, timeout=60)
            finally:
                self._pending.pop(rid, None)

        if resp_data.get("error"):
            raise Exception(f"Worker error: {resp_data['error']}")
        resp_body = base64.b64decode(resp_data.get("body", "")) if resp_data.get("body") else b""
        status_code = resp_data.get("status", 200)
        status_text = {200: "OK", 206: "Partial Content", 301: "Moved", 302: "Found",
                       400: "Bad Request", 403: "Forbidden", 404: "Not Found",
                       500: "Internal Server Error"}.get(status_code, "OK")
        raw = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for k, v in resp_data.get("headers", {}).items():
            raw += f"{k}: {v}\r\n"
        raw += f"Content-Length: {len(resp_body)}\r\n\r\n"
        return raw.encode() + resp_body

    async def close(self):
        await self._close_ws()