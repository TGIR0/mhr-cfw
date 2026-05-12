"""
kcp_tunnel.py — KCP over WebTransport with WebSocket fallback
Requires: pip install kcp-python aioquic websockets
"""
import asyncio
import base64
import json
import logging
import socket
import ssl
import struct
import uuid
from typing import Optional

try:
    import kcp
    HAS_KCP = True
except ImportError:
    HAS_KCP = False

try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False

try:
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived
    HAS_QUIC = True
except ImportError:
    HAS_QUIC = False

log = logging.getLogger("KCP")


class KcpWebTransportRelay:
    """
    WebTransport + KCP relay with automatic fallback.
    Protocol stack: Application → KCP → WebTransport (QUIC) → Worker → Internet
    """

    def __init__(self, config: dict):
        self.google_ip = config.get("google_ip", "216.239.38.120")
        self.sni = config.get("front_domain", "www.google.com")
        self.worker_host = config.get("worker_host", "")
        self._kcp: Optional[kcp.KCP] = None
        self._transport = None
        self._mode = "websocket"

    async def connect(self):
        """Try WebTransport+KCP, then WebSocket, then error."""
        if HAS_KCP and HAS_QUIC:
            try:
                await self._connect_kcp_wt()
                self._mode = "kcp+webtransport"
                log.info("Connected via KCP+WebTransport (ultra-low latency)")
                return
            except Exception as e:
                log.debug("KCP+WT failed: %s", e)

        if HAS_WS:
            await self._connect_ws()
            self._mode = "websocket"
            log.info("Connected via WebSocket (fallback)")

    async def _connect_kcp_wt(self):
        """Establish WebTransport and wrap with KCP."""
        # QUIC connection
        conf = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
        conf.verify_mode = ssl.CERT_NONE

        self._session = await connect(
            self.google_ip, 443,
            configuration=conf,
            server_name=self.sni,
        )

        # WebTransport handshake
        self._stream = await self._session.create_stream(
            f"https://{self.worker_host}/kcp",
            method="CONNECT",
            headers={"Upgrade": "webtransport"},
        )

        # KCP layer
        self._kcp = kcp.KCP(conv=0x11223344, send=self._kcp_send)
        self._kcp.nodelay(1, 10, 2, 1)
        self._kcp.wndsize(256, 256)

        # Start KCP flusher
        asyncio.create_task(self._kcp_flusher())
        # Start reader
        asyncio.create_task(self._kcp_reader())

    def _kcp_send(self, data: bytes):
        """Send KCP output to WebTransport stream."""
        if self._stream:
            self._stream.send(data)

    async def _kcp_flusher(self):
        """Periodically flush KCP pending data."""
        while self._kcp:
            self._kcp.update()
            await asyncio.sleep(0.01)

    async def _kcp_reader(self):
        """Read from WebTransport → feed KCP → dispatch to pending futures."""
        while self._stream:
            try:
                data = await asyncio.wait_for(self._stream.recv(), timeout=30)
                self._kcp.input(data)
                # Check for complete messages
                while True:
                    msg = self._kcp.recv()
                    if not msg:
                        break
                    self._dispatch(msg)
            except (asyncio.TimeoutError, ConnectionError):
                break

    def _dispatch(self, data: bytes):
        """Dispatch received application data to pending request."""
        # This would be connected to the relay engine's response handler
        pass

    async def _connect_ws(self):
        self._ws = await websockets.connect(
            f"wss://{self.worker_host}/",
            ssl=ssl.create_default_context() if self.sni else None,
            server_hostname=self.sni,
        )

    async def relay(self, method: str, url: str, headers: dict, body: bytes = b"") -> bytes:
        """Send HTTP request through KCP or WebSocket tunnel."""
        rid = str(uuid.uuid4())
        payload = json.dumps({
            "id": rid, "method": method, "url": url,
            "headers": headers,
            "body": base64.b64encode(body).decode() if body else "",
        })

        if self._mode == "kcp+webtransport":
            self._kcp.send(payload.encode())
        else:
            await self._ws.send(payload)

        # Wait for response
        # (In production, this would use a pending futures map)
        resp_raw = await self._recv_response(rid)
        return self._build_http_response(json.loads(resp_raw))

    async def _recv_response(self, rid: str) -> bytes:
        """Receive response matching the request ID."""
        # Simplified — in production, use a proper dispatcher
        if self._mode == "kcp+webtransport":
            while True:
                msg = self._kcp.recv()
                if msg:
                    data = json.loads(msg.decode())
                    if data.get("id") == rid:
                        return msg
                await asyncio.sleep(0.005)
        else:
            resp = await self._ws.recv()
            return resp.encode()

    @staticmethod
    def _build_http_response(data: dict) -> bytes:
        if "error" in data:
            raise RuntimeError(data["error"])
        body = base64.b64decode(data.get("body", ""))
        status = data.get("status", 200)
        result = f"HTTP/1.1 {status} OK\r\n"
        for k, v in data.get("headers", {}).items():
            result += f"{k}: {v}\r\n"
        result += f"Content-Length: {len(body)}\r\n\r\n"
        return result.encode() + body

    async def close(self):
        if self._session:
            self._session.close()
        if hasattr(self, '_ws'):
            await self._ws.close()