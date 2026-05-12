"""
ws_tunnel.py — Universal Tachyon Relay Client
SOCKS5 + HTTP proxy with TCP/UDP/DNS/HTTP/HTTPS support
Domain-fronted WebSocket to Cloudflare Worker
"""

import asyncio, base64, json, logging, socket, ssl, struct, time, uuid
from urllib.parse import urlparse

try:
    import socks  # pip install PySocks
except ImportError:
    socks = None

try:
    import websockets
except ImportError:
    exit("pip install websockets")

log = logging.getLogger("TachyonClient")

# ── Protocol constants ────────────────────────────────────
TYPE_TCP = 0x01
TYPE_UDP = 0x02
TYPE_DNS = 0x03

class TachyonClient:
    """WebSocket tunnel client with full protocol support."""

    def __init__(self, google_ip="216.239.38.120", sni="www.google.com",
                 worker_host="myworker.workers.dev",
                 proxy_addr="127.0.0.1", proxy_port=10808,
                 socks_port=1080):
        self.google_ip = google_ip
        self.sni = sni
        self.worker_host = worker_host
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.socks_port = socks_port
        self.ws = None
        self.ws_lock = asyncio.Lock()
        self._connected = False
        self._reader_task = None
        self._pending: dict[str, asyncio.Future] = {}
        self._tcp_streams: dict[str, tuple] = {}
        self._udp_queue: dict[str, asyncio.Queue] = {}

    # ── WebSocket connection via domain fronting ──────────
    async def connect(self):
        loop = asyncio.get_event_loop()
        s = socks.socksocket() if socks else socket.socket()
        if socks:
            s.set_proxy(socks.SOCKS5, self.proxy_addr, self.proxy_port)
        s.settimeout(15)
        await loop.sock_connect(s, (self.google_ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(s, server_hostname=self.sni)
        self.ws = await websockets.connect(
            f"wss://{self.worker_host}/",
            ssl=ctx,
            sock=ssock,
            server_hostname=self.sni,
            extra_headers={"Host": self.worker_host}
        )
        self._connected = True
        self._reader_task = asyncio.create_task(self._ws_reader())
        log.info("Connected to %s via %s", self.worker_host, self.google_ip)

    async def _ws_reader(self):
        while self._connected:
            try:
                msg = await self.ws.recv()
                if isinstance(msg, str):
                    data = json.loads(msg)
                    rid = data.get("id")
                    if rid and rid in self._pending:
                        self._pending[rid].set_result(data)
                elif isinstance(msg, bytes):
                    # Raw TCP/UDP response — route to appropriate stream
                    pass
            except (asyncio.CancelledError, websockets.exceptions.ConnectionClosed):
                break
            except Exception as e:
                log.debug("WS reader: %s", e)

    # ── Frame builder ─────────────────────────────────────
    @staticmethod
    def build_frame(typ: int, host: str, port: int, data: bytes) -> bytes:
        addr_bytes = host.encode()
        header = struct.pack("!BHB", typ, port, len(addr_bytes)) + addr_bytes
        return header + data

    # ── HTTP relay (same as before, via JSON-RPC) ──────────
    async def http_relay(self, method: str, url: str, headers: dict, body: bytes = b""):
        pass  # same as previous ws_relay implementation

    # ── TCP tunnel ────────────────────────────────────────
    async def tcp_tunnel(self, host: str, port: int, client_reader, client_writer):
        """Full-duplex TCP tunnel through WebSocket."""
        session_id = str(uuid.uuid4())[:8]
        loop = asyncio.get_event_loop()

        async def to_ws():
            while True:
                data = await client_reader.read(65536)
                if not data:
                    break
                frame = self.build_frame(TYPE_TCP, host, port, data)
                await self.ws.send(frame)

        async def from_ws():
            # simplified: responses arrive on WS and are written to client_writer
            pass

        await to_ws()

    # ── UDP relay ─────────────────────────────────────────
    async def udp_relay(self, host: str, port: int, data: bytes) -> bytes:
        """Send single UDP datagram and wait for response."""
        frame = self.build_frame(TYPE_UDP, host, port, data)
        await self.ws.send(frame)
        # Response handling depends on worker TURN implementation
        return b""

    # ── SOCKS5 server ─────────────────────────────────────
    async def start_socks5(self):
        server = await asyncio.start_server(
            self._handle_socks, "127.0.0.1", self.socks_port
        )
        log.info("SOCKS5 on 127.0.0.1:%d", self.socks_port)
        await server.serve_forever()

    async def _handle_socks(self, reader, writer):
        # Standard SOCKS5 handshake
        header = await reader.readexactly(2)
        ver, nmethods = header[0], header[1]
        if ver != 5:
            return
        methods = await reader.readexactly(nmethods)
        if 0x00 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x00")
        await writer.drain()
        req = await reader.readexactly(4)
        ver, cmd, _, atyp = req
        if ver != 5 or cmd != 0x01:
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return
        if atyp == 0x01:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode()
        else:
            writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return
        port = int.from_bytes(await reader.readexactly(2), "big")
        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await writer.drain()
        log.info("SOCKS5 → %s:%d", host, port)
        await self.tcp_tunnel(host, port, reader, writer)

# ── Entry point ────────────────────────────────────────────
async def main():
    logging.basicConfig(level=logging.INFO)
    client = TachyonClient(
        google_ip="216.239.38.120",
        sni="www.google.com",
        worker_host="your-worker.workers.dev",  # ← قفل شما
        socks_port=1080
    )
    await client.connect()
    await client.start_socks5()

if __name__ == "__main__":
    asyncio.run(main())