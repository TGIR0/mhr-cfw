#!/usr/bin/env python3
"""
UDP‑over‑TCP tunnel client for mhr-cfw.
Listens on a local UDP port, packs every datagram into a length‑prefixed
frame, and sends it through a WebSocket to the Cloudflare Worker.
"""

import asyncio, struct, socket, logging, signal, time
from collections import deque

try:
    import aiohttp
except ImportError:
    exit("aiohttp required: pip install aiohttp")

logger = logging.getLogger("UDPTunnel")
# ── Configuration ───────────────────────────────────────────────
LISTEN_PORT       = 5353          # local UDP port apps talk to
WORKER_URL        = "https://your-relay.workers.dev/udp"  # your Worker
RECONNECT_DELAY   = 2.0           # seconds
MAX_PACKET_SIZE   = 2048          # safe under typical MTU
WEBSOCKET_TIMEOUT = 30.0

# ── Simple timer‑wheel for inbound UDP “NAT” replies ───────────
class NATTable:
    def __init__(self, ttl=60):
        self._table: dict[int, asyncio.Transport] = {}
        self._ttl = ttl
    def add(self, session_id, transport):
        self._table[session_id] = (time.monotonic(), transport)
    def get(self, session_id):
        entry = self._table.get(session_id)
        if entry is None:
            return None
        ts, transport = entry
        if time.monotonic() - ts > self._ttl:
            del self._table[session_id]
            return None
        return transport
    def expire(self):
        now = time.monotonic()
        expired = [sid for sid, (ts, _) in self._table.items() if now - ts > self._ttl]
        for sid in expired:
            del self._table[session_id]

nat = NATTable(ttl=60)

# ── Protocol helpers ────────────────────────────────────────────
def pack_udp(data: bytes, dst_addr: str, dst_port: int, session_id: int) -> bytes:
    """[2B session][2B port][1B addr_len][addr][data]"""
    addr_bytes = dst_addr.encode()
    return struct.pack("!HHB", session_id, dst_port, len(addr_bytes)) + addr_bytes + data

def unpack_udp(frame: bytes):
    """Returns (session_id, src_port, src_addr, data) or None."""
    if len(frame) < 5:
        return None
    session_id, src_port, addr_len = struct.unpack("!HHB", frame[:5])
    if len(frame) < 5 + addr_len:
        return None
    src_addr = frame[5:5+addr_len].decode()
    data = frame[5+addr_len:]
    return session_id, src_port, src_addr, data

# ── WebSocket client (auto‑reconnect) ───────────────────────────
class TunnelClient:
    def __init__(self, worker_url, listen_port):
        self.url = worker_url
        self.port = listen_port
        self._ws = None
        self._send_queue = deque()
        self._recv_cb = None
        self._running = False

    async def start(self, on_recv):
        self._recv_cb = on_recv
        self._running = True
        asyncio.create_task(self._connect_loop())

    async def _connect_loop(self):
        while self._running:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(self.url, timeout=WEBSOCKET_TIMEOUT) as ws:
                        self._ws = ws
                        logger.info("WebSocket connected")
                        # drain pending
                        while self._send_queue:
                            await ws.send_bytes(self._send_queue.popleft())
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                result = unpack_udp(msg.data)
                                if result:
                                    self._recv_cb(*result)
                            elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                                break
            except Exception as e:
                logger.warning(f"WebSocket error: {e}")
            self._ws = None
            if self._running:
                await asyncio.sleep(RECONNECT_DELAY)

    async def send(self, session_id, dst_addr, dst_port, data):
        frame = pack_udp(data, dst_addr, dst_port, session_id)
        if self._ws and not self._ws.closed:
            try:
                await self._ws.send_bytes(frame)
                return
            except Exception:
                pass
        self._send_queue.append(frame)

# ── UDP server ──────────────────────────────────────────────────
class UDPRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, client):
        self.client = client
        self.transport = None
    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"UDP relay listening on port {LISTEN_PORT}")
    def datagram_received(self, data, addr):
        # addr is (host, port) of the local sender
        src_ip, src_port = addr
        # We use the source port as session_id for simplicity
        session_id = src_port & 0xFFFF
        nat.add(session_id, self.transport)
        # The actual target is extracted from the app’s original destination
        # (we assume a SOCKS5‑like pre‑tunnel; for generic UDP relay
        #  the target address must be embedded inside data — here we use
        #  a simple convention: first 2 bytes = port, rest = hostname)
        # For real apps you would use XUDP or a pre‑established mapping.
        pass  # see _start_relay_server below for the full version

# ── Main entry point ────────────────────────────────────────────
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    client = TunnelClient(WORKER_URL, LISTEN_PORT)

    # real UDP relay with embedded target address
    class RealUDPProtocol(asyncio.DatagramProtocol):
        def __init__(self):
            self.transport = None
        def connection_made(self, transport):
            self.transport = transport
        def datagram_received(self, data, addr):
            # First 2 bytes = destination port (big‑endian)
            # Following bytes until \x00 = destination hostname
            if len(data) < 3:
                return
            dst_port = struct.unpack("!H", data[:2])[0]
            rest = data[2:]
            null_pos = rest.find(b'\x00')
            if null_pos < 0:
                return
            dst_addr = rest[:null_pos].decode()
            payload = rest[null_pos+1:]
            session_id = addr[1] & 0xFFFF
            nat.add(session_id, self.transport)
            asyncio.ensure_future(client.send(session_id, dst_addr, dst_port, payload))

    async def on_recv(session_id, src_port, src_addr, data):
        transport = nat.get(session_id)
        if transport:
            transport.sendto(data, (src_addr, src_port))

    loop = asyncio.get_event_loop()
    # start UDP listener
    listen = loop.create_datagram_endpoint(RealUDPProtocol, local_addr=('127.0.0.1', LISTEN_PORT))
    loop.run_until_complete(listen)
    # start WebSocket client
    loop.run_until_complete(client.start(on_recv))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()