"""
kcp_ws.py — KCP‑over‑WebSocket transport with automatic fallback
Uses: pip install kcp
"""

import asyncio, json, struct, time
import websockets

try:
    import kcp   # python-kcp
except ImportError:
    kcp = None

NEGOTIATION_TIMEOUT = 5.0   # seconds
KCP_MTU = 1400
KCP_WND = 128

class KCPWebSocket:
    def __init__(self, ws_url, google_ip, sni, socks_proxy=None):
        self.ws_url = ws_url
        self.google_ip = google_ip
        self.sni = sni
        self.proxy = socks_proxy
        self.ws = None
        self._kcp = None
        self._mode = None           # 'raw' or 'kcp'

    async def connect(self):
        # برقراری WebSocket با Domain‑Fronting
        s = socks.socksocket() if self.proxy else socket.socket()
        if self.proxy:
            s.set_proxy(socks.SOCKS5, *self.proxy)
        s.settimeout(15)
        await asyncio.get_event_loop().sock_connect(s, (self.google_ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(s, server_hostname=self.sni)
        self.ws = await websockets.connect(
            self.ws_url, ssl=ctx, sock=ssock,
            server_hostname=self.sni,
            extra_headers={"Host": self.ws_url.split("/")[-1]}
        )
        # مذاکره برای KCP
        await self._negotiate()

    async def _negotiate(self):
        if kcp is None:
            self._mode = 'raw'
            return
        await self.ws.send(json.dumps({"cmd": "upgrade", "protocols": ["kcp+jsonrpc", "jsonrpc"]}))
        try:
            resp = await asyncio.wait_for(self.ws.recv(), timeout=NEGOTIATION_TIMEOUT)
            data = json.loads(resp)
            if data.get("protocol") == "kcp+jsonrpc":
                self._kcp = kcp.KCP(conv=0x11223344, send=self._kcp_send)
                self._kcp.setmtu(KCP_MTU)
                self._kcp.wndsize(KCP_WND, KCP_WND)
                self._mode = 'kcp'
                # راه‌اندازی حلقه دریافت KCP
                asyncio.create_task(self._kcp_reader())
                return
        except Exception:
            pass
        # فال‌بک به حالت معمولی
        self._mode = 'raw'

    def _kcp_send(self, data: bytes):
        """ارسال بایت‌های خام KCP از طریق WebSocket"""
        asyncio.ensure_future(self.ws.send(data))

    async def _kcp_reader(self):
        """خواندن فریم‌های WebSocket و تحویل به KCP"""
        while self._mode == 'kcp':
            try:
                raw = await self.ws.recv()
                if isinstance(raw, bytes):
                    self._kcp.input(raw)
                    asyncio.create_task(self._flush_kcp())
                elif isinstance(raw, str):
                    # در حالت KCP نباید متن دریافت کنیم، پس خطا
                    pass
            except:
                break

    async def _flush_kcp(self):
        """بیرون کشیدن داده‌های آماده از KCP"""
        while True:
            buf = self._kcp.recv()
            if not buf:
                break
            # اینجا داده‌های سطح کاربردی (JSON) را پردازش می‌کنیم
            # در این نسخه، مستقیماً به صف تحویل داده می‌شود
            await self._on_app_data(buf)

    async def _on_app_data(self, data: bytes):
        # برای سازگاری با وب‌سوکت معمولی، این متد را override کنید
        pass

    async def send(self, message: dict):
        """ارسال یک پیام JSON (درخواست رله) با توجه به حالت فعال"""
        raw = json.dumps(message).encode()
        if self._mode == 'kcp':
            self._kcp.send(raw)
            asyncio.create_task(self._flush_kcp())   # بلافاصله ارسال
        else:
            await self.ws.send(message)

    async def recv(self) -> dict:
        """دریافت یک پیام JSON (پاسخ)"""
        # این متد باید توسط کلاس بالاتر (که on_app_data را override کرده) مدیریت شود
        raise NotImplementedError