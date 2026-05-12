"""
doh_fronted.py — DNS over HTTPS via Domain Fronting
No external DNS required. Uses Google's DoH service through the same
domain‑fronted TLS connection that the rest of the project uses.
"""

import asyncio, base64, json, logging, socket, ssl, struct, time
from urllib.parse import urlparse

try:
    import socks
except ImportError:
    socks = None

log = logging.getLogger("DoH")

# Google DoH endpoint — reachable via any Google edge IP
DOE_URL = "https://dns.google/dns-query"
DOE_HOST = "dns.google"

class FrontedDoHResolver:
    def __init__(self, google_ip="216.239.38.120", sni="www.google.com",
                 proxy_addr=None, proxy_port=None):
        self.google_ip = google_ip
        self.sni = sni
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self._cache: dict[str, tuple[list[str], float]] = {}
        self._lock = asyncio.Lock()
        self._ttl = 300  # seconds

    async def resolve(self, hostname: str) -> list[str]:
        # Check cache
        now = time.time()
        async with self._lock:
            if hostname in self._cache:
                ips, expiry = self._cache[hostname]
                if now < expiry:
                    return ips

        # Build DNS query wire format
        qname = b"".join(
            len(p).to_bytes(1, "big") + p.encode()
            for p in hostname.split(".")
        ) + b"\x00"
        # Standard DNS query header (ID=0x1234, RD=1, QDCOUNT=1)
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        question = qname + struct.pack("!HH", 1, 1)  # TYPE A, CLASS IN
        dns_wire = header + question

        # Send via domain‑fronted HTTPS to dns.google
        raw_response = await self._doe_request(dns_wire)
        ips = self._parse_a_records(raw_response)

        # Cache
        if ips:
            async with self._lock:
                self._cache[hostname] = (ips, now + self._ttl)

        if not ips:
            raise OSError(f"DoE resolve failed for {hostname}")

        return ips

    async def _doe_request(self, dns_wire: bytes) -> bytes:
        """Send DNS wire-format query to dns.google over domain-fronted TLS."""
        loop = asyncio.get_event_loop()

        # Create socket (SOCKS5 if proxy configured)
        if socks and self.proxy_addr:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, self.proxy_addr, self.proxy_port)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        await loop.sock_connect(s, (self.google_ip, 443))

        # TLS with SNI = www.google.com
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(s, server_hostname=self.sni)

        # HTTP/2 or HTTP/1.1 POST to dns.google
        body = dns_wire
        request = (
            f"POST /dns-query HTTP/1.1\r\n"
            f"Host: {DOE_HOST}\r\n"
            f"Content-Type: application/dns-message\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Accept: application/dns-message\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        ssock.sendall(request.encode() + body)

        # Read response
        response = b""
        while True:
            chunk = ssock.recv(65536)
            if not chunk:
                break
            response += chunk
        ssock.close()

        # Split HTTP headers from body
        if b"\r\n\r\n" in response:
            _, body = response.split(b"\r\n\r\n", 1)
            return body
        return response

    def _parse_a_records(self, data: bytes) -> list[str]:
        """Extract IPv4 addresses from DNS response."""
        ips = []
        try:
            offset = 12  # Skip header
            # Skip question section
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 5

            # Parse answers
            while offset < len(data):
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(data) and data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1
                if offset + 10 > len(data):
                    break
                rtype = struct.unpack("!H", data[offset:offset+2])[0]
                rdlength = struct.unpack("!H", data[offset+8:offset+10])[0]
                if rtype == 1 and rdlength == 4:
                    ip = socket.inet_ntoa(data[offset+10:offset+14])
                    ips.append(ip)
                offset += 10 + rdlength
        except Exception:
            pass
        return ips

# Global singleton
_fronted_resolver: FrontedDoHResolver | None = None

def init(google_ip="216.239.38.120", sni="www.google.com",
         proxy_addr=None, proxy_port=None):
    global _fronted_resolver
    _fronted_resolver = FrontedDoHResolver(
        google_ip=google_ip,
        sni=sni,
        proxy_addr=proxy_addr,
        proxy_port=proxy_port,
    )
    log.info("FrontedDoH initialized")

async def resolve(hostname: str) -> list[str]:
    if _fronted_resolver is None:
        raise RuntimeError("FrontedDoH not initialized. Call doh_fronted.init() first.")
    return await _fronted_resolver.resolve(hostname)