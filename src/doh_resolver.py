"""
doh_resolver.py — DNS over HTTPS resolver
Replaces system DNS to prevent DNS leaks and bypass DNS filtering.
"""

import asyncio
import json
import socket
import struct
from urllib.parse import urlparse

import aiohttp

DOE_DNS_SERVERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://1.1.1.1/dns-query",
]

class DoHResolver:
    def __init__(self, proxy=None):
        self._session = None
        self._proxy = proxy  # e.g., "http://127.0.0.1:8080"
        self._cache: dict[str, list[str]] = {}
        self._lock = asyncio.Lock()

    async def _get_session(self):
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self._session

    async def resolve(self, host: str) -> list[str]:
        """Resolve a hostname to a list of IPv4 addresses via DoH."""
        # Check cache first
        async with self._lock:
            if host in self._cache:
                return self._cache[host]

        # Build DNS query packet (A record request)
        qname = b"".join(
            len(part).to_bytes(1, "big") + part.encode()
            for part in host.split(".")
        ) + b"\x00"
        dns_query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)

        # Send to DoH server
        session = await self._get_session()
        for server_url in DOE_DNS_SERVERS:
            try:
                headers = {
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                }
                async with session.post(
                    server_url,
                    data=dns_query,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                    proxy=self._proxy,
                ) as resp:
                    if resp.status == 200:
                        raw = await resp.read()
                        ips = self._parse_dns_response(raw)
                        if ips:
                            async with self._lock:
                                self._cache[host] = ips
                            return ips
            except Exception:
                continue

        # Fallback to system DNS if DoH fails
        return await self._system_resolve(host)

    def _parse_dns_response(self, data: bytes) -> list[str]:
        """Extract IPv4 addresses from DNS response."""
        ips = []
        try:
            offset = 12  # Skip header
            # Skip question section
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 5  # Skip null byte + QTYPE + QCLASS

            # Parse answers
            while offset < len(data):
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1
                if offset + 10 > len(data):
                    break
                rtype = struct.unpack("!H", data[offset:offset+2])[0]
                rdlength = struct.unpack("!H", data[offset+8:offset+10])[0]
                if rtype == 1 and rdlength == 4:  # A record
                    ip = socket.inet_ntoa(data[offset+10:offset+14])
                    ips.append(ip)
                offset += 10 + rdlength
        except Exception:
            pass
        return ips

    async def _system_resolve(self, host: str) -> list[str]:
        """Fallback to system getaddrinfo."""
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            return list(set(addr[4][0] for addr in infos))
        except Exception:
            return []

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None

# Global singleton
_default_resolver = DoHResolver()

async def resolve(host: str) -> list[str]:
    """Convenience function to resolve a hostname."""
    return await _default_resolver.resolve(host)

def set_proxy(proxy_url: str):
    """Set a proxy for DoH requests (useful when you need to route DoH through your own proxy)."""
    _default_resolver._proxy = proxy_url