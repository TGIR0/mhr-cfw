"""سیستم کش LRU برای پاسخ‌های HTTP"""
import time
import re
from constants import STATIC_EXTS, CACHE_TTL_MAX, CACHE_TTL_STATIC_LONG, CACHE_TTL_STATIC_MED

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
        if size > self._max // 4 or size == 0: return
        while self._size + size > self._max and self._store:
            oldest = next(iter(self._store))
            self._size -= len(self._store[oldest][0])
            del self._store[oldest]
        if url in self._store: self._size -= len(self._store[url][0])
        self._store[url] = (raw_response, time.time() + ttl)
        self._size += size

    @staticmethod
    def parse_ttl(raw_response: bytes, url: str) -> int:
        hdr_end = raw_response.find(b"\r\n\r\n")
        if hdr_end < 0: return 0
        hdr = raw_response[:hdr_end].decode(errors="replace").lower()
        if b"HTTP/1.1 200" not in raw_response[:20]: return 0
        if "no-store" in hdr or "private" in hdr or "set-cookie:" in hdr: return 0
        m = re.search(r"max-age=(\d+)", hdr)
        if m: return min(int(m.group(1)), CACHE_TTL_MAX)
        path = url.split("?")[0].lower()
        for ext in STATIC_EXTS:
            if path.endswith(ext): return CACHE_TTL_STATIC_LONG
        ct_m = re.search(r"content-type:\s*([^\r\n]+)", hdr)
        ct = ct_m.group(1) if ct_m else ""
        if "image/" in ct or "font/" in ct: return CACHE_TTL_STATIC_LONG
        if "text/css" in ct or "javascript" in ct: return CACHE_TTL_STATIC_MED
        if "text/html" in ct or "application/json" in ct: return 0
        return 0