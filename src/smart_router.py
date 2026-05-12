import time, logging
log = logging.getLogger("SmartRoute")
CF_HEADERS = ("cf-ray", "cf-request-id", "__cf")
CAPTCHA_PATTERNS = ("captcha", "challenge", "turnstile", "just a moment")
class CloudflareDetector:
    def __init__(self): self._cache = {}
    def is_behind_cloudflare(self, host, response_headers=None):
        if host in self._cache: return self._cache[host]
        if response_headers:
            for h in CF_HEADERS:
                if h in response_headers: self._cache[host] = True; return True
        return False
    def is_blocked_by_cf(self, status, body_hint=""):
        if status in (403, 503): return True
        if body_hint:
            low = body_hint.lower()
            if any(p in low for p in CAPTCHA_PATTERNS): return True
        return False
    def mark_blocked(self, host, ttl=600):
        self._cache[host] = True
    def mark_clear(self, host):
        self._cache.pop(host, None)

from domain_map import DOMAIN_DEPENDENCIES
class DependencyResolver:
    @staticmethod
    def get_dependencies(host):
        h = host.lower().rstrip(".")
        if h in DOMAIN_DEPENDENCIES: return DOMAIN_DEPENDENCIES[h]
        for domain, deps in DOMAIN_DEPENDENCIES.items():
            if h.endswith("." + domain): return deps
        return []