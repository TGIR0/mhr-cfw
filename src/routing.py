"""منطق مسیریابی هاست و دامنه‌های گوگل"""
import time
from constants import (
    GOOGLE_DIRECT_EXACT_EXCLUDE, GOOGLE_DIRECT_SUFFIX_EXCLUDE,
    GOOGLE_DIRECT_ALLOW_EXACT, GOOGLE_DIRECT_ALLOW_SUFFIXES,
    GOOGLE_OWNED_EXACT, GOOGLE_OWNED_SUFFIXES, SNI_REWRITE_SUFFIXES
)

class HostRouter:
    def __init__(self, direct_exclude: set[str], direct_allow: set[str], hosts: dict, fronter):
        self._direct_google_exclude = direct_exclude
        self._direct_google_allow = direct_allow
        self._hosts = hosts
        self._fronter = fronter
        self._direct_fail_until: dict[str, float] = {}

    def is_google_domain(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        if self._is_direct_excluded(h): return False
        if not self._is_google_owned(h): return False
        return self._is_direct_allowed(h)

    def _is_google_owned(self, host: str) -> bool:
        if host in GOOGLE_OWNED_EXACT: return True
        return any(host.endswith(s) for s in GOOGLE_OWNED_SUFFIXES)

    def _is_direct_excluded(self, host: str) -> bool:
        if host in self._direct_google_exclude: return True
        for s in GOOGLE_DIRECT_SUFFIX_EXCLUDE:
            if host.endswith(s): return True
        return any(host.endswith(t) for t in self._direct_google_exclude if t.startswith("."))

    def _is_direct_allowed(self, host: str) -> bool:
        if host in self._direct_google_allow: return True
        for s in GOOGLE_DIRECT_ALLOW_SUFFIXES:
            if host.endswith(s): return True
        return any(host.endswith(t) for t in self._direct_google_allow if t.startswith("."))

    def sni_rewrite_ip(self, host: str) -> str | None:
        ip = self._hosts_ip(host)
        if ip: return ip
        h = host.lower().rstrip(".")
        for suffix in SNI_REWRITE_SUFFIXES:
            if h == suffix or h.endswith("." + suffix):
                return self._fronter.connect_host
        return None

    def _hosts_ip(self, host: str) -> str | None:
        h = host.lower().rstrip(".")
        if h in self._hosts: return self._hosts[h]
        parts = h.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._hosts: return self._hosts[parent]
        return None

    def is_direct_disabled(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        now = time.time()
        for key in _failure_keys(h):
            until = self._direct_fail_until.get(key, 0)
            if until > now: return True
            self._direct_fail_until.pop(key, None)
        return False

    def remember_failure(self, host: str, ttl: int = 600):
        until = time.time() + ttl
        for key in _failure_keys(host.lower().rstrip(".")):
            self._direct_fail_until[key] = until

def _failure_keys(host: str) -> tuple[str, ...]:
    keys = [host]
    if host.endswith(".google.com") or host == "google.com": keys.append("*.google.com")
    if host.endswith(".googleapis.com") or host == "googleapis.com": keys.append("*.googleapis.com")
    if host.endswith(".gstatic.com") or host == "gstatic.com": keys.append("*.gstatic.com")
    if host.endswith(".googleusercontent.com") or host == "googleusercontent.com": keys.append("*.googleusercontent.com")
    return tuple(dict.fromkeys(keys))