"""
Multi‑URL Quota Failover — automatic switching between multiple
Apps Script deployment IDs on different Google accounts.
"""
import asyncio
import logging
import time

log = logging.getLogger("Failover")


class QuotaFailover:
    """مدیریت چندین Script ID با failover خودکار"""

    def __init__(self, script_ids: list[str], blacklist_ttl: float = 600):
        self._ids = script_ids
        self._blacklist: dict[str, float] = {}  # sid → until timestamp
        self._ttl = blacklist_ttl
        self._idx = 0

    def _next(self) -> str:
        """انتخاب Script ID بعدی با احترام به blacklist"""
        n = len(self._ids)
        if n == 1:
            return self._ids[0]

        # هرس blacklist منقضی شده
        now = time.time()
        self._blacklist = {k: v for k, v in self._blacklist.items() if v > now}

        for _ in range(n):
            sid = self._ids[self._idx % n]
            self._idx += 1
            if sid not in self._blacklist:
                return sid

        # همه بلاک هستند — ریست کن و اولین را برگردان
        self._blacklist.clear()
        log.warning("All script IDs exhausted — resetting blacklist")
        return self._ids[0]

    def blacklist(self, sid: str, reason: str = ""):
        """بلاک کردن یک Script ID موقتاً"""
        if len(self._ids) <= 1:
            return  # نمی‌توان تنها یکی را بلاک کرد
        self._blacklist[sid] = time.time() + self._ttl
        log.warning("Blacklisted %s for %ds%s",
                    sid[-8:] if len(sid) > 8 else sid,
                    int(self._ttl),
                    f" ({reason})" if reason else "")

    def is_blacklisted(self, sid: str) -> bool:
        return sid in self._blacklist and self._blacklist[sid] > time.time()

    @property
    def available_count(self) -> int:
        now = time.time()
        return sum(1 for sid in self._ids if sid not in self._blacklist or self._blacklist[sid] <= now)