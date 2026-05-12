# src/domain_fronter.py — نسخه نهایی ماژولار
import asyncio
import logging
import time

from constants import (
    FRONT_SNI_POOL_GOOGLE, RELAY_TIMEOUT, TLS_CONNECT_TIMEOUT,
    MAX_RESPONSE_BODY_BYTES, PARALLEL_RELAY_MAX,
)
from pool import ConnectionPool
from relay import RelayEngine
from batch import BatchEngine
from stats import StatsCollector

log = logging.getLogger("Fronter")


class DomainFronter:
    def __init__(self, config: dict):
        self.connect_host = config.get("google_ip", "216.239.38.120")
        self.sni_host = config.get("front_domain", "www.google.com")
        self.verify_ssl = config.get("verify_ssl", True)
        self.auth_key = config.get("auth_key", "")

        script = config.get("script_ids") or config.get("script_id")
        self._script_ids = script if isinstance(script, list) else [script]

        # SNI rotation
        self._sni_hosts = self._build_sni(config)
        self._sni_idx = 0

        # Connection pool
        self._pool = ConnectionPool(
            self.connect_host, self._sni_hosts,
            self._sni_idx, self.verify_ssl,
            config.get("tls_connect_timeout", TLS_CONNECT_TIMEOUT)
        )

        # Relay engine
        self._relay_engine = RelayEngine(
            self._pool, self.auth_key, self._script_ids,
            config.get("relay_timeout", RELAY_TIMEOUT),
            worker_secret=config.get("WORKER_SECRET", "")
        )

        # Batching
        self._batch = BatchEngine(self._relay_engine.relay)

        # Stats
        self._stats = StatsCollector()

        self._warmed = False

    def _build_sni(self, config: dict) -> list[str]:
        fd = self.sni_host.lower().rstrip(".")
        overrides = config.get("front_domains")
        if overrides:
            seen = set()
            out = []
            for h in overrides:
                h = str(h).strip().lower().rstrip(".")
                if h and h not in seen:
                    seen.add(h)
                    out.append(h)
            if out:
                return out
        if fd.endswith(".google.com") or fd == "google.com":
            return [fd] + [h for h in FRONT_SNI_POOL_GOOGLE if h != fd]
        return [fd] if fd else ["www.google.com"]

    async def relay(self, method: str, url: str, headers: dict, body: bytes = b"") -> bytes:
        if not self._warmed:
            await self._pool.warm()
            self._warmed = True

        t0 = time.perf_counter()
        try:
            result = await self._batch.submit(
                self._relay_engine._build_payload(method, url, headers, body)
            )
            latency = int((time.perf_counter() - t0) * 1e9)
            host = url.split('/')[2] if '//' in url else url
            self._stats.record(host, len(result), latency, False)
            return result
        except Exception:
            latency = int((time.perf_counter() - t0) * 1e9)
            host = url.split('/')[2] if '//' in url else url
            self._stats.record(host, 0, latency, True)
            raise

    def stats_snapshot(self) -> list[dict]:
        return self._stats.snapshot()

    async def close(self):
        await self._pool.close()