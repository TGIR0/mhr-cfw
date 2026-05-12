# src/stats.py — آمار و گزارش‌ها
import time
import logging
from dataclasses import dataclass, field
from collections import defaultdict

from constants import STATS_LOG_INTERVAL, STATS_LOG_TOP_N

log = logging.getLogger("Fronter")


@dataclass
class HostStat:
    requests: int = 0
    errors: int = 0
    bytes: int = 0
    total_latency_ns: int = 0

    @property
    def avg_ms(self) -> float:
        if self.requests == 0:
            return 0.0
        return self.total_latency_ns / self.requests / 1_000_000


class StatsCollector:
    """جمع‌آوری و گزارش آمار per-host"""

    def __init__(self):
        self._data: dict[str, HostStat] = defaultdict(HostStat)
        self._task: asyncio.Task | None = None

    def record(self, host: str, bytes_count: int, latency_ns: int, errored: bool):
        stat = self._data[host]
        stat.requests += 1
        stat.bytes += max(0, bytes_count)
        stat.total_latency_ns += max(0, latency_ns)
        if errored:
            stat.errors += 1

    def snapshot(self) -> list[dict]:
        items = []
        for host, s in self._data.items():
            items.append({
                "host": host,
                "requests": s.requests,
                "errors": s.errors,
                "bytes": s.bytes,
                "avg_ms": round(s.avg_ms, 1),
            })
        items.sort(key=lambda x: x["bytes"], reverse=True)
        return items

    async def start_logger(self):
        """لاگ دوره‌ای آمار"""
        while True:
            try:
                await asyncio.sleep(STATS_LOG_INTERVAL)
                if not log.isEnabledFor(logging.DEBUG):
                    continue
                snap = self.snapshot()
                if not snap:
                    continue
                top = snap[:STATS_LOG_TOP_N]
                log.debug("── Per-host stats (top %d) ──", len(top))
                for row in top:
                    log.debug("  %-40s %5d req  %2d err  %8d KB  avg %7.1f ms",
                              row["host"][:40], row["requests"], row["errors"],
                              row["bytes"] // 1024, row["avg_ms"])
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("Stats logger: %s", e)