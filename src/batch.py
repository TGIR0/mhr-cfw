# src/batch.py — سیستم بچینگ و coalescing برای DomainFronter
import asyncio
import logging
import time

from constants import BATCH_MAX, BATCH_WINDOW_MICRO, BATCH_WINDOW_MACRO

log = logging.getLogger("Fronter")


class BatchEngine:
    """مدیریت درخواست‌های گروهی و ادغام"""

    def __init__(self, relay_fn):
        self._relay = relay_fn  # تابع رله اصلی
        self._lock = asyncio.Lock()
        self._pending: list[tuple[dict, asyncio.Future]] = []
        self._timer_task: asyncio.Task | None = None
        self._batch_max = BATCH_MAX
        self._window_micro = BATCH_WINDOW_MICRO
        self._window_macro = BATCH_WINDOW_MACRO
        self._enabled = True
        self._disabled_at = 0.0
        self._cooldown = 60
        self._coalesce: dict[str, list[asyncio.Future]] = {}

    async def submit(self, payload: dict, coalesce_key: str | None = None) -> bytes:
        # Coalescing: اگر کلید یکسان وجود داشت، منتظر نتیجه آن شو
        if coalesce_key:
            async with self._lock:
                waiters = self._coalesce.get(coalesce_key)
                if waiters is not None:
                    future = asyncio.get_running_loop().create_future()
                    waiters.append(future)
                    return await future
                self._coalesce[coalesce_key] = []

        # Batch submission
        if not self._enabled:
            if time.time() - self._disabled_at >= self._cooldown:
                self._enabled = True
            else:
                return await self._relay(payload)

        future = asyncio.get_running_loop().create_future()
        async with self._lock:
            self._pending.append((payload, future))
            if len(self._pending) >= self._batch_max:
                batch = self._pending[:]
                self._pending.clear()
                if self._timer_task and not self._timer_task.done():
                    self._timer_task.cancel()
                self._timer_task = None
                asyncio.create_task(self._send_batch(batch))
            elif self._timer_task is None or self._timer_task.done():
                self._timer_task = asyncio.create_task(self._timer())

        result = await future

        # Wake coalesced waiters
        if coalesce_key:
            async with self._lock:
                waiters = self._coalesce.pop(coalesce_key, [])
            for w in waiters:
                if not w.done():
                    w.set_result(result)

        return result

    async def _timer(self):
        await asyncio.sleep(self._window_micro)
        async with self._lock:
            if len(self._pending) <= 1:
                if self._pending:
                    batch = self._pending[:]
                    self._pending.clear()
                    self._timer_task = None
                    asyncio.create_task(self._send_batch(batch))
                return
        await asyncio.sleep(self._window_macro - self._window_micro)
        async with self._lock:
            if self._pending:
                batch = self._pending[:]
                self._pending.clear()
                self._timer_task = None
                asyncio.create_task(self._send_batch(batch))

    async def _send_batch(self, batch: list):
        if len(batch) == 1:
            payload, future = batch[0]
            try:
                result = await self._relay(payload)
                if not future.done():
                    future.set_result(result)
            except Exception as e:
                if not future.done():
                    future.set_result(self._error(502, str(e)))
        else:
            try:
                # ساخت batch payload
                batch_payload = {"q": [p for p, _ in batch]}
                result = await self._relay(batch_payload)
                # parse batch response
                data = __import__('json').loads(result)
                items = data.get("q", [])
                for (_, future), item in zip(batch, items):
                    if not future.done():
                        future.set_result(item if isinstance(item, bytes) else str(item).encode())
            except Exception as e:
                self._enabled = False
                self._disabled_at = time.time()
                await asyncio.gather(*[
                    self._relay(p) for p, _ in batch
                ])

    @staticmethod
    def _error(status: int, message: str) -> bytes:
        body = f"<html><body><h1>{status}</h1><p>{message}</p></body></html>"
        return (f"HTTP/1.1 {status} Error\r\nContent-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n\r\n{body}").encode()