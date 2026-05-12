# src/pool.py — مدیریت پول اتصال TLS برای DomainFronter
import asyncio
import logging
import socket
import ssl
import time

try:
    import certifi
except ImportError:
    certifi = None

from constants import (
    POOL_MAX, POOL_MIN_IDLE, CONN_TTL, SEMAPHORE_MAX,
    TLS_CONNECT_TIMEOUT, WARM_POOL_COUNT,
)

log = logging.getLogger("Fronter")


class ConnectionPool:
    def __init__(self, connect_host: str, sni_hosts: list[str], sni_idx,
                 verify_ssl: bool, tls_connect_timeout: float):
        self._connect_host = connect_host
        self._sni_hosts = sni_hosts
        self._sni_idx = sni_idx
        self._verify_ssl = verify_ssl
        self._tls_connect_timeout = tls_connect_timeout
        self._pool: list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]] = []
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(SEMAPHORE_MAX)
        self._warmed = False
        self._refilling = False
        self._bg_tasks: set[asyncio.Task] = set()
        self._sessions: dict[str, object] = {}

    async def acquire(self):
        now = asyncio.get_running_loop().time()
        async with self._lock:
            while self._pool:
                reader, writer, created = self._pool.pop()
                if (now - created) < CONN_TTL and not reader.at_eof():
                    asyncio.create_task(self._add_one())
                    return reader, writer, created
                try: writer.close()
                except Exception: pass
        reader, writer = await asyncio.wait_for(self._open(), timeout=self._tls_connect_timeout)
        if not self._refilling:
            self._refilling = True
            self._spawn(self._refill())
        return reader, writer, asyncio.get_running_loop().time()

    async def release(self, reader, writer, created):
        now = asyncio.get_running_loop().time()
        if (now - created) >= CONN_TTL or reader.at_eof():
            try: writer.close()
            except Exception: pass
            return
        async with self._lock:
            if len(self._pool) < POOL_MAX:
                self._pool.append((reader, writer, created))
            else:
                try: writer.close()
                except Exception: pass

    async def _open(self):
        loop = asyncio.get_running_loop()
        ip = self._connect_host

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if hasattr(socket, 'TCP_QUICKACK'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
        sock.setblocking(False)

        await loop.sock_connect(sock, (ip, 443))
        ctx = ssl.create_default_context()
        if certifi is not None:
            try: ctx.load_verify_locations(cafile=certifi.where())
            except Exception: pass
        if not self._verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        sni = self._sni_hosts[self._sni_idx % len(self._sni_hosts)]
        self._sni_idx += 1
        return await asyncio.open_connection(sock=sock, ssl=ctx, server_hostname=sni)

    async def _add_one(self):
        try:
            r, w = await asyncio.wait_for(self._open(), timeout=5)
            t = asyncio.get_running_loop().time()
            async with self._lock:
                if len(self._pool) < POOL_MAX:
                    self._pool.append((r, w, t))
                else:
                    try: w.close()
                    except Exception: pass
        except Exception: pass

    async def _refill(self):
        try:
            coros = [self._add_one() for _ in range(8)]
            await asyncio.gather(*coros, return_exceptions=True)
        finally:
            self._refilling = False

    async def maintenance(self):
        while True:
            try:
                await asyncio.sleep(3)
                now = asyncio.get_running_loop().time()
                async with self._lock:
                    alive = []
                    for r, w, t in self._pool:
                        if (now - t) < CONN_TTL and not r.at_eof():
                            alive.append((r, w, t))
                        else:
                            try: w.close()
                            except Exception: pass
                    self._pool = alive
                    idle = len(self._pool)
                needed = max(0, POOL_MIN_IDLE - idle)
                if needed > 0:
                    coros = [self._add_one() for _ in range(min(needed, 5))]
                    await asyncio.gather(*coros, return_exceptions=True)
            except asyncio.CancelledError: break
            except Exception: pass

    async def warm(self):
        if self._warmed: return
        self._warmed = True
        coros = [self._add_one() for _ in range(WARM_POOL_COUNT)]
        results = await asyncio.gather(*coros, return_exceptions=True)
        opened = sum(1 for r in results if not isinstance(r, Exception))
        log.info("Pre-warmed %d/%d TLS connections", opened, WARM_POOL_COUNT)

    async def flush(self):
        async with self._lock:
            for _, writer, _ in self._pool:
                try: writer.close()
                except Exception: pass
            self._pool.clear()

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    async def close(self):
        for t in list(self._bg_tasks):
            t.cancel()
        if self._bg_tasks:
            await asyncio.gather(*self._bg_tasks, return_exceptions=True)
        self._bg_tasks.clear()
        await self.flush()