"""
Cloudflare Worker WebSocket TCP carrier.

This transport is opt-in and only carries TCP streams. It is meant for protocols
that cannot be represented as HTTP requests but can run over a byte-stream
tunnel. UDP and QUIC still require a separate encapsulated datagram design.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from contextlib import suppress
from dataclasses import dataclass

try:
    from websockets.asyncio.client import connect
except Exception:  # pragma: no cover - dependency is optional at import time
    connect = None


log = logging.getLogger("WorkerWS")


@dataclass(frozen=True)
class WorkerWsConfig:
    url: str
    auth_key: str
    connect_timeout: float = 10.0
    ping_interval: float = 20.0
    ping_timeout: float = 20.0


class WorkerWebSocketTransport:
    """Relay one local TCP stream through a Worker WebSocket endpoint."""

    def __init__(self, config: dict):
        self.config = WorkerWsConfig(
            url=str(config.get("worker_ws_url", "")).strip(),
            auth_key=str(config.get("worker_ws_auth_key") or config.get("auth_key", "")),
            connect_timeout=_cfg_float(config, "worker_ws_connect_timeout", 10.0, minimum=1.0),
            ping_interval=_cfg_float(config, "worker_ws_ping_interval", 20.0, minimum=5.0),
            ping_timeout=_cfg_float(config, "worker_ws_ping_timeout", 20.0, minimum=5.0),
        )
        # Retry configuration for resilience
        self._max_retries = _cfg_int(config, "worker_ws_max_retries", 3, minimum=0)
        self._retry_delay = _cfg_float(config, "worker_ws_retry_delay", 1.0, minimum=0.1)
        self._heartbeat_enabled = config.get("worker_ws_heartbeat", True)
        self._connection_stats = {"successes": 0, "failures": 0, "last_error": None}

    @property
    def enabled(self) -> bool:
        return bool(self.config.url and self.config.auth_key and connect is not None)
    
    @property
    def stats(self) -> dict:
        """Return connection statistics for monitoring."""
        return self._connection_stats.copy()

    async def tunnel(
        self,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        if connect is None:
            log.error("websockets package is not available")
            return False
        if not self.config.url:
            log.error("worker_ws_url is not configured")
            return False

        hello = {
            "v": 1,
            "op": "connect",
            "host": host,
            "port": int(port),
            "k": self.config.auth_key,
        }

        # Retry loop with exponential backoff
        last_exc = None
        for attempt in range(max(1, self._max_retries + 1)):
            try:
                if attempt > 0:
                    delay = self._retry_delay * (2 ** (attempt - 1))
                    log.info("Retrying WebSocket connection (attempt %d/%d) after %.1fs...", 
                            attempt + 1, self._max_retries + 1, delay)
                    await asyncio.sleep(delay)
                
                ws_url = self.config.url
                if self.config.auth_key:
                    sep = "&" if "?" in ws_url else "?"
                    ws_url += f"{sep}k={self.config.auth_key}"
                
                async with connect(
                    ws_url,
                    open_timeout=self.config.connect_timeout,
                    ping_interval=self.config.ping_interval if self._heartbeat_enabled else None,
                    ping_timeout=self.config.ping_timeout,
                    max_size=None,
                    max_queue=32,
                    compression=None,
                ) as ws:
                    await ws.send(json.dumps(hello))
                    async with asyncio.timeout(self.config.connect_timeout):
                        raw = await ws.recv()
                    response = _json_message(raw)
                    if response.get("ok") is not True:
                        log.warning(
                            "Worker WebSocket refused %s:%d: %s",
                            host,
                            port,
                            response.get("e", "unknown error"),
                        )
                        self._connection_stats["failures"] += 1
                        self._connection_stats["last_error"] = response.get("e", "unknown error")
                        return False

                    # Connection successful
                    self._connection_stats["successes"] += 1
                    
                    tasks = [
                        asyncio.create_task(self._client_to_ws(reader, ws)),
                        asyncio.create_task(self._ws_to_client(ws, writer)),
                    ]
                    try:
                        _done, pending = await asyncio.wait(
                            tasks, return_when=asyncio.FIRST_COMPLETED,
                        )
                        for t in pending:
                            t.cancel()
                        if pending:
                            await asyncio.gather(*pending, return_exceptions=True)
                    finally:
                        for t in tasks:
                            if not t.done():
                                t.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
                    return True
                    
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_exc = exc
                self._connection_stats["failures"] += 1
                self._connection_stats["last_error"] = str(exc)
                if attempt < self._max_retries:
                    log.debug("WebSocket attempt %d failed: %s", attempt + 1, exc)
                else:
                    log.warning("Worker WebSocket tunnel failed for %s:%d after %d attempts: %s", 
                               host, port, attempt + 1, exc)
        
        return False

    async def _client_to_ws(self, reader: asyncio.StreamReader, ws) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    with suppress(Exception):
                        await ws.send(json.dumps({"op": "close"}))
                    return
                await ws.send(data)
        except (ConnectionError, asyncio.IncompleteReadError):
            with suppress(Exception):
                await ws.send(json.dumps({"op": "close"}))

    async def _ws_to_client(self, ws, writer: asyncio.StreamWriter) -> None:
        try:
            async for message in ws:
                if isinstance(message, bytes):
                    writer.write(message)
                    await writer.drain()
                    continue
                event = _json_message(message)
                op = event.get("op")
                if op == "data":
                    payload = base64.b64decode(event.get("b", ""))
                    if payload:
                        writer.write(payload)
                        await writer.drain()
                elif op == "close":
                    return
                elif op == "error":
                    log.warning("Worker WebSocket stream error: %s", event.get("e"))
                    return
        finally:
            try:
                if not writer.is_closing() and writer.can_write_eof():
                    writer.write_eof()
            except Exception:
                pass


def _json_message(raw) -> dict:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"e": "non-json control message"}
    return data if isinstance(data, dict) else {"e": "invalid control message"}


def _cfg_float(config: dict, key: str, default: float, *, minimum: float) -> float:
    try:
        value = float(config.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def _cfg_int(config: dict, key: str, default: int, *, minimum: int = 1) -> int:
    try:
        value = int(config.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)
