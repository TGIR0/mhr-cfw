"""
HTTP/2 multiplexed transport for domain-fronted connections.

One TLS connection → many concurrent HTTP/2 streams → massive throughput.
Eliminates per-request TLS handshake overhead entirely.

Requires: pip install h2
"""

import asyncio
import logging
import socket
import ssl
from urllib.parse import urlparse
import contextlib

try:
    import certifi
except Exception:
    certifi = None

import codec

log = logging.getLogger("H2")

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


class _StreamState:
    __slots__ = ("status", "headers", "data", "done", "error")

    def __init__(self):
        self.status = 0
        self.headers: dict[str, str] = {}
        self.data = bytearray()
        self.done = asyncio.Event()
        self.error: str | None = None


class H2Transport:

    _RECONNECT_MIN_INTERVAL = 1.0
    _MAX_RESPONSE_BYTES = 200 * 1024 * 1024
    _IDLE_TIMEOUT = 300
    _MAX_RETRIES = 3

    def __init__(self, connect_host: str, sni_host: str,
                 verify_ssl: bool = True,
                 sni_hosts: list[str] | None = None):
        self.connect_host = connect_host
        self.sni_host = sni_host
        self.verify_ssl = verify_ssl
        self._sni_hosts: list[str] = [h for h in (sni_hosts or []) if h] or [sni_host]
        self._sni_idx: int = 0

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._h2: h2.connection.H2Connection | None = None
        self._connected = False

        self._conn_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._read_task: asyncio.Task | None = None
        self._conn_generation = 0
        self._last_reconnect_at: float = 0.0

        self._streams: dict[int, _StreamState] = {}

        self.total_requests = 0
        self.total_streams = 0

    # ── Connection lifecycle ──────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def ensure_connected(self):
        if self._connected:
            return
        async with self._connect_lock:
            if self._connected:
                return
            await self._do_connect()

    async def _do_connect(self):
        ctx = ssl.create_default_context()
        if certifi is not None:
            with contextlib.suppress(Exception):
                ctx.load_verify_locations(cafile=certifi.where())
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        sni = self._sni_hosts[self._sni_idx % len(self._sni_hosts)]
        self._sni_idx += 1
        self.sni_host = sni

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with contextlib.suppress(OSError, AttributeError):
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        raw.setblocking(False)

        try:
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_connect(
                    raw, (self.connect_host, 443),
                ),
                timeout=15,
            )
            self._reader, self._writer = await asyncio.open_connection(
                ssl=ctx, server_hostname=sni, sock=raw,
            )
        except Exception:
            raw.close()
            raise

        ssl_obj = self._writer.get_extra_info("ssl_object")
        negotiated = ssl_obj.selected_alpn_protocol() if ssl_obj else None
        if negotiated != "h2":
            self._writer.close()
            raise RuntimeError(f"H2 ALPN negotiation failed (got {negotiated!r})")

        config = h2.config.H2Configuration(
            client_side=True, header_encoding="utf-8",
        )

        async with self._conn_lock:
            self._h2 = h2.connection.H2Connection(config=config)
            self._h2.initiate_connection()
            self._h2.increment_flow_control_window(2 ** 24 - 65535)
            self._h2.update_settings({
                h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 8 * 1024 * 1024,
                h2.settings.SettingCodes.ENABLE_PUSH: 0,
            })
            await self._flush_unlocked()

        self._connected = True
        self._conn_generation += 1
        generation = self._conn_generation
        self._read_task = asyncio.create_task(self._reader_loop(generation))
        log.info("H2 connected → %s (SNI=%s)", self.connect_host, sni)

    async def reconnect(self):
        async with self._connect_lock:
            loop = asyncio.get_running_loop()
            elapsed = loop.time() - self._last_reconnect_at
            if elapsed < self._RECONNECT_MIN_INTERVAL:
                await asyncio.sleep(self._RECONNECT_MIN_INTERVAL - elapsed)
            self._last_reconnect_at = loop.time()
            await self._close_internal()
            await self._do_connect()

    async def _close_internal(self):
        self._connected = False
        read_task = self._read_task
        self._read_task = None
        if read_task and not read_task.done():
            read_task.cancel()
            await asyncio.gather(read_task, return_exceptions=True)

        writer_to_close = None
        async with self._conn_lock:
            writer_to_close = self._writer
            self._writer = None
            self._reader = None
            self._h2 = None
            for state in list(self._streams.values()):
                state.error = "Connection closed"
                state.done.set()
            self._streams.clear()

        if writer_to_close:
            with contextlib.suppress(Exception):
                writer_to_close.close()
                await writer_to_close.wait_closed()

    # ── Public API ────────────────────────────────────────────────

    async def request(self, method: str, path: str, host: str,
                      headers: dict | None = None,
                      body: bytes | None = None,
                      timeout: float = 25,
                      follow_redirects: int = 5) -> tuple[int, dict, bytes]:
        await self.ensure_connected()
        self.total_requests += 1

        for _ in range(follow_redirects + 1):
            status, resp_headers, resp_body = await self._single_request(
                method, path, host, headers, body, timeout,
            )

            if status not in (301, 302, 303, 307, 308):
                return status, resp_headers, resp_body

            location = resp_headers.get("location", "")
            if not location:
                return status, resp_headers, resp_body

            parsed = urlparse(location)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            host = parsed.netloc or host
            if status not in (307, 308):
                method = "GET"
                body = None
                headers = None

        return status, resp_headers, resp_body

    # ── Stream handling ───────────────────────────────────────────

    async def _single_request(self, method, path, host, headers, body,
                              timeout) -> tuple[int, dict, bytes]:
        if not self._connected:
            await self.ensure_connected()

        state: _StreamState | None = None
        stream_id = 0

        for attempt in range(self._MAX_RETRIES):
            try:
                async with self._conn_lock:
                    stream_id = self._h2.get_next_available_stream_id()

                    h2_headers = [
                        (":method", method.upper()),
                        (":path", path),
                        (":authority", host),
                        (":scheme", "https"),
                        ("accept-encoding", codec.supported_encodings()),
                    ]
                    if headers:
                        for k, v in headers.items():
                            kl = k.lower()
                            if kl == "accept-encoding":
                                continue
                            h2_headers.append((kl, str(v)))
                    if body:
                        h2_headers.append(("content-length", str(len(body))))

                    state = _StreamState()
                    self._streams[stream_id] = state
                    self.total_streams += 1

                    end_stream = not body
                    self._h2.send_headers(
                        stream_id, h2_headers, end_stream=end_stream,
                    )
                    if body:
                        self._send_body_unlocked(stream_id, body)

                    await self._flush_unlocked()
                break
            except Exception:
                if attempt == self._MAX_RETRIES - 1:
                    raise
                await self.reconnect()

        try:
            async with asyncio.timeout(timeout):
                await state.done.wait()
        except TimeoutError as exc:
            if state.done.is_set() and not state.error:
                async with self._conn_lock:
                    self._streams.pop(stream_id, None)
            else:
                async with self._conn_lock:
                    self._streams.pop(stream_id, None)
                    if self._connected and self._h2:
                        with contextlib.suppress(Exception):
                            self._h2.reset_stream(stream_id)
                            await self._flush_unlocked()
                raise TimeoutError(
                    f"H2 stream {stream_id} timed out ({timeout}s)",
                ) from exc

        async with self._conn_lock:
            self._streams.pop(stream_id, None)

        if state.error:
            raise ConnectionError(f"H2 stream error: {state.error}")

        resp_body = bytes(state.data)
        enc = state.headers.get("content-encoding", "")
        if enc:
            resp_body = codec.decode(resp_body, enc)

        return state.status, state.headers, resp_body

    def _send_body_unlocked(self, stream_id: int, body: bytes):
        total = len(body)
        window = self._h2.remote_flow_control_window(stream_id)
        if total > window:
            raise BufferError(
                f"body {total} bytes exceeds flow control window {window}"
            )
        sent = 0
        while body:
            max_size = self._h2.remote_settings.max_frame_size
            window = self._h2.remote_flow_control_window(stream_id)
            send_size = min(len(body), max_size, window)
            if send_size <= 0:
                raise BufferError(
                    f"H2 flow control exhausted after {sent}/{total} bytes"
                )
            end = send_size >= len(body)
            self._h2.send_data(stream_id, body[:send_size], end_stream=end)
            body = body[send_size:]
            sent += send_size

    # ── Background reader ─────────────────────────────────────────

    async def _reader_loop(self, generation: int):
        try:
            while self._connected:
                try:
                    async with asyncio.timeout(self._IDLE_TIMEOUT):
                        data = await self._reader.read(65536)
                except TimeoutError:
                    log.warning("H2 idle timeout (%ds)", self._IDLE_TIMEOUT)
                    break
                if not data:
                    log.warning("H2 remote closed connection")
                    break

                if not self._h2:
                    break
                try:
                    events = self._h2.receive_data(data)
                except Exception as e:
                    log.error("H2 protocol error: %s", e)
                    break

                for event in events:
                    self._dispatch(event)

                async with self._conn_lock:
                    await self._flush_unlocked()

        except asyncio.CancelledError:
            pass
        except ssl.SSLError as e:
            if "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" in str(e):
                log.debug("H2 TLS closed by remote: %s", e)
            else:
                log.error("H2 reader SSL error: %s", e)
        except Exception as e:
            if getattr(e, "winerror", None) == 121:
                log.warning("H2 connection dropped (OS timeout)")
            elif "application data after close notify" in str(e).lower():
                log.debug("H2 reader closed: %s", e)
            else:
                log.error("H2 reader error: %s", e)
        finally:
            if generation != self._conn_generation:
                log.debug("H2 reader ended (stale gen %d)", generation)
            else:
                self._connected = False
                for st in list(self._streams.values()):
                    if not st.done.is_set():
                        st.error = "Connection lost"
                        st.done.set()
                log.info("H2 reader loop ended")

    def _dispatch(self, event):
        if isinstance(event, h2.events.ConnectionTerminated):
            log.warning("H2 GOAWAY (code=%s)", event.error_code)
            self._connected = False
            for st in list(self._streams.values()):
                if not st.done.is_set():
                    st.error = f"GOAWAY (code={event.error_code})"
                    st.done.set()
            return

        sid = getattr(event, "stream_id", None)
        if not sid:
            return

        state = self._streams.get(sid)
        if not state:
            if isinstance(event, h2.events.DataReceived):
                with contextlib.suppress(Exception):
                    self._h2.acknowledge_received_data(
                        event.flow_controlled_length, sid,
                    )
            return

        if isinstance(event, h2.events.ResponseReceived):
            for name, value in event.headers:
                n = name if isinstance(name, str) else name.decode()
                v = value if isinstance(value, str) else value.decode()
                if n == ":status":
                    state.status = int(v)
                else:
                    state.headers[n] = v

        elif isinstance(event, h2.events.DataReceived):
            state.data.extend(event.data)
            if len(state.data) > self._MAX_RESPONSE_BYTES:
                state.error = "response too large"
                state.done.set()
                with contextlib.suppress(Exception):
                    self._h2.reset_stream(sid)
                return
            self._h2.acknowledge_received_data(
                event.flow_controlled_length, sid,
            )

        elif isinstance(event, h2.events.StreamEnded):
            state.done.set()

        elif isinstance(event, h2.events.StreamReset):
            state.error = f"Stream reset (code={event.error_code})"
            state.done.set()

    # ── Internal ──────────────────────────────────────────────────

    async def _flush_unlocked(self):
        if not self._h2 or not self._writer:
            return
        data = self._h2.data_to_send()
        if data:
            self._writer.write(data)
            await self._writer.drain()

    async def close(self):
        if self._h2 and self._connected:
            try:
                async with self._conn_lock:
                    self._h2.close_connection()
                    await self._flush_unlocked()
            except Exception:
                pass
        await self._close_internal()

    async def ping(self):
        if not self._connected or not self._h2:
            return
        try:
            async with self._conn_lock:
                if not self._connected:
                    return
                self._h2.ping(b"\x00" * 8)
                await self._flush_unlocked()
        except Exception as e:
            log.debug("H2 PING failed: %s", e)