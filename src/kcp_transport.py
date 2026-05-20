"""
KCP-style reliability primitives for future UDP/QUIC encapsulation.

This is not wired to the live proxy yet. It gives the project a concrete,
testable session model: sequence numbers, acknowledgements, retransmission
timers, receive buffering, and flow-window limits. The actual carrier can be a
Worker WebSocket, HTTP stream, or a future Rust forwarder.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

CMD_PUSH = 81
CMD_ACK = 82
CMD_PING = 83
CMD_CLOSE = 84

HEADER = struct.Struct("!IBIII")


@dataclass(frozen=True)
class KcpFrame:
    conv: int
    cmd: int
    seq: int
    ack: int
    payload: bytes = b""

    def encode(self) -> bytes:
        return HEADER.pack(self.conv, self.cmd, self.seq, self.ack, len(self.payload)) + self.payload

    @classmethod
    def decode(cls, raw: bytes) -> KcpFrame:
        if len(raw) < HEADER.size:
            raise ValueError("KCP frame is shorter than header")
        conv, cmd, seq, ack, size = HEADER.unpack(raw[:HEADER.size])
        payload = raw[HEADER.size:]
        if len(payload) != size:
            raise ValueError("KCP frame payload length mismatch")
        return cls(conv=conv, cmd=cmd, seq=seq, ack=ack, payload=payload)


@dataclass
class _Inflight:
    frame: KcpFrame
    sent_at: float
    retries: int = 0


class KcpSession:
    """Small KCP-style ARQ session.

    The session emits frames to send via `queue_data()` and `tick()`, accepts
    frames from the carrier via `input_frame()`, and yields ordered payloads
    through `recv_ready()`.
    """

    def __init__(
        self,
        conv: int,
        *,
        mtu: int = 1200,
        window: int = 64,
        resend_after: float = 0.18,
        max_retries: int = 8,
        now: float | None = None,
    ):
        self.conv = int(conv)
        self.mtu = max(256, int(mtu))
        self.window = max(1, int(window))
        self.resend_after = max(0.02, float(resend_after))
        self.max_retries = max(1, int(max_retries))
        self._next_seq = 1
        self._expected_seq = 1
        self._last_ack = 0
        self._inflight: dict[int, _Inflight] = {}
        self._recv_buffer: dict[int, bytes] = {}
        self._closed = False
        self._now = time.monotonic() if now is None else float(now)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def inflight_count(self) -> int:
        return len(self._inflight)

    def queue_data(self, data: bytes, *, now: float | None = None) -> list[KcpFrame]:
        if self._closed:
            raise RuntimeError("KCP session is closed")
        self._set_now(now)
        usable_payload = self.mtu - HEADER.size
        if usable_payload <= 0:
            raise ValueError("MTU too small for KCP frame header")

        emitted: list[KcpFrame] = []
        offset = 0
        while offset < len(data) and len(self._inflight) < self.window:
            chunk = data[offset:offset + usable_payload]
            frame = KcpFrame(self.conv, CMD_PUSH, self._next_seq, self._last_ack, chunk)
            self._inflight[frame.seq] = _Inflight(frame, self._now)
            emitted.append(frame)
            self._next_seq += 1
            offset += len(chunk)
        if offset < len(data):
            raise BufferError("KCP send window is full")
        return emitted

    def input_frame(self, frame: KcpFrame, *, now: float | None = None) -> list[KcpFrame]:
        self._set_now(now)
        if frame.conv != self.conv:
            raise ValueError("KCP conversation id mismatch")
        self._apply_ack(frame.ack)

        if frame.cmd == CMD_ACK:
            return []
        if frame.cmd == CMD_CLOSE:
            self._closed = True
            return [KcpFrame(self.conv, CMD_ACK, 0, self._last_ack)]
        if frame.cmd == CMD_PING:
            return [KcpFrame(self.conv, CMD_ACK, 0, self._last_ack)]
        if frame.cmd != CMD_PUSH:
            return []

        if frame.seq >= self._expected_seq:
            self._recv_buffer.setdefault(frame.seq, frame.payload)
        while self._expected_seq in self._recv_buffer:
            self._last_ack = self._expected_seq
            self._expected_seq += 1
        return [KcpFrame(self.conv, CMD_ACK, 0, self._last_ack)]

    def recv_ready(self) -> list[bytes]:
        ready: list[bytes] = []
        seq = 1
        # Deliver contiguous payloads below the next expected sequence.
        while seq < self._expected_seq:
            payload = self._recv_buffer.pop(seq, None)
            if payload is not None:
                ready.append(payload)
            seq += 1
        return ready

    def tick(self, *, now: float | None = None) -> list[KcpFrame]:
        self._set_now(now)
        if self._closed:
            return []
        resend: list[KcpFrame] = []
        for seq, item in list(self._inflight.items()):
            if self._now - item.sent_at < self.resend_after:
                continue
            if item.retries >= self.max_retries:
                self._closed = True
                raise TimeoutError(f"KCP frame {seq} exceeded retry budget")
            item.retries += 1
            item.sent_at = self._now
            resend.append(item.frame)
        return resend

    def close_frame(self) -> KcpFrame:
        self._closed = True
        return KcpFrame(self.conv, CMD_CLOSE, 0, self._last_ack)

    def _apply_ack(self, ack: int) -> None:
        if ack <= 0:
            return
        for seq in list(self._inflight):
            if seq <= ack:
                self._inflight.pop(seq, None)

    def _set_now(self, now: float | None) -> None:
        if now is not None:
            self._now = float(now)
        else:
            self._now = time.monotonic()
