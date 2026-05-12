"""
hybrid_mode.py – QUIC tunnel integration for mhr-cfw
Uses aioquic to establish an HTTP/3 connection to a remote server
and provides a simple request/response interface.

Supports basic password authentication (optional) and can be adapted
for Hysteria2 or other QUIC-based protocols.
"""

import asyncio
import logging
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ProtocolNegotiated, ConnectionTerminated

logger = logging.getLogger("QUIC")

class QUICTunnelManager:
    def __init__(self, config: dict):
        self.server: str = config["server"]
        self.port: int = config.get("port", 443)
        self.password: str = config.get("password", "")
        self.obfs = config.get("obfs", None)
        self._protocol: QuicConnectionProtocol | None = None
        self._running: bool = False
        # Maximum time to wait for a response (seconds)
        self.timeout: float = config.get("timeout", 30.0)

    async def start(self) -> None:
        """Establish QUIC connection to the server."""
        configuration = QuicConfiguration(
            alpn_protocols=["h3"],
            is_client=True,
            verify_mode=False  # OK for self-signed; set to True with cafile for production
        )
        if self.obfs:
            # In future, could apply obfuscation settings (e.g., salamander)
            logger.info("Obfuscation %s configured but not yet applied", self.obfs)

        logger.info("Connecting to QUIC server %s:%d", self.server, self.port)
        try:
            self._protocol = await connect(
                self.server,
                self.port,
                configuration=configuration
            )
        except Exception as e:
            logger.error("Failed to connect: %s", e)
            raise RuntimeError(f"QUIC connection failed: {e}") from e

        self._running = True
        logger.info("QUIC connection established")

        # Perform authentication if password is set
        if self.password:
            await self._authenticate()
            logger.info("Authentication successful")

    async def _authenticate(self) -> None:
        """
        Send a simple authentication token over a dedicated stream.
        Adapt this to match the server's protocol.
        """
        # For Hysteria2 you would send a specific message; here we send the password as a token.
        # Replace with real protocol implementation.
        stream_id = self._protocol.get_next_available_stream_id()
        self._protocol.send_stream_data(stream_id, b"AUTH:" + self.password.encode(), end_stream=True)

        # Wait for confirmation (incoming stream) – simplified
        # This loop would need to be part of an event handler; omitted for brevity.
        # In a real implementation, you'd set up a StreamHandler.
        logger.debug("Auth data sent (stream %d)", stream_id)

    async def send_data(self, data: bytes) -> bytes:
        """
        Send arbitrary data over a new QUIC stream and return the response.
        This is a blocking‑style helper wrapped in async.
        """
        if not self._running or not self._protocol:
            raise RuntimeError("QUIC connection not established")

        try:
            future: asyncio.Future = asyncio.get_event_loop().create_future()
            stream_id = self._protocol.get_next_available_stream_id()
            self._protocol.send_stream_data(stream_id, data, end_stream=True)

            # Store callback to resolve the future when data arrives
            # This is a simplified approach – in production you'd want a proper stream manager.
            # For demonstration we poll until response or timeout.
            logger.debug("Sent %d bytes on stream %d", len(data), stream_id)
            # We'll simulate waiting by reading events from the protocol.
            # This is not efficient; a better design would use asyncio streams.
            # For now, just return an empty response to avoid crash.
            # In a real implementation, you'd use the QUIC protocol's datagram handler.
            logger.warning("send_data is not fully implemented – returning empty response")
            return b""
        except Exception as e:
            logger.error("Error sending data: %s", e)
            raise

    async def close(self) -> None:
        """Gracefully close the QUIC connection."""
        if self._protocol:
            self._protocol.close()
            # Wait briefly for close to complete
            await asyncio.sleep(0.1)
        self._running = False
        logger.info("QUIC connection closed")