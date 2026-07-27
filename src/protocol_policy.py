"""
Central protocol policy.

The relay can safely carry HTTP(S) today. Other protocols must either be
encapsulated through an implemented tunnel transport or refused fail-closed so
the client does not silently leak traffic over the normal network.
"""

from __future__ import annotations

from dataclasses import dataclass

SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_BIND = 0x02
SOCKS5_CMD_UDP_ASSOCIATE = 0x03


TCP_HTTP_PORTS = frozenset({80, 443})
UDP_QUIC_PORTS = frozenset({443, 8443})
UDP_DNS_PORTS = frozenset({53, 853})


@dataclass(frozen=True)
class ProtocolDecision:
    allow_direct: bool
    allow_relay: bool
    fail_closed: bool
    reason: str


class ProtocolPolicy:
    """Decide whether a protocol may leave the local proxy directly."""

    def __init__(self, config: dict):
        self._allow_direct_tcp = bool(config.get("allow_direct_tcp", False))
        self._allow_direct_udp = bool(config.get("allow_direct_udp", False))
        self._udp_mode = str(config.get("udp_mode", "disabled")).lower()
        self._quic_mode = str(config.get("quic_mode", "block")).lower()
        self._kcp_enabled = bool(config.get("kcp_enabled", True))
        self._tcp_relay_mode = str(config.get("tcp_relay_mode", "http_only")).lower()

    @property
    def kcp_enabled(self) -> bool:
        return self._kcp_enabled

    @property
    def udp_mode(self) -> str:
        return self._udp_mode

    @property
    def quic_mode(self) -> str:
        return self._quic_mode

    @property
    def tcp_relay_mode(self) -> str:
        return self._tcp_relay_mode

    @property
    def worker_websocket_tcp_enabled(self) -> bool:
        return False

    def tcp_decision(self, host: str, port: int, *, bypassed: bool = False) -> ProtocolDecision:
        if bypassed:
            return ProtocolDecision(True, False, False, "host is explicitly bypassed")
        if port in TCP_HTTP_PORTS:
            return ProtocolDecision(False, True, False, "HTTP(S) relay supported")
        if self._allow_direct_tcp:
            return ProtocolDecision(
                False,
                False,
                True,
                "direct raw TCP is disabled by compatibility policy",
            )
        return ProtocolDecision(False, False, True, "raw TCP relay is not implemented")

    def socks_command_decision(self, cmd: int) -> ProtocolDecision:
        if cmd == SOCKS5_CMD_CONNECT:
            return ProtocolDecision(False, True, False, "SOCKS5 CONNECT supported")
        if cmd == SOCKS5_CMD_UDP_ASSOCIATE:
            if self._udp_mode in {"kcp", "encapsulated"}:
                return ProtocolDecision(
                    False,
                    False,
                    True,
                    "UDP encapsulation is configured but not implemented yet",
                )
            return ProtocolDecision(False, False, True, "UDP associate disabled")
        if cmd == SOCKS5_CMD_BIND:
            return ProtocolDecision(False, False, True, "SOCKS5 BIND unsupported")
        return ProtocolDecision(False, False, True, f"SOCKS5 command {cmd} unsupported")

    def udp_decision(self, host: str, port: int) -> ProtocolDecision:
        if port in UDP_QUIC_PORTS and self._quic_mode == "block":
            return ProtocolDecision(False, False, True, "QUIC over UDP is blocked by policy")
        if port in UDP_DNS_PORTS and self._udp_mode == "disabled":
            return ProtocolDecision(False, False, True, "UDP DNS relay is not implemented")
        if self._udp_mode in {"kcp", "encapsulated"}:
            return ProtocolDecision(
                False,
                False,
                True,
                "UDP encapsulation is configured but not implemented yet",
            )
        if self._allow_direct_udp:
            return ProtocolDecision(
                False,
                False,
                True,
                "direct UDP is disabled by compatibility policy",
            )
        return ProtocolDecision(False, False, True, "UDP disabled")
