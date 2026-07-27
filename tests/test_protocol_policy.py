from protocol_policy import (
    SOCKS5_CMD_BIND,
    SOCKS5_CMD_CONNECT,
    SOCKS5_CMD_UDP_ASSOCIATE,
    ProtocolPolicy,
)


def test_default_blocks_raw_tcp_and_udp():
    policy = ProtocolPolicy({})

    tcp = policy.tcp_decision("example.com", 22)
    udp = policy.udp_decision("example.com", 443)
    socks_udp = policy.socks_command_decision(SOCKS5_CMD_UDP_ASSOCIATE)

    assert tcp.fail_closed
    assert "raw TCP" in tcp.reason
    assert udp.fail_closed
    assert "QUIC" in udp.reason
    assert socks_udp.fail_closed


def test_http_ports_are_relayable_without_direct_leak():
    policy = ProtocolPolicy({})

    decision = policy.tcp_decision("example.com", 443)

    assert decision.allow_relay
    assert not decision.allow_direct
    assert not decision.fail_closed


def test_worker_websocket_mode_is_ignored_for_google_relay_only():
    policy = ProtocolPolicy({"tcp_relay_mode": "worker_websocket"})

    decision = policy.tcp_decision("example.com", 5228)

    assert not decision.allow_relay
    assert not decision.allow_direct
    assert decision.fail_closed
    assert not policy.worker_websocket_tcp_enabled


def test_socks5_commands_are_fail_closed_except_connect():
    policy = ProtocolPolicy({})

    connect = policy.socks_command_decision(SOCKS5_CMD_CONNECT)
    bind = policy.socks_command_decision(SOCKS5_CMD_BIND)

    assert connect.allow_relay
    assert bind.fail_closed


def test_direct_udp_is_fail_closed_even_when_requested():
    policy = ProtocolPolicy({"allow_direct_udp": True, "quic_mode": "direct"})

    decision = policy.udp_decision("example.com", 1234)

    assert not decision.allow_direct
    assert decision.fail_closed
