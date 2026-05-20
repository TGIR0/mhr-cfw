from proxy_server import ProxyServer


def make_proxy(**overrides):
    config = {
        "script_id": "AKfycbx-valid-deployment",
        "auth_key": "not-a-placeholder-secret",
        "listen_host": "127.0.0.1",
        "listen_port": 18085,
        "socks5_enabled": False,
        "socks5_port": 11080,
        "front_domain": "www.google.com",
        "google_ip": "216.239.38.120",
        "tcp_relay_mode": "http_only",
    }
    config.update(overrides)
    return ProxyServer(config)


def test_rejects_raw_tcp_by_default_before_acknowledging_tunnel():
    proxy = make_proxy()

    reason = proxy._tunnel_reject_reason("example.com", 22)

    assert reason == "raw TCP relay is not implemented"


def test_allows_http_and_https_relay_by_default():
    proxy = make_proxy()

    assert proxy._tunnel_reject_reason("example.com", 80) is None
    assert proxy._tunnel_reject_reason("example.com", 443) is None


def test_allows_raw_tcp_when_worker_websocket_mode_is_configured():
    proxy = make_proxy(
        tcp_relay_mode="worker_websocket",
        worker_ws_url="wss://relay.example/tcp",
    )

    assert proxy._tunnel_reject_reason("example.com", 5228) is None


def test_block_hosts_override_worker_websocket_mode():
    proxy = make_proxy(
        tcp_relay_mode="worker_websocket",
        worker_ws_url="wss://relay.example/tcp",
        block_hosts=["example.com"],
    )

    assert proxy._tunnel_reject_reason("example.com", 5228) == "matches block_hosts"


def test_bypass_hosts_are_allowed_for_direct_policy():
    proxy = make_proxy(bypass_hosts=["example.com"])

    assert proxy._tunnel_reject_reason("example.com", 5228) is None
