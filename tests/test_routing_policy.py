from routing_policy import RouteDecision, RoutingPolicy


def make_policy(**overrides):
    config = {
        "iran_direct_enabled": True,
        "iran_domain_suffixes": [".ir"],
        "iran_geoip_enabled": False,
        "google_fronted_direct_enabled": True,
        "relay_foreign_enabled": True,
        "compat_block_udp_quic": True,
        "websocket_mode": "http_only",
    }
    config.update(overrides)
    return RoutingPolicy(
        config,
        google_owned_exact={"google.com"},
        google_owned_suffixes=(".google.com", ".gstatic.com"),
        google_allow_exact={"www.google.com", "google.com"},
        google_allow_suffixes=(),
        google_exclude_exact={"accounts.google.com", "drive.google.com"},
        google_exclude_suffixes=(),
        sni_rewrite_suffixes=("youtube.com", "fonts.googleapis.com"),
    )


def test_ir_domain_routes_direct():
    policy = make_policy()

    result = policy.decide_host("example.ir", 443)

    assert result.decision == RouteDecision.IR_DIRECT


def test_ir_geoip_routes_direct(tmp_path):
    db = tmp_path / "ir.cidr"
    db.write_text("5.160.0.0/12\n", encoding="utf-8")
    policy = make_policy(iran_geoip_enabled=True, iran_geoip_db=str(db))

    result = policy.decide_host("5.160.1.10", 443)

    assert result.decision == RouteDecision.IR_DIRECT


def test_foreign_ip_routes_to_relay():
    policy = make_policy(iran_geoip_enabled=True, iran_geoip_db="")

    result = policy.decide_host("1.1.1.1", 443)

    assert result.decision == RouteDecision.RELAY_REQUIRED


def test_allowed_google_routes_fronted_direct():
    policy = make_policy()

    result = policy.decide_host("www.google.com", 443)

    assert result.decision == RouteDecision.GOOGLE_FRONTED_DIRECT


def test_excluded_google_does_not_route_direct():
    policy = make_policy()

    result = policy.decide_host("accounts.google.com", 443)

    assert result.decision == RouteDecision.RELAY_REQUIRED


def test_sni_rewrite_google_like_host_routes_fronted_direct():
    policy = make_policy()

    result = policy.decide_host("www.youtube.com", 443)

    assert result.decision == RouteDecision.GOOGLE_FRONTED_DIRECT


def test_udp_and_websocket_fail_closed_for_compatibility():
    policy = make_policy()

    udp = policy.decide_host("example.com", 443, protocol="udp")
    ws = policy.decide_host("example.com", 443, is_websocket=True)

    assert udp.decision == RouteDecision.FAIL_CLOSED_COMPAT
    assert ws.decision == RouteDecision.FAIL_CLOSED_COMPAT
