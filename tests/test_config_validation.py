from config_validation import ERROR, WARNING, has_errors, validate_config


def valid_config(**overrides):
    config = {
        "script_id": "AKfycbx-valid-deployment",
        "auth_key": "not-a-placeholder-secret",
        "listen_host": "127.0.0.1",
        "listen_port": 8085,
        "socks5_enabled": True,
        "socks5_host": "127.0.0.1",
        "socks5_port": 1080,
        "udp_mode": "disabled",
        "quic_mode": "block",
        "iran_geoip_enabled": False,
    }
    config.update(overrides)
    return config


def severities(issues):
    return {(issue.severity, issue.key) for issue in issues}


def test_valid_config_has_no_errors():
    issues = validate_config(valid_config())

    assert not has_errors(issues)


def test_placeholders_are_errors():
    issues = validate_config(valid_config(
        script_id="YOUR_APPS_SCRIPT_DEPLOYMENT_ID",
        auth_key="CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
    ))

    keys = severities(issues)
    assert (ERROR, "script_id") in keys
    assert (ERROR, "auth_key") in keys
    assert has_errors(issues)


def test_port_collision_is_error():
    issues = validate_config(valid_config(socks5_port=8085))

    assert (ERROR, "socks5_port") in severities(issues)


def test_lan_and_direct_modes_are_warnings():
    issues = validate_config(valid_config(
        listen_host="0.0.0.0",
        allow_direct_tcp=True,
        allow_direct_udp=True,
    ))

    keys = severities(issues)
    assert (WARNING, "listen_host") in keys
    assert (WARNING, "allow_direct_tcp") in keys
    assert (WARNING, "allow_direct_udp") in keys
    assert not has_errors(issues)


def test_full_privacy_log_mode_warns_and_unknown_mode_errors():
    full_issues = validate_config(valid_config(privacy_log_mode="full"))
    bad_issues = validate_config(valid_config(privacy_log_mode="verbose"))

    assert (WARNING, "privacy_log_mode") in severities(full_issues)
    assert not has_errors(full_issues)
    assert (ERROR, "privacy_log_mode") in severities(bad_issues)
    assert has_errors(bad_issues)


def test_missing_geoip_db_warns_unless_required():
    warn_issues = validate_config(valid_config(
        iran_geoip_enabled=True,
        iran_geoip_db="missing-ir.cidr",
    ))
    error_issues = validate_config(valid_config(
        iran_geoip_enabled=True,
        iran_geoip_required=True,
        iran_geoip_db="missing-ir.cidr",
    ))

    assert (WARNING, "iran_geoip_db") in severities(warn_issues)
    assert not has_errors(warn_issues)
    assert (ERROR, "iran_geoip_db") in severities(error_issues)
    assert has_errors(error_issues)


def test_routing_and_websocket_modes_are_validated():
    routing = validate_config(valid_config(routing_mode="unknown"))
    websocket = validate_config(valid_config(websocket_mode="full"))

    assert (ERROR, "routing_mode") in severities(routing)
    assert (ERROR, "websocket_mode") in severities(websocket)


def test_udp_and_quic_non_default_modes_warn_not_error():
    issues = validate_config(valid_config(udp_mode="kcp", quic_mode="encapsulated"))

    keys = severities(issues)
    assert (WARNING, "udp_mode") in keys
    assert (WARNING, "quic_mode") in keys
    assert not has_errors(issues)


def test_worker_websocket_mode_warns_but_stays_fail_closed():
    issues = validate_config(valid_config(tcp_relay_mode="worker_websocket"))

    assert (WARNING, "tcp_relay_mode") in severities(issues)
    assert not has_errors(issues)


def test_worker_websocket_url_is_ignored_in_google_relay_only_mode():
    issues = validate_config(valid_config(
        tcp_relay_mode="worker_websocket",
        worker_ws_url="https://relay.example/tcp",
    ))

    assert (WARNING, "tcp_relay_mode") in severities(issues)
    assert not has_errors(issues)


def test_worker_websocket_wss_url_is_still_ignored():
    issues = validate_config(valid_config(
        tcp_relay_mode="worker_websocket",
        worker_ws_url="wss://relay.example/tcp",
    ))

    assert (WARNING, "tcp_relay_mode") in severities(issues)
    assert not has_errors(issues)


def test_direct_worker_is_ignored_in_google_relay_only_mode():
    issues = validate_config(valid_config(
        direct_worker_enabled=True,
        worker_url="http://relay.example",
    ))

    assert (WARNING, "direct_worker_enabled") in severities(issues)
    assert not has_errors(issues)


def test_direct_worker_derives_https_url_from_websocket_url():
    issues = validate_config(valid_config(
        direct_worker_enabled=True,
        worker_ws_url="wss://relay.example/tcp",
        worker_auth_key="not-a-placeholder-secret",
    ))

    keys = severities(issues)
    assert (WARNING, "direct_worker_enabled") in keys
    assert not has_errors(issues)


def test_direct_worker_requires_non_placeholder_auth():
    issues = validate_config(valid_config(
        direct_worker_enabled=True,
        worker_url="https://relay.example",
        worker_auth_key="CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
        auth_key="CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
    ))

    keys = severities(issues)
    assert (ERROR, "auth_key") in keys
    assert (WARNING, "direct_worker_enabled") in severities(issues)
    assert has_errors(issues)
