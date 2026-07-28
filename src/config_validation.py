"""
Configuration validation for TG Domain Relay.

The validator is intentionally conservative: unsupported transport settings are
reported before startup so users do not accidentally turn a future protocol knob
into a direct network leak.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from routing_policy import load_geoip_networks

ERROR = "ERROR"
WARNING = "WARNING"

_PLACEHOLDER_AUTH_KEYS = {
    "",
    "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "STRONG_SECRET_KEY",
    "your-secret-password-here",
}

_PLACEHOLDER_SCRIPT_IDS = {
    "",
    "YOUR_APPS_SCRIPT_DEPLOYMENT_ID",
    "YOUR_SCRIPT_ID",
}

_SAFE_TCP_RELAY_MODES = {
    "http_only",
    "disabled",
}

_WORKER_WS_TCP_MODES = {
    "worker_websocket",
    "worker_ws",
    "websocket",
}

_UDP_MODES = {
    "disabled",
    "kcp",
    "encapsulated",
}

_QUIC_MODES = {
    "block",
    "encapsulated",
    "direct",
}

_ROUTING_MODES = {
    "compat_smart",
}

_WEBSOCKET_MODES = {
    "http_only",
    "relay",
    "block",
    "disabled",
}


@dataclass(frozen=True)
class ConfigIssue:
    severity: str
    key: str
    message: str


def validate_config(config: dict) -> list[ConfigIssue]:
    """Return startup-blocking errors and operator warnings.

    The function never prints secrets and does not mutate the input dict.
    """
    issues: list[ConfigIssue] = []

    auth_key = str(config.get("auth_key", ""))
    if auth_key in _PLACEHOLDER_AUTH_KEYS:
        issues.append(ConfigIssue(
            ERROR,
            "auth_key",
            "auth_key is missing or still uses a known placeholder.",
        ))

    script_ids = _script_ids(config)
    if not script_ids:
        issues.append(ConfigIssue(
            ERROR,
            "script_id",
            "Apps Script deployment ID is missing.",
        ))
    for idx, sid in enumerate(script_ids):
        if sid in _PLACEHOLDER_SCRIPT_IDS:
            key = "script_id" if len(script_ids) == 1 else f"script_ids[{idx}]"
            issues.append(ConfigIssue(
                ERROR,
                key,
                "Apps Script deployment ID still uses a placeholder.",
            ))

    listen_host = str(config.get("listen_host", "127.0.0.1"))
    listen_port = _as_int(config.get("listen_port", 8080), 8080)
    socks_enabled = bool(config.get("socks5_enabled", True))
    socks_host = str(config.get("socks5_host", listen_host))
    socks_port = _as_int(config.get("socks5_port", 1080), 1080)
    if socks_enabled and listen_host == socks_host and listen_port == socks_port:
        issues.append(ConfigIssue(
            ERROR,
            "socks5_port",
            "HTTP and SOCKS5 listeners cannot use the same host and port.",
        ))

    lan_sharing = bool(config.get("lan_sharing", False))
    if lan_sharing or listen_host in {"0.0.0.0", "::"}:
        issues.append(ConfigIssue(
            WARNING,
            "listen_host",
            "Proxy is reachable from the LAN; protect the host firewall and do not expose it publicly.",
        ))

    if bool(config.get("allow_direct_tcp", False)):
        issues.append(ConfigIssue(
            WARNING,
            "allow_direct_tcp",
            "Direct raw TCP is enabled; unsupported TCP can leave outside the relay path.",
        ))
    if bool(config.get("allow_direct_udp", False)):
        issues.append(ConfigIssue(
            WARNING,
            "allow_direct_udp",
            "Direct UDP is enabled; UDP/QUIC can leave outside the relay path.",
        ))

    privacy_log_mode = str(config.get("privacy_log_mode", "host")).lower()
    if privacy_log_mode not in {"host", "full", "off"}:
        issues.append(ConfigIssue(
            ERROR,
            "privacy_log_mode",
            "Unknown privacy_log_mode. Use 'host', 'full', or 'off'.",
        ))
    elif privacy_log_mode == "full":
        issues.append(ConfigIssue(
            WARNING,
            "privacy_log_mode",
            "Full URL logging can expose paths, query strings, and tokens.",
        ))

    _validate_routing(config, issues)

    udp_mode = str(config.get("udp_mode", "disabled")).lower()
    if udp_mode not in _UDP_MODES:
        issues.append(ConfigIssue(
            ERROR,
            "udp_mode",
            f"Unknown UDP mode '{udp_mode}'. Use one of: {', '.join(sorted(_UDP_MODES))}.",
        ))
    elif udp_mode != "disabled":
        issues.append(ConfigIssue(
            WARNING,
            "udp_mode",
            "UDP carrier is not wired yet; SOCKS5 UDP remains fail-closed.",
        ))


    quic_mode = str(config.get("quic_mode", "block")).lower()
    if quic_mode not in _QUIC_MODES:
        issues.append(ConfigIssue(
            ERROR,
            "quic_mode",
            f"Unknown QUIC mode '{quic_mode}'. Use one of: {', '.join(sorted(_QUIC_MODES))}.",
        ))
    elif quic_mode != "block":
        issues.append(ConfigIssue(
            WARNING,
            "quic_mode",
            "QUIC needs an encapsulated UDP carrier; Apps Script and Worker fetch do not provide UDP egress.",
        ))

    tcp_mode = str(config.get("tcp_relay_mode", "http_only")).lower()
    if tcp_mode in _WORKER_WS_TCP_MODES:
        issues.append(ConfigIssue(
            WARNING,
            "tcp_relay_mode",
            "Worker WebSocket TCP is ignored in google-relay-only mode; raw TCP remains fail-closed.",
        ))
    elif tcp_mode not in _SAFE_TCP_RELAY_MODES:
        issues.append(ConfigIssue(
            ERROR,
            "tcp_relay_mode",
            "Unknown TCP relay mode. Use 'http_only' or 'worker_websocket'.",
        ))

    _validate_worker_ws(config, issues)
    _validate_direct_worker(config, issues)

    return issues


def _validate_routing(config: dict, issues: list[ConfigIssue]) -> None:
    routing_mode = str(config.get("routing_mode", "compat_smart")).lower()
    if routing_mode not in _ROUTING_MODES:
        issues.append(ConfigIssue(
            ERROR,
            "routing_mode",
            "Unknown routing_mode. Use 'compat_smart'.",
        ))

    websocket_mode = str(config.get("websocket_mode", "relay")).lower()
    if websocket_mode not in _WEBSOCKET_MODES:
        issues.append(ConfigIssue(
            ERROR,
            "websocket_mode",
            f"Unknown websocket_mode. Use one of: {', '.join(sorted(_WEBSOCKET_MODES))}.",
        ))

    if bool(config.get("iran_geoip_enabled", True)):
        db_path = str(config.get("iran_geoip_db", "data/geoip/ir.cidr"))
        loaded = load_geoip_networks(db_path)
        if loaded.warning:
            severity = ERROR if bool(config.get("iran_geoip_required", False)) else WARNING
            issues.append(ConfigIssue(severity, "iran_geoip_db", loaded.warning))


def has_errors(issues: list[ConfigIssue]) -> bool:
    return any(issue.severity == ERROR for issue in issues)


def format_issues(issues: list[ConfigIssue]) -> str:
    if not issues:
        return "Config validation passed."
    lines = []
    for issue in issues:
        lines.append(f"[{issue.severity}] {issue.key}: {issue.message}")
    return "\n".join(lines)


def _validate_worker_ws(config: dict, issues: list[ConfigIssue]) -> None:
    tcp_mode = str(config.get("tcp_relay_mode", "http_only")).lower()
    if tcp_mode not in {"worker_websocket", "worker_ws", "websocket"}:
        return
    url = str(config.get("worker_ws_url", "")).strip()
    if not url:
        issues.append(ConfigIssue(
            ERROR,
            "worker_ws_url",
            "tcp_relay_mode=worker_websocket requires a wss:// Worker WebSocket URL.",
        ))
        return
    parsed = urlparse(url)
    if parsed.scheme != "wss" or not parsed.netloc:
        issues.append(ConfigIssue(
            ERROR,
            "worker_ws_url",
            "Worker WebSocket URL must be absolute and use wss://.",
        ))
    ws_key = str(config.get("worker_ws_auth_key") or config.get("auth_key", ""))
    if ws_key in _PLACEHOLDER_AUTH_KEYS:
        issues.append(ConfigIssue(
            ERROR,
            "worker_ws_auth_key",
            "Worker WebSocket auth key is missing or still uses a placeholder.",
        ))


def _validate_direct_worker(config: dict, issues: list[ConfigIssue]) -> None:
    if not bool(config.get("direct_worker_enabled", False)):
        return
    issues.append(ConfigIssue(
        WARNING,
        "direct_worker_enabled",
        "Direct Worker is ignored in google-relay-only mode; foreign traffic stays on Apps Script -> Worker.",
    ))


def _script_ids(config: dict) -> list[str]:
    raw = config.get("script_ids") or config.get("script_id")
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if raw is None:
        return []
    item = str(raw).strip()
    return [item] if item else []


def _as_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
