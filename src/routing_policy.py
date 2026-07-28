"""
Central smart routing policy.

The policy exists to reduce Google Apps Script quota use: Iranian destinations
go direct, explicitly allowed Google hosts use the existing fronted/direct path,
and only foreign HTTP(S) traffic needs the Apps Script -> Worker relay.
Unsupported protocol traffic is fail-closed so clients fall back to TCP/HTTPS
instead of leaking or burning relay quota.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class RouteDecision(StrEnum):
    IR_DIRECT = "IR_DIRECT"
    GOOGLE_FRONTED_DIRECT = "GOOGLE_FRONTED_DIRECT"
    RELAY_REQUIRED = "RELAY_REQUIRED"
    FAIL_CLOSED_COMPAT = "FAIL_CLOSED_COMPAT"


@dataclass(frozen=True)
class RouteResult:
    decision: RouteDecision
    reason: str


@dataclass(frozen=True)
class GeoIpLoadResult:
    networks: tuple[IpNetwork, ...]
    warning: str | None = None


class RoutingPolicy:
    """Decide how a host/protocol should leave the proxy."""

    HTTP_PORTS = frozenset({80, 443})
    _IRAN_DOMAIN_SUFFIX_CACHE: dict[str, bool] = {}
    _IRAN_CACHE_MAX = 8192

    def __init__(
        self,
        config: dict,
        *,
        google_owned_exact: set[str] | frozenset[str],
        google_owned_suffixes: tuple[str, ...],
        google_allow_exact: set[str],
        google_allow_suffixes: tuple[str, ...],
        google_exclude_exact: set[str],
        google_exclude_suffixes: tuple[str, ...],
        sni_rewrite_suffixes: tuple[str, ...],
    ):
        self.routing_mode = str(config.get("routing_mode", "compat_smart")).lower()
        self.iran_direct_enabled = bool(config.get("iran_direct_enabled", True))
        self.iran_geoip_enabled = bool(config.get("iran_geoip_enabled", True))
        self.iran_geoip_required = bool(config.get("iran_geoip_required", False))
        self.google_fronted_direct_enabled = bool(
            config.get("google_fronted_direct_enabled", True)
        )
        self.relay_foreign_enabled = bool(config.get("relay_foreign_enabled", True))
        self.compat_block_udp_quic = bool(config.get("compat_block_udp_quic", True))
        self.websocket_mode = str(config.get("websocket_mode", "relay")).lower()
        self.tcp_worker_ws_enabled = str(
            config.get("tcp_relay_mode", "http_only")
        ).lower() in {"worker_websocket", "worker_ws", "websocket"}
        self.iran_domain_suffixes = _normalize_suffixes(
            config.get("iran_domain_suffixes", [".ir"])
        )
        self.iran_domains = {
            str(item).strip().lower().rstrip(".")
            for item in config.get("iran_domains", [])
            if str(item).strip()
        }
        self.iran_geoip_db = str(config.get("iran_geoip_db", "data/geoip/ir.cidr"))

        self.google_owned_exact = {h.lower().rstrip(".") for h in google_owned_exact}
        self.google_owned_suffixes = google_owned_suffixes
        self.google_allow_exact = google_allow_exact
        self.google_allow_suffixes = google_allow_suffixes
        self.google_exclude_exact = google_exclude_exact
        self.google_exclude_suffixes = google_exclude_suffixes
        self.sni_rewrite_suffixes = sni_rewrite_suffixes

        loaded = load_geoip_networks(self.iran_geoip_db)
        self.iran_networks = loaded.networks if self.iran_geoip_enabled else ()
        self.geoip_warning = loaded.warning if self.iran_geoip_enabled else None

    def decide_host(
        self,
        host: str,
        port: int = 443,
        *,
        scheme: str = "https",
        protocol: str = "tcp",
        is_websocket: bool = False,
    ) -> RouteResult:
        h = _normalize_host(host)
        proto = protocol.lower()

        if proto == "udp":
            if self.compat_block_udp_quic:
                return RouteResult(
                    RouteDecision.FAIL_CLOSED_COMPAT,
                    "udp/quic blocked for client tcp fallback",
                )
            return RouteResult(RouteDecision.FAIL_CLOSED_COMPAT, "udp carrier unavailable")

        if is_websocket and self.websocket_mode == "block":
            return RouteResult(
                RouteDecision.FAIL_CLOSED_COMPAT,
                "websocket blocked by config",
            )
        if port not in self.HTTP_PORTS:
            if self.tcp_worker_ws_enabled:
                return RouteResult(
                    RouteDecision.RELAY_REQUIRED,
                    "tcp relay via worker websocket",
                )
            return RouteResult(
                RouteDecision.FAIL_CLOSED_COMPAT,
                "non-http tcp blocked for compatibility fallback",
            )

        if self.iran_direct_enabled and self.is_iran_destination(h):
            return RouteResult(RouteDecision.IR_DIRECT, "iran destination")

        if (
            self.google_fronted_direct_enabled
            and self.is_google_fronted_direct(h)
        ):
            return RouteResult(
                RouteDecision.GOOGLE_FRONTED_DIRECT,
                "allowed google/fronted destination",
            )

        if self.relay_foreign_enabled and scheme.lower() in {"http", "https"}:
            return RouteResult(RouteDecision.RELAY_REQUIRED, "foreign http relay")

        return RouteResult(RouteDecision.FAIL_CLOSED_COMPAT, "relay disabled")

    def is_iran_destination(self, host: str) -> bool:
        h = _normalize_host(host)
        if not h:
            return False

        # Check cache first
        cached = self._IRAN_DOMAIN_SUFFIX_CACHE.get(h)
        if cached is not None:
            return cached

        if h in self.iran_domains or any(h == suffix.lstrip(".") or h.endswith(suffix) for suffix in self.iran_domain_suffixes):
            result = True
        else:
            ip = _parse_ip(h)
            if ip is not None:
                result = any(ip in network for network in self.iran_networks)
            else:
                result = False

        if len(self._IRAN_DOMAIN_SUFFIX_CACHE) > self._IRAN_CACHE_MAX:
            self._IRAN_DOMAIN_SUFFIX_CACHE.clear()
        self._IRAN_DOMAIN_SUFFIX_CACHE[h] = result
        return result

    def is_google_fronted_direct(self, host: str) -> bool:
        h = _normalize_host(host)
        if not h:
            return False
        if self.is_google_excluded(h):
            return False
        if self.is_google_allowed(h):
            return True
        return any(h == suffix or h.endswith("." + suffix) for suffix in self.sni_rewrite_suffixes)

    def is_google_owned(self, host: str) -> bool:
        h = _normalize_host(host)
        if h in self.google_owned_exact:
            return True
        return any(h.endswith(suffix) for suffix in self.google_owned_suffixes)

    def is_google_allowed(self, host: str) -> bool:
        h = _normalize_host(host)
        if h in self.google_allow_exact:
            return True
        return any(h.endswith(suffix) for suffix in self.google_allow_suffixes)

    def is_google_excluded(self, host: str) -> bool:
        h = _normalize_host(host)
        if h in self.google_exclude_exact:
            return True
        return any(h.endswith(suffix) for suffix in self.google_exclude_suffixes)


def _normalize_suffixes(raw) -> tuple[str, ...]:
    values = raw if isinstance(raw, (list, tuple)) else [raw]
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        suffix = str(item).strip().lower().rstrip(".")
        if not suffix:
            continue
        if not suffix.startswith("."):
            suffix = "." + suffix
        if suffix not in seen:
            seen.add(suffix)
            out.append(suffix)
    return tuple(out)


def _normalize_host(host: str) -> str:
    return str(host or "").strip().strip("[]").lower().rstrip(".")


def _parse_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def load_geoip_networks(path: str) -> GeoIpLoadResult:
    if not path:
        return GeoIpLoadResult((), "iran_geoip_db is empty")
    db_path = Path(path)
    if not db_path.exists():
        return GeoIpLoadResult((), f"GeoIP CIDR file not found: {path}")

    networks: list[IpNetwork] = []
    try:
        for lineno, line in enumerate(db_path.read_text(encoding="utf-8").splitlines(), start=1):
            item = line.split("#", 1)[0].strip()
            if not item:
                continue
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
    except OSError as exc:
        return GeoIpLoadResult((), f"Could not read GeoIP CIDR file: {exc}")
    return GeoIpLoadResult(tuple(networks))
