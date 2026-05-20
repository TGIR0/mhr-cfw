#!/usr/bin/env python3
"""
TG Domain Relay - local HTTP/SOCKS relay via Google Apps Script and
Cloudflare Workers.

Run a local HTTP proxy that tunnels all traffic through a Google Apps
Script relay fronted by www.google.com (TLS SNI shows www.google.com
while the encrypted Host header points at script.google.com).
"""

import argparse
import asyncio
import json
import logging
import os
import sys

import bootstrap  # noqa: F401  # side-effect: keep historical ./src imports working
from cert_installer import install_ca, is_ca_trusted, uninstall_ca
from constants import (
    GOOGLE_DIRECT_ALLOW_EXACT,
    GOOGLE_DIRECT_ALLOW_SUFFIXES,
    GOOGLE_DIRECT_EXACT_EXCLUDE,
    GOOGLE_DIRECT_SUFFIX_EXCLUDE,
    GOOGLE_OWNED_EXACT,
    GOOGLE_OWNED_SUFFIXES,
    PROJECT_DESCRIPTION,
    PROJECT_SLUG,
    SNI_REWRITE_SUFFIXES,
    __version__,
)
from config_validation import format_issues, has_errors, validate_config
from google_ip_scanner import scan_sync
from lan_utils import log_lan_access
from logging_utils import configure as configure_logging
from logging_utils import print_banner
from mitm import CA_CERT_FILE
from proxy_server import ProxyServer
from routing_policy import RoutingPolicy


def setup_logging(level_name: str):
    configure_logging(level_name)


def _redact_id(value: str, *, visible: int = 8) -> str:
    text = str(value or "").strip()
    if not text:
        return "<empty>"
    if len(text) <= visible:
        return "*" * len(text)
    return f"...{text[-visible:]}"


def parse_args():
    parser = argparse.ArgumentParser(
        prog=PROJECT_SLUG,
        description=PROJECT_DESCRIPTION,
    )
    parser.add_argument(
        "-c", "--config",
        default=os.environ.get("DFT_CONFIG", "config.json"),
        help="Path to config file (default: config.json, env: DFT_CONFIG)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Override listen port (env: DFT_PORT)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override listen host (env: DFT_HOST)",
    )
    parser.add_argument(
        "--socks5-port",
        type=int,
        default=None,
        help="Override SOCKS5 listen port (env: DFT_SOCKS5_PORT)",
    )
    parser.add_argument(
        "--disable-socks5",
        action="store_true",
        help="Disable the built-in SOCKS5 listener.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level (env: DFT_LOG_LEVEL)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--install-cert",
        action="store_true",
        help="Install the MITM CA certificate as a trusted root and exit.",
    )
    parser.add_argument(
        "--uninstall-cert",
        action="store_true",
        help="Remove the MITM CA certificate from trusted roots and exit.",
    )
    parser.add_argument(
        "--no-cert-check",
        action="store_true",
        help="Skip the certificate installation check on startup.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan Google IPs to find the fastest reachable one and exit.",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate config and exit without starting the proxy.",
    )
    parser.add_argument(
        "--routing-check",
        metavar="HOST_OR_IP",
        help="Print the smart-routing decision for a host or IP and exit.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Handle cert-only commands before loading config so they can run standalone.
    if args.install_cert or args.uninstall_cert:
        setup_logging("INFO")
        _log = logging.getLogger("Main")

        if args.install_cert:
            _log.info("Installing CA certificate…")
            if not os.path.exists(CA_CERT_FILE):
                from mitm import MITMCertManager
                MITMCertManager()  # side-effect: creates ca/ca.crt + ca/ca.key
            ok = install_ca(CA_CERT_FILE)
            sys.exit(0 if ok else 1)

        _log.info("Removing CA certificate…")
        ok = uninstall_ca(CA_CERT_FILE)
        if ok:
            _log.info("CA certificate removed successfully.")
        else:
            _log.warning("CA certificate removal may have failed. Check logs above.")
        sys.exit(0 if ok else 1)

    config_path = args.config

    try:
        with open(config_path) as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Config not found: {config_path}")
        # Offer the interactive wizard if it's available and we're on a TTY.
        wizard = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup.py")
        if os.path.exists(wizard) and sys.stdin.isatty():
            try:
                answer = input("Run the interactive setup wizard now? [Y/n]: ").strip().lower()
            except EOFError:
                answer = "n"
            if answer in ("", "y", "yes"):
                import subprocess
                rc = subprocess.call([sys.executable, wizard])
                if rc != 0:
                    sys.exit(rc)
                try:
                    with open(config_path) as f:
                        config = json.load(f)
                except Exception as e:
                    print(f"Could not load config after setup: {e}")
                    sys.exit(1)
            else:
                print("Copy config.example.json to config.json and fill in your values,")
                print("or run: python setup.py")
                sys.exit(1)
        else:
            print("Run: python setup.py   (or copy config.example.json to config.json)")
            sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config: {e}")
        sys.exit(1)

    # Environment variable overrides
    if os.environ.get("DFT_AUTH_KEY"):
        config["auth_key"] = os.environ["DFT_AUTH_KEY"]
    if os.environ.get("DFT_SCRIPT_ID"):
        config["script_id"] = os.environ["DFT_SCRIPT_ID"]

    # CLI argument overrides
    if args.port is not None:
        config["listen_port"] = args.port
    elif os.environ.get("DFT_PORT"):
        config["listen_port"] = int(os.environ["DFT_PORT"])

    if args.host is not None:
        config["listen_host"] = args.host
    elif os.environ.get("DFT_HOST"):
        config["listen_host"] = os.environ["DFT_HOST"]

    if args.socks5_port is not None:
        config["socks5_port"] = args.socks5_port
    elif os.environ.get("DFT_SOCKS5_PORT"):
        config["socks5_port"] = int(os.environ["DFT_SOCKS5_PORT"])

    if args.disable_socks5:
        config["socks5_enabled"] = False

    if args.log_level is not None:
        config["log_level"] = args.log_level
    elif os.environ.get("DFT_LOG_LEVEL"):
        config["log_level"] = os.environ["DFT_LOG_LEVEL"]

    # Always Apps Script mode — force-set for backward-compat configs.
    config["mode"] = "apps_script"

    issues = validate_config(config)
    if args.check_config:
        print(format_issues(issues))
        sys.exit(1 if has_errors(issues) else 0)
    if args.routing_check:
        if has_errors(issues):
            print(format_issues(issues))
            sys.exit(1)
        policy = _routing_policy_for_config(config)
        result = policy.decide_host(args.routing_check)
        print(f"{result.decision.value}: {result.reason}")
        sys.exit(0)
    if has_errors(issues):
        print(format_issues(issues))
        print("Fix config.json or run with --check-config for the full validation report.")
        sys.exit(1)

    # ── Google IP Scanner ──────────────────────────────────────────────────
    if args.scan:
        setup_logging("INFO")
        front_domain = config.get("front_domain", "www.google.com")
        _log = logging.getLogger("Main")
        _log.info(f"Scanning Google IPs (fronting domain: {front_domain})")
        ok = scan_sync(front_domain)
        sys.exit(0 if ok else 1)

    setup_logging(config.get("log_level", "INFO"))
    log = logging.getLogger("Main")

    for issue in issues:
        log.warning("Config warning: %s: %s", issue.key, issue.message)

    print_banner(__version__)
    log.info("%s starting (Apps Script relay)", PROJECT_SLUG)

    log.info("Apps Script relay : SNI=%s → script.google.com",
             config.get("front_domain", "www.google.com"))
    script_ids = config.get("script_ids") or config.get("script_id")
    if isinstance(script_ids, list):
        log.info("Script IDs        : %d scripts (sticky per-host)", len(script_ids))
        for i, sid in enumerate(script_ids):
            log.info("  [%d] %s", i + 1, _redact_id(sid))
    else:
        log.info("Script ID         : %s", _redact_id(script_ids))

    # Ensure CA file exists before checking / installing it.
    # MITMCertManager generates ca/ca.crt on first instantiation.
    if not os.path.exists(CA_CERT_FILE):
        from mitm import MITMCertManager
        MITMCertManager()  # side-effect: creates ca/ca.crt + ca/ca.key

    # Auto-install MITM CA if not already trusted
    if not args.no_cert_check:
        if not is_ca_trusted(CA_CERT_FILE):
            log.warning("MITM CA is not trusted — attempting automatic installation…")
            ok = install_ca(CA_CERT_FILE)
            if ok:
                log.info("CA certificate installed. You may need to restart your browser.")
            else:
                log.error(
                    "Auto-install failed. Run with --install-cert (may need admin/sudo) "
                    "or manually install ca/ca.crt as a trusted root CA."
                )
        else:
            log.info("MITM CA is already trusted.")

    # ── LAN sharing configuration ────────────────────────────────────────
    lan_sharing = config.get("lan_sharing", False)
    listen_host = config.get("listen_host", "127.0.0.1")
    if lan_sharing and listen_host == "127.0.0.1":
        config["listen_host"] = "0.0.0.0"
        listen_host = "0.0.0.0"
        log.info("LAN sharing enabled — listening on all interfaces")

    # If either explicit LAN sharing is enabled or we bind to all interfaces,
    # print concrete IPv4 addresses users can use on other devices.
    lan_mode = lan_sharing or listen_host in ("0.0.0.0", "::")
    if lan_mode:
        socks_port = config.get("socks5_port", 1080) if config.get("socks5_enabled", True) else None
        log_lan_access(config.get("listen_port", 8080), socks_port)

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        log.info("Stopped")


def _make_exception_handler(log):
    """Return an asyncio exception handler that silences Windows WinError 10054
    noise from connection cleanup (ConnectionResetError in
    _ProactorBasePipeTransport._call_connection_lost), which is harmless but
    verbose on Python/Windows when a remote host force-closes a socket."""
    def handler(loop, context):
        exc = context.get("exception")
        cb  = context.get("handle") or context.get("source_traceback", "")
        if (
            isinstance(exc, ConnectionResetError)
            and "_call_connection_lost" in str(cb)
        ):
            return  # suppress: benign Windows socket cleanup race
        log.error("[asyncio]  %s", context.get("message", context))
        if exc:
            loop.default_exception_handler(context)
    return handler


async def _run(config):
    loop = asyncio.get_running_loop()
    _log = logging.getLogger("asyncio")
    loop.set_exception_handler(_make_exception_handler(_log))
    server = ProxyServer(config)
    try:
        await server.start()
    finally:
        await server.stop()


def _routing_policy_for_config(config: dict) -> RoutingPolicy:
    configured_direct_exclude = config.get("direct_google_exclude", [])
    google_exclude = {
        h.lower().rstrip(".")
        for h in (
            list(GOOGLE_DIRECT_EXACT_EXCLUDE) +
            list(configured_direct_exclude)
        )
    }
    configured_direct_allow = config.get("direct_google_allow", [])
    google_allow = {
        h.lower().rstrip(".")
        for h in (
            list(GOOGLE_DIRECT_ALLOW_EXACT) +
            list(configured_direct_allow)
        )
    }
    return RoutingPolicy(
        config,
        google_owned_exact=GOOGLE_OWNED_EXACT,
        google_owned_suffixes=GOOGLE_OWNED_SUFFIXES,
        google_allow_exact=google_allow,
        google_allow_suffixes=GOOGLE_DIRECT_ALLOW_SUFFIXES,
        google_exclude_exact=google_exclude,
        google_exclude_suffixes=GOOGLE_DIRECT_SUFFIX_EXCLUDE,
        sni_rewrite_suffixes=SNI_REWRITE_SUFFIXES,
    )


if __name__ == "__main__":
    main()
