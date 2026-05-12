#!/usr/bin/env python3
"""
DomainFront Tunnel v3.1 - Optimized, secure, and future‑ready entry point.
Bypass DPI censorship via Google Apps Script & Cloudflare Workers.
"""

import argparse
import asyncio
import json
import logging
import os
import sys

# ═══ uvloop — ۲ تا ۴ برابر افزایش سرعت I/O ═══
try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from cert_installer import install_ca, uninstall_ca, is_ca_trusted
from constants import __version__
from lan_utils import log_lan_access
from google_ip_scanner import scan_sync
from logging_utils import configure as _configure_logging, print_banner
from mitm import CA_CERT_FILE
from proxy_server import ProxyServer

_PLACEHOLDER_AUTH_KEYS = {
    "",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "your-secret-password-here",
}

# ── Live Log HTTP Server ──────────────────────────────────────
_LOG_BUFFER: list[str] = []

class _LogHandler(logging.Handler):
    def emit(self, record):
        _LOG_BUFFER.append(self.format(record))
        if len(_LOG_BUFFER) > 200:
            _LOG_BUFFER.pop(0)

async def _log_server(config: dict):
    port = config.get("log_server_port", 9090)
    async def handle(reader, writer):
        try:
            request = (await reader.read(4096)).decode()
            if "GET /logs" in request:
                body = json.dumps(_LOG_BUFFER[-100:], indent=2)
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                    f"{body}"
                )
                writer.write(resp.encode())
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
    await asyncio.start_server(handle, "127.0.0.1", port)
    logging.getLogger("Main").info(f"Log server on http://127.0.0.1:{port}/logs")

def setup_logging(level_name: str) -> None:
    _configure_logging(level_name)

def _valid_port(value: int) -> int:
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError(f"Port must be 1-65535, got {value}")
    return value

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="domainfront-tunnel",
        description="Local HTTP proxy that relays traffic through Google Apps Script.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-c", "--config", default=os.environ.get("DFT_CONFIG", "config.json"), help="Path to config file (default: config.json, env: DFT_CONFIG)")
    parser.add_argument("-p", "--port", type=_valid_port, default=None, help="Override HTTP listen port (env: DFT_PORT)")
    parser.add_argument("--host", default=None, help="Override listen host (env: DFT_HOST)")
    parser.add_argument("--socks5-port", type=_valid_port, default=None, help="Override SOCKS5 port and enable SOCKS5 (env: DFT_SOCKS5_PORT)")
    parser.add_argument("--disable-socks5", action="store_true", help="Disable SOCKS5 listener completely")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default=None, help="Override log level (env: DFT_LOG_LEVEL)")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--install-cert", action="store_true", help="Install the MITM CA certificate as a trusted root and exit.")
    parser.add_argument("--uninstall-cert", action="store_true", help="Remove the MITM CA certificate from trusted roots and exit.")
    parser.add_argument("--no-cert-check", action="store_true", help="Skip the certificate installation check on startup.")
    parser.add_argument("--scan", action="store_true", help="Scan Google IPs to find the fastest reachable one and exit.")
    parser.add_argument("--auth-key", help="Override auth_key (env: DFT_AUTH_KEY)")
    parser.add_argument("--script-id", help="Override script_id (env: DFT_SCRIPT_ID)")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    if args.install_cert or args.uninstall_cert:
        setup_logging("INFO")
        log = logging.getLogger("Main")
        if not os.path.exists(CA_CERT_FILE):
            from mitm import MITMCertManager
            MITMCertManager()
        if args.install_cert:
            log.info("Installing CA certificate...")
            ok = install_ca(CA_CERT_FILE)
            sys.exit(0 if ok else 1)
        else:
            log.info("Removing CA certificate...")
            ok = uninstall_ca(CA_CERT_FILE)
            sys.exit(0 if ok else 1)
    config_path = args.config
    try:
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
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
                with open(config_path, encoding="utf-8") as f:
                    config = json.load(f)
            else:
                print("Create config.json or run python setup.py")
                sys.exit(1)
        else:
            print("Run: python setup.py   (or copy config.example.json to config.json)")
            sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config: {e}")
        sys.exit(1)
    if os.environ.get("DFT_AUTH_KEY"):
        config["auth_key"] = os.environ["DFT_AUTH_KEY"]
    if os.environ.get("DFT_SCRIPT_ID"):
        config["script_id"] = os.environ["DFT_SCRIPT_ID"]
    if args.auth_key is not None:
        config["auth_key"] = args.auth_key
    if args.script_id is not None:
        config["script_id"] = args.script_id
    if args.port is not None:
        config["listen_port"] = args.port
    elif os.environ.get("DFT_PORT"):
        config["listen_port"] = _valid_port(int(os.environ["DFT_PORT"]))
    if args.host is not None:
        config["listen_host"] = args.host
    elif os.environ.get("DFT_HOST"):
        config["listen_host"] = os.environ["DFT_HOST"]
    if args.socks5_port is not None:
        config["socks5_port"] = args.socks5_port
        if not args.disable_socks5:
            config["socks5_enabled"] = True
    elif os.environ.get("DFT_SOCKS5_PORT"):
        config["socks5_port"] = _valid_port(int(os.environ["DFT_SOCKS5_PORT"]))
        config["socks5_enabled"] = True
    if args.disable_socks5:
        config["socks5_enabled"] = False
    if args.log_level is not None:
        config["log_level"] = args.log_level
    elif os.environ.get("DFT_LOG_LEVEL"):
        config["log_level"] = os.environ["DFT_LOG_LEVEL"]
    if "auth_key" not in config:
        print("Missing 'auth_key' in config.")
        sys.exit(1)
    if config["auth_key"] in _PLACEHOLDER_AUTH_KEYS:
        print("Refusing to start: 'auth_key' is a placeholder. Set a strong secret.")
        sys.exit(1)
    sid = config.get("script_ids") or config.get("script_id")
    if not sid or sid == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID":
        print("Missing valid 'script_id' or 'script_ids' in config.")
        sys.exit(1)
    if args.scan:
        setup_logging("INFO")
        log = logging.getLogger("Main")
        log.info("Scanning Google IPs for fastest reachable...")
        ok = scan_sync(config.get("front_domain", "www.google.com"))
        sys.exit(0 if ok else 1)
    setup_logging(config.get("log_level", "INFO"))
    log = logging.getLogger("Main")
    print_banner(__version__)
    if not args.no_cert_check:
        if not os.path.exists(CA_CERT_FILE):
            from mitm import MITMCertManager
            MITMCertManager()
        if not is_ca_trusted(CA_CERT_FILE):
            log.warning("MITM CA is not trusted - attempting auto-install...")
            ok = install_ca(CA_CERT_FILE)
            if not ok:
                log.error("Auto-install failed. Run with --install-cert (may need admin/sudo) or manually install ca/ca.crt as a trusted root CA.")
            else:
                log.info("MITM CA installed. You may need to restart your browser.")
        else:
            log.info("MITM CA is already trusted.")
    lan_sharing = config.get("lan_sharing", False)
    listen_host = config.get("listen_host", "127.0.0.1")
    if lan_sharing and listen_host == "127.0.0.1":
        config["listen_host"] = "0.0.0.0"
    if lan_sharing or listen_host in ("0.0.0.0", "::"):
        socks_port = config.get("socks5_port", 1080) if config.get("socks5_enabled", True) else None
        log_lan_access(config.get("listen_port", 8080), socks_port)
        if lan_sharing:
            log.warning("LAN sharing enabled. Make sure your firewall is properly configured to prevent unauthorized access.")
    log.info("DomainFront Tunnel starting (Apps Script relay)")
    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        log.info("Stopped.")

async def _run(config: dict) -> None:
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda loop, context: None)
    _log = logging.getLogger("asyncio")

    def _handler(loop, context):
        exc = context.get("exception")
        cb = context.get("handle") or context.get("source_traceback", "")
        if isinstance(exc, ConnectionResetError) and "_call_connection_lost" in str(cb):
            return
        _log.error("[asyncio] %s", context.get("message", context))
        if exc:
            loop.default_exception_handler(context)
    loop.set_exception_handler(_handler)

    root_logger = logging.getLogger()
    if not any(isinstance(h, _LogHandler) for h in root_logger.handlers):
        root_logger.addHandler(_LogHandler())

    asyncio.create_task(_log_server(config))

    server = ProxyServer(config)
    try:
        await server.start()
    finally:
        await server.stop()

if sys.version_info < (3, 10):
    sys.exit("Python 3.10 or newer is required.")

if __name__ == "__main__":
    main()