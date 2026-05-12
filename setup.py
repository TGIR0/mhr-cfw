#!/usr/bin/env python3
"""
mhr-cfw interactive setup wizard with two modes: simple (beginner) and advanced (full control).
Defaults are tuned for best compatibility with the advanced Code.gs relay.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.json"
EXAMPLE_PATH = HERE / "config.example.json"

# ──────────────────────────────── ANSI colors (fallback) ───────────────────
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ENDC = '\033[0m'

    @staticmethod
    def bold(t):   return C.BOLD + t + C.ENDC
    @staticmethod
    def blue(t):   return C.BLUE + t + C.ENDC
    @staticmethod
    def cyan(t):   return C.CYAN + t + C.ENDC
    @staticmethod
    def green(t):  return C.GREEN + t + C.ENDC
    @staticmethod
    def yellow(t): return C.YELLOW + t + C.ENDC
    @staticmethod
    def red(t):     return C.RED + t + C.ENDC
    @staticmethod
    def dim(t):     return C.DIM + t + C.ENDC

# Try importing rich for prettier output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH = True
    console = Console()
except ImportError:
    RICH = False

def _print_header(text):
    if RICH: console.print(Panel.fit(Text(text, style="bold white on blue"), border_style="bright_blue"))
    else:    print(C.bold(C.blue(text)))

def _print_success(text):
    if RICH: console.print("✔ " + text, style="bold green")
    else:    print(C.green(f"✔ {text}"))

def _print_warning(text):
    if RICH: console.print("⚠ " + text, style="bold yellow")
    else:    print(C.yellow(f"⚠ {text}"))

def _print_error(text):
    if RICH: console.print("✖ " + text, style="bold red")
    else:    print(C.red(f"✖ {text}"))

def _print_info(text):
    if RICH: console.print(text, style="dim")
    else:    print(C.dim(text))

def _print_dim(text):
    if RICH: console.print(text, style="dim")
    else:    print(C.dim(text))

def _ask(prompt, default=None, validator=None):
    hint = f" [{default}]" if default else ""
    while True:
        if RICH: console.print(f"[cyan]?[/cyan] {prompt}[dim]{hint}[/dim]: ", end="")
        else:    print(f"{C.cyan('?')} {prompt}{C.dim(hint) if hint else ''}: ", end="")
        try:
            raw = input().strip()
        except EOFError:
            sys.exit(0)
        if not raw and default is not None:
            return default
        if raw:
            if validator and not validator(raw):
                _print_error("Invalid input. Please try again.")
                continue
            return raw

def _ask_yes_no(question, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        ans = _ask(f"{question} [{hint}]", default="y" if default else "n").lower()
        if ans in ("y","yes"): return True
        if ans in ("n","no"): return False

def _ask_int(prompt, default, min_val=None, max_val=None):
    while True:
        val = _ask(prompt, default=str(default))
        try:
            ival = int(val)
            if (min_val is not None and ival < min_val) or (max_val is not None and ival > max_val):
                _print_error(f"Please enter a number between {min_val} and {max_val}.")
                continue
            return ival
        except ValueError:
            _print_error("Please enter a valid number.")

# ──────────────────────────────── Validation helpers ────────────────────────
DEPLOY_RE = re.compile(r'^AKfycb[a-zA-Z0-9_-]{30,}$')
def is_valid_deployment_id(d): return bool(DEPLOY_RE.match(d))

def is_valid_port(p): return 1 <= p <= 65535

# ──────────────────────────────── Optimized defaults ────────────────────────
def optimized_defaults():
    """Defaults tuned for the advanced Code.gs (v4+) and mhr-cfw v2."""
    base = {
        "mode": "apps_script",
        "google_ip": "216.239.38.120",
        "front_domain": "www.google.com",
        "listen_host": "127.0.0.1",
        "listen_port": 8085,
        "socks5_enabled": True,
        "socks5_port": 1080,
        "log_level": "INFO",
        "verify_ssl": True,
        "lan_sharing": False,
        "relay_timeout": 45,                # 45s safe under 60s UrlFetch limit
        "tls_connect_timeout": 15,
        "tcp_connect_timeout": 10,
        "max_response_body_bytes": 200 * 1024 * 1024,
        "chunked_download_min_size": 5 * 1024 * 1024,
        "chunked_download_chunk_size": 1 * 1024 * 1024,   # 1 MB chunks (less overhead)
        "chunked_download_max_parallel": 8,
        "chunked_download_max_chunks": 256,
        "bypass_hosts": ["localhost", ".local", ".lan", ".home.arpa"],
        "block_hosts": [],
        "direct_google_exclude": [
            "gemini.google.com", "aistudio.google.com", "notebooklm.google.com",
            "labs.google.com", "meet.google.com", "accounts.google.com",
            "ogs.google.com", "mail.google.com", "calendar.google.com",
            "drive.google.com", "docs.google.com", "chat.google.com",
            "maps.google.com", "play.google.com", "translate.google.com",
            "assistant.google.com", "lens.google.com"
        ],
        "direct_google_allow": ["www.google.com", "safebrowsing.google.com"],
        "hosts": {},
        "chunked_download_extensions": [
            ".bin", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
            ".exe", ".msi", ".dmg", ".deb", ".rpm", ".apk", ".iso", ".img",
            ".mp4", ".mkv", ".avi", ".mov", ".webm", ".mp3", ".flac", ".wav",
            ".aac", ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".wasm"
        ]
    }
    if EXAMPLE_PATH.exists():
        try:
            with EXAMPLE_PATH.open() as fh:
                example = json.load(fh)
            for k,v in example.items():
                base[k] = v   # example can override specific keys
        except Exception:
            pass
    return base

def load_existing():
    if not CONFIG_PATH.exists():
        return {}
    try:
        with CONFIG_PATH.open() as fh:
            return json.load(fh)
    except Exception:
        return {}

def merge_configs(base, existing, overrides):
    cfg = base.copy()
    cfg.update(existing)
    cfg.update(overrides)
    return cfg

def write_config(cfg):
    if CONFIG_PATH.exists():
        backup = CONFIG_PATH.with_suffix(".json.bak")
        shutil.copy2(CONFIG_PATH, backup)
        _print_info(f"Previous config backed up to {backup.name}")
    with CONFIG_PATH.open("w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    _print_success(f"Configuration saved to {CONFIG_PATH}")

# ──────────────────────────────── Simple wizard (beginner) ─────────────────
def simple_wizard(cfg):
    _print_header("1. Authentication Key")
    print("This key must match AUTH_KEY in your Code.gs Google Apps Script.")
    current = cfg.get("auth_key","")
    if current:
        _print_info(f"Existing key found (length {len(current)}).")
    new_key = _ask("Enter auth_key (or press Enter to generate a strong random one)", default="")
    if not new_key:
        new_key = secrets.token_urlsafe(32)
        _print_success(f"Generated random key: {new_key}")
        _print_warning("Please copy it now and paste into Code.gs.")
    cfg["auth_key"] = new_key

    _print_header("2. Google Apps Script Deployment ID")
    _print_dim("The ID looks like 'AKfycb...' and is obtained after deploying Code.gs as a Web App.")
    current_id = cfg.get("script_id","") or cfg.get("script_ids",[])
    if isinstance(current_id, list): current_id = ','.join(current_id)
    if current_id:
        _print_info(f"Current ID: {current_id}")
    ids_raw = _ask("Deployment ID (or comma-separated for multiple)", default=None)
    if not ids_raw and current_id:
        _print_info("Keeping existing deployment ID(s).")
    else:
        ids = [x.strip() for x in ids_raw.split(",") if x.strip()]
        if len(ids)==1:
            cfg["script_id"] = ids[0]
            cfg.pop("script_ids", None)
        else:
            cfg["script_ids"] = ids
            cfg.pop("script_id", None)
        _print_success("Deployment ID(s) updated.")

    _print_header("3. Network")
    cfg["lan_sharing"] = _ask_yes_no("Allow devices on LAN to use this proxy? (LAN Sharing)", False)
    if cfg["lan_sharing"]:
        cfg["listen_host"] = "0.0.0.0"
    else:
        cfg["listen_host"] = _ask("Listen host", default=cfg.get("listen_host","127.0.0.1"))
    cfg["listen_port"] = _ask_int("HTTP proxy port", cfg.get("listen_port",8085), 1, 65535)
    cfg["socks5_enabled"] = _ask_yes_no("Enable SOCKS5 proxy?", cfg.get("socks5_enabled", True))
    if cfg["socks5_enabled"]:
        cfg["socks5_port"] = _ask_int("SOCKS5 port", cfg.get("socks5_port",1080), 1, 65535)

    # Show summary and save
    _print_header("Review")
    _print_info(f"  auth_key      = ****{cfg['auth_key'][-4:] if len(cfg['auth_key'])>4 else ''}")
    did = cfg.get("script_id", cfg.get("script_ids",""))
    _print_info(f"  deployment    = {did}")
    _print_info(f"  listen        = {cfg['listen_host']}:{cfg['listen_port']}")
    _print_info(f"  socks5        = {cfg['socks5_enabled']} (port {cfg.get('socks5_port')})")
    if _ask_yes_no("Save this configuration?", True):
        write_config(cfg)
        print("\nNext step: python main.py")

# ──────────────────────────────── Advanced wizard (full) ────────────────────
def advanced_wizard(cfg):
    # Same as before but with tuned defaults; just call the original detailed steps
    # We'll include the full detailed wizard from the previous version (the 7-step one)
    # for brevity I'll implement a simplified version that walks through all sections.
    steps = [
        ("Authentication Key", lambda: _step_auth_key(cfg)),
        ("Deployment ID", lambda: _step_deployment(cfg)),
        ("Network Settings", lambda: _step_network(cfg)),
        ("Timeouts & Performance", lambda: _step_timeouts(cfg)),
        ("Chunked Download", lambda: _step_chunked(cfg)),
        ("Security Extras", lambda: _step_security(cfg)),
        ("Advanced Domain Lists", lambda: _step_advanced(cfg)),
    ]

    for title, func in steps:
        _print_header(title)
        func()

    # Review
    _print_header("Review & Save")
    if _ask_yes_no("Save this configuration?", True):
        write_config(cfg)
        print("\nNext step: python main.py")
    else:
        _print_warning("No changes were written.")

def _step_auth_key(cfg):
    current = cfg.get("auth_key","")
    if current:
        _print_info(f"Existing auth_key (length {len(current)}).")
    new = _ask("auth_key (empty to generate new strong key)", default="")
    if not new:
        new = secrets.token_urlsafe(32)
        _print_success(f"Generated: {new}")
        _print_warning("Copy it now and update Code.gs!")
    cfg["auth_key"] = new

def _step_deployment(cfg):
    current = cfg.get("script_id","") or cfg.get("script_ids",[])
    if isinstance(current, list): current = ','.join(current)
    if current:
        _print_info(f"Current: {current}")
    ids_raw = _ask("Deployment ID(s) comma-separated", default=None)
    if not ids_raw and current:
        _print_info("Keeping existing.")
        return
    ids = [x.strip() for x in ids_raw.split(",") if x.strip()]
    if len(ids)==1:
        cfg["script_id"] = ids[0]; cfg.pop("script_ids", None)
    else:
        cfg["script_ids"] = ids; cfg.pop("script_id", None)

def _step_network(cfg):
    cfg["lan_sharing"] = _ask_yes_no("LAN sharing?", bool(cfg.get("lan_sharing",False)))
    host = cfg.get("listen_host","127.0.0.1")
    if cfg["lan_sharing"] and host=="127.0.0.1": host = "0.0.0.0"
    cfg["listen_host"] = _ask("Listen host", default=host)
    cfg["listen_port"] = _ask_int("HTTP port", cfg.get("listen_port",8085), 1,65535)
    cfg["socks5_enabled"] = _ask_yes_no("Enable SOCKS5?", cfg.get("socks5_enabled",True))
    if cfg["socks5_enabled"]:
        cfg["socks5_port"] = _ask_int("SOCKS5 port", cfg.get("socks5_port",1080), 1,65535)

def _step_timeouts(cfg):
    cfg["relay_timeout"] = _ask_int("Relay timeout (max 60s for Google)", cfg.get("relay_timeout",45), 5,60)
    cfg["tls_connect_timeout"] = _ask_int("TLS connect timeout", cfg.get("tls_connect_timeout",15), 1,30)
    cfg["tcp_connect_timeout"] = _ask_int("TCP connect timeout", cfg.get("tcp_connect_timeout",10), 1,30)
    max_mb = cfg.get("max_response_body_bytes",200*1024*1024)//(1024*1024)
    new_mb = _ask_int("Max response size (MB)", max_mb, 1, 500)
    cfg["max_response_body_bytes"] = new_mb * 1024 * 1024

def _step_chunked(cfg):
    min_sz = cfg.get("chunked_download_min_size",5*1024*1024)//(1024*1024)
    cfg["chunked_download_min_size"] = _ask_int("Min file size for chunking (MB)", min_sz, 1,100) * 1024*1024
    chunk_kb = cfg.get("chunked_download_chunk_size",1*1024*1024)//1024
    cfg["chunked_download_chunk_size"] = _ask_int("Chunk size (KB)", chunk_kb, 64,2048) * 1024
    cfg["chunked_download_max_parallel"] = _ask_int("Max parallel chunks", cfg.get("chunked_download_max_parallel",8), 1,32)
    cfg["chunked_download_max_chunks"] = _ask_int("Max total chunks", cfg.get("chunked_download_max_chunks",256), 1,1024)

def _step_security(cfg):
    curr = cfg.get("WORKER_SECRET","")
    if curr: _print_info("WORKER_SECRET already set.")
    cfg["WORKER_SECRET"] = _ask("Worker shared secret (empty to keep/disable)", default="") or curr
    cfg["verify_ssl"] = _ask_yes_no("Verify SSL certificates?", cfg.get("verify_ssl",True))

def _step_advanced(cfg):
    # bypass hosts
    byp = cfg.get("bypass_hosts",[])
    _print_info(f"Current bypass: {', '.join(byp) if byp else 'none'}")
    add = _ask("Add bypass hosts (comma, empty to keep)", default="")
    if add: cfg["bypass_hosts"] = [h.strip() for h in add.split(",") if h.strip()]
    # block hosts
    blk = cfg.get("block_hosts",[])
    _print_info(f"Current block: {', '.join(blk) if blk else 'none'}")
    add = _ask("Add block hosts (comma)", default="")
    if add: cfg["block_hosts"] = [h.strip() for h in add.split(",") if h.strip()]
    # direct google exclude
    _print_info("Google hosts excluded from relay:")
    _print_dim(", ".join(cfg.get("direct_google_exclude",[])))
    if _ask_yes_no("Override exclude list?", False):
        new = _ask("Comma-separated list", default="")
        if new: cfg["direct_google_exclude"] = [h.strip() for h in new.split(",") if h.strip()]
    # direct google allow
    _print_info("Google hosts always bypass relay:")
    _print_dim(", ".join(cfg.get("direct_google_allow",[])))
    if _ask_yes_no("Override allow list?", False):
        new = _ask("Comma-separated list", default="")
        if new: cfg["direct_google_allow"] = [h.strip() for h in new.split(",") if h.strip()]

# ──────────────────────────────── Non-interactive mode ──────────────────────
def non_interactive(args):
    cfg = merge_configs(optimized_defaults(), load_existing(), {})
    if args.auth_key: cfg["auth_key"] = args.auth_key
    if args.script_id:
        if is_valid_deployment_id(args.script_id):
            cfg["script_id"] = args.script_id; cfg.pop("script_ids", None)
        else:
            _print_error(f"Invalid Deployment ID: {args.script_id}"); sys.exit(1)
    if args.listen_port:
        if is_valid_port(args.listen_port): cfg["listen_port"] = args.listen_port
        else: _print_error(f"Invalid port: {args.listen_port}"); sys.exit(1)
    if args.socks5_port:
        if is_valid_port(args.socks5_port): cfg["socks5_enabled"] = True; cfg["socks5_port"] = args.socks5_port
        else: _print_error(f"Invalid SOCKS5 port: {args.socks5_port}"); sys.exit(1)
    if args.lan_sharing: cfg["lan_sharing"] = True; cfg["listen_host"] = "0.0.0.0"
    write_config(cfg)

# ──────────────────────────────── Main entry ────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="mhr-cfw setup wizard")
    parser.add_argument("--mode", choices=["simple","advanced"], help="Wizard mode (simple for beginners, advanced for full control)")
    parser.add_argument("--auth-key", help="Authentication key")
    parser.add_argument("--script-id", help="Deployment ID")
    parser.add_argument("--listen-port", type=int, help="HTTP proxy port")
    parser.add_argument("--socks5-port", type=int, help="SOCKS5 proxy port")
    parser.add_argument("--lan-sharing", action="store_true", help="Enable LAN sharing")
    parser.add_argument("--non-interactive", action="store_true", help="Skip wizard and apply given arguments")
    args = parser.parse_args()

    if args.non_interactive or any([args.auth_key, args.script_id, args.listen_port, args.socks5_port]):
        non_interactive(args)
        return

    # Interactive mode
    existing = load_existing()
    cfg = merge_configs(optimized_defaults(), existing, {})

    if not args.mode:
        _print_info("Select wizard mode:")
        mode = _ask("  [1] Simple (recommended for beginners)\n  [2] Advanced (full configuration)\nEnter 1 or 2", default="1")
        if mode == "2":
            args.mode = "advanced"
        else:
            args.mode = "simple"

    if args.mode == "simple":
        simple_wizard(cfg)
    else:
        advanced_wizard(cfg)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        _print_dim("Setup cancelled.")
        sys.exit(0)