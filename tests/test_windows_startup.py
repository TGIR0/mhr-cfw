import asyncio
import json
import socket
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from main import _run


def _base_config(port: int, socks_port: int) -> dict:
    return {
        "mode": "apps_script",
        "google_ip": "216.239.38.120",
        "front_domain": "www.google.com",
        "script_id": "AKfycbx-valid-deployment",
        "auth_key": "not-a-placeholder-secret",
        "listen_host": "127.0.0.1",
        "listen_port": port,
        "socks5_enabled": True,
        "socks5_host": "127.0.0.1",
        "socks5_port": socks_port,
        "log_level": "WARNING",
        "verify_ssl": True,
        "lan_sharing": False,
        "relay_timeout": 5,
        "tls_connect_timeout": 5,
        "tcp_connect_timeout": 5,
        "max_response_body_bytes": 1024 * 1024,
        "allow_direct_tcp": False,
        "allow_direct_udp": False,
        "udp_mode": "disabled",
        "quic_mode": "block",
        "iran_geoip_enabled": False,
        "kcp_enabled": True,
        "relay_concurrency": 2,
        "pool_max": 2,
        "pool_min_idle": 0,
        "batch_enabled": False,
        "batch_max": 1,
        "batch_window_micro": 0.005,
        "batch_window_macro": 0.05,
        "parallel_range_enabled": False,
        "parallel_relay": 1,
        "block_hosts": [],
        "bypass_hosts": [],
        "forwarder_hosts": [],
        "direct_google_exclude": [],
        "direct_google_allow": ["www.google.com"],
        "youtube_via_relay": False,
        "hosts": {},
    }


def test_proxy_start_stop_on_windows_loop():
    config = _base_config(_free_port(), _free_port())

    async def runner():
        task = asyncio.create_task(_run(config))
        await asyncio.sleep(0.5)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    asyncio.run(runner())


def test_main_check_config_accepts_valid_windows_config(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(_base_config(_free_port(), _free_port())),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "main.py", "--config", str(config_path), "--check-config"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "Config validation passed."
    assert result.stderr == ""


def test_main_routing_check_prints_only_decision(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(_base_config(_free_port(), _free_port())),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--config",
            str(config_path),
            "--routing-check",
            "example.ir",
        ],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "IR_DIRECT"
    assert result.stderr == ""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
