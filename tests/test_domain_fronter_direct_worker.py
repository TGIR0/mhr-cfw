import asyncio

import pytest

from domain_fronter import DomainFronter


def make_fronter(**overrides):
    config = {
        "google_ip": "216.239.38.120",
        "front_domain": "www.google.com",
        "script_id": "AKfycbx-valid-deployment",
        "auth_key": "not-a-placeholder-secret",
        "direct_worker_enabled": True,
        "worker_url": "https://relay.example",
        "worker_auth_key": "worker-secret",
        "relay_concurrency": 2,
        "pool_max": 1,
        "pool_min_idle": 0,
        "batch_enabled": False,
        "parallel_range_enabled": False,
    }
    config.update(overrides)
    return DomainFronter(config)


def test_direct_worker_payload_adds_worker_auth_key(monkeypatch):
    fronter = make_fronter()
    captured = {}

    async def fake_send(payload):
        captured.update(payload)
        return b'{"s":204,"h":{},"b":""}'

    monkeypatch.setattr(fronter, "_send_worker_direct_payload", fake_send)

    raw = asyncio.run(
        fronter._relay_worker_direct({"m": "GET", "u": "https://example.com/"})
    )

    assert captured["k"] == "worker-secret"
    assert raw.startswith(b"HTTP/1.1 204")


def test_batch_uses_direct_worker_when_preferred(monkeypatch):
    fronter = make_fronter(batch_enabled=True)
    called = {"direct": 0, "apps_script": 0}

    async def fake_direct(payloads):
        called["direct"] += 1
        assert payloads[0]["u"] == "https://example.com/a.js"
        return [b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]

    async def fake_apps_script(payloads):
        called["apps_script"] += 1
        return []

    monkeypatch.setattr(fronter, "_relay_batch_worker_direct", fake_direct)
    monkeypatch.setattr(fronter, "_parse_batch_body", fake_apps_script)

    result = asyncio.run(fronter._relay_batch([
        {"m": "GET", "u": "https://example.com/a.js"},
    ]))

    assert called == {"direct": 1, "apps_script": 0}
    assert result[0].startswith(b"HTTP/1.1 200")


def test_batch_falls_back_after_direct_worker_failure(monkeypatch):
    fronter = make_fronter(batch_enabled=True)
    called = {"direct": 0, "h1": 0}

    async def fake_direct(payloads):
        called["direct"] += 1
        raise TimeoutError("direct unavailable")

    async def fake_acquire():
        called["h1"] += 1
        raise RuntimeError("stop after fallback")

    monkeypatch.setattr(fronter, "_relay_batch_worker_direct", fake_direct)
    monkeypatch.setattr(fronter, "_acquire", fake_acquire)

    with pytest.raises(RuntimeError, match="stop after fallback"):
        asyncio.run(fronter._relay_batch([
            {"m": "GET", "u": "https://example.com/a.js"},
        ]))

    assert called == {"direct": 1, "h1": 1}
    assert not fronter._direct_worker_preferred()
