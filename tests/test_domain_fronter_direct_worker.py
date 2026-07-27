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


def test_batch_ignores_direct_worker_when_google_relay_only(monkeypatch):
    fronter = make_fronter(batch_enabled=True)
    called = {"direct": 0, "h1": 0}

    async def fake_direct(payloads):
        called["direct"] += 1
        raise AssertionError("direct Worker should not be used")

    async def fake_acquire():
        called["h1"] += 1
        raise RuntimeError("apps script path selected")

    monkeypatch.setattr(fronter, "_relay_batch_worker_direct", fake_direct)
    monkeypatch.setattr(fronter, "_acquire", fake_acquire)

    with pytest.raises(RuntimeError, match="apps script path selected"):
        asyncio.run(fronter._relay_batch([
            {"m": "GET", "u": "https://example.com/a.js"},
        ]))

    assert called == {"direct": 0, "h1": 1}


def test_direct_worker_is_not_preferred_even_when_configured(monkeypatch):
    fronter = make_fronter(batch_enabled=True)

    assert not fronter._direct_worker_preferred()
