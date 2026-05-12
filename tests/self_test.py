#!/usr/bin/env python3
"""self_test.py — Automated diagnostic for mhr-cfw relay chain."""

import json, sys, time, urllib.request, urllib.error

CONFIG = json.load(open("config.json"))
AUTH   = CONFIG["auth_key"]
SID    = CONFIG.get("script_id") or CONFIG.get("script_ids",[""])[0]
URL    = f"https://script.google.com/macros/s/{SID}/exec"

passed = 0; failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  ✅ {name}")
        passed += 1
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        failed += 1

def _check(condition, message="Assertion failed"):
    """Helper that raises if condition is False — usable inside lambdas."""
    if not condition:
        raise Exception(message)

print("mhr-cfw Self-Test\n")

# 1. Config sanity
test("config.json has auth_key",
     lambda: _check(CONFIG.get("auth_key") is not None, "Missing auth_key in config.json"))
test("config.json has script_id",
     lambda: _check(SID is not None and len(SID) > 0, "Missing script_id in config.json"))

# 2. Apps Script reachable
def _relay(payload):
    req = urllib.request.Request(URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

test("Apps Script relay (httpbin)",
     lambda: _check("s" in _relay({"k":AUTH,"u":"https://httpbin.org/get","m":"GET"}),
                    "Missing 's' in relay response – Apps Script may be unreachable"))
test("Apps Script rejects bad auth",
     lambda: _check("e" in _relay({"k":"bad","u":"https://httpbin.org/get"}),
                    "Bad auth should return an error"))
test("Worker loop guard",
     lambda: _check(_relay({"k":AUTH,"u":"https://httpbin.org/get","h":{"x-relay-hop":"1"}}).get("e") == "loop detected",
                    "Loop detection failed – worker may be misconfigured"))

print(f"\n{passed}/{passed+failed} passed")
sys.exit(0 if failed==0 else 1)