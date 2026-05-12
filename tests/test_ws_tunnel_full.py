"""
Test suite for direct WebSocket tunnel through Google IP to Cloudflare Worker.
Runs 5 stages, each building on the previous one.
Stops at the first failure and reports exactly which layer broke.
"""

import socket
import ssl
import json
import time
import sys
import base64

# ========== CONFIG ==========
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 10808
GOOGLE_IP = "216.239.38.120"
SNI = "www.google.com"
WORKER_HOST = "tgiranfiltertime.arshia-kingforcallofduty.workers.dev"

# ========== HELPERS ==========
PASSED = 0
FAILED = 0

def test(name, fn):
    global PASSED, FAILED
    try:
        fn()
        print(f"  ✅ {name}")
        PASSED += 1
        return True
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        FAILED += 1
        return False

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ========== STAGE 1: SOCKS5 connectivity to Google IP ==========
section("Stage 1: SOCKS5 → Google IP (raw TCP)")

def test_socks5_tcp():
    try:
        import socks
    except ImportError:
        raise Exception("PySocks not installed")
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
    s.settimeout(10)
    s.connect((GOOGLE_IP, 443))
    s.close()

test("SOCKS5 TCP connect to Google IP:443", test_socks5_tcp)

if FAILED:
    print("\n❌ STAGE 1 FAILED — Check proxy settings")
    sys.exit(1)

# ========== STAGE 2: TLS with SNI = www.google.com ==========
section("Stage 2: TLS handshake with SNI=www.google.com")

def test_tls_handshake():
    import socks
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
    s.settimeout(10)
    s.connect((GOOGLE_IP, 443))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssock = ctx.wrap_socket(s, server_hostname=SNI)
    # موفقیت یعنی handshake بدون خطا انجام شد
    ssock.close()

test("TLS handshake with SNI=www.google.com", test_tls_handshake)

if FAILED:
    print("\n❌ STAGE 2 FAILED — TLS blocked on this IP:SNI")
    sys.exit(1)

# ========== STAGE 3: HTTP request with Host = worker ==========
section("Stage 3: HTTP GET to Worker (Host header)")

HTTP_RESPONSE = None

def test_http_to_worker():
    global HTTP_RESPONSE
    import socks
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
    s.settimeout(10)
    s.connect((GOOGLE_IP, 443))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssock = ctx.wrap_socket(s, server_hostname=SNI)
    req = f"GET / HTTP/1.1\r\nHost: {WORKER_HOST}\r\nConnection: close\r\n\r\n"
    ssock.sendall(req.encode())
    resp = b""
    while True:
        data = ssock.recv(4096)
        if not data:
            break
        resp += data
    ssock.close()
    HTTP_RESPONSE = resp.decode(errors="replace")
    if "HTTP/" not in HTTP_RESPONSE:
        raise Exception(f"No HTTP response: {HTTP_RESPONSE[:100]}")

test("HTTP GET to Worker (Host header)", test_http_to_worker)

if FAILED:
    print("\n❌ STAGE 3 FAILED — Worker not reachable via fronting")
    sys.exit(1)

print(f"\n  Response status line: {HTTP_RESPONSE.split(chr(13))[0]}")

# ========== STAGE 4: WebSocket upgrade ==========
section("Stage 4: WebSocket upgrade")

WS_SOCK = None

def test_ws_upgrade():
    global WS_SOCK
    import socks
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
    s.settimeout(10)
    s.connect((GOOGLE_IP, 443))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssock = ctx.wrap_socket(s, server_hostname=SNI)

    # WebSocket upgrade request
    key = base64.b64encode(b"0123456789abcde").decode()
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {WORKER_HOST}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    ssock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        data = ssock.recv(4096)
        if not data:
            break
        resp += data
    if b"101" not in resp:
        raise Exception(f"WebSocket upgrade failed: {resp.decode(errors='replace')[:200]}")
    WS_SOCK = ssock

test("WebSocket upgrade to Worker", test_ws_upgrade)

if FAILED:
    print("\n❌ STAGE 4 FAILED — Worker does not accept WebSocket")
    sys.exit(1)

# ========== STAGE 5: Send relay request through WebSocket ==========
section("Stage 5: Relay request through WebSocket")

def test_ws_relay():
    if not WS_SOCK:
        raise Exception("No WebSocket connection from Stage 4")

    # WebSocket framing helpers
    def ws_send(data):
        frame = bytearray()
        frame.append(0x81)  # text, final
        if len(data) < 126:
            frame.append(len(data))
        elif len(data) < 65536:
            frame.append(126)
            frame.extend(len(data).to_bytes(2, 'big'))
        else:
            frame.append(127)
            frame.extend(len(data).to_bytes(8, 'big'))
        frame.extend(data.encode() if isinstance(data, str) else data)
        WS_SOCK.sendall(bytes(frame))

    def ws_recv():
        data = WS_SOCK.recv(2)
        if len(data) < 2:
            return None
        opcode = data[0] & 0x0F
        masked = data[1] & 0x80
        length = data[1] & 0x7F
        if length == 126:
            length = int.from_bytes(WS_SOCK.recv(2), 'big')
        elif length == 127:
            length = int.from_bytes(WS_SOCK.recv(8), 'big')
        if masked:
            WS_SOCK.recv(4)  # mask key (server→client shouldn't be masked, but just in case)
        payload = b""
        while len(payload) < length:
            chunk = WS_SOCK.recv(min(length - len(payload), 4096))
            if not chunk:
                break
            payload += chunk
        return payload.decode(errors="replace")

    # ارسال یک درخواست رله واقعی
    req_id = "test-001"
    relay_payload = {
        "id": req_id,
        "method": "GET",
        "url": "https://httpbin.org/get?test=hello",
        "headers": {"Accept": "application/json"},
        "body": None
    }
    ws_send(json.dumps(relay_payload))

    # دریافت پاسخ
    response_raw = ws_recv()
    if not response_raw:
        raise Exception("No response received from WebSocket")
    response = json.loads(response_raw)
    if response.get("id") != req_id:
        raise Exception(f"Wrong response ID: {response.get('id')}")
    if response.get("status") != 200:
        raise Exception(f"Worker returned status {response.get('status')}: {response.get('error', '')}")
    body = base64.b64decode(response.get("body", "")).decode()
    if "test" not in body or "hello" not in body:
        raise Exception(f"Unexpected response body: {body[:100]}")
    print(f"  Response body: {body[:150]}...")

test("Full relay through WebSocket", test_ws_relay)

# ========== STAGE 6: Concurrent requests ==========
section("Stage 6: Concurrent requests (3 in parallel)")

def test_concurrent():
    if not WS_SOCK:
        raise Exception("No WebSocket connection")

    def ws_send(data):
        frame = bytearray()
        frame.append(0x81)
        d = data.encode() if isinstance(data, str) else data
        if len(d) < 126:
            frame.append(len(d))
        elif len(d) < 65536:
            frame.append(126)
            frame.extend(len(d).to_bytes(2, 'big'))
        frame.extend(d)
        WS_SOCK.sendall(bytes(frame))

    def ws_recv_all(count, timeout=15):
        results = []
        WS_SOCK.settimeout(timeout)
        for _ in range(count):
            data = WS_SOCK.recv(2)
            if len(data) < 2:
                break
            length = data[1] & 0x7F
            if length == 126:
                length = int.from_bytes(WS_SOCK.recv(2), 'big')
            elif length == 127:
                length = int.from_bytes(WS_SOCK.recv(8), 'big')
            payload = b""
            while len(payload) < length:
                chunk = WS_SOCK.recv(min(length - len(payload), 4096))
                if not chunk:
                    break
                payload += chunk
            results.append(json.loads(payload.decode()))
        return results

    # Send 3 requests at once
    for i in range(3):
        ws_send(json.dumps({
            "id": f"conc-{i}",
            "method": "GET",
            "url": f"https://httpbin.org/get?req={i}",
            "headers": {},
            "body": None
        }))

    responses = ws_recv_all(3, timeout=20)
    if len(responses) != 3:
        raise Exception(f"Expected 3 responses, got {len(responses)}")
    for r in responses:
        if r.get("status") != 200:
            raise Exception(f"Request {r.get('id')} failed with {r.get('status')}")

test("3 concurrent relay requests", test_concurrent)

# ========== FINAL REPORT ==========
section("Final Report")

print(f"\n  ✅ {PASSED} passed")
if FAILED:
    print(f"  ❌ {FAILED} failed")
    print("\n⚠️  Some tests failed. Do NOT deploy the worker until resolved.")
else:
    print("  🎉 All tests passed! Safe to deploy the WebSocket worker.")

# Cleanup
if WS_SOCK:
    try:
        WS_SOCK.close()
    except:
        pass

sys.exit(0 if FAILED == 0 else 1)