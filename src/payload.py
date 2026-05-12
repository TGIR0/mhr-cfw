# src/payload.py — ساخت payload و HTTP request
import base64
import json


STRIP_HEADERS = frozenset({
    "accept-encoding", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-forwarded-port", "x-real-ip",
    "forwarded", "via", "proxy-authorization", "proxy-connection",
})


def build_payload(method: str, url: str, headers: dict, body: bytes,
                  auth_key: str) -> dict:
    """ساخت payload برای ارسال به Apps Script"""
    p = {"m": method, "u": url, "r": False, "k": auth_key}
    if headers:
        filt = {k: v for k, v in headers.items()
                if k.lower() not in STRIP_HEADERS}
        if filt:
            p["h"] = filt
    if body:
        p["b"] = base64.b64encode(body).decode()
        ct = headers.get("Content-Type") or headers.get("content-type")
        if ct:
            p["ct"] = ct
    return p


def build_http_request(method: str, path: str, body: bytes,
                       host: str = "script.google.com",
                       worker_secret: str = "") -> bytes:
    """ساخت HTTP request برای ارسال به Apps Script"""
    hdrs = {
        "Host": host,
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    if worker_secret:
        hdrs["X-Worker-Secret"] = worker_secret

    req = f"{method} {path} HTTP/1.1\r\n"
    for k, v in hdrs.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    return req.encode() + body