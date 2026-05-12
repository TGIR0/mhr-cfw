# src/parse.py — پارس پاسخ‌های HTTP و JSON
import re
import json
import base64

from constants import MAX_RESPONSE_BODY_BYTES


def split_raw_response(raw: bytes) -> tuple[int, dict, bytes]:
    """تقسیم پاسخ خام HTTP به status, headers, body"""
    if b"\r\n\r\n" not in raw:
        return 0, {}, raw
    header_section, body = raw.split(b"\r\n\r\n", 1)
    lines = header_section.split(b"\r\n")
    status = 0
    if lines:
        m = re.search(rb"\d{3}", lines[0])
        if m:
            status = int(m.group())
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.decode(errors="replace").split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def parse_relay_json(data: dict) -> bytes:
    """تبدیل پاسخ JSON از Apps Script به HTTP response"""
    if "e" in data:
        return _error(502, f"Relay error: {data['e']}")
    status = data.get("s", 200)
    resp_headers = data.get("h", {})
    try:
        body = base64.b64decode(data.get("b", ""))
    except Exception:
        body = b""

    if len(body) > MAX_RESPONSE_BODY_BYTES:
        return _error(502, "Relay response exceeds cap")

    status_text = {
        200: "OK", 206: "Partial Content", 301: "Moved", 302: "Found",
        304: "Not Modified", 400: "Bad Request", 403: "Forbidden",
        404: "Not Found", 500: "Internal Server Error"
    }.get(status, "OK")

    result = f"HTTP/1.1 {status} {status_text}\r\n"
    skip = {"transfer-encoding", "connection", "keep-alive",
            "content-length", "content-encoding"}
    for k, v in resp_headers.items():
        if k.lower() in skip:
            continue
        values = v if isinstance(v, list) else [v]
        for val in values:
            result += f"{k}: {val}\r\n"
    result += f"Content-Length: {len(body)}\r\n\r\n"
    return result.encode() + body


def _error(status: int, message: str) -> bytes:
    body = f"<html><body><h1>{status}</h1><p>{message}</p></body></html>"
    return (f"HTTP/1.1 {status} Error\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode()