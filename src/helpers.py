"""توابع کمکی عمومی برای proxy_server"""
import re
import ipaddress

def is_ip_literal(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False

def parse_content_length(header_block: bytes) -> int:
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep: continue
        if name.strip().lower() == b"content-length":
            try: return int(value.strip())
            except ValueError: return 0
    return 0

def has_unsupported_transfer_encoding(header_block: bytes) -> bool:
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep: continue
        if name.strip().lower() != b"transfer-encoding": continue
        encs = [t.strip().lower() for t in value.decode(errors="replace").split(",") if t.strip()]
        return any(t != "identity" for t in encs)
    return False

def cors_preflight_response(origin: str, acr_method: str, acr_headers: str) -> bytes:
    allow_origin = origin or "*"
    allow_methods = (f"{acr_method}, GET, POST, PUT, DELETE, PATCH, OPTIONS" if acr_method else "GET, POST, PUT, DELETE, PATCH, OPTIONS")
    allow_headers = acr_headers or "*"
    return (f"HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: {allow_origin}\r\n"
            f"Access-Control-Allow-Methods: {allow_methods}\r\n"
            f"Access-Control-Allow-Headers: {allow_headers}\r\n"
            "Access-Control-Allow-Credentials: true\r\nAccess-Control-Max-Age: 86400\r\n"
            "Vary: Origin\r\nContent-Length: 0\r\n\r\n").encode()

def inject_cors_headers(response: bytes, origin: str) -> bytes:
    sep = b"\r\n\r\n"
    if sep not in response: return response
    header_section, body = response.split(sep, 1)
    lines = header_section.decode(errors="replace").split("\r\n")
    lines = [ln for ln in lines if not ln.lower().startswith("access-control-")]
    allow_origin = origin or "*"
    lines += [f"Access-Control-Allow-Origin: {allow_origin}", "Access-Control-Allow-Credentials: true",
              "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS",
              "Access-Control-Allow-Headers: *", "Access-Control-Expose-Headers: *", "Vary: Origin"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body