# src/relay.py — منطق رله اصلی DomainFronter
import asyncio
import json
import logging
import time
import base64
from urllib.parse import urlparse

from constants import RELAY_TIMEOUT, STATEFUL_HEADER_NAMES, STATIC_EXTS
from failover import QuotaFailover

log = logging.getLogger("Fronter")


class RelayEngine:
    """هسته‌ی رله: ارسال درخواست به Apps Script و دریافت پاسخ"""

    def __init__(self, pool, auth_key: str, script_ids: list[str],
                 relay_timeout: float, h2_client=None,
                 worker_secret: str = "", dev_sids: set = None):
        self._pool = pool
        self._auth_key = auth_key
        self._failover = QuotaFailover(script_ids)  # ← جایگزین لیست ساده
        self._relay_timeout = relay_timeout
        self._h2 = h2_client
        self._worker_secret = worker_secret
        self._dev_sids = dev_sids or set()

    # ── script ID selection ─────────────────────────────────
    def _script_id_for_url(self, url: str) -> str:
        if self._failover.available_count == 1:
            return self._failover._next()
        import hashlib
        host = url.split('/')[2] if '//' in url else url
        digest = hashlib.sha1(host.encode()).digest()
        idx = int.from_bytes(digest[:4], 'big') % self._failover.available_count
        # استفاده از _next با احترام به blacklist
        return self._failover._next()

    def _exec_path(self, url: str) -> str:
        sid = self._script_id_for_url(url)
        use_dev = sid in self._dev_sids
        return f"/macros/s/{sid}/{'dev' if use_dev else 'exec'}"

    # ── main relay ──────────────────────────────────────────
    async def relay(self, method: str, url: str, headers: dict, body: bytes = b"") -> bytes:
        payload = self._build_payload(method, url, headers, body)
        full = dict(payload)
        full["k"] = self._auth_key
        json_body = json.dumps(full).encode()
        path = self._exec_path(url)

        reader, writer, created = await self._pool.acquire()
        try:
            request = self._build_http_request("POST", path, json_body)
            writer.write(request)
            await writer.drain()
            raw = await asyncio.wait_for(
                self._read_response(reader),
                timeout=self._relay_timeout
            )
            await self._pool.release(reader, writer, created)
            result = self._parse_relay_response(raw)

            # اگر پاسخ حاوی خطای quota باشد، اسکریپت فعلی را بلاک کن
            if b"quota" in result or b"rate" in result:
                sid = self._script_id_for_url(url)
                self._failover.blacklist(sid, "quota_exceeded")

            return result
        except Exception:
            try: writer.close()
            except Exception: pass
            # در صورت خطای شبکه هم اسکریپت را بلاک کن
            sid = self._script_id_for_url(url)
            self._failover.blacklist(sid, "network_error")
            raise

    # ── HTTP request builder (بدون تغییر) ───────────────────
    def _build_http_request(self, method: str, path: str, body: bytes) -> bytes:
        hdrs = {
            "Host": "script.google.com",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if self._worker_secret:
            hdrs["X-Worker-Secret"] = self._worker_secret

        req = f"{method} {path} HTTP/1.1\r\n"
        for k, v in hdrs.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        return req.encode() + body

    # ── باقی متدها بدون تغییر ────────────────────────────────
    _STRIP = frozenset({
        "accept-encoding", "x-forwarded-for", "x-forwarded-host",
        "x-forwarded-proto", "x-forwarded-port", "x-real-ip",
        "forwarded", "via", "proxy-authorization", "proxy-connection",
    })

    def _build_payload(self, method, url, headers, body):
        p = {"m": method, "u": url, "r": False}
        if headers:
            filt = {k: v for k, v in headers.items()
                    if k.lower() not in self._STRIP}
            if filt:
                p["h"] = filt
        if body:
            p["b"] = base64.b64encode(body).decode()
            ct = headers.get("Content-Type") or headers.get("content-type")
            if ct:
                p["ct"] = ct
        return p

    async def _read_response(self, reader: asyncio.StreamReader) -> bytes:
        raw = b""
        while b"\r\n\r\n" not in raw:
            if len(raw) > 65536:
                return raw
            chunk = await asyncio.wait_for(reader.read(8192), timeout=8)
            if not chunk:
                break
            raw += chunk
        if b"\r\n\r\n" not in raw:
            return raw

        header_section, body = raw.split(b"\r\n\r\n", 1)
        lines = header_section.split(b"\r\n")
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.decode(errors="replace").split(":", 1)
                headers[k.strip().lower()] = v.strip()

        content_length = headers.get("content-length")
        if content_length:
            total = int(content_length)
            remaining = total - len(body)
            while remaining > 0:
                chunk = await asyncio.wait_for(
                    reader.read(min(remaining, 65536)), timeout=20
                )
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
        else:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=2)
                    if not chunk:
                        break
                    body += chunk
                except asyncio.TimeoutError:
                    break
        return body

    def _parse_relay_response(self, body: bytes) -> bytes:
        text = body.decode(errors="replace").strip()
        if not text:
            return self._error(502, "Empty response from relay")

        import re
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group())
                except json.JSONDecodeError:
                    return self._error(502, f"Bad JSON: {text[:200]}")
            else:
                return self._error(502, f"No JSON: {text[:200]}")

        if "e" in data:
            return self._error(502, f"Relay error: {data['e']}")

        status = data.get("s", 200)
        resp_headers = data.get("h", {})
        body_bytes = base64.b64decode(data.get("b", ""))

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
        result += f"Content-Length: {len(body_bytes)}\r\n\r\n"
        return result.encode() + body_bytes

    @staticmethod
    def _error(status: int, message: str) -> bytes:
        body = f"<html><body><h1>{status}</h1><p>{message}</p></body></html>"
        return (f"HTTP/1.1 {status} Error\r\nContent-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n\r\n{body}").encode()