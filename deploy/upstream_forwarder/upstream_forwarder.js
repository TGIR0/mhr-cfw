// Upstream Forwarder — single-file Node 18+ HTTP server.
//
// Purpose: Provide a stable exit IP for the Cloudflare Worker relay so
// CAPTCHA tokens (Turnstile, reCAPTCHA, hCaptcha) bound to the solving
// IP survive verification on the target site.
//
// Run on a VPS with a stable public IP. Expose behind Caddy/nginx with
// TLS — the Worker rejects non-HTTPS forwarder URLs.
//
// Required env:
//   AUTH_KEY  — must match the Worker's UPSTREAM_AUTH_KEY (>= 32 chars)
//
// Optional env:
//   PORT       — listen port (default 8787)
//   HOST       — listen host (default 127.0.0.1, so Caddy/nginx fronts it)
//
// Wire protocol matches main/services/cloudflare-worker/worker.js:
//   POST /fwd  body: { u, m, h, b, ct, r }   →  { s, h, b }  or  { e }

"use strict";

const http = require("http");
const { gunzipSync } = require("zlib");

const AUTH_KEY = process.env.AUTH_KEY || "";
const PORT = parseInt(process.env.PORT, 10) || 8787;
const HOST = process.env.HOST || "127.0.0.1";
const MAX_RESPONSE_BYTES = 200 * 1024 * 1024;
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 300;
const _rateMap = new Map();

function rateLimited(key) {
    const now = Date.now();
    let e = _rateMap.get(key);
    if (!e || now > e.resetAt) {
        e = { count: 0, resetAt: now + RATE_WINDOW_MS };
        _rateMap.set(key, e);
    }
    if (++e.count > RATE_MAX) return true;
    if (_rateMap.size > 10000) {
        for (const [k, v] of _rateMap) {
            if (now > v.resetAt) _rateMap.delete(k);
        }
    }
    return false;
}

if (!AUTH_KEY || AUTH_KEY.length < 32) {
    console.error("FATAL: AUTH_KEY env var missing or shorter than 32 chars.");
    process.exit(1);
}

// Mirrors SKIP_HEADERS in main/script/Code.gs:6-9.
const SKIP_HEADERS = new Set([
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "proxy-connection",
    "proxy-authorization"
]);

const STATUS_PAGE =
    "<!DOCTYPE html><html><head><title>TG Domain Relay Forwarder</title></head>" +
    '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
    '<h1>TG Domain Relay Forwarder <span style="color:#16a34a;font-weight:700">Active</span></h1>' +
    "<p>Stable-exit upstream forwarder for the relay Worker.</p>" +
    "</body></html>";

const server = http.createServer(async (req, res) => {
    try {
        if (req.method === "GET" && (req.url === "/" || req.url === "")) {
            res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
            res.end(STATUS_PAGE);
            return;
        }

        if (req.method !== "POST" || req.url !== "/fwd") {
            sendJson(res, 404, { e: "not found" });
            return;
        }

        if (req.headers["x-upstream-auth"] !== AUTH_KEY) {
            sendJson(res, 401, { e: "unauthorized" });
            return;
        }
        if (rateLimited(req.headers["x-upstream-auth"])) {
            sendJson(res, 429, { e: "rate limited" });
            return;
        }

        const raw = await readBody(req, res);
        let body;
        try {
            body = JSON.parse(raw);
        } catch (_) {
            sendJson(res, 400, { e: "invalid json" });
            return;
        }

        if (!body.u || typeof body.u !== "string" || !/^https?:\/\//i.test(body.u)) {
            sendJson(res, 400, { e: "bad url" });
            return;
        }

        const headers = {};
        if (body.h && typeof body.h === "object") {
            for (const [k, v] of Object.entries(body.h)) {
                if (typeof v !== "string") continue;
                if (SKIP_HEADERS.has(k.toLowerCase())) continue;
                headers[k] = v;
            }
        }
        headers["x-fwd-hop"] = "1";

        const fetchOptions = {
            method: (body.m || "GET").toUpperCase(),
            headers,
            redirect: body.r === false ? "manual" : "follow"
        };

    if (body.b) {
        let buf = Buffer.from(body.b, "base64");
        if (body.ce === "gzip") {
            try {
                buf = gunzipSync(buf);
            } catch (_) { /* fallback to raw */ }
        }
        fetchOptions.body = buf;
    }

        let resp;
        try {
        const controller = new AbortController();
        const fetchTimer = setTimeout(() => controller.abort(), 30_000);
        try {
            resp = await fetch(body.u, { ...fetchOptions, signal: controller.signal });
        } finally {
            clearTimeout(fetchTimer);
        }
        } catch (err) {
            sendJson(res, 502, { e: "fetch failed: " + String(err && err.message || err) });
            return;
        }

        const cl = parseInt(resp.headers.get("content-length") || "0", 10);
        if (cl > MAX_RESPONSE_BYTES) {
            sendJson(res, 502, { e: "response too large" });
            return;
        }
        const buf = Buffer.from(await resp.arrayBuffer());
        if (buf.byteLength > MAX_RESPONSE_BYTES) {
            sendJson(res, 502, { e: "response too large after read" });
            return;
        }
        const responseHeaders = {};
        resp.headers.forEach((v, k) => {
            responseHeaders[k] = v;
        });

        sendJson(res, 200, {
            s: resp.status,
            h: responseHeaders,
            b: buf.toString("base64")
        });
    } catch (err) {
        sendJson(res, 500, { e: String(err && err.message || err) });
    }
});

server.listen(PORT, HOST, () => {
    console.log("upstream_forwarder listening on " + HOST + ":" + PORT);
});

process.on("SIGTERM", () => {
    console.log("SIGTERM received, shutting down");
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000);
});

const MAX_BODY_BYTES = 100 * 1024 * 1024;

function readBody(req, res) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        let rejected = false;
        req.on("data", c => {
            if (rejected) return;
            size += c.length;
            if (size > MAX_BODY_BYTES) {
                rejected = true;
                sendJson(res, 413, { e: "body too large" });
                req.destroy();
                reject(new Error("body too large"));
                return;
            }
            chunks.push(c);
        });
        req.on("end", () => {
            if (!rejected) resolve(Buffer.concat(chunks).toString("utf8"));
        });
        req.on("error", reject);
    });
}

function sendJson(res, status, obj) {
    const payload = JSON.stringify(obj);
    res.writeHead(status, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload),
        "cache-control": "no-store"
    });
    res.end(payload);
}
