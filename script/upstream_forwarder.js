// Upstream Forwarder v2.0 — Node 18+ HTTP server.
// Stable exit IP with safe fetch, timeout, memory limits, and privacy.

"use strict";

const http = require("http");
const { Buffer } = require("buffer");

// ── Environment ────────────────────────────────────────────────────
const AUTH_KEY       = process.env.AUTH_KEY || "";
const PORT           = parseInt(process.env.PORT, 10) || 8787;
const HOST           = process.env.HOST || "127.0.0.1";
const FETCH_TIMEOUT  = parseInt(process.env.FETCH_TIMEOUT_MS, 10) || 25000;
const MAX_BODY_SIZE  = parseInt(process.env.MAX_BODY_SIZE, 10) || 10_485_760; // 10 MB

if (!AUTH_KEY || AUTH_KEY.length < 32) {
  console.error("FATAL: AUTH_KEY must be at least 32 characters long.");
  process.exit(1);
}

// ── Headers to strip (mirrors Google Apps Script relay & browser safety) ──
const SKIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "x-forwarded-for",
  "x-real-ip",
  "x-forwarded-host",
  "x-forwarded-proto",
  "forwarded",
  "via",
  "x-amz-trace-id",
  "cloudfront-viewer-country",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
]);

// ── Self‑block hostnames (prevent loops) ───────────────────────────
let SELF_HOSTS = [];
const server_hostname = HOST === "0.0.0.0" ? undefined : HOST;
if (server_hostname) {
  SELF_HOSTS.push(server_hostname, `localhost`, `127.0.0.1`, `[::1]`);
}

// ── HTTP server ─────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    // Health check / status page
    if (req.method === "GET" && (req.url === "/" || req.url === "")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(STATUS_PAGE);
      return;
    }

    if (req.method !== "POST" || req.url !== "/fwd") {
      sendJson(res, 404, { e: "not found" });
      return;
    }

    // Authenticate
    if (req.headers["x-upstream-auth"] !== AUTH_KEY) {
      sendJson(res, 401, { e: "unauthorized" });
      return;
    }

    // Read body with size limit
    const raw = await readBody(req, MAX_BODY_SIZE);
    let body;
    try {
      body = JSON.parse(raw);
    } catch (_) {
      sendJson(res, 400, { e: "invalid json" });
      return;
    }

    // Validate URL
    if (!body.u || typeof body.u !== "string" || !/^https?:\/\//i.test(body.u)) {
      sendJson(res, 400, { e: "bad url" });
      return;
    }

    let targetUrl;
    try {
      targetUrl = new URL(body.u);
    } catch (_) {
      sendJson(res, 400, { e: "invalid url" });
      return;
    }

    // Block self‑fetch
    if (SELF_HOSTS.some(h => targetUrl.hostname === h || targetUrl.hostname.endsWith("." + h))) {
      sendJson(res, 400, { e: "self fetch blocked" });
      return;
    }

    // Build outgoing headers (clean)
    const headers = {};
    if (body.h && typeof body.h === "object" && !Array.isArray(body.h)) {
      for (const [k, v] of Object.entries(body.h)) {
        if (typeof v !== "string") continue;
        if (SKIP_HEADERS.has(k.toLowerCase())) continue;
        headers[k] = v;
      }
    }
    headers["x-fwd-hop"] = "1";

    // Fetch options
    const fetchOptions = {
      method: (body.m || "GET").toUpperCase(),
      headers,
      redirect: body.r === false ? "manual" : "follow",
      decompress: false,           // ← CRITICAL: keep original encoding
      signal: AbortSignal.timeout(FETCH_TIMEOUT)
    };

    if (body.b) {
      fetchOptions.body = Buffer.from(body.b, "base64");
    }

    // Proxy support (optional)
    const proxyUrl = process.env.OUTBOUND_PROXY || "";
    if (proxyUrl) {
      const { HttpsProxyAgent } = require("https-proxy-agent");
      fetchOptions.agent = new HttpsProxyAgent(proxyUrl);
    }

    // Execute request
    let resp;
    try {
      resp = await fetch(body.u, fetchOptions);
    } catch (err) {
      console.error("Target fetch failed:", err.message);
      sendJson(res, 502, { e: "fetch failed" });
      return;
    }

    // Read response body
    const buf = Buffer.from(await resp.arrayBuffer());

    // Collect headers (preserve multiple Set‑Cookie)
    const responseHeaders = {};
    resp.headers.forEach((v, k) => {
      const key = k.toLowerCase();
      if (key === "set-cookie") {
        if (!responseHeaders[key]) {
          responseHeaders[key] = [];
        }
        responseHeaders[key].push(v);
      } else {
        responseHeaders[key] = v;
      }
    });

    sendJson(res, 200, {
      s: resp.status,
      h: responseHeaders,
      b: buf.toString("base64")
    });

  } catch (err) {
    console.error("Internal error:", err.message);
    sendJson(res, 500, { e: "internal error" });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`upstream_forwarder listening on ${HOST}:${PORT}`);
});

// ── Helpers ─────────────────────────────────────────────────────────
function readBody(req, maxSize) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", chunk => {
      size += chunk.length;
      if (size > maxSize) {
        req.destroy(new Error("Request body too large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
}

const STATUS_PAGE =
  "<!DOCTYPE html><html><head><title>Forwarder Active</title></head>" +
  '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
  '<h1>Forwarder <span style="color:#16a34a;font-weight:700">Active</span></h1>' +
  "<p>Secure upstream relay for the Worker.</p>" +
  "</body></html>";