// Cloudflare Worker

import { connect } from "cloudflare:sockets";

const WORKER_URL = "YOUR_WORKER_HOSTNAME.workers.dev";

const DEFAULT_UPSTREAM_TIMEOUT_MS = 25000;
const DEFAULT_TCP_CONNECT_TIMEOUT_MS = 10000;
const WS_TCP_PATH = "/tcp";

// ── Rate limiting ──────────────────────────────────────────────
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 300;
const MAX_RESPONSE_BYTES = 100 * 1024 * 1024;
const _rateMap = new Map();

function rateLimited(key) {
    const now = Date.now();
    let e = _rateMap.get(key);
    if (!e || now > e.resetAt) {
        e = { count: 0, resetAt: now + RATE_WINDOW_MS };
        _rateMap.set(key, e);
    }
    if (++e.count > RATE_MAX) return true;
    // Lazy cleanup to prevent unbounded memory growth
    if (_rateMap.size > 10000) {
        for (const [k, v] of _rateMap) {
            if (now > v.resetAt) _rateMap.delete(k);
        }
    }
    return false;
}
export default {
    async fetch(request, env) {
        try {
            if (isWebSocketTcpRequest(request)) {
                return handleTcpWebSocket(request, env);
            }

            const hop = request.headers.get("x-relay-hop");
            const fwdHop = request.headers.get("x-fwd-hop");
            if (hop === "1" || fwdHop === "1") {
                return json({ e: "loop detected" }, 508);
            }

            if (request.method === "GET") {
                return json({ ok: true, service: "TG Domain Relay Worker" }, 200);
            }

            if (request.method !== "POST") {
                return json({ e: "Method not allowed." }, 405);
            }

            const req = await request.json();

            if (!authorizedHttpRelay(req, env)) {
                return json({ e: "unauthorized" }, 401);
            }

            if (rateLimited(req.k || "anon")) {
                return json({ e: "rate limited" }, 429);
            }

            if (Array.isArray(req.q)) {
                const results = await Promise.all(req.q.map(async item => {
                    try {
                        return await relayHttp(item, env);
                    } catch (err) {
                        return { e: String(err && err.message || err) };
                    }
                }));
                return json({ q: results });
            }

            return json(await relayHttp(req, env));

        } catch (err) {
            return json({ e: String(err) }, 500);
        }
    }
};

// Minimal gzip decompressor using Streams API (available in Cloudflare Workers)
function decompressGzip(uint8) {
    const ds = new DecompressionStream("gzip");
    const chunk = new Blob([uint8]).stream();
    const stream = chunk.pipeThrough(ds);
    return new Response(stream).arrayBuffer();
}

async function relayHttp(req, env) {
    if (!req || !req.u) {
        return { e: "missing url" };
    }

    let targetUrl;
    try {
        targetUrl = new URL(req.u);
    } catch (_) {
        return { e: "bad url" };
    }

    const BLOCKED_HOSTS = [
        WORKER_URL,
    ];

    if (BLOCKED_HOSTS.some(h => targetUrl.hostname.endsWith(h))) {
        return { e: "self-fetch blocked" };
    }

    const upstreamUrl = (env && env.UPSTREAM_FORWARDER_URL) || "";

    // f === 1: forward; f === 0: skip; missing: legacy client -> forward (compat).
    const wantForward = (req.f === 1) || (req.f === undefined);

    if (upstreamUrl && wantForward) {
        const upstreamResult = await forwardViaUpstreamJson(req, env, upstreamUrl);
        if (upstreamResult) return upstreamResult;
        // fall through to direct fetch only when fail-mode is open
    }

    const headers = new Headers();
    if (req.h && typeof req.h === "object") {
        for (const [k, v] of Object.entries(req.h)) {
            headers.set(k, v);
        }
    }

    headers.set("x-relay-hop", "1");

    const fetchOptions = {
        method: (req.m || "GET").toUpperCase(),
        headers,
        redirect: req.r === false ? "manual" : "follow"
    };

    if (req.b) {
        let bodyBytes = Uint8Array.from(atob(req.b), c => c.charCodeAt(0));
        // Decompress gzip-compressed body if signaled
        if (req.ce === "gzip") {
            try {
                bodyBytes = await decompressGzip(bodyBytes);
            } catch (_) { /* fallback to raw */ }
        }
        fetchOptions.body = bodyBytes;
    }

    const resp = await fetch(targetUrl.toString(), fetchOptions);
    const contentLength = parseInt(resp.headers.get("content-length") || "0", 10);
    if (contentLength > MAX_RESPONSE_BYTES) {
        return { e: "response too large: " + contentLength + " bytes" };
    }
    let buffer;
    try {
        buffer = await resp.arrayBuffer();
    } catch (e) {
        return { e: "response read failed: " + String(e && e.message || e) };
    }
    if (buffer.byteLength > MAX_RESPONSE_BYTES) {
        return { e: "response too large after read: " + buffer.byteLength };
    }

    const responseHeaders = {};
    resp.headers.forEach((v, k) => {
        responseHeaders[k] = v;
    });

    return {
        s: resp.status,
        h: responseHeaders,
        b: arrayBufferToBase64(buffer)
    };
}

function arrayBufferToBase64(buffer) {
    const uint8 = new Uint8Array(buffer);
    const chunks = [];
    const chunkSize = 0x8000;

    for (let i = 0; i < uint8.length; i += chunkSize) {
        chunks.push(String.fromCharCode.apply(
            null,
            uint8.subarray(i, i + chunkSize)
        ));
    }

    return btoa(chunks.join(""));
}

async function handleTcpWebSocket(request, env) {
    const url = new URL(request.url);
    const key = url.searchParams.get("k") || "";
    const expected = env.WORKER_WS_AUTH_KEY || env.UPSTREAM_AUTH_KEY || "";
    if (!expected || key !== expected) {
        return json({ e: "unauthorized" }, 401);
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.binaryType = "arraybuffer";
    server.accept({ allowHalfOpen: true });

    tcpWebSocketSession(server, env).catch(err => {
        try {
            server.send(JSON.stringify({ op: "error", e: String(err && err.message || err) }));
            server.close(1011, "tcp session failed");
        } catch (_) {
            // The socket may already be closed.
        }
    });

    return new Response(null, {
        status: 101,
        webSocket: client
    });
}

async function tcpWebSocketSession(ws, env) {
    let socket = null;
    let writer = null;
    let opened = false;
    const TCP_IDLE_TIMEOUT_MS = 300_000;
    let idleTimer = setTimeout(() => {
        try { ws.close(1000, "idle timeout"); } catch (_) {}
    }, TCP_IDLE_TIMEOUT_MS);

    function resetIdle() {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            try { ws.close(1000, "idle timeout"); } catch (_) {}
        }, TCP_IDLE_TIMEOUT_MS);
    }

    ws.addEventListener("message", async event => {
        resetIdle();
        try {
            if (!opened) {
                const hello = parseJsonControl(event.data);
                if (!authorizedTcpHello(hello, env)) {
                    ws.send(JSON.stringify({ ok: false, e: "unauthorized" }));
                    ws.close(1008, "unauthorized");
                    return;
                }

                const host = String(hello.host || "");
                const port = parseInt(hello.port, 10);
                if (!validTcpTarget(host, port)) {
                    ws.send(JSON.stringify({ ok: false, e: "bad tcp target" }));
                    ws.close(1008, "bad tcp target");
                    return;
                }

                if (rateLimited(hello.k || "tcp-anon")) {
                    ws.send(JSON.stringify({ ok: false, e: "rate limited" }));
                    ws.close(1008, "rate limited");
                    return;
                }

                socket = connect({ hostname: host, port }, { allowHalfOpen: true });
                await waitForSocketOpened(
                    socket,
                    parseInt(env.TCP_CONNECT_TIMEOUT_MS, 10) ||
                        DEFAULT_TCP_CONNECT_TIMEOUT_MS
                );
                writer = socket.writable.getWriter();
                opened = true;
                ws.send(JSON.stringify({ ok: true }));
                pipeTcpToWebSocket(socket, ws, resetIdle);
                return;
            }

            if (typeof event.data === "string") {
                const ctrl = parseJsonControl(event.data);
                if (ctrl.op === "close") {
                    await closeTcpWriter(writer);
                    ws.close(1000, "client closed");
                }
                return;
            }

            const chunk = await websocketDataToUint8Array(event.data);
            await writer.write(chunk);
        } catch (err) {
            try {
                ws.send(JSON.stringify({ op: "error", e: String(err && err.message || err) }));
                ws.close(1011, "tcp write failed");
            } catch (_) {
                // Socket already closed.
            }
        }
    });

    ws.addEventListener("close", async () => {
        clearTimeout(idleTimer);
        await closeTcpWriter(writer);
        try {
            if (socket) await socket.close();
        } catch (_) {
            // Already closed.
        }
    });
}

async function pipeTcpToWebSocket(socket, ws, resetIdle) {
    const reader = socket.readable.getReader();
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value && value.byteLength) {
                resetIdle();
                ws.send(value);
            }
        }
        ws.send(JSON.stringify({ op: "close" }));
        ws.close(1000, "target closed");
    } catch (err) {
        try {
            ws.send(JSON.stringify({ op: "error", e: String(err && err.message || err) }));
            ws.close(1011, "tcp read failed");
        } catch (_) {
            // Socket already closed.
        }
    } finally {
        try {
            reader.releaseLock();
        } catch (_) {
            // Already released.
        }
    }
}

function isWebSocketTcpRequest(request) {
    const upgrade = request.headers.get("Upgrade") || "";
    const url = new URL(request.url);
    return request.method === "GET" &&
        upgrade.toLowerCase() === "websocket" &&
        url.pathname === WS_TCP_PATH;
}

function authorizedTcpHello(hello, env) {
    const expected = env.WORKER_WS_AUTH_KEY || env.UPSTREAM_AUTH_KEY || "";
    return !!expected && hello && hello.v === 1 &&
        hello.op === "connect" && hello.k === expected;
}

function authorizedHttpRelay(req, env) {
    const expected = env.WORKER_AUTH_KEY || "";
    if (!expected) {
        console.error("WORKER_AUTH_KEY is not set — rejecting all requests");
        return false;  // fail-closed
    }
    return req && req.k === expected;
}

const BLOCKED_PORTS = new Set([
    22, 23, 25, 110, 143, 445, 465, 587, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379,
    9200, 9300, 11211, 27017, 27018,
]);

function validTcpTarget(host, port) {
    if (!host || host.length > 253) return false;
    if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
    if (BLOCKED_PORTS.has(port)) return false;
    const lowered = host.toLowerCase();
    if (lowered === WORKER_URL || lowered.endsWith("." + WORKER_URL)) return false;
    if (lowered === "localhost" || lowered.endsWith(".local") ||
        lowered.endsWith(".internal")) return false;
    if (lowered.startsWith("10.") ||
        lowered.startsWith("192.168.") ||
        lowered.startsWith("127.") ||
        lowered.startsWith("169.254.") ||
        lowered === "0.0.0.0") return false;
    if (lowered.startsWith("172.")) {
        const second = parseInt(lowered.split(".")[1], 10);
        if (second >= 16 && second <= 31) return false;
    }
    if (lowered === "::1" || lowered.startsWith("fc") ||
        lowered.startsWith("fd") || lowered.startsWith("fe80")) return false;
    return true;
}

function parseJsonControl(data) {
    if (typeof data !== "string") return {};
    try {
        return JSON.parse(data);
    } catch (_) {
        return {};
    }
}

async function websocketDataToUint8Array(data) {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    if (data instanceof Uint8Array) {
        return data;
    }
    if (data && typeof data.arrayBuffer === "function") {
        return new Uint8Array(await data.arrayBuffer());
    }
    return new TextEncoder().encode(String(data || ""));
}

async function closeTcpWriter(writer) {
    if (!writer) return;
    try {
        await writer.close();
        writer.releaseLock();
    } catch (_) {
        try {
            writer.releaseLock();
        } catch (_) {
            // Already released.
        }
    }
}

async function waitForSocketOpened(socket, timeoutMs) {
    let timer;
    try {
        await Promise.race([
            socket.opened,
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error("TCP connect timeout")), timeoutMs);
            })
        ]);
    } catch (err) {
        try {
            await socket.close();
        } catch (_) {
            // Already closed.
        }
        throw err;
    } finally {
        clearTimeout(timer);
    }
}


async function forwardViaUpstreamJson(req, env, upstreamUrl) {
    const failMode = (env.UPSTREAM_FAIL_MODE || "closed").toLowerCase();
    const timeoutMs = parseInt(env.UPSTREAM_TIMEOUT_MS, 10) || DEFAULT_UPSTREAM_TIMEOUT_MS;
    const authKey = env.UPSTREAM_AUTH_KEY || "";

    let parsed;
    try {
        parsed = new URL(upstreamUrl);
    } catch (_) {
        return upstreamFailureJson("invalid UPSTREAM_FORWARDER_URL", failMode);
    }
    if (parsed.protocol !== "https:") {
        return upstreamFailureJson("UPSTREAM_FORWARDER_URL must be https://", failMode);
    }
    if (parsed.hostname.endsWith(WORKER_URL)) {
        return upstreamFailureJson("self-forward blocked", failMode);
    }
    if (!authKey) {
        return upstreamFailureJson("UPSTREAM_AUTH_KEY missing", failMode);
    }

    const payload = {
        u: req.u,
        m: req.m,
        h: req.h,
        b: req.b,
        ct: req.ct,
        r: req.r
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const resp = await fetch(upstreamUrl, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                "x-upstream-auth": authKey
            },
            body: JSON.stringify(payload),
            signal: controller.signal
        });

        if (!resp.ok) {
            return upstreamFailureJson("forwarder status " + resp.status, failMode);
        }

        return await resp.json();
    } catch (err) {
        return upstreamFailureJson(String(err && err.message || err), failMode);
    } finally {
        clearTimeout(timer);
    }
}

function upstreamFailureJson(reason, failMode) {
    if (failMode === "open") {
        console.warn("upstream forwarder failed (falling back to direct):", reason);
        return null; // signals caller to fall through to direct fetch
    }
    return { e: "upstream forwarder failed: " + reason };
}

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: {
            "content-type": "application/json",
            "cache-control": "no-store"
        }
    });
}
