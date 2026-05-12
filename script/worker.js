// ═══════════════════════════════════════════════════════════════
// Tachyon Relay v10.0 — Universal Protocol Bridge
// Supports: WebSocket, TCP raw, HTTP batch, DNS over HTTPS, UDP over TURN
// Deploy to Cloudflare Workers with: npx wrangler deploy
// ═══════════════════════════════════════════════════════════════

import { connect } from 'cloudflare:sockets';

// ── Configuration (set in Cloudflare Dashboard → Worker → Variables) ─
// RELAY_SECRET — shared secret with Code.gs
// MAX_FETCH_TIMEOUT_MS — fetch timeout (default 30s)
// MAX_RESPONSE_SIZE — max response size in bytes (default 50 MB)

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RESPONSE = 50 * 1024 * 1024; // 50 MB

// ── STUN/TURN constants ─────────────────────────────────────
const STUN_MAGIC = 0x2112A442;
const TURN_SERVERS = [
    { host: 'turn.cloudflare.com', port: 3478 },
    { host: 'openrelay.metered.ca', port: 80 },
];

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        // Health check
        if (request.method === 'GET' && url.pathname === '/health') {
            return json({ status: 'ok', time: Date.now(), version: '10.0.0' });
        }

        // Dashboard
        if (url.pathname === '/dashboard') {
            return serveDashboard(env);
        }

        // WebSocket upgrade (TCP raw + HTTP relay + UDP + DNS)
        if (request.headers.get('Upgrade') === 'websocket') {
            return handleWebSocket(request, env);
        }

        // HTTP relay (batch + single)
        if (request.method === 'POST') {
            try {
                const req = await request.json();
                if (req.q && Array.isArray(req.q)) {
                    return handleBatch(req.q, request, env);
                }
                return handleHttpSingle(req, request, env);
            } catch (e) {
                return json({ e: 'invalid json' }, 400);
            }
        }

        return json({ status: 'Tachyon Relay v10', docs: '/dashboard' });
    },
};

// ═══════════════════════════════════════════════════════════════
// WebSocket handler — universal protocol dispatcher
// ═══════════════════════════════════════════════════════════════
async function handleWebSocket(request, env) {
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    server.addEventListener('message', async (event) => {
        try {
            const frame = new Uint8Array(event.data);
            if (frame.length < 4) return;
            const view = new DataView(frame.buffer);
            const frameType = view.getUint8(0);   // 0x01=TCP, 0x02=HTTP, 0x03=DNS, 0x04=UDP
            const port = view.getUint16(1);
            const addrLen = view.getUint8(3);
            const host = new TextDecoder().decode(frame.slice(4, 4 + addrLen));
            const payload = frame.slice(4 + addrLen);

            switch (frameType) {
                case 0x01: await handleTCP(server, host, port, payload); break;
                case 0x02: await handleHTTP(server, payload); break;
                case 0x03: await handleDNS(server, payload); break;
                case 0x04: await handleUDP(server, host, port, payload); break;
            }
        } catch (e) {
            console.error('Frame error:', e.message);
        }
    });

    return new Response(null, { status: 101, webSocket: client });
}

// ═══════════════════════════════════════════════════════════════
// TCP Raw Tunnel (cloudflare:sockets)
// ═══════════════════════════════════════════════════════════════
async function handleTCP(ws, host, port, initialData) {
    let socket;
    try {
        socket = connect({ hostname: host, port });
    } catch (e) {
        ws.send(new Uint8Array([0x00])); // connection failed
        return;
    }

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    // Send initial data
    if (initialData.length > 0) {
        try { await writer.write(initialData); } catch (e) { socket.close(); return; }
    }

    // Pipe target → WebSocket
    (async () => {
        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                ws.send(value);
            }
            ws.send(new Uint8Array([0x01])); // EOF signal
        } catch (e) {
            // connection closed
        }
    })();

    // Store listener reference for cleanup
    const onMessage = async (msgEvent) => {
        if (msgEvent.data instanceof ArrayBuffer || msgEvent.data instanceof Uint8Array) {
            try { await writer.write(new Uint8Array(msgEvent.data)); } catch (e) { /* closed */ }
        }
    };
    ws.addEventListener('message', onMessage);

    ws.addEventListener('close', () => {
        try { writer.close(); } catch (e) {}
        try { socket.close(); } catch (e) {}
    });
}

// ═══════════════════════════════════════════════════════════════
// HTTP JSON Relay
// ═══════════════════════════════════════════════════════════════
async function handleHTTP(ws, payload) {
    try {
        const req = JSON.parse(new TextDecoder().decode(payload));
        const { id, method, url, headers, body } = req;
        const fetchOpts = {
            method: method || 'GET',
            headers: headers || {},
            redirect: 'follow',
        };
        if (body) {
            fetchOpts.body = Uint8Array.from(atob(body), c => c.charCodeAt(0));
        }

        const resp = await fetch(url, fetchOpts);
        const buf = await resp.arrayBuffer();
        const respBodyB64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
        const respHeaders = {};
        resp.headers.forEach((v, k) => { respHeaders[k] = v; });

        ws.send(JSON.stringify({ id, status: resp.status, headers: respHeaders, body: respBodyB64 }));
    } catch (e) {
        ws.send(JSON.stringify({ id: '?', status: 502, error: e.message }));
    }
}

// ═══════════════════════════════════════════════════════════════
// DNS over HTTPS
// ═══════════════════════════════════════════════════════════════
async function handleDNS(ws, query) {
    try {
        const resp = await fetch('https://cloudflare-dns.com/dns-query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/dns-message' },
            body: query,
        });
        const answer = new Uint8Array(await resp.arrayBuffer());
        ws.send(answer);
    } catch (e) {
        console.error('DNS error:', e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
// UDP over TURN
// ═══════════════════════════════════════════════════════════════
async function handleUDP(ws, host, port, data) {
    for (const turn of TURN_SERVERS) {
        try {
            const socket = connect({ hostname: turn.host, port: turn.port });
            const writer = socket.writable.getWriter();
            const reader = socket.readable.getReader();

            const tid = crypto.getRandomValues(new Uint8Array(12));

            // TURN Allocate
            await writer.write(buildTurnAllocate(tid));

            // TURN Send Indication
            await writer.write(buildTurnSend(host, port, data, tid));

            // Read response
            const { value } = await reader.read();
            if (value) {
                const result = parseTurnData(value);
                if (result) {
                    ws.send(result);
                    writer.close();
                    return;
                }
            }
            writer.close();
        } catch (e) { /* try next TURN server */ }
    }
}

function buildTurnAllocate(tid) {
    const buf = new ArrayBuffer(20);
    const v = new DataView(buf);
    v.setUint16(0, 0x0003); v.setUint16(2, 0);
    v.setUint32(4, STUN_MAGIC);
    new Uint8Array(buf).set(tid, 8);
    return new Uint8Array(buf);
}

function buildTurnSend(peerAddr, peerPort, data, tid) {
    const addrBytes = new Uint8Array(8);
    addrBytes[0] = 0; addrBytes[1] = 1; // IPv4
    addrBytes[2] = (peerPort >> 8) ^ 0x21;
    addrBytes[3] = (peerPort & 0xFF) ^ 0x12;
    const ipParts = peerAddr.split('.').map(Number);
    const xorMagic = new Uint8Array(new Uint32Array([STUN_MAGIC]).buffer);
    for (let i = 0; i < 4; i++) addrBytes[4 + i] = ipParts[i] ^ xorMagic[i];

    const attrLen = 8 + data.length;
    const totalLen = 20 + 4 + attrLen;
    const buf = new ArrayBuffer(totalLen);
    const u8 = new Uint8Array(buf);
    const view = new DataView(buf);
    view.setUint16(0, 0x0016); view.setUint16(2, 4 + attrLen);
    view.setUint32(4, STUN_MAGIC);
    u8.set(tid, 8);
    view.setUint16(20, 0x0012); view.setUint16(22, 8);
    u8.set(addrBytes, 24);
    view.setUint16(32, 0x0013); view.setUint16(34, data.length);
    u8.set(data, 36);
    return u8;
}

function parseTurnData(u8) {
    if (u8.length < 20) return null;
    const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    if (view.getUint16(0) !== 0x0017) return null;
    const msgLen = view.getUint16(2);
    let offset = 20;
    while (offset < 20 + msgLen && offset + 4 <= u8.length) {
        const attrType = view.getUint16(offset);
        const attrLen = view.getUint16(offset + 2);
        offset += 4;
        if (attrType === 0x0013 && offset + attrLen <= u8.length)
            return u8.slice(offset, offset + attrLen);
        offset += attrLen;
        if (offset % 4) offset += 4 - (offset % 4);
    }
    return null;
}

// ═══════════════════════════════════════════════════════════════
// HTTP Relay (POST) — batch + single
// ═══════════════════════════════════════════════════════════════
async function handleBatch(items, request, env) {
    const secret = env.RELAY_SECRET || '';
    if (secret) {
        const sent = request.headers.get('x-worker-secret') || '';
        if (!(await safeEqual(sent, secret))) return json({ e: 'unauthorized' }, 401);
    }

    const results = await Promise.allSettled(
        items.map(item => httpCore(item, env))
    );

    const responseItems = results.map(r =>
        r.status === 'fulfilled' ? r.value : { e: 'worker error', detail: r.reason?.message }
    );

    return json({ q: responseItems });
}

async function handleHttpSingle(req, request, env) {
    const secret = env.RELAY_SECRET || '';
    if (secret) {
        const sent = request.headers.get('x-worker-secret') || '';
        if (!(await safeEqual(sent, secret))) return json({ e: 'unauthorized' }, 401);
    }
    const result = await httpCore(req, env);
    return json(result);
}

async function httpCore(req, env) {
    if (!req.u || typeof req.u !== 'string') return { e: 'missing url' };

    let targetUrl;
    try { targetUrl = new URL(req.u); } catch { return { e: 'invalid url' }; }
    if (isPrivateOrLoopback(targetUrl.hostname)) return { e: 'blocked' };

    const method = (req.m || 'GET').toUpperCase();
    const headers = new Headers();
    if (req.h && typeof req.h === 'object') {
        for (const [k, v] of Object.entries(req.h)) {
            if (typeof v === 'string' && !/[\r\n]/.test(v)) headers.set(k, v);
        }
    }
    if (req.ct && !headers.has('content-type')) headers.set('content-type', req.ct);

    const timeout = Number(env.MAX_FETCH_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;
    const maxSize = Number(env.MAX_RESPONSE_SIZE) || DEFAULT_MAX_RESPONSE;

    let resp;
    try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), timeout);
        resp = await fetch(targetUrl.toString(), {
            method, headers,
            redirect: req.r === false ? 'manual' : 'follow',
            body: req.b ? Uint8Array.from(atob(req.b), c => c.charCodeAt(0)) : undefined,
            signal: ctrl.signal,
        });
        clearTimeout(timer);
    } catch (e) {
        return { e: 'fetch failed', detail: e.message };
    }

    const buf = await resp.arrayBuffer();
    if (buf.byteLength > maxSize) return { e: 'response too large' };
    const bodyBytes = new Uint8Array(buf);

    const respHeaders = {};
    resp.headers.forEach((v, k) => {
        if (k.toLowerCase() === 'set-cookie') (respHeaders[k] ??= []).push(v);
        else respHeaders[k] = v;
    });

    return {
        s: resp.status,
        h: respHeaders,
        b: btoa(String.fromCharCode(...bodyBytes)),
    };
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════
function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { 'content-type': 'application/json; charset=utf-8' },
    });
}

async function safeEqual(a, b) {
    const enc = new TextEncoder();
    const aBytes = enc.encode(a), bBytes = enc.encode(b);
    if (aBytes.length !== bBytes.length) return false;
    return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

function isPrivateOrLoopback(hostname) {
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]') return true;
    if (hostname === '0.0.0.0' || hostname === '[::]') return true;
    const ip = hostname.replace(/^\[|\]$/g, '');
    const parts = ip.split('.');
    if (parts.length === 4) {
        const s = parts.map(Number);
        if (s[0] === 10) return true;
        if (s[0] === 172 && s[1] >= 16 && s[1] <= 31) return true;
        if (s[0] === 192 && s[1] === 168) return true;
        if (s[0] === 100 && s[1] >= 64 && s[1] <= 127) return true;
        if (s[0] === 127) return true;
    }
    return false;
}

function serveDashboard(env) {
    const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Tachyon Relay v10</title><style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:40px;text-align:center}h1{background:linear-gradient(135deg,#58a6ff,#3fb950);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:48px}.card{background:#161b22;border:1px solid #30363d;border-radius:16px;padding:24px;margin:20px auto;max-width:600px;text-align:left}.green{color:#3fb950}.blue{color:#58a6ff}</style></head><body><h1>⚡ Tachyon Relay</h1><p>Universal Protocol Bridge v10.0</p><div class="card"><p>✅ <span class="green">WebSocket</span> — TCP raw, HTTP relay, DNS, UDP</p><p>✅ <span class="blue">HTTP Batch</span> — Worker‑Side Batching</p><p>✅ TCP Sockets (cloudflare:sockets)</p><p>✅ DNS over HTTPS</p><p>✅ UDP over TURN</p></div><p style="color:#8b949e;margin-top:30px">Deployed on Cloudflare Workers</p></body></html>`;
    return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}