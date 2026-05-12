// ═══════════════════════════════════════════
// 🚀 Secure Relay v4.4 — Tunnel + DSR + BFP Edition
// ═══════════════════════════════════════════

const SCRIPT_PROP = PropertiesService.getScriptProperties();
const AUTH_KEY = SCRIPT_PROP.getProperty('AUTH_KEY');
const WORKER_URL = SCRIPT_PROP.getProperty('WORKER_URL');
const WORKER_SECRET = SCRIPT_PROP.getProperty('WORKER_SECRET') || '';
const DEBUG_KEY = SCRIPT_PROP.getProperty('DEBUG_KEY') || 'mydebug123';

const CHUNK_SIZE = 100;
const RATE_LIMIT_WINDOW = 60;
const RATE_LIMIT_MAX = 3000;
const CACHE_ENABLED = true;
const CACHE_TTL = 1800;
const MAX_CACHE_SIZE = 90 * 1024;

// DSR 令牌有效期（秒）
const DSR_TOKEN_TTL = 60;

// تونل دوطرفه – مدت اعتبار (ثانیه)
const TUNNEL_TTL = 90;

const TUNNEL_CACHE_PREFIX = 'tunnel_';

// ═══════════════ هدرهای حذف‌شونده (امنیت) ═══════════════
const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1,
  "proxy-authorization": 1, "proxy-authenticate": 1,
  "x-forwarded-for": 1, "x-real-ip": 1,
  "x-forwarded-host": 1, "x-forwarded-proto": 1,
  "x-forwarded-port": 1, "forwarded": 1,
  "via": 1, "x-amz-trace-id": 1,
  "cloudfront-viewer-country": 1, "cf-connecting-ip": 1,
  "cf-ipcountry": 1, "cf-ray": 1, "cf-visitor": 1
};

function isValidHeaderValue(v) {
  return typeof v === 'string' && !/[\r\n]/.test(v);
}

// ═══════════════ کلاس ++DebugLogger (با بافر خارجی) ═══════════════
class Debugger {
  constructor() {
    this.logs = [];
    this.indentLevel = 0;
  }

  _pad() { return '  '.repeat(this.indentLevel); }

  _store(message) {
    this.logs.push(message);
    _appendToLogBuffer(message);
  }

  log(message, data) {
    const entry = `${this._pad()}${message}`;
    this._store(entry);
    if (data !== undefined) {
      const dataStr = JSON.stringify(data, this._replacer, 2);
      this._store(dataStr);
    }
  }

  warn(message, data) {
    const entry = `${this._pad()}⚠️ ${message}`;
    this._store(entry);
    if (data !== undefined) {
      const dataStr = JSON.stringify(data, this._replacer, 2);
      this._store(dataStr);
    }
  }

  error(message, data) {
    const entry = `${this._pad()}❌ ${message}`;
    this._store(entry);
    if (data !== undefined) {
      const dataStr = JSON.stringify(data, this._replacer, 2);
      this._store(dataStr);
    }
  }

  time(label) { console.time(label); }
  timeEnd(label) { console.timeEnd(label); }

  group(label) {
    this.log(`▼ ${label}`);
    this.indentLevel++;
  }
  groupEnd() {
    this.indentLevel = Math.max(0, this.indentLevel - 1);
    this.log(`▲`);
  }

  _replacer(key, value) {
    if (typeof value === 'string' && value.length > 500) {
      return value.substring(0, 500) + '... [TRUNCATED]';
    }
    return value;
  }
}

// ═══════════════ بافر لاگ خارجی (در CacheService) ═══════════════
const LOG_BUFFER_KEY = 'debug_log_buffer';
const MAX_LOG_ENTRIES = 50;

function _appendToLogBuffer(message) {
  try {
    var cache = CacheService.getScriptCache();
    var raw = cache.get(LOG_BUFFER_KEY);
    var logs = raw ? JSON.parse(raw) : [];
    logs.push({ t: new Date().toISOString(), msg: message });
    if (logs.length > MAX_LOG_ENTRIES) {
      logs = logs.slice(logs.length - MAX_LOG_ENTRIES);
    }
    cache.put(LOG_BUFFER_KEY, JSON.stringify(logs), 600);
  } catch(e) {
    // ignore cache errors
  }
}

function _getLogBuffer() {
  try {
    var cache = CacheService.getScriptCache();
    var raw = cache.get(LOG_BUFFER_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch(e) {
    return [];
  }
}

// ═══════════════ Rate Limiter ═══════════════
function isRateLimited(userIdentifier) {
  if (userIdentifier === '127.0.0.1' || userIdentifier === '::1') return false;
  var cache = CacheService.getScriptCache();
  var key = 'rl_' + userIdentifier;
  var count = cache.get(key);
  if (count === null) {
    cache.put(key, '1', RATE_LIMIT_WINDOW);
    return false;
  }
  var num = parseInt(count, 10);
  if (num >= RATE_LIMIT_MAX) return true;
  cache.put(key, String(num + 1), RATE_LIMIT_WINDOW);
  return false;
}

// ═══════════════ Cache Engine ═══════════════
function getCacheKey(req) {
  return 'resp_' + Utilities.base64Encode(
    Utilities.computeDigest(Utilities.DigestAlgorithm.MD5,
      (req.u || '') + '|' + (req.m || 'GET').toUpperCase())
  );
}

function getFromCache(cacheKey) {
  if (!CACHE_ENABLED) return null;
  var cache = CacheService.getScriptCache();
  var raw = cache.get(cacheKey);
  if (raw) {
    try { return JSON.parse(raw); } catch (e) {}
  }
  return null;
}

function storeInCache(cacheKey, status, body, contentType) {
  if (!CACHE_ENABLED || status < 200 || status >= 300 || !body || body.length > MAX_CACHE_SIZE) return;
  try {
    CacheService.getScriptCache().put(cacheKey, JSON.stringify({
      status: status, body: body, contentType: contentType || 'application/json'
    }), CACHE_TTL);
  } catch (e) {}
}

// ═══════════════ DSR Token Generator ═══════════════
function _generateDsrToken() {
  var secret = WORKER_SECRET;
  if (!secret) return null;
  var now = Math.floor(Date.now() / 1000);
  var expiry = now + DSR_TOKEN_TTL;
  var tokenBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,
    secret + ':' + now + ':' + expiry);
  var token = Utilities.base64Encode(tokenBytes);
  var signatureBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,
    token + ':' + expiry + ':' + secret);
  var signature = Utilities.base64Encode(signatureBytes);
  return token + '.' + expiry + '.' + signature;
}

// ═══════════════ Tunnel helpers ═══════════════
function _generateTunnelId() {
  return Utilities.getUuid();
}

function _tunnelCacheKey(tid) {
  return TUNNEL_CACHE_PREFIX + tid;
}

function _storeTunnel(tid) {
  var cache = CacheService.getScriptCache();
  cache.put(_tunnelCacheKey(tid), '1', TUNNEL_TTL);
}

function _refreshTunnel(tid) {
  var cache = CacheService.getScriptCache();
  var key = _tunnelCacheKey(tid);
  if (cache.get(key) !== null) {
    cache.put(key, '1', TUNNEL_TTL); // تمدید TTL
    return true;
  }
  return false;
}

function _isTunnelValid(tid) {
  var cache = CacheService.getScriptCache();
  return cache.get(_tunnelCacheKey(tid)) !== null;
}

// ═══════════════ ورودی اصلی POST ═══════════════
function doPost(e) {
  const D = new Debugger();
  D.time('TotalExecution');
  D.group('🚪 doPost');

  try {
    D.time('ParsePayload');
    var req = JSON.parse(e.postData.contents);
    D.timeEnd('ParsePayload');
    D.log('📦 درخواست دریافت شد', { u: req.u, m: req.m, tunnel: req.tunnel, dsr: req.dsr_token });

    D.time('Authentication');
    if (req.k !== AUTH_KEY) {
      D.warn('🔑 احراز هویت ناموفق');
      D.timeEnd('Authentication');
      D.timeEnd('TotalExecution');
      return _json({ e: "unauthorized" });
    }
    D.timeEnd('Authentication');
    D.log('🔑 احراز هویت موفق');

    // ── Tunnel commands ─────────────────────────────────────────
    if (req.tunnel === true) {
      // ایجاد تونل جدید
      if (req.create === true) {
        var tid = _generateTunnelId();
        _storeTunnel(tid);
        D.log('🚇 تونل جدید ایجاد شد: ' + tid);
        D.timeEnd('TotalExecution');
        D.groupEnd();
        return ContentService.createTextOutput(JSON.stringify({ tid: tid }));
      }

      // درخواست داده درون تونل
      if (req.tid && req.d) {
        if (!_refreshTunnel(req.tid)) {
          D.warn('🚇 تونل نامعتبر: ' + req.tid);
          D.timeEnd('TotalExecution');
          D.groupEnd();
          return _json({ e: "tunnel_invalid" });
        }

        // base64 decode of the embedded request
        var innerPayload;
        try {
          innerPayload = JSON.parse(Utilities.newBlob(Utilities.base64Decode(req.d)).getDataAsString());
        } catch (x) {
          D.warn('🚇 داده تونل خراب است');
          return _json({ e: "tunnel_bad_data" });
        }

        // Build actual worker payload and send it
        var workerPayload = {
          k: AUTH_KEY,
          u: innerPayload.u || '',
          m: innerPayload.m || 'GET',
          h: innerPayload.h || {},
          b: innerPayload.b || '',
          ct: innerPayload.ct || '',
          r: innerPayload.r !== false,
          raw: innerPayload.raw === true,
          start: innerPayload.start,
          end: innerPayload.end,
          bfp: innerPayload.bfp === true
        };

        if (WORKER_SECRET) {
          workerPayload.h = workerPayload.h || {};
          workerPayload.h['X-Worker-Secret'] = WORKER_SECRET;
        }

        var workerResp;
        try {
          workerResp = UrlFetchApp.fetch(WORKER_URL, {
            method: "post",
            contentType: "application/json",
            payload: JSON.stringify(workerPayload),
            muteHttpExceptions: true,
            followRedirects: innerPayload.r !== false
          });
        } catch (err) {
          D.error('🔌 Worker fetch failed in tunnel');
          return _json({ e: "tunnel_worker_fail" });
        }

        var respBytes = workerResp.getBlob().getBytes();
        var b64 = Utilities.base64Encode(respBytes);
        D.timeEnd('TotalExecution');
        D.groupEnd();
        return ContentService.createTextOutput(JSON.stringify({ d: b64 }));
      }

      // PING keepalive
      if (req.tid && req.d === "PING") {
        if (_refreshTunnel(req.tid)) {
          D.timeEnd('TotalExecution');
          D.groupEnd();
          return ContentService.createTextOutput(JSON.stringify({ d: "PONG" }));
        } else {
          D.warn('🚇 PING for invalid tunnel');
          return _json({ e: "tunnel_invalid" });
        }
      }

      D.warn('🚇 فرمان تونل ناشناخته');
      return _json({ e: "bad_tunnel_request" });
    }

    // ── DSR Token Request ─────────────────────────────────────────
    if (req.dsr_token === true) {
      var token = _generateDsrToken();
      if (!token) {
        D.warn('🔐 DSR Token generation failed - WORKER_SECRET not set');
        D.timeEnd('TotalExecution');
        D.groupEnd();
        return _json({ e: "dsr_not_configured" });
      }
      D.log('🎫 DSR Token صادر شد');
      D.timeEnd('TotalExecution');
      D.groupEnd();
      return ContentService.createTextOutput(JSON.stringify({ dsr_token: token }));
    }

    // ── Rate Limiting ─────────────────────────────────────────────
    D.time('RateLimiting');
    var userIp = e.queryString || 'unknown';
    if (isRateLimited(userIp)) {
      D.warn('⏱️ محدودیت نرخ', { user: userIp });
      D.timeEnd('RateLimiting');
      D.timeEnd('TotalExecution');
      return _json({ e: "rate_limited" });
    }
    D.timeEnd('RateLimiting');
    D.log('⏱️ بررسی محدودیت نرخ موفق');

    // ── Routing ────────────────────────────────────────────────────
    D.time('Routing');
    var result;
    if (Array.isArray(req.q)) {
      D.log('📋 مسیر: پردازش دسته‌ای', { items: req.q.length });
      result = _doBatch(req.q, req.token, D);
    } else {
      D.log('📄 مسیر: پردازش تکی');
      result = _doSingle(req, D);
    }
    D.timeEnd('Routing');

    D.timeEnd('TotalExecution');
    D.groupEnd();
    return result;

  } catch (err) {
    D.error('💥 خطای داخلی', { message: err.message, stack: err.stack });
    D.timeEnd('TotalExecution');
    D.groupEnd();
    return _json({ e: "internal_error" });
  }
}

// ═══════════════ پردازش تکی ═══════════════
function _doSingle(req, D) {
  D.group('📄 _doSingle');

  if (!req.u || !/^https?:\/\//i.test(req.u)) {
    D.error('URL نامعتبر', { u: req.u });
    D.groupEnd();
    return _json({ e: "bad_url" });
  }
  if (req.u.length > 2048) {
    D.error('URL طولانی', { length: req.u.length });
    D.groupEnd();
    return _json({ e: "url_too_long" });
  }

  D.time('SingleRequest');

  var method = (req.m || "GET").toUpperCase();
  var canCache = CACHE_ENABLED && method === "GET" && !req.raw && !req.b;

  D.time('CacheLookup');
  var cacheKey;
  if (canCache) {
    cacheKey = getCacheKey(req);
    var cached = getFromCache(cacheKey);
    if (cached) {
      D.log('✅ پاسخ از کش خوانده شد', { key: cacheKey.substring(0, 20) + '...' });
      D.timeEnd('CacheLookup');
      D.timeEnd('SingleRequest');
      D.groupEnd();
      return ContentService.createTextOutput(cached.body);
    }
  }
  D.timeEnd('CacheLookup');

  D.time('BuildPayload');
  var payload = _buildWorkerPayload(req);
  if (WORKER_SECRET) {
    payload.h = payload.h || {};
    payload.h['X-Worker-Secret'] = WORKER_SECRET;
  }
  D.timeEnd('BuildPayload');
  D.log('📤 Payload برای Worker', { url: payload.u, method: payload.m });

  D.time('WorkerFetch');
  D.log('🔄 ارسال به Worker...');
  var resp;
  try {
    resp = UrlFetchApp.fetch(WORKER_URL, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
      followRedirects: req.r !== false
    });
  } catch (e) {
    D.error('🔌 Worker غیرقابل دسترس', { error: e.message });
    D.timeEnd('WorkerFetch');
    D.timeEnd('SingleRequest');
    D.groupEnd();
    return _json({ e: "worker_unreachable" });
  }
  D.timeEnd('WorkerFetch');

  D.time('ProcessResponse');
  var status = resp.getResponseCode();
  var blob = resp.getBlob();
  D.log('📥 پاسخ از Worker', { status: status, size: blob.getBytes().length });

  if (req.raw) {
    D.log('📦 ارسال پاسخ خام (باینری)');
    if (status >= 400) {
      D.warn('⚠️ خطای Worker در حالت raw', { code: status });
    }
    D.timeEnd('ProcessResponse');
    D.timeEnd('SingleRequest');
    D.groupEnd();
    if (status >= 400) return _json({ e: "worker_error", code: status });
    return ContentService.createTextOutput(blob.getBytes());
  }

  var text = blob.getDataAsString();
  try {
    var json = JSON.parse(text);
    D.log('✅ پاسخ JSON سالم', { keys: Object.keys(json) });

    if (canCache && status >= 200 && status < 300) {
      storeInCache(cacheKey, status, text, 'application/json');
      D.log('💾 پاسخ در کش ذخیره شد');
    }
    D.timeEnd('ProcessResponse');
    D.timeEnd('SingleRequest');
    D.groupEnd();
    return _json(json);
  } catch (e) {
    D.error('⚠️ پاسخ JSON نامعتبر از Worker', { status: status, preview: text.substring(0, 200) });
    D.timeEnd('ProcessResponse');
    D.timeEnd('SingleRequest');
    D.groupEnd();
    return _json({ e: "invalid_worker_format", code: status });
  }
}

// ═══════════════ پردازش دسته‌ای ═══════════════
// ═══════════════ Batch relay اصلاح شده ═══════════════
function _doBatch(items, token, D) {
  D.group('📋 _doBatch');
  D.time('BatchProcessing');

  var startIdx = token ? parseInt(token) : 0;
  if (startIdx >= items.length) {
    D.warn('شروع نامعتبر');
    D.groupEnd();
    return _json({ q: [] });
  }

  // تمام آیتم‌ها را یکجا به Worker می‌فرستیم
  var payloads = [];
  for (var i = startIdx; i < items.length; i++) {
    try {
      var p = _buildWorkerPayload(items[i]);
      payloads.push(p);
    } catch (e) {
      // ورودی نامعتبر را با خطا برمی‌گردانیم
      payloads.push({ e: "bad_url" });
    }
  }

  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify({ q: payloads }),
    muteHttpExceptions: true,
    headers: {}
  };
  if (WORKER_SECRET) {
    options.headers["X-Worker-Secret"] = WORKER_SECRET;
  }

  var workerResp;
  try {
    workerResp = UrlFetchApp.fetch(WORKER_URL, options);
  } catch (e) {
    D.error('🔴 Worker unreachable: ' + e.message);
    D.groupEnd();
    return _json({ e: "worker_unreachable" });
  }

  var text = workerResp.getContentText();
  var data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    D.error('⚠️ پاسخ JSON نامعتبر از Worker');
    return _json({ e: "invalid_worker_format" });
  }

  if (data.e) {
    D.error('Worker error: ' + data.e);
    return _json({ e: data.e });
  }

  // تضمین اندازه‌ی آرایه
  var results = data.q || [];
  if (results.length !== payloads.length) {
    D.warn('تعداد پاسخ‌ها با درخواست‌ها مغایرت دارد', { expected: payloads.length, got: results.length });
  }

  // اگر بعضی آیتم‌ها خطا دارند، آن‌ها را پر کن
  while (results.length < payloads.length) {
    results.push({ e: "missing_response" });
  }

  D.log('✅ Batch کامل شد', { sent: payloads.length, received: results.length });
  D.timeEnd('BatchProcessing');
  D.groupEnd();
  return _json({ q: results });
}

// ═══════════════ Payload Builder (BFP + معمولی) ═══════════════
function _buildWorkerPayload(req) {
  var headers = {};
  if (req.h && typeof req.h === 'object' && !Array.isArray(req.h)) {
    for (var k in req.h) {
      if (req.h.hasOwnProperty(k)) {
        var keyLower = k.toLowerCase();
        if (!SKIP_HEADERS[keyLower] && isValidHeaderValue(req.h[k])) {
          headers[k] = req.h[k];
        }
      }
    }
  }

  // ── BFP: فعال‌سازی حالت باینری ──────────────────────────────
  if (req.bfp === true) {
    headers["X-BFP"] = "1";
  }

  return {
    u: req.u,
    m: (req.m || "GET").toUpperCase(),
    h: headers,
    b: req.b || null,
    ct: req.ct || null,
    r: req.r !== false,
    raw: req.raw === true,
    start: req.start,
    end: req.end
  };
}

// ═══════════════ Helpers ═══════════════
function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj));
}

// ═══════════════ درگاه دریافت لاگ (doGet) ═══════════════
function doGet(e) {
  if (e && e.parameter && e.parameter.debug_key === DEBUG_KEY) {
    var logs = _getLogBuffer();
    return ContentService.createTextOutput(JSON.stringify(logs, null, 2));
  }
  
  return HtmlService.createHtmlOutput(
    '<!DOCTYPE html><html><head><title>Relay</title></head>' +
    '<body style="font-family:sans-serif;text-align:center;margin-top:10%">' +
    '<h1>⛓️ Relay Active</h1><p>Smart caching enabled. Use <code>?debug_key=...</code> for logs.</p></body></html>'
  );
}