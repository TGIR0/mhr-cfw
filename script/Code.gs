// ═══════════════════════════════════════════
// 🧠 ARES v2.0 — Titan Edition
// ═══════════════════════════════════════════

const SCRIPT_PROP = PropertiesService.getScriptProperties();
const AUTH_KEY = SCRIPT_PROP.getProperty('AUTH_KEY');
const WORKER_URL = SCRIPT_PROP.getProperty('WORKER_URL');
const WORKER_SECRET = SCRIPT_PROP.getProperty('WORKER_SECRET') || '';
const HEALTH_KEY = SCRIPT_PROP.getProperty('HEALTH_KEY') || 'titan_health_2026';

const SIBLING_SCRIPTS = (SCRIPT_PROP.getProperty('SIBLING_SCRIPTS') || '').split(',').map(s => s.trim()).filter(Boolean);

const DAILY_QUOTA_LIMIT = 20000;
const QUOTA_WARN_LEVEL = 0.85;

const CACHE_TTL_NORMAL = 1800;
const CACHE_TTL_SAVING = 7200;
const CACHE_TTL_CRITICAL = 14400;

const RATE_LIMIT_WINDOW = 60;
const RATE_LIMIT_MAX = 3000;

// ═══ پیکربندی مدارشکن ═══
const CB_FAIL_THRESHOLD = 3;      // بعد از ۳ خطا قطع شود
const CB_TIMEOUT = 120000;        // به مدت ۲ دقیقه (میلی‌ثانیه)

// ═══ هدرها ═══
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

// ═══ توابع کمکی ═══
function _json(obj) { return ContentService.createTextOutput(JSON.stringify(obj)); }
function isValidHeaderValue(v) { return typeof v === 'string' && !/[\r\n]/.test(v); }
function _isValidUrl(u) { return u && /^https?:\/\//i.test(u) && u.length <= 2048; }
function _getClientIp(e) {
  try { return e.parameter?.['x-forwarded-for'] || e.parameter?.['cf-connecting-ip'] || 'unknown'; } catch (_) { return 'unknown'; }
}

// ═══ ردیاب سهمیه ═══
function _getQuotaCounter() { return parseInt(CacheService.getScriptCache().get('__quota_count__') || '0'); }
function _incrementQuota() {
  const cache = CacheService.getScriptCache();
  let c = _getQuotaCounter() + 1;
  cache.put('__quota_count__', String(c), 86400);
  return c;
}
function _getQuotaHealth() {
  const ratio = _getQuotaCounter() / DAILY_QUOTA_LIMIT;
  if (ratio >= 0.95) return 'critical';
  if (ratio >= QUOTA_WARN_LEVEL) return 'saving';
  return 'normal';
}
function _getAdaptiveTTL() {
  const h = _getQuotaHealth();
  if (h === 'critical') return CACHE_TTL_CRITICAL;
  if (h === 'saving') return CACHE_TTL_SAVING;
  return CACHE_TTL_NORMAL;
}

// ═══ کش ═══
function getCacheKey(req) {
  const raw = (req.u || '') + '|' + (req.m || 'GET').toUpperCase();
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw);
  return 'resp_' + Utilities.base64Encode(digest);
}

// ═══ مدارشکن (Circuit Breaker) ═══
function _isCircuitOpen() {
  const cache = CacheService.getScriptCache();
  return cache.get('__cb_open__') === '1';
}
function _tripCircuit() {
  const cache = CacheService.getScriptCache();
  cache.put('__cb_open__', '1', CB_TIMEOUT / 1000);
  cache.put('__cb_fails__', '0', CB_TIMEOUT / 1000);
}
function _recordFailure() {
  const cache = CacheService.getScriptCache();
  let fails = parseInt(cache.get('__cb_fails__') || '0') + 1;
  cache.put('__cb_fails__', String(fails), 3600);
  if (fails >= CB_FAIL_THRESHOLD) _tripCircuit();
}
function _recordSuccess() {
  CacheService.getScriptCache().put('__cb_fails__', '0', 3600);
}

// ═══ ادغام درخواست تکراری (Deduplication) ═══
function _dedupKey(req) {
  const raw = (req.u || '') + (req.m || 'GET') + JSON.stringify(req.h || {}) + (req.b || '');
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw);
  return 'dedup_' + Utilities.base64Encode(digest);
}
function _isDuplicate(req) {
  const key = _dedupKey(req);
  const cache = CacheService.getScriptCache();
  if (cache.get(key)) return true; // درخواست تکراری است
  cache.put(key, '1', 30); // ۳۰ ثانیه TTL
  return false;
}

// ═══ Failover ═══
function _tryFailover(req) {
  if (!SIBLING_SCRIPTS.length) return null;
  const idx = Math.floor(Math.random() * SIBLING_SCRIPTS.length);
  try {
    const resp = UrlFetchApp.fetch(`https://script.google.com/macros/s/${SIBLING_SCRIPTS[idx]}/exec`, {
      method: "post", contentType: "application/json",
      payload: JSON.stringify(req), muteHttpExceptions: true
    });
    if (resp.getResponseCode() === 200) return JSON.parse(resp.getContentText());
  } catch (_) {}
  return null;
}

// ═══ پردازش تکی ═══
function _doSingle(req) {
  if (!_isValidUrl(req.u)) return _json({ e: "bad_url" });

  const method = (req.m || "GET").toUpperCase();
  const canCache = method === "GET" && !req.raw && !req.b;
  const cacheKey = canCache ? getCacheKey(req) : null;

  // ۱. چک کش
  if (cacheKey) {
    const cache = CacheService.getScriptCache();
    const cached = cache.get(cacheKey);
    if (cached) {
      try { const data = JSON.parse(cached); if (data.expires > Date.now()) return ContentService.createTextOutput(data.body); } catch (_) {}
    }
  }

  // ۲. چک مدارشکن
  if (_isCircuitOpen()) {
    // تلاش برای failover شفاف
    if (SIBLING_SCRIPTS.length) { const fo = _tryFailover(req); if (fo) return _json(fo); }
    return _json({ e: "circuit_open", detail: "Worker unavailable, try later" });
  }

  // ۳. چک سهمیه بحرانی
  const health = _getQuotaHealth();
  if (health === 'critical' && SIBLING_SCRIPTS.length) {
    const fo = _tryFailover(req);
    if (fo) return _json(fo);
  }

  // ۴. چک تکراری بودن (Deduplication) — فقط برای GETها
  if (method === "GET" && _isDuplicate(req)) {
    // این درخواست تکراری است — منتظر پاسخ اصلی باش
    Utilities.sleep(500); // صبر کوتاه
    if (cacheKey) {
      const cached = CacheService.getScriptCache().get(cacheKey);
      if (cached) {
        try { const data = JSON.parse(cached); if (data.expires > Date.now()) return ContentService.createTextOutput(data.body); } catch (_) {}
      }
    }
  }

  const payload = {
    u: req.u, m: method,
    h: req.h || {}, b: req.b || null, ct: req.ct || null,
    r: req.r !== false, raw: req.raw === true, k: AUTH_KEY
  };
  if (WORKER_SECRET) { payload.h = payload.h || {}; payload.h['X-Worker-Secret'] = WORKER_SECRET; }

  try {
    const resp = UrlFetchApp.fetch(WORKER_URL, {
      method: "post", contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true, followRedirects: req.r !== false
    });

    _incrementQuota();
    _recordSuccess(); // ← مدارشکن: ثبت موفقیت

    const status = resp.getResponseCode();
    const text = resp.getContentText();

    if (req.raw) {
      if (status >= 400) return _json({ e: "worker_error", code: status });
      return ContentService.createTextOutput(resp.getBlob().getBytes());
    }

    try {
      const json = JSON.parse(text);
      if (canCache && status >= 200 && status < 300) {
        const ttl = _getAdaptiveTTL();
        CacheService.getScriptCache().put(cacheKey, JSON.stringify({
          body: text, expires: Date.now() + ttl * 1000
        }), ttl);
      }
      return _json(json);
    } catch (_) {
      return _json({ e: "invalid_worker_format", code: status });
    }
  } catch (_) {
    _recordFailure(); // ← مدارشکن: ثبت شکست
    return _json({ e: "worker_unreachable" });
  }
}

// ═══ پردازش دسته‌ای ═══
function _doBatch(items) {
  const payloads = [];
  for (let i = 0; i < items.length; i++) {
    if (_isValidUrl(items[i].u)) {
      const p = { u: items[i].u, m: (items[i].m || "GET").toUpperCase(), h: items[i].h || {}, b: items[i].b || null, ct: items[i].ct || null, r: items[i].r !== false, raw: items[i].raw === true, k: AUTH_KEY };
      if (WORKER_SECRET) { p.h = p.h || {}; p.h['X-Worker-Secret'] = WORKER_SECRET; }
      payloads.push(p);
    } else { payloads.push({ e: "bad_url" }); }
  }

  if (_isCircuitOpen()) return _json({ e: "circuit_open" });

  try {
    const resp = UrlFetchApp.fetch(WORKER_URL, {
      method: "post", contentType: "application/json",
      payload: JSON.stringify({ k: AUTH_KEY, q: payloads }),
      muteHttpExceptions: true, headers: WORKER_SECRET ? { "X-Worker-Secret": WORKER_SECRET } : {}
    });
    _incrementQuota(); _recordSuccess();
    const data = JSON.parse(resp.getContentText());
    if (data.e) return _json({ e: data.e });
    const results = data.q || [];
    while (results.length < payloads.length) results.push({ e: "missing_response" });
    return _json({ q: results });
  } catch (_) {
    _recordFailure();
    return _json({ e: "worker_unreachable" });
  }
}

// ═══ Rate Limiter ═══
function isRateLimited(uid) {
  if (uid === '127.0.0.1' || uid === '::1' || uid === 'unknown') return false;
  const cache = CacheService.getScriptCache();
  const key = 'rl_' + uid;
  let count = parseInt(cache.get(key) || '0');
  if (count >= RATE_LIMIT_MAX) return true;
  cache.put(key, String(count + 1), RATE_LIMIT_WINDOW);
  return false;
}

// ═══════════════ ورودی اصلی ═══════════════
function doPost(e) {
  let req;
  try { req = JSON.parse(e.postData.contents); } catch (_) { return _json({ e: "invalid_json" }); }
  if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });
  if (isRateLimited(_getClientIp(e))) return _json({ e: "rate_limited" });
  if (Array.isArray(req.q)) return _doBatch(req.q);
  return _doSingle(req);
}

function doGet(e) {
  if (e?.parameter?.key === HEALTH_KEY) {
    return _json({
      quota_used: _getQuotaCounter(),
      quota_limit: DAILY_QUOTA_LIMIT,
      health: _getQuotaHealth(),
      circuit_open: _isCircuitOpen(),
      siblings: SIBLING_SCRIPTS.length,
      ttl: _getAdaptiveTTL(),
      fails: parseInt(CacheService.getScriptCache().get('__cb_fails__') || '0')
    });
  }
  return HtmlService.createHtmlOutput('<h1>ARES v2.0 (Titan) Active</h1>');
}