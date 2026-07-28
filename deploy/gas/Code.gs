// Google Apps Script

const AUTH_KEY = "STRONG_SECRET_KEY";
const WORKER_URL = "https://example.workers.dev";
const WORKER_AUTH_KEY = "";

const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  "accept-encoding": 1,
};

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });

    if (Array.isArray(req.q)) return _doBatch(req.q);
    return _doSingle(req);

  } catch (err) {
    return _json({ e: String(err) });
  }
}

function _doSingle(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }

  var payload = _buildWorkerPayload(req);

  var fetchOpts = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    followRedirects: true
  };
  if (WORKER_AUTH_KEY) {
    fetchOpts.headers = { "Authorization": "Bearer " + WORKER_AUTH_KEY };
  }
  var resp = UrlFetchApp.fetch(WORKER_URL, fetchOpts);

  var text = resp.getContentText();
  try {
    return _json(JSON.parse(text));
  } catch (e) {
    return _json({ e: "invalid worker response", raw: text.substring(0, 500) });
  }
}

function _doBatch(items) {
  var fetchArgs = [];
  var errorMap = {};

  for (var i = 0; i < items.length; i++) {
    var item = items[i];

    if (!item.u || typeof item.u !== "string" || !item.u.match(/^https?:\/\//i)) {
      errorMap[i] = "bad url";
      continue;
    }

    var payload = _buildWorkerPayload(item);

    var opts = {
      url: WORKER_URL,
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
      followRedirects: true
    };
    if (WORKER_AUTH_KEY) {
      opts.headers = { "Authorization": "Bearer " + WORKER_AUTH_KEY };
    }
    fetchArgs.push({ _i: i, _o: opts });
  }

  var responses = [];
  if (fetchArgs.length > 0) {
    responses = UrlFetchApp.fetchAll(fetchArgs.map(function(x) { return x._o; }));
  }

  var results = [];
  var rIdx = 0;

  for (var i = 0; i < items.length; i++) {
    if (errorMap.hasOwnProperty(i)) {
      results.push({ e: errorMap[i] });
    } else {
      var resp = responses[rIdx++];
      var text = resp.getContentText();
      try {
        results.push(JSON.parse(text));
      } catch (e) {
        results.push({ e: "invalid worker response", raw: text.substring(0, 500) });
      }
    }
  }

  return _json({ q: results });
}

function _buildWorkerPayload(req) {
  var headers = {};

  if (req.h && typeof req.h === "object") {
    for (var k in req.h) {
      if (req.h.hasOwnProperty(k) && !SKIP_HEADERS[k.toLowerCase()]) {
        headers[k] = req.h[k];
      }
    }
  }

  var out = {
    u: req.u,
    m: (req.m || "GET").toUpperCase(),
    h: headers,
    r: req.r !== false
  };

  // Handle compressed body — decompress on Worker side
  if (req.b) {
    out.b = req.b;
    // Signal that body is gzip-compressed (Apps Script base64 decodes, Worker decompresses)
    if (req.ce === "gzip") {
      out.ce = "gzip";
    }
  }

  if (req.ct) out.ct = req.ct;
  if (typeof req.f === "number") out.f = req.f;
  if (WORKER_AUTH_KEY) out.k = WORKER_AUTH_KEY;
  return out;
}

function doGet(e) {
  return HtmlService.createHtmlOutput(
    "<!DOCTYPE html><html><head><title>TG Domain Relay</title></head>" +
      '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
      "<h1>TG Domain Relay Active</h1><p>Cloudflare Worker routing enabled.</p>" +
      "</body></html>"
  );
}

function _json(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
