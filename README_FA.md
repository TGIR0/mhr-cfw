# TG Domain Relay - راهنمای فارسی

<div dir="rtl">

| [English](README.md) | [Persian](README_FA.md) |
| --- | --- |

این مخزن یک پروژه رله مستقل است و فورک رسمی هیچ پروژه بالادستی نیست. هدف فعلی
ساخت نسخه پایدار Python برای شرایط شبکه ایران است؛ در مرحله بعدی می‌توان مسیر
بازنویسی Rust را با همین قراردادها و تست‌ها آماده کرد.

## معماری فعلی

مسیریابی هوشمند سهمیه Google را فقط برای ترافیکی مصرف می‌کند که واقعاً به relay
نیاز دارد:

```
دامنه/IP ایران             -> اینترنت مستقیم محلی
دامنه‌های Google مجاز      -> مسیر مستقیم fronted
HTTP(S) خارجی              -> Google Apps Script -> Cloudflare Worker
UDP/QUIC/TCP خام/WebSocket -> fail-closed تا برنامه به TCP/HTTPS برگردد
```

```
مرورگر یا برنامه
  -> پروکسی محلی HTTP یا SOCKS5
  -> اتصال TLS به IP فرانت گوگل با SNI گوگل
  -> Google Apps Script
  -> Cloudflare Worker
  -> سایت مقصد
```

مسیر اختیاری برای IP خروجی پایدار:

```
Cloudflare Worker -> Upstream Forwarder روی VPS -> سایت مقصد
```

پروکسی محلی با گواهی CA محلی ترافیک HTTPS مرورگر را باز می‌کند، درخواست HTTP
را به JSON رله تبدیل می‌کند، آن را از مسیر Google Apps Script به Worker می‌فرستد
و پاسخ HTTP بازسازی‌شده را به مرورگر برمی‌گرداند.

## قابلیت‌های فعلی

- پروکسی HTTP محلی و SOCKS5 برای دستور `CONNECT`.
- MITM محلی برای ترافیک HTTPS مرورگر.
- رله Google Apps Script با `UrlFetchApp.fetch()` و `fetchAll()`.
- خروجی Cloudflare Worker با امکان Forwarder روی VPS برای IP پایدار.
- `RoutingPolicy` مرکزی: دامنه‌های `.ir` و GeoIP ایران مستقیم می‌روند، Google
  مجاز از مسیر fronted direct می‌رود، و HTTP(S) خارجی از relay عبور می‌کند.
- HTTP/2 بین کلاینت محلی و گوگل، اگر بسته `h2` نصب باشد و ALPN اجازه بدهد.
- دانلود موازی فایل‌های بزرگ با Range request.
- policy بسته برای raw TCP، UDP و QUIC پشتیبانی‌نشده تا ترافیک به شکل پنهانی
  از شبکه عادی خارج نشود.

## مرزهای واقعی پلتفرم‌ها

این پروژه باید فقط مطابق مستندات رسمی Google و Cloudflare جلو برود.

- Google Apps Script با `UrlFetchApp` برای fetchهای HTTP/HTTPS مستند شده است؛
  runtime عمومی TCP، UDP، QUIC یا WebSocket نیست.
- Cloudflare Workers برای HTTP/HTTPS، WebSocket، ورودی HTTP/3 و سوکت TCP خروجی
  مستند شده‌اند، اما Worker یک خروجی عمومی UDP نیست.
- بنابراین UDP و QUIC باید به صورت فاز جدا با encapsulation یا forwarder
  خودمیزبان طراحی شوند. نباید آن را «پشتیبانی مستقیم UDP/QUIC توسط Apps Script»
  معرفی کرد.
- مقدارهای `allow_direct_tcp`، `allow_direct_udp` و `tcp_relay_mode=worker_websocket`
  در سیاست فعلی google-relay-only نادیده گرفته می‌شوند؛ ترافیک پشتیبانی‌نشده
  fail-closed می‌ماند.

منابع رسمی:

- [Google Apps Script `UrlFetchApp`](https://developers.google.com/apps-script/reference/url-fetch/url-fetch-app)
- [سهمیه‌های Apps Script](https://developers.google.com/apps-script/guides/services/quotas)
- [پروتکل‌های Cloudflare Workers](https://developers.cloudflare.com/workers/reference/protocols/)
- [WebSocket در Workers](https://developers.cloudflare.com/workers/runtime-apis/websockets/)
- [TCP sockets در Workers](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)

## نصب

ویندوز:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

لینوکس / مک:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

اگر PyPI مستقیم در دسترس نبود:

```bash
pip install -r requirements.txt -i https://mirror-pypi.runflare.com/simple/ --trusted-host mirror-pypi.runflare.com
```

## استقرار

1. در Cloudflare یک Worker بسازید و محتوای `deploy/cloudflare-worker/worker.js` را قرار دهید.
2. مقدار `WORKER_URL` در فایل Worker را با دامنه Worker خودتان عوض کنید.
3. در Google Apps Script یک Web app بسازید و محتوای `deploy/gas/Code.gs` را قرار دهید.
4. در `Code.gs` مقدارهای `AUTH_KEY` و `WORKER_URL` را تنظیم کنید. اگر
   `WORKER_AUTH_KEY` در Worker فعال است، همان مقدار را در `Code.gs` هم بگذارید.
5. Apps Script را به صورت Web app با دسترسی `Anyone` deploy کنید.
6. Deployment ID را برای فایل تنظیمات نگه دارید.

## تنظیمات

از نمونه امن، فایل خصوصی بسازید:

```bash
copy config.example.json config.json
```

لینوکس / مک:

```bash
cp config.example.json config.json
```

حداقل این مقدارها را تنظیم کنید:

- `script_id`: Deployment ID از Apps Script.
- `auth_key`: همان رمز `AUTH_KEY` داخل `Code.gs`.
- `google_ip`: IP فرانت گوگل. برای تست candidateها از `python main.py --scan` استفاده کنید.

فایل `config.json` را commit نکنید؛ این فایل به خاطر داشتن secret در `.gitignore`
قرار دارد.

اعتبارسنجی تنظیمات بدون اجرای proxy:

```bash
python main.py --check-config
```

بررسی تصمیم مسیریابی بدون اجرای proxy:

```bash
python main.py --routing-check example.ir
```

### تنظیمات مهم transport و سرعت

| کلید | توضیح |
| --- | --- |
| `routing_mode` | مقدار `compat_smart` تصمیم‌های کم‌مصرف مسیر را فعال می‌کند. |
| `iran_direct_enabled` | مقصدهای ایران را قبل از مصرف سهمیه relay مستقیم می‌فرستد. |
| `iran_domain_suffixes` | پسوندهای دامنه‌ای که ایرانی محسوب می‌شوند (پیش‌فرض: `.ir`). |
| `iran_geoip_enabled` | استفاده از پایگاه CIDR برای شناسایی IP ایران. |
| `iran_geoip_db` | مسیر فایل CIDR (پیش‌فرض: `data/geoip/ir.cidr`). |
| `google_fronted_direct_enabled` | Googleهای مجاز را روی مسیر مستقیم fronted نگه می‌دارد. |
| `relay_foreign_enabled` | HTTP(S) خارجی را روی مسیر Apps Script -> Worker نگه می‌دارد. |
| `websocket_mode` | پیش‌فرض `relay`؛ برای fail-closed کردن WebSocket مقدار `block` بگذارید. |
| `privacy_log_mode` | پیش‌فرض `host`. برای debug مقدار `full` و برای کمترین لاگ `off`. |
| `tcp_relay_mode` | مقدار `http_only` را نگه دارید؛ TCP خام در این فاز بسته است. |
| `udp_mode` | فعلاً `disabled`؛ مقدارهای آینده باید از carrier کپسوله‌شده استفاده کنند. |
| `quic_mode` | پیش‌فرض `block` برای جلوگیری از نشتی UDP/QUIC. |
| `relay_concurrency` | حداکثر تعداد درخواست relay همزمان. |
| `pool_max` / `pool_min_idle` | اندازه pool اتصال TLS. |
| `batch_max` / `batch_window_*` | تنظیمات throughput دسته‌ای Apps Script. |
| `parallel_range_enabled` | افزایش سرعت دانلود بزرگ با Range request. |
| `chunked_download_*` | اندازه chunk، موازی‌سازی و محدودیت‌های دانلود موازی. |

## اجرا

ویندوز:

```
run.bat
```

لینوکس / مک:

```bash
chmod +x run.sh
./run.sh
```

اجرای دستی:

```bash
python main.py
```

پورت‌های پیش‌فرض:

- پروکسی HTTP: `127.0.0.1:8085`
- پروکسی SOCKS5: `127.0.0.1:1080`

## IP خروجی پایدار

IP خروجی Worker ممکن است بین edgeهای Cloudflare تغییر کند. برای سایت‌هایی که
challenge یا session را به IP وصل می‌کنند، می‌توانید
`deploy/upstream_forwarder/upstream_forwarder.js` را روی VPS با IP ثابت اجرا کنید
و این متغیرها را در Worker بگذارید:

| نام | نوع | نمونه |
| --- | --- | --- |
| `UPSTREAM_FORWARDER_URL` | Secret | `https://forwarder.example.com/fwd` |
| `UPSTREAM_AUTH_KEY` | Secret | همان `AUTH_KEY` روی VPS |
| `UPSTREAM_FAIL_MODE` | Variable | `closed` یا `open` |
| `UPSTREAM_TIMEOUT_MS` | Variable | `25000` |

## کتابخانه‌های پایه

| بسته | کاربرد |
| --- | --- |
| `cryptography` | ساخت CA و گواهی‌های MITM. |
| `h2` | انتقال HTTP/2 به سمت گوگل. |
| `certifi` | CA bundle پایدار برای container و Pythonهای embedded. |
| `brotli` / `zstandard` | decode کردن پاسخ‌های مدرن. |
| `websockets` | carrier WebSocket برای tunnel TCP از مسیر Worker. |
| `h11` / `anyio` | کتابخانه‌های پروتکل نگهداری‌شده برای transport WebSocket. |

ابزارهای توسعه در `requirements-dev.txt` هستند.

## ایمنی

این نرم‌افزار فقط برای آموزش، پژوهش و تست ارائه می‌شود. رعایت قوانین محلی و
شرایط استفاده Google و Cloudflare بر عهده کاربر است. کلید خصوصی `ca/ca.key`
حساس است و نباید به کسی داده شود.

## لایسنس

[MIT](LICENSE)

</div>