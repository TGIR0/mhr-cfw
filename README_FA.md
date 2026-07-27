# TG Domain Relay - راهنمای فارسی

<div dir="rtl">

| [English](README.md) | [Persian](README_FA.md) |
| :---: | :---: |

این مخزن یک پروژه رله مستقل است و فورک رسمی هیچ پروژه بالادستی نیست. هدف فعلی
ساخت نسخه پایدار Python برای شرایط شبکه ایران است؛ در مرحله بعدی می توان مسیر
بازنویسی Rust را با همین قراردادها و تست ها آماده کرد.

## معماری فعلی

مسیریابی هوشمند سهمیه Google را فقط برای ترافیکی مصرف می کند که واقعاً به relay
نیاز دارد:

```text
دامنه/IP ایران             -> اینترنت مستقیم محلی
دامنه های Google مجاز      -> مسیر مستقیم fronted
HTTP(S) خارجی              -> Google Apps Script -> Cloudflare Worker
UDP/QUIC/TCP خام/WebSocket -> fail-closed تا برنامه به TCP/HTTPS برگردد
```

```text
مرورگر یا برنامه
  -> پروکسی محلی HTTP یا SOCKS5
  -> اتصال TLS به IP فرانت گوگل با SNI گوگل
  -> Google Apps Script
  -> Cloudflare Worker
  -> سایت مقصد
```

مسیر اختیاری برای IP خروجی پایدار:

```text
Cloudflare Worker -> Upstream Forwarder روی VPS -> سایت مقصد
```

پروکسی محلی با گواهی CA محلی ترافیک HTTPS مرورگر را باز می کند، درخواست HTTP
را به JSON رله تبدیل می کند، آن را از مسیر Google Apps Script به Worker می فرستد
و پاسخ HTTP بازسازی شده را به مرورگر برمی گرداند.

## قابلیت های فعلی

- پروکسی HTTP محلی و SOCKS5 برای دستور `CONNECT`.
- MITM محلی برای ترافیک HTTPS مرورگر.
- رله Google Apps Script با `UrlFetchApp.fetch()` و `fetchAll()`.
- خروجی Cloudflare Worker با امکان Forwarder روی VPS برای IP پایدار.
- `RoutingPolicy` مرکزی: دامنه های `.ir` و GeoIP ایران مستقیم می روند، Google
  مجاز از مسیر fronted direct می رود، و HTTP(S) خارجی از relay عبور می کند.
- HTTP/2 بین کلاینت محلی و گوگل، اگر بسته `h2` نصب باشد و ALPN اجازه بدهد.
- دانلود موازی فایل های بزرگ با Range request.
- policy بسته برای raw TCP، UDP و QUIC پشتیبانی نشده تا ترافیک به شکل پنهانی
  از شبکه عادی خارج نشود.
- پایه KCP-style برای session، ack و retransmit اضافه شده، اما هنوز به مسیر
  زنده proxy وصل نشده است.

## مرزهای واقعی پلتفرم ها

این پروژه باید فقط مطابق مستندات رسمی Google و Cloudflare جلو برود.

- Google Apps Script با `UrlFetchApp` برای fetchهای HTTP/HTTPS مستند شده است؛
  runtime عمومی TCP، UDP، QUIC یا WebSocket نیست.
- Cloudflare Workers برای HTTP/HTTPS، WebSocket، ورودی HTTP/3 و سوکت TCP خروجی
  مستند شده اند، اما Worker یک خروجی عمومی UDP نیست.
- بنابراین UDP و QUIC باید به صورت فاز جدا با encapsulation یا forwarder
  خودمیزبان طراحی شوند. نباید آن را «پشتیبانی مستقیم UDP/QUIC توسط Apps Script»
  معرفی کرد.
- مقدارهای `allow_direct_tcp`، `allow_direct_udp`، `tcp_relay_mode=worker_websocket`
  و `direct_worker_enabled` در سیاست فعلی google-relay-only نادیده گرفته می شوند؛
  ترافیک پشتیبانی نشده fail-closed می ماند.

منابع رسمی:

- Google Apps Script `UrlFetchApp`: https://developers.google.com/apps-script/reference/url-fetch/url-fetch-app
- سهمیه های Apps Script: https://developers.google.com/apps-script/guides/services/quotas
- پروتکل های Cloudflare Workers: https://developers.cloudflare.com/workers/reference/protocols/
- WebSocket در Workers: https://developers.cloudflare.com/workers/runtime-apis/websockets/
- TCP sockets در Workers: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/

## نصب

ویندوز:

```cmd
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

```cmd
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

تنظیمات مهم transport و سرعت:

- `routing_mode`: مقدار `compat_smart` تصمیم های کم مصرف مسیر را فعال می کند.
- `iran_direct_enabled`، `iran_domain_suffixes`، `iran_geoip_enabled`،
  `iran_geoip_db`: مقصدهای ایران را قبل از مصرف سهمیه relay مستقیم می فرستند.
- `google_fronted_direct_enabled`: Googleهای مجاز را روی مسیر مستقیم fronted نگه
  می دارد.
- `relay_foreign_enabled`: HTTP(S) خارجی را روی مسیر Apps Script -> Worker نگه
  می دارد.
- `websocket_mode`: مقدار `http_only`؛ upgradeهایی که روی Apps Script قابل حمل
  نیستند fail-closed می شوند.
- `privacy_log_mode`: پیش فرض `host` است تا path و query string در لاگ محلی
  نیاید. برای debug محلی `full` و برای کمترین لاگ `off` استفاده کنید.
- `tcp_relay_mode`: مقدار `http_only` را نگه دارید؛ TCP خام در این فاز بسته است.
- `udp_mode`: فعلاً `disabled`؛ مقدارهای آینده باید از carrier کپسوله شده استفاده کنند.
- `quic_mode`: پیش فرض `block` برای جلوگیری از نشتی UDP/QUIC.
- `kcp_enabled`، `kcp_mtu`، `kcp_window`، `kcp_resend_after`: تنظیمات reliability
  برای carrier آینده.
- `relay_concurrency`، `pool_max`، `pool_min_idle`، `batch_max`،
  `batch_window_micro`، `batch_window_macro`: تنظیمات throughput مسیر Apps Script.
- `parallel_range_enabled` و کلیدهای `chunked_download_*`: افزایش سرعت دانلودهای بزرگ.

## اجرا

ویندوز:

```cmd
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

پورت های پیش فرض:

- پروکسی HTTP: `127.0.0.1:8085`
- پروکسی SOCKS5: `127.0.0.1:1080`

## IP خروجی پایدار

IP خروجی Worker ممکن است بین edgeهای Cloudflare تغییر کند. برای سایت هایی که
challenge یا session را به IP وصل می کنند، می توانید
`deploy/upstream_forwarder/upstream_forwarder.js` را روی VPS با IP ثابت اجرا کنید
و این متغیرها را در Worker بگذارید:

| نام | نوع | نمونه |
| --- | --- | --- |
| `UPSTREAM_FORWARDER_URL` | Secret | `https://forwarder.example.com/fwd` |
| `UPSTREAM_AUTH_KEY` | Secret | همان `AUTH_KEY` روی VPS |
| `UPSTREAM_FAIL_MODE` | Variable | `closed` یا `open` |
| `UPSTREAM_TIMEOUT_MS` | Variable | `25000` |

## کتابخانه های پایه

- `cryptography`: ساخت CA و گواهی های MITM.
- `h2`: انتقال HTTP/2 به سمت گوگل.
- `certifi`: CA bundle پایدار برای container و Pythonهای embedded.
- `brotli` و `zstandard`: decode کردن پاسخ های مدرن.
- `websockets`: برای آزمایش های future carrier نگه داشته شده، اما در سیاست
  فعلی google-relay-only فعال نیست.
- `aioquic`، `h11` و `anyio`: برای فازهای بعدی QUIC/HTTP، با اتکا به
  پیاده سازی های نگهداری شده به جای parser دستی.
- `ikcp`: گزینه اختیاری برای carrier بومی KCP در نسخه های Python سازگار.

ابزارهای توسعه در `requirements-dev.txt` هستند.

## ایمنی

این نرم افزار فقط برای آموزش، پژوهش و تست ارائه می شود. رعایت قوانین محلی و
شرایط استفاده Google و Cloudflare بر عهده کاربر است. کلید خصوصی `ca/ca.key`
حساس است و نباید به کسی داده شود.

</div>
