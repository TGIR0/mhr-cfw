# TG Domain Relay - راهنمای فارسی

<div dir="rtl">

| [English](README.md) | [Persian](README_FA.md) |
| :---: | :---: |

این مخزن یک پروژه رله مستقل است و فورک رسمی هیچ پروژه بالادستی نیست. هدف فعلی
ساخت نسخه پایدار Python برای شرایط شبکه ایران است؛ در مرحله بعدی می توان مسیر
بازنویسی Rust را با همین قراردادها و تست ها آماده کرد.

## معماری فعلی

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
- رله مستقیم اختیاری به Cloudflare Worker. وقتی hostname خود Worker قابل
  دسترس باشد، پروکسی محلی payloadهای HTTP را مستقیم به Worker می فرستد و
  Apps Script فقط fallback می ماند؛ در نتیجه مصرف سهمیه Google کم می شود.
- carrier اختیاری Worker WebSocket برای streamهای TCP خام؛ پیش فرض خاموش است و
  از مسیر Apps Script جداست.
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
- مقدارهای `allow_direct_tcp` و `allow_direct_udp` پیش فرض `false` دارند. روشن
  کردن آن ها یعنی اولویت دادن به سازگاری به جای مقاومت در برابر نشتی.

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
3. اگر رله مستقیم Worker را فعال می کنید، secret به نام `WORKER_AUTH_KEY` را
   در Worker بگذارید و همان مقدار را در `worker_auth_key` محلی تنظیم کنید.
4. در Google Apps Script یک Web app بسازید و محتوای `deploy/gas/Code.gs` را قرار دهید.
5. در `Code.gs` مقدارهای `AUTH_KEY` و `WORKER_URL` را تنظیم کنید. اگر
   `WORKER_AUTH_KEY` در Worker فعال است، همان مقدار را در `Code.gs` هم بگذارید.
6. Apps Script را به صورت Web app با دسترسی `Anyone` deploy کنید.
7. Deployment ID را برای فایل تنظیمات نگه دارید.

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

تنظیمات مهم transport و سرعت:

- `direct_worker_enabled`: وقتی `true` باشد، payloadهای HTTP اول به
  `worker_url` مستقیم می روند و فقط بعد از failure/circuit-breaker به Apps
  Script برمی گردند. این کم مصرف ترین مسیر از نظر سهمیه Google است، اما فقط
  وقتی کار می کند که hostname Worker از شبکه کاربر قابل دسترس باشد.
- `worker_url` و `worker_auth_key`: endpoint HTTPS و secret مشترک برای رله
  مستقیم Worker. secret سمت Worker با نام `WORKER_AUTH_KEY` باید همین مقدار باشد.
- `direct_worker_concurrency`، `direct_worker_pool_max`،
  `direct_worker_conn_ttl`: تنظیمات pool مستقیم Worker برای کاهش handshake TLS
  و latency.
- `privacy_log_mode`: پیش فرض `host` است تا path و query string در لاگ محلی
  نیاید. برای debug محلی `full` و برای کمترین لاگ `off` استفاده کنید.
- `tcp_relay_mode`: پیش فرض `http_only` است. فقط وقتی Worker endpoint مسیر
  `/tcp` را deploy کردید و `worker_ws_url` را تنظیم کردید، مقدار
  `worker_websocket` بدهید.
- `worker_ws_url`: endpoint به شکل `wss://.../tcp` برای TCP-over-Worker-WebSocket.
  این مسیر سهمیه Apps Script را مصرف نمی کند، اما مستقیم به Cloudflare Worker
  وصل می شود و فقط وقتی کار می کند که hostname خود Worker قابل دسترس باشد.
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

برای carrier اختیاری Worker WebSocket TCP، این secret را در Worker بگذارید و
همان مقدار را در `worker_ws_auth_key` محلی تنظیم کنید، یا از `auth_key` محلی
استفاده کنید:

| نام | نوع | نمونه |
| --- | --- | --- |
| `WORKER_WS_AUTH_KEY` | Secret | رمز بلند تصادفی |

## کتابخانه های پایه

- `cryptography`: ساخت CA و گواهی های MITM.
- `h2`: انتقال HTTP/2 به سمت گوگل.
- `certifi`: CA bundle پایدار برای container و Pythonهای embedded.
- `brotli` و `zstandard`: decode کردن پاسخ های مدرن.
- `websockets`: carrier اختیاری Worker WebSocket برای TCP.
- `aioquic`، `h11` و `anyio`: برای فازهای بعدی QUIC/HTTP، با اتکا به
  پیاده سازی های نگهداری شده به جای parser دستی.
- `ikcp`: گزینه اختیاری برای carrier بومی KCP در نسخه های Python سازگار.

ابزارهای توسعه در `requirements-dev.txt` هستند.

## ایمنی

این نرم افزار فقط برای آموزش، پژوهش و تست ارائه می شود. رعایت قوانین محلی و
شرایط استفاده Google و Cloudflare بر عهده کاربر است. کلید خصوصی `ca/ca.key`
حساس است و نباید به کسی داده شود.

</div>
