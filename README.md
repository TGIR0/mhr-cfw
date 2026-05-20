# TG Domain Relay

Google-fronted HTTP relay with Cloudflare Worker exit.

| [English](README.md) | [Persian](README_FA.md) |
| :---: | :---: |

This repository is an independent relay project, not an official fork of any
upstream project. The goal is to provide a maintainable Python implementation
first, then leave the codebase ready for a future Rust rewrite.

## Current Architecture

```text
Browser / app
  -> local HTTP or SOCKS5 proxy
  -> TLS connection to a Google frontend IP with Google SNI
  -> Google Apps Script web app
  -> Cloudflare Worker
  -> target website
```

Optional stable-exit mode:

```text
Cloudflare Worker -> self-hosted upstream forwarder on a VPS -> target website
```

The local proxy performs HTTPS interception with a local CA certificate, turns
browser HTTP requests into relay JSON, sends them through Google Apps Script,
and receives a raw HTTP response reconstructed from the Worker response.

## What Works Today

- Local HTTP proxy and SOCKS5 `CONNECT` proxy.
- HTTPS MITM for browser-originated HTTP traffic.
- Google Apps Script relay using `UrlFetchApp.fetch()` and `fetchAll()`.
- Cloudflare Worker HTTP exit with optional VPS forwarder for stable IP.
- Optional direct Worker HTTP relay. When the Worker hostname is reachable, the
  local proxy sends HTTP relay payloads straight to Worker and keeps Apps Script
  as fallback, reducing Google URL Fetch quota use.
- Optional Worker WebSocket TCP carrier for raw TCP streams, disabled by default
  and separate from the Apps Script path.
- HTTP/2 multiplexing from the local relay to Google when the `h2` package and
  negotiated ALPN support are available.
- Parallel range download optimization for large HTTP downloads.
- Fail-closed protocol policy for unsupported raw TCP, UDP, and QUIC paths so
  clients do not silently fall back to the normal network.
- KCP-style reliability primitives are present for the future UDP/WebSocket/Rust
  carrier, but not yet wired into the live proxy path.

## Platform Boundaries

This project should stay aligned with vendor documentation instead of inventing
unsupported transport claims.

- Google Apps Script `UrlFetchApp` is the documented path for outbound HTTP(S)
  fetches; it is not a general TCP, UDP, QUIC, or WebSocket runtime.
- Cloudflare Workers support HTTP/HTTPS request handling, WebSockets, HTTP/3
  ingress, and outbound TCP sockets, but Workers are not a generic UDP egress
  runtime.
- UDP and QUIC support must therefore be implemented as a separate tunnel design
  with explicit encapsulation or a self-hosted forwarder. It should not be
  described as direct Apps Script UDP/QUIC support.
- `allow_direct_tcp` and `allow_direct_udp` default to `false`. Turning them on
  trades leak resistance for compatibility and should only be used deliberately.

References:

- Google Apps Script `UrlFetchApp`: https://developers.google.com/apps-script/reference/url-fetch/url-fetch-app
- Google Apps Script quotas: https://developers.google.com/apps-script/guides/services/quotas
- Cloudflare Workers protocols: https://developers.cloudflare.com/workers/reference/protocols/
- Cloudflare Workers WebSockets: https://developers.cloudflare.com/workers/runtime-apis/websockets/
- Cloudflare Workers TCP sockets: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If PyPI is not reachable:

```bash
pip install -r requirements.txt -i https://mirror-pypi.runflare.com/simple/ --trusted-host mirror-pypi.runflare.com
```

## Deploy

1. Create a Cloudflare Worker and paste `deploy/cloudflare-worker/worker.js`.
2. Set `WORKER_URL` in the Worker file to your own `*.workers.dev` hostname.
3. If you enable direct Worker HTTP relay, set the Worker secret
   `WORKER_AUTH_KEY` to the same value as local `worker_auth_key`.
4. Create a Google Apps Script web app and paste `deploy/gas/Code.gs`.
5. Set `AUTH_KEY` and `WORKER_URL` in `Code.gs`. If the Worker secret
   `WORKER_AUTH_KEY` is set, put the same value in `Code.gs` too.
6. Deploy the Apps Script as a Web app with access set to `Anyone`.
7. Copy the Apps Script Deployment ID.

## Configure

Create a private config from the safe example:

```bash
copy config.example.json config.json
```

On Linux/macOS:

```bash
cp config.example.json config.json
```

Set at least:

- `script_id`: your Apps Script Deployment ID.
- `auth_key`: the same secret as `AUTH_KEY` in `Code.gs`.
- `google_ip`: a reachable Google frontend IP. Use `python main.py --scan` to test candidates.

Do not commit `config.json`; it is ignored because it contains secrets.

Validate the config without starting listeners:

```bash
python main.py --check-config
```

Important transport and speed knobs:

- `direct_worker_enabled`: when `true`, HTTP relay payloads try
  `worker_url` first and use Apps Script only after a circuit-breaker failure.
  This is the lowest-quota path, but only works when the Worker hostname is
  reachable from the client network.
- `worker_url` and `worker_auth_key`: HTTPS Worker endpoint and shared secret
  for the direct HTTP relay. Set Worker secret `WORKER_AUTH_KEY` to match.
- `direct_worker_concurrency`, `direct_worker_pool_max`,
  `direct_worker_conn_ttl`: direct Worker keep-alive pool tuning for lower TLS
  handshake overhead and lower latency.
- `privacy_log_mode`: `host` by default, so logs avoid full paths/query strings.
  Use `full` only for local debugging, or `off` for minimal request logging.
- `tcp_relay_mode`: `http_only` by default. Set `worker_websocket` only after
  deploying the Worker `/tcp` endpoint and setting `worker_ws_url`.
- `worker_ws_url`: `wss://.../tcp` endpoint for TCP-over-Worker-WebSocket.
  This path skips Apps Script quota, but it is direct to Cloudflare Worker and
  only works where the Worker hostname itself is reachable.
- `udp_mode`: `disabled` today; future values will use encapsulated carriers.
- `quic_mode`: `block` by default to avoid UDP/QUIC leaks.
- `kcp_enabled`, `kcp_mtu`, `kcp_window`, `kcp_resend_after`: reliability
  settings for the planned KCP-style carrier.
- `relay_concurrency`, `pool_max`, `pool_min_idle`, `batch_max`,
  `batch_window_micro`, `batch_window_macro`: Apps Script throughput tuning.
- `parallel_range_enabled` and the `chunked_download_*` keys: large-download
  acceleration.

## Run

Windows:

```cmd
run.bat
```

Linux/macOS:

```bash
chmod +x run.sh
./run.sh
```

Manual:

```bash
python main.py
```

The default listeners are:

- HTTP proxy: `127.0.0.1:8085`
- SOCKS5 proxy: `127.0.0.1:1080`

## Optional Stable Exit IP

Cloudflare Worker egress IPs can rotate. For sites that bind challenge tokens
or sessions to the source IP, deploy `deploy/upstream_forwarder/upstream_forwarder.js`
on a VPS with a stable IP and configure these Worker variables/secrets:

| Name | Type | Example |
| --- | --- | --- |
| `UPSTREAM_FORWARDER_URL` | Secret | `https://forwarder.example.com/fwd` |
| `UPSTREAM_AUTH_KEY` | Secret | same as the VPS `AUTH_KEY` |
| `UPSTREAM_FAIL_MODE` | Variable | `closed` or `open` |
| `UPSTREAM_TIMEOUT_MS` | Variable | `25000` |

For the optional Worker WebSocket TCP carrier, set this Worker secret and match
it in local `worker_ws_auth_key` (or reuse local `auth_key`):

| Name | Type | Example |
| --- | --- | --- |
| `WORKER_WS_AUTH_KEY` | Secret | long random secret |

## Dependency Baseline

Runtime dependencies are intentionally small:

- `cryptography`: local CA and MITM certificates.
- `h2`: HTTP/2 client transport to Google.
- `certifi`: consistent CA bundle in containers and embedded Python builds.
- `brotli` and `zstandard`: response decoding for modern websites.
- `websockets`: optional Worker WebSocket TCP carrier.
- `aioquic`, `h11`, `anyio`: planned transport work, kept explicit so future
  QUIC and HTTP experiments use maintained protocol libraries.
- `ikcp`: optional future native KCP carrier candidate where Python support is
  available.

Development tools are in `requirements-dev.txt`.

## Safety

This software is provided for educational, testing, and research purposes.
You are responsible for complying with local law and with Google and Cloudflare
terms, quotas, and acceptable-use policies. The local CA private key in `ca/ca.key`
is sensitive and must never be shared.

## License

[MIT](LICENSE)
