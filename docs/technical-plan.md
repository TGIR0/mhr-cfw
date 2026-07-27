# TG Domain Relay Technical Plan

This document is the decision record for rebuilding the project around current
vendor-documented capabilities.

## Baseline Library Set

Runtime:

- `cryptography>=48,<49` for local CA generation, per-host MITM certificates,
  and certificate fingerprint checks.
- `h2>=4.3,<5` for HTTP/2 multiplexing over the Google-fronted TLS connection.
- `certifi>=2026.4.22` for stable CA roots in containers and nonstandard Python
  builds.
- `brotli>=1.2,<2` and `zstandard>=0.25,<1` for response decoding.
- `websockets>=16,<17` for future documented carrier experiments. It is not
  active in the current google-relay-only policy.
- `aioquic>=1.3,<2`, `h11>=0.16,<1`, and `anyio>=4.13,<5` for future transport
  modules.
- `ikcp>=0.0.3,<0.1` as an optional native KCP carrier candidate where the
  Python version supports it.

Development:

- `pytest>=9,<10`, `ruff>=0.15,<0.16`, and `mypy>=2,<3`.

## Supported Transports

- Phase 1 keeps the selected path for foreign HTTP(S):
  local HTTP/SOCKS5 `CONNECT` -> Apps Script `UrlFetchApp` -> Worker `fetch()`.
- Phase 1 also adds smart routing before relay quota is spent: `.ir` and Iran
  GeoIP destinations go direct, allowed Google hosts use the fronted direct path,
  and foreign HTTP(S) uses Apps Script -> Worker.
- Raw TCP, SOCKS5 UDP associate, WebSocket upgrades that cannot ride the HTTP
  relay, and QUIC-over-UDP are refused fail-closed so clients can fall back to
  TCP/HTTPS.
- Worker WebSocket TCP and direct Worker HTTP remain research/legacy paths while
  the selected product path is google-relay-only.
- UDP and QUIC require a separate encapsulated tunnel design. The safe default is
  local UDP -> reliable datagrams over WebSocket/HTTP to a self-hosted forwarder,
  or a Rust/QUIC forwarder later. Do not claim direct Apps Script UDP/QUIC.
- KCP-style reliability is represented by `src/kcp_transport.py`: sequence
  numbers, ACKs, retransmit timers, retry budget, and ordered delivery. The next
  implementation step is a carrier that moves these frames over WebSocket or a
  Rust forwarder.

## Structure To Build Toward

- `relay/`: protocol-neutral request and response dataclasses, size caps, host
  policy, and error types.
- `transports/apps_script.py`: Google Apps Script HTTP relay using the existing
  JSON wire contract.
- `transports/worker.py`: Cloudflare Worker HTTP adapter behind Apps Script.
- `worker_ws_transport.py`: legacy/future TCP-over-Worker-WebSocket adapter,
  disabled by current policy.
- `local_proxy/`: HTTP parser, SOCKS5 parser, MITM certificate integration, and
  routing.
- `protocol_policy.py`: central policy for protocol allow/block decisions and
  leak resistance defaults.
- `kcp_transport.py`: carrier-neutral reliability session for future UDP/QUIC
  encapsulation.
- `deploy/`: Worker, Apps Script, and upstream forwarder assets kept versioned
  with the Python wire contract.

This repo is not there yet; current edits intentionally preserve runtime
behavior while removing clone branding and adding safe scaffolding.

## Vendor Documentation Boundaries

- Google Apps Script: use `UrlFetchApp.fetch()` and `UrlFetchApp.fetchAll()` for
  outbound HTTP(S), and design around Apps Script quotas.
- Cloudflare Workers: use documented HTTP/HTTPS handling, WebSockets, HTTP/3
  ingress, and TCP sockets. Treat UDP as unavailable unless Cloudflare documents
  a general UDP socket API for Workers.
- Cloudflare Worker stable IP: use the existing upstream forwarder pattern or a
  paid/static-egress offering. Do not assume direct Worker `fetch()` has stable
  egress IPs.

Primary references:

- https://developers.google.com/apps-script/reference/url-fetch/url-fetch-app
- https://developers.google.com/apps-script/guides/services/quotas
- https://developers.cloudflare.com/workers/reference/protocols/
- https://developers.cloudflare.com/workers/runtime-apis/websockets/
- https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/

## Immediate Implementation Backlog

- Use `docs/resilience-quota-egress.md` as the route-selection and quota
  decision record before enabling any new default transport.
- Move the remaining flat `src` imports into a package without changing behavior.
- Add tests for config validation, protocol policy, KCP ACK/retransmit behavior,
  host matching, Set-Cookie splitting, response decoding, and SOCKS5
  unsupported-command responses.
- Replace handwritten Worker response base64 conversion with documented,
  chunk-safe helpers and add Worker-side request size caps.
- Add a `--check-config` command that validates placeholders, port collisions,
  missing scripts, and unsafe LAN exposure.
- Add measurable latency/quota tests for smart routing decisions against the
  current Apps Script HTTP path.
