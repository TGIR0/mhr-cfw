# Resilience, Quota, and Egress Strategy

This document records every transport mode that can realistically help TG
Domain Relay repair disrupted connections, reduce Google Apps Script quota use,
and avoid bad shared egress reputation. Every item is constrained by official
Google and Cloudflare behavior.

## Current Path

```text
client
  -> local HTTP/SOCKS5 proxy
  -> Google-fronted TLS connection
  -> Google Apps Script Web App
  -> Cloudflare Worker
  -> destination website
```

This path works because Apps Script can call HTTP(S) destinations with
`UrlFetchApp.fetch()` and `UrlFetchApp.fetchAll()`. It is also the bottleneck:
each relayed HTTP request consumes Apps Script URL Fetch quota, is limited by
Apps Script execution/runtime limits, and adds one extra network hop before
reaching Cloudflare.

## Hard Platform Boundaries

- Apps Script is an HTTP(S) fetch relay, not a public TCP, UDP, QUIC, or
  WebSocket runtime.
- Apps Script quotas are real: URL Fetch calls are capped per day, each script
  execution has a runtime limit, and URL Fetch POST/response sizes have per-call
  limits.
- Workers can accept HTTP(S), WebSocket upgrades, and HTTP/3 ingress. Workers
  can create outbound TCP sockets with `connect()` from `cloudflare:sockets`.
- Workers do not provide general outbound UDP sockets. UDP and QUIC need an
  encapsulated carrier or a self-hosted/Rust forwarder.
- Worker outbound TCP has restrictions: private/loopback/Cloudflare destinations
  are blocked, port 25 is blocked, and each invocation has a documented limit on
  simultaneous open outgoing connections.
- Worker shared egress IPs are not stable and can have reputation problems with
  sensitive services. Dedicated Cloudflare egress IPs exist, but Cloudflare
  documents them as a Zero Trust Enterprise add-on, not a free unlimited feature.

## Transport Decision Matrix

| Mode | Google quota | Latency | Protocol coverage | Reliability role | Status |
| --- | --- | --- | --- | --- | --- |
| Apps Script HTTP relay | High: one or more URL Fetch calls per request | Highest | HTTP(S) only | Baseline fallback through Google fronting | Implemented |
| Apps Script batch relay | Lower per burst | Medium/high | HTTP(S) only | Reduces request overhead under concurrency | Implemented |
| Apps Script HTTP/2 to Google | Same quota, lower queueing | Lower when ALPN works | HTTP(S) relay control plane | Multiplexes local-to-Google requests | Implemented |
| Parallel Range downloads | Higher request count for large files, higher throughput | Lower for large files | Large HTTP GET only | Fills bandwidth when quota budget permits | Implemented |
| Worker WebSocket TCP | No Apps Script quota | Lower if Worker is reachable | TCP byte streams | Direct Cloudflare path and raw TCP carrier | Optional |
| Worker HTTP direct | No Apps Script quota while healthy | Low | HTTP(S) only | Direct Worker data-plane with Apps Script fallback | Implemented |
| Self-hosted forwarder | No Google quota after reaching Worker | Depends on VPS | HTTP(S), TCP, UDP if implemented there | Stable IP and protocol escape hatch | Partially implemented for HTTP |
| KCP over WebSocket/HTTP | Depends on carrier | Medium | Encapsulated datagrams | Repairs packet loss/reordering over bad links | Scaffold only |
| Native Rust QUIC/KCP forwarder | No Google quota after bootstrap | Lowest if reachable | TCP/UDP/QUIC tunnel | Long-term high-throughput carrier | Future |

## Connection Repair Modes

Use these in this order so the relay repairs disruption without leaking traffic:

1. Health-scored route selection

   Track per-route success rate, handshake time, first-byte latency, throughput,
   reset count, and quota errors. Candidate routes are:

   - `worker_websocket_tcp`
   - `apps_script_h2`
   - `apps_script_h1_pool`
   - `apps_script_batch`
   - `upstream_forwarder`

2. Fast retry with idempotency rules

   Retry `GET`, `HEAD`, and `OPTIONS` more aggressively. Retry `POST`, `PUT`,
   `PATCH`, and `DELETE` only when the request has not been sent or when a
   future explicit idempotency key exists.

3. Circuit breaker

   Temporarily mark a route unhealthy after repeated timeouts, TLS failures,
   malformed responses, or quota errors. Do not remove the route permanently;
   test it with low-frequency probes.

4. Session pinning

   Keep a host pinned to a stable script ID or egress path for cookies,
   anti-abuse sessions, and Cloudflare challenges. Only migrate after failure.

5. KCP-style reliability for datagrams

   The project already has a carrier-neutral session model with sequence
   numbers, ACKs, retransmission, windowing, retry budgets, and ordered
   delivery. It should be wired only after a carrier is chosen:

   - WebSocket carrier: `local UDP/TCP frame -> Worker WebSocket -> TCP socket`
   - self-hosted forwarder carrier: `local UDP -> WebSocket/HTTP -> VPS UDP`
   - future Rust carrier: `local TUN/SOCKS -> QUIC/KCP -> clean exit`

6. MTU and chunk control

   Keep KCP/WebSocket frames below common path MTU. The current KCP scaffold
   defaults to `1200` bytes to fit QUIC-like paths. Large HTTP downloads should
   use adaptive Range chunk sizes based on failure rate and observed throughput.

## Bandwidth Saturation Without Unsafe Leaks

To "take over" available bandwidth safely, use application-layer parallelism,
not direct fallback to the normal network:

- Enable HTTP/2 multiplexing toward Google when ALPN supports it.
- Keep HTTP/1.1 TLS pools warm for fallback.
- Use `fetchAll()` batching for concurrent static/API requests where ordering
  does not matter.
- Use request coalescing for duplicate concurrent GETs.
- Use parallel Range only for large files that support `206 Partial Content`.
- Increase concurrency gradually and measure p95/p99 latency, quota burn, and
  error rate. High concurrency can reduce latency until it hits Apps Script,
  Worker, origin, or local memory limits.
- Do not send unsupported raw TCP/UDP directly unless the user explicitly turns
  on `allow_direct_tcp` or `allow_direct_udp`; that trades leak resistance for
  compatibility.

## Google Quota Reduction Plan

### Phase 0: keep current fallback safe

Apps Script remains the reliable bootstrap path because Google fronting is the
reachable entry point under current conditions.

### Phase 1: direct Worker HTTP relay

When `direct_worker_enabled` is true, the local proxy sends HTTP relay payloads
to `worker_url` first. Successful direct responses mark Worker healthy for a
short TTL and reuse a keep-alive TLS pool. Timeouts, malformed responses, or
non-200 Worker responses trip a circuit breaker for `direct_worker_fail_ttl` and
the request falls back through Apps Script. If Worker is reachable, eligible
traffic goes directly:

```text
client -> local proxy -> Worker HTTPS/WebSocket -> destination
```

This removes Apps Script quota from those flows. If Worker is not reachable,
fall back to Apps Script:

```text
client -> local proxy -> Google Apps Script -> Worker -> destination
```

### Phase 2: low-cost reachability probe

Add an explicit low-cost probe that tests whether `https://<worker>/` and
`wss://<worker>/tcp` are reachable from the client network before real traffic
arrives. The probe must use only a few attempts and cache the result with a TTL.
If direct Worker is sometimes blocked but sometimes reachable, use Apps Script
only as a control-plane/bootstrap route:

- fetch current Worker endpoints, versions, and temporary route hints
- record which front domains/IPs are working
- avoid sending data payloads through Apps Script when a direct data-plane path
  is healthy

Do not claim this is zero-quota. It is "near-zero quota" only when the data-plane
stays direct and the control-plane probe frequency is low.

### Phase 3: self-hosted clean forwarder

For sites sensitive to Cloudflare shared egress reputation, route via a
self-hosted forwarder:

```text
client -> local proxy -> Worker -> VPS forwarder with clean IP -> destination
```

For HTTP this pattern already exists. For TCP/UDP it needs a forwarder protocol,
authentication, replay protection, and per-destination allowlists.

## Layered Inspection Checklist

Every candidate path must be tested at these layers before it becomes default:

1. DNS: resolution succeeds, no local poisoning, no private/loopback target.
2. TCP: connect time, reset rate, half-open behavior.
3. TLS: SNI, ALPN, certificate validation, handshake time.
4. HTTP/1.1: keep-alive reuse, chunked/body limits, redirect behavior.
5. HTTP/2: ALPN negotiation, multiplexing stability, stream reset behavior.
6. WebSocket: upgrade success, binary frame size, ping/pong, close semantics.
7. Worker TCP socket: destination restrictions, port restrictions, open
   connection count, backpressure.
8. App relay contract: JSON size, base64 overhead, compression, error mapping.
9. Egress reputation: destination challenge rate, IP consistency, ASN/category.
10. Quota/cost: Apps Script URL Fetch calls, Worker requests, subrequests,
    simultaneous connections, CPU/memory.

## Clean IP Reality

The target "free, unlimited, no-registration, accepted by every company" exit IP
is not a realistic engineering requirement:

- Public/shared proxy and VPN IPs are routinely flagged.
- Cloudflare Worker shared egress can be blocked or challenged by sensitive
  sites because many users share reputation.
- Cloudflare documents dedicated egress IPs as an Enterprise add-on.
- A VPS IP can be cleaner than shared egress, but it is not free, not unlimited,
  and not guaranteed to be accepted by every service.
- Residential or mobile IPs often have better reputation, but legitimate access
  requires an ISP/account/SIM or a paid provider. Free unauthenticated options
  are usually abused and quickly blocked.

Practical options:

| Option | Cost | Registration | Stability | Reputation | Notes |
| --- | --- | --- | --- | --- | --- |
| Cloudflare shared Worker egress | Free tier possible | Cloudflare account | Low/variable | Mixed | Good fallback, weak for sensitive sites |
| Cloudflare dedicated egress | Enterprise add-on | Enterprise account | High | Better | Official static egress path |
| Low-abuse VPS | Paid | Provider account | High | Depends on ASN/IP history | Best practical independent exit |
| BYOIP | Expensive | RIR/provider | High | Best control | Operationally heavy |
| Residential/mobile exit | Paid/owned line | ISP/SIM/provider | Medium | Often better | Must be legitimate and consent-based |

The project should therefore support pluggable exits instead of promising one
universal clean IP. A future `egress_score` module can rank exits by challenge
rate, ASN, RTT, and stability.

## Implementation Backlog

- Add `worker_direct_probe` config and cached health checks for Worker HTTPS and
  Worker WebSocket.
- Add route scoring with p50/p95/p99 latency, failure type, quota errors, and
  recent throughput.
- Add per-host egress pinning and migration only on failure.
- Add explicit Apps Script quota accounting in logs: estimated URL Fetch calls,
  batch size, Range chunk count, and daily burn estimate.
- Add adaptive Range chunk sizing to balance throughput against quota burn.
- Add Worker WebSocket TCP benchmark: handshake time, sustained throughput,
  reconnect behavior, and challenge rate.
- Add self-hosted forwarder TCP/UDP design before enabling UDP/QUIC.
- Add egress allowlists and private-IP blocking to every raw TCP/UDP carrier.
- Add Rust design notes for a future QUIC/KCP/TUN forwarder after Python
  behavior is fully covered by tests.

## References

- Google Apps Script `UrlFetchApp`: https://developers.google.com/apps-script/reference/url-fetch/url-fetch-app
- Google Apps Script quotas: https://developers.google.com/apps-script/guides/services/quotas
- Cloudflare Workers protocols: https://developers.cloudflare.com/workers/reference/protocols/
- Cloudflare Workers WebSockets: https://developers.cloudflare.com/workers/runtime-apis/websockets/
- Cloudflare Workers TCP sockets: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
- Cloudflare Workers limits: https://developers.cloudflare.com/workers/platform/limits/
- Cloudflare dedicated egress IPs: https://developers.cloudflare.com/cloudflare-one/traffic-policies/egress-policies/dedicated-egress-ips/
