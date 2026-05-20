## TODO

- Package the Python code under a project namespace while preserving CLI behavior.
- Expand config validation with allowlists for Worker WebSocket TCP targets.
- Implement the probe/fallback plan from `docs/resilience-quota-egress.md`:
  direct Worker health checks, route scoring, and Apps Script quota accounting.
- Add protocol-policy tests for fail-closed raw TCP, SOCKS5 UDP associate, and
  QUIC blocking.
- Wire the KCP-style session to a documented carrier: Worker WebSocket,
  self-hosted forwarder, or future Rust forwarder.
- Harden the Worker and Apps Script wire contract with explicit size limits and
  version fields.
- Add measured latency and quota benchmarks for Worker WebSocket TCP versus the
  Apps Script HTTP path.
- Design UDP/QUIC as an encapsulated tunnel or self-hosted forwarder path; do not
  present it as direct Apps Script support.
- Prepare a Rust rewrite plan after Python behavior is covered by tests.
