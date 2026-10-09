# Hardening Priorities 8–12

This tranche hardens inbound API resource use, peer URL input handling, deterministic regression coverage, and recurring CI evidence. It does not change QBC v0.1 consensus rules or transaction serialization.

## Priority 8 — Bounded inbound JSON requests

- Adds `QR_CHAIN_MAX_API_REQUEST_BYTES` (default 20 MiB), checked before reading a declared body and enforced again against actual bytes read.
- Rejects malformed/negative Content-Length, invalid UTF-8/JSON, and non-object JSON with a client error rather than letting the handler crash.
- The default allows headroom over the current 16 MiB transaction-size policy. Operators changing transaction limits should review this API limit too.

## Priority 9 — Public transaction rate limiting

- Adds `QR_CHAIN_MAX_PUBLIC_TX_REQUESTS_PER_MINUTE` (default 60 per client IP) for `POST /transactions`.
- Uses a synchronized fixed-window counter shared by handler threads, returns HTTP 429 with `Retry-After`, and bounds stale address bookkeeping.
- This is an in-process guardrail, not a distributed rate limiter. Multiple worker processes or nodes each enforce their own limit. Deployments behind a reverse proxy should only use client-IP forwarding when the proxy is trusted and configured to overwrite forwarded headers; this implementation uses the socket peer address.

## Priority 10 — Peer URL input validation

- Normalizes bare hostnames to HTTP and accepts only HTTP/HTTPS schemes.
- Rejects unsupported schemes, control characters, malformed ports, missing hosts, embedded credentials, query strings, and fragments.
- Loopback/private hosts remain valid for local and private-network deployments. Internet-facing operators should enable the existing peer allowlist and restrict egress at the network layer. URL validation alone is not a complete SSRF defense and does not prevent a remote peer from redirecting a request.

## Priority 11 — Deterministic property regression

- Adds 300 seeded valid-URL normalization/idempotence cases and 100 seeded invalid-scheme mutations.
- Uses only the Python standard library, with fixed seeds for reproducible CI. This is bounded property-style regression, not coverage-guided fuzzing or a replacement for Atheris/Hypothesis campaigns.

## Priority 12 — Recurring extended regression and chaos checks

- Adds a manually triggerable and daily scheduled workflow.
- Runs compilation, deterministic protocol/network/API tests, the bounded multi-node chaos harness, and the full test suite.
- The chaos harness is a bounded simulation; it is not a multi-day production soak and does not prove liveness under real internet conditions.

## Configuration

- `QR_CHAIN_MAX_API_REQUEST_BYTES`: default `20971520` (20 MiB).
- `QR_CHAIN_MAX_PUBLIC_TX_REQUESTS_PER_MINUTE`: default `60` per client IP.

## Validation

The pull-request workflow runs:

```bash
python -W error::ResourceWarning -m unittest tests.test_api_security tests.test_network_properties -v
```

The extended workflow is at `.github/workflows/extended-hardening-soak.yml` and can also be run from GitHub Actions using **Run workflow**.

These controls reduce specific resource-exhaustion and malformed-input risks; they are not a security audit or production-readiness certification.
