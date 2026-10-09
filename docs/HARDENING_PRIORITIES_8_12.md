# Hardening Priorities 8–12

This tranche hardens inbound API resource use, peer URL input handling, deterministic regression coverage, and recurring CI evidence. It does not change QBC v0.1 consensus rules or transaction serialization.

## Priority 8 — Bounded inbound JSON requests

- Adds `QR_CHAIN_MAX_API_REQUEST_BYTES` (default 20 MiB), checked before reading a declared body and enforced again against actual bytes read.
- Rejects malformed/negative Content-Length, invalid UTF-8/JSON, and non-object JSON with a client error rather than letting the handler crash.
- The default allows headroom over the current 16 MiB transaction-size policy. Operators changing transaction limits should review this API limit too.

## Priority 9 — Public transaction rate limiting

- Adds `QR_CHAIN_MAX_PUBLIC_TX_REQUESTS_PER_MINUTE` (default 60 per client IP) for `POST /transactions`.
- Uses a synchronized fixed-window counter shared by handler threads, returns HTTP 429 with `Retry-After`, and bounds stale address bookkeeping.
- The default remains an in-process fixed-window guardrail. Set `QR_CHAIN_TRANSACTION_RATE_LIMIT_REDIS_URL` to use an atomic Redis Lua counter shared by multiple processes/nodes. Supports `redis://` and TLS `rediss://` URLs, optional username/password, and a database path. When Redis is configured but unavailable, requests fail closed with HTTP 503 rather than silently falling back to process-local limits.
- Every participating node must use the same trusted Redis service and compatible limit configuration for a shared budget. Protect Redis with network ACLs/TLS/credentials; don't expose it publicly. Deployments behind a reverse proxy should only use client-IP forwarding when the proxy is trusted and configured to overwrite forwarded headers; this implementation uses the socket peer address.

## Priority 10 — Peer URL input validation

- Normalizes bare hostnames to HTTP and accepts only HTTP/HTTPS schemes.
- Rejects unsupported schemes, control characters, malformed ports, missing hosts, embedded credentials, query strings, and fragments.
- Adds an optional exact outbound authority allowlist (`QR_CHAIN_OUTBOUND_PEER_URL_ALLOWLIST`, comma-separated `host:port` entries) and `QR_CHAIN_REQUIRE_OUTBOUND_PEER_URL_ALLOWLIST` to reject destinations before opening a socket. The strict flag can be enabled even when the list is empty; in that case all outbound peer requests fail closed.
- Peer HTTP redirects are disabled, and backslashes are rejected because URL parsers can interpret them differently. Private/loopback addresses remain usable when explicitly allowed, for private-network deployments.
- **Residual SSRF risk remains:** a hostname allowlist does not pin DNS resolution to the validated connection address and cannot, by itself, prevent DNS rebinding or compromised allowlisted hosts. Production deployments should use fixed peer endpoints, enable the strict allowlist, bind network connections to approved addresses where possible, and enforce outbound firewall/network policies. This is defense in depth, not a claim of complete SSRF immunity.

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
- `QR_CHAIN_TRANSACTION_RATE_LIMIT_REDIS_URL`: optional Redis URL; when set, the shared limiter fails closed on backend errors.
- `QR_CHAIN_OUTBOUND_PEER_URL_ALLOWLIST`: optional comma-separated outbound authorities such as `node-a.example:8080,node-b.example:8443` (include ports when non-default).
- `QR_CHAIN_REQUIRE_OUTBOUND_PEER_URL_ALLOWLIST`: set to `true` to reject outbound peer requests unless their authority matches the configured allowlist.

## Validation

The pull-request workflow runs:

```bash
python -W error::ResourceWarning -m unittest tests.test_api_security tests.test_network_properties -v
```

The extended workflow is at `.github/workflows/extended-hardening-soak.yml` and can also be run from GitHub Actions using **Run workflow**.

These controls reduce specific resource-exhaustion and malformed-input risks; they are not a security audit or production-readiness certification.
