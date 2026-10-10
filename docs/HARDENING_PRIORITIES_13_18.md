# Hardening Priorities 13–18

This tranche focuses on HTTP transport behavior, deterministic abuse regressions, static analysis, and repeatable CI. It does not change QBC v0.1 consensus rules, transaction IDs, block hashes, or signature formats.

## Priority 13 — Bound inbound HTTP client occupancy

- Adds `QR_CHAIN_HTTP_CLIENT_TIMEOUT_SECONDS` (default 10 seconds) as a socket timeout for accepted HTTP connections.
- Rejects unsupported `Transfer-Encoding` because the current API reads request bodies by `Content-Length` and does not implement chunked request decoding.
- Rejects conflicting duplicate `Content-Length` values and non-JSON `Content-Type` values when a content type is supplied. Missing content type remains accepted for compatibility.
- This timeout bounds socket reads, but it is not a substitute for reverse-proxy header limits, connection caps, TLS termination, or a production load test.

## Priority 14 — Safer API response handling

- Adds `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer` to JSON responses.
- Identifies responses as UTF-8 JSON.
- These headers are defense in depth; they do not replace authentication, authorization, TLS, or output-specific privacy review.

## Priority 15 — Peer transport regression coverage

- Adds regression coverage for request framing and the invariant that outbound peer requests use the redirect-disabled transport path.
- The existing outbound authority allowlist still compares the configured authority before connecting. **DNS rebinding remains a residual risk** because hostname resolution is not pinned to an approved IP address by this tranche. Use fixed peer endpoints and network egress controls in production.

## Priority 16 — Concurrent abuse regression

- Adds a deterministic concurrent test that sends many simultaneous requests from one client address and verifies the in-process transaction limiter admits no more than the configured budget.
- This checks thread-level synchronization only; multi-process deployments need the shared Redis limiter configured on every participating node.

## Priority 17 — Static security analysis

- Adds a GitHub CodeQL workflow for Python on pull requests, pushes to `main`, and a weekly schedule.
- The workflow is an automated static-analysis signal, not an independent security audit and not a guarantee that vulnerabilities will be found.

## Priority 18 — Expand hardening gates

- Adds the new HTTP and concurrency regression suite to the existing hardening workflow.
- Runs the regression suite with `ResourceWarning` promoted to errors to catch leaked sockets/files in supported test paths.

## Configuration

- `QR_CHAIN_HTTP_CLIENT_TIMEOUT_SECONDS`: socket timeout for inbound HTTP connections; default `10`.
- `QR_CHAIN_MAX_API_REQUEST_BYTES`: existing JSON body limit; default `20971520` bytes.
- `QR_CHAIN_MAX_PUBLIC_TX_REQUESTS_PER_MINUTE`: existing per-client transaction submission limit; default `60`.

## Validation and limits

Run the new suite locally:

```bash
python -W error::ResourceWarning -m unittest tests.test_http_transport_hardening -v
```

A passing suite is not production-readiness certification. Public deployments still need TLS termination, restricted egress, monitoring, key-custody review, external cryptographic review, and real multi-node load/partition/restart soak tests.
