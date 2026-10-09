# Hardening Priorities 4–7

This branch builds the next hardening tranche after the cryptographic/protocol-vector work. It does not change QBC v0.1 consensus rules.

## Priority 4 — Deterministic fuzz/property regression

- Adds a deterministic malformed-frame corpus covering wrong types, missing/invalid digest values, changed payloads, and malformed auth shapes.
- Adds 100 bounded generated transaction serialization round trips.
- Tests use Python's standard library and fixed random seeds, so CI is reproducible without an optional fuzzing dependency.

This is a regression corpus, not coverage-guided fuzzing. A future step should add a sustained Atheris/Hypothesis job with saved crash cases and resource limits.

## Priority 5 — Migration threat model

- Documents assets, trust boundaries, attacker goals, controls, residual risks, and incident response.
- Explicitly notes that content hashes do not prove source-data truth, SQLite integrity does not prove chain freshness, and pause/recovery must be checked across all claim paths.

The threat model is operational guidance, not an independent security audit.

## Priority 6 — Database backup/recovery

- Adds an integration regression that creates a genesis chain, performs SQLite's online backup API, reopens the backup, and compares best head, UTXO state, summary height, and SQLite integrity.
- Adds a runbook covering WAL-safe backup, restore to a separate directory, independent checkpoints, reconciliation, and special handling of stateful signer state.

The test demonstrates an online-backup/reopen path. It does not simulate disk corruption, power loss, or recovery of stateful keys after a stale backup.

## Priority 7 — Peer networking resource hardening

- Caps peer HTTP response bodies at 8 MiB by default, checks Content-Length when present, and still bounds actual reads because the header may be absent or false.
- Rejects invalid UTF-8/JSON, non-object JSON responses, invalid length headers, and non-positive timeouts/limits.
- Adds regression tests for these cases.

The response limit is local transport policy, not a consensus parameter. Deployments with larger legitimate peer responses should use an explicit larger limit only after reviewing memory and denial-of-service exposure. This does not by itself solve SSRF, TLS identity pinning, request-rate limiting, or internet-scale abuse.

## Validation

CI runs the new suites:

    python -W error::ResourceWarning -m unittest tests.test_protocol_fuzz tests.test_network_hardening tests.test_storage_recovery -v

Do not treat a passing unit suite as a production security certification. Multi-node soak tests, independent review, fuzzing campaigns, backup drills, and operational monitoring remain release gates.
