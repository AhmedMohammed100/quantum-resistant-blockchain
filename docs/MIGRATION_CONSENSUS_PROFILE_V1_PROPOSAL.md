# Versioned migration consensus profile v1 (proposal)

This document records the first implementation slice for deterministic migration
validation. The profile is **opt-in** and is not yet wired into block validation.
Existing QBC v0.1 transaction serialization, transaction IDs, block hashes,
state roots, and live consensus behavior remain unchanged.

## Canonical profile

The Python schema in `qr_blockchain/migration_consensus.py` defines the
proposed `qbc-migration-consensus-profile` version 1 object. It binds:

- chain ID and activation height;
- claim window, provider allowlist, conversion policy and ratio, migration
  pool and per-address caps, epoch limits, dispute window, and escrow period;
- each migration snapshot's source network, reference, manifest hash, and
  entries root.

The validator rejects unknown or missing fields, non-integer numeric policy
values, duplicate providers or snapshots, malformed hashes, and inconsistent
claim windows. Arrays that represent sets are sorted before hashing.
The profile hash is SHA-256 over UTF-8 canonical JSON with sorted object keys
and compact separators. Local snapshot commitments must exactly match the
normalized profile list.

## Current limits and activation questions

This profile creates a reproducible commitment but does **not** by itself make
it a consensus rule. The current node still validates claims using local
configuration and SQLite rows. A later integration must make the configured
profile commitment identical across validators and fail closed on any mismatch
before the activation height, then evaluate post-activation claims solely from
the committed profile/state.

Before enabling that integration, the normative protocol must decide how
consensus state changes after activation handle:

- snapshot/source quarantine or revocation;
- emergency pause and resumption;
- dispute opening and resolution;
- changes to trusted reviewers or provider availability;
- profile replacement, activation delay, and rollback/recovery;
- whether the full registry artifact is distributed or claims carry
  inclusion proofs.

No mutable operator setting or local database status is silently assigned
consensus semantics here. Do not advertise public migration claims as
deterministic or production-ready until these state-transition rules and
block-validation integration are specified and tested across independent
nodes.
