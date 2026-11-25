# Migration Consensus Profile Multi-Node Conformance

## Scope

Authenticated loopback integration tests exercise profile agreement and
migration-claim validation across nodes with separate SQLite stores and node
identities.

- Nodes with matching chain IDs, genesis allocations, profile data, and pinned
  profile digests submit, mine, and synchronize a deterministic test migration
  claim. They converge on the block hash, state root, and destination balance.
- Nodes with different registry commitments reject the peer during handshake
  before importing the migration block or retaining the peer.
- Service-level candidate-block tests reject a source already claimed on the
  candidate branch and reject outputs that do not match the profile's
  conversion amount.

Run the focused suites with:

```bash
python -m unittest tests.test_authenticated_peer_loopback_sync tests.test_migration_consensus_enforcement -v
```

## Evidence limits

The classical claim verifier is a deterministic test double. These regressions
exercise profile-backed consensus handling, duplicate-claim protection, amount
checks, and block transport; they do not validate a production classical
signature implementation or establish external source ownership.

The profile remains opt-in and out-of-band. Public activation requires all
validators to pin the reviewed profile digest and compatible policy,
verification providers, and software. These tests do not establish source-data
truth, external cryptographic review, operator independence, or production
readiness.
