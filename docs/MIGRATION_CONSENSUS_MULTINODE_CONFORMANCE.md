# Migration Consensus Profile Multi-Node Conformance

## Scope

This integration test exercises profile digest agreement through the authenticated
loopback HTTP peer path, using separate SQLite stores and node identities.

- Two nodes with the same chain ID, genesis allocation, migration profile, and
  profile digest establish peer synchronization and converge on the same block
  hash and state root.
- A node with a different registry commitment advertises a different digest;
  synchronization rejects the peer during handshake before importing a block
  or retaining the peer.

Run it with:

```bash
python -m unittest tests.test_authenticated_peer_loopback_sync -v
```

## Evidence limits

This is an integration regression, not proof of a public network rollout or
operator independence. It verifies profile digest agreement and ordinary block
synchronization; it does not construct and mine a migration claim through the
network. Existing service-level tests cover profile-backed migration claim
validation and local database overlay behavior.

The profile remains opt-in and out-of-band. Public activation still requires
all validators to pin the reviewed profile digest and compatible policy,
verification providers, and software. This test does not establish source-data
truth, external cryptographic review, or production readiness.
