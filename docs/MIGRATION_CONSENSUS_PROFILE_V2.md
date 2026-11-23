# Migration consensus profile v2

**Status:** opt-in implementation; not active for existing chains until every
validator configures and pins the same profile artifact. QBC v0.1 block hashes,
transaction IDs, transaction serialization, peer frame bytes, and state roots
are unchanged.

## Build and pin the artifact

Create/import and review the migration snapshots on the chain database first.
Then build the canonical artifact:

```bash
python -m qr_blockchain migration-consensus-profile --activation-height 1 --output migration-profile.json
```

The output contains the complete profile and its SHA-256 `profile_hash`. Configure
every validator with the same artifact and digest:

- `QR_CHAIN_MIGRATION_CONSENSUS_PROFILE_PATH`
- `QR_CHAIN_MIGRATION_CONSENSUS_PROFILE_HASH`

The loader verifies the profile schema, chain ID, version, digest, full snapshot
manifests and entry roots, and exact policy equality against local configuration.
Missing pins, malformed artifacts, and policy drift fail closed. Public-mode
migration claim validation rejects claims when no profile is configured.

The profile is an out-of-band network parameter. Its digest is included in the
protocol manifest and signed in peer handshakes; peers with a different profile
digest cannot establish a session. Validators must agree on the profile before
public claims are enabled. The digest is not embedded in existing v0.1 blocks,
so deploying different profile hashes under one chain ID remains an operator
coordination failure.

## Consensus behavior after activation

Profile v2 pins the full normalized migration registry, including provider,
amount, source address and format, entry review status, snapshot status,
snapshot references and hashes. It also pins every migration policy value used
by claim validation, including provider allowlists, conversion parameters,
claim and dual-control windows, pool and epoch caps, and escrow/dispute windows.

At or after activation, block validation resolves a claim only from this
immutable profile. It does not read node-local source or snapshot rows, local
quarantine flags, local disputes, or the local emergency-pause flag to decide
whether an imported block is valid. The per-address duplicate index and pool
and epoch accounting are derived from the candidate chain. Migration output
spendability is deterministic: the output stays locked until the later of the
pinned escrow and dispute windows; local dispute records do not change block
validity.

Local pause, quarantine, and dispute controls still affect local claim
admission and operator reports. They cannot unilaterally invalidate a block
that follows the pinned profile. A network-wide halt or a change to registry,
policy, or post-finality recovery rules requires coordinated validator action
and a separately reviewed consensus upgrade. Do not interpret this profile
as providing on-chain dispute adjudication or an emergency governance mechanism.

Public profile v2 must activate at height 1. Later activation would leave
historical migration validity dependent on the pre-profile local database; it
requires a separately specified chain upgrade and replay rule.

## Reproducibility and tests

Snapshot ordering and provider-set ordering are canonicalized before hashing.
The complete entries are revalidated against their manifest hash and root.
On startup, existing canonical migration claims are replay-checked against the
profile, including source binding, proof, amount, duplicate use, pool cap, and
epoch cap. A profile that does not reproduce the current canonical claims is
rejected.

Run the focused checks with:

```bash
python -W error::ResourceWarning -m unittest tests.test_migration_consensus_profile tests.test_migration_consensus_enforcement tests.node_service_reports_tests -v
```

This implementation makes claim and spend validation deterministic when all
validators pin the same artifact and run compatible verification code. It does
not establish the truth of legacy source exports, independent reviewer
integrity, cryptographic certification, or external audit completion.
