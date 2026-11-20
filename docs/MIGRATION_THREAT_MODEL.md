# Classical-to-Post-Quantum Migration Threat Model

**Status:** operational security guidance; not a change to QBC v0.1 consensus.

## Assets to protect

- The capped migration allocation and per-source claim uniqueness.
- The mapping from a classical source address to its approved snapshot entry.
- The integrity and provenance of source exports, manifests, approvals, and reviewer identities.
- The user's proof of control of the classical source and acceptance by the destination PQ address.
- Audit evidence needed to investigate disputes, pause claims, and quarantine a compromised snapshot.

## Trust boundaries

1. **Source data provider → ingestion:** source exports are untrusted input until normalized, provenance-bound, reconciled, and reviewed.
2. **Ingestion → snapshot approval:** a valid hash proves content identity, not that the source chain data is truthful. Independent provenance and reviewer quorum remain necessary.
3. **Classical claimant → verifier:** public keys and proofs are attacker-controlled; verification must use the configured provider and source-network/address binding.
4. **Claim transaction → consensus validation:** the node must re-check source status, uniqueness, conversion policy, claim windows, pool and epoch caps, and any required destination attestation.
5. **Operator → governance controls:** pause, block, approval, rollback, and recovery actions require authenticated operators and an auditable record.
6. **Node database → backup/recovery:** a locally consistent database can still contain malicious or stale data; restored state must be integrity-checked and reconciled before serving claims.

## Threats and required responses

| Threat | Primary control | Residual risk / response |
| --- | --- | --- |
| Forged classical ownership proof | Real provider verifier, public-key-derived source address, network/address-format binding | A broken or misconfigured provider can invalidate this assumption; disable that provider and pause claims. |
| Duplicate or replayed claim | Canonical claim message, source-address uniqueness, branch-aware claim checks, chain ID | Reorgs and concurrent submissions require end-to-end tests against canonical and candidate-chain state. |
| Poisoned or incomplete source snapshot | Provenance anchors, deterministic normalization, manifest/root checks, reconciliation | Hashes cannot establish truth; quarantine and require independent source evidence/review. |
| Malicious reviewer or compromised signing key | Reviewer quorum, trusted signer/node configuration, signed approval artifacts | Quorum collusion remains possible; rotate trust roots and suspend snapshot activation. |
| Migration pool or epoch exhaustion | Consensus-side pool, epoch, and per-address caps | Configuration divergence can cause disagreement; publish a signed network manifest before public launch. |
| Destination substitution | Destination acceptance attestation during configured dual-control window | The policy window must be published and tested; a user can still choose an unsafe destination before activation. |
| Emergency pause bypass | Re-check pause and snapshot/source status on each claim path | Test all import, sync, reorg, and recovery paths; a UI-only pause is insufficient. |
| Rollback evidence tampering | Hash-linked manifests and append-only external audit retention | Local database administrators can alter local evidence; periodically export evidence to independently controlled storage. |
| Database rollback to stale state | Independent backups, height/hash checkpoint, integrity check, reconciliation before reopening claims | SQLite integrity alone does not prove the restored chain is current or consensus-correct. |
| Classical key compromise / quantum break | Time-bounded migration, dual control, conservative claim policy | Do not imply that legacy signatures become quantum-resistant; move assets only after a valid proof and independent checks. |

## Incident playbook

1. Pause migration claims at the operator/governance layer; do not silently rewrite historical consensus data.
2. Record the incident time, chain ID, best-head height/hash, affected source network, snapshot reference and manifest hash.
3. Quarantine the implicated snapshot/source and preserve the original bundle plus approval and rollback artifacts.
4. Compare the source export with independently obtained anchors and review the claim transaction on the canonical chain.
5. Rotate compromised operator/reviewer credentials and revise the trusted signer/node allowlist through the documented governance process.
6. Restore only from a known-good SQLite backup, run SQLite integrity checks, compare the restored head against an independently retained checkpoint, and replay/reconcile from trusted peers.
7. Resume claims only after independent review, reconciliation, and a recorded approval.

## Release gate

Before a public migration launch, exercise duplicate claims under concurrency, reorg/replay behavior, poisoned snapshots, signer/quorum compromise, emergency pause on every claim route, stale backup restoration, and rollback evidence retention. Keep the migration feature paused if any gate fails. This document is a threat model, not an independent audit or a guarantee of safety.


## P1 proof threat-model review (2026-11-20)

**Review result:** the cryptographic proof checks are present on transaction
admission and block import, but migration is **not production-ready**. This
review records current implementation behavior and release blockers; it does
not claim an external cryptographic audit or change QBC v0.1 consensus.

### Reviewed paths and existing controls

- `NodeService._validate_migration_claim` is reached for submitted
  transactions and for each transaction in an imported block. It checks the
  claim window, pause flag, configured provider, locally seeded source and
  snapshot status, source/provider/network binding, branch and canonical
  duplicate claims, conversion amount, pool and epoch limits, public-key to
  source identity, provider proof, source-address ownership, and destination
  attestation when its configured height window is active.
- Classical claim proofs bind `Transaction.migration_claim_payload()`; source
  address format/network checks occur when source entries are seeded or a
  snapshot is imported and are repeated during claim validation.
- Existing regression coverage includes valid demo, secp256k1 and RSA proofs,
  tampered demo proofs, mismatched secp256k1 source addresses, quarantined
  snapshots, duplicate pending claims, claim-window enforcement, destination
  dual control, dispute/escrow behavior, and branch-aware duplicate checks.
- This review adds a regression for malformed RSA proof/key encodings, which
  must produce a normal verification failure instead of an uncaught parse
  exception.

### Findings and release gates

| ID / severity | Finding | Evidence and required action |
| --- | --- | --- |
| MTH-01 / **production blocker** | Claim validation depends on node-local migration source and snapshot database rows plus local policy configuration. A block's proof is rechecked, but the source amount, status, snapshot approval, provider allowlist, conversion ratio, and caps are not all committed as deterministic chain state. | Nodes with different imports or configuration can disagree on block validity or minted amount. Before public migration, define and activate a versioned, consensus-bound source registry/policy and distribute reproducible state. Until then, all validators must receive identical reviewed snapshots and policy out of band; this is an operational assumption, not a protocol guarantee. |
| MTH-02 / **high** | Snapshot signature enforcement defaults off; an empty trusted signer list accepts any signer when signatures are supplied. Seeding a source can create an active local snapshot stub without an approval signature. | Production launch must require signed snapshot envelopes and pin trusted signer identities; verify the actual production configuration and reject launch readiness if either control is absent. A signature authenticates the signer, not source-chain truth. |
| MTH-03 / **high** | The configured snapshot reviewer quorum is reported by readiness tooling, but the import path stores one signer identity and does not enforce or retain a multi-reviewer attestation set. Governance approval/quorum artifacts are likewise review artifacts, not consensus-enforced claim prerequisites. | Do not describe the configured number as an enforced quorum. Multi-reviewer persistence, signer independence and action/artifact binding require a separately specified governance/consensus change. |
| MTH-04 / **high** | The RSA PKCS#1 v1.5 verifier is an in-repository pure-Python implementation. It has no independently demonstrated cryptographic review or certification, and currently has no declared accepted key-strength policy. | Treat RSA migration proofs as experimental; before public claims use an independently maintained, reviewed crypto implementation and explicitly specify key-strength and encoding policy. This review does not invent those parameters. |
| MTH-05 / **medium** | Emergency pause, provider configuration, trusted signers, migration policy and source status are local operator controls. Local disagreement or malicious configuration can split validation outcomes. | Publish a signed network policy manifest, monitor policy/configuration drift and rehearse pause activation across all validators before enabling claims. |

### Scope limitations and test evidence

This review covers proof construction/verification, source-address binding,
snapshot trust, claim replay, admission/import validation, and the migration
configuration boundary. It does not verify the truth of legacy-chain exports,
the independence of reviewers, production key custody, or real-world finality.
The pure-Python RSA and secp256k1 implementations are not certified.

The regression tests are executable evidence for local behaviors only. They
do not prove cross-operator snapshot agreement or end-to-end mainnet migration
safety. The P1 review is complete as an assessment; MTH-01 through MTH-04
remain release gates requiring protocol, governance, or independent-cryptography
work before production migration claims are enabled.
