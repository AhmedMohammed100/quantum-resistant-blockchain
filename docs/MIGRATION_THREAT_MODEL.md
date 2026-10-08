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
