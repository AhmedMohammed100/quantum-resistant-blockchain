# Independent-operator multi-node soak kit

## Purpose and status

This kit prepares the first P2 reliability exercise: a long-running QBC test
network operated by separate people on separate machines. It supplements the
existing three-process CI soak, which remains single-operator evidence.

The receipt signer proves that the node identity signed the submitted report.
The values `operator_id` and `machine_id` are signed declarations; the code
cannot prove a real-world person's identity, organizational independence, or
physical/cloud-machine separation. A valid bundle therefore reports
`external_independence_confirmed: false` and still requires external review.

Use a private test chain with test funds and no production keys. This workflow
does not activate or alter consensus rules.

## Per-operator requirements

Recruit at least three operators who control separate organizations or
independent operational teams. Each operator should:

1. Provision a distinct machine and QBC node identity. Do not share node
   identity keys, databases, or operator credentials.
2. Use the same test chain ID, genesis hash, protocol/policy manifest digest,
   software commit, and real signature-provider policy.
3. Maintain authenticated peer connectivity to every other participant.
4. Run continuously for at least 24 hours, recording transaction submission,
   block acceptance, peer synchronization, final head, restarts, and any
   partition, latency, dropped-response, recovery, or rejection events.
5. Preserve raw, timestamped node logs, the sanitized effective configuration,
   manifest/genesis digests, network event timeline, and artifact hashes.
   Redact private keys, API tokens, private IPs where unnecessary, and user
   data. Use an opaque machine identifier rather than a serial number.
6. Produce a signed receipt with the locally configured QBC node identity.

The organizers should independently confirm that each person/team and host is
separate. Do not treat distinct strings or signing keys alone as proof of that
separation.

## Receipt format and commands

Each operator prepares a JSON object with these fields:

```json
{
  "run_id": "qbc-private-soak-2026-11",
  "operator_id": "reviewed-operator-alias",
  "machine_id": "opaque-host-alias",
  "started_at": 1790000000,
  "duration_seconds": 86400,
  "manifest_digest": "64-character manifest SHA-256",
  "software_commit": "40-character source commit",
  "final_head_hash": "64-character converged block hash",
  "peer_node_ids": ["other-node-a", "other-node-b"],
  "passed": true,
  "failure_summary": "",
  "metrics": {
    "transactions_mined": 0,
    "validator_syncs_completed": 0,
    "partition_recoveries": 0,
    "restarts": 0
  }
}
```

The local node signs the receipt:

```powershell
python -m qr_blockchain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db independent-soak-receipt --result-json (Get-Content operator-result.json -Raw) --output signed-receipt.json
```

After collecting at least three receipts, build a bundle:

```json
{
  "bundle_version": 1,
  "receipts": [
    { "...": "signed receipt from operator one" },
    { "...": "signed receipt from operator two" },
    { "...": "signed receipt from operator three" }
  ]
}
```

Validate it with a QBC checkout configured for the same chain ID:

```powershell
python -m qr_blockchain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db independent-soak-verify --input independent-soak-bundle.json --output validation.json
```

The validator checks signatures and receipt hashes, at least three distinct node
signers/operator IDs/machine IDs, a shared run and policy identity, a common
24-hour observation window, matching final heads, successful results, and a
complete participant peer mesh. It rejects duplicate identities, tampering and
mixed-run bundles.

## Acceptance and remaining human review

A code-level validation result with `valid: true` means the signed declarations
are internally consistent. It does **not** mean independent operation has been
verified. Before accepting this P2 deliverable, reviewers must check the
operator roster, organizational separation, machine inventory/hosting evidence,
raw logs, network events, configuration, and retained artifact hashes. Any
inconsistent chain head, unreported outage, failed recovery, signature-provider
mismatch, or unexplained consensus disagreement blocks acceptance.

The current artifact is a collection/verification aid. No independent operators
or machines have been contacted or tested by CI. The P2 criterion remains open
until a real external soak is conducted and its evidence is reviewed.
