# SQLite Database Recovery Runbook

This runbook covers local recovery of the QBC chain and wallet-state SQLite databases. It is operational guidance, not a consensus change.

## Before an incident

- Keep encrypted, access-controlled backups on storage separate from the node host.
- Retain a separately recorded checkpoint containing the expected chain ID, best-head height, and best-head hash. A database's own metadata is not an independent checkpoint.
- Back up the chain database and wallet-state database separately. Stateful signer state is security-critical; never restore an older wallet-state backup over a newer state without a provider-specific recovery procedure.
- Test restores periodically in an isolated directory, never over the live database.

## Create a consistent SQLite backup

Prefer SQLite's online backup API or the SQLite CLI backup command. Do not copy only the main .db file while the node is running: WAL-mode databases may have committed data in -wal.

Example Python backup:

    import sqlite3

    with sqlite3.connect("data/chain.db") as source:
        with sqlite3.connect("backups/chain.db") as destination:
            source.backup(destination)

Repeat for the wallet-state database, preserving its own backup and retention metadata. Protect backup files as sensitive wallet/operational data.

## Restore and verify

1. Stop the node and preserve the original database files for forensic analysis.
2. Restore backups to a new directory; never overwrite the only copy.
3. Run PRAGMA integrity_check against each restored database. Require the exact result ok.
4. Start a node pointed at the restored copy in an isolated environment.
5. Compare the restored chain ID, best-head height and hash against an independently retained checkpoint and a trusted peer or operator record.
6. Run the repository's full test suite and chain/migration integrity reports.
7. Reconcile chain state from trusted peers if the checkpoint differs. SQLite integrity proves structural consistency only; it does not prove that the database is current, consensus-correct, or free of maliciously altered rows.
8. Treat wallet-state recovery separately. If stateful one-time signing material may have rolled back, quarantine the signer and do not sign until the backend's state-recovery guarantees have been reviewed.

## Fail-closed conditions

Do not resume public claims, mining, peer admission, or stateful signing if any of these conditions holds:

- SQLite integrity check fails.
- Restored best-head hash/height cannot be reconciled with an independent checkpoint.
- Chain identity or protocol manifest differs from the intended network.
- Wallet signer state is missing, stale, or ambiguous.
- Migration source/snapshot status or audit evidence cannot be reconciled.

Record the incident, backup provenance, hashes, checks performed, operator approvals, and any recovery/replay action. Do not silently edit historical consensus rows to make the database appear healthy.
