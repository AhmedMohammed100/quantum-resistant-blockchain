# Independent Migration Export Verification

The repository's migration ingestion flow normalizes operator supplied source
exports, builds snapshot and ingestion manifests, and records source provenance.
The standalone verifier provides a separate, standard-library-only check of a
normalized artifact. It does not import the node package, call `NodeService`, or
write to node storage.

## Reproduce the golden artifact check

From the repository root, run:

```sh
python scripts/verify_migration_artifact.py --input tests/fixtures/migration-export-v1.json
python -m unittest tests.test_migration_artifact_verifier tests.test_source_ingestion -v
```

The fixture has fixed snapshot and ingestion manifest hashes. The tests also
alter the source record projection, a snapshot entry, and the source anchor and
confirm that verification fails.

## What is checked

- Snapshot entry schema, uniqueness, counts, amount totals, Merkle root, and
  manifest hash.
- The consensus-relevant projection of each normalized source record against
  the corresponding snapshot entry.
- The normalized-record root and source-export hash.
- Provenance fields and provenance hash, including the source anchor.
- Ingestion manifest fields and ingestion manifest hash.

The node-side ingestion validator performs the same record-to-entry projection
check before an artifact can proceed through the approval/import workflow.
The independent script repeats artifact verification outside the node runtime
so an operator or reviewer can check a saved file without trusting that
workflow's process or database.

## Trust limits

These hashes establish content consistency and detect accidental or
unauthenticated edits when the expected digest is retained independently. They
do **not** establish that the source exporter queried the correct chain, that
the anchored block is canonical or finalized, that source balances are true,
or that the artifact was approved by an authorized reviewer. The golden fixture
uses the repository's demo migration provider and is not a production ownership
proof. Production source extraction still needs network-specific adapters,
independent anchor checks, reviewer controls, and externally retained signed
evidence. This verifier does not change QBC v0.1 serialization, identifiers,
hashes, or consensus behavior.

