# Quantum-Resistant Blockchain Node

This project builds a quantum-resistant blockchain node designed to help users and operators move value from classical cryptographic systems into post-quantum-secure addresses. It focuses on practical migration: verifying legacy ownership, importing auditable source-chain snapshots, protecting stateful PQ signing keys, and running authenticated nodes that can validate, sync, and reorganize chain state safely.

Phase 1 adds:

- persistent SQLite-backed chain state
- structured node configuration
- a service layer for validation and mining
- a JSON HTTP node API
- automated tests around persistence and transaction behavior

Phase 2 adds:

- chain-bound transaction signing to prevent cross-chain replay
- a quantum-signature abstraction layer prepared for stronger PQ schemes
- deterministic block validation and block import
- peer registration and block sync between nodes
- API endpoints for block export, peer discovery, and synchronization

Phase 3 begins the stronger PQ signature transition:

- `xmss_merkle_lamport_v1` becomes the default wallet signing scheme
- Merkle-root addresses replace direct Lamport public-key addresses for new wallets
- each transaction witness carries a leaf index and authentication path
- one-time leaf usage is enforced so a signing tree cannot be reused indefinitely

Phase 4 now adds the production migration boundary:

- a formal signature-provider interface separates wallet/node logic from concrete crypto implementations
- provider registry entries can be `available` or `planned`, making future integrations explicit
- transaction validation resolves a verifier by scheme while local config selects the provider implementation
- the `xmss_nist_v1` slot is now a true external adapter skeleton with a precise dependency error path
- the repo now includes a concrete scaffold module at `qr_chain_xmss_backend/` for the first real XMSS backend boundary
- reserved provider slots now exist for real LMS/HSS and SPHINCS+ backends

Phase 5 now adds authenticated peer networking:

- each node has a durable signing identity backed by the same PQ provider layer
- peer admission happens through a signed handshake instead of blind URL trust
- peer sync uses authenticated request envelopes with timestamps and nonces
- replayed peer requests are rejected

Phase 6 now adds fork-choice and reorganization handling:

- blocks can be stored off-canonical as side branches
- the node selects the best chain by cumulative work with deterministic hash tie-breaking
- canonical UTXO state is rebuilt when a better branch wins
- competing-branch imports can now trigger rollback and replay of state

Phase 7 now hardens peer transport:

- peer handshakes now issue expiring peer sessions instead of relying on one-off admitted identity only
- authenticated peer RPCs are bound to a session id, request path, method, and payload digest
- peer requests must target the local advertised URL exactly
- expired sessions are rejected and replayed nonces still fail closed

Phase 8 now improves external PQ backend readiness:

- the provider registry can report live backend readiness instead of failing only at signing time
- external adapters expose whether their backend module is installed and whether stateful signing hooks are present
- the node API can now report provider readiness through `GET /crypto/providers`

Phase 9 now starts the real XMSS backend integration path:

- `qr_chain_xmss_backend` is now a real adapter package instead of a dead placeholder
- the default mode is an in-repo software XMSS-compatible backend used to exercise the external-provider seam end to end
- the package can also switch to an installed external XMSS library module by environment variable
- provider diagnostics now report which XMSS implementation mode is active
- external library modules must now satisfy a stricter manifest-and-callable validation contract before they are accepted

Phase 10 now adds secure wallet custody:

- persisted wallet and node-identity key state is now protected at rest instead of stored as raw serialized JSON
- the Windows build uses DPAPI by default, binding protected blobs to the local user context
- protected wallet blobs are also bound to wallet label, address, and provider id so state cannot be trivially swapped between rows
- legacy plaintext wallet rows are migrated forward into protected storage on load
- provider diagnostics now also report the active wallet-custody backend

Phase 11 now adds crash-safe signer coordination:

- signing now uses a durable reservation journal instead of only in-memory coordination
- reservation completion writes the final post-sign key state back to storage for stateful providers like OQS/XMSS
- stale ambiguous reservations are promoted into a recovery-required state instead of risking signer-state reuse after a crash
- multi-process workers sharing the same wallet-state database now coordinate through reservation ownership and expiry rules

Phase 12 now hardens mempool policy and peer transport:

- mempool admission now enforces duplicate rejection, pending-capacity limits, minimum fee policy, timestamp sanity, and transaction shape limits
- the pending transaction store now tracks transaction fee and serialized size for policy enforcement and observability
- peer RPCs now use explicit framed messages with protocol versioning and message types instead of loose ad hoc JSON bodies
- framed peer requests and responses carry a canonical frame digest so malformed or cross-type payloads fail closed
- peer block export is now batch-limited per request

Phase 13 now adds adversarial and invariant testing:

- adversarial tests now cover malformed peer frames, tampered digests, and invalid framed block requests
- randomized property-style tests now exercise transaction and block roundtrips plus framed peer message roundtrips
- supply conservation is checked across mined chains as a regression guard
- signer reservation status counts are now exposed in node diagnostics for operational visibility

Phase 14 now adds signer recovery tooling:

- the wallet-state store now promotes stale interrupted reservations during status reads, not only during the next signing attempt
- nodes can now list wallet-key reservation state and identify which addresses require operator recovery
- interrupted ambiguous reservations can now be explicitly acknowledged and cleared through the service layer and HTTP API

Phase 15 now adds operational health and metrics:

- `GET /health` now returns live node health instead of a fixed ok stub
- degraded health is reported when active PQ providers are unavailable or a wallet key is blocked in recovery-required state
- `GET /status` and `GET /metrics` now expose chain, peer-session, custody, reservation, and provider counters for operators

Phase 16 now expands the PQ backend surface:

- `lms_nist_v1` is now a real external adapter boundary instead of a placeholder
- `sphincsplus_v1` is now a real external adapter boundary instead of a placeholder
- both providers now have OQS-backed module targets so the node can grow beyond XMSS without redesigning the crypto registry

Phase 17 now starts classical-to-PQ migration:

- the chain now supports seeded migration snapshot sources keyed by classical addresses
- a new `migration_claim` transaction type can move a seeded classical balance onto a PQ address
- migration proofs are now verified through a separate classical-claim verifier registry
- a demo verifier exercises the flow today, while real `ecdsa_secp256k1` and `rsa_pkcs1v15_sha256` migration verifier boundaries are now defined for future production backends

Phase 18 now adds real classical migration verifiers:

- `ecdsa_secp256k1_migration_v1` now uses a real pure-Python secp256k1 verifier for ownership proofs
- `rsa_pkcs1v15_sha256_migration_v1` now uses a real pure-Python RSA PKCS#1 v1.5 SHA-256 verifier for ownership proofs

Phase 19 now adds migration policy controls:

- migration claims can now be gated by a start height and optional end height
- dual-control periods can now require both the classical ownership proof and a PQ destination acceptance proof
- migration providers can now be allow-listed by node policy

Phase 20 now adds wallet migration helpers:

- the service can now build deterministic migration-claim drafts for external classical signing
- wallets can now assemble final migration claims safely, including optional PQ destination attestations when policy requires them

Phase 21 now hardens provider selection policy:

- the node now exposes preferred and allowed PQ provider policy
- provider diagnostics now recommend a default provider and a stateless-preferred provider when available

Phase 22 now adds migration load and chaos coverage:

- bulk migration claims are exercised across mined blocks
- migration claims are exercised through authenticated node sync
- canonical migration claims are tested across reorgs

Phase 23 now adds auditable migration snapshot imports:

- migration sources can now be imported as deterministic snapshot bundles instead of only being seeded one address at a time
- imported bundles are validated for duplicate addresses, positive amounts, and allowed classical-provider policy before they reach chain state
- each snapshot now records a manifest hash, entries root, entry count, and total amount for operator auditability
- repeated imports of the same snapshot are idempotent, while conflicting re-import attempts fail closed

Phase 24 now adds chain-aware legacy address compatibility:

- migration sources now distinguish between the canonical verifier claim address and the user-facing legacy source address
- built-in profiles now exist for Bitcoin-style, Ethereum-style, RSA, and demo migration networks
- source addresses are validated by format before they are accepted into migration state
- migration claims now carry the seeded source-address metadata so replayed or mismatched claims fail closed

Phase 25 now adds trusted snapshot issuer policy:

- nodes can now require snapshot artifacts to be signed before import
- operators can allow-list trusted snapshot signer addresses and trusted signer node ids
- snapshot signatures are now treated as durable artifact signatures rather than short-lived peer-auth envelopes

Phase 26 now adds live snapshot export tooling:

- nodes can now export a deterministic snapshot bundle directly from stored migration sources
- exports can include only unclaimed sources or the full seeded set
- live exports can be signed immediately for operator handoff between systems

Phase 27 now adds an operator CLI:

- `qr-chain` can now list migration network profiles and export, sign, validate, or import snapshot artifacts
- the same workflow is also available through `python -m qr_blockchain`

Phase 28 now adds real external-address proof linkage:

- secp256k1 migration claims can now prove ownership of Bitcoin-style and Ethereum-style source addresses derived from the claimant public key
- the node no longer treats those external source addresses as snapshot metadata only; they are now verified during the claim path
- canonical claim addresses remain chain-internal, but migration claims can now cryptographically bind them to supported external address formats

Phase 29 now broadens external source-address proof coverage:

- secp256k1 migration claims now support nested Bitcoin SegWit compatibility addresses (`P2SH-P2WPKH`) in addition to Bitcoin P2PKH, native SegWit, and Ethereum EOAs
- the classical verifier registry can now expose whether a backend verifies the seeded external source address directly or only the canonical claim address
- migration admission now requires the claimant public key to prove ownership of the seeded external source address whenever the backend supports it

Phase 30 now adds migration review lifecycle controls:

- migration snapshots and individual migration sources now carry review status, review timestamp, and operator reason fields
- sources and snapshots can now be marked `active`, `quarantined`, or `revoked`
- snapshot review actions can cascade to all contained sources so operators can freeze suspicious imports quickly

Phase 31 now hardens migration admission against reviewed data:

- migration claims are now blocked when either the seeded source or its originating snapshot is not `active`
- claimability reporting now respects migration review state instead of only claim-window and claimed/unclaimed state
- operator review status is now part of exported snapshot metadata so downstream systems can preserve quarantine decisions

Phase 32 now adds migration audit and operator reporting:

- nodes can now generate structured migration audit reports grouped by source network, provider, source status, and snapshot status
- audit reports now flag anomalies such as missing snapshot records, active sources on blocked snapshots, and claimed blocked sources
- new API and CLI controls let operators review, quarantine, revoke, and report on migration inventory without direct database inspection

Phase 33 now adds snapshot reconciliation before import:

- operators can now compare an incoming snapshot artifact against local migration state before committing it
- reconciliation reports show entries that would be added, unchanged entries, changed entries, local entries missing from the incoming artifact, and review-status conflicts
- this gives snapshot operators a dry-run style review step before importing or rejecting source-chain data

Phase 34 now adds migration claim preflight:

- wallets and operators can now ask the node for a claim readiness report before a user signs anything
- preflight reports include claim-window status, source and snapshot review status, provider policy, claim status, and the exact classical/PQ message bytes to sign
- this makes migration wallet UX safer because the node can explain why a claim is not ready before a user produces a legacy signature

Phase 35 now adds signed migration claim receipts:

- once a migration claim is mined, the node can produce a signed receipt for the classical source address, destination PQ address, amount, and transaction id
- receipts are signed by the node identity and can be stored by wallets, operators, or support systems as portable migration evidence

Phase 36 now rounds out migration operator controls:

- snapshot exports can intentionally include inactive sources while preserving quarantine/revocation metadata
- API and CLI surfaces now cover reconciliation, claim preflight, signed claim receipts, review status updates, and audit reports
- the migration pipeline now has review points before import, before signing, before claim admission, and after claim settlement

Phase 37 now adds source-chain export ingestion:

- operators can normalize source-chain or indexer export records into deterministic migration snapshot bundles
- entries can derive canonical migration claim addresses from classical public keys when the export provides them
- exported source addresses are validated against the configured legacy network profile before entering the snapshot pipeline
- normalized source exports can be signed, reconciled, imported, and audited through the same snapshot workflow

Phase 38 now adds source-export schema enforcement:

- source export records now validate required network, provider, snapshot, address, and amount fields before snapshot generation
- exports can include optional source provenance fields such as source height, transaction id, and output index
- records with public keys are checked against the claimed external source address before they can become migration entries

Phase 39 now adds deterministic ingestion manifests:

- normalized source exports now include an ingestion manifest with record count, total amount, records root, source export hash, snapshot manifest hash, and snapshot entries root
- equivalent source exports produce stable ingestion roots even when record order changes
- ingestion warnings are preserved for operator review when a record relies on a precomputed canonical address instead of a public key

Phase 40 now adds batch source-export normalization:

- operators can normalize multiple source-chain exports in one run and receive a batch manifest with item hashes, total records, total amount, and a batch hash
- each batch item remains a normal snapshot artifact, so it can still be reconciled, signed, imported, and audited independently

Phase 41 now adds source-ingestion runbooks:

- normalized source exports can now produce operator runbooks with required evidence and review steps
- runbooks reference the snapshot manifest hash and ingestion manifest hash so review records can be tied back to exact artifacts

Phase 42 now adds ingestion manifest validation:

- normalized source exports can be checked for matching record count, total amount, snapshot manifest hash, and snapshot entries root
- operators can validate ingestion evidence separately from snapshot validation before approving an import

Phase 43 now adds operator approval artifacts:

- operators can create approval records tied to exact ingestion and snapshot manifest hashes
- approvals include operator identity, decision, reason, and a deterministic approval hash
- rejected or malformed approvals cannot be used to execute an approved import

Phase 44 now adds source-ingestion import plans:

- nodes can now dry-run a normalized source export against local migration state and approval evidence
- import plans block changed existing sources, invalid manifests, invalid approvals, and review conflicts before import
- plans report how many entries would import, skip as unchanged, or block as unsafe changes

Phase 45 now adds approved source-ingestion imports:

- approved imports run through the same snapshot import pipeline while preserving the import plan and approval evidence
- approved import results include a post-import migration audit report

Phase 46 now adds rollback evidence:

- approved imports return a rollback evidence block with snapshot ref, manifest hash, entries root, entry count, and the quarantine action needed to freeze the imported snapshot
- this gives operators a concrete recovery artifact if a source export later needs to be halted

Phase 47 now hardens source-ingestion policy gates:

- import execution now requires a valid approval artifact
- changed local sources and review conflicts are blocked at plan time instead of relying on the lower-level snapshot conflict path
- CLI and API controls now cover manifest validation, approval, import planning, and approved import execution

Phase 48 now introduces native currency metadata:

- the node now exposes a native currency name, symbol, decimal precision, and base unit
- balances can be returned in both base units and formatted coin notation
- currency parameters can be configured through environment variables

Phase 49 now adds a monetary policy layer:

- mining subsidy is now derived from a height-aware currency policy instead of a permanently fixed reward
- the policy supports halving intervals and reports next-height subsidy and cumulative issued subsidy

Phase 50 now hardens genesis and max-money checks:

- genesis allocations can be capped by `QR_CHAIN_GENESIS_SUPPLY_CAP`
- genesis allocation totals cannot exceed configured max money

Phase 51 now adds canonical supply accounting:

- the node reports genesis supply, issued subsidy, migration-minted supply, transaction fees, miner-paid fees, and unspent UTXO supply
- supply accounting follows the canonical chain head, so reorgs are reflected in currency metrics

Phase 52 now exposes currency operations:

- HTTP endpoints now expose monetary policy, supply accounting, and formatted address balances
- operator CLI commands now expose the same currency and supply reports

Phase 53 now adds native-currency test coverage:

- tests cover halving behavior, supply snapshots, genesis caps, formatted balances, config overrides, and CLI reporting

## Quantum-resistant direction

The chain now supports a provider registry with both active and reserved backends:

- `hash_lamport_v1`: the original raw Lamport path kept for compatibility
- `xmss_merkle_lamport_v1`: an XMSS-style Merkle-tree wrapper around one-time Lamport leaves
- `xmss_nist_v1`: external adapter skeleton for a future audited XMSS backend module
- `lms_nist_v1`: external adapter boundary for LMS/HSS integration
- `sphincsplus_v1`: external adapter boundary for SPHINCS+ integration

The XMSS-style backend is still the default software provider for new wallets. It remains an in-repo reference implementation rather than a standards-audited production library, but the app is now structured so a real external provider can be registered without changing transaction, node, or API contracts.

The `xmss_nist_v1` adapter loads `qr_chain_xmss_backend` by default. That package now supports two modes:

- `QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION=reference` to use the in-repo software backend
- `QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION=module` plus `QR_CHAIN_XMSS_LIBRARY_MODULE=<module>` to use an installed external XMSS backend

Whichever backend is active should expose:

- `generate_keypair()`
- `derive_address(keypair)`
- `sign(keypair, message)`
- `serialize_keypair(keypair)`
- `deserialize_keypair(payload)`
- `reserve_signing_material(keypair)`
- `sign_with_reservation(keypair, message, reservation)`
- `verify(message, signature, public_key)`
- `address_from_public_key(public_key)`

External library-backed modules should also expose `XMSS_BACKEND_MANIFEST` (or `backend_manifest()`) with:

- `backend_name`
- `api_version=1`
- `scheme_id="xmss_nist_v1"`
- `algorithm_family="xmss"`
- `implementation_type`
- `supports_signing=True`
- `supports_stateful_signing=True`
- `supports_reserved_signing=True`

The default `qr_chain_xmss_backend` package now exposes a working software backend so the `xmss_nist_v1` adapter path can be exercised end to end. It is still a development bridge, not a standards-audited NIST XMSS implementation.

Inside that package, `reference_backend.py` provides the in-repo bridge backend and `module_backend.py` provides the stricter library-backed loading path for future audited integrations.

The first concrete library-backed target is `qr_chain_xmss_backend.oqs_backend`, which adapts the Open Quantum Safe Python bindings (`oqs` from `liboqs-python`) into this contract. In `module` mode, `module_backend.py` now defaults to that OQS target unless you override `QR_CHAIN_XMSS_LIBRARY_MODULE`.

For the OQS-backed target, you can also set:

- `QR_CHAIN_XMSS_OQS_MECHANISM=XMSS-SHA2_10_256`

That target requires both the Python wrapper and the native `liboqs` shared library to be available. Provider diagnostics now distinguish between:

- missing `oqs` Python package
- installed `oqs` package but missing native `liboqs` runtime
- installed runtime but disabled or unsupported XMSS mechanism

The wallet layer now also has a persistent SQLite-backed key-state store for stateful PQ signing. That gives XMSS-style providers a durable place to save leaf/index progress so a restart does not accidentally reuse one-time signing material.

That store now performs atomic signer-state reservations inside SQLite write transactions, so multiple local wallet instances sharing the same state database can coordinate XMSS-style leaf allocation without reusing the same one-time leaf.

On this Windows machine, persisted wallet state is now protected with DPAPI before it is written to SQLite. The database keeps a neutral `__protected__` marker plus an encrypted blob, rather than storing raw serialized key material directly.

The wallet-state store now also keeps a reservation ledger for in-flight signatures. That lets the node distinguish between:

- completed reservations that safely persisted the next signer state
- expired reservations where state had already advanced and the leaf/use was safely burned
- ambiguous interrupted reservations that require operator recovery before the key can sign again

The node can now also surface and clear that recovery-required state through a supported operator path, instead of requiring direct SQLite inspection.

## Migration operations

The migration layer now supports review-aware operator workflows in addition to snapshot import and claim submission.

HTTP endpoints:

- `POST /migration/snapshots/export`
- `POST /migration/source-exports/normalize`
- `POST /migration/source-exports/batch-normalize`
- `POST /migration/source-exports/runbook`
- `POST /migration/source-exports/manifest-status`
- `POST /migration/source-exports/approve`
- `POST /migration/source-exports/import-plan`
- `POST /migration/source-exports/import-approved`
- `POST /migration/snapshots/sign`
- `POST /migration/snapshots/import`
- `POST /migration/snapshots/reconcile`
- `POST /migration/snapshots/status`
- `POST /migration/sources/status`
- `POST /migration/claims/preflight`
- `GET /migration/claims/receipt`
- `GET /migration/report`

CLI commands:

- `python -m qr_blockchain migration-snapshot-export --source-network <network> [--snapshot-ref <ref>] [--include-claimed] [--include-inactive] [--sign]`
- `python -m qr_blockchain migration-source-export-normalize --input source-export.json [--sign]`
- `python -m qr_blockchain migration-source-export-batch-normalize --input source-a.json --input source-b.json`
- `python -m qr_blockchain migration-source-ingestion-runbook --input normalized-source-export.json`
- `python -m qr_blockchain migration-source-ingestion-manifest-status --input normalized-source-export.json`
- `python -m qr_blockchain migration-source-ingestion-approve --input normalized-source-export.json --operator <name> --reason <reason>`
- `python -m qr_blockchain migration-source-ingestion-import-plan --input normalized-source-export.json [--approval approval.json]`
- `python -m qr_blockchain migration-source-ingestion-import-approved --input normalized-source-export.json --approval approval.json`
- `python -m qr_blockchain migration-snapshot-sign --input snapshot.json`
- `python -m qr_blockchain migration-snapshot-import --input snapshot.json`
- `python -m qr_blockchain migration-snapshot-reconcile --input snapshot.json`
- `python -m qr_blockchain migration-snapshot-status --snapshot-ref <ref> --status active|quarantined|revoked [--reason "..."] [--no-cascade]`
- `python -m qr_blockchain migration-source-status --classical-address <address> --status active|quarantined|revoked [--reason "..."]`
- `python -m qr_blockchain migration-claim-preflight --destination-address <pq-address> --classical-address <classical-address> --classical-provider-id <provider> --source-network <network> [--snapshot-ref <ref>]`
- `python -m qr_blockchain migration-claim-receipt --classical-address <classical-address>`
- `python -m qr_blockchain migration-report [--source-network <network>]`

The peer transport is still HTTP-based, but it is now stricter than before: peer endpoints speak a versioned `qr-peer-v1` framed protocol rather than relying on unstructured JSON payloads alone.

The classical migration path is also now taking shape: instead of requiring users to manually abandon an old network, the node can seed balances from a legacy snapshot and let users prove classical ownership before minting the corresponding balance onto a PQ address on this chain.

That migration layer now includes:

- a real `ecdsa_secp256k1` verifier path for legacy ECC ownership proofs
- a real `rsa_pkcs1v15_sha256` verifier path for legacy RSA ownership proofs
- optional dual-control windows where the destination PQ wallet must also explicitly accept the migration claim

It now also has a more operational import path: nodes can ingest full deterministic migration snapshot bundles, persist their manifest metadata separately, and expose both imported snapshots and resulting claimable sources through the API.

That path is now stronger in four practical ways:

- source-chain addresses can be stored in their real external format instead of only the canonical verifier address
- snapshot imports can be gated by trusted signer policy
- nodes can export a fresh snapshot artifact from current migration state
- operators can run the snapshot workflow from a CLI without hand-building JSON requests

For secp256k1-based migration sources, it is now also stronger at claim time: supported Bitcoin and Ethereum source addresses are derived from the submitted public key and checked as part of migration validation, rather than being trusted solely because they appeared in the imported snapshot.

This means the repo is now production-shaped rather than fully production-ready.

## Architecture

- `qr_blockchain/config.py`: environment-driven node configuration, chain identity, peers, and default signature provider selection
- `qr_blockchain/crypto.py`: formal signature-provider interface, provider registry, and current software PQ backends
- `qr_blockchain/custody.py`: wallet custody backends, including Windows DPAPI protection for stored signer state
- `qr_blockchain/legacy_networks.py`: source-network profiles and legacy address-format validation for migration imports
- `qr_blockchain/migration.py`: classical-claim verifier registry and migration-proof helpers
- `qr_blockchain/snapshot.py`: deterministic migration snapshot bundle validation and manifest hashing
- `qr_blockchain/models.py`: transaction and block models
- `qr_blockchain/storage.py`: SQLite persistence for blocks, pending transactions, and UTXOs
- `qr_blockchain/network.py`: simple peer URL normalization and JSON fetch helpers
- `qr_blockchain/auth.py`: node identity management and signed peer envelopes
- `qr_blockchain/wallet_store.py`: SQLite-backed protected wallet-state persistence and reservation coordination
- `qr_blockchain/service.py`: validation, mining, block import, wallet flow, mempool rules, and sync
- `qr_blockchain/api.py`: HTTP API for health, summary, balances, UTXOs, blocks, peers, genesis, mining, and sync
- `qr_blockchain/cli.py`: operator CLI for migration network discovery and snapshot artifact workflows
- `tests/`: unit tests for config, persistence, and transaction behavior

## Run the node

```powershell
python main.py
```

Optional environment variables:

```powershell
$env:QR_CHAIN_DB_PATH = "data/chain.db"
$env:QR_CHAIN_DIFFICULTY = "3"
$env:QR_CHAIN_MINING_REWARD = "30"
$env:QR_CHAIN_HOST = "127.0.0.1"
$env:QR_CHAIN_PORT = "8080"
$env:QR_CHAIN_ID = "qr-chain-devnet"
$env:QR_CHAIN_NODE_ID = "node-a"
$env:QR_CHAIN_PEERS = "http://127.0.0.1:8081"
$env:QR_CHAIN_ADVERTISED_URL = "http://127.0.0.1:8080"
$env:QR_CHAIN_MAX_TRANSACTIONS_PER_BLOCK = "500"
$env:QR_CHAIN_MAX_PENDING_TRANSACTIONS = "2000"
$env:QR_CHAIN_MIN_TRANSACTION_FEE = "1"
$env:QR_CHAIN_MAX_TRANSACTION_SIZE_BYTES = "16777216"
$env:QR_CHAIN_MAX_TRANSACTION_INPUTS = "64"
$env:QR_CHAIN_MAX_TRANSACTION_OUTPUTS = "64"
$env:QR_CHAIN_DEFAULT_SIGNATURE_PROVIDER = "xmss_merkle_lamport_v1"
$env:QR_CHAIN_XMSS_BACKEND_MODULE = "qr_chain_xmss_backend"
$env:QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION = "reference"
$env:QR_CHAIN_XMSS_LIBRARY_MODULE = ""
$env:QR_CHAIN_XMSS_OQS_MECHANISM = "XMSS-SHA2_10_256"
$env:QR_CHAIN_WALLET_STATE_DB_PATH = "data/wallet_state.db"
$env:QR_CHAIN_WALLET_CUSTODY_MODE = "auto"
$env:QR_CHAIN_WALLET_CUSTODY_SCOPE = "current_user"
$env:QR_CHAIN_WALLET_RESERVATION_TTL_SECONDS = "60"
$env:QR_CHAIN_AUTH_TIME_SKEW_SECONDS = "300"
$env:QR_CHAIN_PEER_SESSION_TTL_SECONDS = "900"
$env:QR_CHAIN_PEER_PROTOCOL_VERSION = "qr-peer-v1"
$env:QR_CHAIN_MAX_PEER_BLOCKS_PER_REQUEST = "128"
$env:QR_CHAIN_MIGRATION_CLAIM_START_HEIGHT = "1"
$env:QR_CHAIN_MIGRATION_CLAIM_END_HEIGHT = "0"
$env:QR_CHAIN_MIGRATION_DUAL_CONTROL_START_HEIGHT = "0"
$env:QR_CHAIN_MIGRATION_DUAL_CONTROL_END_HEIGHT = "0"
$env:QR_CHAIN_MIGRATION_REQUIRE_SNAPSHOT_SIGNATURES = "0"
$env:QR_CHAIN_MIGRATION_ALLOWED_CLASSICAL_PROVIDERS = "ecdsa_secp256k1_migration_v1,rsa_pkcs1v15_sha256_migration_v1,classical_claim_demo_v1"
$env:QR_CHAIN_MIGRATION_TRUSTED_SNAPSHOT_SIGNERS = ""
$env:QR_CHAIN_MIGRATION_TRUSTED_SNAPSHOT_NODES = ""
$env:QR_CHAIN_PREFERRED_SIGNATURE_PROVIDERS = "sphincsplus_v1,lms_nist_v1,xmss_nist_v1,xmss_merkle_lamport_v1"
$env:QR_CHAIN_ALLOWED_SIGNATURE_PROVIDERS = ""
python main.py
```

Wallet custody modes:

- `auto`: use Windows DPAPI on Windows, otherwise fall back to plaintext development mode
- `windows_dpapi`: require Windows DPAPI protection explicitly
- `plaintext`: explicit insecure development mode only

Wallet custody scopes for `windows_dpapi`:

- `current_user`: only the current Windows user can decrypt stored wallet state
- `local_machine`: any process with machine-level DPAPI access can decrypt it

Wallet reservation coordination:

- `QR_CHAIN_WALLET_RESERVATION_TTL_SECONDS` controls how long a signing reservation may stay pending before the key is treated as interrupted
- if a provider had already advanced its state at reservation time, the expired reservation is treated as safely burned
- if a provider had not yet advanced its state, the key is placed into a recovery-required state to avoid ambiguous reuse after a crash

Mempool policy:

- `QR_CHAIN_MAX_PENDING_TRANSACTIONS` bounds the local mempool size
- `QR_CHAIN_MIN_TRANSACTION_FEE` sets the minimum relay fee for non-coinbase transactions
- `QR_CHAIN_MAX_TRANSACTION_SIZE_BYTES` caps serialized transaction size
- `QR_CHAIN_MAX_TRANSACTION_INPUTS` and `QR_CHAIN_MAX_TRANSACTION_OUTPUTS` bound transaction fan-in and fan-out

Native currency policy:

- `QR_CHAIN_CURRENCY_NAME` sets the native currency display name
- `QR_CHAIN_CURRENCY_SYMBOL` sets the ticker-style symbol
- `QR_CHAIN_CURRENCY_DECIMALS` sets display precision for formatted balances
- `QR_CHAIN_CURRENCY_BASE_UNIT` names the smallest accounting unit
- `QR_CHAIN_MINING_REWARD` sets the initial block subsidy in base units
- `QR_CHAIN_SUBSIDY_HALVING_INTERVAL` controls the height interval for subsidy halvings
- `QR_CHAIN_GENESIS_SUPPLY_CAP` optionally caps genesis allocations; `0` means no separate genesis cap
- `QR_CHAIN_MAX_MONEY` caps theoretical native supply

Peer framing:

- `QR_CHAIN_PEER_PROTOCOL_VERSION` selects the framed peer RPC version expected by this node
- `QR_CHAIN_MAX_PEER_BLOCKS_PER_REQUEST` limits how many blocks a peer can request or receive in one framed block response

Migration policy:

- `QR_CHAIN_MIGRATION_CLAIM_START_HEIGHT` sets the first block height where migration claims are accepted
- `QR_CHAIN_MIGRATION_CLAIM_END_HEIGHT` optionally closes the claim window after a given height; `0` means no configured end
- `QR_CHAIN_MIGRATION_DUAL_CONTROL_START_HEIGHT` and `QR_CHAIN_MIGRATION_DUAL_CONTROL_END_HEIGHT` define an optional range where the destination PQ wallet must also sign an acceptance proof
- `QR_CHAIN_MIGRATION_REQUIRE_SNAPSHOT_SIGNATURES` forces imported snapshot artifacts to include a signed envelope
- `QR_CHAIN_MIGRATION_ALLOWED_CLASSICAL_PROVIDERS` allow-lists which classical proof systems this node will accept for migration
- `QR_CHAIN_MIGRATION_TRUSTED_SNAPSHOT_SIGNERS` optionally allow-lists signer addresses for snapshot imports
- `QR_CHAIN_MIGRATION_TRUSTED_SNAPSHOT_NODES` optionally allow-lists signer node ids for snapshot imports

Provider policy:

- `QR_CHAIN_PREFERRED_SIGNATURE_PROVIDERS` orders the node’s preferred PQ providers
- `QR_CHAIN_ALLOWED_SIGNATURE_PROVIDERS` optionally restricts which PQ providers the node should recommend or use operationally

## API endpoints

- `GET /health`
- `GET /status`
- `GET /metrics`
- `GET /chain/summary`
- `GET /currency`
- `GET /currency/supply`
- `GET /crypto/providers`
- `GET /migration/policy`
- `GET /migration/networks`
- `GET /migration/report`
- `GET /migration/claims/receipt`
- `GET /migration/snapshots`
- `GET /migration/sources`
- `GET /wallets/status`
- `GET /blocks?start_height=0`
- `GET /blocks/{height}`
- `GET /peers`
- `GET /addresses/{address}/balance`
- `GET /addresses/{address}/utxos`
- `POST /blocks`
- `POST /peers`
- `POST /genesis`
- `POST /transactions`
- `POST /mine`
- `POST /sync`
- `POST /migration/sources`
- `POST /migration/snapshots`
- `POST /migration/snapshots/export`
- `POST /migration/snapshots/sign`
- `POST /migration/snapshots/reconcile`
- `POST /migration/snapshots/status`
- `POST /migration/sources/status`
- `POST /migration/claims/preflight`
- `POST /wallets/recovery`
- `POST /peer/handshake`
- `POST /peer/summary`
- `POST /peer/blocks`

Example genesis request:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/genesis -ContentType "application/json" -Body '{"allocations":{"alice-address":120}}'
```

Example peer registration:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/peers -ContentType "application/json" -Body '{"url":"http://127.0.0.1:8081"}'
```

Example sync request:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/sync -ContentType "application/json" -Body '{"peer_url":"http://127.0.0.1:8081"}'
```

Example wallet recovery status:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8080/wallets/status?label=Alice&provider_id=xmss_nist_v1"
```

Example recovery acknowledgement:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/wallets/recovery -ContentType "application/json" -Body '{"label":"Alice","address":"alice-address","provider_id":"xmss_nist_v1","note":"cleared after operator review"}'
```

Example seeding of a classical migration source:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/migration/sources -ContentType "application/json" -Body '{"classical_address":"secp256k1-p2pkh:00112233445566778899aabbccddeeff00112233","provider_id":"ecdsa_secp256k1_migration_v1","source_network":"legacy-btc-mainnet","source_address":"1BoatSLRHtKNngkdXEeobR76b53LETtpyT","source_address_format":"bitcoin_base58","amount":120,"snapshot_ref":"snapshot-2026-04"}'
```

Example import of a deterministic migration snapshot bundle:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/migration/snapshots -ContentType "application/json" -Body '{"source_network":"legacy-btc-mainnet","snapshot_ref":"snapshot-2026-04","generated_at":1775000000.0,"entries":[{"classical_address":"secp256k1-p2pkh:00112233445566778899aabbccddeeff00112233","provider_id":"ecdsa_secp256k1_migration_v1","source_address":"1BoatSLRHtKNngkdXEeobR76b53LETtpyT","source_address_format":"bitcoin_base58","amount":120}]}'
```

Example migration snapshot listing:

```powershell
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:8080/migration/snapshots
```

Example migration snapshot export and signing:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/migration/snapshots/export -ContentType "application/json" -Body '{"source_network":"legacy-btc-mainnet","snapshot_ref":"snapshot-2026-04","include_claimed":false,"sign":true}'
```

Example migration network profile query:

```powershell
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:8080/migration/networks
```

Example migration policy query:

```powershell
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:8080/migration/policy
```

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Operator CLI

```powershell
qr-chain migration-networks
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db currency
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db currency-supply
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-source-export-normalize --input source-export.json --sign --output snapshot.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-source-export-batch-normalize --input source-a.json --input source-b.json --output batch.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-source-ingestion-runbook --input snapshot.json --output runbook.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-source-ingestion-manifest-status --input snapshot.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-source-ingestion-approve --input snapshot.json --operator operator-a --reason "reviewed source export" --output approval.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-source-ingestion-import-plan --input snapshot.json --approval approval.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-source-ingestion-import-approved --input snapshot.json --approval approval.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-snapshot-export --source-network legacy-demo-ledger --snapshot-ref snapshot-2026-04 --sign --output snapshot.json
qr-chain migration-snapshot-validate --input snapshot.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-snapshot-reconcile --input snapshot.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-snapshot-import --input snapshot.json
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-report --source-network legacy-demo-ledger
qr-chain --db-path data/chain.db --wallet-state-db-path data/wallet_state.db migration-claim-preflight --destination-address pq-address --classical-address legacy-address --classical-provider-id classical_claim_demo_v1 --source-network legacy-demo-ledger
```

## What should follow next

- real source-chain snapshot ingestion from Bitcoin/Ethereum archive or indexer data, with reproducible extraction scripts
- broader legacy-chain family support beyond the current Bitcoin/Ethereum/RSA/demo migration profiles
- production-quality LMS and SPHINCS+ runtime integration and chain-level provider rollout policy
- stronger distributed signer coordination for multi-node or remote signer deployments
- secure key management with hardware-backed custody or isolated signer processes
- transport upgrades beyond HTTP JSON plus load, soak, and chaos testing
