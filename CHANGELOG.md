# Changelog

This changelog preserves the implementation history that previously lived in the README. The README now focuses on the public protocol overview, architecture, security model, and contributor quick start.

## Historical Implementation Phases

### Phase 76 - Load And Chaos Harness

- Added `qr_blockchain.chaos`, a deterministic scripted multi-node harness for mempool floods, fork storms, migration challenge disputes, signer crash/release behavior, and verification throughput.
- Added `load-chaos` CLI and `/testing/load-chaos` API surfaces with configurable scenario, node count, mempool transaction count, migration claim count, and verification batch size.
- Added harness coverage that exercises real `NodeService`, wallet signing, fork choice, migration dispute lifecycle, mempool policy, and verification worker paths against isolated SQLite databases.
- Updated README protocol docs with the load/chaos harness surface and visual flow while preserving the current public-facing structure and diagrams.

### Phase 75 - State Roots, Challenge Lifecycle, And Gossip Scoring

- Added explicit state-root activation policy, including configured activation height, required block version, and rejection of missing roots after activation.
- Added migration-claim reorg coverage to ensure canonical state roots and claimed-source indexes are rebuilt when fork choice moves to a competing branch.
- Extended migration disputes into a lifecycle: `open`, `evidence_submitted`, `resolved_valid`, `resolved_fraud`, and `expired`.
- Added claim-unlock behavior for `resolved_valid` and `expired` disputes, while `resolved_fraud` revokes the affected migration source.
- Added authenticated transaction/block gossip handlers, relay helpers, bad-block/invalid-gossip peer penalties, and peer-diversity readiness checks.

### Phase 74 - Native Verification Worker Pool

- Added a Rust-backed native verification batch API that accepts transaction-input verification jobs and returns per-input pass/fail results.
- Routed `native_test_pq_v1` consensus verification through the Rust extension when available, with fail-closed native errors and Python fallback when the extension is not installed.
- Kept address derivation and ownership prechecks in Python policy code while moving signature verification work for native providers into Rust worker threads.
- Added native batch verification smoke coverage and a multi-input transaction test that confirms the consensus verifier uses the Rust worker pool.
- Updated verification readiness reporting and README protocol docs to describe the native worker-pool boundary.

### Phase 70 - Signer Separation And Verification Boundaries

- Moved wallet signing out of `NodeService` into `qr_blockchain.signer`, introduced a `SignerBackend` protocol and `LocalWalletSigner`, and kept the public `Wallet` facade compatible.
- Added `qr_blockchain.verification` as the consensus-side signature verification boundary with safe worker-level parallelism for multi-input transactions.
- Added native Rust/C crypto target reporting through `crypto-native-boundary`, plus signer/consensus and verification-parallelism API/CLI surfaces.
- Added transaction state-model, validator-networking, migration-finality/fraud, and adversarial-performance readiness reports to cover the full critical-stage path.
- Updated README architecture and PQ signing diagrams to show the signer boundary, native runtime path, and verification worker pool.

### Phase 71 - State Roots, Maturity, Peer Scoring, And Disputes

- Added version-3 block UTXO state roots for newly mined blocks while keeping version-2 hash compatibility.
- Enforced configured coinbase maturity before reward outputs can be spent.
- Added authenticated peer sync scoring with success/failure counters for validator-networking hardening.
- Added persistent migration dispute records, dispute listing/opening API/CLI commands, challenge deadlines, and automatic source quarantine.
- Added focused tests for state roots, coinbase maturity, dispute quarantine, CLI dispute opening, and multi-input verification.

### Phase 72 - Native Rust Signer Boundary

- Added `crates/qr_chain_native_signer`, a Rust crate boundary with PyO3 exports, a deterministic test backend, and an optional `liboqs` feature target.
- Added the `qr_chain_native_signer` Python package bridge that loads a compiled `_native` extension in native mode and otherwise exposes an explicit deterministic test backend.
- Registered `native_test_pq_v1` through the signature provider registry so wallets and tests can exercise the native-provider contract.
- Added precise dependency failure behavior when native extension mode is requested before the Rust extension is built.

### Phase 73 - Native Build And liboqs Wiring

- Installed and repaired the Windows MSVC Rust toolchain path for local native signer builds.
- Built the deterministic PyO3 Rust extension and verified Python can load `qr_chain_native_signer._native`.
- Added Rust liboqs entry points for ML-DSA, Falcon, and SPHINCS+ key generation, signing, and verification behind the `liboqs` feature.
- Replaced the failing `oqs-sys` Windows binding path with a small controlled FFI layer linked against the local `liboqs 0.14.0` runtime.
- Verified ML-DSA-65, Falcon-512, and SPHINCS+-SHAKE-128f-simple native Rust extension signing and verification.

### Phase 1 - Service Architecture

- Added persistent SQLite-backed chain state, structured node configuration, a service layer, a JSON HTTP API, and automated persistence/transaction tests.

### Phase 2 - Chain-Bound Transactions And Sync

- Added chain-bound transaction signing, a signature abstraction layer, deterministic block validation, block import, peer registration, and block sync.

### Phase 3 - XMSS-Style Wallet Direction

- Made `xmss_merkle_lamport_v1` the default wallet signing scheme with Merkle-root addresses, leaf indexes, authentication paths, and one-time leaf enforcement.

### Phase 4 - Signature Provider Boundary

- Introduced a formal signature-provider interface, provider registry status, transaction verifier resolution, and external adapter slots for XMSS, LMS/HSS, and SPHINCS+.

### Phase 5 - Authenticated Peer Networking

- Added durable node identities, signed peer handshakes, authenticated peer request envelopes, timestamps, nonces, and replay rejection.

### Phase 6 - Fork Choice And Reorgs

- Added side-branch storage, cumulative-work fork choice, deterministic hash tie-breaking, and canonical UTXO rebuilds.

### Phase 7 - Peer Session Hardening

- Added expiring peer sessions, request binding to session id, path, method, and payload digest, plus strict target URL checks.

### Phase 8 - Provider Diagnostics

- Added live backend readiness reporting and `GET /crypto/providers`.

### Phase 9 - XMSS Backend Package Boundary

- Added `qr_chain_xmss_backend`, reference/module modes, environment-driven backend selection, diagnostics, and stricter backend manifest validation.

### Phase 10 - Secure Wallet Custody

- Added protected wallet/node identity storage, Windows DPAPI support, context-bound protected blobs, and legacy plaintext migration.

### Phase 11 - Crash-Safe Signer Coordination

- Added durable signer reservations, completion state writes, stale reservation handling, and multi-process coordination rules.

### Phase 12 - Mempool And Peer Framing

- Added duplicate rejection, pending caps, minimum fees, timestamp checks, transaction shape limits, peer frame protocol versions, message types, and frame digests.

### Phase 13 - Adversarial And Invariant Testing

- Added malformed peer frame tests, tamper tests, randomized roundtrips, supply conservation checks, and signer reservation diagnostics.

### Phase 14 - Signer Recovery Tooling

- Added recovery-required wallet-key states, wallet status reporting, and supported recovery acknowledgement paths.

### Phase 15 - Operational Health And Metrics

- Added live `/health`, `/status`, `/metrics`, degraded provider/recovery reporting, and operational counters.

### Phase 16 - LMS And SPHINCS+ Boundaries

- Added external adapter boundaries and OQS-backed module targets for LMS/HSS and SPHINCS+.

### Phase 17 - Classical-To-PQ Migration

- Added seeded migration sources, `migration_claim` transactions, classical-claim verifier registry, and demo verifier support.

### Phase 18 - Real Classical Verifiers

- Added real pure-Python secp256k1 and RSA PKCS#1 v1.5 SHA-256 migration verifier paths.

### Phase 19 - Migration Policy Controls

- Added claim windows, optional dual-control periods, and migration provider allow-lists.

### Phase 20 - Wallet Migration Helpers

- Added deterministic migration-claim drafts and wallet helpers for final claims and PQ destination attestations.

### Phase 21 - Provider Selection Policy

- Added preferred/allowed PQ provider policy and provider recommendation diagnostics.

### Phase 22 - Migration Load And Chaos Coverage

- Added bulk migration, authenticated sync, and reorg coverage for migration claims.

### Phase 23 - Auditable Snapshot Imports

- Added deterministic migration snapshot bundles, duplicate/amount/provider validation, manifest hashes, entries roots, idempotent imports, and conflict rejection.

### Phase 24 - Legacy Address Compatibility

- Added user-facing source addresses, Bitcoin/Ethereum/RSA/demo profiles, source format validation, and source metadata in migration claims.

### Phase 25 - Trusted Snapshot Issuer Policy

- Added signed snapshot artifacts and trusted snapshot signer/node allow-lists.

### Phase 26 - Live Snapshot Export

- Added deterministic snapshot export from stored migration sources, include-claimed support, and signed exports.

### Phase 27 - Operator CLI

- Added `qr-chain` and `python -m qr_blockchain` operator workflows for migration networks and snapshot artifacts.

### Phase 28 - External Address Proof Linkage

- Added secp256k1 proof linkage for Bitcoin-style and Ethereum-style source addresses.

### Phase 29 - Broader Source Address Proofs

- Added nested Bitcoin SegWit compatibility address support and source-ownership capability reporting.

### Phase 30 - Migration Review Lifecycle

- Added `active`, `quarantined`, and `revoked` statuses for snapshots and sources, with cascading review actions.

### Phase 31 - Reviewed Data Admission

- Blocked claims against inactive sources or snapshots and included review status in claimability/export reporting.

### Phase 32 - Migration Audit Reporting

- Added structured migration audit reports and API/CLI controls for review, quarantine, revoke, and report workflows.

### Phase 33 - Snapshot Reconciliation

- Added incoming-vs-local snapshot reconciliation before import.

### Phase 34 - Migration Claim Preflight

- Added claim readiness reports with policy, source status, snapshot status, provider policy, claim state, and exact signing payloads.

### Phase 35 - Signed Migration Receipts

- Added node-signed receipts for mined migration claims.

### Phase 36 - Migration Operator Controls

- Completed review-aware snapshot exports, reconciliation, preflight, receipts, status updates, and audit surfaces.

### Phase 37 - Source-Chain Export Ingestion

- Added normalization of source-chain/indexer records into deterministic migration snapshot bundles.

### Phase 38 - Source Export Schema Enforcement

- Added required field validation, provenance support, and public-key/source-address consistency checks.

### Phase 39 - Deterministic Ingestion Manifests

- Added stable ingestion manifests with record counts, totals, roots, source export hashes, snapshot hashes, and warnings.

### Phase 40 - Batch Source Export Normalization

- Added batch normalization with item hashes, total records, total amount, and batch hash.

### Phase 41 - Source Ingestion Runbooks

- Added operator runbooks tied to snapshot and ingestion manifest hashes.

### Phase 42 - Ingestion Manifest Validation

- Added standalone validation of ingestion evidence before import approval.

### Phase 43 - Operator Approval Artifacts

- Added deterministic approval records with operator identity, decision, reason, and approval hash.

### Phase 44 - Source Ingestion Import Plans

- Added dry-run import plans that block unsafe local changes, invalid manifests, invalid approvals, and review conflicts.

### Phase 45 - Approved Source Ingestion Imports

- Added approved import execution through the snapshot pipeline with approval evidence and post-import audit reports.

### Phase 46 - Rollback Evidence

- Added rollback evidence for approved imports, including manifest hashes and quarantine action guidance.

### Phase 47 - Source Ingestion Policy Gates

- Required valid approval artifacts for imports and expanded CLI/API support for the ingestion approval workflow.

### Phase 48 - Native Currency Metadata

- Added native currency name, symbol, decimals, base unit, formatted balances, and environment configuration.

### Phase 49 - Monetary Policy Layer

- Added height-aware mining subsidy, halving intervals, next-height subsidy, and cumulative subsidy reporting.

### Phase 50 - Genesis And Max-Money Checks

- Added genesis allocation cap support and max-money enforcement.

### Phase 51 - Canonical Supply Accounting

- Added canonical-chain supply reporting for genesis supply, subsidy, migration minting, fees, and UTXO supply.

### Phase 52 - Currency Operations

- Added HTTP and CLI surfaces for monetary policy, supply accounting, and formatted balances.

### Phase 53 - Currency Test Coverage

- Added tests for halving behavior, supply snapshots, genesis caps, formatted balances, config overrides, and CLI reporting.

### Phase 54 - QBC Coin Identity

- Made Quantum Blockchain Coin (`QBC`) the default native asset with 8 decimals and a 500,000,000 QBC cap.

### Phase 55 - Capped Allocation Model

- Added default buckets for migration pool, emissions, ecosystem treasury, security reserve, and public goods/liquidity.

### Phase 56 - Explicit Emission Curve

- Added a 175 QBC initial reward, 500,000-block halving interval, and 175,000,000 QBC emission cap.

### Phase 57 - Migration Conversion Policy

- Formalized capped migration issuance using normalized approved claims instead of unlimited 1:1 source balance minting.

### Phase 58 - Supply Policy Enforcement

- Added emission/migration remaining reporting and validation against genesis, emission, migration, and total supply caps.

### Phase 59 - Protocol Manifest Surface

- Added a machine-readable protocol manifest for chain id, network profile, object versions, peer frame version, QBC policy, migration policy, and security controls.
- Exposed the manifest through service, API, and CLI surfaces.

### Phase 60 - Migration Claim Quote Safety

- Added migration claim quotes with normalized claim amount, migration pool capacity, evidence scoring, and a claim intent hash.
- Exposed claim quotes through service, API, and CLI surfaces so wallets can check claim economics before signing.

### Phase 61 - Migration Claim Lifecycle Status

- Added lifecycle reporting for migration sources so operators and wallets can distinguish claimable, blocked, and claimed states.
- Attached quote data and mined claim settlement records to claim status output.

### Phase 62 - Migration Integrity Reporting

- Added migration integrity reports for missing snapshot records, weak source evidence, unsigned active snapshots when signatures are required, and pool exposure.
- Added migration-layer readiness gates based on integrity, provider availability, pool capacity, and signer recovery state.

### Phase 63 - Peer Admission Policy

- Added bounded peer admission with max admitted peers, optional allowlist enforcement, and denylist checks.
- Applied the policy to manual peer registration and authenticated peer identity admission.

### Phase 64 - ML-DSA OQS Backend Target

- Added `mldsa65_oqs_v1`, a stateless external signature provider backed by Open Quantum Safe `liboqs` through the Python `oqs` bindings.
- Added a `qr_chain_mldsa_backend` package boundary with ML-DSA-65 as the default mechanism and `Dilithium3` as a compatibility alias.
- Provider diagnostics now report ML-DSA standardization metadata, selected OQS mechanism, enabled mechanisms, and clean dependency/runtime errors.

### Phase 65 - Pinned OQS Runtime Path

- Pinned the optional `liboqs-python` dependency path, documented the native `liboqs` runtime target, and verified live `ML-DSA-65` signing through the `mldsa65_oqs_v1` provider.

### Phase 66 - Migration Assurance And Runtime Hardening

- Added source-export provenance hashes, source-chain anchors, and extractor metadata to normalized migration snapshots.
- Added migration governance reports for dispute windows, reviewer quorum, emergency pause, snapshot review state, and blocked sources.
- Added crypto runtime hardening reports for the pinned ML-DSA/OQS backend path.
- Added wallet-safe migration claim packages that bundle quotes, preflight checks, claim-intent hashes, and signing messages.
- Added deterministic adversarial migration checks for blocked snapshots, pool exposure, duplicate claims, and canonical claim uniqueness.

### Phase 67 - Project-Wide Readiness Surfaces

- Added signature strategy and runtime performance reports so the node can prefer fast standardized lattice signatures while preserving hash-based fallback lanes.
- Added transaction resource policy reporting for PQ signature payload sizes, fee-per-KiB inputs, and block/transaction size limits.
- Added consensus/economics readiness reporting for validator policy, coinbase maturity, reward model, halving, and known economic gaps.
- Added release provenance manifests and operator incident-response runbooks for release and operational readiness.

### Phase 68 - Migration Operations And Recovery Planning

- Added migration claim batch planning with pool-after-batch accounting and blocker explanations.
- Added conversion-risk reporting across migration source networks and classical proof providers.
- Added snapshot attestation readiness checks for trusted signers and reviewer quorum gaps.
- Added peer transport readiness and state backup manifests for operator recovery planning.

### Phase 69 - Protocol, Dispute, And Launch Preflight Surfaces

- Added protocol conformance reporting for chain, peer, currency, migration, and object-version surfaces.
- Added migration dispute packets and proof-coverage reporting so weak or contested source entries can be reviewed safely.
- Added node launch preflight gates across operational, migration, crypto, transport, consensus, and backup status.
- Added privacy redaction policy reporting for support bundles and operator evidence handling.
