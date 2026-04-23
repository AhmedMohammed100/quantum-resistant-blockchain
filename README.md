# Quantum-Resistant Blockchain Node

This repository is transitioning from an educational demo into a service-oriented node prototype that keeps the quantum-resistant goal central.

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

## Quantum-resistant direction

The chain now supports a provider registry with both active and reserved backends:

- `hash_lamport_v1`: the original raw Lamport path kept for compatibility
- `xmss_merkle_lamport_v1`: an XMSS-style Merkle-tree wrapper around one-time Lamport leaves
- `xmss_nist_v1`: external adapter skeleton for a future audited XMSS backend module
- `lms_nist_v1`: reserved provider slot for a future audited LMS/HSS backend
- `sphincsplus_v1`: reserved provider slot for a future audited SPHINCS+ backend

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

The peer transport is still HTTP-based, but it is now stricter than before: peer endpoints speak a versioned `qr-peer-v1` framed protocol rather than relying on unstructured JSON payloads alone.

This means the repo is now production-shaped rather than fully production-ready.

## Architecture

- `qr_blockchain/config.py`: environment-driven node configuration, chain identity, peers, and default signature provider selection
- `qr_blockchain/crypto.py`: formal signature-provider interface, provider registry, and current software PQ backends
- `qr_blockchain/custody.py`: wallet custody backends, including Windows DPAPI protection for stored signer state
- `qr_blockchain/models.py`: transaction and block models
- `qr_blockchain/storage.py`: SQLite persistence for blocks, pending transactions, and UTXOs
- `qr_blockchain/network.py`: simple peer URL normalization and JSON fetch helpers
- `qr_blockchain/auth.py`: node identity management and signed peer envelopes
- `qr_blockchain/wallet_store.py`: SQLite-backed protected wallet-state persistence and reservation coordination
- `qr_blockchain/service.py`: validation, mining, block import, wallet flow, mempool rules, and sync
- `qr_blockchain/api.py`: HTTP API for health, summary, balances, UTXOs, blocks, peers, genesis, mining, and sync
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

Peer framing:

- `QR_CHAIN_PEER_PROTOCOL_VERSION` selects the framed peer RPC version expected by this node
- `QR_CHAIN_MAX_PEER_BLOCKS_PER_REQUEST` limits how many blocks a peer can request or receive in one framed block response

## API endpoints

- `GET /health`
- `GET /chain/summary`
- `GET /crypto/providers`
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

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## What should follow next

- real audited XMSS/LMS/SPHINCS+ provider implementations behind the registry
- stronger multi-process and distributed coordination for stateful signer usage across multiple node processes
- secure key management and hardware-backed secrets
- observability, metrics, and operational hardening
