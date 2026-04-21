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

## Quantum-resistant direction

The chain now supports a provider registry with both active and reserved backends:

- `hash_lamport_v1`: the original raw Lamport path kept for compatibility
- `xmss_merkle_lamport_v1`: an XMSS-style Merkle-tree wrapper around one-time Lamport leaves
- `xmss_nist_v1`: external adapter skeleton for a future audited XMSS backend module
- `lms_nist_v1`: reserved provider slot for a future audited LMS/HSS backend
- `sphincsplus_v1`: reserved provider slot for a future audited SPHINCS+ backend

The XMSS-style backend is still the default software provider for new wallets. It remains an in-repo reference implementation rather than a standards-audited production library, but the app is now structured so a real external provider can be registered without changing transaction, node, or API contracts.

The `xmss_nist_v1` adapter expects an optional external Python module, configured with `QR_CHAIN_XMSS_BACKEND_MODULE` and defaulting to the in-repo scaffold package `qr_chain_xmss_backend`. That module should expose:

- `generate_keypair()`
- `derive_address(keypair)`
- `sign(keypair, message)`
- `serialize_keypair(keypair)`
- `deserialize_keypair(payload)`
- `reserve_signing_material(keypair)`
- `sign_with_reservation(keypair, message, reservation)`
- `verify(message, signature, public_key)`
- `address_from_public_key(public_key)`

The scaffold package is intentionally present but non-functional: it raises precise “not integrated yet” errors until it is wired to a real audited XMSS implementation.

The wallet layer now also has a persistent SQLite-backed key-state store for stateful PQ signing. That gives XMSS-style providers a durable place to save leaf/index progress so a restart does not accidentally reuse one-time signing material.

That store now performs atomic signer-state reservations inside SQLite write transactions, so multiple local wallet instances sharing the same state database can coordinate XMSS-style leaf allocation without reusing the same one-time leaf.

This means the repo is now production-shaped rather than fully production-ready.

## Architecture

- `qr_blockchain/config.py`: environment-driven node configuration, chain identity, peers, and default signature provider selection
- `qr_blockchain/crypto.py`: formal signature-provider interface, provider registry, and current software PQ backends
- `qr_blockchain/models.py`: transaction and block models
- `qr_blockchain/storage.py`: SQLite persistence for blocks, pending transactions, and UTXOs
- `qr_blockchain/network.py`: simple peer URL normalization and JSON fetch helpers
- `qr_blockchain/auth.py`: node identity management and signed peer envelopes
- `qr_blockchain/auth.py`: node identity management, session-bound peer envelopes, and request binding helpers
- `qr_blockchain/service.py`: validation, mining, block import, wallet flow, mempool rules, and sync
- `qr_blockchain/storage.py`: canonical head tracking, side-branch storage, and canonical state rebuilds
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
$env:QR_CHAIN_DEFAULT_SIGNATURE_PROVIDER = "xmss_merkle_lamport_v1"
$env:QR_CHAIN_XMSS_BACKEND_MODULE = "qr_chain_xmss_backend"
$env:QR_CHAIN_WALLET_STATE_DB_PATH = "data/wallet_state.db"
$env:QR_CHAIN_AUTH_TIME_SKEW_SECONDS = "300"
$env:QR_CHAIN_PEER_SESSION_TTL_SECONDS = "900"
python main.py
```

## API endpoints

- `GET /health`
- `GET /chain/summary`
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
