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

## Quantum-resistant direction

The current signing path uses the `hash_lamport_v1` suite behind a signature abstraction layer. That keeps the chain quantum-resistant today while making it possible to introduce stronger standardized families such as XMSS, LMS, or SPHINCS+ without rewriting the whole node stack.

This means the repo is now production-shaped rather than fully production-ready.

## Architecture

- `qr_blockchain/config.py`: environment-driven node configuration, chain identity, and peers
- `qr_blockchain/crypto.py`: signature-suite abstraction for quantum-safe wallet verification
- `qr_blockchain/models.py`: transaction and block models
- `qr_blockchain/storage.py`: SQLite persistence for blocks, pending transactions, and UTXOs
- `qr_blockchain/network.py`: simple peer URL normalization and JSON fetch helpers
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

## What phase 3 should add

- standardized post-quantum signature implementations
- authenticated peer-to-peer networking
- deterministic block validation across nodes
- replay protection and chain reorganization logic
- secure key management and hardware-backed secrets
- observability, metrics, and operational hardening
