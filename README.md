# Quantum-Resistant Blockchain Node

This repository is transitioning from an educational demo into a service-oriented node prototype that keeps the quantum-resistant goal central.

Phase 1 adds:

- persistent SQLite-backed chain state
- structured node configuration
- a service layer for validation and mining
- a JSON HTTP node API
- automated tests around persistence and transaction behavior

## Quantum-resistant direction

The current signing path still uses Lamport one-time signatures because they are simple, hash-based, and quantum-resistant. For a true production cryptography stack, the next phase should migrate from raw Lamport keys to standardized post-quantum signature families such as XMSS, LMS, or SPHINCS+ with robust key lifecycle management.

This means the repo is now production-shaped rather than fully production-ready.

## Architecture

- `qr_blockchain/config.py`: environment-driven node configuration
- `qr_blockchain/models.py`: transaction and block models
- `qr_blockchain/storage.py`: SQLite persistence for blocks, pending transactions, and UTXOs
- `qr_blockchain/service.py`: validation, mining, wallet flow, and mempool rules
- `qr_blockchain/api.py`: HTTP API for health, summary, balances, UTXOs, genesis, and mining
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
python main.py
```

## API endpoints

- `GET /health`
- `GET /chain/summary`
- `GET /addresses/{address}/balance`
- `GET /addresses/{address}/utxos`
- `POST /genesis`
- `POST /transactions`
- `POST /mine`

Example genesis request:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/genesis -ContentType "application/json" -Body '{"allocations":{"alice-address":120}}'
```

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## What phase 2 should add

- standardized post-quantum signature schemes
- authenticated peer-to-peer networking
- deterministic block validation across nodes
- replay protection and chain reorganization logic
- secure key management and hardware-backed secrets
- observability, metrics, and operational hardening
