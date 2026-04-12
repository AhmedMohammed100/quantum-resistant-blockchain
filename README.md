# Quantum-Resistant Blockchain Prototype

This project is a small educational blockchain prototype that uses Lamport one-time signatures to simulate a post-quantum transaction flow.

## What it includes

- UTXO-based transaction model
- Lamport one-time signature keypairs
- Wallets that rotate to fresh addresses
- Simple proof-of-work mining
- Genesis funding and mining rewards
- Runnable demo script

## Why Lamport signatures?

Lamport signatures are hash-based and are widely used as a teaching example for post-quantum cryptography because their security does not rely on factoring or elliptic curves.

This prototype is intentionally simplified:

- It is not production-ready
- It keeps blockchain state in memory
- It uses single-input wallet spends for clarity
- It demonstrates concepts rather than network consensus

## Run it

```powershell
python main.py
```

## Project layout

- `main.py` runs a guided demo
- `qr_blockchain/lamport.py` contains the hash-based signature scheme
- `qr_blockchain/core.py` contains the blockchain, wallet, block, and transaction logic

## Expected demo flow

1. Alice receives genesis funds.
2. Alice pays Bob using a Lamport-signed transaction.
3. A miner confirms the transaction in a block.
4. Bob spends part of his funds back to Alice using a fresh Lamport key.
5. Final balances are printed.
