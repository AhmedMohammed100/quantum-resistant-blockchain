#!/usr/bin/env python3
"""Run real post-quantum crypto, transaction, and block validation benchmarks.

Example:
    python benchmarks/benchmark_node.py --operations 8 --block-repetitions 5 --output benchmark.json

The default provider is the real liboqs-backed ML-DSA-65 adapter. The command
fails closed when that provider is unavailable; it never substitutes a test
signature implementation for reported PQ measurements.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import tempfile
import time

from qr_blockchain.config import NodeConfig
from qr_blockchain.crypto import get_signature_provider
from qr_blockchain.models import Block, Transaction, TxOutput
from qr_blockchain.service import NodeService
from qr_blockchain.signer import Wallet


def _rate(operations: int, elapsed: float) -> dict[str, float | int]:
    safe_elapsed = max(elapsed, 1e-12)
    return {
        "operations": operations,
        "elapsed_seconds": elapsed,
        "operations_per_second": operations / safe_elapsed,
        "mean_latency_ms": safe_elapsed * 1000 / operations,
    }


def run_benchmarks(*, provider_id: str, operations: int, block_repetitions: int) -> dict[str, object]:
    # Keep one slot inside the node's default 500-transaction block limit for
    # the mandatory reward transaction constructed below.
    if operations < 1 or operations > 499:
        raise ValueError("operations must be between 1 and 499")
    if block_repetitions < 1 or block_repetitions > 100:
        raise ValueError("block_repetitions must be between 1 and 100")

    provider = get_signature_provider(provider_id)
    provider_status = provider.backend_status()
    if provider_status.get("available") is not True:
        raise RuntimeError(
            f"Benchmark requires the real '{provider_id}' provider; backend status: "
            f"{provider_status.get('error', 'unavailable')}"
        )

    payload = b"QBC benchmark payload: realistic transaction signing and verification"
    started = time.perf_counter()
    crypto_keypair = provider.generate_keypair()
    keygen_seconds = time.perf_counter() - started
    crypto_address = provider.derive_address(crypto_keypair)

    signatures: list[tuple[object, object]] = []
    started = time.perf_counter()
    for index in range(operations):
        signatures.append(provider.sign(crypto_keypair, payload + index.to_bytes(4, "big")))
    signing_seconds = time.perf_counter() - started

    started = time.perf_counter()
    verified = all(
        provider.verify(payload + index.to_bytes(4, "big"), signature, public_key)
        for index, (public_key, signature) in enumerate(signatures)
    )
    verification_seconds = time.perf_counter() - started
    if not verified:
        raise RuntimeError("The configured provider failed to verify its own benchmark signatures.")
    signature_sizes = [
        {
            "public_key_json_bytes": len(json.dumps(public_key, sort_keys=True).encode("utf-8")),
            "signature_json_bytes": len(json.dumps(signature, sort_keys=True).encode("utf-8")),
        }
        for public_key, signature in signatures
    ]

    with tempfile.TemporaryDirectory(prefix="qbc-pq-benchmark-") as temporary_root:
        root = Path(temporary_root)
        config = NodeConfig(
            db_path=root / "chain.db",
            wallet_state_db_path=root / "node-wallet.db",
            deployment_mode="test",
            chain_id="qbc-benchmark-chain",
            node_id="qbc-benchmark-node",
            difficulty=1,
            mining_reward=10,
            min_transaction_fee=1,
            default_signature_provider=provider_id,
            allowed_signature_providers=(provider_id,),
            max_transactions_per_block=operations + 1,
            max_pending_transactions=operations,
            state_root_activation_height=0,
        )
        service = NodeService(config)
        wallets = [Wallet(f"benchmark-sender-{index}", signature_provider=provider_id) for index in range(operations)]
        sender_addresses = [wallet.create_address() for wallet in wallets]
        receiver_wallet = Wallet("benchmark-receiver", signature_provider=provider_id)
        receiver_address = receiver_wallet.create_address()
        service.create_genesis_block({address: 100 for address in sender_addresses})

        started = time.perf_counter()
        transactions = [
            wallet.create_transaction(service, receiver_address, amount=99, fee=1)
            for wallet in wallets
        ]
        transaction_signing_seconds = time.perf_counter() - started

        started = time.perf_counter()
        for transaction in transactions:
            service.submit_transaction(transaction)
        transaction_submission_seconds = time.perf_counter() - started

        latest = service.store.latest_block()
        if latest is None:
            raise RuntimeError("Benchmark chain did not create genesis.")
        reward_transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient="benchmark-miner", amount=10 + len(transactions))],
            chain_id=config.chain_id,
            signature_scheme=provider_id,
            fee=0,
        )
        reward_transaction.finalize()
        block = Block(
            index=1,
            previous_hash=str(latest["block_hash"]),
            transactions=[reward_transaction, *transactions],
            miner="benchmark-miner",
            difficulty=1,
            chain_id=config.chain_id,
            version=3,
            timestamp=max(time.time(), 1.0),
        )
        block.state_root = service._state_root_after_block(
            service.store.utxos_for_head(str(latest["block_hash"])), block
        )
        block.mine()

        started = time.perf_counter()
        for _ in range(block_repetitions):
            service.validate_block(block)
        block_validation_seconds = time.perf_counter() - started

        return {
            "benchmark_version": 1,
            "provider": provider_id,
            "algorithm_family": provider.metadata.algorithm_family,
            "backend": provider_status,
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "processor": platform.processor(),
                "operations_per_batch": operations,
            },
            "crypto": {
                "keygen_seconds": keygen_seconds,
                "signing": _rate(operations, signing_seconds),
                "verification": _rate(operations, verification_seconds),
                "mean_public_key_json_bytes": sum(item["public_key_json_bytes"] for item in signature_sizes)
                / operations,
                "mean_signature_json_bytes": sum(item["signature_json_bytes"] for item in signature_sizes)
                / operations,
            },
            "transaction": {
                "wallet_transaction_signing": _rate(operations, transaction_signing_seconds),
                "node_submission_validation_and_storage": _rate(operations, transaction_submission_seconds),
            },
            "block_validation": {
                "transactions_per_block": len(block.transactions),
                "repetitions": block_repetitions,
                "elapsed_seconds": block_validation_seconds,
                "blocks_per_second": block_repetitions / max(block_validation_seconds, 1e-12),
                "transactions_verified_per_second": (
                    len(transactions) * block_repetitions / max(block_validation_seconds, 1e-12)
                ),
                "block_hash": block.block_hash,
                "state_root": block.state_root,
            },
            "notes": [
                "This measures the installed signature provider and SQLite-backed service path on this runner.",
                "Mining is excluded from block validation timing; the candidate block is built once and validated repeatedly.",
                "Results are measurements, not CI thresholds or performance guarantees.",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", default="mldsa65_oqs_v1")
    parser.add_argument("--operations", type=int, default=8)
    parser.add_argument("--block-repetitions", type=int, default=5)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    report = run_benchmarks(
        provider_id=arguments.provider,
        operations=arguments.operations,
        block_repetitions=arguments.block_repetitions,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

