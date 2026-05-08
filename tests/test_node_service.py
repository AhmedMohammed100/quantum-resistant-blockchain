from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import shutil
import sys
import types
import unittest
from unittest.mock import patch

from qr_blockchain import NodeConfig, NodeService, Wallet
from qr_blockchain.crypto import XMSSMerkleLamportKeyPair, get_signature_suite
from qr_blockchain.migration import (
    build_demo_classical_claim_address,
    build_demo_classical_claim_proof,
    build_demo_classical_claim_public_key,
    classical_claim_message_bytes,
)
from qr_blockchain.models import Transaction, TxOutput
from qr_blockchain.protocol import build_peer_frame
import qr_chain_classical_migration_backend_secp256k1 as secp_backend


def _secp256k1_sign(message: bytes, private_key: int, nonce: int = 7) -> bytes:
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    point = secp_backend._point_mul(nonce, secp_backend._G)
    assert point is not None
    r = point[0] % secp_backend._N
    s = (secp_backend._mod_inv(nonce, secp_backend._N) * (z + r * private_key)) % secp_backend._N
    if s > secp_backend._N // 2:
        s = secp_backend._N - s

    def _der_integer(value: int) -> bytes:
        encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
        return b"\x02" + bytes([len(encoded)]) + encoded

    body = _der_integer(r) + _der_integer(s)
    return b"\x30" + bytes([len(body)]) + body


class NodeServiceTests(unittest.TestCase):
    @staticmethod
    def build_fake_oqs_module(*, mechanisms: list[str] | None = None) -> types.ModuleType:
        module = types.ModuleType("oqs")
        available_mechanisms = mechanisms or ["XMSS-SHA2_10_256"]

        class FakeNativeLibrary:
            def __init__(self):
                self.OQS_SIG_STFL_SECRET_KEY_serialize = lambda *args: 0
                self.OQS_SIG_STFL_SECRET_KEY_deserialize = lambda *args: 0
                self.OQS_SIG_STFL_SECRET_KEY_free = lambda *args: None
                self.OQS_MEM_insecure_free = lambda *args: None

        class FakeStatefulSignature:
            def __init__(self, mechanism: str, secret_key: bytes | None = None):
                self.mechanism = mechanism
                self.secret_key = bytes(secret_key or b"secret:0")
                self.public_key = f"public:{self.mechanism}".encode("utf-8")

            def generate_keypair(self):
                self.secret_key = b"secret:0"
                self.public_key = f"public:{self.mechanism}".encode("utf-8")
                return self.public_key

            def export_secret_key(self):
                return self.secret_key

            def import_secret_key(self, secret_key: bytes):
                self.secret_key = bytes(secret_key)

            def sign(self, message: bytes):
                counter = int(self.secret_key.decode("utf-8").split(":")[1])
                signature = f"sig:{self.mechanism}:{counter}:{message.decode('utf-8')}".encode("utf-8")
                self.secret_key = f"secret:{counter + 1}".encode("utf-8")
                return signature

            def verify(self, message: bytes, signature: bytes, public_key: bytes):
                return (
                    public_key == f"public:{self.mechanism}".encode("utf-8")
                    and signature.decode("utf-8").endswith(message.decode("utf-8"))
                )

        module.__version__ = "0.test"
        module.StatefulSignature = FakeStatefulSignature
        module.get_enabled_stateful_sig_mechanisms = lambda: list(available_mechanisms)
        module.native = lambda: FakeNativeLibrary()
        return module

    def make_config(
        self,
        db_path: Path,
        *,
        chain_id: str = "qr-chain-devnet",
        node_id: str = "node-local",
        advertised_url: str = "http://127.0.0.1:8080",
    ) -> NodeConfig:
        return NodeConfig(
            db_path=db_path,
            wallet_state_db_path=db_path.parent / "wallet_state.db",
            difficulty=1,
            mining_reward=10,
            min_transaction_fee=1,
            max_pending_transactions=8,
            max_transaction_size_bytes=16777216,
            max_transaction_inputs=64,
            max_transaction_outputs=64,
            chain_id=chain_id,
            node_id=node_id,
            advertised_url=advertised_url,
            peer_session_ttl_seconds=120,
            max_peer_blocks_per_request=32,
        )

    def make_service(self) -> tuple[NodeService, Path]:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / self._testMethodName
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        db_path = case_dir / "chain.db"
        service = NodeService(self.make_config(db_path))
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return service, db_path

    def make_additional_service(self, suffix: str, *, chain_id: str = "qr-chain-devnet") -> NodeService:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / f"{self._testMethodName}_{suffix}"
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return NodeService(
            self.make_config(
                case_dir / "chain.db",
                chain_id=chain_id,
                node_id=f"node-{suffix}",
                advertised_url=f"http://{suffix}:8080",
            )
        )

    def wallet_state_db_path(self, suffix: str = "wallet_state.db") -> Path:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / f"{self._testMethodName}_wallet"
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return case_dir / suffix

    def test_persists_chain_state_across_restarts(self) -> None:
        service, db_path = self.make_service()
        alice = Wallet("Alice")
        miner = Wallet("Miner")

        service.create_genesis_block({alice.create_address(): 50})
        miner_address = miner.create_address()
        service.mine_pending_transactions(miner_address)

        restarted = NodeService(self.make_config(db_path))
        self.assertEqual(restarted.chain_summary()["height"], 2)
        self.assertEqual(restarted.balance_for_address(miner_address), 10)

    def test_multi_input_transaction_and_fee_reward(self) -> None:
        service, _ = self.make_service()
        alice = Wallet("Alice")
        bob = Wallet("Bob")
        miner = Wallet("Miner")

        alice_first = alice.create_address()
        alice_second = alice.create_address()
        bob_receive = bob.create_address()
        miner_address = miner.create_address()

        service.create_genesis_block({alice_first: 20, alice_second: 15})
        transaction = alice.create_transaction(service, bob_receive, amount=30, fee=2)
        service.submit_transaction(transaction)
        service.mine_pending_transactions(miner_address)

        self.assertEqual(service.balance_for_address(bob_receive), 30)
        self.assertEqual(service.balance_for_address(miner_address), 12)
        self.assertEqual(alice.balance(service), 3)

    def test_rejects_pending_double_spend(self) -> None:
        service, _ = self.make_service()
        alice = Wallet("Alice")
        bob = Wallet("Bob")

        funding = alice.create_address()
        bob_one = bob.create_address()
        bob_two = bob.create_address()

        service.create_genesis_block({funding: 25})
        first = alice.create_transaction(service, bob_one, amount=10, fee=1)
        second = alice.create_transaction(service, bob_two, amount=10, fee=1)

        service.submit_transaction(first)
        with self.assertRaisesRegex(ValueError, "pending spend"):
            service.submit_transaction(second)

    def test_rejects_low_fee_transaction_under_mempool_policy(self) -> None:
        service, _ = self.make_service()
        alice = Wallet("Alice")
        bob = Wallet("Bob")

        funding = alice.create_address()
        service.create_genesis_block({funding: 25})
        transaction = alice.create_transaction(service, bob.create_address(), amount=10, fee=0)

        with self.assertRaisesRegex(ValueError, "minimum relay policy"):
            service.submit_transaction(transaction)

    def test_rejects_transaction_when_mempool_is_full(self) -> None:
        service, _ = self.make_service()
        service.config = NodeConfig(**{**service.config.__dict__, "max_pending_transactions": 1})
        alice = Wallet("Alice")
        bob = Wallet("Bob")
        carol = Wallet("Carol")

        funding = alice.create_address()
        service.create_genesis_block({funding: 25})
        first = alice.create_transaction(service, bob.create_address(), amount=5, fee=1)
        second = alice.create_transaction(service, carol.create_address(), amount=5, fee=1)

        service.submit_transaction(first)
        with self.assertRaisesRegex(ValueError, "Mempool is full"):
            service.submit_transaction(second)

    def test_rejects_cross_chain_replay(self) -> None:
        service_a, _ = self.make_service()
        service_b = self.make_additional_service("other", chain_id="qr-chain-alt")

        alice = Wallet("Alice")
        bob = Wallet("Bob")

        funding = alice.create_address()
        service_a.create_genesis_block({funding: 30})
        transaction = alice.create_transaction(service_a, bob.create_address(), amount=10, fee=1)

        service_b.create_genesis_block({alice.create_address(): 30})
        with self.assertRaisesRegex(ValueError, "different chain"):
            service_b.submit_transaction(transaction)

    def test_imports_block_from_peer_node(self) -> None:
        source, _ = self.make_service()
        target = self.make_additional_service("target")

        alice = Wallet("Alice")
        bob = Wallet("Bob")
        miner = Wallet("Miner")

        funding = alice.create_address()
        bob_address = bob.create_address()
        miner_address = miner.create_address()

        source.create_genesis_block({funding: 25})
        target.create_genesis_block({funding: 25})
        transaction = alice.create_transaction(source, bob_address, amount=10, fee=1)
        source.submit_transaction(transaction)
        mined_block = source.mine_pending_transactions(miner_address)

        target.import_block(mined_block)

        self.assertEqual(target.chain_summary()["height"], 2)
        self.assertEqual(target.balance_for_address(bob_address), 10)
        self.assertEqual(target.balance_for_address(miner_address), 11)

    def test_reorgs_to_longer_work_branch_and_rebuilds_canonical_state(self) -> None:
        source, _ = self.make_service()
        target = self.make_additional_service("target")

        alice = Wallet("Alice")
        bob = Wallet("Bob")
        carol = Wallet("Carol")
        miner_one = Wallet("MinerOne")
        miner_two = Wallet("MinerTwo")

        funding = alice.create_address()
        bob_address = bob.create_address()
        carol_address = carol.create_address()
        miner_one_address = miner_one.create_address()
        miner_two_address = miner_two.create_address()

        source.create_genesis_block({funding: 30})
        target.create_genesis_block({funding: 30})

        branch_a_tx = alice.create_transaction(target, bob_address, amount=10, fee=1)
        target.submit_transaction(branch_a_tx)
        block_a = target.mine_pending_transactions(miner_one_address)

        branch_b_tx = alice.create_transaction(source, carol_address, amount=7, fee=1)
        source.submit_transaction(branch_b_tx)
        block_b1 = source.mine_pending_transactions(miner_two_address)
        block_b2 = source.mine_pending_transactions(miner_two_address)

        self.assertEqual(target.balance_for_address(bob_address), 10)
        self.assertEqual(target.balance_for_address(carol_address), 0)

        target.import_block(block_b1)
        target.import_block(block_b2)

        self.assertEqual(target.chain_summary()["height"], 3)
        self.assertEqual(target.balance_for_address(bob_address), 0)
        self.assertEqual(target.balance_for_address(carol_address), 7)
        self.assertEqual(target.balance_for_address(miner_one_address), 0)
        self.assertEqual(target.balance_for_address(miner_two_address), 21)
        self.assertEqual(target.get_block(1).block_hash, block_b1.block_hash)
        self.assertEqual(target.get_block(2).block_hash, block_b2.block_hash)

    def test_syncs_missing_blocks_from_peer(self) -> None:
        source, _ = self.make_service()
        target = self.make_additional_service("target")

        alice = Wallet("Alice")
        bob = Wallet("Bob")
        miner = Wallet("Miner")

        funding = alice.create_address()
        bob_address = bob.create_address()
        miner_address = miner.create_address()

        source.create_genesis_block({funding: 40})
        target.create_genesis_block({funding: 40})
        transaction = alice.create_transaction(source, bob_address, amount=14, fee=2)
        source.submit_transaction(transaction)
        mined_block = source.mine_pending_transactions(miner_address)

        peer_url = source.config.advertised_url

        def fake_fetch_json(url: str, *, method: str = "GET", payload: dict[str, object] | None = None, timeout: float = 10.0) -> dict[str, object]:
            if url.endswith("/peer/handshake"):
                return source.accept_peer_handshake(payload["auth"])
            if url.endswith("/peer/summary"):
                return source.authenticated_chain_summary(payload["auth"])
            if url.endswith("/peer/blocks"):
                frame_payload = payload["payload"]
                return source.authenticated_blocks(payload["auth"], int(frame_payload["start_height"]))
            raise AssertionError(f"Unexpected URL {url}")

        with patch("qr_blockchain.service.fetch_json", side_effect=fake_fetch_json):
            imported = target.sync_with_peer(peer_url)

        self.assertEqual(imported, 1)
        self.assertEqual(target.balance_for_address(bob_address), 14)
        self.assertIn(peer_url, target.list_peers())

    def test_migration_claim_moves_seeded_classical_balance_to_pq_address(self) -> None:
        service, _ = self.make_service()
        pq_wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-1")
        classical_address = service.seed_migration_source(
            classical_address=build_demo_classical_claim_address(classical_public_key),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=25,
            snapshot_ref="snapshot-001",
        )["classical_address"]
        pq_address = pq_wallet.create_address()
        transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=pq_address, amount=25)],
            kind="migration_claim",
            chain_id=service.config.chain_id,
            signature_scheme="classical_claim_demo_v1",
            metadata={
                "classical_address": classical_address,
                "classical_provider_id": "classical_claim_demo_v1",
                "source_network": "legacy-demo-ledger",
                "snapshot_ref": "snapshot-001",
                "classical_public_key": classical_public_key,
            },
        )
        transaction.metadata["classical_signature"] = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(transaction.migration_claim_payload()),
        )
        transaction.finalize()

        service.submit_transaction(transaction)
        service.mine_pending_transactions(miner.create_address())

        self.assertEqual(service.balance_for_address(pq_address), 25)
        claim = service.store.migration_claim(classical_address)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["destination_address"], pq_address)

    def test_migration_claim_proves_bitcoin_source_address_from_secp256k1_key(self) -> None:
        service, _ = self.make_service()
        pq_wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        private_key = 1
        public_point = secp_backend._point_mul(private_key, secp_backend._G)
        assert public_point is not None
        public_key_bytes = b"\x04" + public_point[0].to_bytes(32, "big") + public_point[1].to_bytes(32, "big")
        classical_public_key = {"public_key_hex": public_key_bytes.hex()}
        classical_address = service.seed_migration_source(
            classical_address=secp_backend.address_from_public_key(classical_public_key),
            provider_id="ecdsa_secp256k1_migration_v1",
            source_network="legacy-btc-mainnet",
            source_address=secp_backend.derive_bitcoin_p2pkh_addresses(classical_public_key)[0],
            source_address_format="bitcoin_base58",
            amount=21,
            snapshot_ref="snapshot-btc-001",
        )["classical_address"]
        pq_address = pq_wallet.create_address()
        transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=pq_address, amount=21)],
            kind="migration_claim",
            chain_id=service.config.chain_id,
            signature_scheme="ecdsa_secp256k1_migration_v1",
            metadata={
                "classical_address": classical_address,
                "classical_provider_id": "ecdsa_secp256k1_migration_v1",
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "snapshot-btc-001",
                "source_address": secp_backend.derive_bitcoin_p2pkh_addresses(classical_public_key)[0],
                "source_address_format": "bitcoin_base58",
                "classical_public_key": classical_public_key,
            },
        )
        transaction.metadata["classical_signature"] = {
            "signature_hex": _secp256k1_sign(
                classical_claim_message_bytes(transaction.migration_claim_payload()),
                private_key,
            ).hex()
        }
        transaction.finalize()

        service.submit_transaction(transaction)
        service.mine_pending_transactions(miner.create_address())

        self.assertEqual(service.balance_for_address(pq_address), 21)

    def test_rejects_duplicate_pending_migration_claim(self) -> None:
        service, _ = self.make_service()
        pq_wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-2")
        classical_address = build_demo_classical_claim_address(classical_public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=15,
            snapshot_ref="snapshot-002",
        )

        def build_claim() -> Transaction:
            tx = Transaction(
                inputs=[],
                outputs=[TxOutput(recipient=pq_wallet.create_address(), amount=15)],
                kind="migration_claim",
                chain_id=service.config.chain_id,
                signature_scheme="classical_claim_demo_v1",
                metadata={
                    "classical_address": classical_address,
                    "classical_provider_id": "classical_claim_demo_v1",
                    "source_network": "legacy-demo-ledger",
                    "snapshot_ref": "snapshot-002",
                    "classical_public_key": classical_public_key,
                },
            )
            tx.metadata["classical_signature"] = build_demo_classical_claim_proof(
                classical_public_key,
                classical_claim_message_bytes(tx.migration_claim_payload()),
            )
            tx.finalize()
            return tx

        service.submit_transaction(build_claim())
        with self.assertRaisesRegex(ValueError, "pending classical address claim"):
            service.submit_transaction(build_claim())

    def test_wallet_helper_builds_dual_control_migration_claim(self) -> None:
        wallet_db = self.wallet_state_db_path("dual_control_wallet_state.db")
        service = NodeService(
            NodeConfig(
                **{
                    **self.make_config(wallet_db.parent / "chain.db").__dict__,
                    "wallet_state_db_path": wallet_db,
                    "migration_dual_control_start_height": 1,
                    "migration_dual_control_end_height": 0,
                }
            )
        )
        self.addCleanup(lambda: shutil.rmtree(wallet_db.parent, ignore_errors=True))
        pq_wallet = Wallet("PQWallet", state_db_path=wallet_db)
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-3")
        classical_address = build_demo_classical_claim_address(classical_public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=12,
            snapshot_ref="snapshot-003",
        )
        preview = service.build_migration_claim_draft(
            destination_address=pq_wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-003",
            classical_public_key=classical_public_key,
        )
        classical_signature = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(preview.migration_claim_payload()),
        )
        claim = pq_wallet.create_migration_claim(
            service,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=classical_signature,
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-003",
            destination_address=preview.outputs[0].recipient,
            timestamp=preview.timestamp,
        )

        self.assertIn("destination_attestation", claim.metadata)
        service.submit_transaction(claim)
        service.mine_pending_transactions(miner.create_address())
        self.assertEqual(service.balance_for_address(preview.outputs[0].recipient), 12)

    def test_rejects_migration_claim_outside_claim_window(self) -> None:
        wallet_db = self.wallet_state_db_path("claim_window_wallet_state.db")
        service = NodeService(
            NodeConfig(
                **{
                    **self.make_config(wallet_db.parent / "chain.db").__dict__,
                    "wallet_state_db_path": wallet_db,
                    "migration_claim_start_height": 5,
                    "migration_dual_control_start_height": 0,
                    "migration_dual_control_end_height": 0,
                }
            )
        )
        self.addCleanup(lambda: shutil.rmtree(wallet_db.parent, ignore_errors=True))
        pq_wallet = Wallet("PQWallet", state_db_path=wallet_db)
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-4")
        classical_address = build_demo_classical_claim_address(classical_public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=9,
            snapshot_ref="snapshot-004",
        )
        preview = service.build_migration_claim_draft(
            destination_address=pq_wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-004",
            classical_public_key=classical_public_key,
        )
        classical_signature = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(preview.migration_claim_payload()),
        )
        claim = pq_wallet.create_migration_claim(
            service,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=classical_signature,
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-004",
            destination_address=preview.outputs[0].recipient,
            timestamp=preview.timestamp,
        )

        with self.assertRaisesRegex(ValueError, "outside the configured claim window"):
            service.submit_transaction(claim)

    def test_signature_provider_policy_prefers_available_stateless_provider(self) -> None:
        service, _ = self.make_service()

        with patch(
            "qr_blockchain.service.list_signature_provider_statuses",
            return_value=[
                {
                    "provider_id": "xmss_nist_v1",
                    "available": True,
                    "supports_stateful_signing": True,
                    "status": "adapter_ready",
                },
                {
                    "provider_id": "sphincsplus_v1",
                    "available": True,
                    "supports_stateful_signing": False,
                    "status": "adapter_ready",
                },
            ],
        ):
            service.config = NodeConfig(
                **{
                    **service.config.__dict__,
                    "preferred_signature_providers": ("sphincsplus_v1", "xmss_nist_v1"),
                    "allowed_signature_providers": ("xmss_nist_v1", "sphincsplus_v1"),
                }
            )
            policy = service.signature_provider_policy()

        self.assertEqual(policy["recommended_signature_provider"], "sphincsplus_v1")
        self.assertEqual(policy["recommended_stateless_provider"], "sphincsplus_v1")

    def test_rejects_peer_frame_with_wrong_protocol_version(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")

        handshake = build_peer_frame(
            protocol_version="qr-peer-wrong",
            message_type="peer_handshake_request",
            payload={},
            auth=target.build_signed_envelope("peer_handshake_v2", {"target_url": source.config.advertised_url}),
        )

        with self.assertRaisesRegex(ValueError, "protocol version"):
            from qr_blockchain.protocol import parse_peer_frame
            parse_peer_frame(
                handshake,
                expected_protocol_version=source.config.peer_protocol_version,
                expected_message_type="peer_handshake_request",
            )

    def test_authenticated_handshake_admits_peer(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")

        response = source.accept_peer_handshake(
            target.build_signed_envelope("peer_handshake_v2", {"target_url": source.config.advertised_url})
        )
        admitted = target._authenticate_peer_envelope(
            response["auth"],
            expected_purpose="peer_handshake_ack_v2",
            require_existing_peer=False,
            require_session=False,
        )
        target._admit_peer(admitted)

        self.assertIn(source.config.advertised_url, target.list_peers())
        self.assertTrue(admitted["claims"]["session_id"])

    def test_authenticated_request_rejects_replayed_nonce(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")

        response = source.accept_peer_handshake(
            target.build_signed_envelope("peer_handshake_v2", {"target_url": source.config.advertised_url})
        )
        admitted = target._authenticate_peer_envelope(
            response["auth"],
            expected_purpose="peer_handshake_ack_v2",
            require_existing_peer=False,
            require_session=False,
        )
        target._admit_peer(admitted)

        target.store.upsert_peer_session(
            session_id=str(admitted["claims"]["session_id"]),
            node_id=source.config.node_id,
            url=source.config.advertised_url,
            created_at=0.0,
            last_seen=0.0,
            expires_at=float(admitted["claims"]["session_expires_at"]),
            status="active",
        )
        envelope = source.build_peer_session_envelope(
            "peer_summary_v2",
            target.config.advertised_url,
            str(admitted["claims"]["session_id"]),
            "/peer/summary",
        )
        target.authenticated_chain_summary(envelope)
        with self.assertRaisesRegex(ValueError, "already been used"):
            target.authenticated_chain_summary(envelope)

    def test_authenticated_request_rejects_invalid_session_binding(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")

        response = target.accept_peer_handshake(
            source.build_signed_envelope("peer_handshake_v2", {"target_url": target.config.advertised_url})
        )
        admitted = source._authenticate_peer_envelope(
            response["auth"],
            expected_purpose="peer_handshake_ack_v2",
            require_existing_peer=False,
            require_session=False,
        )
        source._admit_peer(admitted)
        target.store.upsert_peer_session(
            session_id=str(admitted["claims"]["session_id"]),
            node_id=source.config.node_id,
            url=source.config.advertised_url,
            created_at=0.0,
            last_seen=0.0,
            expires_at=float(admitted["claims"]["session_expires_at"]),
            status="active",
        )

        envelope = source.build_peer_session_envelope(
            "peer_blocks_v2",
            target.config.advertised_url,
            str(admitted["claims"]["session_id"]),
            "/peer/blocks",
            {"start_height": 999},
        )

        with self.assertRaisesRegex(ValueError, "payload binding"):
            target.authenticated_blocks(envelope, start_height=0)

    def test_wallet_defaults_to_xmss_style_scheme(self) -> None:
        service, _ = self.make_service()
        alice = Wallet("Alice")
        bob = Wallet("Bob")

        funding = alice.create_address()
        service.create_genesis_block({funding: 25})
        transaction = alice.create_transaction(service, bob.create_address(), amount=10, fee=1)

        self.assertEqual(transaction.signature_scheme, "xmss_merkle_lamport_v1")
        self.assertIsInstance(transaction.inputs[0].public_key, dict)
        self.assertEqual(transaction.inputs[0].public_key["scheme"], "xmss_merkle_lamport_v1")
        self.assertIn("auth_path", transaction.inputs[0].signature)
        self.assertIn("leaf_index", transaction.inputs[0].signature)

    def test_xmss_style_suite_verifies_against_merkle_root(self) -> None:
        suite = get_signature_suite("xmss_merkle_lamport_v1")
        keypair = suite.generate_keypair()
        message = b"phase-3 xmss style signing"

        public_key, signature = suite.sign(keypair, message)

        self.assertTrue(suite.verify(message, signature, public_key))

        tampered_signature = dict(signature)
        tampered_path = list(signature["auth_path"])
        tampered_path[0] = tampered_path[0][::-1]
        tampered_signature["auth_path"] = tampered_path
        self.assertFalse(suite.verify(message, tampered_signature, public_key))

    def test_xmss_style_key_exhausts_leaf_budget(self) -> None:
        suite = get_signature_suite("xmss_merkle_lamport_v1")
        keypair = XMSSMerkleLamportKeyPair.generate(height=2)
        message = b"leaf budget"

        for _ in range(4):
            public_key, signature = suite.sign(keypair, message)
            self.assertTrue(suite.verify(message, signature, public_key))

        with self.assertRaisesRegex(ValueError, "exhausted"):
            suite.sign(keypair, message)

    def test_persistent_wallet_reloads_xmss_leaf_state(self) -> None:
        service, _ = self.make_service()
        wallet_db = self.wallet_state_db_path()
        alice = Wallet("Alice", state_db_path=wallet_db)
        bob = Wallet("Bob")

        funding = alice.create_address()
        service.create_genesis_block({funding: 25})
        transaction = alice.create_transaction(service, bob.create_address(), amount=10, fee=1)

        self.assertEqual(transaction.inputs[0].signature["leaf_index"], 0)

        reloaded = Wallet("Alice", state_db_path=wallet_db)
        self.assertIn(funding, reloaded.addresses())
        self.assertEqual(reloaded._keys[funding].next_index, 1)

    def test_wallet_state_is_protected_at_rest(self) -> None:
        service, _ = self.make_service()
        wallet_db = self.wallet_state_db_path("protected_wallet_state.db")
        alice = Wallet("Alice", state_db_path=wallet_db)
        bob = Wallet("Bob")

        funding = alice.create_address()
        service.create_genesis_block({funding: 25})
        alice.create_transaction(service, bob.create_address(), amount=10, fee=1)

        with sqlite3.connect(wallet_db) as connection:
            row = connection.execute(
                """
                SELECT key_state_json, key_state_blob, custody_backend
                FROM wallet_keys
                WHERE label = ? AND address = ?
                """,
                ("Alice", funding),
            ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "__protected__")
        self.assertIsNotNone(row[1])
        self.assertGreater(len(bytes(row[1])), 0)
        self.assertNotIn(b"private_key", bytes(row[1]))
        self.assertNotIn(b"leaf_keypairs", bytes(row[1]))
        self.assertEqual(row[2], "windows_dpapi")

    def test_wallet_store_migrates_legacy_plaintext_rows(self) -> None:
        wallet_db = self.wallet_state_db_path("legacy_wallet_state.db")
        provider = get_signature_suite("xmss_merkle_lamport_v1")
        keypair = provider.generate_keypair()
        address = provider.derive_address(keypair)
        legacy_json = provider.serialize_keypair(keypair)

        with sqlite3.connect(wallet_db) as connection:
            connection.executescript(
                """
                CREATE TABLE wallet_keys (
                    label TEXT NOT NULL,
                    address TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    key_state_json TEXT NOT NULL,
                    state_version INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (label, address)
                );
                """
            )
            connection.execute(
                """
                INSERT INTO wallet_keys (label, address, provider_id, key_state_json, state_version)
                VALUES (?, ?, ?, ?, 0)
                """,
                ("Alice", address, "xmss_merkle_lamport_v1", json.dumps(legacy_json)),
            )

        reloaded = Wallet("Alice", state_db_path=wallet_db)
        self.assertIn(address, reloaded.addresses())

        with sqlite3.connect(wallet_db) as connection:
            row = connection.execute(
                """
                SELECT key_state_json, key_state_blob, custody_backend
                FROM wallet_keys
                WHERE label = ? AND address = ?
                """,
                ("Alice", address),
            ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "__protected__")
        self.assertIsNotNone(row[1])
        self.assertEqual(row[2], "windows_dpapi")

    def test_reservation_completion_persists_stateful_oqs_progress(self) -> None:
        service, _ = self.make_service()
        wallet_db = self.wallet_state_db_path("oqs_wallet_state.db")
        fake_oqs = self.build_fake_oqs_module()

        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "qr_chain_xmss_backend.oqs_backend",
                "QR_CHAIN_XMSS_OQS_MECHANISM": "XMSS-SHA2_10_256",
            },
            clear=False,
        ):
            with patch.dict(sys.modules, {"oqs": fake_oqs}, clear=False):
                alice = Wallet("Alice", signature_provider="xmss_nist_v1", state_db_path=wallet_db)
                bob = Wallet("Bob")
                funding = alice.create_address()
                service.create_genesis_block({funding: 25})
                alice.create_transaction(service, bob.create_address(), amount=10, fee=1)

                reloaded = Wallet("Alice", signature_provider="xmss_nist_v1", state_db_path=wallet_db)
                state = reloaded._provider.serialize_keypair(reloaded._keys[funding])

        self.assertEqual(state["signatures_used"], 1)
        self.assertEqual(state["secret_key_hex"], b"secret:1".hex())

    def test_stale_ambiguous_reservation_requires_recovery(self) -> None:
        wallet_db = self.wallet_state_db_path("stale_reservation_wallet.db")
        fake_oqs = self.build_fake_oqs_module()

        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "qr_chain_xmss_backend.oqs_backend",
                "QR_CHAIN_XMSS_OQS_MECHANISM": "XMSS-SHA2_10_256",
            },
            clear=False,
        ):
            with patch.dict(sys.modules, {"oqs": fake_oqs}, clear=False):
                alice = Wallet(
                    "Alice",
                    signature_provider="xmss_nist_v1",
                    state_db_path=wallet_db,
                    reservation_ttl_seconds=1,
                )
                funding = alice.create_address()

                def reserve_fn(current_state: object) -> tuple[object, object]:
                    keypair = alice._provider.deserialize_keypair(current_state)
                    reservation = alice._provider.reserve_signing_material(keypair)
                    return alice._provider.serialize_keypair(keypair), reservation

                alice._state_store.reserve_wallet_key_state(
                    alice.label,
                    funding,
                    alice.signature_provider,
                    reserve_fn,
                    owner_id=alice._owner_id,
                    now=0.0,
                )

                with self.assertRaisesRegex(ValueError, "requires operator recovery"):
                    alice._state_store.reserve_wallet_key_state(
                        alice.label,
                        funding,
                        alice.signature_provider,
                        reserve_fn,
                        owner_id=alice._owner_id,
                        now=2.0,
                    )

    def test_shared_wallet_instances_coordinate_leaf_reservations(self) -> None:
        service, _ = self.make_service()
        wallet_db = self.wallet_state_db_path("shared_wallet_state.db")
        alice_primary = Wallet("Alice", state_db_path=wallet_db)
        alice_secondary = Wallet("Alice", state_db_path=wallet_db)
        bob = Wallet("Bob")
        carol = Wallet("Carol")

        funding = alice_primary.create_address()
        alice_secondary = Wallet("Alice", state_db_path=wallet_db)
        service.create_genesis_block({funding: 25})

        tx_one = alice_primary.create_transaction(service, bob.create_address(), amount=5, fee=1)
        tx_two = alice_secondary.create_transaction(service, carol.create_address(), amount=5, fee=1)

        self.assertEqual(tx_one.inputs[0].signature["leaf_index"], 0)
        self.assertEqual(tx_two.inputs[0].signature["leaf_index"], 1)

        reloaded = Wallet("Alice", state_db_path=wallet_db)
        self.assertEqual(reloaded._keys[funding].next_index, 2)

    def test_reports_signature_provider_statuses(self) -> None:
        service, _ = self.make_service()

        status = service.signature_provider_statuses()
        providers = {item["provider_id"]: item for item in status["providers"]}

        self.assertEqual(status["default_signature_provider"], service.config.default_signature_provider)
        self.assertEqual(status["wallet_custody"]["backend_id"], "windows_dpapi")
        self.assertIn("xmss_merkle_lamport_v1", providers)
        self.assertIn("xmss_nist_v1", providers)
        self.assertIn("module_path", providers["xmss_nist_v1"])

    def test_wallet_recovery_status_and_manual_recovery_flow(self) -> None:
        wallet_db = self.wallet_state_db_path("recovery_wallet_state.db")
        service = NodeService(
            NodeConfig(
                **{
                    **self.make_config(wallet_db.parent / "chain.db").__dict__,
                    "wallet_state_db_path": wallet_db,
                }
            )
        )
        self.addCleanup(lambda: shutil.rmtree(wallet_db.parent, ignore_errors=True))
        fake_oqs = self.build_fake_oqs_module()

        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "qr_chain_xmss_backend.oqs_backend",
                "QR_CHAIN_XMSS_OQS_MECHANISM": "XMSS-SHA2_10_256",
            },
            clear=False,
        ):
            with patch.dict(sys.modules, {"oqs": fake_oqs}, clear=False):
                alice = Wallet(
                    "Alice",
                    signature_provider="xmss_nist_v1",
                    state_db_path=wallet_db,
                    reservation_ttl_seconds=1,
                )
                funding = alice.create_address()

                def reserve_fn(current_state: object) -> tuple[object, object]:
                    keypair = alice._provider.deserialize_keypair(current_state)
                    reservation = alice._provider.reserve_signing_material(keypair)
                    return alice._provider.serialize_keypair(keypair), reservation

                alice._state_store.reserve_wallet_key_state(
                    alice.label,
                    funding,
                    alice.signature_provider,
                    reserve_fn,
                    owner_id=alice._owner_id,
                    now=0.0,
                )

                with self.assertRaisesRegex(ValueError, "requires operator recovery"):
                    alice._state_store.reserve_wallet_key_state(
                        alice.label,
                        funding,
                        alice.signature_provider,
                        reserve_fn,
                        owner_id=alice._owner_id,
                        now=2.0,
                    )

                status_before = service.wallet_key_statuses(label="Alice", provider_id="xmss_nist_v1")
                self.assertEqual(status_before["reservation_status"]["requires_recovery"], 1)
                self.assertTrue(status_before["wallet_keys"][0]["requires_recovery"])

                recovered = service.recover_wallet_key(
                    "Alice",
                    funding,
                    "xmss_nist_v1",
                    note="cleared after crash inspection",
                )
                self.assertEqual(recovered["status"], "recovered")

                status_after = service.wallet_key_statuses(label="Alice", provider_id="xmss_nist_v1")
                self.assertEqual(status_after["reservation_status"]["recovered"], 1)
                self.assertFalse(status_after["wallet_keys"][0]["requires_recovery"])

                _, _, reservation_id = alice._state_store.reserve_wallet_key_state(
                    alice.label,
                    funding,
                    alice.signature_provider,
                    reserve_fn,
                    owner_id=alice._owner_id,
                    now=3.0,
                )
                self.assertTrue(reservation_id)

    def test_operational_status_reports_degraded_recovery_condition(self) -> None:
        wallet_db = self.wallet_state_db_path("health_recovery_wallet_state.db")
        service = NodeService(
            NodeConfig(
                **{
                    **self.make_config(wallet_db.parent / "chain.db").__dict__,
                    "wallet_state_db_path": wallet_db,
                }
            )
        )
        self.addCleanup(lambda: shutil.rmtree(wallet_db.parent, ignore_errors=True))
        fake_oqs = self.build_fake_oqs_module()

        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "qr_chain_xmss_backend.oqs_backend",
                "QR_CHAIN_XMSS_OQS_MECHANISM": "XMSS-SHA2_10_256",
            },
            clear=False,
        ):
            with patch.dict(sys.modules, {"oqs": fake_oqs}, clear=False):
                alice = Wallet(
                    "Alice",
                    signature_provider="xmss_nist_v1",
                    state_db_path=wallet_db,
                    reservation_ttl_seconds=1,
                )
                funding = alice.create_address()

                def reserve_fn(current_state: object) -> tuple[object, object]:
                    keypair = alice._provider.deserialize_keypair(current_state)
                    reservation = alice._provider.reserve_signing_material(keypair)
                    return alice._provider.serialize_keypair(keypair), reservation

                alice._state_store.reserve_wallet_key_state(
                    alice.label,
                    funding,
                    alice.signature_provider,
                    reserve_fn,
                    owner_id=alice._owner_id,
                    now=0.0,
                )
                with self.assertRaises(ValueError):
                    alice._state_store.reserve_wallet_key_state(
                        alice.label,
                        funding,
                        alice.signature_provider,
                        reserve_fn,
                        owner_id=alice._owner_id,
                        now=2.0,
                    )

                status = service.operational_status()
                self.assertEqual(status["status"], "degraded")
                self.assertIn("wallet keys require signer recovery", " ".join(status["reasons"]))

    def test_metrics_snapshot_reports_operational_counters(self) -> None:
        service, _ = self.make_service()
        alice = Wallet("Alice")
        miner = Wallet("Miner")
        funding = alice.create_address()
        service.create_genesis_block({funding: 25})
        service.mine_pending_transactions(miner.create_address())

        metrics = service.metrics_snapshot()

        self.assertEqual(metrics["chain_height"], 2)
        self.assertGreaterEqual(metrics["utxo_count"], 1)
        self.assertIn("wallet_reservation_status", metrics)
        self.assertIn("available_provider_count", metrics)


if __name__ == "__main__":
    unittest.main()
