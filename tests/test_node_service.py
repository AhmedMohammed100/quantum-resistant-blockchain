from __future__ import annotations

from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from qr_blockchain import NodeConfig, NodeService, Wallet
from qr_blockchain.crypto import XMSSMerkleLamportKeyPair, get_signature_suite


class NodeServiceTests(unittest.TestCase):
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
            chain_id=chain_id,
            node_id=node_id,
            advertised_url=advertised_url,
            peer_session_ttl_seconds=120,
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
                return source.authenticated_blocks(payload["auth"], int(payload["start_height"]))
            raise AssertionError(f"Unexpected URL {url}")

        with patch("qr_blockchain.service.fetch_json", side_effect=fake_fetch_json):
            imported = target.sync_with_peer(peer_url)

        self.assertEqual(imported, 1)
        self.assertEqual(target.balance_for_address(bob_address), 14)
        self.assertIn(peer_url, target.list_peers())

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
        self.assertIn("xmss_merkle_lamport_v1", providers)
        self.assertIn("xmss_nist_v1", providers)
        self.assertIn("module_path", providers["xmss_nist_v1"])


if __name__ == "__main__":
    unittest.main()
