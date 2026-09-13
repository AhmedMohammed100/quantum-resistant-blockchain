from __future__ import annotations

import random
import time
from pathlib import Path
import shutil
import unittest

from qr_blockchain import NodeConfig, NodeService, Wallet
from qr_blockchain.chaos import run_load_chaos_harness
from qr_blockchain.models import Block, Transaction, TxInput, TxOutput
from qr_blockchain.protocol import build_peer_frame, frame_digest, parse_peer_frame


class AdversarialAndPropertyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._rng = random.Random(1337)

    def make_service(self, name: str) -> NodeService:
        root = Path("test_runtime") / f"{self._testMethodName}_{name}"
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        return NodeService(
            NodeConfig(
                db_path=root / "chain.db",
                wallet_state_db_path=root / "wallet_state.db",
                difficulty=1,
                mining_reward=10,
                max_pending_transactions=16,
                min_transaction_fee=1,
                max_transaction_size_bytes=16777216,
                node_id=f"node-{name}",
                advertised_url=f"http://{name}:8080",
            )
        )

    def test_peer_frame_digest_detects_payload_tampering(self) -> None:
        frame = build_peer_frame(
            protocol_version="qr-peer-v1",
            message_type="peer_summary_request",
            payload={"height": 1},
            auth={"demo": True},
        )
        frame["payload"]["height"] = 2

        with self.assertRaisesRegex(ValueError, "digest"):
            parse_peer_frame(
                frame,
                expected_protocol_version="qr-peer-v1",
                expected_message_type="peer_summary_request",
            )

    def test_randomized_peer_frame_roundtrip_property(self) -> None:
        for index in range(25):
            payload = {
                "start_height": self._rng.randint(0, 1000),
                "nonce": f"n-{index}-{self._rng.randint(0, 10_000)}",
            }
            frame = build_peer_frame(
                protocol_version="qr-peer-v1",
                message_type="peer_blocks_request",
                payload=payload,
                auth={"token": f"t-{index}"},
            )
            parsed_payload, parsed_auth = parse_peer_frame(
                frame,
                expected_protocol_version="qr-peer-v1",
                expected_message_type="peer_blocks_request",
            )
            self.assertEqual(parsed_payload, payload)
            self.assertEqual(parsed_auth, {"token": f"t-{index}"})
            self.assertEqual(
                frame["frame_digest"],
                frame_digest("qr-peer-v1", "peer_blocks_request", payload),
            )

    def test_randomized_transaction_roundtrip_property(self) -> None:
        for _ in range(20):
            outputs = [
                TxOutput(recipient=f"addr-{self._rng.randint(1, 999)}", amount=self._rng.randint(1, 50))
                for _ in range(self._rng.randint(1, 4))
            ]
            transaction = Transaction(
                inputs=[
                    TxInput(
                        prev_tx_id=f"tx-{self._rng.randint(1, 999)}",
                        output_index=self._rng.randint(0, 3),
                        public_key={"scheme": "demo"},
                        signature={"sig": "demo"},
                    )
                    for _ in range(self._rng.randint(0, 3))
                ],
                outputs=outputs,
                chain_id="qr-chain-devnet",
                signature_scheme="xmss_merkle_lamport_v1",
                fee=self._rng.randint(0, 5),
                timestamp=round(self._rng.random() * 10_000, 6),
            )
            transaction.finalize()
            reloaded = Transaction.from_dict(
                {
                    "inputs": [vars(item) for item in transaction.inputs],
                    "outputs": [vars(item) for item in transaction.outputs],
                    "chain_id": transaction.chain_id,
                    "signature_scheme": transaction.signature_scheme,
                    "timestamp": transaction.timestamp,
                    "fee": transaction.fee,
                    "tx_id": transaction.tx_id,
                }
            )
            self.assertEqual(reloaded.tx_id, transaction.tx_id)
            self.assertEqual(reloaded.serialize_with_id(), transaction.serialize_with_id())

    def test_randomized_block_roundtrip_property(self) -> None:
        for _ in range(10):
            transaction = Transaction(
                inputs=[],
                outputs=[TxOutput(recipient=f"miner-{self._rng.randint(1, 999)}", amount=10)],
                chain_id="qr-chain-devnet",
                signature_scheme="xmss_merkle_lamport_v1",
                timestamp=round(self._rng.random() * 10_000, 6),
            )
            transaction.finalize()
            block = Block(
                index=self._rng.randint(0, 100),
                previous_hash="0" * 64,
                transactions=[transaction],
                miner=f"miner-{self._rng.randint(1, 999)}",
                difficulty=1,
                timestamp=round(self._rng.random() * 10_000, 6),
            )
            block.mine()
            reloaded = Block.from_dict(block.to_dict())
            self.assertEqual(reloaded.compute_hash(), block.block_hash)
            self.assertEqual(reloaded.to_dict(), block.to_dict())

    def test_malformed_peer_block_request_rejected(self) -> None:
        service = self.make_service("malformed")
        source = self.make_service("source")

        response = service.accept_peer_handshake(
            source.build_signed_envelope("peer_handshake_v2", {"target_url": service.config.advertised_url})
        )
        payload, auth = parse_peer_frame(
            response,
            expected_protocol_version=service.config.peer_protocol_version,
            expected_message_type="peer_handshake_response",
        )
        del payload
        admitted = source._authenticate_peer_envelope(
            auth,
            expected_purpose="peer_handshake_ack_v2",
            require_existing_peer=False,
            require_session=False,
        )
        source._admit_peer(admitted)
        service.store.upsert_peer_session(
            session_id=str(admitted["claims"]["session_id"]),
            node_id=source.config.node_id,
            url=source.config.advertised_url,
            created_at=0.0,
            last_seen=0.0,
            expires_at=float(admitted["claims"]["session_expires_at"]),
            status="active",
        )

        bad_envelope = source.build_peer_session_envelope(
            "peer_blocks_v2",
            service.config.advertised_url,
            str(admitted["claims"]["session_id"]),
            "/peer/blocks",
            {"start_height": -1},
        )
        with self.assertRaisesRegex(ValueError, "start height"):
            service.authenticated_blocks(bad_envelope, start_height=-1)

    def test_property_total_supply_conserved_minus_fees_plus_rewards(self) -> None:
        service = self.make_service("supply")
        alice = Wallet("Alice")
        bob = Wallet("Bob")
        miner = Wallet("Miner")

        alice_address = alice.create_address()
        bob_address = bob.create_address()
        miner_address = miner.create_address()
        genesis_total = 100
        service.create_genesis_block({alice_address: genesis_total})

        mined_blocks = 0
        total_fees = 0
        for amount, fee in [(10, 1), (7, 2), (5, 1)]:
            tx = alice.create_transaction(service, bob_address, amount=amount, fee=fee)
            service.submit_transaction(tx)
            total_fees += fee
            service.mine_pending_transactions(miner_address)
            mined_blocks += 1

        chain_outputs = sum(output.amount for _, _, output in service.list_utxos(alice.addresses() + bob.addresses() + miner.addresses()))
        expected_total = genesis_total + mined_blocks * service.config.mining_reward
        self.assertGreater(total_fees, 0)
        self.assertEqual(chain_outputs, expected_total)

        invariants = service.security_invariant_report()
        self.assertEqual(invariants["security_invariant_status"], "pass", invariants)
        self.assertTrue(
            next(check for check in invariants["checks"] if check["name"] == "canonical_utxo_index_matches_replay")[
                "passed"
            ]
        )
        self.assertTrue(
            next(check for check in invariants["checks"] if check["name"] == "activated_state_roots_match_replay")[
                "passed"
            ]
        )
        self.assertTrue(
            next(
                check
                for check in invariants["checks"]
                if check["name"] == "independent_supply_invariant_matches_utxo_replay"
            )["passed"]
        )

    def test_consensus_rejects_inputless_transfer_mint_and_wrong_difficulty(self) -> None:
        service = self.make_service("inputless-mint")
        miner = Wallet("Miner")
        service.create_genesis_block({"bootstrap": 10})
        parent = service.get_block(0)
        self.assertIsNotNone(parent)

        reward = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=miner.create_address(), amount=10)],
            chain_id=service.config.chain_id,
            signature_scheme=service.config.default_signature_provider,
            timestamp=1.0,
        )
        reward.finalize()
        minted = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient="attacker", amount=1_000_000)],
            chain_id=service.config.chain_id,
            signature_scheme=service.config.default_signature_provider,
            timestamp=1.0,
        )
        minted.finalize()
        block = Block(
            index=1,
            previous_hash=parent.block_hash,
            transactions=[reward, minted],
            miner=reward.outputs[0].recipient,
            difficulty=service.config.difficulty,
            chain_id=service.config.chain_id,
            version=3,
            timestamp=2.0,
        )
        block.state_root = service._state_root_after_block(service.store.all_utxos(), block)
        block.mine()

        with self.assertRaisesRegex(ValueError, "must include at least one input"):
            service.import_block(block)

        block.transactions = [reward]
        block.difficulty = 0
        block.state_root = service._state_root_after_block(service.store.all_utxos(), block)
        block.mine()
        with self.assertRaisesRegex(ValueError, "configured consensus difficulty"):
            service.import_block(block)

        block.difficulty = service.config.difficulty
        reward.fee = 1
        reward.finalize()
        block.state_root = service._state_root_after_block(service.store.all_utxos(), block)
        block.mine()
        with self.assertRaisesRegex(ValueError, "fee-free reward"):
            service.import_block(block)

    def test_consensus_rejects_invalid_timestamp_genesis_and_malformed_second_signature(self) -> None:
        service = self.make_service("consensus-boundaries")
        alice = Wallet("Alice")
        bob = Wallet("Bob")
        first = alice.create_address()
        second = alice.create_address()
        service.create_genesis_block({first: 10, second: 10})

        transaction = alice.create_transaction(service, bob.create_address(), amount=15, fee=1)
        self.assertEqual(len(transaction.inputs), 2)
        transaction.inputs[1].signature = {"malformed": True}
        transaction.finalize()
        with self.assertRaisesRegex(ValueError, "signature"):
            service.submit_transaction(transaction)

        parent = service.get_block(0)
        self.assertIsNotNone(parent)
        reward = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient="miner", amount=10)],
            chain_id=service.config.chain_id,
            signature_scheme=service.config.default_signature_provider,
            timestamp=0.0,
        )
        reward.finalize()
        stale = Block(
            index=1,
            previous_hash=parent.block_hash,
            transactions=[reward],
            miner="miner",
            difficulty=service.config.difficulty,
            chain_id=service.config.chain_id,
            version=3,
            timestamp=0.0,
        )
        stale.state_root = service._state_root_after_block(service.store.all_utxos(), stale)
        stale.mine()
        with self.assertRaisesRegex(ValueError, "greater than its parent"):
            service.import_block(stale)

        future = Block(
            index=1,
            previous_hash=parent.block_hash,
            transactions=[reward],
            miner="miner",
            difficulty=service.config.difficulty,
            chain_id=service.config.chain_id,
            version=3,
            timestamp=time.time() + service.config.auth_time_skew_seconds + 1,
        )
        future.state_root = service._state_root_after_block(service.store.all_utxos(), future)
        future.mine()
        with self.assertRaisesRegex(ValueError, "too far in the future"):
            service.import_block(future)

        fresh_service = self.make_service("invalid-genesis")
        allocation = Transaction(
            inputs=[], outputs=[TxOutput(recipient="one", amount=1)], timestamp=0.0
        )
        allocation.finalize()
        duplicate = Transaction(
            inputs=[], outputs=[TxOutput(recipient="two", amount=1)], timestamp=0.0
        )
        duplicate.finalize()
        invalid_genesis = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[allocation, duplicate],
            miner="genesis",
            difficulty=1,
            version=3,
            timestamp=0.0,
        )
        invalid_genesis.state_root = fresh_service._state_root_after_block({}, invalid_genesis)
        invalid_genesis.mine()
        with self.assertRaisesRegex(ValueError, "exactly one allocation"):
            fresh_service.import_block(invalid_genesis)

    def test_migration_claim_input_and_fee_rules_are_enforced_outside_mempool(self) -> None:
        service = self.make_service("migration-consensus")
        with_input = Transaction(
            inputs=[TxInput(prev_tx_id="missing", output_index=0)],
            outputs=[TxOutput(recipient="pq-destination", amount=1)],
            kind="migration_claim",
            chain_id=service.config.chain_id,
            fee=0,
            timestamp=1.0,
        )
        with_input.finalize()
        with self.assertRaisesRegex(ValueError, "cannot include UTXO inputs"):
            service._validate_transaction_against_view(with_input, {}, effective_height=1)

        with_fee = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient="pq-destination", amount=1)],
            kind="migration_claim",
            chain_id=service.config.chain_id,
            fee=1,
            timestamp=1.0,
        )
        with_fee.finalize()
        with self.assertRaisesRegex(ValueError, "cannot charge a fee"):
            service._validate_transaction_against_view(with_fee, {}, effective_height=1)
            
    def test_security_invariant_report_flags_pending_signer_recovery(self) -> None:
        service = self.make_service("recovery-invariant")
        alice = Wallet(
            "Alice",
            state_db_path=service.config.wallet_state_db_path,
            reservation_ttl_seconds=1,
        )
        funding = alice.create_address()

        def reserve_fn(current_state: object) -> tuple[object, object]:
            return current_state, {"leaf": 0}

        alice._state_store.reserve_wallet_key_state(
            alice.label,
            funding,
            alice.signature_provider,
            reserve_fn,
            owner_id=alice._owner_id,
            now=0.0,
        )

        report = service.security_invariant_report()

        self.assertEqual(report["security_invariant_status"], "fail_closed_review_required")
        recovery_check = next(check for check in report["checks"] if check["name"] == "stateful_signer_recovery_clear")
        self.assertFalse(recovery_check["passed"])
        self.assertEqual(recovery_check["detail"], "1")

    def test_signature_status_reports_reservation_counts(self) -> None:
        service = self.make_service("status")
        status = service.signature_provider_statuses()
        self.assertIn("wallet_reservation_status", status)
        self.assertIsInstance(status["wallet_reservation_status"], dict)

    def test_load_chaos_harness_runs_all_scripted_scenarios(self) -> None:
        root = Path("test_runtime") / self._testMethodName
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))

        report = run_load_chaos_harness(
            base_config=NodeConfig(
                db_path=root / "base_chain.db",
                wallet_state_db_path=root / "base_wallet.db",
                difficulty=1,
                mining_reward=10,
                max_pending_transactions=16,
            ),
            scenario="all",
            node_count=3,
            mempool_transactions=6,
            migration_claims=5,
            verification_batch_size=5,
            work_dir=root / "harness",
        )

        self.assertTrue(report["passed"], report)
        self.assertEqual(report["scenario_count"], 7)
        self.assertIn("mempool_flood", report["results"])
        self.assertIn("fork_storm", report["results"])
        self.assertIn("migration_disputes", report["results"])
        self.assertIn("signer_crash", report["results"])
        self.assertIn("verification_throughput", report["results"])


if __name__ == "__main__":
    unittest.main()
