"""Focused chain tests for NodeService.

Imported by test_node_service.py to preserve the existing unittest entry point.
"""
from tests.node_service_test_support import *
from tests.node_service_test_support import _connect_test_db, _secp256k1_sign


class NodeServiceChainTests(NodeServiceTestSupport):
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

    def test_native_provider_multi_input_verification_uses_rust_worker_pool_when_built(self) -> None:
        if importlib.util.find_spec("qr_chain_native_signer._native") is None:
            self.skipTest("Rust native signer extension is not built.")
        service, _ = self.make_service()

        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_NATIVE_SIGNER_MODE": "extension",
                "QR_CHAIN_NATIVE_SIGNER_USE_LIBOQS": "false",
            },
            clear=False,
        ):
            alice = Wallet("Alice", signature_provider="native_test_pq_v1")
            bob = Wallet("Bob", signature_provider="native_test_pq_v1")
            alice_first = alice.create_address()
            alice_second = alice.create_address()
            service.create_genesis_block({alice_first: 12, alice_second: 12})

            transaction = alice.create_transaction(service, bob.create_address(), amount=20, fee=1)
            verification = verify_transaction_inputs(transaction, service.store.all_utxos(), max_workers=2)

        self.assertTrue(verification.verified, verification.failure)
        self.assertEqual(verification.checked_inputs, 2)
        self.assertEqual(verification.mode, "native_rust_batch")

    def test_configured_provider_allowlist_rejects_deterministic_test_signatures(self) -> None:
        service, _ = self.make_service()
        with patch.dict(
            os.environ,
            {"QR_CHAIN_NATIVE_SIGNER_MODE": "deterministic-test"},
            clear=False,
        ):
            alice = Wallet("Alice", signature_provider="native_test_pq_v1")
            bob = Wallet("Bob")
            funding = alice.create_address()
            service.create_genesis_block({funding: 12})
            transaction = alice.create_transaction(service, bob.create_address(), amount=10, fee=1)

        service.config = replace(
            service.config,
            allowed_signature_providers=("xmss_merkle_lamport_v1",),
        )
        with self.assertRaisesRegex(ValueError, "configured provider allowlist"):
            service.submit_transaction(transaction)

    def test_configured_provider_allowlist_accepts_explicitly_allowed_test_provider(self) -> None:
        service, _ = self.make_service()
        with patch.dict(
            os.environ,
            {"QR_CHAIN_NATIVE_SIGNER_MODE": "deterministic-test"},
            clear=False,
        ):
            alice = Wallet("Alice", signature_provider="native_test_pq_v1")
            bob = Wallet("Bob")
            funding = alice.create_address()
            service.create_genesis_block({funding: 12})
            transaction = alice.create_transaction(service, bob.create_address(), amount=10, fee=1)

        service.config = replace(
            service.config,
            allowed_signature_providers=("native_test_pq_v1",),
        )
        service.submit_transaction(transaction)
        self.assertEqual(service.store.pending_transaction_count(), 1)

    def test_version3_blocks_commit_state_root_and_coinbase_maturity(self) -> None:
        temp_root = Path("test_runtime") / self._testMethodName
        if temp_root.exists():
            shutil.rmtree(temp_root)
        temp_root.mkdir(parents=True)
        self.addCleanup(lambda: shutil.rmtree(temp_root, ignore_errors=True))
        config = replace(self.make_config(temp_root / "chain.db"), coinbase_maturity_blocks=2)
        service = NodeService(config)
        miner = Wallet("Miner")
        bob = Wallet("Bob")

        service.create_genesis_block({"bootstrap": 1})
        miner_address = miner.create_address()
        reward_block = service.mine_pending_transactions(miner_address)
        self.assertEqual(reward_block.version, 3)
        self.assertTrue(reward_block.state_root)

        with self.assertRaisesRegex(ValueError, "Insufficient funds"):
            miner.create_transaction(service, bob.create_address(), amount=1, fee=1)

        service.mine_pending_transactions(miner_address)
        spend_reward = miner.create_transaction(service, bob.create_address(), amount=1, fee=1)
        service.submit_transaction(spend_reward)
        self.assertEqual(service.store.pending_transaction_count(), 1)

    def test_rejects_missing_state_root_after_activation_height(self) -> None:
        service, _ = self.make_service()
        service.config = replace(service.config, state_root_activation_height=1)
        service.create_genesis_block({"bootstrap": 1})
        latest = service.store.latest_block()
        assert latest is not None
        reward = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient="miner", amount=service.currency_policy().subsidy_at_height(1))],
            chain_id=service.config.chain_id,
            signature_scheme=service.config.default_signature_provider,
            fee=0,
        )
        reward.finalize()
        missing_root = Block(
            index=1,
            previous_hash=str(latest["block_hash"]),
            transactions=[reward],
            miner="miner",
            difficulty=service.config.difficulty,
            chain_id=service.config.chain_id,
            version=3,
            state_root="",
        )
        missing_root.mine()

        with self.assertRaisesRegex(ValueError, "missing the required state root"):
            service.import_block(missing_root)

    def test_migration_claim_reorg_rebuilds_state_root_and_claim_index(self) -> None:
        source, _ = self.make_service()
        target = self.make_additional_service("target")
        pq_wallet = Wallet("PQWallet")
        miner = Wallet("Miner")
        classical_public_key = build_demo_classical_claim_public_key("state-root-reorg")
        classical_address = build_demo_classical_claim_address(classical_public_key)

        for service in (source, target):
            service.create_genesis_block({"bootstrap": 1})
            service.seed_migration_source(
                classical_address=classical_address,
                provider_id="classical_claim_demo_v1",
                source_network="legacy-demo-ledger",
                amount=9,
                snapshot_ref="state-root-reorg",
            )

        preview = target.build_migration_claim_draft(
            destination_address=pq_wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            snapshot_ref="state-root-reorg",
            classical_public_key=classical_public_key,
        )
        classical_signature = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(preview.migration_claim_payload()),
        )
        claim = pq_wallet.create_migration_claim(
            target,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=classical_signature,
            source_network="legacy-demo-ledger",
            snapshot_ref="state-root-reorg",
            destination_address=preview.outputs[0].recipient,
            timestamp=preview.timestamp,
        )
        target.submit_transaction(claim)
        target.mine_pending_transactions(miner.create_address())
        self.assertIsNotNone(target.store.migration_claim(classical_address))

        source_miner = miner.create_address()
        first = source.mine_pending_transactions(source_miner)
        second = source.mine_pending_transactions(source_miner)
        target.import_block(first)
        target.import_block(second)

        best = target.get_block(2)
        assert best is not None
        self.assertIsNone(target.store.migration_claim(classical_address))
        self.assertEqual(best.block_hash, second.block_hash)
        self.assertEqual(best.state_root, target.state_root_for_utxos(target.store.all_utxos()))
        self.assertEqual(target.security_invariant_report()["security_invariant_status"], "pass")

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

