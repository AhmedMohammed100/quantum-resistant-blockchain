"""Focused wallet tests for NodeService.

Imported by test_node_service.py to preserve the existing unittest entry point.
"""
from node_service_test_support import *
from node_service_test_support import _connect_test_db, _secp256k1_sign


class NodeServiceWalletTests(NodeServiceTestSupport):
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

        with _connect_test_db(wallet_db) as connection:
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
        expected_backend = "windows_dpapi" if os.name == "nt" else "plaintext"
        self.assertEqual(row[2], expected_backend)
        if expected_backend == "windows_dpapi":
            self.assertNotIn(b"private_key", bytes(row[1]))
            self.assertNotIn(b"leaf_keypairs", bytes(row[1]))
        else:
            # Development mode may explicitly use the plaintext provider on
            # platforms without a native encrypted provider. Production mode
            # is covered separately and must fail closed instead.
            self.assertIn(b"private_key", bytes(row[1]))

    def test_wallet_store_migrates_legacy_plaintext_rows(self) -> None:
        wallet_db = self.wallet_state_db_path("legacy_wallet_state.db")
        provider = get_signature_suite("xmss_merkle_lamport_v1")
        keypair = provider.generate_keypair()
        address = provider.derive_address(keypair)
        legacy_json = provider.serialize_keypair(keypair)

        with _connect_test_db(wallet_db) as connection:
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

        with _connect_test_db(wallet_db) as connection:
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
        self.assertEqual(row[2], "windows_dpapi" if os.name == "nt" else "plaintext")

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
        expected_backend = "windows_dpapi" if os.name == "nt" else "plaintext"
        self.assertEqual(status["wallet_custody"]["backend_id"], expected_backend)
        if expected_backend == "plaintext":
            self.assertIn("warning", status["wallet_custody"])
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

