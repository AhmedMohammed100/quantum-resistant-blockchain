"""Focused migration tests for NodeService.

Imported by test_node_service.py to preserve the existing unittest entry point.
"""
from node_service_test_support import *
from node_service_test_support import _connect_test_db, _secp256k1_sign


class NodeServiceMigrationTests(NodeServiceTestSupport):
    def test_open_migration_dispute_quarantines_source(self) -> None:
        service, _ = self.make_service()
        classical_address = build_demo_classical_claim_address(build_demo_classical_claim_public_key("open-dispute"))
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=8,
            snapshot_ref="disputed-snapshot",
        )

        dispute = service.open_migration_dispute(classical_address, reason="conflicting external ownership proof")
        disputes = service.migration_disputes(classical_address)
        source = service.store.migration_source(classical_address)

        self.assertEqual(dispute["status"], "open")
        self.assertEqual(disputes["open_dispute_count"], 1)
        self.assertEqual(source["status"], "quarantined")
        self.assertIn("open dispute", source["status_reason"])

    def test_migration_dispute_lifecycle_blocks_unlocks_and_revokes_claims(self) -> None:
        service, _ = self.make_service()
        classical_address = build_demo_classical_claim_address(build_demo_classical_claim_public_key("lifecycle"))
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=8,
            snapshot_ref="lifecycle-snapshot",
        )

        opened = service.open_migration_dispute(classical_address, reason="conflicting source export")
        self.assertFalse(service.migration_claim_quote(classical_address)["claimable"])
        evidence = service.submit_migration_dispute_evidence(
            opened["dispute_id"],
            evidence={"source_export_hash": "abc"},
        )
        self.assertEqual(evidence["status"], "evidence_submitted")
        resolved = service.resolve_migration_dispute(
            opened["dispute_id"],
            outcome="resolved_valid",
            resolution_note="operator review accepted original source",
        )
        self.assertEqual(resolved["status"], "resolved_valid")
        self.assertTrue(service.migration_claim_quote(classical_address)["claimable"])

        fraud_address = build_demo_classical_claim_address(build_demo_classical_claim_public_key("fraud"))
        service.seed_migration_source(
            classical_address=fraud_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=5,
            snapshot_ref="fraud-snapshot",
        )
        fraud = service.open_migration_dispute(fraud_address, reason="forged ownership")
        service.resolve_migration_dispute(
            fraud["dispute_id"],
            outcome="resolved_fraud",
            resolution_note="source signature failed review",
        )
        self.assertEqual(service.store.migration_source(fraud_address)["status"], "revoked")
        self.assertFalse(service.migration_claim_quote(fraud_address)["claimable"])

    def test_resolved_fraud_dispute_remains_revoked_after_challenge_window(self) -> None:
        service, _ = self.make_service()
        service.config = replace(service.config, migration_dispute_window_blocks=0)
        classical_address = build_demo_classical_claim_address(build_demo_classical_claim_public_key("fraud-expiry"))
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=7,
            snapshot_ref="fraud-expiry-snapshot",
        )
        service.create_genesis_block({"bootstrap": 1})

        opened = service.open_migration_dispute(classical_address, reason="forged source ownership")
        service.resolve_migration_dispute(
            opened["dispute_id"],
            outcome="resolved_fraud",
            resolution_note="reviewer rejected source proof",
        )
        service.mine_pending_transactions("miner")
        expired = service.expire_migration_disputes()

        self.assertEqual(expired["expired_count"], 0)
        self.assertEqual(service._migration_dispute_by_id(opened["dispute_id"])["status"], "resolved_fraud")
        self.assertEqual(service.store.migration_source(classical_address)["status"], "revoked")
        self.assertFalse(service.migration_claim_quote(classical_address)["claimable"])

    def test_expired_migration_dispute_unlocks_claim_after_challenge_window(self) -> None:
        service, _ = self.make_service()
        service.config = replace(service.config, migration_dispute_window_blocks=0)
        classical_address = build_demo_classical_claim_address(build_demo_classical_claim_public_key("expired"))
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=5,
            snapshot_ref="expired-snapshot",
        )
        service.create_genesis_block({"bootstrap": 1})
        opened = service.open_migration_dispute(classical_address, reason="temporary review")
        service.mine_pending_transactions("miner")

        expired = service.expire_migration_disputes()

        self.assertEqual(expired["expired_count"], 1)
        self.assertEqual(service._migration_dispute_by_id(opened["dispute_id"])["status"], "expired")
        self.assertTrue(service.migration_claim_quote(classical_address)["claimable"])

    def test_source_export_normalization_includes_provenance_hash(self) -> None:
        service, _ = self.make_service()
        public_key = build_demo_classical_claim_public_key("provenance-user")
        payload = {
            "source_network": "legacy-demo-ledger",
            "snapshot_ref": "provenance-snapshot",
            "generated_at": 1.0,
            "provider_id": "classical_claim_demo_v1",
            "extractor": {"name": "demo-exporter", "version": "1.0", "command": "export --height 10"},
            "source_anchor": {"height": 10, "block_hash": "abc123"},
            "records": [{"classical_public_key": public_key, "amount": 11}],
        }

        normalized = service.normalize_source_export_snapshot(payload)

        self.assertTrue(normalized["source_provenance"]["source_provenance_hash"])
        self.assertEqual(
            normalized["ingestion_manifest"]["source_provenance_hash"],
            normalized["source_provenance"]["source_provenance_hash"],
        )

    def test_peer_allowlist_policy_blocks_unapproved_manual_registration(self) -> None:
        service, _ = self.make_service()
        service.config = replace(
            service.config,
            require_peer_allowlist=True,
            peer_allowlist=("http://allowed-peer:8080",),
        )

        with self.assertRaisesRegex(ValueError, "not allowed"):
            service.register_peer("http://blocked-peer:8080")
        self.assertEqual(service.register_peer("http://allowed-peer:8080"), "http://allowed-peer:8080")

    def test_migration_claim_quote_reports_pool_capacity(self) -> None:
        service, _ = self.make_service()
        public_key = build_demo_classical_claim_public_key("quote-user")
        classical_address = build_demo_classical_claim_address(public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=7,
            snapshot_ref="quote-snapshot",
        )

        quote = service.migration_claim_quote(classical_address)

        self.assertTrue(quote["claimable"])
        self.assertEqual(quote["normalized_claim_amount"], 7)
        self.assertEqual(quote["conversion_policy"], service.config.migration_conversion_policy)
        self.assertTrue(quote["claim_intent_hash"])
        self.assertEqual(service.migration_claim_status(classical_address)["lifecycle_state"], "claimable")

    def test_wallet_migration_claim_package_and_adversarial_report(self) -> None:
        service, _ = self.make_service()
        service.create_genesis_block({"bootstrap": 1})
        public_key = build_demo_classical_claim_public_key("package-user")
        classical_address = build_demo_classical_claim_address(public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=9,
            snapshot_ref="package-snapshot",
        )

        package = service.build_wallet_migration_claim_package(
            destination_address="pq-package-destination",
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            snapshot_ref="package-snapshot",
            classical_public_key=public_key,
        )
        adversarial = service.migration_adversarial_simulation_report()

        self.assertTrue(package["ready"])
        self.assertTrue(package["package_hash"])
        self.assertEqual(package["claims"]["classical_address"], classical_address)
        self.assertIn(adversarial["status"], {"passed", "needs_review"})
        self.assertTrue(any(item["name"] == "claimable_amount_within_pool" for item in adversarial["scenarios"]))

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

    def test_migration_escrow_locks_then_unlocks_claim_outputs(self) -> None:
        service, _ = self.make_service()
        service.config = replace(service.config, migration_escrow_blocks=2)
        pq_wallet = Wallet("PQWallet")
        receiver = Wallet("Receiver")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-escrow")
        classical_address = service.seed_migration_source(
            classical_address=build_demo_classical_claim_address(classical_public_key),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=10,
            snapshot_ref="snapshot-escrow",
        )["classical_address"]
        preview = service.build_migration_claim_draft(
            destination_address=pq_wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-escrow",
            classical_public_key=classical_public_key,
        )
        claim = pq_wallet.create_migration_claim(
            service,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=build_demo_classical_claim_proof(
                classical_public_key,
                classical_claim_message_bytes(preview.migration_claim_payload()),
            ),
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-escrow",
            destination_address=preview.outputs[0].recipient,
            timestamp=preview.timestamp,
        )
        service.submit_transaction(claim)
        service.mine_pending_transactions(miner.create_address())

        locked = service.migration_claim_finality(classical_address)
        self.assertEqual(locked["state"], "escrow_locked")
        self.assertGreater(service.utxo_spendability_report(pq_wallet.addresses())["locked_total"], 0)
        with self.assertRaisesRegex(ValueError, "Insufficient funds"):
            pq_wallet.create_transaction(service, receiver.create_address(), amount=5, fee=1)

        service.mine_pending_transactions(miner.create_address())
        service.mine_pending_transactions(miner.create_address())
        self.assertEqual(service.migration_claim_finality(classical_address)["state"], "unlocked")
        spend = pq_wallet.create_transaction(service, receiver.create_address(), amount=5, fee=1)
        service.submit_transaction(spend)

    def test_resolved_fraud_freezes_migration_output_after_claim(self) -> None:
        service, _ = self.make_service()
        service.config = replace(service.config, migration_escrow_blocks=0)
        pq_wallet = Wallet("PQWallet")
        receiver = Wallet("Receiver")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-fraud-freeze")
        classical_address = service.seed_migration_source(
            classical_address=build_demo_classical_claim_address(classical_public_key),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=10,
            snapshot_ref="snapshot-fraud-freeze",
        )["classical_address"]
        preview = service.build_migration_claim_draft(
            destination_address=pq_wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-fraud-freeze",
            classical_public_key=classical_public_key,
        )
        claim = pq_wallet.create_migration_claim(
            service,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=build_demo_classical_claim_proof(
                classical_public_key,
                classical_claim_message_bytes(preview.migration_claim_payload()),
            ),
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-fraud-freeze",
            destination_address=preview.outputs[0].recipient,
            timestamp=preview.timestamp,
        )
        service.submit_transaction(claim)
        service.mine_pending_transactions(miner.create_address())
        dispute = service.open_migration_dispute(classical_address, reason="post-claim forged source")
        service.resolve_migration_dispute(
            dispute["dispute_id"],
            outcome="resolved_fraud",
            resolution_note="fraud proven",
        )

        self.assertEqual(service.migration_claim_finality(classical_address)["state"], "fraud_resolved_frozen")
        decision = service.signed_migration_fraud_recovery_decision(
            classical_address,
            outcome="resolved_fraud",
            recovery_action="freeze_and_revoke_source",
            note="fraud proven",
        )
        self.assertTrue(decision["artifact_hash"])
        with self.assertRaisesRegex(ValueError, "Insufficient funds"):
            pq_wallet.create_transaction(service, receiver.create_address(), amount=5, fee=1)

    def test_migration_conversion_caps_governance_and_registry_reports(self) -> None:
        service, _ = self.make_service()
        service.config = replace(
            service.config,
            migration_claim_per_address_cap=10,
            migration_conversion_ratio_numerator=1,
            migration_conversion_ratio_denominator=2,
            migration_epoch_mint_cap=15,
            migration_epoch_length_blocks=100,
        )
        pq_wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-capped")
        classical_address = service.seed_migration_source(
            classical_address=build_demo_classical_claim_address(classical_public_key),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=50,
            snapshot_ref="snapshot-capped",
        )["classical_address"]
        quote = service.migration_claim_quote(classical_address)
        self.assertEqual(quote["normalized_claim_amount"], 10)
        preview = service.build_migration_claim_draft(
            destination_address=pq_wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-capped",
            classical_public_key=classical_public_key,
        )
        self.assertEqual(preview.outputs[0].amount, 10)
        claim = pq_wallet.create_migration_claim(
            service,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=build_demo_classical_claim_proof(
                classical_public_key,
                classical_claim_message_bytes(preview.migration_claim_payload()),
            ),
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-capped",
            destination_address=preview.outputs[0].recipient,
            timestamp=preview.timestamp,
        )
        service.submit_transaction(claim)
        service.mine_pending_transactions(miner.create_address())

        self.assertEqual(service.migration_proof_registry_report()["entry_count"], 1)
        self.assertEqual(service.migration_conversion_guardrail_report()["epoch"]["minted"], 10)
        manifest = service.signed_migration_economics_governance_manifest()
        self.assertTrue(service.validate_migration_economics_governance_manifest(manifest)["valid"])
        tampered = json.loads(json.dumps(manifest))
        tampered["manifest"]["epoch_mint_cap"] = 999
        self.assertFalse(service.validate_migration_economics_governance_manifest(tampered)["valid"])
        self.assertEqual(service.migration_adversarial_economics_simulation_report()["status"], "pass")
        self.assertEqual(service.migration_economics_invariant_report()["status"], "pass")
        spec = service.migration_economics_specification()
        self.assertTrue(spec["spec_hash"])
        approval = service.sign_migration_governance_approval(
            action="economics_governance_change",
            artifact_hash=manifest["artifact_hash"],
            note="unit test approval",
        )
        quorum = service.migration_governance_quorum_report([approval])
        self.assertEqual(quorum["valid_approval_count"], 1)
        transition = service.migration_escrow_transition_artifact(
            classical_address,
            action="review_hold",
            reason="unit test transition",
        )
        self.assertTrue(transition["artifact_hash"])
        bundle = service.signed_project_audit_bundle()
        self.assertTrue(service.validate_project_audit_bundle(bundle)["valid"])
        tampered_bundle = json.loads(json.dumps(bundle))
        tampered_bundle["bundle"]["artifacts"]["migration_economics_spec"]["migration"]["escrow_blocks"] = 999
        self.assertFalse(service.validate_project_audit_bundle(tampered_bundle)["valid"])

    def test_migration_claim_preflight_exposes_signing_payloads(self) -> None:
        service, _ = self.make_service()
        pq_wallet = Wallet("PQWallet")
        service.create_genesis_block({"bootstrap": 1})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-preflight")
        classical_address = service.seed_migration_source(
            classical_address=build_demo_classical_claim_address(classical_public_key),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=12,
            snapshot_ref="snapshot-preflight",
        )["classical_address"]

        report = service.preflight_migration_claim(
            destination_address=pq_wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            snapshot_ref="snapshot-preflight",
            classical_public_key=classical_public_key,
        )

        self.assertTrue(report["ready"])
        self.assertTrue(report["classical_claim_message_hex"])
        self.assertEqual(report["draft_transaction"]["kind"], "migration_claim")

    def test_signed_migration_claim_receipt_after_mining(self) -> None:
        service, _ = self.make_service()
        pq_wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-receipt")
        classical_address = service.seed_migration_source(
            classical_address=build_demo_classical_claim_address(classical_public_key),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=13,
            snapshot_ref="snapshot-receipt",
        )["classical_address"]
        transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=pq_wallet.create_address(), amount=13)],
            kind="migration_claim",
            chain_id=service.config.chain_id,
            signature_scheme="classical_claim_demo_v1",
            metadata={
                "classical_address": classical_address,
                "classical_provider_id": "classical_claim_demo_v1",
                "source_network": "legacy-demo-ledger",
                "snapshot_ref": "snapshot-receipt",
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
        receipt = service.migration_claim_receipt(classical_address)

        self.assertEqual(receipt["claims"]["tx_id"], transaction.tx_id)
        self.assertEqual(receipt["claims"]["amount"], 13)
        self.assertEqual(receipt["envelope"]["purpose"], "migration_claim_receipt_v1")

    def test_post_finality_migration_fraud_case_is_signed_and_tamper_evident(self) -> None:
        service, _ = self.make_service()
        pq_wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-post-finality")
        classical_address = service.seed_migration_source(
            classical_address=build_demo_classical_claim_address(classical_public_key),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=17,
            snapshot_ref="snapshot-post-finality",
        )["classical_address"]
        transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=pq_wallet.create_address(), amount=17)],
            kind="migration_claim",
            chain_id=service.config.chain_id,
            signature_scheme="classical_claim_demo_v1",
            metadata={
                "classical_address": classical_address,
                "classical_provider_id": "classical_claim_demo_v1",
                "source_network": "legacy-demo-ledger",
                "snapshot_ref": "snapshot-post-finality",
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

        fraud_case = service.post_finality_migration_fraud_case(
            classical_address,
            evidence={"review": "conflicting source export", "source_export_hash": "abc123"},
        )
        validation = service.validate_post_finality_migration_fraud_case(fraud_case)

        self.assertTrue(validation["valid"])
        self.assertEqual(fraud_case["envelope"]["purpose"], "post_finality_migration_fraud_case_v1")
        self.assertEqual(service.store.migration_source(classical_address)["status"], "quarantined")
        self.assertIsNotNone(service.store.migration_claim(classical_address))
        self.assertEqual(fraud_case["claim"]["tx_id"], transaction.tx_id)

        tampered = json.loads(json.dumps(fraud_case))
        tampered["evidence"]["review"] = "mutated after signing"
        self.assertFalse(service.validate_post_finality_migration_fraud_case(tampered)["valid"])

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

    def test_quarantined_snapshot_blocks_migration_claim(self) -> None:
        service, _ = self.make_service()
        pq_wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-quarantine")
        classical_address = build_demo_classical_claim_address(classical_public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=9,
            snapshot_ref="snapshot-quarantine-001",
        )
        service.set_migration_snapshot_status(
            "snapshot-quarantine-001",
            status="quarantined",
            reason="operator review",
        )
        transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=pq_wallet.create_address(), amount=9)],
            kind="migration_claim",
            chain_id=service.config.chain_id,
            signature_scheme="classical_claim_demo_v1",
            metadata={
                "classical_address": classical_address,
                "classical_provider_id": "classical_claim_demo_v1",
                "source_network": "legacy-demo-ledger",
                "snapshot_ref": "snapshot-quarantine-001",
                "source_address": classical_address,
                "source_address_format": "demo_claim_address",
                "classical_public_key": classical_public_key,
            },
        )
        transaction.metadata["classical_signature"] = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(transaction.migration_claim_payload()),
        )
        transaction.finalize()

        with self.assertRaisesRegex(ValueError, "source is blocked"):
            service.submit_transaction(transaction)

    def test_migration_audit_report_flags_active_source_on_quarantined_snapshot(self) -> None:
        service, _ = self.make_service()
        classical_public_key = build_demo_classical_claim_public_key("legacy-user-audit")
        classical_address = build_demo_classical_claim_address(classical_public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=4,
            snapshot_ref="snapshot-audit-001",
        )
        service.set_migration_snapshot_status(
            "snapshot-audit-001",
            status="quarantined",
            reason="audit test",
            cascade_sources=False,
        )

        report = service.migration_audit_report(source_network="legacy-demo-ledger")

        self.assertEqual(report["summary_by_snapshot_status"]["quarantined"], 1)
        self.assertTrue(any(item["kind"] == "active_source_on_blocked_snapshot" for item in report["anomalies"]))

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

