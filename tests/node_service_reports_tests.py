"""Focused reports tests for NodeService.

Imported by test_node_service.py to preserve the existing unittest entry point.
"""
from tests.node_service_test_support import *
from tests.node_service_test_support import _connect_test_db, _secp256k1_sign


class NodeServiceReportTests(NodeServiceTestSupport):
    def test_protocol_manifest_is_reported(self) -> None:
        service, _ = self.make_service()

        manifest = service.protocol_manifest()

        self.assertEqual(manifest["chain_id"], service.config.chain_id)
        self.assertEqual(manifest["native_currency"]["symbol"], "QBC")
        self.assertTrue(manifest["protocol_manifest_hash"])

    def test_migration_readiness_report_exposes_integrity_gates(self) -> None:
        service, _ = self.make_service()

        report = service.migration_readiness_report()

        self.assertIn(report["migration_layer_status"], {"blocked", "operational"})
        self.assertIn("integrity_summary", report)
        self.assertTrue(any(check["name"] == "pq_provider_available" for check in report["checks"]))
        self.assertTrue(any(check["name"] == "governance_window_configured" for check in report["checks"]))

    def test_crypto_hardening_report_tracks_pinned_oqs_runtime(self) -> None:
        service, _ = self.make_service()

        report = service.crypto_runtime_hardening_report()

        self.assertEqual(report["pinned_runtime"]["mechanism"], "ML-DSA-65")
        self.assertTrue(any(check["name"] == "liboqs_python_pin_matches" for check in report["checks"]))
        self.assertIn(report["hardening_status"], {"ready", "needs_review"})

    def test_signature_strategy_and_performance_reports_favor_fast_lattice(self) -> None:
        service, _ = self.make_service()

        strategy = service.signature_strategy_report()
        performance = service.signature_performance_report()

        self.assertEqual(strategy["profile"], service.config.preferred_signature_profile)
        self.assertTrue(any(item["lane"] == "fast_lattice_default" for item in strategy["ranked_providers"]))
        self.assertIn("results", performance)
        self.assertEqual(performance["target_sign_ms"], service.config.target_signature_sign_ms)

    def test_signer_consensus_native_and_parallel_reports(self) -> None:
        service, _ = self.make_service()

        separation = service.signer_consensus_separation_report()
        native = service.native_crypto_runtime_boundary_report()
        parallel = service.parallel_verification_report()
        state_model = service.transaction_state_model_report()
        validator_network = service.validator_networking_readiness_report()
        migration_finality = service.migration_finality_fraud_report()
        adversarial_performance = service.adversarial_performance_readiness_report()

        self.assertEqual(separation["architecture_status"], "separated_boundary")
        self.assertEqual(separation["module_boundaries"]["wallet_signer"], "qr_blockchain.signer.LocalWalletSigner")
        self.assertEqual(native["current_python_role"], "orchestration_policy_api_tests")
        self.assertIn("targets", native)
        self.assertEqual(parallel["parallelism_status"], "native_worker_pool_enabled_for_native_provider")
        self.assertIn("batch_verification_note", parallel)
        self.assertEqual(state_model["state_model_status"], "utxo_deterministic_v1")
        self.assertIn(
            validator_network["validator_networking_status"],
            {"authenticated_gossip_with_diversity_checks", "authenticated_gossip_needs_peer_diversity"},
        )
        self.assertEqual(migration_finality["migration_finality_status"], "challenge_lifecycle_with_claim_unlock_rules")
        self.assertIn("parallelization_policy", adversarial_performance)

    def test_resource_consensus_release_and_incident_reports(self) -> None:
        service, _ = self.make_service()

        resource_policy = service.transaction_resource_policy_report()
        consensus = service.consensus_economics_report()
        release = service.release_provenance_manifest()
        incident = service.operator_incident_runbook()

        self.assertEqual(resource_policy["limits"]["max_signature_payload_bytes"], service.config.max_signature_payload_bytes)
        self.assertIn("known_gaps", consensus)
        self.assertTrue(release["release_manifest_hash"])
        self.assertEqual(incident["migration_pause"]["env"], "QR_CHAIN_MIGRATION_EMERGENCY_PAUSE=true")

    def test_migration_batch_conversion_and_attestation_reports(self) -> None:
        service, _ = self.make_service()
        service.create_genesis_block({"bootstrap": 1})
        first = build_demo_classical_claim_address(build_demo_classical_claim_public_key("batch-one"))
        second = build_demo_classical_claim_address(build_demo_classical_claim_public_key("batch-two"))
        service.seed_migration_source(
            classical_address=first,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=5,
            snapshot_ref="batch-snapshot",
        )
        service.seed_migration_source(
            classical_address=second,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=7,
            snapshot_ref="batch-snapshot",
        )
        service.set_migration_source_status(second, status="quarantined", reason="review")

        batch = service.migration_claim_batch_plan(source_network="legacy-demo-ledger")
        conversion = service.migration_conversion_risk_report()
        attestations = service.migration_snapshot_attestation_readiness()

        self.assertEqual(batch["planned_claim_count"], 1)
        self.assertEqual(batch["blocked_claim_count"], 1)
        self.assertEqual(conversion["by_network"]["legacy-demo-ledger"]["source_count"], 2)
        self.assertEqual(attestations["snapshot_count"], 1)

    def test_protocol_preflight_privacy_and_migration_proof_reports(self) -> None:
        service, _ = self.make_service()
        service.create_genesis_block({"bootstrap": 1})
        public_key = build_demo_classical_claim_public_key("proof-coverage")
        classical_address = build_demo_classical_claim_address(public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=4,
            snapshot_ref="proof-snapshot",
        )

        conformance = service.protocol_conformance_report()
        dispute = service.migration_dispute_packet(classical_address)
        proof_coverage = service.migration_source_proof_coverage_report()
        preflight = service.node_launch_preflight_report()
        redaction = service.privacy_redaction_policy_report()

        self.assertEqual(conformance["conformance_status"], "conformant")
        self.assertTrue(dispute["packet_hash"])
        self.assertEqual(proof_coverage["source_count"], 1)
        self.assertIn(preflight["preflight_status"], {"ready", "blocked"})
        self.assertIn("secret_key_hex", redaction["sensitive_fields"])

    def test_hardening_audit_report_collects_blockers_and_hashes_report(self) -> None:
        service, _ = self.make_service()

        audit = service.hardening_audit_report()

        self.assertIn(audit["audit_status"], {"pass", "warning", "blocked"})
        self.assertTrue(audit["audit_hash"])
        self.assertIn("security_invariants", audit["reports"])
        self.assertIn("production_configuration", audit["reports"])
        self.assertIn("node_preflight", audit["reports"])

    def test_hardening_stage_reports_cover_next_ten_stages(self) -> None:
        service, _ = self.make_service()

        report = service.hardening_stage_reports()

        self.assertEqual(report["stage_count"], 10)
        self.assertTrue(report["hardening_stage_report_hash"])
        stage_names = {stage["name"] for stage in report["stages"]}
        self.assertIn("ci_quality_gates", stage_names)
        self.assertIn("structured_security_policy_profiles", stage_names)
        self.assertIn("external_audit_readiness_package", stage_names)

    def test_hardening_stage_7_to_10_artifacts_validate_and_detect_tampering(self) -> None:
        service, _ = self.make_service()

        native = service.signed_native_crypto_release_provenance()
        self.assertTrue(service.validate_native_crypto_release_provenance(native)["valid"])
        tampered_native = json.loads(json.dumps(native))
        tampered_native["report"]["pinned_runtime"] = "mutated-runtime"
        self.assertFalse(service.validate_native_crypto_release_provenance(tampered_native)["valid"])

        soak = service.build_soak_result_artifact(
            {
                "scenario": "private-testnet-soak",
                "started_at": 1,
                "duration_seconds": 24 * 60 * 60,
                "node_count": 3,
                "passed": True,
                "failure_summary": "",
                "metrics": {"invalid_frames": 0, "fork_recoveries": 2},
            }
        )
        self.assertTrue(service.validate_soak_result_artifact(soak)["valid"])
        tampered_soak = json.loads(json.dumps(soak))
        tampered_soak["result"]["passed"] = False
        self.assertFalse(service.validate_soak_result_artifact(tampered_soak)["valid"])

        recovery = service.database_recovery_manifest()
        self.assertTrue(service.validate_database_recovery_manifest(recovery)["valid"])
        tampered_recovery = json.loads(json.dumps(recovery))
        tampered_recovery["durability_status"] = "mutated"
        self.assertFalse(service.validate_database_recovery_manifest(tampered_recovery)["valid"])

        audit_package = service.signed_external_audit_readiness_package()
        self.assertTrue(service.validate_external_audit_readiness_package(audit_package)["valid"])
        tampered_audit = json.loads(json.dumps(audit_package))
        tampered_audit["package"]["scope"].append("unreviewed extra scope")
        self.assertFalse(service.validate_external_audit_readiness_package(tampered_audit)["valid"])

    def test_signed_consensus_upgrade_manifest_validates_and_detects_tampering(self) -> None:
        service, _ = self.make_service()

        artifact = service.signed_consensus_upgrade_manifest()
        valid = service.validate_consensus_upgrade_manifest_artifact(artifact)

        self.assertTrue(valid["valid"], valid)
        self.assertEqual(
            valid["upgrade_manifest_hash"],
            artifact["manifest"]["upgrade_manifest_hash"],
        )

        tampered = json.loads(json.dumps(artifact))
        tampered["manifest"]["min_fee_per_kib"] = int(tampered["manifest"]["min_fee_per_kib"]) + 1
        invalid = service.validate_consensus_upgrade_manifest_artifact(tampered)

        self.assertFalse(invalid["valid"])
        self.assertFalse(
            next(check for check in invalid["checks"] if check["name"] == "manifest_hash_matches")["passed"]
        )

    def test_network_transport_and_backup_reports(self) -> None:
        service, db_path = self.make_service()
        service.create_genesis_block({"bootstrap": 1})
        service.register_peer("http://peer-a:8080")

        transport = service.network_transport_readiness_report()
        backup = service.state_backup_manifest()

        self.assertEqual(transport["peers"]["http_peer_count"], 1)
        self.assertTrue(backup["backup_manifest_hash"])
        self.assertTrue(backup["files"]["chain_db"]["exists"])
        self.assertEqual(backup["files"]["chain_db"]["path"], str(db_path))

    def test_production_configuration_report_blocks_unsafe_public_defaults(self) -> None:
        service, _ = self.make_service()
        service.config = replace(
            service.config,
            deployment_mode="production",
            host="0.0.0.0",
            advertised_url="http://node.example:8080",
            wallet_custody_mode="plaintext",
            default_signature_provider="xmss_merkle_lamport_v1",
            preferred_signature_providers=("xmss_merkle_lamport_v1",),
            allowed_signature_providers=(),
            migration_allowed_classical_providers=("classical_claim_demo_v1",),
            migration_require_snapshot_signatures=False,
            migration_trusted_snapshot_signers=(),
            require_peer_allowlist=False,
        )

        report = service.production_configuration_report()

        self.assertEqual(report["configuration_status"], "blocked")
        blocker_names = {item["name"] for item in report["blockers"]}
        self.assertIn("wallet_custody_not_plaintext", blocker_names)
        self.assertIn("demo_signature_providers_disabled_for_production", blocker_names)
        self.assertIn("default_signature_provider_allowed", blocker_names)
        self.assertIn("snapshot_signatures_required_for_production_migration", blocker_names)
        self.assertIn("peer_allowlist_required_on_public_bind", blocker_names)
        with self.assertRaisesRegex(ValueError, "Security policy profile is blocked"):
            service.enforce_security_policy_profile()

    def test_production_configuration_report_accepts_hardened_public_config(self) -> None:
        service, _ = self.make_service()
        service.config = replace(
            service.config,
            deployment_mode="production",
            host="0.0.0.0",
            advertised_url="https://node.example",
            peers=("https://peer-a.example",),
            wallet_custody_mode="windows_dpapi",
            default_signature_provider="mldsa65_oqs_v1",
            preferred_signature_providers=("mldsa65_oqs_v1",),
            allowed_signature_providers=("mldsa65_oqs_v1",),
            migration_allowed_classical_providers=(
                "ecdsa_secp256k1_migration_v1",
                "rsa_pkcs1v15_sha256_migration_v1",
            ),
            migration_require_snapshot_signatures=True,
            migration_trusted_snapshot_signers=("qbc1snapshot",),
            require_peer_allowlist=True,
            peer_allowlist=("peer-a",),
            coinbase_maturity_blocks=12,
            state_root_activation_height=0,
        )

        report = service.production_configuration_report()

        self.assertEqual(report["configuration_status"], "ready")
        self.assertFalse(report["blockers"])
        self.assertEqual(service.enforce_security_policy_profile()["configuration_status"], "ready")

        service.config = replace(
            service.config,
            allowed_signature_providers=("sphincsplus_v1",),
        )
        mismatched = service.production_configuration_report()
        self.assertEqual(mismatched["configuration_status"], "blocked")
        self.assertIn(
            "default_signature_provider_allowed",
            {item["name"] for item in mismatched["blockers"]},
        )

    def test_database_durability_report_checks_wal_and_integrity(self) -> None:
        service, _ = self.make_service()

        report = service.database_durability_report()

        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["databases"]["chain"]["journal_mode"], "wal")
        self.assertEqual(report["databases"]["wallet"]["journal_mode"], "wal")
        self.assertEqual(report["databases"]["chain"]["integrity_check"], "ok")
        self.assertEqual(report["databases"]["wallet"]["integrity_check"], "ok")

    def test_migration_governance_report_tracks_disputes_and_pause(self) -> None:
        service, _ = self.make_service()
        public_key = build_demo_classical_claim_public_key("governance-user")
        classical_address = build_demo_classical_claim_address(public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=7,
            snapshot_ref="governance-snapshot",
        )
        service.set_migration_source_status(classical_address, status="quarantined", reason="operator dispute")

        report = service.migration_governance_report()

        self.assertEqual(report["disputes"]["blocked_source_count"], 1)
        self.assertEqual(report["policy"]["dispute_window_blocks"], service.config.migration_dispute_window_blocks)

    def test_migration_integrity_report_flags_missing_snapshot(self) -> None:
        service, _ = self.make_service()
        public_key = build_demo_classical_claim_public_key("integrity-user")
        classical_address = build_demo_classical_claim_address(public_key)
        service.store.add_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=5,
            snapshot_ref="missing-snapshot",
            source_address=classical_address,
            source_address_format="demo_claim_address",
            reviewed_at=1.0,
            added_at=1.0,
        )

        report = service.migration_integrity_report(source_network="legacy-demo-ledger")

        self.assertEqual(report["summary"]["critical_anomaly_count"], 1)
        self.assertEqual(report["anomalies"][0]["type"], "missing_snapshot_record")

