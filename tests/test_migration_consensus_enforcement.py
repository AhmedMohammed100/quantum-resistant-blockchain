from __future__ import annotations

import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from qr_blockchain import NodeConfig, NodeService
from qr_blockchain.migration_consensus import (
    PROFILE_SCHEMA,
    PROFILE_VERSION,
    migration_consensus_profile_hash,
)
from qr_blockchain.models import Transaction, TxOutput
from qr_blockchain.snapshot import MigrationSnapshotBundle, MigrationSnapshotEntry


def profile_payload() -> dict[str, object]:
    bundle = MigrationSnapshotBundle(
        source_network="legacy-a",
        snapshot_ref="snapshot-a",
        generated_at=100.0,
        entries=(
            MigrationSnapshotEntry(
                classical_address="source-a",
                provider_id="provider-a",
                amount=500,
                source_address="source-a",
                source_address_format="hex",
            ),
        ),
    ).to_dict()
    return {
        "profile_schema": PROFILE_SCHEMA,
        "profile_version": PROFILE_VERSION,
        "chain_id": "qbc-testnet",
        "activation_height": 1,
        "policy": {
            "allowed_classical_providers": ["provider-a"],
            "allowed_signature_providers": ["mldsa65_oqs_v1"],
            "claim_start_height": 1,
            "claim_end_height": 1000,
            "conversion_denominator": 2,
            "conversion_numerator": 1,
            "conversion_policy": "ratio",
            "dispute_window_blocks": 20,
            "dual_control_start_height": 0,
            "dual_control_end_height": 0,
            "epoch_length_blocks": 100,
            "epoch_mint_cap": 5000,
            "escrow_blocks": 30,
            "migration_pool_cap": 100000,
            "per_address_cap": 2000,
        },
        "snapshots": [
            {
                **bundle,
                "status": "active",
                "status_reason": "",
                "reviewed_at": 0.0,
            }
        ],
    }


class _AcceptingClassicalVerifier:
    def address_from_public_key(self, _public_key: object) -> str:
        return "source-a"

    def verify_claim(self, _message: bytes, _proof: object, _public_key: object) -> bool:
        return True

    def verify_source_address_ownership(self, _public_key: object, **_kwargs: object) -> bool:
        return True


class MigrationConsensusEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path("test_runtime") / self._testMethodName
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def make_service(self, *, paused: bool = False) -> NodeService:
        profile = profile_payload()
        profile_path = self.root / "migration-profile.json"
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        return NodeService(
            NodeConfig(
                db_path=self.root / "chain.db",
                wallet_state_db_path=self.root / "wallet.db",
                chain_id="qbc-testnet",
                migration_allowed_classical_providers=("provider-a",),
                allowed_signature_providers=("mldsa65_oqs_v1",),
                migration_claim_start_height=1,
                migration_claim_end_height=1000,
                migration_conversion_policy="ratio",
                migration_conversion_ratio_numerator=1,
                migration_conversion_ratio_denominator=2,
                migration_dispute_window_blocks=20,
                migration_dual_control_start_height=0,
                migration_dual_control_end_height=0,
                migration_epoch_length_blocks=100,
                migration_epoch_mint_cap=5000,
                migration_escrow_blocks=30,
                migration_pool_cap=100000,
                migration_claim_per_address_cap=2000,
                migration_emergency_pause=paused,
                migration_consensus_profile_path=profile_path,
                migration_consensus_profile_hash=migration_consensus_profile_hash(profile),
            )
        )

    def test_loaded_profile_is_the_source_of_consensus_registry_data(self) -> None:
        service = self.make_service()
        source, snapshot = service._migration_profile_source("source-a") or ({}, {})
        self.assertEqual(source["amount"], 500)
        self.assertEqual(source["source_network"], "legacy-a")
        self.assertEqual(snapshot["snapshot_ref"], "snapshot-a")
        self.assertIsNone(service.store.migration_source("source-a"))

    def test_profile_blocks_policy_drift_at_startup(self) -> None:
        profile = profile_payload()
        profile_path = self.root / "migration-profile.json"
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not match the pinned consensus profile"):
            NodeService(
                NodeConfig(
                    db_path=self.root / "chain.db",
                    wallet_state_db_path=self.root / "wallet.db",
                    chain_id="qbc-testnet",
                    migration_pool_cap=100001,
                    migration_consensus_profile_path=profile_path,
                    migration_consensus_profile_hash=migration_consensus_profile_hash(profile),
                )
            )

    def test_local_pause_does_not_change_block_validity_but_blocks_admission(self) -> None:
        service = self.make_service(paused=True)
        transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient="pq-destination", amount=250)],
            kind="migration_claim",
            chain_id="qbc-testnet",
            metadata={
                "classical_address": "source-a",
                "classical_provider_id": "provider-a",
                "source_network": "legacy-a",
                "snapshot_ref": "snapshot-a",
                "source_address": "source-a",
                "source_address_format": "hex",
                "classical_public_key": {},
                "classical_signature": {},
            },
        )
        with patch("qr_blockchain.service.get_classical_claim_verifier", return_value=_AcceptingClassicalVerifier()), patch.object(
            service,
            "_validate_destination_attestation",
            return_value=None,
        ):
            with patch.object(service.store, "migration_source", side_effect=AssertionError("local DB used")):
                service._validate_migration_claim(
                    transaction,
                    effective_height=1,
                    claimed_classical_addresses=set(),
                )
            with self.assertRaisesRegex(ValueError, "local admission policy"):
                service._validate_migration_claim(transaction, effective_height=1)

    def test_block_spendability_ignores_local_dispute_and_source_overlays(self) -> None:
        service = self.make_service()
        local_source = {
            "status": "revoked",
            "classical_address": "source-a",
        }
        with patch.object(
            service.store,
            "list_migration_disputes",
            return_value=[{"status": "resolved_fraud"}],
        ), patch.object(service.store, "migration_source", return_value=local_source):
            consensus = service._migration_output_finality_status(
                "source-a",
                origin_height=1,
                current_height=100,
                consensus_context=True,
            )
            local_report = service._migration_output_finality_status(
                "source-a",
                origin_height=1,
                current_height=100,
            )
        self.assertTrue(consensus["spendable"])
        self.assertFalse(local_report["spendable"])

    def test_public_mode_rejects_migration_claims_without_pinned_profile(self) -> None:
        service = object.__new__(NodeService)
        service.config = NodeConfig(deployment_mode="public-testnet")
        service.migration_consensus_profile = None
        transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient="pq-destination", amount=1)],
            kind="migration_claim",
        )
        with self.assertRaisesRegex(ValueError, "require a pinned consensus profile"):
            service._validate_migration_claim(
                transaction,
                effective_height=1,
                claimed_classical_addresses=set(),
            )


if __name__ == "__main__":
    unittest.main()
