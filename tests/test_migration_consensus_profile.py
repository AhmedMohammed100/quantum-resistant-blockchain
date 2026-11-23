from __future__ import annotations

import copy
import unittest

from qr_blockchain.migration_consensus import (
    PROFILE_SCHEMA,
    PROFILE_VERSION,
    migration_consensus_profile_hash,
    validate_migration_consensus_profile,
    verify_migration_consensus_profile,
)
from qr_blockchain.snapshot import MigrationSnapshotBundle, MigrationSnapshotEntry


def profile() -> dict[str, object]:
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
    snapshot = {
        **bundle,
        "status": "active",
        "status_reason": "",
        "reviewed_at": 0.0,
    }
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
        "snapshots": [snapshot],
    }


class MigrationConsensusProfileTests(unittest.TestCase):
    def test_normalizes_order_for_reproducible_hash(self) -> None:
        first = profile()
        second = profile()
        second["policy"] = dict(second["policy"])
        second["policy"]["allowed_classical_providers"] = ["provider-a"]
        second["snapshots"] = list(reversed(second["snapshots"]))
        self.assertEqual(
            migration_consensus_profile_hash(first),
            migration_consensus_profile_hash(second),
        )

    def test_verify_accepts_matching_chain_and_artifact_hash(self) -> None:
        value = profile()
        normalized = verify_migration_consensus_profile(
            value,
            expected_chain_id="qbc-testnet",
            expected_profile_hash=migration_consensus_profile_hash(value),
        )
        self.assertEqual(normalized["chain_id"], "qbc-testnet")

    def test_rejects_missing_and_unknown_policy_fields(self) -> None:
        value = profile()
        del value["policy"]["escrow_blocks"]
        with self.assertRaisesRegex(ValueError, "fields mismatch"):
            validate_migration_consensus_profile(value)
        value = profile()
        value["policy"]["operator_override"] = True
        with self.assertRaisesRegex(ValueError, "fields mismatch"):
            validate_migration_consensus_profile(value)

    def test_rejects_invalid_conversion_window_and_hash_encoding(self) -> None:
        value = profile()
        value["policy"]["conversion_denominator"] = 0
        with self.assertRaisesRegex(ValueError, "denominator"):
            validate_migration_consensus_profile(value)
        value = profile()
        value["snapshots"][0]["entries_root"] = "NOT-A-HASH"
        with self.assertRaisesRegex(ValueError, "manifest_hash"):
            validate_migration_consensus_profile(value)

    def test_rejects_duplicate_snapshots_and_addresses(self) -> None:
        value = profile()
        value["snapshots"].append(copy.deepcopy(value["snapshots"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate classical address"):
            validate_migration_consensus_profile(value)
        value = profile()
        extra = copy.deepcopy(value["snapshots"][0]["entries"][0])
        extra["classical_address"] = "source-b"
        value["snapshots"][0]["entries"].append(extra)
        with self.assertRaisesRegex(ValueError, "manifest_hash"):
            validate_migration_consensus_profile(value)

    def test_rejects_snapshot_status_without_reason(self) -> None:
        value = profile()
        value["snapshots"][0]["status"] = "quarantined"
        with self.assertRaisesRegex(ValueError, "status_reason"):
            validate_migration_consensus_profile(value)

    def test_rejects_chain_and_profile_commitment_mismatch(self) -> None:
        value = profile()
        with self.assertRaisesRegex(ValueError, "chain_id"):
            verify_migration_consensus_profile(
                value,
                expected_chain_id="wrong-chain",
                expected_profile_hash=migration_consensus_profile_hash(value),
            )
        with self.assertRaisesRegex(ValueError, "hash"):
            verify_migration_consensus_profile(
                value,
                expected_chain_id="qbc-testnet",
                expected_profile_hash="0" * 64,
            )


if __name__ == "__main__":
    unittest.main()
