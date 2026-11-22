from __future__ import annotations

import copy
import unittest

from qr_blockchain.migration_consensus import (
    migration_consensus_profile_hash,
    validate_migration_consensus_profile,
    verify_migration_consensus_profile,
)


def profile() -> dict[str, object]:
    return {
        "profile_schema": "qbc-migration-consensus-profile",
        "profile_version": 1,
        "chain_id": "qbc-testnet",
        "activation_height": 100,
        "policy": {
            "allowed_providers": ["provider-b", "provider-a"],
            "claim_start_height": 100,
            "claim_end_height": 1000,
            "conversion_denominator": 2,
            "conversion_numerator": 1,
            "conversion_policy": "ratio",
            "dispute_window_blocks": 20,
            "epoch_length_blocks": 100,
            "epoch_mint_cap": 5000,
            "escrow_blocks": 30,
            "migration_pool_cap": 100000,
            "per_address_cap": 2000,
        },
        "snapshots": [
            {
                "source_network": "legacy-b",
                "snapshot_ref": "snapshot-b",
                "manifest_hash": "b" * 64,
                "entries_root": "d" * 64,
            },
            {
                "source_network": "legacy-a",
                "snapshot_ref": "snapshot-a",
                "manifest_hash": "a" * 64,
                "entries_root": "c" * 64,
            },
        ],
    }


class MigrationConsensusProfileTests(unittest.TestCase):
    def test_normalizes_order_for_reproducible_hash(self) -> None:
        first = profile()
        second = profile()
        second["policy"] = dict(second["policy"])
        second["policy"]["allowed_providers"] = ["provider-a", "provider-b"]
        second["snapshots"] = list(reversed(second["snapshots"]))
        self.assertEqual(
            migration_consensus_profile_hash(first),
            migration_consensus_profile_hash(second),
        )

    def test_verify_accepts_matching_chain_hash_and_snapshot_roots(self) -> None:
        value = profile()
        normalized = verify_migration_consensus_profile(
            value,
            expected_chain_id="qbc-testnet",
            expected_profile_hash=migration_consensus_profile_hash(value),
            local_snapshots=value["snapshots"],
        )
        self.assertEqual(normalized["chain_id"], "qbc-testnet")

    def test_rejects_policy_field_omission_or_unknown_field(self) -> None:
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
        with self.assertRaisesRegex(ValueError, "lowercase hexadecimal"):
            validate_migration_consensus_profile(value)

    def test_rejects_duplicate_snapshots_and_mismatched_local_state(self) -> None:
        value = profile()
        value["snapshots"].append(copy.deepcopy(value["snapshots"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate snapshot"):
            validate_migration_consensus_profile(value)
        value = profile()
        local = copy.deepcopy(value["snapshots"])
        local[0]["entries_root"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "do not match"):
            verify_migration_consensus_profile(
                value,
                expected_chain_id="qbc-testnet",
                expected_profile_hash=migration_consensus_profile_hash(value),
                local_snapshots=local,
            )

    def test_rejects_chain_and_profile_commitment_mismatch(self) -> None:
        value = profile()
        with self.assertRaisesRegex(ValueError, "chain_id"):
            verify_migration_consensus_profile(
                value,
                expected_chain_id="wrong-chain",
                expected_profile_hash=migration_consensus_profile_hash(value),
                local_snapshots=value["snapshots"],
            )
        with self.assertRaisesRegex(ValueError, "hash"):
            verify_migration_consensus_profile(
                value,
                expected_chain_id="qbc-testnet",
                expected_profile_hash="0" * 64,
                local_snapshots=value["snapshots"],
            )


if __name__ == "__main__":
    unittest.main()
