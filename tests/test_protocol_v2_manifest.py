import copy
import unittest

from qr_blockchain.portable_encoding import hash_canonical_v1
from qr_blockchain.protocol_v2 import V2SchemaError
from qr_blockchain.protocol_v2_manifest import validate_v2_network_manifest


def fixture_manifest():
    manifest = {
        "manifest_version": 1,
        "chain_id": "qbc-v2-fixture",
        "genesis_hash": "a" * 64,
        "encoding_profile": "qbc-cjson-v1",
        "transaction_schema_version": 2,
        "block_schema_version": 2,
        "activation": {"mode": "genesis"},
        "transaction_kinds": ["transfer"],
        "signature_providers": [{
            "provider_id": "fixture_pq_v1", "provider_version": "1.0.0",
            "signing_mode": "canonical-bytes", "public_key_schema": "fixture-key-v1",
            "signature_schema": "fixture-signature-v1", "max_public_key_bytes": 4096,
            "max_signature_bytes": 4096,
        }],
        "consensus_profile": {"profile_id": "fixture-pow", "profile_version": "1",
                              "parameters": {"fixture": "consensus-parameters"}},
        "limits": {"max_transaction_bytes": 1 << 20, "max_block_bytes": 4 << 20,
                   "max_metadata_bytes": 16 << 10, "max_inputs": 256, "max_outputs": 256,
                   "max_transactions_per_block": 4096},
    }
    manifest["manifest_digest"] = hash_canonical_v1("network-manifest-v2", manifest)
    return manifest


def validate(manifest):
    return validate_v2_network_manifest(
        manifest, expected_chain_id="qbc-v2-fixture", expected_genesis_hash="a" * 64,
        supported_kinds={"transfer"},
        provider_profiles={("fixture_pq_v1", "1.0.0"): lambda _: None},
        consensus_profiles={("fixture-pow", "1"): lambda _: None},
    )


class ProtocolV2ManifestTests(unittest.TestCase):
    def test_fixture_manifest_matches_deterministic_digest(self):
        manifest = fixture_manifest()
        self.assertEqual(validate(manifest), manifest["manifest_digest"])
        self.assertEqual(manifest["manifest_digest"], "dcaee8df5e114551a305bf44b2a6ee21f53f439faca7f0f05502a3955311649c")

    def test_rejects_unknown_missing_and_wrong_version_fields(self):
        manifest = fixture_manifest(); manifest["extra"] = "not allowed"
        with self.assertRaises(V2SchemaError): validate(manifest)
        manifest = fixture_manifest(); del manifest["genesis_hash"]
        with self.assertRaises(V2SchemaError): validate(manifest)
        manifest = fixture_manifest(); manifest["transaction_schema_version"] = True
        with self.assertRaises(V2SchemaError): validate(manifest)

    def test_rejects_network_mismatch_activation_and_bad_digest(self):
        manifest = fixture_manifest()
        with self.assertRaisesRegex(V2SchemaError, "chain_id"):
            validate_v2_network_manifest(manifest, expected_chain_id="another-net",
                expected_genesis_hash="a" * 64, supported_kinds={"transfer"},
                provider_profiles={("fixture_pq_v1", "1.0.0"): lambda _: None},
                consensus_profiles={("fixture-pow", "1"): lambda _: None})
        manifest = fixture_manifest(); manifest["activation"]["mode"] = "height"
        manifest["manifest_digest"] = hash_canonical_v1("network-manifest-v2", {k: v for k, v in manifest.items() if k != "manifest_digest"})
        with self.assertRaisesRegex(V2SchemaError, "genesis"):
            validate(manifest)
        manifest = fixture_manifest(); manifest["manifest_digest"] = "0" * 64
        with self.assertRaisesRegex(V2SchemaError, "manifest_digest"):
            validate(manifest)

    def test_rejects_unsupported_or_unsorted_profiles_and_kinds(self):
        manifest = fixture_manifest(); manifest["transaction_kinds"] = ["reward", "transfer"]
        manifest["manifest_digest"] = hash_canonical_v1("network-manifest-v2", {k: v for k, v in manifest.items() if k != "manifest_digest"})
        with self.assertRaisesRegex(V2SchemaError, "no local schema"):
            validate(manifest)
        manifest = fixture_manifest()
        with self.assertRaisesRegex(V2SchemaError, "consensus profile"):
            validate_v2_network_manifest(manifest, expected_chain_id="qbc-v2-fixture",
                expected_genesis_hash="a" * 64, supported_kinds={"transfer"},
                provider_profiles={("fixture_pq_v1", "1.0.0"): lambda _: None}, consensus_profiles={})
        manifest = fixture_manifest(); manifest["signature_providers"][0]["provider_version"] = "2.0.0"
        manifest["manifest_digest"] = hash_canonical_v1("network-manifest-v2", {k: v for k, v in manifest.items() if k != "manifest_digest"})
        with self.assertRaisesRegex(V2SchemaError, "provider profile"):
            validate(manifest)

    def test_rejects_duplicate_entries_and_limits_beyond_protocol_ceiling(self):
        manifest = fixture_manifest(); manifest["transaction_kinds"] = ["transfer", "transfer"]
        manifest["manifest_digest"] = hash_canonical_v1("network-manifest-v2", {k: v for k, v in manifest.items() if k != "manifest_digest"})
        with self.assertRaisesRegex(V2SchemaError, "sorted and unique"):
            validate(manifest)
        manifest = fixture_manifest(); manifest["limits"]["max_block_bytes"] = (4 << 20) + 1
        manifest["manifest_digest"] = hash_canonical_v1("network-manifest-v2", {k: v for k, v in manifest.items() if k != "manifest_digest"})
        with self.assertRaisesRegex(V2SchemaError, "normative v2 ceiling"):
            validate(manifest)

    def test_profile_callbacks_receive_copies(self):
        manifest = fixture_manifest(); before = copy.deepcopy(manifest)
        def mutate(profile): profile["mutation"] = True
        validate_v2_network_manifest(manifest, expected_chain_id="qbc-v2-fixture",
            expected_genesis_hash="a" * 64, supported_kinds={"transfer"},
            provider_profiles={("fixture_pq_v1", "1.0.0"): lambda _: None},
            consensus_profiles={("fixture-pow", "1"): mutate})
        self.assertEqual(manifest, before)

    def test_independent_validators_converge_and_reject_network_mismatch(self):
        manifest = fixture_manifest()
        validators = [
            {
                "expected_chain_id": "qbc-v2-fixture",
                "expected_genesis_hash": "a" * 64,
                "supported_kinds": {"transfer"},
                "provider_profiles": {("fixture_pq_v1", "1.0.0"): lambda _: None},
                "consensus_profiles": {("fixture-pow", "1"): lambda _: None},
            }
            for _ in range(3)
        ]
        digests = [validate_v2_network_manifest(manifest, **config) for config in validators]
        self.assertEqual(digests, [manifest["manifest_digest"]] * len(validators))

        validators[2]["expected_genesis_hash"] = "b" * 64
        with self.assertRaisesRegex(V2SchemaError, "genesis_hash"):
            validate_v2_network_manifest(manifest, **validators[2])


if __name__ == "__main__":
    unittest.main()
