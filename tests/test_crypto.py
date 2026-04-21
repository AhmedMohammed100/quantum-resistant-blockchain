from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import patch

from qr_blockchain.crypto import (
    get_signature_provider,
    get_signature_verifier,
    list_signature_providers,
    list_signature_provider_statuses,
)


class SignatureProviderRegistryTests(unittest.TestCase):
    def test_lists_available_and_planned_signature_providers(self) -> None:
        providers = {metadata.provider_id: metadata for metadata in list_signature_providers()}

        self.assertIn("hash_lamport_v1", providers)
        self.assertIn("xmss_merkle_lamport_v1", providers)
        self.assertIn("xmss_nist_v1", providers)
        self.assertIn("lms_nist_v1", providers)
        self.assertIn("sphincsplus_v1", providers)
        self.assertEqual(providers["xmss_nist_v1"].status, "adapter_ready")
        self.assertEqual(providers["sphincsplus_v1"].implementation, "external_backend_boundary")

    def test_resolves_verifier_by_scheme_id(self) -> None:
        verifier = get_signature_verifier("xmss_merkle_lamport_v1")
        self.assertEqual(verifier.metadata.provider_id, "xmss_merkle_lamport_v1")

    def test_planned_provider_boundary_raises_cleanly(self) -> None:
        provider = get_signature_provider("sphincsplus_v1")
        with self.assertRaisesRegex(ValueError, "migration boundary"):
            provider.generate_keypair()

    def test_xmss_external_provider_scaffold_raises_not_integrated_error(self) -> None:
        provider = get_signature_provider("xmss_nist_v1")
        with self.assertRaisesRegex(ValueError, "present but no concrete XMSS cryptography library is integrated yet"):
            provider.generate_keypair()

    def test_xmss_external_provider_raises_precise_dependency_error(self) -> None:
        provider = get_signature_provider("xmss_nist_v1")
        with patch.dict(os.environ, {"QR_CHAIN_XMSS_BACKEND_MODULE": "missing_xmss_backend"}, clear=False):
            with self.assertRaisesRegex(ValueError, "requires the optional backend module 'missing_xmss_backend'"):
                provider.generate_keypair()

    def test_xmss_external_provider_uses_backend_contract(self) -> None:
        module_name = "fake_xmss_backend"
        fake_module = types.ModuleType(module_name)

        def generate_keypair():
            return {"secret": "k1"}

        def derive_address(keypair):
            return f"addr:{keypair['secret']}"

        def sign(keypair, message):
            return {"public": keypair["secret"]}, {"signature": message.decode("utf-8")}

        def verify(message, signature, public_key):
            return signature["signature"] == message.decode("utf-8") and public_key["public"] == "k1"

        def address_from_public_key(public_key):
            return f"addr:{public_key['public']}"

        fake_module.generate_keypair = generate_keypair
        fake_module.derive_address = derive_address
        fake_module.sign = sign
        fake_module.verify = verify
        fake_module.address_from_public_key = address_from_public_key

        sys.modules[module_name] = fake_module
        self.addCleanup(lambda: sys.modules.pop(module_name, None))

        provider = get_signature_provider("xmss_nist_v1")
        with patch.dict(os.environ, {"QR_CHAIN_XMSS_BACKEND_MODULE": module_name}, clear=False):
            keypair = provider.generate_keypair()
            public_key, signature = provider.sign(keypair, b"hello")

            self.assertEqual(provider.derive_address(keypair), "addr:k1")
            self.assertEqual(provider.address_from_public_key(public_key), "addr:k1")
            self.assertTrue(provider.verify(b"hello", signature, public_key))

    def test_lists_backend_status_for_missing_external_provider(self) -> None:
        with patch.dict(os.environ, {"QR_CHAIN_XMSS_BACKEND_MODULE": "missing_xmss_backend"}, clear=False):
            providers = {item["provider_id"]: item for item in list_signature_provider_statuses()}

        self.assertFalse(providers["xmss_nist_v1"]["available"])
        self.assertIn("missing_xmss_backend", providers["xmss_nist_v1"]["error"])
        self.assertFalse(providers["sphincsplus_v1"]["available"])

    def test_lists_backend_status_for_ready_external_provider(self) -> None:
        module_name = "fake_xmss_backend_status"
        fake_module = types.ModuleType(module_name)

        def generate_keypair():
            return {"secret": "k1"}

        def derive_address(keypair):
            return f"addr:{keypair['secret']}"

        def sign(keypair, message):
            return {"public": keypair["secret"]}, {"signature": message.decode("utf-8")}

        def verify(message, signature, public_key):
            return signature["signature"] == message.decode("utf-8") and public_key["public"] == "k1"

        def address_from_public_key(public_key):
            return f"addr:{public_key['public']}"

        def serialize_keypair(keypair):
            return dict(keypair)

        def deserialize_keypair(payload):
            return dict(payload)

        def reserve_signing_material(keypair):
            return {"slot": 0}

        def sign_with_reservation(keypair, message, reservation):
            return sign(keypair, message)

        fake_module.generate_keypair = generate_keypair
        fake_module.derive_address = derive_address
        fake_module.sign = sign
        fake_module.verify = verify
        fake_module.address_from_public_key = address_from_public_key
        fake_module.serialize_keypair = serialize_keypair
        fake_module.deserialize_keypair = deserialize_keypair
        fake_module.reserve_signing_material = reserve_signing_material
        fake_module.sign_with_reservation = sign_with_reservation

        sys.modules[module_name] = fake_module
        self.addCleanup(lambda: sys.modules.pop(module_name, None))

        with patch.dict(os.environ, {"QR_CHAIN_XMSS_BACKEND_MODULE": module_name}, clear=False):
            providers = {item["provider_id"]: item for item in list_signature_provider_statuses()}

        self.assertTrue(providers["xmss_nist_v1"]["available"])
        self.assertEqual(providers["xmss_nist_v1"]["backend_module"], module_name)
        self.assertTrue(providers["xmss_nist_v1"]["supports_stateful_signing"])
        self.assertTrue(providers["xmss_nist_v1"]["supports_reserved_signing"])


if __name__ == "__main__":
    unittest.main()
