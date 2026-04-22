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
    @staticmethod
    def make_manifest(*, backend_name: str, implementation_type: str = "library") -> dict[str, object]:
        return {
            "backend_name": backend_name,
            "api_version": 1,
            "scheme_id": "xmss_nist_v1",
            "algorithm_family": "xmss",
            "implementation_type": implementation_type,
            "supports_signing": True,
            "supports_stateful_signing": True,
            "supports_reserved_signing": True,
        }

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

    def test_xmss_external_provider_scaffold_uses_reference_backend(self) -> None:
        provider = get_signature_provider("xmss_nist_v1")
        keypair = provider.generate_keypair()
        public_key, signature = provider.sign(keypair, b"hello")

        self.assertEqual(provider.derive_address(keypair), provider.address_from_public_key(public_key))
        self.assertTrue(provider.verify(b"hello", signature, public_key))

    def test_xmss_external_provider_raises_precise_dependency_error(self) -> None:
        provider = get_signature_provider("xmss_nist_v1")
        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "missing_xmss_backend",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, "XMSS backend module 'missing_xmss_backend' is not installed"):
                provider.generate_keypair()

    def test_xmss_external_provider_uses_backend_contract(self) -> None:
        module_name = "fake_xmss_backend"
        fake_module = types.ModuleType(module_name)
        fake_module.XMSS_BACKEND_MANIFEST = self.make_manifest(backend_name="fake-xmss-backend")

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

        def export_public_key(keypair):
            return {"public": keypair["secret"]}

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
        fake_module.export_public_key = export_public_key
        fake_module.serialize_keypair = serialize_keypair
        fake_module.deserialize_keypair = deserialize_keypair
        fake_module.reserve_signing_material = reserve_signing_material
        fake_module.sign_with_reservation = sign_with_reservation

        sys.modules[module_name] = fake_module
        self.addCleanup(lambda: sys.modules.pop(module_name, None))

        provider = get_signature_provider("xmss_nist_v1")
        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": module_name,
            },
            clear=False,
        ):
            keypair = provider.generate_keypair()
            public_key, signature = provider.sign(keypair, b"hello")

            self.assertEqual(provider.derive_address(keypair), "addr:k1")
            self.assertEqual(provider.address_from_public_key(public_key), "addr:k1")
            self.assertTrue(provider.verify(b"hello", signature, public_key))

    def test_xmss_external_provider_rejects_invalid_backend_contract(self) -> None:
        module_name = "invalid_xmss_backend"
        fake_module = types.ModuleType(module_name)
        fake_module.XMSS_BACKEND_MANIFEST = self.make_manifest(
            backend_name="invalid-xmss-backend",
            implementation_type="library",
        )
        fake_module.XMSS_BACKEND_MANIFEST["scheme_id"] = "wrong_scheme"

        def generate_keypair():
            return {"secret": "k1"}

        def derive_address(keypair):
            return f"addr:{keypair['secret']}"

        def sign(keypair, message):
            return {"public": keypair["secret"]}, {"signature": message.decode("utf-8")}

        def verify(message, signature, public_key):
            return True

        def address_from_public_key(public_key):
            return "addr:any"

        def export_public_key(keypair):
            return {"public": keypair["secret"]}

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
        fake_module.export_public_key = export_public_key
        fake_module.serialize_keypair = serialize_keypair
        fake_module.deserialize_keypair = deserialize_keypair
        fake_module.reserve_signing_material = reserve_signing_material
        fake_module.sign_with_reservation = sign_with_reservation

        sys.modules[module_name] = fake_module
        self.addCleanup(lambda: sys.modules.pop(module_name, None))

        provider = get_signature_provider("xmss_nist_v1")
        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": module_name,
            },
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, "scheme_id 'wrong_scheme'"):
                provider.generate_keypair()

    def build_fake_oqs_module(
        self,
        *,
        mechanisms: list[str] | None = None,
        native_error: BaseException | None = None,
    ) -> types.ModuleType:
        module = types.ModuleType("oqs")
        available_mechanisms = mechanisms or ["XMSS-SHA2_10_256"]

        class FakeStatefulSignature:
            def __init__(self, mechanism: str):
                self.mechanism = mechanism
                self.secret_key = b""
                self.public_key = b""

            def generate_keypair(self):
                self.public_key = f"public:{self.mechanism}".encode("utf-8")
                self.secret_key = b"secret:0"
                return self.public_key

            def export_secret_key(self):
                return self.secret_key

            def import_secret_key(self, secret_key: bytes):
                self.secret_key = bytes(secret_key)

            def sign(self, message: bytes):
                counter = int(self.secret_key.decode("utf-8").split(":")[1])
                signature = f"sig:{self.mechanism}:{counter}:{message.decode('utf-8')}".encode("utf-8")
                self.secret_key = f"secret:{counter + 1}".encode("utf-8")
                return signature

            def verify(self, message: bytes, signature: bytes, public_key: bytes):
                return (
                    public_key == f"public:{self.mechanism}".encode("utf-8")
                    and signature.decode("utf-8").endswith(message.decode("utf-8"))
                )

        module.__version__ = "0.test"
        module.StatefulSignature = FakeStatefulSignature
        module.get_enabled_stateful_sig_mechanisms = lambda: list(available_mechanisms)
        if native_error is None:
            class FakeNativeLibrary:
                def __init__(self):
                    self.OQS_SIG_STFL_SECRET_KEY_serialize = lambda *args: 0
                    self.OQS_SIG_STFL_SECRET_KEY_deserialize = lambda *args: 0
                    self.OQS_SIG_STFL_SECRET_KEY_free = lambda *args: None
                    self.OQS_MEM_insecure_free = lambda *args: None

            module.native = lambda: FakeNativeLibrary()
        else:
            def _raise_native_error():
                raise native_error
            module.native = _raise_native_error
        return module

    def test_oqs_backend_target_reports_missing_library_cleanly(self) -> None:
        provider = get_signature_provider("xmss_nist_v1")
        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "qr_chain_xmss_backend.oqs_backend",
            },
            clear=False,
        ):
            with patch.dict(sys.modules, {"oqs": None}, clear=False):
                with self.assertRaisesRegex(ValueError, "requires the 'oqs' Python package"):
                    provider.generate_keypair()

    def test_oqs_backend_target_reports_missing_native_runtime_cleanly(self) -> None:
        provider = get_signature_provider("xmss_nist_v1")
        fake_oqs = self.build_fake_oqs_module(native_error=SystemExit("Could not load liboqs shared library"))
        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "qr_chain_xmss_backend.oqs_backend",
            },
            clear=False,
        ):
            with patch.dict(sys.modules, {"oqs": fake_oqs}, clear=False):
                with self.assertRaisesRegex(ValueError, "native liboqs runtime is unavailable"):
                    provider.generate_keypair()

    def test_oqs_backend_target_uses_stateful_signature_runtime(self) -> None:
        provider = get_signature_provider("xmss_nist_v1")
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
                keypair = provider.generate_keypair()
                self.assertEqual(provider.derive_address(keypair), provider.address_from_public_key(provider.export_public_key(keypair)))
                public_key, signature = provider.sign(keypair, b"hello")

                self.assertTrue(provider.verify(b"hello", signature, public_key))
                serialized = provider.serialize_keypair(keypair)
                self.assertEqual(serialized["signatures_used"], 1)
                self.assertEqual(serialized["mechanism"], "XMSS-SHA2_10_256")

    def test_oqs_backend_target_rejects_disabled_mechanism(self) -> None:
        provider = get_signature_provider("xmss_nist_v1")
        fake_oqs = self.build_fake_oqs_module(mechanisms=["XMSS-SHA2_16_256"])
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
                with self.assertRaisesRegex(ValueError, "is not enabled"):
                    provider.generate_keypair()

    def test_lists_backend_status_for_missing_external_provider(self) -> None:
        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "missing_xmss_backend",
            },
            clear=False,
        ):
            providers = {item["provider_id"]: item for item in list_signature_provider_statuses()}

        self.assertFalse(providers["xmss_nist_v1"]["available"])
        self.assertIn("missing_xmss_backend", providers["xmss_nist_v1"]["error"])
        self.assertFalse(providers["sphincsplus_v1"]["available"])

    def test_lists_backend_status_for_missing_oqs_library_target(self) -> None:
        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": "qr_chain_xmss_backend.oqs_backend",
            },
            clear=False,
        ):
            with patch("qr_chain_xmss_backend.oqs_backend._load_oqs", side_effect=ValueError("requires the 'oqs' Python package")):
                providers = {item["provider_id"]: item for item in list_signature_provider_statuses()}

        self.assertFalse(providers["xmss_nist_v1"]["available"])
        self.assertIn("oqs", providers["xmss_nist_v1"]["error"])

    def test_lists_backend_status_for_reference_xmss_provider(self) -> None:
        providers = {item["provider_id"]: item for item in list_signature_provider_statuses()}

        self.assertTrue(providers["xmss_nist_v1"]["available"])
        self.assertEqual(providers["xmss_nist_v1"]["implementation_mode"], "reference")
        self.assertTrue(providers["xmss_nist_v1"]["supports_stateful_signing"])
        self.assertTrue(providers["xmss_nist_v1"]["supports_reserved_signing"])

    def test_lists_backend_status_for_ready_external_provider(self) -> None:
        module_name = "fake_xmss_backend_status"
        fake_module = types.ModuleType(module_name)
        fake_module.XMSS_BACKEND_MANIFEST = self.make_manifest(backend_name="fake-xmss-backend-status")

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

        def export_public_key(keypair):
            return {"public": keypair["secret"]}

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
        fake_module.export_public_key = export_public_key
        fake_module.serialize_keypair = serialize_keypair
        fake_module.deserialize_keypair = deserialize_keypair
        fake_module.reserve_signing_material = reserve_signing_material
        fake_module.sign_with_reservation = sign_with_reservation

        sys.modules[module_name] = fake_module
        self.addCleanup(lambda: sys.modules.pop(module_name, None))

        with patch.dict(
            os.environ,
            {
                "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION": "module",
                "QR_CHAIN_XMSS_LIBRARY_MODULE": module_name,
            },
            clear=False,
        ):
            providers = {item["provider_id"]: item for item in list_signature_provider_statuses()}

        self.assertTrue(providers["xmss_nist_v1"]["available"])
        self.assertEqual(providers["xmss_nist_v1"]["implementation_mode"], "module")
        self.assertEqual(providers["xmss_nist_v1"]["backend_module"], module_name)
        self.assertTrue(providers["xmss_nist_v1"]["supports_stateful_signing"])
        self.assertTrue(providers["xmss_nist_v1"]["supports_reserved_signing"])


if __name__ == "__main__":
    unittest.main()
