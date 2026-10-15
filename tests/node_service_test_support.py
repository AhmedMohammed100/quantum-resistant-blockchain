from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import shutil
import sys
import types
import unittest
from dataclasses import replace
from unittest.mock import patch

from qr_blockchain import NodeConfig, NodeService, Wallet
from qr_blockchain.crypto import XMSSMerkleLamportKeyPair, get_signature_suite
from qr_blockchain.migration import (
    build_demo_classical_claim_address,
    build_demo_classical_claim_proof,
    build_demo_classical_claim_public_key,
    classical_claim_message_bytes,
)
from qr_blockchain.models import Block, Transaction, TxOutput
from qr_blockchain.protocol import build_peer_frame
from qr_blockchain.verification import verify_transaction_inputs
import qr_chain_classical_migration_backend_secp256k1 as secp_backend


class _ClosingSQLiteConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        suppress = super().__exit__(exc_type, exc_value, traceback)
        self.close()
        return suppress


def _connect_test_db(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, factory=_ClosingSQLiteConnection)


def _secp256k1_sign(message: bytes, private_key: int, nonce: int = 7) -> bytes:
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    point = secp_backend._point_mul(nonce, secp_backend._G)
    assert point is not None
    r = point[0] % secp_backend._N
    s = (secp_backend._mod_inv(nonce, secp_backend._N) * (z + r * private_key)) % secp_backend._N
    if s > secp_backend._N // 2:
        s = secp_backend._N - s

    def _der_integer(value: int) -> bytes:
        encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
        return b"\x02" + bytes([len(encoded)]) + encoded

    body = _der_integer(r) + _der_integer(s)
    return b"\x30" + bytes([len(body)]) + body


class NodeServiceTestSupport(unittest.TestCase):
    @staticmethod
    def build_fake_oqs_module(*, mechanisms: list[str] | None = None) -> types.ModuleType:
        module = types.ModuleType("oqs")
        available_mechanisms = mechanisms or ["XMSS-SHA2_10_256"]

        class FakeNativeLibrary:
            def __init__(self):
                self.OQS_SIG_STFL_SECRET_KEY_serialize = lambda *args: 0
                self.OQS_SIG_STFL_SECRET_KEY_deserialize = lambda *args: 0
                self.OQS_SIG_STFL_SECRET_KEY_free = lambda *args: None
                self.OQS_MEM_insecure_free = lambda *args: None

        class FakeStatefulSignature:
            def __init__(self, mechanism: str, secret_key: bytes | None = None):
                self.mechanism = mechanism
                self.secret_key = bytes(secret_key or b"secret:0")
                self.public_key = f"public:{self.mechanism}".encode("utf-8")

            def generate_keypair(self):
                self.secret_key = b"secret:0"
                self.public_key = f"public:{self.mechanism}".encode("utf-8")
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
        module.native = lambda: FakeNativeLibrary()
        return module

    def make_config(
        self,
        db_path: Path,
        *,
        chain_id: str = "qr-chain-devnet",
        node_id: str = "node-local",
        advertised_url: str = "http://127.0.0.1:8080",
    ) -> NodeConfig:
        return NodeConfig(
            db_path=db_path,
            wallet_state_db_path=db_path.parent / "wallet_state.db",
            difficulty=1,
            mining_reward=10,
            min_transaction_fee=1,
            max_pending_transactions=8,
            max_transaction_size_bytes=16777216,
            max_transaction_inputs=64,
            max_transaction_outputs=64,
            chain_id=chain_id,
            node_id=node_id,
            advertised_url=advertised_url,
            peer_session_ttl_seconds=120,
            max_peer_blocks_per_request=32,
        )

    def make_service(self) -> tuple[NodeService, Path]:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / self._testMethodName
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        db_path = case_dir / "chain.db"
        service = NodeService(self.make_config(db_path))
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return service, db_path

    def make_additional_service(self, suffix: str, *, chain_id: str = "qr-chain-devnet") -> NodeService:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / f"{self._testMethodName}_{suffix}"
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return NodeService(
            self.make_config(
                case_dir / "chain.db",
                chain_id=chain_id,
                node_id=f"node-{suffix}",
                advertised_url=f"http://{suffix}:8080",
            )
        )

    def wallet_state_db_path(self, suffix: str = "wallet_state.db") -> Path:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / f"{self._testMethodName}_wallet"
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return case_dir / suffix

