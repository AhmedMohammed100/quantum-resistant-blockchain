from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class NodeConfig:
    db_path: Path = Path("data/chain.db")
    difficulty: int = 3
    mining_reward: int = 30
    currency_name: str = "Quantum Resistant Coin"
    currency_symbol: str = "QRC"
    currency_decimals: int = 8
    currency_base_unit: str = "quark"
    genesis_supply_cap: int = 0
    subsidy_halving_interval: int = 210000
    max_money: int = 21000000 * 100000000
    host: str = "127.0.0.1"
    port: int = 8080
    chain_id: str = "qr-chain-devnet"
    node_id: str = "node-local"
    advertised_url: str = "http://127.0.0.1:8080"
    peers: tuple[str, ...] = ()
    max_transactions_per_block: int = 500
    max_pending_transactions: int = 2000
    min_transaction_fee: int = 1
    max_transaction_size_bytes: int = 16777216
    max_transaction_inputs: int = 64
    max_transaction_outputs: int = 64
    default_signature_provider: str = "xmss_merkle_lamport_v1"
    wallet_state_db_path: Path = Path("data/wallet_state.db")
    wallet_custody_mode: str = "auto"
    wallet_custody_scope: str = "current_user"
    wallet_reservation_ttl_seconds: int = 60
    auth_time_skew_seconds: int = 300
    peer_session_ttl_seconds: int = 900
    peer_protocol_version: str = "qr-peer-v1"
    max_peer_blocks_per_request: int = 128
    migration_claim_start_height: int = 1
    migration_claim_end_height: int = 0
    migration_dual_control_start_height: int = 0
    migration_dual_control_end_height: int = 0
    migration_require_snapshot_signatures: bool = False
    migration_allowed_classical_providers: tuple[str, ...] = (
        "ecdsa_secp256k1_migration_v1",
        "rsa_pkcs1v15_sha256_migration_v1",
        "classical_claim_demo_v1",
    )
    migration_trusted_snapshot_signers: tuple[str, ...] = ()
    migration_trusted_snapshot_nodes: tuple[str, ...] = ()
    preferred_signature_providers: tuple[str, ...] = (
        "sphincsplus_v1",
        "lms_nist_v1",
        "xmss_nist_v1",
        "xmss_merkle_lamport_v1",
    )
    allowed_signature_providers: tuple[str, ...] = ()

    @staticmethod
    def from_env() -> "NodeConfig":
        peers_env = os.getenv("QR_CHAIN_PEERS", "").strip()
        default_provider = os.getenv(
            "QR_CHAIN_DEFAULT_SIGNATURE_PROVIDER",
            os.getenv("QR_CHAIN_DEFAULT_SIGNATURE_SCHEME", "xmss_merkle_lamport_v1"),
        )
        allowed_providers_env = os.getenv("QR_CHAIN_ALLOWED_SIGNATURE_PROVIDERS", "").strip()
        preferred_providers_env = os.getenv("QR_CHAIN_PREFERRED_SIGNATURE_PROVIDERS", "").strip()
        migration_providers_env = os.getenv("QR_CHAIN_MIGRATION_ALLOWED_CLASSICAL_PROVIDERS", "").strip()
        trusted_snapshot_signers_env = os.getenv("QR_CHAIN_MIGRATION_TRUSTED_SNAPSHOT_SIGNERS", "").strip()
        trusted_snapshot_nodes_env = os.getenv("QR_CHAIN_MIGRATION_TRUSTED_SNAPSHOT_NODES", "").strip()
        return NodeConfig(
            db_path=Path(os.getenv("QR_CHAIN_DB_PATH", "data/chain.db")),
            difficulty=int(os.getenv("QR_CHAIN_DIFFICULTY", "3")),
            mining_reward=int(os.getenv("QR_CHAIN_MINING_REWARD", "30")),
            currency_name=os.getenv("QR_CHAIN_CURRENCY_NAME", "Quantum Resistant Coin"),
            currency_symbol=os.getenv("QR_CHAIN_CURRENCY_SYMBOL", "QRC"),
            currency_decimals=int(os.getenv("QR_CHAIN_CURRENCY_DECIMALS", "8")),
            currency_base_unit=os.getenv("QR_CHAIN_CURRENCY_BASE_UNIT", "quark"),
            genesis_supply_cap=int(os.getenv("QR_CHAIN_GENESIS_SUPPLY_CAP", "0")),
            subsidy_halving_interval=int(os.getenv("QR_CHAIN_SUBSIDY_HALVING_INTERVAL", "210000")),
            max_money=int(os.getenv("QR_CHAIN_MAX_MONEY", str(21000000 * 100000000))),
            host=os.getenv("QR_CHAIN_HOST", "127.0.0.1"),
            port=int(os.getenv("QR_CHAIN_PORT", "8080")),
            chain_id=os.getenv("QR_CHAIN_ID", "qr-chain-devnet"),
            node_id=os.getenv("QR_CHAIN_NODE_ID", "node-local"),
            advertised_url=os.getenv("QR_CHAIN_ADVERTISED_URL", "http://127.0.0.1:8080"),
            peers=tuple(peer.strip() for peer in peers_env.split(",") if peer.strip()),
            max_transactions_per_block=int(os.getenv("QR_CHAIN_MAX_TRANSACTIONS_PER_BLOCK", "500")),
            max_pending_transactions=int(os.getenv("QR_CHAIN_MAX_PENDING_TRANSACTIONS", "2000")),
            min_transaction_fee=int(os.getenv("QR_CHAIN_MIN_TRANSACTION_FEE", "1")),
            max_transaction_size_bytes=int(os.getenv("QR_CHAIN_MAX_TRANSACTION_SIZE_BYTES", "16777216")),
            max_transaction_inputs=int(os.getenv("QR_CHAIN_MAX_TRANSACTION_INPUTS", "64")),
            max_transaction_outputs=int(os.getenv("QR_CHAIN_MAX_TRANSACTION_OUTPUTS", "64")),
            default_signature_provider=default_provider,
            wallet_state_db_path=Path(os.getenv("QR_CHAIN_WALLET_STATE_DB_PATH", "data/wallet_state.db")),
            wallet_custody_mode=os.getenv("QR_CHAIN_WALLET_CUSTODY_MODE", "auto"),
            wallet_custody_scope=os.getenv("QR_CHAIN_WALLET_CUSTODY_SCOPE", "current_user"),
            wallet_reservation_ttl_seconds=int(os.getenv("QR_CHAIN_WALLET_RESERVATION_TTL_SECONDS", "60")),
            auth_time_skew_seconds=int(os.getenv("QR_CHAIN_AUTH_TIME_SKEW_SECONDS", "300")),
            peer_session_ttl_seconds=int(os.getenv("QR_CHAIN_PEER_SESSION_TTL_SECONDS", "900")),
            peer_protocol_version=os.getenv("QR_CHAIN_PEER_PROTOCOL_VERSION", "qr-peer-v1"),
            max_peer_blocks_per_request=int(os.getenv("QR_CHAIN_MAX_PEER_BLOCKS_PER_REQUEST", "128")),
            migration_claim_start_height=int(os.getenv("QR_CHAIN_MIGRATION_CLAIM_START_HEIGHT", "1")),
            migration_claim_end_height=int(os.getenv("QR_CHAIN_MIGRATION_CLAIM_END_HEIGHT", "0")),
            migration_dual_control_start_height=int(os.getenv("QR_CHAIN_MIGRATION_DUAL_CONTROL_START_HEIGHT", "0")),
            migration_dual_control_end_height=int(os.getenv("QR_CHAIN_MIGRATION_DUAL_CONTROL_END_HEIGHT", "0")),
            migration_require_snapshot_signatures=os.getenv(
                "QR_CHAIN_MIGRATION_REQUIRE_SNAPSHOT_SIGNATURES", "0"
            ).strip().lower()
            in {"1", "true", "yes", "on"},
            migration_allowed_classical_providers=tuple(
                item.strip()
                for item in migration_providers_env.split(",")
                if item.strip()
            )
            or (
                "ecdsa_secp256k1_migration_v1",
                "rsa_pkcs1v15_sha256_migration_v1",
                "classical_claim_demo_v1",
            ),
            migration_trusted_snapshot_signers=tuple(
                item.strip()
                for item in trusted_snapshot_signers_env.split(",")
                if item.strip()
            ),
            migration_trusted_snapshot_nodes=tuple(
                item.strip()
                for item in trusted_snapshot_nodes_env.split(",")
                if item.strip()
            ),
            preferred_signature_providers=tuple(
                item.strip()
                for item in preferred_providers_env.split(",")
                if item.strip()
            )
            or (
                "sphincsplus_v1",
                "lms_nist_v1",
                "xmss_nist_v1",
                "xmss_merkle_lamport_v1",
            ),
            allowed_signature_providers=tuple(
                item.strip()
                for item in allowed_providers_env.split(",")
                if item.strip()
            ),
        )
