from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import NodeConfig
from .service import NodeService
from .snapshot import MigrationSnapshotBundle, parse_snapshot_import_payload, validate_snapshot_bundle


def _read_json_file(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json_output(payload: dict[str, object], output_path: Path | None) -> None:
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output_path is None:
        sys.stdout.write(serialized)
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(serialized, encoding="utf-8")


def _service_from_args(args: argparse.Namespace) -> NodeService:
    base = NodeConfig.from_env()
    return NodeService(
        NodeConfig(
            db_path=Path(args.db_path) if getattr(args, "db_path", None) else base.db_path,
            difficulty=base.difficulty,
            mining_reward=base.mining_reward,
            host=base.host,
            port=base.port,
            chain_id=base.chain_id,
            node_id=base.node_id,
            advertised_url=base.advertised_url,
            peers=base.peers,
            max_transactions_per_block=base.max_transactions_per_block,
            max_pending_transactions=base.max_pending_transactions,
            min_transaction_fee=base.min_transaction_fee,
            max_transaction_size_bytes=base.max_transaction_size_bytes,
            max_transaction_inputs=base.max_transaction_inputs,
            max_transaction_outputs=base.max_transaction_outputs,
            default_signature_provider=base.default_signature_provider,
            wallet_state_db_path=Path(args.wallet_state_db_path)
            if getattr(args, "wallet_state_db_path", None)
            else base.wallet_state_db_path,
            wallet_custody_mode=base.wallet_custody_mode,
            wallet_custody_scope=base.wallet_custody_scope,
            wallet_reservation_ttl_seconds=base.wallet_reservation_ttl_seconds,
            auth_time_skew_seconds=base.auth_time_skew_seconds,
            peer_session_ttl_seconds=base.peer_session_ttl_seconds,
            peer_protocol_version=base.peer_protocol_version,
            max_peer_blocks_per_request=base.max_peer_blocks_per_request,
            migration_claim_start_height=base.migration_claim_start_height,
            migration_claim_end_height=base.migration_claim_end_height,
            migration_dual_control_start_height=base.migration_dual_control_start_height,
            migration_dual_control_end_height=base.migration_dual_control_end_height,
            migration_require_snapshot_signatures=base.migration_require_snapshot_signatures,
            migration_allowed_classical_providers=base.migration_allowed_classical_providers,
            migration_trusted_snapshot_signers=base.migration_trusted_snapshot_signers,
            migration_trusted_snapshot_nodes=base.migration_trusted_snapshot_nodes,
            preferred_signature_providers=base.preferred_signature_providers,
            allowed_signature_providers=base.allowed_signature_providers,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Quantum-resistant blockchain operator CLI")
    parser.add_argument("--db-path", default=None, help="Path to the chain state SQLite database")
    parser.add_argument("--wallet-state-db-path", default=None, help="Path to the wallet state SQLite database")
    subparsers = parser.add_subparsers(dest="command", required=True)

    networks = subparsers.add_parser("migration-networks", help="List supported migration source-network profiles")
    networks.set_defaults(handler=cmd_migration_networks)

    export_parser = subparsers.add_parser("migration-snapshot-export", help="Export a migration snapshot artifact")
    export_parser.add_argument("--source-network", required=True)
    export_parser.add_argument("--snapshot-ref", default="")
    export_parser.add_argument("--include-claimed", action="store_true")
    export_parser.add_argument("--sign", action="store_true")
    export_parser.add_argument("--output", default=None)
    export_parser.set_defaults(handler=cmd_migration_snapshot_export)

    sign_parser = subparsers.add_parser("migration-snapshot-sign", help="Sign an existing snapshot bundle")
    sign_parser.add_argument("--input", required=True)
    sign_parser.add_argument("--output", default=None)
    sign_parser.set_defaults(handler=cmd_migration_snapshot_sign)

    validate_parser = subparsers.add_parser("migration-snapshot-validate", help="Validate a snapshot artifact")
    validate_parser.add_argument("--input", required=True)
    validate_parser.add_argument("--output", default=None)
    validate_parser.set_defaults(handler=cmd_migration_snapshot_validate)

    import_parser = subparsers.add_parser("migration-snapshot-import", help="Import a snapshot artifact")
    import_parser.add_argument("--input", required=True)
    import_parser.add_argument("--output", default=None)
    import_parser.set_defaults(handler=cmd_migration_snapshot_import)
    return parser


def cmd_migration_networks(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_network_profiles(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_snapshot_export(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = service.export_migration_snapshot(
        source_network=args.source_network,
        snapshot_ref=args.snapshot_ref,
        include_claimed=args.include_claimed,
        sign=args.sign,
    )
    _write_json_output(payload, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_snapshot_sign(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    bundle_payload = payload.get("bundle", payload)
    signed = service.sign_migration_snapshot(dict(bundle_payload))
    _write_json_output(signed, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_snapshot_validate(args: argparse.Namespace) -> int:
    payload = _read_json_file(Path(args.input))
    bundle, envelope = parse_snapshot_import_payload(payload)
    result = {
        "bundle": validate_snapshot_bundle(MigrationSnapshotBundle.from_dict(bundle.to_dict())).to_dict(),
        "has_envelope": envelope is not None,
    }
    if envelope is not None:
        result["envelope"] = {
            "address": str(envelope.get("address", "")),
            "signature_scheme": str(envelope.get("signature_scheme", "")),
            "signature_provider": str(envelope.get("signature_provider", "")),
            "purpose": str(envelope.get("purpose", "")),
        }
    _write_json_output(result, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_snapshot_import(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    imported = service.import_migration_snapshot(payload)
    _write_json_output(imported, None if args.output is None else Path(args.output))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "output"):
        args.output = None
    return int(args.handler(args))
