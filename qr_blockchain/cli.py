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


def _read_json_value(value: str) -> object:
    if not value:
        return None
    return json.loads(value)


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
            currency_name=base.currency_name,
            currency_symbol=base.currency_symbol,
            currency_decimals=base.currency_decimals,
            currency_base_unit=base.currency_base_unit,
            genesis_supply_cap=base.genesis_supply_cap,
            subsidy_halving_interval=base.subsidy_halving_interval,
            max_money=base.max_money,
            emission_supply_cap=base.emission_supply_cap,
            migration_pool_cap=base.migration_pool_cap,
            treasury_allocation_cap=base.treasury_allocation_cap,
            security_reserve_cap=base.security_reserve_cap,
            public_goods_allocation_cap=base.public_goods_allocation_cap,
            migration_conversion_policy=base.migration_conversion_policy,
            reward_recipient_policy=base.reward_recipient_policy,
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

    currency = subparsers.add_parser("currency", help="Show native currency monetary policy")
    currency.add_argument("--output", default=None)
    currency.set_defaults(handler=cmd_currency)

    supply = subparsers.add_parser("currency-supply", help="Show native currency supply accounting")
    supply.add_argument("--output", default=None)
    supply.set_defaults(handler=cmd_currency_supply)

    networks = subparsers.add_parser("migration-networks", help="List supported migration source-network profiles")
    networks.set_defaults(handler=cmd_migration_networks)

    export_parser = subparsers.add_parser("migration-snapshot-export", help="Export a migration snapshot artifact")
    export_parser.add_argument("--source-network", required=True)
    export_parser.add_argument("--snapshot-ref", default="")
    export_parser.add_argument("--include-claimed", action="store_true")
    export_parser.add_argument("--include-inactive", action="store_true")
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

    normalize_parser = subparsers.add_parser(
        "migration-source-export-normalize",
        help="Normalize a source-chain export into a migration snapshot artifact",
    )
    normalize_parser.add_argument("--input", required=True)
    normalize_parser.add_argument("--sign", action="store_true")
    normalize_parser.add_argument("--output", default=None)
    normalize_parser.set_defaults(handler=cmd_migration_source_export_normalize)

    batch_normalize_parser = subparsers.add_parser(
        "migration-source-export-batch-normalize",
        help="Normalize multiple source-chain exports into snapshot artifacts",
    )
    batch_normalize_parser.add_argument("--input", action="append", required=True)
    batch_normalize_parser.add_argument("--output", default=None)
    batch_normalize_parser.set_defaults(handler=cmd_migration_source_export_batch_normalize)

    runbook_parser = subparsers.add_parser(
        "migration-source-ingestion-runbook",
        help="Generate an operator runbook from a normalized source export",
    )
    runbook_parser.add_argument("--input", required=True)
    runbook_parser.add_argument("--output", default=None)
    runbook_parser.set_defaults(handler=cmd_migration_source_ingestion_runbook)

    manifest_status_parser = subparsers.add_parser(
        "migration-source-ingestion-manifest-status",
        help="Validate a normalized source-ingestion manifest",
    )
    manifest_status_parser.add_argument("--input", required=True)
    manifest_status_parser.add_argument("--output", default=None)
    manifest_status_parser.set_defaults(handler=cmd_migration_source_ingestion_manifest_status)

    approval_parser = subparsers.add_parser(
        "migration-source-ingestion-approve",
        help="Create an operator approval artifact for a normalized source export",
    )
    approval_parser.add_argument("--input", required=True)
    approval_parser.add_argument("--operator", required=True)
    approval_parser.add_argument("--decision", default="approved")
    approval_parser.add_argument("--reason", required=True)
    approval_parser.add_argument("--output", default=None)
    approval_parser.set_defaults(handler=cmd_migration_source_ingestion_approve)

    import_plan_parser = subparsers.add_parser(
        "migration-source-ingestion-import-plan",
        help="Build an import plan for a normalized source export",
    )
    import_plan_parser.add_argument("--input", required=True)
    import_plan_parser.add_argument("--approval", default=None)
    import_plan_parser.add_argument("--output", default=None)
    import_plan_parser.set_defaults(handler=cmd_migration_source_ingestion_import_plan)

    import_approved_parser = subparsers.add_parser(
        "migration-source-ingestion-import-approved",
        help="Import a normalized source export using an approval artifact",
    )
    import_approved_parser.add_argument("--input", required=True)
    import_approved_parser.add_argument("--approval", required=True)
    import_approved_parser.add_argument("--output", default=None)
    import_approved_parser.set_defaults(handler=cmd_migration_source_ingestion_import_approved)

    reconcile_parser = subparsers.add_parser("migration-snapshot-reconcile", help="Compare a snapshot artifact with local migration state")
    reconcile_parser.add_argument("--input", required=True)
    reconcile_parser.add_argument("--output", default=None)
    reconcile_parser.set_defaults(handler=cmd_migration_snapshot_reconcile)

    report_parser = subparsers.add_parser("migration-report", help="Emit a migration audit report")
    report_parser.add_argument("--source-network", default=None)
    report_parser.add_argument("--output", default=None)
    report_parser.set_defaults(handler=cmd_migration_report)

    preflight_parser = subparsers.add_parser("migration-claim-preflight", help="Build a claim signing preflight report")
    preflight_parser.add_argument("--destination-address", required=True)
    preflight_parser.add_argument("--classical-address", required=True)
    preflight_parser.add_argument("--classical-provider-id", required=True)
    preflight_parser.add_argument("--source-network", required=True)
    preflight_parser.add_argument("--snapshot-ref", default="")
    preflight_parser.add_argument("--classical-public-key-json", default="")
    preflight_parser.add_argument("--output", default=None)
    preflight_parser.set_defaults(handler=cmd_migration_claim_preflight)

    receipt_parser = subparsers.add_parser("migration-claim-receipt", help="Emit a signed migration claim receipt")
    receipt_parser.add_argument("--classical-address", required=True)
    receipt_parser.add_argument("--unsigned", action="store_true")
    receipt_parser.add_argument("--output", default=None)
    receipt_parser.set_defaults(handler=cmd_migration_claim_receipt)

    snapshot_status_parser = subparsers.add_parser("migration-snapshot-status", help="Set snapshot review status")
    snapshot_status_parser.add_argument("--snapshot-ref", required=True)
    snapshot_status_parser.add_argument("--status", required=True)
    snapshot_status_parser.add_argument("--reason", default="")
    snapshot_status_parser.add_argument("--no-cascade", action="store_true")
    snapshot_status_parser.add_argument("--output", default=None)
    snapshot_status_parser.set_defaults(handler=cmd_migration_snapshot_status)

    source_status_parser = subparsers.add_parser("migration-source-status", help="Set source review status")
    source_status_parser.add_argument("--classical-address", required=True)
    source_status_parser.add_argument("--status", required=True)
    source_status_parser.add_argument("--reason", default="")
    source_status_parser.add_argument("--output", default=None)
    source_status_parser.set_defaults(handler=cmd_migration_source_status)
    return parser


def cmd_migration_networks(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_network_profiles(), None if args.output is None else Path(args.output))
    return 0


def cmd_currency(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.monetary_policy(), None if args.output is None else Path(args.output))
    return 0


def cmd_currency_supply(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.supply_snapshot(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_snapshot_export(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = service.export_migration_snapshot(
        source_network=args.source_network,
        snapshot_ref=args.snapshot_ref,
        include_claimed=args.include_claimed,
        include_inactive=args.include_inactive,
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


def cmd_migration_source_export_normalize(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    normalized = service.normalize_source_export_snapshot(payload, sign=args.sign)
    _write_json_output(normalized, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_source_export_batch_normalize(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payloads = [_read_json_file(Path(path)) for path in args.input]
    normalized = service.normalize_source_export_batch(payloads)
    _write_json_output(normalized, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_source_ingestion_runbook(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    runbook = service.source_ingestion_runbook(payload)
    _write_json_output(runbook, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_source_ingestion_manifest_status(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    status = service.source_ingestion_manifest_status(payload)
    _write_json_output(status, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_source_ingestion_approve(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    approval = service.approve_source_ingestion(
        payload,
        operator=args.operator,
        decision=args.decision,
        reason=args.reason,
    )
    _write_json_output(approval, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_source_ingestion_import_plan(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    approval = _read_json_file(Path(args.approval)) if args.approval else None
    plan = service.source_ingestion_import_plan(payload, approval=approval)
    _write_json_output(plan, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_source_ingestion_import_approved(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    approval = _read_json_file(Path(args.approval))
    result = service.import_approved_source_ingestion(payload, approval=approval)
    _write_json_output(result, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_snapshot_reconcile(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    payload = _read_json_file(Path(args.input))
    report = service.reconcile_migration_snapshot(payload)
    _write_json_output(report, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_report(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    report = service.migration_audit_report(source_network=args.source_network)
    _write_json_output(report, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_claim_preflight(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    report = service.preflight_migration_claim(
        destination_address=args.destination_address,
        classical_address=args.classical_address,
        classical_provider_id=args.classical_provider_id,
        source_network=args.source_network,
        snapshot_ref=args.snapshot_ref,
        classical_public_key=_read_json_value(args.classical_public_key_json),
    )
    _write_json_output(report, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_claim_receipt(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    receipt = service.migration_claim_receipt(args.classical_address, sign=not args.unsigned)
    _write_json_output(receipt, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_snapshot_status(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    snapshot = service.set_migration_snapshot_status(
        args.snapshot_ref,
        status=args.status,
        reason=args.reason,
        cascade_sources=not args.no_cascade,
    )
    _write_json_output(snapshot, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_source_status(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    source = service.set_migration_source_status(
        args.classical_address,
        status=args.status,
        reason=args.reason,
    )
    _write_json_output(source, None if args.output is None else Path(args.output))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "output"):
        args.output = None
    return int(args.handler(args))
