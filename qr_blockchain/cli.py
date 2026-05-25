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
            max_admitted_peers=base.max_admitted_peers,
            peer_allowlist=base.peer_allowlist,
            peer_denylist=base.peer_denylist,
            require_peer_allowlist=base.require_peer_allowlist,
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
            state_root_activation_height=base.state_root_activation_height,
            gossip_fanout=base.gossip_fanout,
            peer_bad_block_penalty=base.peer_bad_block_penalty,
            peer_invalid_frame_penalty=base.peer_invalid_frame_penalty,
            min_peer_diversity=base.min_peer_diversity,
            migration_claim_start_height=base.migration_claim_start_height,
            migration_claim_end_height=base.migration_claim_end_height,
            migration_dual_control_start_height=base.migration_dual_control_start_height,
            migration_dual_control_end_height=base.migration_dual_control_end_height,
            migration_dispute_window_blocks=base.migration_dispute_window_blocks,
            migration_snapshot_reviewer_quorum=base.migration_snapshot_reviewer_quorum,
            migration_emergency_pause=base.migration_emergency_pause,
            migration_require_snapshot_signatures=base.migration_require_snapshot_signatures,
            migration_allowed_classical_providers=base.migration_allowed_classical_providers,
            migration_trusted_snapshot_signers=base.migration_trusted_snapshot_signers,
            migration_trusted_snapshot_nodes=base.migration_trusted_snapshot_nodes,
            preferred_signature_providers=base.preferred_signature_providers,
            allowed_signature_providers=base.allowed_signature_providers,
            preferred_signature_profile=base.preferred_signature_profile,
            target_signature_sign_ms=base.target_signature_sign_ms,
            max_signature_payload_bytes=base.max_signature_payload_bytes,
            min_fee_per_kib=base.min_fee_per_kib,
            coinbase_maturity_blocks=base.coinbase_maturity_blocks,
            validator_set_policy=base.validator_set_policy,
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

    protocol = subparsers.add_parser("protocol", help="Show protocol manifest")
    protocol.add_argument("--output", default=None)
    protocol.set_defaults(handler=cmd_protocol)

    protocol_conformance = subparsers.add_parser("protocol-conformance", help="Show protocol conformance checks")
    protocol_conformance.add_argument("--output", default=None)
    protocol_conformance.set_defaults(handler=cmd_protocol_conformance)

    migration_readiness = subparsers.add_parser("migration-readiness", help="Show migration-layer readiness gates")
    migration_readiness.add_argument("--output", default=None)
    migration_readiness.set_defaults(handler=cmd_migration_readiness)

    crypto_hardening = subparsers.add_parser("crypto-hardening", help="Show pinned PQ runtime hardening status")
    crypto_hardening.add_argument("--output", default=None)
    crypto_hardening.set_defaults(handler=cmd_crypto_hardening)

    crypto_strategy = subparsers.add_parser("crypto-strategy", help="Show signature provider strategy and fast-lattice posture")
    crypto_strategy.add_argument("--output", default=None)
    crypto_strategy.set_defaults(handler=cmd_crypto_strategy)

    crypto_performance = subparsers.add_parser("crypto-performance", help="Measure available stateless signature providers")
    crypto_performance.add_argument("--output", default=None)
    crypto_performance.set_defaults(handler=cmd_crypto_performance)

    native_boundary = subparsers.add_parser("crypto-native-boundary", help="Show native Rust/C crypto boundary targets")
    native_boundary.add_argument("--output", default=None)
    native_boundary.set_defaults(handler=cmd_crypto_native_boundary)

    signer_consensus = subparsers.add_parser("signer-consensus-boundary", help="Show wallet signer and consensus separation")
    signer_consensus.add_argument("--output", default=None)
    signer_consensus.set_defaults(handler=cmd_signer_consensus_boundary)

    verification_parallelism = subparsers.add_parser(
        "verification-parallelism",
        help="Show consensus signature verification worker posture",
    )
    verification_parallelism.add_argument("--output", default=None)
    verification_parallelism.set_defaults(handler=cmd_verification_parallelism)

    tx_state_model = subparsers.add_parser("tx-state-model", help="Show deterministic transaction execution and state model")
    tx_state_model.add_argument("--output", default=None)
    tx_state_model.set_defaults(handler=cmd_tx_state_model)

    state_root_policy = subparsers.add_parser("state-root-policy", help="Show state-root activation rules")
    state_root_policy.add_argument("--output", default=None)
    state_root_policy.set_defaults(handler=cmd_state_root_policy)

    tx_resource_policy = subparsers.add_parser("tx-resource-policy", help="Show transaction and signature payload resource policy")
    tx_resource_policy.add_argument("--output", default=None)
    tx_resource_policy.set_defaults(handler=cmd_tx_resource_policy)

    consensus_economics = subparsers.add_parser("consensus-economics", help="Show consensus and economics readiness report")
    consensus_economics.add_argument("--output", default=None)
    consensus_economics.set_defaults(handler=cmd_consensus_economics)

    validator_networking = subparsers.add_parser("validator-networking", help="Show validator peer-networking readiness")
    validator_networking.add_argument("--output", default=None)
    validator_networking.set_defaults(handler=cmd_validator_networking)

    peer_diversity = subparsers.add_parser("peer-diversity", help="Show anti-eclipse peer diversity status")
    peer_diversity.add_argument("--output", default=None)
    peer_diversity.set_defaults(handler=cmd_peer_diversity)

    migration_finality = subparsers.add_parser("migration-finality-fraud", help="Show migration finality and fraud controls")
    migration_finality.add_argument("--output", default=None)
    migration_finality.set_defaults(handler=cmd_migration_finality_fraud)

    adversarial_performance = subparsers.add_parser(
        "adversarial-performance",
        help="Show adversarial and performance hardening readiness",
    )
    adversarial_performance.add_argument("--output", default=None)
    adversarial_performance.set_defaults(handler=cmd_adversarial_performance)

    load_chaos = subparsers.add_parser("load-chaos", help="Run deterministic multi-node load and chaos scenarios")
    load_chaos.add_argument("--scenario", default="all")
    load_chaos.add_argument("--node-count", type=int, default=3)
    load_chaos.add_argument("--mempool-transactions", type=int, default=8)
    load_chaos.add_argument("--migration-claims", type=int, default=6)
    load_chaos.add_argument("--verification-batch-size", type=int, default=8)
    load_chaos.add_argument("--output", default=None)
    load_chaos.set_defaults(handler=cmd_load_chaos)

    release_provenance = subparsers.add_parser("release-provenance", help="Build a release provenance manifest")
    release_provenance.add_argument("--output", default=None)
    release_provenance.set_defaults(handler=cmd_release_provenance)

    incident_runbook = subparsers.add_parser("incident-runbook", help="Show operator incident-response runbook")
    incident_runbook.add_argument("--output", default=None)
    incident_runbook.set_defaults(handler=cmd_incident_runbook)

    backup_manifest = subparsers.add_parser("backup-manifest", help="Build a chain and wallet backup manifest")
    backup_manifest.add_argument("--output", default=None)
    backup_manifest.set_defaults(handler=cmd_backup_manifest)

    node_preflight = subparsers.add_parser("node-preflight", help="Show launch preflight gates across node subsystems")
    node_preflight.add_argument("--output", default=None)
    node_preflight.set_defaults(handler=cmd_node_preflight)

    redaction_policy = subparsers.add_parser("privacy-redaction-policy", help="Show support-bundle redaction policy")
    redaction_policy.add_argument("--output", default=None)
    redaction_policy.set_defaults(handler=cmd_privacy_redaction_policy)

    network_transport = subparsers.add_parser("network-transport-readiness", help="Show peer transport hardening status")
    network_transport.add_argument("--output", default=None)
    network_transport.set_defaults(handler=cmd_network_transport_readiness)

    migration_governance = subparsers.add_parser("migration-governance", help="Show migration governance gates")
    migration_governance.add_argument("--output", default=None)
    migration_governance.set_defaults(handler=cmd_migration_governance)

    migration_adversarial = subparsers.add_parser("migration-adversarial", help="Run deterministic migration adversarial checks")
    migration_adversarial.add_argument("--output", default=None)
    migration_adversarial.set_defaults(handler=cmd_migration_adversarial)

    migration_batch = subparsers.add_parser("migration-claim-batch-plan", help="Plan a batch of claimable migration sources")
    migration_batch.add_argument("--source-network", default=None)
    migration_batch.add_argument("--limit", type=int, default=100)
    migration_batch.add_argument("--output", default=None)
    migration_batch.set_defaults(handler=cmd_migration_claim_batch_plan)

    conversion_risk = subparsers.add_parser("migration-conversion-risk", help="Show migration conversion concentration and pool risk")
    conversion_risk.add_argument("--output", default=None)
    conversion_risk.set_defaults(handler=cmd_migration_conversion_risk)

    proof_coverage = subparsers.add_parser("migration-proof-coverage", help="Show migration proof evidence coverage")
    proof_coverage.add_argument("--output", default=None)
    proof_coverage.set_defaults(handler=cmd_migration_proof_coverage)

    dispute_packet = subparsers.add_parser("migration-dispute-packet", help="Build a dispute packet for a migration source")
    dispute_packet.add_argument("--classical-address", required=True)
    dispute_packet.add_argument("--output", default=None)
    dispute_packet.set_defaults(handler=cmd_migration_dispute_packet)

    disputes = subparsers.add_parser("migration-disputes", help="List migration disputes")
    disputes.add_argument("--classical-address", default=None)
    disputes.add_argument("--output", default=None)
    disputes.set_defaults(handler=cmd_migration_disputes)

    dispute_open = subparsers.add_parser("migration-dispute-open", help="Open and quarantine a disputed migration source")
    dispute_open.add_argument("--classical-address", required=True)
    dispute_open.add_argument("--reason", required=True)
    dispute_open.add_argument("--evidence-hash", default="")
    dispute_open.add_argument("--output", default=None)
    dispute_open.set_defaults(handler=cmd_migration_dispute_open)

    dispute_evidence = subparsers.add_parser("migration-dispute-evidence", help="Submit evidence for an open migration dispute")
    dispute_evidence.add_argument("--dispute-id", required=True)
    dispute_evidence.add_argument("--evidence-hash", default="")
    dispute_evidence.add_argument("--evidence-json", default="{}")
    dispute_evidence.add_argument("--output", default=None)
    dispute_evidence.set_defaults(handler=cmd_migration_dispute_evidence)

    dispute_resolve = subparsers.add_parser("migration-dispute-resolve", help="Resolve a migration dispute")
    dispute_resolve.add_argument("--dispute-id", required=True)
    dispute_resolve.add_argument("--outcome", choices=["resolved_valid", "resolved_fraud"], required=True)
    dispute_resolve.add_argument("--resolution-note", required=True)
    dispute_resolve.add_argument("--output", default=None)
    dispute_resolve.set_defaults(handler=cmd_migration_dispute_resolve)

    snapshot_attestations = subparsers.add_parser("migration-snapshot-attestations", help="Show snapshot signer/quorum readiness")
    snapshot_attestations.add_argument("--output", default=None)
    snapshot_attestations.set_defaults(handler=cmd_migration_snapshot_attestations)

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

    integrity_parser = subparsers.add_parser("migration-integrity", help="Emit migration integrity and risk report")
    integrity_parser.add_argument("--source-network", default=None)
    integrity_parser.add_argument("--output", default=None)
    integrity_parser.set_defaults(handler=cmd_migration_integrity)

    preflight_parser = subparsers.add_parser("migration-claim-preflight", help="Build a claim signing preflight report")
    preflight_parser.add_argument("--destination-address", required=True)
    preflight_parser.add_argument("--classical-address", required=True)
    preflight_parser.add_argument("--classical-provider-id", required=True)
    preflight_parser.add_argument("--source-network", required=True)
    preflight_parser.add_argument("--snapshot-ref", default="")
    preflight_parser.add_argument("--classical-public-key-json", default="")
    preflight_parser.add_argument("--output", default=None)
    preflight_parser.set_defaults(handler=cmd_migration_claim_preflight)

    claim_package_parser = subparsers.add_parser("migration-claim-package", help="Build a wallet-safe migration claim package")
    claim_package_parser.add_argument("--destination-address", required=True)
    claim_package_parser.add_argument("--classical-address", required=True)
    claim_package_parser.add_argument("--classical-provider-id", required=True)
    claim_package_parser.add_argument("--source-network", required=True)
    claim_package_parser.add_argument("--snapshot-ref", default="")
    claim_package_parser.add_argument("--classical-public-key-json", default="")
    claim_package_parser.add_argument("--output", default=None)
    claim_package_parser.set_defaults(handler=cmd_migration_claim_package)

    quote_parser = subparsers.add_parser("migration-claim-quote", help="Quote a migration claim against pool policy")
    quote_parser.add_argument("--classical-address", required=True)
    quote_parser.add_argument("--output", default=None)
    quote_parser.set_defaults(handler=cmd_migration_claim_quote)

    claim_status_parser = subparsers.add_parser("migration-claim-status", help="Show lifecycle status for a migration claim")
    claim_status_parser.add_argument("--classical-address", required=True)
    claim_status_parser.add_argument("--output", default=None)
    claim_status_parser.set_defaults(handler=cmd_migration_claim_status)

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


def cmd_protocol(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.protocol_manifest(), None if args.output is None else Path(args.output))
    return 0


def cmd_protocol_conformance(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.protocol_conformance_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_readiness(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_readiness_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_crypto_hardening(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.crypto_runtime_hardening_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_crypto_strategy(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.signature_strategy_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_crypto_performance(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.signature_performance_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_crypto_native_boundary(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.native_crypto_runtime_boundary_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_signer_consensus_boundary(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.signer_consensus_separation_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_verification_parallelism(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.parallel_verification_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_tx_state_model(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.transaction_state_model_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_state_root_policy(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.state_root_policy(), None if args.output is None else Path(args.output))
    return 0


def cmd_tx_resource_policy(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.transaction_resource_policy_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_consensus_economics(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.consensus_economics_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_validator_networking(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.validator_networking_readiness_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_peer_diversity(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.peer_diversity_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_finality_fraud(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_finality_fraud_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_adversarial_performance(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.adversarial_performance_readiness_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_load_chaos(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.load_chaos_harness_report(
            scenario=args.scenario,
            node_count=args.node_count,
            mempool_transactions=args.mempool_transactions,
            migration_claims=args.migration_claims,
            verification_batch_size=args.verification_batch_size,
        ),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_release_provenance(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.release_provenance_manifest(), None if args.output is None else Path(args.output))
    return 0


def cmd_incident_runbook(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.operator_incident_runbook(), None if args.output is None else Path(args.output))
    return 0


def cmd_backup_manifest(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.state_backup_manifest(), None if args.output is None else Path(args.output))
    return 0


def cmd_node_preflight(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.node_launch_preflight_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_privacy_redaction_policy(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.privacy_redaction_policy_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_network_transport_readiness(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.network_transport_readiness_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_governance(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_governance_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_adversarial(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_adversarial_simulation_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_claim_batch_plan(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.migration_claim_batch_plan(source_network=args.source_network, limit=args.limit),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_conversion_risk(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_conversion_risk_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_proof_coverage(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_source_proof_coverage_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_dispute_packet(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.migration_dispute_packet(args.classical_address),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_disputes(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.migration_disputes(args.classical_address),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_dispute_open(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.open_migration_dispute(
            args.classical_address,
            reason=args.reason,
            evidence_hash=args.evidence_hash,
        ),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_dispute_evidence(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    evidence = json.loads(args.evidence_json)
    if not isinstance(evidence, dict):
        raise ValueError("--evidence-json must decode to an object")
    _write_json_output(
        service.submit_migration_dispute_evidence(
            args.dispute_id,
            evidence=evidence,
            evidence_hash=args.evidence_hash,
        ),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_dispute_resolve(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.resolve_migration_dispute(
            args.dispute_id,
            outcome=args.outcome,
            resolution_note=args.resolution_note,
        ),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_snapshot_attestations(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_snapshot_attestation_readiness(), None if args.output is None else Path(args.output))
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


def cmd_migration_integrity(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    report = service.migration_integrity_report(source_network=args.source_network)
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


def cmd_migration_claim_package(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    package = service.build_wallet_migration_claim_package(
        destination_address=args.destination_address,
        classical_address=args.classical_address,
        classical_provider_id=args.classical_provider_id,
        source_network=args.source_network,
        snapshot_ref=args.snapshot_ref,
        classical_public_key=_read_json_value(args.classical_public_key_json),
    )
    _write_json_output(package, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_claim_quote(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    quote = service.migration_claim_quote(args.classical_address)
    _write_json_output(quote, None if args.output is None else Path(args.output))
    return 0


def cmd_migration_claim_status(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    status = service.migration_claim_status(args.classical_address)
    _write_json_output(status, None if args.output is None else Path(args.output))
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
