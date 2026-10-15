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
            deployment_mode=base.deployment_mode,
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
            migration_escrow_blocks=base.migration_escrow_blocks,
            migration_claim_per_address_cap=base.migration_claim_per_address_cap,
            migration_epoch_length_blocks=base.migration_epoch_length_blocks,
            migration_epoch_mint_cap=base.migration_epoch_mint_cap,
            migration_conversion_ratio_numerator=base.migration_conversion_ratio_numerator,
            migration_conversion_ratio_denominator=base.migration_conversion_ratio_denominator,
            migration_governance_quorum=base.migration_governance_quorum,
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


def cmd_wallet_utxo_spendability(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.utxo_spendability_report(args.address), None if args.output is None else Path(args.output))
    return 0


def cmd_node_preflight(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.node_launch_preflight_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_hardening_audit(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.hardening_audit_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_hardening_stages(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.hardening_stage_reports(), None if args.output is None else Path(args.output))
    return 0


def cmd_signed_audit_artifact(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.signed_audit_artifact_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_database_durability(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.database_durability_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_native_release_provenance(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.signed_native_crypto_release_provenance(), None if args.output is None else Path(args.output))
    return 0


def cmd_native_release_provenance_validate(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.validate_native_crypto_release_provenance(_read_json_file(Path(args.input))),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_soak_result_artifact(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    result = json.loads(args.result_json)
    if not isinstance(result, dict):
        raise ValueError("--result-json must decode to an object")
    _write_json_output(service.build_soak_result_artifact(result), None if args.output is None else Path(args.output))
    return 0


def cmd_soak_result_validate(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.validate_soak_result_artifact(_read_json_file(Path(args.input))),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_database_recovery_manifest(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.database_recovery_manifest(), None if args.output is None else Path(args.output))
    return 0


def cmd_database_recovery_validate(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.validate_database_recovery_manifest(_read_json_file(Path(args.input))),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_external_audit_package(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.signed_external_audit_readiness_package(), None if args.output is None else Path(args.output))
    return 0


def cmd_external_audit_package_validate(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.validate_external_audit_readiness_package(_read_json_file(Path(args.input))),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_project_audit_bundle(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.signed_project_audit_bundle(), None if args.output is None else Path(args.output))
    return 0


def cmd_project_audit_bundle_validate(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.validate_project_audit_bundle(_read_json_file(Path(args.input))),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_consensus_upgrade_manifest(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.consensus_upgrade_manifest(), None if args.output is None else Path(args.output))
    return 0


def cmd_consensus_upgrade_sign(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.signed_consensus_upgrade_manifest(), None if args.output is None else Path(args.output))
    return 0


def cmd_consensus_upgrade_validate(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    artifact = _read_json_file(Path(args.input))
    _write_json_output(
        service.validate_consensus_upgrade_manifest_artifact(artifact),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_production_config(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.production_configuration_report(), None if args.output is None else Path(args.output))
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


def cmd_migration_escrow_finality(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_escrow_finality_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_conversion_guardrails(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_conversion_guardrail_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_economics_spec(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_economics_specification(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_economics_invariants(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_economics_invariant_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_proof_registry(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(service.migration_proof_registry_report(), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_governance_quorum(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    approvals: list[dict[str, object]] = []
    if args.approvals:
        payload = _read_json_file(Path(args.approvals))
        raw_approvals = payload.get("approvals", [])
        if not isinstance(raw_approvals, list):
            raise ValueError("--approvals must contain an approvals list")
        approvals = [dict(item) for item in raw_approvals]
    _write_json_output(service.migration_governance_quorum_report(approvals), None if args.output is None else Path(args.output))
    return 0


def cmd_migration_governance_approval(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.sign_migration_governance_approval(
            action=args.action,
            artifact_hash=args.artifact_hash,
            note=args.note,
        ),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_escrow_transition(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.migration_escrow_transition_artifact(
            args.classical_address,
            action=args.action,
            reason=args.reason,
        ),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_economics_governance(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.signed_migration_economics_governance_manifest(),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_economics_governance_validate(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.validate_migration_economics_governance_manifest(_read_json_file(Path(args.input))),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_fraud_recovery_decision(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.signed_migration_fraud_recovery_decision(
            args.classical_address,
            outcome=args.outcome,
            recovery_action=args.recovery_action,
            note=args.note,
        ),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_economics_adversarial(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.migration_adversarial_economics_simulation_report(),
        None if args.output is None else Path(args.output),
    )
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


def cmd_migration_post_finality_fraud_case(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    evidence = json.loads(args.evidence_json)
    if not isinstance(evidence, dict):
        raise ValueError("--evidence-json must decode to an object")
    _write_json_output(
        service.post_finality_migration_fraud_case(
            args.classical_address,
            evidence=evidence,
            requested_action=args.requested_action,
        ),
        None if args.output is None else Path(args.output),
    )
    return 0


def cmd_migration_post_finality_fraud_validate(args: argparse.Namespace) -> int:
    service = _service_from_args(args)
    _write_json_output(
        service.validate_post_finality_migration_fraud_case(_read_json_file(Path(args.input))),
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


