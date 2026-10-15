from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import NodeConfig
from .service import NodeService
from .snapshot import MigrationSnapshotBundle, parse_snapshot_import_payload, validate_snapshot_bundle

from .cli_commands import (
    _read_json_file,
    _read_json_value,
    _write_json_output,
    _service_from_args,
    cmd_migration_networks,
    cmd_currency,
    cmd_protocol,
    cmd_protocol_conformance,
    cmd_migration_readiness,
    cmd_crypto_hardening,
    cmd_crypto_strategy,
    cmd_crypto_performance,
    cmd_crypto_native_boundary,
    cmd_signer_consensus_boundary,
    cmd_verification_parallelism,
    cmd_tx_state_model,
    cmd_state_root_policy,
    cmd_tx_resource_policy,
    cmd_consensus_economics,
    cmd_validator_networking,
    cmd_peer_diversity,
    cmd_migration_finality_fraud,
    cmd_adversarial_performance,
    cmd_load_chaos,
    cmd_release_provenance,
    cmd_incident_runbook,
    cmd_backup_manifest,
    cmd_wallet_utxo_spendability,
    cmd_node_preflight,
    cmd_hardening_audit,
    cmd_hardening_stages,
    cmd_signed_audit_artifact,
    cmd_database_durability,
    cmd_native_release_provenance,
    cmd_native_release_provenance_validate,
    cmd_soak_result_artifact,
    cmd_soak_result_validate,
    cmd_database_recovery_manifest,
    cmd_database_recovery_validate,
    cmd_external_audit_package,
    cmd_external_audit_package_validate,
    cmd_project_audit_bundle,
    cmd_project_audit_bundle_validate,
    cmd_consensus_upgrade_manifest,
    cmd_consensus_upgrade_sign,
    cmd_consensus_upgrade_validate,
    cmd_production_config,
    cmd_privacy_redaction_policy,
    cmd_network_transport_readiness,
    cmd_migration_governance,
    cmd_migration_adversarial,
    cmd_migration_claim_batch_plan,
    cmd_migration_conversion_risk,
    cmd_migration_escrow_finality,
    cmd_migration_conversion_guardrails,
    cmd_migration_economics_spec,
    cmd_migration_economics_invariants,
    cmd_migration_proof_registry,
    cmd_migration_governance_quorum,
    cmd_migration_governance_approval,
    cmd_migration_escrow_transition,
    cmd_migration_economics_governance,
    cmd_migration_economics_governance_validate,
    cmd_migration_fraud_recovery_decision,
    cmd_migration_economics_adversarial,
    cmd_migration_proof_coverage,
    cmd_migration_dispute_packet,
    cmd_migration_disputes,
    cmd_migration_dispute_open,
    cmd_migration_dispute_evidence,
    cmd_migration_dispute_resolve,
    cmd_migration_post_finality_fraud_case,
    cmd_migration_post_finality_fraud_validate,
    cmd_migration_snapshot_attestations,
    cmd_currency_supply,
    cmd_migration_snapshot_export,
    cmd_migration_snapshot_sign,
    cmd_migration_snapshot_validate,
    cmd_migration_snapshot_import,
    cmd_migration_source_export_normalize,
    cmd_migration_source_export_batch_normalize,
    cmd_migration_source_ingestion_runbook,
    cmd_migration_source_ingestion_manifest_status,
    cmd_migration_source_ingestion_approve,
    cmd_migration_source_ingestion_import_plan,
    cmd_migration_source_ingestion_import_approved,
    cmd_migration_snapshot_reconcile,
    cmd_migration_report,
    cmd_migration_integrity,
    cmd_migration_claim_preflight,
    cmd_migration_claim_package,
    cmd_migration_claim_quote,
    cmd_migration_claim_status,
    cmd_migration_claim_receipt,
    cmd_migration_snapshot_status,
    cmd_migration_source_status,
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

    wallet_spendability = subparsers.add_parser("wallet-utxo-spendability", help="Show spendable and locked UTXOs")
    wallet_spendability.add_argument("--address", action="append", default=None)
    wallet_spendability.add_argument("--output", default=None)
    wallet_spendability.set_defaults(handler=cmd_wallet_utxo_spendability)

    node_preflight = subparsers.add_parser("node-preflight", help="Show launch preflight gates across node subsystems")
    node_preflight.add_argument("--output", default=None)
    node_preflight.set_defaults(handler=cmd_node_preflight)

    hardening_audit = subparsers.add_parser("hardening-audit", help="Show consolidated hardening audit gates")
    hardening_audit.add_argument("--output", default=None)
    hardening_audit.set_defaults(handler=cmd_hardening_audit)

    hardening_stages = subparsers.add_parser("hardening-stages", help="Show the next hardening stage reports")
    hardening_stages.add_argument("--output", default=None)
    hardening_stages.set_defaults(handler=cmd_hardening_stages)

    signed_audit = subparsers.add_parser("signed-audit-artifact", help="Emit a signed hardening audit artifact")
    signed_audit.add_argument("--output", default=None)
    signed_audit.set_defaults(handler=cmd_signed_audit_artifact)

    database_durability = subparsers.add_parser("database-durability", help="Show SQLite durability and integrity status")
    database_durability.add_argument("--output", default=None)
    database_durability.set_defaults(handler=cmd_database_durability)

    native_release = subparsers.add_parser(
        "native-release-provenance",
        help="Emit a signed native crypto release provenance artifact",
    )
    native_release.add_argument("--output", default=None)
    native_release.set_defaults(handler=cmd_native_release_provenance)

    native_release_validate = subparsers.add_parser(
        "native-release-provenance-validate",
        help="Validate a signed native crypto release provenance artifact",
    )
    native_release_validate.add_argument("--input", required=True)
    native_release_validate.add_argument("--output", default=None)
    native_release_validate.set_defaults(handler=cmd_native_release_provenance_validate)

    soak_artifact = subparsers.add_parser("soak-result-artifact", help="Build a signed long-running soak result artifact")
    soak_artifact.add_argument("--result-json", required=True)
    soak_artifact.add_argument("--output", default=None)
    soak_artifact.set_defaults(handler=cmd_soak_result_artifact)

    soak_validate = subparsers.add_parser("soak-result-validate", help="Validate a signed soak result artifact")
    soak_validate.add_argument("--input", required=True)
    soak_validate.add_argument("--output", default=None)
    soak_validate.set_defaults(handler=cmd_soak_result_validate)

    recovery_manifest = subparsers.add_parser(
        "database-recovery-manifest",
        help="Emit a signed database recovery manifest",
    )
    recovery_manifest.add_argument("--output", default=None)
    recovery_manifest.set_defaults(handler=cmd_database_recovery_manifest)

    recovery_validate = subparsers.add_parser(
        "database-recovery-validate",
        help="Validate a signed database recovery manifest",
    )
    recovery_validate.add_argument("--input", required=True)
    recovery_validate.add_argument("--output", default=None)
    recovery_validate.set_defaults(handler=cmd_database_recovery_validate)

    audit_package = subparsers.add_parser(
        "external-audit-package",
        help="Emit a signed external audit readiness package",
    )
    audit_package.add_argument("--output", default=None)
    audit_package.set_defaults(handler=cmd_external_audit_package)

    audit_package_validate = subparsers.add_parser(
        "external-audit-package-validate",
        help="Validate a signed external audit readiness package",
    )
    audit_package_validate.add_argument("--input", required=True)
    audit_package_validate.add_argument("--output", default=None)
    audit_package_validate.set_defaults(handler=cmd_external_audit_package_validate)

    project_audit_bundle = subparsers.add_parser("project-audit-bundle", help="Emit a signed full-project audit evidence bundle")
    project_audit_bundle.add_argument("--output", default=None)
    project_audit_bundle.set_defaults(handler=cmd_project_audit_bundle)

    project_audit_bundle_validate = subparsers.add_parser(
        "project-audit-bundle-validate",
        help="Validate a signed full-project audit evidence bundle",
    )
    project_audit_bundle_validate.add_argument("--input", required=True)
    project_audit_bundle_validate.add_argument("--output", default=None)
    project_audit_bundle_validate.set_defaults(handler=cmd_project_audit_bundle_validate)

    consensus_upgrade = subparsers.add_parser("consensus-upgrade-manifest", help="Emit consensus parameter upgrade manifest")
    consensus_upgrade.add_argument("--output", default=None)
    consensus_upgrade.set_defaults(handler=cmd_consensus_upgrade_manifest)

    consensus_upgrade_signed = subparsers.add_parser(
        "consensus-upgrade-sign",
        help="Emit a signed consensus parameter upgrade artifact",
    )
    consensus_upgrade_signed.add_argument("--output", default=None)
    consensus_upgrade_signed.set_defaults(handler=cmd_consensus_upgrade_sign)

    consensus_upgrade_validate = subparsers.add_parser(
        "consensus-upgrade-validate",
        help="Validate a signed consensus parameter upgrade artifact",
    )
    consensus_upgrade_validate.add_argument("--input", required=True)
    consensus_upgrade_validate.add_argument("--output", default=None)
    consensus_upgrade_validate.set_defaults(handler=cmd_consensus_upgrade_validate)

    production_config = subparsers.add_parser(
        "production-config",
        help="Show production configuration safety gates",
    )
    production_config.add_argument("--output", default=None)
    production_config.set_defaults(handler=cmd_production_config)

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

    escrow_finality = subparsers.add_parser("migration-escrow-finality", help="Show migration escrow and claim-finality states")
    escrow_finality.add_argument("--output", default=None)
    escrow_finality.set_defaults(handler=cmd_migration_escrow_finality)

    conversion_guardrails = subparsers.add_parser("migration-conversion-guardrails", help="Show migration conversion caps and epoch guardrails")
    conversion_guardrails.add_argument("--output", default=None)
    conversion_guardrails.set_defaults(handler=cmd_migration_conversion_guardrails)

    economics_spec = subparsers.add_parser("migration-economics-spec", help="Show formal migration economics specification")
    economics_spec.add_argument("--output", default=None)
    economics_spec.set_defaults(handler=cmd_migration_economics_spec)

    economics_invariants = subparsers.add_parser("migration-economics-invariants", help="Check migration economics invariants")
    economics_invariants.add_argument("--output", default=None)
    economics_invariants.set_defaults(handler=cmd_migration_economics_invariants)

    proof_registry = subparsers.add_parser("migration-proof-registry", help="Show canonical migration proof registry")
    proof_registry.add_argument("--output", default=None)
    proof_registry.set_defaults(handler=cmd_migration_proof_registry)

    governance_quorum = subparsers.add_parser("migration-governance-quorum", help="Show migration governance quorum status")
    governance_quorum.add_argument("--approvals", default=None, help="Optional JSON file containing {'approvals': [...]}")
    governance_quorum.add_argument("--output", default=None)
    governance_quorum.set_defaults(handler=cmd_migration_governance_quorum)

    governance_approval = subparsers.add_parser("migration-governance-approval", help="Sign a migration governance approval")
    governance_approval.add_argument("--action", required=True)
    governance_approval.add_argument("--artifact-hash", required=True)
    governance_approval.add_argument("--note", default="")
    governance_approval.add_argument("--output", default=None)
    governance_approval.set_defaults(handler=cmd_migration_governance_approval)

    escrow_transition = subparsers.add_parser("migration-escrow-transition", help="Emit a signed migration escrow transition intent")
    escrow_transition.add_argument("--classical-address", required=True)
    escrow_transition.add_argument("--action", choices=["unlock", "freeze", "fraud_freeze", "review_hold"], required=True)
    escrow_transition.add_argument("--reason", required=True)
    escrow_transition.add_argument("--output", default=None)
    escrow_transition.set_defaults(handler=cmd_migration_escrow_transition)

    economics_governance = subparsers.add_parser("migration-economics-governance", help="Emit a signed migration economics governance manifest")
    economics_governance.add_argument("--output", default=None)
    economics_governance.set_defaults(handler=cmd_migration_economics_governance)

    economics_governance_validate = subparsers.add_parser(
        "migration-economics-governance-validate",
        help="Validate a signed migration economics governance manifest",
    )
    economics_governance_validate.add_argument("--input", required=True)
    economics_governance_validate.add_argument("--output", default=None)
    economics_governance_validate.set_defaults(handler=cmd_migration_economics_governance_validate)

    fraud_decision = subparsers.add_parser("migration-fraud-recovery-decision", help="Emit a signed migration fraud recovery decision")
    fraud_decision.add_argument("--classical-address", required=True)
    fraud_decision.add_argument("--outcome", choices=["resolved_valid", "resolved_fraud"], required=True)
    fraud_decision.add_argument("--recovery-action", required=True)
    fraud_decision.add_argument("--note", required=True)
    fraud_decision.add_argument("--output", default=None)
    fraud_decision.set_defaults(handler=cmd_migration_fraud_recovery_decision)

    economics_simulation = subparsers.add_parser("migration-economics-adversarial", help="Run migration economics adversarial checks")
    economics_simulation.add_argument("--output", default=None)
    economics_simulation.set_defaults(handler=cmd_migration_economics_adversarial)

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

    post_finality_case = subparsers.add_parser(
        "migration-post-finality-fraud-case",
        help="Create a signed fraud-recovery case for an already-mined migration claim",
    )
    post_finality_case.add_argument("--classical-address", required=True)
    post_finality_case.add_argument("--evidence-json", required=True)
    post_finality_case.add_argument("--requested-action", default="freeze_destination_outputs")
    post_finality_case.add_argument("--output", default=None)
    post_finality_case.set_defaults(handler=cmd_migration_post_finality_fraud_case)

    post_finality_validate = subparsers.add_parser(
        "migration-post-finality-fraud-validate",
        help="Validate a signed post-finality migration fraud case artifact",
    )
    post_finality_validate.add_argument("--input", required=True)
    post_finality_validate.add_argument("--output", default=None)
    post_finality_validate.set_defaults(handler=cmd_migration_post_finality_fraud_validate)

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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "output"):
        args.output = None
    return int(args.handler(args))
