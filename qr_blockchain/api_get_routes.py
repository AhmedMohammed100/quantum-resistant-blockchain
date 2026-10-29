from __future__ import annotations

from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from .models import Block


class GetRoutesMixin:
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            payload = self.service.operational_status()
            status = HTTPStatus.OK if payload["status"] == "ok" else HTTPStatus.SERVICE_UNAVAILABLE
            self._respond(status, payload)
            return
        if path == "/status":
            self._respond(HTTPStatus.OK, self.service.operational_status())
            return
        if path == "/metrics":
            self._respond(HTTPStatus.OK, self.service.metrics_snapshot())
            return
        if path == "/chain/summary":
            self._respond(HTTPStatus.OK, self.service.chain_summary())
            return
        if path == "/protocol":
            self._respond(HTTPStatus.OK, self.service.protocol_manifest())
            return
        if path == "/protocol/conformance":
            self._respond(HTTPStatus.OK, self.service.protocol_conformance_report())
            return
        if path == "/migration/readiness":
            self._respond(HTTPStatus.OK, self.service.migration_readiness_report())
            return
        if path == "/currency":
            self._respond(HTTPStatus.OK, self.service.monetary_policy())
            return
        if path == "/currency/supply":
            self._respond(HTTPStatus.OK, self.service.supply_snapshot())
            return
        if path == "/crypto/providers":
            self._respond(HTTPStatus.OK, self.service.signature_provider_statuses())
            return
        if path == "/crypto/hardening":
            self._respond(HTTPStatus.OK, self.service.crypto_runtime_hardening_report())
            return
        if path == "/crypto/strategy":
            self._respond(HTTPStatus.OK, self.service.signature_strategy_report())
            return
        if path == "/crypto/performance":
            self._respond(HTTPStatus.OK, self.service.signature_performance_report())
            return
        if path == "/crypto/native-boundary":
            self._respond(HTTPStatus.OK, self.service.native_crypto_runtime_boundary_report())
            return
        if path == "/architecture/signer-consensus":
            self._respond(HTTPStatus.OK, self.service.signer_consensus_separation_report())
            return
        if path == "/consensus/verification-parallelism":
            self._respond(HTTPStatus.OK, self.service.parallel_verification_report())
            return
        if path == "/transactions/state-model":
            self._respond(HTTPStatus.OK, self.service.transaction_state_model_report())
            return
        if path == "/consensus/state-root-policy":
            self._respond(HTTPStatus.OK, self.service.state_root_policy())
            return
        if path == "/transactions/resource-policy":
            self._respond(HTTPStatus.OK, self.service.transaction_resource_policy_report())
            return
        if path == "/consensus/economics":
            self._respond(HTTPStatus.OK, self.service.consensus_economics_report())
            return
        if path == "/network/validator-readiness":
            self._respond(HTTPStatus.OK, self.service.validator_networking_readiness_report())
            return
        if path == "/migration/finality-fraud":
            self._respond(HTTPStatus.OK, self.service.migration_finality_fraud_report())
            return
        if path == "/testing/adversarial-performance":
            self._respond(HTTPStatus.OK, self.service.adversarial_performance_readiness_report())
            return
        if path == "/testing/load-chaos":
            # The harness allocates temporary databases and performs CPU-heavy signing/verification.
            # Keep it behind the operator boundary on exposed nodes.
            if not self._authorize_operator():
                return
            query = parse_qs(parsed.query)
            try:
                report = self.service.load_chaos_harness_report(
                    scenario=query.get("scenario", ["all"])[0],
                    node_count=int(query.get("node_count", ["3"])[0]),
                    mempool_transactions=int(query.get("mempool_transactions", ["8"])[0]),
                    migration_claims=int(query.get("migration_claims", ["6"])[0]),
                    verification_batch_size=int(query.get("verification_batch_size", ["8"])[0]),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, report)
            return
        if path == "/release/provenance":
            self._respond(HTTPStatus.OK, self.service.release_provenance_manifest())
            return
        if path == "/operations/incident-runbook":
            self._respond(HTTPStatus.OK, self.service.operator_incident_runbook())
            return
        if path == "/operations/backup-manifest":
            self._respond(HTTPStatus.OK, self.service.state_backup_manifest())
            return
        if path == "/operations/preflight":
            self._respond(HTTPStatus.OK, self.service.node_launch_preflight_report())
            return
        if path == "/operations/hardening-audit":
            self._respond(HTTPStatus.OK, self.service.hardening_audit_report())
            return
        if path == "/operations/hardening-stages":
            self._respond(HTTPStatus.OK, self.service.hardening_stage_reports())
            return
        if path == "/operations/signed-audit-artifact":
            self._respond(HTTPStatus.OK, self.service.signed_audit_artifact_report())
            return
        if path == "/operations/database-durability":
            self._respond(HTTPStatus.OK, self.service.database_durability_report())
            return
        if path == "/operations/native-release-provenance":
            self._respond(HTTPStatus.OK, self.service.signed_native_crypto_release_provenance())
            return
        if path == "/operations/soak-result-schema":
            self._respond(HTTPStatus.OK, self.service.soak_result_artifact_report())
            return
        if path == "/operations/database-recovery-manifest":
            self._respond(HTTPStatus.OK, self.service.database_recovery_manifest())
            return
        if path == "/operations/external-audit-package":
            self._respond(HTTPStatus.OK, self.service.signed_external_audit_readiness_package())
            return
        if path == "/operations/project-audit-bundle":
            self._respond(HTTPStatus.OK, self.service.signed_project_audit_bundle())
            return
        if path == "/operations/consensus-upgrade-manifest":
            self._respond(HTTPStatus.OK, self.service.consensus_upgrade_manifest())
            return
        if path == "/operations/consensus-upgrade-signed":
            self._respond(HTTPStatus.OK, self.service.signed_consensus_upgrade_manifest())
            return
        if path == "/operations/production-config":
            self._respond(HTTPStatus.OK, self.service.production_configuration_report())
            return
        if path == "/privacy/redaction-policy":
            self._respond(HTTPStatus.OK, self.service.privacy_redaction_policy_report())
            return
        if path == "/network/transport-readiness":
            self._respond(HTTPStatus.OK, self.service.network_transport_readiness_report())
            return
        if path == "/migration/policy":
            self._respond(HTTPStatus.OK, self.service.migration_policy())
            return
        if path == "/migration/governance":
            self._respond(HTTPStatus.OK, self.service.migration_governance_report())
            return
        if path == "/migration/adversarial":
            self._respond(HTTPStatus.OK, self.service.migration_adversarial_simulation_report())
            return
        if path == "/migration/claim-batch-plan":
            query = parse_qs(parsed.query)
            source_network = query.get("source_network", [None])[0]
            limit = int(query.get("limit", ["100"])[0])
            self._respond(HTTPStatus.OK, self.service.migration_claim_batch_plan(source_network=source_network, limit=limit))
            return
        if path == "/migration/conversion-risk":
            self._respond(HTTPStatus.OK, self.service.migration_conversion_risk_report())
            return
        if path == "/migration/escrow-finality":
            self._respond(HTTPStatus.OK, self.service.migration_escrow_finality_report())
            return
        if path == "/migration/conversion-guardrails":
            self._respond(HTTPStatus.OK, self.service.migration_conversion_guardrail_report())
            return
        if path == "/migration/economics-spec":
            self._respond(HTTPStatus.OK, self.service.migration_economics_specification())
            return
        if path == "/migration/economics-invariants":
            self._respond(HTTPStatus.OK, self.service.migration_economics_invariant_report())
            return
        if path == "/migration/governance-quorum":
            self._respond(HTTPStatus.OK, self.service.migration_governance_quorum_report())
            return
        if path == "/migration/proof-registry":
            self._respond(HTTPStatus.OK, self.service.migration_proof_registry_report())
            return
        if path == "/wallet/utxo-spendability":
            query = parse_qs(parsed.query)
            addresses = query.get("address", [])
            self._respond(HTTPStatus.OK, self.service.utxo_spendability_report(addresses or None))
            return
        if path == "/migration/economics-governance":
            self._respond(HTTPStatus.OK, self.service.signed_migration_economics_governance_manifest())
            return
        if path == "/migration/economics-adversarial":
            self._respond(HTTPStatus.OK, self.service.migration_adversarial_economics_simulation_report())
            return
        if path == "/migration/proof-coverage":
            self._respond(HTTPStatus.OK, self.service.migration_source_proof_coverage_report())
            return
        if path == "/migration/snapshot-attestations":
            self._respond(HTTPStatus.OK, self.service.migration_snapshot_attestation_readiness())
            return
        if path == "/migration/dispute-packet":
            query = parse_qs(parsed.query)
            classical_address = query.get("classical_address", [""])[0]
            try:
                packet = self.service.migration_dispute_packet(classical_address)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, packet)
            return
        if path == "/migration/disputes":
            query = parse_qs(parsed.query)
            classical_address = query.get("classical_address", [None])[0]
            self._respond(HTTPStatus.OK, self.service.migration_disputes(classical_address))
            return
        if path == "/network/peer-diversity":
            self._respond(HTTPStatus.OK, self.service.peer_diversity_report())
            return
        if path == "/migration/networks":
            self._respond(HTTPStatus.OK, self.service.migration_network_profiles())
            return
        if path == "/migration/report":
            query = parse_qs(parsed.query)
            source_network = query.get("source_network", [None])[0]
            self._respond(HTTPStatus.OK, self.service.migration_audit_report(source_network=source_network))
            return
        if path == "/migration/integrity":
            query = parse_qs(parsed.query)
            source_network = query.get("source_network", [None])[0]
            self._respond(HTTPStatus.OK, self.service.migration_integrity_report(source_network=source_network))
            return
        if path == "/migration/claims/receipt":
            query = parse_qs(parsed.query)
            classical_address = query.get("classical_address", [""])[0]
            sign = query.get("sign", ["true"])[0].lower() not in {"0", "false", "no"}
            if sign and not self._authorize_operator():
                return
            try:
                receipt = self.service.migration_claim_receipt(classical_address, sign=sign)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, receipt)
            return
        if path == "/migration/claims/quote":
            query = parse_qs(parsed.query)
            classical_address = query.get("classical_address", [""])[0]
            try:
                quote = self.service.migration_claim_quote(classical_address)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, quote)
            return
        if path == "/migration/claims/status":
            query = parse_qs(parsed.query)
            classical_address = query.get("classical_address", [""])[0]
            try:
                status = self.service.migration_claim_status(classical_address)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, status)
            return
        if path == "/migration/snapshots":
            self._respond(HTTPStatus.OK, {"snapshots": self.service.list_migration_snapshots()})
            return
        if path == "/migration/sources":
            self._respond(HTTPStatus.OK, {"sources": self.service.list_migration_sources()})
            return
        if path == "/wallets/status":
            query = parse_qs(parsed.query)
            label = query.get("label", [None])[0]
            provider_id = query.get("provider_id", [None])[0]
            self._respond(
                HTTPStatus.OK,
                self.service.wallet_key_statuses(label=label, provider_id=provider_id),
            )
            return
        if path == "/peers":
            self._respond(HTTPStatus.OK, {"peers": self.service.list_peers()})
            return
        if path == "/blocks":
            query = parse_qs(parsed.query)
            start_height = int(query.get("start_height", ["0"])[0])
            blocks = [block.to_dict() for block in self.service.get_blocks_from_height(start_height)]
            self._respond(HTTPStatus.OK, {"blocks": blocks})
            return
        if path.startswith("/blocks/"):
            height = int(path.split("/")[2])
            block = self.service.get_block(height)
            if block is None:
                self._respond(HTTPStatus.NOT_FOUND, {"error": "Block not found"})
                return
            self._respond(HTTPStatus.OK, block.to_dict())
            return
        if path.startswith("/addresses/") and path.endswith("/balance"):
            address = path.split("/")[2]
            self._respond(HTTPStatus.OK, self.service.formatted_balance_for_address(address))
            return
        if path.startswith("/addresses/") and path.endswith("/utxos"):
            address = path.split("/")[2]
            payload = {
                "address": address,
                "utxos": [
                    {
                        "tx_id": tx_id,
                        "output_index": output_index,
                        "recipient": output.recipient,
                        "amount": output.amount,
                    }
                    for tx_id, output_index, output in self.service.list_utxos([address])
                ],
            }
            self._respond(HTTPStatus.OK, payload)
            return
        self._respond(HTTPStatus.NOT_FOUND, {"error": "Not found"})
