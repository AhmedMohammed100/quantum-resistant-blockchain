from __future__ import annotations

from http import HTTPStatus
from urllib.parse import urlparse

from .api_common import RequestBodyTooLarge
from .models import Block, Transaction
from .protocol import parse_peer_frame


class PostRoutesMixin:
    def do_POST(self) -> None:
        path = urlparse(self.path).path
        # Peer routes carry their own signed protocol envelope. Public
        # transaction submission is rate-limited. Every other route requires
        # operator authentication before an untrusted body is read or decoded.
        public_post_paths = {"/transactions"}
        if path == "/transactions" and not self._allow_public_transaction():
            self.close_connection = True
            return
        if not path.startswith("/peer/") and path not in public_post_paths:
            if not self._authorize_operator():
                # The request body is intentionally unread; close the socket so
                # it cannot be interpreted as another HTTP request.
                self.close_connection = True
                return
        try:
            payload = self._read_json()
        except RequestBodyTooLarge as error:
            self._respond(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": str(error)})
            return
        except (ValueError, UnicodeDecodeError) as error:
            self._respond(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON request: {error}"})
            return


        if path == "/transactions":
            try:
                transaction = Transaction.from_dict(payload)
                self.service.submit_transaction(transaction)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, {"tx_id": transaction.tx_id})
            return

        if path == "/mine":
            miner_address = str(payload.get("miner_address", ""))
            if not miner_address:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "miner_address is required"})
                return
            try:
                block = self.service.mine_pending_transactions(miner_address)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, {"height": block.index, "block_hash": block.block_hash, "transaction_count": len(block.transactions)})
            return

        if path == "/peers":
            peer_url = str(payload.get("url", ""))
            if not peer_url:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "url is required"})
                return
            try:
                normalized = self.service.register_peer(peer_url)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, {"url": normalized})
            return

        if path == "/sync":
            peer_url = str(payload.get("peer_url", ""))
            try:
                if peer_url:
                    imported = self.service.sync_with_peer(peer_url)
                    self._respond(HTTPStatus.OK, {"peer_url": peer_url, "imported_blocks": imported})
                else:
                    self._respond(HTTPStatus.OK, {"results": self.service.sync_with_peers()})
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return

        if path == "/migration/sources":
            classical_address = str(payload.get("classical_address", ""))
            provider_id = str(payload.get("provider_id", ""))
            source_network = str(payload.get("source_network", ""))
            amount = int(payload.get("amount", 0))
            if not classical_address or not provider_id or not source_network:
                self._respond(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "classical_address, provider_id, and source_network are required"},
                )
                return
            try:
                source = self.service.seed_migration_source(
                    classical_address=classical_address,
                    provider_id=provider_id,
                    source_network=source_network,
                    amount=amount,
                    snapshot_ref=str(payload.get("snapshot_ref", "")),
                    source_address=str(payload.get("source_address", "")),
                    source_address_format=str(payload.get("source_address_format", "")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, source)
            return

        if path == "/migration/disputes":
            classical_address = str(payload.get("classical_address", ""))
            reason = str(payload.get("reason", ""))
            if not classical_address or not reason:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "classical_address and reason are required"})
                return
            try:
                dispute = self.service.open_migration_dispute(
                    classical_address,
                    reason=reason,
                    evidence_hash=str(payload.get("evidence_hash", "")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, dispute)
            return

        if path == "/migration/disputes/evidence":
            dispute_id = str(payload.get("dispute_id", ""))
            if not dispute_id:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "dispute_id is required"})
                return
            try:
                evidence = payload.get("evidence", {})
                if not isinstance(evidence, dict):
                    raise ValueError("evidence must be an object")
                dispute = self.service.submit_migration_dispute_evidence(
                    dispute_id,
                    evidence=evidence,
                    evidence_hash=str(payload.get("evidence_hash", "")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, dispute)
            return

        if path == "/migration/disputes/resolve":
            dispute_id = str(payload.get("dispute_id", ""))
            outcome = str(payload.get("outcome", ""))
            note = str(payload.get("resolution_note", ""))
            if not dispute_id or not outcome or not note:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "dispute_id, outcome, and resolution_note are required"})
                return
            try:
                dispute = self.service.resolve_migration_dispute(
                    dispute_id,
                    outcome=outcome,
                    resolution_note=note,
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, dispute)
            return

        if path == "/migration/post-finality-fraud-case":
            classical_address = str(payload.get("classical_address", ""))
            evidence = payload.get("evidence", {})
            if not classical_address:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "classical_address is required"})
                return
            if not isinstance(evidence, dict):
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "evidence must be an object"})
                return
            try:
                fraud_case = self.service.post_finality_migration_fraud_case(
                    classical_address,
                    evidence=evidence,
                    requested_action=str(payload.get("requested_action", "freeze_destination_outputs")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, fraud_case)
            return

        if path == "/migration/post-finality-fraud-validate":
            result = self.service.validate_post_finality_migration_fraud_case(payload)
            self._respond(HTTPStatus.OK if result["valid"] else HTTPStatus.BAD_REQUEST, result)
            return

        if path == "/migration/economics-governance-validate":
            result = self.service.validate_migration_economics_governance_manifest(payload)
            self._respond(HTTPStatus.OK if result["valid"] else HTTPStatus.BAD_REQUEST, result)
            return

        if path == "/migration/governance-approval":
            try:
                approval = self.service.sign_migration_governance_approval(
                    action=str(payload.get("action", "")),
                    artifact_hash=str(payload.get("artifact_hash", "")),
                    note=str(payload.get("note", "")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, approval)
            return

        if path == "/migration/governance-quorum":
            approvals = payload.get("approvals", [])
            if not isinstance(approvals, list):
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "approvals must be a list"})
                return
            self._respond(HTTPStatus.OK, self.service.migration_governance_quorum_report([dict(item) for item in approvals]))
            return

        if path == "/migration/escrow-transition":
            try:
                transition = self.service.migration_escrow_transition_artifact(
                    str(payload.get("classical_address", "")),
                    action=str(payload.get("action", "")),
                    reason=str(payload.get("reason", "")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, transition)
            return

        if path == "/migration/fraud-recovery-decision":
            classical_address = str(payload.get("classical_address", ""))
            outcome = str(payload.get("outcome", ""))
            recovery_action = str(payload.get("recovery_action", ""))
            note = str(payload.get("note", ""))
            if not classical_address or not outcome or not recovery_action or not note:
                self._respond(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "classical_address, outcome, recovery_action, and note are required"},
                )
                return
            try:
                decision = self.service.signed_migration_fraud_recovery_decision(
                    classical_address,
                    outcome=outcome,
                    recovery_action=recovery_action,
                    note=note,
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, decision)
            return

        if path == "/migration/snapshots/export":
            try:
                exported = self.service.export_migration_snapshot(
                    source_network=str(payload.get("source_network", "")),
                    snapshot_ref=str(payload.get("snapshot_ref", "")),
                    include_claimed=bool(payload.get("include_claimed", False)),
                    include_inactive=bool(payload.get("include_inactive", False)),
                    sign=bool(payload.get("sign", False)),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, exported)
            return

        if path == "/migration/source-exports/normalize":
            try:
                normalized = self.service.normalize_source_export_snapshot(
                    payload,
                    sign=bool(payload.get("sign", False)),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, normalized)
            return

        if path == "/migration/source-exports/batch-normalize":
            try:
                exports = payload.get("exports", [])
                if not isinstance(exports, list):
                    raise ValueError("exports must be a list.")
                normalized = self.service.normalize_source_export_batch([dict(item) for item in exports])
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, normalized)
            return

        if path == "/migration/source-exports/runbook":
            try:
                runbook = self.service.source_ingestion_runbook(payload)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, runbook)
            return

        if path == "/migration/source-exports/manifest-status":
            try:
                status = self.service.source_ingestion_manifest_status(payload)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, status)
            return

        if path == "/migration/source-exports/approve":
            try:
                approval = self.service.approve_source_ingestion(
                    dict(payload.get("normalized", payload)),
                    operator=str(payload.get("operator", "")),
                    decision=str(payload.get("decision", "approved")),
                    reason=str(payload.get("reason", "")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, approval)
            return

        if path == "/migration/source-exports/import-plan":
            try:
                plan = self.service.source_ingestion_import_plan(
                    dict(payload.get("normalized", payload)),
                    approval=dict(payload["approval"]) if isinstance(payload.get("approval"), dict) else None,
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, plan)
            return

        if path == "/migration/source-exports/import-approved":
            try:
                result = self.service.import_approved_source_ingestion(
                    dict(payload.get("normalized", {})),
                    approval=dict(payload.get("approval", {})),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, result)
            return

        if path == "/operations/consensus-upgrade-validate":
            result = self.service.validate_consensus_upgrade_manifest_artifact(payload)
            self._respond(HTTPStatus.OK if result["valid"] else HTTPStatus.BAD_REQUEST, result)
            return

        if path == "/operations/native-release-provenance-validate":
            result = self.service.validate_native_crypto_release_provenance(payload)
            self._respond(HTTPStatus.OK if result["valid"] else HTTPStatus.BAD_REQUEST, result)
            return

        if path == "/operations/soak-result-artifact":
            try:
                result_payload = payload.get("result", payload)
                if not isinstance(result_payload, dict):
                    raise ValueError("result must be an object")
                artifact = self.service.build_soak_result_artifact(result_payload)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, artifact)
            return

        if path == "/operations/soak-result-validate":
            result = self.service.validate_soak_result_artifact(payload)
            self._respond(HTTPStatus.OK if result["valid"] else HTTPStatus.BAD_REQUEST, result)
            return

        if path == "/operations/database-recovery-validate":
            result = self.service.validate_database_recovery_manifest(payload)
            self._respond(HTTPStatus.OK if result["valid"] else HTTPStatus.BAD_REQUEST, result)
            return

        if path == "/operations/external-audit-package-validate":
            result = self.service.validate_external_audit_readiness_package(payload)
            self._respond(HTTPStatus.OK if result["valid"] else HTTPStatus.BAD_REQUEST, result)
            return

        if path == "/operations/project-audit-bundle-validate":
            result = self.service.validate_project_audit_bundle(payload)
            self._respond(HTTPStatus.OK if result["valid"] else HTTPStatus.BAD_REQUEST, result)
            return

        if path == "/migration/snapshots/reconcile":
            try:
                report = self.service.reconcile_migration_snapshot(payload)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, report)
            return

        if path == "/migration/claims/preflight":
            try:
                report = self.service.preflight_migration_claim(
                    destination_address=str(payload.get("destination_address", "")),
                    classical_address=str(payload.get("classical_address", "")),
                    classical_provider_id=str(payload.get("classical_provider_id", "")),
                    source_network=str(payload.get("source_network", "")),
                    snapshot_ref=str(payload.get("snapshot_ref", "")),
                    classical_public_key=payload.get("classical_public_key"),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, report)
            return

        if path == "/migration/claims/quote":
            try:
                quote = self.service.migration_claim_quote(str(payload.get("classical_address", "")))
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, quote)
            return

        if path == "/migration/claims/package":
            try:
                package = self.service.build_wallet_migration_claim_package(
                    destination_address=str(payload.get("destination_address", "")),
                    classical_address=str(payload.get("classical_address", "")),
                    classical_provider_id=str(payload.get("classical_provider_id", "")),
                    source_network=str(payload.get("source_network", "")),
                    snapshot_ref=str(payload.get("snapshot_ref", "")),
                    classical_public_key=payload.get("classical_public_key"),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, package)
            return

        if path == "/migration/snapshots/status":
            try:
                snapshot = self.service.set_migration_snapshot_status(
                    str(payload.get("snapshot_ref", "")),
                    status=str(payload.get("status", "")),
                    reason=str(payload.get("reason", "")),
                    cascade_sources=bool(payload.get("cascade_sources", True)),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, snapshot)
            return

        if path == "/migration/sources/status":
            try:
                source = self.service.set_migration_source_status(
                    str(payload.get("classical_address", "")),
                    status=str(payload.get("status", "")),
                    reason=str(payload.get("reason", "")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, source)
            return

        if path == "/migration/snapshots":
            try:
                snapshot = self.service.import_migration_snapshot(payload)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, snapshot)
            return

        if path == "/migration/snapshots/sign":
            try:
                signed_snapshot = self.service.sign_migration_snapshot(payload)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, signed_snapshot)
            return

        if path == "/wallets/recovery":
            label = str(payload.get("label", ""))
            address = str(payload.get("address", ""))
            provider_id = str(payload.get("provider_id", ""))
            if not label or not address or not provider_id:
                self._respond(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "label, address, and provider_id are required"},
                )
                return
            try:
                response = self.service.recover_wallet_key(
                    label,
                    address,
                    provider_id,
                    note=str(payload.get("note", "operator acknowledged interrupted signer reservation")),
                )
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, response)
            return

        if path == "/peer/handshake":
            try:
                _, auth = parse_peer_frame(
                    payload,
                    expected_protocol_version=self.service.config.peer_protocol_version,
                    expected_message_type="peer_handshake_request",
                )
                response = self.service.accept_peer_handshake(auth)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, response)
            return

        if path == "/peer/summary":
            try:
                _, auth = parse_peer_frame(
                    payload,
                    expected_protocol_version=self.service.config.peer_protocol_version,
                    expected_message_type="peer_summary_request",
                )
                response = self.service.authenticated_chain_summary(auth)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, response)
            return

        if path == "/peer/blocks":
            try:
                frame_payload, auth = parse_peer_frame(
                    payload,
                    expected_protocol_version=self.service.config.peer_protocol_version,
                    expected_message_type="peer_blocks_request",
                )
                start_height = int(frame_payload.get("start_height", 0))
                response = self.service.authenticated_blocks(auth, start_height)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, response)
            return

        if path == "/peer/gossip/transaction":
            try:
                frame_payload, auth = parse_peer_frame(
                    payload,
                    expected_protocol_version=self.service.config.peer_protocol_version,
                    expected_message_type="peer_transaction_gossip",
                )
                transaction_payload = frame_payload.get("transaction", {})
                if not isinstance(transaction_payload, dict):
                    raise ValueError("Transaction gossip payload is invalid.")
                response = self.service.receive_authenticated_transaction_gossip(auth, transaction_payload)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, response)
            return

        if path == "/peer/gossip/block":
            try:
                frame_payload, auth = parse_peer_frame(
                    payload,
                    expected_protocol_version=self.service.config.peer_protocol_version,
                    expected_message_type="peer_block_gossip",
                )
                block_payload = frame_payload.get("block", {})
                if not isinstance(block_payload, dict):
                    raise ValueError("Block gossip payload is invalid.")
                response = self.service.receive_authenticated_block_gossip(auth, block_payload)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.OK, response)
            return

        if path == "/blocks":
            try:
                block = Block.from_dict(payload)
                self.service.import_block(block)
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, {"height": block.index, "block_hash": block.block_hash})
            return

        if path == "/genesis":
            allocations = payload.get("allocations", {})
            if not isinstance(allocations, dict):
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "allocations must be an object"})
                return
            try:
                block = self.service.create_genesis_block({str(key): int(value) for key, value in allocations.items()})
            except ValueError as error:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._respond(HTTPStatus.CREATED, {"height": block.index, "block_hash": block.block_hash})
            return

        self._respond(HTTPStatus.NOT_FOUND, {"error": "Not found"})
