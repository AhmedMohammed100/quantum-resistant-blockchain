from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import parse_qs, urlparse

from .config import NodeConfig
from .models import Block, Transaction
from .protocol import parse_peer_frame
from .service import NodeService


class NodeRequestHandler(BaseHTTPRequestHandler):
    service: NodeService

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
        if path == "/transactions/resource-policy":
            self._respond(HTTPStatus.OK, self.service.transaction_resource_policy_report())
            return
        if path == "/consensus/economics":
            self._respond(HTTPStatus.OK, self.service.consensus_economics_report())
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

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        payload = self._read_json()

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

    def log_message(self, format: str, *args: object) -> None:
        return

    def _read_json(self) -> dict[str, object]:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length else b"{}"
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _respond(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def serve(config: NodeConfig) -> None:
    service = NodeService(config)

    class Handler(NodeRequestHandler):
        pass

    Handler.service = service
    server = ThreadingHTTPServer((config.host, config.port), Handler)
    print(f"Quantum-resistant node listening on http://{config.host}:{config.port}")
    server.serve_forever()
