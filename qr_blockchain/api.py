from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlparse

from .config import NodeConfig
from .models import Transaction
from .service import NodeService


class NodeRequestHandler(BaseHTTPRequestHandler):
    service: NodeService

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._respond(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/chain/summary":
            self._respond(HTTPStatus.OK, self.service.chain_summary())
            return
        if path.startswith("/addresses/") and path.endswith("/balance"):
            address = path.split("/")[2]
            self._respond(HTTPStatus.OK, {"address": address, "balance": self.service.balance_for_address(address)})
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
