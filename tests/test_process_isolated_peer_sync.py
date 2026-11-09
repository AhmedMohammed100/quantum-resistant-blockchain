"""Process-isolated authenticated peer sync and restart coverage."""

import json
import http.client
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def _serve_node_process(
    root_text: str,
    node_name: str,
    port: int | None,
    ready_queue,
    advertised_url: str | None = None,
    signature_provider: str = "native_test_pq_v1",
    genesis_address: str = "shared-bootstrap",
) -> None:
    server = None
    ready = False
    try:
        from qr_blockchain.api import BoundedThreadingHTTPServer, NodeRequestHandler
        from qr_blockchain.config import NodeConfig
        from qr_blockchain.service import NodeService

        bind_port = 0 if port is None else port
        server = BoundedThreadingHTTPServer(("127.0.0.1", bind_port), NodeRequestHandler)
        actual_port = int(server.server_address[1])
        url = f"http://127.0.0.1:{actual_port}"
        node_root = Path(root_text) / node_name
        config = NodeConfig(
            db_path=node_root / "chain.db",
            wallet_state_db_path=node_root / "wallet.db",
            difficulty=1,
            mining_reward=10,
            min_transaction_fee=1,
            chain_id="qbc-process-sync-test",
            node_id=f"process-{node_name}",
            advertised_url=advertised_url or url,
            default_signature_provider=signature_provider,
            max_peer_blocks_per_request=32,
            deployment_mode="test",
        )
        service = NodeService(config)
        if service.chain_summary()["height"] == 0:
            service.create_genesis_block({genesis_address: 1_000})
        handler = type(f"ProcessHandler_{node_name}", (NodeRequestHandler,), {"service": service})
        server.RequestHandlerClass = handler
        ready_queue.put({"node": node_name, "url": url, "port": actual_port, "advertised_url": advertised_url or url})
        ready = True
        server.serve_forever()
    except BaseException as error:
        if not ready:
            ready_queue.put({"node": node_name, "error": f"{type(error).__name__}: {error}"})
        raise
    finally:
        if server is not None:
            server.server_close()


def _request_json(url: str, path: str, *, payload: dict[str, object] | None = None) -> dict[str, object]:
    data = None if payload is None else json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {} if data is None else {"Content-Type": "application/json"}
    request = Request(f"{url}{path}", data=data, headers=headers, method="GET" if data is None else "POST")
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


class ProcessIsolatedPeerSyncTests(unittest.TestCase):
    def _start_node(
        self,
        context,
        ready_queue,
        root: Path,
        node_name: str,
        port: int | None = None,
        advertised_url: str | None = None,
        signature_provider: str = "native_test_pq_v1",
        genesis_address: str = "shared-bootstrap",
    ):
        (root / node_name).mkdir(parents=True, exist_ok=True)
        process = context.Process(
            target=_serve_node_process,
            args=(str(root), node_name, port, ready_queue, advertised_url, signature_provider, genesis_address),
            name=f"qbc-node-{node_name}",
        )
        process.start()
        try:
            ready = ready_queue.get(timeout=30)
        except Exception:
            if process.is_alive():
                process.terminate()
            process.join(timeout=10)
            raise
        if ready.get("error"):
            process.join(timeout=10)
            self.fail(f"Node process {node_name} failed to start: {ready['error']}")
        self.assertEqual(ready.get("node"), node_name)
        return process, ready

    def test_real_mldsa_transaction_converges_across_three_process_nodes(self) -> None:
        from qr_blockchain.chain_verifier import verify_chain
        from qr_blockchain.crypto import get_signature_provider
        from qr_blockchain.models import Transaction, TxInput, TxOutput
        from qr_blockchain.signer import Wallet

        context = multiprocessing.get_context("spawn")
        processes = []
        ready_queue = context.Queue()
        signature_provider = "mldsa65_oqs_v1"
        chain_id = "qbc-process-sync-test"
        rounds = int(os.environ.get("QBC_MLDSA_SOAK_ROUNDS", "1"))
        if not 1 <= rounds <= 499:
            self.fail("QBC_MLDSA_SOAK_ROUNDS must be between 1 and 499.")
        environment = {
            "QR_CHAIN_MLDSA_BACKEND_MODULE": "qr_chain_mldsa_backend",
            "QR_CHAIN_MLDSA_OQS_MECHANISM": "ML-DSA-65",
            "QR_CHAIN_DEPLOYMENT_MODE": "test",
            "PYOQS_VERSION": "0.16.0",
        }
        try:
            with patch.dict(os.environ, environment):
                provider = get_signature_provider(signature_provider)
                status = provider.backend_status()
                if status.get("available") is not True:
                    self.skipTest(f"Real ML-DSA runtime is unavailable: {status.get('error', 'unknown error')}")

                sender = Wallet("e2e-sender", signature_provider=signature_provider)
                recipient = Wallet("e2e-recipient", signature_provider=signature_provider)
                miner = Wallet("e2e-miner", signature_provider=signature_provider)
                sender_address = sender.create_address()
                recipient_address = recipient.create_address()
                miner_address = miner.create_address()

                with tempfile.TemporaryDirectory(prefix="qbc-real-mldsa-multinode-") as temporary_root:
                    root = Path(temporary_root)
                    nodes = []
                    for node_name in ("leader", "validator-b", "validator-c"):
                        process, ready = self._start_node(
                            context,
                            ready_queue,
                            root,
                            node_name,
                            signature_provider=signature_provider,
                            genesis_address=sender_address,
                        )
                        processes.append(process)
                        nodes.append(ready)

                    leader_url = str(nodes[0]["url"])
                    genesis = _request_json(leader_url, "/blocks")["blocks"][0]["transactions"][0]
                    previous_tx_id = str(genesis["tx_id"])
                    sender_balance = 1_000
                    started = time.perf_counter()
                    for round_number in range(1, rounds + 1):
                        transaction = Transaction(
                            inputs=[
                                TxInput(
                                    prev_tx_id=previous_tx_id,
                                    output_index=0 if round_number == 1 else 1,
                                )
                            ],
                            outputs=[
                                TxOutput(recipient=recipient_address, amount=1),
                                TxOutput(recipient=sender_address, amount=sender_balance - 2),
                            ],
                            chain_id=chain_id,
                            signature_scheme=signature_provider,
                            fee=1,
                        )
                        signing_result = sender._signer.sign_for_address(
                            sender_address,
                            transaction.signing_payload(),
                        )
                        transaction.inputs[0].public_key = signing_result.public_key
                        transaction.inputs[0].signature = signing_result.signature
                        transaction.finalize()

                        submitted = _request_json(
                            leader_url,
                            "/transactions",
                            payload=json.loads(transaction.serialize_with_id()),
                        )
                        self.assertEqual(submitted["tx_id"], transaction.tx_id)
                        _request_json(leader_url, "/mine", payload={"miner_address": miner_address})
                        previous_tx_id = transaction.tx_id
                        sender_balance -= 2

                        leader_summary = _request_json(leader_url, "/chain/summary")
                        for node in nodes[1:]:
                            node_url = str(node["url"])
                            sync_result = _request_json(node_url, "/sync", payload={"peer_url": leader_url})
                            self.assertEqual(
                                sync_result["imported_blocks"],
                                1,
                                f"sync failed at round {round_number}",
                            )
                            summary = _request_json(node_url, "/chain/summary")
                            self.assertEqual(
                                summary["best_head_hash"],
                                leader_summary["best_head_hash"],
                                f"chain tips diverged at round {round_number}",
                            )

                    duration_seconds = time.perf_counter() - started
                    leader_summary = _request_json(leader_url, "/chain/summary")
                    leader_blocks = _request_json(leader_url, "/blocks")["blocks"]
                    verifier_report = verify_chain(
                        leader_blocks,
                        chain_id=chain_id,
                        subsidy_at_height=lambda height: 10 if height > 0 else 0,
                        difficulty=1,
                        state_root_activation_height=0,
                    )
                    self.assertTrue(verifier_report["valid"], verifier_report.get("error"))
                    self.assertEqual(verifier_report["best_head_hash"], leader_summary["best_head_hash"])

                    for node in nodes[1:]:
                        node_url = str(node["url"])
                        summary = _request_json(node_url, "/chain/summary")
                        self.assertEqual(summary["best_head_hash"], leader_summary["best_head_hash"])
                        self.assertEqual(
                            _request_json(node_url, f"/addresses/{recipient_address}/balance")["amount"],
                            rounds,
                        )
                        self.assertEqual(
                            _request_json(node_url, f"/addresses/{miner_address}/balance")["amount"],
                            11 * rounds,
                        )
                        self.assertEqual(
                            _request_json(node_url, f"/addresses/{sender_address}/balance")["amount"],
                            sender_balance,
                        )
                        self.assertEqual(_request_json(node_url, "/blocks")["blocks"], leader_blocks)

                    report = {
                        "soak_version": 1,
                        "provider": signature_provider,
                        "node_count": len(nodes),
                        "rounds_requested": rounds,
                        "transactions_mined": rounds,
                        "validator_syncs_completed": (len(nodes) - 1) * rounds,
                        "blocks_including_genesis": len(leader_blocks),
                        "duration_seconds": duration_seconds,
                        "transactions_per_second": rounds / max(duration_seconds, 1e-12),
                        "chain_tip_hash": leader_summary["best_head_hash"],
                        "chain_tip_height": leader_summary["height"],
                        "verifier_blocks_checked": verifier_report["blocks_checked"],
                        "all_validators_converged": True,
                        "recipient_balance": rounds,
                        "miner_balance": 11 * rounds,
                        "sender_balance": sender_balance,
                    }
                    report_path = os.environ.get("QBC_MLDSA_SOAK_REPORT_FILE", "")
                    if report_path:
                        output_path = Path(report_path)
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        output_path.write_text(
                            json.dumps(report, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8",
                        )
                    print("MLDSA_MULTINODE_SOAK_REPORT=" + json.dumps(report, sort_keys=True))
        finally:
            for process in reversed(processes):
                if process.is_alive():
                    process.terminate()
                process.join(timeout=10)
                if not process.is_alive():
                    process.close()
            ready_queue.close()
            ready_queue.join_thread()

    def _stop_process(self, process) -> None:
        if process.is_alive():
            process.terminate()
        process.join(timeout=10)
        self.assertFalse(process.is_alive(), f"Node process {process.name} did not stop.")
        process.close()

    def _start_fault_proxy(self):
        state = {"upstream": "", "partitioned": False, "fail_next": {}, "delay_seconds": 0.0, "paths": []}
        lock = threading.Lock()

        class FaultProxyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            forwarded_routes = {
                "/peer/handshake": "/peer/handshake",
                "/peer/summary": "/peer/summary",
                "/peer/blocks": "/peer/blocks",
            }

            def do_POST(self):
                route = self.forwarded_routes.get(self.path)
                if route is None:
                    self.send_error(404, "proxy route is not allowed")
                    return
                with lock:
                    state["paths"].append(self.path)
                    upstream_url = state["upstream"]
                    partitioned = state["partitioned"]
                    delay_seconds = state["delay_seconds"]
                    fail_count = state["fail_next"].get(self.path, 0)
                    if fail_count:
                        state["fail_next"][self.path] = fail_count - 1

                if partitioned or fail_count:
                    body = b'{"error":"simulated peer network failure"}'
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if not upstream_url:
                    self.send_error(502, "proxy upstream is not ready")
                    return
                upstream = urlsplit(upstream_url)
                if (
                    upstream.scheme != "http"
                    or upstream.hostname != "127.0.0.1"
                    or upstream.port is None
                    or upstream.username is not None
                    or upstream.password is not None
                    or upstream.path
                    or upstream.query
                    or upstream.fragment
                ):
                    self.send_error(502, "proxy upstream must be a loopback HTTP authority")
                    return
                if delay_seconds:
                    time.sleep(delay_seconds)

                payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                connection = http.client.HTTPConnection("127.0.0.1", upstream.port, timeout=10)
                try:
                    connection.request(
                        "POST",
                        route,
                        body=payload,
                        headers={"Content-Type": "application/json", "Accept": "application/json"},
                    )
                    response = connection.getresponse()
                    status, response_body = response.status, response.read()
                    content_type = response.getheader("Content-Type", "application/json")
                except OSError:
                    status, response_body, content_type = 502, b'{"error":"upstream unavailable"}', "application/json"
                finally:
                    connection.close()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), FaultProxyHandler)
        thread = threading.Thread(target=server.serve_forever, name="qbc-fault-proxy", daemon=True)
        thread.start()
        proxy_url = f"http://127.0.0.1:{server.server_port}"
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 5)
        return proxy_url, state, lock

    def test_two_process_peer_sync_survives_target_restart(self) -> None:
        context = multiprocessing.get_context("spawn")
        processes = []
        ready_queue = context.Queue()
        try:
            with tempfile.TemporaryDirectory(prefix="qbc-process-peer-sync-") as temporary_root:
                root = Path(temporary_root)
                try:
                    with patch.dict(os.environ, {"QR_CHAIN_NATIVE_SIGNER_MODE": "deterministic-test"}):
                        source_process, source_ready = self._start_node(context, ready_queue, root, "source")
                        processes.append(source_process)
                        target_process, target_ready = self._start_node(context, ready_queue, root, "target")
                        processes.append(target_process)

                        source_url = str(source_ready["url"])
                        target_url = str(target_ready["url"])
                        for _ in range(8):
                            _request_json(source_url, "/mine", payload={"miner_address": "process-miner"})

                        source_summary = _request_json(source_url, "/chain/summary")
                        sync_result = _request_json(
                            target_url,
                            "/sync",
                            payload={"peer_url": source_url},
                        )
                        self.assertEqual(sync_result["imported_blocks"], 8)

                        target_summary = _request_json(target_url, "/chain/summary")
                        self.assertEqual(target_summary["height"], source_summary["height"])
                        self.assertEqual(target_summary["best_head_hash"], source_summary["best_head_hash"])
                        source_blocks = _request_json(source_url, "/blocks")["blocks"]
                        target_blocks = _request_json(target_url, "/blocks")["blocks"]
                        project_fields = lambda blocks: [
                            (block["block_hash"], block.get("state_root", ""))
                            for block in blocks
                        ]
                        self.assertEqual(project_fields(target_blocks), project_fields(source_blocks))

                        target_port = int(target_ready["port"])
                        self._stop_process(target_process)
                        processes.remove(target_process)

                        restarted_process, restarted_ready = self._start_node(
                            context,
                            ready_queue,
                            root,
                            "target",
                            target_port,
                        )
                        processes.append(restarted_process)
                        self.assertEqual(restarted_ready["url"], target_url)

                        restarted_summary = _request_json(target_url, "/chain/summary")
                        self.assertEqual(restarted_summary["height"], source_summary["height"])
                        self.assertEqual(restarted_summary["best_head_hash"], source_summary["best_head_hash"])
                        self.assertEqual(
                            _request_json(target_url, "/sync", payload={"peer_url": source_url})["imported_blocks"],
                            0,
                        )
                        restarted_blocks = _request_json(target_url, "/blocks")["blocks"]
                        self.assertEqual(project_fields(restarted_blocks), project_fields(source_blocks))
                finally:
                    for process in reversed(processes):
                        if process.is_alive():
                            process.terminate()
                        process.join(timeout=10)
                        if not process.is_alive():
                            process.close()
                    processes.clear()
        finally:
            ready_queue.close()
            ready_queue.join_thread()

    def test_peer_sync_recovers_after_partition_latency_and_dropped_block_response(self) -> None:
        context = multiprocessing.get_context("spawn")
        processes = []
        ready_queue = context.Queue()
        proxy_url, proxy_state, proxy_lock = self._start_fault_proxy()
        try:
            with tempfile.TemporaryDirectory(prefix="qbc-hostile-peer-sync-") as temporary_root:
                root = Path(temporary_root)
                try:
                    with patch.dict(os.environ, {"QR_CHAIN_NATIVE_SIGNER_MODE": "deterministic-test"}):
                        source_process, source_ready = self._start_node(
                            context, ready_queue, root, "source", advertised_url=proxy_url
                        )
                        processes.append(source_process)
                        target_process, target_ready = self._start_node(context, ready_queue, root, "target")
                        processes.append(target_process)
                        source_url = str(source_ready["url"])
                        target_url = str(target_ready["url"])
                        with proxy_lock:
                            proxy_state["upstream"] = source_url

                        for _ in range(3):
                            _request_json(source_url, "/mine", payload={"miner_address": "hostile-network-miner"})

                        with proxy_lock:
                            proxy_state["partitioned"] = True
                        with self.assertRaises(HTTPError) as partition_error:
                            _request_json(target_url, "/sync", payload={"peer_url": proxy_url})
                        self.assertEqual(partition_error.exception.code, 502)

                        # Let the isolated target extend its own branch while
                        # the source continues to hold the longer branch.
                        _request_json(
                            target_url,
                            "/mine",
                            payload={"miner_address": "partition-only-miner"},
                        )

                        with proxy_lock:
                            proxy_state["partitioned"] = False
                            proxy_state["delay_seconds"] = 0.02
                            proxy_state["fail_next"]["/peer/blocks"] = 1
                        with self.assertRaises(HTTPError) as dropped_block_error:
                            _request_json(target_url, "/sync", payload={"peer_url": proxy_url})
                        self.assertEqual(dropped_block_error.exception.code, 502)

                        with proxy_lock:
                            proxy_state["delay_seconds"] = 0.01
                        recovered_sync = _request_json(target_url, "/sync", payload={"peer_url": proxy_url})
                        self.assertEqual(recovered_sync["imported_blocks"], 3)
                        source_summary = _request_json(source_url, "/chain/summary")
                        target_summary = _request_json(target_url, "/chain/summary")
                        self.assertEqual(target_summary["height"], source_summary["height"])
                        self.assertEqual(target_summary["best_head_hash"], source_summary["best_head_hash"])
                        self.assertEqual(
                            _request_json(target_url, "/addresses/partition-only-miner/balance")["amount"],
                            0,
                        )

                        target_port = int(target_ready["port"])
                        self._stop_process(target_process)
                        processes.remove(target_process)
                        restarted_process, restarted_ready = self._start_node(
                            context, ready_queue, root, "target", target_port
                        )
                        processes.append(restarted_process)
                        self.assertEqual(restarted_ready["url"], target_url)
                        self.assertEqual(
                            _request_json(target_url, "/chain/summary")["best_head_hash"],
                            source_summary["best_head_hash"],
                        )
                        self.assertEqual(
                            _request_json(target_url, "/sync", payload={"peer_url": proxy_url})["imported_blocks"],
                            0,
                        )
                        with proxy_lock:
                            paths = tuple(proxy_state["paths"])
                        self.assertIn("/peer/handshake", paths)
                        self.assertIn("/peer/summary", paths)
                        self.assertIn("/peer/blocks", paths)
                finally:
                    for process in reversed(processes):
                        if process.is_alive():
                            process.terminate()
                        process.join(timeout=10)
                        if not process.is_alive():
                            process.close()
                    processes.clear()
        finally:
            ready_queue.close()
            ready_queue.join_thread()


if __name__ == "__main__":
    import unittest

    unittest.main()


