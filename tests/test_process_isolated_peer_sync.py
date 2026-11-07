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
            default_signature_provider="native_test_pq_v1",
            max_peer_blocks_per_request=32,
            deployment_mode="test",
        )
        service = NodeService(config)
        if service.chain_summary()["height"] == 0:
            service.create_genesis_block({"shared-bootstrap": 1_000})
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
    ):
        (root / node_name).mkdir(parents=True, exist_ok=True)
        process = context.Process(
            target=_serve_node_process,
            args=(str(root), node_name, port, ready_queue, advertised_url),
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

