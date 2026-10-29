from __future__ import annotations

import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from qr_blockchain.api import NodeRequestHandler
from qr_blockchain.chaos import _validate_load_chaos_limits, run_load_chaos_harness
from qr_blockchain.config import NodeConfig


class LoadChaosSecurityTests(unittest.TestCase):
    def _handler(self, *, token: str, authorization: str, bind_host: str):
        handler = NodeRequestHandler.__new__(NodeRequestHandler)
        harness_report = {"passed": True}
        handler.service = SimpleNamespace(
            config=SimpleNamespace(
                api_auth_token=token,
                deployment_mode="production",
            ),
            load_chaos_harness_report=Mock(return_value=harness_report),
        )
        handler.server = SimpleNamespace(server_address=(bind_host, 8080))
        handler.headers = {"Authorization": authorization}
        handler.path = "/testing/load-chaos?scenario=verification&verification_batch_size=4"
        handler.respond = Mock()
        handler._respond = handler.respond
        return handler, harness_report

    def test_exposed_load_chaos_endpoint_requires_operator_auth_before_work(self) -> None:
        handler, _ = self._handler(token="secret", authorization="", bind_host="0.0.0.0")

        handler.do_GET()

        handler.service.load_chaos_harness_report.assert_not_called()
        handler.respond.assert_called_once()
        self.assertEqual(handler.respond.call_args.args[0], HTTPStatus.UNAUTHORIZED)

    def test_authorized_load_chaos_endpoint_runs_requested_bounded_scenario(self) -> None:
        handler, report = self._handler(
            token="secret", authorization="Bearer secret", bind_host="0.0.0.0"
        )

        handler.do_GET()

        handler.service.load_chaos_harness_report.assert_called_once_with(
            scenario="verification",
            node_count=3,
            mempool_transactions=8,
            migration_claims=6,
            verification_batch_size=4,
        )
        handler.respond.assert_called_once_with(HTTPStatus.OK, report)

    def test_harness_rejects_each_resource_limit_outside_bounds(self) -> None:
        cases = (
            ({"node_count": 9}, "node_count"),
            ({"mempool_transactions": 101}, "mempool_transactions"),
            ({"migration_claims": 101}, "migration_claims"),
            ({"verification_batch_size": 257}, "verification_batch_size"),
            ({"node_count": 1}, "node_count"),
            ({"mempool_transactions": -1}, "mempool_transactions"),
        )
        defaults = {
            "node_count": 3,
            "mempool_transactions": 8,
            "migration_claims": 6,
            "verification_batch_size": 8,
        }
        for overrides, field in cases:
            with self.subTest(field=field, value=next(iter(overrides.values()))):
                with self.assertRaisesRegex(ValueError, field):
                    _validate_load_chaos_limits(**(defaults | overrides))

    def test_invalid_request_does_not_create_or_clean_harness_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qbc-load-chaos-limits-") as directory:
            root = Path(directory)
            harness_root = root / "chaos_harness"
            harness_root.mkdir()
            sentinel = harness_root / "preserve.txt"
            sentinel.write_text("existing data", encoding="utf-8")
            config = NodeConfig(
                db_path=root / "chain.db",
                wallet_state_db_path=root / "wallet.db",
                difficulty=1,
            )

            with self.assertRaisesRegex(ValueError, "mempool_transactions"):
                run_load_chaos_harness(
                    base_config=config,
                    scenario="all",
                    mempool_transactions=101,
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing data")


if __name__ == "__main__":
    unittest.main()
