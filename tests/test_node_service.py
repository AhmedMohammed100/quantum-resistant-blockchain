"""Compatibility entry point for the focused NodeService regression suites."""

import unittest

from tests import node_service_reports_tests as reports
from tests import node_service_chain_tests as chain
from tests import node_service_migration_tests as migration
from tests import node_service_network_tests as network
from tests import node_service_wallet_tests as wallet


class NodeServiceTests(
    reports.NodeServiceReportTests,
    chain.NodeServiceChainTests,
    migration.NodeServiceMigrationTests,
    network.NodeServiceNetworkTests,
    wallet.NodeServiceWalletTests,
):
    """Aggregate all focused suites under the historical test class name."""


if __name__ == "__main__":
    unittest.main()
