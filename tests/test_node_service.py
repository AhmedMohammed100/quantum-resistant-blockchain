"""Compatibility entry point for the focused NodeService regression suites."""

import unittest

from node_service_reports_tests import NodeServiceReportTests
from node_service_chain_tests import NodeServiceChainTests
from node_service_migration_tests import NodeServiceMigrationTests
from node_service_network_tests import NodeServiceNetworkTests
from node_service_wallet_tests import NodeServiceWalletTests


# Preserve the historical import name for existing test runners and scripts.
NodeServiceTests = NodeServiceReportTests


if __name__ == "__main__":
    unittest.main()
