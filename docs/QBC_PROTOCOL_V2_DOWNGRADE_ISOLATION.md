# QBC v2 Downgrade and Mixed-Version Isolation Tests

**Status:** opt-in adversarial conformance evidence for the isolated v2 test profile. This does not activate v2 or alter v0.1 behavior.

The new tests/test_protocol_v2_downgrade.py suite exercises the Python node's loopback peer interface with legacy v0.1, unversioned, future-version, malformed, and network-mismatched handshake responses. A rejected handshake must stop synchronization before the node requests the peer's blocks. Tests also cover a matching v2 handshake followed by a conflicting genesis, durable-state preservation across restart, and recovery by later syncing with a correctly pinned v2 peer.

The matrix verifies the existing strict policy: protocol version, chain ID, manifest digest, and genesis hash must all match exactly. There is no downgrade, fallback, or protocol inference. These tests establish isolation properties for the Python peer path; they do not establish mixed-version interoperability or production cryptographic support. Go consensus conformance is chain-validation-only and does not implement peer transport.

This stage closes a test-coverage gap in the activation checklist. Production activation still requires external protocol/security and operational review, production cryptographic providers and vectors, and a separately approved new-network launch.
