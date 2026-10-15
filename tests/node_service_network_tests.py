"""Focused network tests for NodeService.

Imported by test_node_service.py to preserve the existing unittest entry point.
"""
from tests.node_service_test_support import *
from tests.node_service_test_support import _connect_test_db, _secp256k1_sign


class NodeServiceNetworkTests(NodeServiceTestSupport):
    def test_rejects_peer_frame_with_wrong_protocol_version(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")

        handshake = build_peer_frame(
            protocol_version="qr-peer-wrong",
            message_type="peer_handshake_request",
            payload={},
            auth=target.build_signed_envelope("peer_handshake_v2", {"target_url": source.config.advertised_url}),
        )

        with self.assertRaisesRegex(ValueError, "protocol version"):
            from qr_blockchain.protocol import parse_peer_frame
            parse_peer_frame(
                handshake,
                expected_protocol_version=source.config.peer_protocol_version,
                expected_message_type="peer_handshake_request",
            )

    def test_authenticated_handshake_admits_peer(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")

        response = source.accept_peer_handshake(
            target.build_signed_envelope("peer_handshake_v2", {"target_url": source.config.advertised_url})
        )
        admitted = target._authenticate_peer_envelope(
            response["auth"],
            expected_purpose="peer_handshake_ack_v2",
            require_existing_peer=False,
            require_session=False,
        )
        target._admit_peer(admitted)

        self.assertIn(source.config.advertised_url, target.list_peers())
        self.assertTrue(admitted["claims"]["session_id"])

    def test_authenticated_request_rejects_replayed_nonce(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")

        response = source.accept_peer_handshake(
            target.build_signed_envelope("peer_handshake_v2", {"target_url": source.config.advertised_url})
        )
        admitted = target._authenticate_peer_envelope(
            response["auth"],
            expected_purpose="peer_handshake_ack_v2",
            require_existing_peer=False,
            require_session=False,
        )
        target._admit_peer(admitted)

        target.store.upsert_peer_session(
            session_id=str(admitted["claims"]["session_id"]),
            node_id=source.config.node_id,
            url=source.config.advertised_url,
            created_at=0.0,
            last_seen=0.0,
            expires_at=float(admitted["claims"]["session_expires_at"]),
            status="active",
        )
        envelope = source.build_peer_session_envelope(
            "peer_summary_v2",
            target.config.advertised_url,
            str(admitted["claims"]["session_id"]),
            "/peer/summary",
        )
        target.authenticated_chain_summary(envelope)
        with self.assertRaisesRegex(ValueError, "already been used"):
            target.authenticated_chain_summary(envelope)

    def test_authenticated_request_rejects_invalid_session_binding(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")

        response = target.accept_peer_handshake(
            source.build_signed_envelope("peer_handshake_v2", {"target_url": target.config.advertised_url})
        )
        admitted = source._authenticate_peer_envelope(
            response["auth"],
            expected_purpose="peer_handshake_ack_v2",
            require_existing_peer=False,
            require_session=False,
        )
        source._admit_peer(admitted)
        target.store.upsert_peer_session(
            session_id=str(admitted["claims"]["session_id"]),
            node_id=source.config.node_id,
            url=source.config.advertised_url,
            created_at=0.0,
            last_seen=0.0,
            expires_at=float(admitted["claims"]["session_expires_at"]),
            status="active",
        )

        envelope = source.build_peer_session_envelope(
            "peer_blocks_v2",
            target.config.advertised_url,
            str(admitted["claims"]["session_id"]),
            "/peer/blocks",
            {"start_height": 999},
        )

        with self.assertRaisesRegex(ValueError, "payload binding"):
            target.authenticated_blocks(envelope, start_height=0)

    def test_authenticated_gossip_accepts_transactions_and_penalizes_bad_blocks(self) -> None:
        source = self.make_additional_service("source")
        target = self.make_additional_service("target")
        alice = Wallet("Alice")
        bob = Wallet("Bob")

        funding = alice.create_address()
        source.create_genesis_block({funding: 25})
        target.create_genesis_block({funding: 25})
        response = target.accept_peer_handshake(
            source.build_signed_envelope("peer_handshake_v2", {"target_url": target.config.advertised_url})
        )
        session_id = str(response["payload"]["session_id"])

        transaction = alice.create_transaction(source, bob.create_address(), amount=10, fee=1)
        transaction_payload = json.loads(transaction.serialize_with_id())
        tx_envelope = source.build_peer_session_envelope(
            "peer_transaction_gossip_v1",
            target.config.advertised_url,
            session_id,
            "/peer/gossip/transaction",
            {"transaction": transaction_payload},
        )
        tx_response = target.receive_authenticated_transaction_gossip(tx_envelope, transaction_payload)
        self.assertEqual(tx_response["payload"]["tx_id"], transaction.tx_id)
        self.assertEqual(target.store.pending_transaction_count(), 1)

        bad_block = source.mine_pending_transactions("miner")
        bad_block.state_root = "bad-root"
        bad_block.block_hash = bad_block.compute_hash()
        while not bad_block.block_hash.startswith("0" * bad_block.difficulty):
            bad_block.nonce += 1
            bad_block.block_hash = bad_block.compute_hash()
        bad_payload = bad_block.to_dict()
        bad_envelope = source.build_peer_session_envelope(
            "peer_block_gossip_v1",
            target.config.advertised_url,
            session_id,
            "/peer/gossip/block",
            {"block": bad_payload},
        )
        with self.assertRaisesRegex(ValueError, "state root mismatch"):
            target.receive_authenticated_block_gossip(bad_envelope, bad_payload)

        peer = target.store.peer_identity_by_node_id(source.config.node_id)
        assert peer is not None
        self.assertLess(peer["score"], 0)
        self.assertGreaterEqual(peer["failure_count"], 1)

    def test_authenticated_transaction_gossip_fails_closed_for_invalid_payload(self) -> None:
        source = self.make_additional_service("invalid-source")
        target = self.make_additional_service("invalid-target")
        alice = Wallet("Alice")
        bob = Wallet("Bob")

        funding = alice.create_address()
        source.create_genesis_block({funding: 25})
        target.create_genesis_block({funding: 25})
        response = target.accept_peer_handshake(
            source.build_signed_envelope("peer_handshake_v2", {"target_url": target.config.advertised_url})
        )
        session_id = str(response["payload"]["session_id"])

        transaction = alice.create_transaction(source, bob.create_address(), amount=10, fee=1)
        transaction_payload = json.loads(transaction.serialize_with_id())
        transaction_payload["chain_id"] = "wrong-chain"
        envelope = source.build_peer_session_envelope(
            "peer_transaction_gossip_v1",
            target.config.advertised_url,
            session_id,
            "/peer/gossip/transaction",
            {"transaction": transaction_payload},
        )

        with self.assertRaisesRegex(ValueError, "hash mismatch|different chain"):
            target.receive_authenticated_transaction_gossip(envelope, transaction_payload)

        self.assertEqual(target.store.pending_transaction_count(), 0)
        peer = target.store.peer_identity_by_node_id(source.config.node_id)
        assert peer is not None
        self.assertLess(peer["score"], 0)
        self.assertGreaterEqual(peer["failure_count"], 1)

    def test_peer_diversity_report_flags_eclipse_risk(self) -> None:
        service, _ = self.make_service()
        service.config = replace(service.config, min_peer_diversity=2)
        service.store.upsert_peer_identity(
            node_id="node-a",
            url="http://one.example.com:8080",
            address="addr-a",
            signature_scheme="hash_lamport_v1",
            public_key={},
            status="admitted",
            admitted_at=1.0,
            last_seen=1.0,
        )
        service.store.upsert_peer_identity(
            node_id="node-b",
            url="http://two.example.com:8080",
            address="addr-b",
            signature_scheme="hash_lamport_v1",
            public_key={},
            status="admitted",
            admitted_at=1.0,
            last_seen=1.0,
        )

        report = service.peer_diversity_report()

        self.assertFalse(report["passed"])
        self.assertEqual(report["distinct_groups"], 1)

