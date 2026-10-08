from __future__ import annotations

import copy
import random
import unittest

from qr_blockchain.models import Transaction, TxInput, TxOutput
from qr_blockchain.protocol import build_peer_frame, parse_peer_frame


class ProtocolFuzzRegressionTests(unittest.TestCase):
    """Small deterministic fuzz corpus; no optional fuzzing dependency required."""

    def test_mutated_peer_frames_are_rejected_or_roundtrip_exactly(self) -> None:
        rng = random.Random(0x514243)
        valid = build_peer_frame(
            protocol_version="qr-peer-v1",
            message_type="peer_blocks_request",
            payload={"start_height": 12, "limit": 8, "cursor": None},
            auth={"session_id": "session-a"},
        )
        mutations = []
        for field, value in (
            ("protocol_version", None),
            ("protocol_version", []),
            ("message_type", {"unexpected": True}),
            ("payload", []),
            ("payload", "not-an-object"),
            ("auth", []),
            ("frame_digest", "0" * 64),
            ("frame_digest", None),
        ):
            item = copy.deepcopy(valid)
            item[field] = value
            mutations.append(item)

        for _ in range(100):
            item = copy.deepcopy(valid)
            choice = rng.choice(("payload", "frame_digest", "auth"))
            if choice == "payload":
                item["payload"] = {"start_height": rng.randint(-10, 10_000), "nested": [rng.random()]}
            elif choice == "frame_digest":
                item["frame_digest"] = "".join(rng.choice("0123456789abcdef") for _ in range(64))
            else:
                item["auth"] = rng.choice((None, {}, [], "bad-auth", {"x": rng.random()}))
            mutations.append(item)

        for index, item in enumerate(mutations):
            with self.subTest(index=index):
                try:
                    payload, auth = parse_peer_frame(
                        item,
                        expected_protocol_version="qr-peer-v1",
                        expected_message_type="peer_blocks_request",
                    )
                except (ValueError, TypeError, KeyError):
                    continue
                self.assertEqual(item["frame_digest"], valid["frame_digest"])
                self.assertEqual(payload, valid["payload"])
                self.assertEqual(auth, valid["auth"])

    def test_non_object_frames_never_parse(self) -> None:
        for value in (None, [], (), "", 0, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_peer_frame(
                        value,  # type: ignore[arg-type]
                        expected_protocol_version="qr-peer-v1",
                        expected_message_type="peer_summary_request",
                    )

    def test_transaction_roundtrip_with_bounded_generated_values(self) -> None:
        rng = random.Random(204)
        for index in range(100):
            transaction = Transaction(
                inputs=[
                    TxInput(
                        prev_tx_id=f"{rng.getrandbits(256):064x}",
                        output_index=rng.randrange(0, 100),
                        public_key={"seed": index},
                        signature={"proof": f"sig-{index}"},
                    )
                    for _ in range(rng.randrange(0, 5))
                ],
                outputs=[
                    TxOutput(recipient=f"recipient-{index}-{j}", amount=rng.randrange(1, 10**9))
                    for j in range(rng.randrange(1, 5))
                ],
                chain_id="qr-chain-devnet",
                signature_scheme="test-provider",
                timestamp=round(rng.random() * 1_000_000, 6),
                fee=rng.randrange(0, 1000),
                metadata={"case": index, "labels": [rng.randrange(100) for _ in range(3)]},
            )
            transaction.finalize()
            decoded = Transaction.from_dict(__import__("json").loads(transaction.serialize_with_id()))
            self.assertEqual(decoded.tx_id, transaction.tx_id)
            self.assertEqual(decoded.serialize_with_id(), transaction.serialize_with_id())


if __name__ == "__main__":
    unittest.main()
