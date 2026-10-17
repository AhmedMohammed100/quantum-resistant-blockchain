from __future__ import annotations

import unittest

from qr_blockchain.portable_encoding import canonical_json_v1, hash_canonical_v1


class PortableEncodingV1Tests(unittest.TestCase):
    def test_golden_canonical_json_and_domain_hash(self) -> None:
        value = {"z": 0, "a": "é\n", "n": -12, "b": True}
        expected = '{"a":"é\\u000a","b":true,"n":-12,"z":0}'.encode("utf-8")
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(
            hash_canonical_v1("test-vector", value),
            "80895643fef93bf20130c21775db0765051092bdc393f17d8627a3e615b2a0a2",
        )

    def test_object_key_order_is_independent_of_insertion_order(self) -> None:
        left = {"z": [1, None, False], "a": {"β": 2, "a": 1}}
        right = {"a": {"a": 1, "β": 2}, "z": [1, None, False]}
        self.assertEqual(canonical_json_v1(left), canonical_json_v1(right))
        self.assertEqual(hash_canonical_v1("fixture", left), hash_canonical_v1("fixture", right))

    def test_integer_microsecond_timestamp_vector(self) -> None:
        value = {"timestamp_us": 1700000000123456, "chain_id": "qr-chain-devnet", "ok": True}
        self.assertEqual(
            canonical_json_v1(value),
            b'{"chain_id":"qr-chain-devnet","ok":true,"timestamp_us":1700000000123456}',
        )
        self.assertEqual(
            hash_canonical_v1("test-vector", value),
            "f0620f3f72a593f3413dc535205a31bb3c45e39806e5d54dba3286c017e9ba98",
        )

    def test_empty_object_encoding(self) -> None:
        self.assertEqual(canonical_json_v1({}), b"{}")

    def test_escapes_quotes_backslashes_and_control_characters(self) -> None:
        self.assertEqual(
            canonical_json_v1({'x': '"\\\t\r'}),
            b'{"x":"\\\"\\\\\\u0009\\u000d"}',
        )

    def test_signed_64_bit_boundaries_are_supported(self) -> None:
        self.assertEqual(canonical_json_v1(-(2**63)), b"-9223372036854775808")
        self.assertEqual(canonical_json_v1(2**63 - 1), b"9223372036854775807")

    def test_float_is_rejected_even_when_integral_looking(self) -> None:
        for value in (1.0, 0.0, -0.0, 1e-6):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_json_v1(value)

    def test_integer_outside_signed_64_bit_range_is_rejected(self) -> None:
        for value in (-(2**63) - 1, 2**63):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_json_v1(value)

    def test_non_string_keys_and_non_json_python_types_are_rejected(self) -> None:
        for value in ({1: "bad"}, (1, 2), {1, 2}, b"bytes"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_json_v1(value)

    def test_surrogate_code_points_are_rejected(self) -> None:
        for value in ("\ud800", {"\udfff": 1}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_json_v1(value)

    def test_hash_domain_must_be_lowercase_ascii_token(self) -> None:
        for domain in ("", "Upper", "has space", "é", "x" * 65):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                hash_canonical_v1(domain, {"ok": True})

    def test_domain_separation_changes_digest(self) -> None:
        self.assertNotEqual(
            hash_canonical_v1("transaction", {"x": 1}),
            hash_canonical_v1("block", {"x": 1}),
        )


if __name__ == "__main__":
    unittest.main()
