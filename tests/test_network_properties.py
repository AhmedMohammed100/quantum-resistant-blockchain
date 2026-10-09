from __future__ import annotations

import random
import unittest

from qr_blockchain.network import normalize_peer_url


class PeerUrlPropertyTests(unittest.TestCase):
    def test_normalization_is_idempotent_for_generated_valid_urls(self) -> None:
        rng = random.Random(0x8B12)
        for _ in range(300):
            label_count = rng.randint(2, 4)
            labels = [
                "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(2, 10)))
                for _ in range(label_count)
            ]
            host = ".".join(labels)
            scheme = rng.choice(("http", "https"))
            port = rng.randint(1024, 65535)
            url = f"{scheme}://{host}:{port}/qbc-peer/"
            normalized = normalize_peer_url(url)
            self.assertEqual(normalize_peer_url(normalized), normalized)

    def test_unsafe_url_mutations_are_rejected(self) -> None:
        rng = random.Random(0xA11CE)
        invalid = [
            "ftp://peer.example",
            "file:///etc/passwd",
            "http://user:secret@peer.example",
            "https://peer.example/path?token=secret",
            "https://peer.example/path#fragment",
            "http:///missing-host",
            "http://peer.example:65536",
            "http://peer.example/path\nnext",
        ]
        for _ in range(100):
            prefix = rng.choice(("ftp", "file", "javascript", "gopher"))
            invalid.append(f"{prefix}://peer{rng.randint(0, 9999)}.example")
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    normalize_peer_url(url)


if __name__ == "__main__":
    unittest.main()
