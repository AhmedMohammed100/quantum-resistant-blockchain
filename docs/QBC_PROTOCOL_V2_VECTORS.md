# QBC Protocol v2 Candidate Golden Vectors — H through K

These vectors accompany `docs/QBC_PROTOCOL_V2_NORMATIVE.md`. They are exact encoding/hash fixtures for a proposed v2 profile, not activation evidence. H uses clearly labeled fixture public-key/signature values; it does not contain a valid ML-DSA signature.

## Vector H — transaction-ID preimage

Domain: `transaction-v2`

Logical object: v2 transfer on `qr-chain-devnet`; timestamp 1700000000123456 microseconds; fee 2; one input referencing `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1`; fixture public key `{"fixture":"pk-alice"}`; fixture signature `{"fixture":"sig-alice"}`; one output of 100 quarks to `qbc1alice`; empty metadata; signature scheme `mldsa65`. The `tx_id` field is excluded from the preimage.

Canonical UTF-8 bytes:

```json
{"chain_id":"qr-chain-devnet","fee":2,"inputs":[{"output_index":1,"prev_tx_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","public_key":{"fixture":"pk-alice"},"signature":{"fixture":"sig-alice"}}],"kind":"transfer","metadata":{},"outputs":[{"amount":100,"recipient":"qbc1alice"}],"signature_scheme":"mldsa65","timestamp_us":1700000000123456,"version":2}
```

Expected SHA-256 digest: `01f8a81008a8bde0e793b5e5ca8c569e9c95ffe31fdd473283752f218201a5d0`

## Vector I — flat signature preimage

Domain: `signature-preimage-v2`

This is the same transaction's signing preimage. Public keys, signatures, and `tx_id` are excluded. The schema version and chain ID each appear once.

Canonical UTF-8 bytes:

```json
{"chain_id":"qr-chain-devnet","fee":2,"inputs":[{"output_index":1,"prev_tx_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"kind":"transfer","metadata":{},"outputs":[{"amount":100,"recipient":"qbc1alice"}],"signature_scheme":"mldsa65","timestamp_us":1700000000123456,"version":2}
```

Expected SHA-256 digest: `b0bea7b13223c0d6bd1ba90e9908ccf6dbb8394827df2bc68a80d3447c56d3f1`

## Vector J — state-root preimage

Domain: `state-root-v2`

The array is sorted by transaction ID, then numeric output index.

Canonical UTF-8 bytes:

```json
[{"amount":100,"output_index":1,"recipient":"qbc1alice","tx_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"amount":50,"output_index":0,"recipient":"qbc1bob","tx_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
```

Expected SHA-256 digest: `14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3`

## Vector K — block-hash preimage

Domain: `block-v2`

The block uses height 7, parent hash `bbbb…bbbb` (64 lowercase `b` characters), timestamp 1700000001123456 microseconds, difficulty 2, nonce 9, miner `qbc1miner`, the transaction ID from Vector H, and the state root from Vector J. The block preimage's `transactions` array contains transaction ID strings, not nested objects or serialized JSON strings.

Canonical UTF-8 bytes:

```json
{"chain_id":"qr-chain-devnet","difficulty":2,"height":7,"miner":"qbc1miner","nonce":9,"previous_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state_root":"14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3","timestamp_us":1700000001123456,"transactions":["01f8a81008a8bde0e793b5e5ca8c569e9c95ffe31fdd473283752f218201a5d0"],"version":2}
```

Expected SHA-256 digest: `8409f50017640fea77542ad9bfffe42a173b9d740f6381ab805c4f485d810ac4`

## Conformance rule

Python and Go suites must match every byte and digest above. These vectors prove agreement on the specified encoding/hash cases only. They do not prove semantic schema validation, signature validity, state-transition correctness, fork-choice safety, or production readiness.
