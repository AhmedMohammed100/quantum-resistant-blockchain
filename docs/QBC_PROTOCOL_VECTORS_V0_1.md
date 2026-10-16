# QBC Protocol v0.1 Reference Vectors

These vectors pin selected consensus encodings for the current reference node.
They are compatibility fixtures, not evidence of cryptographic security or a
complete protocol conformance suite. Do not update an expected value to make a
test pass without reviewing the protocol version and compatibility impact.

## Transaction serialization and ID

The canonical transaction JSON and transaction ID are frozen in
`tests/test_protocol_vectors.py`:

- Transaction ID: `9f83e6f9881cf29c25660f19981581883cfa059baf913e3d442803cc088c06e2`
- The transaction uses chain ID `qr-chain-devnet`, timestamp `1700000000.125`,
  fee `7`, one input referencing transaction ID `11` repeated 32 times at
  output index `0`, and one output of `123456789` quarks to
  `qbc1vectorrecipient`.

The test asserts the complete serialized string as well as the ID, so changes
to key ordering, separators, field values, or number rendering are detected.

## Block v3 hash

The block-hash vector in `tests/test_protocol_vectors.py` has expected hash:

`56418d7f0f4198a74af542b28759cf450367116db7f8b75b294057527d1b420d`

Changing only its state root from `22` repeated 32 times to `33` repeated
32 times MUST change the computed block hash.

## Empty UTXO state root

Input canonical JSON: `[]`

SHA-256:

`4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`

## Non-empty UTXO state root

Use these two UTXOs, sorted by (transaction ID, output index):

| Transaction ID | Output index | Recipient | Amount (quarks) |
| --- | ---: | --- | ---: |
| `1111111111111111111111111111111111111111111111111111111111111111` | 0 | `qbc1vectorrecipient` | 123456789 |
| `2222222222222222222222222222222222222222222222222222222222222222` | 2 | `qbc1alice` | 500 |

Canonical JSON UTF-8 input:

```json
[{"amount":123456789,"output_index":0,"recipient":"qbc1vectorrecipient","tx_id":"1111111111111111111111111111111111111111111111111111111111111111"},{"amount":500,"output_index":2,"recipient":"qbc1alice","tx_id":"2222222222222222222222222222222222222222222222222222222222222222"}]
```

Expected SHA-256 state root:

`d29fd96143c9249ef82725bb6b8a7bcf7865a9af42476084672223ffec770a26`

Reordering the in-memory dictionary MUST NOT change this root.

## Difficulty and work

- Genesis difficulty: `1`; per-block work: `16`.
- Example configured non-genesis difficulty: `3`; a valid block hash begins
  with at least `000`; per-block work: `4096`.
- Two blocks at difficulty `3` contribute cumulative work `8192`.
- A hash with only two leading zeroes does not satisfy difficulty `3`.

The reference node uses fixed difficulty, not timestamp-based retargeting.
