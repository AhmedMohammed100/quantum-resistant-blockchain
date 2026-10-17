# QBC Portable Encoding Profile v1 (proposal)

**Status:** proposed successor encoding profile; not activated for consensus.
**Profile identifier:** `qbc-cjson-v1`

This profile defines deterministic bytes for independent implementations. It is
deliberately separate from QBC v0.1's Python `json.dumps` behavior. It MUST NOT
be substituted into existing transaction IDs, block hashes, peer-frame digests,
signature payloads, or state roots without a separately versioned activation
plan and migration policy.

## 1. Value model

A value MUST be one of:
- `null`;
- a boolean;
- a signed 64-bit integer in the inclusive range
  `-9223372036854775808` to `9223372036854775807`;
- a Unicode scalar string (surrogate code points are invalid);
- an array of allowed values; or
- an object whose keys are strings and whose values are allowed values.

Floating-point numbers, tuples, byte strings, non-string object keys, and values
outside this model MUST be rejected. Protocol timestamps in this profile MUST
be represented as integer microseconds in a field named by the relevant object
schema (for example, `timestamp_us`). Conversion from an existing float
timestamp is an application-level migration operation; implementations MUST NOT
silently round or infer a conversion during consensus validation.

## 2. Canonical UTF-8 encoding

1. Output is UTF-8 without a byte-order mark.
2. Object keys are ordered by lexicographic comparison of their UTF-8 byte
   sequences. Duplicate keys are not representable in the in-memory data model;
   JSON parsers consuming wire JSON MUST reject duplicate object keys before
   converting to a map.
3. Arrays retain their original order.
4. No insignificant whitespace is emitted.
5. Strings are emitted as JSON strings. The quotation mark is encoded as
   `\\\"`, the reverse solidus as `\\\\`, and each code point U+0000
   through U+001F as lowercase `\\u00xx` with exactly four hexadecimal
   digits. No short escapes (such as `\\n`) are used. Other Unicode scalar
   values are emitted directly as UTF-8. Unicode normalization MUST NOT be
   applied.
6. Integers use base-10 ASCII digits, no leading plus sign, no leading zeroes
   except the value zero, and a minus sign only for negative values. Negative
   zero is therefore not a valid integer representation.
7. Booleans and null are lowercase ASCII `true`, `false`, and `null`.

The encoder emits bytes, not a runtime-dependent string representation. The
reference implementation is `qr_blockchain.portable_encoding.canonical_json_v1`.

## 3. Domain-separated hashes

For domain token `D` and canonical value `V`, the v1 digest is:

```text
SHA256(
  ASCII("QBC-CJSON-V1") || 0x00 ||
  ASCII(D) || 0x00 ||
  canonical_json_v1(V)
)
```

The domain MUST be a 1–64 character lowercase ASCII token matching
`[a-z0-9][a-z0-9._/-]{0,63}`. Protocol schemas MUST assign a distinct stable
domain to each hashed object type. Digests are rendered as 64 lowercase
hexadecimal characters without a `0x` prefix. Domain separation does not by
itself make a schema safe; each schema must define required fields, ranges,
and semantic validation.

## 4. Golden vectors

### Vector A — escaping, Unicode, ordering, and hash

Logical value:

```json
{"z":0,"a":"é\n","n":-12,"b":true}
```

Canonical UTF-8 text (the sequence `\u000a` is six ASCII characters after
the backslash; `é` is encoded as UTF-8 bytes C3 A9):

```text
{"a":"é\u000a","b":true,"n":-12,"z":0}
```

SHA-256 preimage domain: `test-vector`.

Expected SHA-256:

```text
80895643fef93bf20130c21775db0765051092bdc393f17d8627a3e615b2a0a2
```

### Vector B — integer microseconds

Canonical UTF-8 text:

```text
{"chain_id":"qr-chain-devnet","ok":true,"timestamp_us":1700000000123456}
```

Domain: `test-vector`.

Expected SHA-256:

```text
f0620f3f72a593f3413dc535205a31bb3c45e39806e5d54dba3286c017e9ba98
```

### Vector C — empty object

Canonical UTF-8 text: `{}`.

SHA-256 of the canonical bytes alone (not domain-separated):

```text
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
```

## 5. Conformance requirements

An implementation claiming `qbc-cjson-v1` support MUST:
- match every byte and digest in the golden vectors;
- produce identical output regardless of object insertion order;
- reject floats, out-of-range integers, non-string keys, surrogate code points,
  unsupported host-language types, and invalid hash domains;
- reject duplicate keys when parsing JSON text, before map construction;
- maintain the existing v0.1 encoder and vectors unchanged until an explicit
  protocol activation and migration decision is approved.

The Python tests in `tests/test_portable_encoding.py` are the initial reference
conformance suite. A second implementation in another language should run the
same published vectors before this profile is considered interoperable.

## 6. Activation and compatibility policy

This profile is a building block, not an activation. It does not change the
network manifest, transaction/block schemas, existing hashes, signature
preimages, peer wire format, or state-root encoding. Any consensus adoption
requires a new protocol/object version, explicit activation height or network
genesis, cross-language vectors for every consensus preimage, compatibility
tests, and a reviewed migration plan. No existing expected v0.1 vector should
be rewritten to match this profile.
