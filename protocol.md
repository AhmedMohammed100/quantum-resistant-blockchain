# QBC Protocol Freeze v0.1

**Status:** protocol-definition milestone  
**Protocol name:** Quantum-Resistant Blockchain (QBC)  
**Document version:** `qbc-protocol-v0.1`

This document freezes the consensus-object definitions used by the QBC reference
node.  The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and
**MAY** are to be interpreted as normative requirements.  A node that accepts
an object violating a MUST or MUST NOT is not conformant with this freeze.

This is a UTXO proof-of-work chain.  It deliberately defines the consensus
envelope separately from node-local relay and operational policy: deployments
must agree on all consensus parameters, while mempool limits and provider
availability may be more restrictive locally.

## 1. Chain identity

The chain identifier is an opaque, case-sensitive UTF-8 string.  The v0.1
development network identifier is `qr-chain-devnet`.  Every transaction and
block MUST carry the configured chain identifier and a validator MUST reject an
object whose value differs from its own configured value.  The identifier is
also part of the transaction signing payload, preventing a valid signature from
being replayed on a chain with a different identity.

The native currency is **Quantum Blockchain Coin** (`QBC`):

| Parameter | v0.1 value |
| --- | ---: |
| Smallest unit | `quark` |
| Decimal places | 8 |
| Quarks per QBC | 100,000,000 |
| Maximum supply | 500,000,000 QBC |
| Genesis allocation cap | 125,000,000 QBC |
| Migration pool cap | 200,000,000 QBC |
| Emission cap | 175,000,000 QBC |
| Initial block subsidy | 175 QBC |
| Subsidy halving interval | 500,000 blocks |

Amounts, fees, rewards, and UTXO values are non-negative integers of quarks;
floating-point arithmetic MUST NOT be used for value accounting.  A production
network MUST publish its chain ID, genesis block hash, activation heights,
difficulty rules, supply allocation, and signature-provider allowlist as an
immutable network manifest before accepting public value.

## 2. Hashes and domain separation

`SHA256(x)` means the 32-byte SHA-256 digest of byte string `x`.  Hashes shown
in JSON are 64-character lowercase hexadecimal encodings with no `0x` prefix.
All consensus object hashes in this version use SHA-256:

| Name | Definition |
| --- | --- |
| Transaction ID | `SHA256(UTF8(transaction serialization))` |
| Block hash | `SHA256(UTF8(block-hash preimage))` |
| Peer-frame digest | `SHA256(UTF8(peer-frame preimage))` |
| Address | provider-defined; the compatibility Lamport provider uses SHA-256 as specified in §6 |

The object type and field names in each preimage provide domain separation.
Implementations MUST NOT substitute a hash from a different object type or
silently accept mixed-case, truncated, or non-hex digest strings.

## 3. Canonical serialization

All hashes and signature messages use canonical JSON encoded as UTF-8:

1. Objects are serialized with lexicographically sorted keys at every level.
2. Separators are exactly `,` between elements and `:` between a key and value;
   no insignificant whitespace is emitted.
3. Arrays retain their supplied order.  In particular, input, output, and block
   transaction order are consensus-significant.
4. Strings use JSON string escaping and are UTF-8 encoded.
5. Numbers MUST be JSON numbers.  Value fields MUST be integral; timestamps are
   represented by the reference implementation as seconds with up to six
   fractional decimal places.
6. Optional fields are not omitted from a v0.1 transaction or block preimage;
   use their specified empty value instead.

This definition corresponds to Python `json.dumps(value, sort_keys=True,
separators=(",", ":"))`.  Implementations in other languages MUST produce the
same UTF-8 byte sequence.  Because JSON number rendering can vary among
languages, a production successor MUST replace timestamp floats with integer
microseconds before cross-language consensus use.

## 4. Transaction structure

A version-1 transaction is the following canonical JSON object.  The current
object version is carried by the protocol manifest rather than a `version`
field in each transaction.

```json
{
  "chain_id": "qr-chain-devnet",
  "fee": 0,
  "inputs": [
    {
      "output_index": 0,
      "prev_tx_id": "<64 lowercase hex characters>",
      "public_key": "<provider-defined JSON value>",
      "signature": "<provider-defined JSON value>"
    }
  ],
  "kind": "transfer",
  "metadata": {},
  "outputs": [{"amount": 1, "recipient": "<address>"}],
  "signature_scheme": "<registered provider ID>",
  "timestamp": 0.0
}
```

`tx_id` is not in the transaction-ID preimage.  The wire/storage form appends
`"tx_id":"<transaction ID>"`; a validator MUST recompute and compare it.

Each input references one UTXO by `(prev_tx_id, output_index)`.  Each output
creates one UTXO at `(tx_id, its zero-based array position)`.  `recipient` is
an address and `amount` is a positive integer number of quarks.  `fee` is a
non-negative integer.  Defined transaction kinds are:

* `transfer` — spends referenced UTXOs and creates one or more new UTXOs.
* `migration_claim` — creates exactly one post-quantum destination output from
  an approved classical-source claim; it has no UTXO inputs and has zero fee.

The first transaction in every non-genesis block is the reward transaction. It
has no inputs, has fee zero, and is not a user-submitted `transfer`; its output
sum is constrained by §8.  The genesis transaction likewise has no inputs.

### 4.1 Signature preimage

For every input of a `transfer`, the signer signs the UTF-8 canonical JSON of:

```json
{
  "chain_id": "...",
  "fee": 0,
  "inputs": [{"output_index": 0, "prev_tx_id": "..."}],
  "kind": "transfer",
  "metadata": {},
  "outputs": [{"amount": 1, "recipient": "..."}],
  "signature_scheme": "...",
  "timestamp": 0.0
}
```

This is one transaction-wide message: input public keys and signatures are
excluded, while all outpoints, outputs, fee, chain ID, timestamp, metadata, and
the signature-provider ID are bound.  Every input signature MUST verify over
this exact same payload.

Migration claims additionally bind their classical proof to the canonical JSON
containing `kind`, `chain_id`, `timestamp`, `outputs`, and only these metadata
keys: `classical_address`, `classical_provider_id`, `source_network`, and
`snapshot_ref`.

## 5. Block structure

A block is represented as:

```json
{
  "block_hash": "<64 lowercase hex characters>",
  "chain_id": "qr-chain-devnet",
  "difficulty": 3,
  "index": 1,
  "miner": "<address>",
  "nonce": 0,
  "previous_hash": "<64 lowercase hex characters>",
  "state_root": "<64 lowercase hex characters>",
  "timestamp": 0.0,
  "transactions": [{"<transaction storage field>": "..."}],
  "version": 3
}
```

The storage/wire object contains nested transaction storage objects.  The
block-hash preimage contains all fields above except `block_hash`, but replaces
its `transactions` value with an array of each transaction's **canonical
serialized storage JSON string**, including that transaction's `tx_id`; it is
not an array of nested JSON objects.  For block versions 2 and below,
`state_root` is excluded from the hash preimage.  Version 3 and later include
it.

`previous_hash` for genesis is exactly 64 `0` characters.  A child block MUST
name a known parent and have `index = parent.index + 1`.  Its block hash MUST
have at least `difficulty` leading hexadecimal zeroes.  The canonical best
chain is the branch with greatest cumulative work; equal-work branches are
resolved by choosing the lexicographically greater head hash.

### 5.1 State root

At and after the configured state-root activation height (zero in v0.1), blocks
MUST be version 3 or later and MUST commit to a non-empty post-block UTXO state
root.  Validators derive the root after applying all transactions in order and
MUST reject a mismatching root.  The exact UTXO-root encoding is presently an
implementation-defined compatibility boundary; v0.1 freezes the commitment
requirement but does **not** yet provide a portable Merkle encoding.  Nodes
must therefore use the reference implementation for cross-node validation until
a successor freeze specifies that encoding.

## 6. Addresses and signatures

An address is the provider-derived identifier for a public key.  The
transaction's `signature_scheme` selects a registered signature provider.  A
validator MUST use that provider to derive the address from each input public
key and require exact equality with the referenced UTXO recipient before it
checks the signature.  It MUST then verify the provider-defined signature over
the §4.1 payload.

The v0.1 compatibility provider `hash_lamport_v1` uses a 256-bit Lamport
one-time key:

* A public key is 256 ordered pairs of 32-byte SHA-256 hashes, represented as
  lowercase hexadecimal strings.
* The address is `SHA256(ASCII(concatenate(left || right for every pair in
  order)))`, encoded as lowercase hex.
* A signature discloses one 32-byte secret for each bit of
  `SHA256(signing_payload)`.  The corresponding public-key element must hash
  to the stored value.

Other identifiers, including `xmss_merkle_lamport_v1`, ML-DSA, LMS, SPHINCS+,
and native providers, are provider boundaries rather than new transaction
formats.  A network manifest MUST fix which provider IDs are consensus-allowed,
their implementation/version, address derivation, public-key encoding,
signature encoding, and stateful-key usage rules.  Stateful one-time or
few-time schemes MUST reserve key state durably before signing and MUST NOT
reuse a signing leaf.

## 7. Transaction validation

A consensus validator processes a transaction as follows:

1. Recompute the transaction ID and require equality with `tx_id`.
2. Require the configured `chain_id`, a defined kind, at least one output,
   strictly positive output amounts, and a non-negative fee.
3. For every `transfer` input, require its referenced UTXO to exist and each
   outpoint to occur at most once within the transaction.  Derive each input
   address from its public key and verify its signature as §6 requires.
4. When a `transfer` has inputs, require `sum(outputs) + fee <=
   sum(referenced inputs)`.  Inputs may not spend a coinbase output before its
   configured maturity, or a migration output before its configured
   escrow/finality conditions are satisfied.
5. For `migration_claim`, require its no-input, one-output, zero-fee form and
   validate the approved source binding, provider, snapshot, claim window,
   conversion ratio/caps, destination attestation, and classical-address
   uniqueness.

Nodes MAY apply stricter non-consensus admission limits, including maximum
serialized size, input/output counts, future timestamp skew, minimum relay fee,
fee-per-KiB, signature payload size, and mempool conflict checks.  Such policy
MUST NOT cause a node to reinterpret a valid block as having a different hash.

## 8. Block validation

For a candidate block, a validator MUST:

1. Check the chain ID, supported version, block hash, and proof-of-work target.
2. Require at least one transaction and reject a duplicate stored block.
3. For genesis, require index zero, the all-zero previous hash, and
   chain-matching transactions.  No second genesis block is valid.
4. For a non-genesis block, require a known parent, contiguous height, and a
   first transaction with no inputs.
5. Starting from the parent's UTXO view, validate transactions in array order.
   The first transaction creates reward UTXOs.  Each later normal transaction
   consumes its inputs and creates its outputs; a UTXO may not be consumed
   twice in the block.  Migration claims add outputs and may not duplicate a
   claimed classical address in the block or chain history.
6. Require the reward output total to equal the height's subsidy plus the sum
   of fees in non-reward transactions.  Enforce the configured subsidy,
   migration, allocation, and total-supply caps.
7. Recompute and require the committed post-block state root when version 3 is
   active.

## 9. Versioning and upgrades

The v0.1 manifest declares transaction version 1, block version 3,
migration-snapshot version 1, source-ingestion version 1, approval-artifact
version 1, and peer-frame protocol `qr-peer-v1`.  Block versions below 2 are
invalid; blocks at the state-root activation height and beyond must be version
3 or later.  A peer MUST reject a frame whose protocol version does not exactly
match its configured peer protocol version.

Changing a hash preimage, signature payload, address derivation, transaction
meaning, block validation rule, consensus provider allowlist, or state-root
encoding is a consensus upgrade.  It MUST be assigned a new protocol version,
activated at a declared height, published with deterministic test vectors, and
be explicitly accepted by validating nodes.  New fields MUST NOT be silently
ignored in consensus objects; a change is valid only when its versioned rules
define whether the field is committed and how it is validated.

## 10. Conformance

A QBC Protocol Freeze v0.1 implementation MUST be able to expose a
machine-readable manifest containing the chain ID, object versions, currency
policy, transaction kinds, migration policy, peer protocol version, and a
canonical manifest hash.  Implementations SHOULD test canonical serialization,
transaction-ID recomputation, chain-bound signature replay rejection,
address/public-key binding, duplicate-input rejection, reward accounting,
proof-of-work validation, state-root mismatch rejection, and version/activation
boundaries.
