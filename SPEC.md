---
title: "Pitchain Existence Proof Protocol v1.0"
nav_order: 1
---

# Pitchain Existence Proof Protocol — v1.0

Status: **NORMATIVE** · Protocol id: `pitchain/1` · Payload magic: `PCH1` · Date: 2026-09-07
Repo: https://github.com/adfoke/pitchain-protocol · Spec site: https://adfoke.github.io/pitchain-protocol/
License: MIT · Companion artifacts: `proof.schema.json` (machine schema), `vectors/`
(frozen conformance set), `conformance/pitchain_verify.py` (independent stdlib reference implementation).

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope and trust model

A pitchain proof asserts exactly one conclusion:

> Data whose canonical SHA-256 is `H` existed before the block at height `N`
> (more precisely, before that block's median-time-past) was accepted by the
> Bitcoin network's most-work chain.

Verification requires only: the proof document, optionally the original data, and
access to Bitcoin block data (full node, or one-or-more public block APIs).
It does NOT require trusting the service that issued the proof. The protocol does
not prove authorship, content legality, or sub-block timestamping (see §9).

## 2. Notation and byte-order conventions (READ THIS TWICE)

- `SHA256d(x)` = `SHA256(SHA256(x))`.
- All hashes in JSON are **lowercase hex in display byte order** (the way explorers
  print txids). Internal little-endian reversals happen ONLY inside SPV math (§7.4).
- `a || b` = byte concatenation. `0x50434831` is the ASCII bytes `P C H 1`.
- Integers in payloads are big-endian unless stated otherwise.
- `next_pow2(n)` = smallest power of two ≥ n.

## 3. Evidence

The **evidence hash** is `H = SHA256(canonicalBytes(artifact))` — a plain,
untagged SHA-256 of the artifact bytes. Structured claims (JSON documents) MUST
first be canonicalized (JCS, RFC 8785) by the issuer; the bytes hashed are always
the final serialized bytes. `hashAlg` is fixed `"sha256"` in v1.

## 4. Batch tree

A batch is an ordered list of evidence hashes `L[0..k-1]` (order = acceptance
sequence; ties broken by lexicographic hash). Duplicates SHOULD be deduplicated
into shared leaves by the issuer but MUST be accepted by verifiers.

Domain-separated tagged double-hashes (BIP-340 style):

```
TAG_L    = SHA256(UTF8("pitchain/1/leaf"))   = 68f9c79041f1ddd5...49a8  (full: vectors)
TAG_P    = SHA256(UTF8("pitchain/1/node"))   = e36f84ec1034ff11...a5cf
TAG_PREV = SHA256(UTF8("pitchain/1/prev"))   = 85bf41d83d04c98c...8284

leaf(i)      = SHA256d( TAG_L || L[i] )
prevLeaf(r') = SHA256d( TAG_PREV || r' )      # optional slot 0: previous batch root
node(a, b)   = SHA256d( TAG_P || a || b )    # a=left, b=right; NO sorting
```

Construction (complete binary tree with duplicate-last padding):

1. `P = next_pow2(k)`; leaf layer = `leaf(0..k-1)` extended by replicating
   `leaf(k-1)` until length `P` (rule id `dup-last-v1`).
2. Layer up: pairwise `node(left, right)` until one node remains → **batch root** `R`.
3. The **inclusion path** of leaf `i` at depth `d` is the sibling node at layer `d`;
   direction: bit `d` of `i` (0 → self is left). Path length = `log2(P)`.
   For `k = 1`, `P = 1`, path is empty and `R = leaf(0)`.

Verifiers recompute `R` from `(L[i], i, k, path)`: depth MUST equal
`bitlen(k-1)` and path length MUST equal that depth.

## 5. Anchor payload and transaction

The on-chain commitment is a 45-byte OP_RETURN payload:

| offset | len | field | value |
|--------|-----|-------|-------|
| 0 | 4 | MAGIC | `PCH1` (0x50434831) |
| 4 | 1 | VERSION | `0x01` |
| 5 | 8 | BATCH_ID | u64 **big-endian** |
| 13 | 32 | ROOT | batch root `R`, internal order = display hex bytes (§2) |

Script form: `OP_RETURN OP_PUSHDATA1(0x2d) <45 bytes>` — `6a 2d …`, total 47-byte
scriptPubKey. This fits every historical Bitcoin Core relay policy (≥83B era and
after). Issuers MUST NOT anchor two different roots for one BATCH_ID (equivocation):
after sealing, the root is immutable; transaction replacement (RBF) MAY change the
txid but never the 45-byte payload.

Recommended BATCH_ID: `(unix_seconds << 20) | daily_seq` (sortability, low collision).
The rolling calendar chain (prev root as leaf 0 via TAG_PREV) is RECOMMENDED for
issuers, OPTIONAL for verifiers in v1.

## 6. Proof document

`pitchain-proof/v1`: a JSON object conforming to `proof.schema.json`. Normative fields:

```jsonc
{
  "@context": "https://w3id.org/pitchain/v1",
  "type": "PitchainExistenceProof",
  "version": 1,
  "evidence": {
    "hash": "<H, §3>", "hashAlg": "sha256",
    "label": "<optional display text>",
    "submittedAt": "<optional ISO-8601>",
    "hashComputedBy": "client" | "service"   // optional; "service" ⇒ disclosure duty
  },
  "leaf":  { "index": <i>, "paddingRule": "dup-last-v1" },
  "tree":  { "leafCount": <k>, "path": ["<sibling hex>", ...], "root": "<R>" },
  "batch": { "id": "<BATCH_ID as decimal string>", "closedAt": "<optional>", "chainedRoot": "<optional>" },
  "anchor": {
    "network": "bitcoin" | "testnet4" | "signet",
    "txid": "<64 hex>", "vout": <n>,
    "payload": "<90 hex = §5 45B>",
    "blockHash": "<optional; required for SPV>",
    "height": <optional>,
    "merkleBranch": ["<txid-order hex>", ...],  // optional; required for SPV
    "position": <block tx index>,               // coinbase = 0
    "confirmationsAtIssue": <int>, "mtp": "<ISO-8601>"
  },
  "issuedAt": "<optional>"
}
```

Verifiers MUST ignore unknown fields. Producers MUST NOT emit fields absent from
this spec for `v1` beyond `label/submittedAt/hashComputedBy/closedAt/chainedRoot/
issuedAt` (all optional metadata).

## 7. Verification algorithm

Inputs: proof `p`; optional `data` bytes; optional chain data sources
`header(blockHash) → 80-byte hex` and `anchorTx(txid) → raw tx hex`.
Steps run in order; any failure returns `INVALID` with its class.

**7.1 data** (if `data` given): `SHA256(data) == p.evidence.hash`, else fail class `data`.

**7.2 tree**: recompute root per §4 from `(hash, index, leafCount, path)`; MUST equal
`tree.root`, else fail class `tree`.

**7.3 anchor consistency**: decode `payload` per §5 — magic/version/length checked;
`ROOT == tree.root` and `BATCH_ID == batch.id`, else fail class `anchor`.
If `anchorTx` is available: parse the transaction (§7.6), and `payload` MUST appear
byte-for-byte among its data-carrier (OP_RETURN) outputs, else fail class `script`.

**7.4 inclusion (SPV)** (if `header` is available; requires blockHash/merkleBranch/position):
Bitcoin tx merkle: start `cur = reverse(txid bytes)`; for each level `d`, sibling
`s = reverse(branch[d])`; `cur = SHA256d(cur||s)` if `(position >> d) & 1 == 0` else
`SHA256d(s||cur)`. Final `cur` reversed MUST equal header bytes 36–67 reversed
(`merkleRoot` display order), and `SHA256d(80-byte header)` reversed MUST equal
`blockHash`. Failure → class `inclusion`. `confirmationsAtIssue < min_confs`
(RECOMMENDED 6) → `PROVISIONAL`.

**7.5 result**: `VALID` with time upper bound = header's MTP (median timestamp of the
prior 11 blocks; MAY be recomputed from `height`), plus the strongest level actually
checked: `crypto` / `+script` / `+inclusion`.

**7.6 minimal tx/script parser (BIP144-aware)**: version(4) [marker 0x00 flag 0x01
if segwit] vin(1B) [outpoint(36) scriptsig(1B+skip) seq(4)]… [per-input witness:
items(1B) each (1B+len)]… if segwit — vout(1B) [value(8) script(1B+skip)]… locktime(4).
OP_RETURN scripts start `0x6a`; push data follows canonical single-push (`0x01–0x4b`
inline) or `0x4c + len` (76–255). (Vectors keep all counts < 76; larger canonical
encodings are issuer-tooling concerns, not verifier ones.) Real anchors are witness
transactions; a parser without the marker/witness branch MUST fail `pass-full`
vectors — this branch is REQUIRED, not optional.

## 8. Chain selection caveat

SPV proves *some-block inclusion* + header self-consistency, not best-chain
membership. Verifiers SHOULD obtain the header from a local full node, or cross-check
≥2 independent public sources, or anchor on a height with deep reorg protection.
UI text MUST NOT claim "on the canonical chain" without such sourcing.

## 9. Honest boundaries

This proof does NOT establish: who created the data (§3 hashing any bytes), that the
underlying content is lawful/accurate, timestamps finer than block acceptance, or
anything before submission (a proof issued today cannot evidence data from 1990 —
only from "before block N" backwards to the moment H existed).

## 10. Versioning

A change to §4/§5/§7 semantics REQUIRES a new MAGIC (4 ASCII bytes) and protocol id
(`pitchain/2`). Additive optional JSON fields MAY appear under the same version.
Payload VERSION (1B) is reserved for non-breaking sub-versions only.

## 11. Conformance

An implementation claiming `pitchain/1` verification MUST pass, unchanged, all files
under `vectors/`:

- `tree/n###.json` — items: `{src, dataHash, leaf}`; proofs: `{index, path, root}`.
  Recompute all three levels from `src`.
- `anchor/payload.json` — decode/encode round-trip.
- `proof/positive.json` + `proof/negative.json` — run §7 with the offline chain data
  embedded in `context` (`headerHex`, `anchorTxHex`, `dataSrc` as the data bytes).
  Expectations: `pass-crypto` → not INVALID with `tree+payload` consistent;
  `pass-spv` → VALID with §7.4 executed; `pass-full` → VALID with §7.3 script AND
  §7.4 executed; `fail-<class>` → INVALID with exactly that class (§7).

Profiles: **verifier-basic** = crypto only; **verifier-full** = + script + inclusion;
**issuer** = full + §5 construction + §4 ordering + rolling chain.
Reference: `conformance/pitchain_verify.py` (stdlib Python, written against this
document alone) passes 25/25; the TypeScript reference implementation
(`@pitchain/core`, in the pitchain service repository) passes the same vector set.

## 12. Chainpoint v2 mapping (interop appendix)

`targetHash = evidence.hash` · `merkleRoot = tree.root` · `proof` array =
path expanded left/right by index bits · `anchors = [{type:"BTCOpReturn",
sourceId: anchor.txid}]`. Chainpoint has no header-inclusion or script-binding
steps; conversions from Chainpoint proofs MUST NOT set `pass-spv/pass-full`.

## 13. Security notes

- Second-preimage: verifiers hashing their own bytes (§3) are safe; anyone who can
  find `SHA256(x)==H` could substitute `x` — the property proven is about H only.
- Tag separation (§4) prevents cross-tree substitution between leaves/nodes/prev-chains.
- Service signatures (`receiptSig`, key rotation) are deferred from v1 core:
  the chain payload + optional script binding already carry the trust; signatures
  add at-willingness attribution only, and will appear as `version: 2` proofs or a
  claim-layer document to avoid half-trusted optional crypto in v1.
- Fee spikes delay anchoring, never weaken it: proofs are issued only after
  §7 passes with real blocks.
