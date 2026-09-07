---
title: Home
nav_order: 0
---

# pitchain-protocol

The open standard for Bitcoin-anchored existence proofs. **Protocol id:**
`pitchain/1` · **Status:** v1.0.0 (2026-09-07) · **License:** MIT

A pitchain proof says exactly one thing, honestly:

> Data whose SHA-256 is `H` existed before block `N` — provable by anyone,
> trusting no one.

No tokens. No sidechains. No proprietary verifier. Just Bitcoin and hashes.

## Start here

| You are… | Read / run |
|----------|------------|
| writing a verifier | [SPEC.md](SPEC.md) → pass [vectors/](vectors/) → `python3 conformance/pitchain_verify.py` for a reference run |
| writing an issuer | SPEC §4–§5 (tree + anchor payload) plus §6 (proof document) |
| auditing an implementation | `vectors/proof/negative.json` — six canonical forgeries; each must be rejected with its named failure class |
| rendering proofs pretty | [proof.schema.json](proof.schema.json) · raw JSON over HTTPS from any Pages URL under `/vectors/` |

## The deal

This repository contains **everything needed to verify independently**:

- `SPEC.md` — normative specification (English). Implementation-agnostic; byte-exact.
- `proof.schema.json` — machine-readable proof document schema (JSON Schema 2020-12).
- `vectors/` — frozen conformance vectors: 12 tree families, anchor payload
  round-trips, and 10 end-to-end proofs (4 valid, 6 canonical forgeries), including
  real mainnet block material (block 965880, captured 2026-09-07).
- `conformance/pitchain_verify.py` — an independent reference verifier in pure-stdlib
  Python, written from the spec text alone. If this passes, the spec is implementable
  without us.

The service that anchors proofs (`pitchain.dev`) is **replaceable by design**: proofs
remain verifiable forever if this repo dies, because Bitcoin keeps the roots and you
keep the documents.

## Conformance claim

Implementations MAY claim `pitchain/1` verification conformance by passing all
`vectors/` assertions unchanged (profiles in SPEC §11). Protocol changes follow
SPEC §10 — breaking changes mint a new MAGIC, never a new version of this file's
meaning.
