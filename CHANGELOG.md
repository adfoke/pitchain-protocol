---
title: Changelog
nav_order: 3
---

# Changelog

## v1.0.1 — 2026-09-07

- SPEC §7.6 rewritten BIP144-aware: verifiers MUST handle the segwit marker/witness
  sections when scanning anchor tx outputs (real anchors are witness transactions; a
  legacy-only parser fails `pass-full`). Clarification, not a wire change.
- Vectors 1.1.0: `pp-full-script` / `fneg-script` now embed a **real signed
  P2WPKH witness transaction** (248B) instead of a hand-made legacy serialization.
- Reference verifier updated with the same branch; 25/25 on the new set.

## v1.0.0 — 2026-09-07

- Initial normative spec: batch tree (§4), 45-byte `PCH1` anchor payload (§5),
  proof document (§6), verification with failure classes
  `data/tree/anchor/inclusion/script` (§7).
- Anchor-transaction script binding elevated to a protocol-level step (§7.3):
  the 45-byte payload must appear verbatim in a data-carrier output of the anchor tx.
- Conformance suite frozen: 12 tree vectors, anchor round-trips,
  4 positive + 6 negative end-to-end proofs incl. real mainnet block material.
- Reference conformance verifier: pure-stdlib Python, 25/25.
