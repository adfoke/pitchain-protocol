---
title: Changelog
nav_order: 3
---

# Changelog

## v1.0.0 — 2026-09-07

- Initial normative spec: batch tree (§4), 45-byte `PCH1` anchor payload (§5),
  proof document (§6), verification with failure classes
  `data/tree/anchor/inclusion/script` (§7).
- Anchor-transaction script binding elevated to a protocol-level step (§7.3):
  the 45-byte payload must appear verbatim in a data-carrier output of the anchor tx.
- Conformance suite frozen: 12 tree vectors, anchor round-trips,
  4 positive + 6 negative end-to-end proofs incl. real mainnet block material.
- Reference conformance verifier: pure-stdlib Python, 25/25.
