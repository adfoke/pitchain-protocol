---
title: Contributing
nav_order: 4
---

# Contributing

This is a standard, not a product. Rules of engagement:

1. **Vectors are frozen.** A released `vectors/` file never changes shape. New
   semantics → new version + new MAGIC (SPEC §10).
2. **Two implementations before merge.** Spec edits affecting §4/§5/§7 require the
   proposal to pass the untouched vectors suite in at least two independent
   implementations (the stdlib Python verifier here counts as one).
3. **Negative first.** Any new failure mode needs a negative vector proving honest
   verifiers reject it.
4. Keep the spec implementation-agnostic: no library names, no TypeScript.
