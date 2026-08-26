# Closeout — policy-pack-promotion-kernel-v1

This closeout is a pointer to machine evidence. No statement below satisfies
an acceptance criterion; the referenced mechanisms do.

## Mechanical evidence

- **Conformance matrix (AC-13/AC-14):** `node src/cli.mjs conformance --out <dir>`
  rebuilds the three synthetic repositories (minimal-personal, standard-team,
  strict-target), evaluates a conforming and a planted candidate in each,
  offline-verifies all six receipts with their evidence stores, and emits a
  deterministic `conformance-status@1`. The committed
  [`conformance/status.json`](../../conformance/status.json) is byte-for-byte
  reproducible by that command; `test/conformance.test.mjs` re-runs the matrix
  and compares bytes on every `npm test`.
- **Status transition:** the subject probe reports `EXPERIMENTAL` and
  `promotionEntrypointAvailable: true` only while the committed status
  document is schema-valid, `allPassed`, and pinned to the current kernel
  release (`src/cli.mjs` `subjectProbe`); anything else fails safe to
  `FOUNDATION_ONLY`. Negative controls: `test/subject-probe.test.mjs`.
- **No-orphan law (AC-15):** `test/kernel-census.test.mjs` runs a real
  full-surface evaluation and proves registered = implemented = dispatched =
  emitted = consumed over the kernel's seven mechanisms
  ([`registry/kernel-mechanisms.json`](../../registry/kernel-mechanisms.json))
  with zero exclusions.
- **Acceptance criteria AC-1 … AC-15:** enforced by the suite (`npm test`,
  144 tests, zero-dependency, zero-provider). Hostile fixtures cover policy
  self-modification, symlink escape, candidate/base confusion, replay,
  evidence mutation, duplicate JSON keys, validator impersonation, advisory
  escalation, and every planted orphan class.
- **Zero-provider fence (AC-12):** `test/provider-fence.test.mjs` (static
  import/credential fence over `src/`) plus `test/runner.test.mjs`
  (constructed environment excludes ambient and provider variables at
  runtime).

## Checkpoints

- step 1–2 — schemas, canonical hashing, authority, compiler, census: `17b017e`
- step 3 — mandatory packs, validators, disposition reducer: `245190f`
- step 4 — exact-argv runner, evidence index, evaluate pipeline: `eb848fa`
- step 5 — prior-art, orphan-closure, architecture/target-test adapters: `0f50488`
- step 6 — receipts, signing, offline verification, conformance, transition:
  the commit introducing this document.

## Out of scope (unchanged from the brief)

Nabu UI, GitHub App installation, hosted workers, billing, tier
classification, model routing, authoring review, automatic scope expansion,
deployment approval, and autonomous repair loops remain external systems.
Result caching (brief §8's cacheable-check reuse) is intentionally not
implemented: every evaluation re-executes every check, which is the stricter
default.
