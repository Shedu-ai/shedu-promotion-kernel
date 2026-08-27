# Closeout — policy-pack-promotion-kernel-v1

This closeout is a pointer to machine evidence. No statement below satisfies
an acceptance criterion; the referenced mechanisms do. It reflects the state
after the post-review correction pass, which replaced declared-only runtime
rules with enforced ones.

## Mechanical evidence

- **Runtime isolation:** every target command executes inside the mandatory
  OS sandbox (`src/sandbox.mjs`, darwin `sandbox-exec`): network denied,
  filesystem read-only (device-file exceptions only), fork denied under the
  `maxProcesses: 1` ceiling. The backend is probed by demonstrating an actual
  blocked network bind; if isolation is unavailable — including any platform
  without an implemented backend, or a process ceiling above 1 that this
  backend cannot cap exactly — execution FAILS CLOSED with
  `SANDBOX_UNAVAILABLE`. Negatives: `test/runner.test.mjs` (blocked connect,
  listen, write, fork; forced-unavailable refusal).
- **Resource ceilings:** `maxRuntimeSeconds` is an evaluation-wide deadline
  (per-command timeouts never exceed the remaining budget; past-deadline
  checks receive explicit `SKIPPED`/`DEADLINE_EXCEEDED` records),
  `maxOutputBytes` clamps captured output, `maxArtifactBytes` bounds the
  cumulative evidence store, `maxProcesses` is enforced as above.
- **Phase scheduling:** `validation-plan@1` dispatches one check per phase;
  each executes exactly the commands declared for its own phase, in that
  phase, with per-phase completeness proofs.
- **Halt semantics:** identity, containment, authority (admission), and
  evidence-integrity failures halt the run immediately; every remaining
  required check carries an explicit `SKIPPED` non-success record and the
  reducer fails closed on `CHECK_SKIPPED`.
- **Activation and liveness (brief §7 items 5–6):** never self-asserted.
  For target registries, any status above `LANDED_ONLY` requires hash-bound
  activation-pair evidence committed at the trusted base — a conforming
  receipt (check OBSERVED, PROMOTABLE) and a planted receipt (check FIRED as
  the sole failure, BLOCKED), both offline-verified (`src/activation.mjs`,
  enforced by `orphan-closure-verify@1`). For the kernel's own nine
  mechanisms, `conformance/status.json` carries a `kernelActivation` entry
  per mechanism, proven from retained receipt pairs on every matrix run; an
  unmapped or unproven mechanism fails the matrix.
- **Conformance matrix (AC-13/AC-14):** `node src/cli.mjs conformance --out
  <dir>` — ten deterministic cases (the three AC-13 profiles plus one
  activation case per kernel mechanism), twenty evaluations, all receipts
  offline-verified. The committed status document is byte-for-byte
  reproducible and re-compared on every `npm test`.
- **Status transition:** the probe reports `EXPERIMENTAL` only while the
  committed status is schema-valid, `allPassed`, and pinned to the current
  kernel release; the correction pass demonstrated the regression mechanism
  (version bump → probe fell back to `FOUNDATION_ONLY` until the corrected
  matrix passed).
- **No-orphan law (AC-15):** kernel self-census over a real full-surface run:
  registered = implemented = dispatched = emitted = consumed at 9/9/9/9/9,
  zero exclusions (`test/kernel-census.test.mjs`).
- **Zero-provider fence (AC-12):** static import/credential fence over
  `src/` plus the runtime negatives above; dependency tree provably empty.
- **Suite:** `npm test`, 152 tests, zero dependencies, zero providers.

## Checkpoints

- step 1–2 — schemas, canonical hashing, authority, compiler, census: `17b017e`
- step 3 — mandatory packs, validators, disposition reducer: `245190f`
- step 4 — exact-argv runner, evidence index, evaluate pipeline: `eb848fa`
- step 5 — prior-art, orphan-closure, architecture/target-test adapters: `0f50488`
- step 6 — receipts, signing, offline verification, conformance: `2eb0a3f`
- correction — enforced isolation, ceilings, phases, halts, activation
  evidence: the commit introducing this revision.

## Honest boundaries

- The sandbox backend is implemented for darwin (`sandbox-exec`); every
  other platform fails closed rather than running unisolated.
- A process ceiling above 1 is refused (fork denial is the only exact cap
  this backend offers); contracts requiring subprocess trees are therefore
  not yet evaluatable.
- Builtin validators are kernel code executing in the kernel process; the
  sandbox governs target-supplied code (target commands and validation
  commands), which is the trust boundary the brief draws.
- Result caching (brief §8 cacheable-check reuse) is intentionally not
  implemented; every evaluation re-executes every check.
- Wholesale coherent rewrite of an unsigned receipt bundle remains
  information-theoretically undetectable offline; Ed25519 signing exists for
  exactly that, and per-result evidence anchoring makes every partial
  tampering class detectable without it.

## Correction round 2 (adversarial re-review)

Six findings were closed with engineered fixes and hostile regression tests
(all generated, none narrated):

- **Host-filesystem disclosure:** `src/sandbox.mjs` is now `(deny default)`;
  content reads (`file-read-data`) are confined to the candidate/base
  materializations plus minimal immutable toolchain roots; metadata is
  allowed only for path resolution. Proof: `test/runner.test.mjs`
  (sibling-temp, home-credential, and out-of-root reads blocked; the exact
  `HOST_PRIVATE_VALUE_123` exfil returns `BLOCKED:EPERM`; candidate/base reads
  succeed).
- **Activation binding:** `src/activation.mjs` derives a canonical
  fingerprint over the full check tuple + pack digest + validator byte digest
  + phase/effect/consumer/release; both receipts, the current registry row,
  and the current dispatched plan check must prove the SAME fingerprint.
  Proof: `test/activation.test.mjs` (different-validator/base substitution,
  validator-byte drift, expected-fingerprint mismatch, structural-failure
  masquerade).
- **Evaluation deadline:** `src/deadline.mjs` is a monotonic
  (`perf_hooks.performance.now()`) absolute bound; every command is capped by
  the remaining ms and a late finish cannot be PASS. Proof:
  `test/enforcement.test.mjs` (1s deadline, two 700ms commands).
- **Self-attested EXPERIMENTAL removed:** `src/admission.mjs` recomputes
  `allPassed` (never trusts the bit) AND requires a pinned-key attestation
  binding the kernel commit; direct `evaluate` is gated identically. No key is
  pinned, so the honest result is FOUNDATION_ONLY. Proof:
  `test/subject-probe.test.mjs` (contradictory/unsigned/stale/wrong-commit/
  wrong-key/replay), `test/evaluate.test.mjs` (NOT_ADMITTED gate).
- **Control-surface census:** `src/control-census.mjs` compares controls
  discovered from source (`CONTROL_POINTS` exports) against the
  `control-surface@1` registry — independent sources — covering sandbox,
  ceilings, deadline, halt routing, activation/receipt verification, and
  admission. Proof: `test/control-census.test.mjs` (planted unregistered
  control, unimplemented registry row, absent proving test). Audit:
  `artifactRoot` now determines the evidence layout and is recorded in the
  receipt; `authorization.signature` is verified when present.
- **Process ceiling:** the schema constrains `maxProcesses` to `1`; a
  realistic multi-process runner cannot run and pilot stays blocked. Proof:
  `test/sandbox.test.mjs`.

Native run: darwin with `sandbox-exec`; nested-sandbox refusal is exercised
via an injected probe runner. Resulting subject status: FOUNDATION_ONLY.
