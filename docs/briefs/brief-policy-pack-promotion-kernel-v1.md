# Brief — policy-pack-promotion-kernel-v1

**Status:** IMPLEMENTED · steps 1–6 complete · subject EXPERIMENTAL, gated by regenerable conformance evidence (`conformance/status.json`, sha256 `195446abe23fdfac8be2cbf4192465ee63dc51ff1e119077e4160d2733a57a67`) · closeout: [`closeout-policy-pack-promotion-kernel-v1.md`](closeout-policy-pack-promotion-kernel-v1.md) · 2026-08-26.

## 1. Objective

Turn the public Shedu Promotion Kernel foundation into a deterministic, provider-free promotion gate that evaluates an immutable candidate against a hash-bound work contract and a versioned policy profile. The profile selects reusable policy packs; the kernel compiles them, executes every admitted check, proves that every result reaches the final disposition, and emits a verifiable `PROMOTABLE` or `BLOCKED` receipt.

The first implementation must support exact scope control, validation completeness, prior-art admission, and orphan-mechanism closure without importing the legacy Mode A/B/C controller, its authoring loops, or any model-provider dependency.

## 2. Current State and Prior Art

`shedu-promotion-kernel` currently exposes only an honest `FOUNDATION_ONLY` subject probe. It has no promotion entrypoint, policy engine, model connection, provider credential, target-repository adapter, evidence bundle, or signing path.

The existing Shedu repositories contain useful mechanisms but no clean policy-pack product:

- `lib/write-set-block.mjs` provides a fail-closed typed write-set and canonical digest, but its authority is embedded in a Markdown spec format. The kernel should preserve the typed-path and canonical-digest properties while moving authority into `work-contract@1` JSON.
- `governance-prior-art.mjs` combines a hand-authored capability ledger, generated repository surface, and bounded source inventory. Its project-specific paths must not move into the kernel; its three-layer design should become a target-supplied `capability-index@1` adapter.
- `control-activation-registry.mjs` records registered controls, declared consumers, activation evidence, and operational liveness. Its principle should become the kernel's no-orphan admission law, without copying the monolithic list of historical controls.
- `zero-provider-preflight.mjs` demonstrates that command identity, machine-report capture, shared-base identity, registry admission, and control activation can be checked before any provider call. Policy-pack evaluation v1 must remain entirely zero-provider.
- `evidence-bundle.mjs`, material-tree binding, changed-file attribution, and Ed25519 signing are valid promotion primitives. They may be extracted behind new small contracts after parity tests; the surrounding controller lifecycle must not be transplanted.
- The historical tier matrix and customer governance modes are policy-selection designs, not a portable pack implementation. Tier classification remains outside the kernel. The kernel receives an explicit profile and proves what it enforced.

## 3. Architectural Decision

The kernel owns mechanism; the target repository owns policy content.

```text
Nabu, human, or coding agent
        |
        v
work-contract@1 + policy-profile@1
        |
        v
policy compiler ----> immutable compiled-policy-plan@1
        |
        v
frozen base + frozen candidate + isolated validators
        |
        v
typed check results ----> disposition reducer
        |
        v
PROMOTABLE | BLOCKED receipt bound to every input digest
```

A slice number, brief, specification, prompt, Nabu conversation, or model transcript may be referenced as provenance, but none is executable authority. The kernel acts only on the compiled work contract and profile.

## 4. Required Machine Contracts

### 4.1 `work-contract@1`

Schema-validated JSON containing:

- target repository identity and immutable base commit;
- candidate commit or tree identity;
- objective and acceptance-criterion identifiers;
- exact `allowed`, `readonly`, and `forbidden` path sets;
- exact required validation command arrays;
- declared policy profile id and expected profile digest;
- declared capability-index path and digest when prior-art enforcement is enabled;
- artifact output root, maximum runtime, and resource ceilings;
- authorization identity, issuance time, and optional external signature.

The contract contains no shell command strings. Commands are arrays of non-empty strings. A material scope expansion requires a newly authorized contract; the kernel cannot widen the existing contract.

### 4.2 `policy-pack@1`

A pack is declarative data with:

- stable `packId`, semantic `version`, and description;
- one or more phases from `CONTRACT_ADMISSION`, `CANDIDATE_VALIDATION`, and `PROMOTION_FINALIZATION`;
- explicit dependencies by pack id, version constraint, and expected digest;
- one or more uniquely named checks;
- check effect `BLOCKING` or `ADVISORY`;
- validator kind `BUILTIN` or `TARGET_COMMAND`;
- builtin validator id or exact target-command argv array;
- typed input selectors and output schema id;
- timeout, network policy, filesystem policy, and environment-name allowlist;
- declared result consumer `DISPOSITION_REDUCER` or `EVIDENCE_ONLY`.

Packs cannot contain JavaScript, templates that generate commands, shell fragments, secret values, override rules, or model prompts. A target command executes only from the trusted base revision, read-only, with no network by default. Its path and bytes are hash-bound before candidate evaluation.

### 4.3 `policy-profile@1`

A profile selects exact pack versions and digests and assigns their enforcement modes. Profiles compose constraints by union: one pack cannot weaken, suppress, or override another pack. An incompatible pair produces `POLICY_CONFLICT`; dependency cycles, missing packs, duplicate check ids, unknown validator ids, and digest mismatches fail compilation.

Profile choice is made before candidate work and stored in the work contract. The candidate branch cannot change the effective profile. A personal repository may choose a light profile; an organization may choose a stronger profile without changing kernel code.

### 4.4 `compiled-policy-plan@1`

The compiler resolves the profile to a canonical, deterministic plan containing the ordered check DAG, every source digest, exact argv arrays, resource bounds, expected outputs, and disposition effects. Equal inputs must produce byte-identical plan bytes and digest. The runtime executes only this plan.

### 4.5 `promotion-receipt@1`

The receipt binds:

- kernel release identity;
- target repository, base, and candidate identities;
- work-contract, profile, pack, validator, compiled-plan, and capability-index digests;
- every check result and evidence artifact digest;
- changed-file attribution;
- start and completion timestamps;
- disposition and closed reason codes;
- signing public-key identity and signature when signing is configured.

No console text, model statement, or unindexed artifact can satisfy a check.

## 5. Recommended Initial Policy Packs

### 5.1 Mandatory kernel packs

1. **`candidate-identity@1`** — verifies repository root, immutable base and candidate identities, clean materialization, candidate/base ancestry policy, and post-validation tree stability.
2. **`scope-boundary@1`** — compares every changed path with the authorized path sets; readonly and forbidden changes block; unclassified changes block; contract or profile mutation in the candidate never changes authority.
3. **`validation-plan@1`** — preserves exact command arrays, rejects shell-string reconstruction, runs every required command once per declared phase, captures machine reports, and proves completeness.
4. **`evidence-binding@1`** — indexes every required result, hashes artifacts, rejects missing or mutated evidence, and binds all results to the same candidate and compiled plan.

These four are kernel integrity, not optional project taste. A profile may add constraints but cannot remove them.

### 5.2 Target-selectable packs

5. **`prior-art-admission@1`** — consumes a target-owned `capability-index@1` plus a pre-candidate query manifest. A `doNotRebuild` collision blocks unless the work contract declares an allowed follow-up classification or carries a separately authorized exception receipt. The pack proves that the declared search ran against the declared index; it does not claim that keyword matching can prove semantic completeness.
6. **`orphan-closure@1`** — consumes a target-owned `mechanism-registry@1`. Every new or changed mechanism must declare its owner, producer, runtime consumer, input schema, output schema, activation phase, evidence sink, and at least one planted negative fixture whose firing changes the disposition. Registration without runtime dispatch, runtime dispatch without registration, or produced evidence not consumed by the reducer blocks.
7. **`architecture-boundaries@1`** — runs target-supplied import, ownership, dependency-direction, schema, or call-boundary validators from the trusted base revision.
8. **`target-test-suite@1`** — runs repository-specific tests, type checking, linting, migration checks, and generated-code checks through exact argument arrays and declared machine reporters.

Do not create a single `shedu-all-rules` pack. Compose small packs with independent negative controls so failures identify one authority and packs remain reusable.

## 6. Prior-Art Recommendations

The existing prior-art mechanism should be adapted, not copied verbatim:

- Define `capability-index@1` as JSON Schema rather than constrained YAML parsing inside the public kernel.
- Keep capability content in the target repository or a separately signed policy repository.
- Bind the index to the trusted base commit and reject candidate-authored changes as authority for the current run.
- Require canonical owners, stable identifiers, canonical files, allowed follow-ups, and receipt references for `doNotRebuild` entries.
- Generate a source-surface inventory mechanically and retain the distinction between declared intent, generated surface, and physical discovery.
- Treat unacknowledged protected collisions as blocking. Treat ambiguous semantic similarity as a structured `REVIEW_REQUIRED` admission result for an external authority, not a controller guess.
- Do not add an LLM call to the kernel in v1. Nabu or another authoring system may propose query terms or a collision resolution, but the authorized structured result must be supplied before policy compilation.

## 7. No-Orphan Recommendations

The existing control registry is directionally correct but insufficient as a reusable pack because consumer wiring can be asserted by string occurrence without proving execution or disposition effect. `orphan-closure@1` must require all of the following:

1. **Registration:** exactly one registry row for every admitted mechanism and check.
2. **Implementation:** every registered validator id resolves to exactly one executable implementation from the trusted source.
3. **Dispatch:** the compiled plan includes the check in an applicable fixture.
4. **Production consumption:** the runtime result reaches the declared evidence sink and disposition reducer.
5. **Activation proof:** a planted violation makes the check `FIRED` and changes the final disposition when blocking.
6. **Pass proof:** a conforming fixture records `OBSERVED` without firing.
7. **Reverse census:** exported validators, registered checks, dispatched checks, emitted results, and consumed results form equal sets after declared exclusions.
8. **Operational liveness:** receipts distinguish `LANDED_ONLY`, `INTEGRATED`, `CANARY_PROVEN`, and `OPERATIONAL`; only the configured minimum status satisfies promotion.

The census is generated from schemas, compiled plans, runtime events, and receipts. A prose closeout or test-only import cannot establish liveness.

## 8. Runtime and Authority Rules

- Resolve policy only from the immutable base commit or a pinned signed external source.
- Materialize the candidate separately; never execute candidate-modified policy as authority over that candidate.
- Execute target commands without a shell, with exact argv preservation, fixed working directory, environment-name allowlist, secret-value exclusion, no network by default, timeout, abort, and bounded output capture.
- Reserve no model budget and read no model-provider credential in v1.
- Run blocking checks to completion when safe so one invocation reports all independent failures; stop immediately on identity, containment, authority, or evidence-integrity failure.
- Advisory results are retained but never converted into blockers by the reducer.
- A coding agent may read structured failures and repair a new candidate, but it cannot mutate the prior receipt, profile, pack, base authority, or promotion credential.
- Each retry is a new candidate evaluation bound to a new candidate identity; unchanged successful evidence may be reused only when the plan explicitly marks the check cacheable and all bound input digests match.

## 9. Required Engineering

Implement, at minimum:

- JSON Schemas for the five contracts in section 4 plus `capability-index@1`, `mechanism-registry@1`, typed check results, and closed reason codes;
- canonical JSON hashing with duplicate-key rejection, byte and collection bounds, unknown-key rejection, and path-containment validation;
- policy-pack loader, profile resolver, dependency/conflict compiler, deterministic plan serializer, and two-way orphan census;
- builtin implementations for the four mandatory packs;
- isolated exact-argv target-command runner with machine-report capture;
- initial target-selectable packs from section 5.2 using synthetic target adapters;
- disposition reducer with no override path and explicit `ADVISORY`, `PASS`, `BLOCK`, and infrastructure-failure semantics;
- content-addressed evidence index, offline verifier, and optional Ed25519 receipt signer;
- CLI surfaces `compile`, `evaluate`, `verify-receipt`, and `subject-probe`, each with machine-readable stdout and errors on stderr;
- a `FOUNDATION_ONLY` to `EXPERIMENTAL` status transition controlled by passing conformance evidence, not a README edit.

## 10. Acceptance Criteria

- **AC-1:** Every schema rejects unknown keys, duplicate keys, malformed paths, moving refs, command strings, empty argv, out-of-bound collections, and secret-bearing fields.
- **AC-2:** Equal work contract, profile, packs, base, and candidate produce byte-identical compiled-plan and evaluation digests.
- **AC-3:** A candidate modification to its policy profile, pack, validator, protected test, or capability index cannot change the authority used for that evaluation.
- **AC-4:** Exact argv containing spaces, delimiters, quotes, Unicode, empty-position attacks, and shell metacharacters round-trips byte-for-byte and never invokes a shell.
- **AC-5:** Missing, extra, readonly, forbidden, symlink-escaped, case-colliding, or post-validation changed paths block under `scope-boundary@1`.
- **AC-6:** A protected prior-art collision blocks; an authorized allowed-follow-up passes; an ambiguous collision yields the declared external-review admission result without a kernel-authored semantic ruling.
- **AC-7:** The orphan census blocks each planted class: registered/unimplemented, implemented/unregistered, undispatched, emitted/unconsumed, blocking check whose negative fixture does not alter disposition, and evidence-only output falsely claimed as blocking.
- **AC-8:** Pack dependency cycles, digest drift, duplicate ids, unknown validators, incompatible packs, and attempted weakening overrides fail before candidate commands run.
- **AC-9:** Every required command executes or has an explicit non-success result; omitted work can never produce `PROMOTABLE`.
- **AC-10:** Evidence mutation, omission, replay against another candidate, profile, plan, repository, or base fails offline verification.
- **AC-11:** The receipt's disposition is reproduced from indexed results by the offline verifier; changing console prose has no effect.
- **AC-12:** No production file imports a model SDK, reads provider API-key variables, or makes an outbound model call; a static fence and runtime network negative prove this.
- **AC-13:** Three synthetic repositories pass conformance: minimal personal profile, standard team profile with prior-art and orphan closure, and strict profile with target architecture/test validators.
- **AC-14:** Harness Bench can materialize exact baseline and candidate kernel commits, invoke the subject probe, run the deterministic conformance matrix, and retain receipts without promotion credentials.
- **AC-15:** The complete reverse census reports equal registered, implemented, dispatched, emitted, and consumed blocking-check sets with zero undeclared exclusions.

## 11. Verification

Required evidence is generated rather than narrated:

- unit tests for schema bounds, canonicalization, compiler ordering, conflicts, reducer semantics, and receipt verification;
- property tests for exact argv preservation, path classification, stable hashing, dependency order, and disposition determinism;
- hostile fixtures for policy self-modification, symlink escape, candidate/base confusion, cache replay, evidence mutation, duplicate JSON keys, validator impersonation, advisory escalation, and orphan classes;
- integration tests over disposable Git repositories with independently pinned base and candidate commits;
- zero-network and zero-provider runtime tests;
- one zero-provider conformance run producing an offline-verifiable `PROMOTABLE` receipt and one planted-failure run producing `BLOCKED`;
- Harness Bench subject-contract and deterministic fake-run validation.

## 12. Non-Goals and Sequencing

This brief does not implement Nabu UI, GitHub App installation, hosted workers, billing, customer tier classification, model routing, authoring review, brief/spec/prompt generation, automatic scope expansion, deployment approval, or an autonomous repair loop.

Recommended order inside the implementation:

1. Schemas, canonical hashing, and immutable authority resolution.
2. Profile/pack compiler and two-way orphan census.
3. Mandatory builtin packs and disposition reducer.
4. Exact-argv target-command runner and evidence index.
5. Prior-art, orphan-closure, architecture, and target-test adapters.
6. Receipt verification/signing and Harness Bench conformance.

Do not extract legacy code until the new contract has a failing test that the extracted primitive uniquely satisfies. The implementation is complete only when a coding agent can repeatedly submit immutable candidates, receive structured failures, repair externally, and obtain a verifiable pass without any controller judgment or model-provider connection inside the kernel.
