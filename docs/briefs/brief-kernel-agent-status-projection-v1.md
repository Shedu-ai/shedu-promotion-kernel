# Brief — kernel-agent-status-projection-v1

**Owner:** public `Shedu-ai/shedu-promotion-kernel`

**Consumers:** kernel CLI users, coding agents, and the private
`Shedu-ai/shedu-harness-bench` experiment

**Priority:** HIGH

**Status:** IMPLEMENTED LOCALLY · 245/245 deterministic tests green · zero-provider · commit/CI pin pending · 2026-08-28

## Objective

Give a coding agent a small, closed, deterministic view of the kernel's current
state, blockers, relevant evidence, and mechanically legal next actions without
changing the kernel's promotion decision or asking the agent to reconstruct that
state from a full receipt bundle.

This is a read-only interface over existing authority. The canonical
`promotion-receipt@1`, compiled plan, evidence index, evidence objects,
disposition reducer, admission result, and signed receipt remain the sole
authoritative records. A projection can explain those records; it can never
replace, amend, admit, reduce, sign, or promote them.

## Current-state finding and prior art

The kernel already provides the required authoritative substrate:

- `--subject-probe` reports subject implementation status and capability
  availability;
- `evaluate` atomically publishes `current/receipt.json`, `current/plan.json`,
  and the content-addressed evidence directory, then emits the complete receipt;
- `verify-receipt` verifies receipt, plan, evidence, disposition, and optional
  signature binding;
- `promotion-receipt@1`, `check-result@1`, `evidence-index@1`, and
  `reason-code@1` are closed contracts;
- the supervisor removes stale publication state and exposes only a complete
  `current` bundle.

The missing interface is not another governance mechanism. At the frozen base,
the no-argument CLI returned `KERNEL_NOT_IMPLEMENTED`; after an evaluation, an
agent had to read several large artifacts and infer which failures mattered and
what class of action was allowed. That repeated inference was avoidable and was
not promotion authority.

External agent-interface designs, including `axi.md`, are non-authoritative
design input only. No external runtime, provider, model, package, service, or
network call enters this slice.

## Mechanical contract

### 1. Closed projection contracts

Add strict, `additionalProperties: false` schemas for:

1. `kernel-agent-status@1` — subject admission/capability state;
2. `kernel-evaluation-summary@1` — a compact projection of one verified
   published evaluation;
3. `kernel-evidence-view@1` — metadata and an optional bounded preview for one
   verified evidence artifact; and
4. `kernel-next-action@1` — the closed action-lane enum consumed by both status
   schemas.

All emitted reason codes remain members of `reason-code@1`. All action lanes
come from one source-owned closed registry and are schema-checked. No free-text
recommendation, model-generated explanation, shell command string, or hidden
fallback is admissible.

The initial action lanes are:

- `OBTAIN_EXTERNAL_ADMISSION`
- `SUBMIT_EVALUATION`
- `RETURN_TO_AUTHORIZER`
- `REPAIR_CANDIDATE`
- `REPAIR_EVALUATION_ENVIRONMENT`
- `VERIFY_PROMOTABLE_RECEIPT`
- `EXTERNAL_PROMOTION_DECISION_AVAILABLE`
- `NONE`

The projection emits an ordered set of every applicable lane, not a single
first-error guess. The action set grants no write authority and contains no
executable argv.

### 2. Subject status and no-argument live view

Both of these exact invocations emit `kernel-agent-status@1` on stdout:

```text
node src/cli.mjs
node src/cli.mjs status
```

The document is derived in-process from `committedAdmission()` and the same
branded `isAdmitted()` decision used by `--subject-probe`. It contains the
kernel release, implementation status, promotion-entrypoint availability,
sorted capabilities, admission reason codes, and closed next-action lanes.

No-argument status is read-only and exits zero when it has truthfully reported
`FOUNDATION_ONLY`; lack of external admission is a state, not a CLI failure.
Unknown commands, unknown flags, duplicate flags, missing values, and malformed
values continue to fail closed with `CLI_USAGE` or the applicable closed reason
code.

`--subject-probe` preserves its schema, admission semantics, and existing
capability order. Its bytes change intentionally because the additive
`kernel-agent-interface@1` capability is now declared. The packaging test pins
the new exact document rather than making a false byte-identity claim.

### 3. Verified evaluation projection

This exact invocation reads a previously published output bundle:

```text
node src/cli.mjs status --out <evaluation-output-directory>
```

The command must:

1. resolve `current` without accepting an absolute target, containment escape,
   non-symlink substitution, nested link, or version directory outside `--out`;
2. read the receipt, plan, evidence index, and evidence objects only through
   bounded regular-file reads;
3. call the existing receipt verifier against the complete evidence directory;
4. recompute canonical digests instead of trusting a summary or filename;
5. emit no evaluation summary unless the complete authoritative bundle
   verifies; and
6. derive the projection entirely from the verified documents.

An absent `current` bundle emits a valid, explicit `evaluationState: "ABSENT"`
summary with `SUBMIT_EVALUATION`; malformed, stale, escaped, partial, mutated,
or replayed bundles fail with a closed reason code and exit 2. They do not
degrade to `ABSENT` and do not emit a best-effort summary.

For a present bundle, `kernel-evaluation-summary@1` contains only:

- repository, base, candidate, kernel release, and disposition;
- canonical receipt, plan, and evidence-index digests;
- total checks and counts by effect and outcome;
- every non-passing check's `checkId`, `packId`, effect, outcome, reason codes,
  and evidence artifact identifiers;
- changed-file counts by scope class and change kind;
- receipt signing presence and the result of complete receipt verification;
- the ordered closed next-action set.

The summary contains no evidence body, timestamps as narrative, inferred root
cause, repair proposal, or approval. Its schema sets finite collection and
string bounds so summary size is independent of command stdout/stderr volume.

### 4. Exhaustive next-action derivation

Implement one pure function and one checked-in mapping table that covers every
member of `reason-code@1`. CI fails if a reason code is added without an action
classification.

The mapping is structural and exhaustive:

- unavailable external admission maps to `OBTAIN_EXTERNAL_ADMISSION`;
- no published evaluation maps to `SUBMIT_EVALUATION`;
- authority, authorization, immutable-contract, or permitted-scope failures
  include `RETURN_TO_AUTHORIZER`;
- candidate, prior-art, policy, validation, or candidate-evidence failures
  include `REPAIR_CANDIDATE`;
- toolchain, sandbox, deadline, infrastructure, skipped-check, or incomplete
  execution failures include `REPAIR_EVALUATION_ENVIRONMENT`;
- a verified `PROMOTABLE` receipt includes
  `VERIFY_PROMOTABLE_RECEIPT` and
  `EXTERNAL_PROMOTION_DECISION_AVAILABLE`.

If several categories apply, all applicable lanes are emitted in registry
order. No controller/model supplies or overrides this classification. A lane
never enlarges the work contract, allowed write set, policy profile, or
promotion authority.

### 5. Evidence selectors

This exact read-only interface selects one artifact by authoritative identity:

```text
node src/cli.mjs inspect-evidence --out <evaluation-output-directory> --artifact <artifact-id> [--max-bytes <positive-integer>]
```

Before selection, the complete published bundle must pass the same verification
path as `status --out`. `artifact-id` must resolve exactly once in the verified
evidence index. The object path is derived from its recorded SHA-256 digest,
never from caller path input.

Without `--max-bytes`, `kernel-evidence-view@1` returns metadata only: artifact,
check and validator identities, media type, byte length, and digest. With
`--max-bytes`, the command may include a UTF-8 preview only for
`application/json` or `text/plain`; it reports requested bytes, returned bytes,
total bytes, and `truncated`. Invalid UTF-8 and `application/octet-stream`
remain metadata-only. The preview is explicitly non-authoritative and cannot
be supplied to verification, admission, reduction, or signing.

The maximum accepted preview bound is fixed in source. Negative, zero,
non-integer, over-ceiling, duplicate, or delimiter-composed values fail closed.

### 6. Optional compact evaluation stdout

Preserve today's `evaluate` invocation and full-receipt stdout as the default.
Add the value-bearing option:

```text
evaluate ... --projection full|agent
```

`full` is the default and must be byte-compatible with the current behavior.
`agent` may emit `kernel-evaluation-summary@1` only after atomic publication and
successful re-verification of the newly published complete bundle. The
on-disk bundle is identical under both options; the option controls stdout
presentation only.

The whole-operation deadline covers generation of the selected stdout
projection. A projection failure removes no valid authoritative bundle but
returns a nonzero CLI result; it never fabricates success.

### 7. Machine-declared consumer connection

Advance the Harness Bench subject-template contract to
`harness-bench-subject-template@2` rather than silently widening `@1`. The new
contract adds exact argv arrays and typed parameter maps for subject status,
evaluation status, and evidence inspection. Update `.harness-bench/subject.json`
to declare those entrypoints and `kernel-agent-interface@1` as a capability.

The kernel packaging test must build every new invocation only from the
declaration, execute it, schema-validate its output, and bind the exact argv.
Harness Bench consumption and comparative measurement are owned by the
separate `kernel-agent-interface-benchmark-v1` slice.

## Authority boundaries

- Projections are derived views, never signed evidence or policy authority.
- Receipt verification must succeed before any present-evaluation projection.
- The existing receipt, reducer, evaluator, admission, signing, and atomic
  publication modules do not import projection code.
- Projection modules may import verified contracts and receipt verification;
  authority modules may not import projection modules.
- Status and inspection commands create no file, acquire no promotion lock,
  invoke no validator, start no provider, and make no network call.
- A coding agent may use the view to decide what to inspect next, but only a
  new authorized work contract can change scope.

## Hostile acceptance

The slice is not complete until automated tests prove:

1. no-argument and explicit subject status are deterministic, schema-valid,
   and reflect the branded admission decision;
2. `--subject-probe`, existing CLI errors, and default full-receipt evaluation
   remain compatible;
3. every `reason-code@1` member has exactly one checked mapping entry and every
   possible emitted action is in `kernel-next-action@1`;
4. multi-failure receipts surface every applicable action lane and every
   non-passing check, regardless of result ordering;
5. a forged disposition, receipt digest, plan, candidate binding, evidence
   index, evidence object, signature, or `current` target yields no summary;
6. FIFO, device, socket, oversized file, symlink escape, nested symlink, file
   replacement, stale version, missing member, duplicate artifact identity,
   and invalid UTF-8 attacks fail promptly;
7. metadata-only inspection streams evidence bytes only through the complete
   digest verifier and never retains or emits an evidence body;
8. bounded preview never exceeds its fixed byte ceiling and never changes an
   authoritative digest;
9. summary size stays within its schema bound when a hostile valid receipt
   reaches maximum check and evidence-reference cardinality;
10. exact argv elements containing spaces, quotes, Unicode, semicolons, and
    shell syntax are never split or executed through a shell;
11. all projection paths run with zero provider calls and no network; and
12. the full conformance, activation, policy-mechanism census, runtime-control
    census, sample-policy, macOS, and Linux suites remain green.

## Wiring and orphan closure

This slice is incomplete unless all of the following are mechanically equal:

- every new schema is registered in `src/contracts.mjs`, implemented by one
  producer, dispatched by an exact CLI route, emitted in hostile tests, and
  consumed by the packaging test;
- every action enum member is reachable from a positive or planted negative
  fixture, while stale/unreachable mapping entries fail a census test;
- every declared subject-template argv is executable from the frozen subject
  checkout and every implemented read-only route is declared;
- no projection is registered as a blocking policy mechanism or runtime
  control, because it cannot affect disposition;
- static architecture tests reject any projection import from admission,
  evaluation, reducer, receipt construction, signing, or supervisor authority;
  and
- the follow-on Bench slice pins the exact kernel commit before any comparative
  run. Until that happens, the kernel interface is landed and self-tested but
  no comparative benefit is claimed.

No exclusion, manual ledger entry, README claim, or prose declaration can
satisfy these conditions.

## Non-goals

- generating or repairing code;
- selecting models, providers, agents, or policies;
- re-authoring briefs, specs, prompts, contracts, or write sets;
- changing `PROMOTABLE`/`BLOCKED` semantics;
- replacing canonical JSON or signed receipts with a compact encoding;
- embedding Harness Bench, Nabu, or any model runtime in the public kernel;
- natural-language diagnosis; or
- claiming that a shorter interface improves agent performance before the
  separate controlled benchmark produces evidence.

## Implementation sequence

1. Freeze schemas, action registry, source-architecture rule, and hostile
   fixtures.
2. Implement pure projection and next-action derivation against verified
   in-memory documents.
3. Wire subject status, evaluation status, and evidence inspection.
4. Add the optional evaluation stdout projection without changing the default.
5. Publish subject-template `@2` declarations and exercise them mechanically.
6. Run both orphan censuses, full conformance, cross-platform CI, and two
   byte-stability repetitions.
7. Pin the resulting clean commit as the candidate authority for
   `kernel-agent-interface-benchmark-v1`.

## Implementation evidence

- Closed schemas: `kernel-next-action@1`, `kernel-agent-status@1`,
  `kernel-evaluation-summary@1`, and `kernel-evidence-view@1`.
- Exact CLI routes: no-argument `status`, `status --out`,
  `inspect-evidence`, and `evaluate --projection full|agent`.
- Complete action registry: all 78 closed reason codes mapped; schema drift,
  unknown actions, missing mappings, and unreachable lanes fail at module load
  and in hostile tests.
- Presentation orphan census: three registered surfaces equal three contract
  registrations, producers, CLI dispatches, subject declarations, runtime
  emissions, and schema consumers; planted missing and rogue surfaces fail.
- Authority fence: admission, evaluation, reduction, receipt, signing,
  publication, and supervised evaluation cannot import projection modules.
- Verification: `node --test --test-concurrency=1` passed 245/245; the
  supervisor file independently passed 8/8; `git diff --check` passed.
- Test orchestration: the package test command pins file concurrency to one
  after the unbounded parallel runner wedged a V8 worker during shutdown under
  the combined sandbox workload; the deterministic serial command is the
  repository and CI acceptance command.
- Provider/network use by this slice: zero. Existing sandbox and provider-fence
  tests remain green.

Steps 1–6 are complete locally. Step 7 and a real Linux CI result require a
clean committed candidate and therefore remain mechanically pending until the
implementation is committed and pushed. No comparative agent-performance
claim is made by this slice.
