# Brief — externally-attested-kernel-lifecycle-v1

**Owners:** public `Shedu-ai/shedu-promotion-kernel` verifier and private
`Shedu-ai/shedu-harness-bench` evidence issuer

**Priority:** HIGH

**Status:** IMPLEMENTED · zero-provider qualification · external recertification
and pilot issuance pending · 276/276 kernel tests pass · 2026-09-05

## Objective

Extend the Promotion Kernel's mechanically derived lifecycle from:

```text
FOUNDATION_ONLY → EXPERIMENTAL
```

to:

```text
FOUNDATION_ONLY → EXPERIMENTAL → PILOT_ELIGIBLE → CERTIFIED
```

using externally signed evidence for one exact immutable kernel identity and a
separately hash-bound activation distribution.

This slice must make the existing public product eligible for a bounded real
pilot without introducing an LLM review experiment, a controller judgment, a
mutable status field, a self-issued certificate, or a second governance
engine. `CERTIFIED` is recognized by the lifecycle verifier but cannot be
issued until the separate operational-certification evidence slice completes
after the real pilot.

## Corrected design finding

The Promotion Kernel is a deterministic, model-independent promotion gate. It
does not author code, run Mode A/B/C, or select or invoke model providers.
Therefore an LLM A/A or A/B comparison is neither necessary nor pertinent to
kernel pilot eligibility.

Harness Bench's completed controller A/A calibration proves properties of the
standalone governed controller and its provider routes. It cannot be relabeled
as Promotion Kernel evidence. The earlier
`kernel-pilot-eligibility-evidence-v1` draft is superseded by the deterministic
qualification compiler in this brief.

## Current state and prior art

The public kernel already has the mechanisms needed for a smaller lifecycle
extension:

- `committedAdmission()` derives `EXPERIMENTAL` only after recomputing
  conformance and verifying an external Ed25519 attestation;
- the admission result is module-private and branded, so a caller-built status
  object has no authority;
- the attestation binds the exact kernel release, commit, conformance status,
  mechanism inventory, and control surface;
- Harness Bench owns a protected external evidence issuer and independently
  reproduced the current conformance certification;
- `v0.4.0-experimental.1` provides an immutable activation manifest, public
  authority, detached evidence, exact-commit installer, and launcher;
- the launcher has already produced a real `PROMOTABLE` receipt and a planted
  `BLOCKED` receipt; and
- the kernel has macOS and pinned Linux OCI isolation backends, offline receipt
  verification, control-liveness proofs, and two-way orphan censuses.

The missing mechanism is a versioned lifecycle attestation whose evidence
strength determines the highest admitted status. The existing public
distribution remains honestly `EXPERIMENTAL` and must not be relabeled.

One completed capability is not on public `main`: bounded multi-process Linux
execution is retained on remote commit
`0adeb19c4b5bbc5715d150e496217b4eaa478a0a`. Before freezing the pilot
candidate, that work must either be integrated onto current `main` and
recertified or be explicitly excluded from the pilot's claimed capability and
platform profile. It cannot be treated as available merely because its branch
tests passed.

## Lifecycle meanings

### `FOUNDATION_ONLY`

An unauthenticated source checkout. It may be inspected and tested, but it has
no externally admitted promotion entrypoint.

### `EXPERIMENTAL`

The exact kernel identity passed the existing external conformance
certification. It may evaluate real candidates through its admitted launcher,
but it has not yet passed the public pilot-qualification policy.

### `PILOT_ELIGIBLE`

The exact already-`EXPERIMENTAL` kernel passed the deterministic qualification
in this brief and is available through a verified pilot activation
distribution for the bounded real operational pilot declared by its signed
pilot policy.

This status does not mean evaluated software is correct, that the kernel is
production-certified, or that use outside the signed pilot boundary is
authorized.

### `CERTIFIED`

The exact already-`PILOT_ELIGIBLE` kernel completed the separately specified
operational evidence policy and holds a current external certification
attestation. Certification is expiring, renewable, and revocable. It never
certifies the correctness of every candidate the kernel evaluates.

## Authority boundary

The kernel cannot issue or select its lifecycle status. Harness Bench compiles
qualification evidence from immutable inputs, and a protected external
environment holding the existing kernel-attestation Ed25519 key signs the
canonical lifecycle statement. Normal Bench jobs, the kernel repository,
target repositories, coding agents, model providers, work contracts, policy
packs, and command-line callers have no signing key.

The protected workflow is the issuance boundary. Its request must bind the
exact unsigned statement and evidence root before the protected environment is
entered. Changing the statement after approval invalidates the signature.

This slice does not introduce a new key hierarchy. The existing externally
published authority record remains the trust root for the first pilot. Key
rotation is expressed as a new authority record signed through the protected
issuer and a new immutable distribution; mutable environment values cannot
substitute a key at runtime.

## Mechanical contract

### 1. Versioned lifecycle contracts

Add closed schemas for:

- `kernel-lifecycle-attestation@1`;
- `kernel-pilot-qualification-policy@1`;
- `kernel-pilot-qualification-input@1`;
- `kernel-pilot-qualification-receipt@1`;
- `kernel-agent-status@2`; and
- `promotion-kernel-activation-distribution@2`.

Do not widen the existing `@1` status or activation schemas in place. Every
object uses `additionalProperties: false`; every digest, identity, time,
status, reason, evidence kind, and transition is closed and bounded.

### 2. Exact lifecycle attestation

The signed lifecycle attestation binds at least:

- subject id and canonical repository;
- kernel release, commit, and tree;
- activation-profile id and version;
- digest of the unsigned activation bundle specification, which excludes the
  lifecycle attestation and final publication identities;
- requested status;
- exact predecessor status and attestation digest;
- evidence kind from the closed set `PILOT_QUALIFICATION_COMPLETE` or
  `OPERATIONAL_CERTIFICATION_COMPLETE`, and canonical public-evidence digest;
- evidence-policy id, version, and digest;
- private evidence-manifest root digest;
- conformance-attestation and certification digests;
- mechanism-inventory and control-surface digests;
- claimed platform and execution-profile set;
- issue time, validity start, expiry, and maximum clock skew;
- monotonically increasing lifecycle sequence;
- superseded lifecycle-attestation digest or `null`; and
- external authority id, algorithm, public key, and signature.

The signature covers canonical bytes with only the signature byte field set to
`null`. A different projection is not admissible. The signature's key must
equal the separately supplied activation-authority record; a public key carried
only inside the signed object cannot establish its own trust.

### 3. Evidence ladder and transition reducer

Derive the highest valid state in this order:

```text
valid source + no external evidence                         FOUNDATION_ONLY
valid external conformance evidence                        EXPERIMENTAL
conformance + deterministic pilot qualification            PILOT_ELIGIBLE
pilot predecessor + operational certification evidence     CERTIFIED
```

Legal transitions are:

```text
FOUNDATION_ONLY -> EXPERIMENTAL
EXPERIMENTAL -> PILOT_ELIGIBLE
PILOT_ELIGIBLE -> CERTIFIED
PILOT_ELIGIBLE -> PILOT_ELIGIBLE  (fresh qualification renewal)
CERTIFIED -> CERTIFIED              (fresh operational renewal)
CERTIFIED -> PILOT_ELIGIBLE         (signed downgrade or expiry)
PILOT_ELIGIBLE -> EXPERIMENTAL      (signed downgrade or expiry)
any status -> FOUNDATION_ONLY       (source/conformance admission failure)
```

A renewal requires new evidence, a new validity interval, and an incremented
sequence. Expiry or invalid higher evidence reduces to the highest lower state
whose independent evidence remains valid. No skipped advancement, stale
predecessor, same-evidence renewal, sequence replay, status inversion, or
cross-identity substitution is accepted.

`PILOT_QUALIFICATION_COMPLETE` may request only `PILOT_ELIGIBLE`.
`OPERATIONAL_CERTIFICATION_COMPLETE` may request only `CERTIFIED` and must name
an exact valid `PILOT_ELIGIBLE` predecessor. The mapping is semantic validation,
not a convention in documentation.

### 4. Deterministic pilot qualification

Harness Bench adds one zero-provider compiler. It consumes only an explicit,
digest-complete input manifest and a policy frozen before execution. The
policy binds the exact candidate identity, claimed platforms and execution
profiles, commands, ceilings, required fixtures, evidence authority, and a
maximum `PILOT_ELIGIBLE` validity of 60 days.

Qualification requires all of the following for the same kernel identity and
unsigned activation specification:

1. a current externally signed `EXPERIMENTAL` conformance certification;
2. full kernel tests passing on macOS and pinned Linux OCI for every claimed
   platform/profile;
3. byte-identical conformance status reproduction;
4. complete mechanism and runtime-control censuses with no finding or
   exclusion added for qualification;
5. successful clean installation and `doctor` from an isolated candidate
   activation bundle using fixture lifecycle evidence that cannot be published
   as authority;
6. one real conforming target producing a verified `PROMOTABLE` receipt on
   every claimed platform/profile;
7. one planted scope or policy violation producing a verified `BLOCKED`
   receipt with the intended disposition-changing control observed on every
   claimed platform/profile;
8. offline verification of every receipt, plan, work contract, evidence index,
   artifact root, and optional receipt signature;
9. exact package/repository/release/manifest member equality;
10. secret scan and authority-path substitution negatives passing; and
11. no unresolved critical or high-severity kernel defect in the signed pilot
    policy's incident input.

No model or provider call occurs. A controller narrative, A/A or A/B receipt,
README claim, GitHub label, passing branch, or manually assembled checklist
cannot satisfy the compiler.

The compiler emits only:

- `PILOT_QUALIFICATION_COMPLETE`; or
- `PILOT_QUALIFICATION_INCOMPLETE` with closed reason codes.

### 5. Branded ordered admission

Replace the binary experimental-only admission outcome with one module-private
branded ordered outcome. Export only accessors that require the brand:

- `isAdmitted()` — status is `EXPERIMENTAL` or higher;
- `isPilotEligible()` — status is `PILOT_ELIGIBLE` or `CERTIFIED`;
- `isCertified()` — status is exactly `CERTIFIED`; and
- `admittedLifecycleStatus()` — returns the derived status from a branded
  outcome only.

The evaluation entrypoint remains available for every admitted status at or
above `EXPERIMENTAL`. A higher lifecycle status cannot weaken scope,
validation, sandbox, authority, evidence, reducer, signing, or orphan closure.

### 6. External inputs and bounded transport

The v2 launcher owns paths for the conformance evidence, lifecycle
attestation, qualification evidence, authority record, and expected immutable
identities. These inputs cannot be replaced by target files, ambient authority
variables, work contracts, policy packs, candidate arguments, or controller
overrides.

All authority files use bounded regular-file reads. FIFOs, devices, symlinks,
oversized files, duplicate JSON keys, non-canonical signed bytes, path escapes,
wrong media types, and digest drift fail closed.

### 7. Versioned public activation

Generalize the existing experimental activation compiler and launcher rather
than creating a separate release-publishing system. A v2 activation manifest
binds the complete evidence set, signed lifecycle attestation, exact kernel,
and requested lifecycle state. The launcher must ask the detached exact kernel
to derive its status; it never trusts the manifest's status label.

The lifecycle attestation must not bind the digest, commit, or tree of a
manifest or repository object that contains that attestation. That would create
an unsatisfiable self-hash cycle. Instead:

1. the qualification policy binds the immutable kernel and unsigned activation
   bundle specification;
2. the lifecycle attestation binds those exact inputs and the qualification
   evidence root;
3. the completed activation manifest binds the lifecycle attestation;
4. the package and release-asset censuses bind the completed manifest; and
5. a publication receipt created after merge binds the final distribution
   commit, tree, tag, and release assets.

The operator may prepare and merge the first pilot release through the normal
protected pull-request process. The bundle itself, generated status block,
package membership, release assets, and tag identity must be deterministic and
census-equal. Full GitHub PR/release automation is deferred until repeated
publication demonstrates that it removes meaningful operator risk.

The existing `v0.4.0-experimental.1` tag and evidence remain immutable and
continue to derive exactly `EXPERIMENTAL`.

### 8. Status projection and next actions

`kernel-agent-status@2` reports the derived status, exact subject and
distribution identity, applicable evidence digests and validity, admission
reason codes, promotion-entrypoint availability, and exhaustive next actions.

Add closed next-action lanes for at least:

- `COMPLETE_PILOT_QUALIFICATION`
- `OBTAIN_PILOT_ATTESTATION`
- `RUN_BOUNDED_OPERATIONAL_PILOT`
- `COMPLETE_OPERATIONAL_CERTIFICATION`
- `RENEW_LIFECYCLE_EVIDENCE`
- `PROCESS_LIFECYCLE_DOWNGRADE`

The projection never instructs a user or agent to edit a status field.

## Hostile acceptance

- A hand-built `PILOT_ELIGIBLE`, `CERTIFIED`, or `admitted: true` object has no
  authority.
- Controller A/A or A/B evidence cannot satisfy kernel qualification.
- Evidence for another repository, subject, kernel commit/tree, activation
  specification, policy, platform, profile, or predecessor cannot elevate the
  kernel.
- A passing feature branch that is absent from the frozen candidate cannot be
  claimed as a capability.
- One missing, skipped, duplicated, extra, unverifiable, or digest-drifting
  required qualification result blocks eligibility.
- A `BLOCKED` fixture caused only by infrastructure failure does not prove a
  policy control fired.
- Changed source, mechanism inventory, control surface, conformance evidence,
  launcher, manifest, authority, policy, or package membership invalidates the
  higher status.
- Missing or invalid external signature, expired validity, future validity,
  excessive clock skew, predecessor mismatch, sequence replay, or reused
  evidence fails the higher state.
- Failure of pilot evidence leaves a still-valid `EXPERIMENTAL` admission
  intact.
- `CERTIFIED` cannot be issued from the pilot-qualification evidence kind.
- Direct unauthenticated source remains `FOUNDATION_ONLY`.

## Wiring and orphan closure

This slice is incomplete unless all of the following are mechanically joined:

- v2 schemas → contract registry → semantic validators;
- pilot policy → exact input manifest → qualification compiler;
- conformance evidence + qualification receipt → lifecycle attestation;
- authority record → signature verifier → lifecycle reducer;
- predecessor + sequence + validity → ordered branded admission;
- branded admission → subject probe → agent status → next-action registry;
- CLI/launcher declaration → worker propagation → second admission gate;
- v2 activation manifest → package → release assets → fresh-clone doctor;
- qualification fixtures → receipts → offline verifier → evidence root;
- every new reason code → closed reason registry → hostile fixture; and
- every new control → source discovery → registry → runtime proof → production
  trace → control census.

The two-way lifecycle census must contain equal registered, implemented,
dispatched, emitted, and consumed identities. No prose exclusion, manual status
edit, unregistered workflow, or evidence file without an exact producer and
consumer is permitted.

## Acceptance evidence

- Two clean qualification runs over identical inputs emit byte-identical
  receipts and evidence roots.
- A protected external issuance produces one valid lifecycle attestation for
  `PILOT_ELIGIBLE` and no other status.
- After publication, fresh public clones on every claimed platform derive
  `PILOT_ELIGIBLE`, run the real conforming and planted-block fixtures, and
  verify their receipts offline.
- Removing or mutating any bound member reduces the status mechanically and
  fails the appropriate hostile fixture.
- Existing experimental activation still derives exactly `EXPERIMENTAL`.
- Full kernel, Bench qualification, package, secret-scan, control-liveness,
  and no-orphan suites pass.

## Binding sequence

1. Integrate bounded-process execution onto current kernel `main`, or freeze a
   pilot policy that explicitly excludes it. The recommended pilot includes
   the existing bounded-process work and claims both macOS strict execution and
   Linux OCI strict/bounded execution.
2. Implement this lifecycle slice on that resolved base.
3. Because implementation changes the kernel identity, Harness Bench must
   externally recertify the exact resulting commit to restore
   `EXPERIMENTAL`.
4. Execute the zero-provider deterministic qualification and protected
   issuance for that exact identity.
5. Publish a new immutable pilot prerelease whose fresh-clone doctor derives
   `PILOT_ELIGIBLE`.
6. Run the separately declared bounded real operational pilot.
7. Refresh and implement `kernel-operational-certification-evidence-v1` using
   the retained real-pilot records, then issue `CERTIFIED` only if its frozen
   reducer completes.

## Non-goals

- Running an LLM A/A or A/B experiment.
- Changing the governed controller's Mode A, Mode B, executor, or Mode C.
- Certifying target software correctness or model quality.
- Letting Harness Bench source code, the kernel, or a coding agent self-sign.
- Treating an unmerged branch as an active kernel capability.
- Automating GitHub publication before the first pilot release.
- Issuing `CERTIFIED` without completed operational evidence.
- Claiming guaranteed revocation delivery or secure global time for offline
  installations.
