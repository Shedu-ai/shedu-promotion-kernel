# Brief — bounded-process-tree-v1

**Owner:** public `Shedu-ai/shedu-promotion-kernel`

**Priority:** HIGH

**Status:** IMPLEMENTED LOCALLY · Linux activation pending CI · zero-provider ·
depends on `linux-oci-sandbox-v1` · 2026-08-27

## Objective

Permit explicitly authorized target validators to run a bounded tree of child
processes in the pinned Linux OCI sandbox, so realistic Node test and build
workloads can execute without weakening the existing single-process default,
exact launch-command identity, immutable authorities, containment controls, or
fail-closed promotion boundary.

The added machinery is internal. A human or coding agent continues to submit
one work contract and invoke one evaluation command. No Docker flag, seccomp
rule, cgroup setting, process count, or backend choice becomes an interactive
user decision.

## Current state and prior art

- `work-contract@1` fixes `resourceCeilings.maxProcesses` to `1`.
- `isolateExecution()` rejects every ceiling other than `1` before launch.
- Native macOS denies `process-fork` through its SBPL profile.
- Linux denies process creation through seccomp. Its OCI `--pids-limit 64`
  permits the one Node process's existing threads and is defense in depth; it
  is not an authorization for child processes.
- The Linux backend already binds the Docker client, daemon identity, OCI
  image, platform image, seccomp policy, and in-image Node path; denies network,
  writes, capabilities, privilege gain, and IPC; and removes the complete
  container after timeout or output failure.
- Whole-evaluation runtime, output, and artifact ceilings already exist and
  remain authoritative.
- `sandbox-process-ceiling` is already registered, dispatched, evidenced, and
  consumed. This slice strengthens that mechanism; it must not create a
  duplicate prose-only control.

No existing brief authorizes bounded child processes. This is separate from
operating-system portability and from admitting additional top-level
executables such as `npm`, browsers, databases, or compilers.

## Architectural decision

### Two execution classes

The machine contract admits exactly two classes:

1. `SINGLE_PROCESS` — the current behavior. Process creation remains denied.
2. `BOUNDED_PROCESS_TREE` — available only through the pinned Linux OCI
   backend and only when the trusted policy pack, authorized work contract,
   and selected policy profile all admit the required task budget.

`SINGLE_PROCESS` remains the default and the compatibility behavior for every
existing contract. A coding agent cannot infer, retry with, or increase a
process budget. Insufficient authorization produces a closed machine result
before target code runs.

### Authority intersection

The effective budget is compiled, not selected by the controller:

```text
base-owned policy-pack requirement
        ∩ authorized work-contract ceiling
        ∩ base-owned profile ceiling
        ∩ enforcing backend capability
        ↓
exact compiled task budget or closed refusal
```

The policy-pack requirement is the amount needed by a particular target
validator. The work contract and profile are ceilings, never grants that can
widen that requirement. The compiled plan uses the smallest required value.
Any missing, contradictory, or excessive value fails compilation.

### One enforceable unit

Linux cgroup `pids.max` counts tasks, including threads. The machine contract
therefore uses one internal numeric authority: `maxTasks`. It is the exact
combined ceiling for processes and threads. The `@2` contracts must not call
this value `maxProcesses` or imply that cgroups distinguish the two. A task
ceiling still places a hard upper bound on the number of child processes.
User-facing presets conceal the number; receipts expose it for audit.

## Machine-contract changes

Introduce versioned contract changes rather than silently changing the meaning
of an existing `@1` schema:

1. `policy-pack@2` requires every `TARGET_COMMAND` validator to declare an
   `executionRequirement` containing `class` and `maxTasks`. A
   `SINGLE_PROCESS` requirement retains process-creation denial; its task
   ceiling remains the kernel's measured Node-thread allowance.
2. `work-contract@2` authorizes an `executionCeiling` with the same closed
   fields. `maxTasks` is a positive integer with a kernel-defined hard maximum.
3. `policy-profile@2` adds an `executionPolicy` ceiling. Personal defaults may
   authorize the shipped standard preset; signed organizational profiles may
   lower it without changing kernel code.
4. `compiled-policy-plan@2` binds each check's required and effective class,
   task ceiling, backend capability id, OCI authority digest, and
   seccomp-policy digest.
5. `command-report@2` binds the enforced class and ceilings, a backend-produced
   resource report, and whether the task limit fired.
6. `promotion-receipt@2` and its offline verifier bind those plan and report
   fields without trusting console output.

Existing `@1` receipts remain offline-verifiable. Existing `@1` contracts
continue to mean exactly one process; they are not reinterpreted as `@2`.

## Linux enforcement contract

1. The strict seccomp profile remains byte-identical for `SINGLE_PROCESS`.
2. A separate checked-in, hash-bound bounded-tree seccomp profile admits only
   the process syscalls needed by the conformance workloads. Namespace creation,
   `unshare`, `setns`, privileged operations, network syscalls, and privilege
   gain remain denied.
3. The OCI invocation applies the compiled `maxTasks` through cgroup
   `pids.max`. Absence, rounding, substitution, or inability to read back the
   applied limit produces `SANDBOX_UNAVAILABLE`.
4. A small trusted process-tree supervisor is mounted read-only into the
   immutable OCI image. Its exact bytes are included in the portable plan
   authority and re-hashed with the runtime authority before every execution.
   It is PID 1, launches the exact declared Node argv without a shell, reaps
   descendants, retains the target exit status, and emits its resource report
   through a kernel-owned channel that target output cannot forge.
5. The supervisor records the applied limit and cgroup limit-fire counters.
   Any task-ceiling event makes the check non-success even if target
   code catches the failed fork and exits zero.
6. Timeout, output overflow, supervisor failure, or client interruption kills
   the entire container and all descendants. No background process survives
   evaluation.
7. Candidate and trusted-base materializations remain read-only and
   path-contained. Network, capabilities, no-new-privileges, IPC, environment,
   evidence, and output restrictions remain unchanged.
8. The exact declared top-level argv remains the command identity. Descendant
   behavior is bound to the frozen candidate/base inputs and immutable OCI
   image and is recorded as sandboxed execution, never represented as another
   declared top-level command.
9. Native macOS remains `SINGLE_PROCESS` until it can enforce the same numeric
   ceilings. A bounded request on native macOS returns
   `EXECUTION_BACKEND_REQUIRED`; it never silently weakens or raises the
   budget. Harness Bench or another orchestrator may route the immutable run to
   a conforming Linux worker using this machine reason code.

## Agent and human interface

- The existing evaluation invocation remains the only required action. There
  are no process-related CLI flags.
- Repository policy authors select a named preset when authoring a trusted
  pack; ordinary users do not enter numbers.
- Ship `STRICT` and `STANDARD_TEST` presets. `STRICT` compiles to
  `SINGLE_PROCESS`; `STANDARD_TEST` compiles to a bounded, versioned task
  ceiling.
- A browser/integration preset is a later slice because it also requires a
  separately governed image/toolchain and possible loopback, shared-memory,
  and service-lifecycle rules. This slice must not imply browser support.
- Preflight reports supported execution classes and hard maxima in structured
  output. Agents use that output only for routing; they cannot modify the
  authorized plan.
- Closed reason codes include `PROCESS_TREE_UNAUTHORIZED`,
  `TASK_BUDGET_EXCEEDED`, and `EXECUTION_BACKEND_REQUIRED`.

## Hostile acceptance

- Every existing single-process fixture remains byte-identical where its
  versioned contract permits and continues to prove the first child process is
  denied.
- A positive bounded fixture launches multiple Node children, waits for them,
  and produces a valid machine report and offline-verifiable receipt.
- A policy-pack requirement above either authorized ceiling fails compilation
  before sandbox or target execution.
- A controller-supplied override, environment variable, CLI flag, candidate
  policy edit, or retry cannot increase either ceiling.
- Fork bombs, rapid fork-and-exit loops, detached grandchildren, double-forks,
  and children that ignore termination cannot exceed the cgroup ceiling or
  survive cleanup.
- A target that catches `EAGAIN` and exits zero still fails when the cgroup
  limit-fire counter changed.
- `clone`/`clone3` namespace attacks, `unshare`, `setns`, network bind/connect,
  filesystem writes, capability acquisition, and privilege gain remain denied
  in bounded mode.
- Timeout and output-overflow fixtures prove that the entire tree is gone
  before the result is published.
- Target stdout cannot forge, suppress, truncate, or replace the supervisor's
  resource report.
- Missing cgroup v2 support, absent controllers, unsupported OCI behavior,
  supervisor/image drift, seccomp drift, or unverifiable readback fails closed.
- Replaying a bounded report against another candidate, plan, policy profile,
  OCI authority, or budget fails offline receipt verification.
- Linux CI runs the strict and bounded matrices repeatedly with zero leaked
  containers or processes. macOS CI proves strict compatibility and the
  structured bounded-backend refusal.

## Wiring and no-orphan closure

The slice is incomplete unless all of the following are mechanized:

1. Schemas validate the new authority and evidence fields with unknown-key
   rejection and closed enums.
2. The compiler derives and binds the effective budget without controller
   discretion.
3. The runner consumes the compiled budget and selects the matching seccomp
   authority.
4. The trusted supervisor emits a non-forgeable resource report.
5. The result reducer treats every ceiling event, skipped report, or backend
   mismatch as non-success.
6. Receipts and the offline verifier consume the same budget and resource
   evidence.
7. `sandbox-process-ceiling` remains the single registered control and gains
   positive strict, positive bounded, and planted-overflow activation evidence.
8. The control-surface census proves registration, implementation, dispatch,
   production observation, evidence consumption, and disposition effect on
   both Linux execution classes with no declared exclusion.
9. Subject capabilities, installation documentation, examples, CI, and Harness
   Bench packaging identify `bounded-process-tree@1` only after its activation
   evidence passes.
10. The kernel release changes, invalidating prior external admission evidence;
    the public probe remains honestly `FOUNDATION_ONLY` until new external
    attestation admits the changed execution boundary.

## Verification sequence

1. Freeze the `@2` schemas, closed reason codes, preset mapping, and migration
   fixtures before changing process enforcement.
2. Build and digest-pin the trusted PID-1 supervisor authority; prove exact argv,
   report-channel separation, descendant reaping, and whole-tree termination.
3. Add the bounded seccomp profile and cgroup readback; run the hostile runtime
   probes directly on Linux.
4. Wire compiler, runner, reports, receipts, verifier, reducer, and structured
   preflight end to end.
5. Update activation evidence and run the two-way policy-mechanism and runtime
   control censuses.
6. Run the full strict and bounded conformance matrices on pinned Linux CI,
   strict compatibility on macOS, sample-policy verification, and repeated
   leak detection.
7. Regenerate external admission evidence only after two independent runs
   reproduce the portable result projection.

## Non-goals

This slice does not admit ambient executables, shell command strings, network
access, mutable images, arbitrary Docker configuration, a hosted scheduler,
automatic remote execution, browser/database services, Windows isolation,
multi-process native macOS execution, provider calls, autonomous budget
increases, or user-facing infrastructure configuration.

Implementation is complete only when an interchangeable coding agent can
submit the same authorized contract, receive either a deterministic bounded
result or a closed routing/budget reason, and cannot obtain a larger execution
surface by changing its prompt, environment, candidate, retry behavior, or
controller implementation.
