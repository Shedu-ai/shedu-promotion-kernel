# Closeout — bounded-process-tree-v1

**Status:** IMPLEMENTED AND ACTIVATED · 2026-08-28

## Mechanical result

- Existing `@1` authorities retain strict single-process execution.
- Versioned `@2` work contracts, policy profiles, packs, compiled plans,
  command reports, and receipts bind one closed execution requirement.
- The compiler intersects the base-owned pack requirement with the authorized
  contract and profile ceilings. A prompt, controller, environment variable,
  retry, or candidate edit cannot increase the compiled task budget.
- `STRICT` remains `SINGLE_PROCESS`. `STANDARD_TEST` compiles to
  `BOUNDED_PROCESS_TREE` with `maxTasks: 128` and routes only to the pinned
  Linux OCI backend.
- The bounded backend binds the immutable image, Node executable, seccomp
  bytes, PID-1 supervisor bytes, backend authority, cgroup task limit, exact
  argv, and final resource report.
- PID 1 reaps and terminates descendants before publication. A changed
  `pids.events` limit counter blocks even when target code catches `EAGAIN`
  and exits zero.
- Native macOS rejects bounded requests mechanically; it never widens the
  strict native sandbox.

## Linux activation repairs

- The bounded seccomp derivation admits ordinary non-namespace child creation
  while continuing to deny namespace flags, `unshare`, `setns`, process-group
  escape, capabilities, privilege gain, network creation, bind, connect, and
  listen.
- Only `socketpair(AF_UNIX, ...)` and `shutdown()` were added for Node/libuv
  child-process transport. `shutdown()` can only close directions on an
  existing descriptor; it cannot create or connect a socket.
- The readiness fixture executes exact JavaScript bytes, rejects nested launch
  errors and missing output, and uses synchronous descriptor writes so the
  supervisor receives complete evidence before target exit.
- Backend admission and the registered `sandbox-process-ceiling` proof consume
  one exported pressure-fixture artifact. The fixture drains and reaps its
  children, preventing stale duplicated probes from suppressing the PID-1
  resource report.
- Failed runtime proofs preserve bounded structured details in the control
  census instead of collapsing to an opaque title.

## Reproduced activation evidence

Commit `11386f595599a6b5ad50385051abaf7763b5a1f8` passed two unchanged attempts
of GitHub Actions run
[`33140772049`](https://github.com/Shedu-ai/shedu-promotion-kernel/actions/runs/33140772049):

- [attempt 1](https://github.com/Shedu-ai/shedu-promotion-kernel/actions/runs/33140772049/attempts/1):
  - Linux pinned OCI: 246 tests, 245 pass, 0 fail, 1 intentional macOS-only
    weakened-SBPL demonstration skipped;
  - macOS native sandbox: 246 pass, 0 fail;
  - executable sample policy and honest public probe passed on both jobs.
- [attempt 2](https://github.com/Shedu-ai/shedu-promotion-kernel/actions/runs/33140772049/attempts/2):
  - Linux pinned OCI: 246 tests, 245 pass, 0 fail, the same 1 intentional skip;
  - macOS native sandbox: 246 pass, 0 fail;
  - executable sample policy and honest public probe passed on both jobs.

The local macOS suite also passed 245/245 before the final shared-fixture test
was added; both final CI attempts are the authoritative cross-platform result.

## Orphan closure

- `sandbox-process-ceiling` remains the single registered process control; no
  duplicate control ID or declared exclusion was added.
- The runtime control census reports 21 registered / 21 proven and 14 required
  production observations / 14 observed, with no finding.
- The kernel mechanism census remains complete at 9 registered, implemented,
  dispatched, emitted, and consumed mechanisms, with all 9 activation pairs
  proven and no exclusion.
- The schema, compiler, runner, reducer, receipt verifier, preflight, subject
  capability, documentation, and CI consumers all bind
  `bounded-process-tree@1` mechanically.

## Retained boundary

- Bounded process trees require Linux, a conforming local Docker Engine, and
  the pre-materialized digest-pinned image.
- Target executables remain limited to the closed Node toolchain; this slice
  does not admit browsers, databases, network services, shell strings, or
  ambient executables.
- The public subject remains honestly `FOUNDATION_ONLY`. Version
  `0.5.0-experimental` invalidates prior external admission evidence; a new
  external attestation is required before promotion is available.
