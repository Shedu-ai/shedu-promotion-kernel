# Brief — linux-oci-sandbox-v1

**Owner:** public `Shedu-ai/shedu-promotion-kernel`

**Priority:** HIGH

**Status:** IMPLEMENTING · zero-provider · 2026-08-27

## Objective

Add an enforcing Linux target-command backend without weakening the existing
macOS backend, exact command-array preservation, closed toolchain authority,
or the fail-closed public admission boundary.

## Mechanical contract

1. Linux target commands execute only in
   `docker.io/library/node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5`.
   No tag, moving reference, implicit pull, or fallback image is admissible.
2. Docker resolves only from fixed absolute paths. `PATH`, `DOCKER_HOST`,
   `DOCKER_CONFIG`, and `HOME` cannot substitute its executable, daemon, or
   client authority.
3. Evaluation requires the pinned image to exist before execution and uses
   `--pull never`; an explicit installation command is the sole pull surface.
4. Each command runs with no network namespace, read-only root and declared
   read mounts, all capabilities dropped, no-new-privileges, no IPC, an
   explicit task ceiling, and a checked-in seccomp policy that denies network,
   process creation, and privileged syscalls.
5. `maxProcesses: 1` is enforced by seccomp process-creation denial. The OCI
   task ceiling permits only the interpreter's existing threads and is
   defense-in-depth, not a substitute for fork denial.
6. Candidate roots are mounted read-only. Base-owned validator code is copied
   into a read-only projection containing only its declared input-manifest
   files; undeclared siblings never enter the container.
7. The declared argv remains an exact array in reports and at the in-container
   process boundary. Environment values are passed outside argv from a clean
   map and ambient host secrets are not inherited.
8. Timeout, output, evidence, phase, halt, reducer, receipt, activation, and
   census behavior remains unchanged. A timed-out Docker client triggers
   unique-container cleanup.
9. Unsupported platforms, absent Docker, a non-Linux daemon, missing pinned
   image, authority drift, failed enforcement probes, malformed mount paths,
   and any unsupported process ceiling fail with `SANDBOX_UNAVAILABLE`.
10. The kernel release advances to `0.4.0-experimental`, mechanically
    invalidating all admission attestations created for the prior execution
    boundary.

## Hostile acceptance

- Exact argv with spaces, quotes, shell syntax, Unicode, commas, and option-like
  arguments reaches Node byte-for-byte with no shell.
- Tags, auto-pull, mount delimiter injection, ambient Docker substitution,
  runtime/image drift, missing enforcement, and ceilings above one fail closed.
- Runtime probes demonstrate denied connect/listen, host-private reads, writes,
  and process creation, and verify zero effective capabilities,
  `NoNewPrivs: 1`, and seccomp mode 2.
- The complete suite and sample-policy verification pass on both a native macOS
  runner and an Ubuntu runner using the exact OCI digest.
- The existing policy-mechanism and runtime-control censuses remain complete;
  no new prose-only control or exclusion is added.

## Wiring and orphan closure

This slice is incomplete unless the runtime authority is consumed by the
toolchain, the runner consumes the platform backend and cleanup hook, all four
existing sandbox controls execute and are observed on Linux, installation is
explicit, Linux CI runs the complete suite, and public operating-boundary
claims name the exact supported configuration.
