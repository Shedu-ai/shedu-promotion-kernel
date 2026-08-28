# Closeout — linux-oci-sandbox-v1

**Status:** IMPLEMENTED · 2026-08-27

## Mechanical result

- Linux resolves Docker only at fixed absolute paths and fixes its daemon to
  the local Unix socket; ambient `PATH`, `DOCKER_HOST`, `DOCKER_CONFIG`, and
  `HOME` cannot substitute authority.
- The only admitted image is
  `docker.io/library/node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5`.
  Evaluation uses `--pull never`; installation is the separate
  `npm run sandbox:linux:pull` operation.
- Docker CLI bytes, daemon identity, OCI index, resolved platform image ID,
  checked-in seccomp bytes, and in-image Node path are hash-bound and verified
  before execution.
- Node runs directly as container PID 1 through an exact entrypoint override;
  the image's convenience shell wrapper is not executed.
- Target commands run with network disabled, a read-only root, read-only
  candidate or declared-file projection mounts, all capabilities dropped,
  no-new-privileges, no IPC, a cgroup task ceiling, and deny-by-default
  seccomp with clone admitted only for threads.
- Exact argv remains an array end-to-end. Target environment values never
  enter argv and the Docker client receives a constructed environment.
- Timed-out or output-killed clients invoke unique-container cleanup and remove
  any temporary declared-file projection.
- Kernel release advanced to `0.4.0-experimental`; prior release attestations
  are mechanically stale. The public probe remains honestly
  `FOUNDATION_ONLY` without external admission evidence.

## Adversarial evidence

- Immutable image, no-auto-pull, source-closed daemon, exact argv, environment
  separation, mount-delimiter rejection, entrypoint bypass, and seccomp
  structure are exercised mechanically.
- The Linux runtime probe demonstrates startup plus denied network bind,
  unmounted host-private read, write, and process creation. It verifies zero
  effective capabilities, `NoNewPrivs: 1`, and seccomp mode 2.
- The declared-file projection passes both directions: an undeclared base file
  is unreadable and a declared base file is readable.
- Cross-platform CI run
  [`33124475864`](https://github.com/Shedu-ai/shedu-promotion-kernel/actions/runs/33124475864)
  passed:
  - macOS: 232 tests, 232 pass, 0 fail;
  - Ubuntu: 232 tests, 231 pass, 0 fail, 1 intentional macOS-only weakened-SBPL
    demonstration skipped;
  - sample policy: verified on both;
  - public subject probe: `FOUNDATION_ONLY` on both.

## Orphan closure

- No control ID or exclusion was added. Linux executes the already registered
  network, read, write, process, toolchain, output, and runtime control paths.
- The runtime control-surface census remains 21 registered / 21 proven with
  all 14 production-observable controls observed.
- The policy mechanism census and nine activation pairs remain complete with
  no declared exclusion.

## Retained boundary

- Linux requires a local Docker Engine and a pre-materialized pinned image.
- Only Node target commands are admitted.
- `maxProcesses` remains exactly 1; multi-process target test runners fail
  closed rather than receiving a weaker sandbox.
- Unsupported operating systems and untrusted or absent isolation backends
  fail with `SANDBOX_UNAVAILABLE`.
