# Installation

Shedu Promotion Kernel is currently distributed from its public Git repository. It is
not yet published to the npm registry. Pin a full 40-character commit so installation
does not silently follow a moving branch.

## Requirements and honest operating boundary

- Node.js 22 or newer.
- Git installed at one of the kernel's closed authority paths.
- No provider account, model API key, database, or network service is used by the kernel.
- Schema validation, policy compilation, receipt verification, the subject probe, and
  the test suite are provider-free.
- Target-command evaluation supports either macOS with enforceable `sandbox-exec`, or
  Linux with Docker Engine and the kernel's immutable OCI image installed by digest.
  Other platforms fail closed with `SANDBOX_UNAVAILABLE`.
- Target commands may use only the kernel's exact Node interpreter, run without a shell,
  and receive no network access. Existing `@1` contracts and the `STRICT` preset deny
  process creation. Versioned `@2` authorities may request `STANDARD_TEST`, whose exact
  process-and-thread task ceiling is enforced only by the pinned Linux OCI backend.
- The public checkout intentionally reports `FOUNDATION_ONLY`. `evaluate` remains blocked
  until a separate trusted attestor supplies a signed attestation, its pinned Ed25519
  public key, and the exact attested kernel commit. Installation alone cannot elevate it.

## Option A: pinned source checkout

```sh
git clone https://github.com/Shedu-ai/shedu-promotion-kernel.git
cd shedu-promotion-kernel
git checkout --detach <FULL_40_CHARACTER_COMMIT>
node --version
npm test
npm run verify:sample-policy
npm run subject:probe
```

No dependency-install step is required: the package has zero runtime and development
dependencies. A valid public installation still reports `FOUNDATION_ONLY`; that is the
expected fail-closed result without external admission material.

### Linux: install the pinned sandbox image

On Linux, Docker must be available at `/usr/bin/docker` or
`/usr/local/bin/docker` and connected to the local Linux daemon socket. Install
the one admitted image before running target-command tests or evaluation:

```sh
npm run sandbox:linux:pull
```

The installer resolves this exact immutable authority and prints its verified
local image identity:

```text
docker.io/library/node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
```

Evaluation always uses `--pull never`. A missing image, changed runtime, remote
daemon override, non-Linux daemon, failed isolation probe, or image identity
drift produces `SANDBOX_UNAVAILABLE`; evaluation never downloads or substitutes
an image on its own.

Confirm the live execution route without invoking a provider or running target code:

```sh
node src/cli.mjs execution-preflight
```

The machine response exposes two named presets. `STRICT` is available on a conforming
macOS or Linux worker. `STANDARD_TEST` is available only after the Linux worker proves
the bounded child-process path and a planted `pids.max` event. Agents may use the result
to route an immutable run; they cannot pass a process count or backend override to
`evaluate`.

## Option B: pinned target-repository dependency

From the repository to be governed:

```sh
npm install --save-dev "git+https://github.com/Shedu-ai/shedu-promotion-kernel.git#<FULL_40_CHARACTER_COMMIT>"
./node_modules/.bin/shedu-promotion-kernel --subject-probe
```

Commit both the full commit in `package.json` and the resolved integrity in the target's
lockfile. Do not depend on `main`, a branch name, or an unverified moving tag.

## Install the sample target policy

From a source checkout:

```sh
cp -R examples/node-source-hygiene/.shedu /absolute/path/to/target-repository/
```

From a target repository using Option B:

```sh
cp -R node_modules/@shedu/promotion-kernel/examples/node-source-hygiene/.shedu ./
```

Commit `.shedu/policy/` and `.shedu/validators/` to the target's trusted base revision.
The candidate revision cannot rewrite those base-authoritative bytes for its own run.
See the [sample policy README](../examples/node-source-hygiene/README.md) for the pack,
profile, validator, exact digest workflow, and mechanical verification.

## Compile a target contract

A real `work-contract@1` or `work-contract@2` must contain the target's full base and candidate object IDs,
exact path scope, exact validation-command argument arrays, and the raw-byte SHA-256
digest of `.shedu/policy/profile.json`. It must point to policy authority already committed
at the declared base.

```sh
node /absolute/path/to/shedu-promotion-kernel/src/cli.mjs compile \
  --contract /absolute/path/to/work-contract.json \
  --repo /absolute/path/to/target-repository
```

Compilation emits the corresponding canonical `compiled-policy-plan@1` or
`compiled-policy-plan@2` document on stdout or one
machine-readable blocking error on stderr. The sample verifier constructs a disposable
real Git repository and exercises this exact CLI path; use it as the executable reference
instead of copying placeholder commit IDs into production.

## Bounded Node test suites

Use `@2` only when a base-owned target validator or validation command genuinely needs
child processes. The three independent authorities must all admit the same requirement:

```json
{"class":"BOUNDED_PROCESS_TREE","maxTasks":128}
```

That closed value is the machine expansion of the shipped `STANDARD_TEST` preset. It is
declared as `validator.executionRequirement` in `policy-pack@2`, as
`resourceCeilings.executionCeiling` in `work-contract@2`, and as `executionPolicy` in
`policy-profile@2`. Compilation takes the exact pack requirement and rejects it if either
ceiling is lower. Neither a prompt, retry, environment variable, CLI flag, nor candidate
edit can raise it. The compiled plan additionally binds `bounded-process-tree@1` and the
portable digest of the pinned image, bounded seccomp policy, and trusted supervisor.

`maxTasks` is intentionally not called `maxProcesses`: Linux cgroups count processes and
threads together. If Linux OCI is unavailable, the same contract returns
`EXECUTION_BACKEND_REQUIRED` or `SANDBOX_UNAVAILABLE`; it never falls back to a weaker
native mode.

## Admitted evaluation

An external attestor must independently certify the exact installed kernel commit before
the promotion entrypoint becomes available. Once that authority supplies all three values,
the invocation shape is:

```sh
node src/cli.mjs evaluate \
  --contract /absolute/path/to/work-contract.json \
  --repo /absolute/path/to/target-repository \
  --out /absolute/path/to/output-directory \
  --attestation /absolute/path/to/detached-attestation.json \
  --pinned-key <64_LOWERCASE_HEX_ED25519_PUBLIC_KEY> \
  --expected-commit <ATTESTED_40_CHARACTER_KERNEL_COMMIT>
```

Do not put a private key, provider credential, bearer token, or other secret in a policy
pack, work contract, command argument, profile, or repository file. These materials are
recorded as public evidence. Receipt signing, when used, receives a local PEM path through
`--sign-key`; that key file must remain outside the repository.

## Upgrade

Treat an upgrade as a new authority event:

1. Select and record a new full kernel commit.
2. Run `npm test` and `npm run verify:sample-policy` at that commit.
3. Obtain a new external attestation bound to that exact commit before evaluation.
4. Recompute every changed raw-byte policy/profile digest.
5. Compile a new plan; never reuse a receipt or plan from the prior kernel identity.
