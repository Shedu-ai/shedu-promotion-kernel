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
- Target-command evaluation currently requires macOS and an enforceable `sandbox-exec`
  backend. Other platforms fail closed with `SANDBOX_UNAVAILABLE`.
- Target commands may use only the kernel's exact Node interpreter, run without a shell,
  receive no network access, and cannot fork (`maxProcesses` is exactly `1`).
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

A real `work-contract@1` must contain the target's full base and candidate object IDs,
exact path scope, exact validation-command argument arrays, and the raw-byte SHA-256
digest of `.shedu/policy/profile.json`. It must point to policy authority already committed
at the declared base.

```sh
node /absolute/path/to/shedu-promotion-kernel/src/cli.mjs compile \
  --contract /absolute/path/to/work-contract.json \
  --repo /absolute/path/to/target-repository
```

Compilation emits one canonical `compiled-policy-plan@1` document on stdout or one
machine-readable blocking error on stderr. The sample verifier constructs a disposable
real Git repository and exercises this exact CLI path; use it as the executable reference
instead of copying placeholder commit IDs into production.

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
