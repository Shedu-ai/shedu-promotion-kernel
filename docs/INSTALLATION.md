# Installation

The public experimental distribution is usable on macOS and Linux. It has no
runtime package dependencies, model provider, API key, database, or hosted
service.

## Requirements

- Node.js 22 or newer.
- Git at one of the distribution's fixed system paths.
- macOS with `sandbox-exec`, or Linux with Docker Engine at `/usr/bin/docker`
  or `/usr/local/bin/docker`.

Other platforms fail closed with `SANDBOX_UNAVAILABLE`. On Linux the kernel
uses an immutable OCI image and bounded process tree. On macOS strict target
commands run without child-process creation.

## Recommended: public experimental launcher

```sh
git clone https://github.com/Shedu-ai/shedu-promotion-kernel.git
cd shedu-promotion-kernel
git checkout v0.4.0-experimental.1
npm run experimental:doctor
```

`experimental:doctor` verifies the public Harness Bench signatures and file
digests, installs the exact certified kernel commit into an external cache,
checks its commit, tree, cleanliness, and removed remote, and asks that kernel
for its own admission state. Success prints machine-readable JSON containing:

```json
{
  "ok": true,
  "admission": {
    "implementationStatus": "EXPERIMENTAL",
    "promotionEntrypointAvailable": true,
    "authorityId": "bench-kernel-attestor-2026-08"
  }
}
```

No private key is downloaded or required. The distribution contains only the
signed certification, detached attestation, pinned public key, and immutable
kernel identity. The launcher owns those values and rejects attempts to
replace them on the command line.

The usable command surface is:

```sh
npm run experimental -- setup
npm run experimental -- doctor
npm run experimental -- status
npm run experimental -- probe
npm run experimental -- compile --contract /absolute/work-contract.json --repo /absolute/target-repository
npm run experimental -- evaluate --contract /absolute/work-contract.json --repo /absolute/target-repository --out /absolute/output-directory
npm run experimental -- verify-receipt --receipt /absolute/receipt.json --plan /absolute/plan.json --evidence /absolute/evidence
npm run experimental -- inspect-evidence --out /absolute/output-directory --artifact <artifact-id>
```

The equivalent installed binary is `shedu-kernel-experimental`.

### Linux: install the immutable sandbox image

Run this once before target-command evaluation:

```sh
npm run experimental -- sandbox:linux:pull
```

It installs only:

```text
docker.io/library/node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
```

Evaluation uses `--pull never`. A missing image, substituted Docker binary,
remote daemon override, non-Linux daemon, isolation-probe failure, or identity
drift produces `SANDBOX_UNAVAILABLE` instead of weakening isolation.

## Install inside a target repository

```sh
npm install --save-dev "git+https://github.com/Shedu-ai/shedu-promotion-kernel.git#v0.4.0-experimental.1"
npx shedu-kernel-experimental doctor
```

Commit the exact tag and resolved lockfile integrity. The launcher independently
pins the certified 40-character kernel commit and tree; it never evaluates by
following `main` or another moving branch.

This installation form is a development convenience. For an authoritative
evaluation, run the launcher from the separate pinned checkout above and keep
that checkout outside the coding agent's and target candidate's writable
scope. A target must not be allowed to rewrite the tool that evaluates it.

## Add the sample target policy

From a source checkout:

```sh
cp -R examples/node-source-hygiene/.shedu /absolute/path/to/target-repository/
```

From an installed target dependency:

```sh
cp -R node_modules/@shedu/promotion-kernel/examples/node-source-hygiene/.shedu ./
```

Commit `.shedu/policy/` and `.shedu/validators/` before creating the candidate.
The candidate cannot rewrite those base-authoritative bytes for its own run.
See the [sample policy README](../examples/node-source-hygiene/README.md) for
the exact digest workflow.

## Compile and evaluate a target

A `work-contract@1` binds the target's full base and candidate commit ids,
authorized path scope, exact validation-command argument arrays, resource
ceilings, and the raw-byte SHA-256 digest of its base-owned policy profile.

```sh
npx shedu-kernel-experimental compile \
  --contract /absolute/path/to/work-contract.json \
  --repo /absolute/path/to/target-repository

npx shedu-kernel-experimental evaluate \
  --contract /absolute/path/to/work-contract.json \
  --repo /absolute/path/to/target-repository \
  --out /absolute/path/to/kernel-output
```

Evaluation emits a canonical `promotion-receipt@1` with a disposition of
`PROMOTABLE` or `BLOCKED` and atomically publishes the complete plan, receipt,
and content-addressed evidence under the output directory.

Never put a private key, provider credential, bearer token, or secret in a
policy pack, work contract, command argument, profile, or repository file.
Those inputs are recorded as public evidence. Optional receipt signing accepts
a local PEM file through `--sign-key`; that key remains outside the repository.

## Independent source verification

The admitted distribution deliberately executes the certified detached commit.
To inspect that source without admission:

```sh
git clone https://github.com/Shedu-ai/shedu-promotion-kernel.git
cd shedu-promotion-kernel
git checkout --detach 69253a78f095572b727c2336644b03fbff5476c8
npm test
npm run verify:sample-policy
npm run subject:probe
```

The final probe reports `FOUNDATION_ONLY` because no external evidence was
supplied to that direct invocation. This is the expected self-authorization
boundary; `npm run experimental:doctor` is the separately admitted public path.

## Upgrade

An upgrade is a new authority event: select a new full kernel commit, repeat
the independent test and conformance run, issue a new external attestation,
and publish a new activation manifest. The launcher never reuses an old
attestation for changed kernel source.
