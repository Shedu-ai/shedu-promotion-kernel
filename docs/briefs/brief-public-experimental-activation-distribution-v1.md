# Brief — public-experimental-activation-distribution-v1

**Owner:** public `Shedu-ai/shedu-promotion-kernel`

**Priority:** CRITICAL

**Status:** IMPLEMENTED LOCALLY · zero-provider · 256/256 full-suite target ·
release publication pending · closeout:
[`closeout-public-experimental-activation-distribution-v1.md`](closeout-public-experimental-activation-distribution-v1.md)
· 2026-09-01

## Objective

Make the independently certified Promotion Kernel usable by a public operator
without weakening the rule that an unauthenticated source checkout cannot
authorize itself.

The distribution must turn the existing Harness Bench certification into a
one-command experimental entrypoint. It must not copy a private signing key,
certify a newer source tree with older evidence, convert `FOUNDATION_ONLY` into
a mutable flag, or require a user or coding agent to reconstruct admission
arguments manually.

## Frozen authorities

- Kernel repository: `https://github.com/Shedu-ai/shedu-promotion-kernel.git`
- Certified commit: `69253a78f095572b727c2336644b03fbff5476c8`
- Certified tree: `282e60da4e98d1659767b9d4a1f89097bec275d8`
- Kernel release: `@shedu/promotion-kernel@0.4.0-experimental`
- Attesting authority: `bench-kernel-attestor-2026-08`
- Ed25519 public key:
  `146566b79911ee63307b287c0df8ad726da12c94fec15ae104fd563ae0857555`

The corresponding private key remains external to this repository. It is not
an input to installation, status, compilation, evaluation, or receipt
verification.

## Mechanical contract

1. Publish the signed detached attestation, signed Bench certification, public
   authority declaration, and a closed activation manifest. Bind every byte
   artifact by SHA-256.
2. Provide a zero-dependency Node launcher with a closed command surface. The
   launcher resolves Git only from fixed absolute paths and invokes every
   process as an exact argv array without a shell.
3. Install only the manifest's full commit into a versioned cache through a
   private temporary directory and atomic rename. Verify exact `HEAD`, tree,
   clean state, and evidence bytes before use; then remove the source remote.
4. Inject the attestation path, pinned public key, and expected commit for
   `status`, `probe`, and `evaluate`. Reject caller attempts to replace any of
   those three admission values.
5. Preserve the certified kernel's own branded admission check. The launcher
   may transport admission material but cannot create, override, or imitate an
   admitted outcome.
6. Expose `setup`, `doctor`, `status`, `probe`, `compile`, `evaluate`,
   `verify-receipt`, `inspect-evidence`, `conformance`, and
   `sandbox:linux:pull`. Unknown commands fail closed.
7. Keep the direct source command honest: `node src/cli.mjs status` continues
   to report `FOUNDATION_ONLY`. The public experimental launcher must report
   `EXPERIMENTAL` only after the certified kernel independently verifies the
   supplied evidence.
8. Publish a versioned GitHub release whose tag identifies the distribution
   commit and whose notes identify the distinct certified kernel commit.

## Hostile acceptance

- A changed attestation, certification, public key, commit, tree, or declared
  digest is rejected before the kernel command runs.
- A dirty, incomplete, wrong-commit, wrong-tree, or remote-bearing cached
  checkout is repaired from the fixed authority or rejected.
- `PATH`, a Git-related environment variable, a shell metacharacter, or a
  caller-provided admission flag cannot substitute executable or admission
  authority.
- A valid distribution produces an `EXPERIMENTAL` status and an available
  promotion entrypoint; the same source without external material remains
  `FOUNDATION_ONLY`.
- A real conforming target produces a mechanically verified `PROMOTABLE`
  receipt and a planted policy failure produces `BLOCKED`.
- Public installation and Linux OCI instructions use the launcher and do not
  ask the operator to copy a public key, commit id, or attestation path.

## Wiring and orphan closure

The slice is incomplete unless the manifest, authority, attestation,
certification, launcher, package entrypoint, installation guide, README,
release assets, and tests all refer to the same distribution id and frozen
kernel identity. A distribution census test must derive those connections and
fail on an unreferenced artifact, undeclared launcher command, missing package
entrypoint, or identity mismatch.
