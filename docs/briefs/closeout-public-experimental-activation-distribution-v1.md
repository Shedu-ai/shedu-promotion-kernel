# Closeout — public-experimental-activation-distribution-v1

**Status:** IMPLEMENTED LOCALLY · PUBLICATION PENDING

**Date:** 2026-09-01

## Frozen product identity

- Distribution: `experimental-v1`
- Release tag: `v0.4.0-experimental.1`
- Executed kernel commit:
  `69253a78f095572b727c2336644b03fbff5476c8`
- Executed kernel tree: `282e60da4e98d1659767b9d4a1f89097bec275d8`
- Attestor: `bench-kernel-attestor-2026-08`
- Public-key fingerprint:
  `146566b79911ee63307b287c0df8ad726da12c94fec15ae104fd563ae0857555`
- Activation manifest digest:
  `sha256:edea1dfe2095beab7b3039195ed5ca31f85f9d335517c61bf46318103140dd7c`

## Implemented

1. Published the detached attestation, Harness Bench certification, public
   authority record, and closed activation manifest without any private key.
2. Added `shedu-kernel-experimental`, a zero-dependency launcher that verifies
   all distribution artifacts, both Ed25519 signatures, and their complete
   kernel identity before use.
3. Added atomic exact-commit installation into an external cache with closed
   Git resolution, exact commit/tree verification, clean-state verification,
   and remote removal.
4. Added a clean child environment and mechanically owned admission injection.
   Caller admission flags and ambient admission variables cannot substitute the
   distribution authority.
5. Added setup, doctor, status, probe, compilation, evaluation, receipt,
   evidence, conformance, and Linux-image command routing through exact argv
   arrays without a shell.
6. Replaced the manual public-key/attestation installation protocol with a
   public experimental quickstart while preserving the honest unauthenticated
   `FOUNDATION_ONLY` source entrypoint.
7. Added a distribution wiring census over package entrypoint, command set,
   manifest, authority, signed evidence, and public documentation.

## Hostile verification

- Changed evidence bytes fail their manifest digest.
- Re-digested forged certification bytes fail Ed25519 verification.
- Symlinked activation artifacts fail before parsing.
- Dirty cached source is displaced and atomically repaired.
- Caller flags and poisoned ambient authority variables cannot replace the
  attestation, public key, expected commit, Git executable, or child runtime
  environment.
- A public-network clone of the exact certified commit reaches
  `EXPERIMENTAL` with promotion available.
- A real authorized target emitted `PROMOTABLE`.
- A planted read-only-scope change emitted `BLOCKED` with `CHECK_FIRED`.

## Verification record

- Certified kernel evidence: 247/247 tests, 10/10 conformance, byte-identical
  status reproduction, external `EXPERIMENTAL` probe.
- Distribution hostile and public-installation tests: 14/14.
- Full repository suite target after the added distribution tests: 256/256.
- Sample policy: positive fixture passed, planted fixture blocked, authority
  digests matched, and all mandatory checks compiled.
- npm dry-run package contains the executable launcher and all four activation
  artifacts; launcher mode is executable.

## Preserved boundary

The distribution is experimental, not a production certification. A direct
source checkout still cannot authorize itself. The private attestation key is
not present in the repository, package, cache, command line, or receipt. The
operator must keep the launcher checkout outside the target candidate's
writable scope.
