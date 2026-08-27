# Closeout — portable-conformance-projection-v2

**Status:** IMPLEMENTED · 2026-08-27

## Mechanical result

- Kernel release advanced to `0.3.1-experimental`, invalidating every prior
  release-bound attestation.
- Admission and schema registration accept only `conformance-status@2`.
- Complete receipts retain the original host-bound `evaluationDigest`, exact
  executable digest, command reports, evidence references, and timestamps.
- The committed status projects a separately named
  `resultProjectionDigest`, derived from plan, candidate, disposition, receipt
  reasons, and ordered check identity/effect/outcome/reason data.
- Evidence references and timestamps are excluded from only that portable
  status projection; they remain mandatory and offline-verified in the full
  receipt/evidence bundle.
- The generated v2 status is committed byte-for-byte and its schema is closed
  with `additionalProperties: false`.

## Hostile evidence

- Timestamp and evidence-reference mutation leaves the portable projection
  unchanged while changing the full evaluation digest.
- Plan, candidate, disposition, receipt reason, check identity, effect,
  outcome, and check-reason mutations each change the portable projection.
- A legacy `conformance-status@1` cannot admit the v2 release.
- The external-admission fixture now derives its signed release from the same
  frozen checkout as every other signed input.
- Complete committed suite: 221 tests, 221 pass, 0 fail.
- Kernel mechanism census and control-surface census pass with no exclusion
  added and no enforcement check weakened.

## Downstream consumption

Harness Bench must pin the exact resulting kernel commit, accept only the v2
status for this release, issue new external evidence with its protected Ed25519
authority, and reproduce that evidence on the protected macOS runner. Old
evidence remains invalid by release and commit identity.
