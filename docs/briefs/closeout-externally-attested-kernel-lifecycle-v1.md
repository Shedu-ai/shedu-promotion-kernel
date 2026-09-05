# Closeout — externally-attested-kernel-lifecycle-v1

**Implementation status:** COMPLETE

**Activation status:** PENDING EXTERNAL RECERTIFICATION AND PILOT ISSUANCE

## Mechanical result

- `FOUNDATION_ONLY`, `EXPERIMENTAL`, `PILOT_ELIGIBLE`, and `CERTIFIED` are a
  closed ordered lifecycle derived by the branded admission reducer.
- `PILOT_ELIGIBLE` requires a canonical Ed25519 lifecycle statement, the
  exact external conformance predecessor, a complete deterministic
  qualification receipt, its frozen policy, the unsigned activation
  specification, and the exact kernel commit/tree/control identities.
- Pilot evidence cannot derive `CERTIFIED`; operational certification remains
  closed until its post-pilot compiler is implemented.
- Invalid or expired higher evidence mechanically reduces to a still-valid
  `EXPERIMENTAL` state. Invalid conformance or source identity still reduces
  to `FOUNDATION_ONLY`.
- The v2 activation launcher owns and transports every lifecycle authority
  file through the supervised worker's second admission gate.
- `kernel-agent-status@2` exposes the derived state, identity, evidence
  validity, closed reason codes, and closed next-action lanes.
- The lifecycle admission control is present in source discovery, the control
  registry, executable runtime proof, conformance census, and status digest.

## Evidence

- Full kernel suite: 276 tests, 276 passed, 0 failed.
- Conformance status: byte-identical after deterministic regeneration for
  `@shedu/promotion-kernel@0.6.0-experimental`.
- Control census: 22 registered, 22 proven, 14 production-required, 14
  production-observed, zero findings.
- Hostile coverage includes forged branded states, wrong key/authority,
  mutation, expiry, identity substitution, exact-argv drift, missing results,
  evidence relabeling, and v2 activation-member mutation.

## Honest boundary

This closeout completes the implementation slice, not the authority event.
Direct source remains `FOUNDATION_ONLY`; the last immutable public launcher
remains `EXPERIMENTAL`. A new exact kernel commit must now be independently
recertified by Harness Bench, qualified without providers, signed by the
protected external authority, and published as a v2 pilot activation before
the public product can derive `PILOT_ELIGIBLE`.
