# Brief — artifact-root-bundle-binding-v1

**Status:** IMPLEMENTED · zero-provider reliability repair · 2026-08-30

## Objective

Make supervised publication consume the `artifactRoot` authorized by the exact
work contract instead of assuming `artifacts/`, so every schema-valid root that
the evaluator supports can complete the same atomic promotion path.

## Current defect and prior art

`evaluateCandidate` already validates, normalizes, uses, and records the
contract-declared `artifactRoot`; `agent-projection.mjs` also resolves evidence
from the receipt's bound value. `worker-evaluate.mjs` and `supervisor.mjs`
retained one hardcoded `artifacts/evidence/index.json` bundle member. The
existing supervised fixtures used that default, so isolated tests passed while
the shipped `.shedu/artifacts/` sample failed only during final publication.

## Mechanical change

1. The worker derives the evidence-index member from its schema-validated
   receipt.
2. The supervisor independently validates both the receipt and the exact work
   contract, requires equal `artifactRoot`, requires the receipt disposition to
   equal the worker summary, and derives the required bundle member from that
   contract-bound value.
3. The existing digest and atomic-publication checks operate over the derived
   member without fallback or path probing.
4. A supervised hostile test uses `.shedu/artifacts/`, proves the exact member
   is published and manifested, and would reproduce the prior infrastructure
   failure.

## Orphan closure

The contract field is registered and schema-validated, consumed by evaluation,
emitted in the receipt, consumed independently by worker and supervisor bundle
construction, verified in the published evidence path, and exercised with a
non-default value. No compatibility alias, prose waiver, retry, or second
artifact-root authority is introduced.

## Acceptance

- focused supervisor and agent-projection tests pass;
- full macOS and pinned-Linux OCI suites pass;
- the real externally admitted sample evaluation publishes a verified receipt
  under `.shedu/artifacts/`; and
- a new external attestation binds the repaired exact kernel commit before the
  activation bundle is usable again.
