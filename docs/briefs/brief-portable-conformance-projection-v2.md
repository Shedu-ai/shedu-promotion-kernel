# Brief — portable-conformance-projection-v2

**Owner:** public `Shedu-ai/shedu-promotion-kernel`

**Consumer:** private `Shedu-ai/shedu-harness-bench`

**Status:** IMPLEMENTING · zero-provider · 2026-08-27

## Objective

Make the committed conformance status reproducible across supported macOS
machines without weakening the exact executable identity carried by command
reports, evidence objects, receipts, or evaluation digests.

## Defect and authority boundary

`conformance-status@1` projected each receipt's `evaluationDigest`. That digest
correctly binds evidence references whose command reports include the exact Node
binary digest. Two machines running the same pinned Node release can therefore
produce identical decisions and independently verified receipts but different
evaluation digests when their Node binaries differ by architecture or
distribution. Requiring the public status file to reproduce byte-for-byte while
also embedding that host-bound value is contradictory.

The repair must preserve both authorities:

- host-bound execution identity remains unchanged in command reports, evidence,
  receipts, and `evaluationDigest`; and
- the committed conformance status becomes a portable semantic projection that
  can be reproduced by an external attestor on a different supported host.

## Mechanical contract

1. Replace `conformance-status@1` with `conformance-status@2`; no field is
   silently redefined under the old schema version.
2. Replace each run summary's `evaluationDigest` with
   `resultProjectionDigest`.
3. Derive `resultProjectionDigest` only from the verified receipt's plan,
   candidate, disposition, receipt reason codes, and ordered check identities,
   effects, outcomes, and reason codes. Evidence references and timestamps are
   deliberately excluded because they bind host execution rather than semantic
   disposition.
4. Continue retaining and offline-verifying the complete receipt, plan, and
   evidence store for every conformance run. The portable projection is not a
   substitute for the full evidence.
5. Admission accepts only `conformance-status@2` for this release and still
   requires an externally signed attestation over its exact bytes, mechanism
   inventory, control surface, release, and frozen commit.
6. Bump the kernel release so every prior attestation becomes stale
   mechanically.

## Hostile acceptance tests

- Changing timestamps or evidence references changes the full evaluation
  digest but cannot change `resultProjectionDigest`.
- Changing a check outcome, reason code, identity, candidate, plan, or final
  disposition changes `resultProjectionDigest`.
- A v1 status cannot admit the new release.
- The generated v2 status remains byte-identical across two independent local
  conformance runs and the protected Harness Bench reproduction.
- The complete kernel suite, external probe, registry/census checks, and Bench
  attestation verification remain green.

## Wiring and orphan closure

The slice is incomplete unless the v2 schema is registered and consumed by
admission, the projection producer is consumed by conformance, the committed
status is regenerated, hostile tests exercise both exclusion and sensitivity,
the release bump invalidates old evidence, and Harness Bench pins and certifies
the resulting immutable commit.
