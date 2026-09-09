# Mechanical requirement coverage

The kernel remains independent of every model provider. It does not reason
about product intent. A trusted policy author supplies executable assertions;
the kernel binds their authority, requires execution and reduces the results.

Policies opt into a complete requirement-to-check map by adding inputs such
as `acceptance-criterion.ac-1` to their checks. Once any such input is present,
every `acceptanceCriterionId` in the work contract must be covered. Unknown
criteria, advisory checks, non-reducer consumers and checks outside candidate
validation fail compilation. Target commands must declare a nonempty trusted
base input manifest. Builtin checks can cover mechanical scope requirements.
The map is part of the compiled plan and its digest. Existing policies without
these tags retain their existing behavior and make no new coverage claim.

This proves that every declared criterion is wired to executable validation.
It cannot prove that a test actually represents the criterion, or that a
finite test set covers every valid input. Policy quality and independent
oracle review remain essential.

## Reusable behavioral fixtures

Vendor `policy-tools/behavioral-check.mjs` and a `behavioral-cases@1` JSON
document into the target's trusted base, list both in `inputManifest`, and use:

```json
{
  "kind": "TARGET_COMMAND",
  "argv": ["node", "policy/behavioral-check.mjs", "policy/cases.json"],
  "inputManifest": ["policy/behavioral-check.mjs", "policy/cases.json"],
  "executionRequirement": {"class": "SINGLE_PROCESS", "maxTasks": 64}
}
```

Set the check's `outputSchemaId` to `behavioral-report@1`, its effect to
`BLOCKING`, and `inputs` to the criteria that these scenarios validate.
The example execution requirement applies to policy-pack@2; omit that field
for policy-pack@1. Normal kernel sandbox and resource limits remain enforced.

```json
{
  "schemaVersion": "behavioral-cases@1",
  "criterionIds": ["ac-1"],
  "cases": [{
    "id": "failure-does-not-spend-stock",
    "criterionIds": ["ac-1"],
    "module": "src/reserve.mjs",
    "export": "reserve",
    "args": [{"sku-a": 3}, [{"sku": "sku-a", "quantity": 5}]],
    "expect": {"throws": true},
    "preserveArgs": [0, 1]
  }]
}
```

Each scenario must declare a return value, exact own-property values using
`expect.ownValues` (independent of enumerability), or an expected exception. Optional
`preserveArgs` checks own-property descriptors and values, including
nonenumerable values. `afterArgs` checks explicit postconditions;
`returnArgIndex` and `returnElementsFromArg` check object identity. Use
`freshReturn: true` to reject any returned object aliasing an input object;
`expect.throws` may name `RangeError`, `TypeError`, `SyntaxError` or `Error`.
Fixture values may
encode exact BigInts as `{"$shedu":"bigint","value":"9007199254740993"}`
or undefined as `{"$shedu":"undefined"}`. Nonenumerable data properties use
`{"$shedu":"object","properties":[{"name":"x","value":1,"enumerable":false}]}`.
Cycles, accessors and symbols are outside this initial fixture format.

The runner reports every scenario and rejects missing scenarios or unknown
criteria. The kernel also requires a complete structured PASS report from
checks declaring this output schema: early successful process exit, missing
output, duplicate scenario IDs and omitted criteria do not pass. Candidate
code and assertions execute in the same JavaScript process; this is not a
proof against code that deliberately subverts the test runtime or forges a
report. Use separate trusted validators or stronger isolation for such claims.

## Consuming trusted receipts

Cross-boundary consumers can make the required verification level explicit:

```sh
node src/cli.mjs verify-receipt --receipt receipt.json --plan plan.json \
  --evidence artifacts/evidence --public-key TRUSTED_PUBLIC_KEY_HEX \
  --require trusted-evidence
```

The key must come from an independent trusted configuration, not be adopted
from the supplied receipt. The plan must identify the intended candidate.
This mode rejects omitted keys, unsigned receipts, unexpected signers, absent
evidence, mutation and replay. Library callers use
`verificationPolicy: "TRUSTED_EVIDENCE"`. The result's `verificationLevel`
distinguishes `RECEIPT_INTEGRITY`, `TRUSTED_RECEIPT`, `EVIDENCE_INTEGRITY`,
`TRUSTED_EVIDENCE` and `NONE`. Existing inspection calls remain available.
A successfully verified BLOCKED receipt is still BLOCKED; consumers must
check both verification success and disposition before allowing promotion.

Signatures and evidence requirements authenticate the bounded execution
claim. They do not improve the semantic coverage of its assertions.
