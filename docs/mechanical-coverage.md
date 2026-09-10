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

Put a `behavioral-cases@1` JSON document in the trusted Git base and select
the kernel-owned validator:

```json
{
  "kind": "BUILTIN",
  "builtinId": "behavioral-cases-verify@1",
  "casesPath": "policy/cases.json"
}
```

Set the check's `outputSchemaId` to `behavioral-report@2`, its effect to
`BLOCKING`, its phase to `CANDIDATE_VALIDATION`, its consumer to
`DISPOSITION_REDUCER`, and `inputs` to the criteria these scenarios validate.
This works with all three work-contract versions. The compiler derives
single-process execution within the contract/profile ceilings.

Legacy `behavioral-report@1` checks now fail compilation. Migrate their cases
unchanged to this builtin; a target command's self-reported PASS is not
admissible behavioral authority. The optional `policy-tools/behavioral-check.mjs`
CLI invokes the isolated implementation for local inspection. Do not vendor
that wrapper into a target command or use its stdout to authorize promotion.

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

The kernel parent reads cases from the pinned base commit. Only invocation
inputs cross stdin into a separate, OS-sandboxed Node worker. Candidate
ECMAScript runs inside vendored QuickJS WebAssembly, with no host functions,
filesystem, network, process, inspector or standard-output capability exposed.
A private observer captures argument/return values and identity before and
after execution. Expected answers, comparisons and verdict generation remain
in the trusted kernel parent. Missing, malformed, duplicate or incomplete
observations fail closed. Signed evidence includes cases, inputs, observations,
command reports and the parent-generated verdict. Validator identity binds
cases, implementation files, runtime bundle and toolchain bytes.

The bounded fixture domain is ECMAScript `.mjs` with contained relative imports,
plain data objects/arrays, exact BigInts and settled promises. Each scenario
gets a fresh VM. Shared intrinsics retain ordinary writable semantics. The
observer captures its operations before candidate evaluation, uses private
null-prototype buffers and bypasses candidate iterator/serialization hooks;
proxies, accessors, symbols,
non-data prototypes and host APIs are unsupported. The engine has a 64 MiB
memory limit, 1 MiB stack limit and the command deadline; modules and observation
graphs have byte/size limits. Ordinary Node CI commands keep their existing
runtime. Validate compatibility before migrating other workloads: passing in
QuickJS does not prove all Node runtime behavior matches. Engine vulnerabilities
and hardware side channels are not ruled out by this design or its tests.

`vendor/quickjs/provenance.json`, licenses and an exact npm build lock record
QuickJS 0.32.0 and esbuild 0.28.2. Run
`node scripts/build-behavioral-runtime.mjs` to check reproducibility. There are
no runtime package downloads. This is vendored third-party code, not a claim
that the project has no dependencies.

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
