import assert from "node:assert/strict";
import test from "node:test";
import { validateDocument, validateValue } from "../src/contracts.mjs";
import { REASON_CODES, isReasonCode } from "../src/reason-codes.mjs";
import {
  COMMIT_A,
  ZERO_DIGEST,
  makeCheck,
  makeContract,
  makePack,
  makeProfile,
  pinPacks,
  profileEntries
} from "./fixtures.mjs";

const firstReason = (result) => {
  assert.equal(result.ok, false);
  return result.errors[0].reasonCode;
};

test("every emitted reason code is in the closed set", () => {
  assert.ok(REASON_CODES.length > 30);
  assert.ok(isReasonCode("SCHEMA_VIOLATION"));
  assert.ok(!isReasonCode("MADE_UP_CODE"));
});

test("a valid work contract passes", () => {
  const result = validateValue("work-contract@1", makeContract());
  assert.equal(result.ok, true);
});

test("work contract rejects unknown keys, at every level", () => {
  assert.equal(firstReason(validateValue("work-contract@1", { ...makeContract(), extra: 1 })), "SCHEMA_VIOLATION");
  const contract = makeContract();
  contract.target = { ...contract.target, sneaky: true };
  assert.equal(firstReason(validateValue("work-contract@1", contract)), "SCHEMA_VIOLATION");
});

test("work contract rejects missing required keys", () => {
  const contract = makeContract();
  delete contract.scope;
  assert.equal(firstReason(validateValue("work-contract@1", contract)), "SCHEMA_VIOLATION");
});

test("work contract rejects command strings and empty argv positions", () => {
  const asString = makeContract({
    validationCommands: [{ commandId: "bad", phase: "CANDIDATE_VALIDATION", argv: "npm test" }]
  });
  assert.equal(firstReason(validateValue("work-contract@1", asString)), "SCHEMA_VIOLATION");
  const emptyPosition = makeContract({
    validationCommands: [{ commandId: "bad", phase: "CANDIDATE_VALIDATION", argv: ["node", ""] }]
  });
  assert.equal(firstReason(validateValue("work-contract@1", emptyPosition)), "SCHEMA_VIOLATION");
  const emptyArgv = makeContract({
    validationCommands: [{ commandId: "bad", phase: "CANDIDATE_VALIDATION", argv: [] }]
  });
  assert.equal(firstReason(validateValue("work-contract@1", emptyArgv)), "SCHEMA_VIOLATION");
});

test("work contract rejects moving refs as base identity", () => {
  for (const ref of ["main", "HEAD", "v1.2.3", COMMIT_A.slice(0, 12)]) {
    const contract = makeContract();
    contract.target = { ...contract.target, baseCommit: ref };
    assert.equal(firstReason(validateValue("work-contract@1", contract)), "SCHEMA_VIOLATION", ref);
  }
});

test("work contract rejects malformed and escaping paths", () => {
  const traversal = makeContract({ scope: { allowed: ["../outside"], readonly: [], forbidden: [] } });
  assert.equal(firstReason(validateValue("work-contract@1", traversal)), "PATH_NOT_CONTAINED");
  const gitDir = makeContract({ scope: { allowed: ["src/", ".git/hooks/"], readonly: [], forbidden: [] } });
  assert.equal(firstReason(validateValue("work-contract@1", gitDir)), "PATH_NOT_CONTAINED");
});

test("work contract rejects a path claimed by two scope sets", () => {
  const contract = makeContract({ scope: { allowed: ["src/"], readonly: ["src/"], forbidden: [] } });
  assert.equal(firstReason(validateValue("work-contract@1", contract)), "SCOPE_SET_CONFLICT");
});

test("work contract has no environment-value field; env values cannot be pinned", () => {
  const withEnvValues = makeContract({ environment: { API_KEY: "hunter2" } });
  assert.equal(firstReason(validateValue("work-contract@1", withEnvValues)), "SCHEMA_VIOLATION");
});

// argv is public non-secret configuration; these detectors are
// defense-in-depth against credential-named flags and credential-shaped
// values, not proof that arbitrary strings contain no secret.
test("credential-named flags and credential-shaped argv values are rejected", () => {
  const cases = [
    ["tool", "--token", "abc"],
    ["tool", "--api-key=abc"],
    ["tool", "--client_secret", "abc"],
    ["curl", "-H", "sk-live-abcdef1234567890"],
    ["deploy", "ghp_16charactertoken0000"],
    ["sign", "-----BEGIN RSA PRIVATE KEY-----"]
  ];
  for (const argv of cases) {
    const contract = makeContract({
      validationCommands: [{ commandId: "leaky", phase: "CANDIDATE_VALIDATION", argv }]
    });
    assert.equal(firstReason(validateValue("work-contract@1", contract)), "SECRET_BEARING_FIELD", JSON.stringify(argv));
  }
  // Non-credential flags stay legal, including ones containing embedded words.
  const benign = makeContract({
    validationCommands: [
      { commandId: "fine", phase: "CANDIDATE_VALIDATION", argv: ["git", "log", "--author=someone", "--no-monkey-business"] }
    ]
  });
  assert.equal(validateValue("work-contract@1", benign).ok, true);
});

test("pack argv and env allowlists reject credential names", () => {
  const leakyCommand = makePack({
    checks: [
      makeCheck({ checkId: "leaky-cmd", validator: { kind: "TARGET_COMMAND", argv: ["tool", "--password=hunter2"], inputManifest: [] } })
    ]
  });
  assert.equal(firstReason(validateValue("policy-pack@1", leakyCommand)), "SECRET_BEARING_FIELD");

  for (const name of ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "NPM_AUTH", "CLIENT_SECRET"]) {
    const leakyEnv = makePack({ checks: [makeCheck({ envAllowlist: [name] })] });
    assert.equal(firstReason(validateValue("policy-pack@1", leakyEnv)), "SECRET_BEARING_FIELD", name);
  }
  const reservedEnv = makePack({ checks: [makeCheck({ envAllowlist: ["SHEDU_INTERNAL_MAX_TASKS"] })] });
  assert.equal(firstReason(validateValue("policy-pack@1", reservedEnv)), "SCHEMA_VIOLATION");
  const benignEnv = makePack({ checks: [makeCheck({ envAllowlist: ["PATH", "NODE_ENV", "CI", "SSH_KEY_PATH"] })] });
  assert.equal(validateValue("policy-pack@1", benignEnv).ok, true);
});

test("duplicate JSON keys are rejected before schema validation", () => {
  const result = validateDocument("work-contract@1", '{"schemaVersion":"work-contract@1","schemaVersion":"work-contract@1"}');
  assert.equal(firstReason(result), "DUPLICATE_JSON_KEY");
});

test("a valid policy pack passes; hostile packs are rejected", () => {
  assert.equal(validateValue("policy-pack@1", makePack()).ok, true);

  const dupChecks = makePack({ checks: [makeCheck(), makeCheck()] });
  assert.equal(firstReason(validateValue("policy-pack@1", dupChecks)), "DUPLICATE_CHECK_ID");

  const undeclaredPhase = makePack({ checks: [makeCheck({ phase: "PROMOTION_FINALIZATION" })] });
  assert.equal(firstReason(validateValue("policy-pack@1", undeclaredPhase)), "PHASE_NOT_DECLARED");

  const blockingEvidenceOnly = makePack({ checks: [makeCheck({ resultConsumer: "EVIDENCE_ONLY" })] });
  assert.equal(firstReason(validateValue("policy-pack@1", blockingEvidenceOnly)), "EVIDENCE_ONLY_BLOCKING_CONFLICT");

  const selfDependency = makePack({ dependencies: [{ packId: "example-pack", version: "1.0.0", digest: ZERO_DIGEST }] });
  assert.equal(firstReason(validateValue("policy-pack@1", selfDependency)), "DEPENDENCY_CYCLE");

  const shellString = makePack({ checks: [makeCheck({ validator: { kind: "TARGET_COMMAND", argv: "npm test" } })] });
  assert.equal(firstReason(validateValue("policy-pack@1", shellString)), "SCHEMA_VIOLATION");

  const overrideRule = makePack({ overrides: [{ checkId: "example-check", effect: "ADVISORY" }] });
  assert.equal(firstReason(validateValue("policy-pack@1", overrideRule)), "SCHEMA_VIOLATION");
});

test("a valid profile passes; weakening has no representation", () => {
  const packs = pinPacks([makePack()]);
  assert.equal(validateValue("policy-profile@1", makeProfile(profileEntries(packs))).ok, true);

  const weaken = makeProfile(profileEntries(packs), { weaken: ["example-check"] });
  assert.equal(firstReason(validateValue("policy-profile@1", weaken)), "SCHEMA_VIOLATION");

  const dupPacks = makeProfile([...profileEntries(packs), ...profileEntries(packs)]);
  assert.equal(firstReason(validateValue("policy-profile@1", dupPacks)), "DUPLICATE_PACK_ID");
});

test("mechanism registry requires negative fixtures and unique ids", () => {
  const mechanism = {
    mechanismId: "example-check",
    validatorId: "scope-boundary-classify@1",
    owner: "kernel-team",
    producer: "compiler",
    runtimeConsumer: "disposition-reducer",
    inputSchemaId: "compiled-policy-plan@1",
    outputSchemaId: "check-result@1",
    activationPhase: "CANDIDATE_VALIDATION",
    effect: "BLOCKING",
    resultConsumer: "DISPOSITION_REDUCER",
    evidenceSink: "evidence-index",
    activationEvidence: null,
    negativeFixtures: [{ fixtureId: "planted-violation", description: "planted scope escape must fire" }],
    status: "INTEGRATED"
  };
  const registry = { schemaVersion: "mechanism-registry@1", mechanisms: [mechanism] };
  assert.equal(validateValue("mechanism-registry@1", registry).ok, true);

  const blockingEvidenceOnly = {
    schemaVersion: "mechanism-registry@1",
    mechanisms: [{ ...mechanism, resultConsumer: "EVIDENCE_ONLY" }]
  };
  assert.equal(firstReason(validateValue("mechanism-registry@1", blockingEvidenceOnly)), "EVIDENCE_ONLY_BLOCKING_CONFLICT");

  const noFixtures = {
    schemaVersion: "mechanism-registry@1",
    mechanisms: [{ ...mechanism, negativeFixtures: [] }]
  };
  assert.equal(firstReason(validateValue("mechanism-registry@1", noFixtures)), "SCHEMA_VIOLATION");

  const duplicated = { schemaVersion: "mechanism-registry@1", mechanisms: [mechanism, mechanism] };
  assert.equal(firstReason(validateValue("mechanism-registry@1", duplicated)), "DUPLICATE_ENTRY_ID");
});

test("capability index validates entries and generated surface", () => {
  const index = {
    schemaVersion: "capability-index@1",
    repositoryId: "example-repo",
    entries: [
      {
        capabilityId: "write-set-binding@1",
        owner: "kernel-team",
        title: "Typed write-set binding",
        status: "ACTIVE",
        canonicalFiles: ["src/write-set.mjs"],
        doNotRebuild: true,
        allowedFollowUps: ["extend-path-rules"],
        receiptRefs: ["receipt-2026-08-01"]
      }
    ],
    generatedSurface: [{ path: "src/write-set.mjs", digest: ZERO_DIGEST }]
  };
  assert.equal(validateValue("capability-index@1", index).ok, true);

  const escaping = structuredClone(index);
  escaping.entries[0].canonicalFiles = ["../secrets"];
  assert.equal(firstReason(validateValue("capability-index@1", escaping)), "PATH_NOT_CONTAINED");
});

test("check result and receipt schemas accept valid documents and reject unknown keys", () => {
  const checkResult = {
    schemaVersion: "check-result@1",
    checkId: "example-check",
    packId: "example-pack",
    planDigest: ZERO_DIGEST,
    candidateId: COMMIT_A,
    effect: "BLOCKING",
    outcome: "FIRED",
    reasonCodes: ["SCOPE_SET_CONFLICT"],
    evidence: [{ artifactId: "changed-paths", digest: ZERO_DIGEST }],
    startedAt: "2026-08-26T00:00:00Z",
    completedAt: "2026-08-26T00:00:01Z"
  };
  assert.equal(validateValue("check-result@1", checkResult).ok, true);
  assert.equal(firstReason(validateValue("check-result@1", { ...checkResult, prose: "trust me" })), "SCHEMA_VIOLATION");

  const receipt = {
    schemaVersion: "promotion-receipt@1",
    kernelRelease: "@shedu/promotion-kernel@0.0.0-foundation",
    repositoryId: "example-repo",
    baseCommit: COMMIT_A,
    candidate: { kind: "COMMIT", id: COMMIT_A },
    artifactRoot: "artifacts/",
    digests: {
      workContract: ZERO_DIGEST,
      profile: ZERO_DIGEST,
      packs: [{ packId: "example-pack", version: "1.0.0", digest: ZERO_DIGEST }],
      validators: [],
      compiledPlan: ZERO_DIGEST,
      capabilityIndex: null,
      evidenceIndex: null
    },
    checkResults: [checkResult],
    changedFiles: [{ path: "src/index.mjs", changeKind: "MODIFIED", scopeClass: "ALLOWED" }],
    controlTrace: [{ controlId: "disposition-reduction", invocation: "evaluation", outcome: "BLOCKED", dispositionEffect: true, consumer: "promotion-receipt", planDigest: `sha256:${"a".repeat(64)}`, candidateId: "b".repeat(40), evidenceIndexDigest: `sha256:${"c".repeat(64)}` }],
    startedAt: "2026-08-26T00:00:00Z",
    completedAt: "2026-08-26T00:00:05Z",
    disposition: "BLOCKED",
    reasonCodes: ["SCOPE_SET_CONFLICT"],
    signing: null
  };
  assert.equal(validateValue("promotion-receipt@1", receipt).ok, true);
  assert.equal(firstReason(validateValue("promotion-receipt@1", { ...receipt, notes: "looks fine" })), "SCHEMA_VIOLATION");

  // reason-code@1 is closed: an uppercase-shaped but unknown code is
  // rejected in check results, in receipt reason codes, and in the results
  // nested inside a receipt.
  const madeUpResult = { ...checkResult, reasonCodes: ["MADE_UP_CODE"] };
  const resultCheck = validateValue("check-result@1", madeUpResult);
  assert.equal(resultCheck.ok, false);
  assert.match(resultCheck.errors[0].message, /closed reason-code@1 set/);

  const madeUpReceipt = { ...receipt, reasonCodes: ["MADE_UP_CODE"] };
  assert.equal(validateValue("promotion-receipt@1", madeUpReceipt).ok, false);

  const nestedMadeUp = { ...receipt, checkResults: [madeUpResult] };
  assert.equal(validateValue("promotion-receipt@1", nestedMadeUp).ok, false);
});
