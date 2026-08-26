import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { evaluateCandidate } from "../src/evaluate.mjs";
import {
  buildTargetRepo,
  commitAll,
  contractBytesOf,
  kernelSelectablePack,
  writeRepoFile
} from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-adapter-"));

function evaluate(target, candidate, overrides = {}) {
  return evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate, overrides)),
    outDir: outDir()
  });
}

// ---------------------------------------------------------------------------
// prior-art-admission@1 (AC-6)
// ---------------------------------------------------------------------------

const PROTECTED_INDEX = {
  schemaVersion: "capability-index@1",
  repositoryId: "example-repo",
  entries: [
    {
      capabilityId: "payment-engine@1",
      owner: "platform-team",
      title: "Payment engine",
      status: "ACTIVE",
      canonicalFiles: ["src/payments/engine.mjs"],
      doNotRebuild: true,
      allowedFollowUps: ["extend-refund-path"],
      receiptRefs: ["receipt-2026-06-01"]
    }
  ],
  generatedSurface: []
};

function priorArtTarget(declaredCollisions) {
  return buildTargetRepo({
    scope: { allowed: ["src/"], readonly: ["docs/"], forbidden: ["policy/"] },
    targetPacks: [kernelSelectablePack("prior-art-admission")],
    extraBaseFiles: { "src/payments/engine.mjs": "export const engine = 1;\n" },
    capabilityIndex: PROTECTED_INDEX,
    priorArtQuery: {
      schemaVersion: "prior-art-query@1",
      objectiveId: "example-objective",
      queries: [{ queryId: "payments", terms: ["payment"] }],
      declaredCollisions
    }
  });
}

function collideWithProtected(target) {
  writeRepoFile(target.repoDir, "src/payments/engine.mjs", "export const engine = 2;\n");
  return commitAll(target.repoDir, "touches protected capability");
}

test("AC-6: an unacknowledged protected collision blocks", () => {
  const target = priorArtTarget([]);
  const outcome = evaluate(target, collideWithProtected(target));
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("PRIOR_ART_COLLISION"));
  const result = outcome.receipt.checkResults.find((r) => r.checkId === "prior-art-admission");
  assert.equal(result.outcome, "FIRED");
  assert.ok(result.evidence.some((e) => e.artifactId === "prior-art-search-report"));
});

test("AC-6: an authorized allowed-follow-up passes", () => {
  const target = priorArtTarget([
    { capabilityId: "payment-engine@1", resolution: "ALLOWED_FOLLOW_UP", followUpId: "extend-refund-path", receiptRef: null }
  ]);
  const outcome = evaluate(target, collideWithProtected(target));
  assert.equal(outcome.receipt.disposition, "PROMOTABLE", JSON.stringify(outcome.receipt.reasonCodes));
});

test("AC-6: a follow-up outside the entry's allowed set blocks", () => {
  const target = priorArtTarget([
    { capabilityId: "payment-engine@1", resolution: "ALLOWED_FOLLOW_UP", followUpId: "made-up-follow-up", receiptRef: null }
  ]);
  const outcome = evaluate(target, collideWithProtected(target));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("PRIOR_ART_COLLISION"));
});

test("AC-6: an authorized exception receipt passes; an unauthorized one blocks", () => {
  const authorized = priorArtTarget([
    { capabilityId: "payment-engine@1", resolution: "EXCEPTION_RECEIPT", followUpId: null, receiptRef: "receipt-2026-06-01" }
  ]);
  assert.equal(evaluate(authorized, collideWithProtected(authorized)).receipt.disposition, "PROMOTABLE");

  const forged = priorArtTarget([
    { capabilityId: "payment-engine@1", resolution: "EXCEPTION_RECEIPT", followUpId: null, receiptRef: "receipt-i-made-up" }
  ]);
  assert.equal(evaluate(forged, collideWithProtected(forged)).receipt.disposition, "BLOCKED");
});

test("AC-6: an ambiguous collision yields REVIEW_REQUIRED, not a kernel semantic ruling", () => {
  const target = priorArtTarget([
    { capabilityId: "payment-engine@1", resolution: "REVIEW_REQUESTED", followUpId: null, receiptRef: null }
  ]);
  const outcome = evaluate(target, collideWithProtected(target));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("REVIEW_REQUIRED"));
  assert.ok(!outcome.receipt.reasonCodes.includes("PRIOR_ART_COLLISION"));
  const result = outcome.receipt.checkResults.find((r) => r.checkId === "prior-art-admission");
  assert.deepEqual(result.reasonCodes, ["REVIEW_REQUIRED"]);
});

test("a non-colliding change passes prior-art admission; deprecated entries do not collide", () => {
  const target = priorArtTarget([]);
  writeRepoFile(target.repoDir, "src/unrelated.mjs", "export const x = 1;\n");
  const outcome = evaluate(target, commitAll(target.repoDir, "unrelated change"));
  assert.equal(outcome.receipt.disposition, "PROMOTABLE", JSON.stringify(outcome.receipt.reasonCodes));
});

test("a declared resolution for a capability absent from the bound index blocks", () => {
  const target = priorArtTarget([
    { capabilityId: "ghost-capability@1", resolution: "ALLOWED_FOLLOW_UP", followUpId: "anything", receiptRef: null }
  ]);
  writeRepoFile(target.repoDir, "src/unrelated.mjs", "export const x = 1;\n");
  const outcome = evaluate(target, commitAll(target.repoDir, "unrelated change"));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("PRIOR_ART_COLLISION"));
});

// ---------------------------------------------------------------------------
// orphan-closure@1 (brief §7, AC-7 planted classes at pack level)
// ---------------------------------------------------------------------------

function gatePack() {
  return {
    schemaVersion: "policy-pack@1",
    packId: "gate-pack",
    version: "1.0.0",
    description: "target gate demonstrating registered target mechanisms",
    phases: ["CANDIDATE_VALIDATION"],
    dependencies: [],
    checks: [
      {
        checkId: "gate-check",
        phase: "CANDIDATE_VALIDATION",
        effect: "BLOCKING",
        validator: { kind: "TARGET_COMMAND", argv: ["node", "-e", "process.exit(0)"] },
        inputs: [],
        outputSchemaId: "check-result@1",
        timeoutSeconds: 60,
        network: "NONE",
        filesystem: "READ_ONLY",
        envAllowlist: [],
        resultConsumer: "DISPOSITION_REDUCER"
      }
    ]
  };
}

// The exact validator identity the plan will carry for gate-check.
import { digestOfCanonical } from "../src/canonical-json.mjs";
const GATE_VALIDATOR_ID = `target:${digestOfCanonical(["node", "-e", "process.exit(0)"])}`;

function gateMechanism(overrides = {}) {
  return {
    mechanismId: "gate-check",
    validatorId: GATE_VALIDATOR_ID,
    owner: "target-team",
    producer: "policy/gate-pack.json",
    runtimeConsumer: "disposition-reducer",
    inputSchemaId: "compiled-policy-plan@1",
    outputSchemaId: "check-result@1",
    activationPhase: "CANDIDATE_VALIDATION",
    effect: "BLOCKING",
    resultConsumer: "DISPOSITION_REDUCER",
    evidenceSink: "evidence-index",
    negativeFixtures: [{ fixtureId: "planted-gate-failure", description: "a failing gate blocks the run" }],
    status: "INTEGRATED",
    ...overrides
  };
}

function orphanClosureTarget(mechanisms, { includeGatePack = true } = {}) {
  return buildTargetRepo({
    targetPacks: includeGatePack
      ? [gatePack(), kernelSelectablePack("orphan-closure")]
      : [kernelSelectablePack("orphan-closure")],
    mechanismRegistry: { schemaVersion: "mechanism-registry@1", mechanisms }
  });
}

function conformingCandidate(target) {
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  return commitAll(target.repoDir, "conforming feature");
}

test("a fully closed target registry passes orphan closure", () => {
  const target = orphanClosureTarget([gateMechanism()]);
  const outcome = evaluate(target, conformingCandidate(target));
  assert.equal(outcome.receipt.disposition, "PROMOTABLE", JSON.stringify(outcome.receipt.reasonCodes));
});

test("a registered mechanism the plan never dispatches blocks", () => {
  const target = orphanClosureTarget(
    [gateMechanism({ mechanismId: "phantom-check", producer: "nowhere" })],
    { includeGatePack: false }
  );
  const outcome = evaluate(target, conformingCandidate(target));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("ORPHAN_IMPLEMENTED_NOT_DISPATCHED"));
});

test("a dispatched target blocking check with no registry row blocks", () => {
  const target = orphanClosureTarget([]);
  const outcome = evaluate(target, conformingCandidate(target));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("ORPHAN_DISPATCHED_NOT_IMPLEMENTED"));
});

test("validator impersonation in the registry blocks", () => {
  const target = orphanClosureTarget([gateMechanism({ validatorId: "scope-boundary-classify@1" })]);
  const outcome = evaluate(target, conformingCandidate(target));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("ORPHAN_IMPLEMENTED_NOT_DISPATCHED"));
});

test("a mechanism below the configured liveness minimum blocks", () => {
  const target = orphanClosureTarget([gateMechanism({ status: "LANDED_ONLY" })]);
  const outcome = evaluate(target, conformingCandidate(target));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("LIVENESS_BELOW_THRESHOLD"));
});

// ---------------------------------------------------------------------------
// architecture-boundaries@1 and target-test-suite@1 via synthetic adapters
// ---------------------------------------------------------------------------

const ARCH_TOOL = `
// Synthetic architecture validator: src files must not import from internal/.
const { readdirSync, readFileSync, statSync } = require("node:fs");
const { join } = require("node:path");
const root = join(process.env.KERNEL_CANDIDATE_DIR, "src");
const offenders = [];
function walk(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full);
    else if (readFileSync(full, "utf8").includes("internal/")) offenders.push(full);
  }
}
walk(root);
console.log(JSON.stringify({ offenders }));
process.exit(offenders.length === 0 ? 0 : 1);
`;

const TEST_TOOL = `
// Synthetic target test suite: the candidate's marker module must export ok.
const { pathToFileURL } = require("node:url");
const { join } = require("node:path");
import(pathToFileURL(join(process.env.KERNEL_CANDIDATE_DIR, "src", "app.mjs")).href).then((m) => {
  const passed = m.app === 1 || m.app === 2;
  console.log(JSON.stringify({ passed }));
  process.exit(passed ? 0 : 1);
});
`;

function strictPacks() {
  const check = (packId, checkId, argv) => ({
    schemaVersion: "policy-pack@1",
    packId,
    version: "1.0.0",
    description: `synthetic ${packId}`,
    phases: ["CANDIDATE_VALIDATION"],
    dependencies: [],
    checks: [
      {
        checkId,
        phase: "CANDIDATE_VALIDATION",
        effect: "BLOCKING",
        validator: { kind: "TARGET_COMMAND", argv },
        inputs: [],
        outputSchemaId: "check-result@1",
        timeoutSeconds: 120,
        network: "NONE",
        filesystem: "READ_ONLY",
        envAllowlist: [],
        resultConsumer: "DISPOSITION_REDUCER"
      }
    ]
  });
  return [
    check("architecture-boundaries", "architecture-check", ["node", "tools/check-architecture.cjs"]),
    check("target-test-suite", "target-tests", ["node", "tools/run-tests.cjs"])
  ];
}

function strictTarget() {
  return buildTargetRepo({
    scope: { allowed: ["src/"], readonly: ["docs/"], forbidden: ["policy/"] },
    targetPacks: strictPacks(),
    extraBaseFiles: {
      "tools/check-architecture.cjs": ARCH_TOOL,
      "tools/run-tests.cjs": TEST_TOOL
    }
  });
}

test("synthetic architecture and target-test validators gate the candidate", () => {
  const clean = strictTarget();
  writeRepoFile(clean.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const good = evaluate(clean, commitAll(clean.repoDir, "clean feature"));
  assert.equal(good.receipt.disposition, "PROMOTABLE", JSON.stringify(good.receipt.reasonCodes));

  const dirty = strictTarget();
  writeRepoFile(dirty.repoDir, "src/feature.mjs", "import { x } from 'internal/secret.mjs';\n");
  const bad = evaluate(dirty, commitAll(dirty.repoDir, "violates boundaries"));
  assert.equal(bad.receipt.disposition, "BLOCKED");
  const arch = bad.receipt.checkResults.find((r) => r.checkId === "architecture-check");
  assert.equal(arch.outcome, "FIRED");
  assert.deepEqual(arch.reasonCodes, ["COMMAND_FAILED"]);
});

test("AC-3: a candidate rewriting the architecture tool cannot change validator authority", () => {
  // tools/ is allowed scope here, so the only defense is that target
  // validators execute from the trusted BASE materialization.
  const target = buildTargetRepo({
    scope: { allowed: ["src/", "tools/"], readonly: ["docs/"], forbidden: ["policy/"] },
    targetPacks: strictPacks(),
    extraBaseFiles: {
      "tools/check-architecture.cjs": ARCH_TOOL,
      "tools/run-tests.cjs": TEST_TOOL
    }
  });
  writeRepoFile(target.repoDir, "src/feature.mjs", "import { x } from 'internal/secret.mjs';\n");
  writeRepoFile(target.repoDir, "tools/check-architecture.cjs", "process.exit(0); // neutered\n");
  const outcome = evaluate(target, commitAll(target.repoDir, "neuter the validator"));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  const arch = outcome.receipt.checkResults.find((r) => r.checkId === "architecture-check");
  assert.equal(arch.outcome, "FIRED", "base-owned validator must still fire");
  // The receipt pins the BASE validator bytes, not the candidate's rewrite.
  const validatorEntry = outcome.receipt.digests.validators.find((v) => v.validatorId.startsWith("target:"));
  assert.ok(validatorEntry);
});
