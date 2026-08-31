import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { before } from "node:test";
import {
  AgentProjectionError,
  canonicalProjection,
  inspectPublishedEvidence,
  projectPublishedEvaluation
} from "../src/agent-projection.mjs";
import { validateAgentProjection } from "../src/agent-contracts.mjs";
import { runAgentInterfaceCensus } from "../src/agent-interface-census.mjs";
import { canonicalize } from "../src/canonical-json.mjs";
import { validateValue } from "../src/contracts.mjs";
import { evaluateCandidate } from "../src/evaluate.mjs";
import {
  NEXT_ACTIONS,
  REASON_ACTIONS,
  actionsForEvaluation,
  auditNextActionRegistry
} from "../src/next-actions.mjs";
import { REASON_CODES } from "../src/reason-codes.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const ROOT = new URL("..", import.meta.url);

let baseFixture;

function versionName() {
  return `.v-${process.pid}-${randomBytes(16).toString("hex")}`;
}

function buildPublishedFixture() {
  const outputRoot = mkdtempSync(join(tmpdir(), "shedu-agent-projection-"));
  const version = versionName();
  const versionDir = join(outputRoot, version);
  mkdirSync(versionDir);
  const target = buildTargetRepo({
    validationCommands: [
      { commandId: "unicode-output", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.stdout.write('h\\u00e9llo')"] }
    ]
  });
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "agent projection fixture");
  const contractBytes = contractBytesOf(target.contractFor(candidate));
  writeFileSync(join(versionDir, "work-contract.json"), contractBytes);
  const outcome = evaluateCandidate({ repoDir: target.repoDir, contractBytes, outDir: versionDir });
  assert.equal(outcome.ok, true, JSON.stringify(outcome));
  symlinkSync(version, join(outputRoot, "current"));
  return { outputRoot, version, versionDir, outcome };
}

function cloneFixture() {
  const parent = mkdtempSync(join(tmpdir(), "shedu-agent-projection-clone-"));
  const outputRoot = join(parent, "out");
  cpSync(baseFixture.outputRoot, outputRoot, { recursive: true, verbatimSymlinks: true });
  const version = readlinkSync(join(outputRoot, "current"));
  return { parent, outputRoot, version, versionDir: join(outputRoot, version) };
}

before(() => {
  baseFixture = buildPublishedFixture();
});

test("the next-action registry covers every closed reason code with no unreachable action", () => {
  const audit = auditNextActionRegistry();
  assert.equal(audit.complete, true, JSON.stringify(audit));
  assert.equal(audit.reasonCodes, REASON_CODES.length);
  assert.equal(audit.mappings, REASON_CODES.length);
  assert.deepEqual(Object.keys(REASON_ACTIONS).sort(), [...REASON_CODES].sort());
  assert.equal(new Set(NEXT_ACTIONS).size, NEXT_ACTIONS.length);
});

test("multi-category failures retain every applicable action lane in fixed order", () => {
  const actions = actionsForEvaluation({
    evaluationState: "PRESENT",
    disposition: "BLOCKED",
    reasonCodes: ["COMMAND_TIMEOUT", "AUTHORIZATION_INVALID", "PRIOR_ART_COLLISION"],
    checkResults: [{ outcome: "SKIPPED", reasonCodes: ["CHECK_SKIPPED"] }]
  });
  assert.deepEqual(actions, ["RETURN_TO_AUTHORIZER", "REPAIR_CANDIDATE", "REPAIR_EVALUATION_ENVIRONMENT"]);
  assert.deepEqual(actionsForEvaluation({
    evaluationState: "PRESENT", disposition: "PROMOTABLE", reasonCodes: [], checkResults: []
  }), ["VERIFY_PROMOTABLE_RECEIPT", "EXTERNAL_PROMOTION_DECISION_AVAILABLE"]);
});

test("an absent publication is explicit, canonical, and directs evaluation", () => {
  const outputRoot = mkdtempSync(join(tmpdir(), "shedu-agent-absent-"));
  const summary = projectPublishedEvaluation(outputRoot);
  assert.deepEqual(summary, {
    schemaVersion: "kernel-evaluation-summary@1",
    evaluationState: "ABSENT",
    verification: "NOT_APPLICABLE",
    nextActions: ["SUBMIT_EVALUATION"]
  });
  assert.equal(canonicalProjection(summary), `${canonicalize(summary)}\n`);
});

test("a complete publication projects every non-passing check and consistent counts", () => {
  const summary = projectPublishedEvaluation(baseFixture.outputRoot);
  assert.equal(summary.schemaVersion, "kernel-evaluation-summary@1");
  assert.equal(summary.evaluationState, "PRESENT");
  assert.equal(summary.verification, "VERIFIED");
  assert.equal(summary.disposition, baseFixture.outcome.receipt.disposition);
  assert.equal(summary.checkCounts.total, baseFixture.outcome.receipt.checkResults.length);
  assert.equal(
    summary.nonPassingChecks.length,
    baseFixture.outcome.receipt.checkResults.filter((result) => result.outcome !== "PASS").length
  );
  assert.equal(summary.changedFiles.total, baseFixture.outcome.receipt.changedFiles.length);
  assert.match(summary.digests.receipt, /^sha256:[0-9a-f]{64}$/);
  assert.match(summary.digests.plan, /^sha256:[0-9a-f]{64}$/);
  assert.equal(validateValue("kernel-evaluation-summary@1", summary).ok, true);
});

test("evidence inspection is metadata-only by default and bounded when requested", () => {
  const index = JSON.parse(readFileSync(join(baseFixture.versionDir, "artifacts", "evidence", "index.json"), "utf8"));
  const artifact = index.artifacts.find((entry) => entry.mediaType === "application/json");
  assert.ok(artifact, "fixture must contain JSON evidence");
  const metadata = inspectPublishedEvidence(baseFixture.outputRoot, artifact.artifactId);
  assert.equal(metadata.artifact.artifactId, artifact.artifactId);
  assert.equal(metadata.preview, null);

  const previewed = inspectPublishedEvidence(baseFixture.outputRoot, artifact.artifactId, 17);
  assert.equal(previewed.artifact.digest, artifact.digest);
  assert.equal(previewed.preview.requestedBytes, 17);
  assert.ok(previewed.preview.returnedBytes <= 17);
  assert.equal(Buffer.byteLength(previewed.preview.text, "utf8"), previewed.preview.returnedBytes);
  assert.equal(previewed.preview.totalBytes, artifact.byteLength);
});

test("a missing artifact identity cannot be converted into a best-effort view", () => {
  assert.throws(
    () => inspectPublishedEvidence(baseFixture.outputRoot, "not-indexed"),
    (error) => error instanceof AgentProjectionError && error.reasonCode === "EVIDENCE_MISSING"
  );
});

test("mutated evidence produces no evaluation summary", () => {
  const fixture = cloneFixture();
  const index = JSON.parse(readFileSync(join(fixture.versionDir, "artifacts", "evidence", "index.json"), "utf8"));
  const victim = index.artifacts[0];
  writeFileSync(
    join(fixture.versionDir, "artifacts", "evidence", "objects", "sha256", victim.digest.slice(7)),
    Buffer.alloc(victim.byteLength, 0x78)
  );
  assert.throws(
    () => projectPublishedEvaluation(fixture.outputRoot),
    (error) => error instanceof AgentProjectionError && error.reasonCode === "EVIDENCE_MUTATED"
  );
});

test("absolute, nested, and non-symlink current substitutions fail closed", () => {
  for (const attack of ["absolute", "nested", "directory"]) {
    const fixture = cloneFixture();
    rmSync(join(fixture.outputRoot, "current"), { recursive: true, force: true });
    if (attack === "absolute") {
      symlinkSync(fixture.versionDir, join(fixture.outputRoot, "current"));
    } else if (attack === "nested") {
      mkdirSync(join(fixture.outputRoot, "nested"));
      symlinkSync(`nested/../${fixture.version}`, join(fixture.outputRoot, "current"));
    } else {
      mkdirSync(join(fixture.outputRoot, "current"));
    }
    assert.throws(
      () => projectPublishedEvaluation(fixture.outputRoot),
      (error) => error instanceof AgentProjectionError && error.reasonCode === "EVIDENCE_MUTATED",
      attack
    );
  }
});

test("a FIFO substituted for a bundle member is refused promptly", { skip: process.platform === "win32" }, () => {
  const fixture = cloneFixture();
  const receiptPath = join(fixture.versionDir, "receipt.json");
  rmSync(receiptPath);
  const fifo = spawnSync("mkfifo", [receiptPath], { encoding: "utf8" });
  assert.equal(fifo.status, 0, fifo.stderr);
  const started = performance.now();
  assert.throws(
    () => projectPublishedEvaluation(fixture.outputRoot),
    (error) => error instanceof AgentProjectionError && error.reasonCode === "EVIDENCE_MISSING"
  );
  assert.ok(performance.now() - started < 1000, "FIFO read must not block");
});

test("projection schemas reject unknown actions and contradictory counts", () => {
  const summary = projectPublishedEvaluation(baseFixture.outputRoot);
  const unknown = structuredClone(summary);
  unknown.nextActions = ["DO_WHATEVER"];
  assert.equal(validateValue("kernel-evaluation-summary@1", unknown).ok, false);

  const contradictory = structuredClone(summary);
  contradictory.checkCounts.total += 1;
  assert.equal(validateValue("kernel-evaluation-summary@1", contradictory).ok, false);

  const wrongLane = structuredClone(summary);
  wrongLane.nextActions = ["NONE"];
  assert.equal(validateAgentProjection("kernel-evaluation-summary@1", wrongLane).ok, false);
});

test("the read-only interface has complete registered/implemented/dispatched/emitted/consumed closure", () => {
  const subjectRun = spawnSync(process.execPath, ["src/cli.mjs", "status"], { cwd: ROOT, encoding: "utf8" });
  assert.equal(subjectRun.status, 0, subjectRun.stderr);
  const evaluationRun = spawnSync(
    process.execPath,
    ["src/cli.mjs", "status", "--out", baseFixture.outputRoot],
    { cwd: ROOT, encoding: "utf8" }
  );
  assert.equal(evaluationRun.status, 0, evaluationRun.stderr);
  const index = JSON.parse(readFileSync(join(baseFixture.versionDir, "artifacts", "evidence", "index.json"), "utf8"));
  const evidenceRun = spawnSync(
    process.execPath,
    ["src/cli.mjs", "inspect-evidence", "--out", baseFixture.outputRoot, "--artifact", index.artifacts[0].artifactId],
    { cwd: ROOT, encoding: "utf8" }
  );
  assert.equal(evidenceRun.status, 0, evidenceRun.stderr);
  const observations = [
    { surfaceId: "subject-status", value: JSON.parse(subjectRun.stdout) },
    { surfaceId: "evaluation-status", value: JSON.parse(evaluationRun.stdout) },
    { surfaceId: "evidence-inspection", value: JSON.parse(evidenceRun.stdout) }
  ];
  const census = runAgentInterfaceCensus({ observations });
  assert.equal(census.complete, true, JSON.stringify(census, null, 2));
  assert.deepEqual(census.registered, ["subject-status", "evaluation-status", "evidence-inspection"]);
  assert.equal(census.findings.length, 0);

  const missing = runAgentInterfaceCensus({ observations: observations.slice(0, 2) });
  assert.equal(missing.complete, false);
  assert.ok(missing.findings.some((finding) => finding.reasonCode === "ORPHAN_DISPATCHED_NOT_EMITTED"));
  const extra = runAgentInterfaceCensus({ observations: [...observations, { surfaceId: "rogue-surface", value: {} }] });
  assert.equal(extra.complete, false);
  assert.ok(extra.findings.some((finding) => finding.reasonCode === "ORPHAN_EMITTED_NOT_DISPATCHED"));
});

test("CLI selectors reject delimiter-composed and over-ceiling values without executing them", () => {
  const marker = join(mkdtempSync(join(tmpdir(), "shedu-agent-marker-")), "owned");
  const hostile = spawnSync(
    process.execPath,
    ["src/cli.mjs", "inspect-evidence", "--out", baseFixture.outputRoot, "--artifact", "valid-id", "--max-bytes", `1;touch ${marker}`],
    { cwd: ROOT, encoding: "utf8" }
  );
  assert.equal(hostile.status, 2);
  assert.equal(JSON.parse(hostile.stderr).reasonCode, "CLI_USAGE");
  assert.equal(existsSync(marker), false);

  const oversized = spawnSync(
    process.execPath,
    ["src/cli.mjs", "inspect-evidence", "--out", baseFixture.outputRoot, "--artifact", "valid-id", "--max-bytes", "65537"],
    { cwd: ROOT, encoding: "utf8" }
  );
  assert.equal(oversized.status, 2);
  assert.equal(JSON.parse(oversized.stderr).reasonCode, "CLI_USAGE");
});
