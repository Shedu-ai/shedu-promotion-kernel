import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { validateValue } from "../src/contracts.mjs";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { verifyEvidenceDir } from "../src/evidence.mjs";
import {
  buildTargetRepo,
  commitAll,
  commitPlumbed,
  contractBytesOf,
  writeRepoFile
} from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-eval-"));

function conformingCandidate(target) {
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  return commitAll(target.repoDir, "conforming feature");
}

test("a conforming candidate evaluates to PROMOTABLE with verifiable evidence", () => {
  const target = buildTargetRepo();
  const candidate = conformingCandidate(target);
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: outDir()
  });
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "PROMOTABLE", JSON.stringify(outcome.receipt.reasonCodes));
  assert.equal(validateValue("promotion-receipt@1", outcome.receipt).ok, true);

  // Every mandatory check executed and passed exactly once.
  const outcomes = new Map(outcome.receipt.checkResults.map((r) => [r.checkId, r.outcome]));
  for (const id of [
    "candidate-identity-verify",
    "validation-plan-admission",
    "scope-boundary-classify",
    "validation-plan-validation",
    "candidate-tree-stability",
    "evidence-binding-index",
    "validation-plan-finalization"
  ]) {
    assert.equal(outcomes.get(id), "PASS", id);
  }
  // Changed-file attribution is present and classified.
  assert.deepEqual(outcome.receipt.changedFiles, [
    { path: "src/feature.mjs", changeKind: "ADDED", scopeClass: "ALLOWED" }
  ]);
  // Validator identities are digest-bound.
  assert.ok(outcome.receipt.digests.validators.length >= 5);
  // Evidence store verifies offline.
  const verified = verifyEvidenceDir(join(outcome.outDir, "artifacts", "evidence"));
  assert.equal(verified.ok, true, JSON.stringify(verified.errors));
});

test("AC-2: equal inputs produce byte-identical plan and evaluation digests", () => {
  const target = buildTargetRepo();
  const candidate = conformingCandidate(target);
  const bytes = contractBytesOf(target.contractFor(candidate));
  const first = evaluateCandidate({ repoDir: target.repoDir, contractBytes: bytes, outDir: outDir() });
  const second = evaluateCandidate({ repoDir: target.repoDir, contractBytes: bytes, outDir: outDir() });
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(first.planDigest, second.planDigest);
  assert.equal(first.evaluationDigest, second.evaluationDigest);
});

test("a failing validation command blocks with explicit machine reasons", () => {
  const target = buildTargetRepo({
    validationCommands: [
      { commandId: "will-fail", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.exit(7)"] }
    ]
  });
  const candidate = conformingCandidate(target);
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: outDir()
  });
  assert.equal(outcome.ok, true);
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("CHECK_FIRED"));
  assert.ok(outcome.receipt.reasonCodes.includes("COMMAND_FAILED"));
  // The command is declared for CANDIDATE_VALIDATION and executed by exactly
  // that phase's check; the other phase checks pass with empty command sets.
  const vp = outcome.receipt.checkResults.find((r) => r.checkId === "validation-plan-validation");
  assert.equal(vp.outcome, "FIRED");
  assert.ok(vp.evidence.some((e) => e.artifactId === "command-report-will-fail"));
  assert.equal(outcome.receipt.checkResults.find((r) => r.checkId === "validation-plan-admission").outcome, "PASS");
});

test("a scope violation blocks and the candidate cannot rewrite policy authority", () => {
  const target = buildTargetRepo();
  // The candidate tampers with the profile — a forbidden path AND an attempt
  // to change authority. Authority remains the base version; scope FIREs.
  writeRepoFile(target.repoDir, "policy/profile.json", "{\"weakened\": true}\n");
  const candidate = commitAll(target.repoDir, "hostile policy rewrite");
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: outDir()
  });
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("SCOPE_FORBIDDEN_CHANGE"));
  assert.deepEqual(outcome.receipt.changedFiles, [
    { path: "policy/profile.json", changeKind: "MODIFIED", scopeClass: "FORBIDDEN" }
  ]);
  // Containment failure halts the run: everything after scope-boundary is an
  // explicit SKIPPED record, and validation never ran against the candidate.
  assert.ok(outcome.receipt.reasonCodes.includes("CHECK_SKIPPED"));
  const after = outcome.receipt.checkResults.filter((r) => r.checkId !== "scope-boundary-classify" && r.outcome === "SKIPPED");
  assert.ok(after.some((r) => r.checkId === "validation-plan-validation"));
  assert.ok(after.some((r) => r.checkId === "evidence-binding-index"));
});

test("an identity failure halts the run and fails closed", () => {
  const target = buildTargetRepo();
  const orphan = commitPlumbed(target.repoDir, [{ path: "src/orphan.mjs", content: "1\n" }], "orphan", { parents: [] });
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(orphan)),
    outDir: outDir()
  });
  assert.equal(outcome.ok, true);
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("CANDIDATE_NOT_DESCENDANT"));
  assert.ok(outcome.receipt.reasonCodes.includes("CHECK_SKIPPED"));
  // The identity failure halts immediately; every remaining required check
  // carries an explicit SKIPPED non-success record, so omitted work is
  // recorded, never silent.
  assert.equal(outcome.receipt.checkResults[0].checkId, "candidate-identity-verify");
  assert.equal(outcome.receipt.checkResults[0].outcome, "FIRED");
  const rest = outcome.receipt.checkResults.slice(1);
  assert.ok(rest.length >= 6);
  for (const result of rest) {
    assert.equal(result.outcome, "SKIPPED", result.checkId);
    assert.deepEqual(result.reasonCodes, ["CHECK_SKIPPED"]);
  }
});

test("a blocking target-command pack check gates the disposition", () => {
  const failingPack = {
    schemaVersion: "policy-pack@1",
    packId: "gate-pack",
    version: "1.0.0",
    description: "target gate that always fails",
    phases: ["CANDIDATE_VALIDATION"],
    dependencies: [],
    checks: [
      {
        checkId: "gate-check",
        phase: "CANDIDATE_VALIDATION",
        effect: "BLOCKING",
        validator: { kind: "TARGET_COMMAND", argv: ["node", "-e", "process.exit(3)"] },
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
  const target = buildTargetRepo({ targetPacks: [failingPack] });
  const candidate = conformingCandidate(target);
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: outDir()
  });
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  const gate = outcome.receipt.checkResults.find((r) => r.checkId === "gate-check");
  assert.equal(gate.outcome, "FIRED");
  assert.deepEqual(gate.reasonCodes, ["COMMAND_FAILED"]);
});

test("evidence mutated after the run fails offline verification", () => {
  const target = buildTargetRepo();
  const candidate = conformingCandidate(target);
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: outDir()
  });
  const evidenceDir = join(outcome.outDir, "artifacts", "evidence");
  const index = JSON.parse(readFileSync(join(evidenceDir, "index.json"), "utf8"));
  const victim = index.artifacts[0];
  writeFileSync(join(evidenceDir, "objects", "sha256", victim.digest.slice("sha256:".length)), "mutated");
  const verified = verifyEvidenceDir(evidenceDir);
  assert.equal(verified.ok, false);
  assert.ok(verified.errors.some((e) => e.reasonCode === "EVIDENCE_MUTATED"));
});

test("direct evaluate is refused when the subject is not admitted", () => {
  // The promotion entrypoint is gated by the SAME admission the probe uses.
  // In the shipped state (no pinned attestation key) the subject is
  // FOUNDATION_ONLY, so the CLI evaluate command fails closed with
  // NOT_ADMITTED — direct evaluation cannot bypass the gate.
  const target = buildTargetRepo();
  const candidate = conformingCandidate(target);
  const contractPath = join(mkdtempSync(join(tmpdir(), "shedu-contract-")), "contract.json");
  writeFileSync(contractPath, contractBytesOf(target.contractFor(candidate)));
  const run = spawnSync(
    process.execPath,
    ["src/cli.mjs", "evaluate", "--contract", contractPath, "--repo", target.repoDir, "--out", outDir()],
    { cwd: new URL("..", import.meta.url), encoding: "utf8" }
  );
  assert.equal(run.status, 2, run.stdout);
  assert.equal(JSON.parse(run.stderr).reasonCode, "NOT_ADMITTED");

  // Even with a signing key the gate refuses before evaluating.
  const withKey = spawnSync(
    process.execPath,
    ["src/cli.mjs", "evaluate", "--contract", contractPath, "--repo", target.repoDir, "--out", outDir(), "--sign-key", "/nonexistent"],
    { cwd: new URL("..", import.meta.url), encoding: "utf8" }
  );
  assert.equal(withKey.status, 2);
  assert.equal(JSON.parse(withKey.stderr).reasonCode, "NOT_ADMITTED");

  const usage = spawnSync(process.execPath, ["src/cli.mjs", "evaluate", "--contract"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8"
  });
  assert.equal(usage.status, 2);
  assert.equal(JSON.parse(usage.stderr).reasonCode, "CLI_USAGE");
});
