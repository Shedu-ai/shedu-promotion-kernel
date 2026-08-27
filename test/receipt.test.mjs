import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { canonicalize } from "../src/canonical-json.mjs";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { generateSigningKeyPem, signReceipt, verifyReceipt } from "../src/receipt.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-receipt-"));

function evaluatedRun({ mutateRepo } = {}) {
  const target = buildTargetRepo();
  if (mutateRepo) mutateRepo(target);
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "conforming feature");
  const dir = outDir();
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: dir
  });
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  return {
    outcome,
    receiptBytes: readFileSync(join(dir, "receipt.json")),
    planBytes: readFileSync(join(dir, "plan.json")),
    evidenceDir: join(dir, "artifacts", "evidence"),
    dir
  };
}

test("an honest receipt verifies offline, with and without its evidence store", () => {
  const run = evaluatedRun();
  const bare = verifyReceipt({ receiptBytes: run.receiptBytes, planBytes: run.planBytes });
  assert.equal(bare.ok, true, JSON.stringify(bare.errors));
  assert.equal(bare.disposition, "PROMOTABLE");
  const withEvidence = verifyReceipt({
    receiptBytes: run.receiptBytes,
    planBytes: run.planBytes,
    evidenceDir: run.evidenceDir
  });
  assert.equal(withEvidence.ok, true, JSON.stringify(withEvidence.errors));
});

test("AC-11: a flipped disposition cannot survive verification", () => {
  const run = evaluatedRun();
  const receipt = JSON.parse(run.receiptBytes.toString("utf8"));
  receipt.disposition = "BLOCKED";
  const verification = verifyReceipt({
    receiptBytes: Buffer.from(canonicalize(receipt), "utf8"),
    planBytes: run.planBytes
  });
  assert.equal(verification.ok, false);
  assert.ok(verification.errors.some((e) => e.reasonCode === "DISPOSITION_MISMATCH"));
});

test("a tampered result cannot survive verification", () => {
  // Build a genuinely BLOCKED run: candidate touches readonly docs.
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "docs/readme.md", "modified readonly\n");
  const candidate = commitAll(target.repoDir, "readonly violation");
  const dir = outDir();
  const blocked = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: dir
  });
  assert.equal(blocked.receipt.disposition, "BLOCKED");
  // The attacker rewrites the FIRED result to PASS and the disposition to
  // PROMOTABLE — the reducer reproduction still refuses it.
  const receipt = JSON.parse(readFileSync(join(dir, "receipt.json"), "utf8"));
  const fired = receipt.checkResults.find((r) => r.outcome === "FIRED");
  fired.outcome = "PASS";
  fired.reasonCodes = [];
  receipt.disposition = "PROMOTABLE";
  receipt.reasonCodes = [];
  const verification = verifyReceipt({
    receiptBytes: Buffer.from(canonicalize(receipt), "utf8"),
    planBytes: readFileSync(join(dir, "plan.json")),
    evidenceDir: join(dir, "artifacts", "evidence")
  });
  assert.equal(verification.ok, false, "laundered receipt must not verify");
  assert.ok(verification.errors.some((e) => e.reasonCode === "EVIDENCE_MUTATED"));
});

test("AC-10: replay against another plan, candidate, or run fails", () => {
  const runA = evaluatedRun();
  const runB = evaluatedRun({
    mutateRepo: (target) => writeRepoFile(target.repoDir, "src/app.mjs", "export const app = 99;\n")
  });
  // Receipt from run A presented with plan from run B.
  const crossPlan = verifyReceipt({ receiptBytes: runA.receiptBytes, planBytes: runB.planBytes });
  assert.equal(crossPlan.ok, false);
  assert.ok(crossPlan.errors.some((e) => e.reasonCode === "RECEIPT_REPLAY"));
  // Receipt from run A presented with evidence from run B.
  const crossEvidence = verifyReceipt({
    receiptBytes: runA.receiptBytes,
    planBytes: runA.planBytes,
    evidenceDir: runB.evidenceDir
  });
  assert.equal(crossEvidence.ok, false);
});

test("signing round-trips; any mutation after signing invalidates the signature", () => {
  const run = evaluatedRun();
  const keyPem = generateSigningKeyPem();
  const receipt = JSON.parse(run.receiptBytes.toString("utf8"));
  const signed = signReceipt(receipt, keyPem);
  const signedBytes = Buffer.from(canonicalize(signed), "utf8");
  const good = verifyReceipt({ receiptBytes: signedBytes, planBytes: run.planBytes });
  assert.equal(good.ok, true, JSON.stringify(good.errors));

  const required = verifyReceipt({
    receiptBytes: signedBytes,
    planBytes: run.planBytes,
    expectedPublicKey: signed.signing.publicKey
  });
  assert.equal(required.ok, true);

  // Mutate a timestamp — a field the reducer ignores — and the signature
  // still catches it.
  const tampered = { ...signed, completedAt: "2027-01-01T00:00:00Z" };
  const bad = verifyReceipt({ receiptBytes: Buffer.from(canonicalize(tampered), "utf8"), planBytes: run.planBytes });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some((e) => e.reasonCode === "SIGNATURE_INVALID"));

  // A different key cannot satisfy an expected-key requirement.
  const otherKey = signReceipt(receipt, generateSigningKeyPem());
  const wrongKey = verifyReceipt({
    receiptBytes: Buffer.from(canonicalize(otherKey), "utf8"),
    planBytes: run.planBytes,
    expectedPublicKey: signed.signing.publicKey
  });
  assert.equal(wrongKey.ok, false);

  // Unsigned receipt when a signature is required.
  const unsigned = verifyReceipt({
    receiptBytes: run.receiptBytes,
    planBytes: run.planBytes,
    expectedPublicKey: signed.signing.publicKey
  });
  assert.equal(unsigned.ok, false);
});

test("the verify-receipt CLI verifies and fails closed, machine-readably", () => {
  const run = evaluatedRun();
  const receiptPath = join(run.dir, "receipt.json");
  const planPath = join(run.dir, "plan.json");
  const cwd = new URL("..", import.meta.url);

  const ok = spawnSync(
    process.execPath,
    ["src/cli.mjs", "verify-receipt", "--receipt", receiptPath, "--plan", planPath, "--evidence", run.evidenceDir],
    { cwd, encoding: "utf8" }
  );
  assert.equal(ok.status, 0, ok.stderr);
  const verdict = JSON.parse(ok.stdout);
  assert.equal(verdict.schemaVersion, "receipt-verification@1");
  assert.equal(verdict.ok, true);
  assert.equal(verdict.disposition, "PROMOTABLE");

  // Mutate evidence, then the same invocation fails with exit 2.
  const index = JSON.parse(readFileSync(join(run.evidenceDir, "index.json"), "utf8"));
  writeFileSync(join(run.evidenceDir, "objects", "sha256", index.artifacts[0].digest.slice(7)), "mutated");
  const bad = spawnSync(
    process.execPath,
    ["src/cli.mjs", "verify-receipt", "--receipt", receiptPath, "--plan", planPath, "--evidence", run.evidenceDir],
    { cwd, encoding: "utf8" }
  );
  assert.equal(bad.status, 2);
  assert.equal(JSON.parse(bad.stdout).ok, false);
});

test("a signed receipt round-trips through the verify-receipt CLI with a pinned key", () => {
  const run = evaluatedRun();
  const keyPem = generateSigningKeyPem();
  const signed = signReceipt(JSON.parse(run.receiptBytes.toString("utf8")), keyPem);
  const dir = mkdtempSync(join(tmpdir(), "shedu-signed-"));
  const receiptPath = join(dir, "receipt.json");
  const planPath = join(dir, "plan.json");
  writeFileSync(receiptPath, Buffer.from(canonicalize(signed), "utf8"));
  writeFileSync(planPath, run.planBytes);
  const cli = spawnSync(
    process.execPath,
    ["src/cli.mjs", "verify-receipt", "--receipt", receiptPath, "--plan", planPath, "--public-key", signed.signing.publicKey],
    { cwd: new URL("..", import.meta.url), encoding: "utf8" }
  );
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(JSON.parse(cli.stdout).ok, true);

  // A different pinned key is rejected.
  const other = signReceipt(JSON.parse(run.receiptBytes.toString("utf8")), generateSigningKeyPem());
  const badKey = spawnSync(
    process.execPath,
    ["src/cli.mjs", "verify-receipt", "--receipt", receiptPath, "--plan", planPath, "--public-key", other.signing.publicKey],
    { cwd: new URL("..", import.meta.url), encoding: "utf8" }
  );
  assert.equal(badKey.status, 2);
  assert.equal(JSON.parse(badKey.stdout).ok, false);
});
