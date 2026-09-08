import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, createPublicKey, sign } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import test, { before, after } from "node:test";
import { canonicalize, digestOfBytes } from "../src/canonical-json.mjs";
import { attestationBody } from "../src/admission.mjs";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { verifyReceipt } from "../src/receipt.mjs";
import { inspectPublishedEvidence, projectPublishedEvaluation } from "../src/agent-projection.mjs";
import { buildTargetRepo, commitAll, commitPlumbed, contractBytesOf, defaultTeamPack, git, writeRepoFile } from "./fixtures.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
let parent, copy, head, admissionArgs, workerEnv;
before(() => {
  parent = mkdtempSync(join(tmpdir(), "shedu-independent-hostile-"));
  copy = join(parent, "kernel space % # café");
  mkdirSync(copy);
  for (const dir of ["src", "registry", "packs", "schemas", "conformance", "security", ".harness-bench"]) {
    cpSync(join(root, dir), join(copy, dir), { recursive: true });
  }
  cpSync(join(root, "package.json"), join(copy, "package.json"));
  git(copy, "init", "-q");
  head = commitAll(copy, "synthetic test-only frozen kernel");
  const body = attestationBody({
    kernelCommit: head,
    statusDigest: digestOfBytes(readFileSync(join(copy, "conformance/status.json"))),
    mechanismInventoryDigest: digestOfBytes(readFileSync(join(copy, "registry/kernel-mechanisms.json"))),
    controlSurfaceDigest: digestOfBytes(readFileSync(join(copy, "registry/control-surface.json")))
  });
  // Ephemeral test authority only; never a public release or certification.
  const { privateKey } = generateKeyPairSync("ed25519");
  const pinnedKey = Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url").toString("hex");
  const attestationPath = join(parent, "test-attestation.json");
  writeFileSync(attestationPath, canonicalize({ ...body, signing: {
    algorithm: "ed25519", publicKey: pinnedKey,
    signature: sign(null, Buffer.from(canonicalize(body)), privateKey).toString("hex")
  } }));
  admissionArgs = { attestationPath, pinnedKey, expectedCommit: head };
  workerEnv = { SHEDU_ATTESTATION_FILE: attestationPath, SHEDU_PINNED_KEY: pinnedKey, SHEDU_EXPECTED_COMMIT: head };
});
after(() => rmSync(parent, { recursive: true, force: true }));

test("encoded checkout characters preserve exact admission and still reject wrong authority", async () => {
  const { committedAdmission, isAdmitted } = await import(pathToFileURL(join(copy, "src/admission.mjs")));
  const admitted = committedAdmission(admissionArgs);
  assert.equal(isAdmitted(admitted), true, JSON.stringify(admitted));
  assert.equal(isAdmitted(committedAdmission({ ...admissionArgs, pinnedKey: "a".repeat(64) })), false);
  assert.equal(isAdmitted(committedAdmission({ ...admissionArgs, expectedCommit: "b".repeat(40) })), false);
});

test("encoded checkout characters reach the actual supervisor worker and offline verifier", async () => {
  const { evaluateSupervised } = await import(pathToFileURL(join(copy, "src/supervisor.mjs")));
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "valid candidate");
  const outDir = join(parent, "supervised");
  const result = evaluateSupervised({ repoDir: target.repoDir, contractBytes: contractBytesOf(target.contractFor(candidate)), outDir, maxRuntimeSeconds: 40, workerEnv });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.disposition, "PROMOTABLE", JSON.stringify(result));
  const verified = verifyReceipt({ receiptBytes: readFileSync(join(outDir, "current/receipt.json")), planBytes: readFileSync(join(outDir, "current/plan.json")), evidenceDir: join(outDir, "current/artifacts/evidence") });
  assert.equal(verified.ok, true, JSON.stringify(verified.errors));
});

test("encoded checkout characters preserve the architecture runtime proof", async () => {
  const { CONTROL_PROOFS } = await import(pathToFileURL(join(copy, "src/control-proofs.mjs")));
  const result = CONTROL_PROOFS["architecture-fence"]();
  assert.equal(result.passed, true, JSON.stringify(result));
});

test("encoded checkout characters preserve fresh conformance and the two-way control census", async () => {
  const { runConformance } = await import(pathToFileURL(join(copy, "src/conformance.mjs")));
  const result = runConformance({ outDir: join(parent, "conformance-output") });
  assert.equal(result.status.allPassed, true, JSON.stringify(result.status));
  assert.equal(result.status.controlCensus.complete, true);
});

for (const kind of ["COMMIT", "TREE"]) test(`missing ${kind} is a structured rejection with no retained worktree`, () => {
  const target = buildTargetRepo();
  const before = git(target.repoDir, "worktree", "list", "--porcelain");
  const contract = target.contractFor("f".repeat(40));
  contract.target.candidate.kind = kind;
  let outcome;
  assert.doesNotThrow(() => { outcome = evaluateCandidate({ repoDir: target.repoDir, contractBytes: contractBytesOf(contract), outDir: join(parent, "missing-" + kind) }); });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reasonCode, "AUTHORITY_OBJECT_MISSING");
  assert.equal(git(target.repoDir, "worktree", "list", "--porcelain"), before);
});

test("a failed candidate checkout releases the already-created base worktree", () => {
  const target = buildTargetRepo();
  const candidate = commitPlumbed(target.repoDir, [{ path: "src/" + "a".repeat(300), content: "too long for supported filesystems\n" }], "unmaterializable path");
  const before = git(target.repoDir, "worktree", "list", "--porcelain");
  let outcome;
  assert.doesNotThrow(() => { outcome = evaluateCandidate({ repoDir: target.repoDir, contractBytes: contractBytesOf(target.contractFor(candidate)), outDir: join(parent, "checkout-failure") }); });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reasonCode, "INFRASTRUCTURE_FAILURE");
  assert.equal(git(target.repoDir, "worktree", "list", "--porcelain"), before);
});

function versionTwoPublication() {
  const requirement = { class: "SINGLE_PROCESS", maxTasks: 64 };
  const pack = defaultTeamPack();
  pack.schemaVersion = "policy-pack@2";
  pack.checks[0].validator.executionRequirement = requirement;
  const commands = [{ commandId: "v2-proof", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.stdout.write('v2-visible')"], executionRequirement: requirement }];
  const target = buildTargetRepo({ targetPacks: [pack], profileOverrides: { schemaVersion: "policy-profile@2", executionPolicy: requirement }, validationCommands: commands });
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "v2 candidate");
  const contract = target.contractFor(candidate, { schemaVersion: "work-contract@2", resourceCeilings: { maxOutputBytes: 65536, maxArtifactBytes: 2097152, executionCeiling: requirement } });
  const output = mkdtempSync(join(parent, "v2-publication-"));
  const versionName = ".v-1-" + "0".repeat(32);
  const version = join(output, versionName);
  mkdirSync(version);
  const bytes = contractBytesOf(contract);
  writeFileSync(join(version, "work-contract.json"), bytes);
  const result = evaluateCandidate({ repoDir: target.repoDir, contractBytes: bytes, outDir: version });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.receipt.disposition, "PROMOTABLE");
  assert.equal(verifyReceipt({ receiptBytes: result.receiptBytes, planBytes: readFileSync(join(version, "plan.json")), evidenceDir: join(version, "artifacts/evidence") }).ok, true);
  symlinkSync(versionName, join(output, "current"));
  return { output, version };
}

test("version 2 receipts remain consumable by the status and evidence interfaces", () => {
  const fixture = versionTwoPublication();
  assert.equal(projectPublishedEvaluation(fixture.output).disposition, "PROMOTABLE");
  const view = inspectPublishedEvidence(fixture.output, "command-stdout-v2-proof", 256);
  assert.equal(view.schemaVersion, "kernel-evidence-view@1");
  assert.ok(JSON.stringify(view).includes("v2-visible"));
});

test("version-aware projection still rejects a receipt whose declared version was substituted", () => {
  const fixture = versionTwoPublication();
  const path = join(fixture.version, "receipt.json");
  const receipt = JSON.parse(readFileSync(path));
  receipt.schemaVersion = "promotion-receipt@1";
  writeFileSync(path, canonicalize(receipt));
  assert.throws(() => projectPublishedEvaluation(fixture.output), error => error.reasonCode === "SCHEMA_VIOLATION");
});
