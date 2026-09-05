import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, sign as cryptoSign, createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalize, digestOfBytes } from "../src/canonical-json.mjs";
import { attestationBody } from "../src/admission.mjs";
import { validateAgainstSchema } from "../src/json-schema.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const kernelRoot = new URL("..", import.meta.url).pathname;
const subject = JSON.parse(readFileSync(new URL("../.harness-bench/subject.json", import.meta.url), "utf8"));
const template = JSON.parse(readFileSync(new URL("../schemas/harness-bench-subject-template.schema.json", import.meta.url), "utf8"));

// A generic argv builder that a harness would use: it appends flags PURELY
// from one declared argv + parameter map — nothing is hardcoded here.
function buildArgvFromDeclaration(baseArgv, parameterMap, values) {
  const argv = [...baseArgv];
  for (const [key, spec] of Object.entries(parameterMap)) {
    if (values[key] !== undefined) {
      argv.push(spec.flag, values[key]);
    } else if (spec.required) {
      throw new Error(`declared parameter ${key} is required but no value supplied`);
    }
  }
  return argv;
}

test("subject.json is valid against the Harness Bench subject template and declares a complete parameter map", () => {
  const errors = validateAgainstSchema(template, subject);
  assert.deepEqual(errors, [], JSON.stringify(errors));
  // The map must cover every flag the CLI's evaluate entrypoint accepts, so a
  // harness never has to hardcode a flag.
  for (const key of ["contract", "repository", "outputDir", "attestation", "pinnedKey", "expectedCommit", "signKey", "projection"]) {
    assert.ok(subject.promotionParameterMap[key], `parameter ${key} must be declared`);
  }
  assert.deepEqual(subject.statusArgv, ["node", "src/cli.mjs", "status"]);
  assert.deepEqual(Object.keys(subject.statusParameterMap), ["outputDir"]);
  assert.deepEqual(subject.evidenceInspectionArgv, ["node", "src/cli.mjs", "inspect-evidence"]);
  assert.deepEqual(Object.keys(subject.evidenceInspectionParameterMap), ["outputDir", "artifactId", "maxBytes"]);
  assert.ok(subject.capabilities.includes("kernel-agent-interface@1"));
  assert.equal(subject.publishedReceiptPath, "current/receipt.json");
  assert.deepEqual(subject.executionPreflightArgv, ["node", "src/cli.mjs", "execution-preflight"]);
});

test("driving the CLI purely from the declared argv + parameter map admits and promotes", () => {
  // Build a self-contained committed copy of THIS tree so admission has a clean
  // frozen checkout, and an external verifier signs an attestation for it.
  const copy = realpathSync(mkdtempSync(join(tmpdir(), "shedu-benchpkg-")));
  for (const dir of ["src", "registry", "packs", "schemas", "conformance", "security"]) {
    cpSync(join(kernelRoot, dir), join(copy, dir), { recursive: true });
  }
  cpSync(join(kernelRoot, "package.json"), join(copy, "package.json"));
  const g = (...a) => {
    const r = spawnSync("git", ["-C", copy, ...a], { encoding: "utf8", env: { PATH: process.env.PATH } });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  g("init", "-q");
  g("-c", "user.email=t@invalid", "-c", "user.name=t", "add", "-A");
  g("-c", "user.email=t@invalid", "-c", "user.name=t", "commit", "-q", "-m", "frozen");
  const head = g("rev-parse", "HEAD");

  const statusBytes = readFileSync(join(copy, "conformance", "status.json"));
  const inventoryBytes = readFileSync(join(copy, "registry", "kernel-mechanisms.json"));
  const controlBytes = readFileSync(join(copy, "registry", "control-surface.json"));
  const { privateKey } = generateKeyPairSync("ed25519");
  const publicKeyHex = Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url").toString("hex");
  const body = attestationBody({
    kernelCommit: head,
    statusDigest: digestOfBytes(statusBytes),
    mechanismInventoryDigest: digestOfBytes(inventoryBytes),
    controlSurfaceDigest: digestOfBytes(controlBytes)
  });
  const signature = cryptoSign(null, Buffer.from(canonicalize(body), "utf8"), privateKey).toString("hex");
  const attPath = join(mkdtempSync(join(tmpdir(), "shedu-att-")), "attestation.json");
  writeFileSync(attPath, Buffer.from(canonicalize({ ...body, signing: { algorithm: "ed25519", publicKey: publicKeyHex, signature } }), "utf8"));

  // The subject/target to evaluate.
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const f = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const contractPath = join(mkdtempSync(join(tmpdir(), "shedu-c-")), "contract.json");
  writeFileSync(contractPath, contractBytesOf(target.contractFor(candidate)));
  const out = mkdtempSync(join(tmpdir(), "shedu-out-"));

  // Construct the invocation ENTIRELY from subject.json.
  const argv = buildArgvFromDeclaration(subject.admittedPromotionArgv, subject.promotionParameterMap, {
    contract: contractPath,
    repository: target.repoDir,
    outputDir: out,
    attestation: attPath,
    pinnedKey: publicKeyHex,
    expectedCommit: head
  });
  assert.deepEqual(argv.slice(0, 3), ["node", "src/cli.mjs", "evaluate"]);

  // Run with cwd=copy so the declared relative script path resolves.
  const run = spawnSync(process.execPath, [argv[1], ...argv.slice(2)], {
    cwd: copy,
    encoding: "utf8",
    env: { PATH: process.env.PATH }
  });
  assert.equal(run.status, 0, run.stderr);
  const receipt = JSON.parse(run.stdout);
  assert.equal(receipt.disposition, "PROMOTABLE", JSON.stringify(receipt.reasonCodes));

  // The receipt is published exactly where subject.json declares.
  assert.ok(existsSync(join(out, subject.publishedReceiptPath)));
  const onDiskBytes = readFileSync(join(out, subject.publishedReceiptPath), "utf8");
  const onDisk = JSON.parse(onDiskBytes);
  assert.equal(onDisk.disposition, "PROMOTABLE");
  assert.equal(run.stdout, `${onDiskBytes}\n`, "the default evaluate stdout must remain the exact full receipt");

  // Every read-only interface is also driven solely by the v2 declaration.
  const admittedEnv = {
    PATH: process.env.PATH,
    SHEDU_ATTESTATION_FILE: attPath,
    SHEDU_PINNED_KEY: publicKeyHex,
    SHEDU_EXPECTED_COMMIT: head
  };
  const subjectStatusArgv = buildArgvFromDeclaration(subject.statusArgv, subject.statusParameterMap, {});
  const subjectStatusRun = spawnSync(process.execPath, [subjectStatusArgv[1], ...subjectStatusArgv.slice(2)], {
    cwd: copy, encoding: "utf8", env: admittedEnv
  });
  assert.equal(subjectStatusRun.status, 0, subjectStatusRun.stderr);
  const subjectStatus = JSON.parse(subjectStatusRun.stdout);
  assert.equal(subjectStatus.schemaVersion, "kernel-agent-status@1");
  assert.equal(subjectStatus.implementationStatus, "EXPERIMENTAL");
  assert.deepEqual(subjectStatus.nextActions, ["SUBMIT_EVALUATION"]);

  const evaluationStatusArgv = buildArgvFromDeclaration(subject.statusArgv, subject.statusParameterMap, { outputDir: out });
  const evaluationStatusRun = spawnSync(process.execPath, [evaluationStatusArgv[1], ...evaluationStatusArgv.slice(2)], {
    cwd: copy, encoding: "utf8", env: { PATH: process.env.PATH }
  });
  assert.equal(evaluationStatusRun.status, 0, evaluationStatusRun.stderr);
  const evaluationStatus = JSON.parse(evaluationStatusRun.stdout);
  assert.equal(evaluationStatus.schemaVersion, "kernel-evaluation-summary@1");
  assert.equal(evaluationStatus.verification, "VERIFIED");
  assert.equal(evaluationStatus.disposition, "PROMOTABLE");
  assert.deepEqual(evaluationStatus.nextActions, ["VERIFY_PROMOTABLE_RECEIPT", "EXTERNAL_PROMOTION_DECISION_AVAILABLE"]);

  const index = JSON.parse(readFileSync(join(out, "current", "artifacts", "evidence", "index.json"), "utf8"));
  const selected = index.artifacts[0].artifactId;
  const inspectArgv = buildArgvFromDeclaration(
    subject.evidenceInspectionArgv,
    subject.evidenceInspectionParameterMap,
    { outputDir: out, artifactId: selected, maxBytes: "32" }
  );
  const inspectRun = spawnSync(process.execPath, [inspectArgv[1], ...inspectArgv.slice(2)], {
    cwd: copy, encoding: "utf8", env: { PATH: process.env.PATH }
  });
  assert.equal(inspectRun.status, 0, inspectRun.stderr);
  const evidenceView = JSON.parse(inspectRun.stdout);
  assert.equal(evidenceView.schemaVersion, "kernel-evidence-view@1");
  assert.equal(evidenceView.artifact.artifactId, selected);

  // Compact evaluate stdout is presentation-only: the authoritative on-disk
  // bundle remains a complete promotion-receipt@1.
  const compactOut = mkdtempSync(join(tmpdir(), "shedu-out-agent-"));
  const compactArgv = buildArgvFromDeclaration(subject.admittedPromotionArgv, subject.promotionParameterMap, {
    contract: contractPath,
    repository: target.repoDir,
    outputDir: compactOut,
    attestation: attPath,
    pinnedKey: publicKeyHex,
    expectedCommit: head,
    projection: "agent"
  });
  const compactRun = spawnSync(process.execPath, [compactArgv[1], ...compactArgv.slice(2)], {
    cwd: copy, encoding: "utf8", env: { PATH: process.env.PATH }
  });
  assert.equal(compactRun.status, 0, compactRun.stderr);
  assert.equal(JSON.parse(compactRun.stdout).schemaVersion, "kernel-evaluation-summary@1");
  assert.equal(JSON.parse(readFileSync(join(compactOut, subject.publishedReceiptPath), "utf8")).schemaVersion, "promotion-receipt@1");
});
