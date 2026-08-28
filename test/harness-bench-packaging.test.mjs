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
// from the declared promotionParameterMap — nothing is hardcoded here.
function buildArgvFromDeclaration(values) {
  const argv = [...subject.admittedPromotionArgv];
  for (const [key, spec] of Object.entries(subject.promotionParameterMap)) {
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
  for (const key of ["contract", "repository", "outputDir", "attestation", "pinnedKey", "expectedCommit"]) {
    assert.ok(subject.promotionParameterMap[key], `parameter ${key} must be declared`);
  }
  assert.equal(subject.publishedReceiptPath, "current/receipt.json");
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
  const argv = buildArgvFromDeclaration({
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
  const onDisk = JSON.parse(readFileSync(join(out, subject.publishedReceiptPath), "utf8"));
  assert.equal(onDisk.disposition, "PROMOTABLE");
});
