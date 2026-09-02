import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  DistributionError,
  ensureKernelInstalled,
  verifyDistributionBundle
} from "../scripts/experimental-kernel.mjs";
import {
  buildTargetRepo,
  commitAll,
  contractBytesOf,
  writeRepoFile
} from "./fixtures.mjs";

const root = new URL("..", import.meta.url).pathname;
const activationRoot = new URL("../activation/experimental-v1/", import.meta.url).pathname;
const launcherUrl = new URL("../scripts/experimental-kernel.mjs", import.meta.url).href;

function invoke(argv, cacheRoot, timeout = 180_000, env = process.env) {
  const source = [
    `import { runExperimental } from ${JSON.stringify(launcherUrl)};`,
    "try { process.exitCode = runExperimental(JSON.parse(process.argv[1]), { repository: process.argv[2], cacheRoot: process.argv[3] }); }",
    "catch (cause) { process.stderr.write(JSON.stringify({ reasonCode: cause.reasonCode ?? 'INFRASTRUCTURE_FAILURE', message: cause.message }) + '\\n'); process.exitCode = 2; }"
  ].join("\n");
  return spawnSync(process.execPath, ["--input-type=module", "-e", source, JSON.stringify(argv), root, cacheRoot], {
    encoding: "utf8",
    env,
    timeout,
    maxBuffer: 32 * 1024 * 1024
  });
}

test("the public activation bundle is hash-bound, signed, and identity-consistent", () => {
  const bundle = verifyDistributionBundle();
  assert.equal(bundle.manifest.kernel.commit, "69253a78f095572b727c2336644b03fbff5476c8");
  assert.equal(bundle.manifest.kernel.tree, "282e60da4e98d1659767b9d4a1f89097bec275d8");
  assert.equal(bundle.manifest.authority.publicKey, "146566b79911ee63307b287c0df8ad726da12c94fec15ae104fd563ae0857555");
  assert.match(bundle.manifestDigest, /^sha256:[0-9a-f]{64}$/);
});

test("a one-byte activation-evidence change fails before installation", () => {
  const scratch = mkdtempSync(join(tmpdir(), "shedu-activation-tamper-"));
  try {
    cpSync(activationRoot, scratch, { recursive: true });
    const attestation = join(scratch, "attestation.json");
    writeFileSync(attestation, Buffer.concat([readFileSync(attestation), Buffer.from("\n")]));
    assert.throws(
      () => verifyDistributionBundle({ activationRoot: scratch }),
      (cause) => cause instanceof DistributionError && cause.reasonCode === "ACTIVATION_EVIDENCE_INVALID"
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("re-digesting forged certification bytes cannot replace the signing authority", () => {
  const scratch = mkdtempSync(join(tmpdir(), "shedu-certification-forgery-"));
  try {
    cpSync(activationRoot, scratch, { recursive: true });
    const certificationPath = join(scratch, "certification.json");
    const certification = JSON.parse(readFileSync(certificationPath, "utf8"));
    certification.kernel.commitSha = "a".repeat(40);
    const forgedBytes = Buffer.from(`${JSON.stringify(certification)}\n`, "utf8");
    writeFileSync(certificationPath, forgedBytes);
    const manifestPath = join(scratch, "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.evidence.certification.digest = `sha256:${createHash("sha256").update(forgedBytes).digest("hex")}`;
    writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);
    assert.throws(
      () => verifyDistributionBundle({ activationRoot: scratch }),
      (cause) => cause instanceof DistributionError && cause.reasonCode === "ACTIVATION_EVIDENCE_INVALID"
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("activation artifacts cannot be replaced by symlinks", () => {
  const scratch = mkdtempSync(join(tmpdir(), "shedu-activation-symlink-"));
  try {
    cpSync(activationRoot, scratch, { recursive: true });
    const authority = join(scratch, "authority.json");
    const real = join(scratch, "authority-real.json");
    writeFileSync(real, readFileSync(authority));
    rmSync(authority);
    symlinkSync(real, authority);
    assert.throws(
      () => verifyDistributionBundle({ activationRoot: scratch }),
      (cause) => cause instanceof DistributionError && cause.reasonCode === "ACTIVATION_EVIDENCE_INVALID"
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("the package entrypoint, manifest commands, and public artifacts have no wiring orphan", () => {
  const bundle = verifyDistributionBundle();
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.bin["shedu-kernel-experimental"], "scripts/experimental-kernel.mjs");
  assert.equal(pkg.scripts["experimental:doctor"], "node scripts/experimental-kernel.mjs doctor");
  assert.deepEqual(bundle.manifest.commands, [
    "compile",
    "conformance",
    "doctor",
    "evaluate",
    "inspect-evidence",
    "probe",
    "sandbox:linux:pull",
    "setup",
    "status",
    "verify-receipt"
  ]);
  assert.deepEqual(
    ["authority.json", "attestation.json", "certification.json", "manifest.json"].sort(),
    [bundle.manifest.authority.path, bundle.manifest.evidence.attestation.path, bundle.manifest.evidence.certification.path, "manifest.json"].sort()
  );
});

test("the launcher atomically installs the certified detached source and reaches EXPERIMENTAL", () => {
  const cache = mkdtempSync(join(tmpdir(), "shedu-activation-cache-"));
  try {
    const doctor = invoke(["doctor"], cache);
    assert.equal(doctor.status, 0, doctor.stderr);
    const document = JSON.parse(doctor.stdout);
    assert.equal(document.ok, true);
    assert.equal(document.admission.implementationStatus, "EXPERIMENTAL");
    assert.equal(document.admission.promotionEntrypointAvailable, true);
    assert.equal(document.kernel.reused, false);

    const installed = ensureKernelInstalled({ repository: root, cacheRoot: cache });
    assert.equal(installed.reused, true);
    writeFileSync(join(installed.kernelDir, "candidate-controlled-file"), "tamper\n");
    const repaired = invoke(["doctor"], cache);
    assert.equal(repaired.status, 0, repaired.stderr);
    assert.equal(JSON.parse(repaired.stdout).kernel.reused, false);
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
});

test("the launcher owns admission arguments and rejects caller substitution", () => {
  const cache = mkdtempSync(join(tmpdir(), "shedu-activation-override-"));
  try {
    const result = invoke(["evaluate", "--attestation", "/tmp/forged"], cache);
    assert.equal(result.status, 2);
    assert.equal(JSON.parse(result.stderr).reasonCode, "CLI_USAGE");
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
});

test("ambient PATH and admission variables cannot substitute distribution authority", () => {
  const cache = mkdtempSync(join(tmpdir(), "shedu-activation-ambient-"));
  try {
    const result = invoke(["doctor"], cache, 180_000, {
      ...process.env,
      PATH: "/candidate-controlled-path",
      SHEDU_ATTESTATION_FILE: "/candidate/attestation.json",
      SHEDU_PINNED_KEY: "a".repeat(64),
      SHEDU_EXPECTED_COMMIT: "b".repeat(40)
    });
    assert.equal(result.status, 0, result.stderr);
    const document = JSON.parse(result.stdout);
    assert.equal(document.admission.implementationStatus, "EXPERIMENTAL");
    assert.equal(document.admission.authorityId, "bench-kernel-attestor-2026-08");
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
});

test("the public distribution emits real PROMOTABLE and BLOCKED receipts", { timeout: 240_000 }, (context) => {
  const cache = mkdtempSync(join(tmpdir(), "shedu-activation-evaluate-"));
  const scratch = mkdtempSync(join(tmpdir(), "shedu-activation-contracts-"));
  try {
    const passing = buildTargetRepo();
    writeRepoFile(passing.repoDir, "src/feature.mjs", "export const feature = true;\n");
    const passingCandidate = commitAll(passing.repoDir, "passing candidate");
    const passingContract = join(scratch, "passing.json");
    writeFileSync(passingContract, contractBytesOf(passing.contractFor(passingCandidate)));
    const passingOut = join(scratch, "passing-out");
    const passed = invoke(["evaluate", "--contract", passingContract, "--repo", passing.repoDir, "--out", passingOut], cache, 240_000);
    assert.equal(passed.status, 0, passed.stderr);
    const passingReceipt = JSON.parse(passed.stdout);
    if (passingReceipt.reasonCodes.includes("SANDBOX_UNAVAILABLE")) {
      context.skip("the host is already sandboxed and correctly refuses nested sandbox authority");
      return;
    }
    assert.equal(passingReceipt.disposition, "PROMOTABLE");

    const blocked = buildTargetRepo();
    writeRepoFile(blocked.repoDir, "docs/readme.md", "candidate changed read-only documentation\n");
    const blockedCandidate = commitAll(blocked.repoDir, "blocked candidate");
    const blockedContract = join(scratch, "blocked.json");
    writeFileSync(blockedContract, contractBytesOf(blocked.contractFor(blockedCandidate)));
    const blockedOut = join(scratch, "blocked-out");
    const fired = invoke(["evaluate", "--contract", blockedContract, "--repo", blocked.repoDir, "--out", blockedOut], cache, 240_000);
    assert.equal(fired.status, 0, fired.stderr);
    const receipt = JSON.parse(fired.stdout);
    assert.equal(receipt.disposition, "BLOCKED");
    assert.ok(receipt.reasonCodes.includes("CHECK_FIRED"));
  } finally {
    rmSync(cache, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
  }
});
