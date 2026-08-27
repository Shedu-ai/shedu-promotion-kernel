#!/usr/bin/env node

import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { digestOfBytes, parseStrict } from "../src/canonical-json.mjs";
import { validateDocument, validateValue } from "../src/contracts.mjs";

const KERNEL_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_EXAMPLE_ROOT = join(KERNEL_ROOT, "examples", "node-source-hygiene");

function run(executable, argv, options = {}) {
  const result = spawnSync(executable, argv, { encoding: "utf8", ...options });
  if (result.error) throw result.error;
  return result;
}

function git(repoDir, ...argv) {
  const result = run("git", ["-C", repoDir, ...argv], {
    env: {
      PATH: process.env.PATH,
      GIT_AUTHOR_NAME: "Sample Policy Verifier",
      GIT_AUTHOR_EMAIL: "sample-policy@example.invalid",
      GIT_COMMITTER_NAME: "Sample Policy Verifier",
      GIT_COMMITTER_EMAIL: "sample-policy@example.invalid",
      GIT_AUTHOR_DATE: "2001-01-01T00:00:00Z",
      GIT_COMMITTER_DATE: "2001-01-01T00:00:00Z",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null"
    }
  });
  assert.equal(result.status, 0, `git ${argv.join(" ")} failed: ${result.stderr}`);
  return result.stdout.trim();
}

function write(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function runValidator(validatorPath, candidateDir) {
  return run(process.execPath, [validatorPath], {
    env: { KERNEL_CANDIDATE_DIR: candidateDir }
  });
}

export function verifySamplePolicy({ exampleRoot = DEFAULT_EXAMPLE_ROOT } = {}) {
  const packPath = join(exampleRoot, ".shedu", "policy", "node-source-hygiene.json");
  const profilePath = join(exampleRoot, ".shedu", "policy", "profile.json");
  const validatorPath = join(exampleRoot, ".shedu", "validators", "source-hygiene.mjs");
  const packBytes = readFileSync(packPath);
  const profileBytes = readFileSync(profilePath);
  const pack = validateDocument("policy-pack@1", packBytes);
  const profile = validateDocument("policy-profile@1", profileBytes);
  assert.equal(pack.ok, true, JSON.stringify(pack.errors ?? []));
  assert.equal(profile.ok, true, JSON.stringify(profile.errors ?? []));

  const packDigest = digestOfBytes(packBytes);
  const profileDigest = digestOfBytes(profileBytes);
  const selection = profile.value.packs.find((entry) => entry.packId === pack.value.packId);
  assert.ok(selection, "sample profile does not select the sample pack");
  assert.equal(selection.version, pack.value.version, "sample profile version pin drifted");
  assert.equal(selection.path, ".shedu/policy/node-source-hygiene.json");
  assert.equal(selection.digest, packDigest, "sample profile digest pin drifted");

  const scratch = mkdtempSync(join(tmpdir(), "shedu-sample-policy-"));
  try {
    const passing = join(scratch, "passing");
    const failing = join(scratch, "failing");
    write(join(passing, "src", "index.mjs"), "export const ready = true;\n");
    write(join(failing, "src", "index.mjs"), "// TODO remove placeholder\nexport const ready = false;\n");
    const passRun = runValidator(validatorPath, passing);
    const failRun = runValidator(validatorPath, failing);
    assert.equal(passRun.status, 0, passRun.stderr || passRun.stdout);
    assert.equal(parseStrict(passRun.stdout).status, "PASS");
    assert.equal(failRun.status, 1, failRun.stderr || failRun.stdout);
    assert.equal(parseStrict(failRun.stdout).status, "BLOCKED");

    const repoDir = join(scratch, "target");
    mkdirSync(repoDir);
    git(repoDir, "init", "-q");
    cpSync(join(exampleRoot, ".shedu"), join(repoDir, ".shedu"), { recursive: true });
    write(join(repoDir, "src", "index.mjs"), "export const version = 1;\n");
    git(repoDir, "add", "-A");
    git(repoDir, "commit", "-q", "-m", "base with sample policy");
    const baseCommit = git(repoDir, "rev-parse", "HEAD");
    write(join(repoDir, "src", "index.mjs"), "export const version = 2;\n");
    git(repoDir, "add", "-A");
    git(repoDir, "commit", "-q", "-m", "candidate");
    const candidateCommit = git(repoDir, "rev-parse", "HEAD");

    const contract = {
      schemaVersion: "work-contract@1",
      target: {
        repositoryId: "sample-node-project",
        baseCommit,
        candidate: { kind: "COMMIT", id: candidateCommit }
      },
      objectiveId: "verify-sample-policy",
      acceptanceCriterionIds: ["sample-compiles"],
      scope: {
        allowed: ["src/"],
        readonly: [".shedu/"],
        forbidden: ["package-lock.json"]
      },
      validationCommands: [
        { commandId: "node-syntax", phase: "CANDIDATE_VALIDATION", argv: ["node", "--check", "src/index.mjs"] }
      ],
      policyProfile: {
        profileId: profile.value.profileId,
        path: ".shedu/policy/profile.json",
        digest: profileDigest
      },
      capabilityIndex: null,
      priorArtQuery: null,
      mechanismRegistry: null,
      artifactRoot: ".shedu/artifacts/",
      maxRuntimeSeconds: 120,
      resourceCeilings: {
        maxOutputBytes: 1048576,
        maxArtifactBytes: 1048576,
        maxProcesses: 1
      },
      authorization: {
        identity: "sample-personal-owner",
        issuedAt: "2026-08-27T00:00:00Z",
        signature: null
      }
    };
    assert.equal(validateValue("work-contract@1", contract).ok, true);
    const contractPath = join(scratch, "work-contract.json");
    write(contractPath, `${JSON.stringify(contract)}\n`);
    const compiled = run(process.execPath, [
      join(KERNEL_ROOT, "src", "cli.mjs"),
      "compile",
      "--contract", contractPath,
      "--repo", repoDir
    ]);
    assert.equal(compiled.status, 0, compiled.stderr || compiled.stdout);
    const plan = parseStrict(compiled.stdout);
    assert.equal(validateValue("compiled-policy-plan@1", plan).ok, true);
    const sampleCheck = plan.checks.find((check) => check.checkId === "node-source-hygiene");
    assert.ok(sampleCheck, "compiled plan omitted the sample check");
    assert.deepEqual(sampleCheck.validator.argv, ["node", ".shedu/validators/source-hygiene.mjs"]);

    return {
      schemaVersion: "sample-policy-verification@1",
      ok: true,
      packId: pack.value.packId,
      packDigest,
      profileId: profile.value.profileId,
      profileDigest,
      validator: { passingFixture: "PASS", failingFixture: "BLOCKED" },
      compiledCheckIds: plan.checks.map((check) => check.checkId)
    };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function main() {
  try {
    process.stdout.write(`${JSON.stringify(verifySamplePolicy())}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      schemaVersion: "sample-policy-verification@1",
      ok: false,
      reasonCode: "SAMPLE_POLICY_INVALID",
      message: String(error)
    })}\n`);
    return 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = main();
}
