import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { digestOfBytes, parseStrict } from "../src/canonical-json.mjs";
import { validateValue } from "../src/contracts.mjs";
import {
  commitAll,
  makeCheck,
  makeContract,
  makeGitRepo,
  makePack,
  makeProfile,
  writeRepoFile
} from "./fixtures.mjs";

const kernelRoot = new URL("..", import.meta.url);

function runCli(args) {
  return spawnSync(process.execPath, ["src/cli.mjs", ...args], { cwd: kernelRoot, encoding: "utf8" });
}

// Builds a disposable target repository whose base commit carries the profile
// and packs, plus an authorized contract file pointing at that base.
function buildTarget() {
  const repoDir = makeGitRepo();

  const pack = makePack({
    checks: [
      makeCheck({ checkId: "identity-check", validator: { kind: "BUILTIN", builtinId: "candidate-identity-verify@1" } }),
      makeCheck({
        checkId: "hostile-argv-check",
        validator: {
          kind: "TARGET_COMMAND",
          argv: ["node", "check.mjs", "--arg=a b;rm -rf /", "'quoted'", "$(subshell)", "über✓"]
        }
      })
    ]
  });
  const packBytes = `${JSON.stringify(pack)}\n`;
  writeRepoFile(repoDir, "policy/example-pack.json", packBytes);

  const profile = makeProfile([
    {
      packId: pack.packId,
      version: pack.version,
      path: "policy/example-pack.json",
      digest: digestOfBytes(Buffer.from(packBytes, "utf8"))
    }
  ]);
  const profileBytes = `${JSON.stringify(profile)}\n`;
  writeRepoFile(repoDir, "policy/profile.json", profileBytes);

  const baseCommit = commitAll(repoDir, "base with policy");
  const candidateCommit = commitAll(repoDir, "candidate");

  const contract = makeContract({
    target: { repositoryId: "example-repo", baseCommit, candidate: { kind: "COMMIT", id: candidateCommit } },
    policyProfile: {
      profileId: profile.profileId,
      path: "policy/profile.json",
      digest: digestOfBytes(Buffer.from(profileBytes, "utf8"))
    }
  });
  const contractPath = join(repoDir, "..", `${repoDir.split("/").pop()}-contract.json`);
  writeFileSync(contractPath, `${JSON.stringify(contract)}\n`);
  return { repoDir, contractPath, baseCommit };
}

test("compile emits a schema-valid canonical plan on stdout, deterministically", () => {
  const { repoDir, contractPath } = buildTarget();
  const first = runCli(["compile", "--contract", contractPath, "--repo", repoDir]);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stderr, "");
  const plan = parseStrict(first.stdout.trimEnd());
  assert.equal(validateValue("compiled-policy-plan@1", plan).ok, true);
  assert.deepEqual(
    plan.checks.find((c) => c.checkId === "hostile-argv-check").validator.argv,
    ["node", "check.mjs", "--arg=a b;rm -rf /", "'quoted'", "$(subshell)", "über✓"]
  );

  const second = runCli(["compile", "--contract", contractPath, "--repo", repoDir]);
  assert.equal(second.status, 0);
  assert.equal(second.stdout, first.stdout);
});

test("a candidate commit that weakens policy cannot change the compiled authority", () => {
  const { repoDir, contractPath } = buildTarget();
  const before = runCli(["compile", "--contract", contractPath, "--repo", repoDir]);
  assert.equal(before.status, 0, before.stderr);

  const weakPack = makePack({ checks: [makeCheck({ checkId: "identity-check", effect: "ADVISORY" })] });
  writeRepoFile(repoDir, "policy/example-pack.json", `${JSON.stringify(weakPack)}\n`);
  commitAll(repoDir, "candidate weakens the pack");

  const after = runCli(["compile", "--contract", contractPath, "--repo", repoDir]);
  assert.equal(after.status, 0, after.stderr);
  assert.equal(after.stdout, before.stdout);
});

test("digest drift in the contract blocks compilation with a machine error", () => {
  const { repoDir, contractPath } = buildTarget();
  const contract = JSON.parse(readFileSync(contractPath, "utf8"));
  contract.policyProfile.digest = `sha256:${"9".repeat(64)}`;
  writeFileSync(contractPath, `${JSON.stringify(contract)}\n`);

  const result = runCli(["compile", "--contract", contractPath, "--repo", repoDir]);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  const error = JSON.parse(result.stderr);
  assert.equal(error.schemaVersion, "promotion-kernel-error@1");
  assert.equal(error.status, "BLOCKED");
  assert.equal(error.reasonCode, "AUTHORITY_DIGEST_MISMATCH");
});

test("an invalid contract blocks compilation before any authority is read", () => {
  const { repoDir, contractPath } = buildTarget();
  writeFileSync(contractPath, '{"schemaVersion":"work-contract@1","surprise":true}\n');
  const result = runCli(["compile", "--contract", contractPath, "--repo", repoDir]);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stderr).reasonCode, "SCHEMA_VIOLATION");
});

test("compile usage errors are machine-readable", () => {
  const result = runCli(["compile", "--contract"]);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stderr).reasonCode, "CLI_USAGE");
});

test("undeclared subcommands still fail closed", () => {
  const result = runCli(["evaluate"]);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stderr).reasonCode, "KERNEL_NOT_IMPLEMENTED");
});
