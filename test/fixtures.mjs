import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { digestOfCanonical } from "../src/canonical-json.mjs";

export const COMMIT_A = "a".repeat(40);
export const COMMIT_B = "b".repeat(40);
export const ZERO_DIGEST = `sha256:${"0".repeat(64)}`;

export function makeCheck(overrides = {}) {
  return {
    checkId: "example-check",
    phase: "CANDIDATE_VALIDATION",
    effect: "BLOCKING",
    validator: { kind: "BUILTIN", builtinId: "scope-boundary-classify@1" },
    inputs: ["changed-paths"],
    outputSchemaId: "check-result@1",
    timeoutSeconds: 60,
    network: "NONE",
    filesystem: "READ_ONLY",
    envAllowlist: [],
    resultConsumer: "DISPOSITION_REDUCER",
    ...overrides
  };
}

export function makePack(overrides = {}) {
  return {
    schemaVersion: "policy-pack@1",
    packId: "example-pack",
    version: "1.0.0",
    description: "Example pack",
    phases: ["CANDIDATE_VALIDATION"],
    dependencies: [],
    checks: [makeCheck()],
    ...overrides
  };
}

export function makeProfile(packEntries, overrides = {}) {
  return {
    schemaVersion: "policy-profile@1",
    profileId: "example-profile",
    version: "1.0.0",
    description: "Example profile",
    packs: packEntries,
    strengthen: [],
    ...overrides
  };
}

export function makeContract(overrides = {}) {
  return {
    schemaVersion: "work-contract@1",
    target: {
      repositoryId: "example-repo",
      baseCommit: COMMIT_A,
      candidate: { kind: "COMMIT", id: COMMIT_B }
    },
    objectiveId: "example-objective",
    acceptanceCriterionIds: ["ac-1"],
    scope: {
      allowed: ["src/"],
      readonly: ["docs/"],
      forbidden: ["policy/"]
    },
    validationCommands: [
      { commandId: "unit-tests", phase: "CANDIDATE_VALIDATION", argv: ["node", "--test"] }
    ],
    policyProfile: { profileId: "example-profile", path: "policy/profile.json", digest: ZERO_DIGEST },
    capabilityIndex: null,
    artifactRoot: "artifacts/",
    maxRuntimeSeconds: 600,
    resourceCeilings: { maxOutputBytes: 1048576, maxArtifactBytes: 1048576, maxProcesses: 16 },
    authorization: { identity: "example-authorizer", issuedAt: "2026-08-26T00:00:00Z", signature: null },
    ...overrides
  };
}

// Pins pack documents the way a profile and the compiler expect them:
// canonical digests, standard authority paths.
export function pinPacks(packValues) {
  return packValues.map((value) => ({
    value,
    digest: digestOfCanonical(value),
    path: `policy/${value.packId}.json`
  }));
}

export function profileEntries(pinnedPacks) {
  return pinnedPacks.map((p) => ({
    packId: p.value.packId,
    version: p.value.version,
    path: p.path,
    digest: p.digest
  }));
}

export function git(repoDir, ...args) {
  const r = spawnSync("git", ["-C", repoDir, ...args], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout.trim();
}

export function makeGitRepo() {
  const dir = mkdtempSync(join(tmpdir(), "shedu-kernel-test-"));
  git(dir, "init", "-q");
  return dir;
}

export function writeRepoFile(repoDir, relativePath, content) {
  const target = join(repoDir, relativePath);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

export function commitAll(repoDir, message) {
  git(repoDir, "add", "-A");
  git(
    repoDir,
    "-c", "user.email=kernel-test@example.invalid",
    "-c", "user.name=Kernel Test",
    "-c", "commit.gpgsign=false",
    "commit", "-q", "--allow-empty", "-m", message
  );
  return git(repoDir, "rev-parse", "HEAD");
}
