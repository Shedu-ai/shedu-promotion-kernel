import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { digestOfBytes, digestOfCanonical } from "../src/canonical-json.mjs";

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
    authorization: { mode: "UNSIGNED_PERSONAL", trustedAuthorizers: [] },
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
    priorArtQuery: null,
    mechanismRegistry: null,
    artifactRoot: "artifacts/",
    maxRuntimeSeconds: 600,
    resourceCeilings: { maxOutputBytes: 1048576, maxArtifactBytes: 1048576, maxProcesses: 1 },
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

const GIT_TEST_ENV = {
  PATH: process.env.PATH,
  GIT_AUTHOR_NAME: "Kernel Test",
  GIT_AUTHOR_EMAIL: "kernel-test@example.invalid",
  GIT_AUTHOR_DATE: "2001-01-01T00:00:00Z",
  GIT_COMMITTER_NAME: "Kernel Test",
  GIT_COMMITTER_EMAIL: "kernel-test@example.invalid",
  GIT_COMMITTER_DATE: "2001-01-01T00:00:00Z",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null"
};

export function git(repoDir, ...args) {
  const r = spawnSync("git", ["-C", repoDir, ...args], { encoding: "utf8", env: GIT_TEST_ENV });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout.trim();
}

// Commit content through git plumbing, without touching the filesystem —
// required for hostile fixtures a real checkout cannot represent on this
// machine (case-colliding paths, symlink blobs, orphan commits).
export function commitPlumbed(repoDir, entries, message, { parents = "HEAD", remove = [] } = {}) {
  const head = spawnSync("git", ["-C", repoDir, "rev-parse", "--verify", "HEAD"], { encoding: "utf8", env: GIT_TEST_ENV });
  const parentShas = parents === "HEAD" ? (head.status === 0 ? [head.stdout.trim()] : []) : parents;
  if (head.status === 0) git(repoDir, "read-tree", "HEAD");
  for (const path of remove) {
    git(repoDir, "update-index", "--force-remove", path);
  }
  for (const entry of entries) {
    const hashed = spawnSync("git", ["-C", repoDir, "hash-object", "-w", "--stdin"], {
      input: entry.content,
      encoding: "utf8",
      env: GIT_TEST_ENV
    });
    if (hashed.status !== 0) throw new Error(`hash-object failed: ${hashed.stderr}`);
    git(repoDir, "update-index", "--add", "--cacheinfo", `${entry.mode ?? "100644"},${hashed.stdout.trim()},${entry.path}`);
  }
  const tree = git(repoDir, "write-tree");
  const args = ["commit-tree", tree, "-m", message];
  for (const p of parentShas) args.push("-p", p);
  return git(repoDir, ...args);
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

export function defaultTeamPack() {
  return makePack({
    packId: "team-pack",
    checks: [
      makeCheck({
        checkId: "team-check",
        effect: "ADVISORY",
        validator: { kind: "TARGET_COMMAND", argv: ["node", "-e", "process.exit(0)"], inputManifest: [] }
      })
    ]
  });
}

// A kernel-shipped selectable pack, vendored into a target repository the
// way a real target would: exact pack bytes copied from the kernel release.
export function kernelSelectablePack(packId) {
  const bytes = readFileSync(new URL(`../packs/${packId}.json`, import.meta.url), "utf8");
  return JSON.parse(bytes);
}

// A complete evaluatable target repository: base commit carrying the profile,
// target packs, and any prior-art / mechanism-registry authority documents,
// plus a contract factory bound to that base.
export function buildTargetRepo(options = {}) {
  const {
    scope = { allowed: ["src/"], readonly: ["docs/"], forbidden: ["policy/"] },
    targetPacks = [defaultTeamPack()],
    validationCommands = [
      { commandId: "noop-check", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.exit(0)"] }
    ],
    extraBaseFiles = {},
    profileOverrides = {},
    capabilityIndex = null,
    priorArtQuery = null,
    mechanismRegistry = null
  } = options;

  const repoDir = makeGitRepo();
  writeRepoFile(repoDir, "src/app.mjs", "export const app = 1;\n");
  writeRepoFile(repoDir, "docs/readme.md", "readme\n");
  for (const [path, content] of Object.entries(extraBaseFiles)) {
    writeRepoFile(repoDir, path, content);
  }
  const packSelections = targetPacks.map((value) => {
    const bytes = `${JSON.stringify(value)}\n`;
    const path = `policy/${value.packId}.json`;
    writeRepoFile(repoDir, path, bytes);
    return { packId: value.packId, version: value.version, path, digest: digestOfBytes(Buffer.from(bytes, "utf8")) };
  });
  const authorityRef = (doc, path) => {
    if (doc === null) return null;
    const bytes = `${JSON.stringify(doc)}\n`;
    writeRepoFile(repoDir, path, bytes);
    return { path, digest: digestOfBytes(Buffer.from(bytes, "utf8")) };
  };
  const capabilityIndexRef = authorityRef(capabilityIndex, "policy/capability-index.json");
  const priorArtQueryRef = authorityRef(priorArtQuery, "policy/prior-art-query.json");
  const mechanismRegistryRef = authorityRef(mechanismRegistry, "policy/mechanism-registry.json");

  const profile = makeProfile(packSelections, profileOverrides);
  const profileBytes = `${JSON.stringify(profile)}\n`;
  writeRepoFile(repoDir, "policy/profile.json", profileBytes);
  const baseCommit = commitAll(repoDir, "base with policy");

  const contractFor = (candidateId, overrides = {}) =>
    makeContract({
      target: { repositoryId: "example-repo", baseCommit, candidate: { kind: "COMMIT", id: candidateId } },
      scope,
      validationCommands,
      policyProfile: {
        profileId: profile.profileId,
        path: "policy/profile.json",
        digest: digestOfBytes(Buffer.from(profileBytes, "utf8"))
      },
      capabilityIndex: capabilityIndexRef,
      priorArtQuery: priorArtQueryRef,
      mechanismRegistry: mechanismRegistryRef,
      ...overrides
    });

  return { repoDir, baseCommit, profile, contractFor };
}

export function contractBytesOf(contract) {
  return Buffer.from(`${JSON.stringify(contract)}\n`, "utf8");
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
