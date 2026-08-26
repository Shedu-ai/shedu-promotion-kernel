import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  candidateIdentityVerify,
  candidateTreeStability
} from "../src/validators/candidate-identity.mjs";
import { classifyPath, scopeBoundaryClassify } from "../src/validators/scope-boundary.mjs";
import { materializeWorktree } from "../src/workspace.mjs";
import { commitAll, commitPlumbed, makeContract, makeGitRepo, writeRepoFile } from "./fixtures.mjs";

const SCOPE = { allowed: ["src/"], readonly: ["docs/"], forbidden: ["policy/", "src/secrets/"] };

function makeTargetRepo() {
  const repoDir = makeGitRepo();
  writeRepoFile(repoDir, "src/app.mjs", "export const app = 1;\n");
  writeRepoFile(repoDir, "docs/readme.md", "readme\n");
  writeRepoFile(repoDir, "policy/profile.json", "{}\n");
  const baseCommit = commitAll(repoDir, "base");
  return { repoDir, baseCommit };
}

function contractFor(repoDir, baseCommit, candidateId, scope = SCOPE) {
  return makeContract({
    target: { repositoryId: "example-repo", baseCommit, candidate: { kind: "COMMIT", id: candidateId } },
    scope
  });
}

test("candidate identity passes for a clean descendant candidate", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  writeRepoFile(repoDir, "src/feature.mjs", "export const f = 2;\n");
  const candidate = commitAll(repoDir, "feature");
  const worktree = materializeWorktree(repoDir, candidate);
  try {
    const result = candidateIdentityVerify({
      repoDir,
      workContract: contractFor(repoDir, baseCommit, candidate),
      candidateDir: worktree.dir
    });
    assert.equal(result.outcome, "PASS", JSON.stringify(result));
  } finally {
    worktree.cleanup();
  }
});

test("a non-descendant candidate FIREs", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  const orphan = commitPlumbed(repoDir, [{ path: "src/orphan.mjs", content: "1\n" }], "orphan", { parents: [] });
  const result = candidateIdentityVerify({
    repoDir,
    workContract: contractFor(repoDir, baseCommit, orphan),
    candidateDir: null
  });
  assert.equal(result.outcome, "FIRED");
  assert.ok(result.reasonCodes.includes("CANDIDATE_NOT_DESCENDANT"));
});

test("a dirty candidate materialization FIREs", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  writeRepoFile(repoDir, "src/feature.mjs", "clean\n");
  const candidate = commitAll(repoDir, "feature");
  const worktree = materializeWorktree(repoDir, candidate);
  try {
    writeFileSync(join(worktree.dir, "src", "feature.mjs"), "tampered\n");
    const result = candidateIdentityVerify({
      repoDir,
      workContract: contractFor(repoDir, baseCommit, candidate),
      candidateDir: worktree.dir
    });
    assert.equal(result.outcome, "FIRED");
    assert.ok(result.reasonCodes.includes("WORKSPACE_DIRTY"));
  } finally {
    worktree.cleanup();
  }
});

test("a missing base or candidate FIREs with authority reasons", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  const missing = candidateIdentityVerify({
    repoDir,
    workContract: contractFor(repoDir, baseCommit, "c".repeat(40)),
    candidateDir: null
  });
  assert.equal(missing.outcome, "FIRED");
  assert.ok(missing.reasonCodes.includes("AUTHORITY_OBJECT_MISSING"));
});

test("post-validation mutation FIREs tree stability", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  writeRepoFile(repoDir, "src/feature.mjs", "clean\n");
  const candidate = commitAll(repoDir, "feature");
  const contract = contractFor(repoDir, baseCommit, candidate);
  const worktree = materializeWorktree(repoDir, candidate);
  try {
    const before = candidateTreeStability({ repoDir, workContract: contract, candidateDir: worktree.dir });
    assert.equal(before.outcome, "PASS");
    writeFileSync(join(worktree.dir, "src", "feature.mjs"), "mutated after validation\n");
    const after = candidateTreeStability({ repoDir, workContract: contract, candidateDir: worktree.dir });
    assert.equal(after.outcome, "FIRED");
    assert.ok(after.reasonCodes.includes("CANDIDATE_TREE_UNSTABLE"));
  } finally {
    worktree.cleanup();
  }
});

test("scope classification precedence: longest entry wins", () => {
  assert.equal(classifyPath("src/app.mjs", SCOPE), "ALLOWED");
  assert.equal(classifyPath("src/secrets/key.txt", SCOPE), "FORBIDDEN");
  assert.equal(classifyPath("docs/readme.md", SCOPE), "READONLY");
  assert.equal(classifyPath("rogue.txt", SCOPE), "UNCLASSIFIED");
  assert.equal(classifyPath("src", SCOPE), "UNCLASSIFIED");
});

test("an in-scope change passes and yields changed-file attribution", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  writeRepoFile(repoDir, "src/feature.mjs", "new file\n");
  writeRepoFile(repoDir, "src/app.mjs", "export const app = 2;\n");
  const candidate = commitAll(repoDir, "feature");
  const result = scopeBoundaryClassify({
    repoDir,
    workContract: contractFor(repoDir, baseCommit, candidate)
  });
  assert.equal(result.outcome, "PASS", JSON.stringify(result));
  assert.deepEqual(result.details.changedFiles, [
    { path: "src/app.mjs", changeKind: "MODIFIED", scopeClass: "ALLOWED" },
    { path: "src/feature.mjs", changeKind: "ADDED", scopeClass: "ALLOWED" }
  ]);
});

test("forbidden, readonly, and unclassified changes FIRE", () => {
  const cases = [
    ["policy/profile.json", "SCOPE_FORBIDDEN_CHANGE"],
    ["docs/readme.md", "SCOPE_READONLY_CHANGE"],
    ["rogue.txt", "SCOPE_UNCLASSIFIED_CHANGE"],
    ["src/secrets/key.txt", "SCOPE_FORBIDDEN_CHANGE"]
  ];
  for (const [path, reason] of cases) {
    const { repoDir, baseCommit } = makeTargetRepo();
    writeRepoFile(repoDir, path, "changed\n");
    const candidate = commitAll(repoDir, "hostile");
    const result = scopeBoundaryClassify({
      repoDir,
      workContract: contractFor(repoDir, baseCommit, candidate)
    });
    assert.equal(result.outcome, "FIRED", path);
    assert.ok(result.reasonCodes.includes(reason), `${path}: ${result.reasonCodes}`);
  }
});

test("deleting a readonly file FIREs", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  const candidate = commitPlumbed(repoDir, [], "delete readonly", { remove: ["docs/readme.md"] });
  const result = scopeBoundaryClassify({
    repoDir,
    workContract: contractFor(repoDir, baseCommit, candidate)
  });
  assert.equal(result.outcome, "FIRED");
  assert.ok(result.reasonCodes.includes("SCOPE_READONLY_CHANGE"));
  assert.deepEqual(result.details.changedFiles, [
    { path: "docs/readme.md", changeKind: "DELETED", scopeClass: "READONLY" }
  ]);
});

test("case-colliding candidate paths FIRE", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  const candidate = commitPlumbed(
    repoDir,
    [{ path: "src/App.mjs", content: "collides with src/app.mjs on a folding filesystem\n" }],
    "case collision"
  );
  const result = scopeBoundaryClassify({
    repoDir,
    workContract: contractFor(repoDir, baseCommit, candidate)
  });
  assert.equal(result.outcome, "FIRED");
  assert.ok(result.reasonCodes.includes("SCOPE_CASE_COLLISION"));
});

test("a symlink escaping the repository FIREs; a contained symlink does not", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  const escaping = commitPlumbed(
    repoDir,
    [{ path: "src/link.mjs", content: "../../outside/secret", mode: "120000" }],
    "escaping symlink"
  );
  const escaped = scopeBoundaryClassify({
    repoDir,
    workContract: contractFor(repoDir, baseCommit, escaping)
  });
  assert.equal(escaped.outcome, "FIRED");
  assert.ok(escaped.reasonCodes.includes("SCOPE_SYMLINK_ESCAPE"));

  const { repoDir: repo2, baseCommit: base2 } = makeTargetRepo();
  const contained = commitPlumbed(
    repo2,
    [{ path: "src/link.mjs", content: "app.mjs", mode: "120000" }],
    "contained symlink"
  );
  const ok = scopeBoundaryClassify({
    repoDir: repo2,
    workContract: contractFor(repo2, base2, contained)
  });
  assert.equal(ok.outcome, "PASS", JSON.stringify(ok.reasonCodes));
});

test("an absolute symlink target FIREs", () => {
  const { repoDir, baseCommit } = makeTargetRepo();
  const candidate = commitPlumbed(
    repoDir,
    [{ path: "src/link.mjs", content: "/etc/passwd", mode: "120000" }],
    "absolute symlink"
  );
  const result = scopeBoundaryClassify({
    repoDir,
    workContract: contractFor(repoDir, baseCommit, candidate)
  });
  assert.equal(result.outcome, "FIRED");
  assert.ok(result.reasonCodes.includes("SCOPE_SYMLINK_ESCAPE"));
});
