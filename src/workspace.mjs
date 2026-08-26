import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Workspace materialization for evaluation. Base and candidate are
// materialized as detached git worktrees so validators and target commands
// see exactly the committed tree — never a mutable checkout the candidate
// could influence mid-run.

const GIT_ENV = Object.freeze({
  // Only PATH from the host; fixed identity so tree-wrapping commits are
  // deterministic and no ambient git config leaks into evaluation.
  GIT_AUTHOR_NAME: "shedu-promotion-kernel",
  GIT_AUTHOR_EMAIL: "kernel@invalid",
  GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
  GIT_COMMITTER_NAME: "shedu-promotion-kernel",
  GIT_COMMITTER_EMAIL: "kernel@invalid",
  GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null"
});

export function gitRun(repoDir, args, { binary = false } = {}) {
  return spawnSync("git", ["-C", repoDir, ...args], {
    encoding: binary ? "buffer" : "utf8",
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
    env: { PATH: process.env.PATH, ...GIT_ENV }
  });
}

function gitOrThrow(repoDir, args) {
  const r = gitRun(repoDir, args);
  if (r.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed in ${repoDir}: ${r.stderr}`);
  }
  return r.stdout.trim();
}

// A TREE candidate has no commit to check out; wrap it in a deterministic
// parentless commit so it can be materialized. The wrapper is synthetic
// plumbing only — identity checks still bind to the tree id.
export function committishForCandidate(repoDir, candidate) {
  if (candidate.kind === "COMMIT") return candidate.id;
  return gitOrThrow(repoDir, ["commit-tree", candidate.id, "-m", "kernel-materialization"]);
}

export function materializeWorktree(repoDir, committish) {
  const dir = mkdtempSync(join(tmpdir(), "shedu-kernel-wt-"));
  const r = gitRun(repoDir, ["worktree", "add", "--detach", "--force", dir, committish]);
  if (r.status !== 0) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`cannot materialize ${committish}: ${r.stderr}`);
  }
  return {
    dir,
    cleanup() {
      gitRun(repoDir, ["worktree", "remove", "--force", dir]);
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

export function workspaceStatus(worktreeDir) {
  return gitOrThrow(worktreeDir, ["status", "--porcelain"]);
}

export function headTree(worktreeDir) {
  return gitOrThrow(worktreeDir, ["rev-parse", "HEAD^{tree}"]);
}

export function treeOf(repoDir, committishOrTree) {
  return gitOrThrow(repoDir, ["rev-parse", `${committishOrTree}^{tree}`]);
}

export function isAncestor(repoDir, ancestor, descendant) {
  const r = gitRun(repoDir, ["merge-base", "--is-ancestor", ancestor, descendant]);
  return r.status === 0;
}

const CHANGE_KINDS = { A: "ADDED", M: "MODIFIED", D: "DELETED", T: "MODIFIED", R: "RENAMED" };

// Changed paths between base and candidate, mechanically attributed. Renames
// are disabled so an old path deletion and new path addition are each
// classified against the scope sets on their own.
export function changedFilesBetween(repoDir, base, candidateCommittish) {
  const r = gitRun(repoDir, ["diff", "--name-status", "--no-renames", "-z", base, candidateCommittish]);
  if (r.status !== 0) throw new Error(`git diff failed: ${r.stderr}`);
  const parts = r.stdout.split("\0").filter((p) => p.length > 0);
  const changes = [];
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const kind = CHANGE_KINDS[parts[i][0]];
    if (!kind) throw new Error(`unsupported change status ${parts[i]}`);
    changes.push({ path: parts[i + 1], changeKind: kind });
  }
  return changes;
}

// Full candidate tree listing with modes, for case-collision and symlink
// analysis: [{mode, type, oid, path}].
export function listTree(repoDir, committishOrTree) {
  const r = gitRun(repoDir, ["ls-tree", "-r", "-z", committishOrTree]);
  if (r.status !== 0) throw new Error(`git ls-tree failed: ${r.stderr}`);
  return r.stdout
    .split("\0")
    .filter(Boolean)
    .map((entry) => {
      const tab = entry.indexOf("\t");
      const [mode, type, oid] = entry.slice(0, tab).split(" ");
      return { mode, type, oid, path: entry.slice(tab + 1) };
    });
}

export function readBlobAt(repoDir, committish, path) {
  const r = gitRun(repoDir, ["cat-file", "blob", `${committish}:${path}`], { binary: true });
  if (r.status !== 0) throw new Error(`cannot read ${committish}:${path}: ${r.stderr}`);
  return r.stdout;
}
