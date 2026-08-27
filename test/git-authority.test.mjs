import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import { git, gitAuthorityIdentity, resetGitAuthority } from "../src/git-authority.mjs";
import { verifyFrozenSource } from "../src/admission.mjs";
import { readAuthorityBlob, verifyImmutableCommit } from "../src/authority.mjs";
import { materializeWorktree } from "../src/workspace.mjs";
import { commitAll, makeGitRepo, writeRepoFile } from "./fixtures.mjs";

// A fake `git` that reports an invented clean commit and pretends any status
// is clean. If the kernel resolved git through PATH, this would poison every
// git operation.
function poisonPath() {
  const dir = mkdtempSync(join(tmpdir(), "shedu-fakegit-"));
  const fake = join(dir, "git");
  writeFileSync(
    fake,
    "#!/bin/sh\ncase \"$*\" in\n  *rev-parse*HEAD*) echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef ;;\n  *status*) echo '' ;;\n  *) echo INVENTED ;;\nesac\nexit 0\n"
  );
  chmodSync(fake, 0o755);
  return { dir, original: process.env.PATH };
}

test("the git authority resolves an absolute executable and ignores a poisoned PATH", () => {
  const repo = makeGitRepo();
  writeRepoFile(repo, "src/app.mjs", "1\n");
  const commit = commitAll(repo, "base");

  const { dir, original } = poisonPath();
  process.env.PATH = `${dir}:${original}`;
  try {
    resetGitAuthority();
    // The authority binds an absolute path + digest, never the fake on PATH.
    const id = gitAuthorityIdentity();
    assert.ok(id.path.startsWith("/") && !id.path.includes("shedu-fakegit"), id.path);

    // verifyFrozenSource returns the REAL commit and clean state, not the
    // fake's invented "deadbeef" commit.
    const source = verifyFrozenSource(repo, commit);
    assert.equal(source.ok, true);
    assert.equal(source.commit, commit);
    assert.notEqual(source.commit, "deadbeef".repeat(5));

    // A real version query goes to the real git.
    const v = git(["--version"]);
    assert.equal(v.status, 0);
    assert.match(v.stdout, /git version/);
  } finally {
    process.env.PATH = original;
    resetGitAuthority();
  }
});

test("authority reads and candidate identity ignore the fake git", () => {
  const repo = makeGitRepo();
  writeRepoFile(repo, "policy/x.json", '{"ok":true}\n');
  const commit = commitAll(repo, "base");

  const { dir, original } = poisonPath();
  process.env.PATH = `${dir}:${original}`;
  try {
    resetGitAuthority();
    // A real blob read succeeds against the real object store.
    const blob = readAuthorityBlob(repo, commit, "policy/x.json");
    assert.equal(blob.ok, true);
    assert.match(blob.bytes.toString(), /"ok":true/);
    // Immutable commit verification resolves the real commit.
    assert.equal(verifyImmutableCommit(repo, commit).ok, true);
    // Worktree materialization uses the real git.
    const wt = materializeWorktree(repo, commit);
    try {
      assert.ok(wt.dir.length > 0);
    } finally {
      wt.cleanup();
    }
  } finally {
    process.env.PATH = original;
    resetGitAuthority();
  }
});

test("verifyFrozenSource against a nonexistent repository fails closed", () => {
  const missing = join(tmpdir(), `shedu-nonexistent-${Date.now()}`);
  const source = verifyFrozenSource(missing, null);
  assert.equal(source.ok, false);
  assert.equal(source.clean, false);
});
