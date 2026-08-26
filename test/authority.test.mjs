import assert from "node:assert/strict";
import { symlinkSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { digestOfBytes } from "../src/canonical-json.mjs";
import { loadAuthorityDocument, readAuthorityBlob, verifyImmutableCommit } from "../src/authority.mjs";
import { commitAll, makeGitRepo, makePack, pinPacks, writeRepoFile } from "./fixtures.mjs";

function repoWithPack() {
  const repoDir = makeGitRepo();
  const pack = makePack();
  const packBytes = `${JSON.stringify(pack, null, 2)}\n`;
  writeRepoFile(repoDir, "policy/example-pack.json", packBytes);
  const baseCommit = commitAll(repoDir, "base");
  return { repoDir, pack, packBytes, baseCommit, packDigest: digestOfBytes(Buffer.from(packBytes, "utf8")) };
}

test("moving refs are rejected as authority identity", () => {
  const { repoDir, baseCommit } = repoWithPack();
  for (const ref of ["main", "HEAD", baseCommit.slice(0, 12), "refs/heads/main"]) {
    const result = verifyImmutableCommit(repoDir, ref);
    assert.equal(result.ok, false, ref);
    assert.equal(result.reasonCode, "MOVING_REF_REJECTED");
  }
  assert.equal(verifyImmutableCommit(repoDir, baseCommit).ok, true);
});

test("an absent commit fails closed", () => {
  const { repoDir } = repoWithPack();
  const result = verifyImmutableCommit(repoDir, "c".repeat(40));
  assert.equal(result.ok, false);
  assert.equal(result.reasonCode, "AUTHORITY_OBJECT_MISSING");
});

test("authority documents load with matching digest and reject drift", () => {
  const { repoDir, baseCommit, packDigest } = repoWithPack();
  const loaded = loadAuthorityDocument({
    repoDir,
    baseCommit,
    path: "policy/example-pack.json",
    expectedDigest: packDigest,
    kind: "policy-pack@1"
  });
  assert.equal(loaded.ok, true);
  assert.equal(loaded.value.packId, "example-pack");

  const drift = loadAuthorityDocument({
    repoDir,
    baseCommit,
    path: "policy/example-pack.json",
    expectedDigest: `sha256:${"d".repeat(64)}`,
    kind: "policy-pack@1"
  });
  assert.equal(drift.ok, false);
  assert.equal(drift.reasonCode, "AUTHORITY_DIGEST_MISMATCH");
});

test("candidate commits cannot change the authority used for the run", () => {
  const { repoDir, baseCommit, packDigest } = repoWithPack();
  // A later "candidate" commit rewrites the pack to allow everything.
  const weakened = pinPacks([makePack({ description: "weakened by the candidate" })])[0];
  writeRepoFile(repoDir, "policy/example-pack.json", `${JSON.stringify(weakened.value, null, 2)}\n`);
  commitAll(repoDir, "candidate tampers with policy");

  const loaded = loadAuthorityDocument({
    repoDir,
    baseCommit,
    path: "policy/example-pack.json",
    expectedDigest: packDigest,
    kind: "policy-pack@1"
  });
  assert.equal(loaded.ok, true);
  assert.equal(loaded.value.description, "Example pack");
});

test("missing paths, escaping paths, and symlinks fail closed", () => {
  const { repoDir, baseCommit } = repoWithPack();
  writeRepoFile(repoDir, "outside-target.json", "{}\n");
  symlinkSync("outside-target.json", join(repoDir, "sneaky-link.json"));
  const linkedCommit = commitAll(repoDir, "adds symlink");

  const missing = readAuthorityBlob(repoDir, baseCommit, "policy/nope.json");
  assert.equal(missing.reasonCode, "AUTHORITY_OBJECT_MISSING");

  const escaping = readAuthorityBlob(repoDir, baseCommit, "../etc/passwd");
  assert.equal(escaping.reasonCode, "PATH_NOT_CONTAINED");

  const symlinked = readAuthorityBlob(repoDir, linkedCommit, "sneaky-link.json");
  assert.equal(symlinked.ok, false);
  assert.equal(symlinked.reasonCode, "AUTHORITY_PATH_NOT_BLOB");

  const directory = readAuthorityBlob(repoDir, baseCommit, "policy");
  assert.equal(directory.ok, false);
  assert.equal(directory.reasonCode, "AUTHORITY_PATH_NOT_BLOB");
});

test("a schema-invalid authority document is rejected with its errors", () => {
  const repoDir = makeGitRepo();
  writeRepoFile(repoDir, "policy/bad.json", '{"schemaVersion":"policy-pack@1","unknown":true}\n');
  const commit = commitAll(repoDir, "bad pack");
  const result = loadAuthorityDocument({ repoDir, baseCommit: commit, path: "policy/bad.json", kind: "policy-pack@1" });
  assert.equal(result.ok, false);
  assert.equal(result.reasonCode, "SCHEMA_VIOLATION");
  assert.ok(result.errors.length > 0);
});
