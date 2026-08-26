import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createEvidenceIndex, verifyEvidenceDir } from "../src/evidence.mjs";
import { COMMIT_A, COMMIT_B, ZERO_DIGEST } from "./fixtures.mjs";

const BINDING = {
  repositoryId: "example-repo",
  baseCommit: COMMIT_A,
  candidateId: COMMIT_B,
  workContract: ZERO_DIGEST,
  profile: ZERO_DIGEST,
  packs: [{ packId: "example-pack", version: "1.0.0", digest: ZERO_DIGEST }],
  compiledPlan: ZERO_DIGEST
};

function makeIndex() {
  const rootDir = mkdtempSync(join(tmpdir(), "shedu-evidence-"));
  return { rootDir, index: createEvidenceIndex({ rootDir, binding: BINDING }) };
}

test("artifacts are content-addressed, bound, and verify offline", () => {
  const { rootDir, index } = makeIndex();
  const a = index.put({
    artifactId: "report-alpha",
    checkId: "example-check",
    validatorId: "scope-boundary-classify@1",
    bytes: Buffer.from('{"ok":true}', "utf8")
  });
  assert.match(a.digest, /^sha256:[0-9a-f]{64}$/);
  const finalized = index.finalize();
  assert.equal(finalized.index.binding.compiledPlan, ZERO_DIGEST);

  const verified = verifyEvidenceDir(rootDir);
  assert.equal(verified.ok, true, JSON.stringify(verified.errors));
  rmSync(rootDir, { recursive: true, force: true });
});

test("duplicate artifact ids and post-finalize writes are refused", () => {
  const { rootDir, index } = makeIndex();
  index.put({ artifactId: "one", checkId: "example-check", validatorId: "scope-boundary-classify@1", bytes: Buffer.from("a") });
  assert.throws(
    () => index.put({ artifactId: "one", checkId: "example-check", validatorId: "scope-boundary-classify@1", bytes: Buffer.from("b") }),
    /already indexed/
  );
  index.finalize();
  assert.throws(
    () => index.put({ artifactId: "two", checkId: "example-check", validatorId: "scope-boundary-classify@1", bytes: Buffer.from("c") }),
    /finalized/
  );
  rmSync(rootDir, { recursive: true, force: true });
});

test("mutation, omission, and smuggled objects fail offline verification", () => {
  const { rootDir, index } = makeIndex();
  const a = index.put({
    artifactId: "report-alpha",
    checkId: "example-check",
    validatorId: "scope-boundary-classify@1",
    bytes: Buffer.from("original evidence", "utf8"),
    mediaType: "text/plain"
  });
  index.finalize();
  const objectPath = join(rootDir, "objects", "sha256", a.digest.slice("sha256:".length));

  writeFileSync(objectPath, "tampered evidence!!");
  const mutated = verifyEvidenceDir(rootDir);
  assert.equal(mutated.ok, false);
  assert.ok(mutated.errors.some((e) => e.reasonCode === "EVIDENCE_MUTATED"));

  rmSync(objectPath);
  const missing = verifyEvidenceDir(rootDir);
  assert.equal(missing.ok, false);
  assert.ok(missing.errors.some((e) => e.reasonCode === "EVIDENCE_MISSING"));

  writeFileSync(objectPath, "original evidence");
  writeFileSync(join(rootDir, "objects", "sha256", "f".repeat(64)), "smuggled");
  const smuggled = verifyEvidenceDir(rootDir);
  assert.equal(smuggled.ok, false);
  assert.ok(smuggled.errors.some((e) => e.message.includes("undeclared object")));
  rmSync(rootDir, { recursive: true, force: true });
});
