import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { evaluateSupervised } from "../src/supervisor.mjs";
import { generateSigningKeyPem } from "../src/receipt.mjs";
import { verifyReceipt } from "../src/receipt.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-supervisor-"));

function target() {
  const t = buildTargetRepo();
  writeRepoFile(t.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(t.repoDir, "feature");
  return { repoDir: t.repoDir, contractBytes: contractBytesOf(t.contractFor(candidate)) };
}

const PROMOTABLE_PRESEED = JSON.stringify({ schemaVersion: "promotion-receipt@1", disposition: "PROMOTABLE", preseeded: true });

test("a genuine supervised evaluation publishes one internally consistent digest-bound bundle", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  const r = evaluateSupervised({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 600 });
  assert.equal(r.timedOut, false);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.disposition, "PROMOTABLE", JSON.stringify(r.reasonCodes));
  // The published bundle exists and its members match the summary digests.
  assert.ok(existsSync(join(dir, "receipt.json")));
  assert.ok(existsSync(join(dir, "plan.json")));
  assert.ok(existsSync(join(dir, "artifacts", "evidence", "index.json")));
  const verification = verifyReceipt({
    receiptBytes: readFileSync(join(dir, "receipt.json")),
    planBytes: readFileSync(join(dir, "plan.json")),
    evidenceDir: join(dir, "artifacts", "evidence")
  });
  assert.equal(verification.ok, true, JSON.stringify(verification.errors));
});

test("signing happens inside the supervised boundary", () => {
  const { repoDir, contractBytes } = target();
  const keyPath = join(mkdtempSync(join(tmpdir(), "shedu-key-")), "key.pem");
  writeFileSync(keyPath, generateSigningKeyPem());
  const dir = outDir();
  const r = evaluateSupervised({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 600, signKeyPath: keyPath });
  assert.equal(r.ok, true, JSON.stringify(r));
  const receipt = JSON.parse(readFileSync(join(dir, "receipt.json"), "utf8"));
  assert.equal(receipt.signing?.algorithm, "ed25519");
  const verification = verifyReceipt({
    receiptBytes: readFileSync(join(dir, "receipt.json")),
    planBytes: readFileSync(join(dir, "plan.json")),
    expectedPublicKey: receipt.signing.publicKey
  });
  assert.equal(verification.ok, true, JSON.stringify(verification.errors));
});

test("preseeding a PROMOTABLE receipt then running an invalid evaluation leaves no promotable receipt", () => {
  const { repoDir } = target();
  const dir = outDir();
  writeFileSync(join(dir, "receipt.json"), PROMOTABLE_PRESEED);
  // An invalid contract → the worker's evaluation fails → nothing published,
  // and the preseeded receipt is purged.
  const r = evaluateSupervised({ repoDir, contractBytes: Buffer.from('{"schemaVersion":"work-contract@1"}'), outDir: dir, maxRuntimeSeconds: 60 });
  assert.equal(r.ok, false);
  assert.equal(existsSync(join(dir, "receipt.json")), false, "no promotable receipt may remain");
});

test("a runaway synchronous stall is hard-killed at the ceiling with no published receipt", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  writeFileSync(join(dir, "receipt.json"), PROMOTABLE_PRESEED);
  const started = performance.now();
  const r = evaluateSupervised({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 1, workerEnv: { SHEDU_TEST_STALL_MS: "8000" } });
  const elapsedMs = performance.now() - started;
  assert.equal(r.timedOut, true);
  assert.deepEqual(r.reasonCodes, ["DEADLINE_EXCEEDED"]);
  assert.ok(elapsedMs < 1600, `ran ${Math.round(elapsedMs)}ms`);
  assert.equal(existsSync(join(dir, "receipt.json")), false, "the preseeded receipt must be purged");
});

test("a kill after receipt construction but before summary publication publishes nothing", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  writeFileSync(join(dir, "receipt.json"), PROMOTABLE_PRESEED);
  // The worker constructs the receipt, then stalls 8s BEFORE writing the
  // summary; the 1s ceiling kills it → no summary → nothing published.
  const r = evaluateSupervised({
    repoDir,
    contractBytes,
    outDir: dir,
    maxRuntimeSeconds: 1,
    workerEnv: { SHEDU_TEST_STALL_AFTER_RECEIPT_MS: "8000" }
  });
  assert.equal(r.timedOut, true);
  assert.equal(existsSync(join(dir, "receipt.json")), false);
  assert.equal(existsSync(join(dir, "supervised-result.json")), false);
});

test("a signing failure inside the boundary publishes nothing", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  writeFileSync(join(dir, "receipt.json"), PROMOTABLE_PRESEED);
  // A signing key path that is a DIRECTORY (not a regular file) is refused by
  // the bounded key read; the worker reports failure → nothing published.
  const r = evaluateSupervised({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 60, signKeyPath: dir });
  assert.equal(r.ok, false);
  assert.equal(existsSync(join(dir, "receipt.json")), false);
});
