import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { evaluateSupervised } from "../src/supervisor.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-supervisor-"));

function target() {
  const t = buildTargetRepo();
  writeRepoFile(t.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(t.repoDir, "feature");
  return { repoDir: t.repoDir, contractBytes: contractBytesOf(t.contractFor(candidate)) };
}

test("a genuine supervised evaluation completes and is PROMOTABLE", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  const r = evaluateSupervised({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 600 });
  assert.equal(r.timedOut, false);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.disposition, "PROMOTABLE", JSON.stringify(r.reasonCodes));
  assert.ok(existsSync(join(dir, "receipt.json")));
});

test("a runaway synchronous builtin/stall cannot exceed the hard ceiling or pass", () => {
  // An 8s synchronous stall ignores the cooperative per-command deadline; the
  // OUTER supervisor hard-kills at the 1s whole-evaluation ceiling.
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  const started = performance.now();
  const r = evaluateSupervised({
    repoDir,
    contractBytes,
    outDir: dir,
    maxRuntimeSeconds: 1,
    workerEnv: { SHEDU_TEST_STALL_MS: "8000" }
  });
  const elapsedMs = performance.now() - started;
  assert.equal(r.timedOut, true);
  assert.equal(r.disposition, "BLOCKED");
  assert.deepEqual(r.reasonCodes, ["DEADLINE_EXCEEDED"]);
  // Narrow, defensible tolerance: the hard kill lands near 1s, not the 8s the
  // stall wanted.
  assert.ok(elapsedMs < 1400, `supervised evaluation ran ${Math.round(elapsedMs)}ms; hard ceiling not enforced`);
  // A killed worker leaves no promotable receipt.
  assert.equal(existsSync(join(dir, "receipt.json")), false);
});

test("slow evidence/finalization work is inside the supervised bound", () => {
  // The stall placed after the ceiling still cannot escape: the whole worker
  // (including finalization) is bounded.
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  const started = performance.now();
  const r = evaluateSupervised({
    repoDir,
    contractBytes,
    outDir: dir,
    maxRuntimeSeconds: 1,
    workerEnv: { SHEDU_TEST_STALL_MS: "6000" }
  });
  const elapsedMs = performance.now() - started;
  assert.equal(r.timedOut, true);
  assert.ok(elapsedMs < 1400);
});
