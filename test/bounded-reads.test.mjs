import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { committedAdmission, isAdmitted } from "../src/admission.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

function mkfifo(path) {
  const r = spawnSync("mkfifo", [path], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`mkfifo failed: ${r.stderr}`);
}

// Finding 4 remediation (bounded reads). A FIFO/oversized attestation path is
// REFUSED by a stat-gated bounded read rather than opened — so it cannot block
// the caller. committedAdmission returns FOUNDATION_ONLY promptly.
test("a FIFO attestation path is refused by the bounded read and does not hang admission", () => {
  const dir = mkdtempSync(join(tmpdir(), "shedu-fifo-att-"));
  const fifo = join(dir, "attestation.fifo");
  mkfifo(fifo);
  const started = performance.now();
  const admission = committedAdmission({ attestationPath: fifo, pinnedKey: "a".repeat(64), expectedCommit: "b".repeat(40) });
  const elapsedMs = performance.now() - started;
  assert.equal(isAdmitted(admission), false);
  assert.equal(admission.status, "FOUNDATION_ONLY");
  assert.ok(elapsedMs < 2000, `admission took ${Math.round(elapsedMs)}ms — a bounded read must not block on a FIFO`);
});

// The CLI's contract read is likewise bounded: a FIFO contract is refused
// before the supervised timer, so the whole-operation path cannot hang there.
test("a FIFO contract path is refused by the CLI's bounded read", () => {
  const kernelRoot = new URL("..", import.meta.url).pathname;
  const dir = mkdtempSync(join(tmpdir(), "shedu-fifo-contract-"));
  const fifo = join(dir, "contract.fifo");
  mkfifo(fifo);
  const out = mkdtempSync(join(tmpdir(), "shedu-out-"));
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const f = 2;\n");
  commitAll(target.repoDir, "feature");

  const started = performance.now();
  const run = spawnSync(
    process.execPath,
    [join(kernelRoot, "src", "cli.mjs"), "evaluate", "--contract", fifo, "--repo", target.repoDir, "--out", out],
    { encoding: "utf8", env: { PATH: process.env.PATH }, timeout: 10000 }
  );
  const elapsedMs = performance.now() - started;
  assert.equal(run.status, 2, run.stdout);
  assert.equal(JSON.parse(run.stderr).reasonCode, "AUTHORITY_OBJECT_MISSING");
  assert.ok(elapsedMs < 5000, `CLI took ${Math.round(elapsedMs)}ms — the bounded contract read must not block`);
});

// A regular contract that is silently unrelated to a FIFO still works — the
// bound is on file KIND/size, not on legitimate contracts.
test("a bounded regular contract is accepted (the bound does not reject legitimate files)", () => {
  const dir = mkdtempSync(join(tmpdir(), "shedu-ok-contract-"));
  const path = join(dir, "contract.json");
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const f = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  writeFileSync(path, contractBytesOf(target.contractFor(candidate)));
  const out = mkdtempSync(join(tmpdir(), "shedu-out-"));
  const kernelRoot = new URL("..", import.meta.url).pathname;
  // FOUNDATION_ONLY dev tree → NOT_ADMITTED, but the contract read itself
  // succeeded (the failure is admission, not AUTHORITY_OBJECT_MISSING).
  const run = spawnSync(
    process.execPath,
    [join(kernelRoot, "src", "cli.mjs"), "evaluate", "--contract", path, "--repo", target.repoDir, "--out", out],
    { encoding: "utf8", env: { PATH: process.env.PATH }, timeout: 20000 }
  );
  assert.equal(run.status, 2);
  assert.equal(JSON.parse(run.stderr).reasonCode, "NOT_ADMITTED");
});
