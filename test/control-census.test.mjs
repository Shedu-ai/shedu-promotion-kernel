import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, writeFileSync, appendFileSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import { discoverControlPoints, runControlCensus } from "../src/control-census.mjs";
import { createControlLedger, ControlLedgerError } from "../src/control-runtime.mjs";
import { CONTROL_PROOFS } from "../src/control-proofs.mjs";
import { runArchitectureFence } from "../src/architecture-fence.mjs";
import { isAdmitted } from "../src/admission.mjs";
import { validateDocument } from "../src/contracts.mjs";
import { isolateExecution } from "../src/sandbox.mjs";

const SRC = new URL("../src", import.meta.url).pathname;

function loadRegistry() {
  const doc = validateDocument("control-surface@1", readFileSync(new URL("../registry/control-surface.json", import.meta.url)));
  assert.equal(doc.ok, true, JSON.stringify(doc.errors ?? []));
  return doc.value;
}

test("a genuine run produces a closed control ledger with zero exclusions", () => {
  const report = runControlCensus({ srcDir: SRC, registry: loadRegistry() });
  assert.equal(report.complete, true, JSON.stringify(report.findings, null, 2));
  assert.equal(report.registered.length, report.discovered.length);
  assert.equal(report.proven.length, report.registered.length);
  // Infrastructure controls the policy-plan census cannot see are present.
  for (const id of ["sandbox-network-isolation", "evaluation-deadline", "evaluation-supervisor", "conformance-status-admission", "architecture-fence", "toolchain-authority"]) {
    assert.ok(report.registered.includes(id), id);
    assert.ok(report.proven.includes(id), `${id} must be proven by execution`);
  }
});

test("a runtime control invoked without registration is refused by the ledger", () => {
  const ledger = createControlLedger(["a", "b"]);
  ledger.record({ controlId: "a", invocation: "x", outcome: "PASS" });
  assert.throws(
    () => ledger.record({ controlId: "rogue-control", invocation: "x", outcome: "PASS" }),
    (e) => e instanceof ControlLedgerError && e.reasonCode === "CONTROL_UNREGISTERED"
  );
});

test("a registered control whose runtime proof fails fails closure (not a string title)", () => {
  // Override the sandbox-network proof to REPORT failure — as if a denial had
  // been removed. Closure must fail; a passing title does nothing.
  const proofs = { ...CONTROL_PROOFS, "sandbox-network-isolation": () => ({ passed: false, detail: "denial removed" }) };
  const report = runControlCensus({ srcDir: SRC, registry: loadRegistry(), proofs });
  assert.equal(report.complete, false);
  assert.ok(report.findings.some((f) => f.id === "sandbox-network-isolation" && f.reasonCode === "CONTROL_UNPROVEN"));
});

test("removing sandbox isolation makes a bind succeed — the runtime proof would catch it", () => {
  // The real proof asserts EPERM on a sandboxed bind. If isolation were
  // weakened (e.g. the profile reverted to allow-by-default), the bind would
  // SUCCEED and the proof's EPERM assertion would fail — which is exactly the
  // signal the census consumes. Demonstrate the weakened profile directly.
  const NODE = realpathSync(process.execPath);
  const weakened = "(version 1)(allow default)(deny process-fork)";
  const bind = spawnSync(
    "sandbox-exec",
    ["-p", weakened, NODE, "-e", 'const s=require("node:net").createServer();s.on("error",()=>process.exit(1));s.listen(0,()=>process.exit(0));setTimeout(()=>process.exit(2),3000)'],
    { encoding: "utf8", env: { PATH: process.env.PATH }, timeout: 10000 }
  );
  assert.equal(bind.status, 0, "a weakened (allow default) profile must let a bind succeed");
  // The real proof passes only WITH the enforced default-deny profile.
  assert.equal(CONTROL_PROOFS["sandbox-network-isolation"]().passed, true);
});

test("a registered control absent from source (implementation) fails closure", () => {
  const reg = loadRegistry();
  reg.controls.push({ id: "phantom-control", kind: "verification", definedIn: "src/sandbox.mjs", dispositionEffect: true });
  const report = runControlCensus({ srcDir: SRC, registry: reg });
  assert.equal(report.complete, false);
  assert.ok(report.findings.some((f) => f.id === "phantom-control" && f.reasonCode === "CONTROL_UNIMPLEMENTED"));
});

test("a planted unregistered control (exported in source) is detected", () => {
  const tmpSrc = mkdtempSync(join(tmpdir(), "shedu-src-"));
  cpSync(SRC, tmpSrc, { recursive: true });
  writeFileSync(join(tmpSrc, "rogue-control.mjs"), 'export const CONTROL_POINTS = Object.freeze(["planted-rogue-control"]);\n');
  const report = runControlCensus({ srcDir: tmpSrc, registry: loadRegistry() });
  assert.equal(report.complete, false);
  assert.ok(report.findings.some((f) => f.id === "planted-rogue-control" && f.reasonCode === "CONTROL_UNREGISTERED"));
});

test("the architecture fence forbids constructing admitted/promotable outcomes outside their modules", () => {
  // Baseline: the real source passes the fence.
  assert.equal(runArchitectureFence(SRC).ok, true);

  // The EXACT reproduced bypass: replace the CLI admission assignment with an
  // unconditional admitted outcome in a copied tree.
  const tmpSrc = mkdtempSync(join(tmpdir(), "shedu-src-fence-"));
  cpSync(SRC, tmpSrc, { recursive: true });
  appendFileSync(join(tmpSrc, "cli.mjs"), '\nconst bypass = { admitted: true, status: "EXPERIMENTAL" };\n');
  const fence = runArchitectureFence(tmpSrc);
  assert.equal(fence.ok, false);
  assert.ok(fence.violations.some((v) => v.file === "src/cli.mjs"));

  // Runtime backstop: even if the fence were bypassed, a forged unbranded
  // admission object is not honored.
  assert.equal(isAdmitted({ admitted: true, status: "EXPERIMENTAL" }), false);
});

test("the census consumes a genuine production trace and fails if a productionObservable control is unobserved", async () => {
  const { evaluateCandidate } = await import("../src/evaluate.mjs");
  const { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } = await import("./fixtures.mjs");
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");

  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const f = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: mkdtempSync(join(tmpdir(), "shedu-census-trace-"))
  });
  const trace = outcome.receipt.controlTrace.map((e) => e.controlId);

  // With the genuine trace, every productionObservable control is observed.
  const ok = runControlCensus({ srcDir: SRC, registry: loadRegistry(), productionTrace: trace });
  assert.equal(ok.complete, true, JSON.stringify(ok.findings, null, 2));
  assert.ok(ok.productionObserved.includes("disposition-reduction"));
  assert.ok(ok.productionObserved.includes("sandbox-network-isolation"));

  // Dropping a productionObservable control from the trace fails closure —
  // a standalone proof cannot substitute for real production observation.
  const missing = trace.filter((id) => id !== "disposition-reduction");
  const bad = runControlCensus({ srcDir: SRC, registry: loadRegistry(), productionTrace: missing });
  assert.equal(bad.complete, false);
  assert.ok(bad.findings.some((f) => f.id === "disposition-reduction" && f.reasonCode === "CONTROL_UNOBSERVED"));
});

test("discovery reads the filesystem independently of the registry", () => {
  const discovered = discoverControlPoints(SRC);
  assert.equal(discovered.get("sandbox-network-isolation"), "src/sandbox.mjs");
  assert.equal(discovered.get("evaluation-supervisor"), "src/supervisor.mjs");
  assert.equal(discovered.get("architecture-fence"), "src/architecture-fence.mjs");
});
