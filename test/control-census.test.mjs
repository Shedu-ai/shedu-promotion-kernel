import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { discoverControlPoints, runControlCensus } from "../src/control-census.mjs";
import { validateDocument } from "../src/contracts.mjs";

const SRC = new URL("../src", import.meta.url).pathname;
const TEST = new URL("../test", import.meta.url).pathname;

function loadRegistry() {
  const bytes = readFileSync(new URL("../registry/control-surface.json", import.meta.url));
  const doc = validateDocument("control-surface@1", bytes);
  assert.equal(doc.ok, true, JSON.stringify(doc.errors ?? []));
  return doc.value;
}

test("the real control surface census is complete: discovery equals registration and every control is proven", () => {
  const report = runControlCensus({ srcDir: SRC, testDir: TEST, registry: loadRegistry() });
  assert.equal(report.complete, true, JSON.stringify(report.findings, null, 2));
  // The infrastructure controls the plan census cannot see are present.
  for (const id of [
    "sandbox-network-isolation",
    "sandbox-read-isolation",
    "sandbox-write-isolation",
    "sandbox-process-ceiling",
    "evaluation-deadline",
    "evidence-artifact-ceiling",
    "conformance-status-admission",
    "contract-authorization"
  ]) {
    assert.ok(report.registered.includes(id), `control ${id} must be registered`);
    assert.ok(report.discovered.includes(id), `control ${id} must be discovered in source`);
  }
});

test("a planted unregistered control (sandbox/deadline/status) is detected", () => {
  // Copy the real source tree and inject a NEW control export with no
  // registry row. Independent discovery must flag it.
  const tmpSrc = mkdtempSync(join(tmpdir(), "shedu-src-"));
  cpSync(SRC, tmpSrc, { recursive: true });
  writeFileSync(
    join(tmpSrc, "rogue-control.mjs"),
    'export const CONTROL_POINTS = Object.freeze(["planted-rogue-control"]);\n'
  );
  const report = runControlCensus({ srcDir: tmpSrc, testDir: TEST, registry: loadRegistry() });
  assert.equal(report.complete, false);
  assert.ok(
    report.findings.some((f) => f.id === "planted-rogue-control" && f.reasonCode === "CONTROL_UNREGISTERED"),
    JSON.stringify(report.findings)
  );
});

test("a registered control with no implementation is detected", () => {
  const reg = loadRegistry();
  reg.controls.push({
    id: "phantom-control",
    kind: "isolation",
    definedIn: "src/sandbox.mjs",
    invocationSymbol: "isolateArgv(",
    provingTests: ["the sandbox denies network access to target commands"],
    dispositionEffect: true
  });
  const report = runControlCensus({ srcDir: SRC, testDir: TEST, registry: reg });
  assert.equal(report.complete, false);
  assert.ok(report.findings.some((f) => f.id === "phantom-control" && f.reasonCode === "CONTROL_UNIMPLEMENTED"));
});

test("a registered control whose proving test is absent is detected", () => {
  const reg = loadRegistry();
  const control = reg.controls.find((c) => c.id === "evaluation-deadline");
  // Build the name by concatenation so this literal never appears verbatim in
  // any scanned test file (which would otherwise self-satisfy the census).
  control.provingTests = [["absent", "proving", "test", "marker", "zzz"].join("-")];
  const report = runControlCensus({ srcDir: SRC, testDir: TEST, registry: reg });
  assert.equal(report.complete, false);
  assert.ok(report.findings.some((f) => f.id === "evaluation-deadline" && f.reasonCode === "CONTROL_UNPROVEN"));
});

test("discovery reads the filesystem independently of the registry", () => {
  const discovered = discoverControlPoints(SRC);
  // A representative infrastructure control and a plan control are both found
  // purely from source, with no reference to the registry document.
  assert.equal(discovered.get("sandbox-network-isolation"), "src/sandbox.mjs");
  assert.equal(discovered.get("evaluation-deadline"), "src/deadline.mjs");
  assert.equal(discovered.get("policy-plan-mechanism-census"), "src/census.mjs");
});
