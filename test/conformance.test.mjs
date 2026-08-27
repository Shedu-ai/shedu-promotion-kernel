import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runConformance } from "../src/conformance.mjs";
import { validateDocument } from "../src/contracts.mjs";
import { verifyReceipt } from "../src/receipt.mjs";
import { KERNEL_RELEASE } from "../src/compiler.mjs";

// AC-13/AC-14 plus the kernel activation proof (brief §7 items 5–6): every
// case is a conforming/planted receipt pair, one per kernel mechanism beyond
// the three AC-13 profiles, all offline-verified — and the committed status
// document is regenerable byte-for-byte, which is what entitles the probe to
// report EXPERIMENTAL. The matrix is run once and shared across these tests.

const OUT_DIR = mkdtempSync(join(tmpdir(), "shedu-conformance-run-"));
const RUN = runConformance({ outDir: OUT_DIR });

const EXPECTED_CASES = [
  "minimal-personal",
  "standard-team",
  "strict-target",
  "identity-activation",
  "admission-activation",
  "validation-activation",
  "finalization-activation",
  "stability-activation",
  "evidence-activation",
  "orphan-activation"
];

test("the zero-provider conformance matrix passes and reproduces the committed status byte-for-byte", () => {
  const { status, statusBytes } = RUN;
  assert.equal(status.allPassed, true, JSON.stringify(status, null, 2));
  assert.deepEqual(status.cases.map((c) => c.caseId), EXPECTED_CASES);
  for (const c of status.cases) {
    assert.equal(c.conforming.disposition, "PROMOTABLE", c.caseId);
    assert.equal(c.conforming.receiptVerified, true, c.caseId);
    assert.equal(c.planted.disposition, "BLOCKED", c.caseId);
    assert.equal(c.planted.receiptVerified, true, c.caseId);
    // Where the planted violation is a different candidate or registry, the
    // plans differ; for runtime-only plants (workspace/evidence mutation)
    // the plan is identical by design and only the outcome diverges.
    if (!["stability-activation", "evidence-activation"].includes(c.caseId)) {
      assert.notEqual(c.conforming.planDigest, c.planted.planDigest, c.caseId);
    } else {
      assert.equal(c.conforming.planDigest, c.planted.planDigest, c.caseId);
      assert.notEqual(c.conforming.evaluationDigest, c.planted.evaluationDigest, c.caseId);
    }
  }

  const committed = readFileSync(new URL("../conformance/status.json", import.meta.url));
  assert.equal(statusBytes.toString("utf8"), committed.toString("utf8"));

  const validated = validateDocument("conformance-status@1", committed);
  assert.equal(validated.ok, true);
  assert.equal(validated.value.kernelRelease, KERNEL_RELEASE);
});

test("every kernel mechanism has a mechanically proven activation pair", () => {
  const { status } = RUN;
  const registry = JSON.parse(
    readFileSync(new URL("../registry/kernel-mechanisms.json", import.meta.url), "utf8")
  );
  const proven = new Map(status.kernelActivation.map((a) => [a.mechanismId, a]));
  assert.equal(status.kernelActivation.length, registry.mechanisms.length);
  for (const mechanism of registry.mechanisms) {
    const activation = proven.get(mechanism.mechanismId);
    assert.ok(activation, `${mechanism.mechanismId} has no activation case`);
    assert.equal(activation.proven, true, `${mechanism.mechanismId} activation pair not proven (case ${activation.caseId})`);
  }
});

test("retained conformance receipts remain independently verifiable from disk", () => {
  // evidence-activation deliberately corrupts its planted evidence store, so
  // its planted receipt is verified bare — exactly as the matrix does.
  for (const caseId of EXPECTED_CASES) {
    for (const kind of ["conforming", "planted"]) {
      const runDir = join(OUT_DIR, caseId, kind);
      const withEvidence = !(caseId === "evidence-activation" && kind === "planted");
      const verification = verifyReceipt({
        receiptBytes: readFileSync(join(runDir, "receipt.json")),
        planBytes: readFileSync(join(runDir, "plan.json")),
        evidenceDir: withEvidence ? join(runDir, "artifacts", "evidence") : null
      });
      assert.equal(verification.ok, true, `${caseId}/${kind}: ${JSON.stringify(verification.errors)}`);
    }
  }
});
