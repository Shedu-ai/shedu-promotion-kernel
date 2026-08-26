import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runConformance } from "../src/conformance.mjs";
import { validateDocument } from "../src/contracts.mjs";
import { verifyReceipt } from "../src/receipt.mjs";
import { KERNEL_RELEASE } from "../src/compiler.mjs";

// AC-13/AC-14: the three synthetic repositories, evaluated conforming and
// planted, with every receipt offline-verified — and the committed status
// document is regenerable byte-for-byte, which is what entitles the probe
// to report EXPERIMENTAL.

test("the zero-provider conformance matrix passes and reproduces the committed status byte-for-byte", () => {
  const outDir = mkdtempSync(join(tmpdir(), "shedu-conformance-run-"));
  const { status, statusBytes } = runConformance({ outDir });

  assert.equal(status.allPassed, true, JSON.stringify(status, null, 2));
  assert.deepEqual(status.cases.map((c) => c.caseId), ["minimal-personal", "standard-team", "strict-target"]);
  for (const c of status.cases) {
    assert.equal(c.conforming.disposition, "PROMOTABLE", c.caseId);
    assert.equal(c.conforming.receiptVerified, true, c.caseId);
    assert.equal(c.planted.disposition, "BLOCKED", c.caseId);
    assert.equal(c.planted.receiptVerified, true, c.caseId);
    // Conforming and planted are different candidates, hence different plans.
    assert.notEqual(c.conforming.planDigest, c.planted.planDigest);
  }

  // Byte-for-byte reproducibility: the committed evidence is exactly what a
  // fresh run produces, so the EXPERIMENTAL transition is regenerable, not
  // asserted.
  const committed = readFileSync(new URL("../conformance/status.json", import.meta.url));
  assert.equal(statusBytes.toString("utf8"), committed.toString("utf8"));

  const validated = validateDocument("conformance-status@1", committed);
  assert.equal(validated.ok, true);
  assert.equal(validated.value.kernelRelease, KERNEL_RELEASE);
});

test("retained conformance receipts remain independently verifiable from disk", () => {
  const outDir = mkdtempSync(join(tmpdir(), "shedu-conformance-retain-"));
  runConformance({ outDir });
  for (const caseId of ["minimal-personal", "standard-team", "strict-target"]) {
    for (const kind of ["conforming", "planted"]) {
      const runDir = join(outDir, caseId, kind);
      const verification = verifyReceipt({
        receiptBytes: readFileSync(join(runDir, "receipt.json")),
        planBytes: readFileSync(join(runDir, "plan.json")),
        evidenceDir: join(runDir, "evidence")
      });
      assert.equal(verification.ok, true, `${caseId}/${kind}: ${JSON.stringify(verification.errors)}`);
    }
  }
});
