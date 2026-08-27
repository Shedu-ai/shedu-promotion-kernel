import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { verifyActivationPair, fingerprintFromReceipt } from "../src/activation.mjs";
import { validateDocument } from "../src/contracts.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-activation-"));

// A blocking target-command pack whose gate FIREs when a marker file exists
// in the candidate. `variant` changes the validator BYTES (different argv),
// so its content digest — and thus the activation fingerprint — differs.
function gateGate(variant = "") {
  const argv = ["node", "-e", `process.exit(require("node:fs").existsSync(require("node:path").join(process.env.KERNEL_CANDIDATE_DIR,"src","gate.marker"))?1:0)${variant ? `//${variant}` : ""}`];
  return {
    schemaVersion: "policy-pack@1",
    packId: "gate-pack",
    version: "1.0.0",
    description: "activation gate",
    phases: ["CANDIDATE_VALIDATION"],
    dependencies: [],
    checks: [
      {
        checkId: "gate-check",
        phase: "CANDIDATE_VALIDATION",
        effect: "BLOCKING",
        validator: { kind: "TARGET_COMMAND", argv, inputManifest: [] },
        inputs: [],
        outputSchemaId: "check-result@1",
        timeoutSeconds: 60,
        network: "NONE",
        filesystem: "READ_ONLY",
        envAllowlist: [],
        resultConsumer: "DISPOSITION_REDUCER"
      }
    ]
  };
}

// Produce a conforming (PROMOTABLE, gate OBSERVED) and planted (BLOCKED, gate
// FIRED) receipt pair for a fresh repo.
function pair({ variant = "", repoTag = "x" } = {}) {
  const target = buildTargetRepo({ targetPacks: [gateGate(variant)] });
  writeRepoFile(target.repoDir, `src/${repoTag}.mjs`, "export const x = 1;\n");
  const conformingCandidate = commitAll(target.repoDir, "conforming");
  const conforming = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(conformingCandidate)),
    outDir: outDir()
  });
  assert.equal(conforming.receipt.disposition, "PROMOTABLE", JSON.stringify(conforming.receipt.reasonCodes));
  writeRepoFile(target.repoDir, "src/gate.marker", "planted\n");
  const plantedCandidate = commitAll(target.repoDir, "planted gate");
  const planted = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(plantedCandidate)),
    outDir: outDir()
  });
  assert.equal(planted.receipt.disposition, "BLOCKED");
  return {
    conformingReceiptBytes: conforming.receiptBytes,
    conformingPlanBytes: Buffer.from(JSON.stringify(conforming.plan), "utf8"),
    plantedReceiptBytes: planted.receiptBytes,
    plantedPlanBytes: Buffer.from(JSON.stringify(planted.plan), "utf8")
  };
}

test("a genuine activation pair verifies and proves one stable fingerprint", () => {
  const p = pair();
  const result = verifyActivationPair({ ...p, checkId: "gate-check" });
  assert.equal(result.ok, true, JSON.stringify(result.errors));

  const cReceipt = validateDocument("promotion-receipt@1", p.conformingReceiptBytes).value;
  const cPlan = validateDocument("compiled-policy-plan@1", p.conformingPlanBytes).value;
  const pReceipt = validateDocument("promotion-receipt@1", p.plantedReceiptBytes).value;
  const pPlan = validateDocument("compiled-policy-plan@1", p.plantedPlanBytes).value;
  const fpC = fingerprintFromReceipt(cReceipt, cPlan, "gate-check");
  const fpP = fingerprintFromReceipt(pReceipt, pPlan, "gate-check");
  assert.equal(fpC.ok && fpP.ok, true);
  assert.equal(fpC.fingerprint, fpP.fingerprint);
});

test("substitution: a different-base, different-validator planted receipt is rejected", () => {
  const a = pair({ repoTag: "a" });
  const b = pair({ variant: "different-validator", repoTag: "b" });
  // Conforming from A, planted from B (different base AND different validator
  // bytes). The old code accepted this; the fingerprint + base binding reject.
  const swapped = verifyActivationPair({
    conformingReceiptBytes: a.conformingReceiptBytes,
    conformingPlanBytes: a.conformingPlanBytes,
    plantedReceiptBytes: b.plantedReceiptBytes,
    plantedPlanBytes: b.plantedPlanBytes,
    checkId: "gate-check"
  });
  assert.equal(swapped.ok, false);
  assert.ok(swapped.errors.length > 0);
});

test("validator-byte drift between the two sides is rejected", () => {
  const a = pair({ repoTag: "c" });
  const drifted = pair({ variant: "drift", repoTag: "c" });
  // Same repo layout, but the planted side's validator bytes differ.
  const result = verifyActivationPair({
    conformingReceiptBytes: a.conformingReceiptBytes,
    conformingPlanBytes: a.conformingPlanBytes,
    plantedReceiptBytes: drifted.plantedReceiptBytes,
    plantedPlanBytes: drifted.plantedPlanBytes,
    checkId: "gate-check"
  });
  assert.equal(result.ok, false);
});

test("an expected-fingerprint mismatch (wrong current registry/plan) is rejected", () => {
  const p = pair({ repoTag: "d" });
  const mismatched = verifyActivationPair({
    ...p,
    checkId: "gate-check",
    expectedFingerprint: "sha256-not-the-real-fingerprint"
  });
  assert.equal(mismatched.ok, false);
  assert.ok(mismatched.errors.some((e) => /fingerprint does not match/.test(e.message)));
});

test("a structural reducer failure cannot masquerade as activation", () => {
  const p = pair({ repoTag: "e" });
  // Replace the planted receipt with the conforming one: it is PROMOTABLE,
  // so it is neither BLOCKED nor a genuine firing — rejected.
  const notPlanted = verifyActivationPair({
    conformingReceiptBytes: p.conformingReceiptBytes,
    conformingPlanBytes: p.conformingPlanBytes,
    plantedReceiptBytes: p.conformingReceiptBytes,
    plantedPlanBytes: p.conformingPlanBytes,
    checkId: "gate-check"
  });
  assert.equal(notPlanted.ok, false);
});
