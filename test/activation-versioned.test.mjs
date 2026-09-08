import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { before } from "node:test";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { verifyReceipt } from "../src/receipt.mjs";
import { verifyActivationPair } from "../src/activation.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const execution = { class: "SINGLE_PROCESS", maxTasks: 64 };
function pair(variant = "") {
  const pack = {
    schemaVersion: "policy-pack@2", packId: "versioned-gate", version: "1.0.0",
    description: "versioned activation regression", phases: ["CANDIDATE_VALIDATION"], dependencies: [],
    checks: [{
      checkId: "versioned-gate", phase: "CANDIDATE_VALIDATION", effect: "BLOCKING",
      validator: {
        kind: "TARGET_COMMAND", inputManifest: [], executionRequirement: execution,
        argv: ["node", "-e", `process.exit(require("node:fs").existsSync(require("node:path").join(process.env.KERNEL_CANDIDATE_DIR,"src/gate.marker"))?1:0);${variant}`]
      },
      inputs: [], outputSchemaId: "check-result@1", timeoutSeconds: 30,
      network: "NONE", filesystem: "READ_ONLY", envAllowlist: [], resultConsumer: "DISPOSITION_REDUCER"
    }]
  };
  const target = buildTargetRepo({ targetPacks: [pack], profileOverrides: { schemaVersion: "policy-profile@2", executionPolicy: execution }, validationCommands: [{
    commandId: "feature-value", phase: "CANDIDATE_VALIDATION", executionRequirement: execution,
    argv: ["node", "--input-type=module", "-e", 'import assert from "node:assert/strict"; import {feature} from "./src/feature.mjs"; assert.equal(feature,2);']
  }] });
  const evaluate = candidate => {
    const contract = target.contractFor(candidate, { schemaVersion: "work-contract@2", resourceCeilings: { maxOutputBytes: 65536, maxArtifactBytes: 2097152, executionCeiling: execution } });
    const output = mkdtempSync(join(tmpdir(), "shedu-versioned-activation-"));
    const result = evaluateCandidate({ repoDir: target.repoDir, contractBytes: contractBytesOf(contract), outDir: output });
    assert.equal(result.ok, true, JSON.stringify(result));
    const planBytes = Buffer.from(JSON.stringify(result.plan));
    assert.equal(verifyReceipt({ receiptBytes: result.receiptBytes, planBytes, evidenceDir: join(output, "artifacts/evidence") }).ok, true);
    return { receiptBytes: result.receiptBytes, planBytes, disposition: result.receipt.disposition };
  };
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const conforming = evaluate(commitAll(target.repoDir, "conforming version 2 candidate"));
  writeRepoFile(target.repoDir, "src/gate.marker", "planted\n");
  const planted = evaluate(commitAll(target.repoDir, "planted version 2 candidate"));
  assert.equal(conforming.disposition, "PROMOTABLE");
  assert.equal(planted.disposition, "BLOCKED");
  return { conformingReceiptBytes: conforming.receiptBytes, conformingPlanBytes: conforming.planBytes, plantedReceiptBytes: planted.receiptBytes, plantedPlanBytes: planted.planBytes, checkId: "versioned-gate" };
}
let genuine, drifted;
before(() => { genuine = pair(); drifted = pair("// different validator bytes"); });

test("a fully offline-verified version 2 activation pair is accepted", () => {
  const result = verifyActivationPair(genuine);
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.signed, false);
});
test("version 2 activation rejects the wrong current fingerprint", () => {
  const result = verifyActivationPair({ ...genuine, expectedFingerprint: "wrong-fingerprint" });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => /fingerprint does not match/.test(e.message)));
});
test("version 2 activation rejects absent required signatures", () => {
  const result = verifyActivationPair({ ...genuine, trustPolicy: { requireSignature: true, trustedPublicKeys: [] } });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => /must be signed/.test(e.message)));
});
test("version 2 activation rejects a conforming receipt substituted for the planted run", () => {
  assert.equal(verifyActivationPair({ ...genuine, plantedReceiptBytes: genuine.conformingReceiptBytes, plantedPlanBytes: genuine.conformingPlanBytes }).ok, false);
});
test("version 2 activation rejects validator substitution", () => {
  assert.equal(verifyActivationPair({ ...genuine, plantedReceiptBytes: drifted.plantedReceiptBytes, plantedPlanBytes: drifted.plantedPlanBytes }).ok, false);
});
test("version 2 activation rejects a substituted declared receipt version", () => {
  const changed = JSON.parse(genuine.plantedReceiptBytes);
  changed.schemaVersion = "promotion-receipt@1";
  assert.equal(verifyActivationPair({ ...genuine, plantedReceiptBytes: Buffer.from(JSON.stringify(changed)) }).ok, false);
});
