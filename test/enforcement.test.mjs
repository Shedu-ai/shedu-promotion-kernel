import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { generateSigningKeyPem, signReceipt } from "../src/receipt.mjs";
import { canonicalize } from "../src/canonical-json.mjs";
import { createPrivateKey, createPublicKey, sign as cryptoSign } from "node:crypto";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { verifyContractAuthorization } from "../src/authorization.mjs";
import { verifyEvidenceDir } from "../src/evidence.mjs";
import {
  buildTargetRepo,
  commitAll,
  contractBytesOf,
  makeContract,
  writeRepoFile
} from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-enforce-"));
const evaluate = (target, candidate, overrides) =>
  evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate, overrides)),
    outDir: outDir()
  });

// ---- Finding 3: evaluation-wide deadline -------------------------------

test("a wall-clock deadline is enforced at the point of exhaustion", () => {
  // maxRuntimeSeconds: 1, two CANDIDATE_VALIDATION commands each sleeping
  // 700ms. The first runs; the second must be bounded by the ~300ms
  // remaining and cannot pass. Total wall time stays close to the 1s ceiling.
  const sleep = (id, ms) => ({
    commandId: id,
    phase: "CANDIDATE_VALIDATION",
    argv: ["node", "-e", `const t=Date.now()+${ms};while(Date.now()<t){}`]
  });
  const target = buildTargetRepo({
    validationCommands: [sleep("slow-a", 700), sleep("slow-b", 700)]
  });
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const started = performance.now();
  const outcome = evaluate(target, candidate, { maxRuntimeSeconds: 1 });
  const elapsedMs = performance.now() - started;

  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "BLOCKED", JSON.stringify(outcome.receipt.reasonCodes));
  assert.ok(
    outcome.receipt.reasonCodes.includes("DEADLINE_EXCEEDED") || outcome.receipt.reasonCodes.includes("CHECK_FIRED"),
    JSON.stringify(outcome.receipt.reasonCodes)
  );
  // The validation-phase check must NOT be a clean PASS: the second command
  // could not complete within budget.
  const vp = outcome.receipt.checkResults.find((r) => r.checkId === "validation-plan-validation");
  assert.notEqual(vp.outcome, "PASS");
  // Wall-clock is bounded near the ceiling — not the ~1.4s two full sleeps
  // would take, and well under a runaway.
  assert.ok(elapsedMs < 2500, `evaluation ran ${Math.round(elapsedMs)}ms; deadline not enforced at exhaustion`);
});

// ---- Finding 5 audit: artifactRoot is load-bearing ---------------------

test("evidence is written under the contract artifactRoot and recorded in the receipt", () => {
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const dir = outDir();
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: dir
  });
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  // The receipt records the artifactRoot, and the evidence store physically
  // lives under it — not a hardcoded path.
  assert.equal(outcome.receipt.artifactRoot, "artifacts/");
  assert.ok(existsSync(join(dir, "artifacts", "evidence", "index.json")));
  assert.equal(verifyEvidenceDir(join(dir, "artifacts", "evidence")).ok, true);
});

// ---- Finding 5 audit: evidence-artifact ceiling ------------------------

test("the cumulative evidence ceiling is enforced", () => {
  // A one-byte artifact ceiling makes anchoring the check results overflow,
  // failing the run closed rather than silently exceeding the bound.
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(
      target.contractFor(candidate, {
        resourceCeilings: { maxOutputBytes: 1048576, maxArtifactBytes: 1, maxProcesses: 1 }
      })
    ),
    outDir: outDir()
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reasonCode, "DOCUMENT_BOUNDS_EXCEEDED");
});

// ---- Finding 3/6: phase scheduling -------------------------------------

test("commands execute only in their declared phase", () => {
  // A command declared for PROMOTION_FINALIZATION must not run during
  // CANDIDATE_VALIDATION; each phase check reports only its own commands.
  const target = buildTargetRepo({
    validationCommands: [
      { commandId: "val-cmd", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.exit(0)"] },
      { commandId: "final-cmd", phase: "PROMOTION_FINALIZATION", argv: ["node", "-e", "process.exit(0)"] }
    ]
  });
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const outcome = evaluate(target, candidate);
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  const valResult = outcome.receipt.checkResults.find((r) => r.checkId === "validation-plan-validation");
  const finalResult = outcome.receipt.checkResults.find((r) => r.checkId === "validation-plan-finalization");
  const admissionResult = outcome.receipt.checkResults.find((r) => r.checkId === "validation-plan-admission");
  // val-cmd's report is anchored under the validation check, final-cmd's under
  // finalization, and neither appears under admission.
  assert.ok(valResult.evidence.some((e) => e.artifactId === "command-report-val-cmd"));
  assert.ok(!valResult.evidence.some((e) => e.artifactId === "command-report-final-cmd"));
  assert.ok(finalResult.evidence.some((e) => e.artifactId === "command-report-final-cmd"));
  assert.equal(admissionResult.evidence.length, 0);
});

// ---- Containment halt routing ------------------------------------------

test("a scope violation halts the run and skips remaining checks", () => {
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "policy/profile.json", '{"weakened":true}\n');
  const candidate = commitAll(target.repoDir, "forbidden policy rewrite");
  const outcome = evaluate(target, candidate);
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  assert.ok(outcome.receipt.reasonCodes.includes("SCOPE_FORBIDDEN_CHANGE"));
  assert.ok(outcome.receipt.reasonCodes.includes("CHECK_SKIPPED"));
  const finalization = outcome.receipt.checkResults.find((r) => r.checkId === "evidence-binding-index");
  assert.equal(finalization.outcome, "SKIPPED");
});

// ---- Finding 5 audit: contract authorization ---------------------------

function signContract(workContract, privateKeyPem) {
  const key = createPrivateKey(privateKeyPem);
  const jwk = createPublicKey(key).export({ format: "jwk" });
  const unsigned = { ...workContract, authorization: { ...workContract.authorization, signature: null } };
  const signature = cryptoSign(null, Buffer.from(canonicalize(unsigned), "utf8"), key).toString("hex");
  return {
    ...workContract,
    authorization: {
      ...workContract.authorization,
      signature: {
        algorithm: "ed25519",
        publicKey: Buffer.from(jwk.x, "base64url").toString("hex"),
        signature
      }
    }
  };
}

test("a present but invalid contract authorization signature is rejected", () => {
  // No signature: accepted (identity still binds provenance).
  assert.equal(verifyContractAuthorization(makeContract()).ok, true);

  // A validly self-signed contract: the field is consistent.
  const keyPem = generateSigningKeyPem();
  const signed = signContract(makeContract(), keyPem);
  assert.equal(verifyContractAuthorization(signed).ok, true);

  // Tamper the body after signing: signature no longer matches → rejected.
  const tampered = { ...signed, objectiveId: "tampered-objective" };
  const bad = verifyContractAuthorization(tampered);
  assert.equal(bad.ok, false);
  assert.equal(bad.reasonCode, "AUTHORIZATION_INVALID");

  // Garbage signature bytes → rejected, not inert.
  const garbage = {
    ...makeContract(),
    authorization: {
      identity: "x",
      issuedAt: "2026-08-26T00:00:00Z",
      signature: { algorithm: "ed25519", publicKey: "0".repeat(64), signature: "0".repeat(128) }
    }
  };
  assert.equal(verifyContractAuthorization(garbage).ok, false);

  // And the whole evaluation refuses a contract with a bad signature.
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const contract = target.contractFor(candidate);
  const badContract = {
    ...contract,
    authorization: {
      ...contract.authorization,
      signature: { algorithm: "ed25519", publicKey: "1".repeat(64), signature: "2".repeat(128) }
    }
  };
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: Buffer.from(`${JSON.stringify(badContract)}\n`, "utf8"),
    outDir: outDir()
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reasonCode, "AUTHORIZATION_INVALID");
});
