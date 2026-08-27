import { canonicalize } from "./canonical-json.mjs";
import { validateDocument } from "./contracts.mjs";
import { planCheckValidatorId } from "./census.mjs";
import { verifyReceipt } from "./receipt.mjs";

// Control point: activation verification.
export const CONTROL_POINTS = Object.freeze(["activation-verification"]);

// Mechanical activation proof for a mechanism (brief §7 items 5–6).
//
// Activation evidence is a PAIR of offline-verified receipts:
//   conforming — PROMOTABLE with the subject check OBSERVED (PASS);
//   planted    — BLOCKED where the subject check FIRED as the sole failure.
//
// The two receipts, the current mechanism-registry row, and the current
// dispatched plan check must all prove the SAME canonical activation
// fingerprint: the control's identity independent of which repository ran
// it. The fingerprint binds the complete check tuple, pack identity and
// digest, validator identity AND byte digest, phase, effect, consumer, and
// kernel/reducer release. Base and candidate are deliberately excluded so
// the fingerprint is stable across repositories, while pack and validator
// content digests make substitution — a different base, a different plan, or
// a different validator implementation under the same checkId — fail.

const RELEASE = "reducer-release-bound-to-kernel-release";

// The canonical control identity. Anything run-specific (base, candidate,
// plan digest, timestamps) is excluded; everything that identifies the
// control and its exact implementation is included.
export function activationFingerprint({
  checkId,
  packId,
  packVersion,
  packDigest,
  validatorId,
  validatorDigest,
  phase,
  effect,
  resultConsumer,
  kernelRelease
}) {
  return canonicalize({
    schema: "activation-fingerprint@1",
    checkId,
    packId,
    packVersion,
    packDigest,
    validatorId,
    validatorDigest,
    phase,
    effect,
    resultConsumer,
    kernelRelease,
    reducerRelease: RELEASE
  });
}

// Derive the fingerprint of the subject check from a (receipt, plan) pair.
// Requires the plan to dispatch the check, the receipt to pin the validator
// byte digest and the pack digest, and exactly one result for the check.
export function fingerprintFromReceipt(receipt, plan, checkId) {
  const planChecks = plan.checks.filter((c) => c.checkId === checkId);
  if (planChecks.length !== 1) {
    return { ok: false, message: `plan dispatches ${planChecks.length} checks named ${checkId}, expected exactly one` };
  }
  const planCheck = planChecks[0];
  const results = receipt.checkResults.filter((r) => r.checkId === checkId);
  if (results.length !== 1) {
    return { ok: false, message: `receipt records ${results.length} results for ${checkId}, expected exactly one` };
  }
  const validatorId = planCheckValidatorId(planCheck);
  const validatorEntry = receipt.digests.validators.find((v) => v.validatorId === validatorId);
  if (!validatorEntry) {
    return { ok: false, message: `receipt does not pin a validator digest for ${validatorId}` };
  }
  const packEntry = plan.sourceDigests.packs.find((p) => p.packId === planCheck.packId);
  if (!packEntry) {
    return { ok: false, message: `plan does not pin a pack digest for ${planCheck.packId}` };
  }
  return {
    ok: true,
    result: results[0],
    fingerprint: activationFingerprint({
      checkId,
      packId: planCheck.packId,
      packVersion: planCheck.packVersion,
      packDigest: packEntry.digest,
      validatorId,
      validatorDigest: validatorEntry.digest,
      phase: planCheck.phase,
      effect: planCheck.effect,
      resultConsumer: planCheck.resultConsumer,
      kernelRelease: receipt.kernelRelease
    })
  };
}

// The fingerprint the current run expects for a dispatched check, given the
// current validator byte digest (computed from the trusted base).
export function fingerprintFromCurrentPlan(plan, checkId, validatorDigest) {
  const planCheck = plan.checks.find((c) => c.checkId === checkId);
  if (!planCheck) return { ok: false, message: `current plan does not dispatch ${checkId}` };
  const packEntry = plan.sourceDigests.packs.find((p) => p.packId === planCheck.packId);
  if (!packEntry) return { ok: false, message: `current plan does not pin a pack digest for ${planCheck.packId}` };
  return {
    ok: true,
    fingerprint: activationFingerprint({
      checkId,
      packId: planCheck.packId,
      packVersion: planCheck.packVersion,
      packDigest: packEntry.digest,
      validatorId: planCheckValidatorId(planCheck),
      validatorDigest,
      phase: planCheck.phase,
      effect: planCheck.effect,
      resultConsumer: planCheck.resultConsumer,
      kernelRelease: plan.kernelRelease
    })
  };
}

const STRUCTURAL_REASONS = new Set([
  "DUPLICATE_RESULT",
  "RESULT_BINDING_MISMATCH",
  "MISSING_REQUIRED_RESULT",
  "INFRASTRUCTURE_FAILURE"
]);

// trustPolicy: { requireSignature: bool, trustedPublicKeys: string[] }.
// When requireSignature is true, both receipts must carry a valid signature
// from a trusted key; unsigned evidence is then never treated as authoritative.
export function verifyActivationPair({
  conformingReceiptBytes,
  conformingPlanBytes,
  plantedReceiptBytes,
  plantedPlanBytes,
  checkId,
  expectedFingerprint = null,
  trustPolicy = { requireSignature: false, trustedPublicKeys: [] }
}) {
  const errors = [];
  const fail = (message) => errors.push({ reasonCode: "ACTIVATION_EVIDENCE_INVALID", message });

  const conformingVerdict = verifyReceipt({ receiptBytes: conformingReceiptBytes, planBytes: conformingPlanBytes });
  if (!conformingVerdict.ok) {
    fail(`conforming receipt for ${checkId} does not verify offline`);
    return { ok: false, errors, signed: false };
  }
  const plantedVerdict = verifyReceipt({ receiptBytes: plantedReceiptBytes, planBytes: plantedPlanBytes });
  if (!plantedVerdict.ok) {
    fail(`planted receipt for ${checkId} does not verify offline`);
    return { ok: false, errors, signed: false };
  }

  const conforming = validateDocument("promotion-receipt@1", conformingReceiptBytes).value;
  const planted = validateDocument("promotion-receipt@1", plantedReceiptBytes).value;
  const conformingPlan = validateDocument("compiled-policy-plan@1", conformingPlanBytes).value;
  const plantedPlan = validateDocument("compiled-policy-plan@1", plantedPlanBytes).value;

  // The pair must be the same control over the same repository: a conforming
  // receipt from one run cannot be paired with a planted receipt from an
  // unrelated repository. (Base may legitimately differ — e.g. orphan-closure
  // gets its registry from base, so the planted violation lives in a
  // different base — but the fingerprint below binds pack + validator bytes,
  // so a different CONTROL can never be paired.)
  if (conforming.repositoryId !== planted.repositoryId) {
    fail(`activation receipts for ${checkId} are from different repositories`);
  }

  const trustedKeys = new Set(trustPolicy.trustedPublicKeys ?? []);
  const signedAndTrusted = (receipt) =>
    receipt.signing !== null && trustedKeys.has(receipt.signing.publicKey);
  const bothSignedTrusted = signedAndTrusted(conforming) && signedAndTrusted(planted);
  if (trustPolicy.requireSignature && !bothSignedTrusted) {
    fail(`activation evidence for ${checkId} must be signed by a trusted key under the configured trust policy`);
  }

  // Fingerprints of both sides must exist and be equal.
  const conformingFp = fingerprintFromReceipt(conforming, conformingPlan, checkId);
  const plantedFp = fingerprintFromReceipt(planted, plantedPlan, checkId);
  if (!conformingFp.ok) fail(`conforming: ${conformingFp.message}`);
  if (!plantedFp.ok) fail(`planted: ${plantedFp.message}`);
  if (conformingFp.ok && plantedFp.ok && conformingFp.fingerprint !== plantedFp.fingerprint) {
    fail(`conforming and planted receipts prove different activation fingerprints (different base, plan, pack, or validator)`);
  }
  if (expectedFingerprint !== null && conformingFp.ok && conformingFp.fingerprint !== expectedFingerprint) {
    fail(`activation fingerprint does not match the current registry row and dispatched plan check`);
  }

  // Pass proof: conforming run OBSERVED without firing, promotable.
  if (conforming.disposition !== "PROMOTABLE") fail(`conforming receipt for ${checkId} is not PROMOTABLE`);
  if (conformingFp.ok && (conformingFp.result.outcome !== "PASS" || conformingFp.result.effect !== "BLOCKING")) {
    fail(`conforming receipt does not show ${checkId} OBSERVED as a passing blocking check`);
  }

  // Activation proof: planted run FIRED and blocked, with this firing the
  // sole failure and NOT a structural reducer failure masquerading as one.
  if (planted.disposition !== "BLOCKED") fail(`planted receipt for ${checkId} is not BLOCKED`);
  if (!planted.reasonCodes.includes("CHECK_FIRED")) {
    fail(`planted receipt for ${checkId} did not block because a check FIRED`);
  }
  for (const code of planted.reasonCodes) {
    if (STRUCTURAL_REASONS.has(code)) {
      fail(`planted receipt blocked on a structural reducer failure (${code}), not a genuine activation`);
    }
  }
  if (plantedFp.ok) {
    if (plantedFp.result.outcome !== "FIRED" || plantedFp.result.effect !== "BLOCKING") {
      fail(`planted receipt does not show ${checkId} FIRED as a blocking check`);
    }
    for (const result of planted.checkResults) {
      if (result.checkId === checkId) continue;
      if (result.outcome !== "PASS" && result.outcome !== "SKIPPED") {
        fail(`planted receipt has an unrelated failure (${result.checkId}: ${result.outcome}); the firing of ${checkId} is not proven to change the disposition`);
      }
    }
  }

  return { ok: errors.length === 0, errors, signed: bothSignedTrusted, fingerprint: conformingFp.ok ? conformingFp.fingerprint : null };
}
