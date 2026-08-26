import { verifyReceipt } from "./receipt.mjs";
import { validateDocument } from "./contracts.mjs";

// Mechanical activation proof for a mechanism (brief §7 items 5–6). The
// evidence is a PAIR of offline-verified receipts over the same repository:
//
//   conforming — disposition PROMOTABLE with this check OBSERVED (PASS);
//   planted    — disposition BLOCKED where this check FIRED and is the SOLE
//                failure: every other result is PASS or SKIPPED (skips being
//                the halt this firing caused).
//
// Together they prove the check executes, observes conforming input without
// firing, fires on the planted violation, and that its firing alone changed
// the final disposition. No prose, status flag, or fixture description can
// substitute: both receipts must reproduce their dispositions through the
// reducer under verifyReceipt before any of this is even examined.
export function verifyActivationPair({
  conformingReceiptBytes,
  conformingPlanBytes,
  plantedReceiptBytes,
  plantedPlanBytes,
  checkId
}) {
  const errors = [];
  const fail = (message) => errors.push({ reasonCode: "ACTIVATION_EVIDENCE_INVALID", message });

  const conformingVerdict = verifyReceipt({ receiptBytes: conformingReceiptBytes, planBytes: conformingPlanBytes });
  if (!conformingVerdict.ok) {
    fail(`conforming receipt for ${checkId} does not verify offline`);
    return { ok: false, errors };
  }
  const plantedVerdict = verifyReceipt({ receiptBytes: plantedReceiptBytes, planBytes: plantedPlanBytes });
  if (!plantedVerdict.ok) {
    fail(`planted receipt for ${checkId} does not verify offline`);
    return { ok: false, errors };
  }

  const conforming = validateDocument("promotion-receipt@1", conformingReceiptBytes).value;
  const planted = validateDocument("promotion-receipt@1", plantedReceiptBytes).value;

  if (conforming.repositoryId !== planted.repositoryId) {
    fail(`activation receipts for ${checkId} are from different repositories`);
  }

  // Pass proof: conforming run OBSERVED without firing, promotable.
  if (conforming.disposition !== "PROMOTABLE") {
    fail(`conforming receipt for ${checkId} is not PROMOTABLE`);
  }
  const observed = conforming.checkResults.find((r) => r.checkId === checkId);
  if (!observed || observed.outcome !== "PASS" || observed.effect !== "BLOCKING") {
    fail(`conforming receipt does not show ${checkId} OBSERVED as a passing blocking check`);
  }

  // Activation proof: planted run FIRED and blocked, with this firing the
  // sole failure cause.
  if (planted.disposition !== "BLOCKED") {
    fail(`planted receipt for ${checkId} is not BLOCKED`);
  }
  const fired = planted.checkResults.find((r) => r.checkId === checkId);
  if (!fired || fired.outcome !== "FIRED" || fired.effect !== "BLOCKING") {
    fail(`planted receipt does not show ${checkId} FIRED as a blocking check`);
  } else {
    for (const result of planted.checkResults) {
      if (result.checkId === checkId) continue;
      if (result.outcome !== "PASS" && result.outcome !== "SKIPPED") {
        fail(`planted receipt has an unrelated failure (${result.checkId}: ${result.outcome}); the firing of ${checkId} is not proven to change the disposition`);
      }
    }
  }

  return { ok: errors.length === 0, errors };
}
