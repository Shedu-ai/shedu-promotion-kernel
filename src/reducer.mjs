import { validateValue } from "./contracts.mjs";

// Control point: the deterministic, override-free disposition reduction.
export const CONTROL_POINTS = Object.freeze(["disposition-reduction"]);

// Disposition reducer. Deterministic, with no override path: the disposition
// is a pure function of (plan, planDigest, results) and nothing else.
//
// - Every BLOCKING check routed to the reducer must be answered by exactly
//   one bound result: missing, duplicate, forged-binding, and
//   infrastructure-failed results all fail closed to BLOCKED.
// - Advisory results are consumed and retained but can never block, and the
//   reducer offers no input that could escalate them.
// - EVIDENCE_ONLY results are retained as evidence and never participate in
//   the disposition.
// - Result order does not matter; output ordering follows the plan.
export function reduceDisposition({ plan, planDigest, results }) {
  const blockingReasons = new Set();
  const consumed = [];
  const advisory = [];
  const evidenceOnly = [];
  const problems = [];

  const planChecks = new Map(plan.checks.map((c) => [c.checkId, c]));
  const byCheckId = new Map();

  for (const result of results) {
    const shape = result !== null && typeof result === "object" ? validateValue("check-result@1", result) : { ok: false };
    if (!shape.ok) {
      blockingReasons.add("RESULT_BINDING_MISMATCH");
      problems.push({ reasonCode: "RESULT_BINDING_MISMATCH", checkId: null, message: "a supplied result is not a valid check-result@1" });
      continue;
    }
    if (byCheckId.has(result.checkId)) {
      blockingReasons.add("DUPLICATE_RESULT");
      problems.push({ reasonCode: "DUPLICATE_RESULT", checkId: result.checkId, message: `check ${result.checkId} has more than one result` });
      continue;
    }
    const check = planChecks.get(result.checkId);
    const bound =
      check !== undefined &&
      result.packId === check.packId &&
      result.effect === check.effect &&
      result.planDigest === planDigest &&
      result.candidateId === plan.candidate.id;
    if (!bound) {
      blockingReasons.add("RESULT_BINDING_MISMATCH");
      problems.push({ reasonCode: "RESULT_BINDING_MISMATCH", checkId: result.checkId, message: `result for ${result.checkId} does not bind to the plan, candidate, pack, or declared effect` });
      continue;
    }
    byCheckId.set(result.checkId, result);
  }

  // Consume in plan order so output is deterministic regardless of the order
  // results arrived in.
  for (const check of plan.checks) {
    const result = byCheckId.get(check.checkId);
    if (check.resultConsumer === "EVIDENCE_ONLY") {
      if (result) evidenceOnly.push({ checkId: check.checkId, outcome: result.outcome });
      continue;
    }
    if (check.effect === "BLOCKING") {
      if (!result) {
        blockingReasons.add("MISSING_REQUIRED_RESULT");
        problems.push({ reasonCode: "MISSING_REQUIRED_RESULT", checkId: check.checkId, message: `blocking check ${check.checkId} produced no result` });
        continue;
      }
      consumed.push({ checkId: check.checkId, effect: check.effect, outcome: result.outcome });
      if (result.outcome === "FIRED") {
        blockingReasons.add("CHECK_FIRED");
        for (const code of result.reasonCodes) blockingReasons.add(code);
      } else if (result.outcome === "INFRA_FAILURE") {
        blockingReasons.add("INFRASTRUCTURE_FAILURE");
        for (const code of result.reasonCodes) blockingReasons.add(code);
      } else if (result.outcome === "SKIPPED") {
        // A skipped required check is explicit non-success: fail closed.
        blockingReasons.add("CHECK_SKIPPED");
        for (const code of result.reasonCodes) blockingReasons.add(code);
      }
    } else {
      // ADVISORY routed to the reducer: consumed and retained, never blocking.
      if (result) {
        consumed.push({ checkId: check.checkId, effect: check.effect, outcome: result.outcome });
        advisory.push({ checkId: check.checkId, outcome: result.outcome, reasonCodes: [...result.reasonCodes] });
      }
    }
  }

  return {
    disposition: blockingReasons.size === 0 ? "PROMOTABLE" : "BLOCKED",
    reasonCodes: [...blockingReasons].sort(),
    consumed,
    advisory,
    evidenceOnly,
    problems
  };
}
