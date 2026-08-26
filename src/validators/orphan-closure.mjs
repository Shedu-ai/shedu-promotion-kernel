import { canonicalize } from "../canonical-json.mjs";
import { MANDATORY_PACK_IDS } from "../compiler.mjs";
import { implementedBuiltinValidatorIds } from "../builtin-validators.mjs";
import { planCheckValidatorId } from "../census.mjs";

// orphan-closure-verify@1 — PROMOTION_FINALIZATION.
// Enforces the no-orphan admission law over the TARGET's mechanism registry
// against this run's compiled plan and runtime results:
//   registration  — every target blocking check has exactly one registry row;
//   implementation— every registered validator id resolves to an executable
//                   (an implemented builtin, or the exact hash-bound target
//                   command the plan dispatched);
//   dispatch      — every registered mechanism is dispatched by the plan with
//                   an identical typed tuple;
//   emission      — every registered pre-finalization mechanism produced a
//                   result in this run;
//   liveness      — every row meets the configured minimum status, declared
//                   as a hash-bound check input selector.
// Consumption and disposition effect are enforced by the reducer, which
// consumes every blocking result exactly once, and re-proven offline by the
// receipt verifier. Kernel-mandatory checks are governed by the kernel's own
// registry, not the target's.

const LIVENESS_ORDER = ["LANDED_ONLY", "INTEGRATED", "CANARY_PROVEN", "OPERATIONAL"];
const LIVENESS_SELECTOR = /^liveness-minimum\.(landed-only|integrated|canary-proven|operational)$/;

export function minimumLivenessOf(check) {
  for (const input of check.inputs) {
    const match = LIVENESS_SELECTOR.exec(input);
    if (match) return match[1].toUpperCase().replace(/-/g, "_");
  }
  return "INTEGRATED";
}

export function orphanClosureVerify(context) {
  const { plan, mechanismRegistry, priorResults, evidence, check } = context;
  if (!mechanismRegistry) {
    return {
      outcome: "INFRA_FAILURE",
      reasonCodes: ["INFRASTRUCTURE_FAILURE"],
      details: { failure: "orphan-closure requires a declared mechanism registry" }
    };
  }

  const reasonCodes = new Set();
  const findings = [];
  const mandatory = new Set(MANDATORY_PACK_IDS);
  const kernelSelectable = new Set(["prior-art-admission", "orphan-closure"]);

  const targetChecks = plan.checks.filter(
    (c) =>
      c.effect === "BLOCKING" &&
      c.resultConsumer === "DISPOSITION_REDUCER" &&
      !mandatory.has(c.packId) &&
      !kernelSelectable.has(c.packId)
  );
  const dispatchedById = new Map(targetChecks.map((c) => [c.checkId, c]));
  const registeredById = new Map(mechanismRegistry.mechanisms.map((m) => [m.mechanismId, m]));
  const implementedBuiltins = implementedBuiltinValidatorIds();
  const resultByCheckId = new Map(priorResults.map((r) => [r.checkId, r]));
  const minimumLiveness = minimumLivenessOf(check);
  const minimumIndex = LIVENESS_ORDER.indexOf(minimumLiveness);

  for (const mechanism of mechanismRegistry.mechanisms) {
    const dispatched = dispatchedById.get(mechanism.mechanismId);
    if (!dispatched) {
      reasonCodes.add("ORPHAN_IMPLEMENTED_NOT_DISPATCHED");
      findings.push({ mechanismId: mechanism.mechanismId, class: "REGISTERED_NOT_DISPATCHED" });
      continue;
    }
    // Typed-tuple equality: a registry row for a different validator, phase,
    // effect, or consumer under the same id is an orphan, not a match.
    const dispatchedValidatorId = planCheckValidatorId(dispatched);
    const tupleMatches =
      mechanism.validatorId === dispatchedValidatorId &&
      mechanism.activationPhase === dispatched.phase &&
      mechanism.effect === dispatched.effect &&
      mechanism.resultConsumer === dispatched.resultConsumer;
    if (!tupleMatches) {
      reasonCodes.add("ORPHAN_IMPLEMENTED_NOT_DISPATCHED");
      findings.push({ mechanismId: mechanism.mechanismId, class: "TUPLE_MISMATCH", dispatchedValidatorId });
    }
    // Implementation resolution: builtin ids must be implemented in this
    // kernel; target ids must be exactly the hash-bound dispatched command.
    const validatorResolves = mechanism.validatorId.startsWith("target:")
      ? mechanism.validatorId === dispatchedValidatorId
      : implementedBuiltins.has(mechanism.validatorId);
    if (!validatorResolves) {
      reasonCodes.add("ORPHAN_REGISTERED_NOT_IMPLEMENTED");
      findings.push({ mechanismId: mechanism.mechanismId, class: "REGISTERED_NOT_IMPLEMENTED" });
    }
    // Emission: pre-finalization mechanisms must have produced a result.
    if (mechanism.activationPhase !== "PROMOTION_FINALIZATION" && !resultByCheckId.has(mechanism.mechanismId)) {
      reasonCodes.add("ORPHAN_DISPATCHED_NOT_EMITTED");
      findings.push({ mechanismId: mechanism.mechanismId, class: "DISPATCHED_NOT_EMITTED" });
    }
    if (LIVENESS_ORDER.indexOf(mechanism.status) < minimumIndex) {
      reasonCodes.add("LIVENESS_BELOW_THRESHOLD");
      findings.push({ mechanismId: mechanism.mechanismId, class: "LIVENESS_BELOW_THRESHOLD", status: mechanism.status });
    }
  }

  for (const targetCheck of targetChecks) {
    if (!registeredById.has(targetCheck.checkId)) {
      reasonCodes.add("ORPHAN_DISPATCHED_NOT_IMPLEMENTED");
      findings.push({ mechanismId: targetCheck.checkId, class: "DISPATCHED_NOT_REGISTERED" });
    }
  }

  const details = {
    minimumLiveness,
    targetBlockingChecks: targetChecks.map((c) => c.checkId).sort(),
    registeredMechanisms: mechanismRegistry.mechanisms.map((m) => m.mechanismId).sort(),
    findings
  };
  const evidenceRefs = [];
  if (evidence) {
    evidenceRefs.push(
      evidence.put({
        artifactId: "orphan-closure-report",
        checkId: check.checkId,
        validatorId: "orphan-closure-verify@1",
        bytes: Buffer.from(canonicalize(details), "utf8"),
        mediaType: "application/json"
      })
    );
  }
  return {
    outcome: reasonCodes.size > 0 ? "FIRED" : "PASS",
    reasonCodes: [...reasonCodes].sort(),
    evidence: evidenceRefs,
    details
  };
}
