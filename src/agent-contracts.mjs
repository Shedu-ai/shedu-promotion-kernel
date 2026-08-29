import { validateValue } from "./contracts.mjs";
import { actionsForAdmission, actionsForEvaluation } from "./next-actions.mjs";

const contradiction = (message) => ({ reasonCode: "SCHEMA_VIOLATION", message });

// Projection-only semantic validation. Keeping this layer outside
// contracts.mjs preserves the source dependency direction: presentation may
// consume authority contracts, while admission/evaluation/reduction never
// import presentation or next-action logic.
export function validateAgentProjection(kind, value) {
  const base = validateValue(kind, value);
  if (!base.ok) return base;
  const errors = [];
  if (kind === "kernel-agent-status@1") {
    const expected = actionsForAdmission(value.promotionEntrypointAvailable);
    if (JSON.stringify(value.nextActions) !== JSON.stringify(expected)) {
      errors.push(contradiction("nextActions contradict the projected admission state"));
    }
  } else if (kind === "kernel-evaluation-summary@1") {
    let expected;
    try {
      expected = actionsForEvaluation({
        evaluationState: value.evaluationState,
        disposition: value.disposition ?? null,
        reasonCodes: value.reasonCodes ?? [],
        checkResults: value.nonPassingChecks ?? []
      });
    } catch (error) {
      errors.push(contradiction(`nextActions cannot be derived: ${String(error)}`));
    }
    if (expected !== undefined && JSON.stringify(value.nextActions) !== JSON.stringify(expected)) {
      errors.push(contradiction("nextActions contradict the verified evaluation results"));
    }
  }
  return errors.length === 0 ? base : { ok: false, errors };
}
