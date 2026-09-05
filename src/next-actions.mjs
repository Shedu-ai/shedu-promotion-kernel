import { readFileSync } from "node:fs";
import { REASON_CODES } from "./reason-codes.mjs";

// One source of truth for the closed action-lane vocabulary. The status
// schemas deliberately use only a shape constraint; contracts.mjs enforces
// membership against this enum so the vocabulary cannot drift between files.
const actionSchema = JSON.parse(
  readFileSync(new URL("../schemas/kernel-next-action.schema.json", import.meta.url), "utf8")
);
const agentStatusSchema = JSON.parse(
  readFileSync(new URL("../schemas/kernel-agent-status.schema.json", import.meta.url), "utf8")
);
const agentStatusV2Schema = JSON.parse(
  readFileSync(new URL("../schemas/kernel-agent-status-v2.schema.json", import.meta.url), "utf8")
);
const evaluationSummarySchema = JSON.parse(
  readFileSync(new URL("../schemas/kernel-evaluation-summary.schema.json", import.meta.url), "utf8")
);

export const NEXT_ACTIONS = Object.freeze([...actionSchema.enum]);
const ACTION_SET = new Set(NEXT_ACTIONS);

const freezeMap = (entries) => Object.freeze(Object.fromEntries(
  entries.map(([reasonCode, actions]) => [reasonCode, Object.freeze([...actions])])
));

// Exhaustive reason-code → action-lane classification. This is navigation,
// not authority: the values contain no argv and cannot alter a work contract,
// result, reducer, receipt, admission outcome, or promotion disposition.
export const REASON_ACTIONS = freezeMap([
  ["MALFORMED_JSON", ["RETURN_TO_AUTHORIZER"]],
  ["DUPLICATE_JSON_KEY", ["RETURN_TO_AUTHORIZER"]],
  ["DOCUMENT_BOUNDS_EXCEEDED", ["RETURN_TO_AUTHORIZER"]],
  ["NON_CANONICAL_NUMBER", ["RETURN_TO_AUTHORIZER"]],
  ["SCHEMA_VIOLATION", ["RETURN_TO_AUTHORIZER"]],
  ["SECRET_BEARING_FIELD", ["RETURN_TO_AUTHORIZER"]],
  ["PATH_NOT_CONTAINED", ["RETURN_TO_AUTHORIZER"]],
  ["SCOPE_SET_CONFLICT", ["RETURN_TO_AUTHORIZER"]],
  ["DUPLICATE_COMMAND_ID", ["RETURN_TO_AUTHORIZER"]],
  ["DUPLICATE_CHECK_ID", ["RETURN_TO_AUTHORIZER"]],
  ["DUPLICATE_PACK_ID", ["RETURN_TO_AUTHORIZER"]],
  ["DUPLICATE_ENTRY_ID", ["RETURN_TO_AUTHORIZER"]],
  ["EVIDENCE_ONLY_BLOCKING_CONFLICT", ["RETURN_TO_AUTHORIZER"]],
  ["PHASE_NOT_DECLARED", ["RETURN_TO_AUTHORIZER"]],
  ["MOVING_REF_REJECTED", ["RETURN_TO_AUTHORIZER"]],
  ["AUTHORITY_OBJECT_MISSING", ["RETURN_TO_AUTHORIZER"]],
  ["AUTHORITY_PATH_NOT_BLOB", ["RETURN_TO_AUTHORIZER"]],
  ["AUTHORITY_DIGEST_MISMATCH", ["RETURN_TO_AUTHORIZER"]],
  ["PROFILE_IDENTITY_MISMATCH", ["RETURN_TO_AUTHORIZER"]],
  ["PACK_IDENTITY_MISMATCH", ["RETURN_TO_AUTHORIZER"]],
  ["PACK_NOT_FOUND", ["RETURN_TO_AUTHORIZER"]],
  ["PACK_NOT_SELECTED", ["RETURN_TO_AUTHORIZER"]],
  ["PACK_DIGEST_MISMATCH", ["RETURN_TO_AUTHORIZER"]],
  ["DEPENDENCY_UNSATISFIED", ["RETURN_TO_AUTHORIZER"]],
  ["DEPENDENCY_CYCLE", ["RETURN_TO_AUTHORIZER"]],
  ["PHASE_ORDER_CONFLICT", ["RETURN_TO_AUTHORIZER"]],
  ["UNKNOWN_VALIDATOR", ["RETURN_TO_AUTHORIZER"]],
  ["UNKNOWN_CHECK_STRENGTHENED", ["RETURN_TO_AUTHORIZER"]],
  ["STRENGTHEN_CONFLICT", ["RETURN_TO_AUTHORIZER"]],
  ["POLICY_CONFLICT", ["RETURN_TO_AUTHORIZER"]],
  ["PLAN_ORDER_VIOLATION", ["RETURN_TO_AUTHORIZER"]],
  ["ORPHAN_REGISTERED_NOT_IMPLEMENTED", ["RETURN_TO_AUTHORIZER"]],
  ["ORPHAN_IMPLEMENTED_NOT_REGISTERED", ["RETURN_TO_AUTHORIZER"]],
  ["ORPHAN_IMPLEMENTED_NOT_DISPATCHED", ["RETURN_TO_AUTHORIZER"]],
  ["ORPHAN_DISPATCHED_NOT_IMPLEMENTED", ["RETURN_TO_AUTHORIZER"]],
  ["ORPHAN_DISPATCHED_NOT_EMITTED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["ORPHAN_EMITTED_NOT_DISPATCHED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["ORPHAN_EMITTED_NOT_CONSUMED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["ORPHAN_CONSUMED_NOT_EMITTED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["INVALID_EXCLUSION", ["RETURN_TO_AUTHORIZER"]],
  ["CHECK_FIRED", ["REPAIR_CANDIDATE"]],
  ["MISSING_REQUIRED_RESULT", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["DUPLICATE_RESULT", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["RESULT_BINDING_MISMATCH", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["INFRASTRUCTURE_FAILURE", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["OUTPUT_BUSY", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["CANDIDATE_NOT_DESCENDANT", ["REPAIR_CANDIDATE"]],
  ["WORKSPACE_DIRTY", ["REPAIR_CANDIDATE"]],
  ["CANDIDATE_TREE_UNSTABLE", ["REPAIR_CANDIDATE"]],
  ["SCOPE_FORBIDDEN_CHANGE", ["REPAIR_CANDIDATE"]],
  ["SCOPE_READONLY_CHANGE", ["REPAIR_CANDIDATE"]],
  ["SCOPE_UNCLASSIFIED_CHANGE", ["REPAIR_CANDIDATE"]],
  ["SCOPE_CASE_COLLISION", ["REPAIR_CANDIDATE"]],
  ["SCOPE_SYMLINK_ESCAPE", ["REPAIR_CANDIDATE"]],
  ["COMMAND_FAILED", ["REPAIR_CANDIDATE"]],
  ["COMMAND_TIMEOUT", ["REPAIR_CANDIDATE", "REPAIR_EVALUATION_ENVIRONMENT"]],
  ["PROCESS_TREE_UNAUTHORIZED", ["RETURN_TO_AUTHORIZER"]],
  ["TASK_BUDGET_EXCEEDED", ["RETURN_TO_AUTHORIZER", "REPAIR_CANDIDATE"]],
  ["EXECUTION_BACKEND_REQUIRED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["CHECK_SKIPPED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["DEADLINE_EXCEEDED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["SANDBOX_UNAVAILABLE", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["TOOLCHAIN_UNRESOLVED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["ACTIVATION_EVIDENCE_INVALID", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["LIFECYCLE_EVIDENCE_INVALID", ["COMPLETE_PILOT_QUALIFICATION"]],
  ["LIFECYCLE_ATTESTATION_INVALID", ["OBTAIN_PILOT_ATTESTATION"]],
  ["LIFECYCLE_EXPIRED", ["RENEW_LIFECYCLE_EVIDENCE", "PROCESS_LIFECYCLE_DOWNGRADE"]],
  ["LIFECYCLE_PREDECESSOR_MISMATCH", ["OBTAIN_PILOT_ATTESTATION"]],
  ["LIFECYCLE_SEQUENCE_INVALID", ["OBTAIN_PILOT_ATTESTATION"]],
  ["PRIOR_ART_COLLISION", ["RETURN_TO_AUTHORIZER", "REPAIR_CANDIDATE"]],
  ["REVIEW_REQUIRED", ["RETURN_TO_AUTHORIZER"]],
  ["LIVENESS_BELOW_THRESHOLD", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["EVIDENCE_MISSING", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["EVIDENCE_MUTATED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["RECEIPT_MUTATED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["RECEIPT_REPLAY", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["SIGNATURE_INVALID", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["DISPOSITION_MISMATCH", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["NOT_ADMITTED", ["OBTAIN_EXTERNAL_ADMISSION"]],
  ["CONTROL_UNREGISTERED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["CONTROL_UNIMPLEMENTED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["CONTROL_UNPROVEN", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["CONTROL_UNOBSERVED", ["REPAIR_EVALUATION_ENVIRONMENT"]],
  ["AUTHORIZATION_INVALID", ["RETURN_TO_AUTHORIZER"]],
  ["KERNEL_NOT_IMPLEMENTED", ["NONE"]],
  ["CLI_USAGE", ["NONE"]]
]);

export function isNextAction(value) {
  return ACTION_SET.has(value);
}

export function auditNextActionRegistry() {
  const reasonSet = new Set(REASON_CODES);
  const mapped = Object.keys(REASON_ACTIONS);
  const missingReasonCodes = REASON_CODES.filter((code) => !Object.hasOwn(REASON_ACTIONS, code));
  const unknownReasonCodes = mapped.filter((code) => !reasonSet.has(code));
  const unknownActions = [];
  for (const [code, actions] of Object.entries(REASON_ACTIONS)) {
    if (actions.length === 0 || new Set(actions).size !== actions.length) unknownActions.push(`${code}:invalid-cardinality`);
    for (const action of actions) if (!ACTION_SET.has(action)) unknownActions.push(`${code}:${action}`);
  }
  const reachable = new Set([
    "OBTAIN_EXTERNAL_ADMISSION",
    "SUBMIT_EVALUATION",
    "VERIFY_PROMOTABLE_RECEIPT",
    "EXTERNAL_PROMOTION_DECISION_AVAILABLE",
    "RUN_BOUNDED_OPERATIONAL_PILOT",
    "COMPLETE_OPERATIONAL_CERTIFICATION"
  ]);
  for (const actions of Object.values(REASON_ACTIONS)) for (const action of actions) reachable.add(action);
  const unreachableActions = NEXT_ACTIONS.filter((action) => !reachable.has(action));
  const schemaActionDrift = [];
  for (const [schemaId, values] of [
    ["kernel-agent-status@1", agentStatusSchema.$defs?.nextActions?.items?.enum],
    ["kernel-agent-status@2", agentStatusV2Schema.properties?.nextActions?.items?.enum],
    ["kernel-evaluation-summary@1", evaluationSummarySchema.$defs?.nextActions?.items?.enum]
  ]) {
    if (JSON.stringify(values) !== JSON.stringify(NEXT_ACTIONS)) schemaActionDrift.push(schemaId);
  }
  return {
    complete: missingReasonCodes.length === 0 && unknownReasonCodes.length === 0 &&
      unknownActions.length === 0 && unreachableActions.length === 0 && schemaActionDrift.length === 0,
    reasonCodes: REASON_CODES.length,
    mappings: mapped.length,
    missingReasonCodes,
    unknownReasonCodes,
    unknownActions,
    unreachableActions,
    schemaActionDrift
  };
}

const orderActions = (actions) => {
  const selected = new Set(actions);
  if (selected.size > 1) selected.delete("NONE");
  const ordered = NEXT_ACTIONS.filter((action) => selected.has(action));
  return ordered.length > 0 ? ordered : ["NONE"];
};

export function actionsForAdmission(admitted) {
  return admitted === true ? ["SUBMIT_EVALUATION"] : ["OBTAIN_EXTERNAL_ADMISSION"];
}

export function actionsForLifecycle(status, { lifecycleEvidencePresent = false, failureCode = null } = {}) {
  if (status === "FOUNDATION_ONLY") return ["OBTAIN_EXTERNAL_ADMISSION"];
  if (status === "EXPERIMENTAL") {
    if (failureCode === "LIFECYCLE_EXPIRED") return ["RENEW_LIFECYCLE_EVIDENCE", "PROCESS_LIFECYCLE_DOWNGRADE"];
    if (["LIFECYCLE_ATTESTATION_INVALID", "LIFECYCLE_PREDECESSOR_MISMATCH", "LIFECYCLE_SEQUENCE_INVALID"].includes(failureCode)) {
      return ["OBTAIN_PILOT_ATTESTATION"];
    }
    return ["COMPLETE_PILOT_QUALIFICATION"];
  }
  if (status === "PILOT_ELIGIBLE") {
    return failureCode === "LIFECYCLE_EXPIRED"
      ? ["RENEW_LIFECYCLE_EVIDENCE", "PROCESS_LIFECYCLE_DOWNGRADE"]
      : ["SUBMIT_EVALUATION", "RUN_BOUNDED_OPERATIONAL_PILOT", "COMPLETE_OPERATIONAL_CERTIFICATION"];
  }
  if (status === "CERTIFIED") {
    return failureCode === "LIFECYCLE_EXPIRED"
      ? ["RENEW_LIFECYCLE_EVIDENCE", "PROCESS_LIFECYCLE_DOWNGRADE"]
      : ["SUBMIT_EVALUATION", "RENEW_LIFECYCLE_EVIDENCE"];
  }
  throw new TypeError(`unknown lifecycle status ${String(status)}`);
}

export function actionsForEvaluation({ evaluationState, disposition = null, reasonCodes = [], checkResults = [] }) {
  if (evaluationState === "ABSENT") return ["SUBMIT_EVALUATION"];
  if (evaluationState !== "PRESENT") throw new TypeError(`unknown evaluation state ${String(evaluationState)}`);
  if (disposition === "PROMOTABLE") {
    return ["VERIFY_PROMOTABLE_RECEIPT", "EXTERNAL_PROMOTION_DECISION_AVAILABLE"];
  }
  if (disposition !== "BLOCKED") throw new TypeError(`unknown disposition ${String(disposition)}`);

  const actions = [];
  const codes = [...reasonCodes];
  for (const result of checkResults) {
    if (result.outcome === "INFRA_FAILURE" || result.outcome === "SKIPPED") {
      actions.push("REPAIR_EVALUATION_ENVIRONMENT");
    }
    codes.push(...result.reasonCodes);
  }
  for (const code of codes) {
    const mapped = REASON_ACTIONS[code];
    if (mapped === undefined) throw new TypeError(`unmapped reason code ${String(code)}`);
    actions.push(...mapped);
  }
  return orderActions(actions);
}

const audit = auditNextActionRegistry();
if (!audit.complete) {
  throw new Error(`next-action registry is incomplete: ${JSON.stringify(audit)}`);
}
