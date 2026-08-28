// Closed execution classes and task ceilings for bounded target-command
// execution. Linux cgroup pids.max counts tasks (processes + threads), so the
// authority deliberately uses maxTasks and never pretends it is a process-only
// count.

export const EXECUTION_CLASSES = Object.freeze([
  "SINGLE_PROCESS",
  "BOUNDED_PROCESS_TREE"
]);

export const MIN_TASKS = 8;
export const MAX_TASKS = 512;

export const EXECUTION_PRESETS = Object.freeze({
  STRICT: Object.freeze({ class: "SINGLE_PROCESS", maxTasks: 64 }),
  STANDARD_TEST: Object.freeze({ class: "BOUNDED_PROCESS_TREE", maxTasks: 128 })
});

export const EXECUTION_CAPABILITY_IDS = Object.freeze({
  SINGLE_PROCESS: "single-process@1",
  BOUNDED_PROCESS_TREE: "bounded-process-tree@1"
});

export function isExecutionRequirement(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\0") === "class\0maxTasks" &&
    EXECUTION_CLASSES.includes(value.class) &&
    Number.isSafeInteger(value.maxTasks) &&
    value.maxTasks >= MIN_TASKS &&
    value.maxTasks <= MAX_TASKS
  );
}

export function strictExecutionRequirement() {
  return { ...EXECUTION_PRESETS.STRICT };
}

export function executionCapabilityId(executionClass) {
  const capabilityId = EXECUTION_CAPABILITY_IDS[executionClass];
  if (capabilityId === undefined) throw new Error(`unknown execution class ${JSON.stringify(executionClass)}`);
  return capabilityId;
}

export function runtimeExecutionRequirement(compiledExecution) {
  if (!compiledExecution || typeof compiledExecution !== "object") {
    throw new Error("compiled execution authority is required");
  }
  const value = { class: compiledExecution.class, maxTasks: compiledExecution.maxTasks };
  if (!isExecutionRequirement(value)) throw new Error("compiled execution authority has no valid runtime requirement");
  return value;
}

export function executionRequirementFor({ requirement, contractCeiling, profileCeiling }) {
  for (const [name, value] of [
    ["execution requirement", requirement],
    ["work-contract execution ceiling", contractCeiling],
    ["policy-profile execution ceiling", profileCeiling]
  ]) {
    if (!isExecutionRequirement(value)) {
      return {
        ok: false,
        reasonCode: "SCHEMA_VIOLATION",
        message: `${name} is not a closed execution requirement`
      };
    }
  }

  if (
    requirement.class === "BOUNDED_PROCESS_TREE" &&
    (contractCeiling.class !== "BOUNDED_PROCESS_TREE" || profileCeiling.class !== "BOUNDED_PROCESS_TREE")
  ) {
    return {
      ok: false,
      reasonCode: "PROCESS_TREE_UNAUTHORIZED",
      message: "bounded process-tree execution is not authorized by both the work contract and policy profile"
    };
  }
  if (requirement.maxTasks > contractCeiling.maxTasks || requirement.maxTasks > profileCeiling.maxTasks) {
    return {
      ok: false,
      reasonCode: "PROCESS_TREE_UNAUTHORIZED",
      message: `required task ceiling ${requirement.maxTasks} exceeds an authorized ceiling`
    };
  }

  // The requirement is exact. Higher authority ceilings never widen the
  // runtime surface and are retained only in the source authority digests.
  return { ok: true, value: { ...requirement } };
}

export function executionRequirementForLegacyContract() {
  return strictExecutionRequirement();
}
