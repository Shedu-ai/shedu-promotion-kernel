import { readFileSync } from "node:fs";
import { CanonicalJsonError, parseStrict, validateRelativePath } from "./canonical-json.mjs";
import { validateAgainstSchema } from "./json-schema.mjs";
import { isReasonCode } from "./reason-codes.mjs";
import { EXECUTION_PRESETS, executionCapabilityId, isExecutionRequirement } from "./execution-policy.mjs";

const SCHEMA_FILES = {
  "work-contract@1": "work-contract.schema.json",
  "work-contract@2": "work-contract-v2.schema.json",
  "policy-pack@1": "policy-pack.schema.json",
  "policy-pack@2": "policy-pack-v2.schema.json",
  "policy-profile@1": "policy-profile.schema.json",
  "policy-profile@2": "policy-profile-v2.schema.json",
  "compiled-policy-plan@1": "compiled-policy-plan.schema.json",
  "compiled-policy-plan@2": "compiled-policy-plan-v2.schema.json",
  "promotion-receipt@1": "promotion-receipt.schema.json",
  "promotion-receipt@2": "promotion-receipt-v2.schema.json",
  "capability-index@1": "capability-index.schema.json",
  "mechanism-registry@1": "mechanism-registry.schema.json",
  "check-result@1": "check-result.schema.json",
  "orphan-census@1": "orphan-census.schema.json",
  "command-report@1": "command-report.schema.json",
  "command-report@2": "command-report-v2.schema.json",
  "evidence-index@1": "evidence-index.schema.json",
  "prior-art-query@1": "prior-art-query.schema.json",
  "conformance-status@2": "conformance-status.schema.json",
  "conformance-attestation@1": "conformance-attestation.schema.json",
  "control-surface@1": "control-surface.schema.json",
  "execution-capabilities@1": "execution-capabilities.schema.json"
};

const schemas = new Map(
  Object.entries(SCHEMA_FILES).map(([kind, file]) => [
    kind,
    JSON.parse(readFileSync(new URL(`../schemas/${file}`, import.meta.url), "utf8"))
  ])
);

export const CONTRACT_KINDS = Object.freeze(Object.keys(SCHEMA_FILES));

const err = (reasonCode, message, path) => (path ? { reasonCode, message, path } : { reasonCode, message });

function duplicateIds(ids) {
  const seen = new Set();
  const dups = new Set();
  for (const id of ids) {
    if (seen.has(id)) dups.add(id);
    seen.add(id);
  }
  return [...dups];
}

// Secret handling. The enforceable guarantee is structural, not semantic:
// no contract or pack field can carry an environment VALUE, credential-named
// environment names cannot be allowlisted, and all argv is treated as public
// non-secret configuration — recorded in plans, receipts, and evidence in
// the clear. The (phase-4) runner must construct a clean environment from
// the name allowlist, never inheriting ambient secrets. The detectors below
// are defense-in-depth for credential-NAMED flags and credential-SHAPED
// values; they cannot prove an arbitrary string contains no secret, and no
// claim here says otherwise. They over-reject rather than under-reject.
const SECRET_WORDS = new Set([
  "token",
  "secret",
  "password",
  "passwd",
  "apikey",
  "credential",
  "credentials",
  "bearer",
  "auth",
  "authorization"
]);
const SECRET_WORD_PAIRS = [
  ["api", "key"],
  ["access", "key"],
  ["private", "key"],
  ["session", "key"],
  ["secret", "key"],
  ["client", "secret"]
];
const CREDENTIAL_VALUE_PREFIXES = [
  "sk-", "sk_", "pk_", "rk_",
  "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
  "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xapp-",
  "glpat-", "npm_", "AKIA", "ASIA", "AGE-SECRET-KEY-"
];
const PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;

function wordsNameSecret(words) {
  if (words.some((w) => SECRET_WORDS.has(w))) return true;
  for (let i = 0; i < words.length - 1; i += 1) {
    for (const [a, b] of SECRET_WORD_PAIRS) {
      if (words[i] === a && words[i + 1] === b) return true;
    }
  }
  return false;
}

function argvSecretErrors(argv, location) {
  const out = [];
  for (const element of argv) {
    if (PRIVATE_KEY_RE.test(element)) {
      out.push(err("SECRET_BEARING_FIELD", `${location}: argv element embeds a private key block`));
      continue;
    }
    let candidateValue = element;
    const flag = /^--?([A-Za-z0-9._-]+)(?:=([\s\S]*))?$/.exec(element);
    if (flag) {
      const words = flag[1].toLowerCase().split(/[-_.]/).filter(Boolean);
      if (wordsNameSecret(words)) {
        out.push(err("SECRET_BEARING_FIELD", `${location}: argv flag ${flag[1]} names a credential; secrets must flow through the runner environment, never argv`));
        continue;
      }
      candidateValue = flag[2] ?? "";
    }
    if (CREDENTIAL_VALUE_PREFIXES.some((p) => candidateValue.startsWith(p))) {
      out.push(err("SECRET_BEARING_FIELD", `${location}: argv element carries a credential-shaped value`));
    }
  }
  return out;
}

export function isSecretEnvName(name) {
  return wordsNameSecret(name.toLowerCase().split("_").filter(Boolean));
}

export function isReservedInternalEnvName(name) {
  return typeof name === "string" && name.startsWith("SHEDU_INTERNAL_");
}

function envAllowlistSecretErrors(names, location) {
  const out = [];
  for (const name of names) {
    if (isReservedInternalEnvName(name)) {
      out.push(err("SCHEMA_VIOLATION", `${location}: environment name ${name} is reserved for kernel-to-supervisor authority`));
      continue;
    }
    const words = name.toLowerCase().split("_").filter(Boolean);
    if (wordsNameSecret(words)) {
      out.push(err("SECRET_BEARING_FIELD", `${location}: environment name ${name} names a credential and cannot be allowlisted`));
    }
  }
  return out;
}

function pathErrors(paths, location, opts) {
  const out = [];
  for (const p of paths) {
    const v = validateRelativePath(p, opts);
    if (!v.ok) out.push(err("PATH_NOT_CONTAINED", `${location}: ${v.message}: ${JSON.stringify(p)}`));
  }
  return out;
}

// reason-code@1 is a closed set; the schemas' uppercase pattern is only a
// shape check, so membership is enforced here against the single source.
function reasonCodeErrors(codes, location) {
  const out = [];
  for (const code of codes) {
    if (!isReasonCode(code)) {
      out.push(err("SCHEMA_VIOLATION", `${location}: ${code} is not in the closed reason-code@1 set`));
    }
  }
  return out;
}

function executionRequirementErrors(value, location) {
  if (!isExecutionRequirement(value)) {
    return [err("SCHEMA_VIOLATION", `${location} is not a closed execution requirement`)];
  }
  if (value.class === "SINGLE_PROCESS" && value.maxTasks !== EXECUTION_PRESETS.STRICT.maxTasks) {
    return [err("SCHEMA_VIOLATION", `${location}: SINGLE_PROCESS must use the fixed STRICT task ceiling` )];
  }
  if (value.class === "BOUNDED_PROCESS_TREE" && value.maxTasks <= EXECUTION_PRESETS.STRICT.maxTasks) {
    return [err("SCHEMA_VIOLATION", `${location}: BOUNDED_PROCESS_TREE must exceed the STRICT task allowance`)];
  }
  return [];
}

function compiledExecutionErrors(value, location) {
  const errors = executionRequirementErrors(
    { class: value?.class, maxTasks: value?.maxTasks },
    location
  );
  if (errors.length > 0) return errors;
  if (value.capabilityId !== executionCapabilityId(value.class)) {
    errors.push(err("SCHEMA_VIOLATION", `${location}: capability id does not match the execution class`));
  }
  if (value.class === "BOUNDED_PROCESS_TREE" && value.portableAuthorityDigest === null) {
    errors.push(err("SCHEMA_VIOLATION", `${location}: bounded execution must bind a portable authority digest`));
  }
  if (value.class === "SINGLE_PROCESS" && value.portableAuthorityDigest !== null) {
    errors.push(err("SCHEMA_VIOLATION", `${location}: single-process execution has no portable Linux-only authority`));
  }
  return errors;
}

const SEMANTIC = {
  "work-contract@1": (doc) => {
    const errors = [];
    const setNames = ["allowed", "readonly", "forbidden"];
    for (const name of setNames) {
      errors.push(...pathErrors(doc.scope[name], `scope.${name}`, { allowDirPrefix: true }));
    }
    const seen = new Map();
    for (const name of setNames) {
      for (const p of doc.scope[name]) {
        if (seen.has(p) && seen.get(p) !== name) {
          errors.push(err("SCOPE_SET_CONFLICT", `path ${JSON.stringify(p)} appears in scope.${seen.get(p)} and scope.${name}`));
        }
        seen.set(p, name);
      }
    }
    errors.push(...pathErrors([doc.policyProfile.path], "policyProfile.path"));
    for (const field of ["capabilityIndex", "priorArtQuery", "mechanismRegistry"]) {
      if (doc[field] !== null) {
        errors.push(...pathErrors([doc[field].path], `${field}.path`));
      }
    }
    errors.push(...pathErrors([doc.artifactRoot], "artifactRoot", { allowDirPrefix: true }));
    for (const id of duplicateIds(doc.validationCommands.map((c) => c.commandId))) {
      errors.push(err("DUPLICATE_COMMAND_ID", `validation command id ${id} is declared more than once`));
    }
    for (const command of doc.validationCommands) {
      errors.push(...argvSecretErrors(command.argv, `validationCommands[${command.commandId}]`));
    }
    return errors;
  },

  "policy-pack@1": (doc) => {
    const errors = [];
    for (const id of duplicateIds(doc.checks.map((c) => c.checkId))) {
      errors.push(err("DUPLICATE_CHECK_ID", `check id ${id} is declared more than once in pack ${doc.packId}`));
    }
    for (const id of duplicateIds(doc.dependencies.map((d) => d.packId))) {
      errors.push(err("DUPLICATE_PACK_ID", `pack ${doc.packId} declares dependency ${id} more than once`));
    }
    for (const dep of doc.dependencies) {
      if (dep.packId === doc.packId) {
        errors.push(err("DEPENDENCY_CYCLE", `pack ${doc.packId} depends on itself`));
      }
    }
    for (const check of doc.checks) {
      if (!doc.phases.includes(check.phase)) {
        errors.push(err("PHASE_NOT_DECLARED", `check ${check.checkId} runs in ${check.phase}, which pack ${doc.packId} does not declare`));
      }
      if (check.effect === "BLOCKING" && check.resultConsumer !== "DISPOSITION_REDUCER") {
        errors.push(err("EVIDENCE_ONLY_BLOCKING_CONFLICT", `check ${check.checkId} is BLOCKING but its result never reaches the disposition reducer`));
      }
      if (check.validator.kind === "TARGET_COMMAND") {
        errors.push(...argvSecretErrors(check.validator.argv, `checks[${check.checkId}].validator.argv`));
        errors.push(...pathErrors(check.validator.inputManifest, `checks[${check.checkId}].validator.inputManifest`));
      }
      errors.push(...envAllowlistSecretErrors(check.envAllowlist, `checks[${check.checkId}].envAllowlist`));
    }
    return errors;
  },

  "policy-profile@1": (doc) => {
    const errors = [];
    for (const id of duplicateIds(doc.packs.map((p) => p.packId))) {
      errors.push(err("DUPLICATE_PACK_ID", `profile ${doc.profileId} selects pack ${id} more than once`));
    }
    errors.push(...pathErrors(doc.packs.map((p) => p.path), "packs.path"));
    return errors;
  },

  "compiled-policy-plan@1": (doc) => {
    const errors = [];
    for (const id of duplicateIds(doc.checks.map((c) => c.checkId))) {
      errors.push(err("DUPLICATE_CHECK_ID", `plan contains check id ${id} more than once`));
    }
    const seen = new Set();
    for (const check of doc.checks) {
      for (const dep of check.dependsOn) {
        if (!seen.has(dep)) {
          errors.push(err("PLAN_ORDER_VIOLATION", `check ${check.checkId} depends on ${dep}, which does not precede it in the plan`));
        }
      }
      seen.add(check.checkId);
    }
    return errors;
  },

  "capability-index@1": (doc) => {
    const errors = [];
    for (const id of duplicateIds(doc.entries.map((e) => e.capabilityId))) {
      errors.push(err("DUPLICATE_ENTRY_ID", `capability ${id} is declared more than once`));
    }
    for (const entry of doc.entries) {
      errors.push(...pathErrors(entry.canonicalFiles, `entries[${entry.capabilityId}].canonicalFiles`));
    }
    errors.push(...pathErrors(doc.generatedSurface.map((s) => s.path), "generatedSurface.path"));
    return errors;
  },

  "mechanism-registry@1": (doc) => {
    const errors = [];
    for (const id of duplicateIds(doc.mechanisms.map((m) => m.mechanismId))) {
      errors.push(err("DUPLICATE_ENTRY_ID", `mechanism ${id} is registered more than once`));
    }
    for (const mechanism of doc.mechanisms) {
      for (const id of duplicateIds(mechanism.negativeFixtures.map((f) => f.fixtureId))) {
        errors.push(err("DUPLICATE_ENTRY_ID", `mechanism ${mechanism.mechanismId} declares fixture ${id} more than once`));
      }
      if (mechanism.effect === "BLOCKING" && mechanism.resultConsumer !== "DISPOSITION_REDUCER") {
        errors.push(err("EVIDENCE_ONLY_BLOCKING_CONFLICT", `mechanism ${mechanism.mechanismId} is BLOCKING but its result never reaches the disposition reducer`));
      }
    }
    return errors;
  },

  "check-result@1": (doc) => {
    return reasonCodeErrors(doc.reasonCodes, "reasonCodes");
  },

  "prior-art-query@1": (doc) => {
    const errors = [];
    for (const id of duplicateIds(doc.queries.map((q) => q.queryId))) {
      errors.push(err("DUPLICATE_ENTRY_ID", `query ${id} is declared more than once`));
    }
    for (const id of duplicateIds(doc.declaredCollisions.map((c) => c.capabilityId))) {
      errors.push(err("DUPLICATE_ENTRY_ID", `collision resolution for ${id} is declared more than once`));
    }
    for (const collision of doc.declaredCollisions) {
      if (collision.resolution === "ALLOWED_FOLLOW_UP" && collision.followUpId === null) {
        errors.push(err("SCHEMA_VIOLATION", `collision ${collision.capabilityId} declares ALLOWED_FOLLOW_UP without a followUpId`));
      }
      if (collision.resolution === "EXCEPTION_RECEIPT" && collision.receiptRef === null) {
        errors.push(err("SCHEMA_VIOLATION", `collision ${collision.capabilityId} declares EXCEPTION_RECEIPT without a receiptRef`));
      }
    }
    return errors;
  },

  "promotion-receipt@1": (doc) => {
    const errors = pathErrors(doc.changedFiles.map((f) => f.path), "changedFiles.path");
    errors.push(...reasonCodeErrors(doc.reasonCodes, "reasonCodes"));
    for (const result of doc.checkResults) {
      errors.push(...reasonCodeErrors(result.reasonCodes, `checkResults[${result.checkId}].reasonCodes`));
    }
    return errors;
  }
};

SEMANTIC["work-contract@2"] = (doc) => {
  const errors = SEMANTIC["work-contract@1"](doc);
  errors.push(...executionRequirementErrors(doc.resourceCeilings.executionCeiling, "resourceCeilings.executionCeiling"));
  for (const command of doc.validationCommands) {
    errors.push(...executionRequirementErrors(command.executionRequirement, `validationCommands[${command.commandId}].executionRequirement`));
  }
  return errors;
};

SEMANTIC["policy-pack@2"] = (doc) => {
  const errors = SEMANTIC["policy-pack@1"](doc);
  for (const check of doc.checks) {
    if (check.validator.kind === "TARGET_COMMAND") {
      errors.push(...executionRequirementErrors(check.validator.executionRequirement, `checks[${check.checkId}].validator.executionRequirement`));
    }
  }
  return errors;
};

SEMANTIC["policy-profile@2"] = (doc) => {
  const errors = SEMANTIC["policy-profile@1"](doc);
  errors.push(...executionRequirementErrors(doc.executionPolicy, "executionPolicy"));
  return errors;
};

SEMANTIC["compiled-policy-plan@2"] = (doc) => {
  const errors = SEMANTIC["compiled-policy-plan@1"](doc);
  errors.push(...executionRequirementErrors(doc.executionPolicy.contractCeiling, "executionPolicy.contractCeiling"));
  errors.push(...executionRequirementErrors(doc.executionPolicy.profileCeiling, "executionPolicy.profileCeiling"));
  for (const command of doc.validationCommands) {
    errors.push(...compiledExecutionErrors(command.execution, `validationCommands[${command.commandId}].execution`));
  }
  for (const check of doc.checks) {
    if (check.validator.kind === "TARGET_COMMAND") {
      if (check.execution === null) errors.push(err("SCHEMA_VIOLATION", `checks[${check.checkId}].execution is required for a target command`));
      else errors.push(...compiledExecutionErrors(check.execution, `checks[${check.checkId}].execution`));
    } else if (check.execution !== null) {
      errors.push(err("SCHEMA_VIOLATION", `checks[${check.checkId}].execution must be null for a builtin validator`));
    }
  }
  return errors;
};

SEMANTIC["command-report@2"] = (doc) => {
  const errors = executionRequirementErrors(
    { class: doc.execution.class, maxTasks: doc.execution.maxTasks },
    "execution"
  );
  errors.push(...compiledExecutionErrors(doc.execution, "execution"));
  if (doc.execution.backend === "darwin-sandbox-exec" && doc.execution.class !== "SINGLE_PROCESS") {
    errors.push(err("SCHEMA_VIOLATION", "native macOS cannot claim bounded process-tree enforcement"));
  }
  if (doc.execution.backend === "linux-oci" && doc.execution.backendAuthorityDigest === null) {
    errors.push(err("SCHEMA_VIOLATION", "Linux OCI reports must bind their backend authority digest"));
  }
  return errors;
};

SEMANTIC["promotion-receipt@2"] = (doc) => {
  const errors = SEMANTIC["promotion-receipt@1"](doc);
  for (const id of duplicateIds(doc.executionReports.map((entry) => entry.commandId))) {
    errors.push(err("DUPLICATE_COMMAND_ID", `execution report ${id} is declared more than once`));
  }
  for (const entry of doc.executionReports) {
    errors.push(...SEMANTIC["command-report@2"]({ execution: entry.report }));
  }
  return errors;
};

// Validate an already-parsed value against a contract kind: schema first,
// then contract-specific semantic rules (containment, uniqueness, wiring).
export function validateValue(kind, value) {
  const schema = schemas.get(kind);
  if (!schema) throw new Error(`unknown contract kind ${kind}`);
  const schemaErrors = validateAgainstSchema(schema, value).map((e) =>
    err("SCHEMA_VIOLATION", e.message, e.path)
  );
  if (schemaErrors.length > 0) return { ok: false, errors: schemaErrors };
  const semanticErrors = (SEMANTIC[kind] ?? (() => []))(value);
  if (semanticErrors.length > 0) return { ok: false, errors: semanticErrors };
  return { ok: true, value };
}

// Validate raw document bytes: strict parse (duplicate keys, bounds,
// non-canonical numbers) before any schema logic runs.
export function validateDocument(kind, bytes) {
  let value;
  try {
    value = parseStrict(bytes);
  } catch (e) {
    if (e instanceof CanonicalJsonError) return { ok: false, errors: [err(e.reasonCode, e.message)] };
    throw e;
  }
  return validateValue(kind, value);
}

// Strict-parse once, then select only from an explicit closed version set.
// Callers never guess a version after accepting the document, and an unknown
// schemaVersion cannot fall back to an older, weaker schema.
export function validateVersionedDocument(kinds, bytes) {
  let value;
  try {
    value = parseStrict(bytes);
  } catch (e) {
    if (e instanceof CanonicalJsonError) return { ok: false, errors: [err(e.reasonCode, e.message)] };
    throw e;
  }
  const kind = value?.schemaVersion;
  if (!kinds.includes(kind)) {
    return { ok: false, errors: [err("SCHEMA_VIOLATION", `unsupported schemaVersion ${JSON.stringify(kind)}`)] };
  }
  return validateValue(kind, value);
}
