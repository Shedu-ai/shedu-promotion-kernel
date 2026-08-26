import { readFileSync } from "node:fs";
import { CanonicalJsonError, parseStrict, validateRelativePath } from "./canonical-json.mjs";
import { validateAgainstSchema } from "./json-schema.mjs";
import { isReasonCode } from "./reason-codes.mjs";

const SCHEMA_FILES = {
  "work-contract@1": "work-contract.schema.json",
  "policy-pack@1": "policy-pack.schema.json",
  "policy-profile@1": "policy-profile.schema.json",
  "compiled-policy-plan@1": "compiled-policy-plan.schema.json",
  "promotion-receipt@1": "promotion-receipt.schema.json",
  "capability-index@1": "capability-index.schema.json",
  "mechanism-registry@1": "mechanism-registry.schema.json",
  "check-result@1": "check-result.schema.json",
  "orphan-census@1": "orphan-census.schema.json",
  "command-report@1": "command-report.schema.json",
  "evidence-index@1": "evidence-index.schema.json"
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

function envAllowlistSecretErrors(names, location) {
  const out = [];
  for (const name of names) {
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
    if (doc.capabilityIndex !== null) {
      errors.push(...pathErrors([doc.capabilityIndex.path], "capabilityIndex.path"));
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

  "promotion-receipt@1": (doc) => {
    const errors = pathErrors(doc.changedFiles.map((f) => f.path), "changedFiles.path");
    errors.push(...reasonCodeErrors(doc.reasonCodes, "reasonCodes"));
    for (const result of doc.checkResults) {
      errors.push(...reasonCodeErrors(result.reasonCodes, `checkResults[${result.checkId}].reasonCodes`));
    }
    return errors;
  }
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
