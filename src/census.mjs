import { canonicalize, digestOfCanonical } from "./canonical-json.mjs";
import { validateValue } from "./contracts.mjs";

// Control point: the two-way policy-plan mechanism census.
export const CONTROL_POINTS = Object.freeze(["policy-plan-mechanism-census"]);

// Two-way orphan census. Identity is the full typed tuple
// {id, validatorId, phase, effect, resultConsumer}, not the bare check id:
// a registry row for one validator and a plan dispatching a different
// validator, phase, effect, or consumer under the same id are different
// entries and surface as orphans in both directions. The registered,
// implemented, dispatched, emitted, and consumed sets must be equal after
// declared exclusions. Exclusions are valid only when they excuse a concrete
// missing-stage gap; duplicate entries within a stage are a census error, so
// a replayed result can never stand in for a missing one; and every tuple
// field is validated against its closed value set before set construction —
// consistently repeated garbage is a mechanical error, not a passing census.
// The census is computed from structured inputs (registry, plan, results);
// prose can never satisfy it.

export const CENSUS_STAGES = Object.freeze(["registered", "implemented", "dispatched", "emitted", "consumed"]);

const PHASES = ["CONTRACT_ADMISSION", "CANDIDATE_VALIDATION", "PROMOTION_FINALIZATION"];
const ENTRY_FIELDS = ["id", "validatorId", "phase", "effect", "resultConsumer"];

// "UNRESOLVED"/"unresolved" is the one reserved sentinel, used for a result
// that could not be bound to the plan; by construction it never matches a
// dispatched tuple, so it can only surface as an orphan.
const UNRESOLVED = "UNRESOLVED";
const KEBAB_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const VALIDATOR_ID_RE = /^([a-z0-9]+(-[a-z0-9]+)*@[1-9][0-9]*|target:sha256:[0-9a-f]{64}|unresolved)$/;
const PHASE_VALUES = new Set([...PHASES, UNRESOLVED]);
const EFFECT_VALUES = new Set(["BLOCKING", "ADVISORY", UNRESOLVED]);
const CONSUMER_VALUES = new Set(["DISPOSITION_REDUCER", "EVIDENCE_ONLY", UNRESOLVED]);

function normalizeEntry(raw, stage) {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TypeError(`census stage ${stage} contains a non-object entry; entries must be {${ENTRY_FIELDS.join(", ")}} tuples`);
  }
  const entry = {};
  for (const field of ENTRY_FIELDS) {
    const value = raw[field];
    if (typeof value !== "string" || value.length === 0) {
      throw new TypeError(`census stage ${stage} entry ${JSON.stringify(raw.id ?? "?")} is missing typed field ${field}`);
    }
    entry[field] = value;
  }
  const bad = (field, allowed) => {
    throw new TypeError(
      `census stage ${stage} entry ${JSON.stringify(entry.id)} has invalid ${field} ${JSON.stringify(entry[field])}; expected ${allowed}`
    );
  };
  if (!KEBAB_RE.test(entry.id) || entry.id.length > 128) bad("id", "a kebab-case identifier");
  if (!VALIDATOR_ID_RE.test(entry.validatorId)) bad("validatorId", "a versioned builtin id, target:sha256:<hex>, or the unresolved sentinel");
  if (!PHASE_VALUES.has(entry.phase)) bad("phase", `one of ${[...PHASE_VALUES].join(", ")}`);
  if (!EFFECT_VALUES.has(entry.effect)) bad("effect", `one of ${[...EFFECT_VALUES].join(", ")}`);
  if (!CONSUMER_VALUES.has(entry.resultConsumer)) bad("resultConsumer", `one of ${[...CONSUMER_VALUES].join(", ")}`);

  // The sentinel exists solely to mark an emitted result that could not be
  // bound to the plan. It is all-or-nothing, and it has no meaning — and no
  // admission — in the authority-side stages: a "registered but unresolved"
  // mechanism is a registry bug, not a census entry.
  const sentinelCount = [
    entry.validatorId === "unresolved",
    entry.phase === UNRESOLVED,
    entry.effect === UNRESOLVED,
    entry.resultConsumer === UNRESOLVED
  ].filter(Boolean).length;
  if (sentinelCount > 0) {
    if (sentinelCount !== 4) {
      throw new TypeError(`census stage ${stage} entry ${JSON.stringify(entry.id)} mixes sentinel and concrete fields; the unresolved sentinel is all-or-nothing`);
    }
    if (stage !== "emitted" && stage !== "consumed") {
      throw new TypeError(`census stage ${stage} cannot contain the unresolved sentinel; it marks unbindable results and is admitted only in emitted and consumed`);
    }
  }
  return entry;
}

export function runOrphanCensus({ registered, implemented, dispatched, emitted, consumed, exclusions = [] }) {
  const inputs = { registered, implemented, dispatched, emitted, consumed };
  const errors = [];
  const stageMaps = {};
  for (const stage of CENSUS_STAGES) {
    const map = new Map();
    for (const raw of inputs[stage]) {
      const entry = normalizeEntry(raw, stage);
      const key = canonicalize(entry);
      if (map.has(key)) {
        errors.push({
          reasonCode: "DUPLICATE_ENTRY_ID",
          message: `census stage ${stage} contains duplicate entry ${entry.id}; a replayed entry cannot stand in for a missing one`
        });
        continue;
      }
      map.set(key, entry);
    }
    stageMaps[stage] = map;
  }

  // Raw gaps first, exclusions second: an exclusion must correspond to at
  // least one concrete gap or it is stale and fails the census.
  const rawOrphans = [];
  for (let s = 0; s < CENSUS_STAGES.length - 1; s += 1) {
    const a = CENSUS_STAGES[s];
    const b = CENSUS_STAGES[s + 1];
    for (const [key, entry] of stageMaps[a]) {
      if (!stageMaps[b].has(key)) {
        rawOrphans.push({ entry, class: `ORPHAN_${a.toUpperCase()}_NOT_${b.toUpperCase()}`, missingStage: b });
      }
    }
    for (const [key, entry] of stageMaps[b]) {
      if (!stageMaps[a].has(key)) {
        rawOrphans.push({ entry, class: `ORPHAN_${b.toUpperCase()}_NOT_${a.toUpperCase()}`, missingStage: a });
      }
    }
  }

  const validExclusions = [];
  const suppressed = new Set();
  for (const ex of exclusions) {
    const invalid = (message) => errors.push({ reasonCode: "INVALID_EXCLUSION", message });
    if (typeof ex?.id !== "string" || ex.id.length === 0) {
      invalid("exclusion without an id");
      continue;
    }
    if (!Array.isArray(ex.stages) || ex.stages.length === 0 || ex.stages.some((s) => !CENSUS_STAGES.includes(s))) {
      invalid(`exclusion ${ex.id} names invalid stages`);
      continue;
    }
    if (typeof ex.reason !== "string" || ex.reason.length === 0) {
      invalid(`exclusion ${ex.id} declares no reason`);
      continue;
    }
    const matched = rawOrphans.filter((o) => o.entry.id === ex.id && ex.stages.includes(o.missingStage));
    if (matched.length === 0) {
      invalid(`exclusion ${ex.id} is stale: it matches no missing-stage gap in ${ex.stages.join(", ")}`);
      continue;
    }
    for (const o of matched) suppressed.add(o);
    validExclusions.push({ id: ex.id, stages: [...ex.stages].sort(), reason: ex.reason });
  }

  const orphans = rawOrphans
    .filter((o) => !suppressed.has(o))
    .map((o) => ({ id: o.entry.id, class: o.class, entry: o.entry }))
    .sort(
      (x, y) =>
        (x.id < y.id ? -1 : x.id > y.id ? 1 : 0) ||
        (x.class < y.class ? -1 : x.class > y.class ? 1 : 0) ||
        (canonicalize(x.entry) < canonicalize(y.entry) ? -1 : 1)
    );

  const report = {
    schemaVersion: "orphan-census@1",
    complete: orphans.length === 0 && errors.length === 0,
    stageCounts: Object.fromEntries(CENSUS_STAGES.map((s) => [s, stageMaps[s].size])),
    orphans,
    exclusions: validExclusions,
    errors
  };
  const check = validateValue("orphan-census@1", report);
  if (!check.ok) {
    throw new Error(`census produced an invalid report: ${JSON.stringify(check.errors)}`);
  }
  return report;
}

// Validator identity for a plan check: the builtin id, or a digest-qualified
// name for a target command so two different argv arrays can never alias.
export function planCheckValidatorId(check) {
  return check.validator.kind === "BUILTIN"
    ? check.validator.builtinId
    : `target:${digestOfCanonical(check.validator.argv)}`;
}

function registryEntry(mechanism) {
  return {
    id: mechanism.mechanismId,
    validatorId: mechanism.validatorId,
    phase: mechanism.activationPhase,
    effect: mechanism.effect,
    resultConsumer: mechanism.resultConsumer
  };
}

function planEntry(check) {
  return {
    id: check.checkId,
    validatorId: planCheckValidatorId(check),
    phase: check.phase,
    effect: check.effect,
    resultConsumer: check.resultConsumer
  };
}

export function registeredFromRegistry(registry) {
  return registry.mechanisms.map(registryEntry);
}

export function implementedFromRegistry(registry, implementedValidatorIds) {
  const ids = new Set(implementedValidatorIds);
  return registry.mechanisms.filter((m) => ids.has(m.validatorId)).map(registryEntry);
}

export function dispatchedFromPlan(plan, { effect = "BLOCKING" } = {}) {
  return plan.checks.filter((c) => effect === null || c.effect === effect).map(planEntry);
}

// A result contributes the plan tuple only when it is fully bound: it is a
// schema-valid check-result@1, its checkId matches a plan check, and its
// packId, effect, planDigest, and candidateId all match what that plan
// dispatched. The plan digest is recomputed from the plan itself, so a
// caller cannot pin results against an invented digest. Anything else — a
// partial result, an unknown check, a forged binding, a replay against
// another plan or candidate — yields an unresolved tuple that can only
// surface as an orphan.
export function emittedFromResults(results, plan, planDigest) {
  const expectedPlanDigest = digestOfCanonical(plan);
  if (planDigest !== expectedPlanDigest) {
    throw new TypeError("emittedFromResults: planDigest does not match the digest of the supplied plan");
  }
  const byCheckId = new Map(plan.checks.map((c) => [c.checkId, c]));
  const expectedCandidateId = plan.candidate.id;
  return results.map((r) => {
    const isResult = r !== null && typeof r === "object" && validateValue("check-result@1", r).ok;
    const check = isResult ? byCheckId.get(r.checkId) : undefined;
    const bound =
      check !== undefined &&
      r.packId === check.packId &&
      r.effect === check.effect &&
      r.planDigest === expectedPlanDigest &&
      r.candidateId === expectedCandidateId;
    if (bound) return planEntry(check);
    const id = typeof r?.checkId === "string" && KEBAB_RE.test(r.checkId) && r.checkId.length <= 128 ? r.checkId : "unbound-result";
    return { id, validatorId: "unresolved", phase: UNRESOLVED, effect: UNRESOLVED, resultConsumer: UNRESOLVED };
  });
}
