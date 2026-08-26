import assert from "node:assert/strict";
import test from "node:test";
import { digestOfCanonical } from "../src/canonical-json.mjs";
import { compilePlan } from "../src/compiler.mjs";
import {
  dispatchedFromPlan,
  emittedFromResults,
  implementedFromRegistry,
  planCheckValidatorId,
  registeredFromRegistry,
  runOrphanCensus
} from "../src/census.mjs";
import { makeCheck, makeContract, makePack, makeProfile, pinPacks, profileEntries } from "./fixtures.mjs";

function entry(id, overrides = {}) {
  return {
    id,
    validatorId: "scope-boundary-classify@1",
    phase: "CANDIDATE_VALIDATION",
    effect: "BLOCKING",
    resultConsumer: "DISPOSITION_REDUCER",
    ...overrides
  };
}

const pair = () => [entry("a"), entry("b")];
const complete = () => ({
  registered: pair(),
  implemented: pair(),
  dispatched: pair(),
  emitted: pair(),
  consumed: pair()
});

test("equal typed tuples in all five stages are complete", () => {
  const report = runOrphanCensus(complete());
  assert.equal(report.complete, true);
  assert.deepEqual(report.orphans, []);
  assert.deepEqual(report.stageCounts, { registered: 2, implemented: 2, dispatched: 2, emitted: 2, consumed: 2 });
});

test("every orphan class is detected in both directions", () => {
  const only = (id) => [entry(id)];
  const cases = [
    [{ ...complete(), implemented: only("a") }, "ORPHAN_REGISTERED_NOT_IMPLEMENTED", "b"],
    [{ ...complete(), registered: only("a") }, "ORPHAN_IMPLEMENTED_NOT_REGISTERED", "b"],
    [{ ...complete(), dispatched: only("a") }, "ORPHAN_IMPLEMENTED_NOT_DISPATCHED", "b"],
    [{ ...complete(), implemented: only("a"), registered: only("a") }, "ORPHAN_DISPATCHED_NOT_IMPLEMENTED", "b"],
    [{ ...complete(), emitted: only("a") }, "ORPHAN_DISPATCHED_NOT_EMITTED", "b"],
    [{ ...complete(), dispatched: only("a"), implemented: only("a"), registered: only("a") }, "ORPHAN_EMITTED_NOT_DISPATCHED", "b"],
    [{ ...complete(), consumed: only("a") }, "ORPHAN_EMITTED_NOT_CONSUMED", "b"],
    [{ ...complete(), emitted: only("a"), dispatched: only("a"), implemented: only("a"), registered: only("a") }, "ORPHAN_CONSUMED_NOT_EMITTED", "b"]
  ];
  for (const [input, expectedClass, id] of cases) {
    const report = runOrphanCensus(input);
    assert.equal(report.complete, false, expectedClass);
    assert.ok(
      report.orphans.some((o) => o.id === id && o.class === expectedClass),
      `${expectedClass}: ${JSON.stringify(report.orphans)}`
    );
  }
});

test("a validator swap under the same check id can never report complete", () => {
  const input = complete();
  input.dispatched = [entry("a"), entry("b", { validatorId: "candidate-identity-verify@1" })];
  input.emitted = input.dispatched;
  input.consumed = input.dispatched;
  const report = runOrphanCensus(input);
  assert.equal(report.complete, false);
  assert.ok(report.orphans.some((o) => o.id === "b" && o.class === "ORPHAN_IMPLEMENTED_NOT_DISPATCHED"));
  assert.ok(report.orphans.some((o) => o.id === "b" && o.class === "ORPHAN_DISPATCHED_NOT_IMPLEMENTED"));
});

test("a phase, effect, or consumer swap under the same check id is an orphan", () => {
  for (const overrides of [
    { phase: "PROMOTION_FINALIZATION" },
    { effect: "ADVISORY" },
    { resultConsumer: "EVIDENCE_ONLY" }
  ]) {
    const input = complete();
    input.dispatched = [entry("a"), entry("b", overrides)];
    input.emitted = input.dispatched;
    input.consumed = input.dispatched;
    const report = runOrphanCensus(input);
    assert.equal(report.complete, false, JSON.stringify(overrides));
  }
});

test("declared exclusions suppress exactly their stage gaps", () => {
  const input = {
    ...complete(),
    consumed: [entry("a")],
    exclusions: [{ id: "b", stages: ["consumed"], reason: "advisory telemetry, consumed by evidence index only" }]
  };
  const report = runOrphanCensus(input);
  assert.equal(report.complete, true);
  assert.equal(report.exclusions.length, 1);
});

test("a stale exclusion fails the census even when no gap exists", () => {
  const covered = runOrphanCensus({
    ...complete(),
    exclusions: [{ id: "a", stages: ["consumed"], reason: "claims a gap that does not exist" }]
  });
  assert.equal(covered.complete, false);
  assert.equal(covered.errors[0].reasonCode, "INVALID_EXCLUSION");
  assert.match(covered.errors[0].message, /stale/);

  const ghost = runOrphanCensus({
    ...complete(),
    exclusions: [{ id: "ghost", stages: ["consumed"], reason: "no such check" }]
  });
  assert.equal(ghost.complete, false);
  assert.equal(ghost.errors[0].reasonCode, "INVALID_EXCLUSION");
});

test("an exclusion cannot suppress a gap in a stage it does not declare", () => {
  const input = {
    ...complete(),
    consumed: [entry("a")],
    emitted: [entry("a")],
    exclusions: [{ id: "b", stages: ["consumed"], reason: "consumed only" }]
  };
  const report = runOrphanCensus(input);
  assert.equal(report.complete, false);
  assert.ok(report.orphans.some((o) => o.id === "b" && o.class === "ORPHAN_DISPATCHED_NOT_EMITTED"));
});

test("malformed census entries are a hard error, not a passing census", () => {
  assert.throws(() => runOrphanCensus({ ...complete(), registered: ["a", "b"] }), TypeError);
  assert.throws(() => runOrphanCensus({ ...complete(), emitted: [{ id: "a" }, entry("b")] }), TypeError);
});

test("consistently repeated garbage tuples are a mechanical error, never complete", () => {
  // Identical invalid values across every stage previously sailed through:
  // set equality held, so the census reported complete. Field values must be
  // validated against their closed sets before set construction.
  const garbageCases = [
    { phase: "BANANA" },
    { effect: "ALLOW" },
    { resultConsumer: "NOBODY" },
    { validatorId: "not a validator id" },
    { id: "Not-Kebab" }
  ];
  for (const overrides of garbageCases) {
    const bad = [entry("a"), entry("b", overrides)];
    assert.throws(
      () =>
        runOrphanCensus({ registered: bad, implemented: bad, dispatched: bad, emitted: bad, consumed: bad }),
      TypeError,
      JSON.stringify(overrides)
    );
  }
});

test("the unresolved sentinel is confined to emitted and consumed, all-or-nothing", () => {
  const sentinel = (id) => ({
    id,
    validatorId: "unresolved",
    phase: "UNRESOLVED",
    effect: "UNRESOLVED",
    resultConsumer: "UNRESOLVED"
  });

  // A sentinel supplied in every stage previously satisfied set equality and
  // reported complete. Authority-side stages must reject it outright.
  for (const stage of ["registered", "implemented", "dispatched"]) {
    const input = complete();
    input[stage] = [...input[stage], sentinel("ghost")];
    assert.throws(() => runOrphanCensus(input), TypeError, stage);
  }

  // Mixing sentinel and concrete fields is rejected everywhere.
  const partial = complete();
  partial.emitted = [...partial.emitted, entry("ghost", { phase: "UNRESOLVED" })];
  assert.throws(() => runOrphanCensus(partial), TypeError);

  // Where the sentinel is legitimate, it can only ever be an orphan.
  const input = complete();
  input.emitted = [...input.emitted, sentinel("ghost")];
  input.consumed = [...input.consumed, sentinel("ghost")];
  const report = runOrphanCensus(input);
  assert.equal(report.complete, false);
  assert.ok(report.orphans.some((o) => o.id === "ghost" && o.class === "ORPHAN_EMITTED_NOT_DISPATCHED"));
});

test("duplicate entries within a stage are a census error, not a silent merge", () => {
  const input = complete();
  input.emitted = [entry("a"), entry("b"), entry("b")];
  const report = runOrphanCensus(input);
  assert.equal(report.complete, false);
  assert.equal(report.errors[0].reasonCode, "DUPLICATE_ENTRY_ID");
  assert.match(report.errors[0].message, /emitted/);
  // The gaps themselves are unchanged: the duplicate did not create one.
  assert.deepEqual(report.orphans, []);
});

test("census tuples derive mechanically from registry and compiled plan", () => {
  const pack = makePack({
    checks: [
      makeCheck({ checkId: "blocking-check" }),
      makeCheck({ checkId: "advisory-check", effect: "ADVISORY" })
    ]
  });
  const packs = pinPacks([pack]);
  const profile = makeProfile(profileEntries(packs));
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  const { ok, plan, planDigest } = compilePlan({
    workContract: contract,
    profile,
    profileDigest,
    packs: packs.map((p) => ({ value: p.value, digest: p.digest })),
    mandatoryPacks: []
  });
  assert.equal(ok, true);
  const boundResult = (checkId) => ({
    schemaVersion: "check-result@1",
    checkId,
    packId: "example-pack",
    planDigest,
    candidateId: plan.candidate.id,
    effect: "BLOCKING",
    outcome: "PASS",
    reasonCodes: [],
    evidence: [],
    startedAt: "2026-08-26T00:00:00Z",
    completedAt: "2026-08-26T00:00:01Z"
  });

  const mechanism = {
    mechanismId: "blocking-check",
    validatorId: "scope-boundary-classify@1",
    owner: "kernel-team",
    producer: "compiler",
    runtimeConsumer: "disposition-reducer",
    inputSchemaId: "compiled-policy-plan@1",
    outputSchemaId: "check-result@1",
    activationPhase: "CANDIDATE_VALIDATION",
    effect: "BLOCKING",
    resultConsumer: "DISPOSITION_REDUCER",
    evidenceSink: "evidence-index",
    negativeFixtures: [{ fixtureId: "planted-violation", description: "planted violation must fire" }],
    status: "INTEGRATED"
  };
  const registry = { schemaVersion: "mechanism-registry@1", mechanisms: [mechanism] };

  const registered = registeredFromRegistry(registry);
  const implemented = implementedFromRegistry(registry, ["scope-boundary-classify@1"]);
  const dispatched = dispatchedFromPlan(plan);
  assert.deepEqual(dispatched.map((e) => e.id), ["blocking-check"]);
  assert.deepEqual(registered, dispatched);

  const emitted = emittedFromResults([boundResult("blocking-check")], plan, planDigest);
  const report = runOrphanCensus({ registered, implemented, dispatched, emitted, consumed: emitted });
  assert.equal(report.complete, true);

  // An unimplemented validator id surfaces as registered-but-not-implemented.
  const broken = runOrphanCensus({
    registered,
    implemented: implementedFromRegistry(registry, []),
    dispatched,
    emitted,
    consumed: emitted
  });
  assert.equal(broken.complete, false);
  assert.ok(broken.orphans.some((o) => o.class === "ORPHAN_REGISTERED_NOT_IMPLEMENTED"));

  // A registry row naming a different validator than the plan dispatches
  // under the same id is the exact false-completeness attack: it must fail.
  const swappedRegistry = {
    schemaVersion: "mechanism-registry@1",
    mechanisms: [{ ...mechanism, validatorId: "candidate-identity-verify@1" }]
  };
  const swapped = runOrphanCensus({
    registered: registeredFromRegistry(swappedRegistry),
    implemented: implementedFromRegistry(swappedRegistry, ["candidate-identity-verify@1"]),
    dispatched,
    emitted,
    consumed: emitted
  });
  assert.equal(swapped.complete, false);
  assert.ok(swapped.orphans.some((o) => o.class === "ORPHAN_DISPATCHED_NOT_IMPLEMENTED"));

  // A result the plan never dispatched cannot silently join the census.
  const rogueEmitted = emittedFromResults([boundResult("rogue-check")], plan, planDigest);
  assert.equal(rogueEmitted[0].validatorId, "unresolved");
  assert.equal(rogueEmitted[0].phase, "UNRESOLVED");

  // A result cannot be laundered through the plan: matching the checkId is
  // not enough. Forged packId, effect, planDigest, or candidateId each
  // unbind the result, and the census then fails.
  const forgeries = [
    { packId: "another-pack" },
    { effect: "ADVISORY" },
    { planDigest: `sha256:${"7".repeat(64)}` },
    { candidateId: "9".repeat(40) }
  ];
  for (const forgery of forgeries) {
    const forgedEmitted = emittedFromResults([{ ...boundResult("blocking-check"), ...forgery }], plan, planDigest);
    assert.equal(forgedEmitted[0].validatorId, "unresolved", JSON.stringify(forgery));
    const forgedReport = runOrphanCensus({
      registered,
      implemented,
      dispatched,
      emitted: forgedEmitted,
      consumed: forgedEmitted
    });
    assert.equal(forgedReport.complete, false, JSON.stringify(forgery));
    assert.ok(forgedReport.orphans.some((o) => o.class === "ORPHAN_DISPATCHED_NOT_EMITTED"));
  }

  // The plan digest is recomputed from the plan: omitting it or supplying a
  // well-formed but wrong digest is a hard error, so a caller can never pin
  // results against an invented digest.
  assert.throws(() => emittedFromResults([boundResult("blocking-check")], plan), TypeError);
  const invented = `sha256:${"5".repeat(64)}`;
  assert.throws(
    () => emittedFromResults([{ ...boundResult("blocking-check"), planDigest: invented }], plan, invented),
    TypeError
  );

  // A partial result carrying only the five binding fields is not a
  // check-result@1 and cannot count as emitted.
  const partial = {
    checkId: "blocking-check",
    packId: "example-pack",
    planDigest,
    candidateId: plan.candidate.id,
    effect: "BLOCKING"
  };
  const partialEmitted = emittedFromResults([partial], plan, planDigest);
  assert.equal(partialEmitted[0].validatorId, "unresolved");
  const partialReport = runOrphanCensus({
    registered,
    implemented,
    dispatched,
    emitted: partialEmitted,
    consumed: partialEmitted
  });
  assert.equal(partialReport.complete, false);
  assert.ok(partialReport.orphans.some((o) => o.class === "ORPHAN_DISPATCHED_NOT_EMITTED"));

  // Target commands get digest-qualified validator identity: two different
  // argv arrays can never alias one registered validator.
  const argvCheckA = makeCheck({ checkId: "cmd-a", validator: { kind: "TARGET_COMMAND", argv: ["node", "a.mjs"] } });
  const argvCheckB = makeCheck({ checkId: "cmd-b", validator: { kind: "TARGET_COMMAND", argv: ["node", "b.mjs"] } });
  assert.notEqual(planCheckValidatorId(argvCheckA), planCheckValidatorId(argvCheckB));
  assert.match(planCheckValidatorId(argvCheckA), /^target:sha256:[0-9a-f]{64}$/);
});
