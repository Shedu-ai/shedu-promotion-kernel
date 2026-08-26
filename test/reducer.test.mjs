import assert from "node:assert/strict";
import test from "node:test";
import { digestOfCanonical } from "../src/canonical-json.mjs";
import { compilePlan } from "../src/compiler.mjs";
import { reduceDisposition } from "../src/reducer.mjs";
import { makeCheck, makeContract, makePack, makeProfile, pinPacks, profileEntries } from "./fixtures.mjs";

// Compile a small plan (isolated from mandatory packs) with one blocking,
// one advisory, and one evidence-only check.
function fixture() {
  const pack = makePack({
    checks: [
      makeCheck({ checkId: "blocking-check" }),
      makeCheck({ checkId: "advisory-check", effect: "ADVISORY" }),
      makeCheck({ checkId: "telemetry-check", effect: "ADVISORY", resultConsumer: "EVIDENCE_ONLY" })
    ]
  });
  const packs = pinPacks([pack]);
  const profile = makeProfile(profileEntries(packs));
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  const compiled = compilePlan({
    workContract: contract,
    profile,
    profileDigest,
    packs: packs.map((p) => ({ value: p.value, digest: p.digest })),
    mandatoryPacks: []
  });
  assert.equal(compiled.ok, true);
  return compiled;
}

function makeResult(plan, planDigest, checkId, overrides = {}) {
  const check = plan.checks.find((c) => c.checkId === checkId);
  return {
    schemaVersion: "check-result@1",
    checkId,
    packId: check.packId,
    planDigest,
    candidateId: plan.candidate.id,
    effect: check.effect,
    outcome: "PASS",
    reasonCodes: [],
    evidence: [],
    startedAt: "2026-08-26T00:00:00Z",
    completedAt: "2026-08-26T00:00:01Z",
    ...overrides
  };
}

test("all bound passing results yield PROMOTABLE, consumed in plan order", () => {
  const { plan, planDigest } = fixture();
  const results = plan.checks.map((c) => makeResult(plan, planDigest, c.checkId));
  const out = reduceDisposition({ plan, planDigest, results });
  assert.equal(out.disposition, "PROMOTABLE");
  assert.deepEqual(out.reasonCodes, []);
  assert.deepEqual(out.consumed.map((c) => c.checkId), ["advisory-check", "blocking-check"]);
  assert.deepEqual(out.evidenceOnly, [{ checkId: "telemetry-check", outcome: "PASS" }]);
});

test("the reducer is deterministic under result reordering", () => {
  const { plan, planDigest } = fixture();
  const results = plan.checks.map((c) => makeResult(plan, planDigest, c.checkId));
  const ordered = reduceDisposition({ plan, planDigest, results });
  const shuffled = reduceDisposition({ plan, planDigest, results: [...results].reverse() });
  assert.deepEqual(shuffled, ordered);
});

test("a FIRED blocking result blocks and carries its reason codes", () => {
  const { plan, planDigest } = fixture();
  const results = [
    makeResult(plan, planDigest, "blocking-check", { outcome: "FIRED", reasonCodes: ["SCOPE_FORBIDDEN_CHANGE"] }),
    makeResult(plan, planDigest, "advisory-check"),
    makeResult(plan, planDigest, "telemetry-check")
  ];
  const out = reduceDisposition({ plan, planDigest, results });
  assert.equal(out.disposition, "BLOCKED");
  assert.ok(out.reasonCodes.includes("CHECK_FIRED"));
  assert.ok(out.reasonCodes.includes("SCOPE_FORBIDDEN_CHANGE"));
});

test("a FIRED advisory result never blocks and is retained", () => {
  const { plan, planDigest } = fixture();
  const results = [
    makeResult(plan, planDigest, "blocking-check"),
    makeResult(plan, planDigest, "advisory-check", { outcome: "FIRED", reasonCodes: ["SCOPE_READONLY_CHANGE"] }),
    makeResult(plan, planDigest, "telemetry-check", { outcome: "FIRED", reasonCodes: ["SCOPE_READONLY_CHANGE"] })
  ];
  const out = reduceDisposition({ plan, planDigest, results });
  assert.equal(out.disposition, "PROMOTABLE");
  assert.deepEqual(out.advisory, [
    { checkId: "advisory-check", outcome: "FIRED", reasonCodes: ["SCOPE_READONLY_CHANGE"] }
  ]);
  assert.deepEqual(out.evidenceOnly, [{ checkId: "telemetry-check", outcome: "FIRED" }]);
});

test("a missing blocking result fails closed; missing advisory does not", () => {
  const { plan, planDigest } = fixture();
  const out = reduceDisposition({
    plan,
    planDigest,
    results: [makeResult(plan, planDigest, "advisory-check")]
  });
  assert.equal(out.disposition, "BLOCKED");
  assert.ok(out.reasonCodes.includes("MISSING_REQUIRED_RESULT"));

  const okOut = reduceDisposition({
    plan,
    planDigest,
    results: [makeResult(plan, planDigest, "blocking-check")]
  });
  assert.equal(okOut.disposition, "PROMOTABLE");
});

test("an infrastructure-failed blocking result fails closed", () => {
  const { plan, planDigest } = fixture();
  const results = [
    makeResult(plan, planDigest, "blocking-check", { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"] })
  ];
  const out = reduceDisposition({ plan, planDigest, results });
  assert.equal(out.disposition, "BLOCKED");
  assert.ok(out.reasonCodes.includes("INFRASTRUCTURE_FAILURE"));
});

test("duplicate results block", () => {
  const { plan, planDigest } = fixture();
  const r = makeResult(plan, planDigest, "blocking-check");
  const out = reduceDisposition({ plan, planDigest, results: [r, r] });
  assert.equal(out.disposition, "BLOCKED");
  assert.ok(out.reasonCodes.includes("DUPLICATE_RESULT"));
});

test("forged or malformed bindings block: no result can launder past the plan", () => {
  const { plan, planDigest } = fixture();
  const forgeries = [
    makeResult(plan, planDigest, "blocking-check", { candidateId: "9".repeat(40) }),
    makeResult(plan, planDigest, "blocking-check", { planDigest: `sha256:${"8".repeat(64)}` }),
    makeResult(plan, planDigest, "blocking-check", { packId: "another-pack" }),
    makeResult(plan, planDigest, "advisory-check", { effect: "BLOCKING" }),
    makeResult(plan, planDigest, "blocking-check", { checkId: "unknown-check" }),
    { not: "a result" }
  ];
  for (const forged of forgeries) {
    const results = [
      forged,
      ...plan.checks
        .filter((c) => c.checkId !== (typeof forged.checkId === "string" ? forged.checkId : "-"))
        .map((c) => makeResult(plan, planDigest, c.checkId))
    ];
    const out = reduceDisposition({ plan, planDigest, results });
    assert.equal(out.disposition, "BLOCKED", JSON.stringify(forged));
    assert.ok(
      out.reasonCodes.includes("RESULT_BINDING_MISMATCH") || out.reasonCodes.includes("DUPLICATE_RESULT"),
      JSON.stringify(out.reasonCodes)
    );
  }
});

test("the reducer has no override path: unknown inputs cannot flip a disposition", () => {
  const { plan, planDigest } = fixture();
  const results = [
    makeResult(plan, planDigest, "blocking-check", { outcome: "FIRED", reasonCodes: ["SCOPE_FORBIDDEN_CHANGE"] })
  ];
  const out = reduceDisposition({ plan, planDigest, results, override: "PROMOTABLE", force: true });
  assert.equal(out.disposition, "BLOCKED");
});
