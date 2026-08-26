import assert from "node:assert/strict";
import test from "node:test";
import { digestOfCanonical } from "../src/canonical-json.mjs";
import { validateValue } from "../src/contracts.mjs";
import { compilePlan } from "../src/compiler.mjs";
import { makeCheck, makeContract, makePack, makeProfile, pinPacks, profileEntries } from "./fixtures.mjs";

// These tests isolate profile/pack resolution mechanics from the mandatory
// kernel packs, which are injected unconditionally on the default path and
// covered by mandatory-packs.test.mjs.
const compileBare = (args) => compilePlan(Object.assign({ mandatoryPacks: [] }, args));

// Standard two-pack fixture: "base-pack" plus "dependent-pack" depending on it.
function fixture({ mutateProfile, mutatePacks } = {}) {
  const basePack = makePack({
    packId: "base-pack",
    checks: [makeCheck({ checkId: "base-check", validator: { kind: "BUILTIN", builtinId: "candidate-identity-verify@1" } })]
  });
  const basePinned = pinPacks([basePack])[0];
  const dependentPack = makePack({
    packId: "dependent-pack",
    dependencies: [{ packId: "base-pack", version: "1.0.0", digest: basePinned.digest }],
    checks: [
      makeCheck({ checkId: "dependent-check" }),
      makeCheck({
        checkId: "advisory-check",
        effect: "ADVISORY",
        resultConsumer: "DISPOSITION_REDUCER",
        validator: { kind: "TARGET_COMMAND", argv: ["node", "tools/check.mjs", "--json"] }
      })
    ]
  });
  let packs = pinPacks([basePack, dependentPack]);
  if (mutatePacks) packs = mutatePacks(packs);
  let profile = makeProfile(profileEntries(packs));
  if (mutateProfile) profile = mutateProfile(profile);
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  return { contract, profile, profileDigest, packs: packs.map((p) => ({ value: p.value, digest: p.digest })) };
}

const reasons = (result) => {
  assert.equal(result.ok, false);
  return result.errors.map((e) => e.reasonCode);
};

test("compilation is deterministic: equal inputs give byte-identical plans", () => {
  const { contract, profile, profileDigest, packs } = fixture();
  const first = compileBare({ workContract: contract, profile, profileDigest, packs });
  assert.equal(first.ok, true, JSON.stringify(first.errors ?? []));
  const second = compileBare({ workContract: contract, profile, profileDigest, packs: [...packs].reverse() });
  assert.equal(second.ok, true);
  assert.equal(first.planBytes, second.planBytes);
  assert.equal(first.planDigest, second.planDigest);
});

test("the compiled plan is schema-valid, ordered, and fully digest-bound", () => {
  const { contract, profile, profileDigest, packs } = fixture();
  const { plan } = compileBare({ workContract: contract, profile, profileDigest, packs });
  assert.equal(validateValue("compiled-policy-plan@1", plan).ok, true);
  assert.deepEqual(plan.checks.map((c) => c.checkId), ["base-check", "advisory-check", "dependent-check"]);
  assert.deepEqual(plan.checks.find((c) => c.checkId === "dependent-check").dependsOn, ["base-check"]);
  assert.equal(plan.sourceDigests.workContract, digestOfCanonical(contract));
  assert.equal(plan.sourceDigests.profile, profileDigest);
  assert.equal(plan.sourceDigests.packs.length, 2);
  // exact argv survives byte-for-byte
  const argvCheck = plan.checks.find((c) => c.checkId === "advisory-check");
  assert.deepEqual(argvCheck.validator.argv, ["node", "tools/check.mjs", "--json"]);
});

test("profile digest drift fails before anything compiles", () => {
  const { contract, profile, packs } = fixture();
  const result = compileBare({ workContract: contract, profile, profileDigest: `sha256:${"f".repeat(64)}`, packs });
  assert.ok(reasons(result).includes("AUTHORITY_DIGEST_MISMATCH"));
});

test("pack digest drift fails compilation", () => {
  const { contract, profile, profileDigest, packs } = fixture();
  // A drifted document arrives with the digest its loader actually computed,
  // which no longer matches the profile's pin.
  const tampered = packs.map((p) => {
    if (p.value.packId !== "dependent-pack") return p;
    const drifted = { ...p.value, description: "tampered" };
    return { value: drifted, digest: digestOfCanonical(drifted) };
  });
  const result = compileBare({ workContract: contract, profile, profileDigest, packs: tampered });
  assert.ok(reasons(result).includes("PACK_DIGEST_MISMATCH"));
});

test("dependency cycles fail compilation", () => {
  // Mutually recursive digests cannot both be exact, so a cycle necessarily
  // also carries digest errors; the cycle itself must still be reported.
  const placeholder = `sha256:${"e".repeat(64)}`;
  const packA = makePack({
    packId: "pack-a",
    dependencies: [{ packId: "pack-b", version: "1.0.0", digest: placeholder }],
    checks: [makeCheck({ checkId: "check-a" })]
  });
  const packB = makePack({
    packId: "pack-b",
    dependencies: [{ packId: "pack-a", version: "1.0.0", digest: placeholder }],
    checks: [makeCheck({ checkId: "check-b" })]
  });
  const packs = pinPacks([packA, packB]);
  const profile = makeProfile(profileEntries(packs));
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  const result = compileBare({
    workContract: contract,
    profile,
    profileDigest,
    packs: packs.map((p) => ({ value: p.value, digest: p.digest }))
  });
  assert.ok(reasons(result).includes("DEPENDENCY_CYCLE"));
});

test("duplicate check ids across packs fail compilation", () => {
  const { contract, profile, profileDigest, packs } = fixture({
    mutatePacks: (pinned) => {
      const clash = makePack({ packId: "clash-pack", checks: [makeCheck({ checkId: "base-check" })] });
      return [...pinned, ...pinPacks([clash])];
    },
    mutateProfile: undefined
  });
  const result = compileBare({ workContract: contract, profile, profileDigest, packs });
  assert.ok(reasons(result).includes("DUPLICATE_CHECK_ID"));
});

test("unknown builtin validators fail compilation", () => {
  const rogue = makePack({
    packId: "rogue-pack",
    checks: [makeCheck({ checkId: "rogue-check", validator: { kind: "BUILTIN", builtinId: "made-up-validator@1" } })]
  });
  const packs = pinPacks([rogue]);
  const profile = makeProfile(profileEntries(packs));
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  const result = compileBare({
    workContract: contract,
    profile,
    profileDigest,
    packs: packs.map((p) => ({ value: p.value, digest: p.digest }))
  });
  assert.ok(reasons(result).includes("UNKNOWN_VALIDATOR"));
});

test("unsatisfied dependencies fail compilation", () => {
  const { contract, profile, profileDigest, packs } = fixture({
    mutateProfile: (p) => ({ ...p, packs: p.packs.filter((s) => s.packId !== "base-pack") })
  });
  const result = compileBare({
    workContract: contract,
    profile,
    profileDigest,
    packs: packs.filter((p) => p.value.packId !== "base-pack")
  });
  assert.ok(reasons(result).includes("DEPENDENCY_UNSATISFIED"));
});

test("strengthening ADVISORY to BLOCKING works; weakening is impossible", () => {
  const { contract, profile, profileDigest, packs } = fixture({
    mutateProfile: (p) => ({ ...p, strengthen: ["advisory-check"] })
  });
  const result = compileBare({ workContract: contract, profile, profileDigest, packs });
  assert.equal(result.ok, true, JSON.stringify(result.errors ?? []));
  assert.equal(result.plan.checks.find((c) => c.checkId === "advisory-check").effect, "BLOCKING");
});

test("strengthening an evidence-only check is a conflict", () => {
  const pack = makePack({
    packId: "telemetry-pack",
    checks: [makeCheck({ checkId: "telemetry-check", effect: "ADVISORY", resultConsumer: "EVIDENCE_ONLY" })]
  });
  const packs = pinPacks([pack]);
  const profile = makeProfile(profileEntries(packs), { strengthen: ["telemetry-check"] });
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  const result = compileBare({
    workContract: contract,
    profile,
    profileDigest,
    packs: packs.map((p) => ({ value: p.value, digest: p.digest }))
  });
  assert.ok(reasons(result).includes("STRENGTHEN_CONFLICT"));
});

test("a dependency whose check runs after the dependent's earliest check is a phase-order conflict", () => {
  // dependent-pack gains a CONTRACT_ADMISSION check while base-pack only has
  // CANDIDATE_VALIDATION checks: the old compiler silently dropped the edge
  // and ran the dependent first. This must fail compilation.
  const { contract, profile, profileDigest, packs } = fixture({
    mutatePacks: (pinned) =>
      pinPacks(
        pinned.map((p) =>
          p.value.packId === "dependent-pack"
            ? {
                ...p.value,
                phases: ["CONTRACT_ADMISSION", "CANDIDATE_VALIDATION"],
                checks: [
                  ...p.value.checks,
                  makeCheck({
                    checkId: "early-admission-check",
                    phase: "CONTRACT_ADMISSION",
                    validator: { kind: "BUILTIN", builtinId: "candidate-identity-verify@1" }
                  })
                ]
              }
            : p.value
        )
      )
  });
  const result = compileBare({ workContract: contract, profile, profileDigest, packs });
  assert.ok(reasons(result).includes("PHASE_ORDER_CONFLICT"), JSON.stringify(result.errors ?? "ok"));
});

test("dependsOn always carries every dependency check — nothing is dropped", () => {
  const { contract, profile, profileDigest, packs } = fixture();
  const { plan } = compileBare({ workContract: contract, profile, profileDigest, packs });
  for (const check of plan.checks.filter((c) => c.packId === "dependent-pack")) {
    assert.deepEqual(check.dependsOn, ["base-check"], check.checkId);
  }
});

test("a supplied pack the profile never selected is rejected", () => {
  const { contract, profile, profileDigest, packs } = fixture();
  const extra = pinPacks([makePack({ packId: "uninvited-pack", checks: [makeCheck({ checkId: "uninvited-check" })] })]);
  const result = compileBare({
    workContract: contract,
    profile,
    profileDigest,
    packs: [...packs, { value: extra[0].value, digest: extra[0].digest }]
  });
  assert.ok(reasons(result).includes("PACK_NOT_SELECTED"));
});
