import assert from "node:assert/strict";
import test from "node:test";
import { digestOfCanonical } from "../src/canonical-json.mjs";
import { validateValue } from "../src/contracts.mjs";
import { MANDATORY_PACK_IDS, compilePlan, mandatoryKernelPacks } from "../src/compiler.mjs";
import { knownBuiltinValidatorIds } from "../src/builtin-validators.mjs";
import { makeCheck, makeContract, makePack, makeProfile, pinPacks, profileEntries } from "./fixtures.mjs";

const MANDATORY_CHECK_IDS = [
  "candidate-identity-verify",
  "validation-plan-admission",
  "scope-boundary-classify",
  "validation-plan-validation",
  "candidate-tree-stability",
  "evidence-binding-index",
  "validation-plan-finalization"
];

function fixture() {
  const packs = pinPacks([makePack({ packId: "team-pack", checks: [makeCheck({ checkId: "team-check" })] })]);
  const profile = makeProfile(profileEntries(packs));
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  return { contract, profile, profileDigest, packs: packs.map((p) => ({ value: p.value, digest: p.digest })) };
}

test("the four kernel packs are shipped, strict-valid, and digest-pinned", () => {
  const kernelPacks = mandatoryKernelPacks();
  assert.deepEqual(kernelPacks.map((p) => p.value.packId), [...MANDATORY_PACK_IDS]);
  for (const pack of kernelPacks) {
    assert.equal(validateValue("policy-pack@1", pack.value).ok, true, pack.value.packId);
    assert.match(pack.digest, /^sha256:[0-9a-f]{64}$/);
    for (const check of pack.value.checks) {
      assert.equal(check.validator.kind, "BUILTIN");
      assert.ok(knownBuiltinValidatorIds().has(check.validator.builtinId), check.validator.builtinId);
      assert.equal(check.effect, "BLOCKING");
      assert.equal(check.resultConsumer, "DISPOSITION_REDUCER");
    }
  }
});

test("every default compilation injects all four mandatory packs", () => {
  const { contract, profile, profileDigest, packs } = fixture();
  const result = compilePlan({ workContract: contract, profile, profileDigest, packs });
  assert.equal(result.ok, true, JSON.stringify(result.errors ?? []));
  const checkIds = result.plan.checks.map((c) => c.checkId);
  for (const id of MANDATORY_CHECK_IDS) assert.ok(checkIds.includes(id), id);
  assert.ok(checkIds.includes("team-check"));
  // Admission runs first, finalization last.
  assert.equal(checkIds[0], "candidate-identity-verify");
  assert.deepEqual(checkIds.slice(-3), ["candidate-tree-stability", "evidence-binding-index", "validation-plan-finalization"]);
  // The plan digest set binds the kernel pack digests.
  const pinned = new Map(result.plan.sourceDigests.packs.map((p) => [p.packId, p.digest]));
  for (const pack of mandatoryKernelPacks()) {
    assert.equal(pinned.get(pack.value.packId), pack.digest);
  }
});

test("a profile cannot re-declare, replace, or weaken a mandatory pack", () => {
  const { contract, profileDigest, packs } = fixture();
  const rogueSelection = makeProfile([
    ...profileEntries(pinPacks([makePack({ packId: "team-pack", checks: [makeCheck({ checkId: "team-check" })] })])),
    { packId: "scope-boundary", version: "1.0.0", path: "policy/fake.json", digest: `sha256:${"a".repeat(64)}` }
  ]);
  const rogueContract = makeContract({
    policyProfile: { profileId: rogueSelection.profileId, path: "policy/profile.json", digest: digestOfCanonical(rogueSelection) }
  });
  const result = compilePlan({
    workContract: rogueContract,
    profile: rogueSelection,
    profileDigest: digestOfCanonical(rogueSelection),
    packs
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.reasonCode === "POLICY_CONFLICT"), JSON.stringify(result.errors));
  assert.equal(contract.schemaVersion, "work-contract@1");
  assert.match(profileDigest, /^sha256:/);
});

test("a target-supplied pack impersonating a mandatory pack is rejected", () => {
  const { contract, profile, profileDigest, packs } = fixture();
  const impostor = pinPacks([
    makePack({
      packId: "scope-boundary",
      description: "impostor that weakens scope enforcement",
      checks: [makeCheck({ checkId: "fake-scope-check", effect: "ADVISORY" })]
    })
  ])[0];
  const result = compilePlan({
    workContract: contract,
    profile,
    profileDigest,
    packs: [...packs, { value: impostor.value, digest: impostor.digest }]
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.reasonCode === "POLICY_CONFLICT"));
});

test("a target check id colliding with a mandatory check id fails compilation", () => {
  const clashPacks = pinPacks([
    makePack({ packId: "team-pack", checks: [makeCheck({ checkId: "scope-boundary-classify" })] })
  ]);
  const profile = makeProfile(profileEntries(clashPacks));
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  const result = compilePlan({
    workContract: contract,
    profile,
    profileDigest,
    packs: clashPacks.map((p) => ({ value: p.value, digest: p.digest }))
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.reasonCode === "DUPLICATE_CHECK_ID"));
});
