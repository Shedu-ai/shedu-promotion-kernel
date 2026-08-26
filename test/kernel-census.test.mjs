import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { digestOfCanonical } from "../src/canonical-json.mjs";
import { validateDocument } from "../src/contracts.mjs";
import { compilePlan } from "../src/compiler.mjs";
import { BUILTIN_VALIDATORS, implementedBuiltinValidatorIds, resolveBuiltinValidator } from "../src/builtin-validators.mjs";
import { reduceDisposition } from "../src/reducer.mjs";
import {
  dispatchedFromPlan,
  emittedFromResults,
  implementedFromRegistry,
  registeredFromRegistry,
  runOrphanCensus
} from "../src/census.mjs";
import { materializeWorktree } from "../src/workspace.mjs";
import { commitAll, makeCheck, makeContract, makeGitRepo, makePack, makeProfile, pinPacks, profileEntries, writeRepoFile } from "./fixtures.mjs";

function loadKernelRegistry() {
  const bytes = readFileSync(new URL("../registry/kernel-mechanisms.json", import.meta.url));
  const validated = validateDocument("mechanism-registry@1", bytes);
  assert.equal(validated.ok, true, JSON.stringify(validated.errors ?? []));
  return validated.value;
}

// The two mechanisms whose implementations arrive with the step-4 runner and
// evidence index. Their absence is DECLARED, never silent.
const PENDING_STEP4 = ["validation-plan-execute", "evidence-binding-index"];

function evaluationFixture() {
  const repoDir = makeGitRepo();
  writeRepoFile(repoDir, "src/app.mjs", "export const app = 1;\n");
  writeRepoFile(repoDir, "docs/readme.md", "readme\n");
  const baseCommit = commitAll(repoDir, "base");
  writeRepoFile(repoDir, "src/feature.mjs", "export const f = 2;\n");
  const candidate = commitAll(repoDir, "feature");

  const packs = pinPacks([
    makePack({ packId: "team-pack", checks: [makeCheck({ checkId: "team-check", effect: "ADVISORY" })] })
  ]);
  const profile = makeProfile(profileEntries(packs));
  const profileDigest = digestOfCanonical(profile);
  const workContract = makeContract({
    target: { repositoryId: "example-repo", baseCommit, candidate: { kind: "COMMIT", id: candidate } },
    policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest }
  });
  const compiled = compilePlan({
    workContract,
    profile,
    profileDigest,
    packs: packs.map((p) => ({ value: p.value, digest: p.digest }))
  });
  assert.equal(compiled.ok, true, JSON.stringify(compiled.errors ?? []));
  return { repoDir, workContract, ...compiled };
}

function runImplementedValidators({ repoDir, workContract, plan, planDigest }) {
  const worktree = materializeWorktree(repoDir, workContract.target.candidate.id);
  try {
    const results = [];
    for (const check of plan.checks) {
      if (check.validator.kind !== "BUILTIN") continue;
      if (!BUILTIN_VALIDATORS[check.validator.builtinId]?.implemented) continue;
      const run = resolveBuiltinValidator(check.validator.builtinId);
      const partial = run({ repoDir, workContract, candidateDir: worktree.dir });
      results.push({
        schemaVersion: "check-result@1",
        checkId: check.checkId,
        packId: check.packId,
        planDigest,
        candidateId: plan.candidate.id,
        effect: check.effect,
        outcome: partial.outcome,
        reasonCodes: partial.reasonCodes,
        evidence: [],
        startedAt: "2026-08-26T00:00:00Z",
        completedAt: "2026-08-26T00:00:01Z"
      });
    }
    return results;
  } finally {
    worktree.cleanup();
  }
}

test("the kernel mechanism registry is valid and mirrors the mandatory pack checks exactly", () => {
  const registry = loadKernelRegistry();
  const { plan } = evaluationFixture();
  const registered = registeredFromRegistry(registry);
  const dispatched = dispatchedFromPlan(plan);
  const key = (e) => JSON.stringify(e);
  assert.deepEqual(registered.map(key).sort(), dispatched.map(key).sort());
});

test("kernel self-census: complete with only the two declared step-4 exclusions", () => {
  const registry = loadKernelRegistry();
  const fixture = evaluationFixture();
  const { plan, planDigest } = fixture;

  const results = runImplementedValidators(fixture);
  for (const r of results) assert.equal(r.outcome, "PASS", `${r.checkId}: ${r.reasonCodes}`);

  const reduced = reduceDisposition({ plan, planDigest, results });
  // The pending step-4 checks have no results yet, so the reducer fails
  // closed — omitted work can never produce PROMOTABLE.
  assert.equal(reduced.disposition, "BLOCKED");
  assert.ok(reduced.reasonCodes.includes("MISSING_REQUIRED_RESULT"));

  const dispatched = dispatchedFromPlan(plan);
  const tupleByCheckId = new Map(dispatched.map((e) => [e.id, e]));
  const consumed = reduced.consumed
    .filter((c) => c.effect === "BLOCKING")
    .map((c) => tupleByCheckId.get(c.checkId));

  // Blocking-set census (AC-15 shape): advisory results are retained as
  // evidence but are not members of the blocking-check sets.
  const emitted = emittedFromResults(results, plan, planDigest).filter((e) => e.effect === "BLOCKING");
  const census = runOrphanCensus({
    registered: registeredFromRegistry(registry),
    implemented: implementedFromRegistry(registry, implementedBuiltinValidatorIds()),
    dispatched,
    emitted,
    consumed,
    exclusions: PENDING_STEP4.map((id) => ({
      id,
      stages: ["implemented", "emitted"],
      reason: "implementation arrives with the step-4 target-command runner and evidence index; dispatch already fails closed via MISSING_REQUIRED_RESULT"
    }))
  });
  assert.equal(census.complete, true, JSON.stringify(census, null, 2));
  assert.equal(census.exclusions.length, 2);

  // Honesty proof: without the declared exclusions the census must fail.
  const undeclared = runOrphanCensus({
    registered: registeredFromRegistry(registry),
    implemented: implementedFromRegistry(registry, implementedBuiltinValidatorIds()),
    dispatched,
    emitted,
    consumed
  });
  assert.equal(undeclared.complete, false);
});

test("registry status honestly marks pending mechanisms as LANDED_ONLY", () => {
  const registry = loadKernelRegistry();
  for (const mechanism of registry.mechanisms) {
    if (PENDING_STEP4.includes(mechanism.mechanismId)) {
      assert.equal(mechanism.status, "LANDED_ONLY", mechanism.mechanismId);
    } else {
      assert.equal(mechanism.status, "INTEGRATED", mechanism.mechanismId);
    }
  }
});
