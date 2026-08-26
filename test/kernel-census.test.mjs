import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { validateDocument } from "../src/contracts.mjs";
import { implementedBuiltinValidatorIds } from "../src/builtin-validators.mjs";
import { evaluateCandidate } from "../src/evaluate.mjs";
import {
  dispatchedFromPlan,
  emittedFromResults,
  implementedFromRegistry,
  registeredFromRegistry,
  runOrphanCensus
} from "../src/census.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, kernelSelectablePack, writeRepoFile } from "./fixtures.mjs";

function loadKernelRegistry() {
  const bytes = readFileSync(new URL("../registry/kernel-mechanisms.json", import.meta.url));
  const validated = validateDocument("mechanism-registry@1", bytes);
  assert.equal(validated.ok, true, JSON.stringify(validated.errors ?? []));
  return validated.value;
}

function runKernelEvaluation() {
  // Full kernel surface: mandatory packs (injected) plus both kernel-shipped
  // selectable packs, vendored into the target with minimal authority docs.
  const target = buildTargetRepo({
    targetPacks: [kernelSelectablePack("prior-art-admission"), kernelSelectablePack("orphan-closure")],
    capabilityIndex: {
      schemaVersion: "capability-index@1",
      repositoryId: "example-repo",
      entries: [],
      generatedSurface: []
    },
    priorArtQuery: {
      schemaVersion: "prior-art-query@1",
      objectiveId: "example-objective",
      queries: [{ queryId: "baseline", terms: ["feature"] }],
      declaredCollisions: []
    },
    mechanismRegistry: { schemaVersion: "mechanism-registry@1", mechanisms: [] }
  });
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "conforming feature");
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: mkdtempSync(join(tmpdir(), "shedu-census-"))
  });
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "PROMOTABLE", JSON.stringify(outcome.receipt.reasonCodes));
  return outcome;
}

test("the kernel mechanism registry is valid and mirrors the mandatory pack checks exactly", () => {
  const registry = loadKernelRegistry();
  const { plan } = runKernelEvaluation();
  const registered = registeredFromRegistry(registry);
  const dispatched = dispatchedFromPlan(plan);
  const key = (e) => JSON.stringify(e);
  assert.deepEqual(registered.map(key).sort(), dispatched.map(key).sort());
});

test("kernel self-census over a real run: all five stages equal with ZERO exclusions", () => {
  const registry = loadKernelRegistry();
  const outcome = runKernelEvaluation();
  const { plan, planDigest, receipt, reduced } = outcome;

  const registered = registeredFromRegistry(registry);
  const implemented = implementedFromRegistry(registry, implementedBuiltinValidatorIds());
  const dispatched = dispatchedFromPlan(plan);
  const tupleByCheckId = new Map(dispatched.map((e) => [e.id, e]));
  const emitted = emittedFromResults(receipt.checkResults, plan, planDigest).filter((e) => e.effect === "BLOCKING");
  const consumed = reduced.consumed
    .filter((c) => c.effect === "BLOCKING")
    .map((c) => tupleByCheckId.get(c.checkId));

  const census = runOrphanCensus({ registered, implemented, dispatched, emitted, consumed });
  assert.equal(census.complete, true, JSON.stringify(census, null, 2));
  assert.deepEqual(census.exclusions, []);
  assert.deepEqual(census.stageCounts, {
    registered: 9,
    implemented: 9,
    dispatched: 9,
    emitted: 9,
    consumed: 9
  });
});

test("every kernel mechanism is INTEGRATED with declared negative fixtures", () => {
  const registry = loadKernelRegistry();
  assert.equal(registry.mechanisms.length, 9);
  for (const mechanism of registry.mechanisms) {
    assert.equal(mechanism.status, "INTEGRATED", mechanism.mechanismId);
    assert.ok(mechanism.negativeFixtures.length >= 1, mechanism.mechanismId);
  }
});
