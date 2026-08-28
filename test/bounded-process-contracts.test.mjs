import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { canonicalize, digestOfBytes, digestOfCanonical } from "../src/canonical-json.mjs";
import { compilePlan } from "../src/compiler.mjs";
import { validateValue } from "../src/contracts.mjs";
import { evaluateCandidate } from "../src/evaluate.mjs";
import {
  EXECUTION_PRESETS,
  executionRequirementFor
} from "../src/execution-policy.mjs";
import {
  buildTargetRepo,
  commitAll,
  contractBytesOf,
  makeCheck,
  makeContract,
  makePack,
  makeProfile,
  pinPacks,
  profileEntries,
  writeRepoFile
} from "./fixtures.mjs";
import { verifyReceipt } from "../src/receipt.mjs";

function boundedAuthorities({ requirement = EXECUTION_PRESETS.STANDARD_TEST, contractCeiling = EXECUTION_PRESETS.STANDARD_TEST, profileCeiling = EXECUTION_PRESETS.STANDARD_TEST } = {}) {
  const pack = makePack({
    schemaVersion: "policy-pack@2",
    checks: [
      makeCheck({
        validator: {
          kind: "TARGET_COMMAND",
          argv: ["node", "-e", "process.exit(0)"],
          inputManifest: [],
          executionRequirement: { ...requirement }
        }
      })
    ]
  });
  const pinned = pinPacks([pack]);
  const profile = makeProfile(profileEntries(pinned), {
    schemaVersion: "policy-profile@2",
    executionPolicy: { ...profileCeiling }
  });
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({
    schemaVersion: "work-contract@2",
    validationCommands: [
      {
        commandId: "unit-tests",
        phase: "CANDIDATE_VALIDATION",
        argv: ["node", "--test"],
        executionRequirement: { ...requirement }
      }
    ],
    policyProfile: {
      profileId: profile.profileId,
      path: "policy/profile.json",
      digest: profileDigest
    },
    resourceCeilings: {
      maxOutputBytes: 1048576,
      maxArtifactBytes: 1048576,
      executionCeiling: { ...contractCeiling }
    }
  });
  return { pack, pinned, profile, profileDigest, contract };
}

test("generated @2 schemas are hash-bound to their deterministic generator", () => {
  const provenance = JSON.parse(
    readFileSync(new URL("../schemas/bounded-contracts.provenance.json", import.meta.url), "utf8")
  );
  assert.equal(
    provenance.generatorDigest,
    digestOfBytes(readFileSync(new URL("../scripts/generate-bounded-contract-schemas.mjs", import.meta.url)))
  );
  for (const entry of provenance.generated) {
    assert.equal(digestOfBytes(readFileSync(new URL(`../schemas/${entry.path}`, import.meta.url))), entry.digest, entry.path);
  }
});

test("v2 authorities express a hidden bounded task budget with closed schemas", () => {
  const { pack, profile, contract } = boundedAuthorities();
  assert.equal(validateValue("policy-pack@2", pack).ok, true);
  assert.equal(validateValue("policy-profile@2", profile).ok, true);
  assert.equal(validateValue("work-contract@2", contract).ok, true);

  const mislabeled = structuredClone(contract);
  mislabeled.resourceCeilings.executionCeiling = { class: "SINGLE_PROCESS", maxTasks: 128 };
  assert.equal(validateValue("work-contract@2", mislabeled).ok, false);

  const undersized = structuredClone(profile);
  undersized.executionPolicy = { class: "BOUNDED_PROCESS_TREE", maxTasks: 64 };
  assert.equal(validateValue("policy-profile@2", undersized).ok, false);
});

test("the compiler intersects pack requirement with contract and profile authority", () => {
  const authorities = boundedAuthorities();
  const compiled = compilePlan({
    workContract: authorities.contract,
    profile: authorities.profile,
    profileDigest: authorities.profileDigest,
    packs: authorities.pinned
  });
  assert.equal(compiled.ok, true, JSON.stringify(compiled.errors));
  assert.equal(compiled.plan.schemaVersion, "compiled-policy-plan@2");
  assert.deepEqual(
    { class: compiled.plan.validationCommands[0].execution.class, maxTasks: compiled.plan.validationCommands[0].execution.maxTasks },
    EXECUTION_PRESETS.STANDARD_TEST
  );
  assert.equal(compiled.plan.validationCommands[0].execution.capabilityId, "bounded-process-tree@1");
  assert.match(compiled.plan.validationCommands[0].execution.portableAuthorityDigest, /^sha256:[0-9a-f]{64}$/);
  const target = compiled.plan.checks.find((check) => check.validator.kind === "TARGET_COMMAND");
  assert.deepEqual(
    { class: target.execution.class, maxTasks: target.execution.maxTasks },
    EXECUTION_PRESETS.STANDARD_TEST
  );
  assert.equal(target.execution.capabilityId, "bounded-process-tree@1");
  assert.equal(target.execution.portableAuthorityDigest, compiled.plan.validationCommands[0].execution.portableAuthorityDigest);
  assert.equal(validateValue("compiled-policy-plan@2", compiled.plan).ok, true);
});

test("a pack cannot obtain a larger task surface from a controller or retry", () => {
  const authorities = boundedAuthorities({
    contractCeiling: EXECUTION_PRESETS.STRICT,
    profileCeiling: EXECUTION_PRESETS.STANDARD_TEST
  });
  const compiled = compilePlan({
    workContract: authorities.contract,
    profile: authorities.profile,
    profileDigest: authorities.profileDigest,
    packs: authorities.pinned
  });
  assert.equal(compiled.ok, false);
  assert.ok(compiled.errors.some((error) => error.reasonCode === "PROCESS_TREE_UNAUTHORIZED"));

  const direct = executionRequirementFor({
    requirement: EXECUTION_PRESETS.STANDARD_TEST,
    contractCeiling: EXECUTION_PRESETS.STRICT,
    profileCeiling: EXECUTION_PRESETS.STANDARD_TEST
  });
  assert.deepEqual(direct.reasonCode, "PROCESS_TREE_UNAUTHORIZED");
});

test("legacy @1 contracts retain their exact single-process schema", () => {
  const legacy = makeContract();
  assert.equal(validateValue("work-contract@1", legacy).ok, true);
  const widened = structuredClone(legacy);
  widened.resourceCeilings.maxProcesses = 2;
  assert.equal(validateValue("work-contract@1", widened).ok, false);
});

function evaluateV2(requirement) {
  const targetPack = makePack({
    schemaVersion: "policy-pack@2",
    packId: "bounded-target",
    checks: [
      makeCheck({
        checkId: "bounded-target-check",
        validator: {
          kind: "TARGET_COMMAND",
          argv: ["node", "-e", "process.exit(0)"],
          inputManifest: [],
          executionRequirement: { ...requirement }
        }
      })
    ]
  });
  const target = buildTargetRepo({
    targetPacks: [targetPack],
    profileOverrides: {
      schemaVersion: "policy-profile@2",
      executionPolicy: { ...requirement }
    },
    validationCommands: [
      {
        commandId: "v2-validation",
        phase: "CANDIDATE_VALIDATION",
        argv: ["node", "-e", "process.exit(0)"],
        executionRequirement: { ...requirement }
      }
    ]
  });
  writeRepoFile(target.repoDir, "src/app.mjs", "export const app = 2;\n");
  const candidate = commitAll(target.repoDir, "v2 candidate");
  const contract = target.contractFor(candidate, {
    schemaVersion: "work-contract@2",
    resourceCeilings: {
      maxOutputBytes: 1048576,
      maxArtifactBytes: 1048576,
      executionCeiling: { ...requirement }
    }
  });
  const outDir = mkdtempSync(join(tmpdir(), "shedu-bounded-evaluate-"));
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(contract),
    outDir
  });
  return { ...target, outDir, outcome };
}

test("v2 strict execution passes and binds backend evidence without changing @1", () => {
  const run = evaluateV2(EXECUTION_PRESETS.STRICT);
  try {
    assert.equal(run.outcome.ok, true, JSON.stringify(run.outcome.errors));
    assert.equal(run.outcome.receipt.schemaVersion, "promotion-receipt@2");
    assert.equal(run.outcome.receipt.disposition, "PROMOTABLE", JSON.stringify(run.outcome.receipt.reasonCodes));
    assert.ok(run.outcome.receipt.executionReports.length >= 2);
    assert.ok(run.outcome.receipt.executionReports.every((entry) => entry.report.class === "SINGLE_PROCESS"));
    assert.ok(run.outcome.receipt.executionReports.every((entry) => entry.report.capabilityId === "single-process@1"));
    const verified = verifyReceipt({
      receiptBytes: run.outcome.receiptBytes,
      planBytes: Buffer.from(canonicalize(run.outcome.plan))
    });
    assert.equal(verified.ok, true, JSON.stringify(verified.errors));

    const missing = structuredClone(run.outcome.receipt);
    missing.executionReports.pop();
    const missingVerification = verifyReceipt({
      receiptBytes: Buffer.from(canonicalize(missing)),
      planBytes: Buffer.from(canonicalize(run.outcome.plan))
    });
    assert.equal(missingVerification.ok, false);
    assert.ok(missingVerification.errors.some((error) => error.reasonCode === "EVIDENCE_MISSING"));

    const laundered = structuredClone(run.outcome.receipt);
    laundered.executionReports[0].report.limitFired = true;
    laundered.executionReports[0].report.limitEvents = 1;
    const launderingVerification = verifyReceipt({
      receiptBytes: Buffer.from(canonicalize(laundered)),
      planBytes: Buffer.from(canonicalize(run.outcome.plan))
    });
    assert.equal(launderingVerification.ok, false);
    assert.ok(launderingVerification.errors.some((error) => error.reasonCode === "DISPOSITION_MISMATCH"));

    const replayedAuthority = structuredClone(run.outcome.receipt);
    replayedAuthority.executionReports[0].report.capabilityId = "bounded-process-tree@1";
    replayedAuthority.executionReports[0].report.portableAuthorityDigest = `sha256:${"9".repeat(64)}`;
    const replayedVerification = verifyReceipt({
      receiptBytes: Buffer.from(canonicalize(replayedAuthority)),
      planBytes: Buffer.from(canonicalize(run.outcome.plan))
    });
    assert.equal(replayedVerification.ok, false);
    assert.ok(replayedVerification.errors.some((error) => ["RECEIPT_REPLAY", "SCHEMA_VIOLATION"].includes(error.reasonCode)));
  } finally {
    rmSync(run.repoDir, { recursive: true, force: true });
    rmSync(run.outDir, { recursive: true, force: true });
  }
});

test("bounded execution either runs under Linux OCI or closes with a routing reason", () => {
  const run = evaluateV2(EXECUTION_PRESETS.STANDARD_TEST);
  try {
    assert.equal(run.outcome.ok, true, JSON.stringify(run.outcome.errors));
    const substitutedPlan = structuredClone(run.outcome.plan);
    substitutedPlan.validationCommands[0].execution.portableAuthorityDigest = `sha256:${"8".repeat(64)}`;
    const substituted = verifyReceipt({
      receiptBytes: run.outcome.receiptBytes,
      planBytes: Buffer.from(canonicalize(substitutedPlan))
    });
    assert.equal(substituted.ok, false);
    assert.ok(substituted.errors.some((error) => error.reasonCode === "AUTHORITY_DIGEST_MISMATCH"));
    if (process.platform === "linux") {
      assert.equal(run.outcome.receipt.disposition, "PROMOTABLE", JSON.stringify(run.outcome.receipt.reasonCodes));
      assert.ok(run.outcome.receipt.executionReports.every((entry) => entry.report.backend === "linux-oci"));
    } else {
      assert.equal(run.outcome.receipt.disposition, "BLOCKED");
      assert.ok(run.outcome.receipt.reasonCodes.includes("EXECUTION_BACKEND_REQUIRED"));
      assert.equal(run.outcome.receipt.executionReports.length, 0);
    }
  } finally {
    rmSync(run.repoDir, { recursive: true, force: true });
    rmSync(run.outDir, { recursive: true, force: true });
  }
});
