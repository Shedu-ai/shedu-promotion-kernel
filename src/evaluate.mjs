import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, digestOfBytes, digestOfCanonical, validateRelativePath } from "./canonical-json.mjs";
import { validateDocument, validateValue } from "./contracts.mjs";
import { loadAuthorityDocument, readAuthorityBlob, verifyImmutableCommit } from "./authority.mjs";
import { KERNEL_RELEASE, compilePlan } from "./compiler.mjs";
import { BUILTIN_VALIDATORS, resolveBuiltinValidator } from "./builtin-validators.mjs";
import { planCheckValidatorId } from "./census.mjs";
import { createEvidenceIndex } from "./evidence.mjs";
import { reduceDisposition } from "./reducer.mjs";
import { runTargetCommand } from "./runner.mjs";
import { committishForCandidate, materializeWorktree } from "./workspace.mjs";

// Zero-provider evaluation pipeline: authority resolution from the immutable
// base, compilation with the mandatory kernel packs, isolated execution of
// every admitted check, exactly-once reduction, and a promotion-receipt@1
// bound to every input digest. Policy and target validator code execute only
// from the trusted base materialization; validation commands execute against
// the candidate materialization. No model SDK, provider credential, or
// network grant exists anywhere on this path.

const PHASES = ["CONTRACT_ADMISSION", "CANDIDATE_VALIDATION", "PROMOTION_FINALIZATION"];

function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function builtinValidatorDigest(builtinId) {
  const descriptor = BUILTIN_VALIDATORS[builtinId];
  const bytes = readFileSync(new URL(descriptor.sourceFile, import.meta.url));
  return digestOfBytes(bytes);
}

// A target command's code identity: every argv element that resolves to a
// regular file in the trusted base tree is hash-bound before any candidate
// evaluation, so the receipt pins the exact validator bytes that ran.
function targetValidatorDigest(repoDir, baseCommit, argv) {
  const resolved = [];
  for (const element of argv) {
    const contained = validateRelativePath(element);
    if (!contained.ok) continue;
    const blob = readAuthorityBlob(repoDir, baseCommit, element);
    if (blob.ok) resolved.push({ path: element, digest: digestOfBytes(blob.bytes) });
  }
  return digestOfCanonical(resolved.length > 0 ? resolved : { argv });
}

// The deterministic evaluation identity: plan plus timing-stripped results
// plus disposition. Equal inputs (and deterministic target commands) yield
// byte-identical digests; wall-clock timestamps live only in the receipt.
export function evaluationDigestOf({ planDigest, results, disposition, reasonCodes }) {
  const stripped = results.map((r) => {
    const { startedAt, completedAt, ...rest } = r;
    return rest;
  });
  return digestOfCanonical({ planDigest, results: stripped, disposition, reasonCodes });
}

export function evaluateCandidate({ repoDir, contractBytes, outDir }) {
  const failure = (reasonCode, errors) => ({ ok: false, reasonCode, errors });

  const contract = validateDocument("work-contract@1", contractBytes);
  if (!contract.ok) return failure(contract.errors[0].reasonCode, contract.errors);
  const workContract = contract.value;
  const { baseCommit } = workContract.target;

  const commit = verifyImmutableCommit(repoDir, baseCommit);
  if (!commit.ok) return failure(commit.reasonCode, [commit]);

  const profile = loadAuthorityDocument({
    repoDir,
    baseCommit,
    path: workContract.policyProfile.path,
    expectedDigest: workContract.policyProfile.digest,
    kind: "policy-profile@1"
  });
  if (!profile.ok) return failure(profile.reasonCode, profile.errors ?? [profile]);

  let capabilityIndexDigest = null;
  let capabilityIndex = null;
  if (workContract.capabilityIndex !== null) {
    const loaded = loadAuthorityDocument({
      repoDir,
      baseCommit,
      path: workContract.capabilityIndex.path,
      expectedDigest: workContract.capabilityIndex.digest,
      kind: "capability-index@1"
    });
    if (!loaded.ok) return failure(loaded.reasonCode, loaded.errors ?? [loaded]);
    capabilityIndexDigest = loaded.digest;
    capabilityIndex = loaded.value;
  }

  let priorArtQuery = null;
  if (workContract.priorArtQuery !== null) {
    const loaded = loadAuthorityDocument({
      repoDir,
      baseCommit,
      path: workContract.priorArtQuery.path,
      expectedDigest: workContract.priorArtQuery.digest,
      kind: "prior-art-query@1"
    });
    if (!loaded.ok) return failure(loaded.reasonCode, loaded.errors ?? [loaded]);
    priorArtQuery = loaded.value;
  }

  let mechanismRegistry = null;
  if (workContract.mechanismRegistry !== null) {
    const loaded = loadAuthorityDocument({
      repoDir,
      baseCommit,
      path: workContract.mechanismRegistry.path,
      expectedDigest: workContract.mechanismRegistry.digest,
      kind: "mechanism-registry@1"
    });
    if (!loaded.ok) return failure(loaded.reasonCode, loaded.errors ?? [loaded]);
    mechanismRegistry = loaded.value;
  }

  const packs = [];
  for (const selection of profile.value.packs) {
    const pack = loadAuthorityDocument({
      repoDir,
      baseCommit,
      path: selection.path,
      expectedDigest: selection.digest,
      kind: "policy-pack@1"
    });
    if (!pack.ok) return failure(pack.reasonCode, pack.errors ?? [pack]);
    packs.push({ value: pack.value, digest: pack.digest });
  }

  const compiled = compilePlan({
    workContract,
    profile: profile.value,
    profileDigest: profile.digest,
    packs,
    capabilityIndexDigest
  });
  if (!compiled.ok) return failure(compiled.errors[0].reasonCode, compiled.errors);
  const { plan, planDigest } = compiled;

  mkdirSync(outDir, { recursive: true });
  const evidenceRootDir = join(outDir, "evidence");
  const evidence = createEvidenceIndex({
    rootDir: evidenceRootDir,
    binding: {
      repositoryId: plan.repositoryId,
      baseCommit: plan.baseCommit,
      candidateId: plan.candidate.id,
      workContract: plan.sourceDigests.workContract,
      profile: plan.sourceDigests.profile,
      packs: plan.sourceDigests.packs,
      compiledPlan: planDigest
    }
  });

  const startedAt = nowIso();
  const results = [];
  let changedFiles = [];
  let halted = false;

  const candidateCommittish = committishForCandidate(repoDir, workContract.target.candidate);
  const baseWorktree = materializeWorktree(repoDir, baseCommit);
  const candidateWorktree = materializeWorktree(repoDir, candidateCommittish);
  try {
    for (const check of plan.checks) {
      if (halted) break;
      const checkStarted = nowIso();
      let partial;
      try {
        if (check.validator.kind === "BUILTIN") {
          const run = resolveBuiltinValidator(check.validator.builtinId);
          partial = run({
            repoDir,
            workContract,
            plan,
            planDigest,
            check,
            baseDir: baseWorktree.dir,
            candidateDir: candidateWorktree.dir,
            priorResults: [...results],
            evidence,
            evidenceRootDir,
            capabilityIndex,
            priorArtQuery,
            mechanismRegistry
          });
        } else {
          const execution = runTargetCommand({
            commandId: check.checkId,
            phase: check.phase,
            argv: check.validator.argv,
            cwd: baseWorktree.dir,
            envAllowlist: check.envAllowlist,
            injectEnv: {
              KERNEL_BASE_DIR: baseWorktree.dir,
              KERNEL_CANDIDATE_DIR: candidateWorktree.dir
            },
            timeoutSeconds: Math.min(check.timeoutSeconds, workContract.maxRuntimeSeconds),
            maxOutputBytes: workContract.resourceCeilings.maxOutputBytes
          });
          const refs = [
            evidence.put({
              artifactId: `target-report-${check.checkId}`,
              checkId: check.checkId,
              validatorId: planCheckValidatorId(check),
              bytes: Buffer.from(canonicalize(execution.report), "utf8"),
              mediaType: "application/json"
            }),
            evidence.put({
              artifactId: `target-stdout-${check.checkId}`,
              checkId: check.checkId,
              validatorId: planCheckValidatorId(check),
              bytes: execution.stdout,
              mediaType: "application/octet-stream"
            })
          ];
          if (execution.spawnFailed) {
            partial = { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"], evidence: refs };
          } else if (execution.report.timedOut) {
            partial = { outcome: "FIRED", reasonCodes: ["COMMAND_TIMEOUT"], evidence: refs };
          } else if (!execution.succeeded) {
            partial = { outcome: "FIRED", reasonCodes: ["COMMAND_FAILED"], evidence: refs };
          } else {
            partial = { outcome: "PASS", reasonCodes: [], evidence: refs };
          }
        }
      } catch (error) {
        partial = { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"], evidence: [], details: { failure: String(error) } };
      }

      const result = {
        schemaVersion: "check-result@1",
        checkId: check.checkId,
        packId: check.packId,
        planDigest,
        candidateId: plan.candidate.id,
        effect: check.effect,
        outcome: partial.outcome,
        reasonCodes: partial.reasonCodes ?? [],
        evidence: partial.evidence ?? [],
        startedAt: checkStarted,
        completedAt: nowIso()
      };
      const shape = validateValue("check-result@1", result);
      if (!shape.ok) {
        result.outcome = "INFRA_FAILURE";
        result.reasonCodes = ["INFRASTRUCTURE_FAILURE"];
        result.evidence = [];
      }
      results.push(result);

      if (check.checkId === "scope-boundary-classify" && partial.details?.changedFiles) {
        changedFiles = partial.details.changedFiles;
      }
      // Identity/containment failures are terminal: stop immediately rather
      // than executing validation against an unverified candidate.
      if (check.phase === "CONTRACT_ADMISSION" && check.effect === "BLOCKING" && result.outcome !== "PASS") {
        halted = true;
      }
    }
  } finally {
    candidateWorktree.cleanup();
    baseWorktree.cleanup();
  }

  const reduced = reduceDisposition({ plan, planDigest, results });
  const completedAt = nowIso();
  const finalizedEvidence = evidence.finalize();

  const validatorDigests = new Map();
  for (const check of plan.checks) {
    const validatorId = planCheckValidatorId(check);
    if (validatorDigests.has(validatorId)) continue;
    validatorDigests.set(
      validatorId,
      check.validator.kind === "BUILTIN"
        ? builtinValidatorDigest(check.validator.builtinId)
        : targetValidatorDigest(repoDir, baseCommit, check.validator.argv)
    );
  }

  const receipt = {
    schemaVersion: "promotion-receipt@1",
    kernelRelease: KERNEL_RELEASE,
    repositoryId: plan.repositoryId,
    baseCommit: plan.baseCommit,
    candidate: plan.candidate,
    digests: {
      workContract: plan.sourceDigests.workContract,
      profile: plan.sourceDigests.profile,
      packs: plan.sourceDigests.packs,
      validators: [...validatorDigests.entries()]
        .map(([validatorId, digest]) => ({ validatorId, digest }))
        .sort((a, b) => (a.validatorId < b.validatorId ? -1 : 1)),
      compiledPlan: planDigest,
      capabilityIndex: capabilityIndexDigest
    },
    checkResults: results,
    changedFiles,
    startedAt,
    completedAt,
    disposition: reduced.disposition,
    reasonCodes: reduced.reasonCodes,
    signing: null
  };
  const receiptCheck = validateValue("promotion-receipt@1", receipt);
  if (!receiptCheck.ok) {
    return failure("SCHEMA_VIOLATION", receiptCheck.errors);
  }
  const receiptBytes = Buffer.from(canonicalize(receipt), "utf8");
  writeFileSync(join(outDir, "receipt.json"), receiptBytes);
  writeFileSync(join(outDir, "plan.json"), Buffer.from(compiled.planBytes, "utf8"));

  return {
    ok: true,
    receipt,
    receiptBytes,
    receiptDigest: digestOfBytes(receiptBytes),
    plan,
    planDigest,
    reduced,
    evaluationDigest: evaluationDigestOf({
      planDigest,
      results,
      disposition: reduced.disposition,
      reasonCodes: reduced.reasonCodes
    }),
    evidenceIndexDigest: finalizedEvidence.indexDigest,
    outDir
  };
}
