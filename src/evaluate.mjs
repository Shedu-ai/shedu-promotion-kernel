import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, digestOfBytes, digestOfCanonical } from "./canonical-json.mjs";
import { validateDocument, validateValue } from "./contracts.mjs";
import { loadAuthorityDocument, verifyImmutableCommit } from "./authority.mjs";
import { KERNEL_RELEASE, compilePlan } from "./compiler.mjs";
import { resolveBuiltinValidator } from "./builtin-validators.mjs";
import { planCheckValidatorId } from "./census.mjs";
import { validatorDigestForPlanCheck } from "./validator-digest.mjs";
import { createEvidenceIndex } from "./evidence.mjs";
import { reduceDisposition, isReducerDisposition } from "./reducer.mjs";
import { runTargetCommand } from "./runner.mjs";
import { createDeadline } from "./deadline.mjs";
import { verifyContractAuthorization } from "./authorization.mjs";
import { committishForCandidate, materializeWorktree } from "./workspace.mjs";

// Control points implemented in the evaluation orchestrator.
export const CONTROL_POINTS = Object.freeze(["containment-halt-routing", "artifact-root-enforcement"]);

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

// Checks whose blocking failure is an identity, containment, or
// evidence-integrity failure: the run halts immediately and every remaining
// check receives an explicit SKIPPED non-success record. Admission-phase
// blocking failures (authority) halt as well.
const INTEGRITY_HALT_CHECK_IDS = new Set([
  "candidate-identity-verify",
  "scope-boundary-classify",
  "candidate-tree-stability",
  "evidence-binding-index"
]);

// Exposed for the control-surface runtime proofs: the actual routing table
// and the actual artifact-root resolution the evaluator uses.
export function isIntegrityHaltCheck(checkId) {
  return INTEGRITY_HALT_CHECK_IDS.has(checkId);
}

export function resolveEvidenceDir(outDir, artifactRoot) {
  return join(outDir, artifactRoot.replace(/\/+$/, ""), "evidence");
}

export function evaluateCandidate({ repoDir, contractBytes, outDir, plantHooks = null }) {
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

  // Authorization is verified against the trust root in the base-authoritative
  // profile, not the key embedded in the contract itself.
  const authorization = verifyContractAuthorization(workContract, profile.value.authorization);
  if (!authorization.ok) return failure(authorization.reasonCode, [authorization]);

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
  // artifactRoot is mechanically load-bearing: evidence is written under it,
  // and the receipt records it. It is a contract-declared, path-contained
  // relative directory; the caller's outDir is the operational mount point.
  const artifactRootRel = workContract.artifactRoot.replace(/\/+$/, "");
  const evidenceRootDir = resolveEvidenceDir(outDir, workContract.artifactRoot);
  const evidence = createEvidenceIndex({
    rootDir: evidenceRootDir,
    maxTotalBytes: workContract.resourceCeilings.maxArtifactBytes,
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
  // Evaluation-wide deadline: a MONOTONIC absolute bound over the whole run.
  // Per-command timeouts never exceed the remaining budget, and a check that
  // finishes after exhaustion cannot be recorded PASS.
  const deadline = createDeadline(workContract.maxRuntimeSeconds * 1000);
  const results = [];
  let changedFiles = [];
  let haltCode = null;
  let lastPhase = null;

  const candidateCommittish = committishForCandidate(repoDir, workContract.target.candidate);
  const baseWorktree = materializeWorktree(repoDir, baseCommit);
  const candidateWorktree = materializeWorktree(repoDir, candidateCommittish);
  // Canonical real paths so sandboxed commands never traverse a symlink the
  // sandbox does not grant, and so injected dir env vars point at grantable
  // paths.
  const baseRealDir = realpathSync(baseWorktree.dir);
  const candidateRealDir = realpathSync(candidateWorktree.dir);
  try {
    for (const check of plan.checks) {
      if (lastPhase !== null && check.phase !== lastPhase) {
        plantHooks?.afterPhase?.(lastPhase, { candidateDir: candidateWorktree.dir, evidenceRootDir });
      }
      lastPhase = check.phase;
      const checkStarted = nowIso();

      if (haltCode === null && deadline.expired()) haltCode = "DEADLINE_EXCEEDED";
      if (haltCode !== null) {
        // Explicit non-success record for skipped required work.
        results.push({
          schemaVersion: "check-result@1",
          checkId: check.checkId,
          packId: check.packId,
          planDigest,
          candidateId: plan.candidate.id,
          effect: check.effect,
          outcome: "SKIPPED",
          reasonCodes: [haltCode],
          evidence: [],
          startedAt: checkStarted,
          completedAt: checkStarted
        });
        continue;
      }

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
            baseDir: baseRealDir,
            candidateDir: candidateRealDir,
            priorResults: [...results],
            evidence,
            evidenceRootDir,
            capabilityIndex,
            priorArtQuery,
            mechanismRegistry,
            deadline
          });
        } else {
          const remainingMs = deadline.remainingMs();
          if (remainingMs <= 0) {
            partial = { outcome: "FIRED", reasonCodes: ["DEADLINE_EXCEEDED"], evidence: [] };
          } else {
            const execution = runTargetCommand({
              commandId: check.checkId,
              phase: check.phase,
              argv: check.validator.argv,
              cwd: baseRealDir,
              envAllowlist: check.envAllowlist,
              injectEnv: {
                KERNEL_BASE_DIR: baseRealDir,
                KERNEL_CANDIDATE_DIR: candidateRealDir
              },
              timeoutMs: Math.min(check.timeoutSeconds * 1000, remainingMs),
              maxOutputBytes: workContract.resourceCeilings.maxOutputBytes,
              maxProcesses: workContract.resourceCeilings.maxProcesses,
              readRoots: [baseRealDir, candidateRealDir]
            });
            const refs = [
              evidence.put({
                artifactId: `target-stdout-${check.checkId}`,
                checkId: check.checkId,
                validatorId: planCheckValidatorId(check),
                bytes: execution.stdout,
                mediaType: "application/octet-stream"
              })
            ];
            // A resolvable command has a machine report; a toolchain-rejected
            // one does not.
            if (execution.report !== null) {
              refs.unshift(
                evidence.put({
                  artifactId: `target-report-${check.checkId}`,
                  checkId: check.checkId,
                  validatorId: planCheckValidatorId(check),
                  bytes: Buffer.from(canonicalize(execution.report), "utf8"),
                  mediaType: "application/json"
                })
              );
            }
            if (execution.toolchainRejected) {
              partial = { outcome: "INFRA_FAILURE", reasonCodes: ["TOOLCHAIN_UNRESOLVED"], evidence: refs };
            } else if (execution.spawnFailed) {
              partial = { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"], evidence: refs };
            } else if (execution.report.timedOut) {
              partial = { outcome: "FIRED", reasonCodes: ["COMMAND_TIMEOUT"], evidence: refs };
            } else if (!execution.succeeded) {
              partial = { outcome: "FIRED", reasonCodes: ["COMMAND_FAILED"], evidence: refs };
            } else if (deadline.expired()) {
              partial = { outcome: "FIRED", reasonCodes: ["DEADLINE_EXCEEDED"], evidence: refs };
            } else {
              partial = { outcome: "PASS", reasonCodes: [], evidence: refs };
            }
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
      // Identity, containment, authority (admission), and evidence-integrity
      // failures are terminal: halt immediately; the remaining checks receive
      // explicit SKIPPED records above.
      if (
        result.outcome !== "PASS" &&
        check.effect === "BLOCKING" &&
        (check.phase === "CONTRACT_ADMISSION" || INTEGRITY_HALT_CHECK_IDS.has(check.checkId))
      ) {
        haltCode = "CHECK_SKIPPED";
      }
    }
  } finally {
    candidateWorktree.cleanup();
    baseWorktree.cleanup();
  }

  const reduced = reduceDisposition({ plan, planDigest, results });
  // The disposition must come from the sanctioned reducer, not a forged
  // object: an unbranded disposition is never trusted.
  if (!isReducerDisposition(reduced)) {
    return failure("INFRASTRUCTURE_FAILURE", [{ reasonCode: "INFRASTRUCTURE_FAILURE", message: "disposition was not produced by the disposition reducer" }]);
  }
  const completedAt = nowIso();

  // Anchor every check result in the content-addressed store before the
  // index is finalized: a receipt result rewritten after the fact no longer
  // matches its anchored bytes, and the finalized index digest is bound into
  // the receipt below.
  const checksById = new Map(plan.checks.map((c) => [c.checkId, c]));
  try {
    for (const result of results) {
      evidence.put({
        artifactId: `result-${result.checkId}`,
        checkId: result.checkId,
        validatorId: planCheckValidatorId(checksById.get(result.checkId)),
        bytes: Buffer.from(canonicalize(result), "utf8"),
        mediaType: "application/json"
      });
    }
  } catch (error) {
    return failure("DOCUMENT_BOUNDS_EXCEEDED", [
      { reasonCode: "DOCUMENT_BOUNDS_EXCEEDED", message: `evidence anchoring failed: ${String(error)}` }
    ]);
  }
  const finalizedEvidence = evidence.finalize();

  const validatorDigests = new Map();
  for (const check of plan.checks) {
    const validatorId = planCheckValidatorId(check);
    if (validatorDigests.has(validatorId)) continue;
    validatorDigests.set(validatorId, validatorDigestForPlanCheck(repoDir, baseCommit, check));
  }

  const receipt = {
    schemaVersion: "promotion-receipt@1",
    kernelRelease: KERNEL_RELEASE,
    repositoryId: plan.repositoryId,
    baseCommit: plan.baseCommit,
    candidate: plan.candidate,
    artifactRoot: workContract.artifactRoot,
    digests: {
      workContract: plan.sourceDigests.workContract,
      profile: plan.sourceDigests.profile,
      packs: plan.sourceDigests.packs,
      validators: [...validatorDigests.entries()]
        .map(([validatorId, digest]) => ({ validatorId, digest }))
        .sort((a, b) => (a.validatorId < b.validatorId ? -1 : 1)),
      compiledPlan: planDigest,
      capabilityIndex: capabilityIndexDigest,
      evidenceIndex: finalizedEvidence.indexDigest
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
