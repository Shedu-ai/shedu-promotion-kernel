import { readFileSync } from "node:fs";
import { canonicalize, digestOfBytes, digestOfCanonical } from "./canonical-json.mjs";
import { validateDocument, validateValue } from "./contracts.mjs";
import { knownBuiltinValidatorIds } from "./builtin-validators.mjs";
import { isResolvableTargetExecutable } from "./validator-digest.mjs";
import {
  executionCapabilityId,
  executionRequirementFor,
  executionRequirementForLegacyContract
} from "./execution-policy.mjs";
import { portableLinuxExecutionAuthority } from "./oci-runtime.mjs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const KERNEL_RELEASE = `${pkg.name}@${pkg.version}`;

const PHASES = ["CONTRACT_ADMISSION", "CANDIDATE_VALIDATION", "PROMOTION_FINALIZATION"];

// The four mandatory kernel packs are kernel integrity, not project taste.
// They ship with the kernel release, are strict-parsed and digest-pinned at
// load, and are injected into every compilation: a profile cannot omit,
// re-declare, weaken, or replace them.
export const MANDATORY_PACK_IDS = Object.freeze([
  "candidate-identity",
  "scope-boundary",
  "validation-plan",
  "evidence-binding"
]);

const kernelPacks = MANDATORY_PACK_IDS.map((packId) => {
  const bytes = readFileSync(new URL(`../packs/${packId}.json`, import.meta.url));
  const validated = validateDocument("policy-pack@1", bytes);
  if (!validated.ok) {
    throw new Error(`kernel pack ${packId} is invalid: ${JSON.stringify(validated.errors)}`);
  }
  if (validated.value.packId !== packId) {
    throw new Error(`kernel pack file ${packId}.json declares packId ${validated.value.packId}`);
  }
  return Object.freeze({ value: validated.value, digest: digestOfBytes(bytes) });
});

export function mandatoryKernelPacks() {
  return [...kernelPacks];
}

// Resolve a profile and its packs into a canonical compiled-policy-plan@1.
// Equal inputs produce byte-identical plan bytes and digest. All compile-time
// failures are collected before returning, since no candidate command has run
// yet; any error means no plan is produced.
export function compilePlan({
  workContract,
  profile,
  profileDigest,
  packs,
  capabilityIndexDigest = null,
  builtinValidatorIds = knownBuiltinValidatorIds(),
  mandatoryPacks = mandatoryKernelPacks()
}) {
  const contractVersion = workContract?.schemaVersion;
  const boundedContracts = contractVersion === "work-contract@2";
  const workContractKind = boundedContracts ? "work-contract@2" : "work-contract@1";
  const profileKind = boundedContracts ? "policy-profile@2" : "policy-profile@1";
  for (const [kind, value] of [
    [workContractKind, workContract],
    [profileKind, profile]
  ]) {
    const r = validateValue(kind, value);
    if (!r.ok) return { ok: false, errors: r.errors };
  }
  for (const p of packs) {
    const packKind = boundedContracts ? "policy-pack@2" : "policy-pack@1";
    const r = validateValue(packKind, p.value);
    if (!r.ok) return { ok: false, errors: r.errors };
  }

  const errors = [];
  const fail = (reasonCode, message) => errors.push({ reasonCode, message });

  if (!boundedContracts && contractVersion !== "work-contract@1") {
    fail("SCHEMA_VIOLATION", `unsupported work-contract version ${JSON.stringify(contractVersion)}`);
  }
  if (profile?.schemaVersion !== profileKind) {
    fail("SCHEMA_VIOLATION", `${workContractKind} requires ${profileKind}`);
  }

  if (workContract.policyProfile.digest !== profileDigest) {
    fail("AUTHORITY_DIGEST_MISMATCH", `work contract pins profile digest ${workContract.policyProfile.digest}, received ${profileDigest}`);
  }
  if (workContract.policyProfile.profileId !== profile.profileId) {
    fail("PROFILE_IDENTITY_MISMATCH", `work contract names profile ${workContract.policyProfile.profileId}, document declares ${profile.profileId}`);
  }
  const expectedCapabilityDigest = workContract.capabilityIndex === null ? null : workContract.capabilityIndex.digest;
  if (expectedCapabilityDigest !== capabilityIndexDigest) {
    fail("AUTHORITY_DIGEST_MISMATCH", `work contract pins capability-index digest ${expectedCapabilityDigest}, received ${capabilityIndexDigest}`);
  }

  const supplied = new Map();
  for (const p of packs) {
    if (supplied.has(p.value.packId)) fail("DUPLICATE_PACK_ID", `pack ${p.value.packId} supplied more than once`);
    supplied.set(p.value.packId, p);
  }
  const selected = new Map();
  const mandatoryIds = new Set(mandatoryPacks.map((p) => p.value.packId));
  for (const p of mandatoryPacks) {
    selected.set(p.value.packId, p);
  }
  for (const sel of profile.packs) {
    if (mandatoryIds.has(sel.packId)) {
      fail("POLICY_CONFLICT", `pack ${sel.packId} is a mandatory kernel pack: it is injected by the kernel and cannot be re-declared, replaced, or weakened by a profile`);
    }
  }
  for (const p of packs) {
    if (mandatoryIds.has(p.value.packId)) {
      fail("POLICY_CONFLICT", `pack ${p.value.packId} is a mandatory kernel pack and cannot be supplied from the target repository`);
    }
  }
  for (const sel of profile.packs) {
    if (mandatoryIds.has(sel.packId)) continue;
    const p = supplied.get(sel.packId);
    if (!p) {
      fail("PACK_NOT_FOUND", `profile selects ${sel.packId}@${sel.version} but no pack document was supplied`);
      continue;
    }
    if (p.value.version !== sel.version) {
      fail("PACK_IDENTITY_MISMATCH", `${sel.packId}: profile pins version ${sel.version}, document declares ${p.value.version}`);
    }
    if (p.digest !== sel.digest) {
      fail("PACK_DIGEST_MISMATCH", `${sel.packId}: profile pins ${sel.digest}, supplied document digest is ${p.digest}`);
    }
    selected.set(sel.packId, p);
  }
  for (const packId of supplied.keys()) {
    if (!profile.packs.some((s) => s.packId === packId)) {
      fail("PACK_NOT_SELECTED", `pack ${packId} was supplied but is not selected by profile ${profile.profileId}`);
    }
  }

  for (const [packId, p] of selected) {
    for (const dep of p.value.dependencies) {
      const target = selected.get(dep.packId);
      if (!target || target.value.version !== dep.version) {
        fail("DEPENDENCY_UNSATISFIED", `${packId} requires ${dep.packId}@${dep.version}, which the profile does not select`);
        continue;
      }
      if (target.digest !== dep.digest) {
        fail("PACK_DIGEST_MISMATCH", `${packId} pins ${dep.packId} digest ${dep.digest}, selected digest is ${target.digest}`);
      }
    }
  }

  // Every check of a dependency must be schedulable before every check of the
  // dependent pack: dependencies are never silently dropped or reordered. A
  // dependent check in an earlier phase than any dependency check is a
  // compile-time conflict.
  for (const [packId, p] of selected) {
    const minPhase = Math.min(...p.value.checks.map((c) => PHASES.indexOf(c.phase)));
    for (const dep of p.value.dependencies) {
      const target = selected.get(dep.packId);
      if (!target) continue;
      for (const depCheck of target.value.checks) {
        if (PHASES.indexOf(depCheck.phase) > minPhase) {
          fail(
            "PHASE_ORDER_CONFLICT",
            `pack ${packId} has a check in ${PHASES[minPhase]} but depends on ${dep.packId}, whose check ${depCheck.checkId} runs later in ${depCheck.phase}`
          );
        }
      }
    }
  }

  // Deterministic topological order: Kahn's algorithm with a lexicographically
  // sorted frontier, dependencies first.
  const ids = [...selected.keys()].sort();
  const depsOf = (id) =>
    selected
      .get(id)
      .value.dependencies.map((d) => d.packId)
      .filter((d) => selected.has(d) && d !== id);
  const indegree = new Map(ids.map((id) => [id, depsOf(id).length]));
  const order = [];
  let frontier = ids.filter((id) => indegree.get(id) === 0).sort();
  while (frontier.length > 0) {
    const id = frontier.shift();
    order.push(id);
    for (const other of ids) {
      if (depsOf(other).includes(id)) {
        indegree.set(other, indegree.get(other) - 1);
        if (indegree.get(other) === 0) {
          frontier.push(other);
          frontier = frontier.sort();
        }
      }
    }
  }
  if (order.length !== ids.length) {
    fail("DEPENDENCY_CYCLE", `packs form a dependency cycle: ${ids.filter((id) => !order.includes(id)).join(", ")}`);
  }

  const checkOwner = new Map();
  const checkById = new Map();
  for (const [packId, p] of selected) {
    for (const check of p.value.checks) {
      if (checkOwner.has(check.checkId)) {
        fail("DUPLICATE_CHECK_ID", `check ${check.checkId} is declared by both ${checkOwner.get(check.checkId)} and ${packId}`);
      } else {
        checkOwner.set(check.checkId, packId);
        checkById.set(check.checkId, check);
      }
      if (check.validator.kind === "BUILTIN" && !builtinValidatorIds.has(check.validator.builtinId)) {
        fail("UNKNOWN_VALIDATOR", `check ${check.checkId} references unknown builtin validator ${check.validator.builtinId}`);
      }
      // A target command's executable must be admitted by the closed
      // toolchain authority: an absolute/mutable external validator or a
      // bare non-node name has no admissible identity and is rejected before
      // any candidate command runs.
      if (check.validator.kind === "TARGET_COMMAND" && !isResolvableTargetExecutable(check.validator.argv[0])) {
        fail("UNKNOWN_VALIDATOR", `check ${check.checkId} target command executable ${JSON.stringify(check.validator.argv[0])} is not an admitted toolchain executable`);
      }
    }
  }

  const compileExecution = (requirement, location) => {
    if (!boundedContracts) return executionRequirementForLegacyContract();
    const resolved = executionRequirementFor({
      requirement,
      contractCeiling: workContract.resourceCeilings.executionCeiling,
      profileCeiling: profile.executionPolicy
    });
    if (!resolved.ok) {
      fail(resolved.reasonCode, `${location}: ${resolved.message}`);
      return null;
    }
    const portable = resolved.value.class === "BOUNDED_PROCESS_TREE"
      ? portableLinuxExecutionAuthority(resolved.value.class)
      : { capabilityId: executionCapabilityId(resolved.value.class), portableAuthorityDigest: null };
    return { ...resolved.value, ...portable };
  };

  const compiledValidationCommands = boundedContracts
    ? workContract.validationCommands.map((command) => ({
        commandId: command.commandId,
        phase: command.phase,
        argv: [...command.argv],
        execution: compileExecution(command.executionRequirement, `validation command ${command.commandId}`)
      }))
    : null;

  const strengthened = new Set(profile.strengthen);
  for (const checkId of strengthened) {
    const check = checkById.get(checkId);
    if (!check) {
      fail("UNKNOWN_CHECK_STRENGTHENED", `profile strengthens unknown check ${checkId}`);
      continue;
    }
    if (check.resultConsumer !== "DISPOSITION_REDUCER") {
      fail("STRENGTHEN_CONFLICT", `check ${checkId} is EVIDENCE_ONLY and cannot be strengthened to BLOCKING`);
    }
  }

  if (errors.length > 0) return { ok: false, errors };

  const packOrder = new Map(order.map((id, idx) => [id, idx]));
  const planChecks = [];
  for (const packId of order) {
    const p = selected.get(packId);
    for (const check of p.value.checks) {
      // The phase-order gate above guarantees every dependency check precedes
      // every check of this pack, so nothing is filtered here.
      const dependsOn = new Set();
      for (const dep of p.value.dependencies) {
        for (const depCheck of selected.get(dep.packId).value.checks) {
          dependsOn.add(depCheck.checkId);
        }
      }
      planChecks.push({
        checkId: check.checkId,
        packId,
        packVersion: p.value.version,
        phase: check.phase,
        effect: strengthened.has(check.checkId) ? "BLOCKING" : check.effect,
        validator:
          boundedContracts && check.validator.kind === "TARGET_COMMAND"
            ? {
                kind: check.validator.kind,
                argv: [...check.validator.argv],
                inputManifest: [...check.validator.inputManifest]
              }
            : check.validator,
        inputs: check.inputs,
        outputSchemaId: check.outputSchemaId,
        timeoutSeconds: check.timeoutSeconds,
        network: check.network,
        filesystem: check.filesystem,
        envAllowlist: check.envAllowlist,
        resultConsumer: check.resultConsumer,
        dependsOn: [...dependsOn].sort(),
        ...(boundedContracts
          ? {
              execution:
                check.validator.kind === "TARGET_COMMAND"
                  ? compileExecution(check.validator.executionRequirement, `check ${check.checkId}`)
                  : null
            }
          : {})
      });
    }
  }
  planChecks.sort(
    (a, b) =>
      PHASES.indexOf(a.phase) - PHASES.indexOf(b.phase) ||
      packOrder.get(a.packId) - packOrder.get(b.packId) ||
      (a.checkId < b.checkId ? -1 : 1)
  );

  const plan = {
    schemaVersion: boundedContracts ? "compiled-policy-plan@2" : "compiled-policy-plan@1",
    kernelRelease: KERNEL_RELEASE,
    repositoryId: workContract.target.repositoryId,
    baseCommit: workContract.target.baseCommit,
    candidate: {
      kind: workContract.target.candidate.kind,
      id: workContract.target.candidate.id
    },
    profileId: profile.profileId,
    sourceDigests: {
      workContract: digestOfCanonical(workContract),
      profile: profileDigest,
      capabilityIndex: capabilityIndexDigest,
      packs: [
        ...mandatoryPacks.map((p) => ({ packId: p.value.packId, version: p.value.version, digest: p.digest })),
        ...profile.packs.map((s) => ({ packId: s.packId, version: s.version, digest: s.digest }))
      ].sort((a, b) => (a.packId < b.packId ? -1 : 1))
    },
    checks: planChecks,
    ...(boundedContracts
      ? {
          executionPolicy: {
            contractCeiling: { ...workContract.resourceCeilings.executionCeiling },
            profileCeiling: { ...profile.executionPolicy }
          },
          validationCommands: compiledValidationCommands
        }
      : {})
  };

  if (errors.length > 0) return { ok: false, errors };
  const planCheck = validateValue(boundedContracts ? "compiled-policy-plan@2" : "compiled-policy-plan@1", plan);
  if (!planCheck.ok) {
    throw new Error(`compiler produced an invalid plan: ${JSON.stringify(planCheck.errors)}`);
  }
  const planBytes = canonicalize(plan);
  return {
    ok: true,
    plan,
    planBytes,
    planDigest: digestOfBytes(Buffer.from(planBytes, "utf8"))
  };
}
