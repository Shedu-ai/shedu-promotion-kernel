import {
  lstatSync,
  readlinkSync,
  realpathSync
} from "node:fs";
import { dirname, isAbsolute, join, relative } from "node:path";
import { canonicalize, digestOfCanonical } from "./canonical-json.mjs";
import { readBoundedRegularFile, hashBoundedRegularFile } from "./bounded-file.mjs";
import { validateDocument } from "./contracts.mjs";
import { validateAgentProjection } from "./agent-contracts.mjs";
import {
  admittedKernelIdentity,
  admittedLifecycleEvidence,
  admittedLifecycleStatus,
  isAdmitted,
  lifecycleFailureCode
} from "./admission.mjs";
import { actionsForEvaluation, actionsForLifecycle } from "./next-actions.mjs";
import { verifyReceipt } from "./receipt.mjs";

const MAX_CONTRACT_BYTES = 1_048_576;
const MAX_RECEIPT_BYTES = 1_048_576;
const MAX_PLAN_BYTES = 1_048_576;
export const MAX_EVIDENCE_PREVIEW_BYTES = 65_536;
const VERSION_TARGET_RE = /^\.v-[1-9][0-9]*-[0-9a-f]{32}$/;

export class AgentProjectionError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = "AgentProjectionError";
    this.reasonCode = reasonCode;
  }
}

const fail = (reasonCode, message) => {
  throw new AgentProjectionError(reasonCode, message);
};

function validatedProjection(kind, value) {
  const validated = validateAgentProjection(kind, value);
  if (!validated.ok) {
    fail("INFRASTRUCTURE_FAILURE", `kernel produced an invalid ${kind} projection: ${JSON.stringify(validated.errors)}`);
  }
  return value;
}

export function projectAgentStatus({ admission, probe, kernelRelease }) {
  const admitted = isAdmitted(admission);
  const implementationStatus = admittedLifecycleStatus(admission);
  const identity = admittedKernelIdentity(admission);
  const lifecycleEvidence = admittedLifecycleEvidence(admission);
  const lifecycleFailure = lifecycleFailureCode(admission);
  const status = {
    schemaVersion: "kernel-agent-status@2",
    subject: "shedu-promotion-kernel",
    kernelRelease,
    kernelCommit: identity.kernelCommit,
    kernelTree: identity.kernelTree,
    implementationStatus,
    promotionEntrypointAvailable: probe.promotionEntrypointAvailable,
    capabilities: [...probe.capabilities].sort(),
    admissionReasonCodes: admitted ? [] : ["NOT_ADMITTED"],
    lifecycleReasonCodes: lifecycleFailure === null ? [] : [lifecycleFailure],
    lifecycleEvidence,
    nextActions: actionsForLifecycle(implementationStatus, {
      lifecycleEvidencePresent: lifecycleEvidence !== null || lifecycleFailure !== null,
      failureCode: lifecycleFailure
    })
  };
  return validatedProjection("kernel-agent-status@2", status);
}

function statIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs
  };
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function resolvePublishedVersion(outDir) {
  let root;
  try {
    root = realpathSync(outDir);
  } catch (error) {
    if (error?.code === "ENOENT") return { state: "ABSENT" };
    fail("EVIDENCE_MISSING", "evaluation output directory is unreadable");
  }
  let rootStat;
  try {
    rootStat = lstatSync(root);
  } catch {
    fail("EVIDENCE_MISSING", "evaluation output directory is unreadable");
  }
  if (!rootStat.isDirectory()) fail("EVIDENCE_MUTATED", "evaluation output path is not a directory");

  const currentPath = join(root, "current");
  let currentStat;
  try {
    currentStat = lstatSync(currentPath);
  } catch (error) {
    if (error?.code === "ENOENT") return { state: "ABSENT" };
    fail("EVIDENCE_MISSING", "published current pointer is unreadable");
  }
  if (!currentStat.isSymbolicLink()) fail("EVIDENCE_MUTATED", "published current pointer is not an atomic symlink");

  let target;
  try {
    target = readlinkSync(currentPath);
  } catch {
    fail("EVIDENCE_MUTATED", "published current pointer cannot be resolved");
  }
  if (isAbsolute(target) || !VERSION_TARGET_RE.test(target)) {
    fail("EVIDENCE_MUTATED", "published current pointer has an invalid or escaping target");
  }
  const versionDir = join(root, target);
  let resolvedVersion;
  let versionStat;
  try {
    resolvedVersion = realpathSync(versionDir);
    versionStat = lstatSync(versionDir);
  } catch {
    fail("EVIDENCE_MISSING", "published version directory is missing");
  }
  if (
    resolvedVersion !== versionDir || dirname(resolvedVersion) !== root ||
    !versionStat.isDirectory() || versionStat.isSymbolicLink()
  ) {
    fail("EVIDENCE_MUTATED", "published version directory is not a concrete contained directory");
  }
  return {
    state: "PRESENT",
    root,
    currentPath,
    currentTarget: target,
    currentIdentity: statIdentity(currentStat),
    versionDir,
    versionIdentity: statIdentity(versionStat)
  };
}

function assertPublicationStable(resolved) {
  let currentStat;
  let versionStat;
  let target;
  try {
    currentStat = lstatSync(resolved.currentPath);
    versionStat = lstatSync(resolved.versionDir);
    target = readlinkSync(resolved.currentPath);
  } catch {
    fail("EVIDENCE_MUTATED", "published bundle changed during verification");
  }
  if (
    !currentStat.isSymbolicLink() || !versionStat.isDirectory() || versionStat.isSymbolicLink() ||
    target !== resolved.currentTarget ||
    !sameIdentity(statIdentity(currentStat), resolved.currentIdentity) ||
    !sameIdentity(statIdentity(versionStat), resolved.versionIdentity)
  ) {
    fail("EVIDENCE_MUTATED", "published bundle identity changed during verification");
  }
}

function containedConcreteDirectory(versionDir, path, label) {
  let resolved;
  try {
    resolved = realpathSync(path);
  } catch {
    fail("EVIDENCE_MISSING", `${label} is missing`);
  }
  const rel = relative(versionDir, resolved);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel) || resolved !== path) {
    fail("EVIDENCE_MUTATED", `${label} escapes or uses a symlink`);
  }
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    fail("EVIDENCE_MISSING", `${label} is unreadable`);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail("EVIDENCE_MUTATED", `${label} is not a concrete directory`);
  return resolved;
}

export function loadVerifiedPublishedBundle(outDir) {
  const resolved = resolvePublishedVersion(outDir);
  if (resolved.state === "ABSENT") return resolved;

  let receiptBytes;
  let planBytes;
  let contractBytes;
  try {
    receiptBytes = readBoundedRegularFile(join(resolved.versionDir, "receipt.json"), MAX_RECEIPT_BYTES);
    planBytes = readBoundedRegularFile(join(resolved.versionDir, "plan.json"), MAX_PLAN_BYTES);
    contractBytes = readBoundedRegularFile(join(resolved.versionDir, "work-contract.json"), MAX_CONTRACT_BYTES);
  } catch {
    fail("EVIDENCE_MISSING", "published receipt, plan, or work contract is missing or not a bounded regular file");
  }

  const contractDoc = validateDocument("work-contract@1", contractBytes);
  if (!contractDoc.ok) fail(contractDoc.errors[0].reasonCode, contractDoc.errors[0].message);
  const receiptDoc = validateDocument("promotion-receipt@1", receiptBytes);
  if (!receiptDoc.ok) fail(receiptDoc.errors[0].reasonCode, receiptDoc.errors[0].message);
  const receipt = receiptDoc.value;
  if (
    digestOfCanonical(contractDoc.value) !== receipt.digests.workContract ||
    receipt.artifactRoot !== contractDoc.value.artifactRoot
  ) {
    fail("RECEIPT_REPLAY", "published work contract or artifact root does not match the receipt");
  }

  const evidenceDir = containedConcreteDirectory(
    resolved.versionDir,
    join(resolved.versionDir, receipt.artifactRoot.replace(/\/+$/, ""), "evidence"),
    "published evidence directory"
  );
  const verification = verifyReceipt({
    receiptBytes,
    planBytes,
    evidenceDir,
    evidenceMaxTotalBytes: contractDoc.value.resourceCeilings.maxArtifactBytes
  });
  if (!verification.ok) {
    const first = verification.errors[0] ?? { reasonCode: "EVIDENCE_MUTATED", message: "published bundle did not verify" };
    fail(first.reasonCode, first.message);
  }
  if (verification.evidenceIndex === null) fail("EVIDENCE_MISSING", "published bundle has no verified evidence index");
  assertPublicationStable(resolved);
  return {
    ...resolved,
    contract: contractDoc.value,
    contractBytes,
    receipt: verification.receipt,
    receiptBytes,
    plan: verification.plan,
    planBytes,
    evidenceIndex: verification.evidenceIndex,
    evidenceDir
  };
}

const countValues = (values, keys) => {
  const out = Object.fromEntries(keys.map((key) => [key, 0]));
  for (const value of values) out[value] += 1;
  return out;
};

export function projectPublishedEvaluation(outDir) {
  const bundle = loadVerifiedPublishedBundle(outDir);
  if (bundle.state === "ABSENT") {
    return validatedProjection("kernel-evaluation-summary@1", {
      schemaVersion: "kernel-evaluation-summary@1",
      evaluationState: "ABSENT",
      verification: "NOT_APPLICABLE",
      nextActions: actionsForEvaluation({ evaluationState: "ABSENT" })
    });
  }

  const receipt = bundle.receipt;
  const nonPassingChecks = receipt.checkResults
    .filter((result) => result.outcome !== "PASS")
    .map((result) => ({
      checkId: result.checkId,
      packId: result.packId,
      effect: result.effect,
      outcome: result.outcome,
      reasonCodes: [...result.reasonCodes].sort(),
      evidenceArtifactIds: result.evidence.map((entry) => entry.artifactId).sort()
    }))
    .sort((left, right) => (left.checkId < right.checkId ? -1 : left.checkId > right.checkId ? 1 : 0));
  const reasonCodes = [...receipt.reasonCodes].sort();
  const summary = {
    schemaVersion: "kernel-evaluation-summary@1",
    evaluationState: "PRESENT",
    verification: "VERIFIED",
    kernelRelease: receipt.kernelRelease,
    repositoryId: receipt.repositoryId,
    baseCommit: receipt.baseCommit,
    candidate: { ...receipt.candidate },
    disposition: receipt.disposition,
    reasonCodes,
    digests: {
      receipt: digestOfCanonical(receipt),
      plan: digestOfCanonical(bundle.plan),
      evidenceIndex: digestOfCanonical(bundle.evidenceIndex)
    },
    checkCounts: {
      total: receipt.checkResults.length,
      byEffect: countValues(receipt.checkResults.map((result) => result.effect), ["BLOCKING", "ADVISORY"]),
      byOutcome: countValues(receipt.checkResults.map((result) => result.outcome), ["PASS", "FIRED", "INFRA_FAILURE", "SKIPPED"])
    },
    nonPassingChecks,
    changedFiles: {
      total: receipt.changedFiles.length,
      byScopeClass: countValues(receipt.changedFiles.map((file) => file.scopeClass), ["ALLOWED", "READONLY", "FORBIDDEN", "UNCLASSIFIED"]),
      byChangeKind: countValues(receipt.changedFiles.map((file) => file.changeKind), ["ADDED", "MODIFIED", "DELETED", "RENAMED"])
    },
    signing: {
      present: receipt.signing !== null,
      publicKey: receipt.signing?.publicKey ?? null
    },
    nextActions: actionsForEvaluation({
      evaluationState: "PRESENT",
      disposition: receipt.disposition,
      reasonCodes,
      checkResults: nonPassingChecks
    })
  };
  return validatedProjection("kernel-evaluation-summary@1", summary);
}

function decodePreview(bytes) {
  for (let trim = 0; trim <= Math.min(3, bytes.length); trim += 1) {
    const candidate = bytes.subarray(0, bytes.length - trim);
    try {
      return { text: new TextDecoder("utf-8", { fatal: true }).decode(candidate), returnedBytes: candidate.length };
    } catch {
      // A valid UTF-8 document can end a bounded preview in the middle of a
      // code point. Removing at most three trailing bytes finds its last full
      // code point; an earlier decoding failure is handled as metadata-only.
    }
  }
  return null;
}

export function inspectPublishedEvidence(outDir, artifactId, maxBytes = null) {
  const bundle = loadVerifiedPublishedBundle(outDir);
  if (bundle.state === "ABSENT") fail("EVIDENCE_MISSING", "no published evaluation exists");
  const matches = bundle.evidenceIndex.artifacts.filter((entry) => entry.artifactId === artifactId);
  if (matches.length !== 1) {
    fail(matches.length === 0 ? "EVIDENCE_MISSING" : "EVIDENCE_MUTATED", `artifact ${artifactId} does not resolve exactly once`);
  }
  const artifact = matches[0];
  let preview = null;
  if (maxBytes !== null && artifact.mediaType !== "application/octet-stream") {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_EVIDENCE_PREVIEW_BYTES) {
      throw new TypeError(`maxBytes must be an integer from 1 through ${MAX_EVIDENCE_PREVIEW_BYTES}`);
    }
    const inspected = hashBoundedRegularFile(
      join(bundle.evidenceDir, "objects", "sha256", artifact.digest.slice("sha256:".length)),
      artifact.byteLength,
      { previewBytes: Math.min(maxBytes, artifact.byteLength), validateUtf8: true }
    );
    if (inspected.digest !== artifact.digest || inspected.byteLength !== artifact.byteLength) {
      fail("EVIDENCE_MUTATED", `artifact ${artifactId} changed during inspection`);
    }
    if (inspected.utf8Valid) {
      const decoded = decodePreview(inspected.preview);
      if (decoded !== null) {
        preview = {
          encoding: "utf-8",
          requestedBytes: maxBytes,
          returnedBytes: decoded.returnedBytes,
          totalBytes: artifact.byteLength,
          truncated: decoded.returnedBytes < artifact.byteLength,
          text: decoded.text
        };
      }
    }
  }
  assertPublicationStable(bundle);
  return validatedProjection("kernel-evidence-view@1", {
    schemaVersion: "kernel-evidence-view@1",
    verification: "VERIFIED",
    artifact: { ...artifact },
    preview
  });
}

export function canonicalProjection(value) {
  return `${canonicalize(value)}\n`;
}
