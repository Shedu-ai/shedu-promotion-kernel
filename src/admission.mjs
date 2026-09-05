import { readFileSync } from "node:fs";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { validateDocument } from "./contracts.mjs";
import { KERNEL_RELEASE } from "./compiler.mjs";
import { git } from "./git-authority.mjs";
import { readBoundedRegularFile } from "./bounded-file.mjs";
import { verifyLifecycleEvidence } from "./lifecycle.mjs";

// Control point: conformance/status admission — the FOUNDATION_ONLY →
// EXPERIMENTAL gate, and the gate on the promotion (evaluate) entrypoint.
export const CONTROL_POINTS = Object.freeze(["conformance-status-admission", "lifecycle-status-admission"]);

// The trust root is NOT pinned in mutable subject source. An external
// verifier (Harness Bench / release) supplies the expected public key, the
// detached attestation, and the expected frozen commit at invocation time
// (via env or CLI). Absent externally-supplied evidence, admission is
// honestly FOUNDATION_ONLY. This constant stays empty precisely so that no
// self-produced artifact in the repository can elevate the subject.
export const TRUSTED_ATTESTATION_KEYS = Object.freeze([]);

// Verify the working tree is a CLEAN checkout of exactly the expected commit.
// A dirty tree, or a HEAD other than expected, fails — so an attestation for
// a clean frozen commit cannot admit a modified source tree. (The ultimate
// authority remains Bench re-materializing the frozen commit externally; this
// is the strongest check the subject can perform on itself.)
export function verifyFrozenSource(repoDir, expectedCommit) {
  const run = (args) => git(args, { cwd: repoDir });
  const head = run(["rev-parse", "HEAD"]);
  if (head.status !== 0) return { ok: false, clean: false, commit: null, reason: "not a git repository" };
  const commit = head.stdout.trim();
  const status = run(["status", "--porcelain", "--untracked-files=all"]);
  if (status.status !== 0) return { ok: false, clean: false, commit, reason: "cannot read working-tree status" };
  const clean = status.stdout.trim() === "";
  if (!clean) return { ok: false, clean: false, commit, reason: "working tree is dirty; an attestation for a clean commit cannot admit modified source" };
  if (expectedCommit !== null && commit !== expectedCommit) {
    return { ok: false, clean: true, commit, reason: `HEAD ${commit} does not match the expected frozen commit ${expectedCommit}` };
  }
  return { ok: true, clean: true, commit };
}

// Recompute every status invariant from the status document's contents.
// `allPassed` in the document is NEVER trusted; it must equal what we derive,
// and what we derive must itself be true.
export function deriveConformancePassed(status) {
  const reasons = [];
  const casesOk = status.cases.every(
    (c) =>
      c.conforming.disposition === "PROMOTABLE" &&
      c.conforming.receiptVerified === true &&
      c.planted.disposition === "BLOCKED" &&
      c.planted.receiptVerified === true
  );
  if (!casesOk) reasons.push("a conformance case did not pass on recomputation");
  const activationOk = status.kernelActivation.length > 0 && status.kernelActivation.every((a) => a.proven === true);
  if (!activationOk) reasons.push("a kernel mechanism activation was not proven on recomputation");
  const census = status.controlCensus;
  const censusOk =
    census?.complete === true &&
    census.registered > 0 &&
    census.proven === census.registered &&
    census.productionRequired > 0 &&
    census.productionObserved === census.productionRequired &&
    typeof census.productionEvidenceDigest === "string" &&
    (census.findings?.length ?? 1) === 0;
  if (!censusOk) reasons.push("the control-surface census was not complete on recomputation");
  const derived = casesOk && activationOk && censusOk;
  if (status.allPassed !== derived) {
    reasons.push(`status.allPassed (${status.allPassed}) contradicts the derived result (${derived})`);
    return { passed: false, reasons };
  }
  return { passed: derived, reasons };
}

function verifyAttestationSignature(attestation, trustedKeys) {
  if (!trustedKeys.includes(attestation.signing.publicKey)) return false;
  const unsigned = Buffer.from(canonicalize({ ...attestation, signing: null }), "utf8");
  try {
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(attestation.signing.publicKey, "hex").toString("base64url") },
      format: "jwk"
    });
    return cryptoVerify(null, unsigned, key, Buffer.from(attestation.signing.signature, "hex"));
  } catch {
    return false;
  }
}

// Compute the admitted subject status from independently supplied evidence
// and a pinned trust root. Never elevates from a mutable bit: elevation
// requires (1) status invariants recomputed true AND (2) a detached
// attestation signed by a pinned key that binds this exact kernel commit,
// release, status digest, mechanism inventory, and control surface.
// Module-private brand so an admitted outcome cannot be forged elsewhere: a
// hand-built { admitted: true } object lacks the brand and is not honored.
const ADMISSION_BRAND = Symbol("shedu-admission");

function foundationOutcome(reasons) {
  const outcome = { status: "FOUNDATION_ONLY", admitted: false, reasons, lifecycleEvidence: null, lifecycleFailureCode: null };
  Object.defineProperty(outcome, ADMISSION_BRAND, { value: true, enumerable: false });
  return outcome;
}

function admittedOutcome(status = "EXPERIMENTAL", { lifecycleEvidence = null, lifecycleFailureCode = null, kernelCommit = null, kernelTree = null } = {}) {
  const outcome = { status, admitted: true, reasons: [], lifecycleEvidence, lifecycleFailureCode, kernelCommit, kernelTree };
  Object.defineProperty(outcome, ADMISSION_BRAND, { value: true, enumerable: false });
  return outcome;
}

// The ONLY sanctioned reader of an admission outcome: it honors elevation
// only for an outcome this module produced (branded) that is genuinely
// admitted. A forged object — e.g. an attacker's `{ admitted: true }` — is
// not branded and is treated as un-admitted.
export function isAdmitted(outcome) {
  return outcome?.[ADMISSION_BRAND] === true && outcome.admitted === true &&
    ["EXPERIMENTAL", "PILOT_ELIGIBLE", "CERTIFIED"].includes(outcome.status);
}

export function isPilotEligible(outcome) {
  return outcome?.[ADMISSION_BRAND] === true && ["PILOT_ELIGIBLE", "CERTIFIED"].includes(outcome.status);
}

export function isCertified(outcome) {
  return outcome?.[ADMISSION_BRAND] === true && outcome.status === "CERTIFIED";
}

export function admittedLifecycleStatus(outcome) {
  return outcome?.[ADMISSION_BRAND] === true ? outcome.status : "FOUNDATION_ONLY";
}

export function admittedLifecycleEvidence(outcome) {
  return outcome?.[ADMISSION_BRAND] === true ? outcome.lifecycleEvidence : null;
}

export function lifecycleFailureCode(outcome) {
  return outcome?.[ADMISSION_BRAND] === true ? outcome.lifecycleFailureCode : null;
}

export function admittedKernelIdentity(outcome) {
  return outcome?.[ADMISSION_BRAND] === true
    ? Object.freeze({ kernelCommit: outcome.kernelCommit ?? null, kernelTree: outcome.kernelTree ?? null })
    : Object.freeze({ kernelCommit: null, kernelTree: null });
}

export function computeAdmission({
  statusBytes = null,
  attestationBytes = null,
  trustedKeys = TRUSTED_ATTESTATION_KEYS,
  kernelCommit = null,
  expectedCommit = null,
  sourceClean = true,
  mechanismInventoryDigest = null,
  controlSurfaceDigest = null,
  kernelRelease = KERNEL_RELEASE,
  kernelTree = null,
  lifecycleAttestationBytes = null,
  lifecycleEvidenceBytes = null,
  lifecyclePolicyBytes = null,
  activationSpecificationBytes = null,
  conformanceCertificationBytes = null,
  predecessorLifecycleAttestationBytes = null,
  lifecycleAuthorityId = null,
  now = new Date()
} = {}) {
  if (statusBytes === null) return foundationOutcome(["no conformance status is present"]);
  const statusDoc = validateDocument("conformance-status@2", statusBytes);
  if (!statusDoc.ok) return foundationOutcome(["conformance status is not schema-valid"]);
  if (statusDoc.value.kernelRelease !== kernelRelease) {
    return foundationOutcome([`conformance status is for ${statusDoc.value.kernelRelease}, not ${kernelRelease}`]);
  }
  const derived = deriveConformancePassed(statusDoc.value);
  if (!derived.passed) return foundationOutcome(derived.reasons);

  if (attestationBytes === null) {
    return foundationOutcome(["no detached conformance attestation is present; an externally-pinned signature is required to elevate"]);
  }
  if (trustedKeys.length === 0) {
    return foundationOutcome(["no externally-supplied attestation trust key; cannot elevate above FOUNDATION_ONLY"]);
  }
  const attDoc = validateDocument("conformance-attestation@1", attestationBytes);
  if (!attDoc.ok) return foundationOutcome(["conformance attestation is not schema-valid"]);
  const att = attDoc.value;

  const reasons = [];
  if (!sourceClean) reasons.push("working tree is not a clean checkout of the attested commit");
  if (att.kernelRelease !== kernelRelease) reasons.push("attestation release mismatch");
  if (kernelCommit === null || att.kernelCommit !== kernelCommit) reasons.push("attestation is not bound to the current kernel commit");
  if (expectedCommit !== null && att.kernelCommit !== expectedCommit) reasons.push("attestation commit does not match the externally expected frozen commit");
  if (att.conformanceStatusDigest !== digestOfBytes(statusBytes)) reasons.push("attestation does not bind this conformance status");
  if (mechanismInventoryDigest !== null && att.mechanismInventoryDigest !== mechanismInventoryDigest) {
    reasons.push("attestation does not bind the current mechanism inventory");
  }
  if (controlSurfaceDigest !== null && att.controlSurfaceDigest !== controlSurfaceDigest) {
    reasons.push("attestation does not bind the current control surface");
  }
  if (!verifyAttestationSignature(att, trustedKeys)) reasons.push("attestation signature does not verify against the externally-pinned key");

  if (reasons.length > 0) return foundationOutcome(reasons);

  const lifecyclePresent = lifecycleAttestationBytes !== null || lifecycleEvidenceBytes !== null ||
    lifecyclePolicyBytes !== null || activationSpecificationBytes !== null || conformanceCertificationBytes !== null;
  if (!lifecyclePresent) return admittedOutcome("EXPERIMENTAL", { kernelCommit, kernelTree });
  const lifecycle = verifyLifecycleEvidence({
    attestationBytes: lifecycleAttestationBytes,
    evidenceBytes: lifecycleEvidenceBytes,
    policyBytes: lifecyclePolicyBytes,
    activationSpecificationBytes,
    conformanceAttestationBytes: attestationBytes,
    conformanceCertificationBytes,
    predecessorLifecycleAttestationBytes,
    pinnedKey: trustedKeys.length === 1 ? trustedKeys[0] : null,
    authorityId: lifecycleAuthorityId,
    kernelRelease,
    kernelCommit,
    kernelTree,
    mechanismInventoryDigest,
    controlSurfaceDigest,
    now
  });
  if (!lifecycle.ok) return admittedOutcome("EXPERIMENTAL", { lifecycleFailureCode: lifecycle.reasonCode, kernelCommit, kernelTree });
  return admittedOutcome(lifecycle.status, { lifecycleEvidence: lifecycle.evidence, kernelCommit, kernelTree });
}

function readIfPresent(url) {
  try {
    return readFileSync(url);
  } catch {
    return null;
  }
}

function currentKernelCommit(repoDir) {
  const r = git(["rev-parse", "HEAD"], { cwd: repoDir });
  return r.status === 0 && /^[0-9a-f]{40}$/.test(r.stdout.trim()) ? r.stdout.trim() : null;
}

function currentKernelTree(repoDir) {
  const r = git(["rev-parse", "HEAD^{tree}"], { cwd: repoDir });
  return r.status === 0 && /^[0-9a-f]{40}$/.test(r.stdout.trim()) ? r.stdout.trim() : null;
}

// Assemble admission from the committed conformance status + EXTERNALLY-
// supplied admission evidence (attestation, pinned key, expected commit) via
// environment or explicit overrides. This is the AUTHORITATIVE admission gate:
// both the CLI and the supervised promotion worker call it, so bypassing the
// CLI's early check does not bypass admission. With no external evidence, the
// result is FOUNDATION_ONLY.
export function committedAdmission(overrides = {}) {
  const repoDir = new URL("..", import.meta.url).pathname;
  const statusBytes = readIfPresent(new URL("../conformance/status.json", import.meta.url));
  const inventoryBytes = readIfPresent(new URL("../registry/kernel-mechanisms.json", import.meta.url));
  const controlBytes = readIfPresent(new URL("../registry/control-surface.json", import.meta.url));

  const attestationPath = overrides.attestationPath ?? process.env.SHEDU_ATTESTATION_FILE ?? null;
  const pinnedKey = overrides.pinnedKey ?? process.env.SHEDU_PINNED_KEY ?? null;
  const expectedCommit = overrides.expectedCommit ?? process.env.SHEDU_EXPECTED_COMMIT ?? null;
  const lifecycleAuthorityId = overrides.lifecycleAuthorityId ?? process.env.SHEDU_LIFECYCLE_AUTHORITY_ID ?? null;

  // Bounded read: the attestation must be a regular file of bounded size — a
  // FIFO or a blocking/oversized special file is refused rather than read
  // (which would otherwise hang).
  let attestationBytes = null;
  if (attestationPath) {
    try {
      attestationBytes = readBoundedRegularFile(attestationPath, 64 * 1024);
    } catch {
      attestationBytes = null;
    }
  }

  const boundedOptional = (overrideName, envName) => {
    const path = overrides[overrideName] ?? process.env[envName] ?? null;
    if (!path) return null;
    try {
      return readBoundedRegularFile(path, 1024 * 1024);
    } catch {
      return null;
    }
  };
  const lifecycleAttestationBytes = boundedOptional("lifecycleAttestationPath", "SHEDU_LIFECYCLE_ATTESTATION_FILE");
  const lifecycleEvidenceBytes = boundedOptional("lifecycleEvidencePath", "SHEDU_LIFECYCLE_EVIDENCE_FILE");
  const lifecyclePolicyBytes = boundedOptional("lifecyclePolicyPath", "SHEDU_LIFECYCLE_POLICY_FILE");
  const activationSpecificationBytes = boundedOptional("activationSpecificationPath", "SHEDU_ACTIVATION_SPECIFICATION_FILE");
  const conformanceCertificationBytes = boundedOptional("conformanceCertificationPath", "SHEDU_CONFORMANCE_CERTIFICATION_FILE");
  const predecessorLifecycleAttestationBytes = boundedOptional("predecessorLifecycleAttestationPath", "SHEDU_PREDECESSOR_LIFECYCLE_ATTESTATION_FILE");

  const source = verifyFrozenSource(repoDir, expectedCommit);

  return computeAdmission({
    statusBytes,
    attestationBytes,
    trustedKeys: pinnedKey ? [pinnedKey] : [],
    kernelCommit: source.commit ?? currentKernelCommit(repoDir),
    kernelTree: currentKernelTree(repoDir),
    expectedCommit,
    sourceClean: source.clean,
    mechanismInventoryDigest: inventoryBytes ? digestOfBytes(inventoryBytes) : null,
    controlSurfaceDigest: controlBytes ? digestOfBytes(controlBytes) : null,
    lifecycleAttestationBytes,
    lifecycleEvidenceBytes,
    lifecyclePolicyBytes,
    activationSpecificationBytes,
    conformanceCertificationBytes,
    predecessorLifecycleAttestationBytes,
    lifecycleAuthorityId
  });
}

// For producing an attestation in tests / by an external signer.
export function attestationBody({ kernelCommit, statusDigest, mechanismInventoryDigest, controlSurfaceDigest, kernelRelease = KERNEL_RELEASE }) {
  return {
    schemaVersion: "conformance-attestation@1",
    kernelRelease,
    kernelCommit,
    conformanceStatusDigest: statusDigest,
    mechanismInventoryDigest,
    controlSurfaceDigest,
    signing: null
  };
}
