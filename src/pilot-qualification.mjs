import { canonicalize, digestOfCanonical } from "./canonical-json.mjs";
import { validateDocument, validateValue } from "./contracts.mjs";

const same = (left, right) => canonicalize(left) === canonicalize(right);

const incomplete = (policy, input, reasonCodes) => {
  const base = {
    schemaVersion: "kernel-pilot-qualification-receipt@1",
    subject: input?.subject ?? policy.subject,
    policyId: policy.policyId,
    policyVersion: policy.policyVersion,
    policyDigest: input?.policyDigest ?? digestOfCanonical(policy),
    activationSpecificationDigest: input?.activationSpecificationDigest ?? policy.activationSpecificationDigest,
    conformance: input?.conformance ?? {
      attestationDigest: "sha256:" + "0".repeat(64),
      certificationDigest: "sha256:" + "0".repeat(64),
      mechanismInventoryDigest: "sha256:" + "0".repeat(64),
      controlSurfaceDigest: "sha256:" + "0".repeat(64),
      statusDigest: "sha256:" + "0".repeat(64)
    },
    status: "PILOT_QUALIFICATION_INCOMPLETE",
    reasonCodes: [...new Set(reasonCodes)].sort(),
    resultCount: input?.results?.length ?? 0,
    resultsDigest: digestOfCanonical(input?.results ?? []),
    privateEvidenceManifestRootDigest: digestOfCanonical(input?.privateEvidenceManifest ?? [])
  };
  return { ...base, publicEvidenceDigest: digestOfCanonical(base) };
};

// Zero-provider deterministic compiler. It does not execute checks or decide
// whether a narrative is persuasive; it closes the frozen policy against an
// exact, digest-complete result manifest and emits a canonical receipt.
export function compilePilotQualification({ policyBytes, inputBytes }) {
  const policyDoc = validateDocument("kernel-pilot-qualification-policy@1", policyBytes);
  if (!policyDoc.ok) return { ok: false, errors: policyDoc.errors, receipt: null, receiptBytes: null };
  const inputDoc = validateDocument("kernel-pilot-qualification-input@1", inputBytes);
  if (!inputDoc.ok) {
    const receipt = incomplete(policyDoc.value, null, ["QUALIFICATION_INPUT_INVALID"]);
    return { ok: false, errors: inputDoc.errors, receipt, receiptBytes: canonicalize(receipt) };
  }
  const policy = policyDoc.value;
  const input = inputDoc.value;
  const reasons = [];
  const policyDigest = digestOfCanonical(policy);
  if (input.policyDigest !== policyDigest) reasons.push("QUALIFICATION_POLICY_INVALID");
  if (!same(input.subject, policy.subject) || input.activationSpecificationDigest !== policy.activationSpecificationDigest) {
    reasons.push("QUALIFICATION_IDENTITY_MISMATCH");
  }

  const required = new Map(policy.requiredChecks.map((check) => [check.checkId, check]));
  const observed = new Map();
  for (const result of input.results) {
    if (observed.has(result.checkId)) reasons.push("QUALIFICATION_RESULT_DUPLICATE");
    observed.set(result.checkId, result);
    const expected = required.get(result.checkId);
    if (expected === undefined) {
      reasons.push("QUALIFICATION_RESULT_UNEXPECTED");
      continue;
    }
    if (result.platform !== expected.platform || result.profile !== expected.profile || !same(result.argv, expected.argv)) {
      reasons.push("QUALIFICATION_RESULT_UNEXPECTED");
    }
    if (result.outcome !== expected.expectedOutcome || result.exitCode !== 0) reasons.push("QUALIFICATION_RESULT_FAILED");
  }
  for (const id of required.keys()) if (!observed.has(id)) reasons.push("QUALIFICATION_RESULT_MISSING");
  if (input.privateEvidenceManifest.length < policy.requiredChecks.length) reasons.push("QUALIFICATION_EVIDENCE_INVALID");

  const base = {
    schemaVersion: "kernel-pilot-qualification-receipt@1",
    subject: input.subject,
    policyId: policy.policyId,
    policyVersion: policy.policyVersion,
    policyDigest,
    activationSpecificationDigest: policy.activationSpecificationDigest,
    conformance: input.conformance,
    status: reasons.length === 0 ? "PILOT_QUALIFICATION_COMPLETE" : "PILOT_QUALIFICATION_INCOMPLETE",
    reasonCodes: [...new Set(reasons)].sort(),
    resultCount: input.results.length,
    resultsDigest: digestOfCanonical(input.results),
    privateEvidenceManifestRootDigest: digestOfCanonical(input.privateEvidenceManifest)
  };
  const receipt = { ...base, publicEvidenceDigest: digestOfCanonical(base) };
  const checked = validateValue("kernel-pilot-qualification-receipt@1", receipt);
  if (!checked.ok) return { ok: false, errors: checked.errors, receipt: null, receiptBytes: null };
  return { ok: reasons.length === 0, errors: [], receipt, receiptBytes: canonicalize(receipt) };
}

export function verifyPilotQualificationReceipt({ receiptBytes, policyBytes }) {
  const receiptDoc = validateDocument("kernel-pilot-qualification-receipt@1", receiptBytes);
  const policyDoc = validateDocument("kernel-pilot-qualification-policy@1", policyBytes);
  if (!receiptDoc.ok || !policyDoc.ok) return { ok: false, reasonCode: "LIFECYCLE_EVIDENCE_INVALID" };
  const receipt = receiptDoc.value;
  const policy = policyDoc.value;
  const { publicEvidenceDigest, ...base } = receipt;
  const ok = receipt.status === "PILOT_QUALIFICATION_COMPLETE" && receipt.reasonCodes.length === 0 &&
    publicEvidenceDigest === digestOfCanonical(base) && receipt.policyDigest === digestOfCanonical(policy) &&
    receipt.policyId === policy.policyId && receipt.policyVersion === policy.policyVersion &&
    receipt.activationSpecificationDigest === policy.activationSpecificationDigest && same(receipt.subject, policy.subject);
  return { ok, reasonCode: ok ? null : "LIFECYCLE_EVIDENCE_INVALID", receipt, policy };
}
