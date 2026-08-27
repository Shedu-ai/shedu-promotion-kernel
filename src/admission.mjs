import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { validateDocument } from "./contracts.mjs";
import { KERNEL_RELEASE } from "./compiler.mjs";

// Control point: conformance/status admission — the FOUNDATION_ONLY →
// EXPERIMENTAL gate, and the gate on the promotion (evaluate) entrypoint.
export const CONTROL_POINTS = Object.freeze(["conformance-status-admission"]);

// The trust root: Ed25519 public keys (hex) authorized to attest that this
// kernel commit passed conformance. It is PINNED here, in source, outside the
// mutable subject evidence it verifies. No key is pinned in the public
// build, so no self-produced status document can elevate the subject: an
// externally-held Harness Bench / release key must sign a detached
// attestation. Absent that, admission is honestly FOUNDATION_ONLY.
export const TRUSTED_ATTESTATION_KEYS = Object.freeze([]);

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
  const derived = casesOk && activationOk;
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
export function computeAdmission({
  statusBytes = null,
  attestationBytes = null,
  trustedKeys = TRUSTED_ATTESTATION_KEYS,
  kernelCommit = null,
  mechanismInventoryDigest = null,
  controlSurfaceDigest = null,
  kernelRelease = KERNEL_RELEASE
} = {}) {
  const foundation = (reasons) => ({ status: "FOUNDATION_ONLY", admitted: false, reasons });

  if (statusBytes === null) return foundation(["no conformance status is present"]);
  const statusDoc = validateDocument("conformance-status@1", statusBytes);
  if (!statusDoc.ok) return foundation(["conformance status is not schema-valid"]);
  if (statusDoc.value.kernelRelease !== kernelRelease) {
    return foundation([`conformance status is for ${statusDoc.value.kernelRelease}, not ${kernelRelease}`]);
  }
  const derived = deriveConformancePassed(statusDoc.value);
  if (!derived.passed) return foundation(derived.reasons);

  if (attestationBytes === null) {
    return foundation(["no detached conformance attestation is present; a pinned external signature is required to elevate"]);
  }
  if (trustedKeys.length === 0) {
    return foundation(["no attestation trust root is pinned in this build; cannot elevate above FOUNDATION_ONLY"]);
  }
  const attDoc = validateDocument("conformance-attestation@1", attestationBytes);
  if (!attDoc.ok) return foundation(["conformance attestation is not schema-valid"]);
  const att = attDoc.value;

  const reasons = [];
  if (att.kernelRelease !== kernelRelease) reasons.push("attestation release mismatch");
  if (kernelCommit === null || att.kernelCommit !== kernelCommit) reasons.push("attestation is not bound to the current kernel commit");
  if (att.conformanceStatusDigest !== digestOfBytes(statusBytes)) reasons.push("attestation does not bind this conformance status");
  if (mechanismInventoryDigest !== null && att.mechanismInventoryDigest !== mechanismInventoryDigest) {
    reasons.push("attestation does not bind the current mechanism inventory");
  }
  if (controlSurfaceDigest !== null && att.controlSurfaceDigest !== controlSurfaceDigest) {
    reasons.push("attestation does not bind the current control surface");
  }
  if (!verifyAttestationSignature(att, trustedKeys)) reasons.push("attestation signature does not verify against a pinned trusted key");

  if (reasons.length > 0) return foundation(reasons);
  return { status: "EXPERIMENTAL", admitted: true, reasons: [] };
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
