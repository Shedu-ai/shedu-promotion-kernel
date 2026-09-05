import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalize, digestOfBytes, digestOfCanonical } from "./canonical-json.mjs";
import { validateDocument } from "./contracts.mjs";
import { verifyPilotQualificationReceipt } from "./pilot-qualification.mjs";

export const LIFECYCLE_STATUSES = Object.freeze(["FOUNDATION_ONLY", "EXPERIMENTAL", "PILOT_ELIGIBLE", "CERTIFIED"]);

// The lifecycle verifier never constructs an admitted status on failure. The
// branded admission reducer alone decides which valid lower state survives.
const failure = (reasonCode, message) => ({ ok: false, reasonCode, message, evidence: null });

function canonicalBytesMatch(bytes, value) {
  const normalized = Buffer.from(bytes).toString("utf8").replace(/\n$/, "");
  return normalized === canonicalize(value);
}

function verifySignature(attestation, pinnedKey, authorityId) {
  const authority = attestation.authority;
  if (authority.authorityId !== authorityId || authority.algorithm !== "ed25519" || authority.publicKey !== pinnedKey || typeof authority.signature !== "string") return false;
  try {
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(pinnedKey, "hex").toString("base64url") },
      format: "jwk"
    });
    const unsigned = canonicalize({ ...attestation, authority: { ...authority, signature: null } });
    return cryptoVerify(null, Buffer.from(unsigned, "utf8"), key, Buffer.from(authority.signature, "hex"));
  } catch {
    return false;
  }
}

export function verifyLifecycleEvidence({
  attestationBytes,
  evidenceBytes,
  policyBytes,
  activationSpecificationBytes,
  conformanceAttestationBytes,
  conformanceCertificationBytes,
  predecessorLifecycleAttestationBytes = null,
  pinnedKey,
  authorityId,
  kernelRelease,
  kernelCommit,
  kernelTree,
  mechanismInventoryDigest,
  controlSurfaceDigest,
  now = new Date()
}) {
  if (!attestationBytes || !evidenceBytes || !policyBytes || !activationSpecificationBytes ||
      !conformanceAttestationBytes || !conformanceCertificationBytes || !pinnedKey || !authorityId) {
    return failure("LIFECYCLE_EVIDENCE_INVALID", "the complete externally supplied lifecycle evidence set is absent");
  }
  const attDoc = validateDocument("kernel-lifecycle-attestation@1", attestationBytes);
  if (!attDoc.ok) return failure("LIFECYCLE_ATTESTATION_INVALID", "lifecycle attestation is not schema-valid");
  const att = attDoc.value;
  if (!canonicalBytesMatch(attestationBytes, att)) return failure("LIFECYCLE_ATTESTATION_INVALID", "lifecycle attestation bytes are not canonical");
  if (!verifySignature(att, pinnedKey, authorityId)) return failure("LIFECYCLE_ATTESTATION_INVALID", "lifecycle signature does not verify against the external authority");

  const expectedSubject = {
    subjectId: "shedu-promotion-kernel",
    repository: "https://github.com/Shedu-ai/shedu-promotion-kernel.git",
    kernelRelease,
    kernelCommit,
    kernelTree
  };
  if (canonicalize(att.subject) !== canonicalize(expectedSubject)) return failure("LIFECYCLE_ATTESTATION_INVALID", "lifecycle subject identity does not match this frozen kernel");
  if (att.activationProfile.configurationDigest !== digestOfBytes(activationSpecificationBytes)) {
    return failure("LIFECYCLE_ATTESTATION_INVALID", "lifecycle attestation does not bind the activation specification");
  }
  const conformanceAttestationDigest = digestOfBytes(conformanceAttestationBytes);
  if (att.conformance.attestationDigest !== conformanceAttestationDigest ||
      att.conformance.certificationDigest !== digestOfBytes(conformanceCertificationBytes) ||
      att.conformance.mechanismInventoryDigest !== mechanismInventoryDigest ||
      att.conformance.controlSurfaceDigest !== controlSurfaceDigest) {
    return failure("LIFECYCLE_ATTESTATION_INVALID", "lifecycle attestation does not bind the active conformance evidence and control identity");
  }

  const issued = Date.parse(att.validity.issuedAt);
  const from = Date.parse(att.validity.validFrom);
  const expires = Date.parse(att.validity.expiresAt);
  const clock = now instanceof Date ? now.getTime() : Number(now);
  const skew = att.validity.maxClockSkewSeconds * 1000;
  if (!Number.isFinite(clock) || clock < from - skew || clock > expires + skew) {
    return failure("LIFECYCLE_EXPIRED", "lifecycle evidence is not valid at the evaluation time");
  }
  if (issued > from || from >= expires) return failure("LIFECYCLE_ATTESTATION_INVALID", "lifecycle validity interval is inverted");

  if (att.predecessor.status === "EXPERIMENTAL") {
    if (att.sequence !== 1 || att.supersedes !== null || att.predecessor.attestationDigest !== conformanceAttestationDigest) {
      return failure("LIFECYCLE_PREDECESSOR_MISMATCH", "first lifecycle advancement does not bind the exact experimental predecessor");
    }
  } else {
    if (!predecessorLifecycleAttestationBytes || att.predecessor.attestationDigest !== digestOfBytes(predecessorLifecycleAttestationBytes) || att.supersedes !== att.predecessor.attestationDigest) {
      return failure("LIFECYCLE_PREDECESSOR_MISMATCH", "lifecycle predecessor bytes do not match the signed transition");
    }
    const predecessorDoc = validateDocument("kernel-lifecycle-attestation@1", predecessorLifecycleAttestationBytes);
    if (!predecessorDoc.ok || predecessorDoc.value.requestedStatus !== att.predecessor.status || predecessorDoc.value.sequence + 1 !== att.sequence || canonicalize(predecessorDoc.value.subject) !== canonicalize(att.subject)) {
      return failure("LIFECYCLE_SEQUENCE_INVALID", "lifecycle sequence is replayed, skipped, or crosses subject identity");
    }
  }

  if (att.requestedStatus === "PILOT_ELIGIBLE") {
    const verified = verifyPilotQualificationReceipt({ receiptBytes: evidenceBytes, policyBytes });
    if (!verified.ok) return failure("LIFECYCLE_EVIDENCE_INVALID", "pilot qualification receipt is incomplete or invalid");
    if (att.evidence.kind !== "PILOT_QUALIFICATION_COMPLETE" || att.evidence.publicDigest !== digestOfBytes(evidenceBytes) ||
        att.evidence.policyId !== verified.policy.policyId || att.evidence.policyVersion !== verified.policy.policyVersion ||
        att.evidence.policyDigest !== digestOfCanonical(verified.policy) ||
        att.evidence.privateManifestRootDigest !== verified.receipt.privateEvidenceManifestRootDigest ||
        canonicalize(verified.receipt.subject) !== canonicalize(att.subject) ||
        verified.receipt.conformance.attestationDigest !== att.conformance.attestationDigest ||
        verified.receipt.conformance.certificationDigest !== att.conformance.certificationDigest) {
      return failure("LIFECYCLE_EVIDENCE_INVALID", "pilot qualification evidence does not match the lifecycle statement");
    }
    if (expires - from > verified.policy.validityDays * 86_400_000) {
      return failure("LIFECYCLE_ATTESTATION_INVALID", "lifecycle validity exceeds the frozen pilot policy");
    }
  } else {
    // The operational certification compiler is intentionally a separate
    // post-pilot control. Until its closed receipt is implemented, CERTIFIED
    // cannot be derived from arbitrary bytes.
    return failure("LIFECYCLE_EVIDENCE_INVALID", "operational certification evidence is not implemented");
  }

  return {
    ok: true,
    status: att.requestedStatus,
    reasonCode: null,
    message: null,
    evidence: Object.freeze({
      attestationDigest: digestOfBytes(attestationBytes),
      evidenceDigest: digestOfBytes(evidenceBytes),
      policyDigest: att.evidence.policyDigest,
      validFrom: att.validity.validFrom,
      expiresAt: att.validity.expiresAt,
      sequence: att.sequence,
      executionClaims: att.executionClaims
    })
  };
}
