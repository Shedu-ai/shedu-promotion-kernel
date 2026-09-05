import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalize, digestOfBytes, digestOfCanonical } from "../src/canonical-json.mjs";
import { compilePilotQualification } from "../src/pilot-qualification.mjs";
import { verifyDistributionBundle, DistributionError } from "../scripts/experimental-kernel.mjs";

const sha = (bytes) => digestOfBytes(bytes);
const put = (root, name, value) => {
  const bytes = Buffer.from(canonicalize(value), "utf8");
  writeFileSync(join(root, name), bytes);
  return { path: name, digest: sha(bytes) };
};

function signStandard(value, privateKey, publicKey) {
  const signature = cryptoSign(null, Buffer.from(canonicalize(value), "utf8"), privateKey).toString("hex");
  return { ...value, signing: { algorithm: "ed25519", publicKey, signature } };
}

function buildBundle() {
  const root = mkdtempSync(join(tmpdir(), "shedu-pilot-bundle-"));
  const { privateKey } = generateKeyPairSync("ed25519");
  const publicKey = Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url").toString("hex");
  const authorityId = "bench-kernel-attestor";
  const commit = "a".repeat(40);
  const tree = "b".repeat(40);
  const release = "@shedu/promotion-kernel@0.6.0-experimental";
  const subject = { subjectId: "shedu-promotion-kernel", repository: "https://github.com/Shedu-ai/shedu-promotion-kernel.git", kernelRelease: release, kernelCommit: commit, kernelTree: tree };
  const authority = put(root, "authority.json", { schemaVersion: "promotion-kernel-activation-authority@1", authorityId, algorithm: "ed25519", publicKey, status: "ACTIVE" });
  const conformanceUnsigned = { schemaVersion: "conformance-attestation@1", kernelRelease: release, kernelCommit: commit, conformanceStatusDigest: `sha256:${"1".repeat(64)}`, mechanismInventoryDigest: `sha256:${"2".repeat(64)}`, controlSurfaceDigest: `sha256:${"3".repeat(64)}`, signing: null };
  const conformance = put(root, "conformance-attestation.json", signStandard(conformanceUnsigned, privateKey, publicKey));
  const certificationUnsigned = {
    schemaVersion: "harness-bench-kernel-certification@1", authorityId,
    kernel: { subjectId: "shedu-promotion-kernel", repository: subject.repository, commitSha: commit, treeSha: tree, release },
    verification: { source: { cleanAfterVerification: true, headExact: true, remotesStripped: true, treeExact: true }, test: { failed: 0 }, conformance: { failed: 0, byteIdentical: true }, probe: { implementationStatus: "EXPERIMENTAL", promotionEntrypointAvailable: true } },
    attestationSha256: conformance.digest, allPassed: true, signing: null
  };
  const certification = put(root, "conformance-certification.json", signStandard(certificationUnsigned, privateKey, publicKey));
  const activationSpecValue = { schemaVersion: "promotion-kernel-activation-specification@1", profile: "pilot-v1", kernel: { commit, tree, release } };
  const activationSpecification = put(root, "activation-specification.json", activationSpecValue);
  const policyValue = {
    schemaVersion: "kernel-pilot-qualification-policy@1", policyId: "public-pilot", policyVersion: 1, frozenAt: "2026-09-05T00:00:00Z", subject,
    activationSpecificationDigest: activationSpecification.digest, authorityId, validityDays: 60,
    ceilings: { maxRuntimeSeconds: 3600, maxArtifactBytes: 1000000, maxOutputBytes: 1000000, maxTasks: 64 },
    requiredChecks: [{ checkId: "qualification", platform: "darwin", profile: "STRICT", argv: ["node", "--test"], expectedOutcome: "PASS" }],
    unresolvedIncidents: { critical: 0, high: 0 }
  };
  const policy = put(root, "lifecycle-policy.json", policyValue);
  const inputValue = {
    schemaVersion: "kernel-pilot-qualification-input@1", subject, policyDigest: digestOfCanonical(policyValue), activationSpecificationDigest: activationSpecification.digest,
    conformance: { attestationDigest: conformance.digest, certificationDigest: certification.digest, mechanismInventoryDigest: conformanceUnsigned.mechanismInventoryDigest, controlSurfaceDigest: conformanceUnsigned.controlSurfaceDigest, statusDigest: conformanceUnsigned.conformanceStatusDigest },
    results: [{ checkId: "qualification", platform: "darwin", profile: "STRICT", argv: ["node", "--test"], outcome: "PASS", exitCode: 0, evidenceDigest: `sha256:${"4".repeat(64)}` }],
    privateEvidenceManifest: [{ artifactId: "qualification", digest: `sha256:${"4".repeat(64)}`, byteLength: 1 }], providerCalls: 0
  };
  const compiled = compilePilotQualification({ policyBytes: Buffer.from(canonicalize(policyValue)), inputBytes: Buffer.from(canonicalize(inputValue)) });
  assert.equal(compiled.ok, true);
  const lifecycleEvidence = put(root, "lifecycle-evidence.json", compiled.receipt);
  const lifecycleUnsigned = {
    schemaVersion: "kernel-lifecycle-attestation@1", subject,
    activationProfile: { id: "public-pilot", version: 1, configurationDigest: activationSpecification.digest },
    requestedStatus: "PILOT_ELIGIBLE", predecessor: { status: "EXPERIMENTAL", attestationDigest: conformance.digest },
    evidence: { kind: "PILOT_QUALIFICATION_COMPLETE", publicDigest: lifecycleEvidence.digest, policyId: "public-pilot", policyVersion: 1, policyDigest: policy.digest, privateManifestRootDigest: compiled.receipt.privateEvidenceManifestRootDigest },
    conformance: { attestationDigest: conformance.digest, certificationDigest: certification.digest, mechanismInventoryDigest: conformanceUnsigned.mechanismInventoryDigest, controlSurfaceDigest: conformanceUnsigned.controlSurfaceDigest },
    executionClaims: [{ platform: "darwin", profile: "STRICT" }],
    validity: { issuedAt: "2026-09-05T00:00:00Z", validFrom: "2026-09-05T00:00:00Z", expiresAt: "2026-10-05T00:00:00Z", maxClockSkewSeconds: 60 },
    sequence: 1, supersedes: null,
    authority: { authorityId, algorithm: "ed25519", publicKey, signature: null }
  };
  const lifecycleSignature = cryptoSign(null, Buffer.from(canonicalize(lifecycleUnsigned)), privateKey).toString("hex");
  const lifecycleAttestation = put(root, "lifecycle-attestation.json", { ...lifecycleUnsigned, authority: { ...lifecycleUnsigned.authority, signature: lifecycleSignature } });
  const commands = ["compile", "conformance", "doctor", "evaluate", "inspect-evidence", "probe", "sandbox:linux:pull", "setup", "status", "verify-receipt"];
  const manifest = {
    schemaVersion: "promotion-kernel-activation-distribution@2", distributionId: "pilot-v1", releaseTag: "v0.6.0-pilot.1", requestedStatus: "PILOT_ELIGIBLE",
    kernel: { repository: subject.repository, release, commit, tree },
    authority: { authorityId, algorithm: "ed25519", publicKey, ...authority },
    evidence: { conformanceAttestation: conformance, conformanceCertification: certification, lifecycleAttestation, lifecycleEvidence, lifecyclePolicy: policy, activationSpecification }, commands
  };
  put(root, "manifest.json", manifest);
  return root;
}

test("a v2 pilot bundle binds the full external lifecycle evidence set", () => {
  const root = buildBundle();
  const verified = verifyDistributionBundle({ activationRoot: root });
  assert.equal(verified.manifest.requestedStatus, "PILOT_ELIGIBLE");
  assert.ok(verified.lifecyclePaths.lifecyclePolicyPath.endsWith("lifecycle-policy.json"));
});

test("a lifecycle member mutation is refused before installation", () => {
  const root = buildBundle();
  const path = join(root, "lifecycle-evidence.json");
  const bytes = readFileSync(path);
  bytes[10] ^= 1;
  writeFileSync(path, bytes);
  assert.throws(() => verifyDistributionBundle({ activationRoot: root }), (error) => error instanceof DistributionError && error.reasonCode === "ACTIVATION_EVIDENCE_INVALID");
});
