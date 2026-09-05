import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  admittedLifecycleStatus,
  computeAdmission,
  isAdmitted,
  isCertified,
  isPilotEligible,
  attestationBody
} from "../src/admission.mjs";
import { canonicalize, digestOfBytes, digestOfCanonical } from "../src/canonical-json.mjs";
import { KERNEL_RELEASE } from "../src/compiler.mjs";
import { compilePilotQualification } from "../src/pilot-qualification.mjs";

const statusBytes = readFileSync(new URL("../conformance/status.json", import.meta.url));
const KERNEL_COMMIT = "a".repeat(40);
const KERNEL_TREE = "b".repeat(40);
const INV_DIGEST = `sha256:${"1".repeat(64)}`;
const CTRL_DIGEST = `sha256:${"2".repeat(64)}`;
const AUTHORITY_ID = "kernel-attestation";
const ISSUED = "2026-09-05T12:00:00Z";
const EXPIRES = "2026-10-05T12:00:00Z";

function externalAuthority() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const publicKey = Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url").toString("hex");
  return { privateKey, publicKey };
}

function signConformance(privateKey, publicKey) {
  const body = attestationBody({
    kernelCommit: KERNEL_COMMIT,
    statusDigest: digestOfBytes(statusBytes),
    mechanismInventoryDigest: INV_DIGEST,
    controlSurfaceDigest: CTRL_DIGEST
  });
  const signature = cryptoSign(null, Buffer.from(canonicalize(body), "utf8"), privateKey).toString("hex");
  return Buffer.from(canonicalize({ ...body, signing: { algorithm: "ed25519", publicKey, signature } }), "utf8");
}

function pilotFixture() {
  const authority = externalAuthority();
  const conformanceAttestationBytes = signConformance(authority.privateKey, authority.publicKey);
  const conformanceCertificationBytes = Buffer.from(canonicalize({ external: "certification", commit: KERNEL_COMMIT }), "utf8");
  const activationSpecificationBytes = Buffer.from(canonicalize({ profile: "pilot-v1", members: ["authority", "evidence", "launcher"] }), "utf8");
  const subject = {
    subjectId: "shedu-promotion-kernel",
    repository: "https://github.com/Shedu-ai/shedu-promotion-kernel.git",
    kernelRelease: KERNEL_RELEASE,
    kernelCommit: KERNEL_COMMIT,
    kernelTree: KERNEL_TREE
  };
  const policy = {
    schemaVersion: "kernel-pilot-qualification-policy@1",
    policyId: "public-pilot",
    policyVersion: 1,
    frozenAt: ISSUED,
    subject,
    activationSpecificationDigest: digestOfBytes(activationSpecificationBytes),
    authorityId: AUTHORITY_ID,
    validityDays: 60,
    ceilings: { maxRuntimeSeconds: 3600, maxArtifactBytes: 1000000, maxOutputBytes: 1000000, maxTasks: 64 },
    requiredChecks: [
      { checkId: "darwin-conforming", platform: "darwin", profile: "STRICT", argv: ["node", "test/fixture.mjs", "conforming"], expectedOutcome: "PROMOTABLE" },
      { checkId: "linux-planted", platform: "linux-oci", profile: "STANDARD_TEST", argv: ["node", "test/fixture.mjs", "planted"], expectedOutcome: "BLOCKED" }
    ],
    unresolvedIncidents: { critical: 0, high: 0 }
  };
  const policyBytes = Buffer.from(canonicalize(policy), "utf8");
  const results = policy.requiredChecks.map((check, index) => ({
    checkId: check.checkId,
    platform: check.platform,
    profile: check.profile,
    argv: check.argv,
    outcome: check.expectedOutcome,
    exitCode: 0,
    durationMilliseconds: 1,
    outputBytes: 1,
    evidenceDigest: `sha256:${String(index + 3).repeat(64)}`
  }));
  const input = {
    schemaVersion: "kernel-pilot-qualification-input@1",
    subject,
    policyDigest: digestOfCanonical(policy),
    activationSpecificationDigest: policy.activationSpecificationDigest,
    conformance: {
      attestationDigest: digestOfBytes(conformanceAttestationBytes),
      certificationDigest: digestOfBytes(conformanceCertificationBytes),
      mechanismInventoryDigest: INV_DIGEST,
      controlSurfaceDigest: CTRL_DIGEST,
      statusDigest: digestOfBytes(statusBytes)
    },
    results,
    privateEvidenceManifest: results.map((result) => ({ artifactId: result.checkId, digest: result.evidenceDigest, byteLength: 1 })),
    providerCalls: 0
  };
  const inputBytes = Buffer.from(canonicalize(input), "utf8");
  const compiled = compilePilotQualification({ policyBytes, inputBytes });
  assert.equal(compiled.ok, true, JSON.stringify(compiled.errors));
  const evidenceBytes = Buffer.from(compiled.receiptBytes, "utf8");
  const unsigned = {
    schemaVersion: "kernel-lifecycle-attestation@1",
    subject,
    activationProfile: { id: "public-pilot", version: 1, configurationDigest: policy.activationSpecificationDigest },
    requestedStatus: "PILOT_ELIGIBLE",
    predecessor: { status: "EXPERIMENTAL", attestationDigest: digestOfBytes(conformanceAttestationBytes) },
    evidence: {
      kind: "PILOT_QUALIFICATION_COMPLETE",
      publicDigest: digestOfBytes(evidenceBytes),
      policyId: policy.policyId,
      policyVersion: policy.policyVersion,
      policyDigest: digestOfCanonical(policy),
      privateManifestRootDigest: compiled.receipt.privateEvidenceManifestRootDigest
    },
    conformance: {
      attestationDigest: digestOfBytes(conformanceAttestationBytes),
      certificationDigest: digestOfBytes(conformanceCertificationBytes),
      mechanismInventoryDigest: INV_DIGEST,
      controlSurfaceDigest: CTRL_DIGEST
    },
    executionClaims: [
      { platform: "darwin", profile: "STRICT" },
      { platform: "linux-oci", profile: "STANDARD_TEST" }
    ],
    validity: { issuedAt: ISSUED, validFrom: ISSUED, expiresAt: EXPIRES, maxClockSkewSeconds: 60 },
    sequence: 1,
    supersedes: null,
    authority: { authorityId: AUTHORITY_ID, algorithm: "ed25519", publicKey: authority.publicKey, signature: null }
  };
  const signature = cryptoSign(null, Buffer.from(canonicalize(unsigned), "utf8"), authority.privateKey).toString("hex");
  const lifecycleAttestationBytes = Buffer.from(canonicalize({ ...unsigned, authority: { ...unsigned.authority, signature } }), "utf8");
  return { authority, conformanceAttestationBytes, conformanceCertificationBytes, activationSpecificationBytes, policyBytes, inputBytes, evidenceBytes, lifecycleAttestationBytes };
}

function admission(fixture, extra = {}) {
  return computeAdmission({
    statusBytes,
    attestationBytes: fixture.conformanceAttestationBytes,
    trustedKeys: [fixture.authority.publicKey],
    kernelCommit: KERNEL_COMMIT,
    kernelTree: KERNEL_TREE,
    sourceClean: true,
    mechanismInventoryDigest: INV_DIGEST,
    controlSurfaceDigest: CTRL_DIGEST,
    lifecycleAttestationBytes: fixture.lifecycleAttestationBytes,
    lifecycleEvidenceBytes: fixture.evidenceBytes,
    lifecyclePolicyBytes: fixture.policyBytes,
    activationSpecificationBytes: fixture.activationSpecificationBytes,
    conformanceCertificationBytes: fixture.conformanceCertificationBytes,
    lifecycleAuthorityId: AUTHORITY_ID,
    now: new Date("2026-09-06T12:00:00Z"),
    ...extra
  });
}

test("zero-provider qualification is byte-identical and exact-argv bound", () => {
  const one = pilotFixture();
  const replay = compilePilotQualification({ policyBytes: one.policyBytes, inputBytes: one.inputBytes });
  assert.equal(replay.ok, true);
  assert.equal(one.evidenceBytes.toString("utf8"), replay.receiptBytes);
  const changed = JSON.parse(one.inputBytes);
  changed.results[0].argv = ["node", "test/fixture.mjs", "different"];
  const rejected = compilePilotQualification({ policyBytes: one.policyBytes, inputBytes: Buffer.from(canonicalize(changed), "utf8") });
  assert.equal(rejected.ok, false);
  assert.ok(rejected.receipt.reasonCodes.includes("QUALIFICATION_RESULT_UNEXPECTED"));
});

test("qualification closes evidence identity, ordering, and every declared ceiling", () => {
  for (const mutate of [
    (policy, input) => { input.privateEvidenceManifest[0].digest = `sha256:${"f".repeat(64)}`; },
    (policy, input) => { input.results[0].durationMilliseconds = policy.ceilings.maxRuntimeSeconds * 1000 + 1; },
    (policy, input) => { input.results[0].outputBytes = policy.ceilings.maxOutputBytes + 1; },
    (policy, input) => { input.privateEvidenceManifest[0].byteLength = policy.ceilings.maxArtifactBytes + 1; },
    (policy) => { policy.ceilings.maxTasks = 1; }
  ]) {
    const fixture = pilotFixture();
    const policy = JSON.parse(fixture.policyBytes);
    const input = JSON.parse(fixture.inputBytes);
    mutate(policy, input);
    input.policyDigest = digestOfCanonical(policy);
    const result = compilePilotQualification({
      policyBytes: Buffer.from(canonicalize(policy), "utf8"),
      inputBytes: Buffer.from(canonicalize(input), "utf8")
    });
    assert.equal(result.ok, false);
  }
});

test("a signed exact qualification elevates only the branded admission to PILOT_ELIGIBLE", () => {
  const fixture = pilotFixture();
  const outcome = admission(fixture);
  assert.equal(admittedLifecycleStatus(outcome), "PILOT_ELIGIBLE");
  assert.equal(isAdmitted(outcome), true);
  assert.equal(isPilotEligible(outcome), true);
  assert.equal(isCertified(outcome), false);
  assert.equal(isPilotEligible({ status: "PILOT_ELIGIBLE", admitted: true }), false);
});

test("mutation, expiry, wrong identity, and wrong authority reduce to still-valid EXPERIMENTAL", () => {
  const fixture = pilotFixture();
  const mutated = Buffer.from(fixture.evidenceBytes);
  mutated[10] ^= 1;
  assert.equal(admission(fixture, { lifecycleEvidenceBytes: mutated }).status, "EXPERIMENTAL");
  assert.equal(admission(fixture, { now: new Date("2027-01-01T00:00:00Z") }).status, "EXPERIMENTAL");
  assert.equal(admission(fixture, { kernelTree: "c".repeat(40) }).status, "EXPERIMENTAL");
  assert.equal(admission(fixture, { lifecycleAuthorityId: "other-authority" }).status, "EXPERIMENTAL");
});

test("pilot evidence can never be relabeled CERTIFIED", () => {
  const fixture = pilotFixture();
  const att = JSON.parse(fixture.lifecycleAttestationBytes);
  att.requestedStatus = "CERTIFIED";
  att.predecessor.status = "PILOT_ELIGIBLE";
  att.evidence.kind = "OPERATIONAL_CERTIFICATION_COMPLETE";
  const unsigned = { ...att, authority: { ...att.authority, signature: null } };
  const signature = cryptoSign(null, Buffer.from(canonicalize(unsigned), "utf8"), fixture.authority.privateKey).toString("hex");
  const forged = Buffer.from(canonicalize({ ...unsigned, authority: { ...unsigned.authority, signature } }), "utf8");
  assert.equal(admission(fixture, { lifecycleAttestationBytes: forged }).status, "EXPERIMENTAL");
});
