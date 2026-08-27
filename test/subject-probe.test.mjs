import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign as cryptoSign, createPublicKey } from "node:crypto";
import test from "node:test";
import { canonicalize, digestOfBytes } from "../src/canonical-json.mjs";
import { EXPERIMENTAL_CAPABILITIES, subjectProbe } from "../src/cli.mjs";
import { computeAdmission, deriveConformancePassed, attestationBody } from "../src/admission.mjs";
import { KERNEL_RELEASE } from "../src/compiler.mjs";

const statusBytes = readFileSync(new URL("../conformance/status.json", import.meta.url));
const KERNEL_COMMIT = "a".repeat(40);
const INV_DIGEST = `sha256:${"1".repeat(64)}`;
const CTRL_DIGEST = `sha256:${"2".repeat(64)}`;

function pinnedAttestation() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  const publicKeyHex = Buffer.from(jwk.x, "base64url").toString("hex");
  const body = attestationBody({
    kernelCommit: KERNEL_COMMIT,
    statusDigest: digestOfBytes(statusBytes),
    mechanismInventoryDigest: INV_DIGEST,
    controlSurfaceDigest: CTRL_DIGEST
  });
  const signature = cryptoSign(null, Buffer.from(canonicalize(body), "utf8"), privateKey).toString("hex");
  const attestation = { ...body, signing: { algorithm: "ed25519", publicKey: publicKeyHex, signature } };
  return { attestationBytes: Buffer.from(canonicalize(attestation), "utf8"), publicKeyHex };
}

const baseOk = (extra = {}) => {
  const { attestationBytes, publicKeyHex } = pinnedAttestation();
  return {
    statusBytes,
    attestationBytes,
    trustedKeys: [publicKeyHex],
    kernelCommit: KERNEL_COMMIT,
    mechanismInventoryDigest: INV_DIGEST,
    controlSurfaceDigest: CTRL_DIGEST,
    ...extra
  };
};

test("the shipped subject probe is honestly FOUNDATION_ONLY (no pinned attestation key)", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs", "--subject-probe"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8"
  });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  const probe = JSON.parse(result.stdout);
  assert.equal(probe.implementationStatus, "FOUNDATION_ONLY");
  assert.equal(probe.promotionEntrypointAvailable, false);
});

test("admission machinery elevates ONLY with recomputed status + a pinned signed attestation", () => {
  const ok = computeAdmission(baseOk());
  assert.equal(ok.status, "EXPERIMENTAL");
  assert.equal(ok.admitted, true);
  const probe = subjectProbe(ok);
  assert.equal(probe.implementationStatus, "EXPERIMENTAL");
  assert.deepEqual(probe.capabilities, [...EXPERIMENTAL_CAPABILITIES]);
  assert.equal(probe.promotionEntrypointAvailable, true);
});

test("a contradictory or unsigned status cannot elevate the subject", () => {
  // allPassed asserted true while a case is actually BLOCKED-conforming.
  const status = JSON.parse(statusBytes.toString("utf8"));
  const contradictory = { ...status, cases: status.cases.map((c, i) => (i === 0 ? { ...c, conforming: { ...c.conforming, disposition: "BLOCKED" } } : c)) };
  const contradictoryBytes = Buffer.from(canonicalize(contradictory), "utf8");
  const d = deriveConformancePassed(contradictory);
  assert.equal(d.passed, false);
  assert.equal(computeAdmission(baseOk({ statusBytes: contradictoryBytes })).status, "FOUNDATION_ONLY");

  // allPassed flipped to true over an unproven activation.
  const unproven = { ...status, allPassed: true, kernelActivation: status.kernelActivation.map((a, i) => (i === 0 ? { ...a, proven: false } : a)) };
  assert.equal(computeAdmission(baseOk({ statusBytes: Buffer.from(canonicalize(unproven), "utf8") })).status, "FOUNDATION_ONLY");

  // No attestation at all → FOUNDATION_ONLY even with a valid status.
  assert.equal(computeAdmission({ statusBytes, trustedKeys: [], kernelCommit: KERNEL_COMMIT }).status, "FOUNDATION_ONLY");
  // No pinned trust key → FOUNDATION_ONLY even with an attestation present.
  const { attestationBytes } = pinnedAttestation();
  assert.equal(computeAdmission({ statusBytes, attestationBytes, trustedKeys: [], kernelCommit: KERNEL_COMMIT }).status, "FOUNDATION_ONLY");
});

test("stale, wrong-commit, wrong-key, and replayed attestations all fail closed", () => {
  // Wrong commit.
  assert.equal(computeAdmission(baseOk({ kernelCommit: "b".repeat(40) })).status, "FOUNDATION_ONLY");
  // Wrong release (stale attestation for another release).
  const staleStatus = Buffer.from(canonicalize({ ...JSON.parse(statusBytes.toString("utf8")), kernelRelease: "@shedu/promotion-kernel@0.0.0-old" }), "utf8");
  assert.equal(computeAdmission(baseOk({ statusBytes: staleStatus })).status, "FOUNDATION_ONLY");
  // Wrong key: attestation signed by a key not in the trusted set.
  const { attestationBytes } = pinnedAttestation();
  assert.equal(
    computeAdmission(baseOk({ attestationBytes, trustedKeys: [`${"c".repeat(64)}`] })).status,
    "FOUNDATION_ONLY"
  );
  // Replay: a valid attestation for THIS status presented against a mutated
  // status whose digest no longer matches.
  const mutatedStatus = Buffer.from(canonicalize({ ...JSON.parse(statusBytes.toString("utf8")), cases: [] }), "utf8");
  const admission = computeAdmission(baseOk({ statusBytes: mutatedStatus }));
  assert.equal(admission.status, "FOUNDATION_ONLY");
  // Inventory/control-surface binding mismatch.
  assert.equal(computeAdmission(baseOk({ mechanismInventoryDigest: `sha256:${"9".repeat(64)}` })).status, "FOUNDATION_ONLY");
  assert.equal(computeAdmission(baseOk({ controlSurfaceDigest: `sha256:${"9".repeat(64)}` })).status, "FOUNDATION_ONLY");
});

test("non-probe execution still fails closed", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8"
  });
  assert.equal(result.status, 2);
  assert.deepEqual(JSON.parse(result.stderr), {
    schemaVersion: "promotion-kernel-error@1",
    status: "BLOCKED",
    reasonCode: "KERNEL_NOT_IMPLEMENTED"
  });
});

test("the Bench subject contract is honestly FOUNDATION_ONLY with no promotion entrypoint", () => {
  const subject = JSON.parse(readFileSync(new URL("../.harness-bench/subject.json", import.meta.url), "utf8"));
  assert.equal(subject.implementationStatus, "FOUNDATION_ONLY");
  assert.equal(subject.promotionArgv, null);
  assert.deepEqual(subject.conformanceArgv, ["node", "src/cli.mjs", "conformance"]);
  assert.match(KERNEL_RELEASE, /@shedu\/promotion-kernel@/);
});
