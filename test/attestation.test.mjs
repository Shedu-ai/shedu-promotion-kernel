import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign as cryptoSign, createPublicKey } from "node:crypto";
import test from "node:test";
import { canonicalize, digestOfBytes } from "../src/canonical-json.mjs";
import { computeAdmission, verifyFrozenSource, attestationBody, isAdmitted } from "../src/admission.mjs";
import { KERNEL_RELEASE } from "../src/compiler.mjs";

// A minimal but real conformance-status@2 that recomputes as passed.
const STATUS = {
  schemaVersion: "conformance-status@2",
  kernelRelease: KERNEL_RELEASE,
  allPassed: true,
  cases: [
    { caseId: "c1", conforming: { disposition: "PROMOTABLE", planDigest: `sha256:${"1".repeat(64)}`, resultProjectionDigest: `sha256:${"2".repeat(64)}`, receiptVerified: true }, planted: { disposition: "BLOCKED", planDigest: `sha256:${"3".repeat(64)}`, resultProjectionDigest: `sha256:${"4".repeat(64)}`, receiptVerified: true } },
    { caseId: "c2", conforming: { disposition: "PROMOTABLE", planDigest: `sha256:${"5".repeat(64)}`, resultProjectionDigest: `sha256:${"6".repeat(64)}`, receiptVerified: true }, planted: { disposition: "BLOCKED", planDigest: `sha256:${"7".repeat(64)}`, resultProjectionDigest: `sha256:${"8".repeat(64)}`, receiptVerified: true } },
    { caseId: "c3", conforming: { disposition: "PROMOTABLE", planDigest: `sha256:${"9".repeat(64)}`, resultProjectionDigest: `sha256:${"a".repeat(64)}`, receiptVerified: true }, planted: { disposition: "BLOCKED", planDigest: `sha256:${"b".repeat(64)}`, resultProjectionDigest: `sha256:${"c".repeat(64)}`, receiptVerified: true } }
  ],
  kernelActivation: [{ mechanismId: "m1", caseId: "c1", proven: true }],
  controlCensus: {
    complete: true,
    registered: 21,
    proven: 21,
    productionRequired: 14,
    productionObserved: 14,
    productionEvidenceDigest: `sha256:${"9".repeat(64)}`,
    findings: []
  }
};

const git = (dir, ...args) =>
  spawnSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@t",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@t",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null"
    }
  });

// Build a clean frozen source repo whose committed files match the digests
// the attestation will bind, and return its commit + digests + bytes.
function frozenRepo(salt = "") {
  const dir = mkdtempSync(join(tmpdir(), "shedu-frozen-"));
  git(dir, "init", "-q");
  mkdirSync(join(dir, "conformance"), { recursive: true });
  mkdirSync(join(dir, "registry"), { recursive: true });
  const status = salt ? { ...STATUS, cases: [...STATUS.cases, { caseId: `c-${salt}`, conforming: STATUS.cases[0].conforming, planted: STATUS.cases[0].planted }] } : STATUS;
  const statusBytes = Buffer.from(canonicalize(status), "utf8");
  const inventoryBytes = Buffer.from('{"schemaVersion":"mechanism-registry@1","mechanisms":[]}\n', "utf8");
  const controlBytes = Buffer.from(`{"schemaVersion":"control-surface@1","controls":[]}${salt ? `\n${salt}` : ""}\n`, "utf8");
  writeFileSync(join(dir, "conformance", "status.json"), statusBytes);
  writeFileSync(join(dir, "registry", "kernel-mechanisms.json"), inventoryBytes);
  writeFileSync(join(dir, "registry", "control-surface.json"), controlBytes);
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", "frozen");
  const commit = git(dir, "rev-parse", "HEAD").stdout.trim();
  return { dir, commit, statusBytes, inventoryBytes, controlBytes };
}

function externalSigner() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  return { privateKey, publicKeyHex: Buffer.from(jwk.x, "base64url").toString("hex") };
}

function signAttestation(signer, { commit, statusBytes, inventoryBytes, controlBytes }) {
  const body = attestationBody({
    kernelCommit: commit,
    statusDigest: digestOfBytes(statusBytes),
    mechanismInventoryDigest: digestOfBytes(inventoryBytes),
    controlSurfaceDigest: digestOfBytes(controlBytes)
  });
  const signature = cryptoSign(null, Buffer.from(canonicalize(body), "utf8"), signer.privateKey).toString("hex");
  return Buffer.from(
    canonicalize({ ...body, signing: { algorithm: "ed25519", publicKey: signer.publicKeyHex, signature } }),
    "utf8"
  );
}

function admitFor(repo, signer, attestationBytes, overrides = {}) {
  const source = verifyFrozenSource(repo.dir, overrides.expectedCommit ?? repo.commit);
  return computeAdmission({
    statusBytes: repo.statusBytes,
    attestationBytes,
    trustedKeys: [signer.publicKeyHex],
    kernelCommit: source.commit,
    expectedCommit: overrides.expectedCommit ?? repo.commit,
    sourceClean: overrides.sourceClean ?? source.clean,
    mechanismInventoryDigest: digestOfBytes(repo.inventoryBytes),
    controlSurfaceDigest: digestOfBytes(repo.controlBytes),
    ...overrides.computeOverrides
  });
}

test("end-to-end: an external attestation over a clean frozen commit admits EXPERIMENTAL", () => {
  const repo = frozenRepo();
  const signer = externalSigner();
  const attestationBytes = signAttestation(signer, repo);
  const source = verifyFrozenSource(repo.dir, repo.commit);
  assert.equal(source.ok, true);
  assert.equal(source.clean, true);
  const admission = admitFor(repo, signer, attestationBytes);
  assert.equal(isAdmitted(admission), true, JSON.stringify(admission.reasons));
  assert.equal(admission.status, "EXPERIMENTAL");
});

test("a legacy conformance-status@1 cannot admit the v2 kernel release", () => {
  const legacy = Buffer.from(canonicalize({ ...STATUS, schemaVersion: "conformance-status@1" }), "utf8");
  const outcome = computeAdmission({ statusBytes: legacy });
  assert.equal(isAdmitted(outcome), false);
  assert.match(outcome.reasons.join(" "), /not schema-valid/);
});

test("end-to-end: dirty source cannot run under an attestation for the clean commit", () => {
  const repo = frozenRepo();
  const signer = externalSigner();
  const attestationBytes = signAttestation(signer, repo);
  // Dirty the working tree.
  writeFileSync(join(repo.dir, "conformance", "status.json"), Buffer.concat([repo.statusBytes, Buffer.from("\n")]));
  const source = verifyFrozenSource(repo.dir, repo.commit);
  assert.equal(source.clean, false);
  const admission = admitFor(repo, signer, attestationBytes);
  assert.equal(isAdmitted(admission), false);
});

test("end-to-end: wrong key, wrong commit, stale status, modified registry, replay, missing all fail", () => {
  const repo = frozenRepo();
  const signer = externalSigner();
  const attestationBytes = signAttestation(signer, repo);

  // Wrong key: a different externally-pinned key does not match the signer.
  const wrongKey = externalSigner();
  assert.equal(
    isAdmitted(
      computeAdmission({
        statusBytes: repo.statusBytes,
        attestationBytes,
        trustedKeys: [wrongKey.publicKeyHex],
        kernelCommit: repo.commit,
        expectedCommit: repo.commit,
        sourceClean: true,
        mechanismInventoryDigest: digestOfBytes(repo.inventoryBytes),
        controlSurfaceDigest: digestOfBytes(repo.controlBytes)
      })
    ),
    false
  );

  // Wrong expected commit.
  assert.equal(isAdmitted(admitFor(repo, signer, attestationBytes, { expectedCommit: "0".repeat(40) })), false);

  // Stale status: mutate the status bytes so the attestation digest no longer binds.
  const staleStatus = Buffer.concat([repo.statusBytes, Buffer.from(" ")]);
  assert.equal(
    isAdmitted(
      computeAdmission({
        statusBytes: staleStatus,
        attestationBytes,
        trustedKeys: [signer.publicKeyHex],
        kernelCommit: repo.commit,
        expectedCommit: repo.commit,
        sourceClean: true,
        mechanismInventoryDigest: digestOfBytes(repo.inventoryBytes),
        controlSurfaceDigest: digestOfBytes(repo.controlBytes)
      })
    ),
    false
  );

  // Modified registry (inventory digest mismatch).
  assert.equal(
    isAdmitted(admitFor(repo, signer, attestationBytes, { computeOverrides: { mechanismInventoryDigest: `sha256:${"e".repeat(64)}` } })),
    false
  );

  // Replay: an attestation for a DIFFERENT frozen repo cannot admit this one.
  const other = frozenRepo("salt-2");
  const otherAtt = signAttestation(signer, other);
  assert.equal(isAdmitted(admitFor(repo, signer, otherAtt)), false);

  // Missing attestation.
  assert.equal(isAdmitted(admitFor(repo, signer, null)), false);
});

test("the CLI reads external admission evidence from the environment but stays FOUNDATION_ONLY on a dirty tree", () => {
  // Even with env-supplied attestation + key, the real (dirty, uncommitted)
  // kernel working tree is not a clean checkout of the attested commit, so
  // the shipped probe stays FOUNDATION_ONLY.
  const repo = frozenRepo();
  const signer = externalSigner();
  const attestationBytes = signAttestation(signer, repo);
  const attPath = join(mkdtempSync(join(tmpdir(), "shedu-att-")), "attestation.json");
  writeFileSync(attPath, attestationBytes);
  const run = spawnSync(process.execPath, ["src/cli.mjs", "--subject-probe"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
    env: {
      ...process.env,
      SHEDU_ATTESTATION_FILE: attPath,
      SHEDU_PINNED_KEY: signer.publicKeyHex,
      SHEDU_EXPECTED_COMMIT: repo.commit
    }
  });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(JSON.parse(run.stdout).implementationStatus, "FOUNDATION_ONLY");
});
