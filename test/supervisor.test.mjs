import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdtempSync, readFileSync, readlinkSync, realpathSync, writeFileSync, mkdirSync, readdirSync, symlinkSync } from "node:fs";
import { generateKeyPairSync, sign as cryptoSign, createPublicKey } from "node:crypto";
import { pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import test, { before } from "node:test";
import { canonicalize, digestOfBytes } from "../src/canonical-json.mjs";
import { attestationBody } from "../src/admission.mjs";
import { generateSigningKeyPem, verifyReceipt } from "../src/receipt.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const kernelRoot = new URL("..", import.meta.url).pathname;
const outDir = () => mkdtempSync(join(tmpdir(), "shedu-supervisor-"));

// The supervised promotion path enforces admission UNCONDITIONALLY inside the
// worker. To exercise supervision mechanics (bundle publication, signing,
// deadline kill, atomic publish, purge) we must first make the kernel itself
// admitted. Because admission requires a CLEAN, committed frozen checkout, we
// build a self-contained committed copy of THIS working tree (so uncommitted
// changes are included), freeze it, and have an external verifier sign an
// attestation binding that commit. The supervisor is then imported FROM the
// copy so its worker resolves admission against the clean tree.
let SUP;         // evaluateSupervised imported from the committed copy
let ADMIT_ENV;   // worker env carrying the external admission material

before(async () => {
  const copy = realpathSync(mkdtempSync(join(tmpdir(), "shedu-kernelcopy-")));
  for (const dir of ["src", "registry", "packs", "schemas", "conformance"]) {
    cpSync(join(kernelRoot, dir), join(copy, dir), { recursive: true });
  }
  cpSync(join(kernelRoot, "package.json"), join(copy, "package.json"));
  const g = (...a) => {
    const r = spawnSync("git", ["-C", copy, ...a], { encoding: "utf8", env: { PATH: process.env.PATH } });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  g("init", "-q");
  g("-c", "user.email=t@invalid", "-c", "user.name=t", "add", "-A");
  g("-c", "user.email=t@invalid", "-c", "user.name=t", "commit", "-q", "-m", "frozen");
  const head = g("rev-parse", "HEAD");

  const statusBytes = readFileSync(join(copy, "conformance", "status.json"));
  const inventoryBytes = readFileSync(join(copy, "registry", "kernel-mechanisms.json"));
  const controlBytes = readFileSync(join(copy, "registry", "control-surface.json"));
  const { privateKey } = generateKeyPairSync("ed25519");
  const publicKeyHex = Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url").toString("hex");
  const body = attestationBody({
    kernelCommit: head,
    statusDigest: digestOfBytes(statusBytes),
    mechanismInventoryDigest: digestOfBytes(inventoryBytes),
    controlSurfaceDigest: digestOfBytes(controlBytes)
  });
  const signature = cryptoSign(null, Buffer.from(canonicalize(body), "utf8"), privateKey).toString("hex");
  const attPath = join(mkdtempSync(join(tmpdir(), "shedu-att-")), "attestation.json");
  writeFileSync(attPath, Buffer.from(canonicalize({ ...body, signing: { algorithm: "ed25519", publicKey: publicKeyHex, signature } }), "utf8"));

  ADMIT_ENV = { SHEDU_ATTESTATION_FILE: attPath, SHEDU_PINNED_KEY: publicKeyHex, SHEDU_EXPECTED_COMMIT: head };
  ({ evaluateSupervised: SUP } = await import(pathToFileURL(join(copy, "src", "supervisor.mjs")).href));
});

function target() {
  const t = buildTargetRepo();
  writeRepoFile(t.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(t.repoDir, "feature");
  return { repoDir: t.repoDir, contractBytes: contractBytesOf(t.contractFor(candidate)) };
}

// Preseed a published bundle at the atomic location so purge behaviour is
// observable: a stale `current` bundle must never survive a failed run.
function preseedCurrent(dir) {
  const v = join(dir, ".v-preseed");
  mkdirSync(v, { recursive: true });
  writeFileSync(join(v, "receipt.json"), JSON.stringify({ schemaVersion: "promotion-receipt@1", disposition: "PROMOTABLE", preseeded: true }));
  symlinkSync(".v-preseed", join(dir, "current"));
}
const published = (dir) => join(dir, "current", "receipt.json");

test("a genuine supervised evaluation publishes one internally consistent digest-bound bundle atomically", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  const r = SUP({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 600, workerEnv: ADMIT_ENV });
  assert.equal(r.timedOut, false);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.disposition, "PROMOTABLE", JSON.stringify(r.reasonCodes));
  // `current` is a symlink onto a versioned bundle (atomic publish).
  assert.ok(existsSync(published(dir)));
  assert.ok(existsSync(join(dir, "current", "plan.json")));
  assert.ok(existsSync(join(dir, "current", "artifacts", "evidence", "index.json")));
  const verification = verifyReceipt({
    receiptBytes: readFileSync(published(dir)),
    planBytes: readFileSync(join(dir, "current", "plan.json")),
    evidenceDir: join(dir, "current", "artifacts", "evidence")
  });
  assert.equal(verification.ok, true, JSON.stringify(verification.errors));
});

test("publication is atomic: `current` is a symlink flipped onto a complete bundle, and re-publishing replaces it wholesale", () => {
  const dir = outDir();
  const first = target();
  const r1 = SUP({ repoDir: first.repoDir, contractBytes: first.contractBytes, outDir: dir, maxRuntimeSeconds: 600, workerEnv: ADMIT_ENV });
  assert.equal(r1.ok, true, JSON.stringify(r1));
  // `current` is a SYMLINK (the atomic-flip mechanism), not a copied directory.
  assert.ok(lstatSync(join(dir, "current")).isSymbolicLink(), "current must be a symlink for atomic publish");
  const firstTarget = readlinkSync(join(dir, "current"));
  assert.ok(firstTarget.startsWith(".v-"), firstTarget);
  // The pointed-at bundle is complete.
  assert.ok(existsSync(published(dir)) && existsSync(join(dir, "current", "plan.json")));

  // Re-publish into the same dir: the flip replaces `current` wholesale, and
  // superseded version dirs are cleaned — never a mixed/partial bundle.
  const second = target();
  const r2 = SUP({ repoDir: second.repoDir, contractBytes: second.contractBytes, outDir: dir, maxRuntimeSeconds: 600, workerEnv: ADMIT_ENV });
  assert.equal(r2.ok, true, JSON.stringify(r2));
  assert.ok(lstatSync(join(dir, "current")).isSymbolicLink());
  const secondTarget = readlinkSync(join(dir, "current"));
  assert.notEqual(secondTarget, firstTarget, "the flip must point at the new version");
  // Exactly one version dir remains (the published one); no orphan partial dirs.
  const versionDirs = readdirSync(dir).filter((n) => n.startsWith(".v-"));
  assert.deepEqual(versionDirs, [secondTarget]);
});

test("signing happens inside the supervised boundary", () => {
  const { repoDir, contractBytes } = target();
  const keyPath = join(mkdtempSync(join(tmpdir(), "shedu-key-")), "key.pem");
  writeFileSync(keyPath, generateSigningKeyPem());
  const dir = outDir();
  const r = SUP({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 600, signKeyPath: keyPath, workerEnv: ADMIT_ENV });
  assert.equal(r.ok, true, JSON.stringify(r));
  const receipt = JSON.parse(readFileSync(published(dir), "utf8"));
  assert.equal(receipt.signing?.algorithm, "ed25519");
  const verification = verifyReceipt({
    receiptBytes: readFileSync(published(dir)),
    planBytes: readFileSync(join(dir, "current", "plan.json")),
    expectedPublicKey: receipt.signing.publicKey
  });
  assert.equal(verification.ok, true, JSON.stringify(verification.errors));
});

test("preseeding a PROMOTABLE bundle then running an invalid evaluation leaves no promotable receipt", () => {
  const { repoDir } = target();
  const dir = outDir();
  preseedCurrent(dir);
  // Admission passes (clean copy) but the contract is invalid → evaluation
  // fails → nothing published, and the preseeded bundle is purged.
  const r = SUP({ repoDir, contractBytes: Buffer.from('{"schemaVersion":"work-contract@1"}'), outDir: dir, maxRuntimeSeconds: 60, workerEnv: ADMIT_ENV });
  assert.equal(r.ok, false);
  assert.equal(existsSync(join(dir, "current")), false, "no promotable bundle may remain");
});

test("a runaway synchronous stall is hard-killed at the ceiling with no published bundle", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  preseedCurrent(dir);
  const started = performance.now();
  const r = SUP({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 1, workerEnv: { ...ADMIT_ENV, SHEDU_TEST_STALL_MS: "8000" } });
  const elapsedMs = performance.now() - started;
  assert.equal(r.timedOut, true);
  assert.deepEqual(r.reasonCodes, ["DEADLINE_EXCEEDED"]);
  assert.ok(elapsedMs < 1600, `ran ${Math.round(elapsedMs)}ms`);
  assert.equal(existsSync(join(dir, "current")), false, "the preseeded bundle must be purged");
});

test("a kill after receipt construction but before summary publication publishes nothing", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  preseedCurrent(dir);
  const r = SUP({
    repoDir,
    contractBytes,
    outDir: dir,
    maxRuntimeSeconds: 1,
    workerEnv: { ...ADMIT_ENV, SHEDU_TEST_STALL_AFTER_RECEIPT_MS: "8000" }
  });
  assert.equal(r.timedOut, true);
  assert.equal(existsSync(join(dir, "current")), false);
});

test("a signing failure inside the boundary publishes nothing", () => {
  const { repoDir, contractBytes } = target();
  const dir = outDir();
  preseedCurrent(dir);
  // A signing key path that is a DIRECTORY is refused by the bounded key read;
  // the worker reports failure → nothing published, preseed purged.
  const r = SUP({ repoDir, contractBytes, outDir: dir, maxRuntimeSeconds: 60, signKeyPath: dir, workerEnv: ADMIT_ENV });
  assert.equal(r.ok, false);
  assert.equal(existsSync(join(dir, "current")), false);
});
