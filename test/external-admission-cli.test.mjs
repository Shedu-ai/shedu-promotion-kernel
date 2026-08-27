import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, writeFileSync, rmSync } from "node:fs";
import { generateKeyPairSync, sign as cryptoSign, createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalize, digestOfBytes } from "../src/canonical-json.mjs";
import { attestationBody } from "../src/admission.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const kernelRoot = new URL("..", import.meta.url).pathname;

function git(...args) {
  const r = spawnSync("git", ["-C", kernelRoot, ...args], { encoding: "utf8", env: { PATH: process.env.PATH } });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
}

// End-to-end external admission: freeze the kernel at HEAD in a CLEAN detached
// worktree, have an EXTERNAL verifier sign an attestation binding that exact
// commit + committed conformance status + inventories, then invoke `evaluate`
// through the declared subject contract with the pinned key + attestation and
// obtain admission. Also confirms dirty/wrong-key/wrong-commit all fail.
test("a clean detached worktree with an external attestation admits and evaluates through the CLI", () => {
  const head = git("rev-parse", "HEAD");
  // A clean checkout of HEAD (shares .git; a fresh detached worktree is clean).
  const wt = realpathSync(mkdtempSync(join(tmpdir(), "shedu-wt-")));
  rmSync(wt, { recursive: true, force: true }); // git worktree add needs a non-existent path
  git("worktree", "add", "--detach", wt, head);

  try {
    // The external verifier reads the FROZEN, committed evidence from the
    // worktree and signs an attestation over it.
    const statusBytes = readFileSync(join(wt, "conformance", "status.json"));
    const inventoryBytes = readFileSync(join(wt, "registry", "kernel-mechanisms.json"));
    const controlBytes = readFileSync(join(wt, "registry", "control-surface.json"));
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

    // The subject/target to evaluate.
    const target = buildTargetRepo();
    writeRepoFile(target.repoDir, "src/feature.mjs", "export const f = 2;\n");
    const candidate = commitAll(target.repoDir, "feature");
    const contractPath = join(mkdtempSync(join(tmpdir(), "shedu-c-")), "contract.json");
    writeFileSync(contractPath, contractBytesOf(target.contractFor(candidate)));
    const out = mkdtempSync(join(tmpdir(), "shedu-out-"));

    const cli = join(wt, "src", "cli.mjs");
    const runEvaluate = (extraFlags) =>
      spawnSync(process.execPath, [cli, "evaluate", "--contract", contractPath, "--repo", target.repoDir, "--out", out, ...extraFlags], {
        encoding: "utf8",
        env: { PATH: process.env.PATH }
      });

    // With the correct external material → admitted and PROMOTABLE.
    const admitted = runEvaluate(["--attestation", attPath, "--pinned-key", publicKeyHex, "--expected-commit", head]);
    assert.equal(admitted.status, 0, admitted.stderr);
    const receipt = JSON.parse(admitted.stdout);
    assert.equal(receipt.schemaVersion, "promotion-receipt@1");
    assert.equal(receipt.disposition, "PROMOTABLE", JSON.stringify(receipt.reasonCodes));

    // Wrong pinned key → refused.
    const wrongKey = "a".repeat(64);
    const badKey = runEvaluate(["--attestation", attPath, "--pinned-key", wrongKey, "--expected-commit", head]);
    assert.equal(badKey.status, 2);
    assert.equal(JSON.parse(badKey.stderr).reasonCode, "NOT_ADMITTED");

    // Wrong expected commit → refused.
    const badCommit = runEvaluate(["--attestation", attPath, "--pinned-key", publicKeyHex, "--expected-commit", "b".repeat(40)]);
    assert.equal(badCommit.status, 2);
    assert.equal(JSON.parse(badCommit.stderr).reasonCode, "NOT_ADMITTED");

    // Missing attestation → refused.
    const noAtt = runEvaluate([]);
    assert.equal(noAtt.status, 2);
    assert.equal(JSON.parse(noAtt.stderr).reasonCode, "NOT_ADMITTED");

    // Dirty source at the attested commit → refused (make the worktree dirty).
    writeFileSync(join(wt, "conformance", "status.json"), Buffer.concat([statusBytes, Buffer.from("\n")]));
    const dirty = runEvaluate(["--attestation", attPath, "--pinned-key", publicKeyHex, "--expected-commit", head]);
    assert.equal(dirty.status, 2);
    assert.equal(JSON.parse(dirty.stderr).reasonCode, "NOT_ADMITTED");
  } finally {
    git("worktree", "remove", "--force", wt);
  }
});
