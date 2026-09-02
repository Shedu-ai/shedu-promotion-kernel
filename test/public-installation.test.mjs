import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { authorityDigest } from "../scripts/digest-authority.mjs";
import { verifySamplePolicy } from "../scripts/verify-sample-policy.mjs";

const root = new URL("..", import.meta.url);
const exampleRoot = new URL("../examples/node-source-hygiene/", import.meta.url);

test("the published sample policy is digest-bound, fires negatively, and compiles", () => {
  const verification = verifySamplePolicy();
  assert.equal(verification.ok, true);
  assert.equal(verification.packId, "node-source-hygiene");
  assert.deepEqual(verification.validator, { passingFixture: "PASS", failingFixture: "BLOCKED" });
  assert.ok(verification.compiledCheckIds.includes("node-source-hygiene"));
  assert.ok(verification.compiledCheckIds.includes("scope-boundary-classify"));
});

test("sample pack byte drift is rejected instead of silently changing profile authority", () => {
  const scratch = mkdtempSync(join(tmpdir(), "shedu-sample-policy-drift-"));
  try {
    cpSync(exampleRoot, scratch, { recursive: true });
    const packPath = join(scratch, ".shedu", "policy", "node-source-hygiene.json");
    const bytes = readFileSync(packPath, "utf8");
    writeFileSync(packPath, bytes.replace("Example target policy", "Drifted target policy"));
    assert.throws(() => verifySamplePolicy({ exampleRoot: scratch }), /digest pin drifted/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("authority digest helper reports exact raw bytes and fails closed on bad usage", () => {
  const profilePath = new URL("../examples/node-source-hygiene/.shedu/policy/profile.json", import.meta.url);
  const result = authorityDigest(profilePath);
  assert.equal(result.schemaVersion, "authority-digest@1");
  assert.match(result.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.byteLength, readFileSync(profilePath).length);

  const cli = spawnSync(process.execPath, [fileURLToPath(new URL("../scripts/digest-authority.mjs", import.meta.url))], {
    cwd: root,
    encoding: "utf8"
  });
  assert.equal(cli.status, 2);
  assert.equal(JSON.parse(cli.stderr).reasonCode, "CLI_USAGE");
});

test("the installed-style bin symlink executes the CLI instead of silently doing nothing", () => {
  const scratch = mkdtempSync(join(tmpdir(), "shedu-kernel-bin-"));
  try {
    const binPath = join(scratch, "shedu-promotion-kernel");
    symlinkSync(fileURLToPath(new URL("../src/cli.mjs", import.meta.url)), binPath);
    const result = spawnSync(process.execPath, [binPath, "--subject-probe"], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const probe = JSON.parse(result.stdout);
    assert.equal(probe.schemaVersion, "harness-bench-subject-probe@1");
    assert.equal(probe.implementationStatus, "FOUNDATION_ONLY");
    assert.equal(probe.promotionEntrypointAvailable, false);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("public README links the admitted distribution, installation guide, and executable sample", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const install = readFileSync(new URL("../docs/INSTALLATION.md", import.meta.url), "utf8");
  assert.match(readme, /\[the installation guide\]\(docs\/INSTALLATION\.md\)/);
  assert.match(readme, /\[Node source-hygiene sample\]\(examples\/node-source-hygiene\/README\.md\)/);
  assert.match(install, /npm run verify:sample-policy/);
  assert.match(install, /v0\.4\.0-experimental\.1/);
  assert.match(install, /npm run experimental:doctor/);
  assert.match(install, /shedu-kernel-experimental evaluate/);
  assert.match(install, /69253a78f095572b727c2336644b03fbff5476c8/);
  assert.match(install, /FOUNDATION_ONLY/);
  assert.match(install, /npm run experimental -- sandbox:linux:pull/);
  assert.match(install, /sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5/);
});
