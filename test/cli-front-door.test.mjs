import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  buildTargetRepo,
  commitAll,
  contractBytesOf,
  writeRepoFile
} from "./fixtures.mjs";

const root = new URL("..", import.meta.url);
const productEnv = {
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  TMPDIR: process.env.TMPDIR
};

function runCli(args, env = productEnv) {
  return spawnSync(process.execPath, ["src/cli.mjs", ...args], {
    cwd: root,
    encoding: "utf8",
    env,
    timeout: 180_000
  });
}

test("the default CLI probe uses the experimental launcher, not this working tree", () => {
  const probe = runCli(["--subject-probe"]);
  assert.equal(probe.status, 0, probe.stderr);
  const body = JSON.parse(probe.stdout);
  assert.equal(body.implementationStatus, "EXPERIMENTAL");
  assert.equal(body.promotionEntrypointAvailable, true);
});

test("--source-identity keeps the unauthenticated checkout FOUNDATION_ONLY", () => {
  const probe = runCli(["--source-identity", "--subject-probe"]);
  assert.equal(probe.status, 0, probe.stderr);
  const body = JSON.parse(probe.stdout);
  assert.equal(body.implementationStatus, "FOUNDATION_ONLY");
  assert.equal(body.promotionEntrypointAvailable, false);

  const status = runCli(["--source-identity", "status"]);
  assert.equal(status.status, 0, status.stderr);
  const report = JSON.parse(status.stdout);
  assert.equal(report.implementationStatus, "FOUNDATION_ONLY");
  assert.equal(report.promotionEntrypointAvailable, false);
});

test("default evaluate uses the experimental launcher and can return PROMOTABLE", () => {
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "conforming feature");
  const contractPath = join(mkdtempSync(join(tmpdir(), "shedu-front-door-")), "contract.json");
  writeFileSync(contractPath, contractBytesOf(target.contractFor(candidate)));
  const out = mkdtempSync(join(tmpdir(), "shedu-front-door-out-"));
  const evaluated = runCli([
    "evaluate",
    "--contract",
    contractPath,
    "--repo",
    target.repoDir,
    "--out",
    out
  ]);
  assert.equal(evaluated.status, 0, evaluated.stderr);
  const receipt = JSON.parse(evaluated.stdout);
  assert.equal(receipt.disposition, "PROMOTABLE", JSON.stringify(receipt.reasonCodes));
});
