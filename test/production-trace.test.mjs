import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { evaluateCandidate } from "../src/evaluate.mjs";
import {
  buildTargetRepo,
  commitAll,
  contractBytesOf,
  kernelSelectablePack,
  writeRepoFile
} from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-trace-"));

test("a genuine evaluation binds a production control trace covering the engaged controls", () => {
  // Full surface: mandatory packs + a target-command pack, so sandbox +
  // toolchain + output controls genuinely engage.
  const gate = {
    schemaVersion: "policy-pack@1",
    packId: "gate-pack",
    version: "1.0.0",
    description: "target gate",
    phases: ["CANDIDATE_VALIDATION"],
    dependencies: [],
    checks: [
      {
        checkId: "gate-check",
        phase: "CANDIDATE_VALIDATION",
        effect: "ADVISORY",
        validator: { kind: "TARGET_COMMAND", argv: ["node", "-e", "process.exit(0)"], inputManifest: [] },
        inputs: [],
        outputSchemaId: "check-result@1",
        timeoutSeconds: 60,
        network: "NONE",
        filesystem: "READ_ONLY",
        envAllowlist: [],
        resultConsumer: "DISPOSITION_REDUCER"
      }
    ]
  };
  const target = buildTargetRepo({ targetPacks: [gate] });
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: outDir()
  });
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));

  // The trace is bound in the receipt and records ACTUAL engagements.
  const traced = new Set(outcome.receipt.controlTrace.map((e) => e.controlId));
  for (const id of [
    "contract-authorization",
    "git-authority",
    "evaluation-deadline",
    "artifact-root-enforcement",
    "phase-scheduled-execution",
    "toolchain-authority",
    "sandbox-network-isolation",
    "sandbox-read-isolation",
    "sandbox-write-isolation",
    "sandbox-process-ceiling",
    "command-output-ceiling",
    "containment-halt-routing",
    "evidence-artifact-ceiling",
    "disposition-reduction"
  ]) {
    assert.ok(traced.has(id), `production trace must record ${id}`);
  }
  // The reducer event records the actual disposition.
  const reduction = outcome.receipt.controlTrace.find((e) => e.controlId === "disposition-reduction");
  assert.equal(reduction.outcome, outcome.receipt.disposition);
});

test("a containment halt is recorded as FIRED in the production trace", () => {
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "policy/profile.json", '{"weakened":true}\n');
  const candidate = commitAll(target.repoDir, "forbidden rewrite");
  const outcome = evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: outDir()
  });
  const halt = outcome.receipt.controlTrace.find((e) => e.controlId === "containment-halt-routing");
  assert.equal(halt.outcome, "FIRED");
});

// The exact reproduced bypass: replacing the CLI admission check with
// `if (false)` must NOT grant promotion, because the production worker
// re-enforces admission independently.
test("replacing the CLI admission check with if(false) does not bypass admission", () => {
  const kernelRoot = new URL("..", import.meta.url).pathname;
  // Real-path the staging dir so the copied CLI's import.meta.url main-guard
  // matches process.argv[1] (macOS /var -> /private/var symlink otherwise
  // silently prevents main() from running).
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "shedu-bypass-")));
  for (const dir of ["src", "conformance", "registry", "packs", "schemas"]) {
    cpSync(join(kernelRoot, dir), join(tmp, dir), { recursive: true });
  }
  cpSync(join(kernelRoot, "package.json"), join(tmp, "package.json"));

  // Patch the CLI: neutralize the early admission gate.
  const cliPath = join(tmp, "src", "cli.mjs");
  let cli = readFileSync(cliPath, "utf8");
  cli = cli.replace("if (!isAdmitted(admission)) {", "if (false) {");
  assert.ok(cli.includes("if (false) {"), "the bypass patch must apply");
  writeFileSync(cliPath, cli);

  // Build a target repo + contract to evaluate.
  const target = buildTargetRepo();
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const f = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  const contractPath = join(mkdtempSync(join(tmpdir(), "shedu-c-")), "contract.json");
  writeFileSync(contractPath, contractBytesOf(target.contractFor(candidate)));

  const run = spawnSync(
    process.execPath,
    [cliPath, "evaluate", "--contract", contractPath, "--repo", target.repoDir, "--out", outDir()],
    { encoding: "utf8", env: { PATH: process.env.PATH } }
  );
  // The worker's independent admission gate refuses: no promotion despite the
  // neutralized CLI check.
  assert.equal(run.status, 2, run.stdout);
  assert.equal(JSON.parse(run.stderr).reasonCode, "NOT_ADMITTED");
});
