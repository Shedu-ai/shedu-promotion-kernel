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

// Finding 3 remediation. The admission gate is now UNCONDITIONAL in the
// promotion worker — there is NO caller flag (SHEDU_REQUIRE_ADMISSION /
// requireAdmission) to disable it, and no CLI-side early check whose
// neutralization matters. The reviewer's reproduction (flip requireAdmission
// true->false, replace `if (!isAdmitted(admission))` with `if (false)`) is
// structurally impossible: the flag no longer exists, and stripping the CLI's
// admission plumbing cannot make the worker promote an unadmitted tree.
test("the admission caller-flag is gone and no CLI edit makes the worker promote an unadmitted tree", () => {
  const kernelRoot = new URL("..", import.meta.url).pathname;

  // Static: the disabling flag the reviewer flipped no longer exists anywhere.
  const supervisorSrc = readFileSync(join(kernelRoot, "src", "supervisor.mjs"), "utf8");
  const workerSrc = readFileSync(join(kernelRoot, "src", "worker-evaluate.mjs"), "utf8");
  assert.ok(!supervisorSrc.includes("requireAdmission"), "supervisor must not expose a requireAdmission flag");
  assert.ok(!/SHEDU_REQUIRE_ADMISSION/.test(supervisorSrc + workerSrc), "no caller-controlled admission env gate may exist");
  // The worker gate is unconditional: committedAdmission()/isAdmitted() with
  // no surrounding enabling condition.
  assert.ok(/committedAdmission\(\)/.test(workerSrc) && /if \(!isAdmitted\(admission\)\)/.test(workerSrc), "worker must gate unconditionally");

  // Dynamic: copy the tree, STRIP the CLI's admission plumbing entirely, and
  // confirm the worker still refuses (the copied tree is not a clean frozen
  // git checkout, so committedAdmission() -> FOUNDATION_ONLY -> NOT_ADMITTED).
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "shedu-bypass-")));
  for (const dir of ["src", "conformance", "registry", "packs", "schemas", "security"]) {
    cpSync(join(kernelRoot, dir), join(tmp, dir), { recursive: true });
  }
  cpSync(join(kernelRoot, "package.json"), join(tmp, "package.json"));
  const cliPath = join(tmp, "src", "cli.mjs");
  let cli = readFileSync(cliPath, "utf8");
  // Remove the propagation of admission material to the worker (simulate an
  // attacker gutting the CLI's admission handling).
  cli = cli.replace(/if \(att\) workerEnv\.SHEDU_ATTESTATION_FILE = att;/, "");
  writeFileSync(cliPath, cli);

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
  assert.equal(run.status, 2, run.stdout);
  assert.equal(JSON.parse(run.stderr).reasonCode, "NOT_ADMITTED");
});
