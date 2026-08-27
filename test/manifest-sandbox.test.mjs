import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { buildTargetRepo, commitAll, contractBytesOf, writeRepoFile } from "./fixtures.mjs";

const outDir = () => mkdtempSync(join(tmpdir(), "shedu-manifest-"));

// A target-command pack whose tool tries to read a BASE file. `manifest`
// controls which base files the validator declares (and the sandbox grants).
function probePack(manifest) {
  return {
    schemaVersion: "policy-pack@1",
    packId: "probe-pack",
    version: "1.0.0",
    description: "reads a base file",
    phases: ["CANDIDATE_VALIDATION"],
    dependencies: [],
    checks: [
      {
        checkId: "probe-check",
        phase: "CANDIDATE_VALIDATION",
        effect: "BLOCKING",
        validator: {
          kind: "TARGET_COMMAND",
          // Reads tools/secret-data.txt from BASE (cwd = base worktree).
          argv: ["node", "tools/probe.cjs"],
          inputManifest: manifest
        },
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
}

const PROBE_TOOL =
  'try{const d=require("node:fs").readFileSync(require("node:path").join(process.cwd(),"tools","secret-data.txt"),"utf8");console.log("READ:"+d.trim());process.exit(0)}catch(e){console.error("BLOCKED:"+e.code);process.exit(1)}';

function build(manifest) {
  const target = buildTargetRepo({
    targetPacks: [probePack(manifest)],
    extraBaseFiles: {
      "tools/probe.cjs": PROBE_TOOL,
      "tools/secret-data.txt": "UNDECLARED_BASE_SECRET\n"
    }
  });
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const f = 2;\n");
  const candidate = commitAll(target.repoDir, "feature");
  return evaluateCandidate({
    repoDir: target.repoDir,
    contractBytes: contractBytesOf(target.contractFor(candidate)),
    outDir: outDir()
  });
}

test("a target validator cannot read a base file it did not declare in its manifest", () => {
  // Manifest declares only the tool, NOT secret-data.txt: the read is denied
  // and the check FIREs.
  const outcome = build(["tools/probe.cjs"]);
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "BLOCKED");
  const probe = outcome.receipt.checkResults.find((r) => r.checkId === "probe-check");
  assert.equal(probe.outcome, "FIRED");
  assert.deepEqual(probe.reasonCodes, ["COMMAND_FAILED"]);
});

test("a target validator CAN read a base file it declared in its manifest", () => {
  // Manifest declares both the tool and the data file: the read succeeds.
  const outcome = build(["tools/probe.cjs", "tools/secret-data.txt"]);
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors ?? []));
  assert.equal(outcome.receipt.disposition, "PROMOTABLE", JSON.stringify(outcome.receipt.reasonCodes));
  const probe = outcome.receipt.checkResults.find((r) => r.checkId === "probe-check");
  assert.equal(probe.outcome, "PASS");
});
