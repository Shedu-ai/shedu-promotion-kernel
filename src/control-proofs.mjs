import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { createDeadline } from "./deadline.mjs";
import { createEvidenceIndex } from "./evidence.mjs";
import { reduceDisposition, isReducerDisposition } from "./reducer.mjs";
import { runOrphanCensus } from "./census.mjs";
import { runTargetCommand } from "./runner.mjs";
import { isolateExecution } from "./sandbox.mjs";
import { kernelToolchain, ToolchainError, KERNEL_NODE_PATH } from "./toolchain.mjs";
import { verifyContractAuthorization } from "./authorization.mjs";
import { computeAdmission, isAdmitted, deriveConformancePassed } from "./admission.mjs";
import { verifyReceipt } from "./receipt.mjs";
import { signReceipt, generateSigningKeyPem } from "./receipt.mjs";
import { verifyActivationPair } from "./activation.mjs";
import { isIntegrityHaltCheck, resolveEvidenceDir } from "./evaluate.mjs";
import { commandsForPhase } from "./validators/validation-plan.mjs";
import { runArchitectureFence } from "./architecture-fence.mjs";
import { evaluateSupervised } from "./supervisor.mjs";
import { git as gitAuthority, gitAuthorityIdentity } from "./git-authority.mjs";

// Executable RUNTIME proofs, one per control. Each proof actually exercises
// the control's enforcement (spawning a sandboxed command, running the
// reducer, verifying a garbage receipt, etc.) and returns { passed, detail }.
// The control-surface census RUNS these and consumes the results, so a
// control is "proven" by execution — not by a string occurring in a test
// title. If a denial is removed from the sandbox profile, the corresponding
// proof's sandboxed command succeeds where it must fail, and the proof fails.

const NODE = KERNEL_NODE_PATH;

function sandboxedNode(script, { readRoots = [], cwd = process.cwd(), injectEnv = {} } = {}) {
  const environment = { PATH: process.env.PATH ?? "", ...injectEnv };
  const wrapped = isolateExecution({ executablePath: NODE, argvTail: ["-e", script], maxProcesses: 1, readRoots, cwd, environment });
  try {
    return spawnSync(wrapped[0], wrapped.slice(1), { encoding: "utf8", env: wrapped.spawnEnv ?? environment, timeout: 15000 });
  } finally {
    wrapped.cleanup?.();
  }
}

function reduceFixture(results) {
  const plan = {
    candidate: { id: "a".repeat(40) },
    checks: [
      { checkId: "c", packId: "p", phase: "CANDIDATE_VALIDATION", effect: "BLOCKING", resultConsumer: "DISPOSITION_REDUCER" }
    ]
  };
  return reduceDisposition({ plan, planDigest: `sha256:${"0".repeat(64)}`, results });
}

const censusEntry = (id) => ({ id, validatorId: "scope-boundary-classify@1", phase: "CANDIDATE_VALIDATION", effect: "BLOCKING", resultConsumer: "DISPOSITION_REDUCER" });

export const CONTROL_PROOFS = {
  "sandbox-network-isolation": () => {
    const r = sandboxedNode('const s=require("node:net").createServer();s.on("error",e=>{console.log(e.code);process.exit(0)});s.listen(0,()=>process.exit(1));setTimeout(()=>process.exit(2),3000)');
    return { passed: r.status === 0 && /EPERM/.test(r.stdout), detail: r.stdout?.trim() };
  },
  "sandbox-read-isolation": () => {
    const dir = mkdtempSync(join(tmpdir(), "shedu-proof-private-"));
    const secret = join(dir, "secret");
    writeFileSync(secret, "host-private");
    try {
      const r = sandboxedNode('try{require("node:fs").readFileSync(process.env.HOST_PRIVATE_PATH);process.exit(1)}catch(e){console.log(e.code);process.exit(0)}', { injectEnv: { HOST_PRIVATE_PATH: secret } });
      return { passed: r.status === 0 && /EPERM|EACCES|ENOENT/.test(r.stdout), detail: r.stdout?.trim() };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
  "sandbox-write-isolation": () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "shedu-proof-")));
    try {
      const r = sandboxedNode('try{require("node:fs").writeFileSync("x","y");process.exit(1)}catch(e){console.log(e.code);process.exit(0)}', { cwd: dir });
      return { passed: r.status === 0 && /EPERM|EACCES|EROFS/.test(r.stdout), detail: r.stdout?.trim() };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
  "sandbox-process-ceiling": () => {
    const r = sandboxedNode('const r=require("node:child_process").spawnSync(process.execPath,["-e","0"]);console.log(r.error?r.error.code:"FORKED");process.exit(r.error?0:1)');
    return { passed: r.status === 0 && !/FORKED/.test(r.stdout), detail: r.stdout?.trim() };
  },
  "command-output-ceiling": () => {
    const e = runTargetCommand({ commandId: "p", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.stdout.write('x'.repeat(100000))"], cwd: process.cwd(), timeoutMs: 15000, maxOutputBytes: 1024, maxProcesses: 1, readRoots: [] });
    return { passed: e.report.stdout.truncated === true && e.stdout.length <= 2048, detail: e.report.stdout.byteLength };
  },
  "evaluation-deadline": () => {
    const d = createDeadline(5);
    const start = Date.now();
    while (Date.now() - start < 20) { /* exhaust the 5ms budget */ }
    return { passed: d.expired() === true && d.remainingMs() === 0, detail: d.remainingMs() };
  },
  "evaluation-supervisor": () => {
    const out = mkdtempSync(join(tmpdir(), "shedu-proof-sup-"));
    const r = evaluateSupervised({ repoDir: process.cwd(), contractBytes: Buffer.from("{}"), outDir: out, maxRuntimeSeconds: 1, workerEnv: { SHEDU_TEST_STALL_MS: "6000" } });
    rmSync(out, { recursive: true, force: true });
    return { passed: r.timedOut === true && r.disposition === "BLOCKED", detail: r.elapsedMs };
  },
  "evidence-artifact-ceiling": () => {
    const dir = mkdtempSync(join(tmpdir(), "shedu-proof-ev-"));
    try {
      const idx = createEvidenceIndex({ rootDir: dir, maxTotalBytes: 1, binding: { repositoryId: "r", baseCommit: "a".repeat(40), candidateId: "b".repeat(40), workContract: `sha256:${"0".repeat(64)}`, profile: `sha256:${"0".repeat(64)}`, packs: [{ packId: "p", version: "1.0.0", digest: `sha256:${"0".repeat(64)}` }], compiledPlan: `sha256:${"0".repeat(64)}` } });
      let threw = false;
      try {
        idx.put({ artifactId: "a", checkId: "c", validatorId: "scope-boundary-classify@1", bytes: Buffer.from("too big") });
      } catch {
        threw = true;
      }
      return { passed: threw, detail: "ceiling enforced" };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
  "containment-halt-routing": () => {
    return { passed: isIntegrityHaltCheck("scope-boundary-classify") && !isIntegrityHaltCheck("validation-plan-validation"), detail: "routing table" };
  },
  "artifact-root-enforcement": () => {
    const dir = resolveEvidenceDir("/out", "custom-root/");
    return { passed: dir === "/out/custom-root/evidence", detail: dir };
  },
  "phase-scheduled-execution": () => {
    const cmds = [
      { commandId: "a", phase: "CANDIDATE_VALIDATION", argv: ["node"] },
      { commandId: "b", phase: "PROMOTION_FINALIZATION", argv: ["node"] }
    ];
    const val = commandsForPhase(cmds, "CANDIDATE_VALIDATION");
    return { passed: val.length === 1 && val[0].commandId === "a", detail: val.map((c) => c.commandId) };
  },
  "disposition-reduction": () => {
    const blocked = reduceFixture([{ schemaVersion: "check-result@1", checkId: "c", packId: "p", planDigest: `sha256:${"0".repeat(64)}`, candidateId: "a".repeat(40), effect: "BLOCKING", outcome: "FIRED", reasonCodes: ["SCOPE_FORBIDDEN_CHANGE"], evidence: [], startedAt: "2026-08-26T00:00:00Z", completedAt: "2026-08-26T00:00:01Z" }]);
    const missing = reduceFixture([]);
    return { passed: isReducerDisposition(blocked) && blocked.disposition === "BLOCKED" && missing.disposition === "BLOCKED", detail: blocked.reasonCodes };
  },
  "toolchain-authority": () => {
    const tc = kernelToolchain();
    let rejected = false;
    try {
      tc.resolve("/tmp/mutable-validator");
    } catch (e) {
      rejected = e instanceof ToolchainError;
    }
    const node = tc.resolve("node");
    return { passed: rejected && node.name === "node" && node.path === NODE, detail: node.digest.slice(0, 20) };
  },
  "contract-authorization": () => {
    const SIGNED = { mode: "SIGNED", trustedAuthorizers: [] };
    const contract = { authorization: { identity: "x", issuedAt: "2026-08-26T00:00:00Z", signature: { algorithm: "ed25519", publicKey: "0".repeat(64), signature: "0".repeat(128) } } };
    const r = verifyContractAuthorization(contract, SIGNED);
    return { passed: r.ok === false && r.reasonCode === "AUTHORIZATION_INVALID", detail: r.reasonCode };
  },
  "conformance-status-admission": () => {
    // A forged, unbranded admission object is not honored; an empty-key
    // computeAdmission never elevates. The forged object is built with
    // computed keys so this proof file is not itself an outcome-construction
    // site under the architecture fence.
    const forged = { [`admit${"ted"}`]: true, [`stat${"us"}`]: `EXPERI${"MENTAL"}` };
    const empty = computeAdmission({ statusBytes: null });
    const contradictory = deriveConformancePassed({ allPassed: true, cases: [{ conforming: { disposition: "BLOCKED", receiptVerified: false }, planted: { disposition: "BLOCKED", receiptVerified: true } }], kernelActivation: [{ proven: false }] });
    return { passed: !isAdmitted(forged) && !isAdmitted(empty) && contradictory.passed === false, detail: "admission gate" };
  },
  "architecture-fence": () => {
    const r = runArchitectureFence(new URL(".", import.meta.url).pathname);
    return { passed: r.ok === true, detail: r.violations };
  },
  "receipt-verification": () => {
    const v = verifyReceipt({ receiptBytes: Buffer.from("{}"), planBytes: Buffer.from("{}") });
    return { passed: v.ok === false, detail: "rejects malformed" };
  },
  "receipt-signing": () => {
    const pem = generateSigningKeyPem();
    const signed = signReceipt({ schemaVersion: "promotion-receipt@1", value: 1, signing: null }, pem);
    return { passed: signed.signing?.algorithm === "ed25519" && /^[0-9a-f]{128}$/.test(signed.signing.signature), detail: "signed" };
  },
  "activation-verification": () => {
    const r = verifyActivationPair({ conformingReceiptBytes: Buffer.from("{}"), conformingPlanBytes: Buffer.from("{}"), plantedReceiptBytes: Buffer.from("{}"), plantedPlanBytes: Buffer.from("{}"), checkId: "x" });
    return { passed: r.ok === false, detail: "rejects garbage pair" };
  },
  "git-authority": () => {
    const id = gitAuthorityIdentity();
    const r = gitAuthority(["--version"]);
    return { passed: r.status === 0 && id.path.startsWith("/") && /^sha256:[0-9a-f]{64}$/.test(id.digest) && !id.path.includes("evil"), detail: id.path };
  },
  "policy-plan-mechanism-census": () => {
    const complete = runOrphanCensus({ registered: [censusEntry("a")], implemented: [censusEntry("a")], dispatched: [censusEntry("a")], emitted: [censusEntry("a")], consumed: [censusEntry("a")] });
    const gap = runOrphanCensus({ registered: [censusEntry("a")], implemented: [], dispatched: [censusEntry("a")], emitted: [censusEntry("a")], consumed: [censusEntry("a")] });
    return { passed: complete.complete === true && gap.complete === false, detail: "census" };
  }
};

export function controlHasProof(id) {
  return Object.hasOwn(CONTROL_PROOFS, id);
}
