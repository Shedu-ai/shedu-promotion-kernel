import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { digestOfBytes } from "./canonical-json.mjs";

// Control point: the hard whole-evaluation deadline supervisor with atomic
// bundle publication.
export const CONTROL_POINTS = Object.freeze(["evaluation-supervisor"]);

const WORKER = new URL("./worker-evaluate.mjs", import.meta.url).pathname;

// Remove any current promotable/evaluation artifacts from the caller's output
// directory. An earlier receipt is NEVER reused: it is purged before we either
// publish a fresh bundle or fail.
function purgeOutput(outDir) {
  for (const rel of ["receipt.json", "plan.json", "supervised-result.json", "artifacts"]) {
    rmSync(join(outDir, rel), { recursive: true, force: true });
  }
}

// Supervise the complete public evaluation path AND finalization (signing,
// bundling) in a separate worker process bounded by a HARD monotonic
// wall-clock deadline. The worker evaluates into a private STAGING directory
// and writes its summary LAST; the supervisor publishes the staging bundle to
// the caller's outDir ONLY after a clean exit and a verified summary+bundle.
// On timeout, worker failure, malformed summary, a failed evaluation, or a
// signing failure, nothing is published and no promotable receipt remains.
export function evaluateSupervised({ repoDir, contractBytes, outDir, maxRuntimeSeconds, signKeyPath = null, requireAdmission = false, workerEnv = {} }) {
  mkdirSync(outDir, { recursive: true });
  // Never reuse an earlier receipt: purge the destination up front.
  purgeOutput(outDir);

  const staging = mkdtempSync(join(tmpdir(), "shedu-staging-"));
  const contractPath = join(staging, "work-contract.json");
  writeFileSync(contractPath, contractBytes);

  const env = { PATH: process.env.PATH, ...workerEnv };
  if (signKeyPath) env.SHEDU_SIGN_KEY_FILE = signKeyPath;
  // On the promotion entrypoint, the worker re-enforces admission itself.
  if (requireAdmission) env.SHEDU_REQUIRE_ADMISSION = "1";

  const hardMs = maxRuntimeSeconds * 1000;
  const started = performance.now();
  const run = spawnSync(process.execPath, [WORKER, repoDir, contractPath, staging], {
    encoding: "utf8",
    timeout: hardMs,
    killSignal: "SIGKILL",
    env,
    windowsHide: true
  });
  const elapsedMs = Math.round(performance.now() - started);

  const abort = (outcome) => {
    rmSync(staging, { recursive: true, force: true });
    purgeOutput(outDir);
    return outcome;
  };

  const timedOut = run.error?.code === "ETIMEDOUT" || (run.signal === "SIGKILL" && elapsedMs >= hardMs - 50);
  if (timedOut) {
    return abort({ ok: true, supervised: true, timedOut: true, disposition: "BLOCKED", reasonCodes: ["DEADLINE_EXCEEDED"], elapsedMs });
  }

  const summaryPath = join(staging, "supervised-result.json");
  if (run.status !== 0 || !existsSync(summaryPath)) {
    return abort({ ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: run.stderr?.slice(0, 500) ?? "worker did not complete", elapsedMs });
  }

  let summary;
  try {
    summary = JSON.parse(readFileSync(summaryPath, "utf8"));
  } catch {
    return abort({ ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: "malformed supervised summary", elapsedMs });
  }

  if (summary.ok !== true) {
    return abort({ ok: false, supervised: true, reasonCode: summary.reasonCode ?? "INFRASTRUCTURE_FAILURE", elapsedMs });
  }

  // Verify the bundle is internally consistent before publishing.
  for (const [rel, digest] of Object.entries(summary.bundle ?? {})) {
    const p = join(staging, rel);
    if (!existsSync(p) || digestOfBytes(readFileSync(p)) !== digest) {
      return abort({ ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: `staging bundle member ${rel} is missing or inconsistent`, elapsedMs });
    }
  }

  // Atomic-ish publication: purge the destination, then copy the verified
  // bundle members. (The purge above already ran; repeat defensively.)
  purgeOutput(outDir);
  for (const rel of Object.keys(summary.bundle)) {
    const src = join(staging, rel);
    const dest = join(outDir, rel);
    mkdirSync(join(dest, ".."), { recursive: true });
    cpSync(src, dest);
  }
  // Copy the whole artifacts tree (evidence objects), not just index.json.
  if (existsSync(join(staging, "artifacts"))) {
    cpSync(join(staging, "artifacts"), join(outDir, "artifacts"), { recursive: true });
  }
  const published = { ...summary, supervised: true, timedOut: false, elapsedMs, outDir };
  rmSync(staging, { recursive: true, force: true });
  return published;
}
