import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { digestOfBytes } from "./canonical-json.mjs";

// Control point: the hard whole-evaluation deadline supervisor with atomic
// bundle publication.
export const CONTROL_POINTS = Object.freeze(["evaluation-supervisor"]);

const WORKER = new URL("./worker-evaluate.mjs", import.meta.url).pathname;

function randomToken() {
  return `${process.pid}-${Math.floor(performance.now() * 1000)}-${Math.floor(Math.random() * 1e9)}`;
}

// Remove stale version dirs and any prior current bundle from the output
// directory. An earlier receipt is NEVER reused.
function purgeVersions(outDir) {
  let entries = [];
  try {
    entries = readdirSync(outDir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (name.startsWith(".v-") || name.startsWith(".current-") || name === "current") {
      rmSync(join(outDir, name), { recursive: true, force: true });
    }
  }
}

// Supervise the complete public evaluation path — ADMISSION, contract read,
// evaluation, signing, and bundling — in a separate worker process bounded by
// a HARD monotonic wall-clock deadline. The worker writes into a private
// version directory UNDER outDir (same filesystem) and marks it complete with
// a summary written LAST; the supervisor then publishes atomically by flipping
// the `current` symlink onto the completed version. The admission gate is
// enforced by the worker unconditionally (no caller flag). On timeout, worker
// failure, malformed summary, failed evaluation/admission, or signing failure,
// nothing is published and no `current` bundle remains.
export function evaluateSupervised({ repoDir, contractBytes, outDir, maxRuntimeSeconds, signKeyPath = null, workerEnv = {} }) {
  mkdirSync(outDir, { recursive: true });
  purgeVersions(outDir);

  const token = randomToken();
  const versionDir = join(outDir, `.v-${token}`);
  mkdirSync(versionDir, { recursive: true });
  const contractPath = join(versionDir, "work-contract.json");
  writeFileSync(contractPath, contractBytes);

  const env = { ...process.env, ...workerEnv };
  if (signKeyPath) env.SHEDU_SIGN_KEY_FILE = signKeyPath;

  const hardMs = maxRuntimeSeconds * 1000;
  const started = performance.now();
  const run = spawnSync(process.execPath, [WORKER, repoDir, contractPath, versionDir], {
    encoding: "utf8",
    timeout: hardMs,
    killSignal: "SIGKILL",
    env,
    windowsHide: true
  });
  const elapsedMs = Math.round(performance.now() - started);

  const abort = (outcome) => {
    rmSync(versionDir, { recursive: true, force: true });
    purgeVersions(outDir);
    return outcome;
  };

  const timedOut = run.error?.code === "ETIMEDOUT" || (run.signal === "SIGKILL" && elapsedMs >= hardMs - 50);
  if (timedOut) {
    return abort({ ok: true, supervised: true, timedOut: true, disposition: "BLOCKED", reasonCodes: ["DEADLINE_EXCEEDED"], elapsedMs });
  }

  const summaryPath = join(versionDir, "supervised-result.json");
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
    return abort({ ok: false, supervised: true, reasonCode: summary.reasonCode ?? "INFRASTRUCTURE_FAILURE", reasons: summary.reasons, elapsedMs });
  }

  // Verify the bundle is internally consistent before publishing.
  for (const [rel, digest] of Object.entries(summary.bundle ?? {})) {
    const p = join(versionDir, rel);
    if (!existsSync(p) || digestOfBytes(readFileSync(p)) !== digest) {
      return abort({ ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: `version bundle member ${rel} is missing or inconsistent`, elapsedMs });
    }
  }

  // ATOMIC publication: flip the `current` symlink onto the completed version
  // via a single rename (atomic on POSIX). No partial or cross-run bundle can
  // be observed under `current`.
  const pending = join(outDir, `.current-${token}`);
  try {
    symlinkSync(`.v-${token}`, pending);
    renameSync(pending, join(outDir, "current"));
  } catch (error) {
    rmSync(pending, { force: true });
    return abort({ ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: `atomic publish failed: ${String(error)}`, elapsedMs });
  }
  // Best-effort cleanup of superseded versions (never the just-published one).
  for (const name of readdirSync(outDir)) {
    if (name.startsWith(".v-") && name !== `.v-${token}`) {
      rmSync(join(outDir, name), { recursive: true, force: true });
    }
  }

  return { ...summary, supervised: true, timedOut: false, elapsedMs, outDir, currentDir: join(outDir, "current") };
}

// The published receipt path for a supervised output directory.
export function publishedReceiptPath(outDir) {
  return join(outDir, "current", "receipt.json");
}
export function publishedPlanPath(outDir) {
  return join(outDir, "current", "plan.json");
}
export function publishedEvidenceDir(outDir, artifactRoot) {
  return join(outDir, "current", artifactRoot.replace(/\/+$/, ""), "evidence");
}
