import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, readlinkSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { digestOfBytes } from "./canonical-json.mjs";

// Control point: the hard whole-evaluation deadline supervisor with atomic
// bundle publication.
export const CONTROL_POINTS = Object.freeze(["evaluation-supervisor"]);

const WORKER = new URL("./worker-evaluate.mjs", import.meta.url).pathname;
const OPERATION_CLOCKS = new WeakMap();

// Start the whole-operation clock before CLI prework without exposing a
// caller-settable timestamp. Only a module-branded token can carry an earlier
// start into evaluateSupervised; invented objects start at the call boundary.
export function beginSupervisedOperation() {
  const token = Object.freeze({});
  OPERATION_CLOCKS.set(token, performance.now());
  return token;
}

// Read-only remaining-budget projection for CLI finalization. The start time
// is kept in the module-private WeakMap, so a caller cannot invent or rewind
// it. This lets optional stdout presentation remain inside the same hard
// operation budget without exposing a mutable timestamp.
export function remainingSupervisedOperationMs(operationClock, maxRuntimeSeconds) {
  const started = OPERATION_CLOCKS.get(operationClock);
  if (started === undefined || !Number.isSafeInteger(maxRuntimeSeconds) || maxRuntimeSeconds < 1) return 0;
  return Math.max(0, Math.floor(maxRuntimeSeconds * 1000 - (performance.now() - started)));
}

function randomToken() {
  return `${process.pid}-${randomBytes(16).toString("hex")}`;
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

// Same-output publication is serialized with an atomic symlink lock. A
// second live publisher fails deterministically; it never deletes another
// run's staging directory or current pointer. A lock whose owning process is
// demonstrably gone is mechanically reclaimed, so a crashed supervisor does
// not leave a permanent operational orphan. The owner is encoded in the
// symlink payload, so there is no mkdir/write crash window that can create an
// ownerless lock.
function acquireOutputLock(outDir, token) {
  const lockPath = join(outDir, ".promotion-lock");
  const ownerValue = `${process.pid}:${token}`;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      symlinkSync(ownerValue, lockPath);
      return {
        acquired: true,
        release() {
          try {
            const observed = readlinkSync(lockPath);
            if (observed !== ownerValue) throw new Error("promotion output lock ownership changed before release");
            unlinkSync(lockPath);
          } catch (error) {
            if (error?.code === "ENOENT") return;
            // Never silently report success while leaving an operational lock
            // orphan or deleting another publisher's lock.
            throw error;
          }
        }
      };
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      let ownerPid = null;
      try {
        const match = /^(\d+):/.exec(readlinkSync(lockPath));
        if (match) ownerPid = Number(match[1]);
      } catch {
        return { acquired: false, reasonCode: "OUTPUT_BUSY" };
      }
      if (ownerPid === null || processIsAlive(ownerPid)) return { acquired: false, reasonCode: "OUTPUT_BUSY" };
      const stale = join(outDir, `.stale-lock-${token}`);
      try {
        renameSync(lockPath, stale);
        unlinkSync(stale);
      } catch {
        return { acquired: false, reasonCode: "OUTPUT_BUSY" };
      }
    }
  }
  return { acquired: false, reasonCode: "OUTPUT_BUSY" };
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
export function evaluateSupervised({ repoDir, contractBytes, outDir, maxRuntimeSeconds, signKeyPath = null, workerEnv = {}, operationClock = null }) {
  const hardMs = maxRuntimeSeconds * 1000;
  const started = OPERATION_CLOCKS.get(operationClock) ?? performance.now();
  const elapsed = () => Math.round(performance.now() - started);
  mkdirSync(outDir, { recursive: true });
  const token = randomToken();
  const lock = acquireOutputLock(outDir, token);
  if (!lock.acquired) {
    return { ok: false, supervised: true, reasonCode: lock.reasonCode, message: "another promotion is publishing to this output directory", elapsedMs: elapsed() };
  }

  try {
    purgeVersions(outDir);
    const versionDir = join(outDir, `.v-${token}`);
    mkdirSync(versionDir, { recursive: true });
    const contractPath = join(versionDir, "work-contract.json");
    writeFileSync(contractPath, contractBytes);

    const abort = (outcome) => {
      rmSync(versionDir, { recursive: true, force: true });
      purgeVersions(outDir);
      return outcome;
    };

    const beforeWorkerMs = elapsed();
    if (beforeWorkerMs >= hardMs) {
      return abort({ ok: true, supervised: true, timedOut: true, disposition: "BLOCKED", reasonCodes: ["DEADLINE_EXCEEDED"], elapsedMs: beforeWorkerMs });
    }

    // Construct the worker environment; never inherit unrelated ambient
    // credentials or test controls implicitly.
    const env = { PATH: process.env.PATH ?? "", ...workerEnv };
    if (signKeyPath) env.SHEDU_SIGN_KEY_FILE = signKeyPath;

    const run = spawnSync(process.execPath, [WORKER, repoDir, contractPath, versionDir], {
      encoding: "utf8",
      timeout: Math.max(1, hardMs - beforeWorkerMs),
      killSignal: "SIGKILL",
      env,
      windowsHide: true
    });
    const elapsedMs = elapsed();

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

    // Verify the exact required bundle before publishing; a worker cannot make
    // an empty or partial manifest authoritative.
    const requiredBundle = ["receipt.json", "plan.json", join("artifacts", "evidence", "index.json")];
    if (
      summary.bundle === null ||
      typeof summary.bundle !== "object" ||
      Object.keys(summary.bundle).sort().join("\0") !== [...requiredBundle].sort().join("\0")
    ) {
      return abort({ ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: "worker returned an incomplete or unexpected bundle manifest", elapsedMs });
    }
    for (const [rel, digest] of Object.entries(summary.bundle)) {
      const p = join(versionDir, rel);
      if (!existsSync(p) || digestOfBytes(readFileSync(p)) !== digest) {
        return abort({ ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: `version bundle member ${rel} is missing or inconsistent`, elapsedMs });
      }
    }
    if (elapsed() >= hardMs) {
      return abort({ ok: true, supervised: true, timedOut: true, disposition: "BLOCKED", reasonCodes: ["DEADLINE_EXCEEDED"], elapsedMs: elapsed() });
    }

    // ATOMIC publication: flip the `current` symlink onto the completed version
    // via a single rename (atomic on POSIX). The output lock prevents another
    // publisher from deleting or replacing this run while it finalizes.
    const pending = join(outDir, `.current-${token}`);
    try {
      symlinkSync(`.v-${token}`, pending);
      renameSync(pending, join(outDir, "current"));
    } catch (error) {
      rmSync(pending, { force: true });
      return abort({ ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: `atomic publish failed: ${String(error)}`, elapsedMs: elapsed() });
    }
    if (elapsed() >= hardMs) {
      return abort({ ok: true, supervised: true, timedOut: true, disposition: "BLOCKED", reasonCodes: ["DEADLINE_EXCEEDED"], elapsedMs: elapsed() });
    }

    return { ...summary, supervised: true, timedOut: false, elapsedMs: elapsed(), outDir, currentDir: join(outDir, "current") };
  } finally {
    lock.release();
  }
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
