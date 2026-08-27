import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";

// Control point: the hard whole-evaluation deadline supervisor.
export const CONTROL_POINTS = Object.freeze(["evaluation-supervisor"]);

const WORKER = new URL("./worker-evaluate.mjs", import.meta.url).pathname;

// Supervise the complete public evaluation path in a separate worker process
// bounded by a HARD monotonic wall-clock deadline. The worker performs the
// whole evaluation (parse, authority resolution, materialization, execution,
// finalization); the supervisor SIGKILLs it at the deadline. A killed worker
// yields a deterministic DEADLINE_EXCEEDED / BLOCKED result and NO promotable
// or partially-trusted receipt — the final receipt.json is written only after
// the worker completes reduction, and the supervisor never treats a partial
// tree as promotable.
//
// The contract's maxRuntimeSeconds is the WHOLE-EVALUATION ceiling. An
// internal cooperative deadline (in evaluate.mjs) still bounds each command
// and produces detailed skip evidence; this supervisor is the outer hard
// bound that catches a runaway synchronous control the cooperative deadline
// cannot interrupt.
export function evaluateSupervised({ repoDir, contractBytes, outDir, maxRuntimeSeconds, workerEnv = {} }) {
  mkdirSync(outDir, { recursive: true });
  const contractPath = join(tmpdir(), `shedu-supervised-contract-${process.pid}-${performance.now().toString().replace(".", "")}.json`);
  writeFileSync(contractPath, contractBytes);
  const summaryPath = join(outDir, "supervised-result.json");
  if (existsSync(summaryPath)) rmSync(summaryPath, { force: true });

  const hardMs = maxRuntimeSeconds * 1000;
  const started = performance.now();
  const run = spawnSync(process.execPath, [WORKER, repoDir, contractPath, outDir], {
    encoding: "utf8",
    timeout: hardMs,
    killSignal: "SIGKILL",
    env: { PATH: process.env.PATH, ...workerEnv },
    windowsHide: true
  });
  const elapsedMs = Math.round(performance.now() - started);
  rmSync(contractPath, { force: true });

  const timedOut = run.error?.code === "ETIMEDOUT" || (run.signal === "SIGKILL" && elapsedMs >= hardMs - 50);
  if (timedOut) {
    // Hard deadline hit: deterministic machine failure, never promotable.
    // Any partial receipt the worker may have written is not trusted.
    rmSync(join(outDir, "receipt.json"), { force: true });
    return {
      ok: true,
      supervised: true,
      timedOut: true,
      disposition: "BLOCKED",
      reasonCodes: ["DEADLINE_EXCEEDED"],
      elapsedMs
    };
  }

  if (run.status !== 0 || !existsSync(summaryPath)) {
    return { ok: false, supervised: true, reasonCode: "INFRASTRUCTURE_FAILURE", message: run.stderr?.slice(0, 500) ?? "worker did not complete", elapsedMs };
  }

  const summary = JSON.parse(readFileSync(summaryPath, "utf8"));
  return { ...summary, supervised: true, timedOut: false, elapsedMs };
}
