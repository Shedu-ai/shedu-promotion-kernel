import { performance } from "node:perf_hooks";

// Control point: the evaluation-wide deadline is a monotonic absolute bound
// (perf_hooks.performance.now(), not wall-clock Date.now(), so a clock step
// cannot extend or collapse it). Every validator and every command execution
// is bounded by the REMAINING budget, and once the budget is exhausted no
// further command may run and no late-finishing result may be recorded PASS.
export const CONTROL_POINTS = Object.freeze(["evaluation-deadline"]);

export function createDeadline(totalMs) {
  if (!Number.isFinite(totalMs) || totalMs <= 0) {
    throw new Error("deadline requires a positive millisecond budget");
  }
  const start = performance.now();
  const end = start + totalMs;
  return {
    totalMs,
    remainingMs() {
      return Math.max(0, Math.round(end - performance.now()));
    },
    expired() {
      return performance.now() >= end;
    },
    // Elapsed since the deadline was created, for post-hoc PASS suppression.
    elapsedMs() {
      return Math.round(performance.now() - start);
    }
  };
}
