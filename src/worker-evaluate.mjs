import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import { evaluateCandidate } from "./evaluate.mjs";

// Worker process for the hard-deadline supervisor. It performs the COMPLETE
// evaluation (authority resolution, materialization, execution, reduction,
// receipt construction) so the supervisor's outer wall-clock bound covers the
// whole public evaluation path. It writes a compact result to
// <outDir>/supervised-result.json and exits.

// Supervisor test seam: a synchronous stall that ignores the cooperative
// deadline, used to prove the OUTER supervisor bound hard-kills a runaway
// synchronous control. Guarded by an env var only tests set.
const stallMs = Number(process.env.SHEDU_TEST_STALL_MS ?? "0");
if (Number.isFinite(stallMs) && stallMs > 0) {
  const until = Date.now() + stallMs;
  while (Date.now() < until) {
    // busy-wait; a hard external kill is the only thing that stops this.
  }
}

const [repoDir, contractPath, outDir] = process.argv.slice(2);
const contractBytes = readFileSync(contractPath);
const outcome = evaluateCandidate({ repoDir, contractBytes, outDir });

const summary = outcome.ok
  ? {
      ok: true,
      disposition: outcome.receipt.disposition,
      reasonCodes: outcome.receipt.reasonCodes,
      receiptDigest: outcome.receiptDigest,
      evaluationDigest: outcome.evaluationDigest
    }
  : { ok: false, reasonCode: outcome.reasonCode };
writeFileSync(join(outDir, "supervised-result.json"), Buffer.from(JSON.stringify(summary), "utf8"));
process.exit(0);
