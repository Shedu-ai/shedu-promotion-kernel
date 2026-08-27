import { readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { evaluateCandidate } from "./evaluate.mjs";
import { signReceipt } from "./receipt.mjs";
import { committedAdmission, isAdmitted } from "./admission.mjs";

// Worker process for the hard-deadline supervisor. It performs the COMPLETE
// evaluation AND all promotion finalization (receipt signing, bundle
// manifesting) INSIDE the supervised boundary, into a private STAGING
// directory. The supervisor publishes the bundle to the caller's output only
// after the worker exits cleanly and the summary+bundle verify. The summary
// (supervised-result.json) is written LAST, so a worker killed before that
// point publishes nothing.

// Supervisor test seams (guarded by env vars only tests set): a stall before
// evaluation, and a stall AFTER the receipt is constructed but BEFORE the
// summary is published.
function stall(ms) {
  const n = Number(ms ?? "0");
  if (Number.isFinite(n) && n > 0) {
    const until = Date.now() + n;
    while (Date.now() < until) {
      // busy-wait; only a hard external kill stops this.
    }
  }
}

stall(process.env.SHEDU_TEST_STALL_MS);

const [repoDir, contractPath, staging] = process.argv.slice(2);

// AUTHORITATIVE admission gate. This is the promotion worker; it ALWAYS
// enforces admission from the externally-supplied evidence, with NO caller
// flag to disable it. Admission (including the bounded attestation read)
// runs INSIDE the supervised deadline, so a blocking/FIFO attestation is
// killed by the supervisor rather than hanging. To bypass admission an
// attacker must edit this production gate directly — and a frozen-commit
// attestation will not admit an edited tree.
const admission = committedAdmission();
if (!isAdmitted(admission)) {
  writeFileSync(join(staging, "supervised-result.json"), Buffer.from(JSON.stringify({ ok: false, reasonCode: "NOT_ADMITTED", reasons: admission.reasons }), "utf8"));
  process.exit(0);
}

const contractBytes = readFileSync(contractPath);
const outcome = evaluateCandidate({ repoDir, contractBytes, outDir: staging });

let summary;
if (!outcome.ok) {
  summary = { ok: false, reasonCode: outcome.reasonCode };
} else {
  // Sign inside the boundary if a key is supplied. The key read is bounded
  // and refuses a non-regular file (e.g. a FIFO that could block).
  const keyPath = process.env.SHEDU_SIGN_KEY_FILE ?? null;
  if (keyPath) {
    const st = statSync(keyPath);
    if (!st.isFile() || st.size > 64 * 1024) {
      writeFileSync(join(staging, "supervised-result.json"), Buffer.from(JSON.stringify({ ok: false, reasonCode: "SIGNATURE_INVALID" }), "utf8"));
      process.exit(0);
    }
    const keyPem = readFileSync(keyPath, "utf8");
    const signed = signReceipt(outcome.receipt, keyPem);
    writeFileSync(join(staging, "receipt.json"), Buffer.from(canonicalize(signed), "utf8"));
  }

  // Post-receipt stall seam: a kill here (before the summary below) must
  // leave nothing published.
  stall(process.env.SHEDU_TEST_STALL_AFTER_RECEIPT_MS);

  // Bundle manifest: digests of the published artifacts, so the supervisor
  // can verify the bundle is internally consistent before publishing.
  const bundleFiles = ["receipt.json", "plan.json", join("artifacts", "evidence", "index.json")];
  const bundle = {};
  for (const rel of bundleFiles) {
    bundle[rel] = digestOfBytes(readFileSync(join(staging, rel)));
  }
  summary = {
    ok: true,
    disposition: outcome.receipt.disposition,
    reasonCodes: outcome.receipt.reasonCodes,
    evaluationDigest: outcome.evaluationDigest,
    bundle
  };
}

// The summary is written LAST, marking the bundle complete and publishable.
writeFileSync(join(staging, "supervised-result.json"), Buffer.from(JSON.stringify(summary), "utf8"));
process.exit(0);
