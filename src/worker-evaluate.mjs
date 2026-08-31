import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { evaluateCandidate } from "./evaluate.mjs";
import { signReceipt, validateReceiptSigningKey } from "./receipt.mjs";
import { committedAdmission, isAdmitted } from "./admission.mjs";
import { readBoundedRegularFile } from "./bounded-file.mjs";

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

// Admit optional signing material before starting the expensive evaluation.
// Both this preflight and final signing remain inside the hard-deadline worker.
// The exact bounded bytes are retained, then reparsed by signReceipt, so a
// directory/FIFO/malformed/wrong-algorithm key fails without spending the
// evaluation budget and no path can be substituted between the two stages.
const keyPath = process.env.SHEDU_SIGN_KEY_FILE ?? null;
let keyPem = null;
if (keyPath) {
  try {
    keyPem = readBoundedRegularFile(keyPath, 64 * 1024).toString("utf8");
    validateReceiptSigningKey(keyPem);
  } catch {
    writeFileSync(join(staging, "supervised-result.json"), Buffer.from(JSON.stringify({ ok: false, reasonCode: "SIGNATURE_INVALID" }), "utf8"));
    process.exit(0);
  }
}

const contractBytes = readFileSync(contractPath);
const outcome = evaluateCandidate({ repoDir, contractBytes, outDir: staging });

let summary;
if (!outcome.ok) {
  summary = { ok: false, reasonCode: outcome.reasonCode };
} else {
  // Final signing consumes the exact bytes admitted above and still occurs
  // inside the supervised boundary.
  if (keyPem !== null) {
    const signed = signReceipt(outcome.receipt, keyPem);
    writeFileSync(join(staging, "receipt.json"), Buffer.from(canonicalize(signed), "utf8"));
  }

  // Post-receipt stall seam: a kill here (before the summary below) must
  // leave nothing published.
  stall(process.env.SHEDU_TEST_STALL_AFTER_RECEIPT_MS);

  // Bundle manifest: digests of the published artifacts, so the supervisor
  // can verify the bundle is internally consistent before publishing.
  // The evidence member is contract-declared through artifactRoot. A fixed
  // `artifacts/` path would make a valid non-default root evaluate correctly
  // and then fail during publication. The receipt has already passed the
  // closed promotion-receipt schema and binds the work-contract value.
  const evidenceIndexRel = join(
    outcome.receipt.artifactRoot.replace(/\/+$/, ""), "evidence", "index.json");
  const bundleFiles = ["receipt.json", "plan.json", evidenceIndexRel];
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
