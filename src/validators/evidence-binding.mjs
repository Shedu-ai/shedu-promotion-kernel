import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, digestOfBytes } from "../canonical-json.mjs";

// evidence-binding-index@1 — PROMOTION_FINALIZATION.
// Re-reads every artifact referenced by every prior result from the
// content-addressed store and verifies it hashes to its declared digest;
// verifies every prior result binds to this run's plan digest and candidate;
// and verifies the index binding itself matches the plan. Missing or mutated
// evidence, or an unbound result, FIREs. The verification summary is itself
// indexed evidence.
export function evidenceBindingIndex(context) {
  const { plan, planDigest, priorResults, evidence, evidenceRootDir, check } = context;
  if (!evidence || !evidenceRootDir) {
    return { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"], details: { failure: "no evidence index" } };
  }
  const reasonCodes = new Set();
  const objectsDir = join(evidenceRootDir, "objects", "sha256");
  const indexed = new Map(evidence.artifacts().map((a) => [a.artifactId, a]));
  let artifactsVerified = 0;

  for (const result of priorResults) {
    if (result.planDigest !== planDigest || result.candidateId !== plan.candidate.id) {
      reasonCodes.add("RESULT_BINDING_MISMATCH");
    }
    for (const ref of result.evidence) {
      const entry = indexed.get(ref.artifactId);
      if (!entry) {
        reasonCodes.add("EVIDENCE_MISSING");
        continue;
      }
      if (entry.digest !== ref.digest || entry.checkId !== result.checkId) {
        reasonCodes.add("EVIDENCE_MUTATED");
        continue;
      }
      let bytes;
      try {
        bytes = readFileSync(join(objectsDir, entry.digest.slice("sha256:".length)));
      } catch {
        reasonCodes.add("EVIDENCE_MISSING");
        continue;
      }
      if (digestOfBytes(bytes) !== entry.digest) {
        reasonCodes.add("EVIDENCE_MUTATED");
        continue;
      }
      artifactsVerified += 1;
    }
  }

  const summary = {
    resultsVerified: priorResults.length,
    artifactsVerified,
    planDigest,
    candidateId: plan.candidate.id
  };
  const summaryRef = evidence.put({
    artifactId: "evidence-binding-summary",
    checkId: check.checkId,
    validatorId: "evidence-binding-index@1",
    bytes: Buffer.from(canonicalize(summary), "utf8"),
    mediaType: "application/json"
  });

  return {
    outcome: reasonCodes.size > 0 ? "FIRED" : "PASS",
    reasonCodes: [...reasonCodes].sort(),
    evidence: [summaryRef],
    details: summary
  };
}
