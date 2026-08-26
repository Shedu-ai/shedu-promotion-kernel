import { canonicalize } from "../canonical-json.mjs";
import { changedFilesBetween, committishForCandidate } from "../workspace.mjs";

// prior-art-admission@1 — CONTRACT_ADMISSION.
// Consumes the target-owned capability-index@1 (bound to the trusted base)
// and the pre-candidate prior-art-query@1 manifest. The declared search is
// executed here, at evaluation time, against the declared index — that
// execution, recorded as evidence, is the proof the search ran. A
// doNotRebuild collision blocks unless the manifest carries an authorized
// allowed-follow-up or exception-receipt resolution; a REVIEW_REQUESTED
// resolution yields the declared external-review admission result
// (REVIEW_REQUIRED) — the kernel never rules on semantic similarity.

function entryMatchesTerm(entry, term) {
  const needle = term.toLowerCase();
  if (entry.capabilityId.toLowerCase().includes(needle)) return true;
  if (entry.title.toLowerCase().includes(needle)) return true;
  return entry.canonicalFiles.some((f) => f.toLowerCase().includes(needle));
}

function pathTouches(changedPath, canonicalFile) {
  return changedPath === canonicalFile || changedPath.startsWith(`${canonicalFile}/`);
}

export function priorArtAdmission(context) {
  const { repoDir, workContract, capabilityIndex, priorArtQuery, evidence, check } = context;
  if (!capabilityIndex || !priorArtQuery) {
    return {
      outcome: "INFRA_FAILURE",
      reasonCodes: ["INFRASTRUCTURE_FAILURE"],
      details: { failure: "prior-art-admission requires a declared capability index and prior-art query manifest" }
    };
  }

  const committish = committishForCandidate(repoDir, workContract.target.candidate);
  const changed = changedFilesBetween(repoDir, workContract.target.baseCommit, committish);
  const changedPaths = changed.map((c) => c.path);

  // Execute every declared query against the declared index.
  const searchResults = priorArtQuery.queries.map((query) => ({
    queryId: query.queryId,
    terms: query.terms,
    matchedCapabilityIds: capabilityIndex.entries
      .filter((entry) => query.terms.some((term) => entryMatchesTerm(entry, term)))
      .map((entry) => entry.capabilityId)
      .sort()
  }));

  // Mechanical collision rule: a changed path touches a doNotRebuild entry's
  // canonical files.
  const declaredById = new Map(priorArtQuery.declaredCollisions.map((c) => [c.capabilityId, c]));
  const reasonCodes = new Set();
  const collisions = [];
  for (const entry of capabilityIndex.entries) {
    if (!entry.doNotRebuild || entry.status !== "ACTIVE") continue;
    const touched = changedPaths.filter((p) => entry.canonicalFiles.some((f) => pathTouches(p, f)));
    if (touched.length === 0) continue;
    const declared = declaredById.get(entry.capabilityId);
    let admission;
    if (!declared) {
      admission = "UNACKNOWLEDGED";
      reasonCodes.add("PRIOR_ART_COLLISION");
    } else if (declared.resolution === "ALLOWED_FOLLOW_UP") {
      if (entry.allowedFollowUps.includes(declared.followUpId)) {
        admission = "ALLOWED_FOLLOW_UP";
      } else {
        admission = "FOLLOW_UP_NOT_AUTHORIZED";
        reasonCodes.add("PRIOR_ART_COLLISION");
      }
    } else if (declared.resolution === "EXCEPTION_RECEIPT") {
      if (entry.receiptRefs.includes(declared.receiptRef)) {
        admission = "EXCEPTION_RECEIPT";
      } else {
        admission = "EXCEPTION_NOT_AUTHORIZED";
        reasonCodes.add("PRIOR_ART_COLLISION");
      }
    } else {
      // REVIEW_REQUESTED: a structured admission result for an external
      // authority — blocking, but explicitly not a kernel semantic ruling.
      admission = "REVIEW_REQUIRED";
      reasonCodes.add("REVIEW_REQUIRED");
    }
    collisions.push({ capabilityId: entry.capabilityId, touched, admission });
  }

  // A declared resolution naming a capability that does not exist in the
  // bound index is unauthorized authority and fails closed.
  const knownIds = new Set(capabilityIndex.entries.map((e) => e.capabilityId));
  for (const declared of priorArtQuery.declaredCollisions) {
    if (!knownIds.has(declared.capabilityId)) {
      reasonCodes.add("PRIOR_ART_COLLISION");
      collisions.push({ capabilityId: declared.capabilityId, touched: [], admission: "DECLARED_FOR_UNKNOWN_CAPABILITY" });
    }
  }

  const details = { searchResults, collisions, changedPaths };
  const evidenceRefs = [];
  if (evidence) {
    evidenceRefs.push(
      evidence.put({
        artifactId: "prior-art-search-report",
        checkId: check.checkId,
        validatorId: "prior-art-admission@1",
        bytes: Buffer.from(canonicalize(details), "utf8"),
        mediaType: "application/json"
      })
    );
  }
  return {
    outcome: reasonCodes.size > 0 ? "FIRED" : "PASS",
    reasonCodes: [...reasonCodes].sort(),
    evidence: evidenceRefs,
    details
  };
}
