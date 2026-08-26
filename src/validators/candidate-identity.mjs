import { verifyImmutableCommit } from "../authority.mjs";
import {
  gitRun,
  headTree,
  isAncestor,
  treeOf,
  workspaceStatus
} from "../workspace.mjs";

// candidate-identity-verify@1 — CONTRACT_ADMISSION.
// Verifies the repository root, immutable base and candidate identities,
// candidate/base ancestry, and clean candidate materialization. An identity
// failure is terminal for the run: the engine stops after admission FIREs.
export function candidateIdentityVerify(context) {
  const { repoDir, workContract, candidateDir } = context;
  const reasonCodes = new Set();
  const target = workContract.target;

  const toplevel = gitRun(repoDir, ["rev-parse", "--show-toplevel"]);
  if (toplevel.status !== 0) {
    return { outcome: "FIRED", reasonCodes: ["AUTHORITY_OBJECT_MISSING"], details: { failure: "repository root is not a git repository" } };
  }

  const base = verifyImmutableCommit(repoDir, target.baseCommit);
  if (!base.ok) reasonCodes.add(base.reasonCode);

  if (target.candidate.kind === "COMMIT") {
    const cand = verifyImmutableCommit(repoDir, target.candidate.id);
    if (!cand.ok) reasonCodes.add(cand.reasonCode);
    if (base.ok && cand.ok && !isAncestor(repoDir, target.baseCommit, target.candidate.id)) {
      reasonCodes.add("CANDIDATE_NOT_DESCENDANT");
    }
  } else {
    const tree = gitRun(repoDir, ["cat-file", "-e", `${target.candidate.id}^{tree}`]);
    if (tree.status !== 0) reasonCodes.add("AUTHORITY_OBJECT_MISSING");
  }

  let materializedTree = null;
  if (candidateDir) {
    const status = workspaceStatus(candidateDir);
    if (status !== "") reasonCodes.add("WORKSPACE_DIRTY");
    materializedTree = headTree(candidateDir);
    const expectedTree = reasonCodes.size === 0 ? treeOf(repoDir, target.candidate.id) : null;
    if (expectedTree !== null && materializedTree !== expectedTree) {
      reasonCodes.add("WORKSPACE_DIRTY");
    }
  }

  if (reasonCodes.size > 0) {
    return { outcome: "FIRED", reasonCodes: [...reasonCodes].sort() };
  }
  return {
    outcome: "PASS",
    reasonCodes: [],
    details: { baseCommit: target.baseCommit, candidate: target.candidate, materializedTree }
  };
}

// candidate-tree-stability@1 — PROMOTION_FINALIZATION.
// After validation ran, the materialized candidate must still be exactly the
// candidate tree: no validator or command may have mutated the workspace
// that evidence claims to describe.
export function candidateTreeStability(context) {
  const { repoDir, workContract, candidateDir } = context;
  if (!candidateDir) {
    return { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"], details: { failure: "no candidate workspace to verify" } };
  }
  const reasonCodes = new Set();
  const status = workspaceStatus(candidateDir);
  if (status !== "") reasonCodes.add("CANDIDATE_TREE_UNSTABLE");
  const nowTree = headTree(candidateDir);
  const expectedTree = treeOf(repoDir, workContract.target.candidate.id);
  if (nowTree !== expectedTree) reasonCodes.add("CANDIDATE_TREE_UNSTABLE");
  if (reasonCodes.size > 0) {
    return { outcome: "FIRED", reasonCodes: [...reasonCodes].sort(), details: { dirty: status.split("\n").filter(Boolean) } };
  }
  return { outcome: "PASS", reasonCodes: [], details: { tree: nowTree } };
}
