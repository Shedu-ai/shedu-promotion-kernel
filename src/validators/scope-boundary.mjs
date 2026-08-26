import { changedFilesBetween, committishForCandidate, listTree, readBlobAt } from "../workspace.mjs";

// scope-boundary-classify@1 — CANDIDATE_VALIDATION.
// Every changed path is classified against the contract's exact allowed,
// readonly, and forbidden sets. Readonly, forbidden, and unclassified
// changes FIRE; so do case-colliding candidate paths and symlinks whose
// targets escape the repository. The classification list itself is the
// changed-file attribution consumed by the receipt.

function matchLength(entry, path) {
  if (entry.endsWith("/")) {
    return path.startsWith(entry) ? entry.length : -1;
  }
  return path === entry ? entry.length + 1 : -1;
}

// Longest matching entry wins; exact entries outrank a dir prefix of equal
// spelled length. Identical entries across sets are already rejected by the
// contract validator, so ties cannot occur.
export function classifyPath(path, scope) {
  let best = { scopeClass: "UNCLASSIFIED", length: -1 };
  for (const [setName, scopeClass] of [
    ["allowed", "ALLOWED"],
    ["readonly", "READONLY"],
    ["forbidden", "FORBIDDEN"]
  ]) {
    for (const entry of scope[setName]) {
      const length = matchLength(entry, path);
      if (length > best.length) best = { scopeClass, length };
    }
  }
  return best.scopeClass;
}

function symlinkEscapes(repoDir, committish, path) {
  const target = readBlobAt(repoDir, committish, path).toString("utf8");
  if (target.startsWith("/") || /^[A-Za-z]:[\\/]/.test(target)) return true;
  const dir = path.split("/").slice(0, -1);
  const segments = [...dir];
  for (const part of target.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (segments.length === 0) return true;
      segments.pop();
    } else {
      segments.push(part);
    }
  }
  return false;
}

export function scopeBoundaryClassify(context) {
  const { repoDir, workContract } = context;
  const { baseCommit, candidate } = workContract.target;
  const committish = committishForCandidate(repoDir, candidate);
  const reasonCodes = new Set();

  const changed = changedFilesBetween(repoDir, baseCommit, committish);
  const changedFiles = changed.map((c) => {
    const scopeClass = classifyPath(c.path, workContract.scope);
    if (scopeClass === "FORBIDDEN") reasonCodes.add("SCOPE_FORBIDDEN_CHANGE");
    else if (scopeClass === "READONLY") reasonCodes.add("SCOPE_READONLY_CHANGE");
    else if (scopeClass === "UNCLASSIFIED") reasonCodes.add("SCOPE_UNCLASSIFIED_CHANGE");
    return { path: c.path, changeKind: c.changeKind, scopeClass };
  });

  // Case collisions across the whole candidate tree: on a case-insensitive
  // filesystem two such paths silently alias one file, so authority over
  // "which file changed" is lost.
  const tree = listTree(repoDir, committish);
  const byFolded = new Map();
  for (const entry of tree) {
    const folded = entry.path.toLowerCase();
    if (byFolded.has(folded) && byFolded.get(folded) !== entry.path) {
      reasonCodes.add("SCOPE_CASE_COLLISION");
    }
    byFolded.set(folded, entry.path);
  }

  // Symlinks added or modified by the candidate must not escape the repo.
  const modeByPath = new Map(tree.map((e) => [e.path, e.mode]));
  for (const c of changed) {
    if (c.changeKind === "DELETED") continue;
    if (modeByPath.get(c.path) === "120000" && symlinkEscapes(repoDir, committish, c.path)) {
      reasonCodes.add("SCOPE_SYMLINK_ESCAPE");
    }
  }

  const outcome = reasonCodes.size > 0 ? "FIRED" : "PASS";
  return { outcome, reasonCodes: [...reasonCodes].sort(), details: { changedFiles } };
}
