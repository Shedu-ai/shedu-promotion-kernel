import { spawnSync } from "node:child_process";
import { digestOfBytes, validateRelativePath } from "./canonical-json.mjs";
import { validateDocument } from "./contracts.mjs";

// Immutable authority resolution: policy content is read exclusively from a
// full commit object id, via git plumbing invoked with exact argv and no
// shell. Moving refs, symlinks, non-blob objects, and digest drift all fail
// closed, so a candidate branch can never alter the authority for its own run.

const COMMIT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const MAX_AUTHORITY_BYTES = 8 * 1024 * 1024;

function runGit(repoDir, args, { binary = false } = {}) {
  return spawnSync("git", ["-C", repoDir, ...args], {
    encoding: binary ? "buffer" : "utf8",
    maxBuffer: MAX_AUTHORITY_BYTES,
    windowsHide: true
  });
}

export function verifyImmutableCommit(repoDir, commitId) {
  if (typeof commitId !== "string" || !COMMIT_RE.test(commitId)) {
    return { ok: false, reasonCode: "MOVING_REF_REJECTED", message: `base identity must be a full commit object id, got ${JSON.stringify(commitId)}` };
  }
  const r = runGit(repoDir, ["rev-parse", "--verify", "--end-of-options", `${commitId}^{commit}`]);
  if (r.status !== 0) {
    return { ok: false, reasonCode: "AUTHORITY_OBJECT_MISSING", message: `commit ${commitId} is not present in ${repoDir}` };
  }
  const resolved = r.stdout.trim();
  if (resolved !== commitId) {
    return { ok: false, reasonCode: "MOVING_REF_REJECTED", message: `${commitId} resolved to a different object ${resolved}` };
  }
  return { ok: true, commitId };
}

export function readAuthorityBlob(repoDir, commitId, path) {
  const pathCheck = validateRelativePath(path);
  if (!pathCheck.ok) {
    return { ok: false, reasonCode: pathCheck.reasonCode, message: `${pathCheck.message}: ${JSON.stringify(path)}` };
  }
  const commitCheck = verifyImmutableCommit(repoDir, commitId);
  if (!commitCheck.ok) return commitCheck;

  const ls = runGit(repoDir, ["ls-tree", "-z", commitId, "--", path]);
  if (ls.status !== 0 || ls.stdout === "") {
    return { ok: false, reasonCode: "AUTHORITY_OBJECT_MISSING", message: `${path} does not exist at ${commitId}` };
  }
  const row = ls.stdout
    .split("\0")
    .filter(Boolean)
    .map((entry) => {
      const tab = entry.indexOf("\t");
      const [mode, type, oid] = entry.slice(0, tab).split(" ");
      return { mode, type, oid, path: entry.slice(tab + 1) };
    })
    .find((e) => e.path === path);
  if (!row) {
    return { ok: false, reasonCode: "AUTHORITY_OBJECT_MISSING", message: `${path} does not exist at ${commitId}` };
  }
  if (row.type !== "blob" || (row.mode !== "100644" && row.mode !== "100755")) {
    return { ok: false, reasonCode: "AUTHORITY_PATH_NOT_BLOB", message: `${path} at ${commitId} is ${row.type} mode ${row.mode}, not a regular file` };
  }

  const cat = runGit(repoDir, ["cat-file", "blob", `${commitId}:${path}`], { binary: true });
  if (cat.status !== 0) {
    return { ok: false, reasonCode: "AUTHORITY_OBJECT_MISSING", message: `cannot read blob ${commitId}:${path}` };
  }
  return { ok: true, bytes: cat.stdout };
}

export function loadAuthorityDocument({ repoDir, baseCommit, path, expectedDigest = null, kind }) {
  const blob = readAuthorityBlob(repoDir, baseCommit, path);
  if (!blob.ok) return blob;
  const digest = digestOfBytes(blob.bytes);
  if (expectedDigest !== null && digest !== expectedDigest) {
    return {
      ok: false,
      reasonCode: "AUTHORITY_DIGEST_MISMATCH",
      message: `${path} at ${baseCommit}: expected ${expectedDigest}, found ${digest}`
    };
  }
  const validated = validateDocument(kind, blob.bytes);
  if (!validated.ok) {
    return { ok: false, reasonCode: validated.errors[0].reasonCode, message: `${path} at ${baseCommit} is not a valid ${kind}`, errors: validated.errors };
  }
  return { ok: true, value: validated.value, digest, bytes: blob.bytes };
}
