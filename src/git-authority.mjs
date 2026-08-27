import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { digestOfCanonical } from "./canonical-json.mjs";

// Control point: the closed Git authority.
export const CONTROL_POINTS = Object.freeze(["git-authority"]);

export class GitAuthorityError extends Error {
  constructor(message) {
    super(message);
    this.name = "GitAuthorityError";
    this.reasonCode = "GIT_UNRESOLVED";
  }
}

// Actual toolchain binaries precede the macOS dispatcher. Every path is
// source-closed: PATH and environment variables cannot add a candidate.
const CANDIDATES = Object.freeze([
  "/Library/Developer/CommandLineTools/usr/bin/git",
  "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
  "/opt/homebrew/bin/git",
  "/usr/local/bin/git",
  "/usr/bin/git"
]);

function hashFile(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function baseGitEnv(extraEnv = {}) {
  return {
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
    HOME: "/nonexistent",
    ...extraEnv
  };
}

// Bind every regular helper visible in Git's own exec path. Hard-linked
// helpers are hashed once per inode but retain separate name rows, so adding,
// removing, renaming, or replacing any dispatchable helper changes the digest.
function helperManifest(execPath) {
  const directory = realpathSync(execPath);
  if (!statSync(directory).isDirectory()) throw new GitAuthorityError("git exec-path is not a directory");
  const byInode = new Map();
  const helpers = [];
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory, name);
    let real;
    let stat;
    try {
      real = realpathSync(path);
      stat = statSync(real);
    } catch {
      throw new GitAuthorityError(`git helper ${name} cannot be resolved`);
    }
    if (!stat.isFile()) continue;
    const inode = `${stat.dev}:${stat.ino}`;
    if (!byInode.has(inode)) byInode.set(inode, hashFile(real));
    helpers.push({ name, path: real, digest: byInode.get(inode), size: stat.size });
  }
  if (helpers.length === 0) throw new GitAuthorityError("git exec-path contains no bound helpers");
  return { execPath: directory, helpers, digest: digestOfCanonical(helpers) };
}

function buildAuthority(candidate) {
  const path = realpathSync(candidate);
  if (!statSync(path).isFile()) throw new GitAuthorityError("git candidate is not a regular file");
  const executableDigest = hashFile(path);
  const probe = spawnSync(path, ["--exec-path"], {
    encoding: "utf8",
    env: baseGitEnv(),
    timeout: 10_000,
    windowsHide: true
  });
  const requestedExecPath = probe.status === 0 ? probe.stdout.trim() : "";
  if (!isAbsolute(requestedExecPath)) throw new GitAuthorityError("git did not return an absolute exec-path");
  const helperAuthority = helperManifest(requestedExecPath);
  const authorityDigest = digestOfCanonical({
    executable: { path, digest: executableDigest },
    execPath: helperAuthority.execPath,
    helperManifestDigest: helperAuthority.digest
  });
  return {
    path,
    digest: executableDigest,
    execPath: helperAuthority.execPath,
    helperManifestDigest: helperAuthority.digest,
    authorityDigest
  };
}

let resolved = null;

function resolveGit() {
  if (resolved !== null) return resolved;
  for (const candidate of CANDIDATES) {
    if (!isAbsolute(candidate)) continue;
    try {
      if (existsSync(candidate)) {
        resolved = buildAuthority(candidate);
        return resolved;
      }
    } catch {
      // A partially present or unbindable candidate is not admitted; continue
      // through the closed set.
    }
  }
  throw new GitAuthorityError("no fully bound git executable and helper set found in the closed candidate set");
}

function verifyAuthority(expected) {
  let fresh;
  try {
    fresh = buildAuthority(expected.path);
  } catch (error) {
    throw new GitAuthorityError(`git authority could not be reverified: ${String(error)}`);
  }
  if (fresh.authorityDigest !== expected.authorityDigest) {
    throw new GitAuthorityError(`git authority drifted before use: expected ${expected.authorityDigest}, found ${fresh.authorityDigest}`);
  }
}

// Every invocation re-hashes both the actual executable and the complete Git
// exec-path helper manifest, then pins GIT_EXEC_PATH to that verified path.
export function git(args, { cwd = null, binary = false, extraEnv = {}, maxBuffer = 32 * 1024 * 1024 } = {}) {
  const auth = resolveGit();
  verifyAuthority(auth);
  const fullArgs = cwd === null ? args : ["-C", cwd, ...args];
  return spawnSync(auth.path, fullArgs, {
    encoding: binary ? "buffer" : "utf8",
    windowsHide: true,
    maxBuffer,
    env: baseGitEnv({ GIT_EXEC_PATH: auth.execPath, ...extraEnv })
  });
}

export function gitAuthorityIdentity() {
  const auth = resolveGit();
  verifyAuthority(auth);
  return { ...auth };
}

export function resetGitAuthority() {
  resolved = null;
}
