import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import process from "node:process";

// Control point: the closed Git authority.
export const CONTROL_POINTS = Object.freeze(["git-authority"]);

// A closed, typed Git authority. Every Git operation the kernel performs —
// frozen-source verification, immutable authority reads, candidate inspection,
// worktree materialization, CLI commit discovery — flows through this single
// module. Git is resolved ONLY from a fixed, closed set of absolute system
// locations: never through ambient PATH, and never through a caller-supplied
// override (no environment variable can substitute the executable). Its
// canonical path and content digest are bound, and the digest is reverified
// before every invocation. The child runs in a minimal, constructed
// environment (no ambient config, no ambient PATH) so a fake `git` planted on
// PATH is never consulted.
//
// KNOWN LIMITATION (documented, not silently ignored): on macOS the resolved
// /usr/bin/git is a thin dispatcher that execs the active toolchain's git
// under /Library/Developer/CommandLineTools; binding the dispatcher digest
// does NOT transitively close the underlying git binary + helper programs +
// dylibs. Full toolchain closure is not achievable in-process; it is deferred
// to Harness Bench, which materializes the frozen commit under its own trusted
// toolchain. This module closes the SUBSTITUTION surface (no PATH, no override)
// and binds the dispatcher identity; it does not claim transitive closure.

export class GitAuthorityError extends Error {
  constructor(message) {
    super(message);
    this.name = "GitAuthorityError";
    this.reasonCode = "GIT_UNRESOLVED";
  }
}

const CANDIDATES = ["/usr/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git", "/Library/Developer/CommandLineTools/usr/bin/git"];

function hashFile(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

let resolved = null;

function resolveGit() {
  if (resolved !== null) return resolved;
  // No caller-supplied override: the candidate set is fixed in source. An
  // environment variable can never substitute the git executable.
  for (const candidate of CANDIDATES) {
    if (!isAbsolute(candidate)) continue;
    try {
      if (existsSync(candidate) && statSync(candidate).isFile()) {
        const real = realpathSync(candidate);
        resolved = { path: real, digest: hashFile(real) };
        return resolved;
      }
    } catch {
      // keep searching
    }
  }
  throw new GitAuthorityError("no admitted git executable found in the closed candidate set");
}

// A minimal, constructed environment for git. No ambient PATH: git resolves
// its own subcommands from its exec-path, not PATH. Config is fully neutered.
// Deterministic identity is provided for the rare commit-object operations
// (candidate tree wrapping); extraEnv may add author/committer overrides.
function gitEnv(extraEnv = {}) {
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

// Run a git invocation through the bound authority. The digest is reverified
// immediately before spawning; drift fails closed.
export function git(args, { cwd = null, binary = false, extraEnv = {}, maxBuffer = 32 * 1024 * 1024 } = {}) {
  const auth = resolveGit();
  const fresh = hashFile(auth.path);
  if (fresh !== auth.digest) {
    throw new GitAuthorityError(`git executable digest drifted before use: expected ${auth.digest}, found ${fresh}`);
  }
  const fullArgs = cwd === null ? args : ["-C", cwd, ...args];
  return spawnSync(auth.path, fullArgs, {
    encoding: binary ? "buffer" : "utf8",
    windowsHide: true,
    maxBuffer,
    env: gitEnv(extraEnv)
  });
}

export function gitAuthorityIdentity() {
  const auth = resolveGit();
  return { path: auth.path, digest: auth.digest };
}

// Test seam: reset the cached resolution (the candidate set is re-scanned on
// the next call). Used by tests that manipulate PATH/env to prove no
// substitution surface exists.
export function resetGitAuthority() {
  resolved = null;
}
