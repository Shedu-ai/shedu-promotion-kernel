import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { basename, isAbsolute } from "node:path";
import process from "node:process";

// Control point: the closed toolchain authority.
export const CONTROL_POINTS = Object.freeze(["toolchain-authority"]);

// A closed, typed toolchain authority. Executables are NEVER derived from
// ambient PATH or from an arbitrary argv/executable location, and a readable
// directory prefix is NEVER granted from an executable's install path. The
// only admitted external executable in the experimental backend is the
// kernel's OWN Node interpreter (process.execPath), granted as an exact file
// and verified by content digest immediately before execution. Any other
// bare name, user-directory executable, or mutable external path is refused.

export class ToolchainError extends Error {
  constructor(message) {
    super(message);
    this.name = "ToolchainError";
    this.reasonCode = "TOOLCHAIN_UNRESOLVED";
  }
}

const KERNEL_NODE_PATH = realpathSync(process.execPath);
let kernelNodeDigest = null;

function hashFile(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

// The kernel node is the running interpreter; hash it once per process (the
// binary is large and cannot meaningfully be swapped underneath a running
// process). External/base executables are re-hashed on every use.
function kernelDigest() {
  if (kernelNodeDigest === null) kernelNodeDigest = hashFile(KERNEL_NODE_PATH);
  return kernelNodeDigest;
}

// The set of logical executable names a target command's argv[0] may name.
// v1: "node" only. Absolute paths are accepted only if they resolve to the
// exact kernel node; nothing under a user/home/temp directory is admitted.
export function isAdmittedExecutableName(argv0) {
  if (typeof argv0 !== "string" || argv0.length === 0) return false;
  if (argv0 === "node") return true;
  if (isAbsolute(argv0)) {
    try {
      return realpathSync(argv0) === KERNEL_NODE_PATH;
    } catch {
      return false;
    }
  }
  // A bare name other than "node", or any relative path, is not an admitted
  // toolchain executable (candidate/base *scripts* are argv[1..], never the
  // interpreter).
  return false;
}

// Resolve argv[0] to a concrete, verified executable. Returns
// { path, digest, name }. Throws ToolchainError for anything not admitted.
export function resolveToolchainExecutable(argv0, { toolchain = kernelToolchain() } = {}) {
  return toolchain.resolve(argv0);
}

export function kernelToolchain() {
  return {
    // The identity of the whole toolchain authority (currently the kernel
    // node digest); bound into every target validator identity.
    authorityDigest() {
      return kernelDigest();
    },
    resolve(argv0) {
      if (!isAdmittedExecutableName(argv0)) {
        throw new ToolchainError(
          `executable ${JSON.stringify(argv0)} is not an admitted toolchain executable (only the kernel node is permitted; ambient PATH and external paths are refused)`
        );
      }
      return { path: KERNEL_NODE_PATH, digest: kernelDigest(), name: "node" };
    },
    // Verify the executable content immediately before execution. For the
    // kernel node, verify size+mtime stability (cheap) against first use;
    // re-hash on any metadata change. Fails closed on drift.
    verify(entry) {
      if (entry.name === "node") {
        // Re-derive the digest from disk and compare (kernelDigest is cached
        // only after a real read; a swapped binary changes size, which a
        // re-read would surface). We re-hash to be unambiguous.
        const fresh = hashFile(entry.path);
        if (fresh !== entry.digest) {
          throw new ToolchainError(`kernel node digest drifted before execution: expected ${entry.digest}, found ${fresh}`);
        }
        return true;
      }
      const fresh = hashFile(entry.path);
      if (fresh !== entry.digest) {
        throw new ToolchainError(`executable ${entry.path} digest drifted before execution`);
      }
      return true;
    }
  };
}

// A test-only toolchain over an explicit executable file, so digest-drift and
// non-node rejection can be exercised without the 237MB kernel binary.
export function fileToolchain(executablePath) {
  const real = realpathSync(executablePath);
  const name = basename(real);
  return {
    authorityDigest() {
      return hashFile(real);
    },
    resolve(argv0) {
      let canonical = argv0;
      if (isAbsolute(argv0)) {
        try {
          canonical = realpathSync(argv0);
        } catch {
          canonical = argv0;
        }
      }
      if (canonical !== real && argv0 !== name) {
        throw new ToolchainError(`executable ${JSON.stringify(argv0)} is not admitted by this toolchain`);
      }
      return { path: real, digest: hashFile(real), name };
    },
    verify(entry) {
      const fresh = hashFile(entry.path);
      if (fresh !== entry.digest) {
        throw new ToolchainError(`executable ${entry.path} digest drifted before execution`);
      }
      return true;
    }
  };
}

export { KERNEL_NODE_PATH };
