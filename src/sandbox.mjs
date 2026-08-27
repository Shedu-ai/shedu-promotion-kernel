import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import process from "node:process";

// Control points this module implements (discovered mechanically by the
// control-surface census from the filesystem, independently of any registry).
export const CONTROL_POINTS = Object.freeze([
  "sandbox-network-isolation",
  "sandbox-read-isolation",
  "sandbox-write-isolation",
  "sandbox-process-ceiling"
]);

// Mandatory OS isolation backend for target-command execution. Isolation is
// DEFAULT-DENY: nothing is permitted unless mechanically declared.
//
//   darwin: sandbox-exec with an SBPL profile that denies everything by
//   default, then allows only:
//     - process exec (to launch the resolved executable);
//     - CONTENT reads of the exact resolved executable FILE (never its
//       parent or install prefix), the exact candidate/base materializations,
//       and the minimum immutable system roots a mach-o binary needs to
//       start (never $HOME, /Users, broad /private or /var, or a sibling
//       temporary directory);
//     - metadata reads anywhere (for path resolution; leaks existence, never
//       content);
//     - device-file writes stdio needs;
//   and denies network* and, at the maxProcesses: 1 ceiling, process-fork.
//
// The backend is probed once per process by demonstrating a blocked network
// bind and a blocked out-of-root content read. If isolation cannot be
// enforced — including a nested-sandbox environment where sandbox-exec cannot
// run — a target command FAILS CLOSED with SANDBOX_UNAVAILABLE.

export class SandboxUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = "SandboxUnavailableError";
    this.reasonCode = "SANDBOX_UNAVAILABLE";
  }
}

// Immutable OS roots a dynamically-linked mach-o executable needs to start:
// the dyld shared cache, system frameworks, system libraries, the device
// tree. None is user-writable or carries user secrets.
const SYSTEM_READ_ROOTS = Object.freeze([
  "/usr/lib",
  "/System",
  "/private/var/db/dyld",
  "/Library/Developer/CommandLineTools/usr/lib",
  "/dev"
]);

// SBPL string literals are double-quoted; only backslash and double-quote are
// special. Reject control characters (escaped textually so this source file
// stays valid UTF-8 text, never binary) rather than emitting them.
function sbplString(value) {
  if (/[\u0000-\u001f]/.test(value)) {
    throw new SandboxUnavailableError(`path contains control characters and cannot be sandboxed: ${JSON.stringify(value)}`);
  }
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function buildProfile({ singleProcess, executablePath, readRoots, fileLiterals = [], dirLiterals = [] }) {
  const roots = new Set(SYSTEM_READ_ROOTS);
  for (const root of readRoots) roots.add(root);
  const readSubpaths = [...roots].sort().map((root) => `(subpath ${sbplString(root)})`);
  // The executable is granted as an EXACT FILE (literal), never its prefix.
  const literals = new Set();
  if (executablePath) literals.add(executablePath);
  // Exact file grants (e.g. declared input-manifest blobs) and directory-entry
  // grants (so the interpreter can traverse to them, without content access to
  // undeclared siblings).
  for (const f of fileLiterals) literals.add(f);
  for (const d of dirLiterals) literals.add(d);
  const literalGrants = [...literals].sort().map((p) => `(literal ${sbplString(p)})`).join(" ");
  const rules = [
    "(version 1)",
    "(deny default)",
    "(allow process-exec)",
    singleProcess ? "(deny process-fork)" : "(allow process-fork)",
    "(allow sysctl-read)",
    "(allow mach-lookup)",
    "(allow signal (target self))",
    "(deny network*)",
    // Metadata anywhere (path resolution stats ancestors); content reads only
    // for the exact executable, exact declared files, directory entries needed
    // for traversal, the declared subpath roots, and immutable OS roots. No
    // blanket file-read* and no directory prefix from the executable.
    "(allow file-read-metadata)",
    `(allow file-read* (literal "/") ${literalGrants} ${readSubpaths.join(" ")})`,
    "(deny file-write*)",
    '(allow file-write-data (literal "/dev/null") (literal "/dev/dtracehelper") (literal "/dev/tty") (literal "/dev/random") (literal "/dev/urandom"))',
    '(allow file-write* (subpath "/dev/fd"))'
  ];
  return rules.join("");
}

let probed = null;

function probeBackend(probeRunner = defaultProbeRunner) {
  if (process.platform !== "darwin") {
    return { available: false, reason: `no enforcing sandbox backend is implemented for ${process.platform}` };
  }
  return probeRunner();
}

function defaultProbeRunner() {
  const executablePath = realpathSync(process.execPath);
  const trivialProfile = buildProfile({ singleProcess: true, executablePath, readRoots: [] });

  // The full profile must still permit the executable to start.
  const trivial = spawnSync("sandbox-exec", ["-p", trivialProfile, executablePath, "-e", "process.exit(0)"], {
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
    env: { PATH: process.env.PATH }
  });
  if (trivial.error || trivial.status !== 0) {
    return { available: false, reason: `sandbox-exec probe failed (nested sandbox or unavailable): ${trivial.error ?? trivial.stderr}` };
  }

  // Network denial must demonstrably fail a bind.
  const netScript =
    'const s=require("node:net").createServer();s.on("error",()=>process.exit(1));s.listen(0,()=>process.exit(0));setTimeout(()=>process.exit(2),5000);';
  const netProbe = spawnSync("sandbox-exec", ["-p", trivialProfile, executablePath, "-e", netScript], {
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
    env: { PATH: process.env.PATH }
  });
  if (netProbe.error || netProbe.status !== 1) {
    return { available: false, reason: "sandbox-exec did not demonstrably block a network bind; refusing to trust it" };
  }

  // Content-read denial must demonstrably fail a read outside the roots.
  const readScript =
    'try{require("node:fs").readFileSync("/etc/hosts");process.exit(0)}catch(e){process.exit(e.code==="EPERM"?1:2)}';
  const readProbe = spawnSync("sandbox-exec", ["-p", trivialProfile, executablePath, "-e", readScript], {
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
    env: { PATH: process.env.PATH }
  });
  if (readProbe.error || readProbe.status !== 1) {
    return { available: false, reason: "sandbox-exec did not demonstrably block an out-of-root read; refusing to trust it" };
  }

  return { available: true, reason: null };
}

export function sandboxStatus() {
  if (probed === null) probed = probeBackend();
  return probed;
}

// Wraps a resolved executable + declared argv tail for isolated execution.
// `executablePath` is the concrete, already-verified interpreter (from the
// closed toolchain authority). readRoots are the mechanically declared,
// path-contained roots the command may READ (candidate and base
// materializations). Throws SandboxUnavailableError when isolation cannot be
// enforced — including a process ceiling this backend cannot cap exactly.
export function isolateExecution({ executablePath, argvTail, maxProcesses, readRoots = [], readFiles = [], cwd = process.cwd() }) {
  const status = sandboxStatus();
  if (!status.available) {
    throw new SandboxUnavailableError(`target-command isolation unavailable: ${status.reason}`);
  }
  if (!Number.isSafeInteger(maxProcesses) || maxProcesses < 1) {
    throw new SandboxUnavailableError("a positive process ceiling is required");
  }
  if (maxProcesses !== 1) {
    throw new SandboxUnavailableError(
      `this backend enforces a process ceiling only by fork denial; maxProcesses ${maxProcesses} cannot be capped exactly`
    );
  }
  if (!isAbsolute(executablePath)) {
    throw new SandboxUnavailableError(`executable must be an absolute resolved path: ${JSON.stringify(executablePath)}`);
  }

  const grantedReadRoots = new Set();
  const grant = (p) => {
    grantedReadRoots.add(p);
    try {
      grantedReadRoots.add(realpathSync(p));
    } catch {
      // unresolvable; the literal grant stands
    }
  };
  for (const root of readRoots) {
    if (!isAbsolute(root)) {
      throw new SandboxUnavailableError(`read root must be an absolute path: ${JSON.stringify(root)}`);
    }
    grant(root);
  }

  // Exact-file grants (declared input-manifest blobs) plus the directory
  // entries needed to traverse to them and to the working directory. A dir
  // ENTRY grant permits listing/traversal but NOT reading undeclared child
  // file contents, so a dynamic read of an undeclared base file is denied.
  const fileLiterals = new Set();
  const dirLiterals = new Set();
  const addFile = (f) => {
    const real = (() => {
      try {
        return realpathSync(f);
      } catch {
        return f;
      }
    })();
    fileLiterals.add(f);
    fileLiterals.add(real);
    for (const p of [f, real]) {
      let d = dirname(p);
      while (d && d !== "/" && !dirLiterals.has(d)) {
        dirLiterals.add(d);
        d = dirname(d);
      }
    }
  };
  // The working directory must be traversable/readable (node reads uv_cwd).
  for (const p of [cwd, (() => { try { return realpathSync(cwd); } catch { return cwd; } })()]) {
    let d = p;
    while (d && d !== "/" && !dirLiterals.has(d)) {
      dirLiterals.add(d);
      d = dirname(d);
    }
  }
  for (const f of readFiles) {
    if (!isAbsolute(f)) throw new SandboxUnavailableError(`read file must be an absolute path: ${JSON.stringify(f)}`);
    addFile(f);
  }

  const profile = buildProfile({
    singleProcess: true,
    executablePath,
    readRoots: [...grantedReadRoots],
    fileLiterals: [...fileLiterals],
    dirLiterals: [...dirLiterals]
  });
  return ["sandbox-exec", "-p", profile, executablePath, ...argvTail];
}

// Test seam: force a probe result (null re-probes on next use), or run the
// probe against an injected runner to exercise the nested-sandbox path.
export function overrideSandboxProbe(result) {
  probed = result;
}

export function probeBackendWith(probeRunner) {
  return probeBackend(probeRunner);
}
