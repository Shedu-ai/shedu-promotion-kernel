import { spawnSync } from "node:child_process";
import process from "node:process";

// Mandatory OS isolation backend for target-command execution. The kernel's
// runtime rules — network: NONE and filesystem: READ_ONLY — are enforced by
// the operating system, not by environment hygiene:
//
//   darwin: sandbox-exec with an SBPL profile that denies network* and
//   file-write* (device-file exceptions only), plus process-fork denial when
//   the contract's process ceiling is 1.
//
// The backend is probed once per process by actually attempting a sandboxed
// execution. If no enforcing backend is available, execution FAILS CLOSED:
// no target command runs, and evaluation blocks with SANDBOX_UNAVAILABLE.
// A process ceiling above 1 cannot be exactly enforced by this backend and
// is likewise refused rather than assumed.

export class SandboxUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = "SandboxUnavailableError";
    this.reasonCode = "SANDBOX_UNAVAILABLE";
  }
}

// Write access is limited to device files processes need for basic
// operation; stdout/stderr are inherited pipes and are unaffected.
function darwinProfile({ singleProcess }) {
  const rules = [
    "(version 1)",
    "(allow default)",
    "(deny network*)",
    "(deny file-write*)",
    '(allow file-write-data (literal "/dev/null") (literal "/dev/dtracehelper") (literal "/dev/tty"))',
    '(allow file-write* (subpath "/dev/fd"))'
  ];
  if (singleProcess) rules.push("(deny process-fork)");
  return rules.join("");
}

let probed = null;

function probeBackend() {
  if (process.platform !== "darwin") {
    return { available: false, reason: `no enforcing sandbox backend is implemented for ${process.platform}` };
  }
  // The full profile must still permit a trivial process to run.
  const trivial = spawnSync("sandbox-exec", ["-p", darwinProfile({ singleProcess: true }), "/usr/bin/true"], {
    encoding: "utf8",
    timeout: 10_000,
    windowsHide: true,
    env: { PATH: process.env.PATH }
  });
  if (trivial.error || trivial.status !== 0) {
    return { available: false, reason: `sandbox-exec probe failed: ${trivial.error ?? trivial.stderr}` };
  }
  // Network denial must demonstrably fail a bind attempt: the probe exits 0
  // only if the bind SUCCEEDS, so anything other than a clean nonzero exit
  // means the backend cannot be trusted.
  const bindScript =
    'const s=require("node:net").createServer();s.on("error",()=>process.exit(1));s.listen(0,()=>process.exit(0));setTimeout(()=>process.exit(2),5000);';
  const netProbe = spawnSync(
    "sandbox-exec",
    ["-p", "(version 1)(allow default)(deny network*)", process.execPath, "-e", bindScript],
    { encoding: "utf8", timeout: 15_000, windowsHide: true, env: { PATH: process.env.PATH } }
  );
  if (netProbe.error || netProbe.status !== 1) {
    return { available: false, reason: "sandbox-exec did not demonstrably block a network bind; refusing to trust it" };
  }
  return { available: true, reason: null };
}

export function sandboxStatus() {
  if (probed === null) probed = probeBackend();
  return probed;
}

// Wraps an exact argv for isolated execution. Throws SandboxUnavailableError
// when isolation cannot be enforced — including a process ceiling this
// backend cannot cap exactly.
export function isolateArgv(argv, { maxProcesses }) {
  const status = sandboxStatus();
  if (!status.available) {
    throw new SandboxUnavailableError(`target-command isolation unavailable: ${status.reason}`);
  }
  if (!Number.isSafeInteger(maxProcesses) || maxProcesses < 1) {
    throw new SandboxUnavailableError("a positive process ceiling is required");
  }
  if (maxProcesses !== 1) {
    throw new SandboxUnavailableError(
      `this backend cannot enforce a process ceiling of ${maxProcesses}; only maxProcesses: 1 (fork denial) is enforceable`
    );
  }
  return ["sandbox-exec", "-p", darwinProfile({ singleProcess: true }), ...argv];
}

// Test seam: force a probe result. Passing null re-probes on next use.
export function overrideSandboxProbe(result) {
  probed = result;
}
