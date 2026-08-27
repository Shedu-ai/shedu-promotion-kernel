import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { digestOfBytes } from "./canonical-json.mjs";
import { isSecretEnvName, validateValue } from "./contracts.mjs";
import { isolateArgv } from "./sandbox.mjs";

// Control point: output ceiling is enforced here by clamping captured bytes.
export const CONTROL_POINTS = Object.freeze(["command-output-ceiling"]);

// Exact-argv target-command runner. Never a shell: argv[0] is the executable
// and every element is passed byte-for-byte. Every command executes inside
// the mandatory OS sandbox (no network, read-only filesystem, fork denial
// under the process ceiling) — if isolation cannot be enforced, nothing
// runs. The environment is additionally constructed from scratch — PATH,
// explicitly allowlisted names copied from the host, and kernel-injected
// variables — so ambient secrets are never inherited. Execution is bounded
// by a hard timeout and an output byte ceiling, and the result is a
// schema-validated command-report@1 whose argv echo proves preservation.

const ENV_NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

export function buildCleanEnvironment({ envAllowlist = [], injectEnv = {}, hostEnv = process.env } = {}) {
  const env = { PATH: hostEnv.PATH ?? "" };
  for (const name of envAllowlist) {
    if (!ENV_NAME_RE.test(name) || isSecretEnvName(name)) {
      throw new Error(`environment name ${JSON.stringify(name)} is not an allowlistable name`);
    }
    if (Object.hasOwn(hostEnv, name)) env[name] = hostEnv[name];
  }
  for (const [name, value] of Object.entries(injectEnv)) {
    if (!ENV_NAME_RE.test(name)) {
      throw new Error(`injected environment name ${JSON.stringify(name)} is invalid`);
    }
    env[name] = value;
  }
  return env;
}

function streamReport(buffer, overflowed) {
  const bytes = buffer ?? Buffer.alloc(0);
  return {
    digest: digestOfBytes(bytes),
    byteLength: bytes.length,
    truncated: overflowed
  };
}

export function runTargetCommand({
  commandId,
  phase,
  argv,
  cwd,
  envAllowlist = [],
  injectEnv = {},
  timeoutMs,
  maxOutputBytes,
  maxProcesses,
  readRoots = []
}) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((a) => typeof a !== "string" || a.length === 0)) {
    throw new Error("argv must be a non-empty array of non-empty strings");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("timeoutMs must be a positive integer number of milliseconds");
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1) {
    throw new Error("maxOutputBytes must be a positive integer");
  }

  // Canonicalize the working directory and read roots to their real paths so
  // the child never traverses a symlink (e.g. macOS /var -> /private/var)
  // that the sandbox profile does not grant.
  const realCwd = realpathSync(cwd);
  const realReadRoots = readRoots.map((r) => realpathSync(r));

  // The report echoes the exact declared argv; isolation is transport.
  // isolateArgv throws SandboxUnavailableError when enforcement is
  // impossible — nothing runs unsandboxed.
  const isolated = isolateArgv(argv, { maxProcesses, readRoots: realReadRoots, cwd: realCwd });
  const env = buildCleanEnvironment({ envAllowlist, injectEnv });
  // The child is bounded by the remaining evaluation budget, in
  // milliseconds — never a rounded-up fresh timeout.
  const spawned = spawnSync(isolated[0], isolated.slice(1), {
    cwd: realCwd,
    env,
    shell: false,
    windowsHide: true,
    timeout: timeoutMs,
    killSignal: "SIGKILL",
    maxBuffer: maxOutputBytes,
    encoding: "buffer"
  });

  const timedOut = spawned.error?.code === "ETIMEDOUT";
  // spawnSync kills at maxBuffer but the captured buffer can exceed the
  // ceiling by up to one pipe read; the bound is enforced here by clamping.
  const clamp = (buffer) => {
    const bytes = buffer ?? Buffer.alloc(0);
    return bytes.length > maxOutputBytes
      ? { bytes: bytes.subarray(0, maxOutputBytes), clamped: true }
      : { bytes, clamped: false };
  };
  const stdout = clamp(spawned.stdout);
  const stderr = clamp(spawned.stderr);
  const overflowed = spawned.error?.code === "ENOBUFS" || stdout.clamped || stderr.clamped;
  const spawnFailed = spawned.error !== undefined && !timedOut && spawned.error.code !== "ENOBUFS";
  const report = {
    schemaVersion: "command-report@1",
    commandId,
    phase,
    argv: [...argv],
    exitCode: typeof spawned.status === "number" ? spawned.status & 0xff : null,
    signal: spawned.signal ?? null,
    timedOut,
    stdout: streamReport(stdout.bytes, overflowed),
    stderr: streamReport(stderr.bytes, overflowed)
  };
  const validated = validateValue("command-report@1", report);
  if (!validated.ok) {
    throw new Error(`runner produced an invalid command report: ${JSON.stringify(validated.errors)}`);
  }
  return {
    report,
    stdout: stdout.bytes,
    stderr: stderr.bytes,
    spawnFailed,
    spawnError: spawnFailed ? String(spawned.error) : null,
    succeeded: !spawnFailed && !timedOut && !overflowed && spawned.status === 0
  };
}
