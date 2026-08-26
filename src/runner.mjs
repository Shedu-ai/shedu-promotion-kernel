import { spawnSync } from "node:child_process";
import { digestOfBytes } from "./canonical-json.mjs";
import { isSecretEnvName, validateValue } from "./contracts.mjs";

// Exact-argv target-command runner. Never a shell: argv[0] is the executable
// and every element is passed byte-for-byte. The environment is constructed
// from scratch — PATH, explicitly allowlisted names copied from the host,
// and kernel-injected variables — so ambient secrets are never inherited.
// No network is granted (the runner adds nothing that enables it, and no
// proxy configuration survives the clean environment). Execution is bounded
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
  timeoutSeconds,
  maxOutputBytes
}) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((a) => typeof a !== "string" || a.length === 0)) {
    throw new Error("argv must be a non-empty array of non-empty strings");
  }
  if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds < 1) {
    throw new Error("timeoutSeconds must be a positive integer");
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1) {
    throw new Error("maxOutputBytes must be a positive integer");
  }

  const env = buildCleanEnvironment({ envAllowlist, injectEnv });
  const spawned = spawnSync(argv[0], argv.slice(1), {
    cwd,
    env,
    shell: false,
    windowsHide: true,
    timeout: timeoutSeconds * 1000,
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
