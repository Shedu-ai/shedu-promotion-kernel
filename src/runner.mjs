import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { digestOfBytes } from "./canonical-json.mjs";
import { isReservedInternalEnvName, isSecretEnvName, validateValue } from "./contracts.mjs";
import { isolateExecution } from "./sandbox.mjs";
import { isExecutionRequirement } from "./execution-policy.mjs";
import { kernelToolchain, ToolchainError } from "./toolchain.mjs";

// Control point: output ceiling is enforced here by clamping captured bytes.
export const CONTROL_POINTS = Object.freeze(["command-output-ceiling"]);

// Exact-argv target-command runner. Never a shell: the DECLARED argv is
// preserved byte-for-byte in the command report, while the EXECUTABLE is
// resolved through the closed toolchain authority (never ambient PATH), its
// content digest verified immediately before execution, and the concrete
// absolute executable used as transport. Every command executes inside the
// mandatory OS sandbox (no network, default-deny reads confined to the
// executable file + declared roots, read-only FS, fork denial). The
// environment is constructed from scratch so ambient secrets are never
// inherited. Execution is bounded by the remaining evaluation budget (ms) and
// an output byte ceiling; the result is a schema-validated command-report@1.

const ENV_NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

export function buildCleanEnvironment({ envAllowlist = [], injectEnv = {}, hostEnv = process.env } = {}) {
  const env = { PATH: hostEnv.PATH ?? "" };
  for (const name of envAllowlist) {
    if (!ENV_NAME_RE.test(name) || isSecretEnvName(name) || isReservedInternalEnvName(name)) {
      throw new Error(`environment name ${JSON.stringify(name)} is not an allowlistable name`);
    }
    if (Object.hasOwn(hostEnv, name)) env[name] = hostEnv[name];
  }
  for (const [name, value] of Object.entries(injectEnv)) {
    if (!ENV_NAME_RE.test(name) || isReservedInternalEnvName(name)) {
      throw new Error(`injected environment name ${JSON.stringify(name)} is invalid`);
    }
    env[name] = value;
  }
  return env;
}

function streamReport(bytes, overflowed) {
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
  executionRequirement = null,
  readRoots = [],
  readFiles = [],
  toolchain = kernelToolchain()
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
  if (executionRequirement !== null && !isExecutionRequirement(executionRequirement)) {
    throw new Error("executionRequirement must be a closed execution requirement");
  }

  // Resolve the executable through the closed toolchain and verify its
  // content digest immediately before execution. An unadmitted executable
  // (bare non-node, PATH-poisoned node, user-dir or mutable external path) is
  // refused here; nothing runs unresolved.
  let resolved;
  try {
    resolved = toolchain.resolve(argv[0]);
    toolchain.verify(resolved);
  } catch (error) {
    if (error instanceof ToolchainError) {
      return {
        report: null,
        stdout: Buffer.alloc(0),
        stderr: Buffer.alloc(0),
        spawnFailed: true,
        toolchainRejected: true,
        spawnError: String(error),
        succeeded: false
      };
    }
    throw error;
  }

  const realCwd = realpathSync(cwd);
  const realReadRoots = readRoots.map((r) => realpathSync(r));
  const realReadFiles = readFiles.map((f) => realpathSync(f));

  const env = buildCleanEnvironment({ envAllowlist, injectEnv });
  const isolated = isolateExecution({
    executablePath: resolved.path,
    argvTail: argv.slice(1),
    maxProcesses,
    execution: executionRequirement,
    maxOutputBytes,
    readRoots: realReadRoots,
    readFiles: realReadFiles,
    cwd: realCwd,
    environment: env
  });
  let spawned;
  let resourceReport = null;
  let supervisorParseFailed = null;
  try {
    spawned = spawnSync(isolated[0], isolated.slice(1), {
      cwd: realCwd,
      env: isolated.spawnEnv ?? env,
      shell: false,
      windowsHide: true,
      timeout: timeoutMs,
      killSignal: "SIGKILL",
      maxBuffer: maxOutputBytes + isolated.maxBufferOverhead,
      encoding: "buffer"
    });
    if (isolated.parseSpawnResult && !spawned.error && spawned.status === 0) {
      try {
        const parsed = isolated.parseSpawnResult(spawned.stdout);
        spawned.stdout = parsed.stdout;
        resourceReport = parsed.resourceReport;
        if (
          resourceReport.class !== executionRequirement.class ||
          resourceReport.maxTasks !== executionRequirement.maxTasks
        ) {
          throw new Error("bounded supervisor report does not match the compiled runtime requirement");
        }
        spawned.status = resourceReport.exitCode;
        spawned.signal = resourceReport.signal;
      } catch (error) {
        supervisorParseFailed = error;
      }
    }
  } finally {
    isolated.cleanup?.();
  }

  const timedOut = spawned.error?.code === "ETIMEDOUT";
  const clamp = (buffer) => {
    const bytes = buffer ?? Buffer.alloc(0);
    return bytes.length > maxOutputBytes
      ? { bytes: bytes.subarray(0, maxOutputBytes), clamped: true }
      : { bytes, clamped: false };
  };
  const stdout = clamp(spawned.stdout);
  const stderr = clamp(spawned.stderr);
  const overflowed = spawned.error?.code === "ENOBUFS" || stdout.clamped || stderr.clamped || resourceReport?.outputExceeded === true;
  const taskBudgetExceeded = resourceReport?.limitFired === true;
  const spawnFailed =
    supervisorParseFailed !== null ||
    (spawned.error !== undefined && !timedOut && spawned.error.code !== "ENOBUFS") ||
    (isolated.parseSpawnResult !== null && resourceReport === null && !timedOut && spawned.error?.code !== "ENOBUFS");
  const report = {
    schemaVersion: executionRequirement === null ? "command-report@1" : "command-report@2",
    commandId,
    phase,
    argv: [...argv],
    executable: { name: resolved.name, digest: resolved.digest },
    exitCode: typeof spawned.status === "number" ? spawned.status & 0xff : null,
    signal: spawned.signal ?? null,
    timedOut,
    stdout: streamReport(stdout.bytes, overflowed),
    stderr: streamReport(stderr.bytes, overflowed),
    ...(executionRequirement === null
      ? {}
      : {
          execution: {
            class: executionRequirement.class,
            maxTasks: executionRequirement.maxTasks,
            capabilityId: isolated.capabilityId,
            portableAuthorityDigest: isolated.portableAuthorityDigest,
            backend: isolated.backend,
            backendAuthorityDigest: isolated.backendAuthorityDigest,
            limitFired: taskBudgetExceeded,
            limitEvents: resourceReport?.limitEvents ?? 0
          }
        })
  };
  const validated = validateValue(executionRequirement === null ? "command-report@1" : "command-report@2", report);
  if (!validated.ok) {
    throw new Error(`runner produced an invalid command report: ${JSON.stringify(validated.errors)}`);
  }
  return {
    report,
    stdout: stdout.bytes,
    stderr: stderr.bytes,
    spawnFailed,
    toolchainRejected: false,
    spawnError: spawnFailed ? String(supervisorParseFailed ?? spawned.error ?? "bounded supervisor failed") : null,
    taskBudgetExceeded,
    resourceReport,
    succeeded: !spawnFailed && !timedOut && !overflowed && !taskBudgetExceeded && spawned.status === 0
  };
}
