import { readdirSync, readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const SUPERVISOR_REPORT_MAGIC = "\n\u001eSHEDU_PROCESS_REPORT_V1:";

function integerEnv(name, minimum, maximum) {
  const value = Number(process.env[name]);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} is outside its closed integer bounds`);
  }
  return value;
}

export function parsePidsEvents(text) {
  const entries = Object.fromEntries(
    String(text)
      .trim()
      .split("\n")
      .map((line) => line.trim().split(/\s+/))
      .filter((parts) => parts.length === 2)
      .map(([name, value]) => [name, Number(value)])
  );
  if (!Number.isSafeInteger(entries.max) || entries.max < 0) {
    throw new Error("pids.events did not contain a valid max counter");
  }
  return entries;
}

function readTaskState() {
  const applied = readFileSync("/sys/fs/cgroup/pids.max", "utf8").trim();
  const events = parsePidsEvents(readFileSync("/sys/fs/cgroup/pids.events", "utf8"));
  return { applied, maxEvents: events.max };
}

function targetArgv() {
  const separator = process.argv.indexOf("--", 2);
  const argv = separator === -1 ? [] : process.argv.slice(separator + 1);
  if (argv.length < 1 || argv.some((arg) => typeof arg !== "string" || arg.length === 0)) {
    throw new Error("the supervisor requires an exact non-empty target argv after --");
  }
  if (argv[0] !== "/usr/local/bin/node") {
    throw new Error("the bounded supervisor admits only the pinned in-image Node executable");
  }
  return argv;
}

function targetEnvironment() {
  return Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("SHEDU_INTERNAL_"))
  );
}

function remainingContainerPids() {
  return readdirSync("/proc")
    .filter((name) => /^[0-9]+$/.test(name))
    .map(Number)
    .filter((pid) => pid > 1);
}

async function terminateDescendants() {
  for (let round = 0; round < 50; round += 1) {
    const pids = remainingContainerPids();
    if (pids.length === 0) return;
    for (const pid of pids) {
      try {
        process.kill(pid, "SIGKILL");
      } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  if (remainingContainerPids().length > 0) throw new Error("descendants remained after bounded termination");
}

function writeFinalReport(report) {
  const encoded = Buffer.from(JSON.stringify(report), "utf8").toString("base64url");
  process.stdout.write(`${SUPERVISOR_REPORT_MAGIC}${encoded}\n`);
}

export async function supervise() {
  if (process.pid !== 1) throw new Error("the process-tree supervisor must be container PID 1");
  const executionClass = process.env.SHEDU_INTERNAL_EXECUTION_CLASS;
  if (executionClass !== "BOUNDED_PROCESS_TREE") throw new Error("the supervisor admits only BOUNDED_PROCESS_TREE");
  const maxTasks = integerEnv("SHEDU_INTERNAL_MAX_TASKS", 65, 512);
  const maxOutputBytes = integerEnv("SHEDU_INTERNAL_MAX_OUTPUT_BYTES", 1, 1073741824);
  const before = readTaskState();
  if (before.applied !== String(maxTasks)) {
    throw new Error(`pids.max readback mismatch: required ${maxTasks}, found ${before.applied}`);
  }

  const argv = targetArgv();
  const child = spawn(argv[0], argv.slice(1), {
    cwd: process.cwd(),
    env: targetEnvironment(),
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdoutBytes = 0;
  let stderrBytes = 0;
  let outputExceeded = false;
  const forward = (stream, destination, channel) => {
    stream.on("data", (chunk) => {
      const used = channel === "stdout" ? stdoutBytes : stderrBytes;
      const remaining = Math.max(0, maxOutputBytes - used);
      if (remaining > 0) destination.write(chunk.subarray(0, remaining));
      if (channel === "stdout") stdoutBytes += Math.min(chunk.length, remaining);
      else stderrBytes += Math.min(chunk.length, remaining);
      if (chunk.length > remaining && !outputExceeded) {
        outputExceeded = true;
        child.kill("SIGKILL");
      }
    });
  };
  forward(child.stdout, process.stdout, "stdout");
  forward(child.stderr, process.stderr, "stderr");

  const completed = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (exitCode, signal) => resolve({ exitCode, signal }));
  });
  await terminateDescendants();
  const after = readTaskState();
  const limitEvents = Math.max(0, after.maxEvents - before.maxEvents);
  writeFinalReport({
    schemaVersion: "process-resource-report@1",
    class: executionClass,
    maxTasks,
    limitFired: limitEvents > 0,
    limitEvents,
    outputExceeded,
    exitCode: completed.exitCode,
    signal: completed.signal
  });
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  supervise().catch((error) => {
    process.stderr.write(`process-tree supervisor failed: ${String(error)}\n`);
    process.exitCode = 70;
  });
}
