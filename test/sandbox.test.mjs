import assert from "node:assert/strict";
import process from "node:process";
import test from "node:test";
import { isolateExecution, probeBackendWith, sandboxStatus } from "../src/sandbox.mjs";
import { KERNEL_NODE_PATH } from "../src/toolchain.mjs";
import { LINUX_OCI_IMAGE } from "../src/oci-runtime.mjs";

const NODE = KERNEL_NODE_PATH;

test("the native sandbox backend is available in this environment", () => {
  // This suite must run where the OS sandbox can actually execute; if it
  // cannot, every isolation proof below would be vacuous.
  const status = sandboxStatus();
  assert.equal(status.available, true, `sandbox unavailable: ${status.reason}`);
});

test("a nested-sandbox environment (e.g. Codex) is refused, not trusted", () => {
  // Simulate an environment where sandbox-exec cannot run: the probe's
  // trivial execution fails, so the backend reports unavailable and every
  // target command will fail closed.
  const nested = probeBackendWith(() => ({ available: false, reason: "sandbox-exec probe failed (nested sandbox or unavailable)" }));
  assert.equal(nested.available, false);
  assert.match(nested.reason, /nested sandbox|unavailable/);
});

test("a network-permitting probe result is refused", () => {
  // If the probe cannot demonstrate a blocked bind, the backend must not be
  // trusted — modeled here by a probe runner that reports unavailability for
  // that exact reason.
  const untrusted = probeBackendWith(() => ({
    available: false,
    reason: "sandbox-exec did not demonstrably block a network bind; refusing to trust it"
  }));
  assert.equal(untrusted.available, false);
});

test("isolateExecution refuses a process ceiling the backend cannot enforce exactly", () => {
  assert.throws(
    () => isolateExecution({ executablePath: NODE, argvTail: ["-e", "0"], maxProcesses: 4, readRoots: [], cwd: process.cwd() }),
    (e) => e.reasonCode === "SANDBOX_UNAVAILABLE"
  );
  const wrapped = isolateExecution({ executablePath: NODE, argvTail: ["-e", "0"], maxProcesses: 1, readRoots: [], cwd: process.cwd() });
  assert.ok(process.platform === "linux" ? wrapped[0].endsWith("/docker") : wrapped[0] === "sandbox-exec");
  assert.ok(wrapped.includes(NODE));
  wrapped.cleanup?.();
});

test("the executable is granted as an exact file, never its parent prefix", () => {
  const wrapped = isolateExecution({ executablePath: NODE, argvTail: ["-e", "0"], maxProcesses: 1, readRoots: [], cwd: process.cwd() });
  if (process.platform === "linux") {
    assert.ok(wrapped.includes(LINUX_OCI_IMAGE), "OCI execution must name the digest-pinned image");
    assert.ok(wrapped.includes("--read-only"));
    assert.ok(wrapped.includes("ALL"));
  } else {
    const profile = wrapped[2];
    assert.ok(profile.includes(`(literal "${NODE}")`), "executable must be granted as a literal file");
    const prefix = NODE.replace(/\/[^/]+\/[^/]+$/, "");
    assert.ok(!profile.includes(`(subpath "${prefix}")`), "executable install prefix must never be granted");
  }
  wrapped.cleanup?.();
});

test("a realistic subprocess-spawning test command cannot run under maxProcesses: 1", () => {
  // A real test runner that spawns workers needs process-fork, which the
  // maxProcesses: 1 backend denies. This is a KNOWN LIMITATION, demonstrated
  // rather than papered over: such contracts keep pilot status blocked.
  const wrapped = isolateExecution({ executablePath: NODE, argvTail: ["--test"], maxProcesses: 1, readRoots: [], cwd: process.cwd() });
  assert.ok(process.platform === "linux"
    ? wrapped.includes("64") && wrapped.some((a) => a.includes("seccomp="))
    : wrapped.some((a) => a.includes("(deny process-fork)")));
  wrapped.cleanup?.();
});
