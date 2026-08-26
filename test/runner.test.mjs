import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { validateValue } from "../src/contracts.mjs";
import { buildCleanEnvironment, runTargetCommand } from "../src/runner.mjs";
import { overrideSandboxProbe, sandboxStatus } from "../src/sandbox.mjs";

const DEFAULTS = {
  commandId: "probe",
  phase: "CANDIDATE_VALIDATION",
  cwd: process.cwd(),
  timeoutSeconds: 30,
  maxOutputBytes: 1024 * 1024,
  maxProcesses: 1
};

test("hostile argv round-trips byte-for-byte with no shell interpretation", () => {
  const hostile = [
    "a b;rm -rf /",
    "'single quoted'",
    "\"double quoted\"",
    "$(subshell)",
    "`backticks`",
    "über✓ 😀",
    "--",
    "-x",
    "|&&||>out<in",
    "*glob?",
    "$HOME",
    "\nnewline\ttab"
  ];
  const execution = runTargetCommand({
    ...DEFAULTS,
    argv: ["node", "-e", "console.log(JSON.stringify(process.argv.slice(1)))", "--", ...hostile]
  });
  assert.equal(execution.succeeded, true, execution.spawnError ?? "");
  assert.deepEqual(JSON.parse(execution.stdout.toString("utf8")), hostile);
  // The machine report echoes the exact argv, byte for byte.
  assert.deepEqual(execution.report.argv.slice(4), hostile);
  assert.equal(validateValue("command-report@1", execution.report).ok, true);
});

test("a shell-string command is an executable name, never a shell line", () => {
  const execution = runTargetCommand({ ...DEFAULTS, argv: ["echo $HOME && rm -rf /"] });
  assert.equal(execution.succeeded, false);
  // The sandbox launcher fails to exec the nonexistent binary; either way,
  // nothing shell-interprets the string.
  assert.notEqual(execution.report.exitCode, 0);
});

test("the sandbox denies network access to target commands", () => {
  const connect = runTargetCommand({
    ...DEFAULTS,
    argv: [
      "node",
      "-e",
      'const s=require("node:net").connect(80,"127.0.0.1");s.on("error",e=>{console.log("BLOCKED:"+e.code);process.exit(0)});s.on("connect",()=>{console.log("CONNECTED");process.exit(1)});setTimeout(()=>process.exit(1),3000)'
    ]
  });
  assert.equal(connect.succeeded, true, connect.stderr.toString());
  assert.match(connect.stdout.toString(), /BLOCKED:EPERM/);

  const listen = runTargetCommand({
    ...DEFAULTS,
    argv: [
      "node",
      "-e",
      'const s=require("node:net").createServer();s.on("error",e=>{console.log("BLOCKED:"+e.code);process.exit(0)});s.listen(0,()=>{console.log("LISTENING");process.exit(1)})'
    ]
  });
  assert.equal(listen.succeeded, true, listen.stderr.toString());
  assert.match(listen.stdout.toString(), /BLOCKED:EPERM/);
});

test("the sandbox makes the filesystem read-only for target commands", () => {
  const dir = mkdtempSync(join(tmpdir(), "shedu-robox-"));
  const execution = runTargetCommand({
    ...DEFAULTS,
    cwd: dir,
    argv: [
      "node",
      "-e",
      'try{require("node:fs").writeFileSync("attack.txt","x");console.log("WROTE");process.exit(1)}catch(e){console.log("BLOCKED:"+e.code);process.exit(0)}'
    ]
  });
  assert.equal(execution.succeeded, true, execution.stderr.toString());
  assert.match(execution.stdout.toString(), /BLOCKED:EPERM/);
});

test("the process ceiling is enforced: fork denial at 1, refusal above 1", () => {
  const fork = runTargetCommand({
    ...DEFAULTS,
    argv: [
      "node",
      "-e",
      'const r=require("node:child_process").spawnSync("node",["-e","console.log(1)"]);console.log(r.error?("FORK_BLOCKED:"+r.error.code):"FORKED");process.exit(r.error?0:1)'
    ]
  });
  assert.equal(fork.succeeded, true, fork.stderr.toString());
  assert.match(fork.stdout.toString(), /FORK_BLOCKED/);

  // A ceiling this backend cannot enforce exactly is refused, not assumed.
  assert.throws(() => runTargetCommand({ ...DEFAULTS, maxProcesses: 8, argv: ["node", "-e", "process.exit(0)"] }), /process ceiling/);
});

test("execution fails closed when no enforcing sandbox is available", () => {
  overrideSandboxProbe({ available: false, reason: "forced unavailable for test" });
  try {
    assert.throws(
      () => runTargetCommand({ ...DEFAULTS, argv: ["node", "-e", "process.exit(0)"] }),
      (error) => error.reasonCode === "SANDBOX_UNAVAILABLE"
    );
  } finally {
    overrideSandboxProbe(null);
  }
  assert.equal(sandboxStatus().available, true);
});

test("the environment is constructed, not inherited", () => {
  const hostEnv = {
    PATH: process.env.PATH,
    AMBIENT_LEAK: "should never reach the child",
    ANTHROPIC_API_KEY: "sk-ant-secret",
    OPENAI_API_KEY: "sk-secret",
    ALLOWED_SETTING: "visible"
  };
  const env = buildCleanEnvironment({ envAllowlist: ["ALLOWED_SETTING"], hostEnv });
  assert.deepEqual(Object.keys(env).sort(), ["ALLOWED_SETTING", "PATH"]);
  assert.equal(env.ALLOWED_SETTING, "visible");
});

test("secret-named environment names cannot be allowlisted at the runner either", () => {
  for (const name of ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "CLIENT_SECRET", "not-a-name"]) {
    assert.throws(() => buildCleanEnvironment({ envAllowlist: [name] }), /not an allowlistable name/);
  }
});

test("a child process observes only the clean environment", () => {
  process.env.KERNEL_TEST_AMBIENT = "leak-me";
  try {
    const execution = runTargetCommand({
      ...DEFAULTS,
      argv: ["node", "-e", "console.log(JSON.stringify(Object.keys(process.env).sort()))"],
      injectEnv: { KERNEL_INJECTED: "yes" }
    });
    assert.equal(execution.succeeded, true);
    const names = JSON.parse(execution.stdout.toString("utf8"));
    assert.ok(!names.includes("KERNEL_TEST_AMBIENT"));
    assert.ok(names.includes("KERNEL_INJECTED"));
    assert.ok(names.includes("PATH"));
  } finally {
    delete process.env.KERNEL_TEST_AMBIENT;
  }
});

test("timeouts abort the command and are reported", () => {
  const execution = runTargetCommand({
    ...DEFAULTS,
    argv: ["node", "-e", "setInterval(() => {}, 1000)"],
    timeoutSeconds: 1
  });
  assert.equal(execution.succeeded, false);
  assert.equal(execution.report.timedOut, true);
});

test("output beyond the byte ceiling is bounded and reported as truncated", () => {
  const execution = runTargetCommand({
    ...DEFAULTS,
    argv: ["node", "-e", "process.stdout.write('x'.repeat(1024 * 1024))"],
    maxOutputBytes: 4096
  });
  assert.equal(execution.succeeded, false);
  assert.equal(execution.report.stdout.truncated, true);
  assert.ok(execution.stdout.length <= 8192);
});

test("exit codes and signals are captured in the machine report", () => {
  const failing = runTargetCommand({ ...DEFAULTS, argv: ["node", "-e", "process.exit(7)"] });
  assert.equal(failing.succeeded, false);
  assert.equal(failing.report.exitCode, 7);
  assert.equal(failing.report.timedOut, false);
});
