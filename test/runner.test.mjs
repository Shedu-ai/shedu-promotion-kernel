import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { validateValue } from "../src/contracts.mjs";
import { buildCleanEnvironment, runTargetCommand } from "../src/runner.mjs";
import { overrideSandboxProbe, sandboxStatus } from "../src/sandbox.mjs";

const DEFAULTS = {
  commandId: "probe",
  phase: "CANDIDATE_VALIDATION",
  cwd: process.cwd(),
  timeoutMs: 30_000,
  maxOutputBytes: 1024 * 1024,
  maxProcesses: 1,
  readRoots: []
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
  // The closed toolchain refuses the string outright — it is not the kernel
  // node — so nothing is spawned and nothing shell-interprets it.
  assert.equal(execution.toolchainRejected, true);
  assert.equal(execution.report, null);
});

test("a poisoned PATH cannot substitute the executable; a mutable external validator is refused", () => {
  // argv[0] "node" always resolves to the KERNEL node regardless of PATH.
  const poisoned = { ...process.env, PATH: `/tmp/evil:${process.env.PATH}` };
  const original = process.env.PATH;
  process.env.PATH = poisoned.PATH;
  try {
    const ok = runTargetCommand({ ...DEFAULTS, argv: ["node", "-e", "process.stdout.write('KERNEL')"] });
    assert.equal(ok.succeeded, true);
    assert.equal(ok.stdout.toString(), "KERNEL");
    assert.match(ok.report.executable.name, /node/);
  } finally {
    process.env.PATH = original;
  }
  // An absolute mutable external path and a home-dir executable are refused.
  for (const p of ["/tmp/mutable-validator", `${process.env.HOME}/evil-node`]) {
    const rejected = runTargetCommand({ ...DEFAULTS, argv: [p] });
    assert.equal(rejected.toolchainRejected, true, p);
  }
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

test("the sandbox denies reads outside declared roots", () => {
  // A candidate read root is granted; a sibling temp file and a home-dir
  // credential fixture are NOT, and reading them is blocked.
  const candDir = mkdtempSync(join(tmpdir(), "shedu-cand-"));
  const siblingDir = mkdtempSync(join(tmpdir(), "shedu-sibling-"));
  writeFileSync(join(candDir, "app.mjs"), "export const app=1;\n");
  writeFileSync(join(siblingDir, "secret.txt"), "HOST_PRIVATE_VALUE_123\n");
  const homeCred = join(homedir(), ".shedu-runner-cred");
  writeFileSync(homeCred, "HOME_CRED\n");
  try {
    const exec = runTargetCommand({
      ...DEFAULTS,
      cwd: candDir,
      readRoots: [candDir],
      injectEnv: { SIB: join(siblingDir, "secret.txt"), CRED: homeCred },
      argv: [
        "node",
        "-e",
        'const fs=require("node:fs");const r=(p)=>{try{fs.readFileSync(p);return "OK"}catch(e){return e.code}};console.log(JSON.stringify({sib:r(process.env.SIB),cred:r(process.env.CRED)}))'
      ]
    });
    assert.equal(exec.succeeded, true, exec.stderr.toString());
    const seen = JSON.parse(exec.stdout.toString());
    assert.match(seen.sib, /^(EPERM|EACCES|ENOENT)$/, "sibling temp file must be unreadable");
    assert.match(seen.cred, /^(EPERM|EACCES|ENOENT)$/, "home credential must be unreadable");
  } finally {
    rmSync(homeCred, { force: true });
    rmSync(candDir, { recursive: true, force: true });
    rmSync(siblingDir, { recursive: true, force: true });
  }
});

test("permitted candidate and base reads succeed under the sandbox", () => {
  const candDir = realpathSync(mkdtempSync(join(tmpdir(), "shedu-cand-")));
  const baseDir = realpathSync(mkdtempSync(join(tmpdir(), "shedu-base-")));
  writeFileSync(join(candDir, "app.mjs"), "CANDIDATE_OK\n");
  writeFileSync(join(baseDir, "lib.mjs"), "BASE_OK\n");
  try {
    const exec = runTargetCommand({
      ...DEFAULTS,
      cwd: candDir,
      readRoots: [candDir, baseDir],
      injectEnv: { C: join(candDir, "app.mjs"), B: join(baseDir, "lib.mjs") },
      argv: [
        "node",
        "-e",
        'const fs=require("node:fs");console.log(fs.readFileSync(process.env.C,"utf8").trim()+"|"+fs.readFileSync(process.env.B,"utf8").trim())'
      ]
    });
    assert.equal(exec.succeeded, true, exec.stderr.toString());
    assert.equal(exec.stdout.toString().trim(), "CANDIDATE_OK|BASE_OK");
  } finally {
    rmSync(candDir, { recursive: true, force: true });
    rmSync(baseDir, { recursive: true, force: true });
  }
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
  assert.match(execution.stdout.toString(), /BLOCKED:(EPERM|EACCES|EROFS)/);
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

test("secret-named and supervisor-reserved environment names cannot be allowlisted at the runner", () => {
  for (const name of ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "CLIENT_SECRET", "SHEDU_INTERNAL_MAX_TASKS", "not-a-name"]) {
    assert.throws(() => buildCleanEnvironment({ envAllowlist: [name] }), /not an allowlistable name/);
  }
  assert.throws(
    () => buildCleanEnvironment({ injectEnv: { SHEDU_INTERNAL_EXECUTION_CLASS: "SINGLE_PROCESS" } }),
    /invalid/
  );
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
    timeoutMs: 1000
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
