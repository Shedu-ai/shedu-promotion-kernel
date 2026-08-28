import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { digestOfBytes, digestOfCanonical } from "../src/canonical-json.mjs";
import {
  LINUX_OCI_IMAGE,
  LINUX_OCI_IMAGE_DIGEST,
  LINUX_OCI_BOUNDED_SECCOMP_PATH,
  LINUX_OCI_NODE_PATH,
  LINUX_OCI_SUPERVISOR_CONTAINER_PATH,
  ociHostEnvironment,
  portableLinuxExecutionAuthority
} from "../src/oci-runtime.mjs";
import {
  LINUX_BOUNDED_CHILD_PROBE_SCRIPT,
  buildLinuxOciInvocation,
  formatLinuxBoundedProbeFailure,
  parseLinuxSupervisorOutput
} from "../src/sandbox.mjs";
import { EXECUTION_PRESETS } from "../src/execution-policy.mjs";
import { SUPERVISOR_REPORT_MAGIC, parsePidsEvents } from "../src/process-tree-supervisor.mjs";

const AUTHORITY = {
  runtime: { path: "/usr/bin/docker", digest: `sha256:${"1".repeat(64)}` },
  image: {
    reference: LINUX_OCI_IMAGE,
    indexDigest: LINUX_OCI_IMAGE_DIGEST,
    imageId: `sha256:${"2".repeat(64)}`
  },
  seccompDigests: {
    strict: `sha256:${"3".repeat(64)}`,
    bounded: `sha256:${"4".repeat(64)}`
  },
  supervisorDigest: `sha256:${"5".repeat(64)}`,
  authorityDigest: digestOfCanonical({ test: "authority" })
};

test("the Linux image authority is an immutable OCI digest, never a tag", () => {
  assert.match(LINUX_OCI_IMAGE_DIGEST, /^sha256:[0-9a-f]{64}$/);
  assert.equal(LINUX_OCI_IMAGE, `docker.io/library/node@${LINUX_OCI_IMAGE_DIGEST}`);
  assert.ok(!/library\/node:/.test(LINUX_OCI_IMAGE), "the image reference must not contain a mutable tag");
});

test("the bounded readiness artifact is executable exact JavaScript", () => {
  assert.ok(!LINUX_BOUNDED_CHILD_PROBE_SCRIPT.includes("process.exit("));
  assert.ok(LINUX_BOUNDED_CHILD_PROBE_SCRIPT.includes("process.exitCode="));
  assert.ok(LINUX_BOUNDED_CHILD_PROBE_SCRIPT.includes("!r.error"));
  assert.ok(LINUX_BOUNDED_CHILD_PROBE_SCRIPT.includes("stderr:String(r.stderr"));
  assert.ok(LINUX_BOUNDED_CHILD_PROBE_SCRIPT.includes("writeSync(1"));
  const result = spawnSync(process.execPath, ["-e", LINUX_BOUNDED_CHILD_PROBE_SCRIPT], {
    encoding: "utf8",
    timeout: 5_000
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "CHILD");
});

test("bounded readiness failures retain all machine fields when stderr is empty", () => {
  const reason = formatLinuxBoundedProbeFailure({
    status: 70,
    signal: null,
    stdout: "target-evidence",
    stderr: "",
    resourceReport: { limitFired: true }
  });
  assert.deepEqual(JSON.parse(reason.slice(reason.indexOf("{")).trim()), {
    error: null,
    status: 70,
    signal: null,
    stdout: "target-evidence",
    stderr: "",
    resourceReport: { limitFired: true }
  });
});

test("the OCI transport preserves exact argv and never places environment values in argv", () => {
  const hostile = ["a b", "$(subshell)", "semi;colon", "quotes'\"", "unicode-✓", "--", "x,y"];
  const invocation = buildLinuxOciInvocation({
    authority: AUTHORITY,
    executablePath: LINUX_OCI_NODE_PATH,
    argvTail: hostile,
    readRoots: ["/tmp/candidate"],
    readFiles: [],
    cwd: "/tmp/candidate",
    environment: { PATH: "/poison", SAFE_SETTING: "value that must stay out of argv", TOKENISH_PUBLIC_NAME: "public-mode" },
    containerName: "shedu-kernel-test"
  });
  const imageIndex = invocation.indexOf(LINUX_OCI_IMAGE);
  assert.ok(imageIndex > 0);
  assert.deepEqual(invocation.slice(imageIndex + 1), hostile);
  const entrypointIndex = invocation.indexOf("--entrypoint");
  assert.equal(invocation[entrypointIndex + 1], LINUX_OCI_NODE_PATH);
  assert.ok(!invocation.includes("value that must stay out of argv"));
  assert.ok(invocation.includes("SAFE_SETTING"));
  assert.equal(invocation.spawnEnv.SAFE_SETTING, "value that must stay out of argv");
  assert.equal(invocation.spawnEnv.PATH, "/usr/bin:/bin");
  assert.equal(invocation.backend, "linux-oci");
});

test("the OCI launch is fail-closed and fully hardened before the pinned image", () => {
  const invocation = buildLinuxOciInvocation({
    authority: AUTHORITY,
    executablePath: LINUX_OCI_NODE_PATH,
    argvTail: ["-e", "0"],
    readRoots: ["/tmp/candidate"],
    readFiles: [],
    cwd: "/tmp/candidate",
    environment: {},
    containerName: "shedu-kernel-test"
  });
  const preImage = invocation.slice(0, invocation.indexOf(LINUX_OCI_IMAGE));
  for (const required of ["--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--pids-limit", "64", "--ipc", "none"]) {
    assert.ok(preImage.includes(required), required);
  }
  assert.ok(preImage.includes("no-new-privileges:true"));
  assert.ok(preImage.some((arg) => arg.includes("seccomp=")));
  assert.ok(!preImage.includes("pull"), "evaluation must never pull an image");
});

test("mount delimiter injection and an unpinned image authority are rejected", () => {
  const common = {
    authority: AUTHORITY,
    executablePath: LINUX_OCI_NODE_PATH,
    argvTail: ["-e", "0"],
    readFiles: [],
    cwd: "/tmp/candidate",
    environment: {},
    containerName: "shedu-kernel-test"
  };
  assert.throws(() => buildLinuxOciInvocation({ ...common, readRoots: ["/tmp/evil,dst=/host"] }), /cannot be represented/);
  assert.throws(
    () => buildLinuxOciInvocation({ ...common, authority: { ...AUTHORITY, image: { ...AUTHORITY.image, reference: "node:22" } }, readRoots: ["/tmp/candidate"] }),
    /does not name the pinned image/
  );
});

test("ambient Docker authority variables cannot replace the fixed local daemon", () => {
  const env = ociHostEnvironment({
    PATH: "/tmp/evil",
    HOME: "/tmp/evil-home",
    DOCKER_CONFIG: "/tmp/evil-config",
    DOCKER_HOST: "tcp://attacker.invalid:2375",
    SAFE_SETTING: "retained"
  });
  assert.equal(env.PATH, "/usr/bin:/bin");
  assert.equal(env.HOME, "/nonexistent");
  assert.equal(env.DOCKER_CONFIG, "/nonexistent");
  assert.equal(env.DOCKER_HOST, "unix:///var/run/docker.sock");
  assert.equal(env.SAFE_SETTING, "retained");
});

test("the checked-in seccomp policy mechanically denies network and process creation", () => {
  const policy = JSON.parse(readFileSync(new URL("../security/linux-seccomp.json", import.meta.url), "utf8"));
  const provenance = JSON.parse(readFileSync(new URL("../security/linux-seccomp.provenance.json", import.meta.url), "utf8"));
  assert.equal(provenance.upstreamCommit, "3c28324314729dbade8287e868eef6338c42807a");
  assert.equal(provenance.derivedPolicy, "linux-seccomp.json");
  assert.equal(policy.defaultAction, "SCMP_ACT_ERRNO");
  const unconditionalAllow = new Set(
    policy.syscalls
      .filter((rule) => rule.action === "SCMP_ACT_ALLOW" && !rule.args && !rule.includes)
      .flatMap((rule) => rule.names)
  );
  for (const syscall of ["socket", "connect", "bind", "listen", "fork", "vfork", "mount", "unshare", "ptrace", "process_vm_readv", "process_vm_writev"]) {
    assert.ok(!unconditionalAllow.has(syscall), syscall);
  }
  const clone = policy.syscalls.find((rule) => rule.names.includes("clone"));
  assert.equal(clone.action, "SCMP_ACT_ALLOW");
  assert.deepEqual(clone.args, [{ index: 0, value: 65536, valueTwo: 65536, op: "SCMP_CMP_MASKED_EQ" }]);
  const clone3 = policy.syscalls.find((rule) => rule.names.includes("clone3"));
  assert.equal(clone3.action, "SCMP_ACT_ERRNO");
  assert.equal(clone3.errnoRet, 38);
});

test("bounded OCI execution preserves target argv behind a pinned PID-1 supervisor", () => {
  const target = ["-e", "process.exit(0)", "a b", "$(not-shell)"];
  const invocation = buildLinuxOciInvocation({
    authority: AUTHORITY,
    executablePath: LINUX_OCI_NODE_PATH,
    argvTail: target,
    readRoots: ["/tmp/candidate"],
    readFiles: [],
    cwd: "/tmp/candidate",
    environment: { PUBLIC_SETTING: "not-in-argv" },
    execution: EXECUTION_PRESETS.STANDARD_TEST,
    maxOutputBytes: 4096,
    containerName: "shedu-kernel-bounded-test"
  });
  const imageIndex = invocation.indexOf(LINUX_OCI_IMAGE);
  assert.deepEqual(
    invocation.slice(imageIndex + 1),
    [LINUX_OCI_SUPERVISOR_CONTAINER_PATH, "--", LINUX_OCI_NODE_PATH, ...target]
  );
  assert.equal(invocation[invocation.indexOf("--pids-limit") + 1], "128");
  assert.ok(invocation.includes(`seccomp=${LINUX_OCI_BOUNDED_SECCOMP_PATH}`));
  assert.ok(invocation.some((arg) => arg.includes("process-tree-supervisor.mjs")));
  assert.equal(invocation.spawnEnv.SHEDU_INTERNAL_EXECUTION_CLASS, "BOUNDED_PROCESS_TREE");
  assert.equal(invocation.spawnEnv.SHEDU_INTERNAL_MAX_TASKS, "128");
  assert.equal(invocation.spawnEnv.PUBLIC_SETTING, "not-in-argv");
  assert.ok(!invocation.includes("not-in-argv"));
  assert.equal(invocation.parseSpawnResult, parseLinuxSupervisorOutput);
  assert.equal(invocation.capabilityId, "bounded-process-tree@1");
  assert.equal(
    invocation.portableAuthorityDigest,
    portableLinuxExecutionAuthority("BOUNDED_PROCESS_TREE").portableAuthorityDigest
  );
});

test("the bounded seccomp authority allows ordinary children but not namespaces or group escape", () => {
  const policyUrl = new URL("../security/linux-seccomp-bounded.json", import.meta.url);
  const policyBytes = readFileSync(policyUrl);
  const policy = JSON.parse(policyBytes);
  const provenance = JSON.parse(readFileSync(new URL("../security/linux-seccomp-bounded.provenance.json", import.meta.url), "utf8"));
  assert.equal(provenance.derivedDigest, digestOfBytes(policyBytes));
  assert.equal(provenance.sourceDigest, digestOfBytes(readFileSync(new URL("../security/linux-seccomp.json", import.meta.url))));
  assert.equal(provenance.generatorDigest, digestOfBytes(readFileSync(new URL("../scripts/generate-bounded-seccomp.mjs", import.meta.url))));
  const unconditional = new Set(
    policy.syscalls
      .filter((rule) => rule.action === "SCMP_ACT_ALLOW" && !rule.args && !rule.includes)
      .flatMap((rule) => rule.names)
  );
  assert.ok(unconditional.has("fork"));
  assert.ok(unconditional.has("vfork"));
  for (const syscall of ["unshare", "setns", "setpgid", "setsid", "socket", "socketpair", "connect", "bind", "listen"]) {
    assert.ok(!unconditional.has(syscall), syscall);
  }
  const socketpair = policy.syscalls.find((rule) => rule.names.length === 1 && rule.names[0] === "socketpair");
  assert.equal(socketpair.action, "SCMP_ACT_ALLOW");
  assert.deepEqual(socketpair.args, [{ index: 0, value: 1, op: "SCMP_CMP_EQ" }]);
  const shutdown = policy.syscalls.find((rule) => rule.names.length === 1 && rule.names[0] === "shutdown");
  assert.equal(shutdown.action, "SCMP_ACT_ALLOW");
  assert.equal(shutdown.args, undefined);
  assert.match(shutdown.comment, /cannot create or connect/);
  const clone = policy.syscalls.find((rule) => rule.names.length === 1 && rule.names[0] === "clone");
  assert.equal(clone.args[0].op, "SCMP_CMP_MASKED_EQ");
  assert.ok(clone.args[0].value > 0, "value is the namespace-bit mask");
  assert.equal(clone.args[0].valueTwo, 0, "valueTwo is the required masked result");
  const clone3 = policy.syscalls.find((rule) => rule.names.includes("clone3"));
  assert.equal(clone3.action, "SCMP_ACT_ERRNO");
});

test("only the final supervisor frame is authoritative and target bytes round-trip", () => {
  const forged = `${SUPERVISOR_REPORT_MAGIC}${Buffer.from('{"fake":true}').toString("base64url")}\n`;
  const genuine = {
    schemaVersion: "process-resource-report@1",
    class: "BOUNDED_PROCESS_TREE",
    maxTasks: 128,
    limitFired: false,
    limitEvents: 0,
    outputExceeded: false,
    exitCode: 0,
    signal: null
  };
  const payload = Buffer.concat([
    Buffer.from(`target-before${forged}target-after`),
    Buffer.from(`${SUPERVISOR_REPORT_MAGIC}${Buffer.from(JSON.stringify(genuine)).toString("base64url")}\n`)
  ]);
  const parsed = parseLinuxSupervisorOutput(payload);
  assert.equal(parsed.stdout.toString(), `target-before${forged}target-after`);
  assert.deepEqual(parsed.resourceReport, genuine);
  assert.throws(() => parseLinuxSupervisorOutput(Buffer.from("target only")), /no resource report/);
  assert.deepEqual(parsePidsEvents("max 3\n"), { max: 3 });
});
