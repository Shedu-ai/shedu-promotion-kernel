import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { digestOfCanonical } from "../src/canonical-json.mjs";
import {
  LINUX_OCI_IMAGE,
  LINUX_OCI_IMAGE_DIGEST,
  LINUX_OCI_NODE_PATH,
  ociHostEnvironment
} from "../src/oci-runtime.mjs";
import { buildLinuxOciInvocation } from "../src/sandbox.mjs";

const AUTHORITY = {
  runtime: { path: "/usr/bin/docker", digest: `sha256:${"1".repeat(64)}` },
  image: {
    reference: LINUX_OCI_IMAGE,
    indexDigest: LINUX_OCI_IMAGE_DIGEST,
    imageId: `sha256:${"2".repeat(64)}`
  },
  authorityDigest: digestOfCanonical({ test: "authority" })
};

test("the Linux image authority is an immutable OCI digest, never a tag", () => {
  assert.match(LINUX_OCI_IMAGE_DIGEST, /^sha256:[0-9a-f]{64}$/);
  assert.equal(LINUX_OCI_IMAGE, `docker.io/library/node@${LINUX_OCI_IMAGE_DIGEST}`);
  assert.ok(!/library\/node:/.test(LINUX_OCI_IMAGE), "the image reference must not contain a mutable tag");
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
