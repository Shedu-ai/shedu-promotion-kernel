#!/usr/bin/env node

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import process from "node:process";
import {
  LINUX_OCI_BOUNDED_SECCOMP_PATH,
  LINUX_OCI_IMAGE,
  LINUX_OCI_NODE_PATH
} from "../src/oci-runtime.mjs";

if (process.platform !== "linux") process.exit(0);

const docker = "/usr/bin/docker";
const root = mkdtempSync(join(tmpdir(), "shedu-spawn-diagnostic-"));
const base = JSON.parse(readFileSync(LINUX_OCI_BOUNDED_SECCOMP_PATH, "utf8"));

function policy({ clone = false, clone3 = false, groups = false, unixIpc = false, processVm = false, allRemoved = false }) {
  const next = structuredClone(base);
  if (clone) {
    next.syscalls = next.syscalls.filter((rule) => !rule.names.includes("clone"));
    next.syscalls.push({ names: ["clone"], action: "SCMP_ACT_ALLOW" });
  }
  if (clone3) {
    next.syscalls = next.syscalls.filter((rule) => !rule.names.includes("clone3"));
    next.syscalls.push({ names: ["clone3"], action: "SCMP_ACT_ALLOW" });
  }
  if (groups) {
    next.syscalls.push({ names: ["setpgid", "setsid"], action: "SCMP_ACT_ALLOW" });
  }
  if (unixIpc) {
    next.syscalls.push(
      { names: ["socketpair"], action: "SCMP_ACT_ALLOW", args: [{ index: 0, value: 1, op: "SCMP_CMP_EQ" }] },
      { names: ["socket"], action: "SCMP_ACT_ALLOW", args: [{ index: 0, value: 1, op: "SCMP_CMP_EQ" }] }
    );
  }
  if (processVm) {
    next.syscalls.push({ names: ["process_vm_readv", "process_vm_writev", "ptrace"], action: "SCMP_ACT_ALLOW" });
  }
  if (allRemoved) {
    next.syscalls.push({
      names: [
        "accept", "accept4", "bind", "connect", "getpeername", "getsockname", "getsockopt", "listen",
        "process_vm_readv", "process_vm_writev", "ptrace", "recv", "recvfrom", "recvmmsg", "recvmmsg_time64",
        "recvmsg", "send", "sendmmsg", "sendmsg", "sendto", "setpgid", "setsid", "setsockopt", "shutdown",
        "socket", "socketcall", "socketpair"
      ],
      action: "SCMP_ACT_ALLOW"
    });
  }
  return next;
}

const variants = [
  ["production", base],
  ["allow-groups", policy({ groups: true })],
  ["allow-clone", policy({ clone: true })],
  ["allow-clone3", policy({ clone3: true })],
  ["allow-clone-and-clone3", policy({ clone: true, clone3: true })],
  ["allow-unix-ipc", policy({ unixIpc: true })],
  ["allow-process-vm", policy({ processVm: true })],
  ["allow-clone-and-groups", policy({ clone: true, groups: true })],
  ["allow-all-removed", policy({ allRemoved: true })],
  ["docker-default", null]
];

const probe = [
  "const {spawnSync}=require('node:child_process');",
  "const r=spawnSync(process.execPath,['-e','process.exit(0)']);",
  "process.stdout.write(JSON.stringify({status:r.status,signal:r.signal,error:r.error&&{code:r.error.code,errno:r.error.errno,syscall:r.error.syscall,path:r.error.path}}));"
].join("");

try {
  for (const [name, profile] of variants) {
    const args = [
      "run", "--rm", "--pull", "never",
      "--network", "none", "--read-only", "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges:true",
      "--pids-limit", "128", "--ipc", "none",
      "--user", `${process.getuid()}:${process.getgid()}`,
      "--entrypoint", LINUX_OCI_NODE_PATH
    ];
    if (profile) {
      const path = join(root, `${name}.json`);
      writeFileSync(path, `${JSON.stringify(profile, null, 2)}\n`);
      args.push("--security-opt", `seccomp=${path}`);
    }
    args.push(LINUX_OCI_IMAGE, "-e", probe);
    const result = spawnSync(docker, args, { encoding: "utf8", timeout: 30_000 });
    process.stdout.write(`${JSON.stringify({
      name,
      dockerStatus: result.status,
      dockerSignal: result.signal,
      dockerError: result.error?.message ?? null,
      stdout: result.stdout.trim(),
      stderr: result.stderr.trim()
    })}\n`);
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}
