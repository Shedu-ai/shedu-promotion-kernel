#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const sourceUrl = new URL("../security/linux-seccomp.json", import.meta.url);
const targetUrl = new URL("../security/linux-seccomp-bounded.json", import.meta.url);
const policy = JSON.parse(readFileSync(sourceUrl, "utf8"));

const forbiddenGroupSyscalls = new Set(["setpgid", "setsid"]);
const rewritten = [];
for (const rule of policy.syscalls) {
  if (rule.names.includes("clone") || rule.names.includes("clone3")) continue;
  const names = rule.names.filter((name) => !forbiddenGroupSyscalls.has(name));
  if (names.length > 0) rewritten.push({ ...rule, names });
}

// Namespace flags must remain zero. clone3 is forced to ENOSYS so libc falls
// back to clone, whose scalar flags seccomp can inspect.
const namespaceMask =
  0x00000080 | // CLONE_NEWTIME
  0x00020000 | // CLONE_NEWNS
  0x02000000 | // CLONE_NEWCGROUP
  0x04000000 | // CLONE_NEWUTS
  0x08000000 | // CLONE_NEWIPC
  0x10000000 | // CLONE_NEWUSER
  0x20000000 | // CLONE_NEWPID
  0x40000000;  // CLONE_NEWNET

rewritten.push(
  {
    names: ["shutdown"],
    action: "SCMP_ACT_ALLOW",
    comment: "Allow libuv to half-close an existing AF_UNIX child-process transport; shutdown cannot create or connect a socket."
  },
  {
    names: ["socketpair"],
    action: "SCMP_ACT_ALLOW",
    args: [{ index: 0, value: 1, op: "SCMP_CMP_EQ" }],
    comment: "Allow only AF_UNIX socketpairs required by libuv child-process transport; Internet socket families remain denied."
  },
  {
    names: ["clone"],
    action: "SCMP_ACT_ALLOW",
    // OCI/libseccomp encodes MASKED_EQ as (argument & value) == valueTwo.
    // `value` is therefore the namespace-bit mask and `valueTwo` is the
    // required zero result. Reversing these operands denies every clone.
    args: [{ index: 0, value: namespaceMask, valueTwo: 0, op: "SCMP_CMP_MASKED_EQ" }],
    comment: "Allow threads and child processes only when every namespace-creation flag is zero."
  },
  {
    names: ["fork", "vfork"],
    action: "SCMP_ACT_ALLOW",
    comment: "Bounded by cgroup pids.max; the PID-1 supervisor records every limit-fire event."
  },
  {
    names: ["clone3"],
    action: "SCMP_ACT_ERRNO",
    errnoRet: 38,
    comment: "Force libc to clone so namespace flags remain mechanically inspectable."
  }
);

policy.syscalls = rewritten;
const sourceBytes = readFileSync(sourceUrl);
const derivedBytes = Buffer.from(`${JSON.stringify(policy, null, 2)}\n`, "utf8");
writeFileSync(targetUrl, derivedBytes);
const digest = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const generatorUrl = new URL(import.meta.url);
const provenance = {
  schemaVersion: "derived-seccomp-provenance@1",
  sourcePolicy: "linux-seccomp.json",
  sourceDigest: digest(sourceBytes),
  generator: "../scripts/generate-bounded-seccomp.mjs",
  generatorDigest: digest(readFileSync(generatorUrl)),
  derivedPolicy: "linux-seccomp-bounded.json",
  derivedDigest: digest(derivedBytes)
};
writeFileSync(new URL("../security/linux-seccomp-bounded.provenance.json", import.meta.url), `${JSON.stringify(provenance, null, 2)}\n`);
