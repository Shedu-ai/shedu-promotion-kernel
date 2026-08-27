import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import { kernelToolchain, fileToolchain, ToolchainError, KERNEL_NODE_PATH } from "../src/toolchain.mjs";
import { targetValidatorDigest, isResolvableTargetExecutable } from "../src/validator-digest.mjs";
import { runTargetCommand } from "../src/runner.mjs";
import { commitAll, makeGitRepo, writeRepoFile } from "./fixtures.mjs";

// ---- Finding 1: closed toolchain, no PATH/prefix authority ----------------

test("the kernel node resolves and runs; unadmitted executables are refused", () => {
  const tc = kernelToolchain();
  const node = tc.resolve("node");
  assert.equal(node.path, KERNEL_NODE_PATH);
  assert.equal(node.name, "node");
  assert.match(node.digest, /^sha256:[0-9a-f]{64}$/);
  for (const bad of ["/tmp/mutable-validator", `${process.env.HOME}/evil-node`, "python", "sh", "not-node"]) {
    assert.throws(() => tc.resolve(bad), (e) => e instanceof ToolchainError, bad);
    assert.equal(isResolvableTargetExecutable(bad), false, bad);
  }
  assert.equal(isResolvableTargetExecutable("node"), true);
});

test("a changed executable digest blocks before execution", () => {
  // A small fake executable copied and then mutated: verify() re-hashes and
  // fails closed on drift, BEFORE the command runs.
  const dir = mkdtempSync(join(tmpdir(), "shedu-exe-"));
  const exe = join(dir, "fake-node");
  writeFileSync(exe, "#!/bin/sh\necho version-one\n");
  chmodSync(exe, 0o755);
  const tc = fileToolchain(exe);
  const entry = tc.resolve(exe);
  assert.equal(tc.verify(entry), true);
  // Mutate the executable bytes; the previously-resolved entry's digest now drifts.
  writeFileSync(exe, "#!/bin/sh\necho unrelated-bytes\n");
  assert.throws(() => tc.verify(entry), (e) => e instanceof ToolchainError);
});

test("the runner uses the kernel node regardless of a poisoned PATH", () => {
  const original = process.env.PATH;
  process.env.PATH = `/tmp/evil-bin:${original}`;
  try {
    const e = runTargetCommand({ commandId: "p", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.stdout.write('OK')"], cwd: process.cwd(), timeoutMs: 15000, maxOutputBytes: 4096, maxProcesses: 1, readRoots: [] });
    assert.equal(e.succeeded, true);
    assert.equal(e.stdout.toString(), "OK");
    assert.equal(e.report.executable.digest, kernelToolchain().resolve("node").digest);
  } finally {
    process.env.PATH = original;
  }
});

// ---- Finding 2: validator identity binds executable + base scripts --------

test("a mutable external target validator is rejected at compilation", async () => {
  const { compilePlan } = await import("../src/compiler.mjs");
  const { digestOfCanonical } = await import("../src/canonical-json.mjs");
  const { makeContract, makeProfile, makePack, makeCheck, pinPacks, profileEntries } = await import("./fixtures.mjs");
  const rogue = makePack({
    packId: "rogue-pack",
    checks: [makeCheck({ checkId: "rogue", validator: { kind: "TARGET_COMMAND", argv: ["/tmp/mutable-validator"] } })]
  });
  const packs = pinPacks([rogue]);
  const profile = makeProfile(profileEntries(packs));
  const profileDigest = digestOfCanonical(profile);
  const contract = makeContract({ policyProfile: { profileId: profile.profileId, path: "policy/profile.json", digest: profileDigest } });
  const result = compilePlan({ workContract: contract, profile, profileDigest, packs: packs.map((p) => ({ value: p.value, digest: p.digest })), mandatoryPacks: [] });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.reasonCode === "UNKNOWN_VALIDATOR"));
});

test("validator identity changes with base-script bytes and with the executable", () => {
  const repo = makeGitRepo();
  writeRepoFile(repo, "tools/check.cjs", "console.log('version-one');\n");
  const base1 = commitAll(repo, "base v1");
  const argv = ["node", "tools/check.cjs"];
  const id1 = targetValidatorDigest(repo, base1, argv);

  // Same argv, changed base-script bytes → different validator identity.
  writeRepoFile(repo, "tools/check.cjs", "console.log('version-two-unrelated');\n");
  const base2 = commitAll(repo, "base v2");
  const id2 = targetValidatorDigest(repo, base2, argv);
  assert.notEqual(id1, id2, "changed base-script bytes must change validator identity");

  // Same argv + same base, but a different executable (toolchain) → different.
  const dir = mkdtempSync(join(tmpdir(), "shedu-exe2-"));
  const fake = join(dir, "node");
  writeFileSync(fake, "#!/bin/sh\nexit 0\n");
  chmodSync(fake, 0o755);
  const idOtherExec = targetValidatorDigest(repo, base2, ["node", "tools/check.cjs"], { toolchain: fileToolchain(fake) });
  assert.notEqual(id2, idOtherExec, "a different executable must change validator identity");
});

// ---- Finding 7: source is valid UTF-8 text, never binary -------------------

test("all source, schema, and registry files are valid UTF-8 with no NUL bytes", () => {
  const roots = ["../src", "../schemas", "../registry", "../packs"].map((r) => new URL(r, import.meta.url).pathname);
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else files.push(full);
    }
  };
  for (const r of roots) walk(r);
  assert.ok(files.length >= 25);
  for (const file of files) {
    const buf = readFileSync(file);
    assert.ok(!buf.includes(0x00), `${file} contains a NUL byte`);
    // Fatal UTF-8 decode: throws on malformed bytes.
    assert.doesNotThrow(() => new TextDecoder("utf-8", { fatal: true }).decode(buf), `${file} is not valid UTF-8`);
  }
});

test("git classifies sandbox.mjs as text", () => {
  const r = spawnSync("git", ["-C", new URL("..", import.meta.url).pathname, "diff", "--numstat", "--no-index", "/dev/null", "src/sandbox.mjs"], { encoding: "utf8" });
  // --no-index against /dev/null: a text file reports numeric added lines; a
  // binary file reports "-". The first column must be numeric.
  const firstCol = (r.stdout.trim().split("\n").pop() ?? "").split("\t")[0];
  assert.match(firstCol, /^[0-9]+$/, `sandbox.mjs is classified as ${firstCol === "-" ? "binary" : "text"}`);
});
