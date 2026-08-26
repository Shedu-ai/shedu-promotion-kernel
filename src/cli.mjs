#!/usr/bin/env node

import process from "node:process";
import { readFileSync } from "node:fs";
import { validateDocument } from "./contracts.mjs";
import { loadAuthorityDocument, verifyImmutableCommit } from "./authority.mjs";
import { compilePlan } from "./compiler.mjs";
import { evaluateCandidate } from "./evaluate.mjs";

export const SUBJECT_PROBE = Object.freeze({
  schemaVersion: "harness-bench-subject-probe@1",
  subject: "shedu-promotion-kernel",
  implementationStatus: "FOUNDATION_ONLY",
  capabilities: Object.freeze([
    "exact-argv@1",
    "immutable-subject-identity@1",
    "promotion-kernel-contract@1"
  ]),
  promotionEntrypointAvailable: false
});

function emitError(reasonCode, errors) {
  const doc = { schemaVersion: "promotion-kernel-error@1", status: "BLOCKED", reasonCode };
  if (Array.isArray(errors) && errors.length > 0) {
    doc.errors = errors.map((e) => ({ reasonCode: e.reasonCode, message: e.message }));
  }
  process.stderr.write(`${JSON.stringify(doc)}\n`);
  return 2;
}

function runCompile(argv) {
  const usage = () =>
    emitError("CLI_USAGE", [{ reasonCode: "CLI_USAGE", message: "usage: compile --contract <file> --repo <dir>" }]);
  const flags = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if ((flag !== "--contract" && flag !== "--repo") || value === undefined || flags.has(flag)) {
      return usage();
    }
    flags.set(flag, value);
  }
  if (!flags.has("--contract") || !flags.has("--repo")) return usage();

  let bytes;
  try {
    bytes = readFileSync(flags.get("--contract"));
  } catch {
    return emitError("AUTHORITY_OBJECT_MISSING", [
      { reasonCode: "AUTHORITY_OBJECT_MISSING", message: `cannot read contract file ${flags.get("--contract")}` }
    ]);
  }
  const contract = validateDocument("work-contract@1", bytes);
  if (!contract.ok) return emitError(contract.errors[0].reasonCode, contract.errors);
  const workContract = contract.value;
  const repoDir = flags.get("--repo");
  const baseCommit = workContract.target.baseCommit;

  const commit = verifyImmutableCommit(repoDir, baseCommit);
  if (!commit.ok) return emitError(commit.reasonCode, [commit]);

  const profile = loadAuthorityDocument({
    repoDir,
    baseCommit,
    path: workContract.policyProfile.path,
    expectedDigest: workContract.policyProfile.digest,
    kind: "policy-profile@1"
  });
  if (!profile.ok) return emitError(profile.reasonCode, profile.errors ?? [profile]);

  let capabilityIndexDigest = null;
  if (workContract.capabilityIndex !== null) {
    const index = loadAuthorityDocument({
      repoDir,
      baseCommit,
      path: workContract.capabilityIndex.path,
      expectedDigest: workContract.capabilityIndex.digest,
      kind: "capability-index@1"
    });
    if (!index.ok) return emitError(index.reasonCode, index.errors ?? [index]);
    capabilityIndexDigest = index.digest;
  }

  const packs = [];
  for (const selection of profile.value.packs) {
    const pack = loadAuthorityDocument({
      repoDir,
      baseCommit,
      path: selection.path,
      expectedDigest: selection.digest,
      kind: "policy-pack@1"
    });
    if (!pack.ok) return emitError(pack.reasonCode, pack.errors ?? [pack]);
    packs.push({ value: pack.value, digest: pack.digest });
  }

  const compiled = compilePlan({
    workContract,
    profile: profile.value,
    profileDigest: profile.digest,
    packs,
    capabilityIndexDigest
  });
  if (!compiled.ok) return emitError(compiled.errors[0].reasonCode, compiled.errors);

  process.stdout.write(`${compiled.planBytes}\n`);
  return 0;
}

function parseFlags(argv, allowed) {
  const flags = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (!allowed.includes(flag) || value === undefined || flags.has(flag)) return null;
    flags.set(flag, value);
  }
  return flags;
}

function runEvaluate(argv) {
  const usage = () =>
    emitError("CLI_USAGE", [{ reasonCode: "CLI_USAGE", message: "usage: evaluate --contract <file> --repo <dir> --out <dir>" }]);
  const flags = parseFlags(argv, ["--contract", "--repo", "--out"]);
  if (!flags || !flags.has("--contract") || !flags.has("--repo") || !flags.has("--out")) return usage();
  let contractBytes;
  try {
    contractBytes = readFileSync(flags.get("--contract"));
  } catch {
    return emitError("AUTHORITY_OBJECT_MISSING", [
      { reasonCode: "AUTHORITY_OBJECT_MISSING", message: `cannot read contract file ${flags.get("--contract")}` }
    ]);
  }
  const outcome = evaluateCandidate({
    repoDir: flags.get("--repo"),
    contractBytes,
    outDir: flags.get("--out")
  });
  if (!outcome.ok) return emitError(outcome.reasonCode, outcome.errors);
  process.stdout.write(outcome.receiptBytes);
  process.stdout.write("\n");
  return 0;
}

export function main(argv = process.argv.slice(2)) {
  if (argv.length === 1 && argv[0] === "--subject-probe") {
    process.stdout.write(`${JSON.stringify(SUBJECT_PROBE)}\n`);
    return 0;
  }

  if (argv[0] === "compile") {
    return runCompile(argv.slice(1));
  }
  if (argv[0] === "evaluate") {
    return runEvaluate(argv.slice(1));
  }

  process.stderr.write(`${JSON.stringify({
    schemaVersion: "promotion-kernel-error@1",
    status: "BLOCKED",
    reasonCode: "KERNEL_NOT_IMPLEMENTED"
  })}\n`);
  return 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = main();
}
