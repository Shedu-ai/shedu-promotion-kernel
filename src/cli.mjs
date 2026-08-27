#!/usr/bin/env node

import process from "node:process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { validateDocument } from "./contracts.mjs";
import { loadAuthorityDocument, verifyImmutableCommit } from "./authority.mjs";
import { KERNEL_RELEASE, compilePlan } from "./compiler.mjs";
import { evaluateSupervised } from "./supervisor.mjs";
import { signReceipt, verifyReceipt } from "./receipt.mjs";
import { runConformance } from "./conformance.mjs";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { computeAdmission, isAdmitted, verifyFrozenSource } from "./admission.mjs";
import { git as gitAuthority } from "./git-authority.mjs";

const FOUNDATION_PROBE = Object.freeze({
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

export const EXPERIMENTAL_CAPABILITIES = Object.freeze([
  "exact-argv@1",
  "immutable-subject-identity@1",
  "promotion-kernel-contract@1",
  "policy-pack-compiler@1",
  "mandatory-packs@1",
  "disposition-reducer@1",
  "target-command-runner@1",
  "evidence-index@1",
  "promotion-receipt@1",
  "receipt-verification@1",
  "orphan-census@1",
  "prior-art-admission@1",
  "orphan-closure@1"
]);

// The FOUNDATION_ONLY → EXPERIMENTAL transition is never a mutable status
// bit. `admission` is computed by src/admission.mjs, which recomputes every
// conformance invariant AND requires a detached attestation signed by a
// pinned external key that binds the exact kernel commit. With no pinned key
// in the public build, the honest result is FOUNDATION_ONLY.
export function subjectProbe(admission) {
  // Only a branded, genuinely-admitted outcome elevates; a forged object is
  // not honored.
  if (isAdmitted(admission)) {
    return {
      schemaVersion: "harness-bench-subject-probe@1",
      subject: "shedu-promotion-kernel",
      implementationStatus: "EXPERIMENTAL",
      capabilities: [...EXPERIMENTAL_CAPABILITIES],
      promotionEntrypointAvailable: true
    };
  }
  return { ...FOUNDATION_PROBE, capabilities: [...FOUNDATION_PROBE.capabilities] };
}

function readIfPresent(url) {
  try {
    return readFileSync(url);
  } catch {
    return null;
  }
}

function currentKernelCommit() {
  const r = gitAuthority(["rev-parse", "HEAD"], { cwd: new URL("..", import.meta.url).pathname });
  return r.status === 0 && /^[0-9a-f]{40}$/.test(r.stdout.trim()) ? r.stdout.trim() : null;
}

const repoRoot = () => new URL("..", import.meta.url).pathname;

// Assemble admission from committed conformance status + EXTERNALLY-SUPPLIED
// admission evidence. Harness Bench (or a release verifier) supplies the
// detached attestation, the pinned public key, and the expected frozen commit
// via environment (or CLI flags), OUTSIDE the mutable subject source:
//   SHEDU_ATTESTATION_FILE  path to the detached conformance-attestation@1
//   SHEDU_PINNED_KEY        the externally-pinned Ed25519 public key (hex)
//   SHEDU_EXPECTED_COMMIT   the frozen commit the attestation must bind
// With none supplied, the honest result is FOUNDATION_ONLY.
export function committedAdmission(overrides = {}) {
  const statusBytes = readIfPresent(new URL("../conformance/status.json", import.meta.url));
  const inventoryBytes = readIfPresent(new URL("../registry/kernel-mechanisms.json", import.meta.url));
  const controlBytes = readIfPresent(new URL("../registry/control-surface.json", import.meta.url));

  const attestationPath = overrides.attestationPath ?? process.env.SHEDU_ATTESTATION_FILE ?? null;
  const pinnedKey = overrides.pinnedKey ?? process.env.SHEDU_PINNED_KEY ?? null;
  const expectedCommit = overrides.expectedCommit ?? process.env.SHEDU_EXPECTED_COMMIT ?? null;

  let attestationBytes = null;
  if (attestationPath) {
    try {
      attestationBytes = readFileSync(attestationPath);
    } catch {
      attestationBytes = null;
    }
  }

  const source = verifyFrozenSource(repoRoot(), expectedCommit);

  return computeAdmission({
    statusBytes,
    attestationBytes,
    trustedKeys: pinnedKey ? [pinnedKey] : [],
    kernelCommit: source.commit ?? currentKernelCommit(),
    expectedCommit,
    sourceClean: source.clean,
    mechanismInventoryDigest: inventoryBytes ? digestOfBytes(inventoryBytes) : null,
    controlSurfaceDigest: controlBytes ? digestOfBytes(controlBytes) : null
  });
}

function emitError(reasonCode, errors) {
  const doc = { schemaVersion: "promotion-kernel-error@1", status: "BLOCKED", reasonCode };
  if (Array.isArray(errors) && errors.length > 0) {
    doc.errors = errors.map((e) => ({ reasonCode: e.reasonCode, message: e.message }));
  }
  process.stderr.write(`${JSON.stringify(doc)}\n`);
  return 2;
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

function runCompile(argv) {
  const usage = () =>
    emitError("CLI_USAGE", [{ reasonCode: "CLI_USAGE", message: "usage: compile --contract <file> --repo <dir>" }]);
  const flags = parseFlags(argv, ["--contract", "--repo"]);
  if (!flags || !flags.has("--contract") || !flags.has("--repo")) return usage();

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

function runEvaluate(argv) {
  const usage = () =>
    emitError("CLI_USAGE", [
      { reasonCode: "CLI_USAGE", message: "usage: evaluate --contract <file> --repo <dir> --out <dir> [--sign-key <pem-file>]" }
    ]);
  const flags = parseFlags(argv, ["--contract", "--repo", "--out", "--sign-key"]);
  if (!flags || !flags.has("--contract") || !flags.has("--repo") || !flags.has("--out")) return usage();

  // The promotion entrypoint is gated by the SAME admission the probe uses.
  // Direct `evaluate` cannot bypass it: unless the subject is admitted to
  // EXPERIMENTAL, promotion is refused.
  const admission = committedAdmission();
  if (!isAdmitted(admission)) {
    return emitError("NOT_ADMITTED", admission.reasons.map((message) => ({ reasonCode: "NOT_ADMITTED", message })));
  }

  let contractBytes;
  try {
    contractBytes = readFileSync(flags.get("--contract"));
  } catch {
    return emitError("AUTHORITY_OBJECT_MISSING", [
      { reasonCode: "AUTHORITY_OBJECT_MISSING", message: `cannot read contract file ${flags.get("--contract")}` }
    ]);
  }
  // The public promotion path is supervised by a hard whole-evaluation
  // deadline in a separate worker process.
  const contract = validateDocument("work-contract@1", contractBytes);
  if (!contract.ok) return emitError(contract.errors[0].reasonCode, contract.errors);
  const outDir = flags.get("--out");
  const supervised = evaluateSupervised({
    repoDir: flags.get("--repo"),
    contractBytes,
    outDir,
    maxRuntimeSeconds: contract.value.maxRuntimeSeconds
  });
  if (supervised.timedOut) {
    return emitError("DEADLINE_EXCEEDED", [
      { reasonCode: "DEADLINE_EXCEEDED", message: `evaluation exceeded the ${contract.value.maxRuntimeSeconds}s whole-evaluation ceiling and was killed` }
    ]);
  }
  if (!supervised.ok) return emitError(supervised.reasonCode, [{ reasonCode: supervised.reasonCode, message: supervised.message ?? "" }]);

  let receiptBytes;
  try {
    receiptBytes = readFileSync(join(outDir, "receipt.json"));
  } catch {
    return emitError("INFRASTRUCTURE_FAILURE", [{ reasonCode: "INFRASTRUCTURE_FAILURE", message: "supervised evaluation produced no receipt" }]);
  }
  if (flags.has("--sign-key")) {
    let keyPem;
    try {
      keyPem = readFileSync(flags.get("--sign-key"), "utf8");
    } catch {
      return emitError("SIGNATURE_INVALID", [
        { reasonCode: "SIGNATURE_INVALID", message: `cannot read signing key ${flags.get("--sign-key")}` }
      ]);
    }
    const signed = signReceipt(JSON.parse(receiptBytes.toString("utf8")), keyPem);
    receiptBytes = Buffer.from(canonicalize(signed), "utf8");
    writeFileSync(join(outDir, "receipt.json"), receiptBytes);
  }
  process.stdout.write(receiptBytes);
  process.stdout.write("\n");
  return 0;
}

function runVerifyReceipt(argv) {
  const usage = () =>
    emitError("CLI_USAGE", [
      { reasonCode: "CLI_USAGE", message: "usage: verify-receipt --receipt <file> --plan <file> [--evidence <dir>] [--public-key <hex>]" }
    ]);
  const flags = parseFlags(argv, ["--receipt", "--plan", "--evidence", "--public-key"]);
  if (!flags || !flags.has("--receipt") || !flags.has("--plan")) return usage();
  let receiptBytes;
  let planBytes;
  try {
    receiptBytes = readFileSync(flags.get("--receipt"));
    planBytes = readFileSync(flags.get("--plan"));
  } catch {
    return emitError("AUTHORITY_OBJECT_MISSING", [
      { reasonCode: "AUTHORITY_OBJECT_MISSING", message: "cannot read receipt or plan file" }
    ]);
  }
  const verification = verifyReceipt({
    receiptBytes,
    planBytes,
    evidenceDir: flags.get("--evidence") ?? null,
    expectedPublicKey: flags.get("--public-key") ?? null
  });
  process.stdout.write(
    `${JSON.stringify({
      schemaVersion: "receipt-verification@1",
      ok: verification.ok,
      disposition: verification.disposition,
      errors: verification.errors
    })}\n`
  );
  return verification.ok ? 0 : 2;
}

function runConformanceCommand(argv) {
  const usage = () =>
    emitError("CLI_USAGE", [{ reasonCode: "CLI_USAGE", message: "usage: conformance --out <dir>" }]);
  const flags = parseFlags(argv, ["--out"]);
  if (!flags || !flags.has("--out")) return usage();
  const { status, statusBytes } = runConformance({ outDir: flags.get("--out") });
  process.stdout.write(statusBytes);
  process.stdout.write("\n");
  return status.allPassed ? 0 : 2;
}

export function main(argv = process.argv.slice(2)) {
  if (argv.length === 1 && argv[0] === "--subject-probe") {
    process.stdout.write(`${JSON.stringify(subjectProbe(committedAdmission()))}\n`);
    return 0;
  }

  if (argv[0] === "compile") return runCompile(argv.slice(1));
  if (argv[0] === "evaluate") return runEvaluate(argv.slice(1));
  if (argv[0] === "verify-receipt") return runVerifyReceipt(argv.slice(1));
  if (argv[0] === "conformance") return runConformanceCommand(argv.slice(1));

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
