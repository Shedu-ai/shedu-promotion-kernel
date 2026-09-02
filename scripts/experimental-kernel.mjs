#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const PROJECT_ROOT = resolve(dirname(SCRIPT_PATH), "..");
const ACTIVATION_ROOT = join(PROJECT_ROOT, "activation", "experimental-v1");
const MANIFEST_PATH = join(ACTIVATION_ROOT, "manifest.json");
const MAX_DISTRIBUTION_FILE_BYTES = 1024 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const CLOSED_COMMANDS = Object.freeze([
  "compile",
  "conformance",
  "doctor",
  "evaluate",
  "inspect-evidence",
  "probe",
  "sandbox:linux:pull",
  "setup",
  "status",
  "verify-receipt"
]);
const ADMISSION_FLAGS = new Set(["--attestation", "--pinned-key", "--expected-commit"]);
const GIT_CANDIDATES = Object.freeze([
  "/Library/Developer/CommandLineTools/usr/bin/git",
  "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
  "/opt/homebrew/bin/git",
  "/usr/local/bin/git",
  "/usr/bin/git"
]);

export class DistributionError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = "DistributionError";
    this.reasonCode = reasonCode;
  }
}

function error(reasonCode, message) {
  throw new DistributionError(reasonCode, message);
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

// Self-contained canonical JSON for distribution-signature verification. The
// launcher must not import mutable kernel implementation code before it has
// verified and materialized the certified kernel identity.
function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value) && !Object.is(value, -0)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  error("ACTIVATION_EVIDENCE_INVALID", "signed evidence contains a non-canonical JSON value");
}

function boundedRegularFile(path, activationRoot) {
  let direct;
  try {
    direct = lstatSync(path);
  } catch {
    error("ACTIVATION_EVIDENCE_INVALID", "activation artifact is missing");
  }
  if (!direct.isFile()) error("ACTIVATION_EVIDENCE_INVALID", "activation artifact must not be a symlink or special file");
  const root = `${realpathSync(activationRoot)}${sep}`;
  const real = realpathSync(path);
  if (!real.startsWith(root)) error("ACTIVATION_EVIDENCE_INVALID", "activation artifact escapes its distribution directory");
  const stat = statSync(real);
  if (!stat.isFile() || stat.size > MAX_DISTRIBUTION_FILE_BYTES) {
    error("ACTIVATION_EVIDENCE_INVALID", "activation artifact is not a bounded regular file");
  }
  return readFileSync(real);
}

function parseDocument(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    error("ACTIVATION_EVIDENCE_INVALID", `${label} is not valid JSON`);
  }
}

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    error("ACTIVATION_EVIDENCE_INVALID", `${label} is not an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    error("ACTIVATION_EVIDENCE_INVALID", `${label} has an unexpected field set`);
  }
}

function verifySignature(document, publicKey) {
  const signing = document?.signing;
  if (signing?.algorithm !== "ed25519" || signing.publicKey !== publicKey || !/^[0-9a-f]{128}$/.test(signing.signature ?? "")) {
    return false;
  }
  try {
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey, "hex").toString("base64url") },
      format: "jwk"
    });
    return cryptoVerify(
      null,
      Buffer.from(canonicalize({ ...document, signing: null }), "utf8"),
      key,
      Buffer.from(signing.signature, "hex")
    );
  } catch {
    return false;
  }
}

function validateManifest(manifest) {
  exactKeys(manifest, ["schemaVersion", "distributionId", "releaseTag", "kernel", "authority", "evidence", "commands"], "manifest");
  exactKeys(manifest.kernel, ["repository", "release", "commit", "tree"], "manifest.kernel");
  exactKeys(manifest.authority, ["authorityId", "algorithm", "publicKey", "path", "digest"], "manifest.authority");
  exactKeys(manifest.evidence, ["attestation", "certification"], "manifest.evidence");
  exactKeys(manifest.evidence.attestation, ["path", "digest"], "manifest.evidence.attestation");
  exactKeys(manifest.evidence.certification, ["path", "digest"], "manifest.evidence.certification");
  if (
    manifest.schemaVersion !== "promotion-kernel-activation-distribution@1" ||
    manifest.distributionId !== "experimental-v1" ||
    manifest.kernel.repository !== "https://github.com/Shedu-ai/shedu-promotion-kernel.git" ||
    manifest.kernel.release !== "@shedu/promotion-kernel@0.4.0-experimental" ||
    !SHA40.test(manifest.kernel.commit) ||
    !SHA40.test(manifest.kernel.tree) ||
    manifest.authority.algorithm !== "ed25519" ||
    !HEX64.test(manifest.authority.publicKey) ||
    !SHA256.test(manifest.authority.digest) ||
    !SHA256.test(manifest.evidence.attestation.digest) ||
    !SHA256.test(manifest.evidence.certification.digest) ||
    manifest.authority.path !== "authority.json" ||
    manifest.evidence.attestation.path !== "attestation.json" ||
    manifest.evidence.certification.path !== "certification.json" ||
    !Array.isArray(manifest.commands) ||
    manifest.commands.length !== CLOSED_COMMANDS.length ||
    manifest.commands.some((command, index) => command !== CLOSED_COMMANDS[index])
  ) {
    error("ACTIVATION_EVIDENCE_INVALID", "activation manifest does not match the closed distribution contract");
  }
}

export function verifyDistributionBundle({ activationRoot = ACTIVATION_ROOT } = {}) {
  const manifestPath = activationRoot === ACTIVATION_ROOT ? MANIFEST_PATH : join(activationRoot, "manifest.json");
  const manifestBytes = boundedRegularFile(manifestPath, activationRoot);
  const manifest = parseDocument(manifestBytes, "manifest");
  validateManifest(manifest);

  const loadBound = (entry, label) => {
    const bytes = boundedRegularFile(join(activationRoot, entry.path), activationRoot);
    if (sha256(bytes) !== entry.digest) error("ACTIVATION_EVIDENCE_INVALID", `${label} digest does not match the activation manifest`);
    return { bytes, value: parseDocument(bytes, label) };
  };
  const authority = loadBound(manifest.authority, "authority");
  const attestation = loadBound(manifest.evidence.attestation, "attestation");
  const certification = loadBound(manifest.evidence.certification, "certification");

  exactKeys(authority.value, ["schemaVersion", "authorityId", "algorithm", "publicKey", "status"], "authority");
  if (
    authority.value.schemaVersion !== "promotion-kernel-activation-authority@1" ||
    authority.value.authorityId !== manifest.authority.authorityId ||
    authority.value.algorithm !== manifest.authority.algorithm ||
    authority.value.publicKey !== manifest.authority.publicKey ||
    authority.value.status !== "ACTIVE"
  ) error("ACTIVATION_EVIDENCE_INVALID", "authority document contradicts the activation manifest");

  const key = manifest.authority.publicKey;
  if (!verifySignature(attestation.value, key) || !verifySignature(certification.value, key)) {
    error("ACTIVATION_EVIDENCE_INVALID", "activation evidence signature is invalid");
  }
  const kernel = manifest.kernel;
  if (
    attestation.value.kernelCommit !== kernel.commit ||
    attestation.value.kernelRelease !== kernel.release ||
    attestation.value.signing.publicKey !== key ||
    certification.value.allPassed !== true ||
    certification.value.authorityId !== manifest.authority.authorityId ||
    certification.value.attestationSha256 !== manifest.evidence.attestation.digest ||
    certification.value.kernel?.repository !== kernel.repository ||
    certification.value.kernel?.release !== kernel.release ||
    certification.value.kernel?.commitSha !== kernel.commit ||
    certification.value.kernel?.treeSha !== kernel.tree ||
    certification.value.signing.publicKey !== key ||
    certification.value.verification?.source?.cleanAfterVerification !== true ||
    certification.value.verification?.source?.headExact !== true ||
    certification.value.verification?.source?.remotesStripped !== true ||
    certification.value.verification?.source?.treeExact !== true ||
    certification.value.verification?.test?.failed !== 0 ||
    certification.value.verification?.conformance?.failed !== 0 ||
    certification.value.verification?.conformance?.byteIdentical !== true ||
    certification.value.verification?.probe?.implementationStatus !== "EXPERIMENTAL" ||
    certification.value.verification?.probe?.promotionEntrypointAvailable !== true
  ) error("ACTIVATION_EVIDENCE_INVALID", "signed certification does not admit the manifest's exact kernel identity");

  return Object.freeze({
    manifest,
    manifestDigest: sha256(manifestBytes),
    attestationPath: realpathSync(join(activationRoot, manifest.evidence.attestation.path))
  });
}

function resolveGit() {
  for (const candidate of GIT_CANDIDATES) {
    try {
      const real = realpathSync(candidate);
      if (statSync(real).isFile()) return real;
    } catch {
      // Continue through the source-closed candidate set.
    }
  }
  error("GIT_UNRESOLVED", "no Git executable exists in the closed absolute candidate set");
}

function gitEnv() {
  return {
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
    HOME: "/nonexistent"
  };
}

function cleanRuntimeEnv() {
  return {
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
    TMPDIR: process.platform === "darwin" ? "/private/tmp" : "/tmp",
    LANG: "C",
    LC_ALL: "C"
  };
}

function runGit(gitPath, args, { cwd = null } = {}) {
  const result = spawnSync(gitPath, cwd === null ? args : ["-C", cwd, ...args], {
    encoding: "utf8",
    env: gitEnv(),
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true
  });
  if (result.status !== 0) {
    error("KERNEL_INSTALLATION_FAILED", `Git operation failed: ${args[0] ?? "unknown"}`);
  }
  return result.stdout.trim();
}

function defaultCacheRoot() {
  const base = process.platform === "darwin" ? join(homedir(), "Library", "Caches") : join(homedir(), ".cache");
  return join(base, "shedu-promotion-kernel");
}

function installedIdentity(gitPath, kernelDir, kernel) {
  try {
    if (!lstatSync(kernelDir).isDirectory()) return { ok: false, reason: "cache path is not a directory" };
    const head = runGit(gitPath, ["rev-parse", "HEAD"], { cwd: kernelDir });
    const tree = runGit(gitPath, ["rev-parse", "HEAD^{tree}"], { cwd: kernelDir });
    const dirty = runGit(gitPath, ["status", "--porcelain", "--untracked-files=all"], { cwd: kernelDir });
    const remotes = runGit(gitPath, ["remote"], { cwd: kernelDir });
    const cli = join(kernelDir, "src", "cli.mjs");
    if (!statSync(cli).isFile()) return { ok: false, reason: "kernel CLI is absent" };
    if (head !== kernel.commit) return { ok: false, reason: "kernel commit mismatch" };
    if (tree !== kernel.tree) return { ok: false, reason: "kernel tree mismatch" };
    if (dirty !== "") return { ok: false, reason: "kernel cache is dirty" };
    if (remotes !== "") return { ok: false, reason: "kernel cache retains a remote" };
    return { ok: true, cli };
  } catch (cause) {
    if (cause instanceof DistributionError) return { ok: false, reason: cause.message };
    return { ok: false, reason: "kernel cache cannot be verified" };
  }
}

export function ensureKernelInstalled({ repository = null, cacheRoot = null } = {}) {
  const bundle = verifyDistributionBundle();
  const source = repository ?? bundle.manifest.kernel.repository;
  const root = resolve(cacheRoot ?? defaultCacheRoot());
  const kernelDir = join(root, bundle.manifest.kernel.commit);
  const gitPath = resolveGit();
  if (existsSync(kernelDir)) {
    const current = installedIdentity(gitPath, kernelDir, bundle.manifest.kernel);
    if (current.ok) return Object.freeze({ ...bundle, kernelDir, cli: current.cli, reused: true });
  }

  mkdirSync(root, { recursive: true, mode: 0o700 });
  const lock = join(root, `.install-${bundle.manifest.kernel.commit}.lock`);
  try {
    mkdirSync(lock, { mode: 0o700 });
  } catch {
    error("KERNEL_INSTALLATION_LOCKED", "another installation owns the exact kernel cache lock");
  }
  const temporary = join(root, `.install-${bundle.manifest.kernel.commit}-${randomBytes(8).toString("hex")}`);
  let displaced = null;
  try {
    runGit(gitPath, ["clone", "--no-checkout", "--no-tags", source, temporary]);
    runGit(gitPath, ["checkout", "--detach", bundle.manifest.kernel.commit], { cwd: temporary });
    const head = runGit(gitPath, ["rev-parse", "HEAD"], { cwd: temporary });
    const tree = runGit(gitPath, ["rev-parse", "HEAD^{tree}"], { cwd: temporary });
    if (head !== bundle.manifest.kernel.commit || tree !== bundle.manifest.kernel.tree) {
      error("KERNEL_IDENTITY_MISMATCH", "installed Git object does not match the signed kernel commit and tree");
    }
    runGit(gitPath, ["remote", "remove", "origin"], { cwd: temporary });
    const verified = installedIdentity(gitPath, temporary, bundle.manifest.kernel);
    if (!verified.ok) error("KERNEL_IDENTITY_MISMATCH", verified.reason);
    if (existsSync(kernelDir)) {
      displaced = join(root, `.displaced-${bundle.manifest.kernel.commit}-${randomBytes(8).toString("hex")}`);
      renameSync(kernelDir, displaced);
    }
    renameSync(temporary, kernelDir);
    if (displaced !== null) {
      rmSync(displaced, { recursive: true, force: true });
      displaced = null;
    }
    return Object.freeze({ ...bundle, kernelDir, cli: join(kernelDir, "src", "cli.mjs"), reused: false });
  } catch (cause) {
    if (displaced !== null && !existsSync(kernelDir) && existsSync(displaced)) renameSync(displaced, kernelDir);
    throw cause;
  } finally {
    if (existsSync(temporary)) rmSync(temporary, { recursive: true, force: true });
    if (displaced !== null && existsSync(displaced)) rmSync(displaced, { recursive: true, force: true });
    rmSync(lock, { recursive: true, force: true });
  }
}

function admissionEnv(installation) {
  return {
    ...cleanRuntimeEnv(),
    SHEDU_ATTESTATION_FILE: installation.attestationPath,
    SHEDU_PINNED_KEY: installation.manifest.authority.publicKey,
    SHEDU_EXPECTED_COMMIT: installation.manifest.kernel.commit
  };
}

function childResult(installation, argv, { capture = false } = {}) {
  return spawnSync(process.execPath, [installation.cli, ...argv], {
    encoding: capture ? "utf8" : undefined,
    stdio: capture ? "pipe" : "inherit",
    env: admissionEnv(installation),
    windowsHide: true
  });
}

function rejectAdmissionOverrides(argv) {
  for (const value of argv) {
    if (ADMISSION_FLAGS.has(value)) error("CLI_USAGE", `${value} is distribution-owned and cannot be supplied by the caller`);
  }
}

function runDoctor(installation) {
  const status = childResult(installation, ["status"], { capture: true });
  const probe = childResult(installation, ["--subject-probe"], { capture: true });
  if (status.status !== 0 || probe.status !== 0) error("NOT_ADMITTED", "the certified kernel did not accept its activation distribution");
  const statusDocument = parseDocument(Buffer.from(status.stdout), "kernel status");
  const probeDocument = parseDocument(Buffer.from(probe.stdout), "kernel probe");
  if (statusDocument.implementationStatus !== "EXPERIMENTAL" || probeDocument.promotionEntrypointAvailable !== true) {
    error("NOT_ADMITTED", "the activation distribution did not produce an experimental promotion entrypoint");
  }
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "promotion-kernel-distribution-doctor@1",
    ok: true,
    distributionId: installation.manifest.distributionId,
    manifestDigest: installation.manifestDigest,
    kernel: {
      commit: installation.manifest.kernel.commit,
      tree: installation.manifest.kernel.tree,
      release: installation.manifest.kernel.release,
      cachePath: installation.kernelDir,
      reused: installation.reused
    },
    admission: {
      implementationStatus: statusDocument.implementationStatus,
      promotionEntrypointAvailable: probeDocument.promotionEntrypointAvailable,
      authorityId: installation.manifest.authority.authorityId
    }
  })}\n`);
  return 0;
}

export function runExperimental(argv = process.argv.slice(2), options = {}) {
  const command = argv[0] ?? "status";
  if (!CLOSED_COMMANDS.includes(command)) error("CLI_USAGE", `unknown experimental distribution command: ${command}`);
  const rest = argv.slice(1);
  rejectAdmissionOverrides(rest);
  const installation = ensureKernelInstalled(options);

  if (command === "setup") {
    if (rest.length !== 0) error("CLI_USAGE", "setup accepts no arguments");
    process.stdout.write(`${JSON.stringify({
      schemaVersion: "promotion-kernel-distribution-setup@1",
      distributionId: installation.manifest.distributionId,
      kernelCommit: installation.manifest.kernel.commit,
      kernelTree: installation.manifest.kernel.tree,
      cachePath: installation.kernelDir,
      reused: installation.reused
    })}\n`);
    return 0;
  }
  if (command === "doctor") {
    if (rest.length !== 0) error("CLI_USAGE", "doctor accepts no arguments");
    return runDoctor(installation);
  }

  let kernelArgv;
  if (command === "probe") kernelArgv = ["--subject-probe", ...rest];
  else if (command === "sandbox:linux:pull") kernelArgv = [join(installation.kernelDir, "scripts", "pull-linux-sandbox-image.mjs"), ...rest];
  else if (command === "evaluate") {
    kernelArgv = [
      "evaluate",
      ...rest,
      "--attestation",
      installation.attestationPath,
      "--pinned-key",
      installation.manifest.authority.publicKey,
      "--expected-commit",
      installation.manifest.kernel.commit
    ];
  } else kernelArgv = [command, ...rest];

  const result = command === "sandbox:linux:pull"
    ? spawnSync(process.execPath, kernelArgv, { stdio: "inherit", env: cleanRuntimeEnv(), windowsHide: true })
    : childResult(installation, kernelArgv);
  if (result.error) error("INFRASTRUCTURE_FAILURE", result.error.message);
  return result.status ?? 2;
}

export function isDirectInvocation(argv1 = process.argv[1]) {
  if (typeof argv1 !== "string" || argv1.length === 0) return false;
  try {
    return realpathSync(argv1) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
}

if (isDirectInvocation()) {
  try {
    process.exitCode = runExperimental();
  } catch (cause) {
    const reasonCode = cause instanceof DistributionError ? cause.reasonCode : "INFRASTRUCTURE_FAILURE";
    process.stderr.write(`${JSON.stringify({
      schemaVersion: "promotion-kernel-distribution-error@1",
      status: "BLOCKED",
      reasonCode,
      message: cause instanceof Error ? cause.message : String(cause)
    })}\n`);
    process.exitCode = 2;
  }
}
