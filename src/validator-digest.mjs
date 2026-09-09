import { readFileSync } from "node:fs";
import { digestOfBytes, digestOfCanonical, validateRelativePath } from "./canonical-json.mjs";
import { readAuthorityBlob } from "./authority.mjs";
import { BUILTIN_VALIDATORS } from "./builtin-validators.mjs";
import { kernelToolchain, isAdmittedExecutableName, ToolchainError } from "./toolchain.mjs";

// The byte identity of a validator implementation, hash-bound so a receipt
// (and an activation fingerprint) pins the exact code — and the exact
// toolchain and executable — that ran. There is NO argv-only fallback: a
// target command whose executable is not resolvable through the closed
// toolchain authority has no admissible identity and cannot run.

export function builtinValidatorDigest(builtinId) {
  const descriptor = BUILTIN_VALIDATORS[builtinId];
  if (descriptor.sourceFiles) return digestOfCanonical({schema: "builtin-source-identity@1", files: descriptor.sourceFiles.map(path => ({path, digest: digestOfBytes(readFileSync(new URL(path, import.meta.url)))}))});
  const bytes = readFileSync(new URL(descriptor.sourceFile, import.meta.url));
  return digestOfBytes(bytes);
}

// A target command's code identity binds: the exact declared argv, the
// resolved executable (name + content digest), the toolchain-authority
// digest, and every DECLARED trusted-base input blob in the check's
// inputManifest. There is no heuristic import parsing and no argv-only
// fallback: the manifest is the complete, explicit set of base inputs the
// validator may read, and the sandbox restricts base reads to exactly it.
// Any declared blob that changes changes the identity; any undeclared blob
// that the manifest omits is unreadable at runtime, so a validator cannot
// silently depend on unbound base code. A missing manifest blob is a hard
// error (the validator's identity is not resolvable).
export function targetValidatorDigest(repoDir, baseCommit, validator, { toolchain = kernelToolchain() } = {}) {
  const resolved = toolchain.resolve(validator.argv[0]);
  const manifest = [];
  for (const path of validator.inputManifest ?? []) {
    const contained = validateRelativePath(path);
    if (!contained.ok) throw new ToolchainError(`inputManifest path ${JSON.stringify(path)} is not contained`);
    const blob = readAuthorityBlob(repoDir, baseCommit, path);
    if (!blob.ok) throw new ToolchainError(`inputManifest blob ${JSON.stringify(path)} is missing from the trusted base`);
    manifest.push({ path, digest: digestOfBytes(blob.bytes) });
  }
  manifest.sort((a, b) => (a.path < b.path ? -1 : 1));
  return digestOfCanonical({
    schema: "target-validator-identity@2",
    argv: [...validator.argv],
    executable: { name: resolved.name, digest: resolved.digest },
    toolchainDigest: toolchain.authorityDigest(),
    inputManifest: manifest
  });
}

export function validatorDigestForPlanCheck(repoDir, baseCommit, check, opts = {}) {
  if (check.validator.builtinId === "behavioral-cases-verify@1") {
    const path = check.validator.casesPath;
    if (!validateRelativePath(path).ok) throw new ToolchainError("behavioral cases path is not contained");
    const blob = readAuthorityBlob(repoDir, baseCommit, path);
    if (!blob.ok) throw new ToolchainError("behavioral cases missing from trusted base");
    const toolchain = opts.toolchain ?? kernelToolchain();
    const executable = toolchain.resolve("node");
    return digestOfCanonical({schema: "behavioral-validator-identity@1", implementation: builtinValidatorDigest(check.validator.builtinId), cases: {path, digest: digestOfBytes(blob.bytes)}, toolchainDigest: toolchain.authorityDigest(), executable: {name: executable.name, digest: executable.digest}});
  }
  return check.validator.kind === "BUILTIN"
    ? builtinValidatorDigest(check.validator.builtinId)
    : targetValidatorDigest(repoDir, baseCommit, check.validator, opts);
}

// Static, filesystem-free check the compiler uses to reject a target command
// whose executable is not an admitted toolchain executable.
export function isResolvableTargetExecutable(argv0) {
  return isAdmittedExecutableName(argv0);
}

export { ToolchainError };
