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
  const bytes = readFileSync(new URL(descriptor.sourceFile, import.meta.url));
  return digestOfBytes(bytes);
}

// A target command's code identity binds: the exact declared argv, the
// resolved executable (name + content digest), the toolchain-authority
// digest, and every trusted-base script/module blob named in argv. Throws
// ToolchainError when the executable is not admitted — so an absolute mutable
// external validator cannot obtain a stable spoofable digest.
export function targetValidatorDigest(repoDir, baseCommit, argv, { toolchain = kernelToolchain() } = {}) {
  const resolved = toolchain.resolve(argv[0]);
  const baseScripts = [];
  for (const element of argv.slice(1)) {
    const contained = validateRelativePath(element);
    if (!contained.ok) continue;
    const blob = readAuthorityBlob(repoDir, baseCommit, element);
    if (blob.ok) baseScripts.push({ path: element, digest: digestOfBytes(blob.bytes) });
  }
  return digestOfCanonical({
    schema: "target-validator-identity@1",
    argv: [...argv],
    executable: { name: resolved.name, digest: resolved.digest },
    toolchainDigest: toolchain.authorityDigest(),
    baseScripts
  });
}

export function validatorDigestForPlanCheck(repoDir, baseCommit, check, opts = {}) {
  return check.validator.kind === "BUILTIN"
    ? builtinValidatorDigest(check.validator.builtinId)
    : targetValidatorDigest(repoDir, baseCommit, check.validator.argv, opts);
}

// Static, filesystem-free check the compiler uses to reject a target command
// whose executable is not an admitted toolchain executable.
export function isResolvableTargetExecutable(argv0) {
  return isAdmittedExecutableName(argv0);
}

export { ToolchainError };
