import { readFileSync } from "node:fs";
import { digestOfBytes, digestOfCanonical, validateRelativePath } from "./canonical-json.mjs";
import { readAuthorityBlob } from "./authority.mjs";
import { BUILTIN_VALIDATORS } from "./builtin-validators.mjs";

// The byte identity of a validator implementation, hash-bound so a receipt
// (and an activation fingerprint) pins the exact code that ran.

export function builtinValidatorDigest(builtinId) {
  const descriptor = BUILTIN_VALIDATORS[builtinId];
  const bytes = readFileSync(new URL(descriptor.sourceFile, import.meta.url));
  return digestOfBytes(bytes);
}

// A target command's code identity: every argv element that resolves to a
// regular file in the trusted base tree is hash-bound; a command whose bytes
// change produces a different digest.
export function targetValidatorDigest(repoDir, baseCommit, argv) {
  const resolved = [];
  for (const element of argv) {
    const contained = validateRelativePath(element);
    if (!contained.ok) continue;
    const blob = readAuthorityBlob(repoDir, baseCommit, element);
    if (blob.ok) resolved.push({ path: element, digest: digestOfBytes(blob.bytes) });
  }
  return digestOfCanonical(resolved.length > 0 ? resolved : { argv });
}

export function validatorDigestForPlanCheck(repoDir, baseCommit, check) {
  return check.validator.kind === "BUILTIN"
    ? builtinValidatorDigest(check.validator.builtinId)
    : targetValidatorDigest(repoDir, baseCommit, check.validator.argv);
}
