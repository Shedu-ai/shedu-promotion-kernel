import { lstatSync, mkdirSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { validateDocument, validateValue } from "./contracts.mjs";
import { hashBoundedRegularFile, readBoundedRegularFile } from "./bounded-file.mjs";

const MAX_EVIDENCE_INDEX_BYTES = 1_048_576;

// Control point: the cumulative evidence-artifact byte ceiling.
export const CONTROL_POINTS = Object.freeze(["evidence-artifact-ceiling"]);

// Content-addressed evidence index. Artifact bytes live under
// objects/sha256/<hex>; index.json is an evidence-index@1 document binding
// every artifact to the run's full authority chain and to the check and
// validator that produced it. Mutation or omission of any object is
// detectable offline by recomputing digests.

export function createEvidenceIndex({ rootDir, binding, maxTotalBytes = Number.MAX_SAFE_INTEGER }) {
  const objectsDir = join(rootDir, "objects", "sha256");
  mkdirSync(objectsDir, { recursive: true });
  const artifacts = [];
  const seenIds = new Set();
  let finalized = false;
  let totalBytes = 0;

  return {
    put({ artifactId, checkId, validatorId, bytes, mediaType = "application/json" }) {
      if (finalized) throw new Error("evidence index is finalized");
      if (seenIds.has(artifactId)) throw new Error(`artifact id ${artifactId} already indexed`);
      if (totalBytes + bytes.length > maxTotalBytes) {
        throw new Error(`evidence ceiling exceeded: ${totalBytes + bytes.length} bytes would exceed the ${maxTotalBytes}-byte artifact ceiling`);
      }
      totalBytes += bytes.length;
      seenIds.add(artifactId);
      const digest = digestOfBytes(bytes);
      writeFileSync(join(objectsDir, digest.slice("sha256:".length)), bytes);
      artifacts.push({ artifactId, checkId, validatorId, digest, byteLength: bytes.length, mediaType });
      return { artifactId, digest };
    },
    artifacts() {
      return artifacts.map((a) => ({ ...a }));
    },
    finalize() {
      if (finalized) throw new Error("evidence index is already finalized");
      finalized = true;
      const index = {
        schemaVersion: "evidence-index@1",
        binding,
        artifacts: [...artifacts].sort((a, b) => (a.artifactId < b.artifactId ? -1 : 1))
      };
      const validated = validateValue("evidence-index@1", index);
      if (!validated.ok) throw new Error(`invalid evidence index: ${JSON.stringify(validated.errors)}`);
      const indexBytes = Buffer.from(canonicalize(index), "utf8");
      writeFileSync(join(rootDir, "index.json"), indexBytes);
      return { index, indexBytes, indexDigest: digestOfBytes(indexBytes) };
    }
  };
}

// Offline verification: the index must be schema-valid, every artifact's
// object must be present and hash to its declared digest, and no undeclared
// object may sit in the store.
export function verifyEvidenceDir(rootDir, { maxTotalBytes = Number.MAX_SAFE_INTEGER } = {}) {
  const errors = [];
  let index = null;
  let indexBytes = null;
  let resolvedRoot;
  let objectsDir;
  if (!Number.isSafeInteger(maxTotalBytes) || maxTotalBytes < 0) {
    throw new TypeError("maxTotalBytes must be a non-negative safe integer");
  }
  try {
    resolvedRoot = realpathSync(rootDir);
    if (!lstatSync(resolvedRoot).isDirectory()) throw new Error("evidence root is not a directory");
    objectsDir = join(resolvedRoot, "objects", "sha256");
    if (realpathSync(objectsDir) !== objectsDir || !lstatSync(objectsDir).isDirectory()) {
      throw new Error("evidence object directory is not a concrete contained directory");
    }
    indexBytes = readBoundedRegularFile(join(resolvedRoot, "index.json"), MAX_EVIDENCE_INDEX_BYTES);
    const validated = validateDocument("evidence-index@1", indexBytes);
    if (!validated.ok) return { ok: false, errors: validated.errors, index: null };
    index = validated.value;
  } catch {
    return { ok: false, errors: [{ reasonCode: "EVIDENCE_MISSING", message: "evidence index or concrete object directory is missing or unreadable" }], index: null, indexBytes: null };
  }

  const declared = new Set();
  let totalBytes = 0;
  for (const artifact of index.artifacts) {
    const objectName = artifact.digest.slice("sha256:".length);
    declared.add(objectName);
    totalBytes += artifact.byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > maxTotalBytes) {
      errors.push({ reasonCode: "EVIDENCE_MUTATED", message: `declared evidence exceeds the ${maxTotalBytes}-byte verification ceiling` });
      break;
    }
    let inspected;
    try {
      inspected = hashBoundedRegularFile(join(objectsDir, objectName), artifact.byteLength);
    } catch {
      let exists = false;
      try {
        lstatSync(join(objectsDir, objectName));
        exists = true;
      } catch {
        exists = false;
      }
      errors.push({
        reasonCode: exists ? "EVIDENCE_MUTATED" : "EVIDENCE_MISSING",
        message: `artifact ${artifact.artifactId} object is ${exists ? "not the declared bounded regular file" : "missing"}`
      });
      continue;
    }
    if (inspected.digest !== artifact.digest) {
      errors.push({ reasonCode: "EVIDENCE_MUTATED", message: `artifact ${artifact.artifactId} bytes do not match ${artifact.digest}` });
    }
    if (inspected.byteLength !== artifact.byteLength) {
      errors.push({ reasonCode: "EVIDENCE_MUTATED", message: `artifact ${artifact.artifactId} byte length drifted` });
    }
  }
  let stored = [];
  try {
    stored = readdirSync(objectsDir, { withFileTypes: true });
  } catch {
    stored = [];
  }
  for (const entry of stored) {
    if (!entry.isFile() || !/^[0-9a-f]{64}$/.test(entry.name)) {
      errors.push({ reasonCode: "EVIDENCE_MUTATED", message: `non-regular or malformed object ${entry.name} present in evidence store` });
    } else if (!declared.has(entry.name)) {
      errors.push({ reasonCode: "EVIDENCE_MUTATED", message: `undeclared object ${entry.name} present in evidence store` });
    }
  }
  return { ok: errors.length === 0, errors, index, indexBytes, resolvedRoot, objectsDir, totalBytes };
}
