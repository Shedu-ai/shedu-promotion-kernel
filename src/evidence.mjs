import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { validateDocument, validateValue } from "./contracts.mjs";

// Content-addressed evidence index. Artifact bytes live under
// objects/sha256/<hex>; index.json is an evidence-index@1 document binding
// every artifact to the run's full authority chain and to the check and
// validator that produced it. Mutation or omission of any object is
// detectable offline by recomputing digests.

export function createEvidenceIndex({ rootDir, binding }) {
  const objectsDir = join(rootDir, "objects", "sha256");
  mkdirSync(objectsDir, { recursive: true });
  const artifacts = [];
  const seenIds = new Set();
  let finalized = false;

  return {
    put({ artifactId, checkId, validatorId, bytes, mediaType = "application/json" }) {
      if (finalized) throw new Error("evidence index is finalized");
      if (seenIds.has(artifactId)) throw new Error(`artifact id ${artifactId} already indexed`);
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
export function verifyEvidenceDir(rootDir) {
  const errors = [];
  let index = null;
  try {
    const bytes = readFileSync(join(rootDir, "index.json"));
    const validated = validateDocument("evidence-index@1", bytes);
    if (!validated.ok) return { ok: false, errors: validated.errors, index: null };
    index = validated.value;
  } catch {
    return { ok: false, errors: [{ reasonCode: "EVIDENCE_MISSING", message: "evidence index.json is missing or unreadable" }], index: null };
  }

  const objectsDir = join(rootDir, "objects", "sha256");
  const declared = new Set();
  for (const artifact of index.artifacts) {
    declared.add(artifact.digest.slice("sha256:".length));
    let bytes;
    try {
      bytes = readFileSync(join(objectsDir, artifact.digest.slice("sha256:".length)));
    } catch {
      errors.push({ reasonCode: "EVIDENCE_MISSING", message: `artifact ${artifact.artifactId} object is missing` });
      continue;
    }
    if (digestOfBytes(bytes) !== artifact.digest) {
      errors.push({ reasonCode: "EVIDENCE_MUTATED", message: `artifact ${artifact.artifactId} bytes do not match ${artifact.digest}` });
    }
    if (bytes.length !== artifact.byteLength) {
      errors.push({ reasonCode: "EVIDENCE_MUTATED", message: `artifact ${artifact.artifactId} byte length drifted` });
    }
  }
  let stored = [];
  try {
    stored = readdirSync(objectsDir);
  } catch {
    stored = [];
  }
  for (const name of stored) {
    if (!declared.has(name)) {
      errors.push({ reasonCode: "EVIDENCE_MUTATED", message: `undeclared object ${name} present in evidence store` });
    }
  }
  return { ok: errors.length === 0, errors, index };
}
