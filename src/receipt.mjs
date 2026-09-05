import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify
} from "node:crypto";
import { canonicalize, digestOfBytes, digestOfCanonical } from "./canonical-json.mjs";
import { validateDocument, validateVersionedDocument } from "./contracts.mjs";
import { reduceDisposition } from "./reducer.mjs";
import { verifyEvidenceDir } from "./evidence.mjs";
import { portableLinuxExecutionAuthority } from "./oci-runtime.mjs";

// Control points: offline receipt verification and optional Ed25519 signing.
export const CONTROL_POINTS = Object.freeze(["receipt-verification", "receipt-signing"]);

// Receipt signing and offline verification. The signature covers the
// canonical bytes of the receipt with `signing: null`, so signing binds
// everything else and re-signing after mutation requires the private key.
// Verification is fully offline and reproduces the disposition from the
// indexed results through the same reducer — console prose has no channel
// into any of it (AC-11), and replay against another plan, candidate,
// repository, base, contract, or profile fails on digest identity (AC-10).

export function unsignedReceiptBytes(receipt) {
  return Buffer.from(canonicalize({ ...receipt, signing: null }), "utf8");
}

export function generateSigningKeyPem() {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ type: "pkcs8", format: "pem" });
}

function parseReceiptSigningKey(privateKeyPem) {
  const key = createPrivateKey(privateKeyPem);
  const jwk = createPublicKey(key).export({ format: "jwk" });
  if (jwk.crv !== "Ed25519") throw new Error("receipt signing requires an Ed25519 key");
  return { key, publicKey: Buffer.from(jwk.x, "base64url").toString("hex") };
}

// Validate signing material before an expensive evaluation begins. The worker
// retains the exact bounded bytes and signReceipt reparses those same bytes at
// finalization, so preflight cannot substitute a different key or move signing
// outside the supervised process.
export function validateReceiptSigningKey(privateKeyPem) {
  parseReceiptSigningKey(privateKeyPem);
  return true;
}

export function signReceipt(receipt, privateKeyPem) {
  const { key, publicKey } = parseReceiptSigningKey(privateKeyPem);
  return {
    ...receipt,
    signing: {
      algorithm: "ed25519",
      publicKey,
      signature: cryptoSign(null, unsignedReceiptBytes(receipt), key).toString("hex")
    }
  };
}

function publicKeyFromHex(publicKeyHex) {
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKeyHex, "hex").toString("base64url") },
    format: "jwk"
  });
}

export function verifyReceipt({
  receiptBytes,
  planBytes,
  evidenceDir = null,
  evidenceMaxTotalBytes = Number.MAX_SAFE_INTEGER,
  expectedPublicKey = null
}) {
  const errors = [];
  const fail = (reasonCode, message) => errors.push({ reasonCode, message });

  const receiptDoc = validateVersionedDocument(["promotion-receipt@1", "promotion-receipt@2"], receiptBytes);
  if (!receiptDoc.ok) return { ok: false, errors: receiptDoc.errors, disposition: null, receipt: null, plan: null, evidenceIndex: null };
  const expectedPlanKind = receiptDoc.value.schemaVersion === "promotion-receipt@2"
    ? "compiled-policy-plan@2"
    : "compiled-policy-plan@1";
  const planDoc = validateDocument(expectedPlanKind, planBytes);
  if (!planDoc.ok) return { ok: false, errors: planDoc.errors, disposition: null, receipt: null, plan: null, evidenceIndex: null };
  const receipt = receiptDoc.value;
  const plan = planDoc.value;
  const planDigest = digestOfCanonical(plan);

  if (receipt.schemaVersion === "promotion-receipt@2") {
    const expected = new Map();
    for (const command of plan.validationCommands) {
      expected.set(command.commandId, { execution: command.execution, ownerCheckId: null, phase: command.phase });
    }
    for (const check of plan.checks) {
      if (check.validator.kind === "TARGET_COMMAND") {
        expected.set(check.checkId, { execution: check.execution, ownerCheckId: check.checkId, phase: check.phase });
      }
    }
    for (const [commandId, declaration] of expected) {
      if (declaration.execution.class !== "BOUNDED_PROCESS_TREE") continue;
      const portable = portableLinuxExecutionAuthority(declaration.execution.class);
      if (
        declaration.execution.capabilityId !== portable.capabilityId ||
        declaration.execution.portableAuthorityDigest !== portable.portableAuthorityDigest
      ) {
        fail("AUTHORITY_DIGEST_MISMATCH", `compiled execution authority for ${commandId} does not match this kernel release`);
      }
    }
    const seen = new Set();
    for (const entry of receipt.executionReports) {
      if (seen.has(entry.commandId)) {
        fail("RECEIPT_MUTATED", `execution report ${entry.commandId} is duplicated`);
        continue;
      }
      seen.add(entry.commandId);
      const declaration = expected.get(entry.commandId);
      if (!declaration) {
        fail("RECEIPT_MUTATED", `execution report ${entry.commandId} was not dispatched by the plan`);
        continue;
      }
      if (
        entry.report.class !== declaration.execution.class ||
        entry.report.maxTasks !== declaration.execution.maxTasks ||
        entry.report.capabilityId !== declaration.execution.capabilityId ||
        entry.report.portableAuthorityDigest !== declaration.execution.portableAuthorityDigest
      ) {
        fail("RECEIPT_REPLAY", `execution report ${entry.commandId} does not bind the compiled execution authority`);
      }
      if (entry.report.limitFired) {
        const owner = declaration.ownerCheckId === null
          ? plan.checks.find((check) => check.validator.builtinId === "validation-plan-execute@1" && check.phase === declaration.phase)?.checkId
          : declaration.ownerCheckId;
        const result = receipt.checkResults.find((item) => item.checkId === owner);
        if (!result?.reasonCodes.includes("TASK_BUDGET_EXCEEDED")) {
          fail("DISPOSITION_MISMATCH", `task ceiling fired for ${entry.commandId} without reaching its check result`);
        }
      }
    }
    for (const [commandId, declaration] of expected) {
      const owner = declaration.ownerCheckId === null
        ? plan.checks.find((check) => check.validator.builtinId === "validation-plan-execute@1" && check.phase === declaration.phase)?.checkId
        : declaration.ownerCheckId;
      const result = receipt.checkResults.find((item) => item.checkId === owner);
      if (result && ["PASS", "FIRED"].includes(result.outcome) && !seen.has(commandId)) {
        fail("EVIDENCE_MISSING", `executed check ${owner} has no execution report for ${commandId}`);
      }
    }
  }

  // Replay protection: the receipt must have been produced from exactly this
  // plan, over exactly this repository, base, candidate, contract, profile,
  // pack set, and capability index.
  if (receipt.digests.compiledPlan !== planDigest) {
    fail("RECEIPT_REPLAY", "receipt was not produced from the supplied plan");
  }
  if (receipt.repositoryId !== plan.repositoryId) fail("RECEIPT_REPLAY", "repository identity mismatch");
  if (receipt.baseCommit !== plan.baseCommit) fail("RECEIPT_REPLAY", "base identity mismatch");
  if (receipt.candidate.kind !== plan.candidate.kind || receipt.candidate.id !== plan.candidate.id) {
    fail("RECEIPT_REPLAY", "candidate identity mismatch");
  }
  if (receipt.digests.workContract !== plan.sourceDigests.workContract) fail("RECEIPT_REPLAY", "work-contract digest mismatch");
  if (receipt.digests.profile !== plan.sourceDigests.profile) fail("RECEIPT_REPLAY", "profile digest mismatch");
  if (canonicalize(receipt.digests.packs) !== canonicalize(plan.sourceDigests.packs)) {
    fail("RECEIPT_REPLAY", "pack digest set mismatch");
  }
  if (canonicalize(receipt.digests.capabilityIndex) !== canonicalize(plan.sourceDigests.capabilityIndex)) {
    fail("RECEIPT_REPLAY", "capability-index digest mismatch");
  }

  // Every indexed result must bind to this plan and candidate.
  for (const result of receipt.checkResults) {
    if (result.planDigest !== planDigest || result.candidateId !== receipt.candidate.id) {
      fail("RECEIPT_MUTATED", `result ${result.checkId} does not bind to this plan and candidate`);
    }
  }

  // AC-11: the disposition is reproduced from the indexed results alone.
  const reduced = reduceDisposition({ plan, planDigest, results: receipt.checkResults });
  if (reduced.disposition !== receipt.disposition) {
    fail("DISPOSITION_MISMATCH", `receipt claims ${receipt.disposition}, results reduce to ${reduced.disposition}`);
  }
  if (canonicalize(reduced.reasonCodes) !== canonicalize(receipt.reasonCodes)) {
    fail("DISPOSITION_MISMATCH", "receipt reason codes do not reproduce from the indexed results");
  }

  if (receipt.signing !== null) {
    let signatureValid = false;
    try {
      signatureValid = cryptoVerify(
        null,
        unsignedReceiptBytes(receipt),
        publicKeyFromHex(receipt.signing.publicKey),
        Buffer.from(receipt.signing.signature, "hex")
      );
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) fail("SIGNATURE_INVALID", "receipt signature does not verify");
    if (expectedPublicKey !== null && receipt.signing.publicKey !== expectedPublicKey) {
      fail("SIGNATURE_INVALID", "receipt is signed by an unexpected key");
    }
  } else if (expectedPublicKey !== null) {
    fail("SIGNATURE_INVALID", "receipt is unsigned but a signing key was required");
  }

  let evidence = null;
  if (evidenceDir !== null) {
    evidence = verifyEvidenceDir(evidenceDir, { maxTotalBytes: evidenceMaxTotalBytes });
    if (!evidence.ok) {
      errors.push(...evidence.errors);
    } else {
      // The receipt pins the finalized index digest: an index regenerated to
      // cover for tampered results no longer matches the receipt.
      try {
        if (receipt.digests.evidenceIndex !== digestOfBytes(evidence.indexBytes)) {
          fail("EVIDENCE_MUTATED", "evidence index does not match the digest pinned in the receipt");
        }
      } catch {
        fail("EVIDENCE_MISSING", "evidence index is unreadable");
      }
      const binding = evidence.index.binding;
      if (
        binding.compiledPlan !== planDigest ||
        binding.candidateId !== receipt.candidate.id ||
        binding.baseCommit !== receipt.baseCommit ||
        binding.repositoryId !== receipt.repositoryId ||
        binding.workContract !== receipt.digests.workContract ||
        binding.profile !== receipt.digests.profile
      ) {
        fail("RECEIPT_REPLAY", "evidence index is bound to a different run");
      }
      const indexed = new Map(evidence.index.artifacts.map((a) => [a.artifactId, a]));
      for (const result of receipt.checkResults) {
        for (const ref of result.evidence) {
          const entry = indexed.get(ref.artifactId);
          if (!entry) fail("EVIDENCE_MISSING", `artifact ${ref.artifactId} is not in the evidence index`);
          else if (entry.digest !== ref.digest || entry.checkId !== result.checkId) {
            fail("EVIDENCE_MUTATED", `artifact ${ref.artifactId} does not match the result that claims it`);
          }
        }
        // Every result is anchored: its canonical bytes were indexed during
        // the run, so a result rewritten in the receipt afterwards no longer
        // matches its anchor.
        const anchor = indexed.get(`result-${result.checkId}`);
        if (!anchor) {
          fail("EVIDENCE_MISSING", `result ${result.checkId} has no anchored evidence artifact`);
        } else if (anchor.digest !== digestOfBytes(Buffer.from(canonicalize(result), "utf8"))) {
          fail("EVIDENCE_MUTATED", `result ${result.checkId} does not match its anchored bytes`);
        }
      }
    }
  }

  const ok = errors.length === 0;
  return {
    ok,
    errors,
    disposition: ok ? receipt.disposition : null,
    receipt: ok ? receipt : null,
    plan: ok ? plan : null,
    evidenceIndex: ok ? (evidence?.index ?? null) : null
  };
}
