import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { digestOfBytes, digestOfCanonical } from "./canonical-json.mjs";
import { validateDocument, validateVersionedDocument } from "./contracts.mjs";
import { createControlLedger } from "./control-runtime.mjs";
import { CONTROL_PROOFS } from "./control-proofs.mjs";
import { verifyReceipt } from "./receipt.mjs";
import { evaluatedOutcomeBinding } from "./evaluate.mjs";

// Control-surface census — RUNTIME closure, not string occurrence.
//
// Three surfaces are derived INDEPENDENTLY:
//   - registration:   the control-surface@1 registry (hand-authored);
//   - implementation: control ids discovered by scanning source for
//                     `CONTROL_POINTS` exports (a filesystem lint);
//   - runtime:        each control's executable proof is RUN, and its result
//                     recorded into a registration-gated control ledger.
//
// The census is complete only when registration == implementation, every
// registered control has an executable proof that PASSES when run, and the
// ledger (which refuses events for unregistered controls) records an invoked,
// evidenced, disposition-effect-tagged event for each. A control removed from
// the registry cannot emit a ledger event; a registered control that is not
// invoked or whose runtime proof fails (e.g. a sandbox denial was removed)
// fails closure. Static discovery is retained ONLY as a supplemental lint.

function listFiles(dir, ext) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...listFiles(full, ext));
    else if (name.endsWith(ext)) out.push(full);
  }
  return out;
}

export function discoverControlPoints(srcDir) {
  const discovered = new Map();
  for (const file of listFiles(srcDir, ".mjs")) {
    const content = readFileSync(file, "utf8");
    const blockRe = /CONTROL_POINTS\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\)/g;
    let block;
    while ((block = blockRe.exec(content)) !== null) {
      for (const m of block[1].matchAll(/"([a-z0-9]+(?:-[a-z0-9]+)*)"/g)) {
        discovered.set(m[1], `src/${relative(srcDir, file)}`);
      }
    }
  }
  return discovered;
}

// proofs is injectable so tests can exercise a removed-denial proof failure.
// Production evidence is accepted ONLY as complete receipt/plan/evidence
// bundles. Bare control ids and unverified receipt-shaped objects are not an
// authority surface. Every bundle is verified offline before its trace can
// contribute an observation, and every trace field is checked against the
// verified receipt plus the control registry.
export function runControlCensus({ srcDir, registry, proofs = CONTROL_PROOFS, productionRuns = [] }) {
  const discovered = discoverControlPoints(srcDir);
  const registeredIds = registry.controls.map((c) => c.id);
  const registeredSet = new Set(registeredIds);
  const findings = [];

  // Independent-surface equality: registration vs source implementation.
  for (const [id, file] of discovered) {
    if (!registeredSet.has(id)) {
      findings.push({ id, reasonCode: "CONTROL_UNREGISTERED", message: `control ${id} is exported by ${file} but has no control-surface registry row` });
    }
  }
  for (const control of registry.controls) {
    if (!discovered.has(control.id)) {
      findings.push({ id: control.id, reasonCode: "CONTROL_UNIMPLEMENTED", message: `control ${control.id} is registered but no source exports it as a CONTROL_POINT` });
    }
  }

  // Runtime closure: run each registered control's proof, record into the
  // registration-gated ledger.
  const ledger = createControlLedger(registeredIds);
  for (const control of registry.controls) {
    if (!discovered.has(control.id)) continue;
    const proof = proofs[control.id];
    if (typeof proof !== "function") {
      findings.push({ id: control.id, reasonCode: "CONTROL_UNPROVEN", message: `control ${control.id} has no executable runtime proof` });
      continue;
    }
    let result;
    try {
      result = proof();
    } catch (error) {
      findings.push({ id: control.id, reasonCode: "CONTROL_UNPROVEN", message: `control ${control.id} runtime proof threw: ${String(error)}` });
      continue;
    }
    if (!result || result.passed !== true) {
      findings.push({ id: control.id, reasonCode: "CONTROL_UNPROVEN", message: `control ${control.id} runtime proof did not pass` });
      continue;
    }
    // The ledger refuses events for unregistered controls; recording here is
    // itself a closure check.
    ledger.record({ controlId: control.id, invocation: "runtime-proof", outcome: "PASS", evidence: result.detail ?? null, consumer: "control-census", dispositionEffect: control.dispositionEffect, proven: true });
  }

  const proven = ledger.proven();
  for (const id of registeredIds) {
    if (registeredSet.has(id) && discovered.has(id) && !proven.has(id) && !findings.some((f) => f.id === id)) {
      findings.push({ id, reasonCode: "CONTROL_UNPROVEN", message: `control ${id} produced no runtime ledger event` });
    }
  }

  // Production-trace closure — FAIL CLOSED. A control marked
  // productionObservable MUST be observed in an independently verified run.
  // Invalid bundles contribute ZERO observations.
  const observed = new Set();
  const registryById = new Map(registry.controls.map((control) => [control.id, control]));
  const evidenceBindings = [];
  for (const [runIndex, run] of productionRuns.entries()) {
    const receiptBytes = run?.receiptBytes;
    const planBytes = run?.planBytes;
    const evidenceDir = run?.evidenceDir;
    const executionBinding = evaluatedOutcomeBinding(run?.outcome);
    if (!(Buffer.isBuffer(receiptBytes) || typeof receiptBytes === "string") || !(Buffer.isBuffer(planBytes) || typeof planBytes === "string") || typeof evidenceDir !== "string" || executionBinding === null) {
      findings.push({ id: `production-run-${runIndex}`, reasonCode: "CONTROL_UNOBSERVED", message: "production evidence must contain receiptBytes, planBytes, and evidenceDir" });
      continue;
    }
    let verified;
    let receiptDoc;
    try {
      verified = verifyReceipt({ receiptBytes, planBytes, evidenceDir });
      receiptDoc = validateVersionedDocument(["promotion-receipt@1", "promotion-receipt@2"], receiptBytes);
    } catch {
      verified = { ok: false };
      receiptDoc = { ok: false };
    }
    if (!verified.ok || !receiptDoc.ok) {
      findings.push({ id: `production-run-${runIndex}`, reasonCode: "CONTROL_UNOBSERVED", message: "production receipt/plan/evidence did not verify offline" });
      continue;
    }
    const receipt = receiptDoc.value;
    const bindingValid =
      digestOfBytes(receiptBytes) === executionBinding.receiptDigest &&
      receipt.digests.compiledPlan === executionBinding.planDigest &&
      receipt.candidate.id === executionBinding.candidateId &&
      receipt.digests.evidenceIndex === executionBinding.evidenceIndexDigest &&
      evidenceDir === executionBinding.evidenceDir;
    if (!bindingValid) {
      findings.push({ id: `production-run-${runIndex}`, reasonCode: "CONTROL_UNOBSERVED", message: "production evidence is not bound to the in-process evaluation that emitted it" });
      continue;
    }
    const seenInRun = new Set();
    let runValid = true;
    for (const entry of receipt.controlTrace) {
      const registered = registryById.get(entry.controlId);
      const valid =
        registered !== undefined &&
        !seenInRun.has(entry.controlId) &&
        entry.invocation === "evaluation" &&
        entry.consumer === "promotion-receipt" &&
        entry.dispositionEffect === registered.dispositionEffect &&
        entry.planDigest === receipt.digests.compiledPlan &&
        entry.candidateId === receipt.candidate.id &&
        entry.evidenceIndexDigest === receipt.digests.evidenceIndex;
      if (!valid) {
        findings.push({ id: entry.controlId, reasonCode: "CONTROL_UNOBSERVED", message: `control ${entry.controlId} has an invalid, duplicate, or unbound production trace entry` });
        runValid = false;
      }
      seenInRun.add(entry.controlId);
    }
    const dispositionEntries = receipt.controlTrace.filter((entry) => entry.controlId === "disposition-reduction");
    if (dispositionEntries.length !== 1 || dispositionEntries[0].outcome !== receipt.disposition) {
      findings.push({ id: "disposition-reduction", reasonCode: "CONTROL_UNOBSERVED", message: "a verified production run must have exactly one disposition-reduction entry matching the final disposition" });
      runValid = false;
    }
    if (!runValid) continue;
    for (const entry of receipt.controlTrace) observed.add(entry.controlId);
    evidenceBindings.push({
      planDigest: receipt.digests.compiledPlan,
      candidateId: receipt.candidate.id,
      disposition: receipt.disposition,
      // The evidence-index digest is verified above but deliberately omitted
      // from this conformance projection because result timestamps make the
      // content-addressed evidence store run-variant. The trace projection is
      // timing-free and therefore reproducible byte-for-byte.
      controlTrace: receipt.controlTrace.map((entry) => ({
        controlId: entry.controlId,
        outcome: entry.outcome,
        dispositionEffect: entry.dispositionEffect,
        consumer: entry.consumer,
        planDigest: entry.planDigest,
        candidateId: entry.candidateId
      }))
    });
  }

  const productionObserved = [];
  for (const control of registry.controls) {
    if (control.productionObservable !== true) continue;
    if (observed.has(control.id)) {
      productionObserved.push(control.id);
    } else {
      findings.push({ id: control.id, reasonCode: "CONTROL_UNOBSERVED", message: `control ${control.id} is productionObservable but was not observed in a verified production run` });
    }
  }

  return {
    schemaVersion: "control-census@1",
    complete: findings.length === 0,
    discovered: [...discovered.keys()].sort(),
    registered: [...registeredIds].sort(),
    proven: [...proven].sort(),
    productionObserved: productionObserved.sort(),
    productionEvidenceProvided: productionRuns.length > 0,
    productionEvidenceDigest: evidenceBindings.length > 0 ? digestOfCanonical(evidenceBindings.sort((a, b) => {
      const left = digestOfCanonical(a);
      const right = digestOfCanonical(b);
      return left < right ? -1 : left > right ? 1 : 0;
    })) : null,
    ledgerEvents: ledger.events().length,
    findings: findings.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  };
}
