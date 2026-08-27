import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { createControlLedger } from "./control-runtime.mjs";
import { CONTROL_PROOFS } from "./control-proofs.mjs";

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
export function runControlCensus({ srcDir, registry, proofs = CONTROL_PROOFS }) {
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

  return {
    schemaVersion: "control-census@1",
    complete: findings.length === 0,
    discovered: [...discovered.keys()].sort(),
    registered: [...registeredIds].sort(),
    proven: [...proven].sort(),
    ledgerEvents: ledger.events().length,
    findings: findings.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  };
}
