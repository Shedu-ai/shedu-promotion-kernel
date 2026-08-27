import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

// Control-surface census. Unlike the policy-plan mechanism census (which sees
// only checks dispatched by a compiled plan), this census inventories EVERY
// disposition- or admission-affecting control in the kernel, including
// infrastructure controls introduced outside any plan (sandbox isolation,
// resource ceilings, the deadline, halt routing, activation/receipt
// verification, and admission).
//
// The two sides are derived from INDEPENDENT mechanical sources:
//   - implementation:  discovered by scanning source for `CONTROL_POINTS`
//                      exports on the filesystem;
//   - registration:    the hand-authored control-surface@1 registry.
// The census requires the two sets to be equal — a newly exported control
// with no registry row, or a registry row with no implementation, fails —
// and requires every registered control to have an invocation symbol present
// in source and proving tests present in the test suite.

function listFiles(dir, ext) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...listFiles(full, ext));
    else if (name.endsWith(ext)) out.push(full);
  }
  return out;
}

// Independent implementation surface: every control id exported as a member
// of a `CONTROL_POINTS` array literal anywhere under srcDir.
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

export function runControlCensus({ srcDir, testDir, registry }) {
  const discovered = discoverControlPoints(srcDir);
  const registeredIds = new Map(registry.controls.map((c) => [c.id, c]));

  const srcConcat = listFiles(srcDir, ".mjs")
    .map((f) => readFileSync(f, "utf8"))
    .join("\n");
  const testConcat = listFiles(testDir, ".mjs")
    .map((f) => readFileSync(f, "utf8"))
    .join("\n");

  const findings = [];

  // Independence check: the two mechanically-derived sets must be equal.
  for (const [id, file] of discovered) {
    if (!registeredIds.has(id)) {
      findings.push({ id, reasonCode: "CONTROL_UNREGISTERED", message: `control ${id} is exported by ${file} but has no control-surface registry row` });
    }
  }
  for (const control of registry.controls) {
    if (!discovered.has(control.id)) {
      findings.push({ id: control.id, reasonCode: "CONTROL_UNIMPLEMENTED", message: `control ${control.id} is registered but no source exports it as a CONTROL_POINT` });
      continue;
    }
    // Invocation/dispatch evidence.
    if (!srcConcat.includes(control.invocationSymbol)) {
      findings.push({ id: control.id, reasonCode: "CONTROL_UNPROVEN", message: `control ${control.id} invocation symbol ${JSON.stringify(control.invocationSymbol)} appears nowhere in source` });
    }
    // Proving-test evidence (planted firing / conforming proof).
    for (const testName of control.provingTests) {
      if (!testConcat.includes(testName)) {
        findings.push({ id: control.id, reasonCode: "CONTROL_UNPROVEN", message: `control ${control.id} proving test ${JSON.stringify(testName)} is absent from the test suite` });
      }
    }
  }

  return {
    schemaVersion: "control-census@1",
    complete: findings.length === 0,
    discovered: [...discovered.keys()].sort(),
    registered: [...registeredIds.keys()].sort(),
    findings: findings.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  };
}
