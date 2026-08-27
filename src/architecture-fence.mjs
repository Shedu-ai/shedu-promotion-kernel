import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

// Control point: the architecture fence.
export const CONTROL_POINTS = Object.freeze(["architecture-fence"]);

// A mechanical source-boundary fence: admitted/promotable/experimental
// OUTCOMES may be constructed only inside their sanctioned modules. This
// prevents a copied source tree from fabricating an admitted or promotable
// result by directly constructing the outcome object elsewhere (e.g. replacing
// the CLI admission assignment with a literal `{ admitted: true, status:
// "EXPERIMENTAL" }`). It complements the runtime brands in admission.mjs and
// reducer.mjs: the brand makes a forged object inert at runtime, and this
// fence makes the forgery visible in source review/CI.
//
// The fence is a source lint, not a trust root: an attacker editing the whole
// tree can also edit the fence. Per the threat model, a subject cannot prove
// arbitrary self-modification; Harness Bench's external frozen-commit
// verification is the ultimate authority. The fence raises the number of
// independent surfaces an undetected forgery must modify.

const RULES = [
  {
    id: "admitted-outcome-construction",
    pattern: /admitted:\s*true/,
    allow: new Set(["src/admission.mjs"]),
    message: "an admitted outcome (`admitted: true`) may be constructed only in src/admission.mjs"
  },
  {
    id: "experimental-status-construction",
    pattern: /status:\s*"EXPERIMENTAL"/,
    allow: new Set(["src/admission.mjs"]),
    message: "an EXPERIMENTAL admission status may be constructed only in src/admission.mjs"
  },
  {
    id: "promotable-disposition-construction",
    pattern: /disposition:\s*"PROMOTABLE"/,
    allow: new Set(["src/reducer.mjs"]),
    message: 'a "PROMOTABLE" disposition may be constructed only in src/reducer.mjs'
  }
];

function listFiles(dir, ext) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...listFiles(full, ext));
    else if (name.endsWith(ext)) out.push(full);
  }
  return out;
}

export function runArchitectureFence(srcDir) {
  const violations = [];
  for (const file of listFiles(srcDir, ".mjs")) {
    const rel = `src/${relative(srcDir, file)}`;
    // The fence's own definition necessarily contains the forbidden token
    // patterns as rules; it is not a construction site.
    if (rel === "src/architecture-fence.mjs") continue;
    const content = readFileSync(file, "utf8");
    for (const rule of RULES) {
      if (rule.pattern.test(content) && !rule.allow.has(rel)) {
        violations.push({ ruleId: rule.id, file: rel, message: rule.message });
      }
    }
  }
  return { ok: violations.length === 0, violations };
}
