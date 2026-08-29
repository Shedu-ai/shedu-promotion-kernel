import { readFileSync } from "node:fs";
import { CONTRACT_KINDS } from "./contracts.mjs";
import { validateAgentProjection } from "./agent-contracts.mjs";

const SURFACES = Object.freeze([
  Object.freeze({
    id: "subject-status",
    schemaKind: "kernel-agent-status@1",
    command: "status",
    declarationArgv: "statusArgv"
  }),
  Object.freeze({
    id: "evaluation-status",
    schemaKind: "kernel-evaluation-summary@1",
    command: "status",
    declarationArgv: "statusArgv"
  }),
  Object.freeze({
    id: "evidence-inspection",
    schemaKind: "kernel-evidence-view@1",
    command: "inspect-evidence",
    declarationArgv: "evidenceInspectionArgv"
  })
]);

const source = (relativePath) => readFileSync(new URL(`../${relativePath}`, import.meta.url), "utf8");

// Presentation-surface closure. This is intentionally separate from the
// disposition control census: projections cannot affect admission or
// disposition, but they still must be registered, implemented, dispatched,
// declared, emitted, and consumed in both directions.
export function runAgentInterfaceCensus({ observations = [] } = {}) {
  const findings = [];
  const cliSource = source("src/cli.mjs");
  const producerSource = source("src/agent-projection.mjs");
  const subject = JSON.parse(source(".harness-bench/subject.json"));
  const registeredSchemas = new Set(SURFACES.map((surface) => surface.schemaKind));
  const discoveredSchemas = new Set(CONTRACT_KINDS.filter((kind) =>
    kind.startsWith("kernel-") && kind !== "kernel-next-action@1"));
  const observed = new Map();

  for (const observation of observations) {
    if (observed.has(observation.surfaceId)) {
      findings.push({ id: observation.surfaceId, reasonCode: "DUPLICATE_RESULT", message: "surface emitted more than one census observation" });
      continue;
    }
    observed.set(observation.surfaceId, observation.value);
  }

  for (const schemaKind of discoveredSchemas) {
    if (!registeredSchemas.has(schemaKind)) {
      findings.push({ id: schemaKind, reasonCode: "ORPHAN_IMPLEMENTED_NOT_REGISTERED", message: `${schemaKind} is registered as a kernel projection contract but has no agent-interface surface` });
    }
  }
  for (const surface of SURFACES) {
    if (!discoveredSchemas.has(surface.schemaKind)) {
      findings.push({ id: surface.id, reasonCode: "ORPHAN_REGISTERED_NOT_IMPLEMENTED", message: `${surface.schemaKind} is not registered in contracts.mjs` });
    }
    if (!producerSource.includes(`validatedProjection("${surface.schemaKind}"`)) {
      findings.push({ id: surface.id, reasonCode: "ORPHAN_REGISTERED_NOT_IMPLEMENTED", message: `${surface.schemaKind} has no projection producer` });
    }
    if (!cliSource.includes(`argv[0] === "${surface.command}"`)) {
      findings.push({ id: surface.id, reasonCode: "ORPHAN_IMPLEMENTED_NOT_DISPATCHED", message: `${surface.command} is not dispatched by the CLI` });
    }
    const declaredArgv = subject[surface.declarationArgv];
    if (!Array.isArray(declaredArgv) || declaredArgv.at(-1) !== surface.command) {
      findings.push({ id: surface.id, reasonCode: "ORPHAN_IMPLEMENTED_NOT_DISPATCHED", message: `${surface.command} has no exact subject declaration` });
    }
    const value = observed.get(surface.id);
    if (value === undefined) {
      findings.push({ id: surface.id, reasonCode: "ORPHAN_DISPATCHED_NOT_EMITTED", message: `${surface.id} has no runtime observation` });
    } else {
      const consumed = validateAgentProjection(surface.schemaKind, value);
      if (!consumed.ok) {
        findings.push({ id: surface.id, reasonCode: "ORPHAN_EMITTED_NOT_CONSUMED", message: `${surface.id} output was not consumed as ${surface.schemaKind}` });
      }
    }
  }
  for (const surfaceId of observed.keys()) {
    if (!SURFACES.some((surface) => surface.id === surfaceId)) {
      findings.push({ id: surfaceId, reasonCode: "ORPHAN_EMITTED_NOT_DISPATCHED", message: `${surfaceId} was observed but is not a registered surface` });
    }
  }

  return {
    schemaVersion: "agent-interface-census@1",
    complete: findings.length === 0,
    registered: SURFACES.map((surface) => surface.id),
    schemas: [...registeredSchemas].sort(),
    observed: [...observed.keys()].sort(),
    findings: findings.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0))
  };
}
