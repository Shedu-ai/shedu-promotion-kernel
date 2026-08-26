import { canonicalize } from "../canonical-json.mjs";
import { runTargetCommand } from "../runner.mjs";

// validation-plan-execute@1 — one check instance per phase
// (validation-plan-admission / -validation / -finalization). Each instance
// executes exactly the contract validation commands DECLARED FOR ITS OWN
// PHASE, in that phase, through the sandboxed exact-argv runner against the
// candidate materialization, captures a machine report per command, and
// proves per-phase completeness: every command declared for this phase has
// exactly one report, and any non-success is an explicit FIRED reason —
// omitted work can never look like a pass. Commands are exact argv arrays
// end-to-end; there is no shell and no string reconstruction.
export function validationPlanExecute(context) {
  const { workContract, candidateDir, check, evidence } = context;
  if (!candidateDir) {
    return { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"], details: { failure: "no candidate workspace" } };
  }

  const phaseCommands = workContract.validationCommands.filter((c) => c.phase === check.phase);
  const reasonCodes = new Set();
  const evidenceRefs = [];
  const reports = [];
  let infrastructureFailed = false;

  for (const command of phaseCommands) {
    let execution;
    try {
      execution = runTargetCommand({
        commandId: command.commandId,
        phase: command.phase,
        argv: command.argv,
        cwd: candidateDir,
        envAllowlist: [],
        timeoutSeconds: Math.min(check.timeoutSeconds, workContract.maxRuntimeSeconds),
        maxOutputBytes: workContract.resourceCeilings.maxOutputBytes,
        maxProcesses: workContract.resourceCeilings.maxProcesses
      });
    } catch (error) {
      infrastructureFailed = true;
      if (error?.reasonCode === "SANDBOX_UNAVAILABLE") reasonCodes.add("SANDBOX_UNAVAILABLE");
      reports.push({ commandId: command.commandId, executed: false, error: String(error) });
      continue;
    }
    reports.push({ commandId: command.commandId, executed: true, report: execution.report });
    if (evidence) {
      evidenceRefs.push(
        evidence.put({
          artifactId: `command-report-${command.commandId}`,
          checkId: check.checkId,
          validatorId: "validation-plan-execute@1",
          bytes: Buffer.from(canonicalize(execution.report), "utf8"),
          mediaType: "application/json"
        }),
        evidence.put({
          artifactId: `command-stdout-${command.commandId}`,
          checkId: check.checkId,
          validatorId: "validation-plan-execute@1",
          bytes: execution.stdout,
          mediaType: "application/octet-stream"
        }),
        evidence.put({
          artifactId: `command-stderr-${command.commandId}`,
          checkId: check.checkId,
          validatorId: "validation-plan-execute@1",
          bytes: execution.stderr,
          mediaType: "application/octet-stream"
        })
      );
    }
    if (execution.spawnFailed) {
      infrastructureFailed = true;
    } else if (execution.report.timedOut) {
      reasonCodes.add("COMMAND_TIMEOUT");
    } else if (!execution.succeeded) {
      reasonCodes.add("COMMAND_FAILED");
    }
  }

  // Per-phase completeness proof: exactly one report per declared command.
  const reported = new Set(reports.map((r) => r.commandId));
  const declared = phaseCommands.map((c) => c.commandId);
  const complete = declared.length === reports.length && declared.every((id) => reported.has(id));
  if (!complete) infrastructureFailed = true;

  if (infrastructureFailed) {
    return {
      outcome: "INFRA_FAILURE",
      reasonCodes: ["INFRASTRUCTURE_FAILURE", ...reasonCodes].sort(),
      evidence: evidenceRefs,
      details: { phase: check.phase, reports }
    };
  }
  return {
    outcome: reasonCodes.size > 0 ? "FIRED" : "PASS",
    reasonCodes: [...reasonCodes].sort(),
    evidence: evidenceRefs,
    details: { phase: check.phase, reports }
  };
}
