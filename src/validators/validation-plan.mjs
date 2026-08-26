import { canonicalize } from "../canonical-json.mjs";
import { runTargetCommand } from "../runner.mjs";

// validation-plan-execute@1 — CANDIDATE_VALIDATION.
// Executes every contract validation command exactly once through the
// exact-argv runner against the candidate materialization, captures a
// machine report per command, and proves completeness: every declared
// command has exactly one report, and any non-success is an explicit FIRED
// reason — omitted work can never look like a pass. Commands are exact argv
// arrays end-to-end; there is no shell and no string reconstruction.
export function validationPlanExecute(context) {
  const { workContract, candidateDir, check, evidence } = context;
  if (!candidateDir) {
    return { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"], details: { failure: "no candidate workspace" } };
  }

  const reasonCodes = new Set();
  const evidenceRefs = [];
  const reports = [];
  let infrastructureFailed = false;

  for (const command of workContract.validationCommands) {
    let execution;
    try {
      execution = runTargetCommand({
        commandId: command.commandId,
        phase: command.phase,
        argv: command.argv,
        cwd: candidateDir,
        envAllowlist: [],
        timeoutSeconds: Math.min(check.timeoutSeconds, workContract.maxRuntimeSeconds),
        maxOutputBytes: workContract.resourceCeilings.maxOutputBytes
      });
    } catch (error) {
      infrastructureFailed = true;
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

  // Completeness proof: exactly one report per declared command.
  const reported = new Set(reports.map((r) => r.commandId));
  const declared = workContract.validationCommands.map((c) => c.commandId);
  const complete = declared.length === reports.length && declared.every((id) => reported.has(id));
  if (!complete) infrastructureFailed = true;

  if (infrastructureFailed) {
    return {
      outcome: "INFRA_FAILURE",
      reasonCodes: ["INFRASTRUCTURE_FAILURE", ...reasonCodes].sort(),
      evidence: evidenceRefs,
      details: { reports }
    };
  }
  return {
    outcome: reasonCodes.size > 0 ? "FIRED" : "PASS",
    reasonCodes: [...reasonCodes].sort(),
    evidence: evidenceRefs,
    details: { reports }
  };
}
