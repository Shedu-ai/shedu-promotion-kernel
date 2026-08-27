import { canonicalize } from "../canonical-json.mjs";
import { runTargetCommand } from "../runner.mjs";

// Control point: commands execute in their declared phase, one per-phase
// check instance, bounded by the evaluation deadline.
export const CONTROL_POINTS = Object.freeze(["phase-scheduled-execution"]);

// The exact per-phase command selection the validator uses; exposed for the
// control-surface runtime proof.
export function commandsForPhase(validationCommands, phase) {
  return validationCommands.filter((c) => c.phase === phase);
}

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
  const { workContract, candidateDir, baseDir, check, evidence, deadline } = context;
  if (!candidateDir) {
    return { outcome: "INFRA_FAILURE", reasonCodes: ["INFRASTRUCTURE_FAILURE"], details: { failure: "no candidate workspace" } };
  }

  const phaseCommands = commandsForPhase(workContract.validationCommands, check.phase);
  const reasonCodes = new Set();
  const evidenceRefs = [];
  const reports = [];
  let infrastructureFailed = false;
  // Validation commands exercise CANDIDATE code; the candidate is the granted
  // read root. They do not read the trusted base.
  const readRoots = [candidateDir];

  for (const command of phaseCommands) {
    // Recheck the monotonic deadline before EVERY command. Once exhausted,
    // stop launching and record an explicit non-success — never a PASS.
    const remainingMs = deadline ? deadline.remainingMs() : check.timeoutSeconds * 1000;
    if (remainingMs <= 0) {
      reasonCodes.add("DEADLINE_EXCEEDED");
      reports.push({ commandId: command.commandId, executed: false, deadlineExceeded: true });
      continue;
    }
    const timeoutMs = Math.min(check.timeoutSeconds * 1000, remainingMs);
    let execution;
    try {
      execution = runTargetCommand({
        commandId: command.commandId,
        phase: command.phase,
        argv: command.argv,
        cwd: candidateDir,
        envAllowlist: [],
        timeoutMs,
        maxOutputBytes: workContract.resourceCeilings.maxOutputBytes,
        maxProcesses: workContract.resourceCeilings.maxProcesses,
        readRoots
      });
    } catch (error) {
      infrastructureFailed = true;
      if (error?.reasonCode === "SANDBOX_UNAVAILABLE") reasonCodes.add("SANDBOX_UNAVAILABLE");
      reports.push({ commandId: command.commandId, executed: false, error: String(error) });
      continue;
    }
    if (execution.toolchainRejected) {
      infrastructureFailed = true;
      reasonCodes.add("TOOLCHAIN_UNRESOLVED");
      reports.push({ commandId: command.commandId, executed: false, toolchainRejected: true });
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
    } else if (deadline && deadline.expired()) {
      // A command that completed only after the budget expired cannot count
      // as a pass.
      reasonCodes.add("DEADLINE_EXCEEDED");
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
