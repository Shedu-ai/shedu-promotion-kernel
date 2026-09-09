import {readAuthorityBlob} from '../authority.mjs';
import {canonicalize} from '../canonical-json.mjs';
import {validateCases} from '../behavioral-data.mjs';
import {executeBehavioralCases} from '../behavioral-parent.mjs';
import {runtimeExecutionRequirement} from '../execution-policy.mjs';

// Only this trusted parent can turn observations into a behavioral verdict.
// Cases are data from the pinned Git base, never executable target authority.
export function behavioralCasesVerify({repoDir,plan,check,candidateDir,workContract,evidence,deadline}) {
 const refs=[];
 const put=(label,bytes)=>refs.push(evidence.put({artifactId:`behavioral-${label}-${check.checkId}`,checkId:check.checkId,validatorId:'behavioral-cases-verify@1',bytes:Buffer.isBuffer(bytes)?bytes:Buffer.from(typeof bytes==='string'?bytes:canonicalize(bytes)),mediaType:'application/json'}));
 const authority=readAuthorityBlob(repoDir,plan.baseCommit,check.validator.casesPath);
 if(!authority.ok) return {outcome:'FIRED',reasonCodes:['EVIDENCE_MISSING'],evidence:refs};
 let cases;
 try {
  cases=JSON.parse(authority.bytes);validateCases(cases);
  const bound=check.inputs.filter(x=>x.startsWith('acceptance-criterion.')).map(x=>x.slice('acceptance-criterion.'.length)).sort();
  if(JSON.stringify(bound)!==JSON.stringify([...cases.criterionIds].sort())) throw Error('unbound criteria');
 } catch {return {outcome:'FIRED',reasonCodes:['SCHEMA_VIOLATION'],evidence:refs};}
 put('cases',authority.bytes);
 const remainingMs=deadline?.remainingMs()??check.timeoutSeconds*1000;
 if(remainingMs<=0)return {outcome:'FIRED',reasonCodes:['DEADLINE_EXCEEDED'],evidence:refs};
 const result=executeBehavioralCases(cases,candidateDir,{
  commandId:check.checkId,phase:check.phase,timeoutMs:Math.min(check.timeoutSeconds*1000,remainingMs),
  maxOutputBytes:workContract.resourceCeilings.maxOutputBytes,
  maxProcesses:workContract.schemaVersion==='work-contract@1'?workContract.resourceCeilings.maxProcesses:undefined,
  executionRequirement:check.execution?runtimeExecutionRequirement(check.execution):null
 });
 const {execution,report}=result;
 put('input',result.inputBytes);
 if(execution.report)put('command',execution.report);
 put('observations',execution.stdout);
 put('stderr',execution.stderr);
 if(report)put('verdict',report);
 const reason=execution.toolchainRejected?'TOOLCHAIN_UNRESOLVED':execution.spawnFailed?'INFRASTRUCTURE_FAILURE':
  execution.report?.timedOut?'COMMAND_TIMEOUT':execution.taskBudgetExceeded?'TASK_BUDGET_EXCEEDED':
  !execution.succeeded?'COMMAND_FAILED':!report?'EVIDENCE_MISSING':deadline?.expired()?'DEADLINE_EXCEEDED':report.status!=='PASS'?'COMMAND_FAILED':null;
 return {outcome:reason?(execution.spawnFailed||execution.toolchainRejected?'INFRA_FAILURE':'FIRED'):'PASS',reasonCodes:reason?[reason]:[],evidence:refs,
  details:{reports:[{commandId:check.checkId,executed:!!execution.report,report:execution.report}]}};
}
