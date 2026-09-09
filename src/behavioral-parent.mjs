// Candidate code is never imported here. Only the trusted parent owns cases,
// expected values, assertions and the verdict. The isolated worker emits data.
import {fileURLToPath} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {runTargetCommand} from './runner.mjs';
import {closed,decodeValue,validateCases,snapshot} from './behavioral-data.mjs';
export const BEHAVIORAL_WORKER_FILES = Object.freeze([
 'behavioral-worker.mjs','behavioral-observer-source.mjs','behavioral-data.mjs','../vendor/quickjs/runtime.cjs','../package.json'
].map(path=>fileURLToPath(new URL(path,import.meta.url))));
export const behavioralWorkerArgv=()=>['node',BEHAVIORAL_WORKER_FILES[0]];

function decodeGraph(graph) {
 closed(graph,['roots','nodes']);
 if(!Array.isArray(graph.roots)||!Array.isArray(graph.nodes)||graph.nodes.length>10000)throw Error('invalid observation graph');
 const objects=new Map(),records=new Map();let properties=0;
 for(const row of graph.nodes) {
  if(!Array.isArray(row)||row.length!==3||!Number.isSafeInteger(row[0])||row[0]<0||row[0]>20000||objects.has(row[0])||!['object','array','null'].includes(row[1])||!Array.isArray(row[2]))throw Error('invalid observation node');
  objects.set(row[0],row[1]==='array'?[]:Object.create(row[1]==='null'?null:Object.prototype));records.set(row[0],row);
 }
 function value(item) {
  if(!Array.isArray(item)||![1,2].includes(item.length))throw Error('invalid observation value');
  const [tag,v]=item;
  if(item.length===1){if(tag==='undefined')return undefined;if(tag==='null')return null;throw Error('unknown observation value');}
  if(tag==='ref'){if(!objects.has(v))throw Error('missing observation node');return objects.get(v);}
  if(tag==='string'&&typeof v==='string')return v;
  if(tag==='boolean'&&typeof v==='boolean')return v;
  if(tag==='bigint'&&typeof v==='string'&&/^-?(0|[1-9][0-9]*)$/.test(v))return BigInt(v);
  if(tag==='number'&&typeof v==='string') {const n=Number(v);if(['NaN','Infinity','-Infinity','-0'].includes(v)||String(n)===v)return n;}
  throw Error('invalid observation primitive');
 }
 for(const [id,row] of records){
  const keys=new Set();
  for(const property of row[2]){
   if(!Array.isArray(property)||property.length!==5||typeof property[0]!=='string'||keys.has(property[0])||property.slice(1,4).some(v=>typeof v!=='boolean')||++properties>50000)throw Error('invalid observed property');
   keys.add(property[0]);Object.defineProperty(objects.get(id),property[0],{enumerable:property[1],writable:property[2],configurable:property[3],value:value(property[4])});
  }
 }
 const reachable=new Set();
 function reach(v,depth=0){if(depth>64)throw Error('observation depth exceeded');if(v[0]!=='ref'||reachable.has(v[1]))return;reachable.add(v[1]);for(const p of records.get(v[1])[2])reach(p[4],depth+1);}
 for(const root of graph.roots)reach(root);
 if(reachable.size!==records.size)throw Error('unreachable observation nodes');
 return {values:graph.roots.map(value),objects};
}

export function judgeBehavioralObservations(document, payload) {
 validateCases(document);closed(payload,['schemaVersion','workerPid','parentPid','observations']);
 if(payload.schemaVersion!=='behavioral-observations@1'||!Number.isSafeInteger(payload.workerPid)||!Number.isSafeInteger(payload.parentPid)||!Array.isArray(payload.observations)||payload.observations.length!==document.cases.length)throw Error('incomplete worker observations');
 const seen=new Set();const results=[];
 for(const observation of payload.observations){
  if(!Number.isInteger(observation.index)||observation.index<0||observation.index>=document.cases.length||seen.has(observation.index))throw Error('unbound or duplicate observation');
  seen.add(observation.index);const item=document.cases[observation.index],failures=[];
  if(Object.hasOwn(observation,'error')){
   closed(observation,['index','error']);if(observation.error!=='CANDIDATE_EXECUTION_FAILED')throw Error('unknown observation error');failures.push('candidate-execution-failed');
  }else{
   closed(observation,['index','before','after','threw','exceptionTypes']);
   if(typeof observation.threw!=='boolean'||!Array.isArray(observation.exceptionTypes)||new Set(observation.exceptionTypes).size!==observation.exceptionTypes.length||observation.exceptionTypes.some(v=>!['Error','TypeError','RangeError','SyntaxError'].includes(v)))throw Error('invalid exception observation');
   const before=decodeGraph(observation.before),after=decodeGraph(observation.after),inputs=decodeValue(item.args);
   if(before.values.length!==inputs.length||after.values.length!==inputs.length+1||inputs.some((v,i)=>!isDeepStrictEqual(snapshot(v),snapshot(before.values[i]))))throw Error('observations do not bind invocation arguments');
   const args=after.values.slice(0,-1),returned=after.values.at(-1);
   if(Object.hasOwn(item.expect,'throws')){
    if(!observation.threw)failures.push('expected-exception');
    else if(item.expect.throws!==true&&!observation.exceptionTypes.includes(item.expect.throws))failures.push('exception-type');
   }else if(Object.hasOwn(item.expect,'ownValues')){
    const own=object=>{
     if(!object||typeof object!=='object'||Array.isArray(object))throw Error('returned value is not an object');
     return Object.fromEntries(Reflect.ownKeys(object).map(k=>[k,Object.getOwnPropertyDescriptor(object,k).value]));
    };
    if(observation.threw||!returned||typeof returned!=='object'||Array.isArray(returned)||!isDeepStrictEqual(own(returned),own(decodeValue(item.expect.ownValues))))failures.push('own-property-values');
   }else if(observation.threw||!isDeepStrictEqual(returned,decodeValue(item.expect.returns)))failures.push('return-value');
   for(const index of item.preserveArgs??[])if(!isDeepStrictEqual(snapshot(args[index]),snapshot(before.values[index])))failures.push(`argument-${index}-mutated`);
   for(const entry of item.afterArgs??[])if(!isDeepStrictEqual(args[entry.index],decodeValue(entry.value)))failures.push(`argument-${entry.index}-postcondition`);
   if(item.returnArgIndex!==undefined&&returned!==args[item.returnArgIndex])failures.push('return-identity');
   if(item.returnElementsFromArg!==undefined&&(!Array.isArray(returned)||!Array.isArray(args[item.returnElementsFromArg])||returned.some(value=>!args[item.returnElementsFromArg].includes(value))))failures.push('element-identity');
   if(item.freshReturn===true){
    const originalIds=new Set(observation.before.nodes.map(n=>n[0])),byId=new Map(observation.after.nodes.map(n=>[n[0],n]));const visited=new Set();
    function aliases(v){if(v[0]!=='ref'||visited.has(v[1]))return false;visited.add(v[1]);return originalIds.has(v[1])||byId.get(v[1])[2].some(p=>aliases(p[4]));}
    if(aliases(observation.after.roots.at(-1)))failures.push('return-aliases-input');
   }
  }
  results.push({id:item.id,criterionIds:item.criterionIds,outcome:failures.length?'FAIL':'PASS',failures});
 }
 results.sort((a,b)=>document.cases.findIndex(x=>x.id===a.id)-document.cases.findIndex(x=>x.id===b.id));
 return {schemaVersion:'behavioral-report@2',status:results.every(r=>r.outcome==='PASS')?'PASS':'BLOCKED',scenarios:results.length,results};
}

export function executeBehavioralCases(document,candidateRoot,{commandId='behavioral-worker',phase='CANDIDATE_VALIDATION',timeoutMs=60000,maxOutputBytes=1048576,maxProcesses=1,executionRequirement=null}={}) {
 validateCases(document);
 const input={schemaVersion:'behavioral-worker-input@1',candidateRoot,budgetMs:timeoutMs,maxObservationBytes:maxOutputBytes,invocations:document.cases.map(({module,export:name,args})=>({module,export:name,args}))};
 const inputBytes=Buffer.from(JSON.stringify(input));if(inputBytes.length>4*1024*1024)throw Error('behavioral invocation input exceeds limit');
 const execution=runTargetCommand({commandId,phase,argv:behavioralWorkerArgv(),cwd:candidateRoot,timeoutMs,maxOutputBytes,maxProcesses,executionRequirement,readRoots:[candidateRoot],readFiles:BEHAVIORAL_WORKER_FILES,stdinBytes:inputBytes});
 let observations=null,report=null,error=null;
 if(execution.succeeded){try{observations=JSON.parse(execution.stdout);report=judgeBehavioralObservations(document,observations);}catch(e){error='EVIDENCE_MISSING';}}
 return {execution,inputBytes,observations,report,error};
}

export function runCases(document,candidateRoot,options={}) {
 const {execution,report}=executeBehavioralCases(document,candidateRoot,options);
 if(report)return report;
 return {schemaVersion:'behavioral-report@2',status:'BLOCKED',scenarios:document.cases.length,results:document.cases.map(item=>({id:item.id,criterionIds:item.criterionIds,outcome:'FAIL',failures:[execution.report?.timedOut?'worker-timeout':'worker-observation-missing']}))};
}
