// Only this Node broker has process/file APIs. Candidate ECMAScript executes
// inside WebAssembly with no host function or I/O capability installed.
import {readFileSync,realpathSync} from 'node:fs';
import {resolve,relative,extname} from 'node:path';
import runtime from '../vendor/quickjs/runtime.cjs';
import {OBSERVER_SOURCE} from './behavioral-observer-source.mjs';
const input=JSON.parse(readFileSync(0,'utf8'));
if(input.schemaVersion!=='behavioral-worker-input@1'||!Array.isArray(input.invocations)||input.invocations.length>4096)throw Error('invalid worker input');
const root=realpathSync(input.candidateRoot),end=Date.now()+Math.min(60000,input.budgetMs);
const engine=await runtime.createEngine();
const observations=[];let observationBytes=256;
const outputLimit=input.maxObservationBytes;
if(!Number.isSafeInteger(outputLimit)||outputLimit<1)throw Error("invalid observation limit");
for(let index=0;index<input.invocations.length;index++){
 const invocation=input.invocations[index];let vm;const handles=[];
 try {
  if(Date.now()>=end)throw Error('worker deadline');
  vm=engine.newContext();vm.runtime.setMemoryLimit(64*1024*1024);vm.runtime.setMaxStackSize(1024*1024);vm.runtime.setInterruptHandler(()=>Date.now()>=end);
  const managed=h=>(handles.push(h),h);
  function unwrap(result){if(result.error){const e=managed(result.error);throw Error('JavaScript execution failed');}return managed(result.value);}
  function settle(result){
   if(result.error)return {threw:true,value:managed(result.error)};
   const handle=managed(result.value);
   for(;;){
    const state=vm.getPromiseState(handle);
    if(state.type==='fulfilled')return {threw:false,value:managed(state.value)};
    if(state.type==='rejected')return {threw:true,value:managed(state.error)};
    if(!vm.runtime.hasPendingJob()||Date.now()>=end)throw Error('unsettled or timed out promise');
    const jobs=vm.runtime.executePendingJobs(1000);if(jobs.error){managed(jobs.error);throw Error('promise job failed');}
   }
  }
  let loadedBytes=0;
  function modulePath(path){const p=realpathSync(path),rel=relative(root,p);if(!rel||rel==='..'||rel.startsWith('../')||extname(p)!=='.mjs')throw Error('module outside ECMAScript fixture domain');return p;}
  function load(path){const p=modulePath(path);const bytes=readFileSync(p);loadedBytes+=bytes.length;if(bytes.length>262144||loadedBytes>4*1024*1024)throw Error('module bytes limit');return bytes.toString('utf8');}
  vm.runtime.setModuleLoader(load,(base,name)=>{if(!name.startsWith('./')&&!name.startsWith('../'))throw Error('only relative ECMAScript imports are supported');return modulePath(resolve(base,'..',name));});
  function parseObservation(handle) {const text=vm.getString(handle);if(Buffer.byteLength(text)>outputLimit)throw Error('observation byte limit');return JSON.parse(text);}
  const observer=unwrap(vm.evalCode(OBSERVER_SOURCE));
  const method=name=>managed(vm.getProp(observer,name));
  const args=unwrap(vm.callFunction(method('prepare'),vm.undefined,managed(vm.newString(JSON.stringify(invocation.args)))));
  const before=parseObservation(unwrap(vm.callFunction(method('before'),vm.undefined,args)));
  const path=modulePath(resolve(root,invocation.module));
  const namespace=settle(vm.evalCode(load(path),path,{type:'module'}));if(namespace.threw)throw Error('module initialization failed');
  const fn=managed(vm.getProp(namespace.value,invocation.export));if(vm.typeof(fn)!=='function')throw Error('missing function export');
  const argHandles=invocation.args.map((_,i)=>managed(vm.getProp(args,i)));
  const returned=settle(vm.callFunction(fn,vm.undefined,...argHandles));
  const exceptionTypes=returned.threw?JSON.parse(vm.getString(unwrap(vm.callFunction(method('exception'),vm.undefined,returned.value)))):[];
  const after=parseObservation(unwrap(vm.callFunction(method('after'),vm.undefined,args,returned.threw?vm.undefined:returned.value)));
  const observation={index,before,after,threw:returned.threw,exceptionTypes};
  observationBytes+=Buffer.byteLength(JSON.stringify(observation))+1;
  if(observationBytes>outputLimit)throw Error('aggregate observation limit');
  observations.push(observation);
 }catch(error){observations.push({index,error:'CANDIDATE_EXECUTION_FAILED'});}
 finally{
  for(const handle of handles.reverse())if(handle.alive)handle.dispose();
  if(vm?.alive)vm.dispose();
 }
}
if(observationBytes>outputLimit)throw Error('aggregate observation limit exceeded');
process.stdout.write(JSON.stringify({schemaVersion:'behavioral-observations@1',workerPid:process.pid,parentPid:process.ppid,observations})+'\n');
