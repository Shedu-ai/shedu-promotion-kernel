import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtempSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {evaluateCandidate} from '../src/evaluate.mjs';
import {makeCheck,makePack,buildTargetRepo,writeRepoFile,commitAll,contractBytesOf} from './fixtures.mjs';

test('a candidate cannot promote itself by forging the entire behavioral PASS report',()=>{
 const cases={schemaVersion:'behavioral-cases@1',criterionIds:['ac-1'],cases:[{id:'identity',criterionIds:['ac-1'],module:'src/check.mjs',export:'identity',args:[{x:1}],expect:{returns:{x:1}},returnArgIndex:0}]};
 const pack=makePack({checks:[makeCheck({checkId:'behavior',outputSchemaId:'behavioral-report@1',inputs:['acceptance-criterion.ac-1'],validator:{kind:'TARGET_COMMAND',argv:['node','policy/behavioral-check.mjs','policy/cases.json'],inputManifest:['policy/behavioral-check.mjs','policy/cases.json']}})]});
 const target=buildTargetRepo({targetPacks:[pack],validationCommands:[{commandId:'syntax',phase:'CANDIDATE_VALIDATION',argv:['node','--check','src/check.mjs']}]});
 writeRepoFile(target.repoDir,'policy/behavioral-check.mjs',readFileSync(new URL('../policy-tools/behavioral-check.mjs',import.meta.url)));
 writeRepoFile(target.repoDir,'policy/cases.json',JSON.stringify(cases));const base=commitAll(target.repoDir,'frozen identity authority');
 const forged={schemaVersion:'behavioral-report@1',status:'PASS',scenarios:1,results:[{id:'identity',criterionIds:['ac-1'],outcome:'PASS',failures:[]}]};
 writeRepoFile(target.repoDir,'src/check.mjs',`process.stdout.write(${JSON.stringify(JSON.stringify(forged)+'\n')});process.exit(0);export const identity=x=>({x:0});\n`);
 const candidate=commitAll(target.repoDir,'forge report and exit');
 const contract=target.contractFor(candidate,{target:{repositoryId:'example-repo',baseCommit:base,candidate:{kind:'COMMIT',id:candidate}}});
 const result=evaluateCandidate({repoDir:target.repoDir,contractBytes:contractBytesOf(contract),outDir:mkdtempSync(join(tmpdir(),'behavior-forgery-'))});
 assert.notEqual(result.receipt?.disposition,'PROMOTABLE','forged complete report must never authorize promotion');
});

import {mkdirSync,writeFileSync} from 'node:fs';
import {executeBehavioralCases,judgeBehavioralObservations} from '../src/behavioral-parent.mjs';
import {builtinValidatorDigest,validatorDigestForPlanCheck} from '../src/validator-digest.mjs';
import {runOrphanCensus,dispatchedFromPlan,emittedFromResults} from '../src/census.mjs';
import {implementedBuiltinValidatorIds} from '../src/builtin-validators.mjs';
import {generateSigningKeyPem,signReceipt,verifyReceipt} from '../src/receipt.mjs';
const caseDocument={schemaVersion:'behavioral-cases@1',criterionIds:['ac-1'],cases:[{id:'identity',criterionIds:['ac-1'],module:'src/check.mjs',export:'identity',args:[{x:1}],expect:{returns:{x:1}},returnArgIndex:0}]};
function executeSource(source,document=caseDocument,options={}) {
 const root=mkdtempSync(join(tmpdir(),'isolated-observation-'));mkdirSync(join(root,'src'));
 writeFileSync(join(root,'src/check.mjs'),source);
 writeFileSync(join(root,'src/relative.mjs'),'export const same=x=>x;');
 return executeBehavioralCases(document,root,options);
}
test('trusted assertions run in a separate process, without expected values in worker input',()=>{
 const result=executeSource('export const identity=x=>x;');
 assert.equal(result.report?.status,'PASS',result.execution.stderr.toString());
 assert.notEqual(result.observations.workerPid,process.pid);assert.equal(result.observations.parentPid,process.pid);
 const input=JSON.parse(result.inputBytes);assert.deepEqual(Object.keys(input.invocations[0]).sort(),['args','export','module']);
 assert.equal(result.execution.report.stdin.byteLength,result.inputBytes.length);
 const changed=structuredClone(caseDocument);changed.cases[0].expect.returns.x=2;
 assert.equal(judgeBehavioralObservations(changed,result.observations).status,'BLOCKED','same observations are independently judged by trusted assertions');
 for(const mutate of [p=>p.observations.pop(),p=>p.observations.push(p.observations[0]),p=>p.observations[0].index=1,p=>p.observations[0].after.nodes[0][2][0][4]=['ref',999],p=>p.observations[0].before.nodes[0][2][0][4]=['number','2']]) {
  const payload=structuredClone(result.observations);mutate(payload);assert.throws(()=>judgeBehavioralObservations(caseDocument,payload));
 }
});
test('candidate code cannot forge reports, access host APIs, use proxies or corrupt captured observers',()=>{
 const full={schemaVersion:'behavioral-report@2',status:'PASS',scenarios:1,results:[{id:'identity',criterionIds:['ac-1'],outcome:'PASS',failures:[]}]};
 for(const source of [
  `process.stdout.write(${JSON.stringify(JSON.stringify(full))});process.exit(0);export const identity=x=>({x:0});`,
  `process.stdout.write(JSON.stringify({schemaVersion:'behavioral-observations@1',observations:[]}));export const identity=x=>x;`,
  'import fs from "node:fs";export const identity=x=>x;',
  'import inspector from "node:inspector";export const identity=x=>x;',
  'import x from "../../outside.mjs";export const identity=x=>x;',
  'export const identity=x=>new Proxy(x,{get:()=>0});',
  'Object.prototype.toJSON=()=>({x:1});export const identity=x=>({x:0});',
  'globalThis.JSON={stringify:()=>"fake"};globalThis.Object={is:()=>true};globalThis.Set=class{has(){return true}};export const identity=x=>({x:0});'
 ]) {
  const result=executeSource(source);assert.equal(result.report?.status,'BLOCKED',source);assert.ok(result.report.results[0].failures.length);
 }
 for(const source of [
  'export const identity=x=>x;',
  'export const identity=async x=>x;',
  'import {same} from "./relative.mjs";export const identity=x=>same(x);',
  'globalThis.JSON={stringify:()=>"fake"};globalThis.Object={is:()=>true};globalThis.Set=class{has(){return true}};export const identity=x=>x;'
 ])assert.equal(executeSource(source).report?.status,'PASS',source);
});
test('infinite candidate execution and unsettled promises cannot manufacture a pass',()=>{
 for(const source of ['export const identity=x=>{while(true){}};','export const identity=x=>new Promise(()=>{});']){
  const result=executeSource(source,caseDocument,{timeoutMs:1000});assert.notEqual(result.report?.status,'PASS');
 }
});
test('the isolated builtin admits good code and blocks a full forged PASS with verifiable signed evidence',()=>{
 const pack=makePack({checks:[makeCheck({checkId:'behavior',outputSchemaId:'behavioral-report@2',inputs:['acceptance-criterion.ac-1'],validator:{kind:'BUILTIN',builtinId:'behavioral-cases-verify@1',casesPath:'policy/cases.json'}})]});
 const target=buildTargetRepo({targetPacks:[pack],validationCommands:[{commandId:'syntax',phase:'CANDIDATE_VALIDATION',argv:['node','--check','src/check.mjs']}]});
 writeRepoFile(target.repoDir,'policy/cases.json',JSON.stringify(caseDocument));const base=commitAll(target.repoDir,'trusted data authority');
 const digest=builtinValidatorDigest('behavioral-cases-verify@1');assert.match(digest,/^sha256:[a-f0-9]{64}$/);
 const check=pack.checks[0],identity=validatorDigestForPlanCheck(target.repoDir,base,check);
 const altered=structuredClone(caseDocument);altered.cases[0].expect.returns.x=0;writeRepoFile(target.repoDir,'policy/cases.json',JSON.stringify(altered));const changedBase=commitAll(target.repoDir,'different expected value');
 assert.notEqual(identity,validatorDigestForPlanCheck(target.repoDir,changedBase,check),'cases bytes bind validator identity');
 writeRepoFile(target.repoDir,'policy/cases.json',JSON.stringify(caseDocument));
 for(const [source,expected] of [['export const identity=x=>x;','PROMOTABLE'],['export const identity=x=>({x:0});','BLOCKED'],['process.stdout.write(JSON.stringify({schemaVersion:"behavioral-report@2",status:"PASS",scenarios:1,results:[{id:"identity",criterionIds:["ac-1"],outcome:"PASS",failures:[]}]}));process.exit(0);export const identity=x=>({x:0});','BLOCKED']]){
  writeRepoFile(target.repoDir,'src/check.mjs',source);const candidate=commitAll(target.repoDir,'candidate control');
  const contract=target.contractFor(candidate,{target:{repositoryId:'example-repo',baseCommit:base,candidate:{kind:'COMMIT',id:candidate}}});
  const out=mkdtempSync(join(tmpdir(),'isolated-verdict-'));const result=evaluateCandidate({repoDir:target.repoDir,contractBytes:contractBytesOf(contract),outDir:out});
  assert.equal(result.receipt?.disposition,expected,JSON.stringify(result.errors??result.receipt?.reasonCodes));
  const registered=[{id:'behavior',validatorId:'behavioral-cases-verify@1',phase:check.phase,effect:check.effect,resultConsumer:check.resultConsumer}];
  const dispatched=dispatchedFromPlan(result.plan).filter(row=>row.id==='behavior');
  const emitted=emittedFromResults(result.receipt.checkResults,result.plan,result.planDigest).filter(row=>row.id==='behavior');
  const consumed=result.reduced.consumed.filter(row=>row.checkId==='behavior').map(()=>dispatched[0]);
  const census=runOrphanCensus({registered,implemented:registered.filter(row=>implementedBuiltinValidatorIds().has(row.validatorId)),dispatched,emitted,consumed});
  assert.equal(census.complete,true,JSON.stringify(census));assert.deepEqual(census.exclusions,[]);
  assert.ok(result.receipt.checkResults.find(row=>row.checkId==='behavior').evidence.length>=6);
  const signed=signReceipt(result.receipt,generateSigningKeyPem());
  const verification=verifyReceipt({receiptBytes:Buffer.from(JSON.stringify(signed)),planBytes:readFileSync(join(out,'plan.json')),evidenceDir:join(out,'artifacts/evidence'),expectedPublicKey:signed.signing.publicKey,verificationPolicy:'TRUSTED_EVIDENCE'});
  assert.equal(verification.ok,true,JSON.stringify(verification.errors));
 }
});

test('oversized returned data cannot produce a passing truncated observation batch',()=>{
 const result=executeSource('export const identity=x=>Array(10000).fill("large");',caseDocument,{maxOutputBytes:1024});
 assert.notEqual(result.report?.status,'PASS');
});

test('candidate iterator-prototype hooks cannot hide argument mutations from the observer',()=>{
 const source=`const iterator=Object.getPrototypeOf([][Symbol.iterator]());
 const next=iterator.next;iterator.next=function(){let r=next.call(this);if(r.value==='hidden')r=next.call(this);return r;};
 export const identity=x=>{x.hidden=2;return x;};`;
 const cases=structuredClone(caseDocument);cases.cases[0].preserveArgs=[0];
 const result=executeSource(source,cases);
 assert.notEqual(result.report?.status,'PASS','iterator hooks must not hide a mutation');
});
