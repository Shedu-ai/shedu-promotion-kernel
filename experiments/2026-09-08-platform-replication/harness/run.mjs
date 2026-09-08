import {readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url));
const [kernelArg,label]=process.argv.slice(2);const kernel=resolve(kernelArg);
if(!label || !/^[a-z0-9-]+$/.test(label))throw Error('safe output label required');
const out=join(root,'evidence',label);mkdirSync(out,{recursive:false});
const hash=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
const save=(p,v)=>writeFileSync(p,JSON.stringify(v,null,2)+'\n');
const manifest=JSON.parse(readFileSync(join(root,'INPUT-MANIFEST.json')));
for(const [name,digest] of Object.entries(manifest.files))if(hash(readFileSync(join(root,name)))!==digest)throw Error('frozen bytes changed: '+name);
const {evaluateCandidate,evaluationDigestOf}=await import(pathToFileURL(join(kernel,'src/evaluate.mjs')));
const {verifyActivationPair}=await import(pathToFileURL(join(kernel,'src/activation.mjs')));
const cases=JSON.parse(readFileSync(join(root,'frozen-inputs/cases.json')));
const identity={kernel,commit:spawnSync('git',['-C',kernel,'rev-parse','HEAD'],{encoding:'utf8'}).stdout.trim(),tree:spawnSync('git',['-C',kernel,'rev-parse','HEAD^{tree}'],{encoding:'utf8'}).stdout.trim(),platform:process.platform,architecture:process.arch,node:process.version,startedAt:new Date().toISOString(),environment:{...process.env},inputManifestDigest:hash(readFileSync(join(root,'INPUT-MANIFEST.json')))};
save(join(out,'identity.json'),identity);
const records=[],pairRecords=[];
const targets=new Map();
for(const c of cases){
 let target=targets.get(c.targetBundle);
 if(!target){target=join(out,'targets',c.group+'-'+c.variant);mkdirSync(join(out,'targets'),{recursive:true});const r=spawnSync('git',['clone','--no-hardlinks',join(root,'frozen-inputs',c.targetBundle),target],{encoding:'utf8'});if(r.status!==0)throw Error(r.stderr);spawnSync('git',['-C',target,'remote','remove','origin']);targets.set(c.targetBundle,target);}
 for(let repeat=1;repeat<=3;repeat++){
  const dest=join(out,c.caseId,String(repeat));mkdirSync(dest,{recursive:true});
  const contract=readFileSync(join(root,'frozen-inputs',c.contract));if(hash(contract)!==c.contractDigest)throw Error('contract drift');
  const start=performance.now();let outcome;
  try{outcome=evaluateCandidate({repoDir:target,contractBytes:contract,outDir:join(dest,'bundle')});}catch(e){outcome={ok:false,thrown:{name:e.name,message:e.message,stack:e.stack}};}
  const seconds=(performance.now()-start)/1000;
  let verification=null;
  if(outcome.receipt){
   const r=outcome.receipt, bundle=join(dest,'bundle');
   const argv=[join(kernel,'src/cli.mjs'),'verify-receipt','--receipt',join(bundle,'receipt.json'),'--plan',join(bundle,'plan.json'),'--evidence',join(bundle,r.artifactRoot,'evidence')];
   const check=spawnSync(process.execPath,argv,{encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024});
   writeFileSync(join(dest,'verify.stdout'),check.stdout??'');writeFileSync(join(dest,'verify.stderr'),check.stderr??'');verification={argv:[process.execPath,...argv],exitCode:check.status,error:check.error?.message??null};save(join(dest,'verification.json'),verification);
  }
  const r=outcome.receipt;
  const record={caseId:c.caseId,group:c.group,variant:c.variant,role:c.role,repeat,seconds,ok:outcome.ok,disposition:r?.disposition??null,reasonCodes:r?.reasonCodes??[],expected:c.expectedByPlatform[process.platform]??null,offlineVerificationExitCode:verification?.exitCode??null,errors:outcome.errors??outcome.thrown??null,planDigest:r?.digests.compiledPlan??null,evaluationDigest:r?evaluationDigestOf({planDigest:r.digests.compiledPlan,results:r.checkResults,disposition:r.disposition,reasonCodes:r.reasonCodes}):null,receiptDigest:r?hash(readFileSync(join(dest,'bundle/receipt.json'))):null,bundle:join(dest,'bundle'),checkOutcomes:r?.checkResults.map(x=>({checkId:x.checkId,outcome:x.outcome,reasonCodes:x.reasonCodes}))??[]};
  records.push(record);save(join(dest,'result.json'),record);save(join(out,'results.json'),records);console.log(JSON.stringify({caseId:c.caseId,repeat,disposition:record.disposition,reasons:record.reasonCodes,verified:record.offlineVerificationExitCode}));
 }
}
for(const group of ['v1-strict','v2-strict','v2-bounded'])for(let repeat=1;repeat<=3;repeat++){
 const find=(variant,role)=>records.find(x=>x.group===group&&x.variant===variant&&x.role===role&&x.repeat===repeat);
 const c=find('original','conforming'),p=find('original','planted'),d=find('drift','planted');
 const names=['genuine','wrong-fingerprint','required-signature-absent','not-planted','version-substitution','validator-substitution'];
 if(c.disposition!=='PROMOTABLE'||p.disposition!=='BLOCKED'||c.offlineVerificationExitCode!==0||p.offlineVerificationExitCode!==0){
  for(const mutation of names)pairRecords.push({group,repeat,mutation,status:'NOT_EXECUTED',reason:'No genuine operational pair; retain infrastructure/candidate outcomes separately',expected:mutation==='genuine'?'ACCEPT':'REJECT'});continue;
 }
 const rb=x=>readFileSync(join(x.bundle,'receipt.json')),pb=x=>readFileSync(join(x.bundle,'plan.json'));
 for(const mutation of names){
  const input={conformingReceiptBytes:rb(c),conformingPlanBytes:pb(c),plantedReceiptBytes:rb(p),plantedPlanBytes:pb(p),checkId:'independent-gate'};
  if(mutation==='wrong-fingerprint')input.expectedFingerprint='intentionally-wrong-frozen-fingerprint';
  if(mutation==='required-signature-absent')input.trustPolicy={requireSignature:true,trustedPublicKeys:[]};
  if(mutation==='not-planted'){input.plantedReceiptBytes=rb(c);input.plantedPlanBytes=pb(c);}
  if(mutation==='validator-substitution'){input.plantedReceiptBytes=rb(d);input.plantedPlanBytes=pb(d);}
  if(mutation==='version-substitution'){const changed=JSON.parse(input.plantedReceiptBytes);changed.schemaVersion=changed.schemaVersion==='promotion-receipt@1'?'promotion-receipt@2':'promotion-receipt@1';input.plantedReceiptBytes=Buffer.from(JSON.stringify(changed));}
  let result,status;try{result=verifyActivationPair(input);status=result.ok?'ACCEPT':'REJECT';}catch(e){status='THROWN_EXCEPTION';result={name:e.name,message:e.message,stack:e.stack};}
  const dest=join(out,'pair-mutations',group,String(repeat),mutation);mkdirSync(dest,{recursive:true});
  for(const key of ['conformingReceiptBytes','conformingPlanBytes','plantedReceiptBytes','plantedPlanBytes'])writeFileSync(join(dest,key+'.json'),input[key]);
  const record={group,repeat,mutation,status,expected:mutation==='genuine'?'ACCEPT':'REJECT',result};save(join(dest,'result.json'),record);pairRecords.push(record);
 }
}
save(join(out,'pair-results.json'),pairRecords);
const summary={candidateRuns:records.length,receipts:records.filter(x=>x.receiptDigest).length,offlineVerified:records.filter(x=>x.offlineVerificationExitCode===0).length,dispositionMismatches:records.filter(x=>x.disposition!==x.expected).map(x=>x.caseId),pairChecks:pairRecords.length,pairExecuted:pairRecords.filter(x=>x.status!=='NOT_EXECUTED').length,pairExceptions:pairRecords.filter(x=>x.status==='THROWN_EXCEPTION').length,pairMismatches:pairRecords.filter(x=>x.status!=='NOT_EXECUTED'&&x.status!==x.expected).map(x=>({group:x.group,repeat:x.repeat,mutation:x.mutation,status:x.status})),completedAt:new Date().toISOString()};save(join(out,'summary.json'),summary);console.log(JSON.stringify(summary));
