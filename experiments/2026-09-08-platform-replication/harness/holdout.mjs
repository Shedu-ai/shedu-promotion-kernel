import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url));
const [k,label,source='repaired-native']=process.argv.slice(2),kernel=resolve(k);
const {verifyActivationPair}=await import(pathToFileURL(join(kernel,'src/activation.mjs')));
const {signReceipt,generateSigningKeyPem,verifyReceipt}=await import(pathToFileURL(join(kernel,'src/receipt.mjs')));
const {canonicalize}=await import(pathToFileURL(join(kernel,'src/canonical-json.mjs')));
const definition=JSON.parse(readFileSync(join(root,'frozen-inputs/holdout-consumers.json')));
const out=join(root,'evidence',label);mkdirSync(out,{recursive:false});
const rows=[];
for(const group of ['v1-strict','v2-strict'])for(let repeat=1;repeat<=definition.repeat;repeat++){
 const folder=role=>join(root,'evidence',source,`${group}-original-${role}`,String(repeat),'bundle');
 const read=(role,name)=>readFileSync(join(folder(role),name));
 const privateKey=generateSigningKeyPem();
 const c=signReceipt(JSON.parse(read('conforming','receipt.json')),privateKey);
 const p=signReceipt(JSON.parse(read('planted','receipt.json')),privateKey);
 const untrusted=signReceipt(JSON.parse(read('planted','receipt.json')),generateSigningKeyPem()).signing.publicKey;
 const cb=Buffer.from(canonicalize(c)),pb=Buffer.from(canonicalize(p));
 const cp=read('conforming','plan.json'),pp=read('planted','plan.json');
 const vC=verifyReceipt({receiptBytes:cb,planBytes:cp,evidenceDir:join(folder('conforming'),'artifacts/evidence'),expectedPublicKey:c.signing.publicKey});
 const vP=verifyReceipt({receiptBytes:pb,planBytes:pp,evidenceDir:join(folder('planted'),'artifacts/evidence'),expectedPublicKey:p.signing.publicKey});
 if(!vC.ok||!vP.ok)throw Error('signed source pair failed full offline verification');
 for(const def of definition.cases){
  const input={conformingReceiptBytes:cb,conformingPlanBytes:cp,plantedReceiptBytes:pb,plantedPlanBytes:pp,checkId:'independent-gate',trustPolicy:{requireSignature:true,trustedPublicKeys:[c.signing.publicKey]}};
  if(def.id==='h02-untrusted-signer')input.trustPolicy.trustedPublicKeys=[untrusted];
  if(def.id==='h03-invalid-signature')input.plantedReceiptBytes=Buffer.from(canonicalize({...p,signing:{...p.signing,signature:'0'.repeat(128)}}));
  if(def.id==='h04-nonexistent-check')input.checkId='absent-frozen-check';
  let status,result;try{result=verifyActivationPair(input);status=result.ok?'ACCEPT':'REJECT';}catch(e){status='THROWN_EXCEPTION';result={name:e.name,message:e.message,stack:e.stack};}
  const dest=join(out,group,String(repeat),def.id);mkdirSync(dest,{recursive:true});
  for(const field of ['conformingReceiptBytes','conformingPlanBytes','plantedReceiptBytes','plantedPlanBytes'])writeFileSync(join(dest,field+'.json'),input[field]);
  const row={group,repeat,caseId:def.id,expected:def.expected,status,result,trustPolicy:input.trustPolicy,sourceFullVerification:{conforming:vC.ok,planted:vP.ok}};writeFileSync(join(dest,'result.json'),JSON.stringify(row,null,2)+'\n');rows.push(row);
 }
}
writeFileSync(join(out,'results.json'),JSON.stringify(rows,null,2)+'\n');
const summary={checks:rows.length,passed:rows.filter(x=>x.status===x.expected).length,failed:rows.filter(x=>x.status!==x.expected),privateKeyPersisted:false,officialAuthority:false};writeFileSync(join(out,'summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
if(summary.failed.length)process.exitCode=1;
