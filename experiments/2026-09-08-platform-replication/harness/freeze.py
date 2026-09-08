import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1]; O=R/'frozen-inputs'
env={'PATH':'/usr/local/bin:/usr/bin:/bin','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_AUTHOR_NAME':'Independent Experiment','GIT_AUTHOR_EMAIL':'experiment@example.invalid','GIT_COMMITTER_NAME':'Independent Experiment','GIT_COMMITTER_EMAIL':'experiment@example.invalid','GIT_AUTHOR_DATE':'2003-03-03T03:03:03Z','GIT_COMMITTER_DATE':'2003-03-03T03:03:03Z'}
def data(x): return (json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n').encode()
def sha(b):return 'sha256:'+hashlib.sha256(b).hexdigest()
def git(p,*a):return subprocess.check_output(['git','-C',str(p),*a],env=env,stderr=subprocess.PIPE).decode().strip()
def put(p,n,b): q=p/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b if isinstance(b,bytes) else b.encode())
cases=[]
for ident,version,requirement in [('v1-strict',1,None),('v2-strict',2,{'class':'SINGLE_PROCESS','maxTasks':64}),('v2-bounded',2,{'class':'BOUNDED_PROCESS_TREE','maxTasks':128})]:
 for variant in ['original','drift']:
  folder=O/(ident+'-'+variant);repo=folder/'target';repo.mkdir(parents=True,exist_ok=False)
  git(repo,'init','-q','--initial-branch=main')
  validator={'kind':'TARGET_COMMAND','argv':['node','policy/gate.mjs'],'inputManifest':['policy/gate.mjs']}
  if requirement:validator['executionRequirement']=requirement
  check={'checkId':'independent-gate','phase':'CANDIDATE_VALIDATION','effect':'BLOCKING','validator':validator,'inputs':[],'outputSchemaId':'check-result@1','timeoutSeconds':15,'network':'NONE','filesystem':'READ_ONLY','envAllowlist':[],'resultConsumer':'DISPOSITION_REDUCER'}
  pack={'schemaVersion':f'policy-pack@{version}','packId':'independent-gate-pack','version':'1.0.0','description':'Frozen marker activation authority','phases':['CANDIDATE_VALIDATION'],'dependencies':[],'checks':[check]};pb=data(pack)
  profile={'schemaVersion':f'policy-profile@{version}','profileId':'independent-profile','version':'1.0.0','description':'Frozen activation authority','authorization':{'mode':'UNSIGNED_PERSONAL','trustedAuthorizers':[]},'packs':[{'packId':pack['packId'],'version':'1.0.0','path':'policy/pack.json','digest':sha(pb)}],'strengthen':[]}
  if requirement:profile['executionPolicy']=requirement
  prb=data(profile)
  script='import { existsSync } from "node:fs";\nimport { join } from "node:path";\nprocess.exit(existsSync(join(process.env.KERNEL_CANDIDATE_DIR,"src/gate.marker")) ? 1 : 0);\n'
  if variant=='drift':script+='// different validator byte identity, same decisions\n'
  put(repo,'policy/gate.mjs',script);put(repo,'policy/pack.json',pb);put(repo,'policy/profile.json',prb);put(repo,'src/value.mjs','export const value = 0;\n')
  git(repo,'add','-A');git(repo,'commit','-qm','frozen authority');base=git(repo,'rev-parse','HEAD')
  for candidateKind in ['conforming','planted']:
   put(repo,'src/value.mjs','export const value = 1;\n')
   if candidateKind=='planted':put(repo,'src/gate.marker','synthetic planted failure\n')
   git(repo,'add','-A');git(repo,'commit','-qm',candidateKind);candidate=git(repo,'rev-parse','HEAD')
   cmd={'commandId':'independent-value','phase':'CANDIDATE_VALIDATION','argv':['node','--input-type=module','-e','import assert from "node:assert/strict"; import {value} from "./src/value.mjs"; assert.equal(value,1);']}
   ceilings={'maxOutputBytes':65536,'maxArtifactBytes':2097152}
   if requirement:cmd['executionRequirement']=requirement;ceilings['executionCeiling']=requirement
   else:ceilings['maxProcesses']=1
   contract={'schemaVersion':f'work-contract@{version}','target':{'repositoryId':'independent-activation-target','baseCommit':base,'candidate':{'kind':'COMMIT','id':candidate}},'objectiveId':'valid-value-with-no-marker','acceptanceCriterionIds':['value-one','no-gate-marker'],'scope':{'allowed':['src/'],'readonly':[],'forbidden':['policy/']},'validationCommands':[cmd],'policyProfile':{'profileId':profile['profileId'],'path':'policy/profile.json','digest':sha(prb)},'capabilityIndex':None,'priorArtQuery':None,'mechanismRegistry':None,'artifactRoot':'artifacts/','maxRuntimeSeconds':60,'resourceCeilings':ceilings,'authorization':{'identity':'independent-experimenter','issuedAt':'2026-09-08T21:25:00Z','signature':None}}
   raw=data(contract);fn=candidateKind+'-contract.json';(folder/fn).write_bytes(raw)
   expected='PROMOTABLE' if candidateKind=='conforming' else 'BLOCKED'
   cases.append({'caseId':ident+'-'+variant+'-'+candidateKind,'group':ident,'variant':variant,'role':candidateKind,'contract':str((folder/fn).relative_to(O)),'contractDigest':sha(raw),'targetBundle':str((folder/'target.bundle').relative_to(O)),'baseCommit':base,'candidateCommit':candidate,'candidateTree':git(repo,'rev-parse','HEAD^{tree}'),'expectedByPlatform':{'darwin':'BLOCKED' if ident=='v2-bounded' else expected,'linux':expected},'confidence':0.98,'reasoning':'The frozen base-owned gate blocks exactly marker-bearing candidates. Bounded execution on macOS must fail closed because Linux OCI is required.'})
  git(repo,'bundle','create',str(folder/'target.bundle'),'HEAD');git(repo,'remote')
(O/'cases.json').write_bytes(data(cases))
(O/'astra-decisions.json').write_bytes(data({'frozenAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'model':'gpt-6-astra','reasoning':'xhigh','blinded':False,'decisions':[{k:c[k] for k in ['caseId','expectedByPlatform','confidence','reasoning']} for c in cases],'pairExpectations':{'genuine':'ACCEPT','wrong-fingerprint':'REJECT','required-signature-absent':'REJECT','not-planted':'REJECT','version-substitution':'REJECT','validator-substitution':'REJECT'},'sourceKnowledge':'Author has read activation consumer source and prior experiment; not an independent or blinded model arm.'}))
files={str(p.relative_to(R)):sha(p.read_bytes()) for p in sorted(O.rglob('*')) if p.is_file() and 'target' not in p.relative_to(O).parts}
files['PREREGISTRATION.md']=sha((R/'PREREGISTRATION.md').read_bytes());files['harness/freeze.py']=sha(pathlib.Path(__file__).read_bytes())
(R/'INPUT-MANIFEST.json').write_bytes(data({'frozenAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':files,'cases':len(cases),'repetitions':3,'subjectCommit':'1208c12aef95e03a6b3d6de8c287166b04cac626','subjectTree':'f36f08d193ce50e99ff219822e841225172e675e'}))
for n in files:(R/n).chmod((R/n).stat().st_mode & 0o555)
print(json.dumps({'cases':len(cases),'manifestDigest':sha((R/'INPUT-MANIFEST.json').read_bytes())}))
