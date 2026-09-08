import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, cpSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runControlCensus } from "../src/control-census.mjs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import * as canonical from "../src/canonical-json.mjs";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { verifyReceipt } from "../src/receipt.mjs";
import { validateDocument } from "../src/contracts.mjs";
import { projectPublishedEvaluation, inspectPublishedEvidence } from "../src/agent-projection.mjs";
import { changedFilesBetween, listTree } from "../src/workspace.mjs";
import { scopeBoundaryClassify } from "../src/validators/scope-boundary.mjs";
import { buildTargetRepo, commitAll, commitPlumbed, contractBytesOf, defaultTeamPack, git, writeRepoFile } from "./fixtures.mjs";

const execution = { class: "SINGLE_PROCESS", maxTasks: 64 };
function fixture(version = 3, executionRequirement = execution) {
  const execution = executionRequirement;
  const pack = defaultTeamPack(); pack.schemaVersion = "policy-pack@2"; pack.checks[0].validator.executionRequirement = execution;
  const target = buildTargetRepo({ targetPacks: [pack], profileOverrides: { schemaVersion: "policy-profile@2", executionPolicy: execution }, validationCommands: [{ commandId: "feature-value", phase: "CANDIDATE_VALIDATION", executionRequirement: execution, argv: ["node", "--input-type=module", "-e", 'import assert from "node:assert/strict"; import {feature} from "./src/feature.mjs"; assert.equal(feature,2);'] }] });
  writeRepoFile(target.repoDir, "src/feature.mjs", "export const feature = 2;\n");
  const contractFor = candidate => target.contractFor(candidate, { schemaVersion: `work-contract@${version}`, resourceCeilings: { maxOutputBytes: 65536, maxArtifactBytes: 2097152, executionCeiling: execution } });
  const evaluate = contract => {
    const out = mkdtempSync(join(tmpdir(), "shedu-path-v3-"));
    const bytes = contractBytesOf(contract);
    const result = evaluateCandidate({ repoDir: target.repoDir, contractBytes: bytes, outDir: out });
    return { out, bytes, result };
  };
  return { target, contractFor, evaluate };
}
function verified(run, disposition) {
  assert.equal(run.result.ok, true, JSON.stringify(run.result));
  assert.equal(run.result.receipt.disposition, disposition);
  assert.equal(verifyReceipt({ receiptBytes: run.result.receiptBytes, planBytes: readFileSync(join(run.out,"plan.json")), evidenceDir: join(run.out,"artifacts/evidence") }).ok, true);
}

test("v3 accepts exact space, Unicode and punctuation filenames and offline-verifies their identities", () => {
  const f = fixture(); const paths = ['src/a valid name.mjs','src/café.mjs','src/percent%23.mjs','src/quote"name.mjs'];
  for (const path of paths) writeRepoFile(f.target.repoDir,path,"export const value = 1;\n");
  const run=f.evaluate(f.contractFor(commitAll(f.target.repoDir,"v3 repository paths"))); verified(run,"PROMOTABLE");
  assert.equal(run.result.receipt.schemaVersion,"promotion-receipt@3"); assert.equal(run.result.plan.schemaVersion,"compiled-policy-plan@3");
  for (const path of paths) assert.ok(run.result.receipt.changedFiles.some(x=>x.path===path&&x.scopeClass==="ALLOWED"));
});
test("v3 exact scope entries with spaces preserve the longest-match authority rule", () => {
  const f=fixture();writeRepoFile(f.target.repoDir,"src/restricted/approved file.mjs","export const approved = true;\n");
  const contract=f.contractFor(commitAll(f.target.repoDir,"exact authorized path"));contract.scope.readonly.push("src/restricted/");contract.scope.allowed.push("src/restricted/approved file.mjs");
  verified(f.evaluate(contract),"PROMOTABLE");
});
test("v3 still blocks read-only renames and records both exact paths", () => {
  const f=fixture();writeRepoFile(f.target.repoDir,"docs/read only.md","protected\n");commitAll(f.target.repoDir,"protected spaced base");
  const base=git(f.target.repoDir,"rev-parse","HEAD");git(f.target.repoDir,"mv","docs/read only.md","src/moved file.md");
  const contract=f.contractFor(commitAll(f.target.repoDir,"unauthorized rename"));contract.target.baseCommit=base;
  const run=f.evaluate(contract);verified(run,"BLOCKED");assert.ok(run.result.receipt.reasonCodes.includes("SCOPE_READONLY_CHANGE"));
  assert.ok(run.result.receipt.changedFiles.some(x=>x.path==="docs/read only.md"&&x.changeKind==="DELETED"));
  assert.ok(run.result.receipt.changedFiles.some(x=>x.path==="src/moved file.md"&&x.changeKind==="ADDED"));
});
test("v3 TREE candidates retain exact immutable identity with spaced filenames", () => {
  const f=fixture();writeRepoFile(f.target.repoDir,"src/tree file.mjs","export const tree = true;\n");const candidate=commitAll(f.target.repoDir,"tree path");
  const contract=f.contractFor(candidate);contract.target.candidate={kind:"TREE",id:git(f.target.repoDir,"rev-parse",`${candidate}^{tree}`)};
  const run=f.evaluate(contract);verified(run,"PROMOTABLE");assert.deepEqual(run.result.receipt.candidate,contract.target.candidate);
});
test("v3 published receipts remain consumable and reject declared-version substitution", () => {
  const f=fixture();writeRepoFile(f.target.repoDir,"src/a b.mjs","export const x = 1;\n");const run=f.evaluate(f.contractFor(commitAll(f.target.repoDir,"published spaced name")));verified(run,"PROMOTABLE");
  const pub=mkdtempSync(join(tmpdir(),"shedu-v3-published-")),version=".v-1-"+"0".repeat(32);cpSync(run.out,join(pub,version),{recursive:true});
  writeFileSync(join(pub,version,"work-contract.json"),run.bytes);symlinkSync(version,join(pub,"current"));
  assert.equal(projectPublishedEvaluation(pub).disposition,"PROMOTABLE");
  assert.equal(inspectPublishedEvidence(pub,"command-stdout-feature-value",256).verification,"VERIFIED");
  const receipt=JSON.parse(readFileSync(join(pub,version,"receipt.json")));receipt.schemaVersion="promotion-receipt@2";writeFileSync(join(pub,version,"receipt.json"),JSON.stringify(receipt));
  assert.throws(()=>projectPublishedEvaluation(pub));
});
test("repository path support retains containment and rejects malformed or ambiguous text", () => {
  const validate=canonical.validateRepositoryPath;
  for(const path of ["src/a b.mjs","src/café.mjs","src/percent%23.mjs"])assert.equal(validate(path).ok,true,path);
  for(const path of ["../escape","/absolute","src//empty","src/./dot","src/../escape","src/.git/config","src\\escape","C:/escape","src/x:y","src/tab\tname","src/new\nline","src/nul\0byte","src/\u202ename","src/\ud800name"] )assert.equal(validate(path).ok,false,JSON.stringify(path));
  assert.equal(canonical.validateRelativePath("src/a b.mjs").ok,false);
});
test("v3 leaves authority-file and output-artifact path restrictions intact", () => {
  const f=fixture();const contract=f.contractFor(commitAll(f.target.repoDir,"artifact restriction"));
  const base=validateDocument("work-contract@3",contractBytesOf(contract));assert.equal(base.ok,true,JSON.stringify(base.errors));
  for(const mutate of [x=>x.artifactRoot="artifact output/",x=>x.policyProfile.path="policy/with space.json"]){const changed=structuredClone(contract);mutate(changed);assert.equal(validateDocument("work-contract@3",contractBytesOf(changed)).ok,false);}
});
test("v2 retains its original restricted path semantics", () => {
  const f=fixture(2);writeRepoFile(f.target.repoDir,"src/a b.mjs","export const x = 1;\n");const run=f.evaluate(f.contractFor(commitAll(f.target.repoDir,"legacy filename")));
  assert.equal(run.result.ok,false);assert.equal(run.result.reasonCode,"SCHEMA_VIOLATION");
});
test("Unicode normalization aliases are detected by the scope control", () => {
  const f=fixture();git(f.target.repoDir,"config","core.precomposeUnicode","false");
  const candidate=commitPlumbed(f.target.repoDir,[{path:"src/café.mjs",content:"one\n"},{path:"src/cafe\u0301.mjs",content:"two\n"}],"normalization collision");
  const paths=listTree(f.target.repoDir,candidate).map(x=>x.path);
  assert.ok(paths.includes("src/café.mjs")&&paths.includes("src/cafe\u0301.mjs"),"the fixture must retain both distinct Git names");
  const result=scopeBoundaryClassify({repoDir:f.target.repoDir,workContract:f.contractFor(candidate)});assert.ok(result.reasonCodes.includes("SCOPE_CASE_COLLISION"));
});
test("Git filename transport rejects invalid UTF-8 rather than substituting replacement characters", () => {
  const f=fixture();const blob=git(f.target.repoDir,"rev-parse","HEAD:src/app.mjs");
  const row=Buffer.concat([Buffer.from(`100644 blob ${blob}\tbad`),Buffer.from([255,0])]);
  const result=spawnSync("git",["-C",f.target.repoDir,"mktree","-z"],{input:row,encoding:"buffer"});assert.equal(result.status,0,String(result.stderr));
  const tree=result.stdout.toString().trim();
  assert.throws(()=>listTree(f.target.repoDir,tree),/UTF-8/);
  assert.throws(()=>changedFilesBetween(f.target.repoDir,f.target.baseCommit,tree),/UTF-8/);
});


test("v3 retains bounded execution requirements and rejects missing execution authority", () => {
  const f = fixture(3, { class: "BOUNDED_PROCESS_TREE", maxTasks: 128 });
  writeRepoFile(f.target.repoDir, "src/bounded file.mjs", "export const value = 1;\n");
  const run = f.evaluate(f.contractFor(commitAll(f.target.repoDir, "bounded version 3")));
  verified(run, process.platform === "linux" ? "PROMOTABLE" : "BLOCKED");
  assert.equal(run.result.plan.validationCommands[0].execution.class, "BOUNDED_PROCESS_TREE");
  if (process.platform !== "linux") assert.ok(run.result.receipt.reasonCodes.includes("EXECUTION_BACKEND_REQUIRED"));
  else {
    const changed = structuredClone(run.result.receipt); changed.executionReports = [];
    assert.equal(verifyReceipt({ receiptBytes: Buffer.from(JSON.stringify(changed)), planBytes: readFileSync(join(run.out, "plan.json")), evidenceDir: join(run.out, "artifacts/evidence") }).ok, false);
  }
});


test("the control census accepts a genuine version 3 production trace and rejects a substituted one", () => {
  const f = fixture(); writeRepoFile(f.target.repoDir, "src/census file.mjs", "export const value = 1;\n");
  const run = f.evaluate(f.contractFor(commitAll(f.target.repoDir, "version 3 control census"))); verified(run, "PROMOTABLE");
  const registry = JSON.parse(readFileSync(new URL("../registry/control-surface.json", import.meta.url)));
  const production = { receiptBytes: run.result.receiptBytes, planBytes: readFileSync(join(run.out, "plan.json")), evidenceDir: join(run.out, "artifacts/evidence"), outcome: run.result };
  const args = { srcDir: fileURLToPath(new URL("../src", import.meta.url)), registry };
  const census = runControlCensus({ ...args, productionRuns: [production] });
  assert.equal(census.complete, true, JSON.stringify(census.findings));
  const changed = JSON.parse(production.receiptBytes); changed.schemaVersion = "promotion-receipt@2";
  const rejected = runControlCensus({ ...args, productionRuns: [{ ...production, receiptBytes: Buffer.from(JSON.stringify(changed)) }] });
  assert.equal(rejected.complete, false); assert.equal(rejected.productionObserved.length, 0);
});
