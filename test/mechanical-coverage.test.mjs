import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { compilePlan } from "../src/compiler.mjs";
import { evaluateCandidate } from "../src/evaluate.mjs";
import { signReceipt, generateSigningKeyPem, verifyReceipt } from "../src/receipt.mjs";
import { behavioralReportComplete } from "../src/behavioral-report.mjs";
import { decodeValue, runCases, validateCases } from "../policy-tools/behavioral-check.mjs";
import { makeCheck, makePack, makeProfile, makeContract, pinPacks, profileEntries, buildTargetRepo, writeRepoFile, commitAll, contractBytesOf } from "./fixtures.mjs";

function coverage(overrides = {}, criteria = ["ac-1", "ac-2"]) {
  const check = makeCheck({ checkId: "behavior", inputs: ["acceptance-criterion.ac-1", "acceptance-criterion.ac-2"],
    validator: { kind: "TARGET_COMMAND", argv: ["node", "policy/check.mjs"], inputManifest: ["policy/check.mjs"] }, ...overrides });
  const packs = pinPacks([makePack({ checks: [check] })]);
  return compilePlan({ workContract: makeContract({ acceptanceCriterionIds: criteria }), profile: makeProfile(profileEntries(packs)), profileDigest: "sha256:" + "0".repeat(64), packs });
}

test("criterion bindings require complete executable blocking coverage", () => {
  assert.equal(coverage().ok, true);
  for (const overrides of [
    { inputs: ["acceptance-criterion.ac-1"] },
    { inputs: ["acceptance-criterion.ac-3"] },
    { effect: "ADVISORY" },
    { resultConsumer: "EVIDENCE_ONLY" },
    { phase: "CONTRACT_ADMISSION" },
    { validator: { kind: "TARGET_COMMAND", argv: ["node", "-e", ""], inputManifest: [] } }
  ]) assert.equal(coverage(overrides).ok, false, JSON.stringify(overrides));
  assert.equal(coverage({ inputs: [] }).ok, true, "legacy policies do not opt into coverage");
  assert.equal(coverage({ validator: { kind: "BUILTIN", builtinId: "scope-boundary-classify@1" } }).ok, true, "kernel checks can bind scope criteria");
});

const scenario = (id, changes = {}) => ({ id, criterionIds: ["ac-1"], module: "src/check.mjs", export: "identity", args: [{ x: 1 }], expect: { returns: { x: 1 } }, preserveArgs: [0], ...changes });
const document = (cases) => ({ schemaVersion: "behavioral-cases@1", criterionIds: ["ac-1"], cases });

test("behavioral fixtures preserve exact integers and nonenumerable state", async () => {
  assert.equal(decodeValue({ $shedu: "bigint", value: "9007199254740993" }), 9007199254740993n);
  const root = mkdtempSync(join(tmpdir(), "behavioral-fixture-")); mkdirSync(join(root, "src"));
  writeFileSync(join(root, "src/check.mjs"), `export const identity=x=>x; export function bad(x){delete x.hidden;return x;} export function failure(x){x.balance--;throw Error('failed');}`);
  const good = await runCases(document([scenario("identity", { returnArgIndex: 0 })]), root);
  assert.equal(good.status, "PASS");
  const hidden = { $shedu: "object", properties: [{ name: "hidden", value: 7, enumerable: false }] };
  const ownValues = await runCases(document([
    scenario("hidden-value", { args: [hidden], expect: { ownValues: { hidden: 7 } } }),
    scenario("enumerable-value", { args: [{ hidden: 7 }], expect: { ownValues: { hidden: 7 } } })
  ]), root);
  assert.equal(ownValues.status, "PASS", "value preservation need not preserve enumerability");
  const bad = await runCases(document([scenario("preserve-hidden", { export: "bad", args: [hidden], expect: { returns: {} } })]), root);
  assert.equal(bad.status, "BLOCKED");
  assert.ok(bad.results[0].failures.includes("argument-0-mutated"));
  const atomic = await runCases(document([scenario("atomic", { export: "failure", args: [{ balance: 2 }], expect: { throws: true } })]), root);
  assert.equal(atomic.status, "BLOCKED");
  const wrongException = await runCases(document([scenario("exception-class", { export: "failure", args: [{ balance: 2 }], expect: { throws: "RangeError" }, preserveArgs: [] })]), root);
  assert.ok(wrongException.results[0].failures.includes("exception-type"));
  const alias = await runCases(document([scenario("fresh-result", { freshReturn: true })]), root);
  assert.ok(alias.results[0].failures.includes("return-aliases-input"));
  const report = Buffer.from(JSON.stringify(good));
  assert.equal(behavioralReportComplete(report, ["ac-1"], good.results), true);
  assert.equal(behavioralReportComplete(report, ["ac-1", "ac-2"], good.results), false);
  assert.equal(behavioralReportComplete(Buffer.from(""), ["ac-1"], good.results), false);
  assert.equal(behavioralReportComplete(report, ["ac-1"], [...good.results, { id: "omitted", criterionIds: ["ac-1"] }]), false);
  assert.equal(behavioralReportComplete(Buffer.from(JSON.stringify({ ...good, results: [...good.results, ...good.results], scenarios: 2 })), ["ac-1"], good.results), false);
  assert.throws(() => validateCases({ ...document([scenario("x")]), criterionIds: ["ac-1", "ac-2"] }));
  assert.throws(() => validateCases(document([scenario("x", { module: "../outside.mjs" })])));
});

const execution = { class: "SINGLE_PROCESS", maxTasks: 64 };
for (const version of [1, 2, 3]) test(`v${version} behavioral evaluation and trusted receipt CLI fail closed`, () => {
  const helper = readFileSync(new URL("../policy-tools/behavioral-check.mjs", import.meta.url), "utf8");
  const pack = makePack({ schemaVersion: version === 1 ? "policy-pack@1" : "policy-pack@2", checks: [makeCheck({
    checkId: "behavior", outputSchemaId: "behavioral-report@2", inputs: ["acceptance-criterion.ac-1"],
    validator: { kind: "BUILTIN", builtinId: "behavioral-cases-verify@1", casesPath: "policy/cases.json" }
  })] });
  const target = buildTargetRepo({ targetPacks: [pack], ...(version === 1 ? {} : { profileOverrides: { schemaVersion: "policy-profile@2", executionPolicy: execution } }), validationCommands: [{ commandId: "syntax", phase: "CANDIDATE_VALIDATION", argv: ["node", "--check", "src/check.mjs"], ...(version === 1 ? {} : { executionRequirement: execution }) }] });
  writeRepoFile(target.repoDir, "policy/behavioral-check.mjs", helper);
  writeRepoFile(target.repoDir, "policy/cases.json", JSON.stringify(document([scenario("exact")] )));
  const base = commitAll(target.repoDir, "base-owned behavioral authority");
  // fixture contract factory captures its initial base; point explicitly to
  // the newly frozen authority commit before introducing the candidate.
  writeRepoFile(target.repoDir, "src/check.mjs", "export const identity=x=>x;\n");
  const candidate = commitAll(target.repoDir, "valid identity");
  const contract = target.contractFor(candidate, { schemaVersion: `work-contract@${version}`, target: { repositoryId: "example-repo", baseCommit: base, candidate: { kind: "COMMIT", id: candidate } }, ...(version === 1 ? {} : { resourceCeilings: { maxOutputBytes: 65536, maxArtifactBytes: 2097152, executionCeiling: execution } }) });
  const out = mkdtempSync(join(tmpdir(), "coverage-eval-"));
  const result = evaluateCandidate({ repoDir: target.repoDir, contractBytes: contractBytesOf(contract), outDir: out });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.receipt.disposition, "PROMOTABLE", JSON.stringify(result.receipt.reasonCodes));
  const signed = signReceipt(result.receipt, generateSigningKeyPem());
  const args = { receiptBytes: Buffer.from(JSON.stringify(signed)), planBytes: readFileSync(join(out, "plan.json")), evidenceDir: join(out, "artifacts/evidence"), expectedPublicKey: signed.signing.publicKey, verificationPolicy: "TRUSTED_EVIDENCE" };
  assert.equal(verifyReceipt(args).verificationLevel, "TRUSTED_EVIDENCE");
  for (const change of [{ expectedPublicKey: null }, { evidenceDir: null }, { expectedPublicKey: "0".repeat(64) }, { receiptBytes: result.receiptBytes }, { verificationPolicy: "trusted-ish" }]) {
    const rejected = verifyReceipt({ ...args, ...change }); assert.equal(rejected.ok, false); assert.equal(rejected.verificationLevel, "NONE");
  }
  writeFileSync(join(out, "receipt.json"), args.receiptBytes);
  const cliArgs = ["src/cli.mjs", "verify-receipt", "--receipt", join(out, "receipt.json"), "--plan", join(out, "plan.json"), "--require", "trusted-evidence", "--public-key", signed.signing.publicKey];
  const cli = (argv) => spawnSync(process.execPath, argv, { cwd: new URL("..", import.meta.url), encoding: "utf8" });
  assert.equal(cli(cliArgs).status, 2);
  const verified = cli([...cliArgs, "--evidence", args.evidenceDir]);
  assert.equal(verified.status, 0, verified.stderr); assert.equal(JSON.parse(verified.stdout).verificationLevel, "TRUSTED_EVIDENCE");
  writeRepoFile(target.repoDir, "src/check.mjs", "process.exit(0); export const identity=x=>x;\n");
  const earlyCandidate = commitAll(target.repoDir, "early zero exit bypass");
  const earlyContract = { ...contract, target: { ...contract.target, candidate: { kind: "COMMIT", id: earlyCandidate } } };
  const early = evaluateCandidate({ repoDir: target.repoDir, contractBytes: contractBytesOf(earlyContract), outDir: mkdtempSync(join(tmpdir(), "coverage-early-exit-")) });
  assert.equal(early.receipt.disposition, "BLOCKED"); assert.ok(early.receipt.reasonCodes.includes("COMMAND_FAILED"));
});
