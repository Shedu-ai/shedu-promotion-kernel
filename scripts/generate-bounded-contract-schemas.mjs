#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const root = new URL("../schemas/", import.meta.url);
const load = (name) => JSON.parse(readFileSync(new URL(name, root), "utf8"));
const generated = [];
const digest = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const save = (name, value) => {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  writeFileSync(new URL(name, root), bytes);
  generated.push({ path: name, digest: digest(bytes) });
};

const executionRequirement = {
  type: "object",
  additionalProperties: false,
  required: ["class", "maxTasks"],
  properties: {
    class: { enum: ["SINGLE_PROCESS", "BOUNDED_PROCESS_TREE"] },
    maxTasks: { type: "integer", minimum: 8, maximum: 512 }
  }
};

const compiledExecution = {
  type: "object",
  additionalProperties: false,
  required: ["class", "maxTasks", "capabilityId", "portableAuthorityDigest"],
  properties: {
    class: { enum: ["SINGLE_PROCESS", "BOUNDED_PROCESS_TREE"] },
    maxTasks: { type: "integer", minimum: 8, maximum: 512 },
    capabilityId: { enum: ["single-process@1", "bounded-process-tree@1"] },
    portableAuthorityDigest: { oneOf: [{ type: "null" }, { $ref: "#/$defs/digest" }] }
  }
};

function identify(schema, filename, version) {
  schema.$id = `https://raw.githubusercontent.com/Shedu-ai/shedu-promotion-kernel/main/schemas/${filename}`;
  schema.title = version;
  schema.properties.schemaVersion.const = version;
  return schema;
}

const work = identify(load("work-contract.schema.json"), "work-contract-v2.schema.json", "work-contract@2");
work.$defs.executionRequirement = executionRequirement;
work.properties.validationCommands.items.required.push("executionRequirement");
work.properties.validationCommands.items.properties.executionRequirement = { $ref: "#/$defs/executionRequirement" };
work.properties.resourceCeilings.required = ["maxOutputBytes", "maxArtifactBytes", "executionCeiling"];
delete work.properties.resourceCeilings.properties.maxProcesses;
work.properties.resourceCeilings.properties.executionCeiling = { $ref: "#/$defs/executionRequirement" };
save("work-contract-v2.schema.json", work);

const pack = identify(load("policy-pack.schema.json"), "policy-pack-v2.schema.json", "policy-pack@2");
pack.$defs.executionRequirement = executionRequirement;
const targetValidator = pack.$defs.check.properties.validator.oneOf[1];
targetValidator.required.push("executionRequirement");
targetValidator.properties.executionRequirement = { $ref: "#/$defs/executionRequirement" };
save("policy-pack-v2.schema.json", pack);

const profile = identify(load("policy-profile.schema.json"), "policy-profile-v2.schema.json", "policy-profile@2");
profile.$defs.executionRequirement = executionRequirement;
profile.required.push("executionPolicy");
profile.properties.executionPolicy = { $ref: "#/$defs/executionRequirement" };
save("policy-profile-v2.schema.json", profile);

const plan = identify(load("compiled-policy-plan.schema.json"), "compiled-policy-plan-v2.schema.json", "compiled-policy-plan@2");
plan.$defs.executionRequirement = executionRequirement;
plan.$defs.compiledExecution = compiledExecution;
plan.required.push("executionPolicy", "validationCommands");
plan.properties.executionPolicy = {
  type: "object",
  additionalProperties: false,
  required: ["contractCeiling", "profileCeiling"],
  properties: {
    contractCeiling: { $ref: "#/$defs/executionRequirement" },
    profileCeiling: { $ref: "#/$defs/executionRequirement" }
  }
};
plan.properties.validationCommands = {
  type: "array",
  minItems: 1,
  maxItems: 128,
  items: {
    type: "object",
    additionalProperties: false,
    required: ["commandId", "phase", "argv", "execution"],
    properties: {
      commandId: { $ref: "#/$defs/kebabId" },
      phase: { $ref: "#/$defs/phase" },
      argv: { $ref: "#/$defs/argv" },
      execution: { $ref: "#/$defs/compiledExecution" }
    }
  }
};
plan.$defs.planCheck.required.push("execution");
plan.$defs.planCheck.properties.execution = {
  oneOf: [{ type: "null" }, { $ref: "#/$defs/compiledExecution" }]
};
save("compiled-policy-plan-v2.schema.json", plan);

const report = identify(load("command-report.schema.json"), "command-report-v2.schema.json", "command-report@2");
report.$defs.executionReport = {
  type: "object",
  additionalProperties: false,
  required: ["class", "maxTasks", "capabilityId", "portableAuthorityDigest", "backend", "backendAuthorityDigest", "limitFired", "limitEvents"],
  properties: {
    class: { enum: ["SINGLE_PROCESS", "BOUNDED_PROCESS_TREE"] },
    maxTasks: { type: "integer", minimum: 8, maximum: 512 },
    capabilityId: { enum: ["single-process@1", "bounded-process-tree@1"] },
    portableAuthorityDigest: { oneOf: [{ type: "null" }, { $ref: "#/$defs/digest" }] },
    backend: { enum: ["darwin-sandbox-exec", "linux-oci"] },
    backendAuthorityDigest: { oneOf: [{ type: "null" }, { $ref: "#/$defs/digest" }] },
    limitFired: { type: "boolean" },
    limitEvents: { type: "integer", minimum: 0 }
  }
};
report.$defs.digest = { type: "string", pattern: "^sha256:[0-9a-f]{64}$" };
report.required.push("execution");
report.properties.execution = { $ref: "#/$defs/executionReport" };
save("command-report-v2.schema.json", report);

const receipt = identify(load("promotion-receipt.schema.json"), "promotion-receipt-v2.schema.json", "promotion-receipt@2");
receipt.$defs.executionReport = report.$defs.executionReport;
receipt.required.push("executionReports");
receipt.properties.executionReports = {
  type: "array",
  maxItems: 4096,
  items: {
    type: "object",
    additionalProperties: false,
    required: ["commandId", "report"],
    properties: {
      commandId: { $ref: "#/$defs/kebabId" },
      report: { $ref: "#/$defs/executionReport" }
    }
  }
};
save("promotion-receipt-v2.schema.json", receipt);

writeFileSync(
  new URL("bounded-contracts.provenance.json", root),
  `${JSON.stringify({
    schemaVersion: "generated-contract-provenance@1",
    generator: "../scripts/generate-bounded-contract-schemas.mjs",
    generatorDigest: digest(readFileSync(new URL(import.meta.url))),
    generated
  }, null, 2)}\n`
);
