import assert from "node:assert/strict";
import { test } from "node:test";
import { validateValue } from "../src/contracts.mjs";
import { buildExecutionCapabilities } from "../src/execution-preflight.mjs";

test("agents receive preset capabilities without selecting backend flags or budgets", () => {
  const mac = buildExecutionCapabilities({
    platform: "darwin",
    strictStatus: { available: true },
    boundedStatus: { available: false }
  });
  assert.equal(validateValue("execution-capabilities@1", mac).ok, true);
  assert.deepEqual(mac.presets.map((preset) => preset.name), ["STRICT", "STANDARD_TEST"]);
  assert.equal(mac.presets[0].available, true);
  assert.equal(mac.presets[0].backend, "darwin-sandbox-exec");
  assert.equal(mac.presets[1].available, false);
  assert.equal(mac.presets[1].reasonCode, "EXECUTION_BACKEND_REQUIRED");
  assert.equal(mac.presets[1].capabilityId, "bounded-process-tree@1");
  assert.deepEqual(Object.keys(mac.presets[1]).sort(), ["available", "backend", "capabilityId", "class", "maxTasks", "name", "reasonCode"]);

  const linux = buildExecutionCapabilities({
    platform: "linux",
    strictStatus: { available: true },
    boundedStatus: { available: true }
  });
  assert.equal(linux.presets.every((preset) => preset.backend === "linux-oci" && preset.available), true);
});
