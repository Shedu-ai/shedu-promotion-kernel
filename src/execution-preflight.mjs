import process from "node:process";
import { validateValue } from "./contracts.mjs";
import { EXECUTION_PRESETS, executionCapabilityId } from "./execution-policy.mjs";
import { boundedSandboxStatus, sandboxStatus } from "./sandbox.mjs";

export function buildExecutionCapabilities({ platform, strictStatus, boundedStatus }) {
  const normalizedPlatform = ["darwin", "linux"].includes(platform) ? platform : "unsupported";
  const strictBackend = strictStatus.available
    ? (platform === "linux" ? "linux-oci" : platform === "darwin" ? "darwin-sandbox-exec" : null)
    : null;
  const boundedBackend = boundedStatus.available ? "linux-oci" : null;
  const document = {
    schemaVersion: "execution-capabilities@1",
    platform: normalizedPlatform,
    presets: [
      {
        name: "STRICT",
        ...EXECUTION_PRESETS.STRICT,
        capabilityId: executionCapabilityId(EXECUTION_PRESETS.STRICT.class),
        available: strictStatus.available === true,
        backend: strictBackend,
        reasonCode: strictStatus.available === true ? null : "SANDBOX_UNAVAILABLE"
      },
      {
        name: "STANDARD_TEST",
        ...EXECUTION_PRESETS.STANDARD_TEST,
        capabilityId: executionCapabilityId(EXECUTION_PRESETS.STANDARD_TEST.class),
        available: boundedStatus.available === true,
        backend: boundedBackend,
        reasonCode: boundedStatus.available === true
          ? null
          : platform === "linux" ? "SANDBOX_UNAVAILABLE" : "EXECUTION_BACKEND_REQUIRED"
      }
    ]
  };
  const validated = validateValue("execution-capabilities@1", document);
  if (!validated.ok) throw new Error(`execution preflight produced an invalid document: ${JSON.stringify(validated.errors)}`);
  return document;
}

export function executionPreflight() {
  return buildExecutionCapabilities({
    platform: process.platform,
    strictStatus: sandboxStatus(),
    boundedStatus: boundedSandboxStatus()
  });
}
