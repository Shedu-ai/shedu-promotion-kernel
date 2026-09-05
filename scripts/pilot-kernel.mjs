#!/usr/bin/env node

import process from "node:process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DistributionError, runExperimental } from "./experimental-kernel.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);

export function runPilot(argv = process.argv.slice(2), options = {}) {
  return runExperimental(argv, {
    activationRoot: fileURLToPath(new URL("../activation/pilot-v1", import.meta.url)),
    ...options
  });
}

function isDirect(argv1 = process.argv[1]) {
  try {
    return typeof argv1 === "string" && realpathSync(argv1) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
}

if (isDirect()) {
  try {
    process.exitCode = runPilot();
  } catch (cause) {
    const reasonCode = cause instanceof DistributionError ? cause.reasonCode : "INFRASTRUCTURE_FAILURE";
    process.stderr.write(`${JSON.stringify({
      schemaVersion: "promotion-kernel-distribution-error@1",
      status: "BLOCKED",
      reasonCode,
      message: cause instanceof Error ? cause.message : String(cause)
    })}\n`);
    process.exitCode = 2;
  }
}
