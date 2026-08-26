#!/usr/bin/env node

import process from "node:process";

export const SUBJECT_PROBE = Object.freeze({
  schemaVersion: "harness-bench-subject-probe@1",
  subject: "shedu-promotion-kernel",
  implementationStatus: "FOUNDATION_ONLY",
  capabilities: Object.freeze([
    "exact-argv@1",
    "immutable-subject-identity@1",
    "promotion-kernel-contract@1"
  ]),
  promotionEntrypointAvailable: false
});

export function main(argv = process.argv.slice(2)) {
  if (argv.length === 1 && argv[0] === "--subject-probe") {
    process.stdout.write(`${JSON.stringify(SUBJECT_PROBE)}\n`);
    return 0;
  }

  process.stderr.write(`${JSON.stringify({
    schemaVersion: "promotion-kernel-error@1",
    status: "BLOCKED",
    reasonCode: "KERNEL_NOT_IMPLEMENTED"
  })}\n`);
  return 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = main();
}
