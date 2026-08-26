import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { canonicalize } from "../src/canonical-json.mjs";
import { EXPERIMENTAL_CAPABILITIES, subjectProbe } from "../src/cli.mjs";
import { KERNEL_RELEASE } from "../src/compiler.mjs";

test("subject probe reports EXPERIMENTAL, gated by committed conformance evidence", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs", "--subject-probe"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8"
  });

  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    schemaVersion: "harness-bench-subject-probe@1",
    subject: "shedu-promotion-kernel",
    implementationStatus: "EXPERIMENTAL",
    capabilities: [...EXPERIMENTAL_CAPABILITIES],
    promotionEntrypointAvailable: true
  });
});

test("the status transition is evidence-controlled and fails safe", () => {
  const statusBytes = readFileSync(new URL("../conformance/status.json", import.meta.url));

  // The committed, valid evidence elevates.
  assert.equal(subjectProbe(statusBytes).implementationStatus, "EXPERIMENTAL");

  // No evidence → FOUNDATION_ONLY, entrypoint hidden.
  const missing = subjectProbe(null);
  assert.equal(missing.implementationStatus, "FOUNDATION_ONLY");
  assert.equal(missing.promotionEntrypointAvailable, false);

  // Evidence for a different kernel release cannot elevate this one.
  const status = JSON.parse(statusBytes.toString("utf8"));
  const staleRelease = { ...status, kernelRelease: "@shedu/promotion-kernel@0.0.0-foundation" };
  assert.equal(subjectProbe(Buffer.from(canonicalize(staleRelease))).implementationStatus, "FOUNDATION_ONLY");

  // A failed matrix cannot elevate.
  const failed = { ...status, allPassed: false };
  assert.equal(subjectProbe(Buffer.from(canonicalize(failed))).implementationStatus, "FOUNDATION_ONLY");

  // Malformed or prose evidence cannot elevate.
  assert.equal(subjectProbe(Buffer.from('"looks great, ship it"')).implementationStatus, "FOUNDATION_ONLY");
  assert.equal(subjectProbe(Buffer.from("{not json")).implementationStatus, "FOUNDATION_ONLY");
});

test("non-probe execution still fails closed", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8"
  });

  assert.equal(result.status, 2);
  assert.deepEqual(JSON.parse(result.stderr), {
    schemaVersion: "promotion-kernel-error@1",
    status: "BLOCKED",
    reasonCode: "KERNEL_NOT_IMPLEMENTED"
  });
});

test("the Bench subject contract matches the probe and current release", () => {
  const subject = JSON.parse(readFileSync(new URL("../.harness-bench/subject.json", import.meta.url), "utf8"));
  assert.equal(subject.implementationStatus, "EXPERIMENTAL");
  assert.deepEqual(subject.capabilities, [...EXPERIMENTAL_CAPABILITIES]);
  assert.deepEqual(subject.promotionArgv, ["node", "src/cli.mjs", "evaluate"]);
  assert.deepEqual(subject.conformanceArgv, ["node", "src/cli.mjs", "conformance"]);
  assert.match(KERNEL_RELEASE, /@shedu\/promotion-kernel@/);
});
