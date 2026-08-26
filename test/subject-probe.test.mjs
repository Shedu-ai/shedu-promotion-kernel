import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("subject probe emits the declared machine contract", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs", "--subject-probe"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8"
  });

  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    schemaVersion: "harness-bench-subject-probe@1",
    subject: "shedu-promotion-kernel",
    implementationStatus: "FOUNDATION_ONLY",
    capabilities: [
      "exact-argv@1",
      "immutable-subject-identity@1",
      "promotion-kernel-contract@1"
    ],
    promotionEntrypointAvailable: false
  });
});

test("non-probe execution fails closed", () => {
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
