import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { digestOfBytes } from "../src/canonical-json.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
function fixture() {
  const parent = mkdtempSync(join(tmpdir(), "shedu-utility-entry-"));
  const kernel = join(parent, "kernel space % # café");
  mkdirSync(kernel);
  for (const dir of ["src", "schemas", "registry", "packs", "security", "scripts", "examples"]) cpSync(join(root, dir), join(kernel, dir), { recursive: true });
  cpSync(join(root, "package.json"), join(kernel, "package.json"));
  return { parent, kernel };
}

test("authority digest utility dispatches through encoded paths and symlinks with exact output", () => {
  const { parent, kernel } = fixture();
  try {
    const script = join(kernel, "scripts/digest-authority.mjs");
    const alias = join(parent, "digest-link");
    symlinkSync(script, alias);
    const input = join(kernel, "package.json");
    for (const entry of [script, alias]) {
      const valid = spawnSync(process.execPath, [entry, input], { encoding: "utf8" });
      assert.equal(valid.status, 0, valid.stderr);
      assert.notEqual(valid.stdout.trim(), "", "success must emit the actual digest, not silently skip main");
      const result = JSON.parse(valid.stdout);
      assert.equal(result.digest, digestOfBytes(readFileSync(input)));
      assert.equal(result.byteLength, readFileSync(input).length);
      const invalid = spawnSync(process.execPath, [entry], { encoding: "utf8" });
      assert.equal(invalid.status, 2);
      assert.equal(JSON.parse(invalid.stderr).reasonCode, "CLI_USAGE");
    }
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test("sample-policy utility dispatches through encoded paths and emits executed verification", () => {
  const { parent, kernel } = fixture();
  try {
    const script = join(kernel, "scripts/verify-sample-policy.mjs");
    const alias = join(parent, "verify-sample-link");
    symlinkSync(script, alias);
    for (const entry of [script, alias]) {
      const result = spawnSync(process.execPath, [entry], { encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
      assert.notEqual(result.stdout.trim(), "", "success must emit real fixture results");
      const value = JSON.parse(result.stdout);
      assert.equal(value.ok, true);
      assert.deepEqual(value.validator, { passingFixture: "PASS", failingFixture: "BLOCKED" });
      assert.ok(value.compiledCheckIds.includes("node-source-hygiene"));
    }
  } finally { rmSync(parent, { recursive: true, force: true }); }
});
