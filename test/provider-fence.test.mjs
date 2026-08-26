import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

// AC-12 static fence: no production file may import a model SDK or network
// module, reference a provider credential variable, or embed a model prompt
// channel. The runtime half of AC-12 is covered by the runner environment
// tests: provider keys present in the host environment never reach a child,
// and secret-named env names cannot be allowlisted at any layer.

const SRC_ROOT = new URL("../src", import.meta.url).pathname;

const FORBIDDEN_IMPORT_RE =
  /(from\s+|require\()["'](node:)?(https?|net|tls|dgram|dns|http2)["']|["']@anthropic|["']openai["']|["']undici["']|["']node-fetch["']|["']axios["']|import\(["']/;
const FORBIDDEN_CALL_RE = /\bfetch\s*\(|new\s+WebSocket\s*\(/;
const PROVIDER_ENV_RE = /ANTHROPIC_API_KEY|OPENAI_API_KEY|GOOGLE_API_KEY|AZURE_OPENAI|AWS_BEDROCK|MISTRAL_API_KEY|COHERE_API_KEY/;

function sourceFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
    else if (name.endsWith(".mjs")) out.push(full);
  }
  return out;
}

test("no production file imports a network module or model SDK", () => {
  const files = sourceFiles(SRC_ROOT);
  assert.ok(files.length >= 15, "fence must scan the real production tree");
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    assert.ok(!FORBIDDEN_IMPORT_RE.test(content), `${file} imports a forbidden module`);
    assert.ok(!FORBIDDEN_CALL_RE.test(content), `${file} performs a network call`);
  }
});

test("no production file reads a provider credential variable", () => {
  for (const file of sourceFiles(SRC_ROOT)) {
    const content = readFileSync(file, "utf8");
    assert.ok(!PROVIDER_ENV_RE.test(content), `${file} references a provider credential`);
  }
});

test("the dependency tree is empty: no model SDK can hide in node_modules", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  assert.equal(pkg.optionalDependencies, undefined);
  assert.equal(pkg.peerDependencies, undefined);
});
