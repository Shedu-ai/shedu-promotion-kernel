#!/usr/bin/env node

import { readdirSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";

const SOURCE_EXTENSIONS = new Set([".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"]);
const EXCLUDED_DIRECTORIES = new Set([
  ".git",
  ".shedu",
  "artifacts",
  "coverage",
  "dist",
  "node_modules",
  "vendor"
]);
const MAX_FINDINGS = 256;

function extensionOf(path) {
  const dot = path.lastIndexOf(".");
  return dot === -1 ? "" : path.slice(dot);
}

function fail(message) {
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "sample-source-hygiene-report@1",
    status: "ERROR",
    message
  })}\n`);
  return 2;
}

function scan(root) {
  const findings = [];
  let filesScanned = 0;

  function visit(directory) {
    const entries = readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
    for (const entry of entries) {
      if (findings.length >= MAX_FINDINGS) return;
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRECTORIES.has(entry.name)) visit(path);
        continue;
      }
      if (!entry.isFile() || !SOURCE_EXTENSIONS.has(extensionOf(entry.name))) continue;

      filesScanned += 1;
      const lines = readFileSync(path, "utf8").split(/\r?\n/);
      for (let index = 0; index < lines.length && findings.length < MAX_FINDINGS; index += 1) {
        if (/\b(?:TODO|FIXME)\b/.test(lines[index])) {
          findings.push({ path: relative(root, path), line: index + 1 });
        }
      }
    }
  }

  visit(root);
  return { filesScanned, findings };
}

const candidate = process.env.KERNEL_CANDIDATE_DIR;
if (typeof candidate !== "string" || !isAbsolute(candidate)) {
  process.exitCode = fail("KERNEL_CANDIDATE_DIR must be an absolute path supplied by the kernel");
} else {
  try {
    const root = realpathSync(candidate);
    const report = scan(root);
    const passed = report.findings.length === 0;
    process.stdout.write(`${JSON.stringify({
      schemaVersion: "sample-source-hygiene-report@1",
      status: passed ? "PASS" : "BLOCKED",
      filesScanned: report.filesScanned,
      findings: report.findings,
      truncated: report.findings.length === MAX_FINDINGS
    })}\n`);
    process.exitCode = passed ? 0 : 1;
  } catch (error) {
    process.exitCode = fail(String(error));
  }
}
