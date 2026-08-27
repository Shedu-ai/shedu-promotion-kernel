#!/usr/bin/env node

import { readFileSync, realpathSync, statSync } from "node:fs";
import process from "node:process";
import { digestOfBytes } from "../src/canonical-json.mjs";

export function authorityDigest(path) {
  const resolved = realpathSync(path);
  const stat = statSync(resolved);
  if (!stat.isFile()) throw new Error(`${path} is not a regular file`);
  const bytes = readFileSync(resolved);
  return {
    schemaVersion: "authority-digest@1",
    path,
    byteLength: bytes.length,
    digest: digestOfBytes(bytes)
  };
}

function main(argv) {
  if (argv.length !== 1 || argv[0].startsWith("-")) {
    process.stderr.write(`${JSON.stringify({
      schemaVersion: "authority-digest-error@1",
      reasonCode: "CLI_USAGE",
      message: "usage: node scripts/digest-authority.mjs <regular-file>"
    })}\n`);
    return 2;
  }
  try {
    process.stdout.write(`${JSON.stringify(authorityDigest(argv[0]))}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      schemaVersion: "authority-digest-error@1",
      reasonCode: "AUTHORITY_OBJECT_MISSING",
      message: String(error)
    })}\n`);
    return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = main(process.argv.slice(2));
}
