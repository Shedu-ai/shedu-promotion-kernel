import { readFileSync } from "node:fs";

// The schema file is the single source of truth for the closed code set.
const schema = JSON.parse(
  readFileSync(new URL("../schemas/reason-code.schema.json", import.meta.url), "utf8")
);

export const REASON_CODES = Object.freeze([...schema.enum]);

const codeSet = new Set(REASON_CODES);

export function isReasonCode(code) {
  return codeSet.has(code);
}
