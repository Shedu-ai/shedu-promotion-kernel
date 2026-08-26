import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  CANONICAL_BOUNDS,
  CanonicalJsonError,
  canonicalize,
  digestOfCanonical,
  parseStrict,
  validateRelativePath
} from "../src/canonical-json.mjs";

const reasonOf = (fn) => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof CanonicalJsonError);
    return e.reasonCode;
  }
  return null;
};

test("duplicate object keys are rejected", () => {
  assert.equal(reasonOf(() => parseStrict('{"a":1,"a":2}')), "DUPLICATE_JSON_KEY");
  assert.equal(reasonOf(() => parseStrict('{"a":{"b":1,"b":2}}')), "DUPLICATE_JSON_KEY");
});

test("non-canonical numbers are rejected", () => {
  assert.equal(reasonOf(() => parseStrict("1.5")), "NON_CANONICAL_NUMBER");
  assert.equal(reasonOf(() => parseStrict("1e3")), "NON_CANONICAL_NUMBER");
  assert.equal(reasonOf(() => parseStrict("-0")), "NON_CANONICAL_NUMBER");
  assert.equal(reasonOf(() => parseStrict("9007199254740993")), "NON_CANONICAL_NUMBER");
  assert.equal(parseStrict("-42"), -42);
});

test("malformed JSON is rejected", () => {
  for (const bad of ["{", '{"a":}', "[1,]", '"\\x"', '"unterminated', "01", "nulll", '{"a":1} trailing']) {
    assert.equal(reasonOf(() => parseStrict(bad)), "MALFORMED_JSON", bad);
  }
});

test("bounds are enforced", () => {
  assert.equal(reasonOf(() => parseStrict("[".repeat(40) + "]".repeat(40))), "DOCUMENT_BOUNDS_EXCEEDED");
  const wideArray = `[${Array(CANONICAL_BOUNDS.maxArrayItems + 1).fill("1").join(",")}]`;
  assert.equal(reasonOf(() => parseStrict(wideArray)), "DOCUMENT_BOUNDS_EXCEEDED");
  const bigDoc = `"${"x".repeat(CANONICAL_BOUNDS.maxDocumentBytes + 10)}"`;
  assert.equal(reasonOf(() => parseStrict(bigDoc)), "DOCUMENT_BOUNDS_EXCEEDED");
});

test("canonicalization is byte-identical regardless of key order", () => {
  const a = parseStrict('{"z":1,"a":{"y":[1,2],"b":"x"}}');
  const b = parseStrict('{"a":{"b":"x","y":[1,2]},"z":1}');
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(canonicalize(a), '{"a":{"b":"x","y":[1,2]},"z":1}');
  assert.equal(digestOfCanonical(a), digestOfCanonical(b));
});

test("canonical output survives a parse round trip", () => {
  const value = { unicode: "héllo ✓ \u0000".replace("\u0000", ""), n: 42, arr: [true, false, null] };
  const bytes = canonicalize(value);
  assert.equal(canonicalize(parseStrict(bytes)), bytes);
});

test("canonicalize rejects non-integer numbers and exotic objects", () => {
  assert.equal(reasonOf(() => canonicalize({ a: 1.5 })), "NON_CANONICAL_NUMBER");
  assert.equal(reasonOf(() => canonicalize({ a: new Date(0) })), "MALFORMED_JSON");
  assert.equal(reasonOf(() => canonicalize({ a: undefined })), "MALFORMED_JSON");
});

test("invalid UTF-8 bytes are rejected, never replacement-decoded", () => {
  // 0xff can never appear in UTF-8; a replacement-decoding parser would
  // accept this as "�" and diverge from the digested bytes.
  assert.equal(reasonOf(() => parseStrict(Buffer.from([0x22, 0xff, 0x22]))), "MALFORMED_JSON");
  // Truncated multi-byte sequence.
  assert.equal(reasonOf(() => parseStrict(Buffer.from([0x22, 0xe2, 0x82, 0x22]))), "MALFORMED_JSON");
  // Overlong encoding of "/" (0xc0 0xaf).
  assert.equal(reasonOf(() => parseStrict(Buffer.from([0x22, 0xc0, 0xaf, 0x22]))), "MALFORMED_JSON");
  // Well-formed UTF-8 bytes still parse.
  assert.equal(parseStrict(Buffer.from('"héllo✓"', "utf8")), "héllo✓");
});

test("lone surrogates are rejected in parsing and canonicalization", () => {
  assert.equal(reasonOf(() => parseStrict('"\\ud800"')), "MALFORMED_JSON");
  assert.equal(reasonOf(() => parseStrict('"\\udc00tail"')), "MALFORMED_JSON");
  assert.equal(reasonOf(() => parseStrict('{"\\ud800":1}')), "MALFORMED_JSON");
  assert.equal(reasonOf(() => canonicalize({ a: "\ud800" })), "MALFORMED_JSON");
  // Object keys are held to the same accepted-value definition as values.
  assert.equal(reasonOf(() => canonicalize({ "\ud800": 1 })), "MALFORMED_JSON");
  assert.equal(reasonOf(() => canonicalize({ ["tail\udc00"]: 1 })), "MALFORMED_JSON");
  // A proper surrogate pair is fine and round-trips.
  assert.equal(parseStrict('"\\ud83d\\ude00"'), "😀");
  assert.equal(canonicalize(parseStrict(canonicalize({ emoji: "😀" }))), '{"emoji":"😀"}');
});

test("canonical-json@1 conformance vectors are frozen", () => {
  const suite = JSON.parse(
    readFileSync(new URL("../conformance/canonical-json-v1.json", import.meta.url), "utf8")
  );
  assert.equal(suite.contract, "canonical-json@1");
  assert.ok(suite.vectors.length >= 6);
  for (const vector of suite.vectors) {
    assert.equal(canonicalize(vector.value), vector.canonical, vector.name);
    assert.equal(digestOfCanonical(vector.value), vector.digest, vector.name);
    // The canonical bytes round-trip through the strict parser to the same bytes.
    assert.equal(canonicalize(parseStrict(vector.canonical)), vector.canonical, vector.name);
  }
});

test("path containment", () => {
  const okCases = ["src/index.mjs", "docs/a-b_c.md", "a/b/c"];
  for (const p of okCases) assert.equal(validateRelativePath(p).ok, true, p);
  assert.equal(validateRelativePath("src/", { allowDirPrefix: true }).ok, true);

  const badCases = [
    "/abs/path",
    "../escape",
    "a/../b",
    "a/./b",
    "a//b",
    "a\\b",
    ".git/config",
    "nested/.GIT/config",
    "-flag-like",
    "trailing/",
    "c:/windows",
    "space name",
    "",
    "x".repeat(513)
  ];
  for (const p of badCases) {
    assert.equal(validateRelativePath(p).ok, false, JSON.stringify(p));
  }
});
