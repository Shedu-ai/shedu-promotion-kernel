# Contract — canonical-json@1

**Status:** FROZEN. Any change to these rules is a new contract version; the
conformance vectors in [`conformance/canonical-json-v1.json`](../conformance/canonical-json-v1.json)
must reproduce byte-for-byte on every implementation and every release.

`canonical-json@1` defines the exact byte representation the kernel hashes.
Two implementations conform when, for every accepted value, they produce
identical canonical bytes and therefore identical `sha256:` digests.

## Accepted values

- `null`, `true`, `false`.
- Integers in `[-(2^53 - 1), 2^53 - 1]` only. Fractions, exponents, `-0`, and
  out-of-range integers are rejected (`NON_CANONICAL_NUMBER`).
- Strings of well-formed Unicode. Lone surrogates are rejected whether they
  arrive as raw code units or as `\uXXXX` escapes (`MALFORMED_JSON`).
- Arrays and string-keyed objects of accepted values.

## Input decoding and parsing

- Byte input is decoded as UTF-8 with **fatal** error handling: any malformed
  sequence (including truncated and overlong forms) is rejected. Replacement
  decoding is forbidden — the parsed value must be derivable from exactly the
  bytes whose digest was verified.
- Duplicate object keys are rejected (`DUPLICATE_JSON_KEY`).
- Bounds (rejected with `DOCUMENT_BOUNDS_EXCEEDED`): document ≤ 1,048,576
  bytes, nesting depth ≤ 32, string ≤ 65,536 UTF-16 code units, array ≤ 4,096
  items, object ≤ 1,024 keys.

## Canonical serialization

- No whitespace anywhere.
- Object keys sorted by **UTF-16 code unit** order (JavaScript's default
  string comparison), not by Unicode code point. The
  `utf16-code-unit-key-order` vector pins the difference: a key beginning with
  a surrogate pair (units from `0xD800`) sorts before `U+FF21` even though its
  code point is larger.
- Integers serialized in base 10 with no leading zeros; `0` for zero.
- Strings serialized with ECMAScript `JSON.stringify` escaping: `"` and `\`
  are backslash-escaped; U+0008, U+0009, U+000A, U+000C, U+000D use `\b`,
  `\t`, `\n`, `\f`, `\r`; all other code points below U+0020 use lowercase
  four-digit `\u00xx`; every other character — including non-ASCII, U+2028,
  and U+2029 — is emitted as raw UTF-8.
- The canonical bytes are the UTF-8 encoding of that text.
- Digests are `sha256:` plus lowercase hex SHA-256 over the canonical bytes.

## Round-trip law

For every accepted value `v`: `parse(canonical(v))` succeeds and
`canonical(parse(canonical(v))) === canonical(v)` byte-for-byte.

## Conformance vectors

`conformance/canonical-json-v1.json` carries named `{value, canonical,
digest}` triples covering key sorting, empty structures, escape handling,
UTF-16-vs-code-point key ordering, safe-integer extremes, and a nested mixed
document. A port to another language conforms when all vectors reproduce and
all rejection rules above hold.
