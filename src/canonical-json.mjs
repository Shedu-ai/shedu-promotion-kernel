import { createHash } from "node:crypto";

export const CANONICAL_BOUNDS = Object.freeze({
  maxDocumentBytes: 1_048_576,
  maxDepth: 32,
  maxStringChars: 65_536,
  maxArrayItems: 4_096,
  maxObjectKeys: 1_024
});

export class CanonicalJsonError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = "CanonicalJsonError";
    this.reasonCode = reasonCode;
  }
}

// Strict JSON parser. Beyond RFC 8259 it rejects duplicate object keys,
// fractional/exponent/-0/unsafe numbers, and enforces byte, depth, string,
// array, and key-count bounds so that parse(bytes) accepts exactly the
// documents canonicalize() can emit.
export function parseStrict(input, bounds = CANONICAL_BOUNDS) {
  let text;
  if (typeof input === "string") {
    text = input;
  } else {
    // Fatal decoding: replacement-decoded bytes would let the parsed value
    // diverge from the bytes whose digest was verified.
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(input);
    } catch {
      throw new CanonicalJsonError("MALFORMED_JSON", "input is not valid UTF-8");
    }
  }
  if (Buffer.byteLength(text, "utf8") > bounds.maxDocumentBytes) {
    throw new CanonicalJsonError("DOCUMENT_BOUNDS_EXCEEDED", `document exceeds ${bounds.maxDocumentBytes} bytes`);
  }
  let i = 0;

  const fail = (reasonCode, message) => {
    throw new CanonicalJsonError(reasonCode, `${message} at offset ${i}`);
  };
  const skipWs = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i += 1;
  };
  const literal = (word, value) => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    return fail("MALFORMED_JSON", "invalid literal");
  };

  const parseString = () => {
    if (text[i] !== '"') fail("MALFORMED_JSON", "expected string");
    i += 1;
    let out = "";
    for (;;) {
      if (i >= text.length) fail("MALFORMED_JSON", "unterminated string");
      const c = text[i];
      if (c === '"') {
        i += 1;
        if (!out.isWellFormed()) fail("MALFORMED_JSON", "lone surrogate in string");
        return out;
      }
      if (c === "\\") {
        const e = text[i + 1];
        i += 2;
        if (e === '"') out += '"';
        else if (e === "\\") out += "\\";
        else if (e === "/") out += "/";
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("MALFORMED_JSON", "invalid unicode escape");
          out += String.fromCharCode(Number.parseInt(hex, 16));
          i += 4;
        } else fail("MALFORMED_JSON", "invalid escape");
      } else if (c.charCodeAt(0) < 0x20) {
        fail("MALFORMED_JSON", "raw control character in string");
      } else {
        out += c;
        i += 1;
      }
      if (out.length > bounds.maxStringChars) fail("DOCUMENT_BOUNDS_EXCEEDED", "string exceeds bound");
    }
  };

  const parseNumber = () => {
    const start = i;
    if (text[i] === "-") i += 1;
    if (text[i] === "0") i += 1;
    else if (text[i] >= "1" && text[i] <= "9") {
      while (text[i] >= "0" && text[i] <= "9") i += 1;
    } else fail("MALFORMED_JSON", "invalid number");
    if (text[i] === "." || text[i] === "e" || text[i] === "E") {
      fail("NON_CANONICAL_NUMBER", "fractions and exponents are rejected");
    }
    const raw = text.slice(start, i);
    if (raw === "-0") fail("NON_CANONICAL_NUMBER", "negative zero is rejected");
    const value = Number(raw);
    if (!Number.isSafeInteger(value)) fail("NON_CANONICAL_NUMBER", "integer exceeds safe range");
    return value;
  };

  const parseValue = (depth) => {
    if (depth > bounds.maxDepth) fail("DOCUMENT_BOUNDS_EXCEEDED", "depth exceeds bound");
    skipWs();
    if (i >= text.length) fail("MALFORMED_JSON", "unexpected end of input");
    const c = text[i];
    if (c === "{") {
      i += 1;
      const obj = Object.create(null);
      const seen = new Set();
      skipWs();
      if (text[i] === "}") {
        i += 1;
        return obj;
      }
      for (;;) {
        skipWs();
        const key = parseString();
        if (seen.has(key)) fail("DUPLICATE_JSON_KEY", `duplicate key ${JSON.stringify(key)}`);
        seen.add(key);
        if (seen.size > bounds.maxObjectKeys) fail("DOCUMENT_BOUNDS_EXCEEDED", "object keys exceed bound");
        skipWs();
        if (text[i] !== ":") fail("MALFORMED_JSON", "expected colon");
        i += 1;
        obj[key] = parseValue(depth + 1);
        skipWs();
        if (text[i] === ",") {
          i += 1;
          continue;
        }
        if (text[i] === "}") {
          i += 1;
          return obj;
        }
        fail("MALFORMED_JSON", "expected comma or closing brace");
      }
    }
    if (c === "[") {
      i += 1;
      const arr = [];
      skipWs();
      if (text[i] === "]") {
        i += 1;
        return arr;
      }
      for (;;) {
        arr.push(parseValue(depth + 1));
        if (arr.length > bounds.maxArrayItems) fail("DOCUMENT_BOUNDS_EXCEEDED", "array items exceed bound");
        skipWs();
        if (text[i] === ",") {
          i += 1;
          continue;
        }
        if (text[i] === "]") {
          i += 1;
          return arr;
        }
        fail("MALFORMED_JSON", "expected comma or closing bracket");
      }
    }
    if (c === '"') return parseString();
    if (c === "t") return literal("true", true);
    if (c === "f") return literal("false", false);
    if (c === "n") return literal("null", null);
    if (c === "-" || (c >= "0" && c <= "9")) return parseNumber();
    return fail("MALFORMED_JSON", "unexpected character");
  };

  const value = parseValue(1);
  skipWs();
  if (i !== text.length) fail("MALFORMED_JSON", "trailing content");
  return value;
}

// Deterministic serialization: sorted keys (UTF-16 code unit order), no
// whitespace, safe integers only. Equal values always produce identical bytes.
export function canonicalize(value, bounds = CANONICAL_BOUNDS) {
  const serialize = (v, depth) => {
    if (depth > bounds.maxDepth) throw new CanonicalJsonError("DOCUMENT_BOUNDS_EXCEEDED", "depth exceeds bound");
    if (v === null) return "null";
    const t = typeof v;
    if (t === "boolean") return v ? "true" : "false";
    if (t === "number") {
      if (!Number.isSafeInteger(v) || Object.is(v, -0)) {
        throw new CanonicalJsonError("NON_CANONICAL_NUMBER", "only safe integers are canonical");
      }
      return String(v);
    }
    if (t === "string") {
      if (v.length > bounds.maxStringChars) throw new CanonicalJsonError("DOCUMENT_BOUNDS_EXCEEDED", "string exceeds bound");
      if (!v.isWellFormed()) throw new CanonicalJsonError("MALFORMED_JSON", "lone surrogate in string");
      return JSON.stringify(v);
    }
    if (Array.isArray(v)) {
      if (v.length > bounds.maxArrayItems) throw new CanonicalJsonError("DOCUMENT_BOUNDS_EXCEEDED", "array items exceed bound");
      return `[${v.map((x) => serialize(x, depth + 1)).join(",")}]`;
    }
    if (t === "object") {
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) {
        throw new CanonicalJsonError("MALFORMED_JSON", "unsupported object type");
      }
      const keys = Object.keys(v).sort();
      if (keys.length > bounds.maxObjectKeys) throw new CanonicalJsonError("DOCUMENT_BOUNDS_EXCEEDED", "object keys exceed bound");
      for (const k of keys) {
        if (k.length > bounds.maxStringChars) throw new CanonicalJsonError("DOCUMENT_BOUNDS_EXCEEDED", "object key exceeds string bound");
        if (!k.isWellFormed()) throw new CanonicalJsonError("MALFORMED_JSON", "lone surrogate in object key");
      }
      return `{${keys.map((k) => `${JSON.stringify(k)}:${serialize(v[k], depth + 1)}`).join(",")}}`;
    }
    throw new CanonicalJsonError("MALFORMED_JSON", `unsupported value type ${t}`);
  };
  const out = serialize(value, 1);
  if (Buffer.byteLength(out, "utf8") > bounds.maxDocumentBytes) {
    throw new CanonicalJsonError("DOCUMENT_BOUNDS_EXCEEDED", "canonical document exceeds byte bound");
  }
  return out;
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function digestOfBytes(bytes) {
  return `sha256:${sha256Hex(bytes)}`;
}

export function digestOfCanonical(value) {
  return digestOfBytes(Buffer.from(canonicalize(value), "utf8"));
}

const PATH_CHARSET = /^[A-Za-z0-9._/-]+$/;

// Containment rules for every path a contract or authority document may name.
// Charset is deliberately narrow so paths can never carry shell metacharacters,
// pathspec magic, drive letters, or option-like prefixes.
export function validateRelativePath(path, { allowDirPrefix = false } = {}) {
  const bad = (message) => ({ ok: false, reasonCode: "PATH_NOT_CONTAINED", message });
  if (typeof path !== "string" || path.length === 0) return bad("path must be a non-empty string");
  if (path.length > 512) return bad("path exceeds 512 characters");
  if (!PATH_CHARSET.test(path)) return bad("path contains characters outside [A-Za-z0-9._/-]");
  if (path.startsWith("/")) return bad("absolute paths are rejected");
  if (path.startsWith("-")) return bad("paths may not begin with a dash");
  let body = path;
  if (path.endsWith("/")) {
    if (!allowDirPrefix) return bad("trailing slash is rejected");
    body = path.slice(0, -1);
  }
  for (const segment of body.split("/")) {
    if (segment === "") return bad("empty path segment");
    if (segment === "." || segment === "..") return bad("relative traversal segments are rejected");
    if (segment.toLowerCase() === ".git") return bad(".git segments are rejected");
  }
  return { ok: true, path };
}
