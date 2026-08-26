import { canonicalize } from "./canonical-json.mjs";

// Minimal, dependency-free evaluator for the JSON Schema subset used by the
// kernel's contract schemas: type, const, enum, pattern, min/maxLength,
// minimum/maximum, required, properties, additionalProperties:false,
// min/maxItems, uniqueItems, items, oneOf, and local #/$defs references.
// Any keyword outside this subset in a kernel schema is a schema-authoring bug.

function deepEqual(a, b) {
  try {
    return canonicalize(a) === canonicalize(b);
  } catch {
    return false;
  }
}

export function validateAgainstSchema(rootSchema, value) {
  const resolveRef = (ref) => {
    const m = /^#\/\$defs\/([A-Za-z0-9_-]+)$/.exec(ref);
    if (!m || !rootSchema.$defs || !Object.hasOwn(rootSchema.$defs, m[1])) {
      throw new Error(`unresolvable $ref ${ref}`);
    }
    return rootSchema.$defs[m[1]];
  };

  const visit = (schema, v, path, out) => {
    if (schema.$ref) {
      visit(resolveRef(schema.$ref), v, path, out);
      return;
    }
    if (schema.oneOf) {
      let passed = 0;
      for (const branch of schema.oneOf) {
        const errs = [];
        visit(branch, v, path, errs);
        if (errs.length === 0) passed += 1;
      }
      if (passed !== 1) {
        out.push({ path, message: `expected exactly one matching alternative, matched ${passed}` });
        return;
      }
    }
    if (schema.type) {
      const t = schema.type;
      const ok =
        (t === "object" && v !== null && typeof v === "object" && !Array.isArray(v)) ||
        (t === "array" && Array.isArray(v)) ||
        (t === "string" && typeof v === "string") ||
        (t === "integer" && typeof v === "number" && Number.isInteger(v)) ||
        (t === "number" && typeof v === "number") ||
        (t === "boolean" && typeof v === "boolean") ||
        (t === "null" && v === null);
      if (!ok) {
        out.push({ path, message: `expected type ${t}` });
        return;
      }
    }
    if (Object.hasOwn(schema, "const") && !deepEqual(v, schema.const)) {
      out.push({ path, message: `expected constant ${JSON.stringify(schema.const)}` });
      return;
    }
    if (schema.enum && !schema.enum.some((e) => deepEqual(v, e))) {
      out.push({ path, message: "value not in enum" });
      return;
    }
    if (typeof v === "string") {
      if (schema.pattern && !new RegExp(schema.pattern, "u").test(v)) {
        out.push({ path, message: `string does not match pattern ${schema.pattern}` });
      }
      if (schema.minLength !== undefined && v.length < schema.minLength) {
        out.push({ path, message: `string shorter than ${schema.minLength}` });
      }
      if (schema.maxLength !== undefined && v.length > schema.maxLength) {
        out.push({ path, message: `string longer than ${schema.maxLength}` });
      }
    }
    if (typeof v === "number") {
      if (schema.minimum !== undefined && v < schema.minimum) {
        out.push({ path, message: `number below minimum ${schema.minimum}` });
      }
      if (schema.maximum !== undefined && v > schema.maximum) {
        out.push({ path, message: `number above maximum ${schema.maximum}` });
      }
    }
    if (Array.isArray(v)) {
      if (schema.minItems !== undefined && v.length < schema.minItems) {
        out.push({ path, message: `array shorter than ${schema.minItems}` });
      }
      if (schema.maxItems !== undefined && v.length > schema.maxItems) {
        out.push({ path, message: `array longer than ${schema.maxItems}` });
      }
      if (schema.uniqueItems) {
        const seen = new Set();
        for (const [idx, item] of v.entries()) {
          let key;
          try {
            key = canonicalize(item);
          } catch {
            key = `#${idx}`;
          }
          if (seen.has(key)) out.push({ path, message: "array items are not unique" });
          seen.add(key);
        }
      }
      if (schema.items) {
        v.forEach((item, idx) => visit(schema.items, item, `${path}[${idx}]`, out));
      }
    }
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      const props = schema.properties ?? {};
      if (schema.required) {
        for (const k of schema.required) {
          if (!Object.hasOwn(v, k)) out.push({ path, message: `missing required key ${JSON.stringify(k)}` });
        }
      }
      if (schema.additionalProperties === false) {
        for (const k of Object.keys(v)) {
          if (!Object.hasOwn(props, k)) out.push({ path, message: `unknown key ${JSON.stringify(k)}` });
        }
      }
      for (const [k, sub] of Object.entries(props)) {
        if (Object.hasOwn(v, k)) visit(sub, v[k], `${path}.${k}`, out);
      }
    }
  };

  const errors = [];
  visit(rootSchema, value, "$", errors);
  return errors;
}
