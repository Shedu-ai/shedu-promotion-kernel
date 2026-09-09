import {isAbsolute} from "node:path";
export function closed(value, required, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      required.some((key) => !Object.hasOwn(value, key)) ||
      Object.keys(value).some((key) => ![...required, ...optional].includes(key))) {
    throw new Error("invalid behavioral contract object");
  }
}

// JSON fixtures can represent BigInt, undefined and nonenumerable own values
// without rounding them or silently dropping them during serialization.
export function decodeValue(value) {
  if (Array.isArray(value)) return value.map(decodeValue);
  if (value && typeof value === "object") {
    if (Object.hasOwn(value, "$shedu")) {
      if (value.$shedu === "undefined") { closed(value, ["$shedu"]); return undefined; }
      if (value.$shedu === "bigint") {
        closed(value, ["$shedu", "value"]);
        if (typeof value.value !== "string" || !/^-?(0|[1-9][0-9]*)$/.test(value.value)) throw new Error("invalid bigint fixture");
        return BigInt(value.value);
      }
      if (value.$shedu === "object") {
        closed(value, ["$shedu", "properties"]);
        if (!Array.isArray(value.properties)) throw new Error("invalid properties");
        const object = {};
        for (const property of value.properties) {
          closed(property, ["name", "value", "enumerable"]);
          if (typeof property.name !== "string" || typeof property.enumerable !== "boolean" || Object.hasOwn(object, property.name)) throw new Error("invalid property fixture");
          Object.defineProperty(object, property.name, { value: decodeValue(property.value), enumerable: property.enumerable, writable: true, configurable: true });
        }
        return object;
      }
      throw new Error("unknown fixture value type");
    }
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, decodeValue(entry)]));
  }
  if (typeof value === "number" && !Number.isFinite(value)) throw new Error("nonfinite fixture");
  return value;
}

export function snapshot(value, seen = new Set()) {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) throw new Error("cyclic behavioral value");
  seen.add(value);
  const properties = Reflect.ownKeys(value).map((key) => {
    if (typeof key !== "string") throw new Error("symbol properties are outside this fixture format");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!Object.hasOwn(descriptor, "value")) throw new Error("accessor properties are outside this fixture format");
    return [key, descriptor.enumerable, descriptor.writable, descriptor.configurable, snapshot(descriptor.value, seen)];
  });
  seen.delete(value);
  return { array: Array.isArray(value), properties };
}

export function validateCases(document) {
  closed(document, ["schemaVersion", "criterionIds", "cases"]);
  if (document.schemaVersion !== "behavioral-cases@1" || !Array.isArray(document.criterionIds) ||
      document.criterionIds.length === 0 || new Set(document.criterionIds).size !== document.criterionIds.length ||
      document.criterionIds.some((id) => typeof id !== "string" || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(id)) ||
      !Array.isArray(document.cases) || document.cases.length === 0 || document.cases.length > 4096) throw new Error("invalid behavioral cases");
  const seen = new Set(), covered = new Set();
  for (const item of document.cases) {
    closed(item, ["id", "criterionIds", "module", "export", "args", "expect"], ["preserveArgs", "afterArgs", "returnArgIndex", "returnElementsFromArg", "freshReturn"]);
    if (typeof item.id !== "string" || !item.id || seen.has(item.id)) throw new Error("duplicate or invalid scenario id");
    seen.add(item.id);
    if (!Array.isArray(item.criterionIds) || item.criterionIds.length === 0 || new Set(item.criterionIds).size !== item.criterionIds.length ||
      item.criterionIds.some((id) => !document.criterionIds.includes(id))) throw new Error("unknown or absent criterion");
    item.criterionIds.forEach((id) => covered.add(id));
    if (typeof item.module !== "string" || !/^[A-Za-z0-9._/-]+\.mjs$/.test(item.module) ||
      isAbsolute(item.module) || item.module.split("/").some((part) => ["", ".", ".."].includes(part)) ||
      typeof item.export !== "string" || !item.export || !Array.isArray(item.args)) throw new Error("invalid invocation");
    if (Object.hasOwn(item.expect ?? {}, "returns")) closed(item.expect, ["returns"]);
    else if (Object.hasOwn(item.expect ?? {}, "ownValues")) {
      closed(item.expect, ["ownValues"]);
      if (!item.expect.ownValues || typeof item.expect.ownValues !== "object" || Array.isArray(item.expect.ownValues)) throw new Error("ownValues requires an object");
    }
    else { closed(item.expect, ["throws"]); if (![true, "Error", "TypeError", "RangeError", "SyntaxError"].includes(item.expect.throws)) throw new Error("invalid exception expectation"); }
    if (item.freshReturn !== undefined && typeof item.freshReturn !== "boolean") throw new Error("freshReturn must be Boolean");
    const validIndex = (i) => Number.isInteger(i) && i >= 0 && i < item.args.length;
    if (item.preserveArgs !== undefined && (!Array.isArray(item.preserveArgs) || item.preserveArgs.some((i) => !validIndex(i)))) throw new Error("invalid preservation index");
    if (item.afterArgs !== undefined) {
      if (!Array.isArray(item.afterArgs)) throw new Error("invalid afterArgs");
      for (const after of item.afterArgs) { closed(after, ["index", "value"]); if (!validIndex(after.index)) throw new Error("invalid afterArgs index"); }
    }
    for (const key of ["returnArgIndex", "returnElementsFromArg"]) if (item[key] !== undefined && !validIndex(item[key])) throw new Error("invalid identity index");
    // Decode all authority fixtures before any candidate code is imported.
    decodeValue(item.args);
    if (Object.hasOwn(item.expect, "returns")) decodeValue(item.expect.returns);
    if (Object.hasOwn(item.expect, "ownValues")) decodeValue(item.expect.ownValues);
    for (const after of item.afterArgs ?? []) decodeValue(after.value);
  }
  if (document.criterionIds.some((id) => !covered.has(id))) throw new Error("acceptance criterion has no scenario");
  return document;
}

