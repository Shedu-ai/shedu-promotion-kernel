#!/usr/bin/env node
// Vendor this file and a cases document into the trusted base. The kernel
// executes them through TARGET_COMMAND with both in the input manifest.
import { readFileSync, realpathSync } from "node:fs";
import { resolve, relative, isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

function closed(value, required, optional = []) {
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

function snapshot(value, seen = new Set()) {
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

export async function runCases(document, candidateRoot) {
  validateCases(document);
  const root = realpathSync(candidateRoot);
  // Capture assertions and fixture state before loading untrusted modules.
  const prepared = document.cases.map((item) => ({ item, args: decodeValue(item.args), expected: decodeValue(Object.hasOwn(item.expect, "ownValues") ? item.expect.ownValues : item.expect.returns), after: (item.afterArgs ?? []).map((a) => ({ index: a.index, value: decodeValue(a.value) })) }));
  const results = [];
  const exceptionTypes = { Error, TypeError, RangeError, SyntaxError };
  const objects = (value, result = new Set()) => {
    if (value && typeof value === "object" && !result.has(value)) {
      result.add(value);
      for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
        if (!Object.hasOwn(descriptor, "value")) throw new Error("accessor returned outside fixture domain");
        objects(descriptor.value, result);
      }
    }
    return result;
  };
  for (const { item, args, expected, after } of prepared) {
    const failures = [];
    try {
      const modulePath = realpathSync(resolve(root, item.module));
      const rel = relative(root, modulePath);
      if (rel === ".." || rel.startsWith("../") || isAbsolute(rel)) throw new Error("module escapes candidate");
      const before = (item.preserveArgs ?? []).map((index) => [index, snapshot(args[index])]);
      const module = await import(pathToFileURL(modulePath).href);
      if (typeof module[item.export] !== "function") throw new Error("requested export is not a function");
      const inputObjects = objects(args);
      let returned, caught, threw = false;
      try { returned = await module[item.export](...args); } catch (error) { threw = true; caught = error; }
      if (Object.hasOwn(item.expect, "throws")) {
        if (!threw) failures.push("expected-exception");
        else if (item.expect.throws !== true && !(caught instanceof exceptionTypes[item.expect.throws])) failures.push("exception-type");
      }
      else if (Object.hasOwn(item.expect, "ownValues")) {
        const values = (object) => {
          if (!object || typeof object !== "object" || Array.isArray(object)) throw new Error("expected returned object");
          return Object.fromEntries(Reflect.ownKeys(object).map((key) => {
            const descriptor = Object.getOwnPropertyDescriptor(object, key);
            if (typeof key !== "string" || !Object.hasOwn(descriptor, "value")) throw new Error("expected own data values");
            return [key, descriptor.value];
          }));
        };
        if (threw || !isDeepStrictEqual(values(returned), values(expected))) failures.push("own-property-values");
      }
      else if (threw || !isDeepStrictEqual(returned, expected)) failures.push("return-value");
      for (const [index, original] of before) if (!isDeepStrictEqual(snapshot(args[index]), original)) failures.push(`argument-${index}-mutated`);
      for (const entry of after) if (!isDeepStrictEqual(args[entry.index], entry.value)) failures.push(`argument-${entry.index}-postcondition`);
      if (item.returnArgIndex !== undefined && returned !== args[item.returnArgIndex]) failures.push("return-identity");
      if (item.returnElementsFromArg !== undefined && (!Array.isArray(returned) || !Array.isArray(args[item.returnElementsFromArg]) || returned.some((value) => !args[item.returnElementsFromArg].includes(value)))) failures.push("element-identity");
      if (item.freshReturn === true && [...objects(returned)].some((value) => inputObjects.has(value))) failures.push("return-aliases-input");
    } catch (error) { failures.push(`scenario-error: ${String(error.message).slice(0,200)}`); }
    results.push({ id: item.id, criterionIds: item.criterionIds, outcome: failures.length ? "FAIL" : "PASS", failures });
  }
  return { schemaVersion: "behavioral-report@1", status: results.every((r) => r.outcome === "PASS") ? "PASS" : "BLOCKED", scenarios: results.length, results };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 3 || !process.env.KERNEL_CANDIDATE_DIR) throw new Error("usage: behavioral-check.mjs CASES_JSON with KERNEL_CANDIDATE_DIR set by the kernel");
    const report = await runCases(JSON.parse(readFileSync(process.argv[2], "utf8")), process.env.KERNEL_CANDIDATE_DIR);
    process.stdout.write(JSON.stringify(report) + "\n");
    process.exitCode = report.status === "PASS" ? 0 : 1;
  } catch (error) {
    process.stdout.write(JSON.stringify({ schemaVersion: "behavioral-report@1", status: "ERROR", error: String(error.message).slice(0,300) }) + "\n");
    process.exitCode = 2;
  }
}
