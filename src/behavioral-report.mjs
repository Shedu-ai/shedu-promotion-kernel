// Exit zero alone, including an early process.exit(0), cannot satisfy a
// declared behavioral check. Completion does not prove oracle quality.
export function behavioralReportComplete(bytes, criterionIds, expectedCases) {
  try {
    const report = JSON.parse(bytes.toString("utf8"));
    const keys = (value, expected) => value && typeof value === "object" && !Array.isArray(value) &&
      Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
    if (!keys(report, ["schemaVersion", "status", "scenarios", "results"]) ||
      report.schemaVersion !== "behavioral-report@2" || report.status !== "PASS" ||
      !Array.isArray(report.results) || report.results.length === 0 || report.results.length > 4096 ||
      report.scenarios !== report.results.length || criterionIds.length === 0 ||
      !Array.isArray(expectedCases) || expectedCases.length !== report.results.length) return false;
    const expected = new Map(expectedCases.map((row) => [row.id, row.criterionIds]));
    if (expected.size !== expectedCases.length) return false;
    const ids = new Set(), covered = new Set();
    for (const row of report.results) {
      if (!keys(row, ["id", "criterionIds", "outcome", "failures"]) || typeof row.id !== "string" || !row.id || ids.has(row.id) ||
        row.outcome !== "PASS" || !Array.isArray(row.failures) || row.failures.length !== 0 ||
        !Array.isArray(row.criterionIds) || row.criterionIds.length === 0 || new Set(row.criterionIds).size !== row.criterionIds.length ||
        row.criterionIds.some((id) => !criterionIds.includes(id)) || !expected.has(row.id) ||
        JSON.stringify(row.criterionIds) !== JSON.stringify(expected.get(row.id))) return false;
      ids.add(row.id);
      row.criterionIds.forEach((id) => covered.add(id));
    }
    return criterionIds.every((id) => covered.has(id));
  } catch { return false; }
}
