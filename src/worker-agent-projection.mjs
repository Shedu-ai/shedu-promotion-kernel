import process from "node:process";
import { canonicalProjection, projectPublishedEvaluation } from "./agent-projection.mjs";

const [outDir] = process.argv.slice(2);
if (typeof outDir !== "string" || outDir.length === 0) {
  process.stderr.write(`${JSON.stringify({
    schemaVersion: "promotion-kernel-error@1",
    status: "BLOCKED",
    reasonCode: "CLI_USAGE"
  })}\n`);
  process.exit(2);
}

try {
  process.stdout.write(canonicalProjection(projectPublishedEvaluation(outDir)));
  process.exit(0);
} catch (error) {
  process.stderr.write(`${JSON.stringify({
    schemaVersion: "promotion-kernel-error@1",
    status: "BLOCKED",
    reasonCode: error?.reasonCode ?? "INFRASTRUCTURE_FAILURE"
  })}\n`);
  process.exit(2);
}
