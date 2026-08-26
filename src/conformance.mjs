import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { validateValue } from "./contracts.mjs";
import { KERNEL_RELEASE } from "./compiler.mjs";
import { evaluateCandidate } from "./evaluate.mjs";
import { verifyReceipt } from "./receipt.mjs";

// Zero-provider conformance matrix (AC-13/AC-14). Three synthetic target
// repositories are built deterministically (fixed git identity and dates, so
// commit ids, plan digests, and evaluation digests reproduce byte-for-byte),
// each evaluated twice: a conforming candidate that must be PROMOTABLE and a
// planted-failure candidate that must be BLOCKED. Every receipt is verified
// offline against its plan and evidence. No promotion credential, signing
// key, network access, or model provider is involved.

const GIT_ENV = Object.freeze({
  GIT_AUTHOR_NAME: "kernel-conformance",
  GIT_AUTHOR_EMAIL: "conformance@invalid",
  GIT_AUTHOR_DATE: "2026-01-01T00:00:00Z",
  GIT_COMMITTER_NAME: "kernel-conformance",
  GIT_COMMITTER_EMAIL: "conformance@invalid",
  GIT_COMMITTER_DATE: "2026-01-01T00:00:00Z",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null"
});

function git(args, cwd) {
  const r = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    windowsHide: true,
    env: { PATH: process.env.PATH, ...GIT_ENV }
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout.trim();
}

function writeFile(repoDir, path, content) {
  const target = join(repoDir, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

function commitAll(repoDir, message) {
  git(["add", "-A"], repoDir);
  git(["commit", "-q", "--allow-empty", "-m", message], repoDir);
  return git(["rev-parse", "HEAD"], repoDir);
}

function kernelPackDocument(packId) {
  return JSON.parse(readFileSync(new URL(`../packs/${packId}.json`, import.meta.url), "utf8"));
}

const ADVISORY_PACK = {
  schemaVersion: "policy-pack@1",
  packId: "team-pack",
  version: "1.0.0",
  description: "advisory team gate",
  phases: ["CANDIDATE_VALIDATION"],
  dependencies: [],
  checks: [
    {
      checkId: "team-check",
      phase: "CANDIDATE_VALIDATION",
      effect: "ADVISORY",
      validator: { kind: "TARGET_COMMAND", argv: ["node", "-e", "process.exit(0)"] },
      inputs: [],
      outputSchemaId: "check-result@1",
      timeoutSeconds: 60,
      network: "NONE",
      filesystem: "READ_ONLY",
      envAllowlist: [],
      resultConsumer: "DISPOSITION_REDUCER"
    }
  ]
};

const targetCommandCheck = (checkId, argv) => ({
  checkId,
  phase: "CANDIDATE_VALIDATION",
  effect: "BLOCKING",
  validator: { kind: "TARGET_COMMAND", argv },
  inputs: [],
  outputSchemaId: "check-result@1",
  timeoutSeconds: 120,
  network: "NONE",
  filesystem: "READ_ONLY",
  envAllowlist: [],
  resultConsumer: "DISPOSITION_REDUCER"
});

const ARCH_TOOL = [
  "const { readdirSync, readFileSync, statSync } = require(\"node:fs\");",
  "const { join } = require(\"node:path\");",
  "const root = join(process.env.KERNEL_CANDIDATE_DIR, \"src\");",
  "const offenders = [];",
  "function walk(dir) {",
  "  for (const name of readdirSync(dir)) {",
  "    const full = join(dir, name);",
  "    if (statSync(full).isDirectory()) walk(full);",
  "    else if (readFileSync(full, \"utf8\").includes(\"internal/\")) offenders.push(name);",
  "  }",
  "}",
  "walk(root);",
  "console.log(JSON.stringify({ offenders }));",
  "process.exit(offenders.length === 0 ? 0 : 1);",
  ""
].join("\n");

const TEST_TOOL = [
  "const { pathToFileURL } = require(\"node:url\");",
  "const { join } = require(\"node:path\");",
  "import(pathToFileURL(join(process.env.KERNEL_CANDIDATE_DIR, \"src\", \"app.mjs\")).href).then((m) => {",
  "  const passed = typeof m.app === \"number\";",
  "  console.log(JSON.stringify({ passed }));",
  "  process.exit(passed ? 0 : 1);",
  "});",
  ""
].join("\n");

// Builds one synthetic target repository and its work contract factory.
function buildSyntheticTarget({ targetPacks, extraBaseFiles = {}, capabilityIndex = null, priorArtQuery = null, mechanismRegistry = null, scope }) {
  const repoDir = mkdtempSync(join(tmpdir(), "shedu-conformance-repo-"));
  git(["init", "-q"], repoDir);
  writeFile(repoDir, "src/app.mjs", "export const app = 1;\n");
  writeFile(repoDir, "docs/readme.md", "readme\n");
  for (const [path, content] of Object.entries(extraBaseFiles)) writeFile(repoDir, path, content);

  const packSelections = targetPacks.map((value) => {
    const bytes = `${JSON.stringify(value)}\n`;
    const path = `policy/${value.packId}.json`;
    writeFile(repoDir, path, bytes);
    return { packId: value.packId, version: value.version, path, digest: digestOfBytes(Buffer.from(bytes, "utf8")) };
  });
  const authorityRef = (doc, path) => {
    if (doc === null) return null;
    const bytes = `${JSON.stringify(doc)}\n`;
    writeFile(repoDir, path, bytes);
    return { path, digest: digestOfBytes(Buffer.from(bytes, "utf8")) };
  };
  const capabilityIndexRef = authorityRef(capabilityIndex, "policy/capability-index.json");
  const priorArtQueryRef = authorityRef(priorArtQuery, "policy/prior-art-query.json");
  const mechanismRegistryRef = authorityRef(mechanismRegistry, "policy/mechanism-registry.json");

  const profile = {
    schemaVersion: "policy-profile@1",
    profileId: "conformance-profile",
    version: "1.0.0",
    description: "conformance profile",
    packs: packSelections,
    strengthen: []
  };
  const profileBytes = `${JSON.stringify(profile)}\n`;
  writeFile(repoDir, "policy/profile.json", profileBytes);
  const baseCommit = commitAll(repoDir, "conformance base");

  const contractFor = (candidateId) => ({
    schemaVersion: "work-contract@1",
    target: { repositoryId: "conformance-repo", baseCommit, candidate: { kind: "COMMIT", id: candidateId } },
    objectiveId: "conformance-objective",
    acceptanceCriterionIds: ["ac-13"],
    scope,
    validationCommands: [
      { commandId: "noop-check", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.exit(0)"] }
    ],
    policyProfile: {
      profileId: "conformance-profile",
      path: "policy/profile.json",
      digest: digestOfBytes(Buffer.from(profileBytes, "utf8"))
    },
    capabilityIndex: capabilityIndexRef,
    priorArtQuery: priorArtQueryRef,
    mechanismRegistry: mechanismRegistryRef,
    artifactRoot: "artifacts/",
    maxRuntimeSeconds: 600,
    resourceCeilings: { maxOutputBytes: 1048576, maxArtifactBytes: 1048576, maxProcesses: 16 },
    authorization: { identity: "conformance-authorizer", issuedAt: "2026-08-26T00:00:00Z", signature: null }
  });

  return { repoDir, baseCommit, contractFor };
}

const SCOPE = { allowed: ["src/"], readonly: ["docs/"], forbidden: ["policy/"] };

const CASES = [
  {
    caseId: "minimal-personal",
    build: () => buildSyntheticTarget({ targetPacks: [ADVISORY_PACK], scope: SCOPE }),
    conforming: (repoDir) => {
      writeFile(repoDir, "src/feature.mjs", "export const feature = 2;\n");
      return commitAll(repoDir, "conforming feature");
    },
    planted: (repoDir) => {
      writeFile(repoDir, "policy/profile.json", "{\"weakened\":true}\n");
      return commitAll(repoDir, "planted: forbidden policy rewrite");
    }
  },
  {
    caseId: "standard-team",
    build: () =>
      buildSyntheticTarget({
        targetPacks: [ADVISORY_PACK, kernelPackDocument("prior-art-admission"), kernelPackDocument("orphan-closure")],
        scope: SCOPE,
        extraBaseFiles: { "src/payments/engine.mjs": "export const engine = 1;\n" },
        capabilityIndex: {
          schemaVersion: "capability-index@1",
          repositoryId: "conformance-repo",
          entries: [
            {
              capabilityId: "payment-engine@1",
              owner: "platform-team",
              title: "Payment engine",
              status: "ACTIVE",
              canonicalFiles: ["src/payments/engine.mjs"],
              doNotRebuild: true,
              allowedFollowUps: ["extend-refund-path"],
              receiptRefs: ["receipt-2026-06-01"]
            }
          ],
          generatedSurface: []
        },
        priorArtQuery: {
          schemaVersion: "prior-art-query@1",
          objectiveId: "conformance-objective",
          queries: [{ queryId: "payments", terms: ["payment"] }],
          declaredCollisions: []
        },
        mechanismRegistry: { schemaVersion: "mechanism-registry@1", mechanisms: [] }
      }),
    conforming: (repoDir) => {
      writeFile(repoDir, "src/feature.mjs", "export const feature = 2;\n");
      return commitAll(repoDir, "conforming feature");
    },
    planted: (repoDir) => {
      writeFile(repoDir, "src/payments/engine.mjs", "export const engine = 2;\n");
      return commitAll(repoDir, "planted: unacknowledged prior-art collision");
    }
  },
  {
    caseId: "strict-target",
    build: () =>
      buildSyntheticTarget({
        targetPacks: [
          {
            schemaVersion: "policy-pack@1",
            packId: "architecture-boundaries",
            version: "1.0.0",
            description: "target architecture validators from trusted base",
            phases: ["CANDIDATE_VALIDATION"],
            dependencies: [],
            checks: [targetCommandCheck("architecture-check", ["node", "tools/check-architecture.cjs"])]
          },
          {
            schemaVersion: "policy-pack@1",
            packId: "target-test-suite",
            version: "1.0.0",
            description: "target test suite through exact argv and machine reports",
            phases: ["CANDIDATE_VALIDATION"],
            dependencies: [],
            checks: [targetCommandCheck("target-tests", ["node", "tools/run-tests.cjs"])]
          }
        ],
        scope: SCOPE,
        extraBaseFiles: {
          "tools/check-architecture.cjs": ARCH_TOOL,
          "tools/run-tests.cjs": TEST_TOOL
        }
      }),
    conforming: (repoDir) => {
      writeFile(repoDir, "src/feature.mjs", "export const feature = 2;\n");
      return commitAll(repoDir, "conforming feature");
    },
    planted: (repoDir) => {
      writeFile(repoDir, "src/feature.mjs", "import { x } from 'internal/secret.mjs';\n");
      return commitAll(repoDir, "planted: architecture violation");
    }
  }
];

function runCase(definition, outDir) {
  const summaries = {};
  for (const kind of ["conforming", "planted"]) {
    // Each run gets its own freshly built target so the two candidates are
    // independent immutable commits over an identical base.
    const target = definition.build();
    const candidate = definition[kind](target.repoDir);
    const runOut = join(outDir, definition.caseId, kind);
    const outcome = evaluateCandidate({
      repoDir: target.repoDir,
      contractBytes: Buffer.from(`${JSON.stringify(target.contractFor(candidate))}\n`, "utf8"),
      outDir: runOut
    });
    if (!outcome.ok) {
      throw new Error(`conformance case ${definition.caseId}/${kind} failed to evaluate: ${JSON.stringify(outcome.errors)}`);
    }
    const verification = verifyReceipt({
      receiptBytes: readFileSync(join(runOut, "receipt.json")),
      planBytes: readFileSync(join(runOut, "plan.json")),
      evidenceDir: join(runOut, "evidence")
    });
    summaries[kind] = {
      disposition: outcome.receipt.disposition,
      planDigest: outcome.planDigest,
      evaluationDigest: outcome.evaluationDigest,
      receiptVerified: verification.ok
    };
  }
  return { caseId: definition.caseId, conforming: summaries.conforming, planted: summaries.planted };
}

export function runConformance({ outDir }) {
  mkdirSync(outDir, { recursive: true });
  const cases = CASES.map((definition) => runCase(definition, outDir));
  const allPassed = cases.every(
    (c) =>
      c.conforming.disposition === "PROMOTABLE" &&
      c.conforming.receiptVerified &&
      c.planted.disposition === "BLOCKED" &&
      c.planted.receiptVerified
  );
  const status = {
    schemaVersion: "conformance-status@1",
    kernelRelease: KERNEL_RELEASE,
    allPassed,
    cases
  };
  const validated = validateValue("conformance-status@1", status);
  if (!validated.ok) throw new Error(`invalid conformance status: ${JSON.stringify(validated.errors)}`);
  const statusBytes = Buffer.from(canonicalize(status), "utf8");
  writeFileSync(join(outDir, "conformance-status.json"), statusBytes);
  return { status, statusBytes };
}
