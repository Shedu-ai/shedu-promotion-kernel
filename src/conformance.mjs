import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { canonicalize, digestOfBytes } from "./canonical-json.mjs";
import { validateDocument, validateValue } from "./contracts.mjs";
import { KERNEL_RELEASE } from "./compiler.mjs";
import { evaluateCandidate } from "./evaluate.mjs";
import { verifyReceipt } from "./receipt.mjs";
import { verifyActivationPair } from "./activation.mjs";

// Zero-provider conformance matrix (AC-13/AC-14) and the kernel's own
// activation proof (brief §7 items 5–6). Every synthetic target is built
// deterministically (fixed git identity and dates), each case is evaluated
// twice — conforming (must be PROMOTABLE) and planted (must be BLOCKED) —
// and every receipt is verified offline. Beyond the three AC-13 profiles,
// one planted case exists for EVERY kernel mechanism, and the status
// document records a mechanical activation-pair proof per mechanism: the
// planted receipt shows the mechanism FIRED as the sole failure that
// changed the disposition, and the conforming receipt shows it OBSERVED.
// A kernel mechanism without a proven activation case fails the matrix.

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

// A parentless commit over the same tree: a candidate that is not a
// descendant of base.
function orphanCommit(repoDir) {
  git(["read-tree", "HEAD"], repoDir);
  const tree = git(["write-tree"], repoDir);
  return git(["commit-tree", tree, "-m", "orphan candidate"], repoDir);
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

// Exits 1 when the named marker file exists in the candidate workspace.
const markerCommand = (commandId, phase, marker) => ({
  commandId,
  phase,
  argv: [
    "node",
    "-e",
    `process.exit(require("node:fs").existsSync(require("node:path").join(process.cwd(), "src", "${marker}")) ? 1 : 0)`
  ]
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

const SCOPE = { allowed: ["src/"], readonly: ["docs/"], forbidden: ["policy/"] };
const DEFAULT_COMMANDS = [
  { commandId: "noop-check", phase: "CANDIDATE_VALIDATION", argv: ["node", "-e", "process.exit(0)"] }
];

function buildSyntheticTarget({
  targetPacks,
  extraBaseFiles = {},
  capabilityIndex = null,
  priorArtQuery = null,
  mechanismRegistry = null,
  validationCommands = DEFAULT_COMMANDS,
  scope = SCOPE
}) {
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
    validationCommands,
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
    resourceCeilings: { maxOutputBytes: 1048576, maxArtifactBytes: 8388608, maxProcesses: 1 },
    authorization: { identity: "conformance-authorizer", issuedAt: "2026-08-26T00:00:00Z", signature: null }
  });

  return { repoDir, baseCommit, contractFor };
}

const featureCandidate = (repoDir) => {
  writeFile(repoDir, "src/feature.mjs", "export const feature = 2;\n");
  return commitAll(repoDir, "conforming feature");
};
const markerCandidate = (marker) => (repoDir) => {
  writeFile(repoDir, `src/${marker}`, "planted marker\n");
  return commitAll(repoDir, `planted: ${marker}`);
};

function mutateOneEvidenceObject(evidenceRootDir) {
  const objectsDir = join(evidenceRootDir, "objects", "sha256");
  const names = readdirSync(objectsDir).sort();
  if (names.length === 0) throw new Error("no evidence objects to mutate");
  writeFileSync(join(objectsDir, names[0]), "planted evidence mutation");
}

// Each case: build(kind) constructs a fresh target; conforming/planted
// produce the candidate; optional plantHooks simulate runtime attackers;
// verifyEvidence: false verifies the receipt bare where the planted fixture
// deliberately corrupts the evidence store.
const CASES = [
  {
    caseId: "minimal-personal",
    build: () => buildSyntheticTarget({ targetPacks: [ADVISORY_PACK] }),
    conforming: featureCandidate,
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
    conforming: featureCandidate,
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
        extraBaseFiles: {
          "tools/check-architecture.cjs": ARCH_TOOL,
          "tools/run-tests.cjs": TEST_TOOL
        }
      }),
    conforming: featureCandidate,
    planted: (repoDir) => {
      writeFile(repoDir, "src/feature.mjs", "import { x } from 'internal/secret.mjs';\n");
      return commitAll(repoDir, "planted: architecture violation");
    }
  },
  {
    caseId: "identity-activation",
    build: () => buildSyntheticTarget({ targetPacks: [ADVISORY_PACK] }),
    conforming: featureCandidate,
    planted: (repoDir) => orphanCommit(repoDir)
  },
  {
    caseId: "admission-activation",
    build: () =>
      buildSyntheticTarget({
        targetPacks: [ADVISORY_PACK],
        validationCommands: [...DEFAULT_COMMANDS, markerCommand("admission-gate", "CONTRACT_ADMISSION", "fail-admission.marker")]
      }),
    conforming: featureCandidate,
    planted: markerCandidate("fail-admission.marker")
  },
  {
    caseId: "validation-activation",
    build: () =>
      buildSyntheticTarget({
        targetPacks: [ADVISORY_PACK],
        validationCommands: [markerCommand("validation-gate", "CANDIDATE_VALIDATION", "fail-validation.marker")]
      }),
    conforming: featureCandidate,
    planted: markerCandidate("fail-validation.marker")
  },
  {
    caseId: "finalization-activation",
    build: () =>
      buildSyntheticTarget({
        targetPacks: [ADVISORY_PACK],
        validationCommands: [...DEFAULT_COMMANDS, markerCommand("finalization-gate", "PROMOTION_FINALIZATION", "fail-finalization.marker")]
      }),
    conforming: featureCandidate,
    planted: markerCandidate("fail-finalization.marker")
  },
  {
    caseId: "stability-activation",
    build: () => buildSyntheticTarget({ targetPacks: [ADVISORY_PACK] }),
    conforming: featureCandidate,
    planted: featureCandidate,
    plantHooks: {
      planted: {
        afterPhase: (phase, { candidateDir }) => {
          if (phase === "CANDIDATE_VALIDATION") {
            writeFileSync(join(candidateDir, "src", "feature.mjs"), "mutated after validation\n");
          }
        }
      }
    }
  },
  {
    caseId: "evidence-activation",
    build: () => buildSyntheticTarget({ targetPacks: [ADVISORY_PACK] }),
    conforming: featureCandidate,
    planted: featureCandidate,
    verifyEvidence: { planted: false },
    plantHooks: {
      planted: {
        afterPhase: (phase, { evidenceRootDir }) => {
          if (phase === "CANDIDATE_VALIDATION") mutateOneEvidenceObject(evidenceRootDir);
        }
      }
    }
  },
  {
    caseId: "orphan-activation",
    build: (kind) =>
      buildSyntheticTarget({
        targetPacks: [ADVISORY_PACK, kernelPackDocument("orphan-closure")],
        mechanismRegistry: {
          schemaVersion: "mechanism-registry@1",
          mechanisms:
            kind === "planted"
              ? [
                  {
                    mechanismId: "phantom-check",
                    validatorId: "scope-boundary-classify@1",
                    owner: "target-team",
                    producer: "nowhere",
                    runtimeConsumer: "disposition-reducer",
                    inputSchemaId: "compiled-policy-plan@1",
                    outputSchemaId: "check-result@1",
                    activationPhase: "CANDIDATE_VALIDATION",
                    effect: "BLOCKING",
                    resultConsumer: "DISPOSITION_REDUCER",
                    evidenceSink: "evidence-index",
                    activationEvidence: null,
                    negativeFixtures: [{ fixtureId: "phantom", description: "registered but never dispatched" }],
                    status: "LANDED_ONLY"
                  }
                ]
              : []
        }
      }),
    conforming: featureCandidate,
    planted: featureCandidate
  }
];

const KERNEL_ACTIVATION_MAP = {
  "candidate-identity-verify": "identity-activation",
  "candidate-tree-stability": "stability-activation",
  "scope-boundary-classify": "minimal-personal",
  "validation-plan-admission": "admission-activation",
  "validation-plan-validation": "validation-activation",
  "validation-plan-finalization": "finalization-activation",
  "evidence-binding-index": "evidence-activation",
  "prior-art-admission": "standard-team",
  "orphan-closure-verify": "orphan-activation"
};

function runCase(definition, outDir) {
  const summaries = {};
  for (const kind of ["conforming", "planted"]) {
    const target = definition.build(kind);
    const candidate = definition[kind](target.repoDir);
    const runOut = join(outDir, definition.caseId, kind);
    const outcome = evaluateCandidate({
      repoDir: target.repoDir,
      contractBytes: Buffer.from(`${JSON.stringify(target.contractFor(candidate))}\n`, "utf8"),
      outDir: runOut,
      plantHooks: definition.plantHooks?.[kind] ?? null
    });
    if (!outcome.ok) {
      throw new Error(`conformance case ${definition.caseId}/${kind} failed to evaluate: ${JSON.stringify(outcome.errors)}`);
    }
    const withEvidence = definition.verifyEvidence?.[kind] !== false;
    const verification = verifyReceipt({
      receiptBytes: readFileSync(join(runOut, "receipt.json")),
      planBytes: readFileSync(join(runOut, "plan.json")),
      evidenceDir: withEvidence ? join(runOut, "evidence") : null
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

  // Kernel activation proof: every registered kernel mechanism must map to a
  // case whose receipt pair mechanically proves OBSERVED / FIRED-changes-
  // disposition. An unmapped mechanism fails the matrix.
  const registryDoc = validateDocument(
    "mechanism-registry@1",
    readFileSync(new URL("../registry/kernel-mechanisms.json", import.meta.url))
  );
  if (!registryDoc.ok) throw new Error("kernel mechanism registry is invalid");
  const kernelActivation = registryDoc.value.mechanisms.map((mechanism) => {
    const caseId = KERNEL_ACTIVATION_MAP[mechanism.mechanismId];
    if (!caseId) {
      return { mechanismId: mechanism.mechanismId, caseId: "unmapped", proven: false };
    }
    const load = (kind, file) => readFileSync(join(outDir, caseId, kind, file));
    const pair = verifyActivationPair({
      conformingReceiptBytes: load("conforming", "receipt.json"),
      conformingPlanBytes: load("conforming", "plan.json"),
      plantedReceiptBytes: load("planted", "receipt.json"),
      plantedPlanBytes: load("planted", "plan.json"),
      checkId: mechanism.mechanismId
    });
    return { mechanismId: mechanism.mechanismId, caseId, proven: pair.ok };
  });

  const allPassed =
    cases.every(
      (c) =>
        c.conforming.disposition === "PROMOTABLE" &&
        c.conforming.receiptVerified &&
        c.planted.disposition === "BLOCKED" &&
        c.planted.receiptVerified
    ) && kernelActivation.every((a) => a.proven);

  const status = {
    schemaVersion: "conformance-status@1",
    kernelRelease: KERNEL_RELEASE,
    allPassed,
    cases,
    kernelActivation
  };
  const validated = validateValue("conformance-status@1", status);
  if (!validated.ok) throw new Error(`invalid conformance status: ${JSON.stringify(validated.errors)}`);
  const statusBytes = Buffer.from(canonicalize(status), "utf8");
  writeFileSync(join(outDir, "conformance-status.json"), statusBytes);
  return { status, statusBytes };
}
