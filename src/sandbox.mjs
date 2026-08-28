import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative } from "node:path";
import process from "node:process";
import {
  LINUX_OCI_IMAGE,
  LINUX_OCI_BOUNDED_SECCOMP_PATH,
  LINUX_OCI_NODE_PATH,
  LINUX_OCI_SECCOMP_PATH,
  LINUX_OCI_SUPERVISOR_CONTAINER_PATH,
  LINUX_OCI_SUPERVISOR_PATH,
  linuxOciAuthority,
  ociHostEnvironment,
  portableLinuxExecutionAuthority,
  removeLinuxOciContainer,
  runDockerAuthority
} from "./oci-runtime.mjs";
import { EXECUTION_PRESETS, executionCapabilityId, isExecutionRequirement } from "./execution-policy.mjs";
import { SUPERVISOR_REPORT_MAGIC } from "./process-tree-supervisor.mjs";

// Control points this module implements (discovered mechanically by the
// control-surface census from the filesystem, independently of any registry).
export const CONTROL_POINTS = Object.freeze([
  "sandbox-network-isolation",
  "sandbox-read-isolation",
  "sandbox-write-isolation",
  "sandbox-process-ceiling"
]);

// Mandatory OS isolation backend for target-command execution. Isolation is
// DEFAULT-DENY: nothing is permitted unless mechanically declared.
//
//   darwin: sandbox-exec with an SBPL profile that denies everything by
//   default, then allows only:
//     - process exec (to launch the resolved executable);
//     - CONTENT reads of the exact resolved executable FILE (never its
//       parent or install prefix), the exact candidate/base materializations,
//       and the minimum immutable system roots a mach-o binary needs to
//       start (never $HOME, /Users, broad /private or /var, or a sibling
//       temporary directory);
//     - metadata reads anywhere (for path resolution; leaks existence, never
//       content);
//     - device-file writes stdio needs;
//   and denies network* and, at the maxProcesses: 1 ceiling, process-fork.
//
//   linux: a digest-pinned OCI image under a source-closed Docker runtime,
//   with no network namespace, read-only root and bind mounts, all Linux
//   capabilities dropped, no-new-privileges, and a checked-in seccomp
//   profile. SINGLE_PROCESS denies child creation. BOUNDED_PROCESS_TREE uses
//   a separate hash-bound policy plus exact cgroup pids.max enforcement.
//
// The backend is probed once per process by demonstrating the denials and
// inspecting the effective kernel security state. If isolation cannot be
// enforced, a target command FAILS CLOSED with SANDBOX_UNAVAILABLE.

export class SandboxUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = "SandboxUnavailableError";
    this.reasonCode = "SANDBOX_UNAVAILABLE";
  }
}

export class ExecutionBackendRequiredError extends SandboxUnavailableError {
  constructor(message) {
    super(message);
    this.name = "ExecutionBackendRequiredError";
    this.reasonCode = "EXECUTION_BACKEND_REQUIRED";
  }
}

// Immutable OS roots a dynamically-linked mach-o executable needs to start:
// the dyld shared cache, system frameworks, system libraries, the device
// tree. None is user-writable or carries user secrets.
const SYSTEM_READ_ROOTS = Object.freeze([
  "/usr/lib",
  "/System",
  "/private/var/db/dyld",
  "/Library/Developer/CommandLineTools/usr/lib",
  "/dev"
]);

// SBPL string literals are double-quoted; only backslash and double-quote are
// special. Reject control characters (escaped textually so this source file
// stays valid UTF-8 text, never binary) rather than emitting them.
function sbplString(value) {
  if (/[\u0000-\u001f]/.test(value)) {
    throw new SandboxUnavailableError(`path contains control characters and cannot be sandboxed: ${JSON.stringify(value)}`);
  }
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function buildProfile({ singleProcess, executablePath, readRoots, fileLiterals = [], dirLiterals = [] }) {
  const roots = new Set(SYSTEM_READ_ROOTS);
  for (const root of readRoots) roots.add(root);
  const readSubpaths = [...roots].sort().map((root) => `(subpath ${sbplString(root)})`);
  // The executable is granted as an EXACT FILE (literal), never its prefix.
  const literals = new Set();
  if (executablePath) literals.add(executablePath);
  // Exact file grants (e.g. declared input-manifest blobs) and directory-entry
  // grants (so the interpreter can traverse to them, without content access to
  // undeclared siblings).
  for (const f of fileLiterals) literals.add(f);
  for (const d of dirLiterals) literals.add(d);
  const literalGrants = [...literals].sort().map((p) => `(literal ${sbplString(p)})`).join(" ");
  const rules = [
    "(version 1)",
    "(deny default)",
    "(allow process-exec)",
    singleProcess ? "(deny process-fork)" : "(allow process-fork)",
    "(allow sysctl-read)",
    "(allow mach-lookup)",
    "(allow signal (target self))",
    "(deny network*)",
    // Metadata anywhere (path resolution stats ancestors); content reads only
    // for the exact executable, exact declared files, directory entries needed
    // for traversal, the declared subpath roots, and immutable OS roots. No
    // blanket file-read* and no directory prefix from the executable.
    "(allow file-read-metadata)",
    `(allow file-read* (literal "/") ${literalGrants} ${readSubpaths.join(" ")})`,
    "(deny file-write*)",
    '(allow file-write-data (literal "/dev/null") (literal "/dev/dtracehelper") (literal "/dev/tty") (literal "/dev/random") (literal "/dev/urandom"))',
    '(allow file-write* (subpath "/dev/fd"))'
  ];
  return rules.join("");
}

let probed = null;
let boundedProbed = null;

function probeBackend(probeRunner = defaultProbeRunner) {
  if (probeRunner !== defaultProbeRunner) return probeRunner();
  if (process.platform === "darwin") return defaultProbeRunner();
  if (process.platform === "linux") return defaultLinuxProbeRunner();
  return { available: false, reason: `no enforcing sandbox backend is implemented for ${process.platform}` };
}

function defaultProbeRunner() {
  const executablePath = realpathSync(process.execPath);
  const trivialProfile = buildProfile({ singleProcess: true, executablePath, readRoots: [] });

  // The full profile must still permit the executable to start.
  const trivial = spawnSync("sandbox-exec", ["-p", trivialProfile, executablePath, "-e", "process.exit(0)"], {
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
    env: { PATH: process.env.PATH }
  });
  if (trivial.error || trivial.status !== 0) {
    return { available: false, reason: `sandbox-exec probe failed (nested sandbox or unavailable): ${trivial.error ?? trivial.stderr}` };
  }

  // Network denial must demonstrably fail a bind.
  const netScript =
    'const s=require("node:net").createServer();s.on("error",()=>process.exit(1));s.listen(0,()=>process.exit(0));setTimeout(()=>process.exit(2),5000);';
  const netProbe = spawnSync("sandbox-exec", ["-p", trivialProfile, executablePath, "-e", netScript], {
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
    env: { PATH: process.env.PATH }
  });
  if (netProbe.error || netProbe.status !== 1) {
    return { available: false, reason: "sandbox-exec did not demonstrably block a network bind; refusing to trust it" };
  }

  // Content-read denial must demonstrably fail a read outside the roots.
  const readScript =
    'try{require("node:fs").readFileSync("/etc/hosts");process.exit(0)}catch(e){process.exit(e.code==="EPERM"?1:2)}';
  const readProbe = spawnSync("sandbox-exec", ["-p", trivialProfile, executablePath, "-e", readScript], {
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
    env: { PATH: process.env.PATH }
  });
  if (readProbe.error || readProbe.status !== 1) {
    return { available: false, reason: "sandbox-exec did not demonstrably block an out-of-root read; refusing to trust it" };
  }

  return { available: true, reason: null };
}

function validateLinuxMountPath(path, kind) {
  if (!isAbsolute(path)) {
    throw new SandboxUnavailableError(`${kind} must be an absolute path: ${JSON.stringify(path)}`);
  }
  if (/[,\u0000-\u001f]/.test(path)) {
    throw new SandboxUnavailableError(`${kind} cannot be represented by the OCI mount transport: ${JSON.stringify(path)}`);
  }
  return path;
}

function isWithin(root, path) {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function createReadProjection(cwd, readFiles) {
  const projection = mkdtempSync(join(tmpdir(), "shedu-oci-projection-"));
  chmodSync(projection, 0o755);
  try {
    for (const source of readFiles) {
      const rel = relative(cwd, source);
      if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
        throw new SandboxUnavailableError(`declared read file is outside the command working directory: ${source}`);
      }
      const destination = join(projection, rel);
      mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
      copyFileSync(source, destination);
      chmodSync(destination, 0o444);
    }
    return projection;
  } catch (error) {
    rmSync(projection, { recursive: true, force: true });
    throw error;
  }
}

function attachInvocation(argv, { spawnEnv, cleanup, backend, backendAuthorityDigest = null, portableAuthorityDigest = null, capabilityId, containerName = null, execution, parseSpawnResult = null, maxBufferOverhead = 0 }) {
  Object.defineProperties(argv, {
    spawnEnv: { value: spawnEnv, enumerable: false },
    cleanup: { value: cleanup, enumerable: false, configurable: true },
    backend: { value: backend, enumerable: false },
    backendAuthorityDigest: { value: backendAuthorityDigest, enumerable: false },
    portableAuthorityDigest: { value: portableAuthorityDigest, enumerable: false },
    capabilityId: { value: capabilityId, enumerable: false },
    containerName: { value: containerName, enumerable: false },
    execution: { value: execution, enumerable: false },
    parseSpawnResult: { value: parseSpawnResult, enumerable: false },
    maxBufferOverhead: { value: maxBufferOverhead, enumerable: false }
  });
  return argv;
}

export function parseLinuxSupervisorOutput(stdout) {
  const bytes = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout ?? "");
  const magic = Buffer.from(SUPERVISOR_REPORT_MAGIC, "utf8");
  const offset = bytes.lastIndexOf(magic);
  if (offset < 0) throw new SandboxUnavailableError("bounded supervisor emitted no resource report");
  const encoded = bytes.subarray(offset + magic.length).toString("utf8");
  if (!/^[A-Za-z0-9_-]+\n$/.test(encoded)) {
    throw new SandboxUnavailableError("bounded supervisor resource report framing is malformed");
  }
  let report;
  try {
    report = JSON.parse(Buffer.from(encoded.slice(0, -1), "base64url").toString("utf8"));
  } catch {
    throw new SandboxUnavailableError("bounded supervisor resource report is not JSON");
  }
  if (
    report?.schemaVersion !== "process-resource-report@1" ||
    report.class !== "BOUNDED_PROCESS_TREE" ||
    !Number.isSafeInteger(report.maxTasks) ||
    typeof report.limitFired !== "boolean" ||
    !Number.isSafeInteger(report.limitEvents) ||
    report.limitEvents < 0 ||
    typeof report.outputExceeded !== "boolean" ||
    !(report.exitCode === null || Number.isSafeInteger(report.exitCode)) ||
    !(report.signal === null || typeof report.signal === "string")
  ) {
    throw new SandboxUnavailableError("bounded supervisor resource report has an invalid shape");
  }
  return { stdout: bytes.subarray(0, offset), resourceReport: report };
}

export function buildLinuxOciInvocation({
  authority,
  executablePath,
  argvTail,
  readRoots,
  readFiles,
  cwd,
  environment,
  execution = EXECUTION_PRESETS.STRICT,
  maxOutputBytes = 8 * 1024 * 1024,
  projectionDir = null,
  containerName = `shedu-kernel-${randomBytes(12).toString("hex")}`
}) {
  if (executablePath !== LINUX_OCI_NODE_PATH) {
    throw new SandboxUnavailableError(`Linux OCI execution admits only ${LINUX_OCI_NODE_PATH}`);
  }
  if (authority.image.reference !== LINUX_OCI_IMAGE) {
    throw new SandboxUnavailableError("Linux OCI authority does not name the pinned image");
  }
  if (!isExecutionRequirement(execution)) {
    throw new SandboxUnavailableError("Linux OCI execution requires a closed execution authority");
  }
  const bounded = execution.class === "BOUNDED_PROCESS_TREE";
  const portable = portableLinuxExecutionAuthority(execution.class);
  if (bounded && (!authority.seccompDigests?.bounded || !authority.supervisorDigest)) {
    throw new SandboxUnavailableError("Linux OCI authority does not bind the bounded seccomp policy and supervisor");
  }
  validateLinuxMountPath(cwd, "working directory");
  const roots = [...new Set(readRoots.map((path) => validateLinuxMountPath(path, "read root")))].sort();
  const files = [...new Set(readFiles.map((path) => validateLinuxMountPath(path, "read file")))].sort();

  const args = [
    "run",
    "--rm",
    "--pull", "never",
    "--name", containerName,
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--security-opt", `seccomp=${bounded ? LINUX_OCI_BOUNDED_SECCOMP_PATH : LINUX_OCI_SECCOMP_PATH}`,
    "--pids-limit", String(execution.maxTasks),
    "--ipc", "none"
  ];
  if (typeof process.getuid === "function" && typeof process.getgid === "function") {
    args.push("--user", `${process.getuid()}:${process.getgid()}`);
  }
  args.push(
    "--workdir", cwd,
    "--entrypoint", executablePath,
    "--env", "PATH=/usr/local/bin:/usr/bin:/bin"
  );

  // Mount declared roots at their identical absolute paths so the exact
  // command array needs no path rewriting. If cwd is not covered by a root,
  // mount a generated projection containing only the exact declared files.
  for (const root of roots) {
    args.push("--mount", `type=bind,src=${root},dst=${root},readonly`);
  }
  if (bounded) {
    validateLinuxMountPath(LINUX_OCI_SUPERVISOR_PATH, "process-tree supervisor");
    args.push(
      "--mount",
      `type=bind,src=${LINUX_OCI_SUPERVISOR_PATH},dst=${LINUX_OCI_SUPERVISOR_CONTAINER_PATH},readonly`
    );
  }
  if (!roots.some((root) => isWithin(root, cwd))) {
    if (!projectionDir) throw new SandboxUnavailableError("a read projection is required for an unmounted working directory");
    validateLinuxMountPath(projectionDir, "read projection");
    args.push("--mount", `type=bind,src=${projectionDir},dst=${cwd},readonly`);
  }

  const targetValues = {};
  for (const [name, value] of Object.entries(environment)) {
    if (name === "PATH") continue;
    targetValues[name] = String(value);
    args.push("--env", name);
  }
  if (bounded) {
    targetValues.SHEDU_INTERNAL_EXECUTION_CLASS = execution.class;
    targetValues.SHEDU_INTERNAL_MAX_TASKS = String(execution.maxTasks);
    targetValues.SHEDU_INTERNAL_MAX_OUTPUT_BYTES = String(maxOutputBytes);
    for (const name of ["SHEDU_INTERNAL_EXECUTION_CLASS", "SHEDU_INTERNAL_MAX_TASKS", "SHEDU_INTERNAL_MAX_OUTPUT_BYTES"]) {
      args.push("--env", name);
    }
  }
  // Override the image entrypoint so no shell/bootstrap process runs before
  // Node. Docker execs the verified interpreter as PID 1 with argvTail
  // preserved exactly; the image's convenience entrypoint is not authority.
  args.push(
    authority.image.reference,
    ...(bounded
      ? [LINUX_OCI_SUPERVISOR_CONTAINER_PATH, "--", executablePath, ...argvTail]
      : argvTail)
  );

  const invocation = [authority.runtime.path, ...args];
  return attachInvocation(invocation, {
    backend: "linux-oci",
    backendAuthorityDigest: authority.authorityDigest,
    portableAuthorityDigest: portable.portableAuthorityDigest,
    capabilityId: portable.capabilityId,
    containerName,
    execution: { ...execution },
    spawnEnv: ociHostEnvironment(targetValues),
    cleanup: () => removeLinuxOciContainer(containerName),
    parseSpawnResult: bounded ? parseLinuxSupervisorOutput : null,
    maxBufferOverhead: bounded ? 64 * 1024 : 0
  });
}

function runLinuxProbeScript(authority, script, { cwd, readRoots, environment = {}, execution = EXECUTION_PRESETS.STRICT }) {
  const projection = readRoots.some((root) => isWithin(root, cwd)) ? null : createReadProjection(cwd, []);
  const invocation = buildLinuxOciInvocation({
    authority,
    executablePath: LINUX_OCI_NODE_PATH,
    argvTail: ["-e", script],
    readRoots,
    readFiles: [],
    cwd,
    environment,
    execution,
    maxOutputBytes: 1024 * 1024,
    projectionDir: projection
  });
  try {
    const result = spawnSync(invocation[0], invocation.slice(1), {
      encoding: "buffer",
      env: invocation.spawnEnv,
      timeout: 30_000,
      maxBuffer: 1024 * 1024 + invocation.maxBufferOverhead,
      windowsHide: true
    });
    if (invocation.parseSpawnResult && !result.error && result.status === 0) {
      const parsed = invocation.parseSpawnResult(result.stdout);
      result.stdout = parsed.stdout.toString("utf8");
      result.stderr = (result.stderr ?? Buffer.alloc(0)).toString("utf8");
      result.resourceReport = parsed.resourceReport;
      result.status = parsed.resourceReport.exitCode;
      result.signal = parsed.resourceReport.signal;
    } else {
      result.stdout = (result.stdout ?? Buffer.alloc(0)).toString("utf8");
      result.stderr = (result.stderr ?? Buffer.alloc(0)).toString("utf8");
    }
    return result;
  } finally {
    invocation.cleanup();
    if (projection) rmSync(projection, { recursive: true, force: true });
  }
}

function defaultLinuxBoundedProbeRunner() {
  let root;
  try {
    const authority = linuxOciAuthority();
    root = realpathSync(mkdtempSync(join(tmpdir(), "shedu-oci-bounded-probe-")));
    const positive = runLinuxProbeScript(
      authority,
      'const r=require("node:child_process").spawnSync(process.execPath,["-e","process.stdout.write(\"CHILD\")"]);process.stdout.write(r.stdout);process.exit(r.status??1)',
      { cwd: root, readRoots: [root], execution: EXECUTION_PRESETS.STANDARD_TEST }
    );
    if (positive.error || positive.status !== 0 || positive.stdout !== "CHILD" || positive.resourceReport?.limitFired !== false) {
      return { available: false, reason: `bounded child-process probe failed: ${positive.error ?? positive.stderr ?? positive.stdout}` };
    }

    const pressure = runLinuxProbeScript(
      authority,
      'const {spawn}=require("node:child_process");const children=[];for(let i=0;i<256;i++){const c=spawn(process.execPath,["-e","setTimeout(()=>{},5000)"]);c.on("error",()=>{});children.push(c)}setTimeout(()=>{for(const c of children){try{c.kill("SIGKILL")}catch{}}process.exit(0)},500)',
      { cwd: root, readRoots: [root], execution: { class: "BOUNDED_PROCESS_TREE", maxTasks: 65 } }
    );
    if (pressure.resourceReport?.limitFired !== true || pressure.resourceReport.limitEvents < 1) {
      return { available: false, reason: "bounded cgroup probe did not record a pids.max event" };
    }
    return { available: true, reason: null, backend: "linux-oci", authorityDigest: authority.authorityDigest };
  } catch (error) {
    return { available: false, reason: `Linux OCI bounded sandbox unavailable: ${error}` };
  } finally {
    if (root) rmSync(root, { recursive: true, force: true });
  }
}

function defaultLinuxProbeRunner() {
  let root;
  let privateRoot;
  try {
    const authority = linuxOciAuthority();
    root = realpathSync(mkdtempSync(join(tmpdir(), "shedu-oci-probe-")));
    privateRoot = realpathSync(mkdtempSync(join(tmpdir(), "shedu-oci-private-")));
    const privateFile = join(privateRoot, "host-secret");
    writeFileSync(privateFile, "must-not-enter-container");
    const probes = [
      ["startup", "process.exit(0)", (r) => !r.error && r.status === 0],
      ["network", 'const s=require("node:net").createServer();s.on("error",e=>{console.log(e.code);process.exit(e.code==="EPERM"?0:2)});s.listen(0,()=>process.exit(1))', (r) => r.status === 0 && /EPERM/.test(r.stdout)],
      ["read", 'try{require("node:fs").readFileSync(process.env.HOST_PRIVATE_PATH);process.exit(1)}catch(e){console.log(e.code);process.exit(["ENOENT","EACCES","EPERM"].includes(e.code)?0:2)}', (r) => r.status === 0, { HOST_PRIVATE_PATH: privateFile }],
      ["write", 'try{require("node:fs").writeFileSync("probe-write","x");process.exit(1)}catch(e){console.log(e.code);process.exit(["EROFS","EACCES","EPERM"].includes(e.code)?0:2)}', (r) => r.status === 0],
      ["fork", 'const r=require("node:child_process").spawnSync(process.execPath,["-e","0"]);console.log(r.error?.code||"FORKED");process.exit(r.error?0:1)', (r) => r.status === 0 && !/FORKED/.test(r.stdout)],
      ["kernel-state", 'const s=require("node:fs").readFileSync("/proc/self/status","utf8");const v=Object.fromEntries(s.split("\\n").map(x=>x.split(/:\\s*/)).filter(x=>x.length===2));console.log(JSON.stringify({cap:v.CapEff,nnp:v.NoNewPrivs,seccomp:v.Seccomp}));process.exit(v.CapEff==="0000000000000000"&&v.NoNewPrivs==="1"&&v.Seccomp==="2"?0:1)', (r) => r.status === 0]
    ];
    for (const [name, script, passed, environment = {}] of probes) {
      const result = runLinuxProbeScript(authority, script, { cwd: root, readRoots: [root], environment });
      if (!passed(result)) {
        return { available: false, reason: `Linux OCI ${name} probe failed: ${result.error ?? result.stderr ?? result.stdout}` };
      }
    }
    return { available: true, reason: null, backend: "linux-oci", authorityDigest: authority.authorityDigest };
  } catch (error) {
    return { available: false, reason: `Linux OCI sandbox unavailable: ${error}` };
  } finally {
    if (root) rmSync(root, { recursive: true, force: true });
    if (privateRoot) rmSync(privateRoot, { recursive: true, force: true });
  }
}

export function sandboxStatus() {
  if (probed === null) probed = probeBackend();
  return probed;
}

export function boundedSandboxStatus() {
  if (boundedProbed === null) {
    boundedProbed = process.platform === "linux"
      ? defaultLinuxBoundedProbeRunner()
      : { available: false, reason: "BOUNDED_PROCESS_TREE requires the pinned Linux OCI backend" };
  }
  return boundedProbed;
}

// Wraps a resolved executable + declared argv tail for isolated execution.
// `executablePath` is the concrete, already-verified interpreter (from the
// closed toolchain authority). readRoots are the mechanically declared,
// path-contained roots the command may READ (candidate and base
// materializations). Throws SandboxUnavailableError when isolation cannot be
// enforced — including a requested execution class this backend cannot cap
// exactly.
export function isolateExecution({ executablePath, argvTail, maxProcesses, execution = null, maxOutputBytes = 8 * 1024 * 1024, readRoots = [], readFiles = [], cwd = process.cwd(), environment = {} }) {
  const status = sandboxStatus();
  if (!status.available) {
    throw new SandboxUnavailableError(`target-command isolation unavailable: ${status.reason}`);
  }
  if (execution === null && maxProcesses !== 1) {
    throw new SandboxUnavailableError(
      `this backend enforces a process ceiling only by fork denial; maxProcesses ${maxProcesses} cannot be capped exactly`
    );
  }
  const effectiveExecution = execution ?? EXECUTION_PRESETS.STRICT;
  if (!isExecutionRequirement(effectiveExecution)) {
    throw new SandboxUnavailableError("a closed execution requirement is required");
  }
  if (!isAbsolute(executablePath)) {
    throw new SandboxUnavailableError(`executable must be an absolute resolved path: ${JSON.stringify(executablePath)}`);
  }

  if (process.platform === "linux") {
    if (effectiveExecution.class === "BOUNDED_PROCESS_TREE") {
      const bounded = boundedSandboxStatus();
      if (!bounded.available) throw new SandboxUnavailableError(`bounded target-command isolation unavailable: ${bounded.reason}`);
    }
    const realCwd = realpathSync(cwd);
    const realRoots = readRoots.map((root) => realpathSync(root));
    const realFiles = readFiles.map((file) => realpathSync(file));
    const needsProjection = !realRoots.some((root) => isWithin(root, realCwd));
    const projection = needsProjection ? createReadProjection(realCwd, realFiles) : null;
    try {
      const invocation = buildLinuxOciInvocation({
        authority: linuxOciAuthority(),
        executablePath,
        argvTail,
        readRoots: realRoots,
        readFiles: realFiles,
        cwd: realCwd,
        environment,
        execution: effectiveExecution,
        maxOutputBytes,
        projectionDir: projection
      });
      const cleanup = invocation.cleanup;
      Object.defineProperty(invocation, "cleanup", {
        value: () => {
          cleanup();
          if (projection) rmSync(projection, { recursive: true, force: true });
        },
        enumerable: false
      });
      return invocation;
    } catch (error) {
      if (projection) rmSync(projection, { recursive: true, force: true });
      throw error;
    }
  }

  if (effectiveExecution.class === "BOUNDED_PROCESS_TREE") {
    throw new ExecutionBackendRequiredError("BOUNDED_PROCESS_TREE requires the pinned Linux OCI backend");
  }

  const grantedReadRoots = new Set();
  const grant = (p) => {
    grantedReadRoots.add(p);
    try {
      grantedReadRoots.add(realpathSync(p));
    } catch {
      // unresolvable; the literal grant stands
    }
  };
  for (const root of readRoots) {
    if (!isAbsolute(root)) {
      throw new SandboxUnavailableError(`read root must be an absolute path: ${JSON.stringify(root)}`);
    }
    grant(root);
  }

  // Exact-file grants (declared input-manifest blobs) plus the directory
  // entries needed to traverse to them and to the working directory. A dir
  // ENTRY grant permits listing/traversal but NOT reading undeclared child
  // file contents, so a dynamic read of an undeclared base file is denied.
  const fileLiterals = new Set();
  const dirLiterals = new Set();
  const addFile = (f) => {
    const real = (() => {
      try {
        return realpathSync(f);
      } catch {
        return f;
      }
    })();
    fileLiterals.add(f);
    fileLiterals.add(real);
    for (const p of [f, real]) {
      let d = dirname(p);
      while (d && d !== "/" && !dirLiterals.has(d)) {
        dirLiterals.add(d);
        d = dirname(d);
      }
    }
  };
  // The working directory must be traversable/readable (node reads uv_cwd).
  for (const p of [cwd, (() => { try { return realpathSync(cwd); } catch { return cwd; } })()]) {
    let d = p;
    while (d && d !== "/" && !dirLiterals.has(d)) {
      dirLiterals.add(d);
      d = dirname(d);
    }
  }
  for (const f of readFiles) {
    if (!isAbsolute(f)) throw new SandboxUnavailableError(`read file must be an absolute path: ${JSON.stringify(f)}`);
    addFile(f);
  }

  const profile = buildProfile({
    singleProcess: true,
    executablePath,
    readRoots: [...grantedReadRoots],
    fileLiterals: [...fileLiterals],
    dirLiterals: [...dirLiterals]
  });
  return attachInvocation(["sandbox-exec", "-p", profile, executablePath, ...argvTail], {
    backend: "darwin-sandbox-exec",
    backendAuthorityDigest: null,
    portableAuthorityDigest: null,
    capabilityId: executionCapabilityId(effectiveExecution.class),
    execution: { ...effectiveExecution },
    spawnEnv: environment,
    cleanup: () => {}
  });
}

// Test seam: force a probe result (null re-probes on next use), or run the
// probe against an injected runner to exercise the nested-sandbox path.
export function overrideSandboxProbe(result) {
  probed = result;
  boundedProbed = result;
}

export function probeBackendWith(probeRunner) {
  return probeBackend(probeRunner);
}
