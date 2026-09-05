import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { digestOfBytes, digestOfCanonical } from "./canonical-json.mjs";
import { executionCapabilityId } from "./execution-policy.mjs";

// Official node:22-bookworm-slim OCI index resolved from Docker Hub and
// frozen by digest on 2026-08-27. The digest, not the mutable tag, is the
// execution authority. It contains linux/amd64 and linux/arm64 manifests.
export const LINUX_OCI_IMAGE_DIGEST = "sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5";
export const LINUX_OCI_IMAGE = `docker.io/library/node@${LINUX_OCI_IMAGE_DIGEST}`;
export const LINUX_OCI_NODE_PATH = "/usr/local/bin/node";
export const LINUX_OCI_SECCOMP_PATH = fileURLToPath(new URL("../security/linux-seccomp.json", import.meta.url));
export const LINUX_OCI_BOUNDED_SECCOMP_PATH = fileURLToPath(new URL("../security/linux-seccomp-bounded.json", import.meta.url));
export const LINUX_OCI_SUPERVISOR_PATH = fileURLToPath(new URL("./process-tree-supervisor.mjs", import.meta.url));
export const LINUX_OCI_SUPERVISOR_CONTAINER_PATH = "/shedu-kernel/process-tree-supervisor.mjs";

const DOCKER_CANDIDATES = Object.freeze([
  "/usr/bin/docker",
  "/usr/local/bin/docker"
]);
const DOCKER_HOST = "unix:///var/run/docker.sock";

export class OciRuntimeError extends Error {
  constructor(message) {
    super(message);
    this.name = "OciRuntimeError";
    this.reasonCode = "SANDBOX_UNAVAILABLE";
  }
}

function hashFile(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

// Portable authority is plan material: it deliberately excludes the host's
// Docker client, daemon version, and local image id, while binding every
// immutable byte that defines bounded execution. Runtime authority is
// recorded separately by buildAuthority() and proves which host enforced it.
export function portableLinuxExecutionAuthority(executionClass) {
  const capabilityId = executionCapabilityId(executionClass);
  if (executionClass === "SINGLE_PROCESS") {
    return { capabilityId, portableAuthorityDigest: null };
  }
  if (executionClass !== "BOUNDED_PROCESS_TREE") {
    throw new OciRuntimeError(`unsupported execution class ${JSON.stringify(executionClass)}`);
  }
  const identity = {
    schemaVersion: "linux-oci-portable-execution-authority@1",
    capabilityId,
    imageReference: LINUX_OCI_IMAGE,
    nodePath: LINUX_OCI_NODE_PATH,
    seccompDigest: digestOfBytes(readFileSync(LINUX_OCI_BOUNDED_SECCOMP_PATH)),
    supervisorDigest: digestOfBytes(readFileSync(LINUX_OCI_SUPERVISOR_PATH))
  };
  return { capabilityId, portableAuthorityDigest: digestOfCanonical(identity) };
}

export function ociHostEnvironment(extra = {}) {
  return {
    ...extra,
    PATH: "/usr/bin:/bin",
    HOME: "/nonexistent",
    DOCKER_CONFIG: "/nonexistent",
    DOCKER_HOST
  };
}

function resolveDockerExecutable() {
  for (const candidate of DOCKER_CANDIDATES) {
    if (!isAbsolute(candidate) || !existsSync(candidate)) continue;
    try {
      const path = realpathSync(candidate);
      if (!statSync(path).isFile()) continue;
      return { path, digest: hashFile(path) };
    } catch {
      // A partially present candidate is not authority; continue through the
      // source-closed list. PATH and environment variables never add one.
    }
  }
  throw new OciRuntimeError("no Docker CLI exists at a source-closed runtime path");
}

function runDocker(runtime, args, { timeout = 30_000, maxBuffer = 8 * 1024 * 1024, env = {} } = {}) {
  const result = spawnSync(runtime.path, args, {
    encoding: "utf8",
    windowsHide: true,
    timeout,
    maxBuffer,
    env: ociHostEnvironment(env)
  });
  return result;
}

function parseJsonOutput(result, operation) {
  if (result.error || result.status !== 0) {
    throw new OciRuntimeError(`${operation} failed: ${result.error ?? result.stderr}`);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new OciRuntimeError(`${operation} did not return JSON`);
  }
}

let cachedAuthority = null;

function buildAuthority() {
  if (process.platform !== "linux") {
    throw new OciRuntimeError(`the OCI sandbox backend is linux-only, not ${process.platform}`);
  }
  const runtime = resolveDockerExecutable();
  const server = parseJsonOutput(
    runDocker(runtime, ["version", "--format", "{{json .Server}}"]),
    "Docker server identity"
  );
  if (typeof server?.Os !== "string" || server.Os.toLowerCase() !== "linux") {
    throw new OciRuntimeError(`Docker server must be linux, found ${JSON.stringify(server?.Os)}`);
  }
  const image = parseJsonOutput(
    runDocker(runtime, ["image", "inspect", "--format", "{{json .}}", LINUX_OCI_IMAGE]),
    `pinned image inspection (${LINUX_OCI_IMAGE})`
  );
  if (!/^sha256:[0-9a-f]{64}$/.test(image?.Id ?? "")) {
    throw new OciRuntimeError("pinned image inspection returned no content-addressed image id");
  }
  const repositoryDigests = Array.isArray(image?.RepoDigests) ? image.RepoDigests : [];
  if (!repositoryDigests.some((entry) => entry.endsWith(`@${LINUX_OCI_IMAGE_DIGEST}`))) {
    throw new OciRuntimeError("local image identity is not bound to the required OCI index digest");
  }
  const strictSeccompBytes = readFileSync(LINUX_OCI_SECCOMP_PATH);
  const boundedSeccompBytes = readFileSync(LINUX_OCI_BOUNDED_SECCOMP_PATH);
  const supervisorBytes = readFileSync(LINUX_OCI_SUPERVISOR_PATH);
  const identity = {
    schemaVersion: "linux-oci-authority@1",
    runtime: { path: runtime.path, digest: runtime.digest },
    server: {
      platform: server.Platform?.Name ?? "Docker Engine",
      version: server.Version ?? "unknown",
      apiVersion: server.ApiVersion ?? "unknown",
      os: server.Os,
      arch: server.Arch ?? "unknown"
    },
    image: {
      reference: LINUX_OCI_IMAGE,
      indexDigest: LINUX_OCI_IMAGE_DIGEST,
      imageId: image.Id,
      repositoryDigests: [...repositoryDigests].sort()
    },
    seccompDigests: {
      strict: digestOfBytes(strictSeccompBytes),
      bounded: digestOfBytes(boundedSeccompBytes)
    },
    supervisorDigest: digestOfBytes(supervisorBytes),
    portableAuthorityDigests: {
      bounded: portableLinuxExecutionAuthority("BOUNDED_PROCESS_TREE").portableAuthorityDigest
    }
  };
  return {
    ...identity,
    authorityDigest: digestOfCanonical(identity)
  };
}

export function linuxOciAuthority() {
  if (cachedAuthority === null) cachedAuthority = buildAuthority();
  return structuredClone(cachedAuthority);
}

export function verifyLinuxOciAuthority(expected = linuxOciAuthority()) {
  const fresh = buildAuthority();
  if (fresh.authorityDigest !== expected.authorityDigest) {
    throw new OciRuntimeError(
      `Linux OCI authority drifted: expected ${expected.authorityDigest}, found ${fresh.authorityDigest}`
    );
  }
  return fresh;
}

export function resetLinuxOciAuthority() {
  cachedAuthority = null;
}

export function runDockerAuthority(args, options = {}) {
  const authority = linuxOciAuthority();
  const runtime = { path: authority.runtime.path, digest: authority.runtime.digest };
  if (hashFile(runtime.path) !== runtime.digest) {
    throw new OciRuntimeError("Docker CLI digest drifted before execution");
  }
  return runDocker(runtime, args, options);
}

export function removeLinuxOciContainer(containerName) {
  if (!/^[a-z0-9][a-z0-9_.-]{0,62}$/.test(containerName)) return;
  try {
    const authority = linuxOciAuthority();
    const runtime = { path: authority.runtime.path, digest: authority.runtime.digest };
    if (hashFile(runtime.path) !== runtime.digest) return;
    runDocker(runtime, ["rm", "--force", containerName], { timeout: 15_000, maxBuffer: 1024 * 1024 });
  } catch {
    // Cleanup is best-effort after the supervised command has already ended.
    // The unique name plus --rm prevents reuse; a later daemon cleanup can
    // remove a container whose client was killed mid-request.
  }
}

export function pullPinnedLinuxOciImage() {
  if (process.platform !== "linux") {
    throw new OciRuntimeError("the pinned Linux image can only be installed on Linux");
  }
  const runtime = resolveDockerExecutable();
  const pulled = runDocker(runtime, ["pull", LINUX_OCI_IMAGE], { timeout: 10 * 60_000, maxBuffer: 32 * 1024 * 1024 });
  if (pulled.error || pulled.status !== 0) {
    throw new OciRuntimeError(`pinned image pull failed: ${pulled.error ?? pulled.stderr}`);
  }
  resetLinuxOciAuthority();
  return linuxOciAuthority();
}
