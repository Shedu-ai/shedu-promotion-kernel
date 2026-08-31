import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { createHash } from "node:crypto";

// Read a regular file through one descriptor. O_NOFOLLOW rejects a final-path
// symlink and closes the stat/read substitution race; O_NONBLOCK prevents a
// FIFO/device path from stalling before its type can be checked. Size is
// checked on the opened descriptor before and after the exact bounded read.
export function readBoundedRegularFile(path, maxBytes) {
  if (typeof path !== "string" || path.length === 0) throw new TypeError("path must be a non-empty string");
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new TypeError("maxBytes must be a positive safe integer");
  if (typeof constants.O_NOFOLLOW !== "number" || typeof constants.O_NONBLOCK !== "number") {
    throw new Error("the platform cannot enforce no-follow, non-blocking bounded reads");
  }

  let fd = null;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.size > BigInt(maxBytes)) throw new Error("path is not a bounded regular file");

    const size = Number(before.size);
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    const after = fstatSync(fd, { bigint: true });
    if (
      offset !== size || after.size !== before.size || after.dev !== before.dev || after.ino !== before.ino ||
      after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs
    ) {
      throw new Error("file identity or size changed during bounded read");
    }
    const overflowProbe = Buffer.alloc(1);
    if (readSync(fd, overflowProbe, 0, 1, null) !== 0) throw new Error("file grew during bounded read");
    return bytes;
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

// Stream a regular file through one no-follow descriptor, retaining at most a
// caller-declared preview. This permits evidence verification against large
// authorized artifact ceilings without allocating the whole object in memory.
// The returned digest and preview describe the same descriptor identity; a
// replacement, resize, or timestamp change during the read fails closed.
export function hashBoundedRegularFile(path, maxBytes, { previewBytes = 0, validateUtf8 = false } = {}) {
  if (typeof path !== "string" || path.length === 0) throw new TypeError("path must be a non-empty string");
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new TypeError("maxBytes must be a non-negative safe integer");
  if (!Number.isSafeInteger(previewBytes) || previewBytes < 0 || previewBytes > maxBytes) {
    throw new TypeError("previewBytes must be a non-negative safe integer no larger than maxBytes");
  }
  if (typeof constants.O_NOFOLLOW !== "number" || typeof constants.O_NONBLOCK !== "number") {
    throw new Error("the platform cannot enforce no-follow, non-blocking bounded reads");
  }

  let fd = null;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.size > BigInt(maxBytes)) throw new Error("path is not a bounded regular file");
    const expectedSize = Number(before.size);
    const digest = createHash("sha256");
    const preview = Buffer.alloc(Math.min(previewBytes, expectedSize));
    const decoder = validateUtf8 ? new TextDecoder("utf-8", { fatal: true }) : null;
    const chunk = Buffer.alloc(Math.min(64 * 1024, Math.max(1, expectedSize)));
    let offset = 0;
    let utf8Valid = true;
    while (offset < expectedSize) {
      const count = readSync(fd, chunk, 0, Math.min(chunk.length, expectedSize - offset), null);
      if (count === 0) break;
      const bytes = chunk.subarray(0, count);
      digest.update(bytes);
      if (offset < preview.length) {
        bytes.copy(preview, offset, 0, Math.min(count, preview.length - offset));
      }
      if (decoder !== null && utf8Valid) {
        try {
          decoder.decode(bytes, { stream: true });
        } catch {
          utf8Valid = false;
        }
      }
      offset += count;
    }
    if (decoder !== null && utf8Valid) {
      try {
        decoder.decode();
      } catch {
        utf8Valid = false;
      }
    }
    const after = fstatSync(fd, { bigint: true });
    if (
      offset !== expectedSize || after.size !== before.size || after.dev !== before.dev || after.ino !== before.ino ||
      after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs
    ) {
      throw new Error("file identity or size changed during bounded hash read");
    }
    const overflowProbe = Buffer.alloc(1);
    if (readSync(fd, overflowProbe, 0, 1, null) !== 0) throw new Error("file grew during bounded hash read");
    return {
      digest: `sha256:${digest.digest("hex")}`,
      byteLength: expectedSize,
      preview,
      utf8Valid
    };
  } finally {
    if (fd !== null) closeSync(fd);
  }
}
