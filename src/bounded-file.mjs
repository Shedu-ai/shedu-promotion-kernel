import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

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
