#!/usr/bin/env node
import { pullPinnedLinuxOciImage, LINUX_OCI_IMAGE } from "../src/oci-runtime.mjs";

try {
  const authority = pullPinnedLinuxOciImage();
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "linux-oci-installation@1",
    image: LINUX_OCI_IMAGE,
    imageId: authority.image.imageId,
    authorityDigest: authority.authorityDigest
  })}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({
    reasonCode: error?.reasonCode ?? "SANDBOX_UNAVAILABLE",
    message: String(error)
  })}\n`);
  process.exitCode = 2;
}
