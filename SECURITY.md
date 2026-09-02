# Security Policy

## Supported versions

`v0.4.0-experimental.1` is the supported public pilot distribution. It may be
used to evaluate experimental and non-production candidate changes through
`shedu-kernel-experimental`. It is not a production certification or a warranty
that promoted software is defect-free.

The lower-level `shedu-promotion-kernel` source entrypoint remains
`FOUNDATION_ONLY` without external admission material and must not be treated
as an available promotion gate.

Keep the distribution checkout outside the governed target's writable scope.
The launcher verifies the signed certification and exact detached kernel, but
the operator remains responsible for protecting the launcher and activation
bundle from candidate writes. Installing it inside a target repository is a
development convenience, not an independent trust boundary.

The Ed25519 private attestation key is not distributed. A report claiming that
the private key, an unsigned replacement authority, or a mutable kernel source
can be used by the experimental launcher is a security vulnerability.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities, credential exposure, sandbox escapes, signature bypasses, or false-promotion cases in a public issue. Use GitHub's private vulnerability reporting for this repository. Include the affected commit, exact command array, expected disposition, observed disposition, and a minimal reproducer when safe.

The kernel will fail closed when required identity, evidence, isolation, validation, review, or signature material is absent or invalid.
