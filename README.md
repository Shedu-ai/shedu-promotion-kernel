# Shedu Promotion Kernel

Shedu Promotion Kernel is a model-independent, evidence-bound gate for AI-generated software changes. Its job is deliberately narrow: decide whether an immutable candidate may be promoted into a target repository.

> **Status: EXPERIMENTAL.** The promotion pipeline — compiler, mandatory integrity packs, isolated exact-argv execution, disposition reducer, content-addressed evidence, and offline-verifiable receipts — is implemented and gated by regenerable conformance evidence in [`conformance/status.json`](conformance/status.json). The subject probe reports `EXPERIMENTAL` only while that evidence validates for the current release; it is not a claim of production readiness or certification.

## Promotion path

The kernel is limited to six stages:

1. Accept an exact work contract and target identity.
2. Bind exact commands, roles, policies, and permitted writes.
3. Execute in an isolated workspace.
4. Freeze an immutable candidate commit or tree.
5. Run deterministic validation and independent outcome review.
6. Emit a signed `PROMOTABLE` or `BLOCKED` receipt.

Exploration, idea generation, brief/spec/prompt authoring, provider selection experiments, dashboards, and product-specific governance remain outside the kernel.

## Harness Bench

[`/.harness-bench/subject.json`](.harness-bench/subject.json) is the machine-readable connection contract. Harness Bench resolves the repository to an immutable commit, preserves each launch command as an argument array, invokes the probe, and records the exact subject identity before any experiment.

The probe is evidence-gated:

```sh
npm run subject:probe
```

It reports `EXPERIMENTAL` only while the committed conformance status is schema-valid, fully passed, and pinned to the current kernel release; otherwise it falls back to `FOUNDATION_ONLY` with no promotion entrypoint.

## CLI surfaces

```sh
node src/cli.mjs compile --contract <file> --repo <dir>
node src/cli.mjs evaluate --contract <file> --repo <dir> --out <dir> [--sign-key <pem>]
node src/cli.mjs verify-receipt --receipt <file> --plan <file> [--evidence <dir>] [--public-key <hex>]
node src/cli.mjs conformance --out <dir>
node src/cli.mjs --subject-probe
```

Each emits machine-readable JSON on stdout and machine errors on stderr.

## Development

```sh
npm test
npm run subject:probe
```

The project has no runtime dependencies and requires Node.js 22 or newer.

## Security

Do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
