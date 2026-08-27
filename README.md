# Shedu Promotion Kernel

Shedu Promotion Kernel is a model-independent, evidence-bound gate for AI-generated software changes. Its job is deliberately narrow: decide whether an immutable candidate may be promoted into a target repository.

> **Status: FOUNDATION_ONLY The system is built and has passed several rounds of adversarial testing, but this public version is not yet authorized to approve software changes.
It runs checks in a tightly controlled environment: programs are verified before execution, network access and file changes are blocked, resource and time limits are enforced, and critical failures stop the process. Every decision is backed by tamper-evident evidence and can be independently verified or digitally signed.
Before the kernel can enter experimental use, an independent authority must certify a specific clean version using an external signing key. The public repository cannot certify itself, so it correctly refuses to issue promotion approvals.
The current secure execution environment supports macOS only and permits one process at a time. Multi-process test suites and other operating systems are not yet supported, so the pilot remains blocked until those limitations are addressed.

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

`conformance-status@2` is a portable semantic projection. Full receipts keep
their host-bound evaluation digests and exact executable/evidence identities;
the committed status instead binds plans, candidates, dispositions, and check
outcomes so an external attestor can reproduce it across supported macOS
toolchains without discarding the underlying execution evidence.

## CLI surfaces

```sh
node src/cli.mjs compile --contract <file> --repo <dir>
node src/cli.mjs evaluate --contract <file> --repo <dir> --out <dir> [--sign-key <pem>]
node src/cli.mjs verify-receipt --receipt <file> --plan <file> [--evidence <dir>] [--public-key <hex>]
node src/cli.mjs conformance --out <dir>
node src/cli.mjs --subject-probe
```

Each emits machine-readable JSON on stdout and machine errors on stderr.

## Install and try a policy pack

The current distribution is installed directly from an immutable Git commit; it has no
runtime dependencies and does not connect to a model provider. Follow
[the installation guide](docs/INSTALLATION.md) for a pinned source checkout or a pinned
Git dependency, supported-platform boundaries, and the external-admission requirement.

The repository includes a complete, compiler-verified
[Node source-hygiene sample](examples/node-source-hygiene/README.md): a declarative pack,
an exact-digest profile, and a base-owned target validator. Verify its positive fixture,
negative fixture, authority pins, and compiled plan mechanically:

```sh
npm run verify:sample-policy
```

## Development

```sh
npm test
npm run verify:sample-policy
npm run subject:probe
```

The project has no runtime dependencies and requires Node.js 22 or newer.

## Security

Do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
