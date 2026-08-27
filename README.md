# Shedu Promotion Kernel

Shedu Promotion Kernel is a model-independent, evidence-bound gate for AI-generated software changes. Its job is deliberately narrow: decide whether an immutable candidate may be promoted into a target repository.

Shedu Promotion Kernel is a mechanical approval gate for AI-generated code. It evaluates an immutable candidate against an authorized work contract and selected policy packs. It verifies identity and scope, runs required validation, checks for conflicts with existing capabilities, detects orphaned controls, enforces repository-specific architecture rules, and confirms that all required evidence is complete and untampered. It then issues a machine-verifiable PROMOTABLE or BLOCKED receipt.
The kernel does not generate code or decide what should be built. It determines whether the implementation stayed within its authority and satisfied the mechanical conditions required for promotion.

> **Status: FOUNDATION_ONLY.** The system is built and has passed several rounds of adversarial testing, but this public version is not yet authorized to approve software changes.
It runs checks in a tightly controlled environment: programs are verified before execution, network access and file changes are blocked, resource and time limits are enforced, and critical failures stop the process. Every decision is backed by tamper-evident evidence and can be independently verified or digitally signed.
Before the kernel can enter experimental use, an independent authority must certify a specific clean version using an external signing key. The public repository cannot certify itself, so it correctly refuses to issue promotion approvals.
The secure execution environment supports native macOS isolation and Linux through an immutable, digest-pinned OCI container. Both backends enforce one target process at a time; multi-process target test suites remain unsupported rather than receiving weaker isolation.

## Promotion path

The kernel is limited to six stages:

1. Accept an exact work contract and target identity.
2. Bind exact commands, roles, policies, and permitted writes.
3. Execute in an isolated workspace.
4. Freeze an immutable candidate commit or tree.
5. Run deterministic validation and independent outcome review.
6. Emit a signed `PROMOTABLE` or `BLOCKED` receipt.

Exploration, idea generation, brief/spec/prompt authoring, provider selection experiments, dashboards, and product-specific governance remain outside the kernel.

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
