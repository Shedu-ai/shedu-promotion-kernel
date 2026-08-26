# Shedu Promotion Kernel

Shedu Promotion Kernel is a model-independent, evidence-bound gate for AI-generated software changes. Its job is deliberately narrow: decide whether an immutable candidate may be promoted into a target repository.

> **Status: FOUNDATION ONLY.** The public repository establishes the product boundary, machine-readable subject probe, and Harness Bench connection contract. It does not yet authorize or promote changes.

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

The current probe is intentionally honest:

```sh
npm run subject:probe
```

It reports `FOUNDATION_ONLY`. A scored or pilot run must reject that status until the promotion entrypoint and declared capabilities are implemented and verified.

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
