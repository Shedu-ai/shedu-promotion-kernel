# Shedu Promotion Kernel

Shedu Promotion Kernel is a model-independent, evidence-bound gate for AI-generated software changes. Its job is deliberately narrow: decide whether an immutable candidate may be promoted into a target repository.

> **Status: FOUNDATION_ONLY (honest).** The full promotion pipeline is implemented and hardened across three adversarial-review rounds: a closed toolchain authority (executables resolve without ambient PATH, are granted as exact files rather than install prefixes, and are content-digest verified before execution), a default-deny sandbox (content reads confined to the candidate/base materializations, network denied, filesystem read-only, fork denied; fail-closed on nested sandboxes), a hard whole-evaluation deadline supervised in a separate worker process, cumulative-artifact/output/process ceilings, per-phase command scheduling, containment/identity/authority/evidence halts with explicit skip records, an override-free branded disposition reducer, content-addressed evidence, fingerprint-bound mechanism activation, offline-verifiable and optionally Ed25519-signed receipts, a runtime control-surface census (each control proven by execution) with a source architecture fence, and contract authorization verified against a base-authoritative trust root. Elevation to `EXPERIMENTAL` requires an **externally-supplied** pinned key plus a detached attestation over a **clean frozen commit** (verified working tree). **No external key is pinned in this public build, so the probe honestly reports `FOUNDATION_ONLY`** and the promotion entrypoint is refused — the elevation machinery is real and tested, but cannot be satisfied by editing the subject's own evidence. The sandbox backend currently exists for macOS (`sandbox-exec`); other platforms fail closed. `maxProcesses` is fixed at 1 (fork denial); multi-process test runners are a known limitation that keeps pilot blocked rather than weakening isolation.

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
