# Shedu Promotion Kernel

Shedu Promotion Kernel is a model-independent approval gate for AI-generated code. It decides one question:

> Did this exact, immutable candidate satisfy its authorized requirements and remain within its permitted scope?

The kernel does not generate code, choose a solution, or decide what should be built. Coding agents— (ie Grok build, Codex, Claude Code, or local models)—work outside the kernel. They submit completed candidates for mechanical evaluation.

## What the kernel checks

For every candidate, the kernel mechanically verifies:

- **Identity:** The evaluated Git commit is the exact candidate declared in the work contract.
- **Authority:** Policies, validators, architecture rules, and permitted scope come from a frozen, trusted base commit—not from files rewritten by the candidate.
- **Scope:** Every changed file is classified as writable, read-only, forbidden, or unclassified. Unauthorized changes block promotion.
- **Prior art:** New work is checked against registered capabilities so it cannot silently duplicate, replace, or conflict with an existing mechanism.
- **Required validation:** The exact commands declared by the governing policy are executed with their original argument arrays—without shell parsing or controller substitutions.
- **Architecture:** Repository-specific structural rules are evaluated by registered validators.
- **Orphan closure:** Registered controls must be implemented, dispatched, exercised, evidenced, and consumed. Missing wiring or unregistered mechanisms block promotion.
- **Resource enforcement:** Network access, filesystem writes, execution time, output size, artifact size, and process creation are mechanically restricted.
- **Evidence integrity:** Test results and other evidence are content-addressed and bound to the candidate, compiled plan, execution environment, and final disposition.
- **Completeness:** Missing, malformed, skipped, duplicated, or unverifiable blocking results fail closed.
- **Final disposition:** A fixed reducer—not the coding agent—produces `PROMOTABLE` or `BLOCKED`.

Sandboxed validation: When the kernel executes candidate validation—not while an agent develops the code—it denies network access and host filesystem writes and enforces fixed runtime, output, evidence, and task ceilings. Strict checks prohibit child processes; authorized Linux test suites receive a mechanically bounded process tree. These restrictions prevent candidate-controlled code from altering or escaping its own evaluation.

The resulting receipt can be verified offline and optionally signed with Ed25519.

## How the kernel checks it

The kernel compiles the work contract and policy packs into an immutable execution plan. That plan binds:

- the candidate and trusted base commits;
- exact file permissions;
- exact validators and commands;
- policy and architecture digests;
- execution phases;
- resource ceilings;
- the enforcing sandbox authority; and
- the evidence required for each decision.

Commands run without a shell in a controlled environment. Executables are resolved through a closed toolchain and verified by content digest before use.

On macOS, strict checks run under the native sandbox with child-process creation denied. On Linux, checks run inside an immutable, digest-pinned OCI image with:

- no network;
- a read-only filesystem;
- dropped capabilities;
- `no-new-privileges`;
- a checked-in seccomp policy;
- exact cgroup task ceilings; and
- a trusted PID-1 supervisor that terminates and reaps the complete process tree.

The Linux `STANDARD_TEST` profile supports realistic, numerically bounded multi-process Node test suites. Users and coding agents do not configure Docker, seccomp, cgroups, or process limits themselves.

## How this differs from running a normal harness inside Codex or Claude Code

A normal coding-agent harness usually trusts the agent controlling the run. The agent may choose which commands to execute, alter arguments, retry under different conditions, interpret incomplete output, overlook skipped checks, or summarize its own work as successful. The tests may be mechanical, but the orchestration and final judgment still depend on the same model that produced the code.

Shedu Promotion Kernel treats the coding agent as an untrusted submitter.

The agent cannot:

- change the governing policy for its own candidate;
- expand its authorized write scope;
- substitute validators or executables;
- rewrite commands during execution;
- increase resource limits;
- suppress required checks;
- convert missing evidence into success; or
- override the final disposition.

This separation allows Codex, Claude Code, local models, or future coding agents to be exchanged without making any one controller the authority over its own work.

## Status: `FOUNDATION_ONLY`

The promotion pipeline is implemented and has passed repeated adversarial and cross-platform testing. Strict macOS execution and bounded multi-process Linux OCI execution are operational.

The public repository intentionally remains `FOUNDATION_ONLY` because it cannot authorize itself. Promotion becomes available only when an independent authority certifies a specific clean commit using an externally controlled signing key and supplies the corresponding pinned attestation.

Until then, the repository can compile policies, run conformance tests, verify its isolation mechanisms, and demonstrate the complete decision pipeline—but it correctly refuses to issue authoritative promotion approvals.

## Promotion path

The kernel performs six stages:

1. Accept an exact work contract and immutable target identity.
2. Compile and bind the governing policies, commands, scope, and resource limits.
3. Execute the required checks in an enforced sandbox.
4. Verify candidate stability and freeze the resulting evidence.
5. Mechanically validate completeness, integrity, architecture, prior art, and orphan closure.
6. Emit an offline-verifiable `PROMOTABLE` or `BLOCKED` receipt.

Exploration, idea generation, brief/specification authoring, model selection, dashboards, and product-specific governance remain outside the kernel.

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
