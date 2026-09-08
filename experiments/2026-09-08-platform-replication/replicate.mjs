import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const root = fileURLToPath(new URL('.', import.meta.url));
const [kernelArg, label, tempArg] = process.argv.slice(2);
assert.match(label ?? '', /^[a-z0-9-]+$/);
const kernel = resolve(kernelArg), tmp = resolve(tempArg);
mkdirSync(tmp, { recursive: true }); mkdirSync(join(root, 'evidence'), { recursive: true });
const env = { PATH: `${dirname(process.execPath)}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`, TMPDIR: tmp, LANG: 'en_US.UTF-8', TZ: 'UTC', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_TERMINAL_PROMPT: '0' };
const manifest = JSON.parse(readFileSync(join(root, 'REPLICATION-INPUT-MANIFEST.json')));
for (const [name, digest] of Object.entries(manifest.files)) {
  assert.equal('sha256:' + createHash('sha256').update(readFileSync(join(root, name))).digest('hex'), digest, name);
}
function execute(name, args) {
  const log = join(root, 'evidence', `${label}-${name}`); mkdirSync(log);
  const invocation = { argv: [process.execPath, ...args], cwd: kernel, environment: env, startedAt: new Date().toISOString() };
  writeFileSync(join(log, 'invocation.json'), JSON.stringify(invocation, null, 2) + '\n');
  const started = performance.now();
  const run = spawnSync(process.execPath, args, { cwd: kernel, env, encoding: 'utf8', timeout: 45 * 60 * 1000, maxBuffer: 64 * 1024 * 1024 });
  writeFileSync(join(log, 'stdout'), run.stdout ?? ''); writeFileSync(join(log, 'stderr'), run.stderr ?? '');
  writeFileSync(join(log, 'result.json'), JSON.stringify({ exitCode: run.status, signal: run.signal, error: run.error?.message ?? null, seconds: (performance.now() - started) / 1000, completedAt: new Date().toISOString() }, null, 2) + '\n');
  process.stdout.write(run.stdout ?? ''); process.stderr.write(run.stderr ?? '');
  assert.equal(run.status, 0, `${name} failed; retained ${log}`);
}
execute('corpus-command', [join(root, 'harness/run.mjs'), kernel, label]);
const summary = JSON.parse(readFileSync(join(root, 'evidence', label, 'summary.json')));
assert.equal(summary.candidateRuns, 36); assert.equal(summary.receipts, 36); assert.equal(summary.offlineVerified, 36);
assert.deepEqual(summary.dispositionMismatches, []); assert.equal(summary.pairChecks, 54);
assert.equal(summary.pairExecuted, process.platform === 'linux' ? 54 : 36);
assert.equal(summary.pairExceptions, 0); assert.deepEqual(summary.pairMismatches, []);
execute('holdout-command', [join(root, 'harness/holdout.mjs'), kernel, `${label}-holdout`, label]);
const holdout = JSON.parse(readFileSync(join(root, 'evidence', `${label}-holdout`, 'summary.json')));
assert.equal(holdout.checks, 24); assert.equal(holdout.passed, 24); assert.deepEqual(holdout.failed, []);
console.log(JSON.stringify({ platform: process.platform, label, corpus: summary, holdout }, null, 2));
