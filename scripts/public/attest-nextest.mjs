#!/usr/bin/env node
// Transitional shadow integration. Keep the original command as the fallback.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const [suite, separator, ...native] = process.argv.slice(2);
if (!suite || separator !== '--' || native[0] !== 'cargo' || native[1] !== 'nextest' || native[2] !== 'run') {
  console.error('usage: attest-nextest.mjs SUITE -- cargo nextest run ...');
  process.exit(2);
}
function finish(result) {
  if (result.error) { console.error(result.error.message); process.exit(127); }
  if (result.signal) { process.kill(process.pid, result.signal); }
  process.exit(result.status ?? 125);
}
function fallback(reason) {
  console.error(`Attest shadow unavailable (${reason}); running the original nextest command.`);
  finish(spawnSync(native[0], native.slice(1), { stdio: 'inherit' }));
}
const binary = process.env.ATTEST_BIN || 'attest';
const version = spawnSync(binary, ['version'], { encoding: 'utf8' });
if (version.status !== 0 || !existsSync('attest.toml')) fallback('tool or configuration missing');
const described = spawnSync(binary, ['describe', suite], { encoding: 'utf8' });
let expected;
try { expected = JSON.parse(described.stdout); } catch { fallback('suite inspection failed'); }
const build = [], run = []; let filter = '', profile = 'default', ignored = 'default';
for (let i = 3; i < native.length; i++) {
  const arg = native[i];
  if (arg === '-E') filter = native[++i];
  else if (['--max-fail', '--success-output', '--failure-output', '--show-progress', '--color'].includes(arg)) run.push(arg, native[++i]);
  else if (arg === '--no-output-indent') run.push(arg);
  else if (arg === '--profile' || arg === '-P') profile = native[++i];
  else if (arg === '--run-ignored') ignored = native[++i];
  else build.push(arg);
}
if (JSON.stringify(build) !== JSON.stringify(expected.BuildArgs || []) ||
    JSON.stringify(run) !== JSON.stringify(expected.RunArgs || []) ||
    filter !== expected.Filter || profile !== expected.Profile || ignored !== expected.RunIgnored ||
    (process.env.NEXTEST_PROFILE && process.env.NEXTEST_PROFILE !== expected.Profile)) fallback('suite differs from native CI selection');
for (const [key, value] of Object.entries(expected.Environment || {})) {
  if (key in process.env && process.env[key] !== value) fallback(`environment differs: ${key}`);
}
const git = spawnSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], { encoding: 'utf8' });
if (git.status !== 0) fallback('Git metadata unavailable');
const root = join(git.stdout.trim(), 'attest');
mkdirSync(root, { recursive: true });
const output = mkdtempSync(join(root, 'ci-'));
const result = spawnSync(binary, ['run', suite, '--shadow', '--no-publish', '--output', output], { stdio: 'inherit' });
const nativeExit = join(output, 'native-exit.json');
if (existsSync(nativeExit)) {
  // Observer failures must not change the actual test command's result.
  const { exit_code: code } = JSON.parse(readFileSync(nativeExit, 'utf8'));
  if (result.status !== code) console.error('Attest observer failed; preserving the native nextest result.');
  process.exit(code);
}
if (!existsSync(join(output, 'execution.started'))) fallback('preflight or discovery failed');
finish(result);
