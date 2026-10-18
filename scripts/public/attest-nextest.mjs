#!/usr/bin/env node
// Keep native fallback before execution; live reuse requires complete evidence.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const [suite, separator, ...native] = process.argv.slice(2);
if (!suite || separator !== '--' || native[0] !== 'cargo' || native[1] !== 'nextest' || native[2] !== 'run') {
  console.error('usage: attest-nextest.mjs SUITE -- cargo nextest run ...');
  process.exit(2);
}
const mode = process.env.ATTEST_MODE ?? 'shadow';
if (!['shadow', 'reuse', 'force'].includes(mode)) {
  console.error('ATTEST_MODE must be shadow, reuse, or force.');
  process.exit(2);
}
const testEnvironment = {
  ...process.env,
  ATTEST_MODE: mode,
  BIFROST_OPEN_PACKS_DISABLE: process.env.BIFROST_OPEN_PACKS_DISABLE ?? '1',
};
function finish(result) {
  if (result.error) { console.error(result.error.message); process.exit(127); }
  if (result.signal) { process.kill(process.pid, result.signal); }
  process.exit(result.status ?? 125);
}
function fallback(reason) {
  console.error(`Attest unavailable (${reason}); running the original nextest command.`);
  finish(spawnSync(native[0], native.slice(1), { stdio: 'inherit', env: testEnvironment }));
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
  else if (arg === '--max-fail') run.push(arg, native[++i]);
  else if (arg === '--profile' || arg === '-P') profile = native[++i];
  else if (arg === '--run-ignored') ignored = native[++i];
  else build.push(arg);
}
if (JSON.stringify(build) !== JSON.stringify(expected.BuildArgs || []) ||
    JSON.stringify(run) !== JSON.stringify(expected.RunArgs || []) ||
    filter !== expected.Filter || profile !== expected.Profile || ignored !== expected.RunIgnored ||
    (process.env.NEXTEST_PROFILE && process.env.NEXTEST_PROFILE !== expected.Profile)) fallback('suite differs from native CI selection');
for (const [key, value] of Object.entries(expected.Environment || {})) {
  if (key in testEnvironment && testEnvironment[key] !== value) fallback(`environment differs: ${key}`);
}
const git = spawnSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], { encoding: 'utf8' });
if (git.status !== 0) fallback('Git metadata unavailable');
const root = join(git.stdout.trim(), 'attest');
mkdirSync(root, { recursive: true });
const output = mkdtempSync(join(root, 'ci-'));
const result = spawnSync(binary, ['run', suite, '--no-publish', '--output', output], { stdio: 'inherit', env: testEnvironment });
const nativeExit = join(output, 'native-exit.json');
if (mode === 'shadow' && existsSync(nativeExit)) {
  // Observer failures must not change the actual test command's result.
  const { exit_code: code } = JSON.parse(readFileSync(nativeExit, 'utf8'));
  if (result.status !== code) console.error('Attest observer failed; preserving the native nextest result.');
  process.exit(code);
}
const receipt = join(output, 'result.json');
// A fully cached run has a receipt but never starts the native runner.
if (!existsSync(join(output, 'execution.started')) && !existsSync(receipt)) fallback('preflight or discovery failed');
if (mode !== 'shadow' && result.status === 0) {
  let bundle;
  try { bundle = JSON.parse(readFileSync(receipt, 'utf8')); } catch { /* Fail closed below. */ }
  if (bundle?.complete !== true || bundle.mode !== mode || bundle.suite !== suite || bundle.exit_code !== 0) {
    console.error('Attest did not produce complete test coverage; failing CI without rerunning tests.');
    process.exit(125);
  }
}
finish(result);
