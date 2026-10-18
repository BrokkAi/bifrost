import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const script = new URL('./attest-nextest.mjs', import.meta.url).pathname;
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'attest-wrapper-'));
  const bin = join(root, 'bin'); mkdirSync(bin);
  const executable = (name, source) => writeFileSync(join(bin, name), '#!/usr/bin/env node\n' + source, { mode: 0o755 });
  executable('cargo', `
    const fs = require('node:fs');
    if (process.env.FAKE_CARGO_ENV) fs.writeFileSync(process.env.FAKE_CARGO_ENV, process.env.BIFROST_OPEN_PACKS_DISABLE ?? '<unset>');
    process.exit(7);
  `);
  return { root, bin, executable, env: { ...process.env, PATH: bin + ':' + process.env.PATH } };
}
function run(f) {
  return spawnSync(process.execPath, [script, 'unit', '--', 'cargo', 'nextest', 'run'], { cwd: f.root, env: f.env });
}
function installAttest(f) {
  f.executable('attest', `
    const fs = require('node:fs');
    if (process.argv[2] === 'version') process.exit(0);
    if (process.argv[2] === 'describe') {
      process.stdout.write(JSON.stringify({
        BuildArgs: [], RunArgs: [], Filter: '', Profile: 'default', RunIgnored: 'default',
        Environment: { BIFROST_OPEN_PACKS_DISABLE: '1' },
      }));
      process.exit(0);
    }
    if (process.argv[2] === 'run') {
      if (process.env.ATTEST_ENV_LOG) fs.writeFileSync(process.env.ATTEST_ENV_LOG, process.env.BIFROST_OPEN_PACKS_DISABLE ?? '<unset>');
      const output = process.argv[process.argv.indexOf('--output') + 1];
      if (process.env.FAKE_PREFLIGHT_FAILURE) process.exit(125);
      if (process.env.FAKE_COMPLETE_REUSE) {
        fs.writeFileSync(output + '/result.json', JSON.stringify({
          complete: true, mode: process.env.ATTEST_MODE, suite: 'unit', exit_code: 0,
        }));
        process.exit(0);
      }
      fs.writeFileSync(output + '/execution.started', 'started');
      fs.writeFileSync(output + '/native-exit.json', JSON.stringify({ exit_code: Number(process.env.FAKE_NATIVE_EXIT ?? 0) }));
      if (process.env.FAKE_RECEIPT) fs.writeFileSync(output + '/result.json', process.env.FAKE_RECEIPT);
      process.exit(Number(process.env.FAKE_ATTEST_EXIT ?? 125));
    }
    process.exit(2);
  `);
  f.env.ATTEST_BIN = join(f.bin, 'attest');
}

test('missing observer preserves native failure and defaults only an unset test variable', () => {
  const f = fixture();
  f.env.ATTEST_BIN = join(f.root, 'absent');
  delete f.env.BIFROST_OPEN_PACKS_DISABLE;
  const envLog = join(f.root, 'cargo-env');
  f.env.FAKE_CARGO_ENV = envLog;
  const result = run(f);
  assert.equal(result.status, 7);
  assert.equal(readFileSync(envLog, 'utf8'), '1');
});

test('Attest receives the same unset-only default as the native test command', () => {
  const f = fixture();
  installAttest(f);
  spawnSync('git', ['init', '-q'], { cwd: f.root });
  writeFileSync(join(f.root, 'attest.toml'), 'version=1');
  delete f.env.BIFROST_OPEN_PACKS_DISABLE;
  const envLog = join(f.root, 'attest-env');
  f.env.ATTEST_ENV_LOG = envLog;
  const result = run(f);
  assert.equal(result.status, 0, JSON.stringify({ stderr: result.stderr.toString(), stdout: result.stdout.toString() }));
  assert.equal(readFileSync(envLog, 'utf8'), '1');
});

test('explicit zero and empty values are preserved and select native fallback on manifest mismatch', () => {
  for (const value of ['0', '']) {
    const f = fixture();
    installAttest(f);
    spawnSync('git', ['init', '-q'], { cwd: f.root });
    writeFileSync(join(f.root, 'attest.toml'), 'version=1');
    f.env.BIFROST_OPEN_PACKS_DISABLE = value;
    const envLog = join(f.root, 'cargo-env');
    const attestRunLog = join(f.root, 'attest-run');
    f.env.FAKE_CARGO_ENV = envLog;
    f.env.ATTEST_ENV_LOG = attestRunLog;
    const result = run(f);
    assert.equal(result.status, 7, `value=${JSON.stringify(value)}: ${result.stderr.toString()}`);
    assert.equal(readFileSync(envLog, 'utf8'), value);
    assert.equal(existsSync(attestRunLog), false, 'environment mismatch must select fallback before Attest run');
  }
});

test('live reuse accepts all-cache-hit coverage without native execution or fallback', () => {
  const f = fixture();
  installAttest(f);
  spawnSync('git', ['init', '-q'], { cwd: f.root });
  writeFileSync(join(f.root, 'attest.toml'), 'version=1');
  f.env.ATTEST_MODE = 'reuse';
  f.env.FAKE_COMPLETE_REUSE = '1';
  f.env.FAKE_CARGO_ENV = join(f.root, 'native-ran');
  const result = run(f);
  assert.equal(result.status, 0, result.stderr.toString());
  assert.equal(existsSync(f.env.FAKE_CARGO_ENV), false, 'all cached tests must not fall back to native execution');
});

test('live and force modes retain failures and require complete receipts without rerunning tests', () => {
  const complete = { complete: true, mode: 'reuse', suite: 'unit', exit_code: 0 };
  for (const scenario of [
    { name: 'incomplete collection despite a native pass', native: 0, attest: 125, status: 125 },
    { name: 'native test failure', native: 7, attest: 7, status: 7 },
    { name: 'missing receipt after execution', attest: 0, status: 125 },
    { name: 'malformed receipt', attest: 0, receipt: '{', status: 125 },
    ...[
      { complete: false }, { mode: 'shadow' }, { suite: 'different' }, { exit_code: 7 },
    ].map((change) => ({ name: JSON.stringify(change), attest: 0, receipt: JSON.stringify({ ...complete, ...change }), status: 125 })),
    { name: 'complete live execution', attest: 0, receipt: JSON.stringify(complete), status: 0 },
    { name: 'force mode also fails incomplete collection', mode: 'force', native: 0, attest: 125, status: 125 },
  ]) {
    const f = fixture();
    installAttest(f);
    spawnSync('git', ['init', '-q'], { cwd: f.root });
    writeFileSync(join(f.root, 'attest.toml'), 'version=1');
    f.env.ATTEST_MODE = scenario.mode ?? 'reuse';
    f.env.FAKE_NATIVE_EXIT = String(scenario.native ?? 0);
    f.env.FAKE_ATTEST_EXIT = String(scenario.attest);
    if (scenario.receipt) f.env.FAKE_RECEIPT = scenario.receipt;
    f.env.FAKE_CARGO_ENV = join(f.root, 'native-ran');
    const result = run(f);
    assert.equal(result.status, scenario.status, `${scenario.name}: ${result.stderr.toString()}`);
    assert.equal(existsSync(f.env.FAKE_CARGO_ENV), false, scenario.name + ': no native rerun after execution');
  }
});

test('live preflight failure falls back to the original command before any test execution', () => {
  const f = fixture();
  installAttest(f);
  spawnSync('git', ['init', '-q'], { cwd: f.root });
  writeFileSync(join(f.root, 'attest.toml'), 'version=1');
  f.env.ATTEST_MODE = 'reuse';
  f.env.FAKE_PREFLIGHT_FAILURE = '1';
  f.env.FAKE_CARGO_ENV = join(f.root, 'native-ran');
  const result = run(f);
  assert.equal(result.status, 7, result.stderr.toString());
  assert.equal(readFileSync(f.env.FAKE_CARGO_ENV, 'utf8'), '1');
});
