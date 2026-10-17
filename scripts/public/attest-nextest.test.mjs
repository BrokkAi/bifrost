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
      fs.writeFileSync(output + '/execution.started', 'started');
      fs.writeFileSync(output + '/native-exit.json', JSON.stringify({ exit_code: 0 }));
      process.exit(125);
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
