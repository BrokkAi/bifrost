import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const script = new URL('./attest-nextest.mjs', import.meta.url).pathname;
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'attest-wrapper-'));
  const bin = join(root, 'bin'); mkdirSync(bin);
  const executable = (name, source) => writeFileSync(join(bin, name), '#!/usr/bin/env node\n' + source, { mode: 0o755 });
  executable('cargo', "process.exit(7);");
  return { root, bin, executable, env: { ...process.env, PATH: bin + ':' + process.env.PATH } };
}
test('missing observer preserves native failure', () => {
  const f = fixture(); f.env.ATTEST_BIN = join(f.root, 'absent');
  const result = spawnSync(process.execPath, [script, 'unit', '--', 'cargo', 'nextest', 'run'], { cwd: f.root, env: f.env });
  assert.equal(result.status, 7);
});
test('collector failure preserves successful native tests without rerunning', () => {
  const f = fixture();
  spawnSync('git', ['init', '-q'], { cwd: f.root });
  writeFileSync(join(f.root, 'attest.toml'), 'version=1');
  f.executable('attest', "if(process.argv[2]==='version')process.exit(0);if(process.argv[2]==='describe'){require('node:fs').writeSync(1,JSON.stringify({BuildArgs:[],RunArgs:[],Filter:'',Profile:'default',RunIgnored:'default'}));process.exit(0);}const fs=require('node:fs');const o=process.argv[process.argv.indexOf('--output')+1];fs.writeFileSync(o+'/execution.started','started');fs.writeFileSync(o+'/native-exit.json',JSON.stringify({exit_code:0}));process.exit(125);");
  f.env.ATTEST_BIN = join(f.bin, 'attest');
  const result = spawnSync(process.execPath, [script, 'unit', '--', 'cargo', 'nextest', 'run'], { cwd: f.root, env: f.env });
  assert.equal(result.status, 0, JSON.stringify({stderr: result.stderr.toString(),stdout:result.stdout.toString()}));
});

const loaderBuild = ['--locked', '-p', 'brokk-bifrost-semantic-packs', '--target', 'x86_64-unknown-linux-gnu', '--features', 'download'];
const loaderRun = ['--max-fail', '100', '--success-output', 'immediate', '--failure-output', 'immediate', '--no-output-indent', '--show-progress', 'none', '--color', 'never'];

function loaderObserverFixture() {
  const f = fixture();
  assert.equal(spawnSync('git', ['init', '-q'], {cwd: f.root}).status, 0);
  writeFileSync(join(f.root, 'attest.toml'), 'version=1');
  writeFileSync(join(f.root, 'suite.json'), JSON.stringify({BuildArgs: loaderBuild, RunArgs: loaderRun,
    Filter: '', Profile: 'default', RunIgnored: 'default'}));
  f.executable('cargo', `const fs=require('node:fs');
fs.appendFileSync('native-count','run\\n');
fs.writeFileSync('native-argv.json',JSON.stringify(process.argv.slice(2)));
process.stdout.write('BIFROST_LOADER_CONFORMANCE_V1={"case_id":"fixture"}\\n');
process.exit(Number(process.env.FIXTURE_NATIVE_EXIT||0));`);
  f.executable('attest', `const fs=require('node:fs');
if(process.argv[2]==='version')process.exit(0);
const suite=JSON.parse(fs.readFileSync('suite.json','utf8'));
if(process.argv[2]==='describe'){process.stdout.write(JSON.stringify(suite));process.exit(0);}
fs.writeFileSync('observer-ran','yes');
const output=process.argv[process.argv.indexOf('--output')+1];
fs.writeFileSync(output+'/execution.started','started');
const child=require('node:child_process').spawnSync('cargo',['nextest','run',...suite.BuildArgs,...suite.RunArgs],{stdio:'inherit'});
if(child.error)throw child.error;
fs.writeFileSync(output+'/native-exit.json',JSON.stringify({exit_code:child.status}));
process.exit(125);`);
  f.env.ATTEST_BIN = join(f.bin, 'attest');
  f.env.NEXTEST_PROFILE = 'default';
  return f;
}

test('loader output controls are run arguments and one observed native execution retains raw stdout and exit', () => {
  for (const exitCode of [0, 7]) {
    const f = loaderObserverFixture();
    const result = spawnSync(process.execPath, [script, 'semantic-pack-tests', '--', 'cargo', 'nextest', 'run',
      ...loaderBuild, ...loaderRun], {cwd: f.root, env: {...f.env, FIXTURE_NATIVE_EXIT: String(exitCode)}});
    assert.equal(result.status, exitCode, result.stderr.toString());
    assert.equal(readFileSync(join(f.root, 'native-count'), 'utf8'), 'run\n');
    assert.equal(readFileSync(join(f.root, 'observer-ran'), 'utf8'), 'yes');
    assert.deepEqual(JSON.parse(readFileSync(join(f.root, 'native-argv.json'))), ['nextest', 'run', ...loaderBuild, ...loaderRun]);
    assert.equal(result.stdout.toString(), 'BIFROST_LOADER_CONFORMANCE_V1={"case_id":"fixture"}\n');
  }
});

test('unrepresented loader feature or output selection falls back honestly without an observed execution or rerun', () => {
  for (const args of [loaderBuild.slice(0, -2).concat(loaderRun), loaderBuild.concat(loaderRun.filter((_, i) => i !== 2 && i !== 3))]) {
    const f = loaderObserverFixture();
    const result = spawnSync(process.execPath, [script, 'semantic-pack-tests', '--', 'cargo', 'nextest', 'run', ...args],
      {cwd: f.root, env: f.env});
    assert.equal(result.status, 0, result.stderr.toString());
    assert.match(result.stderr.toString(), /suite differs from native CI selection/);
    assert.equal(existsSync(join(f.root, 'observer-ran')), false);
    assert.equal(readFileSync(join(f.root, 'native-count'), 'utf8'), 'run\n');
    assert.deepEqual(JSON.parse(readFileSync(join(f.root, 'native-argv.json'))), ['nextest', 'run', ...args]);
  }
});

test('the actual semantic suite describes the fixed loader build and output arguments separately', () => {
  const config = new URL('../../attest.toml', import.meta.url).pathname;
  const result = spawnSync('python3', ['-c',
    'import json,sys,tomllib; print(json.dumps(tomllib.load(open(sys.argv[1], "rb"))["suites"]["semantic-pack-tests"]))', config]);
  assert.equal(result.status, 0, result.stderr.toString());
  const suite = JSON.parse(result.stdout);
  assert.deepEqual(suite.build_args, loaderBuild);
  assert.deepEqual(suite.run_args, loaderRun);
  assert.equal(suite.profile, 'default');
  assert.equal(suite.filter, '');
});
