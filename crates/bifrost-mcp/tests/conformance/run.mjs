#!/usr/bin/env node
// Official MCP conformance gate for Bifrost's stdio MCP server (issue #2319).
//
// What this proves, in one command:
//   1. The four spec JSON schemas committed in schemas/ are byte-identical to a
//      fresh extraction from the pinned conformance bundle (schema drift).
//   2. Every scenario the pinned conformance version lists for server testing is
//      triaged in exactly one state: applicable, inapplicable, or expected
//      failure (inventory drift). A pin bump that adds scenarios fails here
//      until a human classifies them.
//   3. Each triaged-applicable scenario still passes against the real Bifrost
//      binary at every supported revision it applies to, and each triaged
//      expected failure still fails (a pass means the triage is stale).
//   4. (default mode only) The Rust half of the gate, `cargo test -p
//      brokk-bifrost-mcp --test mcp_wire_schema`.
//
// Flags:
//   (none)             full gate: drift checks + Rust wire-schema test +
//                      applicable and expected-failure scenarios
//   --ci               same, minus the Rust test (CI's mcp-contract job already
//                      runs every test target in the crate, including that one)
//   --full             also run the scenarios triaged inapplicable, for a triage
//                      refresh; their results are reported but never gate
//   --check-inventory  drift checks only, no scenario execution
//   --scenario <name>  run one scenario at its applicable revisions, printing
//                      every check; no drift checks, no gating
//   --keep             keep the per-run results directory even on success
//
// Environment:
//   BIFROST_MCP_SERVER_BIN  path to the server binary (default:
//                           $CARGO_TARGET_DIR/debug/bifrost-mcp-test-server,
//                           built on demand if absent)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { compareSchemas, DEFAULT_BUNDLE, HERE } from './extract-schemas.mjs';

const REPO_ROOT = path.resolve(HERE, '..', '..', '..', '..');
const CONFORMANCE_CLI = DEFAULT_BUNDLE;
// The revisions Bifrost negotiates. Scenarios whose bracket tags miss both are
// inapplicable by revision and need no triage entry.
const SUPPORTED_REVISIONS = ['2025-11-25', '2026-07-28'];
const SCENARIO_TIMEOUT_MS = 120_000;
const BRIDGE_READY_TIMEOUT_MS = 20_000;
const CONCURRENCY = 4;

const TRIAGE_FILES = {
  applicable: path.join(HERE, 'scenarios-applicable.json'),
  inapplicable: path.join(HERE, 'scenarios-inapplicable.json'),
  'expected-failure': path.join(HERE, 'scenarios-expected-failures.json'),
};

// ---- argument parsing ------------------------------------------------------

function parseArgs(argv) {
  const options = {
    mode: 'default', // default | ci | full | check-inventory | single
    scenario: null,
    keep: false,
  };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--ci':
        options.mode = 'ci';
        break;
      case '--full':
        options.mode = 'full';
        break;
      case '--check-inventory':
        options.mode = 'check-inventory';
        break;
      case '--scenario':
        options.mode = 'single';
        options.scenario = argv[++i];
        if (!options.scenario) throw new Error('--scenario requires a scenario name');
        break;
      case '--keep':
        options.keep = true;
        break;
      default:
        throw new Error(`unknown argument \`${argv[i]}\``);
    }
  }
  return options;
}

// ---- inventory -------------------------------------------------------------

// `conformance list --server` prints one scenario per line:
//   "  - tools-list [2025-06-18,2025-11-25,2026-07-28]"
//   "  - tasks-lifecycle [extension]"
function listServerScenarios() {
  const result = spawnSync(process.execPath, [CONFORMANCE_CLI, 'list', '--server'], {
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(
      `conformance list --server failed (${result.status}):\n${result.stderr || result.stdout}`,
    );
  }
  const scenarios = [];
  for (const line of result.stdout.split('\n')) {
    const m = line.match(/^\s+-\s+(\S+)\s+\[([^\]]+)\]\s*$/);
    if (m) scenarios.push({ name: m[1], tags: m[2].split(',').map((t) => t.trim()) });
  }
  if (scenarios.length === 0) {
    throw new Error('conformance list --server printed no scenarios; output format changed');
  }
  return scenarios;
}

// Revisions to run a scenario at. `[null]` means "run once with no
// --spec-version" (extension scenarios are not on the spec timeline). An empty
// array means the scenario is inapplicable by revision.
function revisionsFor(scenario) {
  if (scenario.tags.includes('extension')) return [null];
  return SUPPORTED_REVISIONS.filter((r) => scenario.tags.includes(r));
}

function loadTriage() {
  const triage = {};
  for (const [state, file] of Object.entries(TRIAGE_FILES)) {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    triage[state] = raw;
  }
  return triage;
}

function triageNames(triage, state) {
  const raw = triage[state];
  return Array.isArray(raw) ? raw : Object.keys(raw);
}

// Assigns exactly one state to every listed scenario and returns
// { states: Map<name, state>, problems: string[] }.
function checkInventory(scenarios, triage) {
  const problems = [];
  const states = new Map();
  const listed = new Set(scenarios.map((s) => s.name));

  for (const [state, file] of Object.entries(TRIAGE_FILES)) {
    for (const name of triageNames(triage, state)) {
      if (!listed.has(name)) {
        problems.push(
          `${path.basename(file)}: \`${name}\` is not listed by the pinned conformance version; remove or rename it`,
        );
      }
    }
  }

  for (const scenario of scenarios) {
    const revisions = revisionsFor(scenario);
    const entries = Object.keys(TRIAGE_FILES).filter((state) =>
      triageNames(triage, state).includes(scenario.name),
    );
    if (revisions.length === 0) {
      // Auto-triaged: the scenario applies to no revision Bifrost negotiates.
      states.set(scenario.name, 'revision-inapplicable');
      if (entries.length > 0) {
        problems.push(
          `${scenario.name}: inapplicable by revision (tags [${scenario.tags.join(',')}] miss ${SUPPORTED_REVISIONS.join(' and ')}) yet listed in ${entries.join(' and ')}; remove the entry`,
        );
      }
      continue;
    }
    if (entries.length === 0) {
      problems.push(
        `${scenario.name}: untriaged (tags [${scenario.tags.join(',')}]); add it to exactly one of ${Object.values(TRIAGE_FILES).map((f) => path.basename(f)).join(', ')}`,
      );
      continue;
    }
    if (entries.length > 1) {
      problems.push(`${scenario.name}: triaged twice, in ${entries.join(' and ')}`);
      continue;
    }
    states.set(scenario.name, entries[0]);
  }
  return { states, problems };
}

// ---- server binary ---------------------------------------------------------

function serverBinary() {
  const override = process.env.BIFROST_MCP_SERVER_BIN;
  if (override) {
    if (!fs.existsSync(override)) {
      throw new Error(`BIFROST_MCP_SERVER_BIN=${override} does not exist`);
    }
    return override;
  }
  const targetDir = process.env.CARGO_TARGET_DIR || path.join(REPO_ROOT, 'target');
  const binary = path.join(targetDir, 'debug', 'bifrost-mcp-test-server');
  if (fs.existsSync(binary)) return binary;
  console.log(`building ${path.relative(REPO_ROOT, binary)} ...`);
  const build = spawnSync(
    'cargo',
    ['build', '-p', 'brokk-bifrost-mcp', '--bin', 'bifrost-mcp-test-server'],
    { cwd: REPO_ROOT, stdio: 'inherit' },
  );
  if (build.status !== 0) throw new Error('cargo build of bifrost-mcp-test-server failed');
  if (!fs.existsSync(binary)) throw new Error(`cargo build succeeded but ${binary} is missing`);
  return binary;
}

// ---- fixture workspace -----------------------------------------------------

// A small multi-language workspace so search and resource tools return real
// content instead of empty results.
const FIXTURE_FILES = {
  'src/greeter.py': `"""Greeting helpers used by the conformance fixture workspace."""


def greet(name: str) -> str:
    """Return a greeting for name."""
    return f"Hello, {name}!"


def farewell(name: str) -> str:
    return f"Goodbye, {name}."
`,
  'src/counter.rs': `/// A counter used by the conformance fixture workspace.
pub struct Counter {
    pub value: u32,
}

impl Counter {
    pub fn new() -> Self {
        Counter { value: 0 }
    }

    pub fn bump(&mut self) {
        self.value += 1;
    }
}

pub fn greet(name: &str) -> String {
    format!("Hello, {name}!")
}
`,
  'README.md': `# Conformance fixture workspace

Two source files (Python and Rust) so Bifrost's search and resource tools have
real content to return while the official conformance scenarios run.
`,
};

function createWorkspace(rootDir) {
  for (const [relative, contents] of Object.entries(FIXTURE_FILES)) {
    const file = path.join(rootDir, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  }
}

// ---- scenario execution ----------------------------------------------------

function startBridge(binary, workspaceRoot) {
  const child = spawn(
    process.execPath,
    [
      path.join(HERE, 'bridge.mjs'),
      '0',
      binary,
      '--root',
      workspaceRoot,
      '--mcp',
      'searchtools',
      '--force-semantic-cpu',
    ],
    {
      cwd: HERE,
      env: { ...process.env, BIFROST_SEMANTIC_INDEX: 'off' },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => (stdout += d.toString('utf8')));
  child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
  const port = new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`bridge did not report a port within ${BRIDGE_READY_TIMEOUT_MS}ms`)),
      BRIDGE_READY_TIMEOUT_MS,
    );
    const poll = setInterval(() => {
      const m = stdout.match(/^BRIDGE_LISTENING (\d+)$/m);
      if (m) {
        clearInterval(poll);
        clearTimeout(timer);
        resolve(Number(m[1]));
      }
    }, 20);
    child.on('exit', (code) => {
      clearInterval(poll);
      clearTimeout(timer);
      reject(new Error(`bridge exited with code ${code} before listening:\n${stderr}`));
    });
  });
  return { child, port, log: () => ({ stdout, stderr }) };
}

function stopBridge(bridge) {
  return new Promise((resolve) => {
    if (bridge.child.exitCode !== null || bridge.child.signalCode !== null) {
      resolve();
      return;
    }
    const done = setTimeout(() => {
      bridge.child.kill('SIGKILL');
      resolve();
    }, 4000);
    bridge.child.once('exit', () => {
      clearTimeout(done);
      resolve();
    });
    bridge.child.kill('SIGTERM');
  });
}

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CONFORMANCE_CLI, ...args], {
      cwd: HERE,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, SCENARIO_TIMEOUT_MS);
    let timedOut = false;
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ exitCode: code, signal, stdout, stderr, timedOut });
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ exitCode: null, signal: null, stdout, stderr: `${stderr}\n${err.message}`, timedOut });
    });
  });
}

// The CLI writes <resultsDir>/server-<scenario>-<timestamp>/checks.json.
function readChecks(resultsDir) {
  if (!fs.existsSync(resultsDir)) return null;
  for (const entry of fs.readdirSync(resultsDir)) {
    const file = path.join(resultsDir, entry, 'checks.json');
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  }
  return null;
}

async function runScenario(job, binary, runDir) {
  const label = job.revision ? `${job.name}@${job.revision}` : `${job.name}@extension`;
  const slug = label.replace(/[^A-Za-z0-9.@-]/g, '_');
  const workspaceRoot = path.join(runDir, 'workspaces', slug);
  const resultsDir = path.join(runDir, 'results', slug);
  fs.mkdirSync(workspaceRoot, { recursive: true });
  fs.mkdirSync(resultsDir, { recursive: true });
  createWorkspace(workspaceRoot);

  let bridge = null;
  try {
    bridge = startBridge(binary, workspaceRoot);
    const port = await bridge.port;
    const args = [
      'server',
      '--url',
      `http://127.0.0.1:${port}/mcp`,
      '--scenario',
      job.name,
      '-o',
      resultsDir,
    ];
    if (job.revision) args.push('--spec-version', job.revision);
    const cli = await runCli(args);
    const checks = readChecks(resultsDir);
    const failedChecks = (checks ?? []).filter((c) => c.status === 'FAILURE');
    const passedChecks = (checks ?? []).filter((c) => c.status === 'SUCCESS');
    // The official aggregator counts only SUCCESS and FAILURE towards a
    // scenario's verdict, so a run with neither judged nothing. That happens
    // when the CLI refuses the requested revision, and when a scenario decides
    // at run time that it cannot be exercised at all (it emits one SKIPPED
    // check). Neither outcome is a pass.
    const skipped = failedChecks.length === 0 && passedChecks.length === 0;
    return {
      ...job,
      label,
      resultsDir,
      exitCode: cli.exitCode,
      timedOut: cli.timedOut,
      skipped,
      checks: checks ?? [],
      failedChecks,
      passedChecks,
      passed: !skipped && cli.exitCode === 0 && failedChecks.length === 0,
      cliStdout: cli.stdout,
      cliStderr: cli.stderr,
      bridgeStderr: bridge.log().stderr,
    };
  } catch (err) {
    return {
      ...job,
      label,
      resultsDir,
      exitCode: null,
      timedOut: false,
      skipped: false,
      checks: [],
      failedChecks: [],
      passedChecks: [],
      passed: false,
      cliStdout: '',
      cliStderr: err.message,
      bridgeStderr: bridge ? bridge.log().stderr : '',
    };
  } finally {
    if (bridge) await stopBridge(bridge);
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  }
}

async function runAll(jobs, binary, runDir) {
  const results = [];
  let next = 0;
  const workers = Array.from({ length: Math.min(CONCURRENCY, jobs.length) }, async () => {
    while (true) {
      const index = next++;
      if (index >= jobs.length) return;
      const job = jobs[index];
      const result = await runScenario(job, binary, runDir);
      results[index] = result;
      const mark = result.passed ? 'pass' : result.skipped ? 'skip' : 'FAIL';
      console.log(`  [${mark}] ${result.label} (${result.state})`);
    }
  });
  await Promise.all(workers);
  return results;
}

// ---- Rust half -------------------------------------------------------------

function runRustGate() {
  console.log('running cargo test -p brokk-bifrost-mcp --test mcp_wire_schema ...');
  const result = spawnSync(
    'cargo',
    ['test', '-p', 'brokk-bifrost-mcp', '--test', 'mcp_wire_schema'],
    { cwd: REPO_ROOT, stdio: 'inherit' },
  );
  return result.status === 0;
}

// ---- reporting -------------------------------------------------------------

function printTable(rows) {
  const header = ['SCENARIO', 'REVISION', 'STATE', 'RESULT', 'CHECKS'];
  const widths = header.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => String(r[i]).length), 0),
  );
  const line = (cells) => cells.map((c, i) => String(c).padEnd(widths[i])).join('  ').trimEnd();
  console.log(line(header));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const row of rows) console.log(line(row));
}

function verdict(state, result) {
  if (result.skipped) {
    // An applicable scenario that judges nothing is lost coverage, so it gates.
    return state === 'applicable'
      ? { text: 'SKIPPED (no checks)', gateFailure: true }
      : { text: 'skipped', gateFailure: false };
  }
  switch (state) {
    case 'applicable':
      return result.passed
        ? { text: 'pass', gateFailure: false }
        : { text: 'FAIL (regression)', gateFailure: true };
    case 'expected-failure':
      return result.passed
        ? { text: 'PASS (stale triage)', gateFailure: true }
        : { text: 'fail (expected)', gateFailure: false };
    case 'inapplicable':
      return result.passed
        ? { text: 'pass (not gating)', gateFailure: false }
        : { text: 'fail (not gating)', gateFailure: false };
    default:
      throw new Error(`unreachable state ${state}`);
  }
}

// ---- main ------------------------------------------------------------------

async function main(argv) {
  const options = parseArgs(argv);
  let failed = false;

  const scenarios = listServerScenarios();
  const triage = loadTriage();
  const { states, problems } = checkInventory(scenarios, triage);

  if (options.mode !== 'single') {
    const schemaProblems = compareSchemas();
    if (schemaProblems.length > 0) {
      console.error('SCHEMA DRIFT against the pinned conformance bundle:');
      for (const p of schemaProblems) console.error(`  ${p}`);
      console.error('  fix: node extract-schemas.mjs --write (only if the pin bump is deliberate)');
      failed = true;
    } else {
      console.log(`schema drift check: 4 schemas match the pinned conformance bundle`);
    }

    if (problems.length > 0) {
      console.error('INVENTORY DRIFT:');
      for (const p of problems) console.error(`  ${p}`);
      failed = true;
    } else {
      const counts = {};
      for (const state of states.values()) counts[state] = (counts[state] ?? 0) + 1;
      console.log(
        `inventory check: ${scenarios.length} scenarios triaged (` +
          Object.entries(counts)
            .sort()
            .map(([k, v]) => `${v} ${k}`)
            .join(', ') +
          ')',
      );
    }
  }

  if (options.mode === 'check-inventory') return failed ? 1 : 0;
  if (failed) {
    console.error('\ndrift checks failed; not running scenarios');
    return 1;
  }

  if (options.mode === 'default') {
    if (!runRustGate()) {
      console.error('Rust wire-schema gate failed (or the test target does not exist)');
      failed = true;
    }
  } else if (options.mode === 'ci') {
    console.log(
      'skipping cargo test -p brokk-bifrost-mcp --test mcp_wire_schema: the mcp-contract CI job already runs every test target in the crate',
    );
  }

  // Build the job list.
  let jobs = [];
  if (options.mode === 'single') {
    const scenario = scenarios.find((s) => s.name === options.scenario);
    if (!scenario) {
      console.error(`unknown scenario \`${options.scenario}\`; see conformance list --server`);
      return 1;
    }
    const revisions = revisionsFor(scenario);
    if (revisions.length === 0) {
      console.error(
        `${scenario.name} applies to [${scenario.tags.join(',')}], none of which Bifrost negotiates`,
      );
      return 1;
    }
    jobs = revisions.map((revision) => ({
      name: scenario.name,
      revision,
      state: states.get(scenario.name) ?? 'applicable',
    }));
  } else {
    const runStates =
      options.mode === 'full'
        ? ['applicable', 'expected-failure', 'inapplicable']
        : ['applicable', 'expected-failure'];
    for (const scenario of scenarios) {
      const state = states.get(scenario.name);
      if (!runStates.includes(state)) continue;
      for (const revision of revisionsFor(scenario)) {
        jobs.push({ name: scenario.name, revision, state });
      }
    }
  }

  const binary = serverBinary();
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bifrost-conformance-'));
  console.log(
    `\nrunning ${jobs.length} (scenario, revision) pairs against ${binary}\n` +
      `results under ${runDir}`,
  );
  const results = await runAll(jobs, binary, runDir);

  if (options.mode === 'single') {
    for (const result of results) {
      console.log(`\n=== ${result.label} ===`);
      for (const check of result.checks) {
        console.log(`  [${check.id}] ${check.status} ${check.description}`);
        if (check.errorMessage) console.log(`      ${check.errorMessage.split('\n').join('\n      ')}`);
      }
      if (result.checks.length === 0) {
        console.log(`  no checks recorded (exit ${result.exitCode})`);
        console.log(result.cliStdout.trimEnd());
        console.log(result.cliStderr.trimEnd());
      }
    }
    console.log(`\nresults kept under ${runDir}`);
    return results.every((r) => r.passed) ? 0 : 1;
  }

  // Aggregate.
  const rows = [];
  const gateFailures = [];
  for (const result of results) {
    const v = verdict(result.state, result);
    if (v.gateFailure) gateFailures.push(result);
    rows.push([
      result.name,
      result.revision ?? '(extension)',
      result.state,
      v.text,
      `${result.passedChecks.length}/${result.passedChecks.length + result.failedChecks.length}`,
    ]);
  }
  for (const scenario of scenarios) {
    if (states.get(scenario.name) === 'revision-inapplicable') {
      rows.push([
        scenario.name,
        `[${scenario.tags.join(',')}]`,
        'revision-inapplicable',
        'not run',
        '-',
      ]);
    }
  }

  console.log('');
  printTable(rows);

  for (const result of gateFailures) {
    console.log(`\nGATE FAILURE: ${result.label} (${result.state})`);
    if (result.timedOut) console.log(`  timed out after ${SCENARIO_TIMEOUT_MS}ms`);
    for (const check of result.failedChecks) {
      console.log(`  [${check.id}] ${check.description}`);
      if (check.errorMessage) console.log(`      ${check.errorMessage.split('\n').join('\n      ')}`);
    }
    if (result.checks.length === 0) {
      console.log(`  no checks recorded (exit ${result.exitCode})`);
      console.log(`  cli stdout: ${result.cliStdout.trim().split('\n').slice(-8).join('\n  ')}`);
      console.log(`  cli stderr: ${result.cliStderr.trim().split('\n').slice(-8).join('\n  ')}`);
    }
    console.log(`  results: ${result.resultsDir}`);
  }

  for (const result of results) {
    if (result.state === 'expected-failure' && !result.passed && !result.skipped) {
      const all = [...new Set(result.failedChecks.map((c) => c.id))];
      const shown = all.slice(0, 5).join(', ');
      const rest = all.length > 5 ? ` (+${all.length - 5} more failing check ids)` : '';
      console.log(`expected failure confirmed: ${result.label} -> ${shown || '(no checks)'}${rest}`);
    }
  }

  const totals = {
    pass: results.filter((r) => r.passed && r.state === 'applicable').length,
    expected: results.filter((r) => !r.passed && r.state === 'expected-failure').length,
    gateFailures: gateFailures.length,
    notGating: results.filter((r) => r.state === 'inapplicable').length,
    skipped: results.filter((r) => r.skipped).length,
  };
  console.log(
    `\ntotals: ${totals.pass} applicable pass, ${totals.expected} expected failures confirmed, ` +
      `${totals.notGating} inapplicable (not gating), ${totals.skipped} skipped, ` +
      `${totals.gateFailures} gate failures`,
  );

  if (gateFailures.length > 0) failed = true;
  if (failed || options.keep) {
    console.log(`results kept under ${runDir}`);
  } else {
    fs.rmSync(runDir, { recursive: true, force: true });
  }
  return failed ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(err.stack ?? String(err));
      process.exit(1);
    },
  );
}
