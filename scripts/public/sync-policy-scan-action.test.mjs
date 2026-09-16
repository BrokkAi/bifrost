// Tests for the policy-scan alias sync.
//
// This script had no tests, and shipped v0.10.5 with a README telling readers
// to pin @v0.10.4 -- the front page of the Marketplace listing. It already
// carried a POLICY_SCAN_ALIAS_URL hook documented as the thing local tests
// would point at a file:// bare repository; nothing ever did.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("sync-policy-scan-action.sh", import.meta.url));

const ACTION = `name: Bifrost Policy Scan
description: Run Bifrost static-analysis policies.

branding:
  icon: shield
  color: purple

inputs:
  version:
    description: Bifrost release tag to install.
    required: false
    default: v0.10.4

runs:
  using: composite
  steps: []
`;

const README = `# Bifrost Policy Scan

## Quick start

\`\`\`yaml
      - uses: BrokkAi/bifrost-policy-scan@v0
\`\`\`

## Versioning

Pin an exact tag when a gate has to stay reproducible:

\`\`\`yaml
      - uses: BrokkAi/bifrost-policy-scan@v0.10.4
\`\`\`
`;

function git(args, cwd) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "Test",
      GIT_AUTHOR_EMAIL: "test@example.com",
      GIT_COMMITTER_NAME: "Test",
      GIT_COMMITTER_EMAIL: "test@example.com",
    },
  });
}

function withFixture(body, { action = ACTION, readme = README } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-policy-scan-sync."));
  try {
    // A release checkout: only the three files the script reads.
    const checkout = path.join(dir, "checkout");
    fs.mkdirSync(path.join(checkout, ".github/actions/policy-scan"), { recursive: true });
    fs.mkdirSync(path.join(checkout, "packaging/policy-scan-action"), { recursive: true });
    fs.writeFileSync(path.join(checkout, ".github/actions/policy-scan/action.yml"), action);
    fs.writeFileSync(path.join(checkout, "packaging/policy-scan-action/README.md"), readme);
    fs.writeFileSync(path.join(checkout, "LICENSE.md"), "Apache 2.0\n");

    // The alias repository, as a bare repo the script can clone and push to.
    const bare = path.join(dir, "alias.git");
    git(["init", "-q", "--bare", "-b", "main", bare]);
    const seed = path.join(dir, "seed");
    git(["init", "-q", "-b", "main", seed]);
    fs.writeFileSync(path.join(seed, "README.md"), "seed\n");
    git(["add", "-A"], seed);
    git(["commit", "-q", "-m", "seed"], seed);
    git(["remote", "add", "origin", bare], seed);
    git(["push", "-q", "origin", "main"], seed);

    return body({ dir, checkout, bare });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function sync(checkout, bare, tag, { githubOutput } = {}) {
  const env = { ...process.env, RELEASE_TAG: tag, POLICY_SCAN_ALIAS_URL: bare };
  if (githubOutput) {
    fs.writeFileSync(githubOutput, "");
    env.GITHUB_OUTPUT = githubOutput;
  }
  const read = () =>
    githubOutput
      ? Object.fromEntries(
        fs.readFileSync(githubOutput, "utf8").split("\n").filter(Boolean)
          .map((line) => {
            const index = line.indexOf("=");
            return [line.slice(0, index), line.slice(index + 1)];
          }),
      )
      : {};
  try {
    const stdout = execFileSync("bash", [SCRIPT], {
      cwd: checkout,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env,
    });
    return { status: 0, stdout, stderr: "", outputs: read() };
  } catch (error) {
    return {
      status: error.status ?? 1,
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? "",
      outputs: read(),
    };
  }
}

function fileAtTag(bare, tag, file) {
  return execFileSync("git", ["show", `${tag}:${file}`], { cwd: bare, encoding: "utf8" });
}

test("both version literals are rewritten to the release being published", () => {
  withFixture(({ checkout, bare }) => {
    const result = sync(checkout, bare, "v0.11.0");
    assert.equal(result.status, 0, result.stderr);

    const action = fileAtTag(bare, "v0.11.0", "action.yml");
    assert.match(action, /^ {4}default: v0\.11\.0$/mu);
    assert.equal((action.match(/v0\.10\.4/gu) ?? []).length, 0, "stale action default survived");

    const readme = fileAtTag(bare, "v0.11.0", "README.md");
    assert.match(readme, /uses: BrokkAi\/bifrost-policy-scan@v0\.11\.0/u);
    assert.equal(
      (readme.match(/v0\.10\.4/gu) ?? []).length,
      0,
      "the README still tells readers to pin the previous release",
    );
  });
});

test("the quick start keeps the floating major tag", () => {
  withFixture(({ checkout, bare }) => {
    assert.equal(sync(checkout, bare, "v0.11.0").status, 0);
    const readme = fileAtTag(bare, "v0.11.0", "README.md");
    // The rewrite must not touch @v0: the quick start deliberately follows the
    // newest release, and pinning it to an exact tag would freeze every reader
    // who copies it.
    assert.match(readme, /uses: BrokkAi\/bifrost-policy-scan@v0$/mu);
  });
});

test("a canonical file that lost or gained its version literal fails the release", () => {
  const cases = [
    ["action.yml with no version default", { action: ACTION.replace("    default: v0.10.4\n", "") }],
    ["action.yml with two version defaults", { action: `${ACTION}    default: v0.9.0\n` }],
    ["README with no pinned example", { readme: README.replace(/^ {6}- uses: .*@v0\.10\.4$/mu, "") }],
  ];
  for (const [label, overrides] of cases) {
    withFixture(({ checkout, bare }) => {
      const result = sync(checkout, bare, "v0.11.0");
      assert.notEqual(result.status, 0, `${label} was accepted`);
      assert.match(result.stderr, /expected exactly one/u);
    }, overrides);
  }
});

test("the exact release tag and the floating major tag both land", () => {
  withFixture(({ checkout, bare }) => {
    assert.equal(sync(checkout, bare, "v0.11.0").status, 0);
    const exact = execFileSync("git", ["rev-parse", "v0.11.0"], { cwd: bare, encoding: "utf8" }).trim();
    const major = execFileSync("git", ["rev-parse", "v0"], { cwd: bare, encoding: "utf8" }).trim();
    const branch = execFileSync("git", ["rev-parse", "main"], { cwd: bare, encoding: "utf8" }).trim();
    assert.equal(major, exact);
    assert.equal(branch, exact);
  });
});

test("an out-of-order older release publishes its tag without moving v0", () => {
  withFixture(({ checkout, bare }) => {
    assert.equal(sync(checkout, bare, "v0.11.0").status, 0);
    const newest = execFileSync("git", ["rev-parse", "v0"], { cwd: bare, encoding: "utf8" }).trim();

    const older = sync(checkout, bare, "v0.10.9");
    assert.equal(older.status, 0, older.stderr);
    assert.match(older.stdout, /exact tag only/u);
    assert.equal(
      execFileSync("git", ["rev-parse", "v0"], { cwd: bare, encoding: "utf8" }).trim(),
      newest,
      "a recovery re-run of an older release downgraded consumers following v0",
    );
    // The older tag still carries its own release's literals.
    assert.match(fileAtTag(bare, "v0.10.9", "action.yml"), /^ {4}default: v0\.10\.9$/mu);
  });
});

// The release step reuses this decision rather than deriving "which release do
// consumers follow" a second time, so the two cannot disagree about whether a
// given sync is the newest.
test("the newest decision is published for the release step to reuse", () => {
  withFixture(({ dir, checkout, bare }) => {
    const githubOutput = path.join(dir, "github-output");

    const newest = sync(checkout, bare, "v0.11.0", { githubOutput });
    assert.equal(newest.status, 0, newest.stderr);
    assert.equal(newest.outputs.is_newest, "1");
    assert.equal(
      newest.outputs.target_commit,
      execFileSync("git", ["rev-parse", "v0.11.0"], { cwd: bare, encoding: "utf8" }).trim(),
    );

    const older = sync(checkout, bare, "v0.10.9", { githubOutput });
    assert.equal(older.status, 0, older.stderr);
    assert.equal(older.outputs.is_newest, "0");
    assert.equal(
      older.outputs.target_commit,
      execFileSync("git", ["rev-parse", "v0.10.9"], { cwd: bare, encoding: "utf8" }).trim(),
    );
  });
});

// GitHub Marketplace refuses to publish a listing whose action description is
// 125 characters or more, and it says so at the publish form -- after the
// release tag is cut, which the sync then refuses to move. v0.10.5 was tagged
// with a 281-character description and could not be listed. Fail here instead.
test("the canonical action description fits the Marketplace limit", () => {
  const action = fs.readFileSync(".github/actions/policy-scan/action.yml", "utf8");
  const folded = action.match(/^description: >-\n((?: {2}.*\n)+)/mu);
  assert.ok(folded, "expected a folded description block in the policy-scan action");
  const description = folded[1]
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .join(" ");
  assert.ok(
    description.length < 125,
    `Marketplace requires under 125 characters; this is ${description.length}: ${description}`,
  );
});

test("the analyzer cache separates runner architectures, versions, and exact builds", () => {
  const action = fs.readFileSync(".github/actions/policy-scan/action.yml", "utf8");
  assert.match(
    action,
    /identity=\$\("\$\{BIFROST_BIN\}" --build-identity\)/u,
  );
  assert.match(
    action,
    /key: bifrost-policy-cache-\$\{\{ runner\.os \}\}-\$\{\{ runner\.arch \}\}-\$\{\{ inputs\.version \}\}-\$\{\{ steps\.analyzer-cache-identity\.outputs\.value \}\}/u,
  );
  assert.doesNotMatch(action, /restore-keys:/u);
});

function gateScript() {
  const action = fs.readFileSync(
    new URL("../../.github/actions/policy-scan/action.yml", import.meta.url),
    "utf8",
  );
  const step = action.indexOf("    - name: Gate on the exit code\n");
  assert.notEqual(step, -1, "the policy-scan action lost its gate step");
  const run = action.indexOf("      run: |\n", step);
  assert.notEqual(run, -1, "the policy-scan gate lost its shell body");
  return action
    .slice(run + "      run: |\n".length)
    .split("\n")
    .filter((line) => line === "" || line.startsWith("        "))
    .map((line) => line.slice(8))
    .join("\n");
}

function runGate({ code, diffBase = "", report, rawReport, failOn = "warning" }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-policy-scan-gate."));
  const reportPath = path.join(dir, "report.sarif");
  if (rawReport !== undefined) {
    fs.writeFileSync(reportPath, rawReport);
  } else if (report !== undefined) {
    fs.writeFileSync(reportPath, JSON.stringify(report));
  }
  try {
    const result = spawnSync("bash", ["-c", gateScript()], {
      cwd: dir,
      encoding: "utf8",
      env: {
        ...process.env,
        CODE: String(code),
        DIFF_BASE: diffBase,
        FAIL_ON: failOn,
        SARIF_PATH: reportPath,
      },
    });
    return {
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function sarifReport({ results = [], diffBaseline, suppressionReviews = [], executionSuccessful = true, notifications = [] } = {}) {
  const properties = {};
  if (diffBaseline !== undefined) {
    properties["bifrost.diffBaseline"] = diffBaseline;
  }
  properties["bifrost.suppressionReviews"] = suppressionReviews;
  return {
    version: "2.1.0",
    runs: [{
      results,
      invocations: [{ executionSuccessful, toolExecutionNotifications: notifications }],
      properties,
    }],
  };
}

function sarifFinding({ disposition = "new", ruleId = "policy.rule", pathName = "src/main.py", line = 7, message = "policy finding", level = "warning", findingId = "finding-1" } = {}) {
  return {
    ruleId,
    level,
    message: { text: message },
    locations: [{ physicalLocation: { artifactLocation: { uri: pathName }, region: { startLine: line } } }],
    properties: {
      "bifrost.diffDisposition": disposition,
      "bifrost.findingId": findingId,
    },
  };
}

test("raw code 1 remains fail-closed when no retained finding explains it", () => {
  const report = sarifReport({
    diffBaseline: { baseRevision: "origin/master", degraded: false },
    results: [sarifFinding({ disposition: "persisting", message: "existing finding" })],
  });
  const baselineOnly = runGate({ code: 1, diffBase: "origin/master", report });
  assert.equal(baselineOnly.status, 1);
  assert.match(baselineOnly.stdout, /no gating finding or orphaned suppression was retained/u);

  const withoutDiff = runGate({ code: 1, report });
  assert.equal(withoutDiff.status, 1);
  assert.match(withoutDiff.stdout, /no gating finding or orphaned suppression was retained/u);

  const unreliable = runGate({
    code: 1,
    diffBase: "origin/master",
    report: sarifReport({
      diffBaseline: { baseRevision: "origin/master", degraded: true },
      results: [sarifFinding({ disposition: "persisting" })],
      executionSuccessful: false,
    }),
  });
  assert.equal(unreliable.status, 1);
  assert.match(unreliable.stdout, /policy gate failure/u);
});

test("an orphaned suppression is printed and keeps code 1 failing", () => {
  const result = runGate({
    code: 1,
    diffBase: "origin/master",
    report: sarifReport({
      diffBaseline: { baseRevision: "origin/master", degraded: false },
      suppressionReviews: [{
        policy_id: "policy.retry",
        finding_id: "old-finding",
        orphan_state: "orphaned",
        rekey_candidates: ["new-finding"],
      }],
    }),
  });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /orphaned suppression: policy\.retry \[finding: old-finding\]/u);
  assert.match(result.stdout, /re-key candidates: new-finding/u);
});

test("a new gating finding is printed and keeps code 1 failing", () => {
  const result = runGate({
    code: 1,
    diffBase: "origin/master",
    report: sarifReport({
      diffBaseline: { baseRevision: "origin/master", degraded: false },
      results: [sarifFinding({ ruleId: "policy.new", pathName: "src/new.py", line: 12, message: "new issue" })],
    }),
  });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /finding: policy\.new src\/new\.py:12 new issue/u);
  assert.match(result.stdout, /policy gate failure/u);
});

test("an unreliable code 2 prints its SARIF diagnostic and fails", () => {
  const result = runGate({
    code: 2,
    report: sarifReport({
      executionSuccessful: false,
      notifications: [{
        descriptor: { id: "diff-base-unreliable" },
        properties: { "bifrost.reportDiagnostic": { code: "diff-base-unreliable" } },
        message: { text: "baseline could not be evaluated" },
      }],
    }),
  });
  assert.equal(result.status, 2);
  assert.match(result.stdout, /diff-base-unreliable: baseline could not be evaluated/u);
  assert.match(result.stdout, /UNRELIABLE/u);
});

test("an unreliable code 2 prints typed policy completion details and fails", () => {
  const result = runGate({
    code: 2,
    report: sarifReport({
      executionSuccessful: false,
      notifications: [{
        descriptor: { id: "BIFROST_POLICY_INCONCLUSIVE" },
        properties: {
          "bifrost.policyId": "bifrost.correctness.example",
          "bifrost.completion": {
            type: "inconclusive",
            reasons: ["partial_discovery"],
          },
        },
        message: { text: "Bifrost policy evaluation was inconclusive" },
      }],
    }),
  });
  assert.equal(result.status, 2);
  assert.match(result.stdout, /BIFROST_POLICY_INCONCLUSIVE: Bifrost policy evaluation was inconclusive/u);
  assert.match(result.stdout, /policy: bifrost\.correctness\.example/u);
  assert.match(result.stdout, /completion: \{"type":"inconclusive","reasons":\["partial_discovery"\]\}/u);
  assert.match(result.stdout, /UNRELIABLE/u);
});

test("unexpected statuses and missing or invalid SARIF fail closed", () => {
  const valid = sarifReport();
  const unexpected = runGate({ code: 9, report: valid });
  assert.equal(unexpected.status, 1);
  assert.match(unexpected.stdout, /unexpected status 9/u);

  const missing = runGate({ code: 0 });
  assert.equal(missing.status, 1);
  assert.match(missing.stdout, /did not emit a SARIF report/u);

  const unsuccessful = runGate({ code: 0, report: sarifReport({ executionSuccessful: false }) });
  assert.equal(unsuccessful.status, 1);
  assert.match(unsuccessful.stdout, /unsuccessful invocation/u);

  const invalid = runGate({ code: 0, rawReport: "not json" });
  assert.equal(invalid.status, 1);
  assert.match(invalid.stdout, /invalid SARIF report/u);

  const wrongShape = runGate({ code: 0, report: { version: "2.1.0", runs: [{ results: [] }] } });
  assert.equal(wrongShape.status, 1);
  assert.match(wrongShape.stdout, /invalid SARIF report/u);
});

function actionScript(name) {
  const action = fs.readFileSync('.github/actions/policy-scan/action.yml', 'utf8');
  const start = action.indexOf(`    - name: ${name}\n`);
  assert.notEqual(start, -1);
  const end = action.indexOf('\n    - name:', start + 1);
  const step = action.slice(start, end === -1 ? undefined : end);
  return step.slice(step.indexOf('      run: |\n') + '      run: |\n'.length)
    .split('\n').filter(line => line === '' || line.startsWith('        '))
    .map(line => line.slice(8)).join('\n');
}

function runActionScript(name, env, cwd) {
  const result = spawnSync('bash', ['-c', actionScript(name)], {
    encoding: 'utf8', cwd, env: { ...process.env, ...env },
  });
  assert.equal(result.status, 0, result.stderr + result.stdout);
  return result;
}

test('managed cache follows the scan through nested roots and ignores inherited overrides', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy action '));
  try {
    const nested = path.join(dir, 'nested root');
    fs.mkdirSync(nested);
    const binary = path.join(dir, 'fake bifrost');
    const capture = path.join(dir, 'capture');
    const output = path.join(dir, 'output');
    fs.writeFileSync(binary, `#!/usr/bin/env bash
if [ "$1" = --build-identity ]; then printf '%s\\n' "\${FAKE_IDENTITY:-$(printf 'a%.0s' {1..40})}"; exit 0; fi
printf '%s\\n' "$PWD" "\${BIFROST_CACHE_ROOT:-}" "\${BIFROST_CACHE_DIR:-}" "$@" > "$CAPTURE"
printf '%s\\n' '{"version":"2.1.0","runs":[]}' > report.sarif
echo 'fake analyzer diagnostic' >&2
exit 2
`, { mode: 0o755 });
    const env = {
      RUNNER_TEMP: dir, GITHUB_WORKSPACE: dir, BIFROST_BIN: binary, GITHUB_OUTPUT: output,
      WORKDIR: 'nested root', CAPTURE: capture,
      BIFROST_CACHE_ROOT: 'inherited root', BIFROST_CACHE_DIR: 'inherited exact',
    };
    runActionScript('Resolve analyzer cache identity', env, dir);
    const outputs = Object.fromEntries(fs.readFileSync(output, 'utf8').trim().split('\n').map(line => {
      const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)];
    }));
    assert.match(outputs['workspace-key'], /^[0-9a-f]{64}$/);
    assert.ok(fs.statSync(outputs['cache-root']).isDirectory());
    const relocated = path.join(dir, 'another checkout');
    fs.mkdirSync(relocated);
    const readOutputs = () => Object.fromEntries(fs.readFileSync(output, 'utf8').trim().split('\n').map(line => {
      const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)];
    }));
    runActionScript('Resolve analyzer cache identity', { ...env, GITHUB_WORKSPACE: relocated }, dir);
    const repeated = readOutputs();
    assert.equal(repeated['cache-path'], outputs['cache-path'], 'cache archive input must survive checkout relocation');
    assert.notEqual(repeated['cache-root'], outputs['cache-root']);
    runActionScript('Resolve analyzer cache identity', { ...env, WORKDIR: 'another root' }, dir);
    assert.notEqual(readOutputs()['workspace-key'], outputs['workspace-key']);
    assert.notEqual(readOutputs()['cache-path'], outputs['cache-path']);
    runActionScript('Resolve analyzer cache identity', { ...env, FAKE_IDENTITY: 'b'.repeat(40) }, dir);
    assert.notEqual(readOutputs().value, outputs.value);
    assert.notEqual(readOutputs()['cache-path'], outputs['cache-path']);
    const invalid = spawnSync('bash', ['-c', actionScript('Resolve analyzer cache identity')], {
      encoding: 'utf8', cwd: dir, env: { ...process.env, ...env, FAKE_IDENTITY: 'invalid' },
    });
    assert.equal(invalid.status, 1);
    assert.match(invalid.stdout, /invalid build identity/);


    const scanEnv = {
      ...env, SARIF_FILE: 'report.sarif', FAIL_ON: 'warning', POLICY_PACKS: '',
      POLICY_IDS: 'rule.one', POLICY_CATEGORIES: '', POLICY_FILES: '', DIFF_BASE: 'abc123',
      POLICY_TIMINGS: 'true', MANAGED_CACHE: 'true', MANAGED_CACHE_ROOT: outputs['cache-root'],
    };
    runActionScript('Run policies', scanEnv, dir);
    const args = fs.readFileSync(capture, 'utf8').split('\n');
    assert.deepEqual(args.slice(0, 3), [fs.realpathSync(nested), outputs['cache-root'], `${outputs['cache-root']}/analyzer`]);
    assert.ok(args.includes('--policy-timings'));
    assert.match(fs.readFileSync(path.join(nested, 'report.sarif.stderr.log'), 'utf8'), /fake analyzer diagnostic/);
    assert.ok(args.includes('--diff-base'));
    assert.match(fs.readFileSync(output, 'utf8'), /exit-code=2\nsarif-file=nested root\/report.sarif\nhas-sarif=true/u);
    runActionScript('Run policies', { ...scanEnv, MANAGED_CACHE: 'false', POLICY_TIMINGS: 'false' }, dir);
    const unmanaged = fs.readFileSync(capture, 'utf8').split('\n');
    assert.deepEqual(unmanaged.slice(1, 3), ['inherited root', 'inherited exact']);
    assert.ok(!unmanaged.includes('--policy-timings'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('scan evidence includes policy incompleteness and is retained before gating', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-evidence.'));
  try {
    const report = sarifReport({ executionSuccessful: false });
    const properties = report.runs[0].properties;
    properties['bifrost.execution'] = { total_elapsed_ms: 51 };
    properties['bifrost.incremental'] = { widened_units: 2 };
    properties['bifrost.policyRuns'] = [{ policyId: 'python.rule', completion: { type: 'inconclusive', reasons: ['budget_exhausted'] }, diagnostics: ['budget exhausted'] }];
    const reportPath = path.join(dir, 'report.sarif');
    fs.writeFileSync(reportPath, JSON.stringify(report));
    const summary = runActionScript('Summarize policy execution', { SARIF_PATH: reportPath, DIFF_BASE: 'abc' }, dir);
    assert.match(summary.stdout, /"policy_work_scope": "head"/);
    assert.match(summary.stdout, /aggregate stages include diff_base when reached/);
    assert.match(summary.stdout, /total_elapsed_ms/);
    assert.match(summary.stdout, /widened_units/);
    assert.match(summary.stdout, /budget exhausted/);
    const gate = runGate({ code: 2, report });
    assert.equal(gate.status, 2);
    assert.match(gate.stdout, /python.rule/);
    const action = fs.readFileSync('.github/actions/policy-scan/action.yml', 'utf8');
    assert.ok(action.indexOf('name: Retain SARIF report') < action.indexOf('name: Gate on the exit code'));
    assert.match(action, /name: Retain SARIF report\n\s+if: always\(\)/);
    assert.match(action, /name: Save analyzer cache\n\s+if: always\(\).*cache-hit != 'true'.*has-sarif == 'true'/);
    assert.match(action, /path: \$\{\{ steps\.analyzer-cache-identity\.outputs\.cache-path \}\}/);
    assert.match(action, /key: \$\{\{ steps\.analyzer-cache\.outputs\.cache-primary-key \}\}/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a supplied semantic-pack executable bypasses Cargo and preserves arguments', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pack helper '));
  try {
    const bin = path.join(dir, 'pack tool');
    const capture = path.join(dir, 'args');
    fs.writeFileSync(bin, '#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "$CAPTURE"\n', { mode: 0o755 });
    fs.writeFileSync(path.join(dir, 'cargo'), '#!/usr/bin/env bash\necho unexpected-cargo >&2\nexit 99\n', { mode: 0o755 });
    const result = spawnSync('bash', ['-c', 'source scripts/lib/semantic-pack-tool.sh; run_semantic_pack_tool generate "output with spaces" spec.json'], {
      encoding: 'utf8', env: { ...process.env, BIFROST_SEMANTIC_PACK_BIN: bin, CAPTURE: capture, PATH: `${dir}${path.delimiter}${process.env.PATH}` },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(fs.readFileSync(capture, 'utf8').trimEnd().split('\n'), ['generate', 'output with spaces', 'spec.json']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
