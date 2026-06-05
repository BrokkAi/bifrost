# Benchmark Harness

`benchmark/targets.toml` is the checked-in pinned corpus manifest for the `bifrost` benchmark harness.

The manifest is intentionally explicit. Each repo entry carries:

- the remote URL
- the exact pinned commit SHA
- the language slice this repo is meant to cover
- optional extension filters when the repo is multi-language
- the enabled benchmark scenarios
- the deterministic probe inputs those scenarios need

Current probe-input fields are:

- `search_patterns` for `search_symbols`
- `location_symbols` for `get_symbol_locations`
- `summary_targets` for `get_summaries`
- `seed_file_paths` for `most_relevant_files`
- `usage_symbols` for `scan_usages`

Milestone 1 validation fails when any of these drift:

- the union of repo languages no longer covers every supported analyzer language from `README.md`
- the union of repo scenarios no longer covers the minimum smoke set
- a repo enables a scenario without the exact inputs that scenario needs

The initial corpus is kept small on purpose. It is meant to be stable enough for daily CI, not a clone of Brokk's much larger baseline suite.

## Layout

Benchmark-local runtime artifacts stay under ignored directories:

- repo cache: `benchmark/.cache/repos`
- subset workspaces: `benchmark/.cache/repos/.subsets`
- JSON reports: `benchmark/benchmark-output`

The important checked-in files in this directory are:

- `targets.toml`: pinned corpus, per-repo probes, and default local paths
- `README.md`: operator documentation for the harness and the planned daily workflow
- `baselines/`: blessed compare targets and promotion notes for the scheduled workflow

## Local Use

Validate the checked-in corpus:

```bash
cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml
```

Run one repo against the full pinned checkout:

```bash
cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo gin-go
```

For faster local iteration, `bifrost_benchmark run` also supports `--max-files N`:

```bash
cargo run --bin bifrost_benchmark -- run \
  --manifest benchmark/targets.toml \
  --repo gin-go \
  --max-files 100
```

That mode creates a deterministic subset workspace under the benchmark repo cache, pins the manifest's explicit probe files first, and preserves `.git` metadata so `most_relevant_files` keeps its git-churn relevance signal. It is intended for smoke-checking the harness itself, not for baseline-quality timing comparisons.

Compare a candidate report against the blessed baseline:

```bash
cargo run --bin bifrost_benchmark -- compare \
  --baseline benchmark/baselines/ubuntu-latest.json \
  --candidate benchmark/benchmark-output/run-20260604T130836Z.json \
  --output benchmark/benchmark-output/compare-local.json
```

Add `--strict` when you want the command to exit nonzero on regressions instead of only writing the compare JSON and human summary.

## Daily Harness Shape

The intended daily workflow contract is:

1. Run `bifrost_benchmark validate` against the checked-in manifest.
2. Run `bifrost_benchmark run` against the same manifest on `ubuntu-latest`.
3. Upload the JSON report artifact from `benchmark/benchmark-output`.
4. Compare that report against `benchmark/baselines/ubuntu-latest.json` when that blessed baseline exists.
5. Publish a short human-readable summary, with optional Slack notification, after the compare step.

The harness already guarantees two useful operator properties for that workflow:

- cached repos can be reused offline once the pinned commit is present locally
- failed scenarios still produce a written report before the CLI exits nonzero

The checked-in GitHub Actions workflow lives at `.github/workflows/benchmark.yml`.

- Scheduled runs execute from the workflow cron at `17 9 * * *` on `ubuntu-latest`.
- Manual runs use `workflow_dispatch` and can optionally scope to one manifest repo and/or `--max-files`.
- Compare runs are strict only when `workflow_dispatch` sets `strict_compare = true`.
- If `benchmark/baselines/ubuntu-latest.json` is not present yet, the workflow uploads the run artifact and records that compare was skipped.

The manual workflow inputs are:

- `repo`: optional manifest repo name, for example `gin-go`
- `max_files`: optional subset cap for smoke runs, for example `100`
- `strict_compare`: when `true`, fail the workflow if the compare step finds regressions

## Slack Hook

The benchmark workflow can optionally trigger a Slack Workflow Builder webhook after the run summary is prepared.

GitHub-side setup:

- configure a repository secret named `SLACK_DAILY_PERF_WEBHOOK_URL`
- keep the webhook URL in that secret, not in a GitHub variable
- if the secret is absent, the workflow skips Slack delivery cleanly
- Slack delivery is best-effort only; webhook or Slack-side failures do not change the benchmark workflow outcome

The webhook payload is benchmark-specific. The workflow sends these fields:

- `ok`
- `error_text`
- `workflow_run_url`
- `head_sha_short`
- `event_name`
- `repo_input`
- `max_files_input`
- `strict_compare`
- `run_outcome`
- `compare_outcome`
- `report_path`
- `compare_path`
- `compare_summary_path`
- `generated_at`
- `selected_repo`
- `report_max_files`
- `repo_count`
- `failed_scenarios_count`
- `compared_scenarios_count`
- `regression_count`
- `improvement_count`
- `missing_candidate_count`
- `new_candidate_count`
- `has_regressions`
- `summary_text`

Slack-side setup:

- update the Slack Workflow Builder message template to consume the benchmark payload above rather than the older Brokk perf-only fields
- the existing shared fields `ok`, `error_text`, `workflow_run_url`, and `head_sha_short` can be reused directly
- replace old perf-specific fields such as `base_sha_short`, `time_*`, `fps_*`, and `coarse_memory_ok` with benchmark-oriented summary content
- keep the current two-message shape if desired: a top-level run summary plus a threaded follow-up with benchmark-specific operator guidance
- do not assume the old Brokk bisect guidance still applies unless the Slack-side thread text is intentionally updated for this workflow

## Configuration Surface

This directory should be the first place to document any new benchmark-specific workflow variables or secrets.

Current stable configuration comes from `targets.toml`:

- `warmup_iterations`
- `measured_iterations`
- `output_dir`
- `repo_cache_dir`
- `required_languages`
- `required_scenarios`

Future workflow-level settings should stay documented here rather than being introduced only in a GitHub Actions YAML or Slack hook. Expected examples include:

- baseline report path for `compare`
- strict-vs-summary failure mode for scheduled runs
- artifact retention knobs
- Slack channel-routing variables for daily notifications

Slack-facing settings should stay benchmark-scoped and documented here alongside:

- when the notification fires
- what report path or compare summary it links to
- whether a nonzero benchmark exit suppresses or changes the Slack message
- which Slack workflow fields or message templates are expected to consume the payload
