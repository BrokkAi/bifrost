# Benchmark Corpus

`benchmark/targets.toml` is the checked-in pinned corpus manifest for the planned `bifrost` benchmark harness.

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

Runtime artifacts stay under ignored benchmark-local directories:

- repo cache: `benchmark/.cache/repos`
- subset workspaces: `benchmark/.cache/repos/.subsets`
- JSON reports: `benchmark/benchmark-output`

For faster local iteration, `bifrost_benchmark run` also supports `--max-files N`. That mode creates a deterministic subset workspace under the benchmark repo cache, pins the manifest's explicit probe files first, then fills the remaining slots with source files from the repo's configured language slice. It is intended for smoke-checking the harness itself, not for baseline-quality timing comparisons.
