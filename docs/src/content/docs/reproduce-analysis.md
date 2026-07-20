---
title: Reproduce an Analysis
description: Preserve the inputs, environment, execution contract, and outputs needed to rerun a Bifrost result.
---

A reproducible Bifrost analysis needs more than a saved query or policy. Preserve the engine, source, workspace, configuration, resolved policy dependency closure, execution limits, and complete typed response so another person can distinguish a changed program from a changed analyzer or policy.

## Recommended Artifact Layout

```text
bifrost-analysis/
├── manifest.json
├── queries/
│   ├── rule.rql
│   └── rule.json
├── policies/
│   ├── rule.rqlp
│   └── endpoints/
│       ├── source.rqlp
│       └── sink.rqlp
├── results/
│   ├── query-result.json
│   └── policy-report.json
└── README.md
```

For a raw query, commit the RQL used for exploration and the canonical JSON used as the stable integration contract. Pin `schema_version` in the query JSON. For a policy, commit every explicitly selected `.rqlp` and `.rql` source plus any registered catalog input. Preserve the canonical policy JSON report before transforming it into a dashboard or prose; human, JSON, and SARIF policy outputs share one canonical model, but JSON is easiest to compare mechanically.

## Run Manifest

Use a machine-readable manifest such as:

```json
{
  "bifrost": {
    "version": "0.8.4",
    "commit": "<full Bifrost commit>",
    "features": [],
    "interface": "cli"
  },
  "source": {
    "repository": "<source repository URL>",
    "commit": "<full source commit>",
    "workspace_root": ".",
    "dirty": false
  },
  "query": {
    "path": "queries/rule.json",
    "sha256": "<query file hash>",
    "schema_version": 2
  },
  "execution": {
    "command": "bifrost --root . --query-file queries/rule.json",
    "toolset": null,
    "result_detail": "full",
    "cache_state": "warm",
    "environment": {}
  },
  "result": {
    "path": "results/result.json",
    "sha256": "<result file hash>",
    "truncated": false,
    "provenance_truncated": false,
    "diagnostic_count": 0
  }
}
```

Replace example values with observed values; do not copy `0.8.4` into a future run without checking the binary. Record only environment variables that affect Bifrost behavior, and redact secrets before publication.

### Policy runs

For `--policy-file`, record the source pins and the resolved meaning separately.
Omitted policy/endpoint and nested RQL versions select the latest compatible
compiled-in lineage; an explicit version is an exact reproducibility pin. The
report retains the actual version and origin either way, but publication
artifacts should normally use explicit pins or show that strict mode accepted
the complete dependency closure.

Add fields such as:

```json
{
  "policy": {
    "roots": ["policies/rule.rqlp"],
    "source_sha256": {"policies/rule.rqlp": "<source hash>"},
    "policy_schema": {"version": 1, "origin": "explicit"},
    "semantic_hash": "<loaded policy semantic hash>",
    "resolved_rql_schemas": [{"version": 2, "origin": "explicit"}],
    "endpoint_manifests": ["<selected endpoint manifest hash>"],
    "catalogs": []
  },
  "execution": {
    "command": "bifrost --root . --policy-file policies/rule.rqlp --format json --fail-on never --require-explicit-schema-versions",
    "format": "json",
    "fail_on": "never"
  },
  "result": {
    "path": "results/policy-report.json",
    "sha256": "<report hash>",
    "completion": "complete",
    "exit_status": 0,
    "diagnostics_truncated": false
  }
}
```

The source hash explains byte-level changes such as comments or formatting.
The loaded semantic hash explains changes to resolved schema, selector,
endpoint, catalog, or precedence meaning. Preserve both rather than treating
one as a substitute for the other. A selected endpoint-directory manifest is
part of the policy meaning; the directory path and unselected leaves are not.

## Capture The Execution Contract

- **Engine:** binary version, full source commit when known, build features/profile, and plugin or package version.
- **Source:** repository and full commit, dirty-tree status or patch, workspace root, submodules, generated/vendor policy, and relevant file filters.
- **Query:** both RQL and canonical JSON when applicable, `schema_version`, file hash, result detail, limits, languages, and path filters.
- **Policy:** every root and dependency source, source hashes, resolved policy/endpoint and nested RQL schema versions plus origins, loaded semantic hash, selected endpoint and catalog manifests, precedence manifest, report limits, output format, `--fail-on`, and strict-version mode.
- **Interface:** exact CLI command, MCP toolset and arguments, Python package version and call, or Rust dependency revision.
- **Environment:** operating system and hardware when timing matters; semantic model ID/directory and accelerator settings when semantic search is involved.
- **Response:** every typed result variant, diagnostics, `truncated`, proof tiers, provenance, and `provenance_truncated` before downstream filtering.

For MCP, record the configured workspace root and the exact `query_code` arguments. A saved `query_file` path is workspace-relative and exclusive with inline query fields. For VS Code, record the extension and server versions and whether the RQL buffer was unsaved; unsaved text is an input that must be preserved separately.

## Cold and Warm Runs

Label cache state precisely. Bifrost's persistent repository cache is `.brokk/bifrost_cache.db` at the primary Git repository root, and linked worktrees share it. A new process using that database is not a fully cold run. Record whether you removed the cache while Bifrost was stopped, reused it, warmed the same process, or changed branches between samples.

Use the [evaluation protocol](/evaluation-evidence/) when publishing timing, memory, precision, or recall. Keep installation downloads and optional semantic-model downloads separate unless they are intentionally part of the measurement.

## Verify Before Publication

1. Check out the recorded Bifrost and source revisions in clean environments.
2. Verify the query and result hashes.
3. Run the exact command or API call and compare complete structured output, allowing only fields explicitly documented as nondeterministic.
4. Confirm diagnostics, policy completion, and all truncation fields before comparing match or finding counts. Status 2 is never a clean zero-finding result.
5. Document any mismatch as an engine, grammar, corpus, environment, or policy difference rather than silently updating the expected artifact.

Finally, attach a [software citation](/cite-bifrost/) and state the bounded claim supported by the result. The [agent result-safety rules](/agent-result-safety/) apply equally to human-authored reports.
