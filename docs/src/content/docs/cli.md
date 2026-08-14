---
title: CLI
description: Use Bifrost from the terminal for one-shot code-intelligence queries.
---

Bifrost can run a single tool once and print the JSON result:

```bash
bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'
```

`--tool` uses the same named tool implementations exposed by the MCP `searchtools` catalog. Use it when you want the MCP tool surface from a shell script or terminal session without starting a long-lived MCP server.

`--args` is inline JSON matching the selected tool's MCP argument object. Omit it for tools that accept an empty object, such as `get_active_workspace`.

## Immutable Git Snapshot Diffs

`analyze_diff` can compare exact Git commits or tree objects. For snapshot trees
that exist only in a separate Git object store, launch Bifrost with
`--diff-snapshot-object-dir`. The value is a trusted path to a Git `objects`
directory, given as either an absolute path or one relative to the launch working
directory; Bifrost resolves it to an absolute path and rejects a missing or
non-directory path before serving requests. It is launch
configuration, never an `analyze_diff` argument, so callers cannot select an
arbitrary filesystem object store.

The flag is valid only with `--tool` and MCP server modes. For example, a review
host that captured two private tree objects can compare them without consulting
the current checkout, index, or `.gitattributes`:

```bash
bifrost --root /path/to/project \
  --diff-snapshot-object-dir /path/to/turn-snapshot/objects \
  --tool analyze_diff \
  --args '{"base":"0123456789abcdef0123456789abcdef01234567","target":"89abcdef0123456789abcdef0123456789abcdef"}'
```

Each explicit endpoint may be a commit-ish or tree-ish (commit resolution wins
when both apply). Results label tree endpoints as `tree:<oid>`. A tree supplied
only as `target` is rejected because it has no parent; provide both `base` and
`target` for a tree-to-tree comparison.

## Saved Code Queries

Run a complete RQL or JSON `query_code` query from a workspace file without the generic tool wrapper:

```bash
bifrost --query-file queries/audit.rql
bifrost --root /path/to/project --query-file queries/audit.json
```

For example, a saved hierarchy query can use `(members (subtypes :transitive true (enclosing-decl (class :name "Service"))))`, or the equivalent JSON steps `enclosing_decl`, transitive `subtypes`, then `members`.

`--query-file` accepts `.rql` and `.json` files only. The default workspace root is the current directory; query-file paths must stay inside that workspace, including after symlinks are resolved. The file contains the complete query, so it cannot be combined with `--tool`, `--args`, or `--sources`.

A saved query may select planning-only explain or measured profile mode with `(explain QUERY)`, `(profile QUERY)`, or the JSON `execution_mode` field. Explain does not access analyzer data while lowering and selecting the query plan, although the one-shot CLI still initializes and indexes its workspace before it runs the request. Profile returns the ordinary result and a versioned telemetry report. See [Explain and Profile CodeQuery](/code-query-explain-profile/).

## Static-Analysis Policies

> **Current execution boundary:** Policy execution supports `:type match`,
> `:type taint`, `:type typestate`, and `:type assertion`. Taint compiles
> compatible source and sink sets into bounded shared solves. Missing bindings,
> unsupported semantics, cancellation, or exhausted budgets remain non-clean
> completion states rather than empty successful results.

Run one or more workspace-relative `.rqlp` policy roots and emit one combined
canonical report:

```bash
bifrost --root /path/to/project \
  --policy-file policies/security.rqlp \
  --policy-file policies/correctness.rqlp \
  --evaluation-date 2026-07-27 \
  --format sarif \
  --fail-on warning \
  --output reports/bifrost.sarif
```

List the policies embedded in the installed binary, then select the whole
pack, one category, or one stable policy ID:

```bash
bifrost --list-policies
bifrost --root /path/to/project \
  --policy-pack bifrost.code-smells \
  --evaluation-date 2026-07-28 \
  --format json
bifrost --root /path/to/project \
  --policy-category performance \
  --policy-id bifrost.correctness.dynamic-evaluation
```

`--policy-pack`, `--policy-category`, and `--policy-id` are repeatable and form
one deduplicated union in manifest order. They can be combined with
`--policy-file`; built-in and workspace policies share one analyzer snapshot,
budget, suppression audit, report, and exit status. `--list-policies` prints the
deterministic manifest without constructing an analyzer and cannot be combined
with evaluation options.

`--policy-file` is repeatable. Every root must be a `(policy ...)` document;
passing a diagnostic-neutral `(endpoint ...)` as a root is a status-2 report.
Policies may still load endpoints and saved `.rql` selectors as explicit
dependencies. The one-shot CLI starts with empty catalog and endpoint
registries. A catalog-backed policy requires a library embedding which
explicitly populated `TaintCatalogRegistry`. A policy that uses only
`(match-endpoints :ids [...])` also requires an embedding to pre-register those
endpoint IDs; in a normal CLI run, the same policy can discover endpoints
through a `match-directory` closure before selecting exact IDs. The CLI does
not scan for workspace policies, endpoints, or catalogs on its own. Built-in
policies are selected only through the explicit selectors above.

By default, policy evaluation reads `.bifrost/suppressions.json` beneath the
workspace root. Pass `--suppressions-file reviews/accepted.json` to select one
different workspace-relative JSON file. A missing file means no project
suppressions; an invalid, unsafe, oversized, or escaping file produces a
canonical diagnostic and status 2 instead of silently running unsuppressed.

Suppression expiration uses `--evaluation-date YYYY-MM-DD`. Omit it for
today's UTC date, resolved once by the CLI, or provide it explicitly for
reproducible JSON/SARIF and stable expiry behavior. A decision remains current
on its `expires_at` date and expires the following day. These options are valid
only in policy mode.

Policy mode cannot be combined with `--query-file`, `--tool`, `--args`,
`--sources`, server/REPL modes, `--no-line-numbers`, or
`--force-semantic-cpu`.

### Policy output and thresholds

`--format` accepts `human` (the default), `json`, or `sarif`. All three are
rendered from the same canonical report and preserve the same rule/finding
IDs, resolved schema and dependency manifests, locations, severity, certainty,
completion, classifications, evidence, witnesses, and CVSS variants. SARIF
uses Unicode-code-point columns and strong finding IDs as stable partial
fingerprints; weak IDs are labeled inconclusive and are not emitted as stable
fingerprints.

Human output is concise by default: applied suppressed findings are counted
but omitted from the active list. Add `--verbose` to retain every finding and
print suppression reasons, acceptance provenance, and stale/expired/drifted
review records. Canonical JSON always retains the complete finding and audit;
SARIF retains the result as an external accepted suppression and preserves its
strong partial fingerprint. `--color auto|always|never` controls ANSI severity colors and Unicode
status symbols; `auto` uses them only for a terminal and respects `NO_COLOR`.
Redirected and file output is plain and deterministic by default. These two
options are rejected with JSON or SARIF output.

`--output PATH` writes the bounded report to a temporary file beside the
destination, synchronizes it, and atomically replaces the destination. A
serialization, write, or replacement failure leaves an existing destination
untouched and exits 2. Without `--output`, the complete bounded encoding is
prepared before stdout is written.

`--fail-on` accepts:

| Value | A complete batch exits 1 for |
| --- | --- |
| `never` | No finding threshold. |
| `finding` | Any active unsuppressed finding, including `unrated`. |
| `note` | An active unsuppressed `note`, `warning`, or `error`. |
| `warning` | An active unsuppressed `warning` or `error` (default). |
| `error` | An active unsuppressed `error` only. |

The process status is:

| Status | Meaning |
| --- | --- |
| `0` | Every requested policy completed and no active unsuppressed finding met the threshold. |
| `1` | Every requested policy completed and at least one active unsuppressed finding met the threshold. |
| `2` | A policy, suppression, schema, composition, evaluation, completeness, serialization, or output failure made the batch unreliable. Status 2 takes precedence over status 1. |

`--fail-on never` disables only the finding threshold; it cannot turn an
invalid, cancelled, incomplete, failed, or unsupported policy into a clean
run. `--require-explicit-schema-versions` rejects compatible inference for the
root and every loaded endpoint or RQL dependency. Omitted versions otherwise
select only the newest compiled-in compatible lineage.

### Gate only on new findings (`--diff-base`)

`--diff-base REV` evaluates the same policies twice: once against the committed
content of `REV` (any revision `git rev-parse` accepts, peeled to a commit) and
once against the working tree. Findings are joined by their stable identities,
each head finding is classified `new` or `persisting`, fixed base findings are
summarized, and the `--fail-on` threshold counts only the new findings. A pull
request that introduces one finding into a repository with hundreds of
pre-existing ones fails with exactly that one finding gating.

```bash
bifrost --root . \
  --policy-pack bifrost.code-smells \
  --format sarif --output out.sarif \
  --diff-base origin/main
```

The CLI does not compute merge bases; pass the pull request's merge base
explicitly (`git merge-base HEAD origin/main`, or the base SHA GitHub
provides). If the workspace root is not inside a git repository or the
revision does not resolve, the run exits 2. If the base revision resolves but
its evaluation is unreliable, the run degrades to full gating with a
`diff-base-unreliable` diagnostic, so a broken base can never hide new
findings. See [Static-Analysis Policies](/static-analysis-policies/) for the
join semantics and [CI Gating with GitHub Actions](/ci-github-actions/) for
the pull-request recipe.

### Accept every existing finding (`--accept-current`, `--baseline-file`)

`--accept-current` runs the selected policies and writes a bulk-acceptance
baseline document containing every current strong finding identity, so later
runs of the same selection gate only on findings introduced afterwards:

```bash
bifrost --root . \
  --policy-pack bifrost.code-smells \
  --accept-current
```

The document is written to `.bifrost/baseline.json` (or the workspace-relative
path given by `--baseline-file`, which also selects the document every
evaluation reads). Acceptance forces `--fail-on never` internally and writes
only on a clean status: an unreliable or non-exhaustive run exits 2 and writes
nothing, because an identity the run could not prove cannot be accepted.
Weak-identity findings are never written and their count is reported on
stderr. Findings already claimed by a suppression or directory scope are not
written either; they stay governed by their own mechanism. `--accept-current`
cannot be combined with `--fail-on` or `--diff-base`, and regeneration is
always an explicit re-run — the baseline never refreshes itself.

On later runs, baselined findings stay in the report with a `baseline`
decision, stop counting toward `--fail-on`, and are audited like suppressions:
a malformed or oversized document is a diagnostic and status 2, a policy edit
marks its entries drifted without reactivating them, and an entry whose
finding an exhaustive run proves absent is reported stale. See
[Static-Analysis Policies](/static-analysis-policies/) for the semantics and
[CI Gating with GitHub Actions](/ci-github-actions/) for the onboarding
recipe.

`match`, `taint`, query-local `typestate`, and `assertion` evaluation are
available now. Typestate
compiles resolved subject/event selectors into the semantic protocol engine and
preserves finding identity, locations, witnesses, and completeness across all
three report formats. Taint resolves typed endpoint bindings, batches compatible
source/sink demand, runs the production data-flow engine, and projects one
retained report. Source-backed analysis works in the ordinary CLI; external
procedure summaries require an embedding that supplies an explicit
semantic-model catalog and activation request. See [Data Flow, Taint, and
Typestate](/data-flow-and-typestate/) and [Static-Analysis
Policies](/static-analysis-policies/) for execution boundaries, endpoint
composition, completeness, finding identity, and CVSS rules.

For the available tool families and tool names, see [MCP Server](../mcp/). For a single tool's description and parameters, ask the CLI directly:

```bash
bifrost --help scan_usages_by_location
bifrost --help scan_usages_by_reference
```

## Output Shape

Tool mode mirrors MCP's structured result shape, but keeps stdout machine-oriented by omitting rendered text content:

```json
{
  "structuredContent": {},
  "isError": false
}
```

Tools whose normal MCP response is text-only return only:

```json
{
  "isError": false
}
```

Use the MCP page as the catalog for what each tool does. Use `bifrost --help <tool>` for the exact input schema accepted by the installed binary.

`semantic_search` follows the same build and runtime rules in CLI tool mode as it does through MCP: Bifrost must be built with the `nlp` feature, semantic indexing must be enabled for the session, and the active root must be a git repository.

## Limit the Workspace

Whole-workspace analysis honors root and nested `.bifrostignore` files. Matching
tracked or untracked files are excluded from code intelligence but remain
visible to text-level tools. See [Workspace
Scope](/workspace-scope/) for syntax and the complete visibility contract.

Use `--sources` when a one-shot query only needs part of a repository. Each value can be a file, directory, or glob under the selected root:

```bash
bifrost --root /path/to/project --tool get_symbol_sources --sources src --sources 'tests/**/*.rs' --args '{"symbols":["src/main.rs"]}'
```

An explicit `--sources` selection overrides `.bifrostignore` for the selected
files.

File-bearing CLI tool arguments also accept git history paths in `<commit-ish>:<path>` form, such as `HEAD~2:src/main.rs`. Parser-backed tools build the one-shot analyzer workspace with that historical content.

## Rendering

Tool mode prints JSON by default. Pass `--no-line-numbers` to remove rendered line and line-range prefixes from text previews while keeping structured line metadata unchanged.

## Help

List modes and toolsets:

```bash
bifrost --help
```

## Related File Ranking

The repository also builds the `most_relevant_files` helper binary:

```bash
cargo build --bin most_relevant_files
./target/debug/most_relevant_files --root /path/to/project path/to/seed_file.py
```

Pass `--exclude-tests` to omit files classified as tests or test support from
the ranking without allowing them to consume the result limit.

## Register Coding Hosts

Run `bifrost --install` to register a user-level MCP server named `brokk` with
installed Codex, Claude Code, OpenCode, Kimi Code, Hermes, and Oh My Pi clients.
The action registers the current executable with `--mcp core|nlp`. It
does not install skills, instruction files, host applications, or the original
Pi extension. See [Install Bifrost](/install/#connect-coding-hosts) for details.
