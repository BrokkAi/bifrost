---
title: CLI
description: Use Bifrost from the terminal for one-shot code-intelligence queries and static-analysis policy runs.
---

The `bifrost` command runs one tool, one saved query, or a policy scan, prints
the result, and exits. It can also start an MCP server or an interactive query
REPL. This page shows the common tasks. For every subcommand, flag, conflict
rule, and exit status, see [CLI Reference](/reference/cli/). For environment
variables, see [Environment Variables](/reference/environment/).

The `bifrost` command does not serve the Language Server Protocol. The
language server is the separate `bifrost-lsp` program; see
[LSP Server](/lsp/).

## Run One Tool

Run a single tool and print its JSON result:

```bash
bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'
```

`--tool` runs the same tool implementations as the MCP server. Use it to call
one tool from a shell script without starting a long-running server.

`--args` is inline JSON in the tool's MCP argument shape. Omit it for tools
that accept an empty object, such as `get_active_workspace`. To see a tool's
description and parameters, ask the installed binary:

```bash
bifrost --help scan_usages_by_location
```

For the list of tools and their arguments, see
[MCP Tools Reference](/reference/mcp-tools/).

### Output Shape

Tool mode always prints one JSON object on stdout. It does not print the
rendered text that an MCP client receives.

- A call that succeeds prints `{"structuredContent": ..., "isError": false}`.
  A tool whose MCP response is text only prints `{"isError": false}`.
- A call that fails prints `{"error": "<message>", "isError": true}`, repeats
  the message on stderr, and exits 1. This includes a failure on an analysis
  worker thread.
- An invalid command line is reported on stderr before any tool runs, so stdout
  is empty.

`--format` applies only to policy reports. `--no-line-numbers` mainly changes
text that an MCP client receives; most `--tool` JSON is the same with or
without it. In MCP mode it also replaces the by-location symbol tools with
`get_definitions_by_reference` and `scan_usages_by_reference`.

### Limit the Workspace

Whole-workspace analysis honors root and nested `.bifrostignore` files. Matching
files are excluded from code intelligence but remain visible to file-level
tools. See [Workspace Scope](/workspace-scope/).

Use `--sources` when a one-shot run needs only part of a repository. Each value
can be a file, directory, or glob under the root:

```bash
bifrost --root /path/to/project --tool get_symbol_sources --sources src --sources 'tests/**/*.rs' --args '{"symbols":["src/main.rs"]}'
```

An explicit `--sources` selection overrides `.bifrostignore` for the selected
files.

A `--sources` run answers cross-file questions over only the files you named.
`scan_usages_by_reference`, `scan_usages_by_location`, `usage_graph`,
`most_relevant_files`, `search_symbols`, `query_code`, and
`get_active_workspace` report `"session_subset": {"files": N}`, the number of
files the session covers. `scan_usages` reports it inside its `scope` block;
the others report it at the top level. Read "no results" from such a run as
"nothing in those N files", not "nothing in the repository". A run without
`--sources` omits the field.

File arguments also accept Git history paths in `<commit-ish>:<path>` form,
such as `HEAD~2:src/main.rs`. Parser-backed tools then analyze that historical
content.

### Compare Immutable Git Snapshots

The diff tools can compare exact Git commits or tree objects. For snapshot
trees that exist only in a separate Git object store, start Bifrost with
`--diff-snapshot-object-dir`. The value is a trusted path to a Git `objects`
directory, absolute or relative to the current directory. Bifrost rejects a
missing path or a path that is not a directory before it serves requests. The
path is launch configuration, never a tool argument, so a caller cannot select
an arbitrary object store.

The flag works only with `--tool` and the MCP server. For example, a review
host that captured two private tree objects can compare them without reading
the current checkout, index, or `.gitattributes`:

```bash
bifrost --root /path/to/project \
  --diff-snapshot-object-dir /path/to/turn-snapshot/objects \
  --tool analyze_diff \
  --args '{"base":"0123456789abcdef0123456789abcdef01234567","target":"89abcdef0123456789abcdef0123456789abcdef"}'
```

Each endpoint may be a commit-ish or a tree-ish. When both apply, the commit
wins. Results label tree endpoints as `tree:<oid>`. A tree given only as
`target` is rejected because it has no parent; give both `base` and `target`
for a tree-to-tree comparison.

## Run a Saved Code Query

Run an RQL query or a canonical JSON `query_code` payload from a workspace
file:

```bash
bifrost --query-file queries/audit.rql
bifrost --root /path/to/project --query-file queries/audit.json
```

For example, a saved hierarchy query can use `(members (subtypes :transitive
true (enclosing-decl (class :name "Service"))))`, or the equivalent JSON steps
`enclosing_decl`, transitive `subtypes`, then `members`.

`--query-file` accepts `.rql` and `.json` files only. The default root is the
current directory. The query file must stay inside the workspace, also after
symlinks are resolved. The file contains the complete query, so it cannot be
combined with `--tool`, `--args`, or `--sources`.

A saved query can select planning-only explain mode or measured profile mode
with `(explain QUERY)`, `(profile QUERY)`, or the JSON `execution_mode` field.
Explain does not read analyzer data while it plans the query, but the one-shot
CLI still builds the workspace first. Profile returns the normal result and a
versioned telemetry report. See
[Explain and Profile CodeQuery](/code-query-explain-profile/).

`--workspace-scaled-limits` runs the query with the execution limits that
policy evaluation uses, which grow with the amount of source, instead of the
interactive limits.

## Static-Analysis Policies

> **Execution boundary:** Policy execution supports `:type match`,
> `:type taint`, `:type typestate`, `:type assertion`, and `:type flow`.
> Taint compiles compatible source and sink sets into bounded shared solves.
> Missing bindings, unsupported semantics, cancellation, or exhausted budgets
> make a run incomplete. They never produce an empty successful result.

### Scan a project (`bifrost scan`)

`bifrost scan` runs the built-in policies on one project with no
configuration:

```bash
bifrost scan /path/to/project
```

The path defaults to the current directory. The scan runs every policy that
the built-in catalog marks `default`. It skips policies marked `opt-in`. Before
the report, it writes one `builtin-policy-pack <id>@<version> policies=<count>`
line per shipped pack and the catalog SHA-256 to stderr, in the same form that
`bifrost --version` prints. An evaluation can record from these lines which
catalog produced the result. In a `--format json` report, each run also records
its policy ID and manifest semantic hash.

`bifrost scan --list-builtin-policies` prints the catalog as JSON without
running anything. A scan accepts `--format`, `--fail-on`, `--evaluation-date`,
`--no-incremental`, `--output`, `--verbose`, and `--color`. It reads the default
suppression, scope, and baseline files under the scanned root. For explicit
selection, other document paths, `--sources`, or diff gating, use the policy
flags below. [Scan a Codebase](/scan-a-codebase/) walks through a scan and its
report.

### Explicit policy selection

`--policy` with no other selection is the same evaluation as `bifrost scan`:

```bash
bifrost --root /path/to/project --policy
```

Run one or more workspace `.rqlp` policies and get one combined report. An
explicit selection replaces the built-in default:

```bash
bifrost --root /path/to/project \
  --policy-file policies/security.rqlp \
  --policy-file policies/correctness.rqlp \
  --evaluation-date 2026-07-27 \
  --format sarif \
  --fail-on warning \
  --output reports/bifrost.sarif
```

List the built-in policies, then select a pack, a category, or one policy ID:

```bash
bifrost --list-policies
bifrost --root /path/to/project \
  --policy-pack bifrost.code-smells \
  --evaluation-date 2026-07-28 \
  --format json
bifrost --root /path/to/project --policy-category performance
bifrost --root /path/to/project --policy-id bifrost.correctness.dynamic-evaluation
```

The three selectors combine like this:

- Repeating one selector widens the selection. `--policy-category correctness
  --policy-category performance` selects both categories.
- Combining different selectors narrows it. `--policy-pack P --policy-id I`
  runs `I` only, and fails with status 2 when `I` is not in `P`.
- A policy whose catalog `activation` is `opt-in` runs only when `--policy-id`
  names it. `scan`, `--policy`, `--policy-pack`, and `--policy-category` skip it.

Selected built-in policies and `--policy-file` inputs share one analyzer
snapshot, budget, suppression audit, report, and exit status.

`--no-builtin-policies` keeps a controlled run free of built-in policies. It
requires at least one `--policy-file` and refuses the built-in selectors.
`--list-row-schemas` prints the `bifrost_relation_schema/v1` catalog of row
domains, fields, and expansions that a relational policy can bind. The two
listing flags exclude each other and every evaluation flag.

Every `--policy-file` root must be a `(policy ...)` document. A root that is an
`(endpoint ...)` document is a status-2 report. A policy can still load
endpoints and saved `.rql` selectors as dependencies. The CLI does not search
the workspace for policy files; it runs only the files you name. A
catalog-backed policy needs a library embedding that registers its catalog. A
policy that selects endpoints only by `(match-endpoints :ids [...])` needs an
embedding that registers those IDs; in a normal CLI run, the policy can find
endpoints through a `match-directory` closure instead.

Semantic-pack activation for policy runs follows `.bifrost/packs.json`. The
report records the activation mode and the decisions for selected, missing,
incompatible, disabled, or incomplete packs. See
[Semantic-Model Packs](/semantic-model-packs/).

`--sources` restricts policy evaluation to the selected files, directories, or
globs:

```bash
bifrost --root /path/to/project --policy-file policies/security.rqlp --sources src/auth
```

`--policy-timings` adds each policy's elapsed time to the report's work
metrics.

Policy flags cannot be combined with `--install`, `--query-file`, `--tool`,
`--args`, `--mcp`, `--repl`, `--no-line-numbers`, `--workspace-scaled-limits`,
or `--diff-snapshot-object-dir`. The listing flags and the explanation flags
also refuse `--sources`.

### Suppressions and evaluation date

By default, policy evaluation reads `.bifrost/suppressions.json`,
`.bifrost/suppressions.private.json`, and `.bifrost/suppressions.local.json`, in
that order, under the workspace root. Each file may be absent. Pass
`--suppressions-file reviews/accepted.json` to read one workspace-relative file
instead of all three. An invalid, unsafe, oversized, or escaping file produces
a diagnostic and status 2; the run never continues without the suppressions.
See [Configuration Files](/reference/configuration-files/) for which file to
commit.

Suppression expiry uses `--evaluation-date YYYY-MM-DD`. Without it, the CLI
uses today's UTC date. Give it explicitly for reproducible JSON and SARIF. A
suppression stays current on its `expires_at` date and expires the next day.

### Policy output and thresholds

`--format` accepts `human` (the default), `json`, or `sarif`. All three come
from the same canonical report and keep the same rule and finding IDs,
resolved schema and dependency manifests, locations, severity, certainty,
completion, classifications, evidence, witnesses, and CVSS variants. SARIF
uses Unicode code-point columns and uses strong finding IDs as stable partial
fingerprints. Weak IDs are labeled inconclusive and are not emitted as stable
fingerprints.

Human output is concise by default. It prints each active finding with its
policy ID, location, and proof summary, and counts applied suppressions without
listing them. Add `--verbose` to print every finding, suppression reasons,
acceptance provenance, stale or expired records, dependency-pack decisions, and
policy audit details. Canonical JSON always keeps the complete finding and
audit. SARIF keeps a suppressed result as an external accepted suppression.
`--color auto|always|never` controls ANSI colors in human output. `auto` uses
colors only when stdout is a terminal, `NO_COLOR` is unset, and the platform is
not Windows. `--verbose` and `--color` are rejected with JSON or SARIF output.

`--output PATH` writes the report to a temporary file beside `PATH`,
synchronizes it, and atomically replaces `PATH`. If serialization, writing, or
replacement fails, an existing file stays unchanged and the run exits 2.

`--fail-on` accepts:

| Value | A complete run exits 1 for |
| --- | --- |
| `never` | No finding threshold. |
| `finding` | Any active unsuppressed finding, including `unrated`. |
| `note` | An active unsuppressed `note`, `warning`, or `error`. |
| `warning` | An active unsuppressed `warning` or `error` (default). |
| `error` | An active unsuppressed `error` only. |

The process status is:

| Status | Meaning |
| --- | --- |
| `0` | The run is reliable, no active unsuppressed finding met the threshold, and no suppression record is orphaned. |
| `1` | The run is reliable, and at least one active unsuppressed finding met the threshold or at least one suppression record is orphaned. An orphaned record names a file that the run analyzed, but that file no longer has the finding. |
| `2` | A policy, suppression, schema, composition, evaluation, completeness, serialization, output, or argument problem made the run unreliable. Status 2 takes precedence over status 1. |

[Policies Reference](/reference/policies/) lists every condition that makes a
run unreliable, including the completion states that cannot support a clean
result.

`--fail-on never` turns off only the finding threshold. An orphaned
suppression record still gives status 1. The flag cannot turn an invalid,
cancelled, incomplete, failed, or unsupported policy into a clean run.

`--require-explicit-schema-versions` rejects an omitted schema version in
the root policy and in every endpoint or RQL dependency. Otherwise an omitted
version selects the newest compatible version built into the binary.

For the exit status of the other modes, see
[CLI Reference](/reference/cli/#exit-status).

### Gate only on new findings (`--diff-base`, `--no-incremental`)

`--diff-base REV` evaluates the same policies twice: once on the committed
content of `REV` (any revision `git rev-parse` accepts, resolved to a commit)
and once on the working tree. Findings are joined by their stable identities.
Each head finding is classified `new` or `persisting`, fixed base findings are
summarized, and the `--fail-on` threshold counts only new findings. A pull
request that introduces one finding into a repository with hundreds of
existing ones fails with exactly that one finding.

```bash
bifrost --root . \
  --policy-pack bifrost.code-smells \
  --format sarif --output out.sarif \
  --diff-base origin/main
```

The CLI does not compute merge bases. Pass the pull request's merge base
explicitly, for example `git merge-base HEAD origin/main` or the base SHA that
GitHub provides. If the root is not in a Git repository or the revision does
not resolve, the run exits 2. If the base revision resolves but its evaluation
is unreliable, the run falls back to full gating with a `diff-base-unreliable`
diagnostic, so a broken base cannot hide new findings. See
[Static-Analysis Policies](/static-analysis-policies/) for the join rules and
[CI Gating with GitHub Actions](/ci-github-actions/) for the pull-request
recipe.

`--diff-base` reads and writes the repository's analyzer cache under
`.bifrost/cache`. The cache stores what each policy concluded on the base
revision and what each part of that evaluation read. A later run against the
same base skips the base export and build, and recomputes only the parts of
the working tree whose inputs changed. Findings, identities, diagnostics,
completion tiers, and the exit status do not depend on the cache contents. An
ordinary full scan also stores complete policy units in the cache. A later
pull-request scan whose base is the scanned revision reuses those units for its
base evaluation, and reuses the working-tree units whose recorded inputs it
verifies. Units from incomplete or widened work are never reused as complete
evidence. The MCP `run_policy` tool evaluates under the same rules and uses
the same cache, so CLI and MCP runs reuse each other's units.

`--no-incremental` turns off policy-unit caching for one run. Every policy is
evaluated in full on both revisions, and no policy units are read or stored.
Reuse produces the same report, so use this flag only to compare against a
full evaluation while you diagnose a difference. The report's `incremental`
section then lists every policy as evaluated in full with the reason
`incremental_disabled`.

### Accept every existing finding (`--accept-current`, `--baseline-file`)

`--accept-current` runs the selected policies and writes a baseline document
that contains every current strong finding identity. Later runs of the same
selection then gate only on findings introduced afterwards:

```bash
bifrost --root . \
  --policy-pack bifrost.code-smells \
  --accept-current
```

The document is written to `.bifrost/baseline.json`, or to the
workspace-relative path in `--baseline-file`, which also selects the document
that every evaluation reads. An acceptance run uses `--fail-on never` and
writes only when the run is reliable and complete and no suppression record is
orphaned. An unreliable run exits 2 and writes nothing, because Bifrost cannot
accept an identity that the run did not prove. A run with an orphaned
suppression record exits 1 and writes nothing. Weak-identity findings are never written; their count is reported on
stderr. Findings already covered by a suppression or a directory scope are not
written either. `--accept-current` cannot be combined with `--fail-on` or
`--diff-base`. To update the baseline, run the command again; the baseline
never updates itself.

On later runs, baselined findings stay in the report with a `baseline`
decision, do not count toward `--fail-on`, and are audited like suppressions.
A malformed or oversized document is a diagnostic and status 2. A policy edit
marks its entries drifted without making them active again. An entry whose
finding a complete run proves absent is reported stale. See
[Static-Analysis Policies](/static-analysis-policies/) for the rules and
[CI Gating with GitHub Actions](/ci-github-actions/) for the onboarding recipe.

### Explain one policy result

`--explain-finding`, `--explain-candidate`, and `--explain-near-misses` ask
why one policy did or did not report something, and print one JSON answer. See
[Static-Analysis Policies](/static-analysis-policies/) for how to read the
answers and [CLI Reference](/reference/cli/#policy-explanation) for the flag
values.

See [Data Flow, Taint, and Typestate](/data-flow-and-typestate/) and
[Static-Analysis Policies](/static-analysis-policies/) for execution
boundaries, endpoint composition, completeness, finding identity, and CVSS
rules.

## Start an MCP Server or the REPL

`bifrost --mcp core` starts an MCP server over stdio. `bifrost --root DIR
--repl` starts the interactive code-query REPL. One MCP server can also serve
several fixed workspaces with repeated `--workspace NAME=PATH`. See
[MCP Server](/mcp/) and [MCP Tools Reference](/reference/mcp-tools/).

## Register Coding Hosts

Run `bifrost --install` to register a user-level MCP server named `brokk` with
installed Codex, Claude Code, OpenCode, Kimi Code, Hermes, and Oh My Pi
clients. The server runs the current executable with `--mcp core`. The command
does not install skills, instruction files, host applications, or the original
Pi extension. See [Install Bifrost](/install/#connect-coding-hosts).

## Help

```bash
bifrost --help
bifrost scan --help
bifrost --help TOOL
```

The repository also builds a `most_relevant_files` development helper, which
release packages do not include. Its arguments are in
[CLI Reference](/reference/cli/#development-helper-most_relevant_files).
