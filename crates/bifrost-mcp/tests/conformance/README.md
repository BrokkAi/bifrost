# Official MCP conformance harness (issue #2319)

This directory runs the upstream `@modelcontextprotocol/conformance` server
scenarios against Bifrost's real stdio MCP binary, and enforces that every
scenario the pinned conformance version publishes is deliberately classified.

Node 22, ES modules, no dependencies beyond the pinned conformance package.

## Running it

Install once (from this directory):

    npm ci

The gate, from the repository root:

    node crates/bifrost-mcp/tests/conformance/run.mjs

| invocation | what it does |
| --- | --- |
| `run.mjs` | schema drift + inventory drift + `cargo test -p brokk-bifrost-mcp --test mcp_wire_schema` + the applicable and expected-failure scenarios |
| `run.mjs --ci` | the same without the Rust test (see below) |
| `run.mjs --full` | additionally runs every scenario triaged inapplicable, for a triage refresh; their results are reported but never gate |
| `run.mjs --check-inventory` | drift checks only, no scenario execution |
| `run.mjs --scenario <name>` | one scenario at its applicable revisions, printing every check; does not gate |
| `run.mjs --keep` | keep the per-run results directory even on success |

`--ci` skips the Rust test on purpose: CI's `mcp-contract` job already runs
`cargo test -p brokk-bifrost-mcp`, which builds and runs every test target in the
crate including `mcp_wire_schema`. Running it again in the Node step would double
the crate's compile and test time for no new information. Default mode (no flags)
does run it, so a local `run.mjs` is the complete gate; a missing
`mcp_wire_schema` target is a failure in default mode.

The server binary is `$CARGO_TARGET_DIR/debug/bifrost-mcp-test-server` (or
`target/debug/...`), built on demand. Override with `BIFROST_MCP_SERVER_BIN`.
Each scenario gets a fresh temporary workspace containing a small Python file, a
small Rust file, and a README, so search and resource tools have real content.

## Files

| file | purpose |
| --- | --- |
| `package.json`, `package-lock.json` | pin `@modelcontextprotocol/conformance` at exactly `0.2.0-alpha.11` |
| `extract-schemas.mjs` | extracts the four official spec schemas from the pinned bundle; default mode compares, `--write` regenerates. `run.mjs` imports the same functions, so the gate performs the identical comparison |
| `schemas/mcp-schema-<revision>.json` | the extracted schemas, checked in. The Rust `mcp_wire_schema` gate loads the two Bifrost supports from here |
| `bridge.mjs` | raw Streamable-HTTP-to-stdio relay (see honesty model below) |
| `run.mjs` | the gate orchestrator |
| `scenarios-applicable.json` | name -> `{proves}`: scenarios that pass today. A failure here fails the gate |
| `scenarios-inapplicable.json` | name -> `{rationale}`: scenarios outside Bifrost's advertised surface. Run only under `--full`, never gate |
| `scenarios-expected-failures.json` | name -> `{rationale, owner}`: scenarios that should apply but fail. A pass here fails the gate as stale triage |

These are JSON rather than YAML deliberately: the harness must not depend on the
conformance package's transitive `yaml` dependency, and JSON needs no parser.

## Triage model

Every scenario `conformance list --server` prints must be in exactly one state.
`run.mjs` fails on a scenario in none of the three files ("untriaged") or in two
("triaged twice"), and on a triage entry naming a scenario upstream no longer
lists. That is what makes a version bump surface new scenarios instead of
silently skipping them.

One state is automatic and needs no entry: a scenario whose bracket revision tags
intersect neither `2025-11-25` nor `2026-07-28` is inapplicable by revision.
Adding such a scenario to a triage file is itself an error, so the files cannot
accumulate entries for revisions Bifrost never negotiates.

Gate semantics per (scenario, revision):

| state | outcome | verdict |
| --- | --- | --- |
| applicable | pass | ok |
| applicable | fail | gate failure (regression; failing checks are printed) |
| applicable | judged nothing | gate failure (lost coverage) |
| expected-failure | fail | ok, one line naming the failing check ids |
| expected-failure | pass | gate failure (stale triage; promote it) |
| inapplicable | either | reported, never gates; only run under `--full` |

Granularity is the whole scenario, not the individual check. There is no
per-check baseline in v1. The visible cost is that a scenario which passes at one
revision and fails at another cannot be split: `prompts-list` is the current
example, and its `scenarios-inapplicable.json` entry says where the underlying
defect is gated instead. Add per-check baselining only if that stops being a
one-off.

## Honesty model: what the bridge does and does not prove

The official runner tests servers exclusively over Streamable HTTP (`--url`);
there is no stdio server mode. Bifrost has no HTTP transport. `bridge.mjs`
therefore sits between them and owns exactly the transport concerns stdio does
not have: HTTP status codes, SSE framing, the standalone GET stream, and a
session id minted on `initialize`.

What the bridge does **not** do is interpret MCP. A POST body is parsed once, to
read the JSON-RPC `id` and `method` for routing, and is re-serialized from that
same parsed value; the child's stdout lines are handled the same way on the
return path. No SDK types, no defaulting, no re-shaping. That is what makes the
runner's built-in `wire-schema-valid` check meaningful: it judges the bytes
Bifrost produced, not an SDK's re-serialization of them.

The consequence is that any requirement whose subject is the HTTP layer is a
statement about `bridge.mjs`, not about Bifrost. Mapping a JSON-RPC error code to
HTTP 400, returning 404 for a terminated session, rejecting a rebinding `Host`
header, validating `x-mcp-*` routing headers, resuming an SSE stream: the bridge
would have to inspect and interpret Bifrost's traffic to satisfy those, which is
exactly the property that keeps the wire-schema evidence honest. Those scenarios
are triaged inapplicable with that reason, including the ones that currently
pass (`server-sse-multiple-streams`), so a green result is never read as Bifrost
evidence.

One child process per bridge, and one bridge per (scenario, revision) pair.
Bifrost correctly rejects a second `initialize` on a connection, and independent
scenario clients would otherwise collide on JSON-RPC ids. Up to four pairs run
concurrently, each fully isolated.

## Bumping the conformance pin

1. `npm install @modelcontextprotocol/conformance@<version> --save-exact` in this
   directory, and commit both `package.json` and `package-lock.json`.
2. `node extract-schemas.mjs --write`, and review the schema diff. A changed
   schema changes what the Rust `mcp_wire_schema` gate enforces.
3. `node run.mjs --full`. Newly listed scenarios fail the inventory check as
   untriaged; scenarios upstream renamed or dropped fail as unknown entries.
4. Re-triage: add each new scenario to exactly one file, and re-classify any
   entry whose result changed. A scenario failing because a fixture tool is
   missing is **inapplicable**; a scenario failing on a real behavior of
   Bifrost's advertised surface is an **expected failure** with a rationale
   naming the failing check ids and an owner.
5. `node run.mjs` must exit 0 before the bump lands.

## Interpreting a fixture-tool result

The upstream server scenarios were written against an SDK fixture server: they
call tools named `test_simple_text`, `slow_compute`, `test_input_required_result_*`
and read resources under `test://`. Bifrost's tool surface is its real product
toolset, so those names do not resolve.

That does not make every such scenario worthless. Some of their checks accept
Bifrost's honest answer -- an `isError` tool result reading `Unknown tool: ...`
is a perfectly valid `CallToolResult` -- and the accompanying `wire-schema-valid`
check still validates Bifrost's real bytes. Those scenarios stay applicable, and
their `scenarios-applicable.json` entry says plainly what the pass proves and
that the fixture tool is absent. Scenarios whose checks require content Bifrost
cannot produce (image, audio, embedded resource, progress notifications,
sampling, elicitation, task creation) are inapplicable.
