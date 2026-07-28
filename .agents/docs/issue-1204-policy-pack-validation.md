# Issue #1204 built-in policy-pack validation

Implementation checkpoint: `435e4bc9` on
`1204-epic-ship-a-built-in-rqlp-code-smell-and-performance-policy-pack`. This
record covers the subsequent review fixes on the same branch as well.

## Shipped surface

- Embedded pack ID: `bifrost.code-smells`, manifest schema 1, pack version 1.1.0.
- Twelve canonical `.rqlp` sources with checked semantic hashes: two correctness
  rules and ten structural performance review rules.
- The sort rule retains one language-neutral selector unchanged across Python,
  Java, TypeScript, and TSX source paths and adds the seven exact Rust slice
  `sort*` variants as one anchored normalized-name family.
- Deterministic selection by pack, category, or stable policy ID.
- One mixed coordinator for embedded and workspace-file inputs.
- CLI discovery and selection through `--list-policies`, `--policy-pack`,
  `--policy-category`, and `--policy-id`.
- Rootless MCP discovery through argument-validated `list_policies` and the same
  bounded selectors on `run_policy`.
- Crate archive presence checks plus staged-plugin MCP listing/execution smoke.

## Focused evidence

The shared inferred-language fixture uses one analyzer snapshot for Python,
Java, JavaScript, TypeScript, and Rust. Every claimed policy/language pair has a
positive source file and a structurally similar outside-loop or safe-API near
miss. The corpus exercises every selector alternative (including root and
nested TSX positives and near misses for the language-neutral sort rule) and
asserts exact finding lines, so one surviving match in a shared file cannot
hide a broken or broadened branch. It also locks the current declaration-crossing behavior as an
explicit lexical positive and proves that `yaml.safe_load` plus
`yaml.load(..., Loader=yaml.SafeLoader)` are not reported. All twelve runs
complete and the near-miss files produce no findings.

Rust coverage is deliberately API-specific. Eight policies now cover slice
sorting, `Regex::new`, whole-file `fs` reads, the exact `serde_json` and
`bincode` entry points listed in the public policy docs, `toml::from_str`,
direct `reqwest` / `ureq` requests, `thread::sleep`, and nested-loop file reads.
Database and subprocess
rules remain unclaimed for Rust because the current structural facts cannot
prove the receiver type of generic instance methods such as `execute`,
`spawn`, `status`, or `output`. Dynamic evaluation and unsafe deserialization
also have no defensible Rust equivalent in this catalog.

Passing commands during implementation:

```text
cargo test --test builtin_policy_pack -- --nocapture
cargo test --lib run_policy_schema_requires_bounded_mixed_inputs
cargo test --lib checked_in_catalog_is_internally_consistent
cargo test --lib list_policies_is_rootless_and_rejects_nonempty_arguments
cargo test --test bifrost_policy_cli built_in -- --nocapture
cargo test --test bifrost_policy_cli unknown_built_in_selector_is_a_policy_invocation_error -- --exact --nocapture
cargo test --test bifrost_mcp_server bifrost_mcp_lists_and_runs_built_in_policies -- --exact --nocapture
cargo test --test bifrost_mcp_server bifrost_split_servers_publish_expected_tool_sets -- --exact --nocapture
cargo test --test bifrost_policy_cli
cargo test --test bifrost_mcp_server
cargo test --test policy_docs
cargo fmt --check
scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
scripts/with-isolated-cargo-target.sh scripts/check-crate-package.sh
```

The final focused reruns passed all 6 built-in pack tests, all 23 policy CLI
tests, all 29 MCP server tests, and the rootless `list_policies` unit test.
Pack and category execution are covered through both host surfaces, with the
complete canonical run ordering asserted rather than only the batch length.

The MCP built-in test also compares the complete canonical CLI report with the
MCP report for the same pinned fixture, including hashes, finding IDs,
locations, completion, and diagnostics.

The strict Clippy run used rustup's Cargo and `cargo-clippy` from one toolchain;
the default shell otherwise paired rustup Cargo with Homebrew `cargo-clippy`
artifacts built by a different LLVM patch level. The Rust-increment rerun pinned
both tools to rustup and passed strict all-target/all-feature Clippy. Package
validation archived all 1,500 expected files, verified the packaged crate, and
produced an 8.9 MiB archive under the 10 MB compressed-size budget. The staged plugin smoke passed launcher
resolution, the recorded Codex handshake, MCP roots, and built-in policy
listing/execution from an empty plugin cache.

The CI-configured host-side full gate used Python 3.13 plus macOS PyO3 dynamic
lookup flags. It passed all 2,011 enabled library tests with seven intentional
ignores, all binary unit tests, and every integration target reached before
`bifrost_lsp_server_scala_semantic_diagnostics_are_runtime_opt_in`. That
unchanged test then waited indefinitely for
`textDocument/publishDiagnostics`. Its exact standalone invocation reproduced
the same wait for more than three minutes, so the run was interrupted. This is
an exact environment/runtime blocker rather than a policy-pack assertion or
compile failure.

The full twelve-policy fixture evaluation completed in 0.12 seconds after the
small analyzer snapshot was built. This number describes the synthetic policy
corpus, not self-repository startup or production p95 latency.

The Rust expansion reran the exact selector corpus after replacing repeated
same-receiver union branches with finite anchored normalized-name predicates.
Every individual Rust API alternative still has an exact expected source line,
and all outside-loop and near-miss Rust calls remain clean.

The final task-level policy check could not use the checked-in
`bifrost-policy-checking` MCP workflow because this Codex task exposed neither
`list_policies` nor `run_policy`. The user-requested CLI dogfood fallback ran
the complete `bifrost.code-smells` pack with evaluation date 2026-07-28 and
`fail-on warning`; there are no canonical repository-defined policy roots
outside fixtures and the embedded pack. The report retained 134 review
findings, had no suppression document, completed seven policies, and marked
five performance policies inconclusive with `execution_budget_exhausted`
(two also reported `stable_anchor_unavailable`). No finding points at a file
changed by this Rust-policy increment. Per the skill contract, this is an
unreliable policy result rather than a green check; #1246 owns the repeated
union seed work.

## Performance observations

An exact current-plugin `get_symbol_sources` call for four symbols completed
successfully in 6.883 seconds in a warm task session. The exact arguments and
environment were added to open performance issue #1228:
<https://github.com/BrokkAi/bifrost/issues/1228#issuecomment-5101473436>.

Two debug-binary self-repository policy profiles did not complete inside an
interactive budget and were cancelled:

- all twelve policies with `BIFROST_PARALLELISM=1`: 213.99 seconds wall,
  66.95 seconds user CPU;
- the dynamic-evaluation policy alone with default parallelism: 134.25 seconds
  wall, 35.51 seconds user CPU.

These runs include `WorkspaceAnalyzer::build` and shared-cache interaction, so
they do not isolate selector cost and are not a release-mode benchmark. They do
show that one-shot self-repository policy startup is not currently interactive;
#1228 owns the cross-tool sub-five-second latency and head-of-line investigation.
The staged release smoke deliberately uses a disposable small workspace and an
already-running MCP process.

## Capability gaps and rejected candidates

- #1232, <https://github.com/BrokkAi/bifrost/issues/1232>, owns
  declaration-bounded containment. Current lexical `inside (loop)` descends
  through a nested callable declaration. A minimized deferred Python `open()`
  body is retained as a tested lexical positive, and every affected rule now
  says explicitly that it is a review prompt requiring execution/invariance
  verification rather than proof that the call executes per iteration.
- #1233, <https://github.com/BrokkAi/bifrost/issues/1233>, owns an explicit
  non-exhaustive proven-only call-policy contract. A real bounded call-graph
  candidate retained exact direct and second-order caller findings but also
  emitted `CALL_RELATION_CANDIDATES_OMITTED`, making the run inconclusive. The
  candidate was removed rather than making the built-in batch unreliable or
  weakening completeness semantics.
- #824 owns source-backed CFG/data-flow/query-policy exposure, and #1205 owns
  the cross-language exact value-flow readiness gate. No file-level projection
  was used to simulate a semantic finding.
- #1246, <https://github.com/BrokkAi/bifrost/issues/1246>, owns structural seed
  sharing across RQL union branches. A fresh Bifrost self-scan proved that the
  multi-language performance category can exceed the fixed two-million-fact
  per-policy budget even after Rust alternatives with the same receiver were
  collapsed. Exact findings are retained, but five runs become inconclusive;
  global hard caps were not raised to hide the repeated work.

These blockers mean the branch delivers #1204's release-bundled structural
wave, CLI/MCP surface, and rule-authoring protocol, but not the epic's required
bounded-call, CFG, and data-flow policy inventory. The epic should remain open
until #1233 and #824/#1205 make that semantic wave release-quality.

## Release boundary

The changes make the branch daily-release-ready by validating archive contents
and exercising the staged binary. No version bump, tag, package publication,
deployment, or scheduled release was performed; those remain explicit release
operations.
