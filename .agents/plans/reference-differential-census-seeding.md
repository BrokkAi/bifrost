# Census-seeded reference differential (breaking FIRD's self-referee blindness)


## Purpose

The reference-differential runner (FIRD, `crates/bifrost-analysis/src/reference_differential/mod.rs`) audits round-trip agreement: enumerate structured reference sites the analyzer already recognizes, forward-resolve each site to its declaration, and check the site appears in the inverse usage result. It has been highly productive (79 tracker issues since 2026-07-21), but it has a structural blind spot: it can only test sites the analyzer itself proposes. A construct the analyzer fails to parse as a reference at all — historically: items inside Rust `cfg_*!` macro blocks, `self`-receiver calls, Scala declarations after closed package blocks — produces no probe site, no forward/inverse disagreement, and therefore no signal, no matter how many usages are silently lost. The MCP property fuzzer (`.agents/plans/mcp_property_fuzzer.md`) has the same limit from the other side: its probes are generated from the index, so what the index cannot see, the fuzzer cannot ask about.

As of 2026-08-03 the open-bug residue concentrates in exactly this plane: six per-language inverse-usage misses (#1526 go, #1527 python, #1528 typescript, #1376 rust, #1537 cpp) plus cfg-gated shadowing (#1377). This plan adds a second, independent probe frontier: a census of raw identifier occurrences produced directly by tree-sitter tokenization, deliberately ignorant of the analyzer's index. Census sites that the tools cannot account for become ranked, triaged findings. The operating model matches the fuzzer campaign: an autonomous agent runs passes, triages by deterministic tiers, files issues with shrunk evidence, and stops when consecutive passes add no new failure signatures.

After this change, a contributor can run the differential on a repository with `--probe-seed census` and receive a ledger of usage-loss candidates ranked by evidence tier, each carrying the census site, the tool responses that fail to account for it, and (for the top tier) a self-contained contradiction requiring no external referee at all.


## Definitions

"Census" means the set of identifier-token occurrences in a repository's source files, produced by walking tree-sitter parse trees and collecting identifier-class leaf nodes with their byte ranges and enclosing-scope path. It is computed by a new module that depends only on the grammars — not on the analyzer's declaration index — so it sees occurrences the index misses. Comments and string contents are excluded by node kind, not by heuristics.

"Seed" means the generator that proposes probe sites to the differential. Today FIRD has one seed: the analyzer's structured reference candidates (`reference_candidate_ranges`). This plan makes the seed pluggable — `--probe-seed index` (today's behavior, unchanged) or `--probe-seed census`.

"Joint blindness" means both the forward path and the inverse path fail on the same construct, producing agreement (both see nothing) that a differential misreads as health. Census seeding exists to break joint blindness: the census proposes the site anyway, and both paths failing on a real occurrence *is* the finding.

"Tier" means the deterministic evidence grade assigned to a census gap before any referee is consulted; tiers are defined in the triage section. "Referee" means an external adjudicator (an LSP server, or a lightweight LLM classifier) consulted only for the residue the tiers cannot settle.

"Failure signature", "shrinking", and "ledger" carry the same meanings as in `.agents/plans/mcp_property_fuzzer.md`: dedup key `(tier, language, syntactic shape)`, minimal reproduction, append-only JSONL with single-line rerun.


## What the census check proves

For each census occurrence of name N at site S (file, byte range), with the occurrence's syntactic role from the tree-sitter node context (call receiver-member, bare call, type position, declaration, local binding, field access):

1. Declarations and local bindings are excluded up front (the census records them for scope analysis but they are not usage probes).
2. Forward: ask the current forward-resolution path what S refers to. This is the same entry FIRD uses today; census seeding changes only where S came from.
3. If forward resolves S to declaration D: run the inverse usage query for D and check S is covered — identical to FIRD's existing comparison. A miss here is FIRD's classic finding, now reachable at sites the index never proposed. This subsumes the "census-seeded self-referee" idea: the forward path adjudicates the site, and forward-vs-inverse disagreement is ticket-grade with no external referee.
4. If forward cannot resolve S: the site enters gap triage (below). This is the joint-blindness residue — the cases FIRD structurally never sees.

Additionally, census enables the inverse-precision check FIRD has never had: every site returned by an inverse usage query must correspond to a census occurrence of N or of a known alias of D. An inverse hit with no census occurrence at its range is a fabricated or misattributed usage — a finding class currently untested in either direction. (Alias knowledge is limited today — Bifrost emits no alias sets — so this check starts name-literal-only and tightens if/when alias emission lands under the #1475 identity work.)


## Gap triage tiers

Tier 1 — same-scope receiver/member evidence, no referee needed. The occurrence is a member-call or field-access of name N, a declaration of N exists in the same file or same module per the census's own scope walk, and no local binding of N shadows the site. Historical calibration: both #1014 repro sites (`self.as_mut().poll_elapsed(cx)` with the definition 70 lines above; `self.poll_next_many(...)` in the same impl block) are tier 1. If the inverse query for the same-scope declaration additionally claims `verified_absent`, escalate severity: a confident wrong claim outranks a mere miss.

Tier 2 — same-module or import-connected evidence. A declaration of N exists in the module the census scope-walk associates with the site, or the file has an import whose terminal name is N. Weaker than tier 1 (aliasing and shadowing get more plausible) but still deterministic.

Tier 3 — everything else: same-name declarations exist only in unrelated modules, or nowhere. Tier 3 is exploration-grade; it is ranked by census-count heuristics (a name with one declaration and forty unaccounted occurrences outranks a name with forty declarations) and is the only tier where a referee earns its cost.

Referees for tier 3 residue, in preference order: an LSP where wiring is cheap and buildless (rust-analyzer, gopls, tsserver), consulted offline against the shrunk ledger rows only, never inline in the pass; a lightweight LLM classifier for the heavy-wiring languages, whose verdict is used for ranking only — the source evidence, not the verdict, goes into any filed issue — with verdicts cached by shrunk-repro hash so classifier nondeterminism cannot resurrect signatures and break run-until-dry termination. Referee integration is milestone 4 and is optional to the core value: tiers 1 and 2 plus the forward-adjudicated misses are expected to carry most of the yield (they cover every historical exemplar this plan was designed around).


## Non-goals and boundaries

The census cannot propose reference sites that carry no token of the target's name: aliased imports at use sites, re-exports under new names, constructor/`apply` sugar, operator references, generated members (the Lombok class). Those remain exclusively the index seed's frontier — which is why this plan adds a seed instead of replacing one. Do not retire `--probe-seed index`.

Schema/contract drift detection is out of scope: census probe encoding is necessarily written against the current build's argument shapes, so it moves with the surface. The frozen trace-replay suite that catches drift is a separate, smaller artifact and deliberately not part of this plan.

Wholesale re-adjudication of tier 3 across the corpus is out of scope for the initial build; tier 3 exists in the ledger from milestone 2 but referee wiring is the final milestone and may be cut if tiers 1-2 saturate the fix pipeline on their own.


## Milestones

**M1 — Census module and tier-1-only pass on one language.** New module (suggest `crates/bifrost-analysis/src/reference_differential/census.rs`): tree-sitter identifier walk producing occurrences with byte range, node-role classification, and a lightweight scope path; exclusion of declaration/local-binding occurrences; the tier-1 gap check (same-file/same-module declaration, shadow check) with no tool calls at all beyond the inverse query for tier-1 candidates. CLI: extend the FIRD driver with `--probe-seed census --tiers 1`. Acceptance: on tokio at the corpus pin, the pass reports the #1014-class shape as covered (those instances are fixed — the acceptance is that the *machinery* proposes those exact sites and finds them now-covered), and a fixture repo containing a deliberately unindexed same-file receiver call yields one tier-1 finding. Fixture-fires-and-healthy-stays-silent is required per invariant-testing convention.

**M2 — Forward adjudication, full tiers, ledger integration.** Census sites flow through the existing forward-resolution and inverse-comparison paths (`--probe-seed` pluggability inside `run`'s site-collection stage, around the current `reference_candidate_ranges` call); forward-resolved census misses land in the standard FIRD report schema tagged `seed: census`; unresolved sites get tier-2/3 classification; signatures, shrinking, and single-line rerun follow the fuzzer's conventions. Acceptance: one full pass on a rust and a go corpus repo produces a tiered ledger; every tier-1/2 row reruns deterministically.

**M3 — Inverse-precision check and corpus runner.** The census-membership check over inverse results (name-literal matching), sharded corpus execution reusing the fuzzer's `--shard` pattern, per-language ranking from the established corpus tooling. Acceptance: corpus pass over the top-N repos of two languages; any inverse hit not backed by a census occurrence surfaces as its own signature class.

**M4 — Referee integration for tier 3 (optional, cuttable).** Offline LSP adjudication for rust/go/ts ledger rows; cached LLM classification for the rest; both feeding rank only. Acceptance: a tier-3 ledger slice gets referee annotations and at least one referee-ranked finding is confirmed by hand to be a genuine miss.

**Campaign.** Run per-language passes tier-1-first (highest precision, zero referee cost), triage and file with the same discipline as the fuzzer campaign, and declare dry per seed: two consecutive full passes with no new signatures. Track campaign state in this file's Progress section.


## Validation

`cargo test` green throughout; census walk and tier classification get unit tests per language grammar quirk they encode (shadowing, module scoping); every tier check needs a firing fixture and a silent healthy fixture; clippy clean per repo convention. The open inverse-usage issues (#1526, #1527, #1528, #1376, #1537, #1377) double as live acceptance material: each names a construct the census should propose and triage — record in the ledger whether the census pass independently rediscovers each one, and treat any it cannot reach as a documented census limitation in this plan.


## Decision log

- 2026-08-03: Plan authored (design originated 2026-07-21 in a P2T trace-audit discussion; captured now, after the fuzzer campaign's tiers 1-7, because the residual open-bug mass concentrates in the joint-blindness plane this seed targets and the fix pipeline has spare capacity — 396 closed vs 351 opened since 2026-07-21).
- Seed pluggability inside FIRD rather than a separate tool: the forward/inverse machinery, report schema, and agent adjudication workflow are identical; only site enumeration differs. Keeping `--probe-seed index` is load-bearing — name-less reference classes (aliases, sugar, generated members) are reachable only from the index side.
- Trace replay demoted out of this plan entirely: as an exploration seed it is census-subset-or-hallucination; its real value (frozen-encoding drift detection, live spelling distributions for the fuzzer's I2/I5 probe sets) belongs to two small separate artifacts.
- Referee is rank-only and offline: verdicts never become ticket evidence (source snippets do), and caching by shrunk-repro hash protects run-until-dry termination from classifier nondeterminism.
- Inverse-precision starts name-literal-only: Bifrost currently emits no alias sets (verified 2026-08-03: `canonical_selector` exists only on `SourceBlock`, no alias enumeration anywhere); if alias emission lands via the #1475 identity work, tighten the check to alias chains.


## Progress

- [ ] M1: census module, tier-1 check, `--probe-seed census --tiers 1`, tokio + fixture acceptance
- [ ] M2: forward adjudication of census sites, tiers 2-3 classification, ledger/shrink/rerun integration
- [ ] M3: inverse-precision check, sharded corpus runner, two-language corpus pass
- [ ] M4 (optional): offline referee wiring for tier 3
- [ ] Campaign: per-language tier-1-first passes; rediscovery audit against #1526/#1527/#1528/#1376/#1537/#1377
