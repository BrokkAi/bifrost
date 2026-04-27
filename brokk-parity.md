# Brokk Parity Notes

This file records the Brokk commits used as parity anchors for Bifrost's Analyzer and SearchTools ports, plus the follow-up Brokk changes reviewed on 2026-04-27.

## Merge Points

### 1. Initial implementation, 2026-03-24

Bifrost's first Analyzer/SearchTools implementation was a snapshot-style port of the Brokk analyzer-backed surface, not a literal cherry-pick of individual Java commits. The latest relevant Brokk commit before the Bifrost implementation window was:

- `6101d54f66` (2026-03-21) `enh: prioritize syntax-aware tools in search prompts and tool descriptions`

Important Brokk Analyzer/SearchTools commits represented in that initial snapshot include:

- `7b7f3fc182` (2025-08-06) `TreeSitter Java Analyzer (#585)`
- `55d231b9fb` (2025-10-29) `Overhaul analyzer APIs and adopt CodeUnit across tools (#1579)`
- `3304aa950a` (2026-01-21) `Consolidate Analyzer capabilities into IAnalyzer and remove CallGraph (#2413)`
- `3d0bbe70db` (2026-01-23) `refactor: rename buildRelatedIdentifiers to summarizeSymbols`
- `a7e146bfb9` (2026-02-13) `feat: add searchFileContents, xpathQuery, and jq tools`
- `b8a1db5618` (2026-02-24) `fix + perf: optimize search tools with batching and result limits`
- `1d9da7e8e0` (2026-02-27) `enh: overhaul SearchTools file content searching`
- `ff7e67f93b` (2026-02-27) `enh: List-ify search tools`
- `3da7c7a793` (2026-03-11) `feat: replace skimDirectory with glob-based skimFiles tool`
- `288a5f3e6c` (2026-03-11) `perf: parallelize definition searching in SearchTools`
- `34430ebf35` (2026-03-13) `perf: optimize searchFileContents`
- `f386c8641b` (2026-03-19) `Improve MCP tool descriptions with workflow guidance and cross-references (#3147)`

The corresponding Bifrost implementation commits are the 2026-03-24 analyzer/searchtools sequence from `44d4a26` through `012c7d8`, with follow-up transport changes in `2801e84` and `5ad77c9`.

### 2. Targeted Analyzer pass, 2026-04-04 through 2026-04-08

This pass focused on targeted Analyzer changes discovered after the initial implementation. The most relevant Brokk commits were:

- `d8e6aa37c2` (2026-04-07) `Use Defensive Child/Parent Tracking in FileAnalysisAccumulator and IAnalyzer (#3260)`
- `4260596066` (2026-04-06) `enh: Add SFT workspace and patch formatting server to SftServer`
- `16be41757c` (2026-04-08) `fix: exclude function-local Go declarations from summaries`
- `01557b4139` (2026-04-08) `fix: exclude function-local Go declarations from summaries`
- `d0f073e4f2` (2026-04-08) `fix: capture grouped function-typed Go vars in summaries`
- `b0464af939` (2026-04-08) `fix: exclude function-local Go interface methods from summaries`
- `a622e99bd6` (2026-04-08) `fix: nest same-file Go receiver methods in summaries`
- `cc4223e8c0` (2026-04-08) `fix: capture generic Go receiver methods in summaries`
- `8ed548d875` (2026-04-08) `fix: include nested anonymous Go struct fields in summaries`
- `1e5e8cee1f` (2026-04-08) `fix: cover Go summary edge cases`
- `fbbbe27f21` (2026-04-08) `fix: avoid bogus ranges on replicated Go members`

The corresponding Bifrost commits include `2a599f1`, `6f9a265`, `3597cd0`, `d5efa5d`, `248b21d`, `2df819c`, `e71843f`, and `1b41e3f`. The Go summary edge-case port appears partial: Bifrost has receiver nesting, error-node recovery, external receiver methods, field ordering, preambles, and nested anonymous fields, but I did not find clear coverage for Brokk's grouped function-typed Go variable fix (`d0f073e4f2`) or the replicated-member range regression (`fbbbe27f21`).

### 3. SearchTools pass, 2026-04-27

This pass explicitly ported the latest Brokk SearchTools surface changes:

- `a44ba8337e` (2026-04-25) `Search tools improvements (#3286)`
- `df8f3ab50b` (2026-04-27) `fix: remove old getClassSkeletons that has been superceded by getSummaries`
- `d1cc95399e` (2026-04-27) `feat: selectFilesForDisplay prioritizes more-important files as determined by our relevance code`
- `d77839150a` (2026-04-27, branch `origin/optimize_selectFilesForDisplay`) `optimize selectFilesForDisplay`

The corresponding Bifrost commits are:

- `50713ff` `Port Brokk searchtools summary surface`
- `67a133c` `Port selectFilesForDisplay prompt wording`

## Analyzer Changes Reviewed After Merge Point 2

Brokk Analyzer commits reviewed from after the 2026-04-08 targeted pass through 2026-04-27:

- Already represented or Bifrost-local equivalent exists: Bifrost has its own 2026-04-23 analyzer performance pass (`c3a940a` through `04f4b4c`) covering clone allocation pressure, shared reverse import indexing, hash-backed state, child canonicalization, and file-read reductions.
- Worth incorporating: `d0f073e4f2` if grouped function-typed Go vars should appear in summaries. This is small and directly in the Analyzer/SearchTools summary surface.
- Worth incorporating: `fbbbe27f21` if Bifrost replicates source ranges onto synthesized sibling Go struct-field declarations. This should be verified with a focused Rust regression before porting because Bifrost's Go extraction is not a direct Java translation.
- Worth evaluating for feature parity, larger scope: `693d7a5909` adds JS/TS reference-graph usages with TSConfig alias resolution. This is relevant if Bifrost intends to grow `scan_usages`/usage-reference behavior, but it is not required for current SearchTools summary/source parity.
- Worth evaluating for feature parity, larger scope: Brokk's code-quality series (`b1124b2df4`, `4a3e862b0e`, `1f54234ee1`, `6b55d10f20`, `251bdbdc93`, `5033ee30e8`, `5d0f8b63c7`, `e1441ff258`, `1311bc8c07`, `7245523a17`, `ef2ecd91f8`, `99eb85a22a`, `91b8187479`, `e44c78d490`, `d241605e50`, `4a0049f240`, `321d7b753c`) adds comment-density, complexity, exception-smell, low-value-test, assertion-smell, and clone-detection APIs. These are Analyzer-adjacent but outside Bifrost's current analyzer-backed SearchTools surface.
- Probably not worth porting now: constant-extraction/refactor-only commits (`7ccee9dce3`, `8aa6facd12`, `ee6e4158ff`, `6c11f62326`, `de02db68aa`, `65bade94d7`) unless needed as prerequisites for a later behavior port.
- Probably not worth porting now: Brokk module/package ownership moves (`56a954baf4`, `a96bf81a62`, `2a87cc103e`) because Bifrost's Rust crate layout is intentionally different.
- Probably not worth porting now: Template Analyzer framework (`968d87e2e2`) unless Bifrost needs Angular/template language analysis.

## SearchTools Changes Reviewed After Merge Point 1

Brokk SearchTools commits reviewed from after the 2026-03-24 initial implementation through 2026-04-27:

- Already incorporated: `a44ba8337e`, `df8f3ab50b`, `d1cc95399e`, and `d77839150a` via Bifrost `50713ff` and `67a133c`.
- No Bifrost action recommended: `035d062b26` fixed Windows glob matching in Java `AlmostGrep`; Bifrost uses Rust path/glob handling instead of the Java implementation.
- No Bifrost action recommended: `1b969ebdba` and `58a5f9cf19` split Brokk MCP/server modules; Bifrost already has native MCP/PyO3 service boundaries.
- No Bifrost action recommended: `fdf5268ef2`/`ab8b22b74b` revert cycle and `67ca8fe17b` structured AI commit-message output are not SearchTools behavior Bifrost exposes.
- Watch only: `09d9366ad2` touched Brokk's app-level SearchTools for Java ACP parity, but the relevant public SearchTools behavior is covered by the later `a44ba8337e` pass.

## Recommended Follow-Ups

1. Add a focused Go analyzer regression for grouped function-typed `var` declarations, then port the `d0f073e4f2` behavior if the regression currently fails.
2. Add a focused Go analyzer regression for replicated anonymous struct-field sibling ranges, then port the `fbbbe27f21` behavior only if Bifrost currently assigns misleading ranges.
3. Treat JS/TS reference-graph usages and code-quality APIs as separate feature ExecPlans, not as parity cleanup for the current SearchTools surface.

## Evidence Commands

Key commands used for this review:

- `git log --date=short --pretty=format:'%h %ad %s' -- brokk-shared/src/main/java/ai/brokk/analyzer ...`
- `git log --date=short --pretty=format:'%h %ad %s' -- brokk-core/src/main/java/ai/brokk/tools/SearchTools.java ...`
- `git show --stat --oneline a44ba8337e df8f3ab50b d1cc95399e`
- `git show --stat --oneline 6b55d10f20 b1124b2df4 4a3e862b0e 1f54234ee1 693d7a5909 4a0049f240 321d7b753c`
- `rg -n "function-typed|anonymous|summarize_symbols|scan_usages|smell|clone|comment" src tests`
