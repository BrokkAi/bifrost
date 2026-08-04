# Adding a language

The post-registry procedure, from `.agents/plans/analysis-language-registry-spi.md`
milestone 1. It is short on purpose: if this document starts growing, the SPI has regressed
and the fix belongs in `LanguageSupport`, not here.

## 1. Implement `LanguageSupport`

In `crates/bifrost-analysis/src/analyzer/<lang>/mod.rs`, add a unit struct `<Lang>Support`
and `impl LanguageSupport for <Lang>Support`. Eight methods have no default and must be
answered: `language`, `ecosystem`, `usage_strategy`, `forward_query_provider`,
`declaration_ranges_limited`, `parser_language`, `structural_spec`, `highlight_query`.

Every other method has a default, and each default is a documented behavior rather than a
stub. Leaving one alone asserts something about the language: no edge pass means it
contributes no workspace edges, no `structural_receiver` means receiver queries report
`receiver_analysis_language_unsupported`, no `type_lookup` means location queries report
`TypeLookupStatus::UnsupportedLanguage`. Read the doc comment before overriding, and again
before not overriding.

## 2. Register it

Add the arm to `language_support` in `analyzer/languages.rs`. The match is exhaustive with
no wildcard, so the new `Language` variant will not compile until it is there.

## 3. Add the assembly-layer variant

In `analyzer/multi_analyzer.rs`: an `AnalyzerDelegate` variant holding the concrete
analyzer, its arms in the delegate's provider accessors, and a `build_delegate!` arm in
`build_language_delegate`. This is the one place outside the registry allowed to name a
concrete per-language analyzer type; the source gate
(`tests/suite_cross_language/language_reach_in_gate.rs`) enforces that everywhere else.

## 4. Register the semantic lowerer

Implement `ProgramSemanticsProvider` for the analyzer and add its
`AnalyzerDelegate::program_semantics_provider` arm.

## 5. Update the capability snapshot

Run the registry unit tests. `the_capability_matrix_matches_its_snapshot` fails with the
new row; paste it into `CAPABILITY_MATRIX` after checking each column says what the
language means to claim.

Done. Nothing else in `bifrost-analysis` needs to learn the language exists.
