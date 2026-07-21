mod common;

use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder, UsageHit};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, ProjectFile, RustAnalyzer};
use common::InlineTestProject;
use std::collections::BTreeSet;
use std::sync::Arc;

fn target(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn authoritative_hits(
    analyzer: &RustAnalyzer,
    target: &CodeUnit,
    files: HashSet<ProjectFile>,
) -> BTreeSet<UsageHit> {
    let provider = ExplicitCandidateProvider::new(Arc::new(files));
    match UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            100,
            100,
        )
        .result
    {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected authoritative Rust usage success, got {other:#?}"),
    }
}

fn terminal_range(source: &str, expression: &str, terminal: &str) -> (usize, usize) {
    let expression_start = source.find(expression).expect("macro path expression");
    let terminal_start = expression.rfind(terminal).expect("terminal path segment");
    let start = expression_start + terminal_start;
    (start, start + terminal.len())
}

#[test]
fn dollar_crate_macro_paths_preserve_crate_root_identity() {
    let macro_source = r#"
macro_rules! generated {
    () => {{
        $crate::support::enabled();
        let _: $crate::support::Name;
        let _: &dyn $crate::Visit;

        $crate::decoy::enabled();
        let _: $crate::decoy::Name;
        let _: &dyn $crate::decoy::Visit;

        $crate::span!();
    }};
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "fixture/Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "fixture/src/lib.rs",
            r#"
mod macros;

pub mod support {
    pub fn enabled() {}
    pub struct Name;
}

pub trait Visit {}

pub mod decoy {
    pub fn enabled() {}
    pub struct Name;
    pub trait Visit {}
}

pub mod span {}

#[macro_export]
macro_rules! span {
    () => {};
}
"#,
        )
        .file("fixture/src/macros.rs", macro_source)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let macro_file = project.file("fixture/src/macros.rs");
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();

    for (fq_name, expression, terminal, decoy) in [
        (
            "fixture.src.support.enabled",
            "$crate::support::enabled()",
            "enabled",
            "$crate::decoy::enabled()",
        ),
        (
            "fixture.src.support.Name",
            "$crate::support::Name",
            "Name",
            "$crate::decoy::Name",
        ),
        (
            "fixture.src.Visit",
            "$crate::Visit",
            "Visit",
            "$crate::decoy::Visit",
        ),
    ] {
        let hits = authoritative_hits(&analyzer, &target(&analyzer, fq_name), candidates.clone());
        let expected = terminal_range(macro_source, expression, terminal);
        let unrelated = terminal_range(macro_source, decoy, terminal);

        assert!(
            hits.iter().any(|hit| {
                hit.file == macro_file && (hit.start_offset, hit.end_offset) == expected
            }),
            "{fq_name} should include its exact $crate macro-body path: {hits:#?}"
        );
        assert!(
            hits.iter().all(|hit| {
                hit.file != macro_file || (hit.start_offset, hit.end_offset) != unrelated
            }),
            "{fq_name} must not include the same-named decoy: {hits:#?}"
        );
    }

    let span_definitions = analyzer.get_definitions("fixture.src.span");
    assert!(
        span_definitions.iter().any(CodeUnit::is_macro),
        "fixture must contain the same-FQN span macro"
    );
    let span_module = span_definitions
        .into_iter()
        .find(CodeUnit::is_module)
        .expect("same-FQN span module");
    let span_hits = authoritative_hits(&analyzer, &span_module, candidates);
    let macro_terminal = terminal_range(macro_source, "$crate::span!", "span");
    assert!(
        span_hits.iter().all(|hit| {
            hit.file != macro_file || (hit.start_offset, hit.end_offset) != macro_terminal
        }),
        "$crate::span! is a macro invocation, not a reference to the same-named module: {span_hits:#?}"
    );
}
