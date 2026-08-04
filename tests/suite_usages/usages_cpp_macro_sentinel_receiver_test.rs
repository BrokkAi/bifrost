use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching C++ declaration in {declarations:#?}"))
}

fn authoritative_exact_ranges(
    analyzer: &CppAnalyzer,
    targets: &[CodeUnit],
    candidate: &ProjectFile,
) -> BTreeSet<(usize, usize)> {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(analyzer, targets, Some(&provider), 1, 1000);
    assert_eq!(
        query.candidate_files,
        std::iter::once(candidate.clone()).collect(),
        "authoritative query must remain limited to the explicit fixture"
    );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative C++ success")
    };
    hits_by_overload
        .values()
        .flatten()
        .map(|hit| {
            assert_eq!(&hit.file, candidate);
            (hit.start_offset, hit.end_offset)
        })
        .collect()
}

fn fixture_token_range(source: &str, labeled_line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(labeled_line)
        .unwrap_or_else(|| panic!("missing fixture line {labeled_line:?}"));
    let token_start = labeled_line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {labeled_line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}

#[test]
fn authoritative_cpp_undefined_namespace_sentinel_recovers_cord_receiver_chains() {
    let source = include_str!("../fixtures/cpp_macro_sentinel_cord_receivers.h");
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cord_receivers.h", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("cord_receivers.h");

    let edge = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.fq_name() == "absl::cord_internal.CordRepBtree$CopyResult.edge"
            && unit.source() == &file
    });
    let as_chars = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.fq_name() == "absl::cord_internal.InlineData.as_chars"
                && unit.source() == &file
        })
        .collect::<Vec<_>>();
    assert!(
        !as_chars.is_empty(),
        "missing InlineData::as_chars overloads"
    );

    let edge_positive = fixture_token_range(
        source,
        "  prefix.edge = CordRepBtree::New(prefix.edge);",
        "edge",
    );
    let edge_near_miss = fixture_token_range(source, "  prefix.edge = 1", "edge");
    let chars_positive = fixture_token_range(source, "  data_.as_chars();", "as_chars");
    let chars_near_miss = fixture_token_range(source, "    data.as_chars();", "as_chars");

    let edge_hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&edge), &file);
    assert!(
        edge_hits.contains(&edge_positive),
        "CopyResult alias receiver must resolve to CordRepBtree::CopyResult::edge: {edge_hits:?}"
    );
    assert!(
        !edge_hits.contains(&edge_near_miss),
        "same-name CopyResult::edge in unrelated namespace must not match: {edge_hits:?}"
    );

    let chars_hits = authoritative_exact_ranges(&analyzer, &as_chars, &file);
    assert!(
        chars_hits.contains(&chars_positive),
        "nested Cord::InlineRep receiver must resolve to cord_internal::InlineData::as_chars: {chars_hits:?}"
    );
    assert!(
        !chars_hits.contains(&chars_near_miss),
        "same-name InlineData::as_chars in unrelated namespace must not match: {chars_hits:?}"
    );
}
