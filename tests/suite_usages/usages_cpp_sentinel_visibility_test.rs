use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language, ProjectFile};
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
        "authoritative query must remain limited to the fixture"
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

fn token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    token_range_occurrence(source, line, token, 0)
}

fn token_range_occurrence(
    source: &str,
    line: &str,
    token: &str,
    occurrence: usize,
) -> (usize, usize) {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .match_indices(token)
        .nth(occurrence)
        .map(|(start, _)| start)
        .unwrap_or_else(|| {
            panic!("missing token occurrence {occurrence} {token:?} in fixture line {line:?}")
        });
    let start = line_start + token_start;
    (start, start + token.len())
}

#[test]
fn authoritative_cpp_namespace_sentinel_recovers_cord_rep_nullability_types() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "cord_internal.h",
            "namespace absl { namespace cord_internal { class CordRep { public: static CordRep* Ref(CordRep*); }; } }\n",
        )
        .file(
            "cord_rep.cc",
            include_str!("../fixtures/cpp_macro_sentinel_cord_rep.h"),
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("cord_rep.cc");
    let source = file.read_to_string().expect("cord rep fixture source");
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::cord_internal.CordRep"
            && unit.source() == &project.file("cord_internal.h")
    });

    let verify_return = token_range(
        &source,
        "static inline CordRep* absl_nullable VerifyTree(CordRep* absl_nullable node) {",
        "CordRep",
    );
    let take_return = token_range(
        &source,
        "static inline CordRep* absl_nonnull TakeRep(CordRep* absl_nonnull node) {",
        "CordRep",
    );
    let take_parameter = token_range_occurrence(
        &source,
        "static inline CordRep* absl_nonnull TakeRep(CordRep* absl_nonnull node) {",
        "CordRep",
        1,
    );
    let unrelated = token_range(
        &source,
        "static CordRep* absl_nullable VerifyTree(CordRep* absl_nullable node) {",
        "CordRep",
    );
    let verify_parameter = token_range_occurrence(
        &source,
        "static inline CordRep* absl_nullable VerifyTree(CordRep* absl_nullable node) {",
        "CordRep",
        1,
    );
    let hits = authoritative_exact_ranges(&analyzer, std::slice::from_ref(&target), &file);
    assert!(
        [verify_return, verify_parameter, take_return, take_parameter]
            .iter()
            .all(|expected| hits.contains(expected)),
        "nullability-annotated CordRep return and parameter types must resolve: hits={hits:#?}"
    );
    assert!(
        !hits.contains(&unrelated),
        "same-spelled CordRep in unrelated namespace must remain excluded: hits={hits:#?}"
    );
}

#[test]
fn authoritative_cpp_duplicate_cord_rep_btree_target_keeps_guarded_definition_owner() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "cpp_macro_sentinel_cord_rep_btree_forward.h",
            include_str!("../fixtures/cpp_macro_sentinel_cord_rep_btree_forward.h"),
        )
        .file(
            "cpp_macro_sentinel_cord_rep_btree_full.h",
            include_str!("../fixtures/cpp_macro_sentinel_cord_rep_btree_full.h"),
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let full_file = project.file("cpp_macro_sentinel_cord_rep_btree_full.h");
    let source = full_file
        .read_to_string()
        .expect("cord rep btree fixture source");
    let full_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::cord_internal.CordRepBtree"
            && unit.source() == &full_file
            && !unit.is_synthetic()
    });
    let forward_file = project.file("cpp_macro_sentinel_cord_rep_btree_forward.h");
    let forward_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::cord_internal.CordRepBtree"
            && unit.source() == &forward_file
            && !unit.is_synthetic()
    });
    assert_ne!(
        full_target, forward_target,
        "physical duplicate declarations must remain distinct"
    );

    let return_type = token_range(
        &source,
        "inline const CordRepBtree* CordRepBtree::AssertValid(",
        "CordRepBtree",
    );
    let owner = token_range_occurrence(
        &source,
        "inline const CordRepBtree* CordRepBtree::AssertValid(",
        "CordRepBtree",
        1,
    );
    let parameter = token_range(&source, "    const CordRepBtree* tree) {", "CordRepBtree");
    let hits = authoritative_exact_ranges(
        &analyzer,
        &[forward_target.clone(), full_target.clone()],
        &full_file,
    );
    assert!(
        [return_type, owner, parameter]
            .iter()
            .all(|expected| hits.contains(expected)),
        "guarded out-of-line definition must stay attached to full CordRepBtree: hits={hits:#?}"
    );
}
