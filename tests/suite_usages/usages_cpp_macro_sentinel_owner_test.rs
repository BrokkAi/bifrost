use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{
    CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile, TestProject,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
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

fn exact_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    candidate: &ProjectFile,
) -> BTreeSet<(usize, usize)> {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            1000,
        );
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
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}

fn fixture() -> (tempfile::TempDir, CppAnalyzer, ProjectFile) {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("cpp_macro_sentinel_btree.h");
    let temp = tempfile::tempdir().expect("fixture temp dir");
    let destination = temp.path().join("cpp_macro_sentinel_btree.h");
    fs::copy(&source, &destination).expect("copy btree fixture");
    let root = temp.path().canonicalize().expect("canonical fixture root");
    let project = TestProject::new(root.clone(), Language::Cpp);
    let analyzer = CppAnalyzer::from_project(project);
    let file = ProjectFile::new(root, "cpp_macro_sentinel_btree.h");
    (temp, analyzer, file)
}

#[test]
fn undefined_namespace_sentinel_recovers_nested_out_of_line_btree_aliases() {
    let (_temp, analyzer, file) = fixture();
    let source = file.read_to_string().expect("fixture source");
    let iterator = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::container_internal.btree$iterator"
            && unit
                .signature()
                .is_some_and(|signature| signature.contains("btree_iterator<node_type"))
            && unit.source() == &file
    });
    let node_type = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::container_internal.btree$node_type"
            && unit.source() == &file
    });
    let namespace_return_type = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::container_internal.ReturnType"
            && unit.source() == &file
    });
    let nested_return_type = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::container_internal.Outer$ReturnType"
            && unit.source() == &file
    });
    let outer_scoped_type = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::container_internal.ScopedType"
            && unit.source() == &file
    });
    let helper_scoped_type = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::container_internal::helper.ScopedType"
            && unit.source() == &file
    });
    let sibling_scoped_type = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::sibling_after_sentinel.ScopedType"
            && unit.source() == &file
    });

    let return_iterator = token_range(
        &source,
        "auto btree<P>::equal_range(const K& key) -> std::pair<iterator, iterator> {",
        "iterator",
    );
    let pair_iterator = token_range(
        &source,
        "  const std::pair<iterator, bool> lower_and_equal = lower_bound_equal(key);",
        "iterator",
    );
    let local_iterator = token_range(
        &source,
        "  const iterator lower = lower_and_equal.first;",
        "iterator",
    );
    let shadowed_iterator = token_range(
        &source,
        "    std::pair<iterator, bool> shadowed;",
        "iterator",
    );
    let local_node_type = token_range(&source, "  node_type* node = nullptr;", "node_type");
    let nested_leading_return = token_range(
        &source,
        "ReturnType Outer<P>::Inner::method() {",
        "ReturnType",
    );
    let helper_return_type = token_range(
        &source,
        "ScopedType use_scoped(ScopedType value) {",
        "ScopedType",
    );
    let sibling_return_type = token_range(
        &source,
        "ScopedType use_sibling(ScopedType value) {",
        "ScopedType",
    );
    let unrelated_iterator = token_range(
        &source,
        "void use_unrelated(typename btree<P>::iterator value,",
        "iterator",
    );

    let iterator_hits = exact_ranges(&analyzer, &iterator, &file);
    assert!(
        [return_iterator, pair_iterator, local_iterator]
            .iter()
            .all(|expected| iterator_hits.contains(expected)),
        "nested template arguments and plain out-of-line alias leaves must resolve exactly: hits={iterator_hits:#?}"
    );
    assert!(
        !iterator_hits.contains(&unrelated_iterator),
        "same-spelled alias in an unrelated namespace must stay excluded: hits={iterator_hits:#?}"
    );
    assert!(
        !iterator_hits.contains(&shadowed_iterator),
        "a block-local alias must shadow the owner alias: hits={iterator_hits:#?}"
    );

    let node_type_hits = exact_ranges(&analyzer, &node_type, &file);
    assert!(
        node_type_hits.contains(&local_node_type),
        "plain node_type leaf in the malformed-sentinel out-of-line body must resolve: hits={node_type_hits:#?}"
    );

    let namespace_return_hits = exact_ranges(&analyzer, &namespace_return_type, &file);
    assert!(
        namespace_return_hits.contains(&nested_leading_return),
        "a nested Outer::Inner leading return type must resolve from the recovered namespace scope: hits={namespace_return_hits:#?}"
    );
    let nested_return_hits = exact_ranges(&analyzer, &nested_return_type, &file);
    assert!(
        !nested_return_hits.contains(&nested_leading_return),
        "the nested Outer::ReturnType near-miss must not capture a namespace-scope leading return type: hits={nested_return_hits:#?}"
    );

    let helper_return_hits = exact_ranges(&analyzer, &helper_scoped_type, &file);
    assert!(
        helper_return_hits.contains(&helper_return_type),
        "a reference in a parser-visible nested namespace must retain its helper namespace owner: hits={helper_return_hits:#?}"
    );
    let outer_scoped_hits = exact_ranges(&analyzer, &outer_scoped_type, &file);
    assert!(
        !outer_scoped_hits.contains(&helper_return_type),
        "the outer ScopedType near-miss must not capture a nested helper namespace reference: hits={outer_scoped_hits:#?}"
    );
    assert!(
        !helper_return_hits.contains(&sibling_return_type),
        "a namespace sibling after the recovered sentinel must not inherit the recovered container_internal scope: hits={helper_return_hits:#?}"
    );
    let sibling_scoped_hits = exact_ranges(&analyzer, &sibling_scoped_type, &file);
    assert!(
        sibling_scoped_hits.contains(&sibling_return_type),
        "the namespace sibling must retain its parser-visible owner: hits={sibling_scoped_hits:#?}"
    );
}
