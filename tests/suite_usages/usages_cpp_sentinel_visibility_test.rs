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
fn authoritative_cpp_namespace_sentinel_recovers_template_parameter_types() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "format_arg.h",
            "namespace absl { namespace str_format_internal { class FormatArgImpl {}; } }\n",
        )
        .file(
            "bind.h",
            "#include \"format_arg.h\"\n\
namespace absl {\n\
ABSL_NAMESPACE_BEGIN\n\
namespace str_format_internal {\n\
std::string AppendPack(std::string* out, absl::Span<const FormatArgImpl> args);\n\
std::string FormatPack(absl::Span<const FormatArgImpl> args);\n\
}\n\
ABSL_NAMESPACE_END\n\
}\n",
        )
        .file(
            "global_near_miss.h",
            "#include \"format_arg.h\"\n\
class FormatArgImpl {};\n\
std::string WrongGlobal(absl::Span<const FormatArgImpl> args);\n",
        )
        .file(
            "namespace_near_miss.h",
            "#include \"format_arg.h\"\n\
namespace unrelated {\n\
class FormatArgImpl {};\n\
std::string WrongNamespace(absl::Span<const FormatArgImpl> args);\n\
}\n",
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::str_format_internal.FormatArgImpl"
            && unit.source() == &project.file("format_arg.h")
    });

    let bind_file = project.file("bind.h");
    let bind_source = bind_file.read_to_string().expect("bind fixture source");
    let append_parameter = token_range_occurrence(
        &bind_source,
        "std::string AppendPack(std::string* out, absl::Span<const FormatArgImpl> args);",
        "FormatArgImpl",
        0,
    );
    let format_parameter = token_range_occurrence(
        &bind_source,
        "std::string FormatPack(absl::Span<const FormatArgImpl> args);",
        "FormatArgImpl",
        0,
    );
    let bind_hits =
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&target), &bind_file);
    assert!(
        [append_parameter, format_parameter]
            .iter()
            .all(|expected| bind_hits.contains(expected)),
        "template arguments in sentinel-truncated parameters must resolve: hits={bind_hits:#?}"
    );

    let global_file = project.file("global_near_miss.h");
    let global_source = global_file
        .read_to_string()
        .expect("global near-miss source");
    let global_parameter = token_range(
        &global_source,
        "std::string WrongGlobal(absl::Span<const FormatArgImpl> args);",
        "FormatArgImpl",
    );
    let global_hits =
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&target), &global_file);
    assert!(
        !global_hits.contains(&global_parameter),
        "a truly global same-spelled type must not resolve to the namespaced target: hits={global_hits:#?}"
    );

    let namespace_file = project.file("namespace_near_miss.h");
    let namespace_source = namespace_file
        .read_to_string()
        .expect("namespace near-miss source");
    let namespace_parameter = token_range(
        &namespace_source,
        "std::string WrongNamespace(absl::Span<const FormatArgImpl> args);",
        "FormatArgImpl",
    );
    let namespace_hits =
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&target), &namespace_file);
    assert!(
        !namespace_hits.contains(&namespace_parameter),
        "a parser-visible unrelated namespace must not resolve to the target: hits={namespace_hits:#?}"
    );
}

#[test]
fn authoritative_cpp_nested_type_leaf_requires_qualified_owner() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "nested_types.h",
            r#"namespace absl {
template <typename IntType = int>
class discrete_distribution {
 public:
  class param_type {};
};

template <typename IntType>
void read_distribution() {
  using param_type = typename discrete_distribution<IntType>::param_type;
  param_type value;
}
}  // namespace absl

namespace target {
template <typename T>
struct Outer {
  struct Inner {};
  struct Other {};
};

template <typename T>
struct OtherOuter {
  struct Inner {};
};

template <typename T>
void right_owner() {
  typename Outer<T>::Inner value;
}

template <typename T>
void wrong_owner() {
  typename OtherOuter<T>::Inner value;
}

template <typename T>
void wrong_member() {
  typename Outer<T>::Other value;
}

void wrong_unqualified() {
  Inner value;
}
}  // namespace target

namespace alternate {
template <typename T>
struct Outer {
  struct Inner {};
};
}

namespace target {
template <typename T>
void wrong_namespace() {
  typename alternate::Outer<T>::Inner value;
}
}  // namespace target
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("nested_types.h");
    let source = file.read_to_string().expect("nested type fixture source");

    let discrete_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl.discrete_distribution$param_type"
            && unit.source() == &file
    });
    let discrete_reference = token_range_occurrence(
        &source,
        "  using param_type = typename discrete_distribution<IntType>::param_type;",
        "param_type",
        1,
    );
    let discrete_hits =
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&discrete_target), &file);
    assert_eq!(
        discrete_hits,
        BTreeSet::from([discrete_reference]),
        "nested class alias reference must emit only its terminal leaf: hits={discrete_hits:#?}"
    );

    let outer_target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "target.Outer$Inner"
            && unit.source() == &file
    });
    let outer_reference = token_range(&source, "  typename Outer<T>::Inner value;", "Inner");
    let wrong_owner = token_range(&source, "  typename OtherOuter<T>::Inner value;", "Inner");
    let wrong_member = token_range(&source, "  typename Outer<T>::Other value;", "Other");
    let wrong_unqualified = token_range(&source, "  Inner value;", "Inner");
    let wrong_namespace = token_range(
        &source,
        "  typename alternate::Outer<T>::Inner value;",
        "Inner",
    );
    let outer_hits =
        authoritative_exact_ranges(&analyzer, std::slice::from_ref(&outer_target), &file);
    assert_eq!(
        outer_hits,
        BTreeSet::from([outer_reference]),
        "qualified nested type must emit only the owner-qualified target leaf: hits={outer_hits:#?}"
    );
    for near_miss in [
        wrong_owner,
        wrong_member,
        wrong_unqualified,
        wrong_namespace,
    ] {
        assert!(
            !outer_hits.contains(&near_miss),
            "same-spelled nested type under another owner must stay excluded: hits={outer_hits:#?}"
        );
    }
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
