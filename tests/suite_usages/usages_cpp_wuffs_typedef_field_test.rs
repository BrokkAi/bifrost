use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile, WorkspaceAnalyzer,
};
use std::collections::BTreeSet;
use std::sync::Arc;

type SourceRange = (usize, usize);

fn usage_ranges(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    caller: &ProjectFile,
) -> (BTreeSet<SourceRange>, BTreeSet<SourceRange>) {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(caller.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_by_overload,
        ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    let proven = hits_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    let unproven = unproven_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    (proven, unproven)
}

fn field_target(
    analyzer: &dyn IAnalyzer,
    owner: &str,
    field: &str,
    source_suffix: &str,
) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Field
                && unit.fq_name() == format!("{owner}.{field}")
                && !unit.is_synthetic()
                && unit.source().rel_path().ends_with(source_suffix)
        })
        .unwrap_or_else(|| panic!("missing {owner}.{field} target in {source_suffix}"))
}

#[test]
fn authoritative_cpp_macro_typedef_recovers_alias_without_phantom_argument() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "internal/cgen/base/token-public.h",
            r#"typedef struct wuffs_base__token__struct {
  uint64_t repr;
} wuffs_base__token;

#define WUFFS_BASE__SLICE(T) struct { T* ptr; size_t len; }
typedef WUFFS_BASE__SLICE(wuffs_base__token) wuffs_base__slice_token;
typedef ordinary_type(ordinary_argument) ordinary_alias;

static inline int64_t wuffs_base__token__value(const wuffs_base__token* t) {
  return ((int64_t)(t->repr)) >> 17;
}
"#,
        )
        .file(
            "release/c/wuffs-v0.3.c",
            r#"typedef struct wuffs_base__token__struct {
  unsigned long long repr;
} wuffs_base__token;
"#,
        )
        .file(
            "release/c/wuffs-v0.4.c",
            r#"typedef struct wuffs_base__token__struct {
  unsigned long long repr;
} wuffs_base__token;
"#,
        )
        .file(
            "release/c/wuffs-unsupported-snapshot.c",
            r#"typedef struct wuffs_base__token__struct {
  unsigned long long repr;
} wuffs_base__token;
"#,
        )
        .file(
            "other.h",
            r#"typedef struct other_token__struct {
  unsigned long long repr;
} other_token;
"#,
        )
        .build();
    let project_handle = project.project_dyn();
    let cold =
        WorkspaceAnalyzer::build_persisted(Arc::clone(&project_handle), AnalyzerConfig::default())
            .expect("persisted analyzer should build");
    drop(cold);
    let reopened = WorkspaceAnalyzer::build_persisted(project_handle, AnalyzerConfig::default())
        .expect("persisted analyzer should reopen");
    let analyzer = reopened.analyzer();
    let caller = project.file("internal/cgen/base/token-public.h");
    let source = caller.read_to_string().expect("caller source");
    let reference_start = source.rfind("repr").expect("t->repr reference");
    let expected = (reference_start, reference_start + "repr".len());

    let token_aliases = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "wuffs_base__token"
                && unit.source() == &caller
        })
        .collect::<Vec<_>>();
    assert_eq!(
        1,
        token_aliases.len(),
        "the macro argument must not create a false wuffs_base__token alias: {token_aliases:#?}"
    );
    assert_eq!(
        Some("typedef struct wuffs_base__token__struct { uint64_t repr; } wuffs_base__token;"),
        token_aliases[0].signature()
    );
    let slice_alias = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "wuffs_base__slice_token"
                && unit.source() == &caller
        })
        .expect("the macro-based slice typedef must retain its declarator name");
    assert_eq!(
        Some("typedef WUFFS_BASE__SLICE(wuffs_base__token) wuffs_base__slice_token;"),
        slice_alias.signature()
    );
    let slice_signature = slice_alias.signature().expect("slice alias signature");
    let slice_start = source
        .find(slice_signature)
        .expect("combined macro typedef signature in source");
    assert_eq!(
        BTreeSet::from([(slice_start, slice_start + slice_signature.len())]),
        analyzer
            .ranges(&slice_alias)
            .into_iter()
            .map(|range| (range.start_byte, range.end_byte))
            .collect(),
        "the recovered alias must retain the complete typedef range"
    );
    assert!(
        analyzer.get_all_declarations().into_iter().all(|unit| {
            unit.source() != &caller
                || !matches!(
                    unit.fq_name().as_str(),
                    "ordinary_argument" | "ordinary_alias"
                )
        }),
        "a non-macro recovery shape must fail closed without publishing an argument or sibling as an alias"
    );

    let target = field_target(
        analyzer,
        "wuffs_base__token__struct",
        "repr",
        "internal/cgen/base/token-public.h",
    );
    assert_eq!(
        "internal/cgen/base/token-public.h",
        target.source().rel_path(),
        "the target must be the visible physical owner"
    );
    let (proven, unproven) = usage_ranges(analyzer, &target, &caller);
    assert_eq!(BTreeSet::from([expected]), proven);
    assert!(
        unproven.is_empty(),
        "target owner must prove t->repr: {unproven:?}"
    );

    let hidden_target = field_target(
        analyzer,
        "wuffs_base__token__struct",
        "repr",
        "release/c/wuffs-v0.3.c",
    );
    let (hidden_proven, _hidden_unproven) = usage_ranges(analyzer, &hidden_target, &caller);
    assert!(
        hidden_proven.is_empty(),
        "a hidden same-FQN physical owner must not prove the visible repr access: {hidden_proven:?}"
    );

    let distinct_target = field_target(analyzer, "other_token__struct", "repr", "other.h");
    let (distinct_proven, distinct_unproven) = usage_ranges(analyzer, &distinct_target, &caller);
    assert!(
        distinct_proven.is_empty() && distinct_unproven.is_empty(),
        "a distinct logical owner must not claim the token access: proven={distinct_proven:?}, unproven={distinct_unproven:?}"
    );
}
