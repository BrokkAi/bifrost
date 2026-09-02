//! Focus tests for the descendant-index build's ancestry reuse (#2868).

use super::KotlinAnalyzer;
use crate::analyzer::{CodeUnit, DescendantIndexScope, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
use std::collections::BTreeSet;

fn fixture() -> (ProjectFile, KotlinAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::Kotlin)
        .file(
            "lib/Library.kt",
            "package lib\n\
             \n\
             open class Base(val seed: Int)\n\
             \n\
             interface Contract\n",
        )
        .file(
            "app/Children.kt",
            "package app\n\
             \n\
             import lib.Base\n\
             import lib.Contract\n\
             \n\
             open class First : Base(1), Contract\n\
             class Second : First()\n\
             class Third : First()\n\
             class Fourth : Second()\n",
        )
        .file(
            "wild/Child.kt",
            "package wild\n\nimport lib.*\n\nclass Wildcard : Base(2)\n",
        )
        .build();
    let wild = ProjectFile::new(fixture.root(), "wild/Child.kt");
    let analyzer = KotlinAnalyzer::new(fixture.project_arc());
    (wild, analyzer)
}

fn base_unit(analyzer: &KotlinAnalyzer) -> CodeUnit {
    analyzer
        .all_declarations()
        .into_iter()
        .find(|unit| unit.fq_name() == "lib.Base")
        .expect("fixture declares lib.Base")
}

fn class_unit(analyzer: &KotlinAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .all_declarations()
        .into_iter()
        .find(|unit| unit.fq_name() == fq_name)
        .unwrap_or_else(|| panic!("fixture declares {fq_name}"))
}

fn sorted_names(units: HashSet<CodeUnit>) -> Vec<String> {
    let mut names: Vec<String> = units.iter().map(CodeUnit::fq_name).collect();
    names.sort();
    names
}

/// A descendant-index build must publish its per-class ancestry into the
/// analyzer's ancestor memo (#2868): the mirai usage scans re-derived the
/// same ladders for the second scope variant and for every later hierarchy
/// question because the batch-hydrated resolution bypassed the memo cells.
#[test]
fn kotlin_descendant_index_populates_the_ancestor_memo() {
    let (wild, analyzer) = fixture();
    let base = base_unit(&analyzer);

    let whole = sorted_names(analyzer.get_direct_descendants(&base));
    assert_eq!(
        whole,
        vec!["app.First".to_string(), "wild.Wildcard".to_string(),]
    );

    let uncancelled = CancellationToken::default();
    let excluded = BTreeSet::from([wild]);
    let excludes = |file: &ProjectFile| excluded.contains(file);
    let scope = DescendantIndexScope::excluding_sources(&uncancelled, &excludes);
    let production = sorted_names(
        analyzer
            .get_direct_descendants_within(&base, &scope)
            .expect("the production-only descendant index completes"),
    );
    assert_eq!(
        production,
        vec!["app.First".to_string()],
        "the production-only variant excludes the rejected source's declarations"
    );

    let first = class_unit(&analyzer, "app.First");
    assert!(
        analyzer.direct_ancestors.get(&first).is_some(),
        "the descendant-index build must publish per-class ancestry into the \
         analyzer's ancestor memo"
    );
    let warm_ancestors = analyzer.get_direct_ancestors(&first);
    let mut warm_names = warm_ancestors
        .iter()
        .map(CodeUnit::fq_name)
        .collect::<Vec<_>>();
    warm_names.sort();
    assert!(
        warm_names == vec!["lib.Base".to_string(), "lib.Contract".to_string()],
        "a warm ancestry answer must keep its resolved supertypes: {warm_names:?}"
    );

    let (_unused_wild, cold_analyzer) = fixture();
    let cold_first = class_unit(&cold_analyzer, "app.First");
    assert!(
        cold_analyzer.direct_ancestors.get(&cold_first).is_none(),
        "a fresh analyzer starts without published ancestry"
    );
    cold_analyzer.get_direct_ancestors(&cold_first);
    assert!(
        cold_analyzer.direct_ancestors.get(&cold_first).is_some(),
        "the per-unit ancestor path publishes through the same memo the \
         descendant-index build reads"
    );
}
