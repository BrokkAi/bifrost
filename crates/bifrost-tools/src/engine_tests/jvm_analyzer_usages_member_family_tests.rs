#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyOutcome;

    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;

    use brokk_bifrost_analysis::analyzer::usages::member_family::java_member_family;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;

    #[test]
    fn java_member_family_conflicting_visibility_alternatives_are_incomplete() {
        for members in [
            "public void run() {} private void run() {}",
            "private void run() {} public void run() {}",
        ] {
            let fixture = InlineTestProject::with_language(Language::Java)
                .file("Contract.java", "interface Contract { void run(); }")
                .file(
                    "Worker.java",
                    format!("class Worker implements Contract {{ {members} }}"),
                )
                .build();
            let analyzer = JavaAnalyzer::new(fixture.project_dyn());
            let member = analyzer
                .declarations(&fixture.file("Worker.java"))
                .into_iter()
                .find(|unit| unit.is_function() && unit.identifier() == "run")
                .expect("written run method");
            assert_eq!(analyzer.signature_metadata(&member).len(), 2);
            let answer = java_member_family(&analyzer, &analyzer, &member, None);
            assert_eq!(
                answer.outcome,
                MemberFamilyOutcome::Incomplete,
                "{answer:?}"
            );
            assert_eq!(answer.reason, Some(MemberFamilyReason::ModifiersUnrecorded));
            assert!(answer.edges.is_empty(), "{answer:?}");
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6664: incomplete Java descendant cache fills panicked during member-family inversion"
)]
fn java_incomplete_descendant_fill_leaves_member_family_open() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete;
    use brokk_bifrost_analysis::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
    use brokk_bifrost_analysis::analyzer::usages::member_family::java_member_family;
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, IAnalyzer, capture_query_reads};
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::capabilities::{HierarchyOpenReason, TypeHierarchyProvider};
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyOutcome;
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;
    use std::collections::BTreeMap;

    let project = InlineTestProject::with_language(Language::Java)
        .file("Base.java", "class Base { public void run() {} }")
        .file(
            "Child.java",
            "class Child extends Base { public void run() {} }",
        )
        .build();
    let analyzer = MultiAnalyzer::new(BTreeMap::from([(
        Language::Java,
        AnalyzerDelegate::new(JavaAnalyzer::new(project.project_dyn())),
    )]));
    let member = analyzer
        .declarations(&project.file("Base.java"))
        .into_iter()
        .find(|unit| unit.is_function() && unit.identifier() == "run")
        .unwrap();
    let owner = analyzer.parent_of(&member).unwrap();
    let gap = QueryReadIncomplete::SemanticEvidenceGap("refused hierarchy input".into());
    let (_, reads) = capture_query_reads(&analyzer, || {
        let scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        analyzer.record_query_incomplete(gap.clone());
        assert!(
            analyzer
                .get_direct_descendants(&owner)
                .open
                .iter()
                .any(|reason| matches!(reason, HierarchyOpenReason::DescendantIndexUnavailable))
        );
        let reasons = scope.captured_read_incompleteness();
        assert_eq!(reasons, vec![gap.clone()]);
    });
    assert_eq!(reads.execution_dependences(), 0, "{reads:?}");
    assert!(reads.unattributed_reads() > 0, "{reads:?}");
    {
        let _scope = AnalyzerQueryScope::new(&analyzer);
        analyzer.record_query_incomplete(gap);
        let answer = java_member_family(&analyzer, &analyzer, &member, None);
        assert_eq!(
            answer.descendants.outcome,
            MemberFamilyOutcome::Incomplete,
            "{answer:?}"
        );
    }
    let descendants = analyzer.get_direct_descendants(&owner);
    let descendants = descendants.definite();
    assert!(
        descendants.iter().any(|unit| unit.identifier() == "Child"),
        "{descendants:?}"
    );
}

#[test]
fn native_java_hierarchy_preserves_parent_alternatives() {
    if run_native_selector_test(
        "BIFROST_TRIAL_NATIVE_JAVA",
        "native_java_hierarchy_preserves_parent_alternatives",
    ) {
        return;
    }
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;
    assert!(std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_some());
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("a/Base.java", "package a; public class Base { public void run() {} }")
        .file("b/Base.java", "package b; public class Base { public void run() {} }")
        .file("c/Child.java", "package c; import a.*; import b.*; class Child extends Base { public void run() {} } class D extends a.Base { public void run() {} }")
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    for path in ["a/Base.java", "b/Base.java", "c/Child.java"] {
        assert!(!analyzer.declarations(&fixture.file(path)).is_empty());
    }
    let declarations = analyzer.declarations(&fixture.file("c/Child.java"));
    let child = declarations
        .iter()
        .find(|unit| unit.identifier() == "Child")
        .unwrap();
    let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
    brokk_bifrost_analysis::analyzer::resolution::reset_selected_fact_operation_construction_count_for_test();
    let answer = analyzer.get_ancestors(child);
    assert_eq!(brokk_bifrost_analysis::analyzer::resolution::selected_fact_operation_construction_count_for_test(), 1, "one forward operation per native delegate per ancestor walk");
    assert!(scope.store_error().is_none(), "{:?}", scope.store_error());
    assert!(answer.edges.is_empty(), "{answer:?}");
    assert_eq!(answer.ambiguous.len(), 1, "{answer:?}");
    let mut alternatives = answer.ambiguous[0]
        .iter()
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    alternatives.sort();
    assert_eq!(alternatives, ["a.Base", "b.Base"]);
    let member = declarations
        .iter()
        .find(|unit| unit.is_function() && unit.fq_name() == "c.Child.run")
        .unwrap();
    brokk_bifrost_analysis::analyzer::resolution::reset_selected_fact_operation_construction_count_for_test();
    let family = brokk_bifrost_analysis::analyzer::usages::member_family::java_member_family(
        &analyzer, &analyzer, member, None,
    );
    assert_eq!(brokk_bifrost_analysis::analyzer::resolution::selected_fact_operation_construction_count_for_test(), 1, "one forward operation per native delegate per family walk");
    assert!(family.edges.is_empty(), "{family:?}");
    assert_eq!(family.reason, Some(brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason::HierarchyAmbiguous));
    let plain = declarations
        .iter()
        .find(|unit| unit.identifier() == "D")
        .unwrap();
    let d_run = declarations
        .iter()
        .find(|unit| unit.fq_name() == "c.D.run")
        .unwrap();
    let d_family = brokk_bifrost_analysis::analyzer::usages::member_family::java_member_family(
        &analyzer, &analyzer, d_run, None,
    );
    assert_eq!(
        d_family
            .edges
            .iter()
            .map(|edge| edge.target.fq_name())
            .collect::<Vec<_>>(),
        ["a.Base.run"],
        "{d_family:?}"
    );
    let answer = analyzer.get_direct_ancestors(plain);
    assert_eq!(
        answer
            .edges
            .iter()
            .map(|unit| unit.fq_name())
            .collect::<Vec<_>>(),
        ["a.Base"],
        "{answer:?}"
    );
}

#[test]
fn native_scala_hierarchy_distinguishes_trait_and_class_first_parents() {
    if run_native_selector_test(
        "BIFROST_TRIAL_NATIVE_SCALA",
        "native_scala_hierarchy_distinguishes_trait_and_class_first_parents",
    ) {
        return;
    }
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::capabilities::{HierarchyOpenReason, TypeHierarchyProvider};
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_jvm_analysis::analyzer::ScalaAnalyzer;
    assert!(std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some());
    let fixture = InlineTestProject::with_language(Language::Scala)
        .file(
            "Parents.scala",
            "trait T\nclass Base\nclass TraitFirst extends T\nclass ClassFirst extends Base\nclass Written extends AnyRef\nclass Unwritten\n",
        )
        .build();
    let analyzer = ScalaAnalyzer::new(fixture.project_dyn());
    let declarations = analyzer.declarations(&fixture.file("Parents.scala"));
    let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
    let child = declarations
        .iter()
        .find(|unit| unit.identifier() == "TraitFirst")
        .unwrap();
    let answer = analyzer.get_direct_ancestors(child);
    assert!(scope.store_error().is_none(), "{:?}", scope.store_error());
    assert_eq!(
        answer
            .edges
            .iter()
            .map(|unit| unit.fq_name())
            .collect::<Vec<_>>(),
        ["T"],
        "{answer:?}"
    );
    assert!(
        answer.is_complete(),
        "the intrinsic AnyRef root stays closed: {answer:?}"
    );
    for name in ["Unwritten", "T"] {
        let owner = declarations
            .iter()
            .find(|unit| unit.identifier() == name)
            .unwrap();
        let answer = analyzer.get_direct_ancestors(owner);
        assert!(answer.is_complete(), "{name}: {answer:?}");
    }
    let written = declarations
        .iter()
        .find(|unit| unit.identifier() == "Written")
        .unwrap();
    let answer = analyzer.get_direct_ancestors(written);
    // #8333 makes Written Complete by binding bare AnyRef to the closed
    // jvm-intrinsic / scala.AnyRef owner. Until that name-resolution gap closes,
    // preserve the open answer. The intrinsic owner emits no source edge.
    assert!(
        answer
            .edges
            .iter()
            .all(|edge| edge.fq_name() == "scala.AnyRef"),
        "{answer:?}"
    );
    assert!(answer.ambiguous.is_empty(), "{answer:?}");
    assert!(
        answer.is_complete()
            || answer.open.iter().all(|reason| matches!(
                reason,
                HierarchyOpenReason::MemberFamily(
                    brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason::HierarchyTruncated
                ) | HierarchyOpenReason::UnreadAncestor(_)
            )),
        "{answer:?}"
    );
    let child = declarations
        .iter()
        .find(|unit| unit.identifier() == "ClassFirst")
        .unwrap();
    let answer = analyzer.get_direct_ancestors(child);
    assert_eq!(
        answer
            .edges
            .iter()
            .map(|unit| unit.fq_name())
            .collect::<Vec<_>>(),
        ["Base"],
        "{answer:?}"
    );
    assert!(answer.open.iter().all(|reason| !matches!(reason, HierarchyOpenReason::UnreadAncestor(ancestor) if ancestor.name == "scala.AnyRef")), "{answer:?}");
}

#[test]
fn native_java_hierarchy_query_replays_reference_receipts() {
    if run_native_selector_test(
        "BIFROST_TRIAL_NATIVE_JAVA",
        "native_java_hierarchy_query_replays_reference_receipts",
    ) {
        return;
    }
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, capture_query_reads};
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;
    assert!(std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_some());
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("a/Base.java", "package a; public class Base {}")
        .file("b/Base.java", "package b; public class Base {}")
        .file(
            "c/Child.java",
            "package c; import a.*; import b.*; class Child extends Base {}",
        )
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let declarations = analyzer.declarations(&fixture.file("c/Child.java"));
    let child = declarations
        .iter()
        .find(|unit| unit.identifier() == "Child")
        .unwrap();
    let scope = AnalyzerQueryScope::new(&analyzer);
    brokk_bifrost_analysis::analyzer::resolution::reset_selected_fact_operation_construction_count_for_test();
    analyzer.with_hierarchy_query_for(child, &mut |query| {
        let (first, first_reads) = capture_query_reads(&analyzer, || query.direct_ancestors(child));
        let (second, second_reads) =
            capture_query_reads(&analyzer, || query.direct_ancestors(child));
        assert!(!first.is_complete());
        assert_eq!(first.ambiguous.len(), 1, "{first:?}");
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
        let mut keys = first_reads.unordered_keys();
        let mut second_keys = second_reads.unordered_keys();
        assert!(
            !keys.is_empty(),
            "the first read must record real dependencies"
        );
        keys.sort_unstable();
        second_keys.sort_unstable();
        assert_eq!(keys, second_keys);
        assert_eq!(
            first_reads.unattributed_reads(),
            second_reads.unattributed_reads()
        );
        assert_eq!(
            first_reads.execution_dependences(),
            second_reads.execution_dependences()
        );
    });
    assert_eq!(brokk_bifrost_analysis::analyzer::resolution::selected_fact_operation_construction_count_for_test(), 1);
    assert!(scope.store_error().is_none(), "{:?}", scope.store_error());
}

fn run_native_selector_test(selector: &str, test: &str) -> bool {
    if std::env::var_os(selector).is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("engine_tests::jvm_analyzer_usages_member_family_tests::{test}"),
            "--nocapture",
        ])
        .env(selector, "1")
        .env("JAVA_HOME", "")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{output:?}"
    );
    true
}

#[test]
fn native_java_descendants_selector_on_and_scoped_cancellation() {
    if run_native_selector_test(
        "BIFROST_TRIAL_NATIVE_JAVA",
        "native_java_descendants_selector_on_and_scoped_cancellation",
    ) {
        return;
    }
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::{
        Language,
        capabilities::{Cancelled, DescendantIndexScope, TypeHierarchyProvider},
    };
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("a/Base.java", "package a; public class Base {}")
        .file("b/Base.java", "package b; public class Base {}")
        .file("c/Child.java", "package c; import a.*; import b.*; class Child extends Base {} class D extends a.Base {}")
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    for path in ["b/Base.java", "c/Child.java"] {
        analyzer.declarations(&fixture.file(path));
    }
    let declarations = analyzer.declarations(&fixture.file("a/Base.java"));
    let base = declarations
        .iter()
        .find(|unit| unit.identifier() == "Base")
        .unwrap();
    brokk_bifrost_analysis::analyzer::resolution::reset_selected_fact_operation_construction_count_for_test();
    let answer = analyzer.get_direct_descendants(base);
    assert_eq!(
        answer
            .edges
            .iter()
            .map(|unit| unit.identifier())
            .collect::<Vec<_>>(),
        ["D"],
        "{answer:?}"
    );
    assert_eq!(
        answer
            .ambiguous
            .iter()
            .flatten()
            .map(|unit| unit.identifier())
            .collect::<Vec<_>>(),
        ["Child"],
        "{answer:?}"
    );
    assert!(brokk_bifrost_analysis::analyzer::resolution::selected_fact_operation_construction_count_for_test() > 0);
    let cancellation = CancellationToken::new();
    let exclude = |_: &brokk_bifrost_core::analyzer::model::ProjectFile| {
        cancellation.cancel();
        false
    };
    let scope = DescendantIndexScope::excluding_sources(&cancellation, &exclude);
    assert_eq!(
        analyzer
            .get_direct_descendants_within(base, &scope)
            .unwrap_err(),
        Cancelled
    );
    assert_eq!(
        analyzer
            .get_direct_descendants_within(base, &scope)
            .unwrap_err(),
        Cancelled
    );
    let outside = InlineTestProject::with_language(Language::Java)
        .file("Outside.java", "class Outside {}")
        .build();
    let other = JavaAnalyzer::new(outside.project_dyn());
    let declarations = other.declarations(&outside.file("Outside.java"));
    let root = declarations
        .iter()
        .find(|unit| unit.identifier() == "Outside")
        .unwrap();
    let unavailable = analyzer.get_direct_descendants(root);
    assert!(
        unavailable.open.iter().any(|reason| {
            matches!(reason,
        brokk_bifrost_core::analyzer::capabilities::HierarchyOpenReason::DescendantIndexUnavailable)
        }),
        "{unavailable:?}"
    );
}

#[test]
fn native_java_descendants_selector_off() {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_some() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "engine_tests::jvm_analyzer_usages_member_family_tests::native_java_descendants_selector_off", "--nocapture"])
            .env_remove("BIFROST_TRIAL_NATIVE_JAVA").output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::{Language, capabilities::TypeHierarchyProvider};
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("Types.java", "class Base {} class Child extends Base {}")
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let declarations = analyzer.declarations(&fixture.file("Types.java"));
    let base = declarations
        .iter()
        .find(|unit| unit.identifier() == "Base")
        .unwrap();
    brokk_bifrost_analysis::analyzer::resolution::reset_selected_fact_operation_construction_count_for_test();
    let answer = analyzer.get_direct_descendants(base);
    assert!(
        answer.edges.iter().any(|unit| unit.identifier() == "Child"),
        "{answer:?}"
    );
    assert_eq!(brokk_bifrost_analysis::analyzer::resolution::selected_fact_operation_construction_count_for_test(), 0);
}

#[test]
fn native_java_descendants_intrinsic_root_budget_cut() {
    if run_native_selector_test(
        "BIFROST_TRIAL_NATIVE_JAVA",
        "native_java_descendants_intrinsic_root_budget_cut",
    ) {
        return;
    }
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;
    use brokk_bifrost_core::analyzer::{
        Language,
        capabilities::{HierarchyOpenReason, TypeHierarchyProvider},
    };
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(
            "java/lang/Object.java",
            "package java.lang; public class Object {}",
        )
        .file("Child.java", "class Child extends java.lang.Object {}")
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    analyzer.declarations(&fixture.file("Child.java"));
    let declarations = analyzer.declarations(&fixture.file("java/lang/Object.java"));
    let root = declarations
        .iter()
        .find(|unit| unit.identifier() == "Object")
        .unwrap();
    let answer = analyzer.get_direct_descendants(root);
    assert!(
        answer.open.iter().any(|reason| matches!(
            reason,
            HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyTruncated)
        )),
        "{answer:?}"
    );
}

#[test]
fn native_java_descendants_intrinsic_refusal_preserves_walk_budget() {
    if run_native_selector_test(
        "BIFROST_TRIAL_NATIVE_JAVA",
        "native_java_descendants_intrinsic_refusal_preserves_walk_budget",
    ) {
        return;
    }
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;
    use brokk_bifrost_core::analyzer::{
        Language,
        capabilities::{HierarchyOpenReason, TypeHierarchyProvider},
    };
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("java/lang/Object.java", "package java.lang; public class Object {}")
        .file("a/Base.java", "package a; public class Base {}")
        .file("b/Base.java", "package b; public class Base {}")
        .file("c/Child.java", "package c; import a.*; import b.*; class Child extends Base {} class D extends a.Base {}")
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    for path in ["b/Base.java", "c/Child.java"] {
        analyzer.declarations(&fixture.file(path));
    }
    let objects = analyzer.declarations(&fixture.file("java/lang/Object.java"));
    let object = objects
        .iter()
        .find(|unit| unit.identifier() == "Object")
        .unwrap();
    let bases = analyzer.declarations(&fixture.file("a/Base.java"));
    let base = bases
        .iter()
        .find(|unit| unit.identifier() == "Base")
        .unwrap();
    // One callback owns one shared descendant session. A deterministic refusal
    // must not poison the budget for a later, answerable hierarchy question.
    analyzer.with_hierarchy_query_for(base, &mut |query| {
        let root = query.direct_descendants(object);
        assert!(
            root.open.iter().any(|reason| matches!(
                reason,
                HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyTruncated)
            )),
            "{root:?}"
        );
        let descendants = query.direct_descendants(base);
        assert_eq!(
            descendants
                .edges
                .iter()
                .map(|unit| unit.identifier())
                .collect::<Vec<_>>(),
            ["D"],
            "{descendants:?}"
        );
        assert_eq!(
            descendants
                .ambiguous
                .iter()
                .flatten()
                .map(|unit| unit.identifier())
                .collect::<Vec<_>>(),
            ["Child"],
            "{descendants:?}"
        );
    });
}
