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
