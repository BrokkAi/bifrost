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
