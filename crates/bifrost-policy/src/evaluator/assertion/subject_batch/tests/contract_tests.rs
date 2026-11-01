use super::*;

#[test]
fn incomplete_subject_product_cannot_mask_a_complete_followup() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "fn subject() {}")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let budget = PolicyBudget::default();
    let batch = SubjectQueryBatch::new(
        workspace.analyzer(),
        std::iter::empty::<&LoadedPolicy>(),
        &budget,
    );
    let incomplete = Arc::new(ExecutedQueryRows {
        items: Vec::new(),
        evidence: Vec::new(),
        completion: CodeQueryCompletion::Incomplete { codes: Vec::new() },
        truncated: true,
        diagnostics: Vec::new(),
        work: Default::default(),
    });
    let complete = Arc::new(ExecutedQueryRows {
        items: Vec::new(),
        evidence: Vec::new(),
        completion: CodeQueryCompletion::Complete,
        truncated: false,
        diagnostics: Vec::new(),
        work: Default::default(),
    });
    let first = batch.reuse_or_execute(
        workspace.analyzer(),
        None,
        |retained| &mut retained.subjects,
        "subject".to_string(),
        || Arc::clone(&incomplete),
    );
    assert!(matches!(
        first.completion,
        CodeQueryCompletion::Incomplete { .. }
    ));
    let second = batch.reuse_or_execute(
        workspace.analyzer(),
        None,
        |retained| &mut retained.subjects,
        "subject".to_string(),
        || Arc::clone(&complete),
    );
    assert!(matches!(second.completion, CodeQueryCompletion::Complete));
}

#[test]
fn repeated_match_selector_reuses_one_complete_unit() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let policy_source = |id: &str| {
        format!(
            r#"(policy
      :id "test.{id}" :name "Shared match" :message "Match" :severity warning
      :analysis (analysis :type match
        :selector (rql (language rust (call :callee (name "target"))))))"#
        )
    };
    let first = crate::test_support::load_match_policy(&policy_source("first"));
    let second = crate::test_support::load_match_policy(&policy_source("second"));
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "fn target() {} fn caller() { target(); }")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let budget = PolicyBudget::default();
    let batch =
        SubjectQueryBatch::new(workspace.analyzer(), [&first, &second].into_iter(), &budget);
    let query = match_policy_query(&first).unwrap();
    let query = executable_match_query(query, &budget).unwrap();
    let shared = batch
        .query_units(
            &query,
            workspace.analyzer(),
            Some(&workspace),
            budget.query_limits(),
        )
        .expect("the repeated selector has one shared unit handle");
    let executions = AtomicUsize::new(0);
    let execute = || {
        executions.fetch_add(1, Ordering::SeqCst);
        UnitExecutionResult {
            rows: Vec::new(),
            work: Default::default(),
            budgeted_work: Default::default(),
            completion: CodeQueryCompletion::Complete,
            diagnostics: Vec::new(),
            truncated: false,
        }
    };
    let first_rows = shared.execute(None, workspace.analyzer(), None, execute);
    let second_rows = shared.execute(None, workspace.analyzer(), None, execute);
    assert!(matches!(
        first_rows.completion,
        CodeQueryCompletion::Complete
    ));
    assert!(matches!(
        second_rows.completion,
        CodeQueryCompletion::Complete
    ));
    assert_eq!(executions.load(Ordering::SeqCst), 1);
}
