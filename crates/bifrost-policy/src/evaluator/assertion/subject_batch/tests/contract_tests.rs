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
        depth_bound_status: None,
        completion: CodeQueryCompletion::Incomplete { codes: Vec::new() },
        truncated: true,
        diagnostics: Vec::new(),
        work: Default::default(),
    });
    let complete = Arc::new(ExecutedQueryRows {
        items: Vec::new(),
        evidence: Vec::new(),
        depth_bound_status: None,
        completion: CodeQueryCompletion::Complete,
        truncated: false,
        diagnostics: Vec::new(),
        work: Default::default(),
    });
    let first = batch.reuse_or_execute(
        workspace.analyzer(),
        None,
        |retained| &mut retained.subjects,
        ("subject".to_string(), false),
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
        ("subject".to_string(), false),
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
            false,
        )
        .expect("the repeated selector has one shared unit handle");
    let executions = AtomicUsize::new(0);
    let execute = || {
        executions.fetch_add(1, Ordering::SeqCst);
        UnitExecutionResult {
            except_left_complete_empty: None,
            rows: Vec::new(),
            work: Default::default(),
            budgeted_work: Default::default(),
            depth_bound_status: None,
            depth_answers: Vec::new(),
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

fn selector_policy(id: &str, opt_in: bool) -> LoadedPolicy {
    let completion = if opt_in {
        " :completion (inconclusive-on [depth_bound_reached])"
    } else {
        ""
    };
    crate::test_support::load_match_policy(&format!(
        r#"(policy
      :id "test.{id}" :name "Shared match" :message "Match" :severity warning
      :analysis (analysis :type match{completion}
        :selector (rql (language rust (call :callee (name "target"))))))"#
    ))
}

fn unit_result() -> UnitExecutionResult {
    UnitExecutionResult {
        except_left_complete_empty: None,
        rows: Vec::new(),
        work: Default::default(),
        budgeted_work: Default::default(),
        depth_bound_status: None,
        depth_answers: Vec::new(),
        completion: CodeQueryCompletion::Complete,
        diagnostics: Vec::new(),
        truncated: false,
    }
}

#[test]
fn depth_opt_in_splits_identical_query_text_into_distinct_entries() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let plain = [selector_policy("a", false), selector_policy("b", false)];
    let opted = [selector_policy("c", true), selector_policy("d", true)];
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "fn target() {} fn caller() { target(); }")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let budget = PolicyBudget::default();
    let batch = SubjectQueryBatch::new(
        workspace.analyzer(),
        plain.iter().chain(opted.iter()),
        &budget,
    );
    let query = executable_match_query(match_policy_query(&plain[0]).unwrap(), &budget).unwrap();
    assert_eq!(
        query.to_canonical_json(),
        executable_match_query(match_policy_query(&opted[0]).unwrap(), &budget)
            .unwrap()
            .to_canonical_json(),
        "the opt-in declaration is not part of the query text"
    );
    let handle = |depth_opt_in| {
        batch
            .query_units(
                &query,
                workspace.analyzer(),
                Some(&workspace),
                budget.query_limits(),
                depth_opt_in,
            )
            .expect("each bit has two consumers of this selector")
    };
    let executions = AtomicUsize::new(0);
    let execute = || {
        executions.fetch_add(1, Ordering::SeqCst);
        unit_result()
    };
    for depth_opt_in in [false, true, false, true] {
        handle(depth_opt_in).execute(None, workspace.analyzer(), None, execute);
    }
    assert_eq!(
        executions.load(Ordering::SeqCst),
        2,
        "one execution per (query, bit); identical pairs are shared"
    );
    assert_eq!(
        batch
            .retained
            .lock()
            .expect("policy subject batch products mutex poisoned")
            .units
            .len(),
        2
    );
}

#[test]
fn depth_opt_in_consumers_of_other_bits_do_not_make_a_query_repeated() {
    let policies = [selector_policy("a", false), selector_policy("c", true)];
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "fn target() {} fn caller() { target(); }")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let budget = PolicyBudget::default();
    let batch = SubjectQueryBatch::new(workspace.analyzer(), policies.iter(), &budget);
    let query = executable_match_query(match_policy_query(&policies[0]).unwrap(), &budget).unwrap();
    for depth_opt_in in [false, true] {
        assert!(
            batch
                .query_units(
                    &query,
                    workspace.analyzer(),
                    Some(&workspace),
                    budget.query_limits(),
                    depth_opt_in,
                )
                .is_none(),
            "a single consumer per bit shares nothing (opt-in: {depth_opt_in})"
        );
    }
}

#[test]
fn subject_product_is_never_reused_across_the_depth_opt_in_bit() {
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    let rows = || {
        Arc::new(ExecutedQueryRows {
            items: Vec::new(),
            evidence: Vec::new(),
            depth_bound_status: None,
            completion: CodeQueryCompletion::Complete,
            truncated: false,
            diagnostics: Vec::new(),
            work: Default::default(),
        })
    };
    let executions = AtomicUsize::new(0);
    let run = |depth_opt_in: bool| {
        batch.reuse_or_execute(
            workspace.analyzer(),
            None,
            |retained| &mut retained.subjects,
            ("subject".to_string(), depth_opt_in),
            || {
                executions.fetch_add(1, Ordering::SeqCst);
                rows()
            },
        )
    };
    let without = run(false);
    let with = run(true);
    assert!(!Arc::ptr_eq(&without, &with));
    assert_eq!(executions.load(Ordering::SeqCst), 2);
    assert!(Arc::ptr_eq(&without, &run(false)));
    assert!(Arc::ptr_eq(&with, &run(true)));
    assert_eq!(executions.load(Ordering::SeqCst), 2);
}
