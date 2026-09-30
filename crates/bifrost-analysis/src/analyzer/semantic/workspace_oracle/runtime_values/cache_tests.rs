use std::sync::Arc;

use super::*;
use crate::CancellationToken;
use crate::analyzer::semantic::{
    ProcedureKind, SemanticBudget, SemanticExecutionBudget, SemanticOutcome,
};
use crate::analyzer::{Language, LanguageDialect, ProjectFile};
use crate::test_support::AnalyzerFixture;

fn javascript_fixture() -> AnalyzerFixture {
    AnalyzerFixture::new_for_language(Language::JavaScript, &[("probe.js", "")])
}

#[test]
fn many_python_procedures_share_syntax_but_keep_distinct_runtime_candidates() {
    let mut source = String::from("import sys\n");
    for index in 0..64 {
        source.push_str(&format!(
            "def read_{index}():\n    return sys.argv[{index}]\n"
        ));
    }
    let fixture = AnalyzerFixture::new_for_language(Language::Python, &[("probe.py", &source)]);
    let file = ProjectFile::new(fixture.project_root(), "probe.py");
    let cancellation = CancellationToken::default();
    let mut materialization_budget = SemanticBudget::default();
    let artifact = fixture
        .analyzer
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
        )
        .expect("Python semantic materialization")
        .available_value()
        .cloned()
        .expect("Python artifact");
    let mut limits = SemanticWork::default_limits();
    limits.source_bytes = source.len();
    let mut budget = SemanticBudget::new(limits).unwrap();
    let mut indices = Vec::new();
    for procedure in artifact
        .procedures()
        .iter()
        .filter(|procedure| procedure.kind() == ProcedureKind::Function)
    {
        let handle = artifact.procedure_handle(procedure.id()).unwrap();
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let outcome = oracle
            .runtime_reads_for_procedure(
                &handle,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("procedure runtime candidates");
        assert!(
            matches!(outcome, SemanticOutcome::Unproven { .. }),
            "{outcome:?}"
        );
        let result = outcome.available_value().unwrap();
        assert!(
            result
                .limitations
                .contains(&RuntimeReadLimitation::ActivationMissing),
            "{result:?}"
        );
        assert!(result.endpoints.is_empty());
        assert_eq!(result.candidates.len(), 1);
        let Some(RuntimeAccessKey::Index(index)) = result.candidates[0].key else {
            panic!("expected distinct argv index: {result:?}");
        };
        indices.push(index);
    }
    indices.sort_unstable();
    assert_eq!(indices, (0..64).collect::<Vec<u128>>());
    assert_eq!(budget.used().source_bytes, source.len());
    assert_eq!(budget.charged_artifact_count(), 1);
}

#[test]
fn independent_oracles_reuse_runtime_syntax_within_a_budget_scope() {
    let fixture = javascript_fixture();
    let dialect = LanguageDialect::Standard(Language::JavaScript);
    let source = "function first() { return process.env.FIRST; }";
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();

    let first_oracle = fixture.analyzer.semantic_oracle_provider();
    let first = first_oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("first runtime syntax extraction");
    let (first_value, first_work) = match first {
        SemanticOutcome::Complete { value, work } => (value, work),
        other => panic!("expected complete first extraction: {other:?}"),
    };

    let second_oracle = fixture.analyzer.semantic_oracle_provider();
    let second = second_oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("second runtime syntax extraction");
    let second_value = match second {
        SemanticOutcome::Complete { value, work } => {
            assert_eq!(work.source_bytes, 0);
            assert_eq!(work.nested_entries, 1);
            value
        }
        other => panic!("expected complete second extraction: {other:?}"),
    };

    assert!(Arc::ptr_eq(&first_value, &second_value));
    assert_eq!(budget.used().source_bytes, source.len());
    assert_eq!(budget.used().nested_entries, first_work.nested_entries + 1);

    let mut fresh_budget = SemanticBudget::default();
    let third_oracle = fixture.analyzer.semantic_oracle_provider();
    let third = third_oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut fresh_budget, &cancellation),
        )
        .expect("fresh-budget runtime syntax extraction");
    let third_value = match third {
        SemanticOutcome::Complete { value, work } => {
            assert_eq!(work.source_bytes, source.len());
            assert_eq!(work.nested_entries, first_work.nested_entries);
            value
        }
        other => panic!("expected complete fresh-budget extraction: {other:?}"),
    };

    assert!(Arc::ptr_eq(&first_value, &third_value));
    assert_eq!(fresh_budget.used().source_bytes, source.len());
    assert_eq!(
        fresh_budget.used().nested_entries,
        first_work.nested_entries
    );
}

fn complete_snapshot(
    oracle: &WorkspaceSemanticOracle<'_>,
    dialect: LanguageDialect,
    source: &str,
) -> Arc<RuntimeSyntaxSnapshot> {
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("runtime syntax extraction");
    let SemanticOutcome::Complete { value, .. } = outcome else {
        panic!("expected complete runtime syntax snapshot: {outcome:?}");
    };
    value
}

#[test]
fn cold_and_warm_runtime_syntax_agree_and_share_arc() {
    let fixture = javascript_fixture();
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let dialect = LanguageDialect::Standard(Language::JavaScript);
    let source = "function first() { return process.env.FIRST; }";

    let cancellation = CancellationToken::default();
    let mut cold_budget = SemanticBudget::default();
    let cold = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut cold_budget, &cancellation),
        )
        .expect("cold runtime syntax extraction");
    let cold_value = match cold {
        SemanticOutcome::Complete { value, .. } => value,
        other => panic!("expected complete cold extraction: {other:?}"),
    };
    assert!(cold_value.facts.complete);
    assert!(!cold_value.has_error);

    let mut same_scope_budget = SemanticBudget::default();
    let same_scope_cold = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut same_scope_budget,
                &cancellation,
            ),
        )
        .expect("same-scope cold runtime syntax extraction");
    let same_scope_cold_work = same_scope_cold.work();
    let same_scope_warm = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut same_scope_budget,
                &cancellation,
            ),
        )
        .expect("same-scope warm runtime syntax extraction");
    let same_scope_warm_value = match same_scope_warm {
        SemanticOutcome::Complete { value, work } => {
            assert_eq!(work.source_bytes, 0);
            assert_eq!(work.nested_entries, 1);
            value
        }
        other => panic!("expected complete same-scope warm extraction: {other:?}"),
    };
    let same_scope_cold_value = same_scope_cold.available_value().unwrap();
    assert!(Arc::ptr_eq(same_scope_cold_value, &same_scope_warm_value));
    assert_eq!(same_scope_budget.used().source_bytes, source.len());
    assert_eq!(
        same_scope_budget.used().nested_entries,
        same_scope_cold_work.nested_entries + 1
    );

    let mut warm_budget = SemanticBudget::default();
    let warm = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut warm_budget, &cancellation),
        )
        .expect("warm runtime syntax extraction");
    let warm_value = match warm {
        SemanticOutcome::Complete { value, work } => {
            assert_eq!(work.source_bytes, source.len());
            assert_eq!(work.nested_entries, cold_value.work.nested_entries);
            value
        }
        other => panic!("expected complete warm extraction: {other:?}"),
    };
    assert!(Arc::ptr_eq(&cold_value, &warm_value));
    assert_eq!(cold_value.facts.reads.len(), warm_value.facts.reads.len());
    assert_eq!(cold_value.facts.writes.len(), warm_value.facts.writes.len());
    assert_eq!(warm_budget.used().source_bytes, source.len());
    assert_eq!(
        warm_budget.used().nested_entries,
        cold_value.work.nested_entries
    );
}

#[test]
fn a_fresh_budget_warm_hit_still_needs_the_full_census() {
    let fixture = javascript_fixture();
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let dialect = LanguageDialect::Standard(Language::JavaScript);
    let source = "function first() { return process.env.FIRST; }";
    let snapshot = complete_snapshot(&oracle, dialect, source);
    assert!(snapshot.work.nested_entries > 1);

    let mut source_limited = SemanticBudget::default().limits();
    source_limited.source_bytes = source.len() - 1;
    let mut source_budget = SemanticBudget::new(source_limited).expect("source-limited budget");
    let source_outcome = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut source_budget,
                &CancellationToken::default(),
            ),
        )
        .expect("source-limited warm hit");
    assert_eq!(
        source_outcome.budget_exceeded().unwrap().dimension(),
        crate::analyzer::semantic::SemanticBudgetDimension::SourceBytes
    );

    let mut rows_limited = SemanticBudget::default().limits();
    rows_limited.nested_entries = snapshot.work.nested_entries - 1;
    let mut rows_budget = SemanticBudget::new(rows_limited).expect("rows-limited budget");
    let rows_outcome = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut rows_budget,
                &CancellationToken::default(),
            ),
        )
        .expect("rows-limited warm hit");
    assert_eq!(
        rows_outcome.budget_exceeded().unwrap().dimension(),
        crate::analyzer::semantic::SemanticBudgetDimension::NestedEntries
    );
}

#[test]
fn a_tiny_budget_does_not_publish_and_a_funded_retry_succeeds() {
    let fixture = javascript_fixture();
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let dialect = LanguageDialect::Standard(Language::JavaScript);
    let source = "function first() { return process.env.FIRST; }";
    let cancellation = CancellationToken::default();

    let mut tiny_budget = SemanticBudget::uniform(1).expect("positive tiny budget");
    let first = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut tiny_budget, &cancellation),
        )
        .expect("tiny-budget extraction");
    assert!(matches!(first, SemanticOutcome::ExceededBudget { .. }));

    let mut funded_budget = SemanticBudget::default();
    let retry = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut funded_budget, &cancellation),
        )
        .expect("funded retry");
    assert!(matches!(retry, SemanticOutcome::Complete { .. }));
    assert_eq!(funded_budget.used().source_bytes, source.len());
}

#[test]
fn a_cold_nested_entry_limit_does_not_publish_and_funded_retry_succeeds() {
    let fixture = javascript_fixture();
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let dialect = LanguageDialect::Standard(Language::JavaScript);
    let source = "function first() { return process.env.FIRST; }";
    let cancellation = CancellationToken::default();

    let mut limits = SemanticBudget::default().limits();
    limits.nested_entries = 1;
    let mut limited_budget = SemanticBudget::new(limits).expect("nested-entry-limited budget");
    let first = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut limited_budget,
                &cancellation,
            ),
        )
        .expect("cold nested-entry-limited extraction");
    assert!(matches!(
        &first,
        SemanticOutcome::ExceededBudget { .. } | SemanticOutcome::Unproven { .. }
    ));
    assert!(!matches!(&first, SemanticOutcome::Complete { .. }));

    let mut funded_budget = SemanticBudget::default();
    let retry = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut funded_budget, &cancellation),
        )
        .expect("funded retry after cold nested-entry limit");
    assert!(matches!(retry, SemanticOutcome::Complete { .. }));
}

#[test]
fn cancellation_does_not_publish_and_a_retry_succeeds() {
    let fixture = javascript_fixture();
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let dialect = LanguageDialect::Standard(Language::JavaScript);
    let source = "function first() { return process.env.FIRST; }";
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut cancelled_budget = SemanticBudget::default();
    let first = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut cancelled_budget, &cancelled),
        )
        .expect("cancelled extraction");
    assert!(matches!(first, SemanticOutcome::Cancelled { .. }));

    let mut funded_budget = SemanticBudget::default();
    let retry = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut funded_budget,
                &CancellationToken::default(),
            ),
        )
        .expect("retry after cancellation");
    assert!(matches!(retry, SemanticOutcome::Complete { .. }));
}

#[test]
fn source_and_dialect_change_cache_identity() {
    let fixture = javascript_fixture();
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let source = "const value = process.env.FIRST;";
    let standard = complete_snapshot(
        &oracle,
        LanguageDialect::Standard(Language::JavaScript),
        source,
    );
    let changed_source = complete_snapshot(
        &oracle,
        LanguageDialect::Standard(Language::JavaScript),
        "const value = process.env.SECOND;",
    );
    let jsx = complete_snapshot(&oracle, LanguageDialect::JavaScriptJsx, source);

    assert!(!Arc::ptr_eq(&standard, &changed_source));
    assert!(!Arc::ptr_eq(&standard, &jsx));
}

#[test]
fn parser_errors_are_complete_snapshots_with_error_marked() {
    let fixture = javascript_fixture();
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let source = "function broken( { return process.env.VALUE; }";
    let snapshot = complete_snapshot(
        &oracle,
        LanguageDialect::Standard(Language::JavaScript),
        source,
    );
    assert!(snapshot.facts.complete);
    assert!(snapshot.has_error);
}

#[test]
fn an_execution_traversal_cap_is_unproven_and_not_cached() {
    let fixture = javascript_fixture();
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let dialect = LanguageDialect::Standard(Language::JavaScript);
    let source = "function first() { return process.env.FIRST; }";
    let cancellation = CancellationToken::default();
    let execution = SemanticExecutionBudget::new(1, 0);
    let mut budget = SemanticBudget::default();
    let first = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::with_execution_budget(
                &mut budget,
                &cancellation,
                &execution,
            ),
        )
        .expect("execution-capped extraction");
    let partial = match first {
        SemanticOutcome::Unproven { partial, .. } => partial,
        other => panic!("expected execution-capped extraction to be unproven: {other:?}"),
    };

    let retry_execution = SemanticExecutionBudget::new(1, usize::MAX);
    let mut retry_budget = SemanticBudget::default();
    let retry = oracle
        .runtime_syntax_for_source(
            dialect,
            source,
            &mut crate::analyzer::semantic::SemanticRequest::with_execution_budget(
                &mut retry_budget,
                &CancellationToken::default(),
                &retry_execution,
            ),
        )
        .expect("retry after execution cap");
    let retry_value = match retry {
        SemanticOutcome::Complete { value, .. } => value,
        other => panic!("expected funded execution retry to complete: {other:?}"),
    };
    assert!(!Arc::ptr_eq(&partial, &retry_value));
}

#[test]
fn same_file_procedures_reuse_one_syntax_census_and_reject_stale_source() {
    let source = "function first() { return process.env.FIRST; }\nfunction second() { return process.env.SECOND; }\n";
    let fixture = AnalyzerFixture::new_for_language(Language::JavaScript, &[("probe.js", source)]);
    let file = ProjectFile::new(fixture.project_root(), "probe.js");
    let cancellation = CancellationToken::default();
    let mut materialization_budget = SemanticBudget::default();
    let artifact = fixture
        .analyzer
        .materialize_program_semantics(
            &file,
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut materialization_budget,
                &cancellation,
            ),
        )
        .expect("semantic materialization")
        .available_value()
        .cloned()
        .expect("semantic artifact");
    let procedure_at = |byte: usize| {
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.kind() == ProcedureKind::Function
                    && procedure.locator().anchor().span().start_byte() as usize == byte
            })
            .unwrap_or_else(|| panic!("no function procedure starts at byte {byte}"));
        artifact
            .procedure_handle(procedure.id())
            .expect("function procedure handle")
    };
    let first = procedure_at(source.find("function first").unwrap());
    let second = procedure_at(source.find("function second").unwrap());
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let mut limits = SemanticBudget::default().limits();
    limits.source_bytes = source.len();
    let mut budget = SemanticBudget::new(limits).expect("exact source budget");
    let first_outcome = oracle
        .runtime_reads_for_procedure(
            &first,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("first runtime read projection");
    assert!(matches!(&first_outcome, SemanticOutcome::Unproven { .. }));
    let first_result = first_outcome
        .available_value()
        .expect("first typed runtime result");
    assert!(
        first_result
            .limitations
            .contains(&RuntimeReadLimitation::ActivationMissing)
    );
    assert!(first_result.endpoints.is_empty());
    assert_eq!(first_result.candidates.len(), 1);
    assert_eq!(
        first_result.candidates[0].key,
        Some(RuntimeAccessKey::Property("FIRST".into()))
    );
    assert_eq!(budget.used().source_bytes, source.len());

    let second_outcome = oracle
        .runtime_reads_for_procedure(
            &second,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("second runtime read projection");
    assert!(matches!(&second_outcome, SemanticOutcome::Unproven { .. }));
    let second_result = second_outcome
        .available_value()
        .expect("second typed runtime result");
    assert!(
        second_result
            .limitations
            .contains(&RuntimeReadLimitation::ActivationMissing)
    );
    assert!(second_result.endpoints.is_empty());
    assert_eq!(second_result.candidates.len(), 1);
    assert_eq!(
        second_result.candidates[0].key,
        Some(RuntimeAccessKey::Property("SECOND".into()))
    );
    assert_eq!(budget.used().source_bytes, source.len());
    assert_eq!(budget.charged_artifact_count(), 1);

    file.write(source.replace("FIRST", "CHANGED"))
        .expect("edit source behind retained handle");
    let mut stale_budget = SemanticBudget::default();
    let stale = oracle
        .runtime_reads_for_procedure(
            &first,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut stale_budget, &cancellation),
        )
        .expect("stale source remains a typed result");
    let stale_result = stale.available_value().expect("stale evidence result");
    assert_eq!(
        stale_result.limitations,
        vec![RuntimeReadLimitation::StaleEvidence]
    );
}
