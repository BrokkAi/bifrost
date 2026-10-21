#[cfg(test)]
mod js_ts_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::{OracleRelationSubject, SemanticWork};

    use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;

    pub (super) use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::assert_proven_local_dispatch as assert_proven_local_dispatch;

    pub (super) use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::first_call_in_artifact as first_call_in_artifact;

    pub (super) use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::semantic_call_fixture_for_language as semantic_call_fixture_for_language;
use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::CallSiteHandle;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTarget;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTargetResolution;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchBoundary;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchCandidate;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DispatchBoundaryKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::CancelledLookupArtifacts;
    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;
    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;
    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchTarget;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
    use brokk_bifrost_core::analyzer::model::CodeUnit;
    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::EvidenceCompleteness;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchResult;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ExactExternalFormalContract;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ExactExternalProcedureTarget;
    use brokk_bifrost_analysis::analyzer::semantic::trace::DispatchQuality;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::MaterializationInterruption;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::PreparedCallDispatch;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::ProcedureRangeLookupStatus;
    use brokk_bifrost_core::analyzer::model::Range;
    use std::cmp::Ordering;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;
    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticLocator;
    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceAnchor;
    use brokk_bifrost_analysis::analyzer::semantic::ids::SourcePosition;
    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceSpan;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGap;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapKind;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapSubject;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticProviderError;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::append_cancelled_target_boundaries;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::apply_dynamic_dispatch_gap;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::attach_dispatch_provenance;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::bound_dispatch_projection;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::cancelled_lookup_outcome;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::compare_dispatch_boundaries;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::compare_locator_fields;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::dispatch_result_work;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::dispatch_target_groups;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::finish_dispatch_interruption;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::materialization_interruption;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::procedures_for_definition_with_limits;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::procedures_for_source_ranges;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::semantic_locator_work;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::synthetic_unmaterialized_external;

    use brokk_bifrost_analysis::analyzer::semantic::call_relations::CallRelationWork;

    use brokk_bifrost_analysis::analyzer::semantic::OracleLimitValues;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::OracleRelationKind;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;

    use crate::analyzer::semantic::SemanticGapDischarge;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudgetDimension;

    use crate::analyzer::semantic::SemanticGapImpact;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticGapId;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticGapImpacts;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::CallableArity;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::model::ParameterMetadata;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::model::SignatureMetadata;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::js_ts_tests_support::calls_in_source_order as calls_in_source_order;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::dispatch_target_shape;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::js_ts_tests_support::external_call_identities as external_call_identities;

    fn semantic_call_fixture() -> (
        AnalyzerFixture,
        brokk_bifrost_analysis::analyzer::semantic::ir::CallSiteHandle,
    ) {
        semantic_call_fixture_for(
            "call.ts",
            "function target() {}\nexport function caller() { target(); }\n",
        )
    }
    fn semantic_call_fixture_for(
        name: &str,
        source: &str,
    ) -> (
        AnalyzerFixture,
        brokk_bifrost_analysis::analyzer::semantic::ir::CallSiteHandle,
    ) {
        semantic_call_fixture_for_language(Language::TypeScript, name, source)
    }
    fn assert_cancelled_boundary_provenance(
        result: &DispatchResult,
        target_evidence: brokk_bifrost_analysis::analyzer::semantic::EvidenceId,
    ) {
        assert!(result.boundaries().iter().all(|boundary| {
            matches!(boundary.kind, DispatchBoundaryKind::Unmaterialized(_))
                && boundary.provenance.len() == 1
                && boundary.provenance[0].record().evidence()[0].id() == target_evidence
                && matches!(
                    boundary.provenance[0].record().subject(),
                    Some(crate::analyzer::semantic::OracleRelationSubject::DispatchBoundary(subject))
                        if subject == &boundary.kind
                )
        }));
    }
    fn semantic_call_handle() -> brokk_bifrost_analysis::analyzer::semantic::ir::CallSiteHandle {
        semantic_call_fixture().1
    }
    const EXTERNAL_CALL_SOURCE: &str = "import { work } from \"third-party\";\nexport function caller(): number { work(); return 1; }\n";
    fn resolve_external_call(
        fixture: &AnalyzerFixture,
        call: &brokk_bifrost_analysis::analyzer::semantic::ir::CallSiteHandle,
    ) -> SemanticOutcome<DispatchResult> {
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        oracle
            .resolve_call(call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("external dispatch should run")
    }
    fn locator_with_anchor(locator: &SemanticLocator, offset: u32) -> SemanticLocator {
        let start = SourcePosition::new(offset, 0, offset);
        let end = SourcePosition::new(offset + 1, 0, offset + 1);
        SemanticLocator::new(
            locator.mount(),
            locator.path().clone(),
            locator.language(),
            locator.declaration().clone(),
            locator.role(),
            SourceAnchor::new(
                SourceSpan::new(start, end).expect("ordered fixture span"),
                0,
            ),
        )
    }
    fn retained_boundary_work(call: &CallSiteHandle, boundary: DispatchBoundary) -> SemanticWork {
        let mut candidates = Vec::new();
        let mut boundaries = vec![boundary];
        attach_dispatch_provenance(
            call,
            &mut candidates,
            &mut boundaries,
            None,
            None,
            OracleLimits::default(),
        )
        .expect("dispatch provenance projection");
        let result = DispatchResult::new(
            call,
            candidates,
            boundaries,
            CandidateCoverage::Open,
            OracleLimits::default(),
        )
        .expect("valid retained dispatch boundary");
        dispatch_result_work(&result)
    }
    /// The JavaScript fixture behind the #2598 acceptance. Each function holds
    /// one call whose owner carries a single segment -- the whole JS/TS
    /// standard surface -- written in one of the four shapes the issue names.
    const JS_EXTERNAL_CALL_SOURCE: &str = r#"import path from 'path';
import p from 'path';
import { Buffer } from 'buffer';
import { helper } from './helper';
const crypto = require('crypto');

export function joined(a, b) {
    return path.join(a, b);
}

export function aliased(a, b) {
    return p.join(a, b);
}

export function buffered(raw) {
    return Buffer.from(raw);
}

export function relative(raw) {
    return helper.run(raw);
}

export function generated() {
    return crypto.randomUUID();
}

export function parsed(raw) {
    return JSON.parse(raw);
}

export function local(opts, raw) {
    return opts.parse(raw);
}

export function shadowed(raw) {
    const JSON = makeCodec();
    return JSON.parse(raw);
}
"#;
    #[test]
    fn adapter_proven_local_callback_bypasses_source_rediscovery() {
        let source = "export function caller() { const callback = () => 1; callback(); }\n";
        let (fixture, call) = semantic_call_fixture_for("callback.ts", source);
        let declared_target = match &call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets
        {
            CallableTargetResolution::Proven(CallableTarget::Local(target)) => *target,
            other => panic!("expected one adapter-proven local callback, got {other:?}"),
        };
        let artifact = Arc::clone(call.procedure().artifact());
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = session
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("adapter-proven callback dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("adapter-proven local dispatch must be complete: {outcome:?}");
        };

        assert_proven_local_dispatch(&value, declared_target);
        assert!(!value.candidates()[0].provenance().is_empty());
        assert_eq!(budget.used().source_bytes, source.len());
        assert!(session.retained_bytes() >= source.len());
    }
    #[test]
    fn resolver_call_after_declared_local_callback_does_not_recharge_source() {
        let source = "function target() {}\nexport function caller() { const callback = () => 1; callback(); target(); }\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("callback.ts", source)]);
        let file = ProjectFile::new(fixture.project_root(), "callback.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let calls = calls_in_source_order(&artifact);
        assert_eq!(calls.len(), 2, "fixture has callback and named calls");
        assert!(matches!(
            calls[0]
                .procedure()
                .semantics()
                .call_site(calls[0].id())
                .expect("callback call row")
                .declared_targets,
            CallableTargetResolution::Proven(CallableTarget::Local(_))
        ));

        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let mut budget = SemanticBudget::default();
        for call in &calls {
            let outcome = session
                .resolve_call(call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .expect("prepared dispatch");
            assert!(outcome.available_value().is_some(), "{outcome:?}");
        }
        assert_eq!(budget.used().source_bytes, 2 * source.len());
        assert_eq!(budget.root_work_peak().source_bytes, source.len());
        assert_eq!(budget.resident().source_bytes, source.len());
    }
    #[test]
    fn prepared_dispatch_session_rejects_a_same_key_distinct_artifact_allocation() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::TypeScript,
            &[(
                "call.ts",
                "function target() {}\nexport function caller() { target(); }\n",
            )],
        );
        let second_workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(fixture.test_project().clone()),
            AnalyzerConfig::default(),
        )
        .expect("second workspace over the same immutable project");
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let cancellation = CancellationToken::default();
        let materialize = |workspace: &WorkspaceAnalyzer| {
            let mut budget = SemanticBudget::default();
            workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("TypeScript semantic materialization")
                .available_value()
                .cloned()
                .expect("TypeScript semantic artifact")
        };
        let selected = materialize(&fixture.analyzer);
        let same_key_sibling = materialize(&second_workspace);
        assert_eq!(selected.key(), same_key_sibling.key());
        assert!(!Arc::ptr_eq(&selected, &same_key_sibling));
        let sibling_call = first_call_in_artifact(&same_key_sibling);
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(selected);
        let mut budget = SemanticBudget::default();
        let error = session
            .resolve_call(
                &sibling_call,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect_err("same-key handles from a distinct allocation are rejected");
        assert!(matches!(error, SemanticProviderError::InvalidIdentity(_)));

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let outcome = session
            .resolve_call(
                &sibling_call,
                &mut SemanticRequest::new(&mut budget, &cancelled),
            )
            .expect("cancellation takes precedence over identity validation");
        assert!(matches!(outcome, SemanticOutcome::Cancelled { .. }));
    }
    #[test]
    fn prepared_dispatch_freezes_source_after_first_demand_but_new_session_revalidates() {
        let source = "function first() {}\nfunction second() {}\nexport function caller() { first(); second(); }\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "call.ts");
        file.write(source).expect("write TypeScript fixture");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let project: Arc<dyn Project> = overlay.clone();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("overlay workspace");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("initial overlay materialization")
            .available_value()
            .cloned()
            .expect("initial overlay artifact");
        let calls = calls_in_source_order(&artifact);
        assert_eq!(calls.len(), 2, "fixture has two call sites");
        let oracle = workspace.semantic_oracle_provider();

        let mut expected_budget = SemanticBudget::default();
        let expected_second = oracle
            .resolve_call(
                &calls[1],
                &mut SemanticRequest::new(&mut expected_budget, &cancellation),
            )
            .expect("second-call baseline before overlay mutation");
        let expected_second_shape = dispatch_target_shape(&expected_second);

        let mut prepared = oracle.prepare_call_dispatch_session(Arc::clone(&artifact));
        let mut prepared_budget = SemanticBudget::default();
        let first = prepared
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut prepared_budget, &cancellation),
            )
            .expect("first demand freezes the caller snapshot");
        assert!(!dispatch_target_shape(&first).is_empty());

        // The prepared contract freezes the caller source/tree, not every
        // downstream declaration snapshot. Keep the local target declarations
        // at the same coordinates while changing the caller generation, so a
        // retained session can still materialize its frozen `second` target.
        let changed_source = source.replace("first(); second();", "first(); first(); ");
        assert_eq!(changed_source.len(), source.len());
        assert_ne!(changed_source, source);
        assert!(overlay.set(file.abs_path(), changed_source));
        let retained_second = prepared
            .resolve_call(
                &calls[1],
                &mut SemanticRequest::new(&mut prepared_budget, &cancellation),
            )
            .expect("the active prepared window remains on its frozen source snapshot");
        assert_eq!(
            dispatch_target_shape(&retained_second),
            expected_second_shape
        );

        let mut fresh = oracle.prepare_call_dispatch_session(artifact);
        let mut fresh_budget = SemanticBudget::default();
        let error = fresh
            .resolve_call(
                &calls[1],
                &mut SemanticRequest::new(&mut fresh_budget, &cancellation),
            )
            .expect_err("a new session revalidates the old handle against the new overlay");
        assert!(matches!(error, SemanticProviderError::InvalidIdentity(_)));
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5113: prepared-pool-only syntax consumed subsequent roots' resident source allowance"
    )]
    fn prepared_pool_source_residency_ends_with_the_active_session() {
        let source = "function target() {}\nexport function caller() { target(); }\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("calls.ts", source)]);
        let file = ProjectFile::new(fixture.project_root(), "calls.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("materialize caller")
            .available_value()
            .cloned()
            .expect("caller artifact");
        let calls = calls_in_source_order(&artifact);
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let pool = oracle.prepare_workspace_dispatch_pool();
        for _ in 0..2 {
            let mut root = SemanticBudget::new_root_child(&budget);
            let result = pool
                .resolve_call(
                    &calls[0],
                    &mut SemanticRequest::new(&mut root, &cancellation),
                )
                .expect("resolve call through prepared pool");
            assert!(!dispatch_target_shape(&result).is_empty());
            assert!(pool.sessions.entry_count() > 0, "prepared syntax is cached");
            assert_eq!(
                root.resident().source_bytes,
                0,
                "returning the active session refunds source even while the pool retains syntax"
            );
            budget.absorb_root_work(root);
            assert_eq!(budget.resident().source_bytes, 0);
        }
    }
    #[test]
    fn later_lookup_truncation_exceeds_nested_entries_after_source_was_paid_once() {
        let source = "import { open } from \"third-party\";\nexport function caller() { open(\"a\"); open(\"b\"); }\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("calls.ts", source)]);
        let file = ProjectFile::new(fixture.project_root(), "calls.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript materialization")
            .available_value()
            .cloned()
            .expect("TypeScript artifact");
        let calls = calls_in_source_order(&artifact);
        assert_eq!(calls.len(), 2, "fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();

        let mut calibration = oracle.prepare_call_dispatch_session(Arc::clone(&artifact));
        let mut calibration_budget = SemanticBudget::default();
        calibration
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut calibration_budget, &cancellation),
            )
            .expect("calibrate first-call nested work");
        let first_nested = calibration_budget.root_work_peak().nested_entries;
        let retained_nested = calibration_budget.resident_peak().nested_entries;
        assert!(first_nested > 0);

        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = source.len();
        limits.nested_entries = first_nested.saturating_add(1);
        assert!(retained_nested > 0 && retained_nested <= limits.nested_entries);
        let parent = SemanticBudget::new(limits).expect("positive work limits");
        let mut resident_limits = limits;
        resident_limits.nested_entries = retained_nested;
        let mut budget = SemanticBudget::new_child(resident_limits, &parent.scope_snapshot());
        let mut prepared = oracle.prepare_call_dispatch_session(Arc::clone(&artifact));
        let first = prepared
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("first call fits the one-source budget");
        assert!(first.available_value().is_some(), "{first:?}");
        assert_eq!(budget.used().source_bytes, 2 * source.len());
        assert!(budget.root_work_peak().nested_entries > 0);

        let truncated_lookup = || CallDispatchLookup {
            status: Some(DefinitionLookupStatus::Ambiguous),
            boundaries: vec![CallDispatchBoundaryKind::Truncated],
            truncated: true,
            budget_exhausted: true,
            work: CallRelationWork {
                examined_candidates: 1,
                ..CallRelationWork::default()
            },
            ..CallDispatchLookup::default()
        };
        let second = oracle
            .resolve_prepared_call(
                &calls[1],
                PreparedCallDispatch {
                    lookup: truncated_lookup(),
                },
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("later truncated lookup remains a typed exhaustion");
        let SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        } = second
        else {
            panic!("a partial that cannot be admitted must be dropped: {second:?}");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
        assert_eq!(work.source_bytes, 0);
        assert_eq!(budget.used().source_bytes, 2 * source.len());

        let mut retaining = oracle.prepare_call_dispatch_session(artifact);
        let mut retaining_budget = SemanticBudget::default();
        let first = retaining
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut retaining_budget, &cancellation),
            )
            .expect("first call fits before the retainable truncation");
        assert!(first.available_value().is_some(), "{first:?}");
        assert_eq!(retaining_budget.used().source_bytes, 2 * source.len());
        let retained = oracle
            .resolve_prepared_call(
                &calls[1],
                PreparedCallDispatch {
                    lookup: truncated_lookup(),
                },
                &mut SemanticRequest::new(&mut retaining_budget, &cancellation),
            )
            .expect("the admitted later truncation retains its typed partial");
        let SemanticOutcome::Unproven { partial, work } = retained else {
            panic!(
                "a retainable truncated lookup stays unproven without work refusal: {retained:?}"
            );
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Truncated);
        assert_eq!(work.source_bytes, 0);
        assert_eq!(retaining_budget.used().source_bytes, 2 * source.len());
    }
    /// #1599: a boundary outcome is only as complete as its refined external
    /// evidence. The direct named import proves an unmaterialized external
    /// target, but absent dependency discovery and open dispatch prevent a
    /// closed target set, so the outcome is `Unproven`.
    #[test]
    fn undeclared_external_call_dispatch_is_unproven() {
        let (fixture, call) = semantic_call_fixture_for("external.ts", EXTERNAL_CALL_SOURCE);
        let outcome = resolve_external_call(&fixture, &call);
        let SemanticOutcome::Unproven {
            partial: result, ..
        } = outcome
        else {
            panic!("undeclared external dispatch must be Unproven: {outcome:?}");
        };
        assert!(
            result
                .boundaries()
                .iter()
                .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::External(_))),
            "{result:?}"
        );
    }
    #[test]
    fn declaration_procedure_lookup_charges_and_observes_cancellation_per_comparison() {
        let (fixture, call) = semantic_call_fixture();
        let definition = fixture
            .analyzer
            .analyzer()
            .get_definitions("target")
            .into_iter()
            .next()
            .expect("target definition");
        let artifact = call.procedure().artifact();

        let cancellation = CancellationToken::default();
        let bounded = procedures_for_definition_with_limits(
            fixture.analyzer.analyzer(),
            &definition,
            artifact,
            1,
            &cancellation,
        );
        assert_eq!(bounded.status, ProcedureRangeLookupStatus::BudgetExhausted);
        assert_eq!(bounded.examined, 1);
        assert!(bounded.handles.is_empty());

        let range_bounded = procedures_for_definition_with_limits(
            fixture.analyzer.analyzer(),
            &definition,
            artifact,
            3,
            &cancellation,
        );
        assert_eq!(
            range_bounded.status,
            ProcedureRangeLookupStatus::BudgetExhausted
        );
        assert_eq!(
            range_bounded.examined, 3,
            "stored declaration ranges must not be cloned past the remaining budget"
        );
        assert!(range_bounded.handles.is_empty());

        cancellation.cancel();
        let cancelled = procedures_for_definition_with_limits(
            fixture.analyzer.analyzer(),
            &definition,
            artifact,
            usize::MAX,
            &cancellation,
        );
        assert_eq!(cancelled.status, ProcedureRangeLookupStatus::Cancelled);
        assert_eq!(cancelled.examined, 0);
        assert!(cancelled.handles.is_empty());
    }
    #[test]
    fn source_range_procedure_lookup_budgets_sorting_and_materialization() {
        let (_fixture, call) = semantic_call_fixture();
        let artifact = call.procedure().artifact();
        let ranges = artifact
            .procedures()
            .iter()
            .map(|procedure| {
                let span = procedure.locator().anchor().span();
                Range {
                    start_byte: span.start_byte() as usize,
                    end_byte: span.end_byte() as usize,
                    start_line: span.start().line() as usize,
                    end_line: span.end().line() as usize,
                }
            })
            .collect::<Vec<_>>();
        assert!(ranges.len() > 1, "fixture must exercise the sorting path");

        let cancellation = CancellationToken::default();
        let complete = procedures_for_source_ranges(artifact, &ranges, usize::MAX, &cancellation);
        assert_eq!(complete.status, ProcedureRangeLookupStatus::Complete);
        assert_eq!(complete.handles.len(), artifact.procedures().len());

        let bounded = procedures_for_source_ranges(
            artifact,
            &ranges,
            complete.examined - 1,
            &CancellationToken::default(),
        );
        assert_eq!(bounded.status, ProcedureRangeLookupStatus::BudgetExhausted);
        assert_eq!(bounded.examined, complete.examined - 1);
        assert!(bounded.handles.is_empty());

        let mid_lookup_cancellation =
            CancellationToken::cancel_after_checks_for_test(complete.examined);
        let cancelled =
            procedures_for_source_ranges(artifact, &ranges, usize::MAX, &mid_lookup_cancellation);
        assert_eq!(cancelled.status, ProcedureRangeLookupStatus::Cancelled);
        assert_eq!(cancelled.examined, complete.examined - 1);
        assert!(cancelled.handles.is_empty());
    }
    #[test]
    fn dispatch_boundary_order_uses_typed_variants_and_numeric_locator_fields() {
        use crate::analyzer::semantic::DeferredInvocationKind;

        let locator = semantic_call_handle()
            .procedure()
            .semantics()
            .locator()
            .clone();
        let early = locator_with_anchor(&locator, 2);
        let late = locator_with_anchor(&locator, 10);

        assert_eq!(compare_locator_fields(&early, &late), Ordering::Less);

        let boundary = |kind| DispatchBoundary {
            kind,
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            provenance: Box::new([]),
        };
        let identity_only = |owner| DispatchBoundary {
            kind: DispatchBoundaryKind::External(None),
            external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                Language::Go,
                owner,
                "Open",
            )),
            exact_external_target: None,
            unmaterialized_external_target: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            provenance: Box::new([]),
        };
        let mut boundaries = vec![
            boundary(DispatchBoundaryKind::Truncated),
            boundary(DispatchBoundaryKind::Deferred {
                target: late,
                kind: DeferredInvocationKind::Generator,
            }),
            boundary(DispatchBoundaryKind::Unresolved),
            boundary(DispatchBoundaryKind::Unmaterialized(early.clone())),
            boundary(DispatchBoundaryKind::External(Some(early))),
            identity_only("z.example/package"),
            identity_only("a.example/package"),
            boundary(DispatchBoundaryKind::External(None)),
        ];
        boundaries.sort_by(compare_dispatch_boundaries);

        assert_eq!(
            boundaries[1]
                .external_callee_identity()
                .expect("first identity-only boundary")
                .owner_fqn(),
            "a.example/package"
        );
        assert_eq!(
            boundaries[2]
                .external_callee_identity()
                .expect("second identity-only boundary")
                .owner_fqn(),
            "z.example/package"
        );

        assert!(matches!(
            boundaries.as_slice(),
            [
                DispatchBoundary {
                    kind: DispatchBoundaryKind::External(None),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::External(None),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::External(None),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::External(Some(_)),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::Unmaterialized(_),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::Deferred { .. },
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::Unresolved,
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::Truncated,
                    ..
                },
            ]
        ));
    }
    #[test]
    fn cancelled_partial_is_open_and_charges_its_retained_boundary() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let observed_work = SemanticWork {
            source_bytes: 64,
            call_sites: 1,
            nested_entries: 3,
            ..SemanticWork::default()
        };
        let (fixture, call) = semantic_call_fixture();
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            OracleLimits::default(),
            CancelledLookupArtifacts {
                resolved_targets: &[],
                low_level_boundaries: &[CallDispatchBoundaryKind::Unresolved(
                    DefinitionLookupStatus::NotFound,
                )],
                exact_external_call: None,
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("cancelled lookup outcome");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            work,
        } = outcome
        else {
            panic!("retained cancelled lookup must publish one partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Open);
        assert_eq!(partial.boundaries().len(), 1);
        assert_eq!(work.nested_entries, observed_work.nested_entries + 4);
        assert_eq!(partial.boundaries()[0].provenance.len(), 1);
        assert!(work.owned_text_bytes > 0);
        assert_eq!(budget.used(), work);
    }
    #[test]
    fn cancelled_partial_preserves_an_independent_projection_cap() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            OracleLimits::uniform(1).expect("positive oracle limits"),
            CancelledLookupArtifacts {
                resolved_targets: &[],
                low_level_boundaries: &[
                    CallDispatchBoundaryKind::External {
                        callee_text: None,
                        normalized_static_owner: None,
                        external_callee_identity: None,
                    },
                    CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NotFound),
                ],
                exact_external_call: None,
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("projection-capped cancelled lookup outcome");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("projection-capped cancellation must retain its partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Truncated);
        assert_eq!(partial.boundaries().len(), 1);
    }
    #[test]
    fn cancelled_partial_preserves_a_retained_truncated_boundary() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            OracleLimits::default(),
            CancelledLookupArtifacts {
                resolved_targets: &[],
                low_level_boundaries: &[CallDispatchBoundaryKind::Truncated],
                exact_external_call: None,
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("truncated cancelled lookup outcome");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("cancelled lookup must retain its truncated boundary")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Truncated);
        assert!(matches!(
            partial.boundaries(),
            [DispatchBoundary {
                kind: DispatchBoundaryKind::Truncated,
                ..
            }]
        ));
    }
    #[test]
    fn cancelled_partial_preserves_resolved_targets_as_typed_boundaries() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let target = CallDispatchTarget {
            definition: CodeUnit::new(
                ProjectFile::new(fixture.project_root(), "call.ts"),
                CodeUnitType::Function,
                "",
                "target",
            ),
            proof: UsageProof::Proven,
            native_incomplete_source_reason: None,
        };
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            OracleLimits::default(),
            CancelledLookupArtifacts {
                resolved_targets: &[target],
                low_level_boundaries: &[],
                exact_external_call: None,
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("cancelled target projection");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("resolved cancelled target must remain in the partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Open);
        assert!(matches!(
            partial.boundaries(),
            [DispatchBoundary {
                kind: DispatchBoundaryKind::Unmaterialized(_),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Partial(_),
                ..
            }]
        ));
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("semantic call row");
        assert_cancelled_boundary_provenance(&partial, call_row.target_evidence);
    }
    #[test]
    fn cancelled_partial_caps_unique_resolved_target_identities() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let source = ProjectFile::new(fixture.project_root(), "call.ts");
        let target = CallDispatchTarget {
            definition: CodeUnit::new(source.clone(), CodeUnitType::Function, "", "target"),
            proof: UsageProof::Unproven,
            native_incomplete_source_reason: None,
        };
        let proven_duplicate = CallDispatchTarget {
            definition: target.definition.clone(),
            proof: UsageProof::Proven,
            native_incomplete_source_reason: None,
        };
        let caller = CallDispatchTarget {
            definition: CodeUnit::new(source, CodeUnitType::Function, "", "caller"),
            proof: UsageProof::Proven,
            native_incomplete_source_reason: None,
        };
        let limits = OracleLimits::new(OracleLimitValues {
            dispatch_targets: 2,
            ..OracleLimitValues::uniform(4)
        })
        .expect("positive dispatch limits");
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            limits,
            CancelledLookupArtifacts {
                resolved_targets: &[target, proven_duplicate, caller],
                low_level_boundaries: &[],
                exact_external_call: None,
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("deduplicated cancelled target projection");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("cancelled target projection must retain its partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Open);
        assert_eq!(partial.boundaries().len(), 2);
        assert!(
            partial.boundaries().iter().all(|boundary| {
                matches!(&boundary.kind, DispatchBoundaryKind::Unmaterialized(_))
            })
        );
        assert!(
            partial
                .boundaries()
                .iter()
                .all(|boundary| { matches!(&boundary.proof, ProofStatus::Proven) })
        );
    }
    #[test]
    fn late_cancellation_precedes_budget_and_caps_remaining_target_groups() {
        let (fixture, call) = semantic_call_fixture();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            materialization_interruption(DispatchQuality::Truncated, true, &cancellation),
            Some(MaterializationInterruption::Cancelled),
            "token cancellation must win when materialization also exceeds its budget"
        );

        let source = ProjectFile::new(fixture.project_root(), "call.ts");
        let targets = ["target", "caller", "not_materialized"]
            .into_iter()
            .map(|name| CallDispatchTarget {
                definition: CodeUnit::new(source.clone(), CodeUnitType::Function, "", name),
                proof: UsageProof::Proven,
                native_incomplete_source_reason: None,
            })
            .collect();
        let groups = dispatch_target_groups(fixture.analyzer.analyzer(), targets);
        let limits = OracleLimits::new(OracleLimitValues {
            provenance_records: 2,
            evidence_handles: 2,
            ..OracleLimitValues::uniform(4)
        })
        .expect("positive cancellation projection limits");
        let mut candidates = Vec::new();
        let mut boundaries = Vec::new();

        let truncated = append_cancelled_target_boundaries(
            fixture.analyzer.analyzer(),
            &candidates,
            &mut boundaries,
            groups,
            limits,
            None,
            None,
        )
        .expect("late-cancelled targets project to typed boundaries");
        assert!(truncated, "the omitted target group must remain observable");
        assert_eq!(
            boundaries.len(),
            2,
            "the helper must stop at the aggregate provenance/evidence cap"
        );

        boundaries.sort_by(compare_dispatch_boundaries);
        boundaries.dedup();
        assert!(!bound_dispatch_projection(
            &mut candidates,
            &mut boundaries,
            limits,
            None,
            None,
        ));
        assert_eq!(boundaries.len(), 2);
        attach_dispatch_provenance(&call, &mut candidates, &mut boundaries, None, None, limits)
            .expect("bounded late-cancellation provenance");
        let result = DispatchResult::new(
            &call,
            candidates,
            boundaries,
            CandidateCoverage::Truncated,
            limits,
        )
        .expect("bounded late-cancellation dispatch partial");
        let target_evidence = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("semantic call row")
            .target_evidence;
        assert_cancelled_boundary_provenance(&result, target_evidence);
    }
    #[test]
    fn cancellation_precedes_a_retained_budget_interruption() {
        let call = semantic_call_handle();
        let mut candidates = Vec::new();
        let mut boundaries = vec![DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
            proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
            completeness: EvidenceCompleteness::Partial("open dispatch".into()),
            provenance: Box::new([]),
        }];
        attach_dispatch_provenance(
            &call,
            &mut candidates,
            &mut boundaries,
            None,
            None,
            OracleLimits::default(),
        )
        .expect("dispatch provenance projection");
        let result = DispatchResult::new(
            &call,
            candidates,
            boundaries,
            CandidateCoverage::Open,
            OracleLimits::default(),
        )
        .expect("valid retained dispatch partial");
        let exceeded = SemanticBudget::uniform(1)
            .expect("positive semantic budget")
            .check_admission(SemanticWork {
                nested_entries: 2,
                ..SemanticWork::default()
            })
            .expect_err("work must exceed the nested-entry budget");
        let work = dispatch_result_work(&result);

        let outcome = *finish_dispatch_interruption(result, true, Some(exceeded), work)
            .expect_err("cancellation must remain the outer interruption");
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled {
                partial: Some(partial),
                work: retained_work,
            } if partial.coverage() == CandidateCoverage::Open && retained_work == work
        ));
    }
    #[test]
    fn cancelled_projection_truncates_to_the_total_evidence_limit() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let limits = OracleLimits::new(OracleLimitValues {
            provenance_records: 2,
            evidence_handles: 1,
            ..OracleLimitValues::uniform(2)
        })
        .expect("positive independent evidence limit");
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            limits,
            CancelledLookupArtifacts {
                resolved_targets: &[],
                low_level_boundaries: &[
                    CallDispatchBoundaryKind::External {
                        callee_text: None,
                        normalized_static_owner: None,
                        external_callee_identity: None,
                    },
                    CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NotFound),
                ],
                exact_external_call: None,
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("evidence-capped cancelled lookup outcome");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("evidence-capped cancellation must retain its partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Truncated);
        assert_eq!(partial.boundaries().len(), 1);
    }
    #[test]
    fn dispatch_provenance_uses_target_and_gap_evidence() {
        let call = semantic_call_handle();
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("semantic call row");
        let gap_evidence = call
            .procedure()
            .semantics()
            .evidence_rows()
            .iter()
            .find(|evidence| evidence.id != call_row.evidence)
            .map(|evidence| evidence.id)
            .expect("caller has independent semantic evidence");
        let exceeded = SemanticBudget::uniform(1)
            .expect("positive semantic budget")
            .check_admission(SemanticWork {
                nested_entries: 2,
                ..SemanticWork::default()
            })
            .expect_err("work must exceed the nested-entry budget");
        let gap = SemanticGap {
            id: SemanticGapId::new(0),
            point: call_row.point,
            subject: SemanticGapSubject::CallSite(call_row.id),
            capability: SemanticCapability::DynamicDispatch,
            impacts: SemanticGapImpacts::single(SemanticGapImpact::DispatchCoverage),
            kind: SemanticGapKind::ExceededBudget,
            budget: Some(exceeded),
            discharge: SemanticGapDischarge::None,
            detail: "dynamic target exploration exceeded its finite budget".into(),
            source: call_row.source,
            evidence: gap_evidence,
        };
        let mut candidates = vec![
            DispatchCandidate::new(
                call.procedure().clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
                OracleLimits::default(),
            )
            .expect("an empty dispatch draft fits every positive provenance limit"),
        ];
        let mut boundaries = Vec::new();
        assert_eq!(
            apply_dynamic_dispatch_gap(&gap, &mut boundaries),
            DispatchQuality::Truncated
        );
        assert!(matches!(
            boundaries.as_slice(),
            [DispatchBoundary {
                kind: DispatchBoundaryKind::Truncated,
                ..
            }]
        ));

        attach_dispatch_provenance(
            &call,
            &mut candidates,
            &mut boundaries,
            Some(&gap),
            None,
            OracleLimits::default(),
        )
        .expect("dispatch provenance projection");

        assert_eq!(
            candidates[0].provenance[0].record().kind(),
            OracleRelationKind::DispatchCandidate
        );
        assert_eq!(
            candidates[0].provenance[0].record().evidence()[0].id(),
            call_row.target_evidence
        );
        assert_eq!(
            boundaries[0].provenance[0].record().kind(),
            OracleRelationKind::DispatchBoundary
        );
        assert_eq!(
            boundaries[0].provenance[0].record().evidence()[0].id(),
            gap.evidence
        );
        assert!(matches!(
            boundaries[0].provenance[0].record().subject(),
            Some(OracleRelationSubject::DispatchBoundary(subject))
                if subject == &boundaries[0].kind
        ));
    }
    #[test]
    fn dispatch_gap_evidence_keeps_distinct_kinds_before_handle_deduplication() {
        let call = semantic_call_handle();
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("semantic call row");
        let shared_evidence = call
            .procedure()
            .semantics()
            .evidence_rows()
            .iter()
            .find(|evidence| evidence.id != call_row.evidence)
            .map(|evidence| evidence.id)
            .expect("caller has independent semantic evidence");
        let exceeded = SemanticBudget::uniform(1)
            .expect("positive semantic budget")
            .check_admission(SemanticWork {
                nested_entries: 2,
                ..SemanticWork::default()
            })
            .expect_err("work must exceed the nested-entry budget");
        let unsupported_gap = SemanticGap {
            id: SemanticGapId::new(0),
            point: call_row.point,
            subject: SemanticGapSubject::CallSite(call_row.id),
            capability: SemanticCapability::DynamicDispatch,
            impacts: SemanticGapImpacts::single(SemanticGapImpact::DispatchCoverage),
            kind: SemanticGapKind::Unsupported,
            budget: None,
            discharge: SemanticGapDischarge::None,
            detail: "dynamic target discovery is unsupported".into(),
            source: call_row.source,
            evidence: shared_evidence,
        };
        let exceeded_gap = SemanticGap {
            id: SemanticGapId::new(1),
            kind: SemanticGapKind::ExceededBudget,
            budget: Some(exceeded),
            discharge: SemanticGapDischarge::None,
            detail: "dynamic target exploration exceeded its finite budget".into(),
            ..unsupported_gap.clone()
        };
        let mut candidates = Vec::new();
        let mut boundaries = vec![
            DispatchBoundary {
                kind: DispatchBoundaryKind::Unresolved,
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
                completeness: EvidenceCompleteness::Partial("open dispatch".into()),
                provenance: Box::new([]),
            },
            DispatchBoundary {
                kind: DispatchBoundaryKind::Truncated,
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Unproven("dispatch limit reached".into()),
                completeness: EvidenceCompleteness::Partial("targets were omitted".into()),
                provenance: Box::new([]),
            },
        ];

        attach_dispatch_provenance(
            &call,
            &mut candidates,
            &mut boundaries,
            Some(&unsupported_gap),
            Some(&exceeded_gap),
            OracleLimits::default(),
        )
        .expect("dispatch gap provenance projection");

        assert!(boundaries.iter().all(|boundary| {
            boundary.provenance[0].record().evidence()
                == [call.procedure().evidence_handle(shared_evidence).unwrap()]
        }));
        assert!(boundaries.iter().all(|boundary| {
            matches!(
                boundary.provenance[0].record().subject(),
                Some(OracleRelationSubject::DispatchBoundary(subject))
                    if subject == &boundary.kind
            )
        }));
    }
    #[test]
    fn retained_boundary_work_includes_owned_locator_payload() {
        let call = semantic_call_handle();
        let locator = call.procedure().semantics().locator().clone();
        let locator_work = semantic_locator_work(&locator);
        let work = retained_boundary_work(
            &call,
            DispatchBoundary {
                kind: DispatchBoundaryKind::Unmaterialized(locator),
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                provenance: Box::new([]),
            },
        );

        assert_eq!(
            work.owned_text_bytes,
            locator_work.owned_text_bytes.saturating_mul(2)
        );
        assert_eq!(
            work.nested_entries,
            // Boundary row plus both the boundary and relation-subject locator
            // payloads, relation handle, relation record, and one evidence.
            1 + locator_work.nested_entries.saturating_mul(2) + 3
        );
    }
    #[test]
    fn retained_exact_external_boundary_work_includes_formal_contract_payload() {
        let call = semantic_call_handle();
        let locator = call.procedure().semantics().locator().clone();
        let locator_work = semantic_locator_work(&locator);
        let artifact = call.procedure().artifact().key().clone();
        let metadata = SignatureMetadata::new(
            "execute(String, int)",
            vec![
                ParameterMetadata::new("value", 0, 5),
                ParameterMetadata::new("radix", 7, 12),
            ],
        )
        .with_callable_arity(CallableArity::exact(2))
        .with_callable_parameter_types(vec!["String".to_owned(), "int".to_owned()]);
        let formal = ExactExternalFormalContract::from_metadata(&metadata)
            .expect("complete formal metadata");
        let formal_entries = formal.parameters().len();
        let formal_text_bytes =
            formal
                .parameters()
                .iter()
                .fold(formal.label().len(), |bytes, parameter| {
                    bytes
                        .saturating_add(parameter.label().len())
                        .saturating_add(parameter.declared_type().map_or(0, str::len))
                });
        let symbol = "execute(java.lang.String,int)";
        let target = ExactExternalProcedureTarget::new(
            artifact.clone(),
            locator.clone(),
            symbol,
            false,
            formal,
        )
        .expect("exact external target");
        let boundary = DispatchBoundary {
            kind: DispatchBoundaryKind::Unmaterialized(locator),
            external_callee_identity: None,
            exact_external_target: Some(target),
            unmaterialized_external_target: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            provenance: Box::new([]),
        };
        assert_eq!(
            boundary.proven_external_receiver_shape(),
            None,
            "a non-Go exact external target does not prove Go receiver shape"
        );
        let work = retained_boundary_work(&call, boundary);

        assert_eq!(
            work.nested_entries,
            5usize
                .saturating_add(locator_work.nested_entries.saturating_mul(3))
                .saturating_add(formal_entries),
            "boundary, target, formal, provenance, and all locator payloads are retained"
        );
        assert_eq!(
            work.owned_text_bytes,
            locator_work
                .owned_text_bytes
                .saturating_mul(3)
                .saturating_add(symbol.len())
                .saturating_add(artifact.path().as_str().len())
                .saturating_add(artifact.adapter().name().len())
                .saturating_add(formal_text_bytes),
            "the budget owns every exact-target and formal-contract string"
        );
    }
    #[test]
    fn retained_unmaterialized_external_boundary_work_includes_identity_payload() {
        let call = semantic_call_handle();
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure");
        let proof = ExactExternalCallProof::go_package_function("os.Open", 0);
        let target = synthetic_unmaterialized_external(
            "os.Open",
            SemanticLanguage::Standard(Language::Go),
            semantic_call,
            Some(&proof),
            None,
        )
        .expect("canonical Go package call");
        let locator = target.locator().clone();
        let locator_work = semantic_locator_work(&locator);
        let identity_text_bytes = target
            .owner_fqn()
            .len()
            .saturating_add(target.member().len());
        let work = retained_boundary_work(
            &call,
            DispatchBoundary {
                kind: DispatchBoundaryKind::External(Some(locator)),
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: Some(target),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                provenance: Box::new([]),
            },
        );

        assert_eq!(
            work.nested_entries,
            5usize.saturating_add(locator_work.nested_entries.saturating_mul(3)),
            "boundary, target, provenance, and all locator payloads are retained"
        );
        assert_eq!(
            work.owned_text_bytes,
            locator_work
                .owned_text_bytes
                .saturating_mul(3)
                .saturating_add(identity_text_bytes),
            "the budget owns the target locator, owner, and member strings"
        );
    }
    #[test]
    fn retained_identity_only_external_boundary_work_includes_owner_and_member() {
        let call = semantic_call_handle();
        let owner = "os";
        let member = "Open";
        let work = retained_boundary_work(
            &call,
            DispatchBoundary {
                kind: DispatchBoundaryKind::External(None),
                external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                    Language::Go,
                    owner,
                    member,
                )),
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                provenance: Box::new([]),
            },
        );

        assert_eq!(
            work.nested_entries, 5,
            "boundary, external identity, provenance handle, relation record, and evidence are retained"
        );
        assert_eq!(
            work.owned_text_bytes,
            owner.len().saturating_add(member.len()),
            "the budget owns the resolver-retained owner and member strings"
        );
    }
    /// #2598: a single-segment JavaScript owner publishes an external identity
    /// exactly when the file binds it to a package or binds it to nothing, and
    /// the identity carries the module's name rather than the local one.
    ///
    /// `has_receiver` is `true` for every case: unlike a Rust scoped path, a
    /// JS/TS member call *is* lowered with a receiver, so an authored JS/TS
    /// summary must declare `"has_receiver": true`.
    #[brokk_bifrost_test_macros::hardwon(
        "#2607: The retained test pins #2607/#3374: single-segment callees need their proved module or global identity"
    )]
    #[test]
    fn a_single_segment_javascript_callee_publishes_its_module_or_global_identity() {
        let identities =
            external_call_identities(Language::JavaScript, "lib.js", JS_EXTERNAL_CALL_SOURCE);
        assert_eq!(
            identities,
            vec![
                // A named import binds a member *of* the module, and that
                // member is the owner: never `buffer`.
                (
                    "Buffer.from(raw)".to_owned(),
                    Some(("Buffer".to_owned(), "from".to_owned(), 1, true))
                ),
                // The same global spelling under a local `const JSON` names
                // that local, so it mints nothing.
                ("JSON.parse(raw)".to_owned(), None),
                // A global nothing in the file binds is its own owner.
                (
                    "JSON.parse(raw)".to_owned(),
                    Some(("JSON".to_owned(), "parse".to_owned(), 1, true))
                ),
                // A CommonJS module-object binding names its module.
                (
                    "crypto.randomUUID()".to_owned(),
                    Some(("crypto".to_owned(), "randomUUID".to_owned(), 0, true))
                ),
                // A relative specifier addresses a workspace file, not a
                // package, so it names no external identity.
                ("helper.run(raw)".to_owned(), None),
                // An unqualified callee has no owner to decide at all.
                ("makeCodec()".to_owned(), None),
                // `opts` is a parameter. The receiver is a runtime value of the
                // enclosing procedure and no authored summary can claim it.
                ("opts.parse(raw)".to_owned(), None),
                // An aliased default import keys under the module it loads, so
                // it publishes the identity `path.join` publishes.
                (
                    "p.join(a, b)".to_owned(),
                    Some(("path".to_owned(), "join".to_owned(), 2, true))
                ),
                (
                    "path.join(a, b)".to_owned(),
                    Some(("path".to_owned(), "join".to_owned(), 2, true))
                ),
                // The module body executes the file-scope `const crypto =
                // require('crypto')`, so its call site is collected like the
                // call sites inside the function bodies (#3374). A bare
                // global callee has no owner to decide at all.
                ("require('crypto')".to_owned(), None),
            ]
        );
    }
    /// #2713: malformed or generated source can retain more than one static
    /// import for a local owner. Neither the last retained candidate nor any
    /// candidate before it is a proven package identity.
    #[test]
    fn competing_javascript_and_typescript_imports_publish_no_external_identity() {
        for (language, filename, source) in [
            (
                Language::JavaScript,
                "lib.js",
                r#"import api from "pkg-a";
import api from "pkg-b";
export function run(raw) { return api.exec(raw); }
"#,
            ),
            (
                Language::TypeScript,
                "lib.ts",
                r#"import api from "pkg-a";
import api from "pkg-b";
export function run(raw: string): string { return api.exec(raw); }
"#,
            ),
            (
                Language::JavaScript,
                "namespace.js",
                r#"import * as api from "pkg-a";
import * as api from "pkg-b";
export function run(raw) { return api.exec(raw); }
"#,
            ),
            (
                Language::TypeScript,
                "namespace.ts",
                r#"import * as api from "pkg-a";
import * as api from "pkg-b";
export function run(raw: string): string { return api.exec(raw); }
"#,
            ),
        ] {
            assert_eq!(
                external_call_identities(language, filename, source),
                vec![("api.exec(raw)".to_owned(), None)]
            );
        }
    }
    /// The import binder retains a bounded candidate set. Crossing that bound
    /// must not make the last retained package look exact.
    #[test]
    fn truncated_static_import_candidates_publish_no_external_identity() {
        for (language, filename, extension) in [
            (Language::JavaScript, "lib.js", ""),
            (Language::TypeScript, "lib.ts", ": string"),
        ] {
            let mut source = String::new();
            for package in 0..=brokk_bifrost_js_ts::syntax::MAX_STATIC_IMPORT_BINDINGS_PER_NAME {
                source.push_str(&format!("import api from 'pkg-{package}';\n"));
            }
            source.push_str(&format!(
                "export function run(raw{extension}) {{ return api.exec(raw); }}\n"
            ));
            assert_eq!(
                external_call_identities(language, filename, &source),
                vec![("api.exec(raw)".to_owned(), None)]
            );
        }
    }
}
