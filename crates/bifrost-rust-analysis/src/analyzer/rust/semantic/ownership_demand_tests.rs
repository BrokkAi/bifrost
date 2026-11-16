use super::*;
use crate::analyzer::i_analyzer::{AnalyzerQueryScope, capture_query_reads};
use crate::analyzer::rust::test_support::{certified_analyzer, project};
use crate::analyzer::semantic::service::CandidateProcedureSide;
use crate::analyzer::semantic_model::{
    CatalogCoordinate, CatalogPackSourceKind, CompilerOptions, SemanticModelActivationEvidence,
    SourceFormat, compile_source, test_snapshot_from_compiled_pack,
};
use brokk_bifrost_test_macros::hardwon;
use std::sync::Arc;

const SOURCE: &str = r#"fn subject() {
    println!("{}", { struct X; 1 });
    let p = std::alloc::alloc(layout);
    std::alloc::dealloc(p, layout);
}"#;

fn snapshot(revision: &str) -> Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot> {
    let pack = serde_json::json!({
        "schema_version": 2, "pack_id": "bifrost.rust-stdlib", "version": "1.100.0-nightly",
        "producer": {"name":"test-only", "version":"1.0.0"},
        "language":"rust", "ecosystem":"cargo",
        "compatibility":{"bifrost":"*", "toolchains":[{"name":"rust", "requirement":"=1.100.0-nightly"}]},
        "provenance":{"source":"test-only ownership macro audit", "revision":revision},
        "license":"NOASSERTION", "completeness":"complete",
        "safety":{"generated_code_only":false, "review_required":false},
        "shards":[{"id":"main", "activation":[{"package":{"name":"app"}}], "payload":{
            "kind":"declaration_facts", "types":[{
                "id":"std.marker", "name":"std.Marker", "type_kind":"struct", "visibility":"public",
                "locator":{"kind":"artifact", "path":"fixture.json", "symbol":"std.Marker"}
            }], "members":[], "relations":[]
        }}]
    });
    let compiled = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&pack).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    test_snapshot_from_compiled_pack(
        compiled,
        SemanticModelActivationEvidence {
            language: "rust".into(),
            ecosystem: "cargo".into(),
            package: Some(CatalogCoordinate {
                name: "app".into(),
                version: Some(semver::Version::new(0, 1, 0)),
            }),
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "rust".into(),
                version: Some(semver::Version::parse("1.100.0-nightly").unwrap()),
            }),
            target: None,
            configuration: None,
            artifact_sha256: None,
        },
        CatalogPackSourceKind::EphemeralWorkspace,
    )
}

fn fixture(
    source: &str,
) -> (
    tempfile::TempDir,
    crate::analyzer::workspace::WorkspaceAnalyzer,
) {
    let (temp, _) = project(&[
        (
            "Cargo.toml",
            "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        ),
        ("src/lib.rs", source),
    ]);
    let (workspace, _) = certified_analyzer(temp.path());
    (temp, workspace)
}

fn materialize(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
) -> crate::analyzer::semantic::ProcedureHandle {
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        "src/lib.rs",
    );
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .unwrap()
        .available_value()
        .unwrap()
        .clone();
    let id = artifact
        .procedures()
        .iter()
        .find(|procedure| procedure.locator().declaration().last_segment_name() == Some("subject"))
        .unwrap()
        .id();
    artifact.procedure_handle(id).unwrap()
}

fn forged_ownership_handle(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
    base: &crate::analyzer::semantic::ProcedureHandle,
) -> crate::analyzer::semantic::ProcedureHandle {
    let prepared = super::semantic_lowering_tests::prepare_fixture(SOURCE);
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        "src/lib.rs",
    );
    let SemanticOutcome::Complete { value: parts, .. } = lower_rust_file(
        &file,
        &prepared,
        &SemanticBudget::default(),
        &CancellationToken::default(),
        lower_lexical_procedure,
    )
    .unwrap() else {
        panic!("forged fixture is structurally valid");
    };
    let artifact = Arc::new(
        crate::analyzer::semantic::SemanticArtifact::try_new(
            base.artifact().key().clone(),
            base.artifact().capabilities().clone(),
            parts,
        )
        .unwrap(),
    );
    artifact.candidate_alternate_handle(base.id()).unwrap()
}

#[test]
#[hardwon("#11532: speculative println alternates exhausted ordinary native procedure budgets")]
fn ordinary_println_keeps_native_budget_profile() {
    let prepared =
        super::semantic_lowering_tests::prepare_fixture("fn subject() { println!(\"hello\"); }");
    let file = ProjectFile::new(std::env::temp_dir(), "capture.rs");
    let cancellation = CancellationToken::default();
    let native = RustSemanticLowerer
        .lower(&file, &prepared, &SemanticBudget::default(), &cancellation)
        .unwrap();
    let parts = native.available_value().unwrap();
    assert!(parts[0].candidate_macro_alternate_parts().is_none());
    let mut limits = SemanticBudget::default().limits();
    limits.program_points = parts[0].points.len();
    let budget = SemanticBudget::new(limits).unwrap();
    let bounded = RustSemanticLowerer
        .lower(&file, &prepared, &budget, &cancellation)
        .unwrap();
    assert!(matches!(bounded, SemanticOutcome::Complete { .. }));
    assert_eq!(budget.refusal_count(), 0);
    assert!(
        bounded.available_value().unwrap()[0]
            .candidate_macro_alternate_parts()
            .is_none()
    );
    // For this ordinary macro there are no executable candidates on master:
    // its published representation is exactly the unguarded base pass.
    let reference = lower_rust_file(
        &file,
        &prepared,
        &SemanticBudget::default(),
        &cancellation,
        |prepared, inputs, spec, budget, cancellation| {
            let mut candidates = LoweredCandidates::default();
            let result = lower_procedure_with_macro_pass(
                prepared,
                inputs,
                spec,
                budget,
                cancellation,
                RustMacroPass::Base,
                &mut candidates,
            );
            assert!(candidates.calls.is_empty());
            result
        },
    )
    .unwrap();
    assert_eq!(native.work(), reference.work());
    let SemanticOutcome::Complete {
        value: native_parts,
        ..
    } = native
    else {
        panic!("native complete");
    };
    let SemanticOutcome::Complete {
        value: reference_parts,
        ..
    } = reference
    else {
        panic!("base reference complete");
    };
    let key = crate::analyzer::semantic::service::semantic_artifact_key_from_content(
        &file,
        brokk_bifrost_core::analyzer::model::LanguageDialect::Standard(Language::Rust),
        crate::analyzer::semantic::ContentIdentity::hash_bytes(prepared.source().as_bytes()),
        None,
        RustSemanticLowerer.identity(),
    )
    .unwrap();
    let native = crate::analyzer::semantic::SemanticArtifact::try_new(
        key.clone(),
        RustSemanticLowerer.capabilities(),
        native_parts,
    )
    .unwrap();
    let reference = crate::analyzer::semantic::SemanticArtifact::try_new(
        key,
        RustSemanticLowerer.capabilities(),
        reference_parts,
    )
    .unwrap();
    assert_eq!(native.key(), reference.key());
    assert_eq!(native.materialization_id(), reference.materialization_id());
    assert_eq!(
        native.procedures()[0].parts_materialization_id(),
        reference.procedures()[0].parts_materialization_id()
    );
}

#[test]
#[hardwon("#11532: ownership refinements must not change ordinary executable selections")]
fn ownership_demand_isolated_from_native_and_executable_views() {
    use crate::analyzer::semantic::service::CandidateProcedureOutcome;
    let (_temp, workspace) = fixture(SOURCE);
    let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        Some(snapshot(
            brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION,
        )),
    );
    let base = materialize(&workspace);
    assert!(base.semantics().candidate_macro_alternate().is_none());
    assert!(base.semantics().pointer_origins().is_empty());
    let native_identity = base.semantics().parts_materialization_id();
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let mut request = SemanticRequest::new(&mut budget, &cancellation);
    let ordinary = workspace
        .selected_procedure_handle(&base, &mut request)
        .unwrap();
    assert_eq!(
        ordinary
            .available_value()
            .unwrap()
            .handle
            .semantics()
            .parts_materialization_id(),
        native_identity
    );
    let CandidateProcedureOutcome::Selected(before) = workspace
        .selected_procedure_and_flows(&base, &mut request)
        .unwrap()
    else {
        panic!("ordinary flows available");
    };
    let before_flows = format!("{:?}", before.flows);
    let (guarded, reads) = capture_query_reads(workspace.analyzer(), || {
        workspace
            .ownership_procedure_handle(&base, &mut request)
            .unwrap()
    });
    let guarded = guarded
        .available_value()
        .expect("audited ownership interpretation");
    assert_eq!(guarded.side, CandidateProcedureSide::Alternate);
    assert!(!guarded.handle.semantics().pointer_origins().is_empty());
    assert!(
        !guarded
            .handle
            .semantics()
            .pointer_invalidations()
            .is_empty()
    );
    assert!(
        reads
            .keys()
            .iter()
            .any(|key| matches!(key, crate::analyzer::ReadKey::Models(_)))
    );
    let (hit, hit_reads) = capture_query_reads(workspace.analyzer(), || {
        workspace
            .ownership_procedure_handle(&base, &mut request)
            .unwrap()
    });
    assert!(
        Arc::ptr_eq(
            guarded.handle.artifact(),
            hit.available_value().unwrap().handle.artifact()
        ),
        "completed ownership admission is request-memoized"
    );
    assert!(
        hit_reads
            .keys()
            .iter()
            .any(|key| matches!(key, crate::analyzer::ReadKey::Models(_))),
        "memo hits replay the audit read"
    );
    let (replayed, replay_reads) = capture_query_reads(workspace.analyzer(), || {
        workspace
            .replay_ownership_procedure_handle(&guarded.handle, &mut request)
            .unwrap()
    });
    assert_eq!(
        replayed.available_value().unwrap().as_ref().unwrap(),
        &guarded.handle
    );
    assert!(
        replay_reads
            .keys()
            .iter()
            .any(|key| matches!(key, crate::analyzer::ReadKey::Models(_)))
    );
    let base_replay = workspace
        .replay_ownership_procedure_handle(&base, &mut request)
        .unwrap();
    assert!(
        matches!(base_replay, SemanticOutcome::Complete { value: None, .. }),
        "transport never upgrades base"
    );
    let forged = forged_ownership_handle(&workspace, &base);
    assert_eq!(forged.durable_key(), guarded.handle.durable_key());
    assert_ne!(forged, guarded.handle);
    let forged_replay = workspace
        .replay_ownership_procedure_handle(&forged, &mut request)
        .unwrap();
    assert!(
        matches!(forged_replay, SemanticOutcome::Complete { value: None, .. }),
        "matching keys do not authorize a forged materialization"
    );
    let untrusted = workspace
        .selected_procedure_handle(&forged, &mut request)
        .unwrap();
    assert_eq!(
        untrusted.available_value().unwrap().side,
        CandidateProcedureSide::Base
    );
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut cancelled_budget = SemanticBudget::default();
    let cancelled_replay = workspace
        .replay_ownership_procedure_handle(
            &guarded.handle,
            &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
        )
        .unwrap();
    assert!(matches!(
        cancelled_replay,
        SemanticOutcome::Unknown { partial: None, .. }
    ));
    let mut limits = SemanticBudget::default().limits();
    limits.program_points = 1;
    let mut tiny_replay = SemanticBudget::new(limits).unwrap();
    let stopped_replay = workspace
        .replay_ownership_procedure_handle(
            &guarded.handle,
            &mut SemanticRequest::new(&mut tiny_replay, &cancellation),
        )
        .unwrap();
    assert!(matches!(
        stopped_replay,
        SemanticOutcome::Unknown { partial: None, .. }
    ));
    let after = workspace
        .selected_procedure_handle(&base, &mut request)
        .unwrap();
    assert_eq!(
        after.available_value().unwrap().side,
        CandidateProcedureSide::Base
    );
    assert_eq!(
        after
            .available_value()
            .unwrap()
            .handle
            .semantics()
            .parts_materialization_id(),
        native_identity
    );
    let CandidateProcedureOutcome::Selected(after) = workspace
        .selected_procedure_and_flows(&base, &mut request)
        .unwrap()
    else {
        panic!("ordinary flows remain available");
    };
    assert_eq!(format!("{:?}", after.flows), before_flows);
    assert_eq!(base.semantics().parts_materialization_id(), native_identity);
}

#[test]
#[hardwon("#11532: stopped ownership acquisitions must not hide higher-budget refinements")]
fn ownership_budget_and_cancellation_stops_are_not_cached() {
    let (_temp, workspace) = fixture(SOURCE);
    let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        Some(snapshot(
            brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION,
        )),
    );
    let base = materialize(&workspace);
    let cancellation = CancellationToken::default();
    let mut limits = SemanticBudget::default().limits();
    limits.program_points = base.semantics().points().len();
    let mut tiny = SemanticBudget::new(limits).unwrap();
    let omissions = AnalyzerQueryScope::capturing_read_incompleteness(workspace.analyzer());
    let low = workspace
        .ownership_procedure_handle(&base, &mut SemanticRequest::new(&mut tiny, &cancellation))
        .unwrap();
    assert!(matches!(
        low,
        SemanticOutcome::Unknown { partial: None, .. }
    ));
    assert_eq!(
        tiny.refusal_count(),
        0,
        "refinement must not poison base analysis"
    );
    assert!(
        omissions
            .captured_read_incompleteness()
            .iter()
            .any(|reason| {
                matches!(
                    reason.base_cause(),
                    crate::analyzer::i_analyzer::QueryReadIncomplete::ProofStopped {
                        cause: Some(crate::analyzer::read_ledger::DerivationExecutionCause::Budget),
                        ..
                    }
                )
            })
    );
    drop(omissions);
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut budget = SemanticBudget::default();
    let stop = workspace
        .ownership_procedure_handle(&base, &mut SemanticRequest::new(&mut budget, &cancelled))
        .unwrap();
    assert!(matches!(
        stop,
        SemanticOutcome::Unknown { partial: None, .. }
    ));
    let forged = forged_ownership_handle(&workspace, &base);
    let unadmitted = workspace
        .replay_ownership_procedure_handle(
            &forged,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
    assert!(
        matches!(unadmitted, SemanticOutcome::Complete { value: None, .. }),
        "stopped acquisitions created no replay authority"
    );
    let mut high = SemanticBudget::default();
    let result = workspace
        .ownership_procedure_handle(&base, &mut SemanticRequest::new(&mut high, &cancellation))
        .unwrap();
    assert!(
        !result
            .available_value()
            .expect("higher-budget rerun completes")
            .handle
            .semantics()
            .pointer_origins()
            .is_empty()
    );
    assert!(base.semantics().candidate_macro_alternate().is_none());
}

#[test]
#[hardwon("#11532: ownership lexical proofs require exact selected audit and unshadowed macros")]
fn ownership_demand_refuses_missing_audit_and_shadowed_macro() {
    for (source, revision) in [
        (SOURCE.to_owned(), "other-revision"),
        (
            format!("macro_rules! println {{ ($($t:tt)*) => {{ struct Generated; }} }} {SOURCE}"),
            brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION,
        ),
    ] {
        let (_temp, workspace) = fixture(&source);
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            Some(snapshot(revision)),
        );
        let base = materialize(&workspace);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let result = workspace
            .ownership_procedure_handle(
                &base,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        assert!(matches!(
            result,
            SemanticOutcome::Unknown { partial: None, .. }
        ));
    }
}

fn legacy_acquire(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
    base: &crate::analyzer::semantic::ProcedureHandle,
    budget: &mut SemanticBudget,
) -> SemanticOutcome<Option<crate::analyzer::semantic::service::SelectedProcedureHandle>> {
    let cancellation = CancellationToken::default();
    if let Err(exceeded) = budget.charge_complete_artifact(base.artifact()) {
        return SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        };
    }
    let _ = workspace
        .selected_procedure_handle(base, &mut SemanticRequest::new(budget, &cancellation))
        .unwrap();
    let mut proof = budget.unit_ledger();
    if let Err(exceeded) = proof.admit(budget.resident()) {
        return SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        };
    }
    let inherited = proof.performed();
    let result = legacy_ownership_procedure_interpretation(
        workspace,
        base,
        &mut SemanticRequest::new(&mut proof, &cancellation),
    )
    .unwrap();
    budget.charge_work(proof.performed().saturating_sub(inherited));
    if let Some(Some(selected)) = result.available_value()
        && let Err(exceeded) = budget.charge_complete_artifact(selected.handle.artifact())
    {
        return SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        };
    }
    result
}

#[test]
#[hardwon("#11532: per-procedure ownership demands rebuilt and retained a whole file each")]
fn ownership_shared_file_matches_558_per_consumer_and_demand_order() {
    let source = (0..12).map(|index| format!("fn {}() {{ println!(\"hello\"); let p = std::alloc::alloc(layout); std::alloc::dealloc(p, layout); }}\n", if index == 0 {"subject".to_owned()} else {format!("subject{index}")})).collect::<String>();
    let (_temp, workspace) = fixture(&source);
    let cancellation = CancellationToken::default();
    let active = Some(snapshot(
        brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION,
    ));
    let bases = {
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            active.clone(),
        );
        let first = materialize(&workspace);
        first
            .artifact()
            .procedures()
            .iter()
            .map(|procedure| first.artifact().procedure_handle(procedure.id()).unwrap())
            .collect::<Vec<_>>()
    };
    let mut expected = Vec::new();
    for base in &bases {
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            active.clone(),
        );
        let mut budget = SemanticBudget::default();
        let result = legacy_acquire(&workspace, base, &mut budget);
        let selected = result.available_value().unwrap().as_ref().unwrap();
        expected.push((
            budget.performed(),
            selected.handle.artifact().materialization_id(),
            selected.handle.artifact().work(),
            format!("{:?}", selected.handle.semantics().pointer_origins()),
        ));
    }
    for order in [
        (0..bases.len()).collect::<Vec<_>>(),
        (0..bases.len()).rev().collect(),
    ] {
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            active.clone(),
        );
        let mut shared = None;
        for index in order {
            let mut budget = SemanticBudget::default();
            let result = workspace
                .ownership_procedure_handle(
                    &bases[index],
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
            let selected = result.available_value().expect("guarded demand completed");
            assert_eq!(
                budget.performed(),
                expected[index].0,
                "558 work for target{index}"
            );
            assert_eq!(
                selected.handle.artifact().materialization_id(),
                expected[index].1
            );
            assert_eq!(selected.handle.artifact().work(), expected[index].2);
            assert_eq!(
                format!("{:?}", selected.handle.semantics().pointer_origins()),
                expected[index].3
            );
            let backing = selected
                .handle
                .artifact()
                .shared_ownership_base()
                .expect("shared native base");
            if let Some(previous) = &shared {
                assert!(Arc::ptr_eq(previous, backing));
            } else {
                shared = Some(backing.clone());
            }
            assert!(
                backing
                    .procedures()
                    .iter()
                    .all(|procedure| procedure.candidate_macro_alternate().is_none())
            );
            assert_eq!(
                selected
                    .handle
                    .artifact()
                    .procedures()
                    .iter()
                    .filter(|procedure| procedure.candidate_macro_alternate().is_some())
                    .count(),
                1,
                "only demanded target has an alternate"
            );
            assert!(
                crate::analyzer::semantic::service::semantic_artifact_retained_bytes(
                    selected.handle.artifact()
                ) < crate::analyzer::semantic::service::semantic_artifact_retained_bytes(backing),
                "view owns only target storage"
            );
        }
    }
}

#[test]
#[hardwon("#11532: cached ownership bases must not change low-budget answers or charges")]
fn ownership_shared_file_budget_replay_matches_558() {
    let source = SOURCE.to_owned()
        + "\nfn other() { println!(\"other\"); let p=std::alloc::alloc(layout); std::alloc::dealloc(p, layout); }";
    let (_temp, workspace) = fixture(&source);
    let cancellation = CancellationToken::default();
    let active = Some(snapshot(
        brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION,
    ));
    let (base, other) = {
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            active.clone(),
        );
        let base = materialize(&workspace);
        let other = base
            .artifact()
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.locator().declaration().last_segment_name() == Some("other")
            })
            .unwrap()
            .id();
        let other = base.artifact().procedure_handle(other).unwrap();
        (base, other)
    };
    let points = base.artifact().work().program_points;
    for cap in points..=points * 3 {
        let mut limits = SemanticBudget::default().limits();
        limits.program_points = cap;
        let (legacy_complete, legacy_work) = {
            let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                active.clone(),
            );
            let mut budget = SemanticBudget::new(limits).unwrap();
            let result = legacy_acquire(&workspace, &base, &mut budget);
            (
                matches!(result, SemanticOutcome::Complete { value: Some(_), .. }),
                budget.performed(),
            )
        };
        for warm_first in [false, true] {
            let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                active.clone(),
            );
            if warm_first {
                let mut high = SemanticBudget::default();
                assert!(
                    workspace
                        .ownership_procedure_handle(
                            &other,
                            &mut SemanticRequest::new(&mut high, &cancellation)
                        )
                        .unwrap()
                        .available_value()
                        .is_some()
                );
            }
            let mut budget = SemanticBudget::new(limits).unwrap();
            let result = workspace
                .ownership_procedure_handle(
                    &base,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
            assert_eq!(
                result.available_value().is_some(),
                legacy_complete,
                "cap={cap} warm={warm_first}"
            );
            assert_eq!(
                budget.performed(),
                legacy_work,
                "cap={cap} warm={warm_first} work"
            );
            let mut high = SemanticBudget::default();
            assert!(
                workspace
                    .ownership_procedure_handle(
                        &base,
                        &mut SemanticRequest::new(&mut high, &cancellation)
                    )
                    .unwrap()
                    .available_value()
                    .is_some(),
                "retry after cap={cap}"
            );
        }
    }
}

#[test]
#[hardwon(
    "#11532: shared ownership preparation must isolate shadowed targets and nested outer guards"
)]
fn ownership_shared_base_keeps_shadowed_and_nested_procedures_isolated() {
    let source = r#"fn subject() {
        macro_rules! println { ($($args:tt)*) => { struct Introduced; } }
        println!("shadowed");
        let p = std::alloc::alloc(layout);
        std::alloc::dealloc(p, layout);
    }
    fn other() {
        println!("standard");
        let p = std::alloc::alloc(layout);
        std::alloc::dealloc(p, layout);
    }"#;
    let (_temp, workspace) = fixture(source);
    let active = Some(snapshot(
        brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION,
    ));
    let cancellation = CancellationToken::default();
    for shadow_first in [true, false] {
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            active.clone(),
        );
        let base = materialize(&workspace);
        let other = base
            .artifact()
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.locator().declaration().last_segment_name() == Some("other")
            })
            .unwrap()
            .id();
        let other = base.artifact().procedure_handle(other).unwrap();
        for (handle, admitted) in if shadow_first {
            [(&base, false), (&other, true)]
        } else {
            [(&other, true), (&base, false)]
        } {
            let mut budget = SemanticBudget::default();
            let result = workspace
                .ownership_procedure_handle(
                    handle,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
            assert_eq!(result.available_value().is_some(), admitted);
            if let Some(selected) = result.available_value() {
                assert!(!selected.handle.semantics().pointer_origins().is_empty());
            }
        }
    }
    let nested = r#"fn subject() {
        println!("outer");
        fn inner() {
            let p = std::alloc::alloc(layout);
            std::alloc::dealloc(p, layout);
        }
    }"#;
    let (_nested_temp, nested_workspace) = fixture(nested);
    let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        nested_workspace.analyzer(),
        active,
    );
    let base = materialize(&nested_workspace);
    let inner = base
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| procedure.locator().declaration().last_segment_name() == Some("inner"))
        .unwrap()
        .id();
    let mut budget = SemanticBudget::default();
    assert!(
        nested_workspace
            .ownership_procedure_handle(
                &base,
                &mut SemanticRequest::new(&mut budget, &cancellation)
            )
            .unwrap()
            .available_value()
            .is_some()
    );
    let mut budget = SemanticBudget::default();
    let result = nested_workspace
        .ownership_procedure_handle(
            &base.artifact().procedure_handle(inner).unwrap(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
    let inner = result
        .available_value()
        .expect("base inner remains available");
    assert!(!inner.handle.is_candidate_alternate());
    assert!(
        inner.handle.semantics().pointer_origins().is_empty(),
        "outer guard must not close nested lexical selection"
    );
}

#[test]
#[hardwon("#11532: concurrent ownership targets must share one cold base allocation")]
fn ownership_shared_base_is_single_flight_across_targets() {
    let source = SOURCE.to_owned()
        + "\nfn other() { println!(\"other\"); let p=std::alloc::alloc(layout); std::alloc::dealloc(p, layout); }";
    let (_temp, workspace) = fixture(&source);
    let active = snapshot(brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION);
    let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        Some(active.clone()),
    );
    let first = materialize(&workspace);
    let handles = first
        .artifact()
        .procedures()
        .iter()
        .map(|procedure| first.artifact().procedure_handle(procedure.id()).unwrap())
        .collect::<Vec<_>>();
    let carried = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
    let barrier = std::sync::Barrier::new(handles.len());
    let selected = std::thread::scope(|scope| {
        let joins = handles
            .iter()
            .map(|handle| {
                let carried = carried.clone();
                let active = active.clone();
                let workspace = &workspace;
                let barrier = &barrier;
                scope.spawn(move || {
                    carried.run(|| {
                        // Model overrides are deliberately thread-owned; the
                        // carried request domain still shares its file memo.
                        let _models = AnalyzerQueryScope::with_active_semantic_model_snapshot(
                            workspace.analyzer(),
                            Some(active),
                        );
                        barrier.wait();
                        let cancellation = CancellationToken::default();
                        let mut budget = SemanticBudget::default();
                        workspace
                            .ownership_procedure_handle(
                                handle,
                                &mut SemanticRequest::new(&mut budget, &cancellation),
                            )
                            .unwrap()
                            .available_value()
                            .unwrap()
                            .clone()
                    })
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    for target in &selected[1..] {
        assert!(Arc::ptr_eq(
            selected[0]
                .handle
                .artifact()
                .shared_ownership_base()
                .unwrap(),
            target.handle.artifact().shared_ownership_base().unwrap()
        ));
    }
}

#[test]
#[hardwon("#12527: 36 refused macro anchors overflowed policy prose and failed pointer runs")]
fn ownership_lexical_refusal_prose_is_bounded_on_both_acquisition_paths() {
    let mut source = String::from(
        "macro_rules! println { ($($t:tt)*) => { struct Generated; } }\nfn subject() {\n",
    );
    for _ in 0..36 {
        source.push_str("println!(\"hello\");\n");
    }
    source.push_str("}\n");
    for legacy in [false, true] {
        let (_temp, workspace) = fixture(&source);
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            Some(snapshot(
                brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION,
            )),
        );
        let base = materialize(&workspace);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let omissions = AnalyzerQueryScope::capturing_read_incompleteness(workspace.analyzer());
        let (unknown, _reads) = capture_query_reads(workspace.analyzer(), || {
            if legacy {
                matches!(
                    legacy_acquire(&workspace, &base, &mut budget),
                    SemanticOutcome::Unknown { .. }
                )
            } else {
                matches!(
                    workspace
                        .ownership_procedure_handle(
                            &base,
                            &mut SemanticRequest::new(&mut budget, &cancellation)
                        )
                        .unwrap(),
                    SemanticOutcome::Unknown { .. }
                )
            }
        });
        assert!(unknown);
        let reasons = omissions.captured_read_incompleteness();
        let detail = reasons
            .iter()
            .find_map(|reason| match reason.base_cause() {
                crate::analyzer::i_analyzer::QueryReadIncomplete::SemanticEvidenceGap(detail)
                    if detail.starts_with("ownership lexical guard refused") =>
                {
                    Some(detail.as_ref())
                }
                _ => None,
            })
            .expect("production ownership acquisition retains its refusal diagnostic");
        assert!(
            detail.len() <= brokk_bifrost_core::bounded_output::MAX_DIAGNOSTIC_MESSAGE_BYTES,
            "{} bytes: {detail}",
            detail.len()
        );
        assert!(
            detail.contains("decision_kinds="),
            "typed summary: {detail}"
        );
        assert!(
            detail.contains("Refused(Evidence)"),
            "refusal kind: {detail}"
        );
        assert!(detail.contains("total_items=36"), "exact total: {detail}");
        let omitted: usize = detail
            .rsplit_once("omitted_items=")
            .unwrap()
            .1
            .parse()
            .unwrap();
        assert!(omitted > 0 && omitted <= 36);
        assert_eq!(detail.matches("CandidateAnchor {").count() + omitted, 36);
    }
}

#[test]
#[hardwon("#12527: omitted earlier detail records must not hide a later typed refusal kind")]
fn ownership_lexical_refusal_summary_keeps_late_kind() {
    use crate::analyzer::languages::{CandidateMacroDecision, CandidateMacroRefusal};
    let evidence =
        CandidateMacroDecision::Refused(CandidateMacroRefusal::Evidence("x".repeat(10_000)));
    let route = CandidateMacroDecision::Refused(CandidateMacroRefusal::Route("late route".into()));
    let detail = ownership_lexical_guard_refusal_detail(&[
        (
            CandidateAnchor {
                start_byte: 1,
                end_byte: 2,
            },
            &evidence,
        ),
        (
            CandidateAnchor {
                start_byte: 3,
                end_byte: 4,
            },
            &route,
        ),
    ]);
    assert!(detail.len() <= brokk_bifrost_core::bounded_output::MAX_DIAGNOSTIC_MESSAGE_BYTES);
    assert!(detail.contains("Refused(Evidence)"));
    assert!(detail.contains("Refused(Route)"));
    assert!(detail.ends_with("omitted_items=2"));
    assert!(detail.contains("total_items=2"));
}
