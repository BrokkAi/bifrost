use brokk_bifrost_analysis::analyzer::semantic_model::*;
use brokk_bifrost_analysis::analyzer::workspace::{
    DependencyPackEcosystem, DependencyPackWorkspaceContext, WorkspaceAnalyzer,
};
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
use brokk_bifrost_core::analyzer::project::{
    FilesystemProject, OverlayProject, Project, TestProject,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use std::collections::BTreeSet;
use std::sync::Arc;

fn request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        host_activation:
            brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        approximate_standard_libraries: Vec::new(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn context<'a>(
    catalog: &'a SemanticPackCatalog,
    activation: &'a SemanticModelActivationRequest,
    cancellation: &'a CancellationToken,
) -> DependencyPackWorkspaceContext<'a> {
    DependencyPackWorkspaceContext {
        catalog,
        persistence: None,
        activation,
        limits: DependencyPackLimits::default(),
        cancellation,
    }
}

#[test]
fn installed_activation_deduplicates_evidence_before_enforcing_runtime_budget() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for (path, source) in [
        (".gitignore", "node_modules/\n"),
        (
            "app.ts",
            "import { create } from 'widget'; export const made = create('x');\n",
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/widget":{"version":"2.1.0"}}}"#,
        ),
        (
            "node_modules/widget/package.json",
            r#"{"name":"widget","version":"2.1.0","types":"index.d.ts"}"#,
        ),
        (
            "node_modules/widget/index.d.ts",
            "export declare function create(value: string): string;\n",
        ),
    ] {
        ProjectFile::new(&root, path).write(source).unwrap();
    }
    let config = AnalyzerConfig::default();
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(&root, Language::TypeScript)),
        config.clone(),
    )
    .unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let live = CancellationToken::default();
    let mut activation = request();
    let baseline_activation = activation.clone();
    let full = workspace.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Npm],
        context(&catalog, &baseline_activation, &live),
    );
    assert!(full.complete(), "{full:#?}");
    let evidence = full.ecosystems[0]
        .preparation
        .as_ref()
        .unwrap()
        .evidence
        .clone();
    assert!(!evidence.is_empty());
    activation.evidence = evidence;
    activation.limits.max_evidence_rows = activation.evidence.len();
    let repeated = workspace.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Npm],
        context(&catalog, &activation, &live),
    );
    assert!(repeated.complete(), "{repeated:#?}");
    let installed = workspace.activate_installed_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Npm],
        context(&catalog, &activation, &live),
    );
    assert_eq!(installed.pending.len(), 1, "{installed:#?}");
    assert_eq!(installed.pending[0].ecosystem, DependencyPackEcosystem::Npm);
    assert_eq!(
        installed.pending[0].dependency_id,
        full.ecosystems[0].discovery.dependencies[0].id
    );
    assert!(
        !installed.outcome.complete(),
        "producible dependencies still require acquisition: {installed:#?}"
    );
    assert!(
        workspace
            .analyzer()
            .dependency_discovery_evidence(Language::TypeScript)
            .is_some()
    );
    let SemanticModelRuntimeOutcome::Ready {
        active: full_active,
        ..
    } = full.runtime.unwrap()
    else {
        panic!("full runtime unavailable")
    };
    let Some(SemanticModelRuntimeOutcome::Ready { active, .. }) = installed.outcome.runtime else {
        panic!("installed runtime unavailable")
    };
    assert_eq!(
        active.active_model_set_hash(),
        full_active.active_model_set_hash()
    );
}

#[test]
fn invalidation_withdraws_every_requested_ecosystem() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(&root, "app.py")
        .write("value = 1\n")
        .unwrap();
    ProjectFile::new(&root, "main.go")
        .write("package main\nfunc main() {}\n")
        .unwrap();
    let mut config = AnalyzerConfig::default();
    config.go.dependency_discovery.mode =
        brokk_bifrost_analysis::analyzer::GoDependencyDiscoveryMode::Disabled;
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::with_languages(
            &root,
            BTreeSet::from([Language::Go, Language::Python]),
        )),
        config.clone(),
    )
    .unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let live = CancellationToken::default();
    let activation = request();
    for ecosystems in [
        [DependencyPackEcosystem::Python, DependencyPackEcosystem::Go],
        [DependencyPackEcosystem::Go, DependencyPackEcosystem::Python],
    ] {
        let outcome = workspace.activate_dependency_packs(
            &config,
            &ecosystems,
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &activation,
                limits: DependencyPackLimits::default(),
                cancellation: &live,
            },
        );
        assert!(outcome.complete(), "{outcome:#?}");
        for language in [Language::Python, Language::Go] {
            assert!(
                workspace
                    .analyzer()
                    .dependency_discovery_evidence(language)
                    .is_some()
            );
        }
        assert!(workspace.invalidate_dependency_pack_state(&ecosystems));
        for language in [Language::Python, Language::Go] {
            assert!(
                workspace
                    .analyzer()
                    .dependency_discovery_evidence(language)
                    .is_none(),
                "{language:?}"
            );
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a677e5e333e2: Python activation reported complete when runtime publication was unavailable"
)]
fn python_activation_requires_ready_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(&root, "app.py")
        .write("value = 1\n")
        .unwrap();
    let config = AnalyzerConfig::default();
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(&root, Language::Python)),
        config.clone(),
    )
    .unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let live = CancellationToken::default();
    let mut activation = request();
    activation.controls.push(SemanticModelActivationControl {
        scope: SemanticModelControlScope::Workspace,
        action: SemanticModelControlAction::Enable,
        selector: SemanticModelPackSelector {
            pack_id: "missing.pack".into(),
            version: None,
            manifest_digest: None,
        },
    });
    activation.limits.max_controls = 0;
    let outcome = workspace.activate_python_environment_packs(
        &config,
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &live,
        },
    );
    assert!(outcome.discovery.complete);
    assert!(outcome.preparation.as_ref().unwrap().complete);
    assert!(matches!(
        outcome.runtime,
        Some(SemanticModelRuntimeOutcome::Unavailable(_))
    ));
    assert!(!outcome.complete(), "{outcome:#?}");
}

#[test]
fn source_snapshot_limit_counts_utf8_bytes() {
    use brokk_bifrost_analysis::analyzer::semantic::ContentIdentity;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(&root, "app.ts");
    let source = "export const value = '\u{e9}';\n";
    file.write(source).unwrap();
    let overlay = Arc::new(OverlayProject::new(Arc::new(TestProject::new(
        &root,
        Language::TypeScript,
    ))));
    let mut workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(overlay.snapshot()),
        AnalyzerConfig::default(),
    )
    .unwrap();
    for (index, source) in [source, "export const changed = '\u{1f642}';\n"]
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            assert!(overlay.set(file.abs_path(), source.to_owned()));
            workspace = workspace
                .clone_with_project(Arc::new(overlay.snapshot()))
                .update(&BTreeSet::from([file.clone()]));
        }
        let fresh = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(overlay.snapshot()),
            AnalyzerConfig::default(),
        )
        .unwrap();
        for analyzer in [&workspace, &fresh] {
            assert!(matches!(
                analyzer
                    .current_program_semantics_artifact_source(&file, source.len() - 1)
                    .unwrap(),
                brokk_bifrost_analysis::analyzer::workspace::SemanticArtifactSourceOutcome::Refused(
                    _
                )
            ));
            for limit in [source.len(), source.len() + 1] {
                let snapshot = analyzer
                    .current_program_semantics_artifact_source(&file, limit)
                    .unwrap();
                let brokk_bifrost_analysis::analyzer::workspace::SemanticArtifactSourceOutcome::Held(snapshot) = snapshot else {
                    panic!("expected current source");
                };
                assert_eq!(snapshot.source(), source);
                assert_eq!(
                    snapshot.key().revision().content(),
                    ContentIdentity::hash_bytes(source.as_bytes())
                );
            }
        }
    }
}

#[test]
fn full_refresh_from_empty_discovers_all_new_languages() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.clone()).unwrap());
    let empty =
        WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
    ProjectFile::new(&root, "A.java")
        .write("class AddedJava {}\n")
        .unwrap();
    ProjectFile::new(&root, "lib.rs")
        .write("pub struct AddedRust;\n")
        .unwrap();
    let fresh = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(FilesystemProject::new(root).unwrap()),
        AnalyzerConfig::default(),
    )
    .unwrap();
    let names = |workspace: &WorkspaceAnalyzer| {
        workspace
            .analyzer()
            .all_declarations()
            .map(|unit| unit.fq_name().to_string())
            .collect::<BTreeSet<_>>()
    };
    let expected = names(&fresh);
    assert!(
        expected.iter().any(|name| name.contains("AddedJava")),
        "{expected:?}"
    );
    assert!(
        expected.iter().any(|name| name.contains("AddedRust")),
        "{expected:?}"
    );
    assert_eq!(names(&empty.update_all()), expected);
    assert_eq!(names(&empty.update_all_with_progress(|_| {})), expected);
}

#[test]
fn comment_touching_declaration_remains_a_header_comment() {
    use crate::code_quality::{
        ReportCommentDensityForFilesParams, report_comment_density_for_files,
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(&root, "A.java")
        .write("// attached\n/** boundary */class A {\n// body\n}\n")
        .unwrap();
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(&root, Language::Java)),
        AnalyzerConfig::default(),
    )
    .unwrap();
    let report = report_comment_density_for_files(
        workspace.analyzer(),
        ReportCommentDensityForFilesParams {
            file_paths: vec!["A.java".into()],
            max_top_level_rows: 0,
            max_files: 0,
        },
    );
    assert!(
        report.report.contains("| `A` | 2 | 1 |"),
        "{}",
        report.report
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#13901: refused exact source mislabeled an operational admission stop as missing content"
)]
fn source_byte_refusal_preserves_admission_evidence_in_gap_proofs() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
    use brokk_bifrost_analysis::analyzer::semantic::{
        DispatchOracle, OracleCallContext, SemanticArtifactSourceOutcome, SemanticBudget,
        SemanticBudgetDimension, SemanticOutcome, SemanticRequest, SemanticWork, ValueFlowOracle,
    };

    let app = "mod guard;\nuse guard::Guard;\nimpl Guard { fn helper(&self) {} }\nfn f() { let g = Guard; let _other = Guard; g.helper(); }\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file("app.rs", app)
        .file(
            "guard.rs",
            "pub struct Guard;\nimpl Drop for Guard { fn drop(&mut self) { println!(\"x\"); } }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("app.rs");
    let cancellation = CancellationToken::default();
    let mut setup = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut setup, &cancellation))
        .unwrap()
        .available_value()
        .cloned()
        .unwrap();
    let procedure = artifact
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("f")
        })
        .and_then(|procedure| artifact.procedure_handle(procedure.id()))
        .unwrap();
    let oracle = workspace.semantic_oracle_provider();
    let limits = SemanticWork {
        source_bytes: 1,
        ..SemanticWork::default_limits()
    };

    // With no source pinned in a query cache, the capped reader proves only
    // that the source has at least two bytes. It must not reread it for a count.
    let cold = SemanticBudget::new(limits).unwrap().unit_ledger();
    let cold_source = workspace
        .current_program_semantics_artifact_source(&file, 1)
        .unwrap();
    let SemanticArtifactSourceOutcome::Refused(exceeded) = cold_source else {
        panic!("expected bounded source refusal");
    };
    assert_eq!(exceeded.attempted(), 2);
    assert_eq!(
        SemanticArtifactSourceOutcome::<()>::Refused(exceeded)
            .on_budget(&cold)
            .unwrap()
            .unwrap_err(),
        exceeded,
    );
    assert_eq!(cold.first_refusal().unwrap().exceeded, exceeded);
    assert_eq!(cold.refusal_count(), 1);
    assert!(cold.refusal_origins().resident_only());
    assert!(exceeded.to_string().contains("at least 2"));

    // Exercise the actual cross-file cleanup proof, first cold and then with
    // an exact prepared snapshot pinned. Both must stop operationally.
    let check_query = |budget: &mut SemanticBudget| {
        let outcome = oracle
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(budget, &cancellation),
            )
            .unwrap();
        let SemanticOutcome::ExceededBudget {
            exceeded, partial, ..
        } = outcome
        else {
            panic!("source admission must remain an operational incomplete outcome: {outcome:?}");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::SourceBytes);
        assert_eq!(exceeded.limit(), 1);
        assert_eq!(budget.first_refusal().unwrap().exceeded, exceeded);
        assert!(budget.refusal_origins().resident_only());
        assert!(
            partial
                .as_ref()
                .is_none_or(|snapshot| snapshot.is_execution_dependent())
        );
        exceeded
    };
    let mut cold_query = SemanticBudget::new(limits).unwrap().unit_ledger();
    assert_eq!(check_query(&mut cold_query).attempted(), 2);

    let _scope = AnalyzerQueryScope::new(workspace.analyzer());
    let source = workspace
        .current_program_semantics_artifact_source(&file, usize::MAX)
        .unwrap();
    let SemanticArtifactSourceOutcome::Held(source) = source else {
        panic!("expected source");
    };
    assert_eq!(source.source(), app);
    let mut warm = SemanticBudget::new(limits).unwrap().unit_ledger();
    assert_eq!(check_query(&mut warm).attempted(), app.len());

    let mut held_budget = SemanticBudget::new(limits).unwrap().unit_ledger();
    let held = workspace
        .held_program_semantics_artifact_source(
            &file,
            &mut SemanticRequest::new(&mut held_budget, &cancellation),
        )
        .unwrap();
    let SemanticArtifactSourceOutcome::Refused(held_refusal) = held else {
        panic!("expected held-source refusal");
    };
    assert_eq!(held_refusal.attempted(), app.len());
    assert_eq!(held_budget.first_refusal().unwrap().exceeded, held_refusal);
    assert_eq!(held_budget.refusal_count(), 1);
    assert!(held_budget.refusal_origins().resident_only());

    // Earlier refusals stay in the ledger, but are outside this request's
    // observation mark. The source attempt must still run and carry its own
    // cause through the cleanup proof and the relation projection.
    let check_mixed = |mut budget: SemanticBudget, old| {
        use brokk_bifrost_core::analyzer::reuse_verdict::{ExecutionCause, ReuseVerdict};
        let mark = budget.refusal_mark();
        let (judged, observed) = SemanticRequest::new(&mut budget, &cancellation)
            .observing_refusals_since(mark)
            .judged_with_refusal(|request| {
                oracle.procedure_relations(&procedure, &OracleCallContext::empty(), request)
            });
        assert_eq!(
            judged.reuse,
            ReuseVerdict::ExecutionDependent(ExecutionCause::BudgetRefusal)
        );
        let outcome = judged.value.unwrap();
        let exceeded = outcome
            .budget_exceeded()
            .expect("this source attempt refused");
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::SourceBytes);
        assert_eq!(exceeded.limit(), 1);
        assert_eq!(exceeded.attempted(), app.len());
        assert_eq!(observed.unwrap().exceeded, exceeded);
        assert_eq!(budget.first_refusal().unwrap().exceeded, old);
        assert_eq!(budget.refusal_count(), 2);
        assert!(budget.refusal_origins().resident_only());
    };
    let old_rows = SemanticBudget::new(limits).unwrap().unit_ledger();
    let old = old_rows
        .check_admission(SemanticWork {
            program_points: limits.program_points + 1,
            ..SemanticWork::default()
        })
        .unwrap_err();
    check_mixed(old_rows, old);
    let mut old_source = SemanticBudget::new(limits).unwrap().unit_ledger();
    let backing = Arc::new(vec![0_u8; 3]);
    let old = old_source.hold_source(&backing, backing.len()).unwrap_err();
    check_mixed(old_source, old);

    // Caller cleanup evidence must survive binding projection even when the
    // borrowed receiver has no callee cleanup or runtime work that could
    // produce a later stop. The caller owns the receiver's Drop.
    let mut dispatch_budget = SemanticBudget::default();
    let provider = workspace.icfg_provider();
    let (call, candidate) = procedure
        .semantics()
        .call_sites()
        .iter()
        .find_map(|site| {
            let call = procedure.call_site_handle(site.id).unwrap();
            let outcome = provider
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
                )
                .unwrap();
            outcome.available_value().and_then(|dispatch| {
                dispatch.candidates().iter().find_map(|candidate| {
                    (candidate
                        .target
                        .semantics()
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("helper"))
                    .then(|| (call.clone(), candidate.clone()))
                })
            })
        })
        .expect("resolved helper call");
    let call_row = procedure.semantics().call_site(call.id()).unwrap();
    assert!(procedure.semantics().call_gap_candidates(call_row).iter().any(|gap| {
        gap.base.discharge == brokk_bifrost_analysis::analyzer::semantic::SemanticGapDischarge::InertDropGlue
    }), "caller receiver cleanup must be relevant to this binding projection");
    let callee_proof_gaps = candidate
        .target
        .semantics()
        .logical_gaps()
        .filter(|gap| {
            gap.base.impacts.contains(
                brokk_bifrost_analysis::analyzer::semantic::SemanticGapImpact::CallEvaluation,
            ) || gap.base.impacts.contains(
                brokk_bifrost_analysis::analyzer::semantic::SemanticGapImpact::ReturnTransfer,
            )
        })
        .collect::<Vec<_>>();
    assert!(
        callee_proof_gaps.is_empty(),
        "callee proof gaps: {callee_proof_gaps:#?}"
    );
    let mut bindings_budget = SemanticBudget::new(limits).unwrap().unit_ledger();
    let (bindings, observed) = SemanticRequest::new(&mut bindings_budget, &cancellation)
        .judged_with_refusal(|request| {
            oracle.call_bindings(&call, &candidate, &OracleCallContext::empty(), request)
        });
    assert_eq!(
        bindings.reuse,
        brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
            brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::BudgetRefusal,
        ),
    );
    let bindings = bindings.value.unwrap();
    let exceeded = bindings
        .budget_exceeded()
        .expect("caller source admission stop");
    assert_eq!(exceeded.dimension(), SemanticBudgetDimension::SourceBytes);
    assert_eq!(exceeded.limit(), 1);
    assert_eq!(exceeded.attempted(), app.len());
    let observed = observed.unwrap();
    assert_eq!(observed.exceeded, exceeded);
    eprintln!("caller cleanup admission refusal: {observed:?}");
    assert_eq!(bindings_budget.first_refusal().unwrap().exceeded, exceeded);
    assert_eq!(bindings_budget.refusal_count(), 1);
    assert!(bindings_budget.refusal_origins().resident_only());
    assert!(bindings.completed_replay().is_none());
    let mut retry_budget = SemanticBudget::default();
    let retry = oracle
        .call_bindings(
            &call,
            &candidate,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut retry_budget, &cancellation),
        )
        .unwrap();
    assert!(retry.available_value().is_some(), "{retry:#?}");
    assert!(retry.budget_exceeded().is_none());
    assert_eq!(retry_budget.refusal_count(), 0);

    let mut control = SemanticBudget::default();
    let outcome = oracle
        .procedure_relations(
            &procedure,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut control, &cancellation),
        )
        .unwrap();
    assert!(control.first_refusal().is_none());
    // The real Drop body retains content gaps; an unrestricted query must not
    // acquire an operational stop merely because the bounded query ran first.
    assert!(!outcome.available_value().unwrap().is_execution_dependent());
}
