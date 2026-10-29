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
            assert!(
                analyzer
                    .current_program_semantics_artifact_source(&file, source.len() - 1)
                    .unwrap()
                    .is_none()
            );
            for limit in [source.len(), source.len() + 1] {
                let snapshot = analyzer
                    .current_program_semantics_artifact_source(&file, limit)
                    .unwrap()
                    .unwrap();
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
