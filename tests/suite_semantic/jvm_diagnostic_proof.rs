//! The JVM half of issue #1619: Java, Kotlin and Scala answer one proof-gated
//! ladder, and every client of that ladder agrees with every other.
//!
//! This module owns the fixture the three per-language files share -- an
//! activated `com.acme:widget` dependency model -- because publishing one is
//! what separates a suppressed unknown from a proved absence, and all three
//! languages need it to reach either.

use std::sync::Arc;

use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::analyzer::structural::BoundaryStatus;
use brokk_bifrost::analyzer::{
    JvmDependencyDiscoveryMode, SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
    SemanticDiagnosticReport, SemanticDiagnosticReportStatus, WorkspaceAnalyzer,
};
use brokk_bifrost::{
    AnalyzerConfig, CancellationToken, JvmExternalDependencies, JvmMavenCoordinate, Language,
};
use semver::Version;

use crate::common::{BuiltInlineTestProject, InlineTestProject};

const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");

/// The single external type the activated model declares, and the only spelling
/// at which any language may find it.
pub const MODELLED_TYPE: &str = "com.acme.Widget";

/// An analyzer configuration that reaches no build tool and no JDK on the host.
///
/// A diagnostic must never trigger dependency discovery, so a test that let
/// discovery run would be measuring the host rather than the ladder.
pub fn offline_config() -> AnalyzerConfig {
    let mut config = AnalyzerConfig::default();
    config.jvm.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
    config.jvm.standard_library_discovery.discover_java_home = false;
    config
}

/// Publish the `com.acme:widget` dependency model onto `analyzer`.
///
/// This is the host-side activation #1617 introduced: explicit work, outside
/// any diagnostic request. Until it runs, no JVM name can be proved absent.
pub fn activate_widget_model(analyzer: &WorkspaceAnalyzer) {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let compiled = compile_source(
        SourceFormat::Json,
        DECLARATIONS_JSON,
        &CompilerOptions::default(),
    )
    .unwrap();
    catalog
        .register_session_pack(
            &compiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "jvm-proof-fixture".to_owned(),
            },
        )
        .unwrap();
    let request = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:widget".to_owned(),
                version: Some(Version::parse("1.5.0").unwrap()),
            }),
            module: None,
            // The pack declares `jdk >= 17.0.0` compatibility, and its one
            // shard activates only for the `jvm` target in the `release`
            // configuration. Evidence that omits any of the three satisfies no
            // shard and publishes an empty overlay -- which would make this
            // fixture silently prove nothing.
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse("17.0.1").unwrap()),
            }),
            target: Some("jvm".to_owned()),
            configuration: Some("release".to_owned()),
            artifact_sha256: None,
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("the widget dependency model must activate");
    };
    assert!(
        analyzer.analyzer().semantic_model_overlay().is_some(),
        "activation must publish an overlay"
    );
}

/// A workspace over `files`, with the widget model published when `activate`.
pub fn jvm_workspace(
    files: &[(&str, &str)],
    activate: bool,
) -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
    let mut project = InlineTestProject::new();
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();
    let analyzer = built.workspace_analyzer(offline_config());
    if activate {
        activate_widget_model(&analyzer);
    }
    (built, analyzer)
}

/// The report `analyzer` produces for `path`, read from the file on disk.
pub fn report_for(
    analyzer: &WorkspaceAnalyzer,
    built: &BuiltInlineTestProject,
    path: &str,
) -> SemanticDiagnosticReport {
    let file = built.file(path);
    let source = analyzer.analyzer().project().read_source(&file).unwrap();
    analyzer.analyzer().semantic_diagnostics(&file, &source)
}

/// Whether `report` holds an outcome resolved at `boundary`.
pub fn resolved_at(report: &SemanticDiagnosticReport, boundary: BoundaryStatus) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(outcome, SemanticDiagnosticOutcome::Resolved { boundary: found, .. }
            if *found == boundary)
    })
}

/// Whether `report` suppressed something because a dependency boundary could
/// not answer.
pub fn suppressed_for_missing_dependency(report: &SemanticDiagnosticReport) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(outcome, SemanticDiagnosticOutcome::Incomplete { reasons, .. }
        if reasons.iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
        )))
    })
}

/// Whether `report` proved a name absent, at any boundary.
pub fn proved_absent(report: &SemanticDiagnosticReport) -> bool {
    report
        .outcomes()
        .iter()
        .any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Absent(_)))
}

fn definition_exists(analyzer: &WorkspaceAnalyzer, name: &str) -> bool {
    !analyzer.analyzer().get_definitions(name).is_empty()
}

// ---------------------------------------------------------------------------
// Acceptance criteria: the three languages, one ladder
// ---------------------------------------------------------------------------

/// A name every retained surface missed, with a model published, is the one
/// state that earns an error -- in all three languages.
#[test]
fn a_published_model_lets_each_jvm_language_prove_a_local_name_absent() {
    let files = [
        (
            "src/app/Consumer.java",
            "package app; class Consumer { MissingType value; }",
        ),
        (
            "src/app/Consumer.kt",
            "package app\n\nclass Consumer(value: MissingType)\n",
        ),
        (
            "src/app/Consumer.scala",
            "package app\nclass Consumer(value: MissingType)\n",
        ),
    ];
    for (path, source) in files {
        let (built, analyzer) = jvm_workspace(&[(path, source)], true);
        let report = report_for(&analyzer, &built, path);
        assert!(
            proved_absent(&report),
            "{path} must prove `MissingType` absent once a model is published: {:#?}",
            report.outcomes()
        );
        assert_eq!(
            1,
            report.diagnostics().len(),
            "{path} must report exactly one unrecognized symbol: {:#?}",
            report.diagnostics()
        );
        assert!(report.diagnostics()[0].message.contains("MissingType"));
    }
}

/// Without that model the same name is suppressed, with the boundary named.
/// This is the false positive #1615 exists to prevent: an unconfigured
/// classpath is not evidence that a name is missing.
#[test]
fn an_unproved_name_is_suppressed_with_a_named_boundary_in_each_jvm_language() {
    let files = [
        (
            "src/app/Consumer.java",
            "package app; class Consumer { MissingType value; }",
        ),
        (
            "src/app/Consumer.kt",
            "package app\n\nclass Consumer(value: MissingType)\n",
        ),
        (
            "src/app/Consumer.scala",
            "package app\nclass Consumer(value: MissingType)\n",
        ),
    ];
    for (path, source) in files {
        let (built, analyzer) = jvm_workspace(&[(path, source)], false);
        let report = report_for(&analyzer, &built, path);
        assert!(
            report.diagnostics().is_empty(),
            "{path} must not report a name it cannot prove absent: {:#?}",
            report.diagnostics()
        );
        assert!(
            suppressed_for_missing_dependency(&report),
            "{path} must name the boundary it could not see past: {:#?}",
            report.outcomes()
        );
        assert_eq!(
            SemanticDiagnosticReportStatus::Incomplete,
            report.status(),
            "{path} suppressed a candidate, so the request is incomplete"
        );
    }
}

/// A type the activated model declares is resolved at the external boundary,
/// never reported -- even though no workspace file declares it and the
/// jar-backed index was never built.
#[test]
fn an_externally_modelled_type_resolves_in_each_jvm_language() {
    let files = [
        (
            "src/app/Consumer.java",
            "package app; import com.acme.Widget; class Consumer { Widget value; }",
        ),
        (
            "src/app/Consumer.kt",
            "package app\n\nimport com.acme.Widget\n\nclass Consumer(value: Widget)\n",
        ),
        (
            "src/app/Consumer.scala",
            "package app\nimport com.acme.Widget\nclass Consumer(value: Widget)\n",
        ),
    ];
    for (path, source) in files {
        let (built, analyzer) = jvm_workspace(&[(path, source)], true);
        let report = report_for(&analyzer, &built, path);
        assert!(
            report.diagnostics().is_empty(),
            "{path} must not report an externally modelled type: {:#?}",
            report.diagnostics()
        );
        assert!(
            resolved_at(&report, BoundaryStatus::ExternalIndexed),
            "{path} must resolve `Widget` at the external boundary: {:#?}",
            report.outcomes()
        );
    }
}

/// The model is consulted at the spelling the language's own import tiers
/// produce. A file that does not import `com.acme.Widget` must not be silenced
/// by it just because the simple name matches.
/// A build that declares an artifact the index could not read is a *different*
/// suppression from an unconfigured classpath, and it must say so: the name may
/// well be in the part that was never read, and no model can rule that out,
/// because the unread artifacts are exactly the ones no activation evidence
/// covers.
#[test]
fn a_declared_but_unreadable_artifact_suppresses_as_declared_unindexed() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Consumer.java",
            "package app; class Consumer { MissingType value; }",
        )
        .build();
    let mut config = offline_config();
    // Metadata discovery must run for the unresolved coordinate to be recorded.
    config.jvm.dependency_discovery.mode = JvmDependencyDiscoveryMode::Metadata;
    config.jvm.external_dependencies = JvmExternalDependencies {
        coordinates: vec![JvmMavenCoordinate::new(
            "com.example",
            "never-installed",
            "1.0.0",
        )],
        ..JvmExternalDependencies::default()
    };
    let analyzer = project.workspace_analyzer(config);
    activate_widget_model(&analyzer);
    // The host builds the index; it finds no local artifact for the declared
    // coordinate and records that as a production diagnostic.
    analyzer.warm_query_indexes();

    let file = project.file("app/Consumer.java");
    let source = analyzer.analyzer().project().read_source(&file).unwrap();
    let report = analyzer.analyzer().semantic_diagnostics(&file, &source);

    assert!(
        report.diagnostics().is_empty(),
        "a partially-read classpath cannot prove anything absent: {:#?}",
        report.diagnostics()
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                        boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                    }
                ))
        )),
        "the boundary must distinguish a declared-but-unread artifact from an \
         unconfigured classpath: {:#?}",
        report.outcomes()
    );
}

/// Two wildcard imports supplying one simple name. Java rejects the reference,
/// so it is ambiguous rather than unrecognized, and both competing routes are
/// workspace declarations.
#[test]
fn a_same_name_wildcard_import_collision_stays_ambiguous_in_java() {
    let files = [
        (
            "src/left/Base.java",
            "package left;\npublic class Base {}\n",
        ),
        (
            "src/right/Base.java",
            "package right;\npublic class Base {}\n",
        ),
        (
            "src/app/Consumer.java",
            "package app;\nimport left.*;\nimport right.*;\nclass Consumer { Base value; }\n",
        ),
    ];
    let (built, analyzer) = jvm_workspace(&files, true);
    let report = report_for(&analyzer, &built, "src/app/Consumer.java");

    assert!(
        report.diagnostics().is_empty(),
        "an ambiguous reference is not an unrecognized one: {:#?}",
        report.diagnostics()
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Ambiguous { boundaries, .. }
                if boundaries.len() == 2
                    && boundaries
                        .iter()
                        .all(|boundary| *boundary == BoundaryStatus::WorkspaceLocal)
        )),
        "both competing routes are workspace declarations: {:#?}",
        report.outcomes()
    );
}

#[test]
fn the_active_model_is_consulted_through_import_tiers_not_by_simple_name() {
    let files = [
        (
            "src/app/Consumer.java",
            "package app; class Consumer { Widget value; }",
        ),
        (
            "src/app/Consumer.kt",
            "package app\n\nclass Consumer(value: Widget)\n",
        ),
        (
            "src/app/Consumer.scala",
            "package app\nclass Consumer(value: Widget)\n",
        ),
    ];
    for (path, source) in files {
        let (built, analyzer) = jvm_workspace(&[(path, source)], true);
        let report = report_for(&analyzer, &built, path);
        assert!(
            proved_absent(&report),
            "{path} spells `Widget` with no import that reaches `com.acme`, so the \
             modelled type is not this reference: {:#?}",
            report.outcomes()
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-client precedence agreement
// ---------------------------------------------------------------------------

/// A Java file naming a Kotlin sibling's type: `get_definition` finds it and
/// diagnostics record it resolved. Neither client may see what the other
/// cannot.
#[test]
fn definition_and_diagnostics_agree_on_a_cross_language_workspace_type() {
    let files = [
        ("src/app/Api.kt", "package app\n\nclass Api\n"),
        (
            "src/app/Consumer.java",
            "package app; class Consumer { Api value; }",
        ),
    ];
    let (built, analyzer) = jvm_workspace(&files, true);
    assert!(
        definition_exists(&analyzer, "app.Api"),
        "the Kotlin sibling must be reachable by definition lookup"
    );

    let report = report_for(&analyzer, &built, "src/app/Consumer.java");
    assert!(
        report.diagnostics().is_empty(),
        "a resolvable cross-language type must never be reported: {:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "the Kotlin sibling is a workspace declaration: {:#?}",
        report.outcomes()
    );
    assert!(
        !proved_absent(&report),
        "nothing in this file is absent: {:#?}",
        report.outcomes()
    );
}

/// The same agreement in the other direction: a Kotlin file naming a Java
/// sibling's type.
#[test]
fn definition_and_diagnostics_agree_on_a_kotlin_reference_to_a_java_sibling() {
    let files = [
        (
            "src/app/Api.java",
            "package app;\n\npublic interface Api {}\n",
        ),
        (
            "src/app/Consumer.kt",
            "package app\n\nclass Consumer(value: Api)\n",
        ),
    ];
    let (built, analyzer) = jvm_workspace(&files, true);
    assert!(
        definition_exists(&analyzer, "app.Api"),
        "the Java sibling must be reachable by definition lookup"
    );

    let report = report_for(&analyzer, &built, "src/app/Consumer.kt");
    assert!(
        report.diagnostics().is_empty(),
        "a resolvable cross-language type must never be reported: {:#?}",
        report.diagnostics()
    );
    assert!(resolved_at(&report, BoundaryStatus::WorkspaceLocal));
}

/// The read-only rule, end to end: a diagnostic request must leave the
/// jar-backed external index unbuilt, however many names it fails to resolve.
///
/// The unit test in `analyzer/scala/mod.rs` pins the same rule at the ladder;
/// this pins it at the request boundary, where a regression would actually
/// cost a user a stalled editor.
#[test]
fn a_diagnostic_request_never_builds_the_jvm_external_index() {
    let files = [
        (
            "src/app/Consumer.java",
            "package app; class Consumer { A a; B b; }",
        ),
        (
            "src/app/Consumer.kt",
            "package app\n\nclass Consumer(a: A, b: B)\n",
        ),
        (
            "src/app/Consumer.scala",
            "package app\nclass Consumer(a: A, b: B)\n",
        ),
    ];
    for (path, source) in files {
        let (built, analyzer) = jvm_workspace(&[(path, source)], true);
        assert!(
            !analyzer.query_indexes_warm(),
            "{path}: nothing may be warm before the request"
        );
        report_for(&analyzer, &built, path);
        assert!(
            !analyzer.query_indexes_warm(),
            "{path}: a diagnostic request must not build the classpath index"
        );
    }
}

/// The index a diagnostic refuses to build is built by the host's warm hook,
/// and the ladder then reads it.
#[test]
fn warming_query_indexes_is_what_builds_the_jvm_external_index() {
    let (_built, analyzer) = jvm_workspace(
        &[("src/app/Consumer.java", "package app; class Consumer {}")],
        false,
    );
    assert!(!analyzer.query_indexes_warm());
    analyzer.warm_query_indexes();
    assert!(
        analyzer.query_indexes_warm(),
        "the warm hook owns the jar reads a diagnostic may not perform"
    );
}

/// One published model, one generation: every JVM language in a mixed workspace
/// reads the same overlay, so the same external type cannot be resolved for one
/// language and reported for another.
#[test]
fn every_jvm_language_reads_the_same_published_model_in_one_workspace() {
    let files = [
        (
            "src/app/FromJava.java",
            "package app; import com.acme.Widget; class FromJava { Widget value; }",
        ),
        (
            "src/app/FromKotlin.kt",
            "package app\n\nimport com.acme.Widget\n\nclass FromKotlin(value: Widget)\n",
        ),
        (
            "src/app/FromScala.scala",
            "package app\nimport com.acme.Widget\nclass FromScala(value: Widget)\n",
        ),
    ];
    let (built, analyzer) = jvm_workspace(&files, true);
    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    assert_eq!(
        SemanticModelOverlayDisposition::Unique,
        overlay.symbols_named(MODELLED_TYPE).disposition,
        "the fixture must declare exactly one `{MODELLED_TYPE}`"
    );

    for (path, _) in files {
        let report = report_for(&analyzer, &built, path);
        assert!(
            report.diagnostics().is_empty(),
            "{path} must not report the shared modelled type: {:#?}",
            report.diagnostics()
        );
        assert!(
            resolved_at(&report, BoundaryStatus::ExternalIndexed),
            "{path} must resolve it at the external boundary: {:#?}",
            report.outcomes()
        );
    }
}

/// An external declaration stays external. Resolving one must never mint a
/// workspace `CodeUnit`, because every downstream client -- navigation,
/// summaries, usage -- would then be pointed at a file that does not exist.
#[test]
fn resolving_an_external_type_creates_no_workspace_code_unit() {
    let files = [(
        "src/app/Consumer.java",
        "package app; import com.acme.Widget; class Consumer { Widget value; }",
    )];
    let (built, analyzer) = jvm_workspace(&files, true);
    let report = report_for(&analyzer, &built, "src/app/Consumer.java");
    assert!(resolved_at(&report, BoundaryStatus::ExternalIndexed));

    let workspace_files: Vec<Arc<str>> = analyzer
        .analyzer()
        .get_all_declarations()
        .iter()
        .map(|unit| Arc::from(unit.fq_name()))
        .collect();
    assert!(
        !workspace_files.iter().any(|fqn| &**fqn == MODELLED_TYPE),
        "`{MODELLED_TYPE}` is a dependency declaration and must not appear \
         among workspace declarations: {workspace_files:#?}"
    );
    let _ = built;
}
