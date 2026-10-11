use super::*;
use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::native_points::native_point_operation_inputs;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::usages::get_definition::{DefinitionLookupStatus, ResolvedReferenceSite};
use crate::analyzer::{AnalyzerConfig, CodeUnitIndex, Project, Range};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use std::sync::Arc;

const CALLER: &str = "package use; import dep.Target; class Use { Target field; }";
const CALLER_PATH: &str = "src/main/java/use/Use.java";
const PROVIDER_PATH: &str = "src/main/java/dep/Target.java";

fn fixture() -> (BuiltInlineTestProject, JavaAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>native-point</artifactId><version>1</version></project>")
        .file(CALLER_PATH, CALLER)
        .file(PROVIDER_PATH, "package dep; public class Target {}")
        .file("src/main/java/decoy/Target.java", "package decoy; public class Target {}")
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    (fixture, analyzer)
}

fn site(source: &str) -> ResolvedReferenceSite {
    let start_byte = source.rfind("Target").unwrap();
    ResolvedReferenceSite {
        path: CALLER_PATH.into(),
        text: "Target".into(),
        range: Range {
            start_byte,
            end_byte: start_byte + 6,
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: start_byte,
        focus_end_byte: start_byte + 6,
    }
}

fn complete(result: BoundedResolution<DefinitionLookupOutcome>) -> DefinitionLookupOutcome {
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    value
}

fn complete_with_evidence(
    result: BoundedResolution<JavaNativeDefinitionResolution>,
) -> JavaNativeDefinitionResolution {
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    value
}

fn native_evidence_at(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    file: &crate::analyzer::ProjectFile,
    source: &str,
    focus_start_byte: usize,
    focus_length: usize,
) -> JavaNativeDefinitionResolution {
    let tree = super::super::parse_tree(source).expect("Java source parses");
    let site = ResolvedReferenceSite {
        path: file.to_string(),
        text: source[focus_start_byte..focus_start_byte + focus_length].to_owned(),
        range: Range {
            start_byte: focus_start_byte,
            end_byte: focus_start_byte + focus_length,
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte,
        focus_end_byte: focus_start_byte + focus_length,
    };
    complete_with_evidence(resolve_java_definition_with_evidence_bounded(
        BoundedReceiverQuery {
            analyzer,
            file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ))
}

#[test]
fn java_native_call_adapter_retains_source_authority() {
    let source = "class App { void accept(String value) {} void caller() { accept(\"x\"); } }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("App.java", source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file("App.java");
    let focus = source.rfind("accept").expect("call name");
    let resolved = native_evidence_at(&analyzer, &file, source, focus, "accept".len());
    assert_eq!(
        resolved.evidence.authority,
        crate::analyzer::usages::get_definition::DefinitionResolutionAuthority::NativeJavaSelected
    );
    assert_eq!(
        resolved.evidence.call_application(),
        crate::analyzer::usages::get_definition::CallApplicationKind::BoundReceiver
    );
    assert!(
        resolved.evidence.exact_external_call().is_none(),
        "a source call has no external proof: {resolved:?}"
    );
    assert!(
        resolved.evidence.external_callee_identity().is_none(),
        "a source call has no external identity: {resolved:?}"
    );
}

#[test]
fn java_native_point_resolves_qualified_static_call_across_same_package_files() {
    let library_path = "src/main/java/conformance/JavaLibrary.java";
    let caller_path = "src/main/java/conformance/JavaCaller.java";
    let library_source =
        "package conformance; final class JavaLibrary { static int javaLeaf() { return 7; } }";
    let caller_source = "package conformance; final class JavaCaller { static int javaRoot() { return JavaLibrary.javaLeaf(); } }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>native-call</artifactId><version>1</version></project>")
        .file(library_path, library_source)
        .file(caller_path, caller_source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(caller_path);
    let owner_focus = caller_source.find("JavaLibrary").expect("type qualifier");
    let owner = native_evidence_at(
        &analyzer,
        &file,
        caller_source,
        owner_focus,
        "JavaLibrary".len(),
    );
    assert_eq!(owner.outcome.definitions.len(), 1, "{owner:?}");
    assert_eq!(
        owner.outcome.definitions[0].short_name(),
        "JavaLibrary",
        "{owner:?}"
    );
    let focus = caller_source.rfind("javaLeaf").expect("call name");
    let resolved = native_evidence_at(&analyzer, &file, caller_source, focus, "javaLeaf".len());

    assert_eq!(
        resolved.outcome.status,
        DefinitionLookupStatus::Resolved,
        "{resolved:?}"
    );
    assert_eq!(resolved.outcome.definitions.len(), 1, "{resolved:?}");
    assert_eq!(
        resolved.evidence.call_application(),
        crate::analyzer::usages::get_definition::CallApplicationKind::PackageFunction
    );
    assert_eq!(
        resolved.evidence.dispatch_extensibility(),
        Some(crate::analyzer::DispatchExtensibility::Closed)
    );
}

#[test]
fn java_native_point_resolves_inherited_nested_type_in_class_body() {
    let source = r#"package app;

class Holder { static class Carried {} }
class Middle extends Holder {}
class Leaf extends Middle {
    static class Uses extends Carried {}
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file("app/NestedScope.java", source)
        .build();
    let analyzer = JavaAnalyzer::new(project.project_dyn());
    let file = project.file("app/NestedScope.java");
    let focus = source.rfind("Carried").expect("inherited nested type");
    let resolved = native_evidence_at(&analyzer, &file, source, focus, "Carried".len());

    assert_eq!(
        resolved.outcome.status,
        DefinitionLookupStatus::Resolved,
        "{resolved:?}"
    );
    assert_eq!(resolved.outcome.definitions.len(), 1, "{resolved:?}");
    assert_eq!(
        resolved.outcome.definitions[0].short_name(),
        "Holder.Carried",
        "{resolved:?}"
    );
}

#[test]
fn java_native_overload_selection_uses_strict_primitive_widening() {
    let source = "class App { void choose(long value) {} void choose(float value) {} void caller() { choose(1); } }";
    let project = InlineTestProject::with_language(Language::Java)
        .file("App.java", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let file = project.file("App.java");
    let focus = source.rfind("choose").expect("call name");
    let resolved = native_evidence_at(analyzer, &file, source, focus, "choose".len());

    assert_eq!(
        resolved.outcome.status,
        DefinitionLookupStatus::Resolved,
        "{resolved:?}"
    );
    let [definition] = resolved.outcome.definitions.as_slice() else {
        panic!("one most-specific overload: {resolved:?}");
    };
    let ranges = analyzer.ranges_of(definition);
    let [range] = ranges.as_slice() else {
        panic!("one declaration range: {definition:?}");
    };
    assert_eq!(
        range.start_byte,
        source.find("void choose(long").expect("long overload")
    );
}

#[test]
fn java_native_call_adapter_proves_external_receiver_and_static_import_shapes() {
    use crate::analyzer::jvm::external::{TestClassFile, TestClassMethod, write_test_class_jar};
    use crate::{AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies};

    let source = "import static java.net.URLDecoder.decode; class App { void run(String raw) { java.net.URLDecoder.decode(raw); java.net.URLDecoder.decode(1); decode(raw); } }";
    let jar_dir = tempfile::tempdir().expect("jar directory");
    let jar_path = jar_dir.path().join("native-call-evidence.jar");
    write_test_class_jar(
        &jar_path,
        &[
            TestClassFile {
                internal_name: "java/lang/String",
                super_internal_name: "java/lang/Object",
                methods: &[],
                private_nested: false,
            },
            TestClassFile {
                internal_name: "java/net/URLDecoder",
                super_internal_name: "java/lang/Object",
                methods: &[TestClassMethod {
                    name: "decode",
                    descriptor: "(Ljava/lang/String;)Ljava/lang/String;",
                    is_static: true,
                }],
                private_nested: false,
            },
        ],
    );
    let project = InlineTestProject::with_language(Language::Java)
        .file("App.java", source)
        .build();
    let config = AnalyzerConfig {
        jvm: JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar_path,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            ..JvmAnalyzerConfig::default()
        },
        ..AnalyzerConfig::default()
    };
    let workspace = project.workspace_analyzer(config);
    let analyzer = workspace.analyzer();
    let file = project.file("App.java");

    let qualified_start = source.find("decode(raw)").expect("qualified call");
    let qualified = native_evidence_at(analyzer, &file, source, qualified_start, "decode".len());
    let qualified_proof = qualified
        .evidence
        .exact_external_call()
        .expect("the selected external static method has one applicable signature");
    assert_eq!(
        qualified_proof.canonical_callee(),
        "java.net.URLDecoder.decode"
    );
    assert_eq!(qualified_proof.parameter_count(), 1);
    assert_eq!(
        qualified.evidence.call_application(),
        crate::analyzer::usages::get_definition::CallApplicationKind::PackageFunction
    );
    assert_eq!(qualified.evidence.dispatch_extensibility(), None);
    assert_eq!(
        qualified.outcome.resolved_reference_target(),
        Some("java.net.URLDecoder.decode")
    );

    let mismatched_start = source.find("decode(1)").expect("mismatched argument");
    let mismatched = native_evidence_at(analyzer, &file, source, mismatched_start, "decode".len());
    assert!(
        mismatched.evidence.exact_external_call().is_none(),
        "a unique arity match is not applicable to an int actual and String formal: {mismatched:?}"
    );

    let imported_start = source.rfind("decode(raw)").expect("static import call");
    let imported = native_evidence_at(analyzer, &file, source, imported_start, "decode".len());
    let imported_proof = imported
        .evidence
        .exact_external_call()
        .expect("selected static import has one exact external declaration");
    assert_eq!(
        imported_proof.canonical_callee(),
        "java.net.URLDecoder.decode"
    );
    assert_eq!(imported_proof.parameter_count(), 1);
    assert_eq!(
        imported
            .evidence
            .external_callee_identity()
            .map(|identity| { (identity.owner_fqn(), identity.member()) }),
        Some(("java.net.URLDecoder", "decode"))
    );
}

#[test]
fn java_native_operation_mounts_every_selected_jvm_snapshot() {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("src/main/java/use/Use.java", "package use; class Use {}")
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let store = analyzer.inner.analyzer_store();
    let workspace_id = analyzer.inner.workspace_id();
    for storage_language in ["kotlin", "scala"] {
        let generation = store
            .ensure_language_epoch_value(storage_language, "native-jvm-mount-test")
            .unwrap();
        store
            .sync_workspace_inputs_for_workspace(
                workspace_id,
                storage_language,
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
    }

    let (snapshots, languages) = native_point_operation_inputs(&analyzer.inner).unwrap();
    assert_eq!(snapshots.len(), 3);
    assert_eq!(
        languages
            .iter()
            .map(SelectedResolutionLanguage::storage_language)
            .collect::<Vec<_>>(),
        ["java", "kotlin", "scala"]
    );
}

#[test]
fn java_native_point_resolves_import_target_from_unique_workspace_rows() {
    let (fixture, analyzer) = fixture();
    let file = fixture.file(CALLER_PATH);
    let site = site(CALLER);
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: CALLER,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].source(),
        &fixture.file(PROVIDER_PATH)
    );
    assert_eq!(outcome.reference.as_ref().unwrap().text, "Target");
    assert!(
        !outcome
            .diagnostics
            .iter()
            .any(|reason| reason.kind == "incomplete_binding"),
        "{outcome:?}"
    );
}

#[test]
fn java_native_point_resolves_declared_method_when_runtime_hierarchy_is_open() {
    let source = "package p; class Worker { public void send(long value) {} } class Use { void run(Worker worker) { worker.send(1); } }";
    let path = "src/p/Use.java";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(path, source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(path);
    let start = source.find("send(1)").expect("call name");
    let site = ResolvedReferenceSite {
        path: path.into(),
        text: "send".into(),
        range: Range {
            start_byte: start,
            end_byte: start + "send".len(),
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: start,
        focus_end_byte: start + "send".len(),
    };
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].fq_name(), "p.Worker.send");
}

#[test]
fn java_native_point_resolves_explicit_and_implicit_this_to_one_method() {
    let source = "class Sample { int value() { return 1; } int f(boolean c) { if (c) return this.value(); else return value(); } }";
    let path = "src/Sample.java";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(path, source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(path);
    let resolve_at = |start_byte| {
        let site = ResolvedReferenceSite {
            path: path.into(),
            text: "value".into(),
            range: Range {
                start_byte,
                end_byte: start_byte + "value".len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + "value".len(),
        };
        complete(resolve_java_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ))
    };
    let explicit = resolve_at(source.find("this.value()").unwrap() + "this.".len());
    let implicit = resolve_at(source.rfind("value()").unwrap());
    assert_eq!(
        explicit.status,
        DefinitionLookupStatus::Resolved,
        "{explicit:?}"
    );
    assert_eq!(
        implicit.status,
        DefinitionLookupStatus::Resolved,
        "{implicit:?}"
    );
    assert_eq!(explicit.definitions, implicit.definitions);
    assert_eq!(explicit.definitions.len(), 1);
}

#[test]
fn java_native_point_excludes_comments_from_call_arguments() {
    let source = "class Sample { static String newBuilder(String scheme, int length, String path) { return scheme; } static String withComment(String scheme, int port, String path) { return newBuilder(scheme, (port >= 0 ? 6 : 0), /* not an argument */ path); } }";
    let path = "src/Sample.java";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(path, source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(path);
    let start_byte = source.rfind("newBuilder").unwrap();
    let site = ResolvedReferenceSite {
        path: path.into(),
        text: "newBuilder".into(),
        range: Range {
            start_byte,
            end_byte: start_byte + "newBuilder".len(),
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: start_byte,
        focus_end_byte: start_byte + "newBuilder".len(),
    };
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].fq_name(), "Sample.newBuilder");
}

#[test]
fn java_native_point_infers_var_receiver_from_factory_result() {
    let source = "package p; public final class Store { public static native Store open(); public native void put(); } class Use { void run() { var store = Store.open(); store.put(); } }";
    let path = "src/p/Store.java";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(path, source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(path);
    let start = source.find("store.put").expect("instance call") + "store.".len();
    let site = ResolvedReferenceSite {
        path: path.into(),
        text: "put".into(),
        range: Range {
            start_byte: start,
            end_byte: start + "put".len(),
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: start,
        focus_end_byte: start + "put".len(),
    };
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].fq_name(), "p.Store.put");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|reason| reason.kind == "incomplete_binding"),
        "{outcome:?}"
    );
}

#[test]
fn java_native_point_rejects_source_mismatch() {
    let (fixture, analyzer) = fixture();
    let file = fixture.file(CALLER_PATH);
    let site = site(CALLER);
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: "class Changed { Target field; }",
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(outcome.status, DefinitionLookupStatus::Unavailable);
    assert!(outcome.definitions.is_empty());
    assert_eq!(outcome.diagnostics[0].kind, "native_source_mismatch");
}

#[test]
fn java_native_point_obeys_cancellation_and_budget() {
    let (fixture, analyzer) = fixture();
    let file = fixture.file(CALLER_PATH);
    let site = site(CALLER);
    let cancellation = CancellationToken::new();
    let result = resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: CALLER,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: Some(&cancellation),
        },
        || cancellation.cancel(),
    );
    assert!(
        matches!(result, BoundedResolution::Cancelled { .. }),
        "{result:?}"
    );
    let result = resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: CALLER,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::tiny(),
            cancellation: None,
        },
        || {},
    );
    assert!(
        matches!(result, BoundedResolution::Exceeded { .. }),
        "{result:?}"
    );
}

#[test]
fn java_native_point_provider_overlay_withdraws_old_package_target() {
    let (fixture, disk) = fixture();
    let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
    let provider = fixture.file(PROVIDER_PATH);
    assert!(overlay.set(
        provider.abs_path(),
        "package moved; public class Target {}".into()
    ));
    let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
    assert!(!analyzer.declarations(&provider).is_empty());
    let file = fixture.file(CALLER_PATH);
    let site = site(CALLER);
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: CALLER,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    assert_eq!(
        std::fs::read_to_string(provider.abs_path()).unwrap(),
        "package dep; public class Target {}"
    );
}

#[test]
fn java_native_point_projects_local_and_parameter_ranges_from_selected_rows() {
    use crate::analyzer::DeclarationKind;
    for (source, kind) in [
        (
            "class Use { int f(int target) { return target; } }",
            DeclarationKind::Parameter,
        ),
        (
            "class Use { int[] f(int... target) { return target; } }",
            DeclarationKind::Parameter,
        ),
        (
            "class Use { int f() { int target=1; return target; } }",
            DeclarationKind::LocalVariable,
        ),
    ] {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file(CALLER_PATH, source)
            .build();
        let disk = JavaAnalyzer::new(fixture.project_dyn());
        let file = fixture.file(CALLER_PATH);
        for selected in [source.to_owned(), format!("// unsaved\n{source}")] {
            let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
            assert!(overlay.set(file.abs_path(), selected.clone()));
            let analyzer =
                disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
            assert!(!analyzer.declarations(&file).is_empty());
            let start_byte = selected.rfind("target").unwrap();
            let line = selected[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
            let site = ResolvedReferenceSite {
                path: CALLER_PATH.into(),
                text: "target".into(),
                range: Range {
                    start_byte,
                    end_byte: start_byte + 6,
                    start_line: line,
                    end_line: line,
                },
                focus_start_byte: start_byte,
                focus_end_byte: start_byte + 6,
            };
            let outcome = complete(resolve_java_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: &analyzer,
                    file: &file,
                    source: &selected,
                    tree: None,
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                || {},
            ));
            assert!(
                matches!(
                    outcome.status,
                    DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Incomplete
                ),
                "{outcome:?}"
            );
            assert!(
                outcome.definitions.is_empty(),
                "a lexical binder is not a workspace unit: {outcome:?}"
            );
            let lexical = outcome
                .lexical_definition
                .expect("selected lexical declaration");
            assert_eq!(lexical.identifier, "target");
            assert_eq!(lexical.kind, kind);
            assert_eq!(lexical.source_file.as_ref(), Some(&file));
            assert_eq!(
                lexical.name_range.start_byte,
                selected.find("target").unwrap()
            );
            assert_eq!(
                &selected[lexical.name_range.start_byte..lexical.name_range.end_byte],
                "target"
            );
            assert!(lexical.declaration_range.start_byte <= lexical.name_range.start_byte);
            assert!(lexical.declaration_range.end_byte >= lexical.name_range.end_byte);
            assert_eq!(std::fs::read_to_string(file.abs_path()).unwrap(), source);
        }
    }
}

#[test]
fn java_native_point_withdraws_answer_when_overlay_changes_after_open() {
    let (fixture, disk) = fixture();
    let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
    let analyzer = disk.clone_with_project(overlay.clone() as Arc<dyn Project>);
    let file = fixture.file(CALLER_PATH);
    let provider = fixture.file(PROVIDER_PATH);
    let site = site(CALLER);
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: CALLER,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {
            assert!(overlay.set(
                provider.abs_path(),
                "package moved; public class Target {}".into()
            ));
        },
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Unavailable,
        "{outcome:?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|reason| reason.kind == "native_stale"),
        "{outcome:?}"
    );
}

#[test]
fn java_native_type_retains_imported_nominal_and_primitive_results() {
    use crate::analyzer::usages::get_type::TypeLookupStatus;
    for (source, expected) in [
        (CALLER, "dep.Target"),
        (
            "package use; class Use { int f(int Target) { return Target; } }",
            "int",
        ),
    ] {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>types</artifactId><version>1</version></project>")
            .file(CALLER_PATH, source)
            .file(PROVIDER_PATH, "package dep; public class Target {}")
            .build();
        let analyzer = JavaAnalyzer::new(fixture.project_dyn());
        let file = fixture.file(CALLER_PATH);
        let site = site(source);
        let result = resolve_java_type_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        );
        let BoundedResolution::Complete { value, work } = result else {
            panic!("{result:?}")
        };
        assert!(work.scope_nodes > 0);
        assert!(
            matches!(
                value.status,
                TypeLookupStatus::Resolved | TypeLookupStatus::Incomplete
            ),
            "{value:?}"
        );
        assert_eq!(value.types.len(), 1, "{value:?}");
        assert_eq!(value.types[0].fqn, expected);
        if expected == "int" {
            assert!(value.types[0].definitions.is_empty());
        } else {
            assert_eq!(value.types[0].definitions.len(), 1);
            assert_eq!(
                value.types[0].definitions[0].source(),
                &fixture.file(PROVIDER_PATH)
            );
            assert_eq!(
                value.status,
                TypeLookupStatus::Resolved,
                "unique selected single-type import proves the workspace declaration"
            );
        }
    }
}

#[test]
fn java_generic_field_type_does_not_use_go_positional_substitution() {
    use crate::analyzer::usages::get_type::TypeLookupStatus;

    let source = "package use; class Box<T> { T value; } class Use { String read(Box<String> box) { return box.value; } }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>generic-parity</artifactId><version>1</version></project>")
        .file(CALLER_PATH, source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(CALLER_PATH);
    let site = site_at(CALLER_PATH, source, "box.value", "value");
    let result = resolve_java_type_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    );
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    assert_eq!(value.status, TypeLookupStatus::Incomplete, "{value:?}");
    assert!(value.types.is_empty(), "{value:?}");
}

#[test]
fn java_native_type_preserves_cancellation_budget_and_source_admission() {
    use crate::analyzer::usages::get_type::TypeLookupStatus;
    let (fixture, analyzer) = fixture();
    let file = fixture.file(CALLER_PATH);
    let site = site(CALLER);
    let cancellation = CancellationToken::new();
    let query = BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source: CALLER,
        tree: None,
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    };
    assert!(matches!(
        resolve_java_type_bounded(
            BoundedReceiverQuery {
                cancellation: Some(&cancellation),
                ..query
            },
            || cancellation.cancel()
        ),
        BoundedResolution::Cancelled { .. }
    ));
    assert!(matches!(
        resolve_java_type_bounded(
            BoundedReceiverQuery {
                budget: ReceiverAnalysisBudget::tiny(),
                ..query
            },
            || {}
        ),
        BoundedResolution::Exceeded { .. }
    ));
    let result = resolve_java_type_bounded(
        BoundedReceiverQuery {
            source: "class Changed {}",
            ..query
        },
        || {},
    );
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    assert_eq!(value.status, TypeLookupStatus::Unavailable);
    assert!(value.types.is_empty());
    assert!(
        value
            .diagnostics
            .iter()
            .any(|reason| reason.kind == "native_source_mismatch")
    );
}

fn site_at(path: &str, source: &str, anchor: &str, needle: &str) -> ResolvedReferenceSite {
    let anchor_start = source.find(anchor).expect("anchor");
    let start_byte = anchor_start
        + source[anchor_start..]
            .find(needle)
            .expect("needle after anchor");
    let end_byte = start_byte + needle.len();
    let line = source[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    ResolvedReferenceSite {
        path: path.into(),
        text: needle.into(),
        range: Range {
            start_byte,
            end_byte,
            start_line: line,
            end_line: line,
        },
        focus_start_byte: start_byte,
        focus_end_byte: end_byte,
    }
}

#[test]
fn java_native_single_type_import_split_returns_both_readings() {
    let caller = "package bench;\nimport bench.mod00000.Module00000;\npublic class BenchTest { public int total() { return new Module00000().changed(1); } }\n";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(
            "bench/mod00000.java",
            "package bench; public class mod00000 { public static class Module00000 { public int changed(int value) { return value; } } }",
        )
        .file(
            "bench/mod00000/Module00000.java",
            "package bench.mod00000; public class Module00000 { public int changed(int value) { return value; } }",
        )
        .file("bench/BenchTest.java", caller)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file("bench/BenchTest.java");
    let site = site_at(
        "bench/BenchTest.java",
        caller,
        "new Module00000",
        "Module00000",
    );
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: caller,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    // The two source shapes are distinct exact targets, so their ambiguity is
    // reportable even though the external inventory remains open.
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "{outcome:?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "incomplete_binding"),
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 2, "{outcome:?}");
}

#[test]
fn java_native_mirrored_single_type_import_collapses_same_declaration_shape() {
    let caller = "package bench;\nimport bench.mod00000.Module00000;\npublic class BenchTest { public int total() { return new Module00000().changed(1); } }\n";
    let module = "package bench.mod00000; public class Module00000 { public int changed(int value) { return value; } }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>mirrored-import</artifactId><version>1</version></project>")
        .file("src/main/java/guava/bench/mod00000/Module00000.java", module)
        .file("src/test/java/android/bench/mod00000/Module00000.java", module)
        .file("src/main/java/bench/BenchTest.java", caller)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let path = "src/main/java/bench/BenchTest.java";
    let file = fixture.file(path);
    let site = site_at(path, caller, "new Module00000", "Module00000");
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: caller,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "incomplete_binding"),
        "{outcome:?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "java-source-access-open"),
        "the Maven source roots establish declaration access; only the import split stays open: {outcome:?}"
    );
}

#[test]
fn java_native_scoped_external_type_uses_ast_qualifier_boundary() {
    let source = "package app; public class UseValue { private com.google.protobuf.Value value; }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("app/Value.java", "package app; public class Value {}")
        .file("app/UseValue.java", source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let path = "app/UseValue.java";
    let file = fixture.file(path);
    let site = site_at(path, source, "Value value", "Value");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must load");
    let tree = parser.parse(source, None).expect("Java source must parse");
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    let boundary = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == "java_scoped_type_external_boundary")
        .expect("scoped external type boundary");
    assert!(boundary.message.contains("com.google.protobuf.Value"));
    assert!(
        boundary.claim.as_ref().is_some_and(|claim| claim
            .subjects
            .iter()
            .any(|subject| subject == "com.google.protobuf.Value")),
        "{outcome:?}"
    );
}

#[test]
fn java_native_scoped_missing_type_in_workspace_package_is_not_external() {
    let source = "package app; public class UseMissing { private app.Missing value; }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("app/Known.java", "package app; public class Known {}")
        .file("app/UseMissing.java", source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let path = "app/UseMissing.java";
    let file = fixture.file(path);
    let site = site_at(path, source, "Missing value", "Missing");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must load");
    let tree = parser.parse(source, None).expect("Java source must parse");
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));

    assert_ne!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:?}"
    );
}

fn native_java_definition_at(
    path: &str,
    source: &str,
    anchor: &str,
    needle: &str,
) -> DefinitionLookupOutcome {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(path, source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(path);
    let site = site_at(path, source, anchor, needle);
    complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ))
}

#[test]
fn java_native_bounded_type_parameter_retains_its_selected_bound_member() {
    let source = "package p; interface Node { Node child(); } class Tree<T extends Node> { void walk(T value) { value.child(); } }";
    let outcome = native_java_definition_at("src/p/Tree.java", source, "value.child()", "child");
    // `child()` is a zero-argument exact match on the indexed interface, so a
    // proven exact selection on an indexed owner closes the owner's ancestor
    // frontier: an implicit-root member of the same signature is overridden by
    // `Node.child`, and one of any other shape is not applicable.
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "a proven exact selection on an indexed owner closes the owner's ancestor frontier: {outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].fq_name(), "p.Node.child");
}

#[test]
fn java_native_local_type_is_visible_after_its_declaration() {
    let source = "package p; class Owner { Object make() { class Local { Local value; } Local value = new Local(); return value; } }";
    let outcome = native_java_definition_at("src/p/Owner.java", source, "Local value =", "Local");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    let self_reference =
        native_java_definition_at("src/p/Owner.java", source, "Local value;", "Local");
    assert_eq!(
        self_reference.status,
        DefinitionLookupStatus::Resolved,
        "{self_reference:?}"
    );
    assert_eq!(self_reference.definitions.len(), 1, "{self_reference:?}");
}

#[test]
fn java_native_enum_switch_label_uses_the_selector_enum_owner() {
    let source = "package p; enum State { IDLE, BUSY } class Owner { int pick(State state) { switch (state) { case IDLE: return 1; default: return 0; } } }";
    let outcome = native_java_definition_at("src/p/Owner.java", source, "case IDLE", "IDLE");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
}

#[brokk_bifrost_test_macros::hardwon(
    "d1238c7e808b: Separately covers arrow-switch AST shape and verifies the selected enum constant identity"
)]
#[test]
fn java_native_arrow_switch_label_uses_the_selector_enum_owner() {
    let source = "package p; enum State { IDLE, BUSY } class Owner { int pick(State state) { return switch (state) { case IDLE -> 1; default -> 0; }; } }";
    let outcome = native_java_definition_at("src/p/Owner.java", source, "case IDLE", "IDLE");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert!(
        outcome.definitions[0].fq_name().ends_with("p.State.IDLE"),
        "{outcome:?}"
    );
}

#[test]
fn java_native_switch_enum_label_beats_same_named_imported_type() {
    let path = "src/main/java/demo/Router.java";
    let source = "package demo;\nimport demo.spi.FAST;\nclass Router {\n    enum Mode { FAST, SLOW }\n    int pick(Mode mode, FAST marker) {\n        switch (mode) {\n            case FAST: return marker.hashCode();\n            default: return 0;\n        }\n    }\n}\n";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>switch-labels</artifactId><version>1</version></project>")
        .file(path, source)
        .file(
            "src/main/java/demo/spi/FAST.java",
            "package demo.spi; public class FAST {}",
        )
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let file = fixture.file(path);
    let site = site_at(path, source, "case FAST:", "FAST");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must load");
    let tree = parser.parse(source, None).expect("Java source must parse");
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert!(
        outcome.definitions[0]
            .fq_name()
            .ends_with("demo.Router.Mode.FAST"),
        "{outcome:?}"
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "211faf231fb6: a Java type pattern was not lowered as a type reference"
)]
#[test]
fn java_native_switch_type_pattern_keeps_its_type_reference() {
    let source = "package p; class Circle {} class Owner { int pick(Object value) { return switch (value) { case Circle circle -> 1; default -> 0; }; } }";
    let outcome =
        native_java_definition_at("src/p/Owner.java", source, "case Circle circle", "Circle");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
}

#[brokk_bifrost_test_macros::hardwon(
    "211faf231fb6: a this-field switch selector used the enum type declared for that field"
)]
#[test]
fn java_native_this_field_switch_selector_uses_its_declared_enum_type() {
    let source = "package p; enum State { IDLE, BUSY } class Owner { State state; int pick() { return switch (this.state) { case IDLE -> 1; default -> 0; }; } }";
    let outcome = native_java_definition_at("src/p/Owner.java", source, "case IDLE", "IDLE");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert!(
        outcome.definitions[0].fq_name().ends_with("p.State.IDLE"),
        "{outcome:?}"
    );
}

#[test]
fn java_native_synchronized_expression_resolves_an_inherited_field() {
    let source = "package p; class SyncObject { final Object mutex; } class SyncCollection extends SyncObject { void run() { synchronized (mutex) { } } }";
    let outcome =
        native_java_definition_at("src/p/Sync.java", source, "synchronized (mutex", "mutex");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
}

#[test]
fn java_native_static_import_boundary_names_the_imported_owner() {
    let source =
        "package use; import static com.external.Owner.lint; class Use { void run() { lint(); } }";
    let outcome = native_java_definition_at("src/use/Use.java", source, "lint()", "lint");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:?}"
    );
    let diagnostic = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == "java_static_import_external_boundary")
        .expect("the external static import boundary is reported");
    let claim = diagnostic.claim.as_ref().expect("structured import claim");
    assert_eq!(claim.subjects, vec!["com.external.Owner.lint".to_string()]);
}

#[brokk_bifrost_test_macros::hardwon(
    "d1238c7e808b: A real package-collision fixture proves an external static import remains authoritative over a local same-package declaration"
)]
#[test]
fn java_native_static_import_keeps_external_owner_authoritative() {
    let caller = "package butterknife.lint; import static com.android.tools.lint.checks.infrastructure.TestLintTask.lint; class InvalidR2UsageDetectorTest { void run() { lint().run(); } }";
    let registry = "package butterknife.lint; public class LintRegistry { public String name() { return \"butterknife\"; } }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(
            "butterknife-lint/src/test/java/butterknife/lint/InvalidR2UsageDetectorTest.java",
            caller,
        )
        .file(
            "butterknife-lint/src/main/java/butterknife/lint/LintRegistry.java",
            registry,
        )
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture
        .file("butterknife-lint/src/test/java/butterknife/lint/InvalidR2UsageDetectorTest.java");
    let site = site_at(
        "butterknife-lint/src/test/java/butterknife/lint/InvalidR2UsageDetectorTest.java",
        caller,
        "lint().run()",
        "lint",
    );
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: caller,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:?}"
    );
    let claim = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == "java_static_import_external_boundary")
        .and_then(|diagnostic| diagnostic.claim.as_ref())
        .expect("the external static import owns the boundary claim");
    assert_eq!(
        claim.subjects,
        vec!["com.android.tools.lint.checks.infrastructure.TestLintTask.lint".to_string()]
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "d1238c7e808b: Checks the distinct java.* static-import boundary and exact owner claim for a nested call expression"
)]
#[test]
fn java_native_static_import_of_jdk_method_keeps_owner_authority() {
    let source = "package app; import static java.net.URLDecoder.decode; class App { String source() { return \"x\"; } void sink(String value) {} void run() { sink(decode(source(), \"UTF-8\")); } }";
    let outcome =
        native_java_definition_at("src/app/App.java", source, "decode(source()", "decode");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:?}"
    );
    let claim = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == "java_static_import_external_boundary")
        .and_then(|diagnostic| diagnostic.claim.as_ref())
        .expect("the JDK static import owns the boundary claim");
    assert_eq!(
        claim.subjects,
        vec!["java.net.URLDecoder.decode".to_string()]
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "d1238c7e808b: Maven source-root metadata closes source access and a cross-file inherited method resolves to the base declaration"
)]
#[test]
fn java_native_inherited_member_query_keeps_the_selected_base_declaration() {
    const POM: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>inherited</artifactId><version>1</version></project>";
    let caller =
        "package app; import pkg.Child; class UseChild { void call(Child child) { child.run(); } }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("pom.xml", POM)
        .file(
            "src/main/java/pkg/Base.java",
            "package pkg; public class Base { public void run() {} }",
        )
        .file(
            "src/main/java/pkg/Child.java",
            "package pkg; public class Child extends Base {}",
        )
        .file("src/main/java/app/UseChild.java", caller)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file("src/main/java/app/UseChild.java");
    let site = site_at(
        "src/main/java/app/UseChild.java",
        caller,
        "child.run()",
        "run",
    );
    let outcome = complete(resolve_java_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: caller,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "java-source-access-open"),
        "the Maven source root closes source access: {outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert!(
        outcome.definitions[0].fq_name().ends_with("pkg.Base.run"),
        "{outcome:?}"
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "d1238c7e808b: One fixture checks ownership for both a named local class field and an anonymous-class field"
)]
#[test]
fn java_native_local_field_stays_in_its_declaring_type_scope() {
    let source = "package p; class Owner { int outer; Object make() { class Local { int local; int read() { return local; } } return new Object() { int marker; int read() { return marker; } }; } }";
    let local = native_java_definition_at("src/p/Owner.java", source, "return local", "local");
    assert_eq!(local.status, DefinitionLookupStatus::Resolved, "{local:?}");
    assert_eq!(local.definitions.len(), 1, "{local:?}");
    assert!(
        local.definitions[0].short_name().contains("Local.local"),
        "{local:?}"
    );

    let anonymous =
        native_java_definition_at("src/p/Owner.java", source, "return marker", "marker");
    assert_eq!(
        anonymous.status,
        DefinitionLookupStatus::Resolved,
        "{anonymous:?}"
    );
    assert_eq!(anonymous.definitions.len(), 1, "{anonymous:?}");
    assert!(
        anonymous.definitions[0].short_name().contains("$anon$"),
        "{anonymous:?}"
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "d1238c7e808b: Checks nested anonymous owner qualification and enum field ownership as separate nested type forms"
)]
#[test]
fn java_native_nested_anonymous_and_enum_fields_keep_their_owners() {
    let nested = "package p; class Owner { Object make() { return new Object() { Object nested() { return new Object() { int leaf; int read() { return leaf; } }; } }; } }";
    let nested_outcome =
        native_java_definition_at("src/p/Owner.java", nested, "return leaf", "leaf");
    assert_eq!(
        nested_outcome.status,
        DefinitionLookupStatus::Resolved,
        "{nested_outcome:?}"
    );
    assert_eq!(nested_outcome.definitions.len(), 1, "{nested_outcome:?}");
    assert!(
        nested_outcome.definitions[0]
            .short_name()
            .matches("$anon$")
            .count()
            >= 2,
        "{nested_outcome:?}"
    );

    let enumeration = "package p; enum State { READY; private final int marker = 1; int read() { return marker; } }";
    let enum_outcome =
        native_java_definition_at("src/p/State.java", enumeration, "return marker", "marker");
    assert_eq!(
        enum_outcome.status,
        DefinitionLookupStatus::Resolved,
        "{enum_outcome:?}"
    );
    assert_eq!(enum_outcome.definitions.len(), 1, "{enum_outcome:?}");
    assert!(
        enum_outcome.definitions[0]
            .short_name()
            .ends_with("State.marker"),
        "{enum_outcome:?}"
    );
}

#[test]
fn java_native_point_resolves_nested_unqualified_same_class_calls() {
    let source = "class Token {} class Other {} class App { static Token source() { return null; } static void sink(Token value) {} static void sink(Other value) {} void run() { sink(source()); } }";
    let path = "src/App.java";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(path, source)
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(path);
    let resolve_at = |needle: &str, method: &str| {
        let start_byte = source.rfind(needle).expect("call site");
        let site = ResolvedReferenceSite {
            path: path.into(),
            text: method.into(),
            range: Range {
                start_byte,
                end_byte: start_byte + method.len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + method.len(),
        };
        complete(resolve_java_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ))
    };

    let source_call = resolve_at("source());", "source");
    let sink_call = resolve_at("sink(source())", "sink");
    assert_eq!(
        source_call.status,
        DefinitionLookupStatus::Resolved,
        "{source_call:?}"
    );
    assert_eq!(source_call.definitions[0].fq_name(), "App.source");
    assert_eq!(
        sink_call.status,
        DefinitionLookupStatus::Resolved,
        "{sink_call:?}"
    );
    let [sink] = sink_call.definitions.as_slice() else {
        panic!("nested source-call result selects one sink overload: {sink_call:?}");
    };
    let ranges = analyzer.ranges_of(sink);
    let [range] = ranges.as_slice() else {
        panic!("one sink declaration range: {sink:?}");
    };
    assert!(
        source[range.start_byte..].starts_with("static void sink(Token"),
        "the nested call result selects the Token formal: {sink_call:?}"
    );
}
