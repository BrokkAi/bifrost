use super::contracts::assert_serial_profile_reconciles;
use super::*;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::semantic::{
    SemanticBudget, SemanticBudgetDimension, SemanticEffect, SemanticRequest, SemanticValueKind,
    ValueFlowKind,
};
use crate::analyzer::semantic_model::{
    CatalogOptions, CompilerOptions, DependencyPackLimits, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
    acquire_active_semantic_models, compile_source,
};
use crate::analyzer::usages::effects::EffectCoverage;
use crate::cancellation::CancellationToken;
use brokk_bifrost_test_macros::hardwon;
use semver::Version;

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#5113: procedure inventory references attributed class-body calls to the initializer"
)]
fn python_procedure_inventory_respects_class_body_ownership_holes() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "marker()\nclass C:\n    marker()\n    def method(self):\n        marker()\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "name": "marker" },
        "steps": [{ "op": "procedure_of" }]
    }))
    .expect("enclosing procedure query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(result.results.len(), 2, "{result:#?}");
    assert_eq!(result.diagnostics.len(), 1, "{result:#?}");
    assert_eq!(
        result.diagnostics[0].code,
        CodeQueryDiagnosticCode::NoEnclosingProcedure,
        "{result:#?}"
    );
}

#[test]
fn occurrence_targets_are_resolved_only_after_the_query_demands_them() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "struct Target;\nfn target() {}\nfn caller(_value: Target) { target(); missing(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();

    let identity_only = CodeQuery::from_sexp("(occurrences :role [type_operand value_reference])")
        .expect("identity-only occurrence query");
    let identity_result = execute_workspace(&workspace, &flow, &identity_only);
    assert_eq!(
        identity_result.results.len(),
        3,
        "{}",
        identity_result.render_text()
    );
    assert!(identity_result.results.iter().all(|item| {
        item.value
            .row()
            .field("target_kind")
            .expect("registered occurrence target field")
            == Some(CodeQueryRowScalarRef::ConstrainedEnum("not_derived"))
    }));

    let target_filter = CodeQuery::from_sexp(
        "(filter :where ((role eq (enum value_reference)) (target_kind eq (enum resolved))) (occurrences :role [type_operand value_reference]))",
    )
    .expect("target-dependent occurrence filter");
    let filtered = execute_workspace(&workspace, &flow, &target_filter);
    assert_eq!(filtered.results.len(), 1, "{}", filtered.render_text());
    let [resolved] = filtered.results.as_slice() else {
        panic!("the target filter keeps only the resolved call: {filtered:#?}");
    };
    let CodeQueryResultValue::Occurrence { value } = &resolved.value else {
        panic!("the filter keeps occurrence rows: {resolved:#?}");
    };
    assert_eq!(value.raw_spelling, "target");
    assert!(matches!(
        resolved.value.row().field("target_kind"),
        Ok(Some(CodeQueryRowScalarRef::ConstrainedEnum("resolved")))
    ));

    let target_step =
        CodeQuery::from_sexp("(occurrence-target (occurrences :role [value_reference]))")
            .expect("occurrence-target step");
    let targeted = execute_workspace(&workspace, &flow, &target_step);
    assert_eq!(targeted.results.len(), 1, "{}", targeted.render_text());
    let CodeQueryResultValue::Declaration { value } = &targeted.results[0].value else {
        panic!("the occurrence-target step returns declarations: {targeted:#?}");
    };
    assert_eq!(value.fq_name, "target");

    let target_projection = CodeQuery::from_sexp(
        "(project :columns (target_kind) (filter :where ((role eq (enum value_reference))) (occurrences :role [type_operand value_reference])))",
    )
    .expect("target projection after occurrence filtering");
    let projected = execute_workspace(&workspace, &flow, &target_projection);
    let mut target_kinds = projected
        .results
        .iter()
        .map(|item| {
            match item
                .value
                .row()
                .field("target_kind")
                .expect("registered occurrence target field")
            {
                Some(CodeQueryRowScalarRef::ConstrainedEnum(kind)) => kind,
                other => panic!("target projection has an enum value: {other:?}"),
            }
        })
        .collect::<Vec<_>>();
    target_kinds.sort_unstable();
    assert_eq!(target_kinds, ["resolved", "unresolved"]);
}

#[test]
fn java_result_obligation_keeps_unselected_jdk_calls_incomplete() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "App.java",
            "class App { void run(String value) { value.trim(); String kept = value.trim(); } }",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query =
        CodeQuery::from_source(r#"(call-result-obligations (call-shape (call :callee "trim")))"#)
            .expect("reviewed obligation query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(result.results.len(), 2, "{}", result.render_text());
    let mut discarded = 0;
    let mut retained = 0;
    for item in &result.results {
        let CodeQueryResultValue::CallResultObligation { value } = &item.value else {
            panic!("the query publishes its own typed row: {item:#?}");
        };
        match value.result_use {
            "discarded" => {
                discarded += 1;
                assert!(value.terminal);
                assert_ne!(value.coverage, "exhaustive");
                assert!(value.reason.is_some());
            }
            "other_context" => {
                retained += 1;
                assert!(value.terminal);
                assert_eq!(value.coverage, "exhaustive");
                assert!(value.reason.is_none());
            }
            other => panic!("unexpected result-use classification: {other}"),
        }
    }
    assert_eq!((discarded, retained), (1, 1));
    assert!(matches!(
        result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
fn native_go_result_obligation_projects_per_port_result_use() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            "package p\nfunc pair() (int, error) { return 1, nil }\nfunc sink(int, error) {}\nfunc run() { pair(); _, _ = pair(); sink(pair()); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query =
        CodeQuery::from_source(r#"(call-result-obligations (call-shape (call :callee "pair")))"#)
            .expect("native result-use query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::CallResultObligation { value } => value,
            other => panic!("unexpected native result-use row: {other:#?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 6, "{}", result.render_text());
    assert_eq!(
        rows.iter()
            .filter(|row| row.result_use == "discarded")
            .count(),
        2
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.result_use == "intentional_discard")
            .count(),
        2
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.result_use == "consumed")
            .count(),
        2
    );
    assert!(rows.iter().all(|row| row.language == "go"));
    let native = rows
        .iter()
        .filter(|row| row.provenance == Some("native"))
        .collect::<Vec<_>>();
    assert_eq!(native.len(), 3, "{rows:#?}");
    assert!(native.iter().all(|row| {
        row.obligation_kind == Some("fallible_status")
            && row.obligation_basis == Some("static_signature")
            && !row.terminal
    }));
    assert!(
        native
            .iter()
            .any(|row| { row.result_use == "discarded" && row.result_ordinal == Some(1) })
    );
    assert!(native.iter().any(|row| {
        row.result_use == "intentional_discard"
            && row.result_use_detail == Some("go_blank_assignment")
            && row.result_ordinal == Some(1)
    }));
    assert!(rows.iter().any(|row| {
        row.result_use_detail == Some("go_blank_assignment") && row.result_ordinal == Some(0)
    }));
}

#[test]
#[hardwon(
    "#8036: native Go dropped the pre-#7954 stdlib callee identities, losing never-error exclusions"
)]
fn native_go_error_obligation_handles_signature_shapes_and_open_boundaries() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            "package p
import \"bytes\"
import \"fmt\"
import \"hash\"
import \"strings\"
type Runner interface { Run() error }
type Worker struct{}
type Fallible func() error
func (Worker) Run() error { return nil }
func fallible() (int, error) { return 1, nil }
func onlyError() error { return nil }
func corrected() error { if err := onlyError(); err != nil { return err }; return nil }
func blank() { _ = onlyError() }
func interfaceCall(r Runner) { r.Run() }
func knownFunctionValue() { var f func() error = onlyError; f() }
func excluded() { var b bytes.Buffer; b.Write(nil) }
func excludedBuilder() { var b strings.Builder; b.Write(nil) }
func excludedHash(h hash.Hash) { h.Write(nil) }
func fmtCall() { fmt.Print(\"\") }
func unresolved() { missing() }
func unknown(value any) { value() }
func direct() { fallible() }
func shadowed() {
    type error struct{}
    var f func() error = func() error { return error{} }
    f()
}
func parameterFunction(f func() error) { f() }
func namedFunctionValue(f Fallible) { f() }
func deferred() { defer onlyError() }
func spawned() { go onlyError() }
func recovered() { fallible( }
",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source(r#"(call-result-obligations (call-shape (call)))"#)
        .expect("native Go obligation query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::CallResultObligation { value } => value,
            other => panic!("unexpected Go obligation row: {other:#?}"),
        })
        .collect::<Vec<_>>();
    let native_discarded = rows
        .iter()
        .filter(|row| row.provenance == Some("native") && row.result_use == "discarded")
        .collect::<Vec<_>>();
    assert!(
        native_discarded.len() >= 4,
        "expected direct, interface, and function-value native findings: {rows:#?}"
    );
    assert!(native_discarded.iter().all(|row| {
        row.obligation_kind == Some("fallible_status")
            && row.obligation_basis.is_some()
            && row.coverage == "exhaustive"
            && !row.terminal
    }));
    assert!(rows.iter().any(|row| {
        row.result_use == "intentional_discard"
            && row.result_use_detail == Some("go_blank_assignment")
            && row.provenance == Some("native")
    }));
    assert!(rows.iter().any(|row| {
        row.reason == Some("native_excluded_stdlib_never_error")
            && row.provenance.is_none()
            && row.terminal
    }));
    assert!(
        rows.iter()
            .filter(|row| {
                row.reason == Some("native_excluded_stdlib_never_error")
                    && row.provenance.is_none()
                    && row.terminal
            })
            .count()
            >= 3
    );
    assert!(rows.iter().any(|row| {
        row.range.start_line > 14
            && row.provenance == Some("native")
            && row.result_use == "discarded"
    }));
    assert!(rows.iter().any(|row| {
        row.range.start_line > 28
            && row.provenance == Some("native")
            && row.result_use == "discarded"
    }));
    assert!(rows.iter().any(|row| {
        row.reason == Some("dispatch_unresolved") || row.reason == Some("native_signature_unknown")
    }));
    assert!(rows.iter().any(|row| {
        row.range.start_line > 14
            && row.provenance.is_none()
            && row.reason == Some("dispatch_unresolved")
    }));
    assert!(rows.iter().any(|row| {
        row.result_use == "open" && row.range.start_line > 14 && row.coverage == "open"
    }));
}

#[test]
fn java_result_obligation_requires_selected_jdk_source_and_discarded_use() {
    use crate::analyzer::{
        DependencyPackEcosystem, DependencyPackWorkspaceContext, JvmAnalyzerConfig,
        JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode,
        JvmStandardLibraryDiscoveryConfig,
    };
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/App.java",
            "class App { void run(String value) { value.trim(); String kept = value.trim(); } void cleanup(String value) { try { System.out.println(value); } finally { value.trim(); } } }",
        )
        .file(
            "src/Lambdas.java",
            "class Lambdas { Runnable discarded(String value) { return () -> value.trim(); } java.util.function.Supplier<String> retained(String value) { return () -> value.trim(); } }",
        )
        .file(
            "src/SourceTargets.java",
            "class SourceTargets { interface Base<T> { T get(); } interface Runnable extends Base<String> {} interface Action { void run(); default int size() { return 1; } static int factory() { return 1; } } Runnable retained(String value) { return () -> value.trim(); } Action discarded(String value) { return () -> value.trim(); } }",
        )
        .file(
            "src/StatusTargets.java",
            "import java.nio.file.Files; import java.nio.file.Path; class StatusTargets { interface Action { void run() throws Exception; } interface Query { boolean run() throws Exception; } Action discarded(Path path) { return () -> Files.deleteIfExists(path); } Query retained(Path path) { return () -> Files.deleteIfExists(path); } }",
        )
        .file(
            "src/Streams.java",
            "class Streams { void run(java.util.stream.Stream<String> values, String value) { values.map(item -> item.trim()); values.forEach(ignored -> value.trim()); } }",
        )
        .file(
            "src/Arguments.java",
            "class Arguments { void run(String value) { Targets.consume(() -> value.trim()); Targets.retain(() -> value.trim()); } }",
        )
        .file(
            "src/Targets.java",
            "class Targets { static void consume(Runnable action) {} static void retain(java.util.function.Supplier<String> action) {} }",
        )
        .file(
            "src/DeleteApp.java",
            "import java.nio.file.Files; import java.nio.file.Path; class DeleteApp { void run(Path path) { Files.deleteIfExists(path); boolean deleted = Files.deleteIfExists(path); } }",
        )
        .file(
            "src/Virtual.java",
            "interface Trimmer { String trim(); } class Left implements Trimmer { public String trim() { return \"left\"; } } class Right implements Trimmer { public String trim() { return \"right\"; } } class Virtual { void run(Trimmer value) { value.trim(); } }",
        )
        .build();
    std::fs::create_dir_all(project.root().join(".bifrost")).expect("configuration directory");
    std::fs::write(
        project.root().join(".bifrost/jvm-toolchains.json"),
        r#"{"schema_version":1,"source_toolchains":[{"source_root":"src","jdk_home":"toolchains/jdk-21"}]}"#,
    ).expect("workspace toolchain document");
    let home = project.root().join("toolchains/jdk-21");
    std::fs::create_dir_all(home.join("lib")).expect("JDK lib directory");
    std::fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").expect("JDK release file");
    let archive = std::fs::File::create(home.join("lib/src.zip")).expect("JDK source archive");
    let mut archive = zip::ZipWriter::new(archive);
    for (path, source) in [
        (
            "java.base/module-info.java",
            "module java.base { exports java.lang; exports java.nio.file; exports java.util.function; exports java.util.stream; }",
        ),
        (
            "java.base/java/lang/Object.java",
            "package java.lang; public class Object { public boolean equals(Object other) { return this == other; } public int hashCode() { return 0; } public String toString() { return \"\"; } }",
        ),
        (
            "java.base/java/lang/Runnable.java",
            "package java.lang; public interface Runnable { void run(); }",
        ),
        (
            "java.base/java/util/function/Supplier.java",
            "package java.util.function; public interface Supplier<T> { T get(); }",
        ),
        (
            "java.base/java/util/function/Function.java",
            "package java.util.function; public interface Function<T, R> { R apply(T value); }",
        ),
        (
            "java.base/java/util/function/Consumer.java",
            "package java.util.function; public interface Consumer<T> { void accept(T value); }",
        ),
        (
            "java.base/java/util/stream/Stream.java",
            "package java.util.stream; public interface Stream<T> { <R> Stream<R> map(java.util.function.Function<? super T, ? extends R> mapper); void forEach(java.util.function.Consumer<? super T> action); }",
        ),
        (
            "java.base/java/lang/String.java",
            "package java.lang; public final class String { public String trim() { return this; } }",
        ),
        (
            "java.base/java/nio/file/Path.java",
            "package java.nio.file; public interface Path {}",
        ),
        (
            "java.base/java/nio/file/Files.java",
            "package java.nio.file; public final class Files { public static boolean deleteIfExists(Path path) { return false; } }",
        ),
    ] {
        archive
            .start_file(
                path,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .expect("JDK source entry");
        archive
            .write_all(source.as_bytes())
            .expect("JDK source bytes");
    }
    archive.finish().expect("finished source archive");

    let config = AnalyzerConfig {
        jvm: JvmAnalyzerConfig {
            dependency_discovery: JvmDependencyDiscoveryConfig {
                mode: JvmDependencyDiscoveryMode::Disabled,
                ..Default::default()
            },
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                discover_java_home: false,
                ..Default::default()
            },
            ..JvmAnalyzerConfig::default()
        },
        ..AnalyzerConfig::default()
    };
    let workspace = project.workspace_analyzer(config.clone());
    let pack = compile_source(
        SourceFormat::Json,
        br#"{
          "schema_version": 5,
          "pack_id": "bifrost.jdk21.result-use-obligations", "version": "1.0.0",
          "producer": {"name": "test", "version": "1.0.0"},
          "language": "java", "ecosystem": "jdk",
          "compatibility": {"bifrost": ">=0.12.0, <1.0.0", "toolchains": [{"name": "jdk", "requirement": ">=21.0.0, <22.0.0"}]},
          "provenance": {"source": "test:reviewed-jdk-result-use"},
          "license": "Apache-2.0", "completeness": "complete",
          "safety": {"generated_code_only": false, "review_required": false},
          "shards": [{
            "id": "result-use", "activation": [{"toolchain": {"name": "jdk", "version": ">=21.0.0, <22.0.0"}, "targets": ["jvm"]}],
            "payload": {"kind": "procedure_summaries", "summaries": [
              {"id": "trim", "target": {"path": "java.base/java/lang/String.java", "symbol": "java.lang.String.trim()", "has_receiver": true, "parameter_count": 0},
               "completeness": "complete", "ordinary_heap_unchanged": true, "covers_overrides": true,
               "normal_result_count": 1, "transfers": [], "effects": [],
               "result_use_obligations": [{"result_ordinal": 0, "kind": "pure_transformation_value"}]},
              {"id": "delete", "target": {"path": "java.base/java/nio/file/Files.java", "symbol": "java.nio.file.Files.deleteIfExists(java.nio.file.Path)", "has_receiver": false, "parameter_count": 1},
               "completeness": "partial", "normal_result_count": 1, "transfers": [],
               "result_use_obligations": [{"result_ordinal": 0, "kind": "fallible_status", "failure_predicate": "false"}]}
            ]}
          }]
        }"#,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("reviewed JDK pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:reviewed-jdk-result-use".to_owned(),
            },
        )
        .expect("register reviewed pack");
    let activation = workspace.activate_dependency_packs(
        workspace
            .config()
            .expect("immutable workspace configuration"),
        &[DependencyPackEcosystem::Jvm],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
                evidence: Vec::new(),
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            limits: DependencyPackLimits::default(),
            cancellation: &CancellationToken::default(),
        },
    );
    assert!(
        matches!(
            activation.runtime,
            Some(SemanticModelRuntimeOutcome::Ready { .. })
        ),
        "JDK source binding and pack activation: {activation:#?}"
    );

    let query =
        CodeQuery::from_source(r#"(call-result-obligations (call-shape (call :callee "trim")))"#)
            .expect("reviewed obligation query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(result.results.len(), 12, "{}", result.render_text());
    let mut positive = 0;
    let mut retained = 0;
    for item in &result.results {
        let CodeQueryResultValue::CallResultObligation { value } = &item.value else {
            panic!("the query publishes its own typed row: {item:#?}");
        };
        if value.path == "src/Virtual.java" {
            assert!(value.arm_count >= 2, "{value:#?}");
            assert_eq!(value.modeled_arm_count, 0, "{value:#?}");
            assert!(value.terminal, "{value:#?}");
            assert_eq!(value.coverage, "open", "{value:#?}");
            assert_eq!(value.reason, Some("target_unresolved"), "{value:#?}");
            continue;
        }
        match value.result_use {
            "discarded" => {
                positive += 1;
                assert!(!value.terminal, "{value:#?}");
                assert_eq!(value.coverage, "exhaustive");
                assert_eq!(value.obligation_kind, Some("pure_transformation_value"));
                assert_eq!(
                    value.pack_id.as_deref(),
                    Some("bifrost.jdk21.result-use-obligations")
                );
            }
            "other_context" => {
                retained += 1;
                assert!(value.terminal, "{value:#?}");
            }
            other => panic!("unexpected result-use classification: {other}"),
        }
    }
    assert_eq!((positive, retained), (6, 5));
    assert!(result.results.iter().any(|item| matches!(&item.value, CodeQueryResultValue::CallResultObligation { value } if value.arm_count > 1 && value.modeled_arm_count == value.arm_count && !value.terminal)), "{result:#?}");

    let status_query = CodeQuery::from_source(
        r#"(call-result-obligations (call-shape (call :callee "deleteIfExists")))"#,
    )
    .expect("reviewed status query");
    let status = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &status_query,
    );
    assert_eq!(status.results.len(), 4, "{}", status.render_text());
    let discarded = status
        .results
        .iter()
        .find_map(|item| match &item.value {
            CodeQueryResultValue::CallResultObligation { value }
                if value.result_use == "discarded" =>
            {
                Some(value)
            }
            _ => None,
        })
        .expect("discarded status result");
    assert!(!discarded.terminal, "{discarded:#?}");
    assert_eq!(discarded.coverage, "exhaustive");
    assert_eq!(discarded.obligation_kind, Some("fallible_status"));
    assert_eq!(discarded.failure_predicate, Some("false"));
    let filter = CodeQuery::from_source(
        r#"(filter :where ((failure_predicate eq (enum false)) (terminal eq false)) (call-result-obligations (call-shape (call :callee "deleteIfExists"))))"#,
    ).expect("typed enum obligation filter");
    let filtered = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &filter,
    );
    assert_eq!(filtered.results.len(), 2, "{}", filtered.render_text());
}

#[test]
fn python_binding_uses_joins_each_parameter_to_its_reference_occurrences() {
    let source = concat!(
        "def run(used, unused):\n",
        "    def inner():\n",
        "        used = 0\n",
        "        return used\n",
        "    return used\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source("(binding-uses (bindings :kind [parameter]))")
        .expect("binding uses query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert_eq!(result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(result.results.len(), 1, "{}", result.render_text());
    let CodeQueryResultValue::Occurrence { value } = &result.results[0].value else {
        panic!(
            "binding_uses returns occurrence rows: {:?}",
            result.results[0]
        );
    };
    assert_eq!(value.raw_spelling, "used");
    assert_eq!(
        value.start_byte,
        source.rfind("return used").unwrap() + "return ".len()
    );
}

#[test]
fn python_binding_uses_joins_local_and_loop_bindings() {
    let source = concat!(
        "def run(items):\n",
        "    local = 1\n",
        "    for item in items:\n",
        "        consume(item)\n",
        "    return local\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source(
        "(binding-uses (bindings :kind [local loop_variable] :name [local item]))",
    )
    .expect("local and loop binding uses query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert!(
        matches!(result.completion(), CodeQueryCompletion::Incomplete { .. }),
        "unresolved references in a scope make binding uses incomplete: {}",
        result.render_text()
    );
    let mut uses = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::Occurrence { value } => {
                (value.raw_spelling.as_str(), value.start_byte)
            }
            other => panic!("binding_uses returns occurrence rows: {other:?}"),
        })
        .collect::<Vec<_>>();
    uses.sort_unstable();
    assert_eq!(
        uses,
        [
            ("item", source.find("item)").expect("loop-variable use")),
            (
                "local",
                source.rfind("return local").expect("local-variable use") + "return ".len()
            ),
        ]
    );
}

#[test]
fn python_binding_difference_selects_bindings_without_resolved_reads() {
    let source = concat!(
        "def run(parameter_used, parameter_unused, items):\n",
        "    local_used = parameter_used\n",
        "    local_unused = 0\n",
        "    for loop_used in items:\n",
        "        local_used = loop_used\n",
        "    for loop_unused in items:\n",
        "        pass\n",
        "    return local_used\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source(
        "(except (bindings :kind [parameter local loop_variable]) (binding-of (binding-uses (bindings :kind [parameter local loop_variable]))))",
    )
    .expect("unused-binding difference query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{}",
        result.render_text()
    );
    let mut unused = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::Binding { value } => (value.name.as_str(), value.start_byte),
            other => panic!("unused-binding difference returns binding rows: {other:?}"),
        })
        .collect::<Vec<_>>();
    unused.sort_unstable_by_key(|(name, _)| *name);
    // Python loops do not open a scope, so the loop-body re-binding of
    // `local_used` is the same function local as the first assignment and wins
    // the `return local_used` read positionally. The superseded first binder is
    // therefore the one without a resolved read, exactly as in straight-line
    // re-assignment (#5339).
    assert_eq!(
        unused,
        [
            (
                "local_unused",
                source.find("local_unused").expect("unused local binder")
            ),
            (
                "local_used",
                source
                    .find("local_used = parameter_used")
                    .expect("first assignment binder without a resolved read")
            ),
            (
                "loop_unused",
                source.find("loop_unused").expect("unused loop binder")
            ),
            (
                "parameter_unused",
                source
                    .find("parameter_unused")
                    .expect("unused parameter binder")
            ),
        ]
    );
}

#[test]
fn python_binding_difference_is_incomplete_for_unresolved_or_dynamic_scope_reads() {
    let query = CodeQuery::from_source(
        "(except (bindings :kind [parameter]) (binding-of (binding-uses (bindings :kind [parameter]))))",
    )
    .expect("unused-parameter difference query");

    for read in [
        "missing_name()",
        "locals()",
        "globals()",
        "eval('value')",
        "exec('value = 1')",
    ] {
        let source = format!("def run(value):\n    {read}\n");
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );

        assert!(
            result.results.is_empty(),
            "incomplete scope must not yield an unused finding for {read}: {:?}",
            result.results
        );
        assert!(
            result.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete
                    && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
            }),
            "incomplete scope must retain a typed diagnostic for {read}: {:?}",
            result.diagnostics
        );
    }

    let source = concat!(
        "def complete(value):\n",
        "    pass\n",
        "def dynamic(hidden):\n",
        "    locals()\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(matches!(
        result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
    let unused = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::Binding { value } => value.name.as_str(),
            other => panic!("unused-parameter difference returns bindings: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(unused, ["value"]);
}

#[test]
fn python_parameter_kind_matches_exact_formal_name_nodes() {
    let source = concat!(
        "def call(\n",
        "    bare,\n",
        "    typed: T,\n",
        "    default=1,\n",
        "    typed_default: U = 2,\n",
        "    *args: V,\n",
        "    required_kw,\n",
        "    **kwargs: W,\n",
        "):\n",
        "    pass\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "parameter" },
        "result_detail": "full"
    }))
    .expect("parameter kind query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let names = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => {
                assert_eq!(value.kind, "parameter");
                let range = value.node_range.as_ref().expect("exact parameter range");
                assert_eq!(range.start_line, range.end_line);
                let line_index = range.start_line.checked_sub(1).expect("one-based line");
                let start = range.start_column.checked_sub(1).expect("one-based column");
                let end = range.end_column.checked_sub(1).expect("one-based column");
                source
                    .lines()
                    .nth(line_index)
                    .expect("parameter source line")
                    .get(start..end)
                    .expect("parameter columns select source text")
                    .to_owned()
            }
            other => panic!("parameter returns structural matches: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "bare",
            "typed",
            "default",
            "typed_default",
            "args",
            "required_kw",
            "kwargs"
        ]
    );

    let signature_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "function", "name": "call" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callable_signature" },
            { "op": "signature_parameters" }
        ]
    }))
    .expect("ordered signature parameter query");
    let signature_result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &signature_query,
    );
    let parameters = signature_result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::SignatureParameter { value } => {
                (value.parameter_index, value.label.as_str())
            }
            other => panic!("signature_parameters returns formal rows: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        parameters,
        [
            (0, "bare"),
            (1, "typed"),
            (2, "default"),
            (3, "typed_default"),
            (4, "args"),
            (5, "required_kw"),
            (6, "kwargs")
        ]
    );
}

#[test]
fn python_all_exports_are_queryable_and_dynamic_surfaces_stay_incomplete() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "exports.py",
            "__all__ = [\"visible\", \"missing\"]\ndef visible(): pass\n",
        )
        .file("dynamic.py", "__all__ = [\"known\", *computed]\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source("(language \"python\" (exports :form python_all))")
        .expect("Python export query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::MaterializationDerivationIncomplete]
        }
    );
    let mut exports = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::Export { value } => (
                value.path.as_str(),
                value.form,
                value.exported_name.as_str(),
                value
                    .local_definition
                    .as_ref()
                    .map(|definition| definition.status()),
            ),
            other => panic!("exports returns export rows: {other:?}"),
        })
        .collect::<Vec<_>>();
    exports.sort_unstable();
    assert_eq!(
        exports,
        [
            ("dynamic.py", "python_all", "known", Some("undefined")),
            ("exports.py", "python_all", "missing", Some("undefined")),
            ("exports.py", "python_all", "visible", Some("defined")),
        ]
    );
    let visible = result.results.iter().find_map(|item| match &item.value {
        CodeQueryResultValue::Export { value } if value.exported_name == "visible" => Some(value),
        _ => None,
    });
    assert!(matches!(
        visible.and_then(|value| value.local_definition.as_ref()),
        Some(brokk_bifrost_rql::structural::CodeQueryExportLocalDefinition::Defined { binding })
            if binding.name == "visible"
                && binding.kind == "function"
                && binding.range.start_line == 2
                && binding.range.start_column == 5
    ));
}

#[test]
fn where_globs_match_slash_normalized_paths() {
    let query = CodeQuery::from_json(&json!({
        "where": ["src/**/*.py"],
        "match": { "kind": "call" }
    }))
    .expect("query should parse");
    let file = ProjectFile::new(
        std::env::temp_dir().join("bifrost-structural-search"),
        std::path::PathBuf::from("src\\app.py"),
    );

    assert!(file_matches_globs(&file, query.seed().unwrap()));
}

#[test]
fn retained_execution_snapshot_wins_over_a_later_changed_source() {
    let directory = tempfile::tempdir().unwrap();
    let analyzer = JavascriptAnalyzer::from_project(TestProject::new(
        directory.path().to_path_buf(),
        Language::JavaScript,
    ));
    let file = ProjectFile::new(
        std::env::temp_dir().join("bifrost-retained-query-snapshot"),
        PathBuf::from("src/app.rs"),
    );
    let original = "fn before() {}\n";
    let changed = "// shifted\nfn before() {}\n";
    let loads = Cell::new(0);
    let mut cache = PipelineRenderCache::default();

    let coordinates = cache
        .coordinates_for(&analyzer, &file, || {
            loads.set(loads.get() + 1);
            Some(if loads.get() == 1 { original } else { changed }.to_string())
        })
        .expect("retained coordinates");

    assert_eq!(coordinates.source, original);
    let digest = source_slice_sha256(coordinates.source.as_str(), &(0..2));
    let coordinates = cache
        .coordinates_for(&analyzer, &file, || {
            loads.set(loads.get() + 1);
            Some(changed.to_string())
        })
        .expect("retained coordinates");
    assert_eq!(coordinates.source, original);
    assert_eq!(
        digest,
        source_slice_sha256(coordinates.source.as_str(), &(0..2))
    );
    assert_eq!(loads.get(), 1, "a later source loader must not run");
    assert!(
        !cache.retain_source_snapshot(&file, changed),
        "conflicting snapshots must not be treated as exact evidence"
    );
}

#[test]
fn conflicting_held_snapshots_are_negative_cached_and_typed_incomplete() {
    let analyzer = crate::analyzer::MultiAnalyzer::default();
    let file = ProjectFile::new(
        std::env::temp_dir().join("bifrost-conflicting-query-snapshot"),
        PathBuf::from("src/app.ts"),
    );
    let mut cache = PipelineRenderCache::default();
    let mut diagnostics = Vec::new();

    assert!(!retain_held_source_snapshot(
        &analyzer,
        &mut cache,
        &file,
        "fn before() {}\n",
        Language::Rust,
        Vec::new(),
        &mut diagnostics,
    ));
    assert!(retain_held_source_snapshot(
        &analyzer,
        &mut cache,
        &file,
        "// shifted\nfn before() {}\n",
        Language::Rust,
        vec![1],
        &mut diagnostics,
    ));
    assert!(cache.source_snapshot(&analyzer, &file).is_none());
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::SemanticResultsOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(diagnostics[0].branch == vec![1]);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn sequential_profile_replays_a_shared_seed_for_each_union_branch() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("export function shared() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({ "match": { "kind": "function", "name": "shared" } });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch],
        "limit": 10
    }))
    .expect("query");

    let detailed = execute_internal(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        true,
    );

    assert_eq!(detailed.result.results.len(), 1);
    let profile = detailed
        .profile
        .expect("valid execution should be profiled");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(
        profile
            .operators
            .iter()
            .filter(|observation| {
                observation.operator == PhysicalQueryOperator::SequentialUnion
            })
            .count(),
        1
    );
    assert_eq!(
        profile
            .operators
            .iter()
            .filter(|observation| observation.operator == PhysicalQueryOperator::Limit)
            .count(),
        1
    );
    let seed_observations = profile
        .operators
        .iter()
        .filter(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
        .collect::<Vec<_>>();
    assert_eq!(seed_observations.len(), 2);
    assert_eq!(seed_observations[0].node, seed_observations[1].node);
    assert_eq!(seed_observations[0].branch, vec![0]);
    assert_eq!(seed_observations[1].branch, vec![1]);
    assert!(
        seed_observations
            .iter()
            .all(|observation| { observation.disposition == QueryOperatorDisposition::Completed })
    );
    assert_eq!(seed_observations[0].cache.seed_result.lookups, 1);
    assert_eq!(seed_observations[0].cache.seed_result.misses, 1);
    assert_eq!(seed_observations[0].cache.seed_result.builds, 1);
    assert_eq!(seed_observations[0].cache.seed_result.complete_builds, 1);
    assert_eq!(seed_observations[1].cache.seed_result.lookups, 1);
    assert_eq!(seed_observations[1].cache.seed_result.hits, 1);
    assert_eq!(seed_observations[1].cache.seed_result.complete_hits, 1);
    assert_eq!(seed_observations[1].cache.seed_result.replayed_items, 1);
    assert_eq!(profile.cache.seed_result.lookups, 2);
    assert_eq!(profile.cache.seed_result.misses, 1);
    assert_eq!(profile.cache.seed_result.hits, 1);
    assert_eq!(profile.cache.seed_result.complete_builds, 1);
    assert_eq!(profile.cache.seed_result.complete_hits, 1);
    let union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
        .expect("union observation");
    assert_eq!(union.input_rows, 2);
    assert_eq!(union.output_rows, 1);
    assert_eq!(union.rows_discarded, Some(1));
    assert!(union.temporary_capacity_bytes_lower_bound > 0);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn parallel_seed_union_matches_serial_fair_budget_roll_forward() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("left.ts"))
        .write("export const left = 1;\n")
        .expect("write left source");
    ProjectFile::new(root.clone(), PathBuf::from("right.ts"))
        .write(
            "export function first() {}\nexport function second() {}\nexport function third() {}\n",
        )
        .expect("write right source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            {
                "where": ["left.ts"],
                "match": { "kind": "function", "name": "missing" }
            },
            {
                "where": ["right.ts"],
                "match": { "kind": "function" }
            }
        ],
        "limit": 10
    }))
    .expect("query");
    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 3,
        ..CodeQueryExecutionLimits::default()
    };

    let sequential = execute_code_query_with_union_strategy(
        &analyzer,
        &query,
        limits,
        UnionExecutionStrategy::Sequential,
        true,
    );
    let parallel = execute_code_query_with_union_strategy(
        &analyzer,
        &query,
        limits,
        UnionExecutionStrategy::Parallel,
        true,
    );

    assert_eq!(
        serde_json::to_value(&parallel.result).expect("parallel result serializes"),
        serde_json::to_value(&sequential.result).expect("sequential result serializes")
    );
    assert_eq!(parallel.work, sequential.work);
    assert_eq!(parallel.evidence, sequential.evidence);
    assert!(
        !parallel.result.truncated,
        "{:?}",
        parallel.result.diagnostics
    );
    assert_eq!(parallel.result.results.len(), 3);

    let profile = parallel.profile.expect("parallel profile");
    assert_eq!(profile.format, "bifrost_code_query_execution_profile/v4");
    assert_eq!(profile.scheduler.worker_limit, 2);
    assert_eq!(profile.scheduler.tasks_enqueued, 2);
    assert_eq!(profile.scheduler.tasks_completed, 2);
    assert!((1..=2).contains(&profile.peak_concurrency));
    assert_eq!(profile.peak_concurrency, profile.scheduler.peak_concurrency);
    let parallel_union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::ParallelUnion)
        .expect("parallel union observation");
    assert!(parallel_union.dependency_wait_ns > 0);
    assert!(parallel_union.scheduling_overhead_ns > 0);
    assert_eq!(
        parallel_union.total_elapsed_ns,
        parallel_union
            .elapsed_ns
            .saturating_add(parallel_union.dependency_wait_ns)
    );
    let operator_work = profile
        .operators
        .iter()
        .fold(QueryOperatorWorkProfile::default(), |work, observation| {
            work.saturating_add(observation.work)
        });
    assert_eq!(operator_work, profile.execution_work);
    assert!(
        sequential
            .profile
            .expect("sequential profile")
            .operators
            .iter()
            .any(|observation| { observation.operator == PhysicalQueryOperator::SequentialUnion })
    );
}

#[test]
fn parallel_seed_union_matches_serial_budget_exhaustion() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("left.ts"))
        .write("export function left_one() {}\nexport function left_two() {}\n")
        .expect("write left source");
    ProjectFile::new(root.clone(), PathBuf::from("right.ts"))
        .write("export function right_one() {}\nexport function right_two() {}\n")
        .expect("write right source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "where": ["left.ts"], "match": { "kind": "function" } },
            { "where": ["right.ts"], "match": { "kind": "function" } }
        ]
    }))
    .expect("query");
    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 3,
        ..CodeQueryExecutionLimits::default()
    };

    let sequential = execute_code_query_with_union_strategy(
        &analyzer,
        &query,
        limits,
        UnionExecutionStrategy::Sequential,
        false,
    );
    let parallel = execute_code_query_with_union_strategy(
        &analyzer,
        &query,
        limits,
        UnionExecutionStrategy::Parallel,
        false,
    );

    assert_eq!(
        serde_json::to_value(&parallel.result).expect("parallel result serializes"),
        serde_json::to_value(&sequential.result).expect("sequential result serializes")
    );
    assert_eq!(parallel.work, sequential.work);
    assert_eq!(parallel.evidence, sequential.evidence);
    assert!(parallel.result.truncated);
    assert_eq!(parallel.result.results.len(), 3);
}

fn shared_scan_union_fixture() -> (
    inline_project::BuiltInlineTestProject,
    TypescriptAnalyzer,
    CodeQuery,
    CodeQueryExecutionLimits,
    DetailedCodeQueryResult,
) {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "export function first() {}\nexport class Second {}\n",
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(
        project.root().to_path_buf(),
        Language::TypeScript,
    ));
    // Kind-only patterns provide no posting terms, so both branches take
    // Scan access over the same file with distinct seed cache keys.
    let probe = CodeQuery::from_json(&json!({ "match": { "kind": "function" }, "limit": 10 }))
        .expect("probe query");
    let probe_run = execute_internal(
        &analyzer,
        None,
        &probe,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
    );
    assert!(!probe_run.result.truncated);
    assert_eq!(probe_run.result.results.len(), 1);
    let scan_facts = usize::try_from(probe_run.work.fact_nodes).expect("facts fit usize");
    assert!(scan_facts > 0);

    let union = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function" } },
            { "match": { "kind": "class" } }
        ],
        "limit": 10
    }))
    .expect("union query");
    // The fair split gives the first branch ceil(max/2) = one full scan;
    // without cross-branch sharing the second branch's identical full-file
    // charge pushes the total to twice the extraction and exhausts this cap.
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: scan_facts.saturating_mul(2).saturating_sub(1),
        ..CodeQueryExecutionLimits::default()
    };

    (project, analyzer, union, limits, probe_run)
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn sequential_union_charges_shared_scan_file_extraction_once() {
    let (_project, analyzer, union, limits, probe_run) = shared_scan_union_fixture();
    assert!(!probe_run.result.truncated);
    assert_eq!(probe_run.result.results.len(), 1);
    let detailed = execute_internal(&analyzer, None, &union, limits, None, None, false);

    assert!(
        !detailed.result.truncated,
        "{:?}",
        detailed.result.diagnostics
    );
    assert!(!detailed.result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
    }));
    assert_eq!(detailed.result.results.len(), 2);
    assert_eq!(detailed.work.fact_nodes, probe_run.work.fact_nodes);
    assert_eq!(detailed.work.scanned_files, probe_run.work.scanned_files);
    assert_eq!(
        detailed.work.scanned_source_bytes,
        probe_run.work.scanned_source_bytes
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn sequential_union_still_charges_distinct_files_fully() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("left.ts"))
        .write("export function left() {}\n")
        .expect("write left source");
    ProjectFile::new(root.clone(), PathBuf::from("right.ts"))
        .write("export function right_one() {}\nexport function right_two() {}\n")
        .expect("write right source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut probe_work = CodeQueryExecutionWork::default();
    for file in ["left.ts", "right.ts"] {
        let probe = CodeQuery::from_json(&json!({
            "where": [file],
            "match": { "kind": "function" },
            "limit": 10
        }))
        .expect("probe query");
        let probe_run = execute_internal(
            &analyzer,
            None,
            &probe,
            CodeQueryExecutionLimits::default(),
            None,
            None,
            false,
        );
        assert!(!probe_run.result.truncated);
        probe_work = probe_work.saturating_add(probe_run.work);
    }

    let union = CodeQuery::from_json(&json!({
        "union": [
            { "where": ["left.ts"], "match": { "kind": "function" } },
            { "where": ["right.ts"], "match": { "kind": "function" } }
        ],
        "limit": 10
    }))
    .expect("union query");
    let detailed = execute_internal(
        &analyzer,
        None,
        &union,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
    );

    assert!(!detailed.result.truncated);
    assert_eq!(detailed.result.results.len(), 3);
    // Genuinely distinct scans keep accumulating: sharing only applies to
    // files an earlier seed scan in the same execution already charged.
    assert_eq!(detailed.work.scanned_files, probe_work.scanned_files);
    assert_eq!(
        detailed.work.scanned_source_bytes,
        probe_work.scanned_source_bytes
    );
    assert_eq!(detailed.work.fact_nodes, probe_work.fact_nodes);
}

#[test]
fn parallel_seed_union_matches_serial_shared_scan_charges() {
    let (_project, analyzer, union, limits, probe_run) = shared_scan_union_fixture();

    let sequential = execute_code_query_with_union_strategy(
        &analyzer,
        &union,
        limits,
        UnionExecutionStrategy::Sequential,
        false,
    );
    let parallel = execute_code_query_with_union_strategy(
        &analyzer,
        &union,
        limits,
        UnionExecutionStrategy::Parallel,
        false,
    );

    assert_eq!(
        serde_json::to_value(&parallel.result).expect("parallel result serializes"),
        serde_json::to_value(&sequential.result).expect("sequential result serializes")
    );
    assert_eq!(parallel.work, sequential.work);
    assert_eq!(parallel.evidence, sequential.evidence);
    assert!(
        !parallel.result.truncated,
        "{:?}",
        parallel.result.diagnostics
    );
    assert_eq!(parallel.result.results.len(), 2);
    assert_eq!(parallel.work.fact_nodes, probe_run.work.fact_nodes);
    assert_eq!(parallel.work.scanned_files, probe_run.work.scanned_files);
}

#[test]
fn absolute_exact_globs_cannot_panic_parallel_selection() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("inside.ts"))
        .write("export function inside() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

    for (left, right) in [
        ("/outside/left.ts", "/outside/right.ts"),
        ("C:/outside/left.ts", "D:/outside/right.ts"),
    ] {
        let query = CodeQuery::from_json(&json!({
            "union": [
                {
                    "where": [left],
                    "languages": ["typescript"],
                    "match": { "kind": "function" }
                },
                {
                    "where": [right],
                    "languages": ["typescript"],
                    "match": { "kind": "function" }
                }
            ]
        }))
        .expect("absolute globs remain valid query syntax");
        let profile = execute_internal(
            &analyzer,
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            None,
            true,
        )
        .profile
        .expect("profile");
        assert!(
            profile
                .operators
                .iter()
                .any(|operator| { operator.operator == PhysicalQueryOperator::SequentialUnion })
        );
        assert!(
            !profile
                .operators
                .iter()
                .any(|operator| { operator.operator == PhysicalQueryOperator::ParallelUnion })
        );
    }
}

#[test]
fn cancellation_bearing_parallel_union_runs_cancellation_safe_tasks() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("left.ts"))
        .write("export function left() {}\n")
        .expect("write left source");
    ProjectFile::new(root.clone(), PathBuf::from("right.ts"))
        .write("export function right() {}\n")
        .expect("write right source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "where": ["left.ts"], "match": { "kind": "function" } },
            { "where": ["right.ts"], "match": { "kind": "function" } }
        ]
    }))
    .expect("query");
    let cancellation = CancellationToken::cancel_after_checks_for_test(2);

    let detailed = execute_internal_with_strategy(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        Some(&cancellation),
        None,
        true,
        UnionExecutionStrategy::Parallel,
        2,
        StructuralAccessMode::Auto,
        None,
    );

    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Cancelled);
    let profile = detailed.profile.expect("cancelled execution profile");
    assert!(
        profile
            .operators
            .iter()
            .any(|operator| { operator.operator == PhysicalQueryOperator::ParallelUnion })
    );
    assert_eq!(profile.scheduler.tasks_started, 2);
    assert_eq!(profile.scheduler.tasks_completed, 2);
    assert!(profile.scheduler.tasks_observed_cancelled_before_start > 0);
}

#[test]
fn fair_budget_wait_is_released_by_cancellation_and_worker_failure() {
    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 1,
        ..CodeQueryExecutionLimits::default()
    };
    let projected = CodeQueryExecutionBudget {
        pipeline_rows: 1,
        ..CodeQueryExecutionBudget::default()
    };

    let cancellation = CancellationToken::default();
    let coordinator = FairSeedBudgetCoordinator::new(
        CodeQueryExecutionBudget::default(),
        limits,
        2,
        Some(&cancellation),
    );
    let lease = coordinator.lease(1);
    let cancelled_waiter = std::thread::spawn(move || lease.admit(projected));
    let deadline = Instant::now() + Duration::from_secs(1);
    while coordinator.waiting_branches() == 0 {
        assert!(
            Instant::now() < deadline,
            "budget branch did not start waiting"
        );
        std::thread::yield_now();
    }
    cancellation.cancel();
    assert!(matches!(
        cancelled_waiter.join().expect("cancelled waiter joins"),
        FairSeedBudgetAdmission::Cancelled
    ));

    let coordinator =
        FairSeedBudgetCoordinator::new(CodeQueryExecutionBudget::default(), limits, 2, None);
    let lease = coordinator.lease(1);
    let failed_waiter = std::thread::spawn(move || lease.admit(projected));
    let deadline = Instant::now() + Duration::from_secs(1);
    while coordinator.waiting_branches() == 0 {
        assert!(
            Instant::now() < deadline,
            "budget branch did not start waiting"
        );
        std::thread::yield_now();
    }
    coordinator.fail();
    assert!(matches!(
        failed_waiter.join().expect("failed waiter joins"),
        FairSeedBudgetAdmission::Cancelled
    ));
}

#[test]
fn profile_marks_truncated_seed_materialization_and_replay_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("function first() {}\nfunction second() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({ "match": { "kind": "function" } });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch]
    }))
    .expect("query");

    let detailed = execute_internal(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            max_pipeline_rows: 2,
            ..CodeQueryExecutionLimits::default()
        },
        None,
        None,
        true,
    );

    assert!(detailed.result.truncated);
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.seed_result.lookups, 2);
    assert_eq!(profile.cache.seed_result.misses, 1);
    assert_eq!(profile.cache.seed_result.incomplete_builds, 1);
    assert_eq!(profile.cache.seed_result.hits, 1);
    assert_eq!(profile.cache.seed_result.incomplete_hits, 1);
    let seed_observations = profile
        .operators
        .iter()
        .filter(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
        .collect::<Vec<_>>();
    assert_eq!(seed_observations.len(), 2);
    assert_eq!(seed_observations[0].cache.seed_result.incomplete_builds, 1);
    assert_eq!(seed_observations[1].cache.seed_result.incomplete_hits, 1);
    assert!(seed_observations.iter().all(|observation| {
        observation
            .terminations
            .contains(&QueryOperatorTermination::PipelineBudget)
    }));
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#2779: a root cap must not make an incomplete seed reusable as complete"
)]
fn profile_does_not_call_a_terminal_cap_seed_cache_complete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("function first() {}\nfunction second() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "function" },
        "limit": 1
    }))
    .expect("query");

    let detailed =
        execute_code_query_profiled(&analyzer, &query, CodeQueryExecutionLimits::default());

    assert_eq!(detailed.result.results.len(), 1);
    assert!(detailed.result.truncated);
    // #2779 regression: the seed's own `TerminalCap` termination (below) is
    // an internal signal for the `Limit` operator above it, not a second
    // truncation to report -- the query must carry exactly the one
    // diagnostic the `Limit` operator names.
    assert_eq!(
        detailed
            .result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ResultLimitReached)
            .count(),
        1,
        "exactly one truncation diagnostic, no double report: {:?}",
        detailed.result.diagnostics
    );
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.seed_result.misses, 1);
    assert_eq!(profile.cache.seed_result.incomplete_builds, 1);
    assert_eq!(profile.cache.seed_result.complete_builds, 0);
    let seed = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
        .expect("seed observation");
    assert_eq!(seed.cache.seed_result.incomplete_builds, 1);
    assert_eq!(
        seed.terminations,
        vec![QueryOperatorTermination::TerminalCap]
    );
    let limit = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::Limit)
        .expect("limit observation");
    assert_eq!(
        limit.terminations,
        vec![QueryOperatorTermination::ResultLimit]
    );
}

#[derive(Clone)]
struct ImportUnsupportedAnalyzer {
    inner: PhpAnalyzer,
}

impl CodeUnitIndex for ImportUnsupportedAnalyzer {
    fn project(&self) -> &dyn crate::analyzer::Project {
        CodeUnitIndex::project(&self.inner)
    }

    fn languages(&self) -> BTreeSet<Language> {
        CodeUnitIndex::languages(&self.inner)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        CodeUnitIndex::all_declarations(&self.inner)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        CodeUnitIndex::search_definitions(&self.inner, pattern, auto_quote)
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        CodeUnitIndex::enclosing_code_unit(&self.inner, file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        CodeUnitIndex::enclosing_code_unit_for_lines(&self.inner, file, start_line, end_line)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        CodeUnitIndex::get_skeleton(&self.inner, code_unit)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        CodeUnitIndex::get_skeleton_header(&self.inner, code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        CodeUnitIndex::get_source(&self.inner, code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        CodeUnitIndex::get_sources(&self.inner, code_unit, include_comments)
    }
}

impl IAnalyzer for ImportUnsupportedAnalyzer {
    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            inner: IAnalyzer::update(&self.inner, changed_files),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: IAnalyzer::update_all(&self.inner),
        }
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        IAnalyzer::extract_call_receiver(&self.inner, reference)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        IAnalyzer::is_access_expression(&self.inner, file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        IAnalyzer::find_nearest_declaration(&self.inner, file, start_byte, end_byte, ident)
    }

    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        IAnalyzer::structural_fact_providers(&self.inner)
    }
}

#[test]
fn profile_marks_unsupported_import_builds_and_replays_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.php"))
        .write("<?php\nfunction target() {}\n")
        .expect("write source");
    // Every shipped language now has an import provider. Hide PHP's provider
    // behind a test adapter while retaining its real structural facts so this
    // remains a capability-gap test instead of depending on a stale matrix.
    let analyzer = ImportUnsupportedAnalyzer {
        inner: PhpAnalyzer::from_project(TestProject::new(root, Language::Php)),
    };
    assert!(analyzer.import_analysis_provider().is_none());
    let imports = json!({
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
    });
    let importers = json!({
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    });
    let query = CodeQuery::from_json(&json!({
        "union": [imports.clone(), imports, importers.clone(), importers]
    }))
    .expect("query");

    let detailed =
        execute_code_query_profiled(&analyzer, &query, CodeQueryExecutionLimits::default());

    assert!(matches!(
        detailed.result.completion(),
        CodeQueryCompletion::Incomplete { codes }
            if codes.contains(&CodeQueryDiagnosticCode::UnsupportedImportAnalysis)
    ));
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.import_forward.lookups, 2);
    assert_eq!(profile.cache.import_forward.misses, 1);
    assert_eq!(profile.cache.import_forward.incomplete_builds, 1);
    assert_eq!(profile.cache.import_forward.complete_builds, 0);
    assert_eq!(profile.cache.import_forward.hits, 1);
    assert_eq!(profile.cache.import_forward.incomplete_hits, 1);
    assert_eq!(profile.cache.import_forward.complete_hits, 0);
    assert_eq!(profile.cache.import_reverse.lookups, 2);
    assert_eq!(profile.cache.import_reverse.misses, 1);
    assert_eq!(profile.cache.import_reverse.incomplete_builds, 1);
    assert_eq!(profile.cache.import_reverse.complete_builds, 0);
    assert_eq!(profile.cache.import_reverse.hits, 1);
    assert_eq!(profile.cache.import_reverse.incomplete_hits, 1);
    assert_eq!(profile.cache.import_reverse.complete_hits, 0);
    assert_eq!(profile.cache.direct_import_topology.lookups, 0);
    assert_eq!(profile.cache.direct_import_topology.misses, 0);
    assert_eq!(profile.cache.direct_import_topology.hits, 0);
    assert_eq!(profile.cache.direct_import_topology.builds, 0);
    assert_eq!(profile.cache.direct_import_topology.complete_builds, 0);
    assert_eq!(profile.cache.direct_import_topology.fallbacks, 0);
    assert_eq!(
        profile
            .operators
            .iter()
            .filter(|observation| {
                observation.operator == PhysicalQueryOperator::PipelineStep
                    && observation
                        .terminations
                        .contains(&QueryOperatorTermination::UnsupportedAnalysis)
            })
            .count(),
        4
    );
}

#[test]
fn profile_preserves_incomplete_reference_cache_state_for_a_sibling() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let source =
        "export function target() {}\nfunction one() { target(); }\nfunction two() { target(); }\n";
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "references_of" },
            { "op": "file_of" }
        ]
    });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch]
    }))
    .expect("query");

    let detailed = execute_internal(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: source.len().saturating_mul(2).saturating_add(4),
            ..CodeQueryExecutionLimits::default()
        },
        None,
        None,
        true,
    );

    assert!(detailed.result.truncated);
    assert!(
        detailed
            .result
            .results
            .iter()
            .all(|item| { !matches!(item.value, CodeQueryResultValue::File { .. }) })
    );
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.inbound_reference.lookups, 2);
    assert_eq!(profile.cache.inbound_reference.misses, 1);
    assert_eq!(profile.cache.inbound_reference.incomplete_builds, 1);
    assert_eq!(profile.cache.inbound_reference.hits, 1);
    assert_eq!(profile.cache.inbound_reference.incomplete_hits, 1);
    let reference_steps = profile
        .operators
        .iter()
        .filter(|observation| observation.cache.inbound_reference.lookups > 0)
        .collect::<Vec<_>>();
    assert_eq!(reference_steps.len(), 2);
    assert!(
        reference_steps
            .iter()
            .all(|observation| observation.result_truncated)
    );
    assert!(
        reference_steps[0]
            .terminations
            .contains(&QueryOperatorTermination::AnalysisLimit)
    );
    assert!(
        reference_steps[1]
            .terminations
            .contains(&QueryOperatorTermination::AnalysisIncomplete),
        "sibling terminations: {:?}",
        reference_steps[1].terminations
    );
    assert_eq!(
        profile
            .operators
            .iter()
            .filter(|observation| {
                observation
                    .terminations
                    .contains(&QueryOperatorTermination::DependencyPipelineHalted)
            })
            .count(),
        2,
        "neither branch may continue a known-incomplete reference layer"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn profile_attributes_root_limit_probe_to_the_limit_operator() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("function one() {}\nfunction two() {}\nfunction three() {}\nfunction four() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({ "match": { "kind": "function" } });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch],
        "limit": 2
    }))
    .expect("query");

    let detailed = execute_internal(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        true,
    );

    assert_eq!(detailed.result.results.len(), 2);
    assert!(detailed.result.truncated);
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    let limit = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::Limit)
        .expect("limit observation");
    assert!(limit.branch.is_empty());
    assert_eq!(limit.disposition, QueryOperatorDisposition::Completed);
    assert_eq!(limit.input_rows, 3);
    assert_eq!(limit.output_rows, 2);
    assert!(limit.operator_truncated);
    assert!(limit.result_truncated);
    assert!(!limit.result_cancelled);
    assert_eq!(limit.rows_visited, 3);
    assert_eq!(limit.rows_discarded, Some(1));
    assert_eq!(
        limit.terminations,
        vec![QueryOperatorTermination::ResultLimit]
    );
    let union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
        .expect("union observation");
    assert_eq!(union.input_rows, 8);
    assert_eq!(union.output_rows, 3);
    assert!(union.operator_truncated);
    assert!(!union.result_truncated);
    assert_eq!(union.rows_visited, 8);
    assert_eq!(union.rows_discarded, Some(5));
    assert!(union.temporary_capacity_bytes_lower_bound > 0);
    assert_eq!(
        union.terminations,
        vec![QueryOperatorTermination::TerminalCap]
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn skipped_set_profile_forwards_cancellation_safe_partial_cardinality() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(
            "function one() { sink(); }\nfunction two() { sink(); }\nfunction three() { sink(); }\n",
        )
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "enclosing_decl" }]
    });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch]
    }))
    .expect("query");

    let detailed = (2..256)
        .find_map(|checks| {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let detailed = execute_internal(
                &analyzer,
                None,
                &query,
                CodeQueryExecutionLimits::default(),
                Some(&cancellation),
                None,
                true,
            );
            let profile = detailed.profile.as_ref()?;
            let union = profile.operators.iter().find(|observation| {
                observation.operator == PhysicalQueryOperator::SequentialUnion
            })?;
            let limit = profile
                .operators
                .iter()
                .find(|observation| observation.operator == PhysicalQueryOperator::Limit)?;
            (union.disposition == QueryOperatorDisposition::Skipped
                && union.output_rows > 0
                && union.output_rows == limit.input_rows)
                .then_some(detailed)
        })
        .expect("cancellation should interrupt a final branch step after a partial row");

    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    let union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
        .expect("union observation");
    let limit = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::Limit)
        .expect("limit observation");
    assert_eq!(union.disposition, QueryOperatorDisposition::Skipped);
    assert!(union.result_cancelled);
    assert_eq!(union.output_rows, limit.input_rows);
    assert!(limit.result_cancelled);
    assert_eq!(
        union.terminations,
        vec![QueryOperatorTermination::DependencyCancelled]
    );
    assert_eq!(
        limit.terminations,
        vec![QueryOperatorTermination::DependencyCancelled]
    );
    assert!(profile.operators.iter().any(|observation| {
        observation.disposition == QueryOperatorDisposition::Cancelled
            && observation
                .terminations
                .contains(&QueryOperatorTermination::CancellationDuringWork)
    }));
    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Cancelled);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6418: empty language arms reserved pipeline rows from the only populated arm"
)]
fn sequential_union_pipeline_budget_ignores_absent_languages() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "main.rs",
            "fn first() {} fn second() {} fn third() {} fn fourth() {}",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [functions_in("python"), functions_in("rust"), functions_in("ruby")],
        "limit": 100
    }))
    .expect("union query");
    let detailed = execute_code_query_with_union_strategy(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            // Leave one row for the existing exhausted-budget preflight on
            // later empty arms; this test isolates the fair divisor.
            max_pipeline_rows: 5,
            ..CodeQueryExecutionLimits::default()
        },
        UnionExecutionStrategy::Sequential,
        true,
    );
    assert!(
        !detailed.result.truncated,
        "{:?}",
        detailed.result.diagnostics
    );
    assert_eq!(detailed.result.results.len(), 4);
    assert_eq!(detailed.work.pipeline_rows, 4);
}

#[test]
fn sequential_union_pipeline_budget_keeps_populated_arms_fair() {
    let project = InlineTestProject::new()
        .file(
            "main.rs",
            "fn first() {} fn second() {} fn third() {} fn fourth() {}",
        )
        .file(
            "main.py",
            "def first(): pass\ndef second(): pass\ndef third(): pass\ndef fourth(): pass\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    // A language set with a populated member and an unscoped seed both
    // keep their share. File scope does not imply language scope, and an
    // applicable arm keeps its share even when its match returns no rows.
    for (second, second_rows) in [
        (
            json!({ "languages": ["python", "ruby"], "match": { "kind": "function" } }),
            2,
        ),
        (
            json!({ "where": ["main.py"], "match": { "kind": "function" } }),
            2,
        ),
        (
            json!({ "languages": ["python"], "match": { "kind": "function", "name": "missing" } }),
            0,
        ),
    ] {
        let query = CodeQuery::from_json(&json!({
            "union": [functions_in("rust"), second],
            "limit": 100
        }))
        .expect("union query");
        let detailed = execute_code_query_with_union_strategy(
            workspace.analyzer(),
            &query,
            CodeQueryExecutionLimits {
                max_pipeline_rows: 4,
                ..CodeQueryExecutionLimits::default()
            },
            UnionExecutionStrategy::Sequential,
            true,
        );
        assert!(detailed.result.truncated);
        assert_eq!(
            detailed.work.pipeline_rows,
            u64::try_from(2 + second_rows).expect("row count fits u64")
        );
        for branch in [0, 1] {
            assert_eq!(
                detailed
                    .result
                    .results
                    .iter()
                    .filter(|row| {
                        row.provenance
                            .iter()
                            .any(|trace| trace.branch.first() == Some(&branch))
                    })
                    .count(),
                if branch == 0 { 2 } else { second_rows },
                "each applicable arm retains its half share: {:?}",
                detailed.result
            );
        }
    }
}

/// Two-language workspace whose volume is concentrated in the first-listed
/// union branch: the Rust files hold nearly all of the facts, the single
/// Python file almost none.
fn skewed_two_language_workspace(root: &std::path::Path) {
    for file in 0..8 {
        let mut source = String::new();
        for function in 0..12 {
            source.push_str(&format!(
                "pub fn rust_{file}_{function}(left: usize, right: usize) -> usize {{\n    let total = left.saturating_add(right);\n    total.saturating_mul({function} + 1)\n}}\n"
            ));
        }
        ProjectFile::new(root.to_path_buf(), PathBuf::from(format!("rust_{file}.rs")))
            .write(&source)
            .expect("write Rust source");
    }
    ProjectFile::new(root.to_path_buf(), PathBuf::from("tiny.py"))
        .write("def python_only():\n    return 1\n")
        .expect("write Python source");
}

fn two_language_analyzer(root: &std::path::Path) -> MultiAnalyzer {
    MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Rust,
            AnalyzerDelegate::new(RustAnalyzer::from_project(TestProject::new(
                root.to_path_buf(),
                Language::Rust,
            ))),
        ),
        (
            Language::Python,
            AnalyzerDelegate::new(PythonAnalyzer::from_project(TestProject::new(
                root.to_path_buf(),
                Language::Python,
            ))),
        ),
    ]))
}

fn functions_in(language: &str) -> serde_json::Value {
    json!({ "languages": [language], "match": { "kind": "function" } })
}

/// Result identity without provenance: a branch's rows carry the union branch
/// index, which a single-branch query has no reason to report.
fn result_identities(result: &CodeQueryResult) -> Vec<serde_json::Value> {
    let mut values = result
        .results
        .iter()
        .map(|item| {
            let mut value = serde_json::to_value(item).expect("result item serializes");
            value
                .as_object_mut()
                .expect("result item is an object")
                .remove("provenance");
            value
        })
        .collect::<Vec<_>>();
    values.sort_by_key(ToString::to_string);
    values
}

/// Scan access keeps the metered lanes proportional to the workspace; the
/// posting index an earlier query may build would charge candidates only and
/// make these budgets non-binding.
fn scan_only_run(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> DetailedCodeQueryResult {
    execute_code_query_with_access_mode(
        analyzer,
        query,
        limits,
        StructuralAccessMode::ScanOnly,
        false,
    )
    .expect("scan access is always available")
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#1766: a starved union branch needs a second chance; #1771: the policy budget must scale to the workspace"
)]
fn sequential_union_retries_a_starved_first_branch() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    skewed_two_language_workspace(&root);
    let analyzer = two_language_analyzer(&root);

    // Calibrate: the union's total fact budget is exactly what the two
    // branches cost on their own, so only the fair split can truncate.
    let mut branch_facts = Vec::new();
    let mut branch_identities = Vec::new();
    for language in ["rust", "python"] {
        let query = CodeQuery::from_json(&json!({
            "languages": [language],
            "match": { "kind": "function" },
            "limit": 1000
        }))
        .expect("branch query");
        let run = scan_only_run(&analyzer, &query, CodeQueryExecutionLimits::default());
        assert!(!run.result.truncated, "{:?}", run.result.diagnostics);
        branch_facts.push(usize::try_from(run.work.fact_nodes).expect("facts fit usize"));
        branch_identities.push(result_identities(&run.result));
    }
    let total_facts = branch_facts[0].saturating_add(branch_facts[1]);
    assert!(
        branch_facts[0] > total_facts.div_ceil(2),
        "the first branch must not fit inside its half share: {branch_facts:?}"
    );

    let union = CodeQuery::from_json(&json!({
        "union": [functions_in("rust"), functions_in("python")],
        "limit": 1000
    }))
    .expect("union query");
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: total_facts,
        ..CodeQueryExecutionLimits::default()
    };

    let detailed = scan_only_run(&analyzer, &union, limits);

    assert!(
        !detailed.result.truncated,
        "{:?}",
        detailed.result.diagnostics
    );
    assert!(
        !detailed.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
        }),
        "{:?}",
        detailed.result.diagnostics
    );
    let mut expected = branch_identities.concat();
    expected.sort_by_key(ToString::to_string);
    assert_eq!(result_identities(&detailed.result), expected);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#1771: a retry must preserve genuine workspace-budget exhaustion"
)]
fn sequential_union_retry_keeps_reporting_genuine_exhaustion() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    skewed_two_language_workspace(&root);
    let analyzer = two_language_analyzer(&root);
    let probe = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function" },
        "limit": 1000
    }))
    .expect("probe query");
    let probe_run = scan_only_run(&analyzer, &probe, CodeQueryExecutionLimits::default());
    assert!(!probe_run.result.truncated);
    let rust_facts = usize::try_from(probe_run.work.fact_nodes).expect("facts fit usize");

    let union = CodeQuery::from_json(&json!({
        "union": [functions_in("rust"), functions_in("python")],
        "limit": 1000
    }))
    .expect("union query");
    // Half of the first branch's own scan: no redistribution completes it.
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: rust_facts / 2,
        ..CodeQueryExecutionLimits::default()
    };

    let detailed = scan_only_run(&analyzer, &union, limits);

    assert!(detailed.result.truncated);
    assert!(
        detailed.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
        }),
        "{:?}",
        detailed.result.diagnostics
    );
    assert!(
        usize::try_from(detailed.work.fact_nodes).expect("facts fit usize") <= rust_facts,
        "a retry must not spend more than the branch's own uncapped scan"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn flow_state_replays_the_exact_artifact_behind_result_handles() {
    use brokk_bifrost_core::analyzer::structural::flow_state::{FlowStateAxis, StateEventClass};

    let source = r#"package main

import "os"

func inspect(path string) bool {
    info, _ := os.Stat(path)
    return info.IsDir()
}

func unrelated(input int) int {
    value := input
    return value
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", source)
        .build();
    let first_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let exact_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("main.go");
    let cancellation = CancellationToken::default();
    let mut flow_cache = super::super::flow_state::FlowStateTraversalCache::default();

    // Populate the traversal cache from a distinct analyzer allocation with
    // the same durable artifact key. This is the deterministic form of the
    // cache-pressure seam: equal keys do not make allocation-scoped handles
    // interchangeable.
    let stale_state = flow_cache.for_file(&first_workspace, &file, Some(&cancellation));
    let mut budget = SemanticBudget::default();
    let exact_outcome = exact_workspace
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("Go artifact materialization");
    let exact_artifact = exact_outcome
        .available_value()
        .cloned()
        .expect("Go artifact remains available");
    let exact_state = flow_cache.for_materialized_file(
        &exact_workspace,
        &file,
        exact_outcome.clone(),
        Some(&cancellation),
    );
    assert!(
        !Arc::ptr_eq(&stale_state, &exact_state),
        "an unbound cache entry must be replaced by exact-artifact state"
    );
    let exact_hit = flow_cache.for_materialized_file(
        &exact_workspace,
        &file,
        exact_outcome.clone(),
        Some(&cancellation),
    );
    assert!(
        Arc::ptr_eq(&exact_state, &exact_hit),
        "the same outcome and artifact allocation reuse full-file state"
    );
    let unknown_state = flow_cache.for_materialized_file(
        &exact_workspace,
        &file,
        crate::analyzer::semantic::SemanticOutcome::Unknown {
            partial: Some(Arc::clone(&exact_artifact)),
            work: exact_outcome.work(),
        },
        Some(&cancellation),
    );
    assert!(
        !Arc::ptr_eq(&exact_state, &unknown_state),
        "outcome quality remains part of cached completeness identity"
    );
    assert!(
        !unknown_state
            .completeness
            .covers(FlowStateAxis::BindingEvents),
        "an Unknown outcome cannot reuse Complete flow state"
    );

    let (exact_derivation, procedure, root, aliases) = exact_state
        .procedures
        .iter()
        .find_map(|derivation| {
            let procedure = exact_artifact.procedure_handle(derivation.procedure)?;
            derivation
                .events
                .iter()
                .filter(|event| event.event_class == StateEventClass::Establish)
                .find_map(|event| {
                    let aliases =
                        derivation.exact_local_value_alias_closure(&procedure, &[event.event]);
                    let reads_info = aliases.reads.iter().filter(|read| {
                        let site = &derivation.event(**read).site.range;
                        source.get(site.start_byte..site.end_byte) == Some("info")
                    });
                    (reads_info.count() == 1)
                        .then(|| (derivation, procedure.clone(), event.event, aliases))
                })
        })
        .expect("the os.Stat info result has one structured read");
    assert!(!aliases.proof_open);
    assert_eq!(aliases.reads.len(), 1);

    let scoped_state = flow_cache.for_materialized_procedure(
        &exact_workspace,
        &file,
        exact_outcome.clone(),
        &procedure,
        Some(&cancellation),
    );
    let [scoped_derivation] = scoped_state.procedures.as_slice() else {
        panic!("one procedure-scoped derivation is cached: {scoped_state:#?}");
    };
    assert_eq!(scoped_derivation.procedure, procedure.id());
    assert_eq!(scoped_derivation.events, exact_derivation.events);
    assert_eq!(scoped_derivation.relations, exact_derivation.relations);
    assert!(
        exact_state.procedures.len() > scoped_state.procedures.len(),
        "the full-file and procedure scopes must remain distinct"
    );
    assert!(
        !Arc::ptr_eq(&exact_state, &scoped_state),
        "the procedure cache entry must not reuse a full-file derivation"
    );
    let scoped_hit = flow_cache.for_materialized_procedure(
        &exact_workspace,
        &file,
        exact_outcome.clone(),
        &procedure,
        Some(&cancellation),
    );
    assert!(
        Arc::ptr_eq(&scoped_state, &scoped_hit),
        "the same procedure scope and artifact allocation reuse state"
    );

    let mut foreign_budget = SemanticBudget::default();
    let foreign_outcome = first_workspace
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut foreign_budget, &cancellation),
        )
        .expect("foreign Go artifact materialization");
    let foreign_procedure = foreign_outcome
        .available_value()
        .expect("foreign Go artifact remains available")
        .procedure_handle(procedure.id())
        .expect("same durable procedure exists in the foreign allocation");
    let foreign_rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        flow_cache.for_materialized_procedure(
            &exact_workspace,
            &file,
            exact_outcome,
            &foreign_procedure,
            Some(&cancellation),
        )
    }));
    assert!(
        foreign_rejected.is_err(),
        "a populated same-id cache entry cannot accept a foreign artifact handle"
    );

    let stale_derivation = stale_state
        .procedures
        .iter()
        .find(|candidate| candidate.procedure == exact_derivation.procedure)
        .expect("both allocations lower the same procedure");
    let root_site = &exact_derivation.event(root).site;
    let stale_root = stale_derivation
        .events
        .iter()
        .find(|event| {
            event.event_class == StateEventClass::Establish && event.site.range == root_site.range
        })
        .expect("both allocations lower the same result establishment");
    let stale_aliases =
        stale_derivation.exact_local_value_alias_closure(&procedure, &[stale_root.event]);
    assert!(
        stale_aliases.proof_open,
        "a same-key derivation from another allocation cannot validate exact handles"
    );
}

fn execute_conditional_result_contract_fixture(source: &str) -> CodeQueryResult {
    execute_conditional_result_contract_files(&[("main.go", source)])
}

fn execute_conditional_result_contract_files(files: &[(&str, &str)]) -> CodeQueryResult {
    execute_conditional_result_contract_files_with_operation(files, "result_contract_uses")
}

fn execute_conditional_result_contract_files_with_operation(
    files: &[(&str, &str)],
    operation: &str,
) -> CodeQueryResult {
    let mut project = InlineTestProject::with_language(Language::Go);
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-conditional-result-contract",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": {
            "source": "test:rql-conditional-result-contract",
            "revision": "reviewed"
        },
        "license": "Apache-2.0",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.conditional-result-contract",
            "activation": [{}],
            "payload": {
                "kind": "procedure_summaries",
                "summaries": [
                    {
                        "id": "os.open",
                        "target": {
                            "path": "src/os/file.go",
                            "symbol": "os.Open(name string)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "normal_result_count": 2,
                        "transfers": [],
                        "effects": [],
                        "result_contracts": [{
                            "result_ordinal": 0,
                            "condition_result_ordinal": 1,
                            "predicate": "null",
                            "result_success_predicate": "non_null",
                            "member_contracts": [
                                {
                                    "member": "Name",
                                    "parameter_count": 0,
                                    "completeness": "complete",
                                    "preconditions": [{
                                        "input": { "kind": "receiver" },
                                        "predicate": "non_null"
                                    }],
                                    "declared_effects": []
                                },
                                {
                                    "member": "Use",
                                    "parameter_count": 1,
                                    "completeness": "complete",
                                    "preconditions": [{
                                        "input": { "kind": "receiver" },
                                        "predicate": "non_null"
                                    }],
                                    "declared_effects": []
                                },
                                {
                                    "member": "UseTwo",
                                    "parameter_count": 2,
                                    "completeness": "complete",
                                    "preconditions": [{
                                        "input": { "kind": "receiver" },
                                        "predicate": "non_null"
                                    }],
                                    "declared_effects": []
                                }
                            ]
                        }]
                    },
                    {
                        "id": "errors.is",
                        "target": {
                            "path": "src/errors/wrap.go",
                            "symbol": "errors.Is(err, target error)",
                            "has_receiver": false,
                            "parameter_count": 2
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "conditional_result_refinements": [{
                            "result_ordinal": 0,
                            "outcome": false,
                            "parameter_ordinal": 0,
                            "predicate": "null",
                            "proof_effect": "does_not_establish"
                        }]
                    },
                    {
                        "id": "errors.as",
                        "target": {
                            "path": "src/errors/wrap.go",
                            "symbol": "errors.As(err error, target any)",
                            "has_receiver": false,
                            "parameter_count": 2
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "conditional_indirect_writes": [{
                            "result_ordinal": 0,
                            "outcome": true,
                            "parameter_ordinal": 1,
                            "target": "pointee"
                        }]
                    },
                    {
                        "id": "os-exec.exit-error-exit-code",
                        "target": {
                            "path": "src/os/exec/exec.go",
                            "symbol": "os/exec.ExitError.ExitCode()",
                            "has_receiver": true,
                            "parameter_count": 0
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "preconditions": [{
                            "input": { "kind": "receiver" },
                            "predicate": "non_null"
                        }]
                    },
                    {
                        "id": "require.no-error",
                        "target": {
                            "path": "require/require.go",
                            "symbol": "github.com/stretchr/testify/require.NoError(t TestingT, err error, msgAndArgs ...interface{})",
                            "has_receiver": false,
                            "variadic": true,
                            "parameter_count": 3
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "normal_return_refinements": [{
                            "parameter_ordinal": 1,
                            "predicate": "null"
                        }]
                    },
                    {
                        "id": "assert.no-error",
                        "target": {
                            "path": "assert/assertions.go",
                            "symbol": "github.com/stretchr/testify/assert.NoError(t TestingT, err error, msgAndArgs ...interface{})",
                            "has_receiver": false,
                            "variadic": true,
                            "parameter_count": 3
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "conditional_result_refinements": [
                            {
                                "result_ordinal": 0,
                                "outcome": true,
                                "parameter_ordinal": 1,
                                "predicate": "null",
                                "proof_effect": "establishes"
                            },
                            {
                                "result_ordinal": 0,
                                "outcome": false,
                                "parameter_ordinal": 1,
                                "predicate": "null",
                                "proof_effect": "does_not_establish"
                            }
                        ]
                    },
                    {
                        "id": "predicate.is-nil",
                        "target": {
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate.IsNil(value error)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "conditional_result_refinements": [{
                            "result_ordinal": 0,
                            "outcome": true,
                            "parameter_ordinal": 0,
                            "predicate": "null",
                            "proof_effect": "establishes"
                        }]
                    },
                    {
                        "id": "predicate.checked",
                        "target": {
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate.Checked(value error)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "normal_return_refinements": [{
                            "parameter_ordinal": 0,
                            "predicate": "null"
                        }]
                    },
                    {
                        "id": "consumer.require",
                        "target": {
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Require(label string, file *os.File)",
                            "has_receiver": false,
                            "parameter_count": 2
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "preconditions": [{
                            "input": { "kind": "parameter", "ordinal": 1 },
                            "predicate": "non_null"
                        }]
                    },
                    {
                        "id": "consumer.observe",
                        "target": {
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Observe(file *os.File)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "preconditions": []
                    },
                    {
                        "id": "os.file.consume",
                        "target": {
                            "path": "src/os/file.go",
                            "symbol": "os.File.Consume(file *os.File)",
                            "has_receiver": true,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "preconditions": [{
                            "input": { "kind": "parameter", "ordinal": 0 },
                            "predicate": "non_null"
                        }]
                    },
                    {
                        "id": "consumer.require-many",
                        "target": {
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.RequireMany(file *os.File, rest ...*os.File)",
                            "has_receiver": false,
                            "variadic": true,
                            "parameter_count": 2
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "preconditions": [{
                            "input": { "kind": "parameter", "ordinal": 0 },
                            "predicate": "non_null"
                        }]
                    }
                ]
            }
        }]
    }"#;
    let declaration_pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-conditional-result-contract-declarations",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": {
            "source": "test:rql-conditional-result-contract-declarations",
            "revision": "reviewed"
        },
        "license": "Apache-2.0",
        "completeness": "partial",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.conditional.declarations",
            "activation": [{}],
            "payload": {
                "kind": "declaration_facts",
                "types": [
                    {
                        "id": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                        "name": "os",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["os"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os"
                        }
                    },
                    {
                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "os.File",
                        "type_kind": "struct",
                        "visibility": "public",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "struct{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os.File"
                        }
                    },
                    {
                        "id": "type.1eef3afbc23b6c534c6d054fc877197155006d5fdbdce518890a99d07a1f85d8",
                        "name": "errors",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["errors"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "errors/errors.go",
                            "symbol": "errors"
                        }
                    },
                    {
                        "id": "type.66dc4abf1c89685d48c53a4f98f69a160a61abbfad9f955c25a70a2bab3b79f8",
                        "name": "github.com/stretchr/testify/require",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["require"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/require/require.go",
                            "symbol": "github.com/stretchr/testify/require"
                        }
                    },
                    {
                        "id": "type.test.rql.os-exec.module",
                        "name": "os/exec",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["exec"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/exec/exec.go",
                            "symbol": "os/exec"
                        }
                    },
                    {
                        "id": "type.test.rql.os-exec.exit-error",
                        "name": "os/exec.ExitError",
                        "type_kind": "struct",
                        "visibility": "public",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "struct{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/exec/exec.go",
                            "symbol": "os/exec.ExitError"
                        }
                    },
                    {
                        "id": "type.253e4ec2c267b0a4d8e7ffbcb21aa17d591dd6f2557d12e01e32ba70dbe923b9",
                        "name": "github.com/stretchr/testify/require.TestingT",
                        "type_kind": "interface",
                        "visibility": "public",
                        "is_abstract": true,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "interface{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/require/require.go",
                            "symbol": "github.com/stretchr/testify/require.TestingT"
                        }
                    },
                    {
                        "id": "type.e7c2e010e38d28ef033ed9e87af4fc76e9606dc0ea77ccdfcf401bb586f3033b",
                        "name": "github.com/stretchr/testify/assert",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["assert"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/assert/assertions.go",
                            "symbol": "github.com/stretchr/testify/assert"
                        }
                    },
                    {
                        "id": "type.a72411f16a9045f73eb852c72f53af4caada3eb3eeb9b350e4eef9665e913d08",
                        "name": "github.com/stretchr/testify/assert.TestingT",
                        "type_kind": "interface",
                        "visibility": "public",
                        "is_abstract": true,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "interface{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/assert/assertions.go",
                            "symbol": "github.com/stretchr/testify/assert.TestingT"
                        }
                    },
                    {
                        "id": "type.test.rql.predicate.module",
                        "name": "example.com/predicate",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["predicate"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate"
                        }
                    },
                    {
                        "id": "type.test.rql.consumer.module",
                        "name": "example.com/app/consumer",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["consumer"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer"
                        }
                    }
                ],
                "members": [
                    {
                        "id": "member.e969c07a9215c885c075e9f2767d17d39f10922eb0ff1394d8222dd7dc40f38e",
                        "owner": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                        "name": "Open",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "name",
                                "type": {
                                    "kind": "named",
                                    "name": "string",
                                    "arguments": [],
                                    "nullable": false
                                },
                                "optional": false,
                                "variadic": false
                            }],
                            "returns": {
                                "kind": "tuple",
                                "elements": [
                                    {
                                        "kind": "pointer",
                                        "element": {
                                            "kind": "declared",
                                            "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                            "arguments": [],
                                            "nullable": false
                                        }
                                    },
                                    {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                ]
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os.Open"
                        }
                    },
                    {
                        "id": "member.test.rql.os.file.name",
                        "owner": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "Name",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [],
                            "returns": {
                                "kind": "named",
                                "name": "string",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/file.go",
                            "symbol": "os.File.Name"
                        }
                    },
                    {
                        "id": "member.test.rql.os.file.use",
                        "owner": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "Use",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "value",
                                "type": {
                                    "kind": "named",
                                    "name": "string",
                                    "arguments": [],
                                    "nullable": false
                                },
                                "optional": false,
                                "variadic": false
                            }]
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/file.go",
                            "symbol": "os.File.Use"
                        }
                    },
                    {
                        "id": "member.test.rql.os.file.use_two",
                        "owner": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "UseTwo",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "first",
                                    "type": {
                                        "kind": "named",
                                        "name": "string",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "second",
                                    "type": {
                                        "kind": "named",
                                        "name": "string",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                }
                            ]
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/file.go",
                            "symbol": "os.File.UseTwo"
                        }
                    },
                    {
                        "id": "member.test.rql.os.file.consume",
                        "owner": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "Consume",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "file",
                                "type": {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                "optional": false,
                                "variadic": false
                            }]
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/file.go",
                            "symbol": "os.File.Consume"
                        }
                    },
                    {
                        "id": "member.f5464663c23ef077afc3ec4cc51c586c1df1ca48fbf68482840875b617208e4b",
                        "owner": "type.1eef3afbc23b6c534c6d054fc877197155006d5fdbdce518890a99d07a1f85d8",
                        "name": "Is",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "err",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "target",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                }
                            ],
                            "returns": {
                                "kind": "named",
                                "name": "bool",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "errors/errors.go",
                            "symbol": "errors.Is"
                        }
                    },
                    {
                        "id": "member.9fd565756088ca91d69be236b28ee436db05c9fa5b505d121a26fcf7d151992d",
                        "owner": "type.1eef3afbc23b6c534c6d054fc877197155006d5fdbdce518890a99d07a1f85d8",
                        "name": "As",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "err",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "target",
                                    "type": {
                                        "kind": "named",
                                        "name": "any",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                }
                            ],
                            "returns": {
                                "kind": "named",
                                "name": "bool",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "errors/errors.go",
                            "symbol": "errors.As"
                        }
                    },
                    {
                        "id": "member.3de3ee8d4154a940e5cf65b19f308ef5e6ba51eb72c419b7fc1294389ba3bdfb",
                        "owner": "type.66dc4abf1c89685d48c53a4f98f69a160a61abbfad9f955c25a70a2bab3b79f8",
                        "name": "NoError",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "t",
                                    "type": {
                                        "kind": "declared",
                                        "id": "type.253e4ec2c267b0a4d8e7ffbcb21aa17d591dd6f2557d12e01e32ba70dbe923b9",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "err",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "msgAndArgs",
                                    "type": {
                                        "kind": "named",
                                        "name": "interface{}",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": true
                                }
                            ]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/require/require.go",
                            "symbol": "github.com/stretchr/testify/require.NoError"
                        }
                    },
                    {
                        "id": "member.test.rql.os-exec.exit-error.exit-code",
                        "owner": "type.test.rql.os-exec.exit-error",
                        "name": "ExitCode",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [],
                            "returns": {
                                "kind": "named",
                                "name": "int",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/exec/exec.go",
                            "symbol": "os/exec.ExitError.ExitCode"
                        }
                    },
                    {
                        "id": "member.a122fd9a4bbd575d30d356130a13f0d70da5f107d578c96a97c583983c397b3f",
                        "owner": "type.e7c2e010e38d28ef033ed9e87af4fc76e9606dc0ea77ccdfcf401bb586f3033b",
                        "name": "NoError",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "t",
                                    "type": {
                                        "kind": "declared",
                                        "id": "type.a72411f16a9045f73eb852c72f53af4caada3eb3eeb9b350e4eef9665e913d08",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "err",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "msgAndArgs",
                                    "type": {
                                        "kind": "named",
                                        "name": "interface{}",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": true
                                }
                            ],
                            "returns": {
                                "kind": "named",
                                "name": "bool",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/assert/assertions.go",
                            "symbol": "github.com/stretchr/testify/assert.NoError"
                        }
                    },
                    {
                        "id": "member.test.rql.predicate.is_nil",
                        "owner": "type.test.rql.predicate.module",
                        "name": "IsNil",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "value",
                                "type": {
                                    "kind": "named",
                                    "name": "error",
                                    "arguments": [],
                                    "nullable": false
                                },
                                "optional": false,
                                "variadic": false
                            }],
                            "returns": {
                                "kind": "named",
                                "name": "bool",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate.IsNil"
                        }
                    },
                    {
                        "id": "member.test.rql.predicate.checked",
                        "owner": "type.test.rql.predicate.module",
                        "name": "Checked",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "value",
                                "type": {
                                    "kind": "named",
                                    "name": "error",
                                    "arguments": [],
                                    "nullable": false
                                },
                                "optional": false,
                                "variadic": false
                            }],
                            "returns": {
                                "kind": "named",
                                "name": "string",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate.Checked"
                        }
                    },
                    {
                        "id": "member.test.rql.consumer.require",
                        "owner": "type.test.rql.consumer.module",
                        "name": "Require",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "label",
                                    "type": {
                                        "kind": "named",
                                        "name": "string",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "file",
                                    "type": {
                                        "kind": "pointer",
                                        "element": {
                                            "kind": "declared",
                                            "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                            "arguments": [],
                                            "nullable": false
                                        }
                                    },
                                    "optional": false,
                                    "variadic": false
                                }
                            ]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Require"
                        }
                    },
                    {
                        "id": "member.test.rql.consumer.observe",
                        "owner": "type.test.rql.consumer.module",
                        "name": "Observe",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "file",
                                "type": {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                "optional": false,
                                "variadic": false
                            }]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Observe"
                        }
                    },
                    {
                        "id": "member.test.rql.consumer.unreviewed",
                        "owner": "type.test.rql.consumer.module",
                        "name": "Unreviewed",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "file",
                                "type": {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                "optional": false,
                                "variadic": false
                            }]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Unreviewed"
                        }
                    },
                    {
                        "id": "member.test.rql.consumer.require_many",
                        "owner": "type.test.rql.consumer.module",
                        "name": "RequireMany",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "file",
                                    "type": {
                                        "kind": "pointer",
                                        "element": {
                                            "kind": "declared",
                                            "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                            "arguments": [],
                                            "nullable": false
                                        }
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "rest",
                                    "type": {
                                        "kind": "pointer",
                                        "element": {
                                            "kind": "declared",
                                            "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                            "arguments": [],
                                            "nullable": false
                                        }
                                    },
                                    "optional": false,
                                    "variadic": true
                                }
                            ]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.RequireMany"
                        }
                    }
                ]
            }
        }]
    }"#;
    let pack = compile_source(SourceFormat::Json, pack_source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| {
            panic!("conditional result-contract pack failed: {diagnostics:#?}")
        });
    let declaration_pack = compile_source(
        SourceFormat::Json,
        declaration_pack_source,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("conditional declaration pack failed: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-conditional-result-contract".to_owned(),
            },
        )
        .expect("register conditional result-contract pack");
    catalog
        .register_session_pack(
            &declaration_pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-conditional-result-contract-declarations".to_owned(),
            },
        )
        .expect("register exact conditional-result declarations");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "test conditional result-contract pack activates: {activation:#?}"
    );

    let query = CodeQuery::from_json(&if operation == "nilness_operations" {
        json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": "exitCode" },
            "steps": [
                { "op": "procedure_of" },
                { "op": operation }
            ],
            "result_detail": "full"
        })
    } else {
        json!({
            "languages": ["go"],
            "match": { "kind": "call", "callee": { "name": "Open" } },
            "steps": [
                { "op": "call_shape" },
                { "op": "call_result_contracts" },
                { "op": operation }
            ],
            "result_detail": "full"
        })
    })
    .expect("conditional result-contract use query");
    execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

fn call_result_contract_value(value: &CodeQueryResultValue) -> &CodeQueryCallResultContract {
    let CodeQueryResultValue::CallResultContract { value } = value else {
        panic!("result-contract wrapper returns its typed row: {value:#?}")
    };
    value
}

fn open_unknown_result_contract(result: &CodeQueryResult) -> &CodeQueryCallResultContract {
    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let value = call_result_contract_value(&item.value);
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, None, "{value:#?}");
    assert_eq!(value.use_validation, Some("unknown"), "{value:#?}");
    assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
    value
}

fn assert_single_open_unknown_result_contract(result: &CodeQueryResult) {
    let value = open_unknown_result_contract(result);
    assert_eq!(value.success_guard_count, 0, "{value:#?}");
}

fn assert_single_guarded_open_unknown_result_contract(result: &CodeQueryResult) {
    let value = open_unknown_result_contract(result);
    assert_eq!(value.success_guard_count, 1, "{value:#?}");
    assert_eq!(
        value.success_guard_coverage,
        Some(EffectCoverage::Exhaustive),
        "{value:#?}"
    );
    assert_eq!(value.success_guard_edges.len(), 1, "{value:#?}");
    assert_eq!(value.possible_success_guard_edges.len(), 1, "{value:#?}");
}

fn assert_single_exhaustive_violated_result_contract(result: &CodeQueryResult) {
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let value = call_result_contract_value(&item.value);
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.success_guard_count, 0, "{value:#?}");
    assert_eq!(
        value.success_guard_coverage,
        Some(EffectCoverage::Exhaustive),
        "{value:#?}"
    );
    assert!(value.success_guard_edges.is_empty(), "{value:#?}");
    assert!(value.possible_success_guard_edges.is_empty(), "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.use_validation, Some("violated"), "{value:#?}");
    assert_eq!(
        value.use_validation_coverage,
        Some("exhaustive"),
        "{value:#?}"
    );
}

fn assert_single_exhaustive_satisfied_result_contract(result: &CodeQueryResult) {
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let value = call_result_contract_value(&item.value);
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.success_guard_count, 0, "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(0), "{value:#?}");
    assert_eq!(value.use_validation, Some("satisfied"), "{value:#?}");
    assert_eq!(
        value.use_validation_coverage,
        Some("exhaustive"),
        "{value:#?}"
    );
}

fn assert_open_unknown_result_contract_uses(
    result: &CodeQueryResult,
    expected_use_counts: &[usize],
) {
    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "{result:#?}"
    );
    assert_eq!(
        result.results.len(),
        expected_use_counts.len(),
        "{result:#?}"
    );
    for (item, expected_use_count) in result.results.iter().zip(expected_use_counts) {
        let value = call_result_contract_value(&item.value);
        assert_eq!(value.coverage, "exhaustive", "{value:#?}");
        assert_eq!(
            value.result_use_count,
            Some(*expected_use_count),
            "{value:#?}"
        );
        assert_eq!(value.success_guard_count, 0, "{value:#?}");
        assert_eq!(value.unguarded_result_use_count, None, "{value:#?}");
        assert_eq!(value.use_validation, Some("unknown"), "{value:#?}");
        assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
    }
}

#[test]
#[hardwon("#7379: a store through a nil pointer was not a nil-dereference operation")]
fn go_nilness_selects_pointer_stores_with_exact_and_unknown_facts() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
func nilStore(r *int) { var c *int; *c = *r }
func allocatedStore(r *int) { c := new(int); *c = *r }
func unknownStore(c *int, r *int) { *c = *r }
func nilReadModifyWrite() { var c *int; *c += 1 }
func parenthesizedRead() int { var c *int; return *(c) }
func parenthesizedStore() { var c *int; *(c) = 1 }
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for (name, expected_count, expected_fact, expected_proof, expected_coverage) in [
        ("nilStore", 2, "nil", "exact", "exhaustive"),
        ("allocatedStore", 2, "non_nil", "exact", "exhaustive"),
        ("unknownStore", 2, "unknown", "unknown", "open"),
        ("nilReadModifyWrite", 1, "nil", "exact", "exhaustive"),
        ("parenthesizedRead", 1, "nil", "exact", "exhaustive"),
        ("parenthesizedStore", 1, "nil", "exact", "exhaustive"),
    ] {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": name },
            "steps": [{ "op": "procedure_of" }, { "op": "nilness_operations" }],
            "result_detail": "full"
        }))
        .expect("Go nilness query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{result:#?}"
        );
        let operations = result
            .results
            .iter()
            .map(|item| {
                let CodeQueryResultValue::NilnessOperation { value } = &item.value else {
                    panic!("expected nilness operation: {item:#?}");
                };
                value
            })
            .collect::<Vec<_>>();
        assert_eq!(operations.len(), expected_count, "{name}: {result:#?}");
        assert!(
            operations.iter().any(|value| value.fact == expected_fact
                && value.proof == expected_proof
                && value.coverage == expected_coverage),
            "{name}: {result:#?}"
        );
    }
}

#[test]
fn go_nilness_keeps_unconstrained_pointer_parameters_open() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            "package main\nfunc dereference(pointer *int) int { return *pointer }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "dereference" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "nilness_operations" }
        ],
        "result_detail": "full"
    }))
    .expect("Go nilness query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let [item] = result.results.as_slice() else {
        panic!(
            "one pointer dereference is reported: {}",
            result.render_text()
        );
    };
    let CodeQueryResultValue::NilnessOperation { value } = &item.value else {
        panic!("the query reports a nilness operation: {item:#?}");
    };
    assert_eq!(value.fact, "unknown");
    assert_eq!(value.proof, "unknown");
    assert_eq!(value.coverage, "open");
    assert_eq!(value.reason, Some("scalar_fact_unknown"));
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn go_exact_assignment_converted_result_and_condition_bindings_are_proven() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func reusedCondition(path string) string {
    var err error
    file, err := os.Open(path)
    if err != nil { return "" }
    return file.Name()
}

func reusedResultAndCondition(path string) string {
    var file *os.File
    var err error
    file, err = os.Open(path)
    if err != nil { return "" }
    return file.Name()
}
"#,
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_eq!(result.results.len(), 2, "{result:#?}");
    for item in &result.results {
        let CodeQueryResultValue::CallResultContract { value } = &item.value else {
            panic!("result-contract wrapper returns its typed row: {item:#?}")
        };
        assert_eq!(value.coverage, "exhaustive", "{value:#?}");
        assert_eq!(value.result_use_count, Some(1), "{value:#?}");
        assert_eq!(value.success_guard_count, 1, "{value:#?}");
        assert_eq!(value.unguarded_result_use_count, Some(0), "{value:#?}");
        assert_eq!(value.use_validation, Some("satisfied"), "{value:#?}");
        assert_eq!(
            value.use_validation_coverage,
            Some("exhaustive"),
            "{value:#?}"
        );
        assert_eq!(
            value.success_guard_coverage,
            Some(EffectCoverage::Exhaustive),
            "{value:#?}"
        );
        assert_eq!(value.success_guard_edges.len(), 1, "{value:#?}");
        assert_eq!(value.possible_success_guard_edges.len(), 1, "{value:#?}");
    }
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "3ac44dca99bb: converted field and index assignments must not fabricate direct result proofs"
)]
fn go_assignment_converted_field_and_index_results_stay_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

type holder struct { file *os.File }

func storeField(target *holder, path string) string {
    target.file, _ = os.Open(path)
    return target.file.Name()
}

func storeIndex(target []*os.File, path string) {
    target[0], _ = os.Open(path)
}
"#,
    );

    assert_open_unknown_result_contract_uses(&result, &[1, 0]);
    for item in &result.results {
        let CodeQueryResultValue::CallResultContract { value } = &item.value else {
            panic!("result-contract wrapper returns its typed row: {item:#?}")
        };
        assert_eq!(
            value.success_guard_coverage,
            Some(EffectCoverage::Open),
            "the converted memory result can hide an unpositioned success guard: {value:#?}"
        );
        assert!(value.success_guard_edges.is_empty(), "{value:#?}");
        assert!(
            value.possible_success_guard_edges.is_empty(),
            "this fixture has no positioned null comparison to retain: {value:#?}"
        );
    }
}

#[test]
fn go_assertion_payload_workspace_proof_requires_current_source_and_budget() {
    use crate::analyzer::semantic::{SemanticOutcome, TransferKind, ValueTransfer};
    use brokk_bifrost_go_analysis::analyzer::workspace_reference_assertion_accepts_payload;

    for (asserted, expected) in [("*Cell", true), ("*Other", false)] {
        let source = format!(
            "package p\ntype Cell struct {{ n int }}\ntype Other struct {{ n int }}\nfunc f() {{ shared := &Cell{{}}; var boxed any = shared; _ = boxed.({asserted}); boxed = &Other{{}} }}\n"
        );
        let project = InlineTestProject::with_language(Language::Go)
            .file("main.go", &source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("main.go");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go artifact");
        let artifact = outcome.available_value().expect("available artifact");
        let mut payload = None;
        let mut assertion = None;
        for procedure in artifact.procedures() {
            let handle = artifact.procedure_handle(procedure.id()).unwrap();
            for event in procedure.points().iter().flat_map(|point| &point.events) {
                match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::ReferenceBoxing,
                        source,
                        ..
                    } if payload.is_none() => {
                        payload = handle.value_handle(source);
                    }
                    SemanticEffect::ValueFlow {
                        kind:
                            ValueFlowKind::Transfer(ValueTransfer {
                                kind: TransferKind::Unboxing,
                                ..
                            }),
                        target,
                        ..
                    } => assertion = handle.value_handle(target),
                    _ => {}
                }
            }
        }
        let payload = payload.expect("boxed payload");
        let assertion = assertion.expect("mutable-interface assertion requires a query");
        let mut budget = SemanticBudget::default();
        let outcome = workspace_reference_assertion_accepts_payload(
            &workspace,
            &assertion,
            &payload,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
        assert!(
            matches!(outcome, SemanticOutcome::Complete { value, .. } if value == expected),
            "{outcome:?}"
        );
        assert_eq!(budget.used(), outcome.work(), "all query work is charged");
        assert_eq!(outcome.work().source_bytes, source.len());
        assert!(outcome.work().nested_entries > 0);

        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = 1;
        let mut bounded = SemanticBudget::new(limits).unwrap();
        assert!(matches!(
            workspace_reference_assertion_accepts_payload(
                &workspace,
                &assertion,
                &payload,
                &mut SemanticRequest::new(&mut bounded, &cancellation),
            )
            .unwrap(),
            SemanticOutcome::ExceededBudget { .. }
        ));
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(matches!(
            workspace_reference_assertion_accepts_payload(
                &workspace,
                &assertion,
                &payload,
                &mut SemanticRequest::new(&mut budget, &cancelled),
            )
            .unwrap(),
            SemanticOutcome::Cancelled { .. }
        ));

        file.write("package p\nfunc replacement() {}\n").unwrap();
        let changed_workspace = project.workspace_analyzer(AnalyzerConfig::default());
        assert!(
            workspace_reference_assertion_accepts_payload(
                &changed_workspace,
                &assertion,
                &payload,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .is_err(),
            "stale handles must not read the new source at old offsets"
        );
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "3ac44dca99bb: deferred captures must not be treated as direct assignment conversions"
)]
fn go_defer_capture_is_not_a_direct_assignment_conversion() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "os"

func deferred(path string) {
    file, _ := os.Open(path)
    defer file.Close()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("main.go");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = workspace
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("Go artifact materialization");
    let artifact = outcome
        .available_value()
        .expect("Go artifact remains available");
    let (procedure, defer_capture) = artifact
        .procedures()
        .iter()
        .find_map(|procedure| {
            procedure.points().iter().find_map(|point| {
                point.events.iter().find_map(|event| match &event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source: _,
                        target,
                    } if procedure.value(*target).is_some_and(|value| {
                        matches!(
                            &value.kind,
                            SemanticValueKind::LanguageDefined(kind)
                                if kind.as_ref() == "go.defer_capture"
                        )
                    }) =>
                    {
                        Some((procedure, *target))
                    }
                    _ => None,
                })
            })
        })
        .expect("defer receiver capture has structured language-defined flow");

    assert!(
        !super::super::effects::is_go_assignment_conversion_target(procedure, defer_capture),
        "a defer capture must not be mistaken for a Go assignment conversion"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a6922f3a7094: preserve C assignment certainty across parenthesized and non-bare right sides"
)]
fn c_assignment_relations_support_parentheses_and_expression_exclusions() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.c",
            r#"void shapes(void) {
    int ordinary = 1;
    ordinary = ((ordinary));
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["cpp"],
        "match": { "kind": "function", "name": "shapes" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations" }
        ],
        "result_detail": "full"
    }))
    .expect("C assignment relation query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let rows = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::AssignmentRelation { value } = &item.value else {
                panic!("assignment relation row: {item:#?}");
            };
            (
                value.range.start_line,
                value.storage_kind,
                value.verdict,
                value.reason,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [(3, "ordinary_local", "self_assignment", None)],
        "{result:#?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a6922f3a7094: bind a shadowed C assignment to the inner declaration identity"
)]
fn c_assignment_relations_resolve_nested_shadow_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.c",
            r#"void shadows(void) {
    int shadow = 2;
    {
        int shadow = 3;
        shadow = shadow;
    }
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["cpp"],
        "match": { "kind": "function", "name": "shadows" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations" }
        ],
        "result_detail": "full"
    }))
    .expect("shadow query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one shadow assignment: {result:#?}");
    };
    let CodeQueryResultValue::AssignmentRelation { value } = &item.value else {
        panic!("assignment relation row: {item:#?}");
    };
    assert_eq!(value.storage_kind, "ordinary_local");
    assert_eq!(value.verdict, "self_assignment");
    assert_eq!(value.coverage, "exhaustive");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a6922f3a7094: keep compound and comma assignments out of bare-copy relations"
)]
fn c_assignment_relations_keep_compound_and_comma_rhs_complete_exclusions() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.c",
            r#"void excluded_shapes(void) {
    int value = 1;
    value += value;
    value = (value, value);
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["cpp"],
        "match": { "kind": "function", "name": "excluded_shapes" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations" }
        ],
        "result_detail": "full"
    }))
    .expect("expression exclusion query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_eq!(result.results.len(), 2, "{result:#?}");
    assert!(result.results.iter().all(|item| {
        matches!(
            &item.value,
            CodeQueryResultValue::AssignmentRelation { value }
                if value.verdict == "excluded" && value.coverage == "exhaustive"
        )
    }));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a6922f3a7094: classify call-shaped C assignment right sides without claiming a copy"
)]
fn c_assignment_relations_keep_call_rhs_as_a_complete_exclusion() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.c",
            r#"int identity(int value) { return value; }
void call_shape(void) {
    int value = 1;
    value = identity(value);
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["cpp"],
        "match": { "kind": "function", "name": "call_shape" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations" }
        ],
        "result_detail": "full"
    }))
    .expect("call exclusion query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one call exclusion: {result:#?}");
    };
    let CodeQueryResultValue::AssignmentRelation { value } = &item.value else {
        panic!("assignment relation row: {item:#?}");
    };
    assert_eq!(value.verdict, "excluded");
    assert_eq!(value.coverage, "exhaustive");
    assert_eq!(value.reason, Some("rhs_not_bare_identifier"));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a6922f3a7094: retain open coverage beside a proven C copy when another right side is unsupported"
)]
fn c_assignment_relations_keep_mixed_positive_and_call_coverage_incomplete() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.c",
            r#"int identity(int value) { return value; }
void mixed(void) {
    int value = 1;
    value = value;
    value = identity(value);
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["cpp"],
        "match": { "kind": "function", "name": "mixed" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations" }
        ],
        "result_detail": "full"
    }))
    .expect("mixed call coverage query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(
        matches!(result.completion(), CodeQueryCompletion::Incomplete { .. }),
        "{result:#?}"
    );
    assert!(result.results.iter().any(|item| {
        matches!(
            &item.value,
            CodeQueryResultValue::AssignmentRelation { value }
                if value.range.start_line == 4
                    && value.verdict == "unknown"
                    && value.coverage == "open"
        )
    }));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a6922f3a7094: scope C qualifier evidence to the selected declarator"
)]
fn c_assignment_relations_scope_qualifiers_to_the_selected_declarator() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.c",
            r#"void selected_declarator(void) {
    int * volatile pointer, ordinary = 1;
    ordinary = ordinary;
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["cpp"],
        "match": { "kind": "function", "name": "selected_declarator" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations" }
        ],
        "result_detail": "full"
    }))
    .expect("selected declarator query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(
        matches!(result.completion(), CodeQueryCompletion::Complete),
        "{result:#?}"
    );
    let ordinary = result
        .results
        .iter()
        .find_map(|item| {
            let CodeQueryResultValue::AssignmentRelation { value } = &item.value else {
                return None;
            };
            (value.range.start_line == 3).then_some(value)
        })
        .expect("ordinary sibling assignment row");
    assert_eq!(ordinary.storage_kind, "ordinary_local", "{result:#?}");
    assert_eq!(ordinary.verdict, "self_assignment", "{result:#?}");
    assert_eq!(ordinary.proof, "exact", "{result:#?}");
    assert_eq!(ordinary.coverage, "exhaustive", "{result:#?}");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a9de523bc3d5: preserve C self-assignment uncertainty after row filtering"
)]
fn c_assignment_relations_keep_open_rows_incomplete_after_filtering() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.c",
            r#"typedef int Scalar;

void unknowns(int condition) {
    int maybe;
    if (condition) {
        maybe = 1;
    }
    maybe = maybe;
    Scalar alias = 1;
    alias = alias;
    int *pointer = 0;
    pointer = pointer;
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query_json = |filtered: bool| {
        let mut steps = vec![
            json!({ "op": "procedure_of" }),
            json!({ "op": "assignment_relations" }),
        ];
        if filtered {
            steps.push(json!({
                "op": "filter",
                "where": [{
                    "field": "verdict",
                    "op": "eq",
                    "value": { "enum": "self_assignment" }
                }]
            }));
        }
        json!({
            "languages": ["cpp"],
            "match": { "kind": "function", "name": "unknowns" },
            "steps": steps,
            "result_detail": "full"
        })
    };

    let raw_query = CodeQuery::from_json(&query_json(false)).expect("raw assignment query");
    let raw = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &raw_query,
    );
    assert!(
        matches!(raw.completion(), CodeQueryCompletion::Incomplete { .. }),
        "{raw:#?}"
    );
    let open_reasons = raw
        .results
        .iter()
        .filter_map(|item| {
            let CodeQueryResultValue::AssignmentRelation { value } = &item.value else {
                return None;
            };
            (value.coverage == "open").then_some(value.reason)
        })
        .collect::<Vec<_>>();
    assert!(open_reasons.len() >= 3, "{raw:#?}");
    assert!(
        open_reasons.contains(&Some("flow_state_incomplete")),
        "{raw:#?}"
    );

    let filtered_query =
        CodeQuery::from_json(&query_json(true)).expect("filtered assignment query");
    let filtered = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &filtered_query,
    );
    assert!(filtered.results.is_empty(), "{filtered:#?}");
    assert!(
        matches!(
            filtered.completion(),
            CodeQueryCompletion::Incomplete { .. }
        ),
        "{filtered:#?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a9de523bc3d5: preserve preprocessor and recovered-syntax gaps in C assignment rows"
)]
fn c_assignment_relations_report_configuration_and_recovery_as_incomplete() {
    for (name, source) in [
        (
            "configured",
            r#"void configured(void) {
    int value = 1;
#if FEATURE
    value = value;
#endif
}
"#,
        ),
        (
            "recovered",
            r#"void recovered(void) {
    int value = 1;
    value = (value;
}
"#,
        ),
        (
            "macro_wrapped",
            r#"void macro_wrapped(void) {
    int value = 1;
#define SELF_ASSIGN(x) x = x
    SELF_ASSIGN(value);
}
"#,
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Cpp)
            .file("main.c", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query = CodeQuery::from_json(&json!({
            "languages": ["cpp"],
            "match": { "kind": "function", "name": name },
            "steps": [
                { "op": "procedure_of" },
                { "op": "assignment_relations" }
            ],
            "result_detail": "full"
        }))
        .expect("C uncertain syntax query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert!(
            matches!(result.completion(), CodeQueryCompletion::Incomplete { .. }),
            "{name}: {result:#?}"
        );
        if matches!(name, "configured" | "macro_wrapped") {
            assert!(
                result.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CodeQueryDiagnosticCode::EffectDerivationIncomplete
                        && diagnostic.message.contains("preprocessing_present")
                }),
                "content configuration gaps must retain their diagnostic class: {result:#?}"
            );
        }
    }
}

fn c_failed_swap_query(name: &str) -> CodeQuery {
    CodeQuery::from_json(&json!({
        "languages": ["cpp"],
        "match": { "kind": "function", "name": name },
        "steps": [
            { "op": "procedure_of" },
            {
                "op": "assignment_relations",
                "assignment_relation": ["failed_swap"]
            }
        ],
        "result_detail": "full"
    }))
    .expect("C failed-swap query")
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a7251c530cc6: unproved volatile C assignments must keep swap relations open"
)]
fn c_failed_swap_keeps_volatile_pair_open() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.c",
            r#"void volatile_pair(void) {
    volatile int first = 1;
    volatile int second = 2;
    first = second;
    second = first;
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &c_failed_swap_query("volatile_pair"),
    );
    assert!(
        matches!(result.completion(), CodeQueryCompletion::Incomplete { .. }),
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one open volatile failed-swap relation: {result:#?}");
    };
    let CodeQueryResultValue::AssignmentRelation { value } = &item.value else {
        panic!("assignment relation row: {item:#?}");
    };
    assert_eq!(value.verdict, "unknown", "{result:#?}");
    assert_eq!(value.coverage, "open", "{result:#?}");
    assert_eq!(value.storage_kind, "volatile", "{result:#?}");
}

#[test]
fn assignment_relations_prove_ruby_local_self_assignment() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("main.rb", "def check\n  value = 1\n  value = value\nend\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["ruby"],
        "match": { "kind": "function", "name": "check" },
        "steps": [{ "op": "procedure_of" }, { "op": "assignment_relations" }],
        "result_detail": "full"
    }))
    .expect("Ruby assignment relation query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert!(
        result.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::AssignmentRelation { value }
                if value.path == "main.rb" && value.verdict == "self_assignment"
        )),
        "{result:#?}"
    );
}

#[test]
fn assignment_relations_prove_ruby_overwritten_unread_local() {
    for (source, expected, complete) in [
        (
            "def check\n  value = 1\n  value = 2\n  value\nend\n",
            1,
            true,
        ),
        (
            "def check\n  value = 1\n  kept = value\n  value = 2\n  kept\nend\n",
            0,
            true,
        ),
        (
            "def check\n  value = 1\n  value += 2\n  value\nend\n",
            0,
            false,
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Ruby)
            .file("main.rb", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query = CodeQuery::from_json(&json!({
            "languages": ["ruby"],
            "match": { "kind": "function", "name": "check" },
            "steps": [
                { "op": "procedure_of" },
                { "op": "assignment_relations", "assignment_relation": ["overwritten_unread"] }
            ],
            "result_detail": "full"
        }))
        .expect("Ruby overwritten-unread assignment relation query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        if complete {
            assert_eq!(
                result.completion(),
                CodeQueryCompletion::Complete,
                "{source}: {result:#?}"
            );
        } else {
            assert!(
                !matches!(result.completion(), CodeQueryCompletion::Complete),
                "{source}: {result:#?}"
            );
        }
        let actual = result
            .results
            .iter()
            .filter(|item| {
                matches!(
                    &item.value,
                    CodeQueryResultValue::AssignmentRelation { value }
                        if value.verdict == "overwritten_unread"
                )
            })
            .count();
        assert_eq!(actual, expected, "{source}: {result:#?}");
    }
}

#[test]
fn java_overwritten_unread_assignment_relations_keep_replacement_event_witnesses() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Sample.java",
            "class Sample { void check(boolean flag) { int value = 1; if (flag) value = 2; else value = 3; } }",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["java"],
        "match": { "kind": "method", "name": "check" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations", "assignment_relation": ["overwritten_unread"] }
        ],
        "result_detail": "full"
    }))
    .expect("Java overwrite query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let findings = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::AssignmentRelation { value }
                if value.verdict == "overwritten_unread" =>
            {
                Some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [finding] = findings.as_slice() else {
        panic!("one first value overwritten on both branches: {result:#?}");
    };
    assert_eq!(finding.relation_kind, "overwritten_unread");
    assert_eq!(finding.replacement_events.len(), 2, "{finding:#?}");
    assert!(finding.replacement_events.iter().all(|event| {
        !event.id.is_empty()
            && event.path == "Sample.java"
            && event.event_class == "establish"
            && event.subject == "binding"
    }));
    assert_ne!(
        finding.replacement_events[0].id,
        finding.replacement_events[1].id
    );
}

#[test]
fn java_overwritten_unread_preserves_lambda_capture_reads() {
    for (body, expected) in [
        (
            "int captured = 1; return () -> { int observed = captured; };",
            0,
        ),
        (
            "int captured = 1; int changed = 1; Runnable task = () -> { int observed = captured; }; changed = 2; return task;",
            1,
        ),
        (
            "int captured = 1; int changed = 1; int observed = changed; Runnable task = () -> { int inside = captured; }; changed = 2; return task;",
            0,
        ),
        (
            "int changed = 1; Runnable task = () -> {}; changed = 2; return task;",
            1,
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "Sample.java",
                format!("class Sample {{ Runnable check() {{ {body} }} }}"),
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        for (kind, count) in [("method", expected), ("lambda", 0)] {
            let query = CodeQuery::from_json(&json!({
                "languages": ["java"],
                "match": { "kind": kind },
                "steps": [
                    { "op": "procedure_of" },
                    { "op": "assignment_relations", "assignment_relation": ["overwritten_unread"] }
                ],
                "result_detail": "full"
            }))
            .unwrap();
            let result = execute_workspace(
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::new(),
                &query,
            );
            assert_eq!(
                result.completion(),
                CodeQueryCompletion::Complete,
                "{body}: {result:#?}"
            );
            let actual = result.results.iter().filter(|item| matches!(&item.value,
            CodeQueryResultValue::AssignmentRelation { value } if value.verdict == "overwritten_unread"
        )).count();
            assert_eq!(actual, count, "{kind}: {body}: {result:#?}");
        }
    }
}

#[test]
fn java_overwritten_unread_requires_every_reachable_finally_copy() {
    for (body, expected) in [
        (
            "int value = 1; try { return value; } finally { value = 2; }",
            0,
        ),
        (
            "int value; try { if (flag) return 1; } finally { value = 1; value = 2; } return value;",
            1,
        ),
        (
            "int value; try { if (flag) return 1; } finally { value = 1; } return value;",
            0,
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "Sample.java",
                format!("class Sample {{ int check(boolean flag) {{ {body} }} }}"),
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query = CodeQuery::from_json(&json!({
            "languages": ["java"],
            "match": { "kind": "method", "name": "check" },
            "steps": [
                { "op": "procedure_of" },
                { "op": "assignment_relations", "assignment_relation": ["overwritten_unread"] }
            ]
        }))
        .expect("Java overwrite query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{body}: {result:#?}"
        );
        let findings = result
            .results
            .iter()
            .filter(|item| {
                matches!(
                    &item.value, CodeQueryResultValue::AssignmentRelation { value }
                        if value.verdict == "overwritten_unread"
                )
            })
            .count();
        assert_eq!(findings, expected, "{body}: {result:#?}");
    }
}

const GO_WRAPPER_MODULE: &str = "module example.com/app\n\ngo 1.22\n";
const EXACT_ERRORS_IS_WRAPPER: &str = r#"package errors

import stderrors "errors"

func Is(x, y error) bool { return stderrors.Is(x, y) }
"#;

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn pre_origin_gaps_do_not_hide_exact_failure_and_success_arm_uses() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[(
            "main.go",
            r#"package main

import "os"

type holder struct { values []int }

func failureArmThenOpenTarget(path string, h *holder) error {
    for range h.values {
        _ = h.values
    }
    file, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open %s: %w", file.Name(), err)
    }
    _ = file.Name()
    return nil
}

func unrelatedEarlierConsumer(path string, h *holder) error {
    for range h.values {
        _ = h.values
    }
    file, err := os.Open(path)
    if err != nil {
        _ = fmt.Errorf("open: %w", err)
        _ = file.Name()
        return err
    }
    return nil
}
"#,
        )],
        "result_contract_operation_uses",
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let mut answers = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
                panic!("result_contract_operation_uses returns its typed row: {item:#?}")
            };
            assert_eq!(value.member.as_deref(), Some("Name"), "{value:#?}");
            assert_eq!(value.applicability, "required", "{value:#?}");
            (value.range.start_line, value.guard, value.coverage)
        })
        .collect::<Vec<_>>();
    answers.sort_unstable_by_key(|(line, _, _)| *line);
    let [failure_arm, success_arm, unrelated_failure_arm] = answers.as_slice() else {
        panic!("the two os.Open results have three exact Name operations: {result:#?}")
    };
    assert!(failure_arm.0 < success_arm.0, "{result:#?}");
    assert_eq!(
        (failure_arm.1, failure_arm.2),
        ("unguarded", "exhaustive"),
        "the closed failure-arm negative remains reportable: {result:#?}"
    );
    assert_eq!(
        (success_arm.1, success_arm.2),
        ("guarded", "exhaustive"),
        "strict acyclic pre-origin gaps cannot bypass the retained guard: {result:#?}"
    );
    assert_eq!(
        (unrelated_failure_arm.1, unrelated_failure_arm.2),
        ("unguarded", "exhaustive"),
        "the unrelated failure-arm use remains an exact negative: {result:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "f8d76596f9f7: confine a modeled negative result arm despite a non-rejoining sibling call"
)]
fn modeled_negative_arm_closes_a_use_despite_a_nonrejoining_sibling_call() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[
            ("go.mod", GO_WRAPPER_MODULE),
            ("internal/errors/errors.go", EXACT_ERRORS_IS_WRAPPER),
            (
                "main.go",
                r#"package main

import (
    wrapped "example.com/app/internal/errors"
    "os"
)

type Printer interface { Println(string) }

func useOnFalseOutcome(path string, printer Printer) string {
    file, err := os.Open(path)
    if wrapped.Is(err, os.ErrNotExist) {
        printer.Println(file.Name())
        return ""
    }
    return file.Name()
}
"#,
            ),
        ],
        "result_contract_operation_uses",
    );

    let mut answers = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
                panic!("result_contract_operation_uses returns its typed row: {item:#?}")
            };
            assert_eq!(value.member.as_deref(), Some("Name"), "{value:#?}");
            assert_eq!(value.applicability, "required", "{value:#?}");
            (value.range.start_line, value.guard, value.coverage)
        })
        .collect::<Vec<_>>();
    answers.sort_unstable_by_key(|(line, _, _)| *line);
    let [true_arm, false_arm] = answers.as_slice() else {
        panic!("two exact result operations: {result:#?}")
    };
    assert!(true_arm.0 < false_arm.0, "{result:#?}");
    assert_eq!(
        (true_arm.1, true_arm.2),
        ("unknown", "open"),
        "the open true arm remains unknown: {result:#?}"
    );
    assert_eq!(
        (false_arm.1, false_arm.2),
        ("unguarded", "exhaustive"),
        "the batched negative proof stays aligned to the false-arm and opposite-arm uses: {result:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn failure_arm_modeled_conditional_positive_stays_open_without_a_collective_proof() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

func modeledConditionalOnFailureArm(path string) string {
    file, err := os.Open(path)
    if err != nil {
        if predicate.IsNil(err) {
        } else {
            return ""
        }
    }
    return file.Name()
}
"#,
    );

    assert_single_guarded_open_unknown_result_contract(&result);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "5c5d4e214494: operation validation must use exact Go preconditions and invocation results"
)]
fn modeled_member_argument_validator_guards_at_invocation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

func guardedInArgument(path string) {
    file, err := os.Open(path)
    file.Use(predicate.Checked(err))
}
"#,
    );

    assert_single_exhaustive_satisfied_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "eb52f52ac7d4: detached calls cannot refine the parent continuation"
)]
fn detached_normal_return_refinement_does_not_guard_parent_continuation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

func detachedValidation(path string) string {
    file, err := os.Open(path)
    go predicate.Checked(err)
    return file.Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "5c5d4e214494: operation validation must use exact Go preconditions and invocation results"
)]
fn later_member_argument_mutation_does_not_preserve_modeled_validation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "errors"
    "os"
    predicate "example.com/predicate"
)

func invalidate(target *error) string {
    *target = errors.New("late failure")
    return "invalidated"
}

func invalidatedInLaterArgument(path string) {
    file, err := os.Open(path)
    file.UseTwo(predicate.Checked(err), invalidate(&err))
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "5c5d4e214494: operation validation must use exact Go preconditions and invocation results"
)]
fn earlier_member_argument_escape_does_not_preserve_modeled_validation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

type lateError struct{}
func (lateError) Error() string { return "late failure" }

func publish(target *error) string {
    go func() { *target = lateError{} }()
    return "published"
}

func escapedInEarlierArgument(path string) {
    file, err := os.Open(path)
    file.UseTwo(publish(&err), predicate.Checked(err))
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "43e04492475f: captured cell loads and stores must preserve ordered result-use evidence"
)]
fn captured_member_argument_mutation_after_validation_preserves_the_modeled_result() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

type capturedError struct{}
func (capturedError) Error() string { return "captured failure" }

func mutatedThroughCapture(path string) {
    file, err := os.Open(path)
    mutate := func() string {
        err = capturedError{}
        return "mutated"
    }
    file.UseTwo(predicate.Checked(err), mutate())
}
"#,
    );

    assert_single_exhaustive_satisfied_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "5c5d4e214494: operation validation must use exact Go preconditions and invocation results"
)]
fn unmodeled_member_argument_validator_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func checked(err error) string {
    if err != nil { panic(err) }
    return "checked"
}

func maybeGuardedInArgument(path string) {
    file, err := os.Open(path)
    file.Use(checked(err))
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "5c5d4e214494: operation validation must use exact Go preconditions and invocation results"
)]
fn parenthesized_direct_receiver_retains_exact_unguarded_use() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func parenthesizedReceiver(path string) string {
    file, _ := os.Open(path)
    return (file).Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "5c5d4e214494: operation validation must use exact Go preconditions and invocation results"
)]
fn captured_child_keeps_result_use_validation_unknown() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func captured(path string) string {
    opened, _ := os.Open(path)
    file := opened
    invoke := func() string { return file.Name() }
    return invoke()
}
"#,
    );

    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.unguarded_result_use_count, None, "{value:#?}");
    assert_eq!(value.use_validation, Some("unknown"), "{value:#?}");
    assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "43e04492475f: captured cell loads and stores must preserve ordered result-use evidence"
)]
fn later_capture_retains_both_the_earlier_direct_and_captured_result_uses() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func observe(*os.File) {}

func useBeforeCapture(t *testing.T, path string) string {
    file, err := os.Open(path)
    check.NoError(t, err)
    name := file.Name()
    go func() { observe(file) }()
    return name
}
"#,
    );

    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "the captured observation remains honestly open: {result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.result_use_count, Some(2), "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.use_validation, Some("violated"), "{value:#?}");
    assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn spawned_assertion_result_does_not_guard_later_result_use() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func observe(bool) {}

func spawnedAssertionConsumer(t *testing.T, path string) string {
    file, err := os.Open(path)
    go observe(check.NoError(t, err))
    return file.Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "eb52f52ac7d4: detached calls cannot refine the parent continuation"
)]
fn detached_assertion_result_sent_back_to_parent_keeps_the_use_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func send(result bool, results chan bool) { results <- result }

func spawnedAssertionFeedback(t *testing.T, path string, results chan bool) string {
    file, err := os.Open(path)
    go send(check.NoError(t, err), results)
    if <-results {
        return file.Name()
    }
    return ""
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "eb52f52ac7d4: detached calls cannot refine the parent continuation"
)]
fn detached_assertion_feedback_across_a_blocking_receive_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func sendSuccess(result bool, results chan bool) {
    if result {
        results <- result
    }
}

func spawnedAssertionFeedback(t *testing.T, path string, results chan bool) string {
    file, err := os.Open(path)
    go sendSuccess(check.NoError(t, err), results)
    <-results
    return file.Name()
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "eb52f52ac7d4: detached calls cannot refine the parent continuation"
)]
fn detached_assertion_feedback_across_an_ordinary_call_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func send(result bool, results chan bool) { results <- result }
func waitForSuccess(results chan bool) { <-results }

func spawnedAssertionFeedback(t *testing.T, path string, results chan bool) string {
    file, err := os.Open(path)
    go send(check.NoError(t, err), results)
    waitForSuccess(results)
    return file.Name()
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "eb52f52ac7d4: detached calls cannot refine the parent continuation"
)]
fn detached_assertion_feedback_across_unspecified_operand_order_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func send(result bool, results chan bool) { results <- result }
func waitForSuccess(results chan bool) string { <-results; return "" }
func combine(left os.File, right string) string { return left.Name() + right }

func spawnedAssertionFeedback(t *testing.T, path string, results chan bool) string {
    file, err := os.Open(path)
    go send(check.NoError(t, err), results)
    return combine(*file, waitForSuccess(results))
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn result_contract_uses_executes_the_projected_contract_wrapper() {
    let source = r#"package main

import "os"

func observe(error) {}

func unchecked() string {
    file, _ := os.Open("missing.xlsx")
    return file.Name()
}

func earlyUse() string {
    file, err := os.Open("missing.xlsx")
    name := file.Name()
    observe(err)
    file.Close()
    return name
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-result-contract",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": { "source": "test:rql-result-contract", "revision": "reviewed" },
        "license": "Apache-2.0",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.os.open",
            "activation": [{}],
            "payload": {
                "kind": "procedure_summaries",
                "summaries": [{
                    "id": "os.open",
                    "target": {
                        "path": "src/os/file.go",
                        "symbol": "os.Open(name string)",
                        "has_receiver": false,
                        "parameter_count": 1
                    },
                    "completeness": "complete",
                    "normal_result_count": 2,
                    "transfers": [],
                    "effects": [],
                    "result_contracts": [{
                        "result_ordinal": 0,
                        "condition_result_ordinal": 1,
                        "predicate": "null",
                        "result_success_predicate": "non_null",
                        "member_contracts": [
                            {
                                "member": "Name",
                                "parameter_count": 0,
                                "completeness": "complete",
                                "preconditions": [{
                                    "input": { "kind": "receiver" },
                                    "predicate": "non_null"
                                }],
                                "declared_effects": []
                            },
                            {
                                "member": "Close",
                                "parameter_count": 0,
                                "completeness": "complete",
                                "preconditions": [],
                                "declared_effects": []
                            }
                        ]
                    }]
                }]
            }
        }]
    }"#;
    let declaration_pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-result-contract-declarations",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": {
            "source": "test:rql-result-contract-declarations",
            "revision": "reviewed"
        },
        "license": "Apache-2.0",
        "completeness": "partial",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.os.declarations",
            "activation": [{}],
            "payload": {
                "kind": "declaration_facts",
                "types": [
                    {
                        "id": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                        "name": "os",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["os"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os"
                        }
                    },
                    {
                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "os.File",
                        "type_kind": "struct",
                        "visibility": "public",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "struct{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os.File"
                        }
                    }
                ],
                "members": [{
                    "id": "member.e969c07a9215c885c075e9f2767d17d39f10922eb0ff1394d8222dd7dc40f38e",
                    "owner": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                    "name": "Open",
                    "member_kind": "function",
                    "visibility": "public",
                    "is_static": true,
                    "is_abstract": false,
                    "is_virtual": false,
                    "signature": {
                        "type_parameters": [],
                        "parameters": [{
                            "name": "name",
                            "type": {
                                "kind": "named",
                                "name": "string",
                                "arguments": [],
                                "nullable": false
                            },
                            "optional": false,
                            "variadic": false
                        }],
                        "returns": {
                            "kind": "tuple",
                            "elements": [
                                {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                {
                                    "kind": "named",
                                    "name": "error",
                                    "arguments": [],
                                    "nullable": false
                                }
                            ]
                        }
                    },
                    "aliases": [],
                    "locator": {
                        "kind": "artifact",
                        "path": "os/os.go",
                        "symbol": "os.Open"
                    }
                }]
            }
        }]
    }"#;
    let pack = compile_source(SourceFormat::Json, pack_source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("result-contract pack failed: {diagnostics:#?}"));
    let declaration_pack = compile_source(
        SourceFormat::Json,
        declaration_pack_source,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| {
        panic!("result-contract declaration pack failed: {diagnostics:#?}")
    });
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-result-contract".to_owned(),
            },
        )
        .expect("register result-contract pack");
    catalog
        .register_session_pack(
            &declaration_pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-result-contract-declarations".to_owned(),
            },
        )
        .expect("register exact result-contract declarations");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "test result-contract pack activates: {activation:#?}"
    );

    // Calibrate the exact nested-entry work of one artifact census plus the
    // three real source-dispatch operations: the two modeled calls plus the
    // `observe(err)` candidate that result-use validation checks for a normal-
    // return refinement. The RQL path below must fit that ledger exactly.
    // Calling materialization again inside any dispatch
    // adds one repeat-cache charge and therefore fails this regression even
    // though all genuine dispatch work still has room.
    let file = project.file("main.go");
    let cancellation = CancellationToken::default();
    let mut setup_budget = SemanticBudget::default();
    let materialized = workspace
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut setup_budget, &cancellation),
        )
        .expect("Go artifact materialization");
    let artifact = materialized
        .available_value()
        .cloned()
        .expect("Go artifact remains available");
    let artifact_nested = artifact.work().nested_entries;
    let mut dispatch_ranges = Vec::new();
    for procedure in artifact.procedures() {
        for call in procedure.call_sites() {
            let mapping = procedure
                .source_mapping(call.source)
                .expect("validated semantic call has a source mapping");
            let span = mapping.locator.anchor().span();
            let start = span.start_byte() as usize;
            let end = span.end_byte() as usize;
            if source
                .get(start..end)
                .is_some_and(|text| text.starts_with("os.Open(") || text == "observe(err)")
                && !dispatch_ranges
                    .iter()
                    .any(|range: &Range| range.start_byte == start && range.end_byte == end)
            {
                dispatch_ranges.push(Range {
                    start_byte: start,
                    end_byte: end,
                    start_line: span.start().line() as usize,
                    end_line: span.end().line() as usize,
                });
            }
        }
    }
    dispatch_ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    assert_eq!(
        dispatch_ranges.len(),
        3,
        "two os.Open calls and one modeled-validator candidate"
    );

    let mut required_nested = artifact_nested;
    let mut calibrated_dispatch_nested = Vec::new();
    for range in dispatch_ranges {
        let mut direct_budget = SemanticBudget::default();
        let direct = workspace
            .semantic_oracle_provider()
            .dispatch_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut direct_budget, &cancellation),
            )
            .expect("direct source dispatch");
        assert!(
            direct.available_value().is_some() && direct.budget_exceeded().is_none(),
            "calibration dispatch remains available: {direct:#?}"
        );
        let dispatch_nested = direct_budget
            .used()
            .nested_entries
            .checked_sub(artifact_nested)
            .expect("direct dispatch includes one artifact census");
        calibrated_dispatch_nested.push(dispatch_nested);
        required_nested = required_nested.saturating_add(dispatch_nested);
    }
    // `result_contract_uses` is a second bounded artifact window. Reopening
    // the same artifact under the same semantic ledger performs one honest
    // repeat-cache lookup; unlike the removed per-dispatch materialization,
    // this lookup owns the next pipeline stage's artifact lifetime.
    required_nested = required_nested.saturating_add(1);
    assert!(required_nested > artifact_nested);

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "result_contract_calls" },
            { "op": "call_result_contracts" },
            { "op": "result_contract_uses" }
        ],
        "result_detail": "full"
    }))
    .expect("result-contract use query");

    let defaults = CodeQueryExecutionLimits::default();
    let default_rows = semantic::semantic_budget_limits(defaults.semantic);
    let limits = CodeQueryExecutionLimits {
        semantic: CodeQuerySemanticLimits {
            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                if dimension == SemanticBudgetDimension::NestedEntries {
                    required_nested
                } else {
                    default_rows.get(dimension)
                }
            })),
            ..defaults.semantic
        },
        ..defaults
    };
    let execution = super::super::execute_internal(
        workspace.analyzer(),
        Some(&workspace),
        &query,
        limits,
        None,
        None,
        false,
    );
    let result = execution.result;

    assert_eq!(
        execution.work.semantic.nested_entries,
        u64::try_from(required_nested).expect("test semantic work fits u64"),
        "artifact={artifact_nested}, dispatch={calibrated_dispatch_nested:?}"
    );
    assert_eq!(execution.work.semantic.materialization_attempts, 2);
    assert_eq!(execution.work.semantic.unique_materialized_files, 1);
    assert!(execution.work.semantic.request_cache_hits > 0);
    assert!(
        result.diagnostics.iter().all(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }),
        "cached full result-contract dispatch must fit its exact calibrated ledger: {result:#?}"
    );

    assert!(
        matches!(result.completion(), CodeQueryCompletion::Complete),
        "the exact early violation closes the only guarded operation: {result:#?}"
    );
    let [unchecked, early] = result.results.as_slice() else {
        panic!("two projected result contracts: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value: unchecked } = &unchecked.value else {
        panic!("result-contract wrapper returns its typed row: {unchecked:#?}")
    };
    assert_eq!(unchecked.result_use_count, Some(1));
    assert_eq!(unchecked.unguarded_result_use_count, Some(1));
    assert_eq!(unchecked.use_validation, Some("violated"));
    assert_eq!(unchecked.use_validation_coverage, Some("exhaustive"));

    let CodeQueryResultValue::CallResultContract { value: early } = &early.value else {
        panic!("result-contract wrapper returns its typed row: {early:#?}")
    };
    assert_eq!(
        early.result_use_count,
        Some(2),
        "Name and nil-tolerant Close are both exact structured operations"
    );
    assert_eq!(
        early.unguarded_result_use_count,
        Some(1),
        "only Name carries the reviewed non-null receiver precondition"
    );
    assert_eq!(early.use_validation, Some("violated"));
    assert_eq!(early.use_validation_coverage, Some("exhaustive"));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#2779: report one root-cap truncation diagnostic without a duplicate backstop"
)]
fn union_query_over_root_limit_reports_exactly_one_truncation_diagnostic() {
    // Regression for issue #2779: a query whose logical plan wraps a `union`
    // set operator directly in the root `Limit` (`query.limit`) must report
    // `truncated=true` and name the cap that caused it, exactly once. This is
    // the shape the OWASP xss selector hit: more matching rows than the
    // policy-overridden `query.limit`, executed through the same detailed
    // path a policy selector uses
    // (`execute_code_query_detailed_eager_index`). The `Limit` operator's own
    // `push_truncation_diagnostic` call already fires whenever its direct
    // child (here, the `union` set) returns more rows than `count`, so this
    // pins that the new root-terminal-cap backstop
    // (`needs_root_terminal_cap_diagnostic`) does not add a second, duplicate
    // diagnostic for the same truncation.
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for i in 0..5 {
        ProjectFile::new(root.clone(), PathBuf::from(format!("f{i}.ts")))
            .write("function first() {}\nfunction second() {}\nfunction third() {}\n")
            .expect("write source");
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branches: Vec<_> = (0..5)
        .map(|i| json!({ "where": [format!("f{i}.ts")], "match": { "kind": "function" } }))
        .collect();
    let query = CodeQuery::from_json(&json!({
        "union": branches,
        "limit": 3
    }))
    .expect("query");

    let detailed = execute_code_query_detailed_eager_index(
        &analyzer,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );

    assert!(detailed.result.truncated);
    assert_eq!(detailed.result.results.len(), 3);
    assert_eq!(
        detailed
            .result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ResultLimitReached)
            .count(),
        1,
        "exactly one truncation diagnostic, no double report: {:?}",
        detailed.result.diagnostics
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#2897: keep truncation diagnostics reproducible across cold and warm query runs"
)]
fn a_truncated_query_reports_identical_diagnostics_on_every_run() {
    // Regression for issue #2897: `result_limit_reached` interpolated the live
    // budget counters (`scanned_files`, `fact_nodes`, ...), which depend on
    // worker scheduling and on how far the scan got before the limit tripped.
    // Two executions of one query over an unchanged workspace reported
    // different messages (5178 facts on one run, 4927 on the next), so a
    // truncated result could not be documented, diffed, or snapshotted; the
    // #1132 cookbook had to drop its `limit: 2` example for that reason. The
    // second run below reuses the warm analyzer, which is the state that made
    // the counters diverge.
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for i in 0..8 {
        ProjectFile::new(root.clone(), PathBuf::from(format!("f{i}.ts")))
            .write("function first() {}\nfunction second() {}\nfunction third() {}\n")
            .expect("write source");
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "languages": ["typescript"],
        "match": { "kind": "function" },
        "limit": 2
    }))
    .expect("query");

    let first = execute(&analyzer, &query);
    let second = execute(&analyzer, &query);

    assert!(first.truncated, "{:?}", first.diagnostics);
    assert_eq!(first.results.len(), 2);
    assert_eq!(
        first
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.message.as_str()))
            .collect::<Vec<_>>(),
        vec![(
            CodeQueryDiagnosticCode::ResultLimitReached,
            "query_code reached the query limit of 2 and returned the first 2 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern",
        )],
    );
    assert_eq!(
        serde_json::to_value(&first).expect("serialize first run"),
        serde_json::to_value(&second).expect("serialize second run"),
        "two runs of one truncating query over an unchanged workspace must agree",
    );
}

/// A `builtins` subset in the schema the pack generator emits: `object` with
/// the members every class inherits, `int` with no members of its own, and
/// `str` with `strip`. The class-set steps need an active pack to classify
/// literals as `builtins.*`; the shipped typeshed pack is a generator spec, so
/// the tests compile this fixture pack the way `python_dependency_pack.rs`
/// does.
const TYPE_FLOW_BUILTINS_PACK: &str = r#"{
  "schema_version": 2,
  "pack_id": "fixture.type-flow-builtins",
  "version": "2026.9.2",
  "producer": { "name": "bifrost-fixture", "version": "1.0.0" },
  "language": "python",
  "ecosystem": "python",
  "compatibility": {
    "bifrost": ">=0.8.0, <1.0.0",
    "toolchains": [{ "name": "cpython", "requirement": ">=3.10.0, <3.15.0" }]
  },
  "provenance": { "source": "checked-in test source", "revision": "fixture-v1" },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "python.builtins",
    "activation": [{
      "toolchain": { "name": "cpython", "version": ">=3.10.0, <3.15.0" },
      "targets": []
    }],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "type.builtins-object",
        "name": "builtins.object",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.object" }
      }, {
        "id": "type.builtins-int",
        "name": "builtins.int",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [{ "hierarchy_kind": "extends", "target": { "kind": "named", "name": "builtins.object" } }],
        "aliases": [],
        "extension_surfaces": [],
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.int" }
      }, {
        "id": "type.builtins-str",
        "name": "builtins.str",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [{ "hierarchy_kind": "extends", "target": { "kind": "named", "name": "builtins.object" } }],
        "aliases": [],
        "extension_surfaces": [],
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.str" }
      }],
      "members": [{
        "id": "member.builtins-object.class",
        "owner": "type.builtins-object",
        "name": "__class__",
        "member_kind": "property",
        "visibility": "public",
        "is_static": false,
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.object.__class__" }
      }, {
        "id": "member.builtins-object.eq",
        "owner": "type.builtins-object",
        "name": "__eq__",
        "member_kind": "method",
        "visibility": "public",
        "is_static": false,
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.object.__eq__" }
      }, {
        "id": "member.builtins-str.strip",
        "owner": "type.builtins-str",
        "name": "strip",
        "member_kind": "method",
        "visibility": "public",
        "is_static": false,
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.str.strip" }
      }],
      "relations": []
    }
  }]
}"#;

#[test]
fn enclosing_decl_keeps_nested_source_filters_out_of_model_augmentation() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("SourceClass.java", "class SourceClass {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    // Engine-only model fixture: an ordinary public class has no source
    // declaration attributes for the source-only predicates below to inspect.
    let source = json!({
        "schema_version": 2,
        "pack_id": "test.rql.java-source-declaration-filters",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "java",
        "ecosystem": "maven",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": { "source": "test:rql-4365-declaration-filters", "revision": "reviewed" },
        "license": "Apache-2.0",
        "completeness": "partial",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "java.declarations",
            "activation": [{}],
            "payload": {
                "kind": "declaration_facts",
                "types": [{
                    "id": "type.example.ordinary",
                    "name": "example.Ordinary",
                    "type_kind": "class",
                    "visibility": "public",
                    "is_abstract": false,
                    "is_sealed": false,
                    "type_parameters": [],
                    "hierarchy": [],
                    "aliases": [],
                    "extension_surfaces": [],
                    "locator": { "kind": "artifact", "path": "Ordinary.java", "symbol": "example.Ordinary" }
                }],
                "members": [],
                "relations": []
            }
        }]
    });
    let pack = compile_source(
        SourceFormat::Json,
        source.to_string().as_bytes(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("declaration fixture compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-4365-declaration-filters".to_owned(),
            },
        )
        .expect("register engine-only declaration fixture");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".to_owned(),
                ecosystem: "maven".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    let SemanticModelRuntimeOutcome::Ready { snapshot, .. } = activation else {
        panic!("declaration fixture activates: {activation:#?}");
    };
    let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        Some(snapshot),
    );
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let baseline = execute_workspace(
        &workspace,
        &flow,
        &CodeQuery::from_sexp("(enclosing-decl (language java (class)))")
            .expect("unfiltered modeled declarations"),
    );
    assert!(
        baseline.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::Declaration { value } if value.fq_name == "example.Ordinary"
        )),
        "the model must participate before testing exclusions: {baseline:#?}"
    );
    for source in [
        r#"(enclosing-decl (language java (class :and [(type-kind "interface")])))"#,
        r#"(enclosing-decl (language java (class :and [(modifier "abstract")])))"#,
        r#"(enclosing-decl (language java (class :or [(type-kind "interface") (modifier "abstract")])))"#,
        r#"(enclosing-decl (language java (class :not (type-kind "class"))))"#,
    ] {
        let query = CodeQuery::from_sexp(source).expect("composed declaration filter");
        let result = execute_workspace(&workspace, &flow, &query);
        assert!(result.results.is_empty(), "{source}: {result:#?}");
    }
}

#[test]
fn anchor_step_reports_a_named_capture_range_and_keeps_the_structural_root() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "if True:\n    nested = 1\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        r#"(result-detail full
             (anchor :capture "test"
               (language python
                 (if :test (literal :capture "test")))))"#,
    )
    .expect("captured conditional test query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert_eq!(result.results.len(), 1, "{}", result.render_text());
    let CodeQueryResultValue::StructuralMatch { value } = &result.results[0].value else {
        panic!(
            "anchor preserves the structural match result: {:#?}",
            result.results
        );
    };
    assert_eq!(value.kind, "if");
    assert_eq!(value.text, "True");
    assert_eq!(value.node_range.unwrap().start_column, 4);
    assert_eq!(value.node_range.unwrap().end_column, 8);
    assert_eq!(value.captures.len(), 1);
    assert_eq!(value.captures[0].text, "True");
}

#[test]
fn python_ordered_collection_index_selects_the_exact_element() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "pair = (\"first\", \"second\")\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "collection_literal",
            "elements": [{
                "kind": "string_literal",
                "index": 1,
                "capture": "selected"
            }]
        }
    }))
    .expect("indexed collection query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert_eq!(result.results.len(), 1, "{}", result.render_text());
    let CodeQueryResultValue::StructuralMatch { value } = &result.results[0].value else {
        panic!(
            "structural query returns a structural match: {:#?}",
            result.results
        );
    };
    assert_eq!(value.text, "(\"first\", \"second\")");
    assert_eq!(value.captures.len(), 1);
    assert_eq!(value.captures[0].name, "selected");
    assert_eq!(value.captures[0].text, "\"second\"");

    let tuple_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "tuple_literal",
            "elements": [{
                "kind": "string_literal",
                "index": 1,
                "capture": "selected"
            }]
        }
    }))
    .expect("tuple-literal element query");
    let tuple = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &tuple_query,
    );
    assert_eq!(tuple.results.len(), 1, "{}", tuple.render_text());
    let CodeQueryResultValue::StructuralMatch { value } = &tuple.results[0].value else {
        panic!("tuple query returns a structural match");
    };
    assert_eq!(value.text, "(\"first\", \"second\")");
    assert_eq!(value.captures.len(), 1);
    assert_eq!(value.captures[0].text, "\"second\"");
}

#[test]
fn python_dictionary_pairs_and_parenthesized_string_parts_are_structural() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            "mapping = {\"$where\": \"query\"}\nvalues = [\"left\" \"right\", (\"paren\" \"concat\")]\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let dictionary_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "collection_literal",
            "elements": [{
                "kind": "object_property",
                "index": 0,
                "key": { "kind": "string_literal", "capture": "key" },
                "value": { "kind": "string_literal", "capture": "value" }
            }]
        }
    }))
    .expect("dictionary key/value query");
    let dictionary = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &dictionary_query,
    );
    assert_eq!(dictionary.results.len(), 1, "{}", dictionary.render_text());
    let CodeQueryResultValue::StructuralMatch { value } = &dictionary.results[0].value else {
        panic!("dictionary query returns a structural match");
    };
    let mut captured_pair = value
        .captures
        .iter()
        .map(|capture| (capture.name.as_str(), capture.text.as_str()))
        .collect::<Vec<_>>();
    captured_pair.sort_unstable();
    assert_eq!(
        captured_pair,
        [("key", "\"$where\""), ("value", "\"query\"")]
    );

    let unparenthesized_concat_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "collection_literal",
            "elements": [{
                "kind": "string_literal",
                "index": 0,
                "parenthesized": false,
                "parts": [
                    { "kind": "string_literal", "index": 0, "capture": "first" },
                    { "kind": "string_literal", "index": 1, "capture": "second" }
                ]
            }]
        }
    }))
    .expect("unparenthesized list concatenation query");
    let unparenthesized_concat = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &unparenthesized_concat_query,
    );
    assert_eq!(
        unparenthesized_concat.results.len(),
        1,
        "{}",
        unparenthesized_concat.render_text()
    );
    let CodeQueryResultValue::StructuralMatch { value } = &unparenthesized_concat.results[0].value
    else {
        panic!("unparenthesized concatenation query returns a structural match");
    };
    assert_eq!(
        value
            .captures
            .iter()
            .map(|capture| (capture.name.as_str(), capture.text.as_str()))
            .collect::<Vec<_>>(),
        [("first", "\"left\""), ("second", "\"right\"")]
    );

    let concat_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "collection_literal",
            "elements": [{
            "kind": "string_literal",
            "index": 1,
            "parenthesized": true,
            "parts": [
                    { "kind": "string_literal", "index": 0, "capture": "first" },
                    { "kind": "string_literal", "index": 1, "capture": "second" }
                ]
            }]
        }
    }))
    .expect("parenthesized implicit-concatenation query");
    let concat = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &concat_query,
    );
    assert_eq!(concat.results.len(), 1, "{}", concat.render_text());
    let CodeQueryResultValue::StructuralMatch { value } = &concat.results[0].value else {
        panic!("concatenation query returns a structural match");
    };
    assert_eq!(
        value
            .captures
            .iter()
            .map(|capture| (capture.name.as_str(), capture.text.as_str()))
            .collect::<Vec<_>>(),
        [("first", "\"paren\""), ("second", "\"concat\"")]
    );
}

#[test]
fn python_duplicate_dictionary_keys_compare_decoded_literals_and_mark_unknowns_incomplete() {
    let source = r#"values = {
    "same": 0,
    "s\x61me": 1,
    0x10: 2,
    16: 3,
    True: 4,
    1: 5,
    None: 6,
    None: 7,
    (2, 3): 8,
    make_key(): 9,
    1.5: 10,
}
"#;
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "object_property",
            "duplicate_key": true,
            "key": { "capture": "key" }
        }
    }))
    .expect("duplicate dictionary key query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let mut keys = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::StructuralMatch { value } = &item.value else {
                panic!("duplicate-key query returns structural matches");
            };
            value
                .captures
                .iter()
                .find(|capture| capture.name == "key")
                .expect("key capture")
                .text
                .clone()
        })
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, ["\"s\\x61me\"", "1", "16", "None"]);
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::UnsupportedStructuralFeature
                && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
                && diagnostic.message.contains("unsupported")
        }),
        "{}",
        result.render_text()
    );
}

#[test]
fn python_direct_assignment_shapes_pair_counts_and_keep_starred_state() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            "a, b = c, d, e\nx, *rest = y, z, w\n[left, right] = [one, two, three]\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let mismatch_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "assignment",
            "assignment_unstarred_count_mismatch": true,
            "assignment_target_starred": false,
            "assignment_value_starred": false
        }
    }))
    .expect("direct assignment-shape query");
    let mismatch = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &mismatch_query,
    );
    assert_eq!(mismatch.results.len(), 2, "{}", mismatch.render_text());
    let mut assignments = mismatch
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::StructuralMatch { value } = &item.value else {
                panic!("assignment shape query returns structural rows");
            };
            value.text.as_str()
        })
        .collect::<Vec<_>>();
    assignments.sort_unstable();
    assert_eq!(
        assignments,
        ["[left, right] = [one, two, three]", "a, b = c, d, e"]
    );

    let starred_query = CodeQuery::from_sexp(
        "(language python (assignment :assignment-target-kind tuple :assignment-target-unstarred-count 1 :assignment-target-starred true))",
    )
    .expect("starred assignment RQL");
    let starred = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &starred_query,
    );
    assert_eq!(starred.results.len(), 1, "{}", starred.render_text());
    let CodeQueryResultValue::StructuralMatch { value } = &starred.results[0].value else {
        panic!("starred assignment query returns a structural row");
    };
    assert_eq!(value.text, "x, *rest = y, z, w");
}

#[test]
fn python_integer_literals_keep_exact_values_and_permission_bits_at_mode_arguments() {
    let overlong_hex = format!("0x{}", "f".repeat(3500));
    let source = format!(
        "import os\nimport other\nos.chmod('secret', 0o777)\nos.chmod('secret', 0o600)\nos.chmod('secret', 511)\nos.chmod('secret', 0x1ff)\nos.chmod('secret', 0b1_1111_1111)\nos.chmod('secret', 0x1_0000_0000_0000_0000_0000_0002)\nos.chmod('secret', {overlong_hex})\nos.chmod('secret', 0o020)\nos.chmod('secret', mode=0o666)\nother.chmod('secret', 0o777)\nos.open('secret', os.O_CREAT, 0o777)\nos.open('secret', os.O_CREAT, 0o600)\n"
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("permissions.py", &source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let world_write_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "call",
            "name": "chmod",
            "receiver": { "name": "os" },
            "args": [{
                "index": 1,
                "kind": "numeric_literal",
                "integer_has_any_bits": 2
            }]
        }
    }))
    .expect("world-write mode query");
    let world_writes = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &world_write_query,
    );
    let mut calls = world_writes
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::StructuralMatch { value } = &item.value else {
                panic!("mode query returns structural call rows");
            };
            value.text.clone()
        })
        .collect::<Vec<_>>();
    calls.sort_unstable();
    let expected_calls = [
        "os.chmod('secret', 0b1_1111_1111)".to_owned(),
        "os.chmod('secret', 0o777)".to_owned(),
        "os.chmod('secret', 0x1_0000_0000_0000_0000_0000_0002)".to_owned(),
        "os.chmod('secret', 0x1ff)".to_owned(),
        "os.chmod('secret', 511)".to_owned(),
    ];
    assert_eq!(calls.len(), expected_calls.len() + 1);
    for expected_call in expected_calls {
        assert!(calls.contains(&expected_call), "{calls:?}");
    }

    let full_mask_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "call",
            "name": "chmod",
            "receiver": { "name": "os" },
            "args": [{
                "index": 1,
                "kind": "numeric_literal",
                "integer_has_all_bits": 4294967295u64
            }]
        }
    }))
    .expect("full-width permission mask query");
    let full_mask_matches = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &full_mask_query,
    );
    assert_eq!(full_mask_matches.results.len(), 1);
    let CodeQueryResultValue::StructuralMatch { value } = &full_mask_matches.results[0].value
    else {
        panic!("full mask query returns a structural call row");
    };
    assert!(value.text.starts_with("os.chmod('secret', 0x"));

    let canonical_value_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "call",
            "name": "chmod",
            "receiver": { "name": "os" },
            "args": [{
                "index": 1,
                "kind": "numeric_literal",
                "integer_value": "511"
            }]
        }
    }))
    .expect("canonical integer mode query");
    let canonical_values = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &canonical_value_query,
    );
    assert_eq!(canonical_values.results.len(), 4);

    let keyword_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "call",
            "name": "chmod",
            "receiver": { "name": "os" },
            "kwargs": {
                "mode": {
                    "kind": "numeric_literal",
                    "integer_has_all_bits": 2,
                    "integer_has_no_bits": 1
                }
            }
        }
    }))
    .expect("keyword mode query");
    let keyword_mode = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &keyword_query,
    );
    assert_eq!(keyword_mode.results.len(), 1);

    let group_write_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "call",
            "name": "chmod",
            "receiver": { "name": "os" },
            "args": [{
                "index": 1,
                "kind": "numeric_literal",
                "integer_has_any_bits": 16,
                "integer_has_no_bits": 7
            }]
        }
    }))
    .expect("group-write mode query");
    let group_writes = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &group_write_query,
    );
    assert_eq!(group_writes.results.len(), 1);

    let open_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {
            "kind": "call",
            "name": "open",
            "receiver": { "name": "os" },
            "args": [{
                "index": 2,
                "kind": "numeric_literal",
                "integer_has_any_bits": 2
            }]
        }
    }))
    .expect("os.open mode argument query");
    let open_modes = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &open_query,
    );
    assert_eq!(open_modes.results.len(), 1);
    let CodeQueryResultValue::StructuralMatch { value } = &open_modes.results[0].value else {
        panic!("open mode query returns structural call rows");
    };
    assert_eq!(value.text, "os.open('secret', os.O_CREAT, 0o777)");
}

/// The plan's Purpose example: `read_config` passes an `int` into a parameter
/// whose body calls `strip`, a member `builtins.int` does not declare.
const TYPE_FLOW_PURPOSE_FIXTURE: &str =
    "def normalize(x):\n    return x.strip()\n\ndef read_config():\n    return normalize(123)\n";

fn type_flow_workspace() -> (inline_project::BuiltInlineTestProject, WorkspaceAnalyzer) {
    type_flow_workspace_with_source(TYPE_FLOW_PURPOSE_FIXTURE)
}

fn type_flow_workspace_with_source(
    source: &str,
) -> (inline_project::BuiltInlineTestProject, WorkspaceAnalyzer) {
    let (project, workspace) = inline_project::python_workspace(&[("app.py", source)]);
    activate_type_flow_builtins(&workspace);
    (project, workspace)
}

fn activate_type_flow_builtins(workspace: &WorkspaceAnalyzer) {
    let pack = compile_source(
        SourceFormat::Json,
        TYPE_FLOW_BUILTINS_PACK.as_bytes(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("builtins fixture pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-type-flow.builtins".to_owned(),
            },
        )
        .expect("register builtins fixture pack");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "python".to_owned(),
                ecosystem: "python".to_owned(),
                package: None,
                module: None,
                toolchain: Some(crate::analyzer::semantic_model::CatalogCoordinate {
                    name: "cpython".to_owned(),
                    version: Some(Version::parse("3.12.0").expect("toolchain version parses")),
                }),
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "builtins fixture pack activates: {activation:#?}"
    );
}

fn type_flow_query(root: &str, op: &str) -> serde_json::Value {
    json!({
        "languages": ["python"],
        "match": { "kind": "function", "name": root },
        "steps": [
            { "op": "procedure_of" },
            { "op": op }
        ],
        "result_detail": "full"
    })
}

#[test]
fn conditional_declared_parameter_condition_states_its_closed_annotation() {
    let (_project, workspace) = type_flow_workspace_with_source(concat!(
        "class C:\n    pass\n\n",
        "class Unbounded[A]:\n",
        "    def write(self, agent: A, name, value):\n",
        "        setattr(agent, name, value)\n\n",
        "def check(space: C):\n",
        "    return space.missing\n",
    ));
    let mut query = type_flow_query("check", "absent_member");
    query["steps"][1]["finding_proof"] = json!("conditional");
    let query = CodeQuery::from_json(&query).expect("conditional absent-member query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let [item] = result.results.as_slice() else {
        panic!("the closed annotation yields one Conditional finding: {result:#?}");
    };
    let CodeQueryResultValue::AbsentMemberFinding { value } = &item.value else {
        panic!("absent_member returns its typed row: {item:#?}");
    };
    assert_eq!(value.proof, "conditional");
    let condition = value.condition.as_deref().expect("Conditional condition");
    assert!(
        condition.contains(
            "if `space` has type `C` (as annotated; no workspace subclass of `C` exists)"
        ),
        "the condition names the declared type and closed hierarchy: {condition}"
    );
}

#[test]
fn conditional_dynamic_write_condition_names_each_possible_write_site() {
    let (_project, workspace) = type_flow_workspace_with_source(concat!(
        "class ContinuousSpace:\n    pass\n\n",
        "class Unbounded[A]:\n",
        "    def write(self, agent: A, name, value):\n",
        "        setattr(agent, name, value)\n\n",
        "def check_space():\n",
        "    return ContinuousSpace()._agent_to_index\n",
    ));
    let mut query = type_flow_query("check_space", "absent_member");
    query["steps"][1]["finding_proof"] = json!("conditional");
    let query = CodeQuery::from_json(&query).expect("conditional absent-member query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let [item] = result.results.as_slice() else {
        panic!("the unbounded write yields one Conditional finding: {result:#?}");
    };
    let CodeQueryResultValue::AbsentMemberFinding { value } = &item.value else {
        panic!("absent_member returns its typed row: {item:#?}");
    };
    assert_eq!(value.proof, "conditional");
    let condition = value.condition.as_deref().expect("Conditional condition");
    assert!(
        condition.contains("unless one of the dynamic writes at app.py:6:")
            && condition.contains("installs `_agent_to_index`"),
        "the condition names the possible write site and member: {condition}"
    );
}

#[test]
fn field_slot_profile_reopens_persisted_index_without_rebuild_or_republication() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", TYPE_FLOW_PURPOSE_FIXTURE)
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("profile query");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    drop(cold_workspace);

    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("warm persisted workspace builds");
    activate_type_flow_builtins(&warm_workspace);
    let warm = execute_workspace_request(
        &warm_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let (CodeQueryResponse::Profile(cold), CodeQueryResponse::Profile(warm)) = (cold, warm) else {
        panic!("profile-mode queries return profiles");
    };
    assert_eq!(
        serde_json::to_value(&cold.result.results).expect("cold rows serialize"),
        serde_json::to_value(&warm.result.results).expect("warm rows serialize"),
        "persistent field-slot reuse must preserve canonical rows"
    );
    for result in [&cold.result, &warm.result] {
        assert!(
            result.diagnostics.iter().all(|diagnostic| !matches!(
                diagnostic.code,
                CodeQueryDiagnosticCode::Cancelled
                    | CodeQueryDiagnosticCode::SemanticProviderFailed
            )),
            "field-slot persistence must not introduce failure diagnostics: {result:#?}"
        );
    }

    let cold = cold.work.semantic.type_flow;
    assert_eq!(cold.field_slot_builds, 1, "{cold:#?}");
    assert_eq!(cold.field_slot_memory_hits, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_hits, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_misses, 1, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_rejections, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_publications, 1, "{cold:#?}");

    let warm = warm.work.semantic.type_flow;
    assert_eq!(warm.field_slot_builds, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_memory_hits, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_hits, 1, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_misses, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_rejections, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_publications, 0, "{warm:#?}");
}

#[test]
fn finding_free_root_result_persistence_reopens_before_discovery_and_serves_both_projections() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", "class Missing:\n    pass\ndef normalize(items):\n    ''.strip()\n    item = items[0]\n    if isinstance(item, Missing):\n        return item.absent\n")
        .build();
    let branch = json!({
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ]
    });
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "union": [branch.clone(), branch],
        "result_detail": "full"
    }))
    .expect("combined type-flow profile query");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let cold_store_snapshot = cold_workspace
        .store()
        .expect("persisted workspace has a store")
        .class_set_root_result_store_snapshot_for_test()
        .expect("cold root-result store snapshot");
    assert_eq!(cold_store_snapshot.generations.len(), 1);
    assert_eq!(cold_store_snapshot.results.len(), 1);
    assert!(!cold_store_snapshot.results[0].result.rows.is_empty());
    drop(cold_workspace);

    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("warm persisted workspace builds");
    activate_type_flow_builtins(&warm_workspace);
    assert_eq!(
        warm_workspace
            .store()
            .expect("persisted workspace has a store")
            .class_set_root_result_store_snapshot_for_test()
            .expect("pre-hit root-result store snapshot"),
        cold_store_snapshot
    );
    let warm = execute_workspace_request(
        &warm_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let absent_query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ],
        "result_detail": "full"
    }))
    .expect("absent-member profile query");
    let warm_absent = execute_workspace_request(
        &warm_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &absent_query,
    );
    assert_eq!(
        warm_workspace
            .store()
            .expect("persisted workspace has a store")
            .class_set_root_result_store_snapshot_for_test()
            .expect("post-hit root-result store snapshot"),
        cold_store_snapshot,
        "durable hits must not mutate rows or published_at"
    );
    let (CodeQueryResponse::Profile(cold), CodeQueryResponse::Profile(warm)) = (cold, warm) else {
        panic!("profile-mode queries return profiles");
    };
    let CodeQueryResponse::Profile(warm_absent) = warm_absent else {
        panic!("profile-mode query returns a profile");
    };
    assert!(
        cold.result.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ClassSetRow { value }
                if value.class.as_deref() == Some("builtins.str")
                    && value.origin == "external"
                    && value.status == "known"
        )),
        "the cold solve must publish a nonempty known external projection: {cold:#?}"
    );
    assert!(
        cold.result.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ClassSetRow { value }
                if value.class.as_deref() == Some("app.Missing")
                    && value.guard_only == Some(true)
        )),
        "guard-only evidence survives the projection: {cold:#?}"
    );
    assert!(
        cold.result
            .render_text()
            .contains("membership from guard only")
    );
    let guarded = cold
        .result
        .results
        .iter()
        .find(|item| {
            matches!(
                &item.value, CodeQueryResultValue::ClassSetRow { value }
                    if value.class.as_deref() == Some("app.Missing")
            )
        })
        .expect("guarded class row");
    assert!(matches!(
        guarded.value.row().field("guard_only"),
        Ok(Some(CodeQueryRowScalarRef::Boolean(true)))
    ));
    assert_eq!(
        serde_json::to_value(&cold.result.results).expect("cold rows serialize"),
        serde_json::to_value(&warm.result.results).expect("warm rows serialize"),
        "durable rows retain IDs, ordering, classes, reasons, status, and source ranges"
    );
    assert_eq!(
        serde_json::to_value(&cold.result.diagnostics).expect("cold diagnostics serialize"),
        serde_json::to_value(&warm.result.diagnostics).expect("warm diagnostics serialize")
    );

    let cold = cold.work.semantic.type_flow;
    // The union's second branch is a second semantic window. Handle-keyed
    // caches close with the first window, so that branch reopens the result
    // the first branch just published instead of reusing a query-local cache.
    assert_eq!(cold.root_result_persistence_hits, 1, "{cold:#?}");
    assert_eq!(cold.root_result_persistence_misses, 1, "{cold:#?}");
    assert_eq!(cold.root_result_persistence_rejections, 0, "{cold:#?}");
    assert_eq!(cold.root_result_store_failures, 0, "{cold:#?}");
    assert_eq!(cold.root_result_publications, 1, "{cold:#?}");
    assert_eq!(cold.solves, 1, "{cold:#?}");
    assert_eq!(cold.cache_hits, 0, "{cold:#?}");
    assert_eq!(cold.finding_rows, 0, "{cold:#?}");

    let warm = warm.work.semantic.type_flow;
    // Each union branch is its own semantic window, and both serve the
    // durable result before discovery.
    assert_eq!(warm.root_result_persistence_hits, 2, "{warm:#?}");
    assert_eq!(warm.root_result_persistence_misses, 0, "{warm:#?}");
    assert_eq!(warm.root_result_persistence_rejections, 0, "{warm:#?}");
    assert_eq!(warm.root_result_store_failures, 0, "{warm:#?}");
    assert_eq!(warm.root_result_publications, 0, "{warm:#?}");
    assert_eq!(warm.solves, 0, "{warm:#?}");
    assert_eq!(warm.cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.snapshot_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.snapshot_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.dispatch_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.dispatch_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.binding_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.binding_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.summary_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.summary_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.root_summary_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.root_summary_observation_rejections, 0, "{warm:#?}");
    assert_eq!(warm.published_summaries, 0, "{warm:#?}");
    assert!(warm.summary_profile.is_empty(), "{warm:#?}");
    assert_eq!(warm.class_set_rows, cold.class_set_rows, "{warm:#?}");
    assert!(warm.class_set_rows > 0, "{warm:#?}");
    assert_eq!(warm.finding_rows, 0, "{warm:#?}");

    assert!(warm_absent.result.results.is_empty(), "{warm_absent:#?}");
    let warm_absent = warm_absent.work.semantic.type_flow;
    assert_eq!(
        warm_absent.root_result_persistence_hits, 1,
        "{warm_absent:#?}"
    );
    assert_eq!(warm_absent.solves, 0, "{warm_absent:#?}");
    assert_eq!(warm_absent.finding_rows, 0, "{warm_absent:#?}");
}

#[test]
fn finding_free_root_result_persistence_preserves_multiple_unknown_reason_order() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file(
            "app.py",
            "def commit(message, marker):\n    return message.split(marker)[0].rstrip()\n",
        )
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "commit" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("class-set profile query");

    let mut runs = Vec::new();
    for _ in 0..2 {
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        activate_type_flow_builtins(&workspace);
        let response = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let CodeQueryResponse::Profile(profile) = response else {
            panic!("profile-mode query returns a profile");
        };
        runs.push(profile);
    }
    let origins = |profile: &CodeQueryProfile| {
        profile
            .result
            .results
            .iter()
            .map(|item| {
                let CodeQueryResultValue::ClassSetRow { value } = &item.value else {
                    panic!("class_set returns typed rows: {item:#?}");
                };
                value.origin.clone()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        origins(&runs[0]),
        vec![
            "unknown:root_parameter".to_string(),
            "unknown:unmodeled_load".to_string(),
        ],
        "the root receiver and indexed element retain independent Unknown reasons; \
         an indexed load does not inherit the split call's container classification"
    );
    assert_eq!(
        serde_json::to_value(&runs[0].result.results).unwrap(),
        serde_json::to_value(&runs[1].result.results).unwrap(),
        "cold projection and store canonicalization use one atom order"
    );
    assert_eq!(
        runs[0].work.semantic.type_flow.root_result_publications, 1,
        "{:#?}",
        runs[0]
    );
    assert_eq!(
        runs[1].work.semantic.type_flow.root_result_persistence_hits, 1,
        "{:#?}",
        runs[1]
    );
    assert_eq!(runs[1].work.semantic.type_flow.solves, 0, "{:#?}", runs[1]);
}

#[test]
fn root_result_persistence_misses_when_non_root_workspace_content_changes() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", "def normalize():\n    return ''.strip()\n")
        .file("sibling.py", "VALUE = 1\n")
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("class-set profile query");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(cold) = cold else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        cold.work.semantic.type_flow.root_result_publications, 1,
        "{cold:#?}"
    );
    let expected = serde_json::to_value(&cold.result.results).expect("cold rows serialize");
    let before = cold_workspace
        .store()
        .expect("persisted workspace has a store")
        .class_set_root_result_store_snapshot_for_test()
        .expect("cold root-result snapshot");
    assert_eq!(before.results.len(), 1);
    drop(cold_workspace);

    project
        .file("sibling.py")
        .write("VALUE = 2\n")
        .expect("edit non-root file");
    project.commit("change sibling only");
    let changed_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("changed persisted workspace builds");
    activate_type_flow_builtins(&changed_workspace);
    let changed = execute_workspace_request(
        &changed_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(changed) = changed else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        serde_json::to_value(&changed.result.results).unwrap(),
        expected,
        "a non-root edit rotates the generation without changing the root projection"
    );
    let changed_work = changed.work.semantic.type_flow;
    assert_eq!(
        changed_work.root_result_persistence_hits, 0,
        "{changed_work:#?}"
    );
    assert_eq!(
        changed_work.root_result_persistence_misses, 1,
        "{changed_work:#?}"
    );
    assert_eq!(
        changed_work.root_result_publications, 1,
        "{changed_work:#?}"
    );
    assert_eq!(changed_work.solves, 1, "{changed_work:#?}");

    let after = changed_workspace
        .store()
        .expect("persisted workspace has a store")
        .class_set_root_result_store_snapshot_for_test()
        .expect("changed root-result snapshot");
    assert_eq!(after.generations.len(), 2);
    assert_eq!(after.results.len(), 2);
    assert_eq!(
        after.results[0].result.key.root_public_digest,
        after.results[1].result.key.root_public_digest,
        "the unchanged root keeps its public identity"
    );
    assert_ne!(
        after.results[0]
            .result
            .key
            .generation
            .workspace_content_digest,
        after.results[1]
            .result
            .key
            .generation
            .workspace_content_digest,
        "the sibling edit rotates the whole-workspace generation"
    );
}

#[test]
fn zero_row_finding_free_root_result_persistence_reopens_as_a_hit() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", "def idle():\n    return 1\n")
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "idle" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("class-set profile query");

    let mut work = Vec::new();
    for _ in 0..2 {
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        activate_type_flow_builtins(&workspace);
        let response = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let CodeQueryResponse::Profile(profile) = response else {
            panic!("profile-mode query returns a profile");
        };
        assert!(profile.result.results.is_empty(), "{profile:#?}");
        work.push(profile.work.semantic.type_flow);
    }
    assert_eq!(work[0].root_result_publications, 1, "{:#?}", work[0]);
    assert_eq!(work[0].solves, 1, "{:#?}", work[0]);
    assert_eq!(work[1].root_result_persistence_hits, 1, "{:#?}", work[1]);
    assert_eq!(work[1].solves, 0, "{:#?}", work[1]);
}

#[test]
fn finding_bearing_root_result_persistence_never_publishes() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", TYPE_FLOW_PURPOSE_FIXTURE)
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ],
        "result_detail": "full"
    }))
    .expect("absent-member profile query");

    let mut runs = Vec::new();
    for _ in 0..2 {
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        activate_type_flow_builtins(&workspace);
        let response = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let CodeQueryResponse::Profile(profile) = response else {
            panic!("profile-mode query returns a profile");
        };
        runs.push(profile);
    }
    assert_eq!(
        serde_json::to_value(&runs[0].result.results).unwrap(),
        serde_json::to_value(&runs[1].result.results).unwrap()
    );
    for run in runs {
        let work = run.work.semantic.type_flow;
        assert_eq!(work.root_result_persistence_hits, 0, "{work:#?}");
        assert_eq!(work.root_result_persistence_misses, 1, "{work:#?}");
        assert_eq!(work.root_result_publications, 0, "{work:#?}");
        assert_eq!(work.solves, 1, "{work:#?}");
        assert_eq!(work.finding_rows, 1, "{work:#?}");
    }
}

#[test]
fn root_result_persistence_store_failure_falls_back_without_mutating_durable_rows() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", TYPE_FLOW_PURPOSE_FIXTURE)
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("class-set profile query");
    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(cold) = cold else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        cold.work.semantic.type_flow.root_result_publications, 1,
        "{cold:#?}"
    );
    drop(cold_workspace);

    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("warm persisted workspace builds");
    activate_type_flow_builtins(&warm_workspace);
    let store = warm_workspace
        .store()
        .expect("persisted workspace has a store");
    store.set_class_set_root_result_operational_failure_for_test(true);
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let fallback = execute_workspace_request(&warm_workspace, &flow_state, &query);
    let CodeQueryResponse::Profile(fallback) = fallback else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        serde_json::to_value(&cold.result.results).unwrap(),
        serde_json::to_value(&fallback.result.results).unwrap(),
        "an operational store failure falls back to the ordinary exact solve"
    );
    assert!(
        fallback
            .result
            .diagnostics
            .iter()
            .all(|diagnostic| !matches!(
                diagnostic.code,
                CodeQueryDiagnosticCode::Cancelled
                    | CodeQueryDiagnosticCode::SemanticProviderFailed
            ))
    );
    let fallback_work = fallback.work.semantic.type_flow;
    assert_eq!(
        fallback_work.root_result_store_failures, 1,
        "{fallback_work:#?}"
    );
    assert_eq!(
        fallback_work.root_result_persistence_hits, 0,
        "{fallback_work:#?}"
    );
    assert_eq!(
        fallback_work.root_result_publications, 0,
        "{fallback_work:#?}"
    );
    assert_eq!(fallback_work.solves, 1, "{fallback_work:#?}");

    store.set_class_set_root_result_operational_failure_for_test(false);
    let recovered = execute_workspace_request(&warm_workspace, &flow_state, &query);
    let CodeQueryResponse::Profile(recovered) = recovered else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        serde_json::to_value(&cold.result.results).unwrap(),
        serde_json::to_value(&recovered.result.results).unwrap()
    );
    let recovered = recovered.work.semantic.type_flow;
    assert_eq!(recovered.root_result_persistence_hits, 1, "{recovered:#?}");
    assert_eq!(recovered.root_result_store_failures, 0, "{recovered:#?}");
    assert_eq!(recovered.root_result_publications, 0, "{recovered:#?}");
    assert_eq!(recovered.solves, 0, "{recovered:#?}");
}

#[test]
fn root_result_persistence_corrupt_and_overcap_rows_fall_back_and_repair_atomically() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", "def normalize():\n    return ''.strip()\n")
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("class-set profile query");
    let workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted workspace builds");
    activate_type_flow_builtins(&workspace);
    let run = || {
        let response = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let CodeQueryResponse::Profile(profile) = response else {
            panic!("profile-mode query returns a profile");
        };
        profile
    };

    let cold = run();
    assert_eq!(
        cold.work.semantic.type_flow.root_result_publications, 1,
        "{cold:#?}"
    );
    let expected = serde_json::to_value(&cold.result.results).expect("cold rows serialize");
    let store = workspace.store().expect("persisted workspace has a store");

    store
        .corrupt_only_class_set_root_result_content_digest_for_test()
        .expect("corrupt sole retained digest");
    let corrupt = run();
    assert_eq!(
        serde_json::to_value(&corrupt.result.results).unwrap(),
        expected
    );
    let corrupt_work = corrupt.work.semantic.type_flow;
    assert_eq!(
        corrupt_work.root_result_persistence_rejections, 1,
        "{corrupt_work:#?}"
    );
    assert_eq!(
        corrupt_work.root_result_store_failures, 0,
        "{corrupt_work:#?}"
    );
    assert_eq!(
        corrupt_work.root_result_publications, 1,
        "{corrupt_work:#?}"
    );
    assert_eq!(corrupt_work.solves, 1, "{corrupt_work:#?}");

    store
        .oversize_only_class_set_root_result_row_count_for_test()
        .expect("oversize sole retained row count");
    let overcap = run();
    assert_eq!(
        serde_json::to_value(&overcap.result.results).unwrap(),
        expected
    );
    let overcap_work = overcap.work.semantic.type_flow;
    assert_eq!(
        overcap_work.root_result_persistence_rejections, 1,
        "{overcap_work:#?}"
    );
    assert_eq!(
        overcap_work.root_result_store_failures, 0,
        "{overcap_work:#?}"
    );
    assert_eq!(
        overcap_work.root_result_publications, 1,
        "{overcap_work:#?}"
    );
    assert_eq!(overcap_work.solves, 1, "{overcap_work:#?}");

    let recovered = run();
    assert_eq!(
        serde_json::to_value(&recovered.result.results).unwrap(),
        expected
    );
    let recovered = recovered.work.semantic.type_flow;
    assert_eq!(recovered.root_result_persistence_hits, 1, "{recovered:#?}");
    assert_eq!(recovered.root_result_publications, 0, "{recovered:#?}");
    assert_eq!(recovered.solves, 0, "{recovered:#?}");
}

#[test]
fn field_slot_store_failure_falls_back_without_publishing_a_memory_hit() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", TYPE_FLOW_PURPOSE_FIXTURE)
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("profile query");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(cold) = cold else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        cold.work.semantic.type_flow.field_slot_publications, 1,
        "{cold:#?}"
    );
    drop(cold_workspace);

    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("warm persisted workspace builds");
    activate_type_flow_builtins(&warm_workspace);
    let store = warm_workspace
        .store()
        .expect("persisted workspace has a store");
    store.set_class_set_field_slot_operational_failure_for_test(true);
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let failed_store = execute_workspace_request(&warm_workspace, &flow_state, &query);
    let CodeQueryResponse::Profile(failed_store) = failed_store else {
        panic!("profile-mode query returns a profile");
    };
    let failed_work = failed_store.work.semantic.type_flow;
    assert_eq!(failed_work.field_slot_builds, 1, "{failed_work:#?}");
    assert_eq!(failed_work.field_slot_memory_hits, 0, "{failed_work:#?}");
    assert_eq!(
        failed_work.field_slot_persistence_hits, 0,
        "{failed_work:#?}"
    );
    assert_eq!(
        failed_work.field_slot_persistence_misses, 0,
        "{failed_work:#?}"
    );
    assert_eq!(
        failed_work.field_slot_persistence_rejections, 0,
        "an operational failure is not rejected persisted evidence: {failed_work:#?}"
    );
    assert_eq!(failed_work.field_slot_publications, 0, "{failed_work:#?}");
    store.set_class_set_field_slot_operational_failure_for_test(false);
    let recovered = execute_workspace_request(&warm_workspace, &flow_state, &query);
    let CodeQueryResponse::Profile(recovered) = recovered else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        serde_json::to_value(&failed_store.result.results).expect("fallback rows serialize"),
        serde_json::to_value(&recovered.result.results).expect("recovered rows serialize")
    );
    let recovered = recovered.work.semantic.type_flow;
    assert_eq!(recovered.field_slot_builds, 0, "{recovered:#?}");
    assert_eq!(recovered.field_slot_memory_hits, 0, "{recovered:#?}");
    assert_eq!(
        recovered.field_slot_persistence_hits, 1,
        "a failed durable acquisition must not leave a ready memory value: {recovered:#?}"
    );
    assert_eq!(recovered.field_slot_persistence_misses, 0, "{recovered:#?}");
    assert_eq!(
        recovered.field_slot_persistence_rejections, 0,
        "{recovered:#?}"
    );
    assert_eq!(recovered.field_slot_publications, 0, "{recovered:#?}");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#5113: point traversal work caused false semantic-budget exhaustion"
)]
fn semantic_scan_work_does_not_exhaust_the_resident_point_grant() {
    let (_project, workspace) = type_flow_workspace();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("profile query");
    let response = execute_workspace_request_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits {
            semantic: CodeQuerySemanticLimits {
                rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                    if dimension == SemanticBudgetDimension::ProgramPoints {
                        // This fixture retains 28 points but visits more than
                        // 30 during solving. Only retained points spend this
                        // grant; repeated visits remain work telemetry.
                        30
                    } else {
                        1 << 20
                    }
                })),
                ..CodeQuerySemanticLimits::default()
            },
            ..CodeQueryExecutionLimits::default()
        },
    );
    let CodeQueryResponse::Profile(profile) = response else {
        panic!("a profile-mode query returns its profile: {response:#?}");
    };
    assert!(
        !profile.work.semantic.budget_exhausted,
        "scan work cannot exhaust a resident grant: {profile:#?}"
    );
    assert!(
        !profile
            .result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted),
        "no false budget diagnostic is raised: {profile:#?}"
    );
    assert!(profile.work.semantic.resident_peaks.program_points <= 30);
    assert!(profile.work.semantic.root_work_peaks.program_points > 30);
    let origins: Vec<&str> = profile
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::ClassSetRow { value } => Some(value.origin.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        origins.contains(&"unknown:root_parameter"),
        "the unresolved root parameter keeps its actual reason: {origins:?}"
    );
}

/// The reviewed try-acquire protocol pack shared by the TryLock guard tests:
/// sync.Mutex and sync.RWMutex with the call-result-true acquisition condition
/// on TryLock and TryRLock (issue #3369).
/// The reviewed conditional-spawn protocol pack shared by the TryGo guard
/// tests: `golang.org/x/sync/errgroup.Group` with `Go` spawning
/// unconditionally, `Wait` joining the group, and `TryGo` spawning exactly
/// when the call's boolean result reports that it did (issue #3371).
/// The reviewed timer protocol pack shared by the timer stop tests:
/// `time.AfterFunc` spawning with its timer, `Timer.Stop` cancelling on a
/// true result, and `Timer.Reset` re-arming (issue #3382).
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "fb68a2103438: prove repeated boxed integral conditions while leaving floating-point conditions open"
)]
fn java_repetition_projects_primitive_and_boxed_proofs_and_floating_gap() {
    let query = CodeQuery::from_source(
        "(branch-relations :relation [repeated-condition] (language java (if)))",
    )
    .expect("typed repeated-condition query");
    for (source, verdict, reason) in [
        (
            "class Sample { int f(int x, boolean ready) { if (ready && x > 5) return 1; else if (ready && x > 5) return 2; return 0; } }",
            "proven",
            None,
        ),
        (
            "class Sample { int f(Integer x) { if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "proven",
            None,
        ),
        (
            "class Sample { int f(Double x) { if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "open",
            Some("unsupported_condition"),
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Java)
            .file("Sample.java", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(
            result.results.len(),
            1,
            "{source}: {}",
            result.render_text()
        );
        let CodeQueryResultValue::BranchRelation { value } = &result.results[0].value else {
            panic!("expected branch relation row");
        };
        assert_eq!(value.verdict, verdict, "{source}: {}", result.render_text());
        assert_eq!(value.reason, reason, "{source}: {}", result.render_text());
        assert!(!value.owner_id.is_empty());
        assert!(value.earlier_ordinal < value.later_ordinal);
    }
}

#[test]
fn branch_relation_step_projects_boolean_return_orientation() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Sample.java",
            "class Sample { static boolean f(boolean x) { if (x) return false; else return true; } }",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query =
        CodeQuery::from_source("(branch-relations :relation [redundant-boolean-return] (if))")
            .expect("typed branch query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(result.diagnostics.is_empty(), "{}", result.render_text());
    assert_eq!(result.results.len(), 1, "{}", result.render_text());
    let CodeQueryResultValue::BranchRelation { value } = &result.results[0].value else {
        panic!("expected branch relation row");
    };
    assert_eq!(value.relation, "redundant_boolean_return");
    assert_eq!(value.verdict, "proven");
    assert_eq!(value.orientation, Some("negated_condition"));
}

#[test]
fn branch_relation_step_does_not_reuse_stale_integer_facts_after_updates() {
    for (update, expected_orientation) in [
        ("x++;", None),
        ("x += 1;", None),
        ("x = 1;", Some("always_true")),
    ] {
        let source = format!(
            "class Sample {{ int f(int x) {{ if (x > 5) {{ {update} if (x < 3) return 1; }} return 0; }} }}"
        );
        let project = InlineTestProject::with_language(Language::Java)
            .file("Sample.java", &source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query =
            CodeQuery::from_source("(branch-relations :relation [contradictory-condition] (if))")
                .expect("typed branch query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let inner = result
            .results
            .iter()
            .filter_map(|item| match &item.value {
                CodeQueryResultValue::BranchRelation { value } => Some(value),
                _ => None,
            })
            .max_by_key(|value| value.owner_range.start_column)
            .expect("inner if produces a branch relation row");
        match expected_orientation {
            Some(orientation) => {
                assert_eq!(
                    inner.verdict,
                    "proven",
                    "{update}: {}",
                    result.render_text()
                );
                assert_eq!(
                    inner.orientation,
                    Some(orientation),
                    "{update}: {}",
                    result.render_text()
                );
            }
            None => assert_ne!(
                inner.verdict,
                "proven",
                "{update}: {}",
                result.render_text()
            ),
        }
    }
}

#[test]
fn branch_relation_step_qualifies_compound_java_conditions() {
    for (source, verdict, orientation, reason) in [
        (
            "class Sample { int f(int x) { if (x > 5 && x < 3) return 1; return 2; } }",
            "proven",
            Some("always_false"),
            None,
        ),
        (
            "class Sample { int f(int x) { if (x > 5 && x < 7) return 1; return 2; } }",
            "distinct",
            None,
            None,
        ),
        (
            "class Sample { int f(Object x) { if (x == null || x != null) return 1; return 2; } }",
            "proven",
            Some("always_true"),
            None,
        ),
        (
            "class Sample { int f(Object x, Object y) { if (x == null || y != null) return 1; return 2; } }",
            "distinct",
            None,
            None,
        ),
        (
            // The arithmetic operand refines nothing; both terminals stay
            // feasible, and that operand is undecided.
            "class Sample { int f(int x) { if (x * 2 > 5 && x < 3) return 1; return 2; } }",
            "open",
            None,
            Some("unknown_scalar"),
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Java)
            .file("Sample.java", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query =
            CodeQuery::from_source("(branch-relations :relation [contradictory-condition] (if))")
                .expect("typed branch query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(
            result.results.len(),
            1,
            "{source}: {}",
            result.render_text()
        );
        let CodeQueryResultValue::BranchRelation { value } = &result.results[0].value else {
            panic!("expected branch relation row");
        };
        assert_eq!(value.verdict, verdict, "{source}: {}", result.render_text());
        assert_eq!(
            value.orientation,
            orientation,
            "{source}: {}",
            result.render_text()
        );
        assert_eq!(value.reason, reason, "{source}: {}", result.render_text());
        assert_eq!(
            result.diagnostics.is_empty(),
            reason.is_none(),
            "{source}: {}",
            result.render_text()
        );
    }
}

/// The contradictory-condition rows of `source`, ordered by owner position.
fn contradictory_condition_rows(
    language: Language,
    path: &str,
    source: &str,
) -> Vec<(&'static str, Option<&'static str>, Option<&'static str>)> {
    let project = InlineTestProject::with_language(language)
        .file(path, source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query =
        CodeQuery::from_source("(branch-relations :relation [contradictory-condition] (if))")
            .expect("typed branch query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let mut rows = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::BranchRelation { value } => Some((
                (value.owner_range.start_line, value.owner_range.start_column),
                value.later_ordinal,
                (value.verdict, value.orientation, value.reason),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|(position, ordinal, _)| (*position, *ordinal));
    rows.into_iter().map(|(_, _, row)| row).collect()
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6415: compound assignment left the target's scalar fact unchanged"
)]
fn branch_relation_step_forgets_rust_compound_assignment_scalar_values() {
    for (source, forbidden) in [
        (
            "fn f(mask: u8) { let mut x: u8 = 0; let mut y: u8 = 7; x |= mask; if x == 0 { y = 1; } let _ = y; }",
            "always_true",
        ),
        (
            "fn f(mask: u8) { let mut x: u8 = 0; let mut y: u8 = 7; x += mask; if x == 0 { y = 1; } let _ = y; }",
            "always_true",
        ),
        (
            "fn f() { let mut x: u8 = 5; x -= 3; if x == 2 {} }",
            "always_false",
        ),
    ] {
        let rows = contradictory_condition_rows(Language::Rust, "sample.rs", source);
        eprintln!("{source}: {rows:?}");
        assert_eq!(rows.len(), 1, "{source}: {rows:?}");
        assert_ne!(rows[0].1, Some(forbidden), "{source}: {rows:?}");
        assert!(
            rows[0].0 == "open" || rows[0] == ("distinct", None, None),
            "{source}: {rows:?}"
        );
    }
}

#[test]
fn branch_relation_step_qualifies_compound_conditions_in_every_pilot_language() {
    let always_false = ("proven", Some("always_false"), None);
    let always_true = ("proven", Some("always_true"), None);
    for (language, path, source, expected) in [
        (
            Language::JavaScript,
            "sample.js",
            "function f(x) { if (x === null && x !== null) return 1; return 2; }",
            vec![always_false],
        ),
        (
            Language::JavaScript,
            "sample.js",
            "function f(x) { if ((x === null) || x !== null) { return 1; } else { return 2; } }",
            vec![always_true],
        ),
        (
            Language::JavaScript,
            "sample.js",
            "function f(x, y) { if (x === null && y !== null) return 1; return 2; }",
            vec![("distinct", None, None)],
        ),
        (
            Language::TypeScript,
            "sample.ts",
            "function f(x: unknown) { if (x === null && (x !== null || x !== null)) return 1; return 2; }",
            vec![always_false],
        ),
        (
            Language::Python,
            "sample.py",
            "def f(x):\n    if x is None and x is not None:\n        return 1\n    return 2\n",
            vec![always_false],
        ),
        (
            Language::Python,
            "sample.py",
            "def f(x):\n    if not (x is None or x is not None):\n        return 1\n    else:\n        return 2\n",
            vec![always_false],
        ),
        (
            Language::Python,
            "sample.py",
            "def f(x):\n    if x is None:\n        return 0\n    elif x is not None or x is None:\n        return 1\n    return 2\n",
            vec![("distinct", None, None), always_true],
        ),
    ] {
        assert_eq!(
            contradictory_condition_rows(language, path, source),
            expected,
            "{language:?}: {source}"
        );
    }
}

#[test]
fn branch_relation_step_decides_python_truth_tests_of_known_and_unconstrained_scalars() {
    for (source, expected) in [
        (
            "def f():\n    x = None\n    if x:\n        return 1\n    return 2\n",
            ("proven", Some("always_false"), None),
        ),
        (
            "def f():\n    x = False\n    if not x:\n        return 1\n    return 2\n",
            ("proven", Some("always_true"), None),
        ),
        (
            "def f(x):\n    if x:\n        return 1\n    return 2\n",
            ("distinct", None, None),
        ),
    ] {
        assert_eq!(
            contradictory_condition_rows(Language::Python, "sample.py", source),
            vec![expected],
            "{source}"
        );
    }
}

#[test]
fn branch_relation_step_joins_java_locals_in_their_declared_domain() {
    // Both writes to `x` take the declared int domain, so the join is the
    // whole int range and no value exceeds its maximum.
    let rows = contradictory_condition_rows(
        Language::Java,
        "Sample.java",
        "class Sample { int f(int p, boolean c) { int x; if (c) x = p; else x = 5; if (x > 2147483647) return 1; return 0; } }",
    );
    assert_eq!(
        rows.last(),
        Some(&("proven", Some("always_false"), None)),
        "{rows:?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "fb68a2103438: preserve signed and boxed Java integer condition proofs"
)]
fn branch_relation_step_qualifies_signed_java_int_constants() {
    for (source, row_count, verdict, orientation, reason) in [
        (
            "class Sample { int f(int x) { if (x < -1) { if (x > 1) return 1; } return 0; } }",
            2,
            "proven",
            Some("always_false"),
            None,
        ),
        (
            "class Sample { int f(int x) { if (x < -1) { if (x > -3) return 1; } return 0; } }",
            2,
            "distinct",
            None,
            None,
        ),
        (
            "class Sample { int f(int x) { if (x < -1) { if (x == -1) return 1; } return 0; } }",
            2,
            "proven",
            Some("always_false"),
            None,
        ),
        (
            "class Sample { int f(int x) { x = -2; if (x > -1) return 1; return 0; } }",
            1,
            "proven",
            Some("always_false"),
            None,
        ),
        (
            "class Sample { int f() { int x = -2147483648; if (x > -2147483647) return 1; return 0; } }",
            1,
            "proven",
            Some("always_false"),
            None,
        ),
        (
            "class Sample { int f(int x) { if (x < -2147483648) return 1; return 0; } }",
            1,
            "proven",
            Some("always_false"),
            None,
        ),
        (
            "class Sample { int f(int x) { if (x < +1) return 1; return 0; } }",
            1,
            "distinct",
            None,
            None,
        ),
        (
            "class Sample { int f(char x) { if (x < -1) return 1; return 0; } }",
            1,
            "proven",
            Some("always_false"),
            None,
        ),
        (
            "class Sample { int f() { byte x = -128; if (x > -127) return 1; return 0; } }",
            1,
            "proven",
            Some("always_false"),
            None,
        ),
        (
            "class Sample { int f(int x) { if (x < -2147483649) return 1; return 0; } }",
            1,
            "open",
            None,
            Some("unsupported_predicate"),
        ),
        (
            "class Sample { int f(int x) { if (x < +2147483648) return 1; return 0; } }",
            1,
            "open",
            None,
            Some("unsupported_predicate"),
        ),
        (
            "class Sample { int f(int x) { if (x < -(2147483648)) return 1; return 0; } }",
            1,
            "open",
            None,
            Some("unsupported_predicate"),
        ),
        (
            // A long constant compares with an int by value after promotion.
            "class Sample { int f(int x) { if (x < -1L) return 1; return 0; } }",
            1,
            "distinct",
            None,
            None,
        ),
        (
            // A radix literal is its type's bit pattern; unary minus negates it.
            "class Sample { int f(int x) { if (x < -0x1) return 1; return 0; } }",
            1,
            "distinct",
            None,
            None,
        ),
        (
            // An ordering unboxes; a null operand throws before it decides.
            "class Sample { int f(Integer x) { if (x < -1) return 1; return 0; } }",
            1,
            "distinct",
            None,
            None,
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Java)
            .file("Sample.java", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query =
            CodeQuery::from_source("(branch-relations :relation [contradictory-condition] (if))")
                .expect("typed branch query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(
            result.results.len(),
            row_count,
            "{source}: {}",
            result.render_text()
        );
        let row = result
            .results
            .iter()
            .filter_map(|result| match &result.value {
                CodeQueryResultValue::BranchRelation { value } => Some(value),
                _ => None,
            })
            .max_by_key(|value| value.owner_range.start_column)
            .expect("condition has a branch relation row");
        assert_eq!(row.verdict, verdict, "{source}: {}", result.render_text());
        assert_eq!(
            row.orientation,
            orientation,
            "{source}: {}",
            result.render_text()
        );
        assert_eq!(row.reason, reason, "{source}: {}", result.render_text());
    }
}

fn assert_java_branch_relation_case(source: &str, verdict: &str, reason: Option<&str>) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("Sample.java", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source("(branch-relations :relation [identical-bodies] (if))")
        .expect("typed branch query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.results.len(),
        1,
        "{source}: {}",
        result.render_text()
    );
    let CodeQueryResultValue::BranchRelation { value } = &result.results[0].value else {
        panic!("expected branch relation row");
    };
    assert_eq!(value.verdict, verdict, "{source}: {}", result.render_text());
    assert_eq!(value.reason, reason, "{source}: {}", result.render_text());
}

#[test]
fn branch_relation_step_compares_java_members_by_receiver_and_resolved_target() {
    for (source, verdict, reason) in [
        (
            "class Sample { int value; int f(boolean flag) { if (flag) return this.value; else return this.value; } }",
            "proven",
            None,
        ),
        (
            "class Sample { int value; int other; int f(boolean flag) { if (flag) return this.value; else return this.other; } }",
            "distinct",
            None,
        ),
        (
            "class Sample { int value; int f(boolean flag, Sample other) { if (flag) return this.value; else return other.value; } }",
            "distinct",
            None,
        ),
        (
            "class Sample { int f(boolean flag, External object) { if (flag) return object.value; else return object.value; } }",
            "proven",
            None,
        ),
        (
            "class Sample { int value() { return 1; } int f(boolean flag) { if (flag) return this.value(); else return value(); } }",
            "proven",
            None,
        ),
        (
            "class Sample { int value; int f(boolean flag) { if (flag) return this.value; else return value; } }",
            "open",
            Some("member_resolution_unavailable"),
        ),
    ] {
        assert_java_branch_relation_case(source, verdict, reason);
    }
}

#[test]
fn branch_relation_field_budget_excludes_unrelated_java_accesses() {
    let unrelated = (0..257)
        .map(|index| format!("int local{index} = this.value;"))
        .collect::<String>();
    let source = format!(
        "class Sample {{ int value; int f(boolean flag) {{ {unrelated} if (flag) return this.value; else return this.value; }} }}"
    );
    let project = InlineTestProject::with_language(Language::Java)
        .file("Sample.java", &source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source("(branch-relations :relation [identical-bodies] (if))")
        .expect("typed branch query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(result.results.len(), 1, "{}", result.render_text());
    let CodeQueryResultValue::BranchRelation { value } = &result.results[0].value else {
        panic!("expected branch relation row");
    };
    assert_eq!(value.verdict, "proven", "{}", result.render_text());
    assert!(result.diagnostics.is_empty(), "{}", result.render_text());
}

#[test]
fn branch_relation_step_pairs_only_java_arm_local_bindings() {
    for (source, verdict, reason) in [
        (
            "class Sample { int f(boolean flag) { if (flag) { int left = 1; return left; } else { int right = 1; return right; } } }",
            "proven",
            None,
        ),
        (
            "class Sample { int f(boolean flag) { if (flag) { int local = 1; return local; } else { int local = 1; return local; } } }",
            "proven",
            None,
        ),
        (
            "class Sample { int f(boolean flag, int shared) { if (flag) { int left = shared; return left; } else { int right = shared; return right; } } }",
            "proven",
            None,
        ),
        (
            "class Sample { int f(boolean flag, int shared) { if (flag) { int left = 1; return left; } else { int right = 1; return shared; } } }",
            "distinct",
            None,
        ),
        (
            "class Sample { long f(boolean flag) { if (flag) { int left = 1; return left; } else { long right = 1; return right; } } }",
            "distinct",
            None,
        ),
        (
            "class Sample { java.util.function.IntSupplier f(boolean flag) { if (flag) { int left = 1; return () -> left; } else { int right = 1; return () -> right; } } }",
            "open",
            Some("deferred_body"),
        ),
    ] {
        assert_java_branch_relation_case(source, verdict, reason);
    }
}

#[test]
fn rust_async_property_excludes_the_sync_near_miss() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            include_str!("../../../../testdata/structural-search/mined-rust-rules/M03/src/lib.rs"),
        )
        .file(
            "src/io_helpers.rs",
            include_str!(
                "../../../../testdata/structural-search/mined-rust-rules/M03/src/io_helpers.rs"
            ),
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let selected_names = |function: &str, predicate: &str| {
        let query = CodeQuery::from_source(&format!(
            "(language rust (function :name \"{function}\" :async {predicate}))"
        ))
        .expect("async callable predicate");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
        .results
        .into_iter()
        .map(|item| match item.value {
            CodeQueryResultValue::StructuralMatch { value } => value.text,
            other => panic!("function query returns structural matches: {other:#?}"),
        })
        .collect::<Vec<_>>()
    };

    for function in ["async_entry", "async_near_miss"] {
        let asynchronous = selected_names(function, "true");
        assert_eq!(asynchronous.len(), 1, "{function}: {asynchronous:#?}");
        assert!(asynchronous[0].contains(function));
    }
    assert!(selected_names("sync_entry", "true").is_empty());

    let synchronous = selected_names("sync_entry", "false");
    assert_eq!(synchronous.len(), 1, "{synchronous:#?}");
    assert!(synchronous[0].contains("sync_entry"));
}

#[test]
fn rust_await_points_join_future_frame_binding_reads() {
    use std::collections::HashSet;

    let source =
        include_str!("../../../../testdata/structural-search/mined-rust-rules/M48/src/lib.rs");
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cases = [
        ("mutex_guard_across_await", "guard", true),
        ("refcell_borrow_across_await", "borrow", true),
        ("rc_across_await", "held", true),
        ("mutex_guard_dropped_before_await", "guard", false),
        ("refcell_borrow_dropped_before_await", "borrow", false),
        ("send_value_across_await", "held", true),
    ];

    for (function, binding, survives) in cases {
        let point_query = CodeQuery::from_source(&format!(
            "(language rust (program-point-of (inside (function :name \"{function}\" :async true) (await))))"
        ))
        .expect("await point query");
        let points = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &point_query,
        );
        assert_eq!(
            points.completion(),
            CodeQueryCompletion::Complete,
            "await projection is complete for {function}: {points:#?}"
        );
        let [point_item] = points.results.as_slice() else {
            panic!("one await maps to one suspend point for {function}: {points:#?}");
        };
        let CodeQueryResultValue::ProgramPoint { value: point } = &point_item.value else {
            panic!("program-point-of returns a program point: {point_item:#?}");
        };

        let events_query = CodeQuery::from_source(&format!(
            "(state-events-of :class [read] :subject [binding] (procedure-of (language rust (function :name \"{function}\" :async true))))"
        ))
        .expect("binding state-event query");
        let events = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &events_query,
        );
        assert_eq!(
            events.completion(),
            CodeQueryCompletion::Complete,
            "scope liveness projection is complete for {function}: {events:#?}"
        );
        let (binding_values, suspend_values, suspend_causes) = events.results.iter().fold(
            (HashSet::new(), HashSet::new(), Vec::new()),
            |(mut binding_values, mut suspend_values, mut suspend_causes), item| {
                let CodeQueryResultValue::StateEvent { value } = &item.value else {
                    panic!("state-events-of returns state-event rows: {item:#?}");
                };
                if source
                    .get(value.start_byte..value.end_byte)
                    .is_some_and(|text| text == binding)
                {
                    binding_values.insert(value.subject_value);
                }
                if value.program_point_id == point.id {
                    suspend_values.insert(value.subject_value);
                    suspend_causes.push((value.subject_value, value.read_cause));
                }
                (binding_values, suspend_values, suspend_causes)
            },
        );
        assert!(
            !binding_values.is_empty(),
            "the fixture has an ordinary read of {binding} in {function}: {events:#?}"
        );
        assert_eq!(
            binding_values
                .iter()
                .any(|value| suspend_values.contains(value)),
            survives,
            "future-frame read for {binding} at {function}, joined by {}: {events:#?}",
            point.id,
        );
        if survives {
            assert!(binding_values.iter().any(|binding| {
                suspend_values.contains(binding)
                    && suspend_causes.contains(&(*binding, Some("post_resume_use")))
            }));
        }
    }
}

#[test]
fn rust_scope_only_await_reads_follow_lexical_scope_and_move_paths() {
    let source = r#"
        async fn scope_only(awaitable: FutureStub, m: MutexStub) {
            let _g = m.lock().unwrap();
            awaitable.await;
        }

        async fn inner_scope(awaitable: FutureStub) {
            { let guard = lock(); }
            awaitable.await;
        }

        async fn explicit_drop(awaitable: FutureStub) {
            let guard = lock();
            drop(guard);
            awaitable.await;
        }

        async fn qualified_drop(awaitable: FutureStub) {
            let guard = lock();
            std::mem::drop(guard);
            awaitable.await;
        }

        async fn moved_then_dropped(awaitable: FutureStub) {
            let guard = lock();
            let held = guard;
            drop(held);
            awaitable.await;
        }

        async fn moved_into_await_operand(awaitable: FutureStub) {
            let guard = lock();
            consume(guard, awaitable).await;
        }

        async fn assignment_rhs_moves(awaitable: FutureStub) {
            let guard = lock();
            let mut target = lock();
            target = guard;
            awaitable.await;
        }

        async fn struct_field_moves(awaitable: FutureStub) {
            let guard = lock();
            let holder = Holder { field: guard };
            awaitable.await;
        }

        async fn one_branch_moves(awaitable: FutureStub, condition: bool) {
            let guard = lock();
            if condition { drop(guard); }
            awaitable.await;
        }

        async fn autoref_and_borrow(awaitable: FutureStub) {
            let guard = lock();
            guard.touch();
            let borrow = &guard;
            awaitable.await;
        }
    "#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    for (function, declaration, expected_live) in [
        ("scope_only", "let _g", true),
        ("inner_scope", "let guard", false),
        ("explicit_drop", "let guard", false),
        ("qualified_drop", "let guard", false),
        ("moved_then_dropped", "let guard", false),
        ("moved_into_await_operand", "let guard", false),
        ("assignment_rhs_moves", "let guard", false),
        ("struct_field_moves", "let guard", false),
        ("one_branch_moves", "let guard", true),
        ("autoref_and_borrow", "let guard", true),
    ] {
        let point_query = CodeQuery::from_source(&format!(
            "(language rust (program-point-of (inside (function :name \"{function}\" :async true) (await))))"
        ))
        .expect("unique await point query");
        let points = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &point_query,
        );
        let [point_item] = points.results.as_slice() else {
            panic!("one await point for {function}: {points:#?}");
        };
        let CodeQueryResultValue::ProgramPoint { value: point } = &point_item.value else {
            panic!("program-point-of returns a point: {point_item:#?}");
        };

        let events_query = CodeQuery::from_source(&format!(
            "(state-events-of :class [read] :subject [binding] :read-cause [scope_end_drop] (procedure-of (language rust (function :name \"{function}\" :async true))))"
        ))
        .expect("scope-only read-cause query");
        let events = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &events_query,
        );
        let establish_query = CodeQuery::from_source(&format!(
            "(state-events-of :class [establish] :subject [binding] (procedure-of (language rust (function :name \"{function}\" :async true))))"
        ))
        .expect("binding establishment query");
        let establishments = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &establish_query,
        );
        let guard = establishments
            .results
            .iter()
            .find_map(|item| {
                let CodeQueryResultValue::StateEvent { value } = &item.value else {
                    panic!("state-events-of returns state-event rows: {item:#?}");
                };
                source
                    .get(value.start_byte..value.end_byte)
                    .is_some_and(|text| text.contains(declaration))
                    .then_some(value.subject_value)
            })
            .unwrap_or_else(|| panic!("guard establishment for {function}: {establishments:#?}"));
        let suspend_reads = events
            .results
            .iter()
            .filter_map(|item| {
                let CodeQueryResultValue::StateEvent { value } = &item.value else {
                    panic!("state-events-of returns state-event rows: {item:#?}");
                };
                assert_eq!(value.read_cause, Some("scope_end_drop"));
                (value.program_point_id == point.id && value.subject_value == guard)
                    .then_some(value)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            !suspend_reads.is_empty(),
            expected_live,
            "scope-only future-frame read at {} in {function}: {events:#?}",
            point.id,
        );
    }
}

#[test]
fn rust_binding_initializer_call_rows_reuse_call_site_ast_identity() {
    use std::collections::HashSet;

    let source = r#"
        use std::future::Future;
        use std::sync::Mutex;

        async fn held(lock: &Mutex<u32>, wait: impl Future<Output = ()>) {
            let _guard = lock.lock().unwrap();
            wait.await;
            std::hint::black_box(&_guard);
        }
    "#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let initializer_query = CodeQuery::from_source(
        r#"(language rust
          (binding-initializer-calls-of
            (state-events-of :class [establish] :subject [binding]
              (procedure-of (function :name "held" :async true)))))"#,
    )
    .expect("binding initializer call query");
    let initializers = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &initializer_query,
    );
    assert_eq!(initializers.completion(), CodeQueryCompletion::Complete);
    assert_eq!(initializers.results.len(), 2, "{initializers:#?}");
    let mut initializer_site_ids = HashSet::new();
    let mut roles = Vec::new();
    for item in &initializers.results {
        let CodeQueryResultValue::BindingInitializerCall { value } = &item.value else {
            panic!("binding-initializer-calls-of returns its typed row: {item:#?}");
        };
        initializer_site_ids.insert(value.site_ast_id.as_str());
        roles.push(value.initializer_role);
    }
    roles.sort_unstable();
    assert_eq!(roles, ["receiver", "result"]);

    let call_shapes_query = CodeQuery::from_source(
        r#"(language rust
          (call-shape
            (inside (function :name "held" :async true) (call))))"#,
    )
    .expect("call-shape query");
    let call_shapes = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &call_shapes_query,
    );
    let call_site_ids = call_shapes
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::CallShape { value } = &item.value else {
                panic!("call-shape returns call rows: {item:#?}");
            };
            value.site_ast_id.as_str()
        })
        .collect::<HashSet<_>>();
    assert!(
        initializer_site_ids.is_subset(&call_site_ids),
        "initializer AST IDs must reuse the call-site identity: {initializer_site_ids:?} vs {call_site_ids:?}"
    );
}

#[test]
fn program_point_of_reports_an_incomplete_result_without_a_unique_suspend() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("src/module.py", "await task\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source("(language python (program-point-of (await)))")
        .expect("await point query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert!(result.results.is_empty(), "{result:#?}");
    assert!(
        matches!(result.completion(), CodeQueryCompletion::Incomplete { .. }),
        "a missing suspend mapping is explicit: {result:#?}"
    );
}

#[test]
fn callee_provenance_filters_project_rust_and_state_python_unsupported() {
    let project = InlineTestProject::new()
        .file("src/lib.rs", "fn run<F: FnMut()>(mut f: F) { f(); }")
        .file("src/probe.py", "def run(f):\n    f()\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for (language, provenance, shape, supplier, bounds) in [
        (
            "rust",
            "caller_supplied",
            "fn_bound_generic",
            Some("parameter 0"),
            vec!["FnMut"],
        ),
        ("python", "unsupported", "unknown", None, vec![]),
    ] {
        let query = CodeQuery::from_sexp(&format!(
            "(filter :where ((callee_provenance eq {provenance}) (callee_type_shape eq {shape})) (call-shape (language {language} (call))))"
        )).expect("callee column filter");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(result.results.len(), 1, "{result:#?}");
        let CodeQueryResultValue::CallShape { value } = &result.results[0].value else {
            panic!("call shape row");
        };
        assert_eq!(value.callee_supplier.as_deref(), supplier);
        assert_eq!(value.callee_bounds, bounds);
    }
}

#[test]
fn unsafe_context_selects_rust_calls_and_reports_python_unsupported() {
    let project = InlineTestProject::new()
        .file("src/lib.rs", "fn helper() {} fn run() { helper(); unsafe { helper(); } } unsafe fn raw() { helper(); }")
        .file("src/probe.py", "def run():\n    helper()\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for (expected, count) in [(true, 2), (false, 1)] {
        let query = CodeQuery::from_sexp(&format!(
            "(language rust (call :unsafe-context {expected}))"
        ))
        .expect("Rust unsafe selector");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(result.results.len(), count, "{result:#?}");
    }
    let query = CodeQuery::from_sexp("(language python (call :unsafe-context true))")
        .expect("property parses before capability check");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(result.results.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unsafe-context")),
        "{result:#?}"
    );
}

#[test]
fn dispatch_file_operations_in_memory_multi_file_query_completes() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname='dispatch_memory'\nversion='0.1.0'\nedition='2024'\n")
        .file("src/lib.rs", "mod other; pub fn first() {} pub fn second() {} pub fn caller() { first(); second(); }\n")
        .file("src/other.rs", "pub fn caller() { crate::first(); crate::second(); }\n")
        .build();
    let project_dyn = project.project_dyn();
    let store = brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test(project_dyn.as_ref()).expect("in-memory store");
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        project_dyn,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
        store,
    )
    .expect("workspace");
    let query = CodeQuery::from_sexp(
        "(filter :where ((ordinal ge 0)) (language rust (dispatch-targets (call))))",
    )
    .expect("dispatch query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(!result.results.is_empty(), "{}", result.render_text());
}
