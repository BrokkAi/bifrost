use super::*;
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelCallApplication, SemanticModelCallableDisposition,
    SemanticModelCallableKey, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
    acquire_active_semantic_models, compile_source,
};
use semver::Version;

fn activate_rust_pack(
    workspace: &WorkspaceAnalyzer,
    source: &str,
    source_id: &str,
) -> std::sync::Arc<ActiveSemanticModelSnapshot> {
    let pack = compile_source(
        SourceFormat::Json,
        source.as_bytes(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("Rust test model compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: source_id.to_owned(),
            },
        )
        .expect("register Rust test model");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "rust".to_owned(),
                ecosystem: "cargo".to_owned(),
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
    match activation {
        SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
        other => panic!("Rust test model activates: {other:#?}"),
    }
}

fn execute_rust_query(workspace: &WorkspaceAnalyzer, query: CodeQuery) -> CodeQueryResult {
    execute_workspace(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

#[test]
fn rust_call_selector_includes_resolved_tokio_spawn() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"tokio_call_selector\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            "pub fn launch() { tokio::spawn(async {}); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": {
            "kind": "call",
            "receiver": { "name": "tokio" },
            "callee": { "name": "spawn" }
        },
        "result_detail": "full"
    }))
    .expect("M01 Tokio subject selector");

    let result = execute_rust_query(&workspace, query);
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_eq!(
        result.results.len(),
        1,
        "the call selector must retain the Tokio task subject: {result:#?}"
    );
    assert!(
        matches!(
            &result.results[0].value,
            CodeQueryResultValue::StructuralMatch { value }
                if value.kind == "concurrent_spawn" && value.text.contains("tokio::spawn")
        ),
        "the selected subject remains explicitly identified as a concurrent spawn: {result:#?}"
    );
}

#[test]
fn task_spawn_transfers_capture_and_preserves_open_object_set() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"task_probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntokio = \"1\"\n",
        )
        .file(
            "src/lib.rs",
            r#"pub struct Sender;
impl Sender { fn send(&self) {} }
fn channel() -> (Sender, ()) { (Sender, ()) }

pub fn resolved_sender_worker() {
    let (sender, _receiver) = channel();
    std::thread::spawn(move || sender.send());
}

pub fn tokio_sender_worker() {
    let (sender, _receiver) = channel();
    tokio::spawn(async move { sender.send(); });
}

pub fn unresolved_tokio_spawn_blocking_worker() {
    let (sender, _receiver) = channel();
    ::tokio::task::spawn_blocking(move || sender.send());
}

pub fn process_control() {
    let _child = std::process::Command::new("worker").spawn();
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = activate_rust_pack(
        &workspace,
        r#"{
          "schema_version": 2,
          "pack_id": "test.rust-tokio-spawn",
          "version": "0.1.0",
          "producer": { "name": "fixture", "version": "1.0.0" },
          "language": "rust",
          "ecosystem": "cargo",
          "compatibility": { "bifrost": ">=0.8.0, <1.0.0", "toolchains": [] },
          "provenance": { "source": "test fixture", "revision": "fixture" },
          "license": "Apache-2.0",
          "completeness": "complete",
          "safety": { "generated_code_only": false, "review_required": false },
          "shards": [{
            "id": "tokio-api",
            "activation": [{}],
            "payload": {
              "kind": "declaration_facts",
              "types": [{
                "id": "tokio",
                "name": "tokio",
                "type_kind": "module",
                "visibility": "public",
                "locator": {
                  "kind": "artifact",
                  "path": "tokio/src/lib.rs",
                  "symbol": "tokio"
                }
              }, {
                "id": "std",
                "name": "std",
                "type_kind": "module",
                "visibility": "public",
                "locator": {
                  "kind": "artifact",
                  "path": "library/std/src/lib.rs",
                  "symbol": "std"
                }
              }, {
                "id": "std-thread",
                "name": "std.thread",
                "type_kind": "module",
                "visibility": "public",
                "locator": {
                  "kind": "artifact",
                  "path": "library/std/src/thread/mod.rs",
                  "symbol": "std.thread"
                }
              }],
              "members": [{
                "id": "tokio.spawn.callable",
                "owner": "tokio",
                "name": "spawn",
                "member_kind": "function",
                "visibility": "public",
                "is_static": true,
                "callable_family_complete": true,
                "signature": {
                  "type_parameters": ["F"],
                  "parameters": [{
                    "name": "future",
                    "type": { "kind": "type_parameter", "name": "F" }
                  }]
                },
                "locator": {
                  "kind": "artifact",
                  "path": "tokio/src/task/spawn.rs",
                  "symbol": "tokio::spawn"
                }
              }, {
                "id": "std.thread.spawn.callable",
                "owner": "std-thread",
                "name": "spawn",
                "member_kind": "function",
                "visibility": "public",
                "is_static": true,
                "callable_family_complete": true,
                "signature": {
                  "type_parameters": ["F"],
                  "parameters": [{
                    "name": "callable",
                    "type": { "kind": "type_parameter", "name": "F" }
                  }]
                },
                "locator": {
                  "kind": "artifact",
                  "path": "library/std/src/thread/mod.rs",
                  "symbol": "std.thread.spawn"
                }
              }],
              "relations": []
            }
          }, {
            "id": "tokio-spawn",
            "activation": [{}],
            "payload": { "kind": "procedure_summaries", "summaries": [{
              "id": "tokio-spawn-task",
              "target": {
                "path": "tokio/src/task/spawn.rs",
                "symbol": "tokio.spawn",
                "has_receiver": false,
                "parameter_count": 1
              },
              "completeness": "complete",
              "transfers": [],
              "concurrency_effects": [{
                "kind": "task_spawn",
                "callable": { "kind": "parameter", "ordinal": 0 }
              }]
            }, {
              "id": "std-thread-spawn-task",
              "target": {
                "path": "library/std/src/thread/mod.rs",
                "symbol": "std.thread.spawn",
                "has_receiver": false,
                "parameter_count": 1
              },
              "completeness": "complete",
              "transfers": [],
              "concurrency_effects": [{
                "kind": "task_spawn",
                "callable": { "kind": "parameter", "ordinal": 0 }
              }]
            }] }
          }]
        }"#,
        "test:rust-tokio-spawn",
    );
    let spawn_model = snapshot.active_models().procedure_summaries_for_member(
        crate::analyzer::semantic_model::ProcedureSummaryMemberKey::new(
            "rust", "tokio", "spawn", false, 1,
        ),
    );
    assert_eq!(spawn_model.records.len(), 1, "{spawn_model:#?}");
    let std_spawn_model = snapshot.active_models().procedure_summaries_for_member(
        crate::analyzer::semantic_model::ProcedureSummaryMemberKey::new(
            "rust",
            "std.thread",
            "spawn",
            false,
            1,
        ),
    );
    assert_eq!(std_spawn_model.records.len(), 1, "{std_spawn_model:#?}");
    assert!(
        spawn_model.records[0]
            .record
            .concurrency_effects
            .iter()
            .any(|effect| matches!(
                effect,
                crate::analyzer::semantic_model::CompiledConcurrencyEffect::TaskSpawn { .. }
            ))
    );
    let overlay = snapshot
        .semantic_model_overlay()
        .expect("model activation publishes a declaration overlay");
    let tokio_root = overlay.symbols_named("tokio");
    assert_eq!(tokio_root.records.len(), 1, "{tokio_root:#?}");
    let spawn_callable = overlay.callable_for_application(
        SemanticModelCallableKey::new("rust", "tokio", "spawn", false, 1),
        &SemanticModelCallApplication::positional(1),
    );
    assert_eq!(
        spawn_callable.disposition,
        SemanticModelCallableDisposition::Unique,
        "{spawn_callable:#?}"
    );
    let std_spawn_callable = overlay.callable_for_application(
        SemanticModelCallableKey::new("rust", "std.thread", "spawn", false, 1),
        &SemanticModelCallApplication::positional(1),
    );
    assert_eq!(
        std_spawn_callable.disposition,
        SemanticModelCallableDisposition::Unique,
        "{std_spawn_callable:#?}"
    );
    let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        Some(snapshot),
    );
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function", "name": "resolved_sender_worker" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "detached_task_transfers" }
        ],
        "result_detail": "full"
    }))
    .expect("detached task transfer query");
    let result = execute_rust_query(&workspace, query);
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert!(
        result.results.iter().any(|item| matches!(
            &item.value,
        CodeQueryResultValue::DetachedTaskTransfer { value }
                if value.role == "capture" && value.timing == "different_task"
        )),
        "the resolver-proven task receives its exact moved sender capture: {result:#?}"
    );

    let tokio_query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function", "name": "tokio_sender_worker" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "detached_task_transfers" }
        ]
    }))
    .expect("Tokio detached task transfer query");
    let tokio = execute_rust_query(&workspace, tokio_query);
    assert_eq!(
        tokio.completion(),
        CodeQueryCompletion::Complete,
        "{tokio:#?}"
    );
    assert!(
        tokio.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::DetachedTaskTransfer { value }
                if value.role == "capture"
                    && value.timing == "different_task"
                    && value.proof == "unknown"
                    && value.coverage == "open"
                    && value.reason == Some("object_set_open")
                    && value.object_id.is_none()
        )),
        "the resolved Tokio TaskSpawn contract retains its captured value and open object-set boundary: {tokio:#?}"
    );

    let unresolved_tokio_query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function", "name": "unresolved_tokio_spawn_blocking_worker" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "detached_task_transfers" }
        ]
    }))
    .expect("unmodeled Tokio detached task query");
    let unresolved_tokio = execute_rust_query(&workspace, unresolved_tokio_query);
    assert!(
        matches!(
            unresolved_tokio.completion(),
            CodeQueryCompletion::Incomplete { .. }
        ),
        "an unmodeled Tokio spawn target remains incomplete: {unresolved_tokio:#?}"
    );
    assert!(unresolved_tokio.results.is_empty(), "{unresolved_tokio:#?}");
    assert!(
        unresolved_tokio.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
        }),
        "the unmodeled Tokio target retains a typed gap: {unresolved_tokio:#?}"
    );

    let process_query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function", "name": "process_control" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "detached_task_transfers" }
        ]
    }))
    .expect("process control transfer query");
    let process = execute_rust_query(&workspace, process_query);
    assert!(
        process.results.is_empty(),
        "Command::spawn stays outside the task-transfer model: {process:#?}"
    );
}

#[test]
fn procedure_callees_follow_only_invoked_callback_formals() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"callback_edges\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            r#"struct Owner;
impl Owner { fn close(&self, _id: u64) {} }
struct Span { id: u64, owner: Owner }

fn invoke<F: FnOnce(&Owner)>(callback: F) { callback(&Owner); }
fn store<F>(callback: F) { let _stored = callback; }

pub fn root(span: &Span) {
    invoke(|ambient| ambient.close(span.id));
    store(|| span.owner.close(span.id));
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function", "name": "root" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "callees" }
        ],
        "result_detail": "full"
    }))
    .expect("procedure-scoped callback traversal query");

    let result = execute_rust_query(&workspace, query);
    let closures = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::Procedure { value } if value.procedure_kind == "closure" => {
                Some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        closures.len(),
        1,
        "only the invoked callback is a callee: {result:#?}"
    );
}

#[test]
fn procedure_effects_keep_anonymous_closure_scope() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"m111_probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            r#"pub mod helpers;

pub fn configure_bad() {
    let mut command = Command;
    command.pre_exec(|| helpers::unsafe_child_operation());
}

pub fn configure_good() {
    helpers::unsafe_child_operation();
    let mut command = Command;
    command.pre_exec(|| helpers::signal_safe_call());
}

struct Command;
impl CommandExt for Command {}
trait CommandExt {
    fn pre_exec<F>(&mut self, _callback: F) {}
}
"#,
        )
        .file(
            "src/helpers.rs",
            "pub fn unsafe_child_operation() {}\npub fn signal_safe_call() {}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = activate_rust_pack(
        &workspace,
        r#"{
          "schema_version": 2,
          "pack_id": "test.rust-async-signal",
          "version": "0.1.0",
          "producer": { "name": "fixture", "version": "1.0.0" },
          "language": "rust",
          "ecosystem": "cargo",
          "compatibility": { "bifrost": ">=0.8.0, <1.0.0", "toolchains": [] },
          "provenance": { "source": "test fixture", "revision": "fixture" },
          "license": "Apache-2.0",
          "completeness": "complete",
          "safety": { "generated_code_only": false, "review_required": false },
          "shards": [{
            "id": "helper-effects",
            "activation": [{}],
            "payload": { "kind": "procedure_summaries", "summaries": [{
              "id": "unsafe-child-operation",
              "target": {
                "path": "src/helpers.rs",
                "symbol": "m111_probe.helpers.unsafe_child_operation",
                "has_receiver": false,
                "parameter_count": 0
              },
              "completeness": "complete",
              "transfers": [],
              "declared_effects": [{
                "id": "bifrost.async_signal_unsafe",
                "timing": "immediate",
                "certainty": "definite"
              }]
            }] }
          }]
        }"#,
        "test:rust-async-signal",
    );
    let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        Some(snapshot),
    );

    let run = |callee: &str| {
        let query = CodeQuery::from_json(&json!({
            "languages": ["rust"],
            "match": {
                "kind": "call",
                "callee": { "name": callee }
            },
            "inside": {
                "kind": "call",
                "callee": { "name": "pre_exec" }
            },
            "steps": [
                { "op": "procedure_of" },
                { "op": "procedure_effects" }
            ],
            "result_detail": "full"
        }))
        .expect("closure-scoped procedure effect query");
        execute_rust_query(&workspace, query)
    };
    let bad = run("unsafe_child_operation");
    assert_eq!(bad.completion(), CodeQueryCompletion::Complete, "{bad:#?}");
    assert!(
        bad.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ProcedureEffect { value }
                if value.effect_id.as_deref() == Some("bifrost.async_signal_unsafe")
                    && value.derivation == "declared"
        )),
        "the bad callback retains its declared unsafe effect: {bad:#?}"
    );

    let good = run("signal_safe_call");
    assert_eq!(
        good.completion(),
        CodeQueryCompletion::Complete,
        "{good:#?}"
    );
    assert!(
        good.results.iter().all(|item| !matches!(
            &item.value,
            CodeQueryResultValue::ProcedureEffect { value }
                if value.effect_id.as_deref() == Some("bifrost.async_signal_unsafe")
        )),
        "the unsafe helper before the callback stays outside its exact procedure: {good:#?}"
    );
}
