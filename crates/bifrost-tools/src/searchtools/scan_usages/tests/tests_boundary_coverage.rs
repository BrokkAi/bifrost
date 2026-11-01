use super::*;

#[test]
fn cancelled_usage_graph_reports_a_cut_at_the_entry_boundary() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Rust,
        &[("src/lib.rs", "pub fn target() {}\n")],
    );
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let graph = usage_graph_with_cancellation(
        fixture.analyzer.analyzer(),
        UsageGraphParams {
            include_same_owner: false,
            include_tests: true,
            paths: None,
            depth: 1,
        },
        cancellation,
    );
    assert!(!graph.complete, "{graph:?}");
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason.code == "cancelled"),
        "{graph:?}"
    );
}

#[test]
fn raw_reference_sites_keep_unmatched_path_reason_with_found_sites() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Python,
        &[
            ("app.py", "def target():\n    pass\n"),
            ("caller.py", "from app import target\ntarget()\n"),
        ],
    );
    let raw = scan_usage_reference_sites_by_location(
        fixture.analyzer.analyzer(),
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: "app.py".into(),
                line: 1,
                column: None,
                symbol: None,
            }],
            include_tests: true,
            paths: Some(vec!["caller.py".into(), "missing.py".into()]),
            include_same_owner: false,
        },
        CancellationToken::default(),
    );
    assert_eq!(raw.len(), 1);
    assert!(
        raw[0]
            .files
            .iter()
            .any(|file| file.path == "caller.py" && file.lines.contains(&2)),
        "{raw:?}"
    );
    assert_eq!(raw[0].incomplete_reason.as_deref(), Some("UnmatchedPaths"));
}

#[test]
fn rooted_graph_excludes_calls_beyond_one_hop() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Rust,
        &[
            ("src/lib.rs", "mod root; mod middle; mod leaf;\n"),
            ("src/root.rs", "pub fn run() { crate::middle::call(); }\n"),
            (
                "src/middle.rs",
                "pub fn call() { crate::leaf::finish(); }\n",
            ),
            ("src/leaf.rs", "pub fn finish() {}\n"),
        ],
    );
    let graph = usage_graph(
        fixture.analyzer.analyzer(),
        UsageGraphParams {
            include_same_owner: false,
            include_tests: true,
            paths: Some(vec!["src/root.rs".into()]),
            depth: 1,
        },
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.from.ends_with("root.run") && edge.to.ends_with("middle.call")),
        "{graph:?}"
    );
    assert!(
        graph
            .edges
            .iter()
            .all(|edge| !edge.from.ends_with("middle.call")),
        "{graph:?}"
    );
}

#[test]
fn mixed_case_macro_guidance_preserves_the_invoked_name() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Cpp,
        &[
            ("defs.h", "#define Foo(x) (x)\n"),
            ("uses.cpp", "#include \"defs.h\"\nint value = Foo(1);\n"),
            ("wrong.h", "#define Other(x) (x)\n"),
        ],
    );
    let result = scan_usages_by_reference(
        fixture.analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["wrong.h#Foo".into()],
            include_tests: true,
            paths: None,
            include_same_owner: false,
        },
    );
    let entry = &result.results[0];
    assert_eq!(entry.status, ScanUsagesStatus::NotFound, "{result:?}");
    let message = entry.message.as_deref().expect("wrong anchor guidance");
    assert!(message.contains("\"name\":\"Foo\""), "{message}");
}

#[test]
fn location_scan_recovery_names_the_location_tool() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Python,
        &[("app.py", "def target():\n    pass\n")],
    );
    let result = scan_usages_by_location(
        fixture.analyzer.analyzer(),
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: "app.py".into(),
                line: 1,
                column: None,
                symbol: None,
            }],
            include_tests: true,
            paths: Some(vec!["missing.py".into()]),
            include_same_owner: false,
        },
    );
    let entry = &result.results[0];
    assert_eq!(
        entry.incomplete_reason,
        Some(ScanUsagesIncompleteReason::UnmatchedPaths)
    );
    let recovery = entry.message.as_deref().unwrap_or_default();
    let recovery = if recovery.contains("re-call") {
        recovery
    } else {
        entry
            .notes
            .iter()
            .find(|note| note.contains("re-call"))
            .map(String::as_str)
            .expect("recovery note")
    };
    assert!(recovery.contains("scan_usages_by_location"), "{result:?}");
}

#[test]
fn withheld_multiline_call_uses_its_start_line() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::TypeScript,
        &[(
            "main.ts",
            "class A { m(x: number): void {} }\nclass B { m(x: number): void {} }\nfunction caller(p: A | B): void {\n  p.m(\n    1\n  );\n}\n",
        )],
    );
    let graph = usage_graph(
        fixture.analyzer.analyzer(),
        UsageGraphParams {
            include_same_owner: false,
            include_tests: true,
            paths: None,
            depth: 1,
        },
    );
    assert!(
        graph
            .withheld_references
            .iter()
            .any(|reference| reference.line == 4),
        "{graph:?}"
    );
}

#[test]
fn scala_class_name_location_selects_the_source_declaration() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Scala,
        &[(
            "Service.scala",
            "class Service(value: String)\nobject Main { val service = new Service(\"x\") }\n",
        )],
    );
    let result = scan_usages_by_location(
        fixture.analyzer.analyzer(),
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: "Service.scala".into(),
                line: 1,
                column: Some(7),
                symbol: None,
            }],
            include_tests: true,
            paths: None,
            include_same_owner: false,
        },
    );
    let entry = &result.results[0];
    assert_eq!(entry.status, ScanUsagesStatus::Found, "{result:?}");
    assert_eq!(entry.fq_name.as_deref(), Some("Service"), "{result:?}");
}

#[test]
fn mixed_macro_and_function_wrong_anchor_uses_general_guidance() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Cpp,
        &[
            ("defs.h", "#define Foo(x) (x)\n"),
            ("ordinary.cpp", "int Foo(int x) { return x; }\n"),
            ("wrong.h", "#define Other(x) (x)\n"),
        ],
    );
    let result = scan_usages_by_reference(
        fixture.analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["wrong.h#Foo".into()],
            include_tests: true,
            paths: None,
            include_same_owner: false,
        },
    );
    let entry = &result.results[0];
    assert_eq!(entry.status, ScanUsagesStatus::NotFound, "{result:?}");
    assert!(
        !entry
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("as a C/C++ macro"),
        "{result:?}"
    );
}

#[test]
fn unsupported_cpp_namespace_diagnostic_keeps_cpp_language_label() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Cpp,
        &[("defs.cpp", "namespace Example { int value; }\n")],
    );
    let result = scan_usages_by_reference(
        fixture.analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["Example".into()],
            include_tests: true,
            paths: None,
            include_same_owner: false,
        },
    );
    let entry = &result.results[0];
    assert_eq!(
        entry.reason_kind.as_deref(),
        Some("unsupported_target_shape"),
        "{result:?}"
    );
    assert!(
        entry
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("C/C++"),
        "{result:?}"
    );
}

#[test]
fn raw_reference_sites_include_model_authored_accessor_call() {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogCoordinate, SemanticModelActivationEvidence, SemanticModelRuntimeOutcome,
    };

    let fixture = AnalyzerFixture::new_for_language(
        Language::Java,
        &[
            (
                "box.java",
                "class box { static void accessor() {} static void target() {} }\n",
            ),
            (
                "Caller.java",
                "class Caller { void run() { box.accessor(); } }\n",
            ),
        ],
    );
    let params = ScanUsagesByLocationParams {
        targets: vec![ScanUsagesTarget {
            path: "box.java".into(),
            line: 1,
            column: Some(51),
            symbol: Some("box.target".into()),
        }],
        include_tests: true,
        paths: None,
        include_same_owner: false,
    };
    let without_model = scan_usage_reference_sites_by_location(
        fixture.analyzer.analyzer(),
        params.clone(),
        CancellationToken::default(),
    );
    assert!(
        without_model[0]
            .files
            .iter()
            .all(|file| file.path != "Caller.java"),
        "{without_model:?}"
    );
    // This session pack exists only in this test. The modeled accessor is a
    // reference to a workspace method, with no target spelling at the callsite.
    // The inactive target shard validates the relation while leaving the
    // workspace declaration as the only active target identity.
    let pack_id = "fixture.raw-accessor-reference";
    let pack = serde_json::json!({
        "schema_version": 2,
        "pack_id": pack_id,
        "version": "1.0.0",
        "producer": { "name": "raw-reference-test", "version": "1.0.0" },
        "language": "java",
        "ecosystem": "test",
        "compatibility": { "bifrost": "*", "toolchains": [] },
        "provenance": { "source": "test-only" },
        "license": "NOASSERTION",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "declarations.fixture.raw-accessor-reference",
            "activation": [{ "module": { "name": "fixture" } }],
            "payload": {
                "kind": "declaration_facts",
                "types": [{
                    "id": "type.box",
                    "name": "box",
                    "type_kind": "class",
                    "visibility": "public",
                    "locator": { "kind": "source", "path": "box.java", "symbol": "box" }
                }],
                "members": [{
                    "id": "member.box.accessor",
                    "owner": "type.box",
                    "name": "accessor",
                    "member_kind": "method",
                    "visibility": "public",
                    "signature": { "parameters": [] },
                    "locator": { "kind": "source", "path": "box.java", "symbol": "box.accessor" }
                }],
                "relations": [{
                    "id": "relation.box.accessor.reference",
                    "relation_kind": "references",
                    "from": "member.box.accessor",
                    "to": "box.target"
                }]
            }
        }, {
            "id": "declarations.fixture.inactive-target",
            "activation": [{ "module": { "name": "inactive" } }],
            "payload": {
                "kind": "declaration_facts",
                "types": [{
                    "id": "box.target",
                    "name": "InactiveTarget",
                    "type_kind": "class",
                    "visibility": "public",
                    "locator": { "kind": "artifact", "path": "fixture.jar", "symbol": "InactiveTarget" }
                }],
                "members": [],
                "relations": []
            }
        }]
    });
    let catalog = brokk_bifrost_analysis::test_support::embedded_session_semantic_pack_fixture(
        pack_id,
        serde_json::to_vec(&pack).unwrap(),
    );
    let outcome = brokk_bifrost_analysis::test_support::activate_semantic_model_fixture(
        fixture.analyzer.analyzer(),
        &catalog,
        pack_id,
        SemanticModelActivationEvidence {
            language: "java".into(),
            ecosystem: "test".into(),
            package: None,
            module: Some(CatalogCoordinate {
                name: "fixture".into(),
                version: None,
            }),
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        },
    );
    assert!(
        matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }),
        "{outcome:?}"
    );
    let raw = scan_usage_reference_sites_by_location(
        fixture.analyzer.analyzer(),
        params,
        CancellationToken::default(),
    );
    assert_eq!(raw.len(), 1, "{raw:?}");
    assert!(
        raw[0]
            .files
            .iter()
            .any(|file| file.path == "Caller.java" && file.lines.contains(&1)),
        "{raw:?}"
    );
}
