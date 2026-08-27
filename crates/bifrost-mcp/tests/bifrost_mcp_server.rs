// `tests/common/mod.rs` is shared with the corpus and wire-schema suites and
// re-exports more than this binary uses.
#[allow(unused_imports)]
mod common;

use brokk_bifrost_analysis::Language;
use brokk_bifrost_policy::{PolicyEvaluationOptions, PolicyFailOn, evaluate_policy_files};
use common::InlineTestProject;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::path::PathBuf;
use std::process::{ChildStderr, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

// This crate's published suite owns its fixtures. Reaching into the private
// root `tests/fixtures/` tree would make the projected public tree fail to
// compile, so the dynamic-eval sample is checked in beside these tests.
const JSON_SCHEMA_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

const MCP_POLICY_APP: &str = include_str!("fixtures/policy-cli/app.py");
const MCP_DYNAMIC_EVAL_POLICY: &str = include_str!("fixtures/policy-cli/dynamic-eval.rqlp");

const PACK_ACTIVATION_JAVA: &str = r#"import java.util.ArrayList;
import java.util.Collections;

class Main {
  void sort(ArrayList<String> values) {
    Collections.sort(values);
  }
}
"#;

const PACK_ACTIVATION_POLICY: &str = r#"(policy
  :schema-version 1
  :id "probe.mcp.external-indexed"
  :name "MCP external references use a structured route"
  :message "the stdlib reference did not resolve through its indexed pack"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql (identifier :text/regex "^Collections$" :capture "target"))
    :asserts [(assert-resolution :id retain-candidate :at "target" :role receiver_position
                :expect-tier external_root :at-least true)
              (assert-boundary :id indexed-boundary :at "target" :role receiver_position
                :forbid-fallback-past external_declared_unindexed)]))
"#;

const PACK_ACTIVATION_JDK: &str = r#"{
  "schema_version": 1,
  "pack_id": "fixture.jdk",
  "version": "21.0.2",
  "producer": { "name": "bifrost-fixture", "version": "1.0.0" },
  "language": "java",
  "ecosystem": "jdk",
  "compatibility": {
    "bifrost": ">=0.8.0, <1.0.0",
    "toolchains": [{ "name": "jdk", "requirement": "=21.0.2" }]
  },
  "provenance": { "source": "checked-in MCP contract fixture", "revision": "fixture-v1" },
  "license": "GPL-2.0-only WITH Classpath-exception-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "jdk.array-list",
    "activation": [{
      "toolchain": { "name": "jdk", "version": "=21.0.2" },
      "targets": ["jvm"]
    }],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "jdk.java-util-arraylist",
        "name": "java.util.ArrayList",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": ["E"],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "java.base/java/util/ArrayList.java",
          "symbol": "java.util.ArrayList"
        }
      }, {
        "id": "jdk.java-util-collections",
        "name": "java.util.Collections",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "java.base/java/util/Collections.java",
          "symbol": "java.util.Collections"
        }
      }],
      "members": [{
        "id": "jdk.java-util-collections.sort",
        "owner": "jdk.java-util-collections",
        "name": "sort",
        "member_kind": "method",
        "visibility": "public",
        "is_static": true,
        "locator": {
          "kind": "artifact",
          "path": "java.base/java/util/Collections.java",
          "symbol": "java.util.Collections.sort"
        }
      }],
      "relations": []
    }
  }]
}"#;

fn mcp_server_binary() -> &'static str {
    option_env!("CARGO_BIN_EXE_bifrost-mcp-test-server")
        .or(option_env!("CARGO_BIN_EXE_bifrost"))
        .expect("Cargo did not provide an MCP server binary")
}

fn install_pack_activation_fixture(root: &std::path::Path) {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogOpenMode, CatalogOptions, CompilerOptions, DurablePackSource, DurablePackSourceKind,
        SemanticPackCatalog, SourceFormat, compile_source,
    };

    let compiled = compile_source(
        SourceFormat::Json,
        PACK_ACTIVATION_JDK.as_bytes(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture pack compilation failed: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open(
        &root.join(".bifrost/packs-catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .expect("open fixture catalog");
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: "test:fixture.jdk@21.0.2".to_owned(),
            },
        )
        .expect("install fixture pack");
}

fn fake_jdk_home(root: &std::path::Path, version: &str) -> PathBuf {
    let home = root.join(format!("jdk-{version}"));
    fs::create_dir_all(&home).expect("create fake JDK home");
    fs::write(
        home.join("release"),
        format!("JAVA_VERSION=\"{version}\"\nIMPLEMENTOR=\"Bifrost fixture\"\n"),
    )
    .expect("write fake JDK release metadata");
    home
}

fn run_pack_activation_policy(
    project: &common::BuiltInlineTestProject,
    java_home: &std::path::Path,
) -> (Value, Value) {
    let mut child = mcp_server_command(project.root(), "searchtools", &[])
        .env("JAVA_HOME", java_home)
        .spawn()
        .expect("spawn pack activation MCP server");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);
    let candidates = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1867,
            "method": "tools/call",
            "params": {
                "name": "query_code",
                "arguments": {
                    "languages": ["java"],
                    "occurrences": { "role": ["receiver_position"] },
                    "steps": [{ "op": "candidates_of", "outcome": ["selected"] }]
                }
            }
        }),
    );
    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1868,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_files": ["policies/external-indexed.rqlp"],
                    "evaluation_date": "2026-08-25",
                    "fail_on": "warning"
                }
            }
        }),
    );
    drop(stdin);
    assert!(child.wait().expect("wait MCP server").success());
    assert_eq!(candidates["result"]["isError"], false, "{candidates:#}");
    assert_eq!(response["result"]["isError"], false, "{response:#}");
    (
        candidates["result"]["structuredContent"].clone(),
        response["result"]["structuredContent"].clone(),
    )
}

fn pack_activation_project(ecosystems: &str, install_pack: bool) -> common::BuiltInlineTestProject {
    let project = InlineTestProject::new()
        .file("src/Main.java", PACK_ACTIVATION_JAVA)
        .file(
            "policies/external-indexed.rqlp",
            PACK_ACTIVATION_POLICY,
        )
        .file(
            ".bifrost/packs.json",
            format!(
                r#"{{ "schema_version": 1, "catalog": ".bifrost/packs-catalog", "ecosystems": {ecosystems} }}"#
            ),
        )
        .build();
    if install_pack {
        install_pack_activation_fixture(project.root());
    }
    project
}

#[test]
fn mcp_bound_policy_reports_exact_pack_activation_and_honest_near_misses() {
    let homes = TempDir::new().expect("fake JDK home root");
    let jdk21 = fake_jdk_home(homes.path(), "21.0.2");
    let compatible = pack_activation_project(r#"["jvm"]"#, true);
    let (compatible_candidates, compatible_run) = run_pack_activation_policy(&compatible, &jdk21);
    assert_eq!(compatible_run["exit_status"], 0, "{compatible_run:#}");
    assert_eq!(
        compatible_run["report"]["runs"][0]["completion"]["type"], "complete",
        "{compatible_run:#}"
    );
    assert_eq!(
        compatible_run["report"]["packs"]["dependency_mode"],
        "configured"
    );
    assert_eq!(compatible_run["report"]["packs"]["complete"], true);
    assert!(
        compatible_candidates["results"]
            .as_array()
            .expect("resolution candidate rows")
            .iter()
            .any(|candidate| {
                candidate["result_type"] == "resolution_candidate"
                    && candidate["boundary"] == "external_indexed"
                    && candidate["outcome"] == "selected"
                    && candidate["external_target"] == "java.util.Collections.sort"
            }),
        "the bound MCP workspace must expose the exact selected boundary: {compatible_candidates:#}"
    );

    let no_pack = pack_activation_project(r#"["jvm"]"#, false);
    let (_, no_pack_run) = run_pack_activation_policy(&no_pack, &jdk21);
    assert_eq!(no_pack_run["exit_status"], 2, "{no_pack_run:#}");
    assert_eq!(
        no_pack_run["report"]["runs"][0]["completion"]["type"],
        "inconclusive"
    );

    let incompatible = pack_activation_project(r#"["jvm"]"#, true);
    let jdk17 = fake_jdk_home(homes.path(), "17.0.10");
    let (_, incompatible_run) = run_pack_activation_policy(&incompatible, &jdk17);
    assert_eq!(incompatible_run["exit_status"], 2, "{incompatible_run:#}");
    assert!(
        incompatible_run["report"]["packs"]["decisions"]
            .as_array()
            .expect("incompatible decisions")
            .iter()
            .any(|decision| decision["status"] == "version_mismatch"),
        "{incompatible_run:#}"
    );

    let disabled = pack_activation_project("[]", true);
    let (_, disabled_run) = run_pack_activation_policy(&disabled, &jdk21);
    assert_eq!(disabled_run["exit_status"], 2, "{disabled_run:#}");
    assert_eq!(
        disabled_run["report"]["packs"]["dependency_mode"],
        "disabled"
    );
    assert_eq!(
        disabled_run["report"]["runs"][0]["completion"]["type"],
        "inconclusive"
    );

    let failed = pack_activation_project(r#"["jvm"]"#, false);
    fs::write(
        failed.root().join(".bifrost/packs-catalog"),
        "not a catalog directory",
    )
    .expect("create invalid configured catalog path");
    let (_, failed_run) = run_pack_activation_policy(&failed, &jdk21);
    assert_eq!(failed_run["exit_status"], 2, "{failed_run:#}");
    assert_eq!(failed_run["report"]["packs"]["complete"], false);
    assert!(
        failed_run["report"]["packs"]["decisions"]
            .as_array()
            .expect("failed activation decisions")
            .iter()
            .any(|decision| decision["status"] == "rejected"),
        "{failed_run:#}"
    );
    assert!(
        failed_run["report"]["diagnostics"]
            .as_array()
            .expect("failed activation diagnostics")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "pack-activation-failed"),
        "{failed_run:#}"
    );
}

fn assert_same_canonical_path(actual: &str, expected: &std::path::Path) {
    assert_eq!(
        std::path::Path::new(actual)
            .canonicalize()
            .expect("canonicalize actual path"),
        expected.canonicalize().expect("canonicalize expected path")
    );
}

#[test]
fn bifrost_searchtools_server_speaks_mcp_stdio() {
    let fixture_root = TempDir::new().expect("temp dir");
    fs::write(
        fixture_root.path().join("SampleTest.java"),
        r#"
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class SampleTest {
            @Test
            void sameValue() {
                String value = "x";
                assertEquals(value, value);
            }
        }
        "#,
    )
    .expect("write java fixture");
    fs::write(
        fixture_root.path().join("sample_spec.rb"),
        r#"
        RSpec.describe Widget do
          it "compares itself" do
            expect(value).to eq(value)
          end
        end
        "#,
    )
    .expect("write ruby fixture");
    fs::write(
        fixture_root.path().join("SampleClone.java"),
        r#"
        public class SampleClone {
            int sameValue(int input) {
                int total = input + 1;
                int doubled = total * 2;
                int adjusted = total - 3;
                if (total > 10) {
                    total = doubled;
                } else {
                    total = adjusted;
                }
                for (int index = 0; index < 3; index++) {
                    total += index;
                }
                if (total % 2 == 0) {
                    total += 5;
                } else {
                    total -= 5;
                }
                return total;
            }
        }
        "#,
    )
    .expect("write clone java fixture");
    fs::write(
        fixture_root.path().join("PeerClone.java"),
        r#"
        public class PeerClone {
            int sameValue(int seed) {
                int amount = seed + 1;
                int doubled = amount * 2;
                int adjusted = amount - 3;
                if (amount > 10) {
                    amount = doubled;
                } else {
                    amount = adjusted;
                }
                for (int index = 0; index < 3; index++) {
                    amount += index;
                }
                if (amount % 2 == 0) {
                    amount += 5;
                } else {
                    amount -= 5;
                }
                return amount;
            }
        }
        "#,
    )
    .expect("write peer clone java fixture");
    let repo = git2::Repository::init(fixture_root.path()).expect("init fixture repo");
    let mut index = repo.index().expect("repo index");
    index
        .add_path(std::path::Path::new("SampleTest.java"))
        .expect("add sample file");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let sig = git2::Signature::now("Test User", "test@example.com").expect("signature");
    repo.commit(Some("HEAD"), &sig, &sig, "initial", &tree, &[])
        .expect("initial commit");
    repo.reference_symbolic(
        "refs/remotes/origin/HEAD",
        "refs/heads/master",
        true,
        "set remote default",
    )
    .expect("set remote default");

    let mut child = Command::new(mcp_server_binary())
        .arg("--root")
        .arg(fixture_root.path())
        .arg("--mcp")
        .arg("searchtools")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "0.1.0"
                }
            }
        }),
    );
    assert_eq!("2.0", initialize["jsonrpc"]);
    assert_eq!(0, initialize["id"]);
    assert_eq!("2025-11-25", initialize["result"]["protocolVersion"]);
    assert_eq!(initialize["result"]["capabilities"]["tools"], json!({}));
    assert_eq!(initialize["result"]["capabilities"]["resources"], json!({}));
    let instructions = initialize["result"]["instructions"]
        .as_str()
        .expect("server instructions");
    assert!(
        instructions.starts_with("Source-code analysis and repository navigation."),
        "{initialize}"
    );
    assert!(instructions.contains("Symbol tools"), "{initialize}");
    assert!(instructions.contains("CodeQuery and RQL"), "{initialize}");
    assert!(instructions.contains("repository policies"), "{initialize}");
    assert!(
        !instructions.contains("Semantic search finds"),
        "semantic search is disabled for this process: {initialize}"
    );
    assert!(instructions.chars().count() <= 2_000, "{initialize}");

    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    let list_tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }),
    );
    let tools = list_tools["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert_eq!(tool_names(tools), {
        let expected = vec![
            "search_symbols",
            "get_symbol_sources",
            "get_summaries",
            "scan_usages_by_location",
            "get_declarations_by_location",
            "get_definitions_by_location",
            "get_type_by_location",
            "rename_symbol",
            "usage_graph",
            "refresh",
            "activate_workspace",
            "get_active_workspace",
            "query_code",
            "list_policies",
            "run_policy",
            "explain_policy",
            "get_symbol_locations",
            "get_symbol_ancestors",
            "most_relevant_files",
            "get_file_contents",
            "search_file_contents",
            "find_files_containing",
            "compute_cyclomatic_complexity",
            "compute_cognitive_complexity",
            "report_comment_density_for_code_unit",
            "report_exception_handling_smells",
            "report_comment_density_for_files",
            "analyze_git_hotspots",
            "report_test_assertion_smells",
            "report_structural_clone_smells",
            "report_long_method_and_god_object_smells",
            "report_dead_code_and_unused_abstraction_smells",
            "report_secret_like_code",
            "analyze_diff",
            "classify_test_files",
        ];
        expected
    });
    assert_tool_schema_omits_property(tools, "get_definitions_by_location", "include_tests");
    assert_tool_schema_omits_property(tools, "get_declarations_by_location", "include_tests");
    // #1575: ranking reports a per-file test verdict instead of taking a
    // boolean it could only honour by guessing.
    assert_tool_schema_omits_property(tools, "most_relevant_files", "include_tests");
    assert_definition_lookup_schema_limits_and_requires_location(tools);
    assert_declaration_lookup_schema_limits_and_requires_location(tools);
    assert_tool_schema_contains_property(tools, "scan_usages_by_location", "targets");
    assert_scan_usages_location_schema(tools);
    assert_type_lookup_schema_limits_and_requires_location(tools);
    assert_rename_symbol_schema_requires_location_and_new_name(tools);

    let list_resources = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1_1,
            "method": "resources/list"
        }),
    );
    assert_eq!(
        list_resources["result"]["resources"],
        json!([
            {
                "uri": "bifrost://agent-guidance/agents.md",
                "name": "bifrost-agents.md",
                "title": "Bifrost AGENTS.md guidance",
                "description": "Appendable agent instructions for Bifrost code-intelligence workflows.",
                "mimeType": "text/markdown",
                "annotations": {
                    "audience": ["user", "assistant"],
                    "priority": 0.8
                }
            }
        ]),
        "{list_resources}"
    );

    let resource = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1_2,
            "method": "resources/read",
            "params": { "uri": "bifrost://agent-guidance/agents.md" }
        }),
    );
    assert_eq!(
        resource["result"]["contents"][0]["uri"], "bifrost://agent-guidance/agents.md",
        "{resource}"
    );
    assert_eq!(
        resource["result"]["contents"][0]["mimeType"], "text/markdown",
        "{resource}"
    );
    let guidance = resource["result"]["contents"][0]["text"]
        .as_str()
        .expect("resource guidance text");
    assert!(guidance.contains("get_summaries"), "{guidance}");
    assert!(guidance.contains("search_symbols"), "{guidance}");
    assert!(guidance.contains("get_symbol_sources"), "{guidance}");
    assert!(guidance.contains("scan_usages_by_location"), "{guidance}");

    let missing_resource = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1_3,
            "method": "resources/read",
            "params": { "uri": "bifrost://agent-guidance/missing.md" }
        }),
    );
    assert_eq!(
        missing_resource["error"]["code"], -32002,
        "{missing_resource}"
    );
    assert!(
        missing_resource["error"]["message"]
            .as_str()
            .expect("missing resource error message")
            .contains("Resource not found"),
        "{missing_resource}"
    );

    let ping = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "ping"
        }),
    );
    assert_eq!(json!({}), ping["result"]);

    let test_assertion_smells = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "report_test_assertion_smells",
                "arguments": {
                    "file_paths": ["SampleTest.java", "sample_spec.rb"]
                }
            }
        }),
    );
    let report = test_assertion_smells["result"]["structuredContent"]["report"]
        .as_str()
        .expect("report string");
    assert!(report.starts_with("## Test assertion smells"), "{report}");
    assert!(report.contains("self-comparison"), "{report}");
    assert!(report.contains("SampleTest.java"), "{report}");
    assert!(report.contains("sample_spec.rb"), "{report}");

    let symbol_sources = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 7_1,
            "method": "tools/call",
            "params": {
                "name": "get_symbol_sources",
                "arguments": {
                    "symbols": ["SampleTest.sameValue"]
                }
            }
        }),
    );
    let source_preview = symbol_sources["result"]["content"][0]["text"]
        .as_str()
        .expect("source preview text");
    assert!(
        source_preview.starts_with("## SampleTest.sameValue\n\n- Location: SampleTest.java:"),
        "{source_preview}"
    );
    assert!(source_preview.contains("```text\n"), "{source_preview}");
    assert!(
        !source_preview.trim_start().starts_with('{'),
        "{source_preview}"
    );
    let source_text = symbol_sources["result"]["structuredContent"]["sources"][0]["text"]
        .as_str()
        .expect("source block text");
    assert!(!source_text.starts_with("6: "), "{source_text}");

    fs::write(
        fixture_root.path().join("PeerTest.java"),
        r#"
        public class PeerTest {
            int sameValue(int seed) {
                int amount = seed + 1;
                if (amount > 10) {
                    return amount * 2;
                }
                return amount - 3;
            }
        }
        "#,
    )
    .expect("write peer java fixture");
    fs::write(fixture_root.path().join("helpers.rs"), "fn helper() {}\n")
        .expect("write rust fixture");
    fs::write(fixture_root.path().join("main.rs"), "fn main() {}\n")
        .expect("write rust main fixture");

    let dead_code_smells = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "report_dead_code_and_unused_abstraction_smells",
                "arguments": {
                    "file_paths": ["helpers.rs", "main.rs"],
                    "fq_names": ["helpers.helper"]
                }
            }
        }),
    );
    let dead_code_report = dead_code_smells["result"]["structuredContent"]["report"]
        .as_str()
        .expect("dead code report string");
    assert!(
        dead_code_report.starts_with("## Dead code and unused abstraction smells"),
        "{dead_code_report}"
    );
    assert!(
        dead_code_report.contains("helpers.helper"),
        "{dead_code_report}"
    );

    let tracked_clone_inputs = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 7_2,
            "method": "tools/call",
            "params": {
                "name": "get_file_contents",
                "arguments": {
                    "file_paths": ["SampleClone.java", "PeerClone.java"]
                }
            }
        }),
    );
    assert_eq!(
        2,
        tracked_clone_inputs["result"]["structuredContent"]["files"]
            .as_array()
            .expect("tracked clone files array")
            .len()
    );
    sleep_for_mtime_tick();
    fs::write(
        fixture_root.path().join("SampleClone.java"),
        r#"
        public class SampleClone {
            int sameValue(int number) {
                int total = number + 1;
                if (total > 10) {
                    return total * 2;
                }
                return total - 3;
            }
        }
        "#,
    )
    .expect("rewrite clone java fixture");
    fs::write(
        fixture_root.path().join("PeerClone.java"),
        r#"
        public class PeerClone {
            int sameValue(int seed) {
                int result = seed + 1;
                if (result > 10) {
                    return result * 2;
                }
                return result - 3;
            }
        }
        "#,
    )
    .expect("rewrite peer java fixture");
    let refresh = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "refresh",
                "arguments": {}
            }
        }),
    );
    assert!(refresh["result"]["structuredContent"]["analyzed_files"].is_number());

    let clone_smells = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "report_structural_clone_smells",
                "arguments": {
                    "file_paths": ["SampleClone.java", "PeerClone.java"]
                }
            }
        }),
    );
    let clone_report = clone_smells["result"]["structuredContent"]["report"]
        .as_str()
        .expect("clone report string");
    assert!(
        clone_report.starts_with("## Structural clone smells"),
        "{clone_report}"
    );
    assert!(
        clone_report.contains("SampleClone.sameValue"),
        "{clone_report}"
    );
    assert!(
        clone_report.contains("PeerClone.sameValue"),
        "{clone_report}"
    );

    let secret_file = fixture_root.path().join("config.properties");
    fs::write(
        &secret_file,
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )
    .expect("write secret fixture");
    let repo = git2::Repository::open(fixture_root.path()).expect("open fixture repo");
    let mut index = repo.index().expect("repo index");
    index
        .add_path(std::path::Path::new("config.properties"))
        .expect("add secret file");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let head_commit = repo
        .head()
        .expect("repo head")
        .target()
        .and_then(|oid| repo.find_commit(oid).ok())
        .expect("head commit");
    let sig = git2::Signature::now("Test User", "test@example.com").expect("signature");
    repo.commit(
        Some("HEAD"),
        &sig,
        &sig,
        "add secret",
        &tree,
        &[&head_commit],
    )
    .expect("commit secret");
    let refresh_after_secret = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "refresh",
                "arguments": {}
            }
        }),
    );
    assert!(refresh_after_secret["result"]["structuredContent"]["analyzed_files"].is_number());

    let secret_scan = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "report_secret_like_code",
                "arguments": {
                    "max_findings": 10,
                    "max_commits": 10
                }
            }
        }),
    );
    let secret_report = secret_scan["result"]["structuredContent"]["report"]
        .as_str()
        .expect("secret report string");
    assert!(
        secret_report.starts_with("## brokk-secret-scan"),
        "{secret_report}"
    );
    assert!(
        secret_report.contains("config.properties"),
        "{secret_report}"
    );
    assert!(
        !secret_report.contains("AKIAIOSFODNN7EXAMPLE"),
        "{secret_report}"
    );
    assert!(
        !secret_report.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        "{secret_report}"
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn cognitive_complexity_reports_every_supported_language_in_one_mcp_call() {
    let workspace = InlineTestProject::new()
        .file(
            "main.go",
            "package main\nfunc goBusy(a, b bool) { if a { if b {} } }\n",
        )
        .file(
            "main.c",
            "int cBusy(int a, int b) { if (a) { if (b) return 1; } return 0; }\n",
        )
        .file(
            "main.cpp",
            "int cppBusy(int a, int b) { if (a) { if (b) return 1; } return 0; }\n",
        )
        .file(
            "main.js",
            "function jsBusy(a, b) { if (a) { if (b) return 1; } return 0; }\n",
        )
        .file(
            "view.jsx",
            "function jsxBusy(a, b) { if (a) { if (b) return <span />; } return null; }\n",
        )
        .file(
            "main.ts",
            "function tsBusy(a: boolean, b: boolean) { if (a) { if (b) return 1; } return 0; }\n",
        )
        .file(
            "view.tsx",
            "function tsxBusy(a: boolean, b: boolean) { if (a) { if (b) return <span />; } return null; }\n",
        )
        .file(
            "main.php",
            "<?php function phpBusy($a, $b) { if ($a) { if ($b) return 1; } return 0; }\n",
        )
        .file(
            "Main.scala",
            "def scalaBusy(a: Boolean, b: Boolean): Int = { if (a) { if (b) 1 else 0 } else 0 }\n",
        )
        .file(
            "Service.cs",
            "class Service { int csharpBusy(bool a, bool b) { if (a) { if (b) return 1; } return 0; } }\n",
        )
        .build();
    let file_paths = [
        "main.go",
        "main.c",
        "main.cpp",
        "main.js",
        "view.jsx",
        "main.ts",
        "view.tsx",
        "main.php",
        "Main.scala",
        "Service.cs",
    ];

    let mut child = spawn_server(workspace.root(), "slopcop", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "compute_cognitive_complexity",
                "arguments": {
                    "file_paths": file_paths,
                    "threshold": 1
                }
            }
        }),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["truncated"], false,
        "{response}"
    );
    let report = response["result"]["structuredContent"]["report"]
        .as_str()
        .expect("cognitive complexity report");
    for function in [
        "goBusy",
        "cBusy",
        "cppBusy",
        "jsBusy",
        "jsxBusy",
        "tsBusy",
        "tsxBusy",
        "phpBusy",
        "scalaBusy",
        "csharpBusy",
    ] {
        assert!(
            report.contains(&format!("{function}: 3")),
            "missing {function} from report:\n{report}"
        );
    }

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_defaults_to_cwd_searchtools_server() {
    let fixture_root = TempDir::new().expect("temp dir");
    fs::write(
        fixture_root.path().join("DefaultRoot.java"),
        "public class DefaultRoot {}\n",
    )
    .expect("write java fixture");
    let repo = git2::Repository::init(fixture_root.path()).expect("init fixture repo");
    let mut index = repo.index().expect("repo index");
    index
        .add_path(std::path::Path::new("DefaultRoot.java"))
        .expect("add java file");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let sig = git2::Signature::now("Test User", "test@example.com").expect("signature");
    repo.commit(Some("HEAD"), &sig, &sig, "initial", &tree, &[])
        .expect("initial commit");

    let mut child = spawn_server_no_args(fixture_root.path());

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let active_workspace = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_active_workspace",
                "arguments": {}
            }
        }),
    );
    assert_same_canonical_path(
        active_workspace["result"]["structuredContent"]["workspace_path"]
            .as_str()
            .expect("workspace path"),
        fixture_root.path(),
    );

    let list_symbols = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_symbols",
                "arguments": { "file_patterns": ["DefaultRoot.java"] }
            }
        }),
    );
    assert_eq!(list_symbols["result"]["isError"], true, "{list_symbols}");
    assert_eq!(
        list_symbols["result"]["content"][0]["text"],
        "Unknown tool: list_symbols"
    );

    let symbol_sources = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_symbol_sources",
                "arguments": { "symbols": ["DefaultRoot.java"] }
            }
        }),
    );
    assert_eq!(
        symbol_sources["result"]["isError"], false,
        "{symbol_sources}"
    );
    assert_eq!(
        symbol_sources["result"]["structuredContent"]["sources"][0]["path"],
        "DefaultRoot.java"
    );
    let source_preview = symbol_sources["result"]["content"][0]["text"]
        .as_str()
        .expect("source preview text");
    assert!(
        source_preview.contains("## DefaultRoot.java"),
        "{source_preview}"
    );
    assert!(
        source_preview.contains("- Location: DefaultRoot.java:1.."),
        "{source_preview}"
    );
    assert!(source_preview.contains("```text\n"), "{source_preview}");

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_query_code_transports_explain_and_profile_reports() {
    let fixture_root = TempDir::new().expect("temp dir");
    fs::write(fixture_root.path().join("App.java"), "class App {}\n").expect("write fixture");
    let mut child = spawn_server(fixture_root.path(), "extended", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let explain = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": {
                "name": "query_code",
                "arguments": {
                    "execution_mode": "explain",
                    "match": {"kind": "class", "name": "App"}
                }
            }
        }),
    );
    assert_eq!(explain["result"]["isError"], false, "{explain}");
    assert_eq!(
        explain["result"]["structuredContent"]["format"],
        "bifrost_code_query_explain/v1"
    );
    assert!(
        explain["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("planning only")),
        "{explain}"
    );

    let profile = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {
                "name": "query_code",
                "arguments": {
                    "execution_mode": "profile",
                    "match": {"kind": "class", "name": "App"}
                }
            }
        }),
    );
    assert_eq!(profile["result"]["isError"], false, "{profile}");
    assert_eq!(
        profile["result"]["structuredContent"]["format"],
        "bifrost_code_query_profile/v2"
    );
    assert_eq!(
        profile["result"]["structuredContent"]["result"]["results"][0]["kind"],
        "class"
    );
    assert!(
        profile["result"]["structuredContent"]["operators"]
            .as_array()
            .is_some_and(|operators| !operators.is_empty()),
        "{profile}"
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_run_policy_uses_the_active_snapshot_and_durable_suppressions() {
    let initial = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", "def harmless(value):\n    return value\n")
        .file("policies/dynamic-eval.rqlp", MCP_DYNAMIC_EVAL_POLICY)
        .build();
    let switched = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", MCP_POLICY_APP)
        .file("policies/dynamic-eval.rqlp", MCP_DYNAMIC_EVAL_POLICY)
        .build();
    let evaluation_date = "2026-07-27";
    let expected = evaluate_policy_files(
        switched.root(),
        &[PathBuf::from("policies/dynamic-eval.rqlp")],
        &PolicyEvaluationOptions::new(evaluation_date.parse().expect("fixed evaluation date"))
            .with_fail_on(PolicyFailOn::Warning),
    )
    .expect("direct policy evaluation");
    assert_eq!(expected.exit_status(), 1);
    let expected_report = serde_json::to_value(expected.report()).expect("serialize direct report");

    let mut child = spawn_server(initial.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let list_tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
    );
    assert!(
        tool_names(
            list_tools["result"]["tools"]
                .as_array()
                .expect("tools array")
        )
        .contains(&"run_policy"),
        "{list_tools}"
    );

    let activate = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": {
                    "workspace_path": switched.root().display().to_string()
                }
            }
        }),
    );
    assert_eq!(activate["result"]["isError"], false, "{activate}");
    assert_same_canonical_path(
        activate["result"]["structuredContent"]["workspace_path"]
            .as_str()
            .expect("activated workspace"),
        switched.root(),
    );

    let baseline = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_files": ["policies/dynamic-eval.rqlp"],
                    "evaluation_date": evaluation_date,
                    "fail_on": "warning"
                }
            }
        }),
    );
    assert_eq!(baseline["result"]["isError"], false, "{baseline}");
    let structured = &baseline["result"]["structuredContent"];
    // A log-safe hash of the request id, so a policy report found in a log can
    // be traced back to the call that produced it without the raw
    // client-controlled id ever being written down. Asserted here, over the
    // wire, because the feature landed as a unit test against one host while
    // the other host serves by default -- which is how it would go missing.
    let correlation = structured["request_correlation_id"]
        .as_str()
        .unwrap_or_else(|| panic!("run_policy must report a correlation id: {baseline}"));
    assert!(
        correlation.starts_with("sha256:") && correlation.len() > "sha256:".len(),
        "correlation id must be a hash, not the raw request id: {correlation}"
    );
    assert_eq!(structured["status"], "finding", "{baseline}");
    assert_eq!(structured["exit_status"], 1, "{baseline}");
    assert_eq!(structured["report"], expected_report, "{baseline}");
    assert_eq!(structured["report"]["schema_version"], 5);
    assert_eq!(
        structured["report"]["execution"]["stage_timings"],
        json!([])
    );
    // Stage attribution is an explicit opt-in sibling (#2611): by default the
    // result carries no `stage_timings` key at all.
    assert!(
        structured.get("stage_timings").is_none(),
        "timings must be requested explicitly: {baseline}"
    );
    assert_eq!(
        structured["report"]["evaluation"]["evaluation_date"],
        evaluation_date
    );
    assert_eq!(
        structured["report"]["runs"][0]["findings"][0]["primary"]["path"],
        "src/app.py"
    );

    let attributed = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_files": ["policies/dynamic-eval.rqlp"],
                    "evaluation_date": evaluation_date,
                    "fail_on": "warning",
                    "include_stage_timings": true
                }
            }
        }),
    );
    assert_eq!(attributed["result"]["isError"], false, "{attributed}");
    let attributed = &attributed["result"]["structuredContent"];
    // The canonical report is identical to the unattributed run's: requested
    // timings ride beside it, never inside it.
    assert_eq!(attributed["report"], expected_report, "{attributed}");
    assert_eq!(
        attributed["report"]["execution"]["stage_timings"],
        json!([])
    );
    let attribution_stages = attributed["stage_timings"]
        .as_array()
        .expect("requested stage timings")
        .iter()
        .map(|timing| timing["stage"].as_str().expect("stage name").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        attribution_stages,
        vec![
            "policy_selection",
            "suppression_preflight",
            "workspace_snapshot",
            "policy_registration",
            "policy_preparation",
            "policy_evaluation",
            "report_construction",
        ],
        "{attributed}"
    );

    let policy_id = structured["report"]["rules"][0]["policy_id"].clone();
    let policy_hash = structured["report"]["rules"][0]["policy_hash"].clone();
    let finding_id = structured["report"]["runs"][0]["findings"][0]["id"].clone();
    let suppression_path = switched.root().join("reviews/accepted.json");
    fs::create_dir_all(suppression_path.parent().expect("suppression parent"))
        .expect("create suppression directory");
    fs::write(
        &suppression_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "suppressions": [{
                "policy_id": policy_id,
                "finding_id": finding_id,
                "identity_stability": "strong",
                "status": "accepted",
                "reason": "Reviewed through MCP",
                "policy_hash_at_acceptance": policy_hash,
                "accepted_by": "mcp-review",
                "accepted_at": "2026-07-01",
                "expires_at": evaluation_date
            }]
        }))
        .expect("serialize suppressions"),
    )
    .expect("write suppressions");

    let suppressed = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_files": ["policies/dynamic-eval.rqlp"],
                    "suppression_file": "reviews/accepted.json",
                    "evaluation_date": evaluation_date
                }
            }
        }),
    );
    let suppressed = &suppressed["result"]["structuredContent"];
    assert_eq!(suppressed["status"], "clean");
    assert_eq!(suppressed["exit_status"], 0);
    assert_eq!(
        suppressed["report"]["runs"][0]["findings"][0]["id"],
        finding_id
    );
    assert_eq!(
        suppressed["report"]["runs"][0]["findings"][0]["suppression"]["status"],
        "accepted"
    );
    assert_eq!(suppressed["report"]["suppressions"][0]["applied"], true);

    let expired = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_files": ["policies/dynamic-eval.rqlp"],
                    "suppression_file": "reviews/accepted.json",
                    "evaluation_date": "2026-07-28"
                }
            }
        }),
    );
    assert_eq!(
        expired["result"]["structuredContent"]["status"], "finding",
        "{expired}"
    );
    assert_eq!(
        expired["result"]["structuredContent"]["report"]["suppressions"][0]["temporal_state"],
        "expired",
        "{expired}"
    );

    fs::write(&suppression_path, "{ invalid suppression json").expect("invalidate suppressions");
    let invalid_suppression = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_files": ["policies/dynamic-eval.rqlp"],
                    "suppression_file": "reviews/accepted.json",
                    "evaluation_date": evaluation_date
                }
            }
        }),
    );
    assert_eq!(
        invalid_suppression["result"]["structuredContent"]["status"], "unreliable",
        "{invalid_suppression}"
    );
    assert_eq!(
        invalid_suppression["result"]["structuredContent"]["exit_status"],
        2
    );
    assert_eq!(
        invalid_suppression["result"]["structuredContent"]["report"]["diagnostics"][0]["code"],
        "suppression-load-failed"
    );

    for (id, arguments) in [
        (
            7,
            json!({
                "policy_files": ["../outside.rqlp"],
                "evaluation_date": evaluation_date
            }),
        ),
        (
            8,
            json!({
                "policy_files": ["policies/dynamic-eval.rqlp"],
                "evaluation_date": "2026-02-30"
            }),
        ),
        (9, json!({ "policy_files": ["policies/dynamic-eval.rqlp"] })),
    ] {
        let invalid = round_trip(
            &mut stdin,
            &mut reader,
            &mut stderr,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": "run_policy", "arguments": arguments }
            }),
        );
        assert_eq!(invalid["error"]["code"], -32602, "{invalid}");
    }

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

/// Malformed suppressions are configuration input, not analyzer input. The
/// RMCP host must return their canonical report before it waits for the cold
/// watcher/snapshot, while retaining the wire correlation contract.
#[test]
fn rmcp_run_policy_malformed_suppressions_fail_before_readiness() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", "def harmless(value):\n    return value\n")
        .file(".bifrost/suppressions.json", "{ malformed")
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        malformed_run_policy_request(1),
    );
    assert_compact_malformed_run_policy_reply(&response, false);

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Task-capable clients must still receive the immediate canonical report;
/// malformed configuration cannot be parked behind a task handle.
#[test]
fn task_capable_rmcp_run_policy_malformed_suppressions_is_not_a_task() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", "def harmless(value):\n    return value\n")
        .file(".bifrost/suppressions.json", "{ malformed")
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_tasks_session(&mut stdin, &mut reader, &mut stderr, "2026-07-28");

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        malformed_run_policy_request(1),
    );
    assert_compact_malformed_run_policy_reply(&response, true);

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

#[test]
fn bifrost_mcp_lists_and_runs_built_in_policies() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", MCP_POLICY_APP)
        .build();
    let mut child = spawn_server(project.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let listed = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "list_policies", "arguments": {} }
        }),
    );
    assert_eq!(listed["result"]["isError"], false, "{listed}");
    assert_eq!(
        listed["result"]["structuredContent"]["id"],
        "bifrost.code-smells"
    );
    assert_eq!(
        listed["result"]["structuredContent"]["policies"]
            .as_array()
            .map(Vec::len),
        Some(13)
    );

    let run = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                    "evaluation_date": "2026-07-28",
                    "fail_on": "warning"
                }
            }
        }),
    );
    assert_eq!(run["result"]["isError"], false, "{run}");
    let structured = &run["result"]["structuredContent"];
    assert_eq!(structured["status"], "finding", "{run}");
    assert_eq!(
        structured["report"]["runs"][0]["policy_id"],
        "bifrost.correctness.dynamic-evaluation"
    );
    assert_eq!(
        structured["report"]["runs"][0]["findings"][0]["primary"]["path"],
        "src/app.py"
    );

    let category = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_categories": ["correctness"],
                    "evaluation_date": "2026-07-28",
                    "fail_on": "never"
                }
            }
        }),
    );
    let category_ids = category["result"]["structuredContent"]["report"]["runs"]
        .as_array()
        .expect("category runs")
        .iter()
        .map(|run| run["policy_id"].as_str().expect("category policy id"))
        .collect::<Vec<_>>();
    assert_eq!(
        category_ids,
        vec![
            "bifrost.correctness.dynamic-evaluation",
            "bifrost.correctness.rayon-in-blocking-lazy-init",
            "bifrost.correctness.unsafe-deserialization"
        ],
        "{category}"
    );

    let pack = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_packs": ["bifrost.code-smells"],
                    "evaluation_date": "2026-07-28",
                    "fail_on": "never"
                }
            }
        }),
    );
    let pack_runs = pack["result"]["structuredContent"]["report"]["runs"]
        .as_array()
        .expect("pack runs");
    let pack_ids = pack_runs
        .iter()
        .map(|run| run["policy_id"].as_str().expect("pack policy id"))
        .collect::<Vec<_>>();
    assert_eq!(
        pack_ids,
        vec![
            "bifrost.correctness.dynamic-evaluation",
            "bifrost.correctness.rayon-in-blocking-lazy-init",
            "bifrost.correctness.unsafe-deserialization",
            "bifrost.performance.database-call-in-loop",
            "bifrost.performance.expensive-operation-in-nested-loop",
            "bifrost.performance.file-read-in-loop",
            "bifrost.performance.loop-invariant-sort",
            "bifrost.performance.network-call-in-loop",
            "bifrost.performance.parsing-in-loop",
            "bifrost.performance.regex-compile-in-loop",
            "bifrost.performance.serialization-in-loop",
            "bifrost.performance.sleep-in-loop",
            "bifrost.performance.subprocess-in-loop",
        ],
        "{pack}"
    );

    let unknown = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_ids": ["bifrost.correctness.missing"],
                    "evaluation_date": "2026-07-28"
                }
            }
        }),
    );
    assert_eq!(unknown["error"]["code"], -32602, "{unknown}");

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_cli_toolset_exposes_classify_test_files() {
    let fixture_root = TempDir::new().expect("temp dir");
    fs::create_dir_all(fixture_root.path().join("src/test/java")).expect("test dir");
    fs::create_dir_all(fixture_root.path().join("src/main/java")).expect("main dir");
    fs::write(
        fixture_root.path().join("SampleTest.java"),
        r#"
        import org.junit.jupiter.api.Test;

        public class SampleTest {
            @Test
            void works() {}
        }
        "#,
    )
    .expect("write test file");
    fs::write(
        fixture_root.path().join("src/test/java/Helper.java"),
        r#"
        public class Helper {
            String value() { return "ok"; }
        }
        "#,
    )
    .expect("write helper file");
    fs::write(
        fixture_root.path().join("src/main/java/Production.java"),
        r#"
        public class Production {
            void works() {}
        }
        "#,
    )
    .expect("write production file");

    let mut child = spawn_server(fixture_root.path(), "cli", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let list_tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
    );
    let tools = list_tools["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert!(
        tool_names(tools).contains(&"classify_test_files"),
        "cli toolset should advertise classify_test_files: {list_tools}"
    );

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "classify_test_files",
                "arguments": {
                    "file_paths": [
                        "SampleTest.java",
                        "src/test/java/Helper.java",
                        "src/main/java/Production.java",
                        "Missing.java"
                    ]
                }
            }
        }),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"],
        json!({
            "classifications": {
                "SampleTest.java": {
                    "kind": "test",
                    "contains_test_code": true
                },
                "src/main/java/Production.java": {
                    "kind": "production",
                    "contains_test_code": false
                },
                "src/test/java/Helper.java": {
                    "kind": "test_support",
                    "contains_test_code": false
                }
            },
            "unresolved": ["Missing.java"]
        }),
        "{response}"
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_normalizes_absolute_paths_inside_workspace() {
    let fixture_root = TempDir::new().expect("temp dir");
    fs::create_dir(fixture_root.path().join("src")).expect("src dir");
    let java_path = fixture_root.path().join("src").join("A.java");
    fs::write(
        &java_path,
        r#"
        public class A {
            void marker() {
                String value = "NEEDLE";
            }
        }
        "#,
    )
    .expect("write java fixture");

    let mut child = spawn_server(fixture_root.path(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let contents = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_file_contents",
                "arguments": { "file_paths": [java_path.display().to_string()] }
            }
        }),
    );
    assert_eq!(contents["result"]["isError"], false, "{contents}");
    assert_eq!(
        contents["result"]["structuredContent"]["files"][0]["path"],
        "src/A.java"
    );

    let summaries = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_summaries",
                "arguments": { "targets": [java_path.display().to_string()] }
            }
        }),
    );
    assert_eq!(summaries["result"]["isError"], false, "{summaries}");
    assert_eq!(
        summaries["result"]["structuredContent"]["summaries"][0]["path"],
        "src/A.java"
    );

    let absolute_glob_root = fixture_root
        .path()
        .canonicalize()
        .expect("canonicalize fixture root");
    let absolute_glob = format!("{}/src/**/*.java", absolute_glob_root.display());
    let search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "search_file_contents",
                "arguments": {
                    "patterns": ["NEEDLE"],
                    "file_path": absolute_glob,
                    "context_lines": 0
                }
            }
        }),
    );
    assert_eq!(search["result"]["isError"], false, "{search}");
    assert_eq!(
        search["result"]["structuredContent"]["matches"][0]["path"],
        "src/A.java"
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_reports_absolute_paths_outside_workspace_as_tool_errors() {
    let fixture_root = TempDir::new().expect("temp dir");
    fs::write(fixture_root.path().join("A.java"), "public class A {}\n")
        .expect("write java fixture");
    let outside = TempDir::new().expect("outside dir");
    let outside_file = outside.path().join("outside.txt");
    fs::write(&outside_file, "outside").expect("write outside fixture");

    let mut child = spawn_server(fixture_root.path(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_file_contents",
                "arguments": { "file_paths": [outside_file.display().to_string()] }
            }
        }),
    );
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["isError"], true, "{response}");
    let message = response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool error text");
    assert!(message.contains("outside active workspace"), "{message}");
    assert!(!message.contains("not found"), "{message}");

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_absolute_paths_follow_activated_workspace() {
    let initial_root = TempDir::new().expect("initial temp dir");
    fs::write(
        initial_root.path().join("Initial.java"),
        "public class Initial {}\n",
    )
    .expect("write initial fixture");

    let switched = TempDir::new().expect("switched temp dir");
    let switched_file = switched.path().join("Switched.java");
    fs::write(&switched_file, "public class Switched {}\n").expect("write switched fixture");
    let switched_root = switched.path().canonicalize().expect("canonicalize");

    let mut child = spawn_server(initial_root.path(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let activate = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": { "workspace_path": switched_root.display().to_string() }
            }
        }),
    );
    assert_eq!(activate["result"]["isError"], false, "{activate}");

    let contents = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_file_contents",
                "arguments": { "file_paths": [switched_file.display().to_string()] }
            }
        }),
    );
    assert_eq!(contents["result"]["isError"], false, "{contents}");
    assert_eq!(
        contents["result"]["structuredContent"]["files"][0]["path"],
        "Switched.java"
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_get_summaries_mixed_targets_include_directory_listing() {
    let fixture_root = TempDir::new().expect("temp dir");
    fs::write(
        fixture_root.path().join("A.java"),
        "public class A { int x() { return 1; } }\n",
    )
    .expect("write fixture");
    fs::write(
        fixture_root.path().join("B.java"),
        "public class B { int y() { return 2; } }\n",
    )
    .expect("write fixture");

    let mut child = spawn_server(fixture_root.path(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_summaries",
                "arguments": { "targets": ["A.java", "."] }
            }
        }),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    let structured = &response["result"]["structuredContent"];
    assert_eq!("A.java", structured["summaries"][0]["path"], "{structured}");
    assert_eq!(false, structured["degraded"], "{structured}");
    assert!(
        structured["listings"][0]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "file" && entry["path"] == "A.java"),
        "{structured}"
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text");
    assert!(text.contains("A.java"), "{text}");
    assert!(text.contains("Directory ."), "{text}");

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_get_summaries_accepts_go_import_path() {
    let fixture_root = TempDir::new().expect("temp dir");
    fs::write(
        fixture_root.path().join("go.mod"),
        "module example.com/m\n\ngo 1.21\n",
    )
    .expect("write go.mod");
    let pkg_dir = fixture_root.path().join("internal").join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    fs::write(
        pkg_dir.join("foo.go"),
        "package pkg\n\nfunc Foo() int { return 1 }\n\ntype Bar struct{}\n",
    )
    .expect("write go source");

    let mut child = spawn_server(fixture_root.path(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    // Import/package paths return direct child packages and exact-package top-level types.
    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_summaries",
                "arguments": { "targets": ["example.com/m/internal/pkg"] }
            }
        }),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    let structured = &response["result"]["structuredContent"];
    assert_eq!(false, structured["degraded"], "{structured}");
    assert!(
        structured["summaries"]
            .as_array()
            .map(Vec::is_empty)
            .unwrap_or(true),
        "{structured}"
    );
    let entries = structured["listings"][0]["entries"]
        .as_array()
        .expect("package listing entries");
    let package_type = entries
        .iter()
        .find(|entry| {
            entry["kind"] == "type" && entry["symbol"] == "example.com/m/internal/pkg.Bar"
        })
        .unwrap_or_else(|| panic!("missing package type in {structured}"));
    assert_eq!("go", package_type["language"]);
    assert_eq!("internal/pkg/foo.go", package_type["path"]);

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_budgets_large_get_summaries_responses() {
    let fixture_root = TempDir::new().expect("temp dir");
    for class_idx in 0..18 {
        let mut source = format!("public class Caller{class_idx} {{\n");
        for method_idx in 0..12 {
            source.push_str(&format!(
                "    public int method{method_idx}(int input) {{ return input + {class_idx} + {method_idx}; }}\n"
            ));
        }
        source.push_str("}\n");
        fs::write(
            fixture_root.path().join(format!("Caller{class_idx}.java")),
            source,
        )
        .expect("write fixture");
    }

    let mut child = spawn_server(fixture_root.path(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_summaries",
                "arguments": { "targets": ["*.java"] }
            }
        }),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text");
    assert!(
        text.len() <= 4096,
        "mcp text should stay within budget, got {} bytes",
        text.len()
    );
    let structured = &response["result"]["structuredContent"];
    assert_eq!(true, structured["degraded"], "{structured}");
    assert_eq!(
        "response_budget_exceeded", structured["degradation"]["reason"],
        "{structured}"
    );
    assert!(
        structured["summaries"].as_array().unwrap().is_empty(),
        "{structured}"
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

fn sleep_for_mtime_tick() {
    thread::sleep(Duration::from_millis(25));
}

fn tool_names(tools: &[Value]) -> Vec<&str> {
    tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect()
}

fn assert_tool_schema_omits_property(tools: &[Value], tool_name: &str, property_name: &str) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == tool_name)
        .unwrap_or_else(|| panic!("missing tool descriptor for {tool_name}"));
    let schema = serde_json::to_string(&tool["inputSchema"]).expect("schema serializes");
    assert!(
        !schema.contains(property_name),
        "{tool_name} schema unexpectedly contains {property_name}: {schema}"
    );
}

fn assert_tool_schema_contains_property(tools: &[Value], tool_name: &str, property_name: &str) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == tool_name)
        .unwrap_or_else(|| panic!("missing tool descriptor for {tool_name}"));
    let schema = serde_json::to_string(&tool["inputSchema"]).expect("schema serializes");
    assert!(
        schema.contains(property_name),
        "{tool_name} schema should contain {property_name}: {schema}"
    );
}

fn assert_scan_usages_location_schema(tools: &[Value]) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "scan_usages_by_location")
        .expect("missing scan_usages_by_location descriptor");
    let schema = &tool["inputSchema"];

    assert_eq!(schema["properties"]["targets"]["minItems"], 1);
    assert_eq!(
        schema["properties"]["targets"]["items"]["required"],
        json!(["path", "line"])
    );
    let serialized = serde_json::to_string(schema).unwrap();
    assert!(!serialized.contains("start_byte"), "{serialized}");
    assert!(!serialized.contains("end_byte"), "{serialized}");
}

fn assert_type_lookup_schema_limits_and_requires_location(tools: &[Value]) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "get_type_by_location")
        .expect("missing get_type_by_location descriptor");
    let schema = &tool["inputSchema"];

    assert_eq!(schema["properties"]["references"]["maxItems"], 100);
    assert_eq!(
        schema["properties"]["references"]["items"]["required"],
        json!(["path", "line"])
    );
    let serialized = serde_json::to_string(schema).unwrap();
    assert!(!serialized.contains("start_byte"), "{serialized}");
    assert!(!serialized.contains("end_byte"), "{serialized}");
}

fn assert_definition_lookup_schema_limits_and_requires_location(tools: &[Value]) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "get_definitions_by_location")
        .expect("missing get_definitions_by_location descriptor");
    let schema = &tool["inputSchema"];

    assert_eq!(schema["properties"]["references"]["maxItems"], 100);
    assert_eq!(
        schema["properties"]["references"]["items"]["required"],
        json!(["path", "line"])
    );
}

fn assert_declaration_lookup_schema_limits_and_requires_location(tools: &[Value]) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "get_declarations_by_location")
        .expect("missing get_declarations_by_location descriptor");
    let schema = &tool["inputSchema"];

    assert_eq!(schema["properties"]["references"]["maxItems"], 100);
    assert_eq!(
        schema["properties"]["references"]["items"]["required"],
        json!(["path", "line"])
    );
}

fn assert_rename_symbol_schema_requires_location_and_new_name(tools: &[Value]) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "rename_symbol")
        .expect("missing rename_symbol descriptor");
    let schema = &tool["inputSchema"];

    assert_eq!(
        schema["required"],
        json!(["path", "line", "column", "new_name"])
    );
    let serialized = serde_json::to_string(schema).unwrap();
    assert!(!serialized.contains("start_byte"), "{serialized}");
    assert!(!serialized.contains("end_byte"), "{serialized}");
    assert_eq!(schema["properties"]["new_name"]["minLength"], 1);
    assert_eq!(schema["properties"]["new_name"]["maxLength"], json!(256));
}

/// The `outputSchema` the running server published for `tool_name`.
///
/// The schema is taken off the wire rather than recomputed in the test: the
/// advertised artifact is the thing that has to describe real output.
fn advertised_output_schema<'a>(tools: &'a [Value], tool_name: &str) -> &'a Value {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == tool_name)
        .unwrap_or_else(|| panic!("missing tool descriptor for {tool_name}"));
    let schema = tool
        .get("outputSchema")
        .unwrap_or_else(|| panic!("{tool_name} advertised no outputSchema: {tool}"));
    assert_eq!(
        schema["$schema"], JSON_SCHEMA_2020_12,
        "{tool_name} outputSchema does not declare the 2020-12 dialect: {schema}"
    );
    schema
}

/// Validate one real `structuredContent` against the schema the server
/// advertised for the tool that produced it.
fn assert_structured_content_matches_advertised_schema(
    tools: &[Value],
    tool_name: &str,
    response: &Value,
) {
    let schema = advertised_output_schema(tools, tool_name);
    let structured = response["result"]
        .get("structuredContent")
        .unwrap_or_else(|| panic!("{tool_name} returned no structuredContent: {response}"));
    let validator = jsonschema::draft202012::new(schema).unwrap_or_else(|error| {
        panic!("{tool_name} outputSchema is not a valid 2020-12 schema: {error}\n{schema}")
    });
    let violations: Vec<String> = validator
        .iter_errors(structured)
        .map(|error| format!("{} at instance path `{}`", error, error.instance_path()))
        .collect();
    assert!(
        violations.is_empty(),
        "{tool_name} structuredContent violates its advertised outputSchema: {violations:?}\nschema: {schema}\ninstance: {structured}"
    );
}

fn call_tool(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: i64,
    name: &str,
    arguments: Value,
) -> Value {
    let response = round_trip(
        stdin,
        reader,
        stderr,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    response
}

#[test]
fn rootless_mcp_binds_to_client_roots_without_analyzing_process_cwd() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    fs::write(
        plugin_dir.path().join("PluginOnly.java"),
        "class PluginOnly {}\n",
    )
    .expect("write plugin fixture");
    let relative_workspace = plugin_dir.path().join("workspace");
    fs::create_dir(&relative_workspace).expect("create relative workspace fixture");
    fs::write(
        relative_workspace.join("RelativeWorkspace.java"),
        "class RelativeWorkspace {}\n",
    )
    .expect("write relative workspace fixture");
    let workspace = TempDir::new().expect("workspace");
    fs::write(
        workspace.path().join("ClientWorkspace.java"),
        "class ClientWorkspace {}\n",
    )
    .expect("write workspace fixture");
    let replacement = TempDir::new().expect("replacement workspace");
    fs::write(
        replacement.path().join("ReplacementWorkspace.java"),
        "class ReplacementWorkspace {}\n",
    )
    .expect("write replacement fixture");

    let mut child = spawn_rootless_server(plugin_dir.path(), "workspace|symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": { "roots": { "listChanged": true } },
                "clientInfo": { "name": "cursor-vscode", "version": "3.12.30" }
            }
        }),
    );
    assert_eq!(initialize["result"]["serverInfo"]["name"], "bifrost");
    assert!(
        initialize["result"]["capabilities"]["experimental"].is_null(),
        "standard roots must take precedence over Codex metadata: {initialize}"
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    // A roots change that reaches the server while its roots/list is still
    // outstanding supersedes the answer. The client withdrew that scope, so it
    // must never become analyzer scope -- not even briefly, and not by being
    // stamped as current when it is bound.
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 19,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["PluginOnly"] }
            }
        }),
    );
    let stale_roots_request = read_line(&mut reader, &mut stderr);
    assert_eq!(
        stale_roots_request["method"], "roots/list",
        "{stale_roots_request}"
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }),
    );
    let plugin_uri = url::Url::from_directory_path(plugin_dir.path())
        .expect("plugin file URI")
        .to_string();
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": stale_roots_request["id"],
            "result": { "roots": [{ "uri": plugin_uri, "name": "stale" }] }
        }),
    );
    let superseded = read_line(&mut reader, &mut stderr);
    assert!(
        superseded["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "a superseded roots answer must not be bound: {superseded}"
    );
    assert!(
        !plugin_dir
            .path()
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "a withdrawn root must never become analyzer storage"
    );

    // Bifrost asks for roots when a request actually needs a workspace, so the
    // first tool call is what triggers the exchange. A relative root can never
    // resolve against process cwd, so answering with one leaves the call
    // unserved rather than silently scoping the analyzer to the plugin dir.
    let rejected_relative_root = call_tool_answering_roots(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["RelativeWorkspace"] }
            }
        }),
        json!({ "roots": [{ "uri": "workspace", "name": "relative" }] }),
    );
    assert!(
        rejected_relative_root["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "a relative client root must never resolve against process cwd: {rejected_relative_root}"
    );

    // Cursor 3.12.30 advertises standard MCP roots but returns its workspace as
    // a native absolute path rather than a file URI. Codex sandbox metadata on
    // the same call must not win against it.
    let search = call_tool_answering_roots(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["ClientWorkspace"] },
                "_meta": codex_sandbox_metadata(plugin_dir.path(), "roots-precedence")
            }
        }),
        json!({
            "roots": [{ "uri": workspace.path().display().to_string(), "name": "fixture" }]
        }),
    );
    assert_eq!(search["result"]["isError"], false, "{search}");
    assert!(search.to_string().contains("ClientWorkspace"), "{search}");
    assert!(!search.to_string().contains("PluginOnly"), "{search}");

    let rejected_activation = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": { "workspace_path": plugin_dir.path().display().to_string() }
            }
        }),
    );
    assert_eq!(
        rejected_activation["result"]["isError"], true,
        "MCP roots must remain the only workspace authority: {rejected_activation}"
    );
    assert!(
        rejected_activation["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|message| message.contains("controlled by MCP client roots")),
        "{rejected_activation}"
    );

    // An approved root stays approved: no further roots exchange, and the
    // rejected activation left it untouched.
    let still_bound_search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["ClientWorkspace"] }
            }
        }),
    );
    assert_eq!(
        still_bound_search["result"]["isError"], false,
        "a rejected activation must leave the approved root active: {still_bound_search}"
    );
    assert!(
        still_bound_search.to_string().contains("ClientWorkspace"),
        "{still_bound_search}"
    );

    // A roots change revokes the scope immediately; the next request that needs
    // a workspace re-negotiates one.
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }),
    );
    let replacement_uri = url::Url::from_directory_path(replacement.path())
        .expect("replacement file URI")
        .to_string();
    let replacement_search = call_tool_answering_roots(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["ReplacementWorkspace"] },
                "_meta": codex_sandbox_metadata(plugin_dir.path(), "roots-refresh")
            }
        }),
        json!({ "roots": [{ "uri": replacement_uri }] }),
    );
    assert_eq!(
        replacement_search["result"]["isError"], false,
        "{replacement_search}"
    );
    assert!(
        replacement_search
            .to_string()
            .contains("ReplacementWorkspace"),
        "{replacement_search}"
    );

    // An empty roots list is the client revoking Bifrost's scope outright.
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }),
    );
    let revoked_search = call_tool_answering_roots(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["ReplacementWorkspace"] }
            }
        }),
        json!({ "roots": [] }),
    );
    assert!(
        revoked_search["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "{revoked_search}"
    );
    assert!(
        !plugin_dir
            .path()
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "plugin cwd must not become analyzer storage"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

#[test]
fn rootless_mcp_binds_from_codex_sandbox_state_and_revokes_per_call_scope() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    fs::write(
        plugin_dir.path().join("PluginOnly.java"),
        "class PluginOnly {}\n",
    )
    .expect("write plugin fixture");
    let workspace = InlineTestProject::new()
        .file("CodexWorkspace.java", "class CodexWorkspace {}\n")
        .build();
    let replacement = InlineTestProject::new()
        .file("SecondWorkspace.java", "class SecondWorkspace {}\n")
        .build();

    assert_codex_metadata_cannot_bind_before_initialize(plugin_dir.path(), workspace.root());

    let mut child = spawn_rootless_server(plugin_dir.path(), "workspace|symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_initialize_request(1),
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"]["codex/sandbox-state-meta"],
        json!({}),
        "{initialize}"
    );

    write_line(&mut stdin, codex_handshake_message("initialized"));

    let search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_search_symbols_call(2, workspace.root(), "codex-test-thread", "CodexWorkspace"),
    );
    assert_eq!(search["result"]["isError"], false, "{search}");
    assert!(search.to_string().contains("CodexWorkspace"), "{search}");

    let rejected_activation = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": { "workspace_path": plugin_dir.path().display().to_string() },
                "_meta": codex_sandbox_metadata(
                    workspace.root(),
                    "codex-test-thread"
                )
            }
        }),
    );
    assert_eq!(
        rejected_activation["result"]["isError"], true,
        "sandbox metadata must remain the only workspace authority: {rejected_activation}"
    );
    assert!(
        rejected_activation["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|message| message.contains("controlled by Codex sandbox metadata")),
        "{rejected_activation}"
    );

    let plugin_scope_search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_search_symbols_call(2_1, workspace.root(), "codex-test-thread", "PluginOnly"),
    );
    assert_eq!(
        plugin_scope_search["result"]["structuredContent"]["files"],
        json!([]),
        "plugin cwd content must not enter workspace scope: {plugin_scope_search}"
    );

    let replacement_search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_search_symbols_call(
            3,
            replacement.root(),
            "codex-test-thread",
            "SecondWorkspace",
        ),
    );
    assert_eq!(
        replacement_search["result"]["isError"], false,
        "{replacement_search}"
    );
    assert!(
        replacement_search.to_string().contains("SecondWorkspace"),
        "{replacement_search}"
    );

    let old_scope_search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_search_symbols_call(
            3_1,
            replacement.root(),
            "codex-test-thread",
            "CodexWorkspace",
        ),
    );
    assert_eq!(
        old_scope_search["result"]["structuredContent"]["files"],
        json!([]),
        "old workspace must not remain queryable: {old_scope_search}"
    );

    let mut invalid_request = codex_search_symbols_call(
        4,
        replacement.root(),
        "codex-test-thread",
        "SecondWorkspace",
    );
    invalid_request["params"]["_meta"]["codex/sandbox-state-meta"]["sandboxCwd"] =
        json!("https://example.com/not-a-workspace");
    let invalid = round_trip(&mut stdin, &mut reader, &mut stderr, invalid_request);
    assert_eq!(invalid["error"]["code"], -32602, "{invalid}");
    assert!(
        invalid["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Invalid Codex sandbox workspace metadata")),
        "{invalid}"
    );

    let rebound = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_search_symbols_call(
            5,
            replacement.root(),
            "codex-test-thread",
            "SecondWorkspace",
        ),
    );
    assert_eq!(rebound["result"]["isError"], false, "{rebound}");

    let unavailable_root = replacement.root().join("missing-workspace");
    let unavailable = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_search_symbols_call(
            5_1,
            &unavailable_root,
            "codex-test-thread",
            "SecondWorkspace",
        ),
    );
    assert_eq!(unavailable["error"]["code"], -32602, "{unavailable}");
    assert!(
        unavailable["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("client workspace root")),
        "a failed replacement must surface the unusable root: {unavailable}"
    );

    let rebound_after_failure = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_search_symbols_call(
            5_2,
            replacement.root(),
            "codex-test-thread",
            "SecondWorkspace",
        ),
    );
    assert_eq!(
        rebound_after_failure["result"]["isError"], false,
        "a failed replacement must leave the old root revoked but allow a later valid bind: {rebound_after_failure}"
    );

    let duplicate_initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 5_3,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": { "roots": { "listChanged": true } },
                "clientInfo": { "name": "replacement-client", "version": "1" }
            }
        }),
    );
    assert_eq!(
        duplicate_initialize["error"]["code"], -32600,
        "duplicate initialize must not replace the connection authority: {duplicate_initialize}"
    );

    let missing = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["SecondWorkspace"] }
            }
        }),
    );
    assert_eq!(missing["error"]["code"], -32603, "{missing}");
    assert!(
        missing["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "{missing}"
    );
    assert!(
        !plugin_dir
            .path()
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "plugin cwd must not become analyzer storage"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
    let mut logs = String::new();
    stderr.read_to_string(&mut logs).expect("read stderr");
    assert!(
        logs.contains("workspace_protocol=codex-sandbox-state"),
        "{logs}"
    );
    assert!(logs.contains("source=codex/sandbox-state-meta"), "{logs}");
    assert!(logs.contains("thread_id=codex-test-thread"), "{logs}");
    assert!(logs.contains("reason=metadata changed"), "{logs}");
    assert!(logs.contains("reason=metadata invalid"), "{logs}");
    assert!(logs.contains("reason=metadata missing"), "{logs}");
    assert!(logs.contains("failed workspace bind"), "{logs}");
    assert!(!logs.contains("permissionProfile"), "{logs}");
    assert!(!logs.contains("writableRoots"), "{logs}");
}

#[test]
fn rootless_mcp_rejects_first_codex_workspace_activation_outside_sandbox() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    let workspace = InlineTestProject::new()
        .file("FirstCallWorkspace.java", "class FirstCallWorkspace {}\n")
        .build();

    let mut child = spawn_rootless_server(plugin_dir.path(), "workspace");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_initialize_request(1),
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"]["codex/sandbox-state-meta"],
        json!({}),
        "{initialize}"
    );
    write_line(&mut stdin, codex_handshake_message("initialized"));

    let rejected_activation = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": { "workspace_path": plugin_dir.path().display().to_string() },
                "_meta": codex_sandbox_metadata(workspace.root(), "first-call-activation")
            }
        }),
    );
    assert_eq!(
        rejected_activation["result"]["isError"], true,
        "the first metadata-bearing call must not escape its sandbox: {rejected_activation}"
    );

    let active_workspace = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_active_workspace",
                "arguments": {},
                "_meta": codex_sandbox_metadata(workspace.root(), "first-call-activation")
            }
        }),
    );
    let active_path = active_workspace["result"]["structuredContent"]["workspace_path"]
        .as_str()
        .expect("active workspace path");
    assert_same_canonical_path(active_path, workspace.root());
    assert!(
        !plugin_dir
            .path()
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "rejected activation must not create analyzer state in the escaped root"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

#[test]
fn explicit_mcp_root_ignores_codex_sandbox_state() {
    let explicit_workspace = InlineTestProject::new()
        .file("ExplicitWorkspace.java", "class ExplicitWorkspace {}\n")
        .build();
    let conflicting_workspace = InlineTestProject::new()
        .file("MetadataWorkspace.java", "class MetadataWorkspace {}\n")
        .build();
    let mut child = spawn_server(explicit_workspace.root(), "symbol", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_initialize_request(1),
    );
    assert!(
        initialize["result"]["capabilities"]["experimental"].is_null(),
        "explicit roots must not negotiate metadata binding: {initialize}"
    );
    write_line(&mut stdin, codex_handshake_message("initialized"));

    let search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["ExplicitWorkspace"] },
                "_meta": codex_sandbox_metadata(conflicting_workspace.root(), "explicit-root")
            }
        }),
    );
    assert_eq!(search["result"]["isError"], false, "{search}");
    assert!(search.to_string().contains("ExplicitWorkspace"), "{search}");
    assert!(
        !search.to_string().contains("MetadataWorkspace"),
        "{search}"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

#[test]
fn rootless_mcp_accepts_codex_sandbox_metadata_from_a_compatible_client() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    fs::write(
        plugin_dir.path().join("PluginOnly.java"),
        "class PluginOnly {}\n",
    )
    .expect("write plugin fixture");
    let workspace = InlineTestProject::new()
        .file("CompatibleWorkspace.java", "class CompatibleWorkspace {}\n")
        .build();
    let mut child = spawn_rootless_server(plugin_dir.path(), "symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    let initialize = initialize_session(&mut stdin, &mut reader, &mut stderr);
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"]["codex/sandbox-state-meta"],
        json!({}),
        "{initialize}"
    );

    let tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }),
    );
    assert!(
        tools["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "{tools}"
    );
    let search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["CompatibleWorkspace"] },
                "_meta": codex_sandbox_metadata(workspace.root(), "compatible-client")
            }
        }),
    );
    assert_eq!(search["result"]["isError"], false, "{search}");
    assert!(
        search.to_string().contains("CompatibleWorkspace"),
        "{search}"
    );
    assert!(
        !plugin_dir
            .path()
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "plugin cwd must not become analyzer storage"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

fn initialize_session(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
) -> Value {
    initialize_session_speaking(stdin, reader, stderr, "2025-11-25")
}

fn initialize_session_speaking(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    protocol_version: &str,
) -> Value {
    let initialize = round_trip(
        stdin,
        reader,
        stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }),
    );
    assert_eq!(
        initialize["result"]["protocolVersion"], protocol_version,
        "server did not negotiate the requested revision: {initialize}"
    );
    write_line(
        stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    initialize
}

fn codex_handshake_message(name: &str) -> Value {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/fixtures/mcp/codex-sandbox-state-handshake.json"
    )))
    .expect("parse recorded Codex MCP handshake fixture");
    fixture
        .get(name)
        .unwrap_or_else(|| panic!("recorded Codex MCP handshake has no {name} message"))
        .clone()
}

fn codex_initialize_request(id: i64) -> Value {
    let mut request = codex_handshake_message("initialize");
    request["id"] = json!(id);
    request
}

/// Send a tool call, answering the `roots/list` request it provokes.
///
/// Bifrost asks a Roots-capable client for its workspace from inside the call
/// that needs one, so a call made while unbound is answered only after the
/// client supplies roots. A call made while already bound provokes no request
/// and its response arrives directly, which is why this peeks at the method
/// rather than assuming an exchange happens.
fn call_tool_answering_roots(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    request: Value,
    roots_result: Value,
) -> Value {
    write_line(stdin, request);
    let message = read_line(reader, stderr);
    if message["method"] != "roots/list" {
        return message;
    }
    write_line(
        stdin,
        json!({ "jsonrpc": "2.0", "id": message["id"], "result": roots_result }),
    );
    read_line(reader, stderr)
}

/// A Codex tool call sent before `initialize` must not bind a workspace.
///
/// The MCP lifecycle permits only `ping` before `initialize`, so the server
/// refuses the call outright and ends the session rather than answering it.
/// That is stricter than returning an "unbound workspace" error: the sandbox
/// metadata is never even interpreted, and the sandbox root is never touched.
/// `server/discover` is the stateless 2026-07-28 entry point: a client sends it
/// *instead of* `initialize`, carrying the negotiation keys in `_meta`, and
/// rmcp answers it before any session exists. It is not a mid-session call.
#[test]
fn rmcp_host_answers_2026_07_28_discovery_before_any_handshake() {
    let workspace = InlineTestProject::new()
        .file("DiscoverMe.java", "class DiscoverMe {}\n")
        .build();
    let mut child = mcp_server_command(workspace.root(), "searchtools", &[])
        .spawn()
        .expect("spawn RMCP bifrost");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    let discover = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": { "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        }),
    );
    let versions = discover["result"]["supportedVersions"]
        .as_array()
        .unwrap_or_else(|| panic!("server/discover must list supported versions: {discover}"));
    for expected in ["2025-11-25", "2026-07-28"] {
        assert!(
            versions.iter().any(|version| version == expected),
            "server/discover must advertise {expected}: {discover}"
        );
    }
    assert_eq!(
        discover["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "bifrost",
        "{discover}"
    );

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_2026_07_28_clients_get_result_types() {
    let workspace = InlineTestProject::new()
        .file("DiscoverMe.java", "class DiscoverMe {}\n")
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": { "name": "modern", "version": "1" }
            }
        }),
    );
    assert_eq!(
        initialize["result"]["protocolVersion"], "2026-07-28",
        "a client asking for the new revision must get it: {initialize}"
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    // The discriminator is what tells a 2026-07-28 client the result is final
    // rather than an MRTR intermediate, so it has to be present.
    let call = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "search_symbols", "arguments": { "patterns": ["DiscoverMe"] } }
        }),
    );
    assert_eq!(call["result"]["resultType"], "complete", "{call}");
    assert_eq!(call["result"]["isError"], false, "{call}");

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

#[test]
fn cache_hints_reach_new_clients_and_stay_off_the_legacy_wire() {
    let workspace = InlineTestProject::new()
        .file("Cacheable.java", "class Cacheable {}\n")
        .build();

    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": { "name": "modern", "version": "1" }
            }
        }),
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    let tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    );
    assert_eq!(tools["result"]["ttlMs"], 300_000, "{tools}");
    // Two servers started in different modes publish different tool lists and
    // nothing in the response says which, so this must not be shared.
    assert_eq!(tools["result"]["cacheScope"], "private", "{tools}");

    let resource = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": { "uri": "bifrost://agent-guidance/agents.md" }
        }),
    );
    // Compiled into the binary, so identical for every client of this build.
    assert_eq!(resource["result"]["ttlMs"], 3_600_000, "{resource}");
    assert_eq!(resource["result"]["cacheScope"], "public", "{resource}");

    // Tool results are never cacheable: every one depends on the bound
    // workspace and the current state of the files in it.
    let call = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "search_symbols", "arguments": { "patterns": ["Cacheable"] } }
        }),
    );
    assert!(call["result"]["ttlMs"].is_null(), "{call}");
    assert!(call["result"]["cacheScope"].is_null(), "{call}");
    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());

    // A 2025-11-25 client has no schema for these fields; rmcp strips
    // `resultType` for legacy peers but not the cache hints, so Bifrost has to.
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);
    let tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    );
    assert!(tools["result"]["ttlMs"].is_null(), "{tools}");
    assert!(tools["result"]["cacheScope"].is_null(), "{tools}");
    let resource = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": { "uri": "bifrost://agent-guidance/agents.md" }
        }),
    );
    assert!(resource["result"]["ttlMs"].is_null(), "{resource}");
    assert!(resource["result"]["cacheScope"].is_null(), "{resource}");

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

#[test]
fn legacy_clients_never_see_a_result_type() {
    let workspace = InlineTestProject::new()
        .file("LegacyOnly.java", "class LegacyOnly {}\n")
        .build();
    // Pinned: the fallback host has no `resultType` to suppress, so asserting
    // its absence there would pass without testing anything.
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    initialize_session(&mut stdin, &mut reader, &mut stderr);
    let call = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "search_symbols", "arguments": { "patterns": ["LegacyOnly"] } }
        }),
    );
    // A 2025-11-25 client has no `resultType` in its schema; emitting one would
    // be a wire-shape regression for every client that ships today.
    assert!(
        call["result"]["resultType"].is_null(),
        "a legacy session must not carry resultType: {call}"
    );
    assert_eq!(call["result"]["isError"], false, "{call}");

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// The four tools of the first `outputSchema` slice (issue #2321). Every other
/// published tool answers with a shape that is not yet a declared contract.
const OUTPUT_SCHEMA_TOOLS: [&str; 4] = [
    "get_active_workspace",
    "list_policies",
    "search_symbols",
    "get_definitions_by_location",
];

#[test]
fn output_schema_reaches_new_clients_and_stays_off_the_legacy_wire() {
    let workspace = InlineTestProject::new()
        .file("Described.java", "class Described {}\n")
        .build();

    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let listed = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
    );
    let tools = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .clone();
    let mut advertising: Vec<&str> = tools
        .iter()
        .filter(|tool| tool.get("outputSchema").is_some())
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    advertising.sort_unstable();
    let mut expected = OUTPUT_SCHEMA_TOOLS;
    expected.sort_unstable();
    assert_eq!(advertising, expected, "{listed}");
    for tool_name in OUTPUT_SCHEMA_TOOLS {
        // Asserts the 2020-12 dialect declaration.
        advertised_output_schema(&tools, tool_name);
    }
    // A tool outside the slice must stay silent rather than advertise a shape
    // nobody has reviewed as a contract.
    assert!(
        tools
            .iter()
            .find(|tool| tool["name"] == "get_file_contents")
            .expect("get_file_contents descriptor")
            .get("outputSchema")
            .is_none(),
        "{listed}"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());

    // `outputSchema` entered the MCP spec at 2025-06-18. A 2025-03-26 client
    // has no schema for the field, so the server has to strip it.
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session_speaking(&mut stdin, &mut reader, &mut stderr, "2025-03-26");

    let listed = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
    );
    let legacy_advertising: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter(|tool| tool.get("outputSchema").is_some())
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert!(legacy_advertising.is_empty(), "{listed}");

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

#[test]
fn output_schema_describes_real_workspace_and_policy_results() {
    let workspace = InlineTestProject::new()
        .file("Described.java", "class Described {}\n")
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let listed = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
    );
    let tools = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .clone();

    let workspace_result = call_tool(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        "get_active_workspace",
        json!({}),
    );
    assert_same_canonical_path(
        workspace_result["result"]["structuredContent"]["workspace_path"]
            .as_str()
            .expect("workspace_path"),
        workspace.root(),
    );
    assert_structured_content_matches_advertised_schema(
        &tools,
        "get_active_workspace",
        &workspace_result,
    );

    let policies = call_tool(
        &mut stdin,
        &mut reader,
        &mut stderr,
        3,
        "list_policies",
        json!({}),
    );
    // Without this the schema check would pass on an empty manifest, proving
    // nothing about the entry shape.
    assert!(
        policies["result"]["structuredContent"]["policies"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "{policies}"
    );
    assert_structured_content_matches_advertised_schema(&tools, "list_policies", &policies);

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// `search_symbols` answers in four shapes and every one of them has to satisfy
/// the single advertised schema: a ranked hit, a bounded answer, an empty
/// answer, and the overload reply that reports counts instead of results.
///
/// The overload needs more deduplicated candidates than
/// `SEARCH_SYMBOLS_MAX_RANKED_CANDIDATES` (10_000), which is why this workspace
/// carries a generated file with that many declarations; the other three shapes
/// share the server so the corpus is indexed once.
#[test]
fn output_schema_describes_search_symbols_hits_bounds_and_overload() {
    let generated_declarations: String = (0..10_000)
        .map(|index| format!("def widget{index}(): pass\n"))
        .collect();
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("widgets.py", generated_declarations)
        .file("alpha.py", "def shared_handler(): pass\n")
        .file("beta.py", "def shared_handler_two(): pass\n")
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let listed = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
    );
    let tools = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .clone();

    let hits = call_tool(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        "search_symbols",
        json!({ "patterns": ["shared_handler"] }),
    );
    let hit_content = &hits["result"]["structuredContent"];
    assert_eq!(hit_content["truncated"], false, "{hits}");
    assert!(
        hit_content["files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()),
        "{hits}"
    );
    assert_structured_content_matches_advertised_schema(&tools, "search_symbols", &hits);

    let bounded = call_tool(
        &mut stdin,
        &mut reader,
        &mut stderr,
        3,
        "search_symbols",
        json!({ "patterns": ["shared_handler"], "limit": 1 }),
    );
    let bounded_content = &bounded["result"]["structuredContent"];
    assert_eq!(bounded_content["truncated"], true, "{bounded}");
    assert_eq!(bounded_content["files"].as_array().map(Vec::len), Some(1));
    assert_structured_content_matches_advertised_schema(&tools, "search_symbols", &bounded);

    let overloaded = call_tool(
        &mut stdin,
        &mut reader,
        &mut stderr,
        4,
        "search_symbols",
        json!({ "patterns": ["widget"] }),
    );
    let overloaded_content = &overloaded["result"]["structuredContent"];
    assert!(
        overloaded_content["too_many_matches"]["total_candidates"]
            .as_u64()
            .is_some_and(|total| total > 10_000),
        "{overloaded}"
    );
    // Ranking was skipped, not truncated, so the overload reply carries counts
    // and no file at all.
    assert_eq!(overloaded_content["total_files"], 0, "{overloaded}");
    assert_structured_content_matches_advertised_schema(&tools, "search_symbols", &overloaded);

    let empty = call_tool(
        &mut stdin,
        &mut reader,
        &mut stderr,
        5,
        "search_symbols",
        json!({ "patterns": ["ZzzNoSuchDeclarationAnywhere"] }),
    );
    let empty_content = &empty["result"]["structuredContent"];
    assert_eq!(empty_content["files"].as_array().map(Vec::len), Some(0));
    assert_eq!(empty_content["truncated"], false, "{empty}");
    assert!(empty_content.get("too_many_matches").is_none(), "{empty}");
    assert_structured_content_matches_advertised_schema(&tools, "search_symbols", &empty);

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

#[test]
fn rootless_mcp_binds_through_mrtr_roots_on_2026_07_28() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    fs::write(
        plugin_dir.path().join("PluginOnly.java"),
        "class PluginOnly {}\n",
    )
    .expect("write plugin fixture");
    let workspace = InlineTestProject::new()
        .file("MrtrWorkspace.java", "class MrtrWorkspace {}\n")
        .build();

    let mut child = spawn_rootless_server(plugin_dir.path(), "workspace|symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": { "name": "modern", "version": "1" }
            }
        }),
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    // 2026-07-28 removed the post-handshake roots lifecycle, so an unbound
    // server answers the tool call with an embedded roots request instead of a
    // result, and the client retries the same call once it can answer.
    let search = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "search_symbols", "arguments": { "patterns": ["MrtrWorkspace"] } }
    });
    let input_required = round_trip(&mut stdin, &mut reader, &mut stderr, search.clone());
    assert_eq!(
        input_required["result"]["resultType"], "input_required",
        "{input_required}"
    );
    assert_eq!(
        input_required["result"]["inputRequests"]["roots"]["method"], "roots/list",
        "{input_required}"
    );
    let request_state = input_required["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("an activation must carry a requestState: {input_required}"));

    // requestState is echoed by the client and so is fully client-controlled.
    // It authorizes nothing; a value the server never issued must not activate
    // a workspace, however well-formed the roots beside it are.
    let workspace_uri = url::Url::from_directory_path(workspace.root())
        .expect("workspace file URI")
        .to_string();
    let mut tampered = search.clone();
    tampered["id"] = json!(3);
    tampered["params"]["requestState"] = json!("bifrost-roots-0-0");
    tampered["params"]["inputResponses"] =
        json!({ "roots": { "roots": [{ "uri": workspace_uri }] } });
    let refused = round_trip(&mut stdin, &mut reader, &mut stderr, tampered);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "an unsolicited requestState must not bind a workspace: {refused}"
    );

    let mut retry = search;
    retry["id"] = json!(4);
    retry["params"]["requestState"] = json!(request_state);
    retry["params"]["inputResponses"] = json!({ "roots": { "roots": [{ "uri": workspace_uri }] } });
    let bound = round_trip(&mut stdin, &mut reader, &mut stderr, retry);
    assert_eq!(bound["result"]["isError"], false, "{bound}");
    assert!(bound.to_string().contains("MrtrWorkspace"), "{bound}");
    assert!(!bound.to_string().contains("PluginOnly"), "{bound}");
    assert!(
        !plugin_dir
            .path()
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "MRTR activation must not analyze the process working directory"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// The per-request negotiation keys a stateless `2026-07-28` request carries
/// in its `_meta` in place of a connection-level `initialize`.
fn stateless_2026_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn stateless_search_symbols_call(id: i64, pattern: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "search_symbols",
            "arguments": { "patterns": [pattern] },
            "_meta": stateless_2026_meta()
        }
    })
}

/// Issue #2007: the `2026-07-28` lifecycle is stateless. A rootless client
/// that never sends `initialize` discovers the server, is asked for its roots
/// through MRTR on its first workspace tool call, and executes the retried
/// call -- every request negotiated independently through its own `_meta`.
#[test]
fn rootless_mcp_executes_stateless_2026_07_28_calls_without_initialize() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    fs::write(
        plugin_dir.path().join("PluginOnly.java"),
        "class PluginOnly {}\n",
    )
    .expect("write plugin fixture");
    let workspace = InlineTestProject::new()
        .file("StatelessWorkspace.java", "class StatelessWorkspace {}\n")
        .build();

    let mut child = spawn_rootless_server(plugin_dir.path(), "workspace|symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    // Discovery opens the session; there is no initialize and no
    // notifications/initialized anywhere in this exchange.
    let discover = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": { "_meta": stateless_2026_meta() }
        }),
    );
    assert!(
        discover["result"]["supportedVersions"]
            .as_array()
            .is_some_and(|versions| versions.iter().any(|version| version == "2026-07-28")),
        "{discover}"
    );

    let search = stateless_search_symbols_call(2, "StatelessWorkspace");
    let input_required = round_trip(&mut stdin, &mut reader, &mut stderr, search.clone());
    assert_eq!(
        input_required["result"]["resultType"], "input_required",
        "an unbound stateless call must be answered with an MRTR roots activation: {input_required}"
    );
    assert_eq!(
        input_required["result"]["inputRequests"]["roots"]["method"], "roots/list",
        "{input_required}"
    );
    let request_state = input_required["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("an activation must carry a requestState: {input_required}"));

    let workspace_uri = url::Url::from_directory_path(workspace.root())
        .expect("workspace file URI")
        .to_string();
    let mut retry = stateless_search_symbols_call(3, "StatelessWorkspace");
    retry["params"]["requestState"] = json!(request_state);
    retry["params"]["inputResponses"] = json!({ "roots": { "roots": [{ "uri": workspace_uri }] } });
    let bound = round_trip(&mut stdin, &mut reader, &mut stderr, retry);
    assert_eq!(
        bound["result"]["resultType"], "complete",
        "the retry must bind the validated root and execute: {bound}"
    );
    assert_eq!(bound["result"]["isError"], false, "{bound}");
    assert!(bound.to_string().contains("StatelessWorkspace"), "{bound}");
    assert!(!bound.to_string().contains("PluginOnly"), "{bound}");

    // A later call on the bound workspace needs no further activation, and
    // still carries its own negotiation keys like every stateless request.
    let followup = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        stateless_search_symbols_call(4, "StatelessWorkspace"),
    );
    assert_eq!(followup["result"]["resultType"], "complete", "{followup}");
    assert_eq!(followup["result"]["isError"], false, "{followup}");

    assert!(
        !plugin_dir
            .path()
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "stateless activation must not analyze the process working directory"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Issue #2007 negative coverage: every stateless request is validated on its
/// own, and nothing short of a Bifrost-issued activation binds a workspace.
#[test]
fn stateless_2026_07_28_requests_are_independently_validated() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    let workspace = InlineTestProject::new()
        .file("Validated.java", "class Validated {}\n")
        .build();
    let workspace_uri = url::Url::from_directory_path(workspace.root())
        .expect("workspace file URI")
        .to_string();

    let mut child = spawn_rootless_server(plugin_dir.path(), "workspace|symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": { "_meta": stateless_2026_meta() }
        }),
    );

    // Required request metadata is per request: declaring the version without
    // the capabilities key is refused at dispatch, before any tool runs.
    let mut missing_capabilities = stateless_search_symbols_call(2, "Validated");
    missing_capabilities["params"]["_meta"] =
        json!({ "io.modelcontextprotocol/protocolVersion": "2026-07-28" });
    let refused = round_trip(&mut stdin, &mut reader, &mut stderr, missing_capabilities);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("required fields")),
        "a stateless request missing required metadata must be refused: {refused}"
    );

    // So is omitting `_meta` entirely on a session that opened statelessly.
    let mut no_meta = stateless_search_symbols_call(3, "Validated");
    no_meta["params"]
        .as_object_mut()
        .expect("params object")
        .remove("_meta");
    let refused = round_trip(&mut stdin, &mut reader, &mut stderr, no_meta);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("required fields")),
        "a stateless request without _meta must be refused: {refused}"
    );

    // An unknown protocol version is refused per request as well.
    let mut unknown_version = stateless_search_symbols_call(4, "Validated");
    unknown_version["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
        json!("2099-01-01");
    let refused = round_trip(&mut stdin, &mut reader, &mut stderr, unknown_version);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Unsupported protocol version")),
        "an unknown protocol version must be refused: {refused}"
    );

    // A requestState Bifrost never issued must not bind, however well-formed
    // the roots beside it are.
    let mut tampered = stateless_search_symbols_call(5, "Validated");
    tampered["params"]["requestState"] = json!("bifrost-roots-0-0");
    tampered["params"]["inputResponses"] =
        json!({ "roots": { "roots": [{ "uri": workspace_uri }] } });
    let refused = round_trip(&mut stdin, &mut reader, &mut stderr, tampered);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "an unsolicited requestState must not bind a workspace: {refused}"
    );

    // A genuine activation answered with unusable roots binds nothing, and
    // only one round is offered: the retry gets the plain unbound error.
    let activation = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        stateless_search_symbols_call(6, "Validated"),
    );
    assert_eq!(
        activation["result"]["resultType"], "input_required",
        "{activation}"
    );
    let request_state = activation["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("an activation must carry a requestState: {activation}"));
    let missing_dir_uri = url::Url::from_directory_path(workspace.root().join("no-such-dir"))
        .expect("missing dir URI")
        .to_string();
    let mut unusable = stateless_search_symbols_call(7, "Validated");
    unusable["params"]["requestState"] = json!(request_state);
    unusable["params"]["inputResponses"] = json!({ "roots": { "roots": [
        { "uri": "https://example.com/not-a-file-root" },
        { "uri": missing_dir_uri }
    ] } });
    let refused = round_trip(&mut stdin, &mut reader, &mut stderr, unusable);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "unusable roots must leave the server unbound: {refused}"
    );

    // The spent requestState is single use: replaying it with usable roots is
    // no longer an activation.
    let mut replay = stateless_search_symbols_call(8, "Validated");
    replay["params"]["requestState"] = json!(request_state);
    replay["params"]["inputResponses"] =
        json!({ "roots": { "roots": [{ "uri": workspace_uri }] } });
    let refused = round_trip(&mut stdin, &mut reader, &mut stderr, replay);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "a replayed requestState must not bind a workspace: {refused}"
    );

    assert!(
        !workspace
            .root()
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "no refused request may have analyzed the workspace"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Read messages until the response for `id` arrives, collecting the
/// `notifications/progress` params seen on the way. Any other interleaved
/// message fails the test: nothing but progress may precede the response.
fn read_response_collecting_progress(
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: i64,
) -> (Value, Vec<Value>) {
    let mut progress = Vec::new();
    loop {
        let message = read_line(reader, stderr);
        if message["id"] == json!(id) {
            return (message, progress);
        }
        assert_eq!(
            message["method"], "notifications/progress",
            "unexpected message while waiting for response {id}: {message}"
        );
        progress.push(message["params"].clone());
    }
}

fn assert_progress_is_monotonic(notifications: &[Value]) {
    let mut last = f64::NEG_INFINITY;
    for notification in notifications {
        let value = notification["progress"]
            .as_f64()
            .unwrap_or_else(|| panic!("progress must be a number: {notification}"));
        assert!(
            value > last,
            "progress must increase on every notification: {notifications:?}"
        );
        assert!(
            notification["total"].is_null(),
            "no phase has a known total; inventing one is forbidden: {notification}"
        );
        last = value;
    }
}

/// Issue #2005: a caller that supplies `progressToken` observes truthful
/// phase progress -- readiness, admission, execution -- on its own request,
/// with the token echoed exactly; a caller that omits the token gets nothing.
#[test]
fn progress_token_yields_phase_progress_and_silence_without_it() {
    let workspace = InlineTestProject::new()
        .file("Progressive.java", "class Progressive {}\n")
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    // A string token, echoed as a string.
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["Progressive"] },
                "_meta": { "progressToken": "progress-abc" }
            }
        }),
    );
    let (response, progress) = read_response_collecting_progress(&mut reader, &mut stderr, 2);
    assert_eq!(response["result"]["isError"], false, "{response}");
    let messages = progress
        .iter()
        .map(|notification| {
            assert_eq!(
                notification["progressToken"], "progress-abc",
                "the token must be preserved exactly: {notification}"
            );
            notification["message"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        vec![
            "waiting for workspace readiness",
            "waiting for analyzer admission",
            "executing search_symbols"
        ],
        "{progress:?}"
    );
    assert_progress_is_monotonic(&progress);

    // An integer token, echoed as a number, not a string.
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["Progressive"] },
                "_meta": { "progressToken": 7 }
            }
        }),
    );
    let (response, progress) = read_response_collecting_progress(&mut reader, &mut stderr, 3);
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(!progress.is_empty(), "{response}");
    for notification in &progress {
        assert_eq!(
            notification["progressToken"],
            json!(7),
            "an integer token must stay a number: {notification}"
        );
    }

    // No token, no notifications: the response is the very next message.
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["Progressive"] }
            }
        }),
    );
    let (response, progress) = read_response_collecting_progress(&mut reader, &mut stderr, 4);
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(
        progress.is_empty(),
        "a caller that did not opt in must receive no progress: {progress:?}"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Issue #2005: concurrent calls with distinct tokens must never cross-route.
/// Every notification carries the token of exactly the call whose phases it
/// reports, and each token's progress is independently monotonic.
#[test]
fn concurrent_progress_tokens_never_cross_route() {
    let workspace = InlineTestProject::new()
        .file(
            "Concurrent.java",
            "public class Concurrent { public void run() {} }\n",
        )
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    // Both calls are on the wire before either response, so their phase
    // notifications can interleave freely; routing is what must not.
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "scan_usages_by_location",
                "arguments": { "targets": [{ "path": "Concurrent.java", "line": 1, "symbol": "Concurrent" }] },
                "_meta": { "progressToken": "scan-token" }
            }
        }),
    );
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["Concurrent"] },
                "_meta": { "progressToken": "search-token" }
            }
        }),
    );

    let mut responses = HashMap::new();
    let mut progress_by_token: HashMap<String, Vec<Value>> = HashMap::new();
    while responses.len() < 2 {
        let message = read_line(&mut reader, &mut stderr);
        if let Some(id) = message["id"].as_i64() {
            responses.insert(id, message);
            continue;
        }
        assert_eq!(message["method"], "notifications/progress", "{message}");
        let token = message["params"]["progressToken"]
            .as_str()
            .unwrap_or_else(|| panic!("string token expected: {message}"))
            .to_string();
        progress_by_token
            .entry(token)
            .or_default()
            .push(message["params"].clone());
    }
    assert_eq!(responses[&10]["result"]["isError"], false, "{responses:?}");
    assert_eq!(responses[&11]["result"]["isError"], false, "{responses:?}");

    let scan = &progress_by_token["scan-token"];
    let search = &progress_by_token["search-token"];
    assert_eq!(progress_by_token.len(), 2, "{progress_by_token:?}");
    assert_progress_is_monotonic(scan);
    assert_progress_is_monotonic(search);
    assert!(
        scan.iter()
            .any(|n| n["message"] == "executing scan_usages_by_location"),
        "{scan:?}"
    );
    assert!(
        search
            .iter()
            .any(|n| n["message"] == "executing search_symbols"),
        "{search:?}"
    );
    assert!(
        !scan
            .iter()
            .any(|n| n["message"] == "executing search_symbols"),
        "phases of one call must not report under another call's token: {scan:?}"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Issue #2005: cancelling a call that opted into progress leaves the session
/// healthy. The cancelled call's progress stops with the call, and the next
/// call is served normally.
#[test]
fn cancellation_with_progress_in_flight_leaves_the_session_healthy() {
    let workspace = InlineTestProject::new()
        .file("Cancellable.java", "class Cancellable {}\n")
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    // Cancel immediately after sending, so the cancellation lands during
    // readiness, admission, or execution -- whichever phase the call is in.
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "scan_usages_by_location",
                "arguments": { "targets": [{ "path": "Cancellable.java", "line": 1, "symbol": "Cancellable" }] },
                "_meta": { "progressToken": "doomed" }
            }
        }),
    );
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": { "requestId": 20, "reason": "test cancels" }
        }),
    );
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["Cancellable"] }
            }
        }),
    );

    // The cancelled call may or may not still answer, depending on how far it
    // got; the follow-up must answer either way, and the only other traffic
    // permitted on the wire is the doomed call's own progress.
    loop {
        let message = read_line(&mut reader, &mut stderr);
        if message["id"] == json!(21) {
            assert_eq!(message["result"]["isError"], false, "{message}");
            break;
        }
        if message["id"] == json!(20) {
            continue;
        }
        assert_eq!(message["method"], "notifications/progress", "{message}");
        assert_eq!(message["params"]["progressToken"], "doomed", "{message}");
    }

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Open a session declaring the MCP Tasks extension (SEP-2663).
fn initialize_tasks_session(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    protocol_version: &str,
) -> Value {
    let initialize = round_trip(
        stdin,
        reader,
        stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": { "extensions": { "io.modelcontextprotocol/tasks": {} } },
                "clientInfo": { "name": "tasks-client", "version": "1" }
            }
        }),
    );
    write_line(
        stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    initialize
}

fn run_policy_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "run_policy",
            "arguments": {
                "policy_files": ["policies/dynamic-eval.rqlp"],
                "evaluation_date": "2026-07-27",
                "fail_on": "warning"
            }
        }
    })
}

fn malformed_run_policy_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "run_policy",
            "arguments": {
                "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                "evaluation_date": "2026-07-27",
                "fail_on": "warning"
            }
        }
    })
}

fn assert_compact_malformed_run_policy_reply(response: &Value, task_capable: bool) {
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    if task_capable {
        assert_ne!(response["result"]["resultType"], "task", "{response}");
    }
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["status"], "unreliable", "{response}");
    assert_eq!(structured["exit_status"], 2, "{response}");
    assert!(
        structured["request_correlation_id"]
            .as_str()
            .is_some_and(|correlation| correlation.starts_with("sha256:")),
        "early run_policy replies retain correlation: {response}"
    );
    let report = &structured["report"];
    assert_eq!(report["schema_version"], 5, "{response}");
    assert_eq!(report["rules"], json!([]), "{response}");
    assert_eq!(report["runs"], json!([]), "{response}");
    assert_eq!(report["diagnostics"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["diagnostics"][0]["code"], "suppression-load-failed");
    assert_eq!(
        report["execution"]["completed_policy_ids"],
        json!([]),
        "{response}"
    );
    assert_eq!(
        report["execution"]["pending_policy_ids"],
        json!([]),
        "{response}"
    );
    let stages = report["execution"]["stage_timings"]
        .as_array()
        .expect("stage timings");
    assert!(
        stages
            .iter()
            .any(|timing| timing["stage"] == "policy_selection")
    );
    assert!(
        stages
            .iter()
            .any(|timing| timing["stage"] == "suppression_preflight")
    );
    assert!(
        stages
            .iter()
            .any(|timing| timing["stage"] == "report_construction")
    );
    assert!(
        stages
            .iter()
            .all(|timing| timing["stage"] != "workspace_snapshot")
    );
    assert!(
        stages
            .iter()
            .all(|timing| timing["stage"] != "policy_evaluation")
    );
    assert!(
        serde_json::to_vec(structured)
            .expect("serialize compact report")
            .len()
            < 24_000,
        "malformed suppression report grew unexpectedly: {structured}"
    );
}

/// Poll `tasks/get` until the task reaches a terminal status, returning the
/// terminal response. Polls faster than the advertised interval because this
/// is a test, not a considerate client.
fn poll_task_until_terminal(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    task_id: &str,
    first_id: i64,
) -> Value {
    let give_up_at = std::time::Instant::now() + Duration::from_secs(60);
    let mut id = first_id;
    loop {
        let response = round_trip(
            stdin,
            reader,
            stderr,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tasks/get",
                "params": { "taskId": task_id }
            }),
        );
        let status = response["result"]["status"]
            .as_str()
            .unwrap_or_else(|| panic!("tasks/get must report a status: {response}"));
        if matches!(status, "completed" | "failed" | "cancelled") {
            return response;
        }
        assert!(
            std::time::Instant::now() < give_up_at,
            "task never settled: {response}"
        );
        id += 1;
        thread::sleep(Duration::from_millis(50));
    }
}

/// A workspace whose cold snapshot build and policy run are slow enough to
/// observe a task in flight: enough files that readiness alone takes long
/// past any cancellation or tiny-TTL window a test needs to hit.
fn slow_policy_project() -> common::BuiltInlineTestProject {
    let mut project = InlineTestProject::with_language(Language::Python)
        .file("policies/dynamic-eval.rqlp", MCP_DYNAMIC_EVAL_POLICY);
    for index in 0..300 {
        project = project.file(
            format!("src/module_{index}.py"),
            format!("def handler_{index}(value):\n    return eval(value)\n"),
        );
    }
    project.build()
}

/// Issue #2006: a capable `2026-07-28` client calling `run_policy` receives a
/// durable task handle and collects the finished report by polling, after the
/// initiating request has ended. The terminal result preserves the synchronous
/// content/structured-content contract, pinned by comparing the embedded
/// report against a direct in-process policy evaluation.
#[test]
fn mcp_tasks_run_policy_completes_through_a_task_handle() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", MCP_POLICY_APP)
        .file("policies/dynamic-eval.rqlp", MCP_DYNAMIC_EVAL_POLICY)
        .build();
    let expected = evaluate_policy_files(
        workspace.root(),
        &[PathBuf::from("policies/dynamic-eval.rqlp")],
        &PolicyEvaluationOptions::new("2026-07-27".parse().expect("fixed evaluation date"))
            .with_fail_on(PolicyFailOn::Warning),
    )
    .expect("direct policy evaluation");
    let expected_report = serde_json::to_value(expected.report()).expect("serialize report");

    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    let initialize = initialize_tasks_session(&mut stdin, &mut reader, &mut stderr, "2026-07-28");
    assert!(
        initialize["result"]["capabilities"]["extensions"]
            .get("io.modelcontextprotocol/tasks")
            .is_some(),
        "the server must advertise the tasks extension: {initialize}"
    );

    let created = round_trip(&mut stdin, &mut reader, &mut stderr, run_policy_request(1));
    assert_eq!(created["result"]["resultType"], "task", "{created}");
    assert_eq!(created["result"]["status"], "working", "{created}");
    assert!(created["result"]["ttlMs"].is_number(), "{created}");
    let task_id = created["result"]["taskId"]
        .as_str()
        .unwrap_or_else(|| panic!("a task handle must carry a taskId: {created}"))
        .to_string();

    let terminal = poll_task_until_terminal(&mut stdin, &mut reader, &mut stderr, &task_id, 10);
    assert_eq!(terminal["result"]["status"], "completed", "{terminal}");
    let result = &terminal["result"]["result"];
    assert_eq!(result["isError"], false, "{terminal}");
    assert!(
        result["content"][0]["text"].is_string(),
        "the terminal result must keep the synchronous content contract: {terminal}"
    );
    let structured = &result["structuredContent"];
    assert_eq!(structured["status"], "finding", "{terminal}");
    assert_eq!(structured["exit_status"], 1, "{terminal}");
    assert_eq!(structured["report"], expected_report, "{terminal}");
    assert!(
        structured["request_correlation_id"]
            .as_str()
            .is_some_and(|correlation| correlation.starts_with("sha256:")),
        "task results keep the run_policy correlation contract: {terminal}"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Issue #2006: clients without the extension must never receive a
/// task-shaped result -- neither a `2026-07-28` client that did not declare
/// it, nor a legacy `2025-11-25` client that did (tasks require the new
/// revision's result discriminators).
#[test]
fn mcp_tasks_never_reach_incapable_or_legacy_clients() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", MCP_POLICY_APP)
        .file("policies/dynamic-eval.rqlp", MCP_DYNAMIC_EVAL_POLICY)
        .build();

    // A 2026-07-28 client without the capability keeps synchronous behavior,
    // and its tasks/get is refused before reaching Bifrost's handler.
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": { "name": "no-tasks", "version": "1" }
            }
        }),
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    let synchronous = round_trip(&mut stdin, &mut reader, &mut stderr, run_policy_request(1));
    assert_eq!(
        synchronous["result"]["resultType"], "complete",
        "{synchronous}"
    );
    assert_eq!(
        synchronous["result"]["structuredContent"]["status"], "finding",
        "{synchronous}"
    );
    let refused = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/get",
            "params": { "taskId": "irrelevant" }
        }),
    );
    assert!(
        !refused["error"].is_null(),
        "tasks/get without the capability must be refused: {refused}"
    );
    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());

    // A 2025-11-25 client declaring the capability still gets synchronous
    // results: the task result shape does not exist in its revision.
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_tasks_session(&mut stdin, &mut reader, &mut stderr, "2025-11-25");
    let synchronous = round_trip(&mut stdin, &mut reader, &mut stderr, run_policy_request(1));
    assert!(
        synchronous["result"]["resultType"].is_null(),
        "a legacy session has no result discriminators at all: {synchronous}"
    );
    assert_eq!(
        synchronous["result"]["structuredContent"]["status"], "finding",
        "{synchronous}"
    );
    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Issue #2006: `tasks/cancel` requests cooperative cancellation and the task
/// settles as terminal `cancelled`, stopping the underlying analyzer work.
#[test]
fn mcp_tasks_cancel_settles_cancelled() {
    let workspace = slow_policy_project();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_tasks_session(&mut stdin, &mut reader, &mut stderr, "2026-07-28");

    let created = round_trip(&mut stdin, &mut reader, &mut stderr, run_policy_request(1));
    assert_eq!(created["result"]["resultType"], "task", "{created}");
    let task_id = created["result"]["taskId"]
        .as_str()
        .expect("taskId")
        .to_string();

    // Cancel immediately: the task is still waiting for the cold snapshot
    // build, so cancellation lands during readiness or admission.
    let ack = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/cancel",
            "params": { "taskId": task_id }
        }),
    );
    assert!(ack["error"].is_null(), "{ack}");

    let terminal = poll_task_until_terminal(&mut stdin, &mut reader, &mut stderr, &task_id, 10);
    assert_eq!(terminal["result"]["status"], "cancelled", "{terminal}");

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Issue #2006: an expired task is observed as terminal `failed`; the TTL is
/// also the execution deadline, so the analyzer work stops rather than
/// running on behind a dead handle.
#[test]
fn mcp_tasks_expire_to_failed() {
    let workspace = slow_policy_project();
    let mut child = mcp_server_command(workspace.root(), "searchtools", &[])
        .env("BIFROST_MCP_TASK_TTL_MS", "300")
        .spawn()
        .expect("spawn bifrost");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_tasks_session(&mut stdin, &mut reader, &mut stderr, "2026-07-28");

    let created = round_trip(&mut stdin, &mut reader, &mut stderr, run_policy_request(1));
    assert_eq!(created["result"]["resultType"], "task", "{created}");
    assert_eq!(created["result"]["ttlMs"], 300, "{created}");
    let task_id = created["result"]["taskId"]
        .as_str()
        .expect("taskId")
        .to_string();

    // The 300-file cold build cannot finish in 300 ms; the task must be
    // observed as failed, not left working forever.
    let terminal = poll_task_until_terminal(&mut stdin, &mut reader, &mut stderr, &task_id, 10);
    assert_eq!(terminal["result"]["status"], "failed", "{terminal}");

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Issue #2006: unknown task ids fail safely.
#[test]
fn mcp_tasks_unknown_ids_fail_safely() {
    let workspace = InlineTestProject::new()
        .file("Anything.java", "class Anything {}\n")
        .build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_tasks_session(&mut stdin, &mut reader, &mut stderr, "2026-07-28");

    for (id, method) in [(1, "tasks/get"), (2, "tasks/update"), (3, "tasks/cancel")] {
        let mut params = json!({ "taskId": "no-such-task" });
        if method == "tasks/update" {
            params["inputResponses"] = json!({});
        }
        let refused = round_trip(
            &mut stdin,
            &mut reader,
            &mut stderr,
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        );
        assert!(
            !refused["error"].is_null(),
            "{method} with an unknown id must fail safely: {refused}"
        );
    }

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

/// Issue #2006: a task handle is bound to the workspace authorization it was
/// created under. After the client revokes its roots, polling the old handle
/// is refused -- the handle must never carry results across a workspace
/// boundary, even though the task itself completed before the revocation.
#[test]
fn mcp_tasks_handles_die_with_workspace_rebinding() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", MCP_POLICY_APP)
        .file("policies/dynamic-eval.rqlp", MCP_DYNAMIC_EVAL_POLICY)
        .build();
    let workspace_uri = url::Url::from_directory_path(workspace.root())
        .expect("workspace file URI")
        .to_string();

    let mut child = spawn_rootless_server(plugin_dir.path(), "workspace|symbol|extended");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_tasks_session(&mut stdin, &mut reader, &mut stderr, "2026-07-28");

    // Rootless 2026-07-28 binding goes through MRTR: the first call is
    // answered with a roots activation, and the retry that carries the roots
    // is the call that becomes the task.
    let activation = round_trip(&mut stdin, &mut reader, &mut stderr, run_policy_request(1));
    assert_eq!(
        activation["result"]["resultType"], "input_required",
        "{activation}"
    );
    let request_state = activation["result"]["requestState"]
        .as_str()
        .expect("requestState")
        .to_string();
    let mut retry = run_policy_request(2);
    retry["params"]["requestState"] = json!(request_state);
    retry["params"]["inputResponses"] = json!({ "roots": { "roots": [{ "uri": workspace_uri }] } });
    let created = round_trip(&mut stdin, &mut reader, &mut stderr, retry);
    assert_eq!(
        created["result"]["resultType"], "task",
        "an MRTR retry from a capable client must still task-ify: {created}"
    );
    let task_id = created["result"]["taskId"]
        .as_str()
        .expect("taskId")
        .to_string();
    let terminal = poll_task_until_terminal(&mut stdin, &mut reader, &mut stderr, &task_id, 10);
    assert_eq!(terminal["result"]["status"], "completed", "{terminal}");

    // The client withdraws its roots. The next tool call proves the
    // revocation landed (the server is unbound again and starts a fresh MRTR
    // round), and the old handle must now be dead.
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }),
    );
    let reactivation = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": { "name": "search_symbols", "arguments": { "patterns": ["handler"] } }
        }),
    );
    assert_eq!(
        reactivation["result"]["resultType"], "input_required",
        "the roots change must unbind the workspace: {reactivation}"
    );

    let refused = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tasks/get",
            "params": { "taskId": task_id }
        }),
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("workspace authorization was revoked")),
        "a rebound workspace must kill outstanding handles: {refused}"
    );

    drop(stdin);
    assert!(child.wait().expect("wait bifrost").success());
}

fn assert_codex_metadata_cannot_bind_before_initialize(
    cwd: &std::path::Path,
    sandbox_root: &std::path::Path,
) {
    // Shape 1: a bare pre-initialize call. The MCP lifecycle permits only
    // `ping` before `initialize`, so the server refuses the whole session.
    let mut child = spawn_rootless_server(cwd, "workspace|symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    write_line(
        &mut stdin,
        codex_search_symbols_call(0, sandbox_root, "codex-test-thread", "CodexWorkspace"),
    );
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .expect("read pre-initialize response");
    assert!(
        response.is_empty(),
        "a tools/call before initialize must not be served: {response}"
    );
    drop(stdin);
    let mut diagnostics = String::new();
    stderr
        .read_to_string(&mut diagnostics)
        .expect("read server diagnostics");
    assert!(
        diagnostics.contains("expect initialized request"),
        "the server must refuse the session, not the individual call: {diagnostics}"
    );
    child.wait().expect("wait bifrost");

    // Shape 2, and the one that actually got through: MCP 2026-07-28 has a
    // stateless lifecycle, so a request whose `_meta` carries the required
    // negotiation keys is dispatched to the handler with no `initialize` at
    // all. Bifrost must still refuse to read a directory on the strength of
    // sandbox metadata alone -- the handshake is what decides whether this
    // connection may name its own workspace. Supplying a junk `requestState`
    // is part of the shape: it steers the call past the MRTR activation branch
    // and straight at the Codex binding path.
    let mut child = spawn_rootless_server(cwd, "workspace|symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    let mut stateless_call =
        codex_search_symbols_call(0, sandbox_root, "codex-test-thread", "CodexWorkspace");
    stateless_call["params"]["requestState"] = json!("unsolicited");
    stateless_call["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
        json!("2026-07-28");
    stateless_call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
    let refused = round_trip(&mut stdin, &mut reader, &mut stderr, stateless_call);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "the stateless 2026-07-28 lifecycle must not let Codex metadata bind a workspace \
         without a handshake: {refused}"
    );
    assert!(
        !refused.to_string().contains("CodexWorkspace"),
        "no analyzer result may be returned for an unauthorized workspace: {refused}"
    );
    assert!(
        !sandbox_root
            .join(".bifrost/cache")
            .join(brokk_bifrost_analysis::cache_db::cache_db_file_name())
            .exists(),
        "Codex metadata must not grant workspace authority before capability negotiation"
    );
    drop(stdin);
    child.wait().expect("wait bifrost");
}

fn codex_search_symbols_call(
    id: i64,
    root: &std::path::Path,
    thread_id: &str,
    pattern: &str,
) -> Value {
    let sandbox_cwd = url::Url::from_directory_path(root)
        .expect("sandbox cwd file URI")
        .to_string();
    let mut request = codex_handshake_message("toolCall");
    request["id"] = json!(id);
    assert_eq!(
        replace_fixture_placeholder(&mut request, "__BIFROST_SANDBOX_CWD__", &sandbox_cwd,),
        2,
        "recorded Codex tool call must contain sandboxCwd and writableRoots placeholders"
    );
    assert_eq!(
        replace_fixture_placeholder(&mut request, "__BIFROST_THREAD_ID__", thread_id),
        1,
        "recorded Codex tool call must contain one thread id placeholder"
    );
    assert_eq!(
        replace_fixture_placeholder(&mut request, "__BIFROST_SYMBOL_PATTERN__", pattern),
        1,
        "recorded Codex tool call must contain one search pattern placeholder"
    );
    request
}

fn replace_fixture_placeholder(value: &mut Value, placeholder: &str, replacement: &str) -> usize {
    match value {
        Value::String(text) if text == placeholder => {
            *text = replacement.to_owned();
            1
        }
        Value::Array(values) => values
            .iter_mut()
            .map(|value| replace_fixture_placeholder(value, placeholder, replacement))
            .sum(),
        Value::Object(fields) => fields
            .values_mut()
            .map(|value| replace_fixture_placeholder(value, placeholder, replacement))
            .sum(),
        _ => 0,
    }
}

fn codex_sandbox_metadata(root: &std::path::Path, thread_id: &str) -> Value {
    codex_search_symbols_call(0, root, thread_id, "unused")["params"]["_meta"].clone()
}

fn spawn_server(root: &std::path::Path, mode: &str, extra_args: &[&str]) -> std::process::Child {
    mcp_server_command(root, mode, extra_args)
        .spawn()
        .expect("spawn bifrost")
}

const PROFILED_STDERR_TAIL_BYTES: usize = 64 * 1024;
const PROFILED_PHASES: [&str; 4] = [
    "queue_wait",
    "execution",
    "response_queue_wait",
    "writer_delivery",
];
const PROFILED_PHASE_MARKERS: [&[u8]; 4] = [
    b"mcp_request.queue_wait[search_symbols]",
    b"mcp_request.execution[search_symbols]",
    b"mcp_request.response_queue_wait[search_symbols]",
    b"mcp_request.writer_delivery[search_symbols]",
];

#[derive(Clone, Default)]
struct ProfiledStderrState {
    tail: VecDeque<u8>,
    tail_truncated: bool,
    observed_phases: [bool; PROFILED_PHASES.len()],
    read_error: Option<String>,
}

impl ProfiledStderrState {
    fn push(&mut self, bytes: &[u8]) {
        if bytes.len() >= PROFILED_STDERR_TAIL_BYTES {
            self.tail.clear();
            self.tail.extend(
                bytes[bytes.len() - PROFILED_STDERR_TAIL_BYTES..]
                    .iter()
                    .copied(),
            );
            self.tail_truncated = true;
        } else {
            let overflow = self
                .tail
                .len()
                .saturating_add(bytes.len())
                .saturating_sub(PROFILED_STDERR_TAIL_BYTES);
            if overflow > 0 {
                self.tail.drain(..overflow);
                self.tail_truncated = true;
            }
            self.tail.extend(bytes.iter().copied());
        }

        for (observed, marker) in self.observed_phases.iter_mut().zip(PROFILED_PHASE_MARKERS) {
            *observed |= bytes.windows(marker.len()).any(|window| window == marker);
        }
    }

    fn observed_phase(&self, phase: &str) -> bool {
        PROFILED_PHASES
            .iter()
            .position(|candidate| *candidate == phase)
            .is_some_and(|index| self.observed_phases[index])
    }

    fn diagnostics(&self) -> String {
        let observed = PROFILED_PHASES
            .into_iter()
            .zip(self.observed_phases)
            .filter_map(|(phase, observed)| observed.then_some(phase))
            .collect::<Vec<_>>();
        let tail = self.tail.iter().copied().collect::<Vec<_>>();
        format!(
            "stderr tail (prefix truncated: {}, observed phases: {:?}, read error: {:?}):\n{}",
            self.tail_truncated,
            observed,
            self.read_error,
            String::from_utf8_lossy(&tail)
        )
    }
}

struct ProfiledStderrDrain {
    state: Arc<Mutex<ProfiledStderrState>>,
    reader: Option<thread::JoinHandle<()>>,
    diagnostic_snapshot: Cursor<Vec<u8>>,
    diagnostic_snapshot_loaded: bool,
}

impl ProfiledStderrDrain {
    fn spawn(stderr: ChildStderr) -> Self {
        let state = Arc::new(Mutex::new(ProfiledStderrState::default()));
        let reader_state = Arc::clone(&state);
        let reader = thread::Builder::new()
            .name("profiled-mcp-stderr".to_string())
            .spawn(move || {
                let mut stderr = BufReader::new(stderr);
                let mut line = Vec::new();
                loop {
                    line.clear();
                    match stderr.read_until(b'\n', &mut line) {
                        Ok(0) => break,
                        Ok(_) => reader_state
                            .lock()
                            .expect("profiled stderr state mutex poisoned")
                            .push(&line),
                        Err(error) => {
                            reader_state
                                .lock()
                                .expect("profiled stderr state mutex poisoned")
                                .read_error = Some(error.to_string());
                            break;
                        }
                    }
                }
            })
            .expect("spawn profiled MCP stderr drain");
        Self {
            state,
            reader: Some(reader),
            diagnostic_snapshot: Cursor::new(Vec::new()),
            diagnostic_snapshot_loaded: false,
        }
    }

    fn capture(&self) -> ProfiledStderrState {
        self.state
            .lock()
            .expect("profiled stderr state mutex poisoned")
            .clone()
    }

    fn finish(mut self) -> ProfiledStderrState {
        self.reader
            .take()
            .expect("profiled stderr reader exists")
            .join()
            .expect("profiled stderr reader panicked");
        self.capture()
    }
}

impl Read for ProfiledStderrDrain {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.diagnostic_snapshot_loaded {
            self.diagnostic_snapshot =
                Cursor::new(self.capture().tail.into_iter().collect::<Vec<_>>());
            self.diagnostic_snapshot_loaded = true;
        }
        self.diagnostic_snapshot.read(buffer)
    }
}

#[test]
fn profiled_stderr_capture_bounds_tail_and_transport_evidence() {
    let mut state = ProfiledStderrState::default();
    state.push(&vec![b'x'; PROFILED_STDERR_TAIL_BYTES + 1]);
    assert_eq!(state.tail.len(), PROFILED_STDERR_TAIL_BYTES);
    assert!(state.tail_truncated);

    for phase in PROFILED_PHASES {
        state.push(
            format!("[bifrost-timing] mcp_request.{phase}[search_symbols] (1 ms)\n").as_bytes(),
        );
    }
    assert!(
        PROFILED_PHASES
            .into_iter()
            .all(|phase| state.observed_phase(phase))
    );
}

fn mcp_server_command(root: &std::path::Path, mode: &str, extra_args: &[&str]) -> Command {
    let mut command = Command::new(mcp_server_binary());
    command.arg("--root").arg(root).arg("--mcp").arg(mode);
    for arg in extra_args {
        command.arg(arg);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Issue #1491: the benchmark's transport-phase profile contract in
/// `src/benchmark/mcp_iteration.rs` requires all four `mcp_request.*` phases
/// (`queue_wait`, `execution`, `response_queue_wait`, `writer_delivery`) in
/// the stderr trace of a profiled RMCP session. The transport wrapper emits
/// the delivery phases. The wire assertion protects the benchmark contract.
#[test]
fn profiled_tool_calls_emit_all_transport_phases() {
    let workspace = InlineTestProject::new()
        .file(
            "Example.java",
            "public class Example { public void execute() {} }\n",
        )
        .build();
    let mut child = mcp_server_command(workspace.root(), "searchtools", &[])
        .env("BIFROST_TIMING", "1")
        .spawn()
        .expect("spawn profiled bifrost");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = ProfiledStderrDrain::spawn(child.stderr.take().expect("stderr"));
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["Example"] }
            }
        }),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    // The delivery phases reach stderr only after the response is on stdout.
    // A second round trip serializes behind that delivery, and waiting for
    // process exit below guarantees stderr is complete before it is read.
    let list = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 42, "method": "tools/list" }),
    );
    assert!(list["result"]["tools"].is_array(), "{list}");

    drop(stdin);
    let status = child.wait().expect("bifrost exits after stdin closes");
    let capture = stderr.finish();
    assert!(status.success(), "{}", capture.diagnostics());
    assert!(capture.read_error.is_none(), "{}", capture.diagnostics());
    for phase in PROFILED_PHASES {
        assert!(
            capture.observed_phase(phase),
            "stderr trace omitted transport phase `{phase}`:\n{}",
            capture.diagnostics()
        );
    }
}

/// A lightweight lookup on the same connection must overtake a long usage
/// scan instead of serializing behind it.
///
/// Two regressions are pinned here. First, `call_tool` once kept the
/// connection's workspace preparation guard alive in a maybe-moved binding
/// (`if serial { state } else { None }`) for the whole non-serial call, so
/// every tool call held the lock through analyzer execution and responses
/// could only arrive in request order. Second, the scan's rayon fan-out ran
/// on the global pool, so a concurrent request whose resolution injects
/// nested parallel work parked until the scan finished. The `mcp_fairness`
/// scenario in benchmark/interactive-latency.toml gates the same overlap
/// against a five-second budget; this is its fast in-repo counterpart.
#[test]
fn light_lookup_overtakes_long_usage_scan() {
    let mut project = InlineTestProject::with_language(Language::Rust).file(
        "hot.rs",
        "pub struct Hot;\npub fn touch(_value: Hot) -> Hot {\n    Hot\n}\n",
    );
    // Enough referencing files that the scan's per-candidate work reliably
    // outlasts one warmed single-symbol lookup by orders of magnitude, while
    // staying quick to write and index.
    for index in 0..300 {
        project = project.file(
            format!("user_{index}.rs"),
            format!(
                "pub fn user_{index}() {{\n    let value = crate::hot::Hot;\n    let _ = crate::hot::touch(value);\n}}\n"
            ),
        );
    }
    let workspace = project.build();
    let mut child = spawn_server(workspace.root(), "searchtools", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    // Warm the lookup once so the measured run is dispatch plus a cache hit,
    // not cold workspace readiness or first-touch hydration.
    let warm = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 60,
            "method": "tools/call",
            "params": {
                "name": "get_symbol_sources",
                "arguments": { "symbols": ["hot.rs#Hot"] }
            }
        }),
    );
    assert_eq!(warm["result"]["isError"], false, "{warm}");

    // Heavy first on the wire, light second. With fair scheduling the light
    // response overtakes; a serialized host can only answer in request order.
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 61,
            "method": "tools/call",
            "params": {
                "name": "scan_usages_by_location",
                "arguments": {
                    "targets": [{ "path": "hot.rs", "line": 1, "symbol": "Hot" }],
                    "include_tests": true,
                    "include_same_owner": true
                }
            }
        }),
    );
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 62,
            "method": "tools/call",
            "params": {
                "name": "get_symbol_sources",
                "arguments": { "symbols": ["hot.rs#Hot"] }
            }
        }),
    );
    let first = read_line(&mut reader, &mut stderr);
    assert_eq!(
        first["id"], 62,
        "the light lookup must answer while the scan is still running: {first}"
    );
    let second = read_line(&mut reader, &mut stderr);
    assert_eq!(second["id"], 61, "{second}");
    assert_eq!(second["result"]["isError"], false, "{second}");

    drop(stdin);
    let _ = child.wait();
}

fn spawn_rootless_server(cwd: &std::path::Path, mode: &str) -> std::process::Child {
    Command::new(mcp_server_binary())
        .arg("--mcp")
        .arg(mode)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rootless bifrost")
}

fn spawn_server_no_args(cwd: &std::path::Path) -> std::process::Child {
    // No mode: the compatibility contract is MCP searchtools. No --root: the
    // server must default its root to the working directory.
    Command::new(mcp_server_binary())
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost")
}

fn round_trip(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    payload: Value,
) -> Value {
    write_line(stdin, payload);
    read_line(reader, stderr)
}

fn write_line(stdin: &mut impl Write, payload: Value) {
    writeln!(stdin, "{payload}").expect("write request");
    stdin.flush().expect("flush request");
}

fn read_line(reader: &mut impl BufRead, stderr: &mut impl Read) -> Value {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).expect("read response");
    if bytes == 0 {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        panic!("server closed before responding; stderr:\n{buf}");
    }
    serde_json::from_str(&line).expect("valid json response")
}
