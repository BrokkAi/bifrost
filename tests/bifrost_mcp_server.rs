mod common;

use common::InlineTestProject;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

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

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"));
    child.env("BIFROST_SEMANTIC_INDEX", "off");
    let mut child = child
        .arg("--force-semantic-cpu")
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
        #[cfg(not(feature = "nlp"))]
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
            "get_symbol_locations",
            "get_symbol_ancestors",
            "find_filenames",
            "list_files",
            "most_relevant_files",
            "search_git_commit_messages",
            "get_git_log",
            "get_commit_diff",
            "jq",
            "xml_skim",
            "xml_select",
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
            "analyze_commit",
            "classify_test_files",
        ];
        #[cfg(feature = "nlp")]
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
            "semantic_search",
            "refresh",
            "activate_workspace",
            "get_active_workspace",
            "query_code",
            "get_symbol_locations",
            "get_symbol_ancestors",
            "find_filenames",
            "list_files",
            "most_relevant_files",
            "search_git_commit_messages",
            "get_git_log",
            "get_commit_diff",
            "jq",
            "xml_skim",
            "xml_select",
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
            "analyze_commit",
            "classify_test_files",
        ];
        expected
    });
    assert_tool_schema_omits_property(tools, "get_definitions_by_location", "include_tests");
    assert_tool_schema_omits_property(tools, "get_declarations_by_location", "include_tests");
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
                    "file_paths": ["SampleTest.java"]
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
fn bifrost_mcp_dispatches_distinct_location_navigation_results() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let mut child = spawn_server(&fixture_root, "symbol", &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);
    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let arguments = json!({
        "references": [{"path": "B.java", "line": 8, "column": 11}]
    });
    let declaration = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {"name": "get_declarations_by_location", "arguments": arguments.clone()}
        }),
    );
    let declaration_result = &declaration["result"]["structuredContent"]["results"][0];
    assert_eq!(
        declaration_result["operation"], "declaration",
        "{declaration}"
    );
    assert!(
        declaration_result.get("declarations").is_some(),
        "{declaration}"
    );
    assert!(
        declaration_result.get("definitions").is_none(),
        "{declaration}"
    );

    let definition = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {"name": "get_definitions_by_location", "arguments": arguments}
        }),
    );
    let definition_result = &definition["result"]["structuredContent"]["results"][0];
    assert_eq!(definition_result["operation"], "definition", "{definition}");
    assert!(
        definition_result.get("definitions").is_some(),
        "{definition}"
    );
    assert!(
        definition_result.get("declarations").is_none(),
        "{definition}"
    );

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
        "bifrost_code_query_profile/v1"
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
fn bifrost_split_servers_publish_expected_tool_sets() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let mut core_expected = vec![
        "search_symbols",
        "get_symbol_sources",
        "get_summaries",
        "scan_usages_by_location",
        "get_declarations_by_location",
        "get_definitions_by_location",
        "get_type_by_location",
        "rename_symbol",
        "usage_graph",
    ];
    #[cfg(feature = "nlp")]
    core_expected.push("semantic_search");
    core_expected.extend(["refresh", "activate_workspace", "get_active_workspace"]);

    assert_server_tool_names(&fixture_root, "core", &core_expected);
    assert_unknown_tool(
        &fixture_root,
        "core",
        "analyze_commit",
        json!({ "revision": "HEAD" }),
    );
    assert_unknown_tool(
        &fixture_root,
        "core",
        "scan_usages",
        json!({ "symbols": ["A"] }),
    );
    assert_unknown_tool(
        &fixture_root,
        "core",
        "get_definitions_by_reference",
        json!({
            "references": [{
                "symbol": "A",
                "context": "class A",
                "target": "A"
            }]
        }),
    );
    assert_server_tool_names(
        &fixture_root,
        "workspace|symbol",
        &[
            "refresh",
            "activate_workspace",
            "get_active_workspace",
            "search_symbols",
            "get_symbol_sources",
            "get_summaries",
            "scan_usages_by_location",
            "get_declarations_by_location",
            "get_definitions_by_location",
            "get_type_by_location",
            "rename_symbol",
            "usage_graph",
        ],
    );
    assert_server_tool_names(
        &fixture_root,
        "text|extended",
        &[
            "get_file_contents",
            "search_file_contents",
            "find_files_containing",
            "query_code",
            "get_symbol_locations",
            "get_symbol_ancestors",
            "find_filenames",
            "list_files",
            "most_relevant_files",
            "search_git_commit_messages",
            "get_git_log",
            "get_commit_diff",
            "jq",
            "xml_skim",
            "xml_select",
        ],
    );
    assert_server_tool_names(
        &fixture_root,
        "extended",
        &[
            "query_code",
            "get_symbol_locations",
            "get_symbol_ancestors",
            "find_filenames",
            "list_files",
            "most_relevant_files",
            "search_git_commit_messages",
            "get_git_log",
            "get_commit_diff",
            "jq",
            "xml_skim",
            "xml_select",
        ],
    );
    assert_server_tool_names(
        &fixture_root,
        "slopcop",
        &[
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
            "analyze_commit",
        ],
    );
    #[cfg(feature = "nlp")]
    assert_server_tool_names(&fixture_root, "nlp", &["semantic_search"]);
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

/// When the embedding model cannot load, semantic_search must surface a
/// clean tool error instead of hanging on the background build.
#[test]
#[cfg(feature = "nlp")]
fn bifrost_semantic_search_fails_cleanly_without_models() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
    command
        // Re-enable the indexer (spawn helpers disable it) but point the
        // embedder at a directory that cannot exist: the engine load fails
        // fast with no network access.
        .env("BIFROST_SEMANTIC_INDEX", "auto")
        .env(
            "BIFROST_EMBED_MODEL_DIR",
            "/nonexistent/bifrost-test-models",
        )
        .arg("--force-semantic-cpu")
        .arg("--root")
        .arg(&fixture_root)
        .arg("--mcp")
        .arg("nlp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn bifrost");
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
                "name": "semantic_search",
                "arguments": { "query": "where is the config loaded", "k": 3 }
            }
        }),
    );
    let message = response["error"]["message"]
        .as_str()
        .expect("json-rpc error message");
    assert!(
        message.contains("semantic index unavailable") || message.contains("disabled"),
        "unexpected error message: {message}"
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_split_servers_reject_tools_outside_their_registry() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    assert_unknown_tool(
        &fixture_root,
        "core",
        "most_relevant_files",
        json!({ "seed_file_paths": ["A.java"] }),
    );
    assert_unknown_tool(
        &fixture_root,
        "extended",
        "get_summaries",
        json!({ "targets": ["A.java"] }),
    );
    assert_unknown_tool(
        &fixture_root,
        "slopcop",
        "get_file_contents",
        json!({ "file_paths": ["A.java"] }),
    );
    assert_unknown_tool(
        &fixture_root,
        "searchtools",
        "search_ast",
        json!({ "match": { "kind": "class", "name": "A" } }),
    );
}

#[test]
fn bifrost_mcp_rename_symbol_returns_structured_edit_set() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let before_a = fs::read_to_string(fixture_root.join("A.java")).expect("read A.java");
    let mut child = spawn_server(&fixture_root, "core", &[]);
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
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "rename_symbol",
                "arguments": {
                    "path": "A.java",
                    "line": 8,
                    "column": 19,
                    "new_name": "renamedMethod2"
                }
            }
        }),
    );
    let structured = &response["result"]["structuredContent"];
    assert_eq!("ok", structured["status"], "response: {response}");
    assert_eq!(
        "A.method2", structured["target"]["symbol"],
        "response: {response}"
    );
    assert!(
        structured["edits"].as_array().unwrap().iter().any(|file| {
            file["path"] == "B.java"
                && file["edits"].as_array().unwrap().iter().any(|edit| {
                    edit["old_text"] == "method2" && edit["new_text"] == "renamedMethod2"
                })
        }),
        "response: {response}"
    );
    assert_eq!(
        before_a,
        fs::read_to_string(fixture_root.join("A.java")).expect("read A.java after rename"),
        "rename_symbol must not mutate files"
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_searchtools_server_supports_runtime_workspace_switch() {
    let initial_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let switched = TempDir::new().expect("temp dir");
    fs::write(
        switched.path().join("Switched.java"),
        "public class Switched {}\n",
    )
    .expect("write fixture");
    let switched_root = switched.path().canonicalize().expect("canonicalize");

    let mut child = spawn_server(&initial_root, "searchtools", &[]);

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    round_trip(
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
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }),
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

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
        tools
            .iter()
            .any(|tool| tool["name"] == "activate_workspace"),
        "activate_workspace missing from tool list: {list_tools}"
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == "get_active_workspace"),
        "get_active_workspace missing from tool list: {list_tools}"
    );

    let initial_active = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_active_workspace",
                "arguments": {}
            }
        }),
    );
    let initial_path = initial_active["result"]["structuredContent"]["workspace_path"]
        .as_str()
        .expect("initial workspace path");
    assert_same_canonical_path(initial_path, &initial_root);

    let activate = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": { "workspace_path": switched_root.display().to_string() }
            }
        }),
    );
    assert_same_canonical_path(
        activate["result"]["structuredContent"]["workspace_path"]
            .as_str()
            .expect("workspace path"),
        &switched_root,
    );

    let after_switch = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "list_symbols",
                "arguments": { "file_patterns": ["Switched.java"] }
            }
        }),
    );
    assert_eq!(after_switch["result"]["isError"], true, "{after_switch}");
    assert_eq!(
        after_switch["result"]["content"][0]["text"],
        "Unknown tool: list_symbols"
    );

    let bad_path = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": { "workspace_path": "relative/path" }
            }
        }),
    );
    assert_eq!(bad_path["error"]["code"], -32602);

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_searchtools_server_can_hide_line_numbers_in_text_preview() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = spawn_server(&fixture_root, "searchtools", &["--no-line-numbers"]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let list_tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/list" }),
    );
    let names = tool_names(
        list_tools["result"]["tools"]
            .as_array()
            .expect("tools array"),
    );
    assert!(names.contains(&"get_definitions_by_reference"), "{names:?}");
    assert!(!names.contains(&"get_definitions_by_location"), "{names:?}");
    assert!(
        !names.contains(&"get_declarations_by_location"),
        "{names:?}"
    );
    assert!(!names.contains(&"get_type_by_location"), "{names:?}");
    assert!(names.contains(&"scan_usages_by_reference"), "{names:?}");
    assert!(!names.contains(&"scan_usages_by_location"), "{names:?}");
    assert!(!names.contains(&"scan_usages"), "{names:?}");
    assert_tool_schema_omits_property(
        list_tools["result"]["tools"]
            .as_array()
            .expect("tools array"),
        "get_definitions_by_reference",
        "include_tests",
    );
    assert_scan_usages_reference_schema(
        list_tools["result"]["tools"]
            .as_array()
            .expect("tools array"),
    );

    let unavailable_location_tool = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "get_definitions_by_location",
                "arguments": {
                    "references": [{
                        "path": "A.java",
                        "line": 1,
                        "column": 1
                    }]
                }
            }
        }),
    );
    assert_eq!(
        unavailable_location_tool["result"]["content"][0]["text"],
        "Unknown tool: get_definitions_by_location",
        "{unavailable_location_tool}"
    );

    let summaries = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_summaries",
                "arguments": {
                    "targets": ["A.java"]
                }
            }
        }),
    );
    let preview = summaries["result"]["content"][0]["text"]
        .as_str()
        .expect("preview text");
    assert!(preview.contains("public class A"), "{preview}");
    assert!(!preview.contains("\"summaries\""), "{preview}");
    assert!(!preview.contains("3..52:"), "{preview}");
    assert!(!preview.contains("8..10:"), "{preview}");
    assert!(
        summaries["result"]["structuredContent"]["summaries"][0]["elements"][0]["start_line"]
            .is_number()
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_core_server_can_hide_line_numbers_in_text_preview() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = spawn_server(&fixture_root, "core", &["--no-line-numbers"]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    initialize_session(&mut stdin, &mut reader, &mut stderr);

    let list_tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/list" }),
    );
    let names = tool_names(
        list_tools["result"]["tools"]
            .as_array()
            .expect("tools array"),
    );
    assert!(names.contains(&"get_definitions_by_reference"), "{names:?}");
    assert!(!names.contains(&"get_definitions_by_location"), "{names:?}");
    assert!(
        !names.contains(&"get_declarations_by_location"),
        "{names:?}"
    );
    assert!(!names.contains(&"get_type_by_location"), "{names:?}");
    assert!(names.contains(&"scan_usages_by_reference"), "{names:?}");
    assert!(!names.contains(&"scan_usages_by_location"), "{names:?}");
    assert!(!names.contains(&"scan_usages"), "{names:?}");

    let unavailable_location_tool = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "get_definitions_by_location",
                "arguments": {
                    "references": [{
                        "path": "A.java",
                        "line": 1,
                        "column": 1
                    }]
                }
            }
        }),
    );
    assert_eq!(
        unavailable_location_tool["result"]["content"][0]["text"],
        "Unknown tool: get_definitions_by_location",
        "{unavailable_location_tool}"
    );

    let summaries = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_summaries",
                "arguments": {
                    "targets": ["A.java"]
                }
            }
        }),
    );
    let preview = summaries["result"]["content"][0]["text"]
        .as_str()
        .expect("preview text");
    assert!(preview.contains("public class A"), "{preview}");
    assert!(!preview.contains("\"summaries\""), "{preview}");
    assert!(!preview.contains("3..52:"), "{preview}");
    assert!(!preview.contains("8..10:"), "{preview}");
    assert!(
        summaries["result"]["structuredContent"]["summaries"][0]["elements"][0]["start_line"]
            .is_number()
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
fn bifrost_mcp_get_summaries_remains_directory_aware() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = spawn_server(&fixture_root, "searchtools", &[]);
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
                "arguments": { "targets": ["."] }
            }
        }),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    let structured = &response["result"]["structuredContent"];
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
    assert!(text.contains("[file] A.java"), "{text}");

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

fn assert_server_tool_names(root: &std::path::Path, mode: &str, expected: &[&str]) {
    let mut child = spawn_server(root, mode, &[]);
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
    assert_eq!(
        tool_names(tools),
        expected,
        "mode {mode} published unexpected tools"
    );
    assert_agents_guidance_resource_available(&mut stdin, &mut reader, &mut stderr);

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

fn assert_scan_usages_reference_schema(tools: &[Value]) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "scan_usages_by_reference")
        .expect("missing scan_usages_by_reference descriptor");
    let schema = &tool["inputSchema"];

    assert_eq!(schema["required"], json!(["symbols"]));
    assert_eq!(schema["properties"]["symbols"]["minItems"], 1);
    assert_eq!(schema["properties"]["symbols"]["items"]["pattern"], "\\S");
    let serialized = serde_json::to_string(schema).unwrap();
    assert!(!serialized.contains("targets"), "{serialized}");
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

fn assert_unknown_tool(root: &std::path::Path, mode: &str, tool_name: &str, arguments: Value) {
    let mut child = spawn_server(root, mode, &[]);
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
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }),
    );
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(
        response["result"]["content"][0]["text"],
        format!("Unknown tool: {tool_name}")
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

fn assert_agents_guidance_resource_available(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
) {
    let list_resources = round_trip(
        stdin,
        reader,
        stderr,
        json!({ "jsonrpc": "2.0", "id": 101, "method": "resources/list" }),
    );
    assert_eq!(
        list_resources["result"]["resources"][0]["uri"], "bifrost://agent-guidance/agents.md",
        "{list_resources}"
    );

    let read_resource = round_trip(
        stdin,
        reader,
        stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "resources/read",
            "params": { "uri": "bifrost://agent-guidance/agents.md" }
        }),
    );
    let text = read_resource["result"]["contents"][0]["text"]
        .as_str()
        .expect("resource text");
    assert!(text.contains("get_summaries"), "{read_resource}");
}

#[test]
fn rootless_mcp_binds_to_client_roots_without_analyzing_process_cwd() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    fs::write(
        plugin_dir.path().join("PluginOnly.java"),
        "class PluginOnly {}\n",
    )
    .expect("write plugin fixture");
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
                "clientInfo": { "name": "codex-mcp-client", "version": "0.145.0" }
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
    let roots_request = read_line(&mut reader, &mut stderr);
    assert_eq!(roots_request["method"], "roots/list", "{roots_request}");
    // If the client's roots change before it answers, the in-flight result is
    // stale and must never become analyzer scope, even briefly.
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
            "id": roots_request["id"],
            "result": { "roots": [{ "uri": plugin_uri, "name": "stale" }] }
        }),
    );
    let current_roots_request = read_line(&mut reader, &mut stderr);
    assert_eq!(
        current_roots_request["method"], "roots/list",
        "{current_roots_request}"
    );
    let workspace_uri = url::Url::from_directory_path(workspace.path())
        .expect("workspace file URI")
        .to_string();
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": current_roots_request["id"],
            "result": { "roots": [{ "uri": workspace_uri, "name": "fixture" }] }
        }),
    );

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
                "arguments": { "patterns": ["ClientWorkspace"] },
                "_meta": codex_sandbox_metadata(plugin_dir.path(), "roots-precedence")
            }
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

    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }),
    );
    let replacement_request = read_line(&mut reader, &mut stderr);
    assert_eq!(
        replacement_request["method"], "roots/list",
        "{replacement_request}"
    );
    let unbound_during_refresh = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["ClientWorkspace"] },
                "_meta": codex_sandbox_metadata(plugin_dir.path(), "roots-refresh")
            }
        }),
    );
    assert!(
        unbound_during_refresh["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "{unbound_during_refresh}"
    );
    let replacement_uri = url::Url::from_directory_path(replacement.path())
        .expect("replacement file URI")
        .to_string();
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": replacement_request["id"],
            "result": { "roots": [{ "uri": replacement_uri }] }
        }),
    );
    let replacement_search = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "search_symbols",
                "arguments": { "patterns": ["ReplacementWorkspace"] }
            }
        }),
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

    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }),
    );
    let revoke_request = read_line(&mut reader, &mut stderr);
    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": revoke_request["id"],
            "result": { "roots": [] }
        }),
    );
    let revoked_search = round_trip(
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
    );
    assert!(
        revoked_search["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "{revoked_search}"
    );
    assert!(
        !plugin_dir.path().join(".brokk/bifrost_cache.db").exists(),
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

    let mut child = spawn_rootless_server(plugin_dir.path(), "workspace|symbol");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = child.stderr.take().expect("stderr");

    let before_initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        codex_search_symbols_call(0, workspace.root(), "codex-test-thread", "CodexWorkspace"),
    );
    assert_eq!(before_initialize["error"]["code"], -32603);
    assert!(
        before_initialize["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not bound to a workspace")),
        "Codex metadata must not grant workspace authority before capability negotiation: {before_initialize}"
    );

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
        !plugin_dir.path().join(".brokk/bifrost_cache.db").exists(),
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
        !plugin_dir.path().join(".brokk/bifrost_cache.db").exists(),
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
        !plugin_dir.path().join(".brokk/bifrost_cache.db").exists(),
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
    let initialize = round_trip(
        stdin,
        reader,
        stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }),
    );
    write_line(
        stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    initialize
}

fn codex_handshake_message(name: &str) -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/mcp/codex-sandbox-state-handshake.json"
    ))
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
    command.env("BIFROST_SEMANTIC_INDEX", "off");
    command.arg("--force-semantic-cpu");
    command.arg("--root").arg(root).arg("--mcp").arg(mode);
    for arg in extra_args {
        command.arg(arg);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost")
}

fn spawn_rootless_server(cwd: &std::path::Path, mode: &str) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .env("BIFROST_SEMANTIC_INDEX", "off")
        .arg("--force-semantic-cpu")
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
    Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .env("BIFROST_SEMANTIC_INDEX", "off")
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
