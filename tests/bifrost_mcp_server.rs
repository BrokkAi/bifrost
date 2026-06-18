use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

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
        .arg("--root")
        .arg(fixture_root.path())
        .arg("--server")
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
            "scan_usages",
            "get_definition_by_location",
            "usage_graph",
            "refresh",
            "activate_workspace",
            "get_active_workspace",
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
        ];
        #[cfg(feature = "nlp")]
        let expected = vec![
            "search_symbols",
            "get_symbol_sources",
            "get_summaries",
            "scan_usages",
            "get_definition_by_location",
            "usage_graph",
            "semantic_search",
            "refresh",
            "activate_workspace",
            "get_active_workspace",
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
        ];
        expected
    });
    assert_tool_schema_omits_property(tools, "get_definition_by_location", "include_tests");

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
    assert_eq!(
        active_workspace["result"]["structuredContent"]["workspace_path"],
        fixture_root
            .path()
            .canonicalize()
            .expect("canonicalize fixture")
            .display()
            .to_string()
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
    assert_eq!(list_symbols["result"]["isError"], false, "{list_symbols}");
    assert_eq!(
        list_symbols["result"]["structuredContent"]["files"][0]["path"],
        "DefaultRoot.java"
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
fn bifrost_split_servers_publish_expected_tool_sets() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let mut core_expected = vec![
        "search_symbols",
        "get_symbol_sources",
        "get_summaries",
        "scan_usages",
        "get_definition_by_location",
        "usage_graph",
    ];
    #[cfg(feature = "nlp")]
    core_expected.push("semantic_search");
    core_expected.extend(["refresh", "activate_workspace", "get_active_workspace"]);

    assert_server_tool_names(&fixture_root, "core", &core_expected);
    assert_unknown_tool(
        &fixture_root,
        "core",
        "get_definition_by_reference",
        json!({
            "references": [{
                "path": "A.java",
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
            "scan_usages",
            "get_definition_by_location",
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
        ],
    );
    #[cfg(feature = "nlp")]
    assert_server_tool_names(&fixture_root, "nlp", &["semantic_search"]);
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
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
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
    let expected_initial = initial_root.canonicalize().expect("canon initial");
    assert_eq!(initial_path, expected_initial.display().to_string());

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
    assert_eq!(
        activate["result"]["structuredContent"]["workspace_path"],
        switched_root.display().to_string()
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
    assert_eq!(
        after_switch["result"]["structuredContent"]["files"][0]["path"],
        "Switched.java"
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
    assert!(names.contains(&"get_definition_by_reference"), "{names:?}");
    assert!(!names.contains(&"get_definition_by_location"), "{names:?}");
    assert_tool_schema_omits_property(
        list_tools["result"]["tools"]
            .as_array()
            .expect("tools array"),
        "get_definition_by_reference",
        "include_tests",
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
                "name": "get_definition_by_location",
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
        "Unknown tool: get_definition_by_location",
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
    assert!(names.contains(&"get_definition_by_reference"), "{names:?}");
    assert!(!names.contains(&"get_definition_by_location"), "{names:?}");

    let unavailable_location_tool = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "get_definition_by_location",
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
        "Unknown tool: get_definition_by_location",
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
        structured["compact_symbols"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "A.java"),
        "{structured}"
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text");
    assert!(text.contains("A.java ("), "{text}");

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_mcp_get_summaries_mixed_targets_include_compact_symbols() {
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
        structured["compact_symbols"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "A.java"),
        "{structured}"
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text");
    assert!(text.contains("A.java"), "{text}");
    assert!(text.contains("A.java ("), "{text}");

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

fn initialize_session(stdin: &mut impl Write, reader: &mut impl BufRead, stderr: &mut impl Read) {
    round_trip(
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
}

fn spawn_server(root: &std::path::Path, mode: &str, extra_args: &[&str]) -> std::process::Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
    command.env("BIFROST_SEMANTIC_INDEX", "off");
    command.arg("--root").arg(root).arg("--server").arg(mode);
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

fn spawn_server_no_args(cwd: &std::path::Path) -> std::process::Child {
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
