use brokk_bifrost::lsp::conversion::path_to_uri_string;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use tempfile::TempDir;

/// Build an LSP-correct `file://` URI for `path`. On Windows, `Path::display()`
/// of a canonicalized path emits the extended-length form (`\\?\C:\…`) which
/// is NOT a valid URI; the crate's path_to_uri_string handles drive letters,
/// percent-encoding, and the leading-slash convention correctly. Tests use
/// this helper instead of hand-rolling `format!("file://{}", path.display())`.
fn uri_for(path: &Path) -> String {
    path_to_uri_string(path)
}

/// Java fixture used by the completion-handler integration tests. `gree` on
/// line 3 is a stand-alone identifier prefix — tree-sitter still extracts the
/// surrounding declarations even though the body doesn't parse cleanly, so
/// the analyzer reports `greetEveryone` as a Function.
const COMPLETOR_JAVA_FIXTURE: &str = "public class Completor {\n    public void greetEveryone() {}\n    void caller() {\n        gree\n    }\n}\n";

fn write_completor_fixture(temp_root: &Path) -> std::path::PathBuf {
    let file = temp_root.join("Completor.java");
    fs::write(&file, COMPLETOR_JAVA_FIXTURE).expect("write Completor.java fixture");
    file
}

struct JvmTypeContextFixtures {
    java_path: PathBuf,
    java_source: &'static str,
    csharp_path: PathBuf,
    csharp_source: &'static str,
    scala_path: PathBuf,
    scala_source: &'static str,
}

fn write_jvm_type_context_fixtures(root: &Path, prefix: &str) -> JvmTypeContextFixtures {
    let java_path = root.join(format!("{prefix}.java"));
    let java_source = "class Widget {}\nclass Child extends Widget {}\nclass Service {\n    Widget build() {\n        Widget local = new Widget();\n        return local;\n    }\n}\n";
    fs::write(&java_path, java_source).expect("write Java type-context fixture");

    let csharp_path = root.join(format!("{prefix}.cs"));
    let csharp_source = "class Widget {}\nclass Service { Widget Build() { Widget local = new Widget(); return local; } }\n";
    fs::write(&csharp_path, csharp_source).expect("write C# type-context fixture");

    let scala_path = root.join(format!("{prefix}.scala"));
    let scala_source = "class Widget\nclass Child extends Widget\nclass Service {\n  def build(): Widget = {\n    val local: Widget = new Widget\n    local\n  }\n}\n";
    fs::write(&scala_path, scala_source).expect("write Scala type-context fixture");

    JvmTypeContextFixtures {
        java_path,
        java_source,
        csharp_path,
        csharp_source,
        scala_path,
        scala_source,
    }
}

struct LspTestServer {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    stderr: ChildStderr,
}

impl LspTestServer {
    fn start(root: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
            .arg("--root")
            .arg(root)
            .arg("--server")
            .arg("lsp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bifrost");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let stderr = child.stderr.take().expect("stderr");
        Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
            stderr,
        }
    }

    fn initialize(&mut self, root: &Path) {
        let root_uri = uri_for(root);
        self.write(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }));
        let _ = self.read_message();
        self.write(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    }

    fn write(&mut self, message: Value) {
        write_message(&mut self.stdin, message);
    }

    fn read_message(&mut self) -> Value {
        read_message(&mut self.reader, &mut self.stderr)
    }

    fn read_notification(&mut self, method: &str) -> Value {
        read_notification(&mut self.reader, &mut self.stderr, method)
    }

    fn shutdown(mut self, id: u64) {
        self.write(json!({"jsonrpc": "2.0", "id": id, "method": "shutdown"}));
        let _ = self.read_message();
        self.write(json!({"jsonrpc": "2.0", "method": "exit"}));
        drop(self.stdin);
        let status = self.child.wait().expect("wait bifrost");
        assert!(status.success(), "bifrost exited unsuccessfully: {status}");
    }
}

#[test]
fn bifrost_lsp_server_handles_initialize_and_shutdown() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": null,
                "capabilities": {}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    assert!(
        initialize["result"]["capabilities"]["textDocumentSync"].is_object(),
        "textDocumentSync should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["typeHierarchyProvider"], true,
        "typeHierarchyProvider should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["callHierarchyProvider"], true,
        "callHierarchyProvider should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["typeDefinitionProvider"], true,
        "typeDefinitionProvider should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["implementationProvider"], true,
        "implementationProvider should be advertised: {initialize}"
    );
    assert!(
        initialize["result"]["capabilities"]["signatureHelpProvider"].is_object(),
        "signatureHelpProvider should be advertised: {initialize}"
    );
    assert!(
        initialize["result"]["capabilities"]["signatureHelpProvider"]["triggerCharacters"]
            .is_null(),
        "signatureHelpProvider should require explicit client requests: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["renameProvider"]["prepareProvider"], true,
        "renameProvider with prepare support should be advertised: {initialize}"
    );
    assert!(
        initialize["result"]["capabilities"]["documentFormattingProvider"].is_object(),
        "documentFormattingProvider should be advertised: {initialize}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}),
    );
    let shutdown = read_message(&mut reader, &mut stderr);
    assert_eq!(shutdown["id"], 2);
    assert!(shutdown["error"].is_null(), "unexpected error: {shutdown}");

    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_indexes_all_startup_workspace_folders() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    let alpha_path = root_a.join("Alpha.java");
    let beta_path = root_b.join("Beta.java");
    fs::write(
        &alpha_path,
        "class AlphaRoot {\n    void alphaOnly() {}\n}\n",
    )
    .expect("write Alpha.java");
    fs::write(&beta_path, "class BetaRoot {\n    void betaOnly() {}\n}\n")
        .expect("write Beta.java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&parent)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": null,
                "workspaceFolders": [
                    {"uri": uri_for(&root_a), "name": "service-a"},
                    {"uri": uri_for(&root_b), "name": "service-b"}
                ],
                "capabilities": {"workspace": {"workspaceFolders": true}}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    assert_eq!(
        initialize["result"]["capabilities"]["workspace"]["workspaceFolders"]["supported"], true,
        "workspace folder support should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["workspace"]["workspaceFolders"]["changeNotifications"],
        true,
        "dynamic workspace folder changes should be advertised: {initialize}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "Only"}
        }),
    );
    let symbols_response = read_message(&mut reader, &mut stderr);
    let symbols = symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {symbols_response}"));
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "alphaOnly"),
        "expected alphaOnly from first root in {symbols:#?}"
    );
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "betaOnly"),
        "expected betaOnly from second root in {symbols:#?}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": uri_for(&beta_path)}}
        }),
    );
    let document_symbols_response = read_message(&mut reader, &mut stderr);
    assert_eq!(
        document_symbols_response["id"], 3,
        "expected documentSymbol response: {document_symbols_response}"
    );
    let document_symbols = document_symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected document symbols, got {document_symbols_response}"));
    assert!(
        document_symbols
            .iter()
            .any(|symbol| symbol["name"] == "BetaRoot"),
        "expected BetaRoot document symbol from second root in {document_symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_honors_configured_roots() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let included = parent.join("included");
    let sibling = parent.join("sibling");
    fs::create_dir_all(&included).expect("create included");
    fs::create_dir_all(&sibling).expect("create sibling");
    fs::write(
        included.join("Included.java"),
        "class IncludedRoot {\n    void includedOnly() {}\n}\n",
    )
    .expect("write Included.java");
    fs::write(
        sibling.join("Sibling.java"),
        "class SiblingRoot {\n    void siblingLeak() {}\n}\n",
    )
    .expect("write Sibling.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": uri_for(&parent),
            "workspaceFolders": [{"uri": uri_for(&parent), "name": "workspace"}],
            "initializationOptions": {
                "roots": [included.display().to_string()]
            },
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "Only"}
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 2);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "includedOnly"),
        "configured root should be indexed: {symbols:#?}"
    );
    assert!(
        symbols.iter().all(|symbol| symbol["name"] != "siblingLeak"),
        "workspace sibling outside configured roots should not be indexed: {symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_honors_excluded_paths() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let src = root.join("src");
    let generated = root.join("generated");
    fs::create_dir_all(&src).expect("create src");
    fs::create_dir_all(&generated).expect("create generated");
    let kept_path = src.join("Kept.java");
    let excluded_path = generated.join("Generated.java");
    fs::write(&kept_path, "class KeptRoot {\n    void keptOnly() {}\n}\n")
        .expect("write Kept.java");
    fs::write(
        &excluded_path,
        "class GeneratedRoot {\n    void generatedLeak() {}\n}\n",
    )
    .expect("write Generated.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "workspaceFolders": [{"uri": uri_for(&root), "name": "workspace"}],
            "initializationOptions": {
                "exclude": ["generated"]
            },
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "Only"}
        }),
    );
    let symbols_response = read_response_for_id(&mut reader, &mut stderr, 2);
    let symbols = symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {symbols_response}"));
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "keptOnly"),
        "non-excluded source should be indexed: {symbols:#?}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "workspace/symbol",
            "params": {"query": "Leak"}
        }),
    );
    let excluded_workspace_response = read_response_for_id(&mut reader, &mut stderr, 3);
    let excluded_workspace_symbols = excluded_workspace_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {excluded_workspace_response}"));
    assert!(
        excluded_workspace_symbols
            .iter()
            .all(|symbol| symbol["name"] != "generatedLeak"),
        "excluded source should not be indexed: {excluded_workspace_symbols:#?}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": uri_for(&excluded_path)}}
        }),
    );
    let excluded_symbols_response = read_response_for_id(&mut reader, &mut stderr, 4);
    assert!(
        excluded_symbols_response["result"].is_null()
            || excluded_symbols_response["result"]
                .as_array()
                .is_some_and(|symbols| symbols.is_empty()),
        "excluded file should not resolve for documentSymbol: {excluded_symbols_response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_adds_workspace_folder_dynamically() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    let outside = parent.join("outside");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::create_dir_all(&outside).expect("create outside");
    fs::write(
        root_a.join("Alpha.java"),
        "class AlphaRoot {\n    void alphaOnly() {}\n}\n",
    )
    .expect("write Alpha.java");
    let beta_path = root_b.join("Beta.java");
    fs::write(
        &beta_path,
        "class BetaRoot {\n    void betaDynamic() {}\n}\n",
    )
    .expect("write Beta.java");
    fs::write(
        outside.join("Outside.java"),
        "class OutsideRoot {\n    void outsideLeak() {}\n}\n",
    )
    .expect("write Outside.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [{"uri": uri_for(&root_a), "name": "service-a"}],
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWorkspaceFolders",
            "params": {
                "event": {
                    "added": [{"uri": uri_for(&root_b), "name": "service-b"}],
                    "removed": []
                }
            }
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "Dynamic"}
        }),
    );
    let symbols_response = read_response_for_id(&mut reader, &mut stderr, 2);
    let symbols = symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {symbols_response}"));
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "betaDynamic"),
        "expected betaDynamic from added root in {symbols:#?}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": uri_for(&beta_path)}}
        }),
    );
    let document_symbols_response = read_response_for_id(&mut reader, &mut stderr, 3);
    let document_symbols = document_symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("expected document symbols from added root, got {document_symbols_response}")
        });
    assert!(
        document_symbols
            .iter()
            .any(|symbol| symbol["name"] == "BetaRoot"),
        "expected BetaRoot document symbol from added root in {document_symbols:#?}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "workspace/symbol",
            "params": {"query": "outsideLeak"}
        }),
    );
    let outside_response = read_response_for_id(&mut reader, &mut stderr, 4);
    let outside_symbols = outside_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {outside_response}"));
    assert!(
        outside_symbols.is_empty(),
        "sibling outside active workspace folders should not be indexed: {outside_symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_removes_workspace_folder_dynamically() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    let request_path = root_a.join("Requester.java");
    let removed_path = root_b.join("Removed.java");
    fs::write(
        &request_path,
        "class Requester {\n    void caller() {\n        removed\n    }\n}\n",
    )
    .expect("write Requester.java");
    fs::write(
        &removed_path,
        "class RemovedRoot {\n    void removedCompletion() {}\n    void broken( {\n}\n",
    )
    .expect("write Removed.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [
                {"uri": uri_for(&root_a), "name": "service-a"},
                {"uri": uri_for(&root_b), "name": "service-b"}
            ],
            "capabilities": {}
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": uri_for(&request_path)},
                "position": {"line": 2, "character": 15}
            }
        }),
    );
    let before_completion = read_response_for_id(&mut reader, &mut stderr, 2);
    let before_items = before_completion["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected completion items, got {before_completion}"));
    assert!(
        before_items
            .iter()
            .any(|item| item["label"] == "removedCompletion"),
        "expected completion from second root before removal: {before_items:#?}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {"textDocument": {"uri": uri_for(&removed_path)}}
        }),
    );
    let publish_before =
        read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");
    assert_eq!(
        publish_before["params"]["uri"],
        uri_for(&removed_path),
        "expected diagnostics for removed-root file before removal: {publish_before}"
    );
    assert!(
        !publish_before["params"]["diagnostics"]
            .as_array()
            .unwrap_or_else(|| panic!("expected diagnostics array, got {publish_before}"))
            .is_empty(),
        "expected parse diagnostics before removing root: {publish_before}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWorkspaceFolders",
            "params": {
                "event": {
                    "added": [],
                    "removed": [{"uri": uri_for(&root_b), "name": "service-b"}]
                }
            }
        }),
    );
    let publish_clear =
        read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");
    assert_eq!(
        publish_clear["params"]["uri"],
        uri_for(&removed_path),
        "expected removed-root diagnostics to be cleared: {publish_clear}"
    );
    assert!(
        publish_clear["params"]["diagnostics"]
            .as_array()
            .unwrap_or_else(|| panic!("expected diagnostics array, got {publish_clear}"))
            .is_empty(),
        "expected empty diagnostics after root removal: {publish_clear}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "workspace/symbol",
            "params": {"query": "removedCompletion"}
        }),
    );
    let after_symbols = read_response_for_id(&mut reader, &mut stderr, 3);
    let symbols = after_symbols["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {after_symbols}"));
    assert!(
        symbols.is_empty(),
        "removed root symbols should disappear: {symbols:#?}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": uri_for(&request_path)},
                "position": {"line": 2, "character": 15}
            }
        }),
    );
    let after_completion = read_response_for_id(&mut reader, &mut stderr, 4);
    let after_items = after_completion["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected completion items, got {after_completion}"));
    assert!(
        !after_items
            .iter()
            .any(|item| item["label"] == "removedCompletion"),
        "completion cache should not retain removed-root symbols: {after_items:#?}"
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": uri_for(&removed_path)}}
        }),
    );
    let removed_document = read_response_for_id(&mut reader, &mut stderr, 5);
    assert!(
        removed_document["result"].is_null(),
        "document requests should no longer route to removed roots: {removed_document}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_replays_open_document_after_workspace_folder_readd() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::write(root_a.join("Alpha.java"), "class AlphaRoot {}\n").expect("write Alpha.java");
    let beta_path = root_b.join("Beta.java");
    fs::write(&beta_path, "class BetaRoot {\n    void diskOnly() {}\n}\n")
        .expect("write Beta.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [
                {"uri": uri_for(&root_a), "name": "service-a"},
                {"uri": uri_for(&root_b), "name": "service-b"}
            ],
            "capabilities": {}
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri_for(&beta_path),
                    "languageId": "java",
                    "version": 1,
                    "text": "class BetaRoot {\n    void overlayOnly() {}\n}\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWorkspaceFolders",
            "params": {
                "event": {
                    "added": [],
                    "removed": [{"uri": uri_for(&root_b), "name": "service-b"}]
                }
            }
        }),
    );
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWorkspaceFolders",
            "params": {
                "event": {
                    "added": [{"uri": uri_for(&root_b), "name": "service-b"}],
                    "removed": []
                }
            }
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "overlayOnly"}
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 2);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "overlayOnly"),
        "re-added root should replay still-open document overlay: {symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_removes_symlinked_workspace_folder_after_symlink_disappears() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let real_root = parent.join("real-service");
    let link_root = parent.join("linked-service");
    fs::create_dir_all(&real_root).expect("create real service");
    std::os::unix::fs::symlink(&real_root, &link_root).expect("create root symlink");
    fs::write(
        real_root.join("Linked.java"),
        "class LinkedRoot {\n    void linkedOnly() {}\n}\n",
    )
    .expect("write Linked.java");
    let link_uri = uri_for(&link_root);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [{"uri": link_uri, "name": "linked-service"}],
            "capabilities": {}
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "linkedOnly"}
        }),
    );
    let before = read_response_for_id(&mut reader, &mut stderr, 2);
    let before_symbols = before["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {before}"));
    assert!(
        before_symbols
            .iter()
            .any(|symbol| symbol["name"] == "linkedOnly"),
        "expected linked root symbol before removal: {before_symbols:#?}"
    );

    fs::remove_file(&link_root).expect("remove root symlink");
    assert!(
        !link_root.exists(),
        "root symlink should be gone before removal notification"
    );
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWorkspaceFolders",
            "params": {
                "event": {
                    "added": [],
                    "removed": [{"uri": link_uri, "name": "linked-service"}]
                }
            }
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "workspace/symbol",
            "params": {"query": "linkedOnly"}
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 3);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols.is_empty(),
        "removing the original symlink URI should remove its canonical analyzer root: {symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_ignores_invalid_dynamic_workspace_folder_additions() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let not_a_dir = root.join("NotADir.java");
    fs::write(
        root.join("Alpha.java"),
        "class AlphaRoot {\n    void alphaStillIndexed() {}\n}\n",
    )
    .expect("write Alpha.java");
    fs::write(&not_a_dir, "class NotADir {}\n").expect("write NotADir.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWorkspaceFolders",
            "params": {
                "event": {
                    "added": [
                        {"uri": "untitled:dynamic-root", "name": "bad-scheme"},
                        {"uri": uri_for(&not_a_dir), "name": "not-a-dir"}
                    ],
                    "removed": []
                }
            }
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "alphaStillIndexed"}
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 2);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "alphaStillIndexed"),
        "invalid additions should not disturb the existing workspace: {symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_indexes_new_file_in_second_workspace_folder() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::write(
        root_a.join("Alpha.java"),
        "class AlphaRoot {\n    void alphaOnly() {}\n}\n",
    )
    .expect("write Alpha.java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&parent)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);
    let beta_path = root_b.join("Beta.java");
    let beta_uri = uri_for(&beta_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": null,
                "workspaceFolders": [
                    {"uri": uri_for(&root_a), "name": "service-a"},
                    {"uri": uri_for(&root_b), "name": "service-b"}
                ],
                "capabilities": {}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    fs::write(
        &beta_path,
        "class BetaRoot {\n    void betaCreatedLater() {}\n}\n",
    )
    .expect("write Beta.java");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWatchedFiles",
            "params": {
                "changes": [{"uri": beta_uri, "type": 1}]
            }
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "betaCreatedLater"}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "betaCreatedLater"),
        "expected newly created second-root symbol in {symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_watched_delete_removes_workspace_symbol() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Watch.java");
    fs::write(&file_path, "class Watch {\n    void removedLater() {}\n}\n")
        .expect("write Watch.java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": uri_for(&root), "capabilities": {}}
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "removedLater"}
        }),
    );
    let before = read_message(&mut reader, &mut stderr);
    let before_symbols = before["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {before}"));
    assert!(
        before_symbols
            .iter()
            .any(|symbol| symbol["name"] == "removedLater"),
        "expected symbol before delete in {before_symbols:#?}"
    );

    fs::remove_file(&file_path).expect("delete Watch.java");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWatchedFiles",
            "params": {
                "changes": [{"uri": file_uri, "type": 3}]
            }
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "workspace/symbol",
            "params": {"query": "removedLater"}
        }),
    );
    let after = read_message(&mut reader, &mut stderr);
    let after_symbols = after["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {after}"));
    assert!(
        !after_symbols
            .iter()
            .any(|symbol| symbol["name"] == "removedLater"),
        "deleted file symbol should be gone, got {after_symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_falls_back_to_root_uri_when_workspace_folders_null() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Fallback.java");
    fs::write(
        &file_path,
        "class FallbackRoot {\n    void fallbackOnly() {}\n}\n",
    )
    .expect("write Fallback.java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root.join("unused-fallback"))
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": uri_for(&root),
                "workspaceFolders": null,
                "capabilities": {}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": uri_for(&file_path)}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert_eq!(
        response["id"], 2,
        "expected documentSymbol response: {response}"
    );
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected document symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "FallbackRoot"),
        "expected rootUri-backed document symbol in {symbols:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_reports_cold_start_progress_when_client_supports_it() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("ProgressFixture.java");
    fs::write(
        &file_path,
        "class ProgressFixture {\n    void work() {}\n}\n",
    )
    .expect("write progress fixture");
    fs::write(
        root.join("progress_fixture.py"),
        "def work():\n    return 1\n",
    )
    .expect("write python progress fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": uri_for(&root),
                "capabilities": {"window": {"workDoneProgress": true}}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    let create = read_message(&mut reader, &mut stderr);
    assert_eq!(create["method"], "window/workDoneProgress/create");
    let token = create["params"]["token"].clone();
    assert_eq!(token, "bifrost-startup-index");
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": create["id"].clone(), "result": null}),
    );

    let begin = read_notification(&mut reader, &mut stderr, "$/progress");
    assert_eq!(begin["params"]["token"], token);
    assert_eq!(begin["params"]["value"]["kind"], "begin");
    assert_eq!(
        begin["params"]["value"]["title"], "Indexing workspace",
        "unexpected begin payload: {begin}"
    );

    let mut saw_report = false;
    let mut saw_end = false;
    let mut last_percentage = 0;
    let mut saw_java_index = false;
    let mut saw_python_after_java_index = false;
    for _ in 0..32 {
        let msg = read_notification(&mut reader, &mut stderr, "$/progress");
        assert_eq!(msg["params"]["token"], token);
        match msg["params"]["value"]["kind"].as_str() {
            Some("report") => {
                saw_report = true;
                let percentage = msg["params"]["value"]["percentage"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("startup report must include percentage: {msg}"));
                assert!(
                    percentage <= 99,
                    "startup reports should leave completion to end: {msg}"
                );
                assert!(
                    percentage >= last_percentage,
                    "startup report percentages should not move backwards: {msg}"
                );
                last_percentage = percentage;
                let message = msg["params"]["value"]["message"]
                    .as_str()
                    .unwrap_or_default();
                if message.contains("Indexed Java declarations") {
                    saw_java_index = true;
                    assert!(
                        percentage < 99,
                        "first language index must not complete multi-language startup: {msg}"
                    );
                }
                if saw_java_index && message.contains("Python") {
                    saw_python_after_java_index = true;
                }
            }
            Some("end") => {
                saw_end = true;
                break;
            }
            other => panic!("unexpected progress kind {other:?}: {msg}"),
        }
    }
    assert!(saw_report, "expected at least one progress report");
    assert!(saw_java_index, "expected Java index progress report");
    assert!(
        saw_python_after_java_index,
        "expected Python progress after Java index report"
    );
    assert!(saw_end, "expected final progress end notification");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": uri_for(&file_path)}}
        }),
    );
    let symbols = read_response_for_id(&mut reader, &mut stderr, 2);
    assert!(
        symbols["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "documentSymbol should still work after startup progress: {symbols}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 3);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_replays_did_open_sent_before_startup_progress_response() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("EarlyOpen.java");
    fs::write(&file_path, "class DiskOnly {}\n").expect("write fixture");
    let uri = uri_for(&file_path);
    let overlay_text = "class OverlayOnly {}\n";

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": uri_for(&root),
                "capabilities": {"window": {"workDoneProgress": true}}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    let create = read_message(&mut reader, &mut stderr);
    assert_eq!(create["method"], "window/workDoneProgress/create");
    let token = create["params"]["token"].clone();

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "languageId": "java",
                    "version": 1,
                    "text": overlay_text
                }
            }
        }),
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": create["id"].clone(), "result": null}),
    );

    let begin = read_notification(&mut reader, &mut stderr, "$/progress");
    assert_eq!(begin["params"]["token"], token);
    assert_eq!(begin["params"]["value"]["kind"], "begin");
    let mut saw_end = false;
    for _ in 0..32 {
        let msg = read_notification(&mut reader, &mut stderr, "$/progress");
        if msg["params"]["value"]["kind"] == "end" {
            saw_end = true;
            break;
        }
    }
    assert!(saw_end, "expected startup progress to finish");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": uri_for(&file_path)},
                "position": {"line": 0, "character": 8}
            }
        }),
    );
    let hover = read_response_for_id(&mut reader, &mut stderr, 2);
    let hover_text = hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("OverlayOnly"),
        "hover should use replayed didOpen overlay, got {hover}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 3);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_skips_startup_progress_without_client_support() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("NoProgress.java");
    fs::write(&file_path, "class NoProgress {}\n").expect("write fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": uri_for(&root),
                "capabilities": {}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": uri_for(&file_path)}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert_ne!(
        response["method"], "window/workDoneProgress/create",
        "server must not create progress when client did not advertise support"
    );
    assert_ne!(
        response["method"], "$/progress",
        "server must not emit progress when client did not advertise support"
    );
    assert_eq!(
        response["id"], 2,
        "expected documentSymbol response: {response}"
    );
    assert!(
        root.join(".bifrost").exists(),
        "server should still create the analyzer cache for clients without work-done progress (progress support is a UI capability, unrelated to persistence)"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 3);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_disables_startup_progress_when_token_create_fails() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("RejectedProgress.java");
    fs::write(&file_path, "class RejectedProgress {}\n").expect("write fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": uri_for(&root),
                "capabilities": {"window": {"workDoneProgress": true}}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    let create = read_message(&mut reader, &mut stderr);
    assert_eq!(create["method"], "window/workDoneProgress/create");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": create["id"].clone(),
            "error": {"code": -32603, "message": "token rejected"}
        }),
    );
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": uri_for(&file_path)}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert_ne!(
        response["method"], "$/progress",
        "server must not emit progress after token creation fails"
    );
    assert_eq!(
        response["id"], 2,
        "expected documentSymbol response after rejected progress token: {response}"
    );
    assert!(
        root.join(".bifrost").exists(),
        "server should still create the analyzer cache after progress token creation fails (progress reporting is independent of persistence)"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 3);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_returns_document_symbols_for_a_java() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let file_uri = uri_for(&canonical_root.join("A.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": root_uri,
                "capabilities": {}
            }
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(init["id"], 1);
    assert_eq!(
        init["result"]["capabilities"]["documentSymbolProvider"], true,
        "documentSymbolProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": file_uri}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert_eq!(response["id"], 2);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array result, got {response}"));

    let class_a = symbols
        .iter()
        .find(|sym| sym["name"] == "A")
        .unwrap_or_else(|| panic!("class A not present: {symbols:#?}"));
    assert_eq!(class_a["kind"], 5, "class kind"); // SymbolKind::CLASS = 5

    let children = class_a["children"]
        .as_array()
        .unwrap_or_else(|| panic!("class A should have children: {class_a}"));
    let child_names: Vec<&str> = children.iter().filter_map(|c| c["name"].as_str()).collect();
    for expected in ["method1", "method2", "AInner", "AInnerStatic"] {
        assert!(
            child_names.contains(&expected),
            "expected {expected} in {child_names:?}"
        );
    }

    let inner = children
        .iter()
        .find(|c| c["name"] == "AInner")
        .expect("AInner");
    let inner_children: Vec<&str> = inner["children"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|c| c["name"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        inner_children.contains(&"AInnerInner"),
        "AInner should contain AInnerInner: {inner_children:?}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_workspace_symbol_finds_method() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["workspaceSymbolProvider"], true,
        "workspaceSymbolProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "method2"}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array result, got {response}"));
    assert!(
        symbols.iter().any(|s| s["name"] == "method2"),
        "expected method2 in {symbols:#?}"
    );
    let method2 = symbols.iter().find(|s| s["name"] == "method2").unwrap();
    let location = &method2["location"];
    let uri = location["uri"].as_str().expect("location uri");
    assert!(uri.ends_with("A.java"), "expected A.java URI, got {uri}");

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_completion_finds_symbol_by_prefix() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    let completor_path = write_completor_fixture(&temp_root);

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&completor_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert!(
        init["result"]["capabilities"]["completionProvider"].is_object(),
        "completionProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 3 (0-based) is `        gree`. The cursor sits at the end of
    // `gree`, character 12 (8 spaces + 4 prefix bytes).
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 3, "character": 12}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let result = &response["result"];
    assert_eq!(
        result["isIncomplete"], false,
        "small fixture should not trigger truncation: {response}"
    );
    let items = result["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    let item = items
        .iter()
        .find(|i| i["label"] == "greetEveryone")
        .unwrap_or_else(|| panic!("greetEveryone not present in {items:#?}"));
    // CompletionItemKind::FUNCTION == 3.
    assert_eq!(item["kind"], 3, "Java method should map to FUNCTION kind");

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_completion_truncates_at_max_results_and_sets_is_incomplete() {
    // Generate a fixture with 501 method declarations that all match the
    // prefix `matchme_`. The handler must cap items at MAX_RESULTS=500 and
    // set isIncomplete=true. Builds confidence in both the truncation logic
    // and the regex-escape path (`autocomplete_definitions` interpolates the
    // query into a regex internally).
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    let mut source = String::from("public class FloodMatch {\n");
    for i in 0..501 {
        use std::fmt::Write;
        writeln!(source, "    public void matchme_{i:03}() {{}}").expect("fmt");
    }
    source.push_str("    void caller() {\n        matchme_\n    }\n}\n");
    let flood_path = temp_root.join("FloodMatch.java");
    fs::write(&flood_path, &source).expect("write FloodMatch.java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&flood_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // The `caller()` body sits on the line right after the 501 method
    // declarations: lines 0..=501 are the class header + methods, line 502 is
    // `    void caller() {`, line 503 is `        matchme_`. The cursor goes
    // at the end of `matchme_` = char position 16 (8 spaces + 8 chars).
    let cursor_line = 503;
    let cursor_char = 16;
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": cursor_line, "character": cursor_char}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let result = &response["result"];
    assert_eq!(
        result["isIncomplete"], true,
        "501 matches should set isIncomplete=true: {response}"
    );
    let items = result["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert_eq!(
        items.len(),
        500,
        "items should be capped at MAX_RESULTS=500: got {}",
        items.len()
    );
    // Spot-check a few specific labels survived truncation. Sort order is
    // analyzer-controlled (Function rank + fq_name alphabetic), so we don't
    // assert which 500 — just that they're well-formed.
    for item in items {
        let label = item["label"].as_str().expect("label string");
        assert!(
            label.starts_with("matchme_"),
            "unexpected label outside the matchme_ namespace: {label}"
        );
        assert_eq!(item["kind"], 3, "all should map to FUNCTION kind");
    }

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_completion_empty_prefix_returns_null() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    let completor_path = write_completor_fixture(&temp_root);

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&completor_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 4 (0-based) is `    }` — character 0 sits on whitespace with no
    // preceding identifier bytes on the same line. The handler must return
    // null (no completions) rather than dumping the whole symbol index.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 4, "character": 0}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert!(
        response["result"].is_null(),
        "empty prefix should produce a null result, got {response}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_goto_definition_finds_class_a_from_b() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let b_uri = uri_for(&canonical_root.join("B.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["definitionProvider"], true,
        "definitionProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 6 (0-based), char 8: cursor is on the `A` in `A a = new A();`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/definition",
            "params": {
                "textDocument": {"uri": b_uri},
                "position": {"line": 6, "character": 8}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert!(!locations.is_empty(), "no definitions found: {response}");
    let uri = locations[0]["uri"].as_str().expect("location uri");
    assert!(uri.ends_with("A.java"), "expected A.java URI, got {uri}");
    // class A's primary range starts on line 2 (0-based) — the `public class A {`
    // declaration in A.java. Asserts position conversion isn't off-by-one.
    let start_line = locations[0]["range"]["start"]["line"]
        .as_u64()
        .expect("range.start.line");
    assert_eq!(
        start_line, 2,
        "expected definition range to start on line 2 (the `public class A {{` line), got {locations:#?}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_type_definition_resolves_rust_explicit_local_type() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let lib_path = root.join("lib.rs");
    let model_path = root.join("model.rs");
    fs::write(
        &lib_path,
        "mod model;\nuse model::Widget;\n\nfn run() {\n    let value: Widget = Widget;\n    let _ = value;\n}\n",
    )
    .expect("write lib.rs");
    fs::write(&model_path, "pub struct Widget;\n").expect("write model.rs");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let lib_uri = uri_for(&lib_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/typeDefinition",
            "params": {
                "textDocument": {"uri": lib_uri},
                "position": {"line": 5, "character": 12}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected one type definition: {response}"
    );
    let uri = locations[0]["uri"].as_str().expect("location uri");
    assert!(
        uri.ends_with("model.rs"),
        "expected model.rs type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_implementation_returns_null_for_go_interface_local_value() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n").expect("write go.mod");
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package main\n\ntype Runner interface {\n    Run() error\n}\n\ntype Worker struct{}\n\nfunc (Worker) Run() error { return nil }\n\nfunc use() {\n    var runner Runner = Worker{}\n    _ = runner\n}\n",
    )
    .expect("write main.go");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/implementation",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 12, "character": 9}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert!(
        response["result"].is_null(),
        "Go local values must not resolve implementations, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_implementation_works_from_go_interface_declaration() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n").expect("write go.mod");
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package main\n\ntype Runner interface {\n    Run() error\n}\n\ntype Worker struct{}\n\nfunc (Worker) Run() error { return nil }\n",
    )
    .expect("write main.go");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/implementation",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 2, "character": 5}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected one type implementation: {response}"
    );
    assert_eq!(
        locations[0]["range"]["start"]["line"], 6,
        "expected Worker declaration from interface declaration lookup: {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_implementation_works_from_go_interface_method() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n").expect("write go.mod");
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package main\n\ntype Runner interface {\n    Run() error\n}\n\ntype Worker struct{}\n\nfunc (Worker) Run() error { return nil }\n",
    )
    .expect("write main.go");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/implementation",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 3, "character": 4}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected one method implementation: {response}"
    );
    assert_eq!(
        locations[0]["range"]["start"]["line"], 8,
        "expected Worker.Run declaration from interface method lookup: {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_go_type_or_implementation_rejects_value_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n").expect("write go.mod");
    let file_path = root.join("main.go");
    let source = "package main\n\ntype Runner interface {\n    Run() error\n}\n\ntype Worker struct {\n    Field int\n}\n\nfunc (Worker) Run() error { return nil }\n\nfunc build() Worker {\n    var local Worker\n    return local\n}\n";
    fs::write(&file_path, source).expect("write Go value-context fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let null_cases = [
        ("func b", "ordinary Go function"),
        ("func (Worker) ", "non-interface Go method"),
        ("Field", "Go struct field"),
        ("var local", "Go local variable"),
    ];
    for (idx, (needle, label)) in null_cases.iter().enumerate() {
        let (line, character) = position_after(source, needle);
        let response = implementation_response(
            &mut stdin,
            &mut reader,
            &mut stderr,
            30 + idx as u64,
            &file_uri,
            line,
            character,
        );
        assert!(
            response["result"].is_null(),
            "{label} must not resolve implementations, got {response}"
        );
    }

    for (idx, (needle, label)) in null_cases.iter().enumerate() {
        let (line, character) = position_after(source, needle);
        let result = prepare_hierarchy_result(
            &mut stdin,
            &mut reader,
            &mut stderr,
            40 + idx as u64,
            "textDocument/prepareTypeHierarchy",
            &file_uri,
            (line, character),
        );
        assert!(
            result.is_null(),
            "{label} must not prepare type hierarchy, got {result}"
        );
    }

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_implementation_filters_java_csharp_scala_value_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let fixtures = write_jvm_type_context_fixtures(&root, "ImplContexts");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);

    let java_uri = uri_for(&fixtures.java_path);
    let (line, character) = position_after(fixtures.java_source, "    W");
    let response = implementation_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        10,
        &java_uri,
        line,
        character,
    );
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected Java type reference implementations, got {response}"));
    assert!(
        locations
            .iter()
            .any(|location| location["range"]["start"]["line"] == 1),
        "expected Java Child implementation from return type, got {response}"
    );
    assert_implementation_null_cases(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        &java_uri,
        fixtures.java_source,
        &[
            ("    Widget b", "Java method names"),
            ("        Widget l", "Java locals"),
        ],
    );

    let csharp_uri = uri_for(&fixtures.csharp_path);
    assert_implementation_null_cases(
        &mut stdin,
        &mut reader,
        &mut stderr,
        13,
        &csharp_uri,
        fixtures.csharp_source,
        &[(" Widget B", "C# method names"), (" Widget l", "C# locals")],
    );

    let scala_uri = uri_for(&fixtures.scala_path);
    let (line, character) = position_after(fixtures.scala_source, ": W");
    let response = implementation_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        15,
        &scala_uri,
        line,
        character,
    );
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected Scala type reference implementations, got {response}"));
    assert!(
        locations
            .iter()
            .any(|location| location["range"]["start"]["line"] == 1),
        "expected Scala Child implementation from return type, got {response}"
    );
    assert_implementation_null_cases(
        &mut stdin,
        &mut reader,
        &mut stderr,
        16,
        &scala_uri,
        fixtures.scala_source,
        &[("def b", "Scala function names"), ("val l", "Scala locals")],
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_implementation_works_from_typescript_type_reference() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");

    let ts_path = root.join("ImplTypeRefs.ts");
    let ts_source =
        "interface Base {}\nclass Child implements Base {}\nlet typed: Base | null = null;\n";
    fs::write(&ts_path, ts_source).expect("write TypeScript implementation type-ref fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);

    let ts_uri = uri_for(&ts_path);
    let (line, character) = position_after(ts_source, "typed: ");
    let response = implementation_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        20,
        &ts_uri,
        line,
        character,
    );
    let locations = response["result"].as_array().unwrap_or_else(|| {
        panic!("expected TypeScript type-reference implementations, got {response}")
    });
    assert!(
        locations
            .iter()
            .any(|location| location["range"]["start"]["line"] == 1),
        "expected TypeScript Child implementation from Base annotation, got {response}"
    );

    let (line, character) = position_after(ts_source, "let t");
    let response = implementation_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        21,
        &ts_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "TypeScript local declaration names must not resolve implementations, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_java_method_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Calculator.java");
    let source = "class Calculator {\n    /**\n     * Adds two values.\n     */\n    int sum(int sum, int right) { return sum + right; }\n    void caller() {\n        int value = sum(1, 2);\n    }\n}\n";
    fs::write(&file_path, source).expect("write Calculator.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "sum(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeSignature"], 0,
        "unexpected signature help: {result}"
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("sum") && label.contains("right")),
        "expected sum signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["sum", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Adds two values.")),
        "expected Java signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_typescript_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("sample.ts");
    let source = "/**\n * Combines two values.\n */\nfunction combine(combine: number, right: number): number {\n  return combine + right;\n}\nconst result = combine(1, 2);\n";
    fs::write(&file_path, source).expect("write sample.ts");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines two values.")),
        "expected TypeScript signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_javascript_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("sample.js");
    let source = "/**\n * Combines JavaScript values.\n */\nfunction combine(combine, right) {\n  return combine + right;\n}\nconst result = combine(1, 2);\n";
    fs::write(&file_path, source).expect("write sample.js");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines JavaScript values.")),
        "expected JavaScript signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_javascript_default_and_rest_parameter_offsets() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("defaults.js");
    let source = "function factory() { return 0; }\n/**\n * Configures JavaScript values.\n */\nfunction configure(left = factory(), right, ...rest) {\n  return right;\n}\nconst result = configure(1, 2, 3);\n";
    fs::write(&file_path, source).expect("write defaults.js");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "configure(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["left", "right", "rest"]);

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_javascript_single_arrow_parameter_offsets() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("arrow.js");
    let source = "const identity = value => value;\nconst result = identity(1);\n";
    fs::write(&file_path, source).expect("write arrow.js");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "identity(");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["value"]);

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_typescript_constructor_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("widget.ts");
    let source = "class Widget {\n  constructor(left: number, right: number) {}\n}\nconst result = new Widget(1, 2);\n";
    fs::write(&file_path, source).expect("write widget.ts");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "Widget(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("Widget") && label.contains("constructor")),
        "expected Widget constructor signature label, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_go_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/signature\n").expect("write go.mod");
    let file_path = root.join("main.go");
    let source = "package main\n\n// combine combines Go values.\nfunc combine(combine func() int, right int, rest ...int) int { return combine() + right + len(rest) }\n\nfunc main() {\n    _ = combine(nil, 2, 3)\n}\n";
    fs::write(&file_path, source).expect("write main.go");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(nil, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right", "rest"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("combine combines Go values.")),
        "expected Go signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_csharp_method_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Calculator.cs");
    let source = "using System;\nclass Calculator {\n    /// <summary>Combines C# values.</summary>\n    int Combine(int Combine, Func<int> factory, int right = 0) { return Combine + factory() + right; }\n    void Caller() {\n        var value = Combine(1, () => 2, 3);\n    }\n}\n";
    fs::write(&file_path, source).expect("write Calculator.cs");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "Combine(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("Combine") && label.contains("right")),
        "expected Combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["Combine", "factory", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines C# values.")),
        "expected C# signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_cpp_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.cpp");
    let source = "/* Combines C++ values. */\nint combine(int combine, int (*factory)(), int* right) { return combine + factory() + *right; }\nint main() {\n    int value = 2;\n    return combine(1, nullptr, &value);\n}\n";
    fs::write(&file_path, source).expect("write calculator.cpp");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "factory", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines C++ values.")),
        "expected C++ signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_python_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.py");
    let source = "# Combines Python values.\ndef combine(combine: int, right: int = helper(1, 2), *rest: int) -> int:\n    return combine + right\n\nvalue = combine(1, 2, 3)\n";
    fs::write(&file_path, source).expect("write calculator.py");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right", "rest"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines Python values.")),
        "expected Python signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_ruby_method_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.rb");
    let source = "class Calculator\n  # Combines Ruby values.\n  def combine(combine, right = helper(1, 2), *rest)\n    combine + right\n  end\n\n  def caller\n    combine(1, 2, 3)\n  end\nend\n";
    fs::write(&file_path, source).expect("write calculator.rb");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected Ruby combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right", "rest"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines Ruby values.")),
        "expected Ruby signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_rust_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.rs");
    let source = "/// Combines Rust values.\nfn combine(combine: i32, right: Option<Result<i32, i32>>) -> i32 {\n    combine + right.unwrap().unwrap()\n}\n\nfn main() {\n    let _ = combine(1, None);\n}\n";
    fs::write(&file_path, source).expect("write calculator.rs");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines Rust values.")),
        "expected Rust signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_php_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.php");
    let source = "<?php\n/** Combines PHP values. */\nfunction combine($combine, callable $factory, int $right = helper(1, 2)) {\n    return $combine + $factory() + $right;\n}\n\n$result = combine(1, fn() => 2, 3);\n";
    fs::write(&file_path, source).expect("write calculator.php");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["$combine", "$factory", "$right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines PHP values.")),
        "expected PHP signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_scala_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "object App {\n  /** Combines Scala values. */\n  def target(target: Int, right: Either[Int, Int] = Left(1)): Int = target + right.fold(identity, identity)\n  val result = target(1, Right(2))\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "target(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("target") && label.contains("right")),
        "expected target signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["target", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines Scala values.")),
        "expected Scala signature documentation, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_handles_scala_brace_argument() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source =
        "object App {\n  def target(value: Int): Int = value\n  val result = target { 1 }\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "target { ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("target") && label.contains("value")),
        "expected target signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["value"]);

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_handles_scala_infix_call() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "object App {\n  class Box {\n    def combine(value: Int): Int = value\n  }\n  val box = new Box\n  val result = box combine 1\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "box combine ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("value")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["value"]);

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_handles_scala_postfix_call() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "object App {\n  class Box {\n    def ready: Boolean = true\n  }\n  val box = new Box\n  val result = box ready\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "box ready");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("ready") && label.contains("Boolean")),
        "expected ready signature label, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_handles_scala_postfix_operator_call() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "object App {\n  class Box {\n    def ! : Boolean = true\n  }\n  val box = new Box\n  val result = box !\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "box !");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("!") && label.contains("Boolean")),
        "expected operator signature label, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_null_outside_call_arguments() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Calculator.java");
    let source = "class Calculator {\n    int sum(int left, int right) { return left + right; }\n    void caller() {\n        int value = 1;\n    }\n}\n";
    fs::write(&file_path, source).expect("write Calculator.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "int value");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/signatureHelp",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character}
            }
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 2);
    assert!(
        response["result"].is_null(),
        "expected null signatureHelp, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_signature_help_uses_did_open_overlay_call_context() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Overlay.java");
    let disk_source = "class Overlay {\n    int target(int left, int right) { return left + right; }\n    void caller() {\n        int value = target(1);\n    }\n}\n";
    let overlay_source = "class Overlay {\n    int target(int left, int right) { return left + right; }\n    void caller() {\n        int value = target(1, 2);\n    }\n}\n";
    fs::write(&file_path, disk_source).expect("write Overlay.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "java",
                    "version": 1,
                    "text": overlay_source
                }
            }
        }),
    );
    let (line, character) = position_after(overlay_source, "target(1, ");

    let result = signature_help(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        result["activeParameter"], 1,
        "signatureHelp should use overlay call text, got {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_unresolved_type() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("plain.js");
    fs::write(
        &file_path,
        "function run() {\n    const value = makeValue();\n    value;\n}\n",
    )
    .expect("write plain.js");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/typeDefinition",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 2, "character": 4}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert!(
        response["result"].is_null(),
        "unresolved type definition should return null, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_typescript_function_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("app.ts");
    let source = "interface Widget {}\nfunction build(): Widget { return {} as Widget; }\nconst value = build();\n";
    fs::write(&file_path, source).expect("write app.ts");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "function ");

    let response = type_definition_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "function declaration name should not resolve a type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_typescript_method_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("app.ts");
    let source =
        "interface Widget {}\nclass Service {\n  build(): Widget { return {} as Widget; }\n}\n";
    fs::write(&file_path, source).expect("write app.ts");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "  ");

    let response = type_definition_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "method declaration name should not resolve a type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_javascript_callable_symbol() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("plain.js");
    let source = "function build() { return {}; }\nconst value = build();\n";
    fs::write(&file_path, source).expect("write plain.js");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "function ");

    let response = type_definition_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "JavaScript callable symbol should return null for type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_java_method_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Service.java");
    let source =
        "class Widget {}\nclass Service {\n    Widget build() { return new Widget(); }\n}\n";
    fs::write(&file_path, source).expect("write Service.java");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "    Widget ");

    let response = type_definition_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "Java method declaration name should not resolve a type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_csharp_method_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Service.cs");
    let source =
        "class Widget {}\nclass Service {\n    Widget Build() { return new Widget(); }\n}\n";
    fs::write(&file_path, source).expect("write Service.cs");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "    Widget ");

    let response = type_definition_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "C# method declaration name should not resolve a type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_rust_function_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let source = "struct Widget;\nfn build() -> Widget { Widget }\nfn run() { let _ = build(); }\n";
    fs::write(&file_path, source).expect("write lib.rs");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "fn ");

    let response = type_definition_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "Rust function declaration name should not resolve a type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_go_function_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/typectx\n").expect("write go.mod");
    let file_path = root.join("main.go");
    let source =
        "package main\n\ntype Widget struct{}\n\nfunc build() Widget { return Widget{} }\n";
    fs::write(&file_path, source).expect("write main.go");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "func ");

    let response = type_definition_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "Go function declaration name should not resolve a type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_scala_function_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "class Widget\nobject App {\n  def build(): Widget = new Widget\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "def ");

    let response = type_definition_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        2,
        &file_uri,
        line,
        character,
    );
    assert!(
        response["result"].is_null(),
        "Scala function declaration name should not resolve a type definition, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_definition_uses_did_open_overlay() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let app_path = root.join("app.ts");
    let model_path = root.join("model.ts");
    fs::write(&model_path, "export interface Widget {}\n").expect("write model.ts");
    fs::write(
        &app_path,
        "import { Widget } from './model';\nlet value = null;\nvalue;\n",
    )
    .expect("write app.ts");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let app_uri = uri_for(&app_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": app_uri,
                    "languageId": "typescript",
                    "version": 1,
                    "text": "import { Widget } from './model';\nlet value: Widget = null as any;\nvalue;\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/typeDefinition",
            "params": {
                "textDocument": {"uri": app_uri},
                "position": {"line": 2, "character": 0}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected overlay type annotation to resolve: {response}"
    );
    let uri = locations[0]["uri"].as_str().expect("location uri");
    assert!(
        uri.ends_with("model.ts"),
        "expected Widget definition from model.ts, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_hover_returns_signature_for_class_a() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let b_uri = uri_for(&canonical_root.join("B.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["hoverProvider"], true,
        "hoverProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": b_uri},
                "position": {"line": 6, "character": 8}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.contains("class A"),
        "hover should mention class A, got: {value}"
    );
    assert!(
        value.starts_with("```java"),
        "hover should be fenced as java, got: {value}"
    );
    // Hover range should cover the `A` identifier under the cursor: line 6,
    // chars 8-9. A bug in identifier_span_at_offset or position_to_byte_offset
    // would produce something else here.
    let range = &response["result"]["range"];
    assert_eq!(range["start"]["line"], 6, "hover range start line");
    assert_eq!(range["start"]["character"], 8, "hover range start char");
    assert_eq!(range["end"]["line"], 6, "hover range end line");
    assert_eq!(range["end"]["character"], 9, "hover range end char");

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_references_finds_class_a_usages() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let a_uri = uri_for(&canonical_root.join("A.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["referencesProvider"], true,
        "referencesProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // A.java line 3, col 13: cursor on the `A` in `public class A {`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/references",
            "params": {
                "textDocument": {"uri": a_uri},
                "position": {"line": 2, "character": 13},
                "context": {"includeDeclaration": false}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array, got {response}"));
    let uris: Vec<&str> = locations.iter().filter_map(|l| l["uri"].as_str()).collect();
    assert!(
        uris.iter().any(|u| u.ends_with("B.java")),
        "expected at least one reference in B.java, got: {uris:?}"
    );
    // B.java line 7 (0-based: 6) is `        A a = new A();`. The two `A`
    // tokens land at chars 8 and 18. Either should appear in the hits.
    let in_b: Vec<&serde_json::Value> = locations
        .iter()
        .filter(|l| {
            l["uri"]
                .as_str()
                .map(|u| u.ends_with("B.java"))
                .unwrap_or(false)
        })
        .collect();
    assert!(!in_b.is_empty(), "no B.java hits: {locations:#?}");
    let on_line_6: Vec<&&serde_json::Value> = in_b
        .iter()
        .filter(|l| l["range"]["start"]["line"] == 6)
        .collect();
    assert!(
        !on_line_6.is_empty(),
        "expected at least one B.java hit on line 6, got: {in_b:#?}"
    );
    let chars: Vec<u64> = on_line_6
        .iter()
        .filter_map(|l| l["range"]["start"]["character"].as_u64())
        .collect();
    assert!(
        chars.iter().any(|c| *c == 8 || *c == 18),
        "expected a hit at char 8 or 18 on B.java line 6, got chars {chars:?}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

const COMMENT_TARGETS_SOURCE: &str = "class CommentTargets {\n    // target\n    void target() {}\n    void caller() {\n        target();\n    }\n}\n";

const SHIFTED_COMMENT_TARGETS_SOURCE: &str = "// unsaved header\nclass CommentTargets {\n    // target\n    void target() {}\n    void caller() {\n        target();\n    }\n}\n";

const INVALID_CONTEXTS_SOURCE: &str = "import a.*;\nimport b.*;\nclass InvalidContexts {\n    String literal = \"Shared\";\n    void caller() {\n        Shared ambiguous = null;\n        int value = MissingShared;\n        if (true) {}\n    }\n}\n";

const CSHARP_AMBIGUOUS_USING_SOURCE: &str = "using Alpha;\nusing Beta;\nnamespace App {\n    public class Consumer {\n        public void Execute() {\n            Target target = null;\n        }\n    }\n}\n";

const SCALA_AMBIGUOUS_IMPORT_SOURCE: &str = "package app\nimport alpha.*\nimport beta.*\nclass Consumer {\n  val target: Target = null\n}\n";

const DUPLICATE_DECLARATION_NAME_SOURCE: &str =
    "class Widget {\n    Widget Widget() {\n        return this;\n    }\n}\n";

fn write_comment_targets_fixture(root: &Path) -> PathBuf {
    let file_path = root.join("CommentTargets.java");
    fs::write(&file_path, COMMENT_TARGETS_SOURCE).expect("write CommentTargets.java");
    file_path
}

fn write_duplicate_declaration_name_fixture(root: &Path) -> PathBuf {
    let file_path = root.join("Widget.java");
    fs::write(&file_path, DUPLICATE_DECLARATION_NAME_SOURCE).expect("write Widget.java");
    file_path
}

fn write_invalid_contexts_fixture(root: &Path) -> PathBuf {
    let package_a = root.join("a");
    let package_b = root.join("b");
    fs::create_dir_all(&package_a).expect("create package a");
    fs::create_dir_all(&package_b).expect("create package b");
    fs::write(
        package_a.join("Shared.java"),
        "package a;\npublic class Shared {}\n",
    )
    .expect("write a.Shared");
    fs::write(
        package_b.join("Shared.java"),
        "package b;\npublic class Shared {}\n",
    )
    .expect("write b.Shared");
    let file_path = root.join("InvalidContexts.java");
    fs::write(&file_path, INVALID_CONTEXTS_SOURCE).expect("write InvalidContexts.java");
    file_path
}

fn write_csharp_ambiguous_using_fixture(root: &Path) -> PathBuf {
    let alpha = root.join("Alpha");
    let beta = root.join("Beta");
    let app = root.join("App");
    fs::create_dir_all(&alpha).expect("create Alpha namespace");
    fs::create_dir_all(&beta).expect("create Beta namespace");
    fs::create_dir_all(&app).expect("create App namespace");
    fs::write(
        alpha.join("Target.cs"),
        "namespace Alpha { public class Target {} }\n",
    )
    .expect("write Alpha.Target");
    fs::write(
        beta.join("Target.cs"),
        "namespace Beta { public class Target {} }\n",
    )
    .expect("write Beta.Target");
    let file_path = app.join("Consumer.cs");
    fs::write(&file_path, CSHARP_AMBIGUOUS_USING_SOURCE).expect("write Consumer.cs");
    file_path
}

fn write_scala_ambiguous_import_fixture(root: &Path) -> PathBuf {
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    let app = root.join("app");
    fs::create_dir_all(&alpha).expect("create alpha package");
    fs::create_dir_all(&beta).expect("create beta package");
    fs::create_dir_all(&app).expect("create app package");
    fs::write(alpha.join("Target.scala"), "package alpha\nclass Target\n")
        .expect("write alpha.Target");
    fs::write(beta.join("Target.scala"), "package beta\nclass Target\n")
        .expect("write beta.Target");
    let file_path = app.join("Consumer.scala");
    fs::write(&file_path, SCALA_AMBIGUOUS_IMPORT_SOURCE).expect("write Consumer.scala");
    file_path
}

#[test]
fn bifrost_lsp_server_definition_ignores_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let (valid_line, valid_character) = position_after(COMMENT_TARGETS_SOURCE, "void ");
    let valid_definition = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        10,
        "textDocument/definition",
        &file_uri,
        valid_line,
        valid_character,
    );

    let (comment_line, comment_character) = position_after(COMMENT_TARGETS_SOURCE, "    // ");
    let comment_definition = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        "textDocument/definition",
        &file_uri,
        comment_line,
        comment_character,
    );

    shutdown_lsp(child, stdin, reader, stderr);

    assert!(
        valid_definition["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "valid declaration should resolve definition, got {valid_definition}"
    );
    assert!(
        comment_definition["result"].is_null(),
        "comment token must not resolve definition, got {comment_definition}"
    );
}

#[test]
fn bifrost_lsp_server_hover_ignores_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let (valid_line, valid_character) = position_after(COMMENT_TARGETS_SOURCE, "void ");
    let valid_hover = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        10,
        "textDocument/hover",
        &file_uri,
        valid_line,
        valid_character,
    );

    let (comment_line, comment_character) = position_after(COMMENT_TARGETS_SOURCE, "    // ");
    let comment_hover = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        "textDocument/hover",
        &file_uri,
        comment_line,
        comment_character,
    );

    shutdown_lsp(child, stdin, reader, stderr);

    assert!(
        valid_hover["result"]["contents"]["value"]
            .as_str()
            .is_some_and(|value| value.contains("target")),
        "valid declaration should produce hover, got {valid_hover}"
    );
    assert!(
        comment_hover["result"].is_null(),
        "comment token must not produce hover, got {comment_hover}"
    );
}

#[test]
fn bifrost_lsp_server_definition_and_hover_select_duplicate_declaration_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_duplicate_declaration_name_fixture(&root);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(DUPLICATE_DECLARATION_NAME_SOURCE, "    Widget ");
    let definition = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        10,
        "textDocument/definition",
        &file_uri,
        line,
        character,
    );
    let hover = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        "textDocument/hover",
        &file_uri,
        line,
        character,
    );

    shutdown_lsp(child, stdin, reader, stderr);

    let definition_items = definition["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected definition locations, got {definition}"));
    assert_eq!(
        definition_items.len(),
        1,
        "method declaration should resolve itself, got {definition}"
    );
    assert_eq!(
        definition_items[0]["range"]["start"]["line"], 1,
        "definition should target the method declaration, got {definition}"
    );
    let hover_value = hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected hover contents, got {hover}"));
    assert!(
        hover_value.contains("Widget Widget()"),
        "hover should describe the method declaration, got {hover_value}"
    );
    assert_eq!(
        hover["result"]["range"]["start"]["character"], 11,
        "hover should highlight the method name under the cursor, not the return type: {hover}"
    );
}

#[test]
fn bifrost_lsp_server_references_ignore_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let (valid_line, valid_character) = position_after(COMMENT_TARGETS_SOURCE, "void ");
    let valid_references = references_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        10,
        &file_uri,
        valid_line,
        valid_character,
        true,
    );

    let (comment_line, comment_character) = position_after(COMMENT_TARGETS_SOURCE, "    // ");
    let comment_references = references_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        &file_uri,
        comment_line,
        comment_character,
        true,
    );

    shutdown_lsp(child, stdin, reader, stderr);

    assert!(
        valid_references["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "valid declaration should find references, got {valid_references}"
    );
    assert!(
        comment_references["result"].is_null()
            || comment_references["result"]
                .as_array()
                .is_some_and(|items| items.is_empty()),
        "comment token must not find references, got {comment_references}"
    );
}

#[test]
fn bifrost_lsp_server_document_highlight_ignores_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let (valid_line, valid_character) = position_after(COMMENT_TARGETS_SOURCE, "void ");
    let valid_highlights = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        10,
        "textDocument/documentHighlight",
        &file_uri,
        valid_line,
        valid_character,
    );

    let (comment_line, comment_character) = position_after(COMMENT_TARGETS_SOURCE, "    // ");
    let comment_highlights = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        "textDocument/documentHighlight",
        &file_uri,
        comment_line,
        comment_character,
    );

    shutdown_lsp(child, stdin, reader, stderr);

    assert!(
        valid_highlights["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "valid declaration should produce highlights, got {valid_highlights}"
    );
    assert!(
        comment_highlights["result"].is_null()
            || comment_highlights["result"]
                .as_array()
                .is_some_and(|items| items.is_empty()),
        "comment token must not produce highlights, got {comment_highlights}"
    );
}

#[test]
fn bifrost_lsp_server_references_and_document_highlight_use_shifted_overlay_declaration() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "java",
                    "version": 1,
                    "text": SHIFTED_COMMENT_TARGETS_SOURCE
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    let (line, character) = position_after(SHIFTED_COMMENT_TARGETS_SOURCE, "void ");
    let references = references_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        10,
        &file_uri,
        line,
        character,
        true,
    );
    let highlights = text_document_position_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        "textDocument/documentHighlight",
        &file_uri,
        line,
        character,
    );

    shutdown_lsp(child, stdin, reader, stderr);

    assert!(
        references["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "shifted overlay declaration should find references, got {references}"
    );
    assert!(
        highlights["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "shifted overlay declaration should produce highlights, got {highlights}"
    );
    assert!(
        highlights["result"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["range"]["start"]["line"] == line
                    && item["range"]["start"]["character"] == character
            })
        }),
        "shifted overlay declaration should highlight the overlaid declaration name, got {highlights}"
    );
}

#[test]
fn bifrost_lsp_server_definition_ignores_literals_keywords_unresolved_and_ambiguous_tokens() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_invalid_contexts_fixture(&root);

    let (child, stdin, reader, stderr) = start_lsp_server(&root);
    let mut client = LspTestClient::new(stdin, reader, stderr, 10);
    let file_uri = uri_for(&file_path);
    let responses = collect_invalid_context_endpoint_responses(
        &mut client,
        &file_uri,
        BroadEndpoint::Definition,
    );

    let (stdin, reader, stderr) = client.into_parts();
    shutdown_lsp(child, stdin, reader, stderr);

    assert_no_invalid_context_results(BroadEndpoint::Definition, &responses);
}

#[test]
fn bifrost_lsp_server_hover_ignores_literals_keywords_unresolved_and_ambiguous_tokens() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_invalid_contexts_fixture(&root);

    let (child, stdin, reader, stderr) = start_lsp_server(&root);
    let mut client = LspTestClient::new(stdin, reader, stderr, 10);
    let file_uri = uri_for(&file_path);
    let responses =
        collect_invalid_context_endpoint_responses(&mut client, &file_uri, BroadEndpoint::Hover);

    let (stdin, reader, stderr) = client.into_parts();
    shutdown_lsp(child, stdin, reader, stderr);

    assert_no_invalid_context_results(BroadEndpoint::Hover, &responses);
}

#[test]
fn bifrost_lsp_server_references_ignore_literals_keywords_unresolved_and_ambiguous_tokens() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_invalid_contexts_fixture(&root);

    let (child, stdin, reader, stderr) = start_lsp_server(&root);
    let mut client = LspTestClient::new(stdin, reader, stderr, 10);
    let file_uri = uri_for(&file_path);
    let responses = collect_invalid_context_endpoint_responses(
        &mut client,
        &file_uri,
        BroadEndpoint::References,
    );

    let (stdin, reader, stderr) = client.into_parts();
    shutdown_lsp(child, stdin, reader, stderr);

    assert_no_invalid_context_results(BroadEndpoint::References, &responses);
}

#[test]
fn bifrost_lsp_server_document_highlight_ignores_literals_keywords_unresolved_and_ambiguous_tokens()
{
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_invalid_contexts_fixture(&root);

    let (child, stdin, reader, stderr) = start_lsp_server(&root);
    let mut client = LspTestClient::new(stdin, reader, stderr, 10);
    let file_uri = uri_for(&file_path);
    let responses = collect_invalid_context_endpoint_responses(
        &mut client,
        &file_uri,
        BroadEndpoint::DocumentHighlight,
    );

    let (stdin, reader, stderr) = client.into_parts();
    shutdown_lsp(child, stdin, reader, stderr);

    assert_no_invalid_context_results(BroadEndpoint::DocumentHighlight, &responses);
}

#[test]
fn bifrost_lsp_server_broad_endpoints_ignore_csharp_ambiguous_using_type() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_csharp_ambiguous_using_fixture(&root);

    let (child, stdin, reader, stderr) = start_lsp_server(&root);
    let mut client = LspTestClient::new(stdin, reader, stderr, 10);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(CSHARP_AMBIGUOUS_USING_SOURCE, "            ");
    let responses = [
        BroadEndpoint::Definition,
        BroadEndpoint::Hover,
        BroadEndpoint::References,
        BroadEndpoint::DocumentHighlight,
    ]
    .into_iter()
    .map(|endpoint| {
        (
            endpoint.label(),
            endpoint_response(&mut client, &file_uri, endpoint, line, character),
        )
    })
    .collect::<Vec<_>>();

    let (stdin, reader, stderr) = client.into_parts();
    shutdown_lsp(child, stdin, reader, stderr);

    for (endpoint, response) in responses {
        let no_result = response["result"].is_null()
            || response["result"]
                .as_array()
                .is_some_and(|items| items.is_empty());
        assert!(
            no_result,
            "C# ambiguous using type must not produce {endpoint} result, got {response}"
        );
    }
}

#[test]
fn bifrost_lsp_server_broad_endpoints_ignore_scala_ambiguous_wildcard_import_type() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_scala_ambiguous_import_fixture(&root);

    let (child, stdin, reader, stderr) = start_lsp_server(&root);
    let mut client = LspTestClient::new(stdin, reader, stderr, 10);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(SCALA_AMBIGUOUS_IMPORT_SOURCE, "  val target: ");
    let responses = [
        BroadEndpoint::Definition,
        BroadEndpoint::Hover,
        BroadEndpoint::References,
        BroadEndpoint::DocumentHighlight,
    ]
    .into_iter()
    .map(|endpoint| {
        (
            endpoint.label(),
            endpoint_response(&mut client, &file_uri, endpoint, line, character),
        )
    })
    .collect::<Vec<_>>();

    let (stdin, reader, stderr) = client.into_parts();
    shutdown_lsp(child, stdin, reader, stderr);

    for (endpoint, response) in responses {
        let no_result = response["result"].is_null()
            || response["result"]
                .as_array()
                .is_some_and(|items| items.is_empty());
        assert!(
            no_result,
            "Scala ambiguous wildcard import type must not produce {endpoint} result, got {response}"
        );
    }
}

#[test]
fn bifrost_lsp_server_prepare_rename_returns_identifier_range() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let a_uri = uri_for(&canonical_root.join("A.java"));

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&fixture_root);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "textDocument/prepareRename",
            "params": {
                "textDocument": {"uri": a_uri},
                "position": {"line": 7, "character": 18}
            }
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 10);
    let result = &response["result"];
    assert_eq!(
        result["placeholder"], "method2",
        "prepare result: {response}"
    );
    assert_eq!(
        result["range"]["start"]["line"], 7,
        "prepare range: {response}"
    );
    assert_eq!(
        result["range"]["start"]["character"], 18,
        "prepare range: {response}"
    );
    assert_eq!(
        result["range"]["end"]["line"], 7,
        "prepare range: {response}"
    );
    assert_eq!(
        result["range"]["end"]["character"], 25,
        "prepare range: {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_rename_returns_workspace_edit_for_java_method() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let a_path = canonical_root.join("A.java");
    let a_uri = uri_for(&a_path);
    let b_uri = uri_for(&canonical_root.join("B.java"));
    let before_a = fs::read_to_string(&a_path).expect("read A.java before rename");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&fixture_root);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "textDocument/rename",
            "params": {
                "textDocument": {"uri": a_uri},
                "position": {"line": 7, "character": 18},
                "newName": "renamedMethod2"
            }
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 11);
    let changes = response["result"]["changes"]
        .as_object()
        .unwrap_or_else(|| panic!("expected WorkspaceEdit.changes, got {response}"));
    let a_edits = changes
        .get(&a_uri)
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("expected A.java edits in {response}"));
    let b_edits = changes
        .get(&b_uri)
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("expected B.java edits in {response}"));

    assert!(
        a_edits.iter().any(|edit| {
            edit["newText"] == "renamedMethod2"
                && edit["range"]["start"]["line"] == 7
                && edit["range"]["start"]["character"] == 18
                && edit["range"]["end"]["character"] == 25
        }),
        "expected declaration edit in A.java: {a_edits:#?}"
    );
    assert!(
        b_edits.iter().any(|edit| {
            edit["newText"] == "renamedMethod2"
                && edit["range"]["start"]["line"] == 8
                && edit["range"]["start"]["character"] == 26
        }),
        "expected usage edit in B.java: {b_edits:#?}"
    );
    assert_eq!(
        fs::read_to_string(&a_path).expect("read A.java after rename request"),
        before_a,
        "rename request must return edits without mutating files"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_rename_rejects_file_coupled_java_class_without_file_edit() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let a_uri = uri_for(&canonical_root.join("A.java"));

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&fixture_root);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "textDocument/prepareRename",
            "params": {
                "textDocument": {"uri": a_uri},
                "position": {"line": 2, "character": 13}
            }
        }),
    );
    let prepare = read_response_for_id(&mut reader, &mut stderr, 14);
    assert!(
        prepare["result"].is_null(),
        "file-coupled Java class rename should not prepare without file operation support: {prepare}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_rename_returns_null_for_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("CommentRename.java");
    fs::write(
        &file_path,
        "class CommentRename {\n    // target\n    void target() {}\n}\n",
    )
    .expect("write fixture");
    let file_uri = uri_for(&file_path);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 15,
            "method": "textDocument/rename",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 1, "character": 7},
                "newName": "renamedTarget"
            }
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 15);
    assert!(
        response["result"].is_null(),
        "comment token must not rename the real method with the same text: {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_rename_keeps_same_short_name_symbols_separate() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let p_service = root.join("p").join("Service.java");
    let p_caller = root.join("p").join("Caller.java");
    let q_service = root.join("q").join("Service.java");
    let q_caller = root.join("q").join("Caller.java");
    fs::create_dir_all(root.join("p")).expect("create p");
    fs::create_dir_all(root.join("q")).expect("create q");
    fs::write(
        &p_service,
        "package p;\npublic class Service {\n    void target() {}\n}\n",
    )
    .expect("write p service");
    fs::write(
        &p_caller,
        "package p;\nclass Caller {\n    void call(Service service) {\n        service.target();\n    }\n}\n",
    )
    .expect("write p caller");
    fs::write(
        &q_service,
        "package q;\npublic class Service {\n    void target() {}\n}\n",
    )
    .expect("write q service");
    fs::write(
        &q_caller,
        "package q;\nclass Caller {\n    void call(Service service) {\n        service.target();\n    }\n}\n",
    )
    .expect("write q caller");

    let p_service_uri = uri_for(&p_service);
    let p_caller_uri = uri_for(&p_caller);
    let q_service_uri = uri_for(&q_service);
    let q_caller_uri = uri_for(&q_caller);
    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 16,
            "method": "textDocument/rename",
            "params": {
                "textDocument": {"uri": p_service_uri},
                "position": {"line": 2, "character": 9},
                "newName": "renamedTarget"
            }
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 16);
    let changes = response["result"]["changes"]
        .as_object()
        .unwrap_or_else(|| panic!("expected WorkspaceEdit.changes, got {response}"));
    assert!(
        changes.contains_key(&p_service_uri),
        "expected selected declaration file edit: {response}"
    );
    assert!(
        changes.contains_key(&p_caller_uri),
        "expected selected package usage edit: {response}"
    );
    assert!(
        !changes.contains_key(&q_service_uri) && !changes.contains_key(&q_caller_uri),
        "rename must not edit same-short-name symbols in another package: {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_rename_uses_open_document_overlay() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("OverlayRename.java");
    fs::write(&file_path, "class DiskOnly {\n    void diskOnly() {}\n}\n")
        .expect("write disk fixture");
    let file_uri = uri_for(&file_path);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "java",
                    "version": 1,
                    "text": "class LiveName {\n    LiveName make() { return new LiveName(); }\n}\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "textDocument/rename",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 6},
                "newName": "RenamedLive"
            }
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 12);
    let changes = response["result"]["changes"]
        .as_object()
        .unwrap_or_else(|| panic!("expected WorkspaceEdit.changes, got {response}"));
    let edits = changes
        .get(&file_uri)
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("expected overlay file edits in {response}"));
    assert!(
        edits.iter().any(|edit| edit["newText"] == "RenamedLive"
            && edit["range"]["start"]["line"] == 0
            && edit["range"]["start"]["character"] == 6),
        "expected declaration edit from overlay text: {edits:#?}"
    );
    assert!(
        !fs::read_to_string(&file_path)
            .expect("read disk fixture")
            .contains("LiveName"),
        "overlay-only symbol must not be read from disk"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_rename_returns_null_for_unresolved_position() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Whitespace.java");
    fs::write(&file_path, "class Whitespace {}\n").expect("write fixture");
    let file_uri = uri_for(&file_path);

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "textDocument/rename",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5},
                "newName": "RenamedWhitespace"
            }
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 13);
    assert!(
        response["result"].is_null(),
        "unresolved rename should return null: {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_finds_java_incoming_and_outgoing_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Calls.java");
    fs::write(
        &file_path,
        "class Service {\n    static void target() {}\n}\nclass Caller {\n    void helper() {\n        Service.target();\n    }\n}\n",
    )
    .expect("write Java call hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let target = prepare_call_hierarchy(&mut stdin, &mut reader, &mut stderr, 10, &file_uri, 1, 16);
    assert_eq!(target["name"], "target", "prepared target: {target}");

    let incoming = call_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        "callHierarchy/incomingCalls",
        target.clone(),
    );
    assert_eq!(incoming.len(), 1, "incoming calls: {incoming:#?}");
    assert_eq!(
        incoming[0]["from"]["name"], "helper",
        "incoming caller should be helper: {incoming:#?}"
    );
    assert_call_range(&incoming[0]["fromRanges"], 5, 16, 22);

    let helper = prepare_call_hierarchy(&mut stdin, &mut reader, &mut stderr, 12, &file_uri, 4, 10);
    assert_eq!(helper["name"], "helper", "prepared helper: {helper}");

    let outgoing = call_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        13,
        "callHierarchy/outgoingCalls",
        helper,
    );
    assert!(
        outgoing.iter().any(|call| call["to"]["name"] == "target"),
        "outgoing calls should include target: {outgoing:#?}"
    );
    let target_call = outgoing
        .iter()
        .find(|call| call["to"]["name"] == "target")
        .expect("target outgoing call");
    assert_call_range(&target_call["fromRanges"], 5, 16, 22);

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_prepare_filters_java_cursor_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("PrepareContexts.java");
    let source = "class Service {\n    static int VALUE = 1;\n    static void target() {}\n}\nclass Caller {\n    void helper() {\n        int local = 1;\n        Service value = null;\n        Service.target();\n        int field = Service.VALUE;\n    }\n}\n";
    fs::write(&file_path, source).expect("write Java prepare-context fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(source, "int l");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        14,
        &file_uri,
        line,
        character,
    );
    assert!(
        result.is_null(),
        "local variables must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(source, "        S");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        15,
        &file_uri,
        line,
        character,
    );
    assert!(
        result.is_null(),
        "type references must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(source, "Service.t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        16,
        &file_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared target call: {target}");

    let (line, character) = position_after(source, "field = Service.V");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        17,
        &file_uri,
        line,
        character,
    );
    assert!(
        result.is_null(),
        "field accesses must not prepare call hierarchy: {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_prepare_filters_js_ts_cursor_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let ts_path = root.join("prepare.ts");
    let ts_source = "interface Shape {}\nclass Maker {}\nfunction target(): void {}\nfunction caller(): void {\n  let local = 1;\n  let typed: Shape | null = null;\n  target();\n  new Maker();\n}\n";
    fs::write(&ts_path, ts_source).expect("write TypeScript prepare-context fixture");
    let js_path = root.join("prepare.js");
    let js_source = "class Worker {\n  run() {}\n}\nfunction caller() {\n  const local = 1;\n  new Worker().run();\n}\n";
    fs::write(&js_path, js_source).expect("write JavaScript prepare-context fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let ts_uri = uri_for(&ts_path);
    let js_uri = uri_for(&js_path);

    let (line, character) = position_after(ts_source, "function t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        18,
        &ts_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared TS function: {target}");

    let (line, character) = position_after(js_source, "  r");
    let run = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        19,
        &js_uri,
        line,
        character,
    );
    assert_eq!(run["name"], "run", "prepared JS method: {run}");

    let (line, character) = position_after(ts_source, "let l");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        20,
        &ts_uri,
        line,
        character,
    );
    assert!(
        result.is_null(),
        "TS local variables must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(ts_source, "let typed: S");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        21,
        &ts_uri,
        line,
        character,
    );
    assert!(
        result.is_null(),
        "TS type references must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(ts_source, "  t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        22,
        &ts_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared TS call: {target}");

    let (line, character) = position_after(ts_source, "new M");
    let maker = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        23,
        &ts_uri,
        line,
        character,
    );
    assert_eq!(maker["name"], "Maker", "prepared TS new call: {maker}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_prepare_filters_rust_cursor_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let source = "struct Widget;\nfn target() {}\nfn caller() {\n    let local = 1;\n    let typed: Option<Widget> = None;\n    target();\n}\n";
    fs::write(&file_path, source).expect("write Rust prepare-context fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(source, "fn t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        24,
        &file_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared Rust function: {target}");

    let (line, character) = position_after(source, "let l");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        25,
        &file_uri,
        line,
        character,
    );
    assert!(
        result.is_null(),
        "Rust local variables must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(source, "Option<W");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        26,
        &file_uri,
        line,
        character,
    );
    assert!(
        result.is_null(),
        "Rust type references must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(source, "    t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        27,
        &file_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared Rust call: {target}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_prepare_filters_remaining_language_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");

    fs::write(
        root.join("go.mod"),
        "module example.com/prepare\n\ngo 1.22\n",
    )
    .expect("write go.mod");
    let go_path = root.join("prepare.go");
    let go_source = "package main\n\ntype Widget struct{}\nfunc target() {}\nfunc caller() {\n    local := 1\n    var typed Widget\n    _ = local\n    _ = typed\n    target()\n}\n";
    fs::write(&go_path, go_source).expect("write Go prepare-context fixture");

    let cs_path = root.join("Prepare.cs");
    let cs_source = "namespace App { class Service { public static int Value; public static void Target() {} } class Caller { void Helper() { var local = 1; Service.Target(); var field = Service.Value; } } }\n";
    fs::write(&cs_path, cs_source).expect("write C# prepare-context fixture");

    let cpp_path = root.join("prepare.cpp");
    let cpp_source = "struct Widget {};\nvoid target() {}\nvoid caller() {\n    int local = 1;\n    Widget typed;\n    target();\n}\n";
    fs::write(&cpp_path, cpp_source).expect("write C++ prepare-context fixture");

    let scala_path = root.join("Prepare.scala");
    let scala_source = "package app\nclass Widget\nobject Service {\n  def target(): Unit = ()\n  def caller(): Unit = {\n    val local = 1\n    val typed: Widget = new Widget\n    target()\n  }\n}\n";
    fs::write(&scala_path, scala_source).expect("write Scala prepare-context fixture");

    let py_path = root.join("prepare.py");
    let py_source = "class Widget:\n    pass\n\ndef target():\n    pass\n\ndef caller():\n    local = 1\n    target()\n";
    fs::write(&py_path, py_source).expect("write Python prepare-context fixture");

    let php_path = root.join("Prepare.php");
    let php_source = "<?php\nnamespace App;\nclass Widget {}\nfunction target(): void {}\nfunction caller(): void {\n    $local = 1;\n    target();\n}\n";
    fs::write(&php_path, php_source).expect("write PHP prepare-context fixture");

    let rb_path = root.join("prepare.rb");
    let rb_source = "class Worker\n  def target\n  end\n\n  def caller\n    target\n  end\nend\n";
    fs::write(&rb_path, rb_source).expect("write Ruby prepare-context fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);

    let go_uri = uri_for(&go_path);
    let (line, character) = position_after(go_source, "func t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        28,
        &go_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared Go function: {target}");
    let (line, character) = position_after(go_source, "local :");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        29,
        &go_uri,
        line,
        character,
    );
    assert!(result.is_null(), "Go locals must not prepare: {result}");
    let (line, character) = position_after(go_source, "    t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        30,
        &go_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared Go call: {target}");

    let cs_uri = uri_for(&cs_path);
    let (line, character) = position_after(cs_source, "void T");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        31,
        &cs_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "Target", "prepared C# method: {target}");
    let (line, character) = position_after(cs_source, "local =");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        32,
        &cs_uri,
        line,
        character,
    );
    assert!(result.is_null(), "C# locals must not prepare: {result}");
    let (line, character) = position_after(cs_source, "Service.T");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        33,
        &cs_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "Target", "prepared C# call: {target}");

    let cpp_uri = uri_for(&cpp_path);
    let (line, character) = position_after(cpp_source, "void t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        34,
        &cpp_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared C++ function: {target}");
    let (line, character) = position_after(cpp_source, "local =");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        35,
        &cpp_uri,
        line,
        character,
    );
    assert!(result.is_null(), "C++ locals must not prepare: {result}");
    let (line, character) = position_after(cpp_source, "    t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        36,
        &cpp_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared C++ call: {target}");

    let scala_uri = uri_for(&scala_path);
    let (line, character) = position_after(scala_source, "def t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        37,
        &scala_uri,
        line,
        character,
    );
    assert_eq!(
        target["name"], "target",
        "prepared Scala function: {target}"
    );
    let (line, character) = position_after(scala_source, "val l");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        38,
        &scala_uri,
        line,
        character,
    );
    assert!(result.is_null(), "Scala locals must not prepare: {result}");
    let (line, character) = position_after(scala_source, "    t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        39,
        &scala_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared Scala call: {target}");

    let py_uri = uri_for(&py_path);
    let (line, character) = position_after(py_source, "def t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        40,
        &py_uri,
        line,
        character,
    );
    assert_eq!(
        target["name"], "target",
        "prepared Python function: {target}"
    );
    let (line, character) = position_after(py_source, "local =");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        41,
        &py_uri,
        line,
        character,
    );
    assert!(result.is_null(), "Python locals must not prepare: {result}");
    let (line, character) = position_after(py_source, "    t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        42,
        &py_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared Python call: {target}");

    let php_uri = uri_for(&php_path);
    let (line, character) = position_after(php_source, "function t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        43,
        &php_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared PHP function: {target}");
    let (line, character) = position_after(php_source, "$local");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        44,
        &php_uri,
        line,
        character,
    );
    assert!(result.is_null(), "PHP locals must not prepare: {result}");
    let (line, character) = position_after(php_source, "    t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        45,
        &php_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared PHP call: {target}");

    let rb_uri = uri_for(&rb_path);
    let (line, character) = position_after(rb_source, "def t");
    let target = prepare_call_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        46,
        &rb_uri,
        line,
        character,
    );
    assert_eq!(target["name"], "target", "prepared Ruby method: {target}");
    let (line, character) = position_after(rb_source, "    t");
    let result = prepare_call_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        47,
        &rb_uri,
        line,
        character,
    );
    assert!(
        result.is_null(),
        "Ruby call references stay unsupported until Ruby definition lookup lands: {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_preserves_java_overload_identity() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Overloads.java");
    fs::write(
        &file_path,
        "class Service {\n    static void target() {}\n    static void target(String value) {}\n    static void stringCaller() {\n        target(\"x\");\n    }\n    static void noArgCaller() {\n        target();\n    }\n}\n",
    )
    .expect("write Java overload call hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let string_target =
        prepare_call_hierarchy(&mut stdin, &mut reader, &mut stderr, 20, &file_uri, 2, 16);
    assert_eq!(
        string_target["detail"], "(String)",
        "prepared overload should carry String signature: {string_target}"
    );

    let incoming = call_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        21,
        "callHierarchy/incomingCalls",
        string_target,
    );
    let callers: Vec<_> = incoming
        .iter()
        .filter_map(|call| call["from"]["name"].as_str())
        .collect();
    assert_eq!(
        callers,
        vec!["stringCaller"],
        "String overload should not include no-arg caller: {incoming:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_ignores_non_call_type_references() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("TypeReference.java");
    fs::write(
        &file_path,
        "class Service {}\nclass Caller {\n    void helper() {\n        Service value = null;\n    }\n}\n",
    )
    .expect("write Java type-reference call hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let service = prepare_call_hierarchy(&mut stdin, &mut reader, &mut stderr, 30, &file_uri, 0, 6);
    assert_eq!(service["name"], "Service", "prepared service: {service}");

    let incoming = call_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        31,
        "callHierarchy/incomingCalls",
        service,
    );
    assert!(
        incoming.is_empty(),
        "type references without calls must not produce incoming call hierarchy edges: {incoming:#?}"
    );

    let helper = prepare_call_hierarchy(&mut stdin, &mut reader, &mut stderr, 30, &file_uri, 2, 10);

    let outgoing = call_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        32,
        "callHierarchy/outgoingCalls",
        helper,
    );
    assert!(
        outgoing.is_empty(),
        "type references without calls must not produce outgoing call hierarchy edges: {outgoing:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_finds_qualified_java_constructor_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let pkg_dir = root.join("pkg");
    fs::create_dir(&pkg_dir).expect("create package dir");
    let service_path = pkg_dir.join("Service.java");
    fs::write(&service_path, "package pkg;\npublic class Service {}\n")
        .expect("write Java service fixture");
    let caller_path = root.join("Caller.java");
    fs::write(
        &caller_path,
        "class Caller {\n    void helper() {\n        new pkg.Service();\n    }\n}\n",
    )
    .expect("write Java qualified constructor fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let caller_uri = uri_for(&caller_path);
    let helper =
        prepare_call_hierarchy(&mut stdin, &mut reader, &mut stderr, 40, &caller_uri, 1, 10);

    let outgoing = call_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        41,
        "callHierarchy/outgoingCalls",
        helper,
    );
    assert!(
        outgoing.iter().any(|call| call["to"]["name"] == "Service"),
        "qualified constructor calls should produce outgoing class edges: {outgoing:#?}"
    );
    let service_call = outgoing
        .iter()
        .find(|call| call["to"]["name"] == "Service")
        .expect("Service outgoing call");
    assert_call_range(&service_call["fromRanges"], 2, 16, 23);

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_does_not_include_nested_function_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("nested.js");
    fs::write(
        &file_path,
        "function target() {}\nfunction outer() {\n    function inner() {\n        target();\n    }\n}\n",
    )
    .expect("write JavaScript nested call hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let outer = prepare_call_hierarchy(&mut stdin, &mut reader, &mut stderr, 40, &file_uri, 1, 9);

    let outgoing = call_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        41,
        "callHierarchy/outgoingCalls",
        outer,
    );
    assert!(
        outgoing.is_empty(),
        "calls inside nested functions must not be attributed to the outer function: {outgoing:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_does_not_include_nested_type_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("NestedType.java");
    fs::write(
        &file_path,
        "class Target {\n    static int value() { return 1; }\n}\nclass Outer {\n    class Inner {\n        int field = Target.value();\n    }\n}\n",
    )
    .expect("write Java nested type call hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let outer = prepare_call_hierarchy(&mut stdin, &mut reader, &mut stderr, 50, &file_uri, 3, 6);

    let outgoing = call_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        51,
        "callHierarchy/outgoingCalls",
        outer,
    );
    assert!(
        outgoing.is_empty(),
        "calls inside nested types must not be attributed to the outer type: {outgoing:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_document_highlight_filters_to_current_file() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let a_uri = uri_for(&canonical_root.join("A.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["documentHighlightProvider"], true,
        "documentHighlightProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // A.java line 2 (0-based), col 13: cursor on the `A` in `public class A {`.
    // The same `A` is referenced from A.java's own body (line 26 `new A()`,
    // line 33 inner-class `new A()`) and from B.java. The handler must
    // return only the A.java hits.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/documentHighlight",
            "params": {
                "textDocument": {"uri": a_uri},
                "position": {"line": 2, "character": 13}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let highlights = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array result, got {response}"));
    assert!(
        !highlights.is_empty(),
        "expected at least one highlight, got: {response}"
    );

    // documentHighlight returns ranges only — no URI field, by spec. Make
    // sure no entry accidentally smuggled one in (i.e. we didn't return
    // `Location` shapes).
    for h in highlights {
        assert!(
            h["uri"].is_null(),
            "documentHighlight result must not include uri: {h}"
        );
        assert!(h["range"].is_object(), "highlight must have range: {h}");
    }

    // The two self-references in A.java live on line 26 (`System.out.println(new A())`)
    // and line 33 (`System.out.println(new A())`). Both must show up.
    let lines: Vec<u64> = highlights
        .iter()
        .filter_map(|h| h["range"]["start"]["line"].as_u64())
        .collect();
    assert!(
        lines.contains(&26) && lines.contains(&33),
        "expected both in-file self-reference highlights on lines 26 and 33, got lines {lines:?}"
    );

    // B.java references `A` on line 6 (`A a = new A();`). The cross-file
    // filter must drop those — if a `6` slips through, the filter regressed
    // (B.java has no other lines that overlap with A.java's expected hits).
    assert!(
        !lines.contains(&6),
        "B.java line-6 reference leaked into highlights, got lines {lines:?}"
    );

    // Regression: the declaration highlight on line 2 (`public class A {`)
    // must scope to the identifier `A` (single character), not the whole
    // class body. A multi-line declaration highlight wipes out the editor's
    // cursor highlight with a giant block.
    let class_decl_highlight = highlights
        .iter()
        .find(|h| h["range"]["start"]["line"].as_u64() == Some(2))
        .unwrap_or_else(|| panic!("expected declaration highlight on line 2, got {highlights:?}"));
    assert_eq!(
        class_decl_highlight["range"]["end"]["line"].as_u64(),
        Some(2),
        "class declaration highlight must stay on a single line, got {class_decl_highlight}"
    );
    assert_eq!(
        class_decl_highlight["range"]["start"]["character"].as_u64(),
        Some(13),
        "class declaration highlight must start at the `A` identifier, got {class_decl_highlight}"
    );
    assert_eq!(
        class_decl_highlight["range"]["end"]["character"].as_u64(),
        Some(14),
        "class declaration highlight must end after the `A` identifier, got {class_decl_highlight}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_hover_includes_doc_comment() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("Documented.java"),
        "/**\n * The documented class.\n * Multi-line.\n */\npublic class Documented {\n    public void noop() {}\n}\n",
    )
    .expect("write fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("Documented.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 4 (0-based) is `public class Documented {` — char 13 is the `D`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": doc_uri},
                "position": {"line": 4, "character": 13}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.contains("class Documented"),
        "hover should include the skeleton: {value}"
    );
    assert!(
        value.contains("The documented class."),
        "hover should include the doc comment first line: {value}"
    );
    assert!(
        value.contains("Multi-line."),
        "hover should include the doc comment second line: {value}"
    );
    assert!(
        !value.contains("/**") && !value.contains("*/"),
        "doc-comment markers should be stripped: {value}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_hover_includes_rust_triple_slash_doc_comment() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("documented.rs"),
        "/// Returns the answer.\n/// Always 42.\npub fn answer() -> i32 { 42 }\n",
    )
    .expect("write fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("documented.rs"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 2 (0-based) is `pub fn answer() -> i32 { 42 }`; char 7 is the `a`
    // in `answer`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": doc_uri},
                "position": {"line": 2, "character": 7}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.contains("fn answer"),
        "hover should include the skeleton: {value}"
    );
    assert!(
        value.contains("Returns the answer."),
        "hover should include the first /// line: {value}"
    );
    assert!(
        value.contains("Always 42."),
        "hover should include the second /// line: {value}"
    );
    assert!(
        !value.contains("///"),
        "/// markers should be stripped: {value}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_hover_surfaces_rust_doc_above_outer_attribute() {
    // Regression: a `///` doc comment separated from the declaration by an
    // outer attribute (`#[derive(...)]`) must still be lifted into hover.
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("attrs.rs"),
        "/// Holds a single value.\n/// Cloneable for convenience.\n#[derive(Debug, Clone)]\npub struct Holder { value: i32 }\n",
    )
    .expect("write fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("attrs.rs"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 3 (0-based) is `pub struct Holder { value: i32 }`; char 11 lands
    // on the `H` in `Holder`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": doc_uri},
                "position": {"line": 3, "character": 11}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.contains("Holds a single value."),
        "hover should surface the first /// line above the attribute: {value}"
    );
    assert!(
        value.contains("Cloneable for convenience."),
        "hover should surface the second /// line above the attribute: {value}"
    );
    assert!(
        !value.contains("derive"),
        "the #[derive(...)] attribute itself must not leak into hover markdown: {value}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_diagnostics_report_parse_error() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("Bad.java"),
        "public class Bad {\n    public void broken( {\n}\n",
    )
    .expect("write fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let bad_uri = uri_for(&temp_root.join("Bad.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert!(
        init["result"]["capabilities"]["diagnosticProvider"].is_object(),
        "diagnosticProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/diagnostic",
            "params": {"textDocument": {"uri": bad_uri}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        !items.is_empty(),
        "expected at least one parse-error diagnostic for malformed Java: {response}"
    );
    assert_eq!(items[0]["severity"], 1, "severity should be Error");
    assert_eq!(items[0]["source"], "bifrost-tree-sitter");

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_diagnostics_edge_cases() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");

    // 1) A syntactically-valid Java file: should produce zero diagnostics.
    fs::write(
        temp_root.join("Clean.java"),
        "public class Clean {\n    public void ok() {}\n}\n",
    )
    .expect("write Clean.java");
    // 2) An unsupported extension: handler should return an empty report,
    //    not an error response, so editors don't spam users with red squiggles
    //    on plain text files.
    fs::write(
        temp_root.join("notes.txt"),
        "hello world\nthis is not source code",
    )
    .expect("write notes.txt");
    // 3) A binary file masquerading as `.java`: handler must not panic.
    fs::write(
        temp_root.join("Binary.java"),
        [0u8, 1, 2, 0xFF, 0xFE, 0xFD, 0u8, b'\n', b'a', b'b', 0u8],
    )
    .expect("write Binary.java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    let cases: &[(&str, &str)] = &[
        ("clean", "Clean.java"),
        ("text", "notes.txt"),
        ("binary", "Binary.java"),
    ];
    for (idx, (label, name)) in cases.iter().enumerate() {
        let id = (idx as u64) + 2;
        let uri = uri_for(&temp_root.join(name));
        write_message(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "textDocument/diagnostic",
                "params": {"textDocument": {"uri": uri}}
            }),
        );
        let response = read_message(&mut reader, &mut stderr);
        assert!(
            response["error"].is_null(),
            "{label}: should not be a JSON-RPC error: {response}"
        );
        let items = response["result"]["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{label}: expected items array, got {response}"));
        assert!(
            items.is_empty(),
            "{label}: expected zero diagnostics, got {items:#?}"
        );
    }

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_go_semantic_diagnostics_pull_reports_unrecognized_symbols() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("go.mod"),
        "module example.com/app\n\ngo 1.22\n",
    )
    .expect("write go.mod");
    fs::create_dir_all(temp_root.join("store")).expect("create store");
    fs::write(
        temp_root.join("store/store.go"),
        "package store\n\nfunc Present() {}\n",
    )
    .expect("write store");
    fs::write(
        temp_root.join("main.go"),
        r#"
package main

import "example.com/app/store"

func Run() {
    missingValue
    store.Missing()
}
"#,
    )
    .expect("write main.go");

    let mut server = LspTestServer::start(&temp_root);
    server.initialize(&temp_root);
    let main_uri = uri_for(&temp_root.join("main.go"));

    server.write(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": main_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items.iter().any(|item| item["source"] == "bifrost-go"
            && item["code"] == "go_unrecognized_symbol"
            && item["message"]
                .as_str()
                .is_some_and(|message| message.contains("missingValue"))),
        "expected missingValue semantic diagnostic: {response}"
    );
    assert!(
        items.iter().any(|item| item["source"] == "bifrost-go"
            && item["code"] == "go_unrecognized_package_member"
            && item["message"]
                .as_str()
                .is_some_and(|message| message.contains("Missing"))),
        "expected store.Missing semantic diagnostic: {response}"
    );

    server.shutdown(3);
}

#[test]
fn bifrost_lsp_server_go_malformed_file_reports_parse_not_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("go.mod"),
        "module example.com/app\n\ngo 1.22\n",
    )
    .expect("write go.mod");
    fs::write(
        temp_root.join("broken.go"),
        "package main\n\nfunc Run( {\n    missingValue\n}\n",
    )
    .expect("write broken.go");

    let mut server = LspTestServer::start(&temp_root);
    server.initialize(&temp_root);
    let broken_uri = uri_for(&temp_root.join("broken.go"));

    server.write(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": broken_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items
            .iter()
            .any(|item| item["source"] == "bifrost-tree-sitter"),
        "expected parse diagnostic for malformed Go: {response}"
    );
    assert!(
        items.iter().all(|item| item["source"] != "bifrost-go"),
        "malformed Go must suppress semantic diagnostics: {response}"
    );

    server.shutdown(3);
}

#[test]
fn bifrost_lsp_server_python_semantic_diagnostics_pull_reports_unrecognized_symbols() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("app.py"),
        r#"
def run():
    missing_value
"#,
    )
    .expect("write app.py");

    let mut server = LspTestServer::start(&temp_root);
    server.initialize(&temp_root);
    let app_uri = uri_for(&temp_root.join("app.py"));

    server.write(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": app_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items.iter().any(|item| item["source"] == "bifrost-python"
            && item["code"] == "python_unrecognized_symbol"
            && item["message"]
                .as_str()
                .is_some_and(|message| message.contains("missing_value"))),
        "expected missing_value semantic diagnostic: {response}"
    );

    server.shutdown(3);
}

#[test]
fn bifrost_lsp_server_python_semantic_diagnostics_malformed_file_reports_parse_not_semantic() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(temp_root.join("broken.py"), "def run(\n    missing_value\n")
        .expect("write broken.py");

    let mut server = LspTestServer::start(&temp_root);
    server.initialize(&temp_root);
    let broken_uri = uri_for(&temp_root.join("broken.py"));

    server.write(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": broken_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items
            .iter()
            .any(|item| item["source"] == "bifrost-tree-sitter"),
        "expected parse diagnostic for malformed Python: {response}"
    );
    assert!(
        items.iter().all(|item| item["source"] != "bifrost-python"),
        "malformed Python must suppress semantic diagnostics: {response}"
    );

    server.shutdown(3);
}

#[test]
fn bifrost_lsp_server_did_save_triggers_reindex() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("Watch.java"),
        "public class Watch {\n    public void initial() {}\n}\n",
    )
    .expect("write fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let watch_uri = uri_for(&temp_root.join("Watch.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Confirm initial workspaceSymbol query finds `initial` and not `added`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "added"}
        }),
    );
    let before = read_message(&mut reader, &mut stderr);
    let names_before: Vec<String> = before["result"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !names_before.iter().any(|n| n == "added"),
        "expected no `added` symbol pre-save, got {names_before:?}"
    );

    // Replace the file content and send didSave.
    fs::write(
        temp_root.join("Watch.java"),
        "public class Watch {\n    public void added() {}\n}\n",
    )
    .expect("rewrite fixture");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {"textDocument": {"uri": watch_uri}}
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "workspace/symbol",
            "params": {"query": "added"}
        }),
    );
    // didSave now emits a publishDiagnostics notification before the
    // workspace/symbol response — skip past it.
    let after = read_response_for_id(&mut reader, &mut stderr, 3);
    let names_after: Vec<String> = after["result"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        names_after.iter().any(|n| n == "added"),
        "expected `added` symbol post-save, got {names_after:?}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 4, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_hover_uses_python_language_tag_for_py_file() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-py");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let py_uri = uri_for(&canonical_root.join("documented.py"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 21 (0-based) is `class DocumentedClass:`. The class name starts
    // at char 6 — guards against the language-tag table emitting "java"
    // (or any wrong tag) for a .py file.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": py_uri},
                "position": {"line": 21, "character": 7}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.starts_with("```python"),
        "expected python-fenced hover for .py file, got: {value}"
    );
    assert!(
        value.contains("DocumentedClass"),
        "hover should mention DocumentedClass, got: {value}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_unknown_request_returns_method_not_found() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": null, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/codeAction",
            "params": {
                "textDocument": {"uri": "file:///nope"},
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end": {"line": 0, "character": 0}
                },
                "context": {"diagnostics": []}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert_eq!(response["id"], 2);
    assert_eq!(
        response["error"]["code"], -32601,
        "expected MethodNotFound (-32601): {response}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_did_save_publishes_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    // Start with a file that parses cleanly.
    fs::write(
        temp_root.join("Push.java"),
        "public class Push {\n    public void ok() {}\n}\n",
    )
    .expect("write fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = uri_for(&temp_root);
    let push_uri = uri_for(&temp_root.join("Push.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Replace the file with broken Java, then send didSave. The server should
    // emit a `textDocument/publishDiagnostics` notification with at least one
    // parse-error item.
    fs::write(
        temp_root.join("Push.java"),
        "public class Push {\n    public void broken( {\n}\n",
    )
    .expect("rewrite fixture");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {"textDocument": {"uri": push_uri}}
        }),
    );

    let publish = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");
    assert_eq!(
        publish["params"]["uri"].as_str(),
        Some(push_uri.as_str()),
        "publishDiagnostics URI should match the saved file: {publish}"
    );
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(
        !items.is_empty(),
        "expected at least one parse-error diagnostic for malformed Java: {publish}"
    );
    assert!(
        items
            .iter()
            .any(|d| d["severity"] == 1 && d["source"] == "bifrost-tree-sitter"),
        "expected an Error-severity bifrost-tree-sitter diagnostic: {publish}"
    );

    // Now save a clean version and verify the server sends an empty
    // diagnostics array — clients use this to clear stale red squiggles.
    fs::write(
        temp_root.join("Push.java"),
        "public class Push {\n    public void ok() {}\n}\n",
    )
    .expect("rewrite fixture");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {"textDocument": {"uri": push_uri}}
        }),
    );
    let cleared = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");
    let cleared_items = cleared["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {cleared}"));
    assert!(
        cleared_items.is_empty(),
        "expected zero diagnostics after clean save, got {cleared}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_did_save_publishes_go_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("go.mod"),
        "module example.com/app\n\ngo 1.22\n",
    )
    .expect("write go.mod");
    fs::write(
        temp_root.join("main.go"),
        "package main\n\nfunc Run() {\n    println(\"ok\")\n}\n",
    )
    .expect("write fixture");

    let mut server = LspTestServer::start(&temp_root);
    server.initialize(&temp_root);
    let main_uri = uri_for(&temp_root.join("main.go"));

    fs::write(
        temp_root.join("main.go"),
        "package main\n\nfunc Run() {\n    missingValue\n}\n",
    )
    .expect("rewrite fixture");
    server.write(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": main_uri}}
    }));

    let publish = server.read_notification("textDocument/publishDiagnostics");
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(
        items.iter().any(|item| item["source"] == "bifrost-go"
            && item["code"] == "go_unrecognized_symbol"
            && item["message"]
                .as_str()
                .is_some_and(|message| message.contains("missingValue"))),
        "expected publishDiagnostics semantic Go item: {publish}"
    );

    server.shutdown(99);
}

#[test]
fn bifrost_lsp_server_did_save_publishes_python_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(temp_root.join("app.py"), "def run():\n    print(\"ok\")\n").expect("write fixture");

    let mut server = LspTestServer::start(&temp_root);
    server.initialize(&temp_root);
    let app_uri = uri_for(&temp_root.join("app.py"));

    fs::write(temp_root.join("app.py"), "def run():\n    missing_value\n")
        .expect("rewrite fixture");
    server.write(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": app_uri}}
    }));

    let publish = server.read_notification("textDocument/publishDiagnostics");
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(
        items.iter().any(|item| item["source"] == "bifrost-python"
            && item["code"] == "python_unrecognized_symbol"
            && item["message"]
                .as_str()
                .is_some_and(|message| message.contains("missing_value"))),
        "expected publishDiagnostics semantic Python item: {publish}"
    );

    server.shutdown(99);
}

#[test]
fn bifrost_lsp_server_returns_folding_ranges_for_a_java() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let file_uri = uri_for(&canonical_root.join("A.java"));

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": root_uri,
                "capabilities": {}
            }
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(init["id"], 1);
    assert_eq!(
        init["result"]["capabilities"]["foldingRangeProvider"], true,
        "foldingRangeProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/foldingRange",
            "params": {"textDocument": {"uri": file_uri}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert_eq!(response["id"], 2);
    let folds = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array result, got {response}"));

    assert!(
        !folds.is_empty(),
        "expected at least one folding range, got {folds:#?}"
    );

    // No mono-line folds, and dedup invariant: every (startLine, endLine) pair is unique.
    let mut pairs: Vec<(u64, u64)> = Vec::with_capacity(folds.len());
    for fold in folds {
        let start = fold["startLine"]
            .as_u64()
            .unwrap_or_else(|| panic!("startLine missing or non-numeric: {fold}"));
        let end = fold["endLine"]
            .as_u64()
            .unwrap_or_else(|| panic!("endLine missing or non-numeric: {fold}"));
        assert!(end > start, "mono-line fold leaked through filter: {fold}");
        pairs.push((start, end));
    }
    let mut sorted = pairs.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        pairs.len(),
        "duplicate folds returned: {pairs:?}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

/// Spin up a bifrost LSP server rooted at `root`, do the initialize handshake,
/// and return (child, stdin, reader, stderr). Used by the didOpen/didChange/
/// didClose tests so each test isn't 50 lines of boilerplate before the
/// scenario starts.
fn start_lsp_server(
    root: &Path,
) -> (
    std::process::Child,
    std::process::ChildStdin,
    BufReader<std::process::ChildStdout>,
    std::process::ChildStderr,
) {
    let root_uri = uri_for(root);
    start_lsp_server_with_params(
        root,
        json!({"processId": null, "rootUri": root_uri, "capabilities": {}}),
    )
}

fn start_lsp_server_with_params(
    root: &Path,
    initialize_params: Value,
) -> (
    std::process::Child,
    std::process::ChildStdin,
    BufReader<std::process::ChildStdout>,
    std::process::ChildStderr,
) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": initialize_params
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );
    (child, stdin, reader, stderr)
}

#[test]
fn bifrost_lsp_server_type_hierarchy_java_round_trips_item_data() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Hierarchy.java");
    fs::write(
        &file_path,
        "class Base {}\nclass Child extends Base {\n    void method() {}\n}\n",
    )
    .expect("write Java hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 10, &file_uri, 1, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        "typeHierarchy/supertypes",
        child_item,
    );
    assert_eq!(
        supertypes.len(),
        1,
        "expected one supertype: {supertypes:#?}"
    );
    assert_eq!(supertypes[0]["name"], "Base", "supertype should be Base");

    let base_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        12,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_python_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("hierarchy.py");
    fs::write(
        &file_path,
        "class Base:\n    pass\n\nclass Child(Base):\n    def method(self):\n        pass\n",
    )
    .expect("write Python hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 20, &file_uri, 3, 6);

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        21,
        "typeHierarchy/supertypes",
        child_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(supertype_names, vec!["Base"], "supertypes: {supertypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_javascript_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("hierarchy.js");
    fs::write(
        &file_path,
        "class Base {}\nclass Child extends Base {\n    method() {}\n}\n",
    )
    .expect("write JavaScript hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 25, &file_uri, 1, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        26,
        "typeHierarchy/supertypes",
        child_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(supertype_names, vec!["Base"], "supertypes: {supertypes:#?}");

    let base_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        27,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_typescript_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("hierarchy.ts");
    let source = "interface Runnable {}\nclass Base {}\nclass Child extends Base implements Runnable {\n    method(): void {}\n}\nlet typed: Base | null = null;\n";
    fs::write(&file_path, source).expect("write TypeScript hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 28, &file_uri, 2, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        29,
        "typeHierarchy/supertypes",
        child_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        supertype_names,
        vec!["Base", "Runnable"],
        "supertypes: {supertypes:#?}"
    );

    let base_item = supertypes
        .iter()
        .find(|item| item["name"] == "Base")
        .cloned()
        .expect("Base supertype item");
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        34,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    let (line, character) = position_after(source, "typed: ");
    let base_ref = prepare_type_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        35,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        base_ref["name"], "Base",
        "prepared TypeScript Base reference: {base_ref}"
    );

    let (line, character) = position_after(source, "let t");
    let result = prepare_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        36,
        "textDocument/prepareTypeHierarchy",
        &file_uri,
        (line, character),
    );
    assert!(
        result.is_null(),
        "TypeScript local declaration names must not prepare hierarchy: {result}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_php_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Hierarchy.php");
    fs::write(
        &file_path,
        "<?php\nnamespace App;\ninterface Contract {}\nclass Base {}\nclass Child extends Base implements Contract {\n    public function method(): void {}\n}\n",
    )
    .expect("write PHP hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 30, &file_uri, 4, 6);

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        31,
        "typeHierarchy/supertypes",
        child_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        supertype_names,
        vec!["Base", "Contract"],
        "supertypes: {supertypes:#?}"
    );

    let base_item = supertypes
        .iter()
        .find(|item| item["name"] == "Base")
        .cloned()
        .expect("Base supertype item");
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        32,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_cpp_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Hierarchy.cpp");
    fs::write(
        &file_path,
        "struct Base {};\nstruct Child : Base {\n    void method() {}\n};\n",
    )
    .expect("write C++ hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 40, &file_uri, 1, 8);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        41,
        "typeHierarchy/supertypes",
        child_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(supertype_names, vec!["Base"], "supertypes: {supertypes:#?}");

    let base_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        42,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_scala_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Hierarchy.scala");
    fs::write(
        &file_path,
        "package app\ntrait Runnable\nclass Base\nclass Child extends Base with Runnable\n",
    )
    .expect("write Scala hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 50, &file_uri, 3, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        51,
        "typeHierarchy/supertypes",
        child_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        supertype_names,
        vec!["Base", "Runnable"],
        "supertypes: {supertypes:#?}"
    );

    let base_item = supertypes
        .iter()
        .find(|item| item["name"] == "Base")
        .cloned()
        .expect("Base supertype item");
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        52,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_rust_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let source = "trait Runnable {}\nstruct Worker;\nimpl Runnable for Worker {}\nfn use_it() { let typed: Worker = Worker; }\n";
    fs::write(&file_path, source).expect("write Rust hierarchy fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let worker_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 60, &file_uri, 1, 8);
    assert_eq!(
        worker_item["name"], "Worker",
        "prepared worker: {worker_item}"
    );

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        61,
        "typeHierarchy/supertypes",
        worker_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        supertype_names,
        vec!["Runnable"],
        "supertypes: {supertypes:#?}"
    );

    let runnable_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        62,
        "typeHierarchy/subtypes",
        runnable_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Worker"], "subtypes: {subtypes:#?}");

    let (line, character) = position_after(source, "typed: ");
    let runnable_ref = prepare_type_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        63,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        runnable_ref["name"], "Worker",
        "prepared Rust Worker reference: {runnable_ref}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_go_type_hierarchy_returns_structural_interface_edges() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n\ngo 1.22\n").expect("write go.mod");
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package app\ntype Runner interface { Run() error }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n",
    )
    .expect("write Go fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let worker = prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 30, &file_uri, 2, 6);
    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        31,
        "typeHierarchy/supertypes",
        worker,
    );
    assert!(
        supertypes.iter().any(|item| item["name"] == "Runner"),
        "expected Runner supertype, got {supertypes:#?}"
    );

    let runner = prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 32, &file_uri, 1, 6);
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        33,
        "typeHierarchy/subtypes",
        runner,
    );
    assert!(
        subtypes.iter().any(|item| item["name"] == "Worker"),
        "expected Worker subtype, got {subtypes:#?}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_ruby_type_hierarchy_and_implementation_filter_value_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("hierarchy.rb");
    let source = "class Base\nend\n\nclass Child < Base\nend\n\nclass Service\n  def build\n    local = Child.new\n    result = local\n  end\nend\n";
    fs::write(&file_path, source).expect("write Ruby hierarchy-context fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(source, "class C");
    let child_item = prepare_type_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        65,
        &file_uri,
        line,
        character,
    );
    assert_eq!(
        child_item["name"], "Child",
        "prepared Ruby Child declaration: {child_item}"
    );
    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        66,
        "typeHierarchy/supertypes",
        child_item,
    );
    assert!(
        supertypes.iter().any(|item| item["name"] == "Base"),
        "expected Ruby Base supertype, got {supertypes:#?}"
    );

    let (line, character) = position_after(source, "class B");
    let response = implementation_response(
        &mut stdin,
        &mut reader,
        &mut stderr,
        67,
        &file_uri,
        line,
        character,
    );
    let locations = response["result"].as_array().unwrap_or_else(|| {
        panic!("expected Ruby implementation from Base declaration, got {response}")
    });
    assert!(
        locations
            .iter()
            .any(|location| location["range"]["start"]["line"] == 3),
        "expected Ruby Child implementation from Base declaration, got {response}"
    );

    let null_cases = [
        ("method name", "def b"),
        ("local declaration", "local ="),
        ("call receiver", "Child.n"),
        ("local reference", "result = loc"),
    ];
    for (index, (label, needle)) in null_cases.iter().enumerate() {
        let (line, character) = position_after(source, needle);
        let result = prepare_hierarchy_result(
            &mut stdin,
            &mut reader,
            &mut stderr,
            68 + (index as u64 * 2),
            "textDocument/prepareTypeHierarchy",
            &file_uri,
            (line, character),
        );
        assert!(
            result.is_null(),
            "Ruby {label} must not prepare type hierarchy: {result}"
        );

        let response = implementation_response(
            &mut stdin,
            &mut reader,
            &mut stderr,
            69 + (index as u64 * 2),
            &file_uri,
            line,
            character,
        );
        assert!(
            response["result"].is_null(),
            "Ruby {label} must not resolve implementations, got {response}"
        );
    }

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_filters_java_csharp_scala_value_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let fixtures = write_jvm_type_context_fixtures(&root, "HierarchyContexts");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);

    let java_uri = uri_for(&fixtures.java_path);
    let (line, character) = position_after(fixtures.java_source, "class S");
    let service = prepare_type_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        70,
        &java_uri,
        line,
        character,
    );
    assert_eq!(
        service["name"], "Service",
        "prepared Java Service: {service}"
    );
    let (line, character) = position_after(fixtures.java_source, "    W");
    let widget_result = prepare_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        71,
        "textDocument/prepareTypeHierarchy",
        &java_uri,
        (line, character),
    );
    let widget = widget_result
        .as_array()
        .unwrap_or_else(|| panic!("expected Java return type to prepare, got {widget_result}"));
    assert_eq!(
        widget.len(),
        1,
        "expected one Java Widget item: {widget:#?}"
    );
    let widget = widget[0].clone();
    assert_eq!(widget["name"], "Widget", "prepared Java Widget: {widget}");
    assert_prepare_type_hierarchy_null_cases(
        &mut stdin,
        &mut reader,
        &mut stderr,
        72,
        &java_uri,
        fixtures.java_source,
        &[
            ("    Widget b", "Java method names"),
            ("        Widget l", "Java locals"),
        ],
    );

    let csharp_uri = uri_for(&fixtures.csharp_path);
    assert_prepare_type_hierarchy_null_cases(
        &mut stdin,
        &mut reader,
        &mut stderr,
        74,
        &csharp_uri,
        fixtures.csharp_source,
        &[(" Widget B", "C# method names"), (" Widget l", "C# locals")],
    );

    let scala_uri = uri_for(&fixtures.scala_path);
    let (line, character) = position_after(fixtures.scala_source, "class S");
    let service = prepare_type_hierarchy(
        &mut stdin,
        &mut reader,
        &mut stderr,
        77,
        &scala_uri,
        line,
        character,
    );
    assert_eq!(
        service["name"], "Service",
        "prepared Scala Service: {service}"
    );
    let (line, character) = position_after(fixtures.scala_source, ": W");
    let widget_result = prepare_hierarchy_result(
        &mut stdin,
        &mut reader,
        &mut stderr,
        78,
        "textDocument/prepareTypeHierarchy",
        &scala_uri,
        (line, character),
    );
    let widget = widget_result
        .as_array()
        .unwrap_or_else(|| panic!("expected Scala return type to prepare, got {widget_result}"));
    assert_eq!(
        widget.len(),
        1,
        "expected one Scala Widget item: {widget:#?}"
    );
    let widget = widget[0].clone();
    assert_eq!(widget["name"], "Widget", "prepared Scala Widget: {widget}");
    assert_prepare_type_hierarchy_null_cases(
        &mut stdin,
        &mut reader,
        &mut stderr,
        79,
        &scala_uri,
        fixtures.scala_source,
        &[("def b", "Scala function names"), ("val l", "Scala locals")],
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

fn assert_implementation_null_cases(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    start_id: u64,
    uri: &str,
    source: &str,
    cases: &[(&str, &str)],
) {
    for (index, (needle, label)) in cases.iter().enumerate() {
        let (line, character) = position_after(source, needle);
        let response = implementation_response(
            stdin,
            reader,
            stderr,
            start_id + index as u64,
            uri,
            line,
            character,
        );
        assert!(
            response["result"].is_null(),
            "{label} must not resolve implementations, got {response}"
        );
    }
}

fn assert_prepare_type_hierarchy_null_cases(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    start_id: u64,
    uri: &str,
    source: &str,
    cases: &[(&str, &str)],
) {
    for (index, (needle, label)) in cases.iter().enumerate() {
        let (line, character) = position_after(source, needle);
        let result = prepare_hierarchy_result(
            stdin,
            reader,
            stderr,
            start_id + index as u64,
            "textDocument/prepareTypeHierarchy",
            uri,
            (line, character),
        );
        assert!(
            result.is_null(),
            "{label} must not prepare type hierarchy: {result}"
        );
    }
}

fn prepare_type_hierarchy(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    uri: &str,
    line: u64,
    character: u64,
) -> Value {
    prepare_hierarchy(
        stdin,
        reader,
        stderr,
        id,
        "textDocument/prepareTypeHierarchy",
        uri,
        (line, character),
    )
}

fn type_hierarchy_relation(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    method: &str,
    item: Value,
) -> Vec<Value> {
    hierarchy_relation(stdin, reader, stderr, id, method, item)
}

fn prepare_call_hierarchy(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    uri: &str,
    line: u64,
    character: u64,
) -> Value {
    prepare_hierarchy(
        stdin,
        reader,
        stderr,
        id,
        "textDocument/prepareCallHierarchy",
        uri,
        (line, character),
    )
}

fn prepare_call_hierarchy_result(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    uri: &str,
    line: u64,
    character: u64,
) -> Value {
    prepare_hierarchy_result(
        stdin,
        reader,
        stderr,
        id,
        "textDocument/prepareCallHierarchy",
        uri,
        (line, character),
    )
}

fn call_hierarchy_relation(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    method: &str,
    item: Value,
) -> Vec<Value> {
    hierarchy_relation(stdin, reader, stderr, id, method, item)
}

fn prepare_hierarchy(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    method: &str,
    uri: &str,
    position: (u64, u64),
) -> Value {
    let result = prepare_hierarchy_result(stdin, reader, stderr, id, method, uri, position);
    let items = result
        .as_array()
        .unwrap_or_else(|| panic!("expected prepare array, got {result}"));
    assert_eq!(items.len(), 1, "expected one prepared item: {items:#?}");
    items[0].clone()
}

fn prepare_hierarchy_result(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    method: &str,
    uri: &str,
    position: (u64, u64),
) -> Value {
    let (line, character) = position;
    write_message(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character}
            }
        }),
    );
    let response = read_response_for_id(reader, stderr, id);
    response["result"].clone()
}

fn hierarchy_relation(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    method: &str,
    item: Value,
) -> Vec<Value> {
    write_message(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": {"item": item}
        }),
    );
    let response = read_response_for_id(reader, stderr, id);
    response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected {method} array, got {response}"))
        .clone()
}

fn signature_help(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    uri: &str,
    line: u64,
    character: u64,
) -> Value {
    write_message(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "textDocument/signatureHelp",
            "params": {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character}
            }
        }),
    );
    let response = read_response_for_id(reader, stderr, id);
    assert!(
        response["error"].is_null(),
        "unexpected signatureHelp error: {response}"
    );
    assert!(
        response["result"].is_object(),
        "expected signatureHelp result object, got {response}"
    );
    response["result"].clone()
}

fn assert_signature_parameter_offsets(result: &Value, signature_index: usize, expected: &[&str]) {
    let signature = &result["signatures"][signature_index];
    let label = signature["label"]
        .as_str()
        .unwrap_or_else(|| panic!("expected signature label, got {result}"));
    let parameters = signature["parameters"]
        .as_array()
        .unwrap_or_else(|| panic!("expected signature parameters, got {result}"));
    assert_eq!(
        parameters.len(),
        expected.len(),
        "unexpected parameter count in {result}"
    );

    for (parameter, expected_label) in parameters.iter().zip(expected) {
        let offsets = parameter["label"]
            .as_array()
            .unwrap_or_else(|| panic!("expected label offsets, got {result}"));
        assert_eq!(offsets.len(), 2, "expected two label offsets in {result}");
        let start = offsets[0]
            .as_u64()
            .unwrap_or_else(|| panic!("expected start offset, got {result}"))
            as usize;
        let end = offsets[1]
            .as_u64()
            .unwrap_or_else(|| panic!("expected end offset, got {result}"))
            as usize;
        assert_eq!(
            &label[start..end],
            *expected_label,
            "unexpected parameter label range in {result}"
        );
    }
}

fn position_after(source: &str, needle: &str) -> (u64, u64) {
    let byte_offset = source.find(needle).expect("needle exists") + needle.len();
    let before = &source[..byte_offset];
    let line = before.bytes().filter(|byte| *byte == b'\n').count() as u64;
    let line_start = before.rfind('\n').map(|index| index + 1).unwrap_or(0);
    let character = source[line_start..byte_offset].chars().count() as u64;
    (line, character)
}

fn assert_call_range(ranges: &Value, line: u64, start_character: u64, end_character: u64) {
    let ranges = ranges
        .as_array()
        .unwrap_or_else(|| panic!("expected call range array, got {ranges}"));
    assert!(
        ranges.iter().any(|range| {
            range["start"]["line"] == line
                && range["start"]["character"] == start_character
                && range["end"]["line"] == line
                && range["end"]["character"] == end_character
        }),
        "expected call range {line}:{start_character}-{end_character}, got {ranges:#?}"
    );
}

fn shutdown_lsp(
    mut child: std::process::Child,
    mut stdin: std::process::ChildStdin,
    mut reader: BufReader<std::process::ChildStdout>,
    mut stderr: std::process::ChildStderr,
) {
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[cfg(unix)]
fn write_stub_command(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, body).expect("write stub command");
    let mut permissions = fs::metadata(path).expect("stub metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod stub command");
}

#[cfg(unix)]
fn formatting_response(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    file_uri: &str,
) -> Value {
    write_message(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "textDocument/formatting",
            "params": {
                "textDocument": {"uri": file_uri},
                "options": {"tabSize": 4, "insertSpaces": true}
            }
        }),
    );
    read_response_for_id(reader, stderr, id)
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_uses_did_open_overlay() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("upper-format");
    fs::write(&file_path, "fn disk() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\ntr '[:lower:]' '[:upper:]'\n");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "rust",
                    "version": 1,
                    "text": "fn overlay() {}\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    let response = formatting_response(&mut stdin, &mut reader, &mut stderr, 10, &file_uri);
    let edits = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
    assert_eq!(
        edits.len(),
        1,
        "expected one full-document edit: {response}"
    );
    assert_eq!(edits[0]["newText"], "FN OVERLAY() {}\n");
    assert_eq!(edits[0]["range"]["start"]["line"], 0);
    assert_eq!(edits[0]["range"]["start"]["character"], 0);
    assert_eq!(edits[0]["range"]["end"]["line"], 1);
    assert_eq!(edits[0]["range"]["end"]["character"], 0);

    shutdown_lsp(child, stdin, reader, stderr);
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_suppresses_stale_snapshot_edits() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("slow-upper-format");
    fs::write(&file_path, "fn disk() {}\n").expect("write disk file");
    write_stub_command(
        &stub_path,
        "#!/bin/sh\nsleep 1\ntr '[:lower:]' '[:upper:]'\n",
    );

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "rust",
                    "version": 1,
                    "text": "fn before() {}\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "textDocument/formatting",
            "params": {
                "textDocument": {"uri": file_uri},
                "options": {"tabSize": 4, "insertSpaces": true}
            }
        }),
    );
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": file_uri, "version": 2},
                "contentChanges": [{"text": "fn after() {}\n"}]
            }
        }),
    );

    let response = read_response_for_id(&mut reader, &mut stderr, 10);
    let edits = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
    assert!(
        edits.is_empty(),
        "expected stale formatting response to be suppressed, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_cancel_stops_active_formatter() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("slow-format");
    fs::write(&file_path, "fn main() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\nsleep 10\ncat\n");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "textDocument/formatting",
            "params": {
                "textDocument": {"uri": file_uri},
                "options": {"tabSize": 4, "insertSpaces": true}
            }
        }),
    );
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "$/cancelRequest",
            "params": {"id": 10}
        }),
    );

    let response = read_response_for_id(&mut reader, &mut stderr, 10);
    assert_eq!(response["error"]["code"], -32800, "{response}");
    let message = response["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("cancelled"), "{response}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_shutdown_cancels_active_formatter() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("slow-format");
    fs::write(&file_path, "fn main() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\nsleep 10\ncat\n");

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "textDocument/formatting",
            "params": {
                "textDocument": {"uri": file_uri},
                "options": {"tabSize": 4, "insertSpaces": true}
            }
        }),
    );

    let started = std::time::Instant::now();
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "shutdown waited for slow formatter instead of cancelling it"
    );
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_returns_empty_edits_for_noop() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("cat-format");
    fs::write(&file_path, "fn unchanged() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\ncat\n");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    let response = formatting_response(&mut stdin, &mut reader, &mut stderr, 10, &file_uri);
    let edits = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
    assert!(
        edits.is_empty(),
        "expected no-op formatting edits: {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_respects_configured_cwd() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let package = root.join("pkg");
    fs::create_dir_all(&package).expect("create package");
    let file_path = package.join("lib.rs");
    let stub_path = root.join("pwd-format");
    fs::write(&file_path, "fn main() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\npwd\n");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["pkg/*.rs"],
                    "command": stub_path.display().to_string(),
                    "cwd": "pkg"
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    let response = formatting_response(&mut stdin, &mut reader, &mut stderr, 10, &file_uri);
    let edits = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
    assert_eq!(edits[0]["newText"], format!("{}\n", package.display()));

    shutdown_lsp(child, stdin, reader, stderr);
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_reports_formatter_failure() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("fail-format");
    fs::write(&file_path, "fn main() {}\n").expect("write disk file");
    write_stub_command(
        &stub_path,
        "#!/bin/sh\necho formatter exploded >&2\nexit 7\n",
    );

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    let response = formatting_response(&mut stdin, &mut reader, &mut stderr, 10, &file_uri);
    let error = response["error"]["message"].as_str().unwrap_or_default();
    assert!(error.contains("formatter exploded"), "{response}");
    assert!(error.contains("exited with status"), "{response}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_did_open_overlay_drives_hover_identifier() {
    // Disk content vs. opened buffer differ in the identifier at (line 0, char 5).
    // Verifies that did{Open,Change,Close} drive both the analyzer reparse and
    // the request-time identifier extraction.
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn original() {}\n").expect("write disk");

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    // didOpen with overlay content — different function name than disk.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "rust",
                    "version": 1,
                    "text": "fn overlay_only() {}\n"
                }
            }
        }),
    );
    // didOpen emits a publishDiagnostics — drain it before the request.
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            }
        }),
    );
    let hover_open = read_response_for_id(&mut reader, &mut stderr, 10);
    let hover_text_open = hover_open["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        hover_text_open.contains("overlay_only"),
        "hover should reflect didOpen overlay, got {hover_text_open}"
    );
    assert!(
        !hover_text_open.contains("original"),
        "hover should NOT show on-disk identifier while overlay is active, got {hover_text_open}"
    );

    // didChange replaces the buffer.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": file_uri, "version": 2},
                "contentChanges": [{"text": "fn changed() {}\n"}]
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            }
        }),
    );
    let hover_changed = read_response_for_id(&mut reader, &mut stderr, 11);
    let hover_text_changed = hover_changed["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        hover_text_changed.contains("changed"),
        "hover should reflect didChange overlay, got {hover_text_changed}"
    );
    assert!(
        !hover_text_changed.contains("overlay_only"),
        "hover should NOT show pre-change overlay after didChange, got {hover_text_changed}"
    );

    // didClose drops the overlay; disk content reasserts.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": file_uri}}
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            }
        }),
    );
    let hover_closed = read_response_for_id(&mut reader, &mut stderr, 12);
    let hover_text_closed = hover_closed["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        hover_text_closed.contains("original"),
        "after didClose, hover should reflect disk content, got {hover_text_closed}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_did_change_completion_finds_overlay_only_symbol() {
    // A Rust file on disk has nothing matching `mark`. didOpen + didChange
    // introduce `mark_overlay_42`. Completion at prefix `mark` must surface it
    // — proving the analyzer reparsed against overlay content AND that
    // completion's mtime cache was bypassed for the overlaid file.
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn placeholder() {}\n").expect("write disk");

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "rust",
                    "version": 1,
                    "text": "fn placeholder() {}\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    // The overlay introduces `mark_overlay_42` followed by a partial call at
    // position (2, 4) so the completion prefix on the cursor is `mark`.
    let overlay_text = "fn mark_overlay_42() {}\nfn caller() {\n    mark\n}\n";
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": file_uri, "version": 2},
                "contentChanges": [{"text": overlay_text}]
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 2, "character": 8}
            }
        }),
    );
    let completion = read_response_for_id(&mut reader, &mut stderr, 20);
    let items = completion["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected completion items array, got {completion}"));
    let labels: Vec<String> = items
        .iter()
        .filter_map(|item| item["label"].as_str().map(str::to_string))
        .collect();
    assert!(
        labels.iter().any(|label| label == "mark_overlay_42"),
        "expected `mark_overlay_42` in completion results, got {labels:?}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_did_close_reverts_completion_to_disk() {
    // After didOpen + didClose, the overlay symbol vanishes from completion
    // results. Guards against state leakage of the overlay across close.
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn disk_placeholder() {}\n").expect("write disk");

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "rust",
                    "version": 1,
                    "text": "fn unique_overlay_token() {}\nfn caller() {\n    uniqu\n}\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": file_uri}}
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    // Disk content has no `unique` symbol; completion (across the workspace)
    // for prefix `unique` must return nothing matching the overlay symbol.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "workspace/symbol",
            "params": {"query": "unique_overlay_token"}
        }),
    );
    let symbols = read_response_for_id(&mut reader, &mut stderr, 30);
    let names: Vec<String> = symbols["result"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !names.iter().any(|n| n == "unique_overlay_token"),
        "overlay symbol should be gone after didClose, got {names:?}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_malformed_didchange_drops_silently_to_client() {
    // A non-conforming client that sends `didChange` events with `range`
    // populated (INCREMENTAL semantics) despite our advertising
    // `TextDocumentSyncKind::FULL` must NOT trigger a parse or a
    // publishDiagnostics — we have no way to apply the partial edits and
    // applying any one of them as a full document would silently truncate
    // the buffer.
    //
    // The visible contract this test pins is the absence of side effects:
    // a hover request issued immediately after the malformed didChange
    // must receive its response without an interleaved publishDiagnostics
    // notification. (Stderr does carry a throttled warning; capturing
    // child stderr deterministically is too flaky to assert on here.)
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn original() {}\n").expect("write disk");

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    // didOpen establishes an overlay and produces one publishDiagnostics.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "rust",
                    "version": 1,
                    "text": "fn original() {}\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    // Malformed didChange: a single content_change with a populated range.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": file_uri, "version": 2},
                "contentChanges": [{
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 0}
                    },
                    "text": "this would be an incremental edit"
                }]
            }
        }),
    );

    // The server should drop the notification with no publishDiagnostics.
    // We can't assert "no message" without a timeout, but we can prove the
    // next message off the wire is the hover response (not a diagnostics
    // notification interleaved before it), since LSP messages are processed
    // serially.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            }
        }),
    );

    // Read the very next inbound message. If the malformed didChange had
    // emitted publishDiagnostics, the notification would arrive first.
    let next = read_message(&mut reader, &mut stderr);
    assert_eq!(
        next["id"].as_u64(),
        Some(40),
        "expected hover response (id 40) as the next message; \
         malformed didChange must not emit publishDiagnostics: {next}"
    );

    // Overlay must still reflect the pre-malformed-didChange state.
    let hover_text = next["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("original"),
        "hover should still see the didOpen overlay content, got {hover_text}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

/// Read messages until a notification with `expected_method` arrives. Skips
/// any other inbound traffic so callers don't have to know the exact ordering
/// of unrelated server-to-client messages.
fn read_notification(
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    expected_method: &str,
) -> Value {
    for _ in 0..32 {
        let msg = read_message(reader, stderr);
        if msg["method"] == expected_method {
            return msg;
        }
    }
    panic!("did not receive {expected_method} within 32 messages");
}

/// Read messages until the response with the given id arrives, skipping
/// notifications (e.g. publishDiagnostics) the server may interleave.
fn read_response_for_id(reader: &mut impl BufRead, stderr: &mut impl Read, id: u64) -> Value {
    for _ in 0..32 {
        let msg = read_message(reader, stderr);
        if msg["id"].as_u64() == Some(id) {
            return msg;
        }
    }
    panic!("did not receive response with id {id} within 32 messages");
}

fn type_definition_response(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    file_uri: &str,
    line: u64,
    character: u64,
) -> Value {
    text_document_position_response(
        stdin,
        reader,
        stderr,
        id,
        "textDocument/typeDefinition",
        file_uri,
        line,
        character,
    )
}

#[allow(clippy::too_many_arguments)]
fn text_document_position_response(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    method: &str,
    file_uri: &str,
    line: u64,
    character: u64,
) -> Value {
    write_message(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character}
            }
        }),
    );
    read_response_for_id(reader, stderr, id)
}

#[allow(clippy::too_many_arguments)]
fn references_response(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    file_uri: &str,
    line: u64,
    character: u64,
    include_declaration: bool,
) -> Value {
    write_message(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "textDocument/references",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character},
                "context": {"includeDeclaration": include_declaration}
            }
        }),
    );
    read_response_for_id(reader, stderr, id)
}

struct LspTestClient {
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    stderr: ChildStderr,
    next_id: u64,
}

impl LspTestClient {
    fn new(
        stdin: ChildStdin,
        reader: BufReader<ChildStdout>,
        stderr: ChildStderr,
        next_id: u64,
    ) -> Self {
        Self {
            stdin,
            reader,
            stderr,
            next_id,
        }
    }

    fn into_parts(self) -> (ChildStdin, BufReader<ChildStdout>, ChildStderr) {
        (self.stdin, self.reader, self.stderr)
    }

    fn text_document_position_response(
        &mut self,
        method: &str,
        file_uri: &str,
        line: u64,
        character: u64,
    ) -> Value {
        let id = self.next_id();
        text_document_position_response(
            &mut self.stdin,
            &mut self.reader,
            &mut self.stderr,
            id,
            method,
            file_uri,
            line,
            character,
        )
    }

    fn references_response(
        &mut self,
        file_uri: &str,
        line: u64,
        character: u64,
        include_declaration: bool,
    ) -> Value {
        let id = self.next_id();
        references_response(
            &mut self.stdin,
            &mut self.reader,
            &mut self.stderr,
            id,
            file_uri,
            line,
            character,
            include_declaration,
        )
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

#[derive(Clone, Copy)]
enum BroadEndpoint {
    Definition,
    Hover,
    References,
    DocumentHighlight,
}

impl BroadEndpoint {
    fn label(self) -> &'static str {
        match self {
            Self::Definition => "definition",
            Self::Hover => "hover",
            Self::References => "references",
            Self::DocumentHighlight => "documentHighlight",
        }
    }
}

fn invalid_context_targets() -> Vec<(&'static str, u64, u64)> {
    [
        (
            "string literal",
            position_after(INVALID_CONTEXTS_SOURCE, "\""),
        ),
        (
            "ambiguous type reference",
            position_after(INVALID_CONTEXTS_SOURCE, "        "),
        ),
        (
            "unresolved expression",
            position_after(INVALID_CONTEXTS_SOURCE, "int value = "),
        ),
        (
            "keyword",
            position_after(INVALID_CONTEXTS_SOURCE, "        if"),
        ),
    ]
    .into_iter()
    .map(|(label, (line, character))| (label, line, character))
    .collect()
}

fn collect_invalid_context_endpoint_responses(
    client: &mut LspTestClient,
    file_uri: &str,
    endpoint: BroadEndpoint,
) -> Vec<(&'static str, Value)> {
    invalid_context_targets()
        .into_iter()
        .map(|(label, line, character)| {
            let response = endpoint_response(client, file_uri, endpoint, line, character);
            (label, response)
        })
        .collect()
}

fn endpoint_response(
    client: &mut LspTestClient,
    file_uri: &str,
    endpoint: BroadEndpoint,
    line: u64,
    character: u64,
) -> Value {
    match endpoint {
        BroadEndpoint::Definition => client.text_document_position_response(
            "textDocument/definition",
            file_uri,
            line,
            character,
        ),
        BroadEndpoint::Hover => {
            client.text_document_position_response("textDocument/hover", file_uri, line, character)
        }
        BroadEndpoint::References => client.references_response(file_uri, line, character, true),
        BroadEndpoint::DocumentHighlight => client.text_document_position_response(
            "textDocument/documentHighlight",
            file_uri,
            line,
            character,
        ),
    }
}

fn assert_no_invalid_context_results(endpoint: BroadEndpoint, responses: &[(&'static str, Value)]) {
    for (label, response) in responses {
        let no_result = match endpoint {
            BroadEndpoint::Definition | BroadEndpoint::Hover => response["result"].is_null(),
            BroadEndpoint::References | BroadEndpoint::DocumentHighlight => {
                response["result"].is_null()
                    || response["result"]
                        .as_array()
                        .is_some_and(|items| items.is_empty())
            }
        };
        assert!(
            no_result,
            "{label} must not produce {} result, got {response}",
            endpoint.label()
        );
    }
}

fn implementation_response(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    file_uri: &str,
    line: u64,
    character: u64,
) -> Value {
    text_document_position_response(
        stdin,
        reader,
        stderr,
        id,
        "textDocument/implementation",
        file_uri,
        line,
        character,
    )
}

fn write_message(stdin: &mut impl Write, payload: Value) {
    let body = serde_json::to_string(&payload).expect("serialize");
    write!(stdin, "Content-Length: {}\r\n\r\n{}", body.len(), body).expect("write");
    stdin.flush().expect("flush");
}

fn read_message(reader: &mut impl BufRead, stderr: &mut impl Read) -> Value {
    let mut content_length: Option<usize> = None;
    loop {
        let mut header = String::new();
        let bytes = reader.read_line(&mut header).expect("read header");
        if bytes == 0 {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            panic!("server closed; stderr:\n{buf}");
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length: ") {
            content_length = Some(rest.parse().expect("Content-Length value"));
        }
    }
    let len = content_length.expect("missing Content-Length header");
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).expect("read body");
    serde_json::from_slice(&body).expect("valid json response")
}
