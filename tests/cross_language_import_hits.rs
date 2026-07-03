//! `Import`-kind hit emission — pattern 3 from
//! `.agents/docs/PARITY_CROSS_LANGUAGE_GENERALIZATION.md`.
//!
//! When a symbol is imported into another file, LSP find-references should
//! report the *import binding* line (the token that brings the target into the
//! file), not just the call sites. These hits are tagged `UsageHitKind::Import`
//! so the call-graph / relevance surfaces filter them while find-references
//! includes them.
//!
//! Python emitted these already; this suite locks in the same behavior for the
//! JS/TS graph (ESM named + aliased imports).

mod common;

use common::lsp_client::LspServer;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Write `files` into a fresh project, place the caret from `caret_file`, run
/// `references` with `include_declaration = true`, and return the reported
/// `(basename, line)` pairs.
fn reference_sites(files: &[(&str, &str)], caret_file: &str) -> (TempDir, Vec<(String, u64)>) {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let mut caret = (0u64, 0u64);
    for (name, src) in files {
        let clean = if let Some(idx) = src.find("<caret>") {
            let before = &src[..idx];
            let line = before.matches('\n').count() as u64;
            let line_start = before.rfind('\n').map(|n| n + 1).unwrap_or(0);
            caret = (line, before[line_start..].chars().count() as u64);
            src.replacen("<caret>", "", 1)
        } else {
            src.to_string()
        };
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture parent");
        }
        std::fs::write(path, clean).expect("write fixture");
    }
    let caret_path: PathBuf = root.join(caret_file);
    let mut server = LspServer::start(&root);
    let locations = server.references(&caret_path, caret.0, caret.1, true);
    server.shutdown();
    let mut sites: Vec<(String, u64)> = locations
        .iter()
        .map(|loc| (basename_of_uri(&loc.uri), loc.line))
        .collect();
    sites.sort();
    (temp, sites)
}

fn basename_of_uri(uri: &str) -> String {
    Path::new(uri)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| uri.to_string())
}

fn assert_import_line_reported(files: &[(&str, &str)], caret_file: &str, import: (&str, u64)) {
    let (_t, sites) = reference_sites(files, caret_file);
    let want = (import.0.to_string(), import.1);
    assert!(
        sites.contains(&want),
        "expected import binding at {import:?} in references; got {sites:?}"
    );
}

#[test]
fn python_reports_import_binding() {
    assert_import_line_reported(
        &[
            ("a.py", "class <caret>Target:\n    pass\n"),
            ("b.py", "from a import Target\nTarget()\n"),
        ],
        "a.py",
        ("b.py", 0),
    );
}

#[test]
fn typescript_reports_named_import_binding() {
    assert_import_line_reported(
        &[
            ("a.ts", "export class <caret>Target {}\n"),
            ("b.ts", "import { Target } from \"./a\";\nnew Target();\n"),
        ],
        "a.ts",
        ("b.ts", 0),
    );
}

#[test]
fn javascript_reports_named_import_binding() {
    assert_import_line_reported(
        &[
            ("a.js", "export class <caret>Target {}\n"),
            (
                "b.js",
                "import { Target } from \"./a.js\";\nnew Target();\n",
            ),
        ],
        "a.js",
        ("b.js", 0),
    );
}

#[test]
fn typescript_reports_aliased_import_binding() {
    assert_import_line_reported(
        &[
            ("a.ts", "export class <caret>Target {}\n"),
            (
                "b.ts",
                "import { Target as Renamed } from \"./a\";\nnew Renamed();\n",
            ),
        ],
        "a.ts",
        ("b.ts", 0),
    );
}

#[test]
fn java_reports_import_binding() {
    assert_import_line_reported(
        &[
            (
                "Target.java",
                "package app;\n\npublic class <caret>Target {}\n",
            ),
            (
                "UseTarget.java",
                "package app;\n\nimport app.Target;\n\npublic class UseTarget { Target value; }\n",
            ),
        ],
        "Target.java",
        ("UseTarget.java", 2),
    );
}

#[test]
fn rust_reports_use_binding() {
    assert_import_line_reported(
        &[
            ("src/lib.rs", "pub mod target;\npub mod consumer;\n"),
            ("src/target.rs", "pub struct <caret>Target;\n"),
            (
                "src/consumer.rs",
                "use crate::target::Target;\n\nfn run(value: Target) {}\n",
            ),
        ],
        "src/target.rs",
        ("consumer.rs", 0),
    );
}

#[test]
fn php_reports_use_binding() {
    assert_import_line_reported(
        &[
            (
                "Target.php",
                "<?php\nnamespace App;\n\nclass <caret>Target {}\n",
            ),
            (
                "UseTarget.php",
                "<?php\nnamespace App\\Feature;\n\nuse App\\Target;\n\nclass UseTarget { public Target $value; }\n",
            ),
        ],
        "Target.php",
        ("UseTarget.php", 3),
    );
}

#[test]
fn scala_reports_import_binding() {
    assert_import_line_reported(
        &[
            ("Target.scala", "package app\n\nclass <caret>Target\n"),
            (
                "UseTarget.scala",
                "package app.feature\n\nimport app.Target\n\nclass UseTarget(value: Target)\n",
            ),
        ],
        "Target.scala",
        ("UseTarget.scala", 2),
    );
}
