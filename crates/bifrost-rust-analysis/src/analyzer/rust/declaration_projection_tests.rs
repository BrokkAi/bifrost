//! Differential boundary checks: one admitted/repaired tree, two consumers.
use super::adapter::RustAdapter;
use brokk_bifrost_analysis::analyzer::source_admission::SourceAdmissionPolicy;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
    BoundedParse, COMPLETE_FILE_PARSE_BUDGET, LanguageAdapter, parse_admitted_source_with_policy,
    set_parser_for_file,
};
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_core::analyzer::parsed_file::DeclarationProjection;
use brokk_bifrost_core::analyzer::project::decode_source_bytes;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

const CORPUS_COMMIT: &str = "2af7f650626e73c402db22ad40ae886bf5778926";
const LARGE_FILES: [&str; 14] = [
    "crates/bifrost-store/src/analyzer/resolution/fact_resolution.rs",
    "crates/bifrost-policy/src/taint_policy.rs",
    "crates/bifrost-store/src/analyzer/store/mod.rs",
    "crates/bifrost-cpp/src/declarations.rs",
    "crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs",
    "crates/bifrost-go-analysis/src/analyzer/go/semantic.rs",
    "crates/bifrost-rust-analysis/src/analyzer/rust/semantic.rs",
    "crates/bifrost-cpp/src/graph/resolver.rs",
    "crates/bifrost-flow/src/flow_state.rs",
    "crates/bifrost-rust/src/resolution.rs",
    "crates/bifrost-jvm-analysis/src/analyzer/jvm/external.rs",
    "crates/bifrost-store/src/analyzer/store/resolution_operation/jvm_context.rs",
    "crates/bifrost-mcp/src/searchtools_service.rs",
    "crates/bifrost-store/src/analyzer/resolution/batch.rs",
];

fn ordered_units(projection: &DeclarationProjection) -> Vec<CodeUnit> {
    let mut units = projection
        .declarations()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    units.sort();
    units
}

fn admitted_tree(adapter: &RustAdapter, file: &ProjectFile, source: &str) -> BoundedParse {
    let mut parser = tree_sitter::Parser::new();
    assert!(set_parser_for_file(&mut parser, adapter, file, source));
    parse_admitted_source_with_policy(
        &mut parser,
        adapter,
        source,
        None,
        Instant::now() + COMPLETE_FILE_PARSE_BUDGET,
        SourceAdmissionPolicy::from_setting(None),
    )
}

#[test]
fn declaration_projection_matches_full_fixture_with_embedded_items_and_recovery() {
    let root = tempfile::tempdir().unwrap();
    for (path, source) in [
        (
            "src/lib.rs",
            include_str!("../../../tests/fixtures/declaration-projection/items.rs"),
        ),
        (
            "src/recovered.rs",
            include_str!("../../../tests/fixtures/declaration-projection/recovered.rs"),
        ),
    ] {
        let file = ProjectFile::new(root.path(), Path::new(path));
        let adapter = RustAdapter::ownerless();
        let BoundedParse::Complete(tree) = admitted_tree(&adapter, &file, source) else {
            panic!("fixture must be admitted: {path}");
        };
        assert_eq!(tree.root_node().kind(), "source_file", "{path}");
        if path == "src/recovered.rs" {
            assert!(
                tree.root_node().has_error(),
                "fixture must exercise recovery"
            );
        }
        let full = adapter
            .parse_file(&file, source, &tree)
            .into_declaration_projection();
        let light = adapter.parse_declaration_projection(&file, source, &tree);
        assert_eq!(ordered_units(&full), ordered_units(&light), "{path}");
        assert_eq!(full, light, "{path}");
    }
}

fn panic_text(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = panic.downcast_ref::<String>() {
        text.clone()
    } else if let Some(text) = panic.downcast_ref::<&str>() {
        (*text).to_string()
    } else {
        "non-string extraction panic".to_string()
    }
}

/// Explicit corpus campaign; never a dependency on an external checkout in CI.
/// Set BIFROST_DECLARATION_CORPUS to a complete git-archive snapshot of
/// CORPUS_COMMIT, BIFROST_DECLARATION_CORPUS_REPOSITORY to the read-only Git
/// repository containing that commit, and BIFROST_DECLARATION_LEDGER to a new
/// output path outside the snapshot. No source/fixture paths are filtered.
#[test]
#[ignore = "explicit fixed-corpus differential; requires snapshot and ledger paths"]
fn declaration_projection_matches_every_fixed_corpus_rust_path() {
    let required_path = |name| {
        let path = PathBuf::from(std::env::var_os(name).expect(name));
        assert!(path.is_absolute(), "{name} must be absolute");
        path
    };
    let root = required_path("BIFROST_DECLARATION_CORPUS");
    let repository = required_path("BIFROST_DECLARATION_CORPUS_REPOSITORY");
    let ledger_path = required_path("BIFROST_DECLARATION_LEDGER");
    assert!(
        !ledger_path.starts_with(&root),
        "ledger must be outside corpus"
    );
    assert!(
        std::env::var_os("BIFROST_MAX_LINE_LENGTH").is_none(),
        "campaign uses default admission policy"
    );
    let repo = git2::Repository::open(repository).unwrap();
    let commit = repo
        .find_commit(git2::Oid::from_str(CORPUS_COMMIT).unwrap())
        .unwrap();
    let mut pending = vec![(commit.tree_id(), PathBuf::new())];
    let mut files = Vec::new();
    while let Some((oid, parent)) = pending.pop() {
        let tree = repo.find_tree(oid).unwrap();
        for entry in &tree {
            let path = parent.join(entry.name().expect("fixed corpus has UTF-8 paths"));
            if entry.kind() == Some(git2::ObjectType::Tree) {
                pending.push((entry.id(), path));
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                assert_eq!(entry.filemode(), 0o100644, "{path:?}");
                files.push((path, entry.id()));
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(files.len(), 5735, "fixed corpus denominator changed");
    let mut ledger = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&ledger_path)
            .unwrap(),
    );
    let mut counts = BTreeMap::<String, usize>::new();
    let mut large = BTreeMap::new();
    for (ordinal, (path, oid)) in files.iter().enumerate() {
        let mut row =
            serde_json::json!({"ordinal": ordinal, "path": path, "blob_oid": oid.to_string()});
        let bytes = std::fs::read(root.join(path)).unwrap();
        assert_eq!(
            git2::Oid::hash_object(git2::ObjectType::Blob, &bytes).unwrap(),
            *oid,
            "snapshot mismatch: {path:?}"
        );
        let status = match decode_source_bytes(bytes) {
            Err(error) => {
                row["detail"] = serde_json::json!(error.to_string());
                "decode_refused"
            }
            Ok(source) => {
                let adapter = RustAdapter::ownerless();
                let file = ProjectFile::new(&root, path);
                match admitted_tree(&adapter, &file, &source) {
                    BoundedParse::Refused(reason) => {
                        row["detail"] = serde_json::json!(format!("{reason:?}"));
                        "admission_refused"
                    }
                    BoundedParse::Cancelled => "admission_cancelled",
                    BoundedParse::TimedOut => "admission_timed_out",
                    BoundedParse::Rejected => "admission_rejected",
                    BoundedParse::Complete(tree) => {
                        row["recovered_tree"] = serde_json::json!(tree.root_node().has_error());
                        let full = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            adapter
                                .parse_file(&file, &source, &tree)
                                .into_declaration_projection()
                        }));
                        let light = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            adapter.parse_declaration_projection(&file, &source, &tree)
                        }));
                        match (full, light) {
                            (Ok(full), Ok(light)) => {
                                let ordered_equal = ordered_units(&full) == ordered_units(&light);
                                row["canonical_order_equal"] = serde_json::json!(ordered_equal);
                                row["declarations"] = serde_json::json!(full.declarations().len());
                                row["fields_equal"] = serde_json::json!({
                                    "declarations": full.declarations() == light.declarations(),
                                    "signatures": full.signatures == light.signatures,
                                    "ranges": full.ranges == light.ranges,
                                    "test_regions": full.test_region_units == light.test_region_units,
                                    "imports": full.imports == light.imports,
                                });
                                if full == light && ordered_equal {
                                    "equal"
                                } else {
                                    std::fs::write(
                                        ledger_path.with_extension(format!("{ordinal}.full.txt")),
                                        format!("{full:#?}"),
                                    )
                                    .unwrap();
                                    std::fs::write(
                                        ledger_path.with_extension(format!("{ordinal}.light.txt")),
                                        format!("{light:#?}"),
                                    )
                                    .unwrap();
                                    "mismatch"
                                }
                            }
                            (full, light) => {
                                row["full_panic"] = serde_json::json!(full.err().map(panic_text));
                                row["light_panic"] = serde_json::json!(light.err().map(panic_text));
                                "extraction_panic"
                            }
                        }
                    }
                }
            }
        };
        row["status"] = serde_json::json!(status);
        *counts.entry(status.to_string()).or_default() += 1;
        let rel = brokk_bifrost_core::path_utils::workspace_relative_slash_path(path);
        if LARGE_FILES.contains(&rel.as_str()) {
            large.insert(rel, status.to_string());
        }
        writeln!(ledger, "{row}").unwrap();
        ledger.flush().unwrap();
    }
    let summary = serde_json::json!({"commit":CORPUS_COMMIT,"total":files.len(),"counts":counts,"large_files":large});
    writeln!(ledger, "{summary}").unwrap();
    ledger.flush().unwrap();
    eprintln!("{summary}");
    assert_eq!(large.len(), 14, "all named large files must be visited");
    assert_eq!(counts.get("mismatch").copied().unwrap_or(0), 0, "{summary}");
    assert_eq!(
        counts.get("extraction_panic").copied().unwrap_or(0),
        0,
        "{summary}"
    );
    assert_eq!(
        counts.get("admission_cancelled").copied().unwrap_or(0),
        0,
        "{summary}"
    );
    assert_eq!(counts.values().sum::<usize>(), 5735);
}
