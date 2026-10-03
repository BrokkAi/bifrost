//! An incremental `WorkspaceAnalyzer::update` that reports only `Cargo.toml`
//! edits must publish what a fresh build of the edited tree publishes
//! (#3749, plan step 1).
//!
//! `Cargo.toml` has no language of its own, so the workspace analyzer decides
//! per delegate whether a changed manifest reaches it. These tests compare,
//! after each edit, the incrementally updated analyzer with a fresh ephemeral
//! build of the same tree on the observable results: the current crate rows
//! (membership, dependencies, imports, gaps), the declaration names, and the
//! cross-crate edges of the usage graph.

use std::collections::BTreeSet;

use rusqlite::Connection;

use crate::AnalyzerConfig;
use crate::analyzer::WorkspaceAnalyzer;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use crate::searchtools::{UsageGraphParams, usage_graph};

const WORKSPACE: &str = "[workspace]\nmembers = [\"app\", \"dep\"]\nresolver = \"2\"\n";
const DEP_MANIFEST: &str = "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
const APP_MANIFEST_WITH_DEP: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ndep = { path = \"../dep\" }\n";
const APP_MANIFEST_WITHOUT_DEP: &str =
    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
const DEP_LIB: &str = "pub fn target() {}\n";
const APP_LIB: &str = "use dep::target;\npub fn caller() { target(); }\n";

/// What a caller can observe of a workspace analyzer's Rust state.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Observed {
    crates: Vec<String>,
    dependencies: Vec<String>,
    imports: Vec<String>,
    gaps: Vec<String>,
    declarations: BTreeSet<String>,
    edges: BTreeSet<String>,
    /// The manifest bytes the store retains for the head revision.
    manifests: Vec<String>,
    /// Whether the crate rows are marked current at the head revision, so a
    /// warm start skips the full crate reconcile.
    crate_rows_current: bool,
}

fn rows(conn: &Connection, sql: &str) -> Vec<String> {
    conn.prepare(sql)
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

/// Rows are keyed by crate name, not by crate key or topology id, so two
/// workspaces at different times compare equal exactly when the crates they
/// publish mean the same thing.
fn observe(workspace: &WorkspaceAnalyzer) -> Observed {
    let store = workspace.store().expect("the workspace has a store");
    let conn = store.read_conn().unwrap();
    let crates = rows(
        &conn,
        "SELECT t.crate_name || ' ' || t.target_kind || ' ' || t.edition \
         || ' complete=' || t.inventory_complete \
         FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) \
         WHERE v.valid_until IS NULL ORDER BY 1",
    );
    let dependencies = rows(
        &conn,
        "SELECT t.crate_name || ' ' || t.target_kind || ' -> ' || d.extern_name || ' ' \
         || d.boundary || ' ' || d.dependency_kind || ' ' \
         || coalesce((SELECT t2.crate_name FROM rust_crate_versions v2 \
              JOIN rust_crate_topologies t2 USING(topology_id) \
              WHERE v2.valid_until IS NULL AND v2.crate_key = d.dependency_crate_key), '-') \
         FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) \
         JOIN rust_crate_dependencies d USING(topology_id) \
         WHERE v.valid_until IS NULL ORDER BY 1",
    );
    let imports = rows(
        &conn,
        "SELECT t.crate_name || ' ' || i.module_path || ' ' || i.bound_name || ' => ' \
         || coalesce((SELECT t2.crate_name FROM rust_crate_versions v2 \
              JOIN rust_crate_topologies t2 USING(topology_id) \
              WHERE v2.valid_until IS NULL AND v2.crate_key = i.target_crate_key), '-') \
         || ' ' || i.target_module_path || ' ' || i.target_name \
         FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) \
         JOIN rust_crate_imports i USING(topology_id) \
         WHERE v.valid_until IS NULL ORDER BY 1",
    );
    let gaps = rows(
        &conn,
        "SELECT t.crate_name || ' ' || g.gap_kind || ' ' || g.subject \
         FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) \
         JOIN rust_crate_gaps g USING(topology_id) \
         WHERE v.valid_until IS NULL ORDER BY 1",
    );
    let manifests = rows(
        &conn,
        "SELECT v.rel_path || ': ' || CAST(s.source_bytes AS TEXT) \
         FROM workspace_file_versions v \
         JOIN workspace_input_sources s ON s.content_oid = v.blob_oid \
         WHERE v.lang = 'rust' AND v.input_kind = 'configuration' AND v.valid_until IS NULL \
         ORDER BY 1",
    );
    let crate_rows_current = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM rust_crate_reconciliations r \
             JOIN workspace_heads h ON h.workspace_id = r.workspace_id \
               AND h.generation = r.generation AND h.revision = r.revision \
             WHERE h.lang = 'rust')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let analyzer = workspace.analyzer();
    let declarations = analyzer
        .get_all_declarations()
        .into_iter()
        .map(|unit| format!("{} {}", unit.fq_name(), unit.source().rel_path().display()))
        .collect();
    let graph = usage_graph(
        analyzer,
        UsageGraphParams {
            include_tests: true,
            paths: None,
            depth: 1,
        },
    );
    let edges = graph
        .edges
        .iter()
        .map(|edge| format!("{} -> {}", edge.from, edge.to))
        .collect();
    Observed {
        crates,
        dependencies,
        imports,
        gaps,
        declarations,
        edges,
        manifests,
        crate_rows_current,
    }
}

fn fixture(files: &[(&str, &str)]) -> BuiltInlineTestProject {
    files
        .iter()
        .fold(InlineTestProject::new(), |project, (path, source)| {
            project.file(*path, *source)
        })
        .build()
}

/// What `edit_and_rebuild` returns.
struct Edited {
    /// What the analyzer looked like before the edit.
    before: Observed,
    updated: WorkspaceAnalyzer,
    /// A fresh build of the edited tree.
    fresh: WorkspaceAnalyzer,
    /// The full rebuilds (`update_all`) the update ran.
    full_updates: usize,
}

/// Apply `edits` (manifests only) to the built tree and feed exactly those
/// paths to `update`.
fn edit_and_rebuild(project: &BuiltInlineTestProject, edits: &[(&str, &str)]) -> Edited {
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let before = observe(&analyzer);
    let root = analyzer.analyzer().project().root().to_path_buf();
    let full_updates = crate::analyzer::tree_sitter_analyzer::full_update_count_for_test(&root);
    let mut changed = BTreeSet::new();
    for (path, source) in edits {
        let file = project.file(path);
        file.write(source).unwrap();
        changed.insert(file);
    }
    let updated = analyzer.update(&changed);
    let full_updates =
        crate::analyzer::tree_sitter_analyzer::full_update_count_for_test(&root) - full_updates;
    let fresh = project.workspace_analyzer(AnalyzerConfig::default());
    Edited {
        before,
        updated,
        fresh,
        full_updates,
    }
}

fn has_edge(observed: &Observed, from_suffix: &str, to_suffix: &str) -> bool {
    observed.edges.iter().any(|edge| {
        edge.split_once(" -> ")
            .is_some_and(|(from, to)| from.ends_with(from_suffix) && to.ends_with(to_suffix))
    })
}

/// (a) A crate is renamed through its manifest, and its dependent follows with
/// Cargo's `package =` key, so no Rust source changes.
#[test]
fn renaming_a_crate_in_its_manifest_matches_a_fresh_build() {
    let project = fixture(&[
        ("Cargo.toml", WORKSPACE),
        ("app/Cargo.toml", APP_MANIFEST_WITH_DEP),
        ("dep/Cargo.toml", DEP_MANIFEST),
        ("app/src/lib.rs", APP_LIB),
        ("dep/src/lib.rs", DEP_LIB),
    ]);
    let renamed_dep = DEP_MANIFEST.replace("name = \"dep\"", "name = \"dep2\"");
    let app_follows = APP_MANIFEST_WITH_DEP.replace(
        "dep = { path = \"../dep\" }",
        "dep = { path = \"../dep\", package = \"dep2\" }",
    );
    let Edited {
        before,
        updated,
        fresh,
        full_updates,
    } = edit_and_rebuild(
        &project,
        &[
            ("dep/Cargo.toml", &renamed_dep),
            ("app/Cargo.toml", &app_follows),
        ],
    );
    assert_eq!(full_updates, 1, "a crate rename rebuilds");
    let expected = observe(&fresh);
    assert!(
        expected
            .crates
            .iter()
            .any(|row| row.starts_with("dep2 lib")),
        "the fresh build sees the renamed crate: {:?}",
        expected.crates
    );
    assert_ne!(
        before.crates, expected.crates,
        "the edit must change crate rows"
    );
    assert_eq!(
        observe(&updated),
        expected,
        "the updated analyzer must publish what a fresh build of the edited tree publishes"
    );
}

/// (b) A path dependency is added, so a reference that used to resolve to
/// nothing now resolves across crates.
#[test]
fn adding_a_path_dependency_matches_a_fresh_build() {
    let project = fixture(&[
        ("Cargo.toml", WORKSPACE),
        ("app/Cargo.toml", APP_MANIFEST_WITHOUT_DEP),
        ("dep/Cargo.toml", DEP_MANIFEST),
        ("app/src/lib.rs", APP_LIB),
        ("dep/src/lib.rs", DEP_LIB),
    ]);
    let Edited {
        before,
        updated,
        fresh,
        full_updates,
    } = edit_and_rebuild(&project, &[("app/Cargo.toml", APP_MANIFEST_WITH_DEP)]);
    assert_eq!(full_updates, 1, "a new path dependency rebuilds");
    let expected = observe(&fresh);
    assert!(
        !has_edge(&before, "caller", "target"),
        "before the edit the cross-crate reference is unresolved: {:?}",
        before.edges
    );
    assert!(
        has_edge(&expected, "caller", "target"),
        "the fresh build resolves the new dependency: {:?}",
        expected.edges
    );
    assert_eq!(
        observe(&updated),
        expected,
        "the updated analyzer must publish what a fresh build of the edited tree publishes"
    );
}

/// Edit `app/Cargo.toml` in a way no crate row reads, and check that the update
/// is incremental and still publishes what a fresh build does, including the
/// exact new manifest bytes and current crate rows.
fn assert_manifest_edit_is_incremental(edited_app_manifest: &str) {
    let project = fixture(&[
        ("Cargo.toml", WORKSPACE),
        ("app/Cargo.toml", APP_MANIFEST_WITH_DEP),
        ("dep/Cargo.toml", DEP_MANIFEST),
        ("app/src/lib.rs", APP_LIB),
        ("dep/src/lib.rs", DEP_LIB),
    ]);
    let Edited {
        before,
        updated,
        fresh,
        full_updates,
    } = edit_and_rebuild(&project, &[("app/Cargo.toml", edited_app_manifest)]);
    assert_eq!(full_updates, 0, "the edit must not rebuild the workspace");
    let expected = observe(&fresh);
    assert!(
        has_edge(&expected, "caller", "target"),
        "the fixture has a cross-crate edge: {:?}",
        expected.edges
    );
    assert!(expected.crate_rows_current);
    assert_ne!(
        before.manifests, expected.manifests,
        "the store retains the edited bytes"
    );
    let unchanged_rows = |observed: &Observed| Observed {
        manifests: Vec::new(),
        ..observed.clone()
    };
    assert_eq!(
        unchanged_rows(&before),
        unchanged_rows(&expected),
        "the edit does not change what a fresh build derives"
    );
    assert_eq!(observe(&updated), expected);
}

/// (c) A comment-only manifest edit changes nothing observable.
#[test]
fn a_comment_only_manifest_edit_changes_nothing() {
    assert_manifest_edit_is_incremental(&format!(
        "# a comment that means nothing\n{APP_MANIFEST_WITH_DEP}"
    ));
}

/// (d) Package metadata, a profile and reformatting reach no crate row.
#[test]
fn a_metadata_and_profile_manifest_edit_changes_nothing() {
    assert_manifest_edit_is_incremental(
        "[package]\nedition = \"2021\"\nversion = \"0.2.0\"\nname = \"app\"\n\
         description = \"now described\"\n\n[dependencies]\ndep = { path = \"../dep\" }\n\n\
         [profile.release]\nopt-level = 3\n",
    );
}
