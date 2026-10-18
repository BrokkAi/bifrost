//! An incremental `WorkspaceAnalyzer::update` that reports only `Cargo.toml`
//! or `.cargo/config.toml` edits must publish what a fresh build of the edited
//! tree publishes (#3749, plan step 1; #3768).
//!
//! Neither file has a language of its own, so the workspace analyzer decides
//! per delegate whether a changed input reaches it. These tests compare,
//! after each edit, the incrementally updated analyzer with a fresh ephemeral
//! build of the same tree on the observable results: the current crate rows
//! (cfg set, modules, dependencies, imports, gaps), the declaration names, and
//! the cross-crate edges of the usage graph.

use std::collections::BTreeSet;

use brokk_bifrost_test_macros::hardwon;
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
    /// The modules each crate places: which `mod` declarations are active.
    modules: Vec<String>,
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
         || ' complete=' || t.inventory_complete || ' cfg=' || json(t.cfg_atoms) \
         FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) \
         WHERE v.valid_until IS NULL ORDER BY 1",
    );
    let modules = rows(
        &conn,
        "SELECT t.crate_name || ' ' || t.target_kind || ' ' || m.container_path || ' ' \
         || s.rel_path || ' ' || m.placement \
         FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) \
         JOIN rust_crate_containers m USING(topology_id) \
         JOIN rust_crate_container_sources s USING(topology_id, container_path) \
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
        modules,
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

/// Apply `edits` (Cargo inputs only) to the built tree and feed exactly those
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
#[hardwon("#3749: a manifest crate rename left incremental crate rows and graph edges stale")]
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
#[hardwon("#3749: a new path dependency stayed unresolved after incremental update")]
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
    assert_edit_is_incremental(
        &[
            ("Cargo.toml", WORKSPACE),
            ("app/Cargo.toml", APP_MANIFEST_WITH_DEP),
            ("dep/Cargo.toml", DEP_MANIFEST),
            ("app/src/lib.rs", APP_LIB),
            ("dep/src/lib.rs", DEP_LIB),
        ],
        "app/Cargo.toml",
        edited_app_manifest,
    );
}

/// Edit the Cargo input `path` of the tree `files` in a way no crate row
/// reads, and check that the update is incremental and still publishes what a
/// fresh build does, including the input's exact new bytes and current crate
/// rows.
fn assert_edit_is_incremental(files: &[(&str, &str)], path: &str, edited: &str) {
    let project = fixture(files);
    let Edited {
        before,
        updated,
        fresh,
        full_updates,
    } = edit_and_rebuild(&project, &[(path, edited)]);
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
#[hardwon("#3749: comment-only edits exposed overbroad Cargo identity invalidation")]
fn a_comment_only_manifest_edit_changes_nothing() {
    assert_manifest_edit_is_incremental(&format!(
        "# a comment that means nothing\n{APP_MANIFEST_WITH_DEP}"
    ));
}

/// `.cargo/config.toml` before each edit: only keys analysis does not read.
const CONFIG_WITHOUT_SETTINGS: &str = "[alias]\nb = \"build\"\n";
const APP_MANIFEST_WITH_REGISTRY_DEP: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ndep = \"0.1\"\n";
/// One module per cfg the configuration can settle.
const CFG_GATED_APP_LIB: &str = "#[cfg(fast_path)]\npub mod fast;\n\
     #[cfg(not(fast_path))]\npub mod slow;\n\
     #[cfg(unix)]\npub mod nix;\n\
     #[cfg(windows)]\npub mod win;\n\
     #[cfg(target_arch = \"wasm32\")]\npub mod wasm;\n";

fn configured_fixture(config_path: &str, app_manifest: &str) -> BuiltInlineTestProject {
    fixture(&[
        ("Cargo.toml", WORKSPACE),
        (config_path, CONFIG_WITHOUT_SETTINGS),
        ("app/Cargo.toml", app_manifest),
        ("dep/Cargo.toml", DEP_MANIFEST),
        ("app/src/lib.rs", CFG_GATED_APP_LIB),
        ("app/src/fast.rs", "pub fn fast() {}\n"),
        ("app/src/slow.rs", "pub fn slow() {}\n"),
        ("app/src/nix.rs", "pub fn nix() {}\n"),
        ("app/src/win.rs", "pub fn win() {}\n"),
        ("app/src/wasm.rs", "pub fn wasm() {}\n"),
        ("dep/src/lib.rs", DEP_LIB),
    ])
}

fn has_module(observed: &Observed, module: &str) -> bool {
    observed
        .modules
        .iter()
        .any(|row| row.starts_with(&format!("app lib {module} ")))
}

fn has_gap(observed: &Observed, kind: &str, module: &str) -> bool {
    observed.gaps.contains(&format!("app {kind} {module}"))
}

/// Edit `config_path` from keys no reader consumes to `edited`, and check that
/// the update rebuilds once and publishes what a fresh build of the edited
/// tree does. Returns the analyzer before the edit and the fresh build.
fn assert_configuration_edit_matches_a_fresh_build(
    project: &BuiltInlineTestProject,
    config_path: &str,
    edited: &str,
) -> (Observed, Observed) {
    let Edited {
        before,
        updated,
        fresh,
        full_updates,
    } = edit_and_rebuild(project, &[(config_path, edited)]);
    assert_eq!(
        full_updates, 1,
        "a configuration that changes crate rows rebuilds"
    );
    let expected = observe(&fresh);
    let derived = |observed: &Observed| Observed {
        manifests: Vec::new(),
        ..observed.clone()
    };
    assert_ne!(
        derived(&before),
        derived(&expected),
        "the edit must change what a fresh build derives"
    );
    assert_eq!(
        observe(&updated),
        expected,
        "the updated analyzer must publish what a fresh build of the edited tree publishes"
    );
    (before, expected)
}

/// `--cfg` rustflags activate `#[cfg(name)]` modules and deactivate
/// `#[cfg(not(name))]` ones. Without them both stay undecided, because a
/// build script could set the cfg.
#[test]
#[hardwon("#3768: Cargo rustflags cfg values were absent from incremental module selection")]
fn cfg_rustflags_in_cargo_configuration_activate_modules_like_a_fresh_build() {
    let project = configured_fixture(".cargo/config.toml", APP_MANIFEST_WITHOUT_DEP);
    let (before, expected) = assert_configuration_edit_matches_a_fresh_build(
        &project,
        ".cargo/config.toml",
        &format!("{CONFIG_WITHOUT_SETTINGS}[build]\nrustflags = [\"--cfg\", \"fast_path\"]\n"),
    );
    assert!(
        has_gap(&before, "unknown_activation", "crate::fast")
            && has_gap(&before, "unknown_activation", "crate::slow"),
        "without the flag both modules are undecided: {:?}",
        before.gaps
    );
    assert!(
        has_module(&expected, "crate::fast"),
        "the flag places the cfg(fast_path) module: {:?}",
        expected.modules
    );
    assert!(
        has_gap(&expected, "inactive_placement", "crate::slow")
            && !has_module(&expected, "crate::slow"),
        "the flag deactivates the cfg(not(fast_path)) module: {:?}",
        expected.gaps
    );
}

/// `build.target` selects that target's cfg set instead of the host's, here
/// through the legacy `.cargo/config`. The target is no CI host, so `unix`
/// and `windows` are both false and `target_arch = "wasm32"` is true.
#[test]
#[hardwon("#3768: Cargo build.target did not select its target cfg set")]
fn build_target_in_cargo_configuration_selects_its_cfg_set_like_a_fresh_build() {
    let project = configured_fixture(".cargo/config", APP_MANIFEST_WITHOUT_DEP);
    let (before, expected) = assert_configuration_edit_matches_a_fresh_build(
        &project,
        ".cargo/config",
        &format!("{CONFIG_WITHOUT_SETTINGS}[build]\ntarget = \"wasm32-unknown-unknown\"\n"),
    );
    assert!(
        has_gap(&before, "inactive_placement", "crate::wasm"),
        "the host is not wasm32: {:?}",
        before.gaps
    );
    assert!(
        has_module(&expected, "crate::wasm"),
        "the wasm32 target places the cfg(target_arch) module: {:?}",
        expected.modules
    );
    for module in ["crate::nix", "crate::win"] {
        assert!(
            has_gap(&expected, "inactive_placement", module) && !has_module(&expected, module),
            "{module} is inactive on wasm32: {:?}",
            expected.gaps
        );
    }
}

/// A `[patch]` in the configuration routes a registry dependency to the
/// workspace member it names, so the cross-crate reference resolves.
#[test]
#[hardwon("#3768: Cargo config patch routes were ignored during incremental analysis")]
fn a_patch_in_cargo_configuration_routes_the_dependency_like_a_fresh_build() {
    let project = fixture(&[
        ("Cargo.toml", WORKSPACE),
        (".cargo/config.toml", CONFIG_WITHOUT_SETTINGS),
        ("app/Cargo.toml", APP_MANIFEST_WITH_REGISTRY_DEP),
        ("dep/Cargo.toml", DEP_MANIFEST),
        ("app/src/lib.rs", APP_LIB),
        ("dep/src/lib.rs", DEP_LIB),
    ]);
    let (before, expected) = assert_configuration_edit_matches_a_fresh_build(
        &project,
        ".cargo/config.toml",
        &format!("{CONFIG_WITHOUT_SETTINGS}[patch.crates-io]\ndep = {{ path = \"dep\" }}\n"),
    );
    let routed = |observed: &Observed| {
        observed
            .dependencies
            .iter()
            .any(|row| row.starts_with("app lib -> dep ") && row.ends_with(" dep"))
    };
    assert!(
        !routed(&before),
        "without the patch dep is a registry crate: {:?}",
        before.dependencies
    );
    assert!(
        routed(&expected),
        "the patch routes dep to the member: {:?}",
        expected.dependencies
    );
    assert!(
        has_edge(&expected, "caller", "target"),
        "the patched route resolves the cross-crate reference: {:?}",
        expected.edges
    );
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

/// Comments and keys analysis does not read reach no crate row, so editing
/// them stays incremental, and the store still retains the new bytes.
#[test]
fn an_unread_cargo_configuration_edit_changes_nothing() {
    assert_edit_is_incremental(
        &[
            ("Cargo.toml", WORKSPACE),
            (
                ".cargo/config.toml",
                "[build]\nrustflags = [\"--cfg\", \"fast_path\"]\n",
            ),
            ("app/Cargo.toml", APP_MANIFEST_WITH_DEP),
            ("dep/Cargo.toml", DEP_MANIFEST),
            ("app/src/lib.rs", APP_LIB),
            ("dep/src/lib.rs", DEP_LIB),
        ],
        ".cargo/config.toml",
        "# a comment\n[alias]\nb = \"build\"\n\
         [build]\njobs = 4\nrustflags   =   [ \"--cfg\", \"fast_path\" ]\n\
         [env]\nRUST_LOG = \"debug\"\n\
         [target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\n",
    );
}

#[test]
#[hardwon("#5172: cfg_if arms did not follow selected Cargo context changes")]
fn cfg_if_context_changes_match_fresh_module_placements() {
    let lib = r#"cfg_if::cfg_if! {
    if #[cfg(windows)] { pub mod win; }
    else if #[cfg(any(windows, unix))] { pub mod nix; }
    else { pub mod other; }
}
pub fn caller() { win::run(); nix::run(); other::run(); }
"#;
    let project = fixture(&[
        ("Cargo.toml", WORKSPACE),
        ("app/Cargo.toml", APP_MANIFEST_WITHOUT_DEP),
        ("dep/Cargo.toml", DEP_MANIFEST),
        ("dep/src/lib.rs", DEP_LIB),
        ("app/src/lib.rs", lib),
        ("app/src/win.rs", "pub fn run() {}"),
        ("app/src/nix.rs", "pub fn run() {}"),
        ("app/src/other.rs", "pub fn run() {}"),
        (
            ".cargo/config.toml",
            "[build]\ntarget = [\"x86_64-pc-windows-msvc\", \"x86_64-unknown-linux-gnu\"]\n",
        ),
    ]);
    for (target, selected) in [
        ("x86_64-pc-windows-msvc", "win"),
        ("x86_64-unknown-linux-gnu", "nix"),
        ("wasm32-unknown-unknown", "other"),
    ] {
        let config = format!("[build]\ntarget = {target:?}\n");
        let (before, after) = assert_configuration_edit_matches_a_fresh_build(
            &project,
            ".cargo/config.toml",
            &config,
        );
        if selected == "win" {
            for name in ["win", "nix", "other"] {
                assert!(
                    has_gap(&before, "unknown_activation", &format!("crate::{name}")),
                    "{:?}",
                    before.gaps
                );
            }
        }
        for name in ["win", "nix", "other"] {
            assert_eq!(
                has_module(&after, &format!("crate::{name}")),
                name == selected,
                "{target}: {:?}",
                after.modules
            );
            if name != selected {
                assert!(
                    has_gap(&after, "inactive_placement", &format!("crate::{name}")),
                    "{target}: {:?}",
                    after.gaps
                );
            }
        }
        assert!(
            !has_gap(&after, "open_export_inventory", "crate"),
            "{target}: {:?}",
            after.gaps
        );
        assert!(
            has_edge(&after, "caller", &format!("{selected}.run")),
            "{target}: {:?}",
            after.edges
        );
    }
}
