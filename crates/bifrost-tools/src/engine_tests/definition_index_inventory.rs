//! The definition-index inventory enumerator against the visitor's own keys,
//! through real analyzers. The store-side matrix pins the enumerator on
//! synthetic rows; this pins the producer, which writes the anchored names and
//! the completeness state the enumerator depends on.

use brokk_bifrost_analysis::analyzer::CodeUnitIndex;
use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryContext, IAnalyzer};
use brokk_bifrost_analysis::analyzer::read_ledger::IndexFamily;
use brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex;
use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::parsed_fixture_state;
use brokk_bifrost_analysis::analyzer::store::{
    AnalyzerStore, DefinitionIndexCandidate, DefinitionInventoryState, ListedSnapshots,
    WorkspaceFileDefinitionInventory, WorkspaceFileRow, WorkspaceId,
};
use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;
use brokk_bifrost_analysis::analyzer::store_bridge::parsed_blob::prepare_parsed_blob;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::gitblob::BlobKey;
use brokk_bifrost_cpp_analysis::analyzer::cpp::CppAnalyzer;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
    LanguageAdapter, TreeSitterAnalyzer, WorkspaceBuildSnapshot, store_context_from_store,
};
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::MutableGenerationProject;
use brokk_bifrost_core::analyzer::project::{
    OverlayProject, Project, WorkspaceFileOmission, WorkspaceFileOmissionReason,
};
use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;
use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use brokk_bifrost_python_analysis::analyzer::python::PythonAdapter;
use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;
use brokk_bifrost_test_macros::hardwon;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

const FAMILIES: [IndexFamily; 4] = [
    IndexFamily::DefinitionExact,
    IndexFamily::DefinitionNormalizedTail,
    IndexFamily::DefinitionIdentifier,
    IndexFamily::PathSymbol,
];

/// A project whose listing reports omissions the test chooses. Unset, a test
/// project reports one `Unknown` omission, which cannot certify a listing.
fn omitting_project(
    language: Language,
    files: &[(&str, &str)],
) -> (tempfile::TempDir, MutableGenerationProject) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for (name, source) in files {
        ProjectFile::new(root.clone(), *name).write(source).unwrap();
    }
    let project = MutableGenerationProject::new(&root, language);
    project.set_omissions(Vec::new());
    (temp, project)
}

fn project(language: Language, files: &[(&str, &str)]) -> (tempfile::TempDir, Arc<dyn Project>) {
    let (temp, project) = omitting_project(language, files);
    (temp, Arc::new(project))
}

fn persisted<A: LanguageAdapter>(project: Arc<dyn Project>, adapter: A) -> TreeSitterAnalyzer<A> {
    let store = AnalyzerStore::open_persistent(&project.root().join("analyzer.db")).unwrap();
    let context = store_context_from_store(project.as_ref(), store, false);
    TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        project,
        adapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .unwrap()
}

/// Rebuilds with a full update, recapturing the project's listing.
fn listed<A: LanguageAdapter>(analyzer: TreeSitterAnalyzer<A>) -> TreeSitterAnalyzer<A> {
    analyzer.update_all()
}

fn blob_oid(source: &str) -> git2::Oid {
    git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap()
}

/// Every key any file emits, with the paths that emit it.
type VisitorKeys = BTreeMap<(&'static str, Vec<u8>), (IndexFamily, BTreeSet<String>)>;

fn visitor_keys<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    root: &std::path::Path,
    files: &[(&str, &str)],
) -> VisitorKeys {
    let mut keys: BTreeMap<_, (IndexFamily, BTreeSet<String>)> = BTreeMap::new();
    for (path, source) in files {
        let file = ProjectFile::new(root.to_path_buf(), *path);
        let entries = analyzer
            .blob_index_keys(&file, blob_oid(source))
            .unwrap_or_else(|| panic!("the visitor enumerates {path}"));
        for (family, key, _) in entries {
            if FAMILIES.contains(&family) {
                keys.entry((family.stable_label(), key.to_vec()))
                    .or_insert_with(|| (family, BTreeSet::new()))
                    .1
                    .insert((*path).to_string());
            }
        }
    }
    keys
}

/// The enumerator at the analyzer's own selected snapshots.
fn index_candidates<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    lang: &str,
    family: IndexFamily,
    key: &[u8],
) -> Option<Vec<DefinitionIndexCandidate>> {
    analyzer
        .analyzer_store()
        .index_blob_candidates_for_key_at(&analyzer.workspace_listing_proof(), lang, family, key)
        .unwrap()
}

/// The paths among the enumerator's candidates whose own visitor keys include
/// `(family, key)`. Candidates are a superset by contract; the visitor selects.
fn selected_candidates<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    root: &std::path::Path,
    sources: &BTreeMap<&str, &str>,
    lang: &str,
    family: IndexFamily,
    key: &[u8],
) -> Option<BTreeSet<String>> {
    let candidates = index_candidates(analyzer, lang, family, key)?;
    Some(
        candidates
            .into_iter()
            .filter(|candidate| {
                let path = candidate.mounted_path.to_string_lossy().into_owned();
                let source = sources[path.as_str()];
                assert_eq!(candidate.blob.oid, blob_oid(source), "{path}");
                let file = ProjectFile::new(root.to_path_buf(), PathBuf::from(&path));
                analyzer
                    .blob_index_keys(&file, candidate.blob.oid)
                    .unwrap()
                    .iter()
                    .any(|(emitted, emitted_key, _)| *emitted == family && &**emitted_key == key)
            })
            .map(|candidate| candidate.mounted_path.to_string_lossy().into_owned())
            .collect(),
    )
}

/// The completeness the design requires: every key some blob emits finds that
/// blob, and Some(empty) is returned only for a key nobody emits.
fn assert_inventory_matches_visitor<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    root: &std::path::Path,
    lang: &str,
    files: &[(&str, &str)],
) -> BTreeSet<&'static str> {
    let sources: BTreeMap<&str, &str> = files.iter().copied().collect();
    let expected = visitor_keys(analyzer, root, files);
    let mut families = BTreeSet::new();
    for ((_, key), (family, paths)) in &expected {
        let actual = selected_candidates(analyzer, root, &sources, lang, *family, key)
            .unwrap_or_else(|| panic!("{lang} inventory unknown for {family:?} {key:?}"));
        assert_eq!(
            &actual,
            paths,
            "{lang} {} {:?}",
            family.stable_label(),
            String::from_utf8_lossy(key)
        );
        families.insert(family.stable_label());
    }
    for family in FAMILIES {
        assert_eq!(
            index_candidates(analyzer, lang, family, b"no.such.Name"),
            Some(vec![]),
            "{lang} {family:?}: proven absence is Some(empty)"
        );
    }
    families
}

const JAVA: &[(&str, &str)] = &[
    (
        "pkg/Alpha.java",
        "package pkg;
public class Alpha {
    public interface Marker {}
    public enum Mode { ON, OFF }
    public record Pair(int a, int b) {}
    private int field;
    public Alpha() {}
    public void run(int x) {}
    public void run(String s) {}
    static <T> T id(T t) { return t; }
    Runnable anonymous = new Runnable() { public void run() {} };
}
",
    ),
    (
        "pkg/Beta.java",
        "package pkg;
public class Beta extends Alpha {
    interface Gamma { default void hello() {} }
}
",
    ),
    ("Top.java", "class Top { void run() {} }\n"),
];

const GO_PACKAGE: &str = "package util

type Widget struct{ N int }

func (w Widget) Size() int { return w.N }

func Make() Widget { return Widget{} }

var Count = 1

const Limit = 2
";

const GO: &[(&str, &str)] = &[
    // The same bytes mounted at two paths: one blob, two final package names.
    ("a/util.go", GO_PACKAGE),
    ("b/util.go", GO_PACKAGE),
    ("main.go", "package main\n\nfunc main() {}\n"),
];

const RUST: &[(&str, &str)] = &[
    (
        "src/lib.rs",
        "pub mod inner;
pub struct Top;
impl Top { pub fn new() -> Self { Top } }
pub trait Tr { fn m(&self); }
pub enum E { A, B }
pub fn free() {}
const C: u8 = 1;
",
    ),
    ("src/inner.rs", "pub struct Deep;\npub fn helper() {}\n"),
];

const PYTHON: &[(&str, &str)] = &[
    (
        "pkg/mod.py",
        "import os\n\nclass C:\n    def m(self):\n        pass\n\ndef f():\n    pass\n",
    ),
    // A path-derived synthetic module row without imports.
    ("pkg/noimports.py", "x = 1\n"),
    ("pkg/__init__.py", ""),
];

#[test]
fn inventory_candidates_cover_every_key_the_visitor_emits() {
    let mut families = BTreeSet::new();
    let (_temp, java) = project(Language::Java, JAVA);
    let analyzer = listed(persisted(Arc::clone(&java), JavaAdapter));
    families.extend(assert_inventory_matches_visitor(
        &analyzer,
        java.root(),
        "java",
        JAVA,
    ));
    assert!(
        index_candidates(&analyzer, "go", IndexFamily::DefinitionExact, b"main.main").is_none(),
        "a language with no selected revision must remain unknown"
    );
    let (_temp, go) = project(Language::Go, GO);
    let analyzer = listed(persisted(Arc::clone(&go), GoAdapter));
    families.extend(assert_inventory_matches_visitor(
        &analyzer,
        go.root(),
        "go",
        GO,
    ));
    let (_temp, rust) = project(Language::Rust, RUST);
    let analyzer = listed(persisted(Arc::clone(&rust), RustAdapter::for_tests()));
    families.extend(assert_inventory_matches_visitor(
        &analyzer,
        rust.root(),
        "rust",
        RUST,
    ));
    let (_temp, python) = project(Language::Python, PYTHON);
    let first = ProjectFile::new(python.root().to_path_buf(), "pkg/mod.py");
    let analyzer = listed(persisted(
        Arc::clone(&python),
        PythonAdapter::for_test_file(&first),
    ));
    families.extend(assert_inventory_matches_visitor(
        &analyzer,
        python.root(),
        "python",
        PYTHON,
    ));
    assert_eq!(
        families,
        FAMILIES
            .iter()
            .map(|family| family.stable_label())
            .collect::<BTreeSet<_>>(),
        "the fixtures exercise every definition family"
    );
}

fn commit_all(root: &std::path::Path, paths: &[&str]) {
    let repo = git2::Repository::init(root).unwrap();
    let mut index = repo.index().unwrap();
    for path in paths {
        index.add_path(std::path::Path::new(path)).unwrap();
    }
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
}

fn fail_blob_writes<A: LanguageAdapter>(analyzer: &TreeSitterAnalyzer<A>, lang: &str, on: bool) {
    let sql = if on {
        format!(
            "CREATE TEMP TRIGGER inventory_fail_blob_writes BEFORE INSERT ON blobs WHEN NEW.lang = '{lang}' BEGIN SELECT RAISE(FAIL, 'forced dirty state'); END;"
        )
    } else {
        "DROP TRIGGER inventory_fail_blob_writes".to_string()
    };
    analyzer
        .analyzer_store()
        .conn
        .execute(move |connection| connection.execute_batch(&sql).unwrap());
}

fn inventory_states<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
) -> BTreeMap<String, Option<String>> {
    let conn = analyzer.analyzer_store().read_conn().unwrap();
    conn.prepare(
        "SELECT rel_path, definition_inventory_state FROM workspace_file_versions
         WHERE valid_until IS NULL",
    )
    .unwrap()
    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

#[test]
fn java_inventory_excludes_configuration_inputs_and_finds_duplicate_sources() {
    let files = [
        ("a/Shared.java", "package pkg; public class Shared {}"),
        ("b/Shared.java", "package pkg; public class Shared {}"),
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion></project>",
        ),
    ];
    let (_temp, project) = project(Language::Java, &files);
    let analyzer = listed(persisted(Arc::clone(&project), JavaAdapter));
    let conn = analyzer.analyzer_store().read_conn().unwrap();
    let rows = conn.prepare(
        "SELECT rel_path, input_kind, definition_inventory_state FROM workspace_file_versions WHERE valid_until IS NULL",
    ).unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    assert!(
        rows.iter()
            .any(|(path, kind, _)| path == "pom.xml" && kind != "source"),
        "{rows:?}"
    );
    for (path, kind, state) in rows {
        if kind == "source" {
            assert_eq!(state.as_deref(), Some("known"), "{path}");
        } else {
            assert_eq!(state, None, "{path} ({kind})");
        }
    }
    assert_inventory_matches_visitor(&analyzer, project.root(), "java", &files[..2]);
}

/// A file whose blob is unpublished when its projection is published is not
/// known, and makes its whole language unknown: the producer never defaults
/// to known. The projection published without its blob differs from the
/// complete one, so the next sync replaces the version and publishes the
/// complete inventory.
#[allow(clippy::too_many_arguments)]
fn assert_unknown_until_complete<A: LanguageAdapter>(
    analyzer: TreeSitterAnalyzer<A>,
    root: &std::path::Path,
    lang: &str,
    edited: &str,
    unrelated_key: &[u8],
    unknown_label: Option<&str>,
    edit: impl Fn(&ProjectFile),
    new_key: &[u8],
) {
    let candidates = |analyzer: &TreeSitterAnalyzer<A>, key: &[u8]| {
        index_candidates(analyzer, lang, IndexFamily::DefinitionExact, key)
    };
    assert!(
        inventory_states(&analyzer)
            .values()
            .all(|state| state.as_deref() == Some("known")),
        "{:?}",
        inventory_states(&analyzer)
    );
    assert_eq!(candidates(&analyzer, unrelated_key).unwrap().len(), 1);
    let file = ProjectFile::new(root.to_path_buf(), edited);
    edit(&file);
    fail_blob_writes(&analyzer, lang, true);
    let dirty = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!dirty.state.dirty_snapshot().is_empty());
    let states = inventory_states(&dirty);
    assert_eq!(
        states[edited].as_deref(),
        unknown_label,
        "{lang} edited file while its blob is unpublished: {states:?}"
    );
    assert!(
        candidates(&dirty, unrelated_key).is_none(),
        "{lang}: one unknown file makes the language unknown"
    );
    fail_blob_writes(&dirty, lang, false);
    let healed = dirty.update(&BTreeSet::from([file]));
    assert!(
        inventory_states(&healed)
            .values()
            .all(|state| state.as_deref() == Some("known")),
        "{:?}",
        inventory_states(&healed)
    );
    assert_eq!(candidates(&healed, unrelated_key).unwrap().len(), 1);
    assert_eq!(
        index_candidates(&healed, lang, IndexFamily::DefinitionIdentifier, new_key)
            .unwrap()
            .into_iter()
            .map(|candidate| candidate.mounted_path)
            .collect::<Vec<_>>(),
        vec![PathBuf::from(edited)]
    );
}

#[test]
fn unpublished_blob_and_incomplete_package_facts_withhold_the_inventory() {
    let (_temp, java) = project(Language::Java, JAVA);
    commit_all(
        java.root(),
        &["pkg/Alpha.java", "pkg/Beta.java", "Top.java"],
    );
    let analyzer = listed(persisted(Arc::clone(&java), JavaAdapter));
    assert_unknown_until_complete(
        analyzer,
        java.root(),
        "java",
        "pkg/Alpha.java",
        b"pkg.Beta",
        // Java publishes no file-level package anchor, so its package facts
        // are complete; the blob is what is unpublished.
        None,
        |file| {
            file.write("package pkg;\npublic class Alpha { void added() {} }\n")
                .unwrap()
        },
        b"added",
    );
    let (_temp, go) = project(Language::Go, GO);
    commit_all(go.root(), &["a/util.go", "b/util.go", "main.go"]);
    let analyzer = listed(persisted(Arc::clone(&go), GoAdapter));
    assert_unknown_until_complete(
        analyzer,
        go.root(),
        "go",
        "a/util.go",
        b"main.main",
        // Go publishes a file-level anchor, and an unpublished blob leaves its
        // package facts uncovered.
        Some("package_facts_incomplete"),
        |file| {
            file.write("package util\n\nfunc Added() {}\n").unwrap();
        },
        b"Added",
    );
}

/// The open source version of a path: its id and the revision that opened it.
fn open_version<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    rel_path: &str,
) -> (i64, i64) {
    let conn = analyzer.analyzer_store().read_conn().unwrap();
    conn.query_row(
        "SELECT file_version_id, valid_from FROM workspace_file_versions
         WHERE valid_until IS NULL AND rel_path = ?1",
        [rel_path],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

fn name_row_count<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file_version_id: i64,
) -> i64 {
    let conn = analyzer.analyzer_store().read_conn().unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM workspace_file_definition_name_rows WHERE file_version_id = ?1",
        [file_version_id],
        |row| row.get(0),
    )
    .unwrap()
}

fn all_known<A: LanguageAdapter>(analyzer: &TreeSitterAnalyzer<A>) -> bool {
    inventory_states(analyzer)
        .values()
        .all(|state| state.as_deref() == Some("known"))
}

/// The enumerator's candidates for every anchored `Make` name the Go fixture
/// emits (one per package spelling), or None when any of them is unknown.
fn go_make_candidates<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    root: &std::path::Path,
) -> Option<BTreeMap<Vec<u8>, BTreeSet<PathBuf>>> {
    let keys = visitor_keys(analyzer, root, &GO[..2])
        .into_iter()
        .filter(|((_, key), (family, _))| {
            *family == IndexFamily::DefinitionExact && key.ends_with(b".Make")
        })
        .map(|((_, key), _)| key)
        .collect::<Vec<_>>();
    assert_eq!(
        keys.len(),
        2,
        "one anchored Make name per package spelling: {keys:?}"
    );
    keys.into_iter()
        .map(|key| {
            let candidates = index_candidates(analyzer, "go", IndexFamily::DefinitionExact, &key)?;
            let paths = candidates
                .into_iter()
                .map(|candidate| candidate.mounted_path)
                .collect::<BTreeSet<_>>();
            assert!(!paths.is_empty(), "{:?}", String::from_utf8_lossy(&key));
            Some((key, paths))
        })
        .collect()
}

/// Fakes a row from before migration 0292 (see `set_inventory_state`).
fn make_alpha_legacy(analyzer: &TreeSitterAnalyzer<JavaAdapter>) {
    make_legacy(analyzer, "java", "pkg/Alpha.java");
}

fn make_legacy<A: LanguageAdapter>(analyzer: &TreeSitterAnalyzer<A>, lang: &str, rel_path: &str) {
    set_inventory_state(analyzer, lang, rel_path, None);
}

/// The one statement in tests that writes a file version's inventory state:
/// NULL fakes a row from before migration 0292, and a label fakes a state the
/// producer stored for evidence that has since changed. It sets no stamp.
fn set_inventory_state<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    lang: &str,
    rel_path: &str,
    state: Option<&str>,
) {
    let (lang, rel_path, state) = (
        lang.to_owned(),
        rel_path.to_owned(),
        state.map(str::to_owned),
    );
    analyzer.analyzer_store().conn.execute(move |connection| {
        connection
            .execute(
                "UPDATE workspace_file_versions SET definition_inventory_state = ?3
                 WHERE valid_until IS NULL AND lang = ?1 AND rel_path = ?2",
                rusqlite::params![lang, rel_path, state],
            )
            .unwrap()
    });
}

/// A version written before migration 0292 has NULL inventory state, which
/// means unknown, and so does every version whose package facts were
/// incomplete or whose names a blob delete withdrew. A sync that computes the
/// file's projection and finds the open version digest-equal rewrites its
/// inventory in place: the file version id and its revision stay, so nothing
/// revision-keyed is re-keyed (#10325 identity ruling). A file the sync does
/// not touch stays unknown.
#[test]
fn legacy_null_inventory_state_is_refilled_in_place_by_a_digest_equal_sync() {
    let (_temp, java) = project(Language::Java, JAVA);
    commit_all(
        java.root(),
        &["pkg/Alpha.java", "pkg/Beta.java", "Top.java"],
    );
    let analyzer = listed(persisted(Arc::clone(&java), JavaAdapter));
    let edited = "pkg/Alpha.java";
    let candidates = |analyzer: &TreeSitterAnalyzer<JavaAdapter>| {
        index_candidates(analyzer, "java", IndexFamily::DefinitionExact, b"pkg.Beta")
    };
    assert_eq!(candidates(&analyzer).unwrap().len(), 1);
    let version = open_version(&analyzer, edited);
    make_alpha_legacy(&analyzer);
    assert!(candidates(&analyzer).is_none(), "a legacy row is unknown");

    // An incremental update of a different file leaves the legacy row alone.
    let top = ProjectFile::new(java.root().to_path_buf(), "Top.java");
    let untouched = analyzer.update(&BTreeSet::from([top]));
    assert_eq!(inventory_states(&untouched)[edited], None);
    assert!(candidates(&untouched).is_none());

    // An incremental update that computes the file's own projection refills it.
    let file = ProjectFile::new(java.root().to_path_buf(), edited);
    let touched = untouched.update(&BTreeSet::from([file]));
    assert_eq!(open_version(&touched, edited), version);
    assert!(all_known(&touched), "{:?}", inventory_states(&touched));
    assert_eq!(candidates(&touched).unwrap().len(), 1);

    // A full sync (a fresh analyzer over the same cache) refills it too.
    make_alpha_legacy(&touched);
    drop((untouched, touched, analyzer));
    let reopened = persisted(Arc::clone(&java), JavaAdapter);
    assert_eq!(open_version(&reopened, edited), version);
    assert!(all_known(&reopened), "{:?}", inventory_states(&reopened));
    // Only after the constructor's own full sync refilled it: a further full
    // update would refill it too and hide a constructor that did not.
    let reopened = listed(reopened);
    assert_eq!(candidates(&reopened).unwrap().len(), 1);

    // A legacy row that a content change closed keeps its NULL state in
    // history. The selection reaches only open versions, so it proves nothing
    // about the selected files.
    make_alpha_legacy(&reopened);
    ProjectFile::new(java.root().to_path_buf(), edited)
        .write("package pkg;\npublic class Alpha { void changed() {} }\n")
        .unwrap();
    let changed = reopened.update(&BTreeSet::from([ProjectFile::new(
        java.root().to_path_buf(),
        edited,
    )]));
    assert_ne!(open_version(&changed, edited), version, "a new version");
    assert!(all_known(&changed), "{:?}", inventory_states(&changed));
    assert_eq!(candidates(&changed).unwrap().len(), 1);
}

/// A blob replacement deletes the blob row, and the name rows of every file
/// version that mounts it cascade away. The file must stop being known in that
/// transaction, because an anchored name (stored on no `code_units` row) would
/// otherwise be proven absent. Readiness does not bring it back; the next full
/// sync rewrites the rows in place.
#[test]
#[hardwon(
    "#10325: re-persisting a mounted blob cascaded away its name rows while the file stayed known"
)]
fn repersisting_a_mounted_blob_withdraws_the_names_until_a_full_sync_refills_them() {
    let (_temp, go) = project(Language::Go, GO);
    commit_all(go.root(), &["a/util.go", "b/util.go", "main.go"]);
    let analyzer = listed(persisted(Arc::clone(&go), GoAdapter));
    let before = go_make_candidates(&analyzer, go.root()).expect("known workspace");
    let versions =
        ["a/util.go", "b/util.go", "main.go"].map(|path| (path, open_version(&analyzer, path)));
    assert!(
        versions
            .iter()
            .all(|(_, (id, _))| name_row_count(&analyzer, *id) > 0)
    );

    // The same bytes are mounted at both util paths, so one blob is shared.
    let file = ProjectFile::new(go.root().to_path_buf(), "a/util.go");
    analyzer.persist_live_blobs(std::slice::from_ref(&file));
    let states = inventory_states(&analyzer);
    assert_eq!(
        states["a/util.go"].as_deref(),
        Some("names_withdrawn"),
        "{states:?}"
    );
    assert_eq!(
        states["b/util.go"].as_deref(),
        Some("names_withdrawn"),
        "{states:?}"
    );
    assert_eq!(states["main.go"].as_deref(), Some("known"), "{states:?}");
    assert_eq!(name_row_count(&analyzer, versions[0].1.0), 0);
    assert!(
        go_make_candidates(&analyzer, go.root()).is_none(),
        "a withdrawn file makes the language unknown, not a proven absence"
    );

    drop(analyzer);
    let reopened = persisted(Arc::clone(&go), GoAdapter);
    for (path, version) in versions {
        assert_eq!(
            open_version(&reopened, path),
            version,
            "{path}: refilled in place"
        );
    }
    assert!(all_known(&reopened), "{:?}", inventory_states(&reopened));
    assert_eq!(
        go_make_candidates(&listed(reopened), go.root()).expect("refilled workspace"),
        before
    );
}

/// One unpublished Go blob makes the whole batch's package facts incomplete,
/// so its published siblings carry `package_facts_incomplete` with complete
/// projections. After the blob publishes, the next full sync sees the siblings
/// digest-equal and refills them in place, opening no new file version.
#[test]
#[hardwon("#10325: one unpublished Go blob left every sibling file unknown forever")]
fn siblings_of_an_unpublished_blob_become_known_on_the_next_full_sync() {
    let (_temp, go) = project(Language::Go, GO);
    commit_all(go.root(), &["a/util.go", "b/util.go", "main.go"]);
    let unpublished = blob_oid(GO[2].1);
    let store = AnalyzerStore::open_persistent(&go.root().join("analyzer.db")).unwrap();
    let sql = format!(
        "CREATE TEMP TRIGGER inventory_fail_one_blob BEFORE INSERT ON blobs WHEN NEW.blob_oid = '{unpublished}' BEGIN SELECT RAISE(FAIL, 'forced unpublished blob'); END;"
    );
    store
        .conn
        .execute(move |connection| connection.execute_batch(&sql).unwrap());
    let context = store_context_from_store(go.as_ref(), store, false);
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&go),
        GoAdapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .unwrap();
    let states = inventory_states(&analyzer);
    assert_eq!(
        states["a/util.go"].as_deref(),
        Some("package_facts_incomplete"),
        "{states:?}"
    );
    assert_eq!(
        states["b/util.go"].as_deref(),
        Some("package_facts_incomplete")
    );
    let siblings = ["a/util.go", "b/util.go"].map(|path| (path, open_version(&analyzer, path)));
    let analyzer = listed(analyzer);
    assert!(go_make_candidates(&analyzer, go.root()).is_none());
    drop(analyzer);

    let healed = persisted(Arc::clone(&go), GoAdapter);
    for (path, version) in siblings {
        assert_eq!(
            open_version(&healed, path),
            version,
            "{path}: no new file version"
        );
    }
    assert!(all_known(&healed), "{:?}", inventory_states(&healed));
    assert!(go_make_candidates(&listed(healed), go.root()).is_some());
}

/// A source that admission refused, or one the enumeration missed, has no
/// selected file version, so the file arms alone prove it absent. The
/// enumerator returns None for a language with an open refusal at its selected
/// revision, and for a listing the analyzer knows was incomplete.
#[test]
#[hardwon("#10325: a refused or unlisted source was invisible to the absence proof")]
fn refused_sources_and_incomplete_listings_make_the_inventory_unknown() {
    let long_line = format!("class Big {{ int {} = 0; }}\n", "x".repeat(20_000));
    let files = [
        ("pkg/Alpha.java", JAVA[0].1),
        ("pkg/Big.java", long_line.as_str()),
    ];
    let (_temp, java) = project(Language::Java, &files);
    let analyzer = persisted(Arc::clone(&java), JavaAdapter);
    let refused = analyzer.selected_source_admission_refusals().unwrap();
    assert_eq!(refused.len(), 1, "the fixture must be refused: {refused:?}");
    // The constructor path observed no listing, so the analyzer's own proof is
    // empty. Name the selected snapshots as proven (or none), and ask the store
    // directly: the arm is what must refuse once the listing is taken as fine.
    let store_answer = |analyzer: &TreeSitterAnalyzer<JavaAdapter>, proven: bool| {
        let listed = if proven {
            ListedSnapshots::new(analyzer.selected_workspace_snapshots().as_ref().clone())
        } else {
            ListedSnapshots::default()
        };
        analyzer
            .analyzer_store()
            .index_blob_candidates_for_key_at(
                &listed,
                "java",
                IndexFamily::DefinitionExact,
                b"no.such.Name",
            )
            .unwrap()
    };
    assert_eq!(
        store_answer(&analyzer, true),
        None,
        "an open refusal withholds the proof"
    );
    assert!(index_candidates(&analyzer, "java", IndexFamily::DefinitionExact, b"x").is_none());

    // The same workspace without the refused file proves absence, unless the
    // caller reports an incomplete listing.
    let (_temp, clean) = project(Language::Java, &files[..1]);
    let analyzer = listed(persisted(Arc::clone(&clean), JavaAdapter));
    assert_eq!(store_answer(&analyzer, true), Some(vec![]));
    assert_eq!(store_answer(&analyzer, false), None);

    // An incomplete enumeration, as the analyzer itself records it. The
    // listing is captured (the constructor path would capture none and be
    // unknown for that reason alone), so the flag is the only difference
    // between the control and the incomplete build.
    let constructed = |listing_complete| {
        let (temp, partial) = project(Language::Java, &files[..1]);
        let store = AnalyzerStore::open_persistent(&partial.root().join("analyzer.db")).unwrap();
        let mut context = store_context_from_store(partial.as_ref(), store, false);
        context.workspace_snapshot =
            WorkspaceBuildSnapshot::capture(partial.as_ref(), None, &[Language::Java]);
        assert!(context.workspace_snapshot.is_some());
        context.workspace_listing_complete = listing_complete;
        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&partial),
            JavaAdapter,
            AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap();
        (temp, analyzer)
    };
    let candidates = |analyzer: &TreeSitterAnalyzer<JavaAdapter>| {
        index_candidates(
            analyzer,
            "java",
            IndexFamily::DefinitionExact,
            b"no.such.Name",
        )
    };
    let (_temp, control) = constructed(true);
    assert_eq!(candidates(&control), Some(vec![]));
    let (_temp, incomplete) = constructed(false);
    assert!(
        all_known(&incomplete),
        "every file is known; only the listing is not"
    );
    assert!(candidates(&incomplete).is_none());
}

#[test]
#[hardwon("#10325: an overlay on an include-claimed C++ header kept the inventory proof")]
fn an_overlay_on_an_include_claimed_header_withholds_the_inventory_proof() {
    // The extensionless header has no language of its own; the C++ analyzer
    // indexes it only because `main.cc` includes it.
    let files = [
        (
            "main.cc",
            "#include \"claimed_header\"\nint main() { return 0; }\n",
        ),
        ("claimed_header", "struct Item {};\n"),
    ];
    let (_temp, cpp) = project(Language::Cpp, &files);
    let analyzer = listed(persisted(Arc::clone(&cpp), CppAdapter));
    let header = ProjectFile::new(cpp.root().to_path_buf(), "claimed_header");
    assert_eq!(header.language(), Language::None);
    assert!(
        analyzer.analyzed_files().contains(&header),
        "the include target must be adopted by the C++ analyzer"
    );
    assert!(analyzer.workspace_listing_complete());
    assert_eq!(
        index_candidates(
            &analyzer,
            "cpp",
            IndexFamily::DefinitionExact,
            b"no.such.Name"
        ),
        Some(vec![]),
        "without an overlay the persisted inventory proves absence"
    );

    let overlay = Arc::new(OverlayProject::new(Arc::clone(&cpp)));
    assert!(overlay.set(
        header.abs_path(),
        "struct Item { int edited; };\n".to_owned()
    ));
    let edited = analyzer.clone_with_project(Arc::new(overlay.snapshot()));
    assert!(
        !edited.workspace_listing_complete(),
        "the overlay replaces content the persisted rows describe"
    );
    assert_eq!(
        index_candidates(
            &edited,
            "cpp",
            IndexFamily::DefinitionExact,
            b"no.such.Name"
        ),
        None
    );
}

/// The full sync derives names only for files it publishes or refills. A
/// digest-equal reopen leaves every stored inventory alone, so it reads no unit
/// tails and holds no per-file name lists.
#[test]
#[hardwon("#10325: an unchanged reopen read the unit tails of every file")]
fn an_unchanged_reopen_reads_unit_tails_only_for_files_it_refills() {
    let (_temp, java) = project(Language::Java, JAVA);
    let tail_reads = |analyzer: &TreeSitterAnalyzer<JavaAdapter>| {
        analyzer
            .analyzer_store()
            .unit_tail_blob_reads
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let first = persisted(Arc::clone(&java), JavaAdapter);
    assert_eq!(
        tail_reads(&first),
        JAVA.len(),
        "a fresh store publishes every file"
    );
    assert!(all_known(&first));
    drop(first);

    let unchanged = persisted(Arc::clone(&java), JavaAdapter);
    assert_eq!(tail_reads(&unchanged), 0, "nothing to publish or refill");
    assert!(all_known(&unchanged));

    // A single-file update that changes nothing derives no names either; a
    // legacy row it must refill reads the one file.
    let alpha = ProjectFile::new(java.root().to_path_buf(), "pkg/Alpha.java");
    let noop = unchanged.update(&BTreeSet::from([alpha.clone()]));
    assert_eq!(tail_reads(&noop), 0, "a no-op update needs no inventory");
    assert!(all_known(&noop));
    make_alpha_legacy(&noop);
    let refilled_in_place = noop.update(&BTreeSet::from([alpha]));
    assert_eq!(tail_reads(&refilled_in_place), 1, "only the refilled file");
    assert!(all_known(&refilled_in_place));

    // One legacy row is refilled; the others are still left alone.
    make_alpha_legacy(&refilled_in_place);
    drop((unchanged, noop, refilled_in_place));
    let refilled = persisted(Arc::clone(&java), JavaAdapter);
    assert_eq!(tail_reads(&refilled), 1, "only the refillable file");
    assert!(all_known(&refilled));
}

#[test]
#[hardwon("#10325: a listing walk error kept the inventory listing complete")]
fn listing_omissions_that_can_hide_a_source_make_the_inventory_unknown() {
    let omission = |reason| WorkspaceFileOmission {
        path: PathBuf::from("pkg/Hidden.java"),
        reason,
    };
    let provable = |analyzer: &TreeSitterAnalyzer<JavaAdapter>| {
        index_candidates(
            analyzer,
            "java",
            IndexFamily::DefinitionExact,
            b"no.such.Name",
        )
        .is_some()
    };
    let files = &JAVA[..1];

    // The constructor used by `persisted` captures the initial clean listing.
    // Each case changes the omissions and then rebuilds, so the full update
    // observes the project's new listing.
    let rebuilt = |reason| {
        let (_temp, project) = omitting_project(Language::Java, files);
        let analyzer = persisted(Arc::new(project.clone()), JavaAdapter);
        project.set_omissions(vec![omission(reason)]);
        let rebuilt = analyzer.update_all();
        assert!(all_known(&rebuilt), "every listed file is known");
        (_temp, rebuilt)
    };

    // Omissions outside the analyzer's universe do not withhold the proof.
    for reason in [
        WorkspaceFileOmissionReason::Symlink,
        WorkspaceFileOmissionReason::NonRegular,
        WorkspaceFileOmissionReason::NonUtf8Name,
    ] {
        let (_temp, analyzer) = rebuilt(reason);
        assert!(provable(&analyzer), "{reason:?} is outside the universe");
    }

    // The three that can drop a source do.
    for reason in [
        WorkspaceFileOmissionReason::WalkError,
        WorkspaceFileOmissionReason::NonUtf8GitPath,
        WorkspaceFileOmissionReason::Unknown,
    ] {
        let (_temp, analyzer) = rebuilt(reason);
        assert!(!provable(&analyzer), "{reason:?} may hide a source");
    }

    // The standalone constructor captures the project's real enumeration:
    // a clean listing proves the inventory before any subsequent sync.
    let (_temp, project) = omitting_project(Language::Java, files);
    let constructed = persisted(Arc::new(project.clone()), JavaAdapter);
    assert!(all_known(&constructed), "every file is known");
    assert!(constructed.workspace_listing_complete());
    assert!(
        provable(&constructed),
        "constructor observed the clean listing"
    );
    assert!(provable(&listed(constructed)), "a captured clean listing");

    // An incremental update sees the omissions of the listing it is given.
    let (_temp, project) = omitting_project(Language::Java, files);
    let analyzer = listed(persisted(Arc::new(project.clone()), JavaAdapter));
    assert!(provable(&analyzer));
    let alpha = ProjectFile::new(project.root().to_path_buf(), "pkg/Alpha.java");
    let unchanged = analyzer.update(&BTreeSet::from([alpha.clone()]));
    assert!(provable(&unchanged), "a clean listing keeps the proof");
    project.set_omissions(vec![omission(WorkspaceFileOmissionReason::WalkError)]);
    let walked = unchanged.update(&BTreeSet::from([alpha.clone()]));
    assert!(all_known(&walked), "only the listing changed");
    assert!(!provable(&walked), "a new walk error withholds the proof");

    // With no cached or supplied listing, the update enumerates the project
    // and recovers proof from the now clean listing.
    project.clear_omissions();
    let blind = analyzer.update(&BTreeSet::from([alpha]));
    assert!(all_known(&blind), "only the listing is unknown");
    assert!(provable(&blind), "the update captured a clean listing");
}

#[test]
#[hardwon("#10325: an older snapshot borrowed a newer complete listing")]
fn a_listing_proof_names_only_the_snapshots_its_own_sync_published() {
    let files = &JAVA[..1];
    let (_temp, project) = omitting_project(Language::Java, files);
    let provable = |analyzer: &TreeSitterAnalyzer<JavaAdapter>| {
        index_candidates(
            analyzer,
            "java",
            IndexFamily::DefinitionExact,
            b"no.such.Name",
        )
    };

    // The first build's listing reports a walk error: its snapshot can be
    // missing a whole source.
    project.set_omissions(vec![WorkspaceFileOmission {
        path: PathBuf::from("pkg/Hidden.java"),
        reason: WorkspaceFileOmissionReason::WalkError,
    }]);
    let failed = persisted(Arc::new(project.clone()), JavaAdapter).update_all();
    assert!(all_known(&failed));
    assert!(provable(&failed).is_none());
    let failed_snapshots = failed.selected_workspace_snapshots();

    // A later build over changed content observes a complete listing.
    ProjectFile::new(project.root().to_path_buf(), "pkg/Alpha.java")
        .write("package pkg;\npublic class Alpha { void later() {} }\n")
        .unwrap();
    project.set_omissions(Vec::new());
    let complete = failed.update_all();
    let complete_snapshots = complete.selected_workspace_snapshots();
    assert_ne!(
        failed_snapshots["java"], complete_snapshots["java"],
        "the later build published a later snapshot"
    );
    assert_eq!(provable(&complete), Some(vec![]));
    assert_eq!(
        complete.workspace_listing_proof().snapshots(),
        &*complete_snapshots,
        "the proof names the snapshot the complete sync published"
    );

    // The fact belongs to the snapshot its sync published. When the analyzer
    // selects another one, as when a later writer advanced the head, the
    // complete listing does not carry over to it.
    complete
        .relational_workspace_snapshots
        .store(Arc::clone(&failed_snapshots));
    assert!(complete.workspace_listing_complete());
    assert!(complete.workspace_listing_proof().snapshots().is_empty());
    assert!(provable(&complete).is_none());
}

#[test]
#[hardwon("#10325: a point update replaced its omission-lookup error with the previous analyzer's")]
fn an_omission_lookup_failure_in_a_point_update_reaches_the_query_boundary() {
    let (_temp, project) = omitting_project(Language::Java, &JAVA[..1]);
    let analyzer = listed(persisted(Arc::new(project.clone()), JavaAdapter));
    let alpha = ProjectFile::new(project.root().to_path_buf(), "pkg/Alpha.java");
    project.fail_cached_omissions();
    let updated = analyzer.update(&BTreeSet::from([alpha]));

    let context = Arc::new(AnalyzerQueryContext::default());
    let attribution = context.enter();
    updated.begin_query(&context);
    let error = context
        .store_error()
        .expect("the failed omission lookup must reach the request boundary");
    updated.end_query(&context);
    drop(attribution);
    assert!(
        error
            .to_string()
            .contains("injected omission lookup failure"),
        "{error}"
    );
    assert!(!updated.workspace_listing_complete());
}

/// A file stored as `unresolved_anchor` had no package name when the sync that
/// published it ran. The next sync must re-derive it: repairing the
/// configuration the anchor depends on changes nothing in the file, so its
/// projection digest is equal and only a refill can bring it to known (as for a
/// NULL or `package_facts_incomplete` state). No project can reach the state
/// through a real configuration edit, so the stored state is faked.
#[test]
fn an_unresolved_anchor_state_is_refilled_in_place_by_a_digest_equal_sync() {
    let (_temp, java) = project(Language::Java, JAVA);
    commit_all(
        java.root(),
        &["pkg/Alpha.java", "pkg/Beta.java", "Top.java"],
    );
    let analyzer = listed(persisted(Arc::clone(&java), JavaAdapter));
    let edited = "pkg/Alpha.java";
    let version = open_version(&analyzer, edited);
    set_inventory_state(&analyzer, "java", edited, Some("unresolved_anchor"));
    assert_eq!(
        inventory_states(&analyzer)[edited].as_deref(),
        Some("unresolved_anchor")
    );
    assert!(
        index_candidates(&analyzer, "java", IndexFamily::DefinitionExact, b"pkg.Beta").is_none(),
        "an unresolved anchor is unknown"
    );

    let file = ProjectFile::new(java.root().to_path_buf(), edited);
    let healed = analyzer.update(&BTreeSet::from([file]));
    assert_eq!(open_version(&healed, edited), version, "refilled in place");
    assert!(all_known(&healed), "{:?}", inventory_states(&healed));
}

fn state_of<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    lang: &str,
    rel_path: &str,
) -> (i64, Option<String>) {
    analyzer
        .analyzer_store()
        .read_conn()
        .unwrap()
        .query_row(
            "SELECT file_version_id, definition_inventory_state FROM workspace_file_versions
             WHERE valid_until IS NULL AND lang = ?1 AND rel_path = ?2",
            [lang, rel_path],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

/// The C reading of a header is published by the content-reading sync, which
/// the ordinary workspace sync treats as foreign. It owns the reading's
/// inventory: the same derivation and refill rules, and a listing proof for
/// the snapshot it publishes.
#[test]
#[hardwon("#10325: C header readings never entered the definition inventory")]
fn c_header_readings_enter_the_definition_inventory() {
    let files = [
        (
            "main.c",
            "#include \"shared.h\"\nint main(void) { return helper(); }\n",
        ),
        // C and C++ disagree about where a tag declared inside an aggregate
        // lives, so this header has a distinct C reading under `cpp:c`.
        (
            "shared.h",
            "int helper(void);\nstruct Outer { struct Inner { int x; } inner; };\n",
        ),
    ];
    let (_temp, c_project) = project(Language::Cpp, &files);
    let constructed =
        CppAnalyzer::new_with_config(Arc::clone(&c_project), AnalyzerConfig::default());
    let analyzer = constructed.update_all();
    let inner = analyzer.inner();
    assert_eq!(
        state_of(inner, "cpp:c", "shared.h").1.as_deref(),
        Some("known"),
        "the header's C reading is inventoried"
    );
    let candidates = index_candidates(inner, "cpp:c", IndexFamily::DefinitionExact, b"Inner")
        .expect("every blob is complete, so the reading answers");
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.mounted_path.clone())
            .collect::<Vec<_>>(),
        vec![PathBuf::from("shared.h")],
        "the header's definition is among the candidates"
    );
    assert_eq!(
        index_candidates(
            inner,
            "cpp:c",
            IndexFamily::DefinitionExact,
            b"no.such.Name"
        ),
        Some(vec![]),
        "an absence is proven"
    );

    // A legacy row of the reading is refilled in place by the next sync, which
    // the ordinary sync would never do for a foreign path.
    let (version, _) = state_of(inner, "cpp:c", "shared.h");
    make_legacy(inner, "cpp:c", "shared.h");
    assert_eq!(state_of(inner, "cpp:c", "shared.h").1, None);
    let rebuilt = analyzer.update_all();
    assert_eq!(
        state_of(rebuilt.inner(), "cpp:c", "shared.h"),
        (version, Some("known".to_owned())),
        "refilled in place"
    );

    // A changed header publishes a new reading at a new revision of `cpp:c`.
    // The listing proof follows the snapshot the content sync published.
    ProjectFile::new(c_project.root().to_path_buf(), "shared.h")
        .write("int helper(void);\nstruct Outer { struct Inner { int y; } inner; };\n")
        .unwrap();
    let changed = rebuilt.update_all();
    let inner = changed.inner();
    assert_ne!(
        state_of(inner, "cpp:c", "shared.h").0,
        version,
        "a new file version"
    );
    assert_eq!(
        index_candidates(inner, "cpp:c", IndexFamily::DefinitionExact, b"Inner")
            .map(|candidates| candidates.len()),
        Some(1)
    );
}

/// The content-reading sync receives only the files the analyzed set kept. A
/// header that admission refused is dropped from that set, so it is also
/// missing from the readings, and the sync removed its `cpp:c` version while
/// still certifying the snapshot as completely listed.
#[test]
#[hardwon("#10325: a C header dropped from the analyzed set vanished from a proven cpp:c snapshot")]
fn a_header_missing_from_the_analyzed_set_leaves_the_c_reading_inventory_unknown() {
    let long_line = format!(
        "struct Outer {{ struct Inner {{ int x; }} inner; }};\nint {} = 0;\n",
        "x".repeat(20_000)
    );
    let files = [
        (
            "main.c",
            "#include \"shared.h\"\nint main(void) { return 0; }\n",
        ),
        ("shared.h", long_line.as_str()),
    ];
    let (_temp, c_project) = project(Language::Cpp, &files);
    let analyzer = CppAnalyzer::new_with_config(Arc::clone(&c_project), AnalyzerConfig::default())
        .update_all();
    let inner = analyzer.inner();
    let header = ProjectFile::new(c_project.root().to_path_buf(), "shared.h");
    assert!(
        !inner.analyzed_files().contains(&header),
        "admission refused the header, so the analyzed set drops it"
    );
    assert!(
        inner.workspace_listing_complete(),
        "the enumeration itself was complete; only the header's reading is missing"
    );
    assert_eq!(
        index_candidates(inner, "cpp:c", IndexFamily::DefinitionExact, b"Inner"),
        None,
        "a definition only the dropped header's C reading could hold is not proven absent"
    );
}

/// The content-reading sync withdraws a language's listing proof when it cannot
/// validate a file. A later update publishes a new snapshot of that language
/// after observing only the files it changed, so it cannot restore the proof:
/// the file that was never validated is still missing from the snapshot.
#[test]
#[hardwon(
    "#10325: a later update granted again the listing proof a content-reading sync had withdrawn"
)]
fn an_update_does_not_grant_again_a_withdrawn_c_reading_listing_proof() {
    let long_line = format!(
        "struct Outer {{ struct Inner {{ int x; }} inner; }};\nint {} = 0;\n",
        "x".repeat(20_000)
    );
    let files = [
        (
            "main.c",
            "#include \"shared.h\"\nint main(void) { return 0; }\n",
        ),
        ("shared.h", long_line.as_str()),
    ];
    let (_temp, c_project) = project(Language::Cpp, &files);
    let analyzer = CppAnalyzer::new_with_config(Arc::clone(&c_project), AnalyzerConfig::default())
        .update_all();
    assert_eq!(
        index_candidates(
            analyzer.inner(),
            "cpp:c",
            IndexFamily::DefinitionExact,
            b"Inner"
        ),
        None,
        "the sync withdrew the proof: admission refused the header"
    );

    // The wrapper would run the content sync again after an update; the inner
    // analyzer's own update does not, which is the state under test.
    let main = ProjectFile::new(c_project.root().to_path_buf(), "main.c");
    main.write("#include \"shared.h\"\nint main(void) { return 1; }\n")
        .unwrap();
    let updated = analyzer.inner().update(&BTreeSet::from([main]));
    assert!(
        updated.workspace_listing_complete(),
        "the update observed a complete listing, so only the withdrawal can refuse the proof"
    );
    assert_eq!(
        index_candidates(&updated, "cpp:c", IndexFamily::DefinitionExact, b"Inner"),
        None,
        "the unvalidated header is still missing from the updated snapshot"
    );
}

#[test]
#[hardwon(
    "#10325: an omission-only listing change kept a non-Rust listing proof, so the inventory proved absence"
)]
fn an_omission_only_update_withdraws_a_java_listing_proof() {
    let (_temp, project) = omitting_project(Language::Java, &JAVA[..1]);
    let analyzer = persisted(Arc::new(project.clone()), JavaAdapter).update_all();
    assert_eq!(
        index_candidates(&analyzer, "java", IndexFamily::DefinitionExact, b"Hidden"),
        Some(Vec::new())
    );
    project.set_omissions(vec![WorkspaceFileOmission {
        path: PathBuf::from("hidden"),
        reason: WorkspaceFileOmissionReason::SymlinkToDirectory,
    }]);
    let updated = analyzer.update(&BTreeSet::new());
    assert_eq!(
        index_candidates(&updated, "java", IndexFamily::DefinitionExact, b"Hidden"),
        None,
        "the omitted directory may contain Hidden even though no source file changed"
    );
    // With the proof already withdrawn, the next no-op update returns early
    // and must not grant the proof again while the omission persists.
    let again = updated.update(&BTreeSet::new());
    assert_eq!(
        index_candidates(&again, "java", IndexFamily::DefinitionExact, b"Hidden"),
        None
    );
}

/// A file version published before its blob waits as `blob_pending`; the blob's
/// publication must promote it in the same transaction, including the
/// selected-content publication.
#[test]
#[hardwon("#10325: selected parsed-content publication never promoted a blob_pending file version")]
fn selected_content_publication_promotes_a_version_that_waited_for_its_blob() {
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let source = "class Owner { void run() {} }\n";
    let generation = store
        .ensure_language_epoch_value("java", "publication-test-v1")
        .unwrap();
    store
        .ensure_resolution_producer_epoch("java", Language::Java)
        .unwrap();
    let blob = blob_oid(source);
    let snapshot = store
        .sync_workspace_inputs_with_rust_listing(
            &WorkspaceId("8".repeat(64)),
            "java",
            generation,
            &[WorkspaceFileRow {
                rel_path: "Owner.java".into(),
                blob_oid: blob,
                decision: None,
            }],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[WorkspaceFileDefinitionInventory {
                rel_path: "Owner.java".into(),
                state: DefinitionInventoryState::ProjectionComplete,
                names: Vec::new(),
            }],
            None,
        )
        .unwrap();
    let state = |store: &AnalyzerStore| -> Option<String> {
        store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT definition_inventory_state FROM workspace_file_versions
                 WHERE valid_until IS NULL AND rel_path = 'Owner.java'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    assert_eq!(state(&store).as_deref(), Some("blob_pending"));

    let parsed = prepare_parsed_blob(
        &BlobKey::unvaried(blob, "java"),
        generation,
        &JavaAdapter,
        parsed_fixture_state(&JavaAdapter, "Owner.java", source),
    )
    .unwrap();
    let outcome = store
        .publish_selected_parsed_content(
            &snapshot,
            "Owner.java",
            parsed,
            &CancellationToken::default(),
        )
        .unwrap();
    assert!(matches!(
        outcome,
        ResolutionContentPublicationOutcome::Ready(_)
    ));
    assert_eq!(state(&store).as_deref(), Some("known"));
}

const GO_MOD_OLD: &str = "module example.com/old\n\ngo 1.21\n";
const GO_MOD_NEW: &str = "module example.com/new\n\ngo 1.21\n";
const GO_FOO: &str = "package pkg\n\nfunc Foo() {}\n";

fn stored_names<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    rel_path: &str,
) -> Vec<String> {
    let conn = analyzer.analyzer_store().read_conn().unwrap();
    conn.prepare(
        "SELECT rows.exact_fqn FROM workspace_file_definition_name_rows AS rows
         JOIN workspace_file_versions AS fv ON fv.file_version_id = rows.file_version_id
         WHERE fv.valid_until IS NULL AND fv.rel_path = ?1 ORDER BY rows.exact_fqn",
    )
    .unwrap()
    .query_map([rel_path], |row| row.get(0))
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

fn go_exact<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    name: &str,
) -> Option<Vec<PathBuf>> {
    index_candidates(
        analyzer,
        "go",
        IndexFamily::DefinitionExact,
        name.as_bytes(),
    )
    .map(|candidates| {
        candidates
            .into_iter()
            .map(|candidate| candidate.mounted_path)
            .collect()
    })
}

/// A `module` edit with an unchanged `.go` file must not leave the old names
/// serving a proven absence of the new one.
#[test]
fn a_go_module_path_edit_never_serves_the_old_names_as_a_proven_absence() {
    let files = [("go.mod", GO_MOD_OLD), ("pkg/a.go", GO_FOO)];
    let mut failures = Vec::new();
    let mut check = |label: &str, analyzer: &TreeSitterAnalyzer<GoAdapter>, edited: bool| {
        let names = stored_names(analyzer, "pkg/a.go");
        let new = go_exact(analyzer, "example.com/new/pkg.Foo");
        let old = go_exact(analyzer, "example.com/old/pkg.Foo");
        eprintln!(
            "{label}: states={:?} names={names:?} new={new:?} old={old:?}",
            inventory_states(analyzer)
        );
        if edited {
            let foo = Some(vec![PathBuf::from("pkg/a.go")]);
            if !(new.is_none() || new == foo) {
                failures.push(format!("{label}: new name is a proven absence: {new:?}"));
            }
            if !(old.is_none() || old == Some(vec![])) {
                failures.push(format!("{label}: old name still maps to the file: {old:?}"));
            }
        }
    };
    // The raw TreeSitterAnalyzer used here is not the GoAnalyzer wrapper, which
    // clears the process-wide nearest-module cache on every update and open
    // (go/mod.rs `invalidate_nearest_go_module_cache` call sites). Do that by hand.
    let write_new = |root: &std::path::Path| {
        brokk_bifrost_go::packages::invalidate_nearest_go_module_cache();
        ProjectFile::new(root.to_path_buf(), "go.mod")
            .write(GO_MOD_NEW)
            .unwrap();
    };

    // A: edit go.mod, report it to `update`.
    let (_temp, go) = project(Language::Go, &files);
    commit_all(go.root(), &["go.mod", "pkg/a.go"]);
    let analyzer = listed(persisted(Arc::clone(&go), GoAdapter));
    check("A before", &analyzer, false);
    write_new(go.root());
    let updated = analyzer.update(&BTreeSet::from([ProjectFile::new(
        go.root().to_path_buf(),
        "go.mod",
    )]));
    check("A after update(go.mod)", &updated, true);
    // A2: the same, but a full rebuild.
    let rebuilt = updated.update_all();
    check("A2 after update_all", &rebuilt, true);

    // B: go.mod edited with no report, then a reopen on the same database.
    let (_temp_b, go_b) = project(Language::Go, &files);
    commit_all(go_b.root(), &["go.mod", "pkg/a.go"]);
    let analyzer_b = listed(persisted(Arc::clone(&go_b), GoAdapter));
    check("B before", &analyzer_b, false);
    drop(analyzer_b);
    write_new(go_b.root());
    let reopened = persisted(Arc::clone(&go_b), GoAdapter);
    check("B reopened (constructor)", &reopened, true);
    let reopened = listed(reopened);
    check("B reopened + update_all", &reopened, true);

    // C: a fresh analyzer on the edited workspace.
    let (_temp_c, go_c) = project(
        Language::Go,
        &[("go.mod", GO_MOD_NEW), ("pkg/a.go", GO_FOO)],
    );
    commit_all(go_c.root(), &["go.mod", "pkg/a.go"]);
    let fresh = listed(persisted(Arc::clone(&go_c), GoAdapter));
    check("C fresh", &fresh, true);
    assert_eq!(
        stored_names(&fresh, "pkg/a.go"),
        vec!["example.com/new/pkg.Foo".to_string()]
    );
    assert_eq!(
        go_exact(&fresh, "example.com/new/pkg.Foo"),
        Some(vec![PathBuf::from("pkg/a.go")])
    );

    assert!(failures.is_empty(), "{failures:#?}");
}
