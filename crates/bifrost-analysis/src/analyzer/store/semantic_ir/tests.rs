//! Round-trip differential: lower real Rust files, store the rows, read them
//! back, and require the rebuilt artifact to be the lowered one.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
use git2::Oid;

use super::{
    PreparedSemanticIr, SemanticIrLoweringOutcome, SemanticIrMountScope,
    SemanticIrPublicationOutcome, insert_semantic_ir_tx, semantic_ir_producer_epoch,
};
use crate::CancellationToken;
use crate::analyzer::rust::{RustAdapter, RustSemanticLowerer};
use crate::analyzer::semantic::partial_flow::fixpoint::{
    ProcedurePartialFlows, parse_time_partial_flows,
};
use crate::analyzer::semantic::service::ProgramSemanticsLowerer;
use crate::analyzer::semantic::service::semantic_artifact_key_from_content;
use crate::analyzer::semantic::{
    ContentIdentity, ProcedureId, ProcedureSemanticsParts, SemanticArtifact, SemanticArtifactKey,
    SemanticBudget, SemanticCapability, SemanticIrVersion, SemanticOutcome, SemanticRequest,
    SourceRevision, StableDigest, WorkspaceMountId, WorkspaceRelativePath,
};
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::planner_statistics::pinned_plans::{explain_pin, pinned};
use crate::analyzer::tree_sitter_analyzer::{
    LanguageAdapter, PreparedSourceOrigin, PreparedSyntaxPreparation, PreparedSyntaxSource,
    PreparedSyntaxTree, prepare_exact_syntax_tree,
};
use crate::analyzer::{AnalyzerConfig, Language, LanguageDialect, ProjectFile};
use crate::inline_project::InlineTestProject;
use crate::text_utils::compute_line_starts;

/// Every `*.rs` file under `root`, sorted, found without recursion.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).expect("read source directory") {
            let path = entry.expect("read source directory entry").path();
            if path.is_dir() {
                directories.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Parse one file the way the Rust adapter prepares exact syntax.
pub(crate) fn prepare(file: &ProjectFile, source: &Arc<str>) -> PreparedSyntaxTree {
    let adapter = RustAdapter;
    assert!(
        adapter.parser_included_ranges(file, source).is_none(),
        "the Rust adapter parses whole files"
    );
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(file))
        .expect("Rust grammar loads");
    let tree = parser
        .parse(source.as_ref(), None)
        .expect("tree-sitter parses");
    let tree = adapter
        .reparse_grammar_gap(source, &tree, None)
        .unwrap_or(tree);
    PreparedSyntaxTree::new(
        PreparedSyntaxSource::Exact(Arc::clone(source)),
        tree,
        compute_line_starts(source),
        LanguageDialect::for_path(Language::Rust, file.rel_path()),
        PreparedSourceOrigin::Disk,
        None,
    )
}

#[derive(Debug, Default)]
struct RoundTripReport {
    files: usize,
    round_tripped: usize,
    /// Files whose lowering did not complete, with the outcome label.
    not_lowered: Vec<(PathBuf, &'static str)>,
    duplicate_content: usize,
    /// Files whose lowering fails or whose lowered parts the artifact
    /// rejects, with the error. The write path stores these as an `Error`
    /// outcome, so they have no rows.
    invalid_lowering: Vec<(PathBuf, String)>,
    /// The largest round-tripped file: its source bytes, its rows and
    /// estimated payload bytes per table, and its total logical rows and
    /// payload bytes.
    largest: Option<LargestFile>,
}

#[derive(Debug)]
struct LargestFile {
    path: PathBuf,
    source_bytes: usize,
    census: Vec<(&'static str, usize, usize)>,
    logical_rows: usize,
    payload_bytes: usize,
}

/// Lower, store, read and decode every Rust file under `root` on `workers`
/// threads, each with its own store, asserting that each decoded artifact
/// has the lowered artifact's materialization id and work. Workers take the
/// largest remaining file first, so the slowest lowerings start at once.
fn round_trip_tree(root: &Path, workers: usize) -> RoundTripReport {
    let root = root.canonicalize().expect("source root exists");
    let mut files = rust_files(&root)
        .into_iter()
        .map(|path| {
            let bytes = std::fs::metadata(&path).expect("source metadata").len();
            (bytes, path)
        })
        .collect::<Vec<_>>();
    files.sort_unstable_by(|left, right| right.cmp(left));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let reports = std::thread::scope(|scope| {
        let handles = (0..workers)
            .map(|_| {
                let root = &root;
                let files = &files;
                let next = &next;
                scope.spawn(move || {
                    let queue = std::iter::from_fn(|| {
                        let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        files.get(index).map(|(_, path)| path)
                    });
                    round_trip_files(root, queue)
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect::<Vec<_>>()
    });
    let mut merged = RoundTripReport::default();
    for report in reports {
        merged.files += report.files;
        merged.round_tripped += report.round_tripped;
        merged.not_lowered.extend(report.not_lowered);
        merged.duplicate_content += report.duplicate_content;
        merged.invalid_lowering.extend(report.invalid_lowering);
        if let Some(largest) = report.largest
            && merged
                .largest
                .as_ref()
                .is_none_or(|current| largest.source_bytes > current.source_bytes)
        {
            merged.largest = Some(largest);
        }
    }
    merged
}

fn round_trip_files<'a>(root: &Path, files: impl Iterator<Item = &'a PathBuf>) -> RoundTripReport {
    let root = root.to_path_buf();
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let lowerer = RustSemanticLowerer;
    let identity = lowerer.identity();
    let capabilities = lowerer.capabilities();
    let epoch = semantic_ir_producer_epoch(&identity);
    assert!(
        store
            .ensure_semantic_ir_producer_epoch("rust", &epoch)
            .unwrap()
    );
    assert!(
        !store
            .ensure_semantic_ir_producer_epoch("rust", &epoch)
            .unwrap()
    );
    let mut seen = std::collections::HashSet::new();
    let mut report = RoundTripReport::default();
    for path in files {
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        report.files += 1;
        let source: Arc<str> = Arc::from(source);
        let rel_path = path.strip_prefix(&root).expect("file under root");
        let file = ProjectFile::new(root.clone(), rel_path);
        let prepared = prepare(&file, &source);
        let parts = match lowerer.lower(
            &file,
            &prepared,
            &SemanticBudget::default(),
            &CancellationToken::default(),
        ) {
            Ok(SemanticOutcome::Complete { value, .. }) => value,
            Err(error) => {
                report
                    .invalid_lowering
                    .push((path.clone(), error.to_string()));
                continue;
            }
            Ok(other) => {
                report.not_lowered.push((path.clone(), other.label()));
                continue;
            }
        };
        let oid = Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        if !seen.insert(oid) {
            report.duplicate_content += 1;
            continue;
        }
        let content =
            ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
        assert_eq!(content, ContentIdentity::hash_bytes(source.as_bytes()));
        let path_identity = WorkspaceRelativePath::try_from_path(file.rel_path()).unwrap();
        let language = LanguageDialect::for_path(Language::Rust, file.rel_path());
        let key = SemanticArtifactKey::new(
            WorkspaceMountId::from_root(file.root()),
            path_identity.clone(),
            language,
            SourceRevision::Disk { content },
            identity.adapter.clone(),
            SemanticIrVersion::current(),
            identity.configuration,
            identity.dependencies,
        );
        let lowered =
            match SemanticArtifact::try_new(key.clone(), capabilities.clone(), parts.clone()) {
                Ok(lowered) => lowered,
                Err(error) => {
                    report
                        .invalid_lowering
                        .push((path.clone(), error.to_string()));
                    continue;
                }
            };

        let prepared_rows = PreparedSemanticIr::prepare(
            SemanticIrLoweringOutcome::Complete { parts },
            None,
            &epoch,
            content,
            source.len(),
        );
        let blob_id = {
            let mut conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 1)",
                [oid.to_string()],
            )
            .unwrap();
            let blob_id = conn.last_insert_rowid();
            let tx = conn.transaction().unwrap();
            assert!(
                insert_semantic_ir_tx(
                    &tx,
                    blob_id,
                    "rust",
                    &prepared_rows,
                    &CancellationToken::default()
                )
                .unwrap()
            );
            tx.commit().unwrap();
            blob_id
        };

        let publication = store
            .semantic_ir_publication(oid, "rust")
            .unwrap()
            .unwrap_or_else(|| panic!("{}: no valid publication", path.display()));
        assert_eq!(publication.blob_id, blob_id);
        assert_eq!(publication.content, content);
        assert_eq!(publication.source_bytes, source.len());
        assert_eq!(publication.outcome, SemanticIrPublicationOutcome::Complete);
        let scope = SemanticIrMountScope {
            mount: WorkspaceMountId::from_root(file.root()),
            path: path_identity,
            language,
            content,
        };
        let decoded = store.read_semantic_ir(blob_id, &scope).unwrap();
        let rebuilt =
            SemanticArtifact::try_new(key, capabilities.clone(), decoded).unwrap_or_else(|error| {
                panic!("{}: decoded parts are invalid: {error}", path.display())
            });
        assert_eq!(
            rebuilt.materialization_id(),
            lowered.materialization_id(),
            "{}: the decoded artifact differs from the lowered one",
            path.display()
        );
        assert_eq!(rebuilt.work(), lowered.work(), "{}", path.display());
        report.round_tripped += 1;
        if report
            .largest
            .as_ref()
            .is_none_or(|largest| source.len() > largest.source_bytes)
        {
            report.largest = Some(LargestFile {
                path: path.clone(),
                source_bytes: source.len(),
                census: prepared_rows.table_census(),
                logical_rows: prepared_rows.logical_rows(),
                payload_bytes: prepared_rows.payload_bytes(),
            });
        }
    }
    report
}

fn print_report(report: &RoundTripReport) {
    println!(
        "{} Rust files, {} round-tripped, {} duplicate contents, not lowered: {:?}, \
         invalid lowering: {:?}",
        report.files,
        report.round_tripped,
        report.duplicate_content,
        report.not_lowered,
        report.invalid_lowering
    );
    if let Some(largest) = &report.largest {
        println!(
            "largest file {} ({} source bytes, {} logical rows, {} estimated payload bytes):",
            largest.path.display(),
            largest.source_bytes,
            largest.logical_rows,
            largest.payload_bytes
        );
        for (table, rows, payload) in &largest.census {
            println!("  {table}: {rows} rows, {payload} estimated payload bytes");
        }
    }
}

#[test]
fn semantic_ir_rows_round_trip_every_rust_fixture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let report = round_trip_tree(&root, 1);
    print_report(&report);
    assert!(report.round_tripped > 0, "{report:?}");
}

/// Runs on every available CPU; `.config/nextest.toml` reserves them.
#[test]
#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
fn semantic_ir_rows_round_trip_every_workspace_crate_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    let report = round_trip_tree(&root, workers);
    print_report(&report);
    assert!(report.round_tripped > 0, "{report:?}");
}

/// A head written under another producer epoch is not a publication, and a
/// head whose outcome is not complete reports that outcome.
#[test]
fn semantic_ir_publication_applies_the_validity_rule() {
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let source = "fn f() {}\n";
    let oid = Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
    let content = ContentIdentity::hash_bytes(source.as_bytes());
    let blob_id = {
        let mut conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 1)",
            [oid.to_string()],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        let prepared = PreparedSemanticIr::prepare(
            SemanticIrLoweringOutcome::Unsupported(SemanticCapability::GuardFacts),
            None,
            "epoch-a",
            content,
            source.len(),
        );
        assert_eq!(prepared.logical_rows(), 1);
        let tx = conn.transaction().unwrap();
        assert!(
            insert_semantic_ir_tx(
                &tx,
                blob_id,
                "rust",
                &prepared,
                &CancellationToken::default()
            )
            .unwrap()
        );
        tx.commit().unwrap();
        blob_id
    };
    assert_eq!(store.semantic_ir_publication(oid, "rust").unwrap(), None);
    store
        .ensure_semantic_ir_producer_epoch("rust", "epoch-a")
        .unwrap();
    let publication = store.semantic_ir_publication(oid, "rust").unwrap().unwrap();
    assert_eq!(publication.blob_id, blob_id);
    assert_eq!(
        publication.outcome,
        SemanticIrPublicationOutcome::Unsupported(SemanticCapability::GuardFacts)
    );
    assert!(
        store
            .ensure_semantic_ir_producer_epoch("rust", "epoch-b")
            .unwrap()
    );
    assert_eq!(store.semantic_ir_publication(oid, "rust").unwrap(), None);
}

/// The head lookup seeks the blob by its identity and the head and the epoch
/// by their keys, with and without representative statistics.
#[test]
fn semantic_ir_publication_lookup_seeks_keys() {
    for state in PlannerStatisticsState::BOTH {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned("semantic_ir_publication"));
        for (table, access) in [
            ("blobs", "sqlite_autoindex_blobs_1"),
            ("publications", "PRIMARY KEY"),
            ("epochs", "PRIMARY KEY"),
        ] {
            assert!(
                plan.iter().any(|detail| {
                    detail.starts_with(&format!("SEARCH {table} ")) && detail.contains(access)
                }),
                "{state}: {table} is not searched by {access}: {plan:#?}"
            );
        }
        for forbidden in ["SCAN", "AUTOMATIC", "TEMP B-TREE", "CO-ROUTINE"] {
            assert!(
                plan.iter().all(|detail| !detail.contains(forbidden)),
                "{state}: the plan uses {forbidden}: {plan:#?}"
            );
        }
    }
}

/// A Rust file served through the public provider comes from its semantic IR
/// rows, and its artifact is the one that lowering the same source produces.
#[test]
fn rust_artifact_served_from_rows_matches_direct_lowering() {
    const LIB: &str = "pub fn first(value: i32) -> i32 { value + 1 }\n";
    const OTHER: &str = "pub struct Holder { pub item: String }\n\
        pub fn second(holder: &Holder) -> &str { &holder.item }\n";
    let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", LIB)
        .file("src/other.rs", OTHER)
        .build();
    let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
    let store = workspace
        .store()
        .expect("the ephemeral workspace has a store");
    let conn = store.read_conn().expect("a read connection");
    let rust_blobs: i64 = conn
        .query_row(
            "SELECT count(*) FROM blobs WHERE lang = 'rust'",
            [],
            |row| row.get(0),
        )
        .expect("count Rust blobs");
    let published: i64 = conn
        .query_row(
            "SELECT count(*) FROM semantic_ir_publications WHERE outcome = 0",
            [],
            |row| row.get(0),
        )
        .expect("count complete semantic IR publications");
    drop(conn);
    assert_eq!(
        published, rust_blobs,
        "every Rust blob must publish complete semantic IR rows"
    );

    let file = project.file("src/lib.rs");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let served = workspace
        .materialize_program_semantics(
            &file,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("materialize the Rust file through the provider")
        .available_value()
        .cloned()
        .expect("the Rust file yields a complete artifact");

    let prepared = match prepare_exact_syntax_tree(
        &RustAdapter,
        &file,
        PreparedSyntaxSource::Exact(Arc::from(LIB)),
        PreparedSourceOrigin::Disk,
        None,
        None,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    ) {
        PreparedSyntaxPreparation::Complete(Some(prepared)) => prepared,
        _ => panic!("the fixture parses"),
    };
    let lowered = match RustSemanticLowerer.lower(
        &file,
        &prepared,
        &SemanticBudget::default(),
        &cancellation,
    ) {
        Ok(SemanticOutcome::Complete { value, .. }) => value,
        Ok(other) => panic!("direct lowering must complete: {}", other.label()),
        Err(error) => panic!("direct lowering failed: {error}"),
    };
    let content = ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
    let key = semantic_artifact_key_from_content(
        &file,
        prepared.dialect(),
        content,
        None,
        RustSemanticLowerer.identity(),
    )
    .expect("the file has a semantic artifact key");
    let direct = SemanticArtifact::try_new_with_budget(
        key,
        RustSemanticLowerer.capabilities(),
        lowered,
        &mut SemanticBudget::default(),
    )
    .expect("the directly lowered artifact validates");
    assert_eq!(served.materialization_id(), direct.materialization_id());
}

/// The partial flows of every procedure of one Rust source, projected the way
/// the parse-time writer projects them, with the lowered procedures they belong
/// to.
fn partial_flows_of(
    source: &str,
) -> (
    ProjectFile,
    Vec<ProcedureSemanticsParts>,
    Vec<ProcedurePartialFlows>,
) {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();
    let file = project.file("lib.rs");
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut materialization_budget = SemanticBudget::default();
    let artifact = analyzer
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
        )
        .expect("Rust semantic materialization runs")
        .available_value()
        .cloned()
        .expect("Rust semantic artifact is available");
    let source: Arc<str> = Arc::from(source);
    let prepared = prepare(&file, &source);
    let flows = parse_time_partial_flows(&artifact, &prepared, &cancellation)
        .expect("the projection is not cancelled");
    let parts = match RustSemanticLowerer.lower(
        &file,
        &prepared,
        &SemanticBudget::default(),
        &CancellationToken::default(),
    ) {
        Ok(SemanticOutcome::Complete { value, .. }) => value,
        other => panic!("the fixture lowers completely: {other:?}"),
    };
    assert_eq!(parts.len(), flows.len(), "one entry per procedure");
    (file, parts, flows)
}

/// Partial flows survive the write and the read: each procedure's ports,
/// flows with their crossed calls, openness and discharged gaps read back
/// equal to the computed value.
#[test]
fn partial_flows_round_trip_through_rows() {
    let source = "pub struct Holder {\n    field: u32,\n}\n\nimpl Holder {\n    pub fn store(&mut self, value: u32) {\n        self.field = value;\n    }\n}\n\npub fn identity(value: u32) -> u32 {\n    value\n}\n\npub fn forward(value: u32) {\n    sink(value);\n}\n\nfn sink(_value: u32) {}\n\npub fn capture(value: u32) -> impl Fn() -> u32 {\n    move || value\n}\n\npub fn around(value: u32) -> u32 {\n    sink(0);\n    value\n}\n\n#[derive(core::clone::Clone, core::marker::Copy)]\npub struct Pair {\n    value: u32,\n}\n\npub fn copy_derivation() {\n    let original = Pair { value: 1 };\n    let copied = original;\n    sink(copied.value);\n}\n";
    let (file, parts, flows) = partial_flows_of(source);
    assert!(
        flows.iter().any(|procedure| !procedure.flows.is_empty()),
        "the fixture has at least one partial flow to round-trip"
    );
    assert!(
        flows
            .iter()
            .flat_map(|procedure| &procedure.flows)
            .any(|flow| flow.crossed.iter().any(|class| !class.is_empty())),
        "the fixture has a flow that crosses a call: {flows:#?}"
    );
    // Both values of the head's relation-proof fact are stored and read back:
    // the copy derivation's load of `copied.value` is a partial relation.
    assert!(
        flows.iter().any(|procedure| procedure.relations_complete)
            && flows.iter().any(|procedure| !procedure.relations_complete),
        "the fixture has procedures with and without an unproven relation: {flows:#?}"
    );
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let identity = RustSemanticLowerer.identity();
    let epoch = semantic_ir_producer_epoch(&identity);
    assert!(
        store
            .ensure_semantic_ir_producer_epoch("rust", &epoch)
            .unwrap()
    );
    let oid = Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
    let content = ContentIdentity::hash_bytes(source.as_bytes());
    let scope = SemanticIrMountScope {
        mount: WorkspaceMountId::from_root(file.root()),
        path: WorkspaceRelativePath::try_from_path(file.rel_path()).unwrap(),
        language: LanguageDialect::for_path(Language::Rust, file.rel_path()),
        content,
    };
    let prepared = PreparedSemanticIr::prepare(
        SemanticIrLoweringOutcome::Complete { parts },
        Some(&flows),
        &epoch,
        content,
        source.len(),
    );
    let blob_id = {
        let mut conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 1)",
            [oid.to_string()],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        let tx = conn.transaction().unwrap();
        assert!(
            insert_semantic_ir_tx(
                &tx,
                blob_id,
                "rust",
                &prepared,
                &CancellationToken::default()
            )
            .unwrap()
        );
        tx.commit().unwrap();
        blob_id
    };
    for (index, expected) in flows.iter().enumerate() {
        let procedure = ProcedureId::new(u32::try_from(index).unwrap());
        let decoded = store
            .read_partial_flows(blob_id, procedure, &scope)
            .unwrap()
            .unwrap_or_else(|| panic!("procedure {index} has a head row"));
        assert_eq!(&decoded, expected, "procedure {index}");
    }
}
