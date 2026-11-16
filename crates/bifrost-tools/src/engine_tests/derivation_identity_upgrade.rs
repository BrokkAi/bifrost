//! Schema-0405 upgrade boundary, including every derived FK descendant.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
use brokk_bifrost_analysis::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::cache_db;
use rusqlite::{Connection, types::Value};

const ROOTS: [&str; 7] = [
    "csharp_compilation_sets",
    "go_context_selections",
    "jvm_context_revisions",
    "resolution_unit_summaries",
    "rust_source_listing_certificates",
    "jvm_external_provider_publications",
    "rust_crate_reconciliations",
];

#[derive(Debug)]
struct ForeignKey {
    child: String,
    parent: String,
    columns: Vec<(String, String)>,
}

fn tables(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap().query_map([], |r| r.get(0)).unwrap()
        .collect::<rusqlite::Result<_>>().unwrap()
}

fn foreign_keys(conn: &Connection) -> Vec<ForeignKey> {
    let mut keys = BTreeMap::new();
    for child in tables(conn) {
        let mut statement = conn.prepare("SELECT id,seq,\"table\",\"from\",\"to\" FROM pragma_foreign_key_list(?1) ORDER BY id,seq").unwrap();
        let rows = statement
            .query_map([&child], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, usize>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (id, ordinal, parent, from, to) = row.unwrap();
            let to = to.unwrap_or_else(|| {
                conn.prepare("SELECT name FROM pragma_table_info(?1) WHERE pk>0 ORDER BY pk")
                    .unwrap()
                    .query_map([&parent], |r| r.get::<_, String>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()[ordinal]
                    .clone()
            });
            keys.entry((child.clone(), id))
                .or_insert_with(|| ForeignKey {
                    child: child.clone(),
                    parent,
                    columns: Vec::new(),
                })
                .columns
                .push((from, to));
        }
    }
    keys.into_values().collect()
}

fn derived_closure(keys: &[ForeignKey]) -> BTreeSet<String> {
    let mut closure = ROOTS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut pending = closure.iter().cloned().collect::<VecDeque<_>>();
    while let Some(parent) = pending.pop_front() {
        for key in keys.iter().filter(|key| key.parent == parent) {
            if closure.insert(key.child.clone()) {
                pending.push_back(key.child.clone());
            }
        }
    }
    closure
}

fn query_rows(conn: &Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut statement = conn.prepare(sql).unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[derive(Debug, PartialEq)]
struct TableSnapshot {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
    digest: [u8; 32],
}

fn table_snapshot(conn: &Connection, table: &str, columns: Vec<String>) -> TableSnapshot {
    let projection = columns
        .iter()
        .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(",");
    let order = (1..=columns.len())
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let rows = query_rows(
        conn,
        &format!("SELECT {projection} FROM \"{table}\" ORDER BY {order}"),
    );
    let mut hash = CanonicalHasher::new(b"bifrost-11570-durable-input-rows");
    for (index, row) in rows.iter().enumerate() {
        hash.field("row", &(index as u64).to_le_bytes());
        for value in row {
            match value {
                Value::Null => hash.field("null", &[]),
                Value::Integer(n) => hash.field("integer", &n.to_le_bytes()),
                Value::Real(n) => hash.field("real", &n.to_bits().to_le_bytes()),
                Value::Text(s) => hash.field("text", s.as_bytes()),
                Value::Blob(b) => hash.field("blob", b),
            }
        }
    }
    TableSnapshot {
        columns,
        rows,
        digest: hash.finish(),
    }
}

fn input_snapshot(
    conn: &Connection,
    derived: &BTreeSet<String>,
) -> BTreeMap<String, TableSnapshot> {
    tables(conn)
        .into_iter()
        .filter(|table| !derived.contains(table))
        .map(|table| {
            let columns = conn
                .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
                .unwrap()
                .query_map([&table], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<String>>>()
                .unwrap();
            let snapshot = table_snapshot(conn, &table, columns);
            (table, snapshot)
        })
        .collect()
}

fn upgraded_input_snapshot(
    conn: &Connection,
    derived: &BTreeSet<String>,
    before: &BTreeMap<String, TableSnapshot>,
    expected_added: &BTreeMap<String, Vec<Vec<Value>>>,
) -> BTreeMap<String, TableSnapshot> {
    // Preserve every original column, including each interior's producer epoch.
    // Added columns are checked separately against their schema-declared default.
    // Name every unclassified table at once, so one forgotten table cannot
    // hide the next.
    let unclassified = tables(conn)
        .into_iter()
        .filter(|table| {
            !derived.contains(table)
                && !before.contains_key(table)
                && !expected_added.contains_key(table)
        })
        .collect::<Vec<_>>();
    assert!(
        unclassified.is_empty(),
        "unclassified durable tables created after schema 405: {unclassified:?}"
    );
    let mut added = BTreeSet::new();
    for table in tables(conn)
        .into_iter()
        .filter(|table| !derived.contains(table))
    {
        let Some(original) = before.get(&table) else {
            added.insert(table.clone());
            let expected = &expected_added[&table];
            let columns = conn
                .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
                .unwrap()
                .query_map([&table], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<String>>>()
                .unwrap();
            assert_eq!(
                table_snapshot(conn, &table, columns).rows,
                *expected,
                "new durable table {table} rows"
            );
            continue;
        };
        let added_columns = conn
            .prepare("SELECT name,dflt_value FROM pragma_table_info(?1) ORDER BY cid")
            .unwrap()
            .query_map([&table], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        for (column, default) in added_columns
            .into_iter()
            .filter(|(name, _)| !original.columns.contains(name))
        {
            // No DEFAULT clause means SQLite's implicit NULL default. Evaluate
            // the expression in SQLite, including NULL, numeric and blob defaults.
            let default = default.as_deref().unwrap_or("NULL");
            let column = column.replace('"', "\"\"");
            let rows = query_rows(
                conn,
                &format!("SELECT \"{column}\", \"{column}\" IS ({default}) FROM \"{table}\""),
            );
            for row in rows {
                assert_eq!(
                    row[1],
                    Value::Integer(1),
                    "{table}.{column} differs from DEFAULT {default}: {row:?}"
                );
            }
        }
    }
    assert_eq!(
        added,
        expected_added.keys().cloned().collect::<BTreeSet<_>>(),
        "classified durable tables created after schema 405"
    );
    before
        .iter()
        .map(|(table, original)| {
            (
                table.clone(),
                table_snapshot(conn, table, original.columns.clone()),
            )
        })
        .collect()
}

fn assert_no_orphans(conn: &Connection, keys: &[ForeignKey]) {
    assert!(query_rows(conn, "PRAGMA foreign_key_check").is_empty());
    // Explicit anti-joins also work when enforcement is disabled, independently
    // of SQLite's FK checker. NULL composite references have SQLite's normal meaning.
    for key in keys {
        let present = key
            .columns
            .iter()
            .map(|(from, _)| format!("child.\"{from}\" IS NOT NULL"))
            .collect::<Vec<_>>()
            .join(" AND ");
        let equals = key
            .columns
            .iter()
            .map(|(from, to)| format!("parent.\"{to}\"=child.\"{from}\""))
            .collect::<Vec<_>>()
            .join(" AND ");
        let sql = format!(
            "SELECT child.* FROM \"{}\" child WHERE {present} AND NOT EXISTS (SELECT 1 FROM \"{}\" parent WHERE {equals})",
            key.child, key.parent
        );
        let orphans = query_rows(conn, &sql);
        assert!(orphans.is_empty(), "{key:?}: {orphans:?}");
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12765: a pre-0427 fragment row's default binary-operation count must not read as a complete empty inventory"
)]
fn populated_405_rust_binary_operation_inventory_rejects_old_epoch() {
    use brokk_bifrost_analysis::analyzer::store::resolution_publication::{
        ResolutionContentInput, ResolutionContentPublicationOutcome,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionStale;
    use brokk_bifrost_analysis::analyzer::store::{GenerationId, WorkspaceId, WorkspaceSnapshotId};
    use brokk_bifrost_core::{
        analyzer::model::Language, cancellation::CancellationToken, gitblob::BlobKey,
    };

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("old-rust.sqlite3");
    let workspace_id = WorkspaceId::for_root(directory.path());
    let old = cache_db::test_connection_through_405();
    old.execute_batch(
        &include_str!("fixtures/derivation_identity_0405.sql")
            .replace("$WORKSPACE_ID", workspace_id.as_str()),
    )
    .unwrap();
    // The Rust producer epoch before binary operations: the change that added
    // migration 0427 also appended this token, so the lever file cut at that
    // line gives the epoch a pre-0427 producer actually recorded. Removing the
    // token would make this epoch current and the fragment admissible.
    let lever_text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../bifrost-store/levers/resolution-bundle-rust.tokens"
    ));
    let binary_operation_token = "12241-string-add-str-type";
    assert!(
        brokk_bifrost_core::lever_tokens::LeverTokens::parse(lever_text)
            .unwrap()
            .tokens()
            .contains(&binary_operation_token),
        "the change that added binary operations must keep its Rust producer token"
    );
    let before_binary_operations = lever_text
        .lines()
        .take_while(|line| line.trim() != binary_operation_token)
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let old_epoch = brokk_bifrost_core::lever_tokens::lever_label(
        "resolution-bundle-rust",
        &before_binary_operations,
    );
    // The old producer certified its inventory complete, before binary
    // operations were part of that producer's contract.
    old.execute("INSERT INTO resolution_fragment_interiors(blob_id,lang,semantic_language,producer_epoch,interior_digest,expected_semantic_site_count,logical_rows,payload_bytes,publication_state) VALUES(4,'rust','rust',?1,zeroblob(32),0,1,0,'complete')", [&old_epoch]).unwrap();
    old.execute(
        "INSERT INTO resolution_producer_epochs(lang,producer_epoch) VALUES('rust',?1)",
        [&old_epoch],
    )
    .unwrap();
    old.execute("VACUUM INTO ?1", [database.to_str().unwrap()])
        .unwrap();
    drop(old);
    let store = AnalyzerStore::open_persistent(&database).unwrap();
    assert_eq!(
        query_rows(
            &store.read_conn().unwrap(),
            "SELECT expected_binary_operation_count FROM resolution_fragment_interiors WHERE blob_id=4"
        ),
        vec![vec![Value::Integer(0)]]
    );
    let owner = WorkspaceSnapshotId {
        workspace_id,
        lang: "rust".into(),
        generation: GenerationId(0),
        revision: 1,
    };
    let key = BlobKey::unvaried(
        git2::Oid::from_str("4444444444444444444444444444444444444444").unwrap(),
        "rust",
    );
    let input = ResolutionContentInput::Parsed {
        key: key.clone(),
        semantic_language: Language::Rust,
    };
    // Cached-content admission is the product gate preceding selected typed
    // reads, including binary operations. Check both an old active epoch and
    // a current active epoch with the old fragment still present.
    for rotate in [false, true] {
        if rotate {
            store
                .ensure_resolution_producer_epoch("rust", Language::Rust)
                .unwrap();
        }
        let outcome = store
            .admit_cached_selected_content(
                &owner,
                "src/lib.rs",
                &key,
                &input,
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(
            matches!(
                outcome,
                ResolutionContentPublicationOutcome::Stale(
                    SelectedResolutionStale::ProducerEpoch { .. }
                )
            ),
            "{outcome:?}"
        );
    }
}

#[test]
fn non_rust_binary_operation_count_is_inapplicable() {
    use brokk_bifrost_core::{analyzer::model::Language, cancellation::CancellationToken};
    for (storage_language, language) in [("go", Language::Go), ("java", Language::Java)] {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::with_language(
            1,
            storage_language,
            language,
            false,
        );
        {
            let inventory = fixture.open_ready(&[]);
            assert_eq!(inventory.persisted_mount_count(), 1);
            assert_eq!(
                query_rows(
                    &fixture.store.read_conn().unwrap(),
                    "SELECT expected_binary_operation_count FROM resolution_fragment_interiors"
                ),
                vec![vec![Value::Integer(0)]]
            );
        }
        // A nonzero value would claim an inventory this producer cannot supply.
        // The product selection gate must classify the count as inapplicable.
        fixture.store.conn.execute_fixture(|conn| {
            conn.execute(
                "UPDATE resolution_fragment_interiors SET expected_binary_operation_count=1",
                [],
            )
            .unwrap();
        });
        let result = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &fixture.snapshots,
            &[fixture.language()],
            &[],
            &CancellationToken::new(),
        );
        let Err(error) = result else {
            panic!("non-Rust operation inventory admitted")
        };
        assert!(
            error
                .to_string()
                .contains("inapplicable resolution family has a nonzero count"),
            "{error}"
        );
    }
}

#[test]
fn populated_405_upgrade_clears_only_derived_closure_and_rebuilds_identities() {
    use brokk_bifrost_analysis::CancellationToken;
    use brokk_bifrost_analysis::analyzer::store::{
        WorkspaceId, go_package_context,
        go_unit_summaries::GoUnitSummaries,
        jvm_external_publication::{JvmExternalProjection, JvmExternalPublication},
        rust_unit_summaries::RustUnitSummaries,
    };
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_shared_store;
    use brokk_bifrost_analysis::native_resolution_test_support::{
        PythonSummaryAuthority, PythonSummaryObservation, PythonSummaryProfile,
    };
    use brokk_bifrost_python_analysis::analyzer::python::native_environment::PythonNativeEnvironment;

    // The production upgrader disables enforcement; also exercise the same
    // registered transaction with enforcement ON to pin NO ACTION ordering.
    for enforced in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("upgrade.sqlite3");
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname=\"identity_upgrade\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
            .file("src/lib.rs", "pub struct Item { pub value: u32 }\n")
            .file("go.mod", "module example.test/upgrade\n\ngo 1.22\n")
            .file("main.go", "package upgrade\ntype Item struct { Value int }\n")
            .file("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
            .file("Program.cs", "public class Item { public int Value; }\n")
            .file("pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>upgrade</artifactId><version>1</version></project>")
            .file("src/main/java/upgrade/Main.java", "package upgrade; public class Main { public int value() { return 1; } }\n")
            .file("module.py", "value = 1\n").build();
        let workspace_id = WorkspaceId::for_root(project.root());
        let config = crate::store_test_support::go_extraction_support_13::source_inventory_config();
        // Ask the real analyzers for current epochs before seeding generation 0.
        // An epoch rotation on reopen would hide reuse of the preserved inputs.
        let reference = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let reference_context =
            store_context_from_shared_store(project.project(), Arc::clone(&reference), false);
        let reference_workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            project.project_dyn(),
            config.clone(),
            reference_context,
        )
        .unwrap();
        let epochs = query_rows(
            &reference.read_conn().unwrap(),
            "SELECT lang,epoch FROM analysis_epochs ORDER BY lang",
        );
        drop(reference_workspace);
        drop(reference);
        let old = cache_db::test_connection_through_405();
        old.execute_batch(
            &include_str!("fixtures/derivation_identity_0405.sql")
                .replace("$WORKSPACE_ID", workspace_id.as_str()),
        )
        .unwrap();
        for epoch in epochs {
            old.execute(
                "INSERT INTO analysis_epochs(lang,epoch,generation) VALUES(?1,?2,0)",
                rusqlite::params![epoch[0], epoch[1]],
            )
            .unwrap();
        }
        assert_eq!(
            old.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            405
        );
        let keys = foreign_keys(&old);
        let derived = derived_closure(&keys);
        assert_eq!(derived.len(), 70, "{derived:?}");
        let empty = derived
            .iter()
            .filter(|t| query_rows(&old, &format!("SELECT 1 FROM {t}")).is_empty())
            .collect::<Vec<_>>();
        assert!(empty.is_empty(), "unpopulated descendants: {empty:?}");
        assert_no_orphans(&old, &keys);
        let before = input_snapshot(&old, &derived);
        for table in [
            "workspace_revisions",
            "workspace_file_versions",
            "python_runtime_acquisitions",
            "python_runtime_environments",
            "python_runtime_declared_environments",
            "python_runtime_artifacts",
        ] {
            assert!(
                !before[table].rows.is_empty(),
                "missing durable input {table}"
            );
        }
        old.execute("VACUUM INTO ?1", [database.to_str().unwrap()])
            .unwrap();
        drop(old);

        let mut upgraded = Connection::open(&database).unwrap();
        cache_db::configure_connection(&mut upgraded).unwrap();
        if enforced {
            upgraded.pragma_update(None, "foreign_keys", true).unwrap();
            cache_db::test_migrate_with_foreign_keys_enabled(&mut upgraded);
        } else {
            cache_db::migrate(&mut upgraded).unwrap();
        }
        let upgraded_keys = foreign_keys(&upgraded);
        let upgraded_derived = derived_closure(&upgraded_keys);
        let remaining = upgraded_derived
            .iter()
            .filter(|t| !query_rows(&upgraded, &format!("SELECT 1 FROM {t}")).is_empty())
            .collect::<Vec<_>>();
        assert!(
            remaining.is_empty(),
            "uncleared derived rows: {remaining:?}"
        );
        assert_eq!(
            upgraded_input_snapshot(
                &upgraded,
                &upgraded_derived,
                &before,
                &BTreeMap::from([
                    // Migration 0427 (#12495) creates it empty.
                    ("resolution_binary_operations".to_owned(), Vec::new()),
                    // Migration 0447 (#12159) creates the macro type candidate
                    // tables empty.
                    ("resolution_macro_type_candidates".to_owned(), Vec::new()),
                    ("resolution_macro_type_elements".to_owned(), Vec::new()),
                    ("resolution_macro_type_segments".to_owned(), Vec::new()),
                    // Migration 0460 (#12956) creates it empty.
                    (
                        "resolution_rust_structural_trait_impls".to_owned(),
                        Vec::new(),
                    ),
                    // Migration 0448 (#12967) creates the Ruby signature tables
                    // empty and seeds the collection epoch at 0.
                    (
                        "ruby_signature_collection_epoch".to_owned(),
                        vec![vec![Value::Integer(1), Value::Integer(0)]],
                    ),
                    ("ruby_signature_files".to_owned(), Vec::new()),
                    ("ruby_signature_methods".to_owned(), Vec::new()),
                    ("ruby_signature_positionals".to_owned(), Vec::new()),
                    ("ruby_signature_types".to_owned(), Vec::new()),
                ]),
            ),
            before,
            "durable row bytes/counts/digests changed (FK={enforced})"
        );
        assert_no_orphans(&upgraded, &upgraded_keys);
        drop(upgraded);

        let store = Arc::new(AnalyzerStore::open_persistent(&database).unwrap());
        let context = store_context_from_shared_store(project.project(), Arc::clone(&store), false);
        let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            project.project_dyn(),
            config,
            context,
        )
        .unwrap();
        let snapshots = store
            .workspace_snapshots_for_current_languages(
                &workspace_id,
                &[
                    "csharp".into(),
                    "go".into(),
                    "java".into(),
                    "python".into(),
                    "rust".into(),
                ],
            )
            .unwrap();
        assert_eq!(snapshots.len(), 5, "{snapshots:?}");
        for snapshot in snapshots.values() {
            assert_eq!(snapshot.workspace_id, workspace_id);
            assert_eq!(
                snapshot.generation.0, 0,
                "first use rotated preserved inputs"
            );
            assert!(snapshot.revision >= 1);
        }
        let cancellation = CancellationToken::new();
        store.reconcile_rust_crates(&snapshots["rust"]).unwrap();
        assert!(
            store
                .reconcile_unit_summaries(&snapshots["rust"], RustUnitSummaries, &cancellation)
                .unwrap()
                .failed
                .is_empty()
        );
        store
            .reconcile_jvm_package_context(&snapshots["java"])
            .unwrap();
        let published = store
            .publish_go_source_context(snapshots["go"].clone(), project.root(), &cancellation)
            .unwrap();
        let go_package_context::GoContextPublicationOutcome::Published(go) = published else {
            panic!("{published:?}")
        };
        assert!(
            store
                .reconcile_unit_summaries(
                    &snapshots["go"],
                    GoUnitSummaries {
                        context_id: go.context_id,
                        profile: go_package_context::source_inventory_profile()
                    },
                    &cancellation
                )
                .unwrap()
                .failed
                .is_empty()
        );
        let python = PythonNativeEnvironment::open(
            &database,
            project.root(),
            PythonSummaryProfile {
                authority: PythonSummaryAuthority::SuppliedAnalysis,
                observation: PythonSummaryObservation::Runtime,
                roots: vec![std::path::PathBuf::new()],
                ordered: true,
                target_digest: [0; 32],
                python_version: None,
            },
        )
        .unwrap();
        let revision = python.publish_project(project.project_dyn()).unwrap();
        assert!(
            python
                .reconcile(revision, &cancellation)
                .unwrap()
                .failed
                .is_empty()
        );
        assert_eq!(
            store
                .publish_jvm_external_projection(
                    || Ok(Some(JvmExternalProjection {
                        provider_id: "item".into(),
                        source_identity: "item".into(),
                        owners: vec![vec![
                            Value::Text("item".into()),
                            Value::Text("upgrade.Owner".into()),
                            Value::Integer(1),
                            Value::Integer(1),
                            Value::Integer(1),
                            Value::Integer(1),
                            Value::Text("[]".into())
                        ]],
                        members: vec![],
                        supertypes: vec![]
                    })),
                    || false
                )
                .unwrap(),
            JvmExternalPublication::Available
        );
        // Each check uses the independently named token file, not the writer's
        // accessor, so a label, token state or mismatched domain cannot pass.
        macro_rules! identity {
            ($name:literal) => {
                brokk_bifrost_core::lever_tokens::lever_identity(
                    $name,
                    include_str!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../bifrost-store/levers/",
                        $name,
                        ".tokens"
                    )),
                )
            };
        }
        let expected = [
            (
                "csharp_compilation_sets",
                "derivation_identity",
                "1",
                identity!("csharp-compilation-derivation"),
            ),
            (
                "go_context_selections",
                "derivation_identity",
                "1",
                identity!("go-context-derivation"),
            ),
            (
                "jvm_context_revisions",
                "derivation_identity",
                "1",
                identity!("jvm-context-derivation"),
            ),
            (
                "resolution_unit_summaries",
                "derivation_identity",
                "lang='rust'",
                identity!("rust-unit-summary-derivation"),
            ),
            (
                "resolution_unit_summaries",
                "derivation_identity",
                "lang='go'",
                identity!("go-unit-summary-derivation"),
            ),
            (
                "resolution_unit_summaries",
                "derivation_identity",
                "lang='python'",
                identity!("python-unit-summary-derivation"),
            ),
            (
                "rust_source_listing_certificates",
                "derivation_identity",
                "1",
                brokk_bifrost_core::lever_tokens::lever_identity(
                    "rust-source-listing-derivation",
                    include_str!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../bifrost-rust/levers/rust-source-listing-derivation.tokens"
                    )),
                ),
            ),
            (
                "jvm_external_provider_publications",
                "projection_identity",
                "1",
                identity!("jvm-external-projection"),
            ),
            (
                "rust_crate_reconciliations",
                "derivation_identity",
                "1",
                identity!("rust-crate-derivation"),
            ),
        ];
        let conn = store.read_conn().unwrap();
        assert_eq!(
            query_rows(&conn, "SELECT DISTINCT workspace_id FROM workspace_heads"),
            vec![vec![Value::Text(workspace_id.0.clone())]],
            "first use built a different workspace"
        );
        assert_eq!(
            query_rows(
                &conn,
                "SELECT lang,generation,revision FROM workspace_revisions WHERE revision=1 ORDER BY lang"
            ),
            ["csharp", "go", "java", "python", "rust"]
                .map(|lang| vec![
                    Value::Text(lang.into()),
                    Value::Integer(0),
                    Value::Integer(1)
                ])
                .to_vec(),
            "first use lost the preserved revisions"
        );
        assert_eq!(
            query_rows(&conn, "SELECT DISTINCT generation FROM analysis_epochs"),
            vec![vec![Value::Integer(0)]],
            "first use rotated generations instead of rebuilding migrated inputs"
        );
        for (table, column, predicate, identity) in expected {
            let rows = query_rows(
                &conn,
                &format!("SELECT {column} FROM {table} WHERE {predicate}"),
            );
            assert!(
                !rows.is_empty(),
                "first use did not rebuild {table}: {predicate}"
            );
            for row in rows {
                assert_eq!(
                    row,
                    vec![Value::Blob(identity.to_vec())],
                    "{table}: {predicate}"
                );
            }
        }
        assert_no_orphans(&conn, &upgraded_keys);
        drop(workspace);
    }
}
