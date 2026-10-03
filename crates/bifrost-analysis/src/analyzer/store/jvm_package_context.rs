//! Deterministic JVM context derived from one immutable source/config snapshot.
//! Only SQLite rows survive reconciliation. Rust holds one pom's parsed facts
//! at a time; source membership is inserted by indexed selected-row queries.

use std::path::{Component, Path, PathBuf};

use brokk_bifrost_core::path_normalization::NormalizePath;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{AnalyzerStore, Result, WorkspaceSnapshotId, WorkspaceSnapshots};
use crate::analyzer::jvm::topology::{
    MavenConfigurationFacts, MavenModelLimitation, MavenValue, maven_configuration_from_bytes,
};

pub(crate) const JVM_CONTEXT_DERIVATION_VERSION: i64 = 1;

pub(super) const JVM_NATIVE_SOURCE_MEMBERSHIP_SQL: &str =
    "INSERT INTO jvm_source_root_files(context_id,root_id,source_file_version_id)
     SELECT context_id,?2,file_version_id FROM jvm_selected_source_files
     WHERE context_id=?1 AND rel_path>=?3 AND rel_path<?4";

impl AnalyzerStore {
    pub(crate) fn reconcile_jvm_package_contexts(
        &self,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<()> {
        for language in ["java", "kotlin", "scala"] {
            if let Some(snapshot) = snapshots.get(language) {
                self.reconcile_jvm_package_context(snapshot)?;
            }
        }
        Ok(())
    }

    pub(crate) fn reconcile_jvm_package_context(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<i64> {
        assert!(matches!(
            snapshot.lang.as_str(),
            "java" | "kotlin" | "scala"
        ));
        let snapshot = snapshot.clone();
        self.conn.execute(move |connection| {
            // Reserve the writer before reading; a deferred snapshot upgrade can
            // fail immediately under contention despite the configured busy timeout.
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            super::require_current_generation(&tx, &snapshot.lang, snapshot.generation)?;
            let existing = tx.query_row(
                "SELECT context_id FROM jvm_context_revisions
                 WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND revision=?4 AND derivation_version=?5",
                params![snapshot.workspace_id.as_str(), snapshot.lang, snapshot.generation.get(), snapshot.revision, JVM_CONTEXT_DERIVATION_VERSION],
                |row| row.get(0),
            ).optional()?;
            if let Some(context_id) = existing {
                return Ok(context_id);
            }
            tx.execute(
                "INSERT INTO jvm_context_revisions(workspace_id,lang,generation,revision,derivation_version)
                 VALUES(?1,?2,?3,?4,?5)",
                params![snapshot.workspace_id.as_str(), snapshot.lang, snapshot.generation.get(), snapshot.revision, JVM_CONTEXT_DERIVATION_VERSION],
            )?;
            let context_id = tx.last_insert_rowid();
            let mut parsed_project = false;
            {
                let mut statement = tx.prepare(
                    "SELECT file_version_id,rel_path,source_bytes FROM jvm_selected_configuration_files
                     WHERE context_id=?1 ORDER BY rel_path",
                )?;
                let mut configurations = statement.query([context_id])?;
                while let Some(row) = configurations.next()? {
                    let file_version_id: i64 = row.get(0)?;
                    let relative_path: String = row.get(1)?;
                    let path = Path::new(&relative_path);
                    match path.file_name().and_then(|name| name.to_str()) {
                        Some("pom.xml") => {
                            let bytes: Option<Vec<u8>> = row.get(2)?;
                            let facts = bytes.as_deref().and_then(|bytes| maven_configuration_from_bytes(path, bytes));
                            if let Some(facts) = facts {
                                publish_project(&tx, context_id, file_version_id, &relative_path, facts)?;
                                parsed_project = true;
                            } else {
                                insert_gap(&tx, context_id, None, Some(file_version_id),
                                    "maven_configuration_unavailable", &relative_path)?;
                            }
                        }
                        Some("build.gradle" | "build.gradle.kts" | "settings.gradle" | "settings.gradle.kts") => {
                            insert_gap(&tx, context_id, None, Some(file_version_id),
                                "gradle_topology_unsupported", &relative_path)?;
                        }
                        _ => {}
                    }
                }
            }
            if !parsed_project {
                insert_gap(&tx, context_id, None, None, "jvm_source_roots_unavailable",
                    "No readable selected Maven project declares a default source layout")?;
            }
            // These source declarations do not identify selected JDK/dependency
            // artifact bytes. Later artifact authority may discharge this gap.
            insert_gap(&tx, context_id, None, None, "jvm_external_inventory_unavailable",
                "Selected source/configuration facts do not certify JDK or external artifacts")?;
            tx.execute(
                "INSERT INTO jvm_context_gaps(context_id,input_file_version_id,code,evidence)
                 SELECT f.context_id,f.file_version_id,'source_root_unowned',f.rel_path
                 FROM jvm_selected_source_files AS f
                 WHERE f.context_id=?1 AND NOT EXISTS(
                   SELECT 1 FROM jvm_source_root_files AS m
                   WHERE m.context_id=f.context_id AND m.source_file_version_id=f.file_version_id)",
                [context_id],
            )?;
            tx.execute(
                "INSERT INTO jvm_context_gaps(context_id,input_file_version_id,code,evidence)
                 SELECT m.context_id,m.source_file_version_id,'source_root_ambiguous',
                        f.rel_path || ': ' || group_concat(r.root_path, ', ')
                 FROM jvm_source_root_files AS m
                 JOIN jvm_source_roots AS r ON r.context_id=m.context_id AND r.root_id=m.root_id
                 JOIN jvm_selected_source_files AS f ON f.context_id=m.context_id AND f.file_version_id=m.source_file_version_id
                 WHERE m.context_id=?1 GROUP BY m.context_id,m.source_file_version_id HAVING COUNT(*)>1",
                [context_id],
            )?;
            tx.commit()?;
            Ok(context_id)
        })
    }
}

fn value_columns(value: &MavenValue) -> (&'static str, Option<&str>) {
    match value {
        MavenValue::Missing => ("missing", None),
        MavenValue::Unresolved => ("unresolved", None),
        MavenValue::Resolved(value) => ("resolved", Some(value)),
    }
}

fn insert_gap(
    tx: &Transaction<'_>,
    context_id: i64,
    project_id: Option<i64>,
    input_file_version_id: Option<i64>,
    code: &str,
    evidence: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO jvm_context_gaps(context_id,project_id,input_file_version_id,code,evidence)
         VALUES(?1,?2,?3,?4,?5)",
        params![
            context_id,
            project_id,
            input_file_version_id,
            code,
            evidence
        ],
    )?;
    Ok(())
}

fn publish_project(
    tx: &Transaction<'_>,
    context_id: i64,
    file_version_id: i64,
    pom_path: &str,
    facts: MavenConfigurationFacts,
) -> Result<()> {
    let (version_state, version_value) = value_columns(&facts.version);
    let directory = crate::path_utils::normalize_pattern(&facts.directory.to_string_lossy());
    tx.execute(
        "INSERT INTO jvm_projects(context_id,pom_file_version_id,directory,group_id,artifact_id,version_state,version_value)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![context_id,file_version_id,directory,facts.group_id,facts.artifact_id,version_state,version_value],
    )?;
    let project_id = tx.last_insert_rowid();
    // An explicit custom layout contradicts default-root ownership. Keep
    // those selected source files unowned until that layout is interpreted.
    if !facts
        .limitations
        .contains(&MavenModelLimitation::CustomSourceRoots)
    {
        for (role, root) in facts.default_source_roots() {
            let root = crate::path_utils::normalize_pattern(&root.to_string_lossy());
            tx.execute(
            "INSERT INTO jvm_source_roots(context_id,project_id,role,root_path) VALUES(?1,?2,?3,?4)",
            params![context_id,project_id,role,root],
        )?;
            let root_id = tx.last_insert_rowid();
            // Normalized SQL paths use '/'. Its immediate ASCII successor '0'
            // bounds exactly the subtree prefix, without glob metacharacters.
            tx.execute(
                JVM_NATIVE_SOURCE_MEMBERSHIP_SQL,
                params![context_id, root_id, format!("{root}/"), format!("{root}0")],
            )?;
        }
    }
    for limitation in &facts.limitations {
        let code = match limitation {
            MavenModelLimitation::ParentModel => "maven_parent_model_unresolved",
            MavenModelLimitation::Profiles => "maven_profiles_unresolved",
            MavenModelLimitation::DependencyManagement => "maven_dependency_management_unresolved",
            MavenModelLimitation::CustomSourceRoots => "maven_custom_source_roots_unresolved",
            MavenModelLimitation::BuildPlugins => "maven_build_plugins_unresolved",
        };
        insert_gap(tx, context_id, Some(project_id), None, code, pom_path)?;
    }
    for module in &facts.modules {
        let selected_path = match module {
            MavenValue::Resolved(module) => selected_module_path(&facts.directory, module),
            MavenValue::Missing | MavenValue::Unresolved => None,
        };
        let selected = if let Some(path) = &selected_path {
            let path = crate::path_utils::normalize_pattern(&path.to_string_lossy());
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM jvm_selected_configuration_files WHERE context_id=?1 AND rel_path=?2)",
                params![context_id,path], |row| row.get::<_, bool>(0),
            )?
        } else {
            false
        };
        if !selected {
            insert_gap(
                tx,
                context_id,
                Some(project_id),
                None,
                "maven_module_unavailable",
                &format!("{pom_path}: {module:?}"),
            )?;
        }
    }
    for dependency in &facts.dependencies {
        let group = value_columns(&dependency.group_id);
        let artifact = value_columns(&dependency.artifact_id);
        let version = value_columns(&dependency.version);
        let artifact_type = value_columns(&dependency.artifact_type);
        let classifier = value_columns(&dependency.classifier);
        let scope = value_columns(&dependency.scope);
        let optional = value_columns(&dependency.optional);
        tx.execute(
            "INSERT INTO jvm_direct_dependencies(context_id,project_id,ordinal,
               group_id_state,group_id_value,artifact_id_state,artifact_id_value,version_state,version_value,
               artifact_type_state,artifact_type_value,classifier_state,classifier_value,scope_state,scope_value,optional_state,optional_value)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![context_id,project_id,dependency.ordinal,group.0,group.1,artifact.0,artifact.1,version.0,version.1,
                artifact_type.0,artifact_type.1,classifier.0,classifier.1,scope.0,scope.1,optional.0,optional.1],
        )?;
        let unresolved = [
            ("groupId", &dependency.group_id),
            ("artifactId", &dependency.artifact_id),
            ("version", &dependency.version),
            ("type", &dependency.artifact_type),
            ("classifier", &dependency.classifier),
            ("scope", &dependency.scope),
            ("optional", &dependency.optional),
        ]
        .into_iter()
        .filter_map(|(name, value)| matches!(value, MavenValue::Unresolved).then_some(name))
        .collect::<Vec<_>>();
        if !unresolved.is_empty() {
            insert_gap(
                tx,
                context_id,
                Some(project_id),
                None,
                "maven_dependency_values_unresolved",
                &format!(
                    "{pom_path}, dependency {}: {unresolved:?}",
                    dependency.ordinal
                ),
            )?;
        }
        if [
            &dependency.group_id,
            &dependency.artifact_id,
            &dependency.version,
        ]
        .into_iter()
        .any(|value| matches!(value, MavenValue::Missing))
        {
            insert_gap(
                tx,
                context_id,
                Some(project_id),
                None,
                "maven_dependency_coordinates_partial",
                &format!(
                    "{pom_path}, dependency {}: group={:?}, artifact={:?}, version={:?}",
                    dependency.ordinal,
                    dependency.group_id,
                    dependency.artifact_id,
                    dependency.version
                ),
            )?;
        }
    }
    Ok(())
}

/// Resolve module paths lexically without permitting an escape or consulting
/// current disk contents. NormalizePath alone would erase a leading escape.
fn selected_module_path(directory: &Path, module: &str) -> Option<PathBuf> {
    let candidate = directory
        .join(crate::path_utils::normalize_pattern(module))
        .join("pom.xml");
    let mut depth = 0usize;
    for component in candidate.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => depth = depth.checked_sub(1)?,
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    crate::path_utils::workspace_rel_path(&candidate.normalize().to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::java::JavaAdapter;
    use crate::analyzer::store::{WorkspaceConfigurationInput, WorkspaceFileRow, WorkspaceId};
    use crate::analyzer::tree_sitter_analyzer::{TreeSitterAnalyzer, ephemeral_store_context};
    use crate::analyzer::{AnalyzerConfig, IAnalyzer, Language};
    use crate::inline_project::InlineTestProject;
    use git2::{ObjectType, Oid};
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use std::thread;

    const POM: &str = "<project><groupId>example</groupId><artifactId>same</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>other</artifactId><scope>test</scope><optional>true</optional></dependency><dependency><groupId>${unknown}</groupId><artifactId>missing</artifactId><version>${unresolved}</version></dependency></dependencies></project>";

    fn snapshot(
        store: &AnalyzerStore,
        language: &str,
        sources: &[(&str, &str)],
        configurations: &[(&str, &str)],
    ) -> WorkspaceSnapshotId {
        let generation = store
            .ensure_language_epoch_value(language, "jvm-context-test")
            .unwrap();
        let files = sources
            .iter()
            .map(|(path, source)| WorkspaceFileRow {
                rel_path: (*path).to_owned(),
                blob_oid: Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap(),
            })
            .collect::<Vec<_>>();
        let inputs = configurations
            .iter()
            .map(|(path, source)| {
                WorkspaceConfigurationInput::new(
                    (*path).to_owned(),
                    source.as_bytes().to_vec().into_boxed_slice(),
                )
            })
            .collect::<Vec<_>>();
        store
            .sync_workspace_inputs_for_workspace(
                &WorkspaceId(
                    "7878787878787878787878787878787878787878787878787878787878787878".to_owned(),
                ),
                language,
                generation,
                &files,
                &[],
                &[],
                &[],
                &[],
                &[],
                &inputs,
                &[],
            )
            .unwrap()
    }

    fn members(store: &AnalyzerStore, context_id: i64) -> Vec<(String, String, String)> {
        store.conn.execute(move |connection| {
            connection.prepare("SELECT rel_path,pom_path,role FROM jvm_selected_source_root_files WHERE context_id=?1 ORDER BY rel_path,pom_path,role")
                .unwrap().query_map([context_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))
                .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        })
    }

    fn gap_codes(store: &AnalyzerStore, context_id: i64) -> Vec<String> {
        store.conn.execute(move |connection| {
            connection
                .prepare(
                    "SELECT code FROM jvm_selected_context_gaps WHERE context_id=?1 ORDER BY code",
                )
                .unwrap()
                .query_map([context_id], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        })
    }

    enum BusyHandlerCommand {
        Busy,
        Release,
    }

    struct BusyHandlerState {
        command: SyncSender<BusyHandlerCommand>,
        continue_rx: Receiver<()>,
        announced: Arc<AtomicBool>,
    }

    thread_local! {
        static JVM_CONTEXT_BUSY_HANDLER_STATE: RefCell<Option<BusyHandlerState>> = const { RefCell::new(None) };
    }

    fn jvm_context_busy_handler(_attempt: i32) -> bool {
        JVM_CONTEXT_BUSY_HANDLER_STATE.with(|state| {
            let state = state.borrow();
            let Some(state) = state.as_ref() else {
                return false;
            };
            if !state.announced.swap(true, Ordering::SeqCst) {
                if state.command.send(BusyHandlerCommand::Busy).is_err() {
                    return false;
                }
                state.continue_rx.recv().is_ok()
            } else {
                true
            }
        })
    }

    #[test]
    fn selected_jvm_roots_keep_path_identity_and_direct_dependency_uncertainty() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let selected = snapshot(
            &store,
            "java",
            &[
                ("one[mod]/src/main/java/Main.java", "class Main {}"),
                ("two/src/test/java/Test.java", "class Test {}"),
                ("one[mod]/src/mainish/Outside.java", "class Outside {}"),
            ],
            &[("one[mod]/pom.xml", POM), ("two/pom.xml", POM)],
        );
        let context = store.reconcile_jvm_package_context(&selected).unwrap();
        assert_eq!(
            store.reconcile_jvm_package_context(&selected).unwrap(),
            context
        );
        assert_eq!(
            members(&store, context),
            vec![
                (
                    "one[mod]/src/main/java/Main.java".into(),
                    "one[mod]/pom.xml".into(),
                    "main".into()
                ),
                (
                    "two/src/test/java/Test.java".into(),
                    "two/pom.xml".into(),
                    "test".into()
                ),
            ]
        );
        let rows = store.conn.execute(move |connection| {
            connection.prepare("SELECT d.ordinal,d.group_id_state,d.version_state,d.scope_value,d.optional_value FROM jvm_direct_dependencies d JOIN jvm_selected_projects p ON p.context_id=d.context_id AND p.project_id=d.project_id WHERE d.context_id=?1 AND p.pom_path='two/pom.xml' ORDER BY d.ordinal")
                .unwrap().query_map([context], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?)))
                .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        });
        assert_eq!(
            rows,
            vec![
                (
                    0,
                    "resolved".into(),
                    "missing".into(),
                    Some("test".into()),
                    Some("true".into())
                ),
                (1, "unresolved".into(), "unresolved".into(), None, None),
            ]
        );
        let gaps = gap_codes(&store, context);
        assert!(gaps.contains(&"source_root_unowned".to_owned()));
        assert!(gaps.contains(&"maven_dependency_values_unresolved".to_owned()));
        assert!(gaps.contains(&"jvm_external_inventory_unavailable".to_owned()));
    }

    #[test]
    fn selected_jvm_source_membership_uses_bounded_snapshot_path_index() {
        use super::super::planner_statistics::pinned_plans::{pinned, plan_rows};
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::types::Value;

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let paths = (0..512)
            .map(|index| format!("module{}/src/main/java/Class{index}.java", index % 8))
            .collect::<Vec<_>>();
        let sources = paths
            .iter()
            .map(|path| (path.as_str(), "class Example {}"))
            .collect::<Vec<_>>();
        let selected = snapshot(&store, "java", &sources, &[("module3/pom.xml", POM)]);
        let context = store.reconcile_jvm_package_context(&selected).unwrap();
        assert_eq!(members(&store, context).len(), 64);
        store.conn.execute(move |connection| {
            let root: i64 = connection
                .query_row(
                    "SELECT root_id FROM jvm_source_roots WHERE context_id=?1 AND role='main'",
                    [context],
                    |row| row.get(0),
                )
                .unwrap();
            let mut query = pinned("jvm_native_source_membership");
            query.params = vec![
                Value::Integer(context),
                Value::Integer(root),
                Value::Text("module3/src/main/".into()),
                Value::Text("module3/src/main0".into()),
            ];
            for statistics in PlannerStatisticsState::BOTH {
                statistics.install(connection);
                let rows = plan_rows(connection, &query).unwrap();
                assert!(
                    rows.iter().any(|row| (row
                        .contains("idx_workspace_file_versions_snapshot_kind")
                        || row.contains("sqlite_autoindex_workspace_file_versions_1"))
                        && row.contains("rel_path>?")
                        && row.contains("rel_path<?")),
                    "{statistics:?}: {rows:?}"
                );
                for forbidden in ["SCAN f", "AUTOMATIC", "TEMP B-TREE", "CO-ROUTINE"] {
                    assert!(
                        !rows.iter().any(|row| row.contains(forbidden)),
                        "{statistics:?}: {rows:?}"
                    );
                }
            }
        });
    }

    #[test]
    fn selected_jvm_publication_is_atomic_and_retryable() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let selected = snapshot(
            &store,
            "java",
            &[("src/main/java/App.java", "class App {}")],
            &[("pom.xml", POM)],
        );
        store.conn.execute(|connection| connection.execute_batch(
            "CREATE TEMP TRIGGER abort_jvm_dependency BEFORE INSERT ON jvm_direct_dependencies BEGIN SELECT RAISE(ABORT, 'injected publication failure'); END;",
        )).unwrap();
        assert!(store.reconcile_jvm_package_context(&selected).is_err());
        let rows = store.conn.execute(|connection| connection.query_row(
            "SELECT (SELECT count(*) FROM jvm_context_revisions),(SELECT count(*) FROM jvm_projects),(SELECT count(*) FROM jvm_source_root_files)", [],
            |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?)),
        )).unwrap();
        assert_eq!(rows, (0, 0, 0));
        store
            .conn
            .execute(|connection| connection.execute_batch("DROP TRIGGER abort_jvm_dependency"))
            .unwrap();
        let context = store.reconcile_jvm_package_context(&selected).unwrap();
        assert_eq!(members(&store, context).len(), 1);
    }

    #[test]
    fn jvm_context_publication_reserves_the_writer_slot_before_reading() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("jvm-context.db");
        let store = AnalyzerStore::open_persistent(&database).unwrap();
        let selected = snapshot(
            &store,
            "java",
            &[("src/main/java/App.java", "class App {}")],
            &[("pom.xml", POM)],
        );

        let (command_tx, command_rx) = mpsc::sync_channel(1);
        let (continue_tx, continue_rx) = mpsc::sync_channel(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<()>(1);
        let contender = thread::spawn(move || -> std::result::Result<(), String> {
            let mut connection = crate::cache_db::open_unified_connection(&database)
                .map_err(|error| format!("opening competing JVM writer: {error}"))?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| format!("reserving competing JVM writer: {error}"))?;
            ready_tx
                .send(())
                .map_err(|_| "sending competing-writer readiness".to_owned())?;
            match command_rx
                .recv()
                .map_err(|_| "waiting for JVM busy-handler command".to_owned())?
            {
                BusyHandlerCommand::Busy => {
                    drop(transaction);
                    continue_tx
                        .send(())
                        .map_err(|_| "releasing JVM publication busy handler".to_owned())?;
                }
                BusyHandlerCommand::Release => drop(transaction),
            }
            Ok(())
        });

        let handler_state = BusyHandlerState {
            command: command_tx.clone(),
            continue_rx,
            announced: Arc::new(AtomicBool::new(false)),
        };
        let announced = Arc::clone(&handler_state.announced);
        let busy_timeout = store
            .conn
            .execute(move |connection| {
                let busy_timeout: u64 =
                    connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
                connection.busy_handler(Some(jvm_context_busy_handler))?;
                JVM_CONTEXT_BUSY_HANDLER_STATE.with(|state| {
                    assert!(state.borrow().is_none(), "JVM busy handler state leaked");
                    *state.borrow_mut() = Some(handler_state);
                });
                Ok::<u64, rusqlite::Error>(busy_timeout)
            })
            .unwrap();
        if ready_rx.recv().is_err() {
            contender
                .join()
                .expect("competing JVM writer panicked during setup")
                .expect("competing JVM writer failed during setup");
            panic!("competing JVM writer dropped readiness");
        }

        let result = store.reconcile_jvm_package_context(&selected);
        if !announced.load(Ordering::SeqCst) {
            command_tx
                .send(BusyHandlerCommand::Release)
                .expect("releasing competing JVM writer after reconciliation failure");
        }
        contender
            .join()
            .expect("competing JVM writer panicked")
            .expect("competing JVM writer failed");
        store
            .conn
            .execute(move |connection| {
                connection.busy_timeout(std::time::Duration::from_millis(busy_timeout))?;
                JVM_CONTEXT_BUSY_HANDLER_STATE.with(|state| {
                    assert!(
                        state.borrow_mut().take().is_some(),
                        "JVM busy handler state missing"
                    );
                });
                Ok::<(), rusqlite::Error>(())
            })
            .unwrap();
        assert!(
            result.is_ok(),
            "JVM publication failed under contention: {result:?}"
        );
    }

    #[test]
    fn selected_jvm_revisions_and_languages_keep_exact_membership() {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("App.java", "class App {}")
            .build();
        let database = fixture.root().join("jvm-context.db");
        let store = AnalyzerStore::open_persistent(&database).unwrap();
        let old_snapshot = snapshot(
            &store,
            "java",
            &[("src/main/java/Old.java", "class Old {}")],
            &[("pom.xml", POM)],
        );
        let old_context = store.reconcile_jvm_package_context(&old_snapshot).unwrap();
        let new_snapshot = snapshot(
            &store,
            "java",
            &[("src/test/java/New.java", "class New {}")],
            &[("pom.xml", POM)],
        );
        let new_context = store.reconcile_jvm_package_context(&new_snapshot).unwrap();
        let kotlin = snapshot(
            &store,
            "kotlin",
            &[("src/main/kotlin/Peer.kt", "class Peer")],
            &[("pom.xml", POM)],
        );
        let kotlin_context = store.reconcile_jvm_package_context(&kotlin).unwrap();
        assert_ne!(old_context, new_context);
        assert_ne!(new_context, kotlin_context);
        assert_eq!(members(&store, old_context)[0].0, "src/main/java/Old.java");
        assert_eq!(members(&store, new_context)[0].0, "src/test/java/New.java");
        assert_eq!(
            members(&store, kotlin_context)[0].0,
            "src/main/kotlin/Peer.kt"
        );
        let foreign_project: i64 = store
            .conn
            .execute(move |connection| {
                connection.query_row(
                    "SELECT project_id FROM jvm_projects WHERE context_id=?1",
                    [kotlin_context],
                    |row| row.get(0),
                )
            })
            .unwrap();
        let invalid_gap = store.conn.execute(move |connection| connection.execute(
            "INSERT INTO jvm_context_gaps(context_id,project_id,code,evidence) VALUES(?1,?2,'cross_context','invalid')",
            params![new_context,foreign_project],
        ));
        assert!(
            invalid_gap.is_err(),
            "scoped gaps cannot name another context's project"
        );
        drop(store);
        let reopened = AnalyzerStore::open_persistent(&database).unwrap();
        assert_eq!(
            reopened
                .reconcile_jvm_package_context(&new_snapshot)
                .unwrap(),
            new_context
        );
        assert_eq!(
            members(&reopened, old_context)[0].0,
            "src/main/java/Old.java"
        );
    }

    #[test]
    fn selected_jvm_scratch_gradle_and_overlapping_roots_stay_partial() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let scratch = snapshot(
            &store,
            "java",
            &[("App.java", "class App {}")],
            &[("build.gradle", "plugins { id 'java' }")],
        );
        let scratch_context = store.reconcile_jvm_package_context(&scratch).unwrap();
        assert!(members(&store, scratch_context).is_empty());
        let gaps = gap_codes(&store, scratch_context);
        for code in [
            "gradle_topology_unsupported",
            "jvm_source_roots_unavailable",
            "source_root_unowned",
        ] {
            assert!(gaps.contains(&code.to_owned()), "{gaps:?}");
        }
        let custom = snapshot(
            &store,
            "java",
            &[("src/main/java/App.java", "class App {}")],
            &[(
                "pom.xml",
                "<project><groupId>example</groupId><artifactId>custom</artifactId><build><sourceDirectory>elsewhere</sourceDirectory></build></project>",
            )],
        );
        let custom_context = store.reconcile_jvm_package_context(&custom).unwrap();
        assert!(members(&store, custom_context).is_empty());
        assert!(
            gap_codes(&store, custom_context)
                .contains(&"maven_custom_source_roots_unresolved".to_owned())
        );
        let overlap = snapshot(
            &store,
            "java",
            &[("src/main/nested/src/main/java/App.java", "class App {}")],
            &[("pom.xml", POM), ("src/main/nested/pom.xml", POM)],
        );
        let overlap_context = store.reconcile_jvm_package_context(&overlap).unwrap();
        assert_eq!(members(&store, overlap_context).len(), 2);
        assert!(gap_codes(&store, overlap_context).contains(&"source_root_ambiguous".to_owned()));
        assert_eq!(
            selected_module_path(Path::new("parent"), "../sibling"),
            Some(PathBuf::from("sibling/pom.xml"))
        );
        assert!(selected_module_path(Path::new("parent"), "../../outside").is_none());
    }

    #[test]
    fn selected_jvm_gap_view_preserves_exact_scope_validation() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let old = snapshot(
            &store,
            "java",
            &[("src/main/java/Old.java", "class Old {}")],
            &[("pom.xml", POM)],
        );
        let old_context = store.reconcile_jvm_package_context(&old).unwrap();
        let changed_pom = POM.replace(
            "<artifactId>same</artifactId>",
            "<artifactId>changed</artifactId>",
        );
        let current = snapshot(
            &store,
            "java",
            &[("src/main/java/New.java", "class New {}")],
            &[("pom.xml", &changed_pom)],
        );
        let current_context = store.reconcile_jvm_package_context(&current).unwrap();
        let foreign = snapshot(
            &store,
            "kotlin",
            &[("src/main/kotlin/Peer.kt", "class Peer")],
            &[("pom.xml", POM)],
        );
        let foreign_context = store.reconcile_jvm_package_context(&foreign).unwrap();
        store.conn.execute(move |connection| {
            let old_project: i64 = connection.query_row("SELECT project_id FROM jvm_projects WHERE context_id=?1", [old_context], |row| row.get(0)).unwrap();
            let current_project: i64 = connection.query_row("SELECT project_id FROM jvm_projects WHERE context_id=?1", [current_context], |row| row.get(0)).unwrap();
            let source = |context: i64| connection.query_row("SELECT file_version_id FROM jvm_selected_source_files WHERE context_id=?1", [context], |row| row.get::<_,i64>(0)).unwrap();
            let old_source = source(old_context);
            let current_source = source(current_context);
            let foreign_source = source(foreign_context);
            // Adversarial rows exercise the public view boundary. The ordinary
            // publisher never creates stale project or foreign input scopes.
            connection.execute("INSERT INTO jvm_projects(context_id,pom_file_version_id,directory,group_id,artifact_id,version_state) SELECT ?1,pom_file_version_id,directory,group_id,artifact_id,'missing' FROM jvm_projects WHERE project_id=?2", params![current_context,old_project]).unwrap();
            let stale_project = connection.last_insert_rowid();
            for (project, file, code) in [
                (Some(current_project), Some(current_source), "proof_live"),
                (Some(stale_project), None, "proof_stale_project"),
                (None, Some(old_source), "proof_stale_input"),
                (None, Some(foreign_source), "proof_foreign_input"),
            ] {
                connection.execute("INSERT INTO jvm_context_gaps(context_id,project_id,input_file_version_id,code,evidence) VALUES(?1,?2,?3,?4,'scope boundary probe')", params![current_context,project,file,code]).unwrap();
            }
            let wrong_project = connection.execute("INSERT INTO jvm_context_gaps(context_id,project_id,code,evidence) VALUES(?1,?2,'proof_foreign_project','rejected by composite FK')", params![current_context,old_project]);
            assert!(wrong_project.is_err());
            // The pre-replacement left-join view is the equivalence oracle.
            let previous = connection.prepare(
                "SELECT g.gap_id FROM jvm_context_gaps g
                 JOIN jvm_context_revisions c ON c.context_id=g.context_id
                 LEFT JOIN jvm_selected_projects p ON p.context_id=g.context_id AND p.project_id=g.project_id
                 LEFT JOIN workspace_file_versions f ON f.file_version_id=g.input_file_version_id
                  AND f.workspace_id=c.workspace_id AND f.lang=c.lang AND f.generation=c.generation
                  AND f.valid_from<=c.revision AND (f.valid_until IS NULL OR f.valid_until>c.revision)
                 WHERE g.context_id=?1 AND (g.project_id IS NULL OR p.project_id IS NOT NULL)
                  AND (g.input_file_version_id IS NULL OR f.file_version_id IS NOT NULL) ORDER BY g.gap_id")
                .unwrap().query_map([current_context], |row| row.get::<_,i64>(0)).unwrap()
                .collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let selected = connection.prepare("SELECT gap_id FROM jvm_selected_context_gaps WHERE context_id=?1 ORDER BY gap_id")
                .unwrap().query_map([current_context], |row| row.get::<_,i64>(0)).unwrap()
                .collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(selected, previous);
            let codes = connection.prepare("SELECT code FROM jvm_selected_context_gaps WHERE context_id=?1 AND code LIKE 'proof_%' ORDER BY code")
                .unwrap().query_map([current_context], |row| row.get::<_,String>(0)).unwrap()
                .collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(codes, ["proof_live"]);
        });
    }

    #[test]
    fn java_analyzer_build_and_updates_publish_selected_contexts() {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("pom.xml", POM)
            .file("src/main/java/App.java", "class App {}")
            .build();
        let project = fixture.project_dyn();
        let context = ephemeral_store_context(project.as_ref()).unwrap();
        let store = Arc::clone(&context.store);
        let first = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap();
        let initial = first.selected_workspace_snapshots()["java"].clone();
        let context_for = |snapshot: &WorkspaceSnapshotId| {
            let snapshot = snapshot.clone();
            store.conn.execute(move |connection| connection.query_row(
                "SELECT context_id FROM jvm_context_revisions WHERE workspace_id=?1 AND lang='java' AND generation=?2 AND revision=?3",
                params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision], |row| row.get::<_,i64>(0),
            )).unwrap()
        };
        let initial_context = context_for(&initial);
        assert_eq!(members(&store, initial_context).len(), 1);
        let source = fixture.file("src/main/java/App.java");
        source.write("class App { int changed; }").unwrap();
        let updated = first.update(&BTreeSet::from([source]));
        let changed = updated.selected_workspace_snapshots()["java"].clone();
        assert_ne!(context_for(&changed), initial_context);
        let pom = fixture.file("pom.xml");
        pom.write("<project><groupId>example</groupId><artifactId>renamed</artifactId><version>2</version></project>").unwrap();
        let configured = updated.update(&BTreeSet::from([pom]));
        let configuration = configured.selected_workspace_snapshots()["java"].clone();
        assert_ne!(context_for(&configuration), context_for(&changed));
        let rebuilt = configured.update_all();
        assert_eq!(
            context_for(&rebuilt.selected_workspace_snapshots()["java"]),
            context_for(&configuration)
        );
    }
}
