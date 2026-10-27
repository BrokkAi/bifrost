use brokk_bifrost_analysis::analyzer::store::jvm_package_context::*;
use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, WorkspaceSnapshotId};
use rusqlite::{TransactionBehavior, params};
use std::path::{Path, PathBuf};
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod tests {
    use super::*;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::Language;

    use brokk_bifrost_analysis::analyzer::store::{
        WorkspaceConfigurationInput, WorkspaceFileRow, WorkspaceId,
    };

    #[cfg(test)]
    use brokk_bifrost_analysis::inline_project::InlineTestProject;

    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    use git2::{ObjectType, Oid};
    #[cfg(test)]
    use std::cell::RefCell;

    #[cfg(test)]
    use std::sync::Arc;

    #[cfg(test)]
    use std::sync::atomic::{AtomicBool, Ordering};

    #[cfg(test)]
    use std::sync::mpsc::{self};
    #[cfg(test)]
    use std::sync::mpsc::{Receiver, SyncSender};

    #[cfg(test)]
    use std::thread;

    #[doc(hidden)]
    pub const POM: &str = "<project><groupId>example</groupId><artifactId>same</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>other</artifactId><scope>test</scope><optional>true</optional></dependency><dependency><groupId>${unknown}</groupId><artifactId>missing</artifactId><version>${unresolved}</version></dependency></dependencies></project>";

    #[doc(hidden)]
    pub fn snapshot(
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
                &[],
            )
            .unwrap()
    }

    #[doc(hidden)]
    pub fn members(store: &AnalyzerStore, context_id: i64) -> Vec<(String, String, String)> {
        store.conn.execute(move |connection| {
            connection.prepare("SELECT rel_path,pom_path,role FROM jvm_selected_source_root_files WHERE context_id=?1 ORDER BY rel_path,pom_path,role")
                .unwrap().query_map([context_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))
                .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        })
    }

    #[cfg(test)]
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

    #[cfg(test)]
    #[test]
    #[hardwon(
        "bee8b6fe1e65: Kotlin source access missed a Java file under the same Maven main root"
    )]
    fn selected_jvm_source_access_uses_shared_maven_roots_for_cross_language_files() {
        #[doc(hidden)]
        pub const POM: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>jvm-call-bindings</artifactId><version>1</version></project>";
        const KOTLIN_CALLER: &str = "src/main/kotlin/jdbc.kt";
        const JAVA_CALLER: &str = "src/main/java/JdbcCall.java";
        const JAVA_TARGET: &str = "src/main/java/java/sql/Statement.java";

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let java_snapshot = snapshot(
            &store,
            "java",
            &[
                (JAVA_CALLER, "class JdbcCall {}"),
                (
                    JAVA_TARGET,
                    "package java.sql; public interface Statement {}",
                ),
            ],
            &[("pom.xml", POM)],
        );
        let kotlin_snapshot = snapshot(
            &store,
            "kotlin",
            &[(KOTLIN_CALLER, "fun use() = Unit")],
            &[("pom.xml", POM)],
        );
        let java_context = store.reconcile_jvm_package_context(&java_snapshot).unwrap();
        let kotlin_context = store
            .reconcile_jvm_package_context(&kotlin_snapshot)
            .unwrap();

        let (java_rows, kotlin_rows, java_access, kotlin_access) =
            store.conn.execute(move |connection| {
                let file_version = |context, path: &str| {
                    connection
                        .query_row(
                            "SELECT file_version_id FROM jvm_selected_source_files WHERE context_id=?1 AND rel_path=?2",
                            rusqlite::params![context, path],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap()
                };
                let row_count = |context, path: &str| {
                    connection
                        .query_row(
                            "SELECT count(*) FROM jvm_selected_source_root_files WHERE context_id=?1 AND rel_path=?2",
                            rusqlite::params![context, path],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap()
                };
                let access = |context, caller, caller_path: &str, target| {
                    connection
                        .query_row(
                            brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::SOURCE_ACCESS,
                            rusqlite::params![context, caller, caller_path, target, JAVA_TARGET],
                            |row| row.get::<_, String>(0),
                        )
                        .unwrap()
                };
                let java_caller = file_version(java_context, JAVA_CALLER);
                let kotlin_caller = file_version(kotlin_context, KOTLIN_CALLER);
                let java_target = file_version(java_context, JAVA_TARGET);
                (
                    (row_count(java_context, JAVA_CALLER), row_count(java_context, JAVA_TARGET)),
                    (row_count(kotlin_context, KOTLIN_CALLER), row_count(kotlin_context, JAVA_TARGET)),
                    access(java_context, java_caller, JAVA_CALLER, java_target),
                    access(kotlin_context, kotlin_caller, KOTLIN_CALLER, java_target),
                )
            });

        assert_eq!(java_rows, (1, 1));
        assert_eq!(kotlin_rows, (1, 0));
        assert_eq!(java_access, "known");
        assert_eq!(kotlin_access, "known");
    }

    #[cfg(test)]
    enum BusyHandlerCommand {
        Busy,
        Release,
    }

    #[cfg(test)]
    struct BusyHandlerState {
        command: SyncSender<BusyHandlerCommand>,
        continue_rx: Receiver<()>,
        announced: Arc<AtomicBool>,
    }

    #[cfg(test)]
    thread_local! {
        static JVM_CONTEXT_BUSY_HANDLER_STATE: RefCell<Option<BusyHandlerState>> = const { RefCell::new(None) };
    }

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
    #[test]
    fn selected_jvm_source_membership_uses_bounded_snapshot_path_index() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::{
            pinned, plan_rows,
        };
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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
}
