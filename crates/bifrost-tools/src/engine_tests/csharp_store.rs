#[cfg(test)]
mod csharp_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    use brokk_bifrost_analysis::analyzer::store::epoch;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

    use brokk_bifrost_core::test_support::write_file;
    use brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAdapter;

    #[test]
    fn csharp_linked_file_access_agrees_per_caller_compilation() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::read_ledger::{DerivationExecutionCause, reason};
        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextIdentities;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_units::{
            ACCESS_UNKNOWN, CSharpUnitAccess, CSharpUnitReader, PLACEMENT_SQL,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection,
            finish_production_selected_sql_trace_on_connection,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test;
        use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
        use brokk_bifrost_core::{analyzer::Language, cancellation::CancellationToken};
        if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "engine_tests::csharp_store::csharp_extraction_tests::csharp_linked_file_access_agrees_per_caller_compilation", "--nocapture"])
                .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
                .output().unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "the child must run: {output:?}"
            );
            return;
        }
        let project = "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"../Linked.cs\" /></ItemGroup></Project>";
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file("A/A.csproj", project)
            .file("B/B.csproj", project)
            .file("Linked.cs", "class Linked {}")
            .file("A/Caller.cs", "class Caller {}")
            .file("A/Target.cs", "class Target {}")
            .file("B/Hidden.cs", "class Hidden {}")
            .file("Outside.cs", "class Outside {}")
            .build();
        let context =
            single_connection_store_context_for_test(fixture.project_dyn().as_ref()).unwrap();
        let workspace_id = context.workspace_id.clone();
        let store = Arc::clone(&context.store);
        let _workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
            context,
        )
        .unwrap();
        let snapshots = store
            .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
            .unwrap();
        let cancellation = CancellationToken::new();
        let languages = [SelectedResolutionLanguage::new("csharp", Language::CSharp)];
        let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace_id,
                &snapshots,
                &languages,
                &[],
                &cancellation,
            )
            .unwrap()
        else {
            panic!("selected C# inventory");
        };
        let identities = SelectedContextIdentities::new();
        let mut reader =
            CSharpUnitReader::new(&selection, &snapshots["csharp"], &identities).unwrap();
        begin_production_selected_sql_trace_on_connection(selection.connection());
        let linked = reader.placements("Linked.cs").unwrap().unwrap();
        let cost = finish_production_selected_sql_trace_on_connection(selection.connection());
        assert_eq!(
            linked
                .iter()
                .map(|p| p.project_path.as_deref())
                .collect::<Vec<_>>(),
            [Some("A/A.csproj"), Some("B/B.csproj")]
        );
        assert_eq!(
            cost.statements
                .iter()
                .filter(|sql| sql.as_str() == PLACEMENT_SQL)
                .count(),
            2,
            "{cost:?}"
        );
        assert_eq!(
            cost.rows_by_shape()
                .iter()
                .find(|(_, _, sql)| *sql == PLACEMENT_SQL)
                .map(|(rows, _, _)| *rows),
            Some(2),
            "{cost:?}"
        );
        let caller = reader.placements("A/Caller.cs").unwrap().unwrap();
        let target = reader.placements("A/Target.cs").unwrap().unwrap();
        let hidden = reader.placements("B/Hidden.cs").unwrap().unwrap();
        begin_production_selected_sql_trace_on_connection(selection.connection());
        assert_eq!(
            reader.access(Some(&caller), Some(&target)).unwrap(),
            CSharpUnitAccess::Visible
        );
        assert_eq!(
            reader.access(Some(&caller), Some(&hidden)).unwrap(),
            CSharpUnitAccess::NotVisible
        );
        let CSharpUnitAccess::Unknown { kind, evidence } =
            reader.access(Some(&linked), Some(&target)).unwrap()
        else {
            panic!("linked callers disagree");
        };
        assert_eq!(kind, ACCESS_UNKNOWN);
        assert_eq!(
            reason::classify_known(kind),
            Some(Some(DerivationExecutionCause::Provider))
        );
        assert!(
            evidence.contains("A/A.csproj") && evidence.contains("B/B.csproj"),
            "{evidence}"
        );
        // A target linked into both projects is visible to A even though B is not.
        assert_eq!(
            reader.access(Some(&caller), Some(&linked)).unwrap(),
            CSharpUnitAccess::Visible
        );
        let outside = reader.placements("Outside.cs").unwrap().unwrap();
        assert!(outside.is_empty());
        assert!(matches!(
            reader.access(Some(&caller), Some(&outside)).unwrap(),
            CSharpUnitAccess::Unknown { .. }
        ));
        let unselected = reader.placements("NotSelected.cs").unwrap();
        assert!(unselected.is_none());
        assert!(matches!(
            reader.access(unselected.as_deref(), Some(&target)).unwrap(),
            CSharpUnitAccess::Unknown { .. }
        ));
        let cost = finish_production_selected_sql_trace_on_connection(selection.connection());
        // These are M2's real closure statements on the held connection, not
        // constructed pair answers or a memo that was never populated.
        let closures: Vec<_> = cost
            .statements
            .iter()
            .filter(|sql| sql.contains("WITH RECURSIVE reach"))
            .collect();
        assert!(
            closures
                .iter()
                .any(|sql| sql.contains("references_complete")),
            "{cost:?}"
        );
        assert!(
            closures.iter().any(|sql| sql.contains("expand")),
            "{cost:?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "5304870f83d5: production C# test-like calls were misclassified by runner-name matching"
    )]
    #[test]
    fn csharp_structured_test_classification_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Http3RequestTests.cs",
            "public class Http3RequestTests {\n\
             [ConditionalTheory]\n\
             public void RequestAbortRaised() { }\n\
             }\n",
        );
        let mut state = parse_state(&CSharpAdapter, &file);
        assert!(state.contains_tests);
        // The direct-name classifier used before this epoch did not recognize
        // custom xUnit attributes and persisted this runnable test as false.
        state.contains_tests = false;
        let state = Arc::new(state);
        let prior_epoch = epoch::csharp_epoch_before_structured_runnable_test_classification();
        assert_prior_parsed_blob_invalidated(&CSharpAdapter, state.as_ref(), &prior_epoch);
    }
    #[brokk_bifrost_test_macros::hardwon(
        "1396a5373c5b: inherited C# test methods were missing from derived-class blast radius"
    )]
    #[test]
    fn csharp_inherited_test_classification_epoch_invalidates_prior_owner_facts() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "BaseSpec.cs",
            "public abstract class BaseSpec {\n\
             [Fact]\n\
             public virtual void Inherited() { }\n\
             }\n",
        );
        let mut state = parse_state(&CSharpAdapter, &file);
        assert!(state.contains_tests);
        assert_eq!(1, state.test_region_units.len());
        // The immediately preceding C# epoch retained only the file-level
        // boolean. It did not identify which declaring type owns the runner
        // method, so a hierarchy walk could not classify derived files.
        state.test_region_units.clear();
        let state = Arc::new(state);
        let prior_epoch = epoch::csharp_epoch_before_inherited_test_classification();
        assert_prior_parsed_blob_invalidated(&CSharpAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn csharp_nested_type_persists_structural_and_namespace_visibility() {
        let temp = tempfile::TempDir::new().unwrap();
        let content = "namespace Demo { class Outer { public class Nested<T> {} } }\n";
        let file = write_file(temp.path(), "Nested.cs", content);
        let oid = oid_for(content.as_bytes());
        let adapter = CSharpAdapter;
        let state = parse_state(&adapter, &file);
        let nested = state
            .declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier().starts_with("Nested"))
            .expect("fixture declares a nested type");
        assert_eq!(nested.package_name(), "Demo");

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "csharp", &adapter, &state)
            .unwrap();
        let workspace_file = WorkspaceFileRow {
            rel_path: brokk_bifrost_core::path_utils::rel_path_string(&file),
            blob_oid: oid,
        };
        store
            .sync_workspace_snapshot(
                "csharp",
                GenerationId::BOOTSTRAP,
                &[workspace_file],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();

        let conn = store.conn.lock().expect("store mutex");
        let containers = conn
            .prepare(
                "SELECT exact_parent_tail
                 FROM live_visible_members
                 WHERE lang = 'csharp' AND identifier LIKE 'Nested%'
                 ORDER BY exact_parent_tail",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(containers, ["Demo", "Demo.Outer"]);

        let (simple_name, normalized_tail, segment_count): (String, String, i64) = conn
            .query_row(
                "SELECT units.simple_type_name, units.normalized_fqn_tail,
                        COUNT(segments.seg_ordinal)
                 FROM code_units AS units
                 JOIN code_unit_fq_segments AS segments
                   ON segments.blob_id = units.blob_id
                  AND segments.unit_key = units.unit_key
                 WHERE units.blob_id = (
                         SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'csharp'
                       )
                   AND units.identifier LIKE 'Nested%'
                 GROUP BY units.blob_id, units.unit_key",
                [oid.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(simple_name, "Nested");
        assert_eq!(normalized_tail, "Demo.Outer.Nested");
        assert_eq!(segment_count, nested.fq().len() as i64);
    }
}
