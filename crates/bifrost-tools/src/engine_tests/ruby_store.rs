#[cfg(test)]
mod ruby_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
    use rusqlite::params;

    use brokk_bifrost_analysis::analyzer::store::{
        AnalyzerStore, bool_to_i64, code_unit_kind_to_i64,
    };

    use std::sync::Arc;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::MAX_LIMITED_QUERY_AGGREGATE_BYTES;

    use brokk_bifrost_core::analyzer::model::MAX_SIGNATURE_METADATA_COLUMN_BYTES;

    use brokk_bifrost_core::analyzer::model::ParameterMetadata;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    use brokk_bifrost_analysis::analyzer::store::SIGNATURE_LABEL_ELISION;

    use brokk_bifrost_core::analyzer::model::SignatureMetadata;

    use brokk_bifrost_analysis::analyzer::store::signature_metadata_for_unit_sql;

    use brokk_bifrost_core::test_support::write_file;

    use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;

    use brokk_bifrost_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_python_analysis::analyzer::python::adapter::PythonAdapter;

    use brokk_bifrost_ruby_analysis::analyzer::ruby::adapter::RubyAdapter;

    use brokk_bifrost_analysis::analyzer::scala::adapter::ScalaAdapter;

    use brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAdapter;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_deleting_side_table_marks_incomplete;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_direct_prepared_parity;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_round_trip;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_signature_metadata_round_trips;

    use brokk_bifrost_analysis::analyzer::store::test_support::fully_populated_signature_metadata;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use brokk_bifrost_analysis::analyzer::store::test_support::replace_test_metadata_bridges;

    #[test]
    fn signature_metadata_columns_round_trip_through_every_reader() {
        let temp = tempfile::TempDir::new().unwrap();
        let populated = fully_populated_signature_metadata();
        let bare = SignatureMetadata::new(populated.label(), Vec::new());
        let different_label = SignatureMetadata::new("different", Vec::new());
        let rows = [populated, bare, different_label];

        assert_signature_metadata_round_trips(
            &RubyAdapter,
            "ruby",
            &write_file(
                temp.path(),
                "factory.rb",
                "class Factory\n  def make(value)\n    value\n  end\nend\n",
            ),
            &rows,
        );
        assert_signature_metadata_round_trips(
            &JavaAdapter,
            "java",
            &write_file(temp.path(), "Factory.java", "class Factory {}\n"),
            &rows,
        );
    }
    #[test]
    fn usage_projection_keeps_plain_first_signature_unpaired() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file(
                "factory.rb",
                "class Factory\n  def make(value)\n    value\n  end\nend\n",
            )
            .build();
        let file = fixture.file("factory.rb");
        let source = file.read_to_string().unwrap();
        let mut state = parse_state(&RubyAdapter, &file);
        let target = state
            .signature_metadata
            .keys()
            .next()
            .cloned()
            .expect("fixture should produce a metadata-bearing unit");
        state.signatures.insert(
            target.clone(),
            vec![
                "plain first signature".to_owned(),
                "metadata-bearing second signature".to_owned(),
            ],
        );
        let metadata = vec![
            SignatureMetadata::new("later alternative one", Vec::new()),
            SignatureMetadata::new("later alternative two", Vec::new()),
        ];
        replace_test_metadata_bridges(&mut state, &target, metadata.len());
        state
            .signature_metadata
            .insert(target.clone(), metadata.clone());
        state
            .signature_metadata_signature_ordinals
            .insert(target.clone(), vec![1, 1]);
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "unpaired-first-signature")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "ruby",
                generation,
                &RubyAdapter,
                &state,
            )
            .unwrap();

        let usage_row = store
            .usage_fact_rows_by_lang("ruby")
            .unwrap()
            .into_iter()
            .find(|row| row.candidate.short_name == target.short_name())
            .expect("usage-fact row for the target unit");
        assert_eq!(
            usage_row.signature.as_deref(),
            Some("plain first signature")
        );
        assert_eq!(usage_row.signature_metadata, None);
        assert_eq!(
            store
                .signature_metadata_for_unit(oid, "ruby", generation, &target)
                .unwrap(),
            metadata,
            "the unbounded callable reader must retain later alternatives"
        );
    }
    #[test]
    #[should_panic(expected = "beyond")]
    fn signature_metadata_pair_preparation_rejects_out_of_range_coordinate() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file(
                "factory.rb",
                "class Factory\n  def make(value)\n    value\n  end\nend\n",
            )
            .build();
        let file = fixture.file("factory.rb");
        let mut state = parse_state(&RubyAdapter, &file);
        let target = state
            .signature_metadata
            .keys()
            .next()
            .cloned()
            .expect("fixture should produce metadata");
        let metadata_len = state.signature_metadata[&target].len();
        state
            .signature_metadata_signature_ordinals
            .insert(target, vec![usize::MAX; metadata_len]);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "invalid-signature-metadata-pair")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "ruby",
                generation,
                &RubyAdapter,
                &state,
            )
            .expect("invalid metadata/signature coordinate must panic during preparation");
    }
    #[test]
    fn signature_metadata_unbounded_reader_preserves_rows_beyond_bounded_byte_budget() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file(
                "factory.rb",
                "class Factory\n  def make(value)\n    value\n  end\nend\n",
            )
            .build();
        let file = fixture.file("factory.rb");
        let mut state = parse_state(&RubyAdapter, &file);
        let target = state.signature_metadata.keys().next().unwrap().clone();
        let metadata = (0..=MAX_LIMITED_QUERY_AGGREGATE_BYTES
            / MAX_SIGNATURE_METADATA_COLUMN_BYTES)
            .map(|ordinal| {
                SignatureMetadata::new(format!("make_{ordinal}"), Vec::new())
                    .with_return_type_text(Some("x".repeat(MAX_SIGNATURE_METADATA_COLUMN_BYTES)))
            })
            .collect::<Vec<_>>();
        replace_test_metadata_bridges(&mut state, &target, metadata.len());
        state
            .signature_metadata
            .insert(target.clone(), metadata.clone());
        state
            .signature_metadata_signature_ordinals
            .insert(target.clone(), vec![0; metadata.len()]);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "unbounded-signature-metadata")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "ruby",
                generation,
                &RubyAdapter,
                &state,
            )
            .unwrap();

        let limited = store
            .signature_metadata_for_unit_limited(oid, "ruby", generation, &target, usize::MAX)
            .unwrap();
        assert!(
            !limited.complete,
            "the bounded API must enforce its byte budget"
        );
        assert_eq!(
            store
                .signature_metadata_for_unit(oid, "ruby", generation, &target)
                .unwrap(),
            metadata,
            "the Vec API must preserve every alternative, without an implicit byte cutoff"
        );

        let assert_indexed = || {
            let conn = store.read_conn().unwrap();
            let mut statement = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {}",
                    signature_metadata_for_unit_sql()
                ))
                .unwrap();
            let plan = statement
                .query_map(
                    params![
                        oid.to_string(),
                        "ruby",
                        target.fq_name(),
                        code_unit_kind_to_i64(target.kind()),
                        target.short_name(),
                        target.signature(),
                        bool_to_i64(target.is_synthetic()),
                        -1i64,
                    ],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter()
                    .any(|detail| detail.contains("SEARCH metadata USING PRIMARY KEY")),
                "unbounded metadata must seek the populated primary key: {plan:?}"
            );
            assert!(
                plan.iter().all(|detail| !detail.contains("SCAN metadata")),
                "unbounded metadata must not scan unrelated metadata: {plan:?}"
            );
        };
        assert_indexed();
        store.refresh_planner_statistics().unwrap();
        assert_indexed();
    }
    /// The size cap is a schema CHECK now, not a read-side gate, so an
    /// oversized row must fail its INSERT and take the whole blob's
    /// transaction with it. The previous shape of this test corrupted a stored
    /// blob with `zeroblob` and asserted the readers nulled it out; there is no
    /// longer a column that can hold such a value.
    ///
    /// The column under test is `return_type_text` rather than `label`: since
    /// issue #2351 the encoder clamps an oversized label, because a label is a
    /// rendering that can always be made shorter. Every other oversized column
    /// still fails loudly, which is what this pins.
    #[brokk_bifrost_test_macros::hardwon(
        "#2351: oversized persisted return-type metadata must fail and roll back instead of publishing a partial blob"
    )]
    #[test]
    fn oversized_signature_metadata_is_rejected_by_the_schema_and_publishes_nothing() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "factory.rb",
            "class Factory\n  def make(value)\n    value\n  end\nend\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let mut state = parse_state(&RubyAdapter, &file);
        let target = state
            .signature_metadata
            .keys()
            .next()
            .cloned()
            .expect("fixture should produce signature metadata");
        state.signature_metadata.insert(
            target.clone(),
            vec![
                SignatureMetadata::new("make(value)", Vec::new()).with_return_type_text(Some(
                    "x".repeat(MAX_SIGNATURE_METADATA_COLUMN_BYTES + 1),
                )),
            ],
        );
        state
            .signature_metadata_signature_ordinals
            .insert(target, vec![0]);
        let state = Arc::new(state);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "oversized-signature-metadata-write-v1")
            .unwrap();

        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "ruby",
            generation,
            &RubyAdapter,
            Arc::clone(&state),
        )
        .expect("preparation encodes columns without enforcing the cap");
        let (outcomes, _) = store.persist_prepared_blobs(
            vec![prepared],
            PersistBatchTargets {
                max_blobs: usize::MAX,
                max_rows: usize::MAX,
                max_payload_bytes: usize::MAX,
            },
        );
        let prepared_error = outcomes[0]
            .error
            .as_ref()
            .expect("the prepared write must fail")
            .to_string();
        assert!(
            prepared_error.contains("CHECK constraint failed"),
            "SQLite must reject the oversized column itself: {prepared_error}"
        );

        let write_error = store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "ruby",
                generation,
                &RubyAdapter,
                state.as_ref(),
            )
            .expect_err("direct persistence must reject oversized signature metadata")
            .to_string();
        assert!(
            write_error.contains("CHECK constraint failed"),
            "SQLite must reject the oversized column itself: {write_error}"
        );
        assert!(
            !store
                .contains_parsed_blob_at_generation(oid, "ruby", generation)
                .unwrap(),
            "a rejected metadata row must roll back instead of publishing a complete omission"
        );
    }
    /// Issue #2351: a label is a rendering, so an oversized one is clamped and
    /// the file still indexes. The parameter spans index the label, so the
    /// clamp must drop the ones that no longer land inside it.
    #[brokk_bifrost_test_macros::hardwon(
        "9b24a4c0ceb1: oversized generated labels aborted persistence instead of being clamped"
    )]
    #[test]
    fn an_oversized_label_is_clamped_instead_of_failing_the_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "factory.rb",
            "class Factory\n  def make(value)\n    value\n  end\nend\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let mut state = parse_state(&RubyAdapter, &file);
        let target = state
            .signature_metadata
            .keys()
            .next()
            .cloned()
            .expect("fixture should produce signature metadata");
        let oversized = format!(
            "make({})",
            "x".repeat(MAX_SIGNATURE_METADATA_COLUMN_BYTES + 1)
        );
        let far_end = oversized.len() - 1;
        state.signature_metadata.insert(
            target.clone(),
            vec![SignatureMetadata::new(
                oversized,
                vec![
                    ParameterMetadata::new("mak", 0, 3),
                    ParameterMetadata::new("tail", far_end - 4, far_end),
                ],
            )],
        );
        state
            .signature_metadata_signature_ordinals
            .insert(target, vec![0]);
        let state = Arc::new(state);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "clamped-signature-label-write-v1")
            .unwrap();

        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "ruby",
                generation,
                &RubyAdapter,
                state.as_ref(),
            )
            .expect("a clamped label must not fail the blob");
        assert!(
            store
                .contains_parsed_blob_at_generation(oid, "ruby", generation)
                .unwrap(),
            "the file must still index despite one pathological declaration"
        );

        let conn = store.conn.lock().expect("store mutex");
        let (label, parameters): (String, String) = conn
            .query_row(
                "SELECT label, parameters FROM unit_signature_metadata_values",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            label.len() <= MAX_SIGNATURE_METADATA_COLUMN_BYTES,
            "the stored label must respect the column cap, got {} bytes",
            label.len()
        );
        assert!(
            label.ends_with(SIGNATURE_LABEL_ELISION),
            "a clamped label must say so in the value itself"
        );
        assert!(
            parameters.contains("\"mak\"") && !parameters.contains("\"tail\""),
            "only spans inside the retained prefix may survive: {parameters}"
        );
    }
    #[test]
    fn metadata_side_table_count_mismatches_are_treated_as_incomplete() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let ruby_file = write_file(
            root,
            "lib/demo.rb",
            "require 'json'\nclass Demo\n  attr_reader :name\n  alias_method :label, :name\n  def initialize(name)\n    @name = name\n  end\n  def self.build(value)\n    new(value)\n  end\nend\n",
        );
        let python_file = write_file(
            root,
            "pkg/corrupt.py",
            "import os\nfrom sys import path\nclass Corrupt:\n    def run(self):\n        return os.getcwd()\n",
        );
        let java_file = write_file(
            root,
            "src/demo/Corrupt.java",
            "package demo;\nimport java.util.List;\nclass Corrupt extends Base { List<String> names; void run(List<String> input) {} }\nclass Base {}\n",
        );
        let scala_file = write_file(
            root,
            "src/main/scala/app/Corrupt.scala",
            "package app\ntrait Runnable\nclass Worker extends Runnable\nobject Core { def run(): Int = 1 }\nobject Facade { export Core.{run as execute, *} }\n",
        );
        let cpp_file = write_file(
            root,
            "include/corrupt.h",
            "template <typename T, typename U = T*> class Corrupt {};\ntemplate <typename T> class Corrupt<T, T*> {};\n",
        );
        let typescript_file = write_file(
            root,
            "src/corrupt.ts",
            "export interface Shape { area(): number }\nexport class Corrupt implements Shape { area(): number { return 1; } }\n",
        );

        for table in [
            "unit_ranges",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_signature_metadata_signatures",
            "unit_children",
            "ruby_method_dispatch_modes",
        ] {
            assert_deleting_side_table_marks_incomplete(&RubyAdapter, "ruby", &ruby_file, table);
        }
        assert_deleting_side_table_marks_incomplete(
            &PythonAdapter::for_test_file(&python_file),
            "python",
            &python_file,
            "import_statements",
        );
        for table in ["unit_supertypes", "reference_identifiers"] {
            assert_deleting_side_table_marks_incomplete(&JavaAdapter, "java", &java_file, table);
        }
        for table in ["scala_traits", "scala_exports"] {
            assert_deleting_side_table_marks_incomplete(&ScalaAdapter, "scala", &scala_file, table);
        }
        assert_deleting_side_table_marks_incomplete(
            &TypescriptAdapter,
            "typescript",
            &typescript_file,
            "materialization_records",
        );
        assert_deleting_side_table_marks_incomplete(
            &CppAdapter,
            "cpp",
            &cpp_file,
            "unit_cpp_class_templates",
        );
    }
    #[test]
    fn round_trips_optional_fact_manifest_languages_and_unrelated_language() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let ruby_file = write_file(
            root,
            "lib/demo.rb",
            "module Demo\n  module_function\n  def build(value)\n    Product.new(value)\n  end\n  class Product\n    attr_reader :name\n    alias_method :label, :name\n    def initialize(name)\n      @name = name\n    end\n    def self.featured\n      new('sample')\n    end\n  end\nend\n",
        );
        let scala_file = write_file(
            root,
            "src/main/scala/app/Demo.scala",
            "package app\ntrait Runnable { def run(first: Int = 0)(rest: String*): Int }\nclass Worker extends Runnable\nobject Core { def run(): Int = 1 }\nobject Facade { export Core.{run as execute, *} }\n",
        );
        let cpp_file = write_file(
            root,
            "include/demo.h",
            "template <typename T, typename U = T*> class Demo {};\ntemplate <typename T> class Demo<T, T*> {};\n",
        );
        let python_file = write_file(root, "pkg/demo.py", "class Demo:\n    pass\n");

        assert_round_trip(&RubyAdapter, "ruby", &ruby_file);
        assert_round_trip(&ScalaAdapter, "scala", &scala_file);
        assert_round_trip(&CppAdapter, "cpp", &cpp_file);
        assert_round_trip(
            &PythonAdapter::for_test_file(&python_file),
            "python",
            &python_file,
        );

        let source = python_file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(
                oid,
                "python",
                &PythonAdapter::for_test_file(&python_file),
                &parse_state(&PythonAdapter::for_test_file(&python_file), &python_file),
            )
            .unwrap();
        let conn = store.conn.lock().unwrap();
        let manifest_rows: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM blob_optional_fact_manifest
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'python')",
                [oid.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(manifest_rows, 0);
    }
    #[test]
    fn direct_adapter_write_matches_explicit_prepared_write() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let ruby_file = write_file(
            root,
            "lib/demo.rb",
            "module Demo\n  module_function\n  def build(value)\n    Product.new(value)\n  end\n  class Product\n    attr_reader :name\n    alias_method :label, :name\n  end\nend\n",
        );
        let scala_file = write_file(
            root,
            "src/main/scala/app/Demo.scala",
            "package app\nimport scala.collection.mutable.ListBuffer\ntrait Runnable\nclass Worker extends Runnable\nobject Core { def run(): Int = 1 }\nobject Facade { export Core.{run as execute, *} }\n",
        );
        let ts_file = write_file(
            root,
            "src/demo.test.ts",
            "import {Thing} from './thing';\nexport class Demo { run(value: Thing): Thing { return value; } }\n",
        );
        let cpp_file = write_file(
            root,
            "include/demo.h",
            "template <typename T, typename U = T*> class Demo {};\ntemplate <typename T> class Demo<T, T*> {};\n",
        );

        assert_direct_prepared_parity(&RubyAdapter, "ruby", &ruby_file);
        assert_direct_prepared_parity(&ScalaAdapter, "scala", &scala_file);
        assert_direct_prepared_parity(&TypescriptAdapter, "typescript", &ts_file);
        assert_direct_prepared_parity(&CppAdapter, "cpp", &cpp_file);
    }
    /// Ruby generation provenance (issue #1476) survives the store: the
    /// producer records literal `attr_*`/`alias_method` generation and the
    /// dynamic site, and both hydration paths return the records verbatim.
    #[test]
    fn materialization_records_round_trip_through_persistence() {
        use brokk_bifrost_core::analyzer::structural::materialization::GenerationInputClass;

        use brokk_bifrost_core::analyzer::structural::materialization::GenerationKind;

        use brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord;

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "provenance.rb",
            "class Widget\n  attr_accessor :name\n  attr_reader label.to_sym\n  def base; end\n  alias_method :aliased, :base\nend\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let state = parse_state(&RubyAdapter, &file);

        let records = &state.materialization_records;
        let generated_units: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::GeneratedDeclaration { kind, unit, .. } => {
                    Some((*kind, unit.fq_name().to_string()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            generated_units,
            vec![
                (GenerationKind::AccessorMacro, "Widget.@name".to_string()),
                (GenerationKind::AccessorMacro, "Widget.name".to_string()),
                (GenerationKind::AccessorMacro, "Widget.name=".to_string()),
                (GenerationKind::AliasMacro, "Widget.aliased".to_string()),
            ],
            "complete recorded generation set: {records:?}"
        );
        let dynamic_sites: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::DynamicGenerationSite { kind, .. } => Some(*kind),
                _ => None,
            })
            .collect();
        assert_eq!(dynamic_sites, vec![GenerationKind::AccessorMacro]);
        for record in records {
            if let MaterializationRecord::GeneratedDeclaration { site, argument, .. } = record {
                assert!(
                    site.start_byte <= argument.start_byte && argument.end_byte <= site.end_byte,
                    "argument must lie inside its generation site: {record:?}"
                );
                assert_eq!(GenerationInputClass::Literal.label(), "literal");
            }
        }

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "materialization-round-trip-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "ruby",
                generation,
                &RubyAdapter,
                &state,
            )
            .unwrap();

        let hydrated = store
            .hydrate_file_state_with_source(oid, "ruby", generation, &RubyAdapter, &file, &source)
            .unwrap()
            .expect("hydration should succeed");
        assert_eq!(
            hydrated.materialization_records,
            state.materialization_records
        );

        let bulk = store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                "ruby",
                &RubyAdapter,
                &HashMap::from_iter([(file.clone(), source)]),
            )
            .unwrap();
        assert_eq!(
            bulk.get(&file)
                .expect("bulk hydration")
                .materialization_records,
            state.materialization_records
        );
    }
}
