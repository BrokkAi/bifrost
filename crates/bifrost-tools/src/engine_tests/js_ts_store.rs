#[cfg(test)]
mod js_ts_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    pub(super) use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    pub(super) use std::sync::Arc;

    pub(super) use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

    pub(super) use brokk_bifrost_core::analyzer::model::ProjectFile;

    pub(super) use brokk_bifrost_analysis::analyzer::store::test_support::assert_round_trip;

    pub(super) use brokk_bifrost_analysis::analyzer::store::epoch;

    pub(super) use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    pub(super) use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use brokk_bifrost_core::test_support::write_file;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_python_analysis::analyzer::python::adapter::PythonAdapter;

    use brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAdapter;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

    fn assert_ts_tsx_bump_invalidates_prior_dialect_blobs(bump_token: &str) {
        fn check<A: LanguageAdapter>(adapter: &A, prior_epoch: &str, file: &ProjectFile) {
            let state = parse_state(adapter, file);
            let oid = oid_for(state.source.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let keys = adapter.storage_language_keys();
            for (key, _) in &keys {
                let generation = store.ensure_language_epoch_value(key, prior_epoch).unwrap();
                store
                    .write_parsed_blob_at_generation(
                        &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                        oid,
                        key,
                        generation,
                        adapter,
                        &state,
                    )
                    .unwrap();
                assert!(store.contains_parsed_blob(oid, key).unwrap());
            }
            // Follow the production path, including its language-level memoization.
            let epochs = keys
                .iter()
                .map(|(key, parser)| {
                    (
                        key.clone(),
                        epoch::epoch_for(adapter.language(), parser).to_string(),
                    )
                })
                .collect::<Vec<_>>();
            store.ensure_language_epoch_values(&epochs).unwrap();
            for (key, _) in &keys {
                assert!(!store.contains_parsed_blob(oid, key).unwrap(), "{key}");
            }
        }

        let fixture = crate::inline_project::InlineTestProject::new()
            .file("view.js", "export const view = 1;")
            .file("view.ts", "export const view = 1;")
            .build();
        for (path, language) in [
            ("view.js", epoch::TestEpochLanguage::JavaScript),
            ("view.ts", epoch::TestEpochLanguage::TypeScript),
        ] {
            let file = fixture.file(path);
            let prior = epoch::epoch_before_bump(language, bump_token);
            if path.ends_with(".js") {
                check(
                    &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
                    &prior,
                    &file,
                );
            } else {
                check(&TypescriptAdapter, &prior, &file);
            }
        }
    }
    /// The TypeScript half of the same #2911 bump.
    #[brokk_bifrost_test_macros::hardwon(
        "#2911: TypeScript aliases gained their own type identity, which stale cache rows could not represent"
    )]
    #[test]
    fn ts_type_alias_identity_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "tags.ts",
            "export type MaxVal = number;\n\nexport const MaxVal = 1;\n",
        );
        let state = Arc::new(parse_state(&TypescriptAdapter, &file));
        let alias = state
            .declarations
            .iter()
            .find(|unit| unit.fq_name() == "tags.ts.MaxVal" && unit.is_class())
            .expect("the current walk mints the alias as a type declaration");
        assert!(
            state
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "tags.ts.MaxVal" && unit.is_field()),
            "the const keeps its own field declaration beside {alias:?}: {:?}",
            state.declarations
        );
        let prior_epoch = epoch::typescript_epoch_before_type_alias_type_identity();
        assert_prior_parsed_blob_invalidated(&TypescriptAdapter, state.as_ref(), &prior_epoch);
    }
    /// #2597: the JavaScript walk now records callable modifier metadata.
    /// A blob written under the prior epoch says "nobody read the modifiers",
    /// which every consumer reads as "undecided" rather than as an error, so
    /// the salt is the only thing that retires those rows.
    #[brokk_bifrost_test_macros::hardwon(
        "#2597: persisted JavaScript callables lacked modifier metadata needed for call binding"
    )]
    #[test]
    fn js_callable_modifier_metadata_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "widget.js",
            "export class Widget {\n    static build(spec) { return new Widget(spec); }\n    render(target) { return target; }\n}\n",
        );
        let state = Arc::new(parse_state(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            &file,
        ));
        let prior_epoch = epoch::epoch_before_bump(
            epoch::TestEpochLanguage::JavaScript,
            "js-ts-callable-modifier-metadata-2026-08",
        );
        assert_prior_parsed_blob_invalidated(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            state.as_ref(),
            &prior_epoch,
        );
    }
    /// #2593: `Receiver.#field = value` no longer mints a Field declaration.
    /// A blob written under the prior epoch still carries the parentless
    /// duplicate of the class field, and nothing in the row says it is stale,
    /// so the salt is the only thing that retires it.
    #[test]
    fn js_private_name_assignment_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "pointers.js",
            "class CurrentPointers {\n    static #pointerType = null;\n    static set(pointerType) { CurrentPointers.#pointerType = pointerType; }\n}\n",
        );
        let state = Arc::new(parse_state(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            &file,
        ));
        let prior_epoch = epoch::javascript_epoch_before_private_name_assignment_declarations();
        assert_prior_parsed_blob_invalidated(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            state.as_ref(),
            &prior_epoch,
        );
    }
    #[brokk_bifrost_test_macros::hardwon(
        "6684f234106d: production JavaScript calls containing `it(` were falsely classified as tests"
    )]
    #[test]
    fn js_structured_test_classification_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "runtime.js",
            "export function emit(value, callback) { callback(value); }\nemit(1, () => {});\n",
        );
        let mut state = parse_state(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            &file,
        );
        assert!(!state.contains_tests);
        // This is the stale value produced by the former `it(` substring
        // matcher for the `emit(...)` production call above.
        state.contains_tests = true;
        let state = Arc::new(state);
        let prior_epoch = epoch::epoch_before_bump(
            epoch::TestEpochLanguage::JavaScript,
            "structured-js-ts-test-classification-2026-08",
        );
        assert_prior_parsed_blob_invalidated(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            state.as_ref(),
            &prior_epoch,
        );
    }
    /// The TypeScript half of the same #2597 bump.
    #[brokk_bifrost_test_macros::hardwon(
        "#2597: persisted TypeScript callables lacked modifier metadata needed for call binding"
    )]
    #[test]
    fn ts_callable_modifier_metadata_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "widget.ts",
            "export class Widget {\n    static build(spec: string): Widget { return new Widget(); }\n    render(target: string): string { return target; }\n}\n",
        );
        let state = Arc::new(parse_state(&TypescriptAdapter, &file));
        let prior_epoch = epoch::epoch_before_bump(
            epoch::TestEpochLanguage::TypeScript,
            "js-ts-callable-modifier-metadata-2026-08",
        );
        assert_prior_parsed_blob_invalidated(&TypescriptAdapter, state.as_ref(), &prior_epoch);
    }
    #[brokk_bifrost_test_macros::hardwon(
        "6684f234106d: production TypeScript calls containing `it(` were falsely classified as tests"
    )]
    #[test]
    fn ts_structured_test_classification_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "runtime.ts",
            "export function init(value: number, callback: (value: number) => void): void { callback(value); }\ninit(1, () => {});\n",
        );
        let mut state = parse_state(&TypescriptAdapter, &file);
        assert!(!state.contains_tests);
        // This is the stale value produced by the former `it(` substring
        // matcher for the `init(...)` production call above.
        state.contains_tests = true;
        let state = Arc::new(state);
        let prior_epoch = epoch::epoch_before_bump(
            epoch::TestEpochLanguage::TypeScript,
            "structured-js-ts-test-classification-2026-08",
        );
        assert_prior_parsed_blob_invalidated(&TypescriptAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn ts_inline_return_type_members_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        // The Authelia shape of #2159: the members `id` and `label` exist as
        // declarations only because the inline return type states them, so a
        // blob written under the prior epoch holds a strictly smaller unit set.
        let file = write_file(
            temp.path(),
            "hooks.ts",
            "export function useShape(): { id?: string; label?: string } {\n    return build();\n}\n",
        );
        let state = Arc::new(parse_state(&TypescriptAdapter, &file));
        let prior_epoch = epoch::epoch_before_bump(
            epoch::TestEpochLanguage::TypeScript,
            "ts-inline-return-type-members-2026-08",
        );
        assert_prior_parsed_blob_invalidated(&TypescriptAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn tsx_ampersand_repair_invalidates_prior_dialect_blobs() {
        assert_ts_tsx_bump_invalidates_prior_dialect_blobs("tsx-literal-ampersands-0.23.5");
    }
    #[brokk_bifrost_test_macros::hardwon(
        "#4479: raw NUL grammar repairs must invalidate cached JS/TSX parser blobs"
    )]
    #[test]
    fn ts_tsx_raw_nul_content_invalidates_prior_dialect_blobs() {
        assert_ts_tsx_bump_invalidates_prior_dialect_blobs("ts-tsx-raw-nul-content-0.23.6-4479");
    }
    #[brokk_bifrost_test_macros::hardwon(
        "#5336: the contextual using parser repair must invalidate persisted TS, TSX, and JSX facts"
    )]
    #[test]
    fn ts_tsx_contextual_using_grammar_invalidates_prior_dialect_blobs() {
        assert_ts_tsx_bump_invalidates_prior_dialect_blobs(
            "ts-tsx-contextual-using-grammar-0.23.7-5336",
        );
    }
    #[brokk_bifrost_test_macros::hardwon(
        "#3864: warm JS/TS blobs must not retain merged wrapper export identities"
    )]
    #[test]
    fn jsts_bundled_export_owners_invalidate_prior_dialect_blobs() {
        assert_ts_tsx_bump_invalidates_prior_dialect_blobs(
            "jsts-commonjs-lexical-export-owners-3864-landing-2026-10-17",
        );
    }
    #[test]
    fn language_epoch_mismatch_deletes_only_that_language() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let java_file = write_file(root, "src/demo/One.java", "package demo;\nclass One {}\n");
        let ts_file = write_file(root, "src/two.ts", "export class Two {}\n");
        let java_oid = oid_for(java_file.read_to_string().unwrap().as_bytes());
        let ts_oid = oid_for(ts_file.read_to_string().unwrap().as_bytes());
        let java = JavaAdapter;
        let ts = TypescriptAdapter;
        let java_state = parse_state(&java, &java_file);
        let ts_state = parse_state(&ts, &ts_file);

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        store
            .ensure_language_epoch_value("typescript", "epoch-a")
            .unwrap();
        store
            .write_parsed_blob(java_oid, "java", &java, &java_state)
            .unwrap();
        store
            .write_parsed_blob(ts_oid, "typescript", &ts, &ts_state)
            .unwrap();

        store
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        assert_eq!(
            store.missing_blobs(&[java_oid], "java").unwrap(),
            vec![java_oid]
        );
        assert_eq!(
            store.missing_blobs(&[ts_oid], "typescript").unwrap(),
            vec![]
        );
        assert_eq!(store.content_row_count(java_oid, "java").unwrap(), 0);
        assert!(store.content_row_count(ts_oid, "typescript").unwrap() > 0);
    }
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn round_trips_java_python_and_typescript_file_states() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let java_file = write_file(
            root,
            "src/demo/Example.java",
            "package demo;\nimport java.util.List;\nclass Example { void run() {} }\n",
        );
        let python_init = write_file(root, "pkg/__init__.py", "");
        let python_file = write_file(
            root,
            "pkg/mod.py",
            "import os\nclass Example:\n    def run(self):\n        return os.getcwd()\n",
        );
        let ts_file = write_file(
            root,
            "src/example.test.ts",
            "import {Thing} from './thing';\nexport class Example { run(): Thing { return new Thing(); } }\n",
        );
        let _ = python_init;

        assert_round_trip(&JavaAdapter, "java", &java_file);
        assert_round_trip(
            &PythonAdapter::for_test_file(&python_file),
            "python",
            &python_file,
        );
        assert_round_trip(&TypescriptAdapter, "typescript", &ts_file);
    }
    /// TS export provenance (issue #1476): the TypeScript dialect's own
    /// visitor records the same export-row vocabulary, including type-space
    /// exports (interfaces, type aliases) and the default re-export.
    #[test]
    fn typescript_export_records_state_their_forms() {
        use brokk_bifrost_core::analyzer::structural::materialization::ExportForm;

        use brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord;

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "exports.ts",
            concat!(
                "export interface Shape { area(): number }\n",
                "export type Alias = Shape;\n",
                "export const answer = 42;\n",
                "export const { high, low: renamed } = bounds;\n",
                "export class Widget {}\n",
                "const table = { greet: 'hi' };\n",
                "export default table;\n",
            ),
        );
        let state = parse_state(&TypescriptAdapter, &file);
        let exports: Vec<_> = state
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::Export {
                    form,
                    exported_name,
                    ..
                } => Some((*form, exported_name.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            exports,
            vec![
                (ExportForm::Named, "Shape".to_string()),
                (ExportForm::Named, "Alias".to_string()),
                (ExportForm::Named, "answer".to_string()),
                (ExportForm::Named, "high".to_string()),
                (ExportForm::Named, "renamed".to_string()),
                (ExportForm::Named, "Widget".to_string()),
                (ExportForm::DefaultNamed, "default".to_string()),
            ],
            "records: {:?}",
            state.materialization_records
        );
    }
    /// JS export provenance (issue #1476): the producer records default,
    /// named, and CommonJS export rows with their forms, and the anonymous
    /// default's synthetic `default` unit is the row's target.
    #[test]
    fn javascript_export_records_state_their_forms() {
        use brokk_bifrost_core::analyzer::structural::materialization::ExportForm;

        use brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord;

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "exports.js",
            concat!(
                "export const answer = 42;\n",
                "export const { alpha, beta: renamed = 1, ...rest } = source;\n",
                "export const [first, second] = pair;\n",
                "export function makeWidget() {}\n",
                "const messages = { greet: 'hi' };\n",
                "export default messages;\n",
            ),
        );
        let state = parse_state(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            &file,
        );
        let exports: Vec<_> = state
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::Export {
                    form,
                    exported_name,
                    target,
                    ..
                } => Some((*form, exported_name.clone(), target.is_some())),
                _ => None,
            })
            .collect();
        assert_eq!(
            exports,
            vec![
                (ExportForm::Named, "answer".to_string(), false),
                (ExportForm::Named, "alpha".to_string(), false),
                (ExportForm::Named, "renamed".to_string(), false),
                (ExportForm::Named, "rest".to_string(), false),
                (ExportForm::Named, "first".to_string(), false),
                (ExportForm::Named, "second".to_string(), false),
                (ExportForm::Named, "makeWidget".to_string(), false),
                (ExportForm::DefaultNamed, "default".to_string(), false),
            ],
            "records: {:?}",
            state.materialization_records
        );

        let commonjs = write_file(
            temp.path(),
            "commonjs.js",
            concat!(
                "const local = () => 1;\n",
                "module.exports = {\n",
                "  inline() { return 2; },\n",
                "  local,\n",
                "};\n",
            ),
        );
        let state = parse_state(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            &commonjs,
        );
        let exports: Vec<_> = state
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::Export {
                    form,
                    exported_name,
                    target,
                    ..
                } => Some((
                    *form,
                    exported_name.clone(),
                    target.as_ref().map(|unit| unit.fq_name().to_string()),
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            exports,
            vec![
                (ExportForm::CommonJsRoot, "module.exports".to_string(), None),
                (
                    ExportForm::CommonJsMember,
                    "inline".to_string(),
                    Some("inline".to_string())
                ),
                (ExportForm::CommonJsMember, "local".to_string(), None),
            ],
            "records: {:?}",
            state.materialization_records
        );

        let anonymous = write_file(
            temp.path(),
            "anonymous.js",
            "export default { greet: 'hi' };\n",
        );
        let state = parse_state(
            &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter,
            &anonymous,
        );
        let default_export = state
            .materialization_records
            .iter()
            .find_map(|record| match record {
                MaterializationRecord::Export {
                    form: ExportForm::DefaultAnonymous,
                    exported_name,
                    target,
                    ..
                } => Some((exported_name.clone(), target.clone())),
                _ => None,
            })
            .expect("anonymous default export row");
        assert_eq!(default_export.0, "default");
        assert_eq!(
            default_export.1.expect("synthetic default unit").fq_name(),
            "default"
        );
    }
}
