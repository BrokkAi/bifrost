#[cfg(test)]
mod js_ts_extraction_root {

    use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;

    use brokk_bifrost_analysis::analyzer::store::resolution::resolution_bundle_epoch;

    use brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAdapter;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::persist_alias_fixture;

    #[test]
    fn production_writer_persists_storage_alias_metadata_digest_and_idempotence() {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let typescript = persist_alias_fixture(
            &store,
            oid(b"typescript tsx storage alias"),
            "typescript:tsx",
            &TypescriptAdapter,
            "src/Model.tsx",
            "export class Model { value = 1; }\n",
        );
        let cpp = persist_alias_fixture(
            &store,
            oid(b"cpp c storage alias"),
            "cpp:c",
            &CppAdapter,
            "src/model.c",
            "struct Model { int value; };\n",
        );
        assert_eq!(typescript.semantic_language, "typescript");
        assert_eq!(cpp.semantic_language, "cpp");
        assert_eq!(
            typescript.producer_epoch,
            resolution_bundle_epoch(Language::TypeScript)
        );
        assert_eq!(cpp.producer_epoch, resolution_bundle_epoch(Language::Cpp));
        assert_ne!(typescript.interior_digest, cpp.interior_digest);
    }
}
