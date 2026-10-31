use crate::selection_fixture_support::write_fixture_blob;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::{
    SelectionFixture, parsed_fixture_state,
};
use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, GenerationId};
use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;
use git2::Oid;
pub fn with_store(
    store: AnalyzerStore,
    mount_count: usize,
    storage_language: &str,
    semantic_language: Language,
    shared_blob: bool,
    bootstrap: bool,
    source: Option<&str>,
) -> SelectionFixture {
    SelectionFixture::with_blob_writer(
        store,
        mount_count,
        storage_language,
        semantic_language,
        shared_blob,
        bootstrap,
        |store, oid, storage_language, semantic_language, generation| {
            if let Some(source) = source {
                let result = match semantic_language {
                    Language::Java => {
                        let state = parsed_fixture_state(&JavaAdapter, "src/Model.java", source);
                        store.write_parsed_blob_at_generation(
                            &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                            &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                                Oid::from_str(oid).unwrap(),
                                storage_language,
                            ),
                            generation,
                            &JavaAdapter,
                            &state,
                        )
                    }
                    Language::Rust => {
                        let state = parsed_fixture_state(&RustAdapter, "src/Model.rs", source);
                        store.write_parsed_blob_at_generation(
                            &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                            &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                                Oid::from_str(oid).unwrap(),
                                storage_language,
                            ),
                            generation,
                            &RustAdapter,
                            &state,
                        )
                    }
                    _ => panic!(
                        "custom selection fixture adapter is not defined for {semantic_language:?}"
                    ),
                };
                result.expect("persist custom selected-resolution fixture blob");
            } else {
                if semantic_language == Language::Rust {
                    write_rust_fixture_blob(store, oid, storage_language, generation);
                } else {
                    write_fixture_blob(store, oid, storage_language, semantic_language, generation);
                }
            }
        },
    )
}

pub trait RustSelectionFixtureExt {
    fn custom_rust_source(mount_count: usize, source: &str) -> Self;
    fn shared_rust_source(mount_count: usize, source: &str) -> Self;
}
impl RustSelectionFixtureExt for SelectionFixture {
    fn custom_rust_source(mount_count: usize, source: &str) -> Self {
        with_store(
            AnalyzerStore::open_ephemeral().unwrap(),
            mount_count,
            "rust",
            Language::Rust,
            false,
            false,
            Some(source),
        )
    }
    fn shared_rust_source(mount_count: usize, source: &str) -> Self {
        with_store(
            AnalyzerStore::open_ephemeral().unwrap(),
            mount_count,
            "rust",
            Language::Rust,
            true,
            false,
            Some(source),
        )
    }
}

// Tools supplies the Rust adapter for selected-resolution fixtures.
pub struct RustSelectionFixture;
impl RustSelectionFixture {
    // Preserve existing fixture call sites while supplying Rust's blob writer.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(mount_count: usize) -> SelectionFixture {
        crate::selection_fixture_support::JvmSelectionFixture::new(mount_count)
    }
}

pub(super) fn write_rust_fixture_blob(
    store: &AnalyzerStore,
    oid: &str,
    storage_language: &str,
    generation: GenerationId,
) {
    let state = parsed_fixture_state(&RustAdapter, "src/model.rs", "struct Model;\n");
    store
        .write_parsed_blob_at_generation(
            &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                Oid::from_str(oid).unwrap(),
                storage_language,
            ),
            generation,
            &RustAdapter,
            &state,
        )
        .expect("persist selected-resolution fixture blob");
}
