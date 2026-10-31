//! Selected-resolution fixture constructors that need JVM adapters.

use brokk_bifrost_analysis::analyzer::Language;
use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::{
    SelectionFixture, parsed_fixture_state,
};
use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, GenerationId};
use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;
use git2::Oid;

#[doc(hidden)]
pub fn write_fixture_blob(
    store: &AnalyzerStore,
    oid: &str,
    storage_language: &str,
    semantic_language: Language,
    generation: GenerationId,
) {
    let (relative_path, source) = match semantic_language {
        Language::Java => ("src/Model.java", "package demo; class Model {}\n"),

        Language::Go => ("src/model.go", "package demo\ntype Model struct {}\n"),
        Language::Rust => ("src/model.rs", "struct Model;\n"),
        _ => panic!("selection fixture adapter is not defined for {semantic_language:?}"),
    };
    let result = match semantic_language {
        Language::Java => {
            let state = parsed_fixture_state(&JavaAdapter, relative_path, source);
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
        Language::Go => {
            let state = parsed_fixture_state(&GoAdapter, relative_path, source);
            store.write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    Oid::from_str(oid).unwrap(),
                    storage_language,
                ),
                generation,
                &GoAdapter,
                &state,
            )
        }
        Language::Rust => {
            let state = parsed_fixture_state(&RustAdapter, relative_path, source);
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
        _ => unreachable!(),
    };
    result.expect("persist selected-resolution fixture blob");
}
#[doc(hidden)]
pub struct JvmSelectionFixture;
impl JvmSelectionFixture {
    // This factory constructs the engine-owned fixture, as the Rust factory does.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(mount_count: usize) -> SelectionFixture {
        Self::with_language(mount_count, "java", Language::Java, false)
    }

    pub fn shared_blob(mount_count: usize) -> SelectionFixture {
        Self::with_language(mount_count, "java", Language::Java, true)
    }

    pub fn custom_source(mount_count: usize, source: &str) -> SelectionFixture {
        Self::custom_language_source(mount_count, source, "java", Language::Java)
    }

    pub fn custom_rust_source(mount_count: usize, source: &str) -> SelectionFixture {
        Self::custom_language_source(mount_count, source, "rust", Language::Rust)
    }

    pub fn shared_rust_source(mount_count: usize, source: &str) -> SelectionFixture {
        Self::with_store(
            AnalyzerStore::open_ephemeral().unwrap(),
            mount_count,
            "rust",
            Language::Rust,
            true,
            false,
            Some(source),
        )
    }

    pub fn custom_language_source(
        mount_count: usize,
        source: &str,
        storage_language: &str,
        semantic_language: Language,
    ) -> SelectionFixture {
        Self::with_store(
            AnalyzerStore::open_ephemeral().unwrap(),
            mount_count,
            storage_language,
            semantic_language,
            false,
            false,
            Some(source),
        )
    }

    pub fn bootstrap(mount_count: usize) -> SelectionFixture {
        Self::with_authority(mount_count, "java", Language::Java, false, true)
    }

    pub fn with_language(
        mount_count: usize,
        storage_language: &str,
        semantic_language: Language,
        shared_blob: bool,
    ) -> SelectionFixture {
        Self::with_authority(
            mount_count,
            storage_language,
            semantic_language,
            shared_blob,
            false,
        )
    }

    pub fn with_authority(
        mount_count: usize,
        storage_language: &str,
        semantic_language: Language,
        shared_blob: bool,
        bootstrap: bool,
    ) -> SelectionFixture {
        Self::with_store(
            AnalyzerStore::open_ephemeral().unwrap(),
            mount_count,
            storage_language,
            semantic_language,
            shared_blob,
            bootstrap,
            None,
        )
    }

    pub fn persistent(mount_count: usize) -> (tempfile::TempDir, SelectionFixture) {
        let temp = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        let fixture = Self::with_store(
            store,
            mount_count,
            "java",
            Language::Java,
            false,
            false,
            None,
        );
        (temp, fixture)
    }

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
                            let state =
                                parsed_fixture_state(&JavaAdapter, "src/Model.java", source);
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
                    write_fixture_blob(store, oid, storage_language, semantic_language, generation);
                }
            },
        )
    }
}
