pub mod analyzer {
    pub use brokk_bifrost_analysis::analyzer::*;
    pub(crate) use rust::crate_identity::RustOverlayCrates;
    pub use rust::rust_is_field_declaration_name;
    #[cfg(any(test, feature = "test-support"))]
    pub use rust::selected_reverse::{
        RustSelectedReverseOutcome, RustSelectedReverseQueries, with_rust_selected_reverse_queries,
    };
    pub use rust::{
        RustAnalyzer, RustDependencyPackAdapter, RustReferenceContext, RustReferenceNamespace,
        RustdocJsonPackProducer, acquire_rust_file_dependency_evidence,
        failure_handlers::rust_failure_handler_body_shapes,
        resolve_rust_semantic_pack_dependencies, rust_declaration_is_enum_variant,
        rust_declaration_matches_reference_namespace, rust_file_dependency_evidence,
        rust_reference_namespace,
    };
    pub use rust::{RustCallResultUseIndex, rust_call_result_use};
    pub use rust::{
        RustNativeObligationProof, rust_call_is_standard_drop, rust_native_result_obligation,
    };
    #[cfg(any(test, feature = "test-support"))]
    pub use rust::{
        reset_rust_tree_parse_counters_for_test, rust_scope_index_build_count_for_test,
        rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
        rust_tree_parsed_bytes_for_test,
    };

    pub mod rust;
    pub mod semantic {
        pub use brokk_bifrost_analysis::analyzer::semantic::*;
        pub mod workspace_oracle {
            pub use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::*;
            pub mod rust;
        }
    }
    pub mod usages {
        pub use brokk_bifrost_analysis::analyzer::usages::*;
        pub mod get_definition {
            pub use brokk_bifrost_analysis::analyzer::usages::get_definition::*;
            pub mod rust;
        }
    }
}

pub use analyzer::rust::*;
pub use analyzer::semantic::workspace_oracle::rust::*;
pub use brokk_bifrost_analysis::{CancellationToken, cancellation, hash, path_utils, profiling};

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::languages::LanguageTable {
    use brokk_bifrost_analysis::analyzer::languages::{LanguageSupport, LanguageTable};
    use brokk_bifrost_analysis::language_registry::engine_resident_language_supports;
    use std::sync::OnceLock;

    static TABLE: OnceLock<LanguageTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        LanguageTable::partial_for_tests(
            engine_resident_language_supports()
                .iter()
                .copied()
                .chain([&RustSupport as &dyn LanguageSupport])
                .collect(),
        )
    })
}

#[cfg(test)]
pub use brokk_bifrost_analysis::inline_project;

pub use brokk_bifrost_analysis::analyzer::{
    RustAnalyzerConfig, RustDependencyApiEvidence, RustPackageApiArtifact, RustSelectedTarget,
};

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(test)]
#[global_allocator]
static HEAP_PIN_ALLOCATOR:
    brokk_bifrost_analysis::analyzer::store::resolution_operation::heap_pin::HeapPinAllocator =
    brokk_bifrost_analysis::analyzer::store::resolution_operation::heap_pin::HeapPinAllocator;
