#![allow(hidden_glob_reexports)]
pub use brokk_bifrost_store::analyzer::store::*;
pub mod resolution_operation {
    #[cfg(any(test, feature = "test-support"))]
    pub use crate::analyzer::store_support::resolution_operation_tests_go_support;
    #[cfg(any(test, feature = "test-support"))]
    pub mod tests {
        pub use crate::analyzer::store_support::java_query_tests;
        pub use crate::analyzer::store_support::rust_root_test_support;
        pub use brokk_bifrost_store::analyzer::store::resolution_operation::tests::*;
    }
    #[cfg(any(test, feature = "test-support"))]
    pub mod reverse {
        pub use crate::analyzer::store_support::reverse::*;
        pub use brokk_bifrost_store::analyzer::store::resolution_operation::reverse::*;
    }
    pub use crate::analyzer::store_bridge::go_graph::{
        GoGraphStageExt, GoReferenceBatchProjection,
    };
    // The Rust graph stage follows the same language-owned source boundary.
    pub use crate::analyzer::store_bridge::rust_graph;
    pub use brokk_bifrost_store::analyzer::store::resolution_operation::*;
}
pub mod epoch {
    pub use crate::analyzer::store_bridge::epoch::epoch_for;
    pub use brokk_bifrost_store::analyzer::store::epoch::*;
}

#[doc(hidden)]
pub use crate::analyzer::store_bridge::{
    AnalyzerStoreEngineExt, prepare_parsed_blob_at_generations,
};

#[cfg(any(test, feature = "test-support"))]
pub mod python_unit_summaries {
    pub use crate::analyzer::store_bridge::PythonEnvironmentPublicationEngineExt;
    pub use brokk_bifrost_store::analyzer::store::python_unit_summaries::*;
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    pub use crate::analyzer::store_support::test_support::*;
    pub use brokk_bifrost_store::analyzer::store::test_support::*;
}
#[cfg(any(test, feature = "test-support"))]
pub use crate::analyzer::store_support::js_ts_resolution_producer_support;
#[cfg(any(test, feature = "test-support"))]
pub mod resolution_selection {
    pub use crate::analyzer::store_support::selection_test_support;
    pub use brokk_bifrost_store::analyzer::store::resolution_selection::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod resolution_producer_tests {
    pub use brokk_bifrost_store::analyzer::store::resolution_producer_tests::*;
    pub mod producer_test_support {
        pub use brokk_bifrost_store::analyzer::store::resolution_producer_tests::producer_test_support::*;
        pub use crate::analyzer::store_support::producer_test_support::*;
    }
}
