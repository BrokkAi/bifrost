//! SQLite-backed analyzer store and resolution support for Bifrost.

pub use brokk_bifrost_core::*;
pub mod analyzer {
    pub use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
    pub use brokk_bifrost_core::analyzer::*;
    pub use brokk_bifrost_core::analyzer::{
        capabilities::*, config::*, fq_name::*, model::*, parsed_file::*, project::*,
        query_token::*,
    };
    pub use brokk_bifrost_semantic::analyzer::semantic;
    pub use semantic::{content_identity, digest, invalidation, topology};
    pub mod semantic_model {
        pub use crate::analyzer::store::{active_models::*, model_catalog::*};
        pub use brokk_bifrost_semantic::analyzer::semantic_model::*;
        pub mod runtime {
            pub use crate::analyzer::store::active_models::*;
            pub use brokk_bifrost_semantic::analyzer::semantic_model::runtime::*;
        }
    }
    pub mod structural {
        pub use brokk_bifrost_core::analyzer::structural::resolution::*;
        pub use brokk_bifrost_core::analyzer::structural::*;
    }
    pub mod read_ledger;
    // Preserve the resolution module lint policy from its engine declaration.
    #[allow(dead_code, unused_imports)]
    pub mod resolution;
    pub mod store;
}
