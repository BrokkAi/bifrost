pub mod analyzer {
    pub mod php;
    pub use php::{
        PhpAnalyzer, PhpCallResultUseIndex, PhpDependencyPackAdapter, php_declared_scalar_types,
        resolve_php_semantic_pack_dependencies,
    };
    pub mod usages {
        pub mod get_definition {
            pub mod php;
        }
        pub mod get_type {
            pub mod php;
            pub(crate) use php::resolve_php_type_bounded;
        }
        pub mod php_graph;
    }
}
pub use analyzer::php::{
    PhpAnalyzer, PhpDependencyPackAdapter, PhpSupport, resolve_php_semantic_pack_dependencies,
};
pub use analyzer::usages::php_graph::PhpUsageGraphStrategy;
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
                .chain([&PhpSupport as &dyn LanguageSupport])
                .collect(),
        )
    })
}

#[cfg(test)]
pub use brokk_bifrost_analysis::inline_project;
