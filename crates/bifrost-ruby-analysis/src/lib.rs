pub mod analyzer {
    pub mod ruby;
    pub use ruby::{
        RubyAnalyzer, RubyDependencyPackAdapter, resolve_ruby_semantic_pack_dependencies,
    };
    pub mod usages {
        pub mod get_definition {
            pub mod ruby;
        }
        pub mod get_type {
            pub(crate) use ruby::resolve_ruby_type_bounded;
            pub mod ruby;
        }
        pub mod ruby_graph;
    }
}

pub use analyzer::ruby::{
    RubyAnalyzer, RubyDependencyPackAdapter, RubyGemArchivePackProducer, RubySupport,
    resolve_ruby_semantic_pack_dependencies,
};
pub use analyzer::usages::ruby_graph::RubyUsageGraphStrategy;

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
                .chain([&RubySupport as &dyn LanguageSupport])
                .collect(),
        )
    })
}

#[cfg(test)]
pub use brokk_bifrost_analysis::inline_project;

pub use analyzer::ruby::{RubyCallResultUseIndex, ruby_declared_scalar_types};
