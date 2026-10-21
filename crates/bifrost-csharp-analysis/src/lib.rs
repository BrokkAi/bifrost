pub mod analyzer {
    pub mod csharp;
    pub use csharp::external::{
        CSharpAssemblyPackProducer, CSharpDependencyPackAdapter, CSharpExternalDeclarationIndex,
        CSharpExternalDeclarationSource, CSharpExternalMember, CSharpExternalMemberKind,
        CSharpExternalType, CSharpExternalTypeKind, CSharpVisibility,
        resolve_csharp_semantic_pack_dependencies,
    };
    pub use csharp::{
        CSharpAnalyzer, CSharpCatchFacts, CSharpCatchTypeRelation, csharp_catch_facts,
    };

    pub mod usages {
        pub mod csharp_graph;
        pub mod get_definition {
            pub mod csharp;
        }
        pub mod get_type {
            pub(crate) use csharp::resolve_csharp_type_bounded;
            pub mod csharp;
        }
    }
}

pub use analyzer::csharp::external::{
    CSharpAssemblyPackProducer, CSharpDependencyPackAdapter, CSharpExternalDeclarationIndex,
    CSharpExternalDeclarationSource, CSharpExternalMember, CSharpExternalMemberKind,
    CSharpExternalType, CSharpExternalTypeKind, CSharpVisibility,
    resolve_csharp_semantic_pack_dependencies,
};
pub use analyzer::csharp::{
    CSharpAdapter, CSharpAnalyzer, CSharpCatchFacts, CSharpCatchTypeRelation, CSharpSupport,
    csharp_catch_facts,
};
pub use analyzer::usages::csharp_graph::CSharpUsageGraphStrategy;
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
                .chain([&CSharpSupport as &dyn LanguageSupport])
                .collect(),
        )
    })
}

#[cfg(test)]
pub use brokk_bifrost_analysis::inline_project;
