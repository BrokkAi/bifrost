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

pub use analyzer::csharp::dependency_evidence;
pub use analyzer::csharp::external::{
    CSharpAssemblyPackProducer, CSharpDependencyPackAdapter, CSharpExternalDeclarationIndex,
    CSharpExternalDeclarationSource, CSharpExternalMember, CSharpExternalMemberKind,
    CSharpExternalType, CSharpExternalTypeKind, CSharpVisibility,
    resolve_csharp_semantic_pack_dependencies,
};
pub use analyzer::csharp::{
    CSharpAdapter, CSharpAnalyzer, CSharpAttributeTypeResolution, CSharpAttributeTypeStatus,
    CSharpCatchFacts, CSharpCatchTypeRelation, CSharpSupport, csharp_catch_facts,
    resolve_csharp_attribute_type,
};
pub use analyzer::usages::csharp_graph::CSharpUsageGraphStrategy;
#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::languages::LanguageTable {
    use brokk_bifrost_analysis::analyzer::languages::{LanguageSupport, LanguageTable};
    use std::sync::OnceLock;

    static TABLE: OnceLock<LanguageTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        LanguageTable::partial_for_tests(vec![&CSharpSupport as &dyn LanguageSupport])
    })
}

#[cfg(test)]
pub use brokk_bifrost_analysis::inline_project;

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_store_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::store::StoreLanguageTable {
    static TABLE: std::sync::OnceLock<brokk_bifrost_analysis::analyzer::store::StoreLanguageTable> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| __brokk_bifrost_language_supports_v1().store_supports())
}

#[cfg(test)]
mod icfg_domain_tests {
    use brokk_bifrost_analysis::analyzer::semantic::icfg::{
        IcfgProvider, IcfgProviderBehaviorIdentity, WorkspaceIcfgProvider,
    };
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#8837: a present empty nearer C# configuration file reused an older full ICFG answer"
    )]
    fn present_empty_csharp_configuration_rotates_retained_full_provider_identity() {
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::CSharp,
            &[
                (
                    "Directory.Build.props",
                    "<Project><PropertyGroup><Root>yes</Root></PropertyGroup></Project>",
                ),
                ("Directory.Build.targets", "<Project />"),
                ("Directory.Packages.props", "<Project />"),
                ("App/Directory.Build.props", ""),
                ("App/Directory.Build.targets", "<Project />"),
                ("App/Directory.Packages.props", "<Project />"),
                ("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
                ("App/Class.cs", "class Class { }"),
            ],
        );
        let provider = WorkspaceIcfgProvider::new(fixture.analyzer());
        let old = IcfgProviderBehaviorIdentity::for_test_workspace_with_domains(
            &provider,
            (
                b"bifrost-icfg-provider/workspace-behavior/v686",
                b"bifrost-icfg-provider/workspace-read-behavior/v685",
            ),
        );
        let current = provider.behavior_identity();
        assert_ne!(
            old.digest(),
            current.digest(),
            "a retained full-provider answer must miss after the domain rotation"
        );
    }
}
