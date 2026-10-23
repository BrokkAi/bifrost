pub mod analyzer {
    pub mod cpp;
    pub use cpp::CppAnalyzer;
    pub use cpp::expression_branch_facts::{
        CAssignmentCandidate, CAssignmentCandidates, CAssignmentSyntaxVerdict,
        c_assignment_candidates, cpp_overwritten_local_candidates,
    };
    pub use cpp::initializer_facts::{
        CppInitializerAccessKind, CppInitializerCandidate, CppInitializerCandidates,
        CppInitializerSyntaxVerdict, cpp_initializer_candidates,
    };
    pub use cpp::provenance_facts::{
        CppProvenanceOutcome, cpp_provenance_for_anchor, cpp_provenance_for_anchor_with_model_key,
    };
    pub use cpp::range_facts;
    pub use cpp::{CppCallResultUseIndex, cpp_call_result_use};
    pub use cpp::{CppNativeObligationProof, cpp_native_result_obligation};
    pub use cpp::{
        cpp_is_constructor_or_destructor_declarator_name, cpp_is_conversion_operator_target_type,
        cpp_is_recovered_macro_character_token_type,
    };
    pub mod usages {
        pub mod cpp_graph;
        pub mod get_definition {
            pub mod cpp;
        }
        pub mod get_type {
            pub mod cpp;
            pub(crate) use cpp::resolve_cpp_type_bounded;
        }
    }
}
pub use analyzer::cpp::{CppAnalyzer, CppSupport};
pub use analyzer::usages::cpp_graph::CppUsageGraphStrategy;
pub use brokk_bifrost_analysis::CancellationToken;
#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::languages::LanguageTable {
    use brokk_bifrost_analysis::analyzer::languages::{LanguageSupport, LanguageTable};
    use std::sync::OnceLock;

    static TABLE: OnceLock<LanguageTable> = OnceLock::new();
    TABLE
        .get_or_init(|| LanguageTable::partial_for_tests(vec![&CppSupport as &dyn LanguageSupport]))
}

#[cfg(test)]
pub use brokk_bifrost_analysis::{TestProject, inline_project};

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_store_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::store::StoreLanguageTable {
    static TABLE: std::sync::OnceLock<brokk_bifrost_analysis::analyzer::store::StoreLanguageTable> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| __brokk_bifrost_language_supports_v1().store_supports())
}
