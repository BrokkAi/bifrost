#[cfg(test)]
pub(crate) mod fixture {

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use git2::Oid;

    use brokk_bifrost_analysis::analyzer::store::PreparedParsedBlob;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::producer_test_support::prepare_with_adapter;
    #[doc(hidden)]
    pub fn prepare(
        oid: Oid,
        state: Arc<FileState>,
        generations: &HashMap<String, GenerationId>,
        required_projections: &[String],
    ) -> PreparedParsedBlob {
        prepare_with_adapter(oid, state, generations, required_projections, &JavaAdapter)
    }
}
