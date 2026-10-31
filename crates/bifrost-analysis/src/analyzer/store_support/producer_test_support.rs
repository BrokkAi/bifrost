use crate::CancellationToken;
use crate::analyzer::store::file_state::FileState;
use crate::analyzer::store::resolution_producer_tests::producer_test_support::*;
use crate::analyzer::store::*;
use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::hash::HashMap;
use git2::Oid;
use std::sync::Arc;
#[doc(hidden)]
pub fn prepare_with_adapter<A: LanguageAdapter>(
    oid: Oid,
    state: Arc<FileState>,
    generations: &HashMap<String, GenerationId>,
    required_projections: &[String],
    adapter: &A,
) -> PreparedParsedBlob {
    let file = crate::analyzer::store::test_blob_file();
    let syntax = crate::analyzer::tree_sitter_analyzer::reparse_retained_source(
        adapter, &file, &state, None,
    );
    let syntax = match syntax {
        crate::analyzer::store::file_state::PreparedSyntaxPreparation::Complete(Some(tree)) => tree,
        _ => panic!("test source must parse within its budget"),
    };
    match AnalyzerStore::prepare_parsed_blob_at_generations(
        &file,
        &syntax,
        &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, PRIMARY),
        generations,
        adapter,
        state,
        required_projections,
        &CancellationToken::default(),
    )
    .expect("prepare combined parsed and resolution bundle")
    {
        PreparedParsedBlobPreparation::Prepared(prepared) => *prepared,
        PreparedParsedBlobPreparation::Cancelled => panic!("uncancelled preparation cancelled"),
    }
}
