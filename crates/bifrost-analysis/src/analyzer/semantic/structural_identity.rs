//! Exact joins from a prepared syntax tree to the normalized structural facts
//! extracted from that same tree.
//!
//! A value mapping that carries its source occurrence's structural identity is
//! what lets a query anchored on an ordinary structural row reach the
//! executable value at that occurrence. The map is built once per prepared
//! source, and each mapping then performs only a tree-node-id lookup.

use tree_sitter::Node;

use crate::analyzer::parser_language_for_dialect;
use crate::analyzer::semantic::{
    ContentIdentity, SemanticProviderError, StableDigest, StructuralNodeIdentity,
};
use crate::analyzer::structural::extract::{
    LimitedFileFacts, extract_file_facts_from_tree_limited,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use brokk_bifrost_core::cancellation::CancellationToken;

#[derive(Debug)]
pub(crate) struct StructuralNodeIndex {
    content: ContentIdentity,
    node_ids: HashMap<usize, u32>,
}

pub(crate) enum StructuralNodeIndexOutcome {
    Complete {
        index: StructuralNodeIndex,
        work_items: usize,
    },
    Exceeded {
        minimum_work_items: usize,
    },
    Cancelled,
}

impl StructuralNodeIndex {
    pub(crate) fn for_source(
        spec: &dyn StructuralSpec,
        prepared: &PreparedSyntaxTree,
        max_work_items: usize,
        cancellation: &CancellationToken,
    ) -> Result<StructuralNodeIndexOutcome, SemanticProviderError> {
        let grammar = parser_language_for_dialect(prepared.dialect()).ok_or_else(|| {
            SemanticProviderError::internal("semantic lowering has no structural parser language")
        })?;
        let extracted = extract_file_facts_from_tree_limited(
            spec,
            &grammar,
            prepared.tree(),
            prepared.source(),
            max_work_items,
            Some(cancellation),
        );
        let (facts, node_ids) = match extracted {
            LimitedFileFacts::CompleteWithNodeIndex { facts, node_ids } => (facts, node_ids),
            LimitedFileFacts::Exceeded { minimum_fact_nodes } => {
                return Ok(StructuralNodeIndexOutcome::Exceeded {
                    minimum_work_items: minimum_fact_nodes,
                });
            }
            LimitedFileFacts::Cancelled => return Ok(StructuralNodeIndexOutcome::Cancelled),
            LimitedFileFacts::Unavailable => {
                return Err(SemanticProviderError::internal(
                    "structural identity extraction is unavailable",
                ));
            }
            LimitedFileFacts::Complete(_) => {
                return Err(SemanticProviderError::internal(
                    "prepared-tree structural extraction omitted its node index",
                ));
            }
        };
        let work_items = facts.work_item_count();
        let content = facts.source_identity();
        assert_eq!(
            content,
            ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256())),
            "structural facts must be extracted from the semantic artifact source"
        );
        Ok(StructuralNodeIndexOutcome::Complete {
            index: Self { content, node_ids },
            work_items,
        })
    }

    pub(crate) fn identity(&self, node: Node<'_>) -> Option<StructuralNodeIdentity> {
        self.node_ids
            .get(&node.id())
            .copied()
            .map(|node_id| StructuralNodeIdentity::new(self.content, node_id))
    }
}
