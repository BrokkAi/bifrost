//! Source data handed to shared call consumers by LanguageSupport.
use crate::analyzer::i_analyzer::QueryReadReceipt;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::structural::spec::{EmbeddedSyntaxForest, EmbeddedSyntaxStop};
use brokk_bifrost_core::domain_memo::ReplayEntry;
use brokk_bifrost_core::retention_budget::RetainedBytes;
use brokk_bifrost_rust::macro_matcher::MacroDefinitionInventory;
use std::sync::Arc;

/// The only operational failure of source preparation. Embedded fixed limits
/// remain auxiliary forest data, not a failed primary source preparation.
#[derive(Debug, Clone, Copy)]
pub struct SourceCancelled;

impl From<SourceCancelled> for EmbeddedSyntaxStop {
    fn from(_: SourceCancelled) -> Self {
        Self::Cancelled
    }
}

/// Consumers keep this budgeted backing alive while borrowing its trees or
/// cloning its inventory Arcs, even if the request region evicts the entry.
pub struct PreparedMacroSource {
    pub prepared: Arc<PreparedSyntaxTree>,
    pub source: Arc<str>,
    pub embedded: Result<Arc<EmbeddedSyntaxForest>, EmbeddedSyntaxStop>,
    pub(super) inventories: std::collections::HashMap<usize, Arc<MacroDefinitionInventory>>,
    pub(super) receipt: Option<QueryReadReceipt>,
}
impl ReplayEntry for PreparedMacroSource {}
impl RetainedBytes for PreparedMacroSource {
    fn retained_bytes(&self) -> usize {
        use crate::analyzer::tree_sitter_analyzer::ByteBounded;
        let embedded = self.embedded.as_ref().map_or(0, |forest| {
            forest.retained_structure_bytes()
                + forest
                    .trees()
                    .iter()
                    .map(|fragment| {
                        crate::analyzer::tree_sitter_analyzer::prepared_syntax_retained_bytes(
                            fragment
                                .range
                                .end_byte
                                .saturating_sub(fragment.range.start_byte),
                        )
                    })
                    .sum::<usize>()
        });
        std::mem::size_of::<Self>()
            + self.prepared.estimated_bytes()
            + std::mem::size_of::<tree_sitter::Tree>()
            + 2 * std::mem::size_of::<usize>()
            + match self.prepared.backing() {
                brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource::Exact(_) => 0,
                brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource::Indexed(_) => {
                    self.source.len() + 2 * std::mem::size_of::<usize>()
                }
            }
            + embedded
            + self
                .receipt
                .as_ref()
                .map_or(0, QueryReadReceipt::retained_bytes)
            + self.inventories.capacity()
                * (std::mem::size_of::<(usize, Arc<MacroDefinitionInventory>)>() + 1)
            + self
                .inventories
                .values()
                .map(|inventory| {
                    inventory.retained_structure_bytes() + 2 * std::mem::size_of::<usize>()
                })
                .sum::<usize>()
    }
}
impl PreparedMacroSource {
    pub fn macro_inventory(&self, tree: &tree_sitter::Tree) -> &Arc<MacroDefinitionInventory> {
        self.inventories
            .get(&tree.root_node().id())
            .expect("tree belongs to the prepared Rust source")
    }
}
