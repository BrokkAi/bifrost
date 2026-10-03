//! Capsule reference source authority, bounded by one typed request batch.

use super::super::Result;
use super::super::resolution_prepare::rust_authority;
use super::super::resolution_selection::SelectedResolutionMountInventory;
use super::typed::{row_semantic, semantic_request_json, visit_stage_rows};
use crate::CancellationToken;
use crate::analyzer::resolution::*;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};

// Runtime correspondence determines producers. The context's actual host,
// rather than an ordinal encoded in a semantic key, determines selected scope.
pub(in crate::analyzer::store) const REFERENCES_SQL: &str = r#"
SELECT context.host_ordinal,context.semantic_key,context.semantic_shared,
       context.source_site,context.host_occurrence,context.module_context,
       context.module_declaration,json(context.cfg)
FROM json_each(?1) request
CROSS JOIN temp.selected_resolution_stage_semantic_coordinates coordinate
 ON coordinate.runtime_key IS request.value->>0
 AND coordinate.shared_id IS request.value->>1
CROSS JOIN temp.selected_resolution_stage_reference_contexts context
 ON context.producer_id=coordinate.producer_id
 AND COALESCE(context.semantic_key,-1)=COALESCE(request.value->>0,-1)
 AND COALESCE(context.semantic_shared,-1)=COALESCE(request.value->>1,-1)
JOIN temp.selected_resolution_scope_mounts scope
 ON scope.mount_ordinal=context.host_ordinal
WHERE context.host_ordinal=coordinate.host_ordinal
"#;

pub(in crate::analyzer::store) fn visit_rust_reference_context_pages(
    selection: &SelectedResolutionMountInventory<'_>,
    references: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredRustReferenceContext>>,
) -> Result<TypedFactReadOutcome> {
    let request = semantic_request_json(references);
    visit_stage_rows(
        selection,
        REFERENCES_SQL,
        &[&request],
        cancellation,
        visitor,
        |row| {
            Ok(LoweredRustReferenceContext::new(
                row_semantic(row, "semantic")?,
                ResolutionSiteId::new(row.get(3)?),
                SourceOccurrenceId::new(row.get(4)?),
                SourceOccurrenceId::new(row.get(5)?),
                row.get::<_, Option<u32>>(6)?.map(SourceDeclarationId::new),
            )
            .with_cfg_condition(rust_authority::decode_cfg(&row.get::<_, String>(7)?)))
        },
        |_, _| {},
    )
}

#[cfg(test)]
#[path = "rust_context_tests.rs"]
mod tests;
