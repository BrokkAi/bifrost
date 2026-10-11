//! Selected cfg activation for one Rust source site.

use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;
use brokk_bifrost_rust::selected_context::RustSelectedActivation;
use std::ops::Range;
use tree_sitter::Tree;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RustSiteActivation {
    NoNode,
    Active,
    Inactive,
    Unknown {
        conditional_site_cfg: Option<RustCfgCondition>,
    },
}

/// Apply the selected crate's cfg to the effective condition enclosing one
/// syntax range. `None` is a cooperative stop from the selected operation.
pub(crate) fn rust_site_activation(
    tree: Option<&Tree>,
    source: &str,
    range: Range<usize>,
    evaluate: impl FnOnce(
        &RustCfgCondition,
    ) -> crate::analyzer::store::Result<Option<(RustSelectedActivation, bool)>>,
) -> crate::analyzer::store::Result<Option<RustSiteActivation>> {
    let Some(node) = tree.and_then(|tree| {
        tree.root_node()
            .descendant_for_byte_range(range.start, range.end)
    }) else {
        return Ok(Some(RustSiteActivation::NoNode));
    };
    let condition = brokk_bifrost_rust::lexical_scope::rust_effective_cfg_condition(node, source);
    if condition == RustCfgCondition::Always {
        return Ok(Some(RustSiteActivation::Active));
    }
    let Some((activation, conditional)) = evaluate(&condition)? else {
        return Ok(None);
    };
    Ok(Some(match activation {
        RustSelectedActivation::Active if conditional => RustSiteActivation::Unknown {
            conditional_site_cfg: Some(condition),
        },
        RustSelectedActivation::Active => RustSiteActivation::Active,
        RustSelectedActivation::Inactive => RustSiteActivation::Inactive,
        RustSelectedActivation::Unknown => RustSiteActivation::Unknown {
            conditional_site_cfg: None,
        },
    }))
}
