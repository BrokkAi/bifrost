//! The one call in Python's lexical-scope inventory that cannot leave the
//! analysis crate.
//!
//! [`PythonLexicalScopeInventory`] itself moved to `brokk-bifrost-python`, but
//! it seeds its parameter set from
//! [`formal_parameter_slots_for_owner_bounded`], which dispatches through
//! `analyzer/languages.rs`'s registry and so stays here. This forwarder resolves
//! the layout under the caller's own `scope_step` meter and hands the names
//! across, preserving the original ordering: the layout is metered first, and a
//! stopped session yields `None` before the body walk begins. `node_range`
//! below reproduces the moved module's private helper byte for byte, including
//! its zero-based lines -- the layout lookup compares byte offsets only, so
//! changing the line base here would be a silent behavior change.

use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_bounded;
use crate::analyzer::{Language, Range};
use brokk_bifrost_python::bindings::PythonLexicalScopeInventory;
use tree_sitter::Node;

pub(crate) fn python_lexical_scope_inventory_bounded<'tree>(
    callable: Node<'tree>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonLexicalScopeInventory<'tree>> {
    let layout = formal_parameter_slots_for_owner_bounded(
        Language::Python,
        callable,
        source,
        &node_range(callable),
        &mut scope_step,
    )?;
    let parameter_names = layout.slots.into_iter().flat_map(|slot| slot.names);
    PythonLexicalScopeInventory::collect_bounded(callable, source, parameter_names, scope_step)
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}
