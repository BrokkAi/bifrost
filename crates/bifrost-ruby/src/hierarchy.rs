//! Ruby's type-hierarchy resolution.
//!
//! `TypeHierarchyProvider` is a core trait but its impl stays on `RubyAnalyzer`,
//! which owns the `direct_ancestors` moka cache, the `types_by_identifier`
//! `OnceLock` and the `direct_descendant_index`. The two decisions behind those
//! cells live here.

use crate::graph_support::RubySource;
use crate::mixins::ruby_forward_superclass_targets;
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::hash::HashMap;

/// Resolves a raw supertype name (a superclass or an
/// `include`/`prepend`/`extend` argument) to a declared type.
///
/// The visitor already renders supertype names into the internal `$`-joined
/// key form, so a fully-qualified reference resolves directly. Relative
/// references (e.g. `Comparable` named inside a namespace) fall back to
/// matching the trailing identifier across all declared types.
pub fn ruby_resolve_supertype(ruby: &dyn RubySource, raw: &str) -> Option<CodeUnit> {
    let cleaned = raw.trim();
    if cleaned.is_empty() {
        return None;
    }

    if let Some(found) = ruby.definitions(cleaned).next() {
        return Some(found.clone());
    }

    let last_segment = cleaned.rsplit('$').next().unwrap_or(cleaned); // fqname-M4: leaf of a `$`-joined ruby type-name string used as a by-identifier index key; no fq threaded here
    ruby.types_by_identifier()
        .get(last_segment)
        .and_then(|types| types.first())
        .cloned()
}

/// Indexes class/module declarations by trailing identifier so the
/// relative-supertype fallback is an O(1) lookup instead of a full
/// `all_declarations` scan per unresolved supertype.
pub fn build_ruby_types_by_identifier(ruby: &dyn RubySource) -> HashMap<String, Vec<CodeUnit>> {
    let mut index: HashMap<String, Vec<CodeUnit>> = HashMap::default();
    for code_unit in ruby.all_declarations() {
        if code_unit.is_class() || code_unit.is_module() {
            index
                .entry(code_unit.identifier().to_string())
                .or_default()
                .push(code_unit.clone());
        }
    }
    index
}

pub fn ruby_supports_type_hierarchy(code_unit: &CodeUnit) -> bool {
    code_unit.is_class() || code_unit.is_module()
}

/// The uncached body of `TypeHierarchyProvider::get_direct_ancestors`; the moka
/// cache around it stays on the analyzer.
pub fn ruby_direct_ancestors(ruby: &dyn RubySource, code_unit: &CodeUnit) -> Vec<CodeUnit> {
    ruby_forward_superclass_targets(ruby, code_unit)
        .iter()
        .filter_map(|raw| ruby_resolve_supertype(ruby, raw))
        .collect()
}
