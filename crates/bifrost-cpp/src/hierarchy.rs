//! C++ type-hierarchy resolution: the include-visible class table and the
//! namespace/alias search that turns a written base specifier into a `CodeUnit`.
//!
//! `analyzer/cpp/hierarchy.rs` in `brokk-bifrost-analysis` keeps the
//! `TypeHierarchyProvider` impl, the two moka caches it reads through and the
//! `test-support` build counter; every decision they memoize is a function here.

use crate::graph_support::CppSource;
use crate::imports::resolve_include_targets_with_index;
use brokk_bifrost_core::analyzer::cpp_facts::CppStructuredAliasTarget;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_core::profiling;

/// Every class-like or alias declaration reachable from `file` through its
/// transitive `#include` closure, sorted and deduplicated.
///
/// This is the builder behind [`CppSource::visible_type_units`]; the
/// analyzer memoizes the result per file and records the build for the
/// `visible_type_units_build_count_for_test` counter before calling in.
///
/// `keep_going` is polled once per file popped from the pending stack, which is
/// the natural checkpoint: one pop is one file's declarations plus one file's
/// imports. `None` means the walk stopped short, and the caller must not
/// memoize it (issue #1748).
pub fn build_cpp_visible_type_units(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    keep_going: &dyn Fn() -> bool,
) -> Option<Vec<CodeUnit>> {
    let _scope =
        profiling::scope_with(|| format!("cpp.visible_types.build[{}]", rel_path_string(file)));
    let include_targets = cpp.include_target_index();
    let mut visited = HashSet::default();
    let mut declarations = Vec::new();
    let mut pending = vec![file.clone()];
    visited.insert(file.clone());

    while let Some(current) = pending.pop() {
        if !keep_going() {
            return None;
        }
        {
            let _decls = profiling::scope("cpp.visible_types.decls");
            declarations.extend(
                cpp.declarations(&current)
                    .into_iter()
                    .filter(|unit| unit.is_class() || cpp.is_type_alias(unit)),
            );
        }

        let imports = {
            let _imports = profiling::scope("cpp.visible_types.imports");
            cpp.canonical_include_paths(token, &current)?
        };
        for include in imports {
            for target in resolve_include_targets_with_index(&current, &include, include_targets) {
                if visited.insert(target.clone()) {
                    pending.push(target);
                }
            }
        }
    }

    declarations.sort();
    declarations.dedup();
    profiling::note_with(|| {
        format!(
            "cpp.visible_types.done[{}] visited={} declarations={}",
            rel_path_string(file),
            visited.len(),
            declarations.len()
        )
    });
    Some(declarations)
}

/// The direct base classes of `code_unit`, resolved through the include-visible
/// class table and canonicalized past any type-alias hops.
///
/// `None` means cancellation or unavailable canonical publication, including
/// any alias in a base-type chain. An empty vector means no resolvable bases.
pub fn cpp_resolve_direct_ancestors(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
    keep_going: &dyn Fn() -> bool,
) -> Option<Vec<CodeUnit>> {
    if !code_unit.is_class() || cpp.is_type_alias(code_unit) {
        return Some(Vec::new());
    }

    let visible = cpp.visible_type_units_while(code_unit.source(), keep_going)?;
    let facts = cpp.declaration_source_properties(token, code_unit)?;
    let mut ancestors = Vec::new();
    for fact in facts {
        for base in fact.bases {
            if let Some(ancestor) = resolve_base_type(
                cpp,
                token,
                code_unit,
                &base.components,
                base.absolute,
                &visible,
                keep_going,
            )? && !ancestors.iter().any(|existing| existing == &ancestor)
            {
                ancestors.push(ancestor);
            }
        }
    }
    Some(ancestors)
}

fn resolve_base_type(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
    components: &[String],
    global: bool,
    visible: &[CodeUnit],
    keep_going: &dyn Fn() -> bool,
) -> Option<Option<CodeUnit>> {
    if !keep_going() {
        return None;
    }
    let name = components.join("::");
    let resolved = if components.len() > 1 || global {
        resolve_qualified_type(code_unit.package_name(), &name, global, visible)
    } else {
        resolve_unqualified_base(code_unit, &name, visible)
    };
    let Some(resolved) = resolved else {
        return Some(None);
    };
    canonicalize_alias(cpp, token, resolved, visible, keep_going)
}

fn resolve_unqualified_base<'a>(
    code_unit: &CodeUnit,
    name: &str,
    visible: &'a [CodeUnit],
) -> Option<&'a CodeUnit> {
    for namespace in namespace_search_order(code_unit.package_name()) {
        if let Some(candidate) = visible.iter().find(|candidate| {
            candidate.identifier() == name && candidate.package_name() == namespace
        }) {
            return Some(candidate);
        }
    }

    visible
        .iter()
        .find(|candidate| candidate.identifier() == name)
}

fn canonicalize_alias(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    visible: &[CodeUnit],
    keep_going: &dyn Fn() -> bool,
) -> Option<Option<CodeUnit>> {
    let mut current = unit.clone();
    let mut seen = HashSet::default();
    loop {
        if !keep_going() {
            return None;
        }
        if !cpp.is_type_alias(&current) {
            return Some(Some(current));
        }
        if !seen.insert(current.fq_name()) {
            return Some(None);
        }
        let facts = cpp.declaration_source_properties(token, &current)?;
        let Some(target) = facts.first().and_then(|fact| fact.alias_target.as_ref()) else {
            return Some(None);
        };
        if !facts
            .iter()
            .all(|fact| fact.alias_target.as_ref() == Some(target))
        {
            return Some(None);
        }
        let CppStructuredAliasTarget::Named {
            components, global, ..
        } = target
        else {
            return Some(None);
        };
        let name = components.join("::");
        if name.is_empty() {
            return Some(None);
        }
        let resolved = if components.len() > 1 || *global {
            resolve_qualified_type(current.package_name(), &name, *global, visible)
        } else {
            visible
                .iter()
                .find(|candidate| {
                    candidate.identifier() == name
                        && candidate.package_name() == current.package_name()
                })
                .or_else(|| {
                    visible
                        .iter()
                        .find(|candidate| candidate.identifier() == name)
                })
        };
        let Some(resolved) = resolved else {
            return Some(None);
        };
        current = resolved.clone();
    }
}

fn resolve_qualified_type<'a>(
    lexical_namespace: &str,
    name: &str,
    global: bool,
    visible: &'a [CodeUnit],
) -> Option<&'a CodeUnit> {
    let namespaces = if global {
        vec![""]
    } else {
        namespace_search_order(lexical_namespace)
    };
    namespaces.into_iter().find_map(|namespace| {
        let qualified = if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{namespace}::{name}")
        };
        visible
            .iter()
            .find(|candidate| cpp_name_for(candidate) == qualified)
    })
}

fn namespace_search_order(package_name: &str) -> Vec<&str> {
    let mut namespaces = Vec::new();
    let mut current = package_name;
    loop {
        namespaces.push(current);
        let Some((parent, _)) = current.rsplit_once("::") else {
            if !current.is_empty() {
                namespaces.push("");
            }
            return namespaces;
        };
        current = parent;
    }
}

fn cpp_name_for(unit: &CodeUnit) -> String {
    let short = unit.short_name().replace(['.', '$'], "::");
    if unit.package_name().is_empty() {
        short
    } else {
        format!("{}::{}", unit.package_name(), short)
    }
}
