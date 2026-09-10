//! Source scopes for declarations emitted by explicitly activated Rust models.

use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
use tree_sitter::Node;

use crate::analyzer::declaration_range::DeclarationNameRangeContext;
use crate::analyzer::semantic_model::{
    GeneratedFunctionScope, SemanticModelLocation, SemanticModelOverlay, SemanticModelSymbol,
    SemanticModelSymbolKind,
};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, ProjectFile, RustAnalyzer, resolve_analyzer};
use brokk_bifrost_rust::declarations::{rust_node_text, rust_package_name};
use brokk_bifrost_rust::graph::ast::{
    rust_path_is_leading_absolute, rust_path_segments, rust_reference_namespace,
};
use brokk_bifrost_rust::imports::{
    RustImportOwner, resolve_rust_module_segments_with_crate, rust_crate_root_package,
    rust_import_projection, rust_module_extents,
};
use brokk_bifrost_rust::usage::RustReferenceNamespace;

pub(crate) fn is_generated_function(symbol: &SemanticModelSymbol) -> bool {
    symbol.language == "rust"
        && symbol.kind == SemanticModelSymbolKind::Function
        && symbol.provenance.rule_id.is_some()
}

fn qualified(module: &str, name: &str) -> String {
    if module.is_empty() {
        name.to_owned()
    } else {
        format!("{module}.{name}")
    }
}

fn module_at(extents: &[(String, usize, usize)], byte: usize) -> &str {
    &extents
        .iter()
        .filter(|(_, start, end)| *start <= byte && byte < *end)
        .min_by_key(|(_, start, end)| end - start)
        .expect("the source root contains every selected node")
        .0
}

/// The anchor must be an actual macro argument. A generated callable is owned
/// by the invocation's lexical scope, not by the spelling of its argument.
pub(crate) fn bind_generated_functions(
    file: &ProjectFile,
    source: &str,
    symbols: &mut [SemanticModelSymbol],
) {
    if !symbols.iter().any(is_generated_function) {
        return;
    }
    let context = DeclarationNameRangeContext::new(file, source.to_owned());
    let Some(root) = context.root_node() else {
        return;
    };
    let extents = rust_module_extents(root, source, &rust_package_name(file));
    for symbol in symbols
        .iter_mut()
        .filter(|symbol| is_generated_function(symbol))
    {
        let SemanticModelLocation::Authored(anchor) = &symbol.location else {
            continue;
        };
        let Some(mut node) =
            root.named_descendant_for_byte_range(anchor.range.start_byte, anchor.range.end_byte)
        else {
            continue;
        };
        while node.kind() != "macro_invocation" {
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
        if node.kind() != "macro_invocation" {
            continue;
        }
        let mut local = None;
        let mut ancestor = node.parent();
        while let Some(parent) = ancestor {
            if matches!(parent.kind(), "mod_item" | "source_file") {
                break;
            }
            if parent.kind() == "block" {
                local = Some((parent.start_byte(), parent.end_byte()));
                break;
            }
            ancestor = parent.parent();
        }
        let module = module_at(&extents, node.start_byte()).to_owned();
        symbol.qualified_name = qualified(&module, &symbol.name);
        symbol.rust_generated_scope = Some(Box::new(GeneratedFunctionScope {
            file: crate::path_utils::rel_path_string(file),
            module,
            local,
        }));
    }
}

fn reference_path(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if !matches!(parent.kind(), "scoped_identifier" | "generic_function") {
            break;
        }
        node = parent;
    }
    node
}

/// Resolve generated free functions using parser-derived paths, import binders,
/// module ownership, lexical visibility, and Cargo target reachability.
pub(crate) fn resolve_generated_functions<'a>(
    analyzer: &dyn IAnalyzer,
    overlay: &'a SemanticModelOverlay,
    file: &ProjectFile,
    reference: &ResolvedReferenceSite,
) -> Vec<&'a SemanticModelSymbol> {
    if !overlay.has_rust_generated_functions() {
        return Vec::new();
    }
    let anchors = overlay.symbols_at_authored_path(&crate::path_utils::rel_path_string(file))
        .records.into_iter().filter(|symbol| {
            symbol.rust_generated_scope.is_some() && matches!(&symbol.location,
                SemanticModelLocation::Authored(anchor) if anchor.range.start_byte == reference.focus_start_byte && anchor.range.end_byte == reference.focus_end_byte)
        }).collect::<Vec<_>>();
    if !anchors.is_empty() {
        return anchors;
    }
    let Some(source) = analyzer.indexed_source(file) else {
        return Vec::new();
    };
    let context = DeclarationNameRangeContext::new(file, source.to_string());
    let Some(root) = context.root_node() else {
        return Vec::new();
    };
    let Some(node) =
        root.named_descendant_for_byte_range(reference.focus_start_byte, reference.focus_end_byte)
    else {
        return Vec::new();
    };
    if rust_reference_namespace(node) != RustReferenceNamespace::Value {
        return Vec::new();
    }
    let node = reference_path(node);
    let Some(path) = rust_path_segments(node) else {
        return Vec::new();
    };
    let Some(last) = path.last() else {
        return Vec::new();
    };
    if last.start_byte() != reference.focus_start_byte
        || last.end_byte() != reference.focus_end_byte
    {
        return Vec::new();
    }
    // Member calls and macro input tokens do not denote a free function path.
    if node
        .parent()
        .is_some_and(|parent| matches!(parent.kind(), "field_expression" | "token_tree"))
    {
        return Vec::new();
    }
    let segments = path
        .iter()
        .map(|node| strip_raw_identifier_prefix(rust_node_text(*node, &source)).to_owned())
        .collect::<Vec<_>>();
    let file_module = rust_package_name(file);
    let extents = rust_module_extents(root, &source, &file_module);
    let module = module_at(&extents, node.start_byte());
    let crate_module = rust_crate_root_package(file);
    let mut routes = Vec::new();
    let mut imported = false;
    for projected in rust_import_projection(root, &source, &file_module) {
        let (owner_module, visible) = match &projected.owner {
            RustImportOwner::Module { module: owner, .. } => (owner.as_str(), owner == module),
            RustImportOwner::LocalOnly {
                module: owner,
                start,
                end,
                ..
            } => (
                owner.as_str(),
                owner == module && *start <= node.start_byte() && node.end_byte() <= *end,
            ),
        };
        if !visible
            || projected.import.info.is_wildcard
            || projected.import.info.local_name() != Some(segments[0].as_str())
        {
            continue;
        }
        imported = true;
        let mut imported_path = projected.import.path;
        imported_path.extend_from_slice(&segments[1..]);
        if let Some(route) =
            resolve_rust_module_segments_with_crate(owner_module, &crate_module, &imported_path)
        {
            routes.push(route);
        }
    }
    if !imported {
        if matches!(segments[0].as_str(), "crate" | "self" | "super")
            || rust_path_is_leading_absolute(node)
        {
            if let Some(route) =
                resolve_rust_module_segments_with_crate(module, &crate_module, &segments)
            {
                routes.push(route);
            }
        } else {
            routes.push(qualified(module, &segments.join(".")));
        }
    }
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer);
    let cargo = rust.map(RustAnalyzer::cargo_routes);
    let mut matches = Vec::new();
    for route in routes {
        for symbol in overlay.symbols_named(&route).records {
            let Some(scope) = &symbol.rust_generated_scope else {
                continue;
            };
            if symbol.qualified_name != route {
                continue;
            }
            if let Some((start, end)) = scope.local
                && (scope.file != crate::path_utils::rel_path_string(file)
                    || scope.module != module
                    || node.start_byte() < start
                    || node.end_byte() > end)
            {
                continue;
            }
            if let Some(cargo) = &cargo {
                let Some(target_file) = analyzer
                    .project()
                    .file_by_rel_path(std::path::Path::new(&scope.file))
                else {
                    continue;
                };
                let target_roots = cargo.target_roots_for_file(&target_file);
                if !target_roots.is_empty()
                    && !cargo.file_can_reference_target_of(file, &target_file)
                {
                    continue;
                }
            }
            if !matches
                .iter()
                .any(|candidate: &&SemanticModelSymbol| std::ptr::eq(*candidate, symbol))
            {
                matches.push(symbol);
            }
        }
    }
    matches
}
