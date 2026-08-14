//! Extracting the per-file Rust usage facts from one parsed tree.
//!
//! The value types and their storage encoding live in
//! [`brokk_bifrost_core::analyzer::rust_facts`]; what is here is the walk that
//! fills them. They are extracted once, in `parse_rust_file`, from the tree
//! that pass already holds, and travel to the store as part of `ParsedFile` /
//! `FileState` like every other language-specific fact (`scala_exports`,
//! `cpp_template_metadata`, ...).
//!
//! Everything here is a function of the file's BYTES alone. Nothing may depend
//! on the file's path, because the store keys these rows by content hash and
//! two byte-identical files at different paths share one row set. Module names
//! are therefore relative to the file's own root module, and import/export
//! paths are the verbatim source spelling.

use tree_sitter::Node;

use brokk_bifrost_core::analyzer::rust_facts::{
    RUST_OCCURRENCE_CODE, RUST_OCCURRENCE_COMMENT, RUST_OCCURRENCE_MACRO, RUST_OCCURRENCE_STRING,
    RustExportFact, RustIdentifierOccurrence, RustImportTargetFact, RustIncludeBindingKind,
    RustIncludeEdgeFact, RustIncludeHostBindingFact, RustModuleFact, RustRulesItemMacroDefinition,
    RustUsageFacts, RustVisibility,
};
use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
use brokk_bifrost_core::hash::HashMap;

use crate::cargo_routes::{extract_rust_module_route_facts, rust_static_string_literal};
use crate::declarations::{
    rust_identifier_like_node_kind, rust_macro_invocation_arguments, rust_node_text,
    rust_unqualified_macro_invocation_name,
};
use crate::imports::{RustImportOwner, rust_import_projection, rust_module_extents};

/// Extract every per-file usage fact from one already-parsed Rust file.
///
/// Called from `parse_rust_file` with the tree that pass already holds; nothing
/// here re-parses, and nothing here consults the analyzer, the file system, or
/// the file's path.
pub fn extract_rust_usage_facts(
    root: Node<'_>,
    source: &str,
    item_macros: &[RustRulesItemMacroDefinition],
) -> RustUsageFacts {
    let modules = extract_modules(root, source);
    let import_targets = extract_import_targets(root, source);
    let exports = extract_exports(&import_targets);
    let identifier_occurrences = extract_identifier_occurrences(root, source);
    let module_routes = extract_rust_module_route_facts(root, source, item_macros);
    let include_edges = extract_include_edges(root, source);
    RustUsageFacts {
        exports,
        import_targets,
        modules,
        identifier_occurrences,
        module_routes,
        include_edges,
    }
}

/// Every `include!("...")` invocation in the file, with the host import
/// bindings lexically in scope at each one.
///
/// Content-only, like everything else here: the literal is recorded as written
/// and its last component indexed, because resolving it needs the host file's
/// own directory and these rows are shared by every file with these bytes.
///
/// An absolute or empty literal is skipped, matching what the resolver would do
/// with it: `include!` resolves relative to the including file, so an absolute
/// path names nothing this workspace owns.
///
/// Explicit stack, never recursion: this runs over every analyzed Rust file.
fn extract_include_edges(root: Node<'_>, source: &str) -> Vec<RustIncludeEdgeFact> {
    let mut edges: Vec<RustIncludeEdgeFact> = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == "macro_invocation"
            && rust_unqualified_macro_invocation_name(node, source) == Some("include")
            && let Some(arguments) = rust_macro_invocation_arguments(node)
            && let Some(literal) = single_named_child(arguments)
            && let Some(relative_path) = rust_static_string_literal(literal, source)
            && !relative_path.is_empty()
            && !std::path::Path::new(&relative_path).is_absolute()
            && let Some(file_name) = std::path::Path::new(&relative_path)
                .file_name()
                .and_then(|name| name.to_str())
        {
            edges.push(RustIncludeEdgeFact {
                file_name: file_name.to_string(),
                include_start: node.start_byte(),
                host_bindings: include_host_bindings(root, source, node.start_byte()),
                relative_path,
            });
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    edges.sort_by(|left, right| {
        left.relative_path
            .cmp(&right.relative_path)
            .then_with(|| left.include_start.cmp(&right.include_start))
    });
    edges.dedup_by(|left, right| {
        left.relative_path == right.relative_path
            && left.include_start == right.include_start
            && left.host_bindings == right.host_bindings
    });
    edges
}

/// The file's import bindings whose lexical scope contains `include_start`.
///
/// The stored `module_specifier` is the written prefix; a glob binds no local
/// name and records `*`, matching what the route composition shadows on.
fn include_host_bindings(
    root: Node<'_>,
    source: &str,
    include_start: usize,
) -> Vec<RustIncludeHostBindingFact> {
    let mut bindings = Vec::new();
    // The base module is empty for the same reason every other fact here is
    // relative: the host's package is path-derived and the reader composes it.
    for projected in rust_import_projection(root, source, "") {
        let (scope_start, scope_end) = match projected.owner {
            RustImportOwner::Module { start, end, .. } => (start, end),
            RustImportOwner::LocalOnly {
                module_start,
                module_end,
                ..
            } => (module_start, module_end),
        };
        if !(scope_start <= include_start && include_start < scope_end) {
            continue;
        }
        let (local_name, module_specifier, imported_name, kind) =
            if projected.import.info.is_wildcard {
                (
                    "*".to_string(),
                    projected.import.path.join("::"),
                    None,
                    RustIncludeBindingKind::Glob,
                )
            } else if projected.import.is_extern_crate || projected.import.path.len() <= 1 {
                let Some(local_name) = projected.import.info.local_name() else {
                    continue;
                };
                (
                    local_name.to_string(),
                    projected.import.path.join("::"),
                    None,
                    RustIncludeBindingKind::Namespace,
                )
            } else {
                let Some((imported_name, module_path)) = projected.import.path.split_last() else {
                    continue;
                };
                let Some(local_name) = projected.import.info.local_name() else {
                    continue;
                };
                (
                    local_name.to_string(),
                    module_path.join("::"),
                    Some(imported_name.clone()),
                    RustIncludeBindingKind::Named,
                )
            };
        if module_specifier.is_empty() {
            continue;
        }
        bindings.push(RustIncludeHostBindingFact {
            local_name,
            module_specifier,
            imported_name,
            scope_start,
            kind,
        });
    }
    bindings.sort_by(|left, right| {
        left.scope_start
            .cmp(&right.scope_start)
            .then_with(|| left.local_name.cmp(&right.local_name))
            .then_with(|| left.module_specifier.cmp(&right.module_specifier))
    });
    bindings.dedup();
    bindings
}

/// The one named child of `node`, or `None` when it has none or several.
fn single_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    let child = children.next()?;
    children.next().is_none().then_some(child)
}

/// The file root plus every module the file declares.
///
/// Inline modules come from [`rust_module_extents`], called with an empty base
/// so the names it produces are already relative to the file root; that is the
/// same projection the module-at-byte lookup consumes, so persisting its output
/// verbatim keeps the stored extents and the live ones identical by
/// construction. `mod name;` declarations have no body to span, so they are
/// collected by a second walk and recorded with the extent of the declaration
/// item itself.
fn extract_modules(root: Node<'_>, source: &str) -> Vec<RustModuleFact> {
    let mut modules: Vec<RustModuleFact> = rust_module_extents(root, source, "")
        .into_iter()
        .map(|(module_name, start_byte, end_byte)| RustModuleFact {
            module_name,
            is_inline: true,
            start_byte,
            end_byte,
        })
        .collect();
    modules.extend(declared_file_modules(root, source));
    modules.sort_by(|left, right| {
        left.start_byte
            .cmp(&right.start_byte)
            .then_with(|| right.end_byte.cmp(&left.end_byte))
            .then_with(|| left.module_name.cmp(&right.module_name))
    });
    modules
}

/// `mod name;` declarations, whose bodies live in another file.
fn declared_file_modules(root: Node<'_>, source: &str) -> Vec<RustModuleFact> {
    let mut declared = Vec::new();
    let mut pending = vec![(root, String::new())];
    while let Some((node, owner)) = pending.pop() {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if child.kind() != "mod_item" {
                pending.push((child, owner.clone()));
                continue;
            }
            let Some(name) = child
                .child_by_field_name("name")
                .map(|name| rust_node_text(name, source).trim().to_string())
                .filter(|name| !name.is_empty())
            else {
                continue;
            };
            let module_name = if owner.is_empty() {
                name
            } else {
                format!("{owner}.{name}")
            };
            match child.child_by_field_name("body") {
                Some(body) => pending.push((body, module_name)),
                None => declared.push(RustModuleFact {
                    module_name,
                    is_inline: false,
                    start_byte: child.start_byte(),
                    end_byte: child.end_byte(),
                }),
            }
        }
    }
    declared
}

/// Every `use` binding in the file, in the projection the usage graph already
/// uses, flattened to storable columns.
fn extract_import_targets(root: Node<'_>, source: &str) -> Vec<RustImportTargetFact> {
    rust_import_projection(root, source, "")
        .into_iter()
        .map(|projected| {
            let (owner_module, owner_start, owner_end, local_extent) = match projected.owner {
                RustImportOwner::Module { module, start, end } => (module, start, end, None),
                RustImportOwner::LocalOnly {
                    module,
                    module_start,
                    module_end,
                    start,
                    end,
                } => (module, module_start, module_end, Some((start, end))),
            };
            let path = &projected.import.path;
            let (module_path, imported_name, bound_name) = if projected.import.info.is_wildcard {
                (path.join("::"), None, None)
            } else {
                let (prefix, name) = path.split_last().map_or_else(
                    || (Vec::new(), None),
                    |(name, prefix)| (prefix.to_vec(), Some(name.clone())),
                );
                (
                    prefix.join("::"),
                    name,
                    projected.import.info.local_name().map(str::to_string),
                )
            };
            RustImportTargetFact {
                module_path,
                bound_name,
                imported_name,
                is_glob: projected.import.info.is_wildcard,
                is_extern_crate: projected.import.is_extern_crate,
                visibility: projected.import.visibility,
                cfg_condition: projected.cfg_condition,
                owner_module,
                owner_start,
                owner_end,
                local_extent,
            }
        })
        .collect()
}

/// The re-export subset of the import bindings: root-module `use` declarations
/// that are visible outside the file.
///
/// This is the same filter `export_index_of_declarations` applies to the same
/// declarations, so the persisted rows and the live projection agree. Local
/// `pub` declarations are the other half of that projection and are NOT
/// recorded here: they are already `code_units` rows, and their export status
/// is a visibility question over those rows rather than a path this file names.
fn extract_exports(import_targets: &[RustImportTargetFact]) -> Vec<RustExportFact> {
    import_targets
        .iter()
        .filter(|target| target.owner_module.is_empty() && target.local_extent.is_none())
        .filter(|target| {
            !matches!(
                target.visibility,
                RustVisibility::Private | RustVisibility::SelfModule
            )
        })
        .filter(|target| !(target.is_glob && target.module_path.is_empty()))
        .filter(|target| {
            target.is_glob || (target.bound_name.is_some() && target.imported_name.is_some())
        })
        .map(|target| RustExportFact {
            exported_name: target.bound_name.clone(),
            source_path: target.module_path.clone(),
            imported_name: target.imported_name.clone(),
            is_glob: target.is_glob,
        })
        .collect()
}

/// Which identifiers occur in this file, and in what contexts.
///
/// The walk is an explicit stack, never recursion: analyzer traversals run over
/// deeply nested ASTs during workspace initialization and must stay stack-safe.
///
/// Code identifiers come from the tree's identifier leaf kinds, canonicalized
/// the same way declaration names are (`r#` stripped, issue #1128), so a lookup
/// by a declaration's `short_name` finds the files that mention it. Comment and
/// string contents have no finer tree structure than the one token, so their
/// identifier-shaped words are split out of that token's text; this adds a
/// context bit and never replaces structure the tree already carries.
fn extract_identifier_occurrences(root: Node<'_>, source: &str) -> Vec<RustIdentifierOccurrence> {
    let mut masks: HashMap<&str, u32> = HashMap::default();
    let mut pending = vec![(root, 0u32)];
    while let Some((node, inherited)) = pending.pop() {
        let kind = node.kind();
        if rust_identifier_like_node_kind(kind) {
            let text = strip_raw_identifier_prefix(&source[node.byte_range()]);
            if !text.is_empty() {
                *masks.entry(text).or_default() |= RUST_OCCURRENCE_CODE | inherited;
            }
            continue;
        }
        match kind {
            "line_comment" | "block_comment" => {
                record_words(
                    &source[node.byte_range()],
                    RUST_OCCURRENCE_COMMENT,
                    &mut masks,
                );
                continue;
            }
            "string_literal" | "raw_string_literal" | "char_literal" => {
                record_words(
                    &source[node.byte_range()],
                    RUST_OCCURRENCE_STRING,
                    &mut masks,
                );
                continue;
            }
            _ => {}
        }
        let inherited = if kind == "token_tree" {
            inherited | RUST_OCCURRENCE_MACRO
        } else {
            inherited
        };
        let mut cursor = node.walk();
        let children = node.children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().map(|child| (child, inherited)));
    }
    let mut occurrences: Vec<_> = masks
        .into_iter()
        .map(|(identifier, context_mask)| RustIdentifierOccurrence {
            identifier: identifier.to_string(),
            context_mask,
        })
        .collect();
    occurrences.sort_by(|left, right| left.identifier.cmp(&right.identifier));
    occurrences
}

/// Record every identifier-shaped word in one opaque token's `text` under
/// `context`. A word starts with a letter or underscore and continues with
/// letters, digits, or underscores -- Rust identifier shape.
fn record_words<'source>(text: &'source str, context: u32, masks: &mut HashMap<&'source str, u32>) {
    let bytes = text.as_bytes();
    let mut start = None;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        let continues = byte.is_ascii_alphanumeric() || byte == b'_';
        match (start, continues) {
            (None, true) if byte.is_ascii_alphabetic() || byte == b'_' => start = Some(offset),
            (Some(begin), false) => {
                *masks.entry(&text[begin..offset]).or_default() |= context;
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        *masks.entry(&text[begin..]).or_default() |= context;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn facts(source: &str) -> RustUsageFacts {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("load rust grammar");
        let tree = parser.parse(source, None).expect("parse rust source");
        let item_macros =
            crate::declarations::rust_rules_item_macro_definitions(tree.root_node(), source);
        extract_rust_usage_facts(tree.root_node(), source, &item_macros)
    }

    #[test]
    fn modules_record_the_file_root_and_every_declared_module() {
        let source = "mod detached;\nmod inline { mod nested { } }\n";
        let modules = facts(source).modules;
        let named: Vec<_> = modules
            .iter()
            .map(|module| (module.module_name.as_str(), module.is_inline))
            .collect();
        assert_eq!(
            named,
            vec![
                ("", true),
                ("detached", false),
                ("inline", true),
                ("inline.nested", true),
            ],
            "modules were {modules:?}"
        );
        assert_eq!(modules[0].start_byte, 0);
        assert_eq!(modules[0].end_byte, source.len());
    }

    #[test]
    fn import_targets_record_named_glob_aliased_and_local_bindings() {
        let source = "\
use alpha::beta::Gamma;
use alpha::beta::*;
use alpha::Delta as Epsilon;
mod inner {
    use crate::Zeta;
    fn f() {
        use crate::Eta;
    }
}
";
        let targets = facts(source).import_targets;
        let described: Vec<_> = targets
            .iter()
            .map(|target| {
                (
                    target.module_path.as_str(),
                    target.bound_name.as_deref(),
                    target.imported_name.as_deref(),
                    target.is_glob,
                    target.owner_module.as_str(),
                    target.local_extent.is_some(),
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                (
                    "alpha::beta",
                    Some("Gamma"),
                    Some("Gamma"),
                    false,
                    "",
                    false
                ),
                ("alpha::beta", None, None, true, "", false),
                ("alpha", Some("Epsilon"), Some("Delta"), false, "", false),
                ("crate", Some("Zeta"), Some("Zeta"), false, "inner", false),
                ("crate", Some("Eta"), Some("Eta"), false, "inner", true),
            ],
            "targets were {targets:?}"
        );
    }

    #[test]
    fn exports_take_the_non_private_root_use_declarations_only() {
        let source = "\
use private::Hidden;
pub use alpha::Shown;
pub use alpha::Renamed as Visible;
pub(crate) use beta::*;
pub(self) use gamma::AlsoHidden;
mod inner {
    pub use delta::NotAFileExport;
}
";
        let exports = facts(source).exports;
        let described: Vec<_> = exports
            .iter()
            .map(|export| {
                (
                    export.exported_name.as_deref(),
                    export.source_path.as_str(),
                    export.imported_name.as_deref(),
                    export.is_glob,
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                (Some("Shown"), "alpha", Some("Shown"), false),
                (Some("Visible"), "alpha", Some("Renamed"), false),
                (None, "beta", None, true),
            ],
            "exports were {exports:?}"
        );
    }

    #[test]
    fn identifier_occurrences_separate_code_comment_string_and_macro_contexts() {
        let source = "\
// mentions_in_comment
fn declared_in_code() {
    let _ = \"mentions_in_string\";
    println!(\"{}\", mentions_in_macro);
}
";
        let occurrences = facts(source).identifier_occurrences;
        let mask = |name: &str| {
            occurrences
                .iter()
                .find(|occurrence| occurrence.identifier == name)
                .unwrap_or_else(|| panic!("{name} missing from {occurrences:?}"))
                .context_mask
        };
        assert_eq!(mask("declared_in_code"), RUST_OCCURRENCE_CODE);
        assert_eq!(mask("mentions_in_comment"), RUST_OCCURRENCE_COMMENT);
        assert_eq!(mask("mentions_in_string"), RUST_OCCURRENCE_STRING);
        assert_eq!(
            mask("mentions_in_macro"),
            RUST_OCCURRENCE_CODE | RUST_OCCURRENCE_MACRO
        );
        assert!(
            occurrences
                .windows(2)
                .all(|pair| pair[0].identifier < pair[1].identifier),
            "occurrences must be deduped and sorted: {occurrences:?}"
        );
    }

    #[test]
    fn raw_identifiers_are_recorded_under_their_canonical_spelling() {
        let occurrences = facts("fn r#match() {}\n").identifier_occurrences;
        assert!(
            occurrences
                .iter()
                .any(|occurrence| occurrence.identifier == "match"),
            "raw identifier should canonicalize: {occurrences:?}"
        );
    }
}
