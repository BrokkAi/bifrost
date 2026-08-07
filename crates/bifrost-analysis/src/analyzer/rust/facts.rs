//! Per-file Rust usage facts: what one file exports, imports, declares as
//! modules, and which identifiers occur in it.
//!
//! These are the forward facts persisted with the blob that produced them (see
//! the `rust_exports`, `rust_import_targets`, `rust_modules` and
//! `rust_identifier_occurrences` tables in
//! `crates/bifrost-core/migrations/cache/0016-rust-usage-facts.sql`). They are
//! extracted once, in `parse_rust_file`, from the tree that pass already holds,
//! and travel to the store as part of `ParsedFile` / `FileState` like every
//! other language-specific fact (`scala_exports`, `cpp_template_metadata`, ...).
//!
//! Everything here is a function of the file's BYTES alone. Nothing may depend
//! on the file's path, because the store keys these rows by content hash and
//! two byte-identical files at different paths share one row set. Module names
//! are therefore relative to the file's own root module, and import/export
//! paths are the verbatim source spelling.

use tree_sitter::Node;

use crate::analyzer::common::{rust_identifier_like_node_kind, strip_raw_identifier_prefix};
use crate::hash::HashMap;

use super::imports::{
    RustImportOwner, RustVisibility, rust_import_projection, rust_module_extents,
};

/// The identifier occurred in ordinary code: a reference, a declaration name,
/// a field, a type. This is the only context a resolver can act on directly.
pub(crate) const RUST_OCCURRENCE_CODE: u32 = 1;
/// The identifier occurred inside a line or block comment.
pub(crate) const RUST_OCCURRENCE_COMMENT: u32 = 1 << 1;
/// The identifier occurred inside a string or character literal.
pub(crate) const RUST_OCCURRENCE_STRING: u32 = 1 << 2;
/// The identifier occurred inside a macro invocation's token tree, where it is
/// text handed to a macro rather than a resolved path.
pub(crate) const RUST_OCCURRENCE_MACRO: u32 = 1 << 3;

/// A name this file publishes through a non-private `use` at its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustExportFact {
    /// The name importers see, after any `as` alias. `None` for a glob.
    pub(crate) exported_name: Option<String>,
    /// The `::`-joined module prefix the name is published from, verbatim.
    pub(crate) source_path: String,
    /// The name inside `source_path` that is published. `None` for a glob.
    pub(crate) imported_name: Option<String>,
    pub(crate) is_glob: bool,
}

/// One binding introduced by a `use` declaration anywhere in this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustImportTargetFact {
    /// For a named import, the `::`-joined prefix as written; for a glob, the
    /// whole written path.
    pub(crate) module_path: String,
    /// The name the import binds locally. `None` for a glob.
    pub(crate) bound_name: Option<String>,
    /// The final written segment. `None` for a glob.
    pub(crate) imported_name: Option<String>,
    pub(crate) is_glob: bool,
    pub(crate) visibility: RustVisibility,
    /// Enclosing module relative to the file root; empty at the root.
    pub(crate) owner_module: String,
    pub(crate) owner_start: usize,
    pub(crate) owner_end: usize,
    /// Byte extent of the function body, block, or closure the `use` sits in,
    /// outside which the binding is not visible. `None` at module scope.
    pub(crate) local_extent: Option<(usize, usize)>,
}

/// A module this file introduces, named relative to the file's root module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustModuleFact {
    /// Dot-joined path below the file root; empty for the file root itself.
    pub(crate) module_name: String,
    /// True when the module's body is in this file (the root, and every
    /// `mod name { ... }`); false for a `mod name;` backed by another file.
    pub(crate) is_inline: bool,
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
}

/// One identifier occurring in this file, with the OR of every context it was
/// seen in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustIdentifierOccurrence {
    pub(crate) identifier: String,
    pub(crate) context_mask: u32,
}

/// Everything the Rust walk records about one file for usage analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RustUsageFacts {
    pub(crate) exports: Vec<RustExportFact>,
    pub(crate) import_targets: Vec<RustImportTargetFact>,
    pub(crate) modules: Vec<RustModuleFact>,
    /// Sorted by identifier, so the persisted row order is deterministic and a
    /// re-analysis of unchanged bytes produces byte-identical rows.
    pub(crate) identifier_occurrences: Vec<RustIdentifierOccurrence>,
}

/// The `visibility` column of `rust_import_targets`.
///
/// Text rather than an integer tag because `InPath` carries a path, and text
/// keeps the stored row inspectable with plain SQL the way the store's other
/// name columns are. `in ` is a prefix no bare keyword can collide with, so the
/// encoding round-trips exactly.
pub(crate) fn encode_rust_visibility(visibility: &RustVisibility) -> String {
    match visibility {
        RustVisibility::Private => "private".to_string(),
        RustVisibility::Public => "public".to_string(),
        RustVisibility::Crate => "crate".to_string(),
        RustVisibility::SelfModule => "self".to_string(),
        RustVisibility::SuperModule => "super".to_string(),
        RustVisibility::InPath(segments) => format!("in {}", segments.join("::")),
    }
}

/// Inverse of [`encode_rust_visibility`]. `None` only for text this build did
/// not write, which means the row came from a schema this build does not own.
///
/// Only the store's fact reader calls this, and that reader has no caller until
/// Milestone 2 of `.agents/plans/rust-usage-index-v2.md` lands `RustUsageQueries`.
#[allow(dead_code)]
pub(crate) fn decode_rust_visibility(encoded: &str) -> Option<RustVisibility> {
    match encoded {
        "private" => Some(RustVisibility::Private),
        "public" => Some(RustVisibility::Public),
        "crate" => Some(RustVisibility::Crate),
        "self" => Some(RustVisibility::SelfModule),
        "super" => Some(RustVisibility::SuperModule),
        _ => encoded
            .strip_prefix("in ")
            .map(|path| RustVisibility::InPath(path.split("::").map(str::to_string).collect())),
    }
}

/// Extract every per-file usage fact from one already-parsed Rust file.
///
/// Called from `parse_rust_file` with the tree that pass already holds; nothing
/// here re-parses, and nothing here consults the analyzer, the file system, or
/// the file's path.
pub(crate) fn extract_rust_usage_facts(root: Node<'_>, source: &str) -> RustUsageFacts {
    let modules = extract_modules(root, source);
    let import_targets = extract_import_targets(root, source);
    let exports = extract_exports(&import_targets);
    let identifier_occurrences = extract_identifier_occurrences(root, source);
    RustUsageFacts {
        exports,
        import_targets,
        modules,
        identifier_occurrences,
    }
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
                .map(|name| {
                    super::declarations::rust_node_text(name, source)
                        .trim()
                        .to_string()
                })
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
                visibility: projected.import.visibility,
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
        .filter(|target| target.is_glob || target.bound_name.is_some())
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
        extract_rust_usage_facts(tree.root_node(), source)
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
    fn rust_visibility_encoding_round_trips() {
        for visibility in [
            RustVisibility::Private,
            RustVisibility::Public,
            RustVisibility::Crate,
            RustVisibility::SelfModule,
            RustVisibility::SuperModule,
            RustVisibility::InPath(vec!["crate".to_string(), "alpha".to_string()]),
        ] {
            let encoded = encode_rust_visibility(&visibility);
            assert_eq!(
                decode_rust_visibility(&encoded),
                Some(visibility.clone()),
                "{visibility:?} encoded as {encoded}"
            );
        }
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
