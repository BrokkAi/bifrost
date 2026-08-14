//! Per-file Rust usage facts: the value types one Rust parse yields for the
//! `rust_*` fact tables, and their storage encoding.
//!
//! These live in core for the same reason [`ScalaExportInfo`] and
//! [`CppTemplateMetadata`] do: they are plain data a language walk produces and
//! [`ParsedFile`] carries to the store. Nothing here names an `IAnalyzer`, a
//! store, a grammar, or a language module, so core is where the workspace
//! dependency rule puts them. The extraction that fills them is tree-sitter
//! work and stays in `brokk-bifrost-rust`; the persistence is SQL and stays in
//! `brokk-bifrost-analysis`.
//!
//! Everything here is a function of one file's BYTES alone. Nothing may depend
//! on the file's path, because the store keys these rows by content hash and
//! two byte-identical files at different paths share one row set. Module names
//! are therefore relative to the file's own root module, and import/export
//! paths are the verbatim source spelling.
//!
//! [`ScalaExportInfo`]: crate::analyzer::model::ScalaExportInfo
//! [`CppTemplateMetadata`]: crate::analyzer::model::CppTemplateMetadata
//! [`ParsedFile`]: crate::analyzer::parsed_file::ParsedFile

/// The identifier occurred in ordinary code: a reference, a declaration name,
/// a field, a type. This is the only context a resolver can act on directly.
pub const RUST_OCCURRENCE_CODE: u32 = 1;
/// The identifier occurred inside a line or block comment.
pub const RUST_OCCURRENCE_COMMENT: u32 = 1 << 1;
/// The identifier occurred inside a string or character literal.
pub const RUST_OCCURRENCE_STRING: u32 = 1 << 2;
/// The identifier occurred inside a macro invocation's token tree, where it is
/// text handed to a macro rather than a resolved path.
pub const RUST_OCCURRENCE_MACRO: u32 = 1 << 3;

/// How far a Rust item is visible from the module that declares it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RustVisibility {
    Private,
    Public,
    Crate,
    SelfModule,
    SuperModule,
    InPath(Vec<String>),
}

/// The `#[cfg(...)]` predicate guarding one item, reduced to the shapes two
/// items can be PROVEN to exclude each other by.
///
/// Anything richer than a bare atom or its negation is [`Self::Unknown`], which
/// proves nothing: the reduction exists only so that `#[cfg(feature = "x")]`
/// and `#[cfg(not(feature = "x"))]` can be recognized as alternatives of one
/// declaration rather than as an ambiguity between two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustCfgCondition {
    Always,
    Atom(String),
    NotAtom(String),
    Unknown,
}

impl RustCfgCondition {
    pub fn proven_mutually_exclusive(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Atom(left), Self::NotAtom(right)) | (Self::NotAtom(left), Self::Atom(right))
                if left == right
        )
    }
}

/// The `cfg_condition` column of `rust_import_targets`.
///
/// Text for the same reason [`encode_rust_visibility`] is: the atom carries a
/// predicate spelling, and a readable column keeps the row inspectable with
/// plain SQL. `atom ` and `not ` are prefixes no bare keyword collides with, so
/// the encoding round-trips exactly.
pub fn encode_rust_cfg_condition(condition: &RustCfgCondition) -> String {
    match condition {
        RustCfgCondition::Always => "always".to_string(),
        RustCfgCondition::Unknown => "unknown".to_string(),
        RustCfgCondition::Atom(atom) => format!("atom {atom}"),
        RustCfgCondition::NotAtom(atom) => format!("not {atom}"),
    }
}

/// Inverse of [`encode_rust_cfg_condition`]. `None` only for text this build did
/// not write.
pub fn decode_rust_cfg_condition(encoded: &str) -> Option<RustCfgCondition> {
    match encoded {
        "always" => Some(RustCfgCondition::Always),
        "unknown" => Some(RustCfgCondition::Unknown),
        _ => encoded
            .strip_prefix("atom ")
            .map(|atom| RustCfgCondition::Atom(atom.to_string()))
            .or_else(|| {
                encoded
                    .strip_prefix("not ")
                    .map(|atom| RustCfgCondition::NotAtom(atom.to_string()))
            }),
    }
}

/// A `macro_rules!` definition written at an item position, with the byte range
/// over which its name is in scope.
///
/// Produced by the Rust declaration walk and persisted as `rust_item_macros`,
/// because the Cargo route index needs to know which item macros could have
/// expanded to a `mod` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustRulesItemMacroDefinition {
    pub name: String,
    pub visible_after: usize,
    pub scope_start: usize,
    pub scope_end: usize,
    pub passthrough: bool,
}

/// A name this file publishes through a non-private `use` at its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustExportFact {
    /// The name importers see, after any `as` alias. `None` for a glob.
    pub exported_name: Option<String>,
    /// The `::`-joined module prefix the name is published from, verbatim.
    pub source_path: String,
    /// The name inside `source_path` that is published. `None` for a glob.
    pub imported_name: Option<String>,
    pub is_glob: bool,
}

/// One binding introduced by a `use` declaration anywhere in this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustImportTargetFact {
    /// For a named import, the `::`-joined prefix as written; for a glob, the
    /// whole written path.
    pub module_path: String,
    /// The name the import binds locally. `None` for a glob.
    pub bound_name: Option<String>,
    /// The final written segment. `None` for a glob.
    pub imported_name: Option<String>,
    pub is_glob: bool,
    /// True for `extern crate name as alias;`, which binds only a namespace.
    /// A plain `use name as alias;` is written identically in every other
    /// stored column, so the distinction cannot be recovered by the reader.
    pub is_extern_crate: bool,
    pub visibility: RustVisibility,
    /// The `#[cfg(...)]` predicate on the `use` declaration that introduced this
    /// binding. Two bindings of one name under proven-disjoint conditions are
    /// alternatives, not an ambiguity.
    pub cfg_condition: RustCfgCondition,
    /// Enclosing module relative to the file root; empty at the root.
    pub owner_module: String,
    pub owner_start: usize,
    pub owner_end: usize,
    /// Byte extent of the function body, block, or closure the `use` sits in,
    /// outside which the binding is not visible. `None` at module scope.
    pub local_extent: Option<(usize, usize)>,
}

/// A module this file introduces, named relative to the file's root module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleFact {
    /// Dot-joined path below the file root; empty for the file root itself.
    pub module_name: String,
    /// True when the module's body is in this file (the root, and every
    /// `mod name { ... }`); false for a `mod name;` backed by another file.
    pub is_inline: bool,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// One identifier occurring in this file, with the OR of every context it was
/// seen in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustIdentifierOccurrence {
    pub identifier: String,
    pub context_mask: u32,
}

/// One lexical scope that `mod` items are declared in: the file root, or a
/// `mod name { ... }` body reachable from it.
///
/// Persisted as `rust_module_scopes`. See that table's comment for why
/// `path_attribute` and `imports_macros` cannot be folded into the route row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleScopeFact {
    /// Index of the enclosing scope in [`RustModuleRouteFacts::scopes`]. `None`
    /// only for the file root, which is always index 0.
    pub parent: Option<usize>,
    /// The inline module's own name; empty for the file root.
    pub module_name: String,
    /// The decoded `#[path = "..."]` value written on this inline module.
    pub path_attribute: Option<String>,
    /// Whether an unbroken `#[macro_use]` chain reaches this scope from the
    /// file root, which is what lets a `mod` item below it import macros into
    /// file scope.
    pub imports_macros: bool,
    pub body_start: usize,
    pub body_end: usize,
}

/// One `mod name;` declaration whose body lives in another file, as written.
///
/// Persisted as `rust_module_routes`. Which file it names is a question about
/// the declaring file's path and the file system, so it is answered by the
/// reader, not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleRouteFact {
    /// Index into [`RustModuleRouteFacts::scopes`].
    pub scope: usize,
    pub module_name: String,
    /// The decoded `#[path = "..."]` value on this declaration. When present it
    /// names exactly one file instead of the two conventional candidates.
    pub path_attribute: Option<String>,
    pub visibility: RustVisibility,
    /// `#[macro_use]` on this declaration, with the scope's chain applied.
    pub imports_macros: bool,
    /// A bare `#[cfg(test)]` on this declaration; see
    /// `rust_declaration_is_bare_cfg_test_gated` for why only the bare
    /// predicate counts.
    pub test_gated: bool,
    pub declaration_start: usize,
    pub declaration_end: usize,
    /// The item macro invocations this declaration was found inside, outermost
    /// first. Empty for a declaration written directly in the source.
    pub gates: Vec<RustMacroGateFact>,
}

/// One item-macro invocation a route was expanded out of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustMacroGateFact {
    pub macro_name: String,
    /// The invocation's start byte in the declaring file.
    pub invocation_start: usize,
}

/// What the Cargo route index reads from one file.
///
/// Split out of the usage facts because it is read wholesale for every analyzed
/// file when the route index composes, where the usage facts are read one
/// candidate file at a time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RustModuleRouteFacts {
    /// Pre-order, so a scope's parent always precedes it. Index 0 is the file
    /// root and is present for every analyzed Rust blob.
    pub scopes: Vec<RustModuleScopeFact>,
    pub routes: Vec<RustModuleRouteFact>,
    /// The `macro_rules!` definitions at item positions, as
    /// `rust_rules_item_macro_definitions` derives them.
    pub item_macros: Vec<RustRulesItemMacroDefinition>,
}

impl RustModuleRouteFacts {
    /// The file's own byte extent, recorded on the root scope.
    ///
    /// `None` only for facts that were never extracted, which the route index
    /// treats as "this file contributes no module edges" exactly as a failed
    /// hydration did.
    pub fn file_extent(&self) -> Option<(usize, usize)> {
        let root = self.scopes.first()?;
        Some((root.body_start, root.body_end))
    }
}

/// One `include!("...")` invocation in this file, as written.
///
/// Persisted as `rust_include_edges`. `relative_path` is the literal after
/// escape decoding and `file_name` its last component; neither the resolved
/// target nor the host's package is stored, because both need the live file's
/// own location and these rows are content-keyed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustIncludeEdgeFact {
    pub relative_path: String,
    pub file_name: String,
    /// The invocation's start byte, which is where the reader takes the host's
    /// lexical package and picks the bindings in scope.
    pub include_start: usize,
    /// The host import bindings whose scope contains `include_start`, in the
    /// order route composition applies them.
    pub host_bindings: Vec<RustIncludeHostBindingFact>,
}

/// One host import binding visible at an include splice.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RustIncludeHostBindingFact {
    pub local_name: String,
    pub module_specifier: String,
    pub imported_name: Option<String>,
    pub scope_start: usize,
    pub kind: RustIncludeBindingKind,
}

/// The three import shapes an include route threads. A narrow enum rather than
/// core's `ImportKind` because only these three can reach a route, and the
/// stored `kind` column round-trips exactly through
/// [`encode_rust_include_binding_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RustIncludeBindingKind {
    Named,
    Namespace,
    Glob,
}

pub fn encode_rust_include_binding_kind(kind: RustIncludeBindingKind) -> &'static str {
    match kind {
        RustIncludeBindingKind::Named => "named",
        RustIncludeBindingKind::Namespace => "namespace",
        RustIncludeBindingKind::Glob => "glob",
    }
}

/// Inverse of [`encode_rust_include_binding_kind`]. `None` only for text this
/// build did not write.
pub fn decode_rust_include_binding_kind(encoded: &str) -> Option<RustIncludeBindingKind> {
    match encoded {
        "named" => Some(RustIncludeBindingKind::Named),
        "namespace" => Some(RustIncludeBindingKind::Namespace),
        "glob" => Some(RustIncludeBindingKind::Glob),
        _ => None,
    }
}

/// Everything the Rust walk records about one file for usage analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RustUsageFacts {
    pub exports: Vec<RustExportFact>,
    pub import_targets: Vec<RustImportTargetFact>,
    pub modules: Vec<RustModuleFact>,
    /// Sorted by identifier, so the persisted row order is deterministic and a
    /// re-analysis of unchanged bytes produces byte-identical rows.
    pub identifier_occurrences: Vec<RustIdentifierOccurrence>,
    /// What the Cargo route index needs from this file (issue #1793).
    pub module_routes: RustModuleRouteFacts,
    /// The file's `include!` invocations, in source order.
    pub include_edges: Vec<RustIncludeEdgeFact>,
}

/// The `visibility` column of `rust_import_targets`.
///
/// Text rather than an integer tag because `InPath` carries a path, and text
/// keeps the stored row inspectable with plain SQL the way the store's other
/// name columns are. `in ` is a prefix no bare keyword can collide with, so the
/// encoding round-trips exactly.
pub fn encode_rust_visibility(visibility: &RustVisibility) -> String {
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
pub fn decode_rust_visibility(encoded: &str) -> Option<RustVisibility> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_include_binding_kind_encoding_round_trips() {
        for kind in [
            RustIncludeBindingKind::Named,
            RustIncludeBindingKind::Namespace,
            RustIncludeBindingKind::Glob,
        ] {
            let encoded = encode_rust_include_binding_kind(kind);
            assert_eq!(
                decode_rust_include_binding_kind(encoded),
                Some(kind),
                "{kind:?} encoded as {encoded}"
            );
        }
    }

    #[test]
    fn rust_cfg_condition_encoding_round_trips() {
        for condition in [
            RustCfgCondition::Always,
            RustCfgCondition::Unknown,
            RustCfgCondition::Atom("feature = \"query_apply\"".to_string()),
            RustCfgCondition::NotAtom("feature = \"query_apply\"".to_string()),
        ] {
            let encoded = encode_rust_cfg_condition(&condition);
            assert_eq!(
                decode_rust_cfg_condition(&encoded),
                Some(condition.clone()),
                "{condition:?} encoded as {encoded}"
            );
        }
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
}
