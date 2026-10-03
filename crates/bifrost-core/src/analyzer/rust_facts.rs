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
//! are therefore relative to the file's own root module, and import paths
//! retain their parsed segments rather than being re-parsed from a rendered
//! string.
//!
//! [`ScalaExportInfo`]: crate::analyzer::model::ScalaExportInfo
//! [`CppTemplateMetadata`]: crate::analyzer::model::CppTemplateMetadata
//! [`ParsedFile`]: crate::analyzer::parsed_file::ParsedFile

use crate::analyzer::resolution_facts::ResolutionScopeId;
use crate::analyzer::source_facts::{
    SourceDeclarationId, SourceFactRows, SourceImportId, SourceOccurrenceId,
};
use crate::hash::HashMap;

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

/// The source-owned `#[cfg(...)]` predicate guarding an item or route.
/// Simple atoms preserve their compact representation; compound predicates use
/// flat postfix instructions so parsing, evaluation and destruction are stack-safe.
/// Unknown denotes syntax whose predicate structure could not be established.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RustCfgCondition {
    Always,
    Atom(String),
    NotAtom(String),
    Expression(Box<[RustCfgInstruction]>),
    Unknown,
}

/// Postfix predicate instructions retain AST structure without recursive trees.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum RustCfgInstruction {
    Atom(String),
    KeyValue { key: String, value: String },
    Not,
    All(usize),
    Any(usize),
    Unknown,
}

impl RustCfgCondition {
    pub fn instructions(&self) -> Vec<RustCfgInstruction> {
        match self {
            Self::Always => vec![RustCfgInstruction::All(0)],
            Self::Atom(atom) => vec![RustCfgInstruction::Atom(atom.clone())],
            Self::NotAtom(atom) => vec![
                RustCfgInstruction::Atom(atom.clone()),
                RustCfgInstruction::Not,
            ],
            Self::Expression(instructions) => instructions.to_vec(),
            Self::Unknown => vec![RustCfgInstruction::Unknown],
        }
    }

    pub fn conjunction(conditions: impl IntoIterator<Item = Self>) -> Self {
        let mut conditions = conditions
            .into_iter()
            .filter(|condition| *condition != Self::Always);
        let Some(first) = conditions.next() else {
            return Self::Always;
        };
        let Some(second) = conditions.next() else {
            return first;
        };
        let mut instructions = first.instructions();
        instructions.extend(second.instructions());
        let mut count = 2;
        for condition in conditions {
            instructions.extend(condition.instructions());
            count += 1;
        }
        instructions.push(RustCfgInstruction::All(count));
        Self::Expression(instructions.into_boxed_slice())
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        match self {
            Self::Atom(atom) | Self::NotAtom(atom) => atom.capacity(),
            Self::Expression(instructions) => {
                std::mem::size_of_val(instructions.as_ref())
                    + instructions
                        .iter()
                        .map(|instruction| match instruction {
                            RustCfgInstruction::Atom(atom) => atom.capacity(),
                            RustCfgInstruction::KeyValue { key, value } => {
                                key.capacity() + value.capacity()
                            }
                            _ => 0,
                        })
                        .sum::<usize>()
            }
            Self::Always | Self::Unknown => 0,
        }
    }

    pub fn proven_mutually_exclusive(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Atom(left), Self::NotAtom(right)) | (Self::NotAtom(left), Self::Atom(right))
                if left == right
        )
    }
}

/// The visibility constraints on a Rust value constructor, excluding the
/// declaration's own visibility. The declaration property owns that value so
/// the constructor reader does not have to duplicate it in this vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustValueConstructorProperties {
    pub field_visibilities: Vec<RustVisibility>,
    pub non_exhaustive: bool,
}

impl RustValueConstructorProperties {
    pub fn estimated_retained_bytes(&self) -> usize {
        self.field_visibilities
            .capacity()
            .saturating_mul(std::mem::size_of::<RustVisibility>())
            .saturating_add(
                self.field_visibilities
                    .iter()
                    .map(rust_visibility_estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
    }
}

/// The source form of a named Rust declaration. These distinctions are finer
/// than display CodeUnit kinds: traits, structs, enums, and unions are all
/// class-like display units, while inline and external modules share a kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustDeclarationKind {
    Struct,
    Enum,
    Union,
    Trait,
    InlineModule,
    ExternalModule,
    Function,
    FunctionSignature,
    Field,
    EnumVariant,
    Const,
    Static,
    Macro,
    TypeAlias,
    AssociatedType,
}

/// The nearest boundary relevant to local versus associated value items.
/// This does not identify an owner or summarize every enclosing ancestor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustDeclarationBoundary {
    ModuleOrFile,
    LocalBlockOrFunction,
    Impl,
    Trait,
}

/// Rust properties captured once for a named declaration at its source
/// identity creation point. Local parameter and pattern declarations share the
/// generic [`SourceDeclarationId`] space but intentionally do not produce this
/// fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustDeclarationPropertyFact {
    pub declaration: SourceDeclarationId,
    pub kind: RustDeclarationKind,
    pub visibility: RustVisibility,
    pub cfg_condition: RustCfgCondition,
    pub value_constructor: Option<Box<RustValueConstructorProperties>>,
    pub macro_exported: bool,
    /// Whether the nearest enclosing impl has a trait. This is not a test
    /// for direct membership or for any farther enclosing trait impl.
    pub trait_impl_member: bool,
    /// Any enclosing impl or trait, including one beyond a function or module.
    pub has_impl_or_trait_ancestor: bool,
    pub nearest_declaration_boundary: RustDeclarationBoundary,
    /// A struct or enum whose `#[serde(..)]` attribute is an inert derive
    /// helper exactly when this derive, spelled as a bare name in the item's
    /// `#[derive(..)]` and not bound in the item's file, resolves to serde's
    /// derive. The file cannot say which derive the name binds (it arrives
    /// through a glob or a parent module's import), so the producer keeps the
    /// item and leaves its binder open, and the crate route decides.
    pub serde_helper_derive: Option<RustSerdeDerive>,
}

/// The serde derives that register `serde` as an inert helper attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RustSerdeDerive {
    Serialize,
    Deserialize,
}

impl RustSerdeDerive {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Serialize => "Serialize",
            Self::Deserialize => "Deserialize",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Serialize" => Some(Self::Serialize),
            "Deserialize" => Some(Self::Deserialize),
            _ => None,
        }
    }
}

/// One source occurrence's Rust type syntax, retained without a parser handle.
///
/// This is deliberately syntax, not a resolved nominal identity. The retained
/// shape and wrapper order are enough for bounded consumers to decide which
/// projection they support; generic arguments retain their exact source
/// occurrences without claiming that this fact evaluates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustTypeSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub wrappers: Vec<RustTypeWrapperSourceFact>,
    pub shape: RustTypeSourceShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustTypeWrapperSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub kind: RustTypeWrapperSourceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustTypeWrapperSourceKind {
    Reference,
    Pointer,
    Array,
    Slice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustTypeSourceShape {
    Path {
        leading_absolute: bool,
        segments: Vec<RustTypePathSegmentSourceFact>,
    },
    Compound {
        occurrence: SourceOccurrenceId,
        kind: RustTypeCompoundSourceKind,
        children: Vec<SourceOccurrenceId>,
        type_parameters: Option<SourceOccurrenceId>,
    },
    Unsupported {
        occurrence: SourceOccurrenceId,
        syntax_kind: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustTypeCompoundSourceKind {
    Abstract,
    Dynamic,
    Bounded,
    HigherRanked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustTypePathSegmentSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub name: String,
    pub generic_arguments: Option<RustGenericArgumentsSourceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustGenericArgumentsSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub arguments: Vec<SourceOccurrenceId>,
}

impl RustTypeSourceFact {
    /// Heap bytes owned below the containing `Vec<RustTypeSourceFact>`. The
    /// containing vector accounts for each fact's inline `size_of` separately.
    pub fn estimated_retained_bytes(&self) -> usize {
        self.wrappers
            .capacity()
            .saturating_mul(std::mem::size_of::<RustTypeWrapperSourceFact>())
            .saturating_add(match &self.shape {
                RustTypeSourceShape::Path { segments, .. } => segments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustTypePathSegmentSourceFact>())
                    .saturating_add(
                        segments
                            .iter()
                            .map(RustTypePathSegmentSourceFact::estimated_retained_bytes)
                            .fold(0usize, usize::saturating_add),
                    ),
                RustTypeSourceShape::Compound { children, .. } => children
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceOccurrenceId>()),
                RustTypeSourceShape::Unsupported { syntax_kind, .. } => syntax_kind.capacity(),
            })
    }
}

impl RustTypePathSegmentSourceFact {
    fn estimated_retained_bytes(&self) -> usize {
        self.name.capacity().saturating_add(
            self.generic_arguments
                .as_ref()
                .map_or(0, RustGenericArgumentsSourceFact::estimated_retained_bytes),
        )
    }
}

impl RustGenericArgumentsSourceFact {
    fn estimated_retained_bytes(&self) -> usize {
        self.arguments
            .capacity()
            .saturating_mul(std::mem::size_of::<SourceOccurrenceId>())
    }
}

impl RustDeclarationPropertyFact {
    pub fn estimated_retained_bytes(&self) -> usize {
        rust_visibility_estimated_retained_bytes(&self.visibility)
            .saturating_add(rust_cfg_condition_estimated_retained_bytes(
                &self.cfg_condition,
            ))
            .saturating_add(self.value_constructor.as_deref().map_or(0, |constructor| {
                std::mem::size_of::<RustValueConstructorProperties>()
                    .saturating_add(constructor.estimated_retained_bytes())
            }))
    }
}

fn rust_visibility_estimated_retained_bytes(visibility: &RustVisibility) -> usize {
    match visibility {
        RustVisibility::InPath(segments) => segments
            .capacity()
            .saturating_mul(std::mem::size_of::<String>())
            .saturating_add(
                segments
                    .iter()
                    .map(String::capacity)
                    .fold(0usize, usize::saturating_add),
            ),
        RustVisibility::Private
        | RustVisibility::Public
        | RustVisibility::Crate
        | RustVisibility::SelfModule
        | RustVisibility::SuperModule => 0,
    }
}

fn rust_cfg_condition_estimated_retained_bytes(condition: &RustCfgCondition) -> usize {
    condition.estimated_retained_bytes()
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
        RustCfgCondition::Expression(instructions) => format!(
            "expression {}",
            serde_json::to_string(instructions).expect("cfg instructions serialize")
        ),
    }
}

/// Inverse of [`encode_rust_cfg_condition`]. `None` only for text this build did
/// not write.
pub fn decode_rust_cfg_condition(encoded: &str) -> Option<RustCfgCondition> {
    if let Some(expression) = encoded.strip_prefix("expression ") {
        return serde_json::from_str(expression)
            .ok()
            .map(RustCfgCondition::Expression);
    }
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
    pub declaration: SourceDeclarationId,
    pub name: String,
    /// Materialized from the canonical declaration occurrence on readback.
    pub visible_after: usize,
    /// Materialized from the canonical enclosing context on readback.
    pub scope_start: usize,
    /// Materialized from the canonical enclosing context on readback.
    pub scope_end: usize,
    pub passthrough: bool,
    /// Every rule expands to its replayed item arguments and nothing else.
    /// Stricter than `passthrough`, which admits a rule that decorates the
    /// items it replays (`$( #[cfg(unix)] $item )*`): only here do the items
    /// exist exactly as the arguments write them, with the activation their
    /// own tokens give. A property of the definition's own rules.
    pub arguments_only: bool,
    /// The activation the definition's rules add to each item they replay,
    /// when every addition is a `cfg` attribute (or a documentation attribute,
    /// which adds none): `$( #[cfg(unix)] $item )*` adds `unix`, and a rule
    /// that adds nothing adds `Always`. `None` when a rule adds anything else,
    /// when the rules disagree, or when the definition is not a passthrough.
    /// A property of the definition's own rules, and of the definition it
    /// delegates to when it is a delegating passthrough in the same file.
    pub decoration: Option<RustCfgCondition>,
    /// No rule can write an item (an empty transcriber, or one with no item
    /// token, no nested invocation and no metavariable that could supply
    /// one), so an item-position invocation declares nothing. A property of
    /// the definition's own rules.
    pub declares_no_item: bool,
    /// Every rule writes only `impl` blocks and splices only `ty`, `expr`,
    /// `path` or `lifetime` fragments, so an item-position invocation binds
    /// no name in its module. A property of the definition's own rules.
    pub writes_only_impls: bool,
    /// Materialized from the canonical declaration property, never an
    /// independently writable persisted attribute.
    pub exported: bool,
}

/// A name this file publishes through a non-private `use` at its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustExportFact {
    /// Explicit link to the import leaf that produced this export. `None` for
    /// legacy or synthetic export rows without coordinated source identity.
    pub source_import_id: Option<SourceImportId>,
    /// The name importers see, after any `as` alias. `None` for a glob or an
    /// underscore import, which is intentionally not referenceable by name.
    pub exported_name: Option<String>,
    /// The `::`-joined module prefix the name is published from, verbatim.
    pub source_path: String,
    /// The name inside `source_path` that is published. `None` for a glob;
    /// underscore imports retain the imported target here while leaving
    /// `exported_name` unnamed.
    pub imported_name: Option<String>,
    pub is_glob: bool,
}

/// Canonical source identities attached to one primary-tree import binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustImportSourceOccurrences {
    /// The whole `use` or `extern crate` declaration node.
    pub declaration: SourceOccurrenceId,
    /// The final imported path segment, absent for a glob import.
    pub target: Option<SourceOccurrenceId>,
    /// The alias token after `as`, absent for an unaliased import.
    pub alias: Option<SourceOccurrenceId>,
}

/// Rust-only interpretation attached to one primary-tree import declaration.
///
/// The declaration occurrence is the source-owned identity shared by grouped
/// import leaves.  Scope occurrences are interned from the same primary AST
/// nodes used to calculate the native owner extents; `None` for `owner_scope`
/// means the file root, whose extent is the complete canonical source bytes.
/// Embedded macro imports do not receive this context because they have no
/// primary Rust target authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustImportContextFact {
    pub declaration: SourceOccurrenceId,
    /// Exact lexical attachment emitted by native import lowering.
    pub native_scope: Option<ResolutionScopeId>,
    pub owner_module: String,
    pub owner_scope: Option<SourceOccurrenceId>,
    pub local_scope: Option<SourceOccurrenceId>,
    pub visibility: RustVisibility,
    pub cfg_condition: RustCfgCondition,
}

impl RustImportContextFact {
    /// Approximate retained memory for source-fact admission accounting.
    pub fn estimated_retained_bytes(&self) -> usize {
        let visibility_bytes = match &self.visibility {
            RustVisibility::InPath(segments) => segments
                .capacity()
                .saturating_mul(std::mem::size_of::<String>())
                .saturating_add(
                    segments
                        .iter()
                        .map(String::capacity)
                        .fold(0usize, usize::saturating_add),
                ),
            _ => 0,
        };
        let cfg_bytes = self.cfg_condition.estimated_retained_bytes();
        self.owner_module
            .capacity()
            .saturating_add(visibility_bytes)
            .saturating_add(cfg_bytes)
    }
}

/// One binding introduced by a `use` declaration anywhere in this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustImportTargetFact {
    /// Native lexical attachment, retained from the canonical import context.
    pub native_scope: Option<ResolutionScopeId>,
    /// The coordinated producer's per-leaf source identity. It is distinct
    /// from this vector's Rust-target ordinal because generic and native
    /// projections have different memberships.
    pub source_import_id: Option<SourceImportId>,
    /// For a named import, the structured `::`-separated qualifier prefix; for
    /// a glob, the complete structured path. Punctuation and the leading
    /// absolute anchor are represented separately by `leading_absolute`.
    pub module_path: Vec<String>,
    /// The name the import binds locally. `None` for a glob or an underscore
    /// import, which introduces no referenceable local name.
    pub bound_name: Option<String>,
    /// The final written segment. `None` for a glob; underscore imports retain
    /// their target segment here.
    pub imported_name: Option<String>,
    pub is_glob: bool,
    /// True when the source use-tree leaf starts with a leading `::` anchor.
    /// This is kept separate from `module_path`, whose segments intentionally
    /// omit punctuation, so selected topology can distinguish an absolute
    /// route from the same spelling resolved relative to its owner module.
    pub leading_absolute: bool,
    /// True for `extern crate name as alias;`, which binds only a namespace.
    /// A plain `use name as alias;` is written identically in every other
    /// stored column, so the distinction cannot be recovered by the reader.
    pub is_extern_crate: bool,
    /// True when an `extern crate` item carries `#[macro_use]` and imports the
    /// target crate's exported macros into the macro-use prelude.
    pub is_macro_use: bool,
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
    /// Canonical source identities for a primary-tree import. Macro-generated
    /// and legacy rows leave this unset because they do not share the primary
    /// tree's source arena.
    pub source_occurrences: Option<RustImportSourceOccurrences>,
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
    /// The `#[cfg(...)]` predicate on the module item. The file-root row is
    /// always [`RustCfgCondition::Always`].
    pub cfg_condition: RustCfgCondition,
}

/// Canonical source-owned module metadata and projection links. The existing
/// module DTOs are materialized from this record and the shared source rows;
/// they are not an independent write authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleSourceFacts {
    pub root: SourceOccurrenceId,
    pub declarations: Vec<RustModuleDeclarationSourceFact>,
    pub invocations: Vec<RustMacroInvocationSourceFact>,
    pub inventory: Vec<RustModuleInventorySourceFact>,
    pub scopes: Vec<RustModuleScopeSourceFact>,
    pub routes: Vec<RustModuleRouteSourceFact>,
    /// The file's top-level inner attributes (`#![..]`), in source order.
    pub inner_attributes: Vec<RustInnerAttributeSourceFact>,
}

/// One top-level inner attribute of a file (`#![no_std]`,
/// `#![cfg_attr(feature = "x", no_std)]`): its path, and the identifiers and
/// literals of its top-level argument tokens, each as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustInnerAttributeSourceFact {
    pub name: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleDeclarationSourceFact {
    pub declaration: SourceDeclarationId,
    pub name: String,
    pub body: Option<SourceOccurrenceId>,
    pub path_attribute: Option<String>,
    pub macro_use: bool,
    pub test_gated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustMacroInvocationSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleInventorySourceFact {
    pub declaration: Option<SourceDeclarationId>,
    pub parent_scope: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleScopeSourceFact {
    pub parent: Option<usize>,
    pub declaration: Option<SourceDeclarationId>,
    pub resolution_scope: Option<ResolutionScopeId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleRouteSourceFact {
    pub scope: usize,
    pub declaration: SourceDeclarationId,
    pub gates: Vec<SourceOccurrenceId>,
}

impl RustModuleSourceFacts {
    /// Materialize the legacy module usage views from canonical source rows.
    /// Every name, range, visibility, cfg predicate, and gate location comes
    /// from an explicit canonical row; a missing link is a producer error.
    pub fn materialize(
        &self,
        occurrences: &SourceFactRows,
        properties: &[RustDeclarationPropertyFact],
    ) -> (
        Vec<RustModuleFact>,
        Vec<RustModuleScopeFact>,
        Vec<RustModuleRouteFact>,
    ) {
        assert!(
            !self.scopes.is_empty(),
            "Rust module source scopes are nonempty"
        );
        let root_scope = &self.scopes[0];
        assert!(
            root_scope.parent.is_none(),
            "Rust module root has no parent"
        );
        assert!(
            root_scope.declaration.is_none(),
            "Rust module root has no declaration"
        );
        assert_eq!(
            self.inventory.first().map(|entry| entry.declaration),
            Some(None),
            "Rust module inventory starts with its root"
        );
        assert_eq!(
            self.inventory.first().map(|entry| entry.parent_scope),
            Some(0),
            "Rust module root inventory scope is zero"
        );
        let root_range = occurrences.occurrence(self.root).range;

        let mut declarations = HashMap::default();
        let mut declaration_properties = HashMap::default();
        for declaration in &self.declarations {
            assert!(
                declarations
                    .insert(declaration.declaration, declaration)
                    .is_none(),
                "one canonical module declaration row per source declaration"
            );
        }
        for property in properties {
            assert!(
                declaration_properties
                    .insert(property.declaration, property)
                    .is_none(),
                "one Rust property row per source declaration"
            );
        }
        for declaration in &self.declarations {
            let property = declaration_properties
                .get(&declaration.declaration)
                .expect("canonical module declaration has Rust properties");
            assert!(
                matches!(
                    (property.kind, declaration.body.is_some()),
                    (RustDeclarationKind::InlineModule, true)
                        | (RustDeclarationKind::ExternalModule, false)
                ),
                "canonical module body and declaration kind agree"
            );
        }

        let mut invocation_names = HashMap::default();
        for invocation in &self.invocations {
            assert!(
                invocation_names
                    .insert(invocation.occurrence, invocation.name.as_str())
                    .is_none(),
                "one canonical macro invocation row per occurrence"
            );
        }

        let mut scope_names = Vec::with_capacity(self.scopes.len());
        let mut scopes = Vec::with_capacity(self.scopes.len());
        for (index, source_scope) in self.scopes.iter().enumerate() {
            if index == 0 {
                scope_names.push(String::new());
                scopes.push(RustModuleScopeFact {
                    parent: None,
                    declaration: None,
                    module_name: String::new(),
                    path_attribute: None,
                    visibility: RustVisibility::Private,
                    imports_macros: true,
                    resolution_scope: source_scope.resolution_scope,
                    body_start: root_range.start_byte,
                    body_end: root_range.end_byte,
                });
                continue;
            }
            let parent = source_scope
                .parent
                .expect("non-root Rust module scope has a parent");
            assert!(parent < index, "Rust module scopes are parent-before-child");
            let declaration_id = source_scope
                .declaration
                .expect("non-root Rust module scope has a declaration");
            let declaration = declarations
                .get(&declaration_id)
                .copied()
                .expect("module scope declaration exists");
            let property = declaration_properties
                .get(&declaration_id)
                .copied()
                .expect("module scope property exists");
            let body = declaration
                .body
                .expect("inline module scope has a body occurrence");
            let body_range = occurrences.occurrence(body).range;
            let full_name = if scope_names[parent].is_empty() {
                declaration.name.clone()
            } else {
                format!("{}.{}", scope_names[parent], declaration.name)
            };
            scope_names.push(full_name);
            let imports_macros = scopes[parent].imports_macros && declaration.macro_use;
            scopes.push(RustModuleScopeFact {
                parent: Some(parent),
                declaration: source_scope.declaration,
                module_name: declaration.name.clone(),
                path_attribute: declaration.path_attribute.clone(),
                visibility: property.visibility.clone(),
                imports_macros,
                resolution_scope: source_scope.resolution_scope,
                body_start: body_range.start_byte,
                body_end: body_range.end_byte,
            });
        }

        let mut modules = Vec::with_capacity(self.inventory.len());
        for (index, entry) in self.inventory.iter().enumerate() {
            if index == 0 {
                assert!(entry.declaration.is_none());
                modules.push(RustModuleFact {
                    module_name: String::new(),
                    is_inline: true,
                    start_byte: root_range.start_byte,
                    end_byte: root_range.end_byte,
                    cfg_condition: RustCfgCondition::Always,
                });
                continue;
            }
            let declaration_id = entry
                .declaration
                .expect("non-root Rust module inventory has a declaration");
            assert!(entry.parent_scope < scopes.len());
            let declaration = declarations
                .get(&declaration_id)
                .copied()
                .expect("module inventory declaration exists");
            let property = declaration_properties
                .get(&declaration_id)
                .copied()
                .expect("module inventory property exists");
            let declaration_range = occurrences
                .occurrence(occurrences.declaration(declaration_id).occurrence)
                .range;
            let (is_inline, start_byte, end_byte) = match declaration.body {
                Some(body) => {
                    let range = occurrences.occurrence(body).range;
                    (true, range.start_byte, range.end_byte)
                }
                None => (
                    false,
                    declaration_range.start_byte,
                    declaration_range.end_byte,
                ),
            };
            let parent_name = &scope_names[entry.parent_scope];
            let module_name = if parent_name.is_empty() {
                declaration.name.clone()
            } else {
                format!("{}.{}", parent_name, declaration.name)
            };
            modules.push(RustModuleFact {
                module_name,
                is_inline,
                start_byte,
                end_byte,
                cfg_condition: property.cfg_condition.clone(),
            });
        }

        let mut routes = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            assert!(route.scope < scopes.len(), "Rust module route scope exists");
            let declaration = declarations
                .get(&route.declaration)
                .copied()
                .expect("module route declaration exists");
            assert!(
                declaration.body.is_none(),
                "Rust module route declaration has no body"
            );
            let property = declaration_properties
                .get(&route.declaration)
                .copied()
                .expect("module route property exists");
            let declaration_range = occurrences
                .occurrence(occurrences.declaration(route.declaration).occurrence)
                .range;
            let gates = route
                .gates
                .iter()
                .map(|occurrence| RustMacroGateFact {
                    macro_name: invocation_names
                        .get(occurrence)
                        .copied()
                        .expect("module route gate invocation exists")
                        .to_string(),
                    invocation_start: occurrences.occurrence(*occurrence).range.start_byte,
                })
                .collect();
            routes.push(RustModuleRouteFact {
                scope: route.scope,
                declaration: route.declaration,
                module_name: declaration.name.clone(),
                path_attribute: declaration.path_attribute.clone(),
                visibility: property.visibility.clone(),
                imports_macros: scopes[route.scope].imports_macros && declaration.macro_use,
                test_gated: declaration.test_gated,
                cfg_condition: property.cfg_condition.clone(),
                declaration_start: declaration_range.start_byte,
                declaration_end: declaration_range.end_byte,
                gates,
            });
        }
        (modules, scopes, routes)
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        self.declarations
            .capacity()
            .saturating_mul(std::mem::size_of::<RustModuleDeclarationSourceFact>())
            .saturating_add(
                self.invocations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustMacroInvocationSourceFact>()),
            )
            .saturating_add(
                self.inventory
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustModuleInventorySourceFact>()),
            )
            .saturating_add(
                self.scopes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustModuleScopeSourceFact>()),
            )
            .saturating_add(
                self.routes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustModuleRouteSourceFact>()),
            )
            .saturating_add(self.declarations.iter().fold(0, |total, declaration| {
                total
                    .saturating_add(declaration.name.capacity())
                    .saturating_add(
                        declaration
                            .path_attribute
                            .as_ref()
                            .map_or(0, String::capacity),
                    )
            }))
            .saturating_add(self.invocations.iter().fold(0, |total, invocation| {
                total.saturating_add(invocation.name.capacity())
            }))
            .saturating_add(self.routes.iter().fold(0, |total, route| {
                total.saturating_add(
                    route
                        .gates
                        .capacity()
                        .saturating_mul(std::mem::size_of::<SourceOccurrenceId>()),
                )
            }))
    }
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
    /// Canonical source declaration for this module scope. The file root has
    /// no source declaration and therefore stores `None`.
    pub declaration: Option<SourceDeclarationId>,
    /// The inline module's own name; empty for the file root.
    pub module_name: String,
    /// The decoded `#[path = "..."]` value written on this inline module.
    pub path_attribute: Option<String>,
    /// The effective source visibility on this inline module declaration.
    pub visibility: RustVisibility,
    /// Whether an unbroken `#[macro_use]` chain reaches this scope from the
    /// file root, which is what lets a `mod` item below it import macros into
    /// file scope.
    pub imports_macros: bool,
    /// The common-resolution scope with the same structured body extent.
    /// `None` when the module is outside native resolution admission, including
    /// macro-generated modules and primary route-only local modules.
    pub resolution_scope: Option<ResolutionScopeId>,
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
    /// Canonical source declaration for this external module declaration.
    pub declaration: SourceDeclarationId,
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
    /// Complete simple cfg activation for selected-context construction.
    /// `test_gated` remains as the incumbent route index's narrow fast path.
    pub cfg_condition: RustCfgCondition,
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
    /// The item-position `macro_rules!` definitions captured by the coordinated
    /// primary producer, with source-derived ranges materialized on readback.
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

/// The source-owned lexical context in which a Rust item was written.
///
/// `context` is an occurrence identity rather than a rendered module name.
/// This keeps embedded replay roots attached to the primary invocation that
/// contains them, even when no display `CodeUnit` was admitted for the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustSourceContextKind {
    FileRoot,
    Module,
    Trait,
    Impl,
    Function,
    Block,
    DeclarationBody,
    Type,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSourceContextFact {
    pub context: SourceOccurrenceId,
    pub parent: Option<SourceOccurrenceId>,
    pub owner: Option<SourceDeclarationId>,
    pub kind: RustSourceContextKind,
}

/// Parser-error state for one source syntax occurrence shared by every source
/// fact that observes that exact node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustItemSyntaxFact {
    pub occurrence: SourceOccurrenceId,
    pub has_error: bool,
}

/// A normalized name whose exact source token remains available in the shared
/// occurrence arena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSourceNameFact {
    pub occurrence: SourceOccurrenceId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustGenericParameterSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub kind: String,
    pub name: Option<RustSourceNameFact>,
}

/// The generic binders declared by one source declaration.
///
/// A missing row means that the declaration has no generic binders. An empty
/// or malformed parameter-list node with no named children is not published.
/// Keeping the owner separate from the declaration-specific facts makes the
/// same inventory usable by every declaration family, including type owners
/// and callables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustDeclarationGenericsSourceFact {
    pub declaration: SourceDeclarationId,
    pub parameters: Vec<RustGenericParameterSourceFact>,
}

/// One direct named child of an impl or trait body. Error and macro nodes are
/// retained so absence of a member cannot be mistaken for a complete body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustItemBodyChildSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub declaration: Option<SourceDeclarationId>,
    pub syntax_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustImplSourceFact {
    pub declaration: SourceDeclarationId,
    pub context: SourceOccurrenceId,
    pub trait_type: Option<SourceOccurrenceId>,
    /// Exact `!` token of a negative trait impl. Absence is ordinary positive
    /// syntax, not a query-time decision about implementation applicability.
    pub negation: Option<SourceOccurrenceId>,
    pub target_type: Option<SourceOccurrenceId>,
    pub body: Option<SourceOccurrenceId>,
    pub body_children: Vec<RustItemBodyChildSourceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustTraitSourceFact {
    pub declaration: SourceDeclarationId,
    pub context: SourceOccurrenceId,
    pub body: Option<SourceOccurrenceId>,
    pub body_children: Vec<RustItemBodyChildSourceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustAliasSourceFact {
    pub declaration: SourceDeclarationId,
    pub context: SourceOccurrenceId,
    pub target_type: Option<SourceOccurrenceId>,
}

/// One named Rust value or field declaration and its optional declared type.
///
/// Tuple fields without a source name intentionally do not produce this fact:
/// there is no source declaration identity for the collector to link without
/// fabricating one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustValueSourceFact {
    pub declaration: SourceDeclarationId,
    pub context: SourceOccurrenceId,
    pub declared_type: Option<SourceOccurrenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustCallableParameterSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub syntax_kind: String,
    pub label: Option<RustSourceNameFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustCallableSourceFact {
    pub declaration: SourceDeclarationId,
    pub context: SourceOccurrenceId,
    pub parameters: Option<SourceOccurrenceId>,
    pub parameter_children: Vec<RustCallableParameterSourceFact>,
    pub return_type: Option<SourceOccurrenceId>,
}

/// Why an item macro did not yield a parsed embedded source tree. This is
/// source-capture evidence, not a display or native-admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustMacroParseFailure {
    MissingInterior,
    ParseUnavailable,
}

/// The syntactic position of one Rust macro invocation in its source tree.
/// This is captured from the live AST while the source occurrence is created;
/// it is not reconstructed from a persisted range or declaration name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustItemMacroSourcePosition {
    /// Direct child of a source file or declaration list.
    DirectItem,
    /// Expression statement directly within a source file or declaration list.
    ItemStatement,
    /// Any other raw AST position, including function-local expressions.
    Other,
}

/// The source-tree outcome for one item-macro invocation. `NotRequested`
/// records that replay was not requested for this position. A parsed root's
/// occurrence has parser-error state in [`RustItemSyntaxFact`]; keeping a
/// second error bit here would allow the two sources of truth to drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustItemMacroExpansion {
    NotRequested,
    Parsed(SourceOccurrenceId),
    EmptyInterior,
    Unavailable(RustMacroParseFailure),
}

/// Source-only evidence for every visited macro invocation. The invocation
/// and parsed root can come from different embedded tree source maps, so both
/// are already-interned IDs rather than node handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustItemMacroSourceFact {
    pub invocation: SourceOccurrenceId,
    pub context: SourceOccurrenceId,
    pub position: RustItemMacroSourcePosition,
    pub expansion: RustItemMacroExpansion,
}

/// The nearest source context containing one import declaration. This link is
/// separate from [`RustImportContextFact`], whose owner and scope fields are a
/// primary-tree import projection and do not describe embedded roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustItemImportContextFact {
    pub declaration: SourceOccurrenceId,
    pub context: SourceOccurrenceId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacroFragmentKind {
    Ident,
    Path,
    Expr,
    Ty,
    Pat,
    Stmt,
    Block,
    Item,
    Meta,
    Tt,
    Vis,
    Lifetime,
    Literal,
}

impl MacroFragmentKind {
    pub fn from_specifier(text: &str) -> Option<Self> {
        Some(match text.trim() {
            "ident" => Self::Ident,
            "path" => Self::Path,
            "expr" | "expr_2021" => Self::Expr,
            "ty" => Self::Ty,
            "pat" | "pat_param" => Self::Pat,
            "stmt" => Self::Stmt,
            "block" => Self::Block,
            "item" => Self::Item,
            "meta" => Self::Meta,
            "tt" => Self::Tt,
            "vis" => Self::Vis,
            "lifetime" => Self::Lifetime,
            "literal" => Self::Literal,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ident => "ident",
            Self::Path => "path",
            Self::Expr => "expr",
            Self::Ty => "ty",
            Self::Pat => "pat",
            Self::Stmt => "stmt",
            Self::Block => "block",
            Self::Item => "item",
            Self::Meta => "meta",
            Self::Tt => "tt",
            Self::Vis => "vis",
            Self::Lifetime => "lifetime",
            Self::Literal => "literal",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacroIdentRole {
    Type,
    Value,
    Pattern,
    Declaration,
    Mixed,
    Unused,
    Undetermined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustMacroDelimiter {
    Parenthesis,
    Bracket,
    Brace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustMacroRepetitionOperator {
    Star,
    Plus,
    Optional,
}

/// One source pattern node. Its containing vector gives parent-before-child
/// order; parent links and occurrences remain local to the same arm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustMacroPatternSourceFact {
    pub occurrence: SourceOccurrenceId,
    pub parent: Option<SourceOccurrenceId>,
    pub kind: RustMacroPatternSourceKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustMacroPatternSourceKind {
    Literal {
        syntax_kind: String,
        text: String,
    },
    Binding {
        name: String,
        fragment: MacroFragmentKind,
    },
    Group {
        delimiter: Option<RustMacroDelimiter>,
    },
    Repetition {
        separator: Option<String>,
        operator: RustMacroRepetitionOperator,
    },
    /// Malformed binding or repetition syntax that cannot match an invocation.
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustMacroIdentRoleSourceFact {
    pub name: String,
    pub role: MacroIdentRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustMacroArmSourceFact {
    pub occurrence: SourceOccurrenceId,
    /// Missing matcher syntax differs from a present matcher with no children.
    pub pattern: Option<SourceOccurrenceId>,
    pub patterns: Vec<RustMacroPatternSourceFact>,
    pub ident_roles: Vec<RustMacroIdentRoleSourceFact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustMacroDefinitionSourceFact {
    pub declaration: SourceDeclarationId,
    /// The enclosing context; macro definitions do not own a context.
    pub context: SourceOccurrenceId,
    pub is_macro_rules: bool,
    pub arms: Vec<RustMacroArmSourceFact>,
}

impl RustMacroDefinitionSourceFact {
    pub fn estimated_retained_bytes(&self) -> usize {
        self.arms
            .capacity()
            .saturating_mul(std::mem::size_of::<RustMacroArmSourceFact>())
            .saturating_add(
                self.arms
                    .iter()
                    .map(|arm| {
                        arm.patterns
                            .capacity()
                            .saturating_mul(std::mem::size_of::<RustMacroPatternSourceFact>())
                            .saturating_add(
                                arm.ident_roles
                                    .capacity()
                                    .saturating_mul(std::mem::size_of::<
                                        RustMacroIdentRoleSourceFact,
                                    >()),
                            )
                            .saturating_add(
                                arm.ident_roles
                                    .iter()
                                    .map(|role| role.name.capacity())
                                    .fold(0usize, usize::saturating_add),
                            )
                            .saturating_add(
                                arm.patterns
                                    .iter()
                                    .map(|pattern| match &pattern.kind {
                                        RustMacroPatternSourceKind::Literal {
                                            syntax_kind,
                                            text,
                                        } => syntax_kind.capacity().saturating_add(text.capacity()),
                                        RustMacroPatternSourceKind::Binding { name, .. } => {
                                            name.capacity()
                                        }
                                        RustMacroPatternSourceKind::Repetition {
                                            separator,
                                            ..
                                        } => separator.as_ref().map_or(0, String::capacity),
                                        RustMacroPatternSourceKind::Group { .. }
                                        | RustMacroPatternSourceKind::Invalid => 0,
                                    })
                                    .fold(0usize, usize::saturating_add),
                            )
                    })
                    .fold(0usize, usize::saturating_add),
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustMacroInvocationInputSourceFact {
    pub invocation: SourceOccurrenceId,
    /// The exact native frontier withheld for this invocation, when present.
    /// Selected replay may close this frontier only after admitting its facts.
    pub native_frontier: Option<(
        crate::analyzer::resolution_facts::ResolutionSiteId,
        ResolutionScopeId,
    )>,
    /// Canonical occurrence for each token, in token preorder.
    pub occurrences: Vec<SourceOccurrenceId>,
    pub tree: RustMacroTokenTree,
}

/// An immutable AST snapshot of invocation input. Byte ranges stay in the
/// original source; the one retained text slice begins at `start_byte`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustMacroTokenTree {
    pub start_byte: usize,
    pub source: String,
    pub tokens: Vec<RustMacroInputToken>,
}

impl RustMacroTokenTree {
    /// The source text of one of this tree's tokens.
    pub fn token_text(&self, token: &RustMacroInputToken) -> &str {
        &self.source[token.start_byte - self.start_byte..token.end_byte - self.start_byte]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustMacroInputToken {
    pub parent: Option<u32>,
    pub syntax_kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Source-owned Rust item structure. These rows are collected before display
/// and native admission; their absence or errors are therefore meaningful to
/// later consumers rather than silently reflecting a projection's choices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RustItemSourceFacts {
    pub contexts: Vec<RustSourceContextFact>,
    pub syntax: Vec<RustItemSyntaxFact>,
    pub generics: Vec<RustDeclarationGenericsSourceFact>,
    pub impls: Vec<RustImplSourceFact>,
    pub traits: Vec<RustTraitSourceFact>,
    pub aliases: Vec<RustAliasSourceFact>,
    pub values: Vec<RustValueSourceFact>,
    pub callables: Vec<RustCallableSourceFact>,
    pub macros: Vec<RustItemMacroSourceFact>,
    pub macro_definitions: Vec<RustMacroDefinitionSourceFact>,
    pub macro_inputs: Vec<RustMacroInvocationInputSourceFact>,
    pub import_contexts: Vec<RustItemImportContextFact>,
}

impl RustItemSourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        let macro_inputs = self
            .macro_inputs
            .capacity()
            .saturating_mul(std::mem::size_of::<RustMacroInvocationInputSourceFact>())
            .saturating_add(
                self.macro_inputs
                    .iter()
                    .map(|input| {
                        input
                            .tree
                            .source
                            .capacity()
                            .saturating_add(
                                input
                                    .occurrences
                                    .capacity()
                                    .saturating_mul(std::mem::size_of::<SourceOccurrenceId>()),
                            )
                            .saturating_add(
                                input
                                    .tree
                                    .tokens
                                    .capacity()
                                    .saturating_mul(std::mem::size_of::<RustMacroInputToken>()),
                            )
                            .saturating_add(
                                input
                                    .tree
                                    .tokens
                                    .iter()
                                    .map(|token| token.syntax_kind.capacity())
                                    .fold(0usize, usize::saturating_add),
                            )
                    })
                    .fold(0usize, usize::saturating_add),
            );
        self.contexts
            .capacity()
            .saturating_mul(std::mem::size_of::<RustSourceContextFact>())
            .saturating_add(macro_inputs)
            .saturating_add(
                self.macro_definitions
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustMacroDefinitionSourceFact>()),
            )
            .saturating_add(
                self.macro_definitions
                    .iter()
                    .map(RustMacroDefinitionSourceFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.syntax
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustItemSyntaxFact>()),
            )
            .saturating_add(
                self.generics
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustDeclarationGenericsSourceFact>()),
            )
            .saturating_add(
                self.impls
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustImplSourceFact>()),
            )
            .saturating_add(
                self.traits
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustTraitSourceFact>()),
            )
            .saturating_add(
                self.aliases
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustAliasSourceFact>()),
            )
            .saturating_add(
                self.values
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustValueSourceFact>()),
            )
            .saturating_add(
                self.callables
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustCallableSourceFact>()),
            )
            .saturating_add(
                self.macros
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustItemMacroSourceFact>()),
            )
            .saturating_add(
                self.import_contexts
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustItemImportContextFact>()),
            )
            .saturating_add(
                self.impls
                    .iter()
                    .map(RustImplSourceFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.traits
                    .iter()
                    .map(RustTraitSourceFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.callables
                    .iter()
                    .map(RustCallableSourceFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.generics
                    .iter()
                    .map(RustDeclarationGenericsSourceFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
    }
}

impl RustDeclarationGenericsSourceFact {
    fn estimated_retained_bytes(&self) -> usize {
        self.parameters
            .capacity()
            .saturating_mul(std::mem::size_of::<RustGenericParameterSourceFact>())
            .saturating_add(estimated_generic_parameters(&self.parameters))
    }
}

impl RustImplSourceFact {
    fn estimated_retained_bytes(&self) -> usize {
        estimated_body_children(&self.body_children).saturating_add(
            self.body_children
                .capacity()
                .saturating_mul(std::mem::size_of::<RustItemBodyChildSourceFact>()),
        )
    }
}

impl RustTraitSourceFact {
    fn estimated_retained_bytes(&self) -> usize {
        estimated_body_children(&self.body_children).saturating_add(
            self.body_children
                .capacity()
                .saturating_mul(std::mem::size_of::<RustItemBodyChildSourceFact>()),
        )
    }
}

impl RustCallableSourceFact {
    fn estimated_retained_bytes(&self) -> usize {
        self.parameter_children
            .capacity()
            .saturating_mul(std::mem::size_of::<RustCallableParameterSourceFact>())
            .saturating_add(
                self.parameter_children
                    .iter()
                    .map(|parameter| {
                        parameter.syntax_kind.capacity().saturating_add(
                            parameter
                                .label
                                .as_ref()
                                .map_or(0, |label| label.name.capacity()),
                        )
                    })
                    .fold(0usize, usize::saturating_add),
            )
    }
}

fn estimated_generic_parameters(parameters: &[RustGenericParameterSourceFact]) -> usize {
    parameters
        .iter()
        .map(|parameter| {
            parameter.kind.capacity().saturating_add(
                parameter
                    .name
                    .as_ref()
                    .map_or(0, |name| name.name.capacity()),
            )
        })
        .fold(0usize, usize::saturating_add)
}

fn estimated_body_children(children: &[RustItemBodyChildSourceFact]) -> usize {
    children
        .iter()
        .map(|child| child.syntax_kind.capacity())
        .fold(0usize, usize::saturating_add)
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
