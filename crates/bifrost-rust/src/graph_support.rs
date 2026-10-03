use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeAliasProvider, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_MACRO;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustDeclarationBoundary, RustDeclarationKind, RustSourceContextKind,
    RustValueConstructorProperties,
};
use brokk_bifrost_core::analyzer::structural::rewrite_path::{
    ALIAS_SUBSTITUTION_RULE, RewriteOutcome, RewriteStep, RewriteTrace,
};
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind, ReexportStar,
};
use brokk_bifrost_core::analyzer::{CodeUnit, Language, ProjectFile, Range};
use brokk_bifrost_core::analyzer::{CodeUnitIndex, default_parent_fq_name};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::profiling;
use std::cell::{OnceCell, RefCell};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

use crate::cargo_routes::{RustCargoRouteIndex, RustCargoTargetRelation};
use crate::crate_naming;
use crate::declarations::{rust_node_text, rust_package_name};
use crate::hierarchy::{
    RustHierarchySourceFacts, resolve_rust_hierarchy_source_ref, source_type_identifier,
};
use crate::hierarchy_source_context::RustSourceContextIndex;
use crate::imports::{
    RustVisibility, resolve_rust_module_path_with_crate, resolve_rust_module_segments_with_crate,
    rust_crate_root_package, rust_item_has_attribute, rust_target_kind_root_alternative,
};
use crate::usage::{
    RustReferenceNamespace, exported_targets_from_files, exported_targets_from_files_while,
};
use crate::usage_queries::{RustDeclarationFacts, RustUsageQueries};
use crate::usage_walks::RustWalkCaches;
use brokk_bifrost_core::analyzer::rust_facts::{RustDeclarationPropertyFact, RustUsageFacts};
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::analyzer::usages::common::same_node;

/// Whether this node is the name token of a Rust declaration head.
///
/// Moved here with the R6.5 legacy deletion: the reference-candidate
/// classifier is its only caller now that the legacy Rust usage graph is gone.
pub fn is_rust_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "function_item"
            | "struct_item"
            | "enum_item"
            | "trait_item"
            | "type_item"
            | "const_item"
            | "static_item"
            | "mod_item"
            | "field_declaration"
            | "enum_variant"
            | "function_signature_item"
    ) && parent.child_by_field_name("name") == Some(node)
}

/// Which Rust namespace a reference token names.
///
/// A macro path names the macro namespace whatever the token's own kind is; a
/// type identifier in call position names a value (a tuple-struct or variant
/// constructor); the qualifier of a scoped identifier names a path prefix.
pub fn rust_reference_namespace(node: Node<'_>) -> RustReferenceNamespace {
    let mut ancestor = Some(node);
    while let Some(current) = ancestor {
        if current.kind() == "macro_invocation"
            && current
                .child_by_field_name("macro")
                .is_some_and(|macro_path| {
                    macro_path.start_byte() <= node.start_byte()
                        && node.end_byte() <= macro_path.end_byte()
                })
        {
            return RustReferenceNamespace::Macro;
        }
        ancestor = current.parent();
    }

    if node.kind() == "type_identifier" && rust_type_identifier_is_call_target(node) {
        return RustReferenceNamespace::Value;
    }
    if matches!(node.kind(), "type_identifier" | "scoped_type_identifier") {
        return RustReferenceNamespace::Type;
    }
    if let Some(parent) = node.parent() {
        if parent.kind() == "scoped_type_identifier" {
            return RustReferenceNamespace::Type;
        }
        if parent.kind() == "scoped_identifier"
            && parent
                .child_by_field_name("path")
                .is_some_and(|path| same_node(path, node))
        {
            return RustReferenceNamespace::PathPrefix;
        }
    }
    RustReferenceNamespace::Value
}

fn rust_type_identifier_is_call_target(node: Node<'_>) -> bool {
    let mut expression = node;
    while let Some(parent) = expression.parent()
        && matches!(parent.kind(), "generic_function" | "generic_type")
    {
        expression = parent;
    }
    expression.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == expression.id())
    })
}

/// The identifier nodes of a Rust path, outermost qualifier first.
///
/// `None` for a node shape that is not a path: a caller must not fall back to
/// splitting the source text. A leading `::` ends the walk with the segments
/// gathered so far, because the absolute root has no node of its own.
pub fn rust_path_segments(mut node: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut reversed = Vec::new();
    loop {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                reversed.push(node.child_by_field_name("name")?);
                let Some(path) = node.child_by_field_name("path") else {
                    if node.child(0).is_some_and(|child| child.kind() == "::") {
                        break;
                    }
                    return None;
                };
                node = path;
            }
            "generic_type" => node = node.child_by_field_name("type")?,
            "generic_function" => node = node.child_by_field_name("function")?,
            "identifier" | "type_identifier" | "self" | "super" | "crate" => {
                reversed.push(node);
                break;
            }
            _ => return None,
        }
    }
    reversed.reverse();
    Some(reversed)
}

/// Whether the path containing `node` is rooted at a leading `::`.
pub fn rust_path_is_leading_absolute(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent()
        && matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier" | "generic_type" | "generic_function"
        )
    {
        node = parent;
    }
    loop {
        match node.kind() {
            "generic_type" => {
                let Some(inner) = node.child_by_field_name("type") else {
                    return false;
                };
                node = inner;
            }
            "generic_function" => {
                let Some(inner) = node.child_by_field_name("function") else {
                    return false;
                };
                node = inner;
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(path) = node.child_by_field_name("path") {
                    node = path;
                } else {
                    return node.child(0).is_some_and(|child| child.kind() == "::");
                }
            }
            _ => return false,
        }
    }
}

/// Whether `owner` is a trait declared in this workspace.
///
/// A declaration from outside the analyzed sources cannot be shown to be a
/// trait, so an owner the file's own declaration list does not contain answers
/// false rather than consulting a name-shaped guess.
pub fn is_trait_owner(
    rust: &dyn RustSource,
    owner: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    let local = rust
        .declarations(owner.source())
        .into_iter()
        .any(|declaration| &declaration == owner);
    if !local {
        return Ok(false);
    }
    is_rust_trait_declaration(rust, owner)
}

/// Mounted declarations retain every exact source declaration's properties.
/// Repeated declarations sharing a CodeUnit are alternatives, not one row.
pub type RustDeclarationSourceProperties = HashMap<CodeUnit, Vec<RustDeclarationPropertyFact>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustCargoRouteError {
    Unavailable,
    Cancelled,
}

/// The bounded indexes Rust's language logic resolves through, plus the core
/// capability traits it reads declarations with. The analyzer implements this
/// by forwarding to its own accessors; every free
/// function in this module and its siblings sees only this surface, so none of
/// them can reach back into the analyzer type.
///
/// The persisted usage facts are deliberately absent: the Cargo route
/// composition and the declaration walk take this trait, so neither can reach
/// the rows whose extraction they precede. Code that answers a usage question
/// takes [`RustFactSource`].
pub trait RustSource:
    CodeUnitIndex + ImportAnalysisProvider + TypeAliasProvider + TypeHierarchyProvider
{
    /// The same index this trait already extends, for handing to the free
    /// functions whose whole input is a declaration store.
    fn code_units(&self) -> &dyn CodeUnitIndex;

    /// The declaration's syntactic owner, which unlike
    /// [`CodeUnitIndex::parent_of`] never falls back to a definition-row lookup.
    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit>;

    /// Exact declaration candidates before display-oriented module deduplication.
    /// Cargo targets may share a module name and must be disambiguated afterward.
    fn declaration_candidates_by_fqn_while(
        &self,
        fq_name: &str,
        keep_going: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<Vec<CodeUnit>>;

    /// Route-free canonical source properties, with no syntax reconstruction.
    fn declaration_source_properties(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustDeclarationSourceProperties>, RustCargoRouteError>;

    /// Direct hierarchy edges from the canonical Rust hierarchy index. The
    /// index is a fallible published product: an unavailable Cargo route must
    /// not be represented as an empty ancestor set.
    fn direct_ancestors(&self, code_unit: &CodeUnit) -> Result<Vec<CodeUnit>, RustCargoRouteError>;

    /// The parsed tree and its source backing for `file`.
    ///
    /// The [`QueryToken`] is proof that a request scope is open, so the cache
    /// this reads is live (issue #2414 step 3).
    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<PreparedSyntaxTree>>;

    fn cargo_routes(&self) -> Result<Arc<RustCargoRouteIndex>, RustCargoRouteError>;

    /// [`Self::cargo_routes`], abandoning a cold build when `keep_going` stops
    /// permitting it. The usage-index build pays for this index on the same
    /// request thread, so a cancelled request must not be stuck behind it.
    /// `dyn` rather than a generic so the trait stays object-safe.
    fn cargo_routes_while(
        &self,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustCargoRouteIndex>, RustCargoRouteError>;

    fn package_file_index(&self) -> Arc<RustPackageFileIndex>;

    fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder;

    fn export_index_of(&self, file: &ProjectFile) -> ReferenceContextResult<Arc<ExportIndex>>;

    /// Progress-aware export-index lookup for bounded reference walks. The
    /// implementation must pass the predicate through any lazy parent/Cargo
    /// resolution instead of loading an unbounded route index first.
    fn export_index_of_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<Arc<ExportIndex>>;

    fn note_module_file_resolution(&self);

    /// Narrow instrumentation hook for the streaming reference-resolution
    /// complexity pins. Implementations count one requested export-name walk.
    fn note_export_name_canonicalization(&self);
}

/// The file-to-blob mapping in both directions, as an object-safe view.
///
/// A store-backed Rust answer starts from a blob oid an inverted lookup
/// returned and has to reach the live `ProjectFile`s that currently hold those
/// bytes, and the reverse. The mapping itself is `LiveSnapshot`, which lives in
/// `brokk-bifrost-analysis` and cannot be named here, so the analyzer hands
/// this view down instead.
pub trait RustLiveBlobs: Send + Sync {
    fn oid_for_path(&self, file: &ProjectFile) -> Option<git2::Oid>;
    fn paths_for_oid(&self, oid: git2::Oid) -> Vec<ProjectFile>;
}

/// One declaration as the crate rows place it: the file a crate places it in,
/// the blob that file held when the rows were derived, and the declaration's
/// id in that blob.
///
/// `(blob, declaration)` alone is content-addressed, so two byte-identical
/// files declare the same pair; the file is what tells their declarations
/// apart, as a resolution mount does. `rel_path` is spelled the way
/// `rust_crate_container_sources` spells it, `path_utils::rel_path_string`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustPlacedDeclaration {
    pub rel_path: String,
    pub blob: git2::Oid,
    pub declaration: u32,
}

/// One impl of a trait as a crate row states it: the file the impl is placed
/// in and that file's blob, the impl item's source declaration there, and the
/// placed declaration of its subject. The declaration and the subject are
/// `None` when the derivation could not bridge them; the reader then resolves
/// that impl's header itself.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustTraitImplRow {
    pub impl_blob: git2::Oid,
    pub impl_rel_path: String,
    pub impl_declaration: Option<u32>,
    pub subject: Option<RustPlacedDeclaration>,
}

/// One item-position macro invocation a file writes: its invocation, its
/// unqualified name when it has one, and what crate derivation decided about
/// its expansion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustItemMacroDecision {
    pub invocation: SourceOccurrenceId,
    pub name: Option<String>,
    pub decided: RustItemMacroDecided,
}

/// What the crates that place a file decided about one of its item-position
/// macro invocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustItemMacroDecided {
    /// Some such crate did not decide it, so its expansion is unknown.
    Undecided,
    /// Every such crate decided it a passthrough: the expansion is the
    /// arguments' items and nothing else, each under the definition's `cfg`
    /// decoration. `compiled` is false only when that decoration is inactive
    /// in every such crate.
    Passthrough { compiled: bool },
}

/// One blob whose item macros could expand to an item that names an asked
/// name: it writes the name inside a macro token tree (`via` is `None`), or it
/// writes the name of a macro defined in such a blob (`via` names the macro and
/// its defining blob).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustMacroExpansionBlob {
    pub blob: git2::Oid,
    pub via: Option<(String, git2::Oid)>,
}

/// One impl that named a trait spelling and did not become a relation row:
/// its file, that file's blob, and its source declaration when the derivation
/// could bridge it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustUnresolvedImpl {
    pub impl_blob: git2::Oid,
    pub impl_rel_path: String,
    pub impl_declaration: Option<u32>,
}

/// The live file a placed row names: the file at `rel_path`, provided it
/// still holds `blob`. A file edited since the rows were derived holds another
/// blob, and the row's declaration ids do not describe it, so it names nothing.
pub fn live_file_at(
    rust: &dyn RustFactSource,
    blob: git2::Oid,
    rel_path: &str,
) -> Option<ProjectFile> {
    rust.live_blobs()
        .paths_for_oid(blob)
        .into_iter()
        .find(|file| brokk_bifrost_core::path_utils::rel_path_string(file) == rel_path)
}

/// [`RustSource`] plus the persisted per-file Rust usage facts, the bounded
/// caches the cross-file walks memoize into, and the facts query-scoped
/// reference contexts resolve lazily.
///
/// Everything here is something only the analyzer can answer: the store handle
/// behind the four inverted lookups, the live blob mapping, the caches it owns,
/// the catch-up that guarantees the rows exist before a walk reads them. Code
/// that runs before any of that
/// exists -- the Cargo route composition, the declaration walk -- takes
/// [`RustSource`] instead, so it cannot re-enter what it is filling.
pub trait RustFactSource: RustSource {
    /// One published blob's persisted facts.
    ///
    /// A known blob with no fact rows is unavailable, not a successful
    /// no-facts answer: the Rust producer always writes the file-root module
    /// witness. Explicit warming may repair that state before a retry.
    fn rust_usage_facts_of_blob(
        &self,
        oid: git2::Oid,
    ) -> Result<Arc<RustUsageFacts>, RustCargoRouteError>;

    /// Blobs that import `module_path`, spelled exactly as written. Candidates,
    /// never answers -- see `usage_queries.rs` for the contract. An empty
    /// successful result means no candidates; a failed indexed read is
    /// unavailable.
    fn rust_import_target_blobs(
        &self,
        module_path: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError>;

    /// Blobs whose structured imports name `component` as an imported module
    /// or as the last component of the module path. Candidates, never answers;
    /// an empty successful result is distinct from an unavailable read.
    fn rust_module_import_candidate_blobs(
        &self,
        component: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError>;

    /// Blobs that re-export `exported_name`. An empty successful result is
    /// distinct from an unavailable read.
    fn rust_export_blobs(&self, exported_name: &str)
    -> Result<Vec<git2::Oid>, RustCargoRouteError>;

    /// The traits one placed type declaration implements, as placed
    /// declarations. Crate derivation bound both ends of every reachable
    /// `impl Trait for Type`, so this is an index seek rather than a walk of
    /// the workspace's impls.
    fn rust_traits_implemented_by(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError>;

    /// The types that implement one placed trait declaration. The reverse
    /// direction of [`RustFactSource::rust_traits_implemented_by`].
    fn rust_types_implementing(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError>;

    /// Every impl of one placed trait declaration as the crate rows state it.
    ///
    /// The bound on every member-level walk across a trait: without it the walk
    /// reads every analyzed file to find the handful that implement the trait,
    /// and resolves every impl header in them to find which are this trait's.
    fn rust_trait_impl_rows(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustTraitImplRow>, RustCargoRouteError>;

    /// The placed traits the crate rows say one placed impl item states: the
    /// impl's blob, its file, and its source declaration there.
    fn rust_traits_of_impl(
        &self,
        impl_item: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError>;

    /// Every item-position macro invocation one live file writes, with what
    /// crate derivation decided about it.
    fn rust_item_macro_decisions(
        &self,
        file: &ProjectFile,
    ) -> Result<Vec<RustItemMacroDecision>, RustCargoRouteError>;

    /// The blobs whose item macros could expand to an item that names one of
    /// `names`: each writes a name inside a macro token tree, or writes the
    /// name of a macro defined in such a blob. File granularity; see
    /// [`RustMacroExpansionBlob`].
    fn rust_macro_expansion_blobs(
        &self,
        names: &[String],
    ) -> Result<Vec<RustMacroExpansionBlob>, RustCargoRouteError>;

    /// The names the impl rows of one placed trait declaration spelled it
    /// with: its identifier, and any name an import or re-export renamed it
    /// to. A header spelled any other way cannot name the trait.
    fn rust_trait_impl_spellings(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<String>, RustCargoRouteError>;

    /// Blobs that both declare a Rust type alias and mention `identifier`.
    ///
    /// The candidate set for "which alias denotes this type", which the
    /// ancestor direction needs because the trait-implementation rows name
    /// whichever spelling the `impl` wrote.
    fn rust_alias_blobs_mentioning(
        &self,
        identifier: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError>;

    /// The placed files holding `impl`s that named this trait spelling and did
    /// not become a trait-implementation row, as `(blob, rel_path)`.
    ///
    /// An impl whose trait reference never bound has no declaration to be
    /// sought by, so the relation cannot point at it, yet it still decides
    /// whether that trait's implementations are exhaustively known. This is how
    /// a reader is told where those impls are, so that it can judge them with
    /// the same resolver the rest of the walk uses rather than refusing the
    /// question on the strength of a spelling.
    fn rust_unresolved_trait_impl_files(
        &self,
        spelling: &str,
    ) -> Result<Vec<RustUnresolvedImpl>, RustCargoRouteError>;

    /// Blobs whose text mentions `identifier`, with the occurrence-context
    /// bitmask each one carries. An empty successful result is distinct from
    /// an unavailable read.
    fn rust_identifier_occurrence_blobs(
        &self,
        identifier: &str,
    ) -> Result<Vec<(git2::Oid, u32)>, RustCargoRouteError>;

    /// Blobs with an `include!` whose literal's last path component is
    /// `file_name`. The inverted direction of `rust_include_edges`, and the
    /// seed of an include-route walk. An empty successful result is distinct
    /// from an unavailable read.
    fn rust_include_blobs(&self, file_name: &str) -> Result<Vec<git2::Oid>, RustCargoRouteError>;

    /// Every blob that writes at least one `include!`. Bounded by the number of
    /// files that use the macro, not by the workspace. An empty successful
    /// result is distinct from an unavailable read.
    fn rust_include_host_blobs(&self) -> Result<Vec<git2::Oid>, RustCargoRouteError>;

    /// One file's declaration identities and their visibility domains, derived
    /// once per file and then served from the analyzer's bounded cache.
    fn rust_declaration_facts_of(
        &self,
        file: &ProjectFile,
    ) -> Result<Arc<RustDeclarationFacts>, RustCargoRouteError>;

    /// One mounted file's complete canonical hierarchy input. The source rows
    /// are published facts; the declaration-to-`CodeUnit` bridge is retained
    /// with every link because one source declaration may have alternatives.
    fn canonical_rust_hierarchy_source_facts(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustHierarchySourceFacts>, RustCargoRouteError>;

    fn live_blobs(&self) -> Arc<dyn RustLiveBlobs>;

    fn walk_caches(&self) -> &Arc<RustWalkCaches>;

    fn reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a>;

    fn reference_context_of_with_progress<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        progress: &'a dyn Fn() -> bool,
    ) -> Option<RustReferenceContext<'a>>;

    fn forward_reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a>;

    fn forward_reference_context_of_with_progress<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        progress: &'a dyn Fn() -> bool,
    ) -> Option<RustReferenceContext<'a>>;
}

/// Read the canonical import binder for the mounted file root.
///
/// Target-file import walks need the module-level binder, not a binder guessed
/// from a source byte offset. The primary parentless `FileRoot` is the
/// canonical anchor; embedded roots are intentionally excluded.
pub fn canonical_rust_file_import_binder(
    rust: &dyn RustFactSource,
    file: &ProjectFile,
    keep_going: &dyn Fn() -> bool,
) -> Result<ImportBinder, RustCargoRouteError> {
    let facts = rust.canonical_rust_hierarchy_source_facts(file, keep_going)?;
    let mut root = None;
    for context in &facts.items.contexts {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        if context.kind == RustSourceContextKind::FileRoot && context.parent.is_none() {
            assert!(
                root.replace(context.context).is_none(),
                "published Rust source facts have one primary file root"
            );
        }
    }
    let root = root.expect("published Rust source facts have one primary file root");
    let contexts = RustSourceContextIndex::new(facts.as_ref(), keep_going)?;
    let binder = contexts.visible_import_binder(facts.as_ref(), root, keep_going)?;
    if !keep_going() {
        return Err(RustCargoRouteError::Cancelled);
    }
    Ok(binder)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceContextError {
    Interrupted,
    CargoRoutes(RustCargoRouteError),
}

impl From<RustCargoRouteError> for ReferenceContextError {
    fn from(error: RustCargoRouteError) -> Self {
        Self::CargoRoutes(error)
    }
}

impl From<ReferenceContextError> for RustCargoRouteError {
    fn from(error: ReferenceContextError) -> Self {
        match error {
            ReferenceContextError::Interrupted => Self::Cancelled,
            ReferenceContextError::CargoRoutes(error) => error,
        }
    }
}

pub type ReferenceContextResult<T> = Result<T, ReferenceContextError>;

pub fn reference_context_checkpoint(progress: &dyn Fn() -> bool) -> ReferenceContextResult<()> {
    progress()
        .then_some(())
        .ok_or(ReferenceContextError::Interrupted)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RustReferenceQuery {
    Bare(String),
    ScopedOwner(String),
}

/// Query-scoped reference resolution for Rust. Construction is deliberately
/// near-free; imports, declarations, and export closures are read only for the
/// names a caller actually asks about.
///
/// Rust node fqns are file-independent dotted module paths (`util.format_value`),
/// so a resolved value *is* the graph node key — projecting to the node fqn is the
/// identity. (For JS/TS, where fqns are bare, the resolved value must carry the
/// file; see the execplan's "Identity model".)
pub struct RustReferenceContext<'a> {
    rust: &'a dyn RustFactSource,
    /// Proof that the request scope this context serves is open. The context
    /// is per-query and per-file, so it carries the proof for the syntax reads
    /// its resolutions make (issue #2414 step 3).
    token: QueryToken<'a>,
    file: ProjectFile,
    forward: bool,
    keep_going: Box<dyn Fn() -> bool + 'a>,
    package: String,
    crate_package: String,
    binder: OnceCell<ImportBinder>,
    same_file: OnceCell<HashMap<String, String>>,
    memo: RefCell<HashMap<RustReferenceQuery, Option<String>>>,
}

impl std::fmt::Debug for RustReferenceContext<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustReferenceContext")
            .field("file", &self.file)
            .field("forward", &self.forward)
            .field("package", &self.package)
            .field("crate_package", &self.crate_package)
            .field("memo", &self.memo)
            .finish_non_exhaustive()
    }
}

impl<'a> RustReferenceContext<'a> {
    pub fn new(
        rust: &'a dyn RustFactSource,
        token: QueryToken<'a>,
        file: &ProjectFile,
        forward: bool,
        keep_going: Box<dyn Fn() -> bool + 'a>,
    ) -> Self {
        Self {
            rust,
            token,
            file: file.clone(),
            forward,
            keep_going,
            package: rust_package_name(file),
            crate_package: rust_crate_root_package(file),
            binder: OnceCell::new(),
            same_file: OnceCell::new(),
            memo: RefCell::new(HashMap::default()),
        }
    }

    /// The request-scope proof this context was built with (issue #2414 step 3).
    pub fn token(&self) -> QueryToken<'a> {
        self.token
    }

    fn resolve_module_package(
        &self,
        module_specifier: &str,
    ) -> ReferenceContextResult<Option<String>> {
        resolve_module_package_while(
            self.rust,
            self.token,
            &self.file,
            module_specifier,
            &*self.keep_going,
        )
    }

    fn resolve_module_files(
        &self,
        module_specifier: &str,
    ) -> ReferenceContextResult<Vec<ProjectFile>> {
        resolve_module_files_while(
            self.rust,
            self.token,
            &self.file,
            module_specifier,
            &*self.keep_going,
        )
    }

    fn binder(&self) -> &ImportBinder {
        self.binder
            .get_or_init(|| self.rust.import_binder_of(&self.file))
    }

    fn same_file(&self) -> &HashMap<String, String> {
        self.same_file.get_or_init(|| {
            self.rust
                .declarations(&self.file)
                .into_iter()
                .map(|unit| (unit.identifier().to_string(), unit.fq_name()))
                .collect()
        })
    }

    /// The callee fqn a bare `name` refers to: a named import, a same-file item,
    /// or a free function imported via `use path::func;` (the binder classifies
    /// the latter as a namespace whose resolved value is the function's own fqn).
    pub fn resolve_bare(&self, name: &str) -> ReferenceContextResult<Option<String>> {
        self.answer(RustReferenceQuery::Bare(name.to_string()))
    }

    pub fn bare_names_resolving_to(
        &self,
        target_fqn: &str,
    ) -> ReferenceContextResult<HashSet<String>> {
        let terminal = target_fqn.rsplit('.').next().unwrap_or(target_fqn);
        let mut candidates = HashSet::from_iter([terminal.to_string()]);
        candidates.extend(
            self.same_file()
                .iter()
                .filter(|(_, fqn)| *fqn == target_fqn)
                .map(|(name, _)| name.clone()),
        );
        candidates.extend(
            self.binder()
                .bindings
                .iter()
                .filter(|(_, binding)| {
                    matches!(binding.kind, ImportKind::Named | ImportKind::Namespace)
                })
                .map(|(local, _)| local.clone()),
        );
        let export_index = self
            .rust
            .export_index_of_while(&self.file, &*self.keep_going)?;
        candidates.extend(
            export_index
                .exports_by_name
                .iter()
                .filter(|(exported, entry)| {
                    exported.as_str() == terminal
                        || matches!(entry, ExportEntry::ReexportedNamed { imported_name, .. } if imported_name == terminal)
                })
                .map(|(exported, _)| exported.clone()),
        );
        let mut result = HashSet::default();
        for name in candidates {
            if self.binds_target(name.as_str(), target_fqn)? {
                result.insert(name);
            }
        }
        Ok(result)
    }

    /// The callee fqn a `path::name` refers to: a module function via a namespace
    /// import, or an associated function on an imported / same-file type.
    pub fn resolve_scoped(&self, path: &str, name: &str) -> ReferenceContextResult<Option<String>> {
        self.resolve_scoped_owner(path)
            .map(|owner| owner.map(|owner| join_rust_fqn(&owner, name)))
    }

    /// The owner fqn a scoped `path::name` begins from: a namespace import, a
    /// rooted module path, or an imported / same-file type.
    pub fn resolve_scoped_owner(&self, path: &str) -> ReferenceContextResult<Option<String>> {
        self.answer(RustReferenceQuery::ScopedOwner(path.to_string()))
    }

    fn answer(&self, query: RustReferenceQuery) -> ReferenceContextResult<Option<String>> {
        if let Some(cached) = self.memo.borrow().get(&query) {
            return Ok(cached.clone());
        }
        let answer = match &query {
            RustReferenceQuery::Bare(name) => self.compute_bare(name),
            RustReferenceQuery::ScopedOwner(path) => self.compute_scoped_owner(path),
        };
        if let Ok(value) = &answer {
            self.memo.borrow_mut().insert(query, value.clone());
        }
        answer
    }

    fn compute_bare(&self, name: &str) -> ReferenceContextResult<Option<String>> {
        reference_context_checkpoint(&*self.keep_going)?;
        if let Some(value) = self.named_binding(name)? {
            return Ok(Some(value));
        }
        if let Some(value) = self.namespace_binding(name)? {
            return Ok(Some(value));
        }
        if let Some(value) = self.same_file().get(name).cloned() {
            return Ok(Some(value));
        }
        self.glob_binding(name)
    }

    fn compute_scoped_owner(&self, path: &str) -> ReferenceContextResult<Option<String>> {
        reference_context_checkpoint(&*self.keep_going)?;
        if let Some(canonical) = self.scoped_binding(path)? {
            return Ok(Some(canonical));
        }
        if let Some((module_path, item_name)) = path.rsplit_once("::")
            && let Some(package) = self.resolve_scoped_owner(module_path)?
        {
            let resolved = join_rust_fqn(&package, item_name);
            // Direct Cargo test/bench/example targets own a private `crate::`
            // root, while `mod common;` can be physically shared at the target
            // kind root. Apply that fallback only to a rooted module prefix
            // with no private backing. Item paths continue through the normal
            // recursive owner/reexport tiers instead of being mistaken for a
            // complete module package.
            if is_rooted_rust_module_path(path)
                && let Some(shared) = resolve_target_kind_root_module_with_progress(
                    self.rust,
                    &self.file,
                    &resolved,
                    Some(&*self.keep_going),
                )?
            {
                return Ok(Some(shared));
            }
            return Ok(Some(resolved));
        }
        if let Some(package) = self.namespace_binding(path)? {
            return Ok(Some(package));
        }
        if is_rooted_rust_module_path(path)
            && let Some(package) =
                resolve_rust_module_path_with_crate(&self.package, &self.crate_package, path)
        {
            return Ok(Some(package));
        }
        let named = self.named_binding(path)?;
        if named.is_some() {
            return Ok(named);
        }
        if let Some(value) = self.same_file().get(path).cloned() {
            return Ok(Some(value));
        }
        self.glob_binding(path)
    }

    fn binds_target(&self, name: &str, target_fqn: &str) -> ReferenceContextResult<bool> {
        Ok(self.named_binding(name)?.as_deref() == Some(target_fqn)
            || self.namespace_binding(name)?.as_deref() == Some(target_fqn)
            || self.same_file().get(name).map(String::as_str) == Some(target_fqn)
            || self.glob_binding(name)?.as_deref() == Some(target_fqn))
    }

    fn named_binding(&self, name: &str) -> ReferenceContextResult<Option<String>> {
        if let Some(binding) = self.binder().bindings.get(name)
            && binding.kind == ImportKind::Named
            && let Some(imported) = binding.imported_name.as_deref()
        {
            let module_files = self.resolve_module_files(&binding.module_specifier)?;
            let mut resolved = self.canonical_export_fqn(&module_files, imported)?;
            if resolved.is_none() {
                resolved = resolve_exported_module_item_fqn(
                    self.rust,
                    self.token,
                    &self.file,
                    &binding.module_specifier,
                    imported,
                    Some(&*self.keep_going),
                )?;
            }
            if resolved.is_some() {
                return Ok(resolved);
            }
            if let Some(package) = self.resolve_module_package(&binding.module_specifier)? {
                return Ok(Some(join_rust_fqn(&package, imported)));
            }
        }
        self.reexported_binding(name)
    }

    fn namespace_binding(&self, name: &str) -> ReferenceContextResult<Option<String>> {
        let Some(binding) = self.binder().bindings.get(name) else {
            return Ok(None);
        };
        if binding.kind != ImportKind::Namespace {
            return Ok(None);
        }
        let segments = parse_symbol_path(Language::Rust, &binding.module_specifier);
        if segments.len() > 1 {
            let parent = segments[..segments.len() - 1].join("::");
            let terminal = segments.last().expect("non-empty parsed Rust path");
            if let Some(fqn) = resolve_exported_module_item_fqn(
                self.rust,
                self.token,
                &self.file,
                &parent,
                terminal,
                Some(&*self.keep_going),
            )? {
                return Ok(Some(fqn));
            }
        }
        if let Some(package) = resolve_exported_module_package(
            self.rust,
            self.token,
            &self.file,
            &binding.module_specifier,
            Some(&*self.keep_going),
        )? {
            return Ok(Some(package));
        }
        self.resolve_module_package(&binding.module_specifier)
    }

    fn reexported_binding(&self, name: &str) -> ReferenceContextResult<Option<String>> {
        let export_index = self
            .rust
            .export_index_of_while(&self.file, &*self.keep_going)?;
        if let Some(ExportEntry::ReexportedNamed {
            module_specifier,
            imported_name,
        }) = export_index.exports_by_name.get(name)
        {
            let module_files = self.resolve_module_files(module_specifier)?;
            let mut targets = self.exported_targets(&module_files, imported_name)?;
            if targets.is_empty() {
                targets.extend(rust_member_reexport_targets_while(
                    self.rust,
                    self.token,
                    &self.file,
                    module_specifier,
                    imported_name,
                    &*self.keep_going,
                )?);
            }
            if targets.is_empty() {
                targets.extend(self.declaration_targets(&module_files, imported_name)?);
            }
            if let Some(fqn) = single_reexport_target_fqn(targets) {
                return Ok(Some(fqn));
            }
        }
        for star in &export_index.reexport_stars {
            reference_context_checkpoint(&*self.keep_going)?;
            let module_files = self.resolve_module_files(&star.module_specifier)?;
            if !self.export_closure_exports(&module_files, name)? {
                continue;
            }
            let mut targets = self.exported_targets(&module_files, name)?;
            if targets.is_empty() {
                targets.extend(self.declaration_targets(&module_files, name)?);
            }
            if let Some(fqn) = single_reexport_target_fqn(targets) {
                return Ok(Some(fqn));
            }
        }
        Ok(None)
    }

    fn glob_binding(&self, name: &str) -> ReferenceContextResult<Option<String>> {
        let mut candidates = HashSet::default();
        for binding in self.binder().bindings.values() {
            if binding.kind != ImportKind::Glob {
                continue;
            }
            reference_context_checkpoint(&*self.keep_going)?;
            let module_files = self.resolve_module_files(&binding.module_specifier)?;
            if self.export_closure_exports(&module_files, name)?
                && let Some(fqn) = self.canonical_export_fqn(&module_files, name)?
            {
                candidates.insert(fqn);
            }
        }
        Ok((candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten())
    }

    fn scoped_binding(&self, path: &str) -> ReferenceContextResult<Option<String>> {
        let Some((local, name)) = path.split_once("::") else {
            return Ok(None);
        };
        if name.contains("::") {
            return Ok(None);
        }
        let Some(binding) = self.binder().bindings.get(local) else {
            return Ok(None);
        };
        if binding.kind != ImportKind::Namespace {
            return Ok(None);
        }
        let module_files = self.resolve_module_files(&binding.module_specifier)?;
        if !self.export_closure_exports(&module_files, name)? {
            return Ok(None);
        }
        self.canonical_export_fqn(&module_files, name)
    }

    fn canonical_export_fqn(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> ReferenceContextResult<Option<String>> {
        canonical_export_fqn_from_files(
            self.rust,
            self.token,
            module_files,
            name,
            self.forward,
            &*self.keep_going,
        )
    }

    fn exported_targets(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> ReferenceContextResult<BTreeSet<(ProjectFile, String)>> {
        reference_context_checkpoint(&*self.keep_going)?;
        if self.forward {
            forward_exported_targets_from_files_with_progress(
                self.rust,
                self.token,
                module_files,
                name,
                &*self.keep_going,
            )
        } else {
            exported_targets_from_files_while(
                self.rust,
                self.token,
                module_files,
                name,
                &*self.keep_going,
            )
            .map_err(Into::into)
        }
    }

    fn declaration_targets(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> ReferenceContextResult<Vec<(ProjectFile, String)>> {
        rust_declaration_targets_in_files_with_progress(
            self.rust.code_units(),
            module_files,
            name,
            &*self.keep_going,
        )
    }

    fn export_closure_exports(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> ReferenceContextResult<bool> {
        let mut visited = HashSet::default();
        let mut pending = module_files.to_vec();
        while let Some(file) = pending.pop() {
            reference_context_checkpoint(&*self.keep_going)?;
            if !visited.insert(file.clone()) {
                continue;
            }
            let index = self.rust.export_index_of_while(&file, &*self.keep_going)?;
            if index.exports_by_name.contains_key(name) {
                return Ok(true);
            }
            for star in &index.reexport_stars {
                pending.extend(resolve_module_files_with_progress(
                    self.rust,
                    self.token,
                    &file,
                    &star.module_specifier,
                    Some(&*self.keep_going),
                )?);
            }
        }
        Ok(false)
    }
}

pub fn reference_context_of<'a>(
    rust: &'a dyn RustFactSource,
    token: QueryToken<'a>,
    file: &ProjectFile,
) -> RustReferenceContext<'a> {
    RustReferenceContext::new(rust, token, file, false, Box::new(|| true))
}

pub fn reference_context_of_while<'a>(
    rust: &'a dyn RustFactSource,
    token: QueryToken<'a>,
    file: &ProjectFile,
    keep_going: impl Fn() -> bool + 'a,
) -> RustReferenceContext<'a> {
    RustReferenceContext::new(rust, token, file, false, Box::new(keep_going))
}

pub fn forward_reference_context_of<'a>(
    rust: &'a dyn RustFactSource,
    token: QueryToken<'a>,
    file: &ProjectFile,
) -> RustReferenceContext<'a> {
    RustReferenceContext::new(rust, token, file, true, Box::new(|| true))
}

pub fn forward_reference_context_of_while<'a>(
    rust: &'a dyn RustFactSource,
    token: QueryToken<'a>,
    file: &ProjectFile,
    keep_going: impl Fn() -> bool + 'a,
) -> RustReferenceContext<'a> {
    RustReferenceContext::new(rust, token, file, true, Box::new(keep_going))
}

fn join_rust_fqn(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}.{name}")
    }
}

/// The analyzed Rust files bucketed by their path-derived package name — the
/// indexed form of the two questions [`RustAnalyzer::resolve_module_files`] asks
/// of the workspace: "is this file analyzed?" and "which analyzed files spell
/// package `p`?".
///
/// Both were previously answered by materializing a fresh `BTreeSet` of every
/// analyzed file and recomputing the allocating `rust_package_name` for each of
/// them, *per call* — a whole-workspace sweep to answer a single-module question,
/// issued once per import binding per file per reference context (#1230 item 3).
/// The projection retains file identities and their path-derived package names
/// only: no declarations, file states, sources, or persisted rows, so it is a
/// pure reindex of data `get_analyzed_files` already returns and cannot change
/// what a resolution answers.
#[derive(Debug, Default)]
pub struct RustPackageFileIndex {
    /// Every analyzed file, in `get_analyzed_files` (sorted) order so membership
    /// is a binary search rather than a second owned copy of each file.
    files: Vec<ProjectFile>,
    /// Package name -> indices into `files`, ascending.
    by_package: HashMap<String, Vec<u32>>,
    /// Import crate name -> root package names, from nearby Cargo manifests.
    crate_packages_by_name: HashMap<String, Vec<String>>,
}

impl RustPackageFileIndex {
    pub fn build(files: BTreeSet<ProjectFile>) -> Self {
        let files: Vec<ProjectFile> = files.into_iter().collect();
        let mut by_package: HashMap<String, Vec<u32>> = HashMap::default();
        let mut crate_packages_by_name: HashMap<String, Vec<String>> = HashMap::default();
        for (index, file) in files.iter().enumerate() {
            let package = rust_package_name(file);
            by_package
                .entry(package.clone())
                .or_default()
                .push(u32::try_from(index).unwrap_or(u32::MAX));
            if let Some(crate_name) = manifest_crate_name(file) {
                let packages = crate_packages_by_name.entry(crate_name).or_default();
                if !packages.contains(&package) {
                    packages.push(package);
                }
            }
        }
        Self {
            files,
            by_package,
            crate_packages_by_name,
        }
    }

    pub fn contains(&self, file: &ProjectFile) -> bool {
        self.files.binary_search(file).is_ok()
    }

    pub fn files_in_package(&self, package: &str) -> impl Iterator<Item = &ProjectFile> {
        self.by_package
            .get(package)
            .into_iter()
            .flatten()
            .filter_map(|index| self.files.get(*index as usize))
    }

    fn crate_packages(&self, import_name: &str) -> &[String] {
        self.crate_packages_by_name
            .get(import_name)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

fn manifest_crate_name(file: &ProjectFile) -> Option<String> {
    let rel_path = file.rel_path();
    if !matches!(
        rel_path.file_name().and_then(|name| name.to_str()),
        Some("lib.rs" | "main.rs")
    ) {
        return None;
    }
    let source_dir = rel_path.parent()?;
    if source_dir.file_name().and_then(|name| name.to_str()) != Some("src") {
        return None;
    }
    let manifest =
        std::fs::read_to_string(file.root().join(source_dir.parent()?.join("Cargo.toml")))
            .ok()?
            .parse::<toml::Value>()
            .ok()?;
    let name = manifest
        .get("lib")
        .and_then(|lib| lib.get("name"))
        .and_then(toml::Value::as_str)
        .or_else(|| {
            manifest
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(toml::Value::as_str)
        })?;
    Some(name.replace('-', "_"))
}

fn single_reexport_target_fqn(
    targets: impl IntoIterator<Item = (ProjectFile, String)>,
) -> Option<String> {
    let mut targets = targets.into_iter();
    let (target_file, target_name) = targets.next()?;
    targets
        .next()
        .is_none()
        .then(|| join_rust_fqn(&rust_package_name(&target_file), &target_name))
}

fn single_rust_target_fqn(
    rust: &dyn RustSource,
    targets: BTreeSet<(ProjectFile, String)>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    let mut fq_names = Vec::new();
    for (target_file, target_name) in targets {
        reference_context_checkpoint(progress)?;
        let properties = declaration_source_properties_while(rust, &target_file, progress)?;
        for unit in rust.declarations(&target_file) {
            reference_context_checkpoint(progress)?;
            if unit.identifier() == target_name {
                let rows = properties
                    .get(&unit)
                    .ok_or(RustCargoRouteError::Unavailable)?;
                if declaration_properties_are_export_visible(rows, progress)? {
                    fq_names.push(unit.fq_name());
                }
            }
        }
    }
    fq_names.sort();
    fq_names.dedup();
    reference_context_checkpoint(progress)?;
    Ok((fq_names.len() == 1).then(|| fq_names.remove(0)))
}

fn is_rooted_rust_module_path(path: &str) -> bool {
    path == "crate"
        || path == "self"
        || path == "super"
        || path.starts_with("crate::")
        || path.starts_with("self::")
        || path.starts_with("super::")
}

fn cargo_routes_for_progress(
    rust: &dyn RustSource,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Arc<RustCargoRouteIndex>> {
    match progress {
        Some(progress) => Ok(rust.cargo_routes_while(progress)?),
        None => Ok(rust.cargo_routes()?),
    }
}

fn route_progress_checkpoint(progress: Option<&dyn Fn() -> bool>) -> ReferenceContextResult<()> {
    progress.map_or(Ok(()), reference_context_checkpoint)
}

fn resolve_declared_local_module_package_with_progress(
    rust: &dyn RustSource,
    importing_file: &ProjectFile,
    module_specifier: &str,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Option<String>> {
    // `ImportBinder` supplies one AST-derived path. A Namespace binding for a
    // function import retains the terminal (`dep::target`), so establish local
    // authority from its first parsed segment and only then anchor the complete
    // path under the importing module.
    let segments = parse_symbol_path(Language::Rust, module_specifier);
    if segments.is_empty()
        || matches!(
            segments.first().map(String::as_str),
            Some("crate" | "self" | "super")
        )
    {
        return Ok(None);
    }
    let package = rust_package_name(importing_file);
    let crate_package = rust_crate_root_package(importing_file);
    let routes = cargo_routes_for_progress(rust, progress)?;
    let local_anchor = if routes.file_uses_rust_2015_edition(importing_file) {
        "crate"
    } else {
        "self"
    };
    let mut root_segments = vec![local_anchor.to_string()];
    root_segments.push(segments[0].clone());
    let Some(local_root) =
        resolve_rust_module_segments_with_crate(&package, &crate_package, root_segments.as_slice())
    else {
        return Ok(None);
    };
    let mut has_module = false;
    for unit in rust.definitions(&local_root) {
        route_progress_checkpoint(progress)?;
        if unit.is_module()
            && routes.target_relation(importing_file, unit.source())
                != RustCargoTargetRelation::Disjoint
        {
            has_module = true;
            break;
        }
    }
    if !has_module {
        return Ok(None);
    }
    let mut local_segments = Vec::with_capacity(segments.len() + 1);
    local_segments.push(local_anchor.to_string());
    local_segments.extend(segments);
    Ok(resolve_rust_module_segments_with_crate(
        &package,
        &crate_package,
        local_segments.as_slice(),
    ))
}

fn rust_declaration_targets_in_files(
    index: &dyn CodeUnitIndex,
    files: &[ProjectFile],
    name: &str,
) -> Vec<(ProjectFile, String)> {
    rust_declaration_targets_in_files_with_progress(index, files, name, &|| true)
        .expect("uninterrupted Rust declaration traversal")
}

fn rust_declaration_targets_in_files_with_progress(
    index: &dyn CodeUnitIndex,
    files: &[ProjectFile],
    name: &str,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Vec<(ProjectFile, String)>> {
    let mut targets = Vec::new();
    for file in files {
        reference_context_checkpoint(progress)?;
        for unit in index.declarations(file) {
            reference_context_checkpoint(progress)?;
            if unit.identifier() == name {
                targets.push((file.clone(), unit.identifier().to_string()));
            }
        }
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

pub fn resolve_visible_import_targets_forward(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> ReferenceContextResult<Vec<(ProjectFile, String)>> {
    let mut targets =
        resolve_imported_export_from_binder_forward(rust, token, file, binder, reference)?;
    for (local_name, binding) in &binder.bindings {
        if local_name != reference || binding.kind != ImportKind::Named {
            continue;
        }
        let imported = binding.imported_name.as_deref().unwrap_or(reference);
        targets.extend(
            resolve_module_files(rust, token, file, &binding.module_specifier)?
                .into_iter()
                .map(|target_file| (target_file, imported.to_string())),
        );
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn declaration_source_properties_while(
    rust: &dyn RustSource,
    file: &ProjectFile,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Arc<RustDeclarationSourceProperties>> {
    match rust.declaration_source_properties(file, progress) {
        Ok(properties) => Ok(properties),
        Err(RustCargoRouteError::Cancelled) => Err(ReferenceContextError::Interrupted),
        Err(error) => Err(error.into()),
    }
}

fn declaration_properties_are_export_visible(
    properties: &[RustDeclarationPropertyFact],
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<bool> {
    for property in properties {
        reference_context_checkpoint(progress)?;
        let visible = match &property.visibility {
            RustVisibility::Public | RustVisibility::Crate => true,
            RustVisibility::InPath(path) => path.first().is_some_and(|segment| segment == "crate"),
            RustVisibility::Private | RustVisibility::SelfModule | RustVisibility::SuperModule => {
                false
            }
        };
        if visible {
            return Ok(true);
        }
    }
    Ok(false)
}

fn export_visible_declarations_from_properties(
    rust: &dyn RustSource,
    file: &ProjectFile,
    declarations: &BTreeSet<CodeUnit>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<HashSet<CodeUnit>> {
    let properties = declaration_source_properties_while(rust, file, progress)?;
    let mut visible = HashSet::default();
    for declaration in declarations {
        reference_context_checkpoint(progress)?;
        let rows = properties
            .get(declaration)
            .ok_or(RustCargoRouteError::Unavailable)?;
        if declaration_properties_are_export_visible(rows, progress)? {
            visible.insert(declaration.clone());
        }
    }
    Ok(visible)
}

pub fn export_index_of_declarations_while(
    rust: &dyn RustFactSource,
    file: &ProjectFile,
    declarations: &BTreeSet<CodeUnit>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<ExportIndex> {
    let _scope = profiling::scope("RustAnalyzer::export_index_of_declarations");
    let mut index = ExportIndex::empty();
    reference_context_checkpoint(progress)?;
    // Re-exports consume the coordinated producer's import properties. The
    // local export set uses the same exact source-declaration properties, so
    // repeated embedded CodeUnits retain existential visibility alternatives.
    let facts = RustUsageQueries::new(rust).facts_of(file)?;
    reference_context_checkpoint(progress)?;
    let export_visible =
        export_visible_declarations_from_properties(rust, file, declarations, progress)?;
    let mut external_visibility = HashMap::default();

    for code_unit in declarations {
        reference_context_checkpoint(progress)?;
        let identifier = code_unit.identifier().trim();
        if identifier.is_empty() || identifier.starts_with('_') {
            continue;
        }
        if !is_module_export_candidate_while(
            rust,
            file,
            code_unit,
            &export_visible,
            &mut external_visibility,
            progress,
        )? {
            continue;
        }
        index.exports_by_name.insert(
            identifier.to_string(),
            ExportEntry::Local {
                local_name: identifier.to_string(),
            },
        );
    }

    for import in facts.iter().flat_map(|facts| &facts.import_targets) {
        reference_context_checkpoint(progress)?;
        if !import.owner_module.is_empty()
            || import.local_extent.is_some()
            || import.is_extern_crate
            || matches!(
                import.visibility,
                RustVisibility::Private | RustVisibility::SelfModule
            )
        {
            continue;
        }
        if import.is_glob {
            if !import.module_path.is_empty() {
                index.reexport_stars.push(ReexportStar {
                    module_specifier: import.module_path.join("::"),
                });
            }
            continue;
        }
        let (Some(imported_name), Some(local_name)) = (&import.imported_name, &import.bound_name)
        else {
            continue;
        };
        index.exports_by_name.insert(
            local_name.clone(),
            ExportEntry::ReexportedNamed {
                module_specifier: import.module_path.join("::"),
                imported_name: imported_name.clone(),
            },
        );
    }

    reference_context_checkpoint(progress)?;
    Ok(index)
}

/// The named/namespace/glob binder walk shared by the forward and inverted
/// export resolvers. `forward` selects which export walk answers a binding; the
/// rest of the traversal is identical, so the two entry points below wrap this
/// rather than duplicating it.
fn resolve_imported_export_from_binder_with_mode(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
    forward: bool,
) -> ReferenceContextResult<Vec<(ProjectFile, String)>> {
    let index = rust.code_units();
    let mut targets = HashSet::default();
    let mut saw_explicit_binding = false;
    for (local_name, binding) in &binder.bindings {
        match binding.kind {
            ImportKind::Named if local_name == reference => {
                saw_explicit_binding = true;
                let imported = binding.imported_name.as_deref().unwrap_or(reference);
                let files = resolve_module_files(rust, token, file, &binding.module_specifier)?;
                let exported = if forward {
                    forward_imported_targets(
                        rust,
                        token,
                        file,
                        &binding.module_specifier,
                        imported,
                    )?
                } else {
                    exported_targets_from_files(rust, token, &files, imported)?
                };
                targets.extend(exported);
                if targets.is_empty() {
                    targets.extend(rust_declaration_targets_in_files(index, &files, imported));
                }
            }
            ImportKind::Namespace if local_name == reference => {
                saw_explicit_binding = true;
                let segments = parse_symbol_path(Language::Rust, &binding.module_specifier);
                let Some((imported, module_segments)) = segments.split_last() else {
                    continue;
                };
                let module_specifier = module_segments.join("::");
                let files = resolve_module_files(rust, token, file, &module_specifier)?;
                let exported = if forward {
                    forward_imported_targets(rust, token, file, &module_specifier, imported)?
                } else {
                    exported_targets_from_files(rust, token, &files, imported)?
                };
                targets.extend(exported);
                if targets.is_empty() {
                    targets.extend(rust_declaration_targets_in_files(index, &files, imported));
                }
            }
            ImportKind::Named
            | ImportKind::Namespace
            | ImportKind::Default
            | ImportKind::CommonJsRequire
            | ImportKind::Glob => {}
        }
    }
    if saw_explicit_binding {
        let mut sorted: Vec<_> = targets.into_iter().collect();
        sorted.sort();
        return Ok(sorted);
    }
    for binding in binder.bindings.values() {
        if matches!(binding.kind, ImportKind::Glob) {
            let files = resolve_module_files(rust, token, file, &binding.module_specifier)?;
            let exported = if forward {
                forward_imported_targets(rust, token, file, &binding.module_specifier, reference)?
            } else {
                exported_targets_from_files(rust, token, &files, reference)?
            };
            targets.extend(exported);
        }
    }
    let mut sorted: Vec<_> = targets.into_iter().collect();
    sorted.sort();
    Ok(sorted)
}

/// Compose imports against module identities, including namespaces brought into
/// scope by another import. A file-only export walk loses inline module scope
/// and cannot follow a crate namespace re-exported through a prelude (#3186).
fn forward_imported_targets(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    module_specifier: &str,
    name: &str,
) -> ReferenceContextResult<BTreeSet<(ProjectFile, String)>> {
    Ok(forward_imported_identities(
        rust,
        token,
        file,
        &rust_package_name(file),
        module_specifier,
        name,
    )?
    .into_iter()
    .map(|identity| (identity.file, identity.name))
    .collect())
}

/// Canonical declarations bound by a module import, with the original module
/// and namespace retained for consumers that must validate exact identities.
pub fn forward_imported_identities(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    package: &str,
    module_specifier: &str,
    name: &str,
) -> ReferenceContextResult<HashSet<crate::usage::RustSymbolIdentity>> {
    let walks = crate::usage_walks::RustUsageWalks::new(rust, token)?;
    let importer = walks.queries().module_key_of(file, package);
    let segments = parse_symbol_path(Language::Rust, module_specifier);
    let mut targets = HashSet::default();
    for route in walks.resolve_segments(file, package, &segments)? {
        for binding in walks
            .bindings_at(&route.target_file, &route.target_module)?
            .iter()
        {
            if binding.name == name && binding.domain.contains_module(&importer) {
                targets.insert(binding.origin.clone());
            }
        }
    }
    Ok(targets)
}

pub fn resolve_imported_export_from_binder_forward(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> ReferenceContextResult<Vec<(ProjectFile, String)>> {
    resolve_imported_export_from_binder_with_mode(rust, token, file, binder, reference, true)
}

pub fn resolve_imported_export_from_binder(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> ReferenceContextResult<Vec<(ProjectFile, String)>> {
    resolve_imported_export_from_binder_with_mode(rust, token, file, binder, reference, false)
}

/// Resolve a `use`-path module specifier (e.g. `crate::util`, `crate::svc`)
/// to the dotted package it names, relative to `importing_file`. This is the
/// `package_name` half of a `CodeUnit::fq_name()` for items in that module, so
/// the inverted usage-graph builder can turn `(module_specifier, name)` into a
/// callee fqn without re-deriving the path arithmetic.
pub fn resolve_module_package(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> ReferenceContextResult<Option<String>> {
    resolve_module_package_traced(rust, token, importing_file, module_specifier, None)
}

/// Progress-aware module-package resolution for bounded callers. The route
/// producer uses the supplied predicate for its cold Cargo/index reads and
/// every alias/export walk; it never falls back to the unbounded route entry
/// point.
pub fn resolve_module_package_while(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    resolve_module_package_traced_with_progress(
        rust,
        token,
        importing_file,
        module_specifier,
        None,
        Some(progress),
    )
}

/// [`resolve_module_package`], recording the import-alias chase into `trace`.
///
/// This is the *same* resolution: `resolve_module_package` is this function
/// with no collector, so an instrumented run takes exactly the branches a
/// production run takes. Every recording site is a no-op when `trace` is
/// `None`, so an uninstrumented resolution allocates nothing for it.
///
/// The chase is the bounded rewrite domain `rust_import_alias` (#1480): the
/// semantic state key is the specifier's root (the rewrite replaces only the
/// root, so the specifier grows every hop and can never repeat), the declared
/// bound is the binder's rewritable root count, and the terminal outcome is
/// converged, cycle, or exceeded-budget.
pub fn resolve_module_package_traced(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    trace: Option<&mut RewriteTrace>,
) -> ReferenceContextResult<Option<String>> {
    resolve_module_package_traced_with_progress(
        rust,
        token,
        importing_file,
        module_specifier,
        trace,
        None,
    )
}

/// Progress-aware form of [`resolve_module_package_traced`]. The trace remains
/// the same production chase; `progress` only controls whether the shared
/// route reads may continue.
pub fn resolve_module_package_traced_while(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    trace: Option<&mut RewriteTrace>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    resolve_module_package_traced_with_progress(
        rust,
        token,
        importing_file,
        module_specifier,
        trace,
        Some(progress),
    )
}

fn resolve_module_package_traced_with_progress(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    mut trace: Option<&mut RewriteTrace>,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Option<String>> {
    route_progress_checkpoint(progress)?;
    let package = rust_package_name(importing_file);
    let crate_package = rust_crate_root_package(importing_file);
    if is_rooted_rust_module_path(module_specifier) {
        return Ok(resolve_rust_module_path_with_crate(
            &package,
            &crate_package,
            module_specifier,
        ));
    }
    if let Some(package) = resolve_declared_local_module_package_with_progress(
        rust,
        importing_file,
        module_specifier,
        progress,
    )? {
        return Ok(Some(package));
    }
    if let Some(package) = cargo_routes_for_progress(rust, progress)?
        .resolve_module_package(importing_file, module_specifier)
    {
        return Ok(Some(package));
    }
    // Only after cargo routing fails — the miss path, not the hot path — try
    // a `use <crate> as <alias>` module alias so the binder is built solely
    // for unresolved roots (issue #1089). Chained renames in one file can
    // cycle (`use a::b as c` plus `use c::d as a`: zellij overflowed the
    // rayon worker stack recursing through them, #1347). The rewrite
    // replaces only the root, so the specifier grows every hop and a
    // whole-string visited set never trips; the cycle lives in root space
    // (the binder maps each root to exactly one target, so revisiting a
    // root is deterministically an infinite loop). Chase iteratively,
    // bounded by the binder's root count; a repeated root stops expanding
    // and the last specifier falls through to the path arithmetic.
    let mut seen_roots = HashSet::default();
    // The visited roots in order, so a cycle can report the sequence that
    // closes it. Only filled while tracing; an uninstrumented run leaves this
    // an unallocated `Vec`.
    let mut visited_order: Vec<String> = Vec::new();
    // The binder's rewritable root count: the finite state space this chase
    // walks, and therefore its declared bound. Computed on the first rewrite
    // rather than up front, so a specifier that never engages the alias rule
    // pays nothing for it.
    let mut declared_bound: Option<usize> = None;
    let mut steps_taken = 0usize;
    let mut current = module_specifier.to_string();
    loop {
        route_progress_checkpoint(progress)?;
        let root = current.split("::").next().unwrap_or(current.as_str());
        if !seen_roots.insert(root.to_string()) {
            if let Some(trace) = trace.as_deref_mut() {
                trace.finish(RewriteOutcome::Cycle {
                    witness: cycle_witness(&visited_order, root),
                });
            }
            break;
        }
        if trace.is_some() {
            visited_order.push(root.to_string());
        }
        let Some(aliased) = rust_apply_import_alias(rust, importing_file, &current) else {
            if let Some(trace) = trace.as_deref_mut() {
                trace.finish(RewriteOutcome::Converged {
                    fixed_point: current.clone(),
                });
            }
            break;
        };
        // Each rewrite consumes one distinct binder root, so `steps_taken`
        // can never pass the bound while the visited set still admits a hop;
        // this guard is the contract's explicit budget terminal rather than a
        // reachable branch. Keeping it in the production path is deliberate:
        // the instrumented chase and the production chase are one loop.
        let bound = *declared_bound
            .get_or_insert_with(|| rust.import_binder_of(importing_file).bindings.len());
        if steps_taken >= bound {
            if let Some(trace) = trace.as_deref_mut() {
                trace.finish(RewriteOutcome::ExceededBudget {
                    explored: steps_taken,
                });
            }
            break;
        }
        steps_taken += 1;
        if let Some(trace) = trace.as_deref_mut() {
            trace.declare_bound(bound);
            trace.record_step(RewriteStep {
                state_key: root.to_string(),
                input: current.clone(),
                output: aliased.clone(),
                rule: ALIAS_SUBSTITUTION_RULE,
            });
        }
        if let Some(package) = resolve_import_alias_exported_module_package_with_progress(
            rust,
            token,
            importing_file,
            &aliased,
            progress,
        )? {
            finish_converged(trace, &aliased);
            return Ok(Some(package));
        }
        if is_rooted_rust_module_path(&aliased) {
            finish_converged(trace, &aliased);
            return Ok(resolve_rust_module_path_with_crate(
                &package,
                &crate_package,
                &aliased,
            ));
        }
        if let Some(package) = cargo_routes_for_progress(rust, progress)?
            .resolve_module_package(importing_file, &aliased)
        {
            finish_converged(trace, &aliased);
            return Ok(Some(package));
        }
        current = aliased;
    }
    Ok(resolve_rust_module_path_with_crate(
        &package,
        &crate_package,
        &current,
    ))
}

/// The ordered state sequence that closes a cycle: the visited roots from the
/// first occurrence of the repeated root onwards, with that root appended so
/// the sequence's last state is the one it repeats.
fn cycle_witness(visited_order: &[String], repeated: &str) -> Vec<String> {
    let start = visited_order
        .iter()
        .position(|state| state == repeated)
        .unwrap_or(0);
    let mut witness: Vec<String> = visited_order[start..].to_vec();
    witness.push(repeated.to_string());
    witness
}

/// Record convergence on `fixed_point` when the chase is instrumented.
///
/// A chase that returns from inside the loop converged just as much as one
/// that falls through: it reached a specifier the routing resolved, and no
/// further rewrite was applied.
fn finish_converged(trace: Option<&mut RewriteTrace>, fixed_point: &str) {
    if let Some(trace) = trace {
        trace.finish(RewriteOutcome::Converged {
            fixed_point: fixed_point.to_string(),
        });
    }
}

fn resolve_import_alias_exported_module_package_with_progress(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    aliased_specifier: &str,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Option<String>> {
    route_progress_checkpoint(progress)?;
    let segments = parse_symbol_path(Language::Rust, aliased_specifier);
    let Some((root, suffix)) = segments.split_first() else {
        return Ok(None);
    };
    let Some(suffix) = (!suffix.is_empty()).then_some(suffix) else {
        return Ok(None);
    };
    if rust_apply_import_alias(rust, importing_file, root).is_some() {
        return Ok(None);
    }
    let mut files =
        resolve_module_files_with_progress(rust, token, importing_file, root, progress)?;
    if files.is_empty() {
        return Ok(None);
    }
    let mut package = None;
    for segment in suffix {
        route_progress_checkpoint(progress)?;
        let Some(target) =
            forward_exported_module_fqn_with_progress(rust, token, &files, segment, progress)?
        else {
            return Ok(None);
        };
        package = Some(target.clone());
        files = resolve_module_files_with_progress(rust, token, importing_file, &target, progress)?;
        if files.is_empty() {
            return Ok(None);
        }
    }
    Ok(package)
}

fn forward_exported_module_fqn_with_progress(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    name: &str,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Option<String>> {
    let mut pending = module_files
        .iter()
        .cloned()
        .map(|file| (file, name.to_string(), false))
        .collect::<Vec<_>>();
    let mut visited = HashSet::default();
    let mut targets = BTreeSet::new();
    while let Some((file, name, reached_through_reexport)) = pending.pop() {
        route_progress_checkpoint(progress)?;
        if !visited.insert((file.clone(), name.clone(), reached_through_reexport)) {
            continue;
        }
        let export_index = match progress {
            Some(progress) => rust.export_index_of_while(&file, progress)?,
            None => rust.export_index_of(&file)?,
        };
        match export_index.exports_by_name.get(&name) {
            Some(ExportEntry::Local { local_name }) => {
                targets.extend(
                    rust.definitions(&format!("{}.{}", rust_package_name(&file), local_name))
                        .filter(|unit| unit.is_module())
                        .map(|unit| unit.fq_name()),
                );
            }
            Some(ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            }) => {
                pending.extend(
                    resolve_module_files_with_progress(
                        rust,
                        token,
                        &file,
                        module_specifier,
                        progress,
                    )?
                    .into_iter()
                    .map(|target| (target, imported_name.clone(), true)),
                );
            }
            Some(ExportEntry::Default { .. } | ExportEntry::ReexportedModule { .. }) => {}
            None if reached_through_reexport => {
                targets.extend(
                    rust.definitions(&format!("{}.{}", rust_package_name(&file), name))
                        .filter(|unit| unit.is_module())
                        .map(|unit| unit.fq_name()),
                );
            }
            None => {}
        }
        for ReexportStar { module_specifier } in &export_index.reexport_stars {
            pending.extend(
                resolve_module_files_with_progress(rust, token, &file, module_specifier, progress)?
                    .into_iter()
                    .map(|target| (target, name.clone(), true)),
            );
        }
    }
    Ok((targets.len() == 1)
        .then(|| targets.into_iter().next())
        .flatten())
}

/// Resolve one export name after the caller has resolved the module files.
/// split out so callers that resolve every export name of *one* module
/// specifier route the invariant `resolve_module_files` once instead of once
/// per name (#1230 item 4).
#[doc(hidden)]
pub fn canonical_export_fqn_from_files(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    name: &str,
    forward: bool,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    rust.note_export_name_canonicalization();
    let targets = if forward {
        forward_exported_targets_from_files_with_progress(
            rust,
            token,
            module_files,
            name,
            progress,
        )?
    } else {
        exported_targets_from_files_while(rust, token, module_files, name, progress)?
    };
    single_rust_target_fqn(rust, targets, progress)
}

pub fn forward_export_fqn_from_files(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    name: &str,
) -> ReferenceContextResult<Option<String>> {
    if let Some(fqn) =
        canonical_export_fqn_from_files(rust, token, module_files, name, true, &|| true)?
    {
        return Ok(Some(fqn));
    }
    let mut member_fqns = BTreeSet::new();
    for file in module_files {
        let index = rust.export_index_of(file)?;
        let Some(ExportEntry::ReexportedNamed {
            module_specifier,
            imported_name,
        }) = index.exports_by_name.get(name)
        else {
            continue;
        };
        let Some(owner_fqn) = resolve_module_package(rust, token, file, module_specifier)? else {
            continue;
        };
        let target_fqn = join_rust_fqn(&owner_fqn, imported_name);
        if rust.definitions(&target_fqn).next().is_some() {
            member_fqns.insert(target_fqn);
        }
    }
    Ok((member_fqns.len() == 1)
        .then(|| member_fqns.into_iter().next())
        .flatten())
}

pub fn forward_exported_targets_from_files(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    export_name: &str,
) -> ReferenceContextResult<BTreeSet<(ProjectFile, String)>> {
    forward_exported_targets_from_files_with_progress(
        rust,
        token,
        module_files,
        export_name,
        &|| true,
    )
}

fn forward_exported_targets_from_files_with_progress(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    export_name: &str,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<BTreeSet<(ProjectFile, String)>> {
    let mut targets = BTreeSet::new();
    let mut visited = HashSet::default();
    let mut pending: Vec<_> = module_files
        .iter()
        .cloned()
        .map(|file| (file, export_name.to_string(), false))
        .collect();
    while let Some((file, name, reached_through_reexport)) = pending.pop() {
        reference_context_checkpoint(progress)?;
        if !visited.insert((file.clone(), name.clone(), reached_through_reexport)) {
            continue;
        }
        let index = rust.export_index_of_while(&file, progress)?;
        match index.exports_by_name.get(&name) {
            Some(ExportEntry::Local { local_name }) => {
                targets.insert((file.clone(), local_name.clone()));
            }
            Some(ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            }) => {
                let module_files =
                    resolve_module_files_while(rust, token, &file, module_specifier, progress)?;
                if module_files.is_empty() {
                    targets.extend(rust_member_reexport_targets_while(
                        rust,
                        token,
                        &file,
                        module_specifier,
                        imported_name,
                        progress,
                    )?);
                } else {
                    pending.extend(
                        module_files
                            .into_iter()
                            .map(|target_file| (target_file, imported_name.clone(), true)),
                    );
                }
            }
            Some(ExportEntry::Default {
                local_name: Some(local_name),
            }) => {
                targets.insert((file.clone(), local_name.clone()));
            }
            Some(ExportEntry::Default { local_name: None })
            | Some(ExportEntry::ReexportedModule { .. }) => {}
            None if reached_through_reexport => {
                let properties = declaration_source_properties_while(rust, &file, progress)?;
                for unit in rust.declarations(&file) {
                    reference_context_checkpoint(progress)?;
                    if unit.identifier() == name {
                        let rows = properties
                            .get(&unit)
                            .ok_or(RustCargoRouteError::Unavailable)?;
                        if declaration_properties_are_export_visible(rows, progress)? {
                            targets.insert((file.clone(), unit.identifier().to_string()));
                        }
                    }
                }
            }
            None => {}
        }
        for star in &index.reexport_stars {
            pending.extend(
                resolve_module_files_while(rust, token, &file, &star.module_specifier, progress)?
                    .into_iter()
                    .map(|target_file| (target_file, name.clone(), true)),
            );
        }
    }
    reference_context_checkpoint(progress)?;
    Ok(targets)
}

pub fn rust_member_reexport_targets(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    owner_path: &str,
    member_name: &str,
) -> ReferenceContextResult<BTreeSet<(ProjectFile, String)>> {
    let Some(owner_fqn) = resolve_module_package(rust, token, file, owner_path)? else {
        return Ok(BTreeSet::new());
    };
    let target_fqn = join_rust_fqn(&owner_fqn, member_name);
    Ok(rust
        .definitions(&target_fqn)
        .map(|candidate| {
            (
                candidate.source().clone(),
                candidate.identifier().to_string(),
            )
        })
        .collect())
}

fn rust_member_reexport_targets_while(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    owner_path: &str,
    member_name: &str,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<BTreeSet<(ProjectFile, String)>> {
    let Some(owner_fqn) = resolve_module_package_while(rust, token, file, owner_path, progress)?
    else {
        return Ok(BTreeSet::new());
    };
    let target_fqn = join_rust_fqn(&owner_fqn, member_name);
    let mut targets = BTreeSet::new();
    for candidate in rust.definitions(&target_fqn) {
        reference_context_checkpoint(progress)?;
        targets.insert((
            candidate.source().clone(),
            candidate.identifier().to_string(),
        ));
    }
    Ok(targets)
}

/// Rewrite a leading aliased `use` segment in `module_specifier` to the
/// imported path. `use forc_pkg::{self as pkg}` makes `pkg` (and `pkg::Item`)
/// mean `forc_pkg` (`forc_pkg::Item`), while `use a::b as c` makes `c` mean
/// `a::b`. Every module resolver must first substitute the alias before
/// routing; otherwise the alias root is unknown and draws a false "not
/// indexed" boundary even though the path is in the workspace (issue #1089).
pub fn rust_apply_import_alias(
    rust: &dyn RustSource,
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> Option<String> {
    let (root, rest) = module_specifier
        .split_once("::")
        .map_or((module_specifier, None), |(root, rest)| (root, Some(rest)));
    if root.is_empty() || matches!(root, "crate" | "self" | "super") {
        return None;
    }
    let binder = rust.import_binder_of(importing_file);
    let binding = binder.bindings.get(root)?;
    rewrite_import_alias_binding(root, rest, binding)
}

fn rewrite_import_alias_binding(
    root: &str,
    rest: Option<&str>,
    binding: &ImportBinding,
) -> Option<String> {
    let imported_name = match binding.kind {
        ImportKind::Namespace if binding.imported_name.is_none() => None,
        ImportKind::Named => Some(binding.imported_name.as_deref()?),
        _ => return None,
    };
    let target = binding.module_specifier.as_str();
    // Only a genuine rename (`use path as alias`) where the alias spelling
    // differs from the imported module's own last segment; an ordinary
    // `use a::b` binding names its own last segment and must not be rewritten
    // (that would loop or mis-route).
    let target_last_segment = imported_name.or_else(|| target.rsplit("::").next());
    if target.is_empty() || target == root || target_last_segment == Some(root) {
        return None;
    }
    Some(match (imported_name, rest) {
        (Some(imported_name), Some(rest)) => format!("{target}::{imported_name}::{rest}"),
        (Some(imported_name), None) => format!("{target}::{imported_name}"),
        (None, Some(rest)) => format!("{target}::{rest}"),
        (None, None) => target.to_string(),
    })
}

pub fn resolve_module_files(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> ReferenceContextResult<Vec<ProjectFile>> {
    resolve_module_files_with_progress(rust, token, importing_file, module_specifier, None)
}

/// Progress-aware form of [`resolve_module_files`] for bounded consumers.
pub fn resolve_module_files_while(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Vec<ProjectFile>> {
    resolve_module_files_with_progress(
        rust,
        token,
        importing_file,
        module_specifier,
        Some(progress),
    )
}

fn resolve_module_files_with_progress(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Vec<ProjectFile>> {
    route_progress_checkpoint(progress)?;
    rust.note_module_file_resolution();
    let analyzed_files = rust.package_file_index();
    let package = rust_package_name(importing_file);
    let crate_package = rust_crate_root_package(importing_file);
    let rooted = is_rooted_rust_module_path(module_specifier);
    // Keep the local declaration witness through file selection. Independent
    // Cargo targets can have the same rendered package/module name.
    let declared_local_module = if rooted {
        None
    } else {
        resolve_declared_local_module_package_with_progress(
            rust,
            importing_file,
            module_specifier,
            progress,
        )?
    };
    let local_target = rooted || declared_local_module.is_some();
    let Some(mut resolved_module) = (if rooted {
        resolve_rust_module_path_with_crate(&package, &crate_package, module_specifier)
    } else if let Some(module) = declared_local_module {
        Some(module)
    } else {
        resolve_module_package_traced_with_progress(
            rust,
            token,
            importing_file,
            module_specifier,
            None,
            progress,
        )?
    }) else {
        return Ok(rust_module_files_from_path(
            importing_file,
            module_specifier,
        ));
    };

    let mut files =
        resolved_module_files_with_progress(rust, importing_file, &resolved_module, progress)?;
    if !rooted
        && files.is_empty()
        && let Some(root_file) = cargo_routes_for_progress(rust, progress)?
            .resolve_crate_root_file(importing_file, module_specifier)
        && analyzed_files.contains(&root_file)
    {
        files.push(root_file);
    }
    files.extend(rust_module_files_from_path(
        importing_file,
        module_specifier,
    ));
    files.sort();
    files.dedup();

    // A crate-root path can name a module re-exported by the crate facade
    // rather than a physical child of that crate. `crate::api` in a facade
    // that says `pub use engine::api` is one namespace with the physical
    // `engine::api`; treating the path-derived `facade.api` spelling as final
    // reports an indexed workspace target as an external boundary. Follow the
    // crate root's structured export graph only after the ordinary physical
    // route misses, so a real local module keeps Rust's normal precedence.
    if files.is_empty()
        && let Some(exported_module) = resolve_exported_module_package(
            rust,
            token,
            importing_file,
            module_specifier,
            progress,
        )?
    {
        resolved_module = exported_module;
        files =
            resolved_module_files_with_progress(rust, importing_file, &resolved_module, progress)?;
    }

    // Path-derived Rust package names are shared by independent Cargo
    // examples, benches, and binaries. Rooted and declared local paths are crate-relative, so
    // only disambiguate when the package lookup actually collided: retain
    // physically shared targets when known, otherwise preserve unknown
    // relationships conservatively, and never cross a proven-disjoint root.
    if local_target && files.len() > 1 {
        let routes = cargo_routes_for_progress(rust, progress)?;
        let mut shared = Vec::new();
        let mut unknown = Vec::new();
        for candidate in files {
            route_progress_checkpoint(progress)?;
            match routes.target_relation(importing_file, &candidate) {
                RustCargoTargetRelation::Shared => shared.push(candidate),
                RustCargoTargetRelation::Unknown => unknown.push(candidate),
                RustCargoTargetRelation::Disjoint => {}
            }
        }
        return Ok(if shared.is_empty() { unknown } else { shared });
    }
    Ok(files)
}

fn resolved_module_files_with_progress(
    rust: &dyn RustSource,
    importing_file: &ProjectFile,
    resolved_module: &str,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Vec<ProjectFile>> {
    route_progress_checkpoint(progress)?;
    let analyzed_files = rust.package_file_index();
    let mut files = Vec::new();
    for file in analyzed_files.files_in_package(resolved_module) {
        route_progress_checkpoint(progress)?;
        files.push(file.clone());
    }
    // Only units that *are* the module's definition back it. A bodiless
    // `mod svc;` item is a forwarder living in the declaring file, so
    // extending with its source handed every consumer lib.rs alongside the
    // real content file (#1342). An inline `mod svc { ... }` keeps its own
    // file: there the declaring file genuinely is the defining file.
    for code_unit in
        rust.declaration_candidates_by_fqn_while(resolved_module, progress.unwrap_or(&|| true))?
    {
        route_progress_checkpoint(progress)?;
        if code_unit.is_module()
            && !is_external_module_declaration(rust, &code_unit)?
            && (code_unit.source() == importing_file
                || is_visible_module_path_while(rust, &code_unit, progress.unwrap_or(&|| true))?)
        {
            files.push(code_unit.source().clone());
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// Follow a crate-root or dependency-crate module path through public facade
/// exports. The crate-root helper above is retained for the explicit `crate::`
/// path used by local module resolution; this variant also admits a routed
/// dependency root such as `facade::api`.
fn resolve_exported_module_package(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Option<String>> {
    route_progress_checkpoint(progress)?;
    let segments = parse_symbol_path(Language::Rust, module_specifier);
    let Some((root, nested)) = segments.split_first() else {
        return Ok(None);
    };
    if nested.is_empty() || matches!(root.as_str(), "self" | "super") {
        return Ok(None);
    }
    let mut files = if root == "crate" {
        let mut roots =
            cargo_routes_for_progress(rust, progress)?.target_roots_for_file(importing_file);
        if roots.is_empty()
            && rust.is_analyzed(importing_file)
            && rust_package_name(importing_file) == rust_crate_root_package(importing_file)
        {
            roots.push(importing_file.clone());
        }
        roots
    } else {
        let Some(root_file) = cargo_routes_for_progress(rust, progress)?
            .resolve_crate_root_file(importing_file, root)
        else {
            return Ok(None);
        };
        vec![root_file]
    };
    files.retain(|file| rust.is_analyzed(file));
    files.sort();
    files.dedup();
    let _guard = ExportedModuleWalkGuard::enter(importing_file, module_specifier);
    let Some(_guard) = _guard else {
        return Ok(None);
    };
    let mut package = None;
    for segment in nested {
        route_progress_checkpoint(progress)?;
        let Some(resolved) =
            forward_exported_module_fqn_with_progress(rust, token, &files, segment, progress)?
        else {
            return Ok(None);
        };
        files = resolved_module_files_with_progress(rust, importing_file, &resolved, progress)?;
        if files.is_empty() {
            return Ok(None);
        }
        package = Some(resolved);
    }
    Ok(package)
}

/// Resolve an item below a module path whose public spelling reaches the
/// module through one or more structured facade re-exports. The final module
/// package is physical, so its export index no longer carries the fact that
/// the path entered through a glob. Use the item's own public declaration as
/// the terminal proof; a private intermediary module is precisely what the
/// facade walk is permitted to hide.
fn resolve_exported_module_item_fqn(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    item_name: &str,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Option<String>> {
    let Some(module_package) =
        resolve_exported_module_package(rust, token, importing_file, module_specifier, progress)?
    else {
        return Ok(None);
    };
    let target_fqn = join_rust_fqn(&module_package, item_name);
    let mut targets = BTreeSet::new();
    for unit in rust.definitions(&target_fqn) {
        route_progress_checkpoint(progress)?;
        if unit.identifier() == item_name && is_rust_export_visible_declaration(rust, &unit)? {
            targets.insert(unit.fq_name());
        }
    }
    Ok((targets.len() == 1)
        .then(|| targets.into_iter().next())
        .flatten())
}

thread_local! {
    /// The (importing file, module specifier) pairs whose crate-root export
    /// walk is in progress on this thread. Thread-local because the walk is
    /// one call stack, and the walks run on rayon workers in parallel.
    static EXPORTED_MODULE_WALKS: RefCell<HashSet<(ProjectFile, String)>> =
        RefCell::new(HashSet::default());
}

/// Marks one crate-root export walk as in progress for as long as it is on the
/// stack. [`ExportedModuleWalkGuard::enter`] answers `None` when the same walk
/// is already running, which is the cycle.
struct ExportedModuleWalkGuard {
    key: (ProjectFile, String),
}

impl ExportedModuleWalkGuard {
    fn enter(importing_file: &ProjectFile, module_specifier: &str) -> Option<Self> {
        let key = (importing_file.clone(), module_specifier.to_string());
        EXPORTED_MODULE_WALKS
            .with(|walks| walks.borrow_mut().insert(key.clone()))
            .then_some(Self { key })
    }
}

impl Drop for ExportedModuleWalkGuard {
    fn drop(&mut self) {
        EXPORTED_MODULE_WALKS.with(|walks| {
            let removed = walks.borrow_mut().remove(&self.key);
            debug_assert!(removed, "an entered export walk must still be recorded");
        });
    }
}

/// Re-spell one rooted module prefix under a Cargo target's shared kind root.
/// The private target spelling wins whenever it has a physical file or an
/// inline declaration in the importing file. The shared spelling must be
/// backed by a file Cargo classifies as shared; unknown and disjoint roots are
/// never admitted here.
fn resolve_target_kind_root_module_with_progress(
    rust: &dyn RustSource,
    importing_file: &ProjectFile,
    resolved: &str,
    progress: Option<&dyn Fn() -> bool>,
) -> ReferenceContextResult<Option<String>> {
    route_progress_checkpoint(progress)?;
    let files = rust.package_file_index();
    let routes = cargo_routes_for_progress(rust, progress)?;
    if files.files_in_package(resolved).next().is_some() {
        return Ok(None);
    }
    let mut has_inline_module = false;
    let mut declares_external_module = false;
    for unit in rust.definitions(resolved) {
        route_progress_checkpoint(progress)?;
        if !unit.is_module() || unit.source() != importing_file {
            continue;
        }
        if is_external_module_declaration(rust, &unit)? {
            declares_external_module = true;
        } else {
            has_inline_module = true;
        }
    }
    if has_inline_module {
        return Ok(None);
    }
    if !declares_external_module {
        return Ok(None);
    }
    let Some(alternative) = rust_target_kind_root_alternative(importing_file, resolved) else {
        return Ok(None);
    };
    let mut has_shared_file = false;
    for candidate in files.files_in_package(&alternative) {
        route_progress_checkpoint(progress)?;
        if routes.target_relation(importing_file, candidate) == RustCargoTargetRelation::Shared {
            has_shared_file = true;
            break;
        }
    }
    Ok(has_shared_file.then_some(alternative))
}

pub fn exact_member(
    index: &dyn CodeUnitIndex,
    source_file: &ProjectFile,
    owner_name: &str,
    member_name: &str,
    _instance_receiver: bool,
) -> Option<CodeUnit> {
    index
        .declarations(source_file)
        .into_iter()
        .find(|code_unit| {
            code_unit.identifier() == member_name
                && index
                    .parent_of(code_unit)
                    .map(|parent| parent.identifier() == owner_name)
                    .unwrap_or(false)
        })
}

pub fn rust_usage_candidate_files(
    rust: &dyn RustSource,
    export_names: HashSet<String>,
    target: &CodeUnit,
) -> HashSet<ProjectFile> {
    let owner_source = rust
        .parent_of(target)
        .map(|owner| owner.source().clone())
        .unwrap_or_else(|| target.source().clone());
    let member_name = target.identifier().to_string();

    let project = rust.project();
    rust.referencing_files_of(&owner_source)
        .into_iter()
        .filter(|file| {
            project.read_source(file).ok().is_some_and(|source| {
                export_names.iter().any(|name| source.contains(name))
                    || source.contains(&member_name)
            })
        })
        .collect()
}

pub fn trait_implementer_names(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    trait_owner: &CodeUnit,
    keep_going: &dyn Fn() -> bool,
) -> Result<HashSet<String>, RustCargoRouteError> {
    let mut implementer_names = HashSet::default();
    for file in impl_files_of_trait(rust, trait_owner)? {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let facts = rust.canonical_rust_hierarchy_source_facts(&file, keep_going)?;
        let contexts = RustSourceContextIndex::new(facts.as_ref(), keep_going)?;
        let mut types: HashMap<SourceOccurrenceId, _> = HashMap::default();
        for ty in &facts.types {
            assert!(
                types.insert(ty.occurrence, ty).is_none(),
                "one source occurrence cannot own two Rust type facts"
            );
        }

        for impl_fact in &facts.items.impls {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            if impl_fact.negation.is_some()
                || !contexts.is_primary(facts.as_ref(), impl_fact.context)?
            {
                continue;
            }
            let Some(trait_occurrence) = impl_fact.trait_type else {
                continue;
            };
            let Some(target_occurrence) = impl_fact.target_type else {
                continue;
            };
            let trait_ref = types
                .get(&trait_occurrence)
                .copied()
                .expect("published impl trait type has a type source fact");
            let target = types
                .get(&target_occurrence)
                .copied()
                .expect("published impl target type has a type source fact");
            let binder =
                contexts.visible_import_binder(facts.as_ref(), impl_fact.context, keep_going)?;
            let Some(resolved_trait) = resolve_rust_hierarchy_source_ref(
                rust,
                token,
                &file,
                &contexts,
                facts.as_ref(),
                impl_fact.context,
                &binder,
                trait_ref,
                |candidate| is_rust_trait_declaration(rust, candidate),
            )?
            else {
                continue;
            };
            if resolved_trait != *trait_owner {
                continue;
            }
            if let Some(name) = source_type_identifier(target) {
                implementer_names.insert(name.to_string());
            }
        }
    }
    if !keep_going() {
        return Err(RustCargoRouteError::Cancelled);
    }
    Ok(implementer_names)
}

/// The files that hold an `impl` of one trait.
///
/// Every member-level walk across a trait used to read `get_analyzed_files()`
/// and resolve each impl it found, which is a whole-workspace pass per
/// question. The trait-implementation rows already name the blobs, so the walk
/// reads those and applies the same filter to a strictly smaller set: every
/// file the old pass would have kept is still here, because a file with no
/// bound impl of the trait contributed nothing to the answer.
///
/// One blob can be mounted at more than one path, so each blob contributes
/// every path it is mounted at.
pub(crate) fn impl_files_of_trait(
    rust: &dyn RustFactSource,
    trait_owner: &CodeUnit,
) -> Result<Vec<ProjectFile>, RustCargoRouteError> {
    let live = rust.live_blobs();
    let mut files = Vec::new();

    // The trait's source can contain impls whose self type has no indexed
    // nominal identity, so no trait-impl row names that file. It is still a
    // bounded source candidate and the caller resolves each impl structurally.
    if live.oid_for_path(trait_owner.source()).is_some() {
        files.push(trait_owner.source().clone());
    }

    // Impls the relation bound: found by the trait's own placed declaration.
    if let Some(blob) = live.oid_for_path(trait_owner.source()) {
        let facts = rust.canonical_rust_hierarchy_source_facts(trait_owner.source(), &|| true)?;
        let rel_path = brokk_bifrost_core::path_utils::rel_path_string(trait_owner.source());
        for (declaration, unit) in &facts.declaration_units {
            if unit != trait_owner {
                continue;
            }
            let placed = RustPlacedDeclaration {
                rel_path: rel_path.clone(),
                blob,
                declaration: declaration.get(),
            };
            for row in rust.rust_trait_impl_rows(&placed)? {
                files.extend(live_file_at(rust, row.impl_blob, &row.impl_rel_path));
            }
        }
    }

    // Impls the relation could not bind: found by the name they wrote. These
    // have no declaration to be sought by, which is the whole reason their
    // spelling is a row. Handing their files to the same walk lets its own
    // resolver decide them, instead of the caller refusing the question
    // because a spelling somewhere failed.
    for unresolved in rust.rust_unresolved_trait_impl_files(trait_owner.identifier())? {
        files.extend(live_file_at(
            rust,
            unresolved.impl_blob,
            &unresolved.impl_rel_path,
        ));
    }

    files.extend(macro_impl_files_of_trait(rust, trait_owner)?);
    files.sort();
    files.dedup();
    Ok(files)
}

/// The files that could hold an impl of one trait inside a macro's token tree.
///
/// Such an `impl` is not an item until the macro is replayed, so no producer
/// fact and no row describes it. It still decides enumerability -- a macro that
/// can contribute an implementation means the trait's implementations are not
/// exhaustively known -- so the files that could hold one have to be offered
/// to the walk. The bound is the identifier and the macro bit together: a file
/// that never writes this name inside a macro cannot expand to an impl of it.
pub(crate) fn macro_impl_files_of_trait(
    rust: &dyn RustFactSource,
    trait_owner: &CodeUnit,
) -> Result<Vec<ProjectFile>, RustCargoRouteError> {
    let live = rust.live_blobs();
    let mut files = Vec::new();
    for (blob, context) in rust.rust_identifier_occurrence_blobs(trait_owner.identifier())? {
        if context & RUST_OCCURRENCE_MACRO != 0 {
            files.extend(live.paths_for_oid(blob));
        }
    }
    Ok(files)
}

pub fn rust_trait_member_implementations(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    trait_member: &CodeUnit,
) -> ReferenceContextResult<Option<Vec<CodeUnit>>> {
    let Some(trait_owner) = rust.parent_of(trait_member) else {
        return Ok(None);
    };
    if !is_trait_owner(rust, &trait_owner)? {
        return Ok(None);
    }
    let Some(member_kind) = rust_trait_member_kind(rust, trait_member)? else {
        return Ok(None);
    };
    let member_name = trait_member.identifier();

    let mut implementations = Vec::new();
    let mut seen = HashSet::default();
    for file in impl_files_of_trait(rust, &trait_owner)? {
        let facts = rust.canonical_rust_hierarchy_source_facts(&file, &|| true)?;
        let contexts = RustSourceContextIndex::new(facts.as_ref(), &|| true)?;
        let mut types = HashMap::default();
        for ty in &facts.types {
            assert!(
                types.insert(ty.occurrence, ty).is_none(),
                "one source occurrence cannot own two Rust type facts"
            );
        }
        let mut declarations: HashMap<SourceDeclarationId, Vec<&CodeUnit>> = HashMap::default();
        for (declaration, unit) in &facts.declaration_units {
            declarations.entry(*declaration).or_default().push(unit);
        }

        for impl_fact in &facts.items.impls {
            if !contexts.is_primary(facts.as_ref(), impl_fact.context)?
                || impl_fact.negation.is_some()
            {
                continue;
            }
            let Some(trait_occurrence) = impl_fact.trait_type else {
                continue;
            };
            let trait_ref = types
                .get(&trait_occurrence)
                .copied()
                .expect("published impl trait type has a type source fact");
            let binder =
                contexts.visible_import_binder(facts.as_ref(), impl_fact.context, &|| true)?;
            let Some(resolved_trait) = resolve_rust_hierarchy_source_ref(
                rust,
                token,
                &file,
                &contexts,
                facts.as_ref(),
                impl_fact.context,
                &binder,
                trait_ref,
                |candidate| is_rust_trait_declaration(rust, candidate),
            )?
            else {
                continue;
            };
            if resolved_trait != trait_owner {
                continue;
            }
            let expected_syntax_kind = match member_kind {
                RustTraitMemberKind::AssociatedType => "type_item",
                RustTraitMemberKind::Method => "function_item",
            };
            for child in &impl_fact.body_children {
                if child.syntax_kind != expected_syntax_kind {
                    continue;
                }
                let Some(declaration) = child.declaration else {
                    continue;
                };
                let Some(candidates) = declarations.get(&declaration) else {
                    continue;
                };
                for candidate in candidates {
                    if candidate.identifier() != member_name
                        || !rust_code_unit_kind_matches(candidate, member_kind)
                    {
                        continue;
                    }
                    let candidate = (**candidate).clone();
                    if seen.insert(candidate.clone()) {
                        implementations.push(candidate);
                    }
                }
            }
        }
    }
    Ok(Some(implementations))
}

fn any_canonical_declaration_property(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
    predicate: impl FnMut(&RustDeclarationPropertyFact) -> bool,
) -> Result<bool, RustCargoRouteError> {
    let properties = rust.declaration_source_properties(code_unit.source(), &|| true)?;
    let rows = properties
        .get(code_unit)
        .ok_or(RustCargoRouteError::Unavailable)?;
    Ok(rows.iter().any(predicate))
}

pub fn is_rust_trait_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::Trait
    })
}

pub fn is_rust_trait_impl_member_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| property.trait_impl_member)
}

pub fn is_rust_struct_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::Struct
    })
}

/// Whether any source alternative supplies a tuple or unit value constructor.
/// Access constraints remain on the canonical constructor properties; missing
/// declaration publication is an error, not evidence that no constructor exists.
pub fn has_rust_value_constructor(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.value_constructor.is_some()
    })
}

pub fn is_rust_enum_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::Enum
    })
}

pub fn is_rust_enum_variant_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::EnumVariant
    })
}

pub fn is_rust_const_or_static_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        matches!(
            property.kind,
            RustDeclarationKind::Const | RustDeclarationKind::Static
        )
    })
}

pub fn is_rust_type_alias_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::TypeAlias
    })
}

pub fn is_rust_type_member_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.has_impl_or_trait_ancestor
            && matches!(
                property.kind,
                RustDeclarationKind::TypeAlias | RustDeclarationKind::AssociatedType
            )
    })
}

pub fn is_rust_free_function_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::Function && !property.has_impl_or_trait_ancestor
    })
}

pub fn is_rust_module_type_alias_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    if !rust.is_type_alias(code_unit) {
        return Ok(false);
    }
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::TypeAlias && !property.has_impl_or_trait_ancestor
    })
}

pub fn is_rust_module_value_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    any_canonical_declaration_property(rust, code_unit, |property| {
        matches!(
            property.kind,
            RustDeclarationKind::Const | RustDeclarationKind::Static
        ) && matches!(
            property.nearest_declaration_boundary,
            RustDeclarationBoundary::ModuleOrFile | RustDeclarationBoundary::LocalBlockOrFunction
        )
    })
}

pub fn is_rust_macro_export_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    if !code_unit.is_macro() {
        return Ok(false);
    }
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::Macro && property.macro_exported
    })
}

pub fn is_rust_public_like_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    let properties = rust.declaration_source_properties(code_unit.source(), &|| true)?;
    let rows = properties
        .get(code_unit)
        .ok_or(RustCargoRouteError::Unavailable)?;
    Ok(rows
        .iter()
        .any(|property| property.visibility != RustVisibility::Private))
}

/// Whether any source alternative has public, crate, or crate-rooted restricted
/// visibility. Unlike `is_rust_public_like_declaration`, this excludes `pub(self)`
/// and `pub(super)`. Missing source facts are unavailable, never private.
pub fn is_rust_export_visible_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    let properties = rust.declaration_source_properties(code_unit.source(), &|| true)?;
    let rows = properties
        .get(code_unit)
        .ok_or(RustCargoRouteError::Unavailable)?;
    declaration_properties_are_export_visible(rows, &|| true).map_err(Into::into)
}

/// Check export visibility with a source-aware owner walk.
///
/// Rust permits separate Cargo targets to reuse the same module FQN. The
/// generic CodeUnitIndex parent lookup returns the first matching definition,
/// which can select a private module from a Python binding target instead of
/// the public module that owns this declaration. Keep the owner walk on the
/// declaration's Cargo target so export indexes do not lose valid symbols.
pub fn is_module_export_candidate(
    rust: &dyn RustSource,
    file: &ProjectFile,
    code_unit: &CodeUnit,
    export_visible: &HashSet<CodeUnit>,
    external_visibility: &mut HashMap<CodeUnit, bool>,
) -> ReferenceContextResult<bool> {
    is_module_export_candidate_while(
        rust,
        file,
        code_unit,
        export_visible,
        external_visibility,
        &|| true,
    )
}

fn is_module_export_candidate_while(
    rust: &dyn RustSource,
    file: &ProjectFile,
    code_unit: &CodeUnit,
    export_visible: &HashSet<CodeUnit>,
    external_visibility: &mut HashMap<CodeUnit, bool>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<bool> {
    reference_context_checkpoint(progress)?;
    if !export_visible.contains(code_unit) {
        return Ok(false);
    }

    let mut current = code_unit.clone();
    loop {
        reference_context_checkpoint(progress)?;
        let parent = match rust_export_parent_while(rust, &current, progress)? {
            RustExportParent::Parent(parent) => parent,
            RustExportParent::Root => return Ok(true),
            RustExportParent::Ambiguous => return Ok(false),
        };
        let parent_is_export_visible = if parent.source() == file {
            export_visible.contains(&parent)
        } else if let Some(visible) = external_visibility.get(&parent) {
            *visible
        } else {
            let properties = declaration_source_properties_while(rust, parent.source(), progress)?;
            let rows = properties
                .get(&parent)
                .ok_or(RustCargoRouteError::Unavailable)?;
            let visible = declaration_properties_are_export_visible(rows, progress)?;
            external_visibility.insert(parent.clone(), visible);
            visible
        };
        if !parent.is_module() || !parent_is_export_visible {
            return Ok(false);
        }
        current = parent;
    }
}

enum RustExportParent {
    Parent(CodeUnit),
    Root,
    Ambiguous,
}

fn rust_export_parent_while(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<RustExportParent> {
    reference_context_checkpoint(progress)?;
    if let Some(parent) = rust.structural_parent_of(code_unit) {
        return Ok(RustExportParent::Parent(parent));
    }
    let Some(owner_fq_name) = default_parent_fq_name(code_unit) else {
        return Ok(RustExportParent::Root);
    };
    let mut candidates = rust.declaration_candidates_by_fqn_while(&owner_fq_name, progress)?;
    if candidates.is_empty() {
        return Ok(RustExportParent::Root);
    }
    reference_context_checkpoint(progress)?;
    if let Some(local) = rust
        .cargo_routes_while(progress)?
        .candidates_in_same_target_root(code_unit.source(), candidates.clone())
    {
        candidates = local;
    }
    candidates.sort();
    candidates.dedup();
    Ok(match candidates.as_slice() {
        [] => RustExportParent::Root,
        [parent] => RustExportParent::Parent(parent.clone()),
        _ => RustExportParent::Ambiguous,
    })
}

fn is_visible_module_path_while(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<bool> {
    let mut current = code_unit.clone();
    loop {
        reference_context_checkpoint(progress)?;
        if !current.is_module() {
            return Ok(false);
        }
        let properties = declaration_source_properties_while(rust, current.source(), progress)?;
        let rows = properties
            .get(&current)
            .ok_or(RustCargoRouteError::Unavailable)?;
        if !declaration_properties_are_export_visible(rows, progress)? {
            return Ok(false);
        }
        current = match rust_export_parent_while(rust, &current, progress)? {
            RustExportParent::Parent(parent) => parent,
            RustExportParent::Root => return Ok(true),
            RustExportParent::Ambiguous => return Ok(false),
        };
    }
}

/// Whether this module unit is a bodiless `mod x;` item, which forwards to a
/// definition in another file rather than being one.
///
/// Reads the canonical declaration property rather than reparsing syntax:
/// `resolve_module_files` asks this per resolution, and the property cache
/// keeps that path bounded.
pub fn is_external_module_declaration(
    rust: &dyn RustSource,
    code_unit: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    if !code_unit.is_module() {
        return Ok(false);
    }
    any_canonical_declaration_property(rust, code_unit, |property| {
        property.kind == RustDeclarationKind::ExternalModule
    })
}

pub fn rust_declaration_node_is<F>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    predicate: F,
) -> bool
where
    F: for<'tree> Fn(Node<'tree>, &str) -> bool,
{
    let Ok(source) = index.project().read_source(code_unit.source()) else {
        return false;
    };
    let Some(tree) = crate::lexical_scope::parse_rust_tree(&source) else {
        return false;
    };
    inspect_rust_named_declaration_node(index, code_unit, tree.root_node(), &source, predicate)
        .unwrap_or(false)
}

/// Inspect the syntax node for a declaration, including an item written inside
/// one or more item-position macro invocations.
///
/// The ordinary Rust tree parses a macro argument as a token tree. The
/// declaration collector reparses item-shaped arguments and stores their exact
/// source ranges, so metadata readers must repeat that structured reparse. Each
/// loop reparses a smaller enclosing token tree. This keeps nested item macros
/// stack safe and preserves the original byte offsets.
pub fn inspect_rust_named_declaration_node<T>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    root: Node<'_>,
    source: &str,
    inspect: impl for<'tree> Fn(Node<'tree>, &str) -> T,
) -> Option<T> {
    let range = index.ranges(code_unit).into_iter().next()?;
    inspect_rust_named_declaration_node_at_range(code_unit, root, source, range, &|| true, &inspect)
        .flatten()
}

/// Inspect every recorded source occurrence of a declaration in deterministic order.
///
/// `CodeUnit` equality intentionally collapses duplicate declarations such as two
/// `#[cfg]` alternatives or two item-macro expansions. Their navigation ranges still
/// identify distinct syntax occurrences, so metadata readers must inspect each range
/// before grouping it by identity. The inner `None` means that one occurrence has no
/// recoverable AST; the outer `None` means the walk was cancelled.
pub fn inspect_rust_named_declaration_nodes_while<T>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    root: Node<'_>,
    source: &str,
    keep_going: &impl Fn() -> bool,
    inspect: impl for<'tree> Fn(Node<'tree>, &str) -> T,
) -> Option<Vec<Option<T>>> {
    let mut ranges = index.ranges(code_unit);
    ranges.sort_unstable_by_key(|range| {
        (
            range.start_byte,
            range.end_byte,
            range.start_line,
            range.end_line,
        )
    });

    let mut occurrences = Vec::with_capacity(ranges.len());
    for range in ranges {
        if !keep_going() {
            return None;
        }
        occurrences.push(inspect_rust_named_declaration_node_at_range(
            code_unit, root, source, range, keep_going, &inspect,
        )?);
    }
    if !keep_going() {
        return None;
    }
    Some(occurrences)
}

fn inspect_rust_named_declaration_node_at_range<T>(
    code_unit: &CodeUnit,
    root: Node<'_>,
    source: &str,
    range: Range,
    keep_going: &impl Fn() -> bool,
    inspect: &impl for<'tree> Fn(Node<'tree>, &str) -> T,
) -> Option<Option<T>> {
    if let Some(node) = rust_named_declaration_node_at_range(code_unit, root, source, range) {
        return Some(Some(inspect(node, source)));
    }

    let Some(mut region) =
        enclosing_macro_token_tree_interior(root, range.start_byte, range.end_byte)
    else {
        return Some(None);
    };
    loop {
        if !keep_going() {
            return None;
        }
        let Some(tree) = crate::lexical_scope::parse_rust_region_tree(source, region.0, region.1)
        else {
            return Some(None);
        };
        let reparsed_root = tree.root_node();
        if let Some(node) =
            rust_named_declaration_node_at_range(code_unit, reparsed_root, source, range)
        {
            return Some(Some(inspect(node, source)));
        }
        let Some(next) =
            enclosing_macro_token_tree_interior(reparsed_root, range.start_byte, range.end_byte)
        else {
            return Some(None);
        };
        if next == region {
            return Some(None);
        }
        region = next;
    }
}

fn enclosing_macro_token_tree_interior(
    root: Node<'_>,
    start_byte: usize,
    end_byte: usize,
) -> Option<(usize, usize)> {
    let mut node = root.descendant_for_byte_range(start_byte, end_byte)?;
    loop {
        if node.kind() == "macro_invocation" {
            let arguments = crate::declarations::rust_macro_invocation_arguments(node)?;
            let open = arguments.child(0)?;
            let close = arguments.child(arguments.child_count().checked_sub(1)?)?;
            if matches!(open.kind(), "(" | "[" | "{")
                && matches!(close.kind(), ")" | "]" | "}")
                && open.end_byte() <= start_byte
                && end_byte <= close.start_byte()
            {
                return Some((open.end_byte(), close.start_byte()));
            }
        }
        node = node.parent()?;
    }
}

pub fn rust_named_declaration_node<'tree>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    root: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let range = index.ranges(code_unit).into_iter().next()?;
    rust_named_declaration_node_at_range(code_unit, root, source, range)
}

fn rust_named_declaration_node_at_range<'tree>(
    code_unit: &CodeUnit,
    root: Node<'tree>,
    source: &str,
    range: Range,
) -> Option<Node<'tree>> {
    let mut node = root.descendant_for_byte_range(range.start_byte, range.end_byte)?;
    loop {
        if node
            .child_by_field_name("name")
            .is_some_and(|name| rust_declaration_name_matches(name, source, code_unit.identifier()))
        {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn rust_declaration_name_matches(name: Node<'_>, source: &str, identifier: &str) -> bool {
    rust_node_text(name, source).trim() == identifier
}

pub fn rust_declaration_node<'tree>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    root: Node<'tree>,
) -> Option<Node<'tree>> {
    let ranges = index.ranges(code_unit);
    let range = ranges.first()?;
    root.descendant_for_byte_range(range.start_byte, range.end_byte)
}

/// The visibility constraints on the value constructor introduced by a tuple
/// or unit struct. Named-field structs are constructed in the type namespace
/// and therefore return `None`.
///
/// Extract only the value-constructor constraints beyond the declaration's
/// own visibility. The declaration producer stores that visibility separately,
/// so canonical property rows do not duplicate it as the first vector entry.
pub fn rust_value_constructor_properties(
    node: Node<'_>,
    source: &str,
) -> Option<RustValueConstructorProperties> {
    if node.kind() != "struct_item" {
        return None;
    }

    let mut field_visibilities = Vec::new();
    match node.child_by_field_name("body") {
        None => {}
        Some(body) if body.kind() == "ordered_field_declaration_list" => {
            let mut pending_visibility = None;
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                match child.kind() {
                    "attribute_item"
                    | "inner_attribute_item"
                    | "line_comment"
                    | "block_comment" => {}
                    "visibility_modifier" => {
                        pending_visibility = Some(rust_visibility_modifier(child, source));
                    }
                    _ => field_visibilities
                        .push(pending_visibility.take().unwrap_or(RustVisibility::Private)),
                }
            }
        }
        Some(_) => return None,
    }

    Some(RustValueConstructorProperties {
        field_visibilities,
        non_exhaustive: rust_item_has_attribute(node, source, "non_exhaustive"),
    })
}

fn rust_visibility_modifier(node: Node<'_>, source: &str) -> RustVisibility {
    crate::imports::rust_visibility_from_modifier(node, source)
}

#[derive(Clone, Copy)]
enum RustTraitMemberKind {
    AssociatedType,
    Method,
}

fn rust_trait_member_kind(
    rust: &dyn RustFactSource,
    trait_member: &CodeUnit,
) -> Result<Option<RustTraitMemberKind>, RustCargoRouteError> {
    if trait_member.is_function() {
        return Ok(Some(RustTraitMemberKind::Method));
    }
    if (trait_member.is_field() || trait_member.is_class())
        && any_canonical_declaration_property(rust, trait_member, |property| {
            matches!(
                property.kind,
                RustDeclarationKind::TypeAlias | RustDeclarationKind::AssociatedType
            )
        })?
    {
        return Ok(Some(RustTraitMemberKind::AssociatedType));
    }
    Ok(None)
}

fn rust_code_unit_kind_matches(code_unit: &CodeUnit, member_kind: RustTraitMemberKind) -> bool {
    match member_kind {
        RustTraitMemberKind::AssociatedType => code_unit.is_class(),
        RustTraitMemberKind::Method => code_unit.is_function(),
    }
}

/// The files that can back the module at `relative_module`, relative to
/// `file`'s own directory: `name.rs`, `name/mod.rs`, and the two `src/`-rooted
/// forms a crate root uses.
pub fn rust_module_files_at(file: &ProjectFile, relative_module: &Path) -> Vec<ProjectFile> {
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        Path::new("src").join(relative_module).with_extension("rs"),
        Path::new("src").join(relative_module).join("mod.rs"),
    ] {
        let candidate = file.with_rel_path(rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

pub fn rust_module_files_from_path(file: &ProjectFile, module_specifier: &str) -> Vec<ProjectFile> {
    let Some(relative_module) = rust_relative_module_path(file, module_specifier) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        PathBuf::from("src")
            .join(&relative_module)
            .with_extension("rs"),
        PathBuf::from("src").join(&relative_module).join("mod.rs"),
    ] {
        let candidate = ProjectFile::new(file.root().to_path_buf(), rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

pub fn rust_module_files_from_segments(
    file: &ProjectFile,
    segments: &[String],
) -> Vec<ProjectFile> {
    let Some(relative_module) = rust_relative_module_segments(file, segments) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        PathBuf::from("src")
            .join(&relative_module)
            .with_extension("rs"),
        PathBuf::from("src").join(&relative_module).join("mod.rs"),
    ] {
        let candidate = ProjectFile::new(file.root().to_path_buf(), rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

pub fn rust_relative_module_segments(file: &ProjectFile, segments: &[String]) -> Option<PathBuf> {
    let (first, rest) = segments.split_first()?;
    let append = |base: &mut PathBuf, parts: &[String]| {
        for part in parts {
            base.push(part);
        }
    };
    let mut module = match first.as_str() {
        "crate" | "self" => {
            let mut path = PathBuf::new();
            append(&mut path, rest);
            path
        }
        "super" => {
            let mut path = file
                .parent()
                .parent()
                .unwrap_or(Path::new(""))
                .to_path_buf();
            let mut index = 0;
            while rest.get(index).is_some_and(|part| part == "super") {
                path.pop();
                index += 1;
            }
            append(&mut path, &rest[index..]);
            path
        }
        crate_name if Some(crate_name) == crate_naming::rust_file_crate_name(file).as_deref() => {
            let mut path = PathBuf::new();
            append(&mut path, rest);
            path
        }
        _ => {
            let parent = file.rel_path().parent().unwrap_or(Path::new(""));
            let stem = file.rel_path().file_stem()?.to_str()?;
            let mut path = if matches!(stem, "lib" | "main" | "mod") {
                parent.to_path_buf()
            } else {
                parent.join(stem)
            };
            append(&mut path, segments);
            path
        }
    };
    (!module.as_os_str().is_empty()).then_some(std::mem::take(&mut module))
}

pub fn rust_relative_module_path(file: &ProjectFile, module_specifier: &str) -> Option<PathBuf> {
    let module = module_specifier
        .strip_prefix("crate::")
        .or_else(|| module_specifier.strip_prefix("self::"))
        .map(PathBuf::from)
        .or_else(|| {
            module_specifier
                .strip_prefix("super::")
                .map(|rest| file.parent().parent().unwrap_or(Path::new("")).join(rest))
        })
        .or_else(|| {
            let (crate_name, rest) = module_specifier.split_once("::")?;
            (Some(crate_name) == crate_naming::rust_file_crate_name(file).as_deref())
                .then(|| rest.into())
        })
        .or_else(|| {
            let relative = PathBuf::from(module_specifier);
            if relative.as_os_str().is_empty() {
                return None;
            }
            let parent = file.rel_path().parent().unwrap_or(Path::new(""));
            let stem = file.rel_path().file_stem()?.to_str()?;
            let module_root = if matches!(stem, "lib" | "main" | "mod") {
                parent.to_path_buf()
            } else {
                parent.join(stem)
            };
            Some(module_root.join(relative))
        })?;
    Some(module.to_string_lossy().replace("::", "/").into())
}

pub fn resolve_direct_import_files(
    rust: &dyn RustSource,
    importing_file: &ProjectFile,
    segments: &[String],
) -> Vec<ProjectFile> {
    let analyzed_files = rust.package_file_index();
    let package = rust_package_name(importing_file);
    let crate_package = rust_crate_root_package(importing_file);

    for end in (1..=segments.len()).rev() {
        let prefix = &segments[..end];
        let module_specifier = prefix.join("::");
        let rooted = is_rooted_rust_module_path(&module_specifier);
        let resolved_modules = if rooted {
            resolve_rust_module_path_with_crate(&package, &crate_package, &module_specifier)
                .into_iter()
                .collect::<Vec<_>>()
        } else if let Some((root, nested)) = prefix.split_first()
            && !analyzed_files.crate_packages(root).is_empty()
        {
            let suffix = nested.join(".");
            analyzed_files
                .crate_packages(root)
                .iter()
                .map(|package| {
                    if suffix.is_empty() {
                        package.clone()
                    } else {
                        format!("{package}.{suffix}")
                    }
                })
                .collect()
        } else {
            resolve_rust_module_path_with_crate(&package, &crate_package, &module_specifier)
                .into_iter()
                .collect()
        };
        let files = resolved_modules
            .into_iter()
            .flat_map(|module| {
                analyzed_files
                    .files_in_package(&module)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        if !files.is_empty() {
            return files;
        }
    }

    Vec::new()
}
