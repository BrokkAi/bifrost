//! Bounded Rust lowering for immutable common resolution facts.
//!
//! This first production tranche is intentionally fail closed. It records the
//! exact lexical substrate needed by simple local and broad lookups. Syntax
//! outside that substrate receives a producer-owned site gap; no blanket
//! whole-file gap hides which position or binder surface remains unsupported.
//! No selected route, filesystem fact, or resolved target enters the
//! content-owned result.

use std::collections::{HashMap, HashSet};

use brokk_bifrost_core::analyzer::model::DeclarationKind;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
    FileResolutionFacts, IntrinsicTypeKind, IntrinsicTypeSeedFact, PositionedIdentifierFact,
    ResolutionAdditionalDefinitionNamespaceFact, ResolutionBinderFact, ResolutionBinderKind,
    ResolutionCallArgumentFact, ResolutionCallExpectedResultFact, ResolutionCallFact,
    ResolutionCallOwnerTypeSegmentFact, ResolutionCallTypeArgumentFact,
    ResolutionCallableParameterFact, ResolutionCallableReceiverFact,
    ResolutionCallableReceiverForm, ResolutionCallableReceiverOrigin,
    ResolutionCallableReceiverOriginFact, ResolutionCallableResultBindingFact,
    ResolutionCallableResultTypeParameterFact, ResolutionCallableSignatureFact,
    ResolutionConditionalBinderFact, ResolutionDeclarationVisibilityFact,
    ResolutionDeclaredTypeRelationFact, ResolutionDeclaredTypeRelationKind,
    ResolutionDeferredMemberOwnerFact, ResolutionDefinitionUnitFact,
    ResolutionEngineRuleEligibilityFact, ResolutionEngineRuleKind, ResolutionGapFact,
    ResolutionGapKind, ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility, ResolutionNameFact,
    ResolutionNameId, ResolutionNamespace, ResolutionReferenceEnumerationGapFact,
    ResolutionReferenceOwnerFact, ResolutionRelationMemberFact, ResolutionRootExportFact,
    ResolutionRootImportAnchor, ResolutionRootImportDemandFact, ResolutionRootImportDemandTarget,
    ResolutionRootImportDemandTargetFact, ResolutionRootImportFact, ResolutionRootImportKind,
    ResolutionRootImportKindFact, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionScopeFact, ResolutionScopeId,
    ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
    ResolutionSiteKind, ResolutionSupertypeFact, ResolutionSupertypeKind, ResolutionTypeRelationId,
    ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
    ResolutionVisibilityEligibilityFact,
};
use brokk_bifrost_core::analyzer::rust_facts::{
    RustDeclarationPropertyFact, RustItemMacroSourcePosition,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceFactRows, SourceOccurrenceId,
    SourceOccurrenceProvenance,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{OccurrenceClass, OccurrenceRole};
use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, HoistingClass};
use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
use brokk_bifrost_core::analyzer::tree_walk::TreeWalkAction;
use tree_sitter::Node;

use crate::declaration_properties::RustDeclarationPropertyCollector;
#[cfg(test)]
use crate::declarations::{
    RustRawRulesItemMacroDefinition, rust_macro_invocation_source_position, walk_rust_primary_tree,
};
use crate::declarations::{
    RustRulesItemMacroDefinition, rust_node_text, rust_parameters_have_self,
    rust_unqualified_macro_invocation_name,
};
use crate::graph_support::{rust_path_is_leading_absolute, rust_path_segments};
#[cfg(test)]
use crate::imports::rust_import_projection_with_source_nodes;
use crate::imports::{RustProjectedImport, RustVisibility};
use crate::lexical_scope::{RustCfgCondition, rust_cfg_condition};
use crate::structural::{call_function_target, rust_occurrence_role, rust_receiver_operand};

#[cfg(test)]
pub(super) fn extract_rust_resolution_facts(root: Node<'_>, source: &str) -> FileResolutionFacts {
    let item_macros = crate::declarations::rust_rules_item_macro_definitions(root, source);
    let item_macros_by_end = item_macros
        .iter()
        .map(|definition| (definition.visible_after, definition))
        .collect::<HashMap<_, _>>();
    let mut builder = RustResolutionBuilder::new(root, source);
    walk_rust_primary_tree(
        root,
        &mut builder,
        |node, _declaration_active, native_active, builder| {
            let action = if native_active {
                if node.is_named() {
                    let projected_imports =
                        matches!(node.kind(), "use_declaration" | "extern_crate_declaration")
                            .then(|| {
                                rust_import_projection_with_source_nodes(node, source, "")
                                    .into_iter().map(|(mut import, nodes)| {
                                        import.source_occurrences = Some(brokk_bifrost_core::analyzer::rust_facts::RustImportSourceOccurrences {
                                            declaration: builder.source_collector.intern_node(nodes.declaration),
                                            target: nodes.target.map(|node| builder.source_collector.intern_node(node)),
                                            alias: nodes.alias.map(|node| builder.source_collector.intern_node(node)),
                                        });
                                        import
                                    }).collect::<Vec<_>>()
                            });
                    let macro_definition = if node.kind() == "macro_definition" {
                        item_macros_by_end
                            .get(&node.end_byte())
                            .map(|raw| builder.test_macro_definition(node, raw))
                    } else {
                        None
                    };
                    builder.enter(
                        node,
                        projected_imports.as_deref(),
                        macro_definition.as_ref(),
                        (node.kind() == "macro_invocation")
                            .then(|| rust_macro_invocation_source_position(node)),
                    )
                } else {
                    TreeWalkAction::Descend
                }
            } else {
                TreeWalkAction::Skip
            };
            (true, action)
        },
        |native_exit, builder| {
            if native_exit {
                builder.exit();
            }
        },
    );
    builder.finish().facts
}

#[derive(Clone, Copy, Debug)]
enum ExitAction {
    Scope,
    DeclarationScope,
    DeclarationOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustPatternBindingPosition {
    Irrefutable,
    Refutable,
    MacroRefutable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustItemAttributeBoundary {
    SourcePreserving,
    GeneratedSurface,
    /// A derive surface whose `#[serde(..)]` helper is inert only if a bare
    /// derive name the file does not bind is serde's derive
    /// (`rust_item_serde_helper_derive`). The item is kept, its binder is
    /// left open, and the crate route decides.
    ConditionalSerdeHelper,
    Transforming,
}

#[derive(Clone, Copy, Debug)]
struct PendingScope {
    scope: ResolutionScopeId,
    callable: Option<ResolutionSiteId>,
}

/// One `let` binding waiting for the typed slot that its initializer
/// expression produces.
///
/// `unwrap_layers` counts the `?`, `.unwrap()` and `.expect(..)` layers written
/// between that expression and the binding. Each layer discharges one unproven
/// `Option`/`Result` indirection layer through its own intermediate call-result
/// slot, and the zero-delta `Initialization` transfer then carries the last one
/// into the binding unchanged.
#[derive(Clone, Copy, Debug)]
struct PendingCallInitialization {
    declaration: ResolutionSiteId,
    target: ResolutionTypeSlotId,
    unwrap_layers: usize,
}

/// One lowered ordinary parameter a callable-parameter row can name, with the
/// declared type its value slot takes.
#[derive(Clone, Copy, Debug)]
struct LoweredParameter {
    declaration: ResolutionSiteId,
    value_type: ResolutionTypeSlotId,
    declared_type: Option<LoweredDeclaredType>,
}

/// One call argument slot waiting for the value its operand expression
/// produces, and the `&` layers written around that operand.
#[derive(Clone, Copy, Debug)]
struct PendingArgument {
    argument: ResolutionTypeSlotId,
    reference_layers: i8,
}

#[derive(Clone, Copy, Debug)]
struct InherentImplContext {
    subject: ResolutionTypeSlotId,
    receiver_subject: ResolutionTypeSlotId,
    relation: ResolutionTypeRelationId,
    next_member_ordinal: u32,
    supports_standard_self: bool,
}

#[derive(Clone, Copy, Debug)]
struct RustSelfTypes {
    nominal: ResolutionTypeSlotId,
    receiver: ResolutionTypeSlotId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoweredDeclaredType {
    identity: ResolutionTypeSlotId,
    indirection: i8,
    reference_indirection: i8,
    /// The name of the bare type identifier the wrappers ended on, when they
    /// ended on one; a type parameter is always such a head.
    head_name: Option<ResolutionNameId>,
}

/// The `impl` or trait a declaration is a direct member of: its syntax node id
/// and whether it is a trait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemberOwner {
    node: usize,
    is_trait: bool,
}

struct PendingMacroFragment {
    binding: crate::macro_matcher::MacroBinding,
    /// Parsed at queue time so that one fragment costs exactly one parse.
    tree: tree_sitter::Tree,
    scope: ResolutionScopeId,
    owner: Option<ResolutionSiteId>,
    /// Where an `item` fragment's item lands. Only a capsule knows it is
    /// anything but lexical; every other fragment is lowered in place.
    container: crate::macro_matcher::RustMacroItemContainer,
    /// Macro arguments use embedded occurrence identity; source-authored
    /// proc-attribute expressions use explicit source subspans.
    occurrence_provenance: SourceOccurrenceProvenance,
    /// The impl or trait whose `Self` the fragment's paths mean.
    self_owner: Option<MacroFragmentSelfOwner>,
}

struct RetainedMacroFragmentTree {
    tree: tree_sitter::Tree,
    scope: ResolutionScopeId,
    owner: Option<ResolutionSiteId>,
    transcriber_range: Option<(usize, usize)>,
}

/// The impl or trait that encloses a macro invocation, which is what `Self`
/// means inside the invocation's fragments.
///
/// A fragment is parsed as a tree of its own, so its nodes have no impl or
/// trait ancestor; the invocation has one. Without this, `Self::check()` in
/// `assert!(Self::check())` had no owner, took an `UnsupportedScopeOrBinder`
/// gap, and never resolved, while the same path outside the macro did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MacroFragmentSelfOwner {
    /// The `impl` item, by node id: its self-type frontier.
    Impl(usize),
    /// The trait item, by node id, and the lower bound its body's `Self::`
    /// paths take. The bound is minted when the invocation's fragments write
    /// a `Self::` path, as it is for the trait body itself.
    Trait {
        item: usize,
        lower_bound: Option<ResolutionTypeSlotId>,
    },
}

impl MacroFragmentSelfOwner {
    const fn item(self) -> usize {
        match self {
            Self::Impl(item) | Self::Trait { item, .. } => item,
        }
    }
}

/// What `RustResolutionBuilder::push_macro_binding_fragment` did with one
/// matched macro binding.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MacroBindingLowering {
    /// The binding's references are queued for the ordinary fragment walk.
    Queued,
    /// The binding carries no reference role, or published its paths already.
    Ignored,
    /// The interior declares names, so lowering it needs declaration authority
    /// the caller has to claim.
    NeedsDeclarations,
}

/// What a visible `macro_rules!` definition's rules are proven to expand to.
#[derive(Clone, Copy, Debug)]
struct MacroExpansionProofs {
    passthrough: bool,
    declares_no_item: bool,
    writes_only_impls: bool,
}

struct ExportedMacroDefinition {
    source: brokk_bifrost_core::analyzer::rust_facts::RustMacroDefinitionSourceFact,
    transcribers: Vec<Option<crate::macro_matcher::MacroTranscriber>>,
    proofs: MacroExpansionProofs,
    declares_no_item_arms: Vec<bool>,
}

struct LocalMacroDefinition {
    scope: ResolutionScopeId,
    visible_after: usize,
    /// The definition is a proven item passthrough
    /// (`RustRulesItemMacroDefinition::passthrough`), the same proof the
    /// crate's item-macro decision reads.
    passthrough: bool,
    /// No rule can write an item
    /// (`RustRulesItemMacroDefinition::declares_no_item`).
    declares_no_item: bool,
    /// Every rule writes only `impl` blocks
    /// (`RustRulesItemMacroDefinition::writes_only_impls`).
    writes_only_impls: bool,
    declares_no_item_arms: Vec<bool>,
    source: brokk_bifrost_core::analyzer::rust_facts::RustMacroDefinitionSourceFact,
    transcribers: Vec<Option<crate::macro_matcher::MacroTranscriber>>,
}

pub(crate) struct RustResolutionBuilder<'source> {
    source: &'source str,
    source_collector: PrimarySourceFactCollector<'source>,
    declaration_properties: RustDeclarationPropertyCollector<'source>,
    site_occurrences: Vec<SourceOccurrenceId>,
    declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    facts: FileResolutionFacts,
    names: HashMap<String, ResolutionNameId>,
    scopes: Vec<ResolutionScopeId>,
    declaration_owners: Vec<ResolutionSiteId>,
    pending_scopes: HashMap<usize, PendingScope>,
    item_scopes: HashMap<ResolutionScopeId, ResolutionScopeId>,
    handled_identifiers: HashSet<usize>,
    type_reference_identities: HashMap<(usize, ResolutionScopeId), ResolutionTypeSlotId>,
    consumed_subtrees: HashSet<usize>,
    pending_glob_imports: Vec<ResolutionSiteId>,
    inherent_impls: HashMap<usize, InherentImplContext>,
    inherent_method_owner_types: HashMap<ResolutionSiteId, ResolutionTypeSlotId>,
    self_type_frontiers: HashMap<usize, RustSelfTypes>,
    /// The scope that binds each lowered trait's own name, kept so a
    /// `Self::`-qualified lookup inside its body can mint the trait's lower
    /// bound without re-walking to the declaration.
    trait_self_bound_scopes: HashMap<usize, ResolutionScopeId>,
    /// The lower bound each trait lends its `Self::` qualifiers, minted on
    /// first use so a trait whose body writes no `Self::` path publishes
    /// nothing extra.
    trait_self_lower_bounds: HashMap<usize, ResolutionTypeSlotId>,
    pending_call_initializations: HashMap<usize, Vec<PendingCallInitialization>>,
    pending_receiver_slots: HashMap<usize, Vec<ResolutionTypeSlotId>>,
    /// Per `?` operand still to be lowered, the call-result slots its value
    /// reaches with one `Option`/`Result` layer removed.
    pending_unwrapped_receiver_slots: HashMap<usize, Vec<ResolutionTypeSlotId>>,
    /// Prelude fall-through root references, published at `finish` for the
    /// sites no other root reference claims: a route head (`::Option`, a
    /// `use` prefix) already has one, and a site has one root reference row.
    prelude_fall_throughs: Vec<ResolutionRootReferenceFact>,
    /// Argument slots waiting for the value their expression node produces.
    /// The walk is pre-order, so a call is lowered before its arguments.
    pending_argument_slots: HashMap<usize, PendingArgument>,
    /// A call that initializes an annotated `let`, waiting to be lowered: the
    /// annotation is the type its result is expected to have.
    pending_expected_results: HashMap<usize, LoweredDeclaredType>,
    /// A callable whose declared result is one of its own type parameters,
    /// waiting for its parameters: those declared as the same type parameter
    /// decide the result at each call.
    callable_result_heads: HashMap<ResolutionSiteId, LoweredDeclaredType>,
    exits: Vec<ExitAction>,
    declaration_sites: HashMap<usize, ResolutionSiteId>,
    macro_fragment_trees: Vec<RetainedMacroFragmentTree>,
    macro_definitions: HashMap<String, Vec<LocalMacroDefinition>>,
    /// Each `#[macro_export]` definition's source fact and its expansion
    /// proofs; `None` when the name is exported twice.
    exported_macro_definitions: HashMap<String, Option<ExportedMacroDefinition>>,
    pending_macro_fragments: Vec<PendingMacroFragment>,
    lowering_macro_fragments: bool,
    /// The `Self` owner of the macro fragment being lowered, if any.
    macro_fragment_self_owner: Option<MacroFragmentSelfOwner>,
    macro_fragment_nodes: HashSet<usize>,
    explicit_source_fragment_nodes: HashSet<usize>,
    /// Root item nodes of capsule `item` fragments that expand into an `impl`
    /// or trait body; see [`Self::lower_associated_macro_item`].
    associated_macro_items: HashSet<usize>,
    /// Items whose `serde` helper depends on a derive only the crate route can
    /// resolve (`RustItemAttributeBoundary::ConditionalSerdeHelper`).
    conditional_serde_items: HashSet<usize>,
    /// The occurrence map of the embedded replay tree this lowering is walking,
    /// moved in for the walk and moved back out after it.
    ///
    /// While it is set, every occurrence and every declaration this lowering
    /// interns goes through it, so an item declaration replay already made is
    /// the one this walk publishes a site for.
    /// `PrimarySourceFactCollector::push_occurrence` allocates unconditionally
    /// and `declare` keys on `(occurrence, name)`, so interning the same bytes
    /// twice would give one source item two declarations, which is the split
    /// `lower_macro_bindings` documents as the thing not to do.
    embedded_identity: Option<crate::declarations::RustEmbeddedSourceMap>,
    /// The declaration replay made for each node of the embedded tree this
    /// lowering is walking, so every reader of a node's property finds replay's
    /// row rather than looking in the primary-by-node map, which by
    /// construction never holds an embedded declaration. Cleared with the walk,
    /// because a dropped tree's node ids may be reused.
    embedded_declarations: HashMap<usize, SourceDeclarationId>,
    /// Item-macro invocations whose interior this lowering already declared, so
    /// `lower_macro_bindings` does not also report the item frontier it no
    /// longer has.
    discharged_item_macros: HashSet<usize>,
    /// While a passthrough invocation written in an `impl` or trait body is
    /// being lowered, that `impl` or trait: the expansion's items are its
    /// members. See [`Self::member_owner`].
    replayed_member_owner: Option<MemberOwner>,
}

pub(crate) struct RustResolutionOutput {
    pub(crate) facts: FileResolutionFacts,
    pub(crate) source_facts: SourceFactRows,
    /// Dense native sites are an interpretation index over canonical source
    /// occurrences, not a second positioned source identity.
    pub(crate) site_occurrences: Vec<SourceOccurrenceId>,
    pub(crate) declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    pub(crate) declaration_properties: Vec<RustDeclarationPropertyFact>,
}

impl<'source> RustResolutionBuilder<'source> {
    pub(crate) fn new(root: Node<'_>, source: &'source str) -> Self {
        let compilation = ResolutionScopeId::new(0);
        let mut exported_macro_definitions = HashMap::new();
        for node in crate::macro_matcher::exported_macro_definition_nodes(root, source) {
            let name = node
                .child_by_field_name("name")
                .expect("captured macro is named");
            exported_macro_definitions
                .entry(rust_node_text(name, source).to_owned())
                .and_modify(|definition| *definition = None)
                .or_insert_with(|| {
                    Some(ExportedMacroDefinition {
                        source: crate::macro_matcher::capture_syntax_macro_definition(node, source),
                        transcribers: crate::macro_matcher::capture_macro_transcribers(
                            node, source,
                        ),
                        proofs: MacroExpansionProofs {
                            passthrough: false,
                            declares_no_item:
                                crate::declarations::rust_macro_definition_declares_no_item(
                                    node, source,
                                ),
                            writes_only_impls:
                                crate::declarations::rust_macro_definition_writes_only_impls(
                                    node, source,
                                ),
                        },
                        declares_no_item_arms:
                            crate::declarations::rust_macro_definition_no_item_arms(node, source),
                    })
                });
        }
        Self {
            source,
            source_collector: PrimarySourceFactCollector::new(source),
            declaration_properties: RustDeclarationPropertyCollector::new(source),
            site_occurrences: Vec::new(),
            declaration_sources: Vec::new(),
            facts: FileResolutionFacts {
                scopes: vec![ResolutionScopeFact {
                    id: compilation,
                    parent: None,
                    owner: None,
                    kind: ResolutionScopeKind::CompilationUnit,
                    inheritance: ResolutionScopeInheritance::Lexical,
                    start_byte: root.start_byte(),
                    end_byte: root.end_byte(),
                }],
                ..FileResolutionFacts::default()
            },
            names: HashMap::new(),
            scopes: vec![compilation],
            declaration_owners: Vec::new(),
            pending_scopes: HashMap::new(),
            item_scopes: HashMap::new(),
            handled_identifiers: HashSet::new(),
            type_reference_identities: HashMap::new(),
            consumed_subtrees: HashSet::new(),
            pending_glob_imports: Vec::new(),
            inherent_impls: HashMap::new(),
            inherent_method_owner_types: HashMap::new(),
            self_type_frontiers: HashMap::new(),
            trait_self_bound_scopes: HashMap::new(),
            trait_self_lower_bounds: HashMap::new(),
            pending_call_initializations: HashMap::new(),
            pending_receiver_slots: HashMap::new(),
            pending_unwrapped_receiver_slots: HashMap::new(),
            prelude_fall_throughs: Vec::new(),
            pending_argument_slots: HashMap::new(),
            pending_expected_results: HashMap::new(),
            callable_result_heads: HashMap::new(),
            exits: Vec::new(),
            declaration_sites: HashMap::new(),
            macro_fragment_trees: Vec::new(),
            macro_definitions: HashMap::new(),
            exported_macro_definitions,
            pending_macro_fragments: Vec::new(),
            lowering_macro_fragments: false,
            macro_fragment_self_owner: None,
            macro_fragment_nodes: HashSet::new(),
            explicit_source_fragment_nodes: HashSet::new(),
            associated_macro_items: HashSet::new(),
            conditional_serde_items: HashSet::new(),
            embedded_identity: None,
            embedded_declarations: HashMap::default(),
            discharged_item_macros: HashSet::new(),
            replayed_member_owner: None,
        }
    }

    pub(crate) fn source_collector_mut(&mut self) -> &mut PrimarySourceFactCollector<'source> {
        &mut self.source_collector
    }

    pub(crate) fn source_collectors_mut(
        &mut self,
    ) -> (
        &mut PrimarySourceFactCollector<'source>,
        &mut RustDeclarationPropertyCollector<'source>,
    ) {
        (&mut self.source_collector, &mut self.declaration_properties)
    }

    pub(crate) fn module_body_scope(&self, module: Node<'_>) -> Option<ResolutionScopeId> {
        debug_assert_eq!(module.kind(), "mod_item");
        let body = module.child_by_field_name("body")?;
        let scope = self.pending_scopes.get(&body.id())?.scope;
        debug_assert_eq!(
            self.facts.scopes[scope.index()].kind,
            ResolutionScopeKind::Package
        );
        Some(scope)
    }

    pub(crate) fn finish(mut self) -> RustResolutionOutput {
        let rooted = self
            .facts
            .root_references
            .iter()
            .map(|root| root.reference)
            .collect::<HashSet<_>>();
        let fall_throughs = std::mem::take(&mut self.prelude_fall_throughs);
        self.facts.root_references.extend(
            fall_throughs
                .into_iter()
                .filter(|fall_through| !rooted.contains(&fall_through.reference)),
        );
        assert!(self.pending_macro_fragments.is_empty());
        assert!(!self.lowering_macro_fragments);
        assert_eq!(self.scopes, [ResolutionScopeId::new(0)]);
        assert!(self.declaration_owners.is_empty());
        assert!(self.exits.is_empty());
        assert!(self.pending_scopes.is_empty());
        assert!(
            self.pending_call_initializations.is_empty(),
            "every let initializer's producing expression is lowered: {:?}",
            self.pending_call_initializations
        );

        assert!(
            self.pending_receiver_slots.is_empty(),
            "every computed receiver is lowered: {:?}",
            self.pending_receiver_slots
        );
        assert!(
            self.pending_unwrapped_receiver_slots.is_empty(),
            "every `?` receiver operand is lowered: {:?}",
            self.pending_unwrapped_receiver_slots
        );
        assert!(
            self.pending_argument_slots.is_empty(),
            "every call argument expression is lowered: {:?}",
            self.pending_argument_slots
        );
        assert!(
            self.pending_expected_results.is_empty(),
            "every annotated let's call initializer is lowered: {:?}",
            self.pending_expected_results
        );
        assert!(
            self.callable_result_heads.is_empty(),
            "every generic result meets its callable's parameters: {:?}",
            self.callable_result_heads
        );

        self.lower_glob_import_demands();
        self.declare_open_member_surfaces();

        validate_rust_resolution_facts(&self.facts);
        assert_eq!(self.site_occurrences.len(), self.facts.sites.len());
        RustResolutionOutput {
            facts: self.facts,
            source_facts: self.source_collector.finish(),
            site_occurrences: self.site_occurrences,
            declaration_sources: self.declaration_sources,
            declaration_properties: self.declaration_properties.into_rows(),
        }
    }

    pub(crate) fn declaration_site_for_node(&self, node_id: usize) -> Option<ResolutionSiteId> {
        self.declaration_sites.get(&node_id).copied()
    }

    fn declaration_properties_for_node(&self, node: Node<'_>) -> &RustDeclarationPropertyFact {
        self.declaration_property_for_node(node)
            .expect("native named declaration has a source property fact")
    }

    pub(crate) fn declaration_property_for_node(
        &self,
        node: Node<'_>,
    ) -> Option<&RustDeclarationPropertyFact> {
        if let Some(declaration) = self.embedded_declarations.get(&node.id()) {
            return self.declaration_properties.for_declaration(*declaration);
        }
        self.declaration_properties.for_primary_node(node)
    }

    #[cfg(test)]
    fn test_macro_definition(
        &mut self,
        node: Node<'_>,
        raw: &RustRawRulesItemMacroDefinition,
    ) -> RustRulesItemMacroDefinition {
        let declaration = self
            .declaration_properties
            .ensure_primary(node, &mut self.source_collector)
            .expect("test macro definition has a canonical source declaration");
        RustRulesItemMacroDefinition {
            declaration,
            name: raw.name.clone(),
            visible_after: raw.visible_after,
            scope_start: raw.scope_start,
            scope_end: raw.scope_end,
            passthrough: raw.passthrough,
            arguments_only: raw.arguments_only,
            decoration: raw.decoration.clone(),
            declares_no_item: crate::declarations::rust_macro_definition_declares_no_item(
                node,
                self.source,
            ),
            writes_only_impls: crate::declarations::rust_macro_definition_writes_only_impls(
                node,
                self.source,
            ),
            exported: raw.exported,
        }
    }

    pub(crate) fn add_definition_unit(&mut self, fact: ResolutionDefinitionUnitFact) {
        self.facts.definition_units.push(fact);
    }

    fn record_declaration_site(&mut self, node: Node<'_>, declaration: ResolutionSiteId) {
        let properties = self.declaration_properties_for_node(node);
        let source_declaration = properties.declaration;
        if properties.cfg_condition != RustCfgCondition::Always {
            self.facts.gaps.push(ResolutionGapFact {
                site: declaration,
                kind: ResolutionGapKind::UnprovenActivation,
            });
        }
        self.declaration_sources
            .push((declaration, source_declaration));
        assert!(
            self.declaration_sites
                .insert(node.id(), declaration)
                .is_none(),
            "one Rust primary declaration node has one native declaration site"
        );
    }

    /// The declaration replay already made for `node`, when this lowering is
    /// walking replay's tree. `None` outside that walk, and for a node that is
    /// not a named item, which is the same condition
    /// `ensure_embedded_source_declaration` applies.
    fn embedded_declaration_for_node(&mut self, node: Node<'_>) -> Option<SourceDeclarationId> {
        let mut map = self.embedded_identity.take()?;
        let declaration =
            crate::declaration_properties::is_rust_named_declaration_kind(node.kind())
                .then(|| node.child_by_field_name("name"))
                .flatten()
                .map(|_| {
                    let declaration = map.declare_node(node, &mut self.source_collector);
                    self.declaration_properties.record_embedded(
                        declaration,
                        node,
                        map.host(),
                        map.host_cfg(),
                    );
                    self.embedded_declarations.insert(node.id(), declaration);
                    declaration
                });
        self.embedded_identity = Some(map);
        declaration
    }

    /// Lower the items of a proven-passthrough item-macro invocation against
    /// the identity declaration replay already gave them.
    ///
    /// `tree` is a copy of the tree replay parsed for this invocation (it shares
    /// replay's syntax nodes, so node ids agree with `map`) and `map` its
    /// occurrence map, moved in for the walk and returned after it. The copy is
    /// retained with the fragment trees for the builder's lifetime: the
    /// builder keys declaration sites and other per-node facts by node id, and
    /// a dropped tree's ids can be reused by the next invocation's replay.
    /// The walk itself is the ordinary one, so the site kind, the namespace and
    /// the binder of each item are decided where every other item's are, in
    /// [`Self::enter`], and the items' own interiors lower with them.
    ///
    /// The caller is the source walker, which has replay's graph borrowed at
    /// this point and has already read the classifier's answer. This lowering
    /// does not re-decide it.
    pub(crate) fn lower_passthrough_item_macro(
        &mut self,
        invocation: Node<'_>,
        tree: tree_sitter::Tree,
        map: crate::declarations::RustEmbeddedSourceMap,
    ) -> crate::declarations::RustEmbeddedSourceMap {
        assert!(
            self.embedded_identity.is_none(),
            "one embedded replay tree is lowered at a time"
        );
        self.discharged_item_macros.insert(invocation.id());
        self.embedded_identity = Some(map);
        self.replayed_member_owner =
            rust_trait_or_impl_member_owner(invocation).map(|owner| MemberOwner {
                node: owner.id(),
                is_trait: owner.kind() == "trait_item",
            });
        self.lower_replayed_items(tree.root_node());
        self.embedded_declarations.clear();
        self.replayed_member_owner = None;
        self.retain_macro_fragment_tree(tree);
        self.embedded_identity
            .take()
            .expect("the embedded replay map is returned to its graph")
    }

    /// The walk of [`Self::lower_passthrough_item_macro`] over replay's tree.
    /// The root is the invocation's token-tree interior, not an item; its
    /// named children are the items the expansion declares.
    fn lower_replayed_items(&mut self, root: Node<'_>) {
        let mut cursor = root.walk();
        let children = root.named_children(&mut cursor).collect::<Vec<_>>();
        let mut pending = children
            .into_iter()
            .rev()
            .map(|child| (child, false))
            .collect::<Vec<_>>();
        while let Some((node, exiting)) = pending.pop() {
            if exiting {
                self.exit();
                continue;
            }
            self.macro_fragment_nodes.insert(node.id());
            // The same authority refusals the fragment walk makes: an import,
            // an `extern crate` and a `macro_rules!` are owned by the import
            // projection and by declaration replay, and this walk has neither
            // the projection nor that authority.
            if matches!(
                node.kind(),
                "use_declaration" | "extern_crate_declaration" | "macro_definition"
            ) {
                self.add_local_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
                continue;
            }
            // A nested invocation expands into its own replay tree with its own
            // occurrence map, which this walk does not hold. Its items are that
            // tree's to declare, so this one leaves the invocation alone rather
            // than lowering a node whose identity belongs to another map.
            if node.kind() == "macro_invocation" {
                continue;
            }
            let action = self.enter(node, None, None, None);
            match action {
                TreeWalkAction::Skip => continue,
                TreeWalkAction::DescendWithExit => pending.push((node, true)),
                TreeWalkAction::Descend => {}
                TreeWalkAction::Stop => {
                    unreachable!("passthrough item lowering does not stop the walk")
                }
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            pending.extend(children.into_iter().rev().map(|child| (child, false)));
        }
    }

    pub(crate) fn enter(
        &mut self,
        node: Node<'_>,
        projected_imports: Option<&[RustProjectedImport]>,
        macro_definition: Option<&RustRulesItemMacroDefinition>,
        macro_source_position: Option<RustItemMacroSourcePosition>,
    ) -> TreeWalkAction {
        if node.kind() == "macro_invocation" {
            assert!(
                macro_source_position.is_some(),
                "every native macro invocation has a captured source position"
            );
        }
        if node.is_error() || node.is_missing() {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return TreeWalkAction::Skip;
        }

        let named_declaration = match self.embedded_declaration_for_node(node) {
            declaration @ Some(_) => declaration,
            None if self.embedded_identity.is_some() => None,
            None => self
                .declaration_properties
                .ensure_primary(node, &mut self.source_collector),
        };

        let cfg_condition = projected_imports
            .and_then(|imports| imports.first().map(|import| import.cfg_condition.clone()))
            .or_else(|| {
                named_declaration.map(|declaration| {
                    self.declaration_properties
                        .for_declaration(declaration)
                        .expect("ensured named declaration owns source properties")
                        .cfg_condition
                        .clone()
                })
            })
            .unwrap_or_else(|| rust_cfg_condition(node, self.source));
        let conditional_module = cfg_condition != RustCfgCondition::Always
            && node.kind() == "mod_item"
            && self.current_scope_is_module_owned();

        if self.consumed_subtrees.contains(&node.id()) {
            // An unsupported impl target or receiver parameter is represented
            // as a whole. Merely handled path tokens must still descend into
            // their generic arguments, which can contain independent uses.
            return TreeWalkAction::Skip;
        }

        if let Some(pending) = self.pending_scopes.remove(&node.id()) {
            self.scopes.push(pending.scope);
            if let Some(callable) = pending.callable {
                self.declaration_owners.push(callable);
                self.exits.push(ExitAction::DeclarationScope);
            } else {
                self.exits.push(ExitAction::Scope);
            }
            return TreeWalkAction::DescendWithExit;
        }

        if rust_node_can_carry_item_attributes(node.kind()) {
            match rust_item_attribute_boundary(node, self.source) {
                RustItemAttributeBoundary::SourcePreserving => {}
                RustItemAttributeBoundary::GeneratedSurface => {
                    // `#[derive(..)]` adds impls; it replaces nothing. This arm
                    // does not skip the node, so the item is walked in full and
                    // every reference authored in it is enumerated. Claiming a
                    // reference-enumeration gap here therefore says something
                    // untrue about the authored source, and it is not local: it
                    // opens the reverse candidate inventory for the fragment, so
                    // every `edges-of`/`used-by` answer about a derived type
                    // reports `InverseIndexResolutionIncomplete` and no relational
                    // assertion over it can publish a verdict. Name the surface
                    // the expansion would add instead, exactly as the cfg-gated
                    // `mod name;` arm below names its placement boundary rather
                    // than opening the same inventory.
                    self.add_semantic_gap(node, ResolutionGapKind::GeneratedItemSurface);
                }
                RustItemAttributeBoundary::ConditionalSerdeHelper => {
                    // The item is authored source rustc keeps whenever its
                    // `serde` helper is inert, so it is walked in full. Its
                    // own binder stays open (`lower_item_declaration`) until
                    // the crate route proves the derive is serde's.
                    self.add_semantic_gap(node, ResolutionGapKind::GeneratedItemSurface);
                    self.conditional_serde_items.insert(node.id());
                }
                RustItemAttributeBoundary::Transforming => {
                    if !self.lower_divan_bench_attribute_arguments(node) {
                        self.add_local_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
                    }
                    return TreeWalkAction::Skip;
                }
            }
        }
        let inherent_impl_id = if node.kind() == "function_item" {
            self.inherent_impl_for_member(node)
        } else {
            None
        };
        let inherent_method = inherent_impl_id.is_some();
        // A trait's own members are lowered into the member scope the trait
        // declaration opened. A trait whose declaration did not lower has no
        // such scope, and its members stay an unsupported member scope below.
        let trait_body_member = self.member_owner(node).is_some_and(|owner| owner.is_trait)
            && self.facts.scopes[self.current_scope().index()].kind
                == ResolutionScopeKind::TypeBody;
        if node.kind() == "function_signature_item" && trait_body_member {
            if self.enter_trait_method_signature(node).is_none() {
                self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
                return TreeWalkAction::Skip;
            }
            return TreeWalkAction::DescendWithExit;
        }
        if node.kind() == "function_item" && trait_body_member {
            // A trait method with a default body. Its declaration is the trait
            // member declaration the bodyless form also gets, and it belongs to
            // the trait's member scope, so it is lowered before any generic
            // parameter scope opens over the body.
            let Some(declaration) = self.lower_trait_method_declaration(node) else {
                self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
                return TreeWalkAction::Skip;
            };
            let has_generic_parameters = node.child_by_field_name("type_parameters").is_some();
            if has_generic_parameters {
                self.enter_generic_parameter_scope(node, None);
                let exit = self
                    .exits
                    .last_mut()
                    .expect("generic trait method has an exit");
                assert!(matches!(exit, ExitAction::Scope));
                *exit = ExitAction::DeclarationScope;
            } else {
                self.exits.push(ExitAction::DeclarationOwner);
            }
            self.lower_trait_default_method_body(node, declaration);
            return TreeWalkAction::DescendWithExit;
        }
        if self.associated_macro_items.contains(&node.id())
            && matches!(
                node.kind(),
                "const_item"
                    | "static_item"
                    | "function_item"
                    | "function_signature_item"
                    | "type_item"
            )
        {
            return self.lower_associated_macro_item(node);
        }
        if matches!(node.kind(), "associated_type" | "type_item")
            && self.member_owner(node).is_some()
        {
            if self.lower_associated_type_declaration(node).is_some() {
                self.exits.push(ExitAction::DeclarationOwner);
                return TreeWalkAction::DescendWithExit;
            }
            self.add_local_gap(node, ResolutionGapKind::UnsupportedMemberScope);
            return TreeWalkAction::Skip;
        }
        if matches!(node.kind(), "const_item" | "static_item") && self.member_owner(node).is_some()
        {
            if self.lower_associated_constant_declaration(node).is_some() {
                return TreeWalkAction::Descend;
            }
            self.add_local_gap(node, ResolutionGapKind::UnsupportedMemberScope);
            return TreeWalkAction::Skip;
        }
        if self.member_owner(node).is_some()
            && !inherent_method
            && matches!(
                node.kind(),
                "associated_type"
                    | "const_item"
                    | "function_item"
                    | "function_signature_item"
                    | "static_item"
                    | "type_item"
            )
        {
            // What is left here is a member shape whose own declaration did
            // not lower: a member of a trait or impl whose header this
            // fragment could not lower, so there is no member scope to put it
            // in. Keep enumeration and reverse inventory open without claiming
            // an unknown free lexical binder.
            self.add_local_gap(node, ResolutionGapKind::UnsupportedMemberScope);
            return TreeWalkAction::Skip;
        }
        if inherent_method {
            let impl_id = inherent_impl_id.expect("inherent method has an impl context");
            let has_generic_parameters = node.child_by_field_name("type_parameters").is_some();
            if self.lower_inherent_method(node, impl_id).is_some() {
                if has_generic_parameters {
                    let exit = self
                        .exits
                        .last_mut()
                        .expect("generic impl method has an exit");
                    assert!(matches!(exit, ExitAction::Scope));
                    *exit = ExitAction::DeclarationScope;
                } else {
                    self.exits.push(ExitAction::DeclarationOwner);
                }
                return TreeWalkAction::DescendWithExit;
            }
            return TreeWalkAction::Descend;
        }

        if node.kind() == "impl_item" {
            let generic = node.child_by_field_name("type_parameters").is_some();
            if generic {
                self.enter_generic_parameter_scope(node, None);
            }
            if self.lower_inherent_impl(node).is_none() {
                self.add_local_gap(node, ResolutionGapKind::UnsupportedMemberScope);
                if generic {
                    self.exit();
                }
                return TreeWalkAction::Skip;
            }
            return if generic {
                TreeWalkAction::DescendWithExit
            } else {
                TreeWalkAction::Descend
            };
        }

        // Nominal declarations own one canonical TypeBody scope regardless of
        // whether their syntax has generic parameters or a value body. Generic
        // binders are lowered into this same scope below; allocating a separate
        // parameter scope would give one TypeDeclaration two competing owners
        // and leave unit/empty declarations without a nominal member scope.
        let nominal_declaration = match node.kind() {
            "struct_item" => self.lower_struct_declaration(node),
            "enum_item" | "union_item" | "trait_item" => self.lower_item_declaration(
                node,
                ResolutionSiteKind::TypeDeclaration,
                ResolutionNamespace::Type,
                ResolutionBinderKind::Type,
            ),
            _ => None,
        };
        if let Some(declaration) = nominal_declaration {
            let type_body = self.enter_type_body_scope(node, declaration);
            self.declaration_owners.push(declaration);
            let exit = self
                .exits
                .last_mut()
                .expect("nominal declaration has a scope exit");
            assert!(matches!(exit, ExitAction::Scope));
            *exit = ExitAction::DeclarationScope;
            if node.kind() == "trait_item" {
                let site = self.add_site(
                    node,
                    ResolutionSiteKind::TypeReference,
                    self.current_scope(),
                );
                let frontier = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                    .expect("Rust resolution type-slot count exceeds u32");
                self.facts.type_slots.push(ResolutionTypeSlotFact {
                    id: frontier,
                    site,
                    role: ResolutionTypeSlotRole::TargetTypeIdentity,
                });
                self.facts.gaps.push(ResolutionGapFact {
                    site,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                });
                assert!(
                    self.self_type_frontiers
                        .insert(
                            node.id(),
                            RustSelfTypes {
                                nominal: frontier,
                                receiver: frontier
                            }
                        )
                        .is_none(),
                    "one Rust trait has one abstract Self frontier"
                );
                assert!(
                    self.trait_self_bound_scopes
                        .insert(node.id(), self.current_scope())
                        .is_none(),
                    "one Rust trait has one declaring scope"
                );
            }
            if let Some(parameters) = node.child_by_field_name("type_parameters") {
                self.lower_generic_parameter_binders(
                    parameters,
                    type_body,
                    node.start_byte(),
                    node.end_byte(),
                );
            }
            if node.kind() == "trait_item"
                && let Some(bounds) = node.child_by_field_name("bounds")
            {
                self.lower_supertrait_bounds(declaration, bounds);
            }
            return TreeWalkAction::DescendWithExit;
        }

        if node.child_by_field_name("type_parameters").is_some() {
            let lowered = match node.kind() {
                "function_item" => {
                    let declaration = self.lower_function_declaration(node);
                    if let Some(declaration) = declaration {
                        self.enter_generic_parameter_scope(node, Some(declaration));
                        let exit = self.exits.last_mut().expect("generic function has an exit");
                        assert!(matches!(exit, ExitAction::Scope));
                        *exit = ExitAction::DeclarationScope;
                        self.lower_callable_return_type(node, declaration);
                        self.lower_callable_body(node, declaration);
                    }
                    declaration
                }
                "type_item" => self.lower_type_alias(node),
                _ => None,
            };
            if let Some(declaration) = lowered {
                if node.kind() != "function_item" {
                    self.enter_generic_parameter_scope(node, Some(declaration));
                    if node.kind() == "type_item" {
                        let exit = self.exits.last_mut().expect("generic alias has an exit");
                        assert!(matches!(exit, ExitAction::Scope));
                        *exit = ExitAction::DeclarationScope;
                        self.lower_type_alias_target(node, declaration);
                    }
                }
                return TreeWalkAction::DescendWithExit;
            }
        }

        match node.kind() {
            "function_item" => {
                if self.lower_function(node).is_some() {
                    self.exits.push(ExitAction::DeclarationOwner);
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "function_signature_item" => {
                if let Some(declaration) = self.lower_function_declaration(node) {
                    self.retain_unlowered_parameter_inventory(node, declaration);
                    self.exits.push(ExitAction::DeclarationOwner);
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "type_item" => {
                if self.lower_type_alias(node).is_some() {
                    self.exits.push(ExitAction::DeclarationOwner);
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "const_item" | "static_item" => {
                if let Some(declaration) = self.lower_item_declaration(
                    node,
                    ResolutionSiteKind::ValueDeclaration,
                    ResolutionNamespace::Value,
                    ResolutionBinderKind::Field,
                ) {
                    self.lower_declared_value_types(
                        &[declaration],
                        node.child_by_field_name("type"),
                        DeclarationTypeRole::Value,
                    );
                }
            }
            "mod_item" if conditional_module && node.child_by_field_name("body").is_none() => {
                // A cfg-gated `mod name;` routes into another compilation unit
                // whose root attachment this fragment cannot state, so its
                // lexical placement stays an explicit boundary.
                self.add_semantic_gap(node, ResolutionGapKind::UnsupportedPlacementBoundary);
                // The declaration still names this module. Publish its binder
                // and export with the declaration's UnprovenActivation gap;
                // the selected crate route decides activation and attachment.
                // Withholding the export loses the name even after the selected
                // topology has proved that this file-backed module is active.
                self.lower_module(node);
            }
            // A cfg-gated inline module is an ordinary module declaration whose
            // body is right here: the route into it is lexical and fully
            // enumerated, and the only open question is whether the module
            // declaration activates, which `record_declaration_site` publishes
            // as an `UnprovenActivation` gap positioned on that exact
            // declaration and which lexical lowering carries into every
            // candidate that reaches it. Withholding its binder withheld its
            // root export too -- a root export is lowered from the binder that
            // attaches the name to its scope -- so `#[cfg(test)] mod test`
            // published no path an export bridge could match and
            // `crate::non_blocking::test` proved an absence at a module
            // declared on the line it was looking at. It still claims no
            // placement boundary: that is a statement about another
            // compilation unit, and making it would open the whole reverse
            // candidate inventory for every fragment in the workspace, so
            // every reverse answer anywhere would report
            // `InverseIndexResolutionIncomplete` once one file spelled
            // `#[cfg(test)] mod tests { .. }`.
            "mod_item" => self.lower_module(node),
            "use_declaration" => {
                self.lower_use_declaration(
                    node,
                    projected_imports.expect("use declarations have a shared projection"),
                );
                return TreeWalkAction::Skip;
            }
            "extern_crate_declaration" => {
                self.lower_extern_crate_declaration(
                    node,
                    projected_imports.expect("extern crate declarations have a shared projection"),
                );
                return TreeWalkAction::Skip;
            }
            "let_declaration" => self.lower_let(node),
            "closure_expression" => {
                self.enter_closure_scope(node);
                return TreeWalkAction::DescendWithExit;
            }
            "for_expression" => {
                self.enter_for_scope(node);
                return TreeWalkAction::DescendWithExit;
            }
            "match_arm" => {
                self.enter_match_arm_scope(node);
                return TreeWalkAction::DescendWithExit;
            }
            "if_expression" | "while_expression" => {
                if let Some(condition) = node.child_by_field_name("condition") {
                    if condition.kind() == "let_condition" {
                        self.prepare_direct_let_condition_scope(node, condition);
                    } else if condition.kind() == "let_chain" {
                        self.prepare_let_chain_scope(node, condition);
                    }
                }
            }
            "call_expression" => self.lower_call_reference(node),
            "type_identifier" => self.lower_bare_type_reference(node),
            "scoped_type_identifier" => {
                if !self.handled_identifiers.contains(&node.id()) {
                    self.lower_qualified_type_reference(node);
                }
            }
            "scoped_identifier" => {
                if !self.handled_identifiers.contains(&node.id()) {
                    self.lower_scoped_expression_reference(node);
                }
            }
            "self" => self.lower_self_expression_reference(node),
            "field_expression" => self.lower_value_field_expression(node),
            "struct_expression" => self.lower_struct_initializer_fields(node),
            "struct_pattern" => self.lower_struct_pattern_references(node),
            "tuple_struct_pattern" => self.lower_tuple_pattern_constructor(node),
            "macro_definition" => {
                self.lower_macro_definition(node, macro_definition);
                return TreeWalkAction::Skip;
            }
            "macro_invocation" => {
                self.lower_macro_invocation(
                    node,
                    macro_source_position.expect(
                        "native macro lowering receives the position captured at source enter",
                    ),
                );
                if !self.lowering_macro_fragments {
                    self.lower_pending_macro_fragments();
                }
                return TreeWalkAction::Skip;
            }
            "associated_type" => {
                // Trait/impl associated types were handled by the member
                // boundary above. The remaining grammar position is an extern
                // type, which has no parser-unit or selected member contract.
                self.add_local_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
                return TreeWalkAction::Skip;
            }
            "attribute_item" | "inner_attribute_item" => return TreeWalkAction::Skip,
            "block" => {
                let parent = self.current_scope();
                let scope = self.allocate_statement_scope(
                    parent,
                    None,
                    ResolutionScopeKind::Block,
                    node.start_byte(),
                    node.end_byte(),
                    node,
                );
                self.scopes.push(scope);
                self.exits.push(ExitAction::Scope);
                return TreeWalkAction::DescendWithExit;
            }
            "identifier" => self.lower_bare_expression_reference(node),
            "enum_variant" => {
                if let Some(declaration) = self.lower_enum_variant(node)
                    && node.child_by_field_name("body").is_some_and(|body| {
                        matches!(
                            body.kind(),
                            "field_declaration_list" | "ordered_field_declaration_list"
                        )
                    })
                {
                    self.enter_type_body_scope(node, declaration);
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "ordered_field_declaration_list" => self.lower_positional_field_declarations(node),
            "field_declaration" => self.lower_named_field_declaration(node),
            "field_identifier" => self.mark_unlowered_identifier_boundary(node),
            _ => {}
        }
        TreeWalkAction::Descend
    }

    pub(crate) fn exit(&mut self) {
        match self
            .exits
            .pop()
            .expect("every Rust requested exit has one action")
        {
            ExitAction::Scope => {
                assert!(self.scopes.len() > 1);
                self.scopes.pop();
            }
            ExitAction::DeclarationOwner => {
                self.declaration_owners
                    .pop()
                    .expect("Rust declaration exits its owner");
            }
            ExitAction::DeclarationScope => {
                assert!(self.scopes.len() > 1);
                self.scopes.pop();
                self.declaration_owners
                    .pop()
                    .expect("Rust declaration scope exits its owner");
            }
        }
    }

    fn current_scope(&self) -> ResolutionScopeId {
        *self
            .scopes
            .last()
            .expect("Rust compilation scope is present")
    }

    /// The scope that owns the items declared where lowering currently is.
    ///
    /// An item declared in a block does not capture: the block's locals,
    /// parameters and pattern binders are invisible inside it, while the items
    /// declared beside it are visible, whatever their source order. A block
    /// that declares an item therefore carries two scopes -- the item scope
    /// this returns, and the local scope below it -- so a name looked up from
    /// inside a nested item walks past the locals and still reaches the
    /// siblings. Everywhere else the two are one scope and this is the current
    /// scope.
    fn item_scope(&self) -> ResolutionScopeId {
        let current = self.current_scope();
        self.item_scopes.get(&current).copied().unwrap_or(current)
    }

    /// Allocate the scope a statement list's locals live in, interposing the
    /// item scope described on [`Self::item_scope`] above it when the list
    /// declares items.
    ///
    /// Both scopes span the same source range and carry the same kind: the item
    /// scope is a lookup boundary within one statement list, not a narrower
    /// region or a different sort of region, and a scope's parent must contain
    /// it. Only the local half owns the declaration whose body it is.
    fn allocate_statement_scope(
        &mut self,
        parent: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        kind: ResolutionScopeKind,
        start_byte: usize,
        end_byte: usize,
        statements: Node<'_>,
    ) -> ResolutionScopeId {
        if !rust_block_declares_items(statements) {
            return self.allocate_scope(parent, owner, kind, start_byte, end_byte);
        }
        let items = self.allocate_scope(parent, None, kind, start_byte, end_byte);
        let scope = self.allocate_scope(items, owner, kind, start_byte, end_byte);
        assert!(
            self.item_scopes.insert(scope, items).is_none(),
            "one Rust statement scope owns one item scope"
        );
        scope
    }

    fn allocate_scope(
        &mut self,
        parent: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        kind: ResolutionScopeKind,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeId {
        let id = ResolutionScopeId::try_from_index(self.facts.scopes.len())
            .expect("Rust resolution scope count exceeds u32");
        self.facts.scopes.push(ResolutionScopeFact {
            id,
            parent: Some(parent),
            owner,
            kind,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte,
            end_byte,
        });
        id
    }

    /// The scope a module body owns.
    ///
    /// Rust looks a path's first segment up in the current module's own items
    /// and then in the preludes; an ancestor module's items are not in scope,
    /// which is why `mod inner { fn f(_: OuterType) {} }` needs a `use` to
    /// compile. The body's scope therefore keeps its parent link -- textual
    /// macro visibility and the placement assertions walk it -- while telling
    /// the lowering that name lookup stops here. Without that, the module's
    /// own name is visible inside its own body and shadows an extern-prelude
    /// crate root of the same spelling.
    fn allocate_module_scope(
        &mut self,
        parent: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeId {
        let id = self.allocate_scope(
            parent,
            owner,
            ResolutionScopeKind::Package,
            start_byte,
            end_byte,
        );
        self.facts.scopes[id.index()].inheritance = ResolutionScopeInheritance::Root;
        id
    }

    fn add_site(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        let occurrence = if let Some(mut map) = self.embedded_identity.take() {
            // One tree, one map: the site of an item replay already declared
            // must be the occurrence replay interned for it, not a second one
            // over the same bytes.
            let occurrence = map.intern_node(node, &mut self.source_collector);
            self.embedded_identity = Some(map);
            occurrence
        } else if self.explicit_source_fragment_nodes.contains(&node.id()) {
            self.source_collector.intern_subspan_bytes(
                node.start_byte(),
                node.end_byte(),
                SourceOccurrenceProvenance::ExplicitSubspan,
            )
        } else if self.macro_fragment_nodes.contains(&node.id()) {
            self.source_collector.intern_subspan_bytes(
                node.start_byte(),
                node.end_byte(),
                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded,
            )
        } else {
            self.source_collector.intern_node(node)
        };
        self.add_site_for_occurrence(occurrence, kind, scope)
    }

    fn add_site_for_occurrence(
        &mut self,
        occurrence: SourceOccurrenceId,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        let range = self.source_collector.occurrence(occurrence).range;
        let id = ResolutionSiteId::try_from_index(self.facts.sites.len())
            .expect("Rust resolution site count exceeds u32");
        self.site_occurrences.push(occurrence);
        self.facts.sites.push(ResolutionSiteFact {
            id,
            scope,
            kind,
            start_byte: range.start_byte,
            end_byte: range.end_byte,
        });
        id
    }

    fn intern_name(&mut self, node: Node<'_>) -> ResolutionNameId {
        let spelling = strip_raw_identifier_prefix(rust_node_text(node, self.source).trim());
        self.intern_spelling(spelling)
    }

    fn intern_spelling(&mut self, spelling: &str) -> ResolutionNameId {
        let spelling = strip_raw_identifier_prefix(spelling.trim());
        assert!(!spelling.is_empty(), "Rust identifier needs a spelling");
        if let Some(id) = self.names.get(spelling) {
            return *id;
        }
        let id = ResolutionNameId::try_from_index(self.facts.names.len())
            .expect("Rust resolution name count exceeds u32");
        self.names.insert(spelling.to_owned(), id);
        self.facts.names.push(ResolutionNameFact {
            id,
            spelling: spelling.to_owned(),
        });
        id
    }

    fn add_identifier(
        &mut self,
        node: Node<'_>,
        site_kind: ResolutionSiteKind,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        self.handled_identifiers.insert(node.id());
        let site = self.add_site(node, site_kind, scope);
        let name = self.intern_name(node);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role,
            namespace,
            qualifier: None,
        });
        if role == ResolutionIdentifierRole::Reference {
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference: site,
                    owner: self.declaration_owners.last().copied(),
                });
            // `Self` is bound by the enclosing `impl` or trait, never by a
            // scope: its typed identity answers it, and no binder, glob,
            // prelude or item macro of a module can supply or shadow it.
            if rust_type_reference_is_self(node, self.source) {
                self.facts.keyword_references.push(site);
            }
            self.add_prelude_fall_through(node, site, site_kind, namespace);
        }
        site
    }

    /// An unqualified type or value name that some edition's std or core
    /// prelude injects falls through every scope to that prelude when no
    /// scope binds it. The fall-through is a root reference at the file's
    /// root scope with no route: it reaches the crate context only when the
    /// lexical lookup found no binding, so a lexical binding wins as in
    /// rustc, and the crate context decides from the crate's edition and
    /// prelude kind whether the prelude supplies the name.
    fn add_prelude_fall_through(
        &mut self,
        node: Node<'_>,
        site: ResolutionSiteId,
        site_kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
    ) {
        use crate::prelude::{RustPreludeNamespace, rust_prelude_candidate};
        let namespace = match namespace {
            ResolutionNamespace::Type => RustPreludeNamespace::Type,
            ResolutionNamespace::Value | ResolutionNamespace::Callable => {
                RustPreludeNamespace::Value
            }
            _ => return,
        };
        if site_kind == ResolutionSiteKind::ImportDeclaration
            || !rust_prelude_candidate(
                strip_raw_identifier_prefix(rust_node_text(node, self.source).trim()),
                namespace,
            )
        {
            return;
        }
        let root_scope = self.nearest_root_scope();
        self.prelude_fall_throughs
            .push(ResolutionRootReferenceFact {
                reference: site,
                root_scope,
                anchor: ResolutionRootImportAnchor::Lexical,
                prefix_reference: None,
            });
    }

    fn add_qualified_identifier(
        &mut self,
        node: Node<'_>,
        site_kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        self.handled_identifiers.insert(node.id());
        let site = self.add_site(node, site_kind, scope);
        let qualifier = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: qualifier,
            site,
            role: ResolutionTypeSlotRole::Receiver,
        });
        let name = self.intern_name(node);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role: ResolutionIdentifierRole::Reference,
            namespace,
            qualifier: Some(qualifier),
        });
        self.facts
            .reference_owners
            .push(ResolutionReferenceOwnerFact {
                reference: site,
                owner: self.declaration_owners.last().copied(),
            });
        site
    }

    fn lower_scoped_expression_reference(
        &mut self,
        node: Node<'_>,
    ) -> Option<ResolutionTypeSlotId> {
        let reference = self.add_scoped_identifier(
            node,
            ResolutionSiteKind::ValueReference,
            ResolutionNamespace::Value,
        )?;
        // A qualified value needs an output projection for the typed member
        // route to discharge its QualifiedReference obligation. Without it,
        // even an exact enum owner leaves `Enum::Variant` incomplete.
        let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: output,
            site: reference,
            role: ResolutionTypeSlotRole::ExpressionValue,
        });
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetDeclaredValueType,
        });
        Some(output)
    }

    fn add_scoped_identifier(
        &mut self,
        node: Node<'_>,
        site_kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
    ) -> Option<ResolutionSiteId> {
        let Some(name) = node.child_by_field_name("name") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return None;
        };
        if let Some(head) = rust_projection_path_head(node) {
            return Some(
                self.lower_projection_member_reference(node, name, head, site_kind, namespace),
            );
        }
        let segments = rust_path_segments(node);
        let explicit_module_anchor = segments.as_ref().is_some_and(|segments| {
            rust_path_is_leading_absolute(node)
                || segments
                    .first()
                    .is_some_and(|segment| rust_path_anchor_keyword(segment.kind()))
        });
        let bare_qualified_route = segments
            .as_ref()
            .is_some_and(|segments| segments.len() >= 2 && !explicit_module_anchor);
        let reference = if explicit_module_anchor {
            self.add_identifier(
                name,
                site_kind,
                ResolutionIdentifierRole::Reference,
                namespace,
                self.current_scope(),
            )
        } else if bare_qualified_route {
            // Keep the receiver slot on a bare qualified terminal. The first
            // segment is represented separately below for native lexical Type
            // lookup, while callable/member continuation still consumes the
            // structured qualifier rather than falling back to a free Value
            // lookup.
            self.add_qualified_identifier(name, site_kind, namespace, self.current_scope())
        } else {
            self.add_qualified_identifier(name, site_kind, namespace, self.current_scope())
        };
        self.add_root_reference_route(node, name, reference, segments, bare_qualified_route);
        Some(reference)
    }

    /// Lower a projection through its implementing type's member frontier.
    /// The bracketed head retains positioned type references and supplies no
    /// lexical module demand. Deferred associated members retain impl ownership.
    fn lower_projection_member_reference(
        &mut self,
        node: Node<'_>,
        name: Node<'_>,
        head: Node<'_>,
        site_kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
    ) -> ResolutionSiteId {
        self.mark_scoped_path_consumed(node);
        let reference =
            self.add_qualified_identifier(name, site_kind, namespace, self.current_scope());
        let mut cursor = head.walk();
        let operand = head.named_children(&mut cursor).next();
        let implementing_type = operand.and_then(|operand| {
            if operand.kind() == "qualified_type" {
                operand.child_by_field_name("type")
            } else {
                Some(operand)
            }
        });
        if let Some(lowered) =
            implementing_type.and_then(|target| self.lower_declared_type_identity(target))
        {
            let qualifier = self
                .facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == reference)
                .and_then(|identifier| identifier.qualifier)
                .expect("projection has a receiver");
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: lowered.identity,
                output: qualifier,
                kind: ResolutionTypeTransferKind::Receiver,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
        } else {
            self.add_frontier_gaps(reference, &[ResolutionGapKind::UnsupportedTypeSyntax]);
        }
        self.lower_return_type_children(head);
        reference
    }

    /// Retain one source-owned route for a qualified reference.
    ///
    /// A bare `left::target` carries a structured Type-namespace prefix
    /// reference. Selected continuation is not allowed to choose a same-named
    /// module until that prefix has been resolved lexically.
    /// Explicit Rust anchors (`crate`, `self`, `super`, or a leading `::`)
    /// distinguish a module route in the source-owned syntax. The terminal
    /// remains the ordinary positioned reference. Both forms preserve the
    /// callable owner; only path-prefix components become route rows.
    fn add_root_reference_route(
        &mut self,
        node: Node<'_>,
        terminal: Node<'_>,
        reference: ResolutionSiteId,
        segments: Option<Vec<Node<'_>>>,
        bare_qualified_route: bool,
    ) {
        let Some(segments) = segments else {
            self.mark_scoped_path_consumed(node);
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        assert_eq!(
            segments.last().map(|segment| segment.id()),
            Some(terminal.id())
        );
        self.mark_scoped_path_consumed(node);
        let leading_absolute = rust_path_is_leading_absolute(node);
        let explicit_module_anchor = leading_absolute
            || segments
                .first()
                .is_some_and(|segment| rust_path_anchor_keyword(segment.kind()));
        if !explicit_module_anchor && !bare_qualified_route {
            return;
        }
        let root_scope = self.nearest_root_scope();
        let anchor = if leading_absolute {
            ResolutionRootImportAnchor::Absolute
        } else {
            ResolutionRootImportAnchor::Lexical
        };
        let first = segments[0];
        let self_prefix = bare_qualified_route && rust_type_reference_is_self(first, self.source);
        if self_prefix && segments.len() > 2 {
            self.lower_self_member_path(node, reference);
            return;
        }
        let bare_first_reference = bare_qualified_route.then(|| {
            self.add_identifier(
                first,
                ResolutionSiteKind::TypeReference,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
                self.current_scope(),
            )
        });
        let final_prefix_reference = if self_prefix {
            None
        } else {
            self.add_path_prefix_occurrences(&segments, root_scope, anchor)
        };
        let prefix = if self_prefix || (bare_qualified_route && segments.len() == 2) {
            Some((
                first,
                bare_first_reference.expect("a bare path has its first reference"),
            ))
        } else if segments.len() > 2
            && (bare_qualified_route
                || (self.macro_fragment_nodes.contains(&node.id())
                    && self.facts.sites[reference.index()].kind
                        == ResolutionSiteKind::CallableReference))
        {
            // Static macro callees retain the prefix continuation needed by
            // $crate::Type::member. Ordinary explicit module routes keep their
            // source-owned access domain, including exact negative lookups.
            let prefix = segments[segments.len() - 2];
            (!rust_path_anchor_keyword(prefix.kind())).then(|| {
                (
                    prefix,
                    final_prefix_reference.expect("the final prefix has its own source reference"),
                )
            })
        } else {
            None
        };
        // An explicit module route whose final prefix names an item keeps its
        // whole route, and its terminal also takes that prefix as its
        // receiver, as a bare path's terminal does: `crate::m::Type::member`
        // is a member of `Type` just as `m::Type::member` is. The route alone
        // answers a prefix that is a module; the engine gives a module no
        // type, so the receiver then adds no member lookup.
        let anchored_receiver = if prefix.is_none() && explicit_module_anchor && segments.len() > 2
        {
            let receiver = segments[segments.len() - 2];
            (!rust_path_anchor_keyword(receiver.kind())).then(|| {
                (
                    receiver,
                    final_prefix_reference.expect("the final prefix has its own source reference"),
                )
            })
        } else {
            None
        };
        if let Some(first_reference) = bare_first_reference
            && prefix.is_none_or(|(_, reference)| reference != first_reference)
        {
            self.add_type_reference_identity(first, first_reference);
        }
        if let Some((prefix_node, prefix_reference)) = prefix.or(anchored_receiver) {
            let qualifier = self
                .facts
                .identifiers
                .iter()
                .rev()
                .find(|identifier| identifier.site == reference)
                .expect("terminal identifier exists")
                .qualifier
                .unwrap_or_else(|| {
                    let qualifier =
                        ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                            .expect("Rust resolution type-slot count exceeds u32");
                    self.facts.type_slots.push(ResolutionTypeSlotFact {
                        id: qualifier,
                        site: reference,
                        role: ResolutionTypeSlotRole::Receiver,
                    });
                    self.facts
                        .identifiers
                        .iter_mut()
                        .rev()
                        .find(|identifier| identifier.site == reference)
                        .expect("terminal identifier exists")
                        .qualifier = Some(qualifier);
                    qualifier
                });
            // A trait body's `Self::` prefix takes the trait as its lower
            // bound, and so does the identity slot of the token itself. The
            // token is a path prefix here and nothing else: what it denotes is
            // what the lookup continues from. Reading the trait's abstract
            // frontier for it instead put that frontier's
            // `UnsupportedHierarchyTraversal` gap into every `Self::name`
            // answer, which left the answer `incomplete` while naming the
            // exact item and left the same use unproven in the inverse. A
            // `self` receiver and a `-> Self` return keep the frontier, where
            // the implementing type really is unknown.
            let bound = rust_type_reference_is_self(prefix_node, self.source)
                .then(|| self.enclosing_trait_self_lower_bound(prefix_node))
                .flatten();
            let input = match bound {
                // The token keeps an identity slot of its own, as every type
                // reference must; it simply takes the bound rather than the
                // frontier, so the frontier's gap stays out of this answer.
                Some(bound) => {
                    let identity =
                        ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                            .expect("Rust resolution type-slot count exceeds u32");
                    self.facts.type_slots.push(ResolutionTypeSlotFact {
                        id: identity,
                        site: prefix_reference,
                        role: ResolutionTypeSlotRole::TargetTypeIdentity,
                    });
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input: bound,
                        output: identity,
                        kind: ResolutionTypeTransferKind::TypeIdentity,
                        indirection_delta: 0,
                        reference_indirection_delta: 0,
                        value_transform: ResolutionTypeTransferValueTransform::Preserve,
                    });
                    identity
                }
                None => self.add_type_reference_identity(prefix_node, prefix_reference),
            };
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input,
                output: qualifier,
                kind: ResolutionTypeTransferKind::Receiver,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
        }
        // Each prefix keeps its source route. The terminal continues from the
        // final prefix's exact binding, whether it denotes a module or a type.
        // `Self::member` is included: `Self` is an implementing type and never
        // a module or a crate root, but the route a root reference publishes is
        // exactly what carries a member demand to the type the prefix resolves
        // to, which is how `Foo::member` reaches the trait `Foo` implements.
        // Withholding the route left `Self::member` with no continuation at
        // all, not with a narrower one.
        self.facts
            .root_references
            .push(ResolutionRootReferenceFact {
                reference,
                root_scope,
                anchor: if prefix.is_some() {
                    ResolutionRootImportAnchor::Lexical
                } else {
                    anchor
                },
                prefix_reference: prefix.map(|(_, reference)| reference),
            });
        if let Some((prefix_node, _)) = prefix {
            let name = self.intern_name(prefix_node);
            self.facts
                .root_reference_segments
                .push(ResolutionRootReferenceSegmentFact {
                    reference,
                    position: 0,
                    name,
                });
        } else {
            for (position, segment) in segments
                .iter()
                .take(segments.len().saturating_sub(1))
                .enumerate()
            {
                let name = self.intern_name(*segment);
                self.facts
                    .root_reference_segments
                    .push(ResolutionRootReferenceSegmentFact {
                        reference,
                        position: u32::try_from(position)
                            .expect("Rust root reference route length exceeds u32"),
                        name,
                    });
            }
        }
    }

    /// Lower `Self::Member::terminal` as a member chain, not a module route.
    ///
    /// `Self::A::b` names no module. `A` is a member of the impl subject and
    /// `b` is a member of `A`, so the module route is the wrong mechanism:
    /// it would ask the crate rows for a module spelled `Self`. Taking `Self`
    /// as the terminal's receiver instead, which is what a two-segment
    /// `Self::A` needs, left every segment between the anchor and the terminal
    /// with no occurrence at all, so a caret on one answered
    /// `native_reference_missing` (#1126).
    ///
    /// The path below the terminal is an ordinary declared type. Lowering it
    /// gives each segment above the terminal the receiver shape a two-segment
    /// path already builds, with the segment above it as its receiver, and its
    /// type identity becomes the terminal's receiver.
    fn lower_self_member_path(&mut self, node: Node<'_>, reference: ResolutionSiteId) {
        let path = node
            .child_by_field_name("path")
            .expect("a multi-segment scoped path has a path child");
        let Some(lowered) = self.lower_declared_type_identity(path) else {
            self.add_frontier_gaps(reference, &[ResolutionGapKind::UnsupportedTypeSyntax]);
            return;
        };
        let qualifier = self
            .facts
            .identifiers
            .iter()
            .rev()
            .find(|identifier| identifier.site == reference)
            .expect("terminal identifier exists")
            .qualifier
            .expect("a bare qualified terminal keeps its receiver slot");
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input: lowered.identity,
            output: qualifier,
            kind: ResolutionTypeTransferKind::Receiver,
            indirection_delta: lowered.indirection,
            reference_indirection_delta: lowered.reference_indirection,
            value_transform: ResolutionTypeTransferValueTransform::Preserve,
        });
    }

    /// Give every path prefix below the path head its own reference occurrence.
    ///
    /// The terminal of a scoped path already owns a route that spells out the
    /// segments above it, but that route is only consumed while the terminal
    /// resolves: the prefix tokens themselves stayed unlowered, so a lookup at
    /// one of them reported a missing reference. Each prefix below the head now
    /// gets the terminal's shape for its own segment: a demand for that
    /// segment's spelling, route rows for the segments above it, and the path's
    /// anchor, so the prefix resolves to exactly the module the full path
    /// passes through. Segment nodes and route rows both come from the grammar
    /// fields recorded by `rust_path_segments`.
    ///
    /// One kind of segment is left out: a named head. A bare path's head is
    /// already an occurrence, the terminal's `prefix_reference`, which owns the
    /// demand for the path's first lexical lookup, and a leading `::` head
    /// names a crate through the extern prelude rather than through a module
    /// route. A named head has no segments above it, so its demand would sit on
    /// an empty route.
    ///
    /// An anchor keyword is not left out, wherever it appears: `crate`, `self`
    /// and `super` name a module, and a caret on one of them has to resolve to
    /// that module the way a caret on any other segment resolves to the module
    /// it names. Such an occurrence differs from a named segment in one way
    /// only: its route includes its own step, because the module it names is
    /// the one its own step reaches rather than one an export lookup finds
    /// inside. `super::super::x` spells its second `super` in the grammar's
    /// `name` field, so both anchors are ordinary segments here.
    fn add_path_prefix_occurrences(
        &mut self,
        segments: &[Node<'_>],
        root_scope: ResolutionScopeId,
        anchor: ResolutionRootImportAnchor,
    ) -> Option<ResolutionSiteId> {
        let mut final_reference = None;
        let prefix_count = segments.len().saturating_sub(1);
        for (position, prefix) in segments[..prefix_count]
            .iter()
            .enumerate()
            .filter(|(position, prefix)| *position > 0 || rust_path_anchor_keyword(prefix.kind()))
        {
            let keyword = rust_path_anchor_keyword(prefix.kind());
            let reference = self.add_identifier(
                *prefix,
                ResolutionSiteKind::TypeReference,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
                self.current_scope(),
            );
            if !keyword {
                final_reference = Some(reference);
            }
            self.facts
                .root_references
                .push(ResolutionRootReferenceFact {
                    reference,
                    root_scope,
                    anchor,
                    prefix_reference: None,
                });
            // A named segment is looked up in the module the segments above it
            // reach. An anchor keyword names that module itself, so its own
            // step belongs in its route: the route ends where the occurrence
            // points.
            let route = if keyword {
                &segments[..=position]
            } else {
                &segments[..position]
            };
            for (row, segment) in route.iter().enumerate() {
                let name = self.intern_name(*segment);
                self.facts
                    .root_reference_segments
                    .push(ResolutionRootReferenceSegmentFact {
                        reference,
                        position: u32::try_from(row)
                            .expect("Rust root reference route length exceeds u32"),
                        name,
                    });
            }
        }
        final_reference
    }

    /// Follow an alias's exact outer type rather than its receiver payload.
    /// Keep a separate projection so Box/Arc dereferencing and Option/Result
    /// unwrapping cannot attach an impl or Self occurrence to the payload.
    fn lower_nominal_type_identity(&mut self, mut node: Node<'_>) -> Option<ResolutionTypeSlotId> {
        while matches!(node.kind(), "generic_type" | "generic_type_with_turbofish") {
            node = node
                .child_by_field_name("type")
                .expect("generic type has a head");
        }
        if !matches!(
            node.kind(),
            "type_identifier"
                | "identifier"
                | "scoped_type_identifier"
                | "scoped_identifier"
                | "primitive_type"
        ) && !rust_is_unit_type(node)
        {
            return Some(self.unresolvable_impl_subject(node));
        }
        let lowered = self.lower_declared_type_identity(node)?;
        if rust_type_reference_is_self(node, self.source) {
            return self
                .enclosing_self_type_frontier(node)
                .or(Some(lowered.identity));
        }
        if node.kind() == "primitive_type" || rust_is_unit_type(node) {
            return Some(lowered.identity);
        }
        let reference = self.facts.type_slots[lowered.identity.index()].site;
        let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: output,
            site: reference,
            role: ResolutionTypeSlotRole::TargetTypeIdentity,
        });
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetNominalTypeIdentity,
        });
        Some(output)
    }

    fn lower_impl_type_identity(&mut self, node: Node<'_>) -> Option<LoweredDeclaredType> {
        if node.kind() == "generic_type" {
            let arguments = node
                .child_by_field_name("type_arguments")
                .expect("Rust generic_type has type_arguments");
            self.lower_return_type_children(arguments);
            if !self.impl_generic_arguments_are_unconstrained_parameters(node, arguments) {
                self.add_semantic_gap(arguments, ResolutionGapKind::UnsupportedTypeSyntax);
            }
            // An impl belongs to the nominal declaration. Its parameter
            // substitution is separate from that declaration's identity.
            let head = node
                .child_by_field_name("type")
                .expect("Rust generic_type has a type field");
            self.lower_declared_type_identity(head)
        } else {
            self.lower_declared_type_identity(node)
        }
    }

    /// A generic impl over every unconstrained type parameter of its nominal
    /// head has the same owner identity regardless of substitution. Preserve
    /// argument references, but do not make that owner route incomplete.
    /// Const arguments, repeated/subset parameters, bounds, where clauses, and
    /// other type syntax still need a substitution proof that this identity
    /// projection does not provide.
    fn impl_generic_arguments_are_unconstrained_parameters(
        &self,
        target: Node<'_>,
        arguments: Node<'_>,
    ) -> bool {
        let mut ancestor = target.parent();
        let implementation = loop {
            let Some(item) = ancestor else {
                return false;
            };
            if item.kind() == "impl_item" {
                break item;
            }
            ancestor = item.parent();
        };
        let Some(parameters) = implementation.child_by_field_name("type_parameters") else {
            return false;
        };
        let mut parameter_names: HashSet<&str> = HashSet::default();
        let mut parameter_cursor = parameters.walk();
        for parameter in parameters.named_children(&mut parameter_cursor) {
            if parameter.kind() != "type_parameter"
                || parameter.child_by_field_name("bounds").is_some()
            {
                return false;
            }
            let Some(name) = parameter.child_by_field_name("name") else {
                return false;
            };
            let spelling = strip_raw_identifier_prefix(rust_node_text(name, self.source).trim());
            if !parameter_names.insert(spelling) {
                return false;
            }
        }
        let mut implementation_cursor = implementation.walk();
        if implementation
            .named_children(&mut implementation_cursor)
            .any(|child| child.kind() == "where_clause")
        {
            return false;
        }
        if parameter_names.is_empty() {
            return false;
        }
        let mut argument_names = HashSet::default();
        let mut argument_cursor = arguments.walk();
        for argument in arguments.named_children(&mut argument_cursor) {
            if argument.kind() != "type_identifier"
                || rust_enclosing_item_generic_parameter_namespace(argument, self.source)
                    != Some(ResolutionNamespace::Type)
            {
                return false;
            }
            let spelling =
                strip_raw_identifier_prefix(rust_node_text(argument, self.source).trim());
            if !argument_names.insert(spelling) {
                return false;
            }
        }
        parameter_names == argument_names
    }

    /// A subject frontier for an impl whose target type this fragment cannot
    /// name. It is a positioned frontier with an `UnsupportedTypeSyntax` gap,
    /// so a member deferred to it never matches a qualifier and the fact says
    /// which token is the reason.
    ///
    /// The gap is a resolution gap only. The names the subject's type syntax
    /// spells (`Foo` in `&[Foo]`, `(Foo, Bar)` or `&Vec<Foo>`) are enumerated
    /// by the ordinary type lowering, so the subject hides no reference, and
    /// an enumeration gap here made every reverse answer in the file
    /// incomplete because of one `impl Trait for &[u8]`.
    fn unresolvable_impl_subject(&mut self, target: Node<'_>) -> ResolutionTypeSlotId {
        let site = self.add_site(
            target,
            ResolutionSiteKind::TypeReference,
            self.current_scope(),
        );
        let subject = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: subject,
            site,
            role: ResolutionTypeSlotRole::TargetTypeIdentity,
        });
        self.add_semantic_gap_at_site(site, ResolutionGapKind::UnsupportedTypeSyntax);
        subject
    }

    fn lower_inherent_impl(&mut self, node: Node<'_>) -> Option<InherentImplContext> {
        let target = node.child_by_field_name("type")?;
        let generic_subject = rust_enclosing_item_generic_parameter_namespace(target, self.source)
            == Some(ResolutionNamespace::Type)
            || rust_qualified_path_root_is_generic_parameter(target, self.source);
        let (subject, receiver_subject) = if generic_subject {
            self.lower_bare_type_reference(target);
            let site = self.add_site(
                target,
                ResolutionSiteKind::TypeReference,
                self.current_scope(),
            );
            let slot = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust type slot count fits u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: slot,
                site,
                role: ResolutionTypeSlotRole::TargetTypeIdentity,
            });
            self.add_frontier_gaps(site, &[ResolutionGapKind::UnsupportedTypeSyntax]);
            (slot, slot)
        } else {
            match self.lower_impl_type_identity(target) {
                Some(lowered)
                    if lowered.indirection == 0
                        && lowered.reference_indirection == 0
                        && rust_is_supported_inherent_impl_target(target, self.source) =>
                {
                    (
                        self.lower_nominal_type_identity(target)
                            .expect("accepted impl type has nominal identity"),
                        lowered.identity,
                    )
                }
                // The subject's type syntax carries an identity this fragment
                // cannot name, or none at all: a reference, a slice, a tuple, a
                // primitive, a `dyn` object, or a wrapper head that projects
                // its payload and would attach these members to the payload's
                // declaration. The impl still has members, and their bodies are
                // ordinary source, so it takes a frontier that resolves to
                // nothing and says so rather than losing the whole body.
                Some(_) | None => {
                    let slot = self.unresolvable_impl_subject(target);
                    (slot, slot)
                }
            }
        };
        // Two impls state something other than "this type implements this
        // trait", and neither may become a positive relation.
        //
        // `impl !Trait for Type` states the opposite outright. `generate! {
        // impl Trait for Type { .. } }` states only that a macro could produce
        // one: the item does not exist until the macro is replayed, and a
        // replay is evidence of uncertainty rather than of an implementation.
        // Both still own a subject and a body, so only the trait half is
        // withheld and the members stay where they are.
        let negated = node
            .children(&mut node.walk())
            .any(|child| child.kind() == "!");
        let from_macro_fragment = self.macro_fragment_nodes.contains(&node.id());
        let trait_target = node
            .child_by_field_name("trait")
            .filter(|_| !negated && !from_macro_fragment)
            .and_then(|target| {
                self.lower_impl_type_identity(target).map(|lowered| {
                    let reference = self.facts.type_slots[lowered.identity.index()].site;
                    self.facts.gaps.push(ResolutionGapFact {
                        site: reference,
                        kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                    });
                    (reference, lowered.identity)
                })
            });
        let relation =
            ResolutionTypeRelationId::try_from_index(self.facts.declared_type_relations.len())
                .expect("Rust declared type-relation count exceeds u32");
        self.facts
            .declared_type_relations
            .push(ResolutionDeclaredTypeRelationFact {
                id: relation,
                subject,
                kind: if trait_target.is_some() {
                    ResolutionDeclaredTypeRelationKind::TraitImplementation
                } else {
                    ResolutionDeclaredTypeRelationKind::InherentImplementation
                },
                target_reference: trait_target.map(|(reference, _)| reference),
                target: trait_target.map(|(_, target)| target),
            });
        let context = InherentImplContext {
            subject,
            receiver_subject,
            relation,
            next_member_ordinal: 0,
            // `impl crate::m::Type` binds `self` exactly as `impl Type` does:
            // `receiver_subject` is the same exact impl subject identity.
            supports_standard_self: matches!(
                target.kind(),
                "type_identifier"
                    | "identifier"
                    | "scoped_type_identifier"
                    | "scoped_identifier"
                    | "generic_type"
            ) || rust_is_unmodelled_primitive_spelling(target, self.source),
        };
        assert!(
            self.inherent_impls.insert(node.id(), context).is_none(),
            "one Rust impl node has one lowering context"
        );
        assert!(
            self.self_type_frontiers
                .insert(
                    node.id(),
                    RustSelfTypes {
                        nominal: subject,
                        receiver: receiver_subject
                    }
                )
                .is_none(),
            "one Rust impl has one Self frontier"
        );
        Some(context)
    }

    /// The `impl` or trait whose body declares `node` as a member.
    ///
    /// In source that is the syntax around the node. An item a passthrough
    /// invocation expands to is a node of declaration replay's tree, whose
    /// root is the invocation's token-tree interior, so its syntax ends there;
    /// when the invocation is written in an `impl` or trait body, the items at
    /// the top of that tree are members of that `impl` or trait, exactly as
    /// the expansion puts them.
    fn member_owner(&self, node: Node<'_>) -> Option<MemberOwner> {
        if let Some(owner) = rust_trait_or_impl_member_owner(node) {
            return Some(MemberOwner {
                node: owner.id(),
                is_trait: owner.kind() == "trait_item",
            });
        }
        let replayed = self.replayed_member_owner?;
        crate::syntax::parent_outside_attributes(node)
            .is_some_and(|parent| parent.parent().is_none())
            .then_some(replayed)
    }

    /// The lowered impl context of `node`'s owning impl, when `node` is a
    /// direct member of an impl whose subject this fragment could lower.
    fn inherent_impl_for_member(&self, node: Node<'_>) -> Option<usize> {
        let owner = self.member_owner(node)?;
        (!owner.is_trait && self.inherent_impls.contains_key(&owner.node)).then_some(owner.node)
    }

    fn lower_associated_type_declaration(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let impl_id = self.inherent_impl_for_member(node);
        let scope = self.current_scope();
        let trait_owner = (self.facts.scopes[scope.index()].kind == ResolutionScopeKind::TypeBody)
            .then(|| self.facts.scopes[scope.index()].owner)
            .flatten();
        if impl_id.is_none() && trait_owner.is_none() {
            return None;
        }
        let name = node.child_by_field_name("name")?;
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::TypeAliasDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
            scope,
        );
        self.record_declaration_site(node, declaration);
        self.declaration_owners.push(declaration);
        self.publish_associated_item_visibility(
            node,
            declaration,
            impl_id.map(|impl_id| self.inherent_impls[&impl_id].relation),
        );
        if let Some(impl_id) = impl_id {
            let context = self
                .inherent_impls
                .get_mut(&impl_id)
                .expect("registered associated impl");
            self.facts
                .relation_members
                .push(ResolutionRelationMemberFact {
                    relation: context.relation,
                    ordinal: context.next_member_ordinal,
                    member: declaration,
                    kind: ResolutionMemberKind::AssociatedType,
                });
            context.next_member_ordinal = context
                .next_member_ordinal
                .checked_add(1)
                .expect("Rust impl member count exceeds u32");
            self.facts
                .deferred_member_owners
                .push(ResolutionDeferredMemberOwnerFact {
                    member: declaration,
                    owner_type: context.subject,
                    kind: ResolutionMemberKind::AssociatedType,
                    access: ResolutionMemberAccess::Type,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
                });
        } else {
            self.add_scope_wide_binder(declaration, scope, ResolutionBinderKind::Type);
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: declaration,
                owner: trait_owner.expect("associated trait owner"),
                kind: ResolutionMemberKind::AssociatedType,
                access: ResolutionMemberAccess::Type,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            });
        }
        if node.child_by_field_name("type").is_some() {
            self.lower_type_alias_target(node, declaration);
        }
        Some(declaration)
    }

    /// An associated constant of a trait or an impl. This is
    /// [`Self::lower_associated_type_declaration`] in the Value namespace: the
    /// declaration is a member of the impl's subject frontier or of the trait
    /// itself, never a free lexical binder in the surrounding module, and its
    /// declared type is lowered here while the walk lowers its value
    /// expression below.
    fn lower_associated_constant_declaration(
        &mut self,
        node: Node<'_>,
    ) -> Option<ResolutionSiteId> {
        let impl_id = self.inherent_impl_for_member(node);
        let scope = self.current_scope();
        let trait_owner = (self.facts.scopes[scope.index()].kind == ResolutionScopeKind::TypeBody)
            .then(|| self.facts.scopes[scope.index()].owner)
            .flatten();
        if impl_id.is_none() && trait_owner.is_none() {
            return None;
        }
        let name = node.child_by_field_name("name")?;
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::ValueDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            scope,
        );
        self.record_declaration_site(node, declaration);
        self.publish_associated_item_visibility(
            node,
            declaration,
            impl_id.map(|impl_id| self.inherent_impls[&impl_id].relation),
        );
        if let Some(impl_id) = impl_id {
            let context = self
                .inherent_impls
                .get_mut(&impl_id)
                .expect("registered associated impl");
            self.facts
                .relation_members
                .push(ResolutionRelationMemberFact {
                    relation: context.relation,
                    ordinal: context.next_member_ordinal,
                    member: declaration,
                    kind: ResolutionMemberKind::Field,
                });
            context.next_member_ordinal = context
                .next_member_ordinal
                .checked_add(1)
                .expect("Rust impl member count exceeds u32");
            self.facts
                .deferred_member_owners
                .push(ResolutionDeferredMemberOwnerFact {
                    member: declaration,
                    owner_type: context.subject,
                    kind: ResolutionMemberKind::Field,
                    access: ResolutionMemberAccess::Type,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
                });
        } else {
            self.add_scope_wide_binder(declaration, scope, ResolutionBinderKind::Field);
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: declaration,
                owner: trait_owner.expect("associated trait owner"),
                kind: ResolutionMemberKind::Field,
                access: ResolutionMemberAccess::Type,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            });
        }
        self.lower_declared_value_types(
            &[declaration],
            node.child_by_field_name("type"),
            DeclarationTypeRole::Value,
        );
        Some(declaration)
    }

    /// Publish the declared visibility of an associated item: a method,
    /// constant or type of an impl, or an item of a trait (`relation` is
    /// `None`). A trait item and an item of a trait impl take the trait's
    /// visibility, so they are public here. An item of an inherent impl has
    /// its own visibility, and a private `const` is as inaccessible outside
    /// its module as a private method (rustc E0624).
    fn publish_associated_item_visibility(
        &mut self,
        node: Node<'_>,
        declaration: ResolutionSiteId,
        relation: Option<ResolutionTypeRelationId>,
    ) {
        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
        let visibility = match relation {
            Some(relation)
                if self.facts.declared_type_relations[relation.index()].kind
                    == ResolutionDeclaredTypeRelationKind::InherentImplementation =>
            {
                crate::declaration_properties::declared_visibility(
                    &self.declaration_properties_for_node(node).visibility,
                )
            }
            _ => DeclaredVisibility::Public,
        };
        self.facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration,
                visibility,
            });
        if visibility != DeclaredVisibility::Public {
            // Exact Rust module access for deferred members is not yet a
            // shared typed-graph relation. Retain that source-owned boundary;
            // the common visibility pass must not certify the candidate, and
            // the selected access policy decides it per requester module.
            self.facts.gaps.push(ResolutionGapFact {
                site: declaration,
                kind: ResolutionGapKind::UnsupportedVisibility,
            });
        }
    }

    fn lower_inherent_method(
        &mut self,
        node: Node<'_>,
        impl_id: usize,
    ) -> Option<ResolutionSiteId> {
        let context = self
            .inherent_impls
            .get(&impl_id)
            .copied()
            .expect("inherent method has a registered impl context");
        let Some(declaration) = self.lower_inherent_method_declaration(node, context) else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return None;
        };
        self.facts
            .relation_members
            .push(ResolutionRelationMemberFact {
                relation: context.relation,
                ordinal: context.next_member_ordinal,
                member: declaration,
                kind: ResolutionMemberKind::Method,
            });
        assert!(
            self.inherent_impls
                .insert(
                    impl_id,
                    InherentImplContext {
                        next_member_ordinal: context
                            .next_member_ordinal
                            .checked_add(1)
                            .expect("Rust impl member count exceeds u32"),
                        ..context
                    },
                )
                .is_some(),
            "inherent impl context remains present while lowering members"
        );
        self.lower_callable_body(node, declaration);
        Some(declaration)
    }

    fn lower_inherent_method_declaration(
        &mut self,
        node: Node<'_>,
        context: InherentImplContext,
    ) -> Option<ResolutionSiteId> {
        let name = node.child_by_field_name("name")?;
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::CallableDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            self.current_scope(),
        );
        self.record_declaration_site(node, declaration);
        self.declaration_owners.push(declaration);
        // Bounds are references in this method's signature. Publish the owner
        // before lowering them, as for free functions and trait methods.
        if node.child_by_field_name("type_parameters").is_some() {
            self.enter_generic_parameter_scope(node, None);
        }
        self.publish_associated_item_visibility(node, declaration, Some(context.relation));
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: node.child_by_field_name("type_parameters").map_or(
                    0,
                    |parameters| {
                        u32::try_from(parameters.named_child_count())
                            .expect("Rust type parameter count exceeds u32")
                    },
                ),
                result_types: Vec::new(),
            });
        self.lower_callable_return_type(node, declaration);
        self.publish_receiver_form(node, declaration);
        let has_self = node
            .child_by_field_name("parameters")
            .is_some_and(rust_parameters_have_self);
        // Deferred owners and qualified references retain dispatch
        // uncertainty. A lexical gap on this declaration would
        // incorrectly withhold a same-named free-function candidate.
        self.facts
            .deferred_member_owners
            .push(ResolutionDeferredMemberOwnerFact {
                member: declaration,
                owner_type: context.subject,
                kind: ResolutionMemberKind::Method,
                access: if has_self {
                    ResolutionMemberAccess::Instance
                } else {
                    ResolutionMemberAccess::Type
                },
                qualifier_compatibility: if has_self {
                    ResolutionMemberQualifierCompatibility::RuntimeOrType
                } else {
                    ResolutionMemberQualifierCompatibility::TypeOnly
                },
            });
        if context.supports_standard_self
            && node
                .child_by_field_name("parameters")
                .is_some_and(rust_has_standard_self_parameter)
        {
            assert!(
                self.inherent_method_owner_types
                    .insert(declaration, context.receiver_subject)
                    .is_none(),
                "one standard-self inherent method has one owner frontier"
            );
        }
        Some(declaration)
    }

    /// The declaration facts of a trait method, which the bodyless signature
    /// form and the default-body form share. Only the scope and parameter
    /// treatment differ between them.
    fn lower_trait_method_declaration(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let name = node.child_by_field_name("name")?;
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::CallableDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
            self.current_scope(),
        );
        self.record_declaration_site(node, declaration);
        self.declaration_owners.push(declaration);
        let scope = self.current_scope();
        let owner = self.facts.scopes[scope.index()]
            .owner
            .expect("trait member scope owner");
        self.add_scope_wide_binder(declaration, scope, ResolutionBinderKind::Callable);
        self.declare_definition_namespace(
            declaration,
            ResolutionNamespace::Value,
            HoistingClass::ScopeWide,
        );
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member: declaration,
            owner,
            kind: ResolutionMemberKind::Method,
            access: if node
                .child_by_field_name("parameters")
                .is_some_and(rust_parameters_have_self)
            {
                ResolutionMemberAccess::Instance
            } else {
                ResolutionMemberAccess::Type
            },
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOrType,
        });
        self.facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration,
                visibility: DeclaredVisibility::Public,
            });

        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: node.child_by_field_name("type_parameters").map_or(
                    0,
                    |parameters| {
                        u32::try_from(parameters.named_child_count())
                            .expect("Rust type parameter count exceeds u32")
                    },
                ),
                result_types: Vec::new(),
            });
        // A trait method called in path form (`Shape::area(&square)`) writes
        // its receiver as the first argument; the form says it takes one.
        self.publish_receiver_form(node, declaration);
        Some(declaration)
    }

    /// The body of a trait method that has one, lowered with the machinery an
    /// inherent method's body uses: one executable scope under the trait's
    /// member scope, `self` bound to the trait's own abstract `Self` frontier,
    /// and parameters and locals as usual. The receiver's type is that
    /// frontier, which carries the trait's `UnsupportedHierarchyTraversal`
    /// gap, so `self.member()` inside a default body stays honestly
    /// unresolved while the `self` token itself has a binder.
    fn lower_trait_default_method_body(&mut self, node: Node<'_>, declaration: ResolutionSiteId) {
        if node
            .child_by_field_name("parameters")
            .is_some_and(rust_has_standard_self_parameter)
        {
            let owner_type = self
                .enclosing_self_type_frontier(node)
                .expect("a lowered trait declaration owns an abstract Self frontier");
            assert!(
                self.inherent_method_owner_types
                    .insert(declaration, owner_type)
                    .is_none(),
                "one trait default method has one receiver frontier"
            );
        }
        self.lower_callable_return_type(node, declaration);
        self.lower_callable_body(node, declaration);
    }

    fn enter_trait_method_signature(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let declaration = self.lower_trait_method_declaration(node)?;
        let scope = self.allocate_scope(
            self.current_scope(),
            Some(declaration),
            ResolutionScopeKind::Executable,
            node.start_byte(),
            node.end_byte(),
        );
        self.scopes.push(scope);
        self.exits.push(ExitAction::DeclarationScope);
        if let Some(parameters) = node.child_by_field_name("type_parameters") {
            self.lower_generic_parameter_binders(
                parameters,
                scope,
                node.start_byte(),
                node.end_byte(),
            );
        }
        self.lower_callable_return_type(node, declaration);
        let mut formals = Vec::new();
        if let Some(parameters) = node.child_by_field_name("parameters") {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if parameter.has_error() {
                    self.add_local_gap(parameter, ResolutionGapKind::MalformedSyntax);
                    self.mark_syntax_subtree_consumed(parameter);
                    continue;
                }
                // A bodyless receiver introduces no runtime use. Explicit
                // receiver type syntax is still visited by the ordinary walk.
                if parameter.kind() == "self_parameter" {
                    self.mark_syntax_subtree_consumed(parameter);
                    continue;
                }
                if let Some(pattern) = parameter.child_by_field_name("pattern") {
                    if pattern.kind() == "self" {
                        self.mark_syntax_subtree_consumed(pattern);
                        continue;
                    }
                    formals.extend(self.lower_ordinary_parameter(
                        parameter,
                        pattern,
                        scope,
                        node.start_byte(),
                    ));
                }
            }
        }
        self.publish_callable_parameters(node, declaration, &formals);
        Some(declaration)
    }

    /// Type syntax can contain independent structured references. Walk that
    /// subtree so generic arguments and positioned `Self` references are
    /// retained without inventing member or lexical binders.
    fn lower_return_type_children(&mut self, root: Node<'_>) {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            match node.kind() {
                "type_identifier" => self.lower_bare_type_reference(node),
                "scoped_type_identifier" => {
                    if !self.handled_identifiers.contains(&node.id()) {
                        self.lower_qualified_type_reference(node);
                    }
                }
                "identifier" => {
                    if rust_occurrence_role(node) == Some(OccurrenceRole::TypeOperand) {
                        self.lower_bare_type_reference(node);
                    } else {
                        self.lower_bare_expression_reference(node);
                    }
                }
                "scoped_identifier" => {
                    if rust_occurrence_role(node) == Some(OccurrenceRole::TypeOperand) {
                        if !self.handled_identifiers.contains(&node.id()) {
                            self.lower_qualified_type_reference(node);
                        }
                    } else if !self.handled_identifiers.contains(&node.id()) {
                        self.lower_scoped_expression_reference(node);
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
    }

    fn mark_syntax_subtree_consumed(&mut self, node: Node<'_>) {
        self.consumed_subtrees.insert(node.id());
    }

    /// Prevent path-prefix tokens from becoming synthetic lexical references.
    /// The path may be left-nested and may contain generic wrappers, so follow
    /// the grammar fields rather than inspecting the source spelling.
    fn mark_scoped_path_consumed(&mut self, node: Node<'_>) {
        let mut current = Some(node);
        while let Some(current_node) = current {
            self.handled_identifiers.insert(current_node.id());
            current = match current_node.kind() {
                "scoped_identifier" | "scoped_type_identifier" => {
                    if let Some(name) = current_node.child_by_field_name("name") {
                        self.handled_identifiers.insert(name.id());
                    }
                    current_node.child_by_field_name("path")
                }
                "generic_type" => current_node.child_by_field_name("type"),
                "generic_function" => current_node.child_by_field_name("function"),
                _ => None,
            };
        }
    }

    fn nearest_root_scope(&self) -> ResolutionScopeId {
        let mut scope = self.current_scope();
        loop {
            match self.facts.scopes[scope.index()].kind {
                ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package => {
                    return scope;
                }
                ResolutionScopeKind::File
                | ResolutionScopeKind::TypeBody
                | ResolutionScopeKind::Executable
                | ResolutionScopeKind::Initializer
                | ResolutionScopeKind::Block => {
                    scope = self.facts.scopes[scope.index()]
                        .parent
                        .expect("non-root Rust scope has a root ancestor");
                }
            }
        }
    }

    fn add_scope_wide_binder(
        &mut self,
        declaration: ResolutionSiteId,
        scope: ResolutionScopeId,
        kind: ResolutionBinderKind,
    ) {
        let bounds = self.facts.scopes[scope.index()];
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope,
            kind,
            hoisting: HoistingClass::ScopeWide,
            activation_start: bounds.start_byte,
            activation_end: bounds.end_byte,
        });
    }

    fn current_scope_is_module_owned(&self) -> bool {
        matches!(
            self.facts.scopes[self.current_scope().index()].kind,
            ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
        )
    }

    fn add_module_root_export(
        &mut self,
        declaration: ResolutionSiteId,
        namespace: ResolutionNamespace,
    ) {
        let root_scope = self.current_scope();
        assert!(
            self.current_scope_is_module_owned(),
            "a Rust root export must be owned by a compilation or package scope"
        );
        self.facts.root_exports.push(ResolutionRootExportFact {
            root_scope,
            declaration,
            namespace,
        });
    }

    fn declare_definition_namespace(
        &mut self,
        declaration: ResolutionSiteId,
        namespace: ResolutionNamespace,
        hoisting: HoistingClass,
    ) {
        assert!(
            self.facts
                .additional_definition_namespaces
                .iter()
                .all(|fact| fact.declaration != declaration || fact.namespace != namespace),
            "one Rust definition namespace authority per declaration and namespace"
        );
        self.facts.additional_definition_namespaces.push(
            ResolutionAdditionalDefinitionNamespaceFact {
                declaration,
                namespace,
                hoisting,
            },
        );
    }

    fn lower_item_declaration(
        &mut self,
        node: Node<'_>,
        site_kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
        binder_kind: ResolutionBinderKind,
    ) -> Option<ResolutionSiteId> {
        let name = node.child_by_field_name("name")?;
        let scope = self.item_scope();
        let declaration = self.add_identifier(
            name,
            site_kind,
            ResolutionIdentifierRole::Declaration,
            namespace,
            scope,
        );
        self.record_declaration_site(node, declaration);
        self.add_scope_wide_binder(declaration, scope, binder_kind);
        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
        let module_owned = self.current_scope_is_module_owned();
        if module_owned && self.conditional_serde_items.contains(&node.id()) {
            // The declaration itself is the open question: a name-keyed gap on
            // its own site leaves every lookup of this name, and every path
            // that reaches this declaration, incomplete until the stage closes
            // the reason, and no other lookup in the scope. A block-local item
            // already carries this gap for its own reason below, and the stage
            // closes only module-level items.
            self.facts.gaps.push(ResolutionGapFact {
                site: declaration,
                kind: ResolutionGapKind::UnsupportedScopeOrBinder,
            });
        }
        if module_owned {
            // Root exports are candidate endpoints, not visibility authority.
            // Retain every module-owned named declaration so selected context
            // can join this exact source site through the native declaration
            // bridge and apply visibility at the terminal.
            self.add_module_root_export(declaration, namespace);
        } else if rust_item_requires_parser_unit(node.kind()) {
            // Rust items are scope-wide lexical declarations even inside a
            // block, and this one's binder is fully modelled: the scope, the
            // name, the activation and the declaration site are all here. Its
            // only shortfall is that selected navigation cannot project it
            // through the module-owned parser-unit inventory, which is a
            // property of this declaration and not of the scope it sits in.
            //
            // It used to say so with an `UnsupportedScopeOrBinder` gap. That
            // kind means the binder structure itself is unknown, and lowering
            // answers it with a wildcard forward candidate gap on the whole
            // enclosing scope, so one `struct Adapter {}` in a function body
            // turned every reference in that body incomplete, whatever it
            // named (#2033). `record_declaration_site` above already bridged
            // this resolution site to the item's canonical source declaration;
            // marking that declaration lexical is the whole of the evidence a
            // consumer can act on, and the point route already answers such a
            // reference with a located lexical definition rather than a
            // `CodeUnit`.
            if node.kind() != "type_item" {
                self.facts.gaps.push(ResolutionGapFact {
                    site: declaration,
                    kind: ResolutionGapKind::UnsupportedScopeOrBinder,
                });
            }
            let source_declaration = self.declaration_properties_for_node(node).declaration;
            self.source_collector
                .mark_lexical(source_declaration, DeclarationKind::BlockLocalItem);
        }
        // A local alias is accessible wherever its lexical binder is visible.
        // Its scope supplies that boundary; it never becomes a root export.
        if self.declaration_properties_for_node(node).visibility == RustVisibility::Public
            || (!module_owned && node.kind() == "type_item")
        {
            self.facts
                .declaration_visibilities
                .push(ResolutionDeclarationVisibilityFact {
                    declaration,
                    visibility: DeclaredVisibility::Public,
                });
        }
        Some(declaration)
    }

    fn lower_struct_declaration(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let declaration = self.lower_item_declaration(
            node,
            ResolutionSiteKind::TypeDeclaration,
            ResolutionNamespace::Type,
            ResolutionBinderKind::Type,
        )?;
        // The value item's visibility is the least visible of the struct and
        // its fields, capped at `pub(crate)` by `#[non_exhaustive]`. A root
        // export carries the declaration's own visibility, so it states the
        // constructor exactly when the two agree: `struct Some(u8)` is a
        // private constructor visible in its module, and must shadow the
        // prelude's `Some` there. When they disagree, as for
        // `pub struct Id(u8)`, exporting would publish a constructor rustc
        // hides, so the export is withheld.
        let (has_constructor, constructor_shares_item_visibility) = {
            let properties = self.declaration_properties_for_node(node);
            let shares = properties
                .value_constructor
                .as_deref()
                .is_some_and(|constructor| {
                    !(constructor.non_exhaustive && properties.visibility == RustVisibility::Public)
                        && constructor.field_visibilities.iter().all(|visibility| {
                            *visibility == RustVisibility::Public
                                || *visibility == properties.visibility
                        })
                });
            (properties.value_constructor.is_some(), shares)
        };
        if !has_constructor {
            return Some(declaration);
        }

        self.declare_definition_namespace(
            declaration,
            ResolutionNamespace::Value,
            HoistingClass::ScopeWide,
        );
        if constructor_shares_item_visibility && self.current_scope_is_module_owned() {
            self.add_module_root_export(declaration, ResolutionNamespace::Value);
        }
        if node.child_by_field_name("body").is_none() {
            // A unit struct's value item is its one zero-argument
            // construction: `struct Square;` makes `Square` a value of type
            // `Square`. A tuple struct's value item is its constructor
            // function instead, which carries no marker.
            self.add_semantic_gap_at_site(declaration, ResolutionGapKind::ImplicitConstructor);
        }
        Some(declaration)
    }

    /// Publish a named struct or union field as a declaration carrying its
    /// declared value type.
    ///
    /// The producer never lowered a field at all: the walk reached the
    /// `field_identifier` and recorded an unlowered boundary. A field is a
    /// member of its owner, which is a `member_owners` row, and a member's
    /// declared type is a `declaration_type_slots` row, which typed fact
    /// lowering builds from nothing else. Without both, a member chain such as
    /// `outer.inner.value` has no receiver type at its second step, so its
    /// terminal has nothing to look a member up in.
    ///
    /// The binder is what a member lookup actually reads: it searches the
    /// owner's member scope head, and a scope's contents are its binders. With
    /// the member row alone every member read stayed unresolved. The binder is
    /// scope-wide inside the type body only, so a bare `value` in the enclosing
    /// module still cannot resolve to a field: nothing outside the type enters
    /// that scope.
    ///
    /// Struct-like enum variants own their fields in a separate member scope.
    fn lower_named_field_declaration(&mut self, node: Node<'_>) {
        let owner_node = node
            .parent()
            .and_then(|fields| fields.parent())
            .filter(|owner| matches!(owner.kind(), "struct_item" | "union_item" | "enum_variant"));
        let Some(owner) = owner_node.and_then(|owner| self.declaration_site_for_node(owner.id()))
        else {
            return;
        };
        let Some(name) = node.child_by_field_name("name") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::ValueDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            self.current_scope(),
        );
        let visibility = self
            .declaration_properties_for_node(node)
            .visibility
            .clone();
        self.publish_field_declaration(
            node,
            declaration,
            owner,
            node.child_by_field_name("type"),
            visibility,
        );
    }

    fn lower_positional_field_declarations(&mut self, node: Node<'_>) {
        let Some(owner) = node
            .parent()
            .and_then(|owner| self.declaration_site_for_node(owner.id()))
        else {
            return;
        };
        let default_visibility = if node.parent().unwrap().kind() == "enum_variant" {
            RustVisibility::Public
        } else {
            RustVisibility::Private
        };
        let mut visibility = default_visibility.clone();
        let mut position = 0;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "attribute_item" | "inner_attribute_item" | "line_comment" | "block_comment" => {
                    continue;
                }
                "visibility_modifier" => {
                    visibility = crate::imports::rust_visibility_from_modifier(child, self.source);
                    continue;
                }
                _ => {}
            }
            let source_declaration = self.declaration_properties.ensure_positional_field(
                child,
                visibility.clone(),
                &mut self.source_collector,
            );
            self.source_collector.mark_lexical_identifier(
                source_declaration,
                DeclarationKind::Field,
                position.to_string(),
            );
            let name_occurrence = self
                .source_collector
                .declaration(source_declaration)
                .name
                .expect("positional field name anchor");
            let declaration = self.add_site_for_occurrence(
                name_occurrence,
                ResolutionSiteKind::ValueDeclaration,
                self.current_scope(),
            );
            let name = self.intern_spelling(&position.to_string());
            self.facts.identifiers.push(PositionedIdentifierFact {
                site: declaration,
                name,
                role: ResolutionIdentifierRole::Declaration,
                namespace: ResolutionNamespace::Value,
                qualifier: None,
            });
            self.publish_field_declaration(child, declaration, owner, Some(child), visibility);
            visibility = default_visibility.clone();
            position += 1;
        }
    }

    fn publish_field_declaration(
        &mut self,
        node: Node<'_>,
        declaration: ResolutionSiteId,
        owner: ResolutionSiteId,
        ty: Option<Node<'_>>,
        visibility: RustVisibility,
    ) {
        let scope = self.current_scope();
        self.record_declaration_site(node, declaration);
        self.add_scope_wide_binder(declaration, scope, ResolutionBinderKind::Field);
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member: declaration,
            owner,
            kind: ResolutionMemberKind::Field,
            access: ResolutionMemberAccess::Instance,
            // Rust has no `Type::field` selection: a field is reachable only
            // through a value of its owner.
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
        });
        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
        if visibility == RustVisibility::Public {
            self.facts
                .declaration_visibilities
                .push(ResolutionDeclarationVisibilityFact {
                    declaration,
                    visibility: DeclaredVisibility::Public,
                });
        }
        self.lower_declared_value_types(&[declaration], ty, DeclarationTypeRole::Value);
    }

    /// A variant has one constructor identity with explicit Rust namespace
    /// authorities. Value reads, calls, and patterns retain that same identity.
    fn lower_enum_variant(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let owner_node = node
            .parent()
            .and_then(|variants| variants.parent())
            .filter(|owner| owner.kind() == "enum_item");
        let owner_node = owner_node?;
        let owner = self.declaration_site_for_node(owner_node.id())?;
        let Some(name) = node.child_by_field_name("name") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return None;
        };
        let scope = self.current_scope();
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::ConstructorDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
            scope,
        );
        self.record_declaration_site(node, declaration);
        self.add_scope_wide_binder(declaration, scope, ResolutionBinderKind::Constructor);
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member: declaration,
            owner,
            kind: ResolutionMemberKind::Constructor,
            access: ResolutionMemberAccess::Type,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
        });
        let body = node.child_by_field_name("body");
        for namespace in std::iter::once(ResolutionNamespace::Value)
            .chain(body.map(|_| ResolutionNamespace::Type))
        {
            self.declare_definition_namespace(declaration, namespace, HoistingClass::ScopeWide);
            self.facts.root_exports.push(ResolutionRootExportFact {
                root_scope: scope,
                declaration,
                namespace,
            });
        }
        if node
            .child_by_field_name("body")
            .is_some_and(|body| body.kind() == "ordered_field_declaration_list")
        {
            self.declare_definition_namespace(
                declaration,
                ResolutionNamespace::Callable,
                HoistingClass::ScopeWide,
            );
        }
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: 0,
                result_types: Vec::new(),
            });
        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
        if self.declaration_properties_for_node(owner_node).visibility == RustVisibility::Public {
            self.facts
                .declaration_visibilities
                .push(ResolutionDeclarationVisibilityFact {
                    declaration,
                    visibility: DeclaredVisibility::Public,
                });
        }
        Some(declaration)
    }

    fn lower_function(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let Some(declaration) = self.lower_function_declaration(node) else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return None;
        };
        self.lower_callable_body(node, declaration);
        Some(declaration)
    }

    fn lower_callable_body(
        &mut self,
        node: Node<'_>,
        declaration: ResolutionSiteId,
    ) -> Option<ResolutionSiteId> {
        let Some(body) = node.child_by_field_name("body") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            // No parameter was lowered, so the absent rows are not arity zero,
            // and none can decide a generic result.
            self.retain_parameter_inventory_gap(declaration);
            self.callable_result_heads.remove(&declaration);
            return None;
        };
        let executable = self.allocate_statement_scope(
            self.item_scope(),
            Some(declaration),
            ResolutionScopeKind::Executable,
            node.start_byte(),
            body.end_byte(),
            body,
        );
        assert!(
            self.pending_scopes
                .insert(
                    body.id(),
                    PendingScope {
                        scope: executable,
                        callable: Some(declaration),
                    },
                )
                .is_none(),
            "one Rust callable body owns one scope"
        );
        let mut formals = Vec::new();
        if let Some(parameters) = node.child_by_field_name("parameters") {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if parameter.has_error() {
                    self.add_local_gap(parameter, ResolutionGapKind::MalformedSyntax);
                    self.mark_syntax_subtree_consumed(parameter);
                    continue;
                }
                if parameter.kind() == "self_parameter" {
                    if let Some(owner_type) =
                        self.inherent_method_owner_types.get(&declaration).copied()
                    {
                        self.lower_standard_self_parameter(
                            parameter,
                            executable,
                            body.start_byte(),
                            body.end_byte(),
                            owner_type,
                        );
                    } else {
                        // Generic, unknown, and non-inherent receiver owners
                        // remain an explicit unsupported boundary. In
                        // particular, do not turn a receiver token into a
                        // free lexical binder when its owner cannot be exact.
                        self.mark_syntax_subtree_consumed(parameter);
                    }
                    continue;
                }
                let pattern = parameter
                    .child_by_field_name("pattern")
                    .or_else(|| (parameter.kind() == "identifier").then_some(parameter));
                if let Some(pattern) = pattern {
                    if pattern.kind() == "self" {
                        // A typed `self: T` parameter is not the standard Rust
                        // receiver form. Keep its type syntax structured, but
                        // do not invent a free Value binder for the `self`
                        // pattern or admit it to the native receiver frontier.
                        // The gap is about the receiver's binding only: the
                        // `self` token declares, and the names its type spells
                        // are enumerated, so the parameter hides no reference.
                        self.mark_syntax_subtree_consumed(pattern);
                        if let Some(type_node) = parameter.child_by_field_name("type") {
                            self.lower_declared_type_identity(type_node);
                        }
                        self.add_semantic_gap(parameter, ResolutionGapKind::UnsupportedTypeSyntax);
                        continue;
                    }
                    formals.extend(self.lower_ordinary_parameter(
                        parameter,
                        pattern,
                        executable,
                        body.start_byte(),
                    ));
                }
            }
        }
        self.publish_callable_parameters(node, declaration, &formals);
        Some(declaration)
    }

    /// Lower one ordinary (non-receiver) parameter: its pattern's binders and
    /// its declared type.
    ///
    /// Returns the parameter's own declaration and declared-value slot when
    /// the pattern is one name or `_`, which are the shapes a
    /// callable-parameter row can name. `_` binds nothing, so it gets a value
    /// declaration site with no identifier and no binder, and its slot carries
    /// no declaration-type property: it is the parameter at its position
    /// without being a definition anything can reach. A destructuring pattern
    /// has no single declaration and returns `None`.
    fn lower_ordinary_parameter(
        &mut self,
        parameter: Node<'_>,
        pattern: Node<'_>,
        scope: ResolutionScopeId,
        activation_start: usize,
    ) -> Option<LoweredParameter> {
        let type_node = parameter.child_by_field_name("type");
        if pattern.kind() == "_" {
            let site = self.add_site(pattern, ResolutionSiteKind::ValueDeclaration, scope);
            let declared = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: declared,
                site,
                role: ResolutionTypeSlotRole::DeclaredValue,
            });
            let declared_type = type_node.and_then(|node| self.lower_declared_type_identity(node));
            self.transfer_declared_type(declared_type, site, declared);
            return Some(LoweredParameter {
                declaration: site,
                value_type: declared,
                declared_type,
            });
        }
        let declarations = self.lower_pattern_bindings(
            pattern,
            scope,
            ResolutionBinderKind::Parameter,
            activation_start,
            RustPatternBindingPosition::Irrefutable,
        );
        if pattern.kind() != "identifier" {
            self.lower_declared_value_types(
                &declarations,
                type_node,
                DeclarationTypeRole::Parameter,
            );
            return None;
        }
        let [declaration] = declarations[..] else {
            panic!("an identifier parameter pattern declares one name: {declarations:?}");
        };
        let declared_type = type_node.and_then(|node| self.lower_declared_type_identity(node));
        let [(_, value_type)] = self
            .allocate_declaration_type_slots(&[declaration], DeclarationTypeRole::Parameter)[..]
        else {
            unreachable!("one declaration allocates one slot");
        };
        self.transfer_declared_type(declared_type, declaration, value_type);
        Some(LoweredParameter {
            declaration,
            value_type,
            declared_type,
        })
    }

    /// Publish one callable's parameter rows in source order, receivers
    /// excluded: a method call supplies its receiver through the call's
    /// receiver slot, not as an argument. A parameter list with any shape the
    /// rows cannot state keeps the callable's applicability gap and publishes
    /// no rows, so absent rows never read as arity zero and present rows never
    /// skip a position.
    fn publish_callable_parameters(
        &mut self,
        node: Node<'_>,
        callable: ResolutionSiteId,
        formals: &[LoweredParameter],
    ) {
        let result_head = self.callable_result_heads.remove(&callable);
        let Some(ordinary_count) = node
            .child_by_field_name("parameters")
            .and_then(rust_modeled_ordinary_parameter_count)
        else {
            self.retain_parameter_inventory_gap(callable);
            return;
        };
        assert_eq!(
            formals.len(),
            ordinary_count,
            "every modeled Rust parameter publishes one declaration"
        );
        for (ordinal, formal) in formals.iter().enumerate() {
            let ordinal = u32::try_from(ordinal).expect("Rust parameter count exceeds u32");
            self.facts
                .callable_parameters
                .push(ResolutionCallableParameterFact {
                    callable,
                    ordinal,
                    parameter: formal.declaration,
                    value_type: formal.value_type,
                    repeated: false,
                });
            // A parameter declared as the result's own type parameter, behind
            // any layers, binds it: the argument's type less the parameter's
            // layers is the type parameter, and the result adds its own.
            if let Some(result) = result_head
                && let Some(declared) = formal.declared_type
                && declared.head_name == result.head_name
            {
                self.facts
                    .callable_result_bindings
                    .push(ResolutionCallableResultBindingFact {
                        callable,
                        parameter_ordinal: ordinal,
                        indirection_delta: result.indirection - declared.indirection,
                        reference_indirection_delta: result.reference_indirection
                            - declared.reference_indirection,
                    });
            }
        }
    }

    /// Publish how an impl method takes its receiver, read from its
    /// `self_parameter`. Method-call lookup needs it to rank an inherent method
    /// against a trait method of the same name.
    fn publish_receiver_form(&mut self, node: Node<'_>, callable: ResolutionSiteId) {
        if let Some(form) = node
            .child_by_field_name("parameters")
            .and_then(rust_receiver_form)
        {
            self.facts
                .callable_receivers
                .push(ResolutionCallableReceiverFact { callable, form });
        }
    }

    fn retain_parameter_inventory_gap(&mut self, callable: ResolutionSiteId) {
        self.facts.gaps.push(ResolutionGapFact {
            site: callable,
            kind: ResolutionGapKind::UnsupportedCallApplicability,
        });
    }

    fn lower_standard_self_parameter(
        &mut self,
        parameter: Node<'_>,
        scope: ResolutionScopeId,
        activation_start: usize,
        activation_end: usize,
        owner_type: ResolutionTypeSlotId,
    ) {
        let Some(name) = rust_self_parameter_name(parameter) else {
            self.add_local_gap(parameter, ResolutionGapKind::MalformedSyntax);
            self.mark_syntax_subtree_consumed(parameter);
            return;
        };
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::ValueDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            scope,
        );
        let occurrence = self.source_collector.intern_node(parameter);
        let name_occurrence = self.source_collector.intern_node(name);
        let source_declaration = self.source_collector.declare_lexical(
            occurrence,
            name_occurrence,
            DeclarationKind::ReceiverParameter,
        );
        self.declaration_sources
            .push((declaration, source_declaration));
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope,
            kind: ResolutionBinderKind::Parameter,
            hoisting: HoistingClass::SourceOrder,
            activation_start,
            activation_end,
        });

        let declared = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: declared,
            site: declaration,
            role: ResolutionTypeSlotRole::DeclaredValue,
        });
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: declared,
                role: DeclarationTypeRole::Parameter,
            });

        let mut cursor = parameter.walk();
        let mut reference_indirection = 0i8;
        let mut addressable = false;
        for child in parameter.children(&mut cursor) {
            match child.kind() {
                "&" => reference_indirection = 1,
                "mutable_specifier" => addressable = true,
                _ => {}
            }
        }
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input: owner_type,
            output: declared,
            kind: ResolutionTypeTransferKind::DeclaredType,
            indirection_delta: reference_indirection,
            reference_indirection_delta: reference_indirection,
            value_transform: ResolutionTypeTransferValueTransform::ToRuntime { addressable },
        });
    }

    /// Connect source declarations to their structured declared type. The
    /// outer Rust wrappers contribute indirection provenance while the named
    /// head remains an ordinary native Type reference/projection.
    ///
    /// Returns each declaration's declared-value slot, in declaration order.
    fn lower_declared_value_types(
        &mut self,
        declarations: &[ResolutionSiteId],
        type_node: Option<Node<'_>>,
        role: DeclarationTypeRole,
    ) -> Vec<ResolutionTypeSlotId> {
        if declarations.is_empty() {
            return Vec::new();
        }
        let type_identity = type_node.and_then(|node| self.lower_declared_type_identity(node));
        let declared_slots = self.allocate_declaration_type_slots(declarations, role);
        for &(declaration, declared) in &declared_slots {
            self.transfer_declared_type(type_identity, declaration, declared);
        }
        declared_slots.into_iter().map(|(_, slot)| slot).collect()
    }

    /// Give one declared-value slot its declared type, or state on the slot's
    /// site that the type syntax has no structured identity.
    fn transfer_declared_type(
        &mut self,
        type_identity: Option<LoweredDeclaredType>,
        site: ResolutionSiteId,
        declared: ResolutionTypeSlotId,
    ) {
        if let Some(lowered) = type_identity {
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: lowered.identity,
                output: declared,
                kind: ResolutionTypeTransferKind::DeclaredType,
                indirection_delta: lowered.indirection,
                reference_indirection_delta: lowered.reference_indirection,
                value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                    addressable: false,
                },
            });
        } else {
            self.add_semantic_gap_at_site(site, ResolutionGapKind::UnsupportedTypeSyntax);
        }
    }

    fn allocate_declaration_type_slots(
        &mut self,
        declarations: &[ResolutionSiteId],
        role: DeclarationTypeRole,
    ) -> Vec<(ResolutionSiteId, ResolutionTypeSlotId)> {
        declarations
            .iter()
            .copied()
            .map(|declaration| {
                let declared = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                    .expect("Rust resolution type-slot count exceeds u32");
                self.facts.type_slots.push(ResolutionTypeSlotFact {
                    id: declared,
                    site: declaration,
                    role: ResolutionTypeSlotRole::DeclaredValue,
                });
                self.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration,
                        slot: declared,
                        role,
                    });
                (declaration, declared)
            })
            .collect()
    }

    fn lower_callable_return_type(&mut self, node: Node<'_>, declaration: ResolutionSiteId) {
        let mut cursor = node.walk();
        let is_async = node.children(&mut cursor).any(|child| {
            if child.kind() != "function_modifiers" {
                return false;
            }
            let mut modifiers = child.walk();
            child
                .children(&mut modifiers)
                .any(|modifier| modifier.kind() == "async")
        });
        if is_async {
            // The annotation describes Future::Output, not the invocation's
            // value type. Retain the binding without inventing a Future type.
            // Async does not hide any source references: only typing is open.
            self.facts.gaps.push(ResolutionGapFact {
                site: declaration,
                kind: ResolutionGapKind::UnsupportedTypeSyntax,
            });
            return;
        }
        let type_identity = match node.child_by_field_name("return_type") {
            Some(type_node) => self.lower_declared_type_identity(type_node),
            None => Some(LoweredDeclaredType {
                identity: self.add_intrinsic_type_seed(
                    declaration,
                    "()",
                    IntrinsicTypeKind::LanguageBuiltin,
                ),
                indirection: 0,
                reference_indirection: 0,
                head_name: None,
            }),
        };
        let declared = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: declared,
            site: declaration,
            role: ResolutionTypeSlotRole::DeclaredValue,
        });
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: declared,
                role: DeclarationTypeRole::Return,
            });
        if let Some(lowered) = type_identity {
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: lowered.identity,
                output: declared,
                kind: ResolutionTypeTransferKind::DeclaredType,
                indirection_delta: lowered.indirection,
                reference_indirection_delta: lowered.reference_indirection,
                value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                    addressable: false,
                },
            });
            if let Some(head) = lowered.head_name
                && let (parameters, positions_exact) = self.callable_type_parameters(node)
                && let Some(position) = parameters.iter().position(|name| *name == Some(head))
            {
                // The declared result is a type parameter of this callable:
                // each call instantiates it, and only an argument its
                // parameters bind, or an explicit type argument at its
                // position, can say to what. The declared result type, the
                // parameter's bound surface, stays as the fallback, and this
                // gap on the result's type reference says why it is not the
                // call's type.
                let reference = self.facts.type_slots[lowered.identity.index()].site;
                self.add_semantic_gap_at_site(reference, ResolutionGapKind::InferredType);
                if positions_exact {
                    self.facts.callable_result_type_parameters.push(
                        ResolutionCallableResultTypeParameterFact {
                            callable: declaration,
                            position: u32::try_from(position)
                                .expect("Rust generic parameter count exceeds u32"),
                            indirection_delta: lowered.indirection,
                            reference_indirection_delta: lowered.reference_indirection,
                        },
                    );
                }
                assert!(
                    self.callable_result_heads
                        .insert(declaration, lowered)
                        .is_none(),
                    "one Rust callable declares one result type"
                );
            } else if let Some(head) = lowered.head_name
                && let Some(position) = self.impl_target_argument_position(node, head)
            {
                // The declared result is a type parameter of the enclosing
                // impl: a call whose path's type segment writes the target
                // type's arguments (`Wrapper::<Square>::make()`) decides it.
                self.facts.callable_result_owner_type_parameters.push(
                    ResolutionCallableResultTypeParameterFact {
                        callable: declaration,
                        position,
                        indirection_delta: lowered.indirection,
                        reference_indirection_delta: lowered.reference_indirection,
                    },
                );
            }
        } else {
            self.add_semantic_gap_at_site(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
        }
    }

    /// Where the enclosing impl's type parameter `head` stands, bare, among
    /// the non-lifetime type arguments of the impl's target type:
    /// `impl<W> Wrapper<W>` puts `W` at 0. `None` when the callable is not an
    /// impl item, `head` is not one of the impl's type parameters, or the
    /// target does not write it as a whole argument (`impl<W> Wrapper<Vec<W>>`).
    fn impl_target_argument_position(
        &mut self,
        callable: Node<'_>,
        head: ResolutionNameId,
    ) -> Option<u32> {
        let owner = callable
            .parent()
            .filter(|list| list.kind() == "declaration_list")?
            .parent()
            .filter(|owner| owner.kind() == "impl_item")?;
        if !self.callable_type_parameters(owner).0.contains(&Some(head)) {
            return None;
        }
        let target = owner
            .child_by_field_name("type")
            .filter(|target| target.kind() == "generic_type")?;
        let arguments = target
            .child_by_field_name("type_arguments")
            .expect("Rust generic_type has type_arguments");
        let mut cursor = arguments.walk();
        let positional = arguments
            .named_children(&mut cursor)
            .filter(|argument| !argument.is_extra() && argument.kind() != "lifetime")
            .collect::<Vec<_>>();
        let mut position = None;
        for (index, argument) in positional.into_iter().enumerate() {
            if argument.kind() == "type_identifier" && self.intern_name(argument) == head {
                position = Some(index);
                break;
            }
        }
        position.map(|index| u32::try_from(index).expect("Rust type argument count exceeds u32"))
    }

    /// The non-lifetime generic parameters a callable (or an impl) declares
    /// itself, from its own `type_parameters` field, in the order an explicit
    /// type argument list names them: a type parameter by its name, a const
    /// parameter as `None`. An enclosing impl's parameters are not a
    /// callable's. The flag is
    /// false when an entry has no fixed position, such as a metavariable in a
    /// macro template or malformed syntax; that entry is also `None`.
    fn callable_type_parameters(
        &mut self,
        callable: Node<'_>,
    ) -> (Vec<Option<ResolutionNameId>>, bool) {
        let Some(parameters) = callable.child_by_field_name("type_parameters") else {
            return (Vec::new(), true);
        };
        let mut cursor = parameters.walk();
        let mut positions_exact = true;
        let entries = parameters
            .named_children(&mut cursor)
            .filter(|parameter| {
                !parameter.is_extra()
                    && !matches!(parameter.kind(), "lifetime_parameter" | "attributes")
            })
            .map(|parameter| match parameter.kind() {
                "type_parameter" => parameter.child_by_field_name("name"),
                "const_parameter" => None,
                _ => {
                    positions_exact = false;
                    None
                }
            })
            .collect::<Vec<_>>();
        let names = entries
            .into_iter()
            .map(|name| name.map(|name| self.intern_name(name)))
            .collect();
        (names, positions_exact)
    }

    fn add_intrinsic_type_seed(
        &mut self,
        site: ResolutionSiteId,
        spelling: &str,
        kind: IntrinsicTypeKind,
    ) -> ResolutionTypeSlotId {
        let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: output,
            site,
            role: ResolutionTypeSlotRole::TargetTypeIdentity,
        });
        let name = self.intern_spelling(spelling);
        self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output,
            name,
            kind,
            indirection: 0,
        });
        output
    }

    fn lower_declared_type_identity(&mut self, mut node: Node<'_>) -> Option<LoweredDeclaredType> {
        let mut indirection = 0i8;
        let mut reference_indirection = 0i8;
        let mut frontier_gaps = Vec::new();
        loop {
            match node.kind() {
                "reference_type" => {
                    let Some(next_indirection) = indirection.checked_add(1) else {
                        self.add_semantic_gap(node, ResolutionGapKind::UnsupportedTypeSyntax);
                        return None;
                    };
                    let Some(next_reference_indirection) = reference_indirection.checked_add(1)
                    else {
                        self.add_semantic_gap(node, ResolutionGapKind::UnsupportedTypeSyntax);
                        return None;
                    };
                    indirection = next_indirection;
                    reference_indirection = next_reference_indirection;
                    node = node
                        .child_by_field_name("type")
                        .expect("Rust reference_type has a type field");
                }
                "pointer_type" => {
                    let Some(next_indirection) = indirection.checked_add(1) else {
                        self.add_semantic_gap(node, ResolutionGapKind::UnsupportedTypeSyntax);
                        return None;
                    };
                    indirection = next_indirection;
                    node = node
                        .child_by_field_name("type")
                        .expect("Rust pointer_type has a type field");
                }
                "generic_type" | "generic_type_with_turbofish" => {
                    let arguments = node
                        .child_by_field_name("type_arguments")
                        .expect("Rust generic_type has type_arguments");
                    let head = node
                        .child_by_field_name("type")
                        .expect("Rust generic_type has a type field");
                    match rust_projected_payload(head, arguments, self.source) {
                        Some(RustProjectedPayload::Dereferenced(payload)) => {
                            // `Box<T>`, `Arc<T>` and `Rc<T>` dereference to
                            // `T`, so member lookup on such a value reaches
                            // `T` with no explicit operation. Project the
                            // payload at the same depth as the pointer and
                            // leave the head identifier to the ordinary
                            // walker, which keeps it in the reference
                            // inventory. The payload is proven, so the
                            // arguments carry no gap.
                            node = payload;
                            continue;
                        }
                        Some(RustProjectedPayload::Unwrapped(payload)) => {
                            // `Option<T>` and `Result<T, E>` are not
                            // transparent: their payload is reached only
                            // through an explicit `?`, `.unwrap()` or
                            // `.expect(..)`. Project the payload behind one
                            // unproven indirection layer, which member lookup
                            // already refuses, so an un-unwrapped receiver
                            // cannot reach the payload's members. An `Unwrap`
                            // transfer at the unwrap site discharges exactly
                            // that layer.
                            let Some(next_indirection) = indirection.checked_add(1) else {
                                self.add_semantic_gap(
                                    node,
                                    ResolutionGapKind::UnsupportedTypeSyntax,
                                );
                                return None;
                            };
                            indirection = next_indirection;
                            node = payload;
                            continue;
                        }
                        None => {}
                    }
                    // A lifetime argument substitutes nothing: `Widget<'a>` and
                    // `Widget` name the same type and expose the same members,
                    // so an argument list that carries only lifetimes leaves
                    // the head exact and records no gap. Without this every
                    // borrowed generic parameter (`&'a Context<'a>`) made its
                    // binding incomplete, which left every call on it unproven.
                    let mut cursor = arguments.walk();
                    if arguments
                        .named_children(&mut cursor)
                        .all(|argument| argument.kind() == "lifetime")
                    {
                        node = head;
                        continue;
                    }
                    // The remaining arguments are unmodelled type syntax, not
                    // an omitted lexical binder. `UnsupportedScopeOrBinder`
                    // would publish a scope-level candidate gap at the
                    // attachment scope, which makes every forward lookup in
                    // that scope incomplete: one `Vec<T>` in a signature would
                    // then poison the file's free calls. The head stays proven;
                    // only the substitution is unknown.
                    self.add_semantic_gap(arguments, ResolutionGapKind::UnsupportedTypeSyntax);
                    frontier_gaps.push(ResolutionGapKind::UnsupportedTypeSyntax);
                    node = head;
                }
                "dynamic_type" | "abstract_type" | "bounded_type" => {
                    let mut head = node;
                    loop {
                        match head.kind() {
                            "bounded_type" => {
                                let mut cursor = head.walk();
                                head = head.named_children(&mut cursor).find(|child| {
                                    !matches!(child.kind(), "lifetime" | "use_bounds")
                                })?;
                            }
                            "reference_type" | "pointer_type" => {
                                let Some(depth) = indirection.checked_add(1) else {
                                    self.add_semantic_gap(
                                        node,
                                        ResolutionGapKind::UnsupportedTypeSyntax,
                                    );
                                    return None;
                                };
                                indirection = depth;
                                if head.kind() == "reference_type" {
                                    reference_indirection = reference_indirection
                                        .checked_add(1)
                                        .expect("reference depth does not exceed total depth");
                                }
                                head = head
                                    .child_by_field_name("type")
                                    .expect("reference has an operand");
                            }
                            _ => break,
                        }
                    }
                    let site = self.add_site(
                        node,
                        ResolutionSiteKind::TypeReference,
                        self.current_scope(),
                    );
                    let identity =
                        ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                            .expect("Rust type slot count fits u32");
                    self.facts.type_slots.push(ResolutionTypeSlotFact {
                        id: identity,
                        site,
                        role: ResolutionTypeSlotRole::TargetTypeIdentity,
                    });
                    self.lower_trait_bounds(node, identity);
                    return Some(LoweredDeclaredType {
                        identity,
                        indirection,
                        reference_indirection,
                        head_name: None,
                    });
                }
                // `&(dyn Trait + Send)`: parentheses group, they add no type.
                "tuple_type"
                    if crate::type_syntax::rust_parenthesized_type_inner(node).is_some() =>
                {
                    node = crate::type_syntax::rust_parenthesized_type_inner(node)
                        .expect("a parenthesized type has an inner type");
                }
                _ => break,
            }
        }

        // Nominal and receiver projections share the same source occurrence.
        // This map lives only while lowering this blob.
        if let Some(&identity) = self
            .type_reference_identities
            .get(&(node.id(), self.current_scope()))
        {
            let identity = if rust_type_reference_is_self(node, self.source) {
                match self.enclosing_self_types(node) {
                    Some(types) if types.receiver != types.nominal => types.receiver,
                    _ => identity,
                }
            } else {
                identity
            };
            let head_name = (node.kind() == "type_identifier" && frontier_gaps.is_empty())
                .then(|| self.intern_name(node));
            self.add_frontier_gaps(self.facts.type_slots[identity.index()].site, &frontier_gaps);
            return Some(LoweredDeclaredType {
                identity,
                indirection,
                reference_indirection,
                head_name,
            });
        }

        if rust_type_reference_is_self(node, self.source) {
            let reference = self.add_identifier(
                node,
                ResolutionSiteKind::TypeReference,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
                self.current_scope(),
            );
            let output = self.add_type_reference_identity(node, reference);
            self.add_frontier_gaps(reference, &frontier_gaps);
            // Only the nominal occurrence is a definition observation. A
            // runtime value may reach a different payload through Deref.
            let identity = match self.enclosing_self_types(node) {
                Some(types) if types.receiver != types.nominal => types.receiver,
                _ => output,
            };
            return Some(LoweredDeclaredType {
                identity,
                indirection,
                reference_indirection,
                head_name: None,
            });
        }

        let intrinsic = if rust_is_unit_type(node) {
            Some(("()", IntrinsicTypeKind::LanguageBuiltin))
        } else {
            rust_primitive_type_spelling(node, self.source)
                .map(|spelling| (spelling, IntrinsicTypeKind::Primitive))
        };
        if let Some((spelling, kind)) = intrinsic {
            self.handled_identifiers.insert(node.id());
            self.mark_syntax_subtree_consumed(node);
            let site = self.add_site(
                node,
                ResolutionSiteKind::TypeReference,
                self.current_scope(),
            );
            return Some(LoweredDeclaredType {
                identity: self.add_intrinsic_type_seed(site, spelling, kind),
                indirection,
                reference_indirection,
                head_name: None,
            });
        }
        if node.kind() == "array_type"
            && let Some(identity) = self.lower_primitive_sequence_type(node)
        {
            return Some(LoweredDeclaredType {
                identity,
                indirection,
                reference_indirection,
                head_name: None,
            });
        }
        let reference = match node.kind() {
            _ if rust_is_unmodelled_primitive_spelling(node, self.source) => {
                Some(self.add_identifier(
                    node,
                    ResolutionSiteKind::TypeReference,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    self.current_scope(),
                ))
            }
            "type_identifier" | "identifier" => {
                let reference = self.add_identifier(
                    node,
                    ResolutionSiteKind::TypeReference,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    self.current_scope(),
                );
                if rust_type_reference_is_self(node, self.source) {
                    self.facts.gaps.push(ResolutionGapFact {
                        site: reference,
                        kind: ResolutionGapKind::UnsupportedScopeOrBinder,
                    });
                }
                Some(reference)
            }
            "scoped_type_identifier" | "scoped_identifier"
                if node
                    .child_by_field_name("path")
                    .and_then(rust_qualified_type_path)
                    .is_some() =>
            {
                self.lower_associated_type_reference(node)
            }
            "scoped_type_identifier" | "scoped_identifier" => self.add_scoped_identifier(
                node,
                ResolutionSiteKind::TypeReference,
                ResolutionNamespace::Type,
            ),
            "qualified_type" => {
                self.add_semantic_gap(node, ResolutionGapKind::AmbiguousQualifiedType);
                frontier_gaps.push(ResolutionGapKind::AmbiguousQualifiedType);
                let alias = node
                    .child_by_field_name("alias")
                    .expect("Rust qualified_type has an alias field");
                self.lower_return_type_children(node);
                self.facts
                    .identifiers
                    .iter()
                    .find(|identifier| {
                        self.facts.sites[identifier.site.index()].start_byte == alias.start_byte()
                            && self.facts.sites[identifier.site.index()].end_byte
                                == alias.end_byte()
                            && identifier.namespace == ResolutionNamespace::Type
                    })
                    .map(|identifier| identifier.site)
            }
            "array_type" | "tuple_type" | "function_type" | "unit_type" => {
                // These wrappers do not have one nominal receiver identity.
                // Their independently named operands still belong to the
                // source reference inventory; uncertainty stays on the type.
                self.lower_return_type_children(node);
                self.add_semantic_gap(node, ResolutionGapKind::UnsupportedTypeSyntax);
                None
            }
            _ => {
                self.add_local_gap(node, ResolutionGapKind::UnsupportedTypeSyntax);
                None
            }
        }?;
        let output = self.add_type_reference_identity(node, reference);
        self.add_frontier_gaps(reference, &frontier_gaps);
        let head_name = (node.kind() == "type_identifier" && frontier_gaps.is_empty())
            .then(|| self.intern_name(node));
        Some(LoweredDeclaredType {
            identity: output,
            indirection,
            reference_indirection,
            head_name,
        })
    }

    /// A slice or array whose element is a primitive type is an intrinsic
    /// type spelled from its structure: `[u8]`, or `[u8; 4]` when the length
    /// is an integer literal, spelled as written. Any other element or length
    /// has no intrinsic identity, and the caller keeps its gap.
    fn lower_primitive_sequence_type(&mut self, node: Node<'_>) -> Option<ResolutionTypeSlotId> {
        let element = node
            .child_by_field_name("element")
            .expect("Rust array_type has an element field");
        let element = rust_primitive_type_spelling(element, self.source)?;
        let (spelling, kind) = match node.child_by_field_name("length") {
            None => (format!("[{element}]"), IntrinsicTypeKind::Slice),
            Some(length) if length.kind() == "integer_literal" => (
                format!(
                    "[{element}; {}]",
                    rust_node_text(length, self.source).trim()
                ),
                IntrinsicTypeKind::Array,
            ),
            Some(_) => return None,
        };
        self.handled_identifiers.insert(node.id());
        self.mark_syntax_subtree_consumed(node);
        let site = self.add_site(
            node,
            ResolutionSiteKind::TypeReference,
            self.current_scope(),
        );
        Some(self.add_intrinsic_type_seed(site, &spelling, kind))
    }

    fn lower_associated_type_reference(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        self.add_scoped_identifier(
            node,
            ResolutionSiteKind::TypeReference,
            ResolutionNamespace::Type,
        )
    }

    /// The type a `Self::name` lookup inside a trait body is bounded below by.
    ///
    /// `Self` in a trait body denotes the implementing type, which this
    /// fragment does not know, and the trait's shared abstract frontier says
    /// exactly that: a `self` receiver there really does have an unknown type.
    /// A `Self::name` path is not unknown in the same way. Rust resolves it
    /// against the trait's own items and its supertraits, so the trait is the
    /// lookup's lower bound, and giving it to the qualifier slot alone leaves
    /// the frontier abstract for every other reader of it.
    ///
    /// The bound is a Type reference positioned on the trait item and spelled
    /// with the trait's own name, bound in the scope that binds that name. The
    /// engine's `TargetTypeIdentity` projection turns that binding into the
    /// trait's type object. It is minted on first use, so a trait whose body
    /// writes no `Self::` path publishes nothing for it.
    fn enclosing_trait_self_lower_bound(&mut self, node: Node<'_>) -> Option<ResolutionTypeSlotId> {
        let mut ancestor = node.parent();
        let trait_item = loop {
            let Some(current) = ancestor else {
                // A macro fragment's tree ends at its own root; its `Self` is
                // the invocation's owner.
                return match self.macro_fragment_self_owner {
                    Some(MacroFragmentSelfOwner::Trait { lower_bound, .. }) => lower_bound,
                    _ => None,
                };
            };
            match current.kind() {
                // Inside an impl, `Self` is the implemented type itself and the
                // ordinary frontier already carries it.
                "impl_item" => return None,
                "trait_item" => break current,
                _ => ancestor = current.parent(),
            }
        };
        if let Some(bound) = self.trait_self_lower_bounds.get(&trait_item.id()) {
            return Some(*bound);
        }
        let scope = *self.trait_self_bound_scopes.get(&trait_item.id())?;
        let name = trait_item.child_by_field_name("name")?;
        let site = self.add_site(trait_item, ResolutionSiteKind::SyntheticReference, scope);
        let interned = self.intern_name(name);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name: interned,
            role: ResolutionIdentifierRole::Reference,
            namespace: ResolutionNamespace::Type,
            qualifier: None,
        });
        self.facts
            .reference_owners
            .push(ResolutionReferenceOwnerFact {
                reference: site,
                owner: self.declaration_owners.last().copied(),
            });
        let bound = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: bound,
            site,
            role: ResolutionTypeSlotRole::TargetTypeIdentity,
        });
        self.facts.binding_projections.push(BindingProjectionFact {
            reference: site,
            output: bound,
            kind: BindingProjectionKind::TargetTypeIdentity,
        });
        // Supertrait properties carry every inherited member lookup, including
        // callable members. Their traversal retains unresolved-edge evidence;
        // the bound itself no longer needs a synthetic traversal failure.
        self.trait_self_lower_bounds.insert(trait_item.id(), bound);
        Some(bound)
    }

    fn enclosing_self_type_frontier(&self, node: Node<'_>) -> Option<ResolutionTypeSlotId> {
        self.enclosing_self_types(node).map(|types| types.nominal)
    }

    fn enclosing_self_types(&self, node: Node<'_>) -> Option<RustSelfTypes> {
        let mut ancestor = node.parent();
        while let Some(current) = ancestor {
            if matches!(current.kind(), "impl_item" | "trait_item") {
                return self.self_type_frontiers.get(&current.id()).copied();
            }
            ancestor = current.parent();
        }
        // A macro fragment's tree ends at its own root; its `Self` is the
        // invocation's owner.
        self.macro_fragment_self_owner
            .and_then(|owner| self.self_type_frontiers.get(&owner.item()).copied())
    }

    /// The impl or trait whose `Self` the fragments of `invocation` mean: the
    /// invocation's own enclosing impl or trait, or, for an invocation inside
    /// a fragment, that fragment's owner. `writes_self_path` says the
    /// fragments write a `Self::` path, which is when a trait's lower bound
    /// is minted.
    fn macro_fragment_self_owner(
        &mut self,
        invocation: Node<'_>,
        writes_self_path: bool,
    ) -> Option<MacroFragmentSelfOwner> {
        let mut ancestor = invocation.parent();
        while let Some(current) = ancestor {
            match current.kind() {
                "impl_item" => return Some(MacroFragmentSelfOwner::Impl(current.id())),
                "trait_item" => {
                    return Some(MacroFragmentSelfOwner::Trait {
                        item: current.id(),
                        lower_bound: if writes_self_path {
                            self.enclosing_trait_self_lower_bound(invocation)
                        } else {
                            None
                        },
                    });
                }
                _ => ancestor = current.parent(),
            }
        }
        self.macro_fragment_self_owner
    }

    fn add_type_reference_identity(
        &mut self,
        node: Node<'_>,
        reference: ResolutionSiteId,
    ) -> ResolutionTypeSlotId {
        let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: output,
            site: reference,
            role: ResolutionTypeSlotRole::TargetTypeIdentity,
        });
        // A frontier has exactly one output producer, in the typed-fact
        // validator and in the sealed schema trigger alike. `Self` therefore
        // takes the transfer and no binding projection: its value comes from
        // the enclosing owner, not from a name binding, because `Self` binds no
        // name of its own.
        if rust_type_reference_is_self(node, self.source) {
            if let Some(owner) = self.enclosing_self_type_frontier(node) {
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input: owner,
                    output,
                    kind: ResolutionTypeTransferKind::TypeIdentity,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
            } else {
                self.add_local_gap_at_site(reference, ResolutionGapKind::UnsupportedScopeOrBinder);
            }
        } else {
            self.facts.binding_projections.push(BindingProjectionFact {
                reference,
                output,
                kind: BindingProjectionKind::TargetTypeIdentity,
            });
        }
        self.type_reference_identities
            .insert((node.id(), self.current_scope()), output);
        output
    }

    fn add_frontier_gaps(&mut self, site: ResolutionSiteId, gaps: &[ResolutionGapKind]) {
        for &kind in gaps {
            if self
                .facts
                .gaps
                .iter()
                .any(|gap| gap.site == site && gap.kind == kind)
            {
                continue;
            }
            self.facts.gaps.push(ResolutionGapFact { site, kind });
        }
    }

    fn enter_generic_parameter_scope(&mut self, node: Node<'_>, owner: Option<ResolutionSiteId>) {
        // TypeBody is reserved for an actual type declaration. Function,
        // method, and type-alias parameters are still lexical binders, but
        // their owning sites are not TypeDeclaration sites and must therefore
        // live in an executable-style parameter scope. Keeping this choice in
        // the producer preserves the common fact invariant instead of making
        // the hydrator reinterpret an invalid TypeBody owner.
        let kind = owner
            .map(|owner| self.facts.sites[owner.index()].kind)
            .filter(|kind| *kind == ResolutionSiteKind::TypeDeclaration)
            .map_or(ResolutionScopeKind::Executable, |_| {
                ResolutionScopeKind::TypeBody
            });
        let generic_scope = self.allocate_scope(
            self.item_scope(),
            owner,
            kind,
            node.start_byte(),
            node.end_byte(),
        );
        self.scopes.push(generic_scope);
        self.lower_generic_parameter_binders(
            node.child_by_field_name("type_parameters")
                .expect("generic declaration retains its parameters"),
            generic_scope,
            node.start_byte(),
            node.end_byte(),
        );
        self.exits.push(ExitAction::Scope);
    }

    fn enter_type_body_scope(
        &mut self,
        node: Node<'_>,
        declaration: ResolutionSiteId,
    ) -> ResolutionScopeId {
        let type_body = self.allocate_scope(
            self.item_scope(),
            Some(declaration),
            ResolutionScopeKind::TypeBody,
            node.start_byte(),
            node.end_byte(),
        );
        self.scopes.push(type_body);
        self.exits.push(ExitAction::Scope);
        type_body
    }

    /// Retain all declared trait surfaces in one explicit type union.
    fn lower_trait_bounds(&mut self, root: Node<'_>, output: ResolutionTypeSlotId) {
        let mut pending = vec![root];
        while let Some(bound) = pending.pop() {
            let head = match bound.kind() {
                "trait_bounds" | "bounded_type" => {
                    let mut cursor = bound.walk();
                    pending.extend(bound.named_children(&mut cursor));
                    continue;
                }
                "dynamic_type" | "abstract_type" => {
                    pending.push(
                        bound
                            .child_by_field_name("trait")
                            .expect("trait type has its bound"),
                    );
                    continue;
                }
                "higher_ranked_trait_bound" | "reference_type" | "pointer_type" => {
                    pending.push(
                        bound
                            .child_by_field_name("type")
                            .expect("bound wrapper has an operand"),
                    );
                    continue;
                }
                "lifetime" | "use_bounds" => continue,
                "generic_type" => {
                    if let Some(arguments) = bound.child_by_field_name("type_arguments") {
                        self.lower_trait_bound_arguments(arguments, output);
                    }
                    bound
                        .child_by_field_name("type")
                        .expect("generic bound has a head")
                }
                "type_identifier" | "scoped_type_identifier" => bound,
                _ => {
                    let site = self.facts.type_slots[output.index()].site;
                    self.add_frontier_gaps(
                        site,
                        &[ResolutionGapKind::UnsupportedHierarchyTraversal],
                    );
                    continue;
                }
            };
            if let Some(lowered) = self.lower_declared_type_identity(head) {
                assert_eq!((lowered.indirection, lowered.reference_indirection), (0, 0));
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input: lowered.identity,
                    output,
                    kind: ResolutionTypeTransferKind::TypeUnion,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
            }
        }
    }

    /// A trait's supertraits, `trait Sub: Base + Other<T>`, are its declared
    /// supertypes: `T::Item` and `T::N` for `T: Sub` reach `Base`'s
    /// associated type and const through them, which the engine's hierarchy
    /// traversal answers from these rows. That traversal admits no callable
    /// member, so `T::base()` and `Self::base()` do not reach `Base::base`
    /// yet. Each bound head is lowered here, in
    /// the trait's type-body scope, so the supertype fact carries its own
    /// reference and identity slot; the walk then skips the handled head and
    /// gives any generic arguments their ordinary treatment. Lifetimes,
    /// `?Sized`, and higher-ranked bounds name no supertrait here and keep the
    /// walk's treatment.
    fn lower_supertrait_bounds(&mut self, subtype: ResolutionSiteId, bounds: Node<'_>) {
        let mut cursor = bounds.walk();
        let bounds = bounds.named_children(&mut cursor).collect::<Vec<_>>();
        for bound in bounds {
            let head = match bound.kind() {
                "type_identifier" | "scoped_type_identifier" => bound,
                "generic_type" => bound
                    .child_by_field_name("type")
                    .expect("generic bound has a head"),
                _ => continue,
            };
            let Some(lowered) = self.lower_declared_type_identity(head) else {
                continue;
            };
            assert_eq!((lowered.indirection, lowered.reference_indirection), (0, 0));
            self.facts.supertypes.push(ResolutionSupertypeFact {
                subtype,
                supertype_reference: self.facts.type_slots[lowered.identity.index()].site,
                supertype_slot: lowered.identity,
                kind: ResolutionSupertypeKind::Interface,
            });
        }
    }

    /// Lower the argument list of a trait bound's generic head.
    ///
    /// An associated-type binding, `A: Trait<Item = T>`, names the same member
    /// that `<A as Trait>::Item` names. The ordinary type-reference walk would
    /// make its left side an unqualified lexical reference, which finds nothing
    /// in the enclosing scope and reports a confident absence. It takes the
    /// qualified member reference the projection form already takes instead:
    /// the receiver is the bounded type's own identity, which this bound is
    /// writing the trait into, so the member resolves through the bound even
    /// when the trait is a renamed import. Everything else in the list,
    /// including the binding's own arguments and its bound value, keeps
    /// ordinary treatment.
    fn lower_trait_bound_arguments(&mut self, arguments: Node<'_>, bounded: ResolutionTypeSlotId) {
        let mut cursor = arguments.walk();
        let arguments = arguments.named_children(&mut cursor).collect::<Vec<_>>();
        for argument in arguments {
            if argument.kind() != "type_binding" {
                self.lower_return_type_children(argument);
                continue;
            }
            let Some(name) = argument.child_by_field_name("name") else {
                self.add_local_gap(argument, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let reference = self.add_qualified_identifier(
                name,
                ResolutionSiteKind::TypeReference,
                ResolutionNamespace::Type,
                self.current_scope(),
            );
            let qualifier = {
                let identifier = self
                    .facts
                    .identifiers
                    .last()
                    .expect("the qualified member reference was just recorded");
                assert_eq!(
                    identifier.site, reference,
                    "the qualified member reference is the last recorded identifier"
                );
                identifier
                    .qualifier
                    .expect("a qualified member reference owns a receiver slot")
            };
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: bounded,
                output: qualifier,
                kind: ResolutionTypeTransferKind::Receiver,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
            // The binding denotes a type, so it owns its type identity the way
            // every other type reference does. Without that output projection
            // the typed member route has nothing to discharge the reference's
            // QualifiedReference obligation with, and an exactly resolved
            // member still reports an incomplete binding.
            self.add_type_reference_identity(name, reference);
            let mut cursor = argument.walk();
            let children = argument
                .named_children(&mut cursor)
                .filter(|child| child.id() != name.id())
                .collect::<Vec<_>>();
            for child in children {
                self.lower_return_type_children(child);
            }
        }
    }

    /// Publish generic parameter declarations as positioned lexical binders.
    /// The declaration sites intentionally have no parser definition unit: a
    /// selected continuation that reaches one remains incomplete, but it can
    /// never fall through to a same-named module or value declaration.
    fn lower_generic_parameter_binders(
        &mut self,
        parameters: Node<'_>,
        scope: ResolutionScopeId,
        activation_start: usize,
        activation_end: usize,
    ) {
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            let (site_kind, namespace, binder_kind) = match parameter.kind() {
                "type_parameter" => (
                    ResolutionSiteKind::TypeDeclaration,
                    ResolutionNamespace::Type,
                    ResolutionBinderKind::Type,
                ),
                "const_parameter" => (
                    ResolutionSiteKind::ValueDeclaration,
                    ResolutionNamespace::Value,
                    ResolutionBinderKind::Parameter,
                ),
                _ => continue,
            };
            let Some(name) = parameter.child_by_field_name("name") else {
                self.add_local_gap(parameter, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let declaration = self.add_identifier(
                name,
                site_kind,
                ResolutionIdentifierRole::Declaration,
                namespace,
                scope,
            );
            let occurrence = self.source_collector.intern_node(parameter);
            let name_occurrence = self.source_collector.intern_node(name);
            let source_declaration = self.source_collector.declare_lexical(
                occurrence,
                name_occurrence,
                DeclarationKind::Parameter,
            );
            self.declaration_sources
                .push((declaration, source_declaration));
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope,
                kind: binder_kind,
                hoisting: HoistingClass::SourceOrder,
                activation_start,
                activation_end,
            });
            if parameter.kind() == "type_parameter" {
                let mut bounds = parameter
                    .child_by_field_name("bounds")
                    .into_iter()
                    .collect::<Vec<_>>();
                let owner = parameters
                    .parent()
                    .expect("generic parameters have an item owner");
                let mut owner_cursor = owner.walk();
                for clause in owner
                    .named_children(&mut owner_cursor)
                    .filter(|child| child.kind() == "where_clause")
                {
                    let mut clause_cursor = clause.walk();
                    for predicate in clause.named_children(&mut clause_cursor) {
                        if let Some(left) = predicate.child_by_field_name("left")
                            && left.kind() == "type_identifier"
                            && strip_raw_identifier_prefix(rust_node_text(left, self.source))
                                == strip_raw_identifier_prefix(rust_node_text(name, self.source))
                            && let Some(bound) = predicate.child_by_field_name("bounds")
                        {
                            bounds.push(bound);
                        }
                    }
                }
                // A type parameter's identity is a slot, never the parameter's
                // own declaration: which type it stands for is decided by each
                // use of the item, by inference the engine does not model. Its
                // bounds are what every such type is known to provide, so they
                // feed the slot. With nothing to feed it -- no bound, or only
                // lifetime bounds -- the slot is fed from the parameter's own
                // syntax carrying an `InferredType` gap, the way an
                // unwritten type is lowered: every value typed by the
                // parameter is then unknown for that named reason, rather than
                // the declaration passing for an exact nominal type.
                let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                    .expect("Rust type slot count fits u32");
                self.facts.type_slots.push(ResolutionTypeSlotFact {
                    id: output,
                    site: declaration,
                    role: ResolutionTypeSlotRole::TargetTypeIdentity,
                });
                self.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration,
                        slot: output,
                        role: DeclarationTypeRole::Identity,
                    });
                let transfers_before = self.facts.type_transfers.len();
                let gaps_before = self.facts.gaps.len();
                for bound in bounds {
                    self.lower_trait_bounds(bound, output);
                }
                let fed = self.facts.type_transfers[transfers_before..]
                    .iter()
                    .any(|transfer| transfer.output == output)
                    || self.facts.gaps[gaps_before..]
                        .iter()
                        .any(|gap| gap.site == declaration);
                if !fed {
                    let inferred =
                        self.add_site(parameter, ResolutionSiteKind::UnsupportedExpression, scope);
                    self.add_semantic_gap_at_site(inferred, ResolutionGapKind::InferredType);
                    let input = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                        .expect("Rust type slot count fits u32");
                    self.facts.type_slots.push(ResolutionTypeSlotFact {
                        id: input,
                        site: inferred,
                        role: ResolutionTypeSlotRole::TargetTypeIdentity,
                    });
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input,
                        output,
                        kind: ResolutionTypeTransferKind::TypeIdentity,
                        indirection_delta: 0,
                        reference_indirection_delta: 0,
                        value_transform: ResolutionTypeTransferValueTransform::Preserve,
                    });
                }
            }
        }
    }

    fn lower_function_declaration(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let declaration = self.lower_item_declaration(
            node,
            ResolutionSiteKind::CallableDeclaration,
            ResolutionNamespace::Value,
            ResolutionBinderKind::Callable,
        )?;
        // Signature references belong to the function too. Lexical parameter
        // and body scopes still enter at their existing points; ownership
        // begins before return types and survives through the full item walk.
        self.declaration_owners.push(declaration);
        self.declare_definition_namespace(
            declaration,
            ResolutionNamespace::Value,
            HoistingClass::ScopeWide,
        );
        // A `#[proc_macro]` function is a macro to every crate that imports
        // it: `routes![..]` names `rocket_codegen::routes`, and a macro
        // namespace lookup is the only one that can reach it. It is still an
        // ordinary function inside its own crate, which is why the macro
        // namespace is an additional one rather than its primary one. A
        // `#[proc_macro_derive(Name)]` publishes its argument instead of the
        // function's name, so it is not this declaration's macro name.
        if crate::imports::rust_item_has_attribute(node, self.source, "proc_macro")
            || crate::imports::rust_item_has_attribute(node, self.source, "proc_macro_attribute")
        {
            self.declare_definition_namespace(
                declaration,
                ResolutionNamespace::Macro,
                HoistingClass::ScopeWide,
            );
            if self.current_scope_is_module_owned() {
                // A macro-namespace lookup has to land on this declaration, so
                // the root export it joins through carries that namespace too.
                self.add_module_root_export(declaration, ResolutionNamespace::Macro);
            }
        }
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: node.child_by_field_name("type_parameters").map_or(
                    0,
                    |parameters| {
                        u32::try_from(parameters.named_child_count())
                            .expect("Rust type parameter count exceeds u32")
                    },
                ),
                result_types: Vec::new(),
            });
        if node.child_by_field_name("type_parameters").is_none() {
            self.lower_callable_return_type(node, declaration);
        }
        Some(declaration)
    }

    /// A bodyless free function (a foreign function) lowers no parameter
    /// declarations, so it publishes no parameter rows. Anything but a lone
    /// receiver keeps the applicability gap: absent rows are not arity zero.
    fn retain_unlowered_parameter_inventory(
        &mut self,
        node: Node<'_>,
        declaration: ResolutionSiteId,
    ) {
        if node
            .child_by_field_name("parameters")
            .and_then(rust_modeled_ordinary_parameter_count)
            != Some(0)
        {
            self.retain_parameter_inventory_gap(declaration);
        }
    }

    fn lower_type_alias(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let declaration = self.lower_item_declaration(
            node,
            ResolutionSiteKind::TypeAliasDeclaration,
            ResolutionNamespace::Type,
            ResolutionBinderKind::Type,
        )?;
        self.declaration_owners.push(declaration);
        self.declare_definition_namespace(
            declaration,
            ResolutionNamespace::Type,
            HoistingClass::ScopeWide,
        );
        if node.child_by_field_name("type_parameters").is_none() {
            self.lower_type_alias_target(node, declaration);
        }
        Some(declaration)
    }

    fn lower_type_alias_target(&mut self, node: Node<'_>, declaration: ResolutionSiteId) {
        let nominal_target = node
            .child_by_field_name("type")
            .and_then(|target| self.lower_nominal_type_identity(target));
        if let Some(input) = nominal_target {
            let slot = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: slot,
                site: declaration,
                role: ResolutionTypeSlotRole::TargetTypeIdentity,
            });
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration,
                    slot,
                    role: DeclarationTypeRole::NominalIdentity,
                });
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input,
                output: slot,
                kind: ResolutionTypeTransferKind::TypeIdentity,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
        }
        let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: output,
            site: declaration,
            role: ResolutionTypeSlotRole::TargetTypeIdentity,
        });
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: output,
                role: DeclarationTypeRole::Identity,
            });
        let Some(target_node) = node.child_by_field_name("type") else {
            self.add_semantic_gap_at_site(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
            return;
        };
        let target =
            if self.generic_alias_target_arguments_preserve_nominal_identity(node, target_node) {
                nominal_target.map(|identity| LoweredDeclaredType {
                    identity,
                    indirection: 0,
                    reference_indirection: 0,
                    head_name: None,
                })
            } else {
                self.lower_declared_type_identity(target_node)
            };
        let Some(target) = target else {
            self.add_semantic_gap_at_site(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
            return;
        };
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input: target.identity,
            output,
            kind: if target.indirection == 0 && target.reference_indirection == 0 {
                ResolutionTypeTransferKind::TypeIdentity
            } else {
                ResolutionTypeTransferKind::TypeAlias
            },
            indirection_delta: target.indirection,
            reference_indirection_delta: target.reference_indirection,
            value_transform: ResolutionTypeTransferValueTransform::Preserve,
        });
    }

    /// A generic alias retains its target's nominal owner when each written
    /// target argument is either one of the alias's own type parameters or a
    /// builtin leaf. The ordinary walk still publishes references to the
    /// parameter arguments. Nested and concrete named substitutions keep the
    /// usual frontier gap because this fact model has no alias-substitution
    /// relation for them.
    fn generic_alias_target_arguments_preserve_nominal_identity(
        &mut self,
        alias: Node<'_>,
        target: Node<'_>,
    ) -> bool {
        if target.kind() != "generic_type" || alias.child_by_field_name("type_parameters").is_none()
        {
            return false;
        }
        let head = target
            .child_by_field_name("type")
            .expect("Rust generic_type has a type field");
        let arguments = target
            .child_by_field_name("type_arguments")
            .expect("Rust generic_type has type_arguments");
        if rust_projected_payload(head, arguments, self.source).is_some() {
            return false;
        }

        let mut parameter_names: HashSet<ResolutionNameId> = HashSet::default();
        let parameters = alias
            .child_by_field_name("type_parameters")
            .expect("generic alias has type parameters");
        let mut parameter_cursor = parameters.walk();
        for parameter in parameters.named_children(&mut parameter_cursor) {
            if parameter.kind() != "type_parameter" {
                continue;
            }
            let Some(name) = parameter.child_by_field_name("name") else {
                return false;
            };
            parameter_names.insert(self.intern_name(name));
        }

        let mut argument_cursor = arguments.walk();
        let mut has_type_argument = false;
        for argument in arguments.named_children(&mut argument_cursor) {
            if argument.kind() == "lifetime" {
                continue;
            }
            has_type_argument = true;
            match argument.kind() {
                "type_identifier" if parameter_names.contains(&self.intern_name(argument)) => {}
                "primitive_type"
                    if rust_primitive_type_spelling(argument, self.source).is_some() => {}
                kind if kind == "unit_type" || rust_is_unit_type(argument) => {}
                _ => return false,
            }
        }
        has_type_argument
    }

    fn lower_module(&mut self, node: Node<'_>) {
        let Some(declaration) = self.lower_item_declaration(
            node,
            ResolutionSiteKind::ModuleDeclaration,
            ResolutionNamespace::Type,
            ResolutionBinderKind::Type,
        ) else {
            return;
        };
        self.declare_definition_namespace(
            declaration,
            ResolutionNamespace::Type,
            HoistingClass::ScopeWide,
        );
        self.lower_module_body(node, Some(declaration));
    }

    fn lower_module_body(&mut self, node: Node<'_>, owner: Option<ResolutionSiteId>) {
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let scope = self.allocate_module_scope(
            self.item_scope(),
            owner,
            body.start_byte(),
            body.end_byte(),
        );
        assert!(
            self.pending_scopes
                .insert(
                    body.id(),
                    PendingScope {
                        scope,
                        callable: None,
                    },
                )
                .is_none(),
            "one inline Rust module body owns one scope"
        );
    }

    fn lower_macro_definition(
        &mut self,
        node: Node<'_>,
        macro_definition: Option<&RustRulesItemMacroDefinition>,
    ) {
        let Some(name) = node.child_by_field_name("name") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let Some(definition) = macro_definition else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let macro_exported = {
            let property = self.declaration_properties_for_node(node);
            assert_eq!(
                definition.declaration, property.declaration,
                "macro DTO must retain its exact source declaration identity"
            );
            property.macro_exported
        };
        let lexical_scope = self.current_scope();
        let bounds = self.facts.scopes[lexical_scope.index()];
        assert_eq!(
            (bounds.start_byte, bounds.end_byte),
            (definition.scope_start, definition.scope_end)
        );
        assert_eq!(rust_node_text(name, self.source).trim(), definition.name);
        let scope = if macro_exported {
            ResolutionScopeId::new(0)
        } else {
            lexical_scope
        };
        let bounds = self.facts.scopes[scope.index()];
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::MacroDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Macro,
            scope,
        );
        self.record_declaration_site(node, declaration);
        let captured = LocalMacroDefinition {
            scope: self.current_scope(),
            visible_after: definition.visible_after,
            passthrough: definition.passthrough,
            declares_no_item: definition.declares_no_item,
            writes_only_impls: definition.writes_only_impls,
            declares_no_item_arms: crate::declarations::rust_macro_definition_no_item_arms(
                node,
                self.source,
            ),
            source: crate::macro_matcher::capture_syntax_macro_definition(node, self.source),
            transcribers: crate::macro_matcher::capture_macro_transcribers(node, self.source),
        };
        self.macro_definitions
            .entry(definition.name.clone())
            .or_default()
            .push(captured);
        let hoisting = if macro_exported {
            HoistingClass::ScopeWide
        } else {
            HoistingClass::SourceOrder
        };
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope,
            kind: ResolutionBinderKind::Macro,
            hoisting,
            activation_start: if macro_exported {
                bounds.start_byte
            } else {
                definition.visible_after
            },
            activation_end: bounds.end_byte,
        });
        self.declare_definition_namespace(declaration, ResolutionNamespace::Macro, hoisting);
        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
        if macro_exported {
            self.facts
                .declaration_visibilities
                .push(ResolutionDeclarationVisibilityFact {
                    declaration,
                    visibility: DeclaredVisibility::Public,
                });
            self.facts.root_exports.push(ResolutionRootExportFact {
                root_scope: scope,
                declaration,
                namespace: ResolutionNamespace::Macro,
            });
        }
        let mut cursor = node.walk();
        for arm in node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "macro_rule")
        {
            if let Some(body) = arm.child_by_field_name("right") {
                let mut parsed = crate::macro_matcher::parse_macro_transcriber(body, self.source);
                // A non-exported macro can only be invoked in this crate.
                // Conditional attributes can add macro_export, so their
                // ordinary crate anchors still require invocation context.
                if !macro_exported
                    && !crate::syntax::item_has_path_attribute(node, self.source, "cfg_attr")
                {
                    parsed
                        .definition_crate_anchors
                        .extend(parsed.ordinary_crate_anchors);
                }
                self.lower_macro_transcriber_paths(
                    parsed.tree,
                    &parsed.metavariables,
                    &parsed.definition_crate_anchors,
                    body.start_byte(),
                    body.end_byte(),
                );
            }
        }
    }

    fn lower_macro_invocation(
        &mut self,
        node: Node<'_>,
        source_position: RustItemMacroSourcePosition,
    ) {
        if rust_unqualified_macro_invocation_name(node, self.source) == Some("include")
            && self
                .match_visible_macro_invocation(node, source_position)
                .is_none()
        {
            // The selected source inventory decides whether this splice exists.
            // A builtin include head is not a reference to a macro declaration.
            self.add_local_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        }
        if rust_unqualified_macro_invocation_name(node, self.source).is_some()
            && let Some(name) = node.child_by_field_name("macro")
        {
            self.add_identifier(
                name,
                ResolutionSiteKind::MacroReference,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Macro,
                self.current_scope(),
            );
        } else if self.inline_module_macro_invocation_name(node).is_some()
            && let Some(macro_path) = node.child_by_field_name("macro")
            && let Some(segments) = rust_path_segments(macro_path)
        {
            let terminal = *segments.last().expect("a macro path has a terminal");
            self.mark_scoped_path_consumed(macro_path);
            self.add_identifier(
                terminal,
                ResolutionSiteKind::MacroReference,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Macro,
                self.current_scope(),
            );
            self.add_path_prefix_occurrences(
                &segments,
                self.nearest_root_scope(),
                ResolutionRootImportAnchor::Lexical,
            );
        } else if let Some(name) = node.child_by_field_name("macro") {
            self.add_scoped_identifier(
                name,
                ResolutionSiteKind::MacroReference,
                ResolutionNamespace::Macro,
            );
        }
        if let Some((matched, proofs, transcribed_paths)) =
            self.match_visible_macro_invocation(node, source_position)
        {
            match matched {
                Ok(arm) => {
                    let frontier = self.lower_macro_bindings(node, &arm, &transcribed_paths);
                    // An item-position invocation of a macro that is neither a
                    // proven passthrough nor proven to declare nothing expands
                    // to whatever its rules write (tract's `from_i!` writes
                    // impls from a `ty`). No row declares that expansion and
                    // the crate does not decide the invocation, so it keeps a
                    // native frontier: its module's export inventory stays
                    // open, and the lowering opens exactly what the expansion
                    // can change (`UnexpandedItemMacro`).
                    // An expansion made only of `impl` blocks binds no name in
                    // the module and opens only member surfaces
                    // (`UnexpandedImplMacro`).
                    if !proofs.passthrough
                        && !proofs.declares_no_item
                        && !frontier
                        && source_position != RustItemMacroSourcePosition::Other
                    {
                        self.add_semantic_gap(
                            node,
                            if proofs.writes_only_impls {
                                ResolutionGapKind::UnexpandedImplMacro
                            } else {
                                ResolutionGapKind::UnexpandedItemMacro
                            },
                        );
                    }
                    return;
                }
                Err(crate::macro_matcher::MacroMatchError::NoArmMatched) => return,
                Err(_) => {}
            }
        }
        let item_position = matches!(
            source_position,
            RustItemMacroSourcePosition::DirectItem | RustItemMacroSourcePosition::ItemStatement
        );
        // The expansion stays unknown, so the semantic gap stands either way.
        // The reference inventory does not have to: an unexpanded token tree
        // still spells its arguments in source, and enumerating them is what
        // keeps a whole-workspace reverse answer complete in any crate that
        // says `assert_eq!` or `println!`.
        if self.lower_definition_less_macro_arguments(node) {
            // The arguments were lowered as expressions, which is a guess
            // about a macro no definition describes; the scope-wide gap is
            // what keeps those guessed references unproven (a rename must not
            // edit `target` inside `unknown_macro!(target)`).
            let kind = if item_position {
                ResolutionGapKind::UnsupportedScopeOrBinder
            } else {
                ResolutionGapKind::UnsupportedExpression
            };
            self.add_semantic_gap(node, kind);
        } else {
            // No argument was lowered, so no reference guesses anything: the
            // only open question is which items the expansion declares
            // (`thread_local! { static .. }`, `lazy_static! { .. }`). Those
            // cannot rebind a name the scope imports by name or declares
            // without a duplicate-name error, so at item position the
            // frontier is the one a matched, undecided invocation gets
            // (`UnexpandedItemMacro`): a wildcard-tier fallback in the scope,
            // which glob-bound, prelude-bound and unbound names still reach,
            // and the member branches of the scope's types. The scope-wide
            // `UnsupportedScopeOrBinder` made every lookup in bifrost-lsp's
            // server.rs incomplete because of one `thread_local!`.
            let kind = if item_position {
                ResolutionGapKind::UnexpandedItemMacro
            } else {
                ResolutionGapKind::UnsupportedExpression
            };
            self.add_local_gap(node, kind);
        }
    }

    /// Enumerate arguments of a macro invocation whose definition is not
    /// visible. Top-level comma- or semicolon-separated groups are expressions,
    /// except the second operand of unqualified `matches!`, which is a
    /// refutable pattern and is lowered in that context.
    ///
    /// Item position is enumerated too, for references only. Declaration
    /// replay remains the sole declaration authority over an item-position
    /// interior: a group that parses as exactly one expression node cannot be
    /// an item, and the fragment walk's authority guard refuses an import, an
    /// `extern crate`, a macro definition and a module mount wherever one
    /// appears inside a group. So `criterion_group!(benches, bench)` publishes
    /// its two value references, while `lazy_static! { static ref X: T = e; }`
    /// parses as no expression and keeps the enumeration gap.
    ///
    /// Returns whether every group parsed, which is the only condition under
    /// which the invocation's reference inventory may be called complete.
    /// Other definitionless macros retain the structured expression guess:
    /// `cfg!(unix)` publishes `unix`, while the `matches!` pattern operand
    /// distinguishes a visible variant from a new pattern binding.
    fn lower_definition_less_macro_arguments(&mut self, node: Node<'_>) -> bool {
        /// Top-level argument groups of a token tree, each as the byte span
        /// from its first token to its last. A separator inside a nested token
        /// tree belongs to that nested node and is never seen here. `;`
        /// separates as `,` does, so `vec![value; count]` reads as two
        /// expressions rather than one unparseable group.
        fn group_spans(arguments: Node<'_>) -> Vec<(usize, usize)> {
            let (interior, _) = crate::macro_matcher::interior_tokens(arguments);
            let mut groups = Vec::new();
            let mut group: Option<(usize, usize)> = None;
            for child in interior {
                if child.is_extra() {
                    continue;
                }
                if matches!(child.kind(), "," | ";") {
                    groups.extend(group.take());
                    continue;
                }
                match &mut group {
                    Some((_, end)) => *end = child.end_byte(),
                    None => group = Some((child.start_byte(), child.end_byte())),
                }
            }
            groups.extend(group);
            groups
        }
        let Some(arguments) = crate::declarations::rust_macro_invocation_arguments(node) else {
            return false;
        };
        let matches_macro =
            rust_unqualified_macro_invocation_name(node, self.source) == Some("matches");
        let groups = group_spans(arguments);
        if matches_macro && groups.len() != 2 {
            return false;
        }
        let scope = self.current_scope();
        let mut bindings = Vec::new();
        for (index, (start_byte, end_byte)) in groups.into_iter().enumerate() {
            let binding = crate::macro_matcher::MacroBinding {
                name: String::new(),
                fragment: if matches_macro && index == 1 {
                    crate::macro_matcher::MacroFragmentKind::Pat
                } else {
                    crate::macro_matcher::MacroFragmentKind::Expr
                },
                start_byte,
                end_byte,
                repetition_path: Vec::new(),
                ident_role: None,
            };
            let Some(tree) = crate::macro_matcher::parse_bound_fragment(&binding, self.source)
            else {
                return false;
            };
            // The group must be one expression node, not a span of several.
            // `lower_macro_fragment` walks the smallest node covering the
            // group's range; for `0; count` that is the wrapper's block, whose
            // rebased range runs past the token tree and would open a scope
            // wider than the scope containing the invocation.
            let covering = tree
                .root_node()
                .descendant_for_byte_range(start_byte, end_byte)
                .filter(|node| node.start_byte() == start_byte && node.end_byte() == end_byte);
            let Some(covering) = covering else {
                return false;
            };
            // An item is not an expression, whatever the wrapper made of it.
            // `wrap_fragment` puts an `Expr` group inside `fn __bifrost_frag()
            // { .. }`, and Rust lets an item appear in a block, so
            // `pub fn f() {}` parses here and covers its group exactly. Lowering
            // it would declare it, and declaration replay is the sole
            // declaration authority over an item-position interior, so the item
            // would get a second source declaration beside replay's: a
            // `PrimaryNode` one carrying the native site and the bridge while
            // replay's `Embedded` one carries the `CodeUnit`, which is the split
            // `lower_macro_bindings` documents as the thing not to do. Refusing
            // the group also keeps the invocation's reference inventory honestly
            // incomplete, because an item interior is not enumerable as
            // expressions.
            if tree.root_node().has_error() || crate::declarations::rust_node_is_item(covering) {
                return false;
            }
            bindings.push((binding, tree));
        }
        for (binding, tree) in &bindings {
            if binding.fragment != crate::macro_matcher::MacroFragmentKind::Pat {
                continue;
            }
            let pattern = tree
                .root_node()
                .descendant_for_byte_range(binding.start_byte, binding.end_byte)
                .expect("parsed pattern fragment retains its captured range");
            let mut nodes = vec![pattern];
            while let Some(node) = nodes.pop() {
                self.macro_fragment_nodes.insert(node.id());
                let mut cursor = node.walk();
                nodes.extend(node.named_children(&mut cursor));
            }
            let pattern_scope = self.allocate_scope(
                scope,
                None,
                ResolutionScopeKind::Block,
                binding.start_byte,
                binding.end_byte,
            );
            self.lower_pattern_bindings(
                pattern,
                pattern_scope,
                ResolutionBinderKind::Pattern,
                binding.end_byte,
                RustPatternBindingPosition::MacroRefutable,
            );
        }
        let owner = self.declaration_owners.last().copied();
        let self_owner = self.macro_fragment_self_owner(
            node,
            bindings
                .iter()
                .any(|(_, tree)| rust_tree_writes_self_path(tree, self.source)),
        );
        self.pending_macro_fragments
            .extend(
                bindings
                    .into_iter()
                    .map(|(binding, tree)| PendingMacroFragment {
                        binding,
                        tree,
                        scope,
                        owner,
                        container: crate::macro_matcher::RustMacroItemContainer::Lexical,
                        occurrence_provenance: SourceOccurrenceProvenance::Embedded,
                        self_owner,
                    }),
            );
        if !self.lowering_macro_fragments {
            self.lower_pending_macro_fragments();
        }
        true
    }

    /// Divan's proc-macro attribute accepts Rust expressions in its `args`
    /// option. The attribute can transform the function, but its structured
    /// expression value still names source items in the bench target's module.
    fn lower_divan_bench_attribute_arguments(&mut self, node: Node<'_>) -> bool {
        use crate::macro_matcher::{MacroBinding, MacroFragmentKind};

        let scope = self.current_scope();
        let owner = self.declaration_owners.last().copied();
        let mut queued = Vec::new();
        let mut recognized = false;
        for attribute_item in crate::syntax::outer_attributes(node) {
            let Some(attribute) = attribute_item.named_child(0) else {
                continue;
            };
            let Some(path) = attribute.named_child(0) else {
                continue;
            };
            let Some(segments) = rust_path_segments(path) else {
                continue;
            };
            if !matches!(segments.as_slice(), [namespace, name]
                if rust_node_text(*namespace, self.source) == "divan"
                    && rust_node_text(*name, self.source) == "bench")
            {
                continue;
            }
            recognized = true;
            self.add_local_gap(path, ResolutionGapKind::UnsupportedExpression);
            let Some(arguments) = attribute.child_by_field_name("arguments") else {
                continue;
            };
            let (tokens, _) = crate::macro_matcher::interior_tokens(arguments);
            let (Some(first), Some(last)) = (tokens.first(), tokens.last()) else {
                continue;
            };
            let option = MacroBinding {
                name: String::new(),
                fragment: MacroFragmentKind::Expr,
                start_byte: first.start_byte(),
                end_byte: last.end_byte(),
                repetition_path: Vec::new(),
                ident_role: None,
            };
            let Some(option_tree) =
                crate::macro_matcher::parse_bound_fragment(&option, self.source)
            else {
                continue;
            };
            let Some(assignment) = option_tree
                .root_node()
                .descendant_for_byte_range(option.start_byte, option.end_byte)
                .filter(|expression| expression.kind() == "assignment_expression")
            else {
                continue;
            };
            let Some(key) = assignment.child_by_field_name("left") else {
                continue;
            };
            if key.kind() != "identifier" || rust_node_text(key, self.source) != "args" {
                continue;
            }
            let Some(value) = assignment.child_by_field_name("right") else {
                continue;
            };
            let binding = MacroBinding {
                name: String::new(),
                fragment: MacroFragmentKind::Expr,
                start_byte: value.start_byte(),
                end_byte: value.end_byte(),
                repetition_path: Vec::new(),
                ident_role: None,
            };
            let Some(tree) = crate::macro_matcher::parse_bound_fragment(&binding, self.source)
            else {
                continue;
            };
            queued.push(PendingMacroFragment {
                binding,
                tree,
                scope,
                owner,
                container: crate::macro_matcher::RustMacroItemContainer::Lexical,
                occurrence_provenance: SourceOccurrenceProvenance::ExplicitSubspan,
                self_owner: None,
            });
        }
        if !queued.is_empty() {
            self.pending_macro_fragments.extend(queued);
            self.lower_pending_macro_fragments();
        }
        recognized
    }

    /// Lower the bindings the arm matched for a persisted per-blob file.
    ///
    /// A fragment whose interior declares items keeps the invocation's native
    /// frontier here: declaration replay owns the declarations an item macro
    /// expands to in this blob, and minting a second set beside them would
    /// give one source item two declarations. The selected macro capsule
    /// discharges that frontier at query time, where the expansion has its own
    /// identity space; see [`Self::lower_capsule_macro_bindings`].
    ///
    /// Returns whether the invocation was left a frontier.
    pub(crate) fn lower_macro_bindings(
        &mut self,
        invocation: Node<'_>,
        arm: &crate::macro_matcher::MacroArmMatch,
        transcribed_output: &crate::macro_matcher::MacroTranscribedOutput,
    ) -> bool {
        let discharged = self.discharged_item_macros.contains(&invocation.id());
        let mut frontier = false;
        self.lower_tt_binding_static_paths(invocation, &arm.bindings, transcribed_output);
        self.lower_macro_transcriber_literal_references(transcribed_output);
        for binding in &arm.bindings {
            if self.push_macro_binding_fragment(invocation, binding)
                == MacroBindingLowering::NeedsDeclarations
                && !discharged
            {
                self.add_local_gap(invocation, ResolutionGapKind::UnsupportedScopeOrBinder);
                frontier = true;
            }
        }
        if !self.lowering_macro_fragments {
            self.lower_pending_macro_fragments();
        }
        frontier
    }

    /// Lower the bindings the arm matched into an operation-local capsule.
    ///
    /// A capsule is one invocation's arguments re-parsed at their host byte
    /// offsets in their own identity space, so an `item` fragment is the
    /// expansion of a passthrough macro and is lowered here with full
    /// declaration authority. That is what closes the native frontier the
    /// persisted lowering left on the invocation. `stmt`, `block` and `pat`
    /// interiors still need a binder the capsule does not model, so their gap
    /// stands.
    ///
    /// `container` is where the expansion lands, read by the caller from
    /// declaration replay's context rows. In an `impl` or trait body the
    /// items are associated items: see [`Self::lower_associated_macro_item`].
    pub(crate) fn lower_capsule_macro_bindings(
        &mut self,
        invocation: Node<'_>,
        arm: &crate::macro_matcher::MacroArmMatch,
        container: crate::macro_matcher::RustMacroItemContainer,
    ) {
        // A selected-input capsule has the matcher result but not the source
        // transcriber, so its tt bindings remain unproven here.
        self.lower_tt_binding_static_paths(
            invocation,
            &arm.bindings,
            &crate::macro_matcher::MacroTranscribedOutput::default(),
        );
        for binding in &arm.bindings {
            if self.push_macro_binding_fragment(invocation, binding)
                != MacroBindingLowering::NeedsDeclarations
            {
                continue;
            }
            if binding.fragment != crate::macro_matcher::MacroFragmentKind::Item {
                self.add_local_gap(invocation, ResolutionGapKind::UnsupportedScopeOrBinder);
                continue;
            }
            let tree = crate::macro_matcher::parse_bound_fragment(binding, self.source)
                .expect("matched item fragment has already parsed successfully");
            let self_owner = self.macro_fragment_self_owner(
                invocation,
                rust_tree_writes_self_path(&tree, self.source),
            );
            self.pending_macro_fragments.push(PendingMacroFragment {
                binding: binding.clone(),
                tree,
                scope: self.current_scope(),
                owner: self.declaration_owners.last().copied(),
                container,
                occurrence_provenance: SourceOccurrenceProvenance::Embedded,
                self_owner,
            });
        }
        if !self.lowering_macro_fragments {
            self.lower_pending_macro_fragments();
        }
    }

    /// Publish the static paths written in an arm's `tt` bindings, and bind
    /// nothing else.
    ///
    /// `$($tokens:tt)*` binds each token of `consume!(wanted::free())`
    /// separately, so no single binding holds the path `wanted::free`. Tokens
    /// that consecutive `tt` bindings cover, with no unbound invocation token
    /// between them, are one run of source, and each run is parsed once for
    /// the paths it spells. A literal matcher token between two bindings
    /// (`$a:tt :: $b:tt`) ends the run, because that token is not transcribed
    /// with them.
    fn lower_tt_binding_static_paths(
        &mut self,
        invocation: Node<'_>,
        bindings: &[crate::macro_matcher::MacroBinding],
        transcribed_output: &crate::macro_matcher::MacroTranscribedOutput,
    ) {
        if transcribed_output.paths.is_empty() && transcribed_output.fragments.is_empty() {
            return;
        }
        let mut spans = bindings
            .iter()
            .filter(|binding| binding.fragment == crate::macro_matcher::MacroFragmentKind::Tt)
            .map(|binding| (binding.start_byte, binding.end_byte))
            .collect::<Vec<_>>();
        if spans.is_empty() {
            return;
        }
        spans.sort_unstable();
        // Every source token of the argument tree. A run can include nested
        // groups, so retain all leaves and use their ranges to detect matcher
        // literals between captured tt bindings.
        let arguments = crate::declarations::rust_macro_invocation_arguments(invocation)
            .expect("a matched macro invocation has an argument token tree");
        let mut tokens = Vec::new();
        let mut pending = vec![arguments];
        while let Some(node) = pending.pop() {
            if node.child_count() == 0 {
                if !node.is_extra() {
                    tokens.push((node.start_byte(), node.end_byte()));
                }
                continue;
            }
            let mut cursor = node.walk();
            pending.extend(node.children(&mut cursor));
        }
        tokens.sort_unstable();
        let mut runs: Vec<(usize, usize)> = Vec::new();
        let mut token_cursor = 0;
        for (start, end) in spans {
            while runs.last().is_some_and(|(_, run_end)| {
                tokens
                    .get(token_cursor)
                    .is_some_and(|token| token.0 < *run_end)
            }) {
                token_cursor += 1;
            }
            let separated = runs.last().is_some_and(|_| {
                tokens
                    .get(token_cursor)
                    .is_some_and(|(token_start, _)| *token_start < start)
            });
            if let Some((_, run_end)) = runs.last_mut().filter(|_| !separated) {
                *run_end = end;
            } else {
                runs.push((start, end));
            }
        }
        for (start_byte, end_byte) in runs {
            let run_fragments = transcribed_output
                .fragments
                .iter()
                .filter(|fragment| {
                    fragment.source == crate::macro_matcher::MacroTranscribedSource::Invocation
                        && fragment.start_byte == start_byte
                        && fragment.end_byte == end_byte
                })
                .collect::<Vec<_>>();
            let mut lowered_fragment = false;
            for fragment in run_fragments {
                let binding = crate::macro_matcher::MacroBinding {
                    name: String::new(),
                    fragment: fragment.fragment,
                    start_byte,
                    end_byte,
                    repetition_path: Vec::new(),
                    ident_role: None,
                };
                let Some(tree) = crate::macro_matcher::parse_bound_fragment(&binding, self.source)
                else {
                    continue;
                };
                let covering = tree
                    .root_node()
                    .descendant_for_byte_range(start_byte, end_byte)
                    .filter(|node| {
                        node.start_byte() == start_byte
                            && node.end_byte() == end_byte
                            && node.kind() == fragment.syntax_kind.as_str()
                    });
                if tree.root_node().has_error()
                    || covering.is_none_or(crate::declarations::rust_node_is_item)
                {
                    continue;
                }
                lowered_fragment = self.push_macro_binding_fragment(invocation, &binding)
                    == MacroBindingLowering::Queued;
                if lowered_fragment {
                    break;
                }
            }
            if lowered_fragment {
                continue;
            }
            let run_paths = transcribed_output
                .paths
                .iter()
                .filter(|path| {
                    path.segments
                        .first()
                        .is_some_and(|(start, _)| *start >= start_byte)
                        && path
                            .segments
                            .last()
                            .is_some_and(|(_, end)| *end <= end_byte)
                })
                .collect::<Vec<_>>();
            if run_paths.is_empty() {
                continue;
            }
            let mut matched = vec![false; run_paths.len()];
            let parse_type = run_paths
                .iter()
                .any(|path| path.role == crate::macro_matcher::MacroTranscribedPathRole::Type);
            let fragments = std::iter::once(crate::macro_matcher::MacroFragmentKind::Expr)
                .chain(parse_type.then_some(crate::macro_matcher::MacroFragmentKind::Ty));
            for fragment in fragments {
                let run = crate::macro_matcher::MacroBinding {
                    name: String::new(),
                    fragment,
                    start_byte,
                    end_byte,
                    repetition_path: Vec::new(),
                    ident_role: None,
                };
                let Some(tree) = crate::macro_matcher::parse_bound_fragment(&run, self.source)
                else {
                    continue;
                };
                for node in self.macro_static_path_nodes(&tree, &[], start_byte, end_byte) {
                    let Some(segments) =
                        crate::graph_support::rust_path_segments(node).map(|segments| {
                            segments
                                .iter()
                                .map(|segment| (segment.start_byte(), segment.end_byte()))
                                .collect::<Vec<_>>()
                        })
                    else {
                        continue;
                    };
                    let role = if node.kind() == "scoped_type_identifier" {
                        crate::macro_matcher::MacroTranscribedPathRole::Type
                    } else {
                        crate::macro_matcher::MacroTranscribedPathRole::Value
                    };
                    let is_call = node.parent().is_some_and(|parent| {
                        parent.kind() == "call_expression"
                            && parent.child_by_field_name("function") == Some(node)
                    });
                    let Some(path_index) = run_paths.iter().position(|path| {
                        path.segments == segments && path.role == role && path.is_call == is_call
                    }) else {
                        continue;
                    };
                    matched[path_index] = true;
                    self.lower_macro_static_path(node);
                }
                self.retain_macro_fragment_tree(tree);
                if matched.iter().all(|matched| *matched) {
                    break;
                }
            }
        }
    }

    fn lower_macro_transcriber_literal_references(
        &mut self,
        transcribed_output: &crate::macro_matcher::MacroTranscribedOutput,
    ) {
        let mut candidates = Vec::new();
        let mut seen = HashSet::new();
        for fragment in transcribed_output.fragments.iter().filter(|fragment| {
            fragment.source == crate::macro_matcher::MacroTranscribedSource::Definition
                && fragment.reference_role.is_some()
        }) {
            if !seen.insert((
                fragment.start_byte,
                fragment.end_byte,
                fragment.reference_role,
            )) {
                continue;
            }
            let Some((tree, scope, owner)) = self.retained_macro_transcriber_fragment(fragment)
            else {
                continue;
            };
            let role = match fragment.reference_role {
                Some(crate::macro_matcher::MacroTranscribedReferenceRole::Type) => 1,
                Some(crate::macro_matcher::MacroTranscribedReferenceRole::Call) => 2,
                None => unreachable!("literal reference candidate has a structured role"),
            };
            let spelling = self
                .source
                .get(fragment.start_byte..fragment.end_byte)
                .expect("replayed source range is a UTF-8 boundary");
            let spelling = strip_raw_identifier_prefix(spelling.trim()).to_owned();
            candidates.push((fragment.clone(), tree, scope, owner, spelling, role));
        }
        let mut namespace_roles = HashMap::<String, u8>::new();
        for (_, _, _, _, spelling, role) in &candidates {
            *namespace_roles.entry(spelling.clone()).or_default() |= role;
        }
        for (fragment, tree, scope, owner, spelling, role) in candidates {
            // A macro template can spell one name in both type and value
            // positions. Without a single namespace identity for that bare
            // template name, keep both sites out of the proven reference set.
            if namespace_roles.get(&spelling) != Some(&role) {
                continue;
            }
            let type_tree = if role == 1 {
                let binding = crate::macro_matcher::MacroBinding {
                    name: String::new(),
                    fragment: crate::macro_matcher::MacroFragmentKind::Ty,
                    start_byte: fragment.start_byte,
                    end_byte: fragment.end_byte,
                    repetition_path: Vec::new(),
                    ident_role: None,
                };
                let Some(type_tree) =
                    crate::macro_matcher::parse_bound_fragment(&binding, self.source)
                else {
                    continue;
                };
                let typed_fragment = crate::macro_matcher::MacroTranscribedFragment {
                    syntax_kind: "type_identifier".to_owned(),
                    ..fragment.clone()
                };
                if macro_transcriber_fragment_node(&type_tree, &typed_fragment).is_none() {
                    continue;
                }
                Some(type_tree)
            } else {
                None
            };
            if role == 2
                && !macro_transcriber_fragment_node(&tree, &fragment).is_some_and(|node| {
                    node.parent().is_some_and(|parent| {
                        parent.kind() == "call_expression"
                            && parent.child_by_field_name("function") == Some(node)
                    })
                })
            {
                continue;
            }
            let scopes = std::mem::replace(&mut self.scopes, vec![scope]);
            let owners =
                std::mem::replace(&mut self.declaration_owners, owner.into_iter().collect());
            if let Some(type_tree) = type_tree {
                let typed_fragment = crate::macro_matcher::MacroTranscribedFragment {
                    syntax_kind: "type_identifier".to_owned(),
                    ..fragment
                };
                let node = macro_transcriber_fragment_node(&type_tree, &typed_fragment)
                    .expect("parsed type fragment has its type identifier");
                if !self.handled_identifiers.contains(&node.id()) {
                    self.lower_bare_type_reference(node);
                }
                self.retain_macro_fragment_tree(type_tree);
            } else {
                let node = macro_transcriber_fragment_node(&tree, &fragment)
                    .expect("replayed call remains in its transcriber tree");
                if !self.handled_identifiers.contains(&node.id())
                    && let Some(call) = node.parent().filter(|parent| {
                        parent.kind() == "call_expression"
                            && parent.child_by_field_name("function") == Some(node)
                    })
                {
                    self.lower_transcriber_call_reference(call);
                }
            }
            assert_eq!(self.scopes, [scope]);
            assert_eq!(self.declaration_owners.last().copied(), owner);
            self.scopes = scopes;
            self.declaration_owners = owners;
        }
    }

    fn retained_macro_transcriber_fragment(
        &self,
        fragment: &crate::macro_matcher::MacroTranscribedFragment,
    ) -> Option<(
        tree_sitter::Tree,
        ResolutionScopeId,
        Option<ResolutionSiteId>,
    )> {
        self.macro_fragment_trees
            .iter()
            .find(|retained| {
                retained.transcriber_range.is_some_and(|(start, end)| {
                    start <= fragment.start_byte && fragment.end_byte <= end
                })
            })
            .map(|retained| (retained.tree.clone(), retained.scope, retained.owner))
    }

    fn retain_macro_fragment_tree(&mut self, tree: tree_sitter::Tree) {
        self.macro_fragment_trees.push(RetainedMacroFragmentTree {
            tree,
            scope: self.current_scope(),
            owner: self.declaration_owners.last().copied(),
            transcriber_range: None,
        });
    }

    fn retain_macro_transcriber_tree(&mut self, tree: tree_sitter::Tree, start: usize, end: usize) {
        self.macro_fragment_trees.push(RetainedMacroFragmentTree {
            tree,
            scope: self.current_scope(),
            owner: self.declaration_owners.last().copied(),
            transcriber_range: Some((start, end)),
        });
    }

    /// Queue the ordinary reference lowering for one matched binding.
    ///
    /// `tt` groups are left to [`Self::lower_tt_binding_static_paths`]; an
    /// `ident` with no transcriber role and every fragment with no reference
    /// role is ignored. The interiors that declare names are reported to the
    /// caller, which decides whether it has the authority to declare them.
    fn push_macro_binding_fragment(
        &mut self,
        invocation: Node<'_>,
        binding: &crate::macro_matcher::MacroBinding,
    ) -> MacroBindingLowering {
        use crate::macro_matcher::{MacroFragmentKind, MacroIdentRole};
        let mut fragment = binding.clone();
        match binding.fragment {
            MacroFragmentKind::Ty | MacroFragmentKind::Path | MacroFragmentKind::Expr => {}
            MacroFragmentKind::Ident => {
                fragment.fragment = match binding.ident_role {
                    Some(MacroIdentRole::Type) => MacroFragmentKind::Ty,
                    Some(MacroIdentRole::Value) => MacroFragmentKind::Expr,
                    _ => return MacroBindingLowering::Ignored,
                };
            }
            MacroFragmentKind::Tt => return MacroBindingLowering::Ignored,
            MacroFragmentKind::Item
            | MacroFragmentKind::Stmt
            | MacroFragmentKind::Block
            | MacroFragmentKind::Pat => return MacroBindingLowering::NeedsDeclarations,
            _ => return MacroBindingLowering::Ignored,
        }
        let tree = crate::macro_matcher::parse_bound_fragment(&fragment, self.source)
            .expect("matched fragment has already parsed successfully");
        let self_owner = self
            .macro_fragment_self_owner(invocation, rust_tree_writes_self_path(&tree, self.source));
        self.pending_macro_fragments.push(PendingMacroFragment {
            binding: fragment,
            tree,
            scope: self.current_scope(),
            owner: self.declaration_owners.last().copied(),
            container: crate::macro_matcher::RustMacroItemContainer::Lexical,
            occurrence_provenance: SourceOccurrenceProvenance::Embedded,
            self_owner,
        });
        MacroBindingLowering::Queued
    }

    /// A path-qualified macro imported by the current inline module is local
    /// only when the path names that module and its `use` binds the same
    /// macro name. This keeps a sibling or later textual definition from
    /// authorizing an unrelated scoped invocation.
    fn inline_module_macro_invocation_name(&self, node: Node<'_>) -> Option<&'source str> {
        let macro_path = node.child_by_field_name("macro")?;
        let segments = rust_path_segments(macro_path)?;
        if segments.len() < 3 || segments[0].kind() != "crate" {
            return None;
        }

        let terminal = *segments.last()?;
        let terminal_name = rust_node_text(terminal, self.source);
        let mut module_nodes = Vec::new();
        let mut ancestor = macro_path.parent();
        while let Some(current) = ancestor {
            if current.kind() == "mod_item" {
                module_nodes.push(current);
            }
            ancestor = current.parent();
        }
        module_nodes.reverse();
        if segments.len() != module_nodes.len() + 2
            || segments
                .iter()
                .skip(1)
                .take(module_nodes.len())
                .zip(&module_nodes)
                .any(|(segment, module)| {
                    module.child_by_field_name("name").is_none_or(|name| {
                        rust_node_text(name, self.source) != rust_node_text(*segment, self.source)
                    })
                })
        {
            return None;
        }

        let module = *module_nodes.last()?;
        let body = module.child_by_field_name("body")?;
        let mut cursor = body.walk();
        let has_local_macro_import = body.named_children(&mut cursor).any(|sibling| {
            let sibling = crate::syntax::unwrap_attributes(sibling);
            sibling.kind() == "use_declaration"
                && rust_cfg_condition(sibling, self.source) == RustCfgCondition::Always
                && crate::imports::rust_imports_from_use_declaration(sibling, self.source)
                    .iter()
                    .any(|import| {
                        import.local_name() == Some(terminal_name)
                            && import.path.as_ref().is_some_and(|path| {
                                path.segments.len() == 1 && path.segments[0] == terminal_name
                            })
                    })
        });
        has_local_macro_import.then_some(terminal_name)
    }

    /// The visible definition's match for `node`, and what its selected rule
    /// is proven to expand to. A `#[macro_export]` definition reached before
    /// its textual position is not visible at that invocation.
    fn match_visible_macro_invocation(
        &self,
        node: Node<'_>,
        source_position: RustItemMacroSourcePosition,
    ) -> Option<(
        Result<crate::macro_matcher::MacroArmMatch, crate::macro_matcher::MacroMatchError>,
        MacroExpansionProofs,
        crate::macro_matcher::MacroTranscribedOutput,
    )> {
        let (definition, transcribers, mut proofs, no_item_arms) = if let Some(name) =
            rust_unqualified_macro_invocation_name(node, self.source)
                .or_else(|| self.inline_module_macro_invocation_name(node))
        {
            self.macro_definitions
                .get(name)
                .and_then(|definitions| {
                    definitions.iter().rev().find(|definition| {
                        if definition.visible_after > node.start_byte() {
                            return false;
                        }
                        let mut scope = Some(self.current_scope());
                        while let Some(current) = scope {
                            if current == definition.scope {
                                return true;
                            }
                            scope = self.facts.scopes[current.index()].parent;
                        }
                        false
                    })
                })
                .map(|definition| {
                    (
                        &definition.source,
                        &definition.transcribers,
                        MacroExpansionProofs {
                            passthrough: definition.passthrough,
                            declares_no_item: definition.declares_no_item,
                            writes_only_impls: definition.writes_only_impls,
                        },
                        definition.declares_no_item_arms.as_slice(),
                    )
                })
                .or_else(|| {
                    self.exported_macro_definitions
                        .get(name)
                        .and_then(Option::as_ref)
                        .map(|definition| {
                            (
                                &definition.source,
                                &definition.transcribers,
                                definition.proofs,
                                definition.declares_no_item_arms.as_slice(),
                            )
                        })
                })
        } else {
            crate::macro_matcher::crate_root_macro_invocation_name(node, self.source).and_then(
                |name| {
                    self.exported_macro_definitions
                        .get(name)
                        .and_then(Option::as_ref)
                        .map(|definition| {
                            (
                                &definition.source,
                                &definition.transcribers,
                                definition.proofs,
                                definition.declares_no_item_arms.as_slice(),
                            )
                        })
                },
            )
        }?;
        let arguments = crate::declarations::rust_macro_invocation_arguments(node)?;
        let matched =
            crate::macro_matcher::match_macro_rules(definition, arguments, self.source, &|| true);
        if let Ok(arm) = &matched {
            proofs.declares_no_item |= *no_item_arms
                .get(arm.arm_index)
                .expect("matched macro arm has a declaration proof");
        }
        let parse_context = Self::macro_transcriber_parse_context(node, source_position);
        let transcribed_output = matched
            .as_ref()
            .ok()
            .and_then(|arm| {
                transcribers
                    .get(arm.arm_index)
                    .and_then(Option::as_ref)
                    .and_then(|transcriber| {
                        parse_context.map(|context| {
                            transcriber.replayed_tt_output(&arm.bindings, self.source, context)
                        })
                    })
            })
            .unwrap_or_default();
        Some((matched, proofs, transcribed_output))
    }

    fn macro_transcriber_parse_context(
        invocation: Node<'_>,
        source_position: RustItemMacroSourcePosition,
    ) -> Option<crate::macro_matcher::MacroTranscriberParseContext> {
        use crate::macro_matcher::MacroTranscriberParseContext as Context;
        match source_position {
            RustItemMacroSourcePosition::DirectItem => return Some(Context::Item),
            RustItemMacroSourcePosition::ItemStatement => return Some(Context::Expression),
            RustItemMacroSourcePosition::Other => {}
        }

        let mut current = invocation;
        while let Some(parent) = current.parent() {
            if parent
                .child_by_field_name("type")
                .is_some_and(|ty| ty.id() == current.id())
            {
                return Some(Context::Type);
            }
            if parent.kind() == "array_type"
                && parent
                    .child_by_field_name("length")
                    .is_some_and(|length| length.id() == current.id())
            {
                return Some(Context::Expression);
            }
            match parent.kind() {
                "generic_type"
                | "type_arguments"
                | "reference_type"
                | "pointer_type"
                | "array_type"
                | "slice_type"
                | "tuple_type"
                | "function_type"
                | "bounded_type"
                | "dynamic_type"
                | "abstract_type"
                | "scoped_type_identifier" => return Some(Context::Type),
                "expression_statement"
                | "call_expression"
                | "arguments"
                | "array_expression"
                | "assignment_expression"
                | "binary_expression"
                | "block"
                | "closure_expression"
                | "field_expression"
                | "if_expression"
                | "index_expression"
                | "let_declaration"
                | "loop_expression"
                | "match_expression"
                | "return_expression"
                | "struct_expression"
                | "unary_expression"
                | "while_expression"
                | "for_expression" => return Some(Context::Expression),
                "source_file"
                | "declaration_list"
                | "function_item"
                | "function_signature_item"
                | "impl_item"
                | "trait_item"
                | "struct_item"
                | "enum_item"
                | "type_item" => return None,
                _ => current = parent,
            }
        }
        None
    }

    fn lower_pending_macro_fragments(&mut self) {
        assert!(!self.lowering_macro_fragments);
        self.lowering_macro_fragments = true;
        while let Some(fragment) = self.pending_macro_fragments.pop() {
            let PendingMacroFragment {
                binding,
                tree,
                scope,
                owner,
                container,
                occurrence_provenance,
                self_owner,
            } = fragment;
            let scopes = std::mem::replace(&mut self.scopes, vec![scope]);
            let owners =
                std::mem::replace(&mut self.declaration_owners, owner.into_iter().collect());
            let self_owners = std::mem::replace(&mut self.macro_fragment_self_owner, self_owner);
            self.lower_macro_fragment(&binding, tree, container, occurrence_provenance);
            assert_eq!(self.scopes, [scope]);
            assert_eq!(self.declaration_owners.last().copied(), owner);
            self.scopes = scopes;
            self.declaration_owners = owners;
            self.macro_fragment_self_owner = self_owners;
        }
        self.lowering_macro_fragments = false;
    }

    fn lower_macro_fragment(
        &mut self,
        binding: &crate::macro_matcher::MacroBinding,
        tree: tree_sitter::Tree,
        container: crate::macro_matcher::RustMacroItemContainer,
        occurrence_provenance: SourceOccurrenceProvenance,
    ) {
        let root = tree
            .root_node()
            .descendant_for_byte_range(binding.start_byte, binding.end_byte)
            .expect("parsed fragment retains its captured range");
        if container == crate::macro_matcher::RustMacroItemContainer::Associated {
            self.associated_macro_items.insert(root.id());
        }
        let mut nodes = vec![root];
        while let Some(node) = nodes.pop() {
            match occurrence_provenance {
                SourceOccurrenceProvenance::Embedded => {
                    self.macro_fragment_nodes.insert(node.id());
                }
                SourceOccurrenceProvenance::ExplicitSubspan => {
                    self.explicit_source_fragment_nodes.insert(node.id());
                }
                SourceOccurrenceProvenance::PrimaryNode => {
                    unreachable!("parsed fragments are not primary AST nodes")
                }
            }
            let mut cursor = node.walk();
            nodes.extend(node.named_children(&mut cursor));
        }
        let mut pending = vec![(root, false)];
        while let Some((node, exiting)) = pending.pop() {
            if exiting {
                self.exit();
                continue;
            }
            let position = (node.kind() == "macro_invocation")
                .then(|| crate::declarations::rust_macro_invocation_source_position(node));
            // A `mod` inside a macro's token tree is the module route facts'
            // to publish: the route carries the invocation as a gate and the
            // crate's module walk decides it, and the answer is
            // `UnsupportedMacroGeneratedModule` when it cannot be made, so the
            // mount is not this walk's gap. What the capsule adds is the
            // declaration the crate row names: a `mod` the invocation replays
            // at module level gets a site and a root export and no binder
            // (`lower_capsule_module_declaration`), so the crate's export
            // lookup can reach it and no lexical lookup can. An inline
            // module's body is lowered in a module scope the declaration owns,
            // so its items are declared and exported under it, exactly as the
            // crate rows place them. A `mod` inside a function body stays
            // skipped.
            if node.kind() == "mod_item" {
                if binding.fragment == crate::macro_matcher::MacroFragmentKind::Item
                    && container == crate::macro_matcher::RustMacroItemContainer::Lexical
                    && self.current_scope_is_module_owned()
                    && let Some(declaration) = self.lower_capsule_module_declaration(node)
                    && let Some(body) = node.child_by_field_name("body")
                {
                    self.lower_module_body(node, Some(declaration));
                    pending.push((body, false));
                }
                continue;
            }
            // Imports, item definitions and macro definitions still require
            // declaration replay authority; do not invent it from a fragment.
            if matches!(
                node.kind(),
                "use_declaration" | "extern_crate_declaration" | "macro_definition"
            ) {
                self.add_local_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
                continue;
            }
            let action = self.enter(node, None, None, position);
            match action {
                TreeWalkAction::Skip => continue,
                TreeWalkAction::DescendWithExit => pending.push((node, true)),
                TreeWalkAction::Descend => {}
                TreeWalkAction::Stop => {
                    unreachable!("native fragment lowering does not stop the walk")
                }
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            pending.extend(children.into_iter().rev().map(|child| (child, false)));
        }
        self.retain_macro_fragment_tree(tree);
    }

    /// Declare a `mod name;` a capsule replays at module level, with no binder.
    ///
    /// The crate decides the invocation and mounts the module through the
    /// module route facts; when it decides it, it declares the module in
    /// `rust_crate_macro_items` against declaration replay's declaration,
    /// whose name range is this declaration's. A crate-row export lookup
    /// finds the capsule's definition at that range and bridges to it through
    /// the root export. A lexical binder would let a reference bind the module
    /// for an invocation the crate left undecided, so there is none, and the
    /// declaration is recorded as route-owned so that lowering does not read
    /// the missing binder as a lexical gap.
    fn lower_capsule_module_declaration(&mut self, node: Node<'_>) -> Option<ResolutionSiteId> {
        let name = node.child_by_field_name("name")?;
        self.declaration_properties
            .ensure_primary(node, &mut self.source_collector)
            .expect("a named module declaration has a source declaration");
        let declaration = self.add_identifier(
            name,
            ResolutionSiteKind::ModuleDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
            self.current_scope(),
        );
        self.record_declaration_site(node, declaration);
        self.facts.route_owned_module_declarations.push(declaration);
        self.add_module_root_export(declaration, ResolutionNamespace::Type);
        Some(declaration)
    }

    /// Lower one capsule `item` fragment that expands into an `impl` or trait
    /// body.
    ///
    /// The item is an associated item of an owner outside this capsule, and
    /// Rust never puts an associated item in unqualified lexical scope: in
    /// `impl Interest { cfg_aio! { pub const AIO: Interest = Interest(AIO); } }`
    /// the `AIO` in the initializer is the enclosing module's `AIO`. So the
    /// item's name is neither a binder nor a root export.
    ///
    /// It is not a declaration here either. A member declaration is published
    /// with its owner, as a relation member of an `impl` or a member of a
    /// trait's body scope (see [`Self::lower_associated_constant_declaration`]),
    /// and the owner's declaration is in the host, not in this capsule. A
    /// declaration with neither a binder nor an owner is a missing binder,
    /// which lowering treats as a lexical gap over the scope, so declaring the
    /// name would make every lookup through the capsule incomplete. The shape
    /// is the one [`Self::enter`] already names for a member whose owner did
    /// not lower in its fragment: `UnsupportedMemberScope`, which is not a
    /// lexical gap and says the member question stays open.
    ///
    /// Unlike that arm, a constant's or a type's interior is still lowered: its
    /// declared type and its value are ordinary references in the owner's
    /// body. A method's parameters and body need the callable's own
    /// declaration for their scopes, so a method keeps the whole-item gap and
    /// its references stay an enumeration gap.
    fn lower_associated_macro_item(&mut self, node: Node<'_>) -> TreeWalkAction {
        match node.kind() {
            "const_item" | "static_item" | "type_item" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.mark_syntax_subtree_consumed(name);
                }
                if node.child_by_field_name("type_parameters").is_some() {
                    self.add_local_gap(node, ResolutionGapKind::UnsupportedMemberScope);
                    return TreeWalkAction::Skip;
                }
                self.add_semantic_gap(node, ResolutionGapKind::UnsupportedMemberScope);
                if let Some(type_node) = node.child_by_field_name("type") {
                    self.lower_declared_type_identity(type_node);
                }
                TreeWalkAction::Descend
            }
            "function_item" | "function_signature_item" => {
                self.add_local_gap(node, ResolutionGapKind::UnsupportedMemberScope);
                TreeWalkAction::Skip
            }
            kind => unreachable!("{kind} is not an associated item kind"),
        }
    }

    fn macro_static_path_nodes<'tree>(
        &mut self,
        tree: &'tree tree_sitter::Tree,
        metavariables: &[(usize, usize)],
        start: usize,
        end: usize,
    ) -> Vec<Node<'tree>> {
        let mut paths = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.end_byte() < start || node.start_byte() > end {
                continue;
            }
            if node.start_byte() >= start && node.end_byte() <= end {
                self.macro_fragment_nodes.insert(node.id());
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.end_byte() < start || node.start_byte() > end {
                continue;
            }
            if node.start_byte() >= start
                && node.end_byte() <= end
                && matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier")
                && !node.has_error()
                && rust_path_segments(node).is_some_and(|segments| {
                    segments.iter().all(|segment| {
                        !metavariables.iter().any(|&(left, right)| {
                            left < segment.end_byte() && segment.start_byte() < right
                        })
                    })
                })
            {
                paths.push(node);
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            pending.extend(children.into_iter().rev());
        }
        paths
    }

    fn lower_macro_transcriber_paths(
        &mut self,
        tree: tree_sitter::Tree,
        metavariables: &[(usize, usize)],
        definition_crate_anchors: &[usize],
        start: usize,
        end: usize,
    ) {
        for node in self.macro_static_path_nodes(&tree, metavariables, start, end) {
            if self.handled_identifiers.contains(&node.id()) {
                continue;
            }
            // `$crate`, and ordinary `crate` for a non-exported macro, pin
            // an item path to this crate. Other template paths need context;
            // publishing a definition-site route would invent a target.
            let definition_anchored = rust_path_segments(node).is_some_and(|segments| {
                segments
                    .first()
                    .is_some_and(|head| definition_crate_anchors.contains(&head.start_byte()))
            });
            if !definition_anchored {
                let name = node
                    .child_by_field_name("name")
                    .expect("static path has a name");
                let (kind, namespace) = if node.kind() == "scoped_type_identifier" {
                    (ResolutionSiteKind::TypeReference, ResolutionNamespace::Type)
                } else {
                    (
                        ResolutionSiteKind::ValueReference,
                        ResolutionNamespace::Value,
                    )
                };
                // Retain the positioned member without a definition-site root
                // route or lexical fallback. Its receiver can only be supplied
                // by an invocation, so this gap belongs to the reference alone.
                let reference =
                    self.add_qualified_identifier(name, kind, namespace, self.current_scope());
                self.add_semantic_gap_at_site(
                    reference,
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                );
                // The head segment (`R` in `R::Database`) is an occurrence
                // too, and it names whatever the invocation site binds, so it
                // takes the same reference-local gap. A middle segment is the
                // terminal of the nested path node this walk also visits, and
                // an anchor keyword names no declaration. With every named
                // segment positioned, the template hides no reference and
                // records no enumeration gap.
                let head = rust_path_segments(node)
                    .and_then(|segments| segments.first().copied())
                    .expect("a static macro path has segments");
                if matches!(head.kind(), "identifier" | "type_identifier")
                    && self.handled_identifiers.insert(head.id())
                {
                    let head_reference = self.add_qualified_identifier(
                        head,
                        ResolutionSiteKind::TypeReference,
                        ResolutionNamespace::Type,
                        self.current_scope(),
                    );
                    self.add_semantic_gap_at_site(
                        head_reference,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    );
                }
                continue;
            }
            if node.kind() == "scoped_type_identifier" {
                self.lower_qualified_type_reference(node);
            } else if let Some(call) = node.parent().filter(|parent| {
                parent.kind() == "call_expression"
                    && parent.child_by_field_name("function") == Some(node)
            }) {
                self.lower_transcriber_call_reference(call);
            } else {
                self.lower_scoped_expression_reference(node);
            }
        }
        self.retain_macro_transcriber_tree(tree, start, end);
    }

    fn lower_macro_static_path(&mut self, node: Node<'_>) {
        if self.handled_identifiers.contains(&node.id()) {
            return;
        }
        if node.kind() == "scoped_type_identifier" {
            self.lower_qualified_type_reference(node);
        } else if let Some(call) = node.parent().filter(|parent| {
            parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(node)
        }) {
            self.lower_transcriber_call_reference(call);
        } else {
            self.lower_scoped_expression_reference(node);
        }
    }

    /// Enumerate the source module names of a use tree, including a glob's
    /// named destination. Leaves and aliases retain their existing lowering.
    fn lower_use_prefix_references(&mut self, declaration: Node<'_>) {
        let argument = declaration
            .child_by_field_name("argument")
            .expect("use has an argument");
        let mut pending = vec![(argument, Vec::new(), ResolutionRootImportAnchor::Lexical)];
        let mut prefix_sites = HashMap::new();
        while let Some((node, mut prefix, mut anchor)) = pending.pop() {
            match node.kind() {
                "use_list" => {
                    let mut cursor = node.walk();
                    pending.extend(
                        node.named_children(&mut cursor)
                            .map(|child| (child, prefix.clone(), anchor)),
                    );
                    continue;
                }
                "scoped_use_list" => {
                    if let Some(path) = node.child_by_field_name("path") {
                        let Some(segments) = rust_path_segments(path) else {
                            continue;
                        };
                        if rust_path_is_leading_absolute(path) {
                            anchor = ResolutionRootImportAnchor::Absolute;
                        }
                        prefix.extend(segments);
                    }
                    pending.push((
                        node.child_by_field_name("list")
                            .expect("scoped use has a list"),
                        prefix,
                        anchor,
                    ));
                    continue;
                }
                "use_as_clause" => {
                    pending.push((
                        node.child_by_field_name("path")
                            .expect("aliased use has a path"),
                        prefix,
                        anchor,
                    ));
                    continue;
                }
                _ => {}
            }
            let path = if node.kind() == "use_wildcard" {
                let Some(path) = node.named_child(0) else {
                    continue;
                };
                path
            } else {
                node
            };
            let Some(segments) = rust_path_segments(path) else {
                continue;
            };
            if rust_path_is_leading_absolute(path) {
                anchor = ResolutionRootImportAnchor::Absolute;
            }
            prefix.extend(segments);
            let count = if node.kind() == "use_wildcard" {
                prefix.len()
            } else {
                prefix.len().saturating_sub(1)
            };
            let root_scope = self.nearest_root_scope();
            for (position, name) in prefix[..count].iter().enumerate() {
                if prefix_sites.contains_key(&name.id()) {
                    continue;
                }
                let keyword = rust_path_anchor_keyword(name.kind());
                let reference = self.add_identifier(
                    *name,
                    ResolutionSiteKind::ImportDeclaration,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    // One `use` item's sites share one scope, and a `use` is an
                    // item: where a block declares items, that is the block's
                    // item scope, which is what `lower_use_declaration` gives
                    // the import's own sites.
                    self.item_scope(),
                );
                prefix_sites.insert(name.id(), reference);
                if keyword || position > 0 || anchor == ResolutionRootImportAnchor::Absolute {
                    let prefix_reference = (anchor == ResolutionRootImportAnchor::Lexical
                        && position > 0
                        && !rust_path_anchor_keyword(prefix[0].kind()))
                    .then(|| prefix_sites.get(&prefix[0].id()).copied())
                    .flatten();
                    self.facts
                        .root_references
                        .push(ResolutionRootReferenceFact {
                            reference,
                            root_scope,
                            anchor,
                            prefix_reference,
                        });
                    // An anchor denotes the module its own step reaches;
                    // a named segment is an export of the preceding module.
                    let route_end = position + usize::from(keyword);
                    for (position, segment) in prefix[..route_end].iter().enumerate() {
                        let name = self.intern_name(*segment);
                        self.facts.root_reference_segments.push(
                            ResolutionRootReferenceSegmentFact {
                                reference,
                                position: u32::try_from(position)
                                    .expect("Rust import prefix fits u32"),
                                name,
                            },
                        );
                    }
                }
            }
        }
    }

    /// `#[macro_use] extern crate rocket;` imports every macro the named
    /// crate publishes, into the crate's macro namespace rather than into one
    /// lexical module: a `routes![..]` written in any file of the crate names
    /// one of them. That scope is the crate, and the names are the
    /// dependency's published macro surface, so the binding belongs to the
    /// crate rows, which hold both. What this fragment owes them is the one
    /// thing only it knows: the declaration's own binder scope, which an
    /// import site states and which `cr_source_imports` requires.
    ///
    /// A plain `extern crate` names a crate alias the selected Cargo topology
    /// owns, and this fragment still states nothing about it.
    fn lower_extern_crate_declaration(
        &mut self,
        node: Node<'_>,
        projected_imports: &[RustProjectedImport],
    ) {
        let root_scope = self.item_scope();
        for projected in projected_imports {
            assert!(
                projected.import.is_extern_crate(),
                "an extern crate declaration projects extern crate imports: {projected:?}"
            );
            if projected.import.is_macro_use {
                self.add_site(node, ResolutionSiteKind::ImportDeclaration, root_scope);
            }
        }
        // The common producer does not yet enumerate the declaration itself as
        // a navigable target, so keep broad enumeration incomplete while
        // preventing its name and alias from becoming bogus lexical Value
        // references.
        self.add_enumeration_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
    }

    fn lower_use_declaration(&mut self, node: Node<'_>, projected_imports: &[RustProjectedImport]) {
        // A `use` is an item: where a block declares items, its binder belongs
        // in that block's item scope, beside the items that can name it.
        let root_scope = self.item_scope();
        if !matches!(
            self.facts.scopes[root_scope.index()].kind,
            ResolutionScopeKind::CompilationUnit
                | ResolutionScopeKind::Package
                | ResolutionScopeKind::Executable
                | ResolutionScopeKind::Block
        ) {
            self.add_local_gap(node, ResolutionGapKind::UnsupportedRoute);
            return;
        }

        let route_root_scope = self.nearest_root_scope();
        let mut unsupported = projected_imports.is_empty();
        for projected in projected_imports {
            assert!(
                !projected.import.is_extern_crate(),
                "extern crate declarations do not use the use-declaration lowering path"
            );
            let import = &projected.import;
            let binding_name = import.binding_name();
            let (route, local_name) = if import.info.is_wildcard {
                (import.path(), None)
            } else {
                let Some((_target_name, route)) = import.path().split_last() else {
                    unsupported = true;
                    continue;
                };
                (route, binding_name.named())
            };
            // A glob names the module it globs, so `use *;` states no source
            // module and there is nothing to route. A named import with an
            // empty route is the opposite: `use serde;`, `use serde as s;` and
            // `use serde::{self as s};` all name the path root itself, which in
            // Rust 2018 is a crate in the extern prelude or an item of the
            // crate root. That import binds its name to the root, so its route
            // is empty and its demand is the root token, and the general
            // lowering below states exactly that with no segments.
            if route.is_empty() && import.info.is_wildcard {
                // Preserve the exact binder scope for crate-row derivation.
                // The blob graph still reports its unsupported empty root route.
                self.add_site(node, ResolutionSiteKind::ImportDeclaration, root_scope);
                self.add_local_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
                continue;
            }

            let site = self.add_site(node, ResolutionSiteKind::ImportDeclaration, root_scope);
            self.facts.root_imports.push(ResolutionRootImportFact {
                site,
                root_scope,
                anchor: if import.info.is_global {
                    ResolutionRootImportAnchor::Absolute
                } else {
                    ResolutionRootImportAnchor::Lexical
                },
            });
            self.facts
                .root_import_kinds
                .push(ResolutionRootImportKindFact {
                    import_site: site,
                    kind: if !import.info.is_wildcard {
                        ResolutionRootImportKind::Named
                    } else {
                        ResolutionRootImportKind::Glob
                    },
                });
            for (position, segment) in route.iter().enumerate() {
                let name = self.intern_spelling(segment);
                self.facts
                    .root_import_segments
                    .push(ResolutionRootImportSegmentFact {
                        import_site: site,
                        position: u32::try_from(position)
                            .expect("Rust import route length exceeds u32"),
                        name,
                    });
            }
            if !import.info.is_wildcard {
                let local_name = local_name.map(|name| self.intern_spelling(name));
                let target_occurrence = projected
                    .source_occurrences
                    .expect("native imports retain primary source occurrences")
                    .target
                    .expect("named import has a target occurrence");
                let target_name =
                    self.intern_spelling(import.path().last().expect("named import has a target"));
                // `{self}` imports the module the prefix reaches, which lives in
                // the type namespace only.
                let namespaces: &[ResolutionNamespace] = if import.module_self {
                    &[ResolutionNamespace::Type]
                } else {
                    &[
                        ResolutionNamespace::Type,
                        ResolutionNamespace::Value,
                        ResolutionNamespace::Macro,
                    ]
                };
                for &namespace in namespaces {
                    if let Some(local_name) = local_name {
                        self.facts
                            .root_import_demands
                            .push(ResolutionRootImportDemandFact {
                                import_site: site,
                                namespace,
                                name: local_name,
                            });
                    }
                    // Retain the original target token even when the import
                    // introduces no local name. Alias tokens do not replace
                    // the target occurrence in references or rename.
                    // Namespace alternatives are separate sites.
                    let reference = self.add_site_for_occurrence(
                        target_occurrence,
                        ResolutionSiteKind::ImportDeclaration,
                        root_scope,
                    );
                    self.facts.identifiers.push(PositionedIdentifierFact {
                        site: reference,
                        name: target_name,
                        role: ResolutionIdentifierRole::Reference,
                        namespace,
                        qualifier: None,
                    });
                    self.facts
                        .reference_owners
                        .push(ResolutionReferenceOwnerFact {
                            reference,
                            owner: self.declaration_owners.last().copied(),
                        });
                    self.facts
                        .root_references
                        .push(ResolutionRootReferenceFact {
                            reference,
                            root_scope: route_root_scope,
                            anchor: if import.info.is_global {
                                ResolutionRootImportAnchor::Absolute
                            } else {
                                ResolutionRootImportAnchor::Lexical
                            },
                            prefix_reference: None,
                        });
                    if let Some(local_name) = local_name {
                        self.facts.root_import_demand_targets.push(
                            ResolutionRootImportDemandTargetFact {
                                import_site: site,
                                namespace,
                                name: local_name,
                                target: ResolutionRootImportDemandTarget::NamedReference(reference),
                            },
                        );
                    }
                    for (position, segment) in route.iter().enumerate() {
                        let name = self.intern_spelling(segment);
                        self.facts.root_reference_segments.push(
                            ResolutionRootReferenceSegmentFact {
                                reference,
                                position: u32::try_from(position)
                                    .expect("Rust import route length fits u32"),
                                name,
                            },
                        );
                    }
                }
            } else {
                self.pending_glob_imports.push(site);
            }
        }
        self.lower_use_prefix_references(node);
        if unsupported {
            self.add_local_gap(node, ResolutionGapKind::UnsupportedRoute);
        }
    }

    /// Rust cannot prove a nominal type's member surface closed, so every
    /// qualified member lookup says so.
    ///
    /// A blanket implementation, a trait bound, a `Deref` chain, or a trait
    /// from a crate this workspace does not index can each supply a member the
    /// owner's own impls never mention. The engine walks the indexed hierarchy
    /// and, reaching no owner that declares the name, would otherwise report a
    /// proved absence: `Host::ITEM` answered `no_definition` rather than the
    /// boundary it is. The engine is language-neutral and Java's surface
    /// really is closed, so the permission is the producer's to give.
    ///
    /// One row per qualified reference. The engine consults it only where it
    /// took the hierarchy branch, which is the nominal-owner case; a
    /// module-qualified route never asks.
    fn declare_open_member_surfaces(&mut self) {
        let qualified = self
            .facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.qualifier.is_some())
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        for site in qualified {
            self.facts
                .engine_rule_eligibilities
                .push(ResolutionEngineRuleEligibilityFact {
                    site,
                    rule: ResolutionEngineRuleKind::OpenMemberSurface,
                });
        }
    }

    fn lower_glob_import_demands(&mut self) {
        let explicit_demands = self
            .facts
            .root_import_demands
            .iter()
            .map(|demand| {
                (
                    self.facts.sites[demand.import_site.index()].scope,
                    demand.namespace,
                    demand.name,
                )
            })
            .collect::<HashSet<_>>();
        let rooted_references = self
            .facts
            .root_references
            .iter()
            .map(|reference| reference.reference)
            .collect::<HashSet<_>>();
        let mut seen = HashSet::new();
        let mut demands = Vec::new();
        for import_site in &self.pending_glob_imports {
            let import_scope = self.facts.sites[import_site.index()].scope;
            for identifier in self
                .facts
                .identifiers
                .iter()
                .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            {
                let reference_site = self.facts.sites[identifier.site.index()];
                let import = self.facts.sites[import_site.index()];
                // Import syntax and rooted references resolve through their
                // structured routes. Treating an import prefix as a glob's
                // lexical demand would invent a Type binding that shadows
                // the dependency crate the import itself names.
                if reference_site.kind == ResolutionSiteKind::ImportDeclaration
                    || rooted_references.contains(&identifier.site)
                    || (import.start_byte <= reference_site.start_byte
                        && reference_site.end_byte <= import.end_byte)
                {
                    continue;
                }
                let scope = reference_site.scope;
                if !explicit_demands.contains(&(
                    import_scope,
                    identifier.namespace,
                    identifier.name,
                )) && rust_scope_is_in_module(&self.facts.scopes, import_scope, scope)
                    && seen.insert((*import_site, identifier.namespace, identifier.name))
                {
                    demands.push(ResolutionRootImportDemandFact {
                        import_site: *import_site,
                        namespace: identifier.namespace,
                        name: identifier.name,
                    });
                    self.facts.root_import_demand_targets.push(
                        ResolutionRootImportDemandTargetFact {
                            import_site: *import_site,
                            namespace: identifier.namespace,
                            name: identifier.name,
                            target: ResolutionRootImportDemandTarget::SameNameGlob,
                        },
                    );
                }
            }
        }
        self.facts.root_import_demands.extend(demands);
    }

    fn lower_let(&mut self, node: Node<'_>) {
        let Some(pattern) = node.child_by_field_name("pattern") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let declarations = self.lower_pattern_bindings(
            pattern,
            self.current_scope(),
            ResolutionBinderKind::Pattern,
            node.end_byte(),
            RustPatternBindingPosition::Irrefutable,
        );
        if let Some(type_node) = node.child_by_field_name("type") {
            // A call initializer is expected to produce the annotated type,
            // which decides a result its callee leaves to inference.
            let expecting = node
                .child_by_field_name("value")
                .filter(|value| value.kind() == "call_expression");
            if !declarations.is_empty() || expecting.is_some() {
                let type_identity = self.lower_declared_type_identity(type_node);
                for (declaration, declared) in
                    self.allocate_declaration_type_slots(&declarations, DeclarationTypeRole::Value)
                {
                    self.transfer_declared_type(type_identity, declaration, declared);
                }
                if let Some(call) = expecting
                    && let Some(expected) = type_identity
                {
                    assert!(
                        self.pending_expected_results
                            .insert(call.id(), expected)
                            .is_none(),
                        "one call initializes one let"
                    );
                }
            }
        } else if pattern.kind() == "identifier"
            && let Some(initializer) = node.child_by_field_name("value")
            && initializer.kind() == "struct_expression"
        {
            // `let value = Type { .. };` names the binding's type in the
            // initializer's own `name` field, the same structured field the
            // receiver path reads for `Type { .. }.member()`. Without this the
            // binding has no declared value type at all, so every later
            // `value.member()` reports an unsupported semantic instead of
            // resolving.
            self.lower_declared_value_types(
                &declarations,
                initializer.child_by_field_name("name"),
                DeclarationTypeRole::Value,
            );
        } else if pattern.kind() == "identifier"
            && let Some(initializer) = node.child_by_field_name("value")
            && let Some((producer, unwrap_layers)) =
                rust_initializer_producer(initializer, self.source)
        {
            let pending = self
                .allocate_declaration_type_slots(&declarations, DeclarationTypeRole::Value)
                .into_iter()
                .map(|(declaration, target)| PendingCallInitialization {
                    declaration,
                    target,
                    unwrap_layers,
                })
                .collect::<Vec<_>>();
            assert!(
                self.pending_call_initializations
                    .insert(producer.id(), pending)
                    .is_none(),
                "one direct call initializer belongs to one let declaration"
            );
        }
    }

    /// Connect the typed slot an initializer expression produced to the `let`
    /// bindings that were waiting for it.
    ///
    /// Each recorded unwrap layer gets its own intermediate call-result slot,
    /// owned by the declaration whose initialization it belongs to, and removes
    /// one unproven `Option`/`Result` indirection layer. The binding's declared
    /// value then comes from a zero-delta `Initialization` transfer, whose
    /// input is a call result or the expression value of a runtime identifier;
    /// nothing else produces a typed slot for a `let` to take.
    fn discharge_pending_initializations(
        &mut self,
        node: Node<'_>,
        produced: Option<ResolutionTypeSlotId>,
        produced_role: ResolutionTypeSlotRole,
    ) {
        for initialization in self
            .pending_call_initializations
            .remove(&node.id())
            .unwrap_or_default()
        {
            let Some(produced) = produced else {
                self.add_local_gap_at_site(
                    initialization.declaration,
                    ResolutionGapKind::UnsupportedExpression,
                );
                continue;
            };
            assert!(
                initialization.unwrap_layers > 0
                    || matches!(
                        produced_role,
                        ResolutionTypeSlotRole::CallResult
                            | ResolutionTypeSlotRole::ExpressionValue
                    ),
                "a bare let initializer must produce a call result or an expression value, got {produced_role:?}"
            );
            let mut input = produced;
            for _ in 0..initialization.unwrap_layers {
                let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                    .expect("Rust resolution type-slot count exceeds u32");
                self.facts.type_slots.push(ResolutionTypeSlotFact {
                    id: output,
                    site: initialization.declaration,
                    role: ResolutionTypeSlotRole::CallResult,
                });
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input,
                    output,
                    kind: ResolutionTypeTransferKind::Unwrap,
                    indirection_delta: -1,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
                input = output;
            }
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input,
                output: initialization.target,
                kind: ResolutionTypeTransferKind::Initialization,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
        }
    }

    fn enter_closure_scope(&mut self, node: Node<'_>) {
        let Some(body) = node.child_by_field_name("body") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            let scope = self.allocate_scope(
                self.current_scope(),
                None,
                ResolutionScopeKind::Executable,
                node.start_byte(),
                node.end_byte(),
            );
            self.scopes.push(scope);
            self.exits.push(ExitAction::Scope);
            return;
        };
        let scope = self.allocate_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Executable,
            node.start_byte(),
            body.end_byte(),
        );
        if let Some(parameters) = node.child_by_field_name("parameters") {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                let pattern = parameter
                    .child_by_field_name("pattern")
                    .unwrap_or(parameter);
                let declarations = self.lower_pattern_bindings(
                    pattern,
                    scope,
                    ResolutionBinderKind::Parameter,
                    body.start_byte(),
                    RustPatternBindingPosition::Irrefutable,
                );
                if let Some(type_node) = parameter.child_by_field_name("type") {
                    self.lower_declared_value_types(
                        &declarations,
                        Some(type_node),
                        DeclarationTypeRole::Parameter,
                    );
                }
            }
        }
        self.scopes.push(scope);
        self.exits.push(ExitAction::Scope);
    }

    fn enter_for_scope(&mut self, node: Node<'_>) {
        let Some(body) = node.child_by_field_name("body") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            let scope = self.allocate_scope(
                self.current_scope(),
                None,
                ResolutionScopeKind::Block,
                node.start_byte(),
                node.end_byte(),
            );
            self.scopes.push(scope);
            self.exits.push(ExitAction::Scope);
            return;
        };
        let scope = self.allocate_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Block,
            node.start_byte(),
            body.end_byte(),
        );
        if let Some(pattern) = node.child_by_field_name("pattern") {
            let _ = self.lower_pattern_bindings(
                pattern,
                scope,
                ResolutionBinderKind::Pattern,
                body.start_byte(),
                RustPatternBindingPosition::Irrefutable,
            );
        } else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
        }
        self.scopes.push(scope);
        self.exits.push(ExitAction::Scope);
    }

    fn enter_match_arm_scope(&mut self, node: Node<'_>) {
        let scope = self.allocate_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Block,
            node.start_byte(),
            node.end_byte(),
        );
        if let Some(pattern) = node.child_by_field_name("pattern") {
            let _ = self.lower_pattern_bindings(
                pattern,
                scope,
                ResolutionBinderKind::Pattern,
                pattern.end_byte(),
                RustPatternBindingPosition::Refutable,
            );
        } else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
        }
        self.scopes.push(scope);
        self.exits.push(ExitAction::Scope);
    }

    fn prepare_direct_let_condition_scope(&mut self, owner: Node<'_>, condition: Node<'_>) {
        let body = owner
            .child_by_field_name("consequence")
            .or_else(|| owner.child_by_field_name("body"));
        let (Some(pattern), Some(body)) = (condition.child_by_field_name("pattern"), body) else {
            self.add_local_gap(owner, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let scope = self.allocate_statement_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Block,
            condition.start_byte(),
            body.end_byte(),
            body,
        );
        let _ = self.lower_pattern_bindings(
            pattern,
            scope,
            ResolutionBinderKind::Pattern,
            body.start_byte(),
            RustPatternBindingPosition::Refutable,
        );
        assert!(
            self.pending_scopes
                .insert(
                    body.id(),
                    PendingScope {
                        scope,
                        callable: None,
                    },
                )
                .is_none(),
            "one direct Rust let condition owns one consequence scope"
        );
    }

    fn prepare_let_chain_scope(&mut self, owner: Node<'_>, chain: Node<'_>) {
        let Some(body) = owner
            .child_by_field_name("consequence")
            .or_else(|| owner.child_by_field_name("body"))
        else {
            self.add_local_gap(owner, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let mut cursor = chain.walk();
        let conditions = chain
            .named_children(&mut cursor)
            .filter(|condition| condition.kind() == "let_condition")
            .collect::<Vec<_>>();
        if conditions.is_empty() {
            self.add_local_gap(owner, ResolutionGapKind::MalformedSyntax);
            return;
        }
        let scope = self.allocate_statement_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Block,
            chain.start_byte(),
            body.end_byte(),
            body,
        );
        for condition in conditions {
            let Some(pattern) = condition.child_by_field_name("pattern") else {
                self.add_local_gap(condition, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let _ = self.lower_pattern_bindings(
                pattern,
                scope,
                ResolutionBinderKind::Pattern,
                condition.end_byte(),
                RustPatternBindingPosition::Refutable,
            );
        }
        for node in [chain, body] {
            assert!(
                self.pending_scopes
                    .insert(
                        node.id(),
                        PendingScope {
                            scope,
                            callable: None,
                        },
                    )
                    .is_none(),
                "one Rust let chain owns its condition and consequence scopes"
            );
        }
    }

    fn lower_pattern_bindings(
        &mut self,
        pattern: Node<'_>,
        scope: ResolutionScopeId,
        kind: ResolutionBinderKind,
        activation_start: usize,
        position: RustPatternBindingPosition,
    ) -> Vec<ResolutionSiteId> {
        let activation_end = self.facts.scopes[scope.index()].end_byte;
        // Rust resolves a bare identifier in a refutable pattern as a path to a
        // unit variant or a constant when one is visible, and as a fresh
        // binding only when none is. An irrefutable position -- a `let`, a `for`
        // loop, a parameter -- rejects a path pattern outright, so a bare
        // identifier there is unconditionally the binder it looks like. Only a
        // match arm and a `let` condition ask the question, and only along the
        // pattern's own alternatives: a name nested inside a destructuring
        // pattern keeps the binder-only treatment that lets a request on it
        // answer the binding itself.
        let alternatives_decide_paths = matches!(
            position,
            RustPatternBindingPosition::Refutable | RustPatternBindingPosition::MacroRefutable
        );
        let mut pending = vec![(pattern, alternatives_decide_paths)];
        let mut binding_nodes = Vec::new();
        while let Some((node, alternative)) = pending.pop() {
            match node.kind() {
                "identifier" => {
                    binding_nodes.push((node, alternative));
                }
                "shorthand_field_identifier" => {
                    binding_nodes.push((node, false));
                }
                "field_pattern" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        pending.push((pattern, false));
                    } else if let Some(name) = node.child_by_field_name("name") {
                        pending.push((name, false));
                    }
                }
                "struct_pattern" | "tuple_struct_pattern" => {
                    let type_node = node.child_by_field_name("type").map(|node| node.id());
                    let mut cursor = node.walk();
                    pending.extend(
                        node.named_children(&mut cursor)
                            .filter(|child| Some(child.id()) != type_node)
                            .map(|child| (child, false)),
                    );
                }
                // A match guard hangs off the same `match_pattern` node as the
                // pattern it guards. It is an expression, not an alternative.
                "match_pattern" => {
                    let guard = node.child_by_field_name("condition").map(|node| node.id());
                    let mut cursor = node.walk();
                    pending.extend(
                        node.named_children(&mut cursor)
                            .map(|child| (child, alternative && Some(child.id()) != guard)),
                    );
                }
                "or_pattern" => {
                    let mut cursor = node.walk();
                    pending.extend(
                        node.named_children(&mut cursor)
                            .map(|child| (child, alternative)),
                    );
                }
                "captured_pattern" | "mut_pattern" | "ref_pattern" | "reference_pattern"
                | "slice_pattern" | "tuple_pattern" => {
                    let mut cursor = node.walk();
                    pending.extend(node.named_children(&mut cursor).map(|child| (child, false)));
                }
                _ => {}
            }
        }
        binding_nodes.sort_unstable_by_key(|(node, _)| (node.start_byte(), node.end_byte()));
        let mut bound_names = HashSet::new();
        let mut repeated_name = false;
        let mut declarations = Vec::new();
        for (node, alternative) in binding_nodes {
            let name = self.intern_name(node);
            if !bound_names.insert(name) {
                self.handled_identifiers.insert(node.id());
                repeated_name = true;
                continue;
            }
            let conditional_reference = alternative.then(|| {
                self.add_identifier(
                    node,
                    ResolutionSiteKind::ValueReference,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                    scope,
                )
            });
            let declaration = self.add_identifier(
                node,
                ResolutionSiteKind::ValueDeclaration,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                scope,
            );
            let owner = pattern
                .parent()
                .filter(|parent| {
                    position != RustPatternBindingPosition::MacroRefutable
                        && matches!(parent.kind(), "parameter" | "let_declaration")
                })
                .unwrap_or(pattern);
            let occurrence = self.source_collector.intern_node(owner);
            let name = self.site_occurrences[declaration.index()];
            let lexical_kind = match kind {
                ResolutionBinderKind::Parameter => DeclarationKind::Parameter,
                ResolutionBinderKind::Local => DeclarationKind::LocalVariable,
                ResolutionBinderKind::Pattern
                    if owner.kind() == "let_declaration" && pattern.kind() == "identifier" =>
                {
                    DeclarationKind::LocalVariable
                }
                ResolutionBinderKind::Pattern => DeclarationKind::PatternVariable,
                _ => unreachable!("pattern lowering requires a lexical binder kind: {kind:?}"),
            };
            let source_declaration =
                self.source_collector
                    .declare_lexical(occurrence, name, lexical_kind);
            self.declaration_sources
                .push((declaration, source_declaration));
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope,
                kind,
                hoisting: HoistingClass::SourceOrder,
                activation_start,
                activation_end,
            });
            if let Some(reference) = conditional_reference {
                self.facts
                    .conditional_binders
                    .push(ResolutionConditionalBinderFact {
                        reference,
                        declaration,
                    });
            }
            declarations.push(declaration);
        }
        if repeated_name {
            self.add_enumeration_gap_in_scope(
                pattern,
                ResolutionGapKind::UnsupportedScopeOrBinder,
                scope,
            );
        }
        declarations
    }

    fn lower_call_reference(&mut self, node: Node<'_>) {
        let lowered = self.lower_call_reference_result(node);
        let expected = self.pending_expected_results.remove(&node.id());
        if let Some((call, _)) = lowered {
            let function = node
                .child_by_field_name("function")
                .expect("a lowered Rust call has a function");
            if function.kind() == "generic_function" {
                let arguments = function
                    .child_by_field_name("type_arguments")
                    .expect("rust_explicit_type_argument_count accepted this generic_function");
                let rows = self.lower_call_type_arguments(arguments, call);
                self.facts.call_type_arguments.extend(rows);
            }
            // `Wrapper::<Square>::make()`: the path's type segment writes the
            // type's arguments, which an impl's parameters take. They are the
            // type's own only if the segment names the type itself rather
            // than an alias, which the engine checks against the segment's
            // identity slot, so a segment without one publishes no rows.
            let target = call_function_target(function);
            if target.kind() == "scoped_identifier"
                && let Some(segment) = target.child_by_field_name("path")
                && segment.kind() == "generic_type"
                && let Some(identity) = self.call_qualifier_identity(call)
            {
                let arguments = segment
                    .child_by_field_name("type_arguments")
                    .expect("Rust generic_type has type_arguments");
                let rows = self.lower_call_type_arguments(arguments, call);
                if !rows.is_empty() {
                    self.facts.call_owner_type_arguments.extend(rows);
                    self.facts
                        .call_owner_type_segments
                        .push(ResolutionCallOwnerTypeSegmentFact { call, identity });
                }
            }
            if let Some(expected) = expected {
                let value = self.declared_value_slot(call, Some(expected));
                self.facts
                    .call_expected_results
                    .push(ResolutionCallExpectedResultFact { call, value });
            }
            match node.child_by_field_name("arguments") {
                Some(arguments) if !rust_arguments_carry_attributes(arguments) => {
                    self.lower_call_arguments(arguments, call);
                }
                // A missing list is malformed, and an attribute on an argument
                // (`#[cfg(..)]`) can remove it: either way the written actuals
                // are not the call's arity.
                _ => self.retain_call_argument_gap(call),
            }
        }
        let result = lowered.map(|(_, result)| result);
        self.discharge_pending_initializations(node, result, ResolutionTypeSlotRole::CallResult);
        self.discharge_pending_receivers(node, result);
        self.discharge_pending_argument(node, result);
    }

    /// A call written in a macro transcriber is a template: `$x` and
    /// `$(..),*` stand for actuals the invocation supplies, so the written
    /// list is not the call's arity, and the walk never visits its arguments.
    fn lower_transcriber_call_reference(&mut self, node: Node<'_>) {
        self.pending_expected_results.remove(&node.id());
        if let Some((call, _)) = self.lower_call_reference_result(node) {
            self.retain_call_argument_gap(call);
        }
    }

    fn retain_call_argument_gap(&mut self, call: ResolutionSiteId) {
        self.facts.gaps.push(ResolutionGapFact {
            site: call,
            kind: ResolutionGapKind::UnsupportedCallApplicability,
        });
    }

    /// Lower one call's callee, call site and result slot, and return the call
    /// site and the result slot. The caller states the argument inventory.
    fn lower_call_reference_result(
        &mut self,
        node: Node<'_>,
    ) -> Option<(ResolutionSiteId, ResolutionTypeSlotId)> {
        let Some(function) = node.child_by_field_name("function") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return None;
        };
        let Some(explicit_type_argument_count) = rust_explicit_type_argument_count(function) else {
            // A generic-call wrapper without both structured children is
            // malformed; never turn that missing syntax into an apparent
            // zero-argument call.
            self.add_local_gap(function, ResolutionGapKind::MalformedSyntax);
            return None;
        };
        let target = call_function_target(function);
        if target.kind() == "generic_function" {
            // The shared structural helper intentionally leaves a malformed
            // generic wrapper in place so structural callers preserve its
            // original node. Resolution records the syntax failure locally.
            self.add_local_gap(target, ResolutionGapKind::MalformedSyntax);
            return None;
        }
        let callee = match target.kind() {
            "identifier" => Some(self.add_identifier(
                target,
                ResolutionSiteKind::CallableReference,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
                self.current_scope(),
            )),
            "scoped_identifier" => self.add_scoped_identifier(
                target,
                ResolutionSiteKind::CallableReference,
                ResolutionNamespace::Value,
            ),
            "field_expression" => {
                let Some(name) = target.child_by_field_name("field") else {
                    self.add_local_gap(target, ResolutionGapKind::MalformedSyntax);
                    return None;
                };
                if name.kind() != "field_identifier" {
                    // Numeric tuple fields (for example `pair.0()`) are
                    // computed function-valued fields, not named methods.
                    self.add_local_gap(target, ResolutionGapKind::UnsupportedExpression);
                    return None;
                }
                let receiver_value = target.child_by_field_name("value");
                let standard_self_owner = receiver_value
                    .filter(|value| value.kind() == "self")
                    .and_then(|_| {
                        self.declaration_owners
                            .last()
                            .and_then(|method| self.inherent_method_owner_types.get(method))
                            .copied()
                    });
                if let Some(self_value) = receiver_value.filter(|value| value.kind() == "self") {
                    // The receiver token is an ordinary value occurrence of the
                    // method's own `self` parameter, so it needs its own value
                    // reference site: without one, a request at that token
                    // reaches no structured Rust reference at all. A
                    // value-position member chain (`self.field`) already
                    // publishes exactly this site; call position only consumed
                    // the token. The receiver type still comes from the impl
                    // subject frontier below, which is the exact owner
                    // identity, so the site adds a binding occurrence without
                    // changing how the member itself resolves.
                    self.lower_runtime_value_reference(self_value);
                    // Both the receiver token and the member name are
                    // positioned references, so what is unknown is the
                    // receiver's owner, not the reference inventory.
                    if standard_self_owner.is_none() {
                        self.add_semantic_gap(target, ResolutionGapKind::UnsupportedScopeOrBinder);
                    }
                }
                let receiver_type = standard_self_owner.or_else(|| {
                    receiver_value
                        .filter(|value| value.kind() != "self")
                        .and_then(|_| self.lower_runtime_identifier_receiver(target))
                });
                let receiver_origin = if receiver_value.is_some_and(|value| value.kind() == "self")
                {
                    standard_self_owner.map(|_| ResolutionCallableReceiverOrigin::CurrentInstance)
                } else if receiver_value.is_some() {
                    Some(ResolutionCallableReceiverOrigin::ExplicitExpression)
                } else {
                    None
                };
                let reference = self.add_qualified_identifier(
                    name,
                    ResolutionSiteKind::MemberReference,
                    ResolutionNamespace::Callable,
                    self.current_scope(),
                );
                let qualifier = self
                    .facts
                    .identifiers
                    .iter()
                    .rev()
                    .find(|identifier| identifier.site == reference)
                    .and_then(|identifier| identifier.qualifier)
                    .expect("Rust callable member reference retains a receiver slot");
                if let Some(input) = receiver_type {
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input,
                        output: qualifier,
                        kind: ResolutionTypeTransferKind::Receiver,
                        indirection_delta: 0,
                        reference_indirection_delta: 0,
                        value_transform: if standard_self_owner.is_some()
                            || self.facts.type_slots[input.index()].role
                                == ResolutionTypeSlotRole::TargetTypeIdentity
                        {
                            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
                        } else {
                            ResolutionTypeTransferValueTransform::Preserve
                        },
                    });
                } else if let Some(value) = receiver_value.map(rust_receiver_operand)
                    && matches!(value.kind(), "field_expression" | "call_expression")
                    && rust_unwrapped_receiver_operand(value, self.source).is_none()
                {
                    self.pending_receiver_slots
                        .entry(value.id())
                        .or_default()
                        .push(qualifier);
                } else if let Some(value) = receiver_value.map(rust_receiver_operand) {
                    self.lower_computed_receiver(value, qualifier, reference);
                }
                if let Some(origin) = receiver_origin {
                    self.facts
                        .callable_receiver_origins
                        .push(ResolutionCallableReceiverOriginFact { reference, origin });
                }
                Some(reference)
            }
            _ => {
                // Keep indirect/computed callees local to their expression. The
                // tree walk still visits their receiver and argument children,
                // so known references remain available to lexical lowering.
                // UnsupportedRoute is reserved for route-shaped syntax whose
                // selected destination is unknown; a computed callee is not
                // such a route.
                self.add_local_gap(target, ResolutionGapKind::UnsupportedExpression);
                return None;
            }
        };
        let callee = callee?;
        if rust_type_reference_is_self(target, self.source) {
            // The constructor names the enclosing impl's concrete type, not a
            // lexical value named Self. Keep that identity separate from the
            // call-result projection and its invocation obligations.
            self.add_type_reference_identity(target, callee);
        }
        // The common callable obligation owns and can discharge this exact
        // callee gap. Omitted argument/signature inventories below have
        // distinct source-site gaps which that discharge cannot erase.
        self.facts.gaps.push(ResolutionGapFact {
            site: callee,
            kind: ResolutionGapKind::UnsupportedCallApplicability,
        });
        let call = self.add_site(node, ResolutionSiteKind::Call, self.current_scope());
        let result = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: result,
            site: call,
            role: ResolutionTypeSlotRole::CallResult,
        });
        self.facts.binding_projections.push(BindingProjectionFact {
            reference: callee,
            output: result,
            kind: BindingProjectionKind::TargetCallableResultType,
        });
        let qualifier = self
            .facts
            .identifiers
            .iter()
            .find(|identifier| identifier.site == callee)
            .and_then(|identifier| identifier.qualifier);
        let receiver = qualifier.map(|input| {
            let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: output,
                site: call,
                role: ResolutionTypeSlotRole::Receiver,
            });
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input,
                output,
                kind: ResolutionTypeTransferKind::Receiver,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
            output
        });
        self.facts.calls.push(ResolutionCallFact {
            call,
            callee,
            receiver,
            result,
            extra_result_slots: Vec::new(),
            explicit_type_argument_count,
        });
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::ArgumentIndependentBinding,
            });
        Some((call, result))
    }

    /// The identity slot of the type reference a call's callee path is
    /// qualified by: the path's final prefix, whose identity feeds the
    /// callee's qualifier. `None` when the qualifier takes no such identity,
    /// as for a module-anchored path.
    fn call_qualifier_identity(&self, call: ResolutionSiteId) -> Option<ResolutionTypeSlotId> {
        let callee = self
            .facts
            .calls
            .iter()
            .rev()
            .find(|fact| fact.call == call)
            .expect("a lowered call has its call fact")
            .callee;
        let qualifier = self
            .facts
            .identifiers
            .iter()
            .rev()
            .find(|identifier| identifier.site == callee)?
            .qualifier?;
        self.facts
            .type_transfers
            .iter()
            .rev()
            .find(|transfer| {
                transfer.output == qualifier
                    && transfer.kind == ResolutionTypeTransferKind::Receiver
            })
            .map(|transfer| transfer.input)
            .filter(|&input| {
                self.facts.type_slots[input.index()].role
                    == ResolutionTypeSlotRole::TargetTypeIdentity
            })
    }

    /// One type-argument row per argument in a call's `type_arguments` list,
    /// either the callable's turbofish (`make::<Square>()`) or its path's type
    /// segment (`Wrapper::<Square>::make()`), in position order with lifetimes
    /// skipped. The callee's generic parameters, or the impl target type's
    /// arguments, are numbered the same way, so position `j` names the `j`-th
    /// non-lifetime one. Each row's slot takes the argument's declared type as
    /// a value, as a parameter's declared slot does. A const argument has no
    /// type to give, and a type the lowering cannot name already carries its
    /// gap on its own syntax: either slot has no input, so it never decides a
    /// result. An associated-item constraint (`Item = T`, `Item: Bound`) has no
    /// position, so a list with one gives no rows.
    fn lower_call_type_arguments(
        &mut self,
        arguments: Node<'_>,
        call: ResolutionSiteId,
    ) -> Vec<ResolutionCallTypeArgumentFact> {
        let mut cursor = arguments.walk();
        let positional = arguments
            .named_children(&mut cursor)
            .filter(|argument| !argument.is_extra() && argument.kind() != "lifetime")
            .collect::<Vec<_>>();
        if positional
            .iter()
            .any(|argument| matches!(argument.kind(), "type_binding" | "trait_bounds"))
        {
            return Vec::new();
        }
        let mut rows = Vec::with_capacity(positional.len());
        for (ordinal, argument) in positional.into_iter().enumerate() {
            let is_const =
                argument.kind() == "block" || rust_literal_type(argument, self.source).is_some();
            let lowered = if is_const {
                None
            } else {
                self.lower_declared_type_identity(argument)
            };
            rows.push(ResolutionCallTypeArgumentFact {
                call,
                ordinal: u32::try_from(ordinal).expect("Rust type argument count exceeds u32"),
                value: self.declared_value_slot(call, lowered),
            });
        }
        rows
    }

    /// A DeclaredValue slot at a call holding a value of `declared`, as a
    /// parameter's declared slot holds its type's value. Without a type the
    /// slot has no input: the syntax that named no type carries its own gap.
    fn declared_value_slot(
        &mut self,
        call: ResolutionSiteId,
        declared: Option<LoweredDeclaredType>,
    ) -> ResolutionTypeSlotId {
        let value = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: value,
            site: call,
            role: ResolutionTypeSlotRole::DeclaredValue,
        });
        if let Some(declared) = declared {
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: declared.identity,
                output: value,
                kind: ResolutionTypeTransferKind::DeclaredType,
                indirection_delta: declared.indirection,
                reference_indirection_delta: declared.reference_indirection,
                value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                    addressable: false,
                },
            });
        }
        value
    }

    /// Publish one argument row per written actual, in source order.
    ///
    /// Each row's slot takes the value its expression produces. A borrow
    /// (`&x`, `&mut x`) is the operand's value behind one more reference
    /// layer, read from the `value` field of each `reference_expression`.
    /// Identifiers, `self`, calls and member chains are lowered later by the
    /// walk, so the slot waits for that node; a path is lowered here, as a
    /// receiver path is. Any other expression has no produced type, so the
    /// slot is fed from a gap on the expression's own site: the argument is
    /// unknown while the call itself stays exactly represented.
    fn lower_call_arguments(&mut self, arguments: Node<'_>, call: ResolutionSiteId) {
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::ArgumentCoercionFilter,
            });
        let mut cursor = arguments.walk();
        let actuals = arguments
            .named_children(&mut cursor)
            .filter(|argument| !argument.is_extra())
            .collect::<Vec<_>>();
        for (ordinal, argument) in actuals.into_iter().enumerate() {
            let value = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: value,
                site: call,
                role: ResolutionTypeSlotRole::Argument,
            });
            self.facts.call_arguments.push(ResolutionCallArgumentFact {
                call,
                ordinal: u32::try_from(ordinal).expect("Rust call argument count exceeds u32"),
                value,
            });
            let mut operand = rust_receiver_operand(argument);
            let mut reference_layers = 0i8;
            while operand.kind() == "reference_expression"
                && let Some(layers) = reference_layers.checked_add(1)
            {
                reference_layers = layers;
                operand = rust_receiver_operand(
                    operand
                        .child_by_field_name("value")
                        .expect("Rust reference_expression has a value field"),
                );
            }
            let pending = PendingArgument {
                argument: value,
                reference_layers,
            };
            match operand.kind() {
                "identifier" | "self" | "call_expression" | "field_expression" => {
                    assert!(
                        self.pending_argument_slots
                            .insert(operand.id(), pending)
                            .is_none(),
                        "one Rust argument expression feeds one argument slot"
                    );
                }
                "scoped_identifier" => {
                    let produced = self.lower_scoped_expression_reference(operand);
                    self.connect_argument(operand, pending, produced);
                }
                _ => self.connect_argument(operand, pending, None),
            }
        }
    }

    fn discharge_pending_argument(
        &mut self,
        node: Node<'_>,
        produced: Option<ResolutionTypeSlotId>,
    ) {
        if let Some(pending) = self.pending_argument_slots.remove(&node.id()) {
            self.connect_argument(node, pending, produced);
        }
    }

    /// Transfer an argument expression's value into its argument slot, behind
    /// the reference layers written around it. A literal whose type its token
    /// fixes is typed by an intrinsic seed on its own site. Any other
    /// expression that produced no value feeds the slot from its own
    /// gap-bearing site instead: an unsuffixed numeric literal names the
    /// inference its type waits for, a closure the inference of its signature,
    /// a macro invocation the expansion that is not replayed, and everything
    /// else is unsupported.
    fn connect_argument(
        &mut self,
        operand: Node<'_>,
        mut pending: PendingArgument,
        produced: Option<ResolutionTypeSlotId>,
    ) {
        let input = produced.unwrap_or_else(|| {
            let literal = rust_literal_type(operand, self.source);
            let site = self.add_site(
                operand,
                if literal.is_some() {
                    ResolutionSiteKind::Literal
                } else {
                    ResolutionSiteKind::UnsupportedExpression
                },
                self.current_scope(),
            );
            let input = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: input,
                site,
                role: ResolutionTypeSlotRole::ExpressionValue,
            });
            match literal {
                Some(RustLiteralType::Exact {
                    primitive,
                    reference_layers,
                }) => {
                    let name = self.intern_spelling(primitive);
                    self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                        output: input,
                        name,
                        kind: IntrinsicTypeKind::Primitive,
                        indirection: 0,
                    });
                    pending.reference_layers = pending
                        .reference_layers
                        .checked_add(reference_layers)
                        .expect("Rust argument reference layers fit i8");
                }
                Some(RustLiteralType::InferredNumeric) => {
                    self.add_semantic_gap_at_site(site, ResolutionGapKind::AmbiguousNumericLiteral);
                }
                // A closure's type is anonymous, and its signature is inferred
                // from the parameter it is passed to: the gap names that
                // inference rather than an unsupported expression.
                None if operand.kind() == "closure_expression" => {
                    self.add_semantic_gap_at_site(site, ResolutionGapKind::InferredType);
                }
                // A macro's expansion is not replayed as a value, so the gap
                // names the macro rather than an unsupported expression. None
                // of the measured corpora passes a call an arguments-only
                // passthrough macro, the one shape whose value is its argument.
                None if operand.kind() == "macro_invocation" => {
                    self.add_semantic_gap_at_site(site, ResolutionGapKind::MacroArgument);
                }
                Some(RustLiteralType::Unsupported) | None => {
                    self.add_semantic_gap_at_site(site, ResolutionGapKind::UnsupportedExpression);
                }
            }
            input
        });
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input,
            output: pending.argument,
            kind: ResolutionTypeTransferKind::Argument,
            indirection_delta: pending.reference_layers,
            reference_indirection_delta: pending.reference_layers,
            // A borrow is a fresh reference value, not the operand's place.
            value_transform: if pending.reference_layers == 0 {
                ResolutionTypeTransferValueTransform::Preserve
            } else {
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
            },
        });
    }

    fn lower_tuple_pattern_constructor(&mut self, node: Node<'_>) {
        let mut path = node
            .child_by_field_name("type")
            .expect("tuple pattern has a constructor");
        while path.kind() == "generic_type" {
            path = path
                .child_by_field_name("type")
                .expect("generic constructor has a head");
        }
        match path.kind() {
            "identifier" | "type_identifier" => {
                self.lower_runtime_value_reference(path);
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                self.lower_scoped_expression_reference(path);
            }
            _ => self.add_local_gap(path, ResolutionGapKind::UnsupportedExpression),
        }
    }

    fn lower_struct_pattern_references(&mut self, node: Node<'_>) {
        let path = node
            .child_by_field_name("type")
            .expect("struct pattern has an owner");
        let owner = self.lower_declared_type_identity(path);
        let owner = self.project_struct_field_owner(owner);
        let mut cursor = node.walk();
        for field in node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "field_pattern")
        {
            if let Some(name) = field.child_by_field_name("name") {
                self.lower_named_field_reference(name, owner);
            }
        }
    }

    fn lower_struct_initializer_fields(&mut self, node: Node<'_>) {
        let name = node
            .child_by_field_name("name")
            .expect("struct expression has an owner");
        let owner = self.lower_declared_type_identity(name);
        let owner = self.project_struct_field_owner(owner);
        let body = node
            .child_by_field_name("body")
            .expect("struct expression has fields");
        let mut cursor = body.walk();
        for initializer in body.named_children(&mut cursor) {
            let field = match initializer.kind() {
                "field_initializer" => initializer.child_by_field_name("field"),
                "shorthand_field_initializer" => {
                    let mut cursor = initializer.walk();
                    let field = initializer
                        .named_children(&mut cursor)
                        .find(|child| child.kind() == "identifier");
                    if let Some(field) = field {
                        self.lower_runtime_value_reference(field);
                    }
                    field
                }
                _ => continue,
            };
            if let Some(field) =
                field.filter(|field| matches!(field.kind(), "identifier" | "field_identifier"))
            {
                self.lower_named_field_reference(field, owner);
            }
        }
    }

    /// Project a separate owner frontier for the declaration whose members
    /// a struct literal writes or a struct pattern reads, preserving its
    /// shared expression-type frontier.
    ///
    /// `lower_declared_type_identity` gives the owner path a
    /// `TargetTypeIdentity` projection, which the evaluator reads through the
    /// constructor rule: for `Enum::Variant` it answers the enum, because a
    /// variant named in a value position denotes a constructor of its enum.
    /// A struct literal's or struct pattern's owner is not that:
    /// `Compound::Map { ser: 2 }` writes, and `Compound::Map { ser: s }`
    /// reads, the fields `Map` declares, not fields of `Compound`, and the
    /// field lookup has to reach the variant's own member scope.
    /// `TargetMemberOwnerType` answers the target itself whenever the target
    /// owns a member scope, and is the ordinary identity projection otherwise,
    /// so `Record { ser: 1 }` is unchanged.
    ///
    /// `Self { .. }` has no binding projection: its frontier takes a
    /// transfer from the impl subject rather than a name binding.
    fn project_struct_field_owner(
        &mut self,
        owner: Option<LoweredDeclaredType>,
    ) -> Option<LoweredDeclaredType> {
        let mut owner = owner?;
        let projection = self
            .facts
            .binding_projections
            .iter()
            .find(|projection| {
                projection.output == owner.identity
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
            })
            .copied();
        if let Some(projection) = projection {
            let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: output,
                site: projection.reference,
                role: ResolutionTypeSlotRole::TargetTypeIdentity,
            });
            self.facts.binding_projections.push(BindingProjectionFact {
                reference: projection.reference,
                output,
                kind: BindingProjectionKind::TargetMemberOwnerType,
            });
            owner.identity = output;
        }
        Some(owner)
    }

    fn lower_named_field_reference(&mut self, field: Node<'_>, owner: Option<LoweredDeclaredType>) {
        let reference = self.add_qualified_identifier(
            field,
            ResolutionSiteKind::MemberReference,
            ResolutionNamespace::Value,
            self.current_scope(),
        );
        let qualifier = self.facts.identifiers.last().unwrap().qualifier.unwrap();
        if let Some(owner) = owner {
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: owner.identity,
                output: qualifier,
                kind: ResolutionTypeTransferKind::Receiver,
                indirection_delta: owner.indirection,
                reference_indirection_delta: owner.reference_indirection,
                value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                    addressable: false,
                },
            });
        }
        let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: output,
            site: reference,
            role: ResolutionTypeSlotRole::ExpressionValue,
        });
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetDeclaredValueType,
        });
    }

    /// Lower a value-position member chain such as `outer.inner.value`.
    ///
    /// Only call position lowered a `field_expression`, so a member read had no
    /// occurrence at all: the walk reached the `field_identifier` and recorded
    /// an unlowered boundary. Each member of the chain now gets the receiver
    /// qualified shape call position builds, and the value of one member feeds
    /// the receiver of the next member outward, so the chain terminal and every
    /// intermediate member have an occurrence. The chain is followed through
    /// the tree-sitter `value` field and lowered from the base outward, so no
    /// step needs recursion.
    fn lower_value_field_expression(&mut self, node: Node<'_>) {
        let output = self.lower_value_field_chain(node);
        self.discharge_pending_argument(node, output);
    }

    /// Lower one member chain whose outermost member is `node`, and return
    /// that member's value slot.
    fn lower_value_field_chain(&mut self, node: Node<'_>) -> Option<ResolutionTypeSlotId> {
        let mut members: Vec<(Node<'_>, Node<'_>)> = Vec::new();
        let mut base = None;
        let mut current = node;
        loop {
            let Some(value) = current.child_by_field_name("value") else {
                self.add_local_gap(current, ResolutionGapKind::MalformedSyntax);
                return None;
            };
            let Some(field) = current.child_by_field_name("field") else {
                self.add_local_gap(current, ResolutionGapKind::MalformedSyntax);
                return None;
            };
            if self.handled_identifiers.contains(&field.id()) {
                // Call position already lowered this member as a callable.
                break;
            }
            assert!(matches!(
                field.kind(),
                "field_identifier" | "integer_literal"
            ));
            members.push((current, field));
            if value.kind() != "field_expression" {
                base = Some(value);
                break;
            }
            current = value;
        }
        let (innermost_member, _) = members.last().copied()?;
        members.reverse();
        let mut receiver = match base {
            Some(value) if value.kind() == "self" => {
                Some(self.lower_runtime_value_reference(value))
            }
            Some(value) if value.kind() == "identifier" => {
                self.lower_runtime_identifier_receiver(innermost_member)
            }
            // A computed receiver (a call result, a `?`, an index, a literal)
            // has no value slot here. The member loop below still publishes
            // every member reference and gives the innermost one its receiver:
            // a pending call result, or `lower_computed_receiver`, which puts
            // the receiver's gap on that member reference. Reference
            // enumeration is therefore complete, so no enumeration gap.
            Some(_) => None,
            // The chain stopped at a member that was lowered already, so no
            // receiver slot exists to transfer from.
            None => None,
        };
        for (member, field) in members {
            let reference = self.add_qualified_identifier(
                field,
                ResolutionSiteKind::MemberReference,
                ResolutionNamespace::Value,
                self.current_scope(),
            );
            if let Some(input) = receiver {
                // `add_qualified_identifier` pushed this member's identifier
                // last, so search from the end: a forward scan would be linear
                // in the file's whole identifier inventory once per member.
                let qualifier = self
                    .facts
                    .identifiers
                    .iter()
                    .rev()
                    .find(|identifier| identifier.site == reference)
                    .and_then(|identifier| identifier.qualifier)
                    .expect("Rust member reference retains a receiver slot");
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input,
                    output: qualifier,
                    kind: ResolutionTypeTransferKind::Receiver,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
            }
            if receiver.is_none()
                && member.id() == innermost_member.id()
                && let Some(value) = base
            {
                let qualifier = self.facts.identifiers.last().unwrap().qualifier.unwrap();
                if value.kind() == "call_expression"
                    && rust_unwrapped_receiver_operand(value, self.source).is_none()
                {
                    self.pending_receiver_slots
                        .entry(value.id())
                        .or_default()
                        .push(qualifier);
                } else {
                    self.lower_computed_receiver(
                        rust_receiver_operand(value),
                        qualifier,
                        reference,
                    );
                }
            }
            let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: output,
                site: reference,
                role: ResolutionTypeSlotRole::ExpressionValue,
            });
            self.facts.binding_projections.push(BindingProjectionFact {
                reference,
                output,
                kind: BindingProjectionKind::TargetDeclaredValueType,
            });
            self.discharge_pending_receivers(member, Some(output));
            receiver = Some(output);
        }
        receiver
    }

    /// Project a receiver from its structured value or construction syntax.
    /// Nested calls publish their result later in the ordinary iterative walk.
    fn lower_runtime_identifier_receiver(
        &mut self,
        target: Node<'_>,
    ) -> Option<ResolutionTypeSlotId> {
        let value = rust_receiver_operand(target.child_by_field_name("value")?);
        match value.kind() {
            "identifier" if !self.handled_identifiers.contains(&value.id()) => {
                Some(self.lower_runtime_value_reference(value))
            }
            "scoped_identifier" => self.lower_scoped_expression_reference(value),
            "struct_expression" => value
                .child_by_field_name("name")
                .and_then(|name| self.lower_declared_type_identity(name))
                .map(|ty| ty.identity),
            // The ordinary iterative walk publishes these child results, and
            // `lower_computed_receiver` takes a `?` over one of them.
            "field_expression" | "call_expression" | "try_expression" => None,
            "string_literal" | "raw_string_literal" | "char_literal" | "integer_literal"
            | "float_literal" | "boolean_literal" => {
                // The method is retained by the caller. Atomic literals have
                // no identifier operands; only the receiver type is unknown.
                let site = self.add_site(value, ResolutionSiteKind::Literal, self.current_scope());
                self.add_semantic_gap_at_site(site, ResolutionGapKind::UnsupportedExpression);
                None
            }
            // Any other computed receiver (an index, a cast, a block): the
            // caller publishes the member reference and
            // `lower_computed_receiver` puts the receiver's gap on it, while
            // the ordinary walk enumerates the operand's own identifiers. No
            // reference goes unpublished, so this is no enumeration gap.
            _ => None,
        }
    }

    /// Give a member's receiver slot the value of a receiver no identifier or
    /// call produces.
    ///
    /// `value?`, `value.unwrap()` and `value.expect(..)` each remove one
    /// unproven `Option`/`Result` layer from their operand, as they do in a
    /// `let` initializer: when the operand is a call or member chain, its
    /// result reaches the receiver through `Unwrap` transfers once the walk
    /// lowers it. The unwrap call is not the receiver's producer: its method
    /// is std's, which nothing indexes. Any other computed receiver (an
    /// index, a literal, a block, a `?` over one of those) has no value type
    /// the producer models, so the receiver slot carries that gap itself.
    /// Without it the slot had no producer and no reason, and the evaluator
    /// could only report a missing slot producer.
    fn lower_computed_receiver(
        &mut self,
        value: Node<'_>,
        qualifier: ResolutionTypeSlotId,
        reference: ResolutionSiteId,
    ) {
        if value.kind() == "self" || value.kind() == "identifier" {
            // An identifier receiver is lowered by its own path, and a `self`
            // without a standard owner already reports its binder gap.
            self.add_semantic_gap_at_site(reference, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        }
        // Every `?`, `.unwrap()` and `.expect(..)` layer between the member
        // and its call or member-chain operand removes one layer, through its
        // own slot, exactly as the layers of a `let` initializer do.
        if let Some((operand, layers)) = rust_unwrapped_receiver_operand(value, self.source) {
            let mut output = qualifier;
            let mut kind = ResolutionTypeTransferKind::Receiver;
            let mut indirection_delta = 0;
            for _ in 0..layers {
                let unwrapped = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                    .expect("Rust resolution type-slot count exceeds u32");
                self.facts.type_slots.push(ResolutionTypeSlotFact {
                    id: unwrapped,
                    site: reference,
                    role: ResolutionTypeSlotRole::CallResult,
                });
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input: unwrapped,
                    output,
                    kind,
                    indirection_delta,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
                output = unwrapped;
                kind = ResolutionTypeTransferKind::Unwrap;
                indirection_delta = -1;
            }
            // The operand's own result enters through the last layer's
            // `Unwrap` transfer once the walk lowers it.
            self.pending_unwrapped_receiver_slots
                .entry(operand.id())
                .or_default()
                .push(output);
            return;
        }
        // The gap describes the receiver's value, not the member's
        // enumeration: the member reference itself is published.
        self.add_semantic_gap_at_site(reference, ResolutionGapKind::UnsupportedExpression);
    }

    fn discharge_pending_receivers(
        &mut self,
        node: Node<'_>,
        result: Option<ResolutionTypeSlotId>,
    ) {
        for output in self
            .pending_unwrapped_receiver_slots
            .remove(&node.id())
            .unwrap_or_default()
        {
            if let Some(input) = result {
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input,
                    output,
                    kind: ResolutionTypeTransferKind::Unwrap,
                    indirection_delta: -1,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
            } else {
                self.add_local_gap_at_site(
                    self.facts.type_slots[output.index()].site,
                    ResolutionGapKind::UnsupportedExpression,
                );
            }
        }
        for output in self
            .pending_receiver_slots
            .remove(&node.id())
            .unwrap_or_default()
        {
            if let Some(input) = result {
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input,
                    output,
                    kind: ResolutionTypeTransferKind::Receiver,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
            } else {
                self.add_local_gap_at_site(
                    self.facts.type_slots[output.index()].site,
                    ResolutionGapKind::UnsupportedExpression,
                );
            }
        }
    }

    fn lower_runtime_value_reference(&mut self, value: Node<'_>) -> ResolutionTypeSlotId {
        let reference = self.add_identifier(
            value,
            ResolutionSiteKind::ValueReference,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
            self.current_scope(),
        );
        let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust resolution type-slot count exceeds u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: output,
            site: reference,
            role: ResolutionTypeSlotRole::ExpressionValue,
        });
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetDeclaredValueType,
        });
        self.discharge_pending_initializations(
            value,
            Some(output),
            ResolutionTypeSlotRole::ExpressionValue,
        );
        self.discharge_pending_argument(value, Some(output));
        output
    }

    fn lower_self_expression_reference(&mut self, node: Node<'_>) {
        if self.handled_identifiers.contains(&node.id()) {
            return;
        }
        self.lower_runtime_value_reference(node);
    }

    fn lower_qualified_type_reference(&mut self, node: Node<'_>) {
        if let Some(reference) = self.add_scoped_identifier(
            node,
            ResolutionSiteKind::TypeReference,
            ResolutionNamespace::Type,
        ) {
            self.add_type_reference_identity(node, reference);
        }
    }

    fn lower_bare_expression_reference(&mut self, node: Node<'_>) {
        if self.handled_identifiers.contains(&node.id()) {
            return;
        }
        if rust_enclosing_item_generic_parameter_namespace(node, self.source)
            == Some(ResolutionNamespace::Value)
        {
            let output = self.lower_runtime_value_reference(node);
            let reference = self.facts.type_slots[output.index()].site;
            self.add_local_gap_at_site(reference, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        }
        let Some(parent) = node.parent() else {
            self.mark_unlowered_identifier_boundary(node);
            return;
        };
        let is_direct_value = parent
            .child_by_field_name("value")
            .is_some_and(|value| value.id() == node.id());
        // A turbofish wraps a value name in its `function` field even when
        // there is no call (for example Unit::<4> or identity::<u8>). Callees
        // already consumed by call lowering were excluded above. Retain the
        // same value reference as a qualified path in this position; generic
        // expression type flow remains governed by its existing wrapper gaps.
        let is_generic_value = parent.kind() == "generic_function"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node.id());
        let is_array_length = parent.kind() == "array_type"
            && parent
                .child_by_field_name("length")
                .is_some_and(|length| length.id() == node.id());
        let is_direct_body = parent.kind() == "closure_expression"
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.id() == node.id());
        let is_direct_condition = matches!(parent.kind(), "if_expression" | "while_expression")
            && parent
                .child_by_field_name("condition")
                .is_some_and(|condition| condition.id() == node.id());
        if !is_direct_value
            && !is_generic_value
            && !is_array_length
            && !is_direct_body
            && !is_direct_condition
            && !matches!(
                parent.kind(),
                "arguments"
                    | "array_expression"
                    | "assignment_expression"
                    | "binary_expression"
                    | "block"
                    | "compound_assignment_expr"
                    | "else_clause"
                    | "expression_statement"
                    | "index_expression"
                    | "parenthesized_expression"
                    | "range_expression"
                    | "return_expression"
                    | "shorthand_field_initializer"
                    | "try_expression"
                    | "tuple_expression"
                    | "unary_expression"
            )
        {
            self.mark_unlowered_identifier_boundary(node);
            return;
        }
        let output = self.lower_runtime_value_reference(node);
        if rust_type_reference_is_self(node, self.source) {
            // A bare `Self` value is the unit constructor of the enclosing
            // impl's type, not a lexical value named Self. Its declaration is
            // that type, so it takes the enclosing-type identity beside its
            // value slot, as the `Self(..)` callee does.
            let reference = self.facts.type_slots[output.index()].site;
            self.add_type_reference_identity(node, reference);
        }
    }

    fn lower_bare_type_reference(&mut self, node: Node<'_>) {
        if self.handled_identifiers.contains(&node.id()) {
            return;
        }
        if rust_occurrence_role(node) != Some(OccurrenceRole::TypeOperand)
            || node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "scoped_identifier" | "scoped_type_identifier"
                )
            })
        {
            self.mark_unlowered_identifier_boundary(node);
            return;
        }
        let reference = self.add_identifier(
            node,
            ResolutionSiteKind::TypeReference,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
            self.current_scope(),
        );
        self.add_type_reference_identity(node, reference);
    }

    fn mark_unlowered_identifier_boundary(&mut self, node: Node<'_>) {
        if self.handled_identifiers.contains(&node.id()) {
            return;
        }
        if rust_occurrence_role(node)
            .is_some_and(|role| role.class() != OccurrenceClass::NonReference)
        {
            self.add_enumeration_gap(node, ResolutionGapKind::UnsupportedExpression);
        }
    }

    fn add_local_gap(&mut self, node: Node<'_>, kind: ResolutionGapKind) {
        let site = self.add_site(
            node,
            ResolutionSiteKind::UnsupportedExpression,
            self.current_scope(),
        );
        self.add_local_gap_at_site(site, kind);
    }

    fn add_semantic_gap(&mut self, node: Node<'_>, kind: ResolutionGapKind) {
        let site = self.add_site(
            node,
            ResolutionSiteKind::UnsupportedExpression,
            self.current_scope(),
        );
        self.add_semantic_gap_at_site(site, kind);
    }

    fn add_semantic_gap_at_site(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        self.facts.gaps.push(ResolutionGapFact { site, kind });
    }

    fn add_local_gap_at_site(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        self.facts.gaps.push(ResolutionGapFact { site, kind });
        self.facts
            .reference_enumeration_gaps
            .push(ResolutionReferenceEnumerationGapFact { site, kind });
    }

    fn add_enumeration_gap(&mut self, node: Node<'_>, kind: ResolutionGapKind) {
        self.add_enumeration_gap_in_scope(node, kind, self.current_scope());
    }

    fn add_enumeration_gap_in_scope(
        &mut self,
        node: Node<'_>,
        kind: ResolutionGapKind,
        scope: ResolutionScopeId,
    ) {
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression, scope);
        self.facts
            .reference_enumeration_gaps
            .push(ResolutionReferenceEnumerationGapFact { site, kind });
    }
}

pub(crate) fn rust_enclosing_item_generic_parameter_namespace(
    node: Node<'_>,
    source: &str,
) -> Option<ResolutionNamespace> {
    if node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) || matches!(parent.kind(), "type_parameter" | "const_parameter")
            && parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node.id())
    }) {
        return None;
    }
    let spelling = strip_raw_identifier_prefix(rust_node_text(node, source).trim());
    let mut ancestor = node.parent();
    while let Some(item) = ancestor {
        if matches!(
            item.kind(),
            "function_item"
                | "function_signature_item"
                | "struct_item"
                | "enum_item"
                | "union_item"
                | "trait_item"
                | "type_item"
                | "impl_item"
        ) {
            let parameters = item.child_by_field_name("type_parameters")?;
            let mut cursor = parameters.walk();
            return parameters
                .named_children(&mut cursor)
                .find_map(|parameter| {
                    let namespace = match (node.kind(), parameter.kind()) {
                        ("type_identifier", "type_parameter") => ResolutionNamespace::Type,
                        ("identifier", "const_parameter") => ResolutionNamespace::Value,
                        _ => return None,
                    };
                    parameter
                        .child_by_field_name("name")
                        .filter(|name| {
                            strip_raw_identifier_prefix(rust_node_text(*name, source).trim())
                                == spelling
                        })
                        .map(|_| namespace)
                });
        }
        ancestor = item.parent();
    }
    None
}

fn macro_transcriber_fragment_node<'tree>(
    tree: &'tree tree_sitter::Tree,
    fragment: &crate::macro_matcher::MacroTranscribedFragment,
) -> Option<Node<'tree>> {
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.end_byte() < fragment.start_byte || node.start_byte() > fragment.end_byte {
            continue;
        }
        if node.start_byte() == fragment.start_byte
            && node.end_byte() == fragment.end_byte
            && node.kind() == fragment.syntax_kind
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    None
}

/// Whether a qualified type path is rooted at a generic parameter of the
/// enclosing item.
///
/// `impl<T> Trait for T::Assoc` names an associated type of the parameter `T`,
/// not the `Assoc` of a module that happens to be called `T`. The head-name
/// check cannot see it, because the head it is given is the whole
/// `T::Assoc` path, and its own guard deliberately refuses to answer for a
/// segment of a qualified path. Walking to the root and asking about that is
/// the same question one level down.
fn rust_qualified_path_root_is_generic_parameter(node: Node<'_>, source: &str) -> bool {
    let mut root = node;
    while matches!(root.kind(), "scoped_type_identifier" | "scoped_identifier") {
        let Some(path) = root.child_by_field_name("path") else {
            return false;
        };
        root = path;
    }
    if root.id() == node.id() {
        return false;
    }
    let spelling = strip_raw_identifier_prefix(rust_node_text(root, source).trim());
    let mut ancestor = node.parent();
    while let Some(item) = ancestor {
        if item.kind() == "impl_item" {
            let Some(parameters) = item.child_by_field_name("type_parameters") else {
                return false;
            };
            let mut cursor = parameters.walk();
            return parameters.named_children(&mut cursor).any(|parameter| {
                parameter.kind() == "type_parameter"
                    && parameter.child_by_field_name("name").is_some_and(|name| {
                        strip_raw_identifier_prefix(rust_node_text(name, source).trim()) == spelling
                    })
            });
        }
        ancestor = item.parent();
    }
    false
}

fn rust_type_reference_is_self(node: Node<'_>, source: &str) -> bool {
    matches!(node.kind(), "type_identifier" | "identifier")
        && strip_raw_identifier_prefix(rust_node_text(node, source).trim()) == "Self"
}

/// Whether a parsed tree writes a path whose prefix is `Self`
/// (`Self::check`, `Self::Output`).
fn rust_tree_writes_self_path(tree: &tree_sitter::Tree, source: &str) -> bool {
    let mut nodes = vec![tree.root_node()];
    while let Some(node) = nodes.pop() {
        if matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier")
            && node
                .child_by_field_name("path")
                .is_some_and(|path| rust_type_reference_is_self(path, source))
        {
            return true;
        }
        let mut cursor = node.walk();
        nodes.extend(node.named_children(&mut cursor));
    }
    false
}

/// The innermost expression of a `let` initializer that produces a typed slot,
/// with the number of unwrap layers written around it.
///
/// A bare initializer is a direct call or a plain runtime identifier: both
/// publish a typed slot the zero-delta `Initialization` transfer can take as
/// its input, a call result for the first and the referenced binding's declared
/// value for the second. An unwrapped initializer also starts from one of
/// those, with the `Unwrap` transfers between them removing one unproven
/// indirection layer each.
fn rust_initializer_producer<'tree>(
    initializer: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, usize)> {
    let mut node = initializer;
    let mut unwrap_layers = 0;
    while let Some(operand) = rust_unwrap_operand(node, source) {
        unwrap_layers += 1;
        node = operand;
    }
    match node.kind() {
        // A bare identifier initializer (`let inner = outer;`) takes the
        // referenced binding's declared value type, which the runtime value
        // reference already publishes as `TargetDeclaredValueType`. Without it
        // the new binding has no declared value at all, so every later
        // `inner.member()` reports an unsupported semantic even where the
        // outer binding's type is known.
        "call_expression" | "identifier" => Some((node, unwrap_layers)),
        _ => None,
    }
}

/// The operand of one `?`, `.unwrap()` or `.expect(..)` layer.
///
/// The method forms are matched through tree-sitter fields by terminal field
/// name and by argument arity, which is what separates `Option::unwrap` from
/// `Result::unwrap_or(default)`. A workspace method of the same name and arity
/// on a type that is neither an `Option` nor a `Result` is read as an unwrap as
/// well. Its receiver then carries no unproven layer for the transfer to
/// remove, so the evaluator reports the adjustment as unrepresentable and the
/// binding stays incomplete rather than taking a wrong type. Separating the two
/// needs the receiver's resolved type, which the producer does not have.
fn rust_unwrap_operand<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if node.kind() == "try_expression" {
        // `try_expression` wraps a single unnamed-field expression child.
        return node.named_child(0);
    }
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "field_expression" {
        return None;
    }
    let field = function.child_by_field_name("field")?;
    if field.kind() != "field_identifier" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    match (
        strip_raw_identifier_prefix(rust_node_text(field, source).trim()),
        arguments.named_child_count(),
    ) {
        ("unwrap", 0) | ("expect", 1) => function.child_by_field_name("value"),
        _ => None,
    }
}

/// The call or member-chain operand under a receiver's `?`, `.unwrap()` and
/// `.expect(..)` layers, and how many layers there are.
///
/// Only those operands publish a result the layers can take once the walk
/// lowers them. Any other receiver, including one with no layer, is `None`.
fn rust_unwrapped_receiver_operand<'tree>(
    receiver: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, usize)> {
    let mut operand = receiver;
    let mut layers = 0usize;
    while let Some(inner) = rust_unwrap_operand(operand, source) {
        operand = rust_receiver_operand(inner);
        layers += 1;
    }
    (layers > 0 && matches!(operand.kind(), "field_expression" | "call_expression"))
        .then_some((operand, layers))
}

/// How a declared wrapper type's payload reaches member lookup.
enum RustProjectedPayload<'tree> {
    /// `Box<T>`, `Arc<T>` and `Rc<T>` dereference to `T`, so a receiver of one
    /// reaches `T`'s members at the pointer's own depth.
    Dereferenced(Node<'tree>),
    /// `Option<T>` and `Result<T, E>` yield `T` only through an explicit
    /// unwrap, so the payload sits behind one unproven indirection layer.
    Unwrapped(Node<'tree>),
}

/// The payload argument a `generic_type` wrapper head projects in place of the
/// head itself, when the argument has a shape `lower_declared_type_identity`
/// already understands.
///
/// These five heads are library types, so no workspace ever declares them and
/// the head reference resolves to nothing. Their payload is what a receiver of
/// that type can reach, which is why the deleted incumbent Rust graph projected
/// the same first argument and refused an un-unwrapped `Result` receiver; the
/// `Unwrap` typed transfer carries that refusal now.
///
/// The head name is read from the AST's terminal path segment, never from
/// display text of the whole path. An argument list of an unexpected arity, or
/// a first argument that is a lifetime, a const argument or a binding, leaves
/// the head unprojected so it keeps its existing treatment instead of an
/// invented payload. `Result` accepts one argument as well as two because the
/// standard single-argument aliases such as `io::Result<T>` carry the same
/// payload in the same position.
fn rust_projected_payload<'tree>(
    head: Node<'_>,
    arguments: Node<'tree>,
    source: &str,
) -> Option<RustProjectedPayload<'tree>> {
    let name = rust_nominal_head_name(head, source)?;
    let mut cursor = arguments.walk();
    let named = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    let first = *named.first()?;
    if !matches!(
        first.kind(),
        "type_identifier"
            | "identifier"
            | "primitive_type"
            | "scoped_type_identifier"
            | "scoped_identifier"
            | "qualified_type"
            | "generic_type"
            | "reference_type"
            | "pointer_type"
            | "dynamic_type"
            | "abstract_type"
            | "bounded_type"
    ) {
        return None;
    }
    match (name, named.len()) {
        ("Box" | "Arc" | "Rc", 1) => Some(RustProjectedPayload::Dereferenced(first)),
        ("Option", 1) | ("Result", 1 | 2) => Some(RustProjectedPayload::Unwrapped(first)),
        _ => None,
    }
}

/// Whether a nominal type head names a wrapper whose declared type is its
/// payload rather than the head itself.
///
/// An inherent impl written against such a head would attach its members to
/// the payload. Rust's orphan rule makes that impl impossible outside the crate
/// that declares the wrapper, so the impl target is refused as an unsupported
/// member scope rather than recorded with the wrong owner.
fn rust_head_projects_its_payload(head: Node<'_>, source: &str) -> bool {
    matches!(
        rust_nominal_head_name(head, source),
        Some("Box" | "Arc" | "Rc" | "Option" | "Result")
    )
}

/// The terminal path segment of a nominal type head, read from the AST's
/// `name` field rather than from display text of the whole path.
fn rust_nominal_head_name<'source>(head: Node<'_>, source: &'source str) -> Option<&'source str> {
    let terminal = match head.kind() {
        "type_identifier" | "identifier" => head,
        "scoped_type_identifier" | "scoped_identifier" => head.child_by_field_name("name")?,
        _ => return None,
    };
    Some(strip_raw_identifier_prefix(
        rust_node_text(terminal, source).trim(),
    ))
}

/// The projection a Rust path is rooted at, when the path has no lexical root.
///
/// `<Service as Runner>::Output` and `<Service>::Output` both spell their head
/// as a `bracketed_type`, which wraps a `qualified_type` in the first form. A
/// projection names a type or a trait, never a module, so the path cannot be
/// walked to a root and no module can be demanded for it. Nested paths below
/// the projection are followed to the same head.
fn rust_projection_path_head(node: Node<'_>) -> Option<Node<'_>> {
    let mut path = node.child_by_field_name("path")?;
    loop {
        match path.kind() {
            "bracketed_type" => return Some(path),
            "scoped_identifier" | "scoped_type_identifier" => {
                path = path.child_by_field_name("path")?;
            }
            "generic_type" => path = path.child_by_field_name("type")?,
            "generic_function" => path = path.child_by_field_name("function")?,
            _ => return None,
        }
    }
}

fn rust_qualified_type_path(path: Node<'_>) -> Option<Node<'_>> {
    if path.kind() == "qualified_type" {
        return Some(path);
    }
    if path.kind() != "bracketed_type" {
        return None;
    }
    let mut cursor = path.walk();
    path.named_children(&mut cursor)
        .find(|child| child.kind() == "qualified_type")
}

fn rust_is_supported_inherent_impl_target(mut node: Node<'_>, source: &str) -> bool {
    while node.kind() == "generic_type" {
        // A wrapper head projects its payload as the declared type, so an impl
        // written against one would attach its members to the payload rather
        // than to the wrapper. Rust's orphan rule makes such an impl impossible
        // outside the crate that declares the wrapper; refuse it as an
        // unsupported member scope rather than record the wrong owner.
        if rust_head_projects_its_payload(
            node.child_by_field_name("type")
                .expect("Rust generic_type has a type field"),
            source,
        ) {
            return false;
        }
        node = node
            .child_by_field_name("type")
            .expect("Rust generic_type has a type field");
    }
    matches!(
        node.kind(),
        "type_identifier" | "identifier" | "scoped_type_identifier" | "scoped_identifier"
    ) || rust_is_unmodelled_primitive_spelling(node, source)
}

/// A `primitive_type` node whose spelling the builtin table does not model.
/// The grammar parses `f16` and `f128` as primitives, but they are unstable
/// builtins, and rustc consults the builtin types only after items and
/// imports in the type namespace. Such a node is therefore an ordinary type
/// name: `use half::f16;` or `pub struct f16;` binds it, and `impl f16` is an
/// inherent impl of that item.
fn rust_is_unmodelled_primitive_spelling(node: Node<'_>, source: &str) -> bool {
    node.kind() == "primitive_type" && rust_primitive_type_spelling(node, source).is_none()
}

fn rust_has_standard_self_parameter(parameters: Node<'_>) -> bool {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .any(|parameter| parameter.kind() == "self_parameter")
}

/// The number of ordinary (non-receiver) parameters a callable-parameter row
/// can state, or `None` when the list has a shape the rows cannot state.
///
/// A row names one declaration: an identifier pattern or `_`, with a type. A
/// destructuring pattern, a parameter attribute (`#[cfg]` can remove the
/// parameter), a C variadic, an anonymous parameter type, and malformed syntax
/// leave the inventory open.
fn rust_modeled_ordinary_parameter_count(parameters: Node<'_>) -> Option<usize> {
    let mut count = 0;
    let mut cursor = parameters.walk();
    for child in parameters.children(&mut cursor) {
        if child.is_extra() || matches!(child.kind(), "(" | ")" | ",") {
            continue;
        }
        if child.has_error() {
            return None;
        }
        match child.kind() {
            "self_parameter" => {}
            "parameter" => {
                let pattern = child.child_by_field_name("pattern")?;
                match pattern.kind() {
                    "self" => {}
                    "identifier" | "_" => {
                        child.child_by_field_name("type")?;
                        count += 1;
                    }
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    Some(count)
}

/// The spelling of a primitive type, or `None` for any other type syntax.
fn rust_primitive_type_spelling<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let spelling = rust_node_text(node, source).trim();
    matches!(
        spelling,
        "bool"
            | "char"
            | "str"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "f32"
            | "f64"
    )
    .then_some(spelling)
}

/// How a parameter list's standard receiver is taken: `self` and `mut self`
/// by value, `&self` (with or without a lifetime) by reference, `&mut self` by
/// mutable reference. A typed receiver (`self: Box<Self>`) and a list with no
/// receiver have no standard form.
fn rust_receiver_form(parameters: Node<'_>) -> Option<ResolutionCallableReceiverForm> {
    let mut cursor = parameters.walk();
    let receiver = parameters
        .named_children(&mut cursor)
        .find(|parameter| parameter.kind() == "self_parameter")?;
    let mut cursor = receiver.walk();
    let tokens = receiver
        .children(&mut cursor)
        .map(|child| child.kind())
        .collect::<Vec<_>>();
    Some(
        match (tokens.contains(&"&"), tokens.contains(&"mutable_specifier")) {
            (false, _) => ResolutionCallableReceiverForm::Value,
            (true, false) => ResolutionCallableReceiverForm::Reference,
            (true, true) => ResolutionCallableReceiverForm::MutableReference,
        },
    )
}

/// What a literal token fixes about its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustLiteralType {
    /// A primitive, behind this many reference layers (`"x"` is `&str`).
    Exact {
        primitive: &'static str,
        reference_layers: i8,
    },
    /// An unsuffixed integer or float: inference picks its type.
    InferredNumeric,
    /// A literal kind the model has no type for, such as a byte string.
    Unsupported,
}

/// The type a literal's own token fixes, or `None` for a non-literal.
///
/// tree-sitter keeps a literal's suffix and prefix inside its one token, so
/// they are read from the token's spelling against Rust's fixed vocabularies,
/// as the Java producer reads an integer literal's `L`. A hexadecimal integer
/// takes no float suffix: `0x1f32` is an unsuffixed integer whose digits end
/// in `f32`.
fn rust_literal_type(node: Node<'_>, source: &str) -> Option<RustLiteralType> {
    const INTEGER_SUFFIXES: [&str; 12] = [
        "u128", "usize", "u16", "u32", "u64", "u8", "i128", "isize", "i16", "i32", "i64", "i8",
    ];
    const FLOAT_SUFFIXES: [&str; 2] = ["f32", "f64"];
    let token = rust_node_text(node, source);
    let exact = |primitive, reference_layers| RustLiteralType::Exact {
        primitive,
        reference_layers,
    };
    let suffixed = |suffixes: &[&'static str]| {
        suffixes
            .iter()
            .copied()
            .find(|suffix| token.ends_with(suffix))
            .map_or(RustLiteralType::InferredNumeric, |suffix| exact(suffix, 0))
    };
    Some(match node.kind() {
        "boolean_literal" => exact("bool", 0),
        "char_literal" if token.starts_with('\'') => exact("char", 0),
        "string_literal" | "raw_string_literal"
            if token.starts_with('"') || token.starts_with('r') =>
        {
            exact("str", 1)
        }
        "char_literal" | "string_literal" | "raw_string_literal" => RustLiteralType::Unsupported,
        "integer_literal" if token.starts_with("0x") || token.starts_with("0X") => {
            suffixed(&INTEGER_SUFFIXES)
        }
        "integer_literal" => {
            let suffixes = INTEGER_SUFFIXES
                .iter()
                .chain(&FLOAT_SUFFIXES)
                .copied()
                .collect::<Vec<_>>();
            suffixed(&suffixes)
        }
        "float_literal" => suffixed(&FLOAT_SUFFIXES),
        _ => return None,
    })
}

/// Whether an argument list carries an attribute, which can remove the
/// argument it annotates.
fn rust_arguments_carry_attributes(arguments: Node<'_>) -> bool {
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .any(|argument| crate::syntax::outer_attributes(argument).next().is_some())
}

fn rust_self_parameter_name(parameter: Node<'_>) -> Option<Node<'_>> {
    debug_assert_eq!(parameter.kind(), "self_parameter");
    let mut cursor = parameter.walk();
    parameter
        .children(&mut cursor)
        .find(|child| child.kind() == "self")
}

fn rust_is_unit_type(node: Node<'_>) -> bool {
    node.kind() == "unit_type" || (node.kind() == "tuple_type" && node.named_child_count() == 0)
}

fn rust_explicit_type_argument_count(function: Node<'_>) -> Option<u32> {
    let mut current = function;
    let mut count = 0u32;
    while current.kind() == "generic_function" {
        let type_arguments = current.child_by_field_name("type_arguments")?;
        let argument_count = u32::try_from(type_arguments.named_child_count())
            .expect("Rust explicit type argument count exceeds u32");
        count = count
            .checked_add(argument_count)
            .expect("Rust explicit type argument count exceeds u32");
        current = current.child_by_field_name("function")?;
    }
    Some(count)
}

fn rust_node_can_carry_item_attributes(kind: &str) -> bool {
    matches!(
        kind,
        "associated_type"
            | "const_item"
            | "enum_item"
            | "foreign_mod_item"
            | "function_item"
            | "function_signature_item"
            | "impl_item"
            | "macro_definition"
            | "mod_item"
            | "struct_item"
            | "static_item"
            | "trait_item"
            | "type_item"
            | "union_item"
            | "use_declaration"
    )
}

/// Whether a path segment is one of Rust's module anchors.
///
/// `crate`, `self` and `super` have their own grammar node kinds in head
/// position; a repeated `super` is spelled in the segment's `name` field and
/// keeps the same kind.
fn rust_path_anchor_keyword(kind: &str) -> bool {
    matches!(kind, "crate" | "self" | "super")
}

/// Whether a statement list declares an item.
///
/// Rust items are the block members that other items in the same block can
/// name, so their presence is what makes the block's item scope necessary.
/// They are direct children of the statement list, which is why this reads
/// only those.
fn rust_block_declares_items(statements: Node<'_>) -> bool {
    if statements.kind() != "block" {
        return false;
    }
    let mut cursor = statements.walk();
    statements
        .named_children(&mut cursor)
        .any(|child| rust_item_requires_parser_unit(child.kind()))
}

fn rust_item_requires_parser_unit(kind: &str) -> bool {
    matches!(
        kind,
        "const_item"
            | "enum_item"
            | "extern_crate_declaration"
            | "function_item"
            | "function_signature_item"
            | "macro_definition"
            | "mod_item"
            | "static_item"
            | "struct_item"
            | "trait_item"
            | "type_item"
            | "union_item"
    )
}

/// Classify built-in attributes and registered derive helper attributes.
///
/// A scoped or otherwise unknown attribute may be a procedural macro and can
/// replace its input item. Treating such an item as an ordinary declaration
/// would be a false affirmative. Derives cannot replace the input declaration,
/// but they can add an unbounded generated surface, so they retain the source
/// item while opening reference enumeration around it.
fn rust_item_attribute_boundary(node: Node<'_>, source: &str) -> RustItemAttributeBoundary {
    let mut boundary = RustItemAttributeBoundary::SourcePreserving;
    let mut conditional = false;
    for attribute_item in crate::syntax::outer_attributes(node) {
        let Some(attribute) = attribute_item.named_child(0) else {
            return RustItemAttributeBoundary::Transforming;
        };
        let Some(path) = attribute.named_child(0) else {
            return RustItemAttributeBoundary::Transforming;
        };
        if rust_tool_attribute_path(path, source) {
            // `#[rustfmt::skip]`, `#[clippy::..]`, `#[diagnostic::..]` name a
            // tool rustc registers; tool attributes are inert and never
            // replace the item.
            continue;
        }
        if path.kind() != "identifier" {
            return RustItemAttributeBoundary::Transforming;
        }
        match rust_node_text(path, source).trim() {
            // Module macro visibility is already retained by Cargo route
            // facts. The built-in attribute does not replace the source body.
            "macro_use" if node.kind() == "mod_item" => {}
            // Rust's unsafe attribute wrapper contains a built-in codegen
            // attribute, not a procedural macro that can replace this item.
            "unsafe"
                if attribute
                    .child_by_field_name("arguments")
                    .and_then(|arguments| arguments.named_child(0))
                    .is_some_and(|inner| {
                        inner.kind() == "identifier"
                            && matches!(rust_node_text(inner, source),
                                "no_mangle" | "export_name" | "link_section" | "naked")
                    }) => {}
            "derive" => boundary = RustItemAttributeBoundary::GeneratedSurface,
            "serde" => {
                if rust_item_has_serde_derive(node, source) {
                    boundary = RustItemAttributeBoundary::GeneratedSurface;
                } else if rust_item_serde_helper_derive(node, source).is_some() {
                    conditional = true;
                    boundary = RustItemAttributeBoundary::GeneratedSurface;
                } else {
                    return RustItemAttributeBoundary::Transforming;
                }
            }
            "cfg" => {
                debug_assert_ne!(
                    rust_cfg_condition(node, source),
                    RustCfgCondition::Always,
                    "a cfg-owned Rust item is handled before attribute boundaries"
                );
            }
            "allow"
            | "warn"
            | "deny"
            | "forbid"
            | "expect"
            | "doc"
            | "repr"
            | "deprecated"
            | "must_use"
            | "inline"
            | "cold"
            | "track_caller"
            | "target_feature"
            | "no_mangle"
            | "export_name"
            | "link_name"
            | "link"
            | "link_section"
            | "used"
            | "non_exhaustive"
            | "path"
            | "macro_export"
            | "automatically_derived"
            | "global_allocator"
            | "panic_handler"
            | "alloc_error_handler"
            // The three procedural-macro entry-point attributes are built in.
            // They mark the function as a macro the crate publishes; they do
            // not replace it, and the body below them is the body rustc
            // compiles. Treating them as unknown skipped the declaration, so a
            // proc-macro crate exported nothing at all and
            // `rocket_codegen::routes` was a name no crate row carried.
            | "proc_macro"
            | "proc_macro_attribute"
            | "proc_macro_derive"
            // Test-harness controls are inert: they do not replace the body.
            | "ignore"
            | "should_panic"
            | "test" => {}
            _ => return RustItemAttributeBoundary::Transforming,
        }
    }
    if conditional {
        RustItemAttributeBoundary::ConditionalSerdeHelper
    } else {
        boundary
    }
}

/// Whether an attribute path is scoped under one of the tools rustc
/// registers (`rustfmt`, `clippy`, `diagnostic`), read from the path's
/// root segment.
fn rust_tool_attribute_path(path: Node<'_>, source: &str) -> bool {
    if path.kind() != "scoped_identifier" {
        return false;
    }
    let mut root = path;
    while root.kind() == "scoped_identifier" {
        let Some(inner) = root.child_by_field_name("path") else {
            return false;
        };
        root = inner;
    }
    root.kind() == "identifier"
        && matches!(
            rust_node_text(root, source),
            "rustfmt" | "clippy" | "diagnostic"
        )
}

/// Whether the item's containing scope declares, aliases or imports `name`.
fn rust_item_scope_binds(node: Node<'_>, source: &str, name: &str) -> bool {
    let parent = crate::syntax::parent_outside_attributes(node)
        .expect("attributed items have a containing scope");
    let mut cursor = parent.walk();
    parent.named_children(&mut cursor).any(|sibling| {
        let sibling = crate::syntax::unwrap_attributes(sibling);
        sibling
            .child_by_field_name("name")
            .is_some_and(|declared| rust_node_text(declared, source) == name)
            || sibling
                .child_by_field_name("alias")
                .is_some_and(|alias| rust_node_text(alias, source) == name)
            || (sibling.kind() == "use_declaration"
                && crate::imports::rust_imports_from_use_declaration(sibling, source)
                    .iter()
                    .any(|import| import.local_name() == Some(name)))
    })
}

/// The derive a struct's or enum's `#[serde(..)]` helper depends on when the
/// file cannot prove it (`rust_item_has_serde_derive` failed): the item
/// derives a bare `Serialize` or `Deserialize` whose binding the file does
/// not show to be serde's. The name arrives through a glob, an enclosing
/// module's import, or an import in the scope whose path is not
/// `serde::<name>`, and only the crate's rows can say whether it is serde's
/// derive. `serde` itself must not be rebound in the scope. `Serialize` is
/// preferred when both are derived; either one registers the helper.
pub(crate) fn rust_item_serde_helper_derive(
    node: Node<'_>,
    source: &str,
) -> Option<brokk_bifrost_core::analyzer::rust_facts::RustSerdeDerive> {
    use brokk_bifrost_core::analyzer::rust_facts::RustSerdeDerive;
    if !matches!(node.kind(), "enum_item" | "struct_item") {
        return None;
    }
    let mut has_helper = false;
    let mut derives = Vec::new();
    for item in crate::syntax::outer_attributes(node) {
        let Some(attribute) = item.named_child(0) else {
            continue;
        };
        let Some(name) = attribute.named_child(0) else {
            continue;
        };
        if name.kind() != "identifier" {
            continue;
        }
        match rust_node_text(name, source) {
            "serde" => has_helper = true,
            "derive" => {
                let Some(arguments) = attribute.child_by_field_name("arguments") else {
                    continue;
                };
                let mut cursor = arguments.walk();
                let tokens = arguments
                    .children(&mut cursor)
                    .filter(|token| {
                        !matches!(token.kind(), "(" | ")" | "line_comment" | "block_comment")
                    })
                    .collect::<Vec<_>>();
                for path in tokens.split(|token| token.kind() == ",") {
                    if let [derive] = path
                        && derive.kind() == "identifier"
                        && let Some(derive) =
                            RustSerdeDerive::from_name(rust_node_text(*derive, source))
                    {
                        derives.push(derive);
                    }
                }
            }
            _ => {}
        }
    }
    if !has_helper
        || rust_item_has_serde_derive(node, source)
        || rust_item_scope_binds(node, source, "serde")
    {
        return None;
    }
    derives
        .iter()
        .copied()
        .find(|derive| *derive == RustSerdeDerive::Serialize)
        .or_else(|| derives.first().copied())
}

/// Serde's Serialize and Deserialize derives register `serde` as an inert
/// helper. A helper does not replace the source item; the derive's generated
/// surface remains incomplete. An unrelated derive or a standalone attribute
/// does not establish this contract.
fn rust_item_has_serde_derive(node: Node<'_>, source: &str) -> bool {
    if !matches!(node.kind(), "enum_item" | "struct_item") {
        return false;
    }
    if rust_item_scope_binds(node, source, "serde") {
        return false;
    }
    for item in crate::syntax::outer_attributes(node) {
        let Some(attribute) = item.named_child(0) else {
            continue;
        };
        let Some(name) = attribute.named_child(0) else {
            continue;
        };
        if name.kind() != "identifier" || rust_node_text(name, source) != "derive" {
            continue;
        }
        let Some(arguments) = attribute.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        let tokens = arguments
            .children(&mut cursor)
            .filter(|token| !matches!(token.kind(), "(" | ")" | "line_comment" | "block_comment"))
            .collect::<Vec<_>>();
        for path in tokens.split(|token| token.kind() == ",") {
            match path {
                [namespace, separator, derive]
                    if namespace.kind() == "identifier"
                        && rust_node_text(*namespace, source) == "serde"
                        && separator.kind() == "::"
                        && derive.kind() == "identifier"
                        && matches!(
                            rust_node_text(*derive, source),
                            "Serialize" | "Deserialize"
                        ) =>
                {
                    return true;
                }
                [derive] if derive.kind() == "identifier" => {
                    let Some(parent) = crate::syntax::parent_outside_attributes(node) else {
                        continue;
                    };
                    let mut cursor = parent.walk();
                    for import in parent.named_children(&mut cursor) {
                        let import = crate::syntax::unwrap_attributes(import);
                        if import.kind() != "use_declaration"
                            || rust_cfg_condition(import, source) != RustCfgCondition::Always
                        {
                            continue;
                        }
                        for projected in
                            crate::imports::rust_imports_from_use_declaration(import, source)
                        {
                            if projected.local_name() != Some(rust_node_text(*derive, source)) {
                                continue;
                            }
                            let path = &projected
                                .path
                                .expect("Rust imports have structured paths")
                                .segments;
                            if matches!(path.as_slice(), [namespace, name] if namespace == "serde" && matches!(name.as_str(), "Serialize" | "Deserialize"))
                            {
                                return true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    false
}

/// The `impl_item` or `trait_item` whose body declares `node` as a member.
///
/// Membership is the parent relation, not an ancestor relation. The grammar
/// puts every member, possibly inside an attribute wrapper, in the
/// `declaration_list` that is the `impl_item`'s or `trait_item`'s `body` field,
/// so an item written anywhere
/// deeper is an ordinary item in whatever scope encloses it. `impl Service { fn
/// run(&self) { const RETRIES: u32 = 3; fn helper() {} } }` declares `RETRIES`
/// and `helper` in the method's block, where they are block-local items with
/// lexical binders, not associated items of `Service`.
fn rust_trait_or_impl_member_owner(node: Node<'_>) -> Option<Node<'_>> {
    let list = crate::syntax::parent_outside_attributes(node)?;
    if list.kind() != "declaration_list" {
        return None;
    }
    let owner = list.parent()?;
    matches!(owner.kind(), "impl_item" | "trait_item").then_some(owner)
}

fn rust_scope_is_in_module(
    scopes: &[ResolutionScopeFact],
    module_scope: ResolutionScopeId,
    mut scope: ResolutionScopeId,
) -> bool {
    loop {
        if scope == module_scope {
            return true;
        }
        let current = scopes[scope.index()];
        if current.kind == ResolutionScopeKind::Package {
            return false;
        }
        let Some(parent) = current.parent else {
            return false;
        };
        scope = parent;
    }
}

fn validate_rust_resolution_facts(facts: &FileResolutionFacts) {
    assert!(!facts.scopes.is_empty());
    for (index, name) in facts.names.iter().enumerate() {
        assert_eq!(name.id.index(), index);
        assert!(!name.spelling.is_empty());
    }
    for (index, scope) in facts.scopes.iter().enumerate() {
        assert_eq!(scope.id.index(), index);
        assert!(scope.start_byte <= scope.end_byte);
        if let Some(parent) = scope.parent {
            assert!(parent.index() < index);
            let parent = facts.scopes[parent.index()];
            assert!(parent.start_byte <= scope.start_byte);
            assert!(scope.end_byte <= parent.end_byte);
        } else {
            assert_eq!(index, 0);
            assert_eq!(scope.kind, ResolutionScopeKind::CompilationUnit);
        }
    }
    for (index, site) in facts.sites.iter().enumerate() {
        assert_eq!(site.id.index(), index);
        let scope = facts.scopes[site.scope.index()];
        assert!(scope.start_byte <= site.start_byte);
        assert!(site.end_byte <= scope.end_byte);
    }
    for identifier in &facts.identifiers {
        assert!(identifier.site.index() < facts.sites.len());
        assert!(identifier.name.index() < facts.names.len());
        if let Some(qualifier) = identifier.qualifier {
            assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
            let slot = facts
                .type_slots
                .get(qualifier.index())
                .expect("qualified Rust reference slot");
            assert_eq!(slot.id, qualifier);
            assert_eq!(slot.site, identifier.site);
            assert_eq!(slot.role, ResolutionTypeSlotRole::Receiver);
        }
    }
    for (index, slot) in facts.type_slots.iter().enumerate() {
        assert_eq!(slot.id.index(), index);
        assert!(slot.site.index() < facts.sites.len());
    }
    let mut identifier_roles_by_site = vec![None; facts.sites.len()];
    for identifier in &facts.identifiers {
        identifier_roles_by_site[identifier.site.index()] = Some(identifier.role);
    }
    for projection in &facts.binding_projections {
        assert!(projection.reference.index() < facts.sites.len());
        assert!(projection.output.index() < facts.type_slots.len());
        assert_eq!(
            identifier_roles_by_site[projection.reference.index()],
            Some(ResolutionIdentifierRole::Reference)
        );
        if projection.kind == BindingProjectionKind::TargetTypeIdentity {
            assert_eq!(
                facts.type_slots[projection.output.index()].role,
                ResolutionTypeSlotRole::TargetTypeIdentity
            );
        }
    }
    // An unqualified type reference with no binding projection is the shape a
    // point query reads as "no absence was proved". `Self` inside an impl is
    // the only Rust occurrence with that shape: a frontier has exactly one
    // output producer, so taking the enclosing owner's `TypeIdentity` transfer
    // means the occurrence carries no binding projection at all, and a point
    // query then sees neither a lookup target nor a root projection. The native
    // definition adapter keys its abstention on those two site facts, so keep
    // the equivalence enforced here rather than letting the two drift.
    let mut projected_by_site = vec![false; facts.sites.len()];
    for projection in &facts.binding_projections {
        projected_by_site[projection.reference.index()] = true;
    }
    let mut transfer_output_by_site = vec![false; facts.sites.len()];
    for transfer in &facts.type_transfers {
        transfer_output_by_site[facts.type_slots[transfer.output.index()].site.index()] = true;
    }
    let mut root_reference_by_site = vec![false; facts.sites.len()];
    for reference in &facts.root_references {
        root_reference_by_site[reference.reference.index()] = true;
    }
    let mut gap_by_site = vec![false; facts.sites.len()];
    for gap in &facts.gaps {
        gap_by_site[gap.site.index()] = true;
    }
    for identifier in &facts.identifiers {
        let site = identifier.site.index();
        if identifier.role != ResolutionIdentifierRole::Reference
            || facts.sites[site].kind != ResolutionSiteKind::TypeReference
            || identifier.qualifier.is_some()
            || root_reference_by_site[site]
            || projected_by_site[site]
        {
            continue;
        }
        assert!(
            transfer_output_by_site[site] || gap_by_site[site],
            "an unqualified Rust type reference without a binding projection takes its type \
             identity from a transfer or records a gap: {identifier:?} at {:?}",
            facts.sites[site]
        );
    }
    for (index, relation) in facts.declared_type_relations.iter().enumerate() {
        assert_eq!(relation.id.index(), index);
        assert!(relation.subject.index() < facts.type_slots.len());
        let inherent = relation.kind == ResolutionDeclaredTypeRelationKind::InherentImplementation;
        assert_eq!(relation.target_reference.is_none(), inherent);
        assert_eq!(relation.target.is_none(), inherent);
        if let Some(target) = relation.target {
            assert!(target.index() < facts.type_slots.len());
            assert_eq!(
                facts.type_slots[target.index()].site,
                relation.target_reference.unwrap()
            );
        }
    }
    for member in &facts.relation_members {
        assert!(member.relation.index() < facts.declared_type_relations.len());
        assert!(member.member.index() < facts.sites.len());
    }
    for owner in &facts.deferred_member_owners {
        assert!(owner.member.index() < facts.sites.len());
        assert!(owner.owner_type.index() < facts.type_slots.len());
        let expected = match owner.kind {
            ResolutionMemberKind::Method => ResolutionSiteKind::CallableDeclaration,
            ResolutionMemberKind::AssociatedType => ResolutionSiteKind::TypeAliasDeclaration,
            // An associated constant. Rust has no deferred instance field:
            // a struct's fields belong to its own type body scope.
            ResolutionMemberKind::Field => ResolutionSiteKind::ValueDeclaration,
            _ => panic!("unsupported deferred Rust member kind: {:?}", owner.kind),
        };
        assert_eq!(facts.sites[owner.member.index()].kind, expected);
    }
    for binder in &facts.binders {
        assert!(binder.declaration.index() < facts.sites.len());
        let scope = facts.scopes[binder.scope.index()];
        assert!(scope.start_byte <= binder.activation_start);
        assert!(binder.activation_start <= binder.activation_end);
        assert!(binder.activation_end <= scope.end_byte);
    }
    for owner in &facts.reference_owners {
        assert!(owner.reference.index() < facts.sites.len());
        if let Some(declaration) = owner.owner {
            assert!(declaration.index() < facts.sites.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionDeclaredTypeRelationKind;
    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionKind, DeclarationTypeRole, FileResolutionFacts, IntrinsicTypeKind,
        ResolutionBinderKind, ResolutionCallableReceiverForm, ResolutionCallableReceiverOrigin,
        ResolutionGapKind, ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
        ResolutionMemberQualifierCompatibility, ResolutionNamespace, ResolutionRootImportAnchor,
        ResolutionRootImportDemandTarget, ResolutionRootImportKind, ResolutionScopeId,
        ResolutionScopeKind, ResolutionSiteId, ResolutionSiteKind, ResolutionTypeSlotId,
        ResolutionTypeSlotRole, ResolutionTypeTransferFact, ResolutionTypeTransferKind,
        ResolutionTypeTransferValueTransform,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, HoistingClass};
    use tree_sitter::Parser;

    use super::extract_rust_resolution_facts;

    /// Every member receiver slot has a producer or a gap on its own site.
    /// A receiver no identifier or call produces (an index, a literal, a
    /// `?`) used to leave its slot with neither, and the evaluator reported
    /// `missing-slot-producer` for it (the point-answer census, 2026-09-24:
    /// 16,492 tract and 57,281 Bifrost answers).
    /// A prelude fall-through is published only for a site no other root
    /// reference claims, so every site keeps one root reference row whatever
    /// path form writes the prelude name.
    #[test]
    fn a_prelude_name_keeps_one_root_reference_per_site() {
        let source = "use std::vec::Vec as V;\nmod m { pub struct Vec; }\nfn f() {\n    let a = ::std::vec::Vec::<u8>::new();\n    let b = Vec::<u8>::new();\n    let c = std::option::Option::Some(1);\n    let d: ::core::option::Option<u8> = None;\n    let e = crate::m::Vec;\n    let g = <Vec<u8>>::new();\n    let h = Some(Vec::<u8>::new());\n}\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let mut sites = std::collections::HashSet::new();
        for root in &facts.root_references {
            assert!(
                sites.insert(root.reference),
                "{root:?} duplicates a root reference"
            );
        }
        assert!(
            facts.root_references.iter().any(|root| {
                root.prefix_reference.is_none()
                    && root.anchor == ResolutionRootImportAnchor::Lexical
                    && !facts
                        .root_reference_segments
                        .iter()
                        .any(|segment| segment.reference == root.reference)
            }),
            "a bare prelude name falls through: {:?}",
            facts.root_references
        );
    }

    #[test]
    fn divan_bench_attribute_arguments_keep_their_source_reference() {
        let source = r#"
const NUM_ENTRIES: usize = 10;

mod parser {
    use crate::NUM_ENTRIES;

    #[divan::bench(args = NUM_ENTRIES)]
    fn bench() {}
}
"#;
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let start = source.rfind("NUM_ENTRIES").expect("bench argument");
        let argument = reference_sites(&facts, "NUM_ENTRIES", ResolutionNamespace::Value)
            .into_iter()
            .find(|site| facts.sites[site.index()].start_byte == start)
            .expect("the attribute expression is a value reference");
        assert!(!facts.gaps.iter().any(|gap| gap.site == argument));
    }

    #[test]
    fn definitionless_matches_pattern_keeps_variant_references() {
        let source =
            "enum State { Ready }\nfn run(value: State) { assert!(matches!(value, Ready)); }\n";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let ready_start = source.rfind("Ready").expect("pattern variant");
        assert!(
            reference_sites(&facts, "Ready", ResolutionNamespace::Value)
                .into_iter()
                .any(|site| facts.sites[site.index()].start_byte == ready_start),
            "an unindexed matches! invocation retains the legacy argument reference: {facts:#?}"
        );

        let source = r#"
enum ParseState { Start { id: u8 } }
use ParseState::*;
fn run(state: ParseState) { let _ = matches!(state, Start { .. }); }
"#;
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let pattern_start = source.find("Start { .. }").expect("struct variant pattern");
        let pattern_reference = facts.identifiers.iter().find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "Start"
                && facts.sites[identifier.site.index()].start_byte == pattern_start
        });
        assert!(
            pattern_reference.is_some(),
            "an unindexed matches! struct pattern remains a positioned reference: {facts:#?}"
        );
        assert!(
            facts.gaps.iter().all(|gap| {
                let site = facts.sites[gap.site.index()];
                site.start_byte != pattern_start || gap.kind != ResolutionGapKind::MalformedSyntax
            }),
            "a parsed matches! pattern must not retain a syntax gap: {facts:#?}"
        );
    }

    #[test]
    fn every_member_receiver_slot_has_a_producer_or_a_gap() {
        for source in [
            "fn f(s: S) { s.ts[0].b(); }",
            "fn f(s: S) { s.ts[0].field; }",
            "fn f(s: S) -> Result<(), ()> { s.maybe()?.b(); Ok(()) }",
            "fn f(s: S) -> Result<(), ()> { s.maybe()?.field; Ok(()) }",
            "fn f(x: Option<u8>) -> Option<()> { x?.b(); None }",
            "fn f() { \"abc\".len(); 1.to_string(); }",
            "fn f(s: S) { assert_eq!(s.ts[0].b(), 1); }",
            "fn f(s: S) { (s.ts[0]).b(); }",
        ] {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .expect("set Rust grammar");
            let tree = parser.parse(source, None).expect("parse fixture");
            let facts = extract_rust_resolution_facts(tree.root_node(), source);
            for slot in facts
                .type_slots
                .iter()
                .filter(|slot| slot.role == ResolutionTypeSlotRole::Receiver)
            {
                let produced = facts.type_transfers.iter().any(|t| t.output == slot.id)
                    || facts
                        .binding_projections
                        .iter()
                        .any(|p| p.output == slot.id)
                    || facts
                        .intrinsic_type_seeds
                        .iter()
                        .any(|seed| seed.output == slot.id);
                // The callee's applicability gap shares the member's site and
                // says nothing about the receiver's value.
                let gapped = facts.gaps.iter().any(|gap| {
                    gap.site == slot.site
                        && gap.kind != ResolutionGapKind::UnsupportedCallApplicability
                });
                assert!(
                    produced || gapped,
                    "{source}: {slot:?} has neither a producer nor a gap"
                );
            }
        }
    }

    #[test]
    fn unnamed_import_retains_target_without_a_lexical_binding() {
        let source = "use crate::ast::Node as _;";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse unnamed import");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(facts.root_import_demands.is_empty(), "{facts:#?}");
        assert!(facts.root_import_demand_targets.is_empty(), "{facts:#?}");
        let targets = facts
            .identifiers
            .iter()
            .map(|identifier| {
                assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
                (
                    facts.names[identifier.name.index()].spelling.as_str(),
                    identifier.namespace,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            targets,
            BTreeSet::from([
                ("ast", ResolutionNamespace::Type),
                ("crate", ResolutionNamespace::Type),
                ("Node", ResolutionNamespace::Type),
                ("Node", ResolutionNamespace::Value),
                ("Node", ResolutionNamespace::Macro),
            ])
        );
        assert!(facts.gaps.is_empty(), "{facts:#?}");
        assert!(facts.reference_enumeration_gaps.is_empty(), "{facts:#?}");
    }

    #[test]
    fn a_local_named_import_does_not_suppress_another_scopes_glob() {
        let source = "use crate::model::*; fn local() { use crate::other::Item; } fn outside() { let _: Item; }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let glob = facts
            .root_import_kinds
            .iter()
            .find(|row| row.kind == ResolutionRootImportKind::Glob)
            .unwrap()
            .import_site;
        assert!(
            facts
                .root_import_demands
                .iter()
                .any(|row| row.import_site == glob
                    && row.namespace == ResolutionNamespace::Type
                    && facts.names[row.name.index()].spelling == "Item"),
            "{facts:#?}"
        );
    }

    fn source_text<'source>(
        facts: &FileResolutionFacts,
        source: &'source str,
        site: ResolutionSiteId,
    ) -> &'source str {
        let site = facts.sites[site.index()];
        &source[site.start_byte..site.end_byte]
    }

    fn gap_inventory<'source>(
        facts: &FileResolutionFacts,
        source: &'source str,
    ) -> Vec<(&'source str, ResolutionGapKind)> {
        let mut gaps = facts
            .gaps
            .iter()
            .map(|gap| {
                let site = facts.sites[gap.site.index()];
                (
                    &source[site.start_byte..site.end_byte],
                    gap.kind,
                    site.start_byte,
                    site.end_byte,
                )
            })
            .collect::<Vec<_>>();
        gaps.sort_by_key(|(_, kind, start_byte, end_byte)| (*start_byte, *end_byte, *kind));
        gaps.into_iter()
            .map(|(spelling, kind, _, _)| (spelling, kind))
            .collect()
    }

    fn enumeration_gap_inventory<'source>(
        facts: &FileResolutionFacts,
        source: &'source str,
    ) -> Vec<(&'source str, ResolutionGapKind)> {
        let mut gaps = facts
            .reference_enumeration_gaps
            .iter()
            .map(|gap| {
                let site = facts.sites[gap.site.index()];
                (
                    &source[site.start_byte..site.end_byte],
                    gap.kind,
                    site.start_byte,
                    site.end_byte,
                )
            })
            .collect::<Vec<_>>();
        gaps.sort_by_key(|(_, kind, start_byte, end_byte)| (*start_byte, *end_byte, *kind));
        gaps.into_iter()
            .map(|(spelling, kind, _, _)| (spelling, kind))
            .collect()
    }

    #[test]
    fn computed_receivers_keep_reference_enumeration_complete() {
        // A member on an index, cast, deref or block receiver is still
        // published; only its receiver type is unknown. That is a point gap on
        // the member, not an enumeration gap (#3764: tract's
        // `inputs[0].datum_type.fact(..)` made every graph over the file
        // report ReferenceEnumerationIncomplete).
        let declarations = "struct F { d: D } struct D; impl D { fn fact(&self) {} }";
        for (body, member) in [
            ("fn f(inputs: &[F]) { inputs[0].d; }", "d"),
            ("fn f(inputs: &[F]) { inputs[0].d.fact(); }", "d"),
            ("fn f(inputs: &[F]) { inputs[0].fact(); }", "fact"),
            ("fn f(x: u8) { (x as F).fact(); }", "fact"),
            ("fn f(x: &F) { (*x).fact(); }", "fact"),
            ("fn f(a: F) { { a }.fact(); }", "fact"),
        ] {
            let source = format!("{declarations} {body}");
            let source = source.as_str();
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let facts = extract_rust_resolution_facts(tree.root_node(), source);
            assert!(
                facts.reference_enumeration_gaps.is_empty(),
                "{body}: {:?}",
                enumeration_gap_inventory(&facts, source)
            );
            let site = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == member
                })
                .unwrap_or_else(|| panic!("{body}: {member} is published as a reference"))
                .site;
            assert!(
                facts
                    .gaps
                    .iter()
                    .any(|gap| gap.site == site
                        && gap.kind == ResolutionGapKind::UnsupportedExpression),
                "{body}: {member} carries its receiver's point gap: {:?}",
                facts.gaps
            );
        }
    }

    #[test]
    fn macro_use_modules_retain_their_source_body_references() {
        let source = "fn target() {} #[macro_use] mod helpers { fn run() { super::target(); } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(
                    |identifier| identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "target"
                )
                .count(),
            1
        );
    }

    #[test]
    fn use_paths_retain_named_module_prefix_occurrences() {
        let source = "mod a { pub mod b { pub struct Item; } } use a::b::{Item}; use a::b::*;";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        for name in ["a", "b"] {
            assert_eq!(
                facts
                    .identifiers
                    .iter()
                    .filter(
                        |identifier| identifier.role == ResolutionIdentifierRole::Reference
                            && facts.names[identifier.name.index()].spelling == name
                            && facts.sites[identifier.site.index()].kind
                                == ResolutionSiteKind::ImportDeclaration
                    )
                    .count(),
                2,
                "missing import prefix {name}"
            );
        }
    }

    #[test]
    fn compound_type_operands_enumerate_without_inventing_receiver_types() {
        let source = "struct Item; const SIZE: usize = 2; fn check(tuple: (Item, Item), array: &[Item; SIZE], slice: &[Item], callback: fn(Item) -> Item) {}";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(
                    |identifier| identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "Item"
                )
                .count(),
            6
        );
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(
                    |identifier| identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "SIZE"
                )
                .count(),
            1
        );
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedTypeSyntax)
        );
    }

    #[test]
    fn destructuring_patterns_retain_constructor_owner_and_field_references() {
        let source = "struct Pair(i32); struct Named { value: i32 } fn check(pair: Pair, named: Named) { let Pair(value) = pair; let Named { value: other } = named; }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .collect::<Vec<_>>();
        for name in ["Pair", "Named"] {
            assert_eq!(
                references
                    .iter()
                    .filter(|identifier| facts.names[identifier.name.index()].spelling == name)
                    .count(),
                2,
                "{references:?}"
            );
        }
        assert_eq!(
            references
                .iter()
                .filter(
                    |identifier| facts.names[identifier.name.index()].spelling == "value"
                        && identifier.qualifier.is_some()
                )
                .count(),
            1
        );
    }

    #[test]
    fn initializer_labels_reference_the_field_and_shorthand_value() {
        let source = "struct Item { value: i32 } impl Item { fn make(value: i32) -> Self { Self { value } } } fn make(value: i32) -> Item { Item { value: value } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "value"
            })
            .collect::<Vec<_>>();
        assert_eq!(
            references
                .iter()
                .filter(|identifier| identifier.qualifier.is_some())
                .count(),
            2,
            "field references: {references:?}"
        );
        assert_eq!(
            references
                .iter()
                .filter(|identifier| identifier.qualifier.is_none())
                .count(),
            2,
            "value references: {references:?}"
        );
    }

    #[test]
    fn shorthand_initializers_retain_the_value_use_separately_from_the_field() {
        let source = "struct Item { value: i32 } fn make(value: i32) -> Item { Item { value } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        let uses = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.qualifier.is_none()
                    && facts.names[identifier.name.index()].spelling == "value"
            })
            .collect::<Vec<_>>();
        assert_eq!(uses.len(), 1);
        let site = facts.sites[uses[0].site.index()];
        assert_eq!(site.kind, ResolutionSiteKind::ValueReference);
        assert_eq!(uses[0].namespace, ResolutionNamespace::Value);
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(site.start_byte, site.end_byte)
            .unwrap();
        assert_eq!(node.parent().unwrap().kind(), "shorthand_field_initializer");
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(
                    |identifier| identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == "value"
                )
                .count(),
            2
        );
    }

    #[test]
    fn conditional_module_bodies_enumerate_without_unconditional_module_binders() {
        let source = "struct Item; #[cfg(test)] mod tests { use super::Item; fn consume(value: Item) -> Item { value } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        let module = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "tests"
            })
            .expect("the conditional module is declared");
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.site == module.site
                    && gap.kind == ResolutionGapKind::UnprovenActivation),
            "the inline module declaration carries its own activation obligation: {:?}",
            gap_inventory(&facts, source)
        );
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedPlacementBoundary),
            "an inline body is a lexical route, so it states no placement boundary: {:?}",
            gap_inventory(&facts, source)
        );
        // The declaration binds its name in the enclosing scope and exports it
        // from that scope, exactly as an unconditional inline module does. The
        // conditional part is the `UnprovenActivation` gap above, which travels
        // with the declaration and reaches every candidate that resolves
        // through it; withholding the binder instead withheld the root export,
        // which is lowered from it, and left `crate::..::tests` with no path an
        // export bridge could match.
        assert!(
            facts
                .binders
                .iter()
                .any(|binder| binder.declaration == module.site
                    && binder.hoisting == HoistingClass::ScopeWide),
            "the conditional module declaration binds its own name: {:?}",
            facts.binders
        );
        assert!(
            facts
                .root_exports
                .iter()
                .any(|export| export.declaration == module.site
                    && export.namespace == ResolutionNamespace::Type),
            "the conditional module declaration exports its own name: {:?}",
            facts.root_exports
        );
        let scope = facts
            .scopes
            .iter()
            .find(|scope| scope.kind == ResolutionScopeKind::Package)
            .unwrap();
        assert_eq!(scope.owner, Some(module.site));
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .collect::<Vec<_>>();
        assert_eq!(
            references
                .iter()
                .filter(
                    |identifier| facts.names[identifier.name.index()].spelling == "Item"
                        && identifier.namespace == ResolutionNamespace::Type
                )
                .count(),
            3
        );
        assert!(references.iter().all(|identifier| {
            let site = facts.sites[identifier.site.index()];
            scope.start_byte <= site.start_byte && site.end_byte <= scope.end_byte
        }));
        assert!(
            facts
                .root_imports
                .iter()
                .all(|import| import.root_scope == scope.id)
        );
        assert!(
            facts
                .root_exports
                .iter()
                .any(|export| export.root_scope == scope.id)
        );
    }

    #[test]
    fn trait_signatures_enumerate_parameters_bounds_and_abstract_self() {
        let source = "struct Item; trait Bound {} trait Service { fn take<'a, T: Bound>(&self, value: &'a Item, other: T) -> Self where T: Bound; fn plain(value: Item) -> Item; }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(references.iter().filter(|name| **name == "Item").count(), 3);
        assert_eq!(
            references.iter().filter(|name| **name == "Bound").count(),
            2
        );
        assert_eq!(references.iter().filter(|name| **name == "Self").count(), 1);
        let self_reference = facts
            .identifiers
            .iter()
            .find(|identifier| facts.names[identifier.name.index()].spelling == "Self")
            .unwrap()
            .site;
        assert!(
            !facts
                .binding_projections
                .iter()
                .any(|projection| projection.reference == self_reference)
        );
        let output = facts
            .type_slots
            .iter()
            .find(|slot| slot.site == self_reference)
            .unwrap()
            .id;
        let transfer = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.output == output)
            .unwrap();
        let frontier = facts.type_slots[transfer.input.index()].site;
        assert!(facts.gaps.iter().any(|gap| gap.site == frontier
            && gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal));
        for binder in &facts.binders {
            if facts.names[facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == binder.declaration)
                .unwrap()
                .name
                .index()]
            .spelling
                == "value"
            {
                assert_eq!(
                    facts.scopes[binder.scope.index()].kind,
                    ResolutionScopeKind::Executable
                );
            }
        }
    }

    #[test]
    fn lifetimes_do_not_hide_classified_value_and_type_references() {
        let source = "struct Item; fn borrow<'a>(value: &'a Item) -> &'a Item { value } fn run() { borrow(&Item); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(facts.names.iter().all(|name| name.spelling != "a"));
        assert!(facts.reference_enumeration_gaps.iter().all(|gap| {
            let site = facts.sites[gap.site.index()];
            let node = tree
                .root_node()
                .named_descendant_for_byte_range(site.start_byte, site.end_byte)
                .unwrap();
            node.parent()
                .is_none_or(|parent| parent.kind() != "lifetime")
        }));
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(references, ["Item", "Item", "value", "borrow", "Item"]);
        for identifier in &facts.identifiers {
            let site = facts.sites[identifier.site.index()];
            assert!(
                facts.reference_enumeration_gaps.iter().all(|gap| {
                    let gap = facts.sites[gap.site.index()];
                    (gap.start_byte, gap.end_byte) != (site.start_byte, site.end_byte)
                }),
                "classified token has no enumeration boundary: {identifier:?}"
            );
        }
    }

    #[test]
    fn first_tranche_lowers_local_bindings_and_remains_fail_closed() {
        let source = r#"
fn callee(input: i32) -> i32 {
    input
}

struct Pair {
    left: i32,
    right: i32,
}

fn caller(input: i32) -> i32 {
    let Pair { left: local, right } = Pair { left: input, right: input };
    callee(local + right + input)
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert_eq!(
            facts
                .scopes
                .iter()
                .map(|scope| scope.kind)
                .collect::<Vec<_>>(),
            [
                ResolutionScopeKind::CompilationUnit,
                ResolutionScopeKind::Executable,
                ResolutionScopeKind::TypeBody,
                ResolutionScopeKind::Executable,
            ]
        );
        let spellings = facts
            .identifiers
            .iter()
            .map(|identifier| {
                (
                    facts.names[identifier.name.index()].spelling.as_str(),
                    identifier.role,
                    identifier.namespace,
                    facts.sites[identifier.site.index()].kind,
                )
            })
            .collect::<Vec<_>>();
        assert!(spellings.contains(&(
            "callee",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            ResolutionSiteKind::CallableDeclaration,
        )));
        assert!(spellings.contains(&(
            "callee",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
            ResolutionSiteKind::CallableReference,
        )));
        assert!(spellings.contains(&(
            "local",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            ResolutionSiteKind::ValueDeclaration,
        )));
        assert!(spellings.contains(&(
            "local",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
            ResolutionSiteKind::ValueReference,
        )));
        let mut pattern_binders = facts
            .binders
            .iter()
            .filter(|binder| binder.kind == ResolutionBinderKind::Pattern)
            .map(|binder| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|identifier| identifier.site == binder.declaration)
                    .expect("pattern binder has its declaration identifier");
                facts.names[identifier.name.index()].spelling.as_str()
            })
            .collect::<Vec<_>>();
        pattern_binders.sort_unstable();
        assert_eq!(pattern_binders, ["local", "right"]);
        assert_eq!(
            facts
                .binders
                .iter()
                .filter(|binder| binder.kind == ResolutionBinderKind::Callable)
                .count(),
            2
        );
        assert!(facts.binders.iter().all(|binder| {
            binder.kind != ResolutionBinderKind::Callable
                || facts
                    .additional_definition_namespaces
                    .iter()
                    .any(|authority| {
                        authority.declaration == binder.declaration
                            && authority.namespace == ResolutionNamespace::Value
                            && authority.hoisting == binder.hoisting
                    })
        }));
        // `callee`, `Pair`, `caller`, and `Pair`'s two fields. A field is a
        // member declaration, so it carries an access-control spelling of its
        // own; both fields here are private and therefore publish no visibility
        // row, only the eligibility to have one.
        assert_eq!(facts.visibility_eligibilities.len(), 5);
        assert_eq!(
            facts
                .binders
                .iter()
                .filter(|binder| binder.kind == ResolutionBinderKind::Parameter)
                .count(),
            2
        );
        assert!(facts.reference_enumeration_gaps.is_empty());
        let root = facts.scopes[0];
        assert!(facts.reference_enumeration_gaps.iter().all(|gap| {
            let site = facts.sites[gap.site.index()];
            site.start_byte != root.start_byte || site.end_byte != root.end_byte
        }));
        assert_eq!(facts.calls.len(), 1);
        // One argument row for the one written actual, and one parameter row
        // for each function's `input: i32`.
        assert_eq!(
            facts
                .call_arguments
                .iter()
                .map(|argument| (argument.call, argument.ordinal))
                .collect::<Vec<_>>(),
            [(facts.calls[0].call, 0)]
        );
        assert_eq!(
            facts
                .callable_parameters
                .iter()
                .map(|parameter| (
                    source_text(&facts, source, parameter.callable),
                    parameter.ordinal,
                    source_text(&facts, source, parameter.parameter),
                ))
                .collect::<Vec<_>>(),
            [("callee", 0, "input"), ("caller", 0, "input")]
        );
        // Both inventories are exact now, so neither the callables nor the
        // call keep an applicability gap. What remains is the callee's own
        // obligation, which the common call obligation discharges, and the
        // binary expression the producer does not type: its gap sits on its
        // own site, so the argument is unknown while the call is not.
        assert_eq!(
            gap_inventory(&facts, source),
            vec![
                ("callee", ResolutionGapKind::UnsupportedCallApplicability),
                (
                    "local + right + input",
                    ResolutionGapKind::UnsupportedExpression
                ),
            ],
        );
    }

    #[test]
    fn unit_types_in_fields_and_aliases_keep_closed_intrinsic_identity() {
        let source = "struct Holder { value: () } type Unit = (); trait Contract { type Item; } impl Contract for Holder { type Item = (); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse unit types");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedTypeSyntax),
            "unit types are supported intrinsic types: {:?}",
            facts.gaps
        );
        for (start, _) in source.match_indices("()") {
            assert!(
                facts.intrinsic_type_seeds.iter().any(|seed| {
                    let site = &facts.sites[facts.type_slots[seed.output.index()].site.index()];
                    seed.kind == IntrinsicTypeKind::LanguageBuiltin
                        && facts.names[seed.name.index()].spelling == "()"
                        && (site.start_byte, site.end_byte) == (start, start + 2)
                }),
                "unit type at {start} needs an intrinsic identity"
            );
        }
    }

    #[test]
    fn declared_returns_and_typed_lets_publish_native_type_projections() {
        let source = r#"
struct Service;

trait Contract {
    fn trait_result(&self) -> Service;
    fn trait_self(&self) -> Box<Self>;
}

fn primitive() -> i32 { 0 }
fn make_service() -> Service { Service }
fn omitted() {}
fn explicit_unit() -> () {}

fn typed(service: Service) -> Service {
    let local: Service = service;
    local
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse declared-type projection fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let declaration_site = |name: &str, kind: ResolutionSiteKind| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                        && facts.sites[identifier.site.index()].kind == kind
                })
                .map(|identifier| identifier.site)
                .unwrap_or_else(|| panic!("missing {kind:?} declaration {name:?}"))
        };
        let return_property = |name: &str| {
            let declaration = declaration_site(name, ResolutionSiteKind::CallableDeclaration);
            let properties = facts
                .declaration_type_slots
                .iter()
                .filter(|property| {
                    property.declaration == declaration
                        && property.role == DeclarationTypeRole::Return
                })
                .collect::<Vec<_>>();
            assert_eq!(
                properties.len(),
                1,
                "expected one return property for {name}"
            );
            let property = properties[0];
            assert_eq!(
                facts.type_slots[property.slot.index()].role,
                ResolutionTypeSlotRole::DeclaredValue
            );
            let transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.output == property.slot
                        && transfer.kind == ResolutionTypeTransferKind::DeclaredType
                })
                .unwrap_or_else(|| panic!("missing declared return transfer for {name}"));
            facts.type_slots[transfer.input.index()]
        };

        let primitive_type = return_property("primitive");
        assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
            seed.output == primitive_type.id && seed.kind == IntrinsicTypeKind::Primitive
        }));
        let make_service_type = return_property("make_service");
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.output == make_service_type.id
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        }));
        for name in ["omitted", "explicit_unit"] {
            let unit_type = return_property(name);
            assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
                seed.output == unit_type.id
                    && seed.kind == IntrinsicTypeKind::LanguageBuiltin
                    && facts.names[seed.name.index()].spelling == "()"
            }));
            let declaration = declaration_site(name, ResolutionSiteKind::CallableDeclaration);
            assert!(!facts.gaps.iter().any(|gap| {
                gap.site == declaration && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
            }));
        }
        let trait_type = return_property("trait_result");
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.output == trait_type.id
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        }));
        let trait_start = source
            .find("fn trait_result")
            .expect("trait method signature");
        assert!(!facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedMemberScope
                && facts.sites[gap.site.index()].start_byte == trait_start
        }));
        let trait_declaration =
            declaration_site("trait_result", ResolutionSiteKind::CallableDeclaration);
        assert!(facts.member_owners.iter().any(|owner| {
            owner.member == trait_declaration
                && owner.kind == ResolutionMemberKind::Method
                && facts.sites[owner.owner.index()].kind == ResolutionSiteKind::TypeDeclaration
        }));
        assert!(
            !facts
                .deferred_member_owners
                .iter()
                .any(|owner| owner.member == trait_declaration)
        );
        let trait_self = declaration_site("trait_self", ResolutionSiteKind::CallableDeclaration);
        let trait_self_property = facts
            .declaration_type_slots
            .iter()
            .find(|property| {
                property.declaration == trait_self && property.role == DeclarationTypeRole::Return
            })
            .expect("trait Self return property");
        let declared_self = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == trait_self_property.slot
                    && transfer.kind == ResolutionTypeTransferKind::DeclaredType
            })
            .expect("trait Self return retains its declared-type transfer");
        let self_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && facts.names[identifier.name.index()].spelling == "Self"
            })
            .expect("nested trait Self reference");
        let self_output = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == self_reference.site
                    && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
            })
            .expect("nested trait Self identity slot")
            .id;
        let self_identity = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == self_output
                    && transfer.kind == ResolutionTypeTransferKind::TypeIdentity
            })
            .expect("trait Self occurrence transfers its abstract owner identity");
        // `-> Box<Self>` returns `Self` behind a transparent owning pointer, so
        // the declared return type is the `Self` occurrence's own identity
        // frontier. Before R3.5 the declared type stopped at the `Box` head and
        // these were two unrelated frontiers.
        assert_eq!(declared_self.input, self_output);
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == facts.type_slots[self_identity.input.index()].site
                && gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal
        }));
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == self_reference.site
                && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
        }));
        let _typed_type = return_property("typed");

        let service = declaration_site("service", ResolutionSiteKind::ValueDeclaration);
        let parameter_properties = facts
            .declaration_type_slots
            .iter()
            .filter(|property| {
                property.declaration == service && property.role == DeclarationTypeRole::Parameter
            })
            .collect::<Vec<_>>();
        assert_eq!(parameter_properties.len(), 1);
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == parameter_properties[0].slot
                && transfer.kind == ResolutionTypeTransferKind::DeclaredType
        }));

        let local = declaration_site("local", ResolutionSiteKind::ValueDeclaration);
        let value_properties = facts
            .declaration_type_slots
            .iter()
            .filter(|property| {
                property.declaration == local && property.role == DeclarationTypeRole::Value
            })
            .collect::<Vec<_>>();
        assert_eq!(value_properties.len(), 1);
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == value_properties[0].slot
                && transfer.kind == ResolutionTypeTransferKind::DeclaredType
        }));
    }

    #[test]
    fn direct_call_let_initializer_transfers_its_result_to_the_binding() {
        let source = r#"
struct Service;

impl Service {
    fn new() -> Self { Service }
    fn run(&self) {}
}

fn caller() {
    let service = Service::new();
    service.run();
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse direct call initializer fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let declaration = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == "service"
            })
            .expect("inferred let binding")
            .site;
        let property = facts
            .declaration_type_slots
            .iter()
            .find(|property| {
                property.declaration == declaration && property.role == DeclarationTypeRole::Value
            })
            .expect("inferred let declared-value frontier");
        let initialization = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == property.slot
                    && transfer.kind == ResolutionTypeTransferKind::Initialization
            })
            .expect("direct call initialization transfer");
        assert_eq!(
            facts.type_slots[initialization.input.index()].role,
            ResolutionTypeSlotRole::CallResult
        );
        assert_eq!(initialization.indirection_delta, 0);
        assert_eq!(initialization.reference_indirection_delta, 0);
        assert_eq!(
            initialization.value_transform,
            ResolutionTypeTransferValueTransform::Preserve
        );
    }

    #[test]
    fn structured_declared_type_wrappers_preserve_heads_indirection_and_gaps() {
        let source = r#"
trait Capability { type Item; }
struct Service;
struct Wrapper<T>(T);

fn wrapped() -> Wrapper<Service> { loop {} }
fn types(
    borrowed: &Service,
    nested: &&Service,
    raw: *const Service,
    mixed: &*const Service,
    generic: Wrapper<Service>,
    qualified: <Service as Capability>::Item,
    dynamic: &dyn Capability,
    opaque: impl Capability,
) {}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse structured declared-wrapper fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let type_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
            })
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert!(type_references.contains(&"Wrapper"));
        assert!(type_references.contains(&"Service"));
        assert!(type_references.contains(&"Capability"));
        assert!(type_references.contains(&"Item"));

        let declared_transfer = |name: &str| {
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                        && matches!(
                            facts.sites[identifier.site.index()].kind,
                            ResolutionSiteKind::CallableDeclaration
                                | ResolutionSiteKind::ValueDeclaration
                        )
                })
                .expect("typed declaration")
                .site;
            let property = facts
                .declaration_type_slots
                .iter()
                .find(|property| property.declaration == declaration)
                .expect("typed declaration property");
            facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.output == property.slot
                        && transfer.kind == ResolutionTypeTransferKind::DeclaredType
                })
                .copied()
                .expect("declared type transfer")
        };
        let input_name = |transfer: ResolutionTypeTransferFact| {
            let union_inputs = facts
                .type_transfers
                .iter()
                .filter(|input| {
                    input.output == transfer.input
                        && input.kind == ResolutionTypeTransferKind::TypeUnion
                })
                .collect::<Vec<_>>();
            let input = match union_inputs.as_slice() {
                [] => transfer.input,
                [input] => input.input,
                _ => panic!("this fixture declares one trait per receiver"),
            };
            let site = facts.type_slots[input.index()].site;
            facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == site)
                .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
                .expect("declared type head reference")
        };

        for (name, head, total, references) in [
            ("wrapped", "Wrapper", 0, 0),
            ("borrowed", "Service", 1, 1),
            ("nested", "Service", 2, 2),
            ("raw", "Service", 1, 0),
            ("mixed", "Service", 2, 1),
            ("generic", "Wrapper", 0, 0),
            ("qualified", "Item", 0, 0),
            ("dynamic", "Capability", 1, 1),
            ("opaque", "Capability", 0, 0),
        ] {
            let transfer = declared_transfer(name);
            assert_eq!(input_name(transfer), head, "declared head for {name}");
            assert_eq!(transfer.indirection_delta, total, "total depth for {name}");
            assert_eq!(
                transfer.reference_indirection_delta, references,
                "reference depth for {name}"
            );
        }

        let gaps = gap_inventory(&facts, source);
        // A supported wrapper keeps its nominal head, so no gap names a whole
        // declared type any more. Unmodelled generic arguments still do: they
        // are type syntax, not an omitted lexical binder, so they carry
        // `UnsupportedTypeSyntax` and leave the attachment scope's lookups
        // alone.
        for (spelling, kind) in &gaps {
            assert!(
                *kind != ResolutionGapKind::UnsupportedTypeSyntax
                    || *spelling == "Wrapper"
                    || spelling.starts_with('<'),
                "supported wrappers must not retain unsupported-syntax gaps: {gaps:?}"
            );
        }
        assert!(gaps.contains(&("Wrapper", ResolutionGapKind::UnsupportedTypeSyntax,)));
        assert!(gaps.contains(&("<Service>", ResolutionGapKind::UnsupportedTypeSyntax,)));
        assert!(
            !gaps
                .iter()
                .any(|(_, kind)| *kind == ResolutionGapKind::AmbiguousQualifiedType)
        );
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.kind == ResolutionTypeTransferKind::Receiver
                && facts.identifiers.iter().any(|identifier| {
                    identifier.site == facts.type_slots[transfer.output.index()].site
                        && facts.names[identifier.name.index()].spelling == "Item"
                })
        }));
        assert!(!gaps.contains(&(
            "dyn Capability",
            ResolutionGapKind::UnsupportedHierarchyTraversal,
        )));
        assert!(!gaps.contains(&(
            "impl Capability",
            ResolutionGapKind::UnsupportedHierarchyTraversal,
        )));
    }

    #[test]
    fn deeply_nested_declared_type_reports_the_fact_range_boundary() {
        let source = format!(
            "struct Service; fn consume(value: {}Service) {{}}",
            "&".repeat(128)
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(&source, None)
            .expect("parse deeply nested reference type");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), &source);
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Type
                && facts.names[identifier.name.index()].spelling == "Service"
        }));
        assert!(
            gap_inventory(&facts, &source)
                .iter()
                .any(|(_, kind)| *kind == ResolutionGapKind::UnsupportedTypeSyntax)
        );
    }

    /// An impl whose subject is not a nominal type keeps its members. The
    /// subject frontier resolves to nothing and carries the reason on the
    /// exact token, so no member is attached to the wrong declaration; before,
    /// the whole impl body was dropped as an unsupported member scope and every
    /// reference written inside it was absent.
    #[test]
    fn nonnominal_inherent_impl_keeps_its_members_under_an_unnameable_subject() {
        let source =
            "struct Service; fn helper() {} impl &Service { fn method(&self) { helper(); } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse nonnominal inherent impl");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert_eq!(facts.declared_type_relations.len(), 1);
        let subject = facts.declared_type_relations[0].subject;
        let subject_site = facts.type_slots[subject.index()].site;
        assert!(
            facts.gaps.iter().any(|gap| {
                gap.site == subject_site && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
            }),
            "{facts:#?}"
        );
        assert!(
            !facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedMemberScope),
            "{facts:#?}"
        );
        assert!(
            facts.deferred_member_owners.iter().any(|owner| {
                owner.owner_type == subject
                    && facts.identifiers.iter().any(|identifier| {
                        identifier.site == owner.member
                            && facts.names[identifier.name.index()].spelling == "method"
                    })
            }),
            "{facts:#?}"
        );
        assert!(
            facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "helper"
            }),
            "the member body is lowered: {facts:#?}"
        );
    }

    #[test]
    fn nominal_declarations_have_one_type_body_scope_and_generic_binders_reuse_it() {
        let source = concat!(
            "struct Empty;\n",
            "enum Choice { None, Some(usize) }\n",
            "union Word { bits: usize }\n",
            "trait Displayable { fn display(&self); }\n",
            "struct Generic<T, const N: usize> { value: T }\n",
            "mod nested { struct Nested; }\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse nominal Rust fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let nominal_names = [
            "Empty",
            "Choice",
            "Word",
            "Displayable",
            "Generic",
            "Nested",
        ];
        for name in nominal_names {
            let declarations = facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.sites[identifier.site.index()].kind
                            == ResolutionSiteKind::TypeDeclaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .collect::<Vec<_>>();
            let [declaration] = declarations.as_slice() else {
                panic!("expected one nominal declaration for {name:?}: {declarations:?}");
            };
            let body_scopes = facts
                .scopes
                .iter()
                .filter(|scope| {
                    scope.kind == ResolutionScopeKind::TypeBody
                        && scope.owner == Some(declaration.site)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                body_scopes.len(),
                1,
                "nominal declaration {name:?} must own exactly one TypeBody"
            );
        }

        let nested_module = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Type
                    && facts.names[identifier.name.index()].spelling == "nested"
            })
            .expect("nested module declaration");
        let nested_package = facts
            .scopes
            .iter()
            .find(|scope| scope.owner == Some(nested_module.site))
            .expect("nested module scope");
        assert_eq!(nested_package.kind, ResolutionScopeKind::Package);

        let generic = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "Generic"
            })
            .expect("generic nominal declaration");
        let generic_body = facts
            .scopes
            .iter()
            .find(|scope| {
                scope.owner == Some(generic.site) && scope.kind == ResolutionScopeKind::TypeBody
            })
            .expect("generic nominal TypeBody");
        for parameter in ["T", "N"] {
            let binder = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == parameter
                })
                .expect("generic parameter declaration");
            assert!(
                facts.binders.iter().any(|fact| {
                    fact.declaration == binder.site && fact.scope == generic_body.id
                })
            );
        }
    }

    #[test]
    fn qualified_terminals_and_item_macros_keep_exact_boundaries() {
        let source = concat!(
            "mod model;\n",
            "macro_rules! opaque_items { () => {}; }\n",
            "opaque_items!();\n",
            "fn caller(_: model::QualifiedType) {\n",
            "    model::qualified_call();\n",
            "    body_macro!();\n",
            "}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse qualified Rust fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let qualified = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                matches!(
                    facts.names[identifier.name.index()].spelling.as_str(),
                    "QualifiedType" | "qualified_call"
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(qualified.len(), 2);
        for identifier in qualified {
            assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
            let site = facts.sites[identifier.site.index()];
            assert_eq!(
                &source[site.start_byte..site.end_byte],
                facts.names[identifier.name.index()].spelling
            );
            assert!(
                identifier.qualifier.is_some(),
                "bare Rust route terminals retain their structured receiver slot"
            );
        }
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.namespace == ResolutionNamespace::Type
                        && facts.names[identifier.name.index()].spelling == "model"
                })
                .count(),
            2,
            "each bare route publishes one positioned Type prefix"
        );
        assert_eq!(facts.binding_projections.len(), 4);
        assert_eq!(
            facts
                .binding_projections
                .iter()
                .filter(|projection| projection.kind == BindingProjectionKind::TargetTypeIdentity)
                .count(),
            3,
            "qualified prefixes and the type terminal own type-identity projections"
        );
        assert_eq!(
            facts
                .binding_projections
                .iter()
                .filter(|projection| {
                    projection.kind == BindingProjectionKind::TargetCallableResultType
                })
                .count(),
            1,
            "the qualified call owns one callable-result projection"
        );
        assert_eq!(facts.type_transfers.len(), 5);
        assert_eq!(
            facts
                .type_transfers
                .iter()
                .filter(|transfer| { transfer.kind == ResolutionTypeTransferKind::DeclaredType })
                .count(),
            2,
            "the omitted callable return transfers its intrinsic unit type, and the `_` \
             parameter its declared type"
        );
        assert_eq!(
            facts
                .type_transfers
                .iter()
                .filter(|transfer| {
                    facts.type_slots[transfer.input.index()].role
                        == ResolutionTypeSlotRole::TargetTypeIdentity
                        && transfer.kind == ResolutionTypeTransferKind::Receiver
                })
                .count(),
            2,
            "each qualified prefix transfers its type identity into a terminal receiver"
        );
        assert_eq!(
            facts
                .type_transfers
                .iter()
                .filter(|transfer| {
                    facts.type_slots[transfer.input.index()].role
                        == ResolutionTypeSlotRole::Receiver
                })
                .count(),
            1,
            "the call transfers its terminal receiver into the call receiver slot"
        );
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.kind == ResolutionTypeTransferKind::Receiver
                && facts.type_slots[transfer.input.index()].role == ResolutionTypeSlotRole::Receiver
                && facts.type_slots[transfer.output.index()].role
                    == ResolutionTypeSlotRole::Receiver
                && facts.sites[facts.type_slots[transfer.output.index()].site.index()].kind
                    == ResolutionSiteKind::Call
        }));
        for prefix in facts.identifiers.iter().filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Type
                && facts.names[identifier.name.index()].spelling == "model"
        }) {
            let projection = facts
                .binding_projections
                .iter()
                .find(|projection| projection.reference == prefix.site)
                .expect("bare prefix has a type identity projection");
            assert_eq!(
                facts.type_slots[projection.output.index()].role,
                ResolutionTypeSlotRole::TargetTypeIdentity
            );
            let terminal = facts
                .root_references
                .iter()
                .find(|route| route.prefix_reference == Some(prefix.site))
                .expect("bare prefix belongs to one root route")
                .reference;
            assert!(facts.type_transfers.iter().any(|transfer| {
                transfer.input == projection.output
                    && facts
                        .identifiers
                        .iter()
                        .find(|identifier| identifier.site == terminal)
                        .and_then(|identifier| identifier.qualifier)
                        == Some(transfer.output)
                    && transfer.kind == ResolutionTypeTransferKind::Receiver
            }));
        }

        let gaps = facts
            .gaps
            .iter()
            .map(|gap| {
                let site = facts.sites[gap.site.index()];
                (&source[site.start_byte..site.end_byte], gap.kind)
            })
            .collect::<Vec<_>>();
        assert!(
            !gaps.iter().any(|(source, _)| *source == "opaque_items!()"),
            "the visible empty matcher and transcriber close this invocation: {gaps:?}"
        );
        assert!(gaps.contains(&("body_macro!()", ResolutionGapKind::UnsupportedExpression,)));
    }

    #[test]
    fn explicit_qualified_routes_publish_every_prefix_below_the_path_head() {
        let source = concat!(
            "mod outer {\n",
            "    fn caller() {\n",
            "        let _: crate::types::Widget = crate::values::make();\n",
            "        crate::left::target();\n",
            "        self::local::local_target();\n",
            "        super::parent::parent_target();\n",
            "        super::super::grand_target();\n",
            "        ::absolute::absolute_target();\n",
            "        ::root_target();\n",
            "        Service::method();\n",
            "        module::bare_target();\n",
            "    }\n",
            "}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse explicit route Rust fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let route_rows = facts
            .root_references
            .iter()
            .map(|route| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|identifier| identifier.site == route.reference)
                    .expect("root reference has its terminal identifier");
                let terminal = facts.names[identifier.name.index()].spelling.as_str();
                let segments = facts
                    .root_reference_segments
                    .iter()
                    .filter(|segment| segment.reference == route.reference)
                    .collect::<Vec<_>>();
                // A bare route's terminal takes its lexical prefix as its
                // receiver; an explicit module route's terminal takes its final
                // segment when that segment names an item, not an anchor.
                let item_receiver = segments.len() >= 2
                    && segments.last().is_some_and(|segment| {
                        !matches!(
                            facts.names[segment.name.index()].spelling.as_str(),
                            "crate" | "self" | "super"
                        )
                    });
                assert_eq!(
                    identifier.qualifier.is_some(),
                    route.prefix_reference.is_some() || item_receiver,
                    "a root route terminal publishes a receiver slot exactly when a route prefix is its receiver: {route:?}"
                );
                let mut names = segments
                    .iter()
                    .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                    .collect::<Vec<_>>();
                assert!(
                    segments
                        .windows(2)
                        .all(|pair| pair[0].position < pair[1].position)
                );
                let mut anchor = route.anchor;
                let mut prefix = route.prefix_reference;
                let mut depth = 0;
                while let Some(parent) = prefix.and_then(|reference| {
                    facts
                        .root_references
                        .iter()
                        .find(|row| row.reference == reference)
                }) {
                    depth += 1;
                    assert!(
                        depth <= facts.root_references.len(),
                        "prefix routes are acyclic"
                    );
                    let mut parent_names = facts
                        .root_reference_segments
                        .iter()
                        .filter(|segment| segment.reference == parent.reference)
                        .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                        .collect::<Vec<_>>();
                    parent_names.extend(names);
                    names = parent_names;
                    anchor = parent.anchor;
                    prefix = parent.prefix_reference;
                }
                (terminal, anchor, names)
            })
            .collect::<Vec<_>>();
        // Static type-qualified terminals are retained as root routes so the
        // selected member evaluator can consume their structured receiver
        // slot; this fixture therefore has the explicit routes above plus
        // `Service::method`. Every path prefix below the path head also
        // publishes its own root route keyed on that prefix token, so an
        // anchored path such as `crate::types::Widget` carries an occurrence
        // for `types` as well as for `Widget`. The head publishes none: a bare
        // path keeps its head on the terminal route's receiver slot (which is
        // why `Service` and `module` add no route of their own), and a leading
        // `::` head names a crate through the extern prelude. An anchor keyword
        // does publish one, wherever it stands, and its route ends on its own
        // step, because the module it names is the one that step reaches:
        // `super::super::grand_target` therefore carries `["super"]` for its
        // first anchor and `["super", "super"]` for its second.
        assert_eq!(route_rows.len(), 22);
        for prefix_row in [
            ("types", ResolutionRootImportAnchor::Lexical, vec!["crate"]),
            ("values", ResolutionRootImportAnchor::Lexical, vec!["crate"]),
            ("left", ResolutionRootImportAnchor::Lexical, vec!["crate"]),
            ("local", ResolutionRootImportAnchor::Lexical, vec!["self"]),
            ("parent", ResolutionRootImportAnchor::Lexical, vec!["super"]),
            ("crate", ResolutionRootImportAnchor::Lexical, vec!["crate"]),
            ("self", ResolutionRootImportAnchor::Lexical, vec!["self"]),
            ("super", ResolutionRootImportAnchor::Lexical, vec!["super"]),
            (
                "super",
                ResolutionRootImportAnchor::Lexical,
                vec!["super", "super"],
            ),
        ] {
            assert!(
                route_rows.contains(&prefix_row),
                "path prefix route missing: {prefix_row:?}"
            );
        }
        assert!(route_rows.contains(&(
            "Widget",
            ResolutionRootImportAnchor::Lexical,
            vec!["crate", "types"],
        )));
        assert!(route_rows.contains(&(
            "make",
            ResolutionRootImportAnchor::Lexical,
            vec!["crate", "values"],
        )));
        assert!(route_rows.contains(&(
            "target",
            ResolutionRootImportAnchor::Lexical,
            vec!["crate", "left"],
        )));
        assert!(route_rows.contains(&(
            "local_target",
            ResolutionRootImportAnchor::Lexical,
            vec!["self", "local"],
        )));
        assert!(route_rows.contains(&(
            "parent_target",
            ResolutionRootImportAnchor::Lexical,
            vec!["super", "parent"],
        )));
        assert!(route_rows.contains(&(
            "grand_target",
            ResolutionRootImportAnchor::Lexical,
            vec!["super", "super"],
        )));
        assert!(route_rows.contains(&(
            "absolute_target",
            ResolutionRootImportAnchor::Absolute,
            vec!["absolute"],
        )));
        assert!(route_rows.contains(&(
            "root_target",
            ResolutionRootImportAnchor::Absolute,
            Vec::<&str>::new(),
        )));
        assert!(route_rows.contains(&(
            "bare_target",
            ResolutionRootImportAnchor::Lexical,
            vec!["module"],
        )));

        let outer_scope = facts
            .scopes
            .iter()
            .find(|scope| scope.kind == ResolutionScopeKind::Package)
            .expect("inline module package scope");
        let caller = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "caller"
            })
            .expect("caller declaration");
        assert!(
            facts
                .root_references
                .iter()
                .all(|route| route.root_scope == outer_scope.id)
        );
        assert!(facts.root_references.iter().all(|route| {
            facts
                .reference_owners
                .iter()
                .find(|owner| owner.reference == route.reference)
                .and_then(|owner| owner.owner)
                == Some(caller.site)
        }));
        assert!(facts.root_imports.is_empty());
        assert!(
            !facts
                .binders
                .iter()
                .any(|binder| binder.kind == ResolutionBinderKind::Import)
        );

        let reference_names = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        for path_component in ["types", "values", "left", "local", "parent"] {
            assert!(
                reference_names.contains(&path_component),
                "path prefix publishes its own reference: {path_component}"
            );
        }
        for anchor in ["crate", "self", "super"] {
            assert!(
                reference_names.contains(&anchor),
                "a path anchor names its module: {anchor}"
            );
        }
        assert!(
            !reference_names.contains(&"absolute"),
            "a leading `::` head names a crate through the extern prelude"
        );
        for bare_prefix in ["Service", "module"] {
            assert!(
                reference_names.contains(&bare_prefix),
                "bare route publishes its Type prefix: {bare_prefix}"
            );
        }

        let method = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "method"
            })
            .expect("type-qualified method terminal remains a reference");
        assert!(method.qualifier.is_some());
        assert!(
            facts
                .root_references
                .iter()
                .any(|route| route.reference == method.site)
        );
    }

    #[test]
    fn literal_method_receivers_keep_names_and_semantic_uncertainty() {
        let source = "fn check() { \"value\".inspect(); true.inspect(); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(
                    |identifier| identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "inspect"
                )
                .count(),
            2
        );
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedExpression)
        );
    }

    #[test]
    fn resultless_call_receiver_keeps_its_gap_and_drains_pending_slots() {
        let source = "fn check() { callbacks[0]().inspect(); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let member = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "inspect"
            })
            .expect("method reference survives the unsupported call");
        assert!(
            facts.gaps.iter().any(|gap| {
                gap.site == member.site && gap.kind == ResolutionGapKind::UnsupportedExpression
            }),
            "resultless receiver records the member's gap: {:?}",
            facts.gaps
        );
    }

    #[test]
    fn compound_method_receivers_enumerate_each_member() {
        let source = "struct Inner; impl Inner { fn run(&self) {} } struct Outer { inner: Inner } impl Outer { fn check(&self) { self.inner.run(); } } fn make(value: Outer) -> Outer { value } fn check(value: Outer) { make(value).inner.run(); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        for name in ["inner", "run"] {
            assert_eq!(
                facts
                    .identifiers
                    .iter()
                    .filter(
                        |identifier| identifier.role == ResolutionIdentifierRole::Reference
                            && facts.names[identifier.name.index()].spelling == name
                            && facts.sites[identifier.site.index()].kind
                                == ResolutionSiteKind::MemberReference
                    )
                    .count(),
                2,
                "{name}"
            );
        }
    }

    #[test]
    fn direct_and_generic_method_calls_keep_terminal_receiver_and_arguments() {
        let source = concat!(
            "struct Service;\n",
            "fn caller(service: Service, arg: i32) {\n",
            "    service.method(arg);\n",
            "    service.method::<i32>(arg);\n",
            "}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse method-call Rust fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let caller = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == "caller"
            })
            .expect("caller declaration");
        let method_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Callable
                    && facts.names[identifier.name.index()].spelling == "method"
            })
            .collect::<Vec<_>>();
        assert_eq!(method_references.len(), 2);
        for method in method_references {
            let site = facts.sites[method.site.index()];
            assert_eq!(site.kind, ResolutionSiteKind::MemberReference);
            assert_eq!(&source[site.start_byte..site.end_byte], "method");
            assert!(method.qualifier.is_some());
            assert_eq!(
                facts
                    .reference_owners
                    .iter()
                    .find(|owner| owner.reference == method.site)
                    .and_then(|owner| owner.owner),
                Some(caller.site)
            );
        }

        for spelling in ["service", "arg"] {
            let references = facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.namespace == ResolutionNamespace::Value
                        && facts.names[identifier.name.index()].spelling == spelling
                })
                .collect::<Vec<_>>();
            assert_eq!(references.len(), 2, "references for {spelling}");
            assert!(references.iter().all(|reference| {
                facts
                    .reference_owners
                    .iter()
                    .find(|owner| owner.reference == reference.site)
                    .and_then(|owner| owner.owner)
                    == Some(caller.site)
            }));
        }

        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedRoute)
        );
    }

    #[test]
    fn indirect_callees_keep_positioned_expression_gaps_and_nested_references() {
        let source = concat!(
            "fn caller(function: fn(i32), values: [fn(i32); 1], index: usize, pair: (fn(i32),), arg: i32) {\n",
            "    (function)(arg);\n",
            "    values[index](arg);\n",
            "    pair.0(arg);\n",
            "}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse indirect-call Rust fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedRoute)
        );
        let expression_gaps = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedExpression)
            .map(|gap| {
                let site = facts.sites[gap.site.index()];
                &source[site.start_byte..site.end_byte]
            })
            .collect::<Vec<_>>();
        assert_eq!(expression_gaps, ["(function)", "values[index]", "pair.0"]);

        let preserved_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && matches!(
                        facts.names[identifier.name.index()].spelling.as_str(),
                        "function" | "values" | "index" | "pair" | "arg"
                    )
            })
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            preserved_references,
            ["function", "arg", "values", "index", "arg", "pair", "arg"]
        );
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "0"
        }));
    }

    #[test]
    fn public_roots_and_named_alias_imports_have_content_owned_route_halves() {
        let source = r#"
pub struct Widget;
pub fn make() {}
use engine::model::Widget as WidgetAlias;
use ::engine::model::Widget as GloballyAnchoredWidget;
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust route fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert_eq!(facts.root_imports.len(), 2);
        assert_eq!(
            facts
                .root_imports
                .iter()
                .map(|import| import.anchor)
                .collect::<Vec<_>>(),
            [
                ResolutionRootImportAnchor::Lexical,
                ResolutionRootImportAnchor::Absolute,
            ]
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedRoute)
                .count(),
            0
        );
        let import = facts.root_imports[0];
        let route = facts
            .root_import_segments
            .iter()
            .filter(|segment| segment.import_site == import.site)
            .map(|segment| facts.names[segment.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(route, ["engine", "model"]);
        let demands = facts
            .root_import_demands
            .iter()
            .filter(|demand| demand.import_site == import.site)
            .map(|demand| {
                (
                    demand.namespace,
                    facts.names[demand.name.index()].spelling.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            demands,
            [
                (ResolutionNamespace::Type, "WidgetAlias"),
                (ResolutionNamespace::Value, "WidgetAlias"),
                (ResolutionNamespace::Macro, "WidgetAlias"),
            ]
        );
        assert_eq!(facts.root_exports.len(), 3);
        assert_eq!(
            facts
                .root_exports
                .iter()
                .map(|export| (
                    facts.names[facts.identifiers[export.declaration.index()].name.index()]
                        .spelling
                        .as_str(),
                    export.namespace,
                ))
                .collect::<Vec<_>>(),
            [
                ("Widget", ResolutionNamespace::Type),
                ("Widget", ResolutionNamespace::Value),
                ("make", ResolutionNamespace::Value),
            ]
        );
        assert!(
            facts
                .declaration_visibilities
                .iter()
                .all(|visibility| { visibility.visibility == DeclaredVisibility::Public })
        );
    }

    #[test]
    fn public_inline_items_publish_exports_from_their_module_scope() {
        let source = r#"
pub mod inline {
    pub fn target() {}
    fn hidden() {}
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse inline Rust export fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let target = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "target"
            })
            .expect("inline target declaration");
        let target_scope = facts.sites[target.site.index()].scope;
        assert_ne!(target_scope, ResolutionScopeId::new(0));
        assert_eq!(
            facts.scopes[target_scope.index()].kind,
            ResolutionScopeKind::Package
        );
        assert!(facts.root_exports.iter().any(|export| {
            export.root_scope == target_scope
                && export.declaration == target.site
                && export.namespace == ResolutionNamespace::Value
        }));
        assert!(facts.root_exports.iter().any(|export| {
            facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == export.declaration)
                .is_some_and(|identifier| facts.names[identifier.name.index()].spelling == "hidden")
        }));
    }

    #[test]
    fn block_local_items_publish_scope_wide_incomplete_binders_without_root_exports() {
        let source = r#"
use engine::model as route;
fn caller() -> usize {
    pub struct route;
    route::target()
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse block-local Rust item fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let route = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Type
                    && facts.names[identifier.name.index()].spelling == "route"
                    && facts.scopes[facts.sites[identifier.site.index()].scope.index()].kind
                        == ResolutionScopeKind::Executable
            })
            .expect("block-local struct declaration");
        let scope = facts.sites[route.site.index()].scope;
        assert_eq!(
            facts.scopes[scope.index()].kind,
            ResolutionScopeKind::Executable
        );
        assert!(facts.binders.iter().any(|binder| {
            binder.declaration == route.site
                && binder.scope == scope
                && binder.hoisting == HoistingClass::ScopeWide
                && binder.activation_start == facts.scopes[scope.index()].start_byte
                && binder.activation_end == facts.scopes[scope.index()].end_byte
        }));
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == route.site && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
        }));
        assert!(
            facts
                .root_exports
                .iter()
                .all(|export| export.declaration != route.site),
            "a block-local item is a lexical binder, not a module export"
        );
        // The item binds in the block's item scope and the reference stands in
        // the local scope below it, so the reference reaches the item by one
        // parent step and never through a module route.
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Type
                && facts.names[identifier.name.index()].spelling == "route"
                && facts.scopes[facts.sites[identifier.site.index()].scope.index()].parent
                    == Some(scope)
        }));
    }

    #[test]
    fn inline_module_named_use_publishes_a_package_attached_import() {
        let source = r#"
pub mod inline {
    use engine::model::Widget as WidgetAlias;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse inline Rust named-use fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert_eq!(facts.root_imports.len(), 1);
        let import = facts.root_imports[0];
        let import_scope = facts.sites[import.site.index()].scope;
        assert_eq!(
            facts.scopes[import_scope.index()].kind,
            ResolutionScopeKind::Package
        );
        assert!(facts.gaps.iter().all(|gap| gap.site != import.site));
        assert_eq!(
            facts
                .root_import_segments
                .iter()
                .filter(|segment| segment.import_site == import.site)
                .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                .collect::<Vec<_>>(),
            ["engine", "model"]
        );
        assert_eq!(
            facts
                .root_import_demands
                .iter()
                .filter(|demand| demand.import_site == import.site)
                .map(|demand| {
                    (
                        demand.namespace,
                        facts.names[demand.name.index()].spelling.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            [
                (ResolutionNamespace::Type, "WidgetAlias"),
                (ResolutionNamespace::Value, "WidgetAlias"),
                (ResolutionNamespace::Macro, "WidgetAlias"),
            ]
        );
    }

    #[test]
    fn inline_module_glob_use_collects_references_from_its_module_scope() {
        let source = r#"
use engine::*;

pub mod inline {
    use engine::*;

    fn caller() {
        inline_imported();
    }
}

fn root_caller() {
    root_imported();
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse inline Rust glob-use fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert_eq!(facts.root_imports.len(), 2);
        let demands_for = |import_site| {
            facts
                .root_import_demands
                .iter()
                .filter(|demand| demand.import_site == import_site)
                .map(|demand| {
                    (
                        demand.namespace,
                        facts.names[demand.name.index()].spelling.as_str(),
                    )
                })
                .collect::<BTreeSet<_>>()
        };
        let imports_by_scope_kind = facts
            .root_imports
            .iter()
            .map(|import| {
                (
                    facts.scopes[facts.sites[import.site.index()].scope.index()].kind,
                    import.site,
                )
            })
            .collect::<Vec<_>>();
        let root_import = imports_by_scope_kind
            .iter()
            .find(|(kind, _)| *kind == ResolutionScopeKind::CompilationUnit)
            .expect("root glob import");
        let inline_import = imports_by_scope_kind
            .iter()
            .find(|(kind, _)| *kind == ResolutionScopeKind::Package)
            .expect("inline glob import");
        assert_eq!(
            demands_for(root_import.1),
            BTreeSet::from([(ResolutionNamespace::Value, "root_imported")])
        );
        assert_eq!(
            demands_for(inline_import.1),
            BTreeSet::from([(ResolutionNamespace::Value, "inline_imported")])
        );
    }

    #[test]
    #[ignore = "finds real bug: tuple_type emits UnsupportedTypeSyntax and no element member identity. Owner: RustResolutionBuilder::lower_declared_type_identity"]
    fn tuple_field_anonymous_tuple_has_a_proven_element_type() {
        let source =
            "struct Item; impl Item { fn run(&self) {} } fn test(pair: (Item,)) { pair.0.run(); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedTypeSyntax),
            "{:?}",
            facts.gaps
        );
        assert_eq!(
            facts
                .member_owners
                .iter()
                .filter(|member| member.kind == ResolutionMemberKind::Field)
                .count(),
            1
        );
    }

    #[test]
    fn tuple_field_unknown_receiver_preserves_type_uncertainty() {
        let source = "fn test(w: Unknown, pair: (Unknown, Unknown)) { w.0.run(); pair.0.1.run(); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let members = facts
            .identifiers
            .iter()
            .filter(|id| facts.sites[id.site.index()].kind == ResolutionSiteKind::MemberReference)
            .map(|id| facts.names[id.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(members, ["run", "0", "run", "0", "1"]);
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedTypeSyntax)
        );
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            facts.reference_enumeration_gaps
        );
    }

    #[test]
    fn tuple_field_receivers_publish_member_chains() {
        let source = "struct Item; impl Item { fn run(&self) {} } struct Wrap(Item); struct Pair(Item, Item); struct Outer(Pair); impl Wrap { fn go(&self) { self.0.run(); } } fn test(w: Wrap, a: Outer) { w.0.run(); a.0.1.run(); let Wrap(inner) = w; inner.run(); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let members = facts
            .identifiers
            .iter()
            .filter(|id| {
                facts.sites[id.site.index()].kind == ResolutionSiteKind::MemberReference
                    && matches!(facts.names[id.name.index()].spelling.as_str(), "0" | "1")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            members
                .iter()
                .map(|id| facts.names[id.name.index()].spelling.as_str())
                .collect::<Vec<_>>(),
            ["0", "0", "0", "1"]
        );
        for member in members {
            let qualifier = member.qualifier.expect("positional member receiver");
            assert!(
                facts
                    .type_transfers
                    .iter()
                    .any(|transfer| transfer.output == qualifier)
            );
            let projection = facts
                .binding_projections
                .iter()
                .find(|projection| {
                    projection.reference == member.site
                        && projection.kind == BindingProjectionKind::TargetDeclaredValueType
                })
                .expect("positional member value");
            assert!(
                facts
                    .type_transfers
                    .iter()
                    .any(|transfer| transfer.input == projection.output)
            );
        }
        let fields = facts
            .member_owners
            .iter()
            .filter(|member| member.kind == ResolutionMemberKind::Field)
            .collect::<Vec<_>>();
        let field_names = fields
            .iter()
            .map(|field| {
                let spelling = |site| {
                    let identifier = facts.identifiers.iter().find(|id| id.site == site).unwrap();
                    facts.names[identifier.name.index()].spelling.as_str()
                };
                (spelling(field.owner), spelling(field.member))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            field_names,
            [("Wrap", "0"), ("Pair", "0"), ("Pair", "1"), ("Outer", "0")]
        );
        assert!(
            facts
                .identifiers
                .iter()
                .any(|id| id.role == ResolutionIdentifierRole::Reference
                    && id.namespace == ResolutionNamespace::Value
                    && facts.names[id.name.index()].spelling == "Wrap")
        );
        assert_eq!(fields.len(), 4);
        for field in fields {
            let site = facts.sites[field.member.index()];
            assert_eq!(
                site.start_byte, site.end_byte,
                "an unnamed field must not capture its type token"
            );
            assert!(
                facts
                    .declaration_type_slots
                    .iter()
                    .any(|slot| slot.declaration == field.member)
            );
        }
    }

    #[test]
    fn tuple_and_unit_structs_publish_one_definition_in_type_and_value_namespaces() {
        let source = r#"
pub struct Unit;
pub struct Tuple(pub u32);
pub struct HiddenField(u32);
pub struct Named { pub value: u32 }

fn make() {
    let _ = Unit;
    let _ = Tuple(1);
    let _ = HiddenField(1);
    let _ = Named { value: 1 };
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust struct-constructor fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::TypeDeclaration
            })
            .map(|identifier| {
                (
                    identifier.site,
                    facts.names[identifier.name.index()].spelling.as_str(),
                    identifier.namespace,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            declarations
                .iter()
                .map(|(_, name, namespace)| (*name, *namespace))
                .collect::<Vec<_>>(),
            [
                ("Unit", ResolutionNamespace::Type),
                ("Tuple", ResolutionNamespace::Type),
                ("HiddenField", ResolutionNamespace::Type),
                ("Named", ResolutionNamespace::Type),
            ]
        );

        let additional_names = facts
            .additional_definition_namespaces
            .iter()
            .filter_map(|additional| {
                if additional.namespace != ResolutionNamespace::Value {
                    return None;
                }
                declarations
                    .iter()
                    .find_map(|(site, name, _)| (*site == additional.declaration).then_some(*name))
                    .inspect(|_| assert_eq!(additional.hoisting, HoistingClass::ScopeWide))
            })
            .collect::<Vec<_>>();
        assert_eq!(additional_names, ["Unit", "Tuple", "HiddenField"]);

        let exported_values = facts
            .root_exports
            .iter()
            .filter(|export| export.namespace == ResolutionNamespace::Value)
            .filter(|export| {
                declarations
                    .iter()
                    .any(|(site, _, _)| *site == export.declaration)
            })
            .map(|export| {
                declarations
                    .iter()
                    .find_map(|(site, name, _)| (*site == export.declaration).then_some(*name))
                    .expect("value root export belongs to a struct declaration")
            })
            .collect::<Vec<_>>();
        assert_eq!(exported_values, ["Unit", "Tuple"]);

        for name in ["Unit", "Tuple", "HiddenField"] {
            assert!(facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == name
            }));
        }
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Type
                && facts.names[identifier.name.index()].spelling == "Named"
        }));
    }

    #[test]
    fn root_glob_import_demands_only_references_in_its_module() {
        let source = r#"
use engine::imported;
use engine::*;

fn caller(_: imported) -> WildcardType {
    imported();
    wildcard();
    wildcard_macro!();
    loop {}
}

mod nested {
    fn caller() {
        excluded();
    }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse Rust glob fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert_eq!(facts.root_imports.len(), 2);
        let import = facts.root_imports[1];
        let route = facts
            .root_import_segments
            .iter()
            .filter(|segment| segment.import_site == import.site)
            .map(|segment| facts.names[segment.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(route, ["engine"]);
        let demands = facts
            .root_import_demands
            .iter()
            .filter(|demand| demand.import_site == import.site)
            .map(|demand| {
                (
                    demand.namespace,
                    facts.names[demand.name.index()].spelling.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            demands,
            BTreeSet::from([
                (ResolutionNamespace::Macro, "wildcard_macro"),
                (ResolutionNamespace::Type, "WildcardType"),
                (ResolutionNamespace::Value, "wildcard"),
            ])
        );
        assert_eq!(
            facts
                .root_import_kinds
                .iter()
                .find(|kind| kind.import_site == import.site)
                .map(|kind| kind.kind),
            Some(ResolutionRootImportKind::Glob)
        );
        assert!(facts.root_import_demand_targets.iter().all(|target| {
            target.import_site != import.site
                || target.target == ResolutionRootImportDemandTarget::SameNameGlob
        }));
    }

    #[test]
    fn exported_macros_keep_scope_wide_root_visibility() {
        let source = r#"
before!();

#[macro_export]
macro_rules! exported {
    () => {};
}

exported!();
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust macro fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let declaration = facts
            .identifiers
            .iter()
            .find(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .expect("macro declaration");
        assert_eq!(declaration.namespace, ResolutionNamespace::Macro);
        let binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == declaration.site)
            .expect("macro binder");
        assert_eq!(binder.kind, ResolutionBinderKind::Macro);
        assert_eq!(binder.hoisting, HoistingClass::ScopeWide);
        assert!(
            facts
                .additional_definition_namespaces
                .iter()
                .any(|authority| {
                    authority.declaration == declaration.site
                        && authority.namespace == ResolutionNamespace::Macro
                        && authority.hoisting == HoistingClass::ScopeWide
                })
        );
        assert!(
            facts
                .visibility_eligibilities
                .iter()
                .any(|eligibility| eligibility.declaration == declaration.site)
        );
        assert_eq!(binder.activation_start, facts.scopes[0].start_byte);
        assert_eq!(binder.activation_end, facts.scopes[0].end_byte);
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
                .collect::<Vec<_>>(),
            ["before", "exported"]
        );
        assert!(facts.root_exports.iter().any(|export| {
            export.declaration == declaration.site && export.namespace == ResolutionNamespace::Macro
        }));
    }

    // Found while capturing the R4.2 native differential leg: the native binary
    // could not index zellij at all, because
    // `zellij-server/src/lib.rs` puts a `#[cfg(unix)]`-gated `use` inside a
    // block expression. The producer published an UnsupportedPlacementBoundary
    // gap whose attachment scope is a Block, and
    // `fact_lowering::placement_scope` asserts that a placement-boundary gap
    // names a root CompilationUnit or Package attachment scope, so
    // `prepare_parsed_blob_at_generations::<RustAdapter>` panicked on the file.
    //
    // Decision 7 retains cfg imports with their lexical attachment. Selection
    // owns activation; no block may masquerade as a module placement boundary.
    #[test]
    fn cfg_gated_use_in_a_block_keeps_a_root_placement_frontier() {
        let source = r#"
pub mod inner {
    pub fn helper() {}
}

pub fn spawn() {
    let _body = {
        #[cfg(unix)]
        use crate::inner::helper;
        move || {}
    };
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse block-scoped cfg use fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        for gap in &facts.gaps {
            if gap.kind != ResolutionGapKind::UnsupportedPlacementBoundary {
                continue;
            }
            let scope = facts.scopes[facts.sites[gap.site.index()].scope.index()];
            assert!(
                matches!(
                    scope.kind,
                    ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
                ),
                "a placement boundary must attach to a root compilation-unit or package scope, \
                 otherwise fact_lowering::placement_scope aborts the whole file: {scope:?}"
            );
        }

        assert!(
            facts.root_imports.iter().any(|import| {
                let scope = facts.scopes[import.root_scope.index()];
                scope.kind == ResolutionScopeKind::Block
            }),
            "cfg imports retain their exact lexical scope for selection"
        );
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "enumerating a cfg import is complete source inventory"
        );
    }

    #[test]
    fn cfg_gated_routes_choose_their_gap_from_the_scope_that_would_bind_them() {
        let source = r#"
#[cfg(unix)]
use engine::root_gated;

pub fn spawn() {
    #[cfg(unix)]
    use engine::body_gated;
    #[cfg(windows)]
    mod body_module {}
    #[cfg(test)]
    extern crate body_crate;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse cfg-gated route fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let gaps = facts
            .gaps
            .iter()
            .map(|gap| {
                let site = facts.sites[gap.site.index()];
                (
                    &source[site.start_byte..site.end_byte],
                    gap.kind,
                    facts.scopes[site.scope.index()].kind,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            gaps,
            vec![
                (
                    "body_module",
                    ResolutionGapKind::UnprovenActivation,
                    ResolutionScopeKind::Executable
                ),
                (
                    "body_module",
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                    ResolutionScopeKind::Executable
                ),
            ],
            "conditional declarations retain activation proof; local module projection retains its independent boundary"
        );
        assert_eq!(
            facts.root_imports.len(),
            2,
            "both cfg use routes are retained"
        );
    }

    #[test]
    fn cfg_owned_regions_are_retained_with_activation_proof_obligations() {
        let source = r#"
#[cfg(feature = "selected")]
pub fn disabled() {}

#[cfg(feature = "selected")]
mod disabled_module {
    pub fn nested() {}
}

#[cfg(feature = "selected")]
use engine::target as disabled_import;

fn caller() {
    disabled();
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse cfg-gated Rust fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            declarations,
            ["disabled", "disabled_module", "nested", "caller"]
        );
        assert_eq!(
            facts
                .root_exports
                .iter()
                .filter(|export| export.root_scope == ResolutionScopeId::new(0))
                .filter_map(|export| {
                    facts
                        .identifiers
                        .iter()
                        .find(|identifier| {
                            identifier.site == export.declaration
                                && identifier.role == ResolutionIdentifierRole::Declaration
                        })
                        .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
                })
                .collect::<Vec<_>>(),
            // A cfg-gated `pub fn` exports its name and carries an activation
            // obligation with it; a cfg-gated inline module is the same shape
            // and exports on the same terms. Only a cfg-gated `mod name;`,
            // whose body is in another compilation unit, has no export to
            // publish from here.
            ["disabled", "disabled_module", "caller"]
        );
        assert_eq!(facts.root_imports.len(), 1);
        assert!(
            facts
                .identifiers
                .iter()
                .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                .any(|identifier| facts.names[identifier.name.index()].spelling == "disabled")
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnprovenActivation)
                .count(),
            3
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
                .count(),
            0,
            "an inline cfg module states no placement boundary; its activation \
             obligation is counted above: {:?}",
            gap_inventory(&facts, source)
        );

        let crate_source = "#![cfg(feature = \"selected\")]\npub fn disabled_crate() {}\n";
        let crate_tree = parser
            .parse(crate_source, None)
            .expect("parse cfg-gated Rust crate fixture");
        let crate_facts = extract_rust_resolution_facts(crate_tree.root_node(), crate_source);
        assert_eq!(crate_facts.identifiers.len(), 1);
        assert_eq!(crate_facts.root_exports.len(), 1);
        assert_eq!(crate_facts.gaps.len(), 1);
    }

    #[test]
    fn cfg_module_activation_is_owned_by_the_selected_package_route() {
        let source = r#"
mod pulse {
    #[cfg(feature = "disabled")]
    mod generated;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse nested cfg module fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert!(facts.reference_enumeration_gaps.is_empty());
        assert_eq!(facts.gaps.len(), 2);
        assert_eq!(
            facts.gaps[0].kind,
            ResolutionGapKind::UnsupportedPlacementBoundary
        );
        let generated = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "generated"
            })
            .unwrap();
        assert!(
            facts
                .binders
                .iter()
                .any(|binder| binder.declaration == generated.site),
            "the selected route must be able to bind an activated file module"
        );
        assert!(
            facts.gaps.iter().any(|gap| gap.site == generated.site
                && gap.kind == ResolutionGapKind::UnprovenActivation)
        );
        let package = facts
            .scopes
            .iter()
            .find(|scope| scope.kind == ResolutionScopeKind::Package)
            .expect("outer module keeps its package scope");
        assert_eq!(package.kind, ResolutionScopeKind::Package);
        assert_eq!(package.parent, Some(ResolutionScopeId::new(0)));
        let owner = package.owner.expect("inline module owns package scope");
        assert_eq!(
            facts.sites[owner.index()].kind,
            ResolutionSiteKind::ModuleDeclaration
        );
        assert_eq!(facts.sites[owner.index()].scope, ResolutionScopeId::new(0));
    }

    #[test]
    fn procedural_attributes_and_members_are_explicit_resolution_boundaries() {
        let source = r#"
#[derive(Clone)]
struct Retained;

#[allow(dead_code)]
fn linted() {}

#[runtime::entry]
fn transformed() {}

trait Service {
    fn trait_method(&self);
}

impl Retained {
    fn inherent_method(&self) {}
}

fn caller(value: Retained) {
    linted();
    transformed();
    let _ = value;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust procedural-boundary fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            declarations,
            BTreeSet::from([
                "Retained",
                "Service",
                "caller",
                "inherent_method",
                "linted",
                "self",
                "trait_method",
                "value",
            ])
        );
        assert!(!declarations.contains("transformed"));
        assert!(declarations.contains("trait_method"));

        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<BTreeSet<_>>();
        assert!(references.contains("Retained"));
        assert!(references.contains("linted"));
        assert!(references.contains("transformed"));
        assert!(references.contains("value"));
        assert!(!references.contains("self"));

        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder)
                .count(),
            1,
            "only the transforming attribute can replace a free lexical binder"
        );
        assert_eq!(
            facts
                .reference_enumeration_gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder)
                .count(),
            1,
            "only the transformed function omits references from enumeration"
        );
        // `#[derive(Clone)]` does not skip `struct Retained;`: it is walked in
        // full, so the authored reference set is complete and the derive must
        // not open enumeration. It names the surface the expansion would add
        // instead, positioned on the item and carried only by the semantic
        // gaps.
        let generated = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::GeneratedItemSurface)
            .map(|gap| {
                let site = facts.sites[gap.site.index()];
                &source[site.start_byte..site.end_byte]
            })
            .collect::<Vec<_>>();
        assert_eq!(generated, vec!["struct Retained;"]);
        assert!(
            facts
                .reference_enumeration_gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::GeneratedItemSurface),
            "a generated surface is not a hole in the authored reference set"
        );
        let surfaces = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedMemberScope)
            .map(|gap| {
                let site = facts.sites[gap.site.index()];
                &source[site.start_byte..site.end_byte]
            })
            .collect::<Vec<_>>();
        assert!(
            surfaces.is_empty(),
            "trait signatures have member owners: {surfaces:?}"
        );
        assert!(facts.member_owners.iter().any(|owner| {
            let site = facts.sites[owner.member.index()];
            &source[site.start_byte..site.end_byte] == "trait_method"
                && owner.kind == ResolutionMemberKind::Method
                && owner.access == ResolutionMemberAccess::Instance
        }));
        assert!(
            facts
                .reference_enumeration_gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedMemberScope),
            "trait dispatch uncertainty does not omit signature references"
        );
    }

    #[test]
    fn type_declarations_own_their_type_dependencies() {
        for (declaration, expected) in [
            ("type Alias = Item;", "Alias"),
            ("type Alias<T> = (Item, T);", "Alias"),
            ("struct Container { value: Item }", "Container"),
            (
                "struct Container<T> { value: Item, marker: T }",
                "Container",
            ),
            ("struct Container(Item);", "Container"),
            ("enum Container { Value(Item) }", "Container"),
            ("trait Api { type Alias: Into<Item>; }", "Alias"),
            (
                "trait Api { type Alias; } impl Api for Item { type Alias = Item; }",
                "Alias",
            ),
        ] {
            let source = format!("struct Item; {declaration}");
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            assert!(!tree.root_node().has_error(), "{source}");
            let facts = extract_rust_resolution_facts(tree.root_node(), &source);
            // The last Item token is the dependency, not an impl subject.
            let offset = source.rfind("Item").unwrap();
            let identifier = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.sites[identifier.site.index()].start_byte == offset
                })
                .expect("positioned type dependency");
            let owner = facts
                .reference_owners
                .iter()
                .find(|row| row.reference == identifier.site)
                .and_then(|row| row.owner)
                .unwrap_or_else(|| panic!("missing declaration owner: {source}"));
            let owner = facts.sites[owner.index()];
            assert_eq!(
                &source[owner.start_byte..owner.end_byte],
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn turbofish_values_retain_bare_names_without_duplicating_calls() {
        let source = "struct Unit<const N: usize>; fn identity<T>() {} fn use_values() { let _unit = Unit::<4>; let _function = identity::<u8>; identity::<u8>(); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        for (written, name, expected_kind) in [
            ("Unit::<4>", "Unit", ResolutionSiteKind::ValueReference),
            (
                "identity::<u8>;",
                "identity",
                ResolutionSiteKind::ValueReference,
            ),
            (
                "identity::<u8>();",
                "identity",
                ResolutionSiteKind::CallableReference,
            ),
        ] {
            let start = source.find(written).unwrap();
            let references = facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == name
                        && facts.sites[identifier.site.index()].start_byte == start
                })
                .collect::<Vec<_>>();
            assert_eq!(
                references.len(),
                1,
                "one reference for {written}: {references:?}"
            );
            assert_eq!(facts.sites[references[0].site.index()].kind, expected_kind);
        }
    }

    #[test]
    fn impl_method_generic_bounds_retain_the_callable_owner() {
        for implementation in [
            "impl Item { fn target<T: Bound, U>(value: T) where U: Bound {} }",
            "impl Api for Item { fn target<T: Bound, U>(value: T) where U: Bound {} }",
        ] {
            let source = format!("trait Bound {{}} trait Api {{}} struct Item; {implementation}");
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            assert!(!tree.root_node().has_error(), "{source}");
            let facts = extract_rust_resolution_facts(tree.root_node(), &source);
            let mut count = 0;
            for identifier in &facts.identifiers {
                if identifier.role != ResolutionIdentifierRole::Reference
                    || facts.names[identifier.name.index()].spelling != "Bound"
                {
                    continue;
                }
                let owner = facts
                    .reference_owners
                    .iter()
                    .find(|row| row.reference == identifier.site)
                    .and_then(|row| row.owner)
                    .unwrap_or_else(|| panic!("bound has no callable owner: {source}"));
                let site = facts.sites[owner.index()];
                assert_eq!(
                    &source[site.start_byte..site.end_byte],
                    "target",
                    "{source}"
                );
                count += 1;
            }
            assert_eq!(count, 2, "inline and where-clause bounds: {source}");
        }
    }

    #[test]
    fn function_signature_references_retain_the_callable_owner() {
        for function in [
            "fn target(value: Item) -> Item { value }",
            "fn target<T>(value: Item) -> Item { value }",
            "impl Item { fn target(value: Item) -> Item { value } }",
            "impl Item { fn target<T>(value: Item) -> Item { value } }",
            "trait Api { fn target(value: Self) -> Self; } impl Api for Item { fn target(value: Item) -> Item { value } }",
            "trait Api { fn target(value: Item) -> Item; }",
            "trait Api { fn target<T>(value: Item) -> Item; }",
            "trait Api { fn target(value: Item) -> Item { value } }",
            "trait Api { fn target<T>(value: Item) -> Item { value } }",
            "unsafe extern \"C\" { fn target(value: Item) -> Item; }",
        ] {
            let source = format!("struct Item; {function} type Outside = Item;");
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            assert!(!tree.root_node().has_error(), "{source}");
            let facts = extract_rust_resolution_facts(tree.root_node(), &source);
            let mut owned = 0;
            for identifier in &facts.identifiers {
                if identifier.role != ResolutionIdentifierRole::Reference
                    || facts.names[identifier.name.index()].spelling != "Item"
                {
                    continue;
                }
                let owner = facts
                    .reference_owners
                    .iter()
                    .find(|owner| owner.reference == identifier.site)
                    .unwrap()
                    .owner;
                let site = facts.sites[identifier.site.index()];
                if site.start_byte >= source.rfind("fn target").unwrap()
                    && site.start_byte < source.find("type Outside").unwrap()
                {
                    let owner = facts.sites[owner
                        .unwrap_or_else(|| {
                            panic!("signature reference at {site:?} has no owner: {source}")
                        })
                        .index()];
                    assert_eq!(
                        &source[owner.start_byte..owner.end_byte],
                        "target",
                        "{source}"
                    );
                    owned += 1;
                } else if site.start_byte >= source.find("type Outside").unwrap() {
                    let owner = facts.sites[owner.expect("alias owns its target").index()];
                    assert_eq!(
                        &source[owner.start_byte..owner.end_byte],
                        "Outside",
                        "function owner leaked into adjacent alias: {source}"
                    );
                }
            }
            assert_eq!(owned, 2, "parameter and return type: {source}");
        }
    }

    #[test]
    fn named_import_references_retain_original_grouped_target_tokens() {
        let source = "use crate::api::{target as local, other};";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse grouped imports");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 8);
        assert_eq!(facts.root_import_kinds.len(), 2);
        assert!(
            facts
                .root_import_kinds
                .iter()
                .all(|fact| fact.kind == ResolutionRootImportKind::Named)
        );
        assert_eq!(facts.root_import_demand_targets.len(), 6);
        assert!(facts.root_import_demand_targets.iter().all(|target| {
            let ResolutionRootImportDemandTarget::NamedReference(reference) = target.target else {
                return false;
            };
            facts.identifiers.iter().any(|identifier| {
                identifier.site == reference
                    && identifier.namespace == target.namespace
                    && identifier.role == ResolutionIdentifierRole::Reference
            })
        }));
        for reference in references {
            let site = facts.sites[reference.site.index()];
            assert_eq!(site.kind, ResolutionSiteKind::ImportDeclaration);
            let spelling = facts.names[reference.name.index()].spelling.as_str();
            assert!(matches!(spelling, "target" | "other" | "api" | "crate"));
            assert_eq!(&source[site.start_byte..site.end_byte], spelling);
            assert_eq!(
                facts
                    .root_reference_segments
                    .iter()
                    .filter(|segment| segment.reference == reference.site)
                    .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                    .collect::<Vec<_>>(),
                if matches!(spelling, "api" | "crate") {
                    vec!["crate"]
                } else {
                    vec!["crate", "api"]
                }
            );
        }
    }

    #[test]
    fn ordinary_inherent_impl_reference_inventory_is_complete() {
        let source =
            "pub struct Service; impl Service { fn method(&self, value: usize) {} } fn caller() {}";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse inherent impl");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert_eq!(facts.relation_members.len(), 1);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        // A method call supplies `self` through its receiver slot, so `value`
        // is the method's one parameter row and its inventory is exact.
        assert_eq!(
            facts
                .callable_parameters
                .iter()
                .map(|parameter| (
                    source_text(&facts, source, parameter.callable),
                    parameter.ordinal,
                    source_text(&facts, source, parameter.parameter),
                ))
                .collect::<Vec<_>>(),
            [("method", 0, "value")]
        );
        assert!(
            !facts
                .gaps
                .iter()
                .any(|gap| { gap.kind == ResolutionGapKind::UnsupportedCallApplicability })
        );
    }

    #[test]
    fn emitted_method_calls_do_not_reopen_reference_inventory() {
        let source = concat!(
            "pub mod hidden;\n",
            "pub fn target(value: usize) {}\n",
            "pub async fn deferred() {}\n",
            "pub struct Service;\n",
            "impl Service { pub fn method(&self, value: usize) {} }\n",
            "pub fn caller(service: Service) { target(1); service.method(2); deferred(); }\n",
            "pub fn empty() {}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse method call");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "method"
        }));
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );

        let source = "fn caller(service: Service) { let value = service.field; }";
        let tree = parser.parse(source, None).expect("parse field read");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let field = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "field"
            })
            .expect("a value-position member read publishes its reference");
        let site = facts.sites[field.site.index()];
        assert_eq!(site.kind, ResolutionSiteKind::MemberReference);
        assert_eq!(&source[site.start_byte..site.end_byte], "field");
        assert_eq!(field.namespace, ResolutionNamespace::Value);
        let qualifier = field
            .qualifier
            .expect("a member reference retains its receiver slot");
        let receiver = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "service"
            })
            .expect("the receiver value publishes its reference");
        let receiver_value = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == receiver.site && slot.role == ResolutionTypeSlotRole::ExpressionValue
            })
            .expect("the receiver value publishes its expression-value slot");
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.kind == ResolutionTypeTransferKind::Receiver
                && transfer.input == receiver_value.id
                && transfer.output == qualifier
        }));
        assert!(
            !enumeration_gap_inventory(&facts, source)
                .contains(&("field", ResolutionGapKind::UnsupportedExpression)),
            "the member read is lowered, so no unlowered boundary remains"
        );
    }

    #[test]
    fn inherent_impl_unsupported_children_retain_inventory_boundaries() {
        let source = "struct Service; impl Service { type Alias = Missing; }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser.parse(source, None).expect("associated type");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(facts.reference_enumeration_gaps.is_empty());
        assert_eq!(
            reference_sites(&facts, "Missing", ResolutionNamespace::Type).len(),
            1
        );
        assert!(
            facts
                .deferred_member_owners
                .iter()
                .any(|owner| owner.kind == ResolutionMemberKind::AssociatedType)
        );
        let generic = "struct Service; impl<T> Service { fn generic(value: T) {} }";
        let tree = parser.parse(generic, None).expect("generic impl");
        let facts = extract_rust_resolution_facts(tree.root_node(), generic);
        assert!(facts.reference_enumeration_gaps.is_empty());
        assert_eq!(
            reference_sites(&facts, "T", ResolutionNamespace::Type).len(),
            1
        );
        let typed = "struct Service; impl Service { fn typed(self: Box<Self>) {} }";
        let tree = parser
            .parse(typed, None)
            .expect("parse unsupported receiver");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), typed);
        // A typed receiver's binding is unsupported, but it hides no
        // reference: `self` declares, and `Box` and `Self` are enumerated.
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, typed)
        );
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedTypeSyntax),
            "the typed receiver keeps its resolution gap: {typed}"
        );
        assert_eq!(
            reference_sites(&facts, "Box", ResolutionNamespace::Type).len(),
            1
        );
        // An associated constant's value is ordinary source. It is enumerated,
        // and the constant itself is a member of the impl's subject.
        let constant = "struct Service; impl Service { const VALUE: usize = missing(); }";
        let tree = parser
            .parse(constant, None)
            .expect("parse associated const");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), constant);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, constant)
        );
        assert_eq!(
            reference_sites(&facts, "missing", ResolutionNamespace::Value).len(),
            1,
            "{facts:#?}"
        );
        assert!(
            facts
                .deferred_member_owners
                .iter()
                .any(|owner| owner.kind == ResolutionMemberKind::Field),
            "{facts:#?}"
        );
    }

    #[test]
    fn trait_impl_bodies_retain_references_and_trait_provenance() {
        let source =
            "struct Service; impl Contract for Service { fn method(&self) { self.method(); } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser.parse(source, None).expect("trait impl");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
        let relation = facts.declared_type_relations[0];
        assert_eq!(
            relation.kind,
            ResolutionDeclaredTypeRelationKind::TraitImplementation
        );
        let trait_reference = relation.target_reference.expect("trait reference");
        let site = facts.sites[trait_reference.index()];
        assert_eq!(&source[site.start_byte..site.end_byte], "Contract");
        assert!(facts.gaps.iter().any(|gap| gap.site == trait_reference
            && gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal));
        assert_eq!(facts.relation_members.len(), 1);
        assert!(facts.identifiers.iter().any(|identifier| identifier.role
            == ResolutionIdentifierRole::Reference
            && facts.names[identifier.name.index()].spelling == "method"));
    }

    #[test]
    fn inherent_self_type_references_transfer_the_impl_identity() {
        let source = r#"
struct Service { value: u32 }
impl Service {
    const VALUE: u32 = 1;
    fn factory() -> Self { Self::new() }
    fn new() -> Self { Self { value: Self::VALUE } }
    fn take(_: Self, _: &Self) {}
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse Self references");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "Self"
            })
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 7);
        let subject = facts.declared_type_relations[0].subject;
        for reference in references {
            let outputs = facts
                .type_slots
                .iter()
                .filter(|slot| {
                    slot.site == reference.site
                        && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
                })
                .map(|slot| slot.id)
                .collect::<Vec<_>>();
            assert_eq!(outputs.len(), 1, "one Self identity slot per occurrence");
            assert!(
                facts.type_transfers.iter().any(|transfer| {
                    transfer.input == subject
                        && transfer.output == outputs[0]
                        && transfer.kind == ResolutionTypeTransferKind::TypeIdentity
                        && transfer.indirection_delta == 0
                        && transfer.reference_indirection_delta == 0
                        && transfer.value_transform
                            == ResolutionTypeTransferValueTransform::Preserve
                }),
                "Self transfer missing for reference {reference:?}, output {:?}, subject {subject:?}; transfers: {:?}",
                outputs[0],
                facts.type_transfers
            );
            // The transfer above is this frontier's one output producer, so the
            // occurrence carries no binding projection. A consumer that reaches
            // a reference's type only through its projections therefore cannot
            // see this frontier and must not read its absence as a proven
            // "no type"; see `adapt_type_answer`.
            assert!(!facts.binding_projections.iter().any(|projection| {
                projection.reference == reference.site
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
            }));
            assert!(!facts.gaps.iter().any(|gap| {
                gap.site == reference.site
                    && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
            }));
        }
        assert_eq!(
            enumeration_gap_inventory(&facts, source),
            Vec::new(),
            "the associated constant is a member of the impl subject, not a gap"
        );
        assert!(
            facts.deferred_member_owners.iter().any(|owner| {
                owner.kind == ResolutionMemberKind::Field
                    && facts.identifiers.iter().any(|identifier| {
                        identifier.site == owner.member
                            && facts.names[identifier.name.index()].spelling == "VALUE"
                    })
            }),
            "{facts:#?}"
        );
    }

    #[test]
    fn trait_self_type_uses_an_abstract_frontier_not_the_trait_declaration() {
        let source = "trait Factory { fn factory() -> Self; }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse trait Self");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let trait_declaration = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "Factory"
            })
            .expect("trait declaration")
            .site;
        assert_eq!(
            facts.sites[trait_declaration.index()].kind,
            ResolutionSiteKind::TypeDeclaration
        );
        let self_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "Self"
            })
            .expect("trait Self reference")
            .site;
        let self_output = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == self_reference
                    && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
            })
            .expect("trait Self identity output")
            .id;
        let transfer = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == self_output
                    && transfer.kind == ResolutionTypeTransferKind::TypeIdentity
            })
            .expect("abstract trait Self transfer");
        let frontier_site = facts.type_slots[transfer.input.index()].site;
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == frontier_site
                && gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal
        }));
        assert!(!facts.binding_projections.iter().any(|projection| {
            projection.output == transfer.input
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        }));
    }

    #[test]
    fn inherent_impls_retain_deferred_members_and_exact_body_owners() {
        let source = r#"
fn free() {}
pub struct Service;

impl Service {
    fn instance(&self) { free(); let _ = self; self.instance(); }
    fn mutable(&mut self) { free(); let _ = self; }
    fn owned(self) { free(); let _ = self; }
    fn owned_mut(mut self) { free(); let _ = self; }
    fn associated() { free(); }
}

impl Service {
    fn typed(self: Box<Self>) { free(); }
}

trait Contract {
    fn skipped(&self);
}

impl Contract for Service {
    fn skipped(&self) { free(); }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse inherent impl fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert_eq!(facts.declared_type_relations.len(), 3);
        assert_eq!(facts.relation_members.len(), 7);
        assert_eq!(
            facts
                .relation_members
                .iter()
                .map(|member| member.ordinal)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 0, 0]
        );
        assert!(facts.relation_members.iter().all(|member| {
            member.kind == ResolutionMemberKind::Method
                && member.relation.index() < facts.declared_type_relations.len()
        }));

        let declaration_named = |name: &str| {
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .map(|identifier| identifier.site)
                .collect::<Vec<_>>()
        };
        let instance = declaration_named("instance");
        let mutable = declaration_named("mutable");
        let owned = declaration_named("owned");
        let owned_mut = declaration_named("owned_mut");
        let associated = declaration_named("associated");
        let typed = declaration_named("typed");
        assert_eq!(instance.len(), 1);
        assert_eq!(mutable.len(), 1);
        assert_eq!(owned.len(), 1);
        assert_eq!(owned_mut.len(), 1);
        assert_eq!(associated.len(), 1);
        assert_eq!(typed.len(), 1);
        let skipped = declaration_named("skipped");
        assert_eq!(skipped.len(), 2);
        assert!(
            facts
                .deferred_member_owners
                .iter()
                .all(|owner| { owner.member != skipped[0] })
        );

        let owner_for = |member| {
            facts
                .deferred_member_owners
                .iter()
                .find(|owner| owner.member == member)
                .expect("inherent method deferred owner")
        };
        let instance_owner = owner_for(instance[0]);
        assert_eq!(instance_owner.kind, ResolutionMemberKind::Method);
        assert_eq!(instance_owner.access, ResolutionMemberAccess::Instance);
        assert_eq!(
            instance_owner.qualifier_compatibility,
            ResolutionMemberQualifierCompatibility::RuntimeOrType
        );
        assert_eq!(owner_for(typed[0]).access, ResolutionMemberAccess::Instance);
        assert_eq!(
            owner_for(typed[0]).qualifier_compatibility,
            ResolutionMemberQualifierCompatibility::RuntimeOrType
        );
        assert_eq!(
            owner_for(associated[0]).access,
            ResolutionMemberAccess::Type
        );
        assert_eq!(
            owner_for(associated[0]).qualifier_compatibility,
            ResolutionMemberQualifierCompatibility::TypeOnly
        );
        let self_declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == "self"
            })
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        assert_eq!(self_declarations.len(), 5);
        let expected_self_types = [
            (instance[0], 1, false),
            (mutable[0], 1, true),
            (owned[0], 0, false),
            (owned_mut[0], 0, true),
        ];
        for (method, indirection_delta, addressable) in expected_self_types {
            let self_declaration = self_declarations
                .iter()
                .copied()
                .find(|declaration| {
                    facts.binders.iter().any(|binder| {
                        binder.declaration == *declaration
                            && binder.kind == ResolutionBinderKind::Parameter
                            && facts.scopes[binder.scope.index()].owner == Some(method)
                    })
                })
                .expect("standard self receiver binder");
            let self_property = facts
                .declaration_type_slots
                .iter()
                .find(|property| {
                    property.declaration == self_declaration
                        && property.role == DeclarationTypeRole::Parameter
                })
                .expect("standard self declared type property");
            let self_transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| transfer.output == self_property.slot)
                .expect("standard self declared type transfer");
            let subject = facts.declared_type_relations[0].subject;
            let subject_reference = facts.type_slots[subject.index()].site;
            assert!(facts.binding_projections.iter().any(|projection| {
                projection.reference == subject_reference
                    && projection.output == self_transfer.input
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
            }));
            assert!(facts.binding_projections.iter().any(|projection| {
                projection.reference == subject_reference
                    && projection.output == subject
                    && projection.kind == BindingProjectionKind::TargetNominalTypeIdentity
            }));
            assert_eq!(self_transfer.indirection_delta, indirection_delta);
            assert_eq!(
                self_transfer.value_transform,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable }
            );
        }
        let self_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == "self"
            })
            .expect("standalone self value reference");
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == self_reference.site
                && projection.kind == BindingProjectionKind::TargetDeclaredValueType
                && facts.type_slots[projection.output.index()].role
                    == ResolutionTypeSlotRole::ExpressionValue
        }));
        let member_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Callable
                    && facts.names[identifier.name.index()].spelling == "instance"
            })
            .expect("self member call reference");
        assert!(facts.callable_receiver_origins.iter().any(|origin| {
            origin.reference == member_reference.site
                && origin.origin == ResolutionCallableReceiverOrigin::CurrentInstance
        }));
        let self_type_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && facts.names[identifier.name.index()].spelling == "Self"
            })
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        // Standard `self` receivers are owned by the deferred member relation.
        // The typed `self: Box<Self>` form is still unsupported as a receiver,
        // but its positioned `Self` type occurrence retains the impl identity.
        assert!(!self_type_references.is_empty());
        assert!(self_type_references.iter().all(|site| {
            facts.type_slots.iter().any(|slot| {
                slot.site == *site
                    && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
                    && facts.type_transfers.iter().any(|transfer| {
                        transfer.input == facts.declared_type_relations[1].subject
                            && transfer.output == slot.id
                            && transfer.kind == ResolutionTypeTransferKind::TypeIdentity
                    })
            })
        }));
        assert!(self_type_references.iter().all(|site| {
            !facts
                .reference_enumeration_gaps
                .iter()
                .any(|gap| gap.site == *site)
        }));

        for declaration in [instance[0], associated[0], typed[0]] {
            assert!(
                !facts
                    .binders
                    .iter()
                    .any(|binder| binder.declaration == declaration)
            );
            assert!(
                !facts
                    .root_exports
                    .iter()
                    .any(|export| export.declaration == declaration)
            );
        }
        let free = declaration_named("free")[0];
        let body_owners = facts
            .reference_owners
            .iter()
            .filter(|owner| owner.reference != free)
            .filter(|owner| {
                facts.identifiers.iter().any(|identifier| {
                    identifier.site == owner.reference
                        && identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "free"
                })
            })
            .map(|owner| owner.owner)
            .collect::<Vec<_>>();
        assert_eq!(
            body_owners,
            vec![
                Some(instance[0]),
                Some(mutable[0]),
                Some(owned[0]),
                Some(owned_mut[0]),
                Some(associated[0]),
                Some(typed[0]),
                Some(skipped[1]),
            ]
        );
    }

    #[test]
    fn handled_qualified_path_retains_generic_argument_calls() {
        let source = "fn value() {}\nfn caller() { Service::<{ value() }>::target(); }\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse generic path fixture");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let calls = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::CallableReference
            })
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(calls, BTreeSet::from(["target", "value"]));
    }

    #[test]
    fn generic_impl_targets_project_the_head_and_retain_argument_evidence() {
        let source = r#"
struct Service<const N: usize>;
fn value() {}

impl<T> Service<{ value() }> {
    fn method() {}
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse generic impl fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert_eq!(facts.declared_type_relations.len(), 1);
        assert_eq!(facts.relation_members.len(), 1);
        assert_eq!(facts.deferred_member_owners.len(), 1);
        let subject = facts.declared_type_relations[0].subject;
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.output == subject
                && projection.kind == BindingProjectionKind::TargetNominalTypeIdentity
                && facts.identifiers.iter().any(|identifier| {
                    identifier.site == projection.reference
                        && facts.names[identifier.name.index()].spelling == "Service"
                })
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            facts.names[identifier.name.index()].spelling == "value"
                && identifier.role == ResolutionIdentifierRole::Reference
        }));
        let gaps = gap_inventory(&facts, source);
        assert!(gaps.contains(&("<{ value() }>", ResolutionGapKind::UnsupportedTypeSyntax,)));
        assert!(
            !gaps
                .iter()
                .any(|(_, kind)| *kind == ResolutionGapKind::UnsupportedScopeOrBinder)
        );
    }

    #[test]
    fn generic_alias_impl_over_unconstrained_parameters_keeps_a_complete_owner() {
        let source = r#"
enum EitherWriter<A, B> { A(A), B(B) }
type OptionalWriter<T> = EitherWriter<T, ()>;
impl<T> OptionalWriter<T> { fn some(value: T) -> Self { EitherWriter::A(value) } }
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse alias impl");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let alias = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "OptionalWriter"
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::TypeAliasDeclaration
            })
            .expect("generic alias declaration")
            .site;
        let alias_identity = facts
            .declaration_type_slots
            .iter()
            .find(|property| {
                property.declaration == alias && property.role == DeclarationTypeRole::Identity
            })
            .expect("generic alias identity")
            .slot;
        let alias_identity_transfer = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.output == alias_identity)
            .expect("generic alias target identity transfer");
        assert_eq!(
            alias_identity_transfer.kind,
            ResolutionTypeTransferKind::TypeIdentity
        );
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.output == alias_identity_transfer.input
                && projection.kind == BindingProjectionKind::TargetNominalTypeIdentity
                && facts.identifiers.iter().any(|identifier| {
                    identifier.site == projection.reference
                        && facts.names[identifier.name.index()].spelling == "EitherWriter"
                })
        }));
        let target_start = source.rfind("OptionalWriter<T>").expect("impl target");
        let arguments_start = target_start + "OptionalWriter".len();
        let argument_start = arguments_start + "<".len();
        assert!(
            facts.gaps.iter().all(|gap| {
                let site = facts.sites[gap.site.index()];
                site.start_byte != arguments_start
                    || gap.kind != ResolutionGapKind::UnsupportedTypeSyntax
            }),
            "the unconstrained impl parameter must not leave an owner gap: {:?}",
            gap_inventory(&facts, source)
        );
        let alias_target_start = source
            .find("EitherWriter<T, ()>")
            .expect("generic alias target");
        let alias_arguments_start = alias_target_start + "EitherWriter".len();
        assert!(
            facts.gaps.iter().all(|gap| {
                let site = facts.sites[gap.site.index()];
                site.start_byte != alias_arguments_start
                    || gap.kind != ResolutionGapKind::UnsupportedTypeSyntax
            }),
            "direct alias parameters and builtin leaves keep the nominal owner complete: {:?}",
            gap_inventory(&facts, source)
        );
        let alias_parameter_argument_start = alias_arguments_start + "<".len();
        assert!(
            facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "T"
                    && facts.sites[identifier.site.index()].start_byte
                        == alias_parameter_argument_start
            }),
            "the alias parameter argument remains enumerated"
        );
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "T"
                && facts.sites[identifier.site.index()].start_byte == argument_start
        }));
    }

    #[test]
    fn owning_smart_pointer_types_project_their_payload_and_keep_the_head_reference() {
        let source = concat!(
            "struct Service;\n",
            "fn take(value: Box<Service>) {}\n",
            "fn hold(value: Wrapper<Service>) {}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse smart pointer fixture");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let reference_named_at = |spelling: &str, start_byte: usize| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == spelling
                        && facts.sites[identifier.site.index()].start_byte == start_byte
                })
                .unwrap_or_else(|| panic!("{spelling} reference at {start_byte}"))
                .site
        };
        let identity_of = |site| {
            facts
                .type_slots
                .iter()
                .find(|slot| {
                    slot.site == site && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
                })
                .unwrap_or_else(|| panic!("type identity slot for site {site:?}"))
                .id
        };
        let declared_input = |declaration_start: usize| {
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.sites[identifier.site.index()].start_byte == declaration_start
                })
                .expect("parameter declaration")
                .site;
            let slot = facts
                .declaration_type_slots
                .iter()
                .find(|property| {
                    property.declaration == declaration
                        && property.role == DeclarationTypeRole::Parameter
                })
                .expect("parameter declared type property")
                .slot;
            facts
                .type_transfers
                .iter()
                .find(|transfer| transfer.output == slot)
                .copied()
                .expect("parameter declared type transfer")
        };

        // `Box<Service>` dereferences to `Service`, so the declared value is
        // the payload at the pointer's own depth, and the arguments carry no
        // gap because the payload is proven.
        let boxed = declared_input(source.find("value: Box").expect("boxed parameter"));
        assert_eq!(
            boxed.input,
            identity_of(reference_named_at(
                "Service",
                source.find("Box<Service>").expect("boxed payload") + "Box<".len()
            ))
        );
        assert_eq!(
            (boxed.indirection_delta, boxed.reference_indirection_delta),
            (0, 0)
        );
        // The head stays in the reference inventory through the ordinary walker.
        reference_named_at("Box", source.find("Box<Service>").expect("boxed head"));

        // An ordinary generic head is unchanged: the head is the declared type
        // and the arguments remain an explicit gap.
        let held = declared_input(source.find("value: Wrapper").expect("wrapper parameter"));
        assert_eq!(
            held.input,
            identity_of(reference_named_at(
                "Wrapper",
                source.find("Wrapper<Service>").expect("wrapper head")
            ))
        );
        assert!(
            gap_inventory(&facts, source)
                .contains(&("<Service>", ResolutionGapKind::UnsupportedTypeSyntax))
        );
    }

    #[test]
    fn unwrapped_let_initializers_discharge_the_option_and_result_payload_layer() {
        let source = concat!(
            "struct Service;\n",
            "struct Error;\n",
            "fn make() -> Result<Service, Error> { loop {} }\n",
            "fn direct() -> Service { loop {} }\n",
            "fn caller(opt: Option<Service>) {\n",
            "    let expected = make().expect(\"x\");\n",
            "    let tried = make()?;\n",
            "    let taken = opt.unwrap();\n",
            "    let plain = direct();\n",
            "}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse unwrap fixture");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let site_at = |start_byte: usize| {
            facts
                .identifiers
                .iter()
                .find(|identifier| facts.sites[identifier.site.index()].start_byte == start_byte)
                .unwrap_or_else(|| panic!("identifier at {start_byte}"))
                .site
        };
        let declared_value_of = |declaration| {
            facts
                .declaration_type_slots
                .iter()
                .find(|property| {
                    property.declaration == declaration
                        && property.role == DeclarationTypeRole::Value
                })
                .expect("declared value property")
                .slot
        };
        let producer_of = |slot| {
            facts
                .type_transfers
                .iter()
                .find(|transfer| transfer.output == slot)
                .copied()
                .unwrap_or_else(|| panic!("producing transfer for slot {slot:?}"))
        };
        let projection_output_of = |reference, kind| {
            facts
                .binding_projections
                .iter()
                .find(|projection| projection.reference == reference && projection.kind == kind)
                .unwrap_or_else(|| panic!("{kind:?} projection for reference {reference:?}"))
                .output
        };

        // `Result<Service, Error>` is not transparent: its payload sits behind
        // one unproven layer that only an unwrap discharges. The declared
        // return type therefore carries (1, 0), and `Option<Service>` the same.
        let returned = producer_of(
            facts
                .declaration_type_slots
                .iter()
                .find(|property| {
                    property.role == DeclarationTypeRole::Return
                        && property.declaration == site_at(source.find("make").expect("make"))
                })
                .expect("make return property")
                .slot,
        );
        assert_eq!(
            (
                returned.kind,
                returned.indirection_delta,
                returned.reference_indirection_delta
            ),
            (ResolutionTypeTransferKind::DeclaredType, 1, 0)
        );
        let parameter = producer_of(
            facts
                .declaration_type_slots
                .iter()
                .find(|property| property.role == DeclarationTypeRole::Parameter)
                .expect("opt parameter property")
                .slot,
        );
        assert_eq!(
            (
                parameter.indirection_delta,
                parameter.reference_indirection_delta
            ),
            (1, 0)
        );

        // Each unwrap layer produces an intermediate call result, and the
        // zero-delta Initialization transfer carries it into the binding.
        let unwrapped_binding = |declaration_start: usize, operand: ResolutionTypeSlotId| {
            let initialization = producer_of(declared_value_of(site_at(declaration_start)));
            assert_eq!(
                (
                    initialization.kind,
                    initialization.indirection_delta,
                    initialization.reference_indirection_delta,
                    initialization.value_transform
                ),
                (
                    ResolutionTypeTransferKind::Initialization,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve
                )
            );
            assert_eq!(
                facts.type_slots[initialization.input.index()].role,
                ResolutionTypeSlotRole::CallResult
            );
            let unwrap = producer_of(initialization.input);
            assert_eq!(
                (
                    unwrap.kind,
                    unwrap.indirection_delta,
                    unwrap.reference_indirection_delta,
                    unwrap.value_transform
                ),
                (
                    ResolutionTypeTransferKind::Unwrap,
                    -1,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve
                )
            );
            assert_eq!(unwrap.input, operand);
        };
        let call_result_of = |call_start: usize| {
            projection_output_of(
                site_at(call_start),
                BindingProjectionKind::TargetCallableResultType,
            )
        };
        unwrapped_binding(
            source.find("expected").expect("expected binding"),
            call_result_of(source.find("make().expect").expect("expect receiver")),
        );
        unwrapped_binding(
            source.find("tried").expect("tried binding"),
            call_result_of(source.find("make()?").expect("try receiver")),
        );
        // A runtime identifier operand supplies an expression value instead.
        unwrapped_binding(
            source.find("taken").expect("taken binding"),
            projection_output_of(
                site_at(source.find("opt.unwrap").expect("opt receiver")),
                BindingProjectionKind::TargetDeclaredValueType,
            ),
        );

        // A bare direct call keeps the R3.4 contract: one zero-delta
        // Initialization straight from the call result.
        let plain = producer_of(declared_value_of(site_at(
            source.find("plain").expect("plain binding"),
        )));
        assert_eq!(
            (plain.kind, plain.indirection_delta),
            (ResolutionTypeTransferKind::Initialization, 0)
        );
        assert_eq!(
            plain.input,
            call_result_of(source.find("direct();").expect("direct call"))
        );
    }

    #[test]
    fn builtin_inert_attribute_preserves_function_resolution() {
        for attributes in [
            "#[test]",
            "#[test] #[ignore]",
            "#[test] #[ignore = \"needs corpus\"]",
            "#[test] #[should_panic]",
            "#[test] #[should_panic(expected = \"failure\")]",
            "#[unsafe(no_mangle)]",
            "#[unsafe(export_name = \"fixture_export\")]",
            "#[unsafe(link_section = \"fixture_section\")]",
        ] {
            let source = r#"
fn target() {}

$ATTRIBUTES
fn verifies_target() {
    target();
}
"#
            .replace("$ATTRIBUTES", attributes);
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .expect("set Rust grammar");
            let tree = parser
                .parse(&source, None)
                .expect("parse Rust test-attribute fixture");
            assert!(
                !tree.root_node().has_error(),
                "{attributes}: {}",
                tree.root_node().to_sexp()
            );
            let facts = extract_rust_resolution_facts(tree.root_node(), &source);

            assert_eq!(
                gap_inventory(&facts, &source),
                vec![("target", ResolutionGapKind::UnsupportedCallApplicability,)],
                "the zero-argument call retains only its callee applicability gap"
            );
            assert!(
                facts.reference_enumeration_gaps.is_empty(),
                "unexpected enumeration gaps: {:?}",
                facts.reference_enumeration_gaps,
            );
            assert!(facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "verifies_target"
            }));
            assert!(facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == "target"
            }));
        }
    }

    #[test]
    fn constants_and_statics_bind_in_the_rust_value_namespace() {
        let source = r#"
pub const EXPORTED: usize = 1;
static LOCAL: usize = 2;

fn caller() -> usize {
    EXPORTED + LOCAL
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust value-item fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        for name in ["EXPORTED", "LOCAL"] {
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .unwrap_or_else(|| panic!("{name} declaration"));
            assert_eq!(declaration.namespace, ResolutionNamespace::Value);
            assert_eq!(
                facts.sites[declaration.site.index()].kind,
                ResolutionSiteKind::ValueDeclaration
            );
            assert!(facts.binders.iter().any(|binder| {
                binder.declaration == declaration.site
                    && binder.kind == ResolutionBinderKind::Field
                    && binder.hoisting == HoistingClass::ScopeWide
            }));
            assert!(facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == name
            }));
        }
        let exported = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "EXPORTED"
            })
            .expect("exported constant declaration");
        assert!(facts.root_exports.iter().any(|export| {
            export.declaration == exported.site && export.namespace == ResolutionNamespace::Value
        }));
        assert!(facts.gaps.is_empty());
    }

    #[test]
    fn bare_conditions_and_assignment_sides_are_value_references() {
        let source = r#"
static READY: bool = true;
static mut COUNTER: usize = 0;

fn caller() {
    if READY {
        unsafe { COUNTER = COUNTER + 1; }
        let _ = 0..COUNTER;
    }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust bare-value fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(references, ["READY", "COUNTER", "COUNTER", "COUNTER"]);
        assert!(facts.gaps.is_empty());
    }

    #[test]
    fn foreign_functions_bind_as_module_callables() {
        let source = r#"
#[link(name = "native")]
unsafe extern "C" {
    fn foreign(input: i32) -> i32;
}

fn caller(input: i32) -> i32 {
    unsafe { foreign(input) }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust foreign-function fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let foreign = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "foreign"
            })
            .expect("foreign function declaration");
        assert_eq!(foreign.namespace, ResolutionNamespace::Value);
        assert_eq!(
            facts.sites[foreign.site.index()].kind,
            ResolutionSiteKind::CallableDeclaration
        );
        assert!(facts.binders.iter().any(|binder| {
            binder.declaration == foreign.site
                && binder.kind == ResolutionBinderKind::Callable
                && binder.hoisting == HoistingClass::ScopeWide
                && binder.scope == ResolutionScopeId::new(0)
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Value
                && facts.names[identifier.name.index()].spelling == "foreign"
        }));
        assert_eq!(
            gap_inventory(&facts, source),
            vec![
                ("foreign", ResolutionGapKind::UnsupportedCallApplicability),
                ("foreign", ResolutionGapKind::UnsupportedCallApplicability),
            ],
            "a foreign function lowers no parameter declarations, so its declaration keeps \
             the gap; the call's one argument is exactly represented, so only the callee's \
             own obligation remains"
        );
    }

    #[test]
    fn local_items_are_incomplete_binders_and_foreign_types_are_point_boundaries() {
        let source = r#"
unsafe extern "C" {
    type Opaque;
}

fn caller() {
    fn local() {}
    struct Local;
    const LOCAL: usize = 1;
    local();
    let _: Option<Local> = None;
    let _ = LOCAL;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust unprojectable-item fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(declarations, ["caller", "local", "Local", "LOCAL"]);
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<BTreeSet<_>>();
        assert!(references.contains("local"));
        assert!(references.contains("Local"));
        assert!(references.contains("LOCAL"));
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder)
                .count(),
            4,
            "the extern type is a point boundary and three local declarations retain incomplete projection evidence"
        );
    }

    #[test]
    fn include_builtin_is_a_splice_boundary_but_a_declared_macro_keeps_replay() {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let source = "include!(\"generated.rs\");";
        let tree = parser.parse(source, None).expect("include syntax");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(facts.identifiers.is_empty());
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder)
        );
        let source = "struct Item; macro_rules! include { ($t:ty) => { fn item(_: $t) {} }; } include!(Item);";
        let tree = parser.parse(source, None).expect("shadowed include syntax");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        // The unit struct's own-construction marker, and the declared macro's
        // expansion: its rule writes `fn item`, which no row holds, so the
        // invocation is an unexpanded item macro rather than a splice.
        assert_eq!(
            gap_inventory(&facts, source),
            vec![
                ("Item", ResolutionGapKind::ImplicitConstructor),
                ("include!(Item)", ResolutionGapKind::UnexpandedItemMacro),
            ],
            "{:?}",
            facts.gaps
        );
        assert!(facts.identifiers.iter().any(|identifier| identifier.role
            == ResolutionIdentifierRole::Reference
            && identifier.namespace == ResolutionNamespace::Type
            && facts.names[identifier.name.index()].spelling == "Item"));
    }

    #[test]
    fn extern_crate_names_do_not_become_lexical_value_references() {
        let source = r#"
extern crate engine as dependency;
use dependency::Item;

fn caller(value: Item) {}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust extern-crate fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        assert!(!facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Value
                && matches!(
                    facts.names[identifier.name.index()].spelling.as_str(),
                    "engine" | "dependency"
                )
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Type
                && facts.names[identifier.name.index()].spelling == "Item"
        }));
        let extern_start = source.find("extern crate").expect("extern declaration");
        assert!(facts.reference_enumeration_gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && facts.sites[gap.site.index()].start_byte == extern_start
        }));
        // `value: Item` is one exact parameter row, so `caller` keeps no
        // applicability gap.
        assert!(
            gap_inventory(&facts, source).is_empty(),
            "{:?}",
            gap_inventory(&facts, source)
        );
    }

    #[test]
    fn generic_items_expose_supported_interiors_without_binding_type_parameters() {
        let source = r#"
struct T;
pub fn target() -> usize { 1 }

pub fn identity<T>(value: T) -> T {
    target();
    value
}

fn caller(value: T) -> T {
    identity(value)
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust generic-shadow fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let generic_start = source.find("pub fn identity").expect("generic function");
        let generic_end = source
            .find("\n}\n\nfn caller")
            .expect("generic function end")
            + 2;

        let t_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && facts.names[identifier.name.index()].spelling == "T"
            })
            .map(|identifier| facts.sites[identifier.site.index()])
            .collect::<Vec<_>>();
        assert_eq!(t_references.len(), 4);
        let generic_t_references = t_references
            .iter()
            .filter(|site| site.start_byte >= generic_start && site.start_byte < generic_end)
            .collect::<Vec<_>>();
        assert_eq!(generic_t_references.len(), 2);
        assert_eq!(
            t_references
                .iter()
                .filter(|site| site.start_byte >= generic_end)
                .count(),
            2
        );
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && facts.names[identifier.name.index()].spelling == "identity"
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "identity"
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "target"
                && facts.sites[identifier.site.index()].start_byte >= generic_start
                && facts.sites[identifier.site.index()].start_byte < generic_end
        }));
        assert_eq!(
            gap_inventory(&facts, source),
            vec![
                ("T", ResolutionGapKind::ImplicitConstructor),
                ("T", ResolutionGapKind::InferredType),
                ("T", ResolutionGapKind::InferredType),
                ("target", ResolutionGapKind::UnsupportedCallApplicability),
                ("identity", ResolutionGapKind::UnsupportedCallApplicability),
            ],
            "the unbounded type parameter's identity is inferred, and so is the generic \
             result's type at each call; parameter and argument inventories are exact, so \
             only each callee's own obligation remains"
        );
        assert!(generic_t_references.iter().all(|reference| {
            !facts.gaps.iter().any(|gap| {
                gap.site == reference.id && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
            })
        }));
        assert!(!facts.reference_enumeration_gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && facts.sites[gap.site.index()].start_byte == generic_start
        }));
    }

    /// A borrow is its operand's value behind one more reference layer per
    /// `&`, so a borrowed argument is typed like its operand, not unknown. An
    /// operand no expression lowering produces keeps its own gap.
    #[test]
    fn borrowed_arguments_add_one_reference_layer_per_borrow() {
        let source = concat!(
            "pub struct Item;\n",
            "impl Item { pub fn get(&self) -> u8 { 0 } }\n",
            "pub fn take<T>(_: T) {}\n",
            "pub fn caller(item: Item) {\n",
            "    take(&item);\n",
            "    take(&mut item);\n",
            "    take(&&item);\n",
            "    take(&(item));\n",
            "    take(&item.get());\n",
            "    take(&[1u8]);\n",
            "}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let mut arguments = facts
            .call_arguments
            .iter()
            .filter(|argument| source_text(&facts, source, argument.call).starts_with("take("))
            .map(|argument| {
                let transfer = facts
                    .type_transfers
                    .iter()
                    .find(|transfer| transfer.output == argument.value)
                    .expect("each argument slot has one producer");
                let input = facts.type_slots[transfer.input.index()];
                (
                    source_text(&facts, source, argument.call),
                    source_text(&facts, source, input.site),
                    input.role,
                    transfer.indirection_delta,
                    transfer.reference_indirection_delta,
                )
            })
            .collect::<Vec<_>>();
        arguments.sort_unstable_by_key(|argument| argument.0);
        assert_eq!(
            arguments,
            [
                (
                    "take(&&item)",
                    "item",
                    ResolutionTypeSlotRole::ExpressionValue,
                    2,
                    2
                ),
                (
                    "take(&(item))",
                    "item",
                    ResolutionTypeSlotRole::ExpressionValue,
                    1,
                    1
                ),
                (
                    "take(&[1u8])",
                    "[1u8]",
                    ResolutionTypeSlotRole::ExpressionValue,
                    1,
                    1
                ),
                (
                    "take(&item)",
                    "item",
                    ResolutionTypeSlotRole::ExpressionValue,
                    1,
                    1
                ),
                (
                    "take(&item.get())",
                    "item.get()",
                    ResolutionTypeSlotRole::CallResult,
                    1,
                    1
                ),
                (
                    "take(&mut item)",
                    "item",
                    ResolutionTypeSlotRole::ExpressionValue,
                    1,
                    1
                ),
            ]
        );
        let array = facts
            .sites
            .iter()
            .find(|site| &source[site.start_byte..site.end_byte] == "[1u8]")
            .expect("the unlowered operand keeps a site");
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == array.id && gap.kind == ResolutionGapKind::UnsupportedExpression
        }));
    }

    /// A callable whose result is one of its own type parameters publishes the
    /// parameters declared as that same type parameter, with the layers that
    /// separate them, and a gap on the result's type reference saying the
    /// declared result is not the call's type. It also publishes the result
    /// type parameter's position among its non-lifetime generic parameters,
    /// with the result's layers, for an explicit type argument to fill. An
    /// enclosing impl's type parameter is not the callable's own. Impl methods
    /// publish the form in which they take their receiver.
    #[test]
    fn generic_results_publish_the_parameters_that_bind_them() {
        let source = concat!(
            "pub trait Shape {}\n",
            "pub fn pick<T: Shape>(value: T) -> T { value }\n",
            "pub fn borrowed<T>(value: &T) -> &T { value }\n",
            "pub fn copied<T>(value: &T) -> T { loop {} }\n",
            "pub fn both<T>(left: T, right: T) -> T { left }\n",
            "pub fn made<T: Shape>() -> T { loop {} }\n",
            "pub fn other<T, U>(value: U) -> T { loop {} }\n",
            "pub fn second<const N: usize, T>() -> T { loop {} }\n",
            "pub fn after<'a, T>(value: &'a str) -> T { loop {} }\n",
            "pub struct Pair<'a, P, Q>(&'a P, Q);\n",
            "impl<'a, A, B> Pair<'a, B, A> {\n",
            "    pub fn second(&self) -> &A { loop {} }\n",
            "    pub fn nested(&self) -> Vec<A> { loop {} }\n",
            "}\n",
            "pub struct Holder<H>(H);\n",
            "impl<H> Holder<H> {\n",
            "    pub fn get(&self, value: H) -> H { value }\n",
            "    pub fn take(self) {}\n",
            "    pub fn change(&mut self) {}\n",
            "    pub fn boxed(self: Box<Self>) {}\n",
            "}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let mut bindings = facts
            .callable_result_bindings
            .iter()
            .map(|binding| {
                (
                    source_text(&facts, source, binding.callable),
                    binding.parameter_ordinal,
                    binding.indirection_delta,
                    binding.reference_indirection_delta,
                )
            })
            .collect::<Vec<_>>();
        bindings.sort_unstable();
        assert_eq!(
            bindings,
            [
                ("borrowed", 0, 0, 0),
                ("both", 0, 0, 0),
                ("both", 1, 0, 0),
                ("copied", 0, -1, -1),
                ("pick", 0, 0, 0),
            ]
        );
        let mut positions = facts
            .callable_result_type_parameters
            .iter()
            .map(|parameter| {
                (
                    source_text(&facts, source, parameter.callable),
                    parameter.position,
                    parameter.indirection_delta,
                    parameter.reference_indirection_delta,
                )
            })
            .collect::<Vec<_>>();
        positions.sort_unstable();
        assert_eq!(
            positions,
            [
                ("after", 0, 0, 0),
                ("borrowed", 0, 1, 1),
                ("both", 0, 0, 0),
                ("copied", 0, 0, 0),
                ("made", 0, 0, 0),
                ("other", 0, 0, 0),
                ("pick", 0, 0, 0),
                ("second", 1, 0, 0),
            ],
            "the result's own type parameter, lifetimes skipped, const parameters counted"
        );
        let mut owner_positions = facts
            .callable_result_owner_type_parameters
            .iter()
            .map(|parameter| {
                (
                    source_text(&facts, source, parameter.callable),
                    parameter.position,
                    parameter.indirection_delta,
                    parameter.reference_indirection_delta,
                )
            })
            .collect::<Vec<_>>();
        owner_positions.sort_unstable();
        assert_eq!(
            owner_positions,
            [("get", 0, 0, 0), ("second", 1, 1, 1)],
            "an impl parameter's position among the impl target's arguments, lifetimes skipped"
        );
        let mut undecided = facts
            .gaps
            .iter()
            .filter(|gap| {
                gap.kind == ResolutionGapKind::InferredType
                    && facts.sites[gap.site.index()].kind == ResolutionSiteKind::TypeReference
            })
            .map(|gap| facts.sites[gap.site.index()].start_byte)
            .collect::<Vec<_>>();
        undecided.sort_unstable();
        let mut expected = [
            "pick", "borrowed", "copied", "both", "made", "other", "second", "after",
        ]
        .map(|name| {
            let line = source.find(&format!("pub fn {name}<")).unwrap();
            line + source[line..].find(") -> ").unwrap()
                + ") -> ".len()
                + usize::from(name == "borrowed")
        })
        .to_vec();
        expected.sort_unstable();
        assert_eq!(
            undecided, expected,
            "each generic result's type reference names why"
        );
        let mut receivers = facts
            .callable_receivers
            .iter()
            .map(|receiver| {
                (
                    source_text(&facts, source, receiver.callable),
                    receiver.form,
                )
            })
            .collect::<Vec<_>>();
        receivers.sort_unstable_by_key(|receiver| receiver.0);
        assert_eq!(
            receivers,
            [
                ("change", ResolutionCallableReceiverForm::MutableReference),
                ("get", ResolutionCallableReceiverForm::Reference),
                ("nested", ResolutionCallableReceiverForm::Reference),
                ("second", ResolutionCallableReceiverForm::Reference),
                ("take", ResolutionCallableReceiverForm::Value),
            ]
        );
    }

    /// A turbofish call publishes one type-argument row per explicit type
    /// argument, lifetimes skipped. Each slot is at the call and takes the
    /// written type as a value, behind its reference layers. A const argument,
    /// or a type with no nominal identity, gives its slot no input. The type
    /// segment of a call's path publishes its arguments the same way, and an
    /// annotated `let` publishes the type it expects of its call initializer.
    #[test]
    fn calls_publish_their_type_arguments_and_expected_results() {
        let source = concat!(
            "pub struct Square;\n",
            "pub fn make<T>() -> T { loop {} }\n",
            "pub fn sized<'a, const N: usize, T>() -> T { loop {} }\n",
            "pub fn caller<'a>(items: &'a [u8]) {\n",
            "    let a = make::<Square>();\n",
            "    let b = make::<&'a Square>();\n",
            "    let c = items.iter().collect::<Vec<_>>();\n",
            "    let d = sized::<'a, 3, Square>();\n",
            "    let e = make::<(Square, Square)>();\n",
            "    let f = make();\n",
            "    let g: &'a Square = make();\n",
            "    let h = Wrapper::<'a, Square>::new::<u8>();\n",
            "    let _: Square = items.get();\n",
            "}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let mut arguments = facts
            .call_type_arguments
            .iter()
            .map(|argument| {
                let slot = facts.type_slots[argument.value.index()];
                assert_eq!(slot.site, argument.call);
                assert_eq!(slot.role, ResolutionTypeSlotRole::DeclaredValue);
                let inputs = facts
                    .type_transfers
                    .iter()
                    .filter(|transfer| transfer.output == argument.value)
                    .map(|transfer| {
                        assert_eq!(transfer.kind, ResolutionTypeTransferKind::DeclaredType);
                        (
                            source_text(
                                &facts,
                                source,
                                facts.type_slots[transfer.input.index()].site,
                            ),
                            transfer.indirection_delta,
                            transfer.reference_indirection_delta,
                        )
                    })
                    .collect::<Vec<_>>();
                (
                    source_text(&facts, source, argument.call),
                    argument.ordinal,
                    inputs,
                )
            })
            .collect::<Vec<_>>();
        arguments.sort_unstable();
        assert_eq!(
            arguments,
            [
                ("Wrapper::<'a, Square>::new::<u8>()", 0, vec![("u8", 0, 0)]),
                ("items.iter().collect::<Vec<_>>()", 0, vec![("Vec", 0, 0)]),
                ("make::<&'a Square>()", 0, vec![("Square", 1, 1)]),
                ("make::<(Square, Square)>()", 0, vec![]),
                ("make::<Square>()", 0, vec![("Square", 0, 0)]),
                ("sized::<'a, 3, Square>()", 0, vec![]),
                ("sized::<'a, 3, Square>()", 1, vec![("Square", 0, 0)]),
            ]
        );
        let input = |slot: ResolutionTypeSlotId| {
            let transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| transfer.output == slot)
                .expect("a declared slot has its type");
            (
                source_text(
                    &facts,
                    source,
                    facts.type_slots[transfer.input.index()].site,
                ),
                transfer.indirection_delta,
                transfer.reference_indirection_delta,
            )
        };
        let owners = facts
            .call_owner_type_arguments
            .iter()
            .map(|argument| {
                (
                    source_text(&facts, source, argument.call),
                    argument.ordinal,
                    input(argument.value),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            owners,
            [("Wrapper::<'a, Square>::new::<u8>()", 0, ("Square", 0, 0))],
            "the path's type segment writes the type's arguments, lifetimes skipped"
        );
        let segments = facts
            .call_owner_type_segments
            .iter()
            .map(|segment| {
                let identity = facts.type_slots[segment.identity.index()];
                assert_eq!(identity.role, ResolutionTypeSlotRole::TargetTypeIdentity);
                (
                    source_text(&facts, source, segment.call),
                    source_text(&facts, source, identity.site),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            segments,
            [("Wrapper::<'a, Square>::new::<u8>()", "Wrapper")],
            "the segment's arguments come with its reference's identity slot"
        );
        let mut expected = facts
            .call_expected_results
            .iter()
            .map(|expected| {
                let slot = facts.type_slots[expected.value.index()];
                assert_eq!(slot.site, expected.call);
                assert_eq!(slot.role, ResolutionTypeSlotRole::DeclaredValue);
                (
                    source_text(&facts, source, expected.call),
                    input(expected.value),
                )
            })
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert_eq!(
            expected,
            [
                ("items.get()", ("Square", 0, 0)),
                ("make()", ("Square", 1, 1)),
            ],
            "an annotated let expects its call initializer's type"
        );
    }

    /// A macro invocation passed as an argument (`vec![..]`, `format!(..)`, a
    /// local `macro_rules!`, behind a borrow or not) feeds its argument slot
    /// from a site whose gap names the macro, so the argument's unknown type
    /// says why.
    #[test]
    fn macro_arguments_name_the_macro_as_the_reason() {
        let source = concat!(
            "macro_rules! bump { ($e:expr) => { $e + 1 } }\n",
            "pub fn take<T>(_: T) {}\n",
            "pub fn caller(value: u8) {\n",
            "    take(vec![1u8]);\n",
            "    take(format!(\"{value}\"));\n",
            "    take(&bump!(value));\n",
            "}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let mut arguments = facts
            .call_arguments
            .iter()
            .map(|argument| {
                let transfer = facts
                    .type_transfers
                    .iter()
                    .find(|transfer| transfer.output == argument.value)
                    .expect("each argument slot has one producer");
                let input = facts.type_slots[transfer.input.index()];
                let gaps = facts
                    .gaps
                    .iter()
                    .filter(|gap| gap.site == input.site)
                    .map(|gap| gap.kind)
                    .collect::<Vec<_>>();
                (source_text(&facts, source, input.site), gaps)
            })
            .collect::<Vec<_>>();
        arguments.sort_unstable();
        assert_eq!(
            arguments,
            [
                ("bump!(value)", vec![ResolutionGapKind::MacroArgument]),
                (
                    "format!(\"{value}\")",
                    vec![ResolutionGapKind::MacroArgument]
                ),
                ("vec![1u8]", vec![ResolutionGapKind::MacroArgument]),
            ]
        );
    }

    /// A literal argument is typed when its token fixes the type: a suffixed
    /// number, a `bool`, a `char`, and a string (`&str`, one reference layer).
    /// An unsuffixed number names the inference its type waits for; a byte or
    /// C literal has no modelled type. A closure's type is inferred from the
    /// parameter it is passed to, and names that inference too.
    #[test]
    fn literal_arguments_are_typed_where_their_token_fixes_the_type() {
        let source = concat!(
            "pub fn take<T>(_: T) {}\n",
            "pub fn caller() {\n",
            "    take(1u8);\n",
            "    take(0xFFi64);\n",
            "    take(1.5f32);\n",
            "    take(7f64);\n",
            "    take(true);\n",
            "    take('c');\n",
            "    take(\"text\");\n",
            "    take(r\"raw\");\n",
            "    take(1);\n",
            "    take(2.5);\n",
            "    take(0x1f32);\n",
            "    take(b\"bytes\");\n",
            "    take(b'b');\n",
            "    take(|value| value);\n",
            "}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let mut arguments = facts
            .call_arguments
            .iter()
            .map(|argument| {
                let transfer = facts
                    .type_transfers
                    .iter()
                    .find(|transfer| transfer.output == argument.value)
                    .expect("each argument slot has one producer");
                let input = facts.type_slots[transfer.input.index()];
                let seed = facts
                    .intrinsic_type_seeds
                    .iter()
                    .find(|seed| seed.output == transfer.input)
                    .map(|seed| facts.names[seed.name.index()].spelling.as_str());
                let gap = facts
                    .gaps
                    .iter()
                    .find(|gap| gap.site == input.site)
                    .map(|gap| gap.kind);
                (
                    source_text(&facts, source, input.site),
                    seed,
                    transfer.indirection_delta,
                    gap,
                )
            })
            .collect::<Vec<_>>();
        arguments.sort_unstable_by_key(|argument| argument.0);
        let mut expected = vec![
            ("1u8", Some("u8"), 0, None),
            ("0xFFi64", Some("i64"), 0, None),
            ("1.5f32", Some("f32"), 0, None),
            ("7f64", Some("f64"), 0, None),
            ("true", Some("bool"), 0, None),
            ("'c'", Some("char"), 0, None),
            ("\"text\"", Some("str"), 1, None),
            ("r\"raw\"", Some("str"), 1, None),
            (
                "1",
                None,
                0,
                Some(ResolutionGapKind::AmbiguousNumericLiteral),
            ),
            (
                "2.5",
                None,
                0,
                Some(ResolutionGapKind::AmbiguousNumericLiteral),
            ),
            (
                "0x1f32",
                None,
                0,
                Some(ResolutionGapKind::AmbiguousNumericLiteral),
            ),
            (
                "b\"bytes\"",
                None,
                0,
                Some(ResolutionGapKind::UnsupportedExpression),
            ),
            (
                "b'b'",
                None,
                0,
                Some(ResolutionGapKind::UnsupportedExpression),
            ),
            (
                "|value| value",
                None,
                0,
                Some(ResolutionGapKind::InferredType),
            ),
        ];
        expected.sort_unstable_by_key(|argument| argument.0);
        assert_eq!(arguments, expected);
    }

    /// A unit struct marks its value item as its own zero-argument
    /// construction; a tuple struct's value item is its constructor function
    /// and a struct with named fields has no value item.
    #[test]
    fn unit_structs_mark_their_value_as_their_own_construction() {
        let source = "pub struct Unit;\npub struct Marker<T>;\npub struct Tuple(u8);\npub struct Named { value: u8 }\n";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let mut marked = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::ImplicitConstructor)
            .map(|gap| source_text(&facts, source, gap.site))
            .collect::<Vec<_>>();
        marked.sort_unstable();
        assert_eq!(marked, ["Marker", "Unit"]);
    }

    /// A type parameter's identity is a slot of its own. Its bounds feed it;
    /// with nothing to feed it the slot says the type is inferred, so the
    /// parameter's declaration never passes for an exact nominal type.
    #[test]
    fn every_type_parameter_publishes_an_identity_slot_its_bounds_feed() {
        let source = concat!(
            "pub trait Shape {}\n",
            "pub fn free<T>(value: T) -> T { value }\n",
            "pub fn bounded<B: Shape>(value: B) -> B { value }\n",
            "pub fn clause<W>(value: W) -> W where W: Shape { value }\n",
            "pub fn lifetime<'a, L: 'a>(value: L) -> L { value }\n",
            "pub struct Holder<H> { value: H }\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        for (name, bounded) in [
            ("T", false),
            ("B", true),
            ("W", true),
            ("L", false),
            ("H", false),
        ] {
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .unwrap_or_else(|| panic!("type parameter {name}"))
                .site;
            let identity = facts
                .declaration_type_slots
                .iter()
                .find(|property| {
                    property.declaration == declaration
                        && property.role == DeclarationTypeRole::Identity
                })
                .unwrap_or_else(|| panic!("{name} publishes an Identity slot"))
                .slot;
            let producers = facts
                .type_transfers
                .iter()
                .filter(|transfer| transfer.output == identity)
                .collect::<Vec<_>>();
            let [producer] = producers.as_slice() else {
                panic!("{name}: one producer feeds the identity slot: {producers:?}");
            };
            let input_site = facts.type_slots[producer.input.index()].site;
            let inferred = facts
                .gaps
                .iter()
                .any(|gap| gap.site == input_site && gap.kind == ResolutionGapKind::InferredType);
            assert_eq!(
                (producer.kind, inferred),
                if bounded {
                    (ResolutionTypeTransferKind::TypeUnion, false)
                } else {
                    (ResolutionTypeTransferKind::TypeIdentity, true)
                },
                "{name}: a bound feeds the slot; otherwise the parameter's type is inferred"
            );
        }
    }

    #[test]
    fn const_generic_uses_do_not_bind_same_named_module_constants() {
        let source = r#"
const N: usize = 8;
fn target() {}

fn generic<const N: usize>() {
    let _: [u8; N] = [0; N];
    target();
}

fn caller() -> usize { N }
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust const-generic fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let generic_start = source.find("fn generic").expect("generic function");
        let generic_end = source
            .find("\n}\n\nfn caller")
            .expect("generic function end")
            + 2;

        let n_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == "N"
            })
            .map(|identifier| facts.sites[identifier.site.index()])
            .collect::<Vec<_>>();
        assert_eq!(n_references.len(), 3);
        let generic_n_references = n_references
            .iter()
            .filter(|site| site.start_byte >= generic_start && site.start_byte < generic_end)
            .collect::<Vec<_>>();
        assert_eq!(generic_n_references.len(), 2);
        assert!(generic_n_references.iter().all(|reference| {
            facts.gaps.iter().any(|gap| {
                gap.site == reference.id && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
            })
        }));
        assert!(n_references.iter().any(|reference| {
            reference.start_byte >= generic_end
                && facts.gaps.iter().all(|gap| gap.site != reference.id)
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "target"
                && facts.sites[identifier.site.index()].start_byte >= generic_start
                && facts.sites[identifier.site.index()].start_byte < generic_end
        }));
    }

    #[test]
    fn closures_and_for_loops_own_their_pattern_binders() {
        let source = r#"
fn caller(values: Vec<i32>) {
    let x = 0;
    let closure = |x| x;
    for x in values {
        let inside = x;
    }
    let after = x;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust closure and loop fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let x_name = facts
            .names
            .iter()
            .find(|name| name.spelling == "x")
            .expect("interned x")
            .id;
        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.name == x_name
            })
            .collect::<Vec<_>>();
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference && identifier.name == x_name
            })
            .collect::<Vec<_>>();
        assert_eq!(declarations.len(), 3);
        assert_eq!(references.len(), 3);

        let declaration_scope_at = |byte| {
            declarations
                .iter()
                .find(|identifier| facts.sites[identifier.site.index()].start_byte == byte)
                .map(|identifier| {
                    facts
                        .binders
                        .iter()
                        .find(|binder| binder.declaration == identifier.site)
                        .expect("x declaration binder")
                        .scope
                })
                .expect("x declaration at byte")
        };
        let reference_scope_at = |byte| {
            references
                .iter()
                .find(|identifier| facts.sites[identifier.site.index()].start_byte == byte)
                .map(|identifier| facts.sites[identifier.site.index()].scope)
                .expect("x reference at byte")
        };
        let outer_declaration = source.find("let x").expect("outer x") + 4;
        let closure_declaration = source.find("|x|").expect("closure x") + 1;
        let closure_reference = source.find("|x| x").expect("closure body x") + 4;
        let for_declaration = source.find("for x").expect("for x") + 4;
        let for_reference = source.find("inside = x").expect("loop body x") + 9;
        let after_reference = source.find("after = x").expect("outer body x") + 8;

        let outer_scope = declaration_scope_at(outer_declaration);
        let closure_scope = declaration_scope_at(closure_declaration);
        let for_scope = declaration_scope_at(for_declaration);
        assert_ne!(closure_scope, outer_scope);
        assert_ne!(for_scope, outer_scope);
        assert_eq!(reference_scope_at(closure_reference), closure_scope);
        assert_eq!(
            facts.scopes[reference_scope_at(for_reference).index()].parent,
            Some(for_scope)
        );
        assert_eq!(reference_scope_at(after_reference), outer_scope);
        assert_eq!(
            gap_inventory(&facts, source),
            vec![
                ("Vec", ResolutionGapKind::UnsupportedTypeSyntax),
                ("<i32>", ResolutionGapKind::UnsupportedTypeSyntax),
            ],
            "the generic argument frontier remains distinct from callable applicability"
        );
    }

    #[test]
    fn match_arm_patterns_shadow_only_within_their_arm() {
        let source = r#"
fn caller(value: Option<i32>) -> i32 {
    let x = 0;
    match value {
        Some(x) if x > 0 => x,
        _ => x,
    }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust match-arm fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let x_name = facts
            .names
            .iter()
            .find(|name| name.spelling == "x")
            .expect("interned x")
            .id;
        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.name == x_name
            })
            .collect::<Vec<_>>();
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference && identifier.name == x_name
            })
            .collect::<Vec<_>>();
        assert_eq!(declarations.len(), 2);
        assert_eq!(references.len(), 3);

        let pattern_byte = source.find("Some(x)").expect("arm pattern") + 5;
        let pattern_site = declarations
            .iter()
            .find(|identifier| facts.sites[identifier.site.index()].start_byte == pattern_byte)
            .expect("arm x declaration");
        let pattern_scope = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == pattern_site.site)
            .expect("arm x binder")
            .scope;
        for byte in [
            source.find("if x").expect("guard x") + 3,
            source.find("=> x,").expect("arm value x") + 3,
        ] {
            let reference = references
                .iter()
                .find(|identifier| facts.sites[identifier.site.index()].start_byte == byte)
                .expect("arm-local x reference");
            assert_eq!(facts.sites[reference.site.index()].scope, pattern_scope);
        }
        let fallback_byte = source.find("_ => x").expect("fallback x") + 5;
        let fallback = references
            .iter()
            .find(|identifier| facts.sites[identifier.site.index()].start_byte == fallback_byte)
            .expect("fallback x reference");
        assert_ne!(facts.sites[fallback.site.index()].scope, pattern_scope);
        assert!(
            gap_inventory(&facts, source).is_empty(),
            "an Option payload is projected, so its arguments record no gap: {:?}",
            gap_inventory(&facts, source)
        );
    }

    #[test]
    fn direct_let_conditions_bind_only_in_their_consequence() {
        let source = r#"
fn caller(first: Option<i32>, second: Option<i32>) {
    let x = 0;
    if let Some(x) = first {
        let inside_if = x;
    } else {
        let outside_if = x;
    }
    while let Some(x) = second {
        let inside_while = x;
        break;
    }
    let after = x;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust direct let-condition fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let x_name = facts
            .names
            .iter()
            .find(|name| name.spelling == "x")
            .expect("interned x")
            .id;
        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.name == x_name
            })
            .collect::<Vec<_>>();
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference && identifier.name == x_name
            })
            .collect::<Vec<_>>();
        assert_eq!(declarations.len(), 3);
        assert_eq!(references.len(), 4);

        let binder_scope_at = |byte| {
            let declaration = declarations
                .iter()
                .find(|identifier| facts.sites[identifier.site.index()].start_byte == byte)
                .expect("conditional x declaration");
            facts
                .binders
                .iter()
                .find(|binder| binder.declaration == declaration.site)
                .expect("conditional x binder")
                .scope
        };
        let reference_scope_at = |byte| {
            references
                .iter()
                .find(|identifier| facts.sites[identifier.site.index()].start_byte == byte)
                .map(|identifier| facts.sites[identifier.site.index()].scope)
                .expect("conditional x reference")
        };
        let outer_scope = binder_scope_at(source.find("let x").expect("outer x") + 4);
        let if_scope = binder_scope_at(source.find("Some(x)").expect("if pattern x") + 5);
        let while_pattern = source.rfind("Some(x)").expect("while pattern x") + 5;
        let while_scope = binder_scope_at(while_pattern);
        assert_eq!(
            reference_scope_at(source.find("inside_if = x").expect("if body x") + 12),
            if_scope
        );
        let outside_scope =
            reference_scope_at(source.find("outside_if = x").expect("else body x") + 13);
        assert_ne!(outside_scope, if_scope);
        assert_eq!(
            facts.scopes[outside_scope.index()].parent,
            Some(outer_scope)
        );
        assert_eq!(
            reference_scope_at(source.find("inside_while = x").expect("while body x") + 15,),
            while_scope
        );
        assert_eq!(
            reference_scope_at(source.find("after = x").expect("after x") + 8),
            outer_scope
        );
        assert!(
            gap_inventory(&facts, source).is_empty(),
            "an Option payload is projected, so its arguments record no gap: {:?}",
            gap_inventory(&facts, source)
        );
    }

    #[test]
    fn chained_let_conditions_bind_in_order_and_only_through_their_body() {
        let source = r#"
fn choose(_: Option<Option<i32>>, _: Option<i32>) -> Option<i32> { None }
fn ready(_: Option<i32>, _: i32) -> bool { true }
fn consume(_: Option<i32>, _: i32) {}

fn caller(x: Option<Option<i32>>, y: Option<Option<i32>>) {
    if let Some(x) = x
        && let Some(y) = choose(y, x)
        && ready(x, y)
    {
        consume(x, y);
    } else {
        consume(x, y);
    }
    consume(x, y);

    while let Some(x) = x
        && let Some(y) = choose(y, x)
        && ready(x, y)
    {
        consume(x, y);
        break;
    }
    consume(x, y);
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust chained let-condition fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let name_id = |spelling| {
            facts
                .names
                .iter()
                .find(|name| name.spelling == spelling)
                .expect("interned chained-let name")
                .id
        };
        let declaration_at = |spelling, byte| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && identifier.name == name_id(spelling)
                        && facts.sites[identifier.site.index()].start_byte == byte
                })
                .expect("chained-let declaration")
        };
        let binder_at = |spelling, byte| {
            let declaration = declaration_at(spelling, byte);
            facts
                .binders
                .iter()
                .find(|binder| binder.declaration == declaration.site)
                .expect("chained-let binder")
        };
        let reference_scope_at = |spelling, byte| {
            let reference = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.name == name_id(spelling)
                        && facts.sites[identifier.site.index()].start_byte == byte
                })
                .expect("chained-let reference");
            facts.sites[reference.site.index()].scope
        };

        let if_x_pattern = source.find("Some(x)").expect("if x pattern") + 5;
        let if_y_pattern = source.find("Some(y)").expect("if y pattern") + 5;
        let if_x = binder_at("x", if_x_pattern);
        let if_y = binder_at("y", if_y_pattern);
        assert_eq!(if_x.scope, if_y.scope);
        let if_initializer_x = source.find("= x\n").expect("if x initializer") + 2;
        let if_initializer_y = source.find("choose(y, x)").expect("if y initializer") + 7;
        let if_later_x = source.find("choose(y, x)").expect("if later x") + 10;
        let if_test_x = source.find("ready(x, y)").expect("if test x") + 6;
        let if_test_y = source.find("ready(x, y)").expect("if test y") + 9;
        assert!(if_x.activation_start > if_initializer_x);
        assert!(if_x.activation_start < if_later_x);
        assert!(if_y.activation_start > if_initializer_y);
        assert!(if_y.activation_start < if_test_y);
        for (spelling, byte) in [
            ("x", if_initializer_x),
            ("y", if_initializer_y),
            ("x", if_later_x),
            ("x", if_test_x),
            ("y", if_test_y),
        ] {
            assert_eq!(reference_scope_at(spelling, byte), if_x.scope);
        }
        let if_body = source.find("consume(x, y);").expect("if body");
        assert_eq!(reference_scope_at("x", if_body + 8), if_x.scope);
        assert_eq!(reference_scope_at("y", if_body + 11), if_x.scope);
        let else_body = source[if_body + 1..]
            .find("consume(x, y);")
            .map(|offset| if_body + 1 + offset)
            .expect("else body");
        let else_scope = reference_scope_at("x", else_body + 8);
        assert_ne!(else_scope, if_x.scope);

        let after_if = source[else_body + 1..]
            .find("consume(x, y);")
            .map(|offset| else_body + 1 + offset)
            .expect("after if");
        let outer_scope = reference_scope_at("x", after_if + 8);
        assert_ne!(outer_scope, if_x.scope);
        assert_eq!(facts.scopes[else_scope.index()].parent, Some(outer_scope));

        let while_x_pattern = source.rfind("Some(x)").expect("while x pattern") + 5;
        let while_y_pattern = source.rfind("Some(y)").expect("while y pattern") + 5;
        let while_x = binder_at("x", while_x_pattern);
        let while_y = binder_at("y", while_y_pattern);
        assert_eq!(while_x.scope, while_y.scope);
        assert_ne!(while_x.scope, if_x.scope);
        let while_start = source.find("while let").expect("while chain");
        let while_initializer_x = source[while_start..]
            .find("= x\n")
            .map(|offset| while_start + offset + 2)
            .expect("while x initializer");
        let while_choose = source[while_start..]
            .find("choose(y, x)")
            .map(|offset| while_start + offset)
            .expect("while y initializer");
        let while_initializer_y = while_choose + 7;
        let while_later_x = while_choose + 10;
        let while_test = source[while_start..]
            .find("ready(x, y)")
            .map(|offset| while_start + offset)
            .expect("while test");
        assert!(while_x.activation_start > while_initializer_x);
        assert!(while_x.activation_start < while_later_x);
        assert!(while_y.activation_start > while_initializer_y);
        assert!(while_y.activation_start < while_test + 9);
        for (spelling, byte) in [
            ("x", while_initializer_x),
            ("y", while_initializer_y),
            ("x", while_later_x),
            ("x", while_test + 6),
            ("y", while_test + 9),
        ] {
            assert_eq!(reference_scope_at(spelling, byte), while_x.scope);
        }
        let while_body = source[after_if + 1..]
            .find("consume(x, y);")
            .map(|offset| after_if + 1 + offset)
            .expect("while body");
        assert_eq!(reference_scope_at("x", while_body + 8), while_x.scope);
        assert_eq!(reference_scope_at("y", while_body + 11), while_x.scope);
        let after_while = source[while_body + 1..]
            .find("consume(x, y);")
            .map(|offset| while_body + 1 + offset)
            .expect("after while");
        assert_eq!(reference_scope_at("x", after_while + 8), outer_scope);
        assert_eq!(reference_scope_at("y", after_while + 11), outer_scope);

        let point_gaps = gap_inventory(&facts, source);
        assert_eq!(
            point_gaps
                .iter()
                .filter(|(_, kind)| *kind == ResolutionGapKind::UnsupportedCallApplicability)
                .map(|(spelling, _)| *spelling)
                .collect::<Vec<_>>(),
            // Every parameter list and argument list here is exact, so only
            // each callee's own obligation remains, which the common call
            // obligation discharges.
            vec![
                "choose", "ready", "consume", "consume", "consume", "choose", "ready", "consume",
                "consume",
            ]
        );
        // A generic head keeps its nominal identity and reports only the
        // unmodelled substitution, which is type syntax: an omitted lexical
        // binder here would publish a scope-level candidate gap and make every
        // lookup in the attachment scope incomplete.
        assert!(
            point_gaps
                .iter()
                .all(|(_, kind)| *kind != ResolutionGapKind::UnsupportedScopeOrBinder)
        );
        assert_eq!(
            point_gaps
                .iter()
                .filter(|(_, kind)| *kind == ResolutionGapKind::UnsupportedTypeSyntax)
                .map(|(spelling, _)| *spelling)
                .collect::<Vec<_>>(),
            Vec::<&str>::new(),
            "an Option payload is projected at every nesting depth"
        );
        assert!(point_gaps.iter().all(|(_, kind)| matches!(
            kind,
            ResolutionGapKind::UnsupportedCallApplicability
                | ResolutionGapKind::UnsupportedTypeSyntax
        )));
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "pattern constructors are enumerated independently of receiver typing"
        );
    }

    #[test]
    fn or_pattern_alternatives_share_one_semantic_binder() {
        let source = r#"
fn caller(value: Result<i32, i32>) -> i32 {
    match value {
        Ok(x) | Err(x) => x,
    }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust or-pattern fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let x_name = facts
            .names
            .iter()
            .find(|name| name.spelling == "x")
            .expect("interned x")
            .id;
        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.name == x_name
            })
            .collect::<Vec<_>>();
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference && identifier.name == x_name
            })
            .collect::<Vec<_>>();
        assert_eq!(declarations.len(), 1);
        assert_eq!(references.len(), 1);
        let binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == declarations[0].site)
            .expect("shared or-pattern binder");
        assert_eq!(facts.sites[references[0].site.index()].scope, binder.scope);
        let pattern_start = source.find("Ok(x)").expect("or pattern");
        assert!(facts.reference_enumeration_gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && facts.sites[gap.site.index()].start_byte == pattern_start
        }));
        assert!(
            gap_inventory(&facts, source).is_empty(),
            "a Result payload is projected, so its arguments record no gap: {:?}",
            gap_inventory(&facts, source)
        );
    }

    fn reference_sites(
        facts: &FileResolutionFacts,
        name: &str,
        namespace: ResolutionNamespace,
    ) -> Vec<ResolutionSiteId> {
        facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == namespace
                    && facts.names[identifier.name.index()].spelling == name
            })
            .map(|identifier| identifier.site)
            .collect()
    }

    /// A projection head is valid Rust syntax and keeps its own type references.
    ///
    /// `<Service as Runner>::Output` names a member of a projection, not a
    /// member of a module. The member therefore carries a type-shaped gap while
    /// the head's own type syntax stays an ordinary type reference. Recording a
    /// lexical demand for the projection instead made every definition query in
    /// the file incomplete.
    #[test]
    fn projection_heads_lower_type_references_without_a_lexical_demand() {
        let source = concat!(
            "struct Service;\n",
            "trait Runner { type Output; }\n",
            "impl Runner for Service { type Output = i32; }\n",
            "type ResultType = <Service as Runner>::Output;\n",
            "fn sibling() {}\n",
            "fn caller() { let _ = sibling; }\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse Rust projection fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let gaps = gap_inventory(&facts, source);
        assert!(
            !gaps
                .iter()
                .any(|(_, kind)| *kind == ResolutionGapKind::MalformedSyntax),
            "a projection head is valid syntax: {gaps:?}"
        );
        assert!(
            !enumeration_gap_inventory(&facts, source)
                .iter()
                .any(|(_, kind)| *kind == ResolutionGapKind::MalformedSyntax),
            "a projection member demands no lexical binder: {gaps:?}"
        );

        for head in ["Service", "Runner"] {
            let projection_start = source.find("<Service as Runner>").unwrap();
            let sites = reference_sites(&facts, head, ResolutionNamespace::Type)
                .into_iter()
                .filter(|site| facts.sites[site.index()].start_byte >= projection_start)
                .collect::<Vec<_>>();
            assert_eq!(
                sites.len(),
                1,
                "{head} inside the qualified type is one Type reference: {gaps:?}"
            );
            let site = facts.sites[sites[0].index()];
            assert_eq!(&source[site.start_byte..site.end_byte], head);
        }

        let members = reference_sites(&facts, "Output", ResolutionNamespace::Type);
        assert_eq!(
            members.len(),
            1,
            "the projection member is the fixture's only Output reference"
        );
        assert!(
            !facts.gaps.iter().any(|gap| gap.site == members[0]
                && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax),
            "the concrete projection is supported: {gaps:?}"
        );
        let associated = facts
            .deferred_member_owners
            .iter()
            .find(|owner| owner.kind == ResolutionMemberKind::AssociatedType)
            .expect("impl associated type owner");
        assert!(
            facts
                .relation_members
                .iter()
                .any(|member| member.member == associated.member
                    && member.kind == ResolutionMemberKind::AssociatedType)
        );
        let member = facts
            .identifiers
            .iter()
            .find(|identifier| identifier.site == members[0])
            .expect("the projection member is a positioned identifier");
        assert!(
            member.qualifier.is_some(),
            "the projection member keeps the receiver slot for its projection"
        );

        let siblings = reference_sites(&facts, "sibling", ResolutionNamespace::Value);
        assert_eq!(
            siblings.len(),
            1,
            "the sibling callable is one Value reference"
        );
        assert!(
            !facts.gaps.iter().any(|gap| gap.site == siblings[0]),
            "a sibling reference in the same file carries no gap: {gaps:?}"
        );
    }
    #[test]
    fn transcriber_item_paths_require_invocation_context_except_dollar_crate() {
        let source = "#[macro_export] macro_rules! pick { () => { (self::MARKER, super::MARKER, crate::MARKER, other::MARKER, $crate::MARKER) }; }";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let references = reference_sites(&facts, "MARKER", ResolutionNamespace::Value);
        assert_eq!(
            references.len(),
            5,
            "every template member retains its source identity: {facts:?}"
        );
        let root = references
            .iter()
            .copied()
            .find(|site| facts.sites[site.index()].start_byte == source.rfind("MARKER").unwrap())
            .expect("$crate member");
        assert!(
            facts
                .root_references
                .iter()
                .any(|route| route.reference == root)
        );
        for spelling in [
            "self::MARKER",
            "super::MARKER",
            "crate::MARKER",
            "other::MARKER",
        ] {
            let start = source.find(spelling).unwrap() + spelling.len() - "MARKER".len();
            let reference = references
                .iter()
                .copied()
                .find(|site| facts.sites[site.index()].start_byte == start)
                .expect("positioned member");
            assert!(
                facts.gaps.iter().any(|gap| {
                    gap.site == reference && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                }),
                "{spelling} needs its own invocation-context gap: {facts:?}"
            );
            assert!(
                facts.identifiers.iter().any(|identifier| {
                    identifier.site == reference && identifier.qualifier.is_some()
                }),
                "{spelling} must not acquire a bare lexical fallback: {facts:?}"
            );
            assert!(
                !facts
                    .root_references
                    .iter()
                    .any(|route| route.reference == reference),
                "{spelling} has no definition-site root route: {facts:?}"
            );
        }
    }

    #[test]
    fn ordinary_transcriber_crate_anchor_respects_export_context() {
        for (attribute, rooted) in [("", true), ("#[macro_export]", false)] {
            let source = format!("{attribute} macro_rules! pick {{ () => {{ crate::MARKER }}; }}");
            let tree = crate::lexical_scope::parse_rust_tree(&source).expect("fixture parses");
            let facts = extract_rust_resolution_facts(tree.root_node(), &source);
            let references = reference_sites(&facts, "MARKER", ResolutionNamespace::Value);
            assert_eq!(references.len(), 1, "{source}: {facts:?}");
            assert_eq!(
                facts
                    .root_references
                    .iter()
                    .any(|route| route.reference == references[0]),
                rooted,
                "{source}: {facts:?}"
            );
            assert_eq!(
                facts.gaps.iter().any(|gap| gap.site == references[0]
                    && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder),
                !rooted,
                "{source}: {facts:?}"
            );
        }
    }

    #[test]
    fn conditional_export_transcriber_keeps_whole_macro_incomplete() {
        let source =
            "#[cfg_attr(custom_cfg, macro_export)] macro_rules! pick { () => { crate::MARKER }; }";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(reference_sites(&facts, "MARKER", ResolutionNamespace::Value).is_empty());
        let mut cursor = tree.root_node().walk();
        let definition = tree
            .root_node()
            .named_children(&mut cursor)
            .map(crate::syntax::unwrap_attributes)
            .find(|node| node.kind() == "macro_definition")
            .expect("fixture has an attributed macro definition");
        assert!(
            facts.reference_enumeration_gaps.iter().any(|gap| {
                let site = &facts.sites[gap.site.index()];
                gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                    && site.start_byte == definition.start_byte()
                    && site.end_byte == definition.end_byte()
            }),
            "conditional export cannot publish definition-site certainty: {facts:?}"
        );
    }

    #[test]
    fn exported_macro_and_static_transcriber_paths_keep_root_routes() {
        let source = "mod hidden { #[macro_export] macro_rules! run { ($x:expr) => { $crate::wanted::free($x); }; } }";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let exported = facts
            .root_exports
            .iter()
            .find(|export| export.namespace == ResolutionNamespace::Macro)
            .expect("exported macro has a root exposure");
        assert_eq!(exported.root_scope, ResolutionScopeId::new(0));
        assert_eq!(
            facts.sites[exported.declaration.index()].scope,
            exported.root_scope
        );
        let sites = reference_sites(&facts, "free", ResolutionNamespace::Value);
        assert_eq!(sites.len(), 1, "{facts:?}");
        assert_eq!(
            facts.sites[sites[0].index()].start_byte,
            source.find("free").unwrap()
        );
        assert!(
            facts
                .root_references
                .iter()
                .any(|route| route.reference == sites[0])
        );
        assert_eq!(facts.calls.len(), 1, "the transcriber retains its AST call");
        let route = facts
            .root_references
            .iter()
            .find(|route| route.reference == sites[0])
            .unwrap();
        let prefix = route
            .prefix_reference
            .expect("a static macro callee retains its typed prefix");
        for (reference, expected) in [(prefix, "crate"), (sites[0], "wanted")] {
            assert_eq!(
                facts
                    .root_reference_segments
                    .iter()
                    .filter(|segment| segment.reference == reference)
                    .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                    .collect::<Vec<_>>(),
                [expected],
                "the prefix chain preserves the complete crate route"
            );
        }
        assert!(reference_sites(&facts, "$x", ResolutionNamespace::Value).is_empty());
        assert!(facts.reference_enumeration_gaps.is_empty(), "{facts:?}");
    }

    #[test]
    fn matched_token_trees_publish_qualified_paths_with_declaration_owners() {
        let source = "macro_rules! consume { ($($tokens:tt)*) => { $($tokens)* }; } fn run() { consume!({ wanted::free(); }); }";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let sites = reference_sites(&facts, "free", ResolutionNamespace::Value);
        assert_eq!(sites.len(), 1, "{facts:?}");
        assert_eq!(
            facts.sites[sites[0].index()].kind,
            ResolutionSiteKind::CallableReference
        );
        assert!(
            facts
                .reference_owners
                .iter()
                .any(|owner| owner.reference == sites[0]),
            "{facts:?}"
        );
        assert!(facts.reference_enumeration_gaps.is_empty(), "{facts:?}");
    }

    #[test]
    fn macro_matcher_references_keep_fragment_namespaces_and_exact_ranges() {
        let source = "struct Item; macro_rules! take { ($t:ty, $e:expr) => {}; } fn f() { let value = 1; take!(Item, value); }";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        for (name, namespace) in [
            ("Item", ResolutionNamespace::Type),
            ("value", ResolutionNamespace::Value),
        ] {
            let sites = reference_sites(&facts, name, namespace);
            assert_eq!(sites.len(), 1, "{facts:?}");
            let site = facts.sites[sites[0].index()];
            assert_eq!(site.start_byte, source.rfind(name).unwrap());
            assert_eq!(&source[site.start_byte..site.end_byte], name);
        }
        assert!(facts.reference_enumeration_gaps.is_empty(), "{facts:?}");
    }

    #[test]
    fn emitted_repeated_transcriber_keeps_its_bare_type_reference() {
        let source = "use crate::{Adaptor, TestOutput}; trait Adaptor<T> {} type TestOutput<EC> = EC; macro_rules! gen_tuple { ($($M:ident),*) => { fn generated<$($M,)* EC>() where $(TestOutput<EC>: Adaptor<$M>,)* {} }; } gen_tuple!(Metric);";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let expected = source
            .match_indices("TestOutput")
            .nth(2)
            .expect("repeated transcriber type")
            .0;
        assert!(
            reference_sites(&facts, "TestOutput", ResolutionNamespace::Type)
                .iter()
                .any(|site| facts.sites[site.index()].start_byte == expected),
            "the emitted repeated bare type name must be a reference at its template source: {facts:#?}"
        );
    }

    #[test]
    fn macro_matcher_failed_and_generated_ident_do_not_create_references() {
        for source in [
            "struct Item; macro_rules! take { (ready $t:ty) => {}; } take!(Item);",
            "struct Item; macro_rules! take { ($name:ident) => { struct $name; }; } take!(Item);",
        ] {
            let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
            let facts = extract_rust_resolution_facts(tree.root_node(), source);
            assert!(reference_sites(&facts, "Item", ResolutionNamespace::Type).is_empty());
            assert!(reference_sites(&facts, "Item", ResolutionNamespace::Value).is_empty());
            assert!(facts.reference_enumeration_gaps.is_empty(), "{facts:?}");
        }
    }
    #[test]
    fn macro_fragments_keep_qualified_paths_and_expression_local_scopes() {
        let source = "macro_rules! take { ($t:ty, $e:expr) => {}; } fn f() { take!(crate::model::Item, { let value = 1; value }); }";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let item = reference_sites(&facts, "Item", ResolutionNamespace::Type);
        assert_eq!(item.len(), 1, "{facts:?}");
        assert!(
            facts
                .root_references
                .iter()
                .any(|route| route.reference == item[0]),
            "{facts:?}"
        );
        let value = reference_sites(&facts, "value", ResolutionNamespace::Value);
        assert_eq!(value.len(), 1, "{facts:?}");
        let reference_scope = facts.sites[value[0].index()].scope;
        assert_eq!(
            facts.scopes[reference_scope.index()].kind,
            ResolutionScopeKind::Block
        );
        assert!(
            facts
                .binders
                .iter()
                .any(|binder| binder.scope == reference_scope
                    && facts
                        .identifiers
                        .iter()
                        .any(|identifier| identifier.site == binder.declaration
                            && facts.names[identifier.name.index()].spelling == "value")),
            "{facts:?}"
        );
    }
    #[test]
    fn macro_item_fragments_keep_an_explicit_generation_boundary() {
        let source = "macro_rules! take { ($item:item) => { $item }; } take!(fn generated() {});";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts
                .reference_enumeration_gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder),
            "{facts:?}"
        );
    }
    #[test]
    fn nested_macro_expressions_reuse_declared_rules_without_rust_recursion() {
        let source = format!(
            "macro_rules! take {{ ($e:expr) => {{ $e }}; }} fn f() {{ let value = 1; {}value{}; }}",
            "take!(".repeat(64),
            ")".repeat(64)
        );
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let tree = crate::lexical_scope::parse_rust_tree(&source).expect("fixture parses");
                let facts = extract_rust_resolution_facts(tree.root_node(), &source);
                let sites = reference_sites(&facts, "value", ResolutionNamespace::Value);
                assert_eq!(sites.len(), 1, "{facts:?}");
                assert_eq!(
                    facts.sites[sites[0].index()].start_byte,
                    source.rfind("value").unwrap()
                );
                assert!(facts.reference_enumeration_gaps.is_empty(), "{facts:?}");
            })
            .expect("spawn bounded-stack fixture")
            .join()
            .expect("nested macros finish on a bounded stack");
    }

    #[test]
    fn trait_bound_associated_constraints_retain_reference_inventory() {
        let source = r#"
trait Store { type Id: Copy; fn get(&self, id: Self::Id) -> u32; }
struct Concrete { values: Vec<u32> }
impl Store for Concrete { type Id = usize; fn get(&self, id: Self::Id) -> u32 { self.values[id] } }
struct Driver<ID> { id: ID }
impl<ID: Copy> Driver<ID> {
    fn invoke<S>(&self, value: &S) -> u32 where S: Store<Id = ID> { value.get(self.id) }
}
fn inline<S: Store<Id = usize>>(value: &S) -> u32 { value.get(0) }
fn opaque(value: &impl Store<Id = usize>) -> u32 { value.get(0) }
fn dynamic(value: &dyn Store<Id = usize>) -> u32 { value.get(0) }
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "{:?}",
            enumeration_gap_inventory(&facts, source)
        );
    }

    /// A Rust item declared in a block does not capture: the block's locals are
    /// invisible inside it, while the items declared beside it are visible.
    /// The producer states both with the scope chain, so this reads the chain.
    #[test]
    fn a_block_local_item_sees_its_siblings_and_not_the_blocks_locals() {
        let source =
            "fn outer() { let hidden = 1; struct Sibling; fn nested() -> Sibling { hidden } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let site_of = |spelling: &str, role: ResolutionIdentifierRole, occurrence: usize| {
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == role
                        && facts.names[identifier.name.index()].spelling == spelling
                })
                .nth(occurrence)
                .unwrap_or_else(|| panic!("{spelling} {role:?} #{occurrence}: {facts:#?}"))
                .site
        };
        let binder_scope = |declaration: ResolutionSiteId| {
            facts
                .binders
                .iter()
                .find(|binder| binder.declaration == declaration)
                .unwrap_or_else(|| panic!("{declaration:?} has a binder: {facts:#?}"))
                .scope
        };
        let mut visible = vec![
            facts.sites[site_of("hidden", ResolutionIdentifierRole::Reference, 0).index()].scope,
        ];
        while let Some(parent) = facts.scopes[visible.last().unwrap().index()].parent {
            visible.push(parent);
        }
        let local = binder_scope(site_of("hidden", ResolutionIdentifierRole::Declaration, 0));
        let sibling = binder_scope(site_of("Sibling", ResolutionIdentifierRole::Declaration, 0));
        assert!(
            !visible.contains(&local),
            "the block's local is visible from the nested item: {visible:?} {facts:#?}"
        );
        assert!(
            visible.contains(&sibling),
            "the block's sibling item is not visible from the nested item: {visible:?} {facts:#?}"
        );
    }

    /// An item written inside a member body is an ordinary block-local item,
    /// not an associated item of the impl. The grammar says so: an associated
    /// item is a direct child of the `declaration_list` that is the impl's
    /// body.
    #[test]
    fn a_block_local_item_in_a_method_body_is_not_an_associated_item() {
        let source = r#"
struct Service;
fn helper() -> u32 { 1 }
impl Service {
    #[inline]
    fn run(&self) -> u32 {
        const RETRIES: u32 = 3;
        #[inline]
        fn nested() -> u32 { helper() }
        static LIMIT: u32 = 9;
        type Count = u32;
        nested() + RETRIES + LIMIT
    }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse block-local items");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert_eq!(
            gap_inventory(&facts, source)
                .into_iter()
                .filter(|(_, kind)| *kind == ResolutionGapKind::UnsupportedMemberScope)
                .collect::<Vec<_>>(),
            Vec::new(),
            "{facts:#?}"
        );
        let declared = |spelling: &str, kind: ResolutionSiteKind| {
            facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == spelling
                    && facts.sites[identifier.site.index()].kind == kind
            })
        };
        assert!(
            declared("RETRIES", ResolutionSiteKind::ValueDeclaration),
            "{facts:#?}"
        );
        assert!(
            declared("LIMIT", ResolutionSiteKind::ValueDeclaration),
            "{facts:#?}"
        );
        assert!(
            declared("nested", ResolutionSiteKind::CallableDeclaration),
            "{facts:#?}"
        );
        assert!(
            declared("Count", ResolutionSiteKind::TypeAliasDeclaration),
            "{facts:#?}"
        );
        assert!(
            facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "helper"
            }),
            "the nested item's body is lowered: {facts:#?}"
        );
        assert!(
            !facts.deferred_member_owners.iter().any(|owner| {
                let site = facts.sites[owner.member.index()];
                matches!(
                    &source[site.start_byte..site.end_byte],
                    "RETRIES" | "LIMIT" | "nested" | "Count"
                )
            }),
            "a block-local item is not a member of the impl subject: {facts:#?}"
        );
    }

    /// A trait method with a default body is lowered like an inherent method:
    /// the body has its own scope under the trait's member scope, `self` is a
    /// binder in it, and `Self` takes the trait's own abstract frontier. Before
    /// this, the whole `function_item` was skipped as an unsupported member
    /// scope, so no reference written in a default body existed at all.
    #[test]
    fn a_trait_default_body_lowers_its_references_and_binds_self() {
        let source = r#"
fn helper() -> u32 { 1 }
trait Connection {
    type TransactionManager;
    fn name(&self) -> u32;
    #[inline]
    fn begin(&mut self) -> u32 { let local = helper(); Self::run(local) + self.name() }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse trait default body");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert_eq!(
            gap_inventory(&facts, source)
                .into_iter()
                .filter(|(_, kind)| *kind == ResolutionGapKind::UnsupportedMemberScope)
                .collect::<Vec<_>>(),
            Vec::new(),
            "{facts:#?}"
        );
        let site_of = |spelling: &str, role: ResolutionIdentifierRole| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == role
                        && facts.names[identifier.name.index()].spelling == spelling
                })
                .unwrap_or_else(|| panic!("{spelling} {role:?}: {facts:#?}"))
                .site
        };
        let body =
            facts.sites[site_of("helper", ResolutionIdentifierRole::Reference).index()].scope;
        let member = facts.scopes[body.index()]
            .parent
            .expect("the default body's scope has the trait member scope above it");
        assert_eq!(
            facts.scopes[member.index()].kind,
            ResolutionScopeKind::TypeBody,
            "{facts:#?}"
        );
        assert_eq!(
            facts.scopes[member.index()].owner,
            Some(site_of("Connection", ResolutionIdentifierRole::Declaration)),
            "{facts:#?}"
        );
        let declaration = site_of("begin", ResolutionIdentifierRole::Declaration);
        assert_eq!(facts.scopes[body.index()].owner, Some(declaration));
        assert!(
            facts.member_owners.iter().any(|owner| {
                owner.member == declaration
                    && owner.owner == site_of("Connection", ResolutionIdentifierRole::Declaration)
                    && owner.access == ResolutionMemberAccess::Instance
            }),
            "a default method is a member of its trait: {facts:#?}"
        );
        let local = site_of("local", ResolutionIdentifierRole::Declaration);
        assert!(
            facts
                .binders
                .iter()
                .any(|binder| binder.declaration == local && binder.scope == body),
            "{facts:#?}"
        );
        // `self` is bound in the body and its declared value type is
        // transferred from the trait's abstract Self frontier, which the trait
        // declaration published with its hierarchy gap.
        let receiver = site_of("self", ResolutionIdentifierRole::Declaration);
        assert!(
            facts
                .binders
                .iter()
                .any(|binder| binder.declaration == receiver && binder.scope == body),
            "{facts:#?}"
        );
        let declared = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == receiver && slot.role == ResolutionTypeSlotRole::DeclaredValue
            })
            .expect("the receiver has a declared value slot");
        let abstract_self = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.output == declared.id)
            .expect("the receiver's type comes from the trait's Self frontier")
            .input;
        let abstract_self_site = facts.type_slots[abstract_self.index()].site;
        assert!(
            facts.gaps.iter().any(|gap| {
                gap.site == abstract_self_site
                    && gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal
            }),
            "the trait's Self frontier keeps its hierarchy gap: {facts:#?}"
        );
        assert!(
            facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "Self"
            }),
            "{facts:#?}"
        );
    }

    /// An associated constant is a member of the impl's subject or of the
    /// trait, in the Value namespace, and its value expression is ordinary
    /// source. Before, the whole `const_item` was an unsupported member scope:
    /// the constant had no declaration site anywhere and the references in its
    /// value did not exist.
    #[test]
    fn associated_constants_are_members_and_their_values_are_lowered() {
        let source = r#"
fn compute() -> usize { 1 }
struct Service;
trait Limited {
    const CEILING: usize;
    const FLOOR: usize = compute();
}
impl Limited for Service {
    const CEILING: usize = compute();
}
impl Service {
    const RETRIES: usize = compute();
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse associated constants");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert_eq!(
            gap_inventory(&facts, source)
                .into_iter()
                .filter(|(_, kind)| *kind == ResolutionGapKind::UnsupportedMemberScope)
                .collect::<Vec<_>>(),
            Vec::new(),
            "{facts:#?}"
        );
        let declarations = |spelling: &str| {
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == spelling
                })
                .map(|identifier| identifier.site)
                .collect::<Vec<_>>()
        };
        for spelling in ["CEILING", "FLOOR", "RETRIES"] {
            for declaration in declarations(spelling) {
                assert_eq!(
                    facts.sites[declaration.index()].kind,
                    ResolutionSiteKind::ValueDeclaration,
                    "{spelling}: {facts:#?}"
                );
            }
        }
        // The trait's own constants are members of the trait declaration; the
        // impl's are deferred to its subject frontier.
        let trait_declaration = declarations("Limited");
        assert_eq!(trait_declaration.len(), 1);
        for spelling in ["CEILING", "FLOOR"] {
            let site = declarations(spelling)[0];
            assert!(
                facts.member_owners.iter().any(|owner| {
                    owner.member == site
                        && owner.owner == trait_declaration[0]
                        && owner.kind == ResolutionMemberKind::Field
                        && owner.access == ResolutionMemberAccess::Type
                }),
                "{spelling}: {facts:#?}"
            );
        }
        for spelling in ["CEILING", "RETRIES"] {
            let site = *declarations(spelling)
                .last()
                .expect("the impl's constant declaration");
            assert!(
                facts.deferred_member_owners.iter().any(|owner| {
                    owner.member == site
                        && owner.kind == ResolutionMemberKind::Field
                        && owner.qualifier_compatibility
                            == ResolutionMemberQualifierCompatibility::TypeOnly
                }),
                "{spelling}: {facts:#?}"
            );
        }
        // Three values, three references to the workspace function.
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "compute"
                })
                .count(),
            3,
            "{facts:#?}"
        );
    }

    /// An item-position invocation of a macro with no visible definition has
    /// its token tree enumerated for references, the way an expression-position
    /// one already did. No declaration is minted: declaration replay stays the
    /// sole authority over an item-position interior, and the invocation keeps
    /// its own `UnsupportedScopeOrBinder` gap for whatever the expansion
    /// declares. A group that is not an expression keeps the enumeration gap.
    #[test]
    fn an_item_position_token_tree_is_enumerated_for_references_only() {
        let source = "fn bench() {}\nstruct Benches;\ncriterion_group!(Benches, bench);\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse item macro");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            references,
            BTreeSet::from(["criterion_group", "Benches", "bench"]),
            "{facts:#?}"
        );
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
                .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["bench", "Benches"]),
            "the enumeration mints no declaration: {facts:#?}"
        );
        assert_eq!(
            gap_inventory(&facts, source),
            vec![
                ("Benches", ResolutionGapKind::ImplicitConstructor),
                (
                    "criterion_group!(Benches, bench)",
                    ResolutionGapKind::UnsupportedScopeOrBinder
                ),
            ],
            "{facts:#?}"
        );
        assert_eq!(
            enumeration_gap_inventory(&facts, source),
            Vec::new(),
            "every group parsed, so the reference inventory is complete"
        );

        // A group that is not an expression keeps the enumeration gap, and the
        // module mount inside it stays declaration replay's to publish.
        let unenumerable = "lazy_static! { static ref TABLE: u32 = 1; }\n";
        let tree = parser.parse(unenumerable, None).expect("parse lazy_static");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), unenumerable);
        assert_eq!(
            enumeration_gap_inventory(&facts, unenumerable),
            vec![(
                "lazy_static! { static ref TABLE: u32 = 1; }",
                ResolutionGapKind::UnexpandedItemMacro
            )],
            "{facts:#?}"
        );
    }
}
