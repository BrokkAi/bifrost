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
    ResolutionCallableResultTypeFact, ResolutionCallableResultTypeParameterFact,
    ResolutionCallableSignatureFact, ResolutionConditionalBinderFact,
    ResolutionDeclarationVisibilityFact, ResolutionDeclaredTypeRelationFact,
    ResolutionDeclaredTypeRelationKind, ResolutionDeferredMemberOwnerFact,
    ResolutionDefinitionUnitFact, ResolutionEngineRuleEligibilityFact, ResolutionEngineRuleKind,
    ResolutionGapFact, ResolutionGapKind, ResolutionGenericFormalDefaultFact,
    ResolutionGenericFormalFact, ResolutionGenericTypeAliasParameterFact, ResolutionIdentifierRole,
    ResolutionLocalWriteFact, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility, ResolutionNameId,
    ResolutionNamespace, ResolutionReferenceEnumerationGapFact, ResolutionReferenceOwnerFact,
    ResolutionRelationMemberFact, ResolutionRootExportFact, ResolutionRootImportAnchor,
    ResolutionRootImportDemandFact, ResolutionRootImportDemandTarget,
    ResolutionRootImportDemandTargetFact, ResolutionRootImportFact, ResolutionRootImportKind,
    ResolutionRootImportKindFact, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionRouteGap, ResolutionScopeFact, ResolutionScopeId,
    ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteId, ResolutionSiteKind,
    ResolutionSupertypeFact, ResolutionSupertypeKind, ResolutionTypeArgumentFact,
    ResolutionTypeConstructorKind, ResolutionTypeProductionFact, ResolutionTypeRelationId,
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum RustItemAttributeBoundary {
    SourcePreserving,
    GeneratedSurface,
    /// Bare item attributes that may be derive helpers. The item is kept and
    /// its binder stays open until the crate route proves the names unbound.
    ConditionalDeriveHelpers(Vec<String>),
    Transforming,
}

#[derive(Clone, Copy, Debug)]
struct PendingScope {
    scope: ResolutionScopeId,
    callable: Option<ResolutionSiteId>,
}

/// One runtime value waiting for its expression's typed slot. Initializers
/// retain their inferred declared value separately from the observed assignment.
#[derive(Debug)]
struct PendingRuntimeValue {
    site: ResolutionSiteId,
    destination: RuntimeValueDestination,
    adjustments: Vec<RuntimeValueAdjustment>,
}

#[derive(Debug)]
struct RuntimeValueAdjustment {
    site: ResolutionSiteId,
    kind: RuntimeValueAdjustmentKind,
}

#[derive(Clone, Copy, Debug)]
enum RuntimeValueAdjustmentKind {
    Borrow,
    Unwrap,
}

#[derive(Clone, Copy, Debug)]
enum RuntimeValueDestination {
    Initializer {
        inferred: Option<ResolutionTypeSlotId>,
    },
    LocalWrite,
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
    receiver_reference_indirection: i8,
    relation: ResolutionTypeRelationId,
    next_member_ordinal: u32,
    supports_standard_self: bool,
}

#[derive(Clone, Copy, Debug)]
struct RustMethodReceiverOwner {
    owner_type: ResolutionTypeSlotId,
    reference_indirection: i8,
}

#[derive(Clone, Copy, Debug)]
struct RustSelfTypes {
    nominal: ResolutionTypeSlotId,
    receiver: ResolutionTypeSlotId,
    receiver_reference_indirection: i8,
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
    /// References inside an unrecognized argument grammar remain guesses.
    guessed_references: bool,
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

struct PendingPrimitiveSeed {
    output: ResolutionTypeSlotId,
    name: ResolutionNameId,
    owner: Option<ResolutionSiteId>,
    sequence: Option<(
        ResolutionSiteId,
        ResolutionTypeConstructorKind,
        Option<String>,
    )>,
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
    conditional_type_applications: HashMap<(usize, ResolutionScopeId), ResolutionTypeSlotId>,
    lowered_type_application_arguments: HashSet<(ResolutionTypeSlotId, u32)>,
    consumed_subtrees: HashSet<usize>,
    pending_glob_imports: Vec<ResolutionSiteId>,
    conditional_imports: HashSet<ResolutionSiteId>,
    // Syntax primitive seeds are provisional until all hoisted binders and
    // imports in this blob have been collected. Literal seeds are never here.
    pending_primitive_seeds: Vec<PendingPrimitiveSeed>,
    pending_primitive_nominal_slots: Vec<(ResolutionTypeSlotId, ResolutionTypeSlotId)>,
    extern_crate_bindings: Vec<(ResolutionScopeId, ResolutionNameId)>,
    inherent_impls: HashMap<usize, InherentImplContext>,
    /// Canonical token ranges for one selected macro input. Re-parsing an
    /// expression fragment can split a lexical numeric token into tuple-field
    /// selectors that have no independent host token occurrence.
    macro_input_token_spans: Option<HashSet<(usize, usize)>>,
    inherent_method_owner_types: HashMap<ResolutionSiteId, RustMethodReceiverOwner>,
    self_type_frontiers: HashMap<usize, RustSelfTypes>,
    /// The scope that binds each lowered trait's own name, kept so a
    /// `Self::`-qualified lookup inside its body can mint the trait's lower
    /// bound without re-walking to the declaration.
    trait_self_bound_scopes: HashMap<usize, ResolutionScopeId>,
    /// The lower bound each trait lends its `Self::` qualifiers, minted on
    /// first use so a trait whose body writes no `Self::` path publishes
    /// nothing extra.
    trait_self_lower_bounds: HashMap<usize, ResolutionTypeSlotId>,
    pending_runtime_values: HashMap<usize, Vec<PendingRuntimeValue>>,
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
    guessing_macro_references: bool,
    /// The `Self` owner of the macro fragment being lowered, if any.
    macro_fragment_self_owner: Option<MacroFragmentSelfOwner>,
    macro_fragment_nodes: HashSet<usize>,
    explicit_source_fragment_nodes: HashSet<usize>,
    /// Root item nodes of capsule `item` fragments that expand into an `impl`
    /// or trait body; see [`Self::lower_associated_macro_item`].
    associated_macro_items: HashSet<usize>,
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
            let name = spelled_name(node).expect("captured macro is named");
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
            conditional_type_applications: HashMap::new(),
            lowered_type_application_arguments: HashSet::new(),
            consumed_subtrees: HashSet::new(),
            pending_glob_imports: Vec::new(),
            conditional_imports: HashSet::new(),
            pending_primitive_seeds: Vec::new(),
            pending_primitive_nominal_slots: Vec::new(),
            extern_crate_bindings: Vec::new(),
            inherent_impls: HashMap::new(),
            macro_input_token_spans: None,
            inherent_method_owner_types: HashMap::new(),
            self_type_frontiers: HashMap::new(),
            trait_self_bound_scopes: HashMap::new(),
            trait_self_lower_bounds: HashMap::new(),
            pending_runtime_values: HashMap::new(),
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
            guessing_macro_references: false,
            macro_fragment_self_owner: None,
            macro_fragment_nodes: HashSet::new(),
            explicit_source_fragment_nodes: HashSet::new(),
            associated_macro_items: HashSet::new(),
            embedded_identity: None,
            embedded_declarations: HashMap::default(),
            discharged_item_macros: HashSet::new(),
            replayed_member_owner: None,
        }
    }

    pub(crate) fn new_for_macro_input(
        root: Node<'_>,
        source: &'source str,
        input: &brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree,
    ) -> Self {
        let mut builder = Self::new(root, source);
        builder.macro_input_token_spans = Some(
            input
                .tokens
                .iter()
                .map(|token| (token.start_byte, token.end_byte))
                .collect(),
        );
        builder
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
        assert!(!self.guessing_macro_references);
        assert_eq!(self.scopes, [ResolutionScopeId::new(0)]);
        assert!(self.declaration_owners.is_empty());
        assert!(self.exits.is_empty());
        assert!(self.pending_scopes.is_empty());
        assert!(
            self.pending_runtime_values.is_empty(),
            "every pending runtime value's producing expression is lowered: {:?}",
            self.pending_runtime_values
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

        self.resolve_primitive_seeds();
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
            self.facts.gaps.push(ResolutionGapFact::new(
                declaration,
                ResolutionGapKind::UnprovenActivation,
            ));
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
            if crate::declaration_properties::is_rust_named_declaration_kind(node.kind())
                && spelled_name(node).is_some()
            {
                let declaration = map.declare_node(node, &mut self.source_collector);
                self.declaration_properties.record_embedded(
                    declaration,
                    node,
                    map.host(),
                    map.host_cfg(),
                );
                self.embedded_declarations.insert(node.id(), declaration);
                Some(declaration)
            } else {
                None
            };
        self.embedded_identity = Some(map);
        declaration
    }

    /// Lower the items of a proven source-preserving item macro (a passthrough
    /// or the documented cfg_if grammar) against
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
    pub(crate) fn lower_replayed_item_macro(
        &mut self,
        invocation: Node<'_>,
        tree: tree_sitter::Tree,
        mut map: crate::declarations::RustEmbeddedSourceMap,
    ) -> crate::declarations::RustEmbeddedSourceMap {
        assert!(
            self.embedded_identity.is_none(),
            "one embedded replay tree is lowered at a time"
        );
        self.discharged_item_macros.insert(invocation.id());
        let host = crate::imports::rust_import_owner(invocation, self.source, "");
        let host_scope = host
            .owner_scope
            .map(|scope| self.source_collector.intern_node(scope));
        map.inherit_import_scope(host_scope, &host.owner);
        self.embedded_identity = Some(map);
        self.replayed_member_owner =
            rust_trait_or_impl_member_owner(invocation).map(|owner| MemberOwner {
                node: owner.id(),
                is_trait: owner.kind() == "trait_item",
            });
        // Replay's tree ends at the invocation interior. Carry the enclosing
        // Self owner just as expression/type macro fragments do, so replayed
        // method receivers and Self types use the original trait/impl frontier.
        let self_owner = self
            .macro_fragment_self_owner(invocation, rust_tree_writes_self_path(&tree, self.source));
        let previous_self_owner =
            std::mem::replace(&mut self.macro_fragment_self_owner, self_owner);
        self.lower_replayed_items(tree.root_node());
        self.macro_fragment_self_owner = previous_self_owner;
        self.embedded_declarations.clear();
        self.replayed_member_owner = None;
        self.retain_macro_fragment_tree(tree);
        self.embedded_identity
            .take()
            .expect("the embedded replay map is returned to its graph")
    }

    /// The walk of [`Self::lower_replayed_item_macro`] over replay's tree.
    /// The root spans the replayed item interiors; its named children are
    /// the ordinary items whose source-preserving structure was proved.
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
            // The replay map supplies provenance for these ordinary items.
            // Macro definitions need their own captured definition authority.
            if node.kind() == "macro_definition" {
                self.add_local_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
                continue;
            }
            // A nested expansion owns another occurrence map. Keep its item
            // surface explicit rather than silently treating it as empty.
            if node.kind() == "macro_invocation" {
                let enumerated = self.lower_guessed_macro_arguments(node);
                let site = self.add_site(
                    node,
                    ResolutionSiteKind::UnsupportedExpression,
                    self.current_scope(),
                );
                self.add_semantic_gap_at_site(site, ResolutionGapKind::UnexpandedItemMacro);
                if !enumerated {
                    self.facts.reference_enumeration_gaps.push(
                        ResolutionReferenceEnumerationGapFact {
                            site,
                            kind: ResolutionGapKind::UnsupportedExpression,
                        },
                    );
                }
                continue;
            }
            let imports = matches!(node.kind(), "use_declaration" | "extern_crate_declaration")
                .then(|| {
                    self.embedded_identity
                        .as_mut()
                        .expect("replay holds its source map")
                        .take_projected_imports(node)
                });
            let action = self.enter(node, imports.as_deref(), None, None);
            if let Some(imports) = imports {
                self.embedded_identity
                    .as_mut()
                    .expect("replay holds its source map")
                    .return_projected_imports(node, imports);
            }
            if node.kind() == "mod_item"
                && let Some(scope) = self.module_body_scope(node)
            {
                self.embedded_identity
                    .as_mut()
                    .expect("replay holds its source map")
                    .record_native_module_scope(node, scope);
            }
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

        if crate::declarations::rust_node_can_carry_item_attributes(node.kind()) {
            self.lower_derive_macro_references(node);
            match rust_item_attribute_boundary(node, self.source) {
                RustItemAttributeBoundary::SourcePreserving => {}
                RustItemAttributeBoundary::GeneratedSurface
                | RustItemAttributeBoundary::ConditionalDeriveHelpers(_) => {
                    // Derives and possible helper attributes preserve authored
                    // bindings under the additive macro assumption. This arm
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
                RustItemAttributeBoundary::Transforming => {
                    // Assume the attribute preserves authored bindings,
                    // generics, defaults and fields. Expansion can add new
                    // names, members and impls, so absence remains open.
                    self.add_semantic_gap(node, ResolutionGapKind::GeneratedItemSurface);
                    self.lower_divan_bench_attribute_arguments(node);
                    // Attribute heads name macros, independently of the
                    // generated item surface. Keep their namespace separate
                    // from a same-named ordinary function.
                    for item in crate::syntax::outer_attributes(node) {
                        let Some(attribute) = item.named_child(0) else {
                            continue;
                        };
                        let Some(path) = attribute.named_child(0) else {
                            continue;
                        };
                        if !rust_attribute_item_can_expand(item, self.source)
                            || (path.kind() == "identifier"
                                && matches!(
                                    rust_node_text(path, self.source),
                                    "cfg_attr" | "derive" | "macro_use"
                                ))
                        {
                            continue;
                        }
                        if path.kind() == "identifier" {
                            self.add_identifier(
                                path,
                                ResolutionSiteKind::MacroReference,
                                ResolutionIdentifierRole::Reference,
                                ResolutionNamespace::Macro,
                                self.current_scope(),
                            );
                        } else {
                            self.add_scoped_identifier(
                                path,
                                ResolutionSiteKind::MacroReference,
                                ResolutionNamespace::Macro,
                            );
                        }
                    }
                    // Keep the source declaration and authored items visible
                    // while retaining the local gap for generated names and
                    // member surfaces. Shared lookup discharges the name gap
                    // only when it finds an existing binding;
                    // skipping here also withheld the native definition
                    // bridge and made the declaration look absent.
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
                self.facts.gaps.push(ResolutionGapFact::new(
                    site,
                    ResolutionGapKind::UnsupportedHierarchyTraversal,
                ));
                assert!(
                    self.self_type_frontiers
                        .insert(
                            node.id(),
                            RustSelfTypes {
                                nominal: frontier,
                                receiver: frontier,
                                receiver_reference_indirection: 0,
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
            "assignment_expression" | "compound_assignment_expr" => self.lower_local_write(node),
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
        brokk_bifrost_core::analyzer::resolution_facts::current_scope_id(
            &self.scopes,
            "Rust compilation scope is present",
        )
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
        self.facts
            .allocate_lexical_scope(parent, owner, kind, start_byte, end_byte)
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
        let id = self
            .facts
            .add_site(scope, kind, range.start_byte, range.end_byte);
        self.site_occurrences.push(occurrence);
        id
    }

    fn intern_name(&mut self, node: Node<'_>) -> ResolutionNameId {
        let spelling = strip_raw_identifier_prefix(rust_node_text(node, self.source).trim());
        self.intern_spelling(spelling)
    }

    fn intern_spelling(&mut self, spelling: &str) -> ResolutionNameId {
        let spelling = strip_raw_identifier_prefix(spelling.trim());
        self.facts.intern_name(&mut self.names, spelling)
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
        let scope = &self.facts.scopes[root_scope.index()];
        assert!(
            scope.kind == ResolutionScopeKind::CompilationUnit
                || (scope.kind == ResolutionScopeKind::Package
                    && scope.inheritance == ResolutionScopeInheritance::Root),
            "prelude fall-through must attach at its module root: {scope:?}"
        );
        self.prelude_fall_throughs
            .push(ResolutionRootReferenceFact {
                reference: site,
                root_scope,
                anchor: ResolutionRootImportAnchor::Lexical,
                prefix_reference: None,
                owner_continued: false,
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
        self.facts
            .binding_projections
            .push(BindingProjectionFact::target_declared_value_type(
                reference, output,
            ));
        Some(output)
    }

    /// Derive arguments are token-tree paths rather than scoped_identifier
    /// nodes. Publish their original terminal tokens and reuse ordinary path
    /// routing; selected resolution owns the macro's workspace or external target.
    fn lower_derive_macro_references(&mut self, node: Node<'_>) {
        for tokens in rust_item_derive_facts(node, self.source).paths {
            // An empty final group is the optional trailing comma.
            let Some(first) = tokens.first().copied() else {
                continue;
            };
            let (anchor, path) = if first.kind() == "::" {
                (ResolutionRootImportAnchor::Absolute, &tokens[1..])
            } else {
                (ResolutionRootImportAnchor::Lexical, tokens.as_slice())
            };
            if path.len() % 2 != 1
                || path.iter().enumerate().any(|(position, token)| {
                    if position % 2 == 0 {
                        !matches!(token.kind(), "identifier" | "crate" | "self" | "super")
                            || !name_node_has_spelling(*token)
                            || rust_type_reference_is_self(*token, self.source)
                    } else {
                        token.kind() != "::"
                    }
                })
            {
                self.add_local_gap(first, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            let segments = path.iter().step_by(2).copied().collect::<Vec<_>>();
            let terminal = *segments.last().expect("a derive path has a terminal");
            if terminal.kind() != "identifier"
                || rust_path_anchor_keyword(terminal, self.source)
                || rust_path_segments_have_misplaced_anchor(
                    segments.iter().copied(),
                    self.source,
                    false,
                )
            {
                self.add_local_gap(first, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            let explicit_module_anchor = anchor == ResolutionRootImportAnchor::Absolute
                || rust_path_anchor_keyword(segments[0], self.source);
            let bare_qualified_route = segments.len() > 1 && !explicit_module_anchor;
            let reference = if bare_qualified_route {
                self.add_qualified_identifier(
                    terminal,
                    ResolutionSiteKind::MacroReference,
                    ResolutionNamespace::Macro,
                    self.current_scope(),
                )
            } else {
                self.add_identifier(
                    terminal,
                    ResolutionSiteKind::MacroReference,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Macro,
                    self.current_scope(),
                )
            };
            self.add_root_reference_route(
                terminal,
                terminal,
                reference,
                Some(segments),
                bare_qualified_route,
                anchor,
            );
        }
    }

    fn add_scoped_identifier(
        &mut self,
        node: Node<'_>,
        site_kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
    ) -> Option<ResolutionSiteId> {
        let Some(name) = spelled_name(node) else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return None;
        };
        if let Some(head) = rust_projection_path_head(node) {
            return Some(
                self.lower_projection_member_reference(node, name, head, site_kind, namespace),
            );
        }
        let segments = rust_path_segments(node);
        if segments.as_ref().is_some_and(|segments| {
            segments
                .iter()
                .any(|segment| !name_node_has_spelling(*segment))
        }) {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return None;
        }
        if segments.as_ref().is_some_and(|segments| {
            rust_path_segments_have_misplaced_anchor(segments.iter().copied(), self.source, false)
        }) {
            self.mark_scoped_path_consumed(node);
            let terminal = segments
                .as_ref()
                .and_then(|segments| segments.last())
                .copied()
                .map(|terminal| self.intern_name(terminal));
            self.add_local_route_gap(
                node,
                ResolutionRouteGap::OmittedReference {
                    scope: self.current_scope(),
                    terminal,
                    namespace: Some(namespace),
                },
            );
            return None;
        }
        let explicit_module_anchor = segments.as_ref().is_some_and(|segments| {
            rust_path_is_leading_absolute(node)
                || segments
                    .first()
                    .is_some_and(|segment| rust_path_anchor_keyword(*segment, self.source))
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
        let anchor = if rust_path_is_leading_absolute(node) {
            ResolutionRootImportAnchor::Absolute
        } else {
            ResolutionRootImportAnchor::Lexical
        };
        self.add_root_reference_route(
            node,
            name,
            reference,
            segments,
            bare_qualified_route,
            anchor,
        );
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
        anchor: ResolutionRootImportAnchor,
    ) {
        let Some(segments) = segments else {
            self.mark_scoped_path_consumed(node);
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if segments
            .iter()
            .any(|segment| !name_node_has_spelling(*segment))
        {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return;
        }
        assert_eq!(
            segments.last().map(|segment| segment.id()),
            Some(terminal.id())
        );
        self.mark_scoped_path_consumed(node);
        let explicit_module_anchor = anchor == ResolutionRootImportAnchor::Absolute
            || segments
                .first()
                .is_some_and(|segment| rust_path_anchor_keyword(*segment, self.source));
        if !explicit_module_anchor && !bare_qualified_route {
            return;
        }
        let root_scope = self.nearest_root_scope();
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
            (!rust_path_anchor_keyword(prefix, self.source)).then(|| {
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
            (!rust_path_anchor_keyword(receiver, self.source)).then(|| {
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
                owner_continued: false,
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
        for (position, prefix) in
            segments[..prefix_count]
                .iter()
                .enumerate()
                .filter(|(position, prefix)| {
                    *position > 0 || rust_path_anchor_keyword(**prefix, self.source)
                })
        {
            let keyword = rust_path_anchor_keyword(*prefix, self.source);
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
                    owner_continued: false,
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
        if rust_is_unit_type(node) {
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
        if rust_primitive_type_spelling(node, self.source).is_some() {
            self.pending_primitive_nominal_slots
                .push((lowered.identity, output));
        } else {
            self.facts.binding_projections.push(BindingProjectionFact {
                reference,
                output,
                kind: BindingProjectionKind::TargetNominalTypeIdentity,
            });
        }
        Some(output)
    }

    fn lower_impl_type_identity(&mut self, node: Node<'_>) -> Option<LoweredDeclaredType> {
        if node.kind() == "generic_type" {
            let arguments = node
                .child_by_field_name("type_arguments")
                .expect("Rust generic_type has type_arguments");
            self.lower_return_type_children(arguments);
            // An impl belongs to the nominal declaration. Its parameter
            // substitution is separate from that declaration's identity.
            let head = node
                .child_by_field_name("type")
                .expect("Rust generic_type has a type field");
            let lowered = self.lower_declared_type_identity(head)?;
            Some(lowered)
        } else {
            self.lower_declared_type_identity(node)
        }
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
        let reference_member_owner = rust_reference_impl_member_owner(target);
        let generic_subject = rust_enclosing_item_generic_parameter_namespace(target, self.source)
            == Some(ResolutionNamespace::Type)
            || rust_qualified_path_root_is_generic_parameter(target, self.source);
        let (subject, receiver_subject, receiver_reference_indirection) = if generic_subject {
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
            (slot, slot, 0)
        } else {
            match self.lower_impl_type_identity(target) {
                Some(lowered)
                    if lowered.indirection == lowered.reference_indirection
                        && lowered.reference_indirection > 0
                        && reference_member_owner.is_some_and(|owner| {
                            rust_has_nominal_type_head(owner, self.source)
                        }) =>
                {
                    // Keep the reference target's own subject frontier and
                    // use T only for member lookup; treating T as the subject
                    // would claim that T itself implements this trait. The
                    // persisted impl-route shape has no reference depth yet,
                    // so the subject remains gapped instead of publishing the
                    // false `T: Trait` relation.
                    (
                        self.unresolvable_impl_subject(target),
                        lowered.identity,
                        lowered.reference_indirection,
                    )
                }
                Some(lowered)
                    if lowered.indirection == 0
                        && lowered.reference_indirection == 0
                        && rust_has_nominal_type_head(target, self.source) =>
                {
                    (
                        self.lower_nominal_type_identity(target)
                            .expect("accepted impl type has nominal identity"),
                        lowered.identity,
                        0,
                    )
                }
                // The subject's type syntax carries an identity this fragment
                // cannot name, or none at all: a reference, a slice, a tuple, a
                // primitive, or a `dyn` object. The impl still has members, and their bodies are
                // ordinary source, so it takes a frontier that resolves to
                // nothing and says so rather than losing the whole body.
                Some(_) | None => {
                    let slot = self.unresolvable_impl_subject(target);
                    (slot, slot, 0)
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
                    self.facts.gaps.push(ResolutionGapFact::new(
                        reference,
                        ResolutionGapKind::UnsupportedHierarchyTraversal,
                    ));
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
        // Deferred candidates reference context.subject, not the self-value
        // receiver_subject. Each impl has its own nominal subject slot, so its
        // written pattern is available directly at the candidate's frontier.
        if let Some(arguments) = target.child_by_field_name("type_arguments") {
            self.lower_type_application_arguments(arguments, subject);
        }

        let context = InherentImplContext {
            subject,
            receiver_subject,
            receiver_reference_indirection,
            relation,
            next_member_ordinal: 0,
            // `impl crate::m::Type` binds `self` as the nominal target. When
            // the target is a reference, `receiver_subject` is its nominal
            // member owner and the reference depth is carried separately.
            supports_standard_self: matches!(
                target.kind(),
                "type_identifier"
                    | "identifier"
                    | "scoped_type_identifier"
                    | "scoped_identifier"
                    | "generic_type"
            ) || rust_is_unmodelled_primitive_spelling(target, self.source)
                || reference_member_owner
                    .is_some_and(|owner| rust_has_nominal_type_head(owner, self.source)),
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
                        receiver: receiver_subject,
                        receiver_reference_indirection,
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
        let name = spelled_name(node)?;
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
        let name = spelled_name(node)?;
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
            self.facts.gaps.push(ResolutionGapFact::new(
                declaration,
                ResolutionGapKind::UnsupportedVisibility,
            ));
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
        let name = spelled_name(node)?;
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
                    .insert(
                        declaration,
                        RustMethodReceiverOwner {
                            owner_type: context.receiver_subject,
                            reference_indirection: context.receiver_reference_indirection,
                        },
                    )
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
        let name = spelled_name(node)?;
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
                    .insert(
                        declaration,
                        RustMethodReceiverOwner {
                            owner_type,
                            reference_indirection: 0,
                        },
                    )
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
            if node.is_error() || node.is_missing() {
                // This eager pass runs before the ordinary tree walk, whose
                // enter guard would otherwise own malformed syntax.
                self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
                continue;
            }
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
                // A call in type syntax (a computed array length such as
                // `[u8; n_limbs(N)]`) is lowered by the main walk when it
                // descends here: that lowering publishes the callee as a
                // CallableReference, the call site and one argument row per
                // actual. This pass runs during the enclosing item's enter,
                // before that descent; lowering the call's operand identifiers
                // now would mark them handled, the walk would key a pending
                // argument slot on each, and the skipped visit would never
                // discharge it. A macro invocation keeps this eager coverage:
                // the walk lowers the invocation but does not descend into its
                // token tree, so this pass is the token-tree identifiers' only
                // reference.
                "call_expression" => continue,
                // A const block can contain a let declaration even inside a
                // type's array length. Its pattern, annotation and initializer
                // belong to the ordinary walk, which lowers the binder before
                // the initializer. Visiting the initializer here first marks
                // its name handled before lower_let can register the pending
                // initialization that the later visit is meant to discharge.
                "let_declaration" | "assignment_expression" | "compound_assignment_expr" => {
                    continue;
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
        self.facts
            .binders
            .push(ResolutionBinderFact::scope_wide(declaration, kind, bounds));
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
        let name = spelled_name(node)?;
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
                self.facts.gaps.push(ResolutionGapFact::new(
                    declaration,
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                ));
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
        let Some(name) = spelled_name(node) else {
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
        for (position, (child, visibility_modifier)) in
            crate::syntax::rust_positional_fields(node).enumerate()
        {
            let visibility = visibility_modifier
                .map(|modifier| {
                    crate::imports::rust_visibility_from_modifier(modifier, self.source)
                })
                .unwrap_or_else(|| default_visibility.clone());
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
        let Some(name) = spelled_name(node) else {
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
            self.retain_call_applicability_gap(declaration);
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
                    if let Some(receiver_owner) =
                        self.inherent_method_owner_types.get(&declaration).copied()
                    {
                        self.lower_standard_self_parameter(
                            parameter,
                            executable,
                            body.start_byte(),
                            body.end_byte(),
                            receiver_owner.owner_type,
                            receiver_owner.reference_indirection,
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
            self.retain_call_applicability_gap(callable);
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
                    list_ordinal: 0,
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

    fn retain_call_applicability_gap(&mut self, callable: ResolutionSiteId) {
        self.facts.gaps.push(ResolutionGapFact::new(
            callable,
            ResolutionGapKind::UnsupportedCallApplicability,
        ));
    }

    fn lower_standard_self_parameter(
        &mut self,
        parameter: Node<'_>,
        scope: ResolutionScopeId,
        activation_start: usize,
        activation_end: usize,
        owner_type: ResolutionTypeSlotId,
        owner_reference_indirection: i8,
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
        let mut reference_indirection = owner_reference_indirection;
        let mut addressable = false;
        for child in parameter.children(&mut cursor) {
            match child.kind() {
                "&" => {
                    reference_indirection = reference_indirection
                        .checked_add(1)
                        .expect("Rust receiver reference indirection fits i8")
                }
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
            self.add_declared_type_transfer(lowered, declared);
        } else {
            self.add_semantic_gap_at_site(site, ResolutionGapKind::UnsupportedTypeSyntax);
        }
    }

    fn add_declared_type_transfer(
        &mut self,
        lowered: LoweredDeclaredType,
        output: ResolutionTypeSlotId,
    ) {
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input: lowered.identity,
            output,
            kind: ResolutionTypeTransferKind::DeclaredType,
            indirection_delta: lowered.indirection,
            reference_indirection_delta: lowered.reference_indirection,
            value_transform: ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        });
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
            self.facts.gaps.push(ResolutionGapFact::new(
                declaration,
                ResolutionGapKind::UnsupportedTypeSyntax,
            ));
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
        let signature = self
            .facts
            .callable_signatures
            .iter_mut()
            .find(|signature| signature.callable == declaration)
            .expect("a callable return belongs to its signature");
        assert!(signature.result_types.is_empty(), "one Rust return type");
        signature
            .result_types
            .push(ResolutionCallableResultTypeFact {
                ordinal: 0,
                value_type: declared,
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
            if argument.kind() == "type_identifier"
                && name_node_has_spelling(argument)
                && self.intern_name(argument) == head
            {
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
                "type_parameter" => spelled_name(parameter),
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

    /// Prove the direct-seed optimization against the completed lexical facts.
    /// A later item or import can shadow an earlier mention, so this cannot
    /// be decided during the preorder syntax walk. All state is blob-local.
    fn resolve_primitive_seeds(&mut self) {
        if self.pending_primitive_seeds.is_empty() {
            assert!(self.pending_primitive_nominal_slots.is_empty());
            return;
        }
        let mut names_by_site = vec![None; self.facts.sites.len()];
        for identifier in &self.facts.identifiers {
            if matches!(
                identifier.namespace,
                ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
            ) && identifier.role != ResolutionIdentifierRole::Reference
            {
                names_by_site[identifier.site.index()] = Some(identifier.name);
            }
        }
        let mut shadowing = self
            .extern_crate_bindings
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        for binder in &self.facts.binders {
            if let Some(name) = names_by_site[binder.declaration.index()] {
                shadowing.insert((binder.scope, name));
            }
        }
        for demand in &self.facts.root_import_demands {
            if matches!(
                demand.namespace,
                ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
            ) {
                shadowing.insert((
                    self.facts.sites[demand.import_site.index()].scope,
                    demand.name,
                ));
            }
        }
        // An unexpanded item macro can supply the same binding a glob can.
        // Unknown binder syntax cannot prove absence either. Keep the same
        // open-inventory result as ordinary lexical lookup.
        let open_scopes = self
            .pending_glob_imports
            .iter()
            .copied()
            .chain(self.facts.gaps.iter().filter_map(|gap| {
                matches!(
                    gap.kind,
                    ResolutionGapKind::UnexpandedItemMacro
                        | ResolutionGapKind::UnsupportedScopeOrBinder
                        | ResolutionGapKind::MalformedSyntax
                )
                .then_some(gap.site)
            }))
            .map(|site| self.facts.sites[site.index()].scope)
            .collect::<HashSet<_>>();
        let mut replaced = HashSet::new();
        let pending = std::mem::take(&mut self.pending_primitive_seeds);
        for PendingPrimitiveSeed {
            output,
            name,
            owner,
            sequence,
        } in pending
        {
            let site = self.facts.type_slots[output.index()].site;
            let mut scope = self.facts.sites[site.index()].scope;
            let root_scope = loop {
                let fact = self.facts.scopes[scope.index()];
                if shadowing.contains(&(scope, name)) || open_scopes.contains(&scope) {
                    break None;
                }
                if fact.inheritance == ResolutionScopeInheritance::Root || fact.parent.is_none() {
                    break Some(scope);
                }
                scope = fact.parent.expect("non-root scope has a parent");
            };
            if root_scope.is_some() {
                continue;
            }
            replaced.insert(output);
            let (site, output) = if let Some((element_site, constructor, length)) = sequence {
                let element_slot =
                    ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                        .expect("Rust resolution type-slot count exceeds u32");
                self.facts.type_slots.push(ResolutionTypeSlotFact {
                    id: element_slot,
                    site: element_site,
                    role: ResolutionTypeSlotRole::TargetTypeIdentity,
                });
                self.facts
                    .type_productions
                    .push(ResolutionTypeProductionFact {
                        output,
                        element: element_slot,
                        constructor,
                        length,
                    });
                (element_site, element_slot)
            } else {
                (site, output)
            };
            self.facts.identifiers.push(PositionedIdentifierFact {
                site,
                name,
                role: ResolutionIdentifierRole::Reference,
                namespace: ResolutionNamespace::Type,
                qualifier: None,
            });
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference: site,
                    owner,
                });
            self.facts.binding_projections.push(BindingProjectionFact {
                reference: site,
                output,
                kind: BindingProjectionKind::TargetTypeIdentity,
            });
        }
        for (input, output) in std::mem::take(&mut self.pending_primitive_nominal_slots) {
            if replaced.contains(&input) {
                self.facts.binding_projections.push(BindingProjectionFact {
                    reference: self.facts.type_slots[input.index()].site,
                    output,
                    kind: BindingProjectionKind::TargetNominalTypeIdentity,
                });
            } else {
                let seed = *self
                    .facts
                    .intrinsic_type_seeds
                    .iter()
                    .find(|seed| seed.output == input)
                    .expect("unshadowed primitive has its direct seed");
                self.facts
                    .intrinsic_type_seeds
                    .push(IntrinsicTypeSeedFact { output, ..seed });
            }
        }
        self.facts
            .intrinsic_type_seeds
            .retain(|seed| !replaced.contains(&seed.output));
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
        self.facts
            .intrinsic_type_seeds
            .push(IntrinsicTypeSeedFact::direct(output, name, kind));
        output
    }

    fn lower_declared_type_identity(&mut self, mut node: Node<'_>) -> Option<LoweredDeclaredType> {
        let mut indirection = 0i8;
        let mut reference_indirection = 0i8;
        let mut frontier_gaps = Vec::new();
        loop {
            // Recovery inserts a missing or error node where a type belongs
            // (`foo::<>()` has a missing type argument). It has no spelling to
            // reference, so retain a local syntax gap and leave the caller's
            // slot without an input.
            if node.is_missing() || node.is_error() {
                self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
                return None;
            }
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
                    let application = self.lower_declared_type_identity(head)?.identity;
                    let (complete, nested_applications) =
                        self.lower_type_application_arguments(arguments, application);
                    if !complete {
                        frontier_gaps.push(ResolutionGapKind::UnsupportedTypeSyntax);
                    }
                    // Written argument rows remain nominal, as they do in impl
                    // subjects. Receiver payloads have separate conditional
                    // outputs, selected only when an enclosing wrapper projects.
                    for (nested, nominal) in nested_applications {
                        self.conditional_type_application(nested, nominal);
                    }
                    let identity = self.conditional_type_application(node, application);
                    self.add_frontier_gaps(
                        self.facts.type_slots[application.index()].site,
                        &frontier_gaps,
                    );
                    return Some(LoweredDeclaredType {
                        identity,
                        indirection,
                        reference_indirection,
                        head_name: None,
                    });
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

        // `Self` in `impl Trait for &T` denotes `&T`, although member lookup
        // uses the `T` identity below. Keep the impl's reference layers in
        // the type flow so `Self` and receiver parameters preserve Rust's
        // exact type while calls and fields can autoderef to their owner.
        if rust_type_reference_is_self(node, self.source)
            && let Some(self_types) = self.enclosing_self_types(node)
        {
            indirection = indirection
                .checked_add(self_types.receiver_reference_indirection)
                .expect("Rust Self indirection fits i8");
            reference_indirection = reference_indirection
                .checked_add(self_types.receiver_reference_indirection)
                .expect("Rust Self reference indirection fits i8");
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
            let head_name = (node.kind() == "type_identifier"
                && name_node_has_spelling(node)
                && frontier_gaps.is_empty())
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
            let identity = self.add_intrinsic_type_seed(site, spelling, kind);
            let head_name = if kind == IntrinsicTypeKind::Primitive {
                let name = self.intern_spelling(spelling);
                self.pending_primitive_seeds.push(PendingPrimitiveSeed {
                    output: identity,
                    name,
                    owner: self.declaration_owners.last().copied(),
                    sequence: None,
                });
                Some(name)
            } else {
                None
            };
            return Some(LoweredDeclaredType {
                identity,
                indirection,
                reference_indirection,
                head_name,
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
                    self.facts.gaps.push(ResolutionGapFact::new(
                        reference,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    ));
                }
                Some(reference)
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
        let head_name = (node.kind() == "type_identifier"
            && name_node_has_spelling(node)
            && frontier_gaps.is_empty())
        .then(|| self.intern_name(node));
        Some(LoweredDeclaredType {
            identity: output,
            indirection,
            reference_indirection,
            head_name,
        })
    }

    /// Queue primitive-spelled sequences through the scalar lexical proof.
    /// Proven builtin elements retain the direct intrinsic optimization;
    /// potentially shadowed elements get a query-time constructor production.
    /// Array lengths keep the literal token spelling, without normalization.
    /// Other element or length syntax remains unsupported.
    fn lower_primitive_sequence_type(&mut self, node: Node<'_>) -> Option<ResolutionTypeSlotId> {
        let element = node
            .child_by_field_name("element")
            .expect("Rust array_type has an element field");
        let element_node = element;
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
        let output = self.add_intrinsic_type_seed(site, &spelling, kind);
        let element_site = self.add_site(
            element_node,
            ResolutionSiteKind::TypeReference,
            self.current_scope(),
        );
        let name = self.intern_spelling(element);
        self.pending_primitive_seeds.push(PendingPrimitiveSeed {
            output,
            name,
            owner: self.declaration_owners.last().copied(),
            sequence: Some((
                element_site,
                match kind {
                    IntrinsicTypeKind::Slice => ResolutionTypeConstructorKind::Slice,
                    IntrinsicTypeKind::Array => ResolutionTypeConstructorKind::Array,
                    _ => unreachable!(),
                },
                node.child_by_field_name("length")
                    .map(|length| rust_node_text(length, self.source).trim().to_owned()),
            )),
        });
        Some(output)
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
        let name = spelled_name(trait_item)?;
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
            self.facts
                .binding_projections
                .push(BindingProjectionFact::target_type_identity(
                    reference, output,
                ));
        }
        self.type_reference_identities
            .insert((node.id(), self.current_scope()), output);
        output
    }

    fn add_frontier_gaps(&mut self, site: ResolutionSiteId, gaps: &[ResolutionGapKind]) {
        for &kind in gaps {
            self.facts.add_gap(site, kind);
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
        for (parent_ordinal, bound) in bounds.into_iter().enumerate() {
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
                parent_ordinal: u32::try_from(parent_ordinal)
                    .expect("a Rust declaration's parent count fits u32"),
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
            let Some(name) = spelled_name(argument) else {
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
        let item = parameters
            .parent()
            .expect("generic parameters have an item owner");
        let formal_owner = matches!(
            item.kind(),
            "struct_item"
                | "enum_item"
                | "union_item"
                | "trait_item"
                | "type_item"
                | "function_item"
                | "function_signature_item"
        )
        .then(|| self.declaration_sites[&item.id()]);
        // Match written application positions: skip lifetimes, but reserve a
        // position for every type or const parameter. Only types emit formal
        // rows, so a const between two types leaves a hole in their ordinals.
        let mut parameter_ordinal = 0_u32;
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
            let ordinal = parameter_ordinal;
            parameter_ordinal = parameter_ordinal
                .checked_add(1)
                .expect("Rust generic parameter count fits u32");
            let Some(name) = spelled_name(parameter) else {
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
                if let Some(owner) = formal_owner {
                    self.facts
                        .generic_formals
                        .push(ResolutionGenericFormalFact {
                            owner,
                            ordinal,
                            parameter: declaration,
                        });
                    if let Some(default_type) = parameter.child_by_field_name("default_type")
                        && let Some(default) = self.lower_generic_formal_default(default_type)
                    {
                        self.facts.generic_formal_defaults.push(
                            ResolutionGenericFormalDefaultFact {
                                owner,
                                ordinal,
                                default,
                            },
                        );
                    }
                }
                let owner = parameters
                    .parent()
                    .expect("generic parameters have an item owner");
                let bounds = crate::structural::rust_declared_type_bounds(owner, name, self.source);
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
            self.retain_call_applicability_gap(declaration);
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
        let type_parameters = node
            .child_by_field_name("type_parameters")
            .map(|parameters| self.lower_generic_type_alias_parameters(parameters));
        let declares_type_parameters = type_parameters
            .as_ref()
            .is_some_and(|parameters| !parameters.is_empty());
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
        let target_expression = self.lower_alias_target_expression(target_node);
        let target = self.lower_declared_type_identity(target_node);
        let Some(target) = target else {
            self.add_semantic_gap_at_site(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
            return;
        };
        if let Some(formal_parameters) = type_parameters.filter(|parameters| !parameters.is_empty())
        {
            if let Some(target_expression) = target_expression {
                for (ordinal, parameter) in formal_parameters.into_iter().enumerate() {
                    self.facts.generic_type_alias_parameters.push(
                        ResolutionGenericTypeAliasParameterFact {
                            alias: declaration,
                            ordinal: u32::try_from(ordinal)
                                .expect("Rust generic type parameter count exceeds u32"),
                            parameter,
                            target: target_expression.identity,
                            indirection_delta: target_expression.indirection,
                            reference_indirection_delta: target_expression.reference_indirection,
                        },
                    );
                }
            } else {
                self.add_semantic_gap_at_site(
                    declaration,
                    ResolutionGapKind::UnsupportedTypeSyntax,
                );
            }
        }
        let has_written_indirection = target_expression
            .map(|expression| expression.indirection != 0 || expression.reference_indirection != 0)
            .unwrap_or(target.indirection != 0 || target.reference_indirection != 0);
        let transfer_target = if has_written_indirection {
            target_expression.unwrap_or(target)
        } else {
            target
        };
        // A reference or pointer alias carries its pointee identity and
        // qualifier layers in the written expression. Its nominal projection
        // is an unsupported impl-subject frontier, not the transfer input.
        // A generic alias's written target names its own unbound formals, so
        // it transfers the nominal head and the formal rows above carry the
        // substitution. A non-generic alias's written target is concrete
        // (`type Alias = Box<Item>`); its applied identity keeps the
        // arguments that Deref payloads and member lookup need.
        let transfer_input = if !has_written_indirection && declares_type_parameters {
            nominal_target.unwrap_or(transfer_target.identity)
        } else {
            transfer_target.identity
        };
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input: transfer_input,
            output,
            kind: written_type_transfer_kind(
                transfer_target.indirection,
                transfer_target.reference_indirection,
            ),
            indirection_delta: transfer_target.indirection,
            reference_indirection_delta: transfer_target.reference_indirection,
            value_transform: ResolutionTypeTransferValueTransform::Preserve,
        });
    }

    fn lower_generic_type_alias_parameters(
        &mut self,
        parameters: Node<'_>,
    ) -> Vec<ResolutionSiteId> {
        let mut parameter_cursor = parameters.walk();
        let mut lowered = Vec::new();
        for parameter in parameters.named_children(&mut parameter_cursor) {
            if parameter.kind() != "type_parameter" {
                continue;
            }
            let Some(name) = spelled_name(parameter) else {
                self.add_local_gap(parameter, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let declaration = self
                .facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && identifier.namespace == ResolutionNamespace::Type
                        && self.facts.sites[identifier.site.index()].start_byte == name.start_byte()
                        && self.facts.sites[identifier.site.index()].end_byte == name.end_byte()
                })
                .map(|identifier| identifier.site);
            if let Some(declaration) = declaration {
                lowered.push(declaration);
            } else {
                self.add_semantic_gap(parameter, ResolutionGapKind::UnsupportedScopeOrBinder);
            }
        }
        lowered
    }

    /// Preserve the identity of a generic alias target's written outer type.
    /// Receiver projection (for example `Box<T>` -> `T`) is useful for member
    /// lookup but is not the alias substitution target.
    fn lower_alias_target_expression(&mut self, mut node: Node<'_>) -> Option<LoweredDeclaredType> {
        let mut indirection = 0_i8;
        let mut reference_indirection = 0_i8;
        loop {
            match node.kind() {
                "reference_type" | "pointer_type" => {
                    indirection = indirection.checked_add(1)?;
                    if node.kind() == "reference_type" {
                        reference_indirection = reference_indirection.checked_add(1)?;
                    }
                    node = node
                        .child_by_field_name("type")
                        .expect("Rust indirection type has a type field");
                }
                "tuple_type"
                    if crate::type_syntax::rust_parenthesized_type_inner(node).is_some() =>
                {
                    node = crate::type_syntax::rust_parenthesized_type_inner(node)
                        .expect("parenthesized type has one inner type");
                }
                "generic_type" | "generic_type_with_turbofish" => {
                    let head = node
                        .child_by_field_name("type")
                        .expect("Rust generic_type has a type field");
                    let lowered = self.lower_declared_type_identity(head)?;
                    let arguments = node
                        .child_by_field_name("type_arguments")
                        .expect("Rust generic_type has type_arguments");
                    if !self
                        .lower_type_application_arguments(arguments, lowered.identity)
                        .0
                    {
                        self.add_semantic_gap(arguments, ResolutionGapKind::UnsupportedTypeSyntax);
                    }
                    let lowered = LoweredDeclaredType {
                        identity: lowered.identity,
                        indirection: indirection.saturating_add(lowered.indirection),
                        reference_indirection: reference_indirection
                            .saturating_add(lowered.reference_indirection),
                        head_name: lowered.head_name,
                    };
                    return Some(self.lower_alias_target_identity(lowered));
                }
                _ => {
                    let lowered = self.lower_declared_type_identity(node)?;
                    let lowered = LoweredDeclaredType {
                        identity: lowered.identity,
                        indirection: indirection.saturating_add(lowered.indirection),
                        reference_indirection: reference_indirection
                            .saturating_add(lowered.reference_indirection),
                        head_name: lowered.head_name,
                    };
                    return Some(self.lower_alias_target_identity(lowered));
                }
            }
        }
    }

    fn lower_alias_target_identity(
        &mut self,
        mut lowered: LoweredDeclaredType,
    ) -> LoweredDeclaredType {
        let source = lowered.identity;
        let site = self.facts.type_slots[source.index()].site;
        let Some(reference) = self
            .facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.site == site
                    && identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
            })
            .map(|identifier| identifier.site)
        else {
            return lowered;
        };
        let already_projected = self.facts.binding_projections.iter().any(|projection| {
            projection.reference == reference
                && projection.output == source
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        });
        if already_projected {
            return lowered;
        }

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
            kind: BindingProjectionKind::TargetTypeIdentity,
        });
        let arguments = self
            .facts
            .type_arguments
            .iter()
            .filter(|argument| argument.application == source)
            .copied()
            .collect::<Vec<_>>();
        self.facts
            .type_arguments
            .extend(
                arguments
                    .into_iter()
                    .map(|argument| ResolutionTypeArgumentFact {
                        application: output,
                        ..argument
                    }),
            );
        lowered.identity = output;
        lowered
    }

    /// Lower a written argument without receiver payload projection. Generic
    /// heads stay nominal; nested applications are returned to the stack walk.
    fn lower_written_type_argument<'tree>(
        &mut self,
        argument: Node<'tree>,
    ) -> Option<(LoweredDeclaredType, Option<Node<'tree>>)> {
        if !rust_is_type_argument_syntax(argument)
            || rust_node_text(argument, self.source) == "_"
            || rust_enclosing_item_generic_parameter_namespace(argument, self.source)
                == Some(ResolutionNamespace::Value)
        {
            self.add_semantic_gap(argument, ResolutionGapKind::UnsupportedTypeSyntax);
            return None;
        }
        let mut expression = argument;
        let mut indirection = 0_i8;
        let mut reference_indirection = 0_i8;
        loop {
            match expression.kind() {
                "reference_type" | "pointer_type" => {
                    let Some(next_indirection) = indirection.checked_add(1) else {
                        self.add_semantic_gap(expression, ResolutionGapKind::UnsupportedTypeSyntax);
                        return None;
                    };
                    indirection = next_indirection;
                    if expression.kind() == "reference_type" {
                        let Some(next_reference) = reference_indirection.checked_add(1) else {
                            self.add_semantic_gap(
                                expression,
                                ResolutionGapKind::UnsupportedTypeSyntax,
                            );
                            return None;
                        };
                        reference_indirection = next_reference;
                    }
                    expression = expression
                        .child_by_field_name("type")
                        .expect("Rust indirection type has a type field");
                }
                "tuple_type"
                    if crate::type_syntax::rust_parenthesized_type_inner(expression).is_some() =>
                {
                    expression = crate::type_syntax::rust_parenthesized_type_inner(expression)
                        .expect("parenthesized type has one inner type");
                }
                _ => break,
            }
        }
        if !rust_is_type_argument_syntax(expression)
            || rust_node_text(expression, self.source) == "_"
            || rust_enclosing_item_generic_parameter_namespace(expression, self.source)
                == Some(ResolutionNamespace::Value)
        {
            self.add_semantic_gap(expression, ResolutionGapKind::UnsupportedTypeSyntax);
            return None;
        }
        let (head, nested) = if matches!(
            expression.kind(),
            "generic_type" | "generic_type_with_turbofish"
        ) {
            (
                expression
                    .child_by_field_name("type")
                    .expect("Rust generic type has a head"),
                Some(
                    expression
                        .child_by_field_name("type_arguments")
                        .expect("Rust generic type has arguments"),
                ),
            )
        } else {
            (expression, None)
        };
        // A formal inside a callable's applied return is a symbolic identity
        // for selected result instantiation. Its ordinary Identity frontier
        // remains the bound surface used for parameter/member lookup.
        let mut ancestor = head.parent();
        let mut symbolic_formal = false;
        while let Some(item) = ancestor {
            if matches!(item.kind(), "function_item" | "function_signature_item") {
                if item
                    .child_by_field_name("return_type")
                    .is_some_and(|result| {
                        result.start_byte() <= head.start_byte()
                            && head.end_byte() <= result.end_byte()
                    })
                    && head.kind() == "type_identifier"
                {
                    let name = self.intern_name(head);
                    symbolic_formal = self.callable_type_parameters(item).0.contains(&Some(name));
                }
                break;
            }
            ancestor = item.parent();
        }
        let mut lowered = if symbolic_formal {
            LoweredDeclaredType {
                identity: self.lower_nominal_type_identity(head)?,
                indirection: 0,
                reference_indirection: 0,
                head_name: None,
            }
        } else {
            self.lower_declared_type_identity(head)?
        };
        lowered.indirection = indirection.saturating_add(lowered.indirection);
        lowered.reference_indirection =
            reference_indirection.saturating_add(lowered.reference_indirection);
        Some((lowered, nested))
    }

    fn lower_generic_formal_default(&mut self, node: Node<'_>) -> Option<ResolutionTypeSlotId> {
        let (lowered, nested) = self.lower_written_type_argument(node)?;
        let slot = if lowered.indirection == 0 && lowered.reference_indirection == 0 {
            lowered.identity
        } else {
            // A default has no enclosing argument row to hold its deltas.
            // Like an alias target, retain a type object while adding the
            // written reference or pointer layers to the nominal head.
            let site = self.add_site(
                node,
                ResolutionSiteKind::TypeReference,
                self.current_scope(),
            );
            let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust type slot count fits u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: output,
                site,
                role: ResolutionTypeSlotRole::TargetTypeIdentity,
            });
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: lowered.identity,
                output,
                kind: written_type_transfer_kind(
                    lowered.indirection,
                    lowered.reference_indirection,
                ),
                indirection_delta: lowered.indirection,
                reference_indirection_delta: lowered.reference_indirection,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
            output
        };
        if let Some(arguments) = nested {
            self.lower_type_application_arguments(arguments, slot);
        }
        Some(slot)
    }

    /// Keep the written nominal application separate from its query-time
    /// receiver projection. The map is scoped to this blob's lowering.
    fn conditional_type_application(
        &mut self,
        node: Node<'_>,
        input: ResolutionTypeSlotId,
    ) -> ResolutionTypeSlotId {
        let key = (node.id(), self.current_scope());
        if let Some(&output) = self.conditional_type_applications.get(&key) {
            return output;
        }
        let site = self.add_site(
            node,
            ResolutionSiteKind::TypeReference,
            self.current_scope(),
        );
        let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Rust type-slot count fits u32");
        self.facts.type_slots.push(ResolutionTypeSlotFact {
            id: output,
            site,
            role: ResolutionTypeSlotRole::TargetTypeIdentity,
        });
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input,
            output,
            kind: ResolutionTypeTransferKind::ConditionalPayload,
            indirection_delta: 0,
            reference_indirection_delta: 0,
            value_transform: ResolutionTypeTransferValueTransform::Preserve,
        });
        self.conditional_type_applications.insert(key, output);
        output
    }

    /// Persist supported arguments without shifting unknown positions. Nested
    /// applications use an explicit stack rather than recursive Rust calls.
    fn lower_type_application_arguments<'tree>(
        &mut self,
        arguments: Node<'tree>,
        application: ResolutionTypeSlotId,
    ) -> (bool, Vec<(Node<'tree>, ResolutionTypeSlotId)>) {
        let mut pending = vec![(arguments, application)];
        let mut complete = true;
        let mut applications = Vec::new();
        while let Some((arguments, application)) = pending.pop() {
            let mut cursor = arguments.walk();
            let mut ordinal = 0_u32;
            // The inferred `_` type is an anonymous grammar token, but still
            // occupies an argument position. Delimiters are not arguments.
            for argument in arguments
                .children(&mut cursor)
                .filter(|argument| argument.is_named() || argument.kind() == "_")
            {
                if argument.is_extra() || argument.kind() == "lifetime" {
                    continue;
                }
                // Every non-lifetime syntax position counts, including unknown
                // const expressions and inferred types. Never shift later types.
                let argument_ordinal = ordinal;
                ordinal = ordinal
                    .checked_add(1)
                    .expect("Rust generic type argument count exceeds u32");
                let Some((lowered, nested)) = self.lower_written_type_argument(argument) else {
                    complete = false;
                    continue;
                };
                if self
                    .lowered_type_application_arguments
                    .insert((application, argument_ordinal))
                {
                    self.facts.type_arguments.push(ResolutionTypeArgumentFact {
                        application,
                        ordinal: argument_ordinal,
                        argument: lowered.identity,
                        indirection_delta: lowered.indirection,
                        reference_indirection_delta: lowered.reference_indirection,
                    });
                }
                if let Some(nested) = nested {
                    applications.push((
                        nested.parent().expect("type arguments have an application"),
                        lowered.identity,
                    ));
                    pending.push((nested, lowered.identity));
                }
            }
        }
        (complete, applications)
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
        let body = self.lower_module_body(node, None);
        self.facts
            .define_module(declaration, ResolutionNamespace::Type, body);
    }

    fn lower_module_body(
        &mut self,
        node: Node<'_>,
        owner: Option<ResolutionSiteId>,
    ) -> Option<ResolutionScopeId> {
        let body = node.child_by_field_name("body")?;
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
        Some(scope)
    }

    fn lower_macro_definition(
        &mut self,
        node: Node<'_>,
        macro_definition: Option<&RustRulesItemMacroDefinition>,
    ) {
        let Some(name) = spelled_name(node) else {
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
        // The source walker already lowered each ordinary cfg_if item with
        // its ordered arm guard. No unknown transcriber remains at this site.
        if self.discharged_item_macros.contains(&node.id())
            && crate::cfg_if::is_cfg_if(node, self.source)
        {
            return;
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
                    if !self.discharged_item_macros.contains(&node.id())
                        && !proofs.passthrough
                        && !proofs.declares_no_item
                        && !frontier
                        && source_position != RustItemMacroSourcePosition::Other
                    {
                        let kind = if proofs.writes_only_impls {
                            ResolutionGapKind::UnexpandedImplMacro
                        } else {
                            ResolutionGapKind::UnexpandedItemMacro
                        };
                        let site = self.add_site(
                            node,
                            ResolutionSiteKind::UnsupportedExpression,
                            self.current_scope(),
                        );
                        self.add_semantic_gap_at_site(site, kind);
                        if transcribed_paths.member_surface_closed {
                            assert_eq!(kind, ResolutionGapKind::UnexpandedItemMacro);
                            self.facts.engine_rule_eligibilities.push(
                                ResolutionEngineRuleEligibilityFact {
                                    site,
                                    rule: ResolutionEngineRuleKind::ClosedMacroMemberSurface,
                                },
                            );
                        }
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
        // A duplicate export has no unique transcriber authority. Parsing
        // its input as an expression is only a guess, including when the
        // invocation itself is in expression position.
        let ambiguous_export = rust_unqualified_macro_invocation_name(node, self.source)
            .or_else(|| crate::macro_matcher::crate_root_macro_invocation_name(node, self.source))
            .is_some_and(|name| {
                self.exported_macro_definitions
                    .get(name)
                    .is_some_and(Option::is_none)
            });
        let enumerated = if item_position || ambiguous_export {
            self.lower_guessed_macro_arguments(node)
        } else {
            self.lower_definition_less_macro_arguments(node)
        };
        if item_position {
            // Like an unexpanded attribute (#5205), this expansion can add
            // names but cannot shadow an existing binding. Its impls keep
            // the member surfaces of scope-owned types open, independently
            // of whether the argument grammar could be guessed.
            let site = self.add_site(
                node,
                ResolutionSiteKind::UnsupportedExpression,
                self.current_scope(),
            );
            self.add_semantic_gap_at_site(site, ResolutionGapKind::GeneratedItemSurface);
            // Keep the member-only obligation on the argument tree. The
            // invocation frontier itself also admits new lexical names;
            // it is not a proof that the macro writes only impl blocks.
            let arguments = crate::declarations::rust_macro_invocation_arguments(node)
                .expect("a macro invocation has its argument tree");
            self.add_semantic_gap(arguments, ResolutionGapKind::UnexpandedImplMacro);
            if !enumerated {
                // Keep the input-inventory obligation on the macro frontier
                // so scoped reverse queries retain its unparseable groups.
                self.facts
                    .reference_enumeration_gaps
                    .push(ResolutionReferenceEnumerationGapFact {
                        site,
                        kind: ResolutionGapKind::UnsupportedExpression,
                    });
            }
        } else if enumerated {
            self.add_semantic_gap(node, ResolutionGapKind::UnsupportedExpression);
        } else {
            self.add_local_gap(node, ResolutionGapKind::UnsupportedExpression);
        }
    }

    /// Unsupported item input and ambiguous exports have no unique grammar
    /// authority, even when their expressions parse. Both primary and replayed
    /// fragments must retain that reference uncertainty.
    fn lower_guessed_macro_arguments(&mut self, node: Node<'_>) -> bool {
        let guessing = self.guessing_macro_references;
        self.guessing_macro_references = true;
        let enumerated = self.lower_definition_less_macro_arguments(node);
        self.guessing_macro_references = guessing;
        enumerated
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
    /// Returns whether every input group parsed. This says nothing about
    /// references synthesized by expansion, which are the accepted residual
    /// for additive generation (#5205). Only unparsed groups leave the
    /// reverse reference inventory incomplete.
    /// Other definitionless macros retain the structured expression guess:
    /// `cfg!(unix)` publishes `unix`, while the `matches!` pattern operand
    /// distinguishes a visible variant from a new pattern binding.
    fn lower_definition_less_macro_arguments(&mut self, node: Node<'_>) -> bool {
        let Some(operands) = crate::macro_matcher::parse_macro_operands(node, self.source) else {
            return false;
        };
        let scope = self.current_scope();
        let bindings = operands
            .into_iter()
            .map(|operand| (operand.binding, operand.tree))
            .collect::<Vec<_>>();
        let first_pattern_identifier = self.facts.identifiers.len();
        let first_pattern_gap = self.facts.gaps.len();
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
        if self.guessing_macro_references {
            self.mark_macro_argument_guesses(first_pattern_identifier, first_pattern_gap);
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
                        guessed_references: self.guessing_macro_references,
                        self_owner,
                    }),
            );
        if !self.lowering_macro_fragments {
            self.lower_pending_macro_fragments();
        }
        true
    }

    /// Divan's proc-macro attribute accepts Rust expressions in its `args`
    /// option. Its structured expression value names source items in the
    /// bench target's module independently of the generated item surface.
    fn lower_divan_bench_attribute_arguments(&mut self, node: Node<'_>) {
        use crate::macro_matcher::{MacroBinding, MacroFragmentKind};

        let scope = self.current_scope();
        let owner = self.declaration_owners.last().copied();
        let mut queued = Vec::new();
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
                guessed_references: self.guessing_macro_references,
                self_owner: None,
            });
        }
        if !queued.is_empty() {
            self.pending_macro_fragments.extend(queued);
            self.lower_pending_macro_fragments();
        }
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
                guessed_references: self.guessing_macro_references,
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
                if macro_transcriber_fragment_node(&type_tree, &fragment).is_none() {
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
                let node = macro_transcriber_fragment_node(&type_tree, &fragment)
                    .expect("parsed type fragment has its type identifier");
                if !self.handled_identifiers.contains(&node.id()) {
                    if node.kind() == "scoped_type_identifier" {
                        self.lower_qualified_type_reference(node);
                    } else {
                        self.lower_bare_type_reference(node);
                    }
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
            guessed_references: self.guessing_macro_references,
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
        if segments.len() < 3
            || segments[0].kind() != "crate"
            || segments
                .iter()
                .any(|segment| !name_node_has_spelling(*segment))
        {
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
                    spelled_name(*module).is_none_or(|name| {
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
                guessed_references,
                self_owner,
            } = fragment;
            let scopes = std::mem::replace(&mut self.scopes, vec![scope]);
            let owners =
                std::mem::replace(&mut self.declaration_owners, owner.into_iter().collect());
            let self_owners = std::mem::replace(&mut self.macro_fragment_self_owner, self_owner);
            let guessing =
                std::mem::replace(&mut self.guessing_macro_references, guessed_references);
            let first_identifier = self.facts.identifiers.len();
            let first_gap = self.facts.gaps.len();
            self.lower_macro_fragment(&binding, tree, container, occurrence_provenance);
            if guessed_references {
                // Keep uncertainty on the references we guessed, never on
                // authored binders beside the invocation. Nested fragments
                // inherit the provenance when they are queued.
                self.mark_macro_argument_guesses(first_identifier, first_gap);
            }
            self.guessing_macro_references = guessing;
            assert_eq!(self.scopes, [scope]);
            assert_eq!(self.declaration_owners.last().copied(), owner);
            self.scopes = scopes;
            self.declaration_owners = owners;
            self.macro_fragment_self_owner = self_owners;
        }
        self.lowering_macro_fragments = false;
    }

    fn mark_macro_argument_guesses(&mut self, first_identifier: usize, first_gap: usize) {
        // Lowering a computed receiver (or a nested macro pattern) can already
        // put this uncertainty on a new reference. The macro guess adds the
        // same obligation only where absent; other gap kinds remain separate.
        // Only this fragment's newly emitted facts can name its new sites.
        let mut unsupported = self.facts.gaps[first_gap..]
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedExpression)
            .map(|gap| gap.site)
            .collect::<HashSet<_>>();
        self.facts.gaps.extend(
            self.facts.identifiers[first_identifier..]
                .iter()
                .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                .filter(|identifier| unsupported.insert(identifier.site))
                .map(|identifier| {
                    ResolutionGapFact::new(
                        identifier.site,
                        ResolutionGapKind::UnsupportedExpression,
                    )
                }),
        );
    }

    fn lower_macro_fragment(
        &mut self,
        binding: &crate::macro_matcher::MacroBinding,
        tree: tree_sitter::Tree,
        container: crate::macro_matcher::RustMacroItemContainer,
        occurrence_provenance: SourceOccurrenceProvenance,
    ) {
        let root = if matches!(
            binding.fragment,
            crate::macro_matcher::MacroFragmentKind::Ty
                | crate::macro_matcher::MacroFragmentKind::Path
        ) {
            // Type and path fragments are parsed inside a synthetic type
            // alias. Its name becomes zero-width when the wrapper prefix is
            // rebased to the captured source range, so lower only the type
            // field rather than treating the wrapper as a source declaration.
            let wrapper = tree
                .root_node()
                .named_child(0)
                .expect("parsed type fragment has its synthetic alias");
            assert_eq!(wrapper.kind(), "type_item");
            wrapper
                .child_by_field_name("type")
                .expect("synthetic type alias has its fragment type")
        } else {
            tree.root_node()
                .descendant_for_byte_range(binding.start_byte, binding.end_byte)
                .expect("parsed fragment retains its captured range")
        };
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
                    self.lower_module_body(node, Some(declaration))
                        .expect("an inline Rust module has a body scope");
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
        let name = spelled_name(node)?;
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
            let Some(segments) = rust_path_segments(node) else {
                self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            if segments
                .iter()
                .any(|segment| !name_node_has_spelling(*segment))
            {
                self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            // `$crate`, and ordinary `crate` for a non-exported macro, pin
            // an item path to this crate. Other template paths need context;
            // publishing a definition-site route would invent a target.
            let definition_anchored = segments
                .first()
                .is_some_and(|head| definition_crate_anchors.contains(&head.start_byte()));
            if !definition_anchored {
                let name = spelled_name(node).expect("validated static path has a name");
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
                let head = segments[0];
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
    fn lower_use_prefix_references(&mut self, declaration: Node<'_>) -> bool {
        let argument = declaration
            .child_by_field_name("argument")
            .expect("use has an argument");
        let mut pending = vec![(argument, Vec::new(), ResolutionRootImportAnchor::Lexical)];
        let mut prefix_sites = HashMap::new();
        let mut unsupported_route = false;
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
                            self.add_local_gap(path, ResolutionGapKind::MalformedSyntax);
                            continue;
                        };
                        if segments
                            .iter()
                            .any(|segment| !name_node_has_spelling(*segment))
                        {
                            self.add_local_gap(path, ResolutionGapKind::MalformedSyntax);
                            continue;
                        }
                        if rust_path_segments_have_misplaced_anchor(
                            prefix.iter().copied().chain(segments.iter().copied()),
                            self.source,
                            false,
                        ) {
                            unsupported_route = true;
                            continue;
                        }
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
                self.add_local_gap(path, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            if segments
                .iter()
                .any(|segment| !name_node_has_spelling(*segment))
            {
                self.add_local_gap(path, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            if rust_path_segments_have_misplaced_anchor(
                prefix.iter().copied().chain(segments.iter().copied()),
                self.source,
                rust_use_path_terminal_self(path, self.source),
            ) {
                unsupported_route = true;
                continue;
            }
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
                let keyword = rust_path_anchor_keyword(*name, self.source);
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
                        && !rust_path_anchor_keyword(prefix[0], self.source))
                    .then(|| prefix_sites.get(&prefix[0].id()).copied())
                    .flatten();
                    self.facts
                        .root_references
                        .push(ResolutionRootReferenceFact {
                            reference,
                            root_scope,
                            anchor,
                            prefix_reference,
                            owner_continued: false,
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
        unsupported_route
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
        let mut needs_enumeration_gap = projected_imports.is_empty();
        for projected in projected_imports {
            assert!(
                projected.import.is_extern_crate(),
                "an extern crate declaration projects extern crate imports: {projected:?}"
            );
            if let Some(name) = projected.import.binding_name().named() {
                let name = self.intern_spelling(name);
                self.extern_crate_bindings.push((root_scope, name));
            }
            if projected.import.is_macro_use {
                self.add_site(node, ResolutionSiteKind::ImportDeclaration, root_scope);
                needs_enumeration_gap = true;
            }
        }
        // A structured plain `extern crate` declaration is fully represented
        // by the shared import projection and Cargo route facts. It does not
        // name an in-workspace declaration site. Macro-use imports still have
        // an open macro surface, and malformed/unprojected declarations stay
        // conservative.
        if needs_enumeration_gap {
            self.add_enumeration_gap(node, ResolutionGapKind::UnsupportedScopeOrBinder);
        }
    }

    fn lower_unprojected_use_declaration(&mut self, node: Node<'_>, scope: ResolutionScopeId) {
        // No projected leaves can mean either no binders (empty groups) or an
        // unknown binder surface (for example `use *;`). Decide from the tree,
        // not from the size of the projection. Comments do not introduce leaves.
        let mut empty_groups = !node.has_error();
        let mut prefixes = Vec::new();
        let mut pending = node
            .child_by_field_name("argument")
            .map(|argument| vec![(argument, Vec::new())])
            .unwrap_or_default();
        empty_groups &= !pending.is_empty();
        while let Some((argument, mut prefix)) = pending.pop() {
            match argument.kind() {
                "use_list" => {
                    let mut cursor = argument.walk();
                    pending.extend(
                        argument
                            .named_children(&mut cursor)
                            .map(|child| (child, prefix.clone())),
                    );
                }
                "scoped_use_list" => {
                    if let Some(path) = argument.child_by_field_name("path") {
                        let Some(segments) = rust_path_segments(path) else {
                            empty_groups = false;
                            break;
                        };
                        prefix.extend(segments);
                        if prefix
                            .iter()
                            .any(|segment| !name_node_has_spelling(*segment))
                            || rust_path_segments_have_misplaced_anchor(
                                prefix.iter().copied(),
                                self.source,
                                false,
                            )
                        {
                            empty_groups = false;
                            break;
                        }
                        prefixes.push((path, prefix.last().copied()));
                    }
                    let Some(list) = argument.child_by_field_name("list") else {
                        empty_groups = false;
                        break;
                    };
                    pending.push((list, prefix));
                }
                "line_comment" | "block_comment" => {}
                _ => {
                    empty_groups = false;
                    break;
                }
            }
        }
        if !empty_groups {
            self.add_local_binder_route_gap(node, scope, &[]);
            return;
        }
        // Prefix lowering emits references only when it reaches a leaf. Empty
        // groups have none, but their paths still name modules. State exactly
        // that omitted reference, without opening the scope's binder surface.
        for (path, terminal) in prefixes {
            let terminal = terminal.map(|terminal| self.intern_name(terminal));
            self.add_local_route_gap(
                path,
                ResolutionRouteGap::OmittedReference {
                    scope,
                    terminal,
                    namespace: Some(ResolutionNamespace::Type),
                },
            );
        }
    }

    fn lower_use_declaration(&mut self, node: Node<'_>, projected_imports: &[RustProjectedImport]) {
        // A `use` is an item: where a block declares items, its binder belongs
        // in that block's item scope, beside the items that can name it.
        let root_scope = self.item_scope();
        if projected_imports.is_empty() {
            self.lower_unprojected_use_declaration(node, root_scope);
            return;
        }
        if !matches!(
            self.facts.scopes[root_scope.index()].kind,
            ResolutionScopeKind::CompilationUnit
                | ResolutionScopeKind::Package
                | ResolutionScopeKind::Executable
                | ResolutionScopeKind::Block
        ) {
            self.add_local_binder_route_gap(node, root_scope, projected_imports);
            return;
        }

        let route_root_scope = self.nearest_root_scope();
        let mut unsupported = false;
        for projected in projected_imports {
            assert!(
                !projected.import.is_extern_crate(),
                "extern crate declarations do not use the use-declaration lowering path"
            );
            let import = &projected.import;
            let allow_terminal_self_import =
                !import.module_self || import.path().last().is_none_or(|segment| segment != "self");
            if rust_import_path_has_misplaced_anchor(import.path(), allow_terminal_self_import) {
                unsupported = true;
                continue;
            }
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
            if projected.cfg_condition != RustCfgCondition::Always {
                self.conditional_imports.insert(site);
            }
            self.facts.root_imports.push(ResolutionRootImportFact {
                site,
                root_scope,
                anchor: if import.info.is_global {
                    ResolutionRootImportAnchor::Absolute
                } else {
                    ResolutionRootImportAnchor::Lexical
                },
                position: None,
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
                            owner_continued: false,
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
        unsupported |= self.lower_use_prefix_references(node);
        if unsupported {
            self.add_local_binder_route_gap(node, root_scope, projected_imports);
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
        // An unconditional named import wins in every selected cfg context.
        // Conditional imports keep their glob alternatives until selection.
        let explicit_demands = self
            .facts
            .root_import_demands
            .iter()
            .filter(|demand| !self.conditional_imports.contains(&demand.import_site))
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
        }
        // The grammar places `mut` beside the identifier in a let declaration;
        // destructuring and ref patterns need component/reference projections,
        // so they cannot take the initializer's value wholesale.
        if pattern.kind() == "identifier" {
            let [declaration] = declarations[..] else {
                assert!(
                    declarations.is_empty(),
                    "one identifier declares one binding"
                );
                return;
            };
            // Keep the inferred value property even before the first write;
            // an absent initializer contributes no input to that property.
            let inferred = if node.child_by_field_name("type").is_none() {
                let [(_, slot)] = self
                    .allocate_declaration_type_slots(&[declaration], DeclarationTypeRole::Value)[..]
                else {
                    unreachable!("one declaration allocates one slot");
                };
                Some(slot)
            } else {
                None
            };
            if let Some(initializer) = node.child_by_field_name("value") {
                self.queue_runtime_value(
                    initializer,
                    PendingRuntimeValue {
                        site: declaration,
                        destination: RuntimeValueDestination::Initializer { inferred },
                        adjustments: Vec::new(),
                    },
                );
            }
        } else if node.child_by_field_name("value").is_some() {
            self.lower_unknown_pattern_initializers(pattern, &declarations);
        }
    }

    /// These binders receive runtime values, but component/reference projection
    /// is not modeled. Retain that unknown input independently of any annotated
    /// type so a later write cannot make the observed value appear complete.
    fn lower_unknown_pattern_initializers(
        &mut self,
        pattern: Node<'_>,
        declarations: &[ResolutionSiteId],
    ) {
        for &declaration in declarations {
            assert_eq!(
                self.facts.sites[declaration.index()].kind,
                ResolutionSiteKind::ValueDeclaration
            );
            self.connect_runtime_value(
                pattern,
                PendingRuntimeValue {
                    site: declaration,
                    destination: RuntimeValueDestination::Initializer { inferred: None },
                    adjustments: Vec::new(),
                },
                None,
            );
        }
    }

    fn lower_local_write(&mut self, node: Node<'_>) {
        // A parsed token-tree fragment is reference evidence, not proof that
        // `name = value` executes: it can be a macro's named option. Proven
        // item passthrough replay has declaration authority and uses the
        // ordinary statement semantics within its replayed item bodies.
        if self.embedded_identity.is_none()
            && (self.macro_fragment_nodes.contains(&node.id())
                || self.explicit_source_fragment_nodes.contains(&node.id()))
        {
            return;
        }
        let Some(left) = node.child_by_field_name("left") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if left.kind() != "identifier" || !name_node_has_spelling(left) {
            // A field/index/dereference target does not rebind its receiver.
            // Tuple and array targets rebind their bare names, but need
            // component projections before any RHS values can be copied.
            self.add_semantic_gap(left, ResolutionGapKind::UnsupportedExpression);
            let mut targets = vec![left];
            while let Some(target) = targets.pop() {
                match target.kind() {
                    "tuple_expression" | "array_expression" | "parenthesized_expression" => {
                        let mut cursor = target.walk();
                        let children = target.named_children(&mut cursor).collect::<Vec<_>>();
                        targets.extend(children.into_iter().rev());
                    }
                    "identifier" if name_node_has_spelling(target) => {
                        let output = self.lower_runtime_value_reference(target);
                        let pending = PendingRuntimeValue {
                            site: self.facts.type_slots[output.index()].site,
                            destination: RuntimeValueDestination::LocalWrite,
                            adjustments: Vec::new(),
                        };
                        self.connect_runtime_value(target, pending, None);
                    }
                    _ => {}
                }
            }
            return;
        }
        let output = self.lower_runtime_value_reference(left);
        let target = self.facts.type_slots[output.index()].site;
        let pending = PendingRuntimeValue {
            site: target,
            destination: RuntimeValueDestination::LocalWrite,
            adjustments: Vec::new(),
        };
        if node.kind() == "assignment_expression"
            && let Some(right) = node.child_by_field_name("right")
        {
            self.queue_runtime_value(right, pending);
        } else {
            // Compound operators compute a new value. Keep an unknown input
            // rather than treating their RHS as the result of that operation.
            self.connect_runtime_value(node, pending, None);
        }
    }

    fn queue_runtime_value(&mut self, value: Node<'_>, mut pending: PendingRuntimeValue) {
        if let Some((producer, adjustments)) = rust_runtime_value_producer(value, self.source) {
            pending.adjustments = adjustments
                .into_iter()
                .map(|(wrapper, kind)| RuntimeValueAdjustment {
                    site: self.add_site(
                        wrapper,
                        if wrapper.kind() == "call_expression" {
                            ResolutionSiteKind::Call
                        } else {
                            ResolutionSiteKind::UnaryExpression
                        },
                        self.current_scope(),
                    ),
                    kind,
                })
                .collect();
            self.pending_runtime_values
                .entry(producer.id())
                .or_default()
                .push(pending);
        } else {
            self.connect_runtime_value(value, pending, None);
        }
    }

    /// Connect an expression's produced value to every waiting initializer or
    /// write, preserving the order of borrow and unwrap layers before recording
    /// the observation.
    fn discharge_pending_runtime_values(
        &mut self,
        node: Node<'_>,
        produced: Option<ResolutionTypeSlotId>,
    ) {
        for pending in self
            .pending_runtime_values
            .remove(&node.id())
            .unwrap_or_default()
        {
            self.connect_runtime_value(node, pending, produced);
        }
    }

    fn connect_runtime_value(
        &mut self,
        node: Node<'_>,
        pending: PendingRuntimeValue,
        produced: Option<ResolutionTypeSlotId>,
    ) {
        let mut input = produced.unwrap_or_else(|| {
            let site = self.add_site(
                node,
                ResolutionSiteKind::UnsupportedExpression,
                self.current_scope(),
            );
            assert_ne!(site, pending.site, "unknown input owns a separate gap site");
            let value = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: value,
                site,
                role: ResolutionTypeSlotRole::ExpressionValue,
            });
            self.add_semantic_gap_at_site(site, ResolutionGapKind::UnsupportedExpression);
            value
        });
        assert!(matches!(
            self.facts.type_slots[input.index()].role,
            ResolutionTypeSlotRole::CallResult | ResolutionTypeSlotRole::ExpressionValue
        ));
        // Syntax was peeled outside-in; values flow from the leaf back out.
        for adjustment in pending.adjustments.into_iter().rev() {
            let (role, kind, indirection_delta, reference_indirection_delta, value_transform) =
                match adjustment.kind {
                    RuntimeValueAdjustmentKind::Borrow => (
                        ResolutionTypeSlotRole::ExpressionValue,
                        ResolutionTypeTransferKind::AddressOf,
                        1,
                        1,
                        ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                    ),
                    RuntimeValueAdjustmentKind::Unwrap => (
                        ResolutionTypeSlotRole::CallResult,
                        ResolutionTypeTransferKind::Unwrap,
                        -1,
                        0,
                        ResolutionTypeTransferValueTransform::Preserve,
                    ),
                };
            let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                .expect("Rust resolution type-slot count exceeds u32");
            self.facts.type_slots.push(ResolutionTypeSlotFact {
                id: output,
                site: adjustment.site,
                role,
            });
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input,
                output,
                kind,
                indirection_delta,
                reference_indirection_delta,
                value_transform,
            });
            input = output;
        }
        match pending.destination {
            RuntimeValueDestination::Initializer { inferred } => {
                if let Some(output) = inferred {
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input,
                        output,
                        kind: ResolutionTypeTransferKind::Initialization,
                        indirection_delta: 0,
                        reference_indirection_delta: 0,
                        value_transform: ResolutionTypeTransferValueTransform::Preserve,
                    });
                }
                let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                    .expect("Rust resolution type-slot count exceeds u32");
                self.facts.type_slots.push(ResolutionTypeSlotFact {
                    id: output,
                    site: pending.site,
                    role: ResolutionTypeSlotRole::AssignmentValue,
                });
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input,
                    output,
                    kind: ResolutionTypeTransferKind::Assignment,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
            }
            RuntimeValueDestination::LocalWrite => {
                self.facts.local_writes.push(ResolutionLocalWriteFact {
                    target: pending.site,
                    value: input,
                });
            }
        }
    }

    fn enter_closure_scope(&mut self, node: Node<'_>) {
        let Some(body) = node.child_by_field_name("body") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            let scope =
                self.allocate_node_scope(node, ResolutionScopeKind::Executable, node.end_byte());
            self.activate_scope(scope);
            return;
        };
        let scope =
            self.allocate_node_scope(node, ResolutionScopeKind::Executable, body.end_byte());
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
        self.activate_scope(scope);
    }

    fn enter_for_scope(&mut self, node: Node<'_>) {
        let Some(body) = node.child_by_field_name("body") else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            let scope = self.allocate_node_scope(node, ResolutionScopeKind::Block, node.end_byte());
            self.activate_scope(scope);
            return;
        };
        let scope = self.allocate_node_scope(node, ResolutionScopeKind::Block, body.end_byte());
        if let Some(pattern) = node.child_by_field_name("pattern") {
            let declarations = self.lower_pattern_bindings(
                pattern,
                scope,
                ResolutionBinderKind::Pattern,
                body.start_byte(),
                RustPatternBindingPosition::Irrefutable,
            );
            self.lower_unknown_pattern_initializers(pattern, &declarations);
        } else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
        }
        self.activate_scope(scope);
    }

    fn enter_match_arm_scope(&mut self, node: Node<'_>) {
        let scope = self.allocate_node_scope(node, ResolutionScopeKind::Block, node.end_byte());
        if let Some(pattern) = node.child_by_field_name("pattern") {
            let declarations = self.lower_pattern_bindings(
                pattern,
                scope,
                ResolutionBinderKind::Pattern,
                pattern.end_byte(),
                RustPatternBindingPosition::Refutable,
            );
            self.lower_unknown_pattern_initializers(pattern, &declarations);
        } else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
        }
        self.activate_scope(scope);
    }

    fn allocate_node_scope(
        &mut self,
        node: Node<'_>,
        kind: ResolutionScopeKind,
        end_byte: usize,
    ) -> ResolutionScopeId {
        self.allocate_scope(
            self.current_scope(),
            None,
            kind,
            node.start_byte(),
            end_byte,
        )
    }

    fn activate_scope(&mut self, scope: ResolutionScopeId) {
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
        self.prepare_let_condition_scope(
            condition,
            body,
            [(condition, Some(pattern), body.start_byte())],
            [(
                body,
                "one direct Rust let condition owns one consequence scope",
            )],
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
        let pending = [
            (
                chain,
                "one Rust let chain owns its condition and consequence scopes",
            ),
            (
                body,
                "one Rust let chain owns its condition and consequence scopes",
            ),
        ];
        self.prepare_let_condition_scope(
            chain,
            body,
            conditions.into_iter().map(|condition| {
                (
                    condition,
                    condition.child_by_field_name("pattern"),
                    condition.end_byte(),
                )
            }),
            pending,
        );
    }

    fn prepare_let_condition_scope<'tree>(
        &mut self,
        scope_node: Node<'tree>,
        body: Node<'tree>,
        conditions: impl IntoIterator<Item = (Node<'tree>, Option<Node<'tree>>, usize)>,
        pending_nodes: impl IntoIterator<Item = (Node<'tree>, &'static str)>,
    ) {
        let scope = self.allocate_statement_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Block,
            scope_node.start_byte(),
            body.end_byte(),
            body,
        );
        for (condition, pattern, activation_start) in conditions {
            let Some(pattern) = pattern else {
                self.add_local_gap(condition, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let declarations = self.lower_pattern_bindings(
                pattern,
                scope,
                ResolutionBinderKind::Pattern,
                activation_start,
                RustPatternBindingPosition::Refutable,
            );
            self.lower_unknown_pattern_initializers(pattern, &declarations);
        }
        for (node, assertion_message) in pending_nodes {
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
                "{}",
                assertion_message
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
                    // Recovery leaves a zero-width missing identifier in
                    // pattern position (`if let = x {}`); it has no spelling
                    // to bind. The walk's visit of the node itself records
                    // the MalformedSyntax gap.
                    if name_node_has_spelling(node) {
                        binding_nodes.push((node, alternative));
                    }
                }
                "shorthand_field_identifier" => {
                    if name_node_has_spelling(node) {
                        binding_nodes.push((node, false));
                    }
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
                    self.lower_type_application_arguments(arguments, identity);
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
                _ => self.retain_call_applicability_gap(call),
            }
        }
        let result = lowered.map(|(_, result)| result);
        self.discharge_pending_runtime_values(node, result);
        self.discharge_pending_receivers(node, result);
        self.discharge_pending_argument(node, result);
    }

    /// A call written in a macro transcriber is a template: `$x` and
    /// `$(..),*` stand for actuals the invocation supplies, so the written
    /// list is not the call's arity, and the walk never visits its arguments.
    fn lower_transcriber_call_reference(&mut self, node: Node<'_>) {
        self.pending_expected_results.remove(&node.id());
        if let Some((call, _)) = self.lower_call_reference_result(node) {
            self.retain_call_applicability_gap(call);
        }
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
                if !name_node_has_spelling(name) {
                    self.add_local_gap(target, ResolutionGapKind::MalformedSyntax);
                    return None;
                }
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
                    // the token. The receiver's nominal owner and reference
                    // layers come from the impl context below, so the site
                    // adds a binding occurrence without changing how the
                    // member itself resolves.
                    self.lower_runtime_value_reference(self_value);
                    // An unknown owner is not an omitted binder: the member
                    // reference below still inventories the callee, and
                    // lower_computed_receiver attaches its receiver gap to
                    // that positioned reference when no owner is available.
                }
                let receiver_type =
                    standard_self_owner
                        .map(|owner| owner.owner_type)
                        .or_else(|| {
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
                    let reference_indirection =
                        standard_self_owner.map_or(0, |owner| owner.reference_indirection);
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input,
                        output: qualifier,
                        kind: ResolutionTypeTransferKind::Receiver,
                        indirection_delta: reference_indirection,
                        reference_indirection_delta: reference_indirection,
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
        self.facts.gaps.push(ResolutionGapFact::new(
            callee,
            ResolutionGapKind::UnsupportedCallApplicability,
        ));
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
            self.add_declared_type_transfer(declared, value);
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
                list_ordinal: 0,
                ordinal: u32::try_from(ordinal).expect("Rust call argument count exceeds u32"),
                value,
                label: None,
            });
            let mut operand = rust_receiver_operand(argument);
            let mut reference_layers = 0i8;
            while operand.kind() == "reference_expression" {
                let Some(inner) = rust_borrow_operand(operand) else {
                    break;
                };
                let Some(layers) = reference_layers.checked_add(1) else {
                    // Leave the unsupported wrapper as the gap-fed operand;
                    // do not truncate the depth and type its inner value.
                    break;
                };
                reference_layers = layers;
                operand = rust_receiver_operand(inner);
            }
            let pending = PendingArgument {
                argument: value,
                reference_layers,
            };
            match operand.kind() {
                // A missing operand (`f(&&)` leaves a missing identifier
                // under the reference layers) is skipped by the walk, so a
                // slot keyed on it would never discharge. Fall to the
                // gap-feeding arm instead.
                "identifier" | "self" | "call_expression" | "field_expression"
                    if !operand.is_missing() && !operand.is_error() =>
                {
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
            let mut literal = rust_literal_type(operand, self.source);
            if let Some(RustLiteralType::Exact {
                reference_layers, ..
            }) = literal
            {
                match pending.reference_layers.checked_add(reference_layers) {
                    Some(layers) => pending.reference_layers = layers,
                    // A string already contributes one reference layer. Even
                    // 127 written borrows must leave an unknown, not panic or
                    // publish a truncated intrinsic type.
                    None => literal = Some(RustLiteralType::Unsupported),
                }
            }
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
                Some(RustLiteralType::Exact { primitive, .. }) => {
                    let name = self.intern_spelling(primitive);
                    self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                        output: input,
                        name,
                        kind: IntrinsicTypeKind::Primitive,
                        indirection: 0,
                    });
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
        let Some(name) = node
            .child_by_field_name("name")
            .filter(|name| name_node_has_spelling(*name))
        else {
            self.add_local_gap(node, ResolutionGapKind::MalformedSyntax);
            self.discharge_pending_runtime_values(node, None);
            return;
        };
        let owner = self.lower_declared_type_identity(name);
        if self.pending_runtime_values.contains_key(&node.id()) {
            let produced = owner.map(|owner| {
                let site = self.add_site(node, ResolutionSiteKind::Literal, self.current_scope());
                let output = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
                    .expect("Rust resolution type-slot count exceeds u32");
                self.facts.type_slots.push(ResolutionTypeSlotFact {
                    id: output,
                    site,
                    role: ResolutionTypeSlotRole::ExpressionValue,
                });
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input: owner.identity,
                    output,
                    kind: ResolutionTypeTransferKind::Construction,
                    indirection_delta: owner.indirection,
                    reference_indirection_delta: owner.reference_indirection,
                    value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                        addressable: false,
                    },
                });
                output
            });
            self.discharge_pending_runtime_values(node, produced);
        }
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
        if !name_node_has_spelling(field) {
            self.add_local_gap(field, ResolutionGapKind::MalformedSyntax);
            return;
        }
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
        self.facts
            .binding_projections
            .push(BindingProjectionFact::target_declared_value_type(
                reference, output,
            ));
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
            if !name_node_has_spelling(field) {
                self.add_local_gap(current, ResolutionGapKind::MalformedSyntax);
                return None;
            }
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
            let site_kind = if field.kind() == "integer_literal"
                && self
                    .macro_input_token_spans
                    .as_ref()
                    .is_some_and(|tokens| !tokens.contains(&(field.start_byte(), field.end_byte())))
            {
                // A macro token tree can retain `0.0` as one canonical token,
                // while an `$expr` fragment parses it as two tuple selectors.
                // Keep each positional lookup for type flow, but do not publish
                // a reference to a selector with no exact host token.
                ResolutionSiteKind::SyntheticReference
            } else {
                ResolutionSiteKind::MemberReference
            };
            let reference = self.add_qualified_identifier(
                field,
                site_kind,
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
                .filter(|name| name_node_has_spelling(*name))
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
            // The receiver token is inventoried, but this path has no modeled
            // receiver owner. Keep that uncertainty on the member rather than
            // implying that a lexical binder or reference may be missing.
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
        self.facts
            .binding_projections
            .push(BindingProjectionFact::target_declared_value_type(
                reference, output,
            ));
        self.discharge_pending_runtime_values(value, Some(output));
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
                    | "await_expression"
                    | "base_field_initializer"
                    | "binary_expression"
                    | "block"
                    | "break_expression"
                    | "compound_assignment_expr"
                    | "else_clause"
                    | "expression_statement"
                    | "index_expression"
                    | "let_chain"
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

    fn add_local_binder_route_gap(
        &mut self,
        node: Node<'_>,
        scope: ResolutionScopeId,
        projected_imports: &[RustProjectedImport],
    ) {
        let site = self.add_site(
            node,
            ResolutionSiteKind::UnsupportedExpression,
            self.current_scope(),
        );
        let bindings = if projected_imports.is_empty() {
            // Unprojectable syntax supplies no publishing binder evidence.
            vec![(None, false)]
        } else {
            projected_imports
                .iter()
                .map(|projected| {
                    let name = projected
                        .import
                        .binding_name()
                        .named()
                        .map(|name| self.intern_spelling(name));
                    (name, projected.import.visibility != RustVisibility::Private)
                })
                .collect()
        };
        for (name, may_publish) in bindings {
            self.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownBinder {
                    scope,
                    name,
                    namespace: None,
                    may_publish,
                },
            );
        }
        self.facts
            .add_reference_enumeration_gap(site, ResolutionGapKind::UnsupportedRoute);
    }

    fn add_local_route_gap(&mut self, node: Node<'_>, route: ResolutionRouteGap) {
        let site = self.add_site(
            node,
            ResolutionSiteKind::UnsupportedExpression,
            self.current_scope(),
        );
        self.facts.add_route_gap(site, route);
        self.facts
            .add_reference_enumeration_gap(site, ResolutionGapKind::UnsupportedRoute);
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
        self.facts.gaps.push(ResolutionGapFact::new(site, kind));
    }

    fn add_local_gap_at_site(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        self.add_semantic_gap_at_site(site, kind);
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

/// Returns a node's name field only when it has an identifier spelling.
///
/// A recovered name can be a zero-width missing node; it has no spelling.
/// Returning None lets the walk record the MalformedSyntax gap.
fn spelled_name<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    node.child_by_field_name("name")
        .filter(|name| name_node_has_spelling(*name))
}

fn name_node_has_spelling(node: Node<'_>) -> bool {
    !node.is_missing() && !node.is_error()
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
                .filter(|name| name_node_has_spelling(*name))
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
        ) && let Some(parameters) = item.child_by_field_name("type_parameters")
        {
            let mut cursor = parameters.walk();
            if let Some(namespace) = parameters
                .named_children(&mut cursor)
                .find_map(|parameter| {
                    let namespace = match (node.kind(), parameter.kind()) {
                        ("type_identifier", "type_parameter") => ResolutionNamespace::Type,
                        ("identifier" | "type_identifier", "const_parameter") => {
                            ResolutionNamespace::Value
                        }
                        _ => return None,
                    };
                    parameter
                        .child_by_field_name("name")
                        .filter(|name| name_node_has_spelling(*name))
                        .filter(|name| {
                            strip_raw_identifier_prefix(rust_node_text(*name, source).trim())
                                == spelling
                        })
                        .map(|_| namespace)
                })
            {
                return Some(namespace);
            }
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
                    && spelled_name(parameter).is_some_and(|name| {
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

/// The operand of one borrow, shared by argument and local-value lowering.
/// Missing operands belong to parser recovery, never to pending value work.
fn rust_borrow_operand(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "reference_expression" || node.is_missing() || node.is_error() {
        return None;
    }
    node.child_by_field_name("value")
        .filter(|operand| !operand.is_missing() && !operand.is_error())
}

/// The runtime producer beneath a local initializer or assignment RHS, with
/// borrow and unwrap adjustments in outside-in syntax order. Calls, runtime
/// identifiers and struct constructions publish runtime slots. Parentheses
/// are transparent at every wrapper; unsupported leaves retain their gap.
fn rust_runtime_value_producer<'tree>(
    initializer: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Vec<(Node<'tree>, RuntimeValueAdjustmentKind)>)> {
    let mut node = rust_receiver_operand(initializer);
    let mut adjustments = Vec::new();
    loop {
        // Recovery can leave a missing identifier under wrappers (`???` is
        // nested try_expressions). The walk skips missing/error nodes, so no
        // pending value may be keyed on one.
        if node.is_missing() || node.is_error() {
            return None;
        }
        let (operand, kind) = if node.kind() == "reference_expression" {
            (
                rust_borrow_operand(node)?,
                RuntimeValueAdjustmentKind::Borrow,
            )
        } else if let Some(operand) = rust_unwrap_operand(node, source) {
            (operand, RuntimeValueAdjustmentKind::Unwrap)
        } else {
            break;
        };
        adjustments.push((node, kind));
        node = rust_receiver_operand(operand);
    }
    match node.kind() {
        // A bare identifier initializer (`let inner = outer;`) takes the
        // referenced binding's declared value type, which the runtime value
        // reference already publishes as `TargetDeclaredValueType`. Without it
        // the new binding has no declared value at all, so every later
        // `inner.member()` reports an unsupported semantic even where the
        // outer binding's type is known.
        "call_expression" | "identifier" | "struct_expression" => Some((node, adjustments)),
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

fn rust_reference_impl_member_owner(mut node: Node<'_>) -> Option<Node<'_>> {
    let mut saw_reference = false;
    loop {
        if let Some(inner) = crate::type_syntax::rust_parenthesized_type_inner(node) {
            node = inner;
            continue;
        }
        if node.kind() != "reference_type" {
            break;
        }
        saw_reference = true;
        node = node
            .child_by_field_name("type")
            .expect("Rust reference_type has a type field");
    }
    saw_reference.then_some(node)
}

// Grammar eligibility only; selected resolution establishes the head's identity.
fn rust_has_nominal_type_head(mut node: Node<'_>, source: &str) -> bool {
    while node.kind() == "generic_type" {
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
    if node.kind() != "primitive_type" {
        return None;
    }
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

fn rust_is_type_argument_syntax(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "abstract_type"
            | "array_type"
            | "bounded_type"
            | "dynamic_type"
            | "function_type"
            | "generic_type"
            | "generic_type_with_turbofish"
            | "identifier"
            | "macro_invocation"
            | "never_type"
            | "pointer_type"
            | "primitive_type"
            | "qualified_type"
            | "reference_type"
            | "scoped_identifier"
            | "scoped_type_identifier"
            | "tuple_type"
            | "type_identifier"
            | "unit_type"
    )
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

/// Whether a path segment is one of Rust's module anchors.
///
/// The grammar gives head anchors their own node kinds, and a repeated
/// `super` keeps that kind. It reports a later `self` in a scoped identifier's
/// `name` field as an `identifier`, so classify that selected token by its
/// spelling as well.
fn rust_path_anchor_keyword(node: Node<'_>, source: &str) -> bool {
    matches!(node.kind(), "crate" | "self" | "super")
        || (node.kind() == "identifier"
            && source
                .get(node.byte_range())
                .is_some_and(|spelling| matches!(spelling, "crate" | "self" | "super")))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RustPathAnchorKind {
    Crate,
    SelfValue,
    Super,
    SelfType,
}

/// Whether a structured path puts an anchor after an ordinary segment.
///
/// Only `super` may follow a leading anchor, and only while every earlier
/// segment is `self` or `super` (`super::super::x`, `self::super::x`), which
/// is rustc's rule. A grouped `use` may also end its route at the special
/// `self` leaf.
fn rust_path_has_misplaced_anchor(
    anchors: impl Iterator<Item = Option<RustPathAnchorKind>>,
    allow_terminal_self_import: bool,
) -> bool {
    let (segment_count, upper_bound) = anchors.size_hint();
    assert_eq!(
        Some(segment_count),
        upper_bound,
        "Rust path segment iterator has an exact size"
    );
    let mut leading_super_prefix = true;
    for (position, anchor) in anchors.enumerate() {
        let Some(anchor) = anchor else {
            leading_super_prefix = false;
            continue;
        };
        if allow_terminal_self_import
            && position + 1 == segment_count
            && anchor == RustPathAnchorKind::SelfValue
        {
            continue;
        }
        if position == 0 {
            leading_super_prefix = matches!(
                anchor,
                RustPathAnchorKind::Super | RustPathAnchorKind::SelfValue
            );
        } else if anchor != RustPathAnchorKind::Super || !leading_super_prefix {
            return true;
        }
    }
    false
}

fn rust_path_segments_have_misplaced_anchor<'tree>(
    segments: impl Iterator<Item = Node<'tree>>,
    source: &str,
    allow_terminal_self_import: bool,
) -> bool {
    rust_path_has_misplaced_anchor(
        segments.map(|segment| rust_path_anchor_kind(segment, source)),
        allow_terminal_self_import,
    )
}

fn rust_import_path_has_misplaced_anchor(
    segments: &[String],
    allow_terminal_self_import: bool,
) -> bool {
    rust_path_has_misplaced_anchor(
        segments
            .iter()
            .map(|segment| rust_path_anchor_kind_from_spelling(segment)),
        allow_terminal_self_import,
    )
}

fn rust_path_anchor_kind(node: Node<'_>, source: &str) -> Option<RustPathAnchorKind> {
    match node.kind() {
        "crate" => Some(RustPathAnchorKind::Crate),
        "self" => Some(RustPathAnchorKind::SelfValue),
        "super" => Some(RustPathAnchorKind::Super),
        "identifier" | "type_identifier" => {
            // Tree-sitter can expose an interior contextual keyword as the
            // `name` field's ordinary identifier kind while recovering an
            // invalid path. The syntax tree selected this segment; inspect
            // only that token's value to classify it.
            rust_path_anchor_kind_from_spelling(rust_node_text(node, source).trim())
        }
        _ => None,
    }
}

fn rust_path_anchor_kind_from_spelling(spelling: &str) -> Option<RustPathAnchorKind> {
    match spelling {
        "crate" => Some(RustPathAnchorKind::Crate),
        "self" => Some(RustPathAnchorKind::SelfValue),
        "super" => Some(RustPathAnchorKind::Super),
        "Self" => Some(RustPathAnchorKind::SelfType),
        _ => None,
    }
}

fn rust_use_path_terminal_self(node: Node<'_>, source: &str) -> bool {
    let Some(segments) = rust_path_segments(node) else {
        return false;
    };
    if !segments.last().is_some_and(|segment| {
        rust_path_anchor_kind(*segment, source) == Some(RustPathAnchorKind::SelfValue)
    }) {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "use_list" => true,
        "use_declaration" => parent.child_by_field_name("argument") == Some(node),
        "use_wildcard" => parent.named_child(0) == Some(node),
        "scoped_use_list" => parent
            .child_by_field_name("list")
            .is_some_and(|list| list.id() == node.id()),
        "use_as_clause" => {
            parent.child_by_field_name("path") == Some(node)
                && parent.parent().is_some_and(|grandparent| {
                    matches!(grandparent.kind(), "use_list" | "scoped_use_list")
                        || (grandparent.kind() == "use_declaration"
                            && grandparent.child_by_field_name("argument") == Some(parent))
                })
        }
        _ => false,
    }
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

/// One effective outer attribute on a Rust item.
///
/// `path` contains the structured identifier nodes in source order. Attributes
/// introduced by `cfg_attr` retain that fact so callers that need unconditional
/// evidence can distinguish them from ordinary outer attributes.
pub(crate) struct RustEffectiveItemAttribute<'tree> {
    pub(crate) path: Vec<Node<'tree>>,
    pub(crate) arguments: Option<Node<'tree>>,
    pub(crate) from_cfg_attr: bool,
}

/// Return an item's effective outer attributes, recursively expanding each
/// `cfg_attr` payload with an explicit worklist. A malformed attribute shape
/// returns `None`; callers that classify transformation boundaries must keep
/// treating that item as transforming.
pub(crate) fn rust_item_effective_attributes<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Vec<RustEffectiveItemAttribute<'tree>>> {
    rust_effective_attributes(crate::syntax::outer_attributes(node), source)
}

/// Return the effective attributes authored by `attribute_items`, recursively
/// expanding each `cfg_attr` payload with an explicit worklist. A malformed
/// attribute shape returns `None`.
fn rust_effective_attributes<'tree>(
    attribute_items: impl IntoIterator<Item = Node<'tree>>,
    source: &str,
) -> Option<Vec<RustEffectiveItemAttribute<'tree>>> {
    let mut pending = attribute_items
        .into_iter()
        .map(|attribute_item| {
            let attribute = attribute_item.named_child(0)?;
            let path = attribute.named_child(0)?;
            let path = rust_path_segments(path)?;
            (!path.is_empty()).then_some(RustEffectiveItemAttribute {
                path,
                arguments: attribute.child_by_field_name("arguments"),
                from_cfg_attr: false,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    pending.reverse();

    let mut effective = Vec::new();
    while let Some(attribute) = pending.pop() {
        if attribute.path.len() == 1
            && attribute.path[0].kind() == "identifier"
            && rust_node_text(attribute.path[0], source).trim() == "cfg_attr"
        {
            let arguments = attribute.arguments?;
            let mut inner = rust_cfg_attr_inner_attributes(arguments, source)?;
            pending.extend(inner.drain(..).rev());
        } else {
            effective.push(attribute);
        }
    }
    Some(effective)
}

/// Built-in attributes rustc resolves before path-based scope lookup.
///
/// A same-named import is an ambiguity error rather than a shadowing macro, and
/// none of these attributes expands to code. `test`, `global_allocator` and
/// `alloc_error_handler` are absent because they are prelude attribute macros
/// that an import can shadow.
const RUST_INERT_BUILTIN_ATTRIBUTES: &[&str] = &[
    "allow",
    "warn",
    "deny",
    "forbid",
    "expect",
    "doc",
    "repr",
    "deprecated",
    "must_use",
    "inline",
    "cold",
    "track_caller",
    "target_feature",
    "no_mangle",
    "export_name",
    "link_name",
    "link",
    "link_section",
    "used",
    "non_exhaustive",
    "path",
    "macro_export",
    "automatically_derived",
    "panic_handler",
    "proc_macro",
    "proc_macro_attribute",
    "proc_macro_derive",
    "ignore",
    "should_panic",
];

/// Whether an `unsafe(...)` attribute wrapper contains a built-in codegen
/// attribute rather than a procedural macro that can replace the item.
fn rust_unsafe_attribute_is_inert(arguments: Option<Node<'_>>, source: &str) -> bool {
    arguments
        .and_then(|arguments| arguments.named_child(0))
        .is_some_and(|inner| {
            inner.kind() == "identifier"
                && matches!(
                    rust_node_text(inner, source),
                    "no_mangle" | "export_name" | "link_section" | "naked"
                )
        })
}

/// Parse a `cfg_attr` token tree's comma-separated inner attribute groups.
/// The predicate is structurally checked but left unevaluated; expansion is
/// modeled conservatively for every possible configuration.
fn rust_cfg_attr_inner_attributes<'tree>(
    arguments: Node<'tree>,
    source: &str,
) -> Option<Vec<RustEffectiveItemAttribute<'tree>>> {
    if arguments.kind() != "token_tree" {
        return None;
    }
    let mut cursor = arguments.walk();
    let children = arguments
        .children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect::<Vec<_>>();
    let [open, inner @ .., close] = children.as_slice() else {
        return None;
    };
    if open.kind() != "(" || close.kind() != ")" {
        return None;
    }

    let mut groups = inner.split(|child| child.kind() == ",").collect::<Vec<_>>();
    if groups.last().is_some_and(|group| group.is_empty()) {
        groups.pop();
    }
    if groups.len() < 2 || groups.iter().any(|group| group.is_empty()) {
        return None;
    }

    crate::lexical_scope::rust_cfg_predicate_condition(groups[0], source)?;

    groups
        .into_iter()
        .skip(1)
        .map(|group| {
            let first = group.first()?;
            if first.kind() != "identifier" {
                return None;
            }
            let mut path = vec![*first];
            let mut index = 1;
            while group.get(index).is_some_and(|child| child.kind() == "::") {
                let segment = group.get(index + 1)?;
                if segment.kind() != "identifier" {
                    return None;
                }
                path.push(*segment);
                index += 2;
            }

            let remaining = &group[index..];
            let arguments = match remaining {
                [] => None,
                [arguments] if arguments.kind() == "token_tree" => Some(*arguments),
                [equals, value @ ..] if equals.kind() == "=" && !value.is_empty() => None,
                _ => return None,
            };
            Some(RustEffectiveItemAttribute {
                path,
                arguments,
                from_cfg_attr: true,
            })
        })
        .collect()
}

/// Classify built-in attributes and registered derive helper attributes.
///
/// A scoped or otherwise unknown attribute may be a procedural macro. Assume
/// attributes and derives preserve authored bindings, generics and fields;
/// their unexpanded output leaves added names, members and impls unknown.
fn rust_item_attribute_boundary(node: Node<'_>, source: &str) -> RustItemAttributeBoundary {
    let mut boundary = RustItemAttributeBoundary::SourcePreserving;
    let mut conditional_helpers = Vec::new();
    let Some(attributes) = rust_item_effective_attributes(node, source) else {
        return RustItemAttributeBoundary::Transforming;
    };
    let has_nonempty_derive = matches!(node.kind(), "struct_item" | "enum_item" | "union_item")
        && rust_item_derive_facts(node, source)
            .paths
            .iter()
            .any(|path| !path.is_empty());
    for attribute in attributes {
        let path = &attribute.path;
        if rust_tool_attribute_path(path, source) {
            // `#[rustfmt::skip]`, `#[clippy::..]`, `#[diagnostic::..]` name a
            // tool rustc registers; tool attributes are inert and never
            // replace the item.
            continue;
        }
        if rust_ctor_dtor_attribute_path(path, source) {
            // The ctor/dtor crates arrange startup and shutdown calls around
            // the attributed function. When their expansion is unavailable,
            // the authored function remains the source callable for
            // reachability queries; the decorator fact supplies the startup
            // edge. Do not turn this known source-preserving contract into an
            // unknown attribute-macro boundary.
            continue;
        }
        if path.len() != 1 || path[0].kind() != "identifier" {
            return RustItemAttributeBoundary::Transforming;
        }
        let name = strip_raw_identifier_prefix(rust_node_text(path[0], source).trim());
        match name {
            // Module macro visibility is already retained by Cargo route
            // facts. The built-in attribute does not replace the source body.
            "macro_use" if node.kind() == "mod_item" => {}
            // Rust's unsafe attribute wrapper contains a built-in codegen
            // attribute, not a procedural macro that can replace this item.
            "unsafe" if rust_unsafe_attribute_is_inert(attribute.arguments, source) => {}
            "derive" => boundary = RustItemAttributeBoundary::GeneratedSurface,
            "serde" => {
                if rust_item_has_serde_derive(node, source) {
                    boundary = RustItemAttributeBoundary::GeneratedSurface;
                } else if has_nonempty_derive && !rust_item_scope_binds(node, source, name) {
                    conditional_helpers.push(name.to_owned());
                    boundary = RustItemAttributeBoundary::GeneratedSurface;
                } else {
                    return RustItemAttributeBoundary::Transforming;
                }
            }
            "cfg" => {
                if attribute.from_cfg_attr {
                    return RustItemAttributeBoundary::Transforming;
                }
                debug_assert_ne!(
                    rust_cfg_condition(node, source),
                    RustCfgCondition::Always,
                    "a cfg-owned Rust item is handled before attribute boundaries"
                );
            }
            // These three are prelude attribute macros that an import can
            // shadow, so they remain hazards for the expansion proof, but the
            // boundary still accepts them as inert: they do not replace the
            // authored declaration.
            "global_allocator" | "alloc_error_handler" | "test" => {}
            // Everything else in the built-in list is inert, including the
            // three procedural-macro entry-point attributes (`proc_macro`,
            // `proc_macro_attribute`, `proc_macro_derive`). They mark the
            // function as a macro the crate publishes; they do not replace it,
            // and the body below them is the body rustc compiles. Treating them
            // as unknown skipped the declaration, so a proc-macro crate
            // exported nothing at all and `rocket_codegen::routes` was a name
            // no crate row carried. Test-harness controls (`ignore`,
            // `should_panic`) are inert too: they do not replace the body.
            name if RUST_INERT_BUILTIN_ATTRIBUTES.contains(&name) => {}
            _ => {
                if has_nonempty_derive && !rust_item_scope_binds(node, source, name) {
                    conditional_helpers.push(name.to_owned());
                    boundary = RustItemAttributeBoundary::GeneratedSurface;
                } else {
                    return RustItemAttributeBoundary::Transforming;
                }
            }
        }
    }
    if !conditional_helpers.is_empty() {
        conditional_helpers.sort_unstable();
        conditional_helpers.dedup();
        RustItemAttributeBoundary::ConditionalDeriveHelpers(conditional_helpers)
    } else {
        boundary
    }
}

/// Whether one source `attribute_item` or `inner_attribute_item` may expand to
/// code.
///
/// The published start bytes feed a textual macro-scope closure proof: a
/// reverse-inventory resolver needs to know that no earlier attribute in a
/// lexical scope prefix can generate a `macro_rules!`. An attribute shape this
/// function cannot classify is therefore a hazard, not inert. Malformed
/// attributes are hazards too.
pub(crate) fn rust_attribute_item_can_expand(attribute_item: Node<'_>, source: &str) -> bool {
    let Some(attributes) = rust_effective_attributes(std::iter::once(attribute_item), source)
    else {
        return true;
    };
    attributes
        .iter()
        .any(|attribute| !rust_effective_attribute_is_inert(attribute, source))
}

/// Whether one effective attribute provably expands to no code.
///
/// Tool attributes, `cfg` (which only removes code), the inert built-ins, and
/// the inert `unsafe(...)` codegen wrapper are safe. Everything else,
/// including `derive`, `macro_use`, the prelude attribute macros, scoped paths
/// and unknown names, may expand to code.
fn rust_effective_attribute_is_inert(
    attribute: &RustEffectiveItemAttribute<'_>,
    source: &str,
) -> bool {
    let path = &attribute.path;
    if rust_tool_attribute_path(path, source) {
        return true;
    }
    if path.len() != 1 || path[0].kind() != "identifier" {
        return false;
    }
    let name = strip_raw_identifier_prefix(rust_node_text(path[0], source).trim());
    match name {
        "cfg" => true,
        "unsafe" => rust_unsafe_attribute_is_inert(attribute.arguments, source),
        name if RUST_INERT_BUILTIN_ATTRIBUTES.contains(&name) => true,
        _ => false,
    }
}

/// The bare item attributes which need a crate-level absence proof before
/// they can be treated as inert derive helpers. `None` means the item either
/// has no conditional helper or has another transforming attribute.
pub(crate) fn rust_item_conditional_derive_helper_attributes(
    node: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    match rust_item_attribute_boundary(node, source) {
        RustItemAttributeBoundary::ConditionalDeriveHelpers(attributes) => Some(attributes),
        _ => None,
    }
}

/// Whether this source declaration has an attribute or derive surface that
/// the producer leaves open. Source facts persist this per declaration so
/// Cargo route inventory can report the same structured boundary after the
/// unsupported AST site itself has been discarded.
pub(crate) fn rust_item_has_generated_surface_boundary(node: Node<'_>, source: &str) -> bool {
    !matches!(
        rust_item_attribute_boundary(node, source),
        RustItemAttributeBoundary::SourcePreserving
    )
}

/// Whether an attribute path is scoped under one of the tools rustc
/// registers (`rustfmt`, `clippy`, `diagnostic`), read from the path's
/// root segment.
fn rust_tool_attribute_path(path: &[Node<'_>], source: &str) -> bool {
    path.len() > 1
        && path[0].kind() == "identifier"
        && matches!(
            rust_node_text(path[0], source),
            "rustfmt" | "clippy" | "diagnostic"
        )
}

/// Whether an outer attribute is one of the ctor/dtor startup markers.
///
/// The path is read from tree-sitter's structured path fields. Both the
/// package spelling (`#[ctor::ctor]`, `#[dtor::dtor]`) and the short spelling
/// (`#[ctor]`, `#[dtor]`) identify the same source-preserving callable
/// fallback when the proc-macro expansion is unavailable.
fn rust_ctor_dtor_attribute_path(segments: &[Node<'_>], source: &str) -> bool {
    let text = |segment: Node<'_>| rust_node_text(segment, source).trim();
    match segments {
        [name] => matches!(text(*name), "ctor" | "dtor"),
        [namespace, name] => {
            text(*namespace) == text(*name) && matches!(text(*name), "ctor" | "dtor")
        }
        _ => false,
    }
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
            .filter(|declared| name_node_has_spelling(*declared))
            .is_some_and(|declared| {
                strip_raw_identifier_prefix(rust_node_text(declared, source).trim()) == name
            })
            || sibling
                .child_by_field_name("alias")
                .filter(|alias| name_node_has_spelling(*alias))
                .is_some_and(|alias| {
                    strip_raw_identifier_prefix(rust_node_text(alias, source).trim()) == name
                })
            || (sibling.kind() == "use_declaration"
                && crate::imports::rust_imports_from_use_declaration(sibling, source)
                    .iter()
                    .any(|import| {
                        import
                            .local_name()
                            .is_some_and(|bound| strip_raw_identifier_prefix(bound) == name)
                    }))
    })
}

/// The syntactic paths listed in this item's effective `derive(..)` attributes,
/// including attributes expanded from `cfg_attr`.
#[derive(Default)]
struct RustItemDeriveFacts<'tree> {
    paths: Vec<Vec<Node<'tree>>>,
}

fn rust_item_derive_facts<'tree>(node: Node<'tree>, source: &str) -> RustItemDeriveFacts<'tree> {
    let mut facts = RustItemDeriveFacts::default();
    let Some(attributes) = rust_item_effective_attributes(node, source) else {
        return facts;
    };
    for attribute in attributes {
        let Some(name) = attribute.path.first().copied() else {
            continue;
        };
        if attribute.path.len() != 1 || name.kind() != "identifier" {
            continue;
        }
        if rust_node_text(name, source) == "derive" {
            let Some(arguments) = attribute.arguments else {
                continue;
            };
            let mut cursor = arguments.walk();
            let tokens = arguments
                .children(&mut cursor)
                .filter(|token| {
                    !matches!(token.kind(), "(" | ")" | "line_comment" | "block_comment")
                })
                .collect::<Vec<_>>();
            facts.paths.extend(
                tokens
                    .split(|token| token.kind() == ",")
                    .map(|path| path.to_vec()),
            );
        }
    }
    facts
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
    for path in rust_item_derive_facts(node, source).paths {
        match path.as_slice() {
            [namespace, separator, derive]
                if namespace.kind() == "identifier"
                    && rust_node_text(*namespace, source) == "serde"
                    && separator.kind() == "::"
                    && derive.kind() == "identifier"
                    && matches!(rust_node_text(*derive, source), "Serialize" | "Deserialize") =>
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

/// The transfer kind for a written type whose nominal head gains reference
/// or pointer layers. A type identity carries no layers, so any layer makes
/// the transfer an alias that retains the head's type object.
fn written_type_transfer_kind(
    indirection: i8,
    reference_indirection: i8,
) -> ResolutionTypeTransferKind {
    if indirection == 0 && reference_indirection == 0 {
        ResolutionTypeTransferKind::TypeIdentity
    } else {
        ResolutionTypeTransferKind::TypeAlias
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionDeclaredTypeRelationKind;
    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionKind, DeclarationTypeRole, FileResolutionFacts, IntrinsicTypeKind,
        ResolutionBinderKind, ResolutionCallableReceiverForm, ResolutionGapKind,
        ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
        ResolutionMemberQualifierCompatibility, ResolutionNamespace, ResolutionRootImportAnchor,
        ResolutionRootImportDemandTarget, ResolutionRootImportKind, ResolutionScopeId,
        ResolutionScopeKind, ResolutionSiteId, ResolutionSiteKind, ResolutionTypeSlotRole,
        ResolutionTypeTransferKind,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;
    use tree_sitter::{Node, Parser};

    use super::extract_rust_resolution_facts;

    #[test]
    fn grammar_attribute_expansion_boundaries() {
        // cfg_attr is configuration dependent: every possible effective
        // attribute must be inert to prove that it cannot generate code.
        for (attribute, can_expand) in [
            ("#[unsafe(no_mangle)]", false),
            ("#[unsafe(unknown)]", true),
            ("#[cfg_attr(flag, inline, unknown_attr)]", true),
            ("#[cfg_attr(flag, unknown_attr, inline)]", true),
            ("#[cfg_attr(flag, allow::inject)]", true),
            ("#[cfg_attr(, inline)]", true),
            ("#[cfg_attr(flag, inline,)]", false),
            ("#[cfg_attr(flag, inline, cold)]", false),
        ] {
            let source = format!("{attribute} fn f() {{}}");
            let tree = crate::lexical_scope::parse_rust_tree(&source).unwrap();
            assert!(!tree.root_node().has_error());
            let mut pending = vec![tree.root_node()];
            let node = loop {
                let node = pending.pop().expect("attribute in fixture");
                if node.kind() == "attribute_item" {
                    break node;
                }
                pending.extend(node.named_children(&mut node.walk()));
            };
            assert_eq!(
                super::rust_attribute_item_can_expand(node, &source),
                can_expand,
                "{attribute}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5015: writes hid unknown incoming values of initialized and implicit Rust pattern binders"
    )]
    fn pattern_initializers_keep_unknown_inputs_separate_from_static_types() {
        let source = r#"
struct Item;
struct Pair { field: Item }
fn run(input: (Item, Item), optional: Option<Item>, pairs: Vec<(Item, Item)>, named: Pair) {
    let (mut tuple, mut sibling) = input;
    tuple = Item {};
    sibling = Item {};
    tuple.summary();
    let (mut annotated): Item = Item {};
    annotated = Item {};
    annotated.summary();
    let Pair { field: mut field } = named;
    field = Item {};
    field.summary();
    let mut plain;
    plain = Item {};
    let (mut absent, _);
    absent = Item {};
    for (mut looped, _) in pairs {
        looped = Item {};
        looped.summary();
    }
    match optional {
        Some(mut arm) => { arm = Item {}; arm.summary(); }
        None => {}
    }
    if let Some(mut conditional) = optional {
        conditional = Item {};
        conditional.summary();
    }
    while let Some(mut repeated) = optional {
        repeated = Item {};
        repeated.summary();
        break;
    }
    if let Some(mut chained) = optional && let Some(mut chained_second) = optional {
        chained = Item {};
        chained_second = Item {};
    }
    let closure = |parameter: Item| parameter;
}
"#;
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        for name in [
            "tuple",
            "sibling",
            "annotated",
            "field",
            "looped",
            "arm",
            "conditional",
            "repeated",
            "chained",
            "chained_second",
            "plain",
            "absent",
            "input",
            "parameter",
        ] {
            let declaration = facts
                .binders
                .iter()
                .find(|binder| {
                    source_text(&facts, source, binder.declaration) == name
                        && matches!(
                            binder.kind,
                            ResolutionBinderKind::Pattern | ResolutionBinderKind::Parameter
                        )
                })
                .expect("lexical binder")
                .declaration;
            let assignments = facts
                .type_slots
                .iter()
                .filter(|slot| {
                    slot.site == declaration && slot.role == ResolutionTypeSlotRole::AssignmentValue
                })
                .collect::<Vec<_>>();
            if matches!(name, "plain" | "absent" | "input" | "parameter") {
                assert!(assignments.is_empty(), "no implicit input for {name}");
                continue;
            }
            assert_eq!(assignments.len(), 1, "one initializer for {name}");
            let producers = facts
                .type_transfers
                .iter()
                .filter(|transfer| transfer.output == assignments[0].id)
                .collect::<Vec<_>>();
            assert_eq!(producers.len(), 1, "one assignment producer for {name}");
            assert_eq!(producers[0].kind, ResolutionTypeTransferKind::Assignment);
            let unknown = facts.type_slots[producers[0].input.index()];
            assert_eq!(unknown.role, ResolutionTypeSlotRole::ExpressionValue);
            assert_ne!(unknown.site, declaration);
            assert_eq!(
                facts.sites[unknown.site.index()].kind,
                ResolutionSiteKind::UnsupportedExpression
            );
            assert!(facts.gaps.iter().any(|gap| {
                gap.site == unknown.site && gap.kind == ResolutionGapKind::UnsupportedExpression
            }));
            assert!(facts.gaps.iter().all(|gap| gap.site != declaration));
            assert!(
                facts
                    .reference_enumeration_gaps
                    .iter()
                    .all(|gap| gap.site != unknown.site)
            );
            assert!(facts.type_transfers.iter().all(|transfer| {
                transfer.output != unknown.id
                    && (transfer.input != unknown.id
                        || transfer.kind == ResolutionTypeTransferKind::Assignment)
            }));
            assert!(
                facts
                    .binding_projections
                    .iter()
                    .all(|projection| projection.output != unknown.id)
            );
            assert!(
                facts
                    .intrinsic_type_seeds
                    .iter()
                    .all(|seed| seed.output != unknown.id)
            );
            assert!(facts.type_slots.iter().all(|slot| {
                slot.role != ResolutionTypeSlotRole::Receiver || slot.site != unknown.site
            }));
            let properties = facts
                .declaration_type_slots
                .iter()
                .filter(|property| property.declaration == declaration)
                .collect::<Vec<_>>();
            if name == "annotated" {
                assert_eq!(properties.len(), 1);
                let declared = properties[0].slot;
                let producer = facts
                    .type_transfers
                    .iter()
                    .find(|transfer| transfer.output == declared)
                    .expect("annotation's static type producer");
                assert_eq!(producer.kind, ResolutionTypeTransferKind::DeclaredType);
                assert_ne!(producer.input, unknown.id);
                assert!(
                    facts
                        .gaps
                        .iter()
                        .all(|gap| gap.site != facts.type_slots[declared.index()].site)
                );
            } else {
                assert!(properties.is_empty(), "no invented static type for {name}");
            }
            assert_eq!(
                facts
                    .local_writes
                    .iter()
                    .filter(|write| { source_text(&facts, source, write.target) == name })
                    .count(),
                1,
                "one independent write for {name}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5015: mutable let patterns and assignment targets use positioned identifier fields"
    )]
    fn local_write_grammar_keeps_mutability_outside_the_binder() {
        let source = "fn run() { let mut value: Item = make(); value = Item {}; value += make(); }";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        assert!(!tree.root_node().has_error());
        let binding = find_first_node(tree.root_node(), "let_declaration").expect("let");
        let pattern = binding.child_by_field_name("pattern").expect("pattern");
        assert_eq!(pattern.kind(), "identifier");
        let mut cursor = binding.walk();
        assert!(
            binding
                .named_children(&mut cursor)
                .any(|child| child.kind() == "mutable_specifier")
        );
        assert_eq!(
            binding
                .child_by_field_name("type")
                .expect("annotation")
                .kind(),
            "type_identifier"
        );
        for kind in ["assignment_expression", "compound_assignment_expr"] {
            let assignment = find_first_node(tree.root_node(), kind).expect("assignment");
            assert_eq!(
                assignment
                    .child_by_field_name("left")
                    .expect("target")
                    .kind(),
                "identifier"
            );
            let right = assignment.child_by_field_name("right").expect("value");
            assert!(matches!(
                right.kind(),
                "struct_expression" | "call_expression"
            ));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5015: borrowed initializer and write values lost their runtime producers and wrapper order"
    )]
    fn borrowed_local_values_preserve_wrapper_order_and_recovery() {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferValueTransform;

        let source = concat!(
            "fn run(body: Body, other: Other) {\n",
            "    let mut value = (&(body));\n",
            "    value = (&mut (other));\n",
            "    let before = (&(make().unwrap()));\n",
            "    let after = ((&(make())).unwrap());\n",
            "    let tried = (&((make())?));\n",
            "}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        assert!(!tree.root_node().has_error());
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        for transfer in facts
            .type_transfers
            .iter()
            .filter(|transfer| transfer.kind == ResolutionTypeTransferKind::Initialization)
        {
            assert_eq!(
                (
                    transfer.indirection_delta,
                    transfer.reference_indirection_delta,
                    transfer.value_transform
                ),
                (0, 0, ResolutionTypeTransferValueTransform::Preserve)
            );
        }
        let chain = |mut value| {
            let mut wrappers = Vec::new();
            while let Some(transfer) = facts.type_transfers.iter().find(|transfer| {
                transfer.output == value
                    && matches!(
                        transfer.kind,
                        ResolutionTypeTransferKind::AddressOf | ResolutionTypeTransferKind::Unwrap
                    )
            }) {
                let output = facts.type_slots[value.index()];
                assert_eq!(
                    facts
                        .type_transfers
                        .iter()
                        .filter(|producer| producer.output == value)
                        .count(),
                    1,
                    "each wrapper has exactly one producer"
                );
                match transfer.kind {
                    ResolutionTypeTransferKind::AddressOf => {
                        assert_eq!(output.role, ResolutionTypeSlotRole::ExpressionValue);
                        assert_eq!(
                            (
                                transfer.indirection_delta,
                                transfer.reference_indirection_delta,
                                transfer.value_transform
                            ),
                            (
                                1,
                                1,
                                ResolutionTypeTransferValueTransform::ToRuntime {
                                    addressable: false
                                }
                            )
                        );
                    }
                    ResolutionTypeTransferKind::Unwrap => {
                        assert_eq!(output.role, ResolutionTypeSlotRole::CallResult);
                        assert_eq!(
                            (
                                transfer.indirection_delta,
                                transfer.reference_indirection_delta,
                                transfer.value_transform
                            ),
                            (-1, 0, ResolutionTypeTransferValueTransform::Preserve)
                        );
                    }
                    _ => unreachable!(),
                }
                assert!(facts.gaps.iter().all(|gap| gap.site != output.site));
                wrappers.push((transfer.kind, source_text(&facts, source, output.site)));
                value = transfer.input;
            }
            (
                wrappers,
                source_text(&facts, source, facts.type_slots[value.index()].site),
            )
        };
        let initializer = |name| {
            let assignment = facts
                .type_slots
                .iter()
                .find(|slot| {
                    slot.role == ResolutionTypeSlotRole::AssignmentValue
                        && source_text(&facts, source, slot.site) == name
                })
                .expect("observed initializer");
            let transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| transfer.output == assignment.id)
                .expect("initializer assignment producer");
            assert_eq!(transfer.kind, ResolutionTypeTransferKind::Assignment);
            assert_eq!(
                (
                    transfer.indirection_delta,
                    transfer.reference_indirection_delta,
                    transfer.value_transform
                ),
                (0, 0, ResolutionTypeTransferValueTransform::Preserve)
            );
            transfer.input
        };
        use ResolutionTypeTransferKind::{AddressOf, Unwrap};
        assert_eq!(
            chain(initializer("value")),
            (vec![(AddressOf, "&(body)")], "body")
        );
        assert_eq!(facts.local_writes.len(), 1);
        assert_eq!(
            chain(facts.local_writes[0].value),
            (vec![(AddressOf, "&mut (other)")], "other")
        );
        assert_eq!(
            chain(initializer("before")),
            (
                vec![
                    (AddressOf, "&(make().unwrap())"),
                    (Unwrap, "make().unwrap()")
                ],
                "make()"
            )
        );
        assert_eq!(
            chain(initializer("after")),
            (
                vec![(Unwrap, "(&(make())).unwrap()"), (AddressOf, "&(make())")],
                "make()"
            )
        );
        assert_eq!(
            chain(initializer("tried")),
            (
                vec![(AddressOf, "&((make())?)"), (Unwrap, "(make())?")],
                "make()"
            )
        );

        // Neither recovered missing operands nor unsupported leaves may leave
        // pending producer slots that the extraction walk can never discharge.
        for source in [
            "fn f() { let mut value = &&; value = &&; take(&&); }",
            "fn f() { let mut value = &([1u8]); value = &(opaque!()); }",
        ] {
            let facts = parse_and_extract(source);
            assert!(facts.gaps.iter().any(|gap| matches!(
                gap.kind,
                ResolutionGapKind::MalformedSyntax | ResolutionGapKind::UnsupportedExpression
            )));
            for transfer in facts
                .type_transfers
                .iter()
                .filter(|transfer| transfer.kind == ResolutionTypeTransferKind::Assignment)
            {
                let input = facts.type_slots[transfer.input.index()];
                assert!(facts.gaps.iter().any(|gap| gap.site == input.site));
            }
            for write in &facts.local_writes {
                let input = facts.type_slots[write.value.index()];
                assert!(facts.gaps.iter().any(|gap| gap.site == input.site));
            }
        }

        // Argument edges aggregate i8 depths; strings have an intrinsic
        // reference layer as well. Runtime borrows instead keep one edge per
        // wrapper, so they do not truncate at the argument representation cap.
        let source = format!(
            "fn f(body: Body) {{ let value = {}body; take({}\"text\"); take({}body); }}",
            "&".repeat(128),
            "&".repeat(127),
            "&".repeat(128)
        );
        let facts = parse_and_extract(&source);
        assert_eq!(
            facts
                .type_transfers
                .iter()
                .filter(|transfer| transfer.kind == AddressOf)
                .count(),
            128
        );
        assert_eq!(facts.call_arguments.len(), 2);
        for argument in &facts.call_arguments {
            let transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| transfer.output == argument.value)
                .expect("gap-fed argument");
            let input = facts.type_slots[transfer.input.index()];
            assert!(facts.gaps.iter().any(|gap| gap.site == input.site
                && gap.kind == ResolutionGapKind::UnsupportedExpression));
            assert!(
                facts
                    .intrinsic_type_seeds
                    .iter()
                    .all(|seed| seed.output != input.id)
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5015: local writes retain RHS values without treating macro named options as assignments"
    )]
    fn local_writes_preserve_initial_values_macro_isolation_and_unknown_inputs() {
        let source = r#"
struct Item { field: u32 }
fn run(other: u32) {
    let mut actual = Item { field: other };
    let mut annotated: Item = make();
    let uninitialized: Item;
    actual = make();
    annotated = make().unwrap();
    options!(actual = make());
    let _ = format!("{actual:?}", actual = make());
    actual += make();
    actual = { make() };
    actual.field = make();
    (actual, annotated) = (make(), make());
}
"#;
        let facts = parse_and_extract(source);
        let writes = facts
            .local_writes
            .iter()
            .map(|write| {
                let target = facts.sites[write.target.index()];
                (
                    &source[target.start_byte..target.end_byte],
                    target.start_byte,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            writes,
            [
                (
                    "actual",
                    source.find("actual = make();").expect("ordinary write")
                ),
                (
                    "annotated",
                    source
                        .find("annotated = make().unwrap();")
                        .expect("unwrapped write")
                ),
                (
                    "actual",
                    source.find("actual += make();").expect("compound write")
                ),
                (
                    "actual",
                    source
                        .find("actual = { make() };")
                        .expect("unsupported RHS")
                ),
                (
                    "actual",
                    source.find("(actual, annotated)").expect("tuple target") + 1
                ),
                (
                    "annotated",
                    source.find("(actual, annotated)").expect("tuple target") + 9
                ),
            ]
        );
        for write in &facts.local_writes[2..] {
            let site = facts.type_slots[write.value.index()].site;
            assert!(facts.gaps.iter().any(
                |gap| gap.site == site && gap.kind == ResolutionGapKind::UnsupportedExpression
            ));
            assert!(
                !facts
                    .type_transfers
                    .iter()
                    .any(|transfer| transfer.output == write.value)
            );
            assert!(
                !facts
                    .binding_projections
                    .iter()
                    .any(|projection| projection.output == write.value)
            );
        }
        let unwrapped = facts.local_writes[1].value;
        assert!(
            facts
                .type_transfers
                .iter()
                .any(|transfer| transfer.output == unwrapped
                    && transfer.kind == ResolutionTypeTransferKind::Unwrap)
        );
        for (name, expected_initializer) in [
            ("actual", true),
            ("annotated", true),
            ("uninitialized", false),
        ] {
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .expect("local declaration")
                .site;
            let assignments = facts
                .type_slots
                .iter()
                .filter(|slot| {
                    slot.site == declaration && slot.role == ResolutionTypeSlotRole::AssignmentValue
                })
                .collect::<Vec<_>>();
            assert_eq!(
                assignments.len(),
                usize::from(expected_initializer),
                "{name}"
            );
            if let Some(assignment) = assignments.first() {
                let observed = facts
                    .type_transfers
                    .iter()
                    .find(|transfer| transfer.output == assignment.id)
                    .expect("observed initializer");
                assert_eq!(observed.kind, ResolutionTypeTransferKind::Assignment);
                let declared = facts
                    .declaration_type_slots
                    .iter()
                    .find(|slot| slot.declaration == declaration)
                    .expect("declared value")
                    .slot;
                let inferred = facts
                    .type_transfers
                    .iter()
                    .find(|transfer| transfer.output == declared)
                    .expect("declared producer");
                if name == "actual" {
                    assert_eq!(inferred.kind, ResolutionTypeTransferKind::Initialization);
                    assert_eq!(inferred.input, observed.input);
                    assert!(
                        facts
                            .type_transfers
                            .iter()
                            .any(|transfer| transfer.output == observed.input
                                && transfer.kind == ResolutionTypeTransferKind::Construction)
                    );
                } else {
                    assert_eq!(inferred.kind, ResolutionTypeTransferKind::DeclaredType);
                    assert_ne!(inferred.input, observed.input);
                    assert!(
                        facts
                            .call_expected_results
                            .iter()
                            .any(|expected| expected.call
                                == facts.type_slots[observed.input.index()].site)
                    );
                }
            }
        }
        for target in ["actual.field", "(actual, annotated)"] {
            assert!(
                facts.gaps.iter().any(|gap| {
                    let site = facts.sites[gap.site.index()];
                    gap.kind == ResolutionGapKind::UnsupportedExpression
                        && &source[site.start_byte..site.end_byte] == target
                }),
                "complex target {target} remains explicit"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5015: an inferred uninitialized let lacked a declaration value property for later writes"
    )]
    fn inferred_uninitialized_let_owns_an_empty_declaration_value_property() {
        let source = "fn run() { let mut value; value = Item {}; value.summary(); }";
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        assert!(!tree.root_node().has_error());
        let binding = find_first_node(tree.root_node(), "let_declaration").expect("let");
        let pattern = binding.child_by_field_name("pattern").expect("pattern");
        assert_eq!(pattern.kind(), "identifier");
        assert!(binding.child_by_field_name("type").is_none());
        assert!(binding.child_by_field_name("value").is_none());

        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let declaration = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.sites[identifier.site.index()].start_byte == pattern.start_byte()
            })
            .expect("positioned binding")
            .site;
        let properties = facts
            .declaration_type_slots
            .iter()
            .filter(|property| {
                property.declaration == declaration && property.role == DeclarationTypeRole::Value
            })
            .collect::<Vec<_>>();
        assert_eq!(properties.len(), 1);
        let value = properties[0].slot;
        assert_eq!(
            facts.type_slots[value.index()].role,
            ResolutionTypeSlotRole::DeclaredValue
        );
        assert!(
            !facts
                .type_transfers
                .iter()
                .any(|transfer| transfer.output == value)
        );
        assert!(
            !facts.type_slots.iter().any(|slot| {
                slot.site == declaration && slot.role == ResolutionTypeSlotRole::AssignmentValue
            }),
            "an uninitialized let must not invent an initializer observation"
        );
        let [write] = facts.local_writes[..] else {
            panic!("one structured write: {:?}", facts.local_writes);
        };
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == write.value
                && transfer.kind == ResolutionTypeTransferKind::Construction
        }));
        assert!(
            facts.binding_projections.iter().any(|projection| {
                projection.kind == BindingProjectionKind::TargetDeclaredValueType
                    && facts.type_slots[projection.output.index()].role
                        == ResolutionTypeSlotRole::ExpressionValue
            }),
            "the later receiver reads the binding's value property"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "1d29ea967529: An unsupported first generic argument leaves the supported second argument at ordinal 1 without duplicate positions."
    )]
    fn unsupported_generic_type_argument_preserves_later_source_ordinals() {
        let source = "struct Pair<A, B>(A, B); type Alias = Pair<[Vec<u8>; 4], String>;";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);

        let pair_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && facts.names[identifier.name.index()].spelling == "Pair"
            })
            .expect("Pair type reference");
        let pair_application = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == pair_reference.site
                    && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
            })
            .expect("Pair generic application identity")
            .id;
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| { gap.kind == ResolutionGapKind::UnsupportedTypeSyntax })
        );
        let pair_ordinals = facts
            .type_arguments
            .iter()
            .filter(|argument| argument.application == pair_application)
            .map(|argument| argument.ordinal)
            .collect::<Vec<_>>();
        assert_eq!(pair_ordinals, [1]);

        let mut ordinals = std::collections::HashMap::<_, Vec<_>>::new();
        for argument in &facts.type_arguments {
            ordinals
                .entry(argument.application)
                .or_default()
                .push(argument.ordinal);
        }
        for values in ordinals.values_mut() {
            values.sort_unstable();
            assert_eq!(
                values
                    .iter()
                    .copied()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                values.len()
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "d42eb16faa98: A bare value name inside an inert bench attribute remains a positioned, gap-free value reference."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "e14f7ee95970: Unexpanded matches! calls retain unit and struct-variant pattern references without marking parsed pattern syntax malformed."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "365b87dd9c25: receiver slots without a producer now retain their own semantic gap instead of reporting missing-slot-producer"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "409f65441fb6: use ... as _ creates no root demand or binder but retains crate, module, and target references in all three namespaces."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "77a06ad02155: A function-local named import does not consume the root glob's demand for an outside type reference."
    )]
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
        sorted_gap_inventory(
            facts,
            source,
            facts.gaps.iter().map(|gap| (gap.site, gap.kind)),
        )
    }

    fn enumeration_gap_inventory<'source>(
        facts: &FileResolutionFacts,
        source: &'source str,
    ) -> Vec<(&'source str, ResolutionGapKind)> {
        sorted_gap_inventory(
            facts,
            source,
            facts
                .reference_enumeration_gaps
                .iter()
                .map(|gap| (gap.site, gap.kind)),
        )
    }

    fn sorted_gap_inventory<'source>(
        facts: &FileResolutionFacts,
        source: &'source str,
        gaps: impl Iterator<Item = (ResolutionSiteId, ResolutionGapKind)>,
    ) -> Vec<(&'source str, ResolutionGapKind)> {
        let mut gaps = gaps
            .map(|(gap_site, kind)| {
                let site = facts.sites[gap_site.index()];
                (
                    &source[site.start_byte..site.end_byte],
                    kind,
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
    #[brokk_bifrost_test_macros::hardwon(
        "#5496: unknown self receivers opened unrelated lexical lookup; retain computed receiver coverage from 07efbb5a4d52."
    )]
    fn computed_receivers_keep_reference_enumeration_complete() {
        // A member on an index, cast, deref or block receiver is still
        // published; only its receiver type is unknown. That is a point gap on
        // the member, not an enumeration gap (#3764: tract's
        // `inputs[0].datum_type.fact(..)` made every graph over the file
        // report ReferenceEnumerationIncomplete).
        let declarations = "struct F { d: D } struct D; impl D { fn fact(&self) {} }";
        for (body, member, gap_kind) in [
            (
                "fn f(inputs: &[F]) { inputs[0].d; }",
                "d",
                ResolutionGapKind::UnsupportedExpression,
            ),
            (
                "fn f(inputs: &[F]) { inputs[0].d.fact(); }",
                "d",
                ResolutionGapKind::UnsupportedExpression,
            ),
            (
                "fn f(inputs: &[F]) { inputs[0].fact(); }",
                "fact",
                ResolutionGapKind::UnsupportedExpression,
            ),
            (
                "fn f(x: u8) { (x as F).fact(); }",
                "fact",
                ResolutionGapKind::UnsupportedExpression,
            ),
            (
                "fn f(x: &F) { (*x).fact(); }",
                "fact",
                ResolutionGapKind::UnsupportedExpression,
            ),
            (
                "fn f(a: F) { { a }.fact(); }",
                "fact",
                ResolutionGapKind::UnsupportedExpression,
            ),
            (
                "trait Bits { fn bits(self); } impl Bits for f32 { fn bits(self) { self.to_bits(); } }",
                "to_bits",
                ResolutionGapKind::UnsupportedScopeOrBinder,
            ),
            (
                "trait Bits { fn bits(self); } impl Bits for f64 { fn bits(self) { self.to_bits(); } }",
                "to_bits",
                ResolutionGapKind::UnsupportedScopeOrBinder,
            ),
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
                    .any(|gap| gap.site == site && gap.kind == gap_kind),
                "{body}: {member} carries its receiver's point gap: {:?}",
                facts.gaps
            );
            if member == "to_bits" {
                assert!(facts.identifiers.iter().any(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "self"
                        && facts.sites[identifier.site.index()].kind
                            == ResolutionSiteKind::ValueReference
                }));
                assert!(
                    facts.gaps.iter().all(|gap| {
                        gap.kind != ResolutionGapKind::UnsupportedScopeOrBinder || gap.site == site
                    }),
                    "unknown self owner must not create a separate scope gap: {:?}",
                    facts.gaps
                );
                assert!(facts.gaps.iter().any(|gap| {
                    gap.site == site && gap.kind == ResolutionGapKind::UnsupportedCallApplicability
                }));
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "44e6532de2c8: the built-in macro_use attribute no longer hides authored module-body references"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "5abce7d67c02: named and glob use prefixes remain source-backed module references"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "daff3876726e: compound type operands remain enumerable while receiver types are uncertain"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "2f7a0c403c99: destructuring constructor paths and field references are not lost from the inventory"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "0a8ed815ecf9: The shorthand value token remains one unqualified value reference beside its field declaration and initializer field role."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "c4bc84ba8df2: An inline cfg module keeps a scope-wide binder and root export plus a module-owned activation obligation, not a placement gap."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "d43a2c3d664f: Trait signatures retain parameter, bound, and abstract Self references while Self's unknown hierarchy remains at the owner frontier."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "53fa192e84bd: Lifetime syntax is excluded from identifier/gap inventories while adjacent value and type references retain exact classifications."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "d71b186f1b06: unit types in declared fields and aliases retain intrinsic identity without a false unsupported-type gap"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "8585863e192c: deeply nested type syntax stops at the supported range and reports a structured gap"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#4289: an interior self after super was incorrectly accepted as a Rust route"
    )]
    fn interior_self_after_super_is_gapped_before_route_publication() {
        let source = "mod outer { fn caller() { super::self::target(); } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse Rust path fixture");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let route_start = source.find("super::self::target").expect("fixture path");
        let route_end = route_start + "super::self::target".len();
        let overlaps_route = |site: ResolutionSiteId| {
            let site = facts.sites[site.index()];
            site.start_byte < route_end && route_start < site.end_byte
        };
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedRoute && overlaps_route(gap.site)
        }));
        assert!(
            facts
                .root_references
                .iter()
                .all(|route| { !overlaps_route(route.reference) })
        );
        assert!(facts.identifiers.iter().all(|identifier| {
            identifier.qualifier.is_none() || !overlaps_route(identifier.site)
        }));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "bafe8bb228ba: path heads remain anchors while every proper qualified prefix gets its own route"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#2622: a resultless call receiver keeps its typed gap and still drains pending slots"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "18b74c827c06: Ordinary and turbofish method calls each keep one callable terminal, receiver, argument references, and their enclosing function owner."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "18b74c827c06: Parenthesized, indexed, and positional-field callees receive exact expression gaps while their nested callee and argument names stay enumerated."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "9cd33cb91f85: A block-local item shadows an import across its executable scope but remains incomplete and never becomes a package root export."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "6499ba69fe8c: anonymous tuple element identity remains unsupported after tuple-index receiver lowering"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "412e2663a745: A cfg use retains its block attachment while any placement-boundary gap stays on a compilation-unit or package scope, avoiding the recorded producer panic."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "a31af62cdcef: block-local cfg routes retain their own scope and no longer abort native indexing"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "c4bc84ba8df2: A nested external module binder belongs to the inline package route and carries an activation gap independent of placement."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#4460: an attribute-transformed item kept only a generic binder gap"
    )]
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
                "transformed",
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
        assert!(declarations.contains("transformed"));
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
            0,
            "attributes preserve authored lexical binders"
        );
        assert_eq!(
            facts
                .reference_enumeration_gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder)
                .count(),
            0,
            "attributes preserve authored references"
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
        assert_eq!(generated, vec!["struct Retained;", "fn transformed() {}"]);
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
    #[brokk_bifrost_test_macros::hardwon(
        "6817b86c92fc: bare turbofish values retain their source reference and do not duplicate call references"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "83331792af4c: generic bounds written on methods remain owned by the method declaration"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "166be2920f5a: signature-only type references retain callable ownership for usage analysis"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "72ea5aebc651: Grouped aliases retain each original target token as a positioned reference and link every namespace demand back to it."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "af644701226f: A simple inherent method publishes its one explicit parameter and closes applicability without an enumeration gap."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "8731e84750dd: Public direct calls, method calls, async calls, and a member field read remain fully enumerated with a receiver transfer."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "af644701226f: Associated types, generic and typed receivers, and associated-constant expressions retain references while representing only unsupported member/type frontiers."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "adef0d5a13cc: trait implementation methods and body references remain source-backed"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "33949a66f0c4: Alias-to-alias impl routing keeps its nominal owner complete and links both alias and impl generic parameters to exact argument positions."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "1545f747714f: Eight built-in test and unsafe attributes leave the function declaration and target reference intact without changing the sole call-applicability gap."
    )]
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
            "#[ctor]",
            "#[ctor::ctor]",
            "#[dtor]",
            "#[dtor::dtor]",
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
    #[brokk_bifrost_test_macros::hardwon(
        "e600080df58f: bare conditions, assignments, and range bounds retain value references"
    )]
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
        assert_eq!(
            gap_inventory(&facts, source),
            [("COUNTER + 1", ResolutionGapKind::UnsupportedExpression)]
        );
        assert_eq!(facts.local_writes.len(), 1);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "9cd33cb91f85: Block-local functions, types, and constants remain visible incomplete binders, while an opaque foreign type stays a point boundary."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "ecdce00e1642: Rust 2015 extern-crate names and aliases are not fabricated as lexical value references"
    )]
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
        assert!(!facts.reference_enumeration_gaps.iter().any(|gap| {
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

        let macro_source = "#[macro_use] extern crate engine;";
        let macro_tree = parser
            .parse(macro_source, None)
            .expect("parse macro-use extern-crate fixture");
        let macro_facts = extract_rust_resolution_facts(macro_tree.root_node(), macro_source);
        let macro_extern_start = macro_source
            .find("extern crate")
            .expect("macro-use extern declaration");
        assert!(macro_facts.reference_enumeration_gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && macro_facts.sites[gap.site.index()].start_byte == macro_extern_start
        }));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "3fc5c9280742: Generic aliases preserve nested alias, generic-head, formal-parameter, and concrete type-argument links at each source occurrence."
    )]
    fn generic_type_alias_facts_preserve_nested_targets_and_concrete_arguments() {
        let source = concat!(
            "struct Tensor;\n",
            "type Leaf<T> = Option<T>;\n",
            "type Outer<U> = Leaf<Vec<U>>;\n",
            "fn consume(_: Outer<Tensor>) {}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let declaration_at = |start: usize| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.sites[identifier.site.index()].start_byte == start
                })
                .unwrap_or_else(|| panic!("type declaration at {start}"))
                .site
        };
        let reference_slot_at = |start: usize| {
            let reference = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.sites[identifier.site.index()].start_byte == start
                })
                .unwrap_or_else(|| panic!("type reference at {start}"))
                .site;
            facts
                .type_slots
                .iter()
                .find(|slot| {
                    slot.site == reference
                        && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
                })
                .unwrap_or_else(|| panic!("type identity slot at {start}"))
                .id
        };
        let type_argument = |application, ordinal| {
            facts
                .type_arguments
                .iter()
                .find(|argument| argument.application == application && argument.ordinal == ordinal)
                .unwrap_or_else(|| panic!("type argument {ordinal} for {application:?}"))
        };

        let leaf_start = source.find("Leaf<T>").unwrap();
        let leaf = declaration_at(leaf_start);
        let leaf_formal = declaration_at(leaf_start + "Leaf<".len());
        let outer_start = source.find("Outer<U>").unwrap();
        let outer = declaration_at(outer_start);
        let outer_formal = declaration_at(outer_start + "Outer<".len());
        let leaf_target = facts
            .generic_type_alias_parameters
            .iter()
            .find(|parameter| parameter.alias == leaf && parameter.parameter == leaf_formal)
            .expect("Leaf formal-to-target row");
        let outer_target = facts
            .generic_type_alias_parameters
            .iter()
            .find(|parameter| parameter.alias == outer && parameter.parameter == outer_formal)
            .expect("Outer formal-to-target row");

        let option_start = source.find("Option<T>").unwrap();
        assert_eq!(
            facts.type_slots[leaf_target.target.index()].site,
            facts.type_slots[reference_slot_at(option_start).index()].site,
            "the alias target frontier retains its outer generic head reference"
        );
        let leaf_argument = type_argument(leaf_target.target, 0);
        assert_eq!(
            leaf_argument.argument,
            reference_slot_at(option_start + "Option<".len())
        );

        let target_leaf_start = source.find("Leaf<Vec<U>>").unwrap();
        let target_leaf_slot = outer_target.target;
        assert_eq!(
            facts.type_slots[target_leaf_slot.index()].site,
            facts.type_slots[reference_slot_at(target_leaf_start).index()].site,
            "the alias-of-alias target retains the referenced alias head"
        );
        let vector_slot = type_argument(target_leaf_slot, 0).argument;
        assert_eq!(
            type_argument(vector_slot, 0).argument,
            reference_slot_at(source.find("Vec<U>").unwrap() + "Vec<".len())
        );

        let application_start = source.find("Outer<Tensor>").unwrap();
        let application_slot = reference_slot_at(application_start);
        assert_eq!(
            type_argument(application_slot, 0).argument,
            reference_slot_at(application_start + "Outer<".len())
        );
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
    #[brokk_bifrost_test_macros::hardwon(
        "985c255966c6: generic call results follow instantiated argument types instead of returning a bound or wrong member"
    )]
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

    /// A literal argument is typed when its token fixes the type: a suffixed
    /// number, a `bool`, a `char`, and a string (`&str`, one reference layer).
    /// An unsuffixed number names the inference its type waits for; a byte or
    /// C literal has no modelled type. A closure's type is inferred from the
    /// parameter it is passed to, and names that inference too.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "f315e9c723a9: literal arguments with syntax-fixed types do not remain unsupported-expression gaps"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "955f6461cafc: unit-struct values carry their own declared construction type"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "bff239a86067: a generic result does not resolve to the type-parameter declaration itself"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "e6531efe91f1: Closure and for-loop x binders get separate scopes, with the iterable and post-loop reference remaining in the outer scope."
    )]
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
        let vec_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "Vec"
            })
            .expect("Vec type reference");
        let vec_application = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == vec_reference.site
                    && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
            })
            .expect("Vec application identity")
            .id;
        assert!(facts.type_arguments.iter().any(|argument| {
            let site = facts.type_slots[argument.argument.index()].site;
            argument.application == vec_application
                && argument.ordinal == 0
                && &source[facts.sites[site.index()].start_byte..facts.sites[site.index()].end_byte]
                    == "i32"
        }));
        assert_eq!(
            gap_inventory(&facts, source),
            [
                ("0", ResolutionGapKind::UnsupportedExpression),
                ("|x| x", ResolutionGapKind::UnsupportedExpression),
                ("x", ResolutionGapKind::UnsupportedExpression),
            ]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e6531efe91f1: The Some(x) binder owns its guard/body references, while a fallback arm resolves x from the outer binding."
    )]
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
        assert_eq!(
            gap_inventory(&facts, source),
            [
                ("0", ResolutionGapKind::UnsupportedExpression),
                ("Some(x) if x > 0", ResolutionGapKind::UnsupportedExpression),
            ],
            "the outer initializer and unmodeled pattern input stay explicit"
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
        assert_eq!(
            gap_inventory(&facts, source),
            [
                ("0", ResolutionGapKind::UnsupportedExpression),
                ("Some(x)", ResolutionGapKind::UnsupportedExpression),
                ("Some(x)", ResolutionGapKind::UnsupportedExpression),
            ],
            "the outer initializer and unmodeled pattern inputs stay explicit"
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
                | ResolutionGapKind::UnsupportedExpression
        )));
        assert_eq!(
            point_gaps
                .iter()
                .filter(|(_, kind)| *kind == ResolutionGapKind::UnsupportedExpression)
                .map(|(spelling, _)| *spelling)
                .collect::<Vec<_>>(),
            ["Some(x)", "Some(y)", "Some(x)", "Some(y)"],
            "each implicit pattern input remains unknown independently of its constructor path"
        );
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
        assert_eq!(
            gap_inventory(&facts, source),
            [("Ok(x) | Err(x)", ResolutionGapKind::UnsupportedExpression)],
            "one semantic binder retains one unknown incoming value across its alternatives"
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
    #[brokk_bifrost_test_macros::hardwon(
        "e64fac43c061: Qualified projection heads retain Service and Runner type references while the associated Output remains a receiver-qualified member, not a lexical name demand."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "c2fbc27c1b4f: Definition-site self/super/crate/other paths remain context-gapped while the exported $crate path keeps its root route."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "b5571087c346: The same crate:: path roots in a local macro but becomes invocation-context uncertain after macro_export."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "cc07fde1f900: Matched ty and expr fragments publish exactly one type/value reference at each invocation token range."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "24736353a071: a self metavariable in an impl macro was parsed as a type and crashed the Rust producer."
    )]
    fn macro_self_receiver_identifier_stays_an_expression_fragment() {
        let source = r#"
struct Layer { value: u64 }
macro_rules! add_fields {
    ($current:ident, $other:ident; $($field:ident),+ $(,)?) => {
        Self { $($field: $current.$field.saturating_add($other.$field)),+ }
    };
}
impl Layer {
    fn add(self, other: Self) -> Self { add_fields!(self, other; value,) }
}
"#;
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("fixture parses");
        let _facts = extract_rust_resolution_facts(tree.root_node(), source);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "c355a27ef45c: A repeated macro transcriber retains the definition-site TestOutput type reference when emitted through a captured repetition."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "cc07fde1f900: A failed matcher and a declaration-name metavariable each avoid fabricating Item as a type or value reference."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "cc07fde1f900: A matched qualified type fragment retains its route, while a block expression fragment owns its local value binder and reference."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "cc07fde1f900: An item metavariable invocation records an unresolved declaration-generation boundary rather than inventing emitted item facts."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "cc07fde1f900: Sixty-four nested invocations on a bounded stack resolve the innermost value reference once and preserve complete enumeration."
    )]
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

    /// A Rust item declared in a block does not capture: the block's locals are
    /// invisible inside it, while the items declared beside it are visible.
    /// The producer states both with the scope chain, so this reads the chain.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "bd32ab64683f: block-local items see sibling items but cannot capture enclosing block locals"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "82d98fd34208: items nested in an impl method body remain block-local rather than associated members"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "098e4db4efc0: A trait default method body gets its own scope, local and self binders, helper references, and an abstract trait-Self receiver frontier."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "1ccbb9186c59: associated constants and their initializer references are not omitted from impl members"
    )]
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
    /// sole authority over an item-position interior. Generated names stay
    /// open independently of recovered arguments. Reverse inventory is open
    /// only when an input group cannot be enumerated as references.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "ae985d50fe2d: A criterion_group token tree exposes its macro, type, and callable references without minting declarations; an opaque lazy_static group remains a boundary."
    )]
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
                    ResolutionGapKind::GeneratedItemSurface
                ),
                ("(Benches, bench)", ResolutionGapKind::UnexpandedImplMacro),
                ("Benches", ResolutionGapKind::UnsupportedExpression),
                ("bench", ResolutionGapKind::UnsupportedExpression),
            ],
            "{facts:#?}"
        );
        assert_eq!(
            enumeration_gap_inventory(&facts, source),
            vec![],
            "#5517: fully parsed macro inputs have a complete reference inventory"
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
                ResolutionGapKind::UnsupportedExpression
            )],
            "{facts:#?}"
        );
    }

    /// Iterative subtree search; the fixtures are tiny but the walk stays
    /// stack-safe.
    fn find_first_node<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if node.kind() == kind {
                return Some(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        None
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5133: a guessed macro operand inside cfg_if duplicated its computed receiver gap"
    )]
    fn guessed_macro_operand_preserves_one_computed_receiver_gap() {
        // Reduced from the pinned Vector Windows event source. The coordinated
        // parser replays cfg_if arms; the standalone native helper does not.
        let source = r#"
cfg_if::cfg_if! {
    if #[cfg(windows)] {
        fn query(error: Error) {
            emit!(QueryError {
                channel: "all".to_string(),
                error: error.to_string(),
            });
        }
    }
}
"#;
        let facts = crate::test_helpers::parse_rust_fixture(source).resolution_facts;
        let mut seen = std::collections::HashSet::new();
        for gap in &facts.gaps {
            assert!(seen.insert(gap), "duplicate gap: {gap:?}");
        }
        let methods = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "to_string"
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 2, "both authored method references survive");
        for method in methods {
            assert!(
                facts.gaps.iter().any(|gap| gap.site == method.site
                    && gap.kind == ResolutionGapKind::UnsupportedExpression),
                "guessed macro references retain their uncertainty"
            );
            assert!(
                facts.gaps.iter().any(|gap| gap.site == method.site
                    && gap.kind == ResolutionGapKind::UnsupportedCallApplicability),
                "independent call obligations remain present"
            );
        }
    }

    fn parse_and_extract(source: &str) -> FileResolutionFacts {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse fixture");
        extract_rust_resolution_facts(tree.root_node(), source)
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "3dc93c95f31f: quicksilver round 3 on brokk-bifrost-rust: malformed cfg_attr predicates supplied inert evidence"
    )]
    fn quicksilver_cfg_attr_predicate_requires_structure() {
        for (predicate, can_expand) in [
            ("42", true),
            ("not()", true),
            ("not(unix, windows)", true),
            ("unknown(unix)", true),
            ("all(42)", true),
            ("unix = 42", true),
            ("all[unix]", true),
            ("", true),
            ("unix", false),
            ("feature = \"cli\"", false),
            ("not(unix)", false),
            ("all(unix, not(windows),)", false),
            ("any()", false),
            ("true", false),
            ("false", false),
        ] {
            let source = format!("#[cfg_attr({predicate}, inline)] fn f() {{}}");
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            assert!(
                !tree.root_node().has_error(),
                "{}",
                tree.root_node().to_sexp()
            );
            let mut pending = vec![tree.root_node()];
            let attribute = loop {
                let node = pending.pop().expect("fixture has an attribute");
                if node.kind() == "attribute_item" {
                    break node;
                }
                pending.extend(node.named_children(&mut node.walk()));
            };
            assert_eq!(
                super::rust_attribute_item_can_expand(attribute, &source),
                can_expand,
                "{predicate}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "3dc93c95f31f: quicksilver round 3 on brokk-bifrost-rust: local wrapper names lost nominal impl owners"
    )]
    fn quicksilver_local_wrapper_impl_has_nominal_subject() {
        for name in ["Box", "Option", "Result", "Arc", "Rc"] {
            let source =
                format!("struct {name}<T>(T); impl<T> {name}<T> {{ fn method(&self) {{}} }}");
            let facts = parse_and_extract(&source);
            let relation = facts
                .declared_type_relations
                .first()
                .expect("impl relation");
            let site = facts.type_slots[relation.subject.index()].site;
            assert!(
                !facts
                    .gaps
                    .iter()
                    .any(|gap| gap.site == site
                        && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax),
                "local {name} impl subject was refused as a std wrapper"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "3dc93c95f31f: quicksilver round 3 on brokk-bifrost-rust: legal local trait impls for foreign wrappers lost their subjects"
    )]
    fn quicksilver_local_trait_foreign_wrapper_has_nominal_subject() {
        let source = "trait Local { fn method(&self); } impl Local for std::boxed::Box<u8> { fn method(&self) {} }";
        let facts = parse_and_extract(source);
        let relation = facts
            .declared_type_relations
            .iter()
            .find(|r| r.kind == ResolutionDeclaredTypeRelationKind::TraitImplementation)
            .expect("trait impl");
        let site = facts.type_slots[relation.subject.index()].site;
        assert!(!facts.gaps.iter().any(|gap| gap.site == site && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax),
            "legal local trait impl subject was refused by the inherent-impl orphan rationale");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5133: grouped tuple-field attributes shifted native positional field identities"
    )]
    fn grouped_tuple_field_attributes_do_not_shift_native_ordinals() {
        let source = "struct S(#[first] pub u8, #[second] u16); enum E { V(#[third] u32, u64) }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse fixture");
        assert!(!tree.root_node().has_error(), "{source}");
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let mut ordinals = facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .filter_map(|identifier| {
                let spelling = facts.names[identifier.name.index()].spelling.as_str();
                spelling.parse::<u32>().is_ok().then_some(spelling)
            })
            .collect::<Vec<_>>();
        ordinals.sort_unstable();
        assert_eq!(ordinals, ["0", "0", "1", "1"]);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "6dc4d18752fb: recovered lifetime was accepted as a path and reached strict lowering"
    )]
    fn forwarded_macro_lifetimes_and_paths_do_not_panic_during_lowering() {
        let issue_70446 = r#"macro_rules! foo {
    ($(: $p:path)? $(: $l:lifetime)? ) => { bar! {$(: $p)? $(: $l)? } };
}

macro_rules! bar {
    ($(: $p:path)? $(: $l:lifetime)? ) => {};
}

foo! {: 'a }

fn main() {}
"#;
        let facts = parse_and_extract(issue_70446);
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && facts.names[identifier.name.index()].spelling == "main"
        }));

        let issue_7911 = r#"trait FooBar { fn dummy(&self) {} }
struct Bar(i32);
struct Foo { bar: Bar }
impl FooBar for Bar {}
trait Test {
    fn get_immut(&self) -> &dyn FooBar;
    fn get_mut(&mut self) -> &mut dyn FooBar;
}
macro_rules! generate_test { ($type_:path, $slf:ident, $field:expr) => (
    impl Test for $type_ {
        fn get_immut(&$slf) -> &dyn FooBar { &$field as &dyn FooBar }
        fn get_mut(&mut $slf) -> &mut dyn FooBar { &mut $field as &mut dyn FooBar }
    }
)}
generate_test!(Foo, self, self.bar);
"#;
        let facts = parse_and_extract(issue_7911);
        assert!(facts.names.iter().any(|name| name.spelling == "FooBar"));
    }

    /// A call in declared-type syntax (a computed array length such as
    /// `[u8; mask_len(N)]`) is lowered by the main walk when it descends to
    /// the call: the callee is a CallableReference and each actual produces
    /// one argument row. The declared-type pass runs during the enclosing
    /// item's enter, before that descent; when it lowered the call's operand
    /// identifiers itself they were already handled at the walk's visit, and
    /// the pending argument slot call lowering keyed on each was never
    /// discharged, tripping the "every call argument expression is lowered"
    /// seal (#4279).
    #[test]
    fn calls_in_declared_type_positions_are_lowered_once_by_the_walk() {
        let source = "fn mask_len(n: usize) -> usize { n }\n\
                      const N: usize = 4;\n\
                      fn f() -> [u8; mask_len(N)] { loop {} }\n\
                      const C: [u8; mask_len(N)] = [0u8; 4];\n\
                      struct S([u8; mask_len(N)]);\n\
                      impl S { type T = [u8; mask_len(N)]; }\n\
                      fn g() where [(); mask_len(N)]: {}\n";
        // Extraction completing at all is the seal tripwire: finish() asserts
        // every pending argument slot was discharged.
        let facts = parse_and_extract(source);
        let callees = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::CallableReference
                    && facts.names[identifier.name.index()].spelling == "mask_len"
            })
            .count();
        assert_eq!(
            callees, 5,
            "one CallableReference per declared-type call: {facts:#?}"
        );
        let arguments = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::ValueReference
                    && facts.names[identifier.name.index()].spelling == "N"
            })
            .count();
        assert_eq!(
            arguments, 5,
            "one Value reference per call argument: {facts:#?}"
        );
    }

    #[test]
    fn let_initializer_in_const_type_position_is_lowered_once_by_the_walk() {
        let source = "fn f<const N: usize>() -> [u8; { let x = N; N + 1 }] { loop {} }";
        let facts = parse_and_extract(source);
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && facts.names[identifier.name.index()].spelling == "N"
            })
            .count();
        assert_eq!(
            references, 2,
            "both const-block uses are retained: {facts:#?}"
        );
    }

    /// The declared-type pass must not skip macro invocations the way it
    /// skips calls: the walk lowers an invocation but never descends into its
    /// token tree, so the pass is the interior identifiers' only
    /// reference-enumeration coverage (#4279's exception is call_expression
    /// only; IronRDP's `[u8; concat_arrays_size!(..)]` relies on this).
    #[test]
    fn macro_in_declared_type_array_length_keeps_eager_coverage() {
        let source = "struct S([u8; concat_arrays_size!(X)]);";
        let facts = parse_and_extract(source);
        assert_eq!(
            enumeration_gap_inventory(&facts, source),
            vec![
                (
                    "concat_arrays_size",
                    ResolutionGapKind::UnsupportedExpression
                ),
                ("X", ResolutionGapKind::UnsupportedExpression),
            ],
            "the token tree's identifiers stay enumerated: {facts:#?}"
        );
    }

    /// Recovery turns `???` into nested try_expressions over a zero-width
    /// missing identifier. That node is not a value producer: the walk skips
    /// it, so a pending initialization keyed on it was never discharged,
    /// tripping the "every let initializer's producing expression is lowered"
    /// seal (#4291).
    #[test]
    fn missing_let_initializer_produces_no_pending_initialization() {
        let source = "fn f() { let a = ???; }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse fixture");
        // Pin the recovery assumption so the fixture stays honest across
        // grammar versions: the value is nested try_expressions over one
        // zero-width missing identifier.
        let let_declaration =
            find_first_node(tree.root_node(), "let_declaration").expect("fixture has a let");
        let value = let_declaration
            .child_by_field_name("value")
            .expect("let has a value");
        assert_eq!(value.kind(), "try_expression");
        let mut missing = Vec::new();
        let mut pending = vec![value];
        while let Some(node) = pending.pop() {
            if node.is_missing() {
                missing.push(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        assert_eq!(missing.len(), 1, "one recovery placeholder under the tries");
        assert_eq!(missing[0].kind(), "identifier");
        assert_eq!(
            missing[0].start_byte(),
            missing[0].end_byte(),
            "the recovered identifier is zero-width"
        );

        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            gap_inventory(&facts, source)
                .iter()
                .any(|(_, kind)| *kind == ResolutionGapKind::MalformedSyntax),
            "the skipped missing node leaves a MalformedSyntax gap: {facts:#?}"
        );
        assert!(
            facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "a"
            }),
            "the binding itself is still declared: {facts:#?}"
        );
    }

    /// The symmetric argument case: recovery leaves a missing identifier
    /// under the reference layers of `g(&&)`. Call lowering must not key a
    /// pending argument slot on an operand the walk skips (#4291).
    #[test]
    fn missing_call_argument_falls_to_the_gap_fed_slot() {
        let source = "fn f() { g(&&); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse fixture");
        // Same recovery assumption: one zero-width missing identifier, here
        // under two reference layers in the call's arguments.
        let arguments = find_first_node(tree.root_node(), "arguments").expect("fixture has a call");
        let mut missing = Vec::new();
        let mut pending = vec![arguments];
        while let Some(node) = pending.pop() {
            if node.is_missing() {
                missing.push(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        assert_eq!(
            missing.len(),
            1,
            "one recovery placeholder in the arguments"
        );
        assert_eq!(missing[0].kind(), "identifier");

        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        assert!(
            gap_inventory(&facts, source)
                .iter()
                .any(|(_, kind)| *kind == ResolutionGapKind::MalformedSyntax),
            "the skipped missing operand leaves a MalformedSyntax gap: {facts:#?}"
        );
    }

    /// A missing node where a name belongs has no spelling to intern. Each
    /// reader treats it like an absent name instead of interning an empty
    /// spelling, which the "resolution names need a spelling" seal rejects
    /// (#4286, from c2rust's `fn empty_generics<>(test: *const i32) {}`).
    #[test]
    fn missing_names_leave_gaps_not_empty_spellings() {
        // The exact c2rust exemplar: the type_parameter's name is a missing
        // type_identifier.
        let exemplar = "fn empty_generics<>(test: *const i32) {}";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(exemplar, None).expect("parse fixture");
        // Pin the recovery assumption: a type_parameter whose name field is a
        // zero-width missing node.
        let parameter =
            find_first_node(tree.root_node(), "type_parameter").expect("fixture has a parameter");
        let name = parameter
            .child_by_field_name("name")
            .expect("the parameter's name field is present");
        assert!(name.is_missing(), "recovery leaves a missing name");
        assert_eq!(name.start_byte(), name.end_byte());

        let truncated_let = "fn f() { if let = x {} }";
        let let_tree = parser.parse(truncated_let, None).expect("parse fixture");
        // Same assumption in pattern position: the let condition's pattern is
        // a missing identifier.
        let condition = find_first_node(let_tree.root_node(), "let_condition")
            .expect("fixture has a condition");
        let pattern = condition
            .child_by_field_name("pattern")
            .expect("the condition's pattern field is present");
        assert!(pattern.is_missing(), "recovery leaves a missing pattern");
        assert_eq!(pattern.kind(), "identifier");

        // A truncated match arm takes the same missing pattern, a generic
        // alias's parameter list the same missing name, and a turbofish with
        // a missing type argument reaches declared-type lowering.
        for source in [
            exemplar,
            truncated_let,
            "fn f() { match x { => {} } }",
            "type T<> = u8;",
            "fn f() { foo::<>(); }",
        ] {
            let tree = parser.parse(source, None).expect("parse fixture");
            let facts = extract_rust_resolution_facts(tree.root_node(), source);
            assert!(
                gap_inventory(&facts, source)
                    .iter()
                    .any(|(_, kind)| *kind == ResolutionGapKind::MalformedSyntax),
                "the missing syntax leaves a MalformedSyntax gap in {source:?}: {facts:#?}"
            );
            assert!(
                facts.names.iter().all(|name| !name.spelling.is_empty()),
                "no empty spelling is interned for {source:?}: {facts:#?}"
            );
        }
    }

    #[test]
    fn missing_impl_type_arguments_leave_gaps_not_empty_spellings() {
        let source = "impl<> T<> for S<> {}";
        let facts = parse_and_extract(source);
        assert!(
            gap_inventory(&facts, source)
                .iter()
                .any(|(_, kind)| *kind == ResolutionGapKind::MalformedSyntax),
            "the missing impl type argument leaves a MalformedSyntax gap: {facts:#?}"
        );
        assert!(
            facts.names.iter().all(|name| !name.spelling.is_empty()),
            "the missing impl type argument has no spelling: {facts:#?}"
        );
    }

    #[test]
    fn missing_field_name_leaves_a_gap_not_an_empty_spelling() {
        for source in [
            "fn main() { let y = 42; let x = y.; }",
            "fn main() { let y = 42; let x = y.(); }",
            "struct S(u8); fn f(s: S) { s.1e+; }",
        ] {
            let facts = parse_and_extract(source);
            assert!(
                gap_inventory(&facts, source)
                    .iter()
                    .any(|(_, kind)| *kind == ResolutionGapKind::MalformedSyntax),
                "the missing field name leaves a MalformedSyntax gap: {facts:#?}"
            );
            assert!(
                facts.names.iter().all(|name| !name.spelling.is_empty()),
                "the missing field name has no spelling: {facts:#?}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5243: slice and array elements bypassed a source primitive shadow"
    )]
    fn composite_primitive_shadows_require_lexical_element_types() {
        let facts = parse_and_extract("struct u8; fn inspect(slice: &[u8], array: [u8; 4]) {}");
        assert_eq!(facts.type_productions.len(), 2, "{facts:#?}");
        assert!(facts.type_components.is_empty(), "{facts:#?}");
        assert!(
            facts.intrinsic_type_seeds.iter().all(|seed| !matches!(
                seed.kind,
                IntrinsicTypeKind::Slice | IntrinsicTypeKind::Array
            )),
            "a shadowed element cannot assert a builtin sequence: {facts:#?}"
        );
        for production in &facts.type_productions {
            let projection = facts
                .binding_projections
                .iter()
                .find(|projection| projection.output == production.element)
                .expect("the constructor operand has a lexical projection");
            assert_eq!(projection.kind, BindingProjectionKind::TargetTypeIdentity);
            let identifier = facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == projection.reference)
                .expect("the lexical element has a written reference");
            assert_eq!(identifier.namespace, ResolutionNamespace::Type);
            assert_eq!(facts.names[identifier.name.index()].spelling, "u8");
        }
    }

    #[test]
    fn raw_identifier_matching_primitive_spelling_remains_a_reference() {
        let source = "type r#Type = r#u32;";
        let facts = parse_and_extract(source);
        assert!(
            facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "u32"
            }),
            "the raw type name is a reference even when its canonical spelling is primitive-like: {facts:#?}"
        );
    }
}

#[cfg(test)]
mod ownership_lowering_grammar_boundary {
    use super::*;

    #[test]
    fn ownership_resolution_grammar_contract() {
        let source = concat!(
            "struct Widget<T>(T); type Plain = Widget<u8>; type Fish = Widget::<u8>;\n",
            "impl Widget<u8> { fn instance(&self) {} fn associated() {} }\n",
            "impl (u8, u8) { fn tuple_instance(&self) {} fn tuple_associated() {} }\n",
            "trait Receiver { fn boxed(self: Box<Self>); fn static_call(); }\n",
            "trait Bound { type Item; } fn capture<T>() -> impl Bound<Item = T> + use<T> { loop {} }\n",
            "unsafe extern \"C\" { fn empty(); fn argument(value: u8); }\n",
        );
        let tree = crate::test_helpers::parse_rust(source);
        assert!(!tree.root_node().has_error());
        let mut pending = vec![tree.root_node()];
        let mut type_heads = Vec::new();
        let mut capture_return = None;
        while let Some(node) = pending.pop() {
            match node.kind() {
                "function_item"
                    if node
                        .child_by_field_name("name")
                        .is_some_and(|name| &source[name.byte_range()] == "capture") =>
                {
                    capture_return = Some(
                        node.child_by_field_name("return_type")
                            .unwrap()
                            .byte_range(),
                    );
                }
                "type_item" => {
                    let ty = node.child_by_field_name("type").unwrap();
                    type_heads.push((
                        ty.start_byte(),
                        ty.kind(),
                        ty.child_by_field_name("type").unwrap().kind(),
                    ));
                }
                "type_binding" => {
                    assert_eq!(
                        node.child_by_field_name("name").unwrap().kind(),
                        "type_identifier"
                    );
                    assert_eq!(
                        node.child_by_field_name("type").unwrap().kind(),
                        "type_identifier"
                    );
                }
                _ => {}
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        type_heads.sort_unstable();
        assert_eq!(
            type_heads
                .into_iter()
                .map(|(_, kind, head)| (kind, head))
                .collect::<Vec<_>>(),
            [
                ("generic_type", "type_identifier"),
                ("generic_type", "type_identifier")
            ]
        );
        let facts = extract_rust_resolution_facts(tree.root_node(), source);
        let text = |site: ResolutionSiteId| {
            let row = facts.sites[site.index()];
            &source[row.start_byte..row.end_byte]
        };
        let mut access = facts
            .deferred_member_owners
            .iter()
            .map(|member| (text(member.member), member.access))
            .collect::<Vec<_>>();
        access.extend(
            facts
                .member_owners
                .iter()
                .filter(|member| member.kind == ResolutionMemberKind::Method)
                .map(|member| (text(member.member), member.access)),
        );
        access.sort_by_key(|(name, _)| *name);
        assert_eq!(
            access,
            [
                ("associated", ResolutionMemberAccess::Type),
                ("boxed", ResolutionMemberAccess::Instance),
                ("instance", ResolutionMemberAccess::Instance),
                ("static_call", ResolutionMemberAccess::Type),
                ("tuple_associated", ResolutionMemberAccess::Type),
                ("tuple_instance", ResolutionMemberAccess::Instance),
            ]
        );
        // Both alias spellings denote the same nominal head. A tuple impl
        // remains unsupported, independently of receiver access syntax.
        let nominal_projections = facts
            .binding_projections
            .iter()
            .filter(|projection| {
                projection.kind == BindingProjectionKind::TargetNominalTypeIdentity
                    && text(projection.reference) == "Widget"
            })
            .count();
        assert_eq!(nominal_projections, 3, "{facts:#?}");
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
                    && text(gap.site) == "(u8, u8)")
        );
        let capture_return = capture_return.unwrap();
        let within_return =
            |site: ResolutionSiteId| capture_return.contains(&facts.sites[site.index()].start_byte);
        assert!(
            facts.type_transfers.iter().any(|transfer| transfer.kind
                == ResolutionTypeTransferKind::TypeUnion
                && within_return(facts.type_slots[transfer.output.index()].site)),
            "trait return lowering ran"
        );
        assert!(
            !facts.gaps.iter().any(|gap| gap.kind
                == ResolutionGapKind::UnsupportedHierarchyTraversal
                && within_return(gap.site)),
            "precise captures introduce no supertype: {:?}",
            facts
                .gaps
                .iter()
                .map(|gap| (text(gap.site), gap.kind))
                .collect::<Vec<_>>()
        );
        let bindings = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && text(identifier.site) == "Item"
            })
            .collect::<Vec<_>>();
        assert_eq!(bindings.len(), 1, "{bindings:?}");
        assert!(
            bindings[0].qualifier.is_some(),
            "associated type binding selects a trait member"
        );
        let mut foreign_gaps = facts
            .gaps
            .iter()
            .filter(|gap| matches!(text(gap.site), "empty" | "argument"))
            .map(|gap| (text(gap.site), gap.kind))
            .collect::<Vec<_>>();
        foreign_gaps.sort_by_key(|(name, kind)| (*name, format!("{kind:?}")));
        assert!(
            foreign_gaps.iter().any(|(name, kind)| *name == "argument"
                && *kind == ResolutionGapKind::UnsupportedCallApplicability),
            "{foreign_gaps:?}"
        );
        assert!(
            !foreign_gaps.iter().any(|(name, kind)| *name == "empty"
                && *kind == ResolutionGapKind::UnsupportedCallApplicability),
            "{foreign_gaps:?}"
        );
    }
}

#[cfg(test)]
mod qs3_resolution_contract {
    use super::*;
    use crate::test_helpers::{parse_rust, parse_rust_fixture};

    #[test]
    fn qs3_constructor_and_type_grammar_boundary() {
        let source = "struct Pair<T>(T); mod api { struct Named; } macro_rules! take_type { ($t:ty) => {}; } fn f() { let Pair(x) = input; let Pair::<u8>(y) = input; let value: crate::api::Named; take_type!(crate::api::Named); } fn typed() -> crate::api::Named { loop {} }";
        let tree = parse_rust(source);
        assert!(!tree.root_node().has_error());
        let parsed = parse_rust_fixture(source);
        let facts = parsed.resolution_facts;
        let mut pending = vec![tree.root_node()];
        let mut constructors = Vec::new();
        let mut types = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "tuple_struct_pattern" {
                let mut head = node.child_by_field_name("type").unwrap();
                if head.kind() == "generic_type" {
                    head = head.child_by_field_name("type").unwrap();
                }
                constructors.push((head.start_byte(), head.end_byte()));
                assert!(
                    facts
                        .sites
                        .iter()
                        .any(|site| site.start_byte == head.start_byte()
                            && site.end_byte == head.end_byte()
                            && site.kind == ResolutionSiteKind::ValueReference)
                );
            }
            if node.kind() == "scoped_type_identifier"
                && &source[node.byte_range()] == "crate::api::Named"
            {
                types.push(node.byte_range());
                assert!(facts.sites.iter().any(|site| site.start_byte
                    == node.child_by_field_name("name").unwrap().start_byte()
                    && site.end_byte == node.end_byte()
                    && site.kind == ResolutionSiteKind::TypeReference));
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        assert_eq!(constructors.len(), 2);
        assert_eq!(types.len(), 2);
        // The captured :ty fragment has the same type role as AST annotations.
        let named_type_references = facts
            .sites
            .iter()
            .filter(|site| {
                site.kind == ResolutionSiteKind::TypeReference
                    && &source[site.start_byte..site.end_byte] == "Named"
            })
            .count();
        assert_eq!(named_type_references, 3);
    }

    #[test]
    fn qs3_projection_head_grammar_boundary() {
        let source = "type A = <Service as Runner>::Output::Nested; type B = <Service as Runner>::Output<u8>::Nested; fn f() { <Service as Runner>::Output::new(); }";
        let tree = parse_rust(source);
        assert!(!tree.root_node().has_error());
        let mut stack = vec![tree.root_node()];
        let mut paths = Vec::new();
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "scoped_type_identifier" | "scoped_identifier")
                && matches!(
                    &source[node.byte_range()],
                    "<Service as Runner>::Output::Nested"
                        | "<Service as Runner>::Output<u8>::Nested"
                        | "<Service as Runner>::Output::new"
                )
            {
                let head = rust_projection_path_head(node).unwrap();
                assert_eq!(head.kind(), "bracketed_type");
                assert_eq!(&source[head.byte_range()], "<Service as Runner>");
                paths.push(node.kind());
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        paths.sort_unstable();
        assert_eq!(
            paths,
            [
                "scoped_identifier",
                "scoped_type_identifier",
                "scoped_type_identifier"
            ]
        );
    }

    #[test]
    fn qs3_empty_import_route_boundary() {
        for (source, empty) in [
            (
                "use crate::{}; fn target() {} fn call() { target(); }",
                true,
            ),
            ("use crate::{nested::{/*empty*/}}; fn target() {}", true),
            ("use *; fn target() {}", false),
        ] {
            let parsed = parse_rust_fixture(source);
            let gaps = &parsed.resolution_facts.gaps;
            assert!(!gaps.is_empty(), "route classification ran: {source}");
            let unknown_binder = gaps
                .iter()
                .any(|gap| matches!(gap.route(), Some(ResolutionRouteGap::UnknownBinder { .. })));
            assert_eq!(unknown_binder, !empty, "{source}: {gaps:?}");
        }
    }
}
