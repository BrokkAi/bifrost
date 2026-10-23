//! Rust lowering into the language-neutral executable-semantics IR.
//!
//! Tree-sitter nodes and fields describe Rust syntax here; graph mechanics,
//! abrupt-completion routing, and immutable adjacency storage stay in the
//! shared semantic substrate.

use brokk_bifrost_analysis::analyzer::common::is_comment_kind;
use brokk_bifrost_semantic::analyzer::semantic::inventory::{
    ProcedureInventoryBuilder, ProcedureInventoryOutcome, ProcedureLoweringInput,
    ProcedureTreeWalkOutcome, ProcedureWalkScopes, ProcedureWalkStep, walk_procedure_tree,
};
use brokk_bifrost_semantic::analyzer::semantic::lowering::*;

use brokk_bifrost_semantic::analyzer::semantic::lowering::ConditionTargets;

use brokk_bifrost_semantic::analyzer::semantic::lowering::DecompositionExpansion;

use brokk_bifrost_semantic::analyzer::semantic::lowering::DecompositionStep;

use brokk_bifrost_semantic::analyzer::semantic::lowering::ProcedureWork;

use brokk_bifrost_semantic::analyzer::semantic::lowering::ProcedureWorkHandler;

use brokk_bifrost_semantic::analyzer::semantic::lowering::ShortCircuitKind;

use brokk_bifrost_semantic::analyzer::semantic::lowering::charge_lowering_traversal_step;

use brokk_bifrost_semantic::analyzer::semantic::lowering::dispatch_procedure_work;

use brokk_bifrost_semantic::analyzer::semantic::lowering::emit_cleanup_completion_route;

use brokk_bifrost_semantic::analyzer::semantic::lowering::field_matches;

use brokk_bifrost_semantic::analyzer::semantic::lowering::ordered_decomposition_steps;

use brokk_bifrost_semantic::analyzer::semantic::lowering::schedule_sequential_work;

use brokk_bifrost_semantic::analyzer::semantic::lowering::schedule_sequential_work_with_scopes;

use brokk_bifrost_semantic::analyzer::semantic::lowering::schedule_short_circuit_condition;

use brokk_bifrost_analysis::analyzer::semantic::structural_identity::StructuralNodeIndex;

use brokk_bifrost_analysis::analyzer::semantic::structural_identity::StructuralNodeIndexOutcome;
use tree_sitter::Node;

use brokk_bifrost_rust::declarations::{
    rust_callable_dispatch_extensibility, rust_node_text, rust_nominal_type_path,
};
use brokk_bifrost_rust::format_args::{RustFormattingMacro, RustLoggingMacro, RustValueMacro};
use brokk_bifrost_rust::lexical_scope::rust_pattern_identifier_binding_bounded;
use brokk_bifrost_rust::macro_matcher::ExportedMacroDefinitions;
use brokk_bifrost_rust::ownership::{
    RustOwnershipClass, RustOwnershipIncomplete, RustOwnershipIndex, RustReferenceCoercion,
    rust_dereference_operand, rust_node_is_in_unsafe_context, rust_reference_expression_value,
    rust_reference_is_mutable, rust_reference_type_referent,
};
use brokk_bifrost_rust::structural::RUST_STRUCTURAL_SPEC;
use brokk_bifrost_rust::structural::{call_function_target, rust_method_call_parts};
use brokk_bifrost_rust::syntax::unwrap_attributes;

use brokk_bifrost_analysis::analyzer::declared_scalar::DeclaredScalarType;

use brokk_bifrost_analysis::analyzer::declared_scalar::rust_scalar_type_from_literal;

use brokk_bifrost_analysis::analyzer::declared_scalar::rust_scalar_type_from_type;

use brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalBindingResolution;

use brokk_bifrost_analysis::analyzer::lexical_definitions::binding_excluded_child_fields;

use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots_for_owner;

use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CleanupRouteOperation, CompletionKind, CompletionRequest, CompletionRoute,
    ProcedureCfgBuilder, ScopeBinding, ScopeCleanupAction, ScopeFrameId,
};
use brokk_bifrost_analysis::analyzer::lexical_definitions::resolve_lexical_binding_from_focus;

use brokk_bifrost_semantic::analyzer::semantic::lowering::completion_label;

use brokk_bifrost_semantic::analyzer::semantic::lowering::formal_multiplicity;

use brokk_bifrost_semantic::analyzer::semantic::service::ProgramSemanticsLowerer;

use brokk_bifrost_semantic::analyzer::semantic::service::SemanticAdapterIdentity;

use brokk_bifrost_analysis::analyzer::semantic::*;

use crate::analyzer::semantic_model::SemanticModelCallApplication;

use crate::analyzer::semantic_model::SemanticModelCallableDisposition;

use crate::analyzer::semantic_model::SemanticModelCallableKey;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use crate::analyzer::semantic_model::SemanticModelOverlayDisposition;

use crate::analyzer::semantic_model::SemanticModelSymbol;

use crate::analyzer::semantic_model::SemanticModelSymbolKind;

use crate::analyzer::semantic_model::TypeRef;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use brokk_bifrost_core::analyzer::tree_walk::WalkControl;

use brokk_bifrost_core::analyzer::tree_walk::try_walk_named_tree_preorder;

use brokk_bifrost_core::analyzer::model::DispatchExtensibility;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::RustAnalyzer;

use crate::analyzer::RustOverlayCrates;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

// Bumping this rotates every public wire id hashed from the adapter
// fingerprint (`SemanticArtifactKey::push_environment_identity`). A checked-in
// golden that embeds one must be re-blessed with `BIFROST_BLESS=1` in the same
// change; the code-query tutorial pages elide such ids (#5016).
// #5911: tuple component establishments and ownership change immutable effects;
// unchanged source must not reuse artifacts that omitted those transfers.
// BrokkAi/tree-sitter-rust#3: grammar 0.24.7 changes inclusive prefix ranges
// from assignments to ranges, changing effects for unchanged source.
const ADAPTER_VERSION: &[u8] = b"rust-value-semantics-v48";
const RUST_REPEAT_ARRAY_ELEMENT_CAP: u128 = 1024;
/// Bound on the reference levels peeled from a method receiver while
/// recovering the written type the call auto-derefs through. Real receiver
/// chains are short, and the bound keeps a pathological chain from walking
/// unbounded.
const RUST_RECEIVER_DEREFERENCE_BOUND: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustMacroCallCandidate {
    Formatting(RustFormattingMacro),
    Logging(RustLoggingMacro),
    Value(RustValueMacro),
}

/// Select Rust's format-argument grammar from the structured macro path. This
/// is only a syntax gate; query-time dispatch still proves the macro identity.
fn rust_macro_call_candidate(path: Node<'_>, source: &str) -> Option<RustMacroCallCandidate> {
    let segments = brokk_bifrost_rust::graph_support::rust_path_segments(path)?;
    let terminal = segments.last()?;
    let name = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(node_text(
        source, *terminal,
    )?);
    if brokk_bifrost_rust::format_args::rust_value_macro(name).is_some() && segments.len() > 1 {
        let owner = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
            node_text(source, segments[0])?,
        );
        if segments.len() != 2 || !matches!(owner, "std" | "core" | "alloc") {
            return None;
        }
    }
    if segments.len() == 2 {
        let owner = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
            node_text(source, segments[0])?,
        );
        if let Some(logging) = brokk_bifrost_rust::format_args::rust_logging_macro(owner, name) {
            return Some(RustMacroCallCandidate::Logging(logging));
        }
    }
    brokk_bifrost_rust::format_args::rust_formatting_macro(name)
        .map(RustMacroCallCandidate::Formatting)
        .or_else(|| {
            brokk_bifrost_rust::format_args::rust_value_macro(name)
                .map(RustMacroCallCandidate::Value)
        })
}

impl_program_semantics_provider!(RustAnalyzer, RustSemanticLowerer);

/// Stateless: Rust lowering is file-local and consults no semantic model.
#[doc(hidden)]
pub struct RustSemanticLowerer;

impl ProgramSemanticsLowerer for RustSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity::for_adapter(
            "rust",
            ADAPTER_VERSION,
            b"rust-intrafile-execution-defaults-v1",
            brokk_bifrost_analysis::analyzer::semantic::lowering::semantic_model_dependency_fingerprint(
                None,
                b"rust-semantic-model-set-v1\0",
            ),
        )
    }

    fn capabilities(&self) -> SemanticCapabilities {
        rust_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        let operand_forest =
            match brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxForest::parse(
                &RUST_STRUCTURAL_SPEC,
                prepared.tree().root_node(),
                prepared.source(),
                budget.limits().nested_entries,
                Some(cancellation),
            ) {
                Ok(forest) => forest,
                Err(
                    brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxStop::Cancelled,
                ) => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: SemanticWork::default(),
                    });
                }
                Err(
                    brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxStop::Exceeded,
                ) => {
                    let limit = budget.limits().nested_entries;
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded: SemanticBudgetExceeded::new(
                            SemanticBudgetDimension::NestedEntries,
                            limit,
                            limit.saturating_add(1),
                        ),
                        work: SemanticWork {
                            nested_entries: limit.saturating_add(1),
                            ..SemanticWork::default()
                        },
                    });
                }
            };
        let operand_nodes = operand_forest
            .trees()
            .iter()
            .map(|tree| {
                let root = tree.root();
                ((root.start_byte(), root.end_byte()), root)
            })
            .collect::<HashMap<_, _>>();
        let mut operand_children: HashMap<usize, Vec<Node<'_>>> = HashMap::default();
        for tree in operand_forest.trees() {
            operand_children
                .entry(tree.anchor)
                .or_default()
                .push(tree.root());
        }
        let (inventory, initial_work) =
            match enumerate_procedures(file, prepared, &operand_forest, budget, cancellation)?
                .into_lowering_input()
            {
                ProcedureLoweringInput::Complete {
                    value,
                    initial_work,
                } => (value, initial_work),
                ProcedureLoweringInput::Stopped(outcome) => return Ok(outcome),
            };

        let RustProcedureInventory {
            specs,
            ownership,
            exported_macro_definitions,
        } = inventory;

        let procedure_targets = specs
            .iter()
            .map(|spec| {
                (
                    spec.callable.id(),
                    RustNestedProcedureTarget {
                        id: spec.id,
                        captures: spec.captures.clone(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        // One file prescan, shared by every procedure: what this file states
        // about its own functions' return types, its struct declarations, and
        // which of those structs run no destructor.
        let facts = rust_file_facts(prepared);
        let mut initial_work = initial_work;
        let structural_node_index = match StructuralNodeIndex::for_source_with_forest(
            &RUST_STRUCTURAL_SPEC,
            prepared,
            &operand_forest,
            budget.limits().nested_entries,
            cancellation,
        )? {
            StructuralNodeIndexOutcome::Complete { index, work_items } => {
                initial_work = initial_work.conservative_add(SemanticWork {
                    nested_entries: work_items,
                    ..SemanticWork::default()
                });
                Some(index)
            }
            StructuralNodeIndexOutcome::Exceeded { .. } => None,
            StructuralNodeIndexOutcome::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: initial_work,
                });
            }
        };
        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(
                    prepared,
                    RustProcedureInputs {
                        facts: &facts,
                        ownership: &ownership,
                        exported_macro_definitions: &exported_macro_definitions,
                        procedure_targets: &procedure_targets,
                        structural_node_index: structural_node_index.as_ref(),
                        operand_nodes: &operand_nodes,
                        operand_children: &operand_children,
                    },
                    spec,
                    staged_budget,
                    cancellation,
                )
            },
        )
    }
}

fn rust_capabilities() -> SemanticCapabilities {
    let mut builder = crate::analyzer::semantic::capabilities::tree_sitter_adapter_capabilities();
    for capability in [
        // Same-file `static` reads have an exact declaration-backed location;
        // references this adapter cannot resolve retain a local structured gap.
        SemanticCapability::StaticMemory,
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
    ] {
        builder = builder.partial(capability);
    }
    // FieldMemory and IndexMemory stay partial: a field or element store and
    // load is lowered into a real memory row whenever the place is a single
    // selector or a single constant index over a value this procedure can
    // name (#2667). Unsupported targets keep their structured gaps.
    // GuardFacts stays partial: this adapter publishes guard rows for built-in primitive
    // comparisons, Boolean truth tests, literal conditions, and structured
    // integer comparisons with an integer literal or unambiguous same-file
    // top-level const bound. An absent normalized predicate remains opaque
    // because a non-primitive Rust operator may dispatch to user code (#2443).
    builder.build()
}

#[derive(Clone)]
struct ProcedureSpec<'tree> {
    id: ProcedureId,
    body: Node<'tree>,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    callable: Node<'tree>,
    captures: Box<[RustCaptureSpec<'tree>]>,
}

#[derive(Clone)]
struct RustCaptureSpec<'tree> {
    name: Box<str>,
    declaration_start: usize,
    reference: Node<'tree>,
    mode: CaptureMode,
}

#[derive(Clone)]
struct RustNestedProcedureTarget<'tree> {
    id: ProcedureId,
    captures: Box<[RustCaptureSpec<'tree>]>,
}

struct RustProcedureInventory<'tree> {
    specs: Vec<ProcedureSpec<'tree>>,
    ownership: RustOwnershipIndex<'tree, 'tree>,
    exported_macro_definitions: ExportedMacroDefinitions<'tree>,
}

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<RustProcedureInventory<'tree>>;

fn enumerate_procedures<'tree>(
    file: &ProjectFile,
    prepared: &'tree PreparedSyntaxTree,
    forest: &'tree brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxForest,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureEnumeration<'tree>, SemanticProviderError> {
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "rust-source", budget)?;
    let mut charge_ownership = |entries| {
        if cancellation.is_cancelled() {
            return Err(None);
        }
        inventory
            .observe_additional_work(SemanticWork {
                nested_entries: entries,
                ..SemanticWork::default()
            })
            .map_err(Some)
    };
    let ownership = match RustOwnershipIndex::build(root, prepared.source(), &mut charge_ownership)
        .and_then(|mut ownership| {
            ownership.register_embedded_syntax(forest, &mut charge_ownership)?;
            Ok(ownership)
        }) {
        Ok(ownership) => ownership,
        Err(Some(stop)) => return Ok(stop.into_outcome()),
        Err(None) => return Ok(inventory.cancelled()),
    };
    let root_path = inventory.root_path();
    let mut macro_definition_candidates = Vec::new();
    let mut specs = match walk_procedure_tree(
        root,
        root_path,
        &mut inventory,
        cancellation,
        named_children,
        |frame, inventory| {
            if frame.node.kind() == "macro_definition" {
                macro_definition_candidates.push(frame.node);
            }
            let mut container_body = None;
            if let Some(segment_kind) = declaration_container_kind(frame.node) {
                let name = declaration_container_name(prepared.source(), frame.node);
                let anchor = source_anchor(frame.node, 0)
                    .map_err(SemanticProviderError::invalid_identity)?;
                let container_path = inventory.push_container(
                    frame.declaration_path,
                    segment_kind,
                    name.as_deref(),
                    anchor,
                )?;
                if let Some(body) = frame.node.child_by_field_name("body") {
                    container_body = Some((body.id(), container_path));
                }
            }
            let mut callable_body = None;
            let value = if let Some((kind, segment_kind, body, properties)) =
                callable_shape(frame.node, frame.lexical_parent)
            {
                let name = callable_name(prepared.source(), frame.node);
                let anchor = source_anchor(frame.node, 0)
                    .map_err(SemanticProviderError::invalid_identity)?;
                let identity = match inventory.allocate_procedure(
                    frame.declaration_path,
                    segment_kind,
                    name.as_deref(),
                    anchor,
                )? {
                    Ok(identity) => identity,
                    Err(stop) => return Ok(ProcedureWalkStep::ExceededBudget(stop)),
                };
                callable_body = Some((body.id(), identity.id, identity.declaration_path));
                Some(ProcedureSpec {
                    id: identity.id,
                    body,
                    locator: identity.locator,
                    lexical_parent: frame.lexical_parent,
                    kind,
                    properties,
                    callable: frame.node,
                    captures: Box::new([]),
                })
            } else {
                None
            };
            Ok(ProcedureWalkStep::Continue {
                value,
                scopes: ProcedureWalkScopes {
                    container_body,
                    callable_body,
                },
            })
        },
    )? {
        ProcedureTreeWalkOutcome::Complete(specs) => specs,
        ProcedureTreeWalkOutcome::ExceededBudget(stop) => return Ok(stop.into_outcome()),
        ProcedureTreeWalkOutcome::Cancelled => return Ok(inventory.cancelled()),
    };

    match populate_rust_capture_specs(&mut specs, prepared.source(), &mut inventory, cancellation) {
        Ok(()) => {}
        Err(RustCapturePrepassStop::Budget(stop)) => return Ok(stop.into_outcome()),
        Err(RustCapturePrepassStop::Cancelled) => return Ok(inventory.cancelled()),
    }
    let exported_macro_definitions =
        ExportedMacroDefinitions::from_candidates(macro_definition_candidates, prepared.source());
    Ok(inventory.complete(RustProcedureInventory {
        specs,
        ownership,
        exported_macro_definitions,
    }))
}

enum RustCapturePrepassStop {
    Budget(crate::analyzer::semantic::inventory::ProcedureInventoryStop),
    Cancelled,
}

/// Resolve closure free variables through the existing lexical scopes. Captures
/// crossing another closure are relayed through each intervening environment.
fn populate_rust_capture_specs<'tree>(
    specs: &mut [ProcedureSpec<'tree>],
    source: &str,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), RustCapturePrepassStop> {
    let mut captures =
        vec![HashMap::<(Box<str>, usize), RustCaptureSpec<'tree>>::default(); specs.len()];
    for child_index in 0..specs.len() {
        let child = &specs[child_index];
        if !is_rust_closure_callable(child.callable) {
            continue;
        }
        let mut pending = Vec::new();
        try_walk_named_tree_preorder(child.body, true, |node| {
            if cancellation.is_cancelled() {
                return Err(RustCapturePrepassStop::Cancelled);
            }
            inventory
                .charge_traversal_entry()
                .map_err(RustCapturePrepassStop::Budget)?;
            if node.id() != child.body.id() && is_rust_nested_execution_boundary(node) {
                return Ok(WalkControl::SkipChildren);
            }
            if !matches!(node.kind(), "identifier" | "self") {
                return Ok(WalkControl::Continue);
            }
            let Some(name) = node_text(source, node) else {
                return Ok(WalkControl::Continue);
            };
            let Some(binding) = resolve_lexical_binding_from_focus(
                Language::Rust,
                node,
                source,
                node.start_byte(),
                name,
            ) else {
                return Ok(WalkControl::Continue);
            };
            let definition = match binding {
                LexicalBindingResolution::Parameter(definition)
                | LexicalBindingResolution::OtherLocal(definition) => definition,
            };
            if child.callable.start_byte() <= definition.declaration_range.start_byte
                && definition.declaration_range.end_byte <= child.callable.end_byte()
            {
                return Ok(WalkControl::Continue);
            }
            let Some(owner) = specs
                .iter()
                .filter(|candidate| {
                    candidate.callable.start_byte() <= definition.declaration_range.start_byte
                        && definition.declaration_range.end_byte <= candidate.callable.end_byte()
                })
                .min_by_key(|candidate| {
                    candidate.callable.end_byte() - candidate.callable.start_byte()
                })
                .map(|candidate| candidate.id)
            else {
                return Ok(WalkControl::Continue);
            };
            pending.push((
                Box::<str>::from(name),
                definition.name_range.start_byte,
                node,
                owner,
            ));
            Ok(WalkControl::Continue)
        })?;

        for (name, declaration_start, reference, owner) in pending {
            let mut target_id = child.id;
            while target_id != owner {
                let target = specs
                    .iter()
                    .find(|candidate| candidate.id == target_id)
                    .expect("lexical parent procedure id resolves within this file");
                if !is_rust_closure_callable(target.callable) {
                    break;
                }
                let mode = rust_capture_mode(target.callable, reference);
                let capture = RustCaptureSpec {
                    name: name.clone(),
                    declaration_start,
                    reference,
                    mode,
                };
                captures[target_id.index()]
                    .entry((name.clone(), declaration_start))
                    .and_modify(|existing| {
                        if existing.mode != capture.mode {
                            existing.mode = CaptureMode::Unknown;
                        }
                    })
                    .or_insert(capture);
                let Some(parent) = target.lexical_parent else {
                    break;
                };
                target_id = parent;
            }
        }
    }

    for spec in specs {
        let mut procedure_captures = captures[spec.id.index()]
            .drain()
            .map(|(_, capture)| capture)
            .collect::<Vec<_>>();
        procedure_captures.sort_by_key(|capture| (capture.declaration_start, capture.name.clone()));
        spec.captures = procedure_captures.into_boxed_slice();
    }
    Ok(())
}

fn is_rust_closure_callable(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "closure_expression" | "async_block" | "gen_block"
    )
}

fn rust_capture_mode(callable: Node<'_>, reference: Node<'_>) -> CaptureMode {
    if direct_child_kind(callable, "move") {
        return CaptureMode::Move;
    }
    if rust_capture_use_may_mutate(reference, callable) {
        return CaptureMode::Unknown;
    }
    CaptureMode::LanguageDefined("rust_shared_borrow".into())
}

fn rust_capture_use_may_mutate(reference: Node<'_>, callable: Node<'_>) -> bool {
    let mut current = reference;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "assignment_expression" | "compound_assignment_expr"
        ) && parent
            .child_by_field_name("left")
            .is_some_and(|left| rust_node_contains(left, reference))
        {
            return true;
        }
        if parent.kind() == "reference_expression"
            && direct_named_child_kind(parent, "mutable_specifier").is_some()
            && parent
                .child_by_field_name("value")
                .is_some_and(|value| rust_node_contains(value, reference))
        {
            return true;
        }
        if parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| rust_node_contains(function, reference))
        {
            return true;
        }
        if parent.id() == callable.id() {
            break;
        }
        current = parent;
    }
    false
}

fn rust_node_contains(ancestor: Node<'_>, target: Node<'_>) -> bool {
    let mut current = target;
    while let Some(parent) = current.parent() {
        if parent.id() == ancestor.id() {
            return true;
        }
        current = parent;
    }
    ancestor.id() == target.id()
}

fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "mod_item" => Some(DeclarationSegmentKind::Namespace),
        "trait_item" | "impl_item" => Some(DeclarationSegmentKind::Type),
        _ => None,
    }
}

fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    match node.kind() {
        "mod_item" | "trait_item" => node
            .child_by_field_name("name")
            .map(|name| rust_node_text(name, source).trim())
            .filter(|name| !name.is_empty())
            .map(Box::<str>::from),
        "impl_item" => impl_target_owner_name(source, node),
        _ => None,
    }
}

fn impl_target_owner_name(source: &str, impl_item: Node<'_>) -> Option<Box<str>> {
    let target = impl_item.child_by_field_name("type")?;
    if !is_nominal_impl_target_shape(target) {
        return None;
    }
    let path = rust_nominal_type_path(target, source)?;
    if path
        .first()
        .is_some_and(|name| impl_declares_type_parameter(impl_item, source, name))
    {
        return None;
    }
    Some(path.join(".").into_boxed_str())
}

fn is_nominal_impl_target_shape(node: Node<'_>) -> bool {
    match node.kind() {
        "identifier" | "type_identifier" => true,
        "generic_type" => node
            .child_by_field_name("type")
            .is_some_and(is_nominal_impl_target_shape),
        "scoped_identifier" | "scoped_type_identifier" => {
            node.child_by_field_name("name")
                .is_some_and(|name| matches!(name.kind(), "identifier" | "type_identifier"))
                && node
                    .child_by_field_name("path")
                    .is_none_or(is_nominal_impl_target_path)
        }
        _ => false,
    }
}

fn is_nominal_impl_target_path(node: Node<'_>) -> bool {
    match node.kind() {
        "crate" | "self" | "super" | "identifier" | "type_identifier" => true,
        "scoped_identifier" | "scoped_type_identifier" => {
            node.child_by_field_name("name")
                .is_some_and(|name| matches!(name.kind(), "identifier" | "type_identifier"))
                && node
                    .child_by_field_name("path")
                    .is_none_or(is_nominal_impl_target_path)
        }
        _ => false,
    }
}

fn impl_declares_type_parameter(impl_item: Node<'_>, source: &str, target: &str) -> bool {
    let Some(parameters) = impl_item.child_by_field_name("type_parameters") else {
        return false;
    };
    named_children(parameters).into_iter().any(|parameter| {
        parameter.kind() == "type_parameter"
            && parameter
                .child_by_field_name("name")
                .is_some_and(|name| rust_node_text(name, source).trim() == target)
    })
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    brokk_bifrost_semantic::analyzer::semantic::lowering::callable_name_with_binding(
        source,
        node,
        || enclosing_let_name(source, node),
    )
}

fn enclosing_let_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => value = parent,
            "let_declaration" if field_matches(parent, "value", value) => {
                return parent
                    .child_by_field_name("pattern")
                    .and_then(single_binding_identifier)
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            _ => return None,
        }
    }
}

fn single_binding_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" => return Some(node),
            "mut_pattern" | "ref_pattern" | "captured_pattern" => {
                let children = named_children(node);
                if children.len() != 1 {
                    return None;
                }
                node = children[0];
            }
            _ => return None,
        }
    }
}

fn callable_shape<'tree>(
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    let (kind, segment_kind, body, is_async, is_generator, is_static) = match node.kind() {
        "function_item" => {
            let is_method = lexical_parent.is_none() && has_impl_or_trait_parent(node);
            let (kind, segment_kind) = if lexical_parent.is_some() {
                (
                    ProcedureKind::LocalFunction,
                    DeclarationSegmentKind::LocalFunction,
                )
            } else if is_method {
                (ProcedureKind::Method, DeclarationSegmentKind::Method)
            } else {
                (ProcedureKind::Function, DeclarationSegmentKind::Function)
            };
            (
                kind,
                segment_kind,
                node.child_by_field_name("body")?,
                function_is_async(node),
                false,
                is_method && !function_has_self_parameter(node),
            )
        }
        "closure_expression" => (
            ProcedureKind::Closure,
            DeclarationSegmentKind::Closure,
            node.child_by_field_name("body")?,
            direct_child_kind(node, "async"),
            false,
            false,
        ),
        "async_block" => (
            ProcedureKind::Closure,
            DeclarationSegmentKind::AnonymousCallable,
            first_named_child(node)?,
            true,
            false,
            false,
        ),
        "gen_block" => (
            ProcedureKind::Closure,
            DeclarationSegmentKind::AnonymousCallable,
            first_named_child(node)?,
            false,
            true,
            false,
        ),
        _ => return None,
    };
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async,
            is_generator,
            is_static,
            is_synthetic: false,
            invocation: if is_async || is_generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            },
            dispatch_extensibility: if node.kind() == "function_item" {
                rust_callable_dispatch_extensibility(node)
            } else {
                DispatchExtensibility::Closed
            },
            call_boundary: ProcedureCallBoundary::Direct,
            receiver_binding: Default::default(),
            construction_return: Default::default(),
        },
    ))
}

fn has_impl_or_trait_parent(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "impl_item" | "trait_item" => return true,
            "function_item" | "closure_expression" | "source_file" => return false,
            _ => node = parent,
        }
    }
    false
}

fn function_is_async(node: Node<'_>) -> bool {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "function_modifiers")
        .is_some_and(|modifiers| direct_child_kind(modifiers, "async"))
}

fn function_has_self_parameter(node: Node<'_>) -> bool {
    node.child_by_field_name("parameters")
        .map(named_children)
        .is_some_and(|parameters| {
            parameters
                .into_iter()
                .any(|parameter| parameter.kind() == "self_parameter")
        })
}

type RustLoweringError = ProcedureLoweringError;

type EdgeTarget = ControlTarget;

type Work<'tree> = ProcedureWork<'tree>;

struct ScopedNodeSchedule<'schedule, 'tree> {
    children: &'schedule [Node<'tree>],
    entries: &'schedule [ProgramPointId],
    scopes: &'schedule [ScopeFrameId],
}

#[derive(Clone, Copy)]
enum RustAssignmentTarget {
    Binding(ValueId),
    Memory {
        kind: MemoryAccessKind,
        location: MemoryLocationId,
    },
    Unsupported,
}

struct LoweringContext<'tree, 'targets> {
    source_root: Node<'tree>,
    source: &'tree str,
    operand_children: &'targets HashMap<usize, Vec<Node<'tree>>>,
    operand_nodes: &'targets HashMap<(usize, usize), Node<'tree>>,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding<'tree>>>,
    captured_bindings: HashMap<Box<str>, ValueId>,
    captured_binding_sources: HashMap<(Box<str>, usize), ValueId>,
    procedure_targets: &'targets HashMap<usize, RustNestedProcedureTarget<'tree>>,
    /// Exact declared or structurally inferred type evidence for bindings.
    value_types: HashMap<ValueId, RustValueType<'tree>>,
    /// Primitive scalar types that make comparison and Boolean truth tests
    /// built in for this procedure.
    scalar_types: HashMap<ValueId, DeclaredScalarType>,
    /// Complete source-owned Copy proofs, retained only for this procedure's
    /// lowering. Inert-drop facts are not ownership proofs.
    proven_copies: HashMap<ValueId, TransferKind>,
    /// Complete tuple-let plans from preindex, consumed at their binding point.
    /// These borrowed nodes and vectors die with this lowering invocation.
    tuple_lets: HashMap<usize, Result<RustTupleLetProof<'tree>, RustOwnershipIncomplete>>,
    return_type: Option<Node<'tree>>,
    procedure_body: Node<'tree>,
    function_scope: ScopeFrameId,
    normal_exit: ProgramPointId,
    exceptional_exit: ProgramPointId,
    cleanup_gap_exit_points: HashSet<ProgramPointId>,
    definitely_non_dropping: HashSet<ValueId>,
    /// What this file states about its own functions, structs, and destructors.
    facts: &'targets RustFileFacts<'tree>,
    ownership: &'targets RustOwnershipIndex<'tree, 'tree>,
    exported_macro_definitions: &'targets ExportedMacroDefinitions<'tree>,
    structural_node_index: Option<&'targets StructuralNodeIndex>,
    /// The struct or array shape each value provably holds, which is what lets
    /// a field or index place name a memory location this procedure owns.
    value_shapes: HashMap<ValueId, RustValueShape>,
    /// One value per distinct constant index magnitude, so equivalent integer
    /// literal spellings name the same index value.
    constant_index_values: HashMap<u128, ValueId>,
    /// Materialized same-file static locations, keyed by declaration name byte.
    static_locations: HashMap<usize, MemoryLocationId>,
    receiver: Option<ValueId>,
    next_cleanup_region: usize,
    /// Cleanup regions whose droppable values are only parameters or direct
    /// `let` bindings: the parameter region and lexical block regions.
    binding_cleanup_regions: HashSet<CleanupRegionId>,
    cleanup_nodes: HashMap<CleanupRegionId, Node<'tree>>,
    binding_nodes: HashMap<ValueId, Node<'tree>>,
    binding_places: HashMap<ValueId, SemanticPlace>,
    cleanup_places_by_binding: HashMap<ValueId, Vec<SemanticPlace>>,
    cleanup_owners_by_region: HashMap<CleanupRegionId, Vec<ValueId>>,
    binding_metadata: HashMap<ValueId, PointMetadata>,
    binding_scopes: HashMap<ValueId, (usize, usize, usize)>,
    cleanup_drop_incompletes: HashMap<SemanticPlace, LifecycleIncompleteReason>,
    parameter_values: Vec<ValueId>,
    move_outs: Vec<MoveOutFact>,
    pointer_origins: Vec<PointerOrigin>,
    pointer_aliases: Vec<PointerAlias>,
    pointer_accesses: Vec<PointerAccess>,
    pointer_invalidations: Vec<PointerInvalidation>,
    owner_lifetime_end_points: HashSet<(ValueId, ProgramPointId)>,
    incomplete_facts: Vec<SemanticIncompleteFact>,
    pointer_origins_by_place: HashMap<SemanticPlace, PointerOriginId>,
    pointer_origins_by_owner: HashMap<ValueId, PointerOriginId>,
    pointer_owner_lifetimes:
        HashMap<ValueId, (PointerInvalidationTarget, PointerInvalidationCause)>,
    manually_drop_values: HashSet<ValueId>,
    pointer_origins_by_pointer: HashMap<ValueId, Vec<(PointerOriginId, PointerByteOffset)>>,
    pointer_pointees_by_value: HashMap<ValueId, RustPointerPointee<'tree>>,
    pointer_fact_targets_by_source: HashMap<ValueId, Vec<PendingPointerFactTransfer>>,
}

impl<'tree, 'targets> ProcedureWorkHandler<'tree> for LoweringContext<'tree, 'targets> {
    fn cancellation_token(&self) -> &CancellationToken {
        self.session.cancellation()
    }

    fn lower_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: ControlTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<ProcedureWork<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let node = unwrap_attributes(node);
        self.session.record_statement_entry(builder, node, entry)?;
        self.statement(builder, node, entry, next, scope, stack)
    }

    fn lower_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: ControlTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<ProcedureWork<'tree>>,
    ) -> Result<(), RustLoweringError> {
        self.expression(builder, unwrap_attributes(node), entry, next, scope, stack)
    }

    fn lower_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        targets: ConditionTargets,
        scope: ScopeFrameId,
        stack: &mut Vec<ProcedureWork<'tree>>,
    ) -> Result<(), RustLoweringError> {
        self.condition(
            builder,
            unwrap_attributes(node),
            entry,
            targets.when_true,
            targets.when_false,
            scope,
            stack,
        )
    }
}

/// The shape a value provably holds, as far as one file can state it.
///
/// Only two shapes matter to the heap stratum: a value of a struct this file
/// declares, whose field declarations then identify a `Field` location and
/// prove the projection needs no user `Deref`; and a fixed-size array, whose
/// subscript is the language's own indexing rather than an `Index`
/// implementation. Anything else has no shape here and keeps its gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RustValueShape {
    Struct(Box<str>),
    Array { primitive_elements: bool },
}

#[derive(Debug, Clone, Copy)]
enum RustValueType<'tree> {
    Declared(Node<'tree>),
    Borrowed {
        mutable: bool,
        referent: Node<'tree>,
    },
}

#[derive(Debug, Clone, Copy)]
enum RustPointerPointee<'tree> {
    Type(Node<'tree>),
    Byte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingPointerFactTransfer {
    target: ValueId,
    point: ProgramPointId,
    metadata: PointMetadata,
}

struct RustNormalizedGuard {
    predicate: GuardPredicate,
    subject: Option<ValueId>,
    predicate_true_on_condition_true: bool,
}

#[derive(Debug, Clone, Copy)]
enum RustTypeOperation {
    Dereference,
    Borrow { mutable: bool },
}

#[derive(Debug, Clone, Copy)]
struct LocalBinding<'tree> {
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
    initializer: Option<Node<'tree>>,
}

#[derive(Clone, Copy)]
enum RustTupleComponentSource<'tree> {
    Literal(Node<'tree>),
    Field {
        aggregate: Node<'tree>,
        ordinal: usize,
    },
}

#[derive(Clone, Copy)]
struct RustTupleComponentProof<'tree> {
    binding: Node<'tree>,
    source: RustTupleComponentSource<'tree>,
    ty: Option<Node<'tree>>,
    copy: TransferKind,
}

struct RustTupleLetProof<'tree> {
    pattern: Node<'tree>,
    components: Vec<RustTupleComponentProof<'tree>>,
}

struct RustProcedureInputs<'inputs, 'tree> {
    facts: &'inputs RustFileFacts<'tree>,
    ownership: &'inputs RustOwnershipIndex<'tree, 'tree>,
    exported_macro_definitions: &'inputs ExportedMacroDefinitions<'tree>,
    procedure_targets: &'inputs HashMap<usize, RustNestedProcedureTarget<'tree>>,
    structural_node_index: Option<&'inputs StructuralNodeIndex>,
    operand_children: &'inputs HashMap<usize, Vec<Node<'tree>>>,
    operand_nodes: &'inputs HashMap<(usize, usize), Node<'tree>>,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    inputs: RustProcedureInputs<'_, 'tree>,
    spec: &ProcedureSpec<'tree>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), RustLoweringError> {
    let RustProcedureInputs {
        facts,
        ownership,
        exported_macro_definitions,
        procedure_targets,
        structural_node_index,
        operand_nodes,
        operand_children,
    } = inputs;
    let mut parts = ProcedureSemanticsParts::new(
        spec.id,
        spec.locator.clone(),
        spec.kind,
        SourceMappingId::new(0),
        EvidenceId::new(0),
    );
    parts.lexical_parent = spec.lexical_parent;
    parts.properties = spec.properties;
    let ProcedureLoweringStart {
        mut builder,
        session,
        entry,
        normal_exit,
        exceptional_exit,
        function_scope,
    } = ProcedureLoweringSession::start(parts, budget, cancellation)?;
    let mut context = LoweringContext {
        source: prepared.source(),
        source_root: prepared.tree().root_node(),
        operand_nodes,
        operand_children,
        session,
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        captured_bindings: HashMap::default(),
        captured_binding_sources: HashMap::default(),
        procedure_targets,
        value_types: HashMap::default(),
        scalar_types: HashMap::default(),
        proven_copies: HashMap::default(),
        tuple_lets: HashMap::default(),
        return_type: spec.callable.child_by_field_name("return_type"),
        procedure_body: spec.body,
        function_scope,
        normal_exit,
        exceptional_exit,
        cleanup_gap_exit_points: HashSet::default(),
        definitely_non_dropping: HashSet::default(),
        facts,
        ownership,
        exported_macro_definitions,
        structural_node_index,
        value_shapes: HashMap::default(),
        constant_index_values: HashMap::default(),
        static_locations: HashMap::default(),
        receiver: None,
        next_cleanup_region: 0,
        binding_cleanup_regions: HashSet::default(),
        cleanup_nodes: HashMap::default(),
        binding_nodes: HashMap::default(),
        binding_places: HashMap::default(),
        cleanup_places_by_binding: HashMap::default(),
        cleanup_owners_by_region: HashMap::default(),
        binding_metadata: HashMap::default(),
        binding_scopes: HashMap::default(),
        cleanup_drop_incompletes: HashMap::default(),
        parameter_values: Vec::new(),
        move_outs: Vec::new(),
        pointer_origins: Vec::new(),
        pointer_aliases: Vec::new(),
        pointer_accesses: Vec::new(),
        pointer_invalidations: Vec::new(),
        owner_lifetime_end_points: HashSet::default(),
        incomplete_facts: Vec::new(),
        pointer_origins_by_place: HashMap::default(),
        pointer_origins_by_owner: HashMap::default(),
        pointer_owner_lifetimes: HashMap::default(),
        manually_drop_values: HashSet::default(),
        pointer_origins_by_pointer: HashMap::default(),
        pointer_pointees_by_value: HashMap::default(),
        pointer_fact_targets_by_source: HashMap::default(),
    };
    context.emit_procedure_inputs(&mut builder, entry, spec.callable)?;
    context.emit_capture_inputs(&mut builder, entry, spec)?;
    let body_scope = if !context.parameter_values.is_empty() {
        context.next_cleanup_region = 1;
        let region = CleanupRegionId::new(0);
        let parameter_scope =
            builder.push_scope(Some(function_scope), ScopeBinding::Cleanup { region });
        let parameter_source = context
            .parameter_values
            .first()
            .and_then(|value| context.binding_nodes.get(value))
            .copied()
            .unwrap_or(spec.callable);
        context.cleanup_nodes.insert(region, parameter_source);
        let has_cleanup_actions = context.register_binding_cleanup_actions(
            &mut builder,
            parameter_scope,
            region,
            &context.parameter_values.clone(),
            entry,
        )?;
        if has_cleanup_actions {
            context.binding_cleanup_regions.insert(region);
            parameter_scope
        } else {
            function_scope
        }
    } else {
        function_scope
    };
    context.emit_local_bindings(&mut builder, spec.body)?;

    if spec.properties.is_async {
        context.session.record_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "invoking this async Rust callable creates a deferred future; polling and executor scheduling are not stitched into control flow",
        )?;
    }
    if spec.properties.is_generator {
        context.session.record_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "invoking this generator block creates deferred resumable state; construction and resumption are not stitched into control flow",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let return_source = if spec.body.kind() == "block" {
        block_tail_expression(spec.body)
    } else {
        Some(spec.body)
    };
    let body_next = if let Some(return_source) = return_source {
        let implicit_return = context.point(&mut builder, spec.body, Vec::new())?;
        let source = context.expression_value(
            &mut builder,
            return_source,
            expression_value_kind(return_source),
        )?;
        let transferred =
            context.value(&mut builder, implicit_return, SemanticValueKind::Temporary)?;
        let return_value =
            context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
        context.append_ownership_transfer(
            &mut builder,
            implicit_return,
            return_source,
            source,
            transferred,
            context.return_type.map(RustValueType::Declared),
        )?;
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                source: transferred,
                target: return_value,
            },
        )?;
        if !rust_expression_has_direct_value_evidence(return_source) {
            context.session.record_gap(
                &mut builder,
                implicit_return,
                SemanticGapSubject::Value(return_value),
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "tail-expression result transfer requires value refinement",
            )?;
        }
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ProcedureReturn {
                value: Some(return_value),
            },
        )?;
        if body_scope == function_scope {
            context.session.add_target_edge(
                &mut builder,
                implicit_return,
                EdgeTarget::normal(normal_exit),
            )?;
        } else if let Some(route) = builder.resolve_completion(
            body_scope,
            &CompletionRequest::new(CompletionKind::Return, None),
        ) {
            context.route(&mut builder, implicit_return, &route)?;
        } else {
            return Err(RustLoweringError::Invalid(
                "normal Rust return has no function cleanup continuation".into(),
            ));
        }
        EdgeTarget::normal(implicit_return)
    } else {
        EdgeTarget::normal(normal_exit)
    };
    let initial = if spec.body.kind() == "block" {
        Work::Statement {
            node: spec.body,
            entry: body_entry,
            next: body_next,
            scope: body_scope,
        }
    } else {
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: body_next,
            scope: body_scope,
        }
    };
    let mut pending = vec![initial];
    context
        .session
        .add_target_edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

    let (mut parts, mut work) = drive_and_finish_procedure(
        builder,
        pending.drain(..).rev(),
        entry,
        normal_exit,
        exceptional_exit,
        cancellation,
        |builder, work, stack| dispatch_procedure_work(&mut context, builder, work, stack),
    )?;
    for (owner, point) in &context.owner_lifetime_end_points {
        let point = *point;
        let place = context
            .binding_places
            .get(owner)
            .expect("every cleanup owner has a tracked binding place");
        let metadata = *context
            .binding_metadata
            .get(owner)
            .expect("every cleanup owner has binding source evidence");
        let scope_end_at = ScopeEndAt::Point(point);
        if context.pointer_origins_by_place.contains_key(place)
            && !context.cleanup_places_by_binding.contains_key(owner)
            && !parts
                .scope_ends
                .iter()
                .any(|scope_end| &scope_end.place == place && scope_end.at == scope_end_at)
        {
            parts.scope_ends.push(ScopeEndFact {
                place: place.clone(),
                at: scope_end_at,
                source: metadata.source,
                evidence: metadata.evidence,
            });
        }
        let invalidation = context.owner_invalidation(*owner);
        if !context.value_is_manually_drop(*owner)
            && let Some((target, cause)) = invalidation
        {
            context.pointer_invalidations.push(PointerInvalidation {
                point,
                target,
                cause,
                strength: PointerRelationStrength::Must,
                source: metadata.source,
                evidence: metadata.evidence,
            });
        }
    }
    let partial_evidence_reason = "Rust semantic evidence is partial at a typed incomplete fact";
    let mut partial_evidence_count = 0_usize;
    let mut partial_evidence_by_source_reason = HashMap::default();
    for fact in &mut context.incomplete_facts {
        let key = (fact.source, fact.reason);
        let evidence = *partial_evidence_by_source_reason
            .entry(key)
            .or_insert_with(|| {
                let id = EvidenceId::try_from_index(parts.evidence_rows.len())
                    .expect("Rust incomplete evidence IDs fit the validated dense-ID domain");
                parts.evidence_rows.push(Evidence {
                    id,
                    proof: ProofStatus::Proven,
                    completeness: EvidenceCompleteness::Partial(partial_evidence_reason.into()),
                    sources: Box::new([fact.source]),
                });
                partial_evidence_count += 1;
                id
            });
        fact.evidence = evidence;
    }
    let pointer_rows = context
        .pointer_origins
        .len()
        .saturating_add(context.pointer_aliases.len())
        .saturating_add(context.pointer_accesses.len())
        .saturating_add(context.pointer_invalidations.len())
        .saturating_add(context.incomplete_facts.len())
        .saturating_add(context.move_outs.len());
    parts.pointer_origins.extend(context.pointer_origins);
    parts.pointer_aliases.extend(context.pointer_aliases);
    parts.pointer_accesses.extend(context.pointer_accesses);
    parts
        .pointer_invalidations
        .extend(context.pointer_invalidations);
    parts.incomplete_facts.extend(context.incomplete_facts);
    parts.move_outs.extend(context.move_outs);
    work = work.conservative_add(SemanticWork {
        evidence: partial_evidence_count,
        owned_text_bytes: partial_evidence_count.saturating_mul(partial_evidence_reason.len()),
        nested_entries: pointer_rows.saturating_add(partial_evidence_count),
        ..SemanticWork::default()
    });
    Ok((parts, work))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn emit_capture_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        spec: &ProcedureSpec<'tree>,
    ) -> Result<(), RustLoweringError> {
        let Some(lexical_parent) = spec.lexical_parent else {
            debug_assert!(spec.captures.is_empty());
            return Ok(());
        };
        for (index, capture) in spec.captures.iter().enumerate() {
            let metadata = self.value_mapping(builder, capture.reference)?;
            let value = self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Local,
            )?;
            let location = self.session.add_memory_location(
                builder,
                entry,
                MemoryLocationKind::Capture {
                    lexical_parent,
                    binding: Some(value),
                },
            )?;
            let expected = MemoryLocationId::try_from_index(index)
                .map_err(|_| RustLoweringError::Invalid("too many Rust captures".into()))?;
            if location != expected {
                return Err(RustLoweringError::Invalid(format!(
                    "Rust capture destination must be {expected}, allocated {location}"
                )));
            }
            self.append_effect(
                builder,
                entry,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Capture,
                    location,
                    result: value,
                },
            )?;
            self.captured_bindings.insert(capture.name.clone(), value);
            self.captured_binding_sources
                .insert((capture.name.clone(), capture.declaration_start), value);
        }
        Ok(())
    }

    fn emit_procedure_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        callable: Node<'tree>,
    ) -> Result<(), RustLoweringError> {
        let layout = formal_parameter_slots_for_owner(Language::Rust, callable, self.source)
            .unwrap_or_default();
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            if self.session.cancellation().is_cancelled() {
                return Err(RustLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            let node = callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(callable);
            let metadata = self.value_mapping(builder, node)?;
            let place = self.local_binding_place(builder, metadata.source);
            let parameter_name = slot.unique_name().map(Box::<str>::from);
            let passing_mode = slot.passing_mode;
            let value = if slot.receiver {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Receiver { dispatch: true },
                )?;
                self.receiver = Some(value);
                value
            } else {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Parameter {
                        ordinal,
                        multiplicity: formal_multiplicity(slot.variadic),
                        name: parameter_name,
                        passing_mode,
                    },
                )?;
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or_else(|| RustLoweringError::Invalid("too many parameters".into()))?;
                value
            };
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.binding_places.entry(value)
            {
                entry.insert(place);
                self.binding_metadata.insert(value, metadata);
                self.binding_nodes.insert(value, node);
                self.parameter_values.push(value);
                let body = callable.child_by_field_name("body").unwrap_or(callable);
                self.binding_scopes.insert(
                    value,
                    (body.start_byte(), body.start_byte(), body.end_byte()),
                );
            }
            if rust_parameter_is_definitely_non_dropping(node) {
                self.definitely_non_dropping.insert(value);
            }
            if node
                .child_by_field_name("type")
                .is_some_and(|type_node| type_node.kind() == "pointer_type")
            {
                self.add_incomplete_fact(
                    entry,
                    SemanticIncompleteSubject::Value(value),
                    SemanticIncompleteReason::Pointer(PointerIncompleteReason::RawPointerType),
                    metadata,
                );
            }
            // The declared parameter type states the shape directly. A
            // receiver declares none, so it takes the shape of the type its
            // enclosing `impl` block names.
            let declared_type = if slot.receiver {
                rust_impl_self_type(callable)
            } else {
                node.child_by_field_name("type")
            };
            if let Some(declared_type) = declared_type {
                let value_type = if slot.receiver && direct_child_kind(node, "&") {
                    RustValueType::Borrowed {
                        mutable: direct_named_child_kind(node, "mutable_specifier").is_some(),
                        referent: declared_type,
                    }
                } else {
                    RustValueType::Declared(declared_type)
                };
                self.value_types.insert(value, value_type);
                let whole_binding = slot.receiver
                    || if let Some(pattern) = node.child_by_field_name("pattern") {
                        self.flat_value_binding_name(builder, pattern)?.is_some()
                    } else {
                        false
                    };
                if whole_binding
                    && matches!(value_type, RustValueType::Declared(_))
                    && let Ok(copy) = self.prove_type_copy(builder, declared_type)?
                {
                    // This runs before parameter cleanup registration. A source-
                    // owned Copy proof excludes user Drop, including aliases.
                    self.retain_copy_proof(builder, value, copy)?;
                }
                if !slot.receiver
                    && let Some(scalar_type) =
                        rust_scalar_type_from_type(self.source, declared_type)
                {
                    self.scalar_types.insert(value, scalar_type);
                }
            }
            let declared_shape =
                declared_type.and_then(|ty| rust_declared_type_shape(self.source, ty));
            if let Some(shape) = declared_shape {
                self.value_shapes.insert(value, shape);
            }
            for name in slot.names {
                self.parameters.insert(name.into_boxed_str(), value);
            }
        }
        if let Some(receiver) = self.receiver {
            self.parameters.insert("self".into(), receiver);
        }
        Ok(())
    }

    fn local_binding_place(
        &self,
        builder: &ProcedureCfgBuilder,
        source: SourceMappingId,
    ) -> SemanticPlace {
        let locator = &builder.source_mapping(source).locator;
        SemanticPlace::LocalBinding(SemanticLocator::new(
            locator.mount(),
            locator.path().clone(),
            locator.language(),
            locator.declaration().clone(),
            SemanticRole::Value,
            locator.anchor(),
        ))
    }

    fn register_binding_cleanup_actions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        scope: ScopeFrameId,
        region: CleanupRegionId,
        values: &[ValueId],
        source_point: ProgramPointId,
    ) -> Result<bool, RustLoweringError> {
        enum FieldWork<'tree> {
            Expand {
                type_node: Node<'tree>,
                place: SemanticPlace,
                member_path: Vec<String>,
            },
            Register(ScopeCleanupAction),
        }

        let mut any_cleanup_actions = false;
        for value in values.iter().rev().copied() {
            let Some(place) = self.binding_places.get(&value).cloned() else {
                continue;
            };
            let mut binding_has_drop = false;
            let mut cleanup_places = vec![place.clone()];
            let metadata = *self
                .binding_metadata
                .get(&value)
                .expect("each owned binding has declaration source evidence");
            self.cleanup_owners_by_region
                .entry(region)
                .or_default()
                .push(value);
            let (behavior, incomplete) = self.drop_behavior(value);
            if let Some(incomplete) = incomplete {
                self.cleanup_drop_incompletes
                    .insert(place.clone(), incomplete);
            }
            if self.value_is_manually_drop(value) {
                self.cleanup_drop_incompletes
                    .insert(place.clone(), LifecycleIncompleteReason::ManuallyDrop);
            }
            if !matches!(&behavior, DropBehavior::Trivial) {
                builder.register_scope_cleanup_action(
                    scope,
                    ScopeCleanupAction::Drop {
                        place: place.clone(),
                        behavior,
                        source: metadata.source,
                        evidence: metadata.evidence,
                    },
                )?;
                binding_has_drop = true;
            }
            if let Some(RustValueType::Declared(type_node)) = self.value_types.get(&value).copied()
                && !self.proven_copies.contains_key(&value)
                && !self.type_is_manually_drop(type_node)
            {
                let member_path =
                    rust_nominal_type_path(type_node, self.source).unwrap_or_default();
                let mut pending = vec![FieldWork::Expand {
                    type_node,
                    place: place.clone(),
                    member_path,
                }];
                while let Some(work) = pending.pop() {
                    match work {
                        FieldWork::Expand {
                            type_node,
                            place,
                            member_path,
                        } => {
                            if self.type_is_manually_drop(type_node) {
                                self.cleanup_drop_incompletes
                                    .insert(place, LifecycleIncompleteReason::ManuallyDrop);
                                continue;
                            }
                            match self.ownership.drop_fields_for_type(type_node) {
                                Ok(fields) => {
                                    for (index, (name, field_type)) in
                                        fields.into_iter().enumerate()
                                    {
                                        let (field_behavior, field_incomplete) =
                                            self.drop_behavior_for_type(field_type);
                                        if field_incomplete.is_none()
                                            && matches!(&field_behavior, DropBehavior::Trivial)
                                            && matches!(
                                                field_type.kind(),
                                                "primitive_type"
                                                    | "reference_type"
                                                    | "pointer_type"
                                                    | "unit_type"
                                            )
                                        {
                                            continue;
                                        }
                                        let source_node = name.unwrap_or(field_type);
                                        let field_metadata =
                                            self.value_mapping(builder, source_node)?;
                                        let selector = name
                                            .and_then(|name| node_text(self.source, name))
                                            .map(str::to_owned)
                                            .unwrap_or_else(|| index.to_string());
                                        let mut path = member_path.clone();
                                        path.push(selector);
                                        let anchor = source_anchor(source_node, 0)
                                            .map_err(RustLoweringError::Invalid)?;
                                        let member_segment = DeclarationSegment::named(
                                            DeclarationSegmentKind::Namespace,
                                            format!("rust-field:{}", path.join("::")),
                                            SourceAnchor::new(
                                                SourceSpan::new(
                                                    SourcePosition::new(0, 0, 0),
                                                    SourcePosition::new(0, 0, 0),
                                                )
                                                .expect(
                                                    "zero-width field identity anchor is valid",
                                                ),
                                                0,
                                            ),
                                            0,
                                        )
                                        .expect("a structured Rust field path is non-empty");
                                        let member_declaration =
                                            DeclarationLocator::new(vec![member_segment]).expect(
                                                "a Rust field member has one identity segment",
                                            );
                                        let procedure = self.session.locator();
                                        let member = SemanticLocator::new(
                                            procedure.mount(),
                                            WorkspaceRelativePath::new(
                                                crate::analyzer::semantic::RUST_FIELD_MEMBER_PATH,
                                            )
                                            .expect("canonical Rust field member path is portable"),
                                            procedure.language(),
                                            member_declaration,
                                            SemanticRole::MemoryLocation,
                                            anchor,
                                        );
                                        let location = self.session.add_memory_location(
                                            builder,
                                            source_point,
                                            MemoryLocationKind::Field {
                                                base: value,
                                                member,
                                            },
                                        )?;
                                        let field_place = SemanticPlace::MemoryLocation(location);
                                        cleanup_places.push(field_place.clone());
                                        if let Some(reason) = field_incomplete {
                                            self.cleanup_drop_incompletes
                                                .insert(field_place.clone(), reason);
                                        }
                                        pending.push(FieldWork::Expand {
                                            type_node: field_type,
                                            place: field_place.clone(),
                                            member_path: path,
                                        });
                                        pending.push(FieldWork::Register(
                                            ScopeCleanupAction::Drop {
                                                place: field_place,
                                                behavior: field_behavior,
                                                source: field_metadata.source,
                                                evidence: field_metadata.evidence,
                                            },
                                        ));
                                    }
                                }
                                Err(reason) => {
                                    self.cleanup_drop_incompletes.insert(
                                        place,
                                        match reason {
                                            RustOwnershipIncomplete::GenericObligation => {
                                                LifecycleIncompleteReason::GenericDropObligation
                                            }
                                            RustOwnershipIncomplete::MissingType => {
                                                LifecycleIncompleteReason::MissingType
                                            }
                                            _ => LifecycleIncompleteReason::UnsupportedCleanup,
                                        },
                                    );
                                }
                            }
                        }
                        FieldWork::Register(action) => {
                            if let ScopeCleanupAction::Drop { behavior, .. } = &action {
                                if matches!(behavior, DropBehavior::Trivial) {
                                    continue;
                                }
                                binding_has_drop = true;
                            }
                            builder.register_scope_cleanup_action(scope, action)?;
                        }
                    }
                }
            }
            if binding_has_drop {
                builder.register_scope_cleanup_action(
                    scope,
                    ScopeCleanupAction::ScopeEnd {
                        place: place.clone(),
                        source: metadata.source,
                        evidence: metadata.evidence,
                    },
                )?;
                self.cleanup_places_by_binding.insert(value, cleanup_places);
                any_cleanup_actions = true;
            }
        }
        Ok(any_cleanup_actions)
    }

    fn drop_behavior(&self, value: ValueId) -> (DropBehavior, Option<LifecycleIncompleteReason>) {
        if self.value_is_manually_drop(value) {
            return (DropBehavior::Trivial, None);
        }
        if matches!(
            self.value_types.get(&value),
            Some(RustValueType::Borrowed { .. })
        ) {
            return (DropBehavior::Trivial, None);
        }
        if self.definitely_non_dropping.contains(&value) {
            return (DropBehavior::Trivial, None);
        }
        let Some(RustValueType::Declared(type_node)) = self.value_types.get(&value).copied() else {
            return (
                DropBehavior::Destructor(CallableTargetResolution::Unknown),
                Some(LifecycleIncompleteReason::MissingType),
            );
        };
        self.drop_behavior_for_type(type_node)
    }

    fn drop_behavior_for_type(
        &self,
        type_node: Node<'tree>,
    ) -> (DropBehavior, Option<LifecycleIncompleteReason>) {
        if self.type_is_manually_drop(type_node) {
            return (DropBehavior::Trivial, None);
        }
        if matches!(
            type_node.kind(),
            "primitive_type" | "reference_type" | "pointer_type" | "unit_type"
        ) {
            return (DropBehavior::Trivial, None);
        }
        // A struct this file proves plain (every field is a primitive or another
        // plain struct, and the file states no `impl Drop` for it) owns no
        // destructor, so its own drop glue is trivial and its field expansion
        // mints no cleanup action. This mirrors `expression_is_definitely_non_dropping`,
        // which already trusts the same proof when it types a struct literal, and
        // it keeps a nested plain struct (`LevelOne { b: LevelTwo { c: LevelThree } }`)
        // from being reported as an unrouted destructor merely because the
        // ownership classifier cannot prove the struct `Copy` from this file alone.
        if self.type_is_plain_struct(type_node) {
            return (DropBehavior::Trivial, None);
        }
        match self.ownership.drop_impl_method_for_type(type_node) {
            Ok(Some(method)) => {
                if let Some(target) = self.procedure_targets.get(&method.id()) {
                    (
                        DropBehavior::Destructor(CallableTargetResolution::Proven(
                            CallableTarget::Local(target.id),
                        )),
                        None,
                    )
                } else {
                    (
                        DropBehavior::Destructor(CallableTargetResolution::Unknown),
                        Some(LifecycleIncompleteReason::UnresolvedTraitDispatch),
                    )
                }
            }
            Ok(None) => match self.ownership.classify_nominal_type_for_drop(type_node) {
                RustOwnershipClass::ScalarCopy | RustOwnershipClass::AggregateCopy => {
                    (DropBehavior::Trivial, None)
                }
                RustOwnershipClass::Incomplete(RustOwnershipIncomplete::GenericObligation) => (
                    DropBehavior::Destructor(CallableTargetResolution::Unknown),
                    Some(LifecycleIncompleteReason::GenericDropObligation),
                ),
                RustOwnershipClass::Incomplete(RustOwnershipIncomplete::MissingType) => (
                    DropBehavior::Destructor(CallableTargetResolution::Unknown),
                    Some(LifecycleIncompleteReason::MissingType),
                ),
                RustOwnershipClass::Incomplete(_) => (
                    DropBehavior::Destructor(CallableTargetResolution::Unknown),
                    Some(LifecycleIncompleteReason::UnresolvedTraitDispatch),
                ),
                _ => match self.ownership.drop_fields_for_type(type_node) {
                    Ok(_) => (DropBehavior::Trivial, None),
                    Err(RustOwnershipIncomplete::GenericObligation) => (
                        DropBehavior::Destructor(CallableTargetResolution::Unknown),
                        Some(LifecycleIncompleteReason::GenericDropObligation),
                    ),
                    Err(RustOwnershipIncomplete::MissingType) => (
                        DropBehavior::Destructor(CallableTargetResolution::Unknown),
                        Some(LifecycleIncompleteReason::MissingType),
                    ),
                    Err(_) => (
                        DropBehavior::Destructor(CallableTargetResolution::Unknown),
                        Some(LifecycleIncompleteReason::UnsupportedCleanup),
                    ),
                },
            },
            Err(RustOwnershipIncomplete::GenericObligation) => (
                DropBehavior::Destructor(CallableTargetResolution::Unknown),
                Some(LifecycleIncompleteReason::GenericDropObligation),
            ),
            Err(RustOwnershipIncomplete::MissingType) => (
                DropBehavior::Destructor(CallableTargetResolution::Unknown),
                Some(LifecycleIncompleteReason::MissingType),
            ),
            Err(_) => (
                DropBehavior::Destructor(CallableTargetResolution::Unknown),
                Some(LifecycleIncompleteReason::UnresolvedTraitDispatch),
            ),
        }
    }

    fn type_is_manually_drop(&self, type_node: Node<'tree>) -> bool {
        let Some(path) = rust_type_path_node(type_node) else {
            return false;
        };
        self.ownership
            .resolves_standard_path(path, &["core", "mem", "ManuallyDrop"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "mem", "ManuallyDrop"])
    }

    /// Whether this file proves the named struct owns no `Drop`.
    ///
    /// `plain_structs` is the same proof `expression_is_definitely_non_dropping`
    /// consults for a struct literal, so the two agree on which values can skip
    /// cleanup. Only a bare local name qualifies: a scoped path or a generic
    /// instantiation keeps its own (unproven) drop behavior.
    fn type_is_plain_struct(&self, type_node: Node<'tree>) -> bool {
        type_node.kind() == "type_identifier"
            && self
                .facts
                .plain_structs
                .contains(rust_node_text(type_node, self.source))
    }

    fn value_is_manually_drop(&self, value: ValueId) -> bool {
        self.manually_drop_values.contains(&value)
            || self.value_types.get(&value).is_some_and(|ty| {
                matches!(ty, RustValueType::Declared(type_node) if self.type_is_manually_drop(*type_node))
            })
    }

    fn add_stack_pointer_origin(
        &mut self,
        place: SemanticPlace,
        byte_extent: Option<u128>,
        point: ProgramPointId,
        metadata: PointMetadata,
    ) -> PointerOriginId {
        if let Some(id) = self.pointer_origins_by_place.get(&place).copied() {
            return id;
        }
        let id = PointerOriginId::try_from_index(self.pointer_origins.len())
            .expect("Rust pointer origin IDs fit the validated dense-ID domain");
        self.pointer_origins.push(PointerOrigin {
            id,
            point,
            kind: PointerOriginKind::StackPlace {
                place: place.clone(),
            },
            byte_extent,
            source: metadata.source,
            evidence: metadata.evidence,
        });
        self.pointer_origins_by_place.insert(place, id);
        id
    }

    fn add_allocation_pointer_origin(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        pointer: ValueId,
        byte_extent: Option<u128>,
        allocation_kind: AllocationKind,
        point: ProgramPointId,
        metadata: PointMetadata,
    ) -> Result<PointerOriginId, RustLoweringError> {
        let allocation = self
            .session
            .add_allocation(builder, point, pointer, allocation_kind)?;
        let id = PointerOriginId::try_from_index(self.pointer_origins.len())
            .expect("Rust pointer origin IDs fit the validated dense-ID domain");
        self.pointer_origins.push(PointerOrigin {
            id,
            point,
            kind: PointerOriginKind::Allocation { allocation },
            byte_extent,
            source: metadata.source,
            evidence: metadata.evidence,
        });
        Ok(id)
    }

    fn add_pointer_alias(
        &mut self,
        point: ProgramPointId,
        pointer: ValueId,
        origin: PointerOriginId,
        byte_offset: PointerByteOffset,
        strength: PointerRelationStrength,
        metadata: PointMetadata,
    ) {
        let aliases = self.pointer_origins_by_pointer.entry(pointer).or_default();
        if aliases.contains(&(origin, byte_offset)) {
            return;
        }
        aliases.push((origin, byte_offset));
        self.pointer_aliases.push(PointerAlias {
            point,
            pointer,
            origin,
            byte_offset,
            strength,
            source: metadata.source,
            evidence: metadata.evidence,
        });
    }

    fn register_pointer_fact_target(
        &mut self,
        source: ValueId,
        target: ValueId,
        point: ProgramPointId,
        metadata: PointMetadata,
    ) {
        if source == target {
            return;
        }
        let targets = self
            .pointer_fact_targets_by_source
            .entry(source)
            .or_default();
        let transfer = PendingPointerFactTransfer {
            target,
            point,
            metadata,
        };
        if !targets.contains(&transfer) {
            targets.push(transfer);
        }
    }

    fn propagate_pointer_facts_to_targets(&mut self, source: ValueId) {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        enum Fact {
            Alias(PointerOriginId, PointerByteOffset),
            OwnerOrigin(PointerOriginId),
            OwnerLifetime(PointerInvalidationTarget, PointerInvalidationCause),
            PointeeByte,
            PointeeType(usize),
            ManuallyDrop,
        }

        if !self.pointer_fact_targets_by_source.contains_key(&source) {
            return;
        }
        let mut pending = Vec::new();
        let mut enqueued = HashSet::default();
        {
            let mut enqueue = |value, fact| {
                if enqueued.insert((value, fact)) {
                    pending.push((value, fact));
                }
            };
            for (origin, offset) in self
                .pointer_origins_by_pointer
                .get(&source)
                .into_iter()
                .flatten()
                .copied()
            {
                enqueue(source, Fact::Alias(origin, offset));
            }
            if let Some(origin) = self.pointer_origins_by_owner.get(&source).copied() {
                enqueue(source, Fact::OwnerOrigin(origin));
            }
            if let Some((target, cause)) = self.pointer_owner_lifetimes.get(&source).copied() {
                enqueue(source, Fact::OwnerLifetime(target, cause));
            }
            if let Some(pointee) = self.pointer_pointees_by_value.get(&source).copied() {
                enqueue(
                    source,
                    match pointee {
                        RustPointerPointee::Byte => Fact::PointeeByte,
                        RustPointerPointee::Type(node) => Fact::PointeeType(node.id()),
                    },
                );
            }
            if self.manually_drop_values.contains(&source) {
                enqueue(source, Fact::ManuallyDrop);
            }
        }

        while let Some((value, fact)) = pending.pop() {
            let targets = self
                .pointer_fact_targets_by_source
                .get(&value)
                .cloned()
                .unwrap_or_default();
            for transfer in targets {
                match fact {
                    Fact::Alias(origin, offset) => self.add_pointer_alias(
                        transfer.point,
                        transfer.target,
                        origin,
                        offset,
                        PointerRelationStrength::Must,
                        transfer.metadata,
                    ),
                    Fact::OwnerOrigin(origin) => {
                        self.pointer_origins_by_owner
                            .insert(transfer.target, origin);
                    }
                    Fact::OwnerLifetime(target, cause) => {
                        self.pointer_owner_lifetimes
                            .insert(transfer.target, (target, cause));
                    }
                    Fact::PointeeByte => {
                        self.pointer_pointees_by_value
                            .insert(transfer.target, RustPointerPointee::Byte);
                    }
                    Fact::PointeeType(node_id) => {
                        let Some(RustPointerPointee::Type(node)) =
                            self.pointer_pointees_by_value.get(&value).copied()
                        else {
                            unreachable!("a typed-pointee transfer retains its source type");
                        };
                        assert_eq!(node.id(), node_id);
                        self.pointer_pointees_by_value
                            .insert(transfer.target, RustPointerPointee::Type(node));
                    }
                    Fact::ManuallyDrop => {
                        self.manually_drop_values.insert(transfer.target);
                    }
                }
                if enqueued.insert((transfer.target, fact)) {
                    pending.push((transfer.target, fact));
                }
            }
        }
    }

    fn add_pointer_access(
        &mut self,
        point: ProgramPointId,
        pointer: ValueId,
        kind: PointerAccessKind,
        width: PointerAccessWidth,
        metadata: PointMetadata,
    ) {
        self.pointer_accesses.push(PointerAccess {
            point,
            pointer,
            kind,
            width,
            source: metadata.source,
            evidence: metadata.evidence,
        });
    }

    fn add_pointer_invalidation(
        &mut self,
        point: ProgramPointId,
        target: PointerInvalidationTarget,
        cause: PointerInvalidationCause,
        strength: PointerRelationStrength,
        metadata: PointMetadata,
    ) {
        self.pointer_invalidations.push(PointerInvalidation {
            point,
            target,
            cause,
            strength,
            source: metadata.source,
            evidence: metadata.evidence,
        });
    }

    fn owner_invalidation(
        &self,
        owner: ValueId,
    ) -> Option<(PointerInvalidationTarget, PointerInvalidationCause)> {
        self.pointer_owner_lifetimes
            .get(&owner)
            .copied()
            .or_else(|| {
                self.pointer_origins_by_owner
                    .get(&owner)
                    .copied()
                    .map(|origin| {
                        (
                            PointerInvalidationTarget::Origin(origin),
                            PointerInvalidationCause::OwnerDropped,
                        )
                    })
            })
    }

    fn transfer_pointer_owner_facts(&mut self, source: ValueId, target: ValueId) {
        if let Some(origin) = self.pointer_origins_by_owner.remove(&source) {
            self.pointer_origins_by_owner.insert(target, origin);
        }
        if let Some(invalidation) = self.pointer_owner_lifetimes.remove(&source) {
            self.pointer_owner_lifetimes.insert(target, invalidation);
        }
        if self.manually_drop_values.remove(&source) {
            self.manually_drop_values.insert(target);
        }
    }

    fn add_incomplete_fact(
        &mut self,
        point: ProgramPointId,
        subject: SemanticIncompleteSubject,
        reason: SemanticIncompleteReason,
        metadata: PointMetadata,
    ) {
        self.incomplete_facts.push(SemanticIncompleteFact {
            point,
            subject,
            reason,
            source: metadata.source,
            evidence: metadata.evidence,
        });
    }

    fn pointer_pointee(&self, node: Node<'tree>) -> Option<RustPointerPointee<'tree>> {
        let node = unwrap_attributes(node);
        if let Some(value) = self.expression_values.get(&node.id()).copied()
            && let Some(pointee) = self.pointer_pointees_by_value.get(&value)
        {
            return Some(*pointee);
        }
        if let Some(value) = self.binding_value(node)
            && let Some(pointee) = self.pointer_pointees_by_value.get(&value)
        {
            return Some(*pointee);
        }
        if let Some(RustValueType::Declared(type_node)) = self.expression_type(node)
            && type_node.kind() == "pointer_type"
        {
            return type_node
                .child_by_field_name("type")
                .map(RustPointerPointee::Type);
        }
        if node.kind() != "call_expression" {
            return None;
        }
        let function = call_function_target(node.child_by_field_name("function")?);
        if self
            .ownership
            .resolves_standard_path(function, &["core", "alloc", "alloc"])
            || self
                .ownership
                .resolves_standard_path(function, &["std", "alloc", "alloc"])
            || self
                .ownership
                .resolves_standard_path(function, &["alloc", "alloc", "alloc"])
        {
            return Some(RustPointerPointee::Byte);
        }
        if self
            .ownership
            .resolves_standard_path(function, &["std", "boxed", "Box", "into_raw"])
            || self
                .ownership
                .resolves_standard_path(function, &["alloc", "boxed", "Box", "into_raw"])
        {
            let argument = call_arguments(node).first().copied()?;
            let RustValueType::Declared(owner_type) = self.expression_type(argument)? else {
                return None;
            };
            return rust_generic_type_argument(owner_type, 0).map(RustPointerPointee::Type);
        }
        let (receiver, member) = rust_method_call_parts(function)?;
        let method = node_text(self.source, member)?;
        if !matches!(method, "as_ptr" | "as_mut_ptr") {
            return None;
        }
        let receiver_type = match self.expression_type(receiver)? {
            RustValueType::Declared(type_node) => type_node,
            RustValueType::Borrowed { referent, .. } => referent,
        };
        let receiver_path = rust_type_path_node(receiver_type)?;
        if !self
            .ownership
            .resolves_standard_path(receiver_path, &["std", "vec", "Vec"])
            && !self
                .ownership
                .resolves_standard_path(receiver_path, &["alloc", "vec", "Vec"])
        {
            return None;
        }
        rust_generic_type_argument(receiver_type, 0).map(RustPointerPointee::Type)
    }

    fn pointer_pointee_type(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        match self.pointer_pointee(node)? {
            RustPointerPointee::Type(type_node) => Some(type_node),
            RustPointerPointee::Byte => None,
        }
    }

    fn is_raw_pointer_expression(&self, node: Node<'tree>) -> bool {
        self.pointer_pointee(node).is_some()
    }

    fn pointer_width_for_expression(&self, node: Node<'tree>) -> PointerAccessWidth {
        self.pointer_pointee(node)
            .and_then(|pointee| match pointee {
                RustPointerPointee::Type(type_node) => rust_type_byte_size(self.source, type_node),
                RustPointerPointee::Byte => Some(1),
            })
            .map_or(PointerAccessWidth::Unknown, PointerAccessWidth::Exact)
    }

    fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), RustLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(RustLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node.id() != body.id() && is_rust_nested_execution_boundary(node) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "let_declaration"
                && let Some(pattern) = node.child_by_field_name("pattern")
                && let Some((scope_start, scope_end)) = rust_local_scope(node)
            {
                let simple_binding = identity_binding_identifier(pattern).map(|name| name.id());
                for name in rust_pattern_binding_identifiers(pattern) {
                    let Some(text) = node_text(self.source, name) else {
                        continue;
                    };
                    let metadata = self.value_mapping(builder, name)?;
                    let place = self.local_binding_place(builder, metadata.source);
                    let value = self.session.add_value_with_metadata(
                        builder,
                        metadata,
                        SemanticValueKind::Local,
                    )?;
                    self.binding_places.insert(value, place);
                    self.binding_metadata.insert(value, metadata);
                    self.binding_nodes.insert(value, name);
                    self.binding_scopes
                        .insert(value, (node.end_byte(), scope_start, scope_end));
                    self.locals
                        .entry(text.into())
                        .or_default()
                        .push(LocalBinding {
                            declaration_start: name.start_byte(),
                            visible_from: node.end_byte(),
                            scope_start,
                            scope_end,
                            value,
                            initializer: node.child_by_field_name("value"),
                        });
                    if simple_binding == Some(name.id()) {
                        // The declared type states the shape when there is one;
                        // otherwise the initializer does. The walk is preorder, so a
                        // local this initializer names was already classified, which is
                        // what lets `let alias = &original;` take `original`'s own
                        // struct shape. A destructuring pattern does not give each
                        // binding the whole initializer's type or shape.
                        let declared_type = node
                            .child_by_field_name("type")
                            .map(RustValueType::Declared)
                            .or_else(|| {
                                node.child_by_field_name("value")
                                    .and_then(|initializer| self.expression_type(initializer))
                            });
                        if let Some(declared_type) = declared_type {
                            self.value_types.insert(value, declared_type);
                            if let RustValueType::Declared(ty) = declared_type {
                                let authoritative = if node.child_by_field_name("type").is_some() {
                                    true
                                } else if let Some(initializer) = node.child_by_field_name("value")
                                {
                                    match self.tuple_source_leaf(builder, initializer)? {
                                        Ok(source) => matches!(
                                            self.tuple_binding_type(builder, source)?,
                                            Some(RustValueType::Declared(source_type)) if source_type == ty
                                        ),
                                        Err(_) => false,
                                    }
                                } else {
                                    false
                                };
                                if authoritative
                                    && let Ok(copy) = self.prove_type_copy(builder, ty)?
                                {
                                    // Use a written type or an already proved
                                    // binding, never the file-wide call-return
                                    // heuristic as new tuple/cleanup authority.
                                    self.retain_copy_proof(builder, value, copy)?;
                                }
                            }
                        }
                        if let Some(scalar_type) = node
                            .child_by_field_name("type")
                            .and_then(|type_node| {
                                rust_scalar_type_from_type(self.source, type_node)
                            })
                            .or_else(|| {
                                node.child_by_field_name("value").and_then(|initializer| {
                                    rust_scalar_type_from_literal(self.source, initializer)
                                })
                            })
                        {
                            self.scalar_types.insert(value, scalar_type);
                        }
                        if let Some(shape) = node
                            .child_by_field_name("type")
                            .and_then(|ty| rust_declared_type_shape(self.source, ty))
                            .or_else(|| {
                                node.child_by_field_name("value")
                                    .and_then(|initializer| self.expression_shape(initializer))
                            })
                        {
                            self.value_shapes.insert(value, shape);
                        }
                        if node
                            .child_by_field_name("type")
                            .is_some_and(|ty| ty.kind() == "primitive_type")
                            || node
                                .child_by_field_name("value")
                                .is_some_and(|initializer| {
                                    self.expression_is_definitely_non_dropping(initializer)
                                })
                        {
                            self.definitely_non_dropping.insert(value);
                        }
                    }
                }
                if pattern.kind() == "tuple_pattern" {
                    let proof = self.prove_tuple_let(builder, node, pattern)?;
                    if let Ok(proof) = &proof {
                        for component in &proof.components {
                            let text = node_text(self.source, component.binding)
                                .expect("a proved tuple binding has a source name");
                            charge_rust_tuple_work(
                                builder,
                                self.session.cancellation(),
                                self.locals.get(text).map_or(0, Vec::len),
                            )?;
                            let value = self
                                .local_declaration_value(text, component.binding.start_byte())
                                .expect("tuple leaves were preindexed before their proof");
                            charge_rust_tuple_work(builder, self.session.cancellation(), 3)?;
                            if let Some(ty) = component.ty {
                                self.value_types.insert(value, RustValueType::Declared(ty));
                                if let Some(scalar) = rust_scalar_type_from_type(self.source, ty) {
                                    self.scalar_types.insert(value, scalar);
                                }
                            } else if let RustTupleComponentSource::Literal(source) =
                                component.source
                                && let Some(scalar) =
                                    rust_scalar_type_from_literal(self.source, source)
                            {
                                self.scalar_types.insert(value, scalar);
                            }
                            self.retain_copy_proof(builder, value, component.copy)?;
                        }
                    }
                    charge_lowering_traversal_step(builder, self.session.cancellation())?;
                    self.tuple_lets.insert(node.id(), proof);
                }
            }
            // A `for` or match-arm pattern binds a local too. Without it the loop variable
            // resolved to nothing inside the body, so an element read there
            // began a fresh unrelated value. A destructuring pattern binds one
            // local per component, so `for (key, value) in map` mints two
            // (#2705); binding only the single-identifier form left both names
            // unbound and silently dropped every flow through such a loop.
            if matches!(node.kind(), "for_expression" | "match_arm")
                && let Some(pattern) = node.child_by_field_name("pattern")
                && let Some(body) = node
                    .child_by_field_name("body")
                    .or_else(|| node.child_by_field_name("value"))
            {
                // An element proven non-dropping makes each component of that
                // element non-dropping too: destructuring moves out of a value
                // that owns no destructor.
                let element_is_non_dropping = node.kind() == "for_expression"
                    && node
                        .child_by_field_name("value")
                        .is_some_and(rust_iteration_element_is_definitely_non_dropping);
                let visible_from = if node.kind() == "match_arm" {
                    pattern.start_byte()
                } else {
                    body.start_byte()
                };
                let (scope_start, scope_end) = if node.kind() == "match_arm" {
                    (node.start_byte(), node.end_byte())
                } else {
                    (body.start_byte(), body.end_byte())
                };
                for name in rust_pattern_binding_identifiers(pattern) {
                    let Some(text) = node_text(self.source, name) else {
                        continue;
                    };
                    let metadata = self.value_mapping(builder, name)?;
                    let place = self.local_binding_place(builder, metadata.source);
                    let value = self.session.add_value_with_metadata(
                        builder,
                        metadata,
                        SemanticValueKind::Local,
                    )?;
                    self.binding_places.insert(value, place);
                    self.binding_metadata.insert(value, metadata);
                    self.binding_nodes.insert(value, name);
                    self.binding_scopes
                        .insert(value, (visible_from, scope_start, scope_end));
                    self.locals
                        .entry(text.into())
                        .or_default()
                        .push(LocalBinding {
                            declaration_start: name.start_byte(),
                            visible_from,
                            scope_start,
                            scope_end,
                            value,
                            initializer: None,
                        });
                    if element_is_non_dropping {
                        self.definitely_non_dropping.insert(value);
                    }
                }
            }
            Ok(WalkControl::Continue)
        })
    }

    fn prove_type_copy(
        &self,
        builder: &mut ProcedureCfgBuilder,
        ty: Node<'tree>,
    ) -> Result<Result<TransferKind, RustOwnershipIncomplete>, RustLoweringError> {
        let class = self.ownership.classify_type_bounded(ty, |entries| {
            charge_rust_tuple_work(builder, self.session.cancellation(), entries)
        })?;
        Ok(match class {
            RustOwnershipClass::ScalarCopy => Ok(TransferKind::Copy),
            RustOwnershipClass::AggregateCopy => Ok(TransferKind::AggregateCopy),
            RustOwnershipClass::Incomplete(reason) => Err(reason),
            // A reference binding mode or a move needs its own alias/place
            // transfer; neither is an implicit tuple-component Copy proof.
            _ => Err(RustOwnershipIncomplete::UnsupportedType),
        })
    }

    fn retain_copy_proof(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        value: ValueId,
        copy: TransferKind,
    ) -> Result<(), RustLoweringError> {
        assert!(matches!(
            copy,
            TransferKind::Copy | TransferKind::AggregateCopy
        ));
        charge_rust_tuple_work(builder, self.session.cancellation(), 2)?;
        self.proven_copies.insert(value, copy);
        self.definitely_non_dropping.insert(value);
        Ok(())
    }

    fn tuple_syntax_children(
        &self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Vec<Node<'tree>>, RustLoweringError> {
        charge_lowering_traversal_step(builder, self.session.cancellation())?;
        let mut result = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            charge_lowering_traversal_step(builder, self.session.cancellation())?;
            if !is_comment_kind(child.kind()) {
                result.push(child);
            }
        }
        charge_lowering_traversal_step(builder, self.session.cancellation())?;
        Ok(result)
    }

    fn tuple_source_leaf(
        &self,
        builder: &mut ProcedureCfgBuilder,
        mut node: Node<'tree>,
    ) -> Result<Result<Node<'tree>, RustOwnershipIncomplete>, RustLoweringError> {
        loop {
            charge_lowering_traversal_step(builder, self.session.cancellation())?;
            if node.is_missing() || node.has_error() {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            }
            if node.kind() != "parenthesized_expression" {
                return Ok(Ok(node));
            }
            let children = self.tuple_syntax_children(builder, node)?;
            let [child] = children.as_slice() else {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            };
            node = *child;
        }
    }

    fn flat_value_binding_name(
        &self,
        builder: &mut ProcedureCfgBuilder,
        pattern: Node<'tree>,
    ) -> Result<Option<Node<'tree>>, RustLoweringError> {
        charge_lowering_traversal_step(builder, self.session.cancellation())?;
        if pattern.is_missing() || pattern.has_error() {
            return Ok(None);
        }
        match pattern.kind() {
            "identifier" => Ok(Some(pattern)),
            "mut_pattern" => {
                let children = self.tuple_syntax_children(builder, pattern)?;
                match children.as_slice() {
                    [modifier, name]
                        if modifier.kind() == "mutable_specifier"
                            && !modifier.is_missing()
                            && name.kind() == "identifier"
                            && !name.is_missing() =>
                    {
                        Ok(Some(*name))
                    }
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    fn tuple_binding_type(
        &self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<RustValueType<'tree>>, RustLoweringError> {
        if !matches!(node.kind(), "identifier" | "self") {
            return Ok(None);
        }
        let Some(name) = node_text(self.source, node) else {
            return Ok(None);
        };
        let name = name.strip_prefix("r#").unwrap_or(name);
        // The shared lexical selector scans this same-name cohort. Charge
        // those visits before delegating, rather than adding a second selector.
        let candidates = self.locals.get(name).map_or(0, Vec::len);
        charge_rust_tuple_work(
            builder,
            self.session.cancellation(),
            candidates.saturating_add(1),
        )?;
        let Some(value) = self.binding_value(node) else {
            return Ok(None);
        };
        if !self.proven_copies.contains_key(&value) {
            return Ok(None);
        }
        charge_rust_tuple_work(
            builder,
            self.session.cancellation(),
            self.parameter_values.len(),
        )?;
        if self.parameter_values.contains(&value) {
            let declaration = self.binding_nodes[&value];
            if declaration.kind() != "self_parameter" {
                let Some(pattern) = declaration.child_by_field_name("pattern") else {
                    return Ok(None);
                };
                if self.flat_value_binding_name(builder, pattern)?.is_none() {
                    // A destructured formal's aggregate slot is not the value
                    // of each name in that pattern. That producer stays open.
                    return Ok(None);
                }
            }
        }
        Ok(self.value_types.get(&value).copied())
    }

    fn prove_tuple_let(
        &self,
        builder: &mut ProcedureCfgBuilder,
        declaration: Node<'tree>,
        pattern: Node<'tree>,
    ) -> Result<Result<RustTupleLetProof<'tree>, RustOwnershipIncomplete>, RustLoweringError> {
        charge_lowering_traversal_step(builder, self.session.cancellation())?;
        // Explicit target annotations need a distinct source/target type
        // compatibility proof. This first by-value envelope does not guess it.
        if pattern.is_missing()
            || pattern.has_error()
            || declaration.child_by_field_name("alternative").is_some()
            || declaration.child_by_field_name("type").is_some()
        {
            return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
        }
        let Some(initializer) = declaration.child_by_field_name("value") else {
            return Ok(Err(RustOwnershipIncomplete::MissingType));
        };
        let source = match self.tuple_source_leaf(builder, initializer)? {
            Ok(source) => source,
            Err(reason) => return Ok(Err(reason)),
        };
        let leaves = self.tuple_syntax_children(builder, pattern)?;
        if leaves.is_empty() {
            return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
        }
        let mut names = Vec::new();
        for leaf in leaves {
            charge_lowering_traversal_step(builder, self.session.cancellation())?;
            let Some(name) = self.flat_value_binding_name(builder, leaf)? else {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            };
            // A flat identifier can be an irrefutable constant pattern. Prove
            // every leaf independently of the tentative local inventory before
            // retaining any component Copy/type or cleanup metadata.
            if !rust_pattern_identifier_binding_bounded(
                self.source_root,
                self.source,
                leaf,
                &mut |entries| {
                    charge_rust_tuple_work(builder, self.session.cancellation(), entries)
                },
            )? {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            }
            charge_lowering_traversal_step(builder, self.session.cancellation())?;
            names.push(name);
        }
        let mut components = Vec::new();
        if source.kind() == "tuple_expression" {
            let children = self.tuple_syntax_children(builder, source)?;
            if children.len() != names.len() {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            }
            for (binding, child) in names.into_iter().zip(children) {
                let child = match self.tuple_source_leaf(builder, child)? {
                    Ok(child) => child,
                    Err(reason) => return Ok(Err(reason)),
                };
                let ty = match self.tuple_binding_type(builder, child)? {
                    Some(RustValueType::Declared(ty)) => Some(ty),
                    Some(RustValueType::Borrowed { .. }) => {
                        return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
                    }
                    None => None,
                };
                let copy = if let Some(ty) = ty {
                    match self.prove_type_copy(builder, ty)? {
                        Ok(copy) => copy,
                        Err(reason) => return Ok(Err(reason)),
                    }
                } else {
                    // These literal categories carry an intrinsic value type;
                    // a type identifier's spelling would not prove the same.
                    match child.kind() {
                        "integer_literal" | "float_literal" | "char_literal"
                        | "boolean_literal" | "true" | "false" => TransferKind::Copy,
                        "unit_expression" => TransferKind::AggregateCopy,
                        _ => return Ok(Err(RustOwnershipIncomplete::MissingType)),
                    }
                };
                charge_lowering_traversal_step(builder, self.session.cancellation())?;
                components.push(RustTupleComponentProof {
                    binding,
                    source: RustTupleComponentSource::Literal(child),
                    ty,
                    copy,
                });
            }
        } else {
            // Other runtime expressions retain their existing call/place gaps.
            // The first aggregate path projects a captured binding read only.
            if !matches!(source.kind(), "identifier" | "self") {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            }
            let Some(RustValueType::Declared(ty)) = self.tuple_binding_type(builder, source)?
            else {
                return Ok(Err(RustOwnershipIncomplete::MissingType));
            };
            match self.prove_type_copy(builder, ty)? {
                Ok(TransferKind::AggregateCopy) => {}
                Ok(_) => return Ok(Err(RustOwnershipIncomplete::UnsupportedType)),
                Err(reason) => return Ok(Err(reason)),
            }
            let types = self
                .ownership
                .tuple_component_types_bounded(ty, |entries| {
                    charge_rust_tuple_work(builder, self.session.cancellation(), entries)
                })?;
            let types = match types {
                Ok(types) => types,
                Err(reason) => return Ok(Err(reason)),
            };
            if types.len() != names.len() {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            }
            for (ordinal, (binding, ty)) in names.into_iter().zip(types).enumerate() {
                let copy = match self.prove_type_copy(builder, ty)? {
                    Ok(copy) => copy,
                    Err(reason) => return Ok(Err(reason)),
                };
                charge_lowering_traversal_step(builder, self.session.cancellation())?;
                components.push(RustTupleComponentProof {
                    binding,
                    source: RustTupleComponentSource::Field {
                        aggregate: source,
                        ordinal,
                    },
                    ty: Some(ty),
                    copy,
                });
            }
        }
        charge_lowering_traversal_step(builder, self.session.cancellation())?;
        Ok(Ok(RustTupleLetProof {
            pattern,
            components,
        }))
    }

    fn append_tuple_let(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        proof: RustTupleLetProof<'tree>,
    ) -> Result<ProgramPointId, RustLoweringError> {
        let cancellation = self.session.cancellation();
        let steps = ordered_decomposition_steps(
            builder,
            cancellation,
            proof.pattern,
            None::<usize>,
            |builder, _target, component, children| {
                if component.is_some() {
                    return Ok(DecompositionExpansion::Leaf);
                }
                for (ordinal, component) in proof.components.iter().enumerate() {
                    children.push(builder, cancellation, component.binding, Some(ordinal))?;
                }
                Ok(DecompositionExpansion::Children {
                    boundary: Some(proof.pattern),
                })
            },
        )?;
        let mut previous = entry;
        let mut values = Vec::new();
        for step in steps {
            match step {
                DecompositionStep::Boundary(pattern) => {
                    let boundary = self.point(builder, pattern, Vec::new())?;
                    self.session.add_target_edge(
                        builder,
                        previous,
                        EdgeTarget::normal(boundary),
                    )?;
                    previous = boundary;
                    // Capture every component before the first binding write.
                    // Work::Expression still evaluates the whole RHS once on
                    // the CFG path before entry, reusing these occurrence IDs.
                    for component in &proof.components {
                        charge_lowering_traversal_step(builder, self.session.cancellation())?;
                        let value = match component.source {
                            RustTupleComponentSource::Literal(source) => self.expression_value(
                                builder,
                                source,
                                expression_value_kind(source),
                            )?,
                            RustTupleComponentSource::Field { aggregate, ordinal } => {
                                let base = self.expression_value(
                                    builder,
                                    aggregate,
                                    expression_value_kind(aggregate),
                                )?;
                                let member = self
                                    .canonical_field_member_locator(&format!("tuple:{ordinal}"));
                                let location = self.session.add_memory_location(
                                    builder,
                                    boundary,
                                    MemoryLocationKind::Field { base, member },
                                )?;
                                let metadata = self.value_mapping(builder, component.binding)?;
                                let result = self.session.add_value_with_metadata(
                                    builder,
                                    metadata,
                                    SemanticValueKind::Temporary,
                                )?;
                                self.append_effect(
                                    builder,
                                    boundary,
                                    SemanticEffect::MemoryLoad {
                                        kind: MemoryAccessKind::Field,
                                        location,
                                        result,
                                    },
                                )?;
                                result
                            }
                        };
                        charge_lowering_traversal_step(builder, self.session.cancellation())?;
                        values.push(value);
                    }
                }
                DecompositionStep::Leaf { target, source } => {
                    let ordinal = source.expect("a tuple leaf has a proved component ordinal");
                    let component = proof.components[ordinal];
                    assert_eq!(target, component.binding);
                    let name =
                        node_text(self.source, target).expect("a proved tuple leaf has a name");
                    charge_rust_tuple_work(
                        builder,
                        self.session.cancellation(),
                        self.locals.get(name).map_or(0, Vec::len),
                    )?;
                    let binding = self
                        .local_declaration_value(name, target.start_byte())
                        .expect("tuple binding was preindexed");
                    let point = self.point(builder, target, Vec::new())?;
                    self.session
                        .add_target_edge(builder, previous, EdgeTarget::normal(point))?;
                    self.append_assignment_value_flow(
                        builder,
                        point,
                        values[ordinal],
                        binding,
                        ValueFlowKind::Transfer(ValueTransfer {
                            kind: component.copy,
                            operation: TransferOperation::None,
                        }),
                    )?;
                    previous = point;
                }
            }
        }
        charge_lowering_traversal_step(builder, self.session.cancellation())?;
        Ok(previous)
    }

    fn local_at(&self, name: &str, byte: usize) -> Option<ValueId> {
        self.local_binding_at(name, byte)
            .map(|binding| binding.value)
    }

    fn local_binding_at(&self, name: &str, byte: usize) -> Option<&LocalBinding<'tree>> {
        brokk_bifrost_analysis::analyzer::common::visible_local_binding(
            self.locals.get(name)?,
            byte,
            |binding| (binding.visible_from, binding.scope_start, binding.scope_end),
            |binding, (_, scope_start, scope_end)| {
                (
                    scope_end - scope_start,
                    std::cmp::Reverse(binding.declaration_start),
                )
            },
        )
    }

    fn local_declaration_value(&self, name: &str, declaration_start: usize) -> Option<ValueId> {
        brokk_bifrost_analysis::analyzer::common::local_value_for_declaration(
            self.locals
                .get(name)?
                .iter()
                .map(|binding| (binding.declaration_start, binding.value)),
            declaration_start,
        )
    }

    fn capture_source_value(&self, capture: &RustCaptureSpec<'_>) -> Option<ValueId> {
        self.local_declaration_value(&capture.name, capture.declaration_start)
            .or_else(|| {
                (capture.name.as_ref() == "self")
                    .then_some(self.receiver)
                    .flatten()
            })
            .or_else(|| self.parameters.get(&capture.name).copied())
            .or_else(|| {
                self.captured_binding_sources
                    .get(&(capture.name.clone(), capture.declaration_start))
                    .copied()
            })
    }

    fn binding_value(&self, node: Node<'_>) -> Option<ValueId> {
        let node = unwrap_attributes(node);
        let name = node_text(self.source, node)?;
        let name = name.strip_prefix("r#").unwrap_or(name);
        match node.kind() {
            "self" => self
                .receiver
                .or_else(|| self.captured_bindings.get(name).copied()),
            "identifier" => self
                .local_at(name, node.start_byte())
                .or_else(|| self.parameters.get(name).copied())
                .or_else(|| self.captured_bindings.get(name).copied()),
            _ => None,
        }
    }

    fn static_declaration_at(
        &self,
        node: Node<'tree>,
        name: &str,
    ) -> Option<&RustStaticDeclaration<'tree>> {
        let mut best = None;
        let mut best_scope_width = usize::MAX;
        let mut ambiguous = false;
        for declaration in &self.facts.static_declarations {
            let scope = declaration.scope.byte_range();
            if declaration.name.as_ref() != name
                || scope.start > node.start_byte()
                || node.end_byte() > scope.end
            {
                continue;
            }
            let width = scope.end - scope.start;
            if width < best_scope_width {
                best = Some(declaration);
                best_scope_width = width;
                ambiguous = false;
            } else if width == best_scope_width {
                ambiguous = true;
            }
        }
        (!ambiguous).then_some(best).flatten()
    }

    fn static_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        node: Node<'tree>,
        name: &str,
    ) -> Result<Option<MemoryLocationId>, RustLoweringError> {
        let Some(declaration) = self.static_declaration_at(node, name) else {
            return Ok(None);
        };
        let declaration_start = declaration.name_node.start_byte();
        if let Some(location) = self.static_locations.get(&declaration_start).copied() {
            return Ok(Some(location));
        }
        let anchor = source_anchor(declaration.name_node, 0).map_err(RustLoweringError::Invalid)?;
        let member = DeclarationSegment::named(
            DeclarationSegmentKind::Namespace,
            format!("rust-static:{name}"),
            anchor,
            0,
        )
        .expect("a Rust static identifier is non-empty");
        let declaration_path = DeclarationLocator::new(vec![member])
            .expect("a Rust static locator has its declaration segment");
        let procedure = self.session.locator();
        let member = SemanticLocator::new(
            procedure.mount(),
            procedure.path().clone(),
            procedure.language(),
            declaration_path,
            SemanticRole::MemoryLocation,
            anchor,
        );
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Static { member },
        )?;
        self.static_locations.insert(declaration_start, location);
        Ok(Some(location))
    }

    fn scalar_binding_operand(&self, node: Node<'tree>) -> Option<(ValueId, DeclaredScalarType)> {
        let node = peel_rust_parentheses(node);
        if !matches!(node.kind(), "identifier" | "self") {
            return None;
        }
        let value = self.binding_value(node)?;
        let scalar_type = self.scalar_types.get(&value).copied()?;
        Some((value, scalar_type))
    }

    fn scalar_literal_operand(&self, node: Node<'tree>) -> Option<DeclaredScalarType> {
        rust_scalar_type_from_literal(self.source, peel_rust_parentheses(node))
    }

    fn scalar_constant_operand(
        &self,
        node: Node<'tree>,
    ) -> Option<(DeclaredScalarType, Option<u128>)> {
        let node = peel_rust_parentheses(node);
        if let Some(scalar_type) = self.scalar_literal_operand(node) {
            return Some((scalar_type, None));
        }
        self.rust_integer_constant_value(node)
            .map(|value| (DeclaredScalarType::Unsigned(128), Some(value)))
    }

    fn scalar_operator_is_builtin(&self, node: Node<'tree>) -> bool {
        let node = unwrap_attributes(node);
        if node.kind() == "unary_expression" {
            return node.child(0).is_some_and(|operator| operator.kind() == "!")
                && node
                    .named_child(0)
                    .and_then(|operand| self.scalar_binding_operand(operand))
                    .is_some_and(|(_, scalar_type)| scalar_type == DeclaredScalarType::Boolean);
        }
        if node.kind() != "binary_expression" {
            return false;
        }
        let Some(operator) = node.child_by_field_name("operator") else {
            return false;
        };
        if !matches!(operator.kind(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
            return false;
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        let left_binding = self.scalar_binding_operand(left);
        let right_binding = self.scalar_binding_operand(right);
        let left_literal = self.scalar_constant_operand(left);
        let right_literal = self.scalar_constant_operand(right);
        let integer = |scalar_type| {
            matches!(
                scalar_type,
                DeclaredScalarType::Signed(_) | DeclaredScalarType::Unsigned(_)
            )
        };
        match (left_binding, right_binding, left_literal, right_literal) {
            (Some((_, left_type)), Some((_, right_type)), None, None) => {
                ((integer(left_type) && integer(right_type))
                    || (left_type == DeclaredScalarType::Boolean
                        && right_type == DeclaredScalarType::Boolean))
                    && (integer(left_type) || matches!(operator.kind(), "==" | "!="))
            }
            (Some((_, binding_type)), None, None, Some((literal_type, _)))
            | (None, Some((_, binding_type)), Some((literal_type, _)), None) => {
                (integer(binding_type) && integer(literal_type))
                    || (matches!(operator.kind(), "==" | "!=")
                        && binding_type == DeclaredScalarType::Boolean
                        && literal_type == DeclaredScalarType::Boolean)
            }
            _ => false,
        }
    }

    /// The exact type syntax a bounded expression path inherits.
    ///
    /// This deliberately handles only binding paths, parentheses, builtin
    /// reference construction/dereference, struct construction, casts, and a
    /// uniquely named same-file function's declared result. User `Deref`,
    /// indirect/ambiguous calls, projections, and inferred literal defaults
    /// need resolver/type-checker facts this intrafile producer does not own.
    fn expression_type(&self, node: Node<'tree>) -> Option<RustValueType<'tree>> {
        let node = unwrap_attributes(node);
        if let Some(ty) = self
            .expression_values
            .get(&node.id())
            .and_then(|value| self.value_types.get(value))
            .copied()
        {
            return Some(ty);
        }
        let mut current = node;
        let mut operations = Vec::new();
        let mut ty = loop {
            current = unwrap_attributes(current);
            match current.kind() {
                "parenthesized_expression" => current = first_named_child(current)?,
                "identifier" | "self" => {
                    break self
                        .binding_value(current)
                        .and_then(|value| self.value_types.get(&value).copied())?;
                }
                "unary_expression" => {
                    operations.push(RustTypeOperation::Dereference);
                    current = rust_dereference_operand(current)?;
                }
                "reference_expression" => {
                    operations.push(RustTypeOperation::Borrow {
                        mutable: rust_reference_is_mutable(current),
                    });
                    current = rust_reference_expression_value(current)?;
                }
                "struct_expression" => {
                    break current
                        .child_by_field_name("name")
                        .map(RustValueType::Declared)?;
                }
                "type_cast_expression" => {
                    break current
                        .child_by_field_name("type")
                        .map(RustValueType::Declared)?;
                }
                "call_expression" => {
                    let function = current.child_by_field_name("function")?;
                    let function = call_function_target(function);
                    if function.kind() != "identifier" || self.binding_value(function).is_some() {
                        return None;
                    }
                    let name = node_text(self.source, function)?;
                    break self
                        .facts
                        .function_return_types
                        .get(name)
                        .copied()
                        .flatten()
                        .map(RustValueType::Declared)?;
                }
                _ => return None,
            }
        };
        for operation in operations.into_iter().rev() {
            ty = match operation {
                RustTypeOperation::Dereference => self.dereferenced_type(ty)?,
                RustTypeOperation::Borrow { mutable } => {
                    let RustValueType::Declared(referent) = ty else {
                        return None;
                    };
                    RustValueType::Borrowed { mutable, referent }
                }
            };
        }
        Some(ty)
    }

    fn is_standard_allocator_function(&self, function: Node<'tree>) -> bool {
        self.ownership
            .resolves_standard_path(function, &["core", "alloc", "alloc"])
            || self
                .ownership
                .resolves_standard_path(function, &["std", "alloc", "alloc"])
            || self
                .ownership
                .resolves_standard_path(function, &["alloc", "alloc", "alloc"])
    }

    fn dereferenced_type(&self, ty: RustValueType<'tree>) -> Option<RustValueType<'tree>> {
        match ty {
            RustValueType::Declared(reference) => {
                rust_reference_type_referent(reference).map(RustValueType::Declared)
            }
            RustValueType::Borrowed { referent, .. } => Some(RustValueType::Declared(referent)),
        }
    }

    fn expression_ownership(&self, node: Node<'tree>) -> RustOwnershipClass {
        let node = unwrap_attributes(node);
        if let Some(ty) = self.expression_type(node) {
            return match ty {
                RustValueType::Declared(ty) => self.ownership.classify_type(ty),
                RustValueType::Borrowed { mutable: true, .. } => {
                    RustOwnershipClass::MutableReference
                }
                RustValueType::Borrowed { mutable: false, .. } => {
                    RustOwnershipClass::SharedReference
                }
            };
        }
        if matches!(
            node.kind(),
            "integer_literal"
                | "float_literal"
                | "char_literal"
                | "boolean_literal"
                | "true"
                | "false"
        ) {
            RustOwnershipClass::ScalarCopy
        } else if node.kind() == "unit_expression" {
            RustOwnershipClass::AggregateCopy
        } else {
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::MissingType)
        }
    }

    fn exact_reference_alias(
        &self,
        source: RustValueType<'tree>,
        target: RustValueType<'tree>,
    ) -> Result<(), RustOwnershipIncomplete> {
        match (source, target) {
            (RustValueType::Declared(source), RustValueType::Declared(target)) => {
                match self.ownership.classify_reference_coercion(source, target) {
                    RustReferenceCoercion::SharedAlias
                    | RustReferenceCoercion::MutableAlias
                    | RustReferenceCoercion::MutableToSharedReborrow
                    | RustReferenceCoercion::ArrayReferenceToSlice => Ok(()),
                    RustReferenceCoercion::Incomplete(reason) => Err(reason),
                }
            }
            (RustValueType::Borrowed { mutable, referent }, RustValueType::Declared(target)) => {
                let target_referent = rust_reference_type_referent(target)
                    .ok_or(RustOwnershipIncomplete::UnsupportedType)?;
                self.exact_reference_parts(
                    mutable,
                    referent,
                    rust_reference_is_mutable(target),
                    target_referent,
                )
            }
            (
                RustValueType::Declared(source),
                RustValueType::Borrowed {
                    mutable: target_mutable,
                    referent: target_referent,
                },
            ) => {
                let source_referent = rust_reference_type_referent(source)
                    .ok_or(RustOwnershipIncomplete::UnsupportedType)?;
                self.exact_reference_parts(
                    rust_reference_is_mutable(source),
                    source_referent,
                    target_mutable,
                    target_referent,
                )
            }
            (
                RustValueType::Borrowed { mutable, referent },
                RustValueType::Borrowed {
                    mutable: target_mutable,
                    referent: target_referent,
                },
            ) => self.exact_reference_parts(mutable, referent, target_mutable, target_referent),
        }
    }

    fn exact_reference_parts(
        &self,
        mutable: bool,
        referent: Node<'tree>,
        target_mutable: bool,
        target_referent: Node<'tree>,
    ) -> Result<(), RustOwnershipIncomplete> {
        if target_mutable && !mutable {
            return Err(RustOwnershipIncomplete::UnsupportedType);
        }
        if self
            .ownership
            .exact_type_equivalence(referent, target_referent)?
        {
            return Ok(());
        }
        if referent.kind() == "array_type"
            && referent.child_by_field_name("length").is_some()
            && (target_referent.kind() == "slice_type"
                || (target_referent.kind() == "array_type"
                    && target_referent.child_by_field_name("length").is_none()))
        {
            let source_element = referent
                .child_by_field_name("element")
                .ok_or(RustOwnershipIncomplete::MissingType)?;
            let target_element = target_referent
                .child_by_field_name("element")
                .or_else(|| first_named_child(target_referent))
                .ok_or(RustOwnershipIncomplete::MissingType)?;
            if self
                .ownership
                .exact_type_equivalence(source_element, target_element)?
            {
                return Ok(());
            }
        }
        Err(RustOwnershipIncomplete::UnsupportedType)
    }

    fn compatible_transfer_ownership(
        &self,
        source: Node<'tree>,
        source_binding: Option<ValueId>,
        target_type: Option<RustValueType<'tree>>,
    ) -> RustOwnershipClass {
        if rust_node_is_in_unsafe_context(source) {
            return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType);
        }
        // Reuse the caller's already-selected binding and complete preindex
        // proof. Looking it up again would add an uncharged lexical walk.
        let bounded_copy = source_binding.and_then(|value| self.proven_copies.get(&value));
        let ownership = match bounded_copy {
            Some(TransferKind::Copy) => RustOwnershipClass::ScalarCopy,
            Some(TransferKind::AggregateCopy) => RustOwnershipClass::AggregateCopy,
            Some(_) => unreachable!("only Copy proofs enter proven_copies"),
            None => self.expression_ownership(source),
        };
        if ownership == RustOwnershipClass::Move {
            let mut current = source;
            while current.kind() == "parenthesized_expression" {
                let Some(inner) = first_named_child(current) else {
                    return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::MissingType);
                };
                current = inner;
            }
            if rust_dereference_operand(current).is_some() {
                return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType);
            }
        }
        let Some(target_type) = target_type else {
            return ownership;
        };
        let Some(source_type) = self.expression_type(source) else {
            return match target_type {
                RustValueType::Declared(target_type) => self
                    .ownership
                    .classify_literal_for_type(source, target_type),
                RustValueType::Borrowed { .. } => {
                    RustOwnershipClass::Incomplete(RustOwnershipIncomplete::MissingType)
                }
            };
        };
        match ownership {
            RustOwnershipClass::SharedReference | RustOwnershipClass::MutableReference => self
                .exact_reference_alias(source_type, target_type)
                .map_or_else(RustOwnershipClass::Incomplete, |_| ownership),
            RustOwnershipClass::ScalarCopy
            | RustOwnershipClass::AggregateCopy
            | RustOwnershipClass::Move => {
                let RustValueType::Declared(source_type) = source_type else {
                    return RustOwnershipClass::Incomplete(
                        RustOwnershipIncomplete::UnsupportedType,
                    );
                };
                let target_node = match target_type {
                    RustValueType::Declared(node) => node,
                    RustValueType::Borrowed { .. } => {
                        return RustOwnershipClass::Incomplete(
                            RustOwnershipIncomplete::UnsupportedType,
                        );
                    }
                };
                if source_type == target_node && bounded_copy.is_some() {
                    // Identical owner-backed type evidence, not generic-name
                    // equivalence: the bounded proof was attached at this binding.
                    return ownership;
                }
                match self.ownership.exact_type_equivalence(
                    source_type,
                    match target_type {
                        RustValueType::Declared(target_type) => target_type,
                        RustValueType::Borrowed { .. } => {
                            return RustOwnershipClass::Incomplete(
                                RustOwnershipIncomplete::UnsupportedType,
                            );
                        }
                    },
                ) {
                    Ok(true) => ownership,
                    Ok(false) => {
                        RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType)
                    }
                    Err(reason) => RustOwnershipClass::Incomplete(reason),
                }
            }
            RustOwnershipClass::Incomplete(_) => ownership,
        }
    }

    fn transfer_source_value(&self, node: Node<'tree>) -> Option<ValueId> {
        let mut current = node;
        loop {
            current = unwrap_attributes(current);
            match current.kind() {
                "parenthesized_expression" => current = first_named_child(current)?,
                "identifier" | "self" => return self.binding_value(current),
                _ => return None,
            }
        }
    }

    fn append_ownership_transfer(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        source_node: Node<'tree>,
        expression_source: ValueId,
        target: ValueId,
        target_type: Option<RustValueType<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let metadata = self.metadata(point)?;
        self.register_pointer_fact_target(expression_source, target, point, metadata);
        if let Some(leaf) = rust_transparent_value_leaf(source_node) {
            let leaf_value = self.expression_value(builder, leaf, expression_value_kind(leaf))?;
            self.register_pointer_fact_target(leaf_value, target, point, metadata);
        }
        let source_binding = self.transfer_source_value(source_node);
        let tracked_owner = source_binding.is_some_and(|source| {
            self.pointer_origins_by_owner.contains_key(&source)
                || self.pointer_owner_lifetimes.contains_key(&source)
                || self.manually_drop_values.contains(&source)
        });
        let classification = if tracked_owner {
            RustOwnershipClass::Move
        } else {
            self.compatible_transfer_ownership(source_node, source_binding, target_type)
        };
        let is_move = classification == RustOwnershipClass::Move;
        // Only an exact move consumes the binding itself. Copy and alias
        // relations keep the expression occurrence as their source, matching
        // the adapter's existing evaluation flow while giving a move kill the
        // binding identity that later-use reasoning observes.
        let source = if classification == RustOwnershipClass::Move {
            source_binding
                .filter(|source| *source != target)
                .unwrap_or(expression_source)
        } else {
            expression_source
        };
        let aliases = self
            .pointer_origins_by_pointer
            .get(&source)
            .cloned()
            .or_else(|| {
                self.transfer_source_value(source_node)
                    .and_then(|source| self.pointer_origins_by_pointer.get(&source).cloned())
            })
            .unwrap_or_default();
        let ownership_source = source_binding.unwrap_or(source);
        if let Some(origin) = self
            .pointer_origins_by_owner
            .get(&ownership_source)
            .copied()
        {
            self.pointer_origins_by_owner.insert(target, origin);
        }
        if let Some(lifetime) = self.owner_invalidation(ownership_source) {
            self.pointer_owner_lifetimes.insert(target, lifetime);
        }
        if let Some(pointee) = self.pointer_pointee(source_node) {
            self.pointer_pointees_by_value.insert(target, pointee);
        }
        if self.manually_drop_values.contains(&ownership_source) {
            self.manually_drop_values.insert(target);
        }
        if !aliases.is_empty() {
            for (origin, offset) in aliases {
                self.add_pointer_alias(
                    point,
                    target,
                    origin,
                    offset,
                    PointerRelationStrength::Must,
                    metadata,
                );
            }
        }
        if matches!(
            classification,
            RustOwnershipClass::AggregateCopy | RustOwnershipClass::Move
        ) && let Some(fields) = self.declared_struct_fields(source_node)
        {
            // The shared oracle requires copied contents at the transfer point.
            // Read them before a move consumes the source binding.
            for field in fields {
                self.append_struct_field_transfer(
                    builder,
                    point,
                    source_node,
                    source,
                    target,
                    field,
                )?;
            }
        }
        let kind = match classification {
            RustOwnershipClass::ScalarCopy => Some(TransferKind::Copy),
            RustOwnershipClass::AggregateCopy => Some(TransferKind::AggregateCopy),
            RustOwnershipClass::Move => Some(TransferKind::Move {
                invalidation: MoveInvalidation::Invalidated,
            }),
            RustOwnershipClass::SharedReference | RustOwnershipClass::MutableReference => None,
            RustOwnershipClass::Incomplete(reason) => {
                let mut ownership_source = source_node;
                while ownership_source.kind() == "parenthesized_expression" {
                    let Some(inner) = first_named_child(ownership_source) else {
                        break;
                    };
                    ownership_source = inner;
                }
                // Copy versus move changes the meaning only when a transfer
                // reads reusable source storage. A fresh rvalue has no source
                // binding to preserve or invalidate, so its constructor,
                // call, or operator lowering owns any remaining gap. Exact
                // reference coercions and dereferences still need an ownership
                // decision because they select aliasing or place semantics.
                let needs_exact_ownership = self.transfer_source_value(source_node).is_some()
                    || matches!(
                        ownership_source.kind(),
                        "reference_expression" | "unary_expression"
                    );
                if !needs_exact_ownership || self.expression_type(source_node).is_none() {
                    self.append_assignment_value_flow(
                        builder,
                        point,
                        source,
                        target,
                        ValueFlowKind::Local,
                    )?;
                    return Ok(());
                }
                self.append_assignment_value_flow(
                    builder,
                    point,
                    source,
                    target,
                    ValueFlowKind::LanguageDefined,
                )?;
                self.session.record_gap(
                    builder,
                    point,
                    SemanticGapSubject::Value(target),
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    ownership_gap_detail(reason),
                )?;
                return Ok(());
            }
        };
        self.append_assignment_value_flow(
            builder,
            point,
            source,
            target,
            kind.map_or(ValueFlowKind::Local, |kind| {
                ValueFlowKind::Transfer(ValueTransfer {
                    kind,
                    operation: TransferOperation::None,
                })
            }),
        )?;
        if is_move {
            self.transfer_pointer_owner_facts(source, target);
            let metadata = self.metadata(point)?;
            if let Some(place) = self.binding_places.get(&source).cloned() {
                self.move_outs.push(MoveOutFact {
                    place,
                    point,
                    source_value: source,
                    target_value: target,
                    state_after: MoveOutState::Uninitialized,
                    source: metadata.source,
                    evidence: metadata.evidence,
                });
            } else if matches!(source_node.kind(), "field_expression" | "index_expression")
                && let Some(base) = source_node
                    .child_by_field_name("value")
                    .and_then(|base| self.binding_value(base))
                && let Some(place) = self.binding_places.get(&base).cloned()
            {
                self.move_outs.push(MoveOutFact {
                    place: place.clone(),
                    point,
                    source_value: source,
                    target_value: target,
                    state_after: MoveOutState::PartiallyInitialized,
                    source: metadata.source,
                    evidence: metadata.evidence,
                });
                self.add_incomplete_fact(
                    point,
                    SemanticIncompleteSubject::Place(place),
                    SemanticIncompleteReason::Lifecycle(LifecycleIncompleteReason::PartialMove),
                    metadata,
                );
            }
        }
        Ok(())
    }

    /// Establish a binding from its selected value and the caller's flow proof.
    /// Component callers supply a projected/captured value, not the aggregate's
    /// AST expression; this primitive performs no whole-binding ownership lookup.
    fn append_assignment_value_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        source: ValueId,
        target: ValueId,
        kind: ValueFlowKind,
    ) -> Result<(), RustLoweringError> {
        self.append_effect(
            builder,
            point,
            SemanticEffect::Assignment {
                target,
                value: source,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind,
                source,
                target,
            },
        )
    }

    fn append_consumed_move(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        source_node: Node<'tree>,
        target_value: ValueId,
    ) -> Result<(), RustLoweringError> {
        let Some(source_value) = self.transfer_source_value(source_node) else {
            return Ok(());
        };
        if source_value == target_value {
            return Ok(());
        }
        self.append_effect(
            builder,
            point,
            SemanticEffect::Assignment {
                target: target_value,
                value: source_value,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Transfer(ValueTransfer {
                    kind: TransferKind::Move {
                        invalidation: MoveInvalidation::Invalidated,
                    },
                    operation: TransferOperation::None,
                }),
                source: source_value,
                target: target_value,
            },
        )?;
        if let Some(place) = self.binding_places.get(&source_value).cloned() {
            let metadata = self.metadata(point)?;
            self.move_outs.push(MoveOutFact {
                place,
                point,
                source_value,
                target_value,
                state_after: MoveOutState::Uninitialized,
                source: metadata.source,
                evidence: metadata.evidence,
            });
        }
        self.transfer_pointer_owner_facts(source_value, target_value);
        Ok(())
    }

    /// The shape this expression's value provably holds.
    ///
    /// A reference is transparent on purpose: Rust auto-dereferences a
    /// reference to a struct, so `holder.value` and `alias.value` project the
    /// same field of the same struct type, and `&` is the language's own
    /// borrow rather than a user `Deref` implementation.
    fn expression_shape(&self, node: Node<'_>) -> Option<RustValueShape> {
        // A borrow, a parenthesis chain, and an access path are all unbounded
        // in source, so the walk down to the root is a loop and the selectors
        // it collected are applied afterwards rather than by recursion.
        let mut selectors = Vec::new();
        let mut current = node;
        let root = loop {
            current = unwrap_attributes(current);
            match current.kind() {
                "identifier" | "self" => {
                    let name = node_text(self.source, current)?;
                    let value = self
                        .local_at(name, current.start_byte())
                        .or_else(|| self.parameters.get(name).copied())
                        .or_else(|| self.captured_bindings.get(name).copied())?;
                    break self.value_shapes.get(&value).cloned()?;
                }
                "parenthesized_expression" => current = first_named_child(current)?,
                "reference_expression" => current = current.child_by_field_name("value")?,
                "field_expression" => {
                    selectors.push(node_text(
                        self.source,
                        current.child_by_field_name("field")?,
                    )?);
                    current = current.child_by_field_name("value")?;
                }
                "struct_expression" => {
                    break rust_declared_type_shape(
                        self.source,
                        current.child_by_field_name("name")?,
                    )?;
                }
                "array_expression" => {
                    break RustValueShape::Array {
                        primitive_elements: runtime_expression_children(current)
                            .into_iter()
                            .all(|element| self.expression_is_definitely_non_dropping(element)),
                    };
                }
                _ => return None,
            }
        };
        let mut shape = root;
        for selector in selectors.into_iter().rev() {
            let RustValueShape::Struct(owner) = shape else {
                return None;
            };
            shape = self
                .facts
                .struct_fields
                .get(&(owner, selector.into()))?
                .as_ref()?
                .shape
                .clone()?;
        }
        Some(shape)
    }

    /// What this file declares about the field `base.field` names, when the
    /// base's shape picks exactly one struct declaration.
    fn field_declaration(&self, base: Node<'_>, field: Node<'_>) -> Option<RustFieldDeclaration> {
        let RustValueShape::Struct(name) = self.expression_shape(base)? else {
            return None;
        };
        let field = node_text(self.source, field)?;
        self.facts
            .struct_fields
            .get(&(name, field.into()))
            .cloned()
            .flatten()
    }

    /// The complete named field set of one unambiguous, non-generic struct
    /// declaration in this file. Unknown layouts never become an empty set.
    fn declared_struct_fields(&self, node: Node<'tree>) -> Option<Vec<Node<'tree>>> {
        let RustValueShape::Struct(owner) = self.expression_shape(node)? else {
            return None;
        };
        let body = self
            .facts
            .struct_field_lists
            .get(&owner)
            .copied()
            .flatten()?;
        Some(
            named_children(body)
                .into_iter()
                .filter(|field| field.kind() == "field_declaration")
                .map(|field| {
                    field
                        .child_by_field_name("name")
                        .expect("Rust field declaration has a name")
                })
                .collect(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_struct_field_transfer(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        structure: Node<'tree>,
        source: ValueId,
        target: ValueId,
        field: Node<'tree>,
    ) -> Result<(), RustLoweringError> {
        let (member, resolved, exact_member_key) = self.memory_member_locator(structure, field)?;
        let source_location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Field {
                base: source,
                member: member.clone(),
            },
        )?;
        let target_location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Field {
                base: target,
                member,
            },
        )?;
        if !resolved {
            self.add_field_identity_gap(builder, point, source_location, exact_member_key)?;
            self.add_field_identity_gap(builder, point, target_location, exact_member_key)?;
        }
        let value = self.value(builder, point, SemanticValueKind::Temporary)?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Field,
                location: source_location,
                result: value,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::Field,
                location: target_location,
                value,
            },
        )
    }

    /// Whether a field expression denotes no runtime memory location.
    ///
    /// One shape reads like a field access but is not one: a method call's
    /// callee (`receiver.method(...)`), whose selection the call site already
    /// models. Minting a `Field` location for it would publish an
    /// undischargeable field-memory gap on syntax that holds nothing.
    fn field_denotes_no_location(&self, node: Node<'tree>) -> bool {
        let mut current = node;
        while let Some(parent) = current.parent() {
            match parent.kind() {
                "generic_function" => current = parent,
                "call_expression" => {
                    return field_matches(parent, "function", current)
                        && parent
                            .child_by_field_name("function")
                            .is_some_and(|function| rust_method_call_parts(function).is_some());
                }
                _ => return false,
            }
        }
        false
    }

    /// Whether reading or writing this place runs only the language's own
    /// projection.
    ///
    /// A field of a struct this file declares is a direct projection: no
    /// autoderef step past a user `Deref`, and no `DerefMut` on the write
    /// side. A subscript of a fixed-size array is the language's own indexing,
    /// not an `Index` or `IndexMut` implementation. Any other place keeps the
    /// `Calls` gap that says an implicit trait method may run here.
    fn place_access_is_language_defined(&self, place: Node<'_>) -> bool {
        let place = unwrap_attributes(place);
        match place.kind() {
            "field_expression" => place
                .child_by_field_name("value")
                .zip(place.child_by_field_name("field"))
                .and_then(|(base, field)| self.field_declaration(base, field))
                .is_some(),
            "index_expression" => {
                let children = runtime_expression_children(place);
                let [base, _] = children.as_slice() else {
                    return false;
                };
                matches!(
                    self.expression_shape(*base),
                    Some(RustValueShape::Array { .. })
                )
            }
            _ => false,
        }
    }

    /// The member identity of `base.field`, and whether this file knows its
    /// declaration. An unresolved named selector or tuple index gets the same
    /// canonical locator in every procedure and file; declaration/type
    /// resolution remains a separate gap.
    fn memory_member_locator(
        &mut self,
        base: Node<'tree>,
        field: Node<'tree>,
    ) -> Result<(SemanticLocator, bool, bool), RustLoweringError> {
        let procedure = self.session.locator();
        let declaration = self.field_declaration(base, field);
        if let Some(declaration) = declaration {
            let RustValueShape::Struct(owner) = self
                .expression_shape(base)
                .expect("field declaration resolution has a structured base")
            else {
                unreachable!("field declaration resolution requires a struct base")
            };
            let owner = DeclarationSegment::named(
                DeclarationSegmentKind::Type,
                owner.to_string(),
                declaration.anchor,
                0,
            )
            .expect("a declared Rust struct has a non-empty identifier");
            let declaration_path = DeclarationLocator::new(vec![owner])
                .expect("a Rust field locator has its owning struct segment");
            return Ok((
                SemanticLocator::new(
                    procedure.mount(),
                    procedure.path().clone(),
                    procedure.language(),
                    declaration_path,
                    SemanticRole::MemoryLocation,
                    declaration.anchor,
                ),
                true,
                true,
            ));
        }

        if let Some(member_key) = rust_field_member_key(self.source, field) {
            // Rust auto-deref through user Deref/DerefMut is assumed to return
            // the same target for the same base object. A Deref that returns
            // different objects per call is outside this identity contract.
            return Ok((
                self.canonical_field_member_locator(&member_key),
                false,
                true,
            ));
        }

        let anchor = source_anchor(field, 0).map_err(RustLoweringError::Invalid)?;
        Ok((procedure.memory_location_at(anchor), false, false))
    }

    fn canonical_field_member_locator(&self, member_key: &str) -> SemanticLocator {
        let procedure = self.session.locator();
        let position = SourcePosition::new(0, 0, 0);
        let span = SourceSpan::new(position, position)
            .expect("zero-width canonical member anchor is valid");
        let anchor = SourceAnchor::new(span, 0);
        let member = DeclarationSegment::named(
            DeclarationSegmentKind::Namespace,
            format!("rust-field:{member_key}"),
            anchor,
            0,
        )
        .expect("structured Rust member keys are non-empty");
        let declaration = DeclarationLocator::new(vec![member])
            .expect("a canonical Rust member locator has one segment");
        let path = WorkspaceRelativePath::new(crate::analyzer::semantic::RUST_FIELD_MEMBER_PATH)
            .expect("canonical Rust member path is portable");
        SemanticLocator::new(
            procedure.mount(),
            path,
            procedure.language(),
            declaration,
            SemanticRole::MemoryLocation,
            anchor,
        )
    }

    fn add_field_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
        exact_member_key: bool,
    ) -> Result<(), RustLoweringError> {
        if exact_member_key {
            // Declaration/type uncertainty does not affect memory identity:
            // the structured member key identifies one field of a proven base.
            self.session.add_gap_with_exact_impacts(
                builder,
                point,
                SemanticGapSubject::MemoryLocation(location),
                SemanticCapability::FieldMemory,
                SemanticGapImpacts::NONE,
                SemanticGapKind::Unknown,
                "Rust field declaration/type is unresolved; the AST member key is exact",
            )?;
        } else {
            self.session.add_unknown_field_identity_gap(
                builder,
                point,
                location,
                "Rust field occurrence has no resolved declaration or supported AST member key",
            )?;
        }
        Ok(())
    }

    /// The index value of `base[index]`, when the index is a Rust integer
    /// literal whose magnitude can be represented in `u128`.
    ///
    /// A store and a load meet on an exact index only when both name the same
    /// value, so one value is interned per distinct numeric magnitude. A
    /// non-literal or unrepresentable index has no proven identity here and
    /// yields `None`, which the caller turns into an `Any` index plus an
    /// index-memory gap.
    fn canonical_integer_index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<(ValueId, u128)>, RustLoweringError> {
        let Some(index) = rust_integer_literal_value(self.source, node) else {
            return Ok(None);
        };
        if let Some(value) = brokk_bifrost_analysis::analyzer::common::reuse_cached_expression_value(
            &self.constant_index_values,
            &mut self.expression_values,
            index,
            node.id(),
        ) {
            return Ok(Some((value, index)));
        }
        let value =
            self.expression_value(builder, node, SemanticValueKind::UnsignedInteger(index))?;
        self.constant_index_values.insert(index, value);
        Ok(Some((value, index)))
    }

    fn array_ordinal_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        ordinal: u128,
    ) -> Result<ValueId, RustLoweringError> {
        if let Some(value) = self.constant_index_values.get(&ordinal).copied() {
            return Ok(value);
        }
        let metadata = self.value_mapping(builder, node)?;
        let value = self.session.add_value_with_metadata(
            builder,
            metadata,
            SemanticValueKind::UnsignedInteger(ordinal),
        )?;
        self.constant_index_values.insert(ordinal, value);
        Ok(value)
    }

    fn emit_array_element_store(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        array: Node<'tree>,
        base: ValueId,
        ordinal: u128,
        value: ValueId,
    ) -> Result<(), RustLoweringError> {
        let index = self.array_ordinal_value(builder, array, ordinal)?;
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Index {
                base,
                index: Some(index),
                constant_index: Some(ordinal),
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::Index,
                location,
                value,
            },
        )?;
        Ok(())
    }

    fn index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<(ValueId, u128)>, RustLoweringError> {
        self.canonical_integer_index_value(builder, node)
    }

    fn add_dynamic_index_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), RustLoweringError> {
        self.session.add_unprojected_index_gap(
            builder,
            point,
            location,
            "Rust dynamic index identity is not proven",
        )
    }

    fn add_repeat_array_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), RustLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::IndexMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unsupported,
            "Rust repeated-array length is not a bounded integer literal, so precise element stores are not materialized",
        )?;
        Ok(())
    }

    /// Whether this expression names storage this procedure already holds,
    /// rather than producing a fresh temporary.
    ///
    /// An identifier qualifies only when it resolves to a local or a
    /// parameter. A bare path that names a unit struct or a constant --
    /// `Guard`, `None` -- is spelled the same way and produces a new value, so
    /// borrowing it does extend a temporary's lifetime.
    fn is_place(&self, node: Node<'_>) -> bool {
        let mut current = node;
        loop {
            current = unwrap_attributes(current);
            match current.kind() {
                "identifier" | "self" => {
                    let Some(name) = node_text(self.source, current) else {
                        return false;
                    };
                    return self
                        .local_at(name, current.start_byte())
                        .or_else(|| self.parameters.get(name).copied())
                        .or_else(|| self.captured_bindings.get(name).copied())
                        .is_some();
                }
                "field_expression" => {
                    let Some(base) = current.child_by_field_name("value") else {
                        return false;
                    };
                    current = base;
                }
                "index_expression" | "parenthesized_expression" => {
                    let Some(inner) = first_named_child(current) else {
                        return false;
                    };
                    current = inner;
                }
                "unary_expression" => {
                    let Some(operand) = rust_dereference_operand(current) else {
                        return false;
                    };
                    return self
                        .expression_type(operand)
                        .and_then(|ty| self.dereferenced_type(ty))
                        .is_some();
                }
                _ => return false,
            }
        }
    }

    /// Whether this expression's value provably owns no `Drop`.
    ///
    /// A literal, a binding already proven non-dropping, a borrow of a place,
    /// an operator applied to non-dropping operands, a cast to a primitive, a
    /// call to a same-file `fn` with a non-dropping return type, an array or
    /// struct literal whose parts are themselves proven, and a read of a
    /// primitive field or element all produce a value that runs no destructor.
    /// Anything else answers `false`, which keeps the drop-omission gaps.
    ///
    /// The walk is an explicit worklist rather than recursion: operator nesting
    /// in a source file is unbounded.
    fn expression_is_definitely_non_dropping(&self, node: Node<'_>) -> bool {
        let mut pending = vec![node];
        while let Some(node) = pending.pop() {
            let node = unwrap_attributes(node);
            if matches!(
                expression_value_kind(node),
                SemanticValueKind::Constant | SemanticValueKind::Boolean(_)
            ) {
                continue;
            }
            match node.kind() {
                "identifier" => {
                    let proven = node_text(self.source, node)
                        .and_then(|name| {
                            self.local_at(name, node.start_byte())
                                .or_else(|| self.parameters.get(name).copied())
                                .or_else(|| self.captured_bindings.get(name).copied())
                        })
                        .is_some_and(|value| self.definitely_non_dropping.contains(&value));
                    if !proven {
                        return false;
                    }
                }
                // Borrowing a place -- a local, a field, an element -- owns
                // nothing and extends nothing: the referent already lives as
                // long as whatever binds it, and its own binding answers the
                // drop question. Borrowing anything else produces a temporary
                // whose lifetime the borrow extends to the end of the
                // enclosing block, so `&Guard::new()` does run a `Drop` there
                // and keeps the gaps.
                "reference_expression" => {
                    if !node
                        .child_by_field_name("value")
                        .is_some_and(|operand| self.is_place(operand))
                    {
                        return false;
                    }
                }
                "binary_expression" | "unary_expression" | "parenthesized_expression" => {
                    let operands = runtime_expression_children(node);
                    if operands.is_empty() {
                        return false;
                    }
                    pending.extend(operands);
                }
                "type_cast_expression" => {
                    if !node
                        .child_by_field_name("type")
                        .is_some_and(|ty| ty.kind() == "primitive_type")
                    {
                        return false;
                    }
                }
                // An array owns whatever its elements own and nothing else:
                // `[T; N]` has no user `Drop` implementation of its own.
                "array_expression" => {
                    pending.extend(runtime_expression_children(node));
                }
                // A struct literal of a struct this file proves plain: every
                // field is a primitive or another plain struct, and this file
                // states no `impl Drop` for it.
                "struct_expression" => {
                    let plain = node
                        .child_by_field_name("name")
                        .filter(|name| name.kind() == "type_identifier")
                        .and_then(|name| node_text(self.source, name))
                        .is_some_and(|name| self.facts.plain_structs.contains(name));
                    if !plain {
                        return false;
                    }
                    pending.extend(runtime_expression_children(node));
                }
                // The initializer list itself carries no value; what it holds
                // are the field values, and those decide.
                "field_initializer_list"
                | "field_initializer"
                | "shorthand_field_initializer"
                | "base_field_initializer" => {
                    pending.extend(runtime_expression_children(node));
                }
                // Reading a field or an element whose declared type is a
                // primitive produces a primitive.
                "field_expression" => {
                    let primitive = node
                        .child_by_field_name("value")
                        .zip(node.child_by_field_name("field"))
                        .and_then(|(base, field)| self.field_declaration(base, field))
                        .is_some_and(|declaration| declaration.primitive);
                    if !primitive {
                        return false;
                    }
                }
                "index_expression" => {
                    let children = runtime_expression_children(node);
                    let [base, _] = children.as_slice() else {
                        return false;
                    };
                    if !matches!(
                        self.expression_shape(*base),
                        Some(RustValueShape::Array {
                            primitive_elements: true
                        })
                    ) {
                        return false;
                    }
                }
                "call_expression" => {
                    let non_dropping_result = node
                        .child_by_field_name("function")
                        .filter(|function| function.kind() == "identifier")
                        .and_then(|function| node_text(self.source, function))
                        .and_then(|name| self.facts.non_dropping_return_functions.get(name))
                        .copied()
                        .unwrap_or(false);
                    if !non_dropping_result {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    /// Whether writing over this assignment target can run a destructor.
    ///
    /// Assignment drops the value it replaces. When the target is a binding
    /// this procedure already proved holds no `Drop`, or a field or element
    /// whose declared type is a primitive, nothing is dropped, and the
    /// drop-omission gaps would be claiming a cleanup that cannot happen. Any
    /// other target -- a dereference, a destructuring pattern, a name this
    /// procedure does not bind -- keeps them.
    fn assignment_replaces_droppable_value(&self, left: Node<'_>) -> bool {
        let left = unwrap_attributes(left);
        match left.kind() {
            "identifier" => {
                let Some(name) = node_text(self.source, left) else {
                    return true;
                };
                self.local_at(name, left.start_byte())
                    .or_else(|| self.parameters.get(name).copied())
                    .or_else(|| self.captured_bindings.get(name).copied())
                    .is_none_or(|target| !self.definitely_non_dropping.contains(&target))
            }
            // Overwriting a field or an element whose declared type is a
            // primitive drops nothing: a primitive is `Copy` and cannot
            // implement `Drop`.
            "field_expression" | "index_expression" => {
                !self.expression_is_definitely_non_dropping(left)
            }
            _ => true,
        }
    }

    fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, RustLoweringError> {
        let node = unwrap_attributes(node);
        let kind = if node.kind() == "reference_expression" && rust_reference_is_mutable(node) {
            SemanticValueKind::Address
        } else {
            rust_literal_value_kind(self.source, node).unwrap_or(kind)
        };
        self.session.cached_node_value(
            builder,
            &mut self.expression_values,
            node,
            kind,
            |session, builder, node| session.add_node_mapping(builder, node),
        )
    }
    fn source_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, RustLoweringError> {
        let metadata = self.value_mapping(builder, node)?;
        self.session
            .add_value_with_metadata(builder, metadata, kind)
    }

    fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), RustLoweringError> {
        let Some(name) = node_text(self.source, node) else {
            return Ok(());
        };
        let (source, kind) = if node.kind() == "self" {
            self.captured_bindings
                .get(name)
                .copied()
                .map(|value| (Some(value), ValueFlowKind::Local))
                .unwrap_or((self.receiver, ValueFlowKind::Receiver))
        } else if node.kind() == "identifier" {
            if let Some(local) = self.local_at(name, node.start_byte()) {
                (Some(local), ValueFlowKind::Local)
            } else if let Some(captured) = self.captured_bindings.get(name).copied() {
                (Some(captured), ValueFlowKind::Local)
            } else {
                (self.parameters.get(name).copied(), ValueFlowKind::Parameter)
            }
        } else {
            (None, ValueFlowKind::Local)
        };
        if let Some(source) = source {
            if source != target {
                // The read is spelled by the name itself, not by the enclosing
                // evaluation's point: for `x = y` that point is the whole
                // assignment.
                let metadata = self.value_mapping(builder, node)?;
                self.session.append_effect_with_metadata(
                    builder,
                    point,
                    metadata,
                    SemanticEffect::ValueFlow {
                        kind,
                        source,
                        target,
                    },
                )?;
            }
        } else if node.kind() == "identifier"
            && let Some(location) = self.static_location(builder, point, node, name)?
        {
            let metadata = self.value_mapping(builder, node)?;
            self.session.append_effect_with_metadata(
                builder,
                point,
                metadata,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Static,
                    location,
                    result: target,
                },
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        match (node.kind(), rust_boolean_operator(node)) {
            ("binary_expression", Some(operator @ ("&&" | "||"))) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let kind = match operator {
                    "&&" => ShortCircuitKind::And,
                    "||" => ShortCircuitKind::Or,
                    _ => unreachable!("the match arm selects Rust boolean operators"),
                };
                schedule_short_circuit_condition(
                    stack,
                    kind,
                    (left, entry),
                    (right, right_entry),
                    when_true,
                    when_false,
                    scope,
                    |node, entry, when_true, when_false, scope| Work::Condition {
                        node,
                        entry,
                        when_true,
                        when_false,
                        scope,
                    },
                );
                Ok(())
            }
            ("let_chain", _) => {
                let conditions = runtime_expression_children(node);
                self.schedule_condition_chain(
                    builder,
                    entry,
                    &conditions,
                    when_true,
                    when_false,
                    scope,
                    stack,
                )
            }
            ("parenthesized_expression", _) => {
                let value = first_named_child(node).ok_or_else(|| missing_field(node, "value"))?;
                stack.push(Work::Condition {
                    node: value,
                    entry,
                    when_true,
                    when_false,
                    scope,
                });
                Ok(())
            }
            ("unary_expression", _)
                if node.child(0).is_some_and(|operator| operator.kind() == "!") =>
            {
                let operand = node
                    .named_child(0)
                    .ok_or_else(|| missing_field(node, "operand"))?;
                stack.push(Work::Condition {
                    node: operand,
                    entry,
                    when_true: when_false,
                    when_false: when_true,
                    scope,
                });
                Ok(())
            }
            _ => {
                let decision = self.point(builder, node, Vec::new())?;
                self.session.add_target_edge(builder, decision, when_true)?;
                self.session
                    .add_target_edge(builder, decision, when_false)?;

                let normalized = self.normalize_condition(builder, node)?;
                let (predicate, subject, true_target, false_target) = if let Some(normalized) =
                    normalized
                {
                    let (true_target, false_target) = if normalized.predicate_true_on_condition_true
                    {
                        (when_true, when_false)
                    } else {
                        (when_false, when_true)
                    };
                    (
                        normalized.predicate,
                        normalized.subject,
                        true_target,
                        false_target,
                    )
                } else {
                    (
                        GuardPredicate::Opaque {
                            digest: GuardConditionDigest::from_syntax_kind(node.kind()),
                        },
                        Some(self.expression_value(builder, node, expression_value_kind(node))?),
                        when_true,
                        when_false,
                    )
                };
                let arm = |target: EdgeTarget| {
                    Some(GuardArm {
                        target_point: target.point,
                        kind: target.kind,
                    })
                };
                self.session.add_guard_fact(
                    builder,
                    decision,
                    predicate,
                    subject,
                    arm(true_target),
                    arm(false_target),
                )?;
                stack.push(Work::Expression {
                    node,
                    entry,
                    next: EdgeTarget::normal(decision),
                    scope,
                });
                Ok(())
            }
        }
    }

    fn normalize_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<RustNormalizedGuard>, RustLoweringError> {
        let node = peel_rust_parentheses(node);
        if let Some(value) = rust_constant_condition(node) {
            return Ok(Some(RustNormalizedGuard {
                predicate: GuardPredicate::ConstantBoolean { value },
                subject: None,
                predicate_true_on_condition_true: true,
            }));
        }
        if let Some((_, DeclaredScalarType::Boolean)) = self.scalar_binding_operand(node) {
            let subject = self.expression_value(builder, node, expression_value_kind(node))?;
            return Ok(Some(RustNormalizedGuard {
                predicate: GuardPredicate::Truthy { value: subject },
                subject: Some(subject),
                predicate_true_on_condition_true: true,
            }));
        }
        if node.kind() != "binary_expression" {
            return Ok(None);
        }
        let (Some(operator), Some(left), Some(right)) = (
            node.child_by_field_name("operator"),
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return Ok(None);
        };
        let operator = operator.kind();
        let left = peel_rust_parentheses(left);
        let right = peel_rust_parentheses(right);
        let left_binding = self.scalar_binding_operand(left);
        let right_binding = self.scalar_binding_operand(right);
        let integer = |scalar_type| {
            matches!(
                scalar_type,
                DeclaredScalarType::Signed(_) | DeclaredScalarType::Unsigned(_)
            )
        };
        if let (Some((left_value, left_type)), Some((right_value, right_type))) =
            (left_binding, right_binding)
            && left_value == right_value
            && ((integer(left_type) && integer(right_type))
                || (left_type == DeclaredScalarType::Boolean
                    && right_type == DeclaredScalarType::Boolean
                    && matches!(operator, "==" | "!=")))
        {
            let value = match operator {
                "<" | ">" | "!=" => false,
                "<=" | ">=" | "==" => true,
                _ => return Ok(None),
            };
            return Ok(Some(RustNormalizedGuard {
                predicate: GuardPredicate::ConstantBoolean { value },
                subject: None,
                predicate_true_on_condition_true: true,
            }));
        }

        let left_literal = self.scalar_constant_operand(left);
        let right_literal = self.scalar_constant_operand(right);
        if let Some((subject, subject_type, constant, constant_type, constant_value, reversed)) =
            match (left_binding, right_binding, left_literal, right_literal) {
                (Some((_, subject_type)), None, None, Some((constant_type, constant_value))) => {
                    Some((
                        left,
                        subject_type,
                        right,
                        constant_type,
                        constant_value,
                        false,
                    ))
                }
                (None, Some((_, subject_type)), Some((constant_type, constant_value)), None) => {
                    Some((
                        right,
                        subject_type,
                        left,
                        constant_type,
                        constant_value,
                        true,
                    ))
                }
                _ => None,
            }
        {
            if integer(subject_type) && integer(constant_type) {
                let constant = if let Some(value) = constant_value {
                    self.expression_value(
                        builder,
                        constant,
                        SemanticValueKind::UnsignedInteger(value),
                    )?
                } else {
                    self.expression_value(builder, constant, expression_value_kind(constant))?
                };
                let subject =
                    self.expression_value(builder, subject, expression_value_kind(subject))?;
                let relation = match operator {
                    "<" => Some(IntegerComparison::LessThan),
                    "<=" => Some(IntegerComparison::LessThanOrEqual),
                    ">" => Some(IntegerComparison::GreaterThan),
                    ">=" => Some(IntegerComparison::GreaterThanOrEqual),
                    _ => None,
                };
                let predicate = match (relation, operator) {
                    (Some(relation), _) => GuardPredicate::OrderedIntegerComparison {
                        relation: if reversed {
                            relation.reverse()
                        } else {
                            relation
                        },
                        constant,
                    },
                    (None, "==") => GuardPredicate::ConstantEquality {
                        negated: false,
                        constant,
                    },
                    (None, "!=") => GuardPredicate::ConstantEquality {
                        negated: true,
                        constant,
                    },
                    (None, _) => return Ok(None),
                };
                return Ok(Some(RustNormalizedGuard {
                    predicate,
                    subject: Some(subject),
                    predicate_true_on_condition_true: true,
                }));
            }

            if subject_type == DeclaredScalarType::Boolean
                && constant_type == DeclaredScalarType::Boolean
                && matches!(operator, "==" | "!=")
            {
                let Some(constant_value) = rust_boolean_literal_value(self.source, constant) else {
                    return Ok(None);
                };
                let subject =
                    self.expression_value(builder, subject, expression_value_kind(subject))?;
                let predicate_true_on_condition_true = if operator == "==" {
                    constant_value
                } else {
                    !constant_value
                };
                return Ok(Some(RustNormalizedGuard {
                    predicate: GuardPredicate::Truthy { value: subject },
                    subject: Some(subject),
                    predicate_true_on_condition_true,
                }));
            }
        }

        // A reviewed built-in operation can produce a scalar value without
        // leaving a declared scalar type on the local. Keep the comparison
        // fact structured in that case: the scalar operator gap remains, so
        // this row does not claim that an unresolved implementation is a
        // built-in operation. The row still gives the taint plan the exact
        // binding and edge needed for its source-selective barrier.
        let left_constant = self.rust_integer_constant_value(left);
        let right_constant = self.rust_integer_constant_value(right);
        if let Some((
            fallback_subject,
            fallback_constant_node,
            fallback_constant_value,
            fallback_reversed,
        )) = match (left_constant, right_constant) {
            (Some(value), None) => Some((right, left, value, true)),
            (None, Some(value)) => Some((left, right, value, false)),
            (Some(_), Some(_)) | (None, None) => None,
        } {
            let constant = self.expression_value(
                builder,
                fallback_constant_node,
                SemanticValueKind::UnsignedInteger(fallback_constant_value),
            )?;
            let subject = self.expression_value(
                builder,
                fallback_subject,
                expression_value_kind(fallback_subject),
            )?;
            let relation = match operator {
                "<" => Some(IntegerComparison::LessThan),
                "<=" => Some(IntegerComparison::LessThanOrEqual),
                ">" => Some(IntegerComparison::GreaterThan),
                ">=" => Some(IntegerComparison::GreaterThanOrEqual),
                _ => None,
            };
            let predicate = match (relation, operator) {
                (Some(relation), _) => GuardPredicate::OrderedIntegerComparison {
                    relation: if fallback_reversed {
                        relation.reverse()
                    } else {
                        relation
                    },
                    constant,
                },
                (None, "==") => GuardPredicate::ConstantEquality {
                    negated: false,
                    constant,
                },
                (None, "!=") => GuardPredicate::ConstantEquality {
                    negated: true,
                    constant,
                },
                (None, _) => return Ok(None),
            };
            return Ok(Some(RustNormalizedGuard {
                predicate,
                subject: Some(subject),
                predicate_true_on_condition_true: true,
            }));
        }
        Ok(None)
    }

    fn rust_integer_constant_value(&self, node: Node<'tree>) -> Option<u128> {
        let node = unwrap_attributes(node);
        if let Some(value) = rust_integer_literal_value(self.source, node) {
            return Some(value);
        }
        if node.kind() != "identifier" || self.binding_value(node).is_some() {
            return None;
        }
        let name = node_text(self.source, node)?;
        self.facts.integer_constants.get(name).copied().flatten()
    }

    #[allow(clippy::too_many_arguments)]
    fn schedule_condition_chain(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        conditions: &[Node<'tree>],
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        if conditions.is_empty() {
            return self.session.add_target_edge(builder, entry, when_true);
        }
        let entries = conditions
            .iter()
            .map(|condition| self.point(builder, *condition, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.session
            .add_target_edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..conditions.len()).rev() {
            let success = entries
                .get(index + 1)
                .copied()
                .map(|point| EdgeTarget {
                    point,
                    kind: ControlEdgeKind::ConditionalTrue,
                })
                .unwrap_or(when_true);
            stack.push(Work::Condition {
                node: conditions[index],
                entry: entries[index],
                when_true: success,
                when_false,
                scope,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        match node.kind() {
            "block" => self.block(builder, node, entry, next, scope, stack),
            "expression_statement" => {
                let expression =
                    first_named_child(node).ok_or_else(|| missing_field(node, "expression"))?;
                stack.push(Work::Expression {
                    node: expression,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "let_declaration" => self.let_declaration(builder, node, entry, next, scope, stack),
            "function_item"
            | "function_signature_item"
            | "type_item"
            | "struct_item"
            | "enum_item"
            | "union_item"
            | "trait_item"
            | "impl_item"
            | "mod_item"
            | "use_declaration"
            | "extern_crate_declaration"
            | "macro_definition"
            | "foreign_mod_item"
            | "const_item"
            | "static_item"
            | "empty_statement"
            | "attribute_item"
            | "inner_attribute_item"
            | "attributes" => self.session.add_target_edge(builder, entry, next),
            _ if is_rust_expression(node.kind()) => {
                stack.push(Work::Expression {
                    node,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn block(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let children = named_children(node)
            .into_iter()
            .filter(|child| child.kind() != "label")
            .collect::<Vec<_>>();
        let label = direct_named_child_kind(node, "label");
        let labeled_scope = if let Some(label) = label {
            let label = node_text(self.source, label).map(Box::<str>::from);
            builder.push_scope(
                Some(scope),
                ScopeBinding::Breakable {
                    label,
                    accepts_unlabeled: false,
                    break_target: next.point,
                    break_edge_kind: next.kind,
                },
            )
        } else {
            scope
        };

        let entries = children
            .iter()
            .map(|child| {
                self.point(
                    builder,
                    execution_node(unwrap_attributes(*child)),
                    Vec::new(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut child_scopes = Vec::with_capacity(children.len());
        let mut active_scope = labeled_scope;
        let mut has_cleanup_actions = false;
        for (index, child) in children.iter().copied().enumerate() {
            child_scopes.push(active_scope);
            if child.kind() != "let_declaration" || child.child_by_field_name("value").is_none() {
                continue;
            }
            let values = self.declaration_binding_values(child);
            if values.is_empty() {
                continue;
            }
            let cleanup_source = child.child_by_field_name("pattern").unwrap_or(child);
            let cleanup_scope = self.push_cleanup_scope(builder, active_scope, cleanup_source)?;
            let region = CleanupRegionId::new(
                u32::try_from(self.next_cleanup_region - 1)
                    .expect("push_cleanup_scope allocated this region"),
            );
            if self.register_binding_cleanup_actions(
                builder,
                cleanup_scope,
                region,
                &values,
                entries[index],
            )? {
                has_cleanup_actions = true;
            }
            self.binding_cleanup_regions.insert(region);
            active_scope = cleanup_scope;
        }

        let function_fallthrough =
            node.id() == self.procedure_body.id() && next.point == self.normal_exit;
        let stop_before = if function_fallthrough {
            self.function_scope
        } else {
            labeled_scope
        };
        let needs_scope_exit =
            has_cleanup_actions || (function_fallthrough && scope != self.function_scope);
        let scope_exit = if needs_scope_exit {
            Some(self.session.add_cleanup_boundary_point(builder, node)?)
        } else {
            None
        };
        let effective_next = scope_exit.map(EdgeTarget::normal).unwrap_or(next);
        let cleanup_target = if next.kind == ControlEdgeKind::Normal {
            next.point
        } else if scope_exit.is_some() {
            let relay = self.session.add_cleanup_boundary_point(builder, node)?;
            self.session.add_target_edge(builder, relay, next)?;
            relay
        } else {
            next.point
        };
        let route =
            builder.normal_cleanup_completion_until(active_scope, stop_before, cleanup_target);
        if let Some(scope_exit) = scope_exit {
            self.route(builder, scope_exit, &route)?;
        } else if active_scope != stop_before {
            self.record_owner_lifetime_ends(&route);
        }
        self.schedule_nodes_with_scopes(
            builder,
            entry,
            ScopedNodeSchedule {
                children: &children,
                entries: &entries,
                scopes: &child_scopes,
            },
            effective_next,
            stack,
        )
    }

    fn push_cleanup_scope(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        parent: ScopeFrameId,
        source: Node<'tree>,
    ) -> Result<ScopeFrameId, RustLoweringError> {
        let region = CleanupRegionId::new(
            u32::try_from(self.next_cleanup_region)
                .map_err(|_| RustLoweringError::Invalid("too many Rust cleanup regions".into()))?,
        );
        self.next_cleanup_region += 1;
        self.cleanup_nodes.insert(region, source);
        Ok(builder.push_scope(Some(parent), ScopeBinding::Cleanup { region }))
    }

    fn declaration_binding_values(&self, declaration: Node<'tree>) -> Vec<ValueId> {
        let mut values = Vec::new();
        let Some(pattern) = declaration.child_by_field_name("pattern") else {
            return values;
        };
        for name in rust_pattern_binding_identifiers(pattern) {
            let Some(text) = node_text(self.source, name) else {
                continue;
            };
            if let Some(value) = self.local_declaration_value(text, name.start_byte()) {
                values.push(value);
            }
        }
        values
    }

    /// Publish the omitted implicit `Drop` at `point`.
    ///
    /// `discharge` is the proof obligation for cleanup routing, resource
    /// and resource release: `InertDropGlue` when every value
    /// this drop can destroy is a parameter or a `let` binding of the
    /// procedure, which the workspace oracle can type (#3757); `None` otherwise.
    /// Destructor unwinding uses the corresponding non-rejoining exit proof.
    fn add_drop_omission_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
        discharge: SemanticGapDischarge,
    ) -> Result<(), RustLoweringError> {
        for (capability, kind, gap_discharge, detail) in [
            (
                SemanticCapability::CleanupControlFlow,
                SemanticGapKind::Unknown,
                discharge,
                "implicit Drop order and cleanup routing are not lowered",
            ),
            (
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unknown,
                discharge,
                "resource release depends on inferred types and Drop implementations",
            ),
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                SemanticGapDischarge::None,
                "implicit Drop::drop invocations are not emitted as fabricated call sites",
            ),
            // The unwind edge a panicking destructor would take is simply not
            // lowered, which is `Unsupported` rather than `Unknown`: it is the
            // exact shape the shared implicit-abort discharge closes when no
            // handler or cleanup body runs user code (#1952). Stating it as
            // `Unknown` made every Rust snapshot uncertain forever.
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                if discharge == SemanticGapDischarge::InertDropGlue {
                    SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
                } else {
                    SemanticGapDischarge::ExitOnlyProcedureCompletion
                },
                "destructor unwinding and destructor panic routing are not lowered",
            ),
        ] {
            self.session.add_gap_with_impacts_and_discharge(
                builder,
                point,
                SemanticGapSubject::Point,
                capability,
                SemanticGapImpacts::NONE,
                kind,
                gap_discharge,
                format!("{context}; {detail}"),
            )?;
        }
        Ok(())
    }

    fn unsupported_pattern_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        pattern: Node<'tree>,
        scrutinee: Node<'tree>,
        detail: &str,
    ) -> Result<(), RustLoweringError> {
        let mut root = scrutinee;
        let root_binding = loop {
            root = unwrap_attributes(root);
            match root.kind() {
                "identifier" | "self" => break self.binding_value(root),
                "field_expression" => root = required_field(root, "value")?,
                "index_expression" | "parenthesized_expression" => {
                    let Some(base) = first_named_child(root) else {
                        break None;
                    };
                    root = base;
                }
                "unary_expression" => {
                    let Some(base) = rust_dereference_operand(root) else {
                        break None;
                    };
                    root = base;
                }
                _ => break None,
            }
        };
        let mut bindings = Vec::new();
        for name in rust_pattern_binding_identifiers(pattern) {
            let text = node_text(self.source, name).expect("pattern identifier has source text");
            if let Some(value) = self.local_declaration_value(text, name.start_byte()) {
                let mut ancestor = name;
                let by_reference = loop {
                    if ancestor.kind() == "ref_pattern" {
                        break true;
                    }
                    if ancestor.id() == pattern.id() {
                        break false;
                    }
                    ancestor = ancestor.parent().expect("binding belongs to its pattern");
                };
                if by_reference && let Some(root_binding) = root_binding {
                    // Retain the borrowed root and the reference's installation
                    // in a lexical slot. The shared address-escape analysis
                    // recognizes this store, conservatively opening the root
                    // even when the pattern selects only a subplace (#6409).
                    let address = self.value(builder, point, SemanticValueKind::Address)?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::Assignment {
                            target: address,
                            value: root_binding,
                        },
                    )?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::Assignment {
                            target: value,
                            value: address,
                        },
                    )?;
                    let location = self.session.add_memory_location(
                        builder,
                        point,
                        MemoryLocationKind::LexicalCell { binding: value },
                    )?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::LexicalCell,
                            location,
                            value: address,
                        },
                    )?;
                }
                bindings.push(value);
            }
        }
        if bindings.is_empty() {
            self.session.record_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                SemanticCapability::LocalFlow,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        } else {
            for binding in bindings {
                self.session.record_gap(
                    builder,
                    point,
                    SemanticGapSubject::Value(binding),
                    SemanticCapability::Values,
                    SemanticGapKind::Unsupported,
                    detail,
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn let_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let value = node.child_by_field_name("value");
        let alternative = node.child_by_field_name("alternative");
        let Some(value) = value else {
            return self.session.add_target_edge(builder, entry, next);
        };
        let binding = self.point(builder, node, Vec::new())?;
        let mut initialized = binding;
        if let Some(pattern) = node.child_by_field_name("pattern") {
            if is_wildcard_pattern(pattern) {
                // `_` binds and moves nothing. A place expression such as a
                // local parameter therefore creates neither local value flow
                // nor a lexical-scope cleanup obligation. A fresh temporary
                // can still be dropped at the end of this statement; retain
                // that distinct omission at the binding point.
                if !self.is_place(value) && !self.expression_is_definitely_non_dropping(value) {
                    self.add_drop_omission_gaps(
                        builder,
                        binding,
                        "a temporary discarded by a wildcard let may require immediate Drop at the end of the statement",
                        SemanticGapDischarge::InertDropGlue,
                    )?;
                }
            } else if let Some(name) = identity_binding_identifier(pattern) {
                let name_text = node_text(self.source, name).ok_or_else(|| {
                    RustLoweringError::Invalid("Rust binding has an invalid name range".into())
                })?;
                let target = self
                    .local_declaration_value(name_text, name.start_byte())
                    .ok_or_else(|| {
                        RustLoweringError::Invalid(
                            "Rust local declaration was not preindexed".into(),
                        )
                    })?;
                let source = self.expression_value(builder, value, expression_value_kind(value))?;
                self.append_ownership_transfer(
                    builder,
                    binding,
                    value,
                    source,
                    target,
                    node.child_by_field_name("type")
                        .map(RustValueType::Declared),
                )?;
            } else if let Some(proof) = self.tuple_lets.remove(&node.id()) {
                match proof {
                    Ok(proof) => initialized = self.append_tuple_let(builder, binding, proof)?,
                    Err(reason) => self.unsupported_pattern_gaps(
                        builder,
                        binding,
                        pattern,
                        value,
                        &format!(
                            "tuple-let component ownership is unproved: {}",
                            ownership_gap_detail(reason)
                        ),
                    )?,
                }
            } else {
                self.unsupported_pattern_gaps(
                    builder,
                    binding,
                    pattern,
                    value,
                    "destructuring and by-reference Rust let patterns are not lowered as identity-preserving local flow",
                )?;
            }
        }
        if let Some(alternative) = alternative {
            let success = self.point(builder, node, Vec::new())?;
            let alternative_entry = self.point(builder, alternative, Vec::new())?;
            // No control-flow gap: the matched and diverging successors are
            // both represented as edges below. What the pattern binds is a
            // value question, already published by the binding's `Values`
            // gaps (or the point fallback for an unidentified pattern).
            self.session.add_target_edge(
                builder,
                binding,
                EdgeTarget {
                    point: success,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
            )?;
            self.session.add_target_edge(
                builder,
                binding,
                EdgeTarget {
                    point: alternative_entry,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            self.session.add_target_edge(builder, success, next)?;
            stack.push(Work::Statement {
                node: alternative,
                entry: alternative_entry,
                next,
                scope,
            });
        } else {
            self.session.add_target_edge(builder, initialized, next)?;
        }
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(binding),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        match node.kind() {
            "call_expression" => self.call_expression(builder, node, entry, next, scope, stack),
            "struct_expression" => {
                self.struct_allocation_expression(builder, node, entry, next, scope, stack)
            }
            "array_expression" => {
                self.array_allocation_expression(builder, node, entry, next, scope, stack)
            }
            "assignment_expression" => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "compound_assignment_expr" => {
                self.compound_assignment_expression(builder, node, entry, next, scope, stack)
            }
            "parenthesized_expression" => {
                let value = first_named_child(node).ok_or_else(|| missing_field(node, "value"))?;
                self.transparent_expression(builder, node, value, entry, next, scope, stack)
            }
            "reference_expression" => {
                let value = required_field(node, "value")?;
                self.transparent_expression(builder, node, value, entry, next, scope, stack)
            }
            "type_cast_expression" => {
                let value = required_field(node, "value")?;
                self.conversion_expression(builder, node, value, entry, next, scope, stack)
            }
            "closure_expression" | "async_block" | "gen_block" => {
                self.callable_expression(builder, node, entry, next)
            }
            "if_expression" => self.if_expression(builder, node, entry, next, scope, stack),
            "match_expression" => self.match_expression(builder, node, entry, next, scope, stack),
            "loop_expression" => self.loop_expression(builder, node, entry, next, scope, stack),
            "while_expression" => self.while_expression(builder, node, entry, next, scope, stack),
            "for_expression" => self.for_expression(builder, node, entry, next, scope, stack),
            "break_expression" => self.break_expression(builder, node, entry, scope, stack),
            "continue_expression" => self.continue_expression(builder, node, entry, scope),
            "return_expression" => self.return_expression(builder, node, entry, scope, stack),
            "try_expression" => self.try_expression(builder, node, entry, next, scope, stack),
            "try_block" => self.try_block(builder, node, entry, scope, stack),
            "await_expression" => self.await_expression(builder, node, entry, next, scope, stack),
            "yield_expression" => self.yield_expression(builder, node, entry, scope, stack),
            "macro_invocation" => self.macro_invocation(builder, node, entry, next, scope, stack),
            "block" => self.block(builder, node, entry, next, scope, stack),
            "unsafe_block" => {
                let block = first_named_child(node).ok_or_else(|| missing_field(node, "block"))?;
                stack.push(Work::Statement {
                    node: block,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "const_block" => {
                self.session.record_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unsupported,
                    "inline const evaluation happens at compile time and is not represented as runtime control flow",
                )?;
                self.session.add_target_edge(builder, entry, next)
            }
            "binary_expression" if rust_boolean_operator(node).is_some() => {
                let merge = self.point(builder, node, Vec::new())?;
                // Both arms of the short circuit reconvene here, and the
                // boolean this expression produces derives from whichever
                // operands were evaluated to reach it.
                let result = self.expression_value(builder, node, expression_value_kind(node))?;
                let operands = runtime_expression_children(node)
                    .into_iter()
                    .map(|child| {
                        self.expression_value(builder, child, expression_value_kind(child))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, merge, operands, result)?;
                self.session.add_target_edge(builder, merge, next)?;
                stack.push(Work::Condition {
                    node,
                    entry,
                    when_true: EdgeTarget {
                        point: merge,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: merge,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "unary_expression"
                if rust_dereference_operand(node)
                    .is_some_and(|operand| self.is_raw_pointer_expression(operand)) =>
            {
                self.raw_pointer_dereference(builder, node, entry, next, scope, stack)
            }
            "unary_expression"
                if rust_dereference_operand(node)
                    .and_then(|operand| self.expression_type(operand))
                    .and_then(|ty| self.dereferenced_type(ty))
                    .is_some() =>
            {
                let operand = rust_dereference_operand(node)
                    .expect("a structurally proven dereference retains its operand");
                self.transparent_expression(builder, node, operand, entry, next, scope, stack)
            }
            "binary_expression" | "unary_expression" => {
                self.operator_expression(builder, node, entry, next, scope, stack)
            }
            "field_expression"
                if !self.field_denotes_no_location(node) && !is_rust_assignment_target(node) =>
            {
                self.field_load(builder, node, entry, next, scope, stack)
            }
            "index_expression"
                if !is_rust_assignment_target(node)
                    && runtime_expression_children(node).len() == 2 =>
            {
                self.index_load(builder, node, entry, next, scope, stack)
            }
            kind if implicit_runtime_call_reason(kind).is_some() => {
                self.implicit_call_expression(builder, node, entry, next, scope, stack)
            }
            "let_condition" => {
                let value = required_field(node, "value")?;
                stack.push(Work::Expression {
                    node: value,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "let_chain" => {
                let merge = self.point(builder, node, Vec::new())?;
                self.session.add_target_edge(builder, merge, next)?;
                stack.push(Work::Condition {
                    node,
                    entry,
                    when_true: EdgeTarget {
                        point: merge,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: merge,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "generic_function" => {
                let function = required_field(node, "function")?;
                stack.push(Work::Expression {
                    node: function,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            kind if is_runtime_leaf(kind) => {
                let value = self.expression_value(builder, node, expression_value_kind(node))?;
                self.emit_lexical_input_flow(builder, node, entry, value)?;
                self.session.add_target_edge(builder, entry, next)
            }
            kind if is_runtime_container(kind) => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn struct_allocation_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        self.session
            .add_allocation(builder, terminal, result, AllocationKind::Object)?;
        let body = required_field(node, "body")?;
        let mut evaluations = Vec::new();
        let mut initialized = HashSet::default();
        let mut update = None;
        for initializer in named_children(body) {
            let (field, value) = match initializer.kind() {
                "field_initializer" => (
                    required_field(initializer, "field")?,
                    required_field(initializer, "value")?,
                ),
                "shorthand_field_initializer" => {
                    let field = named_children(initializer)
                        .into_iter()
                        .find(|child| child.kind() == "identifier")
                        .expect("Rust shorthand initializer has a field identifier");
                    (field, field)
                }
                "base_field_initializer" => {
                    let base = first_named_child(initializer)
                        .expect("Rust struct update has a base expression");
                    evaluations.push(base);
                    update = Some(base);
                    continue;
                }
                _ => continue,
            };
            evaluations.push(value);
            initialized.insert(
                rust_field_member_key(self.source, field)
                    .expect("Rust initializer has a named field key"),
            );
            let value = self.expression_value(builder, value, expression_value_kind(value))?;
            let (member, resolved, exact_member_key) = self.memory_member_locator(node, field)?;
            let location = self.session.add_memory_location(
                builder,
                terminal,
                MemoryLocationKind::Field {
                    base: result,
                    member,
                },
            )?;
            if !resolved {
                self.add_field_identity_gap(builder, terminal, location, exact_member_key)?;
            }
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Field,
                    location,
                    value,
                },
            )?;
        }
        if let Some(base) = update {
            if let Some(fields) = self.declared_struct_fields(node) {
                let base_value =
                    self.expression_value(builder, base, expression_value_kind(base))?;
                for field in fields {
                    if initialized.contains(
                        &rust_field_member_key(self.source, field)
                            .expect("declared Rust field has a named key"),
                    ) {
                        continue;
                    }
                    self.append_struct_field_transfer(
                        builder, terminal, node, base_value, result, field,
                    )?;
                }
            } else {
                self.session.record_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::FieldMemory,
                    SemanticGapKind::Unknown,
                    "Rust struct update has no known declaration field set",
                )?;
            }
        }
        self.session.add_target_edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn array_allocation_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        self.session
            .add_allocation(builder, terminal, result, AllocationKind::Array)?;
        let elements = rust_array_initializer_elements(node);
        if let Some(length_node) = node.child_by_field_name("length") {
            let Some(element) = elements.first() else {
                return Err(RustLoweringError::Invalid(
                    "Rust repeated array expression is missing its initializer".into(),
                ));
            };
            match rust_integer_literal_value(self.source, length_node) {
                Some(length) if length <= RUST_REPEAT_ARRAY_ELEMENT_CAP => {
                    if length != 0 {
                        let value = self.expression_value(
                            builder,
                            *element,
                            expression_value_kind(*element),
                        )?;
                        for ordinal in 0..length {
                            self.emit_array_element_store(
                                builder, terminal, node, result, ordinal, value,
                            )?;
                        }
                    }
                    // A bounded repeat initializer evaluates one structured
                    // value and writes it to each known ordinal. These precise
                    // stores let later writes kill one element without
                    // retaining a whole-array flow.
                }
                _ => {
                    let value =
                        self.expression_value(builder, *element, expression_value_kind(*element))?;
                    let location = self.session.add_memory_location(
                        builder,
                        terminal,
                        MemoryLocationKind::Index {
                            base: result,
                            index: None,
                            constant_index: None,
                            identity: crate::analyzer::semantic::IndexedLocationIdentity::Aggregate,
                        },
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Index,
                            location,
                            value,
                        },
                    )?;
                    // An unbounded repeat still initializes every element from
                    // this one value, so aggregate flow reaches exact indexed
                    // reads without expanding stores. The typed gap keeps
                    // nonliteral and over-cap lengths from claiming complete
                    // absence evidence. The fresh allocation result keeps
                    // separate arrays distinct.
                    self.session.append_language_defined_value_flows(
                        builder,
                        terminal,
                        [value],
                        result,
                    )?;
                    self.add_repeat_array_gap(builder, terminal, location)?;
                }
            }
        } else {
            for (ordinal, element) in elements.into_iter().enumerate() {
                let ordinal = u128::try_from(ordinal).map_err(|_| {
                    RustLoweringError::Invalid("Rust array literal has too many elements".into())
                })?;
                let value =
                    self.expression_value(builder, element, expression_value_kind(element))?;
                self.emit_array_element_store(builder, terminal, node, result, ordinal, value)?;
            }
        }
        self.session.add_target_edge(builder, terminal, next)?;
        let children = runtime_expression_children(node);
        self.schedule_expressions(
            builder,
            entry,
            &children,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let left = required_field(node, "left")?;
        let right = required_field(node, "right")?;
        let terminal = self.point(builder, node, Vec::new())?;
        let value = self.expression_value(builder, right, expression_value_kind(right))?;
        let (target, mut evaluations) = self.assignment_target(builder, left, terminal, scope)?;
        self.write_assignment_target(builder, terminal, target, right, value)?;
        evaluations.push(right);
        self.session.add_target_edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    fn assignment_target(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        left: Node<'tree>,
        terminal: ProgramPointId,
        scope: ScopeFrameId,
    ) -> Result<(RustAssignmentTarget, Vec<Node<'tree>>), RustLoweringError> {
        if left.kind() == "unary_expression"
            && let Some(pointer_node) = rust_dereference_operand(left)
            && self.is_raw_pointer_expression(pointer_node)
        {
            let pointer =
                self.expression_value(builder, pointer_node, expression_value_kind(pointer_node))?;
            let width = self.pointer_width_for_expression(pointer_node);
            let metadata = self.metadata(terminal)?;
            self.add_pointer_access(terminal, pointer, PointerAccessKind::Write, width, metadata);
            if width == PointerAccessWidth::Unknown {
                self.add_incomplete_fact(
                    terminal,
                    SemanticIncompleteSubject::Value(pointer),
                    SemanticIncompleteReason::Pointer(PointerIncompleteReason::UnknownLayout),
                    metadata,
                );
            }
            let location = self.session.add_memory_location(
                builder,
                terminal,
                MemoryLocationKind::Dereference { address: pointer },
            )?;
            return Ok((
                RustAssignmentTarget::Memory {
                    kind: MemoryAccessKind::Dereference,
                    location,
                },
                vec![pointer_node],
            ));
        }
        if left.kind() == "identifier" {
            let name = node_text(self.source, left).ok_or_else(|| {
                RustLoweringError::Invalid("Rust assignment has an invalid target range".into())
            })?;
            let target = self
                .local_at(name, left.start_byte())
                .or_else(|| self.parameters.get(name).copied())
                .or_else(|| self.captured_bindings.get(name).copied());
            if target.is_none() {
                self.session.record_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unknown,
                    "assignment target does not name a represented Rust local or parameter",
                )?;
            }
            if self.assignment_replaces_droppable_value(left) {
                self.add_drop_omission_gaps(
                    builder,
                    terminal,
                    "assignment may replace a live value",
                    SemanticGapDischarge::None,
                )?;
            }
            return Ok((
                target
                    .map(RustAssignmentTarget::Binding)
                    .unwrap_or(RustAssignmentTarget::Unsupported),
                Vec::new(),
            ));
        }

        // A single field or index target is a real store into memory. The
        // target's own base is still evaluated, but the target node itself is
        // never scheduled as an expression: reading it would publish a load of
        // the location this statement writes.
        let place = matches!(left.kind(), "field_expression" | "index_expression")
            .then_some(left)
            .filter(|place| {
                place.kind() != "field_expression" || !self.field_denotes_no_location(*place)
            });
        let mut target = RustAssignmentTarget::Unsupported;
        let evaluations = if let Some(place) = place {
            let mut evaluations = Vec::new();
            match place.kind() {
                "field_expression" => {
                    let base = required_field(place, "value")?;
                    let field = required_field(place, "field")?;
                    let base_value =
                        self.expression_value(builder, base, expression_value_kind(base))?;
                    let (member, resolved, exact_member_key) =
                        self.memory_member_locator(base, field)?;
                    let location = self.session.add_memory_location(
                        builder,
                        terminal,
                        MemoryLocationKind::Field {
                            base: base_value,
                            member,
                        },
                    )?;
                    if !resolved {
                        self.add_field_identity_gap(builder, terminal, location, exact_member_key)?;
                    }
                    target = RustAssignmentTarget::Memory {
                        kind: MemoryAccessKind::Field,
                        location,
                    };
                    evaluations.insert(0, base);
                }
                _ => {
                    let children = runtime_expression_children(place);
                    let [base, index_node] = children.as_slice() else {
                        return Err(RustLoweringError::Invalid(
                            "Rust index place does not have a base and an index".into(),
                        ));
                    };
                    let base_value =
                        self.expression_value(builder, *base, expression_value_kind(*base))?;
                    let indexed = self.index_value(builder, *index_node)?;
                    let (index, constant_index) = indexed
                        .map_or((None, None), |(value, constant_index)| {
                            (Some(value), Some(constant_index))
                        });
                    let location = self.session.add_memory_location(
                        builder,
                        terminal,
                        MemoryLocationKind::Index {
                            base: base_value,
                            index,
                            constant_index,
                            identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
                        },
                    )?;
                    if index.is_none() {
                        self.add_dynamic_index_gap(builder, terminal, location)?;
                    }
                    target = RustAssignmentTarget::Memory {
                        kind: MemoryAccessKind::Index,
                        location,
                    };
                    evaluations.insert(0, *index_node);
                    evaluations.insert(0, *base);
                }
            }
            evaluations
        } else {
            self.session.record_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unsupported,
                "dereferenced, destructuring, and call-selector Rust assignment targets are not yet lowered into memory flow",
            )?;
            vec![left]
        };
        // One scoped fact per point: the place-evaluation traits a field, index,
        // or dereference target may invoke are reported alongside the drop
        // omissions this same terminal already publishes rather than as a
        // second Point/Calls row. A place whose access is the language's own
        // projection, replacing a value that provably owns no `Drop`, invokes
        // neither and publishes nothing.
        if !self.place_access_is_language_defined(left)
            || self.assignment_replaces_droppable_value(left)
        {
            self.add_drop_omission_gaps(
                builder,
                terminal,
                "place assignment may invoke custom DerefMut or IndexMut behavior and may replace a live value",
                SemanticGapDischarge::None,
            )?;
        } else if left.kind() == "index_expression" {
            // The abort edge an out-of-range index would take is not lowered.
            // `Unsupported` on a `Point` subject is the exact shape the shared
            // implicit-abort discharge closes when no handler or cleanup body
            // runs user code (#1952). A place that also publishes the
            // drop-omission family already carries this exact scoped fact in
            // that family's own `ExceptionalControlFlow` row, and #2638's
            // contract allows only one row per (point, subject, capability).
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                terminal,
                scope,
                SemanticGapKind::Unsupported,
                "an index store may abort on an out-of-range index; that abort edge is not lowered",
            )?;
        }
        Ok((target, evaluations))
    }

    fn write_assignment_target(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        target: RustAssignmentTarget,
        source_node: Node<'tree>,
        value: ValueId,
    ) -> Result<(), RustLoweringError> {
        match target {
            RustAssignmentTarget::Binding(target) => {
                let target_type = self.value_types.get(&target).copied();
                self.append_ownership_transfer(
                    builder,
                    point,
                    source_node,
                    value,
                    target,
                    target_type,
                )
            }
            RustAssignmentTarget::Memory { kind, location } => self.append_effect(
                builder,
                point,
                SemanticEffect::MemoryStore {
                    kind,
                    location,
                    value,
                },
            ),
            RustAssignmentTarget::Unsupported => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn transparent_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        value: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let source = self.expression_value(builder, value, expression_value_kind(value))?;
        let target = self.expression_value(builder, node, expression_value_kind(node))?;
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Assignment {
                target,
                value: source,
            },
        )?;
        // Parenthesizing a value, or taking a reference to it, does not change
        // what the value is. The assignment alone records only that the write
        // happened; this flow records that the result *is* the operand.
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source,
                target,
            },
        )?;
        self.session.add_target_edge(builder, terminal, next)?;
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn conversion_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        value: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let target = self.expression_value(builder, node, expression_value_kind(node))?;
        // A cast changes a value's type, never where its data came from. The
        // result therefore derives from the operand rather than keeping the
        // operand's identity, which is exactly a language-defined flow. Ending
        // the operand's history here instead published a gap the conversion
        // does not actually have.
        let source = self.expression_value(builder, value, expression_value_kind(value))?;
        let modelled_allocator_result = value.kind() == "call_expression"
            && value
                .child_by_field_name("function")
                .map(call_function_target)
                .is_some_and(|function| self.is_standard_allocator_function(function));
        let pointer_to_pointer_cast = node
            .child_by_field_name("type")
            .is_some_and(|type_node| type_node.kind() == "pointer_type")
            && (modelled_allocator_result
                || self.expression_type(value).is_some_and(|value_type| {
                    matches!(
                        value_type,
                        RustValueType::Declared(type_node) if type_node.kind() == "pointer_type"
                    )
                }));
        if pointer_to_pointer_cast {
            let metadata = self.metadata(terminal)?;
            self.register_pointer_fact_target(source, target, terminal, metadata);
        }
        self.session
            .append_language_defined_value_flows(builder, terminal, [source], target)?;
        if let Some(target_type) = node
            .child_by_field_name("type")
            .filter(|type_node| type_node.kind() == "pointer_type")
        {
            self.value_types
                .insert(target, RustValueType::Declared(target_type));
            let reference = peel_rust_parentheses(value);
            if reference.kind() == "reference_expression"
                && let Some(referent) = rust_reference_expression_value(reference)
                && let Some(binding) = self.binding_value(referent)
                && let Some(place) = self.binding_places.get(&binding).cloned()
            {
                let metadata = self.metadata(terminal)?;
                let extent = self.value_types.get(&binding).and_then(|ty| match ty {
                    RustValueType::Declared(type_node) => {
                        rust_type_byte_size(self.source, *type_node)
                    }
                    RustValueType::Borrowed { .. } => None,
                });
                let origin = self.add_stack_pointer_origin(place, extent, terminal, metadata);
                self.add_pointer_alias(
                    terminal,
                    target,
                    origin,
                    PointerByteOffset::Exact(0),
                    PointerRelationStrength::Must,
                    metadata,
                );
            } else {
                let metadata = self.metadata(terminal)?;
                let aliases = self
                    .pointer_origins_by_pointer
                    .get(&source)
                    .cloned()
                    .or_else(|| {
                        self.binding_value(value).and_then(|binding| {
                            self.pointer_origins_by_pointer.get(&binding).cloned()
                        })
                    })
                    .unwrap_or_default();
                if aliases.is_empty() {
                    if self
                        .expression_type(value)
                        .is_none_or(|ty| !matches!(ty, RustValueType::Declared(type_node) if type_node.kind() == "pointer_type"))
                    {
                        self.add_incomplete_fact(
                            terminal,
                            SemanticIncompleteSubject::Value(target),
                            SemanticIncompleteReason::Pointer(
                                PointerIncompleteReason::UnsupportedOperation,
                            ),
                            metadata,
                        );
                    }
                } else {
                    for (origin, offset) in aliases {
                        self.add_pointer_alias(
                            terminal,
                            target,
                            origin,
                            offset,
                            PointerRelationStrength::Must,
                            metadata,
                        );
                    }
                }
            }
        }
        self.session.add_target_edge(builder, terminal, next)?;
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
    }

    fn raw_pointer_dereference(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let operand = rust_dereference_operand(node)
            .expect("a raw pointer dereference has a structured operand");
        let terminal = self.point(builder, node, Vec::new())?;
        let pointer = self.expression_value(builder, operand, expression_value_kind(operand))?;
        let width = self.pointer_width_for_expression(operand);
        let metadata = self.metadata(terminal)?;
        self.add_pointer_access(terminal, pointer, PointerAccessKind::Read, width, metadata);
        self.session.record_gap(
            builder,
            terminal,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "raw-pointer dereference remains outside the exact builtin-reference proof",
        )?;
        if width == PointerAccessWidth::Unknown {
            self.add_incomplete_fact(
                terminal,
                SemanticIncompleteSubject::Value(pointer),
                SemanticIncompleteReason::Pointer(PointerIncompleteReason::UnknownLayout),
                metadata,
            );
        }
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        self.session
            .append_language_defined_value_flows(builder, terminal, [pointer], result)?;
        self.session.add_target_edge(builder, terminal, next)?;
        stack.push(Work::Expression {
            node: operand,
            entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
    }

    /// An operator application: `a + b`, `!flag`, `*handle`.
    ///
    /// The operator's result derives from every operand it evaluates. Without
    /// that flow an arithmetic or comparison step silently ended the value's
    /// history, which is what left every computed Rust tail expression
    /// unknown.
    #[allow(clippy::too_many_arguments)]
    fn operator_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let children = runtime_expression_children(node);
        let operands = children
            .iter()
            .map(|child| self.expression_value(builder, *child, expression_value_kind(*child)))
            .collect::<Result<Vec<_>, _>>()?;
        self.session
            .append_language_defined_value_flows(builder, terminal, operands, result)?;
        if !self.scalar_operator_is_builtin(node) {
            self.session.record_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                implicit_runtime_call_reason(node.kind())
                    .expect("operator expressions carry an implicit-call reason"),
            )?;
        }
        if rust_operation_can_abort(node) {
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                terminal,
                scope,
                SemanticGapKind::Unsupported,
                "arithmetic overflow, division by zero, or an invalid dereference may abort here; that abort edge is not lowered",
            )?;
        }
        self.session.add_target_edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &children,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    /// `base.field` read as a value: a load from the field's own location.
    #[allow(clippy::too_many_arguments)]
    fn field_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let base = required_field(node, "value")?;
        let field = required_field(node, "field")?;
        let access = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let base_value = self.expression_value(builder, base, expression_value_kind(base))?;
        let (member, resolved, exact_member_key) = self.memory_member_locator(base, field)?;
        let location = self.session.add_memory_location(
            builder,
            access,
            MemoryLocationKind::Field {
                base: base_value,
                member,
            },
        )?;
        if !resolved {
            self.add_field_identity_gap(builder, access, location, exact_member_key)?;
        }
        self.append_effect(
            builder,
            access,
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Field,
                location,
                result,
            },
        )?;
        // Projecting a field of a struct this file declares is the language's
        // own projection: no autoderef step reaches a user `Deref`, and the
        // projection itself cannot abort. Any other base keeps both claims.
        if !self.place_access_is_language_defined(node) {
            self.session.record_gap(
                builder,
                access,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "field projection may require implicit autoderef operations that are not emitted as call sites",
            )?;
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                access,
                scope,
                SemanticGapKind::Unsupported,
                "an implicit Rust autoderef may abort here; that abort edge is not lowered",
            )?;
        }
        self.session.add_target_edge(builder, access, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &[base],
            EdgeTarget::normal(access),
            scope,
            stack,
        )
    }

    /// `base[index]` read as a value: a load from the element's own location.
    #[allow(clippy::too_many_arguments)]
    fn index_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let children = runtime_expression_children(node);
        let [base, index_node] = children.as_slice() else {
            return Err(RustLoweringError::Invalid(
                "Rust index expression does not have a base and an index".into(),
            ));
        };
        let access = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let base_value = self.expression_value(builder, *base, expression_value_kind(*base))?;
        let indexed = self.index_value(builder, *index_node)?;
        let (index, constant_index) = indexed.map_or((None, None), |(value, constant_index)| {
            (Some(value), Some(constant_index))
        });
        let location = self.session.add_memory_location(
            builder,
            access,
            MemoryLocationKind::Index {
                base: base_value,
                index,
                constant_index,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
        )?;
        if index.is_none() {
            self.add_dynamic_index_gap(builder, access, location)?;
        }
        self.append_effect(
            builder,
            access,
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Index,
                location,
                result,
            },
        )?;
        if self.pointer_pointee_type(*base).is_some() {
            let width = self
                .pointer_pointee_type(*base)
                .and_then(|element| rust_type_byte_size(self.source, element))
                .map_or(PointerAccessWidth::Unknown, PointerAccessWidth::Exact);
            let aliases = self
                .pointer_origins_by_pointer
                .get(&base_value)
                .cloned()
                .or_else(|| {
                    self.binding_value(*base)
                        .and_then(|binding| self.pointer_origins_by_pointer.get(&binding).cloned())
                })
                .unwrap_or_default();
            let pointer = if aliases.is_empty() {
                base_value
            } else {
                let address = self.value(builder, access, SemanticValueKind::Address)?;
                let element_size = match width {
                    PointerAccessWidth::Exact(size) => Some(size),
                    PointerAccessWidth::ValueTimes { .. } | PointerAccessWidth::Unknown => None,
                };
                for (origin, base_offset) in aliases {
                    let offset = match (base_offset, element_size, constant_index) {
                        (PointerByteOffset::Exact(base), Some(size), Some(index)) => {
                            i128::try_from(index)
                                .ok()
                                .and_then(|index| index.checked_mul(i128::try_from(size).ok()?))
                                .and_then(|index| base.checked_add(index))
                                .map_or(PointerByteOffset::Unknown, PointerByteOffset::Exact)
                        }
                        _ => PointerByteOffset::Unknown,
                    };
                    self.add_pointer_alias(
                        access,
                        address,
                        origin,
                        offset,
                        PointerRelationStrength::Must,
                        self.metadata(access)?,
                    );
                }
                address
            };
            let metadata = self.metadata(access)?;
            self.add_pointer_access(access, pointer, PointerAccessKind::Read, width, metadata);
            if width == PointerAccessWidth::Unknown {
                self.add_incomplete_fact(
                    access,
                    SemanticIncompleteSubject::Value(pointer),
                    SemanticIncompleteReason::Pointer(PointerIncompleteReason::UnknownLayout),
                    metadata,
                );
            }
        }
        if !self.place_access_is_language_defined(node) {
            self.session.record_gap(
                builder,
                access,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "indexing may invoke Index or IndexMut implicitly; no fabricated trait call site is emitted",
            )?;
        }
        // Built in or not, an index read may abort on an out-of-range index.
        self.add_non_rejoining_exceptional_exit_gap(
            builder,
            access,
            scope,
            SemanticGapKind::Unsupported,
            "indexing may abort on an out-of-range index; that abort edge is not lowered",
        )?;
        self.session.add_target_edge(builder, access, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &children,
            EdgeTarget::normal(access),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compound_assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let left = required_field(node, "left")?;
        let right = required_field(node, "right")?;
        let boundary = self.point(builder, node, Vec::new())?;
        let terminal = self.point(builder, node, Vec::new())?;
        let (target, mut evaluations) = self.assignment_target(builder, left, terminal, scope)?;
        let old = match target {
            RustAssignmentTarget::Binding(value) => value,
            RustAssignmentTarget::Memory { kind, location } => {
                if kind == MemoryAccessKind::Dereference {
                    let pointer_node = rust_dereference_operand(left)
                        .expect("a dereference assignment target has a pointer operand");
                    let pointer = self.expression_value(
                        builder,
                        pointer_node,
                        expression_value_kind(pointer_node),
                    )?;
                    let width = self.pointer_width_for_expression(pointer_node);
                    let metadata = self.metadata(boundary)?;
                    self.add_pointer_access(
                        boundary,
                        pointer,
                        PointerAccessKind::Read,
                        width,
                        metadata,
                    );
                    if width == PointerAccessWidth::Unknown {
                        self.add_incomplete_fact(
                            boundary,
                            SemanticIncompleteSubject::Value(pointer),
                            SemanticIncompleteReason::Pointer(
                                PointerIncompleteReason::UnknownLayout,
                            ),
                            metadata,
                        );
                    }
                }
                let result = self.expression_value(builder, left, expression_value_kind(left))?;
                self.append_effect(
                    builder,
                    boundary,
                    SemanticEffect::MemoryLoad {
                        kind,
                        location,
                        result,
                    },
                )?;
                result
            }
            RustAssignmentTarget::Unsupported => {
                self.expression_value(builder, left, expression_value_kind(left))?
            }
        };
        let operand = self.expression_value(builder, right, expression_value_kind(right))?;
        // Place adjustments and replacement Drop are reported by
        // assignment_target at the terminal, separately from the operator call.
        self.implicit_call_boundary(builder, node, boundary, scope)?;
        // Operator-assignment traits may compute anything. Keep both data
        // dependencies for value-flow and taint, without preserving scalar facts.
        let result = self.value(builder, boundary, SemanticValueKind::Temporary)?;
        self.session.append_language_defined_value_flows(
            builder,
            boundary,
            [old, operand],
            result,
        )?;
        self.write_assignment_target(builder, terminal, target, node, result)?;
        self.session
            .add_target_edge(builder, boundary, EdgeTarget::normal(terminal))?;
        self.session.add_target_edge(builder, terminal, next)?;
        evaluations.push(right);
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    fn implicit_call_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        boundary: ProgramPointId,
        scope: ScopeFrameId,
    ) -> Result<(), RustLoweringError> {
        let reason = implicit_runtime_call_reason(node.kind())
            .expect("implicit-call expressions are dispatched by node kind");
        self.session.record_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            reason,
        )?;
        if rust_operation_can_abort(node) {
            // Not lowering the abort edge is `Unsupported`, the shape the
            // shared implicit-abort discharge closes; an operation that cannot
            // abort publishes nothing at all.
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                boundary,
                scope,
                SemanticGapKind::Unsupported,
                "an implicit Rust built-in check may abort here; that abort edge is not lowered",
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn implicit_call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        self.implicit_call_boundary(builder, node, boundary, scope)?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        self.session.record_gap(
            builder,
            boundary,
            SemanticGapSubject::Value(result),
            SemanticCapability::Values,
            SemanticGapKind::Unknown,
            "implicit call result is not modeled (#6409)",
        )?;
        self.session.add_target_edge(builder, boundary, next)?;
        let children = runtime_expression_children(node);
        self.schedule_expressions(
            builder,
            entry,
            &children,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn if_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let condition = required_field(node, "condition")?;
        let consequence = required_field(node, "consequence")?;
        let alternative = node
            .child_by_field_name("alternative")
            .and_then(first_named_child);
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let consequence_has_bindings = condition_introduces_pattern_bindings(condition);
        let consequence_scope = if consequence_has_bindings {
            self.push_cleanup_scope(builder, scope, condition)?
        } else {
            scope
        };
        let consequence_entry =
            self.schedule_branch(builder, consequence, next, consequence_scope, stack)?;
        if consequence_has_bindings {
            self.add_drop_omission_gaps(
                builder,
                consequence_entry.expect("scheduled branch has an entry"),
                "values introduced by an if-let condition may require implicit Drop when the consequence completes",
                SemanticGapDischarge::None,
            )?;
        }
        let alternative_entry = alternative
            .map(|alternative| self.schedule_branch(builder, alternative, next, scope, stack))
            .transpose()?
            .flatten();
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: EdgeTarget {
                point: consequence_entry.unwrap_or(next.point),
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false: EdgeTarget {
                point: alternative_entry.unwrap_or(next.point),
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope,
        });
        self.session
            .add_target_edge(builder, entry, EdgeTarget::normal(condition_entry))
    }

    fn schedule_branch(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<Option<ProgramPointId>, RustLoweringError> {
        let entry = self.point(builder, node, Vec::new())?;
        if node.kind() == "block" {
            stack.push(Work::Statement {
                node,
                entry,
                next,
                scope,
            });
        } else {
            stack.push(Work::Expression {
                node,
                entry,
                next,
                scope,
            });
        }
        Ok(Some(entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn match_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let value = required_field(node, "value")?;
        let body = required_field(node, "body")?;
        let arms = named_children(body)
            .into_iter()
            .filter(|child| child.kind() == "match_arm")
            .collect::<Vec<_>>();
        let decision = self.point(builder, node, Vec::new())?;
        // No point-wide control-flow gap: every arm gets a case edge below and
        // the last arm's guard-false edge continues past the match, so the
        // represented successor set is a superset of the real one. What a
        // selected pattern *binds* is still unknown, and that is published per
        // arm, on the value it binds.
        if arms.is_empty() {
            self.session.add_target_edge(builder, decision, next)?;
        } else {
            let candidates = arms
                .iter()
                .map(|arm| {
                    arm.child_by_field_name("pattern")
                        .map(|pattern| self.point(builder, pattern, Vec::new()))
                        .unwrap_or_else(|| self.point(builder, *arm, Vec::new()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut arm_scopes = Vec::with_capacity(arms.len());
            for (index, candidate) in candidates.iter().enumerate() {
                let pattern = required_field(arms[index], "pattern")?;
                arm_scopes.push(self.push_cleanup_scope(builder, scope, pattern)?);
                // Only an arm that actually binds a name introduces a value
                // whose identity and drop obligation are unresolved. A literal
                // or wildcard arm introduces neither.
                let binds = arms[index]
                    .child_by_field_name("pattern")
                    .is_some_and(rust_pattern_binds_value);
                if !binds {
                    continue;
                }
                self.unsupported_pattern_gaps(
                    builder,
                    *candidate,
                    pattern,
                    value,
                    "what a selected Rust match pattern binds depends on the scrutinee's runtime shape",
                )?;
                self.add_drop_omission_gaps(
                    builder,
                    *candidate,
                    "values introduced by a selected match pattern may require implicit Drop when the arm completes",
                    SemanticGapDischarge::None,
                )?;
            }
            for candidate in &candidates {
                self.session.add_target_edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: *candidate,
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
            }
            for index in (0..arms.len()).rev() {
                let arm = arms[index];
                let arm_value = required_field(arm, "value")?;
                let arm_entry = self.point(builder, arm_value, Vec::new())?;
                stack.push(Work::Expression {
                    node: arm_value,
                    entry: arm_entry,
                    next,
                    scope: arm_scopes[index],
                });
                let pattern = required_field(arm, "pattern")?;
                if let Some(guard) = pattern.child_by_field_name("condition") {
                    stack.push(Work::Condition {
                        node: guard,
                        entry: candidates[index],
                        when_true: EdgeTarget {
                            point: arm_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        when_false: EdgeTarget {
                            point: candidates.get(index + 1).copied().unwrap_or(next.point),
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                        scope: arm_scopes[index],
                    });
                } else {
                    self.session.add_target_edge(
                        builder,
                        candidates[index],
                        EdgeTarget {
                            point: arm_entry,
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                }
            }
        }
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(decision),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn loop_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let body = required_field(node, "body")?;
        let body_entry = self.point(builder, body, Vec::new())?;
        // A `loop` re-enters its body.
        self.session
            .record_loop_site(builder, node, body_entry, body_entry)?;
        let label = control_label(node, self.source);
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label,
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: body_entry,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: loop_scope,
        });
        self.session
            .add_target_edge(builder, entry, EdgeTarget::normal(body_entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn while_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        self.session
            .record_loop_site(builder, node, condition_entry, body_entry)?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: control_label(node, self.source),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: condition_entry,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let body_has_bindings = condition_introduces_pattern_bindings(condition);
        let body_scope = if body_has_bindings {
            self.push_cleanup_scope(builder, loop_scope, condition)?
        } else {
            loop_scope
        };
        if body_has_bindings {
            self.add_drop_omission_gaps(
                builder,
                body_entry,
                "values introduced by a while-let condition may require implicit Drop after each selected iteration",
                SemanticGapDischarge::None,
            )?;
        }
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: condition_entry,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: body_scope,
        });
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false: EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope: loop_scope,
        });
        self.session
            .add_target_edge(builder, entry, EdgeTarget::normal(condition_entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn for_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let iterable = required_field(node, "value")?;
        let body = required_field(node, "body")?;
        let test = self.point(builder, node, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: control_label(node, self.source),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: test,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let pattern = required_field(node, "pattern")?;
        let body_scope = self.push_cleanup_scope(builder, loop_scope, pattern)?;
        // The values the pattern binds are values of this procedure like any
        // other: each derives from the iterable. Publishing that element-of
        // relation is what carries a tainted collection into a loop body. A
        // destructuring pattern binds one value per component and every one of
        // them derives from the iterable, so `for (key, value) in map` publishes
        // two element-of flows rather than none (#2705).
        let elements = node
            .child_by_field_name("pattern")
            .map(rust_pattern_binding_identifiers)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|name| {
                node_text(self.source, name)
                    .and_then(|text| self.local_declaration_value(text, name.start_byte()))
            })
            .collect::<Vec<_>>();
        let region = CleanupRegionId::new(
            u32::try_from(self.next_cleanup_region - 1)
                .expect("push_cleanup_scope allocated this region"),
        );
        let _has_cleanup_actions = self
            .register_binding_cleanup_actions(builder, body_scope, region, &elements, body_entry)?;
        if !elements.is_empty() {
            self.binding_cleanup_regions.insert(region);
        }
        if !elements.is_empty() {
            let iterable_value =
                self.expression_value(builder, iterable, expression_value_kind(iterable))?;
            for element in &elements {
                self.session.append_language_defined_value_flows(
                    builder,
                    body_entry,
                    [iterable_value],
                    *element,
                )?;
            }
        }
        // A pattern that binds a primitive element runs no destructor, exactly
        // as for a `let`.
        let element_may_drop = elements.is_empty()
            || elements
                .iter()
                .any(|element| !self.definitely_non_dropping.contains(element));
        if element_may_drop {
            self.add_drop_omission_gaps(
                builder,
                body_entry,
                "the per-iteration for-pattern value may require implicit Drop after the selected iteration",
                SemanticGapDischarge::None,
            )?;
        }
        self.session.record_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "IntoIterator conversion and Iterator::next are implicit calls not emitted as fabricated call sites",
        )?;
        // No `NormalControlFlow` gap: both successors of the exhaustion test
        // are represented below, so claiming the loop's control flow is
        // unknown over-states what is missing.
        self.session.add_target_edge(
            builder,
            test,
            EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.session.add_target_edge(
            builder,
            test,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: test,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: body_scope,
        });
        // When the iterable provably yields at least one element, the first
        // iteration enters the body without consulting the exhaustion test.
        // Routing the entry through the test instead would keep a
        // zero-iteration path that this loop does not have, and a kill inside
        // the body would then look avoidable. Java's counted `for` states the
        // same fact through `for_condition_starts_true`.
        let first_iteration = if rust_iteration_yields_an_element(iterable, self.source) {
            EdgeTarget::normal(body_entry)
        } else {
            EdgeTarget::normal(test)
        };
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: first_iteration,
            scope,
        });
        Ok(())
    }

    fn break_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let label_node = direct_named_child_kind(node, "label");
        let value = named_children(node)
            .into_iter()
            .find(|child| child.kind() != "label");
        let terminal = if value.is_some() {
            self.point(builder, node, Vec::new())?
        } else {
            entry
        };
        if value.is_some() {
            self.session.record_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "break value transfer into the loop or labeled-block result is not represented",
            )?;
        }
        let label = label_node.and_then(|label| node_text(self.source, label));
        self.abrupt(builder, terminal, scope, CompletionKind::Break, label)?;
        if let Some(value) = value {
            stack.push(Work::Expression {
                node: value,
                entry,
                next: EdgeTarget::normal(terminal),
                scope,
            });
        }
        Ok(())
    }

    fn continue_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
    ) -> Result<(), RustLoweringError> {
        let label =
            direct_named_child_kind(node, "label").and_then(|label| node_text(self.source, label));
        self.abrupt(builder, entry, scope, CompletionKind::Continue, label)
    }

    fn return_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let value_node = first_named_child(node);
        let terminal = if value_node.is_some() {
            self.point(builder, node, Vec::new())?
        } else {
            entry
        };
        let value = value_node
            .map(|_| self.value(builder, terminal, SemanticValueKind::Return))
            .transpose()?;
        if let (Some(value_node), Some(value)) = (value_node, value) {
            let source =
                self.expression_value(builder, value_node, expression_value_kind(value_node))?;
            let transferred = self.value(builder, terminal, SemanticValueKind::Temporary)?;
            self.append_ownership_transfer(
                builder,
                terminal,
                value_node,
                source,
                transferred,
                self.return_type.map(RustValueType::Declared),
            )?;
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    source: transferred,
                    target: value,
                },
            )?;
        }
        self.append_effect(builder, terminal, SemanticEffect::ProcedureReturn { value })?;
        self.abrupt(builder, terminal, scope, CompletionKind::Return, None)?;
        if let Some(value_node) = value_node {
            stack.push(Work::Expression {
                node: value_node,
                entry,
                next: EdgeTarget::normal(terminal),
                scope,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn try_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let operand = first_named_child(node).ok_or_else(|| missing_field(node, "operand"))?;
        let branch = self.point(builder, node, Vec::new())?;
        let continued = self.point(builder, node, Vec::new())?;
        let residual = self.point(builder, node, Vec::new())?;
        let operand_value =
            self.expression_value(builder, operand, expression_value_kind(operand))?;
        let continued_value = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let residual_value = self.value(builder, residual, SemanticValueKind::Return)?;
        let residual_payload = self.value(builder, residual, SemanticValueKind::Temporary)?;
        // The IR has no enum-variant payload projection. Assignment conservatively
        // approximates both payloads, so error taint can also reach the output.
        // Try::branch is language control, not an implicit user call. Its opaque
        // two-way split keeps both outcomes without treating the variant as bool.
        let returns_option = self.return_type.is_some_and(|ty| {
            ty.kind() == "generic_type"
                && ty.child_by_field_name("type").is_some_and(|name| {
                    name.kind() == "type_identifier"
                        && node_text(self.source, name) == Some("Option")
                })
        });
        self.append_effect(
            builder,
            continued,
            SemanticEffect::Assignment {
                target: continued_value,
                value: operand_value,
            },
        )?;
        if !returns_option {
            self.append_effect(
                builder,
                residual,
                SemanticEffect::Assignment {
                    target: residual_payload,
                    value: operand_value,
                },
            )?;
        }
        self.session.add_target_edge(
            builder,
            branch,
            EdgeTarget {
                point: continued,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.session.add_target_edge(builder, continued, next)?;
        self.session.add_target_edge(
            builder,
            branch,
            EdgeTarget {
                point: residual,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        // ProcedureReturn carries control; this transfer publishes its normal
        // return-value port, exactly as an explicit return does. For Option the
        // payload is fresh None, so no operand taint reaches the return port.
        self.append_effect(
            builder,
            residual,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                source: residual_payload,
                target: residual_value,
            },
        )?;
        self.append_effect(
            builder,
            residual,
            SemanticEffect::ProcedureReturn {
                value: Some(residual_value),
            },
        )?;
        self.session.add_gap_with_impacts_and_discharge(
            builder,
            residual,
            SemanticGapSubject::Value(residual_value),
            SemanticCapability::CleanupControlFlow,
            SemanticGapImpacts::NONE,
            SemanticGapKind::Unknown,
            SemanticGapDischarge::InertDropGlue,
            "the ? residual path may drop temporaries and enclosing locals before returning",
        )?;
        if !returns_option {
            let return_type = self.return_type.and_then(|ty| node_text(self.source, ty));
            self.session.add_gap_with_impacts_and_discharge(
                builder,
                residual,
                SemanticGapSubject::Value(residual_value),
                SemanticCapability::Values,
                SemanticGapImpacts::NONE,
                SemanticGapKind::Unknown,
                SemanticGapDischarge::ResidualConversion,
                format!(
                    "the ? residual conversion to {} is not modeled: the operand's error type is not known at the workspace host",
                    return_type.unwrap_or("unresolved")
                ),
            )?;
        }
        self.abrupt(builder, residual, scope, CompletionKind::Return, None)?;
        stack.push(Work::Expression {
            node: operand,
            entry,
            next: EdgeTarget::normal(branch),
            scope,
        });
        Ok(())
    }

    fn try_block(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _scope: ScopeFrameId,
        _stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        first_named_child(node).ok_or_else(|| missing_field(node, "block"))?;
        let boundary = self.point(builder, node, Vec::new())?;
        self.session
            .add_target_edge(builder, entry, EdgeTarget::normal(boundary))?;
        for (capability, kind, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "try-block success and residual propagation are not yet lowered",
            ),
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "calls and Try/FromResidual conversions inside the unsupported try block are not emitted",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "panic and residual behavior inside the unsupported try block are not lowered",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                SemanticGapKind::Unknown,
                "temporary and lexical Drop behavior inside the unsupported try block is not lowered",
            ),
            (
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unknown,
                "resource release inside the unsupported try block depends on inferred types and Drop implementations",
            ),
            (
                SemanticCapability::Values,
                SemanticGapKind::Unsupported,
                "the try-block result value is not represented",
            ),
        ] {
            self.session.record_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                capability,
                kind,
                detail,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn await_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let awaited_node = first_named_child(node);
        let structural_node_index = self.structural_node_index;
        let AwaitScaffold {
            suspend,
            normal_resume: normal,
            exceptional_resume: exceptional,
            ..
        } = self
            .session
            .add_await_scaffold(builder, |session, builder| {
                let range = node.byte_range();
                let occurrence = session.next_source_occurrence(range.start, range.end);
                let anchor = source_anchor(node, occurrence).map_err(RustLoweringError::Invalid)?;
                let ast_identity = structural_node_index.and_then(|index| index.identity(node));
                session.add_mapping_with_ast_identity(
                    builder,
                    anchor,
                    SourceMappingKind::Exact,
                    ast_identity,
                )
            })?;
        self.session.add_target_edge(builder, normal, next)?;
        let live_places = self
            .binding_scopes
            .iter()
            .filter(|(_, (live_from, scope_start, scope_end))| {
                *live_from <= node.start_byte()
                    && *scope_start <= node.start_byte()
                    && node.end_byte() <= *scope_end
            })
            .flat_map(|(value, _)| {
                self.cleanup_places_by_binding
                    .get(value)
                    .into_iter()
                    .flatten()
                    .cloned()
            })
            .collect::<Vec<_>>();
        if let Some(cancellation_route) =
            builder.resolve_cancellation(scope, self.exceptional_exit, &live_places)
        {
            if !completion_has_unrouted_drop(&cancellation_route) {
                self.add_drop_omission_gaps(
                    builder,
                    exceptional,
                    "the awaited future temporary may require implicit Drop on exceptional resume",
                    SemanticGapDischarge::None,
                )?;
            }
            self.route(builder, exceptional, &cancellation_route)?;
        } else {
            self.abrupt(builder, exceptional, scope, CompletionKind::Throw, None)?;
        }
        self.session.record_gap(
            builder,
            suspend,
            SemanticGapSubject::Point,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            "Future::poll, executor scheduling, wakeups, pinning, repeated pending states, and the conservative exceptional boundary require async refinement",
        )?;
        self.session.record_gap(
            builder,
            suspend,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "IntoFuture::into_future and Future::poll are implicit calls not emitted as fabricated call sites",
        )?;
        self.add_non_rejoining_exceptional_exit_gap(
            builder,
            suspend,
            scope,
            SemanticGapKind::Unknown,
            "implicit future conversion and polling may panic, but their exceptional behavior is not refined",
        )?;
        if let Some(awaited_node) = awaited_node {
            stack.push(Work::Expression {
                node: awaited_node,
                entry,
                next: EdgeTarget::normal(suspend),
                scope,
            });
        } else {
            self.session
                .add_target_edge(builder, entry, EdgeTarget::normal(suspend))?;
        }
        Ok(())
    }

    fn yield_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let value = first_named_child(node);
        let suspend = if value.is_some() {
            self.point(builder, node, Vec::new())?
        } else {
            entry
        };
        self.session.record_gap(
            builder,
            suspend,
            SemanticGapSubject::Point,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "yield suspension, saved generator state, and resume value are not lowered",
        )?;
        if let Some(value) = value {
            stack.push(Work::Expression {
                node: value,
                entry,
                next: EdgeTarget::normal(suspend),
                scope,
            });
        }
        Ok(())
    }

    fn macro_invocation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let lexical_context = self
            .source_root
            .descendant_for_byte_range(node.start_byte(), node.end_byte())
            .expect("macro fragment retains its original source range");
        let local_macro = brokk_bifrost_rust::macro_matcher::macro_invocation_is_locally_bound(
            node,
            self.source,
            self.exported_macro_definitions,
            lexical_context,
        );
        let Some(path) = node.child_by_field_name("macro") else {
            self.macro_boundary(builder, node, entry, scope)?;
            return Ok(());
        };
        let address_of_name = brokk_bifrost_rust::graph_support::rust_path_segments(path)
            .and_then(|segments| segments.last().copied())
            .and_then(|segment| node_text(self.source, segment));
        let address_of_candidate = matches!(address_of_name, Some("addr_of" | "addr_of_mut"));
        // Parse-time IR is content-only. Under #5205's names-preserved
        // assumption, built-ins whose semantics we already lower (a #5220
        // runtime layout, a formatting macro, or a value intrinsic such as
        // vec!/matches!) apply unless this file supplies a different macro. Cross-file glob/macro_use
        // shadowing is the accepted residual risk tracked by #5282; query-time
        // sink/source binding still requires resolver proof. No Format exception.
        let candidate = rust_macro_call_candidate(path, self.source);
        let supported_builtin = matches!(
            candidate,
            Some(RustMacroCallCandidate::Value(_) | RustMacroCallCandidate::Formatting(_))
        )
            || brokk_bifrost_rust::format_args::rust_macro_runtime_layout_for_path(
                path,
                self.source,
            )
            .is_some();
        if local_macro || !supported_builtin || candidate.is_none() {
            let boundary = self.opaque_macro_call(builder, node, path, entry, next, scope)?;
            if address_of_candidate {
                let value = self.expression_value(builder, node, SemanticValueKind::Address)?;
                self.add_incomplete_fact(
                    boundary,
                    SemanticIncompleteSubject::Value(value),
                    SemanticIncompleteReason::Pointer(
                        PointerIncompleteReason::UnsupportedOperation,
                    ),
                    self.metadata(boundary)?,
                );
            }
            return Ok(());
        }
        let candidate = candidate.expect("a supported built-in has a macro grammar candidate");
        self.builtin_macro_call(builder, node, path, candidate, entry, next, scope, stack)
    }

    /// An expansion can invoke arbitrary code, but its captured tokens are
    /// not Rust call arguments. Keep the invocation open without evaluating
    /// operands or passing their values to the unknown target (#5267).
    fn opaque_macro_call(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        path: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Result<ProgramPointId, RustLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.source_value(
            builder,
            rust_callable_anchor(path),
            SemanticValueKind::Callable,
        )?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(
            builder,
            rust_callable_anchor(path),
            SemanticValueKind::Exception,
        )?;
        let resolution = CallableTargetResolution::Unknown;
        let metadata = self.metadata(invoke)?;
        self.append_effect(
            builder,
            invoke,
            SemanticEffect::CallableReference {
                result: callee,
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets: resolution.clone(),
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
        )?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver: None,
                arguments: Box::new([]),
                normal_results: Box::new([]),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        // Retain the opaque token region as a source boundary, without
        // lowering any expression inside it. A source query for a captured
        // identifier must not widen to this call's result or its enclosing
        // aggregate merely because the tokens have no executable read point.
        let input = if let Some(tokens) =
            brokk_bifrost_rust::declarations::rust_macro_invocation_arguments(node)
        {
            let input = self.point(builder, tokens, Vec::new())?;
            self.session
                .add_target_edge(builder, entry, EdgeTarget::normal(input))?;
            input
        } else {
            entry
        };
        self.session
            .add_target_edge(builder, input, EdgeTarget::normal(invoke))?;
        self.session
            .add_target_edge(builder, invoke, EdgeTarget::normal(normal))?;
        self.session.add_target_edge(
            builder,
            invoke,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.session.add_target_edge(builder, normal, next)?;
        self.abrupt(builder, exceptional, scope, CompletionKind::Throw, None)?;
        self.session.add_callable_resolution_gaps(
            builder, invoke, callee, call_site, &resolution,
            "unknown macro identity requires query-time dispatch refinement",
            "unknown macro expansion: captured tokens are not evaluated or passed as argument values",
        )?;
        self.session.record_gap(
            builder,
            invoke,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            "unknown macro expansion may return, break, continue, or propagate an error; normal call continuations do not refine this control flow",
        )?;
        Ok(invoke)
    }

    #[allow(clippy::too_many_arguments)]
    fn builtin_macro_call(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        path: Node<'tree>,
        candidate: RustMacroCallCandidate,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let argument_evaluation = self.point(builder, node, Vec::new())?;
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        // Match call_expression lowering: the callable value is anchored to
        // the structured path's terminal name, which exact-call dispatch maps
        // back to the full path from the invocation's source range.
        let callable_anchor = rust_callable_anchor(path);
        let callee = self.source_value(builder, callable_anchor, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, callable_anchor, SemanticValueKind::Exception)?;
        let resolution = CallableTargetResolution::Unknown;
        let metadata = self.metadata(invoke)?;
        // SemanticCallSite has no macro-specific callable kind. A formatting
        // invocation uses its Function form; exact macro identity is resolved
        // later by ordinary query-time dispatch from the structured AST path.
        self.append_effect(
            builder,
            invoke,
            SemanticEffect::CallableReference {
                result: callee,
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets: resolution.clone(),
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
        )?;

        let runtime_layout =
            brokk_bifrost_rust::format_args::rust_macro_runtime_layout_for_path(path, self.source);
        let is_sink_macro = runtime_layout.is_some();
        let has_writer_receiver = matches!(
            candidate,
            RustMacroCallCandidate::Formatting(macro_kind) if macro_kind.has_writer_receiver()
        );
        let mut vector_element_count = None;
        let parsed = match candidate {
            RustMacroCallCandidate::Value(RustValueMacro::Matches) => {
                brokk_bifrost_rust::format_args::rust_matches_macro_scrutinee(node, self.source)
                    .map(|argument| vec![argument])
            }
            RustMacroCallCandidate::Value(RustValueMacro::Vec) => {
                brokk_bifrost_rust::format_args::rust_vec_macro_arguments(node, self.source).map(
                    |arguments| match arguments {
                        brokk_bifrost_rust::format_args::RustVecMacroArguments::Elements(
                            elements,
                        ) => {
                            vector_element_count = Some(elements.len());
                            elements
                        }
                        brokk_bifrost_rust::format_args::RustVecMacroArguments::Repeated(
                            repeated,
                        ) => {
                            vector_element_count = Some(1);
                            vec![repeated.element, repeated.count]
                        }
                    },
                )
            }
            _ => brokk_bifrost_rust::format_args::rust_format_macro_arguments(node, self.source),
        };
        let arguments = parsed.as_ref().ok();
        let mut complete = arguments.is_some();
        let mut receiver = None;
        let mut call_arguments = Vec::new();
        let mut argument_values = Vec::new();
        let mut operand_nodes = Vec::new();
        if let Some(arguments) = arguments {
            if matches!(
                candidate,
                RustMacroCallCandidate::Value(RustValueMacro::Dbg)
            ) && arguments.len() != 1
            {
                complete = false;
            }
            for argument in arguments {
                if let Some(expression) = self
                    .operand_nodes
                    .get(&(
                        argument.value_range.start_byte,
                        argument.value_range.end_byte,
                    ))
                    .copied()
                {
                    self.emit_local_bindings(builder, expression)?;
                    operand_nodes.push(expression);
                } else {
                    complete = false;
                }
            }
            if has_writer_receiver {
                if let Some(writer) = arguments.first() {
                    receiver = Some(self.format_macro_argument_value(
                        builder,
                        node,
                        argument_evaluation,
                        writer,
                    )?);
                } else {
                    complete = false;
                }
            }
            for (index, argument) in arguments.iter().enumerate() {
                if has_writer_receiver && index == 0 {
                    continue;
                }
                let value =
                    self.format_macro_argument_value(builder, node, argument_evaluation, argument)?;
                argument_values.push(value);
                if !is_sink_macro {
                    call_arguments.push(SemanticCallArgument::direct(
                        value,
                        ArgumentDomain::Positional,
                    ));
                }
            }

            let format_index = brokk_bifrost_rust::format_args::rust_macro_format_operand(
                node,
                self.source,
                arguments,
            );
            let expects_format = matches!(
                candidate,
                RustMacroCallCandidate::Formatting(_) | RustMacroCallCandidate::Logging(_)
            ) || matches!(
                candidate,
                RustMacroCallCandidate::Value(RustValueMacro::Assert | RustValueMacro::DebugAssert)
                    if arguments.len() > 1
            ) || matches!(
                candidate,
                RustMacroCallCandidate::Value(
                    RustValueMacro::AssertEq
                        | RustValueMacro::AssertNe
                        | RustValueMacro::DebugAssertEq
                        | RustValueMacro::DebugAssertNe
                ) if arguments.len() > 2
            );
            if expects_format && format_index.is_none() {
                complete = false;
            }
            if let Some(format_index) = format_index {
                let format_literal = arguments
                    .get(format_index)
                    .and_then(|argument| {
                        self.operand_nodes
                            .get(&(
                                argument.value_range.start_byte,
                                argument.value_range.end_byte,
                            ))
                            .copied()
                    })
                    .filter(|literal| {
                        matches!(literal.kind(), "string_literal" | "raw_string_literal")
                    });
                let decoded_format = format_literal.and_then(|literal| {
                    brokk_bifrost_rust::cargo_routes::rust_static_string_literal(
                        literal,
                        self.source,
                    )
                });
                let captures = format_literal
                    .and_then(|literal| self.operand_children.get(&literal.id()))
                    .cloned()
                    .unwrap_or_default();
                for capture in &captures {
                    let value =
                        self.expression_value(builder, *capture, expression_value_kind(*capture))?;
                    operand_nodes.push(*capture);
                    if is_sink_macro {
                        argument_values.push(value);
                    } else {
                        call_arguments.push(SemanticCallArgument::direct(
                            value,
                            ArgumentDomain::Positional,
                        ));
                    }
                }
                if let Some(decoded_format) = decoded_format {
                    match brokk_bifrost_rust::format_args::parse_rust_format_string(&decoded_format)
                    {
                        Ok(format) => {
                            let positional = arguments
                                .iter()
                                .skip(format_index + 1)
                                .filter(|argument| argument.name.is_none())
                                .collect::<Vec<_>>();
                            let named = arguments
                                .iter()
                                .filter_map(|argument| argument.name.as_deref())
                                .collect::<HashSet<_>>();
                            let mut implicit_index = 0;
                            for reference in format.references.iter() {
                                match reference {
                                    brokk_bifrost_rust::format_args::RustFormatArgumentReference::Implicit => {
                                        if positional.get(implicit_index).is_none() {
                                            complete = false;
                                        }
                                        implicit_index += 1;
                                    }
                                    brokk_bifrost_rust::format_args::RustFormatArgumentReference::Index(index) => {
                                        if positional.get(*index).is_none() {
                                            complete = false;
                                        }
                                    }
                                    brokk_bifrost_rust::format_args::RustFormatArgumentReference::Name(name) => {
                                        if named.contains(name.as_ref()) {
                                            continue;
                                        }
                                        if !captures.iter().any(|capture| node_text(self.source, *capture) == Some(name.as_ref())) {
                                            complete = false;
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => complete = false,
                    }
                } else {
                    complete = false;
                }
            }

            if let Some(layout) = runtime_layout {
                use brokk_bifrost_rust::format_args::RustMacroRuntimeArgument;
                call_arguments.clear();
                for role in layout.arguments {
                    let value = match *role {
                        RustMacroRuntimeArgument::Message { first_operand }
                        | RustMacroRuntimeArgument::OptionalMessage { first_operand } => {
                            let aggregate = self.value_at_source_range(
                                builder,
                                node.range(),
                                SemanticValueKind::Temporary,
                            )?;
                            // Captures are appended after written operands, so the
                            // same slice excludes condition/comparison inputs.
                            self.session.append_language_defined_value_flows(
                                builder,
                                argument_evaluation,
                                argument_values.iter().skip(first_operand).copied(),
                                aggregate,
                            )?;
                            if matches!(role, RustMacroRuntimeArgument::OptionalMessage { .. }) {
                                let has_message = arguments.len() > first_operand;
                                let option = self.value_at_source_range(
                                    builder,
                                    node.range(),
                                    SemanticValueKind::Temporary,
                                )?;
                                self.session.add_allocation(
                                    builder,
                                    argument_evaluation,
                                    option,
                                    AllocationKind::Object,
                                )?;
                                let variant = self.value_at_source_range(
                                    builder,
                                    node.range(),
                                    SemanticValueKind::ConstantString(
                                        if has_message {
                                            "core.option.Option.Some"
                                        } else {
                                            "core.option.Option.None"
                                        }
                                        .into(),
                                    ),
                                )?;
                                let tag = self.session.add_memory_location(
                                    builder,
                                    argument_evaluation,
                                    MemoryLocationKind::Property {
                                        base: option,
                                        key: "variant".into(),
                                    },
                                )?;
                                self.append_effect(
                                    builder,
                                    argument_evaluation,
                                    SemanticEffect::MemoryStore {
                                        kind: MemoryAccessKind::Property,
                                        location: tag,
                                        value: variant,
                                    },
                                )?;
                                if has_message {
                                    let payload = self.session.add_memory_location(
                                        builder,
                                        argument_evaluation,
                                        MemoryLocationKind::Property {
                                            base: option,
                                            key: "core.option.Option.Some.0".into(),
                                        },
                                    )?;
                                    self.append_effect(
                                        builder,
                                        argument_evaluation,
                                        SemanticEffect::MemoryStore {
                                            kind: MemoryAccessKind::Property,
                                            location: payload,
                                            value: aggregate,
                                        },
                                    )?;
                                    self.session.append_language_defined_value_flows(
                                        builder,
                                        argument_evaluation,
                                        [aggregate],
                                        option,
                                    )?;
                                }
                                option
                            } else {
                                aggregate
                            }
                        }
                        RustMacroRuntimeArgument::AssertionKind => {
                            let kind = match candidate {
                                RustMacroCallCandidate::Value(
                                    RustValueMacro::AssertNe | RustValueMacro::DebugAssertNe,
                                ) => "Ne",
                                _ => "Eq",
                            };
                            self.value_at_source_range(
                                builder,
                                node.range(),
                                SemanticValueKind::ConstantString(kind.into()),
                            )?
                        }
                        RustMacroRuntimeArgument::BorrowedOperand(index) => {
                            let (Some(argument), Some(value)) =
                                (arguments.get(index), argument_values.get(index))
                            else {
                                complete = false;
                                continue;
                            };
                            self.borrow_macro_argument_value(
                                builder,
                                argument,
                                argument_evaluation,
                                *value,
                            )?
                        }
                        RustMacroRuntimeArgument::DebugOperand => {
                            let (Some(argument), Some(value)) =
                                (arguments.first(), argument_values.first())
                            else {
                                complete = false;
                                continue;
                            };
                            let reference = self.borrow_macro_argument_value(
                                builder,
                                argument,
                                argument_evaluation,
                                *value,
                            )?;
                            let aggregate = self.value_at_source_range(
                                builder,
                                node.range(),
                                SemanticValueKind::Temporary,
                            )?;
                            self.session.append_language_defined_value_flows(
                                builder,
                                argument_evaluation,
                                [reference],
                                aggregate,
                            )?;
                            aggregate
                        }
                    };
                    call_arguments.push(SemanticCallArgument::direct(
                        value,
                        ArgumentDomain::Positional,
                    ));
                }
                // Result-producing macros use the query-time intrinsic
                // transfer after dispatch proves their standard identity.
                // A syntax candidate alone must not taint a user macro result.
            }
        }

        match candidate {
            RustMacroCallCandidate::Value(RustValueMacro::Dbg) => {
                if let Some(value) = argument_values.first() {
                    self.session.append_language_defined_value_flows(
                        builder,
                        argument_evaluation,
                        [*value],
                        result,
                    )?;
                }
            }
            RustMacroCallCandidate::Value(RustValueMacro::Vec) => {
                let element_count = vector_element_count.unwrap_or_default();
                self.session.append_language_defined_value_flows(
                    builder,
                    argument_evaluation,
                    argument_values.iter().take(element_count).copied(),
                    result,
                )?;
                call_arguments = argument_values
                    .iter()
                    .take(element_count)
                    .copied()
                    .map(|value| SemanticCallArgument::direct(value, ArgumentDomain::Positional))
                    .collect();
            }
            _ => {}
        }

        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: call_arguments.into_boxed_slice(),
                normal_results: Box::new([]),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        let operand_entries = operand_nodes
            .iter()
            .map(|operand| self.point(builder, *operand, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.session.add_target_edge(
            builder,
            entry,
            EdgeTarget::normal(
                operand_entries
                    .first()
                    .copied()
                    .unwrap_or(argument_evaluation),
            ),
        )?;
        schedule_sequential_work(
            stack,
            &operand_nodes,
            &operand_entries,
            EdgeTarget::normal(argument_evaluation),
            scope,
            |_, node, entry, next, scope| Work::Expression {
                node,
                entry,
                next,
                scope,
            },
        );
        self.session
            .add_target_edge(builder, argument_evaluation, EdgeTarget::normal(invoke))?;
        self.session
            .add_target_edge(builder, invoke, EdgeTarget::normal(normal))?;
        self.session.add_target_edge(
            builder,
            invoke,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.session.add_target_edge(builder, normal, next)?;
        self.add_droppable_initializer_temporary_gap(builder, node, exceptional, scope)?;
        self.abrupt(builder, exceptional, scope, CompletionKind::Throw, None)?;
        // This is the same query-deferred target representation and paired
        // refinement gaps as an ordinary Rust path call. A user macro remains
        // open when its resolved identity has no intrinsic summary.
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;
        if matches!(
            candidate,
            RustMacroCallCandidate::Formatting(RustFormattingMacro::Panic)
                | RustMacroCallCandidate::Value(
                    RustValueMacro::Panic
                        | RustValueMacro::Unreachable
                        | RustValueMacro::Todo
                        | RustValueMacro::Unimplemented
                )
        ) {
            // The terminal macro name selects argument grammar, but query-time
            // dispatch has not yet proved the exact macro identity. Keep the
            // normal-completion boundary open until exact call resolution.
            let subject = SemanticGapSubject::CallSite(call_site);
            self.session.add_gap_with_impacts_and_discharge(
                builder,
                invoke,
                subject,
                SemanticCapability::NormalControlFlow,
                SemanticGapImpacts::for_gap(SemanticCapability::NormalControlFlow, subject),
                SemanticGapKind::Unknown,
                SemanticGapDischarge::CallResolution,
                "diverging macro identity is unresolved, so normal completion remains open",
            )?;
        }
        if !complete {
            self.session.record_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "built-in macro arguments or placeholder references are malformed, unavailable, or unresolved",
            )?;
        }
        Ok(())
    }

    fn format_macro_argument_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        _invocation: Node<'tree>,
        point: ProgramPointId,
        argument: &brokk_bifrost_rust::format_args::RustFormatMacroArgument,
    ) -> Result<ValueId, RustLoweringError> {
        if let Some(expression) = self
            .operand_nodes
            .get(&(
                argument.value_range.start_byte,
                argument.value_range.end_byte,
            ))
            .copied()
        {
            return self.expression_value(builder, expression, expression_value_kind(expression));
        }
        let value = self.value_at_source_range(
            builder,
            argument.value_range,
            SemanticValueKind::Temporary,
        )?;
        self.session.record_gap(
            builder,
            point,
            SemanticGapSubject::Value(value),
            SemanticCapability::Values,
            SemanticGapKind::Unsupported,
            "macro operand has no executable native expression fragment",
        )?;
        Ok(value)
    }

    fn borrow_macro_argument_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        argument: &brokk_bifrost_rust::format_args::RustFormatMacroArgument,
        point: ProgramPointId,
        value: ValueId,
    ) -> Result<ValueId, RustLoweringError> {
        let borrowed =
            self.value_at_source_range(builder, argument.value_range, SemanticValueKind::Address)?;
        self.session
            .append_language_defined_value_flows(builder, point, [value], borrowed)?;
        Ok(borrowed)
    }

    fn value_at_source_range(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        range: tree_sitter::Range,
        kind: SemanticValueKind,
    ) -> Result<ValueId, RustLoweringError> {
        let start = range.start_point;
        let end = range.end_point;
        let source_position = |byte, point: tree_sitter::Point| {
            Ok::<_, RustLoweringError>(SourcePosition::new(
                u32::try_from(byte)
                    .map_err(|_| RustLoweringError::Invalid("source byte exceeds u32".into()))?,
                u32::try_from(point.row)
                    .map_err(|_| RustLoweringError::Invalid("source line exceeds u32".into()))?,
                u32::try_from(point.column)
                    .map_err(|_| RustLoweringError::Invalid("source column exceeds u32".into()))?,
            ))
        };
        let span = SourceSpan::new(
            source_position(range.start_byte, start)?,
            source_position(range.end_byte, end)?,
        )
        .map_err(|error| RustLoweringError::Invalid(error.to_string()))?;
        let anchor = SourceAnchor::new(
            span,
            self.session
                .next_source_occurrence(range.start_byte, range.end_byte),
        );
        let metadata = self
            .session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)?;
        self.session
            .add_value_with_metadata(builder, metadata, kind)
    }

    fn macro_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
    ) -> Result<ProgramPointId, RustLoweringError> {
        // Keep macro-expansion uncertainty on a source-mapped boundary for the
        // invocation itself. The incoming point may carry a distinct gap (for
        // example, implicit Drop uncertainty for a match-arm binding), so
        // publishing the macro rows there would violate GapIndex's one-row
        // contract and conflate the two semantic causes. No continuation is
        // fabricated after an opaque expansion.
        let boundary = self.point(builder, node, Vec::new())?;
        self.session
            .add_target_edge(builder, entry, EdgeTarget::normal(boundary))?;
        self.add_incomplete_fact(
            boundary,
            SemanticIncompleteSubject::Procedure,
            SemanticIncompleteReason::Lifecycle(
                LifecycleIncompleteReason::UnsupportedMacroExpansion,
            ),
            self.metadata(boundary)?,
        );
        self.session.record_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            "macro token-tree expansion is unavailable; control after this invocation is intentionally not fabricated",
        )?;
        self.session.record_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "calls produced by macro expansion are unavailable and no textual macro parser is used",
        )?;
        self.add_non_rejoining_exceptional_exit_gap(
            builder,
            boundary,
            scope,
            SemanticGapKind::Unknown,
            "macro expansion may introduce panic or other exceptional behavior that is unavailable",
        )?;
        self.session.record_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::NonLocalControl,
            SemanticGapKind::Unsupported,
            "macro expansion may introduce return, break, continue, or other non-local control that is unavailable",
        )?;
        self.session.record_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::CleanupControlFlow,
            SemanticGapKind::Unsupported,
            "macro expansion may introduce scope exits or cleanup control that is unavailable",
        )?;
        self.session.record_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ResourceManagement,
            SemanticGapKind::Unsupported,
            "resource acquisition and release produced by macro expansion are unavailable",
        )?;
        Ok(boundary)
    }

    /// The qualified type path the receiver's written type proves, through
    /// the same-file `use` bindings when the written name is terminal-only.
    /// A terminal name this file shadows or binds ambiguously stays
    /// unresolved.
    fn receiver_qualified_type_identity(&self, receiver: Node<'tree>) -> Option<Vec<Box<str>>> {
        let Some(mut ty) = self.expression_type(receiver) else {
            let name = node_text(self.source, receiver)?;
            let initializer = self
                .local_binding_at(name, receiver.start_byte())?
                .initializer?;
            let function = (initializer.kind() == "call_expression")
                .then(|| initializer.child_by_field_name("function"))
                .flatten()
                .map(call_function_target)?;
            return self
                .vec_constructor_type_identity(function)
                .map(|(segments, _)| segments);
        };
        for _ in 0..RUST_RECEIVER_DEREFERENCE_BOUND {
            match self.dereferenced_type(ty) {
                Some(inner) => ty = inner,
                None => break,
            }
        }
        let RustValueType::Declared(ty) = ty else {
            return None;
        };
        let mut segments = rust_nominal_type_path(ty, self.source)?
            .into_iter()
            .map(Box::<str>::from)
            .collect::<Vec<_>>();
        if segments.len() == 1 {
            let [terminal] = segments.as_slice() else {
                return None;
            };
            segments = self.use_binding_identity(terminal)?.clone();
        }
        Some(segments)
    }

    fn vec_constructor_type_fact(
        &self,
        function: Node<'tree>,
        call_site: CallSiteId,
    ) -> Option<CallReceiverTypeFact> {
        let (receiver_type, member) = self.vec_constructor_type_identity(function)?;
        Some(CallReceiverTypeFact {
            call_site,
            receiver_type: receiver_type.into_boxed_slice(),
            member,
        })
    }

    fn vec_constructor_type_identity(
        &self,
        function: Node<'tree>,
    ) -> Option<(Vec<Box<str>>, Box<str>)> {
        let path = call_function_target(function);
        for (owner, identity) in [
            (&["std", "vec", "Vec"][..], &["std", "vec", "Vec"][..]),
            (&["alloc", "vec", "Vec"][..], &["alloc", "vec", "Vec"][..]),
        ] {
            for member in ["new", "with_capacity"] {
                let expected = [owner, &[member][..]].concat();
                if self.ownership.resolves_standard_path(path, &expected) {
                    return Some((
                        identity
                            .iter()
                            .map(|segment| Box::<str>::from(*segment))
                            .collect(),
                        member.into(),
                    ));
                }
            }
        }
        None
    }

    fn use_binding_identity(&self, terminal: &str) -> Option<&Vec<Box<str>>> {
        if self.facts.shadowed_type_names.contains(terminal) {
            return None;
        }
        self.facts.use_bindings.get(terminal)?.as_ref()
    }

    fn call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let function = required_field(node, "function")?;
        let callable_anchor = rust_callable_anchor(function);
        let callee =
            self.expression_value(builder, callable_anchor, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, callable_anchor, SemanticValueKind::Exception)?;
        let receiver_node = rust_call_receiver(function);
        let receiver = receiver_node
            .map(|receiver| {
                self.expression_value(builder, receiver, expression_value_kind(receiver))
            })
            .transpose()?;
        let callable_kind = if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let resolution = CallableTargetResolution::Unknown;
        let metadata = self.metadata(invoke)?;
        self.append_effect(
            builder,
            invoke,
            SemanticEffect::CallableReference {
                result: callee,
                callable: CallableValue {
                    kind: callable_kind,
                    targets: resolution.clone(),
                    target_evidence: metadata.evidence,
                    bound_receiver: receiver,
                    environment: None,
                },
            },
        )?;

        let arguments = call_arguments(node);
        let call_argument_values = arguments
            .iter()
            .map(|argument| {
                self.expression_value(builder, *argument, expression_value_kind(*argument))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.emit_pointer_call_facts(
            builder,
            function,
            receiver_node,
            receiver,
            &arguments,
            &call_argument_values,
            invoke,
            normal,
            result,
        )?;
        let argument_values = call_argument_values
            .iter()
            .map(|value| SemanticCallArgument::direct(*value, ArgumentDomain::Positional))
            .collect::<Vec<_>>();
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: argument_values.into_boxed_slice(),
                normal_results: Box::new([]),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        // Calls whose receiver or associated owner this file proves publish
        // that structural identity beside the call site. Model contracts are
        // applied from this fact when a query reaches the call.
        let receiver_fact = if let Some((receiver, member)) = rust_method_call_parts(function)
            && let Some(segments) = self.receiver_qualified_type_identity(receiver)
            && segments.len() >= 2
            && let Some(member) = node_text(self.source, member)
        {
            Some(CallReceiverTypeFact {
                call_site,
                receiver_type: segments.into_boxed_slice(),
                member: Box::from(member),
            })
        } else {
            self.vec_constructor_type_fact(function, call_site)
        };
        if let Some(fact) = receiver_fact {
            builder.add_call_receiver_type_fact(fact)?;
        }
        self.session
            .add_target_edge(builder, invoke, EdgeTarget::normal(normal))?;
        self.session.add_target_edge(
            builder,
            invoke,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        // A local passed as `&mut local` may be written through the borrow
        // during the call, and the borrow's value is that local's own value
        // (a reference expression is transparent here). After the call the
        // local therefore may hold whatever the borrowed value holds, so a
        // callee's write through the borrow, or an input source bound to the
        // argument, reaches the local's later reads (#3757). The write-back
        // preserves value-flow transport for taint and points-to consumers,
        // but its runtime value is unknown to scalar consumers.
        for (argument, value) in arguments.iter().zip(call_argument_values.iter()) {
            if argument.kind() == "reference_expression"
                && direct_named_child_kind(*argument, "mutable_specifier").is_some()
                && let Some(local) = argument
                    .child_by_field_name("value")
                    .and_then(|place| self.binding_value(place))
            {
                self.append_effect(
                    builder,
                    normal,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source: *value,
                        target: local,
                    },
                )?;
            }
        }
        self.session.add_target_edge(builder, normal, next)?;
        self.add_droppable_initializer_temporary_gap(builder, node, exceptional, scope)?;
        self.abrupt(builder, exceptional, scope, CompletionKind::Throw, None)?;
        if receiver_node.is_some() {
            // The receiver adjustment is part of the question the call's
            // resolution answers, so it rides on the call-target gap instead
            // of a second point-scoped gap that no resolution can close
            // (#3757). The Rust resolver reaches a method only through the
            // receiver's own type after built-in reference dereferences; it
            // reports a `Deref` method surface as unsupported instead of
            // following it. A call it resolves completely therefore ran no
            // user `Deref` or `DerefMut` to find its target, and an exact
            // external identity is minted from the same written receiver
            // type. An unresolved call keeps the gap as a residual call.
            debug_assert!(matches!(resolution, CallableTargetResolution::Unknown));
            self.session.record_gap(
                builder,
                invoke,
                SemanticGapSubject::Value(callee),
                SemanticCapability::CallableReferences,
                SemanticGapKind::Unknown,
                "callable target requires whole-program Rust dispatch refinement",
            )?;
            self.session.add_gap_with_impacts_and_discharge(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::Calls,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
                SemanticGapKind::Unknown,
                SemanticGapDischarge::CallResolution,
                "call target requires whole-program Rust dispatch refinement; method receiver autoderef and autoref adjustments may invoke Deref or DerefMut and are not emitted as call sites",
            )?;
        } else {
            self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;
        }
        let generic_call = function.kind() == "generic_function";
        let dispatch_detail = match (generic_call, receiver_node.is_some()) {
            (true, true) => Some(
                "generic Rust method applicability depends on unresolved type arguments and bounds, while dispatch may use a trait implementation after autoderef",
            ),
            (true, false) => Some(
                "generic Rust call applicability depends on unresolved type arguments and bounds",
            ),
            (false, true) => Some(
                "method dispatch may use a trait implementation after autoderef; receiver type and complete implementation coverage require type refinement",
            ),
            (false, false) => None,
        };
        if let Some(detail) = dispatch_detail {
            self.session.record_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                detail,
            )?;
        }
        if receiver_node.is_some() {
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                invoke,
                scope,
                SemanticGapKind::Unsupported,
                "implicit method receiver adjustments may abort; that abort edge is not lowered",
            )?;
        }

        let evaluations = call_operand_evaluations(node)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(invoke),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_pointer_call_facts(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        function: Node<'tree>,
        receiver_node: Option<Node<'tree>>,
        receiver_value: Option<ValueId>,
        arguments: &[Node<'tree>],
        argument_values: &[ValueId],
        invoke: ProgramPointId,
        normal: ProgramPointId,
        result: ValueId,
    ) -> Result<(), RustLoweringError> {
        let metadata = self.metadata(invoke)?;
        let path = call_function_target(function);
        let is_read = self
            .ownership
            .resolves_standard_path(path, &["core", "ptr", "read"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "ptr", "read"]);
        let is_read_unaligned = self
            .ownership
            .resolves_standard_path(path, &["core", "ptr", "read_unaligned"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "ptr", "read_unaligned"]);
        let is_from_raw_parts = self
            .ownership
            .resolves_standard_path(path, &["core", "slice", "from_raw_parts"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "slice", "from_raw_parts"]);
        let is_alloc = self.is_standard_allocator_function(path);
        let is_dealloc = self
            .ownership
            .resolves_standard_path(path, &["core", "alloc", "dealloc"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "alloc", "dealloc"])
            || self
                .ownership
                .resolves_standard_path(path, &["alloc", "alloc", "dealloc"]);
        let is_box_into_raw = self
            .ownership
            .resolves_standard_path(path, &["std", "boxed", "Box", "into_raw"])
            || self
                .ownership
                .resolves_standard_path(path, &["alloc", "boxed", "Box", "into_raw"]);
        let is_box_new = self
            .ownership
            .resolves_standard_path(path, &["std", "boxed", "Box", "new"])
            || self
                .ownership
                .resolves_standard_path(path, &["alloc", "boxed", "Box", "new"]);
        let is_box_from_raw = self
            .ownership
            .resolves_standard_path(path, &["std", "boxed", "Box", "from_raw"])
            || self
                .ownership
                .resolves_standard_path(path, &["alloc", "boxed", "Box", "from_raw"]);
        let is_drop = self
            .ownership
            .resolves_standard_path(path, &["core", "mem", "drop"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "mem", "drop"]);
        let is_forget = self
            .ownership
            .resolves_standard_path(path, &["core", "mem", "forget"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "mem", "forget"]);
        let is_manually_drop_drop = self
            .ownership
            .resolves_standard_path(path, &["core", "mem", "ManuallyDrop", "drop"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "mem", "ManuallyDrop", "drop"]);
        let is_manually_drop_new = self
            .ownership
            .resolves_standard_path(path, &["core", "mem", "ManuallyDrop", "new"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "mem", "ManuallyDrop", "new"]);
        let is_manually_drop_into_inner = self
            .ownership
            .resolves_standard_path(path, &["core", "mem", "ManuallyDrop", "into_inner"])
            || self
                .ownership
                .resolves_standard_path(path, &["std", "mem", "ManuallyDrop", "into_inner"]);
        let is_manually_drop_operation =
            is_manually_drop_new || is_manually_drop_drop || is_manually_drop_into_inner;
        let receiver_type = receiver_node.and_then(|receiver| self.expression_type(receiver));
        let receiver_declared_type = receiver_type.map(|ty| match ty {
            RustValueType::Declared(node) => node,
            RustValueType::Borrowed { referent, .. } => referent,
        });
        let method_name = path
            .child_by_field_name("field")
            .and_then(|field| node_text(self.source, field));
        let modeled_raw_pointer_receiver = receiver_node
            .is_some_and(|receiver| self.is_raw_pointer_expression(receiver))
            && matches!(
                method_name,
                Some("read" | "read_unaligned" | "as_ref" | "cast" | "add")
            );
        let modeled_raw_pointer_arguments = is_read
            || is_read_unaligned
            || is_from_raw_parts
            || is_alloc
            || is_dealloc
            || is_box_new
            || is_box_into_raw
            || is_box_from_raw
            || is_drop
            || is_forget;
        if !modeled_raw_pointer_receiver && !modeled_raw_pointer_arguments {
            for (argument, value) in arguments.iter().zip(argument_values) {
                if self
                    .expression_type(*argument)
                    .is_some_and(|ty| matches!(ty, RustValueType::Declared(node) if node.kind() == "pointer_type"))
                {
                    self.add_incomplete_fact(
                        invoke,
                        SemanticIncompleteSubject::Value(*value),
                        SemanticIncompleteReason::Pointer(PointerIncompleteReason::ExternalEscape),
                        metadata,
                    );
                }
            }
        }
        if receiver_declared_type.is_some_and(|type_node| type_node.kind() == "pointer_type")
            && !modeled_raw_pointer_receiver
            && let Some(receiver_value) = receiver_value
        {
            self.add_incomplete_fact(
                invoke,
                SemanticIncompleteSubject::Value(receiver_value),
                SemanticIncompleteReason::Pointer(PointerIncompleteReason::UnsupportedOperation),
                metadata,
            );
        }

        if is_read || is_read_unaligned {
            if let (Some(argument), Some(pointer)) = (arguments.first(), argument_values.first()) {
                let width = self.pointer_width_for_expression(*argument);
                let pointer = self.binding_value(*argument).unwrap_or(*pointer);
                self.add_pointer_access(invoke, pointer, PointerAccessKind::Read, width, metadata);
                if width == PointerAccessWidth::Unknown {
                    self.add_incomplete_fact(
                        invoke,
                        SemanticIncompleteSubject::Value(pointer),
                        SemanticIncompleteReason::Pointer(PointerIncompleteReason::UnknownLayout),
                        metadata,
                    );
                }
            }
        } else if is_from_raw_parts {
            if let ([pointer_node, _length_node], [pointer, length]) = (arguments, argument_values)
            {
                if let Some(pointer_type) =
                    self.expression_type(*pointer_node).and_then(|ty| match ty {
                        RustValueType::Declared(type_node)
                            if type_node.kind() == "pointer_type" =>
                        {
                            Some(type_node)
                        }
                        RustValueType::Borrowed { .. } | RustValueType::Declared(_) => None,
                    })
                {
                    self.value_types
                        .insert(result, RustValueType::Declared(pointer_type));
                }
                let width = self
                    .pointer_pointee_type(*pointer_node)
                    .and_then(|element| {
                        rust_type_byte_size(self.source, element).map(|multiplier| {
                            PointerAccessWidth::ValueTimes {
                                value: *length,
                                multiplier,
                            }
                        })
                    });
                let width = width.unwrap_or(PointerAccessWidth::Unknown);
                let pointer = self.binding_value(*pointer_node).unwrap_or(*pointer);
                self.add_pointer_access(invoke, pointer, PointerAccessKind::Read, width, metadata);
                if width == PointerAccessWidth::Unknown {
                    self.add_incomplete_fact(
                        invoke,
                        SemanticIncompleteSubject::Value(pointer),
                        SemanticIncompleteReason::Pointer(PointerIncompleteReason::UnknownLayout),
                        metadata,
                    );
                }
                let aliases = self
                    .pointer_origins_by_pointer
                    .get(&pointer)
                    .cloned()
                    .or_else(|| {
                        self.binding_value(*pointer_node).and_then(|binding| {
                            self.pointer_origins_by_pointer.get(&binding).cloned()
                        })
                    })
                    .unwrap_or_default();
                for (origin, offset) in aliases {
                    self.add_pointer_alias(
                        invoke,
                        result,
                        origin,
                        offset,
                        PointerRelationStrength::Must,
                        metadata,
                    );
                }
            }
        } else if is_dealloc {
            if let Some(pointer) =
                arguments
                    .first()
                    .zip(argument_values.first())
                    .map(|(argument, value)| {
                        let argument = peel_rust_parentheses(*argument);
                        // A raw-pointer-to-raw-pointer cast keeps the address.
                        // Anchor deallocation to the source binding so a helper
                        // parameter remains visible to interprocedural flow.
                        let pointer_cast = if argument.kind() == "type_cast_expression"
                            && argument
                                .child_by_field_name("type")
                                .is_some_and(|target| target.kind() == "pointer_type")
                        {
                            argument
                                .child_by_field_name("value")
                                .filter(|operand| {
                                    matches!(
                                        self.expression_type(*operand),
                                        Some(RustValueType::Declared(ty))
                                            if ty.kind() == "pointer_type"
                                    )
                                })
                                .and_then(|operand| self.binding_value(operand))
                        } else {
                            None
                        };
                        pointer_cast.unwrap_or(*value)
                    })
            {
                self.add_pointer_invalidation(
                    invoke,
                    PointerInvalidationTarget::Pointer(pointer),
                    PointerInvalidationCause::Deallocated,
                    PointerRelationStrength::Must,
                    metadata,
                );
            }
        } else if is_alloc {
            self.pointer_pointees_by_value
                .insert(result, RustPointerPointee::Byte);
            let origin = self.add_allocation_pointer_origin(
                builder,
                result,
                None,
                AllocationKind::LanguageDefined("rust_allocator".into()),
                invoke,
                metadata,
            )?;
            self.add_pointer_alias(
                invoke,
                result,
                origin,
                PointerByteOffset::Exact(0),
                PointerRelationStrength::Must,
                metadata,
            );
            self.add_incomplete_fact(
                invoke,
                SemanticIncompleteSubject::PointerOrigin(origin),
                SemanticIncompleteReason::Pointer(PointerIncompleteReason::UnknownAllocationExtent),
                metadata,
            );
        } else if is_box_new {
            let byte_extent = arguments
                .first()
                .and_then(|argument| self.expression_type(*argument))
                .and_then(|ty| match ty {
                    RustValueType::Declared(type_node) => {
                        rust_type_byte_size(self.source, type_node)
                    }
                    RustValueType::Borrowed { .. } => None,
                });
            let origin = self.add_allocation_pointer_origin(
                builder,
                result,
                byte_extent,
                AllocationKind::LanguageDefined("rust_box_allocation".into()),
                invoke,
                metadata,
            )?;
            self.add_pointer_alias(
                invoke,
                result,
                origin,
                PointerByteOffset::Exact(0),
                PointerRelationStrength::Must,
                metadata,
            );
            self.pointer_origins_by_owner.insert(result, origin);
            self.pointer_owner_lifetimes.insert(
                result,
                (
                    PointerInvalidationTarget::Origin(origin),
                    PointerInvalidationCause::OwnerDropped,
                ),
            );
            if byte_extent.is_none() {
                self.add_incomplete_fact(
                    invoke,
                    SemanticIncompleteSubject::PointerOrigin(origin),
                    SemanticIncompleteReason::Pointer(
                        PointerIncompleteReason::UnknownAllocationExtent,
                    ),
                    metadata,
                );
            }
        } else if is_box_from_raw {
            if let Some((argument, pointer)) = arguments.first().zip(argument_values.first()) {
                let pointer = self.binding_value(*argument).unwrap_or(*pointer);
                self.add_pointer_invalidation(
                    invoke,
                    PointerInvalidationTarget::Pointer(pointer),
                    PointerInvalidationCause::OwnershipTransferred,
                    PointerRelationStrength::Must,
                    metadata,
                );
                self.pointer_owner_lifetimes.insert(
                    result,
                    (
                        PointerInvalidationTarget::Pointer(pointer),
                        PointerInvalidationCause::Deallocated,
                    ),
                );
                if let Some(pointee) = self.pointer_pointee_type(*argument) {
                    self.value_types
                        .insert(result, RustValueType::Declared(pointee));
                }
            }
        } else if is_box_into_raw {
            let existing_origin = arguments
                .first()
                .and_then(|argument| self.binding_value(*argument))
                .and_then(|owner| self.pointer_origins_by_owner.get(&owner).copied())
                .or_else(|| {
                    argument_values
                        .first()
                        .and_then(|owner| self.pointer_origins_by_owner.get(owner).copied())
                });
            if let Some((argument, value)) = arguments.first().zip(argument_values.first()) {
                self.append_consumed_move(builder, invoke, *argument, *value)?;
            }
            let byte_extent = arguments
                .first()
                .and_then(|argument| self.expression_type(*argument))
                .and_then(|type_node| match type_node {
                    RustValueType::Declared(type_node) => rust_generic_type_argument(type_node, 0),
                    RustValueType::Borrowed { .. } => None,
                })
                .and_then(|type_node| rust_type_byte_size(self.source, type_node));
            if let Some(pointee) = arguments.first().and_then(|argument| {
                self.expression_type(*argument)
                    .and_then(|type_node| match type_node {
                        RustValueType::Declared(type_node) => {
                            rust_generic_type_argument(type_node, 0)
                        }
                        RustValueType::Borrowed { .. } => None,
                    })
            }) {
                self.pointer_pointees_by_value
                    .insert(result, RustPointerPointee::Type(pointee));
            }
            let origin = if let Some(origin) = existing_origin {
                origin
            } else {
                self.add_allocation_pointer_origin(
                    builder,
                    result,
                    byte_extent,
                    AllocationKind::LanguageDefined("rust_box_allocation".into()),
                    invoke,
                    metadata,
                )?
            };
            self.add_pointer_alias(
                invoke,
                result,
                origin,
                PointerByteOffset::Exact(0),
                PointerRelationStrength::Must,
                metadata,
            );
            self.pointer_origins_by_owner.remove(&result);
            self.pointer_owner_lifetimes.remove(&result);
            if byte_extent.is_none() {
                self.add_incomplete_fact(
                    invoke,
                    SemanticIncompleteSubject::PointerOrigin(origin),
                    SemanticIncompleteReason::Pointer(
                        PointerIncompleteReason::UnknownAllocationExtent,
                    ),
                    metadata,
                );
            }
        } else if is_drop {
            if let Some((argument, argument_value)) = arguments
                .first()
                .zip(argument_values.first())
                .map(|(a, v)| (*a, *v))
            {
                let owner = self.binding_value(argument).or_else(|| {
                    (self.pointer_owner_lifetimes.contains_key(&argument_value)
                        || self.pointer_origins_by_owner.contains_key(&argument_value))
                    .then_some(argument_value)
                });
                let manually_drop_owner =
                    owner.is_some_and(|owner| self.value_is_manually_drop(owner));
                let owner_invalidation = if manually_drop_owner {
                    None
                } else {
                    owner.and_then(|owner| self.owner_invalidation(owner))
                };
                let owns_pointer_origin = owner_invalidation.is_some();
                if owns_pointer_origin
                    || self.compatible_transfer_ownership(argument, owner, None)
                        == RustOwnershipClass::Move
                {
                    let consumed = self.value(builder, invoke, SemanticValueKind::Temporary)?;
                    self.append_consumed_move(builder, invoke, argument, consumed)?;
                }
                if let Some(owner) = owner
                    && let Some(place) = self.binding_places.get(&owner).cloned()
                {
                    let (behavior, incomplete) = self.drop_behavior(owner);
                    builder.emit_cleanup_action_fact(
                        invoke,
                        &ScopeCleanupAction::Drop {
                            place: place.clone(),
                            behavior,
                            source: metadata.source,
                            evidence: metadata.evidence,
                        },
                    )?;
                    if let Some(reason) = incomplete {
                        self.incomplete_facts.push(SemanticIncompleteFact {
                            point: invoke,
                            subject: SemanticIncompleteSubject::Place(place),
                            reason: SemanticIncompleteReason::Lifecycle(reason),
                            source: metadata.source,
                            evidence: metadata.evidence,
                        });
                    }
                }
                if manually_drop_owner {
                    let subject = owner
                        .and_then(|owner| self.binding_places.get(&owner).cloned())
                        .map_or(
                            SemanticIncompleteSubject::Value(argument_value),
                            SemanticIncompleteSubject::Place,
                        );
                    self.add_incomplete_fact(
                        invoke,
                        subject,
                        SemanticIncompleteReason::Lifecycle(
                            LifecycleIncompleteReason::ManuallyDrop,
                        ),
                        metadata,
                    );
                }
                if let Some((target, cause)) = owner_invalidation {
                    self.add_pointer_invalidation(
                        invoke,
                        target,
                        cause,
                        PointerRelationStrength::Must,
                        metadata,
                    );
                }
            }
        } else if is_forget {
            if let Some((argument, argument_value)) = arguments.first().zip(argument_values.first())
            {
                let consumed = self.value(builder, invoke, SemanticValueKind::Temporary)?;
                self.append_consumed_move(builder, invoke, *argument, consumed)?;
                let subject = self
                    .binding_value(*argument)
                    .and_then(|owner| self.binding_places.get(&owner).cloned())
                    .map_or(
                        SemanticIncompleteSubject::Value(*argument_value),
                        SemanticIncompleteSubject::Place,
                    );
                self.add_incomplete_fact(
                    invoke,
                    subject,
                    SemanticIncompleteReason::Lifecycle(LifecycleIncompleteReason::ForgottenOwner),
                    metadata,
                );
            }
        } else if is_manually_drop_operation {
            if is_manually_drop_new && let Some(argument) = arguments.first() {
                self.append_consumed_move(builder, invoke, *argument, result)?;
                if let Some(source) = argument_values.first().copied() {
                    self.transfer_pointer_owner_facts(source, result);
                }
                self.manually_drop_values.insert(result);
            } else if is_manually_drop_into_inner && let Some(argument) = arguments.first() {
                self.append_consumed_move(builder, invoke, *argument, result)?;
                if let Some(source) = argument_values.first().copied() {
                    self.transfer_pointer_owner_facts(source, result);
                }
                self.manually_drop_values.remove(&result);
            }
            if is_manually_drop_drop
                && let Some(owner) = arguments
                    .first()
                    .and_then(|argument| rust_reference_expression_value(*argument))
                    .and_then(|value| self.binding_value(value))
                && let Some((target, cause)) = self.owner_invalidation(owner)
            {
                self.add_pointer_invalidation(
                    invoke,
                    target,
                    cause,
                    PointerRelationStrength::Must,
                    metadata,
                );
            }
            let subject = arguments
                .first()
                .and_then(|argument| self.binding_value(*argument))
                .and_then(|owner| self.binding_places.get(&owner).cloned())
                .map_or(
                    SemanticIncompleteSubject::Value(result),
                    SemanticIncompleteSubject::Place,
                );
            self.add_incomplete_fact(
                invoke,
                subject,
                SemanticIncompleteReason::Lifecycle(LifecycleIncompleteReason::ManuallyDrop),
                metadata,
            );
        } else if let (Some(receiver_node), Some(receiver_value), Some(method)) =
            (receiver_node, receiver_value, method_name)
        {
            let receiver_is_vec = receiver_declared_type
                .and_then(rust_type_path_node)
                .is_some_and(|type_path| {
                    self.ownership
                        .resolves_standard_path(type_path, &["std", "vec", "Vec"])
                        || self
                            .ownership
                            .resolves_standard_path(type_path, &["alloc", "vec", "Vec"])
                });
            let receiver_is_raw_pointer = self.is_raw_pointer_expression(receiver_node);

            if receiver_is_vec && matches!(method, "as_ptr" | "as_mut_ptr") {
                if let Some(pointee) = receiver_declared_type
                    .and_then(|type_node| rust_generic_type_argument(type_node, 0))
                {
                    self.pointer_pointees_by_value
                        .insert(result, RustPointerPointee::Type(pointee));
                }
                let owner = self.binding_value(receiver_node);
                let origin = if let Some(origin) =
                    owner.and_then(|owner| self.pointer_origins_by_owner.get(&owner).copied())
                {
                    origin
                } else {
                    self.add_allocation_pointer_origin(
                        builder,
                        result,
                        None,
                        AllocationKind::LanguageDefined("rust_vec_buffer".into()),
                        invoke,
                        metadata,
                    )?
                };
                self.add_pointer_alias(
                    invoke,
                    result,
                    origin,
                    PointerByteOffset::Exact(0),
                    PointerRelationStrength::Must,
                    metadata,
                );
                if let Some(owner) = owner {
                    self.pointer_origins_by_owner.insert(owner, origin);
                    self.pointer_owner_lifetimes.insert(
                        owner,
                        (
                            PointerInvalidationTarget::Origin(origin),
                            PointerInvalidationCause::OwnerDropped,
                        ),
                    );
                }
                self.add_incomplete_fact(
                    invoke,
                    SemanticIncompleteSubject::PointerOrigin(origin),
                    SemanticIncompleteReason::Pointer(
                        PointerIncompleteReason::UnknownAllocationExtent,
                    ),
                    metadata,
                );
            } else if receiver_is_vec && method == "push" {
                if let Some(owner) = self.binding_value(receiver_node)
                    && let Some(origin) = self.pointer_origins_by_owner.get(&owner).copied()
                {
                    self.add_pointer_invalidation(
                        invoke,
                        PointerInvalidationTarget::Origin(origin),
                        PointerInvalidationCause::PossibleReallocation,
                        PointerRelationStrength::May,
                        metadata,
                    );
                }
            } else if receiver_is_raw_pointer
                && matches!(method, "read" | "read_unaligned" | "as_ref")
            {
                let width = self.pointer_width_for_expression(receiver_node);
                self.add_pointer_access(
                    invoke,
                    receiver_value,
                    PointerAccessKind::Read,
                    width,
                    metadata,
                );
                if width == PointerAccessWidth::Unknown {
                    self.add_incomplete_fact(
                        invoke,
                        SemanticIncompleteSubject::Value(receiver_value),
                        SemanticIncompleteReason::Pointer(PointerIncompleteReason::UnknownLayout),
                        metadata,
                    );
                }
            } else if receiver_is_raw_pointer && method == "cast" {
                if let Some(type_argument) = rust_call_type_argument(function, 0) {
                    self.value_types
                        .insert(result, RustValueType::Declared(type_argument));
                    self.pointer_pointees_by_value
                        .insert(result, RustPointerPointee::Type(type_argument));
                }
                self.session.append_language_defined_value_flows(
                    builder,
                    normal,
                    [receiver_value],
                    result,
                )?;
                let aliases = self
                    .pointer_origins_by_pointer
                    .get(&receiver_value)
                    .cloned()
                    .or_else(|| {
                        self.binding_value(receiver_node)
                            .and_then(|value| self.pointer_origins_by_pointer.get(&value).cloned())
                    })
                    .unwrap_or_default();
                for (origin, offset) in aliases {
                    self.add_pointer_alias(
                        invoke,
                        result,
                        origin,
                        offset,
                        PointerRelationStrength::Must,
                        metadata,
                    );
                }
            } else if receiver_is_raw_pointer && method == "add" {
                if let Some(pointer_type) =
                    receiver_declared_type.filter(|type_node| type_node.kind() == "pointer_type")
                {
                    self.value_types
                        .insert(result, RustValueType::Declared(pointer_type));
                }
                if let Some(pointee) = self.pointer_pointee(receiver_node) {
                    self.pointer_pointees_by_value.insert(result, pointee);
                }
                self.session.append_language_defined_value_flows(
                    builder,
                    normal,
                    [receiver_value],
                    result,
                )?;
                if let Some(offset_node) = arguments.first() {
                    let offset_value = argument_values.first().copied();
                    let element_size =
                        self.pointer_pointee(receiver_node)
                            .and_then(|pointee| match pointee {
                                RustPointerPointee::Type(element) => {
                                    rust_type_byte_size(self.source, element)
                                }
                                RustPointerPointee::Byte => Some(1),
                            });
                    let base_aliases = self
                        .pointer_origins_by_pointer
                        .get(&receiver_value)
                        .cloned()
                        .or_else(|| {
                            self.binding_value(receiver_node).and_then(|value| {
                                self.pointer_origins_by_pointer.get(&value).cloned()
                            })
                        })
                        .unwrap_or_default();
                    for (origin, base_offset) in base_aliases {
                        let byte_offset = match (
                            base_offset,
                            element_size,
                            rust_integer_literal_value(self.source, *offset_node),
                            offset_value,
                        ) {
                            (PointerByteOffset::Exact(base), Some(size), Some(count), _) => {
                                i128::try_from(count)
                                    .ok()
                                    .and_then(|count| count.checked_mul(i128::try_from(size).ok()?))
                                    .and_then(|bytes| base.checked_add(bytes))
                                    .map_or(PointerByteOffset::Unknown, PointerByteOffset::Exact)
                            }
                            (PointerByteOffset::Exact(0), Some(1), None, Some(value)) => {
                                PointerByteOffset::Value(value)
                            }
                            _ => PointerByteOffset::Unknown,
                        };
                        self.add_pointer_alias(
                            invoke,
                            result,
                            origin,
                            byte_offset,
                            PointerRelationStrength::Must,
                            metadata,
                        );
                        if byte_offset == PointerByteOffset::Unknown {
                            self.add_incomplete_fact(
                                invoke,
                                SemanticIncompleteSubject::PointerOrigin(origin),
                                SemanticIncompleteReason::Pointer(
                                    PointerIncompleteReason::UnknownLayout,
                                ),
                                metadata,
                            );
                        }
                    }
                }
            }
        }
        self.propagate_pointer_facts_to_targets(result);
        Ok(())
    }

    fn call_is_droppable_let_initializer(&self, node: Node<'tree>) -> bool {
        let mut child = node;
        let mut parent = child.parent();
        while let Some(ancestor) = parent {
            match ancestor.kind() {
                "let_declaration" => {
                    return field_matches(ancestor, "value", child)
                        && self
                            .declaration_binding_values(ancestor)
                            .iter()
                            .any(|value| {
                                !matches!(self.drop_behavior(*value).0, DropBehavior::Trivial)
                            });
                }
                "function_item"
                | "function_signature_item"
                | "closure_expression"
                | "async_block"
                | "gen_block" => return false,
                _ => {
                    child = ancestor;
                    parent = ancestor.parent();
                }
            }
        }
        false
    }

    fn add_droppable_initializer_temporary_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        exceptional: ProgramPointId,
        scope: ScopeFrameId,
    ) -> Result<(), RustLoweringError> {
        if self.call_is_droppable_let_initializer(node)
            && !builder
                .resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
                .is_some_and(|route| completion_has_unrouted_drop(&route))
        {
            self.add_drop_omission_gaps(
                builder,
                exceptional,
                "a droppable let initializer may create temporaries whose exceptional cleanup is not lowered",
                // The owning let binding's drop behavior is the proof input;
                // the workspace oracle keeps unknown or user-defined Drop
                // implementations open and discharges only proven-inert glue.
                SemanticGapDischarge::InertDropGlue,
            )?;
        }
        Ok(())
    }

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), RustLoweringError> {
        let result = self.expression_value(builder, node, SemanticValueKind::Callable)?;
        let target = self.procedure_targets.get(&node.id());
        let targets = target.map_or(CallableTargetResolution::Unknown, |target| {
            CallableTargetResolution::Proven(CallableTarget::Local(target.id))
        });
        let environment = if target.is_some_and(|target| !target.captures.is_empty()) {
            Some(self.session.add_allocation(
                builder,
                entry,
                result,
                AllocationKind::ClosureEnvironment,
            )?)
        } else {
            None
        };
        let callable = CallableValue {
            kind: CallableReferenceKind::Lambda,
            targets: targets.clone(),
            target_evidence: self.metadata(entry)?.evidence,
            bound_receiver: None,
            environment,
        };
        self.append_effect(
            builder,
            entry,
            SemanticEffect::CallableCreation { result, callable },
        )?;
        let Some(target) = target else {
            self.session.record_gap(
                builder,
                entry,
                SemanticGapSubject::Value(result),
                SemanticCapability::CallableReferences,
                SemanticGapKind::Unknown,
                "closure syntax has no materialized procedure target",
            )?;
            self.session.record_gap(
                builder,
                entry,
                SemanticGapSubject::Value(result),
                SemanticCapability::Captures,
                SemanticGapKind::Unknown,
                "closure capture environment cannot be tied to a materialized target",
            )?;
            return self.session.add_target_edge(builder, entry, next);
        };
        if let Some(environment) = environment {
            let mut capture_environment_unresolved = false;
            for (index, capture) in target.captures.iter().enumerate() {
                let Some(captured) = self.capture_source_value(capture) else {
                    capture_environment_unresolved = true;
                    continue;
                };
                let destination = MemoryLocationId::try_from_index(index)
                    .map_err(|_| RustLoweringError::Invalid("too many Rust captures".into()))?;
                let capture_id = self.session.add_capture(
                    builder,
                    entry,
                    result,
                    target.id,
                    environment,
                    CaptureSource::Value(captured),
                    destination,
                    capture.mode.clone(),
                )?;
                if capture.mode == CaptureMode::Unknown {
                    capture_environment_unresolved = true;
                    self.session.record_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Capture(capture_id),
                        SemanticCapability::Captures,
                        SemanticGapKind::Unknown,
                        "Rust closure capture may require a mutable borrow or receiver adjustment",
                    )?;
                }
            }
            if capture_environment_unresolved {
                self.session.record_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::Captures,
                    SemanticGapKind::Unknown,
                    "Rust closure environment contains a capture whose source or mode is unresolved",
                )?;
            }
        }
        if matches!(node.kind(), "async_block" | "gen_block")
            || (node.kind() == "closure_expression" && direct_child_kind(node, "async"))
        {
            self.session.record_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unsupported,
                "creating this callable does not immediately execute its deferred body",
            )?;
        }
        self.session.add_target_edge(builder, entry, next)
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), RustLoweringError> {
        self.session
            .add_unhandled_control_syntax_gap(builder, entry, node.kind())
            .map(|_| ())
    }

    fn schedule_nodes_with_scopes(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        schedule: ScopedNodeSchedule<'_, 'tree>,
        next: EdgeTarget,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        if schedule.children.is_empty() {
            return self.session.add_target_edge(builder, entry, next);
        }
        debug_assert_eq!(schedule.children.len(), schedule.entries.len());
        debug_assert_eq!(schedule.children.len(), schedule.scopes.len());
        self.session
            .add_target_edge(builder, entry, EdgeTarget::normal(schedule.entries[0]))?;
        schedule_sequential_work_with_scopes(
            stack,
            schedule.children,
            schedule.entries,
            next,
            schedule.scopes,
            |_, node, entry, next, scope| Work::Statement {
                node,
                entry,
                next,
                scope,
            },
        );
        Ok(())
    }

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        if children.is_empty() {
            return self.session.add_target_edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, unwrap_attributes(*child), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.session
            .add_target_edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        schedule_sequential_work(
            stack,
            children,
            &entries,
            next,
            scope,
            |_, node, entry, next, scope| Work::Expression {
                node,
                entry,
                next,
                scope,
            },
        );
        Ok(())
    }

    fn abrupt(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        kind: CompletionKind,
        label: Option<&str>,
    ) -> Result<(), RustLoweringError> {
        let Some(route) = builder.resolve_completion(scope, &CompletionRequest::new(kind, label))
        else {
            if matches!(kind, CompletionKind::Break | CompletionKind::Continue) {
                self.session.add_unmatched_completion_gap(
                    builder,
                    from,
                    kind,
                    if label.is_some() {
                        SemanticCapability::NonLocalControl
                    } else {
                        SemanticCapability::NormalControlFlow
                    },
                )?;
                return Ok(());
            }
            return Err(RustLoweringError::Invalid(format!(
                "{} completion has no matching structured continuation",
                completion_label(kind)
            )));
        };
        self.route(builder, from, &route)
    }

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
    ) -> Result<(), RustLoweringError> {
        let has_unrouted_drop = completion_has_unrouted_drop(route);
        self.record_owner_lifetime_ends(route);
        for operation in route.operations() {
            let CleanupRouteOperation::Action(ScopeCleanupAction::Drop {
                place,
                behavior,
                source,
                evidence,
            }) = operation
            else {
                continue;
            };
            if matches!(
                behavior,
                DropBehavior::Destructor(CallableTargetResolution::Unknown)
            ) {
                let reason = self
                    .cleanup_drop_incompletes
                    .get(place)
                    .copied()
                    .unwrap_or(LifecycleIncompleteReason::UnsupportedCleanup);
                self.incomplete_facts.push(SemanticIncompleteFact {
                    point: from,
                    subject: SemanticIncompleteSubject::Place(place.clone()),
                    reason: SemanticIncompleteReason::Lifecycle(reason),
                    source: *source,
                    evidence: *evidence,
                });
            } else if let Some(reason) = self.cleanup_drop_incompletes.get(place).copied() {
                self.incomplete_facts.push(SemanticIncompleteFact {
                    point: from,
                    subject: SemanticIncompleteSubject::Place(place.clone()),
                    reason: SemanticIncompleteReason::Lifecycle(reason),
                    source: *source,
                    evidence: *evidence,
                });
            }
        }
        if has_unrouted_drop {
            let discharge = if self.cleanup_route_drops_are_binding_only(route) {
                SemanticGapDischarge::InertDropGlue
            } else {
                SemanticGapDischarge::None
            };
            self.add_drop_omission_gaps(
                builder,
                from,
                "scope exit crosses a destructor whose invocation is not routed as an ICFG call",
                discharge,
            )?;
            let destination = route.destination().target();
            if (destination == self.normal_exit || destination == self.exceptional_exit)
                && self.cleanup_gap_exit_points.insert(destination)
            {
                self.add_drop_omission_gaps(
                    builder,
                    destination,
                    "procedure exit crosses a destructor whose invocation is not routed as an ICFG call",
                    discharge,
                )?;
            }
        }
        emit_cleanup_completion_route(builder, &mut self.session, from, route)
    }

    fn cleanup_route_drops_are_binding_only(&self, route: &CompletionRoute) -> bool {
        let mut cleanup_index = 0;
        let mut has_drop = false;
        let mut binding_only = true;
        for operation in route.operations() {
            match operation {
                CleanupRouteOperation::Action(ScopeCleanupAction::Drop {
                    behavior: DropBehavior::Destructor(_),
                    ..
                }) => {
                    let region = route
                        .cleanups()
                        .get(cleanup_index)
                        .expect("drop action belongs to a cleanup region");
                    has_drop = true;
                    binding_only &= self.binding_cleanup_regions.contains(region);
                }
                CleanupRouteOperation::Region {
                    cleanup_index: actual_index,
                    region,
                } => {
                    assert_eq!(*actual_index, cleanup_index);
                    assert_eq!(Some(region), route.cleanups().get(cleanup_index));
                    cleanup_index += 1;
                }
                CleanupRouteOperation::Action(_) => {}
            }
        }
        has_drop && binding_only
    }

    fn record_owner_lifetime_ends(&mut self, route: &CompletionRoute) {
        let point = route.destination().target();
        for operation in route.operations() {
            let CleanupRouteOperation::Region { region, .. } = operation else {
                continue;
            };
            if let Some(owners) = self.cleanup_owners_by_region.get(region) {
                for owner in owners {
                    self.owner_lifetime_end_points.insert((*owner, point));
                }
            }
        }
    }

    fn resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
    ) -> Result<(), RustLoweringError> {
        self.session.add_callable_resolution_gaps(
            builder,
            point,
            callee,
            call_site,
            resolution,
            "callable target requires whole-program Rust dispatch refinement",
            "call target requires whole-program Rust dispatch refinement",
        )
    }

    fn point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, RustLoweringError> {
        self.session
            .add_node_point(builder, unwrap_attributes(node), effects)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, RustLoweringError> {
        self.session
            .add_node_mapping(builder, unwrap_attributes(node))
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, RustLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, RustLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), RustLoweringError> {
        self.session.append_effect(builder, point, effect)
    }

    /// Rust aborts do not resume normal evaluation after the failing
    /// operation. Preserve that proof on this exceptional-flow gap only when
    /// the exact evaluation scope has no already-active cleanup user code.
    fn add_non_rejoining_exceptional_exit_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        scope: ScopeFrameId,
        kind: SemanticGapKind,
        detail: &str,
    ) -> Result<(), RustLoweringError> {
        let route = builder
            .resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
            .expect("a Rust evaluation scope must resolve abort completion");
        let discharge = if route.cleanups().is_empty() {
            SemanticGapDischarge::NonRejoiningExceptionalExit
        } else if self.cleanup_route_drops_are_binding_only(&route) {
            // The active cleanups destroy only parameters and `let`
            // bindings, which the workspace oracle can prove inert (#3757).
            SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
        } else {
            SemanticGapDischarge::ExitOnlyProcedureCompletion
        };
        self.session.add_gap_with_impacts_and_discharge(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapImpacts::NONE,
            kind,
            discharge,
            detail,
        )?;
        Ok(())
    }
}

fn completion_has_unrouted_drop(route: &CompletionRoute) -> bool {
    route.operations().iter().any(|operation| {
        matches!(
            operation,
            CleanupRouteOperation::Action(ScopeCleanupAction::Drop {
                behavior: DropBehavior::Destructor(_),
                ..
            })
        )
    })
}

fn call_operand_evaluations(call: Node<'_>) -> Result<Vec<Node<'_>>, RustLoweringError> {
    let function = required_field(call, "function")?;
    let mut result = Vec::new();
    let runtime_function = call_function_target(function);
    if let Some((receiver, _member)) = rust_method_call_parts(function) {
        result.push(receiver);
    } else {
        match runtime_function.kind() {
            "identifier" => result.push(runtime_function),
            "scoped_identifier" => {}
            _ => result.push(runtime_function),
        }
    }
    result.extend(call_arguments(call));
    Ok(result)
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|argument| !is_compile_time_syntax(argument.kind()))
        .collect()
}

fn rust_callable_anchor(function: Node<'_>) -> Node<'_> {
    let target = call_function_target(function);
    if let Some((_receiver, member)) = rust_method_call_parts(function) {
        member
    } else {
        match target.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                target.child_by_field_name("name").unwrap_or(target)
            }
            _ => target,
        }
    }
}

fn rust_call_receiver(function: Node<'_>) -> Option<Node<'_>> {
    rust_method_call_parts(function).map(|(receiver, _member)| receiver)
}

fn charge_rust_tuple_work(
    builder: &mut ProcedureCfgBuilder,
    cancellation: &CancellationToken,
    entries: usize,
) -> Result<(), RustLoweringError> {
    if cancellation.is_cancelled() {
        return Err(RustLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    for _ in 0..entries {
        charge_lowering_traversal_step(builder, cancellation)?;
    }
    Ok(())
}

/// The identifier bound to the whole value of `pattern`.
///
/// `ref x` is excluded: it binds a reference to the value (`&T`), not the
/// value itself, so it carries neither the value's type nor its drop.
/// `single_binding_identifier` accepts `ref x` because it only needs the name.
fn identity_binding_identifier(mut pattern: Node<'_>) -> Option<Node<'_>> {
    loop {
        match pattern.kind() {
            "identifier" => return Some(pattern),
            "mut_pattern" | "captured_pattern" => {
                let children = named_children(pattern);
                if children.len() != 1 {
                    return None;
                }
                pattern = children[0];
            }
            _ => return None,
        }
    }
}

fn is_wildcard_pattern(pattern: Node<'_>) -> bool {
    pattern.kind() == "_"
}

/// Whether this pattern introduces a binding.
///
/// A bare `identifier` in pattern position binds; a path that names a variant
/// or constant reaches the tree as the `type` field of a struct or
/// tuple-struct pattern, or as a `scoped_identifier`, and binds nothing. A
/// unit variant written bare (`None`) is indistinguishable from a binding in
/// the syntax alone and is counted as binding, which only adds a gap.
fn rust_pattern_binds_value(pattern: Node<'_>) -> bool {
    !rust_pattern_binding_identifiers(pattern).is_empty()
}

/// Every identifier this pattern binds, in source order.
///
/// One `identifier`, possibly wrapped in `mut` or `ref`, is the common case. A
/// tuple, slice, or struct pattern binds one identifier per component, which is
/// the shape `for (key, value) in map` writes (#2705): before this, such a
/// pattern bound nothing at all, so the loop body's `value` began a fresh
/// unrelated value and the iterable's contents stopped flowing into the body.
///
/// The exclusions are the same ones [`rust_pattern_binds_value`] always
/// applied: a `match_pattern`'s `condition` is a guard expression rather than a
/// pattern, a struct or tuple-struct pattern's `type` names the variant, and a
/// `scoped_identifier` is a path. A unit variant written bare (`None`) is
/// indistinguishable from a binding in the syntax alone and is counted as one,
/// which only adds a value nothing reads.
///
/// The walk is an explicit stack: pattern nesting in a source file is
/// unbounded.
fn rust_pattern_binding_identifiers(pattern: Node<'_>) -> Vec<Node<'_>> {
    let mut bindings = Vec::new();
    let mut pending = vec![pattern];
    while let Some(current) = pending.pop() {
        match current.kind() {
            "identifier" => {
                bindings.push(current);
                continue;
            }
            "scoped_identifier" => continue,
            _ => {}
        }
        // `condition` is the `if` guard of a `match_pattern` (`Some(x) if x > 0`).
        let excluded = binding_excluded_child_fields(Language::Rust, current.kind())
            .iter()
            .copied()
            .chain(["condition"])
            .filter_map(|field| current.child_by_field_name(field))
            .map(|node| node.id())
            .collect::<Vec<_>>();
        pending.extend(
            named_children(current)
                .into_iter()
                .filter(|child| !excluded.contains(&child.id())),
        );
    }
    bindings.sort_by_key(Node::start_byte);
    bindings
}

fn rust_local_scope(node: Node<'_>) -> Option<(usize, usize)> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if matches!(
            candidate.kind(),
            "block" | "closure_expression" | "function_item" | "async_block" | "gen_block"
        ) {
            return Some((candidate.start_byte(), candidate.end_byte()));
        }
        parent = candidate.parent();
    }
    None
}

fn is_rust_nested_execution_boundary(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_item" | "closure_expression" | "async_block" | "gen_block"
    )
}

fn peel_rust_parentheses(mut node: Node<'_>) -> Node<'_> {
    loop {
        node = unwrap_attributes(node);
        if node.kind() != "parenthesized_expression" {
            return node;
        }
        let Some(inner) = first_named_child(node) else {
            return node;
        };
        node = inner;
    }
}

fn rust_boolean_literal_value(source: &str, node: Node<'_>) -> Option<bool> {
    let node = peel_rust_parentheses(node);
    match node.kind() {
        "true" => Some(true),
        "false" => Some(false),
        "boolean_literal" => match source.get(node.byte_range())? {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn rust_literal_value_kind(source: &str, node: Node<'_>) -> Option<SemanticValueKind> {
    let node = peel_rust_parentheses(node);
    if let Some(value) = rust_boolean_literal_value(source, node) {
        return Some(SemanticValueKind::Boolean(value));
    }
    if node.kind() == "integer_literal" {
        let text = source.get(node.byte_range())?;
        if text.starts_with("0b") || text.starts_with("0o") || text.starts_with("0x") {
            return None;
        }
        let (value, suffix) = rust_integer_literal_parts(source, node)?;
        return if suffix.is_empty() || suffix.starts_with("u") {
            Some(SemanticValueKind::UnsignedInteger(value))
        } else {
            Some(SemanticValueKind::SignedInteger(
                i128::try_from(value).ok()?,
            ))
        };
    }
    if node.kind() == "unary_expression"
        && node.child(0).is_some_and(|operator| operator.kind() == "-")
    {
        let operand = node.named_child(0)?;
        return match rust_literal_value_kind(source, operand)? {
            SemanticValueKind::UnsignedInteger(value) => Some(SemanticValueKind::SignedInteger(
                i128::try_from(value).ok()?.checked_neg()?,
            )),
            SemanticValueKind::SignedInteger(value) => {
                Some(SemanticValueKind::SignedInteger(value.checked_neg()?))
            }
            _ => None,
        };
    }
    None
}

fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    let node = unwrap_attributes(node);
    match node.kind() {
        "closure_expression" | "async_block" | "gen_block" => SemanticValueKind::Callable,
        "true" => SemanticValueKind::Boolean(true),
        "false" => SemanticValueKind::Boolean(false),
        "boolean_literal" => match node.child(0).map(|child| child.kind()) {
            Some("true") => SemanticValueKind::Boolean(true),
            Some("false") => SemanticValueKind::Boolean(false),
            _ => SemanticValueKind::Constant,
        },
        kind if kind.ends_with("_literal") || kind == "unit_expression" => {
            SemanticValueKind::Constant
        }
        _ => SemanticValueKind::Temporary,
    }
}

/// Whether this expression's lowering already publishes where its value came
/// from, so a tail-expression return needs no value-refinement gap.
fn rust_expression_has_direct_value_evidence(node: Node<'_>) -> bool {
    let node = rust_transparent_value_leaf(node).unwrap_or_else(|| unwrap_attributes(node));
    matches!(
        node.kind(),
        "call_expression"
            | "struct_expression"
            | "array_expression"
            | "parenthesized_expression"
            | "reference_expression"
            | "binary_expression"
            | "unary_expression"
            | "type_cast_expression"
    ) || is_runtime_leaf(node.kind())
}

fn ownership_gap_detail(reason: RustOwnershipIncomplete) -> &'static str {
    match reason {
        RustOwnershipIncomplete::GenericObligation => {
            "Rust ownership transfer depends on an unresolved generic trait obligation"
        }
        RustOwnershipIncomplete::AmbiguousIdentity => {
            "Rust ownership transfer has more than one structured nominal type candidate"
        }
        RustOwnershipIncomplete::UnresolvedPath => {
            "Rust ownership transfer refers to a nominal type whose declaration identity is unresolved"
        }
        RustOwnershipIncomplete::RawPointer => {
            "Rust ownership transfer crosses a raw-pointer type outside the safe reference proof"
        }
        RustOwnershipIncomplete::MacroExpansion => {
            "Rust ownership transfer depends on macro-expanded type or trait facts that are unavailable"
        }
        RustOwnershipIncomplete::WrongTraitIdentity => {
            "Rust ownership transfer names Copy, Clone, or Drop without proving the builtin trait identity"
        }
        RustOwnershipIncomplete::CyclicNominal => {
            "Rust ownership transfer belongs to a cyclic nominal proof that did not reach a fixed point"
        }
        RustOwnershipIncomplete::MissingType => {
            "Rust ownership transfer has no exact source and destination type evidence"
        }
        RustOwnershipIncomplete::UnsupportedType => {
            "Rust ownership transfer uses a type shape whose Copy or move semantics are not proven"
        }
    }
}

/// A declared type that proves the value it describes owns no `Drop`.
///
/// A reference never runs a destructor when it goes out of scope, and a
/// primitive (`i32`, `bool`, `char`, ...) is `Copy` and cannot implement
/// `Drop`. Both facts are read from the declared type node, never from the
/// spelling of the source text.
fn rust_type_is_definitely_non_dropping(ty: Node<'_>) -> bool {
    matches!(ty.kind(), "reference_type" | "primitive_type")
}

/// The shape a declared type states, read from the type node itself.
///
/// A reference is transparent for the same reason it is in `expression_shape`:
/// `&Holder` and `&mut Holder` both project `Holder`'s own fields.
fn rust_declared_type_shape(source: &str, ty: Node<'_>) -> Option<RustValueShape> {
    let mut current = ty;
    loop {
        match current.kind() {
            "type_identifier" => {
                return node_text(source, current).map(|name| RustValueShape::Struct(name.into()));
            }
            "reference_type" => current = current.child_by_field_name("type")?,
            "array_type" => {
                return Some(RustValueShape::Array {
                    primitive_elements: current
                        .child_by_field_name("element")
                        .is_some_and(|element| element.kind() == "primitive_type"),
                });
            }
            _ => return None,
        }
    }
}

fn rust_type_path_node(ty: Node<'_>) -> Option<Node<'_>> {
    match ty.kind() {
        "generic_type" => ty.child_by_field_name("type"),
        "type_identifier" | "scoped_type_identifier" => Some(ty),
        _ => None,
    }
}

fn rust_call_type_argument(function: Node<'_>, index: usize) -> Option<Node<'_>> {
    let arguments = function.child_by_field_name("type_arguments")?;
    named_children(arguments).get(index).copied()
}

fn rust_generic_type_argument(type_node: Node<'_>, index: usize) -> Option<Node<'_>> {
    let arguments = type_node.child_by_field_name("type_arguments")?;
    named_children(arguments)
        .into_iter()
        .filter(|argument| {
            matches!(
                argument.kind(),
                "primitive_type"
                    | "unit_type"
                    | "never_type"
                    | "reference_type"
                    | "pointer_type"
                    | "array_type"
                    | "slice_type"
                    | "tuple_type"
                    | "type_identifier"
                    | "scoped_type_identifier"
                    | "generic_type"
            )
        })
        .nth(index)
}

fn rust_type_byte_size(source: &str, ty: Node<'_>) -> Option<u128> {
    match ty.kind() {
        "primitive_type" => match node_text(source, ty)?.trim() {
            "i8" | "u8" | "bool" => Some(1),
            "i16" | "u16" => Some(2),
            "i32" | "u32" | "f32" | "char" => Some(4),
            "i64" | "u64" | "f64" => Some(8),
            "i128" | "u128" | "f128" => Some(16),
            _ => None,
        },
        "array_type" => {
            let element = ty.child_by_field_name("element")?;
            let length = rust_integer_literal_value(source, ty.child_by_field_name("length")?)?;
            rust_type_byte_size(source, element)?.checked_mul(length)
        }
        _ => None,
    }
}

/// The `Self` type of the `impl` block this callable is declared in.
/// Whether this expression is written by the assignment that contains it.
///
/// A write target is not a read. The lowered store replaces its own evaluation
/// list so the target node is never scheduled, but a compound assignment --
/// whose update this adapter does not lower -- still schedules its place, and
/// minting a `MemoryLoad` there would publish a read of the very location the
/// statement overwrites.
fn is_rust_assignment_target(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression" => current = parent,
            "assignment_expression" | "compound_assignment_expr" => {
                return field_matches(parent, "left", current);
            }
            _ => return false,
        }
    }
    false
}

/// The `Self` type of the `impl` block this callable is declared in.
fn rust_impl_self_type(callable: Node<'_>) -> Option<Node<'_>> {
    let mut current = callable;
    while let Some(parent) = current.parent() {
        if parent.kind() == "impl_item" {
            return parent.child_by_field_name("type");
        }
        if is_rust_nested_execution_boundary(parent) {
            return None;
        }
        current = parent;
    }
    None
}

fn rust_parameter_is_definitely_non_dropping(node: Node<'_>) -> bool {
    node.child_by_field_name("type")
        .is_some_and(rust_type_is_definitely_non_dropping)
        || rust_type_is_definitely_non_dropping(node)
        || rust_self_parameter_is_borrowed(node)
}

/// `&self` and `&mut self` borrow the receiver: the grammar spells the borrow
/// as an anonymous `&` token inside `self_parameter`, which has no `type`
/// field. A by-value `self` owns the receiver and may run its destructor.
pub(crate) fn rust_self_parameter_is_borrowed(node: Node<'_>) -> bool {
    if node.kind() != "self_parameter" {
        return false;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == "&")
}

/// What one struct declaration in this file states about one of its fields.
#[derive(Debug, Clone)]
struct RustFieldDeclaration {
    /// The field's own `field_identifier`, which is the identity two
    /// occurrences of that field must agree on to name one memory location.
    anchor: SourceAnchor,
    /// Whether the declared field type is a primitive, so overwriting the
    /// field drops nothing.
    primitive: bool,
    /// The shape the declared field type states, which is what lets a nested
    /// access path resolve its next selector.
    shape: Option<RustValueShape>,
}

/// Everything one Rust file states that every procedure lowered from it reads.
///
/// All three tables are file-scoped by construction: this adapter lowers one
/// file at a time and never consults another. That is the same posture the
/// Python adapter's `instance_field_proofs` takes, and it is stated here so a
/// reader does not mistake any of these for a whole-crate proof.
struct RustFileFacts<'tree> {
    /// Same-file top-level integer constants keyed by their bare identifier.
    /// `None` marks a duplicate or unsupported initializer, which no longer
    /// proves one constant identity.
    integer_constants: HashMap<Box<str>, Option<u128>>,
    /// One unambiguous same-file bare function name and its declared return
    /// type. Duplicate names retain `None` rather than selecting by spelling.
    function_return_types: HashMap<Box<str>, Option<Node<'tree>>>,
    /// Same-file `fn` names whose declared return type owns no `Drop`.
    non_dropping_return_functions: HashMap<Box<str>, bool>,
    /// Every `(struct, field)` this file declares. `None` marks a pair the
    /// file states more than once, which no longer picks a declaration.
    struct_fields: HashMap<(Box<str>, Box<str>), Option<RustFieldDeclaration>>,
    /// Unambiguous named-field struct bodies, including empty field sets.
    /// Kept only for this file lowering; duplicate declarations retain None.
    struct_field_lists: HashMap<Box<str>, Option<Node<'tree>>>,
    /// Structs this file declares whose values provably run no destructor:
    /// every field is a primitive or another such struct, the struct takes no
    /// type parameters, and this file states no `impl Drop` for it.
    plain_structs: HashSet<Box<str>>,
    /// Qualified paths this file's top-level `use` items bind, keyed by the
    /// bound terminal name. `None` marks a name bound by more than one item,
    /// which no longer proves one path.
    use_bindings: HashMap<Box<str>, Option<Vec<Box<str>>>>,
    /// Import paths used only to derive Rust modeled receiver owners. This
    /// recognizes explicit aliases without widening the shared import
    /// consumer's deliberately narrower clause contract.
    receiver_use_bindings: HashMap<Box<str>, Option<Vec<Box<str>>>>,
    /// Type-namespace names this file declares, which may shadow a `use`
    /// binding; a name here resolves through no import.
    shadowed_type_names: HashSet<Box<str>>,
    /// Source-declared types for parameters, locals, statics, and constants.
    /// These are per-file facts reused by receiver matching and remain tied to
    /// this file's syntax tree.
    typed_bindings: Vec<RustTypedBinding<'tree>>,
    /// Structured same-file static declarations and their lexical item scopes.
    static_declarations: Vec<RustStaticDeclaration<'tree>>,
}

struct RustStaticDeclaration<'tree> {
    name: Box<str>,
    name_node: Node<'tree>,
    scope: Node<'tree>,
}

#[derive(Debug, Clone)]
struct RustTypedBinding<'tree> {
    name: Box<str>,
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    kind: RustTypedBindingKind,
    declared_type: Option<Node<'tree>>,
    initializer: Option<Node<'tree>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustTypedBindingKind {
    Parameter,
    Local,
    StaticOrConst,
}

fn rust_file_facts<'tree>(prepared: &'tree PreparedSyntaxTree) -> RustFileFacts<'tree> {
    rust_file_facts_from_tree(prepared.source(), prepared.tree())
}

fn rust_file_facts_from_tree<'tree>(
    source: &'tree str,
    tree: &'tree tree_sitter::Tree,
) -> RustFileFacts<'tree> {
    let mut integer_constants: HashMap<Box<str>, Option<u128>> = HashMap::default();
    let mut function_return_types: HashMap<Box<str>, Option<Node<'tree>>> = HashMap::default();
    let mut non_dropping_return_functions: HashMap<Box<str>, bool> = HashMap::default();
    let mut struct_fields: HashMap<(Box<str>, Box<str>), Option<RustFieldDeclaration>> =
        HashMap::default();
    let mut struct_field_lists = HashMap::default();
    // Every struct this file declares, with the field types it states, plus
    // the names this file declares more than once and the names it implements
    // `Drop` for. Both disqualify a struct from the plainness fixpoint below.
    let mut declared_fields: HashMap<Box<str>, Vec<Node<'_>>> = HashMap::default();
    let mut disqualified: HashSet<Box<str>> = HashSet::default();
    let mut every_struct_drops = false;
    let mut use_bindings: HashMap<Box<str>, Option<Vec<Box<str>>>> = HashMap::default();
    let mut receiver_use_bindings: HashMap<Box<str>, Option<Vec<Box<str>>>> = HashMap::default();
    let mut shadowed_type_names: HashSet<Box<str>> = HashSet::default();
    let mut typed_bindings = Vec::new();
    let mut static_declarations = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_item" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|name| node_text(source, name))
                {
                    if node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "source_file")
                    {
                        let return_type = node.child_by_field_name("return_type");
                        function_return_types
                            .entry(name.into())
                            .and_modify(|unique| *unique = None)
                            .or_insert(return_type);
                    }
                    let non_dropping = node
                        .child_by_field_name("return_type")
                        .is_some_and(rust_type_is_definitely_non_dropping);
                    non_dropping_return_functions
                        .entry(name.into())
                        .and_modify(|agreed| *agreed = *agreed && non_dropping)
                        .or_insert(non_dropping);
                }
            }
            "struct_item" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|name| node_text(source, name))
                {
                    shadowed_type_names.insert(name.into());
                    struct_field_lists
                        .entry(name.into())
                        .and_modify(|body| *body = None)
                        .or_insert_with(|| {
                            node.child_by_field_name("body").filter(|body| {
                                body.kind() == "field_declaration_list"
                                    && node.child_by_field_name("type_parameters").is_none()
                            })
                        });
                    let fields = node
                        .child_by_field_name("body")
                        .filter(|body| body.kind() == "field_declaration_list")
                        .map(named_children)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|child| child.kind() == "field_declaration")
                        .collect::<Vec<_>>();
                    for field in &fields {
                        let Some(field_name) = field
                            .child_by_field_name("name")
                            .and_then(|name| node_text(source, name))
                        else {
                            continue;
                        };
                        let declaration = field
                            .child_by_field_name("name")
                            .and_then(|name| source_anchor(name, 0).ok())
                            .map(|anchor| RustFieldDeclaration {
                                anchor,
                                primitive: field
                                    .child_by_field_name("type")
                                    .is_some_and(|ty| ty.kind() == "primitive_type"),
                                shape: field
                                    .child_by_field_name("type")
                                    .and_then(|ty| rust_declared_type_shape(source, ty)),
                            });
                        match struct_fields.entry((name.into(), field_name.into())) {
                            std::collections::hash_map::Entry::Vacant(entry) => {
                                entry.insert(declaration);
                            }
                            std::collections::hash_map::Entry::Occupied(mut entry) => {
                                entry.insert(None);
                            }
                        }
                    }
                    if node.child_by_field_name("type_parameters").is_some()
                        || declared_fields.insert(name.into(), fields).is_some()
                    {
                        disqualified.insert(name.into());
                    }
                }
            }
            "parameter" => {
                if let Some(pattern) = node.child_by_field_name("pattern")
                    && let Some(name) = identity_binding_identifier(pattern)
                    && let Some(name_text) = node_text(source, name)
                    && let Some((scope_start, scope_end)) = rust_local_scope(node)
                {
                    typed_bindings.push(RustTypedBinding {
                        name: name_text.into(),
                        declaration_start: name.start_byte(),
                        visible_from: node.end_byte(),
                        scope_start,
                        scope_end,
                        kind: RustTypedBindingKind::Parameter,
                        declared_type: node.child_by_field_name("type"),
                        initializer: None,
                    });
                }
            }
            "self_parameter" => {
                if let Some((scope_start, scope_end)) = rust_local_scope(node)
                    && let Some(declared_type) = rust_impl_self_type(node)
                {
                    typed_bindings.push(RustTypedBinding {
                        name: "self".into(),
                        declaration_start: node.start_byte(),
                        visible_from: node.end_byte(),
                        scope_start,
                        scope_end,
                        kind: RustTypedBindingKind::Parameter,
                        declared_type: Some(declared_type),
                        initializer: None,
                    });
                }
            }
            "let_declaration" => {
                if let Some(pattern) = node.child_by_field_name("pattern")
                    && let Some(name) = identity_binding_identifier(pattern)
                    && let Some(name_text) = node_text(source, name)
                    && let Some((scope_start, scope_end)) = rust_local_scope(node)
                {
                    typed_bindings.push(RustTypedBinding {
                        name: name_text.into(),
                        declaration_start: name.start_byte(),
                        visible_from: node.end_byte(),
                        scope_start,
                        scope_end,
                        kind: RustTypedBindingKind::Local,
                        declared_type: node.child_by_field_name("type"),
                        initializer: node.child_by_field_name("value"),
                    });
                }
            }
            "static_item" | "const_item" => {
                if node.kind() == "const_item"
                    && node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "source_file")
                    && let Some(name) = node
                        .child_by_field_name("name")
                        .and_then(|name| node_text(source, name))
                {
                    let value = node
                        .child_by_field_name("value")
                        .and_then(|value| rust_integer_constant_value(source, value));
                    match integer_constants.entry(name.into()) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(value);
                        }
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            entry.insert(None);
                        }
                    }
                }
                if let Some(name) = node.child_by_field_name("name")
                    && let Some(name_text) = node_text(source, name)
                {
                    let (scope_start, scope_end) =
                        rust_local_scope(node).unwrap_or((0, source.len()));
                    typed_bindings.push(RustTypedBinding {
                        name: name_text.into(),
                        declaration_start: name.start_byte(),
                        visible_from: if scope_start == 0 { 0 } else { node.end_byte() },
                        scope_start,
                        scope_end,
                        kind: RustTypedBindingKind::StaticOrConst,
                        declared_type: node.child_by_field_name("type"),
                        initializer: None,
                    });
                }
                // Statics are also memory locations for resource identity
                // (#3850); constants are values, not places.
                if node.kind() == "static_item"
                    && let (Some(name_node), Some(scope)) = (
                        node.child_by_field_name("name"),
                        rust_item_lexical_scope(node),
                    )
                    && let Some(name) = node_text(source, name_node)
                {
                    static_declarations.push(RustStaticDeclaration {
                        name: name.into(),
                        name_node,
                        scope,
                    });
                }
            }
            "impl_item" => {
                let implements_drop = node
                    .child_by_field_name("trait")
                    .and_then(|declared| node_text(source, declared))
                    .is_some_and(|declared| declared.trim_end_matches('>').ends_with("Drop"));
                if implements_drop {
                    match node
                        .child_by_field_name("type")
                        .filter(|declared| declared.kind() == "type_identifier")
                        .and_then(|declared| node_text(source, declared))
                    {
                        Some(name) => {
                            disqualified.insert(name.into());
                        }
                        // A `Drop` implementation whose subject is not a plain
                        // name -- a generic instantiation, a path, a tuple --
                        // names a type this prescan does not identify, so no
                        // struct in this file keeps its plainness proof.
                        None => every_struct_drops = true,
                    }
                }
            }
            "use_declaration" => {
                // Only file-scope imports bind for these procedures; a `use`
                // inside a nested module keeps its own scope, and resolving
                // it by hand would guess a scope this prescan does not own.
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "source_file")
                    && let Some(clause) = node.named_child(0)
                {
                    let bindings = rust_use_clause_bindings(clause, source);
                    if let Some(bindings) = bindings.as_ref() {
                        for (terminal, segments) in bindings {
                            record_rust_use_binding(
                                &mut receiver_use_bindings,
                                terminal.clone(),
                                segments.clone(),
                            );
                        }
                    } else if let Some(bindings) =
                        rust_receiver_use_alias_clause_bindings(clause, source)
                    {
                        for (terminal, segments) in bindings {
                            record_rust_use_binding(&mut receiver_use_bindings, terminal, segments);
                        }
                    }
                    if let Some(bindings) = bindings {
                        for (terminal, segments) in bindings {
                            if segments.len() < 2 {
                                continue;
                            }
                            record_rust_use_binding(&mut use_bindings, terminal, segments);
                        }
                    }
                }
            }
            "enum_item" | "mod_item" | "trait_item" | "type_item" | "union_item" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|name| node_text(source, name))
                {
                    shadowed_type_names.insert(name.into());
                }
            }
            _ => {}
        }
        stack.extend(named_children(node));
    }

    // A type-namespace item declared anywhere in this file may shadow a
    // same-named `use` binding for the procedures that see it; fail closed
    // rather than picking a scope by hand.
    for name in &shadowed_type_names {
        use_bindings.remove(name);
    }

    // A struct is plain when every field is a primitive or another plain
    // struct. The fixpoint grows the proven set until it stops changing, which
    // terminates because the set only grows and is bounded by the file's
    // declarations. A cyclic `struct A { b: B }`/`struct B { a: A }` is
    // impossible in Rust without indirection, and indirection is not a
    // primitive type, so a cycle simply never enters the set.
    let mut plain_structs: HashSet<Box<str>> = HashSet::default();
    if !every_struct_drops {
        loop {
            let mut grew = false;
            for (name, fields) in &declared_fields {
                if disqualified.contains(name) || plain_structs.contains(name) {
                    continue;
                }
                let plain = fields.iter().all(|field| {
                    field.child_by_field_name("type").is_some_and(|ty| {
                        ty.kind() == "primitive_type"
                            || node_text(source, ty)
                                .is_some_and(|declared| plain_structs.contains(declared))
                    })
                });
                if plain {
                    plain_structs.insert(name.clone());
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
    }

    RustFileFacts {
        integer_constants,
        function_return_types,
        non_dropping_return_functions,
        struct_fields,
        struct_field_lists,
        plain_structs,
        use_bindings,
        receiver_use_bindings,
        shadowed_type_names,
        typed_bindings,
        static_declarations,
    }
}

/// The nearest Rust item scope that owns a static declaration. Block-local
/// statics and module-level statics use the same structured name lookup while
/// the narrower scope wins over an enclosing module declaration.
fn rust_item_lexical_scope(item: Node<'_>) -> Option<Node<'_>> {
    let mut current = item.parent()?;
    loop {
        if matches!(current.kind(), "source_file" | "declaration_list" | "block") {
            return Some(current);
        }
        current = current.parent()?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RustSourceRange {
    start: usize,
    end: usize,
}

impl RustSourceRange {
    fn of(node: Node<'_>) -> Self {
        Self {
            start: node.start_byte(),
            end: node.end_byte(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RustReceiverBindingFact {
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    kind: RustTypedBindingKind,
    declared_type: Option<RustSourceRange>,
    initializer: Option<RustSourceRange>,
}

/// Query-scoped source facts needed to bind a value receiver to one exact
/// active Rust model owner. The fact set is built once for one blob inside a
/// definition batch; all syntax is retained as byte ranges, not tree nodes.
pub(crate) struct RustReceiverTypeFacts {
    bindings: HashMap<Box<str>, Vec<RustReceiverBindingFact>>,
    function_return_types: HashMap<Box<str>, Option<RustSourceRange>>,
    use_bindings: HashMap<Box<str>, Option<Vec<Box<str>>>>,
    shadowed_type_names: HashSet<Box<str>>,
}

const RUST_PRELUDE_MODEL_OWNERS: &[(&[&str], &str)] = &[
    (&["std", "boxed", "Box"], "std.boxed.Box"),
    (&["alloc", "boxed", "Box"], "alloc.boxed.Box"),
    (&["std", "vec", "Vec"], "std.vec.Vec"),
    (&["alloc", "vec", "Vec"], "alloc.vec.Vec"),
    (&["std", "string", "String"], "std.string.String"),
    (&["alloc", "string", "String"], "alloc.string.String"),
];

enum RustReceiverTypeWork<'tree> {
    Expression(Node<'tree>),
    DeclaredType(Node<'tree>),
    ModelReceiverCall {
        member: Box<str>,
        parameter_count: u32,
    },
}

impl RustReceiverTypeFacts {
    pub(crate) fn from_tree(source: &str, tree: &tree_sitter::Tree) -> Self {
        let facts = rust_file_facts_from_tree(source, tree);
        Self::from_file_facts(&facts)
    }

    fn from_file_facts(facts: &RustFileFacts<'_>) -> Self {
        let mut bindings: HashMap<Box<str>, Vec<RustReceiverBindingFact>> = HashMap::default();
        for binding in &facts.typed_bindings {
            bindings
                .entry(binding.name.clone())
                .or_default()
                .push(RustReceiverBindingFact {
                    declaration_start: binding.declaration_start,
                    visible_from: binding.visible_from,
                    scope_start: binding.scope_start,
                    scope_end: binding.scope_end,
                    kind: binding.kind,
                    declared_type: binding.declared_type.map(RustSourceRange::of),
                    initializer: binding.initializer.map(RustSourceRange::of),
                });
        }
        Self {
            bindings,
            function_return_types: facts
                .function_return_types
                .iter()
                .map(|(name, return_type)| (name.clone(), return_type.map(RustSourceRange::of)))
                .collect(),
            use_bindings: facts.receiver_use_bindings.clone(),
            shadowed_type_names: facts.shadowed_type_names.clone(),
        }
    }

    /// Derive the exact active-model owner of one value expression. Unknown,
    /// conflicting, and trait receivers remain unresolved. The caller checks
    /// the selected member family's completeness separately from type identity.
    pub(crate) fn owner_of_expression(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        expression: Node<'_>,
        overlay: &SemanticModelOverlay,
        nominal_owner: &mut dyn FnMut(Node<'_>) -> Option<String>,
    ) -> Option<String> {
        self.owner_of_expression_with_ownership(
            source,
            tree,
            expression,
            overlay,
            nominal_owner,
            None,
        )
    }

    fn owner_of_expression_with_ownership(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        expression: Node<'_>,
        overlay: &SemanticModelOverlay,
        nominal_owner: &mut dyn FnMut(Node<'_>) -> Option<String>,
        ownership: Option<&RustOwnershipIndex<'_, '_>>,
    ) -> Option<String> {
        if !self.has_unresolved_receiver_binding(source, expression) {
            return None;
        }
        let mut pending = vec![RustReceiverTypeWork::Expression(expression)];
        let mut results = Vec::<Option<String>>::new();
        while let Some(work) = pending.pop() {
            match work {
                RustReceiverTypeWork::Expression(node) => {
                    let node = unwrap_attributes(node);
                    match node.kind() {
                        "parenthesized_expression" => match first_named_child(node) {
                            Some(inner) => pending.push(RustReceiverTypeWork::Expression(inner)),
                            None => results.push(None),
                        },
                        "reference_expression" => match rust_reference_expression_value(node) {
                            Some(inner) => pending.push(RustReceiverTypeWork::Expression(inner)),
                            None => results.push(None),
                        },
                        "unary_expression" => match rust_dereference_operand(node) {
                            Some(inner) => pending.push(RustReceiverTypeWork::Expression(inner)),
                            None => results.push(None),
                        },
                        "identifier" | "self" => {
                            let name = if node.kind() == "self" {
                                "self"
                            } else {
                                let Some(name) = node_text(source, node) else {
                                    results.push(None);
                                    continue;
                                };
                                name
                            };
                            let Some(binding) = self.binding_at(name, node.start_byte()) else {
                                results.push(None);
                                continue;
                            };
                            let range = binding.declared_type.or(binding.initializer);
                            match range.and_then(|range| rust_node_at_range(tree, range)) {
                                Some(value)
                                    if binding.declared_type
                                        == Some(RustSourceRange::of(value)) =>
                                {
                                    pending.push(RustReceiverTypeWork::DeclaredType(value));
                                }
                                Some(value) => {
                                    pending.push(RustReceiverTypeWork::Expression(value))
                                }
                                None => results.push(None),
                            }
                        }
                        "struct_expression" => match node.child_by_field_name("name") {
                            Some(ty) => pending.push(RustReceiverTypeWork::DeclaredType(ty)),
                            None => results.push(None),
                        },
                        "type_cast_expression" => match node.child_by_field_name("type") {
                            Some(ty) => pending.push(RustReceiverTypeWork::DeclaredType(ty)),
                            None => results.push(None),
                        },
                        "call_expression" => {
                            let Some(function) = node.child_by_field_name("function") else {
                                results.push(None);
                                continue;
                            };
                            let function = call_function_target(function);
                            if function.kind() == "field_expression" {
                                let Some(receiver) = function.child_by_field_name("value") else {
                                    results.push(None);
                                    continue;
                                };
                                let Some(member) = function
                                    .child_by_field_name("field")
                                    .and_then(|field| node_text(source, field))
                                else {
                                    results.push(None);
                                    continue;
                                };
                                let Ok(parameter_count) = u32::try_from(call_arguments(node).len())
                                else {
                                    results.push(None);
                                    continue;
                                };
                                pending.push(RustReceiverTypeWork::ModelReceiverCall {
                                    member: member.into(),
                                    parameter_count,
                                });
                                pending.push(RustReceiverTypeWork::Expression(receiver));
                            } else if matches!(function.kind(), "identifier" | "scoped_identifier")
                            {
                                match self.path_call_return_type(
                                    source,
                                    tree,
                                    function,
                                    node,
                                    overlay,
                                    nominal_owner,
                                    ownership,
                                ) {
                                    Some(owner) => results.push(Some(owner)),
                                    None => results.push(None),
                                }
                            } else {
                                results.push(None);
                            }
                        }
                        _ => results.push(None),
                    }
                }
                RustReceiverTypeWork::DeclaredType(ty) => {
                    results.push(nominal_owner(ty));
                }
                RustReceiverTypeWork::ModelReceiverCall {
                    member,
                    parameter_count,
                } => {
                    let Some(receiver_owner) = results.pop().flatten() else {
                        results.push(None);
                        continue;
                    };
                    results.push(self.model_call_return_type(
                        overlay,
                        &receiver_owner,
                        &member,
                        true,
                        parameter_count,
                    ));
                }
            }
        }
        (results.len() == 1)
            .then(|| results.pop().flatten())
            .flatten()
    }

    fn has_unresolved_receiver_binding(&self, source: &str, expression: Node<'_>) -> bool {
        let mut node = unwrap_attributes(expression);
        loop {
            match node.kind() {
                "parenthesized_expression" => {
                    let Some(inner) = first_named_child(node) else {
                        return false;
                    };
                    node = inner;
                }
                "reference_expression" => {
                    let Some(inner) = rust_reference_expression_value(node) else {
                        return false;
                    };
                    node = inner;
                }
                "unary_expression" => {
                    let Some(inner) = rust_dereference_operand(node) else {
                        return false;
                    };
                    node = inner;
                }
                "identifier" | "self" => {
                    let name = if node.kind() == "self" {
                        "self"
                    } else if let Some(name) = node_text(source, node) {
                        name
                    } else {
                        return false;
                    };
                    let Some(binding) = self.binding_at(name, node.start_byte()) else {
                        return false;
                    };
                    return match binding.kind {
                        // Native proof runs first. When it declines, the active
                        // model can still identify an explicitly typed external
                        // receiver or follow a model-backed local initializer.
                        RustTypedBindingKind::Local => {
                            binding.declared_type.is_some() || binding.initializer.is_some()
                        }
                        RustTypedBindingKind::Parameter => binding.declared_type.is_some(),
                        // Some resolver versions do not classify block-local
                        // static/const items as value bindings. Preserve the
                        // declared-type fallback for those item nodes only.
                        RustTypedBindingKind::StaticOrConst => binding.declared_type.is_some(),
                    };
                }
                // The upstream resolver handles modeled returns when it can
                // establish the call identity from its own source facts. G03
                // fills only the gap where an active model's structured return
                // type supplies the receiver owner (for example, an imported
                // alias to Command::new). owner_of_expression still requires a
                // unique, complete callable and nominal return type.
                "call_expression" => return true,
                _ => return false,
            }
        }
    }

    fn binding_at(&self, name: &str, byte: usize) -> Option<RustReceiverBindingFact> {
        let bindings = self.bindings.get(name)?;
        let best = bindings
            .iter()
            .filter(|binding| {
                binding.visible_from <= byte
                    && binding.scope_start <= byte
                    && byte < binding.scope_end
            })
            .min_by_key(|binding| {
                (
                    binding.scope_end - binding.scope_start,
                    std::cmp::Reverse(binding.declaration_start),
                )
            })?;
        Some(*best)
    }

    #[allow(clippy::too_many_arguments)]
    fn path_call_return_type(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        function: Node<'_>,
        call: Node<'_>,
        overlay: &SemanticModelOverlay,
        nominal_owner: &mut dyn FnMut(Node<'_>) -> Option<String>,
        ownership: Option<&RustOwnershipIndex<'_, '_>>,
    ) -> Option<String> {
        let segments = brokk_bifrost_rust::graph_support::rust_path_segments(function)?;
        let names = segments
            .iter()
            .map(|segment| node_text(source, *segment).map(str::to_owned))
            .collect::<Option<Vec<_>>>()?;
        let call_start = call.start_byte();
        if names.len() > 1 {
            let member = names.last()?;
            let parameter_count = u32::try_from(call_arguments(call).len()).ok()?;
            if let Some(ownership) = ownership {
                for &(standard_owner_path, model_owner) in RUST_PRELUDE_MODEL_OWNERS {
                    let mut expected = standard_owner_path.to_vec();
                    expected.push(member.as_str());
                    if ownership.resolves_standard_path(function, &expected)
                        && let Some(return_owner) = self.model_call_return_type(
                            overlay,
                            model_owner,
                            member,
                            false,
                            parameter_count,
                        )
                    {
                        return Some(return_owner);
                    }
                }
            }
        }
        if names.len() == 1 {
            let name = names.first()?;
            if function.kind() == "identifier" && self.binding_at(name, call_start).is_some() {
                return None;
            }
            if let Some(path) = self.imported_path(name, call_start) {
                let mut full_path = path;
                let parameter_count = u32::try_from(call_arguments(call).len()).ok()?;
                let member = full_path.pop()?;
                let owner = full_path.join(".");
                return self.model_call_return_type(
                    overlay,
                    &owner,
                    &member,
                    false,
                    parameter_count,
                );
            }
            let return_type = self.function_return_types.get(name.as_str())?.as_ref()?;
            return rust_node_at_range(tree, *return_type).and_then(nominal_owner);
        }
        let mut full_path = self.qualified_path_segments(names, call_start)?;
        let member = full_path.pop()?;
        let owner = full_path.join(".");
        let parameter_count = u32::try_from(call_arguments(call).len()).ok()?;
        self.model_call_return_type(overlay, &owner, &member, false, parameter_count)
    }

    fn model_call_return_type(
        &self,
        overlay: &SemanticModelOverlay,
        owner: &str,
        member: &str,
        has_receiver: bool,
        parameter_count: u32,
    ) -> Option<String> {
        let owner_symbol = unique_rust_model_symbol(overlay, owner)?;
        if !matches!(
            owner_symbol.kind,
            SemanticModelSymbolKind::Module
                | SemanticModelSymbolKind::Struct
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Union
        ) {
            return None;
        }
        let callable = overlay.callable_for_application(
            SemanticModelCallableKey::new(
                Language::Rust.config_label(),
                &owner_symbol.qualified_name,
                member,
                has_receiver,
                parameter_count,
            ),
            &SemanticModelCallApplication::positional(parameter_count),
        );
        if callable.disposition != SemanticModelCallableDisposition::Unique {
            return None;
        }
        let [callable] = callable.records.as_slice() else {
            return None;
        };
        if !callable.externally_visible() || callable.provenance.ambiguous {
            return None;
        }
        let returned = callable.structured_signature()?.returns.as_ref()?;
        self.model_type_ref_owner(overlay, returned)
    }

    fn model_type_ref_owner(
        &self,
        overlay: &SemanticModelOverlay,
        mut reference: &TypeRef,
    ) -> Option<String> {
        loop {
            match reference {
                TypeRef::ByRef { element, .. } | TypeRef::Pointer { element } => {
                    reference = element;
                }
                TypeRef::Declared { id, .. } => {
                    let matched = overlay.symbols_with_id(id);
                    if matched.disposition != SemanticModelOverlayDisposition::Unique {
                        return None;
                    }
                    let [symbol] = matched.records.as_slice() else {
                        return None;
                    };
                    let resolved = unique_rust_model_symbol(overlay, &symbol.qualified_name)?;
                    return nominal_rust_model_type(resolved)
                        .then(|| resolved.qualified_name.clone());
                }
                TypeRef::Named { name, .. } => {
                    let symbol = unique_rust_model_symbol(overlay, name)?;
                    return nominal_rust_model_type(symbol).then(|| symbol.qualified_name.clone());
                }
                _ => return None,
            }
        }
    }

    fn qualified_path_segments(
        &self,
        mut segments: Vec<String>,
        byte: usize,
    ) -> Option<Vec<String>> {
        let first = segments.first()?;
        if self.shadowed_type_names.contains(first.as_str()) {
            return None;
        }
        if let Some(imported) = self.imported_path(first, byte) {
            let mut qualified = imported;
            qualified.extend(segments.into_iter().skip(1));
            segments = qualified;
        }
        Some(segments)
    }

    fn imported_path(&self, name: &str, _byte: usize) -> Option<Vec<String>> {
        self.use_bindings
            .get(name)?
            .as_ref()
            .map(|segments| segments.iter().map(|segment| segment.to_string()).collect())
    }
}

fn rust_node_at_range<'tree>(
    tree: &'tree tree_sitter::Tree,
    range: RustSourceRange,
) -> Option<Node<'tree>> {
    let node = tree
        .root_node()
        .named_descendant_for_byte_range(range.start, range.end)?;
    (node.start_byte() == range.start && node.end_byte() == range.end).then_some(node)
}

fn nominal_rust_model_type(symbol: &SemanticModelSymbol) -> bool {
    symbol.owner_id.is_none()
        && symbol.language == Language::Rust.config_label()
        && symbol.externally_visible()
        && !symbol.provenance.ambiguous
        && matches!(
            symbol.kind,
            SemanticModelSymbolKind::Struct
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Union
        )
}

fn unique_rust_model_symbol<'a>(
    overlay: &'a SemanticModelOverlay,
    identity: &str,
) -> Option<&'a SemanticModelSymbol> {
    let symbol = RustOverlayCrates::new(Some(overlay)).referenceable_symbol(identity)?;
    (symbol.owner_id.is_none()
        && symbol.language == Language::Rust.config_label()
        && symbol.externally_visible()
        && !symbol.provenance.ambiguous)
        .then_some(symbol)
}

/// The explicit terminal bindings one top-level `use` clause makes, as
/// `(bound name, qualified segments)` pairs. `None` marks a clause shape this
/// prescan does not model, such as an alias or a wildcard, and no binding may
/// be inferred for it.
type RustUseBinding = (Box<str>, Vec<Box<str>>);

fn rust_use_clause_bindings(clause: Node<'_>, source: &str) -> Option<Vec<RustUseBinding>> {
    match clause.kind() {
        "identifier" => {
            let name = node_text(source, clause)?;
            Some(vec![(name.into(), vec![name.into()])])
        }
        "scoped_identifier" => {
            let segments = rust_use_path_segments(clause, source)?;
            let terminal = segments.last()?.clone();
            Some(vec![(terminal, segments)])
        }
        "scoped_use_list" => {
            let prefix = clause
                .child_by_field_name("path")
                .and_then(|path| rust_use_path_segments(path, source))
                .unwrap_or_default();
            let list = clause.child_by_field_name("list")?;
            rust_use_list_bindings(list, prefix, source)
        }
        "use_list" => rust_use_list_bindings(clause, Vec::new(), source),
        _ => None,
    }
}

fn rust_receiver_use_alias_clause_bindings(
    clause: Node<'_>,
    source: &str,
) -> Option<Vec<RustUseBinding>> {
    let mut pending = vec![(clause, Vec::<Box<str>>::new())];
    let mut bindings = Vec::new();
    while let Some((node, prefix)) = pending.pop() {
        match node.kind() {
            "use_as_clause" => {
                let mut path = prefix;
                path.extend(rust_use_path_segments(
                    node.child_by_field_name("path")?,
                    source,
                )?);
                let alias = node_text(source, node.child_by_field_name("alias")?)?;
                if alias != "_" {
                    bindings.push((alias.into(), path));
                }
            }
            "scoped_use_list" => {
                let mut nested_prefix = prefix;
                if let Some(path) = node.child_by_field_name("path") {
                    nested_prefix.extend(rust_use_path_segments(path, source)?);
                }
                pending.push((node.child_by_field_name("list")?, nested_prefix));
            }
            "use_list" => {
                for child in named_children(node).into_iter().rev() {
                    pending.push((child, prefix.clone()));
                }
            }
            "identifier" => {
                let name: Box<str> = node_text(source, node)?.into();
                let mut path = prefix;
                path.push(name.clone());
                bindings.push((name, path));
            }
            "scoped_identifier" => {
                let mut path = prefix;
                path.extend(rust_use_path_segments(node, source)?);
                let terminal = path.last()?.clone();
                bindings.push((terminal, path));
            }
            "self" => {}
            _ => return None,
        }
    }
    Some(bindings)
}

fn record_rust_use_binding(
    bindings: &mut HashMap<Box<str>, Option<Vec<Box<str>>>>,
    terminal: Box<str>,
    segments: Vec<Box<str>>,
) {
    match bindings.entry(terminal) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(Some(segments));
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            if entry.get().as_deref() != Some(segments.as_slice()) {
                entry.insert(None);
            }
        }
    }
}

fn rust_use_list_bindings(
    list: Node<'_>,
    prefix: Vec<Box<str>>,
    source: &str,
) -> Option<Vec<RustUseBinding>> {
    let mut bindings = Vec::new();
    for child in named_children(list) {
        match child.kind() {
            "identifier" => {
                let name = node_text(source, child)?;
                let mut segments = prefix.clone();
                segments.push(name.into());
                bindings.push((name.into(), segments));
            }
            // `use a::{self}` binds the module itself, not a type this
            // consumer models.
            "self" => {}
            "scoped_identifier" => {
                let segments = rust_use_path_segments(child, source)?;
                let terminal = segments.last()?.clone();
                bindings.push((terminal, segments));
            }
            "scoped_use_list" => {
                let mut nested_prefix = prefix.clone();
                nested_prefix.extend(rust_use_path_segments(
                    child.child_by_field_name("path")?,
                    source,
                )?);
                bindings.extend(rust_use_list_bindings(
                    child.child_by_field_name("list")?,
                    nested_prefix,
                    source,
                )?);
            }
            "use_list" => {
                bindings.extend(rust_use_list_bindings(child, prefix.clone(), source)?);
            }
            _ => return None,
        }
    }
    Some(bindings)
}

fn rust_use_path_segments(node: Node<'_>, source: &str) -> Option<Vec<Box<str>>> {
    if !matches!(
        node.kind(),
        "identifier" | "crate" | "self" | "super" | "scoped_identifier"
    ) {
        return None;
    }
    let segments = brokk_bifrost_rust::graph_support::rust_path_segments(node)?;
    if brokk_bifrost_rust::graph_support::rust_path_is_leading_absolute(node)
        || segments
            .iter()
            .any(|segment| !matches!(segment.kind(), "identifier" | "crate" | "self" | "super"))
    {
        return None;
    }
    segments
        .into_iter()
        .map(|segment| {
            Some(
                source
                    .get(segment.start_byte()..segment.end_byte())?
                    .trim()
                    .to_string()
                    .into_boxed_str(),
            )
        })
        .collect()
}

/// Whether iterating this expression yields elements that own no `Drop`.
///
/// A range is the case that decides: `Range<T>` implements `Iterator` only for
/// `T: Step`, and every `Step` type is a `Copy` primitive (an integer or
/// `char`). Iterating any other expression yields elements of a type this
/// adapter cannot see, so it answers `false`.
fn rust_iteration_element_is_definitely_non_dropping(iterable: Node<'_>) -> bool {
    iterable.kind() == "range_expression"
}

/// The outcome a literal branch condition fixes, when it is literal.
///
/// `if true` and `if false` -- and the same wrapped in parentheses -- decide
/// their branch at compile time.
fn rust_constant_condition(condition: Node<'_>) -> Option<bool> {
    let mut cursor = condition;
    loop {
        match cursor.kind() {
            "true" | "false" => {
                return brokk_bifrost_core::analyzer::structural::adapter_helpers::boolean_literal_value(
                    cursor.kind(),
                );
            }
            // `boolean_literal` wraps the `true`/`false` keyword, which the
            // grammar spells as an anonymous token.
            "boolean_literal" => cursor = cursor.child(0)?,
            "parenthesized_expression" => cursor = first_named_child(cursor)?,
            _ => return None,
        }
    }
}

/// Whether iterating this expression provably yields at least one element.
///
/// Only a literal integer range answers `true`: `0..3` has three elements and
/// `0..=3` has four, both known from the two literal bounds and the range
/// operator. A suffixed or separated literal (`3u32`, `1_000`) does not parse
/// here and answers `false`, which only keeps a zero-iteration path the loop
/// may not have.
fn rust_iteration_yields_an_element(iterable: Node<'_>, source: &str) -> bool {
    if iterable.kind() != "range_expression" || iterable.child_count() != 3 {
        return false;
    }
    let literal = |index: usize| {
        iterable
            .child(index)
            .filter(|node| node.kind() == "integer_literal")
            .and_then(|node| node_text(source, node))
            .and_then(|text| text.parse::<i128>().ok())
    };
    let (Some(start), Some(end)) = (literal(0), literal(2)) else {
        return false;
    };
    match iterable.child(1).map(|operator| operator.kind()) {
        Some("..") => start < end,
        Some("..=") => start <= end,
        _ => false,
    }
}

/// Whether this operator can abort the procedure.
///
/// Rust arithmetic aborts on overflow in a debug profile and on division by
/// zero in every profile; a shift aborts when the amount exceeds the operand
/// width; a dereference aborts on an invalid pointer. Comparison, boolean,
/// bitwise, and negation-free operators cannot. The operator is read from the
/// node, not matched against source text.
fn rust_operation_can_abort(node: Node<'_>) -> bool {
    match node.kind() {
        "binary_expression" => node
            .child_by_field_name("operator")
            .is_some_and(|operator| {
                matches!(operator.kind(), "+" | "-" | "*" | "/" | "%" | "<<" | ">>")
            }),
        // `unary_expression` spells its operator as an anonymous first child.
        "unary_expression" => {
            let operator = node.child(0).map(|operator| operator.kind());
            match operator {
                Some("-")
                    if node
                        .named_child(0)
                        .is_some_and(|operand| operand.kind() == "integer_literal") =>
                {
                    false
                }
                Some("-" | "*") => true,
                _ => false,
            }
        }
        "compound_assignment_expr" => {
            node.child_by_field_name("operator")
                .is_some_and(|operator| {
                    matches!(
                        operator.kind(),
                        "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>="
                    )
                })
        }
        // Indexing aborts on an out-of-range index, and a field projection
        // reaches its field through an autoderef chain whose `Deref`
        // implementation this adapter has not resolved and cannot rule out.
        "index_expression" | "field_expression" => true,
        _ => false,
    }
}

/// The non-negative magnitude of one tree-sitter-classified Rust integer
/// literal. Rust permits decimal, binary, octal, and hexadecimal forms,
/// optional `_` separators, and an optional integer type suffix. Decoding the
/// token payload canonicalizes equivalent spellings without interpreting any
/// surrounding source or macro text.
fn rust_integer_literal_value(source: &str, node: Node<'_>) -> Option<u128> {
    rust_integer_literal_parts(source, node).map(|(value, _)| value)
}

/// Canonical member identity read from a tree-sitter `field_expression`'s
/// `field` child. The AST classifies named members and tuple indices, so this
/// does not need a declaration lookup or source-text search.
fn rust_field_member_key(source: &str, field: Node<'_>) -> Option<String> {
    match field.kind() {
        "field_identifier" | "identifier" => {
            let name = node_text(source, field)?;
            Some(format!("named:{}", name.strip_prefix("r#").unwrap_or(name)))
        }
        "integer_literal" => {
            rust_integer_literal_value(source, field).map(|index| format!("tuple:{index}"))
        }
        _ => None,
    }
}

fn rust_integer_constant_value(source: &str, node: Node<'_>) -> Option<u128> {
    let mut cursor = unwrap_attributes(node);
    loop {
        match cursor.kind() {
            "parenthesized_expression" => {
                cursor = first_named_child(cursor)?;
            }
            "integer_literal" => return rust_integer_literal_value(source, cursor),
            _ => return None,
        }
    }
}

/// Retain the token's type suffix when a consumer must check a contextual
/// requirement, such as the `usize` type of an array length.
pub(crate) fn rust_integer_literal_parts<'source>(
    source: &'source str,
    node: Node<'_>,
) -> Option<(u128, &'source str)> {
    if node.kind() != "integer_literal" {
        return None;
    }
    let text = node_text(source, node)?;
    let bytes = text.as_bytes();
    let (radix, start) = if bytes.starts_with(b"0b") {
        (2, 2)
    } else if bytes.starts_with(b"0o") {
        (8, 2)
    } else if bytes.starts_with(b"0x") {
        (16, 2)
    } else {
        (10, 0)
    };
    let mut offset = start;
    let mut digits = 0;
    let mut value = 0u128;
    while let Some(byte) = bytes.get(offset).copied() {
        if byte == b'_' {
            offset += 1;
            continue;
        }
        let Some(digit) = char::from(byte).to_digit(radix) else {
            break;
        };
        value = value
            .checked_mul(u128::from(radix))?
            .checked_add(u128::from(digit))?;
        digits += 1;
        offset += 1;
    }
    if digits == 0 {
        return None;
    }
    let suffix = text.get(offset..)?;
    if !matches!(
        suffix,
        "" | "u8"
            | "i8"
            | "u16"
            | "i16"
            | "u32"
            | "i32"
            | "u64"
            | "i64"
            | "u128"
            | "i128"
            | "isize"
            | "usize"
    ) {
        return None;
    }
    Some((value, suffix))
}

/// The runtime initializer expression(s) represented by a Rust array
/// expression. A named `length` field is the grammar's repeat-array form,
/// `[value; length]`; it has one initializer rather than a list of elements.
fn rust_array_initializer_elements(node: Node<'_>) -> Vec<Node<'_>> {
    debug_assert_eq!(node.kind(), "array_expression");
    let length = node.child_by_field_name("length");
    named_children(node)
        .into_iter()
        .filter(|child| !is_compile_time_syntax(child.kind()))
        .filter(|child| length.is_none_or(|length| child.id() != length.id()))
        .collect()
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    let node = unwrap_attributes(node);
    match node.kind() {
        "binary_expression" | "assignment_expression" | "compound_assignment_expr" => [
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ]
        .into_iter()
        .flatten()
        .map(unwrap_attributes)
        .collect(),
        "field_expression" | "reference_expression" | "type_cast_expression" => node
            .child_by_field_name("value")
            .into_iter()
            .map(unwrap_attributes)
            .collect(),
        "let_condition" => node
            .child_by_field_name("value")
            .into_iter()
            .map(unwrap_attributes)
            .collect(),
        "unary_expression"
        | "parenthesized_expression"
        | "await_expression"
        | "try_expression"
        | "yield_expression"
        | "return_expression" => first_named_child(node)
            .into_iter()
            .map(unwrap_attributes)
            .collect(),
        "generic_function" => node
            .child_by_field_name("function")
            .into_iter()
            .map(unwrap_attributes)
            .collect(),
        "struct_expression" => node
            .child_by_field_name("body")
            .map(runtime_expression_children)
            .unwrap_or_default(),
        "field_initializer" => node
            .child_by_field_name("value")
            .into_iter()
            .map(unwrap_attributes)
            .collect(),
        "base_field_initializer" => first_named_child(node)
            .into_iter()
            .map(unwrap_attributes)
            .collect(),
        "index_expression"
        | "array_expression"
        | "tuple_expression"
        | "range_expression"
        | "field_initializer_list"
        | "let_chain"
        | "arguments" => named_children(node)
            .into_iter()
            .filter(|child| !is_compile_time_syntax(child.kind()))
            .collect(),
        _ => Vec::new(),
    }
}

fn execution_node(node: Node<'_>) -> Node<'_> {
    let node = unwrap_attributes(node);
    if node.kind() == "expression_statement" {
        first_named_child(node)
            .filter(|expression| {
                !matches!(
                    expression.kind(),
                    "return_expression" | "break_expression" | "continue_expression"
                )
            })
            .unwrap_or(node)
    } else {
        node
    }
}

fn block_tail_expression(block: Node<'_>) -> Option<Node<'_>> {
    let tail = named_children(block)
        .into_iter()
        .rfind(|child| child.kind() != "label")?;
    if tail.kind() == "expression_statement" {
        if direct_child_kind(tail, ";") {
            None
        } else {
            first_named_child(tail).filter(|expression| is_rust_expression(expression.kind()))
        }
    } else {
        is_rust_expression(tail.kind()).then_some(tail)
    }
}

fn rust_transparent_value_leaf(mut node: Node<'_>) -> Option<Node<'_>> {
    let original = node.id();
    loop {
        node = unwrap_attributes(node);
        match node.kind() {
            "parenthesized_expression" => node = first_named_child(node)?,
            "unsafe_block" => node = first_named_child(node)?,
            "block" => node = block_tail_expression(node)?,
            _ => return (node.id() != original).then_some(node),
        }
    }
}

fn rust_boolean_operator(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" => Some("&&"),
        "||" => Some("||"),
        _ => None,
    }
}

fn control_label(node: Node<'_>, source: &str) -> Option<Box<str>> {
    direct_named_child_kind(node, "label")
        .and_then(|label| node_text(source, label))
        .map(Box::<str>::from)
}

use brokk_bifrost_core::analyzer::tree_walk::{
    first_named_child_of_kind as direct_named_child_kind, has_child_of_kind as direct_child_kind,
};

fn condition_introduces_pattern_bindings(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "let_condition" {
            return true;
        }
        if current.id() != node.id()
            && matches!(
                current.kind(),
                "function_item" | "closure_expression" | "async_block" | "gen_block"
            )
        {
            continue;
        }
        stack.extend(named_children(current));
    }
    false
}

/// Procedure syntax roles for the Rust lowering. A block's statements and
/// its trailing expression are statements; items declare and do not run.
/// `loop` is an unconditional loop and `while`/`while let` are conditional;
/// `for` iterates and is not assessed.
pub(crate) const PROCEDURE_SYNTAX_ROLES:
    brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles =
    brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles {
        statement_kind: rust_statement_kind,
        loop_site: |node| {
            use brokk_bifrost_analysis::analyzer::loop_facts::LoopKind;

            use brokk_bifrost_analysis::analyzer::loop_facts::LoopSyntax;
            match node.kind() {
                "loop_expression" => Some(LoopSyntax {
                    kind: LoopKind::For,
                    body: node.child_by_field_name("body"),
                    condition: None,
                }),
                "while_expression" => Some(LoopSyntax {
                    kind: LoopKind::While,
                    body: node.child_by_field_name("body"),
                    condition: node.child_by_field_name("condition"),
                }),
                _ => None,
            }
        },
        loop_site_with_source: None,
        procedure_matches: |_, node| {
            matches!(
                node.kind(),
                "function_item" | "closure_expression" | "async_block" | "gen_block"
            )
        },
        nested_procedure: |node| {
            matches!(
                node.kind(),
                "function_item"
                    | "closure_expression"
                    | "async_block"
                    | "gen_block"
                    | "impl_item"
                    | "trait_item"
                    | "mod_item"
                    | "const_item"
                    | "static_item"
                    | "macro_definition"
            )
        },
    };

fn rust_statement_kind(node: Node<'_>) -> Option<&'static str> {
    if !node.parent().is_some_and(|parent| parent.kind() == "block") {
        return None;
    }
    Some(match node.kind() {
        "expression_statement" => "expression",
        "let_declaration" => "local_declaration",
        "empty_statement" => "empty",
        "block" => "block",
        kind if is_rust_expression(kind) => "expression",
        _ => return None,
    })
}

fn is_rust_expression(kind: &str) -> bool {
    is_runtime_leaf(kind)
        || is_runtime_container(kind)
        || matches!(
            kind,
            "call_expression"
                | "closure_expression"
                | "async_block"
                | "gen_block"
                | "if_expression"
                | "match_expression"
                | "loop_expression"
                | "while_expression"
                | "for_expression"
                | "break_expression"
                | "continue_expression"
                | "return_expression"
                | "try_expression"
                | "try_block"
                | "await_expression"
                | "yield_expression"
                | "macro_invocation"
                | "block"
                | "unsafe_block"
                | "const_block"
                | "let_condition"
                | "let_chain"
                | "generic_function"
        )
}

fn is_runtime_container(kind: &str) -> bool {
    matches!(
        kind,
        "binary_expression"
            | "assignment_expression"
            | "compound_assignment_expr"
            | "field_expression"
            | "index_expression"
            | "array_expression"
            | "tuple_expression"
            | "range_expression"
            | "reference_expression"
            | "unary_expression"
            | "parenthesized_expression"
            | "type_cast_expression"
            | "struct_expression"
            | "field_initializer_list"
            | "field_initializer"
            | "shorthand_field_initializer"
            | "base_field_initializer"
            | "arguments"
    )
}

fn implicit_runtime_call_reason(kind: &str) -> Option<&'static str> {
    match kind {
        "binary_expression" => Some(
            "operator traits and comparison traits may be invoked implicitly; no fabricated trait call site is emitted",
        ),
        "assignment_expression" => Some(
            "assignment place evaluation may invoke DerefMut or IndexMut and replacing the old value may invoke Drop::drop; no fabricated call sites are emitted",
        ),
        "compound_assignment_expr" => Some(
            "compound assignment may invoke an operator-assignment trait; no fabricated call sites are emitted",
        ),
        "field_expression" => Some(
            "field projection may require implicit autoderef operations that are not emitted as call sites",
        ),
        "index_expression" => Some(
            "indexing may invoke Index or IndexMut implicitly; no fabricated trait call site is emitted",
        ),
        "unary_expression" => Some(
            "unary operators and dereference may invoke operator or Deref traits that are not emitted as call sites",
        ),
        _ => None,
    }
}

fn is_runtime_leaf(kind: &str) -> bool {
    kind.ends_with("_literal")
        || matches!(
            kind,
            "identifier"
                | "scoped_identifier"
                | "field_identifier"
                | "self"
                | "super"
                | "crate"
                | "metavariable"
                | "unit_expression"
                | "true"
                | "false"
        )
}

fn is_compile_time_syntax(kind: &str) -> bool {
    // Rust casts evaluate at runtime despite the type-related node prefix.
    if kind == "type_cast_expression" {
        return false;
    }
    kind.starts_with("type_")
        || kind.ends_with("_type")
        || matches!(
            kind,
            "type_identifier"
                | "scoped_type_identifier"
                | "generic_type"
                | "generic_type_with_turbofish"
                | "type_arguments"
                | "type_parameters"
                | "where_clause"
                | "attribute_item"
                | "inner_attribute_item"
                | "attributes"
                | "visibility_modifier"
        )
}

pub(crate) fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !is_comment_kind(child.kind()))
        .filter(|child| child.kind() != "attributes")
        .map(unwrap_attributes)
        .collect()
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !is_comment_kind(child.kind()) && child.kind() != "attributes")
        .map(unwrap_attributes)
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, RustLoweringError> {
    brokk_bifrost_semantic::analyzer::semantic::lowering::required_field_or_else(
        node,
        field,
        missing_field,
    )
    .map(unwrap_attributes)
}

#[cfg(test)]
mod semantic_lowering_tests {
    use std::sync::Arc;

    use crate::analyzer::rust::semantic::*;

    use brokk_bifrost_core::analyzer::model::LanguageDialect;

    use brokk_bifrost_semantic::analyzer::semantic::service::ProgramSemanticsLowerer;

    use brokk_bifrost_semantic::analyzer::semantic::service::semantic_artifact_key_from_content;

    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSourceOrigin;

    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource;

    use brokk_bifrost_core::text_utils::compute_line_starts;

    fn lower_fixture(source: &str) -> Vec<ProcedureSemanticsParts> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar is valid");
        let tree = parser.parse(source, None).expect("fixture parses");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::<str>::from(source)),
            tree,
            compute_line_starts(source),
            LanguageDialect::Standard(Language::Rust),
            PreparedSourceOrigin::Disk,
            None,
        );
        let lowerer = RustSemanticLowerer;
        let file = ProjectFile::new(std::env::temp_dir(), "capture.rs");
        let SemanticOutcome::Complete { value, .. } = lowerer
            .lower(
                &file,
                &prepared,
                &SemanticBudget::default(),
                &CancellationToken::default(),
            )
            .expect("Rust lowering succeeds")
        else {
            panic!("fixture lowering must complete");
        };
        value
    }

    #[test]
    fn rust_exceptional_exit_discharge_corpus() {
        // Keep this public unit test self-contained: the private root golden
        // Rust sources are absent from the projected public workspace, so
        // the corpus is inline.
        let corpus = [
            ("conditional", "fn choose(ready: bool) -> u8 { if ready { 3 } else { 4 } }"),
            (
                "inherent-and-trait-methods",
                "struct Panel;
             trait Draw { fn draw(&self, scale: u32) -> u32; }
             impl Panel { fn draw(&self) -> u32 { 7 } }
             impl Draw for Panel { fn draw(&self, scale: u32) -> u32 { scale } }
             fn paint(panel: &Panel) -> u32 { panel.draw() }",
            ),
            (
                "loops",
                "struct Batch { items: Vec<u32> }
             fn sort_outer(mut pending: Vec<u32>, rounds: Vec<Vec<u32>>) -> usize {
                 let mut count = 0;
                 for round in rounds { pending.sort(); count += round.len(); }
                 count
             }
             fn sort_local(rounds: Vec<Vec<u32>>) -> usize {
                 let mut count = 0;
                 for round in rounds { let mut local = round; local.sort(); count += local.len(); }
                 count
             }
             fn sort_collected(rounds: Vec<Vec<u32>>) -> usize {
                 let mut count = 0;
                 for round in rounds {
                     let mut copy = round.iter().copied().collect::<Vec<u32>>();
                     copy.sort();
                     count += copy.len();
                 }
                 count
             }
             fn sort_field(batches: Vec<Batch>) -> usize {
                 let mut count = 0;
                 for mut batch in batches { batch.items.sort(); count += batch.items.len(); }
                 count
             }
             fn sort_shadowed(mut pending: Vec<u32>, rounds: Vec<Vec<u32>>) -> usize {
                 let mut count = 0;
                 for round in rounds {
                     pending.sort();
                     { let mut pending = Vec::new(); pending = round; count += pending.len(); }
                 }
                 count
             }
             fn sort_in_closure(mut pending: Vec<u32>, times: usize) -> usize {
                 let mut count = 0;
                 for _ in 0..times { let mut run = || pending.sort(); run(); count += 1; }
                 count
             }
             fn sort_reassigned(mut pending: Vec<u32>, rounds: Vec<Vec<u32>>) -> usize {
                 let mut count = 0;
                 for round in rounds { pending = round; pending.sort(); count += pending.len(); }
                 count
             }
             fn sort_after_seed(mut pending: Vec<u32>, seed: Vec<u32>, rounds: Vec<Vec<u32>>) -> usize {
                 let mut count = 0;
                 pending = seed;
                 for round in rounds { pending.sort(); count += pending.len() + round.len(); }
                 count
             }
             fn sort_pushing(mut pending: Vec<u32>, rounds: Vec<Vec<u32>>) -> usize {
                 let mut lens = Vec::new();
                 for round in rounds { pending.sort(); lens.push(pending.len() + round.len()); }
                 lens.len()
             }
             fn sort_tracking_last(mut pending: Vec<u32>, rounds: Vec<Vec<u32>>) -> usize {
                 let mut lens = Vec::new();
                 let mut last = 0;
                 for round in rounds { pending.sort(); last = round.len(); lens.push(pending.len() + last); }
                 lens.len()
             }",
            ),
            (
                "drop-guard-early-return",
                "struct Lock;
             impl Drop for Lock { fn drop(&mut self) {} }
             fn guarded(stop: bool) -> u8 {
                 let _held = Lock;
                 if stop { return 5; }
                 6
             }",
            ),
        ];
        let corpus = corpus
            .into_iter()
            .map(|(path, source)| (path, String::from(source)))
            .chain(std::iter::once((
                "exit-shapes",
                String::from(
                    "async fn polling(f: impl Future<Output = ()>) { f.await; }
             fn opaque() { unknown!(); }
             fn index(mut xs: [u8; 2], i: usize) { let y = xs[i]; xs[i] = y; }
             fn field(x: Unknown) { consume(x.a); }
             fn temporary() { consume(make() + make()); }
             fn residual() { let _ = try { step()? }; }
             fn reference_patterns(mut root: (u8, u8)) {
                 let (ref left, ref mut right) = root; consume(left); consume(right);
                 match root { (ref a, ref mut b) => { consume(a); consume(b); } }
             }",
                ),
            )));
        let mut checked = 0;
        for (path, source) in corpus {
            let procedures = lower_fixture(&source);
            for procedure in &procedures {
                for gap in &procedure.gaps {
                    if gap.capability != SemanticCapability::ExceptionalControlFlow
                        || gap.detail.as_ref()
                            == "panic and residual behavior inside the unsupported try block are not lowered"
                    {
                        continue;
                    }
                    checked += 1;
                    assert!(
                        matches!(
                            gap.discharge,
                            SemanticGapDischarge::NonRejoiningExceptionalExit
                                | SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
                                | SemanticGapDischarge::ExitOnlyProcedureCompletion
                        ),
                        "{path}: {gap:?}"
                    );
                }
            }
            assert_artifact_builds(procedures, &source);
        }
        assert!(checked > 0, "corpus must exercise exceptional gaps");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5522: numeric Rust tuple-field calls were lowered as bound methods on the tuple base"
    )]
    fn rust_callable_tuple_fields_load_as_values_without_method_receivers() {
        const SOURCE: &str = concat!(
            "type Callable = fn(i32);\n",
            "struct TupleHolder(Callable, (Callable, Callable));\n",
            "struct Holder { callback: Callable, method: Callable }\n",
            "impl Holder {\n",
            "    fn callback(&self, _: i32) {}\n",
            "    fn method<T>(&self, _: T) {}\n",
            "}\n",
            "impl TupleHolder {\n",
            "    fn run(&self, holder: &Holder) {\n",
            "    self.0(1);\n",
            "    self.1.0(2);\n",
            "    (self.0)(3);\n",
            "    holder.callback(4);\n",
            "    (holder.callback)(5);\n",
            "    holder.method::<i32>(6);\n",
            "    }\n",
            "}\n",
        );
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.locator.declaration().last_segment_name() == Some("run"))
            .expect("tuple-struct run procedure");
        let text_for_mapping = |mapping_id| {
            let mapping = procedure
                .source_mappings
                .iter()
                .find(|mapping| mapping.id == mapping_id)
                .expect("source mapping");
            let span = mapping.locator.anchor().span();
            &SOURCE[span.start_byte() as usize..span.end_byte() as usize]
        };
        let expected = [
            ("self.0(1)", "self.0", false),
            ("self.1.0(2)", "self.1.0", false),
            ("(self.0)(3)", "(self.0)", false),
            ("holder.callback(4)", "callback", true),
            ("(holder.callback)(5)", "(holder.callback)", false),
            ("holder.method::<i32>(6)", "method", true),
        ];
        assert_eq!(procedure.call_sites.len(), expected.len());
        for (call_site, (call_text, callee_text, has_receiver)) in
            procedure.call_sites.iter().zip(expected)
        {
            assert_eq!(text_for_mapping(call_site.source), call_text);
            let callee = procedure
                .values
                .iter()
                .find(|value| value.id == call_site.callee)
                .expect("callable value");
            assert_eq!(text_for_mapping(callee.source), callee_text);
            assert_eq!(call_site.receiver.is_some(), has_receiver, "{call_text}");
            let callable = procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .find_map(|event| match &event.effect {
                    SemanticEffect::CallableReference { result, callable }
                        if *result == call_site.callee =>
                    {
                        Some(callable)
                    }
                    _ => None,
                })
                .expect("callable reference effect");
            assert_eq!(
                callable.kind,
                if has_receiver {
                    CallableReferenceKind::BoundMethod
                } else {
                    CallableReferenceKind::Function
                },
                "{call_text}"
            );
            assert_eq!(callable.bound_receiver, call_site.receiver, "{call_text}");
        }
        for field in ["self.0", "self.1.0"] {
            assert!(
                procedure
                    .points
                    .iter()
                    .flat_map(|point| &point.events)
                    .any(|event| match &event.effect {
                        SemanticEffect::MemoryLoad {
                            kind: MemoryAccessKind::Field,
                            result,
                            ..
                        } => procedure
                            .values
                            .iter()
                            .find(|value| value.id == *result)
                            .is_some_and(|value| text_for_mapping(value.source) == field),
                        _ => false,
                    }),
                "computed tuple field `{field}` is loaded as a callable value"
            );
        }
        assert_artifact_builds(procedures, SOURCE);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4975+#5911: Copy structs and tuple components must not invent destructor omissions"
    )]
    fn rust_copy_destructor_gaps_ignore_unsafe_mentions_but_keep_unknown_and_macros() {
        // Qualify the same-file type so the separate bare-name plain-struct
        // proof does not hide the ownership classifier's unsafe-context gate.
        let source = r#"
#[derive(core::marker::Copy, core::clone::Clone)]
struct Pair(u32);
fn safe_copy(value: crate::Pair) {}
unsafe fn unsafe_copy(value: crate::Pair) {}
unsafe fn unknown(value: Missing) {}
unsafe fn macro_copy(value: crate::Pair) { opaque!(value); }
"#;
        let procedures = lower_fixture(source);
        assert_eq!(procedures.len(), 4);
        for (procedure, (name, expected_drop_gaps)) in procedures.iter().zip([
            ("safe_copy", 0),
            ("unsafe_copy", 0),
            ("unknown", 8),
            ("macro_copy", 0),
        ]) {
            let drop_gaps = procedure
                .gaps
                .iter()
                .filter(|gap| {
                    gap.detail.starts_with("scope exit crosses a destructor")
                        || gap
                            .detail
                            .starts_with("procedure exit crosses a destructor")
                })
                .count();
            assert_eq!(
                drop_gaps, expected_drop_gaps,
                "{name}: {:#?}",
                procedure.gaps
            );
            if name == "macro_copy" {
                assert!(
                    procedure.gaps.iter().any(|gap| {
                        gap.kind == SemanticGapKind::Unknown
                            && gap.capability == SemanticCapability::Calls
                    }),
                    "macro expansion must still carry uncertainty"
                );
            }
        }
        // Keep the ownership fixture separate from the earlier macro/unsafe
        // controls: this observes component effects, not a spelling waiver.
        const TUPLES: &str = r#"
type Pair = (usize, usize);
type SizeHint = (usize, Option<usize>);
fn tuple_parameter(sh: Pair) -> usize {
    let (mut low, hi) = sh;
    low = low;
    low
}
fn tuple_option(sh: SizeHint) -> usize {
    let (mut low, hi) = sh;
    low = low;
    low
}
fn tuple_literal(a: usize, b: usize) -> usize {
    let (mut a, b) = (b, a);
    a = a;
    a
}
fn tuple_unknown<T>(sh: (usize, T)) -> usize {
    let (mut low, hi) = sh;
    low = low;
    low
}
"#;
        let tuples = lower_fixture(TUPLES);
        assert_eq!(tuples.len(), 4);
        for name in [
            "tuple_parameter",
            "tuple_option",
            "tuple_literal",
            "tuple_unknown",
        ] {
            let procedure = tuples
                .iter()
                .find(|procedure| procedure.locator.declaration().last_segment_name() == Some(name))
                .expect("tuple procedure");
            let text = |mapping: SourceMappingId| {
                let span = procedure.source_mappings[mapping.index()]
                    .locator
                    .anchor()
                    .span();
                &TUPLES[span.start_byte() as usize..span.end_byte() as usize]
            };
            if name == "tuple_unknown" {
                assert!(
                    procedure
                        .gaps
                        .iter()
                        .any(|gap| gap.capability == SemanticCapability::Values
                            && matches!(gap.subject, SemanticGapSubject::Value(_))
                            && gap.impacts.contains(SemanticGapImpact::ValueFlow)),
                    "unknown sibling ownership cannot become initialized: {:#?}",
                    procedure.gaps
                );
                assert!(
                    !procedure
                        .points
                        .iter()
                        .flat_map(|point| &point.events)
                        .any(|event| matches!(
                            event.effect,
                            SemanticEffect::MemoryLoad {
                                kind: MemoryAccessKind::Field,
                                ..
                            }
                        )),
                    "a refused plan publishes no tuple projections"
                );
                continue;
            }
            assert!(
                !procedure.gaps.iter().any(|gap| matches!(
                    gap.capability,
                    SemanticCapability::LocalFlow
                        | SemanticCapability::Values
                        | SemanticCapability::CleanupControlFlow
                        | SemanticCapability::ResourceManagement
                )),
                "proved component Copy must precede cleanup registration: {name}: {:#?}",
                procedure.gaps
            );
            assert!(procedure.drops.is_empty(), "{name}: {:#?}", procedure.drops);
            assert!(
                procedure.move_outs.is_empty(),
                "Copy must not consume the aggregate: {name}: {:#?}",
                procedure.move_outs
            );
            let mut current = procedure
                .points
                .iter()
                .find(|point| {
                    point
                        .events
                        .iter()
                        .any(|event| matches!(event.effect, SemanticEffect::Entry))
                })
                .expect("entry")
                .id;
            let mut visited = HashSet::default();
            let mut ordered = Vec::new();
            loop {
                assert!(
                    visited.insert(current),
                    "straight-line tuple fixture must not cycle"
                );
                ordered.extend(procedure.points[current.index()].events.iter());
                let successors = procedure
                    .control_edges
                    .iter()
                    .filter(|edge| {
                        edge.source_point == current && edge.kind == ControlEdgeKind::Normal
                    })
                    .collect::<Vec<_>>();
                match successors.as_slice() {
                    [] => break,
                    [edge] => current = edge.target_point,
                    _ => panic!("tuple fixture has one normal continuation: {successors:?}"),
                }
            }
            let local = |name: &str| {
                procedure
                    .values
                    .iter()
                    .find(|value| {
                        matches!(value.kind, SemanticValueKind::Local) && text(value.source) == name
                    })
                    .expect("tuple local")
                    .id
            };
            if name == "tuple_literal" {
                let parameter = |ordinal| {
                    procedure.values.iter().find(|value|
                    matches!(value.kind, SemanticValueKind::Parameter {ordinal: actual, ..} if actual == ordinal))
                    .expect("literal source parameter").id
                };
                let mut reads = Vec::new();
                let mut writes = Vec::new();
                for (target, source, expected) in [
                    (local("a"), parameter(1), "b"),
                    (local("b"), parameter(0), "a"),
                ] {
                    let (write, value) = ordered
                        .iter()
                        .enumerate()
                        .find_map(|(index, event)| match event.effect {
                            SemanticEffect::Assignment {
                                target: actual,
                                value,
                            } if actual == target => Some((index, value)),
                            _ => None,
                        })
                        .expect("literal component establishment");
                    assert_eq!(text(procedure.values[value.index()].source), expected);
                    let read = ordered.iter().position(|event| matches!(event.effect,
                        SemanticEffect::ValueFlow {source: actual, target, ..} if actual == source && target == value))
                        .expect("captured parameter read");
                    reads.push(read);
                    writes.push(write);
                }
                assert!(
                    reads[0] < reads[1] && reads[1] < writes[0] && writes[0] < writes[1],
                    "all captured RHS reads precede ordered binding writes: {reads:?}, {writes:?}"
                );
            } else {
                let loads = ordered
                    .iter()
                    .enumerate()
                    .filter_map(|(index, event)| match event.effect {
                        SemanticEffect::MemoryLoad {
                            kind: MemoryAccessKind::Field,
                            location,
                            result,
                        } => Some((index, location, result)),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    loads.len(),
                    2,
                    "both real components are projected: {name}: {loads:?}"
                );
                assert_ne!(
                    loads[0].2, loads[1].2,
                    "sibling projections have distinct values"
                );
                let mut writes = Vec::new();
                for (ordinal, target_name) in ["low", "hi"].into_iter().enumerate() {
                    let (_, location, result) = loads[ordinal];
                    let MemoryLocationKind::Field { base, member } =
                        &procedure.memory_locations[location.index()].kind
                    else {
                        panic!("tuple projection is a field");
                    };
                    let expected_member = format!("rust-field:tuple:{ordinal}");
                    assert_eq!(
                        member.declaration().last_segment_name(),
                        Some(expected_member.as_str())
                    );
                    assert_eq!(text(procedure.values[base.index()].source), "sh");
                    let target = local(target_name);
                    let write = ordered.iter().position(|event| matches!(event.effect,
                        SemanticEffect::Assignment {target: actual, value} if actual == target && value == result))
                        .expect("component establishment uses its projected value");
                    let expected = if name == "tuple_option" && ordinal == 1 {
                        TransferKind::AggregateCopy
                    } else {
                        TransferKind::Copy
                    };
                    assert!(
                        matches!(ordered[write+1].effect, SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Transfer(ValueTransfer {kind, operation: TransferOperation::None}), source, target: actual,
                    } if kind == expected && source == result && actual == target),
                        "exact component Copy transfer follows its Assignment"
                    );
                    writes.push(write);
                }
                assert!(
                    loads[1].0 < writes[0] && writes[0] < writes[1],
                    "both projections precede ordered leaf establishments: {loads:?}, {writes:?}"
                );
            }
        }
        assert_artifact_builds(tuples, TUPLES);

        // A bare identifier may select an irrefutable constant pattern. The
        // tentative local inventory is not independent proof of a binder.
        const CONSTANT_PATTERN: &str = r#"
const UNIT: () = ();
fn selected(sh: ((), usize)) -> usize {
    let (UNIT, low) = sh;
    low
}
fn variable(sh: ((), usize)) -> usize {
    let (unit, low) = sh;
    low
}
"#;
        let constants = lower_fixture(CONSTANT_PATTERN);
        assert_eq!(constants.len(), 2);
        for name in ["selected", "variable"] {
            let procedure = constants
                .iter()
                .find(|procedure| procedure.locator.declaration().last_segment_name() == Some(name))
                .expect("constant-pattern contrast procedure");
            let text = |mapping: SourceMappingId| {
                let span = procedure.source_mappings[mapping.index()]
                    .locator
                    .anchor()
                    .span();
                &CONSTANT_PATTERN[span.start_byte() as usize..span.end_byte() as usize]
            };
            if name == "selected" {
                assert!(
                    procedure
                        .gaps
                        .iter()
                        .any(|gap| gap.capability == SemanticCapability::Values
                            && matches!(gap.subject, SemanticGapSubject::Value(_))
                            && gap.impacts.contains(SemanticGapImpact::ValueFlow)),
                    "unproved constant-vs-binder ownership must retain the tuple refusal: {:#?}",
                    procedure.gaps
                );
                for event in procedure.points.iter().flat_map(|point| &point.events) {
                    match event.effect {
                        SemanticEffect::Assignment { target, .. }
                        | SemanticEffect::ValueFlow {
                            target,
                            kind:
                                ValueFlowKind::Transfer(ValueTransfer {
                                    kind: TransferKind::Copy | TransferKind::AggregateCopy,
                                    ..
                                }),
                            ..
                        } => {
                            assert_ne!(
                                text(procedure.values[target.index()].source),
                                "UNIT",
                                "a constant pattern cannot acquire a binding establishment or Copy transfer: {event:?}"
                            );
                        }
                        SemanticEffect::MemoryLoad {
                            kind: MemoryAccessKind::Field,
                            ..
                        } => {
                            panic!(
                                "a refused tuple plan publishes no component projection: {event:?}"
                            );
                        }
                        _ => {}
                    }
                }
            } else {
                assert!(
                    !procedure.gaps.iter().any(|gap| matches!(
                        gap.capability,
                        SemanticCapability::LocalFlow
                            | SemanticCapability::Values
                            | SemanticCapability::CleanupControlFlow
                            | SemanticCapability::ResourceManagement
                    )),
                    "the actual unit binder must preserve supported component proof: {:#?}",
                    procedure.gaps
                );
                let unit = procedure
                    .values
                    .iter()
                    .find(|value| {
                        matches!(value.kind, SemanticValueKind::Local)
                            && text(value.source) == "unit"
                    })
                    .expect("actual unit binding")
                    .id;
                let events = procedure
                    .points
                    .iter()
                    .flat_map(|point| &point.events)
                    .collect::<Vec<_>>();
                let sources = events
                    .iter()
                    .filter_map(|event| match event.effect {
                        SemanticEffect::Assignment { target, value } if target == unit => {
                            Some(value)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let [source] = sources.as_slice() else {
                    panic!(
                        "the actual unit binder has exactly one component establishment: {sources:?}"
                    );
                };
                assert!(
                    events.iter().any(|event| matches!(event.effect,
                    SemanticEffect::ValueFlow { source: actual, target,
                        kind: ValueFlowKind::Transfer(ValueTransfer {
                            kind: TransferKind::AggregateCopy, operation: TransferOperation::None,
                        }),
                    } if actual == *source && target == unit)),
                    "the actual unit component retains its proved Copy transfer"
                );
            }
        }
        assert_artifact_builds(constants, CONSTANT_PATTERN);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4913: unknown struct update fields were silently omitted"
    )]
    fn rust_struct_update_unknown_field_set_retains_gap() {
        let procedures = lower_fixture(
            "fn run(base: External) { let updated = External { value: 1, ..base }; }",
        );
        let [procedure] = procedures.as_slice() else {
            panic!("one source procedure is expected");
        };
        assert!(procedure.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::FieldMemory
                && gap.kind == SemanticGapKind::Unknown
                && matches!(gap.subject, SemanticGapSubject::Value(_))
        }));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4848: pointer calls in opaque macro invocations must not become source call facts"
    )]
    fn pointer_calls_inside_macro_invocations_remain_opaque() {
        const SOURCE: &str = r#"
macro_rules! forward { ($($tokens:tt)*) => { $($tokens)* }; }
unsafe fn f(pointer: *const u8) {
    unsafe { core::ptr::read(pointer); }
    forward!(core::ptr::read(pointer));
}
"#;
        let procedures = lower_fixture(SOURCE);
        let [procedure] = procedures.as_slice() else {
            panic!("one source procedure is expected");
        };

        assert_eq!(procedure.call_sites.len(), 2);
        assert!(procedure.call_sites[1].arguments.is_empty());
        assert_eq!(procedure.pointer_accesses.len(), 1);
    }

    #[test]
    fn rust_closures_publish_exact_targets_and_capture_modes() {
        const SOURCE: &str = r#"
fn outer() {
    let (sender, _receiver) = channel();
    let detached = async move { sender.send(()); };
    let span = acquire_span();
    let callback = || inspect(span.id);
    let mut value = 0;
    let mutating = || { value = 1; };
}

fn with_parameters(span: &Span, doc_id: u64) {
    let borrowed_parameter = || inspect(span.owner.id);
    let moved_parameter = move || inspect(doc_id);
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure.locator.anchor().span().start_byte() as usize
                        == SOURCE.find("fn outer").expect("outer function")
            })
            .expect("outer procedure");
        let child_for = |name: &str| {
            procedures.iter().find(|procedure| {
                procedure.lexical_parent == Some(parent.id)
                    && procedure.locator.anchor().span().start_byte() as usize
                        == SOURCE.find(name).expect("fixture name")
            })
        };

        let detached = child_for("async move").expect("async task body");
        let sender_capture = parent
            .captures
            .iter()
            .find(|capture| capture.target == detached.id)
            .expect("captured sender row");
        assert_eq!(sender_capture.mode, CaptureMode::Move);
        let CaptureSource::Value(sender_value) = sender_capture.captured else {
            panic!("the moved sender capture has an exact parent value");
        };
        let sender_source = parent
            .values
            .iter()
            .find(|value| value.id == sender_value)
            .and_then(|value| {
                parent
                    .source_mappings
                    .iter()
                    .find(|mapping| mapping.id == value.source)
            })
            .expect("captured sender value retains its lexical source");
        let sender_span = sender_source.locator.anchor().span();
        assert_eq!(
            &SOURCE[sender_span.start_byte() as usize..sender_span.end_byte() as usize],
            "sender",
            "capture source must identify the destructured sender binding"
        );
        assert!(
            parent
                .points
                .iter()
                .flat_map(|point| &point.events)
                .any(|event| {
                    event.effect
                        == SemanticEffect::CaptureBind {
                            capture: sender_capture.id,
                        }
                })
        );
        assert!(detached.memory_locations.iter().any(|location| {
            location.id == sender_capture.destination
                && matches!(
                    location.kind,
                    MemoryLocationKind::Capture {
                        lexical_parent,
                        binding: Some(_)
                    } if lexical_parent == parent.id
                )
        }));
        assert!(
            detached
                .points
                .iter()
                .flat_map(|point| &point.events)
                .any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::MemoryLoad {
                            kind: MemoryAccessKind::Capture,
                            location,
                            ..
                        } if location == sender_capture.destination
                    )
                })
        );
        let callable_event = parent
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match &event.effect {
                SemanticEffect::CallableCreation { callable, .. }
                    if callable.targets
                        == CallableTargetResolution::Proven(CallableTarget::Local(detached.id)) =>
                {
                    Some(callable)
                }
                _ => None,
            })
            .expect("exact callable target");
        assert!(callable_event.environment.is_some());

        let callback = child_for("|| inspect").expect("borrowed callback");
        assert!(parent.captures.iter().any(|capture| {
            capture.target == callback.id
                && capture.mode == CaptureMode::LanguageDefined("rust_shared_borrow".into())
        }));

        let mutating = child_for("|| { value").expect("mutable callback");
        assert!(parent.captures.iter().any(|capture| {
            capture.target == mutating.id && capture.mode == CaptureMode::Unknown
        }));
        assert!(parent.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::Captures
                && matches!(gap.subject, SemanticGapSubject::Capture(_))
        }));

        let parameter_parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure.locator.anchor().span().start_byte() as usize
                        == SOURCE
                            .find("fn with_parameters")
                            .expect("parameter function")
            })
            .expect("function with closure capture parameters");
        for (closure_source, binding_name, expected_mode) in [
            (
                "|| inspect(span.owner.id)",
                "span",
                CaptureMode::LanguageDefined("rust_shared_borrow".into()),
            ),
            ("move || inspect(doc_id)", "doc_id", CaptureMode::Move),
        ] {
            let closure = procedures
                .iter()
                .find(|procedure| {
                    procedure.lexical_parent == Some(parameter_parent.id)
                        && procedure.locator.anchor().span().start_byte() as usize
                            == SOURCE.find(closure_source).expect("parameter closure")
                })
                .expect("parameter closure procedure");
            let capture = parameter_parent
                .captures
                .iter()
                .find(|capture| capture.target == closure.id)
                .expect("parameter capture row");
            assert_eq!(capture.mode, expected_mode);
            let CaptureSource::Value(value_id) = capture.captured else {
                panic!("parameter capture has an exact value source");
            };
            let value = parameter_parent
                .values
                .iter()
                .find(|value| value.id == value_id)
                .expect("parameter capture value retains its parameter identity");
            assert!(
                matches!(
                    &value.kind,
                    SemanticValueKind::Parameter {
                        name: Some(name),
                        ..
                    } if name.as_ref() == binding_name
                ),
                "captured source resolves to parameter `{binding_name}`: {value:#?}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "eaae4724689f: a runtime cast was filtered from a Rust index place"
    )]
    fn rust_index_store_with_casted_index_lowers_as_dynamic_memory_location() {
        let procedures =
            lower_fixture("fn store(slice: &mut [u8], index: u8) { slice[index as usize] = 1; }\n");
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("store procedure");
        let location_id = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match &event.effect {
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Index,
                    location,
                    ..
                } => Some(*location),
                _ => None,
            })
            .expect("indexed assignment publishes a memory store");
        let location = procedure
            .memory_locations
            .iter()
            .find(|location| location.id == location_id)
            .expect("indexed store location");
        assert!(matches!(
            &location.kind,
            MemoryLocationKind::Index { index: None, .. }
        ));
        assert!(procedure.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::IndexMemory
                && matches!(
                    &gap.subject,
                    SemanticGapSubject::MemoryLocation(id) if *id == location_id
                )
        }));
    }

    /// The source text of the value each capture row of the closure starting
    /// at the first occurrence of `closure_text` captures.
    fn captured_names(
        procedures: &[ProcedureSemanticsParts],
        source: &str,
        closure_text: &str,
    ) -> Vec<String> {
        let closure_start = source.find(closure_text).expect("closure in fixture");
        let closure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_some()
                    && procedure.locator.anchor().span().start_byte() as usize == closure_start
            })
            .expect("closure procedure");
        procedures
            .iter()
            .flat_map(|parent| {
                parent
                    .captures
                    .iter()
                    .filter(move |capture| capture.target == closure.id)
                    .map(move |capture| {
                        let captured_mapping = match capture.captured {
                            CaptureSource::Value(value) => {
                                parent
                                    .values
                                    .iter()
                                    .find(|candidate| candidate.id == value)
                                    .expect("captured value exists")
                                    .source
                            }
                            CaptureSource::Location(location) => {
                                parent
                                    .memory_locations
                                    .iter()
                                    .find(|candidate| candidate.id == location)
                                    .expect("captured location exists")
                                    .source
                            }
                        };
                        let mapping = parent
                            .source_mappings
                            .iter()
                            .find(|mapping| mapping.id == captured_mapping)
                            .expect("captured value has a source mapping");
                        let span = mapping.locator.anchor().span();
                        source[span.start_byte() as usize..span.end_byte() as usize].to_owned()
                    })
            })
            .collect()
    }

    /// The lowered procedures must also pass artifact validation, which is
    /// where the missing capture binding was reported.
    fn assert_artifact_builds(procedures: Vec<ProcedureSemanticsParts>, source: &str) {
        let file = ProjectFile::new(std::env::temp_dir(), "capture.rs");
        let key = semantic_artifact_key_from_content(
            &file,
            LanguageDialect::Standard(Language::Rust),
            ContentIdentity::hash_bytes(source.as_bytes()),
            None,
            RustSemanticLowerer.identity(),
        )
        .expect("fixture has a semantic artifact key");
        SemanticArtifact::try_new(key, RustSemanticLowerer.capabilities(), procedures)
            .expect("the lowered fixture validates");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "eb9926938572: a let tuple-struct pattern bound its constructor as a local, so a closure naming it captured an undeclared binding"
    )]
    fn a_closure_naming_a_let_pattern_constructor_captures_nothing() {
        const SOURCE: &str = r#"
fn f(o: Option<i32>) {
    let Some(_x) = o;
    let c = || Some(1);
    c();
}
"#;
        let procedures = lower_fixture(SOURCE);
        assert!(captured_names(&procedures, SOURCE, "|| Some(1)").is_empty());
        assert_artifact_builds(procedures, SOURCE);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "eb9926938572: a let-else tuple-struct pattern bound its constructor, so a closure comparing against Some(\"x\") failed capture validation"
    )]
    fn a_closure_comparing_with_a_let_else_constructor_captures_only_its_operands() {
        const SOURCE: &str = r#"
fn has_modifier(node: Node<'_>, source: &str) -> bool {
    let Some(_modifiers) = node.parent() else {
        return false;
    };
    children_iter(node).any(|modifier| node_text(modifier, source) == Some("x"))
}
"#;
        let procedures = lower_fixture(SOURCE);
        // The parameter's source mapping spans its whole declaration; the
        // point is that the closure captures this one parameter and no
        // constructor.
        assert_eq!(
            captured_names(&procedures, SOURCE, "|modifier|"),
            ["source: &str"]
        );
        assert_artifact_builds(procedures, SOURCE);
    }
}

#[cfg(test)]
mod grouped_attribute_ast_tests {

    use crate::analyzer::rust::semantic::*;

    fn parse(source: &str) -> tree_sitter::Tree {
        let tree = brokk_bifrost_analysis::test_support::parse_fixture_tree(
            source,
            tree_sitter_rust::LANGUAGE.into(),
        );
        assert!(
            !tree.root_node().has_error(),
            "fixture must parse without recovery:\n{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3208: grouped attribute wrappers split Rust declarations and expression values"
    )]
    fn adapter_children_replace_attribute_wrappers_with_their_items() {
        let source = concat!(
            "#[derive(Debug)]\n",
            "fn annotated() {\n",
            "    #[cfg(any())]\n",
            "    mod inner {}\n",
            "    #[allow(unused)]\n",
            "    let value = 1;\n",
            "}\n",
        );
        let tree = parse(source);
        let root_children = named_children(tree.root_node());
        assert_eq!(root_children.len(), 1);
        assert_eq!(root_children[0].kind(), "function_item");

        let body = root_children[0]
            .child_by_field_name("body")
            .expect("function body");
        let body_children = named_children(body)
            .into_iter()
            .map(|node| node.kind().to_string())
            .collect::<Vec<_>>();
        assert_eq!(body_children, ["mod_item", "let_declaration"]);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3208: attributed tail expressions lost their payload value after the grammar switch"
    )]
    fn an_attributed_tail_expression_is_lowered_as_its_value() {
        let source = "#[cfg(any())] fn f() -> i32 { #[cfg(any())] 1 }\n";
        let tree = parse(source);
        let function = named_children(tree.root_node())
            .into_iter()
            .next()
            .expect("function item");
        let body = function.child_by_field_name("body").expect("function body");
        let tail = block_tail_expression(body).expect("attributed tail value");
        assert_eq!(tail.kind(), "integer_literal");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3208: grouped attributes were mistaken for Rust array elements"
    )]
    fn grouped_attributes_are_not_array_elements() {
        let source = "fn f() { let values = [#[allow(dead_code)] 1]; }\n";
        let tree = parse(source);
        let function = named_children(tree.root_node())
            .into_iter()
            .next()
            .expect("function item");
        let body = function.child_by_field_name("body").expect("function body");
        let let_declaration = named_children(body)
            .into_iter()
            .find(|node| node.kind() == "let_declaration")
            .expect("let declaration");
        let array = let_declaration
            .child_by_field_name("value")
            .expect("array initializer");
        let elements = rust_array_initializer_elements(array);
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].kind(), "integer_literal");
    }

    #[test]
    fn boolean_literals_retain_their_scalar_values() {
        let source = "fn f() { consume(true); consume(false); }\n";
        let tree = parse(source);
        let true_start = source.find("true").expect("true literal");
        let false_start = source.find("false").expect("false literal");
        let true_node = tree
            .root_node()
            .named_descendant_for_byte_range(true_start, true_start + 4)
            .expect("true node");
        let false_node = tree
            .root_node()
            .named_descendant_for_byte_range(false_start, false_start + 5)
            .expect("false node");
        assert_eq!(
            expression_value_kind(true_node),
            SemanticValueKind::Boolean(true)
        );
        assert_eq!(
            expression_value_kind(false_node),
            SemanticValueKind::Boolean(false)
        );
    }
}

#[cfg(test)]
mod receiver_type_fact_tests {

    use crate::analyzer::rust::semantic::*;
    use tree_sitter::Parser;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        parser.parse(source, None).expect("Rust tree")
    }

    #[test]
    fn explicit_rust_receiver_bindings_retain_type_and_initializer_ranges() {
        let source = concat!(
            "use std::sync::Mutex;\n",
            "struct Child;\n",
            "fn make() -> Child { Child }\n",
            "fn caller(parameter: Mutex<()>) {\n",
            "    let local: Mutex<()> = parameter;\n",
            "    let child = make();\n",
            "    static LOCK: Mutex<()> = unsafe { std::mem::zeroed() };\n",
            "    const COUNT: u32 = 1;\n",
            "    let _ = (local, child, LOCK, COUNT);\n",
            "}\n",
        );
        let tree = parse(source);
        let facts = RustReceiverTypeFacts::from_tree(source, &tree);
        let file_facts = rust_file_facts_from_tree(source, &tree);
        let use_byte = source.find("let _ =").expect("binding use");

        for name in ["parameter", "local", "LOCK", "COUNT"] {
            assert!(
                facts.binding_at(name, use_byte).is_some(),
                "the explicit Rust binding `{name}` remains available in its lexical scope"
            );
        }
        let lock = facts.binding_at("LOCK", use_byte).expect("static binding");
        let lock_type = lock.declared_type.expect("static declared type");
        assert_eq!(&source[lock_type.start..lock_type.end], "Mutex<()>");
        assert!(lock.initializer.is_none(), "the declared static type wins");
        assert_eq!(file_facts.static_declarations.len(), 1);
        assert_eq!(file_facts.static_declarations[0].name.as_ref(), "LOCK");

        let parameter = facts
            .binding_at("parameter", use_byte)
            .expect("parameter binding");
        let parameter_type = parameter.declared_type.expect("parameter declared type");
        assert_eq!(
            &source[parameter_type.start..parameter_type.end],
            "Mutex<()>"
        );

        let child = facts.binding_at("child", use_byte).expect("local binding");
        let initializer = child.initializer.expect("local initializer");
        assert_eq!(&source[initializer.start..initializer.end], "make()");
        assert!(facts.function_return_types.contains_key("make"));
    }
}

#[cfg(test)]
mod hashmap_consumer_tests;
