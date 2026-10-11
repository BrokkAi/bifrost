//! Go selected-context point resolver used by production queries.

use super::GoAnalyzer;
use crate::CancellationToken;
#[cfg(test)]
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::native_points::{
    adapt_definition_answer, adapt_type_answer, open_native_point_operation,
    unavailable_definition, unavailable_type,
};
use crate::analyzer::resolution::{
    ForwardCandidateArtifactCache, GoReceiverSlotTypeOverlay, ResolutionBatchMetrics,
    SelectedSemanticLocator,
};
use crate::analyzer::resolve_analyzer;
use crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;
use crate::analyzer::store::resolution_operation::{
    GoExternalPackageProvenance, GoPreparedImportContext, GoPreparedImportContextOutcome,
    GoSelectedExternalImport, SelectedResolutionContextMetrics, SelectedResolutionLocated,
    SelectedResolutionOperation, SelectedResolutionOperationOpenOutcome,
    SelectedResolutionOperationOutcome,
    go_receiver_anchor::{
        GoReceiverAnchorMember, GoReceiverReferenceBinding, GoReceiverTypeAnchor,
    },
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, CallApplicationKind, DefinitionLookupDiagnostic, DefinitionLookupOutcome,
    DefinitionLookupStatus, ExactExternalCallProof, ResolvedReferenceSite,
};
use crate::analyzer::usages::get_type::TypeLookupOutcome;
#[cfg(test)]
use crate::analyzer::usages::get_type::{TypeLookupDiagnostic, TypeLookupStatus, TypeLookupType};
#[cfg(test)]
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub(crate) struct GoNativeDefinitionResolution {
    pub(crate) outcome: DefinitionLookupOutcome,
    #[allow(dead_code)] // Consumed by Go call-target evidence when native routing is promoted.
    pub(crate) call_application: CallApplicationKind,
    pub(crate) exact_external_call: Option<ExactExternalCallProof>,
    pub(crate) external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
}

fn external_identity_from_proof(
    proof: Option<&ExactExternalCallProof>,
) -> Option<ResolverOwnedExternalCalleeIdentity> {
    let proof = proof?;
    let (owner_fqn, member) = crate::analyzer::semantic::split_canonical_qualified_callee(
        proof.canonical_callee(),
        crate::analyzer::Language::Go,
    )?;
    Some(ResolverOwnedExternalCalleeIdentity::new(
        crate::analyzer::Language::Go,
        owner_fqn,
        member,
    ))
}

#[derive(Clone)]
struct GoPointFileContext {
    context: GoPreparedImportContext,
    selected_imports: Vec<GoSelectedExternalImport>,
}

/// A type query on an interface method name is a declaration-site query: the
/// producer has no reference there, so the answer is the interface that owns
/// the method.
#[cfg(test)]
fn go_interface_method_owner_type(
    query: BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
) -> Option<TypeLookupOutcome> {
    let root = query.tree?.root_node();
    let selected =
        smallest_named_node_covering(root, query.site.focus_start_byte, query.site.focus_end_byte)?;
    let mut method = selected;
    while method.kind() != "method_elem" {
        method = method.parent()?;
    }
    let method_name = method.child_by_field_name("name")?;
    if selected.start_byte() < method_name.start_byte()
        || selected.end_byte() > method_name.end_byte()
    {
        return None;
    }
    let interface = method.parent()?;
    if interface.kind() != "interface_type" {
        return None;
    }
    let type_spec = interface.parent()?;
    if type_spec.kind() != "type_spec" {
        return None;
    }
    let type_name = type_spec.child_by_field_name("name")?;
    let owner_text = query
        .source
        .get(type_name.start_byte()..type_name.end_byte())?;
    let member_name = query
        .source
        .get(method_name.start_byte()..method_name.end_byte())?
        .to_owned();
    let mut owners = go
        .declarations(query.file)
        .into_iter()
        .filter(|unit| unit.is_class() && unit.terminal_name() == owner_text)
        .filter(|unit| {
            go.ranges(unit).iter().any(|range| {
                range.start_byte <= type_spec.start_byte() && range.end_byte >= type_spec.end_byte()
            })
        })
        .collect::<Vec<_>>();
    owners.sort();
    owners.dedup();
    let [owner] = owners.as_slice() else {
        return None;
    };
    Some(TypeLookupOutcome {
        status: TypeLookupStatus::Resolved,
        reference: Some(query.site.clone()),
        types: vec![TypeLookupType {
            fqn: owner.fq_name().to_string(),
            definitions: vec![owner.clone()],
            semantic_model_id: None,
        }],
        diagnostics: vec![TypeLookupDiagnostic {
            kind: "go_interface_method_owner".into(),
            message: "selected Go interface method belongs to this interface type".into(),
        }],
        target_kind: TypeLookupTargetKind::MemberOwner { member_name },
    })
}

/// The producer has no answer for this site. That is a structured miss, not a
/// failure of the store, so it is incomplete evidence rather than unavailable.
#[cfg(test)]
fn incomplete_go_type(
    site: &ResolvedReferenceSite,
    kind: &'static str,
    message: String,
) -> TypeLookupOutcome {
    TypeLookupOutcome {
        status: TypeLookupStatus::Incomplete,
        reference: Some(site.clone()),
        types: Vec::new(),
        diagnostics: vec![TypeLookupDiagnostic {
            kind: kind.into(),
            message,
        }],
        target_kind: TypeLookupTargetKind::ValueExpression,
    }
}

fn go_point_local_binding_for_identifier<'tree>(
    identifier: tree_sitter::Node<'tree>,
    usage: tree_sitter::Node<'tree>,
    source: &str,
) -> Option<(tree_sitter::Node<'tree>, Option<tree_sitter::Node<'tree>>)> {
    let name = identifier.utf8_text(source.as_bytes()).ok()?;
    let mut functions = Vec::new();
    let mut use_blocks = Vec::new();
    let mut ancestor = usage;
    loop {
        if ancestor.kind() == "block" {
            use_blocks.push(ancestor);
        }
        if matches!(
            ancestor.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) && let Some(body) = ancestor.child_by_field_name("body")
        {
            functions.push(body);
        }
        let Some(parent) = ancestor.parent() else {
            break;
        };
        ancestor = parent;
    }
    if functions.is_empty() {
        return None;
    }
    let mut pending = functions;
    let mut best: Option<(
        usize,
        usize,
        tree_sitter::Node<'_>,
        Option<tree_sitter::Node<'_>>,
    )> = None;
    while let Some(candidate) = pending.pop() {
        if candidate.start_byte() > usage.start_byte() {
            continue;
        }
        if candidate.end_byte() <= usage.start_byte() {
            let (left, right) = match candidate.kind() {
                "short_var_declaration" => (
                    candidate.child_by_field_name("left"),
                    candidate.child_by_field_name("right"),
                ),
                "var_spec" => (
                    candidate.child_by_field_name("name"),
                    candidate.child_by_field_name("value"),
                ),
                "range_clause" => (candidate.child_by_field_name("left"), None),
                _ => (None, None),
            };
            if let Some(left) = left {
                let lefts = if left.kind() == "expression_list" {
                    (0..left.named_child_count())
                        .filter_map(|index| left.named_child(index))
                        .collect::<Vec<_>>()
                } else {
                    vec![left]
                };
                let rights = right.map(|right| {
                    if right.kind() == "expression_list" {
                        (0..right.named_child_count())
                            .filter_map(|index| right.named_child(index))
                            .collect::<Vec<_>>()
                    } else {
                        vec![right]
                    }
                });
                for (position, left) in lefts.iter().enumerate() {
                    if left.kind() != "identifier"
                        || left.utf8_text(source.as_bytes()).ok() != Some(name)
                    {
                        continue;
                    }
                    // One call on the right initializes several binders only as its
                    // results. Position 0 is the call's first result; later positions
                    // have no single initializer, so they stay without one.
                    let value = rights
                        .as_ref()
                        .and_then(|rights| rights.get(position).copied());
                    let mut declaration_block = if candidate.kind() == "range_clause" {
                        candidate
                            .parent()
                            .and_then(|for_statement| for_statement.child_by_field_name("body"))
                            .unwrap_or(candidate)
                    } else {
                        candidate
                    };
                    while declaration_block.kind() != "block" {
                        let Some(parent) = declaration_block.parent() else {
                            break;
                        };
                        declaration_block = parent;
                    }
                    if declaration_block.kind() != "block"
                        || !use_blocks
                            .iter()
                            .any(|block| block.id() == declaration_block.id())
                    {
                        continue;
                    }
                    let depth = use_blocks
                        .iter()
                        .position(|block| block.id() == declaration_block.id())
                        .expect("an admitted Go binding scope is an ancestor of its use");
                    let rank = use_blocks.len() - depth;
                    if best.is_none_or(|(prior_rank, prior_start, _, _)| {
                        rank > prior_rank
                            || (rank == prior_rank && candidate.start_byte() > prior_start)
                    }) {
                        best = Some((rank, candidate.start_byte(), *left, value));
                    }
                }
            }
        }
        pending.extend(
            (0..candidate.named_child_count())
                .rev()
                .filter_map(|index| candidate.named_child(index)),
        );
    }
    best.map(|(_, _, name, initializer)| (name, initializer))
}

fn go_point_local_initializer_for_identifier<'tree>(
    identifier: tree_sitter::Node<'tree>,
    usage: tree_sitter::Node<'tree>,
    source: &str,
) -> Option<Option<tree_sitter::Node<'tree>>> {
    go_point_local_binding_for_identifier(identifier, usage, source)
        .map(|(_, initializer)| initializer)
}

pub(crate) struct GoPointReceiverAnchor {
    pub(crate) kind: u8,
    pub(crate) owner_type_name: Option<String>,
    pub(crate) owner_call_reference: Option<(usize, usize)>,
    pub(crate) name: String,
    pub(crate) member_name: String,
    pub(crate) reference_start_byte: usize,
    pub(crate) reference_end_byte: usize,
    pub(crate) binding: Option<GoPointBindingAnchor>,
}

pub(crate) struct GoPointBindingAnchor {
    pub(crate) declaration_start_byte: usize,
    pub(crate) declaration_end_byte: usize,
    pub(crate) reference_start_byte: usize,
    pub(crate) reference_end_byte: usize,
    pub(crate) member_name: String,
    pub(crate) followup_member_name: Option<String>,
    pub(crate) initializer: Option<GoPointBindingInitializer>,
}

pub(crate) enum GoPointBindingInitializer {
    CallResult {
        function_start_byte: usize,
        function_end_byte: usize,
    },
    FieldChain {
        root_declaration_start_byte: usize,
        root_declaration_end_byte: usize,
        member_names: Vec<String>,
    },
}

fn go_point_simple_type_name(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" | "type_identifier" => {
                return Some(current.utf8_text(source.as_bytes()).ok()?.to_owned());
            }
            "pointer_type" | "generic_type" | "parenthesized_type" => {
                current = current
                    .child_by_field_name("type")
                    .or_else(|| current.named_child(0))?;
            }
            _ => return None,
        }
    }
}

fn go_point_parameter_binding_for_identifier<'tree>(
    identifier: tree_sitter::Node<'tree>,
    usage: tree_sitter::Node<'tree>,
    source: &str,
) -> Option<(tree_sitter::Node<'tree>, tree_sitter::Node<'tree>)> {
    let name = identifier.utf8_text(source.as_bytes()).ok()?;
    let mut function = usage;
    loop {
        if matches!(
            function.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            for field in ["receiver", "parameters"] {
                let Some(parameters) = function.child_by_field_name(field) else {
                    continue;
                };
                let mut pending = vec![parameters];
                while let Some(node) = pending.pop() {
                    if node.kind() == "parameter_declaration" {
                        let Some(parameter_type) = node.child_by_field_name("type") else {
                            continue;
                        };
                        let Some(parameter_names) = node.child_by_field_name("name") else {
                            continue;
                        };
                        let names = if parameter_names.kind() == "identifier_list" {
                            (0..parameter_names.named_child_count())
                                .filter_map(|index| parameter_names.named_child(index))
                                .collect::<Vec<_>>()
                        } else {
                            vec![parameter_names]
                        };
                        if let Some(parameter_name) = names.into_iter().find(|parameter_name| {
                            parameter_name.utf8_text(source.as_bytes()).ok() == Some(name)
                        }) {
                            return Some((parameter_name, parameter_type));
                        }
                    }
                    pending.extend(
                        (0..node.named_child_count())
                            .rev()
                            .filter_map(|index| node.named_child(index)),
                    );
                }
            }
        }
        function = function.parent()?;
    }
}

fn go_point_parameter_type_for_identifier<'tree>(
    identifier: tree_sitter::Node<'tree>,
    usage: tree_sitter::Node<'tree>,
    source: &str,
) -> Option<tree_sitter::Node<'tree>> {
    go_point_parameter_binding_for_identifier(identifier, usage, source)
        .map(|(_, parameter_type)| parameter_type)
}

fn go_point_binding_for_identifier<'tree>(
    identifier: tree_sitter::Node<'tree>,
    usage: tree_sitter::Node<'tree>,
    source: &str,
) -> Option<(tree_sitter::Node<'tree>, Option<tree_sitter::Node<'tree>>)> {
    go_point_local_binding_for_identifier(identifier, usage, source).or_else(|| {
        go_point_parameter_binding_for_identifier(identifier, usage, source)
            .map(|(name, _parameter_type)| (name, None))
    })
}

fn go_point_binding_initializer(
    initializer: tree_sitter::Node<'_>,
    source: &str,
) -> Option<GoPointBindingInitializer> {
    let mut initializer = initializer;
    while initializer.kind() == "parenthesized_expression" {
        initializer = initializer.named_child(0)?;
    }
    if initializer.kind() == "call_expression" {
        let function = initializer.child_by_field_name("function")?;
        return Some(GoPointBindingInitializer::CallResult {
            function_start_byte: function.start_byte(),
            function_end_byte: function.end_byte(),
        });
    }

    let mut member_names = Vec::new();
    let mut root = initializer;
    while root.kind() == "selector_expression" {
        let field = root.child_by_field_name("field")?;
        member_names.push(field.utf8_text(source.as_bytes()).ok()?.to_owned());
        root = root.child_by_field_name("operand")?;
    }
    if member_names.is_empty() || root.kind() != "identifier" {
        return None;
    }
    let (root_declaration, _) = go_point_binding_for_identifier(root, root, source)?;
    member_names.reverse();
    Some(GoPointBindingInitializer::FieldChain {
        root_declaration_start_byte: root_declaration.start_byte(),
        root_declaration_end_byte: root_declaration.end_byte(),
        member_names,
    })
}

fn go_point_expression_type_name(
    expression: tree_sitter::Node<'_>,
    usage: tree_sitter::Node<'_>,
    source: &str,
) -> Option<String> {
    if expression.kind() != "identifier" {
        return None;
    }
    if let Some(initializer) = go_point_local_initializer_for_identifier(expression, usage, source)
    {
        let initializer = initializer?;
        if initializer.kind() == "composite_literal" {
            let type_node = initializer.child_by_field_name("type")?;
            return go_point_simple_type_name(type_node, source);
        }
        return None;
    }
    let root = expression;
    let mut function = usage;
    loop {
        if matches!(
            function.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            let parameter = go_point_parameter_type_for_identifier(root, usage, source)?;
            return go_point_simple_type_name(parameter, source);
        }
        function = function.parent()?;
    }
}

fn go_point_call_callee_reference(
    expression: tree_sitter::Node<'_>,
    usage: tree_sitter::Node<'_>,
    source: &str,
) -> Option<(usize, usize)> {
    if expression.kind() != "identifier" {
        return None;
    }
    let initializer = go_point_local_initializer_for_identifier(expression, usage, source)??;
    let mut callee = match initializer.kind() {
        "call_expression" => initializer.child_by_field_name("function")?,
        // tree-sitter-go can represent a generic function invocation with
        // arguments as a type-conversion node. The keyed call-obligation read
        // below distinguishes it from a real conversion.
        "type_conversion_expression" => initializer.child_by_field_name("type")?,
        _ => return None,
    };
    loop {
        callee = match callee.kind() {
            "identifier" | "type_identifier" | "field_identifier" => {
                return Some((callee.start_byte(), callee.end_byte()));
            }
            "generic_type" | "type_instantiation_expression" | "parenthesized_expression" => callee
                .child_by_field_name("type")
                .or_else(|| callee.named_child(0))?,
            // tree-sitter-go represents an unambiguous generic invocation
            // such as New[string, struct{}](...) as an index expression.
            // Only unwrap it when the indexed node is structurally a type;
            // ordinary function-valued indexing is not a declaration anchor.
            "index_expression" => {
                let index = callee.child_by_field_name("index")?;
                if !go_point_is_type_argument(index) {
                    return None;
                }
                callee.child_by_field_name("operand")?
            }
            _ => return None,
        };
    }
}

fn go_point_is_type_argument(node: tree_sitter::Node<'_>) -> bool {
    matches!(
        node.kind(),
        "type_identifier"
            | "qualified_type"
            | "generic_type"
            | "pointer_type"
            | "array_type"
            | "implicit_length_array_type"
            | "slice_type"
            | "map_type"
            | "channel_type"
            | "parenthesized_type"
            | "struct_type"
            | "interface_type"
            | "function_type"
    )
}

pub(crate) fn go_point_receiver_anchor(
    site: &ResolvedReferenceSite,
    tree: &tree_sitter::Tree,
    source: &str,
) -> Option<GoPointReceiverAnchor> {
    let root = tree.root_node();
    let focused = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    let mut selected = focused;
    loop {
        if selected.kind() == "selector_expression"
            && selected.child_by_field_name("field").is_some_and(|field| {
                field.start_byte() == site.focus_start_byte
                    && field.end_byte() == site.focus_end_byte
            })
        {
            break;
        }
        selected = selected.parent()?;
    }
    let receiver = selected.child_by_field_name("operand")?;
    let member_name = source
        .get(site.focus_start_byte..site.focus_end_byte)?
        .to_owned();
    let (anchor, owner_expression, kind) = match receiver.kind() {
        "selector_expression" => (
            receiver.child_by_field_name("field")?,
            receiver.child_by_field_name("operand")?,
            0,
        ),
        "identifier" => {
            let call_function =
                go_point_local_initializer_for_identifier(receiver, receiver, source)
                    .flatten()
                    .filter(|initializer| initializer.kind() == "call_expression")
                    .and_then(|initializer| initializer.child_by_field_name("function"))
                    .filter(|function| function.kind() == "selector_expression");
            if let Some(function) = call_function {
                (
                    function.child_by_field_name("field")?,
                    function.child_by_field_name("operand")?,
                    1,
                )
            } else {
                let (declaration, binding_initializer) =
                    go_point_binding_for_identifier(receiver, receiver, source)?;
                let name = receiver.utf8_text(source.as_bytes()).ok()?.to_owned();
                return Some(GoPointReceiverAnchor {
                    kind: 2,
                    owner_type_name: None,
                    owner_call_reference: None,
                    name,
                    member_name: member_name.clone(),
                    reference_start_byte: receiver.start_byte(),
                    reference_end_byte: receiver.end_byte(),
                    binding: Some(GoPointBindingAnchor {
                        declaration_start_byte: declaration.start_byte(),
                        declaration_end_byte: declaration.end_byte(),
                        reference_start_byte: receiver.start_byte(),
                        reference_end_byte: receiver.end_byte(),
                        member_name,
                        followup_member_name: None,
                        initializer: binding_initializer.and_then(|initializer| {
                            go_point_binding_initializer(initializer, source)
                        }),
                    }),
                });
            }
        }
        "call_expression" => {
            let function = receiver.child_by_field_name("function")?;
            if function.kind() != "selector_expression" {
                return None;
            }
            (
                function.child_by_field_name("field")?,
                function.child_by_field_name("operand")?,
                1,
            )
        }
        _ => return None,
    };
    let name = anchor.utf8_text(source.as_bytes()).ok()?.to_owned();
    let reference_start_byte = anchor.start_byte();
    let reference_end_byte = anchor.end_byte();
    // Routes are tried in their established order: a declared type name, then
    // the owner's call callee, and only then the owner's binding with a
    // follow-up member. The binding route adds keyed chain reads, so it must
    // not preempt an owner that the cheaper routes already answer.
    let owner_type_name = go_point_expression_type_name(owner_expression, receiver, source);
    let owner_call_reference = owner_type_name
        .is_none()
        .then(|| go_point_call_callee_reference(owner_expression, receiver, source))
        .flatten();
    let binding = if owner_type_name.is_none()
        && owner_call_reference.is_none()
        && owner_expression.kind() == "identifier"
    {
        go_point_binding_for_identifier(owner_expression, receiver, source).map(
            |(declaration, binding_initializer)| GoPointBindingAnchor {
                declaration_start_byte: declaration.start_byte(),
                declaration_end_byte: declaration.end_byte(),
                reference_start_byte: owner_expression.start_byte(),
                reference_end_byte: owner_expression.end_byte(),
                member_name: name.clone(),
                followup_member_name: Some(member_name.clone()),
                initializer: binding_initializer
                    .and_then(|initializer| go_point_binding_initializer(initializer, source)),
            },
        )
    } else {
        None
    };
    if owner_type_name.is_none() && owner_call_reference.is_none() && binding.is_none() {
        return None;
    }
    Some(GoPointReceiverAnchor {
        kind,
        owner_type_name,
        owner_call_reference,
        name,
        member_name,
        reference_start_byte,
        reference_end_byte,
        binding,
    })
}

fn go_point_selector_is_package_member_lookup(
    query: BoundedReceiverQuery<'_>,
    tree: &tree_sitter::Tree,
    selected_imports: &[GoSelectedExternalImport],
) -> bool {
    let Some(selector) =
        brokk_bifrost_go::graph::reference::go_selector_descriptor(tree.root_node(), query.site)
    else {
        return false;
    };
    if selector.focus_segment == 0
        || !matches!(selector.base.kind(), "identifier" | "package_identifier")
    {
        return false;
    }
    let Some(base_name) = selector.base.utf8_text(query.source.as_bytes()).ok() else {
        return false;
    };
    // A local declaration shadows an import with the same spelling.
    if go_point_local_initializer_for_identifier(selector.base, selector.base, query.source)
        .is_some()
        || go_point_parameter_type_for_identifier(selector.base, selector.base, query.source)
            .is_some()
    {
        return true;
    }
    if selected_imports
        .iter()
        .any(|selected| selected.package_name == base_name)
    {
        return false;
    }
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "import_spec" {
            if brokk_bifrost_go::declarations::go_import_spec_binding_name(node, query.source)
                == Some(base_name)
            {
                return false;
            }
            continue;
        }
        pending.extend(
            (0..node.named_child_count())
                .rev()
                .filter_map(|index| node.named_child(index)),
        );
    }
    true
}

fn attach_go_package_incomplete(outcome: &mut DefinitionLookupOutcome) {
    if outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "go-package-incomplete")
    {
        return;
    }
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "go-package-incomplete".into(),
        message:
            "a saved sibling has a Go build constraint, so selected package members may be absent"
                .into(),
        claim: None,
    });
}

fn go_call_selector_reference_at(
    tree: &tree_sitter::Tree,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    let root = tree.root_node();
    let Some(focused) = root
        .named_descendant_for_byte_range(start_byte, end_byte)
        .filter(|node| node.start_byte() == start_byte && node.end_byte() == end_byte)
    else {
        return false;
    };
    let is_indexed_callee = |function: tree_sitter::Node<'_>, selector: tree_sitter::Node<'_>| {
        let mut current = function;
        loop {
            if current.id() == selector.id() {
                return true;
            }
            current = match current.kind() {
                "parenthesized_expression" => {
                    let Some(inner) = current.named_child(0) else {
                        return false;
                    };
                    inner
                }
                "index_expression" => {
                    let Some(operand) = current.child_by_field_name("operand") else {
                        return false;
                    };
                    operand
                }
                _ => return false,
            };
        }
    };

    let mut current = focused;
    loop {
        if current.kind() == "selector_expression"
            && current.child_by_field_name("field").is_some_and(|field| {
                field.start_byte() == start_byte && field.end_byte() == end_byte
            })
        {
            let selector = current;
            let mut enclosing = current;
            while let Some(parent) = enclosing.parent() {
                if parent.kind() == "call_expression"
                    && parent
                        .child_by_field_name("function")
                        .is_some_and(|function| is_indexed_callee(function, selector))
                {
                    return true;
                }
                enclosing = parent;
            }
        }
        let Some(parent) = current.parent() else {
            return false;
        };
        current = parent;
    }
}

fn go_identifier_call_reference_at(
    tree: &tree_sitter::Tree,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    let Some(mut function) = tree
        .root_node()
        .named_descendant_for_byte_range(start_byte, end_byte)
        .filter(|node| {
            node.start_byte() == start_byte
                && node.end_byte() == end_byte
                && matches!(node.kind(), "identifier" | "package_identifier")
        })
    else {
        return false;
    };
    loop {
        let Some(parent) = function.parent() else {
            return false;
        };
        if parent.kind() == "call_expression" {
            return parent
                .child_by_field_name("function")
                .is_some_and(|callee| callee.id() == function.id());
        }
        if parent.kind() != "parenthesized_expression"
            || parent
                .named_child(0)
                .is_none_or(|child| child.id() != function.id())
        {
            return false;
        }
        function = parent;
    }
}

fn go_generic_instantiation_callee_reference_at(
    tree: &tree_sitter::Tree,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    let Some(mut base) = tree
        .root_node()
        .named_descendant_for_byte_range(start_byte, end_byte)
        .filter(|node| {
            node.start_byte() == start_byte
                && node.end_byte() == end_byte
                && matches!(
                    node.kind(),
                    "identifier" | "type_identifier" | "field_identifier"
                )
        })
    else {
        return false;
    };
    while let Some(application) = base.parent() {
        if application.kind() == "generic_type"
            && application
                .child_by_field_name("type")
                .is_some_and(|type_node| type_node.id() == base.id())
        {
            let Some(parent) = application.parent() else {
                return false;
            };
            if parent.kind() == "type_conversion_expression"
                && parent
                    .child_by_field_name("type")
                    .is_some_and(|type_node| type_node.id() == application.id())
                && parent.child_by_field_name("operand").is_some()
            {
                return true;
            }
            return false;
        }
        if application.kind() == "type_instantiation_expression"
            && application
                .child_by_field_name("type")
                .is_some_and(|type_node| type_node.id() == base.id())
        {
            return application.parent().is_some_and(|call| {
                call.kind() == "call_expression"
                    && call
                        .child_by_field_name("function")
                        .is_some_and(|function| function.id() == application.id())
            });
        }
        if application.kind() != "parenthesized_type" {
            return false;
        }
        base = application;
    }
    false
}

pub(crate) struct GoNativePointRequest<'a> {
    go: &'a GoAnalyzer,
    operation: SelectedResolutionOperation<'a, 'a>,
    context_id: i64,
    overlay: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    files: HashMap<String, GoPointFileContext>,
    forward_candidate_artifacts: HashMap<String, ForwardCandidateArtifactCache>,
    point_metrics: ResolutionBatchMetrics,
    record_work: bool,
    phase_nanos: GoPointPhaseNanos,
}

#[derive(Default)]
struct GoPointPhaseNanos {
    file_context: u128,
    native_resolution: u128,
    native_sql: u128,
}

pub(crate) enum GoNativePointRequestOpen<'a> {
    Ready(Box<GoNativePointRequest<'a>>),
    Unavailable { kind: &'static str, message: String },
    Cancelled,
}

impl<'a> GoNativePointRequest<'a> {
    pub(crate) fn open(
        go: &'a GoAnalyzer,
        overlay: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        cancellation: &CancellationToken,
    ) -> crate::analyzer::store::Result<GoNativePointRequestOpen<'a>> {
        if cancellation.is_cancelled() {
            return Ok(GoNativePointRequestOpen::Cancelled);
        }
        if !go.inner.workspace_declaration_identities_authoritative() {
            return Ok(GoNativePointRequestOpen::Unavailable {
                kind: "native_identity_authority_unavailable",
                message: "selected native declaration identities are not authoritative".into(),
            });
        }
        let snapshots = go.inner.selected_workspace_snapshots();
        let (Some(snapshot), Some(profile)) = (snapshots.get("go"), go.native_context_profile())
        else {
            return Ok(GoNativePointRequestOpen::Unavailable {
                kind: "native_context_unavailable",
                message: "selected Go package/import context is unavailable".into(),
            });
        };
        let Some(context) = go
            .inner
            .analyzer_store()
            .selected_go_context(snapshot, &profile)?
        else {
            return Ok(GoNativePointRequestOpen::Unavailable {
                kind: "native_context_unavailable",
                message: "selected Go package/import context is unavailable".into(),
            });
        };
        if cancellation.is_cancelled() {
            return Ok(GoNativePointRequestOpen::Cancelled);
        }
        let operation = match open_native_point_operation(&go.inner, cancellation)? {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                return Ok(GoNativePointRequestOpen::Unavailable {
                    kind: "native_unavailable",
                    message: format!("{reason:?}"),
                });
            }
            SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                return Ok(GoNativePointRequestOpen::Unavailable {
                    kind: "native_stale",
                    message: format!("{reason:?}"),
                });
            }
            SelectedResolutionOperationOpenOutcome::Cancelled => {
                return Ok(GoNativePointRequestOpen::Cancelled);
            }
        };
        Ok(GoNativePointRequestOpen::Ready(Box::new(Self {
            go,
            operation,
            context_id: context.context_id,
            overlay,
            files: HashMap::default(),
            forward_candidate_artifacts: HashMap::default(),
            point_metrics: ResolutionBatchMetrics::default(),
            record_work: std::env::var_os("BIFROST_TRIAL_NATIVE_GO_POINT_WORK").is_some(),
            phase_nanos: GoPointPhaseNanos::default(),
        })))
    }

    /// The selected operation and Go context the unit-summary differential test
    /// uses as the incumbent readers' oracle.
    #[cfg(test)]
    pub(crate) fn oracle_for_test(&self) -> (&SelectedResolutionOperation<'a, 'a>, i64) {
        (&self.operation, self.context_id)
    }

    fn file_context(
        &mut self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> crate::analyzer::store::Result<Option<GoPointFileContext>> {
        let started = self.record_work.then(Instant::now);
        let result = self.prepare_file_context(path, cancellation);
        if let Some(started) = started {
            self.phase_nanos.file_context += started.elapsed().as_nanos();
        }
        result
    }

    fn point_receiver_slot_type_overlay(
        &self,
        path: &str,
        file_context: &GoPointFileContext,
        query: BoundedReceiverQuery<'_>,
        tree: &tree_sitter::Tree,
        cancellation: &CancellationToken,
    ) -> crate::analyzer::store::Result<Option<GoReceiverSlotTypeOverlay>> {
        let Some(anchor) = go_point_receiver_anchor(query.site, tree, query.source) else {
            return Ok(None);
        };
        let Some(slot) = self.operation.go_point_receiver_slot(
            file_context.context.demand.context_id,
            path,
            query.site.focus_start_byte,
            query.site.focus_end_byte,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let (
            package_id,
            source_role,
            selected_anchor,
            mut chain_bindings,
            mut chain_slots,
            binding_reference,
        ) = if let Some(binding) = anchor.binding.as_ref() {
            let Some((package_id, source_role, binding_anchor)) =
                self.operation.go_point_binding_type_anchor(
                    file_context.context.demand.context_id,
                    path,
                    binding.declaration_start_byte,
                    binding.declaration_end_byte,
                    &binding.member_name,
                    cancellation,
                )?
            else {
                return Ok(None);
            };
            let binding_reference = Some((
                binding.reference_start_byte,
                binding.reference_end_byte,
                binding_anchor.definition,
            ));
            if let Some(followup_member_name) = binding.followup_member_name.as_ref() {
                let GoReceiverAnchorMember::Known {
                    member,
                    reference_bindings,
                    typed_slots,
                    ..
                } = self.operation.resolve_go_receiver_anchor_member(
                    file_context.context.demand.context_id,
                    package_id,
                    &source_role,
                    &binding_anchor,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                (
                    package_id,
                    source_role,
                    GoReceiverTypeAnchor::field_type(member, followup_member_name.clone()),
                    reference_bindings.into_vec(),
                    typed_slots.into_vec(),
                    binding_reference,
                )
            } else {
                (
                    package_id,
                    source_role,
                    binding_anchor,
                    Vec::new(),
                    Vec::new(),
                    binding_reference,
                )
            }
        } else if let Some(owner_type_name) = anchor.owner_type_name.as_deref() {
            let Some((package_id, source_role, selected_anchor)) =
                self.operation.go_point_receiver_type_anchor(
                    file_context.context.demand.context_id,
                    path,
                    anchor.kind,
                    owner_type_name,
                    &anchor.name,
                    &anchor.member_name,
                    cancellation,
                )?
            else {
                return Ok(None);
            };
            (
                package_id,
                source_role,
                selected_anchor,
                Vec::new(),
                Vec::new(),
                None,
            )
        } else {
            let (call_start, call_end) = anchor
                .owner_call_reference
                .expect("a Go receiver anchor has a type name or call-result anchor");
            let Some(call_reference) = self.operation.go_point_call_reference_at(
                path,
                call_start,
                call_end,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let Some((package_id, source_role, call_anchor)) =
                self.operation.go_point_callable_result_anchor(
                    file_context.context.demand.context_id,
                    path,
                    call_reference,
                    cancellation,
                )?
            else {
                return Ok(None);
            };
            let Some(call_types) = self.operation.go_receiver_anchor_types(
                file_context.context.demand.context_id,
                package_id,
                &source_role,
                &call_anchor,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let Some(owner_type_name) = self
                .operation
                .go_point_type_name(call_types.receiver_type.identity(), cancellation)?
            else {
                return Ok(None);
            };
            let Some(result_slot) =
                self.operation
                    .go_point_callable_result_slot(path, call_reference, cancellation)?
            else {
                return Ok(None);
            };
            let mut chain_bindings = call_types.reference_bindings.into_vec();
            chain_bindings.push(GoReceiverReferenceBinding {
                reference: call_reference,
                definition: call_anchor.definition,
            });
            let mut chain_slots = call_types.typed_slots.into_vec();
            chain_slots.push((
                result_slot,
                crate::analyzer::resolution::ResolutionSlotValue::runtime(
                    call_types.receiver_type,
                    false,
                ),
            ));
            let Some((member_package_id, member_source_role, selected_anchor)) =
                self.operation.go_point_receiver_type_anchor(
                    file_context.context.demand.context_id,
                    path,
                    anchor.kind,
                    &owner_type_name,
                    &anchor.name,
                    &anchor.member_name,
                    cancellation,
                )?
            else {
                return Ok(None);
            };
            assert_eq!(package_id, member_package_id);
            assert_eq!(source_role, member_source_role);
            (
                package_id,
                source_role,
                selected_anchor,
                chain_bindings,
                chain_slots,
                None,
            )
        };
        let GoReceiverAnchorMember::Known {
            receiver_type,
            member,
            member_result_type,
            reference_bindings,
            typed_slots,
        } = self.operation.resolve_go_receiver_anchor_member(
            file_context.context.demand.context_id,
            package_id,
            &source_role,
            &selected_anchor,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let Some(query_reference) = self.operation.go_point_reference_at(
            path,
            query.site.focus_start_byte,
            query.site.focus_end_byte,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let query_result_slot = if let Some(result_type) = member_result_type {
            self.operation
                .go_point_callable_result_slot(path, query_reference, cancellation)?
                .map(|slot| (slot, result_type))
        } else {
            None
        };
        let Some(anchor_reference) = self.operation.go_point_reference_at(
            path,
            anchor.reference_start_byte,
            anchor.reference_end_byte,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        if let Some((start_byte, end_byte, definition)) = binding_reference {
            let Some(reference) =
                self.operation
                    .go_point_reference_at(path, start_byte, end_byte, cancellation)?
            else {
                return Ok(None);
            };
            chain_bindings.push(GoReceiverReferenceBinding {
                reference,
                definition,
            });
        }
        chain_bindings.extend(reference_bindings.into_vec());
        let mut bindings = chain_bindings;
        bindings.push(GoReceiverReferenceBinding {
            reference: anchor_reference,
            definition: selected_anchor.definition,
        });
        bindings.sort_unstable();
        let mut canonical = Vec::with_capacity(bindings.len());
        for binding in bindings {
            if let Some((prior_reference, prior_definition)) = canonical.last()
                && *prior_reference == binding.reference
            {
                if *prior_definition != binding.definition {
                    return Ok(None);
                }
                continue;
            }
            canonical.push((binding.reference, binding.definition));
        }
        chain_slots.extend(typed_slots.into_vec());
        chain_slots.sort_unstable();
        chain_slots.dedup();
        let overlay = GoReceiverSlotTypeOverlay {
            slot,
            ty: receiver_type,
            reference_bindings: canonical.into_boxed_slice(),
            typed_slots: chain_slots.into_boxed_slice(),
            query_binding: (query_reference, member),
            query_result_slot,
        };
        Ok(Some(overlay))
    }

    fn prepare_file_context(
        &mut self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> crate::analyzer::store::Result<Option<GoPointFileContext>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(context) = self.files.get(path) {
            return Ok(Some(context.clone()));
        }
        let GoPreparedImportContextOutcome::Ready(context) = self
            .operation
            .go_file_import_context(self.context_id, path, cancellation)?
        else {
            return Ok(None);
        };
        let mut selected_imports =
            self.operation
                .go_selected_external_imports(self.context_id, path, cancellation)?;
        let unresolved_imports =
            self.operation
                .go_selected_unresolved_imports(self.context_id, path, cancellation)?;
        append_model_backed_external_imports(
            unresolved_imports,
            self.overlay.as_deref(),
            cancellation,
            &mut selected_imports,
        );
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let context = GoPointFileContext {
            context: *context,
            selected_imports,
        };
        self.files.insert(path.to_owned(), context.clone());
        Ok(Some(context))
    }

    pub(crate) fn resolve_type(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        if cancellation.is_cancelled() {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        if !self
            .go
            .inner
            .source_matches_selected_native_content(query.file, query.source)
        {
            return BoundedResolution::Complete {
                value: unavailable_type(
                    query.site,
                    "native_source_mismatch",
                    "supplied native reference text differs from the admitted selected source"
                        .into(),
                ),
                work: ReceiverAnalysisWork::default(),
            };
        }
        let path = crate::path_utils::rel_path_string(query.file);
        let file_context = match self.file_context(&path, &cancellation) {
            Ok(Some(context)) => context,
            Ok(None) if cancellation.is_cancelled() => {
                return BoundedResolution::Cancelled {
                    work: ReceiverAnalysisWork::default(),
                };
            }
            Ok(None) => {
                return BoundedResolution::Complete {
                    value: unavailable_type(
                        query.site,
                        "native_context_unavailable",
                        "selected native import context is unavailable".into(),
                    ),
                    work: ReceiverAnalysisWork::default(),
                };
            }
            Err(error) => {
                return BoundedResolution::Complete {
                    value: unavailable_type(query.site, "native_store_error", error.to_string()),
                    work: ReceiverAnalysisWork::default(),
                };
            }
        };
        let parsed_tree = query
            .tree
            .is_none()
            .then(|| crate::analyzer::usages::get_definition::parse_go_tree(query.source))
            .flatten();
        let receiver_overlay = if let Some(tree) = query.tree.or(parsed_tree.as_ref()) {
            match self.point_receiver_slot_type_overlay(
                &path,
                &file_context,
                query,
                tree,
                &cancellation,
            ) {
                Ok(overlay) => overlay,
                Err(error) => {
                    return BoundedResolution::Complete {
                        value: unavailable_type(
                            query.site,
                            "native_store_error",
                            error.to_string(),
                        ),
                        work: ReceiverAnalysisWork::default(),
                    };
                }
            }
        } else {
            None
        };
        let generic_callee = query.tree.or(parsed_tree.as_ref()).is_some_and(|tree| {
            go_generic_instantiation_callee_reference_at(
                tree,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
            )
        });
        let artifacts = self
            .forward_candidate_artifacts
            .entry(path.clone())
            .or_default();
        let locator = if generic_callee {
            SelectedSemanticLocator::for_reference_range_in_namespace(
                "go",
                path,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
                ResolutionNamespace::TypeOrValue,
            )
        } else {
            SelectedSemanticLocator::for_reference_range(
                "go",
                path,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
            )
        };
        let mut metrics = SelectedResolutionContextMetrics;
        let native_sql_before = self
            .record_work
            .then(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows)
            .flatten();
        let native_started = self.record_work.then(Instant::now);
        let native = self
            .operation
            .resolve_native_reference_types_bounded_for_go_request(
                file_context.context,
                receiver_overlay,
                &locator,
                query.budget,
                &cancellation,
                &mut metrics,
                artifacts,
                &mut self.point_metrics,
            );
        if let Some(started) = native_started {
            self.phase_nanos.native_resolution += started.elapsed().as_nanos();
            if let (Some(before), Some(after)) = (
                native_sql_before,
                brokk_bifrost_core::cache_db::sql_profile::totals_with_rows(),
            ) {
                self.phase_nanos.native_sql += after.2 - before.2;
            }
        }
        match native {
            Ok(BoundedResolution::Complete { value, work }) => {
                match value {
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) => match answer.types {
                        crate::analyzer::store::resolution_operation::SelectedNativeTypes::Cancelled => {
                            BoundedResolution::Cancelled { work }
                        }
                        // A reference that names a type has no value type to report. The
                        // incumbent answers it as no_type, so the native answer does too.
                        _ if answer.answer.site_metadata().is_some_and(|metadata| {
                            metadata.site_kind()
                                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::TypeReference
                        }) => {
                            BoundedResolution::Complete {
                                value: go_type_name_site_outcome(query.site),
                                work,
                            }
                        }
                        _ => BoundedResolution::Complete {
                            value: adapt_type_answer(query.site, crate::analyzer::Language::Go, answer),
                            work,
                        },
                    },
                    #[cfg(test)]
                    SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                        let value = go_interface_method_owner_type(query, self.go).unwrap_or_else(|| {
                            incomplete_go_type(
                                query.site,
                                "native_missing",
                                "selected native Go type answer is absent".into(),
                            )
                        });
                        BoundedResolution::Complete { value, work }
                    }
                    #[cfg(not(test))]
                    SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                        BoundedResolution::Complete {
                            value: unavailable_type(
                                query.site,
                                "native_missing",
                                "selected native Go type answer is absent".into(),
                            ),
                            work,
                        }
                    }
                    SelectedResolutionOperationOutcome::Unavailable(reason) => BoundedResolution::Complete {
                        value: unavailable_type(query.site, "native_unavailable", format!("{reason:?}")),
                        work,
                    },
                    SelectedResolutionOperationOutcome::Stale(reason) => BoundedResolution::Complete {
                        value: unavailable_type(query.site, "native_stale", format!("{reason:?}")),
                        work,
                    },
                    SelectedResolutionOperationOutcome::Cancelled(_) => {
                        BoundedResolution::Cancelled { work }
                    }
                }
            }
            Ok(BoundedResolution::Exceeded { limit, work }) => {
                BoundedResolution::Exceeded { limit, work }
            }
            Ok(BoundedResolution::Cancelled { work }) => BoundedResolution::Cancelled { work },
            Err(error) => BoundedResolution::Complete {
                value: unavailable_type(query.site, "native_store_error", error.to_string()),
                work: ReceiverAnalysisWork::default(),
            },
        }
    }

    fn resolve_definition_native(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> (
        BoundedResolution<(
            DefinitionLookupOutcome,
            Option<crate::analyzer::resolution::FactResolutionAnswer>,
        )>,
        Vec<GoSelectedExternalImport>,
    ) {
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        if cancellation.is_cancelled() {
            return (
                BoundedResolution::Cancelled {
                    work: ReceiverAnalysisWork::default(),
                },
                Vec::new(),
            );
        }
        if !self
            .go
            .inner
            .source_matches_selected_native_content(query.file, query.source)
        {
            return (
                BoundedResolution::Complete {
                    value: (
                        unavailable_definition(
                            query.site,
                            "native_source_mismatch",
                            "supplied native reference text differs from the admitted selected source"
                                .into(),
                        ),
                        None,
                    ),
                    work: ReceiverAnalysisWork::default(),
                },
                Vec::new(),
            );
        }
        let path = crate::path_utils::rel_path_string(query.file);
        let file_context = match self.file_context(&path, &cancellation) {
            Ok(Some(context)) => context,
            Ok(None) if cancellation.is_cancelled() => {
                return (
                    BoundedResolution::Cancelled {
                        work: ReceiverAnalysisWork::default(),
                    },
                    Vec::new(),
                );
            }
            Ok(None) => {
                return (
                    BoundedResolution::Complete {
                        value: (
                            unavailable_definition(
                                query.site,
                                "native_context_unavailable",
                                "selected native import context is unavailable".into(),
                            ),
                            None,
                        ),
                        work: ReceiverAnalysisWork::default(),
                    },
                    Vec::new(),
                );
            }
            Err(error) => {
                return (
                    BoundedResolution::Complete {
                        value: (
                            unavailable_definition(
                                query.site,
                                "native_store_error",
                                error.to_string(),
                            ),
                            None,
                        ),
                        work: ReceiverAnalysisWork::default(),
                    },
                    Vec::new(),
                );
            }
        };
        let parsed_tree = query
            .tree
            .is_none()
            .then(|| crate::analyzer::usages::get_definition::parse_go_tree(query.source))
            .flatten();
        let receiver_overlay = if let Some(tree) = query.tree.or(parsed_tree.as_ref()) {
            match self.point_receiver_slot_type_overlay(
                &path,
                &file_context,
                query,
                tree,
                &cancellation,
            ) {
                Ok(overlay) => overlay,
                Err(error) => {
                    return (
                        BoundedResolution::Complete {
                            value: (
                                unavailable_definition(
                                    query.site,
                                    "native_store_error",
                                    error.to_string(),
                                ),
                                None,
                            ),
                            work: ReceiverAnalysisWork::default(),
                        },
                        Vec::new(),
                    );
                }
            }
        } else {
            None
        };
        let call_selector = query.tree.or(parsed_tree.as_ref()).is_some_and(|tree| {
            go_call_selector_reference_at(
                tree,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
            )
        });
        let artifacts = self
            .forward_candidate_artifacts
            .entry(path.clone())
            .or_default();
        let selected_imports = file_context.selected_imports.clone();
        let locator = if call_selector {
            SelectedSemanticLocator::for_reference_range_in_namespace(
                "go",
                path,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
                ResolutionNamespace::Callable,
            )
        } else {
            SelectedSemanticLocator::for_reference_range(
                "go",
                path,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
            )
        };
        let mut metrics = SelectedResolutionContextMetrics;
        let native_sql_before = self
            .record_work
            .then(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows)
            .flatten();
        let native_started = self.record_work.then(Instant::now);
        let native = self
            .operation
            .resolve_native_reference_units_bounded_for_go_request(
                file_context.context,
                receiver_overlay,
                &locator,
                query.budget,
                &cancellation,
                &mut metrics,
                artifacts,
                &mut self.point_metrics,
            );
        if let Some(started) = native_started {
            self.phase_nanos.native_resolution += started.elapsed().as_nanos();
            if let (Some(before), Some(after)) = (
                native_sql_before,
                brokk_bifrost_core::cache_db::sql_profile::totals_with_rows(),
            ) {
                self.phase_nanos.native_sql += after.2 - before.2;
            }
        }
        let result = match native {
            Ok(BoundedResolution::Complete { value, work }) => {
                match value {
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) => match answer.definitions {
                        crate::analyzer::store::resolution_operation::SelectedNativeDefinitions::Cancelled => {
                            BoundedResolution::Cancelled { work }
                        }
                        _ => {
                            let native_answer = answer.answer.clone();
                            BoundedResolution::Complete {
                                value: (
                                    adapt_definition_answer(
                                        query.site,
                                        crate::analyzer::Language::Go,
                                        answer,
                                    ),
                                    Some(native_answer),
                                ),
                                work,
                            }
                        }
                    },
                    SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                        BoundedResolution::Complete {
                            value: (
                                unavailable_definition(
                                    query.site,
                                    "native_reference_unavailable",
                                    "the selected producer has no reference at this source range".into(),
                                ),
                                None,
                            ),
                            work,
                        }
                    }
                    SelectedResolutionOperationOutcome::Unavailable(reason) => BoundedResolution::Complete {
                        value: (
                            unavailable_definition(query.site, "native_unavailable", format!("{reason:?}")),
                            None,
                        ),
                        work,
                    },
                    SelectedResolutionOperationOutcome::Stale(reason) => BoundedResolution::Complete {
                        value: (
                            unavailable_definition(query.site, "native_stale", format!("{reason:?}")),
                            None,
                        ),
                        work,
                    },
                    SelectedResolutionOperationOutcome::Cancelled(_) => {
                        BoundedResolution::Cancelled { work }
                    }
                }
            }
            Ok(BoundedResolution::Exceeded { limit, work }) => {
                BoundedResolution::Exceeded { limit, work }
            }
            Ok(BoundedResolution::Cancelled { work }) => BoundedResolution::Cancelled { work },
            Err(error) => BoundedResolution::Complete {
                value: (
                    unavailable_definition(query.site, "native_store_error", error.to_string()),
                    None,
                ),
                work: ReceiverAnalysisWork::default(),
            },
        };
        (result, selected_imports)
    }

    pub(crate) fn resolve_definition_with_evidence(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<GoNativeDefinitionResolution> {
        let (mut native, selected_imports) = self.resolve_definition_native(query);
        let parsed_tree = query
            .tree
            .is_none()
            .then(|| crate::analyzer::usages::get_definition::parse_go_tree(query.source))
            .flatten();
        let mut sibling_query_error = None;
        if let Some(tree) = query.tree.or(parsed_tree.as_ref())
            && let BoundedResolution::Complete {
                value: (value, _), ..
            } = &mut native
            && value.status == DefinitionLookupStatus::Incomplete
            && go_point_selector_is_package_member_lookup(query, tree, &selected_imports)
        {
            let path = crate::path_utils::rel_path_string(query.file);
            let context_id = self
                .files
                .get(&path)
                .expect("an incomplete native Go point has a prepared file context")
                .context
                .demand
                .context_id;
            match self.operation.go_point_has_build_constrained_sibling(
                context_id,
                &path,
                &query.cancellation.cloned().unwrap_or_default(),
            ) {
                Ok(true) => attach_go_package_incomplete(value),
                Ok(false) => {}
                Err(error) => sibling_query_error = Some(error),
            }
        }
        if let Some(error) = sibling_query_error {
            let work = match &native {
                BoundedResolution::Complete { work, .. } => *work,
                BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => {
                    unreachable!("only a completed point answer checks package siblings")
                }
            };
            native = BoundedResolution::Complete {
                value: (
                    unavailable_definition(query.site, "native_store_error", error.to_string()),
                    None,
                ),
                work,
            };
        }
        finish_go_definition_resolution(
            query,
            self.go,
            self.overlay.clone(),
            selected_imports,
            native,
        )
    }

    pub(crate) fn resolve_definition_answer(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<Option<crate::analyzer::resolution::FactResolutionAnswer>> {
        match self.resolve_definition_native(query).0 {
            BoundedResolution::Complete {
                value: (_, answer),
                work,
            } => BoundedResolution::Complete {
                value: answer,
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        }
    }
}
#[cfg(test)]
fn external_callee_identity(
    proof: Option<&ExactExternalCallProof>,
) -> Option<ResolverOwnedExternalCalleeIdentity> {
    external_identity_from_proof(proof)
}

fn go_add_resolution_work(
    mut first: ReceiverAnalysisWork,
    second: ReceiverAnalysisWork,
) -> ReceiverAnalysisWork {
    first.setup_nodes = first.setup_nodes.saturating_add(second.setup_nodes);
    first.summary_expansions = first
        .summary_expansions
        .saturating_add(second.summary_expansions);
    first.scope_nodes = first.scope_nodes.saturating_add(second.scope_nodes);
    first
}

fn go_bare_identifier_is_call_target(
    root: tree_sitter::Node<'_>,
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
) -> bool {
    let Some(identifier) =
        smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return false;
    };
    if !matches!(identifier.kind(), "identifier" | "package_identifier") {
        return false;
    }
    identifier.parent().is_some_and(|callable| {
        callable.kind() == "call_expression"
            && callable
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == identifier.id())
    })
}

pub(super) fn append_model_backed_external_imports(
    unresolved_import_paths: impl IntoIterator<Item = String>,
    overlay: Option<&crate::analyzer::semantic_model::SemanticModelOverlay>,
    cancellation: &crate::CancellationToken,
    selected_imports: &mut Vec<GoSelectedExternalImport>,
) {
    let packages = crate::analyzer::go::package_identity::GoOverlayPackages::new(overlay);
    for import_path in unresolved_import_paths {
        if cancellation.is_cancelled() {
            return;
        }
        if selected_imports
            .iter()
            .any(|selected| selected.source_spelling == import_path)
        {
            continue;
        }
        let Some(identity) = packages.modeled_package_identity(&import_path) else {
            continue;
        };
        selected_imports.push(GoSelectedExternalImport {
            source_spelling: import_path.clone(),
            import_path,
            package_name: identity.package_name,
            provenance: GoExternalPackageProvenance::SemanticModel {
                symbol_id: identity.symbol_id,
                pack_id: identity.pack_id,
                pack_digest: identity.pack_digest,
                record_id: identity.record_id,
            },
        });
    }
}

pub(crate) fn resolve_go_definition_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    match resolve_go_definition_with_evidence_bounded(query, after_open) {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value: value.outcome,
            work,
        },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

pub(crate) fn resolve_go_definition_with_evidence_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<GoNativeDefinitionResolution> {
    let record_work = std::env::var_os("BIFROST_TRIAL_NATIVE_GO_POINT_WORK").is_some();
    let total_started = record_work.then(Instant::now);
    let sql_before = record_work
        .then(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows)
        .flatten();
    let path = record_work.then(|| crate::path_utils::rel_path_string(query.file));
    let focus = (query.site.focus_start_byte, query.site.focus_end_byte);
    let Some(go) = resolve_analyzer::<GoAnalyzer>(query.analyzer) else {
        return BoundedResolution::Complete {
            value: GoNativeDefinitionResolution {
                outcome: unavailable_definition(
                    query.site,
                    "native_analyzer_unavailable",
                    "Go analyzer is unavailable".into(),
                ),
                exact_external_call: None,
                call_application: CallApplicationKind::Unknown,
                external_callee_identity: None,
            },
            work: ReceiverAnalysisWork::default(),
        };
    };
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let open_started = record_work.then(Instant::now);
    let opened =
        GoNativePointRequest::open(go, query.analyzer.semantic_model_overlay(), &cancellation);
    let open_nanos = open_started.map_or(0, |started| started.elapsed().as_nanos());
    let mut request = match opened {
        Ok(GoNativePointRequestOpen::Ready(request)) => request,
        Ok(GoNativePointRequestOpen::Unavailable { kind, message }) => {
            return BoundedResolution::Complete {
                value: GoNativeDefinitionResolution {
                    outcome: unavailable_definition(query.site, kind, message),
                    exact_external_call: None,
                    call_application: CallApplicationKind::Unknown,
                    external_callee_identity: None,
                },
                work: ReceiverAnalysisWork::default(),
            };
        }
        Ok(GoNativePointRequestOpen::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return BoundedResolution::Complete {
                value: GoNativeDefinitionResolution {
                    outcome: unavailable_definition(
                        query.site,
                        "native_store_error",
                        error.to_string(),
                    ),
                    exact_external_call: None,
                    call_application: CallApplicationKind::Unknown,
                    external_callee_identity: None,
                },
                work: ReceiverAnalysisWork::default(),
            };
        }
    };
    after_open();
    let result = request.resolve_definition_with_evidence(query);
    if record_work {
        let sql_after = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
        let sql = sql_before
            .zip(sql_after)
            .map(|(before, after)| (after.0 - before.0, after.1 - before.1, after.2 - before.2));
        let work = match &result {
            BoundedResolution::Complete { work, .. }
            | BoundedResolution::Exceeded { work, .. }
            | BoundedResolution::Cancelled { work } => work,
        };
        let candidate_cache = request.operation.go_point_candidate_read_stats();
        let total_nanos = total_started
            .expect("point work logging starts a request timer")
            .elapsed()
            .as_nanos();
        let native_non_sql_nanos = request
            .phase_nanos
            .native_resolution
            .saturating_sub(request.phase_nanos.native_sql);
        let accounted_nanos = open_nanos
            .saturating_add(request.phase_nanos.file_context)
            .saturating_add(request.phase_nanos.native_resolution);
        let other_nanos = total_nanos.saturating_sub(accounted_nanos);
        eprintln!(
            "go_native_point_work kind=definition path={} focus={:?} sql={sql:?} phases_ns=(request:{total_nanos},open:{open_nanos},file_context:{},native_resolution:{},native_sql:{},native_non_sql:{native_non_sql_nanos},other:{other_nanos}) resolution={:?} receiver={work:?} candidate_cache={candidate_cache:?} request_file_contexts={}",
            path.expect("profile path is captured when point work logging is enabled"),
            focus,
            request.phase_nanos.file_context,
            request.phase_nanos.native_resolution,
            request.phase_nanos.native_sql,
            request.point_metrics,
            request.files.len(),
        );
    }
    result
}

fn finish_go_definition_resolution(
    query: BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
    overlay: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    selected_imports: Vec<GoSelectedExternalImport>,
    native: BoundedResolution<(
        DefinitionLookupOutcome,
        Option<crate::analyzer::resolution::FactResolutionAnswer>,
    )>,
) -> BoundedResolution<GoNativeDefinitionResolution> {
    match native {
        BoundedResolution::Complete {
            value: (mut outcome, _native_answer),
            work,
        } => {
            if query.cancellation.is_some_and(|token| token.is_cancelled()) {
                return BoundedResolution::Cancelled { work };
            }
            let mut call_application = CallApplicationKind::Unknown;
            let mut external_callee_identity = None;
            let mut exact_external_call = None;
            let external_projection_unavailable = outcome.status
                == DefinitionLookupStatus::Unavailable
                && outcome.diagnostics.iter().any(|diagnostic| {
                    diagnostic.kind == "native_definition_projection_unavailable"
                });
            let native_import_context_unavailable = outcome.status
                == DefinitionLookupStatus::Unavailable
                && outcome.diagnostics.iter().any(|diagnostic| {
                    matches!(
                        diagnostic.kind.as_str(),
                        "native_context_unavailable"
                            | "native_unavailable"
                            | "native_reference_unavailable"
                            | "native_definition_projection_unavailable"
                    )
                });
            let external_candidate_status = matches!(
                outcome.status,
                DefinitionLookupStatus::Resolved
                    | DefinitionLookupStatus::Incomplete
                    | DefinitionLookupStatus::NoDefinition
                    | DefinitionLookupStatus::UnresolvableImportBoundary
            ) || external_projection_unavailable
                || native_import_context_unavailable;
            let parsed_tree = (external_candidate_status && query.tree.is_none())
                .then(|| crate::analyzer::usages::get_definition::parse_go_tree(query.source))
                .flatten();
            let tree = query.tree.or(parsed_tree.as_ref());
            let selector = tree.and_then(|tree| {
                brokk_bifrost_go::graph::reference::go_selector_descriptor(
                    tree.root_node(),
                    query.site,
                )
            });
            let import_qualifier = selector.as_ref().is_some_and(|selector| {
                selector.focus_segment == 0
                    && matches!(selector.base.kind(), "identifier" | "package_identifier")
            });
            let external_package_member = selector.as_ref().is_some_and(|selector| {
                selector.focus_segment == 1
                    && selector.members.len() == 1
                    && matches!(selector.base.kind(), "identifier" | "package_identifier")
            });
            let identifier_call = tree.is_some_and(|tree| {
                go_identifier_call_reference_at(
                    tree,
                    query.site.focus_start_byte,
                    query.site.focus_end_byte,
                )
            });
            if external_candidate_status
                && (!selected_imports.is_empty()
                    || import_qualifier
                    || external_package_member
                    || identifier_call)
                && let Some(tree) = tree
            {
                let query_with_tree = BoundedReceiverQuery {
                    tree: Some(tree),
                    ..query
                };
                let external_session =
                        crate::analyzer::usages::get_definition::resolution_session::ResolutionSession::bounded(
                            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                                max_scope_nodes: query.budget.max_scope_nodes.saturating_sub(work.scope_nodes),
                                max_summary_expansions: query.budget.max_summary_expansions.saturating_sub(work.summary_expansions),
                                ..query.budget
                            },
                            query.cancellation,
                        );
                call_application =
                    crate::analyzer::usages::get_definition::go_native_call_application(
                        query_with_tree,
                        go,
                        &external_session,
                        overlay.clone(),
                        &selected_imports,
                    );
                let external = selector.as_ref().and_then(|selector| {
                        if !matches!(selector.base.kind(), "identifier" | "package_identifier") {
                            return None;
                        }
                        if selector.focus_segment == 0 {
                            selected_imports
                                .iter()
                                .find_map(|selected| {
                                    crate::analyzer::usages::get_definition::go_native_external_import_binding_resolution(
                                        query_with_tree,
                                        go,
                                        &external_session,
                                        selected,
                                    )
                                })
                                .map(|outcome| {
                                    (outcome, None, CallApplicationKind::Unknown, None)
                                })
                                .or_else(|| {
                                    crate::analyzer::usages::get_definition::go_native_import_namespace_resolution(
                                        query_with_tree,
                                        go,
                                        &external_session,
                                    )
                                    .map(|outcome| {
                                        (outcome, None, CallApplicationKind::Unknown, None)
                                    })
                                })
                        } else if selector.focus_segment == 1 {
                            selected_imports.iter().find_map(|selected| {
                                crate::analyzer::usages::get_definition::go_native_external_package_member_resolution(
                                        query_with_tree,
                                        go,
                                        &external_session,
                                        overlay.clone(),
                                        selected,
                                )
                            }).or_else(|| {
                                crate::analyzer::usages::get_definition::go_native_source_imported_member_resolution(
                                    query_with_tree,
                                    go,
                                    &external_session,
                                )
                            })
                        } else {
                            None
                        }
                    });
                if let Some((external_outcome, proof, application, identity)) = external {
                        outcome = external_outcome;
                        exact_external_call = proof;
                        call_application = application;
                        external_callee_identity = identity;
                    } else if let Some((external_outcome, proof, identity)) =
                        crate::analyzer::usages::get_definition::go_native_unmodeled_external_package_member_resolution(
                            query_with_tree,
                            go,
                            &external_session,
                            overlay.clone(),
                            &selected_imports,
                        )
                    {
                        outcome = external_outcome;
                        exact_external_call = proof;
                        external_callee_identity = identity;
                    } else if let Some((external_outcome, proof, application, identity)) =
                        crate::analyzer::usages::get_definition::go_native_external_dot_import_call_resolution(
                            query_with_tree,
                            go,
                            &external_session,
                        )
                    {
                        outcome = external_outcome;
                        exact_external_call = proof;
                        call_application = exact_external_call
                            .as_ref()
                            .map_or(application, ExactExternalCallProof::call_application);
                        external_callee_identity = identity;
                    } else if let Some((external_outcome, proof)) =
                        crate::analyzer::usages::get_definition::go_native_external_receiver_call_resolution(
                            query_with_tree,
                            &external_session,
                            &selected_imports,
                        )
                    {
                        outcome = external_outcome;
                        exact_external_call = Some(proof);
                        call_application = exact_external_call
                            .as_ref()
                            .map_or(CallApplicationKind::Unknown, ExactExternalCallProof::call_application);
                        external_callee_identity =
                            external_identity_from_proof(exact_external_call.as_ref());
                    } else if outcome.definitions.is_empty()
                        && let Some(call_outcome) = crate::analyzer::usages::get_definition::go_native_workspace_unqualified_call_resolution(
                            query_with_tree,
                            &external_session,
                        )
                    {
                        outcome = call_outcome;
                        outcome.reference.get_or_insert_with(|| query.site.clone());
                        call_application = CallApplicationKind::PackageFunction;
                    }
                if call_application == CallApplicationKind::Unknown
                    && outcome.status == DefinitionLookupStatus::Resolved
                    && outcome.definitions.len() == 1
                    && outcome.definitions[0].is_function()
                    && !outcome.definitions[0].owner_is_type_scope()
                    && go_bare_identifier_is_call_target(tree.root_node(), query.site)
                {
                    call_application = CallApplicationKind::PackageFunction;
                }
                if outcome.status == DefinitionLookupStatus::Resolved
                    && outcome.definitions.len() == 1
                    && outcome.definitions[0].is_function()
                    && outcome.definitions[0].owner_is_type_scope()
                    && matches!(
                        call_application,
                        CallApplicationKind::Unknown | CallApplicationKind::ReceiverBindingUnknown
                    )
                    && exact_external_call.is_none()
                {
                    call_application = crate::analyzer::usages::get_definition::go_native_local_receiver_call_application(
                            query_with_tree,
                            &external_session,
                        )
                        .unwrap_or(call_application);
                }
                match external_session.finish((
                    outcome,
                    call_application,
                    exact_external_call,
                    external_callee_identity,
                )) {
                    BoundedResolution::Complete {
                        value:
                            (outcome, call_application, exact_external_call, external_callee_identity),
                        work: external_work,
                    } => {
                        return BoundedResolution::Complete {
                            value: GoNativeDefinitionResolution {
                                outcome,
                                call_application,
                                exact_external_call,
                                external_callee_identity,
                            },
                            work: go_add_resolution_work(work, external_work),
                        };
                    }
                    BoundedResolution::Exceeded {
                        limit,
                        work: external_work,
                    } => {
                        return BoundedResolution::Exceeded {
                            limit,
                            work: go_add_resolution_work(work, external_work),
                        };
                    }
                    BoundedResolution::Cancelled {
                        work: external_work,
                    } => {
                        return BoundedResolution::Cancelled {
                            work: go_add_resolution_work(work, external_work),
                        };
                    }
                }
            }
            let external_callee_identity = external_callee_identity
                .or_else(|| external_identity_from_proof(exact_external_call.as_ref()));
            BoundedResolution::Complete {
                value: GoNativeDefinitionResolution {
                    outcome,
                    call_application,
                    exact_external_call,
                    external_callee_identity,
                },
                work,
            }
        }
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

pub(crate) fn resolve_go_type_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<TypeLookupOutcome> {
    let record_work = std::env::var_os("BIFROST_TRIAL_NATIVE_GO_POINT_WORK").is_some();
    let total_started = record_work.then(Instant::now);
    let sql_before = record_work
        .then(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows)
        .flatten();
    let path = record_work.then(|| crate::path_utils::rel_path_string(query.file));
    let focus = (query.site.focus_start_byte, query.site.focus_end_byte);
    let Some(go) = resolve_analyzer::<GoAnalyzer>(query.analyzer) else {
        return BoundedResolution::Complete {
            value: unavailable_type(
                query.site,
                "native_analyzer_unavailable",
                "Go analyzer is unavailable".into(),
            ),
            work: ReceiverAnalysisWork::default(),
        };
    };
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let open_started = record_work.then(Instant::now);
    let opened =
        GoNativePointRequest::open(go, query.analyzer.semantic_model_overlay(), &cancellation);
    let open_nanos = open_started.map_or(0, |started| started.elapsed().as_nanos());
    let mut request = match opened {
        Ok(GoNativePointRequestOpen::Ready(request)) => request,
        Ok(GoNativePointRequestOpen::Unavailable { kind, message }) => {
            return BoundedResolution::Complete {
                value: unavailable_type(query.site, kind, message),
                work: ReceiverAnalysisWork::default(),
            };
        }
        Ok(GoNativePointRequestOpen::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return BoundedResolution::Complete {
                value: unavailable_type(query.site, "native_store_error", error.to_string()),
                work: ReceiverAnalysisWork::default(),
            };
        }
    };
    after_open();
    let result = request.resolve_type(query);
    if record_work {
        let sql_after = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
        let sql = sql_before
            .zip(sql_after)
            .map(|(before, after)| (after.0 - before.0, after.1 - before.1, after.2 - before.2));
        let work = match &result {
            BoundedResolution::Complete { work, .. }
            | BoundedResolution::Exceeded { work, .. }
            | BoundedResolution::Cancelled { work } => work,
        };
        let candidate_cache = request.operation.go_point_candidate_read_stats();
        let total_nanos = total_started
            .expect("point work logging starts a request timer")
            .elapsed()
            .as_nanos();
        let native_non_sql_nanos = request
            .phase_nanos
            .native_resolution
            .saturating_sub(request.phase_nanos.native_sql);
        let accounted_nanos = open_nanos
            .saturating_add(request.phase_nanos.file_context)
            .saturating_add(request.phase_nanos.native_resolution);
        let other_nanos = total_nanos.saturating_sub(accounted_nanos);
        eprintln!(
            "go_native_point_work kind=type path={} focus={:?} sql={sql:?} phases_ns=(request:{total_nanos},open:{open_nanos},file_context:{},native_resolution:{},native_sql:{},native_non_sql:{native_non_sql_nanos},other:{other_nanos}) resolution={:?} receiver={work:?} candidate_cache={candidate_cache:?} request_file_contexts={}",
            path.expect("profile path is captured when point work logging is enabled"),
            focus,
            request.phase_nanos.file_context,
            request.phase_nanos.native_resolution,
            request.phase_nanos.native_sql,
            request.point_metrics,
            request.files.len(),
        );
    }
    result
}

#[cfg(test)]
#[path = "native_points/tests.rs"]
mod tests;

/// The no-type answer for a Go reference that names a type. The incumbent gives
/// this outcome, with this diagnostic, for a type-name site.
fn go_type_name_site_outcome(site: &ResolvedReferenceSite) -> TypeLookupOutcome {
    crate::analyzer::usages::get_type::no_type(
        "go_no_supported_type",
        format!("`{}` does not have a supported explicit Go type", site.text),
    )
}

/// The production Go point and type resolver.
pub(crate) struct GoNativeRolloutPoints;

impl crate::analyzer::languages::StructuralReceiverResolver for GoNativeRolloutPoints {
    fn reuses_request_scoped_native_points(&self) -> bool {
        true
    }

    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_go_type_bounded(query, || {})
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        resolve_go_definition_bounded(query, || {})
    }

    #[cfg(test)]
    fn resolve_definition_with_evidence_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<(DefinitionLookupOutcome, Option<ExactExternalCallProof>)> {
        match resolve_go_definition_with_evidence_bounded(query, || {}) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: (value.outcome, value.exact_external_call),
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        }
    }
}
