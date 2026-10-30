//! Go selected-context point resolver used by production queries.

use crate::analyzer::go::GoAnalyzer;
use brokk_bifrost_analysis::analyzer::resolution::SemanticId;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedLocalDeclarationOutcome;

use brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion;
use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::native_points::adapt_definition_answer;

use brokk_bifrost_analysis::analyzer::native_points::adapt_type_answer;

use brokk_bifrost_analysis::analyzer::native_points::open_native_point_operation;

use brokk_bifrost_analysis::analyzer::native_points::unavailable_definition;

use brokk_bifrost_analysis::analyzer::native_points::unavailable_type;

use brokk_bifrost_analysis::analyzer::resolution::batch::ForwardCandidateArtifactCache;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::GoReceiverSlotTypeOverlay;

use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeAssignmentValue;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoExternalPackageProvenance;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoPreparedImportContext;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoPreparedImportContextOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoSelectedExternalImport;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_receiver_anchor::GoReceiverAnchorMember;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_receiver_anchor::GoReceiverReferenceBinding;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_receiver_anchor::GoReceiverTypeAnchor;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupType;

use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;
use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub(crate) struct GoNativeDefinitionResolution {
    pub(crate) native_resolution: Option<Box<brokk_bifrost_analysis::analyzer::usages::get_definition::NativeResolutionCompletion>>,
    pub(crate) model_member_selection:
        Option<Box<brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeModelMemberSelection>>,
    pub(crate) outcome: DefinitionLookupOutcome,
    #[allow(dead_code)] // Consumed by Go call-target evidence when native routing is promoted.
    pub(crate) call_application: CallApplicationKind,
    pub(crate) exact_external_call: Option<ExactExternalCallProof>,
    pub(crate) external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
}

/// The legacy receiver-candidate call shape, from certified native bindings.
/// This names an external call without proving a method body or dispatch closure.
pub(crate) fn declared_external_receiver_call(
    operation: &mut SelectedResolutionOperation<'_, '_>,
    prepared: GoPreparedImportContext,
    query: BoundedReceiverQuery<'_>,
) -> brokk_bifrost_analysis::analyzer::store::Result<
    BoundedResolution<Option<ExactExternalCallProof>>,
> {
    use brokk_bifrost_analysis::analyzer::QueryScope;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    // Each call expression has its own remaining scope-work allowance, including
    // AST descent, parentheses and dependent argument-result shape resolution.
    let session = ResolutionSession::bounded(query.budget, query.cancellation);
    let syntax = (|| {
        let tree = query.tree?;
        let focused = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(tree.root_node(), query.site.focus_start_byte, query.site.focus_end_byte, || session.scope_step());
        let mut site = query.site.clone();
        if let Some(field) = focused
            .filter(|node| node.kind() == "selector_expression")
            .and_then(|node| node.child_by_field_name("field"))
        {
            site.focus_start_byte = field.start_byte();
            site.focus_end_byte = field.end_byte();
        }
        let query = BoundedReceiverQuery {
            site: &site,
            ..query
        };
        let selector = brokk_bifrost_go::references::go_selector_descriptor_with_scope(
            tree.root_node(),
            query.site,
            || session.scope_step(),
        )?;
        if selector.focus_segment != 1
            || selector.members.len() != 1
            || selector.base.kind() != "identifier"
        {
            return None;
        }
        let callable = selector.members[0]
            .parent()
            .expect("a selector field has its expression");
        let mut function = callable;
        while let Some(parent) = function
            .parent()
            .filter(|parent| parent.kind() == "parenthesized_expression")
        {
            if !session.scope_step() {
                return None;
            }
            function = parent;
        }
        let Some(call) = function.parent().filter(|call| {
            call.kind() == "call_expression"
                && call
                    .child_by_field_name("function")
                    .is_some_and(|node| node.id() == function.id())
        }) else {
            // Indexed/generic callables are not a declared receiver member proof.
            return None;
        };
        let _arguments = call
            .child_by_field_name("arguments")
            .filter(|arguments| !arguments.has_error() && !arguments.is_missing())?;
        let go = brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(query.analyzer)?;
        let scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(query.analyzer);
        let support =
            crate::analyzer::usages::get_definition::go::AnalyzerGoDefinitionProvider::bounded(
                go,
                &session,
                query.analyzer.semantic_model_overlay(),
            );
        let parameter_count =
            crate::analyzer::usages::get_definition::go::go_callable_modeled_argument_count(
                &support,
                scope.token(),
                go,
                query.file,
                query.source,
                function,
            )?;
        Some((
            selector,
            u32::try_from(parameter_count).expect("Go argument count fits call schema"),
        ))
    })();
    let (selector, parameter_count, syntax_work) = match session.finish(syntax) {
        BoundedResolution::Complete {
            value: Some((selector, count)),
            work,
        } => (selector, count, work),
        BoundedResolution::Complete { value: None, work } => {
            return Ok(BoundedResolution::Complete { value: None, work });
        }
        BoundedResolution::Exceeded { limit, work } => {
            return Ok(BoundedResolution::Exceeded { limit, work });
        }
        BoundedResolution::Cancelled { work } => return Ok(BoundedResolution::Cancelled { work }),
    };
    let tree = query.tree.expect("selected syntax has a tree");
    let remaining_syntax_budget = session.remaining_budget().expect("bounded session");
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let path = brokk_bifrost_core::path_utils::rel_path_string(query.file);
    let locator = SelectedSemanticLocator::for_reference_range(
        "go",
        &path,
        selector.base.start_byte(),
        selector.base.end_byte(),
    );
    let (definition, work) = match operation.resolve_local_declaration_bounded(
        &locator,
        remaining_syntax_budget,
        &cancellation,
    )? {
        BoundedResolution::Complete {
            value: SelectedResolutionOperationOutcome::Native(Some((_, definition))),
            work,
        } => (definition, go_add_resolution_work(syntax_work, work)),
        BoundedResolution::Complete { work, .. } => {
            return Ok(BoundedResolution::Complete {
                value: None,
                work: go_add_resolution_work(syntax_work, work),
            });
        }
        BoundedResolution::Exceeded { limit, work } => {
            return Ok(BoundedResolution::Exceeded {
                limit,
                work: go_add_resolution_work(syntax_work, work),
            });
        }
        BoundedResolution::Cancelled { work } => {
            return Ok(BoundedResolution::Cancelled {
                work: go_add_resolution_work(syntax_work, work),
            });
        }
    };
    // A Go local is declared in the reference file, so its range is in this tree.
    debug_assert!(
        definition
            .source_file
            .as_ref()
            .is_none_or(|file| file == query.file),
        "Go local declaration outside the reference file {:?}: {definition:?}",
        query.file
    );
    let mut proof = None;
    let declaration_session =
        ResolutionSession::bounded_after_shared_work(query.budget, query.cancellation, work);
    let result = (|| {
        let declaration = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(tree.root_node(), definition.name_range.start_byte, definition.name_range.end_byte, || declaration_session.scope_step())?
            .parent()?;
        if let Some(parameters) = declaration
            .parent()
            .filter(|node| node.kind() == "parameter_list")
        {
            if !declaration_session.scope_steps(parameters.named_child_count()) {
                return None;
            }
            if brokk_bifrost_go::declarations::go_parameter_syntax(parameters)
                .iter()
                .any(|parameter| {
                    parameter.variadic
                        && parameter.name_nodes.iter().any(|name| {
                            name.byte_range()
                                == (definition.name_range.start_byte
                                    ..definition.name_range.end_byte)
                        })
                })
            {
                return None;
            }
        }
        let mut ty = declaration.child_by_field_name("type")?;
        if ty.kind() == "pointer_type" {
            ty = ty.named_child(0)?;
        }
        if ty.kind() != "qualified_type" || ty.has_error() || ty.is_missing() {
            return None;
        }
        let package = ty.child_by_field_name("package")?;
        let name = ty.child_by_field_name("name")?;
        let member = selector.members[0];
        Some((package, name, member))
    })();
    let (result, work) = match declaration_session.finish(result) {
        BoundedResolution::Complete { value, work } => (value, work),
        BoundedResolution::Exceeded { limit, work } => {
            return Ok(BoundedResolution::Exceeded { limit, work });
        }
        BoundedResolution::Cancelled { work } => return Ok(BoundedResolution::Cancelled { work }),
    };
    let Some((package, name, member)) = result else {
        return Ok(BoundedResolution::Complete { value: proof, work });
    };
    let locator = SelectedSemanticLocator::for_reference_range(
        "go",
        &path,
        package.start_byte(),
        package.end_byte(),
    );
    let remaining =
        brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
            max_scope_nodes: query
                .budget
                .max_scope_nodes
                .saturating_sub(work.scope_nodes),
            max_summary_expansions: query
                .budget
                .max_summary_expansions
                .saturating_sub(work.summary_expansions),
            max_resolution_rounds: query
                .budget
                .max_resolution_rounds
                .saturating_sub(work.resolution_rounds),
            ..query.budget
        };
    match operation.resolve_go_unindexed_import_bounded(
        prepared,
        &locator,
        remaining,
        &cancellation,
    )? {
        BoundedResolution::Complete {
            value,
            work: import_work,
        } => {
            if let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                Some(package),
            )) = value
            {
                let owner = format!(
                    "{}.{}",
                    package,
                    name.utf8_text(query.source.as_bytes())
                        .expect("selected type name is UTF-8")
                );
                let member = member
                    .utf8_text(query.source.as_bytes())
                    .expect("selected member is UTF-8");
                proof = Some(ExactExternalCallProof::go_receiver_candidate(
                    format!("{owner}.{member}"),
                    parameter_count,
                ));
            }
            Ok(BoundedResolution::Complete {
                value: proof,
                work: go_add_resolution_work(work, import_work),
            })
        }
        BoundedResolution::Exceeded {
            limit,
            work: import_work,
        } => Ok(BoundedResolution::Exceeded {
            limit,
            work: go_add_resolution_work(work, import_work),
        }),
        BoundedResolution::Cancelled { work: import_work } => Ok(BoundedResolution::Cancelled {
            work: go_add_resolution_work(work, import_work),
        }),
    }
}

fn external_identity_from_proof(
    proof: Option<&ExactExternalCallProof>,
) -> Option<ResolverOwnedExternalCalleeIdentity> {
    let proof = proof?;
    let (owner_fqn, member) =
        brokk_bifrost_analysis::analyzer::semantic::split_canonical_qualified_callee(
            proof.canonical_callee(),
            brokk_bifrost_core::analyzer::model::Language::Go,
        )?;
    Some(ResolverOwnedExternalCalleeIdentity::new(
        brokk_bifrost_core::analyzer::model::Language::Go,
        owner_fqn,
        member,
    ))
}

/// A model-owned declaration proof, separate from a value type and from the
/// durable JVM inventory's overload coordinates.
struct GoOverlayDefinitionProjection {
    direct_target: GoOverlayDirectTarget,
}

struct GoOverlayDirectTarget {
    provider_digest: String,
    canonical_symbol: String,
}

#[derive(Clone)]
struct GoPointFileContext {
    context: GoPreparedImportContext,
    selected_imports: Vec<GoSelectedExternalImport>,
}

/// Read a declaration-site method's owner from indexed declaration identity and
/// metadata, rather than inferring ownership from surrounding source syntax.
fn go_interface_method_owner_type(
    query: BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
) -> Option<TypeLookupOutcome> {
    let mut owners = go
        .declarations(query.file)
        .into_iter()
        .filter(|unit| {
            unit.is_function()
                && unit.owner_is_type_scope()
                && unit.terminal_name() == query.site.text
        })
        .filter(|unit| {
            go.ranges(unit).iter().any(|range| {
                range.start_byte == query.site.focus_start_byte
                    && query.site.focus_end_byte <= range.end_byte
            })
        })
        .filter(|method| {
            go.signature_metadata(method).iter().any(|metadata| {
                metadata.dispatch_extensibility()
                    == Some(brokk_bifrost_core::analyzer::model::DispatchExtensibility::Open)
            })
        })
        .filter_map(|method| go.parent_of(&method))
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
        target_kind: TypeLookupTargetKind::MemberOwner {
            member_name: query.site.text.clone(),
        },
    })
}

/// The producer has no answer for this site. That is a structured miss, not a
/// failure of the store, so it is incomplete evidence rather than unavailable.
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
    go_point_call_expression_callee_reference(initializer)
}

fn go_point_call_expression_callee_reference(
    call: tree_sitter::Node<'_>,
) -> Option<(usize, usize)> {
    if !matches!(
        call.kind(),
        "call_expression" | "type_conversion_expression"
    ) {
        return None;
    }
    go_point_expression_value_anchor_reference(call)
}

fn go_point_argument_value_anchor(
    mut expression: tree_sitter::Node<'_>,
) -> Option<(usize, usize, u32)> {
    while let Some(parent) = expression
        .parent()
        .filter(|node| node.kind() == "parenthesized_expression")
    {
        expression = parent;
    }
    let arguments = expression
        .parent()
        .filter(|node| node.kind() == "argument_list")?;
    let call = arguments.parent()?;
    if call.child_by_field_name("arguments") != Some(arguments) {
        return None;
    }
    let (start, end) = go_point_call_expression_callee_reference(call)?;
    let mut cursor = arguments.walk();
    let ordinal = arguments
        .named_children(&mut cursor)
        .filter(|node| !node.is_extra())
        .position(|argument| argument == expression)?;
    Some((
        start,
        end,
        u32::try_from(ordinal).expect("Go call argument ordinal fits u32"),
    ))
}

fn go_point_expression_value_anchor_reference(
    expression: tree_sitter::Node<'_>,
) -> Option<(usize, usize)> {
    let mut callee = match expression.kind() {
        "call_expression" => expression.child_by_field_name("function")?,
        // tree-sitter-go can represent a generic function invocation with
        // arguments as a type-conversion node. The keyed call-obligation read
        // below distinguishes it from a real conversion.
        "type_conversion_expression" | "composite_literal" => {
            expression.child_by_field_name("type")?
        }
        _ => return None,
    };
    loop {
        callee = match callee.kind() {
            "identifier" | "type_identifier" | "field_identifier" => {
                return Some((callee.start_byte(), callee.end_byte()));
            }
            "selector_expression" => callee.child_by_field_name("field")?,
            "qualified_type" => callee.child_by_field_name("name")?,
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
        brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)
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
                .as_deref()
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

fn attach_go_package_incomplete(outcome: &mut DefinitionLookupOutcome, package: &str) {
    if outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "go-package-incomplete")
    {
        return;
    }
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "go-package-incomplete".into(),
        message: format!(
            "package {package:?} has unselected source input, so selected package members may be absent"
        ),
        claim: None,
    });
}

fn go_declaration_definition(
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    definitions: Vec<(
        brokk_bifrost_analysis::analyzer::resolution::model::SemanticId,
        brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinition,
    )>,
) -> Option<DefinitionLookupOutcome> {
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinition;

    if definitions.is_empty() {
        return None;
    }
    let mut units = Vec::new();
    let mut lexical_definition = None;
    for (_, definition) in definitions {
        match definition {
            SelectedNativeDefinition::Unit(unit) => units.push(unit),
            SelectedNativeDefinition::Lexical(definition) => lexical_definition = Some(definition),
            SelectedNativeDefinition::Intrinsic { .. } => {
                debug_assert!(
                    false,
                    "a declaration identifier cannot denote an intrinsic definition"
                );
            }
        }
    }
    Some(DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status: DefinitionLookupStatus::Resolved,
        reference: Some(site.clone()),
        definitions: units,
        lexical_definition,
        diagnostics: Vec::new(),
    })
}

struct GoNativeDefinitionEvidence {
    model_selection: Option<Box<brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeModelMemberSelection>>,
    answer: brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactResolutionAnswer,
    receiver_application: Option<CallApplicationKind>,
}

enum GoDefinitionOperation<T> {
    Native {
        value: T,
        work: ReceiverAnalysisWork,
    },
    Failed(Box<BoundedResolution<(DefinitionLookupOutcome, Option<GoNativeDefinitionEvidence>)>>),
}

fn go_definition_operation<T>(
    site: &ResolvedReferenceSite,
    result: brokk_bifrost_analysis::analyzer::store::Result<
        BoundedResolution<SelectedResolutionOperationOutcome<T>>,
    >,
) -> GoDefinitionOperation<T> {
    match result {
        Ok(BoundedResolution::Complete {
            value: SelectedResolutionOperationOutcome::Native(value),
            work,
        }) => GoDefinitionOperation::Native { value, work },
        Ok(BoundedResolution::Complete {
            value: SelectedResolutionOperationOutcome::Unavailable(reason),
            work,
        }) => GoDefinitionOperation::Failed(Box::new(BoundedResolution::Complete {
            value: (
                unavailable_definition(site, "native_unavailable", format!("{reason:?}")),
                None,
            ),
            work,
        })),
        Ok(BoundedResolution::Complete {
            value: SelectedResolutionOperationOutcome::Stale(reason),
            work,
        }) => GoDefinitionOperation::Failed(Box::new(BoundedResolution::Complete {
            value: (
                unavailable_definition(site, "native_stale", format!("{reason:?}")),
                None,
            ),
            work,
        })),
        Ok(BoundedResolution::Complete {
            value: SelectedResolutionOperationOutcome::Cancelled(_),
            work,
        })
        | Ok(BoundedResolution::Cancelled { work }) => {
            GoDefinitionOperation::Failed(Box::new(BoundedResolution::Cancelled { work }))
        }
        Ok(BoundedResolution::Exceeded { limit, work }) => {
            GoDefinitionOperation::Failed(Box::new(BoundedResolution::Exceeded { limit, work }))
        }
        Err(error) => GoDefinitionOperation::Failed(Box::new(BoundedResolution::Complete {
            value: (
                unavailable_definition(site, "native_store_error", error.to_string()),
                None,
            ),
            work: ReceiverAnalysisWork::default(),
        })),
    }
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

#[doc(hidden)]
pub struct GoNativePointRequest<'a> {
    go: &'a GoAnalyzer,
    operation: SelectedResolutionOperation<'a, 'a>,
    base_profile: [u8; 32],
    overlay: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
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

#[doc(hidden)]
pub enum GoNativePointRequestOpen<'a> {
    Ready(Box<GoNativePointRequest<'a>>),
    Unavailable { kind: &'static str, message: String },
    Cancelled,
}

impl<'a> GoNativePointRequest<'a> {
    pub(crate) fn import_diagnostic_view(
        &self,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<
        brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoImportDiagnosticView,
    >>{
        let path = brokk_bifrost_core::path_utils::rel_path_string(file);
        let Some(selected) = self
            .operation
            .go_context_for_file(&self.base_profile, &path)?
        else {
            return Ok(None);
        };
        self.operation
            .go_import_diagnostic_view(selected.context_id, &path, cancellation)
    }

    pub(crate) fn resolve_local_declaration(
        &mut self,
        locator: &SelectedSemanticLocator,
        budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        BoundedResolution<SelectedLocalDeclarationOutcome>,
    > {
        self.operation
            .resolve_local_declaration_bounded(locator, budget, cancellation)
    }

    #[cfg(test)]
    pub(crate) fn method_family_for_test(
        &self,
        target: &brokk_bifrost_core::analyzer::model::CodeUnit,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::store::resolution_operation::go_method_family::GoMethodFamily,
    >{
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::GoReverseCandidateOutcome;
        let path = brokk_bifrost_core::path_utils::rel_path_string(target.source());
        let (context, profile) = self
            .operation
            .go_contexts_for_file(&self.base_profile, &path)?
            .pop()
            .expect("target belongs to a context");
        match self.operation.go_reverse_candidate_sites(
            target,
            context.context_id,
            true,
            &profile,
            cancellation,
        )? {
            GoReverseCandidateOutcome::Ready(candidates) => Ok(candidates.family),
            GoReverseCandidateOutcome::TargetUncovered(reason)
            | GoReverseCandidateOutcome::Unavailable(reason) => Err(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(reason),
            ),
            GoReverseCandidateOutcome::Cancelled => Err(
                brokk_bifrost_analysis::analyzer::store::StoreError::new("family query cancelled"),
            ),
        }
    }

    pub(crate) fn begin_receiver_query(
        &mut self,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    ) {
        if let Some(cache) = self
            .forward_candidate_artifacts
            .get_mut(&brokk_bifrost_core::path_utils::rel_path_string(file))
        {
            cache.reset_owner_expansions();
        }
    }
    #[doc(hidden)]
    pub fn open(
        go: &'a GoAnalyzer,
        overlay: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<GoNativePointRequestOpen<'a>> {
        if cancellation.is_cancelled() {
            return Ok(GoNativePointRequestOpen::Cancelled);
        }
        if !go.inner.workspace_declaration_identities_authoritative() {
            return Ok(GoNativePointRequestOpen::Unavailable {
                kind: "native_identity_authority_unavailable",
                message: "selected native declaration identities are not authoritative".into(),
            });
        }
        let Some(base_profile) = go.native_context_base_profile() else {
            return Ok(GoNativePointRequestOpen::Unavailable {
                kind: "native_context_unavailable",
                message: "selected Go package/import base profile is unavailable".into(),
            });
        };
        let operation = match open_native_point_operation(&go.inner, cancellation)? {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => {
                (*operation).with_go_model_authority(overlay.clone().map(|overlay| overlay as Arc<dyn brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedModelAuthority + Send + Sync>))
            }
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
            base_profile,
            overlay,
            files: HashMap::default(),
            forward_candidate_artifacts: HashMap::default(),
            point_metrics: ResolutionBatchMetrics::default(),
            record_work: std::env::var_os("BIFROST_TRIAL_NATIVE_GO_POINT_WORK").is_some(),
            phase_nanos: GoPointPhaseNanos::default(),
        })))
    }

    /// A file-scoped request binds authority before any answer or fast path.
    #[doc(hidden)]
    pub fn open_for_file(
        go: &'a GoAnalyzer,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        overlay: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<GoNativePointRequestOpen<'a>> {
        let opened = Self::open(go, overlay, cancellation)?;
        if let GoNativePointRequestOpen::Ready(request) = &opened {
            let path = brokk_bifrost_core::path_utils::rel_path_string(file);
            if request
                .operation
                .go_context_for_file(&request.base_profile, &path)?
                .is_none()
            {
                return Ok(GoNativePointRequestOpen::Unavailable {
                    kind: "native_context_unavailable",
                    message: format!("selected Go context has no workspace source {path}"),
                });
            }
        }
        Ok(opened)
    }

    fn open_for_query(
        query: BoundedReceiverQuery<'a>,
        profile: &mut Option<GoPointWorkProfile>,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<GoNativePointRequestOpen<'a>> {
        let Some(go) = resolve_analyzer::<GoAnalyzer>(query.analyzer) else {
            return Ok(GoNativePointRequestOpen::Unavailable {
                kind: "native_analyzer_unavailable",
                message: "Go analyzer is unavailable".into(),
            });
        };
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        let open_started = profile.as_ref().map(|_| Instant::now());
        // The delegate owns the store, but a composite analyzer may own the
        // overlay authority. Include overlay acquisition in the open interval.
        let opened = Self::open_for_file(
            go,
            query.file,
            query.analyzer.semantic_model_overlay(),
            &cancellation,
        );
        let open_nanos = open_started.map_or(0, |started| started.elapsed().as_nanos());
        if let Some(profile) = profile {
            profile.open_nanos = open_nanos;
        }
        opened
    }

    /// The selected operation and Go context the unit-summary differential test
    /// uses as the incumbent readers' oracle.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn oracle_for_test(
        &mut self,
        path: &str,
    ) -> (&mut SelectedResolutionOperation<'a, 'a>, i64) {
        let context = self
            .operation
            .go_context_for_file(&self.base_profile, path)
            .expect("select oracle context")
            .expect("oracle source belongs to a context");
        (&mut self.operation, context.context_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn resolve_assignment_value_bounded(
        &mut self,
        path: &str,
        locator: &SelectedSemanticLocator,
        budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<
            BoundedResolution<
                SelectedResolutionOperationOutcome<
                    SelectedResolutionLocated<SelectedNativeAssignmentValue>,
                >,
            >,
        >,
    > {
        if cancellation.is_cancelled() {
            return Ok(Some(BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            }));
        }
        let Some(file_context) = self.file_context(path, cancellation)? else {
            return Ok(None);
        };
        self.operation
            .resolve_go_assignment_value_bounded(
                file_context.context,
                locator,
                budget,
                cancellation,
            )
            .map(Some)
    }

    fn file_context(
        &mut self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<GoPointFileContext>> {
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
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<GoReceiverSlotTypeOverlay>> {
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
                brokk_bifrost_analysis::analyzer::resolution::model::ResolutionSlotValue::runtime(
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
        let overlay = GoReceiverSlotTypeOverlay::new(
            slot,
            receiver_type,
            canonical.into_boxed_slice(),
            chain_slots.into_boxed_slice(),
            (query_reference, member),
            query_result_slot,
        );
        Ok(Some(overlay))
    }

    fn prepare_file_context(
        &mut self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<GoPointFileContext>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(context) = self.files.get(path) {
            return Ok(Some(context.clone()));
        }
        let Some(selected) = self
            .operation
            .go_context_for_file(&self.base_profile, path)?
        else {
            return Ok(None);
        };
        let GoPreparedImportContextOutcome::Ready(context) = self
            .operation
            .go_file_import_context(selected.context_id, path, cancellation)?
        else {
            return Ok(None);
        };
        let selected_imports =
            self.operation
                .go_selected_external_imports(selected.context_id, path, cancellation)?;
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

    fn revalidate_answer<T>(
        &mut self,
        answer: BoundedResolution<T>,
        cancellation: &CancellationToken,
        unavailable: impl FnOnce(&'static str, String) -> T,
    ) -> BoundedResolution<T> {
        let BoundedResolution::Complete { value, work } = answer else {
            return answer;
        };
        let failed =
            match self
                .operation
                .finish_native(value, &ResolutionCompletion::Complete, cancellation)
            {
                Ok(SelectedResolutionOperationOutcome::Native(value)) => {
                    return BoundedResolution::Complete { value, work };
                }
                Ok(SelectedResolutionOperationOutcome::Cancelled(_)) => {
                    return BoundedResolution::Cancelled { work };
                }
                Ok(SelectedResolutionOperationOutcome::Stale(reason)) => {
                    ("native_stale", format!("{reason:?}"))
                }
                Ok(SelectedResolutionOperationOutcome::Unavailable(reason)) => {
                    ("native_unavailable", format!("{reason:?}"))
                }
                Err(error) => ("native_store_error", error.to_string()),
            };
        BoundedResolution::Complete {
            value: unavailable(failed.0, failed.1),
            work,
        }
    }

    pub(crate) fn go_static_type_member(
        &mut self,
        query: BoundedReceiverQuery<'_>,
        receiver: brokk_bifrost_analysis::analyzer::resolution::ResolutionTypeRef,
        member_name: &str,
        receiver_addressable: bool,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<BoundedResolution<Option<brokk_bifrost_analysis::analyzer::store::resolution_operation::go_receiver_anchor::GoStaticTypeMember>>>{
        use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        let session = ResolutionSession::bounded(query.budget, Some(&cancellation));
        let path = brokk_bifrost_core::path_utils::rel_path_string(query.file);
        let Some(context) = self.file_context(&path, &cancellation)? else {
            return Ok(session.finish(None));
        };
        let lookup = self.operation.go_static_member_lookup(member_name);
        Ok(
            match self.operation.go_static_type_member(
                context.context,
                &path,
                receiver,
                lookup,
                receiver_addressable,
                &cancellation,
                &session,
            )? {
                BoundedResolution::Complete {
                    value: SelectedResolutionOperationOutcome::Native(value),
                    work,
                } => BoundedResolution::Complete {
                    value: Some(value),
                    work,
                },
                BoundedResolution::Complete {
                    value: SelectedResolutionOperationOutcome::Cancelled(_),
                    work,
                }
                | BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
                BoundedResolution::Complete { work, .. } => {
                    BoundedResolution::Complete { value: None, work }
                }
                BoundedResolution::Exceeded { limit, work } => {
                    BoundedResolution::Exceeded { limit, work }
                }
            },
        )
    }

    pub(crate) fn resolve_type(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        self.resolve_type_with_evidence(query, |_| {})
    }

    pub(crate) fn resolve_type_with_evidence(
        &mut self,
        query: BoundedReceiverQuery<'_>,
        evidence: impl FnMut(&brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedNativeReferenceTypes),
    ) -> BoundedResolution<TypeLookupOutcome> {
        let answer = self.resolve_type_inner(query, None, evidence);
        self.revalidate_answer(
            answer,
            &query.cancellation.cloned().unwrap_or_default(),
            |kind, message| unavailable_type(query.site, kind, message),
        )
    }

    pub(crate) fn resolve_declared_type_with_evidence(
        &mut self,
        query: BoundedReceiverQuery<'_>,
        definition: SemanticId,
        evidence: impl FnMut(&brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedNativeReferenceTypes),
    ) -> BoundedResolution<TypeLookupOutcome> {
        let answer = self.resolve_type_inner(query, Some(definition), evidence);
        self.revalidate_answer(
            answer,
            &query.cancellation.cloned().unwrap_or_default(),
            |kind, message| unavailable_type(query.site, kind, message),
        )
    }

    fn resolve_type_inner(
        &mut self,
        query: BoundedReceiverQuery<'_>,
        definition: Option<SemanticId>,
        mut evidence: impl FnMut(&brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedNativeReferenceTypes),
    ) -> BoundedResolution<TypeLookupOutcome> {
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        if cancellation.is_cancelled() {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        let path = brokk_bifrost_core::path_utils::rel_path_string(query.file);
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
        let parsed_tree = query
            .tree
            .is_none()
            .then(|| crate::analyzer::usages::get_definition::go::parse_go_tree(query.source))
            .flatten();
        // A whole expression asks for its produced value, rather than its
        // anchor binding. Go's AST fields select the anchor; persisted call
        // obligations or construction transfers select its exact value slot.
        let selected_expression = query.tree.or(parsed_tree.as_ref()).and_then(|tree| {
            let selected = smallest_named_node_covering(
                tree.root_node(),
                query.site.focus_start_byte,
                query.site.focus_end_byte,
            )?;
            (selected.start_byte() == query.site.focus_start_byte
                && selected.end_byte() == query.site.focus_end_byte)
                .then_some(selected)
        });
        let expression_anchor =
            selected_expression.and_then(go_point_expression_value_anchor_reference);
        // Computed call arguments already have an exact persisted input slot.
        // Use that slot, not the callee's return type or an operand's type.
        let argument_anchor = selected_expression
            .filter(|node| {
                expression_anchor.is_none()
                    && node.named_child_count() > 0
                    && !matches!(node.kind(), "selector_expression" | "qualified_type")
            })
            .and_then(go_point_argument_value_anchor);
        let expression_value = if let Some((start, end)) = expression_anchor {
            match self
                .operation
                .go_point_expression_value_slot_at(&path, start, end, &cancellation)
            {
                Ok(slot) => slot,
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
        let mut selected_site = query.site.clone();
        if let Some((start, end)) = argument_anchor
            .map(|(start, end, _)| (start, end))
            .or_else(|| expression_anchor.filter(|_| expression_value.is_some()))
        {
            selected_site.focus_start_byte = start;
            selected_site.focus_end_byte = end;
        }
        let selected_query = BoundedReceiverQuery {
            site: &selected_site,
            ..query
        };
        let receiver_overlay = if let Some(tree) = query.tree.or(parsed_tree.as_ref()) {
            match self.point_receiver_slot_type_overlay(
                &path,
                &file_context,
                selected_query,
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
                selected_site.focus_start_byte,
                selected_site.focus_end_byte,
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
                selected_site.focus_start_byte,
                selected_site.focus_end_byte,
                ResolutionNamespace::TypeOrValue,
            )
        } else {
            SelectedSemanticLocator::for_reference_range(
                "go",
                path,
                selected_site.focus_start_byte,
                selected_site.focus_end_byte,
            )
        };
        let locator = if let Some((_, _, ordinal)) = argument_anchor {
            locator.with_call_argument_ordinal(ordinal)
        } else {
            locator
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
                expression_value,
                receiver_overlay,
                &locator,
                definition,
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
                    ) => {
                        evidence(&answer);
                        match answer.value_types {
                        brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeTypes::Cancelled => {
                            BoundedResolution::Cancelled { work }
                        }
                        // A whole expression's type anchor retains TypeReference
                        // metadata, but its explicit value slot is the result.
                        // Only bare type positions have no value type. The type
                        // child of a composite literal selects the expression.
                        _ if answer.query_result_slot.is_none()
                            && answer.answer.site_metadata().is_some_and(|metadata| {
                            metadata.site_kind()
                                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::TypeReference
                        }) => {
                            BoundedResolution::Complete {
                                value: if query.tree.or(parsed_tree.as_ref()).is_some_and(|tree| {
                                    let Some(selected) = smallest_named_node_covering(
                                        tree.root_node(),
                                        query.site.focus_start_byte,
                                        query.site.focus_end_byte,
                                    ) else {
                                        return false;
                                    };
                                    selected.parent().is_some_and(|parent| {
                                        parent.kind() == "composite_literal"
                                            && parent.child_by_field_name("type") == Some(selected)
                                    })
                                }) {
                                    adapt_type_answer(query.site, brokk_bifrost_core::analyzer::model::Language::Go, answer)
                                } else {
                                    go_type_name_site_outcome(query.site)
                                },
                                work,
                            }
                        }
                        _ => BoundedResolution::Complete {
                            value: adapt_type_answer(query.site, brokk_bifrost_core::analyzer::model::Language::Go, answer),
                            work,
                        },
                    }
                    }
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Missing,
                    ) => {
                        let value =
                            go_interface_method_owner_type(query, self.go).unwrap_or_else(|| {
                                let type_parameter_declaration =
                                    query.tree.or(parsed_tree.as_ref()).is_some_and(|tree| {
                                        let Some(selected) = smallest_named_node_covering(
                                            tree.root_node(),
                                            query.site.focus_start_byte,
                                            query.site.focus_end_byte,
                                        ) else {
                                            return false;
                                        };
                                        selected.parent().is_some_and(|parent| {
                                            parent.kind() == "type_parameter_declaration" && {
                                                let mut cursor = parent.walk();
                                                parent
                                                    .children_by_field_name("name", &mut cursor)
                                                    .any(|name| name == selected)
                                            }
                                        })
                                    });
                                if type_parameter_declaration {
                                    go_type_name_site_outcome(query.site)
                                } else {
                                    incomplete_go_type(
                                        query.site,
                                        "native_missing",
                                        "selected native Go type answer is absent".into(),
                                    )
                                }
                            });
                        BoundedResolution::Complete { value, work }
                    }
                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                        BoundedResolution::Complete {
                            value: unavailable_type(
                                query.site,
                                "native_unavailable",
                                format!("{reason:?}"),
                            ),
                            work,
                        }
                    }
                    SelectedResolutionOperationOutcome::Stale(reason) => {
                        BoundedResolution::Complete {
                            value: unavailable_type(
                                query.site,
                                "native_stale",
                                format!("{reason:?}"),
                            ),
                            work,
                        }
                    }
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
        BoundedResolution<(DefinitionLookupOutcome, Option<GoNativeDefinitionEvidence>)>,
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
        let path = brokk_bifrost_core::path_utils::rel_path_string(query.file);
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
        let parsed_tree = query
            .tree
            .is_none()
            .then(|| crate::analyzer::usages::get_definition::go::parse_go_tree(query.source))
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
        let selected_imports = file_context.selected_imports.clone();
        let declaration_locator = SelectedSemanticLocator::for_declaration_range(
            "go",
            &path,
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        );
        let declaration = self.operation.declaration_at_range_bounded(
            &declaration_locator,
            query.budget,
            &cancellation,
            |ready, definitions, cancellation, session| {
                brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::project_native_definition_units(
                    ready,
                    definitions,
                    cancellation,
                    session,
                )
            },
            brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinitions::Cancelled,
        );
        if let Some(result) = declaration.transpose() {
            match go_definition_operation(query.site, result) {
                GoDefinitionOperation::Native {
                    value: definitions,
                    work,
                } => match definitions {
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinitions::Ready(definitions) => {
                        if let Some(outcome) = go_declaration_definition(query.site, definitions) {
                            return (
                                BoundedResolution::Complete {
                                    value: (outcome, None),
                                    work,
                                },
                                selected_imports,
                            );
                        }
                    }
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinitions::Cancelled => {
                        return (BoundedResolution::Cancelled { work }, selected_imports);
                    }
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinitions::Unavailable => {
                        return (
                            BoundedResolution::Complete {
                                value: (
                                    unavailable_definition(
                                        query.site,
                                        "native_definition_projection_unavailable",
                                        "selected declaration has no supported source projection".into(),
                                    ),
                                    None,
                                ),
                                work,
                            },
                            selected_imports,
                        );
                    }
                },
                GoDefinitionOperation::Failed(failure) => {
                    return (*failure, selected_imports);
                }
            }
        }
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
        let locator = if call_selector {
            SelectedSemanticLocator::for_reference_range_preferring_namespace(
                "go",
                path,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
                // Go call sites share their reference with conversions; the
                // resolver orders its Value and Type lookup routes. Method
                // selectors use Callable references over the same token.
                ResolutionNamespace::TypeOrValue,
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
        let result = match go_definition_operation(query.site, native) {
            GoDefinitionOperation::Native {
                value: SelectedResolutionLocated::Found(answer),
                work,
            } => match answer.definitions {
                brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinitions::Cancelled => {
                    BoundedResolution::Cancelled { work }
                }
                _ => {
                    // The selected member route already records whether lookup
                    // started from a runtime value or a type qualifier. Do not
                    // resolve its base again with a second type evaluator.
                    let mut members = answer
                        .member_contexts
                        .iter()
                        .filter(|member| member.selected)
                        .peekable();
                    let local_receiver_application = (members.peek().is_some()
                        && members.all(|member| {
                            member.route_kind
                                == brokk_bifrost_analysis::analyzer::resolution::FactMemberRouteKind::Member
                        }))
                    .then_some(CallApplicationKind::BoundReceiver);
                    let native_answer = answer.answer.clone();
                    let model_selection = answer.model_member_selection.clone().filter(|selection| selection.native_target_count == 0 || selection.candidates.iter().any(|candidate| candidate.selected && !candidate.rejected));
                    let outcome = if model_selection.is_some() {
                        DefinitionLookupOutcome {
                            modeled_definitions: Vec::new(), status: DefinitionLookupStatus::Incomplete,
                            reference: Some(query.site.clone()), definitions: match &answer.definitions {
                                brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinitions::Ready(rows) => rows.iter().filter_map(|(_, definition)| match definition {
                                    brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinition::Unit(unit) => Some(unit.clone()), _ => None,
                                }).collect(),
                                _ => Vec::new(),
                            }, lexical_definition: None,
                            diagnostics: answer.named_reasons.iter().map(|(kind, message)| DefinitionLookupDiagnostic { kind: (*kind).into(), message: message.clone(), claim: None }).collect(),
                        }
                    } else {
                        adapt_definition_answer(query.site, brokk_bifrost_core::analyzer::model::Language::Go, answer)
                    };
                    BoundedResolution::Complete {
                        value: (
                            outcome,
                            Some(GoNativeDefinitionEvidence {
                                model_selection,
                                answer: native_answer,
                                receiver_application: local_receiver_application,
                            }),
                        ),
                        work,
                    }
                }
            },
            GoDefinitionOperation::Native {
                value: SelectedResolutionLocated::Missing,
                work,
            } => BoundedResolution::Complete {
                value: (
                    unavailable_definition(
                        query.site,
                        "native_reference_unavailable",
                        "the selected producer has no reference at this source range".into(),
                    ),
                    None,
                ),
                work,
            },
            GoDefinitionOperation::Failed(failure) => *failure,
        };
        (result, selected_imports)
    }

    /// Use selected native binding for the base, then model owner/member
    /// postings for the selected path. Local shadows and workspace packages
    /// cannot enter this external declaration authority.
    fn overlay_definition_projection(
        &mut self,
        query: BoundedReceiverQuery<'_>,
        tree: &tree_sitter::Tree,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        BoundedResolution<Option<GoOverlayDefinitionProjection>>,
    > {
        let empty = || BoundedResolution::Complete {
            value: None,
            work: ReceiverAnalysisWork::default(),
        };
        let Some(overlay) = self.overlay.clone() else {
            return Ok(empty());
        };
        let path = brokk_bifrost_core::path_utils::rel_path_string(query.file);
        let Some(prepared) = self.files.get(&path).cloned() else {
            return Ok(empty());
        };
        if prepared.context.demand.modeled_imports.is_empty()
            || !self
                .go
                .inner
                .source_matches_selected_native_content(query.file, query.source)
        {
            return Ok(empty());
        }
        let Some(selector) =
            brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)
        else {
            return Ok(empty());
        };
        if selector
            .members
            .iter()
            .take(selector.focus_segment)
            .next()
            .is_none()
            || !matches!(selector.base.kind(), "identifier" | "package_identifier")
        {
            return Ok(empty());
        }
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        let locator = SelectedSemanticLocator::for_reference_range(
            "go",
            path.clone(),
            selector.base.start_byte(),
            selector.base.end_byte(),
        );
        let mut metrics = SelectedResolutionContextMetrics;
        let base = self
            .operation
            .resolve_native_reference_units_bounded_for_go_request(
                prepared.context.clone(),
                None,
                &locator,
                query.budget,
                &cancellation,
                &mut metrics,
                self.forward_candidate_artifacts.entry(path).or_default(),
                &mut self.point_metrics,
            )?;
        let (value, work) = match base {
            BoundedResolution::Complete { value, work } => (value, work),
            BoundedResolution::Exceeded { limit, work } => {
                return Ok(BoundedResolution::Exceeded { limit, work });
            }
            BoundedResolution::Cancelled { work } => {
                return Ok(BoundedResolution::Cancelled { work });
            }
        };
        let direct_target = (|| {
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) = value
            else {
                return None;
            };
            if answer.answer.binding().completion()
                != &brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion::Complete
            {
                return None;
            }
            let [definition] = answer.answer.binding().targets() else {
                return None;
            };
            let ordinal = brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal::new(
                definition.ordinal()?,
            );
            let provider = prepared
                .context
                .demand
                .modeled_imports
                .get(&(ordinal, *definition))?;
            let GoExternalPackageProvenance::SemanticModel { pack_digest, .. } =
                &provider.provenance
            else {
                // GoTool binders carry no single pack; the receiver walk's mint selects their model owner.
                return None;
            };
            Some((provider.import_path.clone(), pack_digest.clone()))
        })();
        let Some((import_path, provider_digest)) = direct_target else {
            return Ok(BoundedResolution::Complete { value: None, work });
        };
        let session =
            brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::bounded(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_scope_nodes: query
                        .budget
                        .max_scope_nodes
                        .saturating_sub(work.scope_nodes),
                    max_summary_expansions: query
                        .budget
                        .max_summary_expansions
                        .saturating_sub(work.summary_expansions),
                    ..query.budget
                },
                query.cancellation,
            );
        let packages =
            crate::analyzer::go::package_identity::GoOverlayPackages::new(Some(&overlay));
        let package = packages
            .modeled_package_identity(&import_path)
            .expect("a selected modeled import belongs to the captured overlay");
        assert_eq!(
            package.pack_digest, provider_digest,
            "a selected Go binder keeps its captured package provider"
        );
        let selected = crate::analyzer::go::package_identity::go_visible_member_path(
            &import_path,
            selector
                .members
                .iter()
                .take(selector.focus_segment)
                .map(|node| {
                    node.utf8_text(query.source.as_bytes())
                        .expect("selected Go member is source text")
                }),
            |package, member| {
                packages
                    .visible_member(package, member)
                    .map(|symbol| symbol.qualified_name.clone())
            },
            |name| {
                packages
                    .visible_symbol(name)
                    .filter(|symbol| symbol.qualified_name == name)
                    .map(|symbol| symbol.qualified_name.clone())
            },
            || session.scope_step(),
        )
        .and_then(|selected| {
            let symbol = packages.visible_symbol(&selected.symbol_name)?;
            // Promoted members keep the embedded declaration's provider,
            // which can differ from the importing package's provider.
            Some(GoOverlayDefinitionProjection {
                direct_target: GoOverlayDirectTarget {
                    provider_digest: symbol.provenance.pack_digest.clone(),
                    canonical_symbol: selected.reference_name,
                },
            })
        });
        Ok(match session.finish(selected) {
            BoundedResolution::Complete {
                value,
                work: overlay_work,
            } => BoundedResolution::Complete {
                value,
                work: go_add_resolution_work(work, overlay_work),
            },
            BoundedResolution::Exceeded {
                limit,
                work: overlay_work,
            } => BoundedResolution::Exceeded {
                limit,
                work: go_add_resolution_work(work, overlay_work),
            },
            BoundedResolution::Cancelled { work: overlay_work } => BoundedResolution::Cancelled {
                work: go_add_resolution_work(work, overlay_work),
            },
        })
    }

    pub(crate) fn resolve_definition_with_evidence(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<GoNativeDefinitionResolution> {
        let result = self.resolve_definition_with_evidence_inner(query);
        self.revalidate_answer(
            result,
            &query.cancellation.cloned().unwrap_or_default(),
            |kind, message| GoNativeDefinitionResolution {
                native_resolution: None,
                model_member_selection: None,
                outcome: unavailable_definition(query.site, kind, message),
                call_application: CallApplicationKind::Unknown,
                exact_external_call: None,
                external_callee_identity: None,
            },
        )
    }

    // Classification needs the binder's value role, not the receiver's type.
    // In particular, an unmodeled external type must not erase a local or
    // package-level value declaration's bound-receiver application.
    fn targetless_receiver_application(
        &mut self,
        query: BoundedReceiverQuery<'_>,
        tree: &tree_sitter::Tree,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        BoundedResolution<Option<CallApplicationKind>>,
    > {
        let empty = || BoundedResolution::Complete {
            value: None,
            work: ReceiverAnalysisWork::default(),
        };
        if !go_call_selector_reference_at(
            tree,
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        ) {
            return Ok(empty());
        }
        let Some(selector) =
            brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)
        else {
            return Ok(empty());
        };
        // A call-expression operand is a runtime value even when its result
        // type is open. This classifies application, not a member target.
        if selector.base.kind() == "call_expression" {
            return Ok(BoundedResolution::Complete {
                value: Some(CallApplicationKind::BoundReceiver),
                work: ReceiverAnalysisWork::default(),
            });
        }
        if !matches!(selector.base.kind(), "identifier" | "package_identifier") {
            return Ok(empty());
        }
        let base = selector.base;
        let locator = SelectedSemanticLocator::for_reference_range(
            "go",
            brokk_bifrost_core::path_utils::rel_path_string(query.file),
            base.start_byte(),
            base.end_byte(),
        );
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        let lexical_work =
            match self.resolve_local_declaration(&locator, query.budget, &cancellation)? {
                BoundedResolution::Complete {
                    value: SelectedResolutionOperationOutcome::Native(Some((_, definition))),
                    work,
                } => {
                    // Type parameters share DeclarationKind::Parameter with
                    // value parameters. Only a value declaration binds a
                    // runtime receiver; T.Method(receiver, ...) stays open.
                    let runtime_value = match definition.kind {
                        brokk_bifrost_analysis::analyzer::DeclarationKind::LocalVariable => true,
                        brokk_bifrost_analysis::analyzer::DeclarationKind::Parameter
                        | brokk_bifrost_analysis::analyzer::DeclarationKind::ReceiverParameter => {
                            tree.root_node()
                                .named_descendant_for_byte_range(
                                    definition.name_range.start_byte,
                                    definition.name_range.end_byte,
                                )
                                .and_then(|name| name.parent())
                                .is_some_and(|declaration| {
                                    matches!(
                                        declaration.kind(),
                                        "parameter_declaration" | "variadic_parameter_declaration"
                                    )
                                })
                        }
                        _ => unreachable!("a selected local binder has a local declaration kind"),
                    };
                    return Ok(BoundedResolution::Complete {
                        value: runtime_value.then_some(CallApplicationKind::BoundReceiver),
                        work,
                    });
                }
                BoundedResolution::Complete {
                    value: SelectedResolutionOperationOutcome::Cancelled(_),
                    work,
                }
                | BoundedResolution::Cancelled { work } => {
                    return Ok(BoundedResolution::Cancelled { work });
                }
                BoundedResolution::Exceeded { limit, work } => {
                    return Ok(BoundedResolution::Exceeded { limit, work });
                }
                BoundedResolution::Complete { work, .. } => work,
            };
        let site = ResolvedReferenceSite {
            path: query.site.path.clone(),
            text: query
                .source
                .get(base.byte_range())
                .expect("selector base has a source range")
                .to_owned(),
            range: brokk_bifrost_core::analyzer::model::Range {
                start_byte: base.start_byte(),
                end_byte: base.end_byte(),
                start_line: base.start_position().row + 1,
                end_line: base.end_position().row + 1,
            },
            focus_start_byte: base.start_byte(),
            focus_end_byte: base.end_byte(),
        };
        let (selected, _) = self.resolve_definition_native(BoundedReceiverQuery {
            site: &site,
            tree: Some(tree),
            budget:
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_scope_nodes: query
                        .budget
                        .max_scope_nodes
                        .saturating_sub(lexical_work.scope_nodes),
                    max_summary_expansions: query
                        .budget
                        .max_summary_expansions
                        .saturating_sub(lexical_work.summary_expansions),
                    max_resolution_rounds: query
                        .budget
                        .max_resolution_rounds
                        .saturating_sub(lexical_work.resolution_rounds),
                    ..query.budget
                },
            ..query
        });
        Ok(match selected {
            BoundedResolution::Complete {
                value: (definition, _),
                work,
            } => {
                let value = (definition.status == DefinitionLookupStatus::Resolved
                    && matches!(definition.definitions.as_slice(), [unit] if unit.is_field()))
                .then_some(CallApplicationKind::BoundReceiver);
                BoundedResolution::Complete {
                    value,
                    work: go_add_resolution_work(lexical_work, work),
                }
            }
            BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded {
                limit,
                work: go_add_resolution_work(lexical_work, work),
            },
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled {
                work: go_add_resolution_work(lexical_work, work),
            },
        })
    }

    fn resolve_definition_with_evidence_inner(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<GoNativeDefinitionResolution> {
        let (mut native, selected_imports) = self.resolve_definition_native(query);
        let parsed_tree = query
            .tree
            .is_none()
            .then(|| crate::analyzer::usages::get_definition::go::parse_go_tree(query.source))
            .flatten();
        let mut sibling_query_error = None;
        if let Some(tree) = query.tree.or(parsed_tree.as_ref())
            && let BoundedResolution::Complete { work, .. } = &native
        {
            let prior_work = *work;
            let remaining = BoundedReceiverQuery {
                budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_scope_nodes: query.budget.max_scope_nodes.saturating_sub(prior_work.scope_nodes),
                    max_summary_expansions: query.budget.max_summary_expansions.saturating_sub(prior_work.summary_expansions),
                    ..query.budget
                },
                ..query
            };
            match self.overlay_definition_projection(remaining, tree) {
                Ok(BoundedResolution::Complete { value, work }) => {
                    if let BoundedResolution::Complete {
                        value: (outcome, answer),
                        work: total,
                    } = &mut native
                    {
                        *total = go_add_resolution_work(prior_work, work);
                        if let Some(projection) = value {
                            assert!(
                                !projection.direct_target.provider_digest.is_empty(),
                                "model target has provider authority"
                            );
                            let mut reference = query.site.clone();
                            reference.text = projection.direct_target.canonical_symbol;
                            *outcome = DefinitionLookupOutcome {
                                modeled_definitions: Vec::new(),
                                status: DefinitionLookupStatus::NoDefinition,
                                reference: Some(reference),
                                definitions: Vec::new(),
                                lexical_definition: None,
                                diagnostics: Vec::new(),
                            };
                            *answer = None;
                        }
                    }
                }
                Ok(BoundedResolution::Exceeded { limit, work }) => {
                    native = BoundedResolution::Exceeded {
                        limit,
                        work: go_add_resolution_work(prior_work, work),
                    }
                }
                Ok(BoundedResolution::Cancelled { work }) => {
                    native = BoundedResolution::Cancelled {
                        work: go_add_resolution_work(prior_work, work),
                    }
                }
                Err(error) => sibling_query_error = Some(error),
            }
        }
        if let Some(tree) = query.tree.or(parsed_tree.as_ref())
            && let BoundedResolution::Complete {
                value: (value, _), ..
            } = &mut native
            && value.status == DefinitionLookupStatus::Incomplete
            && go_point_selector_is_package_member_lookup(query, tree, &selected_imports)
        {
            let path = brokk_bifrost_core::path_utils::rel_path_string(query.file);
            let context_id = self
                .files
                .get(&path)
                .expect("an incomplete native Go point has a prepared file context")
                .context
                .demand
                .context_id;
            match self.operation.go_point_package_with_unselected_source(
                context_id,
                &path,
                &query.cancellation.cloned().unwrap_or_default(),
            ) {
                Ok(Some(package)) => attach_go_package_incomplete(value, &package),
                Ok(None) => {}
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
        let native_resolution = match &native {
            BoundedResolution::Complete { value: (_, Some(evidence)), .. } => Some(Box::new(
                brokk_bifrost_analysis::analyzer::usages::get_definition::NativeResolutionCompletion {
                    completion: evidence.answer.completion().clone(),
                    identities: self.operation.ready.context_identities.clone(),
                }
            )),
            _ => None,
        };
        let legacy_reasons = match &native {
            BoundedResolution::Complete {
                value: (_, Some(evidence)),
                ..
            } => super::model_receiver::legacy_model_reasons(
                evidence.model_selection.as_deref(),
                evidence.answer.completion(),
                &self.operation.ready.context_identities,
            ),
            _ => std::collections::BTreeSet::new(),
        };
        let path = brokk_bifrost_core::path_utils::rel_path_string(query.file);
        let source_refusals = self
            .files
            .get(&path)
            .map_or_else(Vec::new, |file| file.context.source_import_refusals.clone());
        let mut answer = finish_go_definition_resolution(
            query,
            self.go,
            self.overlay.clone(),
            selected_imports,
            source_refusals,
            native,
        );
        if let BoundedResolution::Complete { value, .. } = &mut answer {
            value.native_resolution = native_resolution;
        }
        if !legacy_reasons.is_empty()
            && let Some(tree) = query.tree.or(parsed_tree.as_ref())
            && let BoundedResolution::Complete { value, work } = &mut answer
            && value.model_member_selection.is_none()
            && value.exact_external_call.is_none()
            && value.call_application != CallApplicationKind::PackageFunction
            && matches!(
                value.outcome.status,
                DefinitionLookupStatus::NoDefinition
                    | DefinitionLookupStatus::Incomplete
                    | DefinitionLookupStatus::UnresolvableImportBoundary
            )
        {
            let prior_work = *work;
            let budget =
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_scope_nodes: query
                        .budget
                        .max_scope_nodes
                        .saturating_sub(prior_work.scope_nodes),
                    max_summary_expansions: query
                        .budget
                        .max_summary_expansions
                        .saturating_sub(prior_work.summary_expansions),
                    max_resolution_rounds: query
                        .budget
                        .max_resolution_rounds
                        .saturating_sub(prior_work.resolution_rounds),
                    ..query.budget
                };
            let session = brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::bounded(budget, query.cancellation);
            let selected =
                crate::analyzer::usages::get_definition::go::go_g1b_legacy_model_receiver(
                    BoundedReceiverQuery {
                        tree: Some(tree),
                        budget,
                        ..query
                    },
                    &session,
                    &legacy_reasons,
                );
            match session.finish(selected) {
                BoundedResolution::Complete {
                    value: target,
                    work: legacy_work,
                } => {
                    *work = go_add_resolution_work(prior_work, legacy_work);
                    if let Some(target) = target
                        && let (Some(callee), Some(proof)) =
                            (target.external_callee, target.external_call)
                    {
                        let mut reference = query.site.clone();
                        reference.text = callee;
                        value.outcome = DefinitionLookupOutcome {
                            modeled_definitions: Vec::new(),
                            status: DefinitionLookupStatus::UnresolvableImportBoundary,
                            reference: Some(reference),
                            definitions: Vec::new(),
                            lexical_definition: None,
                            diagnostics: legacy_reasons
                                .iter()
                                .map(|reason| DefinitionLookupDiagnostic {
                                    kind: reason.label().into(),
                                    message:
                                        "named native G1b gap retains the legacy receiver answer"
                                            .into(),
                                    claim: None,
                                })
                                .collect(),
                        };
                        value.call_application = proof.call_application();
                        value.external_callee_identity =
                            target.external_concrete_owner_fqn.map(|owner| {
                                ResolverOwnedExternalCalleeIdentity::new(
                                    brokk_bifrost_core::analyzer::Language::Go,
                                    owner,
                                    target.member,
                                )
                            });
                        value.exact_external_call = Some(proof);
                    }
                }
                BoundedResolution::Exceeded { limit, work } => {
                    answer = BoundedResolution::Exceeded {
                        limit,
                        work: go_add_resolution_work(prior_work, work),
                    }
                }
                BoundedResolution::Cancelled { work } => {
                    answer = BoundedResolution::Cancelled {
                        work: go_add_resolution_work(prior_work, work),
                    }
                }
            }
        }
        if let Some(tree) = query.tree.or(parsed_tree.as_ref())
            && let BoundedResolution::Complete { value, work } = &mut answer
            && value.outcome.definitions.is_empty()
            && value.model_member_selection.is_none()
            && value.exact_external_call.is_none()
            && matches!(
                value.call_application,
                CallApplicationKind::Unknown | CallApplicationKind::ReceiverBindingUnknown
            )
        {
            let prior_work = *work;
            let remaining = BoundedReceiverQuery {
                budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_scope_nodes: query.budget.max_scope_nodes.saturating_sub(prior_work.scope_nodes),
                    max_summary_expansions: query.budget.max_summary_expansions.saturating_sub(prior_work.summary_expansions),
                    max_resolution_rounds: query.budget.max_resolution_rounds.saturating_sub(prior_work.resolution_rounds),
                    ..query.budget
                },
                ..query
            };
            match self.targetless_receiver_application(remaining, tree) {
                Ok(BoundedResolution::Complete {
                    value: application,
                    work: binder_work,
                }) => {
                    *work = go_add_resolution_work(prior_work, binder_work);
                    if let Some(application) = application {
                        value.call_application = application;
                    }
                }
                Ok(BoundedResolution::Exceeded { limit, work }) => {
                    answer = BoundedResolution::Exceeded {
                        limit,
                        work: go_add_resolution_work(prior_work, work),
                    };
                }
                Ok(BoundedResolution::Cancelled { work }) => {
                    answer = BoundedResolution::Cancelled {
                        work: go_add_resolution_work(prior_work, work),
                    };
                }
                Err(error) => {
                    value.outcome =
                        unavailable_definition(query.site, "native_store_error", error.to_string())
                }
            }
        }
        if let Some(tree) = query.tree.or(parsed_tree.as_ref())
            && let BoundedResolution::Complete { value, work } = &mut answer
            && value.outcome.definitions.is_empty()
            && value.outcome.modeled_definitions.is_empty()
            && value.model_member_selection.is_none()
            && value.exact_external_call.is_none()
            && value.external_callee_identity.is_none()
            && matches!(
                value.outcome.status,
                DefinitionLookupStatus::NoDefinition | DefinitionLookupStatus::Incomplete
            )
        {
            let path = brokk_bifrost_core::path_utils::rel_path_string(query.file);
            if let Some(file_context) = self.files.get(&path) {
                match declared_external_receiver_call(
                    &mut self.operation,
                    file_context.context.clone(),
                    BoundedReceiverQuery {
                        tree: Some(tree),
                        budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                            max_scope_nodes: query.budget.max_scope_nodes.saturating_sub(work.scope_nodes),
                            max_summary_expansions: query.budget.max_summary_expansions.saturating_sub(work.summary_expansions),
                            max_resolution_rounds: query.budget.max_resolution_rounds.saturating_sub(work.resolution_rounds),
                            ..query.budget
                        },
                        ..query
                    },
                ) {
                    Ok(BoundedResolution::Complete {
                        value: proof,
                        work: receiver_work,
                    }) => {
                        *work = go_add_resolution_work(*work, receiver_work);
                        if let Some(proof) = proof {
                            let reference = value
                                .outcome
                                .reference
                                .get_or_insert_with(|| query.site.clone());
                            reference.text = proof.canonical_callee().to_owned();
                            value.outcome.status =
                                DefinitionLookupStatus::UnresolvableImportBoundary;
                            value.call_application = proof.call_application();
                            // With no model owner, legacy published no concrete-owner identity,
                            // including for hash.Hash. The candidate proof carries the call shape.
                            value.external_callee_identity = None;
                            value.exact_external_call = Some(proof);
                        }
                    }
                    Ok(BoundedResolution::Exceeded {
                        limit,
                        work: receiver_work,
                    }) => {
                        answer = BoundedResolution::Exceeded {
                            limit,
                            work: go_add_resolution_work(*work, receiver_work),
                        };
                    }
                    Ok(BoundedResolution::Cancelled {
                        work: receiver_work,
                    }) => {
                        answer = BoundedResolution::Cancelled {
                            work: go_add_resolution_work(*work, receiver_work),
                        };
                    }
                    Err(error) => {
                        value.outcome = unavailable_definition(
                            query.site,
                            "native_store_error",
                            error.to_string(),
                        )
                    }
                }
            }
        }
        // Model/import projections can complete after an unavailable native
        // path; the final request boundary must still revalidate its publication.
        self.revalidate_answer(
            answer,
            &query.cancellation.cloned().unwrap_or_default(),
            |kind, message| GoNativeDefinitionResolution {
                native_resolution: None,
                model_member_selection: None,
                outcome: unavailable_definition(query.site, kind, message),
                exact_external_call: None,
                call_application: CallApplicationKind::Unknown,
                external_callee_identity: None,
            },
        )
    }
}
#[cfg(test)]
fn external_callee_identity(
    proof: Option<&ExactExternalCallProof>,
) -> Option<ResolverOwnedExternalCalleeIdentity> {
    external_identity_from_proof(proof)
}

pub(super) fn go_add_resolution_work(
    first: ReceiverAnalysisWork,
    second: ReceiverAnalysisWork,
) -> ReceiverAnalysisWork {
    first.saturating_add(second)
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

pub(crate) fn append_model_backed_external_imports(
    unresolved_import_paths: impl IntoIterator<Item = String>,
    overlay: Option<
        &brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
    >,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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

// Measurement state exists only when point-work logging is enabled. The
// request independently samples its own work flag and owns its phase clocks.
struct GoPointWorkProfile {
    total_started: Option<Instant>,
    sql_before: Option<(u64, u64, u128)>,
    path: Option<String>,
    focus: (usize, usize),
    open_nanos: u128,
}

struct GoPointWorkReport<'result> {
    sql: Option<(u64, u64, u128)>,
    work: &'result ReceiverAnalysisWork,
    candidate_cache: Option<(usize, usize)>,
    total_nanos: u128,
    native_non_sql_nanos: u128,
    other_nanos: u128,
}

impl GoPointWorkProfile {
    fn start(query: BoundedReceiverQuery<'_>) -> Option<Self> {
        let record_work = std::env::var_os("BIFROST_TRIAL_NATIVE_GO_POINT_WORK").is_some();
        let total_started = record_work.then(Instant::now);
        let sql_before = record_work
            .then(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows)
            .flatten();
        let path = record_work.then(|| brokk_bifrost_core::path_utils::rel_path_string(query.file));
        let focus = (query.site.focus_start_byte, query.site.focus_end_byte);
        record_work.then_some(Self {
            total_started,
            sql_before,
            path,
            focus,
            open_nanos: 0,
        })
    }

    #[track_caller]
    fn collect<'result, T>(
        &self,
        request: &GoNativePointRequest<'_>,
        result: &'result BoundedResolution<T>,
    ) -> GoPointWorkReport<'result> {
        // Preserve the SQL boundary before reading result work and cache stats.
        let sql_after = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
        let sql = self
            .sql_before
            .zip(sql_after)
            .map(|(before, after)| (after.0 - before.0, after.1 - before.1, after.2 - before.2));
        let work = match result {
            BoundedResolution::Complete { work, .. }
            | BoundedResolution::Exceeded { work, .. }
            | BoundedResolution::Cancelled { work } => work,
        };
        let candidate_cache = request.operation.go_point_candidate_read_stats();
        let total_nanos = self
            .total_started
            .expect("point work logging starts a request timer")
            .elapsed()
            .as_nanos();
        let native_non_sql_nanos = request
            .phase_nanos
            .native_resolution
            .saturating_sub(request.phase_nanos.native_sql);
        let accounted_nanos = self
            .open_nanos
            .saturating_add(request.phase_nanos.file_context)
            .saturating_add(request.phase_nanos.native_resolution);
        let other_nanos = total_nanos.saturating_sub(accounted_nanos);
        GoPointWorkReport {
            sql,
            work,
            candidate_cache,
            total_nanos,
            native_non_sql_nanos,
            other_nanos,
        }
    }

    #[track_caller]
    fn report_definition(
        self,
        request: &GoNativePointRequest<'_>,
        result: &BoundedResolution<GoNativeDefinitionResolution>,
    ) {
        let GoPointWorkReport {
            sql,
            work,
            candidate_cache,
            total_nanos,
            native_non_sql_nanos,
            other_nanos,
        } = self.collect(request, result);
        let open_nanos = self.open_nanos;
        eprintln!(
            "go_native_point_work kind=definition path={} focus={:?} sql={sql:?} phases_ns=(request:{total_nanos},open:{open_nanos},file_context:{},native_resolution:{},native_sql:{},native_non_sql:{native_non_sql_nanos},other:{other_nanos}) resolution={:?} receiver={work:?} candidate_cache={candidate_cache:?} request_file_contexts={}",
            self.path
                .as_deref()
                .expect("profile path is captured when point work logging is enabled"),
            self.focus,
            request.phase_nanos.file_context,
            request.phase_nanos.native_resolution,
            request.phase_nanos.native_sql,
            request.point_metrics,
            request.files.len(),
        );
    }

    #[track_caller]
    fn report_type(
        self,
        request: &GoNativePointRequest<'_>,
        result: &BoundedResolution<TypeLookupOutcome>,
    ) {
        let GoPointWorkReport {
            sql,
            work,
            candidate_cache,
            total_nanos,
            native_non_sql_nanos,
            other_nanos,
        } = self.collect(request, result);
        let open_nanos = self.open_nanos;
        eprintln!(
            "go_native_point_work kind=type path={} focus={:?} sql={sql:?} phases_ns=(request:{total_nanos},open:{open_nanos},file_context:{},native_resolution:{},native_sql:{},native_non_sql:{native_non_sql_nanos},other:{other_nanos}) resolution={:?} receiver={work:?} candidate_cache={candidate_cache:?} request_file_contexts={}",
            self.path
                .as_deref()
                .expect("profile path is captured when point work logging is enabled"),
            self.focus,
            request.phase_nanos.file_context,
            request.phase_nanos.native_resolution,
            request.phase_nanos.native_sql,
            request.point_metrics,
            request.files.len(),
        );
    }
}

#[doc(hidden)]
pub fn resolve_go_definition_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    resolve_go_definition_with_evidence_bounded(query, after_open).map(|value| value.outcome)
}

pub(crate) fn resolve_go_definition_with_evidence_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<GoNativeDefinitionResolution> {
    let mut profile = GoPointWorkProfile::start(query);
    let opened = GoNativePointRequest::open_for_query(query, &mut profile);
    let mut request = match opened {
        Ok(GoNativePointRequestOpen::Ready(request)) => request,
        Ok(GoNativePointRequestOpen::Unavailable { kind, message }) => {
            return BoundedResolution::Complete {
                value: GoNativeDefinitionResolution {
                    native_resolution: None,
                    model_member_selection: None,
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
                    native_resolution: None,
                    model_member_selection: None,
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
    if let Some(profile) = profile {
        profile.report_definition(&request, &result);
    }
    result
}

fn finish_go_definition_resolution(
    query: BoundedReceiverQuery<'_>,
    go: &GoAnalyzer,
    overlay: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_imports: Vec<GoSelectedExternalImport>,
    source_refusals: Vec<
        brokk_bifrost_analysis::analyzer::store::go_package_context::GoSourceImportRefusal,
    >,
    native: BoundedResolution<(DefinitionLookupOutcome, Option<GoNativeDefinitionEvidence>)>,
) -> BoundedResolution<GoNativeDefinitionResolution> {
    match native {
        BoundedResolution::Complete {
            value: (mut outcome, native_evidence),
            work,
        } => {
            let (native_answer, local_receiver_application, model_selection) = native_evidence
                .map_or((None, None, None), |evidence| {
                    (
                        Some(evidence.answer),
                        evidence.receiver_application,
                        evidence.model_selection,
                    )
                });
            if query.cancellation.is_some_and(|token| token.is_cancelled()) {
                return BoundedResolution::Cancelled { work };
            }
            if let Some(selection) = model_selection.as_deref() {
                let parsed = query
                    .tree
                    .is_none()
                    .then(|| {
                        crate::analyzer::usages::get_definition::go::parse_go_tree(query.source)
                    })
                    .flatten();
                let query = BoundedReceiverQuery {
                    tree: query.tree.or(parsed.as_ref()),
                    ..query
                };
                let descriptor =
                    crate::analyzer::go::model_receiver::transient_selection(query, selection)
                        .unwrap_or_else(|| {
                            brokk_bifrost_analysis::analyzer::semantic::DeferredMemberSelection {
                                member: query.site.text.clone().into(),
                                receiver_place: None,
                                receiver_pointer_depth: None,
                            }
                        });
                let session = brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::bounded(query.budget, query.cancellation);
                let crate::analyzer::go::model_receiver::GoModelReceiverSelection::Handled(
                    mut selected,
                ) = crate::analyzer::go::model_receiver::go_selected_model_receiver_call(
                    query,
                    Some(selection),
                    &descriptor,
                    &session,
                )
                else {
                    unreachable!("a model selection is handled even when open");
                };
                selected.outcome.definitions = outcome.definitions;
                selected.outcome.diagnostics.extend(outcome.diagnostics);
                let application = selected.proof.as_ref().map_or(
                    CallApplicationKind::Unknown,
                    ExactExternalCallProof::call_application,
                );
                return match session.finish(()) {
                    BoundedResolution::Complete { .. } => BoundedResolution::Complete {
                        value: GoNativeDefinitionResolution {
                            native_resolution: None,
                            model_member_selection: Some(Box::new(selection.clone())),
                            outcome: selected.outcome,
                            call_application: application,
                            exact_external_call: selected.proof,
                            external_callee_identity: selected.identity,
                        },
                        work,
                    },
                    BoundedResolution::Exceeded { limit, work } => {
                        BoundedResolution::Exceeded { limit, work }
                    }
                    BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
                };
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
            let native_unindexed_frontier = native_answer.as_ref().is_some_and(|answer| {
                answer
                    .projected_frontiers()
                    .iter()
                    .any(|state| !state.unindexed_external().is_empty())
            }) && outcome.status
                == DefinitionLookupStatus::UnresolvableImportBoundary;
            if native_unindexed_frontier && !go.workspace_package_inventory_complete() {
                // A presumed name cannot prove that an unplaced or overlaid
                // workspace package is external to this request.
                outcome.status = DefinitionLookupStatus::Incomplete;
                outcome.diagnostics.push(DefinitionLookupDiagnostic {
                    claim: None,
                    kind: "go-package-incomplete".into(),
                    message: "the request's workspace package inventory cannot prove an external provider".into(),
                });
            }
            let external_candidate_status = matches!(
                outcome.status,
                DefinitionLookupStatus::Resolved
                    | DefinitionLookupStatus::Incomplete
                    | DefinitionLookupStatus::NoDefinition
                    | DefinitionLookupStatus::UnresolvableImportBoundary
            ) || external_projection_unavailable
                || native_import_context_unavailable;
            let parsed_tree = (external_candidate_status && query.tree.is_none())
                .then(|| crate::analyzer::usages::get_definition::go::parse_go_tree(query.source))
                .flatten();
            let tree = query.tree.or(parsed_tree.as_ref());
            let selector = tree.and_then(|tree| {
                brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)
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
                        brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::bounded(
                            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                                max_scope_nodes: query.budget.max_scope_nodes.saturating_sub(work.scope_nodes),
                                max_summary_expansions: query.budget.max_summary_expansions.saturating_sub(work.summary_expansions),
                                max_resolution_rounds: query.budget.max_resolution_rounds.saturating_sub(work.resolution_rounds),
                                ..query.budget
                            },
                            query.cancellation,
                        );
                call_application =
                    crate::analyzer::usages::get_definition::go::go_native_call_application(
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
                                    crate::analyzer::usages::get_definition::go::go_native_external_import_binding_resolution(
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
                                    crate::analyzer::usages::get_definition::go::go_native_import_namespace_resolution(
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
                                crate::analyzer::usages::get_definition::go::go_native_external_package_member_resolution(
                                        query_with_tree,
                                        go,
                                        &external_session,
                                        overlay.clone(),
                                        selected,
                                )
                            }).or_else(|| {
                                // A selected source definition is authoritative even when an
                                // import's spelling differs from its canonical package path.
                                if !outcome.definitions.is_empty() {
                                    return None;
                                }
                                crate::analyzer::usages::get_definition::go::go_native_source_imported_member_resolution(
                                    query_with_tree,
                                    go,
                                    &external_session,
                                    &source_refusals,
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
                    } else if outcome.definitions.is_empty()
                        && let Some((external_outcome, proof, identity)) =
                        crate::analyzer::usages::get_definition::go::go_native_unmodeled_external_package_member_resolution(
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
                        crate::analyzer::usages::get_definition::go::go_native_external_dot_import_call_resolution(
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
                    } else if outcome.definitions.is_empty()
                        && let Some(call_outcome) = crate::analyzer::usages::get_definition::go::go_native_workspace_unqualified_call_resolution(
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
                    call_application = local_receiver_application.unwrap_or(call_application);
                }
                if outcome.status == DefinitionLookupStatus::Resolved
                    && let Some(rejected) =
                        crate::analyzer::usages::get_definition::go::go_source_call_arity_rejection(
                            query_with_tree,
                            &external_session,
                            &outcome.definitions,
                            call_application,
                        )
                {
                    outcome = rejected;
                    exact_external_call = None;
                    external_callee_identity = None;
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
                                native_resolution: None,
                                model_member_selection: None,
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
                    native_resolution: None,
                    model_member_selection: None,
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
    let mut profile = GoPointWorkProfile::start(query);
    let opened = GoNativePointRequest::open_for_query(query, &mut profile);
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
    if let Some(profile) = profile {
        profile.report_type(&request, &result);
    }
    result
}

#[cfg(test)]
#[path = "native_points/tests.rs"]
mod tests;

/// The no-type answer for a Go reference that names a type. The incumbent gives
/// this outcome, with this diagnostic, for a type-name site.
fn go_type_name_site_outcome(site: &ResolvedReferenceSite) -> TypeLookupOutcome {
    brokk_bifrost_analysis::analyzer::usages::get_type::no_type(
        "go_no_supported_type",
        format!("`{}` does not have a supported explicit Go type", site.text),
    )
}

/// The production Go point and type resolver.
pub(crate) struct GoNativeRolloutPoints;

impl brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver
    for GoNativeRolloutPoints
{
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

    #[cfg(any(test, feature = "test-support"))]
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

impl brokk_bifrost_analysis::analyzer::languages::ReceiverRequest for GoNativePointRequest<'_> {
    fn resolve_type(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        self.begin_receiver_query(query.file);
        GoNativePointRequest::resolve_type(self, query)
    }

    fn resolve_definition(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        self.resolve_definition_with_evidence(query)
            .map(|value| value.outcome)
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn activate_receiver_models_for_test(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
) -> brokk_bifrost_analysis::analyzer::semantic_model::SemanticPackCatalog {
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbolKind;
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        AuthoredSemanticModelPack, CatalogOptions, CompilerOptions, SemanticModelActivationRequest,
        SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
        SessionPackSource, SessionPackSourceKind, acquire_active_semantic_models, compile_pack,
    };
    use serde_json::json;
    let declarations = brokk_bifrost_analysis::analyzer::semantic_model::overlay::go_extra_support_0::go_external_receiver_test_overlay();
    let mut types = Vec::new();
    let mut members = Vec::new();
    let ids = declarations
        .symbols()
        .iter()
        .enumerate()
        .map(|(index, declaration)| (declaration.id.clone(), format!("symbol-{index}")))
        .collect::<std::collections::HashMap<_, _>>();
    for declaration in declarations.symbols() {
        let locator = json!({"kind":"artifact", "path":"synthetic/receiver.go", "symbol":declaration.qualified_name});
        if let Some(owner) = &declaration.owner_id {
            members.push(json!({"id":ids[declaration.id.as_str()], "owner":ids[owner.as_str()], "name":declaration.name,
                "member_kind":"method", "visibility":"public", "is_static":false,
                "signature":declaration.structured_signature, "receiver":declaration.receiver, "locator":locator}));
        } else {
            let kind = match declaration.kind {
                SemanticModelSymbolKind::Module => "module",
                SemanticModelSymbolKind::Struct => "struct",
                _ => unreachable!("receiver fixture supplies modules and structs"),
            };
            types.push(
                json!({"id":ids[declaration.id.as_str()], "name":declaration.qualified_name, "type_kind":kind,
                "aliases":declaration.aliases, "visibility":"public", "locator":locator}),
            );
        }
    }
    let authored: AuthoredSemanticModelPack = serde_json::from_value(json!({
        "schema_version":brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        "language":"go", "ecosystem":"go-module", "pack_id":"test.go-selected-receivers", "version":"1.0.0",
        "compatibility":{}, "license":"MIT", "safety":{"generated_code_only":false,"review_required":false},
        "producer":{"name":"test-only","version":"1.0.0"}, "completeness":"complete",
        "provenance":{"source":"Synthetic engine receiver fixture, activated through the selected model catalog"},
        "shards":[{"id":"declarations", "activation":[{}], "payload":{"kind":"declaration_facts", "types":types, "members":members}}],
    })).unwrap();
    let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_compiled_pack(
            &compiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:go-selected-receivers".into(),
            },
        )
        .unwrap();
    let activation = SemanticModelActivationRequest {
        approximate_standard_libraries: Vec::new(),
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![
            brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence {
                language: "go".into(),
                ecosystem: "go-module".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
        ],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer,
            &catalog,
            None,
            &activation,
            &brokk_bifrost_core::cancellation::CancellationToken::new()
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));
    catalog
}
