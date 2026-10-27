//! Java selected-context entry point, exercised before atomic JVM cutover.

use crate::analyzer::java::JavaAnalyzer;

use brokk_bifrost_core::analyzer::model::DeclarationKind;

use crate::analyzer::java::imports::JavaTypeResolution;

use crate::analyzer::jvm::external::JvmExternalDeclarationSource;

use crate::analyzer::jvm::external::JvmExternalMember;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::native_points::NativeExpressionValueTypeLookup;

use brokk_bifrost_analysis::analyzer::native_points::NativePointContext;

use brokk_bifrost_analysis::analyzer::native_points::resolve_native_definition_bounded;

use brokk_bifrost_analysis::analyzer::native_points::resolve_native_expression_value_type_bounded;

use brokk_bifrost_analysis::analyzer::native_points::resolve_native_type_bounded;

use brokk_bifrost_analysis::analyzer::native_points::unavailable_definition;

use brokk_bifrost_analysis::analyzer::native_points::unavailable_type;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    SemanticModelCallableKey, SemanticModelSymbolKind, TypeRef,
};

use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JavaExternalStaticImportBoundary;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JavaImportContext;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::CallArgumentConversionProver;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionUnknown;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::CallEvidence;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ClaimSubjectRole;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::usages::get_definition::UnindexedClaim;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionNamespace,
};
use brokk_bifrost_core::analyzer::tree_walk::named_children;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
use brokk_bifrost_jvm::java::declarations::find_nearest_declaration_from_node;
use brokk_bifrost_jvm::java::graph::return_type::java_type_name_from_node;
use brokk_bifrost_jvm::java::graph_support::{
    java_object_creation_enclosing_expression, java_type_parameter_bounds,
    java_type_parameter_in_scope,
};
use tree_sitter::Node;

#[doc(hidden)]
pub fn resolve_java_definition_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    match resolve_java_definition_with_evidence_bounded(query, after_open) {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value: value.outcome,
            work,
        },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

#[derive(Debug)]
pub(crate) struct JavaNativeDefinitionResolution {
    pub(crate) outcome: DefinitionLookupOutcome,
    // The outcome-only structural receiver API cannot carry this call evidence;
    // native Java call-target integration needs the richer bounded entrypoint.
    #[allow(dead_code)] // Retained for the coordinated JVM call-routing flip.
    pub(crate) evidence: CallEvidence,
}

pub(crate) fn resolve_java_definition_with_evidence_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<JavaNativeDefinitionResolution> {
    brokk_bifrost_analysis::analyzer::usages::get_definition::trace::begin_native_trace();
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(query.analyzer) else {
        return BoundedResolution::Complete {
            value: JavaNativeDefinitionResolution {
                outcome: unavailable_definition(
                    query.site,
                    "native_analyzer_unavailable",
                    "Java analyzer is unavailable".into(),
                ),
                evidence: CallEvidence::default(),
            },
            work: ReceiverAnalysisWork::default(),
        };
    };
    let anchored = java_creation_keyword_anchor(query);
    let query = match &anchored {
        Some(site) => BoundedReceiverQuery { site, ..query },
        None => query,
    };
    let site_text = query.site.text.clone();
    let reference_namespace = java_constructor_reference_namespace(&query);
    let mut external_static_imports = Vec::new();
    let mut open_jvm_alias_imports = Vec::new();
    let resolution = resolve_native_definition_bounded(
        &java.inner,
        query,
        reference_namespace,
        |operation, path, cancellation| {
            Ok(match operation.java_import_context(path, cancellation)? {
                JavaImportContext::Ready {
                    context,
                    external_static_imports: boundaries,
                    open_jvm_alias_imports: open_aliases,
                    ..
                } => {
                    external_static_imports = boundaries;
                    open_jvm_alias_imports = open_aliases;
                    NativePointContext::Ready {
                        context,
                        selected_import_model: None,
                    }
                }
                JavaImportContext::Unavailable => NativePointContext::Unavailable,
                JavaImportContext::Cancelled => NativePointContext::Cancelled,
            })
        },
        after_open,
    );
    let resolution =
        crate::analyzer::jvm::native_points::project_jvm_declaration_site(query, resolution);
    let resolution = apply_static_import_boundary(&site_text, &external_static_imports, resolution);
    let resolution =
        apply_explicit_type_import_boundary(java, query, &open_jvm_alias_imports, resolution);
    match resolution {
        BoundedResolution::Complete { mut value, work } => {
            let evidence =
                java_native_call_evidence(java, query, &mut value, &external_static_imports);
            BoundedResolution::Complete {
                value: JavaNativeDefinitionResolution {
                    outcome: value,
                    evidence,
                },
                work,
            }
        }
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

fn apply_explicit_type_import_boundary(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    open_jvm_alias_imports: &[String],
    resolution: BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let BoundedResolution::Complete { mut value, work } = resolution else {
        return resolution;
    };
    if !matches!(
        value.status,
        DefinitionLookupStatus::Incomplete | DefinitionLookupStatus::NoDefinition
    ) || !value.definitions.is_empty()
        || value.lexical_definition.is_some()
    {
        return BoundedResolution::Complete { value, work };
    }
    // Qualified creation looks up a member type on its enclosing instance;
    // a lexical type import cannot describe that constructor boundary.
    if let Some(JavaNativeCallSite::Constructor {
        creation,
        type_node,
    }) = java_native_call_site(query)
        && java_object_creation_enclosing_expression(creation, type_node).is_some()
    {
        return BoundedResolution::Complete { value, work };
    }
    let Some(tree) = query.tree else {
        return BoundedResolution::Complete { value, work };
    };
    let Some(focus) =
        brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering(
            tree.root_node(),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        )
    else {
        return BoundedResolution::Complete { value, work };
    };
    if value.status == DefinitionLookupStatus::NoDefinition && !java_is_import_target_name(focus) {
        return BoundedResolution::Complete { value, work };
    }
    let scope = AnalyzerQueryScope::new(query.analyzer);
    let token = scope.token();
    if let Some(scoped_type) = java_scoped_type_route_node(focus)
        && let Some(raw_type) = query
            .source
            .get(scoped_type.start_byte()..scoped_type.end_byte())
            .map(str::trim)
            .filter(|name| !name.is_empty())
        && let Some((subject, external_target)) =
            java_scoped_external_type_route(java, query, token, scoped_type, raw_type)
    {
        crate::analyzer::jvm::native_points::project_jvm_external_boundary(
            &mut value,
            query.site,
            &subject,
            external_target.as_deref(),
            None,
        );
        value.diagnostics.insert(0, DefinitionLookupDiagnostic {
            kind: "java_scoped_type_external_boundary".into(),
            message: format!(
                "`{subject}` is a scoped Java type whose qualifier is outside the indexed workspace"
            ),
            claim: Some(UnindexedClaim::external_boundary(
                subject,
                ClaimSubjectRole::Type,
            )),
        });
        return BoundedResolution::Complete { value, work };
    }
    let Some((owner_node, member_node)) = java_imported_type_route_nodes(focus) else {
        return BoundedResolution::Complete { value, work };
    };
    let Some(simple_name) = query
        .source
        .get(owner_node.start_byte()..owner_node.end_byte())
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return BoundedResolution::Complete { value, work };
    };
    let Some(owner) = java.explicit_imported_type_fqn(token, query.file, simple_name) else {
        return BoundedResolution::Complete { value, work };
    };
    if open_jvm_alias_imports.iter().any(|alias| alias == &owner) {
        return BoundedResolution::Complete { value, work };
    }
    let overlay = query.analyzer.semantic_model_overlay();
    let resolved_owner =
        java.resolve_type_name_with_external(token, overlay.clone(), query.file, &owner);
    if matches!(&resolved_owner, Some(JavaTypeResolution::Source(_))) {
        return BoundedResolution::Complete { value, work };
    }

    let (subject, written_route, role, external_target) = if let Some(member_node) = member_node {
        let Some(member) = query
            .source
            .get(member_node.start_byte()..member_node.end_byte())
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            return BoundedResolution::Complete { value, work };
        };
        let member_fqn = format!("{owner}.{member}");
        if matches!(&resolved_owner, Some(JavaTypeResolution::External(_))) {
            let nested_type = java.resolve_type_name_with_external(
                token,
                overlay.clone(),
                query.file,
                &member_fqn,
            );
            let external_member =
                java.resolve_member_name_with_external(token, overlay, query.file, &member_fqn);
            if nested_type.is_none() && external_member.is_none() {
                brokk_bifrost_analysis::analyzer::usages::get_definition::record_native_external_route(member_fqn);
                return BoundedResolution::Complete { value, work };
            }
            let target = external_member
                .map(|member| member.fqn().to_owned())
                .or_else(|| match nested_type {
                    Some(JavaTypeResolution::External(nested)) => Some(nested.fqn().to_owned()),
                    Some(JavaTypeResolution::Source(_)) | None => None,
                });
            (
                member_fqn,
                format!("{simple_name}.{member}"),
                ClaimSubjectRole::Member,
                target,
            )
        } else {
            (
                member_fqn,
                format!("{simple_name}.{member}"),
                ClaimSubjectRole::Member,
                None,
            )
        }
    } else {
        let target = match resolved_owner {
            Some(JavaTypeResolution::External(external)) => Some(external.fqn().to_owned()),
            Some(JavaTypeResolution::Source(_)) | None => None,
        };
        (
            owner,
            simple_name.to_owned(),
            ClaimSubjectRole::Type,
            target,
        )
    };

    crate::analyzer::jvm::native_points::project_jvm_external_boundary(
        &mut value,
        query.site,
        &written_route,
        external_target.as_deref(),
        None,
    );
    value.diagnostics.insert(0, DefinitionLookupDiagnostic {
        kind: "java_imported_type_external_boundary".into(),
        message: format!(
            "`{subject}` is reached through an explicit Java type import not indexed in this workspace; its declaration may be outside the indexed workspace, including when only a partial workspace is indexed"
        ),
        claim: Some(UnindexedClaim::external_boundary(subject, role)),
    });
    BoundedResolution::Complete { value, work }
}

fn java_scoped_external_type_route(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    scoped_type: tree_sitter::Node<'_>,
    raw_type: &str,
) -> Option<(String, Option<String>)> {
    let child_count = scoped_type.named_child_count();
    if child_count < 2 {
        return None;
    }
    let qualifier = scoped_type.named_child(0)?;
    let terminal = scoped_type.named_child(child_count - 1)?;
    if terminal.kind() != "type_identifier" {
        return None;
    }
    let qualifier_text = query
        .source
        .get(qualifier.start_byte()..qualifier.end_byte())?
        .trim();
    if qualifier_text.is_empty() {
        return None;
    }

    let overlay = query.analyzer.semantic_model_overlay();
    match java.resolve_type_name_with_external(token, overlay.clone(), query.file, raw_type) {
        Some(JavaTypeResolution::Source(_)) => return None,
        Some(JavaTypeResolution::External(external)) => {
            return Some((raw_type.to_owned(), Some(external.fqn().to_owned())));
        }
        None => {}
    }
    if java
        .resolve_type_name_with_external(token, overlay, query.file, qualifier_text)
        .is_some()
    {
        return None;
    }

    // An unresolved simple prefix is still a PackageOrTypeName. An
    // unindexed on-demand import may supply an obscuring type (#5556), so
    // absence from the workspace does not prove an external package route.
    if qualifier.kind() == "type_identifier" {
        return None;
    }

    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Java);
    let qualifier_is_in_workspace =
        definitions.package_exists(qualifier_text) || definitions.fqn_prefix_exists(qualifier_text);
    if !definitions.can_publish() || qualifier_is_in_workspace {
        return None;
    }
    Some((raw_type.to_owned(), None))
}

fn java_scoped_type_route_node(focus: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    if focus.kind() != "type_identifier" {
        return None;
    }
    let scoped = focus
        .parent()
        .filter(|parent| parent.kind() == "scoped_type_identifier")?;
    let terminal_index = scoped.named_child_count().checked_sub(1)?;
    scoped
        .named_child(terminal_index)
        .filter(|last| last.id() == focus.id())
        .map(|_| scoped)
}

fn java_is_import_target_name(focus: tree_sitter::Node<'_>) -> bool {
    if focus.kind() != "identifier" {
        return false;
    }
    let mut path = focus;
    while let Some(parent) = path.parent().filter(|parent| {
        parent.kind() == "scoped_identifier" && parent.child_by_field_name("name") == Some(path)
    }) {
        path = parent;
    }
    path.parent()
        .is_some_and(|parent| parent.kind() == "import_declaration")
}

fn java_imported_type_route_nodes(
    focus: tree_sitter::Node<'_>,
) -> Option<(tree_sitter::Node<'_>, Option<tree_sitter::Node<'_>>)> {
    if focus.kind() == "type_identifier" {
        return Some((focus, None));
    }
    if java_is_import_target_name(focus) {
        return Some((focus, None));
    }
    let expression = match focus.kind() {
        "field_access" | "method_invocation" => Some(focus),
        "identifier" => focus.parent().filter(|parent| match parent.kind() {
            "field_access" => {
                parent.child_by_field_name("object") == Some(focus)
                    || parent.child_by_field_name("field") == Some(focus)
            }
            "method_invocation" => {
                parent.child_by_field_name("object") == Some(focus)
                    || parent.child_by_field_name("name") == Some(focus)
            }
            _ => false,
        }),
        _ => None,
    }?;
    let owner = expression.child_by_field_name("object")?;
    if owner.kind() != "identifier" {
        return None;
    }
    let member = match expression.kind() {
        "field_access" => expression.child_by_field_name("field"),
        "method_invocation" => expression.child_by_field_name("name"),
        _ => None,
    }?;
    Some((owner, Some(member)))
}

fn apply_static_import_boundary(
    site_text: &str,
    boundaries: &[JavaExternalStaticImportBoundary],
    resolution: BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let mut matching = boundaries
        .iter()
        .filter(|boundary| boundary.member == site_text);
    let Some(boundary) = matching.next() else {
        return resolution;
    };
    if matching.next().is_some() {
        return resolution;
    }
    let (mut value, work) = match resolution {
        BoundedResolution::Complete { value, work } => (value, work),
        other => return other,
    };
    if value.status != DefinitionLookupStatus::Incomplete
        || !value.definitions.is_empty()
        || value.lexical_definition.is_some()
    {
        return BoundedResolution::Complete { value, work };
    }
    value.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    value.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "java_static_import_external_boundary".into(),
        message: format!(
            "`{}` appears to cross a Java static import boundary at `{}` not indexed in this workspace",
            boundary.member, boundary.owner
        ),
        claim: Some(UnindexedClaim::external_boundary(
            format!("{}.{}", boundary.owner, boundary.member),
            ClaimSubjectRole::Any,
        )),
    });
    BoundedResolution::Complete { value, work }
}

#[derive(Clone, Copy)]
enum JavaNativeCallSite<'tree> {
    Method {
        invocation: Node<'tree>,
        receiver: Option<Node<'tree>>,
        member: Node<'tree>,
    },
    Constructor {
        creation: Node<'tree>,
        type_node: Node<'tree>,
    },
}

#[derive(Clone, Copy)]
enum JavaNativeReceiverForm {
    BoundValue,
    TypeQualifier,
}

fn java_native_call_evidence(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    outcome: &mut DefinitionLookupOutcome,
    external_static_imports: &[JavaExternalStaticImportBoundary],
) -> CallEvidence {
    if outcome.status == DefinitionLookupStatus::Unavailable {
        return CallEvidence::default();
    }
    let mut evidence = CallEvidence::native_java_selected();
    let Some(call_site) = java_native_call_site(query) else {
        return evidence;
    };
    let scope = AnalyzerQueryScope::new(query.analyzer);
    let token = scope.token();
    if let JavaNativeCallSite::Constructor {
        creation,
        type_node,
    } = call_site
        && outcome.definitions.is_empty()
        && outcome.lexical_definition.is_none()
    {
        let type_name = java_native_constructor_type_name(query, creation, type_node);
        if type_name.is_none()
            && java_object_creation_enclosing_expression(creation, type_node).is_some()
            && outcome.definitions.is_empty()
            && outcome.lexical_definition.is_none()
        {
            outcome.status = DefinitionLookupStatus::Incomplete;
            outcome.diagnostics.push(DefinitionLookupDiagnostic {
                kind: "java_qualified_constructor_incomplete".into(),
                message:
                    "the enclosing instance has no resolved static owner for its inner constructor"
                        .into(),
                claim: None,
            });
            return evidence;
        }
        if let Some((proof, owner, member)) = type_name.and_then(|type_name| {
            java_native_external_constructor_proof(
                java,
                query,
                token,
                creation,
                &type_name,
                java_native_call_argument_types(java, query, token, creation).as_deref(),
            )
        }) {
            if let Some(proof) = proof {
                publish_java_external_call_boundary(query, outcome, &proof, &owner, &member);
                return evidence.with_native_java_external_call(proof, &owner, &member, false);
            }
            publish_java_external_incomplete_member_identity(query, outcome, &owner, &member);
            return evidence.with_native_java_external_member_identity(&owner, &member);
        }
    }
    if !outcome.definitions.is_empty()
        || outcome.lexical_definition.is_some()
        || !matches!(
            outcome.status,
            DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::UnresolvableImportBoundary
                | DefinitionLookupStatus::Incomplete
                | DefinitionLookupStatus::Ambiguous
        )
        || (outcome.status == DefinitionLookupStatus::Ambiguous
            && !outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "native_external_member_inventory"))
        || (outcome.status == DefinitionLookupStatus::Incomplete
            && !outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "incomplete_binding"))
    {
        return java_native_source_call_evidence(query.analyzer, outcome, call_site, evidence);
    }
    match call_site {
        JavaNativeCallSite::Method {
            invocation,
            receiver,
            member,
        } => {
            let Some(member_name) = node_text_for_query(member, query.source) else {
                return evidence;
            };
            let Some(actual_types) =
                java_native_call_argument_types(java, query, token, invocation)
            else {
                return evidence;
            };
            let receiver_type = receiver.map(|receiver| {
                java_native_external_receiver(java, query, token, receiver, invocation)
            });
            let external_call = if receiver.is_some() {
                match receiver_type.as_ref() {
                    Some(JavaNativeReceiverResolution::External { owner, form }) => {
                        java_native_external_method_resolution(
                            java,
                            query,
                            token,
                            owner,
                            member_name,
                            &actual_types,
                            *form,
                        )
                    }
                    Some(
                        JavaNativeReceiverResolution::Typed | JavaNativeReceiverResolution::Untyped,
                    )
                    | None => None,
                }
            } else {
                let mut matching = external_static_imports
                    .iter()
                    .filter(|boundary| boundary.member == member_name);
                let boundary = matching.next();
                if matching.next().is_some() {
                    None
                } else {
                    boundary.and_then(|boundary| {
                        let owner = java_native_external_type(java, query, token, &boundary.owner)?;
                        java_native_external_method_resolution(
                            java,
                            query,
                            token,
                            owner.fqn(),
                            member_name,
                            &actual_types,
                            JavaNativeReceiverForm::TypeQualifier,
                        )
                    })
                }
            };
            let external_call = external_call.or_else(|| {
                // This canonical value comes from selected external inventory
                // rows, not from parsing the call's source text.
                if receiver.is_some()
                    || !outcome
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.kind == "native_external_member_inventory")
                {
                    return None;
                }
                let (owner, selected_member) = outcome.reference.as_ref()?.text.rsplit_once('.')?;
                if selected_member != member_name {
                    return None;
                }
                java_native_external_method_resolution(
                    java,
                    query,
                    token,
                    owner,
                    selected_member,
                    &actual_types,
                    JavaNativeReceiverForm::BoundValue,
                )
                .or_else(|| {
                    java_native_external_method_resolution(
                        java,
                        query,
                        token,
                        owner,
                        selected_member,
                        &actual_types,
                        JavaNativeReceiverForm::TypeQualifier,
                    )
                })
            });
            if let Some(JavaNativeExternalMethodResolution {
                owner,
                member,
                invocation,
            }) = external_call
            {
                match invocation {
                    JavaNativeExternalInvocation::Selected {
                        proof,
                        dispatch_closed,
                    } => {
                        publish_java_external_call_boundary(
                            query, outcome, &proof, &owner, &member,
                        );
                        evidence = evidence.with_native_java_external_call(
                            *proof,
                            &owner,
                            &member,
                            dispatch_closed,
                        );
                    }
                    JavaNativeExternalInvocation::Witnessed => {
                        publish_java_external_incomplete_member_identity(
                            query, outcome, &owner, &member,
                        );
                        evidence =
                            evidence.with_native_java_external_member_identity(&owner, &member);
                    }
                    JavaNativeExternalInvocation::Rejected => {
                        // A known inapplicable member can still be named for
                        // navigation, without becoming a structured call identity.
                        publish_java_external_member_identity(query, outcome, &owner, &member);
                    }
                }
            } else if receiver.is_some()
                && matches!(receiver_type, Some(JavaNativeReceiverResolution::Untyped))
                && outcome.status == DefinitionLookupStatus::Incomplete
                && outcome.definitions.is_empty()
                && outcome.lexical_definition.is_none()
            {
                publish_java_unmodeled_receiver_boundary(query, outcome, member_name);
            }
            if let Some(receiver) = receiver {
                publish_java_imported_bound_boundary(java, query, token, receiver, outcome);
            }
        }
        JavaNativeCallSite::Constructor { .. } => {}
    }
    evidence
}

fn publish_java_unmodeled_receiver_boundary(
    query: BoundedReceiverQuery<'_>,
    outcome: &mut DefinitionLookupOutcome,
    member: &str,
) {
    let reference = outcome.reference.get_or_insert_with(|| query.site.clone());
    reference.text = member.to_owned();
    outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    if outcome
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.kind != "java_native_unmodeled_receiver")
    {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "java_native_unmodeled_receiver".into(),
            message: format!("`{member}` is called on a receiver with no resolved source type"),
            claim: None,
        });
    }
}

fn publish_java_imported_bound_boundary(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    receiver: Node<'_>,
    outcome: &mut DefinitionLookupOutcome,
) {
    if receiver.kind() != "identifier"
        || !outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "jvm-import-owner-open")
    {
        return;
    }
    let Some(name) = node_text_for_query(receiver, query.source) else {
        return;
    };
    let Some(declaration) = find_nearest_declaration_from_node(receiver, name, query.source) else {
        return;
    };
    let Some(root) = query.tree.map(|tree| tree.root_node()) else {
        return;
    };
    let Some(node) = root
        .named_descendant_for_byte_range(declaration.range.start_byte, declaration.range.end_byte)
    else {
        return;
    };
    let declaration = node
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")
        .unwrap_or(node);
    let Some(type_node) = crate::analyzer::java::declared_type_node(declaration) else {
        return;
    };
    let Some(type_name) = java_type_name_from_node(type_node, query.source) else {
        return;
    };
    let Some(parameter) = java_type_parameter_in_scope(type_node, query.source, &type_name) else {
        return;
    };
    // Select each bound's own route: another bound's gap cannot establish
    // that this spelling uses an import instead of a lexical source type.
    for bound in java_type_parameter_bounds(parameter) {
        let Some(name) = java_type_name_from_node(bound, query.source) else {
            continue;
        };
        let Some(site) = java_constructor_type_terminal(bound) else {
            continue;
        };
        let Some(bound_value) = java_native_expression_value_type_at_node(query, site) else {
            continue;
        };
        if bound_value
            .value_types
            .types
            .iter()
            .any(|ty| !ty.definitions.is_empty())
            || !bound_value
                .value_types
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "jvm-import-owner-open")
        {
            continue;
        }
        let canonical = match bound_value.value_types.types.as_slice() {
            [ty] => Some(ty.fqn.clone()),
            [] => java.explicit_imported_type_fqn(token, query.file, &name),
            _ => None,
        };
        let Some(canonical) = canonical else {
            continue;
        };
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "java_native_imported_receiver_bound".into(),
            message: format!(
                "receiver bounded by `{name}`, imported Java type `{canonical}`; native member lookup reached an unindexed import owner"
            ),
            claim: Some(UnindexedClaim::external_boundary(
                canonical,
                ClaimSubjectRole::Type,
            )),
        });
    }
}

fn java_native_source_call_evidence(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    outcome: &DefinitionLookupOutcome,
    call_site: JavaNativeCallSite<'_>,
    evidence: CallEvidence,
) -> CallEvidence {
    if !matches!(
        outcome.status,
        DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous
    ) || outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "incomplete_binding")
    {
        return evidence;
    }
    let mut target_shape = None;
    let mut every_target_is_closed = true;
    for definition in &outcome.definitions {
        if definition.source().language() != Language::Java || !definition.is_function() {
            return evidence;
        }
        let metadata = analyzer.signature_metadata(definition);
        if metadata.is_empty() {
            return evidence;
        }
        for signature in metadata {
            if !signature.callable_modifiers_recorded() {
                return evidence;
            }
            let shape = (
                signature.callable_is_constructor(),
                signature.callable_is_static(),
            );
            if target_shape.is_some_and(|previous| previous != shape) {
                return evidence;
            }
            target_shape = Some(shape);
            every_target_is_closed &= signature.dispatch_extensibility()
                == Some(brokk_bifrost_core::analyzer::model::DispatchExtensibility::Closed)
                || signature.callable_is_constructor()
                || signature.callable_is_static()
                || signature.callable_declared_visibility()
                    == Some(
                        brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility::Private,
                    );
        }
    }
    let Some((is_constructor, is_static)) = target_shape else {
        return evidence;
    };
    let call_application = match (call_site, is_constructor) {
        (JavaNativeCallSite::Constructor { .. }, true) => {
            brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind::PackageFunction
        }
        (JavaNativeCallSite::Method { .. }, false) if is_static => {
            brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind::PackageFunction
        }
        (JavaNativeCallSite::Method { .. }, false) => {
            brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind::BoundReceiver
        }
        _ => return evidence,
    };
    // Super invocation selects the superclass implementation nonvirtually,
    // even when the selected declaration is itself overridable.
    let super_invocation = matches!(call_site, JavaNativeCallSite::Method { invocation, .. }
        if brokk_bifrost_jvm::java::graph_support::java_callable_receiver_origin(invocation)
            == ResolutionCallableReceiverOrigin::Super);
    evidence.with_native_java_source_call(
        call_application,
        (every_target_is_closed || super_invocation)
            .then_some(brokk_bifrost_core::analyzer::model::DispatchExtensibility::Closed),
    )
}

fn java_native_call_site<'tree>(
    query: BoundedReceiverQuery<'tree>,
) -> Option<JavaNativeCallSite<'tree>> {
    let tree = query.tree?;
    let focus = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering(
        tree.root_node(),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    )?;
    let mut ancestor = Some(focus);
    while let Some(node) = ancestor {
        if node.kind() == "method_invocation"
            && let Some(member) = node.child_by_field_name("name")
            && member.start_byte() == query.site.focus_start_byte
            && member.end_byte() == query.site.focus_end_byte
        {
            return Some(JavaNativeCallSite::Method {
                invocation: node,
                receiver: node.child_by_field_name("object"),
                member,
            });
        }
        if node.kind() == "object_creation_expression"
            && let Some(type_node) = node.child_by_field_name("type")
            && java_constructor_type_terminal(type_node).is_some_and(|terminal| {
                terminal.start_byte() == query.site.focus_start_byte
                    && terminal.end_byte() == query.site.focus_end_byte
            })
        {
            return Some(JavaNativeCallSite::Constructor {
                creation: node,
                type_node,
            });
        }
        ancestor = node.parent();
    }
    None
}

fn node_text_for_query<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    source.get(node.start_byte()..node.end_byte())
}

fn java_native_external_receiver(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    receiver: Node<'_>,
    enclosing_call: Node<'_>,
) -> JavaNativeReceiverResolution {
    let from_site_type =
        java_native_external_receiver_from_site_type(java, query, token, receiver, enclosing_call);
    if !matches!(from_site_type, JavaNativeReceiverResolution::Untyped) {
        return from_site_type;
    }
    // Preserve established parameter/local and type-qualifier receiver binding.
    // Actual applicability and selected external call-result typing are separate
    // claims; neither is inferred by these receiver-binding routes.
    if let Some(receiver) =
        java_native_external_receiver_from_identifier(java, query, token, receiver)
    {
        return receiver;
    }
    if let Some(receiver) =
        java_native_external_receiver_from_type_qualifier(java, query, token, receiver)
    {
        return receiver;
    }
    JavaNativeReceiverResolution::Untyped
}

fn java_native_external_receiver_from_identifier(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    receiver: Node<'_>,
) -> Option<JavaNativeReceiverResolution> {
    if receiver.kind() != "identifier" {
        return None;
    }
    let name = node_text_for_query(receiver, query.source)?;
    if let Some(declaration) = find_nearest_declaration_from_node(receiver, name, query.source)
        && matches!(
            declaration.kind,
            DeclarationKind::Parameter
                | DeclarationKind::ReceiverParameter
                | DeclarationKind::LocalVariable
                | DeclarationKind::CatchParameter
                | DeclarationKind::EnhancedForVariable
                | DeclarationKind::LambdaParameter
                | DeclarationKind::PatternVariable
                | DeclarationKind::ResourceVariable
                | DeclarationKind::Field
        )
    {
        let root = query.tree?.root_node();
        let declaration_node = root.named_descendant_for_byte_range(
            declaration.range.start_byte,
            declaration.range.end_byte,
        )?;
        let type_declaration = declaration_node
            .parent()
            .filter(|parent| parent.kind() == "variable_declarator")
            .unwrap_or(declaration_node);
        let type_node = crate::analyzer::java::declared_type_node(type_declaration)?;
        let type_name = java_type_name_from_node(type_node, query.source)?;
        let owner = java_native_external_type(java, query, token, &type_name)?;
        return Some(JavaNativeReceiverResolution::External {
            owner: owner.fqn().to_owned(),
            form: JavaNativeReceiverForm::BoundValue,
        });
    }
    let owner = java_native_external_type(java, query, token, name)?;
    Some(JavaNativeReceiverResolution::External {
        owner: owner.fqn().to_owned(),
        form: JavaNativeReceiverForm::TypeQualifier,
    })
}

fn java_native_external_receiver_from_type_qualifier(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    receiver: Node<'_>,
) -> Option<JavaNativeReceiverResolution> {
    if matches!(
        receiver.kind(),
        "method_invocation" | "object_creation_expression" | "this" | "super"
    ) {
        return None;
    }
    let spelling = node_text_for_query(receiver, query.source)?;
    let owner = java_native_external_type(java, query, token, spelling)?;
    Some(JavaNativeReceiverResolution::External {
        owner: owner.fqn().to_owned(),
        form: JavaNativeReceiverForm::TypeQualifier,
    })
}

fn java_native_external_receiver_from_site_type(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    receiver: Node<'_>,
    _enclosing_call: Node<'_>,
) -> JavaNativeReceiverResolution {
    if matches!(receiver.kind(), "this" | "super") {
        return JavaNativeReceiverResolution::Typed;
    }
    if receiver.kind() == "method_invocation" {
        return match java_native_argument_type(java, query, token, receiver) {
            Some(TypeRef::Named {
                name, arguments, ..
            }) if arguments.is_empty() => {
                match java_native_static_external_type(java, query, &name) {
                    Some(owner) => JavaNativeReceiverResolution::External {
                        owner: owner.fqn().to_owned(),
                        form: JavaNativeReceiverForm::BoundValue,
                    },
                    None => JavaNativeReceiverResolution::Typed,
                }
            }
            Some(TypeRef::Declared { .. }) => JavaNativeReceiverResolution::Typed,
            _ => JavaNativeReceiverResolution::Untyped,
        };
    }
    let Some(site_node) = java_native_receiver_type_site_node(receiver) else {
        return JavaNativeReceiverResolution::Untyped;
    };
    let Some(value) = java_native_expression_value_type_at_node(query, site_node) else {
        return JavaNativeReceiverResolution::Untyped;
    };
    let receiver_target_kind = value.value_types.target_kind.clone();
    let static_type = value.static_type;
    let Some(TypeRef::Named {
        name, arguments, ..
    }) = static_type
    else {
        return if matches!(static_type, Some(TypeRef::Declared { .. })) {
            JavaNativeReceiverResolution::Typed
        } else {
            JavaNativeReceiverResolution::Untyped
        };
    };
    if !arguments.is_empty() {
        return JavaNativeReceiverResolution::Typed;
    }
    let Some(owner) = java_native_static_external_type(java, query, &name) else {
        return JavaNativeReceiverResolution::Typed;
    };
    JavaNativeReceiverResolution::External {
        owner: owner.fqn().to_owned(),
        form: if receiver_target_kind == TypeLookupTargetKind::TypeReference {
            JavaNativeReceiverForm::TypeQualifier
        } else {
            JavaNativeReceiverForm::BoundValue
        },
    }
}

fn java_native_reference_site_at_node(
    query: BoundedReceiverQuery<'_>,
    node: Node<'_>,
) -> Option<ResolvedReferenceSite> {
    let text = node_text_for_query(node, query.source)?;
    let start = node.start_position();
    let end = node.end_position();
    Some(ResolvedReferenceSite {
        path: query.site.path.clone(),
        text: text.to_owned(),
        range: brokk_bifrost_core::analyzer::model::Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: start.row + 1,
            end_line: end.row + 1,
        },
        focus_start_byte: node.start_byte(),
        focus_end_byte: node.end_byte(),
    })
}

fn java_native_expression_value_type_at_node(
    query: BoundedReceiverQuery<'_>,
    node: Node<'_>,
) -> Option<NativeExpressionValueTypeLookup> {
    let site = java_native_reference_site_at_node(query, node)?;
    let type_query = BoundedReceiverQuery {
        analyzer: query.analyzer,
        file: query.file,
        source: query.source,
        tree: query.tree,
        site: &site,
        budget: query.budget,
        cancellation: query.cancellation,
    };
    match resolve_java_expression_value_type_bounded(type_query, || {}) {
        BoundedResolution::Complete { value, .. } => Some(value),
        BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => None,
    }
}

fn java_native_receiver_type_site_node(mut receiver: Node<'_>) -> Option<Node<'_>> {
    while receiver.kind() == "parenthesized_expression" {
        receiver = receiver.named_child(0)?;
    }
    match receiver.kind() {
        "identifier" | "type_identifier" | "scoped_type_identifier" => Some(receiver),
        "method_invocation" => receiver.child_by_field_name("name"),
        "field_access" => receiver.child_by_field_name("field"),
        "object_creation_expression" => receiver
            .child_by_field_name("type")
            .and_then(java_constructor_type_terminal),
        _ => None,
    }
}

enum JavaNativeReceiverResolution {
    External {
        owner: String,
        form: JavaNativeReceiverForm,
    },
    Typed,
    Untyped,
}

fn java_native_external_type(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    spelling: &str,
) -> Option<crate::analyzer::jvm::external::JvmExternalType> {
    let selected = java_selected_jdk_artifact(java, query);
    match java.resolve_type_name_with_selected_jdk(
        token,
        query.analyzer.semantic_model_overlay(),
        query.file,
        spelling,
        selected
            .as_ref()
            .and_then(|evidence| evidence.artifact_sha256.as_deref()),
    )? {
        JavaTypeResolution::External(external) => Some(external),
        JavaTypeResolution::Source(_) => None,
    }
}

/// This name already came from a complete native static-type result or the
/// selected declaration's return term. Do not replay caller scope lookup on
/// a declaration-owned FQN; raw constructor spellings use the scope resolver.
fn java_native_static_external_type(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    fqn: &str,
) -> Option<crate::analyzer::jvm::external::JvmExternalType> {
    let selected = java_selected_jdk_artifact(java, query);
    let surface = match selected
        .as_ref()
        .and_then(|evidence| evidence.artifact_sha256.as_deref())
    {
        Some(digest) => java
            .external_declarations_for_source_jdk(query.analyzer.semantic_model_overlay(), digest),
        None => java.external_declarations(query.analyzer.semantic_model_overlay()),
    };
    surface.get(fqn)
}

enum JavaNativeExternalInvocation {
    Selected {
        proof: Box<ExactExternalCallProof>,
        dispatch_closed: bool,
    },
    Witnessed,
    Rejected,
}

struct JavaNativeExternalMethodResolution {
    owner: String,
    member: String,
    invocation: JavaNativeExternalInvocation,
}

fn java_native_external_method_resolution(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    owner: &str,
    member: &str,
    actual_types: &[TypeRef],
    form: JavaNativeReceiverForm,
) -> Option<JavaNativeExternalMethodResolution> {
    let canonical = format!("{owner}.{member}");
    let selected = java_selected_jdk_artifact(java, query);
    let resolved: JvmExternalMember = java.resolve_member_name_with_selected_jdk(
        token,
        query.analyzer.semantic_model_overlay(),
        query.file,
        &canonical,
        selected
            .as_ref()
            .and_then(|evidence| evidence.artifact_sha256.as_deref()),
    )?;
    // The written receiver can inherit this member from another declaring owner.
    // Canonical declaration identity and bound-receiver dispatch are independent.
    let (owner, declared_member) = resolved.fqn().rsplit_once('.')?;
    debug_assert_eq!(declared_member, member);
    let member = declared_member;
    let bound_receiver = matches!(form, JavaNativeReceiverForm::BoundValue);
    if resolved.is_static() == bound_receiver {
        return None;
    }
    let surface = match selected
        .as_ref()
        .and_then(|artifact| artifact.artifact_sha256.as_deref())
    {
        Some(digest) => java
            .external_declarations_for_source_jdk(query.analyzer.semantic_model_overlay(), digest),
        None => java.external_declarations(query.analyzer.semantic_model_overlay()),
    };
    let Some(parameter_count) = resolved.applicable_parameter_count_for_argument_types(
        bound_receiver,
        actual_types,
        Some(&surface),
    ) else {
        return Some(JavaNativeExternalMethodResolution {
            owner: owner.to_owned(),
            member: member.to_owned(),
            invocation: if resolved.may_apply_to_argument_types(
                bound_receiver,
                actual_types,
                Some(&surface),
            ) {
                JavaNativeExternalInvocation::Witnessed
            } else {
                JavaNativeExternalInvocation::Rejected
            },
        });
    };
    let proof = match form {
        JavaNativeReceiverForm::BoundValue => {
            ExactExternalCallProof::java_bound_external_member(owner, member, parameter_count)
        }
        JavaNativeReceiverForm::TypeQualifier => {
            ExactExternalCallProof::java_static_external_member(owner, member, parameter_count)
        }
    }
    .with_external_member_identity(
        query
            .analyzer
            .active_semantic_model_snapshot()
            .and_then(|snapshot| {
                resolved.inventory_identity_for_argument_types(
                    snapshot.active_models(),
                    bound_receiver,
                    actual_types,
                    Some(&surface),
                )
            })
            .or_else(|| {
                resolved.direct_inventory_identity_for_argument_types(
                    bound_receiver,
                    actual_types,
                    Some(&surface),
                )
            }),
    )
    .with_source_jdk_artifact(selected.filter(|artifact| {
        artifact.artifact_sha256.as_deref() == resolved.jdk_artifact_sha256()
            && resolved.jdk_artifact_sha256().is_some()
    }));
    let dispatch_closed = resolved
        .non_overridable_for_argument_types(bound_receiver, actual_types, Some(&surface))
        .is_some();
    Some(JavaNativeExternalMethodResolution {
        owner: owner.to_owned(),
        member: member.to_owned(),
        invocation: JavaNativeExternalInvocation::Selected {
            proof: Box::new(proof),
            dispatch_closed,
        },
    })
}

fn publish_java_external_member_identity(
    query: BoundedReceiverQuery<'_>,
    outcome: &mut DefinitionLookupOutcome,
    owner: &str,
    member: &str,
) {
    let reference = outcome.reference.get_or_insert_with(|| query.site.clone());
    reference.text = format!("{owner}.{member}");
}

fn publish_java_external_incomplete_member_identity(
    query: BoundedReceiverQuery<'_>,
    outcome: &mut DefinitionLookupOutcome,
    owner: &str,
    member: &str,
) {
    publish_java_external_member_identity(query, outcome, owner, member);
    outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    if outcome
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.kind != "java_native_external_member_identity")
    {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "java_native_external_member_identity".into(),
            message: format!("`{owner}.{member}` names an external Java member"),
            claim: None,
        });
    }
}

fn java_native_call_argument_types(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    call: Node<'_>,
) -> Option<Vec<TypeRef>> {
    let arguments = call.child_by_field_name("arguments")?;
    if arguments.has_error() || arguments.is_missing() {
        return None;
    }
    let mut cursor = arguments.walk();
    Some(
        arguments
            .named_children(&mut cursor)
            .filter(|argument| !argument.is_extra())
            .map(|argument| {
                java_native_argument_type(java, query, token, argument).unwrap_or(TypeRef::Unknown)
            })
            .collect(),
    )
}

/// The conversion consumer uses the same expression and slot query as native
/// overload selection. The supplied source must still be the selected snapshot.
pub(crate) fn java_native_model_argument_type(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    expression: Node<'_>,
    source: &str,
) -> Option<TypeRef> {
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    let tree = brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language(
        file,
        Language::Java,
        source,
    )?;
    let text = source.get(expression.byte_range())?;
    let site = ResolvedReferenceSite {
        path: brokk_bifrost_core::path_utils::rel_path_string(file),
        text: text.to_owned(),
        range: brokk_bifrost_core::analyzer::model::Range {
            start_byte: expression.start_byte(),
            end_byte: expression.end_byte(),
            start_line: expression.start_position().row + 1,
            end_line: expression.end_position().row + 1,
        },
        focus_start_byte: expression.start_byte(),
        focus_end_byte: expression.end_byte(),
    };
    let cancellation = analyzer.active_query_cancellation();
    let query = BoundedReceiverQuery {
        analyzer,
        file,
        source,
        tree: Some(&tree),
        site: &site,
        budget: Default::default(),
        cancellation: cancellation.as_ref(),
    };
    let scope = AnalyzerQueryScope::new(java);
    java_native_argument_type(java, query, scope.token(), expression)
}

fn java_native_argument_type(
    _java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    mut expression: Node<'_>,
) -> Option<TypeRef> {
    if expression.has_error() || expression.is_missing() {
        return None;
    }
    while expression.kind() == "parenthesized_expression" {
        expression = expression.named_child(0)?;
    }
    if let Some(intrinsic) =
        crate::analyzer::java::call_conversion::intrinsic_argument_type(expression, query.source)
    {
        return Some(intrinsic);
    }
    if matches!(
        expression.kind(),
        "method_invocation" | "object_creation_expression"
    ) {
        // Each nested query descends to a strict argument/receiver child.
        // Bound the remaining resolver call stack by the existing Java
        // expression budget; deeper expressions retain an unknown type.
        let mut nesting = 0;
        let mut ancestor = expression.parent();
        while let Some(node) = ancestor {
            if matches!(
                node.kind(),
                "method_invocation" | "object_creation_expression"
            ) {
                nesting += 1;
            }
            if nesting >= crate::analyzer::java::call_conversion::JAVA_EXPRESSION_DEPTH_LIMIT {
                return None;
            }
            ancestor = node.parent();
        }
        let member = if expression.kind() == "object_creation_expression" {
            let type_node = expression.child_by_field_name("type")?;
            // The existing proof transports a nominal owner, not substituted
            // type arguments. Keep parameterized construction conservative.
            if type_node.kind() == "generic_type" {
                return None;
            }
            java_constructor_type_terminal(type_node)?
        } else {
            expression.child_by_field_name("name")?
        };
        let site = java_native_reference_site_at_node(query, member)?;
        let call_query = BoundedReceiverQuery {
            analyzer: query.analyzer,
            file: query.file,
            source: query.source,
            tree: query.tree,
            site: &site,
            budget: query.budget,
            cancellation: query.cancellation,
        };
        match resolve_java_definition_with_evidence_bounded(call_query, || {}) {
            BoundedResolution::Complete { value, .. } => {
                if let Some(proof) = value.evidence.exact_external_call() {
                    if expression.kind() == "object_creation_expression" {
                        // Nominal identity alone cannot validate a nested call.
                        // The existing constructor proof has independently
                        // selected an applicable declaration using its actuals.
                        let (owner, _) = proof.canonical_callee().rsplit_once('.')?;
                        return Some(TypeRef::Named {
                            name: owner.to_owned(),
                            arguments: Vec::new(),
                            nullable: false,
                        });
                    }
                    let identity = proof.external_member_identity()?;
                    return match _java
                        .inner
                        .analyzer_store()
                        .selected_external_member_return_type(identity)
                    {
                        Ok(ty) => ty.map(|term| {
                            crate::analyzer::jvm::external::normalize_jvm_model_type_ref(
                                query.analyzer.semantic_model_overlay().as_deref(),
                                &term,
                            )
                        }),
                        Err(error) => {
                            eprintln!(
                                "selected external result type read failed for {identity:?}: {error}"
                            );
                            None
                        }
                    };
                }
            }
            BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => {
                return None;
            }
        }
    }
    if let Some((callee, ordinal)) = java_native_argument_projection(expression) {
        let site = java_native_reference_site_at_node(query, callee)?;
        let argument_query = BoundedReceiverQuery {
            site: &site,
            ..query
        };
        return match brokk_bifrost_analysis::analyzer::native_points::resolve_native_call_argument_type_bounded(
            &_java.inner,
            argument_query,
            ordinal,
            prepare_context,
            || {},
        ) {
            BoundedResolution::Complete { value, .. } => value.static_type,
            BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => None,
        };
    }
    let site = java_native_receiver_type_site_node(expression).unwrap_or(expression);
    java_native_expression_value_type_at_node(query, site)?.static_type
}

/// Recover only the structured call coordinate. The stored producer slot,
/// not this syntax walk, supplies the expression's static type.
fn java_native_argument_projection(mut expression: Node<'_>) -> Option<(Node<'_>, u32)> {
    while let Some(parent) = expression.parent() {
        if parent.kind() != "parenthesized_expression" {
            break;
        }
        expression = parent;
    }
    let arguments = expression.parent()?;
    if arguments.kind() != "argument_list" {
        return None;
    }
    let mut cursor = arguments.walk();
    let ordinal = arguments
        .named_children(&mut cursor)
        .filter(|argument| !argument.is_extra())
        .position(|argument| argument == expression)?;
    let call = arguments.parent()?;
    let callee = match call.kind() {
        "method_invocation" => call.child_by_field_name("name")?,
        "object_creation_expression" => {
            java_constructor_type_terminal(call.child_by_field_name("type")?)?
        }
        _ => return None,
    };
    Some((
        callee,
        u32::try_from(ordinal).expect("Java actual ordinal fits u32"),
    ))
}

enum JavaNativeConstructorSelection {
    Proven(usize),
    IncompleteHierarchy,
}

fn java_native_constructor_type_name(
    query: BoundedReceiverQuery<'_>,
    creation: Node<'_>,
    type_node: Node<'_>,
) -> Option<String> {
    let type_name = java_type_name_from_node(type_node, query.source)?;
    // A qualified creation selects the inner type of the enclosing instance,
    // never a same-named import in the caller's lexical scope.
    if let Some(enclosing) = java_object_creation_enclosing_expression(creation, type_node) {
        let site = java_native_receiver_type_site_node(enclosing)?;
        let value = java_native_expression_value_type_at_node(query, site)?.value_types;
        if value.status
            != brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus::Resolved
            || value.target_kind != TypeLookupTargetKind::ValueExpression
        {
            return None;
        }
        let [owner] = value.types.as_slice() else {
            return None;
        };
        Some(format!("{}.{type_name}", owner.fqn))
    } else {
        Some(type_name)
    }
}

fn java_native_external_constructor_proof(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    creation: Node<'_>,
    type_name: &str,
    actual_types: Option<&[TypeRef]>,
) -> Option<(Option<ExactExternalCallProof>, String, String)> {
    let owner = java_native_external_type(java, query, token, type_name)?;
    let type_node = creation
        .child_by_field_name("type")
        .expect("a constructor call site has a structured type node");
    if java_object_creation_enclosing_expression(creation, type_node).is_some()
        && owner.fqn() != type_name
    {
        return None;
    }
    let arguments = creation.child_by_field_name("arguments")?;
    if arguments.has_error() || arguments.is_missing() {
        return None;
    }
    let mut cursor = arguments.walk();
    let actuals = arguments
        .named_children(&mut cursor)
        .filter(|argument| !argument.is_extra())
        .collect::<Vec<_>>();
    if let Some(actual_types) = actual_types {
        assert_eq!(
            actual_types.len(),
            actuals.len(),
            "constructor type facts share the structured actual inventory"
        );
    }
    let overlay = query.analyzer.semantic_model_overlay()?;
    let JvmExternalDeclarationSource::SemanticPack { declaration_id, .. } = owner.source() else {
        return None;
    };
    let arity = u32::try_from(actuals.len()).ok()?;
    let mut matching = overlay
        .members_of(declaration_id)
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.language == "java"
                && symbol.kind == SemanticModelSymbolKind::Constructor
                && !symbol.has_receiver()
                && symbol.visibility
                    == brokk_bifrost_analysis::analyzer::semantic_model::Visibility::Public
                && symbol
                    .structured_signature
                    .as_ref()
                    .is_some_and(|signature| {
                        signature.parameters.len() == arity as usize
                            && signature
                                .parameters
                                .iter()
                                .all(|parameter| !parameter.variadic)
                    })
        });
    let selected = matching.next()?;
    let candidates = std::iter::once(selected)
        .chain(matching)
        .collect::<Vec<_>>();
    if candidates.iter().any(|symbol| {
        !symbol.callable_family_complete
            && symbol.provenance.completeness
                != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness::Complete
    }) {
        return None;
    }
    let signatures = candidates
        .iter()
        .map(|symbol| {
            symbol
                .structured_signature
                .as_ref()
                .expect("constructor candidates have a structured signature")
                .parameters
                .iter()
                .map(|parameter| parameter.r#type.clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let selection = actual_types
        .and_then(|actual_types| {
            crate::analyzer::jvm::external::select_java_external_signature_for_types(
                actual_types,
                &signatures,
            )
        })
        .map(JavaNativeConstructorSelection::Proven)
        .or_else(|| {
            let [signature] = signatures.as_slice() else {
                return None;
            };
            assert_eq!(
                actuals.len(),
                signature.len(),
                "constructor applicability uses the same structured actual count"
            );
            let mut incomplete_hierarchy = false;
            for (actual, formal) in actuals.iter().copied().zip(signature) {
                match crate::analyzer::java::call_conversion::CALL_ARGUMENT_CONVERSION_PROVER
                    .prove_model_argument(java, query.file, actual, query.source, formal)
                {
                    Ok(_) => {}
                    Err(
                        ConversionUnknown::IncompleteHierarchy
                        | ConversionUnknown::UnresolvedSourceType
                        | ConversionUnknown::UnresolvedTargetType
                        | ConversionUnknown::AmbiguousBinding
                        | ConversionUnknown::GenericSubstitution
                        | ConversionUnknown::UnsupportedExpression
                        | ConversionUnknown::BudgetExhausted
                        | ConversionUnknown::SignatureApplicability,
                    ) => {
                        incomplete_hierarchy = true;
                    }
                    Err(_) => return None,
                }
            }
            if incomplete_hierarchy {
                Some(JavaNativeConstructorSelection::IncompleteHierarchy)
            } else {
                Some(JavaNativeConstructorSelection::Proven(0))
            }
        })?;
    let JavaNativeConstructorSelection::Proven(selected_index) = selection else {
        return Some((None, owner.fqn().to_owned(), "<init>".to_owned()));
    };
    let selected = candidates.into_iter().nth(selected_index)?;
    let key = SemanticModelCallableKey::new("java", owner.fqn(), &selected.name, false, arity);
    overlay.callable_family_id_for_target(key)?;
    let member = selected.name.clone();
    let proof = ExactExternalCallProof::java_external_constructor(owner.fqn(), &member, arity);
    Some((Some(proof), owner.fqn().to_owned(), member))
}

fn publish_java_external_call_boundary(
    query: BoundedReceiverQuery<'_>,
    outcome: &mut DefinitionLookupOutcome,
    proof: &ExactExternalCallProof,
    owner: &str,
    member: &str,
) {
    outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    let reference = outcome.reference.get_or_insert_with(|| query.site.clone());
    reference.text = proof.canonical_callee().to_owned();
    if outcome
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.kind != "java_native_external_call_boundary")
    {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "java_native_external_call_boundary".into(),
            message: format!(
                "`{}` names an external Java callable; inventory member {:?}",
                proof.canonical_callee(),
                proof.external_member_identity()
            ),
            claim: Some(UnindexedClaim::external_boundary(
                format!("{owner}.{member}"),
                ClaimSubjectRole::Member,
            )),
        });
    }
}

fn java_selected_jdk_artifact(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
) -> Option<brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence> {
    let home = java.selected_jdk_home_for_file(query.file).ok()?;
    query
        .analyzer
        .active_semantic_model_snapshot()?
        .jdk_artifact_for_home(home)
        .cloned()
}

// The creation keyword has no producer reference. Navigate through the same
// constructor type reference used when the cursor is on the written type.
fn java_creation_keyword_anchor(query: BoundedReceiverQuery<'_>) -> Option<ResolvedReferenceSite> {
    crate::analyzer::jvm::native_points::jvm_reference_anchor(query, |creation| {
        if creation.kind() != "object_creation_expression" {
            return None;
        }
        let mut cursor = creation.walk();
        let keyword = creation
            .children(&mut cursor)
            .find(|child| child.kind() == "new")?;
        if keyword.start_byte() != query.site.focus_start_byte
            || keyword.end_byte() != query.site.focus_end_byte
        {
            return None;
        }
        java_constructor_type_terminal(creation.child_by_field_name("type")?)
    })
}

fn java_constructor_reference_namespace(
    query: &BoundedReceiverQuery<'_>,
) -> Option<ResolutionNamespace> {
    let tree = query.tree?;
    let start = query.site.focus_start_byte;
    let end = query.site.focus_end_byte;
    let reference = tree
        .root_node()
        .named_descendant_for_byte_range(start, end)?;
    if reference.start_byte() != start
        || reference.end_byte() != end
        || !matches!(reference.kind(), "identifier" | "type_identifier")
    {
        return None;
    }
    let mut ancestor = reference.parent();
    while let Some(node) = ancestor {
        if node.kind() == "object_creation_expression"
            && node
                .child_by_field_name("type")
                .and_then(java_constructor_type_terminal)
                .is_some_and(|terminal| terminal.id() == reference.id())
        {
            // An anonymous creation names its written supertype; its synthetic
            // constructor has no source declaration to navigate to.
            return Some(
                if named_children(node)
                    .into_iter()
                    .any(|child| child.kind() == "class_body")
                {
                    ResolutionNamespace::Type
                } else {
                    ResolutionNamespace::Constructor
                },
            );
        }
        ancestor = node.parent();
    }
    None
}

fn java_constructor_type_terminal(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "type_identifier" => return Some(node),
            "scoped_type_identifier" => {
                return node
                    .child_by_field_name("name")
                    .or_else(|| named_children(node).into_iter().last());
            }
            "generic_type" => node = named_children(node).into_iter().next()?,
            _ => return None,
        }
    }
}

pub(crate) fn resolve_java_type_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<TypeLookupOutcome> {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(query.analyzer) else {
        return BoundedResolution::Complete {
            value: unavailable_type(
                query.site,
                "native_analyzer_unavailable",
                "Java analyzer is unavailable".into(),
            ),
            work: ReceiverAnalysisWork::default(),
        };
    };
    resolve_native_type_bounded(&java.inner, query, prepare_context, after_open)
}

fn resolve_java_expression_value_type_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<NativeExpressionValueTypeLookup> {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(query.analyzer) else {
        return BoundedResolution::Complete {
            value: NativeExpressionValueTypeLookup {
                value_types: unavailable_type(
                    query.site,
                    "native_analyzer_unavailable",
                    "Java analyzer is unavailable".into(),
                ),
                static_type: None,
            },
            work: ReceiverAnalysisWork::default(),
        };
    };
    resolve_native_expression_value_type_bounded(&java.inner, query, prepare_context, after_open)
}

fn prepare_context(
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    path: &str,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> brokk_bifrost_analysis::analyzer::store::Result<NativePointContext> {
    Ok(match operation.java_import_context(path, cancellation)? {
        JavaImportContext::Ready { context, .. } => NativePointContext::Ready {
            context,
            selected_import_model: None,
        },
        JavaImportContext::Unavailable => NativePointContext::Unavailable,
        JavaImportContext::Cancelled => NativePointContext::Cancelled,
    })
}

#[cfg(test)]
#[path = "native_points/tests.rs"]
mod tests;

/// The rollout probe's view of the native Java point resolver.
#[allow(dead_code)] // Retained for the coordinated JVM-language native routing flip.
pub(crate) struct JavaNativeRolloutPoints;

impl brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver
    for JavaNativeRolloutPoints
{
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_java_type_bounded(query, || {})
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        resolve_java_definition_bounded(query, || {})
    }

    fn resolve_definition_with_call_evidence_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<(DefinitionLookupOutcome, CallEvidence)> {
        match resolve_java_definition_with_evidence_bounded(query, || {}) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: (value.outcome, value.evidence),
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        }
    }
}
