//! Java selected-context entry point, exercised before atomic JVM cutover.

use super::JavaAnalyzer;
use crate::analyzer::DeclarationKind;
use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::jvm::external::{JvmExternalDeclarationSource, JvmExternalMember};
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::native_points::{
    NativePointContext, resolve_native_definition_bounded, resolve_native_type_bounded,
    unavailable_definition, unavailable_type,
};
use crate::analyzer::resolve_analyzer;
use crate::analyzer::semantic_model::{SemanticModelCallableKey, SemanticModelSymbolKind, TypeRef};
use crate::analyzer::store::resolution_operation::{
    JavaExternalStaticImportBoundary, JavaImportContext,
};
use crate::analyzer::usages::call_conversion::{CallArgumentConversionProver, ConversionUnknown};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, CallEvidence, ClaimSubjectRole, DefinitionLookupDiagnostic,
    DefinitionLookupOutcome, DefinitionLookupStatus, ExactExternalCallProof, UnindexedClaim,
};
use crate::analyzer::usages::get_type::TypeLookupOutcome;
use crate::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, BoundedDefinitionLookup, Language, QueryScope,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::tree_walk::named_children;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
use brokk_bifrost_jvm::java::declarations::find_nearest_declaration_from_node;
use brokk_bifrost_jvm::java::graph::return_type::java_type_name_from_node;
use tree_sitter::Node;

pub(crate) fn resolve_java_definition_bounded(
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
    if value.status != DefinitionLookupStatus::Incomplete
        || !value.definitions.is_empty()
        || value.lexical_definition.is_some()
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

    let (subject, role, external_target) = if let Some(member_node) = member_node {
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
                crate::analyzer::usages::get_definition::record_native_external_route(member_fqn);
                return BoundedResolution::Complete { value, work };
            }
            let target = external_member
                .map(|member| member.fqn().to_owned())
                .or_else(|| match nested_type {
                    Some(JavaTypeResolution::External(nested)) => Some(nested.fqn().to_owned()),
                    Some(JavaTypeResolution::Source(_)) | None => None,
                });
            (member_fqn, ClaimSubjectRole::Member, target)
        } else {
            (member_fqn, ClaimSubjectRole::Member, None)
        }
    } else {
        let target = match resolved_owner {
            Some(JavaTypeResolution::External(external)) => Some(external.fqn().to_owned()),
            Some(JavaTypeResolution::Source(_)) | None => None,
        };
        (owner, ClaimSubjectRole::Type, target)
    };

    crate::analyzer::jvm::native_points::project_jvm_external_boundary(
        &mut value,
        query.site,
        &subject,
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
    token: crate::analyzer::QueryToken<'_>,
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

fn java_imported_type_route_nodes(
    focus: tree_sitter::Node<'_>,
) -> Option<(tree_sitter::Node<'_>, Option<tree_sitter::Node<'_>>)> {
    if focus.kind() == "type_identifier" {
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
        && let Some((proof, owner, member)) = java_native_external_constructor_proof(
            java,
            query,
            token,
            creation,
            type_node,
            java_native_call_argument_types(java, query, token, creation).as_deref(),
        )
    {
        if let Some(proof) = proof {
            publish_java_external_call_boundary(query, outcome, &proof, &owner, &member);
            return evidence.with_native_java_external_call(proof, &owner, &member, false);
        }
        publish_java_external_incomplete_member_identity(query, outcome, &owner, &member);
        return evidence.with_native_java_external_member_identity(&owner, &member);
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
            let external_call = if let Some(receiver) = receiver {
                java_native_external_receiver(java, query, token, receiver).and_then(
                    |(owner, form)| {
                        java_native_external_method_proof(
                            java,
                            query,
                            token,
                            &owner,
                            member_name,
                            &actual_types,
                            form,
                        )
                    },
                )
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
                        java_native_external_method_proof(
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
                java_native_external_method_proof(
                    java,
                    query,
                    token,
                    owner,
                    selected_member,
                    &actual_types,
                    JavaNativeReceiverForm::BoundValue,
                )
                .or_else(|| {
                    java_native_external_method_proof(
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
            if let Some((proof, owner, member, dispatch_closed)) = external_call {
                if let Some(proof) = proof {
                    publish_java_external_call_boundary(query, outcome, &proof, &owner, &member);
                    evidence = evidence.with_native_java_external_call(
                        proof,
                        &owner,
                        &member,
                        dispatch_closed,
                    );
                } else {
                    publish_java_external_member_identity(query, outcome, &owner, &member);
                }
            } else if let Some(receiver) = receiver.filter(|receiver| {
                receiver.kind() == "method_invocation"
                    && outcome.status == DefinitionLookupStatus::Incomplete
                    && outcome.definitions.is_empty()
                    && outcome.lexical_definition.is_none()
            }) && java_chained_receiver_has_no_declaration(java, query, token, receiver)
            {
                publish_java_unmodeled_receiver_boundary(query, outcome, member_name);
            }
        }
        JavaNativeCallSite::Constructor { .. } => {}
    }
    evidence
}

fn java_chained_receiver_has_no_declaration(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    receiver: Node<'_>,
) -> bool {
    use crate::analyzer::usages::get_definition::java::{
        JavaResolutionSession, JavaSourceInvocationReturn, java_external_invocation_return_type,
        java_source_invocation_return_declaration,
    };
    use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    let cancellation = query.analyzer.active_query_cancellation();
    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Java);
    let session = JavaResolutionSession::bounded(
        &definitions,
        ReceiverAnalysisBudget::default(),
        cancellation.as_ref(),
    );
    if !matches!(
        java_source_invocation_return_declaration(
            query.analyzer,
            token,
            &session,
            query.file,
            query.source,
            receiver,
        ),
        JavaSourceInvocationReturn::NoSourceDeclaration
    ) {
        return false;
    }
    java_external_invocation_return_type(java, token, &session, query.file, query.source, receiver)
        .is_none()
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

fn java_native_source_call_evidence(
    analyzer: &dyn crate::analyzer::IAnalyzer,
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
                == Some(crate::analyzer::DispatchExtensibility::Closed)
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
            crate::analyzer::usages::get_definition::CallApplicationKind::PackageFunction
        }
        (JavaNativeCallSite::Method { .. }, false) if is_static => {
            crate::analyzer::usages::get_definition::CallApplicationKind::PackageFunction
        }
        (JavaNativeCallSite::Method { .. }, false) => {
            crate::analyzer::usages::get_definition::CallApplicationKind::BoundReceiver
        }
        _ => return evidence,
    };
    evidence.with_native_java_source_call(
        call_application,
        every_target_is_closed.then_some(crate::analyzer::DispatchExtensibility::Closed),
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
    token: crate::analyzer::QueryToken<'_>,
    receiver: Node<'_>,
) -> Option<(String, JavaNativeReceiverForm)> {
    if matches!(receiver.kind(), "this" | "super") {
        return None;
    }
    if receiver.kind() == "identifier"
        && let Some(name) = node_text_for_query(receiver, query.source)
        && let Some(declaration) = find_nearest_declaration_from_node(receiver, name, query.source)
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
        let type_node = super::declared_type_node(type_declaration)?;
        let type_name = java_type_name_from_node(type_node, query.source)?;
        let owner = java_native_external_type(java, query, token, &type_name)?;
        return Some((owner.fqn().to_owned(), JavaNativeReceiverForm::BoundValue));
    }
    let spelling = node_text_for_query(receiver, query.source)?;
    let owner = java_native_external_type(java, query, token, spelling)?;
    Some((
        owner.fqn().to_owned(),
        JavaNativeReceiverForm::TypeQualifier,
    ))
}

fn java_native_external_type(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
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

fn java_native_external_method_proof(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    owner: &str,
    member: &str,
    actual_types: &[TypeRef],
    form: JavaNativeReceiverForm,
) -> Option<(Option<ExactExternalCallProof>, String, String, bool)> {
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
    if resolved.fqn() != canonical {
        return None;
    }
    let bound_receiver = matches!(form, JavaNativeReceiverForm::BoundValue);
    if resolved.is_static() == bound_receiver {
        return None;
    }
    let Some(parameter_count) =
        resolved.applicable_parameter_count_for_argument_types(bound_receiver, actual_types)
    else {
        return Some((None, owner.to_owned(), member.to_owned(), false));
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
                )
            })
            .or_else(|| {
                resolved.direct_inventory_identity_for_argument_types(bound_receiver, actual_types)
            }),
    )
    .with_source_jdk_artifact(selected.filter(|artifact| {
        artifact.artifact_sha256.as_deref() == resolved.jdk_artifact_sha256()
            && resolved.jdk_artifact_sha256().is_some()
    }));
    let dispatch_closed = resolved
        .non_overridable_for_argument_types(bound_receiver, actual_types)
        .is_some();
    Some((
        Some(proof),
        owner.to_owned(),
        member.to_owned(),
        dispatch_closed,
    ))
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
    token: crate::analyzer::QueryToken<'_>,
    call: Node<'_>,
) -> Option<Vec<TypeRef>> {
    let arguments = call.child_by_field_name("arguments")?;
    if arguments.has_error() || arguments.is_missing() {
        return None;
    }
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|argument| !argument.is_extra())
        .map(|argument| java_native_argument_type(java, query, token, argument))
        .collect()
}

fn java_native_argument_type(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    mut expression: Node<'_>,
) -> Option<TypeRef> {
    if expression.has_error() || expression.is_missing() {
        return None;
    }
    while expression.kind() == "parenthesized_expression" {
        expression = expression.named_child(0)?;
    }
    if let Some(primitive) = super::primitive_actual_type_from_syntax(expression, query.source) {
        return Some(java_native_primitive_type_ref(primitive));
    }
    match expression.kind() {
        "string_literal" | "text_block" => Some(TypeRef::Named {
            name: "java.lang.String".into(),
            arguments: Vec::new(),
            nullable: false,
        }),
        "null_literal" => Some(TypeRef::Named {
            name: "<null>".into(),
            arguments: Vec::new(),
            nullable: false,
        }),
        "identifier" => {
            let name = node_text_for_query(expression, query.source)?;
            let declaration = find_nearest_declaration_from_node(expression, name, query.source)?;
            if !matches!(
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
            ) {
                return None;
            }
            let root = query.tree?.root_node();
            let declaration_node = root.named_descendant_for_byte_range(
                declaration.range.start_byte,
                declaration.range.end_byte,
            )?;
            let type_declaration = declaration_node
                .parent()
                .filter(|parent| parent.kind() == "variable_declarator")
                .unwrap_or(declaration_node);
            let type_node = super::declared_type_node(type_declaration)?;
            java_native_type_ref_from_type_node(java, query, token, type_node)
        }
        "cast_expression" => {
            let type_node = expression.child_by_field_name("type")?;
            java_native_type_ref_from_type_node(java, query, token, type_node)
        }
        "object_creation_expression" => {
            let type_node = expression.child_by_field_name("type")?;
            java_native_type_ref_from_type_node(java, query, token, type_node)
        }
        _ => None,
    }
}

fn java_native_type_ref_from_type_node(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    type_node: Node<'_>,
) -> Option<TypeRef> {
    let mut base = type_node;
    let mut dimensions = 0_usize;
    while base.kind() == "array_type" {
        let mut cursor = base.walk();
        let array_dimensions = base
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "dimensions")
            .count();
        dimensions = dimensions
            .checked_add(array_dimensions.max(1))
            .expect("Java array dimension count must fit usize");
        base = base.child_by_field_name("element")?;
    }
    let mut resolved = if let Some(primitive) = super::primitive_type(base) {
        java_native_primitive_type_ref(primitive)
    } else {
        let type_name = java_type_name_from_node(base, query.source)?;
        java_native_type_ref(java, query, token, &type_name)?
    };
    for _ in 0..dimensions {
        resolved = TypeRef::Array {
            element: Box::new(resolved),
        };
    }
    Some(resolved)
}

fn java_native_primitive_type_ref(
    primitive: crate::analyzer::usages::call_conversion::JavaPrimitive,
) -> TypeRef {
    use crate::analyzer::usages::call_conversion::JavaPrimitive;
    let name = match primitive {
        JavaPrimitive::Boolean => "boolean",
        JavaPrimitive::Byte => "byte",
        JavaPrimitive::Short => "short",
        JavaPrimitive::Char => "char",
        JavaPrimitive::Int => "int",
        JavaPrimitive::Long => "long",
        JavaPrimitive::Float => "float",
        JavaPrimitive::Double => "double",
    };
    TypeRef::Named {
        name: name.into(),
        arguments: Vec::new(),
        nullable: false,
    }
}

fn java_native_type_ref(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    spelling: &str,
) -> Option<TypeRef> {
    if let Some(primitive) = super::primitive_for_name(spelling) {
        return Some(java_native_primitive_type_ref(primitive));
    }
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
        JavaTypeResolution::Source(unit) => Some(TypeRef::Declared {
            id: unit.declaration_id().as_str().to_owned(),
            arguments: Vec::new(),
            nullable: false,
        }),
        JavaTypeResolution::External(external) => Some(TypeRef::Named {
            name: external.fqn().to_owned(),
            arguments: Vec::new(),
            nullable: false,
        }),
    }
}

enum JavaNativeConstructorSelection {
    Proven(usize),
    IncompleteHierarchy,
}

fn java_native_external_constructor_proof(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    creation: Node<'_>,
    type_node: Node<'_>,
    actual_types: Option<&[TypeRef]>,
) -> Option<(Option<ExactExternalCallProof>, String, String)> {
    let type_name = java_type_name_from_node(type_node, query.source)?;
    let owner = java_native_external_type(java, query, token, &type_name)?;
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
                && symbol.visibility == crate::analyzer::semantic_model::Visibility::Public
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
                != crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
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
    let selection =
        actual_types
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
                    match super::call_conversion::CALL_ARGUMENT_CONVERSION_PROVER
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
) -> Option<crate::analyzer::semantic_model::SemanticModelActivationEvidence> {
    let home = java.selected_jdk_home_for_file(query.file).ok()?;
    query
        .analyzer
        .active_semantic_model_snapshot()?
        .jdk_artifact_for_home(home)
        .cloned()
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

fn prepare_context(
    operation: &crate::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    path: &str,
    cancellation: &crate::CancellationToken,
) -> crate::analyzer::store::Result<NativePointContext> {
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

impl crate::analyzer::languages::StructuralReceiverResolver for JavaNativeRolloutPoints {
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
