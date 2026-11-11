//! Java selected-context entry point, exercised before atomic JVM cutover.

use crate::analyzer::java::JavaAnalyzer;

use brokk_bifrost_core::analyzer::model::DeclarationKind;

use crate::analyzer::java::imports::JavaTypeResolution;

use crate::analyzer::jvm::external::JvmExternalMember;
use crate::analyzer::jvm::external::QueryGapRecorder;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::native_points::NativeExpressionValueTypeLookup;

use brokk_bifrost_analysis::analyzer::native_points::NativePointContext;

use brokk_bifrost_analysis::analyzer::native_points::resolve_native_definition_answer_bounded_in_batch;
#[cfg(test)]
use brokk_bifrost_analysis::analyzer::native_points::resolve_native_definition_bounded;

use brokk_bifrost_analysis::analyzer::native_points::resolve_native_type_bounded;

use brokk_bifrost_analysis::analyzer::native_points::unavailable_definition;

use brokk_bifrost_analysis::analyzer::native_points::unavailable_type;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::resolution::SelectedExplicitImportBoundary;
use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JavaExternalStaticImportBoundary;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JavaImportContext;

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

use brokk_bifrost_analysis::analyzer::native_points::{NativePointBatch, NativePointRole};
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
        BoundedResolution::Unavailable { reason, work } => {
            BoundedResolution::Unavailable { reason, work }
        }
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

#[derive(Debug, Clone)]
pub(crate) struct JavaNativeDefinitionResolution {
    pub(crate) outcome: DefinitionLookupOutcome,
    pub(crate) evidence: CallEvidence,
    // Only call-local scope/applicability obligations escape to a proved
    // receiver consumer. Result-only generic gaps remain on that result (#7667).
    pub(crate) call_binding_reason_digests: Vec<[u8; 32]>,
}

#[derive(Debug)]
struct NativeExternalArgumentBinding {
    completion: brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion,
    members: Vec<brokk_bifrost_analysis::analyzer::resolution::ExternalMemberIdentity>,
    reason_digests: Vec<(
        brokk_bifrost_analysis::analyzer::resolution::SemanticId,
        [u8; 32],
    )>,
    call_binding_reason_digests: Vec<[u8; 32]>,
    constructor_hierarchy_reason_digests: Vec<(std::sync::Arc<str>, [u8; 32])>,
    static_type_qualifier_reason_digests: Vec<(
        brokk_bifrost_analysis::analyzer::resolution::ExternalOwnerIdentity,
        [u8; 32],
    )>,
}

impl NativeExternalArgumentBinding {
    fn extend_static_type_qualifier_reasons(
        &self,
        proof: &ExactExternalCallProof,
        reasons: &mut Vec<[u8; 32]>,
    ) {
        let Some(identity) = proof.external_member_identity() else {
            return;
        };
        reasons.extend(
            self.static_type_qualifier_reason_digests
                .iter()
                .filter(|(owner, _)| owner == &identity.owner)
                .map(|(_, digest)| *digest),
        );
    }

    fn admits(
        &self,
        proof: &ExactExternalCallProof,
        owner: &str,
        member: &str,
        receiver_calls: &[[u8; 32]],
    ) -> bool {
        // The Java prover selected one declaration using every actual conversion.
        // Its inventory_identity_for_argument_types compares the selected formal
        // list (including arity); the identity below is published unchanged as
        // the binding target by with_native_java_external_call.
        let Some(identity) = proof.external_member_identity() else {
            return false;
        };
        // The receiver owner is the shared route's nominal FQN, including an
        // intrinsic Object. Comparing it does not map or replace root identities.
        if identity.owner.owner_fqn.as_ref() != owner
            || proof.canonical_callee().rsplit_once('.') != Some((owner, member))
            || (!self.members.is_empty() && !self.members.contains(identity))
        {
            return false;
        }
        match &self.completion {
            brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete => true,
            brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Incomplete(reasons) => reasons.iter().all(|reason| {
                let reason = match reason {
                    brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(reason)
                    | brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::OpenBoundary {
                        semantic: reason,
                        status: brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus::ExternalDeclaredUnindexed,
                    } => reason,
                    _ => return false,
                };
                self.reason_digests.iter().any(|(candidate, digest)| {
                    candidate == reason
                        && (receiver_calls.contains(digest)
                            || self.call_binding_reason_digests.contains(digest))
                })
            }),
        }
    }
}

#[derive(Debug)]
enum JavaNativePointStop {
    Exceeded(
        brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit,
        ReceiverAnalysisWork,
    ),
    #[allow(dead_code)]
    Unavailable(&'static str, ReceiverAnalysisWork),
    Cancelled(ReceiverAnalysisWork),
}

pub(crate) fn resolve_java_definition_with_evidence_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<JavaNativeDefinitionResolution> {
    resolve_java_definition_with_evidence_in_batch(query, None, after_open)
}

pub(crate) fn resolve_java_definition_with_evidence_in_batch(
    query: BoundedReceiverQuery<'_>,
    batch: Option<&NativePointBatch>,
    after_open: impl FnOnce(),
) -> BoundedResolution<JavaNativeDefinitionResolution> {
    let Ok(_model_scope) =
        brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::pin_selected_model_snapshot(
            query.analyzer,
        )
    else {
        return BoundedResolution::Complete {
            value: JavaNativeDefinitionResolution {
                outcome: unavailable_definition(
                    query.site,
                    "native_stale",
                    "selected model authority changed".into(),
                ),
                evidence: CallEvidence::default(),
                call_binding_reason_digests: Vec::new(),
            },
            work: ReceiverAnalysisWork::default(),
        };
    };
    let anchored = java_creation_keyword_anchor(query);
    let query = match &anchored {
        Some(site) => BoundedReceiverQuery { site, ..query },
        None => query,
    };
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(query.analyzer) else {
        return resolve_java_definition_with_evidence_uncached(query, None, after_open);
    };
    match batch {
        Some(batch) => {
            use brokk_bifrost_analysis::analyzer::native_points::map_bounded;
            let resolved = batch.definition(&java.inner, query, || map_bounded(
                resolve_java_definition_with_evidence_uncached(query, Some(batch), after_open),
                |value| brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution {
                    outcome: value.outcome,
                    evidence: value.evidence,
                    call_binding_discharge_digests: value.call_binding_reason_digests,
                },
            ));
            map_bounded(resolved, |value| JavaNativeDefinitionResolution {
                outcome: value.outcome,
                evidence: value.evidence,
                call_binding_reason_digests: value.call_binding_discharge_digests,
            })
        }
        None => resolve_java_definition_with_evidence_uncached(query, None, after_open),
    }
}

fn resolve_java_definition_with_evidence_uncached(
    query: BoundedReceiverQuery<'_>,
    batch: Option<&NativePointBatch>,
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
                call_binding_reason_digests: Vec::new(),
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

    let resolution = resolve_native_definition_answer_bounded_in_batch(
        &java.inner,
        query,
        reference_namespace,
        batch,
        |operation, path, cancellation| {
            Ok(
                match java_import_context(java, query.analyzer, operation, path, cancellation)? {
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
                },
            )
        },
        after_open,
        |answer| {
            let boundary = answer.explicit_import_boundary.clone();
            let Some(binding) = answer.argument_binding.as_ref() else {
                return (None, boundary);
            };
            let binding = NativeExternalArgumentBinding {
                completion: binding.completion().clone(),
                reason_digests: answer.argument_reason_digests.clone(),
                static_type_qualifier_reason_digests: answer
                    .static_type_qualifier_reason_digests
                    .clone(),
                call_binding_reason_digests: answer.call_binding_reason_digests.clone(),
                constructor_hierarchy_reason_digests: answer
                    .constructor_hierarchy_reason_digests
                    .clone(),
                members: answer
                    .external_members
                    .iter()
                    .map(|member| member.identity.clone())
                    .collect(),
            };
            (Some(binding), boundary)
        },
    );
    let (resolution, (argument_binding, explicit_import_boundary)) = match resolution {
        BoundedResolution::Complete {
            value: (outcome, projected),
            work,
        } => (
            BoundedResolution::Complete {
                value: outcome,
                work,
            },
            projected.unwrap_or_default(),
        ),
        BoundedResolution::Cancelled { work } => return BoundedResolution::Cancelled { work },
        BoundedResolution::Exceeded { limit, work } => {
            return BoundedResolution::Exceeded { limit, work };
        }
        BoundedResolution::Unavailable { reason, work } => {
            return BoundedResolution::Unavailable { reason, work };
        }
    };

    let resolution =
        crate::analyzer::jvm::native_points::project_jvm_declaration_site(query, resolution);
    let resolution = apply_static_import_boundary(&site_text, &external_static_imports, resolution);
    let resolution = apply_explicit_type_import_boundary(
        java,
        query,
        &open_jvm_alias_imports,
        explicit_import_boundary,
        resolution,
    );
    match resolution {
        BoundedResolution::Complete { mut value, work } => {
            let mut call_binding_reason_digests = Vec::new();
            let evidence = match java_native_call_evidence(
                java,
                query,
                &mut value,
                &external_static_imports,
                argument_binding.as_ref(),
                &mut call_binding_reason_digests,
                batch,
            ) {
                Ok(evidence) => evidence,
                Err(JavaNativePointStop::Exceeded(limit, nested_work)) => {
                    return BoundedResolution::Exceeded {
                        limit,
                        work: nested_work,
                    };
                }
                Err(JavaNativePointStop::Unavailable(reason, nested_work)) => {
                    return BoundedResolution::Unavailable {
                        reason,
                        work: nested_work,
                    };
                }
                Err(JavaNativePointStop::Cancelled(nested_work)) => {
                    return BoundedResolution::Cancelled { work: nested_work };
                }
            };

            BoundedResolution::Complete {
                value: JavaNativeDefinitionResolution {
                    outcome: value,
                    evidence,
                    call_binding_reason_digests,
                },
                work,
            }
        }
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Unavailable { reason, work } => {
            BoundedResolution::Unavailable { reason, work }
        }
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

/// Project a Java import boundary onto an answer with no target. A scoped
/// type whose qualifier is outside the workspace is a type-context route. A
/// simple type name uses the store's simple-type-name decision, which names
/// the winning single-type import. An ambiguous `N.member` prefix is a
/// different question (JLS 6.5.2): no type-name decision reclassifies it, so
/// it keeps the store's Incomplete answer until a prefix decision proves it.
///
/// An import declaration's own target name is still answered here from the
/// analyzer's import declarations (#9546 follow-up): the store has no link
/// from that terminal reference to its binder, so its boundary is not part
/// of the simple-type-name decision.
fn apply_explicit_type_import_boundary(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    open_jvm_alias_imports: &[String],
    explicit_import_boundary: Option<SelectedExplicitImportBoundary>,
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
    if java_is_import_target_name(focus) {
        let Some(simple_name) = query
            .source
            .get(focus.start_byte()..focus.end_byte())
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
        let external_target = match java.resolve_type_name_with_external(
            token,
            query.analyzer.semantic_model_overlay(),
            query.file,
            &owner,
        ) {
            Some(JavaTypeResolution::Source(_)) => {
                return BoundedResolution::Complete { value, work };
            }
            Some(JavaTypeResolution::External(external)) => Some(external.fqn().to_owned()),
            None => None,
        };
        crate::analyzer::jvm::native_points::project_jvm_external_boundary(
            &mut value,
            query.site,
            simple_name,
            external_target.as_deref(),
            None,
        );
        value
            .diagnostics
            .insert(0, java_imported_type_boundary_diagnostic(owner));
        return BoundedResolution::Complete { value, work };
    }
    let Some(boundary) = explicit_import_boundary else {
        return BoundedResolution::Complete { value, work };
    };
    crate::analyzer::jvm::native_points::project_jvm_external_boundary(
        &mut value,
        query.site,
        &boundary.simple_name,
        boundary.external_target.as_deref(),
        None,
    );
    value.diagnostics.insert(
        0,
        java_imported_type_boundary_diagnostic(boundary.imported_fqn.to_string()),
    );
    BoundedResolution::Complete { value, work }
}

fn java_imported_type_boundary_diagnostic(subject: String) -> DefinitionLookupDiagnostic {
    DefinitionLookupDiagnostic {
        kind: "java_imported_type_external_boundary".into(),
        message: format!(
            "`{subject}` is reached through an explicit Java type import not indexed in this workspace; its declaration may be outside the indexed workspace, including when only a partial workspace is indexed"
        ),
        claim: Some(UnindexedClaim::external_boundary(
            subject,
            ClaimSubjectRole::Type,
        )),
    }
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

fn native_external_member_inventory_selected(outcome: &DefinitionLookupOutcome) -> bool {
    outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "native_external_member_inventory")
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
        // #7619: the nearer selected family owns both navigation and call evidence.
        || native_external_member_inventory_selected(&value)
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
    argument_binding: Option<&NativeExternalArgumentBinding>,
    call_binding_reason_digests: &mut Vec<[u8; 32]>,
    batch: Option<&NativePointBatch>,
) -> Result<CallEvidence, JavaNativePointStop> {
    if outcome.status == DefinitionLookupStatus::Unavailable {
        return Ok(CallEvidence::default());
    }
    let mut evidence = CallEvidence::native_java_selected();
    let Some(call_site) = java_native_call_site(query) else {
        return Ok(evidence);
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
            return Ok(evidence);
        }
        let actual_types = if type_name.is_some() {
            java_native_call_argument_types(java, query, token, creation, batch)?
        } else {
            None
        };
        if let Some((proof, owner, member)) = type_name.and_then(|type_name| {
            java_native_external_constructor_proof(
                java,
                query,
                token,
                creation,
                &type_name,
                actual_types.as_deref(),
            )
        }) {
            // Constructor-only exception: the exact constructed owner's
            // unread hierarchy cannot hide a constructor, which is not inherited.
            // Do not export these identities to a later member receiver.
            let constructor_reasons = argument_binding
                .map(|binding| {
                    binding
                        .constructor_hierarchy_reason_digests
                        .iter()
                        .filter(|(candidate, _)| candidate.as_ref() == owner)
                        .map(|(_, digest)| *digest)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if let Some(proof) = proof
                && argument_binding.is_some_and(|binding| {
                    binding.admits(&proof, &owner, &member, &constructor_reasons)
                })
            {
                if let Some(binding) = argument_binding {
                    call_binding_reason_digests
                        .extend_from_slice(&binding.call_binding_reason_digests);
                }
                publish_java_external_call_boundary(query, outcome, &proof, &owner, &member);
                return Ok(evidence.with_native_java_external_call(proof, &owner, &member, false));
            }
            publish_java_external_incomplete_member_identity(query, outcome, &owner, &member);
            return Ok(evidence.with_native_java_external_member_identity(&owner, &member));
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
            && !native_external_member_inventory_selected(outcome))
        || (outcome.status == DefinitionLookupStatus::Incomplete
            && !outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "incomplete_binding"))
    {
        return Ok(java_native_source_call_evidence(
            query.analyzer,
            outcome,
            call_site,
            evidence,
        ));
    }
    match call_site {
        JavaNativeCallSite::Method {
            invocation,
            receiver,
            member,
        } => {
            let Some(member_name) = node_text_for_query(member, query.source) else {
                return Ok(evidence);
            };
            let Some(actual_types) =
                java_native_call_argument_types(java, query, token, invocation, batch)?
            else {
                return Ok(evidence);
            };

            let mut receiver_call_reasons = Vec::new();
            let receiver_type = receiver
                .map(|receiver| {
                    java_native_external_receiver(
                        java,
                        query,
                        token,
                        receiver,
                        invocation,
                        &mut receiver_call_reasons,
                        batch,
                    )
                })
                .transpose()?;

            let external_call = if receiver.is_some() {
                match receiver_type.as_ref() {
                    Some(
                        JavaNativeReceiverResolution::External {
                            owner,
                            form,
                            arguments,
                        }
                        | JavaNativeReceiverResolution::ParameterizedCallResult {
                            owner,
                            form,
                            arguments,
                        },
                    ) => java_native_external_method_resolution(
                        java,
                        query,
                        token,
                        owner,
                        member_name,
                        &actual_types,
                        *form,
                        arguments.as_deref(),
                    ),
                    Some(
                        JavaNativeReceiverResolution::Typed | JavaNativeReceiverResolution::Untyped,
                    )
                    | None => None,
                }
            } else if native_external_member_inventory_selected(outcome) {
                // #7619: a selected nearer inherited member owns this call.
                // Static imports cannot replace its external inventory family.
                None
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
                            None,
                        )
                    })
                }
            };
            let external_call = external_call.or_else(|| {
                // This canonical value comes from selected external inventory
                // rows, not from parsing the call's source text.
                if receiver.is_some() || !native_external_member_inventory_selected(outcome) {
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
                    None,
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
                        None,
                    )
                })
            });
            if let Some(JavaNativeExternalMethodResolution {
                owner,
                member,
                invocation,
                model_member_selection,
            }) = external_call
            {
                evidence.model_member_selection = model_member_selection;
                match invocation {
                    JavaNativeExternalInvocation::Selected {
                        proof,
                        dispatch_closed,
                    } => {
                        if matches!(
                            receiver_type.as_ref(),
                            Some(JavaNativeReceiverResolution::External {
                                form: JavaNativeReceiverForm::TypeQualifier,
                                ..
                            })
                        ) && let Some(binding) = argument_binding
                        {
                            // The qualifier is a type, not a value whose declared
                            // type may be a supertype of the actual member owner.
                            // Only the exact declaring model identity can close it.
                            binding.extend_static_type_qualifier_reasons(
                                &proof,
                                &mut receiver_call_reasons,
                            );
                        }
                        // #7619: strict and loose invocation applicability do
                        // not depend on the return type (JLS 15.12.2). A type
                        // parameter anywhere in a parameter already makes the
                        // Java conversion prover return Unknown. Thus a proven
                        // conversion for every argument permits the registered
                        // result-only generic obligation to remain on the result
                        // type without contaminating the actual-to-formal binding.
                        // Never bypass any other shared receiver obligation.
                        let needs_owner_discharge = matches!(
                            receiver_type.as_ref(),
                            Some(JavaNativeReceiverResolution::ParameterizedCallResult { .. })
                        ) || (matches!(
                            receiver_type.as_ref(),
                            Some(JavaNativeReceiverResolution::External {
                                form: JavaNativeReceiverForm::BoundValue,
                                ..
                            })
                        ) && argument_binding.is_some_and(
                            |binding| !binding.static_type_qualifier_reason_digests.is_empty(),
                        ));
                        // A value receiver must not reuse a type qualifier's
                        // owner discharge, even when the member is selected.
                        if needs_owner_discharge
                            && !argument_binding.is_some_and(|binding| {
                                binding.admits(&proof, &owner, &member, &receiver_call_reasons)
                            })
                        {
                            publish_java_external_incomplete_member_identity(
                                query, outcome, &owner, &member,
                            );
                            return Ok(
                                evidence.with_native_java_external_member_identity(&owner, &member)
                            );
                        }
                        // Each inherited call-local identity is accepted only
                        // after that receiver call independently proved the same
                        // selected member and all conversions. Owner uncertainty
                        // and inherited generic-result reasons are never exported.
                        call_binding_reason_digests.extend_from_slice(&receiver_call_reasons);
                        if let Some(binding) = argument_binding {
                            call_binding_reason_digests
                                .extend_from_slice(&binding.call_binding_reason_digests);
                        }
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
    Ok(evidence)
}

fn publish_java_unmodeled_receiver_boundary(
    query: BoundedReceiverQuery<'_>,
    outcome: &mut DefinitionLookupOutcome,
    member: &str,
) {
    let reference = outcome.reference.get_or_insert_with(|| query.site.clone());
    reference.text = member.to_owned();
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
    // A parameter declared directly with a single-type import has an import
    // owner even when that owner's members are not indexed (JLS 7.5.1).
    // Keep this distinct from an unbounded type parameter or a call result,
    // neither of which proves an imported owner.
    if let Some(site) = java_constructor_type_terminal(type_node)
        && let Some(value) = java_native_expression_value_type_at_node(query, site)
        && value
            .value_types
            .types
            .iter()
            .all(|ty| ty.definitions.is_empty())
        && value
            .value_types
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "jvm-import-owner-open")
        && let Some(canonical) = java.explicit_imported_type_fqn(token, query.file, &type_name)
        && value.value_types.types.iter().all(|ty| ty.fqn == canonical)
    {
        outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
        return;
    }
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
        // This bound was proved to name an unindexed import. An unbounded
        // type variable never reaches this branch and remains incomplete.
        outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
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
    receiver_call_reasons: &mut Vec<[u8; 32]>,
    batch: Option<&NativePointBatch>,
) -> Result<JavaNativeReceiverResolution, JavaNativePointStop> {
    let from_site_type = java_native_external_receiver_from_site_type(
        java,
        query,
        token,
        receiver,
        enclosing_call,
        receiver_call_reasons,
        batch,
    )?;

    if !matches!(from_site_type, JavaNativeReceiverResolution::Untyped) {
        return Ok(from_site_type);
    }
    // Preserve established parameter/local and type-qualifier receiver binding.
    // Actual applicability and selected external call-result typing are separate
    // claims; neither is inferred by these receiver-binding routes.
    if let Some(receiver) =
        java_native_external_receiver_from_identifier(java, query, token, receiver)
    {
        return Ok(receiver);
    }
    if let Some(receiver) =
        java_native_external_receiver_from_type_qualifier(java, query, token, receiver)
    {
        return Ok(receiver);
    }
    Ok(JavaNativeReceiverResolution::Untyped)
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
            arguments: None,
        });
    }
    let owner = java_native_external_type(java, query, token, name)?;
    Some(JavaNativeReceiverResolution::External {
        owner: owner.fqn().to_owned(),
        form: JavaNativeReceiverForm::TypeQualifier,
        arguments: None,
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
        arguments: None,
    })
}

fn java_native_external_receiver_from_site_type(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    receiver: Node<'_>,
    _enclosing_call: Node<'_>,

    receiver_call_reasons: &mut Vec<[u8; 32]>,
    batch: Option<&NativePointBatch>,
) -> Result<JavaNativeReceiverResolution, JavaNativePointStop> {
    if receiver.kind() == "method_invocation" {
        return Ok(
            match java_native_argument_type_with_call_reasons(
                java,
                query,
                token,
                receiver,
                receiver_call_reasons,
                batch,
            )? {
                Some(TypeRef::Named {
                    name, arguments, ..
                }) => match java_native_static_external_type(java, query, &name) {
                    Some(owner) if !arguments.is_empty() => {
                        JavaNativeReceiverResolution::ParameterizedCallResult {
                            owner: owner.fqn().to_owned(),
                            form: JavaNativeReceiverForm::BoundValue,
                            arguments: Some(arguments),
                        }
                    }
                    Some(owner) => JavaNativeReceiverResolution::External {
                        owner: owner.fqn().to_owned(),
                        form: JavaNativeReceiverForm::BoundValue,
                        arguments: None,
                    },
                    None => JavaNativeReceiverResolution::Typed,
                },
                Some(TypeRef::Declared { .. }) => JavaNativeReceiverResolution::Typed,
                _ => JavaNativeReceiverResolution::Untyped,
            },
        );
    }
    if matches!(receiver.kind(), "this" | "super") {
        return Ok(JavaNativeReceiverResolution::Typed);
    }
    let mut receiver_expression = receiver;
    while receiver_expression.kind() == "parenthesized_expression" {
        let Some(inner) = receiver_expression.named_child(0) else {
            return Ok(JavaNativeReceiverResolution::Untyped);
        };
        receiver_expression = inner;
    }
    // An anonymous creation's value is the anonymous class, which its
    // declaration types through the site path below; only a named class
    // creation takes its receiver from the constructor binding (#10021).
    // Some(proof) below requires Selected, the unique applicable complete
    // binding; Witnessed (applicable with open alternatives) yields None.
    // Java constructors are not inherited, so that exact owner's class is
    // the class created here.
    if receiver_expression.kind() == "object_creation_expression"
        && !named_children(receiver_expression)
            .into_iter()
            .any(|child| child.kind() == "class_body")
        && let Some(type_node) = receiver_expression.child_by_field_name("type")
        && let Some(type_name) =
            java_native_constructor_type_name(query, receiver_expression, type_node)
        && java_native_external_type(java, query, token, &type_name).is_some()
    {
        let actuals =
            java_native_call_argument_types(java, query, token, receiver_expression, batch)?;
        let binding = java_native_external_constructor_proof(
            java,
            query,
            token,
            receiver_expression,
            &type_name,
            actuals.as_deref(),
        );
        if let Some((Some(_proof), owner, _)) = binding.as_ref() {
            return Ok(JavaNativeReceiverResolution::External {
                owner: owner.clone(),
                form: JavaNativeReceiverForm::BoundValue,
                // A creation's explicit or inferred type arguments are not
                // bound yet (#7860), so its members keep unsubstituted
                // signatures.
                arguments: None,
            });
        }
        // A witnessed binding has an applicable target despite open
        // alternatives. A rejected binding has none. Reuse the same
        // refusal rule as nested argument conversion without resolving
        // the call again while the site's store reader is held.
        if java_native_creation_constructor_refused(false, false, false, binding.is_some()) {
            return Ok(JavaNativeReceiverResolution::Untyped);
        }
    }

    let Some(site_node) = java_native_receiver_type_site_node(receiver) else {
        return Ok(JavaNativeReceiverResolution::Untyped);
    };

    let Some(value) = java_native_expression_value_type_at_node_in_batch(query, site_node, batch)?
    else {
        return Ok(JavaNativeReceiverResolution::Untyped);
    };
    Ok((|| -> JavaNativeReceiverResolution {
        let mut receiver_expression = receiver;
        while receiver_expression.kind() == "parenthesized_expression" {
            let Some(inner) = receiver_expression.named_child(0) else {
                return JavaNativeReceiverResolution::Untyped;
            };
            receiver_expression = inner;
        }
        let is_type_name = matches!(
            receiver_expression.kind(),
            "identifier" | "type_identifier" | "scoped_type_identifier" | "field_access"
        );
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
        let Some(owner) = java_native_static_external_type(java, query, &name) else {
            return JavaNativeReceiverResolution::Typed;
        };
        JavaNativeReceiverResolution::External {
            owner: owner.fqn().to_owned(),
            // Only the store-projected Applied shape supplies exact arguments.
            // The AST-declared fallback deliberately supplies none.
            arguments: (!arguments.is_empty()).then_some(arguments),
            // Only name-like references can denote a static type qualifier.
            form: if is_type_name && receiver_target_kind == TypeLookupTargetKind::TypeReference {
                JavaNativeReceiverForm::TypeQualifier
            } else {
                JavaNativeReceiverForm::BoundValue
            },
        }
    })())
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
    java_native_expression_value_type_at_node_in_batch(query, node, None)
        .ok()
        .flatten()
}

fn java_native_expression_value_type_at_node_in_batch(
    query: BoundedReceiverQuery<'_>,
    node: Node<'_>,
    batch: Option<&NativePointBatch>,
) -> Result<Option<NativeExpressionValueTypeLookup>, JavaNativePointStop> {
    let Some(site) = java_native_reference_site_at_node(query, node) else {
        return Ok(None);
    };
    let type_query = BoundedReceiverQuery {
        site: &site,
        ..query
    };
    let resolve = || resolve_java_expression_value_type_in_batch(type_query, batch, || {});
    let result = match batch {
        Some(batch) => match resolve_analyzer::<JavaAnalyzer>(query.analyzer) {
            Some(java) => batch.expression(
                &java.inner,
                type_query,
                NativePointRole::ExpressionValue,
                resolve,
            ),
            None => resolve(),
        },
        None => resolve(),
    };
    match result {
        BoundedResolution::Complete { value, .. } => Ok(Some(value)),
        BoundedResolution::Exceeded { limit, work } => {
            Err(JavaNativePointStop::Exceeded(limit, work))
        }
        BoundedResolution::Unavailable { reason, work } => {
            Err(JavaNativePointStop::Unavailable(reason, work))
        }
        BoundedResolution::Cancelled { work } => Err(JavaNativePointStop::Cancelled(work)),
    }
}

fn java_native_receiver_type_site_node(mut receiver: Node<'_>) -> Option<Node<'_>> {
    while receiver.kind() == "parenthesized_expression" {
        receiver = receiver.named_child(0)?;
    }
    match receiver.kind() {
        "identifier" | "type_identifier" | "scoped_type_identifier" => Some(receiver),
        // The expression-value resolver indexes references by source range;
        // a cast's target reference is the selected site for its value type.
        "cast_expression" => {
            let mut cursor = receiver.walk();
            let mut types = receiver.children_by_field_name("type", &mut cursor);
            let type_node = types.next()?;
            types.next().is_none().then_some(type_node)
        }
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
        arguments: Option<Vec<TypeRef>>,
    },
    ParameterizedCallResult {
        owner: String,
        form: JavaNativeReceiverForm,
        arguments: Option<Vec<TypeRef>>,
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
    let selected = java.selected_jdk_artifact_for_file(query.analyzer, query.file);
    match java.resolve_type_name_with_selected_jdk(
        token,
        query.analyzer.semantic_model_overlay(),
        query.file,
        spelling,
        selected
            .as_ref()
            .and_then(|evidence| evidence.artifact_sha256.as_deref()),
    )? {
        JavaTypeResolution::External(external) => Some(external.into_type()),
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
    let selected = java.selected_jdk_artifact_for_file(query.analyzer, query.file);
    let surface = match selected
        .as_ref()
        .and_then(|evidence| evidence.artifact_sha256.as_deref())
    {
        Some(digest) => java
            .external_declarations_for_source_jdk(query.analyzer.semantic_model_overlay(), digest),
        None => java.external_declarations(query.analyzer.semantic_model_overlay()),
    };
    surface.get(&QueryGapRecorder::new(java), fqn)
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
    model_member_selection: Option<Box<brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeModelMemberSelection>>,
    owner: String,
    member: String,
    invocation: JavaNativeExternalInvocation,
}

#[expect(
    clippy::too_many_arguments,
    reason = "receiver owner, arguments, and call context are independent selection inputs"
)]
fn java_native_external_method_resolution(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    owner: &str,
    member: &str,
    actual_types: &[TypeRef],
    form: JavaNativeReceiverForm,
    receiver_arguments: Option<&[TypeRef]>,
) -> Option<JavaNativeExternalMethodResolution> {
    let query_owner = owner;
    let canonical = format!("{owner}.{member}");
    let selected = java.selected_jdk_artifact_for_file(query.analyzer, query.file);
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
    }
    .with_active_models(
        query
            .analyzer
            .active_semantic_model_snapshot()
            .map(|snapshot| std::sync::Arc::clone(snapshot.active_models())),
    );
    let owner_bindings = receiver_arguments
        .and_then(|arguments| surface.java_owner_bindings(query_owner, owner, arguments));
    let (selection, model_member_selection) = if let Some(bindings) = owner_bindings.as_ref() {
        resolved.invocation_with_bound_diagnostics(
            bound_receiver,
            actual_types,
            Some(&surface),
            Some(bindings),
        )
    } else {
        resolved.invocation_with_diagnostics(bound_receiver, actual_types, Some(&surface))
    };
    record_external_invocation(
        query.site.focus_start_byte,
        owner,
        member,
        selection.as_ref().err().copied(),
    );
    let parameter_count = match selection {
        Ok(count) => count,
        Err(cause) => {
            return Some(JavaNativeExternalMethodResolution {
                model_member_selection,
                owner: owner.to_owned(),
                member: member.to_owned(),
                invocation: match cause {
                    JavaExternalInvocationFailure::NoApplicable => {
                        JavaNativeExternalInvocation::Rejected
                    }
                    JavaExternalInvocationFailure::Ambiguous
                    | JavaExternalInvocationFailure::Unproven => {
                        JavaNativeExternalInvocation::Witnessed
                    }
                },
            });
        }
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
                    owner_bindings.as_ref(),
                )
            })
            .or_else(|| {
                resolved.direct_inventory_identity_for_argument_types(
                    bound_receiver,
                    actual_types,
                    Some(&surface),
                    owner_bindings.as_ref(),
                )
            }),
    )
    .with_source_jdk_artifact(selected.filter(|artifact| {
        artifact.artifact_sha256.as_deref() == resolved.jdk_artifact_sha256()
            && resolved.jdk_artifact_sha256().is_some()
    }));
    let mut proof = proof;
    proof.type_argument_bindings = owner_bindings.as_ref().and_then(|bindings| {
        resolved.selected_type_argument_bindings(bound_receiver, actual_types, &surface, bindings)
    });
    let dispatch_closed = resolved
        .non_overridable_for_argument_types(
            bound_receiver,
            actual_types,
            Some(&surface),
            owner_bindings.as_ref(),
        )
        .is_some();
    Some(JavaNativeExternalMethodResolution {
        model_member_selection: None,
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
    batch: Option<&NativePointBatch>,
) -> Result<Option<Vec<TypeRef>>, JavaNativePointStop> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Ok(None);
    };
    if arguments.has_error() || arguments.is_missing() {
        return Ok(None);
    }
    let mut cursor = arguments.walk();
    Ok(Some(
        arguments
            .named_children(&mut cursor)
            .filter(|argument| !argument.is_extra())
            .map(|argument| {
                java_native_argument_type(java, query, token, argument, batch)
                    .map(|ty| ty.unwrap_or(TypeRef::Unknown))
            })
            .collect::<Result<Vec<_>, _>>()?,
    ))
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
    java_native_argument_type(java, query, scope.token(), expression, None)
        .ok()
        .flatten()
}

fn java_native_argument_type(
    _java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    expression: Node<'_>,
    batch: Option<&NativePointBatch>,
) -> Result<Option<TypeRef>, JavaNativePointStop> {
    java_native_argument_type_with_call_reasons(
        _java,
        query,
        _token,
        expression,
        &mut Vec::new(),
        batch,
    )
}

fn java_native_creation_constructor_refused(
    exact_external_call: bool,
    has_definition: bool,
    has_lexical_definition: bool,
    has_modeled_definition: bool,
) -> bool {
    !exact_external_call && !has_definition && !has_lexical_definition && !has_modeled_definition
}

fn java_native_argument_type_with_call_reasons(
    _java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    mut expression: Node<'_>,
    call_binding_reason_digests: &mut Vec<[u8; 32]>,
    batch: Option<&NativePointBatch>,
) -> Result<Option<TypeRef>, JavaNativePointStop> {
    let mut stopped = None;
    let ty = (|| -> Option<TypeRef> {
        if expression.has_error() || expression.is_missing() {
            return None;
        }
        while expression.kind() == "parenthesized_expression" {
            expression = expression.named_child(0)?;
        }
        if let Some(intrinsic) = crate::analyzer::java::call_conversion::intrinsic_argument_type(
            expression,
            query.source,
        ) {
            return Some(intrinsic);
        }
        if matches!(
            expression.kind(),
            "method_invocation" | "object_creation_expression"
        ) {
            // Each nested query descends to a strict argument/receiver child.
            // Bound the remaining resolver call stack by the existing Java
            // expression budget; deeper expressions retain an unknown type.
            // Count syntax ancestors, not dynamic resolver recursion. This cutoff
            // is identical for a memoized point and a freshly requested point.
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
            match resolve_java_definition_with_evidence_in_batch(call_query, batch, || {}) {
                BoundedResolution::Complete { value, .. } => {
                    if expression.kind() == "object_creation_expression"
                        && java_native_creation_constructor_refused(
                            value.evidence.exact_external_call().is_some(),
                            !value.outcome.definitions.is_empty(),
                            value.outcome.lexical_definition.is_some(),
                            !value.outcome.modeled_definitions.is_empty(),
                        )
                    {
                        // No constructor accepts these actuals, so the creation
                        // is erroneous and its value proves no outer conversion
                        // (#3699, #10021).
                        return None;
                    }
                    if let Some(proof) = value.evidence.exact_external_call() {
                        call_binding_reason_digests
                            .extend_from_slice(&value.call_binding_reason_digests);
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
                            Ok(ty) => ty.and_then(|term| {
                                let term = if let Some(bindings) = &proof.type_argument_bindings {
                                    let bindings = bindings
                                        .iter()
                                        .map(|(name, ty)| (name.to_string(), ty.clone()))
                                        .collect();
                                    term.substitute(&bindings, 64)?
                                } else {
                                    term
                                };
                                Some(
                                    crate::analyzer::jvm::external::normalize_jvm_model_type_ref(
                                        query.analyzer.semantic_model_overlay().as_deref(),
                                        &term,
                                    ),
                                )
                            }),
                            Err(error) => {
                                eprintln!(
                                    "selected external result type read failed for {identity:?}: {error}"
                                );
                                // Preserve the existing unknown result, but
                                // prevent this failed read or an enclosing
                                // point from entering the batch memo.
                                query.analyzer.mark_execution_dependent();
                                None
                            }
                        };
                    }
                }
                BoundedResolution::Exceeded { limit, work } => {
                    stopped = Some(JavaNativePointStop::Exceeded(limit, work));
                    return None;
                }
                BoundedResolution::Unavailable { reason, work } => {
                    stopped = Some(JavaNativePointStop::Unavailable(reason, work));
                    return None;
                }
                BoundedResolution::Cancelled { work } => {
                    stopped = Some(JavaNativePointStop::Cancelled(work));
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
            let resolve = || {
                brokk_bifrost_analysis::analyzer::native_points::resolve_native_call_argument_type_bounded_in_batch(
            &_java.inner,
            argument_query,
            ordinal,
            batch,
            |operation, path, cancellation| {
                prepare_context(_java, query.analyzer, operation, path, cancellation)
            },
            || {},
        )
            };
            let result = match batch {
                Some(batch) => batch.expression(
                    &_java.inner,
                    argument_query,
                    NativePointRole::CallArgument(ordinal),
                    resolve,
                ),
                None => resolve(),
            };
            return match result {
                BoundedResolution::Complete { value, .. } => value.static_type,
                BoundedResolution::Exceeded { limit, work } => {
                    stopped = Some(JavaNativePointStop::Exceeded(limit, work));
                    None
                }
                BoundedResolution::Unavailable { reason, work } => {
                    stopped = Some(JavaNativePointStop::Unavailable(reason, work));
                    None
                }
                BoundedResolution::Cancelled { work } => {
                    stopped = Some(JavaNativePointStop::Cancelled(work));
                    None
                }
            };
        }
        let site = java_native_receiver_type_site_node(expression).unwrap_or(expression);
        match java_native_expression_value_type_at_node_in_batch(query, site, batch) {
            Ok(value) => value?.static_type,
            Err(stop) => {
                stopped = Some(stop);
                None
            }
        }
    })();
    match stopped {
        Some(stop) => Err(stop),
        None => Ok(ty),
    }
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
    let Some(actual_types) = actual_types else {
        return Some((None, owner.fqn().to_owned(), "<init>".to_owned()));
    };
    // Constructor descriptors have the same instance declaration shape as
    // methods. Reuse their strict, loose and variable-arity selection, then
    // publish a receiverless constructor application of the selected formal
    // count and exact inventory identity.
    let resolution = java_native_external_method_resolution(
        java,
        query,
        token,
        owner.fqn(),
        "<init>",
        actual_types,
        JavaNativeReceiverForm::BoundValue,
        None,
    )?;
    match resolution.invocation {
        JavaNativeExternalInvocation::Selected { proof, .. } => {
            let constructor = ExactExternalCallProof::java_external_constructor(
                &resolution.owner,
                &resolution.member,
                proof.parameter_count,
            )
            .with_external_member_identity(proof.external_member_identity().cloned())
            .with_source_jdk_artifact(proof.source_jdk_artifact.clone());
            Some((Some(constructor), resolution.owner, resolution.member))
        }
        JavaNativeExternalInvocation::Witnessed => {
            Some((None, resolution.owner, resolution.member))
        }
        JavaNativeExternalInvocation::Rejected => None,
    }
}

fn publish_java_external_call_boundary(
    query: BoundedReceiverQuery<'_>,
    outcome: &mut DefinitionLookupOutcome,
    proof: &ExactExternalCallProof,
    owner: &str,
    member: &str,
) {
    // Both callers publish only after admission matches the owner/member
    // inventory identity, discharges call-local obligations, and proves every
    // remaining receiver obligation and argument conversion. This certifies
    // the callee binding; result-type completeness is independent.
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
    let Ok(_model_scope) =
        brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::pin_selected_model_snapshot(
            query.analyzer,
        )
    else {
        return BoundedResolution::Complete {
            value: unavailable_type(
                query.site,
                "native_stale",
                "selected model authority changed".into(),
            ),
            work: ReceiverAnalysisWork::default(),
        };
    };
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
    resolve_native_type_bounded(
        &java.inner,
        query,
        |operation, path, cancellation| {
            prepare_context(java, query.analyzer, operation, path, cancellation)
        },
        after_open,
    )
}

fn resolve_java_expression_value_type_in_batch(
    query: BoundedReceiverQuery<'_>,
    batch: Option<&NativePointBatch>,
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
    brokk_bifrost_analysis::analyzer::native_points::resolve_native_expression_value_type_bounded_in_batch(
        &java.inner,
        query,
        batch,
        |operation, path, cancellation| {
            prepare_context(java, query.analyzer, operation, path, cancellation)
        },
        after_open,
    )
}

/// Translate a carrier only after the shared public-frontier agreement proof.
/// Java's producer erases a type variable to its bound. A complete, single-valued
/// bound is a static type proof; the immutable whitelist still decides admission.
/// Intersection bounds and other multi-valued/incomplete frontiers decline.
/// Go differs because its producer leaves type-parameter frontiers incomplete by
/// design. Kotlin and Scala do not call this observed-type bridge: their language
/// hooks retain UnsupportedLanguage, so their type-variable behavior is unchanged.
fn java_observed_value_type(
    answer: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedNativeReferenceTypes,
) -> brokk_bifrost_analysis::analyzer::semantic::ObservedValueType {
    use brokk_bifrost_analysis::analyzer::native_points::selected_value_type_for_barrier;
    use brokk_bifrost_analysis::analyzer::resolution::FactProjectedTypeNodeForm;
    use brokk_bifrost_analysis::analyzer::semantic::{
        ObservedValueType, ValueShape, ValueTypeBarrierReason,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
        SelectedNativeDefinition, SelectedNativeTypes,
    };
    let selected = match selected_value_type_for_barrier(&answer.answer, answer.query_result_slot) {
        Ok(Some(selected)) => selected,
        Ok(None) => return ObservedValueType::Undecided(ValueTypeBarrierReason::IncompleteType),
        Err(reason) => return ObservedValueType::Undecided(reason),
    };
    let SelectedNativeTypes::Ready {
        nominal,
        intrinsic,
        external_owners,
    } = &answer.value_types
    else {
        return ObservedValueType::Undecided(ValueTypeBarrierReason::IncompleteType);
    };
    for shape in answer.answer.projected_type_shapes() {
        if let Some(root) = shape
            .nodes()
            .iter()
            .find(|node| node.slot() == shape.root_slot() && node.identity() == selected.identity())
        {
            match root.form() {
                FactProjectedTypeNodeForm::Array(_) => {
                    return ObservedValueType::NonNamed(ValueShape::Array);
                }
                FactProjectedTypeNodeForm::Unsupported => {
                    return ObservedValueType::Undecided(ValueTypeBarrierReason::UnknownType);
                }
                _ => {}
            }
        }
    }
    // An external owner that a selected provider declares is a nominal proof.
    // Decide it before the intrinsic descriptors: the store also gives every
    // selected external owner a synthesized LanguageBuiltin descriptor (#7853),
    // which the rule below would reject. An implicit-package name that no
    // provider declares proves nothing and falls through to that rule.
    if let Some((_, owner)) = external_owners
        .iter()
        .find(|(identity, owner)| *identity == selected.identity() && owner.is_provider_declared())
    {
        return ObservedValueType::Named {
            canonical: owner.owner_fqn.to_string(),
        };
    }
    if let Some(descriptor) = intrinsic
        .iter()
        .find(|item| item.identity() == selected.identity())
    {
        use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
        return match descriptor.kind() {
            IntrinsicTypeKind::Array => ObservedValueType::NonNamed(ValueShape::Array),
            IntrinsicTypeKind::Primitive if descriptor.spelling() != "null" => {
                ObservedValueType::Named {
                    canonical: descriptor.spelling().to_owned(),
                }
            }
            // String is Java's resolved literal intrinsic. Any other LanguageBuiltin
            // without a provider-declared owner does not prove resolution.
            IntrinsicTypeKind::LanguageBuiltin if descriptor.spelling() == "java.lang.String" => {
                ObservedValueType::Named {
                    canonical: descriptor.spelling().to_owned(),
                }
            }
            _ => ObservedValueType::Undecided(ValueTypeBarrierReason::IncompleteType),
        };
    }
    if let Some((_, definition)) = nominal
        .iter()
        .find(|(identity, _)| *identity == selected.identity())
    {
        return match definition {
            SelectedNativeDefinition::Lexical(_) => {
                ObservedValueType::Undecided(ValueTypeBarrierReason::UnknownType)
            }
            SelectedNativeDefinition::Unit(unit) => ObservedValueType::Named {
                canonical: unit.fq_name().to_string(),
            },
            SelectedNativeDefinition::Intrinsic { canonical_name, .. } => {
                ObservedValueType::Named {
                    canonical: canonical_name.clone(),
                }
            }
            SelectedNativeDefinition::ExternalOwner { owner, .. } => ObservedValueType::Named {
                canonical: owner.owner_fqn.to_string(),
            },
        };
    }
    // An identity without a selected nominal declaration is not a named proof.
    ObservedValueType::Undecided(ValueTypeBarrierReason::UnknownType)
}

pub(super) fn observed_value_type(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    observation: &brokk_bifrost_analysis::analyzer::semantic::BarrierObservation,
    request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
) -> Result<
    brokk_bifrost_analysis::analyzer::semantic::ObservedValueType,
    brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
> {
    use ValueTypeBarrierReason::{
        BudgetExceeded, Cancelled, IncompleteType, UnavailableObservation, UnsupportedLanguage,
    };
    use brokk_bifrost_analysis::analyzer::semantic::{
        ObservedValueType, SemanticWork, ValueTypeBarrierReason, frozen_call_operand_node,
        prepare_value_type_barrier_source, value_type_barrier_source_matches,
    };
    if std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_none() {
        return Ok(ObservedValueType::Undecided(UnsupportedLanguage));
    }
    if request.cancellation.is_cancelled() {
        return Ok(ObservedValueType::Undecided(Cancelled));
    }
    if !request.charge_execution_traversal(1) {
        return Ok(ObservedValueType::Undecided(BudgetExceeded));
    }
    let java =
        resolve_analyzer::<JavaAnalyzer>(analyzer).expect("Java support belongs to Java analyzer");
    let semantics = observation.point().procedure().semantics();
    let value = semantics
        .value(observation.value())
        .expect("validated value");
    let mapping = semantics
        .source_mapping(value.source)
        .expect("validated mapping");
    if mapping.kind != brokk_bifrost_analysis::analyzer::semantic::SourceMappingKind::Exact {
        return Ok(ObservedValueType::Undecided(UnavailableObservation));
    }
    let file = brokk_bifrost_core::analyzer::model::ProjectFile::new(
        java.inner.project().root(),
        mapping.locator.path().as_path(),
    );
    if observation.point().procedure().artifact().key().mount()
        != brokk_bifrost_analysis::analyzer::semantic::WorkspaceMountId::from_root(file.root())
    {
        return Ok(ObservedValueType::Undecided(UnavailableObservation));
    }
    let prepared = match prepare_value_type_barrier_source(
        &java.inner,
        &mut Default::default(),
        &file,
        request,
    ) {
        Ok(prepared) => prepared,
        Err(reason) => return Ok(ObservedValueType::Undecided(reason)),
    };
    if !value_type_barrier_source_matches(observation, &prepared) {
        return Ok(ObservedValueType::Undecided(UnavailableObservation));
    }
    let Some(mut node) =
        frozen_call_operand_node(observation, &prepared, "method_invocation", |call| {
            call.child_by_field_name("object")
        })
    else {
        return Ok(ObservedValueType::Undecided(UnavailableObservation));
    };
    while node.kind() == "parenthesized_expression" {
        let Some(child) = node.named_child(0) else {
            return Ok(ObservedValueType::Undecided(IncompleteType));
        };
        node = child;
    }
    // #7612: reference casts have no native target-type publication on this base.
    // Decline rather than accidentally using the operand's type.
    if matches!(node.kind(), "cast_expression" | "null_literal") {
        return Ok(ObservedValueType::Undecided(IncompleteType));
    }
    let Some(site_node) = java_native_receiver_type_site_node(node) else {
        return Ok(ObservedValueType::Undecided(IncompleteType));
    };
    let site = ResolvedReferenceSite {
        path: brokk_bifrost_core::path_utils::rel_path_string(&file),
        text: prepared.source()[site_node.byte_range()].to_owned(),
        range: brokk_bifrost_core::analyzer::model::Range {
            start_byte: site_node.start_byte(),
            end_byte: site_node.end_byte(),
            start_line: site_node.start_position().row + 1,
            end_line: site_node.end_position().row + 1,
        },
        focus_start_byte: site_node.start_byte(),
        focus_end_byte: site_node.end_byte(),
    };
    let result =
        brokk_bifrost_analysis::analyzer::native_points::resolve_native_observed_value_type_bounded(
            &java.inner,
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source: prepared.source(),
                tree: Some(prepared.tree()),
                site: &site,
                budget: Default::default(),
                cancellation: Some(request.cancellation),
            },
            |operation, path, cancellation| {
                prepare_context(java, analyzer, operation, path, cancellation)
            },
            java_observed_value_type,
        );
    let work = match &result {
        BoundedResolution::Complete { work, .. }
        | BoundedResolution::Cancelled { work }
        | BoundedResolution::Exceeded { work, .. } => work,
        BoundedResolution::Unavailable { work, .. } => work,
    };
    request.budget.charge_work(SemanticWork {
        events: work.scope_nodes.saturating_add(work.hierarchy_order_steps),
        ..Default::default()
    });
    if !request
        .charge_execution_traversal(work.scope_nodes.saturating_add(work.hierarchy_order_steps))
    {
        return Ok(ObservedValueType::Undecided(BudgetExceeded));
    }
    Ok(match result {
        BoundedResolution::Complete { value, .. } => value,
        BoundedResolution::Cancelled { .. } => ObservedValueType::Undecided(Cancelled),
        BoundedResolution::Exceeded { .. } => ObservedValueType::Undecided(BudgetExceeded),
        BoundedResolution::Unavailable { .. } => {
            ObservedValueType::Undecided(UnavailableObservation)
        }
    })
}

/// Base Java import contexts that this request's point operations built.
/// Every point opens its own selected operation, so without reuse a policy run
/// rebuilt one file's base context once per point (#8127). The memo is
/// request-scoped (it dies with the analyzer's query read cache) and bounded by
/// retained bytes, so it never grows with the workspace.
struct JavaImportContextSnapshots {
    #[cfg(test)]
    restores: std::sync::atomic::AtomicUsize,
    entries: moka::sync::Cache<
        brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContextSnapshotKey,
        std::sync::Arc<PublishedJavaImportContext>,
    >,
}

/// A published snapshot with the read receipt of the cold build that made it.
struct PublishedJavaImportContext {
    snapshot:
        brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContextSnapshot,
    receipt: brokk_bifrost_analysis::analyzer::common::QueryCacheBuildReceipt,
}

impl PublishedJavaImportContext {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
            + self.snapshot.retained_bytes()
            + std::mem::size_of_val(&self.receipt)
    }
}

/// Retained bytes per request. One base context retains roughly tens to a few
/// hundred KiB, and a policy run demands about one per Java file it reads.
const JAVA_IMPORT_CONTEXT_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

impl Default for JavaImportContextSnapshots {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            restores: std::sync::atomic::AtomicUsize::new(0),
            entries: moka::sync::Cache::builder()
                .max_capacity(JAVA_IMPORT_CONTEXT_SNAPSHOT_BYTES)
                .weigher(
                    |key: &brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContextSnapshotKey,
                     published: &std::sync::Arc<PublishedJavaImportContext>| {
                    u32::try_from(key.retained_bytes() + published.retained_bytes())
                        .unwrap_or(u32::MAX)
                })
                .build(),
        }
    }
}

/// One file's base Java import context. When another point operation of this
/// request already built it, restore that build and replay its read receipt,
/// so the caller's ledger records the same reads as a cold build; otherwise
/// build it cold and publish it. Every refusal falls back to the cold build.
fn java_import_context(
    java: &JavaAnalyzer,
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    path: &str,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> brokk_bifrost_analysis::analyzer::store::Result<JavaImportContext> {
    let Some(snapshots) = java
        .inner
        .active_query_request_memo::<JavaImportContextSnapshots>()
    else {
        return operation.java_import_context(path, cancellation);
    };
    let key = operation.jvm_import_context_snapshot_key(Language::Java, path);
    if let Some(published) = snapshots.entries.get(&key) {
        match operation.restore_jvm_import_context_snapshot(&published.snapshot)? {
            Ok(context) => {
                #[cfg(test)]
                snapshots
                    .restores
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                published.receipt.replay();
                operation.profile_jvm_import_context_snapshot("restored");
                return Ok(context);
            }
            Err(refusal) => operation.profile_jvm_import_context_snapshot(("restore", refusal)),
        }
    }
    let (built, receipt) =
        brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(analyzer, || {
            operation.jvm_import_context_with_snapshot(Language::Java, path, cancellation)
        });
    let (context, snapshot) = built?;
    match snapshot {
        // A build that depended on budget, cancellation or a provider failure
        // is never retained (#8184).
        Ok(_) if receipt.has_execution_dependences() => {
            operation.profile_jvm_import_context_snapshot(("publish", "execution_dependent"));
        }
        Ok(snapshot) => {
            snapshots.entries.insert(
                key,
                std::sync::Arc::new(PublishedJavaImportContext { snapshot, receipt }),
            );
            operation.profile_jvm_import_context_snapshot("published");
        }
        Err(refusal) => operation.profile_jvm_import_context_snapshot(("publish", refusal)),
    }
    Ok(context)
}

fn prepare_context(
    java: &JavaAnalyzer,
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    path: &str,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> brokk_bifrost_analysis::analyzer::store::Result<NativePointContext> {
    Ok(
        match java_import_context(java, analyzer, operation, path, cancellation)? {
            JavaImportContext::Ready { context, .. } => NativePointContext::Ready {
                context,
                selected_import_model: None,
            },
            JavaImportContext::Unavailable => NativePointContext::Unavailable,
            JavaImportContext::Cancelled => NativePointContext::Cancelled,
        },
    )
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
        resolve_java_definition_with_evidence_bounded(query, || {})
            .map(|value| (value.outcome, value.evidence))
    }
}

/// The actual selector result at a source call site, for regression goldens.
pub use crate::analyzer::jvm::external::JavaExternalInvocationFailure;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct JavaExternalInvocationObservation {
    pub start_byte: usize,
    pub owner: String,
    pub member: String,
    pub failure: Option<JavaExternalInvocationFailure>,
}

static EXTERNAL_INVOCATION_OBSERVATIONS: std::sync::Mutex<
    Option<std::collections::BTreeSet<JavaExternalInvocationObservation>>,
> = std::sync::Mutex::new(None);

/// Capture only during the supplied test query; no observations survive it.
pub fn with_external_invocation_observations<T>(
    run: impl FnOnce() -> T,
) -> (T, Vec<JavaExternalInvocationObservation>) {
    struct Capture;
    impl Drop for Capture {
        fn drop(&mut self) {
            EXTERNAL_INVOCATION_OBSERVATIONS.lock().unwrap().take();
        }
    }
    assert!(
        EXTERNAL_INVOCATION_OBSERVATIONS
            .lock()
            .unwrap()
            .replace(Default::default())
            .is_none(),
        "invocation captures cannot overlap"
    );
    let guard = Capture;
    let value = run();
    let rows = EXTERNAL_INVOCATION_OBSERVATIONS
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .into_iter()
        .collect();
    drop(guard);
    (value, rows)
}

fn record_external_invocation(
    start_byte: usize,
    owner: &str,
    member: &str,
    failure: Option<JavaExternalInvocationFailure>,
) {
    if let Some(rows) = EXTERNAL_INVOCATION_OBSERVATIONS.lock().unwrap().as_mut() {
        assert!(rows.len() < 4096, "bounded test observation capture");
        rows.insert(JavaExternalInvocationObservation {
            start_byte,
            owner: owner.to_owned(),
            member: member.to_owned(),
            failure,
        });
    }
}
