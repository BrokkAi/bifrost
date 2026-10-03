//! Java selected-context entry point, exercised before atomic JVM cutover.

use super::JavaAnalyzer;
use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::native_points::{
    NativePointContext, resolve_native_definition_bounded, resolve_native_type_bounded,
    unavailable_definition, unavailable_type,
};
use crate::analyzer::resolve_analyzer;
use crate::analyzer::store::resolution_operation::{
    JavaExternalStaticImportBoundary, JavaImportContext,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, ClaimSubjectRole, DefinitionLookupDiagnostic, DefinitionLookupOutcome,
    DefinitionLookupStatus, UnindexedClaim,
};
use crate::analyzer::usages::get_type::TypeLookupOutcome;
use crate::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, BoundedDefinitionLookup, Language, QueryScope,
};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;

pub(crate) fn resolve_java_definition_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(query.analyzer) else {
        return BoundedResolution::Complete {
            value: unavailable_definition(
                query.site,
                "native_analyzer_unavailable",
                "Java analyzer is unavailable".into(),
            ),
            work: ReceiverAnalysisWork::default(),
        };
    };
    let site_text = query.site.text.clone();
    let mut external_static_imports = Vec::new();
    let resolution = resolve_native_definition_bounded(
        &java.inner,
        query,
        |operation, path, cancellation| {
            Ok(match operation.java_import_context(path, cancellation)? {
                JavaImportContext::Ready {
                    context,
                    external_static_imports: boundaries,
                    ..
                } => {
                    external_static_imports = boundaries;
                    NativePointContext::Ready(*context)
                }
                JavaImportContext::Unavailable => NativePointContext::Unavailable,
                JavaImportContext::Cancelled => NativePointContext::Cancelled,
            })
        },
        after_open,
    );
    let resolution = apply_static_import_boundary(&site_text, external_static_imports, resolution);
    apply_explicit_type_import_boundary(java, query, resolution)
}

fn apply_explicit_type_import_boundary(
    java: &JavaAnalyzer,
    query: BoundedReceiverQuery<'_>,
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
        if let Some(target) = external_target {
            crate::analyzer::usages::get_definition::record_java_external_route_with_target(
                subject.clone(),
                target,
            );
        } else {
            crate::analyzer::usages::get_definition::record_java_external_route(subject.clone());
        }
        value.status = DefinitionLookupStatus::UnresolvableImportBoundary;
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
                crate::analyzer::usages::get_definition::record_java_external_route(member_fqn);
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

    if let Some(target) = external_target {
        crate::analyzer::usages::get_definition::record_java_external_route_with_target(
            subject.clone(),
            target,
        );
    } else {
        crate::analyzer::usages::get_definition::record_java_external_route(subject.clone());
    }
    value.status = DefinitionLookupStatus::UnresolvableImportBoundary;
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
    boundaries: Vec<JavaExternalStaticImportBoundary>,
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
        JavaImportContext::Ready { context, .. } => NativePointContext::Ready(*context),
        JavaImportContext::Unavailable => NativePointContext::Unavailable,
        JavaImportContext::Cancelled => NativePointContext::Cancelled,
    })
}

#[cfg(test)]
#[path = "native_points/tests.rs"]
mod tests;

/// The rollout probe's view of the native Java point resolver.
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
}
