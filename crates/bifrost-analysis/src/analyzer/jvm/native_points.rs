//! One selected-source point resolver for the shared Java/Kotlin/Scala realm.

use crate::CancellationToken;
use crate::analyzer::jvm::external::qualified_model_symbols;
use crate::analyzer::jvm::import_routes::{ExplicitImportModelRoute, explicit_import_model_route};
use crate::analyzer::languages::{BoundedReceiverQuery, StructuralReceiverResolver};
use crate::analyzer::native_points::{
    NativePointContext, SelectedNativeImportModel, resolve_native_definition_bounded,
    resolve_native_type_bounded, unavailable_definition, unavailable_type,
};
use crate::analyzer::resolution::language_implicit_root_providers;
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_operation::{JvmImportContext, SelectedResolutionOperation};
use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, ClaimSubjectRole, DefinitionLookupDiagnostic, DefinitionLookupOutcome,
    DefinitionLookupStatus, ResolvedReferenceSite, UnindexedClaim, boundary_unchecked,
    candidates_outcome, kotlin_import_model_outcome, no_definition,
};
use crate::analyzer::usages::get_type::TypeLookupOutcome;
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
use crate::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, BoundedDefinitionLookup, Language,
};
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::named_children;
use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;
use brokk_bifrost_jvm::kotlin::imports::kotlin_import_info_from_node;
use brokk_bifrost_jvm::kotlin::syntax::{self, kotlin_is_declaration_name};
use brokk_bifrost_jvm::scala::graph::syntax as scala_syntax;

pub(crate) static JVM_NATIVE_ROLLOUT_POINTS: JvmNativeRolloutPoints = JvmNativeRolloutPoints;

pub(crate) struct JvmNativeRolloutPoints;

impl StructuralReceiverResolver for JvmNativeRolloutPoints {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        match query_language(&query) {
            Language::Java => {
                crate::analyzer::java::native_points::resolve_java_type_bounded(query, || {})
            }
            Language::Kotlin => {
                let Some(kotlin) = crate::analyzer::resolve_analyzer::<
                    crate::analyzer::kotlin::KotlinAnalyzer,
                >(query.analyzer) else {
                    return unavailable_jvm_type(query.site, Language::Kotlin);
                };
                resolve_jvm_type_bounded(
                    kotlin.tree_sitter_analyzer(),
                    Language::Kotlin,
                    query,
                    || {},
                )
            }
            Language::Scala => {
                let Some(scala) = crate::analyzer::resolve_analyzer::<
                    crate::analyzer::scala::ScalaAnalyzer,
                >(query.analyzer) else {
                    return unavailable_jvm_type(query.site, Language::Scala);
                };
                resolve_jvm_type_bounded(
                    scala.tree_sitter_analyzer(),
                    Language::Scala,
                    query,
                    || {},
                )
            }
            language => unreachable!("JVM native point query has a non-JVM language: {language:?}"),
        }
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        match query_language(&query) {
            Language::Java => {
                crate::analyzer::java::native_points::resolve_java_definition_bounded(query, || {})
            }
            Language::Kotlin => {
                let Some(kotlin) = crate::analyzer::resolve_analyzer::<
                    crate::analyzer::kotlin::KotlinAnalyzer,
                >(query.analyzer) else {
                    return unavailable_jvm_definition(query.site, Language::Kotlin);
                };
                let resolution = resolve_jvm_definition_bounded(
                    kotlin.tree_sitter_analyzer(),
                    Language::Kotlin,
                    query,
                    || {},
                );
                let resolution = project_kotlin_star_import_ambiguity(query, resolution);
                project_kotlin_external_boundary(kotlin, query, resolution)
            }
            Language::Scala => {
                let Some(scala) = crate::analyzer::resolve_analyzer::<
                    crate::analyzer::scala::ScalaAnalyzer,
                >(query.analyzer) else {
                    return unavailable_jvm_definition(query.site, Language::Scala);
                };
                let resolution = resolve_jvm_definition_bounded(
                    scala.tree_sitter_analyzer(),
                    Language::Scala,
                    query,
                    || {},
                );
                project_scala_external_boundary(scala, query, resolution)
            }
            language => unreachable!("JVM native point query has a non-JVM language: {language:?}"),
        }
    }
}

fn query_language(query: &BoundedReceiverQuery<'_>) -> Language {
    let language = crate::analyzer::common::language_for_file(query.file);
    assert!(
        matches!(
            language,
            Language::Java | Language::Kotlin | Language::Scala
        ),
        "JVM native point query has a non-JVM file language: {language:?}"
    );
    language
}

fn resolve_jvm_definition_bounded<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    language: Language,
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    assert_eq!(inner.adapter().language(), language);
    if language == Language::Kotlin
        && let Some(tree) = query.tree
        && let Some(node) = smallest_named_node_covering(
            tree.root_node(),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        )
        && kotlin_is_declaration_name(node)
    {
        let mut value = no_definition(
            "declaration_site",
            format!(
                "`{}` is a Kotlin declaration name, not a reference",
                query.site.text
            ),
        );
        value.reference = Some(query.site.clone());
        return BoundedResolution::Complete {
            value,
            work: Default::default(),
        };
    }
    let lookup = query.site.text.clone();
    let namespace = query
        .tree
        .and_then(|tree| {
            brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering(
                tree.root_node(),
                query.site.focus_start_byte,
                query.site.focus_end_byte,
            )
        })
        .and_then(|node| match node.kind() {
            "type_identifier" | "scoped_type_identifier" | "stable_type_identifier" => {
                Some(ResolutionNamespace::Type)
            }
            _ => None,
        });
    resolve_native_definition_bounded(
        inner,
        query,
        None,
        |operation, path, cancellation| {
            prepare_definition_context(
                operation,
                language,
                path,
                cancellation,
                query,
                &lookup,
                namespace,
            )
        },
        after_open,
    )
}

/// Keep Kotlin's established diagnostic when exact native candidates came
/// from competing star-import owners. Candidate selection remains owned by
/// native resolution; this hook only gives that proven ambiguity its
/// language-specific surface.
fn project_kotlin_star_import_ambiguity(
    query: BoundedReceiverQuery<'_>,
    resolution: BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let BoundedResolution::Complete { value, work } = resolution else {
        return resolution;
    };
    if value.status != DefinitionLookupStatus::Ambiguous
        || value.definitions.len() < 2
        || value
            .definitions
            .iter()
            .any(|definition| !definition.is_class())
    {
        return BoundedResolution::Complete { value, work };
    }
    let Some(tree) = query.tree else {
        return BoundedResolution::Complete { value, work };
    };
    let Some(mut focus) = smallest_named_node_covering(
        tree.root_node(),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    ) else {
        return BoundedResolution::Complete { value, work };
    };
    while focus.kind() != "user_type" {
        let Some(parent) = focus.parent() else {
            return BoundedResolution::Complete { value, work };
        };
        focus = parent;
    }
    if focus.start_byte() > query.site.focus_start_byte
        || focus.end_byte() < query.site.focus_end_byte
    {
        return BoundedResolution::Complete { value, work };
    }
    let Some(components) = syntax::kotlin_type_name_components(focus, query.source) else {
        return BoundedResolution::Complete { value, work };
    };
    if components.len() != 1 {
        return BoundedResolution::Complete { value, work };
    }
    let spelled = &components[0];
    let simple_name = spelled.as_str();
    let owners = value
        .definitions
        .iter()
        .filter_map(|definition| {
            if definition.terminal_name() != simple_name {
                return None;
            }
            let mut segments = definition.fq_segment_texts();
            segments.pop()?;
            Some(segments)
        })
        .collect::<Vec<_>>();
    if owners.len() != value.definitions.len() {
        return BoundedResolution::Complete { value, work };
    }

    let mut stack = vec![tree.root_node()];
    let mut star_import_owners: Vec<Vec<String>> = Vec::new();
    while let Some(node) = stack.pop() {
        if node.kind() == "import_header"
            && let Some(import) = kotlin_import_info_from_node(node, query.source)
            && import.is_wildcard
            && let Some(path) = import.path
        {
            star_import_owners.push(path.segments);
        }
        stack.extend(named_children(node));
    }
    let distinct_owners = owners.iter().enumerate().any(|(index, left)| {
        owners.iter().skip(index + 1).any(|right| {
            left != right
                && star_import_owners.iter().any(|owner| owner == left)
                && star_import_owners.iter().any(|owner| owner == right)
        })
    });
    if !distinct_owners {
        return BoundedResolution::Complete { value, work };
    }

    let mut value = no_definition(
        "ambiguous_kotlin_type",
        format!("`{spelled}` is bound to different owners by more than one Kotlin star import"),
    );
    value.reference = Some(query.site.clone());
    BoundedResolution::Complete { value, work }
}

/// Project a proven JVM external route through the shared boundary result.
///
/// The language adapter supplies the route and its evidence; this shared step
/// protects workspace winners, publishes the same trace row for every JVM
/// language, and preserves a canonical reference when the adapter resolved one.
pub(crate) fn project_jvm_external_boundary(
    outcome: &mut DefinitionLookupOutcome,
    site: &ResolvedReferenceSite,
    route_name: &str,
    external_target: Option<&str>,
    reference_text: Option<&str>,
) -> bool {
    if !outcome.definitions.is_empty() || outcome.lexical_definition.is_some() {
        return false;
    }
    let eligible_status = matches!(
        outcome.status,
        DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::Incomplete
            | DefinitionLookupStatus::UnresolvableImportBoundary
    ) || (outcome.status == DefinitionLookupStatus::Resolved
        && external_target.is_some());
    if !eligible_status {
        return false;
    }

    outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    if let Some(reference_text) = reference_text {
        let reference = outcome.reference.get_or_insert_with(|| site.clone());
        reference.text = reference_text.to_owned();
    }
    if let Some(target) = external_target {
        crate::analyzer::usages::get_definition::record_native_external_route_with_target(
            route_name.to_owned(),
            target.to_owned(),
        );
    } else {
        crate::analyzer::usages::get_definition::record_native_external_route(
            route_name.to_owned(),
        );
    }
    true
}

fn project_kotlin_external_boundary(
    kotlin: &crate::analyzer::kotlin::KotlinAnalyzer,
    query: BoundedReceiverQuery<'_>,
    resolution: BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let BoundedResolution::Complete { mut value, work } = resolution else {
        return resolution;
    };
    if !matches!(
        value.status,
        DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::Incomplete
            | DefinitionLookupStatus::Resolved
    ) || !value.definitions.is_empty()
        || !value.modeled_definitions.is_empty()
        || value.lexical_definition.is_some()
    {
        return BoundedResolution::Complete { value, work };
    }
    let Some(tree) = query.tree else {
        return BoundedResolution::Complete { value, work };
    };
    let Some(focus) = smallest_named_node_covering(
        tree.root_node(),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    ) else {
        return BoundedResolution::Complete { value, work };
    };
    if kotlin_is_declaration_name(focus) {
        return BoundedResolution::Complete { value, work };
    }

    if let Some(header) = syntax::kotlin_enclosing_import_header(focus) {
        let Some((segments, targets_declaration)) =
            kotlin_import_target_segments_through_focus(header, focus, query.source)
        else {
            return BoundedResolution::Complete { value, work };
        };
        let candidate = segments.join(".");
        let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Kotlin);
        let workspace_targets = definitions
            .fqn_in_any_language(&candidate)
            .into_iter()
            .filter(|unit| !unit.is_synthetic())
            .collect::<Vec<_>>();
        if !workspace_targets.is_empty() {
            return BoundedResolution::Complete {
                value: candidates_outcome(workspace_targets),
                work,
            };
        }
        if let Some(projected) = kotlin_import_model_outcome(query.analyzer, query.site, &candidate)
        {
            return BoundedResolution::Complete {
                value: projected,
                work,
            };
        }
        if definitions.package_exists_in_any_language(&candidate) {
            return BoundedResolution::Complete { value, work };
        }

        // A workspace package can also receive declarations from a selected
        // dependency, so its presence does not prove this imported member is
        // absent when no active declaration provider supplied the target.
        if targets_declaration {
            value = kotlin_import_target_incomplete(
                value,
                query.site,
                &candidate,
                "no active Kotlin declaration provider proved this import target",
            );
        }
        return BoundedResolution::Complete { value, work };
    }

    let scope = AnalyzerQueryScope::new(query.analyzer);
    let token = scope.token();
    let projected = if focus.kind() == "type_identifier" {
        kotlin_external_type_route(kotlin, query, token, focus).map(
            |(route_name, external_target, boundary_status)| {
                (
                    route_name,
                    external_target,
                    ClaimSubjectRole::Type,
                    Some(boundary_status),
                )
            },
        )
    } else if let Some(member) = kotlin_external_member_evidence(kotlin, query, token, focus) {
        let Some(target) = member.member_target else {
            if value.status == DefinitionLookupStatus::Incomplete
                && member.owner_status != BoundaryStatus::ExternalDeclaredUnindexed
            {
                value.status = DefinitionLookupStatus::NoDefinition;
            }
            return BoundedResolution::Complete { value, work };
        };
        Some((target.clone(), Some(target), ClaimSubjectRole::Member, None))
    } else {
        None
    };
    let Some((route_name, external_target, role, boundary_status)) = projected else {
        if focus.kind() == "type_identifier"
            && value.status == DefinitionLookupStatus::NoDefinition
            && value.definitions.is_empty()
            && value.modeled_definitions.is_empty()
            && value.lexical_definition.is_none()
            && value.diagnostics.is_empty()
            && let Some(segments) = kotlin_type_segments_through_focus(focus, query.source)
            && segments.len() == 1
        {
            let spelling = segments.join(".");
            let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Kotlin);
            if definitions.fqn_in_any_language(&spelling).is_empty()
                && !definitions.package_exists_in_any_language(&spelling)
            {
                let mut missing = no_definition(
                    "no_indexed_definition",
                    format!("`{spelling}` is not indexed as a Kotlin type"),
                );
                let mut reference = query.site.clone();
                reference.text = spelling;
                missing.reference = Some(reference);
                return BoundedResolution::Complete {
                    value: missing,
                    work,
                };
            }
        }
        return BoundedResolution::Complete { value, work };
    };
    if role == ClaimSubjectRole::Type
        && boundary_status == Some(BoundaryStatus::ExternalDeclaredUnindexed)
        && external_target.is_none()
    {
        let Some(spelling) = kotlin_type_segments_through_focus(focus, query.source)
            .map(|segments| segments.join("."))
        else {
            return BoundedResolution::Complete { value, work };
        };
        // Gated upstream: `kotlin_external_type_route` proves that the
        // selected import owner lies outside the workspace package index.
        if project_jvm_external_boundary(&mut value, query.site, &spelling, None, Some(&spelling)) {
            let boundary = boundary_unchecked(
                format!(
                    "`{spelling}` appears to cross a Kotlin import boundary not indexed in this workspace"
                ),
                UnindexedClaim::external_boundary(spelling, ClaimSubjectRole::Type),
            );
            value.diagnostics = boundary.diagnostics;
        }
        return BoundedResolution::Complete { value, work };
    }
    let reference_text = external_target.as_deref().unwrap_or(&route_name);
    if !project_jvm_external_boundary(
        &mut value,
        query.site,
        &route_name,
        external_target.as_deref(),
        Some(reference_text),
    ) {
        return BoundedResolution::Complete { value, work };
    }
    let message = match role {
        ClaimSubjectRole::Type => {
            format!("`{route_name}` names a Kotlin type outside the indexed workspace")
        }
        ClaimSubjectRole::Member => {
            format!("`{route_name}` names a JVM member outside the indexed workspace")
        }
        _ => unreachable!("Kotlin external projection emits only type and member claims"),
    };
    value.diagnostics.insert(
        0,
        DefinitionLookupDiagnostic {
            kind: "kotlin_native_external_boundary".into(),
            message,
            claim: Some(UnindexedClaim::external_boundary(route_name, role)),
        },
    );
    BoundedResolution::Complete { value, work }
}

fn project_scala_external_boundary(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    resolution: BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let BoundedResolution::Complete { mut value, work } = resolution else {
        return resolution;
    };
    if !matches!(
        value.status,
        DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::Incomplete
            | DefinitionLookupStatus::Resolved
    ) || !value.definitions.is_empty()
        || !value.modeled_definitions.is_empty()
        || value.lexical_definition.is_some()
    {
        return BoundedResolution::Complete { value, work };
    }
    let Some(tree) = query.tree else {
        return BoundedResolution::Complete { value, work };
    };
    let Some(focus) = smallest_named_node_covering(
        tree.root_node(),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    ) else {
        return BoundedResolution::Complete { value, work };
    };
    if scala_is_declaration_name(focus) || scala_reference_is_import_export_or_package_syntax(focus)
    {
        return BoundedResolution::Complete { value, work };
    }

    let scope = AnalyzerQueryScope::new(query.analyzer);
    let token = scope.token();
    if matches!(focus.kind(), "type_identifier" | "stable_type_identifier") {
        let segments = scala_type_lookup_segments_through_focus(focus, query.source);
        if !segments.is_empty() {
            let written = segments.join(".");
            let (status, external_target) =
                crate::analyzer::usages::get_definition::boundary_evidence(
                    query.analyzer,
                    query.file,
                    &written,
                );
            let bare_implicit_root = segments.len() == 1
                && !language_implicit_root_providers(Language::Scala).is_empty();
            let exact_external_target =
                status == BoundaryStatus::ExternalIndexed && external_target.is_some();
            if (exact_external_target || bare_implicit_root)
                && !(status == BoundaryStatus::ExternalIndexed && external_target.is_none())
                && !external_target.as_ref().is_some_and(|target| {
                    !AnalyzerDefinitionLookup::new(query.analyzer, Language::Scala)
                        .fqn_in_any_language(target)
                        .is_empty()
                })
            {
                let route_name = external_target.clone().unwrap_or(written);
                return finish_scala_external_boundary(
                    value,
                    work,
                    query.site,
                    route_name,
                    external_target,
                    ClaimSubjectRole::Type,
                );
            }
        }
    } else if let Some(member) = scala_external_member_evidence(scala, query, token, focus) {
        if let Some(target) = member.member_target {
            return finish_scala_external_boundary(
                value,
                work,
                query.site,
                target.clone(),
                Some(target),
                ClaimSubjectRole::Member,
            );
        }
        if value.status == DefinitionLookupStatus::Incomplete
            && member.owner_status != BoundaryStatus::ExternalDeclaredUnindexed
            && member.explicit_import_route
        {
            value.status = DefinitionLookupStatus::NoDefinition;
        }
    } else if scala_identifier_is_implicit_root_reference(focus) {
        let Some(name) = query
            .source
            .get(focus.start_byte()..focus.end_byte())
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            return BoundedResolution::Complete { value, work };
        };
        if !language_implicit_root_providers(Language::Scala).is_empty() {
            let (status, external_target) =
                crate::analyzer::usages::get_definition::boundary_evidence(
                    query.analyzer,
                    query.file,
                    name,
                );
            if status != BoundaryStatus::ExternalIndexed || external_target.is_some() {
                return finish_scala_external_boundary(
                    value,
                    work,
                    query.site,
                    name.to_owned(),
                    external_target,
                    ClaimSubjectRole::Any,
                );
            }
        }
    }
    BoundedResolution::Complete { value, work }
}

fn scala_identifier_is_implicit_root_reference(focus: tree_sitter::Node<'_>) -> bool {
    if focus.kind() != "identifier" || scala_syntax::named_argument_label_owner(focus).is_some() {
        return false;
    }
    true
}

fn scala_reference_is_import_export_or_package_syntax(mut focus: tree_sitter::Node<'_>) -> bool {
    while let Some(parent) = focus.parent() {
        if matches!(
            parent.kind(),
            "import_declaration" | "export_declaration" | "package_clause"
        ) {
            return true;
        }
        focus = parent;
    }
    false
}

fn scala_type_lookup_segments_through_focus(
    focus: tree_sitter::Node<'_>,
    source: &str,
) -> Vec<String> {
    let mut current = focus;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "scoped_type_identifier" | "projected_type" | "stable_type_identifier"
        ) {
            let segments = crate::analyzer::scala::scala_type_lookup_segments(parent, source);
            if segments.len() > 1 {
                return segments;
            }
        }
        current = parent;
    }
    crate::analyzer::scala::scala_type_lookup_segments(focus, source)
}

fn finish_scala_external_boundary(
    mut value: DefinitionLookupOutcome,
    work: ReceiverAnalysisWork,
    site: &ResolvedReferenceSite,
    route_name: String,
    external_target: Option<String>,
    role: ClaimSubjectRole,
) -> BoundedResolution<DefinitionLookupOutcome> {
    if !project_jvm_external_boundary(
        &mut value,
        site,
        &route_name,
        external_target.as_deref(),
        Some(&route_name),
    ) {
        return BoundedResolution::Complete { value, work };
    }
    let (kind, message) = match role {
        ClaimSubjectRole::Type => (
            "scala_native_external_boundary",
            format!("`{route_name}` names a Scala type outside the indexed workspace"),
        ),
        ClaimSubjectRole::Member => (
            "scala_native_external_boundary",
            format!("`{route_name}` names a JVM member outside the indexed workspace"),
        ),
        ClaimSubjectRole::Any => (
            "scala_native_implicit_root_boundary",
            format!(
                "`{route_name}` may be supplied by an implicit Scala root outside the indexed workspace"
            ),
        ),
        _ => unreachable!("Scala external projection emits only type and member claims"),
    };
    value.diagnostics.insert(
        0,
        DefinitionLookupDiagnostic {
            kind: kind.into(),
            message,
            claim: Some(UnindexedClaim::external_boundary(route_name, role)),
        },
    );
    BoundedResolution::Complete { value, work }
}

struct ScalaExternalMemberEvidence {
    owner_status: BoundaryStatus,
    explicit_import_route: bool,
    member_target: Option<String>,
}

fn scala_external_member_evidence(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    focus: tree_sitter::Node<'_>,
) -> Option<ScalaExternalMemberEvidence> {
    let access = scala_member_access_for_focus(focus)?;
    let receiver = access.child_by_field_name("value")?;
    let member_node = access.child_by_field_name("field")?;
    let owner_segments = crate::analyzer::scala::scala_type_lookup_segments(receiver, query.source);
    if owner_segments.is_empty()
        || !scala_unindexed_route_has_provider(scala, query, token, &owner_segments)
    {
        return None;
    }
    let owner = owner_segments.join(".");
    let explicit_import_route = scala_explicit_import_binds(scala, query, token, &owner_segments);
    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Scala);
    let (owner_status, owner_target) = crate::analyzer::usages::get_definition::boundary_evidence(
        query.analyzer,
        query.file,
        &owner,
    );
    if owner_target
        .as_ref()
        .is_some_and(|target| !definitions.fqn_in_any_language(target).is_empty())
    {
        return None;
    }
    let member_name = query
        .source
        .get(member_node.start_byte()..member_node.end_byte())?
        .trim();
    if member_name.is_empty() {
        return None;
    }
    let member_target = scala
        .resolve_member_name_with_external(
            token,
            query.analyzer.semantic_model_overlay(),
            query.file,
            &format!("{owner}.{member_name}"),
        )
        .map(|member| member.fqn().to_owned());
    Some(ScalaExternalMemberEvidence {
        owner_status,
        explicit_import_route,
        member_target,
    })
}

fn scala_member_access_for_focus(focus: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    if focus.kind() == "call_expression" {
        let function = focus.child_by_field_name("function")?;
        return (function.kind() == "field_expression").then_some(function);
    }
    if focus.kind() == "field_expression" {
        return Some(focus);
    }
    let parent = focus.parent()?;
    if parent.kind() == "field_expression"
        && ["field", "value"].iter().any(|field_name| {
            parent
                .child_by_field_name(field_name)
                .is_some_and(|field| field.id() == focus.id())
        })
    {
        return Some(parent);
    }
    None
}

fn scala_unindexed_route_has_provider(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    segments: &[String],
) -> bool {
    let Some(_) = segments.first() else {
        return false;
    };
    if segments.len() == 1 {
        return scala_explicit_import_binds(scala, query, token, segments)
            || !language_implicit_root_providers(Language::Scala).is_empty();
    }
    let (status, _) = crate::analyzer::usages::get_definition::boundary_evidence(
        query.analyzer,
        query.file,
        &segments.join("."),
    );
    status != BoundaryStatus::ExternalUnknown
}

fn scala_explicit_import_binds(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    segments: &[String],
) -> bool {
    let Some(head) = segments.first() else {
        return false;
    };
    scala
        .tree_sitter_analyzer()
        .import_info_of(token, query.file)
        .iter()
        .any(|import| import.is_wildcard || import.local_name() == Some(head.as_str()))
}

fn scala_is_declaration_name(mut node: tree_sitter::Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent
            .child_by_field_name("name")
            .is_some_and(|name| name.id() == node.id())
        {
            return true;
        }
        node = parent;
    }
    false
}

fn kotlin_import_target_segments_through_focus(
    header: tree_sitter::Node<'_>,
    focus: tree_sitter::Node<'_>,
    source: &str,
) -> Option<(Vec<String>, bool)> {
    let path = named_children(header)
        .into_iter()
        .find(|child| child.kind() == "identifier")?;
    let segments = named_children(path)
        .into_iter()
        .filter(|child| child.kind() == "simple_identifier")
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return None;
    }
    let focus_index = segments
        .iter()
        .position(|segment| segment.id() == focus.id());
    let last = focus_index.unwrap_or(segments.len() - 1);
    let targets_declaration = focus_index.is_none_or(|index| index == segments.len() - 1)
        && !named_children(header)
            .into_iter()
            .any(|child| child.kind() == "wildcard_import");
    let candidate = segments[..=last]
        .iter()
        .map(|segment| kotlin_node_text(*segment, source).map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    Some((candidate, targets_declaration))
}

fn kotlin_import_target_incomplete(
    mut outcome: DefinitionLookupOutcome,
    site: &ResolvedReferenceSite,
    candidate: &str,
    reason: &str,
) -> DefinitionLookupOutcome {
    if outcome.status == DefinitionLookupStatus::NoDefinition {
        outcome.status = DefinitionLookupStatus::Incomplete;
        outcome.reference.get_or_insert_with(|| {
            let mut reference = site.clone();
            reference.text = candidate.to_owned();
            reference
        });
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "kotlin_import_target_unavailable".to_owned(),
            message: format!("`{candidate}` could not be confirmed: {reason}"),
            claim: None,
        });
    }
    outcome
}

fn kotlin_external_type_route(
    kotlin: &crate::analyzer::kotlin::KotlinAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    focus: tree_sitter::Node<'_>,
) -> Option<(String, Option<String>, BoundaryStatus)> {
    let segments = kotlin_type_segments_through_focus(focus, query.source)?;
    let written = segments.join(".");
    if written.is_empty() {
        return None;
    }
    let imports = kotlin
        .tree_sitter_analyzer()
        .import_info_of(token, query.file);
    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Kotlin);
    let head = segments.first()?;
    let mut routes = Vec::new();
    let mut matched_named_import = false;
    for import in &imports {
        let Some(path) = import
            .path
            .as_ref()
            .filter(|path| !path.segments.is_empty())
        else {
            continue;
        };
        if !import.is_wildcard && import.local_name() == Some(head.as_str()) {
            matched_named_import = true;
            if path.segments.len() < 2 {
                continue;
            }
            let package = path.segments[..path.segments.len() - 1].join(".");
            if !package.is_empty() && !kotlin_workspace_package_exists(&definitions, &package) {
                routes.push(path.render_segments("."));
            }
        } else if import.is_wildcard {
            let package = path.render_segments(".");
            if !kotlin_workspace_package_exists(&definitions, &package) {
                routes.push(format!("{package}.{written}"));
            }
        }
    }
    if !matched_named_import && segments.len() > 1 {
        let qualifier = segments[..segments.len() - 1].join(".");
        if !kotlin_workspace_package_exists(&definitions, &qualifier) {
            routes.push(written.clone());
        }
    }
    routes.sort();
    routes.dedup();
    let [route] = routes.as_slice() else {
        return None;
    };

    let (status, external_target) = kotlin.external_boundary_evidence(
        token,
        query.analyzer.semantic_model_overlay(),
        query.file,
        &written,
    );
    if status == BoundaryStatus::ExternalIndexed && external_target.is_none() {
        return None;
    }
    if external_target
        .as_ref()
        .is_some_and(|target| !definitions.fqn_in_any_language(target).is_empty())
    {
        return None;
    }
    Some((
        external_target.clone().unwrap_or_else(|| route.clone()),
        external_target,
        status,
    ))
}

struct KotlinExternalMemberEvidence {
    owner_status: BoundaryStatus,
    member_target: Option<String>,
}

fn kotlin_external_member_evidence(
    kotlin: &crate::analyzer::kotlin::KotlinAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    focus: tree_sitter::Node<'_>,
) -> Option<KotlinExternalMemberEvidence> {
    let navigation = kotlin_navigation_for_member_focus(focus)?;
    let receiver = syntax::kotlin_navigation_receiver(navigation)?;
    let owner = kotlin_receiver_type_spelling(receiver, query.source)?;
    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Kotlin);
    let (owner_status, owner_target) = kotlin.external_boundary_evidence(
        token,
        query.analyzer.semantic_model_overlay(),
        query.file,
        &owner,
    );
    if owner_target
        .as_ref()
        .is_some_and(|target| !definitions.fqn_in_any_language(target).is_empty())
    {
        return None;
    }
    if owner_target.is_none()
        && !kotlin_explicit_external_owner_import_exists(kotlin, query, token, &definitions, &owner)
    {
        return None;
    }
    let member_node = syntax::kotlin_navigation_member(navigation)?;
    let member_name = kotlin_node_text(member_node, query.source)?;
    let spelling = format!("{owner}.{member_name}");
    let resolved = kotlin
        .resolve_member_name_with_external(
            token,
            query.analyzer.semantic_model_overlay(),
            query.file,
            &spelling,
        )
        .map(|member| member.fqn().to_owned());
    Some(KotlinExternalMemberEvidence {
        owner_status,
        member_target: resolved,
    })
}

fn kotlin_explicit_external_owner_import_exists(
    kotlin: &crate::analyzer::kotlin::KotlinAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: crate::analyzer::QueryToken<'_>,
    definitions: &AnalyzerDefinitionLookup<'_>,
    owner: &str,
) -> bool {
    kotlin
        .tree_sitter_analyzer()
        .import_info_of(token, query.file)
        .iter()
        .any(|import| {
            if import.is_wildcard {
                return false;
            }
            let Some(path) = import.path.as_ref().filter(|path| path.segments.len() > 1) else {
                return false;
            };
            if import.local_name() != Some(owner) {
                return false;
            }
            let package = path.segments[..path.segments.len() - 1].join(".");
            !kotlin_workspace_package_exists(definitions, &package)
        })
}

fn kotlin_type_segments_through_focus(
    focus: tree_sitter::Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    let mut user_type = focus;
    while user_type.kind() != "user_type" {
        user_type = user_type.parent()?;
    }
    let mut segments = Vec::new();
    let mut selected = false;
    for segment in syntax::kotlin_user_type_segments(user_type) {
        if segment.id() == focus.id() {
            selected = true;
        }
        if !selected {
            segments.push(kotlin_node_text(segment, source)?.to_owned());
        } else {
            segments.push(kotlin_node_text(segment, source)?.to_owned());
            break;
        }
    }
    selected
        .then_some(segments)
        .filter(|segments| !segments.is_empty())
}

fn kotlin_workspace_package_exists(
    definitions: &AnalyzerDefinitionLookup<'_>,
    package: &str,
) -> bool {
    !package.is_empty()
        && (definitions.package_exists_in_any_language(package)
            || definitions.fqn_prefix_exists(package))
}

fn kotlin_navigation_for_member_focus(
    focus: tree_sitter::Node<'_>,
) -> Option<tree_sitter::Node<'_>> {
    let mut current = Some(focus);
    while let Some(node) = current {
        if node.kind() == "call_expression"
            && let Some(callee) = syntax::kotlin_callee(node)
            && syntax::kotlin_is_navigation_kind(callee.kind())
            && callee.start_byte() <= focus.start_byte()
            && callee.end_byte() >= focus.end_byte()
        {
            return Some(callee);
        }
        if node.id() == focus.id() && syntax::kotlin_is_navigation_kind(node.kind()) {
            return Some(node);
        }
        if syntax::kotlin_is_navigation_kind(node.kind())
            && let Some(member) = syntax::kotlin_navigation_member(node)
            && member.start_byte() <= focus.start_byte()
            && member.end_byte() >= focus.end_byte()
        {
            return Some(node);
        }
        current = node.parent();
    }
    None
}

fn kotlin_receiver_type_spelling(receiver: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    let receiver = syntax::kotlin_unwrap_receiver(receiver);
    match receiver.kind() {
        "simple_identifier" => {
            let name = kotlin_node_text(receiver, source)?;
            let Some(binding) = kotlin_local_binding(receiver, source, name) else {
                return Some(name.to_owned());
            };
            if let Some(type_node) = syntax::kotlin_binding_type_node(binding) {
                return syntax::kotlin_type_spelling(type_node, source);
            }
            let property = binding
                .parent()
                .filter(|parent| parent.kind() == "property_declaration")?;
            let initializer = named_children(property)
                .into_iter()
                .rev()
                .find(|child| syntax::kotlin_is_expression_kind(child.kind()))?;
            if initializer.kind() != "call_expression" {
                return None;
            }
            let callee = syntax::kotlin_callee(initializer)?;
            kotlin_name_path(callee, source)
        }
        kind if syntax::kotlin_is_navigation_kind(kind) => {
            let segments = syntax::kotlin_dotted_navigation_segments_with_max_depth(receiver, 8)?;
            let first = *segments.first()?;
            if let Some(name) = kotlin_node_text(first, source)
                && kotlin_local_binding(first, source, name).is_some()
            {
                return None;
            }
            Some(
                segments
                    .into_iter()
                    .map(|segment| kotlin_node_text(segment, source).map(str::to_owned))
                    .collect::<Option<Vec<_>>>()?
                    .join("."),
            )
        }
        "as_expression" => {
            let type_node = named_children(receiver).into_iter().next_back()?;
            syntax::kotlin_type_spelling(type_node, source)
        }
        _ => None,
    }
}

fn kotlin_name_path(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "simple_identifier" | "type_identifier" => Some(kotlin_node_text(node, source)?.to_owned()),
        kind if syntax::kotlin_is_navigation_kind(kind) => Some(
            syntax::kotlin_dotted_navigation_segments_with_max_depth(node, 8)?
                .into_iter()
                .map(|segment| kotlin_node_text(segment, source).map(str::to_owned))
                .collect::<Option<Vec<_>>>()?
                .join("."),
        ),
        _ => None,
    }
}

fn kotlin_local_binding<'tree>(
    node: tree_sitter::Node<'tree>,
    source: &str,
    name: &str,
) -> Option<tree_sitter::Node<'tree>> {
    let reference_start = node.start_byte();
    let mut current = node.parent();
    while let Some(scope) = current {
        let mut stack = named_children(scope);
        while let Some(candidate) = stack.pop() {
            if candidate.start_byte() > reference_start {
                continue;
            }
            match candidate.kind() {
                "parameter" | "class_parameter" => {
                    if let Some(declared) = named_children(candidate)
                        .into_iter()
                        .find(|child| child.kind() == "simple_identifier")
                        && kotlin_node_text(declared, source) == Some(name)
                    {
                        return Some(candidate);
                    }
                }
                "variable_declaration" => {
                    if syntax::kotlin_binding_name_nodes(candidate)
                        .into_iter()
                        .any(|declared| kotlin_node_text(declared, source) == Some(name))
                    {
                        return Some(candidate);
                    }
                }
                "class_declaration"
                | "object_declaration"
                | "companion_object"
                | "function_declaration" => continue,
                _ => stack.extend(named_children(candidate)),
            }
        }
        current = scope.parent();
    }
    None
}

fn kotlin_node_text<'source>(
    node: tree_sitter::Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn resolve_jvm_type_bounded<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    language: Language,
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<TypeLookupOutcome> {
    assert_eq!(inner.adapter().language(), language);
    let lookup = query.site.text.clone();
    resolve_native_type_bounded(
        inner,
        query,
        |operation, path, cancellation| {
            prepare_context(
                operation,
                language,
                path,
                cancellation,
                &lookup,
                Some(ResolutionNamespace::Type),
                None,
            )
        },
        after_open,
    )
}

fn prepare_definition_context(
    operation: &SelectedResolutionOperation<'_, '_>,
    language: Language,
    path: &str,
    cancellation: &CancellationToken,
    query: BoundedReceiverQuery<'_>,
    lookup: &str,
    namespace: Option<ResolutionNamespace>,
) -> Result<NativePointContext> {
    let query_scope = query
        .cancellation
        .map(|token| AnalyzerQueryScope::with_cancellation(query.analyzer, token))
        .unwrap_or_else(|| AnalyzerQueryScope::new(query.analyzer));
    let import_route =
        explicit_import_model_route(query.analyzer, query_scope.token(), query.file, query.site);
    let selected_model = import_route.as_ref().and_then(|route| {
        let overlay = query.analyzer.semantic_model_overlay()?;
        let mut symbols = qualified_model_symbols(&overlay, &route.target).into_iter();
        let symbol = symbols.next()?;
        if symbols.next().is_some() || symbol.provenance.ambiguous {
            return None;
        }
        Some((route.clone(), symbol.clone()))
    });
    prepare_context(
        operation,
        language,
        path,
        cancellation,
        lookup,
        namespace,
        selected_model,
    )
}

fn prepare_context(
    operation: &SelectedResolutionOperation<'_, '_>,
    language: Language,
    path: &str,
    cancellation: &CancellationToken,
    lookup: &str,
    namespace: Option<ResolutionNamespace>,
    selected_model: Option<(
        ExplicitImportModelRoute,
        crate::analyzer::semantic_model::SemanticModelSymbol,
    )>,
) -> Result<NativePointContext> {
    Ok(
        match operation.jvm_import_context(language, path, cancellation)? {
            JvmImportContext::Ready {
                context,
                scoped_gaps,
                ..
            } => {
                let selected_model = selected_model.and_then(|(route, symbol)| {
                    let mut matching_model_gaps = scoped_gaps
                        .iter()
                        .filter(|gap| model_import_gap_matches(gap, &route, lookup, namespace));
                    let gap = matching_model_gaps.next()?;
                    if matching_model_gaps.next().is_some() {
                        return None;
                    }
                    Some(Box::new(SelectedNativeImportModel {
                        symbol,
                        source_token: gap.source_token,
                        gap_reason: gap.reason,
                    }))
                });
                let matching_gaps = scoped_gaps
                    .into_iter()
                    .filter(|gap| {
                        gap.lookup.spelling() == lookup
                            && namespace.is_none_or(|namespace| gap.lookup.namespace() == namespace)
                            && !selected_model.as_ref().is_some_and(|model| {
                                gap.source_token == model.source_token
                                    && gap.reason == model.gap_reason
                            })
                    })
                    .collect::<Vec<_>>();
                let context = matching_gaps.into_iter().fold(*context, |context, gap| {
                    context.with_additional_context_owned_inventory_reason(gap.reason)
                });
                NativePointContext::Ready {
                    context: Box::new(context),
                    selected_import_model: selected_model,
                }
            }
            JvmImportContext::Unavailable => NativePointContext::Unavailable,
            JvmImportContext::Cancelled => NativePointContext::Cancelled,
        },
    )
}

fn model_import_gap_matches(
    gap: &crate::analyzer::store::resolution_operation::JvmImportContextGap,
    route: &ExplicitImportModelRoute,
    lookup: &str,
    namespace: Option<ResolutionNamespace>,
) -> bool {
    gap.kind == "jvm-import-owner-open"
        && gap.owner.as_deref() == Some(route.owner.as_str())
        && gap.lookup.spelling() == lookup
        && route.local_name == lookup
        && namespace.is_none_or(|namespace| gap.lookup.namespace() == namespace)
}

fn unavailable_jvm_definition(
    site: &ResolvedReferenceSite,
    language: Language,
) -> BoundedResolution<DefinitionLookupOutcome> {
    BoundedResolution::Complete {
        value: unavailable_definition(
            site,
            "native_analyzer_unavailable",
            format!("{} analyzer is unavailable", language.config_label()),
        ),
        work: Default::default(),
    }
}

fn unavailable_jvm_type(
    site: &ResolvedReferenceSite,
    language: Language,
) -> BoundedResolution<TypeLookupOutcome> {
    BoundedResolution::Complete {
        value: unavailable_type(
            site,
            "native_analyzer_unavailable",
            format!("{} analyzer is unavailable", language.config_label()),
        ),
        work: Default::default(),
    }
}
