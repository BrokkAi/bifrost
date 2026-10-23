//! One selected-source point resolver for the shared Java/Kotlin/Scala realm.

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::jvm_external::qualified_model_symbols;

use crate::analyzer::jvm::import_routes::ExplicitImportModelRoute;

use crate::analyzer::jvm::import_routes::explicit_import_model_route;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_analysis::analyzer::native_points::NativePointContext;

use brokk_bifrost_analysis::analyzer::native_points::SelectedNativeImportModel;

use brokk_bifrost_analysis::analyzer::native_points::resolve_native_definition_bounded;

use brokk_bifrost_analysis::analyzer::native_points::resolve_native_type_bounded;

use brokk_bifrost_analysis::analyzer::native_points::unavailable_definition;

use brokk_bifrost_analysis::analyzer::native_points::unavailable_type;

use brokk_bifrost_analysis::analyzer::resolution::fact_source::language_implicit_root_providers;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ClaimSubjectRole;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::usages::get_definition::UnindexedClaim;

use brokk_bifrost_analysis::analyzer::usages::get_definition::boundary_unchecked;

use brokk_bifrost_analysis::analyzer::usages::get_definition::candidates_outcome;

use crate::analyzer::usages::get_definition::kotlin_import_model_outcome;

use crate::analyzer::usages::get_definition::kotlin_package_reference_outcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::no_definition;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::named_children;
use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;
use brokk_bifrost_jvm::kotlin::imports::kotlin_import_info_from_node;
use brokk_bifrost_jvm::kotlin::syntax::{self, kotlin_is_declaration_name};
use brokk_bifrost_jvm::scala::graph::syntax as scala_syntax;

#[doc(hidden)]
pub static JVM_NATIVE_ROLLOUT_POINTS: JvmNativeRolloutPoints = JvmNativeRolloutPoints;

#[doc(hidden)]
pub struct JvmNativeRolloutPoints;

impl StructuralReceiverResolver for JvmNativeRolloutPoints {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        match query_language(&query) {
            #[cfg(any(test, feature = "test-support"))]
            Language::Java => {
                crate::analyzer::java::native_points::resolve_java_type_bounded(query, || {})
            }
            Language::Kotlin => {
                let Some(kotlin) =
                    brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                        crate::analyzer::kotlin::KotlinAnalyzer,
                    >(query.analyzer)
                else {
                    return unavailable_jvm_type(query.site, Language::Kotlin);
                };
                let anchored = kotlin_call_value_anchor(query);
                let query = match &anchored {
                    Some(site) => BoundedReceiverQuery { site, ..query },
                    None => query,
                };
                resolve_jvm_type_bounded(
                    kotlin.tree_sitter_analyzer(),
                    Language::Kotlin,
                    query,
                    || {},
                )
            }
            Language::Scala => {
                let Some(scala) =
                    brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                        crate::analyzer::scala::ScalaAnalyzer,
                    >(query.analyzer)
                else {
                    return unavailable_jvm_type(query.site, Language::Scala);
                };
                resolve_jvm_type_bounded(
                    scala.tree_sitter_analyzer(),
                    Language::Scala,
                    query,
                    || {},
                )
            }
            language => {
                unreachable!("native JVM point query is unavailable for language: {language:?}")
            }
        }
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        match query_language(&query) {
            #[cfg(any(test, feature = "test-support"))]
            Language::Java => {
                crate::analyzer::java::native_points::resolve_java_definition_bounded(query, || {})
            }
            Language::Kotlin => {
                brokk_bifrost_analysis::analyzer::usages::get_definition::trace::begin_native_trace(
                );
                let Some(kotlin) =
                    brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                        crate::analyzer::kotlin::KotlinAnalyzer,
                    >(query.analyzer)
                else {
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
                brokk_bifrost_analysis::analyzer::usages::get_definition::trace::begin_native_trace(
                );
                let Some(scala) =
                    brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                        crate::analyzer::scala::ScalaAnalyzer,
                    >(query.analyzer)
                else {
                    return unavailable_jvm_definition(query.site, Language::Scala);
                };
                let resolution = resolve_jvm_definition_bounded(
                    scala.tree_sitter_analyzer(),
                    Language::Scala,
                    query,
                    || {},
                );
                project_scala_external_boundary(
                    scala,
                    query,
                    project_jvm_declaration_site(query, resolution),
                )
            }
            language => {
                unreachable!("native JVM point query is unavailable for language: {language:?}")
            }
        }
    }
}

// A whole Kotlin call expression asks for the value the call produces. The
// producer publishes no reference at the call's own range: the call value is
// the callee reference's `TargetCallableResultType` projection, so the point
// is focused on that callee. The reported site keeps the whole expression.
// This mirrors Go's whole-expression anchor selection in its native points.
fn kotlin_call_value_anchor(query: BoundedReceiverQuery<'_>) -> Option<ResolvedReferenceSite> {
    let call = smallest_named_node_covering(
        query.tree?.root_node(),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    )
    .filter(|node| {
        node.kind() == "call_expression"
            && node.start_byte() == query.site.focus_start_byte
            && node.end_byte() == query.site.focus_end_byte
    })?;
    let callee = syntax::kotlin_callee(call)?;
    let anchor = match callee.kind() {
        "simple_identifier" => callee,
        "navigation_expression" => syntax::kotlin_navigation_member(callee)?,
        _ => return None,
    };
    let mut site = query.site.clone();
    site.focus_start_byte = anchor.start_byte();
    site.focus_end_byte = anchor.end_byte();
    Some(site)
}

fn query_language(query: &BoundedReceiverQuery<'_>) -> Language {
    let language = brokk_bifrost_core::analyzer::common::language_for_file(query.file);
    assert!(
        matches!(
            language,
            Language::Java | Language::Kotlin | Language::Scala
        ),
        "JVM native point query has a non-JVM file language: {language:?}"
    );
    language
}

// A point's display text can cover the whole qualified path, while its
// focus identifies the demanded name. Import-context selection uses that
// structured focus; the shared preparation supplies its qualifier names.
fn jvm_point_lookup(query: BoundedReceiverQuery<'_>) -> &str {
    query
        .tree
        .and_then(|tree| {
            smallest_named_node_covering(
                tree.root_node(),
                query.site.focus_start_byte,
                query.site.focus_end_byte,
            )
        })
        .and_then(|node| node.utf8_text(query.source.as_bytes()).ok())
        .unwrap_or(&query.site.text)
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
    let lookup = jvm_point_lookup(query);
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
    let reference_namespace = (language == Language::Scala)
        .then(|| {
            query.tree.and_then(|tree| {
                smallest_named_node_covering(
                    tree.root_node(),
                    query.site.focus_start_byte,
                    query.site.focus_end_byte,
                )
            })
        })
        .flatten()
        .filter(|node| scala_syntax::explicit_constructor_reference(*node))
        .map(|_| ResolutionNamespace::Constructor);
    resolve_native_definition_bounded(
        inner,
        query,
        reference_namespace,
        |operation, path, cancellation| {
            prepare_definition_context(
                operation,
                language,
                path,
                cancellation,
                query,
                lookup,
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
        brokk_bifrost_analysis::analyzer::usages::get_definition::record_native_external_route_with_target(
            route_name.to_owned(),
            target.to_owned(),
        );
    } else {
        brokk_bifrost_analysis::analyzer::usages::get_definition::record_native_external_route(
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
    if value
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "intrinsic_type_reference")
    {
        return BoundedResolution::Complete { value, work };
    }
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
            let mut package = kotlin_package_reference_outcome(&candidate);
            package.reference = Some(query.site.clone());
            return BoundedResolution::Complete {
                value: package,
                work,
            };
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
    let type_segments = if focus.kind() == "type_identifier" {
        kotlin_type_segments_through_focus(focus, query.source)
    } else if focus.kind() == "simple_identifier"
        && syntax::kotlin_call_with_callee(focus).is_some()
    {
        // A bare Kotlin callee can construct an imported external type even
        // when its semantic model describes no constructors. Require a type
        // declaration below; an imported function is not a constructor route.
        Some(vec![
            brokk_bifrost_jvm::kotlin::declarations::kotlin_identifier_text(focus, query.source)
                .to_owned(),
        ])
    } else {
        None
    };
    let projected =
        if let Some(segments) = type_segments {
            kotlin_external_type_route(kotlin, query, token, &segments)
                .filter(|(_, target, _)| {
                    if focus.kind() == "type_identifier" {
                        return true;
                    }
                    let Some(target) = target else {
                        return false;
                    };
                    let Some(owner) = kotlin
                        .external_declarations(query.analyzer.semantic_model_overlay())
                        .resolve_qualified_name(target, "")
                    else {
                        return false;
                    };
                    let crate::analyzer::jvm::external::JvmExternalDeclarationSource::SemanticPack {
                    declaration_id, ..
                } = owner.source() else {
                    return false;
                };
                    let Some(active) = query.analyzer.active_semantic_models() else {
                        return false;
                    };
                    active.types_named(target).records.iter().any(|candidate| {
                        candidate.record.id == *declaration_id
                            && (!candidate
                                .shard
                                .independently_enumerates_jvm_owner(candidate.record)
                                || !candidate
                                    .record
                                    .jvm_inventory
                                    .as_ref()
                                    .is_some_and(|inventory| inventory.callables_complete))
                    })
                })
                .map(|(route_name, external_target, boundary_status)| {
                    (
                        route_name,
                        external_target,
                        ClaimSubjectRole::Type,
                        Some(boundary_status),
                    )
                })
        } else {
            // Only the shared resolver can prove absence. A known receiver type
            // does not certify complete member or extension-provider inventories.
            kotlin_external_member_target(kotlin, query, token, focus)
                .map(|target| (target.clone(), Some(target), ClaimSubjectRole::Member, None))
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

/// A bare spelling in the Scala universe (`Int`, `String`) that no selected
/// source scope declares resolves to a language builtin identity. That identity
/// has no source unit, so the native answer is unavailable for want of a
/// projection. It names a type outside the indexed workspace, so the external
/// boundary projection treats it as the unresolved reference it was before the
/// universe table existed.
fn scala_universe_hit_without_unit(
    value: &DefinitionLookupOutcome,
    query: BoundedReceiverQuery<'_>,
) -> bool {
    if value.status != DefinitionLookupStatus::Unavailable
        || !value
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "native_definition_projection_unavailable")
    {
        return false;
    }
    let Some(focus) = query.tree.and_then(|tree| {
        smallest_named_node_covering(
            tree.root_node(),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        )
    }) else {
        return false;
    };
    matches!(focus.kind(), "type_identifier" | "identifier")
        && query
            .source
            .get(focus.start_byte()..focus.end_byte())
            .is_some_and(|spelling| {
                brokk_bifrost_analysis::analyzer::resolution::universe::lookup(
                    Language::Scala,
                    ResolutionNamespace::TypeOrValue,
                    spelling.trim(),
                )
                .is_some()
            })
}

/// A cursor on a declaration name or on an import alias is not a reference: the
/// producer publishes no reference there, so the native lookup finds nothing to
/// locate. Project language-classified non-reference sites with the shared
/// `declaration_or_import_site` diagnostic, instead of the unavailable status
/// that a missing reference maps to.
pub(crate) fn project_jvm_declaration_site(
    query: BoundedReceiverQuery<'_>,
    resolution: BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let BoundedResolution::Complete { value, work } = resolution else {
        return resolution;
    };
    if value.status != DefinitionLookupStatus::Unavailable
        || !value
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "native_reference_unavailable")
    {
        return BoundedResolution::Complete { value, work };
    }
    let Some(focus) = query.tree.and_then(|tree| {
        smallest_named_node_covering(
            tree.root_node(),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        )
    }) else {
        return BoundedResolution::Complete { value, work };
    };
    let language = query_language(&query);
    if !brokk_bifrost_analysis::analyzer::languages::language_support_for_hook(
        language,
        "native_non_reference_site",
    )
    .is_some_and(|support| support.native_non_reference_site(focus))
    {
        return BoundedResolution::Complete { value, work };
    }
    BoundedResolution::Complete {
        value: DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status: DefinitionLookupStatus::NoDefinition,
            reference: Some(query.site.clone()),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: vec![DefinitionLookupDiagnostic {
                claim: None,
                kind: DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND.into(),
                message: format!("`{}` is not a {language:?} reference site", query.site.text),
            }],
        },
        work,
    }
}

fn project_scala_external_boundary(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    resolution: BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let BoundedResolution::Complete { mut value, work } = resolution else {
        return resolution;
    };
    if scala_universe_hit_without_unit(&value, query) {
        value.status = DefinitionLookupStatus::NoDefinition;
        value
            .diagnostics
            .retain(|diagnostic| diagnostic.kind != "native_definition_projection_unavailable");
    }
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
    if scala_is_declaration_name(focus)
        || scala_is_import_alias(focus)
        || scala_reference_is_export_or_package_syntax(focus)
    {
        return BoundedResolution::Complete { value, work };
    }

    let scope = AnalyzerQueryScope::new(query.analyzer);
    let token = scope.token();
    let incomplete_hierarchy_names = if value.status == DefinitionLookupStatus::Incomplete {
        scala_enclosing_external_supertype_names(query, token, focus)
    } else {
        Vec::new()
    };
    let unindexed_diagnostic_names = incomplete_hierarchy_names
        .iter()
        .filter(|name| {
            AnalyzerDefinitionLookup::new(query.analyzer, Language::Scala)
                .fqn_in_any_language(name)
                .is_empty()
        })
        .collect::<Vec<_>>();
    if !unindexed_diagnostic_names.is_empty() {
        let diagnostic = value
            .diagnostics
            .iter_mut()
            .find(|diagnostic| diagnostic.kind == "incomplete_binding")
            .expect("an incomplete native answer has an incomplete_binding diagnostic");
        diagnostic.message = format!(
            "selected native binding is incomplete: UnsupportedHierarchyTraversal for unindexed supertype(s) {unindexed_diagnostic_names:?}"
        );
    }
    if matches!(focus.kind(), "type_identifier" | "stable_type_identifier") {
        let segments = scala_type_lookup_segments_through_focus(focus, query.source);
        if !segments.is_empty() {
            let written = segments.join(".");
            let (status, external_target) =
                brokk_bifrost_analysis::analyzer::usages::get_definition::trace::boundary_evidence(
                    query.analyzer,
                    query.file,
                    &written,
                );
            // An unmatched constructor does not prove its type is external.
            let bare_implicit_root = segments.len() == 1
                && !scala_syntax::explicit_constructor_reference(focus)
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
    } else if let Some(target) = scala_external_member_target(scala, query, token, focus) {
        if let Some(target) = target {
            return finish_scala_external_boundary(
                value,
                work,
                query.site,
                target.clone(),
                Some(target),
                ClaimSubjectRole::Member,
            );
        }
        // A recognized external member route stays with shared closure even
        // when its provider did not bind the member.
        return BoundedResolution::Complete { value, work };
    } else if scala_identifier_is_implicit_root_reference(focus)
        && !(value.status == DefinitionLookupStatus::Incomplete
            && !incomplete_hierarchy_names.is_empty())
    {
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
                brokk_bifrost_analysis::analyzer::usages::get_definition::trace::boundary_evidence(
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

fn scala_enclosing_external_supertype_names(
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    focus: tree_sitter::Node<'_>,
) -> Vec<String> {
    let Some(tree) = query.tree else {
        return Vec::new();
    };
    let Some(scala) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        crate::analyzer::scala::ScalaAnalyzer,
    >(query.analyzer) else {
        return Vec::new();
    };
    let model = query.analyzer.semantic_model_overlay();
    let mut names = Vec::new();
    let mut ancestor = Some(focus);
    while let Some(node) = ancestor {
        if matches!(
            node.kind(),
            "class_definition" | "trait_definition" | "object_definition" | "enum_definition"
        ) {
            for (parent, _) in
                brokk_bifrost_jvm::scala::supertypes::scala_supertype_lookup_nodes(node)
            {
                let segments = brokk_bifrost_jvm::scala::supertypes::scala_type_lookup_segments(
                    parent,
                    query.source,
                );
                if !segments.is_empty()
                    && brokk_bifrost_analysis::analyzer::usages::get_definition::trace::boundary_evidence(
                        query.analyzer,
                        query.file,
                        &segments.join("."),
                    )
                    .0 == BoundaryStatus::ExternalDeclaredUnindexed
                {
                    let written = segments.join(".");
                    let name = scala
                        .external_type_name(token, model.clone(), query.file, &written)
                        .or_else(|| scala_imported_supertype_name(scala, &query, token, &segments))
                        .or_else(|| {
                            if segments.len() > 1 {
                                Some(written.clone())
                            } else {
                                brokk_bifrost_jvm::scala::wildcard_imports::
                                    scala_package_prefixes_at(
                                        tree.root_node(),
                                        query.source,
                                        parent.start_byte(),
                                    )
                                    .last()
                                    .filter(|prefix| !prefix.is_empty())
                                    .map(|prefix| format!("{prefix}.{written}"))
                                    .or(Some(written))
                            }
                        });
                    if let Some(name) = name {
                        names.push(name);
                    }
                }
            }
        }
        ancestor = node.parent();
    }
    names.sort_unstable();
    names.dedup();
    names
}

fn scala_imported_supertype_name(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: &BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    segments: &[String],
) -> Option<String> {
    let [name] = segments else {
        return None;
    };
    let mut candidates = Vec::new();
    for import in scala
        .import_info_of_limited(token, query.file, usize::MAX)
        .rows
    {
        let Some(path) = brokk_bifrost_jvm::scala::wildcard_imports::scala_import_path(&import)
        else {
            continue;
        };
        if import.is_wildcard {
            candidates.push(format!("{path}.{name}"));
        } else if import.local_name() == Some(name.as_str()) {
            candidates.push(path);
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    let mut declared_unindexed = candidates
        .into_iter()
        .filter(|candidate| {
            brokk_bifrost_analysis::analyzer::usages::get_definition::trace::boundary_evidence(
                query.analyzer,
                query.file,
                candidate,
            )
            .0 == BoundaryStatus::ExternalDeclaredUnindexed
        })
        .collect::<Vec<_>>();
    declared_unindexed.sort_unstable();
    declared_unindexed.dedup();
    (declared_unindexed.len() == 1).then(|| declared_unindexed.remove(0))
}

fn scala_identifier_is_implicit_root_reference(focus: tree_sitter::Node<'_>) -> bool {
    focus.kind() == "identifier" && scala_syntax::named_argument_label_owner(focus).is_none()
}

fn scala_reference_is_export_or_package_syntax(mut focus: tree_sitter::Node<'_>) -> bool {
    while let Some(parent) = focus.parent() {
        if matches!(parent.kind(), "export_declaration" | "package_clause") {
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
            let segments =
                brokk_bifrost_jvm::scala::supertypes::scala_type_lookup_segments(parent, source);
            if segments.len() > 1 {
                return segments;
            }
        }
        current = parent;
    }
    brokk_bifrost_jvm::scala::supertypes::scala_type_lookup_segments(focus, source)
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

fn scala_external_member_target(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    focus: tree_sitter::Node<'_>,
) -> Option<Option<String>> {
    let access = scala_member_access_for_focus(focus)?;
    let receiver = access.child_by_field_name("value")?;
    let member_node = access.child_by_field_name("field")?;
    let owner_segments =
        brokk_bifrost_jvm::scala::supertypes::scala_type_lookup_segments(receiver, query.source);
    if owner_segments.is_empty()
        || !scala_unindexed_route_has_provider(scala, query, token, &owner_segments)
    {
        return None;
    }
    let owner = owner_segments.join(".");
    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Scala);
    let (_, owner_target) =
        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::boundary_evidence(
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
    Some(
        scala
            .resolve_member_name_with_external(
                token,
                query.analyzer.semantic_model_overlay(),
                query.file,
                &format!("{owner}.{member_name}"),
            )
            .map(|member| member.fqn().to_owned()),
    )
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
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    segments: &[String],
) -> bool {
    let Some(_) = segments.first() else {
        return false;
    };
    if segments.len() == 1 {
        return scala_explicit_import_binds(scala, query, token, segments)
            || !language_implicit_root_providers(Language::Scala).is_empty();
    }
    let (status, _) =
        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::boundary_evidence(
            query.analyzer,
            query.file,
            &segments.join("."),
        );
    status != BoundaryStatus::ExternalUnknown
}

fn scala_explicit_import_binds(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
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

pub(crate) fn scala_non_reference_site(node: tree_sitter::Node<'_>) -> bool {
    scala_is_declaration_name(node) || scala_is_import_alias(node)
}

/// The alias of a renaming import selector (`{default => renderDefault}`).
fn scala_is_import_alias(node: tree_sitter::Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "as_renamed_identifier" | "arrow_renamed_identifier"
        ) && parent.child_by_field_name("alias") == Some(node)
    })
}

/// A node named by its parent's `name` field. A type parameter list names
/// several children with that field, so every one is compared.
fn scala_is_declaration_name(mut node: tree_sitter::Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        let mut cursor = parent.walk();
        if parent
            .children_by_field_name("name", &mut cursor)
            .any(|name| name.id() == node.id())
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
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    segments: &[String],
) -> Option<(String, Option<String>, BoundaryStatus)> {
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
        if !kotlin_workspace_package_exists(&definitions, &qualifier)
            && !definitions
                .fqn_in_any_language(&qualifier)
                .iter()
                .any(|definition| definition.is_class())
        {
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

fn kotlin_external_member_target(
    kotlin: &crate::analyzer::kotlin::KotlinAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    focus: tree_sitter::Node<'_>,
) -> Option<String> {
    let navigation = kotlin_navigation_for_member_focus(focus)?;
    let receiver = syntax::kotlin_navigation_receiver(navigation)?;
    let owner = kotlin_receiver_type_spelling(receiver, query.source)?;
    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Kotlin);
    let (_, owner_target) = kotlin.external_boundary_evidence(
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
    kotlin
        .resolve_member_name_with_external(
            token,
            query.analyzer.semantic_model_overlay(),
            query.file,
            &spelling,
        )
        .map(|member| member.fqn().to_owned())
}

fn kotlin_explicit_external_owner_import_exists(
    kotlin: &crate::analyzer::kotlin::KotlinAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
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
    let lookup = jvm_point_lookup(query);
    resolve_native_type_bounded(
        inner,
        query,
        |operation, path, cancellation| {
            prepare_context(
                operation,
                language,
                path,
                cancellation,
                lookup,
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
        brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol,
    )>,
) -> Result<NativePointContext> {
    Ok(
        match operation.jvm_import_context_for_name(language, path, lookup, cancellation)? {
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
    gap: &brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContextGap,
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
