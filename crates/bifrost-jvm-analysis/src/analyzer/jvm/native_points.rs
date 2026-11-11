//! One selected-source point resolver for the shared Java/Kotlin/Scala realm.

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::jvm_external::qualified_model_symbols;

use crate::analyzer::jvm::import_routes::ExplicitImportModelRoute;

use crate::analyzer::jvm::import_routes::explicit_import_model_route;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_analysis::analyzer::native_points::NativePointContext;

use brokk_bifrost_analysis::analyzer::native_points::SelectedNativeImportModel;

use brokk_bifrost_analysis::analyzer::native_points::resolve_native_definition_answer_bounded;

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

use brokk_bifrost_analysis::analyzer::usages::get_definition::CallEvidence;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ClaimSubjectRole;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolutionAuthority;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeReferenceUnits;

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
        let Ok(_model_scope) =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::pin_selected_model_snapshot(
                query.analyzer,
            )
        else {
            return unavailable_jvm_type(query.site, query_language(&query));
        };
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
        let Ok(_model_scope) =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::pin_selected_model_snapshot(
                query.analyzer,
            )
        else {
            return unavailable_jvm_definition(query.site, query_language(&query));
        };
        match query_language(&query) {
            #[cfg(any(test, feature = "test-support"))]
            Language::Java => {
                crate::analyzer::java::native_points::resolve_java_definition_bounded(query, || {})
            }
            Language::Kotlin | Language::Scala => {
                match resolve_jvm_definition_with_call_evidence(query) {
                    BoundedResolution::Complete {
                        value: (outcome, _),
                        work,
                    } => BoundedResolution::Complete {
                        value: outcome,
                        work,
                    },
                    BoundedResolution::Exceeded { limit, work } => {
                        BoundedResolution::Exceeded { limit, work }
                    }
                    BoundedResolution::Unavailable { reason, work } => {
                        BoundedResolution::Unavailable { reason, work }
                    }
                    BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
                }
            }
            language => {
                unreachable!("native JVM point query is unavailable for language: {language:?}")
            }
        }
    }

    fn resolve_definition_with_call_evidence_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<(DefinitionLookupOutcome, CallEvidence)> {
        if matches!(query_language(&query), Language::Kotlin | Language::Scala) {
            return resolve_jvm_definition_with_call_evidence(query);
        }
        match self.resolve_definition_bounded(query) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: (value, CallEvidence::default()),
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Unavailable { reason, work } => {
                BoundedResolution::Unavailable { reason, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        }
    }
}

/// Resolve a Kotlin or Scala reference and, when it is the callee of a call,
/// the exact external call its selected answer proves. The proof comes from
/// the shared selected-answer projection; each language supplies only its
/// callee test and its own outcome projections.
fn resolve_jvm_definition_with_call_evidence(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<(DefinitionLookupOutcome, CallEvidence)> {
    let language = query_language(&query);
    let Ok(_model_scope) =
        brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::pin_selected_model_snapshot(
            query.analyzer,
        )
    else {
        return with_default_evidence(unavailable_jvm_definition(query.site, language));
    };
    brokk_bifrost_analysis::analyzer::usages::get_definition::trace::begin_native_trace();
    match language {
        Language::Kotlin => {
            let Some(kotlin) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                crate::analyzer::kotlin::KotlinAnalyzer,
            >(query.analyzer) else {
                return with_default_evidence(unavailable_jvm_definition(query.site, language));
            };
            resolve_jvm_call_evidence(
                kotlin.tree_sitter_analyzer(),
                language,
                query,
                kotlin_focus_is_callee(query),
                |resolution| {
                    project_kotlin_external_boundary(
                        kotlin,
                        query,
                        project_kotlin_star_import_ambiguity(query, resolution),
                    )
                },
            )
        }
        Language::Scala => {
            let Some(scala) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                crate::analyzer::scala::ScalaAnalyzer,
            >(query.analyzer) else {
                return with_default_evidence(unavailable_jvm_definition(query.site, language));
            };
            resolve_jvm_call_evidence(
                scala.tree_sitter_analyzer(),
                language,
                query,
                scala_focus_is_callee(query),
                |resolution| {
                    project_scala_external_boundary(
                        scala,
                        query,
                        project_jvm_declaration_site(query, resolution),
                    )
                },
            )
        }
        language => unreachable!("JVM call evidence is unavailable for language: {language:?}"),
    }
}

/// The exact external call the selected native answer proves for a Scala
/// callee, or no evidence for any other site. The incumbent Scala resolver
/// answers navigation; this is the shared selected-answer projection that
/// supplies its call proof. A proven call's outcome names the proven member,
/// as every exact external call boundary does: a constructor is `T.<init>`,
/// not the type the incumbent resolved.
pub(crate) fn scala_native_call_evidence(
    query: BoundedReceiverQuery<'_>,
    outcome: &mut DefinitionLookupOutcome,
) -> CallEvidence {
    if !scala_focus_is_callee(query) {
        return CallEvidence::default();
    }
    let Ok(_model_scope) =
        brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::pin_selected_model_snapshot(
            query.analyzer,
        )
    else {
        return CallEvidence::default();
    };
    let Some(scala) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        crate::analyzer::scala::ScalaAnalyzer,
    >(query.analyzer) else {
        return CallEvidence::default();
    };
    // The proof lookup is auxiliary: the incumbent answer owns the traced
    // candidates for this reference.
    let selected =
        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::without_recording(|| {
            resolve_jvm_definition_answer_bounded(
                scala.tree_sitter_analyzer(),
                Language::Scala,
                query,
                || {},
                |units| selected_external_call(Language::Scala, units),
            )
        });
    match selected {
        BoundedResolution::Complete {
            value: (_, Some(Some(call))),
            ..
        } => {
            outcome
                .reference
                .get_or_insert_with(|| query.site.clone())
                .text = format!("{}.{}", call.owner, call.member);
            call.evidence()
        }
        _ => CallEvidence::default(),
    }
}

fn resolve_jvm_call_evidence<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    language: Language,
    query: BoundedReceiverQuery<'_>,
    called: bool,
    project_outcome: impl FnOnce(
        BoundedResolution<DefinitionLookupOutcome>,
    ) -> BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<(DefinitionLookupOutcome, CallEvidence)> {
    let resolution = resolve_jvm_definition_answer_bounded(
        inner,
        language,
        query,
        || {},
        |units| {
            called
                .then(|| selected_external_call(language, units))
                .flatten()
        },
    );
    let (resolution, selected) = match resolution {
        BoundedResolution::Complete {
            value: (outcome, selected),
            work,
        } => (
            BoundedResolution::Complete {
                value: outcome,
                work,
            },
            selected.flatten(),
        ),
        BoundedResolution::Exceeded { limit, work } => {
            return BoundedResolution::Exceeded { limit, work };
        }
        BoundedResolution::Unavailable { reason, work } => {
            return BoundedResolution::Unavailable { reason, work };
        }
        BoundedResolution::Cancelled { work } => return BoundedResolution::Cancelled { work },
    };
    match project_outcome(resolution) {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value: (
                value,
                selected.map_or_else(CallEvidence::default, |call| call.evidence()),
            ),
            work,
        },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Unavailable { reason, work } => {
            BoundedResolution::Unavailable { reason, work }
        }
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

fn with_default_evidence(
    resolution: BoundedResolution<DefinitionLookupOutcome>,
) -> BoundedResolution<(DefinitionLookupOutcome, CallEvidence)> {
    match resolution {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value: (value, CallEvidence::default()),
            work,
        },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Unavailable { reason, work } => {
            BoundedResolution::Unavailable { reason, work }
        }
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

/// The one external JVM member a call's selected applicability answer kept.
///
/// The store's call applicability (shared, with each language's adapter)
/// already chose the overload and proved its receiver and argument
/// conversions; a complete single-target answer is that proof. The call shape
/// comes from the selected inventory row, never from the callee's spelling.
struct SelectedExternalCall {
    declaring_language: Language,
    owner: String,
    member: String,
    is_static: bool,
    parameter_count: u32,
}

impl SelectedExternalCall {
    fn evidence(&self) -> CallEvidence {
        let proof = if self.member == "<init>" {
            ExactExternalCallProof::java_external_constructor(
                &self.owner,
                &self.member,
                self.parameter_count,
            )
        } else if self.is_static {
            ExactExternalCallProof::java_static_external_member(
                &self.owner,
                &self.member,
                self.parameter_count,
            )
        } else {
            ExactExternalCallProof::java_bound_external_member(
                &self.owner,
                &self.member,
                self.parameter_count,
            )
        };
        CallEvidence::selected_external_call(
            self.declaring_language,
            proof,
            &self.owner,
            &self.member,
            DefinitionResolutionAuthority::Incumbent,
        )
    }
}

fn selected_external_call(
    caller: Language,
    units: &SelectedNativeReferenceUnits,
) -> Option<SelectedExternalCall> {
    let binding = units.answer.binding();
    let ([_], [member]) = (binding.targets(), units.external_members.as_slice()) else {
        return None;
    };
    (binding.completion() == &ResolutionCompletion::Complete).then_some(())?;
    let declaring_language = member.declaring_language?;
    brokk_bifrost_analysis::analyzer::languages::calls_external_declarations_of(
        caller,
        declaring_language,
    )
    .then_some(())?;
    Some(SelectedExternalCall {
        declaring_language,
        owner: member.identity.owner.owner_fqn.to_string(),
        member: member.member_name.clone(),
        is_static: member.is_static,
        parameter_count: member.callable_parameter_count?,
    })
}

/// Whether the focused reference is the callee of a Kotlin call: a bare
/// `name(...)`, the member of `receiver.name(...)`, or the member of a
/// property read `receiver.name`, which applies a Java getter exactly when
/// resolution selects one.
fn kotlin_focus_is_callee(query: BoundedReceiverQuery<'_>) -> bool {
    let Some(focus) = query.tree.and_then(|tree| {
        smallest_named_node_covering(
            tree.root_node(),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        )
    }) else {
        return false;
    };
    if syntax::kotlin_call_with_callee(focus).is_some() {
        return true;
    }
    focus
        .parent()
        .filter(|suffix| suffix.kind() == "navigation_suffix")
        .and_then(|suffix| suffix.parent())
        .filter(|navigation| {
            syntax::kotlin_navigation_member(*navigation).map(|member| member.id())
                == Some(focus.id())
        })
        .is_some_and(|navigation| {
            syntax::kotlin_call_with_callee(navigation).is_some()
                || syntax::kotlin_property_read_member(navigation).is_some()
        })
}

/// Whether the focused reference is the callee leaf of a Scala call: the
/// function of `f(...)`, the member of `x.m(...)`, the type of `new T(...)`, or
/// the operator of an infix or postfix application. The shared call-site
/// syntax names the callee leaf of each of these call nodes.
fn scala_focus_is_callee(query: BoundedReceiverQuery<'_>) -> bool {
    let Some(tree) = query.tree else {
        return false;
    };
    let Some(focus) = smallest_named_node_covering(
        tree.root_node(),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    ) else {
        return false;
    };
    let focus = brokk_bifrost_core::analyzer::usages::reference_site::node_range(focus);
    brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::exact_call_reference_for_reverse_site(
        tree,
        Language::Scala,
        &focus,
    )
    .is_some_and(|callee| (callee.start_byte, callee.end_byte) == (focus.start_byte, focus.end_byte))
}

// A whole Kotlin call expression asks for the value the call produces. The
// producer publishes no reference at the call's own range: the call value is
// the callee reference's `TargetCallableResultType` projection, so the point
// is focused on that callee. The reported site keeps the whole expression.
// This mirrors Go's whole-expression anchor selection in its native points.
fn kotlin_call_value_anchor(query: BoundedReceiverQuery<'_>) -> Option<ResolvedReferenceSite> {
    jvm_reference_anchor(query, |call| {
        if call.kind() != "call_expression"
            || call.start_byte() != query.site.focus_start_byte
            || call.end_byte() != query.site.focus_end_byte
        {
            return None;
        }
        let callee = syntax::kotlin_callee(call)?;
        match callee.kind() {
            "simple_identifier" => Some(callee),
            "navigation_expression" => syntax::kotlin_navigation_member(callee),
            _ => None,
        }
    })
}

// Languages select the reference-bearing node from the syntax around the
// requested focus. Keep the original display site while focusing the native
// locator on the reference published by the producer.
pub(crate) fn jvm_reference_anchor<'tree>(
    query: BoundedReceiverQuery<'tree>,
    select: impl FnOnce(tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>>,
) -> Option<ResolvedReferenceSite> {
    let selected = smallest_named_node_covering(
        query.tree?.root_node(),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    )?;
    let anchor = select(selected)?;
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

fn resolve_jvm_definition_answer_bounded<A: LanguageAdapter, T>(
    inner: &TreeSitterAnalyzer<A>,
    language: Language,
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
    project: impl FnOnce(&SelectedNativeReferenceUnits) -> T,
) -> BoundedResolution<(DefinitionLookupOutcome, Option<T>)> {
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
            value: (value, None),
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
    resolve_native_definition_answer_bounded(
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
        project,
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
///
/// The route must be proven for the question its site asks. A simple type
/// name's occurrence decision proves a type route; it does not reclassify an
/// ambiguous `N.member` prefix, where `N` may be a variable, field or member
/// type in scope (JLS 6.5.2 and the Kotlin and Scala name rules). Such a
/// prefix keeps its Incomplete answer until a prefix decision proves it.
/// A target makes the route a selected, complete boundary.
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
                        .resolve_qualified_name(
                            &crate::analyzer::jvm::external::QueryGapRecorder::new(kotlin),
                            target,
                            "",
                        )
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
                        brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                            &candidate.shard.manifest.language,
                        ) == "jvm"
                            && candidate.record.id == *declaration_id
                            && (!candidate
                                .shard
                                .independently_enumerates_jvm_owner(&candidate.record)
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
            match kotlin_external_member_target(kotlin, query, token, focus) {
                Some(KotlinReceiverOwner::Typed(target)) => {
                    Some((target.clone(), Some(target), ClaimSubjectRole::Member, None))
                }
                Some(KotlinReceiverOwner::Unproven(target)) => {
                    // External evidence declares the member, so the shared
                    // resolver has not proven it absent. The receiver is not
                    // proven to name its owner type either, so no boundary is
                    // claimed: the answer stays Incomplete until a prefix
                    // decision proves the receiver.
                    if value.status == DefinitionLookupStatus::NoDefinition {
                        value.status = DefinitionLookupStatus::Incomplete;
                        value.diagnostics.push(DefinitionLookupDiagnostic {
                            kind: "kotlin_external_member_prefix_unproven".to_owned(),
                            message: format!(
                                "`{target}` is declared outside the indexed workspace, but no \
                                 type-name decision proves the receiver names its owner"
                            ),
                            claim: None,
                        });
                    }
                    return BoundedResolution::Complete { value, work };
                }
                None => None,
            }
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
    } else if scala_external_member_route(scala, query, token, focus) {
        // The receiver `N` of `N.member` is a name in expression position: a
        // value, object, field or member type in scope can bind it before an
        // imported type does. No type-name decision proves that, so a
        // recognized external member route keeps the shared Incomplete answer
        // until a prefix decision proves `N` names the external type.
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

/// Whether the focus is the member route of a field expression whose
/// receiver spells an unindexed external type.
fn scala_external_member_route(
    scala: &crate::analyzer::scala::ScalaAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    focus: tree_sitter::Node<'_>,
) -> bool {
    let Some(access) = scala_member_access_for_focus(focus) else {
        return false;
    };
    let (Some(receiver), Some(member_node)) = (
        access.child_by_field_name("value"),
        access.child_by_field_name("field"),
    ) else {
        return false;
    };
    let owner_segments =
        brokk_bifrost_jvm::scala::supertypes::scala_type_lookup_segments(receiver, query.source);
    if owner_segments.is_empty()
        || !scala_unindexed_route_has_provider(scala, query, token, &owner_segments)
    {
        return false;
    }
    let owner = owner_segments.join(".");
    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Scala);
    let (_, owner_target) =
        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::boundary_evidence(
            query.analyzer,
            query.file,
            &owner,
        );
    !owner_target
        .as_ref()
        .is_some_and(|target| !definitions.fqn_in_any_language(target).is_empty())
        && query
            .source
            .get(member_node.start_byte()..member_node.end_byte())
            .is_some_and(|name| !name.trim().is_empty())
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
) -> Option<KotlinReceiverOwner> {
    let navigation = kotlin_navigation_for_member_focus(focus)?;
    let receiver = syntax::kotlin_navigation_receiver(navigation)?;
    let receiver_owner = match kotlin_receiver_owner(receiver, query.source)? {
        KotlinReceiverOwner::Unproven(name)
            if kotlin_receiver_names_explicit_import(kotlin, query, token, receiver, &name) =>
        {
            KotlinReceiverOwner::Typed(name)
        }
        owner => owner,
    };
    let owner = match &receiver_owner {
        KotlinReceiverOwner::Typed(owner) | KotlinReceiverOwner::Unproven(owner) => owner,
    };
    let definitions = AnalyzerDefinitionLookup::new(query.analyzer, Language::Kotlin);
    let (_, owner_target) = kotlin.external_boundary_evidence(
        token,
        query.analyzer.semantic_model_overlay(),
        query.file,
        owner,
    );
    if owner_target
        .as_ref()
        .is_some_and(|target| !definitions.fqn_in_any_language(target).is_empty())
    {
        return None;
    }
    if owner_target.is_none()
        && !kotlin_explicit_external_owner_import_exists(kotlin, query, token, &definitions, owner)
    {
        return None;
    }
    let member_node = syntax::kotlin_navigation_member(navigation)?;
    let member_name = kotlin_node_text(member_node, query.source)?;
    let spelling = format!("{owner}.{member_name}");
    let member = kotlin
        .resolve_member_name_with_external(
            token,
            query.analyzer.semantic_model_overlay(),
            query.file,
            &spelling,
        )?
        .fqn()
        .to_owned();
    Some(match receiver_owner {
        KotlinReceiverOwner::Typed(_) => KotlinReceiverOwner::Typed(member),
        KotlinReceiverOwner::Unproven(_) => KotlinReceiverOwner::Unproven(member),
    })
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

/// A Kotlin member receiver's owner spelling, or the member reached through
/// it, tagged with whether the receiver is proven to name that owner.
enum KotlinReceiverOwner {
    /// A local binding's declared or constructed type, an `as` cast's type,
    /// or an identifier that `kotlin_receiver_names_explicit_import` proves
    /// names an explicitly imported type.
    Typed(String),
    /// An identifier no local binding declares. In receiver position it may
    /// be a property, object, parameter or member type in scope as well as an
    /// imported type, and no type-name decision proves which. It can refute a
    /// proven absence but cannot select an external boundary. A dotted name
    /// supplies no owner at all.
    Unproven(String),
}

/// Whether the receiver identifier `name` of `name.member` is proven to name
/// the one type an explicit import binds to it.
///
/// Kotlin resolves a simple name through linked scopes, nearest first: local
/// declarations, then the members of implicit receivers (enclosing classes and
/// objects, extension and lambda receivers, a script), then the file's explicit
/// imports. Package members, star imports and default imports are weaker than
/// explicit imports (Kotlin specification, "Linked scopes"), so they cannot
/// take the name from an explicit import. The decision goes through the shared
/// tier evaluator: a nearer tier that is Open keeps the receiver Unproven.
///
/// The implicit-receiver tier is closed only where none exists. Enumerating a
/// class's or a receiver type's members is S3's prefix decision (#8675); until
/// it lands, any enclosing receiver context leaves that tier Open.
fn kotlin_receiver_names_explicit_import(
    kotlin: &crate::analyzer::kotlin::KotlinAnalyzer,
    query: BoundedReceiverQuery<'_>,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    receiver: tree_sitter::Node<'_>,
    name: &str,
) -> bool {
    use brokk_bifrost_analysis::analyzer::resolution::tier_evaluator::{
        ContributorClosure, TierContributor, TierDecision, TierInput, TierReceipt, evaluate_tiers,
    };

    let closed = |selected_read, candidates| TierContributor {
        candidates,
        closure: ContributorClosure::Closed(TierReceipt { selected_read }),
    };
    // `None` stands for a nearer declaration of the name, `Some` for the
    // import path an explicit import binds to it.
    let local = kotlin_local_binding(receiver, query.source, name).is_some()
        || kotlin_catch_parameter_binds(receiver, query.source, name);
    let implicit_receiver = if kotlin_implicit_receiver_context(query, receiver) {
        TierContributor {
            candidates: Vec::new(),
            closure: ContributorClosure::Open,
        }
    } else {
        closed("kotlin_implicit_receiver_context", Vec::new())
    };
    let mut imports = kotlin
        .tree_sitter_analyzer()
        .import_info_of(token, query.file)
        .iter()
        .filter(|import| !import.is_wildcard && import.local_name() == Some(name))
        .filter_map(|import| {
            import
                .path
                .as_ref()
                .map(|path| Some(path.segments.join(".")))
        })
        .collect::<Vec<_>>();
    imports.sort_unstable();
    imports.dedup();
    let tiers = [
        TierInput {
            rank: 0,
            contributors: vec![closed(
                "kotlin_local_bindings",
                if local { vec![None] } else { Vec::new() },
            )],
        },
        TierInput {
            rank: 1,
            contributors: vec![implicit_receiver],
        },
        TierInput {
            rank: 2,
            contributors: vec![closed("kotlin_explicit_imports", imports)],
        },
    ];
    let (_, decision) = evaluate_tiers(tiers, |_| {});
    matches!(
        decision,
        TierDecision::Unique {
            selected: Some(_),
            ..
        }
    )
}

/// Whether an enclosing `catch` clause binds `name` over `node`.
fn kotlin_catch_parameter_binds(node: tree_sitter::Node<'_>, source: &str, name: &str) -> bool {
    let mut current = node.parent();
    while let Some(scope) = current {
        if scope.kind() == "catch_block"
            && named_children(scope)
                .into_iter()
                .find(|child| child.kind() == "simple_identifier")
                .is_some_and(|binder| {
                    binder.end_byte() <= node.start_byte()
                        && kotlin_node_text(binder, source) == Some(name)
                })
        {
            return true;
        }
        current = scope.parent();
    }
    false
}

/// Whether `node` may sit under an implicit receiver whose members could bind
/// a simple name before the file's imports do. Any enclosing class, object,
/// lambda or anonymous function, an extension function or property, a script,
/// and a tree with parse errors (where a context-receiver list or a receiver
/// declaration could hide) all count.
fn kotlin_implicit_receiver_context(
    query: BoundedReceiverQuery<'_>,
    node: tree_sitter::Node<'_>,
) -> bool {
    if query
        .file
        .rel_path()
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("kts"))
    {
        return true;
    }
    let mut current = node.parent();
    while let Some(scope) = current {
        if scope.is_error() || (scope.has_error() && scope.parent().is_none()) {
            return true;
        }
        match scope.kind() {
            "class_declaration" | "object_declaration" | "companion_object" | "object_literal"
            | "class_body" | "enum_class_body" | "enum_entry" | "lambda_literal"
            | "annotated_lambda" | "anonymous_function" => return true,
            "function_declaration" | "property_declaration"
                if scope.child_by_field_name("receiver").is_some()
                    || named_children(scope)
                        .into_iter()
                        .filter(|child| child.kind() == "modifiers")
                        .flat_map(named_children)
                        .any(|modifier| modifier.kind() == "context_parameters") =>
            {
                return true;
            }
            _ => {}
        }
        current = scope.parent();
    }
    false
}

fn kotlin_receiver_owner(
    receiver: tree_sitter::Node<'_>,
    source: &str,
) -> Option<KotlinReceiverOwner> {
    let receiver = syntax::kotlin_unwrap_receiver(receiver);
    match receiver.kind() {
        "simple_identifier" => {
            let name = kotlin_node_text(receiver, source)?;
            let Some(binding) = kotlin_local_binding(receiver, source, name) else {
                return Some(KotlinReceiverOwner::Unproven(name.to_owned()));
            };
            if let Some(type_node) = syntax::kotlin_binding_type_node(binding) {
                return syntax::kotlin_type_spelling(type_node, source)
                    .map(KotlinReceiverOwner::Typed);
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
            kotlin_name_path(callee, source).map(KotlinReceiverOwner::Typed)
        }
        "as_expression" => {
            let type_node = named_children(receiver).into_iter().next_back()?;
            syntax::kotlin_type_spelling(type_node, source).map(KotlinReceiverOwner::Typed)
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
        let matched = qualified_model_symbols(&overlay, &route.target);
        if matches!(
            matched.disposition,
            brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(
                _
            )
        ) {
            return None;
        }
        let mut symbols = matched.records.into_iter();
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
        std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol>,
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
                let mut context = *context;
                let mut registered = std::collections::HashSet::new();
                for gap in &matching_gaps {
                    // The store checked equivalent provenance and closure for
                    // every repeated reason when it prepared this context.
                    if registered.insert(gap.reason) {
                        context =
                            context.with_additional_context_owned_inventory_reason(gap.reason);
                    }
                }
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
