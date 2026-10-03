//! Rust point and type consumers of the selected native operation.
//!
//! Source authority, canonical binding identity, and typed completion are
//! established inside the selected operation before public result projection.

use super::RustAnalyzer;
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::resolution::{
    FactResolutionAnswer, ResolutionBatchMetrics, ResolutionCompletion, ResolutionSlotValue,
    SelectedSemanticLocator, SemanticId,
};
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionLocated, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
    SelectedRustCallerReferenceOutcome, SelectedRustReferenceAnswer, SelectedRustSourceDefinition,
    SelectedRustSourceDefinitionProjection, SelectedRustTypeProjection,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, ClaimSubjectRole, DefinitionLookupDiagnostic, DefinitionLookupOutcome,
    DefinitionLookupStatus, UnindexedClaim,
};
use crate::analyzer::usages::get_type::projection_target_kind;
use crate::analyzer::usages::get_type::{
    TypeLookupDiagnostic, TypeLookupOutcome, TypeLookupStatus, TypeLookupType,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{CodeUnit, Language, resolve_analyzer};
use crate::path_utils::rel_path_string;
use brokk_bifrost_core::analyzer::resolution_facts::{BindingProjectionKind, ResolutionSiteKind};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "native_points/tests.rs"]
mod tests;

/// Adapt one selected native Rust reference into the definition lookup
/// vocabulary without consulting a legacy candidate or lexical resolver.
pub(crate) fn resolve_rust_definition_bounded(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    resolve_rust_definition_bounded_with_after_open(query, || {})
}

/// Variant used by stale/cancellation fixtures to observe the operation after
/// opening the selected snapshot but before reading the focused reference.
pub(crate) fn resolve_rust_definition_bounded_with_after_open(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(query.analyzer) else {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable for the selected native point operation",
        )
        .into_complete_resolution();
    };
    if !cancellation.is_cancelled() && !rust.inner.workspace_declaration_identities_authoritative()
    {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "native_identity_authority_unavailable",
            "selected Rust declaration identity inputs are not authoritative",
        )
        .into_complete_resolution();
    }

    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
    {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust point operation is unavailable: {reason:?}"),
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust point operation is stale: {reason:?}"),
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust point operation failed to open: {error}"),
            )
            .into_complete_resolution();
        }
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);

    let mut operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust point operation is unavailable: {reason:?}"),
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust point operation is stale: {reason:?}"),
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust point operation failed to open: {error}"),
            )
            .into_complete_resolution();
        }
    };
    after_open();

    let source_matches = rust
        .inner
        .source_matches_selected_native_content(query.file, query.source);
    if cancellation.is_cancelled() {
        return BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        };
    }
    if !source_matches {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "native_source_mismatch",
            "supplied Rust reference text is not backed by the admitted selected source",
        )
        .into_complete_resolution();
    }

    // Rust's wildcard token, inferred type, and unnamed import alias have no
    // declaration. The grammar represents the latter two as identifiers, so
    // inspect the focused AST token rather than asking the reference locator
    // for a fact the producer deliberately does not emit.
    if query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .is_some_and(|node| {
                node.kind() == "_"
                    || (matches!(node.kind(), "identifier" | "type_identifier")
                        && node.utf8_text(query.source.as_bytes()) == Ok("_"))
            })
    }) {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::NoDefinition,
            "rust_non_reference_syntax",
            "the focused Rust wildcard, inferred type, or unnamed alias has no declaration",
        )
        .into_complete_resolution();
    }

    // An explicit crate anchor is syntax, not a reference to a declaration.
    // The producer deliberately omits its binder demand: no scope exports a
    // declaration named by this keyword. Preserve the focused token instead
    // of looking up the terminal of the containing path or reporting a
    // missing fact. This also applies inside macro token trees.
    if query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .is_some_and(|node| node.kind() == "crate")
    }) {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::NoDefinition,
            "crate_anchor",
            "the focused crate anchor has no source declaration",
        )
        .into_complete_resolution();
    }

    // Relative module anchors in a macro transcriber belong to the invocation
    // module. The definition-site token alone does not select an expansion,
    // so resolving it against the containing source module would invent a
    // target. Inspect the original AST, before any template-path projection.
    if query.tree.is_some_and(|tree| {
        let Some(node) = tree
            .root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
        else {
            return false;
        };
        if !matches!(node.kind(), "self" | "super") {
            return false;
        }
        let mut ancestor = node.parent();
        while let Some(parent) = ancestor {
            if parent.kind() == "macro_rule" {
                return parent.child_by_field_name("right").is_some_and(|body| {
                    body.start_byte() <= node.start_byte() && node.end_byte() <= body.end_byte()
                });
            }
            ancestor = parent.parent();
        }
        false
    }) {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Incomplete,
            "macro_expansion_context_required",
            "the relative module anchor in this macro template requires an invocation context",
        )
        .into_complete_resolution();
    }

    // A Rust lifetime names a binder introduced by a generic parameter list, a
    // `for<..>` clause or an impl header, and no analyzer publishes such a
    // binder as a CodeUnit. The producer emits neither a name nor a reference
    // site for one on purpose (`brokk_bifrost_rust::resolution`,
    // `lifetimes_do_not_hide_classified_value_and_type_references`), so the
    // point route has to decide this token instead of reporting the absent
    // fact: every lifetime was answering `unavailable`, which the census
    // grades as inconclusive rather than as the local binding it is. The
    // grammar keeps the tick and the name inside one `lifetime` node, so read
    // the retained AST rather than the source text.
    if query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .is_some_and(|node| {
                node.kind() == "lifetime"
                    || node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "lifetime")
            })
    }) {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::NoDefinition,
            crate::analyzer::usages::get_definition::LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
            "the focused Rust lifetime is a local binder, not a reference to a declaration",
        )
        .into_complete_resolution();
    }

    // Declaration self-navigation and body references need the same selected
    // activation as ordinary endpoint resolution. Read the retained AST, never
    // interpret source text or assume a host in the producer.
    if let Some(node) = query.tree.and_then(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
    }) {
        let condition =
            brokk_bifrost_rust::lexical_scope::rust_effective_cfg_condition(node, query.source);
        if condition != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always {
            use brokk_bifrost_rust::selected_context::RustSelectedActivation;
            match operation.rust_cfg_activation_for_caller(
                query.file.rel_path(),
                &condition,
                &cancellation,
            ) {
                Ok(Some(RustSelectedActivation::Active)) => {}
                Ok(Some(RustSelectedActivation::Inactive)) => {
                    return complete_definition(
                        query.site,
                        DefinitionLookupStatus::NoDefinition,
                        "inactive_cfg",
                        "the selected Rust cfg predicate is refuted",
                    )
                    .into_complete_resolution();
                }
                Ok(Some(RustSelectedActivation::Unknown)) => {
                    return complete_definition(
                        query.site,
                        DefinitionLookupStatus::Incomplete,
                        "unknown_activation",
                        "the selected Rust cfg predicate contains an undecidable atom",
                    )
                    .into_complete_resolution();
                }
                Ok(None) => {
                    return BoundedResolution::Cancelled {
                        work: ReceiverAnalysisWork::default(),
                    };
                }
                Err(error) => {
                    return complete_definition(
                        query.site,
                        DefinitionLookupStatus::Unavailable,
                        "native_store_error",
                        format!("selected Rust cfg lookup failed: {error}"),
                    )
                    .into_complete_resolution();
                }
            }
        }
    }

    let macro_invocation = query.tree.and_then(|tree| {
        let token = tree
            .root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)?;
        brokk_bifrost_rust::macro_matcher::enclosing_macro_invocation_for_argument(token)
    });
    let macro_binding = if let Some(invocation) = macro_invocation {
        let local = brokk_bifrost_rust::macro_matcher::match_local_macro_invocation(
            invocation,
            query.source,
        );
        let matched = if local.is_some() {
            local
        } else if let Some(head) = invocation.child_by_field_name("macro")
            && head.kind() == "identifier"
            && let Some(arguments) = invocation.child_by_field_name("token_tree").or_else(|| {
                let mut cursor = invocation.walk();
                invocation
                    .named_children(&mut cursor)
                    .find(|node| node.kind() == "token_tree")
            })
        {
            match operation.match_selected_textual_macro(
                query.file.rel_path(),
                invocation.start_byte(),
                arguments.start_byte(),
                &query.source[head.byte_range()],
                &cancellation,
            ) {
                Ok(matched) => matched,
                Err(error) => {
                    return complete_definition(
                        query.site,
                        DefinitionLookupStatus::Unavailable,
                        "native_store_error",
                        format!("selected macro replay failed: {error}"),
                    )
                    .into_complete_resolution();
                }
            }
        } else {
            None
        };
        Some(matched)
    } else {
        None
    };
    let mut matcher_diagnostic = None;
    if let Some(matched) = macro_binding {
        use brokk_bifrost_rust::macro_matcher::{
            MacroMatchError, MacroNamespaceEvidence, classify_fragment_interior,
            token_namespace_evidence,
        };
        match matched {
            Some(Err(MacroMatchError::NoArmMatched)) => {
                return complete_definition(
                    query.site,
                    DefinitionLookupStatus::NoDefinition,
                    "macro_matcher_failed",
                    "no arm in the visible macro definition matches the invocation",
                )
                .into_complete_resolution();
            }
            Some(Ok(arm)) => {
                let start = query.site.focus_start_byte;
                let end = query.site.focus_end_byte;
                match token_namespace_evidence(&arm, start, end) {
                    // The matcher bound the focused token to a declaration
                    // position. The token denotes itself; that is an answer,
                    // and the whole selection is irrelevant to it.
                    Some(MacroNamespaceEvidence::Declaration) => {
                        return complete_definition(
                            query.site,
                            DefinitionLookupStatus::NoDefinition,
                            crate::analyzer::usages::get_definition::MACRO_MATCHER_DECLARATION_DIAGNOSTIC_KIND,
                            "the matched token binds a declaration position, so it denotes itself",
                        )
                        .into_complete_resolution();
                    }
                    // `tt`, `meta`, `vis`, `lifetime`, `literal`, or an `ident`
                    // whose transcriber role is mixed, unused or undetermined
                    // (`macro_matcher.rs:287-305`). The matcher is saying it
                    // does not know which namespace the token is in, and a
                    // `tt` group can hold a path. That is an incompleteness,
                    // never a proved absence.
                    Some(MacroNamespaceEvidence::NoNamespace) => {
                        return complete_definition(
                            query.site,
                            DefinitionLookupStatus::Incomplete,
                            crate::analyzer::usages::get_definition::MACRO_FRAGMENT_NO_NAMESPACE_DIAGNOSTIC_KIND,
                            "the matched macro fragment carries no namespace, so the token's reference role is undecided",
                        )
                        .into_complete_resolution();
                    }
                    // The matcher bound the token inside a parsed fragment.
                    // Which namespace it is in is the fragment's own syntax to
                    // answer, so classify it there rather than treating the
                    // whole interior as undecided: a declaration name inside an
                    // `item` fragment denotes itself and is not a forward
                    // reference to anything.
                    Some(MacroNamespaceEvidence::Interior(fragment)) => {
                        let binding = arm
                            .binding_containing(start, end)
                            .expect("interior evidence comes from a containing binding");
                        let interior = classify_fragment_interior(
                            fragment,
                            &query.source[binding.start_byte..binding.end_byte],
                            start - binding.start_byte,
                            end - binding.start_byte,
                        );
                        if interior == Some(MacroNamespaceEvidence::Declaration) {
                            return complete_definition(
                                query.site,
                                DefinitionLookupStatus::NoDefinition,
                                crate::analyzer::usages::get_definition::MACRO_MATCHER_DECLARATION_DIAGNOSTIC_KIND,
                                "the matched token binds a declaration position, so it denotes itself",
                            )
                            .into_complete_resolution();
                        }
                    }
                    _ => {}
                }
                matcher_diagnostic =
                    arm.binding_containing(start, end)
                        .map(|binding| DefinitionLookupDiagnostic {
                            claim: None,
                            kind: "macro_matcher_binding".to_owned(),
                            message: format!(
                                "arm={} fragment={}",
                                arm.arm_index,
                                binding.fragment.as_str()
                            ),
                        });
            }
            // No visible `macro_rules!` matches this invocation's head. That
            // is a fact about the macro, not about the focused token: a
            // definition-less macro's token tree is enumerated as expression
            // fragments and lowered by the ordinary walk, so the token has
            // ordinary reference sites. Fall through to them. Only a group
            // the enumeration could not lower keeps a macro gap, and it keeps
            // it as the producer's own gap rather than as an early return
            // that claims the whole workspace does not contain the name.
            None => {}
            Some(Err(_)) => {}
        }
    }

    // Declaration identifiers denote themselves, even when there is no
    // reference row at the focused range. The selected lookup serves both
    // persisted source bridges and transient native declaration facts.
    let declaration = operation.rust_declaration_at_range_bounded(
        &SelectedSemanticLocator::for_declaration_range(
            "rust",
            rel_path_string(query.file),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        ),
        query.budget,
        &cancellation,
    );
    match declaration {
        Ok(None) => {}
        Ok(Some(result)) => {
            return match result {
                BoundedResolution::Exceeded { limit, work } => {
                    BoundedResolution::Exceeded { limit, work }
                }
                BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
                BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                    value: adapt_declaration_value(query.site, value),
                    work,
                },
            };
        }
        Err(error) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust declaration lookup failed: {error}"),
            )
            .into_complete_resolution();
        }
    }

    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        rel_path_string(query.file),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    );
    // Asked before the operation is consumed, and only for a path head, the
    // one shape `claim_external_route_head` reads it for.
    let (head_names_macro_module, head_workspace_crate) = if focused_route_head(&query) {
        match operation
            .rust_reference_names_macro_module(&locator, &cancellation)
            .and_then(|macro_module| {
                Ok((
                    macro_module,
                    operation.rust_reference_names_workspace_crate(&locator, &cancellation)?,
                ))
            }) {
            Ok(names) => names,
            Err(error) => {
                return complete_definition(
                    query.site,
                    DefinitionLookupStatus::Unavailable,
                    "native_store_error",
                    format!("selected Rust route head read failed: {error}"),
                )
                .into_complete_resolution();
            }
        }
    } else {
        (false, None)
    };
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut point_metrics = ResolutionBatchMetrics::default();
    let result = operation.resolve_rust_reference_for_caller_bounded(
        query.file.rel_path(),
        &locator,
        query.budget,
        &cancellation,
        &mut context_metrics,
        &mut point_metrics,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust point operation failed: {error}"),
            )
            .into_complete_resolution();
        }
    };

    match result {
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        BoundedResolution::Complete { value, work } => {
            let mut outcome = adapt_definition_value(&query, value);
            outcome.diagnostics.extend(matcher_diagnostic);
            name_unresolved_receiver_owner(query.tree, query.source, query.site, &mut outcome);
            claim_external_route_head(
                &mut outcome,
                &query,
                head_names_macro_module,
                head_workspace_crate.as_deref(),
            );
            if cancellation.is_cancelled() {
                BoundedResolution::Cancelled { work }
            } else {
                BoundedResolution::Complete {
                    value: outcome,
                    work,
                }
            }
        }
    }
}

/// Name the owner type a `self.member` read reached when the member did not
/// resolve to any indexed declaration.
///
/// `impl Mystery { fn poll(&self) { self.inner ... } }`, where `Mystery` is
/// declared nowhere the workspace indexes, leaves the receiver's type
/// unresolved. The generic "no source-backed definition" wording then names
/// neither the owner the read tried nor a next query, which is the dead end
/// #1019 reported. The enclosing `impl` still writes its self type, so the
/// diagnostic reads it from that `impl_item`'s own `type` field and names a
/// concrete retry. The answer itself does not change: the member really has no
/// indexed definition.
fn name_unresolved_receiver_owner(
    tree: Option<&tree_sitter::Tree>,
    source: &str,
    site: &crate::analyzer::usages::get_definition::ResolvedReferenceSite,
    outcome: &mut DefinitionLookupOutcome,
) {
    if outcome.status != DefinitionLookupStatus::NoDefinition {
        return;
    }
    let Some(node) = tree.and_then(|tree| {
        tree.root_node()
            .descendant_for_byte_range(site.focus_start_byte, site.focus_end_byte)
    }) else {
        return;
    };
    let member_of_self_receiver = node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(node)
            && parent
                .child_by_field_name("value")
                .is_some_and(|receiver| receiver.kind() == "self")
    });
    if !member_of_self_receiver {
        return;
    }
    let Some(owner) = enclosing_impl_self_type_name(node, source) else {
        return;
    };
    let member = &source[node.byte_range()];
    for diagnostic in &mut outcome.diagnostics {
        if diagnostic.kind == "no_indexed_definition" {
            diagnostic.message = format!(
                "`{member}` looks like a member of `{owner}`, but `{owner}` has no indexed Rust \
                 declaration; try get_symbol_sources with \"{owner}.{member}\" or search_symbols \
                 for \"{member}\""
            );
        }
    }
}

/// The name the nearest enclosing `impl` writes for its self type, read from
/// the `impl_item`'s `type` field and its own structured children. An `impl`
/// whose self type is not a named path (a reference, a tuple, `dyn Trait`)
/// names no owner and yields `None`.
fn enclosing_impl_self_type_name<'source>(
    node: tree_sitter::Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let mut current = node.parent()?;
    let mut self_type = loop {
        if current.kind() == "impl_item" {
            break current.child_by_field_name("type")?;
        }
        current = current.parent()?;
    };
    loop {
        match self_type.kind() {
            "generic_type" => self_type = self_type.child_by_field_name("type")?,
            "scoped_type_identifier" => self_type = self_type.child_by_field_name("name")?,
            "type_identifier" => return Some(&source[self_type.byte_range()]),
            _ => return None,
        }
    }
}

/// A path's first segment that names no module this workspace compiles has
/// left the workspace, and that is a boundary rather than a decided negative
/// (owner decision, 2026-09-17).
///
/// The crate route already says this for the demand it resolves: both copies
/// of the guard, in `rust_crate_context` and in `rust_demand/rows`, claim
/// `ExternalDeclaredUnindexed` when a route head matches no module. A caret on
/// the head itself never reaches them. That segment has its own lexical Type
/// reference, issued by `brokk_bifrost_rust::resolution`'s
/// `add_root_reference_route` for exactly this shape, and resolving it asks a
/// lexical question only, so the demand provider is never entered, nothing
/// claims the boundary, and the empty selection answers `no_definition`.
/// Navigating to `serde_json` in `serde_json::to_string_pretty`, and to the
/// original spelling of a Cargo-renamed dependency, both landed there.
///
/// The claim is made only where the route itself would make it: the focused
/// token is the first segment of a multi-segment path, it is not one of the
/// explicit module anchors, and the selection finished having found no
/// definition at all. A head the workspace does compile resolves and never
/// reaches here.
///
/// A head that names a module the crate declares for an item macro in the
/// reference's own module is not such a boundary: the module is compiled, and
/// the head finds nothing only because a crate-declared module has no lexical
/// binder. That answer is incomplete, not a boundary.
///
/// A head that names a workspace crate, by its extern name or through an alias
/// of its root (`use forc_pkg::{self as pkg};`), is not one either: the crate
/// is compiled, and the head finds nothing only because a crate root has no
/// declaration. The answer stays `no_definition` and says the head is a crate
/// namespace in this workspace (#1089).
fn claim_external_route_head(
    outcome: &mut DefinitionLookupOutcome,
    query: &BoundedReceiverQuery<'_>,
    head_names_macro_module: bool,
    head_workspace_crate: Option<&str>,
) {
    if outcome.status != DefinitionLookupStatus::NoDefinition
        || !outcome.definitions.is_empty()
        || outcome.lexical_definition.is_some()
        || !focused_route_head(query)
    {
        return;
    }
    outcome.diagnostics.retain(|diagnostic| {
        diagnostic.kind
            != crate::analyzer::usages::get_definition::RUST_NO_INDEXED_DEFINITION_DIAGNOSTIC_KIND
    });
    if let Some(crate_name) = head_workspace_crate {
        let head = &query.source[query.site.focus_start_byte..query.site.focus_end_byte];
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: crate::analyzer::usages::get_definition::RUST_WORKSPACE_CRATE_NAMESPACE_DIAGNOSTIC_KIND
                .to_owned(),
            message: format!(
                "`{head}` names the Rust crate `{crate_name}` in this workspace; a crate root is a \
                 namespace, not a single indexed declaration"
            ),
        });
        return;
    }
    if head_names_macro_module {
        outcome.status = DefinitionLookupStatus::Incomplete;
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "incomplete_binding".to_owned(),
            message: "the focused Rust path head names a module an item macro declares in this \
                      module; a path head is bound lexically, and a macro-declared module has no \
                      lexical binder"
                .to_owned(),
        });
        return;
    }
    outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        claim: None,
        kind:
            crate::analyzer::usages::get_definition::RUST_UNINDEXED_IMPORT_BOUNDARY_DIAGNOSTIC_KIND
                .to_owned(),
        message: "the focused Rust path head names no module this workspace compiles".to_owned(),
    });
}

/// Whether the focused token is the first segment of a multi-segment path and
/// not one of the explicit module anchors. The head of a grouped `use`
/// (`pkg` in `use pkg::{A, B};`) is the `path` of its `scoped_use_list`.
fn focused_route_head(query: &BoundedReceiverQuery<'_>) -> bool {
    query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .and_then(|token| Some((token, token.parent()?)))
            .is_some_and(|(token, path)| {
                matches!(
                    path.kind(),
                    "scoped_identifier" | "scoped_type_identifier" | "scoped_use_list"
                ) && path.child_by_field_name("path").map(|head| head.id()) == Some(token.id())
                    && !matches!(token.kind(), "crate" | "self" | "super" | "metavariable")
            })
    })
}

fn adapt_declaration_value(
    site: &crate::analyzer::usages::get_definition::ResolvedReferenceSite,
    value: SelectedResolutionOperationOutcome<SelectedRustSourceDefinitionProjection>,
) -> DefinitionLookupOutcome {
    let rows = match value {
        SelectedResolutionOperationOutcome::Native(
            SelectedRustSourceDefinitionProjection::Complete(rows),
        ) => rows,
        SelectedResolutionOperationOutcome::Native(
            SelectedRustSourceDefinitionProjection::Cancelled,
        )
        | SelectedResolutionOperationOutcome::Cancelled(_) => {
            return complete_definition(
                site,
                DefinitionLookupStatus::Incomplete,
                "native_cancelled",
                "selected Rust declaration lookup was cancelled",
            )
            .0;
        }
        SelectedResolutionOperationOutcome::Native(
            SelectedRustSourceDefinitionProjection::Unavailable,
        ) => {
            return complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_definition_projection_unavailable",
                "selected Rust declaration has no source projection",
            )
            .0;
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust declaration lookup is unavailable: {reason:?}"),
            )
            .0;
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust declaration lookup is stale: {reason:?}"),
            )
            .0;
        }
    };
    let mut definitions = Vec::new();
    let mut lexical = Vec::new();
    let mut withdrawn = 0usize;
    for (_, definition) in rows {
        match definition {
            SelectedRustSourceDefinition::Unit(unit) => definitions.push(unit),
            SelectedRustSourceDefinition::Lexical(row) => lexical.push(row),
            // The parser published neither a `CodeUnit` nor a lexical binder
            // for this declaration, so neither vocabulary has a row to carry
            // it. `WithoutUnit` is one alternative's own answer, so it
            // withdraws that alternative and the point answers from the rest.
            // Refusing the whole point for it threw away the alternatives that
            // did project, which is what the reverse batch used to do too.
            SelectedRustSourceDefinition::WithoutUnit { .. } => withdrawn += 1,
        }
    }
    definitions.sort_unstable();
    definitions.dedup();
    lexical.dedup();
    // Every alternative withdrew itself, so the point has no source-backed
    // answer to publish and says so once, for the whole point.
    if definitions.is_empty() && lexical.is_empty() {
        assert!(
            withdrawn > 0,
            "a complete Rust declaration projection publishes at least one alternative"
        );
        return complete_definition(
            site,
            DefinitionLookupStatus::Unavailable,
            "native_definition_projection_unavailable",
            "selected Rust declaration has no source projection",
        )
        .0;
    }
    let status = if definitions.len() + lexical.len() == 1 {
        DefinitionLookupStatus::Resolved
    } else {
        DefinitionLookupStatus::Ambiguous
    };
    let outcome = DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: None,
        definitions,
        lexical_definition: (lexical.len() == 1).then(|| lexical.remove(0)),
        diagnostics: Vec::new(),
    };
    crate::analyzer::usages::get_definition::trace::record_selected_units(&outcome);
    crate::analyzer::usages::get_definition::trace::record_selected_lexical(&outcome);
    outcome
}

/// Adapt one selected native Rust type projection into the type lookup
/// vocabulary. Type exactness is decided by the selected typed frontiers, not
/// by binding completion or by the order in which slots happen to be stored.
pub(crate) fn resolve_rust_type_bounded(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<TypeLookupOutcome> {
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(query.analyzer) else {
        return complete_type(
            query.site,
            TypeLookupStatus::Unavailable,
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable for the selected native type operation",
            TypeLookupTargetKind::ValueExpression,
        )
        .into_complete_resolution();
    };
    if !cancellation.is_cancelled() && !rust.inner.workspace_declaration_identities_authoritative()
    {
        return complete_type(
            query.site,
            TypeLookupStatus::Unavailable,
            "native_identity_authority_unavailable",
            "selected Rust declaration identity inputs are not authoritative",
            TypeLookupTargetKind::ValueExpression,
        )
        .into_complete_resolution();
    }

    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
    {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust type operation is unavailable: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust type operation is stale: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust type operation failed to open: {error}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust type operation is unavailable: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust type operation is stale: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust type operation failed to open: {error}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
    };

    let source_matches = rust
        .inner
        .source_matches_selected_native_content(query.file, query.source);
    if cancellation.is_cancelled() {
        return BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        };
    }
    if !source_matches {
        return complete_type(
            query.site,
            TypeLookupStatus::Unavailable,
            "native_source_mismatch",
            "supplied Rust reference text is not backed by the admitted selected source",
            TypeLookupTargetKind::ValueExpression,
        )
        .into_complete_resolution();
    }

    // A type answer cannot escape the activation of its enclosing source body.
    if let Some(node) = query.tree.and_then(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
    }) {
        let condition =
            brokk_bifrost_rust::lexical_scope::rust_effective_cfg_condition(node, query.source);
        if condition != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always {
            use brokk_bifrost_rust::selected_context::RustSelectedActivation;
            match operation.rust_cfg_activation_for_caller(
                query.file.rel_path(),
                &condition,
                &cancellation,
            ) {
                Ok(Some(RustSelectedActivation::Active)) => {}
                Ok(Some(RustSelectedActivation::Inactive)) => {
                    return complete_type(
                        query.site,
                        TypeLookupStatus::NoType,
                        "inactive_cfg",
                        "the selected Rust cfg predicate is refuted",
                        TypeLookupTargetKind::ValueExpression,
                    )
                    .into_complete_resolution();
                }
                Ok(Some(RustSelectedActivation::Unknown)) => {
                    return complete_type(
                        query.site,
                        TypeLookupStatus::Incomplete,
                        "unknown_activation",
                        "the selected Rust cfg predicate contains an undecidable atom",
                        TypeLookupTargetKind::ValueExpression,
                    )
                    .into_complete_resolution();
                }
                Ok(None) => {
                    return BoundedResolution::Cancelled {
                        work: ReceiverAnalysisWork::default(),
                    };
                }
                Err(error) => {
                    return complete_type(
                        query.site,
                        TypeLookupStatus::Unavailable,
                        "native_store_error",
                        format!("selected Rust cfg lookup failed: {error}"),
                        TypeLookupTargetKind::ValueExpression,
                    )
                    .into_complete_resolution();
                }
            }
        }
    }

    let expression = query
        .tree
        .and_then(|tree| {
            tree.root_node()
                .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
        })
        .map(brokk_bifrost_rust::structural::rust_receiver_operand);
    let name = expression.and_then(brokk_bifrost_rust::structural::expression_name_node);
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        rel_path_string(query.file),
        name.map_or(query.site.focus_start_byte, |name| name.start_byte()),
        name.map_or(query.site.focus_end_byte, |name| name.end_byte()),
    );
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut point_metrics = ResolutionBatchMetrics::default();
    let result = operation.resolve_rust_type_for_caller_bounded(
        query.file.rel_path(),
        &locator,
        query.budget,
        &cancellation,
        &mut context_metrics,
        &mut point_metrics,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust type operation failed: {error}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
    };

    match result {
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        BoundedResolution::Complete { value, work } => {
            let mut value = adapt_type_value(query, rust, value);
            if expression
                .is_some_and(|node| matches!(node.kind(), "call_expression" | "struct_expression"))
            {
                value.target_kind = TypeLookupTargetKind::ValueExpression;
            }
            BoundedResolution::Complete { value, work }
        }
    }
}

fn adapt_definition_value(
    query: &BoundedReceiverQuery<'_>,
    value: SelectedRustCallerReferenceOutcome,
) -> DefinitionLookupOutcome {
    let site = query.site;
    match value {
        SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile => complete_definition(
            site,
            DefinitionLookupStatus::Unavailable,
            "unsupported_caller_profile",
            "the selected Rust caller profile is not supported by native resolution",
        )
        .into_complete_value(),
        SelectedRustCallerReferenceOutcome::Operation(outcome) => match outcome {
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                complete_definition(
                    site,
                    DefinitionLookupStatus::Unavailable,
                    "native_reference_missing",
                    "the structured Rust reference site is absent from selected native facts",
                )
                .into_complete_value()
            }
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) => {
                let modeled = modeled_macro_definitions(query, &answer);
                let mut outcome = adapt_definition_answer(site, answer);
                match modeled {
                    Ok(definitions) if !definitions.is_empty() => {
                        outcome.status =
                            if definitions.len() == 1 && !definitions[0].provenance.ambiguous {
                                DefinitionLookupStatus::Resolved
                            } else {
                                DefinitionLookupStatus::Ambiguous
                            };
                        outcome
                            .diagnostics
                            .retain(|diagnostic| diagnostic.kind != "incomplete_binding");
                        outcome.modeled_definitions = definitions;
                        crate::analyzer::usages::get_definition::trace::record_selected_modeled(
                            &outcome,
                        );
                    }
                    Ok(_) => {}
                    Err(error) => outcome.diagnostics.push(DefinitionLookupDiagnostic {
                        claim: None,
                        kind: "rust_generated_route_unavailable".to_owned(),
                        message: format!("Rust generated declaration route failed: {error:?}"),
                    }),
                }
                outcome
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust point operation is unavailable: {reason:?}"),
            )
            .into_complete_value(),
            SelectedResolutionOperationOutcome::Stale(reason) => complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust point operation is stale: {reason:?}"),
            )
            .into_complete_value(),
            SelectedResolutionOperationOutcome::Cancelled(_) => complete_definition(
                site,
                DefinitionLookupStatus::Cancelled,
                "cancelled",
                "selected Rust point operation was cancelled",
            )
            .into_complete_value(),
        },
    }
}

/// No binding, producer projection, or transfer-owned identity was examined.
/// A lexical negative can legitimately have this shape; an observed type
/// frontier, including an abstract one, cannot.
fn reference_answer_has_no_candidate(resolution: &FactResolutionAnswer) -> bool {
    resolution.binding().targets().is_empty()
        && matches!(
            resolution.binding().completion(),
            ResolutionCompletion::Complete
        )
        && resolution.projections().is_empty()
        && resolution.observed_type_identity().is_none()
}

/// An unqualified type occurrence without any observed identity is not a
/// proved lexical absence. Complete transfer observations are exposed separately
/// from binding projections and do not take this abstention path.
fn definition_answer_abstains(resolution: &FactResolutionAnswer) -> bool {
    reference_answer_has_no_candidate(resolution)
        && resolution.site_metadata().is_some_and(|metadata| {
            metadata.site_kind() == ResolutionSiteKind::TypeReference && metadata.unqualified()
        })
}

/// Name every reason one selected binding is incomplete, for a public
/// diagnostic.
///
/// The site used to format `{completion:?}`, so each reason printed a
/// `SemanticId` as a 32-byte array and the message named no gap at all. A
/// reason kind is what a reader can act on, so each reason is rendered by its
/// kind, with the boundary status for an open boundary and the semantic's own
/// hex identity for every kind that names one. `ResolutionIncompleteReason::kind`
/// panics for the three operation-local reasons, so the match is written out
/// rather than delegated to it.
///
/// A semantic that is one of the binding's own targets is named beside its hex
/// identity, from the `(SemanticId, definition)` pairing the answer keeps.
/// Every other semantic prints as hex alone: the only others this route names
/// with source text are the macro-generated-module gaps, and those are already
/// published beside this diagnostic as `UnsupportedMacroGeneratedModule`.
fn describe_incomplete_binding(
    completion: &ResolutionCompletion,
    names: &std::collections::BTreeMap<SemanticId, String>,
) -> String {
    use crate::analyzer::resolution::ResolutionIncompleteReason as Reason;
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        unreachable!("an incomplete binding diagnostic requires an incomplete completion")
    };
    let named = |semantic: &SemanticId| match names.get(semantic) {
        Some(name) => format!("{semantic}, {name}"),
        None => format!("{semantic}"),
    };
    let mut described = Vec::with_capacity(reasons.len());
    for reason in reasons.iter() {
        described.push(match reason {
            Reason::Cancelled => "cancelled".to_owned(),
            Reason::CyclicExpansion(path) => format!("cyclic_expansion({path})"),
            Reason::CyclicPrefixDependency(semantic) => {
                format!("cyclic_prefix_dependency({})", named(semantic))
            }
            Reason::InconsistentPrecedence(semantic) => {
                format!("inconsistent_precedence({})", named(semantic))
            }
            Reason::OpenBoundary { semantic, status } => {
                format!("open_boundary({}, {})", status.label(), named(semantic))
            }
            Reason::UnsupportedSemantic(semantic) => {
                format!("unsupported_semantic({})", named(semantic))
            }
            Reason::ReceiverBudgetExhausted(semantic) => {
                format!("receiver_budget_exhausted({})", named(semantic))
            }
            Reason::TimeBudgetExceeded(semantic) => {
                format!("time_budget_exceeded({})", named(semantic))
            }
            Reason::UnmountedFile { fragment } => format!("unmounted_file({fragment})"),
        });
    }
    described.join(", ")
}

/// Stage the member attribution the selected operation recorded, so the
/// candidate rows the trace publishes carry the owner the resolver found the
/// member on instead of no attribution at all.
///
/// Only targets the member lookup itself selected have a row. An associated
/// call that resolves through the scoped-owner path names no owner and is
/// deliberately left unattributed: absence is the correct report, and a depth
/// of zero would be a claim the resolver never made.
fn stage_rust_member_attribution(answers: &[SelectedRustReferenceAnswer]) {
    use crate::analyzer::store::resolution_operation::SelectedRustMemberReach;
    use crate::analyzer::structural::{HierarchyRelation, MemberDispatchTier};
    use crate::analyzer::usages::get_definition::trace::{HierarchyHopRecord, MemberEnrichment};
    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

    let staged = answers
        .iter()
        .flat_map(|answer| {
            answer.member_attributions.iter().filter_map(|attribution| {
                let name = answer
                    .definition_names
                    .iter()
                    .find(|(semantic, _)| *semantic == attribution.target)
                    .map(|(_, name)| name.clone())?;
                let (hierarchy_depth, dispatch_tier, route) = match &attribution.reach {
                    SelectedRustMemberReach::Direct {
                        declared_by_trait_implementation,
                    } => (
                        0,
                        if *declared_by_trait_implementation {
                            MemberDispatchTier::TraitOrInterface
                        } else {
                            MemberDispatchTier::InherentOrDirect
                        },
                        Vec::new(),
                    ),
                    SelectedRustMemberReach::Hierarchy {
                        owner_path,
                        implementation_hop,
                    } => (
                        owner_path.len() - 1,
                        MemberDispatchTier::TraitOrInterface,
                        owner_path
                            .windows(2)
                            .enumerate()
                            .map(|(hop, pair)| HierarchyHopRecord {
                                hop,
                                from: pair[0].clone(),
                                to: pair[1].clone(),
                                relation: if hop == 0 && *implementation_hop {
                                    HierarchyRelation::TraitImpl
                                } else {
                                    HierarchyRelation::Supertype
                                },
                            })
                            .collect(),
                    ),
                };
                Some((
                    name,
                    MemberEnrichment {
                        owner: attribution.owner.clone(),
                        hierarchy_depth,
                        dispatch_tier,
                        // The Rust member seam checks the member's namespace
                        // and nothing about the call shape, so the
                        // applicability axis is untested here.
                        applicability: ApplicabilityVerdict::Unknown,
                        route,
                    },
                ))
            })
        })
        .collect::<Vec<_>>();
    if staged.is_empty() {
        return;
    }
    crate::analyzer::usages::get_definition::trace::stage_member_context(staged);
}

/// An explicit modeled declaration can account for the exact invocation
/// that blocked binding. Every remaining reason and every selected Cargo view
/// must be covered; an unrelated macro or native candidate remains incomplete.
fn modeled_macro_definitions(
    query: &BoundedReceiverQuery<'_>,
    answers: &[SelectedRustReferenceAnswer],
) -> Result<
    Vec<crate::analyzer::semantic_model::SemanticModelSymbol>,
    brokk_bifrost_rust::graph_support::RustCargoRouteError,
> {
    use crate::analyzer::resolution::ResolutionIncompleteReason;
    use crate::analyzer::semantic_model::SemanticModelLocation;
    if answers.is_empty()
        || answers.iter().any(|answer| {
            !answer.resolution.binding().targets().is_empty()
                || !answer.definitions.is_empty()
                || !answer.lexical_definitions.is_empty()
                || !matches!(answer.resolution.binding().completion(),
                ResolutionCompletion::Incomplete(reasons) if reasons.iter().all(|reason| {
                    matches!(reason, ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                        if answer.macro_expansion_gaps.iter().any(|gap| gap.semantic == *semantic))
                }))
        })
    {
        return Ok(Vec::new());
    }
    let Some(overlay) = query.analyzer.semantic_model_overlay() else {
        return Ok(Vec::new());
    };
    let records = super::generated_model::resolve_generated_functions(
        query.analyzer,
        &overlay,
        query.file,
        query.site,
    )?;
    let gaps = answers
        .iter()
        .flat_map(|answer| &answer.macro_expansion_gaps)
        .collect::<Vec<_>>();
    let covers = |symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
                  gap: &crate::analyzer::store::resolution_operation::SelectedRustMacroExpansionGap| {
        matches!(&symbol.location, SemanticModelLocation::Authored(anchor)
            if anchor.path == gap.relative_path
                && gap.start_byte <= anchor.range.start_byte
                && anchor.range.end_byte <= gap.end_byte)
    };
    if gaps.is_empty()
        || gaps
            .iter()
            .any(|gap| !records.iter().any(|symbol| covers(symbol, gap)))
        || records
            .iter()
            .any(|symbol| !gaps.iter().any(|gap| covers(symbol, gap)))
    {
        return Ok(Vec::new());
    }
    Ok(records.into_iter().cloned().collect())
}

fn adapt_definition_answer(
    site: &crate::analyzer::usages::get_definition::ResolvedReferenceSite,
    answers: Vec<SelectedRustReferenceAnswer>,
) -> DefinitionLookupOutcome {
    let canonical_targets = answers
        .iter()
        .flat_map(|answer| answer.resolution.binding().targets().iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    let completion = answers
        .iter()
        .fold(ResolutionCompletion::Complete, |completion, answer| {
            completion.combine(answer.resolution.binding().completion())
        });
    let definition_names = answers
        .iter()
        .flat_map(|answer| answer.definition_names.iter().cloned())
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut inventory_details = answers
        .iter()
        .flat_map(|answer| answer.inventory_details.iter().cloned())
        .collect::<Vec<_>>();
    inventory_details.sort_unstable();
    inventory_details.dedup();
    let mut named_reasons = answers
        .iter()
        .flat_map(|answer| answer.named_reasons.iter().cloned())
        .collect::<Vec<_>>();
    named_reasons.sort_unstable();
    named_reasons.dedup();
    let mut boundary_import_names = answers
        .iter()
        .flat_map(|answer| answer.boundary_import_names.iter().cloned())
        .collect::<Vec<_>>();
    boundary_import_names.sort_unstable();
    boundary_import_names.dedup();
    stage_rust_member_attribution(&answers);
    let mut definitions = Vec::new();
    let mut lexical = Vec::new();
    let mut examined_answers = 0usize;
    for answer in answers {
        if !definition_answer_abstains(&answer.resolution) {
            examined_answers += 1;
        }
        definitions.extend(answer.definitions);
        lexical.extend(answer.lexical_definitions);
    }
    definitions.sort_unstable();
    definitions.dedup();
    lexical.sort_by(|left, right| {
        left.identifier
            .cmp(&right.identifier)
            .then_with(|| {
                left.declaration_range
                    .start_byte
                    .cmp(&right.declaration_range.start_byte)
            })
            .then_with(|| {
                left.declaration_range
                    .end_byte
                    .cmp(&right.declaration_range.end_byte)
            })
    });
    lexical.dedup();
    // One open inventory can be open for more than one reason (an undecided
    // item macro, a withheld declaration); each reason its evidence names is
    // one diagnostic kind, carrying the whole detail.
    let mut diagnostics = inventory_details
        .into_iter()
        .flat_map(|detail| {
            let parsed: serde_json::Value =
                serde_json::from_str(&detail).expect("an open inventory detail is JSON");
            let mut reasons = parsed["evidence"]
                .as_array()
                .expect("an open inventory detail lists its evidence")
                .iter()
                .map(|evidence| {
                    evidence["reason"]
                        .as_str()
                        .expect("open inventory evidence names its reason")
                        .to_owned()
                })
                .collect::<Vec<_>>();
            reasons.sort_unstable();
            reasons.dedup();
            reasons
                .into_iter()
                .map(move |kind| DefinitionLookupDiagnostic {
                    claim: None,
                    kind,
                    message: detail.clone(),
                })
        })
        .chain(
            named_reasons
                .into_iter()
                .map(|(name, evidence)| DefinitionLookupDiagnostic {
                    claim: None,
                    kind: name.to_owned(),
                    message: evidence,
                }),
        )
        .collect::<Vec<_>>();
    if lexical.len() > 1 {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_lexical_definition".to_owned(),
            message: format!(
                "selected Rust binding has multiple lexical definitions; no winner was selected: {lexical:?}"
            ),
        });
    }
    // A reference that reached a block-local item names it, although the item
    // has no parser unit; see `rust_block_local_binding_is_decided`.
    let binding_complete = matches!(completion, ResolutionCompletion::Complete)
        || crate::analyzer::store::resolution_operation::rust_block_local_binding_is_decided(
            &definitions,
            &lexical,
            &completion,
        );
    let lexical_count = lexical.len();
    let lexical_definition = (lexical_count == 1).then(|| lexical.remove(0));
    // Display CodeUnits can compare equal for distinct source declarations.
    // Deduplicate aliases by canonical target identity, before projecting that
    // identity into the public presentation vocabulary.
    let canonical_target_count = canonical_targets.len();
    // An answer whose only incompleteness is that the language orders none of
    // its candidates is an ambiguity with a named cause, not a missing fact:
    // every candidate is a declaration the reference may name, and nothing is
    // unseen. Rust's E0034 is this shape.
    let unordered_candidates = canonical_target_count > 1
        && matches!(&completion, ResolutionCompletion::Incomplete(reasons)
        if reasons.iter().all(|reason| matches!(
            reason,
            crate::analyzer::resolution::ResolutionIncompleteReason::InconsistentPrecedence(_)
        )));
    let external_boundary = canonical_target_count == 0
        && lexical_definition.is_none()
        && matches!(&completion, ResolutionCompletion::Incomplete(reasons)
        if reasons.iter().all(|reason| matches!(reason,
            crate::analyzer::resolution::ResolutionIncompleteReason::OpenBoundary {
                status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                ..
            }
        )));
    let status = if external_boundary {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: (!boundary_import_names.is_empty()).then(|| {
                UnindexedClaim::external_boundary_many(boundary_import_names, ClaimSubjectRole::Any)
            }),
            kind: "unindexed_import_boundary".to_owned(),
            message: format!("selected Rust binding reaches an unindexed import: {completion:?}"),
        });
        DefinitionLookupStatus::UnresolvableImportBoundary
    } else if unordered_candidates {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "unordered_candidates".to_owned(),
            message: format!(
                "the language orders none of these candidates over the others (for Rust trait items, rustc E0034: multiple applicable items in scope): {:?}; {}",
                definitions.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
                describe_incomplete_binding(&completion, &definition_names)
            ),
        });
        DefinitionLookupStatus::Ambiguous
    } else if !binding_complete {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "incomplete_binding".to_owned(),
            message: format!(
                "selected Rust binding is incomplete: {}",
                describe_incomplete_binding(&completion, &definition_names)
            ),
        });
        DefinitionLookupStatus::Incomplete
    } else if canonical_target_count > 1 {
        DefinitionLookupStatus::Ambiguous
    } else if definitions.is_empty() {
        if lexical_definition.is_some() {
            DefinitionLookupStatus::Resolved
        } else if examined_answers == 0 {
            // No selected alternative exposed a binding or type observation.
            // Do not turn unexamined type syntax into a proved absence.
            diagnostics.push(DefinitionLookupDiagnostic {
                claim: None,
                kind: "unprojected_type_frontier".to_owned(),
                message: "selected Rust reference carries no binding candidate, so its definition frontier was not examined".to_owned(),
            });
            DefinitionLookupStatus::Incomplete
        } else {
            diagnostics.push(DefinitionLookupDiagnostic {
                claim: None,
                kind: "no_indexed_definition".to_owned(),
                message: "the selected Rust binding has no source-backed definition".to_owned(),
            });
            DefinitionLookupStatus::NoDefinition
        }
    } else if definitions.len() == 1 && lexical_definition.is_none() {
        DefinitionLookupStatus::Resolved
    } else if definitions.len() == 1 && lexical_definition.is_some() {
        DefinitionLookupStatus::Ambiguous
    } else {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_definition".to_owned(),
            message: "selected Rust binding resolved to multiple workspace definitions".to_owned(),
        });
        DefinitionLookupStatus::Ambiguous
    };
    if status == DefinitionLookupStatus::Ambiguous
        && !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "ambiguous_definition")
        && definitions.len() > 1
    {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_definition".to_owned(),
            message: "selected Rust binding resolved to multiple workspace definitions".to_owned(),
        });
    }
    let outcome = DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: Some(site.clone()),
        definitions,
        lexical_definition,
        diagnostics,
    };
    crate::analyzer::usages::get_definition::trace::record_selected_units(&outcome);
    // A lexical binding is the answer, so the trace has to carry it as the
    // selection. The shared lexical constructor records this row for every
    // other language; the selected Rust operation builds its own outcome and
    // reached the trace with no selected candidate at all, which let a
    // consumer read a complete trace whose only row was a rejected peer.
    if outcome.status == DefinitionLookupStatus::Resolved {
        crate::analyzer::usages::get_definition::trace::record_selected_lexical(&outcome);
    }
    outcome
}

fn adapt_type_value(
    query: BoundedReceiverQuery<'_>,
    rust: &RustAnalyzer,
    value: SelectedRustCallerReferenceOutcome<SelectedRustTypeProjection>,
) -> TypeLookupOutcome {
    let site = query.site;
    match value {
        SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile => complete_type(
            site,
            TypeLookupStatus::Unavailable,
            "unsupported_caller_profile",
            "the selected Rust caller profile is not supported by native resolution",
            TypeLookupTargetKind::ValueExpression,
        )
        .into_complete_value(),
        SelectedRustCallerReferenceOutcome::Operation(outcome) => match outcome {
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                complete_type(
                    site,
                    TypeLookupStatus::Unavailable,
                    "native_reference_missing",
                    "the structured Rust reference site is absent from selected native facts",
                    TypeLookupTargetKind::ValueExpression,
                )
                .into_complete_value()
            }
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) => adapt_type_answer(query, rust, answer),
            SelectedResolutionOperationOutcome::Unavailable(reason) => complete_type(
                site,
                TypeLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust type operation is unavailable: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_value(),
            SelectedResolutionOperationOutcome::Stale(reason) => complete_type(
                site,
                TypeLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust type operation is stale: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_value(),
            SelectedResolutionOperationOutcome::Cancelled(_) => complete_type(
                site,
                TypeLookupStatus::Cancelled,
                "cancelled",
                "selected Rust type operation was cancelled",
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_value(),
        },
    }
}

fn adapt_type_answer(
    query: BoundedReceiverQuery<'_>,
    rust: &RustAnalyzer,
    answers: Vec<SelectedRustReferenceAnswer<SelectedRustTypeProjection>>,
) -> TypeLookupOutcome {
    let site = query.site;
    let local_declaration = match answers.as_slice() {
        [answer] if answer.definitions.is_empty() => match answer.lexical_definitions.as_slice() {
            [definition] => Some(definition.clone()),
            _ => None,
        },
        _ => None,
    };
    let mut diagnostics = Vec::new();
    let mut canonical_types = BTreeMap::<(SemanticId, u32), (String, Vec<CodeUnit>)>::new();
    let mut typed_complete = true;
    let mut target_kind = None;
    let mut projected_answers = 0usize;
    for answer in &answers {
        if reference_answer_has_no_candidate(&answer.resolution) {
            continue;
        }
        // A member-owner projection names the declaration whose members a
        // literal writes, not the type of the expression that writes them:
        // `Enum::Variant { .. }` has type `Enum` and writes `Variant`'s
        // fields. The owner path carries distinct projection outputs on one
        // occurrence, so a type query reads the type frontier and leaves the
        // member-owner frontier to the field lookup that asked for it.
        if answer.resolution.observed_type_identity().is_none()
            && !answer.resolution.projections().is_empty()
            && answer
                .resolution
                .projections()
                .iter()
                .all(|projection| projection.kind() == BindingProjectionKind::TargetMemberOwnerType)
        {
            continue;
        }
        projected_answers += 1;
        let observed_identity = answer.resolution.observed_type_identity();
        let (alternative_kind, selected_projection_kind, projection_kinds) =
            if observed_identity.is_some() {
                (
                    TypeLookupTargetKind::TypeReference,
                    Some(BindingProjectionKind::TargetTypeIdentity),
                    vec![BindingProjectionKind::TargetTypeIdentity],
                )
            } else {
                projection_target_kind(answer.resolution.projections())
            };
        target_kind = Some(match target_kind {
            Some(existing) if existing != alternative_kind => TypeLookupTargetKind::ValueExpression,
            _ => alternative_kind,
        });
        let mut selected_frontier_count = 0usize;
        if answer.resolution.projections().is_empty() && observed_identity.is_none() {
            typed_complete = false;
            diagnostics.push(TypeLookupDiagnostic {
                kind: "missing_type_projection".to_owned(),
                message: "selected Rust reference has no typed projection metadata".to_owned(),
            });
        }
        if !matches!(
            answer.resolution.binding().completion(),
            ResolutionCompletion::Complete
        ) {
            typed_complete = false;
            diagnostics.push(TypeLookupDiagnostic {
                kind: "incomplete_binding".to_owned(),
                message: "selected Rust binding is incomplete; its type is not exact".to_owned(),
            });
        }
        let output_slots = answer
            .resolution
            .projections()
            .iter()
            .filter(|projection| Some(projection.kind()) == selected_projection_kind)
            .map(|projection| projection.output_slot())
            .chain(observed_identity);
        for output_slot in output_slots {
            let Some(frontier) = answer
                .resolution
                .projected_frontiers()
                .iter()
                .find(|frontier| frontier.slot() == output_slot)
            else {
                typed_complete = false;
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "missing_typed_frontier".to_owned(),
                    message: format!(
                        "selected Rust projection {:?} has no output frontier",
                        selected_projection_kind
                    ),
                });
                continue;
            };
            selected_frontier_count += 1;
            if !matches!(frontier.completion(), ResolutionCompletion::Complete) {
                typed_complete = false;
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "incomplete_typed_frontier".to_owned(),
                    message: format!(
                        "selected Rust type frontier is incomplete: {:?}",
                        frontier.completion()
                    ),
                });
            }
            for value in frontier.possible_values() {
                let identity = value.ty().identity();
                if let Some(descriptor) = answer
                    .projection
                    .intrinsic_types
                    .iter()
                    .find(|descriptor| descriptor.identity() == identity)
                {
                    let fqn = render_type_spelling(descriptor.spelling(), *value, &mut diagnostics);
                    canonical_types
                        .entry((identity, value.ty().indirection()))
                        .or_insert((fqn, Vec::new()));
                    continue;
                }
                let Some(source_definition) = answer
                    .projection
                    .nominal_types
                    .iter()
                    .find(|(candidate, _)| *candidate == identity)
                    .map(|(_, definition)| definition)
                else {
                    typed_complete = false;
                    diagnostics.push(TypeLookupDiagnostic {
                        kind: "missing_nominal_type_definition".to_owned(),
                        message: format!(
                            "selected Rust type identity {identity:?} has no source definition"
                        ),
                    });
                    continue;
                };
                match source_definition {
                    SelectedRustSourceDefinition::Unit(unit) => {
                        let fqn = render_type_spelling(&unit.fq_name(), *value, &mut diagnostics);
                        canonical_types
                            .entry((identity, value.ty().indirection()))
                            .or_insert_with(|| (fqn, Vec::new()))
                            .1
                            .push(unit.clone());
                    }
                    SelectedRustSourceDefinition::Lexical(definition) => {
                        typed_complete = false;
                        diagnostics.push(TypeLookupDiagnostic {
                        kind: "unsupported_lexical_type_definition".to_owned(),
                        message: format!(
                            "selected Rust type identity has lexical source evidence but no nominal CodeUnit: {definition:?}"
                        ),
                    });
                    }
                    SelectedRustSourceDefinition::WithoutUnit {
                        source_file,
                        declaration_range,
                    } => {
                        typed_complete = false;
                        diagnostics.push(TypeLookupDiagnostic {
                            kind: "unsupported_unit_less_type_definition".to_owned(),
                            message: format!(
                                "selected Rust type identity is declared where the parser published no CodeUnit: {source_file:?} {declaration_range:?}"
                            ),
                        });
                    }
                }
            }
        }
        if selected_frontier_count == 0 && !answer.resolution.projections().is_empty() {
            typed_complete = false;
        }
        if projection_kinds.len() > 1 {
            diagnostics.push(TypeLookupDiagnostic {
            kind: "ambiguous_type_projection_kind".to_owned(),
            message: format!(
                "selected Rust reference has projection kinds {projection_kinds:?}; only {selected_projection_kind:?} was projected"
            ),
        });
        }
    }
    let canonical_type_count = canonical_types.len();
    let canonical_keys = canonical_types.keys().copied().collect::<Vec<_>>();
    let mut types = BTreeMap::<String, Vec<CodeUnit>>::new();
    for (fqn, definitions) in canonical_types.into_values() {
        types.entry(fqn).or_default().extend(definitions);
    }
    for definitions in types.values_mut() {
        definitions.sort_unstable();
        definitions.dedup();
    }
    let mut types = types
        .into_iter()
        .map(|(fqn, definitions)| TypeLookupType {
            fqn,
            definitions,
            semantic_model_id: None,
        })
        .collect::<Vec<_>>();
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_mut_reference_qualifier")
    {
        typed_complete = false;
    }
    let status = if !typed_complete {
        TypeLookupStatus::Incomplete
    } else if projected_answers == 0 {
        // No selected alternative exposed a type producer or observation.
        diagnostics.push(TypeLookupDiagnostic {
            kind: "unprojected_type_frontier".to_owned(),
            message: "selected Rust reference carries no typed projection, so its type frontier was not examined".to_owned(),
        });
        TypeLookupStatus::Incomplete
    } else if types.is_empty() {
        // The type frontier was examined and named nothing. Say so: the status
        // alone cannot tell a proved absence from a route that never looked,
        // and the decided-negative guard reads the kind, not the status.
        diagnostics.push(TypeLookupDiagnostic {
            kind: crate::analyzer::usages::get_definition::RUST_NO_TYPED_PROJECTION_DIAGNOSTIC_KIND
                .to_owned(),
            message: "the selected Rust type frontier was complete and named no type".to_owned(),
        });
        TypeLookupStatus::NoType
    } else if canonical_type_count == 1 {
        TypeLookupStatus::Resolved
    } else {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "ambiguous_type".to_owned(),
            message: format!(
                "selected Rust typed projections retain multiple canonical types: keys={canonical_keys:?}, displayed={:?}",
                types.iter().map(|ty| &ty.fqn).collect::<Vec<_>>()
            ),
        });
        TypeLookupStatus::Ambiguous
    };
    if status == TypeLookupStatus::Resolved
        && let [candidate] = types.as_mut_slice()
        && let Some(definition) = local_declaration.as_ref()
        && let Some(alias_fqn) = rust_local_type_alias_display_fqn(query, rust, definition)
    {
        // Keep the written local alias as the type's display name while the
        // candidate definitions retain the canonical target used by member
        // resolution.
        candidate.fqn = alias_fqn;
    }
    TypeLookupOutcome {
        status,
        reference: Some(site.clone()),
        types,
        diagnostics,
        target_kind: target_kind.unwrap_or(TypeLookupTargetKind::ValueExpression),
    }
}

fn rust_local_type_alias_display_fqn(
    query: BoundedReceiverQuery<'_>,
    rust: &RustAnalyzer,
    definition: &crate::analyzer::lexical_definitions::LexicalDefinition,
) -> Option<String> {
    assert!(
        definition
            .source_file
            .as_ref()
            .is_none_or(|file| file == query.file),
        "local Rust binding belongs to another source file: {:?}",
        definition.source_file
    );
    let tree = query.tree?;
    let range = &definition.declaration_range;
    let mut declaration = tree
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
    while !matches!(
        declaration.kind(),
        "let_declaration" | "parameter" | "closure_parameter"
    ) {
        declaration = declaration.parent()?;
    }
    let alias_type = declaration.child_by_field_name("type")?;
    if !matches!(
        alias_type.kind(),
        "type_identifier" | "scoped_type_identifier" | "scoped_identifier"
    ) {
        return None;
    }
    let site = crate::analyzer::usages::reference_site::resolve_reference_site(
        &crate::analyzer::usages::reference_site::SourceLocationRequest {
            file: query.file.clone(),
            line: None,
            column: None,
            start_byte: Some(alias_type.start_byte()),
            end_byte: Some(alias_type.end_byte()),
        },
        query.source,
        Some(tree.root_node()),
    )
    .ok()?;
    let resolution = resolve_rust_definition_bounded(BoundedReceiverQuery {
        site: &site,
        ..query
    });
    let BoundedResolution::Complete { value, .. } = resolution else {
        return None;
    };
    let [alias] = value.definitions.as_slice() else {
        return None;
    };
    (value.status == DefinitionLookupStatus::Resolved && rust.is_type_alias(alias))
        .then(|| alias.fq_name().to_owned())
}

fn render_type_spelling(
    spelling: &str,
    value: ResolutionSlotValue,
    diagnostics: &mut Vec<TypeLookupDiagnostic>,
) -> String {
    let indirection = value.ty().indirection() as usize;
    if matches!(
        value,
        ResolutionSlotValue::Runtime {
            addressable: true,
            ..
        }
    ) && indirection > 0
    {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "unsupported_mut_reference_qualifier".to_owned(),
            message: format!(
                "selected Rust typed value retains mutable reference evidence for `{spelling}`; the public type projection cannot encode `&mut` exactly"
            ),
        });
    }
    format!("{}{}", "&".repeat(indirection), spelling)
}

struct CompleteOutcome<T>(T);

impl<T> CompleteOutcome<T> {
    fn into_complete_value(self) -> T {
        self.0
    }

    fn into_complete_resolution(self) -> BoundedResolution<T> {
        BoundedResolution::Complete {
            value: self.0,
            work: ReceiverAnalysisWork::default(),
        }
    }
}

fn complete_definition(
    site: &crate::analyzer::usages::get_definition::ResolvedReferenceSite,
    status: DefinitionLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
) -> CompleteOutcome<DefinitionLookupOutcome> {
    CompleteOutcome(DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: Some(site.clone()),
        definitions: Vec::new(),
        lexical_definition: None,
        diagnostics: vec![DefinitionLookupDiagnostic {
            claim: None,
            kind: kind.into(),
            message: message.into(),
        }],
    })
}

fn complete_type(
    site: &crate::analyzer::usages::get_definition::ResolvedReferenceSite,
    status: TypeLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
    target_kind: TypeLookupTargetKind,
) -> CompleteOutcome<TypeLookupOutcome> {
    CompleteOutcome(TypeLookupOutcome {
        status,
        reference: Some(site.clone()),
        types: Vec::new(),
        diagnostics: vec![TypeLookupDiagnostic {
            kind: kind.into(),
            message: message.into(),
        }],
        target_kind,
    })
}
