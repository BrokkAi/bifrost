//! Projection of one native selected Go model receiver, shared by point,
//! outgoing, and semantic dispatch. This adapter never infers a receiver.
use crate::analyzer::go::GoAnalyzer;
use crate::analyzer::usages::get_definition::go::{
    AnalyzerGoDefinitionProvider, go_selected_receiver_argument_shape,
};
use brokk_bifrost_analysis::analyzer::QueryScope;
use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
use brokk_bifrost_analysis::analyzer::semantic::{
    DeferredMemberSelection, MemberReceiverPreparation, ResolverOwnedExternalCalleeIdentity,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeModelMemberSelection;
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    DefinitionLookupDiagnostic, DefinitionLookupOutcome, DefinitionLookupStatus,
    ExactExternalCallProof,
};
use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, Language, resolve_analyzer};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

pub(crate) struct GoSelectedModelReceiverCall {
    pub outcome: DefinitionLookupOutcome,
    pub proof: Option<ExactExternalCallProof>,
    pub identity: Option<ResolverOwnedExternalCalleeIdentity>,
    pub interface: bool,
    pub preparation: Option<MemberReceiverPreparation>,
    pub reasons: Vec<String>,
}

/// Standalone navigation has no semantic place IDs. Retain that absence;
/// native candidate types may prove depth, but syntax alone never does.
pub(crate) fn transient_selection(
    query: BoundedReceiverQuery<'_>,
    selection: &ProjectedNativeModelMemberSelection,
) -> Option<DeferredMemberSelection> {
    let tree = query.tree?;
    let descriptor =
        brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)?;
    let member = descriptor.focused_node();
    let candidates = selection
        .candidates
        .iter()
        .filter(|candidate| candidate.selected && !candidate.rejected)
        .collect::<Vec<_>>();
    Some(DeferredMemberSelection {
        member: query.source.get(member.byte_range())?.into(),
        receiver_place: None,
        receiver_pointer_depth: match candidates.as_slice() {
            [candidate] if candidate.receiver_route_proven => {
                Some(candidate.receiver_pointer_depth)
            }
            _ => None,
        },
    })
}

pub(crate) enum GoModelReceiverSelection {
    NotModel,
    Handled(Box<GoSelectedModelReceiverCall>),
}

/// A handled open or empty model answer never re-enters legacy inference.
pub(crate) fn go_selected_model_receiver_call(
    query: BoundedReceiverQuery<'_>,
    selection: Option<&ProjectedNativeModelMemberSelection>,
    descriptor: &DeferredMemberSelection,
    session: &ResolutionSession,
) -> GoModelReceiverSelection {
    let Some(selection) = selection else {
        return GoModelReceiverSelection::NotModel;
    };
    let mut result = GoSelectedModelReceiverCall {
        outcome: DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status: if selection.native_target_count > 1 {
                DefinitionLookupStatus::Ambiguous
            } else {
                DefinitionLookupStatus::Incomplete
            },
            reference: Some(query.site.clone()),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        },
        proof: None,
        identity: None,
        interface: false,
        preparation: None,
        reasons: Vec::new(),
    };
    let candidates = selection
        .candidates
        .iter()
        .filter(|candidate| candidate.selected && !candidate.rejected)
        .collect::<Vec<_>>();
    let [candidate] = candidates.as_slice() else {
        result
            .reasons
            .push("go-model-receiver-selection-open".into());
        result.outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "go-model-receiver-selection-open".into(),
            message: "native model receiver selection is missing, rejected, or ambiguous".into(),
            claim: None,
        });
        return GoModelReceiverSelection::Handled(Box::new(result));
    };
    let canonical = format!(
        "{}.{}",
        candidate.owner.owner_fqn, candidate.declaration.name
    );
    if selection.native_target_count == 1 {
        result.outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    }
    result
        .outcome
        .reference
        .as_mut()
        .expect("selected site")
        .text = canonical.clone();
    result.interface = candidate.interface;
    let complete = candidate.complete;
    let runtime = candidate.receiver_runtime;
    let pointer = candidate.receiver_pointer_depth;
    let matches_hint = !candidate.receiver_route_proven
        || descriptor
            .receiver_pointer_depth
            .is_none_or(|hint| hint == pointer);
    let matches_member = descriptor.member.as_ref() == candidate.declaration.name;
    let shape = query.tree.and_then(|tree| {
        let selector =
            brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), query.site)?;
        let member = selector.focused_node();
        let callable = member.parent()?;
        if callable.kind() != "selector_expression" {
            return None;
        }
        let go = resolve_analyzer::<GoAnalyzer>(query.analyzer)?;
        let scope = AnalyzerQueryScope::new(query.analyzer);
        let support = AnalyzerGoDefinitionProvider::bounded(
            go,
            session,
            query.analyzer.semantic_model_overlay(),
        );
        go_selected_receiver_argument_shape(
            &support,
            scope.token(),
            go,
            query.file,
            query.source,
            callable,
        )
    });
    let applicable_shape = shape.filter(|(count, spread)| {
        let Some(signature) = candidate.declaration.structured_signature.as_ref() else {
            return false;
        };
        let variadic = signature
            .parameters
            .last()
            .is_some_and(|parameter| parameter.variadic);
        if *spread {
            variadic && *count == signature.parameters.len()
        } else {
            let minimum = signature
                .parameters
                .iter()
                .filter(|parameter| !parameter.optional && !parameter.variadic)
                .count();
            *count >= minimum && (variadic || *count <= signature.parameters.len())
        }
    });
    let declared_receiver = candidate
        .declaration
        .receiver
        .map(|receiver| receiver.pointer);
    let receiver_applicable = candidate.interface
        || declared_receiver.is_some_and(|declared| {
            !declared
                || pointer == 1
                || (pointer == 0 && candidate.receiver_addressable == Some(true))
        });
    let declared = selection.native_target_count == 1
        && runtime
        && pointer <= 1
        && matches_hint
        && matches_member
        && receiver_applicable
        && candidate.receiver_proven
        && candidate.route_exact;
    let proven = declared && (candidate.selection_complete || candidate.interface) && complete;
    if let Some((count, _)) =
        applicable_shape.filter(|_| selection.native_target_count == 1 && runtime && matches_member)
    {
        let count = u32::try_from(count).expect("bounded Go call arity fits u32");
        // Go models have no durable member inventory ordinal. These
        // constructors intentionally leave external_member_identity None;
        // the canonical declaring owner, call shape and provenance travel
        // together instead of fabricating a JVM inventory coordinate.
        // Declared owner/member identity and argument shape remain usable
        // when import openness withholds exhaustive invocation proof.
        if declared && !candidate.interface {
            result.identity = Some(ResolverOwnedExternalCalleeIdentity::new(
                Language::Go,
                candidate.owner.owner_fqn.to_string(),
                candidate.declaration.name.clone(),
            ));
        }
        result.proof = Some(if proven && candidate.interface {
            ExactExternalCallProof::go_interface_receiver(canonical.clone(), count)
        } else if proven {
            ExactExternalCallProof::go_concrete_receiver(canonical.clone(), count)
        } else {
            ExactExternalCallProof::go_receiver_candidate(canonical.clone(), count)
        });
    }
    result
        .reasons
        .extend(candidate.incomplete_reasons.iter().cloned());
    if !candidate.route_exact {
        result
            .reasons
            .push("go-model-members-not-depth-exact".into());
    }
    if !proven || applicable_shape.is_none() {
        result
            .reasons
            .push("go-model-receiver-applicability-unproven".into());
    }
    if !candidate.receiver_route_proven {
        result
            .reasons
            .push("go-model-promoted-receiver-storage-unavailable".into());
    } else if proven && !candidate.interface {
        // This is the language binding kind, not a fabricated memory place.
        // Shared MemberReceiverFlow requires the descriptor's real place for
        // AddressOfPlace and withholds the storage route when it is absent.
        result.preparation = declared_receiver.and_then(|declared| {
            super::go_method_receiver_preparation(
                declared,
                pointer == 1,
                candidate.receiver_addressable == Some(true),
            )
        });
    }
    if candidate.interface {
        result
            .reasons
            .push("go-model-interface-implementation-family-open".into());
    }
    result.outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "unresolvable_import_boundary".into(),
        message: format!("`{canonical}` is declared by the selected external Go model"),
        claim: None,
    });
    for reason in &result.reasons {
        result.outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: reason.clone(),
            message: format!("{reason}: selected declaring member `{canonical}`"),
            claim: None,
        });
    }
    GoModelReceiverSelection::Handled(Box::new(result))
}

/// Static membership shares the native receiver operation with modeled calls;
/// the caller supplies its already completed type and addressability category.
pub(crate) fn go_selected_static_type_member(
    request: &mut super::native_points::GoNativePointRequest<'_>,
    query: BoundedReceiverQuery<'_>,
    receiver: brokk_bifrost_analysis::analyzer::resolution::ResolutionTypeRef,
    member_name: &str,
    receiver_addressable: bool,
) -> brokk_bifrost_analysis::analyzer::store::Result<brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<Option<brokk_bifrost_analysis::analyzer::store::resolution_operation::go_receiver_anchor::GoStaticTypeMember>>>{
    request.go_static_type_member(query, receiver, member_name, receiver_addressable)
}
