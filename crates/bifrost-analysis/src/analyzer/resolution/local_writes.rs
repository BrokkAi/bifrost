//! Attach structured writes through the native lexical graph before publishing
//! typed rows. All temporary indexes below belong to this one file publication.

use std::borrow::Cow;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    DeclarationTypeRole, FileResolutionFacts, ResolutionBinderKind, ResolutionGapFact,
    ResolutionGapKind, ResolutionIdentifierRole, ResolutionNamespace, ResolutionSiteId,
    ResolutionSiteKind, ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
};

use crate::hash::{HashMap, HashSet};

use super::batch::BatchResolutionEngine;
use super::engine::{PreloadedFragmentSource, ResolutionQuery};
use super::fact_lowering::{
    LoweredCandidateDirection, LoweredCoverageGap, LoweredResolutionFragment, LoweredSemanticRole,
    LoweringCoverageFrontier, LoweringGapOrigin, gap_reason_semantic_identity,
};
use super::local_identity::ResolutionIdentityCatalogBuilder;
use super::model::{BindingNodeId, ResolutionCompletion};

pub(super) fn attach_local_writes<'facts>(
    facts: &'facts FileResolutionFacts,
    lexical: &LoweredResolutionFragment,
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
) -> Cow<'facts, FileResolutionFacts> {
    if facts.local_writes.is_empty()
        && !facts
            .binding_events
            .iter()
            .any(|event| event.value.is_some())
    {
        return Cow::Borrowed(facts);
    }

    let identifiers = facts
        .identifiers
        .iter()
        .map(|identifier| (identifier.site, identifier))
        .collect::<HashMap<_, _>>();
    let sites = facts
        .sites
        .iter()
        .map(|site| (site.id, site))
        .collect::<HashMap<_, _>>();
    let slots = facts
        .type_slots
        .iter()
        .map(|slot| (slot.id, *slot))
        .collect::<HashMap<_, _>>();
    let references = lexical
        .semantics()
        .iter()
        .filter(|site| site.role() == LoweredSemanticRole::Reference)
        .map(|site| (site.site(), *site))
        .collect::<HashMap<_, _>>();
    let definitions = lexical
        .semantics()
        .iter()
        .filter(|site| site.role() == LoweredSemanticRole::Definition)
        .map(|site| (site.semantic(), site.site()))
        .collect::<HashMap<_, _>>();
    let binders = facts
        .binders
        .iter()
        .map(|binder| (binder.declaration, binder.kind))
        .collect::<HashMap<_, _>>();
    let named_labels = facts
        .named_argument_labels
        .iter()
        .map(|label| label.reference)
        .collect::<HashSet<_>>();
    for write in &facts.local_writes {
        assert_eq!(
            sites
                .get(&write.target)
                .expect("local write target must be positioned")
                .kind,
            ResolutionSiteKind::ValueReference,
            "a local write target must be a bare value reference"
        );
        let identifier = identifiers
            .get(&write.target)
            .expect("local write target must be an existing positioned identifier");
        assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
        assert!(
            identifier.qualifier.is_none(),
            "local write target must be bare"
        );
        assert!(matches!(
            identifier.namespace,
            ResolutionNamespace::Value | ResolutionNamespace::TypeOrValue
        ));
        assert!(
            !named_labels.contains(&write.target),
            "a named argument label is not a write"
        );
        assert!(
            references.contains_key(&write.target),
            "local write target must have a lexical reference"
        );
        assert!(matches!(
            slots
                .get(&write.value)
                .expect("local write must retain its RHS slot")
                .role,
            ResolutionTypeSlotRole::ExpressionValue | ResolutionTypeSlotRole::CallResult
        ));
    }

    // A one-file preload cannot prove an outward route empty. Open the shared
    // root for this attachment query only; the native precedence machinery can
    // still prove a nearer lexical binder beats every outward alternative.
    let first = facts
        .local_writes
        .first()
        .map(|write| write.target)
        .or_else(|| {
            facts
                .binding_events
                .iter()
                .find(|event| event.value.is_some())
                .map(|event| event.target)
        })
        .expect("write attachment has an input");
    let origin = LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary);
    let reason = identities.semantic(gap_reason_semantic_identity(first, origin));
    let mut gaps = lexical.gaps().to_vec();
    gaps.push(LoweredCoverageGap::new(
        CanonicalHasher::new(b"bifrost-local-write-open-root:v1").finish(),
        reason,
        first,
        origin,
        LoweringCoverageFrontier::Candidate {
            direction: LoweredCandidateDirection::Forward,
            endpoint: BindingNodeId::universal_root(),
            lookup: None,
        },
    ));
    let source = PreloadedFragmentSource::from_lowered_fragments([LoweredResolutionFragment::new(
        lexical.fragment(),
        lexical.language(),
        lexical.nodes().to_vec(),
        lexical.paths().to_vec(),
        lexical.semantics().to_vec(),
        gaps,
    )]);
    let engine = BatchResolutionEngine::new(&source);
    let cancellation = crate::CancellationToken::new();
    let mut inputs = HashMap::<ResolutionSiteId, Vec<ResolutionTypeSlotId>>::default();
    let mut failed_sites = HashSet::default();
    // Binding events carry exact, source-proven identity even when the ordered
    // scope timeline cannot yet prove the runtime availability of that slot.
    for event in &facts.binding_events {
        if let Some(value) = event.value {
            assert!(matches!(
                slots[&value].role,
                ResolutionTypeSlotRole::ExpressionValue | ResolutionTypeSlotRole::CallResult
            ));
            inputs.entry(event.slot).or_default().push(value);
        }
    }
    for write in &facts.local_writes {
        let reference = references[&write.target].semantic();
        let answer = engine
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("a validated preloaded lexical graph must resolve local write targets");
        let declaration = match answer.targets() {
            [target] if answer.completion() == &ResolutionCompletion::Complete => {
                definitions.get(target).copied().filter(|site| {
                    matches!(
                        binders.get(site),
                        Some(ResolutionBinderKind::Local | ResolutionBinderKind::Pattern)
                    )
                })
            }
            _ => None,
        };
        if let Some(declaration) = declaration {
            inputs.entry(declaration).or_default().push(write.value);
        } else {
            failed_sites.insert(write.target);
            // An exact parameter match proves which declaration is written,
            // but its incoming observed value is not modeled. Keep the gap at
            // the write without marking its known static type incomplete.
            let exact_parameter = answer.completion() == &ResolutionCompletion::Complete
                && matches!(
                    answer.targets(),
                    [target]
                        if definitions.get(target).is_some_and(|site| {
                            binders.get(site) == Some(&ResolutionBinderKind::Parameter)
                        })
                );
            if !exact_parameter {
                // Retain incompleteness on every known alternative, without
                // attaching the RHS to an arbitrary or conditional definition.
                failed_sites.extend(
                    answer
                        .targets()
                        .iter()
                        .filter_map(|target| definitions.get(target).copied()),
                );
            }
        }
    }

    let mut normalized = facts.clone();
    normalized.local_writes.clear();
    let mut seen_gaps = normalized.gaps.iter().cloned().collect::<HashSet<_>>();
    let mut failed_sites = failed_sites.into_iter().collect::<Vec<_>>();
    failed_sites.sort_unstable();
    for site in failed_sites {
        let gap = ResolutionGapFact::new(site, ResolutionGapKind::UnsupportedExpressionType);
        if seen_gaps.insert(gap.clone()) {
            normalized.gaps.push(gap);
        }
    }

    let mut transfers_by_output = HashMap::<_, Vec<_>>::default();
    for (index, transfer) in facts.type_transfers.iter().enumerate() {
        transfers_by_output
            .entry(transfer.output)
            .or_default()
            .push(index);
    }
    let produced_slots = facts
        .type_transfers
        .iter()
        .map(|transfer| transfer.output)
        .chain(facts.intrinsic_type_seeds.iter().map(|seed| seed.output))
        .chain(
            facts
                .binding_projections
                .iter()
                .map(|projection| projection.output),
        )
        .collect::<HashSet<_>>();
    let mut unproduced_values = HashMap::<_, Vec<_>>::default();
    for property in &facts.declaration_type_slots {
        if property.role == DeclarationTypeRole::Value
            && slots[&property.slot].role == ResolutionTypeSlotRole::DeclaredValue
            && !produced_slots.contains(&property.slot)
        {
            unproduced_values
                .entry(property.declaration)
                .or_default()
                .push(property.slot);
        }
    }
    let mut slots_by_site = HashMap::<_, Vec<_>>::default();
    for slot in &facts.type_slots {
        slots_by_site.entry(slot.site).or_default().push(*slot);
    }
    let mut next_slot = facts
        .type_slots
        .iter()
        .map(|slot| slot.id.get())
        .max()
        .map_or(0, |id| {
            id.checked_add(1).expect("local write slot IDs fit u32")
        });
    let mut written = inputs.into_iter().collect::<Vec<_>>();
    written.sort_unstable_by_key(|(site, _)| *site);
    for (declaration, mut inputs) in written {
        let mut observed = None;
        let mut assignment = None;
        let mut initializations = Vec::new();
        for slot in slots_by_site.get(&declaration).into_iter().flatten() {
            if slot.role == ResolutionTypeSlotRole::AssignmentValue {
                assert!(
                    observed.replace(slot.id).is_none(),
                    "a binder has one observed assignment slot"
                );
            }
            for &index in transfers_by_output.get(&slot.id).into_iter().flatten() {
                let transfer = facts.type_transfers[index];
                match (slot.role, transfer.kind) {
                    (
                        ResolutionTypeSlotRole::AssignmentValue,
                        ResolutionTypeTransferKind::Assignment,
                    ) => {
                        assert!(
                            assignment.replace(index).is_none(),
                            "assignment must remain a single producer"
                        );
                        inputs.push(transfer.input);
                    }
                    (
                        ResolutionTypeSlotRole::DeclaredValue,
                        ResolutionTypeTransferKind::Initialization,
                    ) => {
                        inputs.push(transfer.input);
                        initializations.push(index);
                    }
                    _ => {}
                }
            }
        }
        inputs.sort_unstable();
        inputs.dedup();
        let join = append_slot(
            &mut normalized,
            &mut next_slot,
            declaration,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        for input in inputs {
            assert!(matches!(
                slots[&input].role,
                ResolutionTypeSlotRole::ExpressionValue | ResolutionTypeSlotRole::CallResult
            ));
            normalized
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    input,
                    join,
                    ResolutionTypeTransferKind::ValueJoin,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                ));
        }
        let observed = observed.unwrap_or_else(|| {
            append_slot(
                &mut normalized,
                &mut next_slot,
                declaration,
                ResolutionTypeSlotRole::AssignmentValue,
            )
        });
        if let Some(index) = assignment {
            normalized.type_transfers[index].input = join;
        } else {
            // Reuse the inferred binding's category conversion when it owns
            // one. Explicit declared-type producers remain entirely separate.
            let boundary = initializations
                .first()
                .map(|&index| facts.type_transfers[index]);
            normalized
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    join,
                    observed,
                    ResolutionTypeTransferKind::Assignment,
                    boundary.map_or(0, |transfer| transfer.indirection_delta),
                    boundary.map_or(0, |transfer| transfer.reference_indirection_delta),
                    boundary.map_or(ResolutionTypeTransferValueTransform::Preserve, |transfer| {
                        transfer.value_transform
                    }),
                ));
        }
        for index in initializations {
            normalized.type_transfers[index].input = join;
        }
        // An inferred declaration without an initializer still owns its value
        // property. Writes supply that property's value without inventing an
        // initializer input or replacing a static/other affirmative producer.
        for &output in unproduced_values.get(&declaration).into_iter().flatten() {
            normalized
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    join,
                    output,
                    ResolutionTypeTransferKind::Initialization,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                ));
        }
    }
    Cow::Owned(normalized)
}

fn append_slot(
    facts: &mut FileResolutionFacts,
    next_slot: &mut u32,
    site: ResolutionSiteId,
    role: ResolutionTypeSlotRole,
) -> ResolutionTypeSlotId {
    let id = ResolutionTypeSlotId::new(*next_slot);
    *next_slot = next_slot
        .checked_add(1)
        .expect("local write slot IDs fit u32");
    facts
        .type_slots
        .push(ResolutionTypeSlotFact { id, site, role });
    id
}

#[cfg(test)]
mod tests {
    use crate::analyzer::resolution::local_writes::go_extraction_support_0::*;

    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        DeclarationTypeSlotFact, IntrinsicTypeKind, IntrinsicTypeSeedFact, ResolutionBinderFact,
        ResolutionLocalWriteFact, ResolutionNameId, ResolutionScopeId, ResolutionScopeKind,
        ResolutionSiteKind,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

    use super::*;
    use crate::analyzer::resolution::local_identity::PerRequestSharedNames;
    use crate::analyzer::resolution::test_support::{
        fragment, identifier, name, scope, site, transfer,
    };

    #[test]
    #[hardwon("#5015: a parameter write lacks evidence for its incoming observed value")]
    fn parameter_write_marks_the_gap_without_replacing_static_type_facts() {
        let mut facts = fixture();
        facts
            .binders
            .iter_mut()
            .find(|binder| binder.declaration == ResolutionSiteId::new(0))
            .expect("fixture parameter binder")
            .kind = ResolutionBinderKind::Parameter;
        facts
            .declaration_type_slots
            .iter_mut()
            .find(|property| property.declaration == ResolutionSiteId::new(0))
            .expect("fixture parameter property")
            .role = DeclarationTypeRole::Parameter;
        facts.local_writes = vec![ResolutionLocalWriteFact {
            target: ResolutionSiteId::new(2),
            value: ResolutionTypeSlotId::new(6),
        }];

        let static_type = facts.allocate_type_slot(
            ResolutionSiteId::new(6),
            ResolutionTypeSlotRole::TargetTypeIdentity,
        );
        facts
            .intrinsic_type_seeds
            .push(IntrinsicTypeSeedFact::direct(
                static_type,
                ResolutionNameId::new(2),
                IntrinsicTypeKind::Primitive,
            ));
        let static_producer = ResolutionTypeTransferFact::new(
            static_type,
            ResolutionTypeSlotId::new(0),
            ResolutionTypeTransferKind::DeclaredType,
            0,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
        facts.type_transfers[0] = static_producer;
        let parameter_assignment = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == ResolutionSiteId::new(0)
                    && slot.role == ResolutionTypeSlotRole::AssignmentValue
            })
            .expect("fixture parameter assignment slot")
            .id;
        facts
            .type_transfers
            .retain(|transfer| transfer.output != parameter_assignment);
        facts
            .type_slots
            .retain(|slot| slot.id != parameter_assignment);

        let normalized = normalize(&facts);
        assert!(normalized.gaps.contains(&ResolutionGapFact::new(
            ResolutionSiteId::new(2),
            ResolutionGapKind::UnsupportedExpressionType
        )));
        assert!(!normalized.gaps.contains(&ResolutionGapFact::new(
            ResolutionSiteId::new(0),
            ResolutionGapKind::UnsupportedExpressionType
        )));
        assert_eq!(
            normalized.declaration_type_slots,
            facts.declaration_type_slots
        );
        assert!(normalized.type_transfers.contains(&static_producer));
        assert!(normalized.local_writes.is_empty());
        assert!(!normalized.type_transfers.iter().any(|transfer| {
            matches!(
                transfer.kind,
                ResolutionTypeTransferKind::ValueJoin | ResolutionTypeTransferKind::Assignment
            ) && normalized
                .type_slots
                .iter()
                .any(|slot| slot.id == transfer.output && slot.site == ResolutionSiteId::new(0))
        }));
    }

    #[test]
    #[should_panic(expected = "assignment must remain a single producer")]
    #[hardwon("#5015: normalizing local writes must not hide multiple assignment producers")]
    fn local_write_normalization_still_rejects_multiple_assignments() {
        let mut facts = fixture();
        facts.type_transfers.push(facts.type_transfers[1]);
        normalize(&facts);
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extraction_support_0 {
    use crate::analyzer::resolution::local_identity::PerRequestSharedNames;
    use crate::analyzer::resolution::local_writes::*;
    use crate::analyzer::resolution::test_support::{
        fragment, identifier, name, scope, site, transfer,
    };
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        DeclarationTypeSlotFact, IntrinsicTypeKind, IntrinsicTypeSeedFact, ResolutionBinderFact,
        ResolutionLocalWriteFact, ResolutionNameId, ResolutionScopeId, ResolutionScopeKind,
        ResolutionSiteKind,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    #[doc(hidden)]
    pub fn fixture() -> FileResolutionFacts {
        let mut facts = FileResolutionFacts {
            names: vec![name(0, "x"), name(1, "missing"), name(2, "int")],
            scopes: vec![
                scope(0, None, None, ResolutionScopeKind::CompilationUnit, 0, 100),
                scope(1, Some(0), None, ResolutionScopeKind::Block, 20, 70),
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 1, ResolutionSiteKind::ValueDeclaration, 40),
                site(2, 1, ResolutionSiteKind::ValueReference, 30),
                site(3, 1, ResolutionSiteKind::ValueReference, 50),
                site(4, 0, ResolutionSiteKind::ValueReference, 80),
                site(5, 0, ResolutionSiteKind::ValueReference, 90),
                site(6, 0, ResolutionSiteKind::UnsupportedExpression, 2),
                site(7, 1, ResolutionSiteKind::UnsupportedExpression, 41),
                site(8, 1, ResolutionSiteKind::UnsupportedExpression, 31),
                site(9, 1, ResolutionSiteKind::UnsupportedExpression, 51),
                site(10, 0, ResolutionSiteKind::UnsupportedExpression, 81),
                site(11, 0, ResolutionSiteKind::UnsupportedExpression, 91),
            ],
            ..FileResolutionFacts::default()
        };
        for id in 0..6 {
            facts.identifiers.push(identifier(
                id,
                u32::from(id == 5),
                if id < 2 {
                    ResolutionIdentifierRole::Declaration
                } else {
                    ResolutionIdentifierRole::Reference
                },
                ResolutionNamespace::Value,
                None,
            ));
        }
        for (declaration, scope, start, end) in [(0, 0, 2, 100), (1, 1, 41, 70)] {
            facts.binders.push(ResolutionBinderFact {
                declaration: ResolutionSiteId::new(declaration),
                scope: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(
                    scope,
                ),
                kind: ResolutionBinderKind::Local,
                hoisting: HoistingClass::SourceOrder,
                activation_start: start,
                activation_end: end,
            });
            let declared = facts.allocate_type_slot(
                ResolutionSiteId::new(declaration),
                ResolutionTypeSlotRole::DeclaredValue,
            );
            facts.declaration_type_slots.push(DeclarationTypeSlotFact {
                declaration: ResolutionSiteId::new(declaration),
                slot: declared,
                role: DeclarationTypeRole::Value,
            });
            facts.allocate_type_slot(
                ResolutionSiteId::new(declaration),
                ResolutionTypeSlotRole::AssignmentValue,
            );
        }
        for id in 6..12 {
            let slot = facts.allocate_type_slot(
                ResolutionSiteId::new(id),
                ResolutionTypeSlotRole::ExpressionValue,
            );
            if id < 10 {
                facts
                    .intrinsic_type_seeds
                    .push(IntrinsicTypeSeedFact::direct(
                        slot,
                        ResolutionNameId::new(2),
                        IntrinsicTypeKind::Primitive,
                    ));
            } else {
                facts.gaps.push(ResolutionGapFact::new(
                    ResolutionSiteId::new(id),
                    ResolutionGapKind::UnsupportedExpressionType,
                ));
            }
        }
        facts.type_transfers = vec![
            transfer(
                4,
                0,
                ResolutionTypeTransferKind::Initialization,
                0,
                ResolutionTypeTransferValueTransform::Preserve,
            ),
            transfer(
                4,
                1,
                ResolutionTypeTransferKind::Assignment,
                0,
                ResolutionTypeTransferValueTransform::Preserve,
            ),
            transfer(
                5,
                2,
                ResolutionTypeTransferKind::Initialization,
                0,
                ResolutionTypeTransferValueTransform::Preserve,
            ),
            transfer(
                5,
                3,
                ResolutionTypeTransferKind::Assignment,
                0,
                ResolutionTypeTransferValueTransform::Preserve,
            ),
        ];
        for (target, value) in [(2, 6), (3, 7), (4, 8), (5, 9), (2, 6)] {
            facts.local_writes.push(ResolutionLocalWriteFact {
                target: ResolutionSiteId::new(target),
                value: ResolutionTypeSlotId::new(value),
            });
        }
        facts
    }
    #[doc(hidden)]
    pub fn normalize(facts: &FileResolutionFacts) -> FileResolutionFacts {
        let names = PerRequestSharedNames::new();
        let mut identities =
            ResolutionIdentityCatalogBuilder::new(fragment("local-writes"), &names);
        let lexical =
            crate::analyzer::resolution::fact_lowering::lower_file_resolution_facts_with_identities(
                &mut identities,
                Language::Go,
                facts,
            );
        attach_local_writes(facts, &lexical, &mut identities).into_owned()
    }
}
