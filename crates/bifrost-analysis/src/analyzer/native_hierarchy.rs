//! Shared conversion of native parent evidence to public hierarchy answers.
use crate::analyzer::resolution::{ClassifiedSupertypeKind, ResolutionCompletion};
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_operation::direct_supertypes::DirectSupertypeAnswer;
use crate::analyzer::store::resolution_operation::*;
use brokk_bifrost_core::analyzer::capabilities::{
    HierarchyAnswer, HierarchyOpenReason, PlatformInventoryMethod, UnreadMemberFamilyAncestor,
};
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_core::cancellation::CancellationToken;
use std::collections::HashMap;

/// Language rules for external roots and unread member inventories.
pub struct HierarchyConversionRules {
    pub intrinsic_provider: &'static str,
    pub intrinsic_root: fn(&str) -> Option<&'static str>,
    pub unread_inventory: fn(&str) -> Option<&'static [PlatformInventoryMethod]>,
}

pub struct MappedParent {
    pub kind: Option<ClassifiedSupertypeKind>,
    pub ordinal: u32,
    pub targets: Vec<CodeUnit>,
    pub unread: Vec<UnreadMemberFamilyAncestor>,
    pub intrinsic_root: Option<crate::analyzer::resolution::ExternalOwnerIdentity>,
    pub alternatives: usize,
    pub complete: bool,
}

pub fn stopped() -> HierarchyAnswer {
    HierarchyAnswer {
        open: vec![HierarchyOpenReason::MemberFamily(
            MemberFamilyReason::HierarchyTruncated,
        )],
        ..HierarchyAnswer::complete(Vec::new())
    }
}

pub fn convert(
    operation: &SelectedResolutionOperation<'_, '_>,
    raw: DirectSupertypeAnswer,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
    rules: &HierarchyConversionRules,
    normalize: impl FnOnce(&mut Vec<MappedParent>),
) -> Result<HierarchyAnswer> {
    let mut answer = HierarchyAnswer::complete(Vec::new());
    if raw.completion != ResolutionCompletion::Complete {
        answer.open.extend(stopped().open);
    }
    let mut external = HashMap::new();
    let mut source = Vec::new();
    for target in raw.parents.iter().flat_map(|parent| &parent.targets) {
        if let Some(owner) = operation.hierarchy_external_owner(*target) {
            external.insert(*target, owner);
        } else {
            source.push(*target);
        }
    }
    source.sort_unstable();
    source.dedup();
    let mut units = HashMap::new();
    if !source.is_empty() {
        match operation.selected_hierarchy_definition_units(&source, cancellation, session)? {
            SelectedNativeDefinitions::Ready(definitions) => {
                for (id, definition) in definitions {
                    match definition {
                        SelectedNativeDefinition::Unit(unit) => {
                            units.insert(id, unit);
                        }
                        SelectedNativeDefinition::Intrinsic { canonical_name, .. } => {
                            external.insert(
                                id,
                                crate::analyzer::resolution::ExternalOwnerIdentity {
                                    provider_id: std::sync::Arc::from(rules.intrinsic_provider),
                                    owner_fqn: std::sync::Arc::from(canonical_name),
                                },
                            );
                        }
                        SelectedNativeDefinition::ExternalOwner { owner, .. } => {
                            external.insert(id, owner);
                        }
                        SelectedNativeDefinition::Lexical(_) => {
                            answer.open.extend(stopped().open);
                        }
                    }
                }
            }
            SelectedNativeDefinitions::Cancelled | SelectedNativeDefinitions::Unavailable => {
                answer.open.extend(stopped().open);
            }
        }
    }
    let mut parents = Vec::new();
    for parent in raw.parents {
        let selected_owner = (parent.targets.is_empty()
            && parent.kind != Some(ClassifiedSupertypeKind::ImplicitSuperclass))
        .then(|| operation.hierarchy_reference_owner(parent.reference))
        .flatten();
        let mut mapped = MappedParent {
            kind: parent.kind,
            ordinal: parent.parent_ordinal,
            targets: Vec::new(),
            unread: Vec::new(),
            intrinsic_root: None,
            alternatives: parent.targets.len(),
            complete: parent.completion == ResolutionCompletion::Complete,
        };
        for target in parent.targets {
            if let Some(unit) = units.get(&target) {
                mapped.targets.push(unit.clone());
            } else if let Some(owner) = external.get(&target) {
                if let Some(root) = (rules.intrinsic_root)(&owner.owner_fqn)
                    && owner.provider_id.as_ref() == rules.intrinsic_provider
                    && mapped.alternatives == 1
                    && mapped.complete
                {
                    mapped.intrinsic_root =
                        Some(crate::analyzer::resolution::ExternalOwnerIdentity {
                            provider_id: std::sync::Arc::from(rules.intrinsic_provider),
                            owner_fqn: std::sync::Arc::from(root),
                        });
                } else {
                    // External coordinates do not carry interface metadata.
                    // Keep the unread edge open rather than inventing a root.
                    mapped.unread.push(UnreadMemberFamilyAncestor {
                        name: owner.owner_fqn.to_string(),
                        inventory: (rules.unread_inventory)(&owner.owner_fqn),
                    });
                }
            } else {
                mapped.complete = false;
            }
        }
        if let Some(owner) = selected_owner {
            mapped.unread.push(UnreadMemberFamilyAncestor {
                name: owner.owner_fqn.to_string(),
                inventory: (rules.unread_inventory)(&owner.owner_fqn),
            });
        }
        parents.push(mapped);
    }
    normalize(&mut parents);
    parents.sort_by_key(|parent| {
        (
            match parent.kind {
                Some(
                    ClassifiedSupertypeKind::Superclass
                    | ClassifiedSupertypeKind::ImplicitSuperclass,
                ) => 0,
                _ => 1,
            },
            parent.ordinal,
        )
    });
    for parent in parents {
        if let Some(root) = parent.intrinsic_root {
            assert_eq!(root.provider_id.as_ref(), rules.intrinsic_provider);
            assert!(parent.complete && parent.alternatives == 1);
            assert!(parent.targets.is_empty());
            // The Java member-family query can nominate an intrinsic root as
            // unread. Ordinary direct-ancestor queries leave this empty.
            answer.open.extend(
                parent
                    .unread
                    .into_iter()
                    .map(HierarchyOpenReason::UnreadAncestor),
            );
            continue;
        }
        if parent.alternatives > 1 {
            answer.ambiguous.push(parent.targets);
            answer.open.push(HierarchyOpenReason::MemberFamily(
                MemberFamilyReason::HierarchyAmbiguous,
            ));
        } else if parent.complete {
            answer.edges.extend(parent.targets);
        }
        if parent.alternatives == 0 || !parent.complete {
            answer.open.extend(stopped().open);
        }
        answer.open.extend(
            parent
                .unread
                .into_iter()
                .map(HierarchyOpenReason::UnreadAncestor),
        );
    }
    Ok(answer)
}
