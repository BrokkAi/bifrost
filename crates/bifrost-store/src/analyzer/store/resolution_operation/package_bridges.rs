//! Ordered, query-local assembly over language-selected package inventories.

use super::*;
use crate::analyzer::resolution::{
    LoweredPackageMember, LoweredPackageReference, SelectedPackageBridgeDescriptor,
};

pub(super) struct PackageBridgePair<'a, E> {
    pub reference: &'a LoweredPackageReference,
    pub member: &'a LoweredPackageMember,
    pub target_fragment: BindingFragmentId,
    pub target_mount: SelectedResolutionMountOrdinal,
    pub extra: E,
}

pub(super) struct PackageBridgeAdmission<E> {
    pub evidence: E,
    pub completion: ResolutionCompletion,
}

pub(super) trait PackageBridgeRules {
    type Extra;
    type Admission;

    fn admit(
        &self,
        operation: &ReadySelectedResolution<'_, '_>,
        pair: &PackageBridgePair<'_, Self::Extra>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>>;

    fn descriptor(
        &self,
        pair: &PackageBridgePair<'_, Self::Extra>,
        admission: Self::Admission,
    ) -> SelectedPackageBridgeDescriptor;

    /// A set rule may only drop or annotate bridges, never reorder or add them.
    /// Positions refer to the ordered descriptor slice and must stay ascending.
    fn admit_set(
        &self,
        _name: SemanticId,
        _descriptors: &[SelectedPackageBridgeDescriptor],
        _positions: &mut Vec<usize>,
    ) -> ResolutionCompletion {
        ResolutionCompletion::Complete
    }

    fn fold_completion(
        &self,
        completion: &mut ResolutionCompletion,
        descriptor: &SelectedPackageBridgeDescriptor,
    ) {
        *completion = completion.combine(descriptor.completion());
    }
}

pub(super) struct PackageBridgeAssembly {
    pub descriptors: Vec<SelectedPackageBridgeDescriptor>,
    pub completion: ResolutionCompletion,
}

impl PackageBridgeAssembly {
    fn cancelled() -> Self {
        Self {
            descriptors: Vec::new(),
            completion: ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
        }
    }
}

pub(super) fn assemble_package_bridges<'a, R: PackageBridgeRules>(
    operation: &ReadySelectedResolution<'_, '_>,
    pairs: impl Iterator<Item = PackageBridgePair<'a, R::Extra>>,
    rules: &R,
    cancellation: &CancellationToken,
) -> Result<PackageBridgeAssembly>
where
    R::Extra: 'a,
{
    // Names keep their first-seen order. Positions retain the original pair
    // order after set admission, including when references interleave names.
    let mut groups = Vec::<(SemanticId, Vec<usize>)>::new();
    let mut descriptors = Vec::new();
    let mut by_name = HashMap::default();
    let mut completion = ResolutionCompletion::Complete;
    for pair in pairs {
        if cancellation.is_cancelled() {
            return Ok(PackageBridgeAssembly::cancelled());
        }
        let admission = rules.admit(operation, &pair, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(PackageBridgeAssembly::cancelled());
        }
        let Some(admission) = admission else {
            continue;
        };
        let descriptor = rules.descriptor(&pair, admission);
        rules.fold_completion(&mut completion, &descriptor);
        let group = *by_name.entry(pair.reference.lookup).or_insert_with(|| {
            groups.push((pair.reference.lookup, Vec::new()));
            groups.len() - 1
        });
        groups[group].1.push(descriptors.len());
        descriptors.push(descriptor);
    }
    let mut admitted = vec![false; descriptors.len()];
    for (name, mut positions) in groups {
        if cancellation.is_cancelled() {
            return Ok(PackageBridgeAssembly::cancelled());
        }
        completion = completion.combine(&rules.admit_set(name, &descriptors, &mut positions));
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        for position in positions {
            assert!(
                !admitted[position],
                "set admission retains each position once"
            );
            admitted[position] = true;
        }
    }
    if cancellation.is_cancelled() {
        return Ok(PackageBridgeAssembly::cancelled());
    }
    Ok(PackageBridgeAssembly {
        descriptors: descriptors
            .into_iter()
            .zip(admitted)
            .filter_map(|(descriptor, keep)| keep.then_some(descriptor))
            .collect(),
        completion,
    })
}
