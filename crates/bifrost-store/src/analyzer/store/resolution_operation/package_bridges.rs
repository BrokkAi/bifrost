//! Ordered, query-local assembly over language-selected package inventories.

use super::package_context::SelectedPackageRows;
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

/// A language's index retains its own empty/absent and completeness evidence.
/// Source selection (including Unavailable) happens before this interface.
pub(super) trait PackagePlanRules {
    type Source;
    type Index;

    /// Read one source's index, polling cancellation while processing references.
    fn read_index(
        &self,
        source: &Self::Source,
        references: &[LoweredPackageReference],
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Self::Index>>;
}

pub(super) struct PackagePlanEntry<'a, S, I> {
    pub source: &'a S,
    pub index: I,
}

pub(super) type PackagePlan<'a, R> =
    Vec<PackagePlanEntry<'a, <R as PackagePlanRules>::Source, <R as PackagePlanRules>::Index>>;

/// Build a query-local plan in source-hook order, retaining each index intact:
/// complete-empty, absent and incomplete inventories are never conflated.
/// Unavailable cannot enter this builder: the caller selects sources first.
/// With no references, return before any member-read hook call. Otherwise poll
/// cancellation per source; index hooks poll it per reference they process.
/// Planning preserves source/member order and descriptor cardinality.
pub(super) fn build_package_plan<'a, R: PackagePlanRules>(
    sources: &'a [R::Source],
    references: &[LoweredPackageReference],
    rules: &R,
    cancellation: &CancellationToken,
) -> Result<SelectedPackageRows<PackagePlan<'a, R>>> {
    let mut plan = Vec::new();
    if references.is_empty() {
        return Ok(SelectedPackageRows::Ready(plan));
    }
    for source in sources {
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        let SelectedPackageRows::Ready(index) =
            rules.read_index(source, references, cancellation)?
        else {
            return Ok(SelectedPackageRows::Cancelled);
        };
        plan.push(PackagePlanEntry { source, index });
    }
    Ok(SelectedPackageRows::Ready(plan))
}

/// One ordered member and its target placement, before pairing a reference.
pub(super) struct PackageBridgeTarget<'a, E> {
    pub member: &'a LoweredPackageMember,
    pub target_fragment: BindingFragmentId,
    pub target_mount: SelectedResolutionMountOrdinal,
    pub extra: E,
}

pub(super) trait PackagePairingRules: PackagePlanRules {
    type Bridges: PackageBridgeRules;

    /// Match a structured reference to the index's ordered member inventory.
    fn matching_members<'a>(
        &'a self,
        source: &'a Self::Source,
        index: &'a Self::Index,
        reference: &'a LoweredPackageReference,
    ) -> impl Iterator<Item = PackageBridgeTarget<'a, <Self::Bridges as PackageBridgeRules>::Extra>>;
}

/// Plan and assemble in source-major, then reference, then matching-member
/// order. The caller supplies unique references (deduplication errors must
/// propagate) and bridge rules constructed after any preceding import phase.
/// Source and member hook order and descriptor cardinality are preserved.
/// Cancellation is polled per source and reference, including unmatched ones.
/// No references means no member reads. Indices retain empty/absent evidence;
/// Unavailable remains the caller's source-selection outcome, never an empty
/// plan. Languages with reference-major emission use the plan builder directly.
pub(super) fn drive_package_bridges<R: PackagePairingRules>(
    operation: &ReadySelectedResolution<'_, '_>,
    sources: &[R::Source],
    references: &[LoweredPackageReference],
    plan_rules: &R,
    bridge_rules: &R::Bridges,
    cancellation: &CancellationToken,
) -> Result<PackageBridgeAssembly> {
    let SelectedPackageRows::Ready(plan) =
        build_package_plan(sources, references, plan_rules, cancellation)?
    else {
        return Ok(PackageBridgeAssembly::cancelled());
    };
    let pairs = plan.iter().flat_map(|entry| {
        references
            .iter()
            .take_while(|_| !cancellation.is_cancelled())
            .flat_map(move |reference| {
                plan_rules
                    .matching_members(entry.source, &entry.index, reference)
                    .map(move |target| PackageBridgePair {
                        reference,
                        member: target.member,
                        target_fragment: target.target_fragment,
                        target_mount: target.target_mount,
                        extra: target.extra,
                    })
            })
    });
    assemble_package_bridges(operation, pairs, bridge_rules, cancellation)
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
