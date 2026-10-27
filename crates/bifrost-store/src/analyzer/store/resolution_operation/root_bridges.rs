//! Ordered, query-lived assembly of already selected root bridge pairs.
use super::*;

/// Provider selection belongs to the language. `extra` carries the route,
/// placement or access authority that is not part of the source-owned halves.
pub(super) struct RootBridgePair<'a, Extra> {
    pub import_half: &'a SelectedRootPathHalf,
    pub export_half: &'a SelectedRootPathHalf,
    pub extra: Extra,
}

pub(super) trait RootBridgeRules {
    type Extra;
    type Admission;

    fn admit(
        &self,
        operation: &ReadySelectedResolution<'_, '_>,
        pair: &RootBridgePair<'_, Self::Extra>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>>;

    fn descriptor(
        &self,
        pair: &RootBridgePair<'_, Self::Extra>,
        admission: Self::Admission,
    ) -> SelectedRootBridgeDescriptor;

    /// Decide over all descriptors for one source lookup name. The positions
    /// refer to the ordered assembly; retaining them preserves candidate order.
    fn admit_set(
        &self,
        _name: &str,
        _descriptors: &[SelectedRootBridgeDescriptor],
        _positions: &mut Vec<usize>,
    ) -> ResolutionCompletion {
        ResolutionCompletion::Complete
    }

    /// Route-owned evidence must not accidentally become context-wide evidence.
    fn fold_completion(
        &self,
        completion: &mut ResolutionCompletion,
        descriptor: &SelectedRootBridgeDescriptor,
    );
}

pub(super) struct RootBridgeAssembly {
    pub descriptors: Vec<SelectedRootBridgeDescriptor>,
    pub completion: ResolutionCompletion,
}

/// Consume the language's candidate order without reading inventories again.
/// All temporary grouping and descriptors die with this request.
pub(super) fn assemble_root_bridges<'a, Rules: RootBridgeRules>(
    operation: &ReadySelectedResolution<'_, '_>,
    pairs: impl Iterator<Item = RootBridgePair<'a, Rules::Extra>>,
    rules: &Rules,
    cancellation: &CancellationToken,
) -> Result<RootBridgeAssembly> {
    let mut descriptors = Vec::new();
    for pair in pairs {
        if cancellation.is_cancelled() {
            break;
        }
        let admission = rules.admit(operation, &pair, cancellation)?;
        if cancellation.is_cancelled() {
            break;
        }
        if let Some(admission) = admission {
            descriptors.push(rules.descriptor(&pair, admission));
        }
    }
    let mut names: HashMap<&str, Vec<usize>> = HashMap::default();
    for (position, descriptor) in descriptors.iter().enumerate() {
        if cancellation.is_cancelled() {
            break;
        }
        names
            .entry(descriptor.source_demand().spelling())
            .or_default()
            .push(position);
    }
    let mut admitted = vec![false; descriptors.len()];
    let mut completion = ResolutionCompletion::Complete;
    for (name, mut positions) in names {
        if cancellation.is_cancelled() {
            break;
        }
        completion = completion.combine(&rules.admit_set(name, &descriptors, &mut positions));
        for position in positions {
            assert_eq!(descriptors[position].source_demand().spelling(), name);
            admitted[position] = true;
        }
    }
    if cancellation.is_cancelled() {
        return Ok(RootBridgeAssembly {
            descriptors: Vec::new(),
            completion: ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
        });
    }
    let descriptors = descriptors
        .into_iter()
        .zip(admitted)
        .filter_map(|(descriptor, admitted)| admitted.then_some(descriptor))
        .collect::<Vec<_>>();
    for descriptor in &descriptors {
        rules.fold_completion(&mut completion, descriptor);
    }
    Ok(RootBridgeAssembly {
        descriptors,
        completion,
    })
}
