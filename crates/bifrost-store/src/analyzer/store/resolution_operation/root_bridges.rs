//! Ordered, query-lived import pairing and root bridge assembly.
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

/// A pairing phase preserves unavailable and cancelled as distinct outcomes.
pub(super) enum RootBridgeStep<T> {
    Ready(T),
    Unavailable,
    Cancelled,
}

/// A language's inventory read and lazy filter/stop for one pairing unit.
/// The inventory may be memoized and may carry read evidence. Selection must
/// retain its encounter order and keep any state-dependent stops lazy.
pub(super) trait RootTargetRules {
    type Exports;
    type Bridges: RootBridgeRules;

    /// Retain unavailable/cancelled reads as outcomes, never empty successes.
    fn read_exports(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<RootBridgeStep<Self::Exports>>;

    /// Construct admission rules after the inventory read, preserving authority
    /// loading and any read-evidence fold before the first pair is offered.
    fn bridge_rules(&mut self, exports: &Self::Exports) -> Self::Bridges;

    fn pairs<'a>(
        &'a self,
        import: &'a SelectedRootPathHalf,
        exports: &'a Self::Exports,
        rules: &'a Self::Bridges,
    ) -> impl Iterator<Item = RootBridgePair<'a, <Self::Bridges as RootBridgeRules>::Extra>>;

    fn unavailable(&self, _rules: &Self::Bridges) -> bool {
        false
    }
}

/// Read and pair exactly one target, then append its descriptors in order.
/// Each call preserves one assembler invocation and its admission-set boundary;
/// targets or members must not be grouped. Unavailable rules/reads and cancelled
/// assembly propagate distinctly; the caller keeps its existing interpretation.
/// Inventory and assembly state live only for this query. The reader and lazy
/// selection hooks preserve read evidence and filter/first-witness semantics.
/// Return the admission rules so a caller can recover metadata accumulated by
/// admission, without putting its output-dependent continuation in this step.
pub(super) fn append_root_target<R: RootTargetRules>(
    operation: &ReadySelectedResolution<'_, '_>,
    import: &SelectedRootPathHalf,
    rules: &mut R,
    descriptors: &mut Vec<SelectedRootBridgeDescriptor>,
    cancellation: &CancellationToken,
) -> Result<RootBridgeStep<R::Bridges>> {
    if cancellation.is_cancelled() {
        return Ok(RootBridgeStep::Cancelled);
    }
    let exports = match rules.read_exports(cancellation)? {
        RootBridgeStep::Ready(exports) => exports,
        RootBridgeStep::Unavailable => return Ok(RootBridgeStep::Unavailable),
        RootBridgeStep::Cancelled => return Ok(RootBridgeStep::Cancelled),
    };
    let bridge_rules = rules.bridge_rules(&exports);
    let assembly = assemble_root_bridges(
        operation,
        rules.pairs(import, &exports, &bridge_rules),
        &bridge_rules,
        cancellation,
    )?;
    if rules.unavailable(&bridge_rules) {
        return Ok(RootBridgeStep::Unavailable);
    }
    if assembly
        .completion
        .contains_reason(ResolutionIncompleteReason::Cancelled)
    {
        return Ok(RootBridgeStep::Cancelled);
    }
    descriptors.extend(assembly.descriptors);
    Ok(RootBridgeStep::Ready(bridge_rules))
}

/// Language rules for the ordered import loop. Preparation runs once per
/// import, before target enumeration. Targets are already in language order;
/// the driver never sorts them. Target rules borrow that import's preparation.
pub(super) trait RootImportRules {
    type Prepared;
    type Target;
    type TargetRules<'a>: RootTargetRules
    where
        Self: 'a;

    /// Gate the import inventory read, after caller-owned authority loading.
    fn has_imports(&self) -> bool;
    fn read_imports(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<RootBridgeStep<Vec<SelectedRootPathHalf>>>;
    /// Poll cancellation for this import, including when it has no targets.
    fn prepare(
        &self,
        import: &SelectedRootPathHalf,
        cancellation: &CancellationToken,
    ) -> Result<RootBridgeStep<Self::Prepared>>;
    fn targets(&self, prepared: &Self::Prepared) -> Result<impl Iterator<Item = Self::Target>>;
    fn target_rules<'a>(
        &'a self,
        prepared: &'a Self::Prepared,
        target: Self::Target,
    ) -> Self::TargetRules<'a>;
}

/// Preserve inventory import order, preparation-before-targets, target-hook
/// order, and each target's export order/cardinality. Poll cancellation at
/// each target; preparation polls it per import at its existing read boundary.
/// A false precheck means no import inventory read.
/// Unavailable/cancelled preparation, inventory or pairing propagates unchanged;
/// ordinary errors propagate unchanged. All working state dies with the query.
pub(super) fn drive_root_imports<R: RootImportRules>(
    operation: &ReadySelectedResolution<'_, '_>,
    rules: &R,
    cancellation: &CancellationToken,
) -> Result<RootBridgeStep<Vec<SelectedRootBridgeDescriptor>>> {
    let mut descriptors = Vec::new();
    if !rules.has_imports() {
        return Ok(RootBridgeStep::Ready(descriptors));
    }
    let imports = match rules.read_imports(cancellation)? {
        RootBridgeStep::Ready(imports) => imports,
        RootBridgeStep::Unavailable => return Ok(RootBridgeStep::Unavailable),
        RootBridgeStep::Cancelled => return Ok(RootBridgeStep::Cancelled),
    };
    for import in imports {
        let SelectedRootPathHalf::Import { .. } = import else {
            continue;
        };
        let prepared = match rules.prepare(&import, cancellation)? {
            RootBridgeStep::Ready(prepared) => prepared,
            RootBridgeStep::Unavailable => return Ok(RootBridgeStep::Unavailable),
            RootBridgeStep::Cancelled => return Ok(RootBridgeStep::Cancelled),
        };
        for target in rules.targets(&prepared)? {
            let mut target_rules = rules.target_rules(&prepared, target);
            match append_root_target(
                operation,
                &import,
                &mut target_rules,
                &mut descriptors,
                cancellation,
            )? {
                RootBridgeStep::Ready(_) => {}
                RootBridgeStep::Unavailable => return Ok(RootBridgeStep::Unavailable),
                RootBridgeStep::Cancelled => return Ok(RootBridgeStep::Cancelled),
            }
        }
    }
    Ok(RootBridgeStep::Ready(descriptors))
}
