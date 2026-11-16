//! Terminal endpoint demands for an ordinary sink plan. Nonlocal dependencies
//! retain their authored workspace scope; only proved location-preserving
//! operators pass the demand backwards to their inputs.
use super::*;

#[derive(Debug, Default)]
pub(super) struct ReachedSinkSites {
    files: Vec<ProjectFile>,
    ranges: HashMap<ProjectFile, HashSet<(usize, usize)>>,
    retained_bytes: usize,
}

impl ReachedSinkSites {
    pub(super) fn insert(
        &mut self,
        site: &CallSiteValue,
        budget: &mut CodeQueryExecutionBudget,
        limits: CodeQueryExecutionLimits,
    ) -> bool {
        if self.contains_range(&site.0.file, site.0.range) {
            return true;
        }
        // Include HashMap/HashSet spare capacity and the owned file key. This
        // inventory lives under the existing semantic retained-byte allowance.
        let bytes = 8 * std::mem::size_of::<(usize, usize)>() + 4 * site.0.file.retained_bytes();
        if budget.retained_evidence_bytes.saturating_add(bytes) > limits.semantic.max_retained_bytes
        {
            return false;
        }
        budget.retained_evidence_bytes += bytes;
        self.retained_bytes += bytes;
        let ranges = self.ranges.entry(site.0.file.clone()).or_insert_with(|| {
            self.files.push(site.0.file.clone());
            HashSet::default()
        });
        ranges.insert((site.0.range.start_byte, site.0.range.end_byte));
        true
    }

    pub(super) fn len(&self) -> usize {
        self.ranges.values().map(HashSet::len).sum()
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(super) fn files(&self) -> &[ProjectFile] {
        &self.files
    }

    pub(super) fn contains_range(&self, file: &ProjectFile, range: Range) -> bool {
        self.ranges
            .get(file)
            .is_some_and(|ranges| ranges.contains(&(range.start_byte, range.end_byte)))
    }

    pub(super) fn contains(&self, value: &PipelineValue) -> bool {
        let (file, range) = match value {
            PipelineValue::StructuralMatch(seed) => (&seed.file, seed_range(seed)),
            PipelineValue::CallSite(site) => (&site.0.file, site.0.range),
            PipelineValue::DispatchTarget(target) => (target.file(), target.site.range),
            _ => return false,
        };
        self.contains_range(file, range)
    }
}

/// A demand is an output restriction, not a change to the ordinary seed scope
/// of arbitrary predecessors. Nodes beyond a nonlocal operator run normally.
#[derive(Debug)]
pub(super) struct SinkDemandExecution {
    pub(super) sites: Arc<ReachedSinkSites>,
    nodes: Vec<bool>,
}

impl SinkDemandExecution {
    pub(super) fn new(sites: Arc<ReachedSinkSites>, plan: &PhysicalQueryPlan) -> Self {
        let mut nodes = vec![false; plan.node_count()];
        let mut pending = vec![plan.root()];
        while let Some(id) = pending.pop() {
            if std::mem::replace(&mut nodes[id.index()], true) {
                continue;
            }
            let dependencies = plan.node(id).dependencies();
            match plan.logical_node(id).operator() {
                LogicalQueryOperator::Limit { .. } => {
                    pending.extend(dependencies.iter().copied());
                }
                LogicalQueryOperator::Set { op, .. } => {
                    if *op == SetOperator::Union {
                        pending.extend(dependencies.iter().copied());
                    } else {
                        // Intersections and exclusions prove their complete
                        // original dependency questions once. Restrict only
                        // the first relation at the final set merge.
                    }
                }
                LogicalQueryOperator::Step { step, .. } => {
                    // These steps retain the exact source anchor. Other steps
                    // may move it (including to another file), so their full
                    // input relation remains a global dependency evaluated
                    // once, never once for every demanded endpoint.
                    if matches!(
                        step,
                        QueryStep::Filter(_)
                            | QueryStep::Project(_)
                            | QueryStep::IdenticalCaptures { .. }
                    ) || (matches!(step, QueryStep::DispatchTargets)
                        && matches!(
                            plan.logical_node(dependencies[0]).output_kind(),
                            crate::query::QueryValueKind::StructuralMatch
                                | crate::query::QueryValueKind::CallSite
                        ))
                    {
                        pending.extend(dependencies.iter().copied());
                    }
                }
                LogicalQueryOperator::Correlate { .. }
                | LogicalQueryOperator::RequireBoth { .. } => {
                    // These produce composite identities. Their full original
                    // dependencies retain join/existence semantics. A later
                    // anchor-changing step must enumerate these predecessors.
                }
                LogicalQueryOperator::Seed(_)
                | LogicalQueryOperator::OccurrenceSeed(_)
                | LogicalQueryOperator::ScopeSeed(_)
                | LogicalQueryOperator::BindingSeed(_)
                | LogicalQueryOperator::GenerationSiteSeed(_)
                | LogicalQueryOperator::ExportSeed(_)
                | LogicalQueryOperator::PathSeed(_)
                | LogicalQueryOperator::ConfigurationFactsSeed(_)
                | LogicalQueryOperator::DependencyEvidenceSeed(_)
                | LogicalQueryOperator::CallReachability { .. } => {}
            }
        }
        Self { sites, nodes }
    }

    pub(super) fn for_node(&self, id: PhysicalQueryNodeId) -> Option<Arc<ReachedSinkSites>> {
        self.nodes[id.index()].then(|| Arc::clone(&self.sites))
    }
}

/// Test-only work counters for one demand-filled endpoint membership table.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct CallReachabilityDemandProbe {
    counters: Arc<[std::sync::atomic::AtomicUsize; 4]>,
}

#[cfg(any(test, feature = "test-support"))]
impl CallReachabilityDemandProbe {
    /// Fills, lookups, charged sink pipeline rows, charged sink scanned files.
    pub fn snapshot(&self) -> [usize; 4] {
        std::array::from_fn(|index| self.counters[index].load(std::sync::atomic::Ordering::Relaxed))
    }

    pub(super) fn filled(&self, rows: usize, files: usize) {
        for (counter, amount) in [(0, 1), (2, rows), (3, files)] {
            self.counters[counter].fetch_add(amount, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub(super) fn lookup(&self) {
        self.counters[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

// The reference strategy is available only to test-support callers and is
// keyed by the exact test workspace, so parallel unrelated tests cannot
// accidentally switch strategy. No CLI option or production mode exists.
#[cfg(any(test, feature = "test-support"))]
static GLOBAL_REFERENCE_ROOTS: std::sync::LazyLock<std::sync::Mutex<HashSet<std::path::PathBuf>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::default()));

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_global_call_reachability_reference<T>(
    root: &std::path::Path,
    run: impl FnOnce() -> T,
) -> T {
    let root = root
        .canonicalize()
        .expect("reference test workspace exists");
    assert!(
        GLOBAL_REFERENCE_ROOTS
            .lock()
            .expect("reference roots poisoned")
            .insert(root.clone())
    );
    struct Remove(std::path::PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            assert!(
                GLOBAL_REFERENCE_ROOTS
                    .lock()
                    .expect("reference roots poisoned")
                    .remove(&self.0)
            );
        }
    }
    let _remove = Remove(root);
    run()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn call_reachability_global_reference_active(root: &std::path::Path) -> bool {
    let roots = GLOBAL_REFERENCE_ROOTS
        .lock()
        .expect("reference roots poisoned");
    !roots.is_empty() && root.canonicalize().is_ok_and(|root| roots.contains(&root))
}
