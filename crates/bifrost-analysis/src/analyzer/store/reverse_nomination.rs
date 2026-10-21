//! Request-local target selection and reverse exposure discovery.
//!
//! Published language summaries nominate a superset. Forward confirmation is
//! the binding authority; discovery does not rank routes.
use super::reverse_candidates::{ReverseCandidateKey, read_reverse_candidates};
use super::*;
use rusqlite::params;

pub(super) const REVERSE_DEFINITION_SITE_SQL: &str = "SELECT sites.blob_id, sites.source_site FROM temp.selected_resolution_mounts AS mounts CROSS JOIN resolution_semantic_sites AS sites ON sites.blob_id = mounts.blob_id AND sites.semantic_key = ?2 AND sites.semantic_role = 'definition' WHERE mounts.mount_ordinal = ?1";

pub(super) type ReverseLookupSource = (i64, String, Option<u32>);
type ExposureIdentity = (Vec<u8>, String, String);

/// One spelling of a target in a selected module, with its traversal depth.
pub(super) struct ReverseExposure {
    pub topology: i64,
    pub key: Vec<u8>,
    pub module: String,
    pub name: String,
    pub depth: i64,
}
impl ReverseExposure {
    pub fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            topology: row.get(0)?,
            key: row.get(1)?,
            module: row.get(2)?,
            name: row.get(4)?,
            depth: row.get(6)?,
        })
    }
    fn identity(&self) -> ExposureIdentity {
        (self.key.clone(), self.module.clone(), self.name.clone())
    }
}

pub(super) struct ReverseExposureSeeds {
    pub exposures: Vec<ReverseExposure>,
    pub sources: HashSet<ReverseLookupSource>,
    pub unbound_spelling: Option<String>,
}
pub(super) struct ReverseExposureStep {
    pub candidates: Vec<(i64, u32)>,
    pub sources: Vec<ReverseLookupSource>,
    pub successors: Vec<ReverseExposure>,
}
pub(super) struct ReverseSourceLookup {
    pub candidates: Vec<(i64, u32)>,
    pub keys: Vec<ReverseCandidateKey>,
}

pub struct ReverseCandidateSet {
    pub(super) locators: Vec<SelectedSemanticLocator>,
    pub(super) names: Vec<(i64, String, String)>,
}
impl ReverseCandidateSet {
    pub(super) fn into_seeded_locators(
        mut self,
        seeds: &[SelectedSemanticLocator],
    ) -> Vec<SelectedSemanticLocator> {
        self.locators.extend(seeds.iter().cloned());
        self.locators.sort();
        self.locators.dedup();
        self.locators
    }

    /// The defining file is admitted even if discovery found no references.
    #[doc(hidden)]
    pub fn files<'a>(
        &'a self,
        root: &'a Path,
        target: &'a CodeUnit,
    ) -> impl Iterator<Item = ProjectFile> + 'a {
        std::iter::once(target.source().clone()).chain(
            self.locators
                .iter()
                .map(move |locator| ProjectFile::new(root, locator.relative_path())),
        )
    }
}

/// Language hooks read existing indexed summaries and classify source forms.
/// The shared caller owns traversal, selection, grouping and deduplication.
pub(super) trait ReverseNominationHooks {
    fn locate_reverse_definition(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>>;
    fn persisted_target(
        &self,
        mount: &SelectedResolutionOperationMount,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Option<(i64, i64)>>;
    fn overlay_routes(
        &self,
        mount: &SelectedResolutionOperationMount,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SelectedSemanticLocator>>;
    fn exposure_seeds(
        &self,
        target: &CodeUnit,
        blob: i64,
        site: i64,
    ) -> Result<ReverseExposureSeeds>;
    fn exposure_successors(
        &self,
        exposure: &ReverseExposure,
        extra_names: &[String],
    ) -> Result<ReverseExposureStep>;
    fn source_ranges(
        &self,
        target: &CodeUnit,
        sources: &HashSet<ReverseLookupSource>,
    ) -> Result<Vec<SelectedSemanticLocator>>;
    fn source_lookup(
        &self,
        blob: i64,
        name: &str,
        scope: Option<u32>,
        cancellation: &CancellationToken,
    ) -> Result<ReverseSourceLookup>;
    fn root_lookup(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<ReverseSourceLookup>>;
    fn observation_sites(
        &self,
        blob: i64,
        site: u32,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<ResolutionSiteId>>>;
    fn site_locators(&self, blob: i64, site: u32) -> Result<Vec<SelectedSemanticLocator>>;
}

/// Each request input keeps its candidate set, including an empty set.
/// Break reports the first unavailable input without selecting it a second time.
pub(super) fn group_reverse_inputs<T>(
    targets: &[CodeUnit],
    mut nominate: impl FnMut(&CodeUnit) -> Result<Option<T>>,
) -> Result<std::ops::ControlFlow<usize, Vec<T>>> {
    let mut groups = Vec::with_capacity(targets.len());
    for (ordinal, target) in targets.iter().enumerate() {
        let Some(group) = nominate(target)? else {
            return Ok(std::ops::ControlFlow::Break(ordinal));
        };
        groups.push(group);
    }
    Ok(std::ops::ControlFlow::Continue(groups))
}

/// Merge the distinct locators from the candidate projections.
pub(super) fn merged_locators(
    parts: [&[SelectedSemanticLocator]; 3],
) -> Vec<&SelectedSemanticLocator> {
    let mut locators = parts.into_iter().flatten().collect::<Vec<_>>();
    locators.sort();
    locators.dedup();
    locators
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn is_overlay_mount(&self, mount: &SelectedResolutionOperationMount) -> bool {
        self.ready
            .content_mounts
            .iter()
            .any(|request| request.persisted_relative_path() == mount.persisted_relative_path())
    }
}

pub(super) fn nominate_reverse_target(
    operation: &SelectedResolutionOperation<'_, '_>,
    hooks: &impl ReverseNominationHooks,
    target: &CodeUnit,
    extra_names: &[String],
    cancellation: &CancellationToken,
) -> Result<Option<ReverseCandidateSet>> {
    let Some(definition) = hooks.locate_reverse_definition(target, cancellation)? else {
        return Ok(None);
    };
    let lexical = operation.ready.lexical_source();
    let Some(provenance) = lexical.semantic_provenance(definition, cancellation)? else {
        return Ok(None);
    };
    let SelectedSemanticProvenance::FragmentLocal(local) = provenance else {
        return Err(StoreError::new(
            "source definition must have local provenance",
        ));
    };
    let mount = operation
        .mount_table()
        .mount_by_ordinal(local.mount().ordinal())?;
    let conn = operation.ready.inventory.connection();
    let mut overlay_locators = Vec::new();
    let coordinate = if operation.is_overlay_mount(&mount) {
        overlay_locators.extend(hooks.overlay_routes(&mount, target.identifier(), cancellation)?);
        hooks.persisted_target(&mount, target, cancellation)?
    } else {
        Some(
            conn.prepare_cached(REVERSE_DEFINITION_SITE_SQL)?
                .query_row(
                    params![local.mount().ordinal().get(), local.local_key().get()],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )?,
        )
    };
    let Some((blob, site)) = coordinate else {
        return Ok(Some(ReverseCandidateSet {
            locators: overlay_locators,
            names: Vec::new(),
        }));
    };
    let seeds = hooks.exposure_seeds(target, blob, site)?;
    let mut sources = seeds.sources;
    let mut candidates = HashSet::default();
    let mut names = HashSet::from_iter([target.identifier().to_owned()]);
    let mut pending = seeds.exposures;
    let mut reached = pending
        .iter()
        .map(ReverseExposure::identity)
        .collect::<HashSet<_>>();
    let mut inventory_names = Vec::new();
    while let Some(exposure) = pending.pop() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if exposure.depth == 64 {
            return Err(StoreError::new("reverse export route reached depth 64"));
        }
        names.insert(exposure.name.clone());
        inventory_names.push((
            exposure.topology,
            exposure.module.clone(),
            exposure.name.clone(),
        ));
        let step = hooks.exposure_successors(&exposure, extra_names)?;
        candidates.extend(step.candidates);
        sources.extend(step.sources);
        for successor in step.successors {
            if reached.insert(successor.identity()) {
                pending.push(successor);
            }
        }
    }
    let additional_sources = sources
        .iter()
        .flat_map(|(blob, _, scope)| {
            extra_names
                .iter()
                .map(move |name| (*blob, name.clone(), *scope))
        })
        .collect::<Vec<_>>();
    sources.extend(additional_sources);
    let range_locators = hooks.source_ranges(target, &sources)?;
    if let Some(spelling) = seeds.unbound_spelling {
        let member_sources = sources
            .iter()
            .map(|(blob, _, _)| (*blob, spelling.clone(), None))
            .collect::<Vec<_>>();
        sources.extend(member_sources);
    }
    names.extend(extra_names.iter().cloned());
    let mut lookup_keys = Vec::new();
    for (blob, name, scope) in sources {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let found = hooks.source_lookup(blob, &name, scope, cancellation)?;
        candidates.extend(found.candidates);
        lookup_keys.extend(found.keys);
    }
    let Some(groups) = read_reverse_candidates(operation, &lookup_keys, cancellation)? else {
        return Ok(None);
    };
    for candidate in groups.into_iter().flatten() {
        candidates.insert((candidate.context.blob, candidate.site.get()));
    }
    let mut root_keys = Vec::new();
    for name in &names {
        let Some(found) = hooks.root_lookup(name, cancellation)? else {
            return Ok(None);
        };
        candidates.extend(found.candidates);
        root_keys.extend(found.keys);
    }
    let Some(groups) = read_reverse_candidates(operation, &root_keys, cancellation)? else {
        return Ok(None);
    };
    for candidate in groups.into_iter().flatten() {
        candidates.insert((candidate.context.blob, candidate.site.get()));
    }
    for request in &operation.ready.content_mounts {
        let mount = operation
            .mount_table()
            .mount_for_path(
                request.storage_language(),
                request.persisted_relative_path(),
            )?
            .expect("selected content mount");
        for name in &names {
            overlay_locators.extend(hooks.overlay_routes(&mount, name, cancellation)?);
        }
    }
    let mut observations = Vec::new();
    for &(blob, site) in &candidates {
        let Some(observed) = hooks.observation_sites(blob, site, cancellation)? else {
            return Ok(None);
        };
        observations.extend(observed.into_iter().map(|site| (blob, site.get())));
    }
    candidates.extend(observations);
    let mut locators = overlay_locators;
    locators.extend(range_locators);
    for (blob, site) in candidates {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        locators.extend(hooks.site_locators(blob, site)?);
    }
    locators.sort();
    locators.dedup();
    inventory_names.sort_unstable();
    inventory_names.dedup();
    Ok(Some(ReverseCandidateSet {
        locators,
        names: inventory_names,
    }))
}
