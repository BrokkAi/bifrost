//! Immutable snapshot-local postings for structural seed selection.
//!
//! The matcher remains the semantic authority. Every posting is a positive,
//! sound candidate relation over normalized facts; query negatives, regexes,
//! containment, and nested predicates are always verified by the matcher.

use super::kinds::{NormalizedKind, Role};
use super::planner::{
    StructuralAccessPathEstimate, StructuralAccessPathKind, StructuralAccessRequirements,
    StructuralPostingEstimate, StructuralPostingTerm, supports_exact_role_name_posting,
};
use super::provider::{StructuralFactsCacheOutcome, StructuralSearchProvider};
use crate::ProjectFile;
use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, map_with_capacity};
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub(crate) const STRUCTURAL_INDEX_REPRESENTATION_VERSION: u32 = 1;
const MAX_INDEX_FILES: usize = 1_000_000;
const MAX_INDEX_FACT_NODES: u64 = 100_000_000;
const MAX_INDEX_SOURCE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FACT_CANCELLATION_BATCH: usize = 4096;
const SOURCE_CANCELLATION_BATCH: usize = 64 * 1024;
const SOURCE_FILTER_WORDS_PER_FILE: usize = 64;
const MIN_KIND_NAME_POSTING_ROWS: usize = 128;
const BUILD_WORKING_BYTES_MULTIPLIER: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StructuralIndexKey {
    representation_version: u32,
    source_generation: u64,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct FactAddress {
    pub(crate) file: u32,
    pub(crate) fact: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct StructuralIndexFile {
    pub(crate) file: ProjectFile,
    pub(crate) source_bytes: u64,
    pub(crate) fact_nodes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RolePostingKey {
    role: Role,
    value: Box<str>,
    keyword: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct KindNamePostingKey {
    kind: NormalizedKind,
    name: Box<str>,
}

#[derive(Debug)]
pub(crate) struct SnapshotStructuralIndex {
    source_generation: u64,
    files: Box<[StructuralIndexFile]>,
    file_ids: HashMap<ProjectFile, u32>,
    kind_postings: HashMap<NormalizedKind, Box<[FactAddress]>>,
    name_postings: HashMap<Box<str>, Box<[FactAddress]>>,
    /// Only combinations that are strictly narrower than their name posting.
    /// A name used by exactly one actual kind is already represented optimally
    /// by `name_postings` and is not duplicated here.
    kind_name_postings: HashMap<KindNamePostingKey, Box<[FactAddress]>>,
    role_postings: HashMap<RolePostingKey, Box<[FactAddress]>>,
    source_trigram_filters: Box<[u64]>,
    retained_bytes: u64,
}

impl SnapshotStructuralIndex {
    pub(crate) const fn source_generation(&self) -> u64 {
        self.source_generation
    }

    pub(crate) fn file(&self, file: &ProjectFile) -> Option<&StructuralIndexFile> {
        let id = self.file_ids.get(file).copied()?;
        self.files.get(id as usize)
    }

    pub(crate) fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Returns false only when at least one required anchor is definitely
    /// absent from the indexed source. Hash collisions can return true for an
    /// absent anchor, in which case the caller verifies with `str::contains`.
    pub(crate) fn source_may_contain(
        &self,
        file: &ProjectFile,
        required_anchors: &[String],
    ) -> Option<bool> {
        let file_id = self.file_ids.get(file).copied()? as usize;
        let start = file_id.checked_mul(SOURCE_FILTER_WORDS_PER_FILE)?;
        let end = start.checked_add(SOURCE_FILTER_WORDS_PER_FILE)?;
        let filter = self.source_trigram_filters.get(start..end)?;
        Some(
            required_anchors
                .iter()
                .all(|anchor| trigram_filter_may_contain(filter, anchor.as_bytes())),
        )
    }

    pub(crate) fn select(
        &self,
        requirements: &StructuralAccessRequirements,
        scoped_files: &[ProjectFile],
        source_verification_required: bool,
        cache_ready_before_lookup: bool,
        cancellation: &CancellationToken,
    ) -> Result<Option<StructuralCandidateSet>, &'static str> {
        if requirements.terms().is_empty() {
            return Ok(None);
        }
        let mut scoped_ids = Vec::with_capacity(scoped_files.len());
        let mut scoped_fact_nodes = 0u64;
        for (index, file) in scoped_files.iter().enumerate() {
            if index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
                return Err("structural index selection cancelled");
            }
            let Some(id) = self.file_ids.get(file).copied() else {
                return Err("snapshot index does not contain a scoped provider file");
            };
            scoped_ids.push(id);
            scoped_fact_nodes =
                scoped_fact_nodes.saturating_add(u64::from(self.files[id as usize].fact_nodes));
        }
        scoped_ids.sort_unstable();
        scoped_ids.dedup();

        let mut terms = self.selection_terms(requirements, &scoped_ids);
        terms.sort_by(|left, right| {
            left.estimated_rows
                .cmp(&right.estimated_rows)
                .then_with(|| left.label.cmp(right.label))
        });
        let selected_label = terms
            .iter()
            .map(|term| term.label)
            .collect::<Vec<_>>()
            .join("+");
        let mut selected = terms
            .first()
            .map(|term| term.materialize(&scoped_ids, cancellation))
            .transpose()?
            .unwrap_or_default();
        for term in terms.iter().skip(1) {
            let mut examined = 0usize;
            let mut cancelled = false;
            selected.retain(|address| {
                if examined.is_multiple_of(FACT_CANCELLATION_BATCH) && cancellation.is_cancelled() {
                    cancelled = true;
                }
                examined = examined.saturating_add(1);
                !cancelled && term.contains(*address)
            });
            if cancelled || cancellation.is_cancelled() {
                return Err("structural index selection cancelled");
            }
            if selected.is_empty() {
                break;
            }
        }

        let mut by_file: HashMap<ProjectFile, Vec<u32>> = HashMap::default();
        for address in &selected {
            by_file
                .entry(self.files[address.file as usize].file.clone())
                .or_default()
                .push(address.fact);
        }
        let estimate = StructuralAccessPathEstimate {
            kind: StructuralAccessPathKind::Posting,
            provider_files: self.files.len() as u64,
            scoped_files: scoped_files.len() as u64,
            scoped_fact_nodes,
            candidate_files: by_file.len() as u64,
            candidate_facts: selected.len() as u64,
            selected_terms: terms
                .iter()
                .map(|term| StructuralPostingEstimate {
                    label: term.label,
                    candidate_facts: term.estimated_rows,
                })
                .collect(),
            source_verification_required,
            cache_ready_before_lookup,
        };
        Ok(Some(StructuralCandidateSet {
            selected: selected_label,
            estimate,
            by_file,
        }))
    }

    fn selection_terms<'a>(
        &'a self,
        requirements: &'a StructuralAccessRequirements,
        scoped_files: &[u32],
    ) -> Vec<SelectionTerm<'a>> {
        let kinds = requirements.terms().iter().find_map(|term| match term {
            StructuralPostingTerm::Kinds(kinds) => Some(kinds.as_slice()),
            _ => None,
        });
        let exact_name = requirements.terms().iter().find_map(|term| match term {
            StructuralPostingTerm::ExactName(name) => Some(name.as_str()),
            _ => None,
        });
        let combined = kinds
            .zip(exact_name)
            .and_then(|(kinds, name)| self.kind_name_term(kinds, name, scoped_files));
        let uses_combined = combined.is_some();

        let mut terms = Vec::with_capacity(requirements.terms().len());
        if let Some(combined) = combined {
            terms.push(combined);
        }
        for term in requirements.terms() {
            if uses_combined
                && matches!(
                    term,
                    StructuralPostingTerm::Kinds(_) | StructuralPostingTerm::ExactName(_)
                )
            {
                continue;
            }
            terms.push(self.term(term, scoped_files));
        }
        terms
    }

    fn kind_name_term<'a>(
        &'a self,
        requested_kinds: &[NormalizedKind],
        name: &str,
        scoped_files: &[u32],
    ) -> Option<SelectionTerm<'a>> {
        let mut postings = Vec::new();
        let mut name_has_combination_postings = false;
        for (key, posting) in &self.kind_name_postings {
            if key.name.as_ref() != name {
                continue;
            }
            name_has_combination_postings = true;
            if requested_kinds
                .iter()
                .any(|requested| key.kind.satisfies(*requested))
            {
                postings.push(posting.as_ref());
            }
        }
        if !name_has_combination_postings {
            return None;
        }
        Some(SelectionTerm::new("kind_name", postings, scoped_files))
    }

    fn term<'a>(&'a self, term: &StructuralPostingTerm, scoped_files: &[u32]) -> SelectionTerm<'a> {
        let postings = match term {
            StructuralPostingTerm::Kinds(kinds) => self
                .kind_postings
                .iter()
                .filter(|(actual, _)| kinds.iter().any(|requested| actual.satisfies(*requested)))
                .map(|(_, posting)| posting.as_ref())
                .collect(),
            StructuralPostingTerm::ExactName(name) => self
                .name_postings
                .get(name.as_str())
                .map(|posting| vec![posting.as_ref()])
                .unwrap_or_default(),
            StructuralPostingTerm::RoleName { role, name } => self
                .role_postings
                .get(&RolePostingKey {
                    role: *role,
                    value: name.as_str().into(),
                    keyword: false,
                })
                .map(|posting| vec![posting.as_ref()])
                .unwrap_or_default(),
            StructuralPostingTerm::KwargKeyword(keyword) => self
                .role_postings
                .get(&RolePostingKey {
                    role: Role::Kwarg,
                    value: keyword.as_str().into(),
                    keyword: true,
                })
                .map(|posting| vec![posting.as_ref()])
                .unwrap_or_default(),
        };
        SelectionTerm::new(term.label(), postings, scoped_files)
    }
}

struct SelectionTerm<'a> {
    label: &'static str,
    postings: Vec<&'a [FactAddress]>,
    estimated_rows: u64,
}

impl<'a> SelectionTerm<'a> {
    fn new(label: &'static str, postings: Vec<&'a [FactAddress]>, scoped_files: &[u32]) -> Self {
        let estimated_rows = postings.iter().fold(0u64, |total, posting| {
            total.saturating_add(scoped_posting_len(posting, scoped_files))
        });
        Self {
            label,
            postings,
            estimated_rows,
        }
    }

    fn contains(&self, address: FactAddress) -> bool {
        self.postings
            .iter()
            .any(|posting| posting.binary_search(&address).is_ok())
    }

    fn materialize(
        &self,
        scoped_files: &[u32],
        cancellation: &CancellationToken,
    ) -> Result<Vec<FactAddress>, &'static str> {
        let capacity = usize::try_from(self.estimated_rows)
            .map_err(|_| "structural candidate cardinality exceeds platform limit")?;
        let mut rows = Vec::with_capacity(capacity);
        for (file_index, &file) in scoped_files.iter().enumerate() {
            if file_index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
                return Err("structural index selection cancelled");
            }
            let ranges = self
                .postings
                .iter()
                .map(|posting| posting_range_for_file(posting, file))
                .filter(|posting| !posting.is_empty())
                .collect::<Vec<_>>();
            let mut positions = vec![0usize; ranges.len()];
            loop {
                let next = ranges
                    .iter()
                    .zip(&positions)
                    .filter_map(|(range, &position)| range.get(position).copied())
                    .min();
                let Some(next) = next else {
                    break;
                };
                if rows.last().copied() != Some(next) {
                    rows.push(next);
                    if rows.len() % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
                        return Err("structural index selection cancelled");
                    }
                }
                for (range, position) in ranges.iter().zip(&mut positions) {
                    while range.get(*position).copied() == Some(next) {
                        *position += 1;
                    }
                }
            }
        }
        if cancellation.is_cancelled() {
            Err("structural index selection cancelled")
        } else {
            Ok(rows)
        }
    }
}

#[inline]
fn trigram_filter_positions(trigram: &[u8]) -> [usize; 2] {
    debug_assert_eq!(trigram.len(), 3);
    let packed =
        usize::from(trigram[0]) | (usize::from(trigram[1]) << 8) | (usize::from(trigram[2]) << 16);
    let bit_count = SOURCE_FILTER_WORDS_PER_FILE * u64::BITS as usize;
    debug_assert!(bit_count.is_power_of_two());
    [packed & (bit_count - 1), (packed >> 12) & (bit_count - 1)]
}

fn insert_source_trigrams(
    filter: &mut [u64],
    source: &[u8],
    cancellation: &CancellationToken,
) -> bool {
    debug_assert_eq!(filter.len(), SOURCE_FILTER_WORDS_PER_FILE);
    for (index, trigram) in source.windows(3).enumerate() {
        if index % SOURCE_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
            return false;
        }
        for bit in trigram_filter_positions(trigram) {
            filter[bit / u64::BITS as usize] |= 1u64 << (bit % u64::BITS as usize);
        }
    }
    !cancellation.is_cancelled()
}

fn trigram_filter_may_contain(filter: &[u64], anchor: &[u8]) -> bool {
    if anchor.len() < 3 {
        return true;
    }
    anchor.windows(3).all(|trigram| {
        trigram_filter_positions(trigram).into_iter().all(|bit| {
            filter
                .get(bit / u64::BITS as usize)
                .is_some_and(|word| word & (1u64 << (bit % u64::BITS as usize)) != 0)
        })
    })
}

fn posting_range_for_file(posting: &[FactAddress], file: u32) -> &[FactAddress] {
    let start = posting.partition_point(|address| address.file < file);
    let end = posting[start..].partition_point(|address| address.file == file) + start;
    &posting[start..end]
}

fn scoped_posting_len(posting: &[FactAddress], scoped_files: &[u32]) -> u64 {
    scoped_files.iter().fold(0u64, |total, &file| {
        total.saturating_add(posting_range_for_file(posting, file).len() as u64)
    })
}

#[derive(Debug)]
pub(crate) struct StructuralCandidateSet {
    pub(crate) selected: String,
    pub(crate) estimate: StructuralAccessPathEstimate,
    by_file: HashMap<ProjectFile, Vec<u32>>,
}

impl StructuralCandidateSet {
    pub(crate) fn facts_for(&self, file: &ProjectFile) -> &[u32] {
        self.by_file.get(file).map_or(&[], Vec::as_slice)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StructuralIndexBuildMetrics {
    pub(crate) files: u64,
    pub(crate) source_bytes: u64,
    pub(crate) fact_nodes: u64,
    pub(crate) facts_bytes: u64,
    pub(crate) memory_hits: u64,
    pub(crate) persisted_hydrations: u64,
    pub(crate) extractions: u64,
    pub(crate) unavailable: u64,
    pub(crate) unknown_outcomes: u64,
    pub(crate) elapsed_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructuralIndexLifecycle {
    Hit,
    Built,
}

pub(crate) enum StructuralIndexAcquisition {
    Ready {
        index: Arc<SnapshotStructuralIndex>,
        lifecycle: StructuralIndexLifecycle,
        wait: CompleteValueWait,
        build: StructuralIndexBuildMetrics,
    },
    Unavailable {
        reason: &'static str,
        wait: CompleteValueWait,
        build: StructuralIndexBuildMetrics,
    },
    Cancelled {
        wait: CompleteValueWait,
        build: StructuralIndexBuildMetrics,
    },
}

#[derive(Clone)]
#[doc(hidden)]
pub struct SnapshotStructuralIndexCache {
    complete: CompleteValueCache<StructuralIndexKey, SnapshotStructuralIndex>,
    max_retained_bytes: u64,
    auto_reuse_generation: Arc<AtomicU64>,
}

impl SnapshotStructuralIndexCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            complete: CompleteValueCache::<StructuralIndexKey, SnapshotStructuralIndex>::new(
                max_retained_bytes,
                |_, index| index.retained_bytes().clamp(1, u32::MAX as u64) as u32,
            ),
            max_retained_bytes,
            auto_reuse_generation: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }

    pub(crate) fn acquire(
        &self,
        provider: &dyn StructuralSearchProvider,
        cancellation: &CancellationToken,
    ) -> StructuralIndexAcquisition {
        let key = StructuralIndexKey {
            representation_version: STRUCTURAL_INDEX_REPRESENTATION_VERSION,
            source_generation: provider.structural_source_generation(),
        };
        let (acquisition, wait) = self.complete.acquire(&key, cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => StructuralIndexAcquisition::Ready {
                index: value,
                lifecycle: StructuralIndexLifecycle::Hit,
                wait,
                build: StructuralIndexBuildMetrics::default(),
            },
            CompleteValueAcquisition::Cancelled => StructuralIndexAcquisition::Cancelled {
                wait,
                build: StructuralIndexBuildMetrics::default(),
            },
            CompleteValueAcquisition::Leader { permit } => {
                match build_index(
                    provider,
                    cancellation,
                    self.max_retained_bytes,
                    key.source_generation,
                ) {
                    Ok((_index, build)) if cancellation.is_cancelled() => {
                        StructuralIndexAcquisition::Cancelled { wait, build }
                    }
                    Ok((_index, build))
                        if provider.structural_source_generation() != key.source_generation =>
                    {
                        StructuralIndexAcquisition::Unavailable {
                            reason: "structural source generation changed during index construction",
                            wait,
                            build,
                        }
                    }
                    Ok((index, build)) => {
                        let index = Arc::new(index);
                        permit.publish_complete(Arc::clone(&index));
                        StructuralIndexAcquisition::Ready {
                            index,
                            lifecycle: StructuralIndexLifecycle::Built,
                            wait,
                            build,
                        }
                    }
                    Err(BuildFailure::Cancelled { metrics }) => {
                        StructuralIndexAcquisition::Cancelled {
                            wait,
                            build: metrics,
                        }
                    }
                    Err(BuildFailure::Unavailable { reason, metrics }) => {
                        StructuralIndexAcquisition::Unavailable {
                            reason,
                            wait,
                            build: metrics,
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn get_ready(
        &self,
        source_generation: u64,
        cancellation: &CancellationToken,
    ) -> Option<Arc<SnapshotStructuralIndex>> {
        self.complete.get_ready(
            &StructuralIndexKey {
                representation_version: STRUCTURAL_INDEX_REPRESENTATION_VERSION,
                source_generation,
            },
            cancellation,
        )
    }

    /// Auto avoids paying a whole-snapshot construction cost for a query that
    /// may run only once. The first viable request records reuse interest and
    /// scans; a subsequent request may build. Forced indexed tests bypass this
    /// policy and exercise construction directly.
    pub(crate) fn observe_auto_reuse_opportunity(&self, source_generation: u64) -> bool {
        self.auto_reuse_generation
            .swap(source_generation, Ordering::AcqRel)
            == source_generation
    }

    #[cfg(test)]
    fn len_for_test(&self) -> u64 {
        self.complete.len_for_test()
    }
}

#[derive(Debug)]
enum BuildFailure {
    Cancelled {
        metrics: StructuralIndexBuildMetrics,
    },
    Unavailable {
        reason: &'static str,
        metrics: StructuralIndexBuildMetrics,
    },
}

fn unavailable_failure(
    started: Instant,
    reason: &'static str,
    mut metrics: StructuralIndexBuildMetrics,
) -> BuildFailure {
    metrics.elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    BuildFailure::Unavailable { reason, metrics }
}

fn cancelled_failure(started: Instant, mut metrics: StructuralIndexBuildMetrics) -> BuildFailure {
    metrics.elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    BuildFailure::Cancelled { metrics }
}

fn push_posting<K: Eq + std::hash::Hash>(
    rows: &mut HashMap<K, Vec<FactAddress>>,
    key: K,
    key_heap_bytes: usize,
    address: FactAddress,
    estimated_working_bytes: &mut u64,
) {
    match rows.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            if entry.get().last().copied() != Some(address) {
                entry.get_mut().push(address);
                *estimated_working_bytes = estimated_working_bytes
                    .saturating_add((size_of::<FactAddress>() as u64).saturating_mul(2));
            }
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            *estimated_working_bytes = estimated_working_bytes
                .saturating_add((size_of::<FactAddress>() as u64).saturating_mul(2))
                .saturating_add((size_of::<(K, Vec<FactAddress>)>() as u64).saturating_mul(2))
                .saturating_add(key_heap_bytes as u64);
            entry.insert(vec![address]);
        }
    }
}

fn working_budget_exceeded(estimated_working_bytes: u64, max_retained_bytes: u64) -> bool {
    estimated_working_bytes > max_retained_bytes.saturating_mul(BUILD_WORKING_BYTES_MULTIPLIER)
}

fn build_index(
    provider: &dyn StructuralSearchProvider,
    cancellation: &CancellationToken,
    max_retained_bytes: u64,
    source_generation: u64,
) -> Result<(SnapshotStructuralIndex, StructuralIndexBuildMetrics), BuildFailure> {
    let started = Instant::now();
    let mut files = provider.structural_files();
    files.sort();
    files.dedup();
    let mut metrics = StructuralIndexBuildMetrics::default();
    if files.len() > MAX_INDEX_FILES || u32::try_from(files.len()).is_err() {
        return Err(unavailable_failure(
            started,
            "structural index file limit exceeded",
            metrics,
        ));
    }

    let filter_word_count = match files.len().checked_mul(SOURCE_FILTER_WORDS_PER_FILE) {
        Some(count) => count,
        None => {
            return Err(unavailable_failure(
                started,
                "structural index source-filter limit exceeded",
                metrics,
            ));
        }
    };
    let filter_bytes = match filter_word_count.checked_mul(size_of::<u64>()) {
        Some(bytes) => bytes as u64,
        None => {
            return Err(unavailable_failure(
                started,
                "structural index source-filter limit exceeded",
                metrics,
            ));
        }
    };
    if filter_bytes > max_retained_bytes {
        return Err(unavailable_failure(
            started,
            "structural index retained-byte limit exceeded",
            metrics,
        ));
    }
    let mut estimated_working_bytes =
        filter_bytes.saturating_add((files.len() as u64).saturating_mul(
            (size_of::<ProjectFile>()
                + size_of::<StructuralIndexFile>() * 2
                + size_of::<(ProjectFile, u32)>() * 2) as u64,
        ));
    if working_budget_exceeded(estimated_working_bytes, max_retained_bytes) {
        return Err(unavailable_failure(
            started,
            "structural index construction-byte limit exceeded",
            metrics,
        ));
    }
    // Do not reserve provider-sized index tables until the fixed-footprint
    // preflight has proved that this snapshot is viable for the cache budget.
    let mut indexed_files = Vec::with_capacity(files.len());
    let mut file_ids = map_with_capacity(files.len());
    let mut kind_rows: HashMap<NormalizedKind, Vec<FactAddress>> = HashMap::default();
    let mut name_rows: HashMap<Box<str>, Vec<FactAddress>> = HashMap::default();
    let mut role_rows: HashMap<RolePostingKey, Vec<FactAddress>> = HashMap::default();
    let mut fact_kinds = Vec::with_capacity(files.len());
    let mut source_trigram_filters = vec![0u64; filter_word_count];

    for (file_id, file) in files.into_iter().enumerate() {
        if cancellation.is_cancelled() {
            metrics.elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            return Err(BuildFailure::Cancelled { metrics });
        }
        metrics.files = metrics.files.saturating_add(1);
        let (facts, outcome) = provider.structural_facts_with_outcome(&file);
        match outcome {
            StructuralFactsCacheOutcome::MemoryHit => {
                metrics.memory_hits = metrics.memory_hits.saturating_add(1)
            }
            StructuralFactsCacheOutcome::PersistedHydration => {
                metrics.persisted_hydrations = metrics.persisted_hydrations.saturating_add(1)
            }
            StructuralFactsCacheOutcome::Extracted => {
                metrics.extractions = metrics.extractions.saturating_add(1)
            }
            StructuralFactsCacheOutcome::Unavailable => {
                metrics.unavailable = metrics.unavailable.saturating_add(1)
            }
            StructuralFactsCacheOutcome::Unknown => {
                metrics.unknown_outcomes = metrics.unknown_outcomes.saturating_add(1)
            }
        }
        let Some(facts) = facts else {
            return Err(unavailable_failure(
                started,
                "structural index facts unavailable",
                metrics,
            ));
        };
        // FileFacts owns the exact source snapshot used to derive every span.
        // Reusing it here avoids a second provider/store source lookup during
        // construction and cannot observe a different analyzer generation.
        let source = facts.source();
        metrics.source_bytes = metrics.source_bytes.saturating_add(source.len() as u64);
        if metrics.source_bytes > MAX_INDEX_SOURCE_BYTES {
            return Err(unavailable_failure(
                started,
                "structural index source-byte limit exceeded",
                metrics,
            ));
        }
        let fact_nodes = match u32::try_from(facts.nodes().len()) {
            Ok(count) => count,
            Err(_) => {
                return Err(unavailable_failure(
                    started,
                    "structural index per-file fact limit exceeded",
                    metrics,
                ));
            }
        };
        metrics.fact_nodes = metrics.fact_nodes.saturating_add(fact_nodes as u64);
        metrics.facts_bytes = metrics.facts_bytes.saturating_add(facts.estimated_bytes());
        if metrics.fact_nodes > MAX_INDEX_FACT_NODES {
            return Err(unavailable_failure(
                started,
                "structural index fact-node limit exceeded",
                metrics,
            ));
        }
        let file_id = file_id as u32;
        file_ids.insert(file.clone(), file_id);
        indexed_files.push(StructuralIndexFile {
            file: file.clone(),
            source_bytes: source.len() as u64,
            fact_nodes,
        });
        let filter_start = file_id as usize * SOURCE_FILTER_WORDS_PER_FILE;
        if !insert_source_trigrams(
            &mut source_trigram_filters[filter_start..filter_start + SOURCE_FILTER_WORDS_PER_FILE],
            source.as_bytes(),
            cancellation,
        ) {
            return Err(cancelled_failure(started, metrics));
        }

        estimated_working_bytes = estimated_working_bytes.saturating_add(
            (facts.nodes().len() as u64)
                .saturating_mul(size_of::<NormalizedKind>() as u64)
                .saturating_mul(2),
        );
        if working_budget_exceeded(estimated_working_bytes, max_retained_bytes) {
            return Err(unavailable_failure(
                started,
                "structural index construction-byte limit exceeded",
                metrics,
            ));
        }
        let mut file_fact_kinds = Vec::with_capacity(facts.nodes().len());
        for (fact_id, node) in facts.nodes().iter().enumerate() {
            if fact_id % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
                return Err(cancelled_failure(started, metrics));
            }
            let address = FactAddress {
                file: file_id,
                fact: fact_id as u32,
            };
            file_fact_kinds.push(node.kind);
            push_posting(
                &mut kind_rows,
                node.kind,
                0,
                address,
                &mut estimated_working_bytes,
            );
            if let Some(name) = node.name {
                let name: Box<str> = name.text(facts.source()).into();
                let name_len = name.len();
                push_posting(
                    &mut name_rows,
                    name,
                    name_len,
                    address,
                    &mut estimated_working_bytes,
                );
            }
            for target in facts.roles(fact_id as u32) {
                if supports_exact_role_name_posting(target.role) {
                    let effective_name = target
                        .name
                        .or_else(|| target.node.and_then(|node| facts.node(node).name));
                    if let Some(name) = effective_name {
                        let value: Box<str> = name.text(facts.source()).into();
                        let value_len = value.len();
                        push_posting(
                            &mut role_rows,
                            RolePostingKey {
                                role: target.role,
                                value,
                                keyword: false,
                            },
                            value_len,
                            address,
                            &mut estimated_working_bytes,
                        );
                    }
                }
                if target.role == Role::Kwarg
                    && let Some(keyword) = target.keyword
                {
                    let value: Box<str> = keyword.text(facts.source()).into();
                    let value_len = value.len();
                    push_posting(
                        &mut role_rows,
                        RolePostingKey {
                            role: target.role,
                            value,
                            keyword: true,
                        },
                        value_len,
                        address,
                        &mut estimated_working_bytes,
                    );
                }
            }
            if fact_id % FACT_CANCELLATION_BATCH == 0
                && working_budget_exceeded(estimated_working_bytes, max_retained_bytes)
            {
                return Err(unavailable_failure(
                    started,
                    "structural index construction-byte limit exceeded",
                    metrics,
                ));
            }
        }
        fact_kinds.push(file_fact_kinds.into_boxed_slice());
    }

    let Some(kind_postings) = boxed_rows(kind_rows, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    let Some(name_postings) = boxed_rows(name_rows, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    let mut kind_name_rows: HashMap<KindNamePostingKey, Vec<FactAddress>> = HashMap::default();
    for (name_index, (name, all_name_rows)) in name_postings.iter().enumerate() {
        if name_index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
            return Err(cancelled_failure(started, metrics));
        }
        if all_name_rows.len() < MIN_KIND_NAME_POSTING_ROWS {
            continue;
        }
        let mut counts_by_kind: HashMap<NormalizedKind, usize> = HashMap::default();
        for (address_index, &address) in all_name_rows.iter().enumerate() {
            if address_index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
                return Err(cancelled_failure(started, metrics));
            }
            let kind = fact_kinds[address.file as usize][address.fact as usize];
            *counts_by_kind.entry(kind).or_default() += 1;
        }
        let widest = counts_by_kind.values().copied().max().unwrap_or(0);
        if widest.saturating_mul(4) > all_name_rows.len().saturating_mul(3) {
            continue;
        }
        let mut rows_by_kind: HashMap<NormalizedKind, Vec<FactAddress>> = HashMap::default();
        for (address_index, &address) in all_name_rows.iter().enumerate() {
            if address_index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
                return Err(cancelled_failure(started, metrics));
            }
            let kind = fact_kinds[address.file as usize][address.fact as usize];
            push_posting(
                &mut rows_by_kind,
                kind,
                0,
                address,
                &mut estimated_working_bytes,
            );
            if address_index % FACT_CANCELLATION_BATCH == 0
                && working_budget_exceeded(estimated_working_bytes, max_retained_bytes)
            {
                return Err(unavailable_failure(
                    started,
                    "structural index construction-byte limit exceeded",
                    metrics,
                ));
            }
        }
        for (kind, rows) in rows_by_kind {
            estimated_working_bytes = estimated_working_bytes
                .saturating_add(
                    (size_of::<(KindNamePostingKey, Vec<FactAddress>)>() as u64).saturating_mul(2),
                )
                .saturating_add(name.len() as u64);
            kind_name_rows.insert(
                KindNamePostingKey {
                    kind,
                    name: name.clone(),
                },
                rows,
            );
        }
    }
    drop(fact_kinds);
    if working_budget_exceeded(estimated_working_bytes, max_retained_bytes) {
        return Err(unavailable_failure(
            started,
            "structural index construction-byte limit exceeded",
            metrics,
        ));
    }
    let Some(kind_name_postings) = boxed_rows(kind_name_rows, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    let Some(role_postings) = boxed_rows(role_rows, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    let mut index = SnapshotStructuralIndex {
        source_generation,
        files: indexed_files.into_boxed_slice(),
        file_ids,
        kind_postings,
        name_postings,
        kind_name_postings,
        role_postings,
        source_trigram_filters: source_trigram_filters.into_boxed_slice(),
        retained_bytes: 0,
    };
    let Some(retained_bytes) = retained_bytes(&index, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    index.retained_bytes = retained_bytes;
    if index.retained_bytes > max_retained_bytes {
        return Err(unavailable_failure(
            started,
            "structural index retained-byte limit exceeded",
            metrics,
        ));
    }
    if cancellation.is_cancelled() {
        return Err(cancelled_failure(started, metrics));
    }
    metrics.elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    Ok((index, metrics))
}

fn boxed_rows<K: Eq + std::hash::Hash>(
    rows: HashMap<K, Vec<FactAddress>>,
    cancellation: &CancellationToken,
) -> Option<HashMap<K, Box<[FactAddress]>>> {
    let mut boxed = map_with_capacity(rows.len());
    for (index, (key, values)) in rows.into_iter().enumerate() {
        if index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
            return None;
        }
        debug_assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
        boxed.insert(key, values.into_boxed_slice());
    }
    (!cancellation.is_cancelled()).then_some(boxed)
}

fn retained_bytes(
    index: &SnapshotStructuralIndex,
    cancellation: &CancellationToken,
) -> Option<u64> {
    let mut bytes = (size_of::<SnapshotStructuralIndex>() as u64)
        .saturating_add((size_of::<Arc<SnapshotStructuralIndex>>() * 2) as u64)
        .saturating_add(
            (index.files.len() as u64)
                .saturating_mul(size_of::<StructuralIndexFile>() as u64)
                .saturating_add(hash_table_allocation_bytes::<ProjectFile, u32>(
                    index.file_ids.capacity(),
                ))
                .saturating_add(hash_table_allocation_bytes::<
                    NormalizedKind,
                    Box<[FactAddress]>,
                >(index.kind_postings.capacity()))
                .saturating_add(hash_table_allocation_bytes::<Box<str>, Box<[FactAddress]>>(
                    index.name_postings.capacity(),
                ))
                .saturating_add(hash_table_allocation_bytes::<
                    KindNamePostingKey,
                    Box<[FactAddress]>,
                >(index.kind_name_postings.capacity()))
                .saturating_add(hash_table_allocation_bytes::<
                    RolePostingKey,
                    Box<[FactAddress]>,
                >(index.role_postings.capacity()))
                .saturating_add(
                    (index.source_trigram_filters.len() as u64)
                        .saturating_mul(size_of::<u64>() as u64),
                ),
        );
    for (entry_index, (name, posting)) in index.name_postings.iter().enumerate() {
        if entry_index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes
            .saturating_add(name.len() as u64)
            .saturating_add((posting.len() * size_of::<FactAddress>()) as u64);
    }
    for (entry_index, (key, posting)) in index.role_postings.iter().enumerate() {
        if entry_index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes
            .saturating_add(key.value.len() as u64)
            .saturating_add((posting.len() * size_of::<FactAddress>()) as u64);
    }
    for (entry_index, (key, posting)) in index.kind_name_postings.iter().enumerate() {
        if entry_index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes
            .saturating_add(key.name.len() as u64)
            .saturating_add((posting.len() * size_of::<FactAddress>()) as u64);
    }
    for posting in index.kind_postings.values() {
        bytes = bytes.saturating_add((posting.len() * size_of::<FactAddress>()) as u64);
    }
    (!cancellation.is_cancelled()).then_some(bytes)
}

fn hash_table_allocation_bytes<K, V>(capacity: usize) -> u64 {
    // std/hashbrown stores a control byte alongside every raw bucket. Using
    // the public element capacity is conservative enough for admission while
    // avoiding dependence on the private raw-table bucket count.
    (capacity as u64).saturating_mul((size_of::<(K, V)>() + 1) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;
    use crate::analyzer::Range;
    use crate::analyzer::structural::facts::{FileFacts, NormalizedNode};
    use crate::compact_graph::CompactRows;

    struct FakeProvider {
        files: Vec<ProjectFile>,
        facts: HashMap<ProjectFile, Arc<FileFacts>>,
    }

    impl StructuralSearchProvider for FakeProvider {
        fn structural_language(&self) -> Language {
            Language::Python
        }

        fn structural_files(&self) -> Vec<ProjectFile> {
            self.files.clone()
        }

        fn structural_source(&self, file: &ProjectFile) -> Option<String> {
            self.facts.get(file).map(|facts| facts.source().to_string())
        }

        fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>> {
            self.facts.get(file).cloned()
        }

        fn structural_extraction_count(&self) -> u64 {
            0
        }

        fn structural_hydration_count(&self) -> u64 {
            0
        }

        fn structural_supports_kind(&self, _kind: NormalizedKind) -> bool {
            true
        }

        fn structural_supports_role(&self, _role: Role) -> bool {
            true
        }
    }

    fn provider() -> FakeProvider {
        let temp = tempfile::tempdir().expect("temp dir").keep();
        let root = temp.canonicalize().expect("canonical root");
        let file = ProjectFile::new(root, "app.py");
        let source = "class App:\n    pass\n".to_string();
        let facts = FileFacts::new(
            source,
            vec![0, 11],
            vec![NormalizedNode {
                kind: NormalizedKind::Class,
                range: Range {
                    start_byte: 0,
                    end_byte: 19,
                    start_line: 1,
                    end_line: 2,
                },
                parent: None,
                name: Some(super::super::facts::Span {
                    start_byte: 6,
                    end_byte: 9,
                }),
                subtree_end: 1,
            }],
            CompactRows::from_parts(vec![0, 0], Vec::new()),
        );
        FakeProvider {
            files: vec![file.clone()],
            facts: HashMap::from_iter([(file, Arc::new(facts))]),
        }
    }

    fn ambiguous_name_provider() -> FakeProvider {
        let temp = tempfile::tempdir().expect("temp dir").keep();
        let root = temp.canonicalize().expect("canonical root");
        let file = ProjectFile::new(root, "shared.py");
        let source = "Shared ".repeat(MIN_KIND_NAME_POSTING_ROWS);
        let nodes = (0..MIN_KIND_NAME_POSTING_ROWS)
            .map(|index| {
                let start_byte = index * "Shared ".len();
                NormalizedNode {
                    kind: if index < MIN_KIND_NAME_POSTING_ROWS / 2 {
                        NormalizedKind::Class
                    } else {
                        NormalizedKind::Function
                    },
                    range: Range {
                        start_byte,
                        end_byte: start_byte + "Shared".len(),
                        start_line: 1,
                        end_line: 1,
                    },
                    parent: None,
                    name: Some(super::super::facts::Span {
                        start_byte,
                        end_byte: start_byte + "Shared".len(),
                    }),
                    subtree_end: index as u32 + 1,
                }
            })
            .collect::<Vec<_>>();
        let facts = FileFacts::new(
            source,
            vec![0],
            nodes,
            CompactRows::from_parts(vec![0; MIN_KIND_NAME_POSTING_ROWS + 1], Vec::new()),
        );
        FakeProvider {
            files: vec![file.clone()],
            facts: HashMap::from_iter([(file, Arc::new(facts))]),
        }
    }

    #[test]
    fn exact_kind_and_name_postings_select_dense_addresses() {
        let provider = provider();
        let (index, metrics) =
            build_index(&provider, &CancellationToken::default(), 1024 * 1024, 0)
                .expect("index builds");
        let requirements = StructuralAccessRequirements::new_for_test(vec![
            StructuralPostingTerm::Kinds(vec![NormalizedKind::Declaration]),
            StructuralPostingTerm::ExactName("App".to_string()),
        ]);
        let selected = index
            .select(
                &requirements,
                &provider.files,
                false,
                false,
                &CancellationToken::default(),
            )
            .expect("complete scope")
            .expect("indexed requirements");

        assert_eq!(selected.estimate.candidate_files, 1);
        assert_eq!(selected.estimate.candidate_facts, 1);
        assert_eq!(selected.facts_for(&provider.files[0]), [0]);
        assert_eq!(metrics.fact_nodes, 1);
        assert!(index.retained_bytes() > 0);
    }

    #[test]
    fn non_redundant_kind_name_posting_is_selected() {
        let provider = ambiguous_name_provider();
        let (index, _) = build_index(&provider, &CancellationToken::default(), 1024 * 1024, 0)
            .expect("index builds");
        let requirements = StructuralAccessRequirements::new_for_test(vec![
            StructuralPostingTerm::Kinds(vec![NormalizedKind::Class]),
            StructuralPostingTerm::ExactName("Shared".to_string()),
        ]);
        let selected = index
            .select(
                &requirements,
                &provider.files,
                false,
                false,
                &CancellationToken::default(),
            )
            .expect("complete scope")
            .expect("indexed requirements");

        assert_eq!(selected.selected, "kind_name");
        assert_eq!(
            selected.estimate.candidate_facts,
            (MIN_KIND_NAME_POSTING_ROWS / 2) as u64
        );
        assert_eq!(
            selected.facts_for(&provider.files[0]),
            (0..MIN_KIND_NAME_POSTING_ROWS as u32 / 2).collect::<Vec<_>>()
        );
    }

    #[test]
    fn source_filter_has_no_false_negatives_and_short_anchors_verify() {
        let provider = provider();
        let (index, _) = build_index(&provider, &CancellationToken::default(), 1024 * 1024, 0)
            .expect("index builds");
        let file = &provider.files[0];

        assert_eq!(
            index.source_may_contain(file, &["App".to_string()]),
            Some(true)
        );
        assert_eq!(
            index.source_may_contain(file, &["zzzz-absent".to_string()]),
            Some(false)
        );
        assert_eq!(
            index.source_may_contain(file, &["z".to_string()]),
            Some(true)
        );
    }

    #[test]
    fn complete_index_is_reused_by_the_snapshot_owner() {
        let provider = provider();
        let cache = SnapshotStructuralIndexCache::new(1024 * 1024);
        let cancellation = CancellationToken::default();

        let StructuralIndexAcquisition::Ready {
            index: first,
            lifecycle: StructuralIndexLifecycle::Built,
            ..
        } = cache.acquire(&provider, &cancellation)
        else {
            panic!("first acquisition must build")
        };
        let StructuralIndexAcquisition::Ready {
            index: second,
            lifecycle: StructuralIndexLifecycle::Hit,
            ..
        } = cache.acquire(&provider, &cancellation)
        else {
            panic!("second acquisition must hit")
        };

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(cache.len_for_test(), 1);
    }

    #[test]
    fn cancelled_build_never_publishes() {
        let provider = provider();
        let cache = SnapshotStructuralIndexCache::new(1024 * 1024);
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        assert!(matches!(
            cache.acquire(&provider, &cancellation),
            StructuralIndexAcquisition::Cancelled { .. }
        ));
        assert_eq!(cache.len_for_test(), 0);
    }

    #[test]
    fn cancellation_after_partial_construction_never_publishes() {
        let provider = provider();
        let cache = SnapshotStructuralIndexCache::new(1024 * 1024);
        let cancellation = CancellationToken::cancel_after_checks_for_test(6);

        assert!(matches!(
            cache.acquire(&provider, &cancellation),
            StructuralIndexAcquisition::Cancelled { .. }
        ));
        assert_eq!(cache.len_for_test(), 0);
    }

    #[test]
    fn fixed_footprint_over_budget_never_publishes() {
        let provider = provider();
        let cache = SnapshotStructuralIndexCache::new(1);

        assert!(matches!(
            cache.acquire(&provider, &CancellationToken::default()),
            StructuralIndexAcquisition::Unavailable {
                reason: "structural index retained-byte limit exceeded",
                ..
            }
        ));
        assert_eq!(cache.len_for_test(), 0);
    }

    #[test]
    fn unavailable_provider_facts_never_publish() {
        let mut provider = provider();
        provider.facts.clear();
        let cache = SnapshotStructuralIndexCache::new(1024 * 1024);

        assert!(matches!(
            cache.acquire(&provider, &CancellationToken::default()),
            StructuralIndexAcquisition::Unavailable {
                reason: "structural index facts unavailable",
                ..
            }
        ));
        assert_eq!(cache.len_for_test(), 0);
    }

    #[test]
    fn cancelled_candidate_selection_stops_without_rows() {
        let provider = ambiguous_name_provider();
        let (index, _) = build_index(&provider, &CancellationToken::default(), 1024 * 1024, 0)
            .expect("index builds");
        let requirements = StructuralAccessRequirements::new_for_test(vec![
            StructuralPostingTerm::Kinds(vec![NormalizedKind::Class]),
            StructuralPostingTerm::ExactName("Shared".to_string()),
        ]);
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        assert_eq!(
            index
                .select(&requirements, &provider.files, false, true, &cancellation,)
                .expect_err("selection must observe cancellation"),
            "structural index selection cancelled"
        );
    }

    #[test]
    fn retained_census_grows_with_posting_content() {
        let simple = provider();
        let ambiguous = ambiguous_name_provider();
        let (simple, _) = build_index(&simple, &CancellationToken::default(), 1024 * 1024, 0)
            .expect("simple index builds");
        let (ambiguous, _) = build_index(&ambiguous, &CancellationToken::default(), 1024 * 1024, 0)
            .expect("larger index builds");

        assert!(ambiguous.retained_bytes() > simple.retained_bytes());
    }
}
