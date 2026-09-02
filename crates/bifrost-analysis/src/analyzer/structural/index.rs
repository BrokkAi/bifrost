//! Immutable snapshot-local postings for structural seed selection.
//!
//! The matcher remains the semantic authority. Every posting is a positive,
//! sound candidate relation over normalized facts; query negatives, regexes,
//! containment, and nested predicates are always verified by the matcher.

use super::facts::FileFacts;
use super::index_query::{
    SourceAnchorGroup, StructuralAccessPathEstimate, StructuralAccessPathKind,
    StructuralAccessRequirements, StructuralPostingEstimate, StructuralPostingTerm,
    supports_exact_role_name_posting,
};
use super::kinds::{NormalizedKind, Role};
use super::provider::{StructuralFactProvider, StructuralFactsCacheOutcome, StructuralIndexCensus};
use crate::ProjectFile;
use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::invalidation::{
    ArtifactVerdict, ArtifactVerdictLog, DerivedArtifactId, DerivedArtifactKind,
    InvalidationReason, RetentionReason,
};
use crate::analyzer::semantic::ids::StableDigest;
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, map_with_capacity};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use rayon::prelude::*;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// Version 2: `collection_literal` facts plus `iterable`/`elements` role
// postings change derived index content (#2647).
// Version 3: TypeScript `parameter` facts plus their decorator role postings
// change derived index content (#2644).
// Version 4: JSX element/attribute and object-property facts plus their
// tag/attribute/child/key/value role postings change derived index content (#2645).
// Version 5: `module` facts for module and namespace declarations change
// derived index content (#2518).
pub const STRUCTURAL_INDEX_REPRESENTATION_VERSION: u32 = 5;
const MAX_INDEX_FILES: usize = 1_000_000;
const MAX_INDEX_FACT_NODES: u64 = 100_000_000;
const MAX_INDEX_SOURCE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FACT_CANCELLATION_BATCH: usize = 4096;
const SOURCE_CANCELLATION_BATCH: usize = 64 * 1024;
const SOURCE_FILTER_WORDS_PER_FILE: usize = 64;
const MIN_KIND_NAME_POSTING_ROWS: usize = 128;
const BUILD_WORKING_BYTES_MULTIPLIER: u64 = 3;
/// Retained index bytes charged per indexed source byte, and per indexed file.
///
/// The posting arrays, their name keys, and the per-file trigram filter are
/// what a finished index retains, and all three grow with the source. Measured
/// on this repository (release build, warm cache) by building every provider's
/// index with the budget lifted; retained bytes per source byte, and the
/// residual per file once two bytes per source byte are charged:
///
/// | language   | files | source bytes | retained bytes | per source byte |
/// |------------|-------|--------------|----------------|-----------------|
/// | Rust       |  1998 |   64_535_673 |    103_636_999 |            1.61 |
/// | JavaScript |   104 |      999_921 |      2_115_675 |            2.12 |
/// | Python     |    81 |      803_333 |      1_431_105 |            1.78 |
/// | TypeScript |    62 |      423_586 |        859_208 |            2.03 |
/// | Go         |    12 |       69_223 |        162_805 |            2.35 |
/// | C#         |    10 |        7_241 |         26_310 |            3.63 |
/// | Ruby       |    20 |        2_457 |         21_814 |            8.88 |
///
/// The small providers are dominated by their per-file cost, not by their
/// source: one `StructuralIndexFile`, one hash-table slot per posting map, and
/// 512 bytes of trigram filter. Two bytes per source byte plus four kilobytes
/// per file bounds every language measured from above, most closely Go at
/// 1.15x and Rust at 1.32x, so the estimate rejects only what really cannot be
/// retained.
const RETAINED_INDEX_BYTES_PER_SOURCE_BYTE: u64 = 2;
const RETAINED_INDEX_BYTES_PER_FILE: u64 = 4096;
/// The share of the memo budget one provider keeps even when its source is a
/// rounding error of the workspace's.
///
/// The per-file term above dominates a provider with a handful of tiny files:
/// Ruby's twenty files here cost 21_814 retained bytes for 2_457 source bytes,
/// which is 0.004% of this workspace's source and would apportion to under ten
/// kilobytes. A floor keeps a small provider indexed instead of scanning
/// forever, and ten of them cost 10/64 of the memo budget, so the apportioned
/// parts plus the floors stay near one budget rather than one budget per
/// provider.
const MINIMUM_INDEX_BUDGET_DIVISOR: u64 = 64;
/// The share a provider gets when it cannot census itself at all.
///
/// This is the fixed share every provider used before the workspace could size
/// them, kept for third-party providers and for a project whose listing cannot
/// be read.
const UNCENSUSED_INDEX_BUDGET_DIVISOR: u64 = 4;
/// Files whose facts are acquired in parallel per assembly step during index
/// construction; bounds the transient working set the parallel prefetch can
/// hold beyond the provider's own facts cache.
const INDEX_BUILD_ACQUISITION_CHUNK: usize = 256;

/// The identity of one immutable posting set.
///
/// Before #2449 the second field was the project's process-local
/// `analysis_generation()`, so every accepted change in the process retired
/// every language's postings. It is now the content identity of exactly the
/// files this provider indexes: an edit to another language leaves it alone, a
/// no-op update leaves it alone, and a grammar or configuration change rotates
/// it because both are folded into the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StructuralIndexKey {
    representation_version: u32,
    content_identity: WorkspaceContentIdentity,
}

impl StructuralIndexKey {
    const ARTIFACT_DOMAIN: &[u8] = b"bifrost-structural-index-key:v1";

    fn new(content_identity: WorkspaceContentIdentity) -> Self {
        Self {
            representation_version: STRUCTURAL_INDEX_REPRESENTATION_VERSION,
            content_identity,
        }
    }

    fn artifact(self) -> DerivedArtifactId {
        let mut hasher = CanonicalHasher::new(Self::ARTIFACT_DOMAIN);
        hasher.field(
            "representation_version",
            &self.representation_version.to_be_bytes(),
        );
        hasher.field("content", self.content_identity.digest().as_bytes());
        DerivedArtifactId::new(
            DerivedArtifactKind::StructuralIndex,
            StableDigest::from_array(hasher.finish()),
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FactAddress {
    pub file: u32,
    pub fact: u32,
}

#[derive(Debug, Clone)]
pub struct StructuralIndexFile {
    pub file: ProjectFile,
    pub source_bytes: u64,
    pub fact_nodes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RolePostingKey {
    role: Role,
    value: Box<str>,
    keyword: bool,
}

type KindNamePostings = HashMap<Box<str>, Vec<(NormalizedKind, Box<[FactAddress]>)>>;
type MutableKindNamePostings = HashMap<Box<str>, Vec<(NormalizedKind, Vec<FactAddress>)>>;

#[derive(Debug)]
pub struct SnapshotStructuralIndex {
    content_identity: WorkspaceContentIdentity,
    files: Box<[StructuralIndexFile]>,
    file_ids: HashMap<ProjectFile, u32>,
    kind_postings: HashMap<NormalizedKind, Box<[FactAddress]>>,
    name_postings: HashMap<Box<str>, Box<[FactAddress]>>,
    /// Only combinations that are strictly narrower than their name posting.
    /// A name used by exactly one actual kind is already represented optimally
    /// by `name_postings` and is not duplicated here.
    kind_name_postings: KindNamePostings,
    role_postings: HashMap<RolePostingKey, Box<[FactAddress]>>,
    source_trigram_filters: Box<[u64]>,
    retained_bytes: u64,
}

impl SnapshotStructuralIndex {
    pub const fn content_identity(&self) -> WorkspaceContentIdentity {
        self.content_identity
    }

    pub fn file(&self, file: &ProjectFile) -> Option<&StructuralIndexFile> {
        let id = self.file_ids.get(file).copied()?;
        self.files.get(id as usize)
    }

    pub fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Returns false only when at least one required anchor group has every
    /// alternative definitely absent from the indexed source. Hash collisions
    /// can return true for an absent anchor, in which case the caller
    /// verifies with `str::contains`.
    pub fn source_may_contain(
        &self,
        file: &ProjectFile,
        required_anchors: &[SourceAnchorGroup],
    ) -> Option<bool> {
        let file_id = self.file_ids.get(file).copied()? as usize;
        let start = file_id.checked_mul(SOURCE_FILTER_WORDS_PER_FILE)?;
        let end = start.checked_add(SOURCE_FILTER_WORDS_PER_FILE)?;
        let filter = self.source_trigram_filters.get(start..end)?;
        Some(required_anchors.iter().all(|group| {
            group
                .alternatives()
                .iter()
                .any(|anchor| trigram_filter_may_contain(filter, anchor.as_bytes()))
        }))
    }

    pub fn select(
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
        let full_provider_scope = scoped_ids.len() == self.files.len()
            && scoped_ids
                .iter()
                .copied()
                .enumerate()
                .all(|(index, file)| usize::try_from(file).ok() == Some(index));

        let mut terms =
            self.selection_terms(requirements, &scoped_ids, full_provider_scope, cancellation)?;
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
        full_provider_scope: bool,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SelectionTerm<'a>>, &'static str> {
        let kinds = requirements.terms().iter().find_map(|term| match term {
            StructuralPostingTerm::Kinds(kinds) => Some(kinds.as_slice()),
            _ => None,
        });
        let exact_names = requirements.terms().iter().find_map(|term| match term {
            StructuralPostingTerm::ExactName(names) => Some(names.as_slice()),
            _ => None,
        });
        let combined = if let Some((kinds, names)) = kinds.zip(exact_names) {
            self.kind_name_term(
                kinds,
                names,
                scoped_files,
                full_provider_scope,
                cancellation,
            )?
        } else {
            None
        };
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
            terms.push(self.term(term, scoped_files, full_provider_scope, cancellation)?);
        }
        Ok(terms)
    }

    fn kind_name_term<'a>(
        &'a self,
        requested_kinds: &[NormalizedKind],
        names: &[String],
        scoped_files: &[u32],
        full_provider_scope: bool,
        cancellation: &CancellationToken,
    ) -> Result<Option<SelectionTerm<'a>>, &'static str> {
        // Names whose sole actual kind matches are represented only by
        // `name_postings`, so the combined term is sound only when every
        // requested name has a kind/name combination; otherwise fall back to
        // the separate kind and name terms.
        let mut postings = Vec::new();
        for name in names {
            let Some(combinations) = self.kind_name_postings.get(name.as_str()) else {
                return Ok(None);
            };
            postings.extend(
                combinations
                    .iter()
                    .filter(|(kind, _)| {
                        requested_kinds
                            .iter()
                            .any(|requested| kind.satisfies(*requested))
                    })
                    .map(|(_, posting)| posting.as_ref()),
            );
        }
        SelectionTerm::new(
            "kind_name",
            postings,
            scoped_files,
            full_provider_scope,
            cancellation,
        )
        .map(Some)
    }

    fn term<'a>(
        &'a self,
        term: &StructuralPostingTerm,
        scoped_files: &[u32],
        full_provider_scope: bool,
        cancellation: &CancellationToken,
    ) -> Result<SelectionTerm<'a>, &'static str> {
        let postings = match term {
            StructuralPostingTerm::Kinds(kinds) => self
                .kind_postings
                .iter()
                .filter(|(actual, _)| kinds.iter().any(|requested| actual.satisfies(*requested)))
                .map(|(_, posting)| posting.as_ref())
                .collect(),
            StructuralPostingTerm::ExactName(names) => names
                .iter()
                .filter_map(|name| self.name_postings.get(name.as_str()))
                .map(|posting| posting.as_ref())
                .collect(),
            StructuralPostingTerm::RoleName { role, names } => names
                .iter()
                .filter_map(|name| {
                    self.role_postings.get(&RolePostingKey {
                        role: *role,
                        value: name.as_str().into(),
                        keyword: false,
                    })
                })
                .map(|posting| posting.as_ref())
                .collect(),
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
        SelectionTerm::new(
            term.label(),
            postings,
            scoped_files,
            full_provider_scope,
            cancellation,
        )
    }
}

struct SelectionTerm<'a> {
    label: &'static str,
    postings: Vec<ScopedPosting<'a>>,
    estimated_rows: u64,
}

enum ScopedPosting<'a> {
    Full(&'a [FactAddress]),
    Filtered(Vec<FactAddress>),
}

impl ScopedPosting<'_> {
    fn as_slice(&self) -> &[FactAddress] {
        match self {
            Self::Full(posting) => posting,
            Self::Filtered(posting) => posting,
        }
    }
}

impl<'a> SelectionTerm<'a> {
    fn new(
        label: &'static str,
        postings: Vec<&'a [FactAddress]>,
        scoped_files: &[u32],
        full_provider_scope: bool,
        cancellation: &CancellationToken,
    ) -> Result<Self, &'static str> {
        let mut scoped_postings = Vec::with_capacity(postings.len());
        for posting in postings {
            let posting = if full_provider_scope {
                ScopedPosting::Full(posting)
            } else {
                let Some(rows) = scoped_posting_rows(posting, scoped_files, cancellation) else {
                    return Err("structural index selection cancelled");
                };
                ScopedPosting::Filtered(rows)
            };
            scoped_postings.push(posting);
        }
        let postings = scoped_postings;
        let estimated_rows = postings.iter().fold(0u64, |total, posting| {
            total.saturating_add(posting.as_slice().len() as u64)
        });
        Ok(Self {
            label,
            postings,
            estimated_rows,
        })
    }

    fn contains(&self, address: FactAddress) -> bool {
        self.postings
            .iter()
            .any(|posting| posting.as_slice().binary_search(&address).is_ok())
    }

    fn materialize(
        &self,
        _scoped_files: &[u32],
        cancellation: &CancellationToken,
    ) -> Result<Vec<FactAddress>, &'static str> {
        let capacity = usize::try_from(self.estimated_rows)
            .map_err(|_| "structural candidate cardinality exceeds platform limit")?;
        let mut rows = Vec::with_capacity(capacity);
        let mut positions = vec![0usize; self.postings.len()];
        loop {
            let next = self
                .postings
                .iter()
                .zip(&positions)
                .filter_map(|(posting, &position)| posting.as_slice().get(position).copied())
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
            for (posting, position) in self.postings.iter().zip(&mut positions) {
                while posting.as_slice().get(*position).copied() == Some(next) {
                    *position += 1;
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

fn scoped_posting_rows(
    posting: &[FactAddress],
    scoped_files: &[u32],
    cancellation: &CancellationToken,
) -> Option<Vec<FactAddress>> {
    let mut rows = Vec::new();
    let mut scope_index = 0usize;
    for (index, &address) in posting.iter().enumerate() {
        if index.is_multiple_of(FACT_CANCELLATION_BATCH) && cancellation.is_cancelled() {
            return None;
        }
        while scoped_files
            .get(scope_index)
            .is_some_and(|file| *file < address.file)
        {
            scope_index += 1;
        }
        let Some(&scoped_file) = scoped_files.get(scope_index) else {
            break;
        };
        if scoped_file == address.file {
            rows.push(address);
        }
    }
    (!cancellation.is_cancelled()).then_some(rows)
}

#[derive(Debug)]
pub struct StructuralCandidateSet {
    pub selected: String,
    pub estimate: StructuralAccessPathEstimate,
    by_file: HashMap<ProjectFile, Vec<u32>>,
}

impl StructuralCandidateSet {
    pub fn facts_for(&self, file: &ProjectFile) -> &[u32] {
        self.by_file.get(file).map_or(&[], Vec::as_slice)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StructuralIndexBuildMetrics {
    pub files: u64,
    pub source_bytes: u64,
    pub fact_nodes: u64,
    pub facts_bytes: u64,
    pub memory_hits: u64,
    pub persisted_hydrations: u64,
    pub extractions: u64,
    pub unavailable: u64,
    pub unknown_outcomes: u64,
    pub elapsed_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralIndexLifecycle {
    Hit,
    Built,
}

pub enum StructuralIndexAcquisition {
    Ready {
        index: Arc<SnapshotStructuralIndex>,
        lifecycle: StructuralIndexLifecycle,
        wait: CompleteValueWait,
        build: StructuralIndexBuildMetrics,
    },
    Unavailable {
        reason: Arc<str>,
        wait: CompleteValueWait,
        build: StructuralIndexBuildMetrics,
    },
    Cancelled {
        wait: CompleteValueWait,
        build: StructuralIndexBuildMetrics,
    },
}

/// Snapshot-owned complete postings, keyed by the content they were built from.
///
/// The cache outlives an analyzer update (#2449): `from_state` hands the next
/// generation this same cache instead of an empty one, because a key nothing
/// asks for again is retired by the byte budget rather than by a rotation that
/// also discards the keys that are still exact.
#[derive(Clone)]
pub struct SnapshotStructuralIndexCache {
    complete: CompleteValueCache<StructuralIndexKey, SnapshotStructuralIndex>,
    /// The whole memo budget every structural provider apportions between
    /// them. One provider's own budget is derived from it per acquisition,
    /// because only the provider's census says how much of the workspace's
    /// source this provider is.
    memo_budget_bytes: u64,
    auto_reuse_content: Arc<Mutex<Option<WorkspaceContentIdentity>>>,
    rejected: Arc<Mutex<Option<StructuralIndexRejection>>>,
    verdicts: Arc<ArtifactVerdictLog>,
}

/// What one provider's posting index would cost, and what it is allowed to
/// cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProviderIndexBudget {
    estimated_retained_bytes: u64,
    max_retained_bytes: u64,
}

/// Size one provider's posting index against the workspace it indexes.
///
/// A fixed per-provider share made the budget wrong in both directions on this
/// repository (#2879): 64 MiB was thirteen times what nine of the ten
/// providers retained together, and two thirds of what the Rust provider
/// needed, so the one index worth having was the one rejected.
///
/// The apportioned term gives a provider the share of the memo budget its own
/// source is of the workspace's, so the apportioned parts sum to exactly one
/// memo budget however many providers there are. The floor keeps a provider
/// whose index costs per file rather than per byte from being apportioned out
/// of existence, and adds at most one sixty-fourth of the budget per provider
/// on top. The estimate caps both, because a provider is never handed more
/// budget than its own index can use, so the retained total is bounded by the
/// workspace's own size whenever that is the smaller number.
fn provider_index_budget(
    memo_budget_bytes: u64,
    census: StructuralIndexCensus,
) -> ProviderIndexBudget {
    let estimated_retained_bytes = census
        .source_bytes
        .saturating_mul(RETAINED_INDEX_BYTES_PER_SOURCE_BYTE)
        .saturating_add(census.files.saturating_mul(RETAINED_INDEX_BYTES_PER_FILE));
    // A provider's own source is part of the workspace's, so the share is at
    // most one even when a stale listing says otherwise; a workspace with no
    // source at all apportions nothing and leaves the floor to decide.
    let workspace_source_bytes = census
        .workspace_source_bytes
        .max(census.source_bytes)
        .max(1);
    let apportioned =
        memo_budget_bytes.saturating_mul(census.source_bytes) / workspace_source_bytes;
    ProviderIndexBudget {
        estimated_retained_bytes,
        max_retained_bytes: estimated_retained_bytes
            .min(apportioned.max(memo_budget_bytes / MINIMUM_INDEX_BUDGET_DIVISOR)),
    }
}

/// Request-scoped structural-index lifecycle shared by serial and parallel
/// seed branches. Deferred Auto observations are published only after the
/// whole request finishes, and the workspace content the selection was made
/// against remains guarded through replay and rendering.
#[derive(Clone, Default)]
pub struct QueryStructuralIndexSession {
    deferred_auto:
        Arc<Mutex<HashMap<(usize, WorkspaceContentIdentity), SnapshotStructuralIndexCache>>>,
    selected_content: Arc<Mutex<Option<WorkspaceContentIdentity>>>,
    inconsistent_selection: Arc<AtomicBool>,
}

impl QueryStructuralIndexSession {
    pub fn defer_auto_build(
        &self,
        cache: &SnapshotStructuralIndexCache,
        content_identity: WorkspaceContentIdentity,
    ) {
        self.deferred_auto
            .lock()
            .expect("structural index Auto deferral lock poisoned")
            .entry((cache.owner_identity(), content_identity))
            .or_insert_with(|| cache.clone());
    }

    pub fn publish_auto_observations(&self) {
        let deferred = std::mem::take(
            &mut *self
                .deferred_auto
                .lock()
                .expect("structural index Auto deferral lock poisoned"),
        );
        for ((_, content_identity), cache) in deferred {
            cache.record_auto_reuse_opportunity(content_identity);
        }
    }

    pub fn record_selection(&self, content_identity: WorkspaceContentIdentity) {
        let mut selected = self
            .selected_content
            .lock()
            .expect("structural index content guard lock poisoned");
        match *selected {
            Some(existing) if existing != content_identity => {
                self.inconsistent_selection.store(true, Ordering::Release);
            }
            Some(_) => {}
            None => *selected = Some(content_identity),
        }
    }

    pub fn selections_are_current(
        &self,
        is_current: impl FnOnce(WorkspaceContentIdentity) -> bool,
    ) -> bool {
        if self.inconsistent_selection.load(Ordering::Acquire) {
            return false;
        }
        self.selected_content
            .lock()
            .expect("structural index content guard lock poisoned")
            .is_none_or(is_current)
    }
}

#[derive(Debug, Clone)]
struct StructuralIndexRejection {
    key: StructuralIndexKey,
    reason: Arc<str>,
}

impl SnapshotStructuralIndexCache {
    /// The ready cache holds whatever the per-provider budgets admit, so its
    /// own capacity is the whole memo budget those budgets are apportioned
    /// from: a provider's index is never larger than its budget, and the
    /// budgets are what bounds the total.
    pub fn new(memo_budget_bytes: u64) -> Self {
        Self {
            complete: CompleteValueCache::<StructuralIndexKey, SnapshotStructuralIndex>::new(
                memo_budget_bytes,
                |_, index| index.retained_bytes().clamp(1, u32::MAX as u64) as u32,
            ),
            memo_budget_bytes,
            auto_reuse_content: Arc::new(Mutex::new(None)),
            rejected: Arc::new(Mutex::new(None)),
            verdicts: Arc::new(ArtifactVerdictLog::default()),
        }
    }

    pub fn verdicts(&self) -> &ArtifactVerdictLog {
        &self.verdicts
    }

    fn rejection_for(&self, key: StructuralIndexKey) -> Option<Arc<str>> {
        self.rejected
            .lock()
            .expect("structural index rejection lock poisoned")
            .as_ref()
            .filter(|rejection| rejection.key == key)
            .map(|rejection| Arc::clone(&rejection.reason))
    }

    /// Retain the most recent rejection.
    ///
    /// Source generations were ordered, so the old rule kept the newest by
    /// comparison. Content identities are not ordered and must not be: the
    /// question a rejection answers is "did the build for *this exact* content
    /// fail", and `rejection_for` already compares the whole key, so the last
    /// writer is the right one to keep.
    fn record_rejection(&self, key: StructuralIndexKey, reason: Arc<str>) {
        *self
            .rejected
            .lock()
            .expect("structural index rejection lock poisoned") =
            Some(StructuralIndexRejection { key, reason });
    }

    pub fn acquire(
        &self,
        provider: &dyn StructuralFactProvider,
        cancellation: &CancellationToken,
    ) -> StructuralIndexAcquisition {
        let Some(content_identity) = provider.structural_content_identity() else {
            self.verdicts.record(ArtifactVerdict::Invalidated(
                InvalidationReason::ContentIdentityEvidenceMissing {
                    artifact: StructuralIndexKey::new(WorkspaceContentIdentity::unattested())
                        .artifact(),
                },
            ));
            return StructuralIndexAcquisition::Unavailable {
                reason: Arc::from(
                    "structural provider states no content identity for its analyzed files",
                ),
                wait: CompleteValueWait::default(),
                build: StructuralIndexBuildMetrics::default(),
            };
        };
        let key = StructuralIndexKey::new(content_identity);
        if let Some(reason) = self.rejection_for(key) {
            return StructuralIndexAcquisition::Unavailable {
                reason,
                wait: CompleteValueWait::default(),
                build: StructuralIndexBuildMetrics::default(),
            };
        }
        let (acquisition, wait) = self.complete.acquire(&key, cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                self.verdicts.record(ArtifactVerdict::Retained(
                    RetentionReason::InputsUnchanged {
                        artifact: key.artifact(),
                    },
                ));
                StructuralIndexAcquisition::Ready {
                    index: value,
                    lifecycle: StructuralIndexLifecycle::Hit,
                    wait,
                    build: StructuralIndexBuildMetrics::default(),
                }
            }
            CompleteValueAcquisition::Cancelled => StructuralIndexAcquisition::Cancelled {
                wait,
                build: StructuralIndexBuildMetrics::default(),
            },
            CompleteValueAcquisition::Rejected => StructuralIndexAcquisition::Unavailable {
                reason: self.rejection_for(key).unwrap_or_else(|| {
                    Arc::from("structural index construction rejected by same-key leader")
                }),
                wait,
                build: StructuralIndexBuildMetrics::default(),
            },
            CompleteValueAcquisition::Leader { permit } => {
                if let Some(reason) = self.rejection_for(key) {
                    permit.publish_rejected();
                    return StructuralIndexAcquisition::Unavailable {
                        reason,
                        wait,
                        build: StructuralIndexBuildMetrics::default(),
                    };
                }
                self.verdicts.record(ArtifactVerdict::Invalidated(
                    InvalidationReason::NoRetainedArtifact {
                        artifact: key.artifact(),
                    },
                ));
                let mut files = provider.structural_files();
                files.sort();
                files.dedup();
                // Size this provider's budget against the workspace it shares,
                // and do not spend a whole-snapshot build on postings that
                // budget could never retain. The census prices the same files
                // the build would walk, so a provider whose index cannot fit
                // is rejected here for zero build work rather than after the
                // build measures the finished index (#2879).
                let max_retained_bytes = match provider.structural_index_census(&files) {
                    Some(census) => {
                        let budget = provider_index_budget(self.memo_budget_bytes, census);
                        crate::profiling::note_with(|| {
                            format!(
                                "structural-index preflight language={:?} census={census:?} \
                                 budget={budget:?}",
                                provider.structural_language()
                            )
                        });
                        if budget.estimated_retained_bytes > budget.max_retained_bytes {
                            let reason: Arc<str> = Arc::from(format!(
                                "structural index estimated retained-byte limit exceeded: \
                                 {} estimated for {} files and {} source bytes exceeds the {} \
                                 byte budget this provider holds of {} shared bytes",
                                budget.estimated_retained_bytes,
                                census.files,
                                census.source_bytes,
                                budget.max_retained_bytes,
                                self.memo_budget_bytes
                            ));
                            self.record_rejection(key, Arc::clone(&reason));
                            permit.publish_rejected();
                            return StructuralIndexAcquisition::Unavailable {
                                reason,
                                wait,
                                build: StructuralIndexBuildMetrics::default(),
                            };
                        }
                        budget.max_retained_bytes
                    }
                    None => self.memo_budget_bytes / UNCENSUSED_INDEX_BUDGET_DIVISOR,
                };
                match build_index(
                    provider,
                    files,
                    cancellation,
                    max_retained_bytes,
                    key.content_identity,
                ) {
                    Ok((_index, build)) if cancellation.is_cancelled() => {
                        StructuralIndexAcquisition::Cancelled { wait, build }
                    }
                    Ok((_index, build))
                        if provider.structural_content_identity() != Some(key.content_identity) =>
                    {
                        let reason: Arc<str> = Arc::from(
                            "structural analyzed content changed during index construction",
                        );
                        self.record_rejection(key, Arc::clone(&reason));
                        permit.publish_rejected();
                        StructuralIndexAcquisition::Unavailable {
                            reason,
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
                        self.record_rejection(key, Arc::clone(&reason));
                        permit.publish_rejected();
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

    pub fn get_ready(
        &self,
        content_identity: WorkspaceContentIdentity,
        cancellation: &CancellationToken,
    ) -> Option<Arc<SnapshotStructuralIndex>> {
        let ready = self
            .complete
            .get_ready(&StructuralIndexKey::new(content_identity), cancellation);
        self.verdicts.record(match ready {
            Some(_) => ArtifactVerdict::Retained(RetentionReason::InputsUnchanged {
                artifact: StructuralIndexKey::new(content_identity).artifact(),
            }),
            None => ArtifactVerdict::Invalidated(InvalidationReason::NoRetainedArtifact {
                artifact: StructuralIndexKey::new(content_identity).artifact(),
            }),
        });
        ready
    }

    /// Auto avoids paying a whole-snapshot construction cost for a query that
    /// may run only once. The first viable request records reuse interest and
    /// scans; a subsequent request may build. Forced indexed tests bypass this
    /// policy and exercise construction directly.
    pub fn auto_reuse_observed(&self, content_identity: WorkspaceContentIdentity) -> bool {
        *self
            .auto_reuse_content
            .lock()
            .expect("structural index Auto reuse lock poisoned")
            == Some(content_identity)
    }

    /// Whether a build for exactly this content is already running.
    ///
    /// A request that asks this has a cheaper answer available -- the scan the
    /// index would have accelerated -- so it takes the scan instead of parking
    /// behind a whole-snapshot build it did not start (#2879).
    pub fn build_in_flight(&self, content_identity: WorkspaceContentIdentity) -> bool {
        self.complete
            .build_in_flight(&StructuralIndexKey::new(content_identity))
    }

    /// Whether a structural query has asked this provider's index to be reused
    /// and nothing has answered yet: no retained index, and no deterministic
    /// rejection.
    ///
    /// This is what the background warm builds and what leaves an analyzer
    /// generation not yet warm. It is deliberately not "has an index": a
    /// provider nothing has queried has nothing outstanding, and a provider
    /// whose index was rejected for its budget has been answered.
    pub fn auto_build_outstanding(&self, content_identity: WorkspaceContentIdentity) -> bool {
        let key = StructuralIndexKey::new(content_identity);
        self.auto_reuse_observed(content_identity)
            && self.rejection_for(key).is_none()
            && self
                .complete
                .get_ready(&key, &CancellationToken::default())
                .is_none()
    }

    fn record_auto_reuse_opportunity(&self, content_identity: WorkspaceContentIdentity) {
        *self
            .auto_reuse_content
            .lock()
            .expect("structural index Auto reuse lock poisoned") = Some(content_identity);
    }

    fn owner_identity(&self) -> usize {
        Arc::as_ptr(&self.auto_reuse_content) as usize
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
        reason: Arc<str>,
        metrics: StructuralIndexBuildMetrics,
    },
}

fn unavailable_failure(
    started: Instant,
    reason: impl Into<Arc<str>>,
    mut metrics: StructuralIndexBuildMetrics,
) -> BuildFailure {
    metrics.elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    BuildFailure::Unavailable {
        reason: reason.into(),
        metrics,
    }
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

fn push_string_posting(
    rows: &mut HashMap<Box<str>, Vec<FactAddress>>,
    value: &str,
    address: FactAddress,
    estimated_working_bytes: &mut u64,
    max_retained_bytes: u64,
) -> bool {
    if let Some(posting) = rows.get_mut(value) {
        if posting.last().copied() != Some(address) {
            let projected = estimated_working_bytes
                .saturating_add((size_of::<FactAddress>() as u64).saturating_mul(2));
            if working_budget_exceeded(projected, max_retained_bytes) {
                return false;
            }
            posting.push(address);
            *estimated_working_bytes = projected;
        }
        return true;
    }

    let projected = estimated_working_bytes
        .saturating_add((size_of::<FactAddress>() as u64).saturating_mul(2))
        .saturating_add((size_of::<(Box<str>, Vec<FactAddress>)>() as u64).saturating_mul(2))
        .saturating_add(value.len() as u64);
    if working_budget_exceeded(projected, max_retained_bytes) {
        return false;
    }
    rows.insert(value.into(), vec![address]);
    *estimated_working_bytes = projected;
    true
}

fn role_key_allocation_fits(
    estimated_working_bytes: u64,
    value_len: usize,
    max_retained_bytes: u64,
) -> bool {
    let projected = estimated_working_bytes
        .saturating_add(value_len as u64)
        .saturating_add((size_of::<FactAddress>() as u64).saturating_mul(2))
        .saturating_add((size_of::<(RolePostingKey, Vec<FactAddress>)>() as u64).saturating_mul(2));
    !working_budget_exceeded(projected, max_retained_bytes)
}

fn working_budget_exceeded(estimated_working_bytes: u64, max_retained_bytes: u64) -> bool {
    estimated_working_bytes > max_retained_bytes.saturating_mul(BUILD_WORKING_BYTES_MULTIPLIER)
}

/// Build one provider's postings over `files`, which the caller has already
/// ordered and deduplicated for the preflight census.
fn build_index(
    provider: &dyn StructuralFactProvider,
    files: Vec<ProjectFile>,
    cancellation: &CancellationToken,
    max_retained_bytes: u64,
    content_identity: WorkspaceContentIdentity,
) -> Result<(SnapshotStructuralIndex, StructuralIndexBuildMetrics), BuildFailure> {
    let started = Instant::now();
    debug_assert!(files.windows(2).all(|pair| pair[0] < pair[1]));
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

    // Fact acquisition (parse + normalize on a cold cache) dominates build
    // time and is independent per file, so acquire each chunk in parallel and
    // assemble it sequentially in file order before acquiring the next; the
    // chunk bound keeps the transient working set proportional to the chunk.
    let mut file_id = 0u32;
    for chunk in files.chunks(INDEX_BUILD_ACQUISITION_CHUNK) {
        if cancellation.is_cancelled() {
            metrics.elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            return Err(BuildFailure::Cancelled { metrics });
        }
        let acquired: Vec<(Option<Arc<FileFacts>>, StructuralFactsCacheOutcome)> = chunk
            .par_iter()
            .map(|file| provider.structural_facts_with_outcome(file))
            .collect();
        for (file, (facts, outcome)) in chunk.iter().zip(acquired) {
            metrics.files = metrics.files.saturating_add(1);
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
                // Name the file: an all-or-nothing rejection that hides which
                // file poisoned the slice is undiagnosable from the profile
                // (#1459).
                return Err(unavailable_failure(
                    started,
                    format!(
                        "structural index facts unavailable: {}",
                        file.rel_path().display()
                    ),
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
            let fact_nodes = match u32::try_from(facts.work_item_count()) {
                Ok(count) => count,
                Err(_) => {
                    return Err(unavailable_failure(
                        started,
                        "structural index per-file node-and-role fact limit exceeded",
                        metrics,
                    ));
                }
            };
            metrics.fact_nodes = metrics.fact_nodes.saturating_add(fact_nodes as u64);
            metrics.facts_bytes = metrics.facts_bytes.saturating_add(facts.estimated_bytes());
            if metrics.fact_nodes > MAX_INDEX_FACT_NODES {
                return Err(unavailable_failure(
                    started,
                    "structural index node-and-role fact limit exceeded",
                    metrics,
                ));
            }
            file_ids.insert(file.clone(), file_id);
            indexed_files.push(StructuralIndexFile {
                file: file.clone(),
                source_bytes: source.len() as u64,
                fact_nodes,
            });
            let filter_start = file_id as usize * SOURCE_FILTER_WORDS_PER_FILE;
            if !insert_source_trigrams(
                &mut source_trigram_filters
                    [filter_start..filter_start + SOURCE_FILTER_WORDS_PER_FILE],
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
                if working_budget_exceeded(estimated_working_bytes, max_retained_bytes) {
                    return Err(unavailable_failure(
                        started,
                        "structural index construction-byte limit exceeded",
                        metrics,
                    ));
                }
                if let Some(name) = node.name {
                    let name = name.text(facts.source());
                    if !push_string_posting(
                        &mut name_rows,
                        name,
                        address,
                        &mut estimated_working_bytes,
                        max_retained_bytes,
                    ) {
                        return Err(unavailable_failure(
                            started,
                            "structural index construction-byte limit exceeded",
                            metrics,
                        ));
                    }
                }
                for target in facts.roles(fact_id as u32) {
                    if supports_exact_role_name_posting(target.role) {
                        let effective_name = target
                            .name
                            .or_else(|| target.node.and_then(|node| facts.node(node).name));
                        if let Some(name) = effective_name {
                            let value = name.text(facts.source());
                            let value_len = value.len();
                            if !role_key_allocation_fits(
                                estimated_working_bytes,
                                value_len,
                                max_retained_bytes,
                            ) {
                                return Err(unavailable_failure(
                                    started,
                                    "structural index construction-byte limit exceeded",
                                    metrics,
                                ));
                            }
                            push_posting(
                                &mut role_rows,
                                RolePostingKey {
                                    role: target.role,
                                    value: value.into(),
                                    keyword: false,
                                },
                                value_len,
                                address,
                                &mut estimated_working_bytes,
                            );
                            if working_budget_exceeded(estimated_working_bytes, max_retained_bytes)
                            {
                                return Err(unavailable_failure(
                                    started,
                                    "structural index construction-byte limit exceeded",
                                    metrics,
                                ));
                            }
                        }
                    }
                    if target.role == Role::Kwarg
                        && let Some(keyword) = target.keyword
                    {
                        let value = keyword.text(facts.source());
                        let value_len = value.len();
                        if !role_key_allocation_fits(
                            estimated_working_bytes,
                            value_len,
                            max_retained_bytes,
                        ) {
                            return Err(unavailable_failure(
                                started,
                                "structural index construction-byte limit exceeded",
                                metrics,
                            ));
                        }
                        push_posting(
                            &mut role_rows,
                            RolePostingKey {
                                role: target.role,
                                value: value.into(),
                                keyword: true,
                            },
                            value_len,
                            address,
                            &mut estimated_working_bytes,
                        );
                        if working_budget_exceeded(estimated_working_bytes, max_retained_bytes) {
                            return Err(unavailable_failure(
                                started,
                                "structural index construction-byte limit exceeded",
                                metrics,
                            ));
                        }
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
            file_id += 1;
        }
    }

    let Some(kind_postings) = boxed_rows(kind_rows, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    let Some(name_postings) = boxed_rows(name_rows, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    let mut kind_name_rows = MutableKindNamePostings::default();
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
        let mut combinations = rows_by_kind.into_iter().collect::<Vec<_>>();
        combinations.sort_by_key(|(kind, _)| *kind);
        estimated_working_bytes = estimated_working_bytes
            .saturating_add(
                (size_of::<(Box<str>, Vec<(NormalizedKind, Vec<FactAddress>)>)>() as u64)
                    .saturating_mul(2),
            )
            .saturating_add(name.len() as u64)
            .saturating_add((combinations.capacity() as u64).saturating_mul(size_of::<(
                NormalizedKind,
                Vec<FactAddress>,
            )>()
                as u64));
        kind_name_rows.insert(name.clone(), combinations);
        if working_budget_exceeded(estimated_working_bytes, max_retained_bytes) {
            return Err(unavailable_failure(
                started,
                "structural index construction-byte limit exceeded",
                metrics,
            ));
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
    let Some(kind_name_postings) = boxed_kind_name_rows(kind_name_rows, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    let Some(role_postings) = boxed_rows(role_rows, cancellation) else {
        return Err(cancelled_failure(started, metrics));
    };
    let mut index = SnapshotStructuralIndex {
        content_identity,
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
    metrics.elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    // The measured counterpart of the preflight estimate: what the finished
    // index actually retains for the source it indexed. This pair is how the
    // estimate's bytes-per-source-byte constants stay calibrated.
    crate::profiling::note_with(|| {
        format!(
            "structural-index built language={:?} metrics={metrics:?} retained_bytes={} \
             max_retained_bytes={max_retained_bytes}",
            provider.structural_language(),
            index.retained_bytes
        )
    });
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

fn boxed_kind_name_rows(
    rows: MutableKindNamePostings,
    cancellation: &CancellationToken,
) -> Option<KindNamePostings> {
    let mut boxed = map_with_capacity(rows.len());
    let mut observed = 0usize;
    for (name, combinations) in rows {
        let mut boxed_combinations = Vec::with_capacity(combinations.len());
        for (kind, values) in combinations {
            if observed.is_multiple_of(FACT_CANCELLATION_BATCH) && cancellation.is_cancelled() {
                return None;
            }
            observed = observed.saturating_add(values.len().max(1));
            debug_assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
            boxed_combinations.push((kind, values.into_boxed_slice()));
        }
        boxed.insert(name, boxed_combinations);
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
                    Box<str>,
                    Vec<(NormalizedKind, Box<[FactAddress]>)>,
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
    for (entry_index, (name, combinations)) in index.kind_name_postings.iter().enumerate() {
        if entry_index % FACT_CANCELLATION_BATCH == 0 && cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes.saturating_add(name.len() as u64).saturating_add(
            (combinations.capacity() as u64)
                .saturating_mul(size_of::<(NormalizedKind, Box<[FactAddress]>)>() as u64),
        );
        for (_, posting) in combinations {
            bytes = bytes.saturating_add((posting.len() * size_of::<FactAddress>()) as u64);
        }
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
    use crate::analyzer::structural::occurrences::OccurrenceRole;
    use crate::compact_graph::CompactRows;

    struct FakeProvider {
        files: Vec<ProjectFile>,
        facts: HashMap<ProjectFile, Arc<FileFacts>>,
        /// What this provider reports before a build. `None` models a
        /// third-party provider that cannot answer, which leaves the build
        /// governed by its own construction limits.
        census: Option<StructuralIndexCensus>,
        /// Holds every facts lookup until the test releases it, so a test can
        /// observe an index build while it is still in flight.
        gate: Option<Arc<BuildGate>>,
    }

    /// A latch the test opens to let a stalled build finish.
    #[derive(Default)]
    struct BuildGate {
        released: Mutex<bool>,
        changed: std::sync::Condvar,
    }

    impl BuildGate {
        fn wait(&self) {
            let mut released = self.released.lock().expect("build gate poisoned");
            while !*released {
                released = self.changed.wait(released).expect("build gate poisoned");
            }
        }

        fn release(&self) {
            *self.released.lock().expect("build gate poisoned") = true;
            self.changed.notify_all();
        }
    }

    fn content(seed: u64) -> WorkspaceContentIdentity {
        WorkspaceContentIdentity::for_test(seed)
    }

    /// Order the provider's files the way [`SnapshotStructuralIndexCache`]
    /// does before it censuses and builds them.
    fn build_index_for_test(
        provider: &dyn StructuralFactProvider,
        max_retained_bytes: u64,
        content_identity: WorkspaceContentIdentity,
    ) -> Result<(SnapshotStructuralIndex, StructuralIndexBuildMetrics), BuildFailure> {
        let mut files = provider.structural_files();
        files.sort();
        files.dedup();
        build_index(
            provider,
            files,
            &CancellationToken::default(),
            max_retained_bytes,
            content_identity,
        )
    }

    impl StructuralFactProvider for FakeProvider {
        fn structural_language(&self) -> Language {
            Language::Python
        }

        fn structural_content_identity(&self) -> Option<WorkspaceContentIdentity> {
            // A fake provider's analyzed content is fixed for its lifetime, so
            // one identity per distinct file set is exactly right here.
            Some(content(self.files.len() as u64))
        }

        fn structural_files(&self) -> Vec<ProjectFile> {
            self.files.clone()
        }

        fn structural_index_census(&self, _files: &[ProjectFile]) -> Option<StructuralIndexCensus> {
            self.census
        }

        fn structural_source(&self, file: &ProjectFile) -> Option<String> {
            self.facts.get(file).map(|facts| facts.source().to_string())
        }

        fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>> {
            if let Some(gate) = &self.gate {
                gate.wait();
            }
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

        fn structural_supports_occurrence_role(&self, _role: OccurrenceRole) -> bool {
            true
        }

        fn structural_supports_environment_axis(
            &self,
            _axis: crate::analyzer::structural::resolution::EnvironmentAxis,
        ) -> bool {
            true
        }

        fn structural_supports_materialization_axis(
            &self,
            _axis: crate::analyzer::structural::materialization::MaterializationAxis,
        ) -> bool {
            true
        }

        fn structural_supports_edge_axis(
            &self,
            _axis: crate::analyzer::structural::edges::EdgeAxis,
        ) -> bool {
            true
        }

        fn structural_supports_identity_axis(
            &self,
            _axis: crate::analyzer::structural::routes::IdentityAxis,
        ) -> bool {
            true
        }

        fn structural_supports_route_relation(
            &self,
            _relation: crate::analyzer::structural::routes::RouteHopKind,
        ) -> bool {
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
                boolean_value: None,
                construct: None,
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
                call_site: None,
            }],
            CompactRows::from_parts(vec![0, 0], Vec::new()),
            CompactRows::from_parts(vec![0, 0], Vec::new()),
        );
        FakeProvider {
            files: vec![file.clone()],
            facts: HashMap::from_iter([(file, Arc::new(facts))]),
            census: None,
            gate: None,
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
                    boolean_value: None,
                    construct: None,
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
                    call_site: None,
                }
            })
            .collect::<Vec<_>>();
        let facts = FileFacts::new(
            source,
            vec![0],
            nodes,
            CompactRows::from_parts(vec![0; MIN_KIND_NAME_POSTING_ROWS + 1], Vec::new()),
            CompactRows::from_parts(vec![0; MIN_KIND_NAME_POSTING_ROWS + 1], Vec::new()),
        );
        FakeProvider {
            files: vec![file.clone()],
            facts: HashMap::from_iter([(file, Arc::new(facts))]),
            census: None,
            gate: None,
        }
    }

    #[test]
    fn exact_kind_and_name_postings_select_dense_addresses() {
        let provider = provider();
        let (index, metrics) =
            build_index_for_test(&provider, 1024 * 1024, content(1)).expect("index builds");
        let requirements = StructuralAccessRequirements::new_for_test(vec![
            StructuralPostingTerm::Kinds(vec![NormalizedKind::Declaration]),
            StructuralPostingTerm::ExactName(vec!["App".to_string()]),
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
        let (index, _) =
            build_index_for_test(&provider, 1024 * 1024, content(1)).expect("index builds");
        let requirements = StructuralAccessRequirements::new_for_test(vec![
            StructuralPostingTerm::Kinds(vec![NormalizedKind::Class]),
            StructuralPostingTerm::ExactName(vec!["Shared".to_string()]),
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
        let (index, _) =
            build_index_for_test(&provider, 1024 * 1024, content(1)).expect("index builds");
        let file = &provider.files[0];

        assert_eq!(
            index.source_may_contain(file, &[SourceAnchorGroup::new(vec!["App".to_string()])]),
            Some(true)
        );
        assert_eq!(
            index.source_may_contain(
                file,
                &[SourceAnchorGroup::new(vec!["zzzz-absent".to_string()])]
            ),
            Some(false)
        );
        assert_eq!(
            index.source_may_contain(file, &[SourceAnchorGroup::new(vec!["z".to_string()])]),
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
    fn request_session_defers_auto_admission_and_guards_every_selected_content() {
        let cache = SnapshotStructuralIndexCache::new(1024 * 1024);
        let session = QueryStructuralIndexSession::default();

        assert!(!cache.auto_reuse_observed(content(7)));
        session.defer_auto_build(&cache, content(7));
        session.defer_auto_build(&cache, content(7));
        assert!(
            !cache.auto_reuse_observed(content(7)),
            "sibling branches must not publish a later-request observation"
        );
        session.publish_auto_observations();
        assert!(cache.auto_reuse_observed(content(7)));

        session.record_selection(content(11));
        assert!(session.selections_are_current(|selected| selected == content(11)));
        assert!(!session.selections_are_current(|selected| selected == content(12)));
        session.record_selection(content(12));
        assert!(
            !session.selections_are_current(|_| true),
            "one request cannot combine posting selections from different workspace content"
        );
    }

    /// Milestone J (#2449): a provider that states no content identity gets no
    /// index at all -- not an index keyed by a constant, which is what the old
    /// zero-generation default silently gave it.
    #[test]
    fn a_provider_without_a_content_identity_is_never_served_from_the_index() {
        struct UnattestedProvider(FakeProvider);

        impl StructuralFactProvider for UnattestedProvider {
            fn structural_language(&self) -> Language {
                self.0.structural_language()
            }

            fn structural_content_identity(&self) -> Option<WorkspaceContentIdentity> {
                None
            }

            fn structural_files(&self) -> Vec<ProjectFile> {
                self.0.structural_files()
            }

            fn structural_source(&self, file: &ProjectFile) -> Option<String> {
                self.0.structural_source(file)
            }

            fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>> {
                self.0.structural_facts(file)
            }

            fn structural_extraction_count(&self) -> u64 {
                0
            }

            fn structural_hydration_count(&self) -> u64 {
                0
            }

            fn structural_supports_kind(&self, kind: NormalizedKind) -> bool {
                self.0.structural_supports_kind(kind)
            }

            fn structural_supports_role(&self, role: Role) -> bool {
                self.0.structural_supports_role(role)
            }

            fn structural_supports_occurrence_role(
                &self,
                role: super::super::occurrences::OccurrenceRole,
            ) -> bool {
                self.0.structural_supports_occurrence_role(role)
            }

            fn structural_supports_environment_axis(
                &self,
                axis: super::super::resolution::EnvironmentAxis,
            ) -> bool {
                self.0.structural_supports_environment_axis(axis)
            }

            fn structural_supports_materialization_axis(
                &self,
                axis: super::super::materialization::MaterializationAxis,
            ) -> bool {
                self.0.structural_supports_materialization_axis(axis)
            }

            fn structural_supports_edge_axis(&self, axis: super::super::edges::EdgeAxis) -> bool {
                self.0.structural_supports_edge_axis(axis)
            }

            fn structural_supports_identity_axis(
                &self,
                axis: super::super::routes::IdentityAxis,
            ) -> bool {
                self.0.structural_supports_identity_axis(axis)
            }

            fn structural_supports_route_relation(
                &self,
                relation: super::super::routes::RouteHopKind,
            ) -> bool {
                self.0.structural_supports_route_relation(relation)
            }
        }

        let cache = SnapshotStructuralIndexCache::new(1024 * 1024);
        let provider = UnattestedProvider(provider());

        assert!(matches!(
            cache.acquire(&provider, &CancellationToken::default()),
            StructuralIndexAcquisition::Unavailable { reason, .. }
                if reason.contains("no content identity")
        ));
        assert_eq!(cache.len_for_test(), 0);
        let (retained, invalidated) = cache.verdicts().totals();
        assert_eq!((0, 1), (retained, invalidated));
        assert_eq!(
            vec!["content_identity_evidence_missing"],
            cache
                .verdicts()
                .recent()
                .iter()
                .map(|verdict| verdict.stable_label())
                .collect::<Vec<_>>()
        );
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
            StructuralIndexAcquisition::Unavailable { reason, .. }
                if &*reason == "structural index retained-byte limit exceeded"
        ));
        assert_eq!(cache.len_for_test(), 0);
    }

    #[test]
    fn census_over_budget_rejects_before_any_build_work() {
        let mut provider = provider();
        // The whole workspace is this provider's, so it is apportioned the
        // whole memo budget below and still needs far more than that.
        provider.census = Some(StructuralIndexCensus {
            files: 4_096,
            source_bytes: 64 * 1024 * 1024,
            workspace_source_bytes: 64 * 1024 * 1024,
        });
        let cache = SnapshotStructuralIndexCache::new(1024 * 1024);

        let StructuralIndexAcquisition::Unavailable { reason, build, .. } =
            cache.acquire(&provider, &CancellationToken::default())
        else {
            panic!("an index that cannot be retained must not be built")
        };

        assert!(
            reason.contains("estimated retained-byte limit exceeded"),
            "unexpected rejection reason: {reason}"
        );
        // The whole point: the rejection costs no fact acquisition, no
        // posting assembly, and no measured build time.
        assert_eq!(build, StructuralIndexBuildMetrics::default());
        assert_eq!(build.elapsed_ns, 0);
        assert_eq!(build.files, 0);
        assert_eq!(cache.len_for_test(), 0);
    }

    #[test]
    fn a_build_in_flight_is_visible_to_a_caller_that_can_scan_instead() {
        let gate = Arc::new(BuildGate::default());
        let mut provider = provider();
        provider.gate = Some(Arc::clone(&gate));
        let content_identity = provider
            .structural_content_identity()
            .expect("fake provider states its content");
        let cache = SnapshotStructuralIndexCache::new(16 * 1024 * 1024);
        let cancellation = CancellationToken::default();

        assert!(!cache.build_in_flight(content_identity));

        std::thread::scope(|scope| {
            let builder = scope.spawn(|| cache.acquire(&provider, &CancellationToken::default()));

            // The flight is claimed before any fact is acquired, so a request
            // that arrives now sees a build it must not follow, and no index.
            let deadline = Instant::now() + std::time::Duration::from_secs(30);
            while !cache.build_in_flight(content_identity) {
                assert!(
                    Instant::now() < deadline,
                    "the build never claimed a flight"
                );
                std::thread::yield_now();
            }
            assert!(
                cache.get_ready(content_identity, &cancellation).is_none(),
                "an in-flight build must not present a half-built index"
            );

            gate.release();
            assert!(matches!(
                builder.join().expect("the build thread must not panic"),
                StructuralIndexAcquisition::Ready {
                    lifecycle: StructuralIndexLifecycle::Built,
                    ..
                }
            ));
        });

        assert!(!cache.build_in_flight(content_identity));
        assert!(
            cache.get_ready(content_identity, &cancellation).is_some(),
            "the request after the build must find the index"
        );
    }

    #[test]
    fn census_within_budget_still_builds() {
        let mut provider = provider();
        provider.census = Some(StructuralIndexCensus {
            files: 1,
            source_bytes: 64 * 1024,
            workspace_source_bytes: 64 * 1024,
        });
        let cache = SnapshotStructuralIndexCache::new(16 * 1024 * 1024);

        assert!(matches!(
            cache.acquire(&provider, &CancellationToken::default()),
            StructuralIndexAcquisition::Ready {
                lifecycle: StructuralIndexLifecycle::Built,
                ..
            }
        ));
        assert_eq!(cache.len_for_test(), 1);
    }

    #[test]
    fn a_minority_language_keeps_a_floor_of_the_shared_budget() {
        let memo_budget_bytes = 256 * 1024 * 1024;
        // A handful of tiny files whose index costs per file, not per byte:
        // the Ruby shape measured in #2879.
        let minority = StructuralIndexCensus {
            files: 20,
            source_bytes: 2_457,
            workspace_source_bytes: 66_925_413,
        };
        let budget = provider_index_budget(memo_budget_bytes, minority);

        assert!(
            budget.max_retained_bytes >= budget.estimated_retained_bytes,
            "a minority language must not be apportioned out of existence: {budget:?}"
        );
        assert_eq!(
            budget.max_retained_bytes, budget.estimated_retained_bytes,
            "a provider is never handed more budget than its own index can use"
        );
    }

    #[test]
    fn a_dominant_language_is_apportioned_more_than_a_fixed_share() {
        let memo_budget_bytes = 256 * 1024 * 1024;
        // The Rust slice of this repository, whose index needed 103_636_999
        // retained bytes and was rejected by the old fixed memo/4 share.
        let dominant = StructuralIndexCensus {
            files: 1_998,
            source_bytes: 64_535_673,
            workspace_source_bytes: 66_925_413,
        };
        let budget = provider_index_budget(memo_budget_bytes, dominant);

        assert!(
            budget.max_retained_bytes > memo_budget_bytes / 4,
            "a language holding 96% of the workspace source must outgrow the \
             old fixed share: {budget:?}"
        );
        assert!(
            budget.max_retained_bytes >= 103_636_999,
            "the measured Rust index must now fit its budget: {budget:?}"
        );
        assert!(
            budget.max_retained_bytes <= memo_budget_bytes,
            "no provider may claim more than the shared budget: {budget:?}"
        );
    }

    #[test]
    fn deterministic_rejection_is_reused_without_rebuilding_the_generation() {
        let provider = provider();
        let cache = SnapshotStructuralIndexCache::new(1);

        let StructuralIndexAcquisition::Unavailable {
            reason: first_reason,
            build: first_build,
            ..
        } = cache.acquire(&provider, &CancellationToken::default())
        else {
            panic!("first acquisition must reject the fixed footprint")
        };
        let StructuralIndexAcquisition::Unavailable {
            reason: second_reason,
            build: second_build,
            ..
        } = cache.acquire(&provider, &CancellationToken::default())
        else {
            panic!("second acquisition must reuse the rejection")
        };

        assert_eq!(first_reason, second_reason);
        assert!(first_build.elapsed_ns > 0);
        assert_eq!(second_build, StructuralIndexBuildMetrics::default());
        assert_eq!(cache.len_for_test(), 0);
    }

    #[test]
    fn long_identifier_is_rejected_before_index_key_allocation_exceeds_budget() {
        let temp = tempfile::tempdir().expect("temp dir").keep();
        let root = temp.canonicalize().expect("canonical root");
        let file = ProjectFile::new(root, "large.py");
        let identifier = "a".repeat(256 * 1024);
        let facts = FileFacts::new(
            identifier.clone(),
            vec![0],
            vec![NormalizedNode {
                kind: NormalizedKind::Class,
                boolean_value: None,
                construct: None,
                range: Range {
                    start_byte: 0,
                    end_byte: identifier.len(),
                    start_line: 1,
                    end_line: 1,
                },
                parent: None,
                name: Some(super::super::facts::Span {
                    start_byte: 0,
                    end_byte: identifier.len(),
                }),
                subtree_end: 1,
                call_site: None,
            }],
            CompactRows::from_parts(vec![0, 0], Vec::new()),
            CompactRows::from_parts(vec![0, 0], Vec::new()),
        );
        let provider = FakeProvider {
            files: vec![file.clone()],
            facts: HashMap::from_iter([(file, Arc::new(facts))]),
            census: None,
            gate: None,
        };

        let failure = build_index_for_test(&provider, 32 * 1024, content(1))
            .expect_err("identifier key must be rejected by construction budget");
        assert!(matches!(
            failure,
            BuildFailure::Unavailable { reason, .. }
                if &*reason == "structural index construction-byte limit exceeded"
        ));
    }

    #[test]
    fn unavailable_provider_facts_never_publish() {
        let mut provider = provider();
        provider.facts.clear();
        let cache = SnapshotStructuralIndexCache::new(1024 * 1024);

        let StructuralIndexAcquisition::Unavailable { reason, .. } =
            cache.acquire(&provider, &CancellationToken::default())
        else {
            panic!("factless provider must be unavailable")
        };
        // The rejection names the poisoning file so an all-or-nothing abort is
        // diagnosable from the profile (#1459).
        assert!(
            reason.starts_with("structural index facts unavailable: "),
            "{reason}"
        );
        assert!(reason.ends_with(".py"), "{reason}");
        assert_eq!(cache.len_for_test(), 0);
    }

    /// #1459: an empty file (a real workspace shape -- empty `__init__.py`)
    /// must not abort the provider index. Before the fix,
    /// `extract_file_facts_limited` returned `Unavailable` for empty sources,
    /// this acquire came back `Unavailable { "structural index facts
    /// unavailable" }`, and the whole Python slice fell back to scan mode for
    /// the session.
    #[test]
    fn empty_file_does_not_abort_the_provider_index() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let empty = ProjectFile::new(root.clone(), "pkg/__init__.py");
        empty.write("").expect("write empty file");
        let module = ProjectFile::new(root.clone(), "pkg/module.py");
        module
            .write("def real_function():\n    return 1\n")
            .expect("write module");
        let analyzer = crate::analyzer::PythonAnalyzer::from_project(
            crate::analyzer::TestProject::new(root, crate::analyzer::Language::Python),
        );
        let providers = crate::analyzer::IAnalyzer::structural_fact_providers(&analyzer);
        let provider = *providers.first().expect("python structural provider");

        let cache = SnapshotStructuralIndexCache::new(64 * 1024 * 1024);
        let StructuralIndexAcquisition::Ready { index, .. } =
            cache.acquire(provider, &CancellationToken::default())
        else {
            panic!("empty file must not reject the index")
        };
        assert!(index.file(&empty).is_some());
        assert!(index.file(&module).is_some());
    }

    #[test]
    fn cancelled_candidate_selection_stops_without_rows() {
        let provider = ambiguous_name_provider();
        let (index, _) =
            build_index_for_test(&provider, 1024 * 1024, content(1)).expect("index builds");
        let requirements = StructuralAccessRequirements::new_for_test(vec![
            StructuralPostingTerm::Kinds(vec![NormalizedKind::Class]),
            StructuralPostingTerm::ExactName(vec!["Shared".to_string()]),
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
        let (simple, _) =
            build_index_for_test(&simple, 1024 * 1024, content(1)).expect("simple index builds");
        let (ambiguous, _) =
            build_index_for_test(&ambiguous, 1024 * 1024, content(2)).expect("larger index builds");

        assert!(ambiguous.retained_bytes() > simple.retained_bytes());
    }
}
