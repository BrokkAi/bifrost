// The traversal primitives and the two byte-range readers below them are pure
// tree-sitter node arithmetic, so they live in `brokk-bifrost-core` and are
// re-exported here at the paths every caller already uses. The budgeted walk
// followed them there with the receiver-facts vocabulary it serves: its counter
// is its own and its cancellation token is a core type. What stays is
// everything built on `FileState`.
pub use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
pub(crate) use brokk_bifrost_core::analyzer::tree_walk::{
    BoundedNamedTreeWalk, WalkControl, expanded_comment_start, try_walk_named_tree_preorder,
    walk_named_tree_preorder, walk_named_tree_preorder_bounded, walk_tree_preorder,
};

// `PreparedSyntaxTree` and its source backing hold model data plus a live
// `tree_sitter::Tree`, so they live in `brokk-bifrost-core` where a language
// crate can consume them, and are re-exported here at the paths their callers
// already use. What stays is the preparation pipeline below: the parse, the
// per-request single-flight cell, the byte-bounded cross-request store, and
// `FileState`'s implementation of the core index contract.
use brokk_bifrost_core::analyzer::prepared_syntax::{IndexedFileFacts, PreparedSourceIndex};
pub(crate) use brokk_bifrost_core::analyzer::prepared_syntax::{
    PreparedSourceOrigin, PreparedSyntaxSource, PreparedSyntaxTree,
};

use crate::analyzer::CodeUnitIndex;
use arc_swap::ArcSwapOption;
use brokk_bifrost_core::analyzer::code_unit_index::file_namespace_from_top_level_declarations;
use brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex;

use crate::analyzer::cognitive_complexity;
use crate::analyzer::common::{
    IdentifierSeek, decorated_identifier_seeks, identifier_addresses_target,
};
use crate::analyzer::fq_name::absent_segment_separators;
use crate::analyzer::pool_memo::{KeyedPoolSafeMemo, install_on_dedicated_build_pool};
use crate::analyzer::project::{OverlayRevision, ProjectSourceOrigin, ProjectSourceSnapshot};
use crate::analyzer::read_ledger::{IndexFamily, ReadKey};
use crate::analyzer::store::liveness::{
    FileStatStamp, LivePathEntry, LivePathMap, LiveSnapshot, Liveness,
};
use crate::analyzer::store::query::QueryResolver;
use crate::analyzer::store::{
    ActiveSearchBlob, AnalyzerStore, GenerationId, HierarchyStorageKey, HydratedCandidateRow,
    HydratedDefinitionOrderCandidateRow, HydratedMountedCandidateRow as MountedCandidateRow,
    LimitedQueryRows, PathSymbolRow, PersistBatchLimits, PersistBatchStats, PreparedParsedBlob,
    RelationalStoreOutcome, RenderedDefinitionCandidateOutcome, RenderedDefinitionRequest,
    StoreError, WorkspaceAnchorRow, WorkspaceContentPackageFact, WorkspaceFileRow,
    WorkspacePackageEdgeRow, WorkspacePackageFileRow, WorkspaceSnapshots,
};
use crate::analyzer::structural::materialization::MaterializationRecord;
use crate::analyzer::tier_demand::TierDemand;
use crate::analyzer::{
    AnalyzerBuildTierAccess, AnalyzerConfig, CodeBaseMetrics, CodeUnit, CodeUnitType,
    CppTemplateMetadata, DeclarationInfo, DefinitionLanguageScope, FqName, IAnalyzer, ImportInfo,
    InformationTier, Language, LanguageDialect, PackageAnchor, Project, ProjectFile, QueryScope,
    QueryToken, Range, RelationalBatchError, RelationalBatchOutcome, RelationalCallableFact,
    RelationalDefinitionLookup, RelationalDefinitionQuery, RelationalDefinitionRequest,
    RelationalDefinitionResult, RelationalDefinitionValue, RubyMethodDispatchMode,
    SearchSymbolCandidate, SearchSymbolCandidates, SearchSymbolPatternBatch, SignatureMetadata,
    SummaryFileProjection,
};
use crate::cancellation::CancellationToken;
use crate::gitblob;
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use crate::profiling;
use crate::text_utils::compute_line_starts;
use git2::{ObjectType, Oid};
use rayon::prelude::*;
use regex::RegexBuilder;
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tree_sitter::{Language as TsLanguage, ParseOptions, Parser, Tree};

// `FileState` holds the full parsed source (`source: String`) plus every
// declaration-shaped collection derived from it (imports, signatures,
// supertypes, ranges, children, ...) keyed by `CodeUnit`. For a typical
// FileState values have widely different retained sizes. A generated
// amalgamation can be orders of magnitude larger than an ordinary source file,
// so an entry-count limit gives neither a useful RSS limit nor useful cache
// admission. Keep the shared and query-local caches within this one slice of
// the existing analyzer memo budget.
const FILE_STATE_CACHE_BUDGET_DIVISOR: u64 = 2;
const QUERY_FILE_STATE_CACHE_BUDGET_DIVISOR: usize = 4;
const MIN_FILE_STATE_CACHE_BYTES: usize = 32 * 1024 * 1024;
const FILE_STATE_CACHE_CORPUS_FRACTION_DIVISOR: usize = 10;
const FILE_STATE_BYTES_PER_PERSISTED_BYTE: usize = 4;
const SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY: usize = 1_024;
const BULK_FILE_STATE_QUERY_LIMIT: usize = 1_024;

fn file_state_cache_ceiling_bytes(config: &AnalyzerConfig) -> usize {
    let total = usize::try_from(config.memo_cache_budget_bytes()).unwrap_or(usize::MAX);
    let share = usize::try_from(config.memo_cache_budget_bytes() / FILE_STATE_CACHE_BUDGET_DIVISOR)
        .unwrap_or(usize::MAX);
    if share < MIN_FILE_STATE_CACHE_BYTES {
        total
    } else {
        share
    }
}

fn file_state_cache_budget_bytes(
    config: &AnalyzerConfig,
    active_persisted_payload_bytes: Option<usize>,
) -> usize {
    let ceiling = file_state_cache_ceiling_bytes(config);
    let minimum = ceiling.min(MIN_FILE_STATE_CACHE_BYTES);
    let Some(payload_bytes) = active_persisted_payload_bytes else {
        return ceiling;
    };
    payload_bytes
        .saturating_mul(FILE_STATE_BYTES_PER_PERSISTED_BYTE)
        .saturating_div(FILE_STATE_CACHE_CORPUS_FRACTION_DIVISOR)
        .max(minimum)
        .min(ceiling)
}

fn query_file_state_cache_budget_bytes(file_state_cache_budget: usize) -> usize {
    file_state_cache_budget / QUERY_FILE_STATE_CACHE_BUDGET_DIVISOR
}
const QUERY_PREPARED_SYNTAX_CACHE_CAPACITY: usize = 1_024;
// Retained bytes per source byte for a prepared tree. The tree pins its source
// text (1x), the tree-sitter subtree arena (8-11x source for the Rust and
// C-family grammars: roughly one 64-byte heap subtree per five source bytes),
// one `usize` per line (~0.3x), and for the indexed flavor a shared
// `FileState`. 16 is a deliberate over-estimate so the cap below bounds the
// real footprint from above rather than tracking it.
const PREPARED_SYNTAX_BYTES_PER_SOURCE_BYTE: usize = 16;
// Charged on top of the source estimate so an empty or tiny file still costs
// something: without it a workspace of empty files would be unbounded.
const PREPARED_SYNTAX_STORE_ENTRY_OVERHEAD_BYTES: usize = 512;

/// Conservatively estimate the retained source-and-tree footprint of one
/// prepared syntax snapshot.
///
/// Keep non-store owners on the same admission estimate as the retained
/// prepared-syntax cache. The estimate includes the pinned source text as
/// well as tree-sitter's subtree arena and a fixed allocation allowance.
pub(crate) fn prepared_syntax_retained_bytes(source_bytes: usize) -> usize {
    source_bytes
        .saturating_mul(PREPARED_SYNTAX_BYTES_PER_SOURCE_BYTE)
        .saturating_add(PREPARED_SYNTAX_STORE_ENTRY_OVERHEAD_BYTES)
}
// ~32 MiB of source at the multiplier above. That comfortably holds the whole
// Rust candidate set of a Bifrost-sized workspace (~23 MiB across the 662
// candidates of the #1450 repro), so a warm scan reparses nothing, while a
// Trino-class workspace is capped here instead of growing without bound.
const PREPARED_SYNTAX_STORE_MAX_BYTES: usize = 512 * 1024 * 1024;
// Retained bytes per `raw_snippet` byte for one retained `ImportInfo`. Every
// other string an import carries -- `identifier`, `alias`, the structured
// path's segments, lexical prefixes and scope names -- is spelled inside the
// same import declaration the snippet holds, so the snippet length bounds
// their total; 4 is a deliberate over-estimate covering that plus each
// `String`'s own allocation slack.
const IMPORT_INFO_BYTES_PER_SNIPPET_BYTE: usize = 4;
// Charged per import on top of the snippet estimate: the `ImportInfo` struct,
// its `Option`/`Vec` headers, and the `StructuredImportPath` behind it.
const IMPORT_INFO_PER_IMPORT_OVERHEAD_BYTES: usize = 256;
// Charged per file so a file with no imports at all still costs something:
// without it a workspace of import-free files would be unbounded.
const IMPORT_INFO_STORE_ENTRY_OVERHEAD_BYTES: usize = 512;
// Import infos are kilobytes per file where prepared trees are megabytes: the
// whole Bifrost Rust candidate set (1100 distinct files in the #1451 repro)
// charges well under 10 MiB at the estimates above. 64 MiB is therefore
// enormous headroom for a workspace of this shape while still capping a
// Trino-class workspace by recency instead of letting it grow without bound.
const IMPORT_INFO_STORE_MAX_BYTES: usize = 64 * 1024 * 1024;
// Type-alias checks need only a small set of `CodeUnit` values per file. Keep
// these persisted projections separate from complete FileState values so a
// broad C++ visibility walk does not retain every source and side table.
const TYPE_ALIAS_STORE_TEXT_BYTES_MULTIPLIER: usize = 2;
const TYPE_ALIAS_STORE_UNIT_OVERHEAD_BYTES: usize = 256;
const TYPE_ALIAS_STORE_ENTRY_OVERHEAD_BYTES: usize = 512;
const TYPE_ALIAS_STORE_MAX_BYTES: usize = 32 * 1024 * 1024;
// A large generated file can have thousands of declaration ranges. A linear
// scan for every reference makes lexical-owner lookup quadratic in that file.
// Keep an interval index for these states and bound its retained `CodeUnit`
// copies independently from complete FileState values.
#[cfg(test)]
const ENCLOSING_CODE_UNIT_INDEX_MIN_DECLARATIONS: usize = 128;
const ENCLOSING_CODE_UNIT_INDEX_TEXT_BYTES_MULTIPLIER: usize = 2;
const ENCLOSING_CODE_UNIT_INDEX_ENTRY_OVERHEAD_BYTES: usize = 128;
const ENCLOSING_CODE_UNIT_INDEX_STORE_ENTRY_OVERHEAD_BYTES: usize = 512;
const ENCLOSING_CODE_UNIT_INDEX_STORE_MAX_BYTES: usize = 32 * 1024 * 1024;
// `SummaryFileProjection` is much lighter than `FileState`: no source text,
// just the declaration/signature/range/children maps used to render
// `get_summaries`. Call it a few KB per entry; 128 entries is a small,
// bounded addition (well under 1 MB) in exchange for a much higher hit rate
// under concurrent summary requests than the previous cap of 32.
const SUMMARY_FILE_PROJECTION_CACHE_CAPACITY: usize = 128;
const STORE_WRITE_IMMEDIATE_RETRIES: usize = 2;
const STORE_WRITE_RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
const STORE_WRITE_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);
// OpenJDK and LLVM contain generated-style fixtures that can keep one tree-sitter
// worker busy for tens of minutes after all ordinary files finish (issue #1690).
// Bound each complete-file parse so one blob cannot hold the workspace build open.
const COMPLETE_FILE_PARSE_BUDGET: Duration = Duration::from_secs(10);
/// Name any file whose whole analysis takes longer than this.
///
/// [`COMPLETE_FILE_PARSE_BUDGET`] bounds the tree-sitter parse but not the
/// adapter walk that follows it, so one file can still hold a build open long
/// after every other worker has finished. On Godot that tail is 77 percent of
/// the C++ parse phase while fifteen workers idle. Without the file's name a
/// reader sees only a slow build and reaches for the persistence knobs.
const SLOW_FILE_ANALYSIS_NOTE_NANOS: usize = 5_000_000_000;

enum BoundedParse {
    Complete(Tree),
    Cancelled,
    TimedOut,
    Rejected,
}

/// Point `parser` at `file`'s grammar and, when the language restricts what the
/// parse may read, at the included ranges for `source`.
///
/// Returns false when the grammar or the ranges are rejected, which is the
/// caller's signal that this file yields no tree.
fn set_parser_for_file<A: LanguageAdapter + ?Sized>(
    parser: &mut Parser,
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> bool {
    if parser
        .set_language(&adapter.parser_language_for_file(file))
        .is_err()
    {
        return false;
    }
    match adapter.parser_included_ranges(file, source) {
        Some(ranges) => parser.set_included_ranges(&ranges).is_ok(),
        // A parser is reused across files, so an earlier file's ranges must be
        // cleared rather than left in place.
        None => parser.set_included_ranges(&[]).is_ok(),
    }
}

fn parse_complete_file_bounded(
    parser: &mut Parser,
    source: &str,
    cancellation: Option<&CancellationToken>,
    budget: Duration,
) -> BoundedParse {
    let deadline = Instant::now() + budget;
    let mut timed_out = false;
    let mut read = |offset: usize, _| &source.as_bytes()[offset..];
    let mut progress = |_: &tree_sitter::ParseState| {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return true;
        }
        timed_out = Instant::now() >= deadline;
        timed_out
    };
    let tree = parser.parse_with_options(
        &mut read,
        None,
        Some(ParseOptions::new().progress_callback(&mut progress)),
    );
    if let Some(tree) = tree {
        return BoundedParse::Complete(tree);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        BoundedParse::Cancelled
    } else if timed_out {
        BoundedParse::TimedOut
    } else {
        BoundedParse::Rejected
    }
}

fn limited_projection_rows<T: Clone>(rows: Option<&[T]>, limit: usize) -> LimitedQueryRows<T> {
    if limit == 0 {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }
    let rows = rows.unwrap_or_default();
    let inspected = rows.len().min(limit);
    let projected = rows.iter().take(limit).cloned().collect();
    if rows.len() > limit {
        LimitedQueryRows::incomplete(projected, inspected)
    } else {
        // A dirty in-memory state knows its exact vector length, unlike a
        // limited SQL cursor, so equality with the cap is authoritative.
        LimitedQueryRows::complete(projected, inspected)
    }
}

fn projection_rows_for_unit<'a, T>(
    rows: &'a HashMap<CodeUnit, Vec<T>>,
    unit: &CodeUnit,
) -> Option<&'a [T]> {
    projection_value_for_unit(rows, unit).map(Vec::as_slice)
}

fn projection_value_for_unit<'a, T>(
    rows: &'a HashMap<CodeUnit, T>,
    unit: &CodeUnit,
) -> Option<&'a T> {
    rows.get(unit).or_else(|| {
        rows.iter()
            .find(|(candidate, _)| {
                candidate.kind() == unit.kind()
                    && candidate.fq_name() == unit.fq_name()
                    && candidate.short_name() == unit.short_name()
                    && candidate.signature() == unit.signature()
                    && candidate.is_synthetic() == unit.is_synthetic()
            })
            .map(|(_, rows)| rows)
    })
}

#[cfg(test)]
static PREPARED_FAILURE_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
#[cfg(test)]
static PREPARATION_FAILURE_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
#[cfg(test)]
static FORCED_PARSE_TIMEOUT_PATHS: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());
#[cfg(test)]
static PANICKING_ANALYSIS_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
#[cfg(test)]
static BLOCK_UNTIL_BUILD_ABORT_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
#[cfg(test)]
static BLOCKING_ANALYSIS_OBSERVED_ABORT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static BLOCKING_ANALYSIS_READY: (Mutex<bool>, std::sync::Condvar) =
    (Mutex::new(false), std::sync::Condvar::new());

/// The whole build's "stop, something already failed" signal.
///
/// One language's build worker panicking must stop the whole build, not merely
/// be reported once every sibling has finished. `std::thread::scope` joins each
/// spawned thread before it returns, so with no signal to stop, the time to
/// surface a panic is the duration of the SLOWEST language rather than the time
/// to the panic. On a large multi-language repository that is indistinguishable
/// from a hang: microsoft/PowerToys panicked in the Cpp worker within seconds
/// and then outlived a 1872-second timeout (issue #2359).
///
/// Every language delegate in one build shares this through
/// [`AnalyzerStoreContext`], which is already cloned per language. A worker
/// that observes an abort stops claiming new work and returns whatever it has;
/// the delegate is discarded either way, because the recorded panic is
/// re-raised as soon as the fan-out joins.
#[derive(Debug, Default)]
pub(crate) struct BuildAbort {
    aborted: std::sync::atomic::AtomicBool,
}

impl BuildAbort {
    pub(crate) fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
    }

    pub(crate) fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BulkFileStateSource {
    Include,
    Omit,
}

#[derive(Clone)]
pub(crate) struct AnalyzerStoreContext {
    pub(crate) store: Arc<AnalyzerStore>,
    pub(crate) workspace_id: crate::analyzer::store::WorkspaceId,
    pub(crate) gc: Arc<crate::analyzer::store::gc::AnalyzerGcCoordinator>,
    pub(crate) liveness: Option<Arc<Liveness>>,
    /// The immutable listing and live identities captured for one workspace
    /// build. This is consumed by the delegate constructor and must not be
    /// retained by the long-lived workspace build context.
    pub(crate) workspace_snapshot: Option<Arc<WorkspaceBuildSnapshot>>,
    /// Whether the most recent full workspace enumeration completed. A
    /// package-membership hit remains useful when this is false, but an exact
    /// miss cannot prove absence from the current workspace.
    pub(crate) workspace_listing_complete: bool,
    /// The blob ids an immutable revision image's own tree walk already
    /// resolved, if this build analyzes one. See [`RevisionBlobIdentities`].
    pub(crate) revision_blobs: Option<Arc<RevisionBlobIdentities>>,
    pub(crate) live_paths: Arc<LivePathMap>,
    pub(crate) generations: Arc<HashMap<String, GenerationId>>,
    /// Shared by every language delegate the same build fans out to. See
    /// [`BuildAbort`].
    pub(crate) build_abort: Arc<BuildAbort>,
    /// Counts the construction-only tier crossings for the current build.
    /// Finished observers remain attached to the analyzer context but ignore
    /// later incremental work.
    pub(crate) build_tier_access: Arc<AnalyzerBuildTierAccess>,
}

/// Build-scoped view shared by all language delegates in one workspace build.
///
/// The listing is captured once before the language fan-out and the live path
/// entries are resolved against that same listing. Delegates still own their
/// own [`LivePathMap`]; this type only prevents each delegate from repeating
/// the workspace walk and Git identity projection.
#[derive(Clone)]
pub(crate) struct WorkspaceBuildSnapshot {
    files: Arc<BTreeSet<ProjectFile>>,
    live_entries: Arc<HashMap<ProjectFile, LivePathEntry>>,
    disk_stats: Arc<HashMap<ProjectFile, FileStatStamp>>,
    analysis_generation: u64,
}

impl WorkspaceBuildSnapshot {
    pub(crate) fn capture(
        project: &dyn Project,
        liveness: Option<&Liveness>,
        selected_languages: &[Language],
    ) -> Option<Arc<Self>> {
        let files = {
            let _scope = profiling::scope("WorkspaceBuildSnapshot::list_files");
            project.all_files_shared().ok()?
        };
        let mut live_entries = map_with_capacity(files.len());
        let mut disk_stats = map_with_capacity(files.len());
        let analysis_generation = project.analysis_generation();
        if let Some(liveness) = liveness {
            let _scope = profiling::scope("WorkspaceBuildSnapshot::resolve_identities");
            let mut selected_files = BTreeSet::new();
            {
                let _scope = profiling::scope("WorkspaceBuildSnapshot::select_languages");
                for language in selected_languages {
                    if let Ok(language_files) =
                        project.analyzable_files_from(files.as_ref(), *language)
                    {
                        selected_files.extend(language_files);
                    }
                }
            }
            let disk_files: Vec<_> = selected_files
                .iter()
                .filter(|file| !project.has_overlay(file))
                .cloned()
                .collect();
            if !disk_files.is_empty()
                && let Ok(disk_oids) = liveness.oids_and_stats_for_files(&disk_files)
            {
                for (file, (oid, stat)) in disk_oids {
                    disk_stats.insert(file.clone(), stat);
                    live_entries.insert(file.clone(), LivePathEntry::filesystem(file, oid));
                }
            }
            for file in selected_files
                .iter()
                .filter(|file| project.has_overlay(file))
            {
                let Ok(source) = project.read_source(file) else {
                    continue;
                };
                let Ok(oid) = Oid::hash_object(ObjectType::Blob, source.as_bytes()) else {
                    continue;
                };
                live_entries.insert(file.clone(), LivePathEntry::overlay(file.clone(), oid));
            }
        }
        Some(Arc::new(Self {
            files,
            live_entries: Arc::new(live_entries),
            disk_stats: Arc::new(disk_stats),
            analysis_generation,
        }))
    }

    pub(crate) fn files(&self) -> &BTreeSet<ProjectFile> {
        self.files.as_ref()
    }

    pub(crate) fn live_entry(
        &self,
        project: &dyn Project,
        file: &ProjectFile,
    ) -> Option<LivePathEntry> {
        let entry = self.live_entries.get(file)?.clone();
        let is_overlay = project.has_overlay(file);
        if is_overlay != entry.is_overlay() {
            return None;
        }
        if is_overlay {
            (project.analysis_generation() == self.analysis_generation).then_some(entry)
        } else {
            let expected = self.disk_stats.get(file)?;
            Liveness::file_stat_matches(file, expected).then_some(entry)
        }
    }
}

/// The Git blob ids of one immutable revision image, taken from the tree walk
/// that exported it.
///
/// A revision image is written into a temporary directory that holds no Git
/// repository, so `resolve_live_oids` finds no identity source there and would
/// otherwise re-read and re-hash every exported byte to recover an id the
/// exporter already had in hand. The exporter walks the revision's tree, and a
/// tree entry carries its blob id, so the whole inventory is free.
pub(crate) struct RevisionBlobIdentities {
    /// Keyed by the workspace-relative path the export wrote, which is exactly
    /// the `rel_path` the image's `FileSetProject` names that file by.
    entries: HashMap<std::path::PathBuf, RevisionBlob>,
}

struct RevisionBlob {
    oid: Oid,
    /// Whether a debug build re-hashes this file's bytes and asserts they hash
    /// to `oid`. See [`RevisionBlobIdentities::oid_for`].
    sampled: bool,
}

/// One entry in this many, in sorted path order starting at the first, carries
/// the debug re-hash assertion. Starting at the first entry means every
/// immutable test fixture in the repository -- all of them far smaller than the
/// stride -- checks at least one file, while a monorepo revision pays the
/// re-hash for well under two percent of its files.
const REVISION_BLOB_ASSERTION_STRIDE: usize = 64;

impl RevisionBlobIdentities {
    /// `written` names the files whose bytes the image put on disk; `named_only`
    /// names the rest, which the image serves from the repository's object
    /// database instead.
    ///
    /// Only a written entry can carry the re-hash assertion, because only a
    /// written entry has a second, independently produced copy of the bytes to
    /// compare against. Re-reading a named-only entry through the object
    /// database would compare the blob id to itself.
    pub(crate) fn new(
        mut written: Vec<(std::path::PathBuf, Oid)>,
        named_only: Vec<(std::path::PathBuf, Oid)>,
    ) -> Self {
        written.sort_unstable();
        // The path-restricted exporters union several selections, so one path
        // can be offered twice. A repeated path always carries the same blob
        // id -- both come from the same tree entry -- so keeping the first is
        // not a choice between disagreeing answers.
        written.dedup_by(|left, right| left.0 == right.0);
        let mut entries: HashMap<std::path::PathBuf, RevisionBlob> = written
            .into_iter()
            .enumerate()
            .map(|(index, (path, oid))| {
                (
                    path,
                    RevisionBlob {
                        oid,
                        sampled: index % REVISION_BLOB_ASSERTION_STRIDE == 0,
                    },
                )
            })
            .collect();
        for (path, oid) in named_only {
            entries.insert(
                path,
                RevisionBlob {
                    oid,
                    sampled: false,
                },
            );
        }
        Self { entries }
    }

    /// The revision's blob id for `file`, or `None` when this image does not
    /// name it.
    ///
    /// A sampled entry is verified against the bytes on disk in debug builds,
    /// in the model of the `FqName` round-trip assertion: the inventory and the
    /// export are produced by one tree walk, so a disagreement is a construction
    /// bug that must fail where it is introduced rather than silently publish
    /// facts under the wrong content key.
    pub(crate) fn oid_for(&self, file: &ProjectFile) -> Option<Oid> {
        let entry = self.entries.get(file.rel_path())?;
        if entry.sampled {
            debug_assert!(
                Self::sampled_bytes_agree(file, entry.oid),
                "revision inventory names {} as blob {} but its exported bytes hash differently",
                file.abs_path().display(),
                entry.oid,
            );
        }
        Some(entry.oid)
    }

    /// Whether `file`'s bytes on disk hash to `oid`. Only ever asked of a
    /// written entry; an unreadable file passes, because a missing write is a
    /// different failure that the read itself reports.
    fn sampled_bytes_agree(file: &ProjectFile, oid: Oid) -> bool {
        let Ok(bytes) = std::fs::read(file.abs_path()) else {
            return true;
        };
        Oid::hash_object(ObjectType::Blob, &bytes) == Ok(oid)
    }
}

pub(crate) struct StructuralSnapshotKey {
    oid: Oid,
    lang: String,
    generation: GenerationId,
}

pub(crate) fn ephemeral_store_context(
    project: &dyn Project,
) -> std::result::Result<AnalyzerStoreContext, StoreError> {
    let store = AnalyzerStore::open_ephemeral()
        .map_err(|error| error.context("opening the ephemeral analyzer store"))?;
    Ok(store_context_from_store(project, store, true))
}

pub(crate) fn persistent_store_context(
    project: &dyn Project,
) -> std::result::Result<AnalyzerStoreContext, StoreError> {
    persistent_store_context_with_automatic_gc(project, true)
}

pub(crate) fn persistent_store_context_without_automatic_gc(
    project: &dyn Project,
) -> std::result::Result<AnalyzerStoreContext, StoreError> {
    persistent_store_context_with_automatic_gc(project, false)
}

fn persistent_store_context_with_automatic_gc(
    project: &dyn Project,
    automatic_gc: bool,
) -> std::result::Result<AnalyzerStoreContext, StoreError> {
    let store = match project.persistence_root() {
        Some(root) => {
            let db_path = crate::analyzer::store::analyzer_db_path(root);
            AnalyzerStore::open_persistent(&db_path).map_err(|error| {
                error.context(format!(
                    "opening the persisted analyzer store at {}; this cache is derived state, so remove {} and retry to rebuild it",
                    db_path.display(),
                    db_path.display(),
                ))
            })?
        }
        None => {
            return Err(StoreError::new(rootless_persistence_message(
                project.root(),
            )));
        }
    };
    Ok(store_context_from_store(project, store, automatic_gc))
}

/// Report a persisted build over a project with no persistence identity, with
/// its exits ordered by how much reuse they preserve.
///
/// Silently opening a throwaway store here was the old behavior and the reason
/// this message exists: a caller that asked for persistence got a database that
/// was deleted on drop, so every run re-parsed the whole world and nothing said
/// so. The ephemeral door is still open, but only through the footgun
/// constructor, where the caller states the intent.
fn rootless_persistence_message(root: &std::path::Path) -> String {
    format!(
        "cannot build a persisted analyzer over {}: this project has no persistence root, so \
         there is no identity to cache under.\n\
         A persisted build reuses content-addressed facts across runs; a project with no \
         persistence root has nowhere to put them, and a store that is discarded on drop is not \
         what was asked for.\n\
         1. Analyze through a rooted project. A FilesystemProject over the checkout persists to \
         the shared cache at the primary repository root, and every linked worktree shares it.\n\
         2. For a whole immutable revision, use the shared revision cache: \
         RevisionExport::build_workspace, or build_revision_analyzer. A fact keyed by blob id \
         describes those bytes for every consumer, so the revision's blobs stay warm.\n\
         3. If the view really is session-only or partial (a changed-file-scoped set, a checkout \
         you must leave byte-identical, cold-build measurement), say so with \
         WorkspaceAnalyzer::build_ephemeral_footgun. A partial file set must not become a \
         workspace's cached picture of itself.\n\
         4. For a multi-root host whose root set resolves to no machine cache directory, set \
         BIFROST_CACHE_ROOT=<writable local root>; Bifrost derives one root-set-specific child \
         under it.",
        root.display(),
    )
}

/// Store context for one immutable revision image whose parsed facts belong in
/// the repository's shared content-addressed cache.
///
/// The store is supplied by the caller rather than derived from the project,
/// because a revision image's root is a self-deleting export directory: the
/// cache that serves it is the one at the *original* repository root, and no
/// funnel from the export path can find it. Automatic garbage collection is
/// off for the same reason -- reachability is computed from the analyzed root,
/// and the export directory holds no Git repository to compute it from.
pub(crate) fn revision_image_store_context(
    project: &dyn Project,
    store: Arc<AnalyzerStore>,
) -> AnalyzerStoreContext {
    store_context_from_shared_store(project, store, false)
}

fn store_context_from_store(
    project: &dyn Project,
    store: AnalyzerStore,
    automatic_gc: bool,
) -> AnalyzerStoreContext {
    store_context_from_shared_store(project, Arc::new(store), automatic_gc)
}

fn store_context_from_shared_store(
    project: &dyn Project,
    store: Arc<AnalyzerStore>,
    automatic_gc: bool,
) -> AnalyzerStoreContext {
    let liveness = gitblob::discover(project.root())
        .and_then(|repo| Liveness::new(repo).ok())
        .map(Arc::new);
    let gc = if automatic_gc {
        crate::analyzer::store::gc::AnalyzerGcCoordinator::default()
    } else {
        crate::analyzer::store::gc::AnalyzerGcCoordinator::disabled()
    };
    AnalyzerStoreContext {
        store,
        workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
        gc: Arc::new(gc),
        liveness,
        workspace_snapshot: None,
        workspace_listing_complete: true,
        revision_blobs: None,
        live_paths: Arc::new(LivePathMap::trust_filesystem_generation()),
        generations: Arc::new(HashMap::default()),
        build_abort: Arc::new(BuildAbort::default()),
        build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
    }
}

pub trait LanguageAdapter: Send + Sync + 'static {
    fn language(&self) -> Language;
    fn query_directory(&self) -> &'static str;
    fn parser_language(&self) -> TsLanguage {
        crate::analyzer::parser_language_for(self.language())
            .expect("analyzable language must have a registered parser grammar")
    }
    fn parser_language_for_file(&self, file: &ProjectFile) -> TsLanguage {
        crate::analyzer::parser_language_for_path(self.language(), file.rel_path())
            .expect("analyzable language must have a registered parser grammar")
    }
    /// The byte ranges of `source` this file's parser may read, or `None` to
    /// read the whole file.
    ///
    /// Only C# overrides this. Its grammar cannot represent a preprocessor
    /// directive inside a declaration, so a directive that splits a member
    /// signature or an expression breaks the parse and the declaration walk
    /// then loses the members around it (issue #1803). C# answers with the
    /// ranges that hide directive lines and inactive conditional branches.
    /// Ranges select bytes of the original source, so every node keeps its
    /// raw-file offset and no transformed source exists.
    fn parser_included_ranges(
        &self,
        _file: &ProjectFile,
        _source: &str,
    ) -> Option<Vec<tree_sitter::Range>> {
        None
    }
    /// The storage key this specific `file` was (or would be) persisted
    /// under. Derived from the file's own detected language rather than
    /// this adapter's language, so the cross-adapter row guard in
    /// `paths_for_row`/`resolve_candidate_rows_limited` actually
    /// discriminates: two adapters can share a live file (or a stale
    /// candidate row's blob oid can resolve to a path analyzed by a
    /// different language) and must not serve each other's rows.
    /// Multi-key adapters (e.g. TypeScript, which splits `.ts`/`.tsx`
    /// into distinct storage keys) override this.
    /// The storage language key a file's rows live under.
    ///
    /// `&'static str` rather than `String`: every key is a language config
    /// label chosen from a fixed set, and this is asked once per candidate row
    /// per live path on the query paths, where allocating a key only to compare
    /// it to a stored one was a measurable share of a chromium probe phase
    /// (issue #1928). A caller that needs ownership says so.
    fn storage_language_key_for_file(&self, file: &ProjectFile) -> &'static str {
        // An include-claimed file (#1837) has an extension no language owns, so
        // the file-derived key would be `Language::None` and its rows would
        // land under a storage key this adapter never serves a generation for.
        // Claiming adapters own that whole unclaimed-extension key namespace,
        // which is sound exactly while one language infers claims -- the
        // invariant `LanguageAdapter::infer_claimed_files` documents.
        if self.claims_included_files() && crate::analyzer::common::has_unclaimed_extension(file) {
            return self.language().config_label();
        }
        crate::analyzer::common::language_for_file(file).config_label()
    }
    /// Whether this adapter infers additional analyzable files from the imports
    /// of the files its extension list already selects (#1837).
    ///
    /// The gate exists so the generic pipeline can skip the whole inference
    /// stage -- a workspace listing scan plus one import-fact hydration -- for
    /// the eleven languages that do not infer.
    fn claims_included_files(&self) -> bool {
        false
    }
    /// The claim edges this adapter contributes: for each source file, the
    /// workspace files it references that no language's extension registry
    /// claims and that this adapter therefore adopts for indexing (#1837).
    ///
    /// `sources` pairs each analyzed file of this adapter with the imports
    /// recorded for it. `claimable` is every workspace file whose extension no
    /// language owns (extensionless files included); returning anything outside
    /// it is a contract violation the caller asserts against. A source with no
    /// claimable reference contributes no entry.
    ///
    /// Edges, not a flat set: the caller closes the relation transitively and
    /// drops a claim when the last reference to it disappears, and both need
    /// the attribution. The caller also drives the closure -- it calls this
    /// with the files it has just adopted and repeats until the set stops
    /// growing, so an implementation answers only for the `sources` it is
    /// handed and never walks the graph itself.
    ///
    /// Determinism: the answer must be a pure function of `sources`,
    /// `claimable` and the static extension registry. No discovery order, no
    /// first-claimant-wins.
    ///
    /// CLAIMS SEAM -- single claimant. C++ is the only implementor today, and
    /// [`crate::analyzer::languages::claim_inferring_languages`] is the registry
    /// that says so. If a second language ever infers claims, a file both
    /// languages claim must be dropped from BOTH sets and reported by a
    /// diagnostic naming the claimants, and
    /// [`LanguageAdapter::storage_language_key_for_file`] above must stop
    /// handing the unclaimed-extension key namespace to whichever adapter is
    /// asking. The registry's own assertion pins the single-claimant premise;
    /// no multi-claimant machinery exists yet on purpose.
    fn infer_claimed_files(
        &self,
        sources: &[(ProjectFile, Vec<ImportInfo>)],
        claimable: &BTreeSet<ProjectFile>,
    ) -> HashMap<ProjectFile, BTreeSet<ProjectFile>> {
        let _ = (sources, claimable);
        HashMap::default()
    }
    /// The demand [`LanguageAdapter::infer_claimed_files`] leaves behind
    /// (#1865): for each source, the path-suffix keys a workspace file that
    /// does not exist yet would have to match for one of that source's import
    /// directives to reach it.
    ///
    /// Recorded at the imports tier by `reconcile_claimed_files` from exactly
    /// the same `sources`, so the record and the relation always describe one
    /// generation. `TreeSitterAnalyzer::update` consults it to decide whether a
    /// newly created unclaimed-extension file can change the claim relation at
    /// all; a miss means the event is local and no bulk store read runs.
    ///
    /// The contract is completeness, not precision: an implementation must emit
    /// a key for every file its resolution *could* accept, because the caller
    /// treats a miss as proof that re-derivation would find nothing. An extra
    /// key costs one derivation; a missing one leaves a file unindexed until the
    /// next full build. An adapter that does not claim included files has no
    /// demand to record.
    fn claim_demand(
        &self,
        sources: &[(ProjectFile, Vec<ImportInfo>)],
    ) -> HashMap<ProjectFile, BTreeSet<String>> {
        let _ = sources;
        HashMap::default()
    }
    fn storage_language_keys(&self) -> Vec<(String, TsLanguage)> {
        vec![(
            self.language().config_label().to_string(),
            self.parser_language(),
        )]
    }
    fn file_extension(&self) -> &'static str;
    fn normalize_full_name(&self, fq_name: &str) -> String {
        fq_name.to_string()
    }
    /// Canonical lookup identity for a name that is already structured.
    /// Persistence and relational queries use this method; rendered-string
    /// normalization remains only for legacy input surfaces during migration.
    fn normalize_fq_name(&self, fq_name: &FqName) -> FqName {
        fq_name.clone()
    }
    /// Additional containers through which a definition is directly visible,
    /// beyond its structured FqName parent. The returned names are structured
    /// full identities; persistence converts them to the same content tail as
    /// the owning unit.
    fn visibility_containers(&self, _unit: &CodeUnit) -> Vec<FqName> {
        Vec::new()
    }
    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        unit.identifier().to_string()
    }
    /// Whether fully-qualified lookup keys are intrinsic to blob contents.
    /// Path-derived adapters must leave these projections absent because one
    /// blob may be mounted at multiple live workspace paths.
    fn persist_content_stable_lookup_keys(&self) -> bool {
        false
    }
    /// The separators this adapter's lookup spellings are peeled on -- and, by
    /// the same declaration, the separators it treats as a *join* wherever one
    /// appears in a spelling.
    ///
    /// That second reading is what lets `definition_candidate_short_names` drop
    /// a spelling as a structurally guaranteed miss. A language whose
    /// identifiers can themselves contain a separator must not list it: scala's
    /// cons class is named `::`, so scala peels on `.` alone and `::` in a
    /// scala spelling is a declaration's name rather than a join. The one
    /// declaration answers both questions, so the two cannot drift apart.
    fn lookup_candidate_separators(&self) -> &'static [&'static str] {
        &[".", "::"]
    }
    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        lookup_suffix_candidates(normalized_fq_name, self.lookup_candidate_separators())
    }
    fn is_anonymous_structure(&self, _fq_name: &str) -> bool {
        false
    }
    fn storage_content_qualifier(&self, code_unit: &CodeUnit, _content_qualifier: &str) -> String {
        code_unit.package_name().to_string()
    }
    /// Whether an ASCII substring match over the persisted content qualifier
    /// is a sound candidate filter for this adapter's normalized FQNs.
    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        true
    }
    fn storage_file_content_qualifier(&self, package_name: &str) -> String {
        package_name.to_string()
    }
    fn hydrate_content_qualifier(&self, content_qualifier: &str, _file: &ProjectFile) -> String {
        content_qualifier.to_string()
    }
    /// The package prefix `file` contributes on its own, for the storage-side
    /// name prefilter of a symbol search.
    ///
    /// A search pattern is matched against a hydrated fully-qualified name, so a
    /// prefilter over persisted columns is sound only if every package prefix
    /// hydration can produce is visible to it. The persisted
    /// `content_qualifier` is one such prefix; this is the other one, the value
    /// hydration falls back to when the qualifier carries nothing. The default
    /// hydrates with an empty qualifier, which is exactly that fallback for
    /// every adapter whose hydration either ignores the qualifier or returns it
    /// unchanged.
    ///
    /// `None` means hydration blends the qualifier into a path-derived prefix,
    /// so the reachable prefixes are not enumerable from the path and no
    /// prefilter may drop this file's declarations.
    fn prefilter_path_package(&self, file: &ProjectFile) -> Option<String> {
        Some(self.hydrate_content_qualifier("", file))
    }
    /// The anchor a unit's persisted package prefix is resolved against when
    /// the extractor recorded none. `None` means this language's packages are
    /// intrinsic to the blob and must be persisted in full.
    fn default_package_anchor(&self) -> Option<PackageAnchor> {
        None
    }
    /// The anchor used to publish a parsed file's package membership even when
    /// the file contains no persisted declarations. `None` means declaration
    /// facts alone define this language's workspace package inventory.
    fn workspace_file_package_anchor(&self) -> Option<PackageAnchor> {
        None
    }
    /// Whether this language has any non-source workspace inputs that can
    /// change the canonical identity of its declarations.
    fn has_workspace_package_identity_inputs(&self) -> bool {
        false
    }
    /// Whether a non-source `file` contributes to this language's canonical
    /// workspace package identity. An unsaved overlay of such an input cannot
    /// be represented by package rows built from the disk workspace, so exact
    /// package misses cease to be authoritative for that request snapshot.
    fn workspace_package_identity_input(&self, _file: &ProjectFile) -> bool {
        false
    }
    /// Additional import spellings for one canonical workspace package.
    ///
    /// The canonical row remains authoritative declaration identity. Aliases
    /// are package-membership rows only, for language layouts such as Go's
    /// `vendor` directories where source imports a structured path suffix.
    fn workspace_package_aliases(&self, _file: &ProjectFile, _canonical: &FqName) -> Vec<FqName> {
        Vec::new()
    }
    /// Resolve `anchor` to the live package prefix it names for `file`. `None`
    /// means this adapter cannot place that anchor, which makes the unit fall
    /// back to a fully persisted name. `content_qualifier` is the unit's stored
    /// qualifier text, which some languages (Go) need to reconstruct the
    /// prefix.
    fn resolve_package_anchor(
        &self,
        _anchor: PackageAnchor,
        _content_qualifier: &str,
        _file: &ProjectFile,
    ) -> Option<FqName> {
        None
    }
    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        !code_unit.is_file_scope()
    }
    fn storage_contains_tests(&self, state: &FileState) -> bool {
        state.contains_tests
    }
    fn hydrate_contains_tests(&self, stored: bool, _file: &ProjectFile, _source: &str) -> bool {
        stored
    }
    fn synthesize_hydrated_units(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _state: &mut FileState,
    ) {
    }
    fn synthesize_summary_projection(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _has_structured_imports: bool,
        _projection: &mut SummaryFileProjection,
    ) {
    }
    fn path_synthetic_module_unit(&self, _file: &ProjectFile) -> Option<CodeUnit> {
        None
    }
    fn has_path_synthetic_module_units(&self) -> bool {
        false
    }
    fn path_synthetic_module_requires_imports(&self) -> bool {
        false
    }
    fn include_path_synthetic_module(&self, _has_structured_imports: bool) -> bool {
        true
    }
    fn contains_tests(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _tree: &Tree,
        _parsed: &ParsedFile,
    ) -> bool {
        false
    }
    fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile;
    /// Every reading of this blob: the file's own, plus any extra row-sets it
    /// contributes under storage language keys other than
    /// [`LanguageAdapter::storage_language_key_for_file`]'s answer.
    ///
    /// One blob normally has one reading, and the default says so. C++ is the
    /// exception: a header has no compilation language of its own, so its
    /// blob has both a C and a C++ reading, and the two disagree about where a
    /// tag declared inside an aggregate member list lives (issue #1970). The
    /// adapter returns the second reading only when it actually differs from
    /// the first, which is what makes "no rows under the other key" mean
    /// "identical to the primary" rather than "not computed yet".
    ///
    /// The readings arrive together because everything they share -- the tree,
    /// its parent index, and every fact family the second reading's dialect
    /// does not change -- is then computed once (Milestone 3b of
    /// `.agents/plans/immutable-revision-persisted-fact-reuse.md`). Called once
    /// per blob parse, on one tree, so an implementor must not re-parse. Each
    /// extra reading is persisted under its returned key at that key's own
    /// store generation and is never hydrated back into the file's own state.
    fn parse_file_with_projections(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> (ParsedFile, Vec<(&'static str, ParsedFile)>) {
        (self.parse_file(file, source, tree), Vec::new())
    }
    fn definition_priority(&self, _code_unit: &CodeUnit) -> i32 {
        0
    }
    /// Optional per-language cognitive-complexity configuration. Languages
    /// without a scoring config return `None`, which makes
    /// [`TreeSitterAnalyzer::compute_cognitive_complexities`] yield an empty
    /// result.
    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        None
    }
    /// Optional structural-search spec (issue #328). Languages that return
    /// `Some` expose `query_code` support through
    /// [`crate::analyzer::structural::StructuralFactProvider`].
    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        crate::analyzer::structural_spec_for(self.language())
    }
}

pub(crate) fn lookup_suffix_candidates(
    normalized_fq_name: &str,
    separators: &[&str],
) -> Vec<String> {
    let mut candidates = vec![normalized_fq_name.to_string()];
    let mut frontier = vec![normalized_fq_name.to_string()];
    while let Some(current) = frontier.pop() {
        for separator in separators {
            if let Some((_, suffix)) = current.split_once(separator)
                && !suffix.is_empty()
            {
                let suffix = suffix.to_string();
                if !candidates.contains(&suffix) {
                    frontier.push(suffix.clone());
                    candidates.push(suffix);
                }
            }
        }
    }
    candidates.sort_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));
    candidates.dedup();
    candidates
}

pub type BuildProgress = Arc<dyn Fn(BuildProgressEvent) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProgressPhase {
    Enumerate,
    Reconcile,
    Parse,
    Persist,
    Index,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildProgressEvent {
    pub language: Language,
    pub phase: BuildProgressPhase,
    pub completed: usize,
    pub total: usize,
    pub file: Option<ProjectFile>,
}

impl BuildProgressEvent {
    fn new(
        language: Language,
        phase: BuildProgressPhase,
        completed: usize,
        total: usize,
        file: Option<ProjectFile>,
    ) -> Self {
        Self {
            language,
            phase,
            completed,
            total,
            file,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileState {
    pub(crate) source: String,
    pub(crate) package_name: String,
    /// Content-only qualifier persisted with a blob. Languages whose canonical
    /// package identity depends on the live path recompose it during hydration.
    pub(crate) content_qualifier: String,
    pub(crate) top_level_declarations: Vec<CodeUnit>,
    pub(crate) declarations: HashSet<CodeUnit>,
    pub(crate) definition_lookup_units: HashSet<CodeUnit>,
    pub(crate) imports: Vec<ImportInfo>,
    pub(crate) scala_exports: HashMap<CodeUnit, Vec<crate::analyzer::ScalaExportInfo>>,
    /// Per-file Rust usage facts on their way to the `rust_*` fact tables (see
    /// [`brokk_bifrost_core::analyzer::rust_facts`]). Empty for every other
    /// language, and empty on a `FileState` hydrated from the store: the query
    /// side reads those rows straight from SQL by blob oid rather than through
    /// a materialized `FileState`, so hydrating them here would be dead weight
    /// on every cache hit. Same rule as `parse_errors` below.
    pub(crate) rust_usage_facts: brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts,
    pub(crate) raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    pub(crate) supertype_lookup_paths: HashMap<CodeUnit, Vec<String>>,
    pub(crate) type_identifiers: HashSet<String>,
    pub(crate) signatures: HashMap<CodeUnit, Vec<String>>,
    pub(crate) signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
    pub(crate) cpp_template_metadata: HashMap<CodeUnit, CppTemplateMetadata>,
    pub(crate) ruby_method_dispatch_modes: HashMap<CodeUnit, RubyMethodDispatchMode>,
    pub(crate) ranges: HashMap<CodeUnit, Vec<Range>>,
    pub(crate) children: HashMap<CodeUnit, Vec<CodeUnit>>,
    pub(crate) scala_traits: HashSet<CodeUnit>,
    pub(crate) type_aliases: HashSet<CodeUnit>,
    pub(crate) contains_tests: bool,
    /// Declarations that lie in a structurally-evidenced test region (see
    /// [`ParsedFile::test_region_units`]). Persisted per-unit via the
    /// `code_units.in_test_region` column and consulted by symbol-level test
    /// filtering (`search_symbols`, commit symbol snapshots). Empty for
    /// languages that do not thread test-region taint.
    pub(crate) test_region_units: HashSet<CodeUnit>,
    /// Declaration-materialization provenance recorded by the language walk
    /// (see [`ParsedFile::materialization_records`]); persisted per file.
    pub(crate) materialization_records: Vec<MaterializationRecord>,
    /// Tree-sitter parse errors captured during `analyze_file`. The LSP
    /// diagnostic handler reads this instead of re-parsing on every keystroke
    /// — see issue #102. `None` when the `FileState` was hydrated from the
    /// blob store (which does not carry parse_errors); the diagnostic handler
    /// falls back to a fresh parse in that case until the next `update`
    /// re-populates the field.
    pub(crate) parse_errors: Option<Vec<crate::analyzer::ParseError>>,
    /// Whether tree-sitter completed the whole source before this state was
    /// assembled. A timed-out parse still carries a conservative file-scope
    /// marker for in-memory reads, but the store must never publish that
    /// marker as a complete parsed blob.
    pub(crate) parse_complete: bool,
    /// Row-sets this same blob contributes under storage language keys other
    /// than the file's own, produced by
    /// [`LanguageAdapter::parse_file_with_projections`] and persisted alongside
    /// the primary row-set (see `write_parsed_blob_tx`).
    ///
    /// Empty for every language but C++, and empty on a hydrated state: a
    /// projection is a write-side product of one parse, never a hydration
    /// output. `blobs`/`code_units` are already keyed `(blob_oid, lang)`, so
    /// this needs no schema of its own.
    pub(crate) additional_projections: Vec<(&'static str, Arc<FileState>)>,
}

impl FileState {
    /// Return a conservative retained-byte estimate for cache admission.
    ///
    /// Rust cannot report heap allocation sizes. This accounts for owned
    /// buffers and map slots, then charges a fixed allocator allowance. The
    /// value is a cache budget estimate, not an RSS measurement.
    fn estimated_retained_bytes(&self) -> usize {
        const ALLOCATION_ALLOWANCE_NUMERATOR: usize = 3;
        const ALLOCATION_ALLOWANCE_DENOMINATOR: usize = 2;

        let strings = self
            .imports
            .iter()
            .map(|import| import.raw_snippet.capacity())
            .chain(self.type_identifiers.iter().map(|value| value.capacity()))
            .chain(self.raw_supertypes.iter().flat_map(|(unit, values)| {
                std::iter::once(unit.fq_name().capacity())
                    .chain(values.iter().map(|value| value.capacity()))
            }))
            .chain(
                self.supertype_lookup_paths
                    .values()
                    .flat_map(|values| values.iter().map(|value| value.capacity())),
            )
            .chain(
                self.signatures
                    .values()
                    .flat_map(|values| values.iter().map(|value| value.capacity())),
            )
            .fold(0usize, usize::saturating_add);
        let collection_slots = self
            .top_level_declarations
            .capacity()
            .saturating_mul(std::mem::size_of::<CodeUnit>())
            .saturating_add(
                self.declarations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.definition_lookup_units
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.imports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ImportInfo>()),
            )
            .saturating_add(
                self.scala_exports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(
                        CodeUnit,
                        Vec<crate::analyzer::ScalaExportInfo>,
                    )>()),
            )
            .saturating_add(
                self.raw_supertypes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<String>)>()),
            )
            .saturating_add(
                self.supertype_lookup_paths
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<String>)>()),
            )
            .saturating_add(
                self.type_identifiers
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                self.signatures
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<String>)>()),
            )
            .saturating_add(
                self.signature_metadata
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<SignatureMetadata>)>()),
            )
            .saturating_add(
                self.cpp_template_metadata
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, CppTemplateMetadata)>()),
            )
            .saturating_add(
                self.ruby_method_dispatch_modes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, RubyMethodDispatchMode)>()),
            )
            .saturating_add(
                self.ranges
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<Range>)>()),
            )
            .saturating_add(
                self.children
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<CodeUnit>)>()),
            )
            .saturating_add(
                self.scala_traits
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.type_aliases
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.test_region_units
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.materialization_records
                    .capacity()
                    .saturating_mul(std::mem::size_of::<MaterializationRecord>()),
            )
            .saturating_add(
                self.parse_errors
                    .as_ref()
                    .map(|errors| {
                        errors
                            .capacity()
                            .saturating_mul(std::mem::size_of::<crate::analyzer::ParseError>())
                    })
                    .unwrap_or_default(),
            );
        let direct = std::mem::size_of::<Self>()
            .saturating_add(self.source.capacity())
            .saturating_add(self.package_name.capacity())
            .saturating_add(self.content_qualifier.capacity())
            .saturating_add(strings)
            .saturating_add(collection_slots);
        direct
            .saturating_mul(ALLOCATION_ALLOWANCE_NUMERATOR)
            .saturating_div(ALLOCATION_ALLOWANCE_DENOMINATOR)
    }
}

/// The indexed backing a prepared tree consults for declaration facts. The
/// contract itself is core-owned so a language crate can consume prepared
/// syntax; `FileState` is the analysis-side storage record that satisfies it.
impl PreparedSourceIndex for FileState {
    fn source(&self) -> &str {
        &self.source
    }

    fn declaration_ranges(&self, code_unit: &CodeUnit) -> Option<&[Range]> {
        self.ranges.get(code_unit).map(Vec::as_slice)
    }

    fn direct_children(&self, owner: &CodeUnit) -> Option<&[CodeUnit]> {
        self.children.get(owner).map(Vec::as_slice)
    }
}

/// The narrowed view a bulk state read hands to a whole-workspace pass; see
/// [`IndexedFileFacts`].
impl IndexedFileFacts for FileState {
    fn top_level_declarations(&self) -> &[CodeUnit] {
        &self.top_level_declarations
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.imports
    }
}

/// The requested source snapshot exceeded a caller-supplied preparation cap.
/// `minimum_source_bytes` is the smallest size proven by the bounded read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedSyntaxLimitExceeded {
    minimum_source_bytes: usize,
}

impl PreparedSyntaxLimitExceeded {
    pub(crate) const fn minimum_source_bytes(self) -> usize {
        self.minimum_source_bytes
    }
}

#[derive(Debug)]
pub(crate) enum PreparedSyntaxLimitedOutcome {
    /// The prepared tree, plus the blob identity of the exact source snapshot
    /// it was prepared from. The two are captured together by
    /// `resolve_prepared_source`, so a caller may pair anything it derives
    /// from the source with that identity.
    Available(Oid, Arc<PreparedSyntaxTree>),
    Exceeded(PreparedSyntaxLimitExceeded),
    Cancelled,
    Unavailable,
}

enum PreparedSyntaxPreparation {
    Complete(Option<Arc<PreparedSyntaxTree>>),
    Cancelled,
}

#[derive(Clone)]
pub(crate) struct HierarchyDeclarationFacts {
    pub(crate) declaration: CodeUnit,
    pub(crate) primary_range: Option<Range>,
    pub(crate) in_test_region: bool,
    pub(crate) imports: Arc<[ImportInfo]>,
    pub(crate) raw_supertypes: Arc<[String]>,
    storage_key: Option<HierarchyStorageKey>,
}

pub(crate) struct ImportFileFacts {
    pub(crate) package_name: String,
    pub(crate) imports: Vec<ImportInfo>,
    pub(crate) contains_tests: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirtyFileStateStatus {
    Retryable,
    TerminalStale,
    TerminalResourceBound,
}

fn dirty_file_state_status(error: &StoreError) -> DirtyFileStateStatus {
    if error.is_stale_generation() {
        DirtyFileStateStatus::TerminalStale
    } else if error.is_resource_bound() {
        DirtyFileStateStatus::TerminalResourceBound
    } else {
        DirtyFileStateStatus::Retryable
    }
}

#[derive(Debug, Clone)]
struct DirtyFileState {
    state: Arc<FileState>,
    generation: GenerationId,
    attempts: usize,
    next_retry_at: Instant,
    status: DirtyFileStateStatus,
    _last_error: String,
}

#[derive(Debug, Default)]
struct AnalyzerRuntimeState {
    fresh_parse_errors: HashMap<ProjectFile, Vec<crate::analyzer::ParseError>>,
    dirty_file_states: Mutex<HashMap<FileStateCacheKey, DirtyFileState>>,
    dirty_path_symbol_rows: Mutex<HashMap<ProjectFile, (String, PathSymbolRow)>>,
    /// Whether this generation accounts for every workspace package file.
    /// Positive package rows remain usable when false; only absence loses
    /// authority. Incremental generations may clear but never restore it.
    workspace_package_inventory_complete: bool,
    /// Content identities of the non-source inputs that qualified this
    /// generation's workspace declarations. Request overlays are authoritative
    /// only when their digest agrees with this exact baseline.
    workspace_package_identity_input_digests: HashMap<ProjectFile, [u8; 32]>,
    seeded_file_states: Vec<(FileStateCacheKey, Arc<FileState>)>,
    persistence_stats: PersistBatchStats,
    /// Include-driven claim relation for this generation (#1837): analyzed file
    /// -> the unclaimed-extension workspace files it references. Empty for the
    /// eleven adapters that do not infer claims. Retained rather than recomputed
    /// so an incremental update re-reads imports only for the files that
    /// changed: everything else's edges are still valid, and the claim set is
    /// the transitive closure of the whole relation from the
    /// extension-discovered roots.
    claim_edges: HashMap<ProjectFile, BTreeSet<ProjectFile>>,
    /// The unresolved demand the same derivation recorded (#1865). Carried
    /// forward across an update exactly like `claim_edges`, and for the same
    /// reason: both are per-generation facts about the relation, and re-deriving
    /// one without the other would let `update` consult a record describing a
    /// generation the edges no longer match.
    tier_demand: TierDemand,
    /// Bulk import-fact reads the include-claim derivation performed while
    /// producing this generation (#1865).
    ///
    /// The observable the locality pin needs. The tier funnel on
    /// `TreeSitterAnalyzer` cannot serve it: claim derivation is a static
    /// pass that runs before the analyzer holding the new generation exists,
    /// so it has no `&self` to count against. Counting on the state it
    /// produces attributes the reads to exactly the generation that made them.
    claim_import_reads: AtomicUsize,
}

/// The previous generation's include-claim relation, handed to the next
/// derivation by `TreeSitterAnalyzer::reconcile_claimed_files`.
///
/// One struct rather than two parameters because the edges and the unresolved
/// demand recorded with them are only ever correct together: an update that
/// carried one forward without the other would consult a record describing a
/// generation the relation no longer matches. Both are empty on a build, which
/// re-derives them from the whole extension-discovered set.
#[derive(Debug, Default)]
struct RetainedClaimRelation {
    edges: HashMap<ProjectFile, BTreeSet<ProjectFile>>,
    demand: TierDemand,
}

#[derive(Debug, Default)]
struct ClaimMembershipDelta {
    added: Vec<ProjectFile>,
    dropped: Vec<ProjectFile>,
}

impl AnalyzerRuntimeState {
    fn new(
        fresh_parse_errors: HashMap<ProjectFile, Vec<crate::analyzer::ParseError>>,
        dirty_file_states: HashMap<FileStateCacheKey, DirtyFileState>,
        dirty_path_symbol_rows: HashMap<ProjectFile, (String, PathSymbolRow)>,
        seeded_file_states: Vec<(FileStateCacheKey, Arc<FileState>)>,
    ) -> Self {
        let workspace_package_inventory_complete =
            dirty_file_states.is_empty() && dirty_path_symbol_rows.is_empty();
        Self {
            fresh_parse_errors,
            dirty_file_states: Mutex::new(dirty_file_states),
            dirty_path_symbol_rows: Mutex::new(dirty_path_symbol_rows),
            workspace_package_inventory_complete,
            workspace_package_identity_input_digests: HashMap::default(),
            seeded_file_states,
            persistence_stats: PersistBatchStats::default(),
            claim_edges: HashMap::default(),
            tier_demand: TierDemand::default(),
            claim_import_reads: AtomicUsize::new(0),
        }
    }

    /// Fold `other`'s parse errors and seeded states into this state. Used when
    /// a build reconciles include-claimed files in a second pass: the two
    /// passes produce one generation's runtime state, not two.
    fn absorb(&mut self, other: AnalyzerRuntimeState) {
        let AnalyzerRuntimeState {
            fresh_parse_errors,
            dirty_file_states,
            dirty_path_symbol_rows,
            workspace_package_inventory_complete,
            workspace_package_identity_input_digests,
            seeded_file_states,
            persistence_stats,
            claim_edges,
            tier_demand,
            claim_import_reads,
        } = other;
        self.fresh_parse_errors.extend(fresh_parse_errors);
        // The second pass was handed this pass's dirty maps as input and
        // returns the merged result, so it replaces rather than extends.
        *self
            .dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned") = dirty_file_states
            .into_inner()
            .expect("dirty file-state mutex poisoned");
        *self
            .dirty_path_symbol_rows
            .lock()
            .expect("dirty path-symbol mutex poisoned") = dirty_path_symbol_rows
            .into_inner()
            .expect("dirty path-symbol mutex poisoned");
        self.workspace_package_inventory_complete &= workspace_package_inventory_complete;
        self.workspace_package_identity_input_digests
            .extend(workspace_package_identity_input_digests);
        self.seeded_file_states.extend(seeded_file_states);
        self.seeded_file_states
            .truncate(SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY);
        self.persistence_stats.merge(persistence_stats);
        self.claim_edges.extend(claim_edges);
        self.tier_demand.absorb(tier_demand);
        self.claim_import_reads
            .fetch_add(claim_import_reads.into_inner(), Ordering::Relaxed);
    }

    fn mark_workspace_package_inventory_incomplete(&mut self) {
        self.workspace_package_inventory_complete = false;
    }

    fn seed_snapshot_file_states(&self, cache: &mut SourceSnapshotFileStateIndex) {
        for (key, state) in self
            .seeded_file_states
            .iter()
            .take(SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY)
        {
            cache.insert(key.clone(), Arc::clone(state));
        }
    }

    fn dirty_snapshot(&self) -> HashMap<FileStateCacheKey, DirtyFileState> {
        self.dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .clone()
    }

    fn has_dirty_file_states(&self) -> bool {
        !self
            .dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .is_empty()
    }

    fn dirty_path_symbol_snapshot(&self) -> HashMap<ProjectFile, (String, PathSymbolRow)> {
        self.dirty_path_symbol_rows
            .lock()
            .expect("dirty path-symbol mutex poisoned")
            .clone()
    }

    fn dirty_content_qualifier(&self, key: &FileStateCacheKey) -> Option<String> {
        self.dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .get(key)
            .map(|dirty| dirty.state.content_qualifier.clone())
    }

    fn dirty_imports(&self, key: &FileStateCacheKey) -> Option<Vec<ImportInfo>> {
        self.dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .get(key)
            .map(|dirty| dirty.state.imports.clone())
    }

    fn dirty_file_state(&self, key: &FileStateCacheKey) -> Option<Arc<FileState>> {
        self.dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .get(key)
            .map(|dirty| Arc::clone(&dirty.state))
    }
}

struct ReconcileFileStates {
    files: Vec<ProjectFile>,
    replace_live_paths: bool,
    progress: Option<BuildProgress>,
    dirty_file_states: HashMap<FileStateCacheKey, DirtyFileState>,
    dirty_path_symbol_rows: HashMap<ProjectFile, (String, PathSymbolRow)>,
}

enum PreparedAnalysis {
    AllStarted,
    Ready {
        file: ProjectFile,
        prepared: Box<PreparedParsedBlob>,
    },
    PreparationFailed {
        file: ProjectFile,
        state: Arc<FileState>,
        error: String,
    },
    Unparseable(ProjectFile),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepresentativeBlobOutcome {
    Persisted,
    Dirty,
    Unparseable,
}

#[derive(Debug, Default)]
struct PreparedInFlight {
    current_items: usize,
    current_payload_bytes: usize,
    peak_items: usize,
    peak_payload_bytes: usize,
}

impl PreparedInFlight {
    fn add(&mut self, payload_bytes: usize) {
        self.current_items = self.current_items.saturating_add(1);
        self.current_payload_bytes = self.current_payload_bytes.saturating_add(payload_bytes);
        self.peak_items = self.peak_items.max(self.current_items);
        self.peak_payload_bytes = self.peak_payload_bytes.max(self.current_payload_bytes);
    }

    fn remove(&mut self, payload_bytes: usize) {
        self.current_items = self.current_items.saturating_sub(1);
        self.current_payload_bytes = self.current_payload_bytes.saturating_sub(payload_bytes);
    }
}

type PreparedPersistenceOutcome = Option<(Arc<FileState>, Option<StoreError>)>;
type PreparedOutcomeHandler<'a> = dyn FnMut(ProjectFile, PreparedPersistenceOutcome) + 'a;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileStateCacheKey {
    oid: Oid,
    rel_path: std::path::PathBuf,
}

struct StreamingFileRead {
    depth: usize,
    file: ProjectFile,
    state: Option<Arc<FileState>>,
}

thread_local! {
    static STREAMING_FILE_READS: RefCell<HashMap<usize, StreamingFileRead>> =
        RefCell::new(HashMap::default());
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PreparedSyntaxCacheKey {
    file_state: FileStateCacheKey,
    origin: PreparedSourceOrigin,
    overlay_revision: Option<OverlayRevision>,
    flavor: PreparedSyntaxCacheFlavor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PreparedSyntaxCacheFlavor {
    Indexed,
    ExactSource,
}

/// The retained footprint a `ByteBoundedStore` charges an entry against its
/// cap. Deliberate over-estimates: the cap must bound the real footprint from
/// above rather than track it.
trait ByteBounded {
    fn estimated_bytes(&self) -> usize;
}

impl ByteBounded for Arc<PreparedSyntaxTree> {
    fn estimated_bytes(&self) -> usize {
        prepared_syntax_retained_bytes(self.source().len())
    }
}

impl ByteBounded for Arc<[ImportInfo]> {
    fn estimated_bytes(&self) -> usize {
        self.iter()
            .map(|import| {
                import
                    .raw_snippet
                    .len()
                    .saturating_mul(IMPORT_INFO_BYTES_PER_SNIPPET_BYTE)
                    .saturating_add(IMPORT_INFO_PER_IMPORT_OVERHEAD_BYTES)
            })
            .fold(
                IMPORT_INFO_STORE_ENTRY_OVERHEAD_BYTES,
                usize::saturating_add,
            )
    }
}

impl ByteBounded for Arc<[CodeUnit]> {
    fn estimated_bytes(&self) -> usize {
        self.iter()
            .map(|unit| {
                unit.fq_name()
                    .len()
                    .saturating_add(unit.short_name().len())
                    .saturating_add(unit.signature().map_or(0, str::len))
                    .saturating_mul(TYPE_ALIAS_STORE_TEXT_BYTES_MULTIPLIER)
                    .saturating_add(TYPE_ALIAS_STORE_UNIT_OVERHEAD_BYTES)
            })
            .fold(TYPE_ALIAS_STORE_ENTRY_OVERHEAD_BYTES, usize::saturating_add)
    }
}

#[derive(Debug, Clone)]
struct EnclosingCodeUnitRange {
    range: Range,
    code_unit: CodeUnit,
    ordinal: usize,
}

/// A sorted interval index over the persisted declaration ranges in one
/// `FileState`. `prefix_max_end_bytes` stops a backwards scan once no earlier
/// range can contain the requested byte span.
#[derive(Debug)]
struct EnclosingCodeUnitIndex {
    ranges: Vec<EnclosingCodeUnitRange>,
    prefix_max_end_bytes: Vec<usize>,
}

impl EnclosingCodeUnitIndex {
    fn from_file_state(state: &FileState) -> Self {
        Self::from_declaration_ranges(state.declarations.iter().flat_map(|code_unit| {
            state
                .ranges
                .get(code_unit)
                .into_iter()
                .flatten()
                .copied()
                .map(|range| (code_unit.clone(), range))
        }))
    }

    fn from_declaration_ranges(declarations: impl IntoIterator<Item = (CodeUnit, Range)>) -> Self {
        let mut next_ordinals = HashMap::default();
        let mut ranges = Vec::new();
        for (code_unit, range) in declarations {
            let ordinal = next_ordinals.entry(code_unit.clone()).or_insert(0);
            let current_ordinal = *ordinal;
            *ordinal += 1;
            ranges.push(EnclosingCodeUnitRange {
                range,
                code_unit,
                ordinal: current_ordinal,
            });
        }
        ranges.sort_unstable_by(|left, right| {
            left.range
                .start_byte
                .cmp(&right.range.start_byte)
                .then_with(|| left.range.end_byte.cmp(&right.range.end_byte))
                .then_with(|| left.ordinal.cmp(&right.ordinal))
                .then_with(|| left.code_unit.cmp(&right.code_unit))
        });
        let mut prefix_max_end_bytes = Vec::with_capacity(ranges.len());
        let mut max_end_byte = 0;
        for candidate in &ranges {
            max_end_byte = max_end_byte.max(candidate.range.end_byte);
            prefix_max_end_bytes.push(max_end_byte);
        }
        Self {
            ranges,
            prefix_max_end_bytes,
        }
    }

    fn enclosing_code_unit(&self, range: &Range) -> Option<CodeUnit> {
        let upper_bound = self
            .ranges
            .partition_point(|candidate| candidate.range.start_byte <= range.start_byte);
        let mut first_containing_range_by_unit = HashMap::default();
        for index in (0..upper_bound).rev() {
            let candidate = &self.ranges[index];
            if candidate.range.contains(range) {
                first_containing_range_by_unit
                    .entry(candidate.code_unit.clone())
                    .and_modify(|(best_ordinal, best_range)| {
                        if candidate.ordinal < *best_ordinal {
                            *best_ordinal = candidate.ordinal;
                            *best_range = candidate.range;
                        }
                    })
                    .or_insert((candidate.ordinal, candidate.range));
            }
            if index == 0 || self.prefix_max_end_bytes[index - 1] < range.end_byte {
                break;
            }
        }
        select_enclosing_code_unit(
            first_containing_range_by_unit
                .into_iter()
                .map(|(code_unit, (_, candidate_range))| (candidate_range, code_unit)),
        )
    }
}

impl ByteBounded for Arc<EnclosingCodeUnitIndex> {
    fn estimated_bytes(&self) -> usize {
        self.ranges
            .iter()
            .map(|candidate| {
                candidate
                    .code_unit
                    .fq_name()
                    .len()
                    .saturating_add(candidate.code_unit.short_name().len())
                    .saturating_add(candidate.code_unit.signature().map_or(0, str::len))
                    .saturating_mul(ENCLOSING_CODE_UNIT_INDEX_TEXT_BYTES_MULTIPLIER)
                    .saturating_add(std::mem::size_of::<EnclosingCodeUnitRange>())
                    .saturating_add(ENCLOSING_CODE_UNIT_INDEX_ENTRY_OVERHEAD_BYTES)
            })
            .chain(std::iter::once(
                self.prefix_max_end_bytes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<usize>()),
            ))
            .fold(
                ENCLOSING_CODE_UNIT_INDEX_STORE_ENTRY_OVERHEAD_BYTES,
                usize::saturating_add,
            )
    }
}

/// A byte-bounded LRU of content-addressed derivations, retained across
/// requests behind whatever per-request single-flight layer the caller already
/// has.
///
/// Every key this store is instantiated with is content addressed -- blob oid
/// plus path, plus whatever else distinguishes the derivation -- so an edited
/// file resolves to a *different* key and can never read a stale value.
/// Superseded entries are dead weight the byte bound evicts, never a
/// correctness hazard, so there is no invalidation path.
///
/// A plain `HashMap` under one coarse mutex, following `parent_units`: each
/// access is a single bounded lookup, so per-key single-flight would cost more
/// than the duplicate derivation a race can cause. The store lives and dies
/// with the analyzer instance; clones share it, since a detached clone
/// recomputing the workspace is exactly the #1175 shape.
#[derive(Debug)]
struct ByteBoundedStore<K, V> {
    entries: HashMap<K, ByteBoundedStoreEntry<V>>,
    retained_bytes: usize,
    max_bytes: usize,
    /// Monotonic recency stamp. Bumped per access rather than maintaining an
    /// intrusive LRU list, which eviction reads back as a sort key.
    tick: u64,
}

#[derive(Debug)]
struct ByteBoundedStoreEntry<V> {
    value: V,
    estimated_bytes: usize,
    last_used: u64,
}

/// Prepared trees retained across requests, behind the per-request
/// `QueryReadCache::prepared_syntax` single-flight layer (#1450).
type PreparedSyntaxStore = ByteBoundedStore<PreparedSyntaxCacheKey, Arc<PreparedSyntaxTree>>;

/// Per-file import infos retained across requests (#1451). The warm Rust usage
/// scan asked for the same file's imports tens of thousands of times per
/// request, every one a SQLite hydration.
type ImportInfoStore = ByteBoundedStore<FileStateCacheKey, Arc<[ImportInfo]>>;
type TypeAliasStore = ByteBoundedStore<FileStateCacheKey, Arc<[CodeUnit]>>;
type EnclosingCodeUnitStore = ByteBoundedStore<FileStateCacheKey, Arc<EnclosingCodeUnitIndex>>;

impl<K: Eq + std::hash::Hash + Clone, V: Clone + ByteBounded> ByteBoundedStore<K, V> {
    fn new(max_bytes: usize) -> Self {
        Self {
            entries: HashMap::default(),
            retained_bytes: 0,
            max_bytes,
            tick: 0,
        }
    }

    fn get(&mut self, key: &K) -> Option<V> {
        self.tick += 1;
        let tick = self.tick;
        let entry = self.entries.get_mut(key)?;
        entry.last_used = tick;
        Some(entry.value.clone())
    }

    /// Only successful derivations reach here: a `None` outcome keeps its
    /// per-request-only negative caching, and a cancelled one is never retained
    /// anywhere.
    fn retain(&mut self, key: K, value: V) {
        let estimated_bytes = value.estimated_bytes();
        // A value that alone exceeds the whole budget would evict the entire
        // store to hold one entry that the next insert drops again.
        if estimated_bytes > self.max_bytes {
            return;
        }
        self.tick += 1;
        let replaced = self.entries.insert(
            key,
            ByteBoundedStoreEntry {
                value,
                estimated_bytes,
                last_used: self.tick,
            },
        );
        if let Some(replaced) = replaced {
            debug_assert!(self.retained_bytes >= replaced.estimated_bytes);
            self.retained_bytes -= replaced.estimated_bytes;
        }
        self.retained_bytes += estimated_bytes;
        if self.retained_bytes > self.max_bytes {
            self.evict_to_watermark();
        }
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.entries.clear();
        self.retained_bytes = 0;
        self.tick = 0;
    }

    /// Evicting past the cap down to a watermark amortizes the recency sort:
    /// stopping exactly at the cap would re-sort the whole map on every insert
    /// once the store is full.
    fn evict_to_watermark(&mut self) {
        let watermark = self.max_bytes / 8 * 7;
        let mut by_recency: Vec<(u64, K)> = self
            .entries
            .iter()
            .map(|(key, entry)| (entry.last_used, key.clone()))
            .collect();
        by_recency.sort_unstable_by_key(|(last_used, _)| *last_used);
        for (_, key) in by_recency {
            if self.retained_bytes <= watermark {
                break;
            }
            let evicted = self
                .entries
                .remove(&key)
                .expect("recency snapshot key must still be present");
            debug_assert!(self.retained_bytes >= evicted.estimated_bytes);
            self.retained_bytes -= evicted.estimated_bytes;
        }
    }
}

/// How many files' blob identities [`SourceBlobOidMemo`] retains. One entry is
/// a `ProjectFile`, a length, a 64-bit source hash, a 20-byte oid, and moka's
/// bookkeeping, so the cap bounds the memo to a few megabytes on the largest
/// workspaces; it is a bound rather than a target.
const SOURCE_BLOB_OID_MEMO_ENTRIES: u64 = 32_768;

/// The blob oid of the exact source string last hashed for one file, with the
/// cheap identity (length and FxHash) that lets a later call recognize the
/// same bytes without re-running SHA-1.
#[derive(Clone, Copy)]
struct SourceBlobIdentity {
    len: usize,
    source_hash: u64,
    oid: Oid,
}

/// Per-file memo of "the blob oid of these exact source bytes" (#2917).
///
/// Every query path that persists or looks up facts under a file's content key
/// used to recompute that key with libgit2's collision-detecting SHA-1 over the
/// whole source, per file per query: about 10% of a warm C++ inverse scan. The
/// answer is a pure function of the bytes, so it is memoized per file and
/// validated by the source's length and FxHash -- the identity the structural
/// facts cache already trusts -- and shared across analyzer clones like the
/// other content-keyed memos. A file whose bytes change (a dirty edit, a new
/// overlay revision) misses on the identity and is hashed once more.
struct SourceBlobOidMemo {
    entries: moka::sync::Cache<ProjectFile, SourceBlobIdentity>,
    /// SHA-1 computations performed, for the #2917 cost pin.
    #[cfg(any(test, feature = "test-support"))]
    hashes: AtomicUsize,
}

impl Default for SourceBlobOidMemo {
    fn default() -> Self {
        Self {
            entries: moka::sync::Cache::builder()
                .max_capacity(SOURCE_BLOB_OID_MEMO_ENTRIES)
                .build(),
            #[cfg(any(test, feature = "test-support"))]
            hashes: AtomicUsize::new(0),
        }
    }
}

impl SourceBlobOidMemo {
    fn oid_of(&self, file: &ProjectFile, source: &str) -> Oid {
        let source_hash = crate::analyzer::structural::provider::hash_source(source);
        if let Some(known) = self.entries.get(file)
            && known.len == source.len()
            && known.source_hash == source_hash
        {
            return known.oid;
        }
        #[cfg(any(test, feature = "test-support"))]
        self.hashes.fetch_add(1, Ordering::Relaxed);
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
            .expect("hashing in-memory bytes as a blob cannot fail");
        self.entries.insert(
            file.clone(),
            SourceBlobIdentity {
                len: source.len(),
                source_hash,
                oid,
            },
        );
        oid
    }
}

#[derive(Debug, Clone, Copy)]
struct ResolvedLiveSource {
    oid: Oid,
}

#[derive(Debug, Clone)]
struct ResolvedPreparedSource {
    oid: Oid,
    snapshot: ProjectSourceSnapshot,
}

/// A bound on how far `order` (see below) is allowed to grow past `capacity`
/// before we pay for a compaction pass. Lazy deletion means every `touch`
/// leaves a stale duplicate behind instead of scanning to remove it, so
/// without this bound a cache whose keys are re-touched far more often than
/// new keys are inserted (the common case: a handful of hot files touched on
/// every call) would grow `order` unboundedly even though `entries` stays at
/// `capacity`. Compacting at a small multiple of `capacity` keeps the
/// amortized cost of `touch`/`insert` O(1) while capping `order`'s memory at
/// O(capacity).
const CACHE_ORDER_COMPACT_FACTOR: usize = 4;

#[derive(Debug)]
struct BoundedFileCache<T> {
    capacity: usize,
    /// Value plus the `stamp` of the most recent `order` entry that refers to
    /// it. Only the `order` entry whose stamp matches this one is "live";
    /// any earlier entries for the same key are stale leftovers from prior
    /// touches (see `touch`).
    entries: HashMap<FileStateCacheKey, (Arc<T>, u64)>,
    /// Touch history, oldest first. A key may appear multiple times: every
    /// `get`/`insert` touch pushes a fresh `(key, stamp)` pair rather than
    /// scanning to relocate an existing one (that scan was the O(n)
    /// `VecDeque::retain` this type replaced). Eviction pops from the front
    /// and discards entries whose stamp no longer matches `entries`, so the
    /// first pop that *does* match is the true least-recently-used survivor.
    order: VecDeque<(FileStateCacheKey, u64)>,
    next_stamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileStateCacheSegment {
    Probation,
    Protected,
}

#[derive(Debug)]
struct FileStateCacheEntry {
    state: Arc<FileState>,
    estimated_bytes: usize,
    stamp: u64,
    segment: FileStateCacheSegment,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FileStateCacheStats {
    hits: usize,
    misses: usize,
    admissions: usize,
    promotions: usize,
    evictions: usize,
    rejected_admissions: usize,
}

/// A byte-bounded segmented LRU for complete file states.
///
/// One-time scans enter probation. A second access promotes an entry to the
/// protected segment. This keeps an unrelated scan from displacing an already
/// useful working set while the byte bound protects whale workspaces.
#[derive(Debug)]
struct SegmentedFileStateCache {
    max_bytes: usize,
    protected_max_bytes: usize,
    retained_bytes: usize,
    probation_bytes: usize,
    protected_bytes: usize,
    entries: HashMap<FileStateCacheKey, FileStateCacheEntry>,
    probation_order: VecDeque<(FileStateCacheKey, u64)>,
    protected_order: VecDeque<(FileStateCacheKey, u64)>,
    next_stamp: u64,
    stats: FileStateCacheStats,
}

impl SegmentedFileStateCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            protected_max_bytes: max_bytes.saturating_mul(4) / 5,
            retained_bytes: 0,
            probation_bytes: 0,
            protected_bytes: 0,
            entries: HashMap::default(),
            probation_order: VecDeque::new(),
            protected_order: VecDeque::new(),
            next_stamp: 0,
            stats: FileStateCacheStats::default(),
        }
    }

    fn get(&mut self, key: &FileStateCacheKey) -> Option<Arc<FileState>> {
        let Some(entry) = self.entries.get(key) else {
            self.stats.misses = self.stats.misses.saturating_add(1);
            return None;
        };
        self.stats.hits = self.stats.hits.saturating_add(1);
        let state = Arc::clone(&entry.state);
        self.touch(key);
        Some(state)
    }

    fn insert(&mut self, key: FileStateCacheKey, state: Arc<FileState>) {
        let estimated_bytes = state.estimated_retained_bytes();
        if estimated_bytes > self.max_bytes {
            self.stats.rejected_admissions = self.stats.rejected_admissions.saturating_add(1);
            return;
        }
        if let Some(replaced) = self.entries.remove(&key) {
            self.remove_accounting(&replaced);
        }
        let stamp = self.next_stamp();
        self.entries.insert(
            key.clone(),
            FileStateCacheEntry {
                state,
                estimated_bytes,
                stamp,
                segment: FileStateCacheSegment::Probation,
            },
        );
        self.retained_bytes = self.retained_bytes.saturating_add(estimated_bytes);
        self.probation_bytes = self.probation_bytes.saturating_add(estimated_bytes);
        self.probation_order.push_back((key, stamp));
        self.stats.admissions = self.stats.admissions.saturating_add(1);
        self.enforce_bounds();
        self.maybe_compact();
    }

    #[cfg(test)]
    fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    #[cfg(test)]
    fn contains(&self, key: &FileStateCacheKey) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    fn stats(&self) -> FileStateCacheStats {
        self.stats
    }

    fn touch(&mut self, key: &FileStateCacheKey) {
        let stamp = self.next_stamp();
        let Some(entry) = self.entries.get_mut(key) else {
            return;
        };
        if entry.segment == FileStateCacheSegment::Probation {
            entry.segment = FileStateCacheSegment::Protected;
            self.probation_bytes = self.probation_bytes.saturating_sub(entry.estimated_bytes);
            self.protected_bytes = self.protected_bytes.saturating_add(entry.estimated_bytes);
            self.stats.promotions = self.stats.promotions.saturating_add(1);
        }
        entry.stamp = stamp;
        match entry.segment {
            FileStateCacheSegment::Probation => {
                self.probation_order.push_back((key.clone(), stamp))
            }
            FileStateCacheSegment::Protected => {
                self.protected_order.push_back((key.clone(), stamp))
            }
        }
        self.enforce_bounds();
        self.maybe_compact();
    }

    fn next_stamp(&mut self) -> u64 {
        let stamp = self.next_stamp;
        self.next_stamp = self.next_stamp.wrapping_add(1);
        stamp
    }

    fn enforce_bounds(&mut self) {
        while self.protected_bytes > self.protected_max_bytes {
            if !self.demote_protected_one() {
                break;
            }
        }
        while self.retained_bytes > self.max_bytes {
            if self.evict_one(FileStateCacheSegment::Probation) {
                continue;
            }
            if !self.evict_one(FileStateCacheSegment::Protected) {
                break;
            }
        }
    }

    fn demote_protected_one(&mut self) -> bool {
        while let Some((key, stamp)) = self.protected_order.pop_front() {
            let next_stamp = self.next_stamp();
            let Some(entry) = self.entries.get_mut(&key) else {
                continue;
            };
            if entry.segment != FileStateCacheSegment::Protected || entry.stamp != stamp {
                continue;
            }
            entry.segment = FileStateCacheSegment::Probation;
            entry.stamp = next_stamp;
            self.protected_bytes = self.protected_bytes.saturating_sub(entry.estimated_bytes);
            self.probation_bytes = self.probation_bytes.saturating_add(entry.estimated_bytes);
            self.probation_order.push_back((key, entry.stamp));
            return true;
        }
        false
    }

    fn evict_one(&mut self, segment: FileStateCacheSegment) -> bool {
        let order = match segment {
            FileStateCacheSegment::Probation => &mut self.probation_order,
            FileStateCacheSegment::Protected => &mut self.protected_order,
        };
        while let Some((key, stamp)) = order.pop_front() {
            let is_live = self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.segment == segment && entry.stamp == stamp);
            if !is_live {
                continue;
            }
            let entry = self
                .entries
                .remove(&key)
                .expect("live file-state cache entry must remain present");
            self.remove_accounting(&entry);
            self.stats.evictions = self.stats.evictions.saturating_add(1);
            return true;
        }
        false
    }

    fn remove_accounting(&mut self, entry: &FileStateCacheEntry) {
        self.retained_bytes = self.retained_bytes.saturating_sub(entry.estimated_bytes);
        match entry.segment {
            FileStateCacheSegment::Probation => {
                self.probation_bytes = self.probation_bytes.saturating_sub(entry.estimated_bytes);
            }
            FileStateCacheSegment::Protected => {
                self.protected_bytes = self.protected_bytes.saturating_sub(entry.estimated_bytes);
            }
        }
    }

    fn maybe_compact(&mut self) {
        let threshold = self
            .entries
            .len()
            .saturating_mul(CACHE_ORDER_COMPACT_FACTOR);
        if self.probation_order.len() > threshold.max(CACHE_ORDER_COMPACT_FACTOR) {
            self.probation_order.retain(|(key, stamp)| {
                self.entries.get(key).is_some_and(|entry| {
                    entry.segment == FileStateCacheSegment::Probation && entry.stamp == *stamp
                })
            });
        }
        if self.protected_order.len() > threshold.max(CACHE_ORDER_COMPACT_FACTOR) {
            self.protected_order.retain(|(key, stamp)| {
                self.entries.get(key).is_some_and(|entry| {
                    entry.segment == FileStateCacheSegment::Protected && entry.stamp == *stamp
                })
            });
        }
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.entries.clear();
        self.probation_order.clear();
        self.protected_order.clear();
        self.retained_bytes = 0;
        self.probation_bytes = 0;
        self.protected_bytes = 0;
    }
}

#[derive(Debug)]
struct QueryFileStateCache {
    entries: HashMap<FileStateCacheKey, Arc<FileState>>,
    retained_bytes: usize,
    max_bytes: usize,
}

impl QueryFileStateCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            entries: HashMap::default(),
            retained_bytes: 0,
            max_bytes,
        }
    }

    fn get(&self, key: &FileStateCacheKey) -> Option<Arc<FileState>> {
        self.entries.get(key).cloned()
    }

    fn retain(&mut self, key: FileStateCacheKey, state: Arc<FileState>) -> bool {
        if let Some(existing) = self.entries.get_mut(&key) {
            *existing = state;
            return true;
        }
        let estimated_bytes = state.estimated_retained_bytes();
        if estimated_bytes > self.max_bytes
            || self.retained_bytes.saturating_add(estimated_bytes) > self.max_bytes
        {
            return false;
        }
        self.entries.insert(key, state);
        self.retained_bytes = self.retained_bytes.saturating_add(estimated_bytes);
        true
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.entries.clear();
        self.retained_bytes = 0;
    }
}

type FileStateCache = SegmentedFileStateCache;
type SummaryFileProjectionCache = BoundedFileCache<SummaryFileProjection>;
type PreparedSyntaxRequestCache =
    HashMap<PreparedSyntaxCacheKey, Arc<OnceLock<Option<Arc<PreparedSyntaxTree>>>>>;
// Snapshot file states belong to one immutable analyzer generation. Unlike the
// transient cache, this index is seeded once when the generation is built and
// never receives an insert or eviction. Keep its bounded seed as a plain map so
// read-only analyzer calls do not pay for recency metadata that can never affect
// the index.
type SourceSnapshotFileStateIndex = HashMap<FileStateCacheKey, Arc<FileState>>;
type TopLevelClassUnitsByPackageCell = Arc<OnceLock<Arc<HashMap<String, Vec<CodeUnit>>>>>;

#[derive(Debug)]
struct QueryReadCache {
    contexts: Vec<Arc<crate::analyzer::AnalyzerQueryContext>>,
    /// Each request memo is independently synchronized. The outer cache lock
    /// only protects this handle set and the active-context list; callers clone
    /// one handle under that lock and then operate on the selected cache after
    /// dropping it, so an insertion in one memo cannot block readers of another.
    analyzed_live_files: Arc<RwLock<Option<Vec<ProjectFile>>>>,
    live_sources: Arc<RwLock<HashMap<ProjectFile, Option<ResolvedLiveSource>>>>,
    current_sources: Arc<RwLock<HashMap<ProjectFile, Option<String>>>>,
    prepared_sources: Arc<RwLock<HashMap<ProjectFile, Option<ResolvedPreparedSource>>>>,
    file_states: Arc<RwLock<QueryFileStateCache>>,
    prepared_syntax: Arc<RwLock<PreparedSyntaxRequestCache>>,
    /// Persisted top-level class declarations bucketed by package, hydrated at
    /// most once per request. `class_declarations_in_package` answers a
    /// *package-scoped* question with a *whole-workspace* declaration scan, so
    /// asking it once per (file, using-directive) pair — which is exactly what
    /// C# import-graph candidate discovery does — re-hydrates every declaration
    /// in the workspace thousands of times per query (#1194).
    ///
    /// `Arc<OnceLock<..>>`, not a plain `Option`: candidate discovery can hydrate this from many
    /// threads at once (parallel import-graph scans), and a check-then-compute-then-store `Option`
    /// lets every thread that misses the check before the first writer finishes redo the same
    /// whole-workspace scan. Cloning the `Arc` out from under `query_read_cache`'s coarse lock (see
    /// `top_level_class_units_by_package_cell`) and calling `get_or_init` on that handle keeps the
    /// expensive hydration off the coarse lock while still guaranteeing only one thread runs it.
    top_level_class_units_by_package: TopLevelClassUnitsByPackageCell,
    /// The workspace file listing bucketed by basename, walked at most once per
    /// request (#1334). Same `Arc<OnceLock<..>>` single-flight shape and the
    /// same reason as the bucket map above: `WorkspaceFileResolver`s are
    /// constructed per call site and inside per-symbol `rayon` closures, so a
    /// non-single-flight cache would let concurrent misses each redo the
    /// ignore-aware tree walk this exists to eliminate.
    workspace_file_index: crate::analyzer::WorkspaceFileIndexCell,
    /// Owner units keyed by owner fq name, resolved at most once per name per
    /// request (#1230 item 6).
    ///
    /// `parent_of` answers a *single-name* question with a store
    /// `definition_candidates` query, and the callers that dominate a Rust scan
    /// ask it once per declaration: every top-level item in a module asks for
    /// the same owner name, so a file of N items paid N identical queries (8/60
    /// gdb samples, all under `export_index_of_declarations`). Memoizing by
    /// owner name collapses those to one per distinct owner.
    ///
    /// A plain `HashMap` under its own inner lock, not an `Arc<OnceLock<..>>`
    /// per key: each entry is one bounded lookup rather than a whole-workspace
    /// hydration, so a racing duplicate query is cheap and single-flighting per
    /// key would cost more than it saves.
    parent_units: Arc<RwLock<HashMap<String, Option<CodeUnit>>>>,
    /// Definition candidates keyed by fq name, resolved at most once per name
    /// per request and per concurrent same-name burst.
    ///
    /// `definitions` is the single hottest store read in candidate discovery:
    /// the shared import-graph walk asks it once per import statement in the
    /// workspace, and a workspace's import statements name far fewer distinct
    /// targets than there are import statements (#1748). Candidate scanning is
    /// parallel, so a check-then-insert map allowed every worker in a same-name
    /// burst to repeat the candidate assembly and path-symbol read. Use the
    /// pool-independent per-key cells here as well as for the persisted rows
    /// below: distinct names remain parallel, while one fq name has one complete
    /// answer and one publication point.
    definition_units: Arc<KeyedPoolSafeMemo<String, Vec<CodeUnit>>>,
    /// The workspace's path-synthetic module units, walked at most once per
    /// request (#1774). See [`TreeSitterAnalyzer::workspace_module_walk`].
    workspace_module_walk: Arc<RwLock<Option<Arc<WorkspaceModuleWalk>>>>,
    /// Per-file [`ClassRangeIndex`], built at most once per file per request
    /// (#2679). The definition resolvers ask the enclosing-class question once
    /// per reference site, so a bulk scan rebuilt this whole-file index — a
    /// declaration-set clone plus one range lookup per class — once per
    /// occurrence, and in Scala inside per-import and per-preceding-binding
    /// loops on top of that. A plain `HashMap` under one lock, following
    /// `parent_units`: each entry is a bounded per-file build, so a racing
    /// duplicate is cheap and per-key single-flighting would cost more than it
    /// saves.
    class_ranges: Arc<RwLock<HashMap<ProjectFile, Arc<ClassRangeIndex>>>>,
    /// The definition-lookup memos every `AnalyzerDefinitionLookup` built
    /// during this request answers from (#2883). See
    /// [`crate::analyzer::DefinitionLookupMemo`].
    definition_lookup: Arc<crate::analyzer::DefinitionLookupMemo>,
}

/// One request's materialization of the workspace's path-synthetic module
/// units, plus the live snapshot it was read from. See
/// [`TreeSitterAnalyzer::workspace_module_walk`].
struct WorkspaceModuleWalk {
    snapshot: Arc<LiveSnapshot>,
    entries: Vec<(ProjectFile, Oid, CodeUnit)>,
    /// Live paths visited by the walk, so a memo hit reports the same
    /// `inspected` budget figure the walk itself would have reported.
    inspected: usize,
}

// `LiveSnapshot` is not `Debug`, and the entry list is workspace-sized, so
// report the shape rather than the contents.
impl std::fmt::Debug for WorkspaceModuleWalk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkspaceModuleWalk")
            .field("entries", &self.entries.len())
            .field("inspected", &self.inspected)
            .finish()
    }
}

impl Default for QueryReadCache {
    fn default() -> Self {
        Self::new(MIN_FILE_STATE_CACHE_BYTES / QUERY_FILE_STATE_CACHE_BUDGET_DIVISOR)
    }
}

#[derive(Debug, Clone, Copy)]
enum DefinitionRangeStart {
    Persisted(Option<usize>),
    FileState,
}

#[derive(Debug, Clone)]
struct DefinitionSortCandidate {
    unit: CodeUnit,
    range_start: DefinitionRangeStart,
}

/// The recorder a read funnel pushes its [`ReadKey`]s into.
///
/// It holds the request boundaries that were open when the funnel was crossed,
/// so one push reaches every ledger around it. Constructing one is the only
/// work a ledger-free run would have to do, which is why
/// [`TreeSitterAnalyzer::record_reads`] refuses to build it at all in that
/// case.
pub(crate) struct ReadKeySink<'a> {
    contexts: &'a [Arc<crate::analyzer::AnalyzerQueryContext>],
}

impl ReadKeySink<'_> {
    pub(crate) fn push(&mut self, key: crate::analyzer::read_ledger::ReadKey) {
        for context in self.contexts {
            if let Some(ledger) = context.read_ledger() {
                ledger.record(key.clone());
            }
        }
    }
}

impl QueryReadCache {
    fn new(file_state_budget_bytes: usize) -> Self {
        Self {
            contexts: Vec::new(),
            analyzed_live_files: Arc::new(RwLock::new(None)),
            live_sources: Arc::new(RwLock::new(HashMap::default())),
            current_sources: Arc::new(RwLock::new(HashMap::default())),
            prepared_sources: Arc::new(RwLock::new(HashMap::default())),
            file_states: Arc::new(RwLock::new(QueryFileStateCache::new(
                file_state_budget_bytes,
            ))),
            prepared_syntax: Arc::new(RwLock::new(HashMap::default())),
            top_level_class_units_by_package: Arc::new(OnceLock::new()),
            workspace_file_index: Arc::new(OnceLock::new()),
            parent_units: Arc::new(RwLock::new(HashMap::default())),
            definition_units: Arc::new(KeyedPoolSafeMemo::new()),
            workspace_module_walk: Arc::new(RwLock::new(None)),
            class_ranges: Arc::new(RwLock::new(HashMap::default())),
            definition_lookup: Arc::default(),
        }
    }

    /// Register `context` as an open request boundary. Returns whether it was
    /// newly registered, which is what keeps the analyzer's attached-ledger
    /// count in step with this list under the re-entrant `begin_query` calls
    /// nested scopes make.
    fn begin(&mut self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) -> bool {
        if self.contexts.is_empty() {
            self.reset_request_caches();
            self.top_level_class_units_by_package = Arc::new(OnceLock::new());
            self.workspace_file_index = Arc::new(OnceLock::new());
        }
        if self
            .contexts
            .iter()
            .any(|active| Arc::ptr_eq(active, context))
        {
            return false;
        }
        self.contexts.push(Arc::clone(context));
        true
    }

    /// Retire `context`. Returns whether it was registered here.
    fn end(&mut self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) -> bool {
        let was_active = !self.contexts.is_empty();
        let before = self.contexts.len();
        self.contexts.retain(|active| !Arc::ptr_eq(active, context));
        let removed = self.contexts.len() < before;
        if was_active && self.contexts.is_empty() {
            self.reset_request_caches();
            self.top_level_class_units_by_package = Arc::new(OnceLock::new());
            self.workspace_file_index = Arc::new(OnceLock::new());
        }
        removed
    }

    /// Replace every request memo at an outer-scope transition. Callers that
    /// already cloned an old handle may finish against that detached map, but
    /// no subsequent operation can publish into the new request's handles.
    fn reset_request_caches(&mut self) {
        self.analyzed_live_files = Arc::new(RwLock::new(None));
        self.live_sources = Arc::new(RwLock::new(HashMap::default()));
        self.current_sources = Arc::new(RwLock::new(HashMap::default()));
        self.prepared_sources = Arc::new(RwLock::new(HashMap::default()));
        let max_bytes = self
            .file_states
            .read()
            .expect("query file-state cache read lock poisoned")
            .max_bytes;
        self.file_states = Arc::new(RwLock::new(QueryFileStateCache::new(max_bytes)));
        self.prepared_syntax = Arc::new(RwLock::new(HashMap::default()));
        self.parent_units = Arc::new(RwLock::new(HashMap::default()));
        self.definition_units = Arc::new(KeyedPoolSafeMemo::new());
        self.workspace_module_walk = Arc::new(RwLock::new(None));
        self.class_ranges = Arc::new(RwLock::new(HashMap::default()));
        self.definition_lookup = Arc::default();
    }

    fn is_active(&self) -> bool {
        !self.contexts.is_empty()
    }

    /// The deadline governing the innermost active request boundary.
    ///
    /// Scopes nest (a scan opens one, a nested resolver may open another), and
    /// an inner scope can only narrow a deadline, never widen one, so the
    /// innermost token that carries one governs.
    fn active_cancellation(&self) -> Option<CancellationToken> {
        self.contexts
            .iter()
            .rev()
            .find_map(|context| context.cancellation().cloned())
    }

    fn active_semantic_model_overlay(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>> {
        self.contexts
            .iter()
            .rev()
            .find_map(|context| context.semantic_model_overlay_override_for_current_thread())
    }

    fn active_semantic_model_snapshot(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>> {
        self.contexts.iter().rev().find_map(|context| {
            context.active_semantic_model_snapshot_override_for_current_thread()
        })
    }

    #[cfg(test)]
    fn analyzed_live_files(&self) -> Option<Vec<ProjectFile>> {
        if !self.is_active() {
            return None;
        }
        self.analyzed_live_files
            .read()
            .expect("query analyzed-live cache read lock poisoned")
            .clone()
    }

    #[cfg(test)]
    fn retain_analyzed_live_files(&self, files: Vec<ProjectFile>) {
        if self.is_active() {
            *self
                .analyzed_live_files
                .write()
                .expect("query analyzed-live cache write lock poisoned") = Some(files);
        }
    }

    /// The single-flight cell backing `persisted_top_level_classes_in_package`. Callers clone this
    /// `Arc` handle out from under the coarse `query_read_cache` lock and call `get_or_init` on
    /// their own copy, so the (potentially expensive) hydration never runs while that lock is held.
    fn top_level_class_units_by_package_cell(&self) -> Option<TopLevelClassUnitsByPackageCell> {
        self.is_active()
            .then(|| Arc::clone(&self.top_level_class_units_by_package))
    }

    /// The single-flight cell backing `IAnalyzer::workspace_file_index_cell`.
    /// Cloned out from under the coarse lock so the tree walk never runs while
    /// it is held.
    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.is_active()
            .then(|| Arc::clone(&self.workspace_file_index))
    }

    #[cfg(test)]
    fn prepared_syntax_cell_with_capacity(
        &self,
        key: PreparedSyntaxCacheKey,
        capacity: usize,
    ) -> Option<Arc<OnceLock<Option<Arc<PreparedSyntaxTree>>>>> {
        if !self.is_active() {
            return None;
        }
        let mut prepared_syntax = self
            .prepared_syntax
            .write()
            .expect("query prepared-syntax cache write lock poisoned");
        if let Some(cell) = prepared_syntax.get(&key) {
            return Some(Arc::clone(cell));
        }
        if prepared_syntax.len() >= capacity {
            return None;
        }
        let cell = Arc::new(OnceLock::new());
        prepared_syntax.insert(key, Arc::clone(&cell));
        Some(cell)
    }
}

impl<T> BoundedFileCache<T> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::default(),
            order: VecDeque::new(),
            next_stamp: 0,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&mut self, key: &FileStateCacheKey) -> Option<Arc<T>> {
        let state = Arc::clone(&self.entries.get(key)?.0);
        self.touch(key);
        Some(state)
    }

    fn insert(&mut self, key: FileStateCacheKey, value: Arc<T>) {
        if self.capacity == 0 {
            return;
        }
        let stamp = self.next_stamp;
        self.next_stamp += 1;
        let is_new_key = self.entries.insert(key.clone(), (value, stamp)).is_none();
        self.order.push_back((key, stamp));
        if is_new_key {
            while self.entries.len() > self.capacity {
                self.evict_one();
            }
        }
        self.maybe_compact();
    }

    /// O(1) touch: record a fresh, newest-timestamped entry in `order`
    /// without scanning to remove the key's previous occurrence. Stale
    /// duplicates are discarded lazily, either by `evict_one` (which skips
    /// them) or `maybe_compact` (which filters them out in bulk).
    fn touch(&mut self, key: &FileStateCacheKey) {
        let stamp = self.next_stamp;
        self.next_stamp += 1;
        if let Some(entry) = self.entries.get_mut(key) {
            entry.1 = stamp;
        }
        self.order.push_back((key.clone(), stamp));
        self.maybe_compact();
    }

    /// Pop from the front of `order` until we find (and remove) a genuine
    /// LRU victim: an entry whose stamp still matches what `entries` holds.
    /// Earlier pops that don't match are stale duplicates left behind by
    /// `touch` and are simply dropped.
    fn evict_one(&mut self) {
        while let Some((key, stamp)) = self.order.pop_front() {
            let is_live = matches!(self.entries.get(&key), Some((_, current)) if *current == stamp);
            if is_live {
                self.entries.remove(&key);
                return;
            }
        }
    }

    /// Bulk-drop stale `order` duplicates once they outnumber `entries` by
    /// more than `CACHE_ORDER_COMPACT_FACTOR`, so long-lived caches whose
    /// keys are touched far more often than evicted don't grow `order`
    /// without bound. Filtering keeps at most one (the live) entry per key.
    fn maybe_compact(&mut self) {
        let threshold = self.capacity.saturating_mul(CACHE_ORDER_COMPACT_FACTOR);
        if self.order.len() <= threshold.max(CACHE_ORDER_COMPACT_FACTOR) {
            return;
        }
        let entries = &self.entries;
        self.order.retain(
            |(key, stamp)| matches!(entries.get(key), Some((_, current)) if current == stamp),
        );
    }
}

pub use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;

use crate::analyzer::semantic::ids::StableDigest;

/// Isolated cost of the extra readings
/// [`LanguageAdapter::parse_file_with_projections`] produces beyond the file's
/// own, summed over the parse fan-out.
///
/// The work sits per file inside the rayon workers, so a plain
/// `profiling::scope` there would emit one interleaved BEGIN/END pair per file
/// from every worker at once. These counters accumulate lock-free instead and
/// are reported once per parse batch, the way `RustScanPhaseTimings` reports
/// its phases. They are keyed by language because `WorkspaceAnalyzer::build`
/// runs one build thread per language concurrently, so a single global would
/// mix the languages together. The adapter that produces an extra reading
/// records its own span, because only the adapter knows which part of its work
/// the extra reading is.
const ADDITIONAL_PROJECTION_LANGUAGES: usize = Language::Kotlin as usize + 1;
static ADDITIONAL_PROJECTION_NANOS: [AtomicU64; ADDITIONAL_PROJECTION_LANGUAGES] =
    [const { AtomicU64::new(0) }; ADDITIONAL_PROJECTION_LANGUAGES];
static ADDITIONAL_PROJECTION_FILES: [AtomicUsize; ADDITIONAL_PROJECTION_LANGUAGES] =
    [const { AtomicUsize::new(0) }; ADDITIONAL_PROJECTION_LANGUAGES];
static ADDITIONAL_PROJECTION_PUBLISHED: [AtomicUsize; ADDITIONAL_PROJECTION_LANGUAGES] =
    [const { AtomicUsize::new(0) }; ADDITIONAL_PROJECTION_LANGUAGES];

pub(crate) fn record_additional_projection(
    language: Language,
    started: Option<Instant>,
    published: usize,
) {
    let Some(started) = started else {
        return;
    };
    let index = language as usize;
    let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    ADDITIONAL_PROJECTION_NANOS[index].fetch_add(nanos, Ordering::Relaxed);
    ADDITIONAL_PROJECTION_FILES[index].fetch_add(1, Ordering::Relaxed);
    ADDITIONAL_PROJECTION_PUBLISHED[index].fetch_add(published, Ordering::Relaxed);
}

/// Report this language's running `additional_projections` total. Cumulative
/// over the process, so the value after the last batch is the build's total.
fn note_additional_projection_totals(language: Language) {
    profiling::note_with(|| {
        let index = language as usize;
        format!(
            "additional_projections[{language:?}] cumulative files={} published={} total_ms={:.1}",
            ADDITIONAL_PROJECTION_FILES[index].load(Ordering::Relaxed),
            ADDITIONAL_PROJECTION_PUBLISHED[index].load(Ordering::Relaxed),
            ADDITIONAL_PROJECTION_NANOS[index].load(Ordering::Relaxed) as f64 / 1_000_000.0,
        )
    });
}

pub struct TreeSitterAnalyzer<A> {
    project: Arc<dyn Project>,
    adapter: Arc<A>,
    config: AnalyzerConfig,
    state: Arc<AnalyzerRuntimeState>,
    /// Structural-search facts cache (issue #328). Shared across clones and
    /// incremental `update()` generations — entries are validated against a
    /// hash of the current in-memory source, so surviving stale entries are
    /// self-healing rather than wrong.
    structural_cache: Arc<crate::analyzer::structural::provider::StructuralFactsCache>,
    /// Complete immutable postings for this exact analyzer generation.
    /// Ordinary clones share the owner; updates and overlays replace it.
    structural_index_cache: Arc<crate::analyzer::structural::provider::StructuralFactSnapshotCache>,
    /// Complete immutable typed relations for this exact analyzer snapshot.
    /// Ordinary clones share the owner; updates carry the content-keyed halves
    /// forward and overlays replace it.
    snapshot_caches: Arc<crate::analyzer::AnalyzerSnapshotCaches>,
    /// The language epoch and configuration half of this analyzer's #2449
    /// content identity, derived once. See `build_content_identity_base`.
    content_identity_base: StableDigest,
    semantic_cache: crate::analyzer::semantic::service::CompleteSemanticArtifactCache,
    /// Content digests already derived for a blob, so a repeat semantic
    /// materialization of an unchanged file does not re-hash it. Keyed by the
    /// blob identity of the exact source the digest was taken from, so an
    /// entry is a pure function of content and can never go stale.
    semantic_source_digests: crate::analyzer::semantic::service::SourceContentIdentityMemo,
    /// Blob oids already derived for a file's exact source bytes, so a query
    /// path that keys facts by content does not re-hash an unchanged file.
    /// See [`Self::blob_oid_of`].
    blob_oids: Arc<SourceBlobOidMemo>,
    store_context: AnalyzerStoreContext,
    /// Immutable path-to-blob identities for the source generation that built
    /// this analyzer. Queries may refresh `store_context.live_paths` as they
    /// observe later working-tree bytes, so that mutable projection cannot
    /// answer whether new source still matches this generation.
    indexed_live_snapshot: Arc<LiveSnapshot>,
    /// Opaque identities of the SQLite workspace projections published for
    /// this immutable analyzer generation. Comparing these scalar rows keeps
    /// the hot relational path on liveness views while allowing a retained
    /// analyzer to detect that those mutable views now describe a successor.
    relational_workspace_snapshots: Arc<arc_swap::ArcSwap<WorkspaceSnapshots>>,
    /// Per-request persisted read model. Live OIDs are validated once and
    /// hydrated states remain available for the graph traversal.
    query_read_cache: Arc<RwLock<QueryReadCache>>,
    /// Immutable request snapshot of validated live OIDs. The broad C++ inverse
    /// batch publishes this after its one full liveness pass so hot source
    /// lookups avoid both request-cache locks; ordinary requests fall back to
    /// `query_read_cache`'s lazy map.
    live_source_snapshot: Arc<ArcSwapOption<HashMap<ProjectFile, ResolvedLiveSource>>>,
    /// Immutable request snapshot of hydrated file states. The broad C++
    /// inverse batch publishes this after one bulk hydration pass so hot
    /// fetch/range lookups avoid both request-cache locks; ordinary requests
    /// fall back to `query_read_cache`'s lazy map.
    query_file_state_snapshot: Arc<ArcSwapOption<HashMap<FileStateCacheKey, Arc<FileState>>>>,
    /// Cross-request prepared trees behind the per-request layer above. The
    /// #1416 warm scan was dominated by re-parsing candidates a previous
    /// request had already parsed; content-addressed keys let those survive.
    prepared_syntax_store: Arc<Mutex<PreparedSyntaxStore>>,
    /// Cross-request per-file import infos. The #1451 warm scan resolved
    /// lexical imports by asking the store for the same file's imports over and
    /// over: 70k hydrations across 1100 distinct files in one request.
    import_info_store: Arc<Mutex<ImportInfoStore>>,
    /// Cross-request type-alias projections. A type-alias check is common in
    /// C++ resolution, but it needs only this small persisted fact.
    type_alias_store: Arc<Mutex<TypeAliasStore>>,
    /// Cross-request indexes for smallest-enclosing declaration lookup in
    /// generated files with large declaration sets.
    enclosing_code_unit_store: Arc<Mutex<EnclosingCodeUnitStore>>,
    #[cfg(test)]
    live_oid_validation_counts: Arc<Mutex<HashMap<ProjectFile, usize>>>,
    /// Crossings of each information tier's storage funnel, per file, for perf
    /// pins (#2414). Always compiled: a tier crossing is a parse or a store
    /// read, so one map update per crossing is free relative to the work it
    /// measures — and the counter has to survive in non-test builds for
    /// integration tests to pin it (#1175, where a detached analyzer clone
    /// re-parsed one 4.8 MB header tens of thousands of times inside a single
    /// scan).
    tier_access_counts: Arc<Mutex<HashMap<(InformationTier, ProjectFile), usize>>>,
    /// The same crossings summed over files. The usage-graph tier has no file
    /// key at all, and the import tier's pre-#2414 counter was already a plain
    /// total: what must stay bounded there is the number of *store reads* the
    /// per-reference calls turn into (#1451), not any one file's share.
    tier_access_totals: Arc<[AtomicUsize; InformationTier::COUNT]>,
    /// How many of the open query contexts carry a read ledger.
    ///
    /// Every read funnel consults this before it builds a [`ReadKey`], so a
    /// run with no ledger attached -- which is every run that is not an
    /// incremental policy evaluation -- pays one relaxed load and allocates
    /// nothing. It tracks `query_read_cache.contexts`, which a clone starts
    /// empty, so it is minted fresh per clone rather than shared.
    attached_read_ledgers: Arc<AtomicUsize>,
    transient_file_states: Arc<Mutex<FileStateCache>>,
    source_snapshot_file_states: Arc<SourceSnapshotFileStateIndex>,
    summary_file_projections: Arc<Mutex<SummaryFileProjectionCache>>,
    full_hydration_count: Arc<AtomicUsize>,
    bulk_hydration_count: Arc<AtomicUsize>,
    /// File states [`TreeSitterAnalyzer::authoritative_file_states_for_queries`]
    /// materializes, summed over its calls.
    ///
    /// Every one of them used to be a deep `FileState` clone -- source text and
    /// all -- and the walk that produced them visited every cached state rather
    /// than the snapshot's overlay set, so one relational batch cost the size of
    /// the process's file-state cache (#2883). A request with no overlay open
    /// must count zero here however many states are cached.
    authoritative_file_state_reads: Arc<AtomicUsize>,
    sql_definitions_query_count: Arc<AtomicUsize>,
    definition_candidates_query_count: Arc<AtomicUsize>,
    definition_prefetch_batch_count: Arc<AtomicUsize>,
    relational_definition_batch_call_count: Arc<AtomicUsize>,
    definition_candidate_row_read_count: Arc<AtomicUsize>,
    /// Candidate spellings dropped by `definition_candidate_short_names`
    /// because the persisted `short_name` vocabulary for this adapter's
    /// language cannot contain a separator they carry. Each one is a store seek
    /// that did not happen (issue #1748).
    structural_miss_spelling_count: Arc<AtomicUsize>,
    enclosing_code_unit_query_count: Arc<AtomicUsize>,
    full_declaration_scan_count: Arc<AtomicUsize>,
    /// Persisted declarations that a `search_symbols` request hydrated into
    /// `CodeUnit`s. The scan count alone cannot see the #1199 regression shape:
    /// one shared scan still hydrated the entire workspace projection before
    /// any pattern was applied, so this counter pins the *per-scan* work to the
    /// size of the answer rather than the size of the workspace.
    search_candidate_hydration_count: Arc<AtomicUsize>,
    /// Materializations of the whole analyzed-file listing. Rust module
    /// resolution answered a *single-module* question by relisting every
    /// analyzed file and recomputing its package name, once per call; pinned by
    /// #1230 item 3.
    analyzed_file_listing_count: Arc<AtomicUsize>,
    /// Whole-workspace declaration scans issued to answer a *package-scoped*
    /// class lookup (`class_declarations_in_package`). Pinned by #1194.
    package_declaration_scan_count: Arc<AtomicUsize>,
    workspace_path_scan_count: Arc<AtomicUsize>,
    _state: PhantomData<A>,
}

impl<A> Clone for TreeSitterAnalyzer<A> {
    fn clone(&self) -> Self {
        Self {
            project: Arc::clone(&self.project),
            adapter: Arc::clone(&self.adapter),
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            structural_cache: Arc::clone(&self.structural_cache),
            structural_index_cache: Arc::clone(&self.structural_index_cache),
            snapshot_caches: Arc::clone(&self.snapshot_caches),
            content_identity_base: self.content_identity_base,
            semantic_cache: self.semantic_cache.clone(),
            semantic_source_digests: self.semantic_source_digests.clone(),
            blob_oids: Arc::clone(&self.blob_oids),
            store_context: self.store_context.clone(),
            indexed_live_snapshot: Arc::clone(&self.indexed_live_snapshot),
            relational_workspace_snapshots: Arc::clone(&self.relational_workspace_snapshots),
            query_read_cache: Arc::new(RwLock::new(QueryReadCache::default())),
            live_source_snapshot: Arc::new(ArcSwapOption::empty()),
            query_file_state_snapshot: Arc::new(ArcSwapOption::empty()),
            prepared_syntax_store: Arc::clone(&self.prepared_syntax_store),
            import_info_store: Arc::clone(&self.import_info_store),
            type_alias_store: Arc::clone(&self.type_alias_store),
            enclosing_code_unit_store: Arc::clone(&self.enclosing_code_unit_store),
            #[cfg(test)]
            live_oid_validation_counts: Arc::clone(&self.live_oid_validation_counts),
            tier_access_counts: Arc::clone(&self.tier_access_counts),
            tier_access_totals: Arc::clone(&self.tier_access_totals),
            attached_read_ledgers: Arc::new(AtomicUsize::new(0)),
            transient_file_states: Arc::clone(&self.transient_file_states),
            source_snapshot_file_states: Arc::clone(&self.source_snapshot_file_states),
            summary_file_projections: Arc::clone(&self.summary_file_projections),
            full_hydration_count: Arc::clone(&self.full_hydration_count),
            authoritative_file_state_reads: Arc::clone(&self.authoritative_file_state_reads),
            bulk_hydration_count: Arc::clone(&self.bulk_hydration_count),
            sql_definitions_query_count: Arc::clone(&self.sql_definitions_query_count),
            definition_candidates_query_count: Arc::clone(&self.definition_candidates_query_count),
            definition_prefetch_batch_count: Arc::clone(&self.definition_prefetch_batch_count),
            relational_definition_batch_call_count: Arc::clone(
                &self.relational_definition_batch_call_count,
            ),
            definition_candidate_row_read_count: Arc::clone(
                &self.definition_candidate_row_read_count,
            ),
            structural_miss_spelling_count: Arc::clone(&self.structural_miss_spelling_count),
            enclosing_code_unit_query_count: Arc::clone(&self.enclosing_code_unit_query_count),
            full_declaration_scan_count: Arc::clone(&self.full_declaration_scan_count),
            search_candidate_hydration_count: Arc::clone(&self.search_candidate_hydration_count),
            package_declaration_scan_count: Arc::clone(&self.package_declaration_scan_count),
            analyzed_file_listing_count: Arc::clone(&self.analyzed_file_listing_count),
            workspace_path_scan_count: Arc::clone(&self.workspace_path_scan_count),
            _state: PhantomData,
        }
    }
}

impl<A> TreeSitterAnalyzer<A> {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut snapshot = self.clone();
        snapshot.project = project;
        // A request overlay may publish a transient source OID while it parses
        // an unsaved revision. Keep that projection local to the request just
        // as update/update_all keep their next-generation projections local;
        // sharing it would make a later sibling or cleared overlay resolve the
        // old transient OID instead of its own project source.
        snapshot.store_context.live_paths = Arc::new(
            self.store_context
                .live_paths
                .fork_from_snapshot(Arc::clone(&self.indexed_live_snapshot)),
        );
        snapshot.structural_index_cache = Arc::new(
            crate::analyzer::structural::provider::StructuralFactSnapshotCache::new(
                self.config.memo_cache_budget_bytes(),
            ),
        );
        snapshot.snapshot_caches = Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
            self.config.memo_cache_budget_bytes() / 8,
        ));
        snapshot
    }
}

impl<A> TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn child_order_key(ranges: &HashMap<CodeUnit, Vec<Range>>, code_unit: &CodeUnit) -> usize {
        ranges
            .get(code_unit)
            .into_iter()
            .flatten()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX)
    }

    fn canonicalize_children(
        descendants: &mut Vec<CodeUnit>,
        ranges: &HashMap<CodeUnit, Vec<Range>>,
    ) {
        if descendants.len() < 2 {
            return;
        }

        let mut seen = set_with_capacity(descendants.len());
        let mut keyed = Vec::with_capacity(descendants.len());
        for child in descendants.drain(..) {
            if seen.insert(child.clone()) {
                keyed.push((Self::child_order_key(ranges, &child), child));
            }
        }

        keyed.sort_by(|(left_start, left), (right_start, right)| {
            left_start.cmp(right_start).then_with(|| left.cmp(right))
        });
        descendants.extend(keyed.into_iter().map(|(_, child)| child));
    }

    pub fn new(project: Arc<dyn Project>, adapter: A) -> Self {
        Self::new_with_config(project, adapter, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, adapter: A, config: AnalyzerConfig) -> Self {
        Self::new_internal(project, adapter, config, None, None)
            .expect("failed to initialize in-memory analyzer store")
    }

    pub(crate) fn new_with_config_storage_context_and_progress(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> std::result::Result<Self, StoreError> {
        Self::new_internal(project, adapter, config, progress, Some(store_context))
    }

    pub fn new_with_progress<F>(project: Arc<dyn Project>, adapter: A, progress: F) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_with_config_and_progress(project, adapter, AnalyzerConfig::default(), progress)
    }

    pub fn new_with_config_and_progress<F>(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_internal(project, adapter, config, Some(Arc::new(progress)), None)
            .expect("failed to initialize in-memory analyzer store")
    }

    fn new_internal(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
        store_context: Option<AnalyzerStoreContext>,
    ) -> std::result::Result<Self, StoreError> {
        let adapter = Arc::new(adapter);
        let mut store_context = match store_context {
            Some(store_context) => store_context,
            None => ephemeral_store_context(project.as_ref())?,
        };
        let epochs = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(storage_key, parser_language)| {
                (
                    storage_key,
                    crate::analyzer::store::epoch::epoch_for(adapter.language(), &parser_language)
                        .to_string(),
                )
            })
            .collect::<Vec<_>>();
        let generations = store_context
            .store
            .ensure_language_epoch_values(&epochs)
            .map_err(|error| error.context("publishing analyzer epochs"))?;
        store_context.generations = Arc::new(generations);
        let state = {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::new_with_config",
                adapter.language()
            ));
            Arc::new(Self::build_state(
                project.as_ref(),
                adapter.as_ref(),
                &config,
                progress,
                &store_context,
            ))
        };
        // The snapshot is only a build-scoped input. Do not retain the full
        // workspace listing or startup OID projection in the long-lived
        // analyzer context after all language delegates have consumed it.
        store_context.workspace_snapshot = None;
        let mut source_snapshot_file_states =
            map_with_capacity(SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY);
        state.seed_snapshot_file_states(&mut source_snapshot_file_states);

        let structural_cache = Arc::new(Self::build_structural_cache(&config));
        let structural_index_cache = Arc::new(Self::build_structural_index_cache(&config));
        let snapshot_caches = Arc::new(Self::build_snapshot_caches(&config));
        let content_identity_base = Self::build_content_identity_base(&config, adapter.as_ref());
        let semantic_cache = crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
            config.memo_cache_budget_bytes() / 8,
        );
        let active_persisted_payload_bytes = store_context
            .store
            .active_file_state_payload_bytes(&store_context.generations)
            .ok();
        let file_state_cache_budget =
            file_state_cache_budget_bytes(&config, active_persisted_payload_bytes);
        let query_file_state_cache_budget =
            query_file_state_cache_budget_bytes(file_state_cache_budget);
        let storage_languages = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(lang, _)| lang)
            .collect::<Vec<_>>();
        let relational_workspace_snapshots = Arc::new(
            store_context
                .store
                .workspace_snapshots_for_langs(
                    &store_context.workspace_id,
                    &storage_languages,
                    store_context.generations.as_ref(),
                )
                .map_err(|error| error.context("capturing relational workspace identities"))?,
        );
        let indexed_live_snapshot = store_context.live_paths.snapshot();
        Ok(Self {
            project,
            adapter,
            config,
            state,
            structural_cache,
            structural_index_cache,
            snapshot_caches,
            content_identity_base,
            semantic_cache,
            semantic_source_digests:
                crate::analyzer::semantic::service::SourceContentIdentityMemo::default(),
            blob_oids: Arc::new(SourceBlobOidMemo::default()),
            store_context,
            indexed_live_snapshot,
            relational_workspace_snapshots: Arc::new(arc_swap::ArcSwap::from(
                relational_workspace_snapshots,
            )),
            query_read_cache: Arc::new(RwLock::new(QueryReadCache::new(
                query_file_state_cache_budget,
            ))),
            live_source_snapshot: Arc::new(ArcSwapOption::empty()),
            query_file_state_snapshot: Arc::new(ArcSwapOption::empty()),
            prepared_syntax_store: Arc::new(Mutex::new(PreparedSyntaxStore::new(
                PREPARED_SYNTAX_STORE_MAX_BYTES,
            ))),
            import_info_store: Arc::new(Mutex::new(ImportInfoStore::new(
                IMPORT_INFO_STORE_MAX_BYTES,
            ))),
            type_alias_store: Arc::new(Mutex::new(TypeAliasStore::new(TYPE_ALIAS_STORE_MAX_BYTES))),
            enclosing_code_unit_store: Arc::new(Mutex::new(EnclosingCodeUnitStore::new(
                ENCLOSING_CODE_UNIT_INDEX_STORE_MAX_BYTES,
            ))),
            #[cfg(test)]
            live_oid_validation_counts: Arc::new(Mutex::new(HashMap::default())),
            tier_access_counts: Arc::new(Mutex::new(HashMap::default())),
            tier_access_totals: Arc::new(Default::default()),
            attached_read_ledgers: Arc::new(AtomicUsize::new(0)),
            transient_file_states: Arc::new(Mutex::new(FileStateCache::new(
                file_state_cache_budget,
            ))),
            source_snapshot_file_states: Arc::new(source_snapshot_file_states),
            summary_file_projections: Arc::new(Mutex::new(SummaryFileProjectionCache::new(
                SUMMARY_FILE_PROJECTION_CACHE_CAPACITY,
            ))),
            full_hydration_count: Arc::new(AtomicUsize::new(0)),
            authoritative_file_state_reads: Arc::new(AtomicUsize::new(0)),
            bulk_hydration_count: Arc::new(AtomicUsize::new(0)),
            sql_definitions_query_count: Arc::new(AtomicUsize::new(0)),
            definition_candidates_query_count: Arc::new(AtomicUsize::new(0)),
            definition_prefetch_batch_count: Arc::new(AtomicUsize::new(0)),
            relational_definition_batch_call_count: Arc::new(AtomicUsize::new(0)),
            definition_candidate_row_read_count: Arc::new(AtomicUsize::new(0)),
            structural_miss_spelling_count: Arc::new(AtomicUsize::new(0)),
            enclosing_code_unit_query_count: Arc::new(AtomicUsize::new(0)),
            full_declaration_scan_count: Arc::new(AtomicUsize::new(0)),
            search_candidate_hydration_count: Arc::new(AtomicUsize::new(0)),
            package_declaration_scan_count: Arc::new(AtomicUsize::new(0)),
            workspace_path_scan_count: Arc::new(AtomicUsize::new(0)),
            analyzed_file_listing_count: Arc::new(AtomicUsize::new(0)),
            _state: PhantomData,
        })
    }

    /// The structural facts cache takes a slice of the shared memo budget,
    /// like the per-language memo caches do.
    fn build_structural_cache(
        config: &AnalyzerConfig,
    ) -> crate::analyzer::structural::provider::StructuralFactsCache {
        crate::analyzer::structural::provider::StructuralFactsCache::new(
            config.memo_cache_budget_bytes() / 8,
        )
    }

    pub(crate) fn structural_cache(
        &self,
    ) -> &crate::analyzer::structural::provider::StructuralFactsCache {
        &self.structural_cache
    }

    fn build_structural_index_cache(
        config: &AnalyzerConfig,
    ) -> crate::analyzer::structural::provider::StructuralFactSnapshotCache {
        crate::analyzer::structural::provider::StructuralFactSnapshotCache::new(
            config.memo_cache_budget_bytes(),
        )
    }

    pub(crate) fn structural_index_cache(
        &self,
    ) -> &crate::analyzer::structural::provider::StructuralFactSnapshotCache {
        &self.structural_index_cache
    }

    fn build_snapshot_caches(config: &AnalyzerConfig) -> crate::analyzer::AnalyzerSnapshotCaches {
        crate::analyzer::AnalyzerSnapshotCaches::new(config.memo_cache_budget_bytes() / 8)
    }

    /// Everything except the analyzed file set that decides what a derived
    /// value over this analyzer's language means (#2449).
    ///
    /// Derived once per analyzer construction because it formats the analyzer
    /// configuration; the per-query half is only the memoized live file-set
    /// digest folded into this.
    fn build_content_identity_base(config: &AnalyzerConfig, adapter: &A) -> StableDigest {
        let mut epochs = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(storage_key, parser_language)| {
                (
                    storage_key,
                    crate::analyzer::store::epoch::epoch_for(adapter.language(), &parser_language),
                )
            })
            .collect::<Vec<_>>();
        epochs.sort();
        let mut epoch_hasher = crate::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-workspace-content:storage-language-epochs:v1",
        );
        for (storage_key, epoch) in &epochs {
            epoch_hasher.field(storage_key, epoch.as_bytes());
        }
        crate::analyzer::content_identity::language_identity_base(
            adapter.language(),
            &epoch_hasher.finish(),
            // The configuration carries no fingerprint of its own, and its
            // literal representation is the same input #2529 chose for the
            // portable workspace identity. It is formatted once per analyzer,
            // never once per query.
            StableDigest::sha256(format!("{config:?}").as_bytes()),
        )
    }

    /// The content identity of this analyzer's analyzed file set.
    ///
    /// This replaces the process-local `analysis_generation()` counter in every
    /// snapshot-scoped cache key: it moves exactly when the content, the
    /// language epoch, or the analyzer configuration moves, so an update that
    /// changed nothing this language owns leaves every value derived from it
    /// reusable.
    pub(crate) fn language_content_identity(&self) -> StableDigest {
        let overlays = self.project.overlay_content();
        let language = self.adapter.language();
        let mut overlay_paths = self
            .state
            .workspace_package_identity_input_digests
            .iter()
            .map(|(file, digest)| (crate::path_utils::rel_path_string(file), *digest))
            .collect::<BTreeMap<_, _>>();
        if let Some(overlays) = overlays.as_deref() {
            for (file, digest) in overlays.entries() {
                if crate::analyzer::common::language_for_file(file) == language
                    || self.adapter.workspace_package_identity_input(file)
                {
                    overlay_paths.insert(crate::path_utils::rel_path_string(file), *digest);
                }
            }
        }
        crate::analyzer::content_identity::language_content_identity(
            self.content_identity_base,
            self.indexed_live_snapshot
                .content_digest(overlays.as_deref()),
            overlay_paths
                .iter()
                .map(|(path, digest)| (path.as_str(), digest)),
        )
    }

    pub(crate) fn snapshot_caches(&self) -> &crate::analyzer::AnalyzerSnapshotCaches {
        &self.snapshot_caches
    }

    pub(crate) fn semantic_source_digests(
        &self,
    ) -> &crate::analyzer::semantic::service::SourceContentIdentityMemo {
        &self.semantic_source_digests
    }

    /// The workspace's reusable identity for `file` in the current analyzer
    /// generation, answered without reading the file, or `None` when the
    /// workspace cannot answer that cheaply and soundly.
    ///
    /// `None` is returned for every case where the recorded identity is not
    /// provably the file's current content:
    ///
    /// * an unsaved overlay shadows the file, so its disk stat says nothing
    ///   about the content an analysis would see;
    /// * the live path map has no entry, or the entry is an overlay whose
    ///   revision is not represented by the path map;
    /// * the file's current stat differs from the recorded one.
    ///
    /// An analyzer configured to trust its filesystem generation deliberately
    /// does not stat here. Its snapshot changes only through an explicit
    /// update, so the recorded OID remains the content identity for that
    /// generation even if the file changes behind the analyzer's back.
    ///
    /// A `Some` answer costs one stat. It is deliberately not a fallback
    /// chain: a caller uses this to *skip* reading the file, so a hidden read
    /// here would defeat the purpose and hide real work from a budget.
    pub(crate) fn reusable_live_oid(&self, file: &ProjectFile) -> Option<Oid> {
        if self.project.has_overlay(file) {
            return None;
        }
        self.store_context
            .live_paths
            .snapshot()
            .reusable_oid_for_path(file)
    }

    pub(crate) fn materialize_semantics_with_lowerer(
        &self,
        lowerer: &dyn crate::analyzer::semantic::service::ProgramSemanticsLowerer,
        file: &ProjectFile,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            Arc<crate::analyzer::semantic::SemanticArtifact>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        crate::analyzer::semantic::service::materialize_with_lowerer(
            self,
            &self.semantic_cache,
            lowerer,
            file,
            request,
        )
    }

    pub(crate) fn current_semantic_artifact_source_with_lowerer(
        &self,
        lowerer: &dyn crate::analyzer::semantic::service::ProgramSemanticsLowerer,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<
        Option<crate::analyzer::semantic::SemanticArtifactSourceSnapshot>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        crate::analyzer::semantic::service::current_artifact_source_with_lowerer(
            self,
            lowerer,
            file,
            max_source_bytes,
        )
    }

    /// The Git blob oid of `source`, the exact bytes a caller is about to key
    /// facts by, for `file`.
    ///
    /// This is the one place a query path turns a source string into the
    /// store's content key (#2917). The identity is a property of the bytes,
    /// not of the snapshot: a concurrent disk or overlay change hands the
    /// caller different bytes and so a different oid, never a stale one. The
    /// SHA-1 runs once per (file, bytes) and is memoized against the source's
    /// length and FxHash, so a repeat query over an unchanged file pays a
    /// hash-map probe and one FxHash pass instead of libgit2's
    /// collision-detecting SHA-1 over the whole file.
    pub(crate) fn blob_oid_of(&self, file: &ProjectFile, source: &str) -> Oid {
        self.blob_oids.oid_of(file, source)
    }

    /// SHA-1 blob hashes [`Self::blob_oid_of`] computed since the last reset.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn blob_hash_count_for_test(&self) -> usize {
        self.blob_oids.hashes.load(Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reset_blob_hash_count_for_test(&self) {
        self.blob_oids.hashes.store(0, Ordering::Relaxed);
    }

    /// Resolve a persistence identity for the exact source string being
    /// normalized. Keying by the supplied bytes prevents a concurrent file or
    /// overlay change from associating facts with a different live OID.
    pub(crate) fn structural_snapshot_key(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> Option<StructuralSnapshotKey> {
        if self.store_context.store.is_ephemeral() {
            return None;
        }
        let oid = self.blob_oid_of(file, source);
        let lang = self.adapter.storage_language_key_for_file(file);
        let generation = self.store_context.generations.get(lang).copied()?;
        Some(StructuralSnapshotKey {
            oid,
            lang: lang.to_string(),
            generation,
        })
    }

    pub(crate) fn load_structural_facts_rows(
        &self,
        key: &StructuralSnapshotKey,
        facts_version: i64,
    ) -> Result<Option<crate::analyzer::structural::facts::PersistedStructuralFacts>, StoreError>
    {
        self.store_context.store.load_structural_facts_rows(
            key.oid,
            &key.lang,
            key.generation,
            facts_version,
        )
    }

    pub(crate) fn persist_structural_facts_rows(
        &self,
        key: &StructuralSnapshotKey,
        facts_version: i64,
        facts: crate::analyzer::structural::facts::PersistedStructuralFacts,
    ) -> Result<bool, StoreError> {
        self.store_context.store.upsert_structural_facts_rows(
            key.oid,
            &key.lang,
            key.generation,
            facts_version,
            facts,
        )
    }

    pub fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    /// The project handle itself, for a collaborator that outlives the borrow.
    /// `AliasResolver` holds one so its workspace-package index can be built on
    /// demand from the project's cached listing, instead of forcing a workspace
    /// walk when the resolver is constructed.
    pub fn shared_project(&self) -> Arc<dyn Project> {
        Arc::clone(&self.project)
    }

    pub fn adapter(&self) -> &A {
        self.adapter.as_ref()
    }

    pub(crate) fn workspace_package_inventory_complete(&self) -> bool {
        if !self.state.workspace_package_inventory_complete {
            return false;
        }
        let Some(overlays) = self.project.overlay_content() else {
            return true;
        };
        if overlays.entries().iter().any(|(file, _)| {
            crate::analyzer::common::language_for_file(file) == self.adapter.language()
        }) {
            return false;
        }
        if !self.adapter.has_workspace_package_identity_inputs() {
            return true;
        }
        overlays.entries().iter().all(|(file, digest)| {
            !self.adapter.workspace_package_identity_input(file)
                || self
                    .state
                    .workspace_package_identity_input_digests
                    .get(file)
                    == Some(digest)
        })
    }

    /// Whether the package-qualified identities stored for this analyzer can be
    /// returned by a request snapshot.
    ///
    /// A package-identity input such as Go's `go.mod` can rekey every source
    /// declaration below it without changing any source blob OID. A cloned
    /// request project deliberately does not rebuild the workspace, so its
    /// persisted and transient declaration rows still carry the disk identity.
    /// Until a real update reprojects those rows, suppress every positive
    /// declaration answer instead of mixing the request's package namespace
    /// with stale disk-qualified bodies.
    pub(crate) fn workspace_declaration_identities_authoritative(&self) -> bool {
        if !self.adapter.has_workspace_package_identity_inputs() {
            return true;
        }
        self.project
            .overlay_content()
            .as_deref()
            .is_none_or(|overlays| {
                overlays.entries().iter().all(|(file, digest)| {
                    !self.adapter.workspace_package_identity_input(file)
                        || self
                            .state
                            .workspace_package_identity_input_digests
                            .get(file)
                            == Some(digest)
                })
            })
    }

    /// Build the analyzer for the next generation out of an already-reconciled
    /// state.
    ///
    /// `structural_index_cache` and `snapshot_caches` are the previous
    /// generation's, carried across rather than replaced (#2449). Every value
    /// they hold is keyed by a
    /// [`crate::analyzer::content_identity::WorkspaceContentIdentity`], so an
    /// update that did not change this language's analyzed content cannot make
    /// one of them wrong, and an update that did change it simply asks a key
    /// nothing answers. Stale entries are retired by the caches' own byte
    /// budgets, which is the same rule the typestate summary repository
    /// adopted in Milestone D.
    ///
    /// `snapshot_caches` carries only its content-keyed halves; the semantic
    /// model publication inside it stays snapshot-scoped and is minted fresh.
    // Every parameter is a distinct thing the next generation inherits, and
    // both callers pass a different mix of retained and freshly derived
    // values; a parameter struct would only rename the list.
    #[allow(clippy::too_many_arguments)]
    fn from_state(
        project: Arc<dyn Project>,
        adapter: Arc<A>,
        config: AnalyzerConfig,
        state: AnalyzerRuntimeState,
        structural_cache: Arc<crate::analyzer::structural::provider::StructuralFactsCache>,
        structural_index_cache: Arc<
            crate::analyzer::structural::provider::StructuralFactSnapshotCache,
        >,
        snapshot_caches: Arc<crate::analyzer::AnalyzerSnapshotCaches>,
        content_identity_base: StableDigest,
        semantic_cache: crate::analyzer::semantic::service::CompleteSemanticArtifactCache,
        store_context: AnalyzerStoreContext,
        relational_workspace_snapshots: Arc<WorkspaceSnapshots>,
    ) -> Self {
        let mut source_snapshot_file_states =
            map_with_capacity(SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY);
        state.seed_snapshot_file_states(&mut source_snapshot_file_states);
        let active_persisted_payload_bytes = store_context
            .store
            .active_file_state_payload_bytes(&store_context.generations)
            .ok();
        let file_state_cache_budget =
            file_state_cache_budget_bytes(&config, active_persisted_payload_bytes);
        let query_file_state_cache_budget =
            query_file_state_cache_budget_bytes(file_state_cache_budget);
        let indexed_live_snapshot = store_context.live_paths.snapshot();
        Self {
            project,
            adapter,
            config,
            state: Arc::new(state),
            structural_cache,
            structural_index_cache,
            snapshot_caches,
            content_identity_base,
            semantic_cache,
            semantic_source_digests:
                crate::analyzer::semantic::service::SourceContentIdentityMemo::default(),
            blob_oids: Arc::new(SourceBlobOidMemo::default()),
            store_context,
            indexed_live_snapshot,
            relational_workspace_snapshots: Arc::new(arc_swap::ArcSwap::from(
                relational_workspace_snapshots,
            )),
            query_read_cache: Arc::new(RwLock::new(QueryReadCache::new(
                query_file_state_cache_budget,
            ))),
            live_source_snapshot: Arc::new(ArcSwapOption::empty()),
            query_file_state_snapshot: Arc::new(ArcSwapOption::empty()),
            prepared_syntax_store: Arc::new(Mutex::new(PreparedSyntaxStore::new(
                PREPARED_SYNTAX_STORE_MAX_BYTES,
            ))),
            import_info_store: Arc::new(Mutex::new(ImportInfoStore::new(
                IMPORT_INFO_STORE_MAX_BYTES,
            ))),
            type_alias_store: Arc::new(Mutex::new(TypeAliasStore::new(TYPE_ALIAS_STORE_MAX_BYTES))),
            enclosing_code_unit_store: Arc::new(Mutex::new(EnclosingCodeUnitStore::new(
                ENCLOSING_CODE_UNIT_INDEX_STORE_MAX_BYTES,
            ))),
            #[cfg(test)]
            live_oid_validation_counts: Arc::new(Mutex::new(HashMap::default())),
            tier_access_counts: Arc::new(Mutex::new(HashMap::default())),
            tier_access_totals: Arc::new(Default::default()),
            attached_read_ledgers: Arc::new(AtomicUsize::new(0)),
            transient_file_states: Arc::new(Mutex::new(FileStateCache::new(
                file_state_cache_budget,
            ))),
            source_snapshot_file_states: Arc::new(source_snapshot_file_states),
            summary_file_projections: Arc::new(Mutex::new(SummaryFileProjectionCache::new(
                SUMMARY_FILE_PROJECTION_CACHE_CAPACITY,
            ))),
            full_hydration_count: Arc::new(AtomicUsize::new(0)),
            authoritative_file_state_reads: Arc::new(AtomicUsize::new(0)),
            bulk_hydration_count: Arc::new(AtomicUsize::new(0)),
            sql_definitions_query_count: Arc::new(AtomicUsize::new(0)),
            definition_candidates_query_count: Arc::new(AtomicUsize::new(0)),
            definition_prefetch_batch_count: Arc::new(AtomicUsize::new(0)),
            relational_definition_batch_call_count: Arc::new(AtomicUsize::new(0)),
            definition_candidate_row_read_count: Arc::new(AtomicUsize::new(0)),
            structural_miss_spelling_count: Arc::new(AtomicUsize::new(0)),
            enclosing_code_unit_query_count: Arc::new(AtomicUsize::new(0)),
            full_declaration_scan_count: Arc::new(AtomicUsize::new(0)),
            search_candidate_hydration_count: Arc::new(AtomicUsize::new(0)),
            package_declaration_scan_count: Arc::new(AtomicUsize::new(0)),
            workspace_path_scan_count: Arc::new(AtomicUsize::new(0)),
            analyzed_file_listing_count: Arc::new(AtomicUsize::new(0)),
            _state: PhantomData,
        }
    }

    fn build_parser(language: TsLanguage) -> Parser {
        let mut parser = Parser::new();
        parser
            .set_language(&language)
            .expect("failed to load tree-sitter language");
        parser
    }

    fn analyze_file(
        parser: &mut Parser,
        adapter: &A,
        project: &dyn Project,
        file: &ProjectFile,
    ) -> Option<FileState> {
        let source = project.read_source(file).ok()?;
        Self::analyze_source(parser, adapter, file, source)
    }

    fn analyze_source(
        parser: &mut Parser,
        adapter: &A,
        file: &ProjectFile,
        source: String,
    ) -> Option<FileState> {
        Self::analyze_source_with_budget(
            parser,
            adapter,
            file,
            source,
            Self::complete_file_parse_budget(file),
        )
    }

    fn complete_file_parse_budget(file: &ProjectFile) -> Duration {
        #[cfg(test)]
        if FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned")
            .iter()
            .any(|path| path.as_path() == file.abs_path().as_path())
        {
            return Duration::ZERO;
        }
        #[cfg(not(test))]
        let _ = file;
        COMPLETE_FILE_PARSE_BUDGET
    }

    fn analyze_source_with_budget(
        parser: &mut Parser,
        adapter: &A,
        file: &ProjectFile,
        source: String,
        budget: Duration,
    ) -> Option<FileState> {
        if crate::analyzer::common::is_unparseable_source(source.as_str()) {
            return None;
        }
        if !set_parser_for_file(parser, adapter, file, source.as_str()) {
            return None;
        }
        let tree = match parse_complete_file_bounded(parser, &source, None, budget) {
            BoundedParse::Complete(tree) => tree,
            BoundedParse::TimedOut => {
                let mut parsed = ParsedFile::new(String::new());
                parsed.add_file_scope(file, &source);
                return Some(Self::file_state_from_parsed(
                    source,
                    parsed,
                    false,
                    Some(Vec::new()),
                    false,
                ));
            }
            BoundedParse::Cancelled => unreachable!("no cancellation token supplied"),
            BoundedParse::Rejected => return None,
        };
        // Every reading of this blob at once, and before the file scope is
        // added: `add_file_scope` contributes the identical module unit to
        // every reading, so an implementor comparing its readings against each
        // other compares only what the language walk itself produced.
        let (mut parsed, projections) = adapter.parse_file_with_projections(file, &source, &tree);
        parsed.add_file_scope(file, &source);
        let contains_tests = adapter.contains_tests(file, &source, &tree, &parsed);
        let parse_errors = {
            let mut errors = Vec::new();
            collect_parse_errors(tree.root_node(), &mut errors);
            Some(errors)
        };
        let additional_projections = projections
            .into_iter()
            .map(|(storage_key, mut projection)| {
                projection.add_file_scope(file, &source);
                (
                    storage_key,
                    Arc::new(Self::file_state_from_parsed(
                        String::new(),
                        projection,
                        contains_tests,
                        None,
                        true,
                    )),
                )
            })
            .collect();

        // The source travels in the `FileState` for the rest of this build and
        // is dropped when the state is persisted: the store has never held a
        // source column (see `.agents/plans/ANALYZER_SQLITE_STORE_EXECPLAN.md`;
        // reads go to the working tree first, then the Git object database).
        // `payload_bytes` counts it in flight and `persisted_payload_bytes`
        // subtracts it again before `blob_payload_costs` is written.
        let mut state =
            Self::file_state_from_parsed(source, parsed, contains_tests, parse_errors, true);
        state.additional_projections = additional_projections;
        Some(state)
    }

    /// Assemble a `FileState` from a completed parse.
    ///
    /// Shared with the bounded-parse timeout path above, which produces a
    /// file-scope-only `ParsedFile` rather than reaching the walk at all, and
    /// must still hand back a `FileState` of exactly the same shape.
    fn file_state_from_parsed(
        source: String,
        mut parsed: ParsedFile,
        contains_tests: bool,
        parse_errors: Option<Vec<crate::analyzer::ParseError>>,
        parse_complete: bool,
    ) -> FileState {
        let declarations = parsed.take_declarations();

        FileState {
            source,
            content_qualifier: parsed.content_qualifier,
            package_name: parsed.package_name,
            top_level_declarations: parsed.top_level_declarations,
            declarations,
            definition_lookup_units: parsed.definition_lookup_units,
            imports: parsed.imports,
            scala_exports: parsed.scala_exports,
            rust_usage_facts: parsed.rust_usage_facts,
            raw_supertypes: parsed.raw_supertypes,
            supertype_lookup_paths: parsed.supertype_lookup_paths,
            type_identifiers: parsed.type_identifiers,
            signatures: parsed.signatures,
            signature_metadata: parsed.signature_metadata,
            cpp_template_metadata: parsed.cpp_template_metadata,
            ruby_method_dispatch_modes: parsed.ruby_method_dispatch_modes,
            ranges: parsed.ranges,
            children: parsed.children,
            scala_traits: parsed.scala_traits,
            type_aliases: parsed.type_aliases,
            contains_tests,
            test_region_units: parsed.test_region_units,
            materialization_records: parsed.materialization_records,
            parse_errors,
            parse_complete,
            additional_projections: Vec::new(),
        }
    }

    pub fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        if code_unit.is_module() {
            return None;
        }

        self.fetch_file_state(code_unit.source()).and_then(|state| {
            state.children.iter().find_map(|(parent, children)| {
                children
                    .iter()
                    .any(|child| child == code_unit)
                    .then(|| parent.clone())
            })
        })
    }

    pub fn top_level_file_scope_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        if code_unit.is_module() {
            return None;
        }

        let state = self.fetch_file_state(code_unit.source())?;
        if !state
            .top_level_declarations
            .iter()
            .any(|declaration| declaration == code_unit)
        {
            return None;
        }

        state
            .declarations
            .iter()
            .find(|declaration| declaration.is_file_scope())
            .cloned()
    }

    fn analyze_files(
        adapter: &A,
        project: &dyn Project,
        config: &AnalyzerConfig,
        files: Vec<ProjectFile>,
        progress: Option<BuildProgress>,
        store_context: &AnalyzerStoreContext,
    ) -> Vec<(ProjectFile, Option<FileState>)> {
        let _scope = profiling::scope(format!(
            "TreeSitterAnalyzer::{:?}::analyze_files[{}]",
            adapter.language(),
            files.len()
        ));
        if files.is_empty() {
            return Vec::new();
        }

        let total = files.len();
        let language = adapter.parser_language();
        let completed = AtomicUsize::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.parallelism())
            .build()
            .expect("failed to build analyzer thread pool");

        let states = pool.install(|| {
            files
                .into_par_iter()
                .map_init(
                    || Self::build_parser(language.clone()),
                    |parser, file| {
                        store_context
                            .build_tier_access
                            .record_tier_access(InformationTier::Syntax);
                        let state = Self::analyze_file(parser, adapter, project, &file);
                        if let Some(progress) = progress.as_ref() {
                            let current = completed.fetch_add(1, Ordering::Relaxed) + 1;
                            progress(BuildProgressEvent::new(
                                adapter.language(),
                                BuildProgressPhase::Parse,
                                current,
                                total,
                                Some(file.clone()),
                            ));
                        }
                        (file, state)
                    },
                )
                .collect::<Vec<_>>()
        });
        note_additional_projection_totals(adapter.language());
        states
    }

    fn analyze_prepare_and_persist_files(
        adapter: &A,
        project: &dyn Project,
        config: &AnalyzerConfig,
        targets: Vec<(ProjectFile, Oid, String, GenerationId)>,
        progress: Option<BuildProgress>,
        store_context: &AnalyzerStoreContext,
        mut on_outcome: impl FnMut(ProjectFile, PreparedPersistenceOutcome),
    ) -> PersistBatchStats {
        const PREPARED_CHANNEL_CAPACITY: usize = 8;
        if targets.is_empty() {
            return PersistBatchStats::default();
        }

        let total = targets.len();
        let language = adapter.parser_language();
        let completed = AtomicUsize::new(0);
        let started = AtomicUsize::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.parallelism())
            .build()
            .expect("failed to build analyzer thread pool");
        let (prepared_tx, prepared_rx) = std::sync::mpsc::sync_channel(PREPARED_CHANNEL_CAPACITY);
        let producer_progress = progress.clone();
        let in_flight = Arc::new(Mutex::new(PreparedInFlight::default()));
        let mut stats = PersistBatchStats::default();
        let timing_enabled = profiling::enabled();
        let mut prepared_channel_recv_elapsed = Duration::ZERO;
        let mut prepared_channel_recvs = 0usize;
        let blob_persistence_elapsed = Cell::new(Duration::ZERO);
        let blob_persistence_batches = Cell::new(0usize);
        let limits = PersistBatchLimits::PRODUCTION;
        stats.configured_max_in_flight_items = config
            .parallelism()
            .saturating_add(PREPARED_CHANNEL_CAPACITY)
            .saturating_add(limits.max_blobs);

        // The producer's panic is captured rather than left to the scope's own
        // join. `std::thread::scope` reports a panicked child by panicking with
        // its own `&str` "a scoped thread panicked", which replaces the parse
        // failure's real message and location: on microsoft/PowerToys that is
        // all a caller saw of an FqName boundary assert (issue #2359). Catching
        // it here and re-raising it from inside the scope's own closure sends
        // the original payload up instead.
        let producer_panic: Mutex<Option<Box<dyn std::any::Any + Send>>> = Mutex::new(None);
        // Where this phase's wall time went, reported below. The clocks run
        // whether or not timing is on: two `Instant::now` calls against a
        // multi-millisecond parse are unmeasurable, and always collecting them
        // means the reported split is the one the ordinary build produced
        // rather than one a measurement mode perturbed. `send_block_nanos` is
        // summed over all workers, so divide by parallelism to compare it with
        // the wall clock.
        let phase_start = std::time::Instant::now();
        let writer_before = crate::analyzer::store::writer::attribution::snapshot();
        let send_block_nanos = AtomicUsize::new(0);
        let analyze_nanos = AtomicUsize::new(0);
        let recv_wait_nanos = std::cell::Cell::new(0u128);
        let persist_call_nanos = std::cell::Cell::new(0u128);
        std::thread::scope(|scope| {
            let producer_tx = prepared_tx.clone();
            let producer_in_flight = Arc::clone(&in_flight);
            let producer_panic = &producer_panic;
            let send_block_nanos = &send_block_nanos;
            let analyze_nanos = &analyze_nanos;
            scope.spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    pool.install(|| {
                        targets.into_par_iter().for_each_init(
                            || Self::build_parser(language.clone()),
                            |parser, (file, oid, storage_key, generation)| {
                                let current_started = started.fetch_add(1, Ordering::SeqCst) + 1;
                                if current_started == total {
                                    producer_tx
                                        .send(PreparedAnalysis::AllStarted)
                                        .expect("persistence receiver should remain connected");
                                }
                                // Another language's worker has already panicked and
                                // the whole build is being torn down, so parsing this
                                // file can only delay the panic reaching its caller.
                                // Leaving it unpersisted is the ordinary state of a
                                // file nobody has indexed yet (#2359).
                                if store_context.build_abort.is_aborted() {
                                    return;
                                }
                                Self::block_until_build_abort_for_test(&file, store_context);
                                Self::panic_during_analysis_for_test(&file);
                                store_context
                                    .build_tier_access
                                    .record_tier_access(InformationTier::Syntax);
                                let analyze_start = std::time::Instant::now();
                                let analyzed = Self::analyze_file(parser, adapter, project, &file);
                                let analyze_elapsed = analyze_start.elapsed().as_nanos() as usize;
                                if analyze_elapsed >= SLOW_FILE_ANALYSIS_NOTE_NANOS {
                                    profiling::note(format!(
                                        "slow_file_analysis {} elapsed_ms={:.1}",
                                        file.rel_path().display(),
                                        analyze_elapsed as f64 / 1.0e6
                                    ));
                                }
                                analyze_nanos.fetch_add(analyze_elapsed, Ordering::Relaxed);
                                let result = match analyzed {
                                    Some(state) => {
                                        let state = Arc::new(state);
                                        if Self::should_inject_preparation_failure_for_test(&file) {
                                            PreparedAnalysis::PreparationFailed {
                                                file,
                                                state,
                                                error: "injected preparation failure".to_string(),
                                            }
                                        } else {
                                            match AnalyzerStore::prepare_parsed_blob(
                                                oid,
                                                &storage_key,
                                                generation,
                                                adapter,
                                                Arc::clone(&state),
                                            ) {
                                                Ok(mut prepared) => {
                                                    Self::inject_prepared_failure_for_test(
                                                        &file,
                                                        &mut prepared,
                                                    );
                                                    PreparedAnalysis::Ready {
                                                        file,
                                                        prepared: Box::new(prepared),
                                                    }
                                                }
                                                Err(error) => PreparedAnalysis::PreparationFailed {
                                                    file,
                                                    state,
                                                    error: error.to_string(),
                                                },
                                            }
                                        }
                                    }
                                    None => PreparedAnalysis::Unparseable(file),
                                };
                                if let Some(progress) = producer_progress.as_ref() {
                                    let current = completed.fetch_add(1, Ordering::Relaxed) + 1;
                                    let file = match &result {
                                        PreparedAnalysis::Ready { file, .. }
                                        | PreparedAnalysis::PreparationFailed { file, .. }
                                        | PreparedAnalysis::Unparseable(file) => file.clone(),
                                        PreparedAnalysis::AllStarted => {
                                            unreachable!("start marker is not a parse result")
                                        }
                                    };
                                    progress(BuildProgressEvent::new(
                                        adapter.language(),
                                        BuildProgressPhase::Parse,
                                        current,
                                        total,
                                        Some(file),
                                    ));
                                }
                                if let PreparedAnalysis::Ready { prepared, .. } = &result {
                                    producer_in_flight
                                        .lock()
                                        .expect("prepared in-flight mutex poisoned")
                                        .add(prepared.payload_bytes());
                                }
                                let send_start = std::time::Instant::now();
                                producer_tx
                                    .send(result)
                                    .expect("persistence receiver should remain connected");
                                send_block_nanos.fetch_add(
                                    send_start.elapsed().as_nanos() as usize,
                                    Ordering::Relaxed,
                                );
                            },
                        );
                    });
                }));
                if let Err(payload) = outcome {
                    *producer_panic
                        .lock()
                        .expect("producer panic mutex poisoned") = Some(payload);
                }
            });
            drop(prepared_tx);

            let mut pending = Vec::new();
            let mut pending_files = HashMap::default();
            // Running totals for `pending`, carried instead of refolded: the
            // fold ran on every push, which is quadratic over a 256-blob batch
            // on the serial persist consumer (#2267).
            let mut pending_rows = 0usize;
            let mut pending_bytes = 0usize;
            let mut persist_completed = 0usize;
            let mut tail_mode = false;
            let flush = |pending: &mut Vec<PreparedParsedBlob>,
                         pending_files: &mut HashMap<(Oid, String), ProjectFile>,
                         pending_rows: &mut usize,
                         pending_bytes: &mut usize,
                         stats: &mut PersistBatchStats,
                         persist_completed: &mut usize,
                         on_outcome: &mut PreparedOutcomeHandler<'_>| {
                if pending.is_empty() {
                    return;
                }
                let prepared = std::mem::take(pending);
                *pending_rows = 0;
                *pending_bytes = 0;
                let persist_start = std::time::Instant::now();
                let (outcomes, batch_stats) =
                    store_context.store.persist_prepared_blobs(prepared, limits);
                // One clock feeds both reports: the phase split below and the
                // profiling line's per-batch persistence total.
                let persist_elapsed = persist_start.elapsed();
                persist_call_nanos.set(persist_call_nanos.get() + persist_elapsed.as_nanos());
                blob_persistence_elapsed.set(
                    blob_persistence_elapsed
                        .get()
                        .saturating_add(persist_elapsed),
                );
                blob_persistence_batches.set(blob_persistence_batches.get().saturating_add(1));
                *persist_completed = persist_completed.saturating_add(
                    batch_stats
                        .committed_blobs
                        .saturating_add(batch_stats.failed_blobs),
                );
                if let Some(progress) = progress.as_ref() {
                    progress(BuildProgressEvent::new(
                        adapter.language(),
                        BuildProgressPhase::Persist,
                        *persist_completed,
                        total,
                        None,
                    ));
                }
                stats.merge(batch_stats);
                for outcome in outcomes {
                    in_flight
                        .lock()
                        .expect("prepared in-flight mutex poisoned")
                        .remove(outcome.prepared.payload_bytes());
                    let key = (outcome.prepared.oid(), outcome.prepared.lang().to_string());
                    let file = pending_files
                        .remove(&key)
                        .expect("prepared outcome must retain its file envelope");
                    on_outcome(
                        file,
                        Some((Arc::clone(outcome.prepared.state()), outcome.error)),
                    );
                }
            };

            let add_ready = |file: ProjectFile,
                             prepared: Box<PreparedParsedBlob>,
                             pending: &mut Vec<PreparedParsedBlob>,
                             pending_files: &mut HashMap<(Oid, String), ProjectFile>,
                             pending_rows: &mut usize,
                             pending_bytes: &mut usize| {
                let key = (prepared.oid(), prepared.lang().to_string());
                if pending_files.insert(key, file).is_some() {
                    panic!("duplicate prepared blob key in reconcile batch");
                }
                let rows = prepared.logical_rows();
                let bytes = prepared.payload_bytes();
                pending.push(*prepared);
                *pending_rows = pending_rows.saturating_add(rows);
                *pending_bytes = pending_bytes.saturating_add(bytes);
                // The totals only stay correct while every drain resets
                // them, so debug builds pay for the fold this replaced and
                // compare, rather than trusting the invariant silently.
                debug_assert_eq!(
                    *pending_rows,
                    pending.iter().fold(0usize, |total, blob| {
                        total.saturating_add(blob.logical_rows())
                    }),
                    "pending row total drifted from the pending batch"
                );
                debug_assert_eq!(
                    *pending_bytes,
                    pending.iter().fold(0usize, |total, blob| {
                        total.saturating_add(blob.payload_bytes())
                    }),
                    "pending payload byte total drifted from the pending batch"
                );
                pending.len() >= limits.max_blobs
                    || *pending_rows >= limits.max_rows
                    || *pending_bytes >= limits.max_payload_bytes
            };

            let mut deferred = None;
            loop {
                let message = match deferred.take() {
                    Some(message) => Ok(message),
                    None => {
                        let recv_start = std::time::Instant::now();
                        let received = prepared_rx.recv();
                        // As above: one clock, both reports.
                        let recv_elapsed = recv_start.elapsed();
                        recv_wait_nanos.set(recv_wait_nanos.get() + recv_elapsed.as_nanos());
                        prepared_channel_recv_elapsed =
                            prepared_channel_recv_elapsed.saturating_add(recv_elapsed);
                        prepared_channel_recvs = prepared_channel_recvs.saturating_add(1);
                        received
                    }
                };
                match message {
                    Ok(PreparedAnalysis::AllStarted) => {
                        flush(
                            &mut pending,
                            &mut pending_files,
                            &mut pending_rows,
                            &mut pending_bytes,
                            &mut stats,
                            &mut persist_completed,
                            &mut on_outcome,
                        );
                        tail_mode = true;
                    }
                    Ok(PreparedAnalysis::Ready { file, prepared }) => {
                        if add_ready(
                            file,
                            prepared,
                            &mut pending,
                            &mut pending_files,
                            &mut pending_rows,
                            &mut pending_bytes,
                        ) {
                            flush(
                                &mut pending,
                                &mut pending_files,
                                &mut pending_rows,
                                &mut pending_bytes,
                                &mut stats,
                                &mut persist_completed,
                                &mut on_outcome,
                            );
                        }
                        if tail_mode {
                            loop {
                                match prepared_rx.try_recv() {
                                    Ok(PreparedAnalysis::Ready { file, prepared }) => {
                                        if add_ready(
                                            file,
                                            prepared,
                                            &mut pending,
                                            &mut pending_files,
                                            &mut pending_rows,
                                            &mut pending_bytes,
                                        ) {
                                            flush(
                                                &mut pending,
                                                &mut pending_files,
                                                &mut pending_rows,
                                                &mut pending_bytes,
                                                &mut stats,
                                                &mut persist_completed,
                                                &mut on_outcome,
                                            );
                                        }
                                    }
                                    Ok(other) => {
                                        deferred = Some(other);
                                        break;
                                    }
                                    Err(std::sync::mpsc::TryRecvError::Empty)
                                    | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                                }
                            }
                            flush(
                                &mut pending,
                                &mut pending_files,
                                &mut pending_rows,
                                &mut pending_bytes,
                                &mut stats,
                                &mut persist_completed,
                                &mut on_outcome,
                            );
                        }
                    }
                    Ok(PreparedAnalysis::PreparationFailed { file, state, error }) => {
                        stats.failed_blobs = stats.failed_blobs.saturating_add(1);
                        persist_completed = persist_completed.saturating_add(1);
                        if let Some(progress) = progress.as_ref() {
                            progress(BuildProgressEvent::new(
                                adapter.language(),
                                BuildProgressPhase::Persist,
                                persist_completed,
                                total,
                                None,
                            ));
                        }
                        on_outcome(file, Some((state, Some(StoreError::new(error)))));
                    }
                    Ok(PreparedAnalysis::Unparseable(file)) => {
                        persist_completed = persist_completed.saturating_add(1);
                        if let Some(progress) = progress.as_ref() {
                            progress(BuildProgressEvent::new(
                                adapter.language(),
                                BuildProgressPhase::Persist,
                                persist_completed,
                                total,
                                None,
                            ));
                        }
                        on_outcome(file, None);
                    }
                    Err(std::sync::mpsc::RecvError) => {
                        flush(
                            &mut pending,
                            &mut pending_files,
                            &mut pending_rows,
                            &mut pending_bytes,
                            &mut stats,
                            &mut persist_completed,
                            &mut on_outcome,
                        );
                        break;
                    }
                }
            }
        });
        // Raised from the parent thread, with the producer's own payload, so
        // the parse failure's message and location reach the caller intact.
        if let Some(payload) = producer_panic
            .into_inner()
            .expect("producer panic mutex poisoned")
        {
            std::panic::resume_unwind(payload);
        }
        let in_flight = in_flight.lock().expect("prepared in-flight mutex poisoned");
        debug_assert_eq!(in_flight.current_items, 0);
        debug_assert_eq!(in_flight.current_payload_bytes, 0);
        stats.peak_in_flight_items = in_flight.peak_items;
        stats.peak_in_flight_payload_bytes = in_flight.peak_payload_bytes;
        if timing_enabled {
            let language = adapter.language().config_label();
            profiling::duration(
                format!("analyze_prepare_and_persist.prepared_channel_recv[{language}]"),
                prepared_channel_recv_elapsed,
            );
            profiling::duration(
                format!("analyze_prepare_and_persist.blob_persistence[{language}]"),
                blob_persistence_elapsed.get(),
            );
            profiling::note(format!(
                "language={language} prepared_channel_recvs={prepared_channel_recvs} blob_persistence_batches={} persist_transactions={} failed_attempts={} committed_blobs={} failed_blobs={} logical_rows={} prepared_bytes={} peak_batch_blobs={} peak_batch_rows={} peak_batch_bytes={} peak_in_flight_items={} peak_in_flight_bytes={} configured_max_in_flight_items={}",
                blob_persistence_batches.get(),
                stats.transactions,
                stats.failed_transaction_attempts,
                stats.committed_blobs,
                stats.failed_blobs,
                stats.logical_rows,
                stats.payload_bytes,
                stats.peak_batch_blobs,
                stats.peak_batch_rows,
                stats.peak_batch_payload_bytes,
                stats.peak_in_flight_items,
                stats.peak_in_flight_payload_bytes,
                stats.configured_max_in_flight_items,
            ));
            // Parse and persistence overlap, so neither one's own duration says
            // which of them set the phase's length. These four totals do.
            // `writer_busy` against `phase_ms` says whether the single SQLite
            // writer was saturated; `producer_send_block` says whether workers
            // waited on it; `analyze_ms_total` against `phase_ms * workers`
            // says whether the parse pool was busy at all. Reading only the
            // in-flight peak invites the opposite conclusion: it sits at its
            // derived bound whenever one flush is in progress, whatever the
            // pool is doing.
            let elapsed_ms = phase_start.elapsed().as_secs_f64() * 1000.0;
            let writer =
                crate::analyzer::store::writer::attribution::snapshot().since(writer_before);
            let workers = config.parallelism().max(1) as f64;
            profiling::note(format!(
                "persist_attribution files={total} phase_ms={elapsed_ms:.1} worker_thread_ms={:.1} writer_busy_ms={:.1} writer_idle_ms={:.1} writer_jobs={} consumer_persist_ms={:.1} consumer_recv_wait_ms={:.1} producer_send_block_ms={:.1} analyze_ms_total={:.1} workers={workers}",
                elapsed_ms * workers,
                writer.busy_nanos as f64 / 1.0e6,
                writer.idle_nanos as f64 / 1.0e6,
                writer.jobs,
                persist_call_nanos.get() as f64 / 1.0e6,
                recv_wait_nanos.get() as f64 / 1.0e6,
                send_block_nanos.load(Ordering::Relaxed) as f64 / 1.0e6,
                analyze_nanos.load(Ordering::Relaxed) as f64 / 1.0e6,
            ));
        }
        note_additional_projection_totals(adapter.language());
        stats
    }

    fn inject_prepared_failure_for_test(file: &ProjectFile, prepared: &mut PreparedParsedBlob) {
        #[cfg(test)]
        {
            let failure_path = PREPARED_FAILURE_PATH
                .lock()
                .expect("prepared failure path mutex poisoned");
            if failure_path
                .as_ref()
                .is_some_and(|path| path == &file.abs_path())
            {
                prepared.inject_invalid_range_for_test();
            }
        }
        #[cfg(not(test))]
        let _ = (file, prepared);
    }

    /// Stands in for a language frontend that panics on one file, which is what
    /// the `$safeprojectname$` FqName assert did on PowerToys (#2359).
    fn panic_during_analysis_for_test(file: &ProjectFile) {
        #[cfg(test)]
        {
            let panicking = PANICKING_ANALYSIS_PATH
                .lock()
                .expect("panicking analysis path mutex poisoned")
                .clone();
            if panicking.is_some_and(|path| path == file.abs_path()) {
                let (ready, ready_changed) = &BLOCKING_ANALYSIS_READY;
                let ready = ready
                    .lock()
                    .expect("blocking analysis ready mutex poisoned");
                let (ready, wait) = ready_changed
                    .wait_timeout_while(ready, Duration::from_secs(30), |ready| !*ready)
                    .expect("blocking analysis ready mutex poisoned while waiting");
                assert!(
                    *ready && !wait.timed_out(),
                    "blocking sibling did not enter analysis before the safety timeout"
                );
                drop(ready);
                panic!("injected analysis panic for {}", file.rel_path().display());
            }
        }
        #[cfg(not(test))]
        let _ = file;
    }

    /// Stands in for a sibling language whose build is still busy when another
    /// language panics: it holds until the build abort reaches it.
    ///
    /// The safety timeout exists so that a regression fails the test instead of
    /// wedging the whole test binary, which is the very failure mode this hook
    /// is here to catch.
    fn block_until_build_abort_for_test(file: &ProjectFile, store_context: &AnalyzerStoreContext) {
        #[cfg(test)]
        {
            let blocking = BLOCK_UNTIL_BUILD_ABORT_PATH
                .lock()
                .expect("block until build abort path mutex poisoned")
                .clone();
            if blocking.is_some_and(|path| path == file.abs_path()) {
                let (ready, ready_changed) = &BLOCKING_ANALYSIS_READY;
                *ready
                    .lock()
                    .expect("blocking analysis ready mutex poisoned") = true;
                ready_changed.notify_one();
                let deadline = Instant::now() + Duration::from_secs(30);
                while !store_context.build_abort.is_aborted() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if store_context.build_abort.is_aborted() {
                    BLOCKING_ANALYSIS_OBSERVED_ABORT.store(true, Ordering::Release);
                }
            }
        }
        #[cfg(not(test))]
        let _ = (file, store_context);
    }

    fn should_inject_preparation_failure_for_test(file: &ProjectFile) -> bool {
        #[cfg(test)]
        {
            return PREPARATION_FAILURE_PATH
                .lock()
                .expect("preparation failure path mutex poisoned")
                .as_ref()
                .is_some_and(|path| path == &file.abs_path());
        }
        #[cfg(not(test))]
        {
            let _ = file;
            false
        }
    }

    fn resolve_live_oids(
        project: &dyn Project,
        files: &[ProjectFile],
        store_context: &AnalyzerStoreContext,
        replace_live_paths: bool,
    ) -> Result<HashMap<ProjectFile, Oid>, String> {
        let _scope = profiling::scope("TreeSitterAnalyzer::resolve_live_oids");
        type PlannedLiveOid = Option<(ProjectFile, Oid, LivePathEntry)>;

        let workspace_snapshot = store_context.workspace_snapshot.as_deref();
        let liveness = store_context.liveness.as_ref();
        let revision_blobs = store_context.revision_blobs.as_deref();
        let plan_one = |file: &ProjectFile| -> Result<PlannedLiveOid, String> {
            let has_overlay = project.has_overlay(file);
            let revision_oid = revision_blobs.and_then(|blobs| blobs.oid_for(file));
            // An immutable revision image names every analyzer-visible file of
            // the revision but writes only the analyzers' configuration inputs
            // to disk; the rest are served from the repository's object
            // database. Absence from the filesystem is therefore not absence
            // from the revision, and dropping such a file here would make the
            // analyzer's picture of the revision silently partial.
            if revision_oid.is_none() && !file.exists() && !has_overlay {
                return Ok(None);
            }
            if let Some(snapshot) = workspace_snapshot
                && let Some(entry) = snapshot.live_entry(project, file)
            {
                return Ok(Some((file.clone(), entry.oid(), entry)));
            }
            let (oid, entry) = if has_overlay {
                let source = project.read_source(file).map_err(|err| err.to_string())?;
                let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                    .map_err(|err| err.to_string())?;
                (oid, LivePathEntry::overlay(file.clone(), oid))
            } else if let Some(oid) = revision_oid {
                // The tree walk that exported this immutable image already
                // named this file's blob, so there is nothing to hash: the
                // export directory is written once and never edited, and the
                // identity is the revision's by definition rather than an
                // observation of the bytes that happen to be on disk.
                (oid, LivePathEntry::filesystem_hashed(file.clone(), oid))
            } else if let Some(liveness) = liveness {
                // Point resolution hashes the bytes currently on disk, so an
                // incremental update observes the edit that triggered it.
                let Some(oid) = liveness.oid_for_path(file)? else {
                    return Ok(None);
                };
                (oid, LivePathEntry::filesystem(file.clone(), oid))
            } else {
                // No Git identity source, so the bytes on disk are hashed here.
                // Nothing else will notice a later disk edit on this
                // analyzer's behalf, so the identity is not checked for
                // liveness against the file's stat: the analyzer must keep
                // answering from the generation it indexed until it is
                // explicitly refreshed. The stat is still captured with the
                // hash, so content-derived work can be reused only while the
                // file provably still holds these bytes.
                let bytes = std::fs::read(file.abs_path()).map_err(|err| err.to_string())?;
                let oid =
                    Oid::hash_object(ObjectType::Blob, &bytes).map_err(|err| err.to_string())?;
                (oid, LivePathEntry::filesystem_hashed(file.clone(), oid))
            };
            Ok(Some((file.clone(), oid, entry)))
        };
        // The hashing burst runs on the process-shared dedicated build pool.
        // A fresh `rayon::ThreadPool` per call spawned and joined one set of OS
        // threads per reconcile, which an incremental update pays repeatedly
        // (#2115); the shared pool is also off the global pool, so the burst
        // does not park interactive requests behind it.
        let plan_parallel = |subset: &[ProjectFile]| -> Vec<Result<PlannedLiveOid, String>> {
            if subset.len() <= 1 {
                return subset.iter().map(&plan_one).collect();
            }
            install_on_dedicated_build_pool(|| subset.par_iter().map(&plan_one).collect())
        };

        let planned = if replace_live_paths && let Some(liveness) = liveness {
            // Startup and full-sweep reconciles project every disk file with
            // one shared Git identity scan instead of hashing each clean file.
            // Incremental updates stay on point resolution above: they carry
            // few files and must observe the edit that triggered them without
            // depending on the startup scan.
            let (overlay_files, disk_files): (Vec<ProjectFile>, Vec<ProjectFile>) = files
                .iter()
                .cloned()
                .partition(|file| project.has_overlay(file));
            let mut planned = Vec::with_capacity(files.len());
            let mut unresolved_overlays = Vec::new();
            for file in overlay_files {
                if let Some(snapshot) = workspace_snapshot
                    && let Some(entry) = snapshot.live_entry(project, &file)
                {
                    let oid = entry.oid();
                    planned.push(Ok(Some((file, oid, entry))));
                } else {
                    unresolved_overlays.push(file);
                }
            }
            planned.extend(plan_parallel(&unresolved_overlays));

            let mut unresolved_disk = Vec::new();
            for file in disk_files {
                if let Some(snapshot) = workspace_snapshot
                    && let Some(entry) = snapshot.live_entry(project, &file)
                {
                    let oid = entry.oid();
                    planned.push(Ok(Some((file, oid, entry))));
                } else {
                    unresolved_disk.push(file);
                }
            }
            if !unresolved_disk.is_empty() {
                planned.extend(liveness.oids_for_files(&unresolved_disk)?.into_iter().map(
                    |(file, oid)| {
                        let entry = LivePathEntry::filesystem(file.clone(), oid);
                        Ok(Some((file, oid, entry)))
                    },
                ));
            }
            planned
        } else {
            plan_parallel(files)
        };

        let mut out = map_with_capacity(files.len());
        let mut live_entries = Vec::with_capacity(files.len());
        for result in planned {
            let Some((file, oid, entry)) = result? else {
                continue;
            };
            live_entries.push(entry);
            out.insert(file, oid);
        }
        if let Some(liveness) = store_context.liveness.as_ref() {
            liveness.refresh_overlay(live_entries.iter().cloned())?;
        }
        if replace_live_paths {
            store_context.live_paths.replace_all(live_entries);
        } else {
            store_context.live_paths.refresh(live_entries);
        }
        Ok(out)
    }

    fn build_state(
        project: &dyn Project,
        adapter: &A,
        config: &AnalyzerConfig,
        progress: Option<BuildProgress>,
        store_context: &AnalyzerStoreContext,
    ) -> AnalyzerRuntimeState {
        let _scope = profiling::scope(format!(
            "TreeSitterAnalyzer::{:?}::build_state",
            adapter.language()
        ));
        let workspace_snapshot = store_context.workspace_snapshot.as_deref();

        let (analyzable_files, enumeration_complete): (Vec<_>, bool) = {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::enumerate_files",
                adapter.language()
            ));
            let files = match workspace_snapshot {
                Some(snapshot) => {
                    project.analyzable_files_from(snapshot.files(), adapter.language())
                }
                None => project.analyzable_files(adapter.language()),
            };
            match files {
                Ok(files) => (
                    files.into_iter().collect(),
                    store_context.workspace_listing_complete,
                ),
                Err(_) => (Vec::new(), false),
            }
        };
        if let Some(progress) = progress.as_ref() {
            progress(BuildProgressEvent::new(
                adapter.language(),
                BuildProgressPhase::Enumerate,
                analyzable_files.len(),
                analyzable_files.len(),
                None,
            ));
        }
        let mut state = {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::reconcile_file_states",
                adapter.language()
            ));
            Self::reconcile_file_states(
                project,
                adapter,
                config,
                store_context,
                ReconcileFileStates {
                    files: analyzable_files.clone(),
                    replace_live_paths: true,
                    progress: progress.clone(),
                    dirty_file_states: HashMap::default(),
                    dirty_path_symbol_rows: HashMap::default(),
                },
            )
        };
        if !enumeration_complete {
            state.mark_workspace_package_inventory_incomplete();
        }
        // Another language already panicked: every phase below is work whose
        // only effect is to postpone that panic reaching the caller (#2359).
        if store_context.build_abort.is_aborted() {
            return state;
        }
        // Include-driven inference runs after the extension-discovered files
        // are reconciled, because the imports it reads are exactly what that
        // pass persisted: the closure costs one bulk import-fact hydration per
        // round instead of a second read of every source in the workspace.
        let mut indexed_files = analyzable_files.clone();
        let claim_delta = Self::reconcile_claimed_files(
            project,
            adapter,
            config,
            store_context,
            &analyzable_files,
            RetainedClaimRelation::default(),
            &mut state,
        );
        debug_assert!(
            claim_delta.dropped.is_empty(),
            "a full build cannot drop a retained claim"
        );
        indexed_files.extend(claim_delta.added);
        {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::sync_path_symbol_units",
                adapter.language()
            ));
            let (dirty, package_inventory_complete) =
                Self::sync_path_symbol_units(adapter, &indexed_files, store_context);
            state
                .dirty_path_symbol_rows
                .lock()
                .expect("dirty path-symbol mutex poisoned")
                .extend(dirty);
            if !package_inventory_complete {
                state.mark_workspace_package_inventory_incomplete();
            }
        }

        if let Some(progress) = progress.as_ref() {
            let total = indexed_files.len();
            progress(BuildProgressEvent::new(
                adapter.language(),
                BuildProgressPhase::Index,
                total,
                total,
                None,
            ));
        }
        state.workspace_package_identity_input_digests =
            Self::workspace_package_identity_input_digests(project, adapter, workspace_snapshot);
        store_context
            .gc
            .schedule(project.root(), Arc::clone(&store_context.store));
        state
    }

    /// Snapshot the non-source inputs that qualified this generation's
    /// declarations. Package hydration is defined against the filesystem
    /// generation, not a later request overlay, so these bytes deliberately
    /// bypass `Project::read_source`.
    fn workspace_package_identity_input_digests(
        project: &dyn Project,
        adapter: &A,
        workspace_snapshot: Option<&WorkspaceBuildSnapshot>,
    ) -> HashMap<ProjectFile, [u8; 32]> {
        let files = match workspace_snapshot {
            Some(snapshot) => Cow::Borrowed(snapshot.files()),
            None => match project.all_files_shared() {
                Ok(files) => Cow::Owned((*files).clone()),
                Err(_) => return HashMap::default(),
            },
        };
        files
            .iter()
            .filter(|file| adapter.workspace_package_identity_input(file))
            .filter_map(|file| {
                std::fs::read(file.abs_path()).ok().map(|source| {
                    (
                        file.clone(),
                        crate::analyzer::canonical_hash::sha256_bytes(&source),
                    )
                })
            })
            .collect()
    }

    /// Every workspace file whose extension no language claims: the universe
    /// include-driven inference may draw from (#1837).
    ///
    /// `.bifrostignore` is applied later, to the files inference actually
    /// adopts, not here. `Project::is_bifrostignored` answers one path at a time
    /// off a whole-workspace listing, so asking it about every non-source file
    /// in the repository would cost a listing per file.
    fn claimable_workspace_files(
        project: &dyn Project,
        workspace_snapshot: Option<&WorkspaceBuildSnapshot>,
    ) -> BTreeSet<ProjectFile> {
        let files = if let Some(snapshot) = workspace_snapshot {
            snapshot.files().clone()
        } else {
            let Ok(files) = project.all_files_shared() else {
                return BTreeSet::new();
            };
            (*files).clone()
        };
        files
            .iter()
            .filter(|file| crate::analyzer::common::has_unclaimed_extension(file))
            .cloned()
            .collect()
    }

    /// The import rows recorded for `files`, read from the store rather than
    /// re-parsed. Files whose state is dirty (a failed persist) answer from the
    /// dirty entry so a claim is not lost to a transient write failure.
    fn stored_import_facts(
        adapter: &A,
        store_context: &AnalyzerStoreContext,
        state: &AnalyzerRuntimeState,
        files: &[ProjectFile],
    ) -> Vec<(ProjectFile, Vec<ImportInfo>)> {
        let snapshot = store_context.live_paths.snapshot();
        let mut entries = Vec::with_capacity(files.len());
        let mut out = Vec::with_capacity(files.len());
        for file in files {
            let Some(oid) = snapshot.validated_oid_for_path(file) else {
                continue;
            };
            let storage_key = adapter.storage_language_key_for_file(file);
            let key = Self::transient_cache_key(oid, file);
            match state.dirty_imports(&key) {
                Some(imports) => out.push((file.clone(), imports)),
                None => entries.push((file.clone(), oid, storage_key.to_string())),
            }
        }
        if entries.is_empty() {
            return out;
        }
        for _ in &entries {
            store_context
                .build_tier_access
                .record_tier_access(InformationTier::Imports);
        }
        state.claim_import_reads.fetch_add(1, Ordering::Relaxed);
        let facts = store_context
            .store
            .hydrate_import_facts_by_key(&entries, store_context.generations.as_ref(), adapter)
            .unwrap_or_default();
        out.extend(facts.into_iter().map(|(file, facts)| (file, facts.imports)));
        out
    }

    /// The claim set implied by `edges`: every file in `claimable` reachable
    /// from an extension-discovered file of this adapter's language.
    ///
    /// Iterative worklist, never recursion -- an include chain is as deep as the
    /// workspace makes it. The result is a set keyed by file, so it does not
    /// depend on the order `edges` iterates in. Intersecting with `claimable`
    /// retires an edge whose target has left the workspace since the generation
    /// that recorded it.
    fn closed_claim_set(
        adapter: &A,
        edges: &HashMap<ProjectFile, BTreeSet<ProjectFile>>,
        claimable: &BTreeSet<ProjectFile>,
    ) -> BTreeSet<ProjectFile> {
        let mut claimed = BTreeSet::new();
        let mut worklist = Vec::new();
        let push_targets = |targets: &BTreeSet<ProjectFile>,
                            claimed: &mut BTreeSet<ProjectFile>,
                            worklist: &mut Vec<ProjectFile>| {
            for target in targets {
                if claimable.contains(target) && claimed.insert(target.clone()) {
                    worklist.push(target.clone());
                }
            }
        };
        for (source, targets) in edges {
            // Only an extension-discovered file seeds the closure. A claimed
            // file's own edges are followed when the closure reaches it, so a
            // cycle of unreferenced `.inc` files claims nothing.
            if crate::analyzer::common::language_for_file(source) != adapter.language() {
                continue;
            }
            push_targets(targets, &mut claimed, &mut worklist);
        }
        while let Some(file) = worklist.pop() {
            let Some(targets) = edges.get(&file) else {
                continue;
            };
            push_targets(targets, &mut claimed, &mut worklist);
        }
        claimed
    }

    /// Adopt the files this adapter's analyzed sources pull in and reconcile
    /// them exactly like extension-discovered files (#1837).
    ///
    /// `roots` are the files whose imports seed the relation -- the whole
    /// extension-discovered set on a build, only the changed files on an update.
    /// `retained` carries the previous generation's relation and its unresolved
    /// demand forward on an update and is empty on a build. `state` receives the
    /// merged reconcile results, the closed relation and the demand record.
    ///
    /// Cost: one bulk import-fact read per round over the frontier, no source
    /// reads. A build's first frontier is the whole extension-discovered set,
    /// which is why the imports come from the store the preceding reconcile just
    /// filled rather than from a second pass over the workspace's bytes. An
    /// update with no root pays nothing, which is what makes a created file
    /// that answers no recorded demand free (#1865).
    ///
    /// Returns the exact live-membership delta produced by claim inference.
    /// A full build treats the additions as indexed files; an incremental
    /// update refreshes relational workspace rows for both additions and
    /// removals.
    fn reconcile_claimed_files(
        project: &dyn Project,
        adapter: &A,
        config: &AnalyzerConfig,
        store_context: &AnalyzerStoreContext,
        roots: &[ProjectFile],
        retained: RetainedClaimRelation,
        state: &mut AnalyzerRuntimeState,
    ) -> ClaimMembershipDelta {
        let workspace_snapshot = store_context.workspace_snapshot.as_deref();
        let RetainedClaimRelation {
            edges: retained_edges,
            mut demand,
        } = retained;
        if !adapter.claims_included_files() {
            return ClaimMembershipDelta::default();
        }
        let _scope = profiling::scope(format!(
            "TreeSitterAnalyzer::{:?}::reconcile_claimed_files",
            adapter.language()
        ));
        let claimable = Self::claimable_workspace_files(project, workspace_snapshot);
        let previous_live_paths = store_context.live_paths.snapshot();
        let mut edges = retained_edges;
        // The roots' imports are read even when nothing is eligible today.
        // They used to be skipped in that case, but the round below is also
        // where the unresolved demand for this generation is recorded (#1865),
        // and that record is what decides whether a file created *tomorrow* can
        // be claimed: skipping it would leave a workspace whose only
        // unclaimed-extension file is the one about to be generated unable to
        // ever adopt it. The skipped case is a workspace with no non-source
        // file at all -- no README, no license -- which is one bulk read on a
        // build that already read every one of those files' bytes.
        let mut frontier: Vec<ProjectFile> = roots.to_vec();
        let mut visited: HashSet<ProjectFile> = roots.iter().cloned().collect();
        let mut claimed_files = Vec::new();
        // Fixpoint over the claim relation. Each round reads one frontier's
        // imports, reconciles whatever that frontier newly claims, and makes
        // those files the next frontier; the visited set bounds the loop by the
        // workspace file count.
        while !frontier.is_empty() {
            let sources = Self::stored_import_facts(adapter, store_context, state, &frontier);
            let round_edges = adapter.infer_claimed_files(&sources, &claimable);
            // Recorded from the same `sources` as the edges, in the same round,
            // so the demand record can never describe a generation the relation
            // does not (#1865).
            let round_demand = adapter.claim_demand(&sources);
            for source in &frontier {
                demand.clear_source(InformationTier::Imports, source);
            }
            for (source, keys) in round_demand {
                demand.set_source(InformationTier::Imports, source, keys);
            }
            debug_assert!(
                round_edges
                    .values()
                    .flatten()
                    .all(|target| claimable.contains(target)),
                "{:?} claimed files outside the claimable set: {:?}",
                adapter.language(),
                round_edges
                    .values()
                    .flatten()
                    .filter(|target| !claimable.contains(*target))
                    .collect::<Vec<_>>()
            );
            for source in &frontier {
                // An import-less source drops out of the relation: the removal
                // of its last claiming `#include` is what test 6 turns on.
                edges.remove(source);
            }
            edges.extend(round_edges);

            let closed = Self::closed_claim_set(adapter, &edges, &claimable);
            let unvisited = closed
                .into_iter()
                .filter(|file| visited.insert(file.clone()))
                .collect::<Vec<_>>();
            // The probe is a per-path listing scan, so its cost is the product of
            // this round's newly claimed files and the ignore rules. The span is
            // measured over the whole round rather than per file: it is the only
            // way to see the product, and "this set is small" below is the
            // assumption it exists to check.
            frontier = {
                let _scope = crate::profiling::scope_with(|| {
                    format!("claim.bifrostignore_probe[{} files]", unvisited.len())
                });
                unvisited
                    .into_iter()
                    // Applied here rather than to the whole claimable universe: this
                    // set is small, and the ignore probe is a per-path listing scan.
                    .filter(|file| !project.is_bifrostignored(file.rel_path()))
                    .collect()
            };
            if frontier.is_empty() {
                break;
            }
            frontier.sort();
            let round_state = Self::reconcile_file_states(
                project,
                adapter,
                config,
                store_context,
                ReconcileFileStates {
                    files: frontier.clone(),
                    // Additive: the extension-discovered pass already replaced
                    // the live path map, and a claimed file joins it.
                    replace_live_paths: false,
                    progress: None,
                    dirty_file_states: state.dirty_snapshot(),
                    dirty_path_symbol_rows: state.dirty_path_symbol_snapshot(),
                },
            );
            state.absorb(round_state);
            claimed_files.extend(
                frontier
                    .iter()
                    .filter(|file| previous_live_paths.oid_for_path(file).is_none())
                    .cloned(),
            );
        }
        let closed = Self::closed_claim_set(adapter, &edges, &claimable);
        // Files that were claimed by the previous generation's relation and are
        // not claimed by this one leave the analyzed set: drop their live paths
        // so the GC can collect their rows and no query serves them.
        let dropped: Vec<ProjectFile> = store_context
            .live_paths
            .snapshot()
            .all_paths()
            .filter(|file| crate::analyzer::common::has_unclaimed_extension(file))
            .filter(|file| !closed.contains(*file))
            .cloned()
            .collect();
        if !dropped.is_empty() {
            store_context.live_paths.remove(dropped.iter().cloned());
            if let Some(liveness) = store_context.liveness.as_ref() {
                liveness.remove_overlay_paths(dropped.iter().cloned());
            }
        }
        state.claim_edges = edges;
        state.tier_demand = demand;
        claimed_files.retain(|file| closed.contains(file));
        ClaimMembershipDelta {
            added: claimed_files,
            dropped,
        }
    }

    fn path_symbol_row(adapter: &A, file: &ProjectFile, blob_oid: Oid) -> Option<PathSymbolRow> {
        let unit = adapter.path_synthetic_module_unit(file)?;
        Some(PathSymbolRow {
            rel_path: crate::path_utils::rel_path_string(file),
            blob_oid,
            kind: unit.kind(),
            package_name: unit.package_name().to_string(),
            short_name: unit.short_name().to_string(),
            exact_fqn: unit.fq_name(),
            normalized_fqn: adapter.normalize_full_name(&unit.fq_name()),
        })
    }

    #[allow(clippy::type_complexity)]
    fn workspace_snapshot_relations(
        adapter: &A,
        entries: &[(ProjectFile, WorkspaceFileRow, Option<PathSymbolRow>)],
        facts: &[WorkspaceContentPackageFact],
    ) -> Result<
        (
            Vec<String>,
            Vec<WorkspacePackageFileRow>,
            Vec<WorkspacePackageEdgeRow>,
            Vec<WorkspaceAnchorRow>,
        ),
        StoreError,
    > {
        let interner = crate::analyzer::fq_name::segment_interner();
        let mut facts_by_blob: HashMap<Oid, Vec<&WorkspaceContentPackageFact>> = HashMap::default();
        for fact in facts {
            facts_by_blob.entry(fact.blob_oid).or_default().push(fact);
        }
        let mut packages = HashSet::default();
        let mut package_files: HashMap<(String, String), WorkspacePackageFileRow> =
            HashMap::default();
        let mut edges = HashSet::default();
        let mut anchors: HashMap<(String, PackageAnchor), WorkspaceAnchorRow> = HashMap::default();

        let mut record_package =
            |package: FqName, file: &WorkspaceFileRow| -> Result<(), StoreError> {
                let package_name = package.display_native(adapter.language(), interner);
                packages.insert(package_name.clone());
                package_files.insert(
                    (package_name.clone(), file.rel_path.clone()),
                    WorkspacePackageFileRow {
                        package_name,
                        rel_path: file.rel_path.clone(),
                    },
                );
                let mut child = package;
                while !child.is_empty() {
                    let parent = child
                        .parent()
                        .expect("a non-empty package has a structured parent");
                    let parent_name = parent.display_native(adapter.language(), interner);
                    let child_name = child.display_native(adapter.language(), interner);
                    packages.insert(parent_name.clone());
                    edges.insert((file.rel_path.clone(), parent_name, child_name));
                    child = parent;
                }
                Ok(())
            };

        for (project_file, file, _) in entries {
            if let Some(blob_facts) = facts_by_blob.get(&file.blob_oid) {
                for fact in blob_facts {
                    let full_package = if let Some(anchor) = fact.anchor {
                        let prefix = adapter
                            .resolve_package_anchor(
                                anchor,
                                &fact.content_qualifier,
                                project_file,
                            )
                            .ok_or_else(|| {
                                StoreError::new(format!(
                                    "adapter {:?} cannot resolve persisted anchor {anchor:?} for {}",
                                    adapter.language(),
                                    project_file.rel_path().display()
                                ))
                            })?;
                        let prefix_name = prefix.display_native(adapter.language(), interner);
                        let row = WorkspaceAnchorRow {
                            rel_path: file.rel_path.clone(),
                            anchor,
                            package_name: prefix_name,
                        };
                        if let Some(existing) =
                            anchors.insert((file.rel_path.clone(), anchor), row.clone())
                        {
                            assert_eq!(
                                existing, row,
                                "one file/anchor pair resolves to one package prefix"
                            );
                        }
                        let mut full = prefix;
                        full.extend_from(&fact.package_tail);
                        full
                    } else {
                        fact.package_tail.clone()
                    };
                    for alias in adapter.workspace_package_aliases(project_file, &full_package) {
                        record_package(alias, file)?;
                    }
                    record_package(full_package, file)?;
                }
            }
            if let Some(unit) = adapter.path_synthetic_module_unit(project_file) {
                let canonical = unit.package_fq();
                for alias in adapter.workspace_package_aliases(project_file, &canonical) {
                    record_package(alias, file)?;
                }
                record_package(canonical, file)?;
            }
        }

        let mut packages = packages.into_iter().collect::<Vec<_>>();
        packages.sort();
        let mut package_files = package_files.into_values().collect::<Vec<_>>();
        package_files.sort_by(|left, right| {
            left.package_name
                .cmp(&right.package_name)
                .then_with(|| left.rel_path.cmp(&right.rel_path))
        });
        let mut edges = edges
            .into_iter()
            .map(
                |(rel_path, parent_package_name, child_package_name)| WorkspacePackageEdgeRow {
                    rel_path,
                    parent_package_name,
                    child_package_name,
                },
            )
            .collect::<Vec<_>>();
        edges.sort();
        let mut anchors = anchors.into_values().collect::<Vec<_>>();
        anchors.sort();
        Ok((packages, package_files, edges, anchors))
    }

    fn sync_path_symbol_units(
        adapter: &A,
        files: &[ProjectFile],
        store_context: &AnalyzerStoreContext,
    ) -> (HashMap<ProjectFile, (String, PathSymbolRow)>, bool) {
        let snapshot = store_context.live_paths.snapshot();
        let mut rows_by_language: HashMap<
            String,
            Vec<(ProjectFile, WorkspaceFileRow, Option<PathSymbolRow>)>,
        > = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(lang, _)| (lang, Vec::new()))
            .collect();
        for file in files {
            let Some(blob_oid) = snapshot.validated_oid_for_path(file) else {
                continue;
            };
            let workspace_file = WorkspaceFileRow {
                rel_path: crate::path_utils::rel_path_string(file),
                blob_oid,
            };
            let path_symbol = Self::path_symbol_row(adapter, file, blob_oid);
            rows_by_language
                .entry(adapter.storage_language_key_for_file(file).to_string())
                .or_default()
                .push((file.clone(), workspace_file, path_symbol));
        }
        let mut dirty = HashMap::default();
        let mut package_inventory_complete = true;
        for (lang, entries) in rows_by_language {
            let files = entries
                .iter()
                .map(|(_, file, _)| file.clone())
                .collect::<Vec<_>>();
            let path_symbols = entries
                .iter()
                .filter_map(|(_, _, row)| row.clone())
                .collect::<Vec<_>>();
            let blob_oids = files.iter().map(|file| file.blob_oid).collect::<Vec<_>>();
            let relations = store_context.store.workspace_content_package_facts(
                &lang,
                store_context.generations[&lang],
                &blob_oids,
                adapter.workspace_file_package_anchor(),
            );
            let relations = relations.and_then(|facts| {
                package_inventory_complete &= facts.complete;
                Self::workspace_snapshot_relations(adapter, &entries, &facts.facts)
            });
            let mut persisted = false;
            if let Ok((packages, package_files, package_edges, anchors)) = relations {
                for attempt in 0..=STORE_WRITE_IMMEDIATE_RETRIES {
                    if store_context
                        .store
                        .sync_workspace_snapshot_for_workspace(
                            &store_context.workspace_id,
                            &lang,
                            store_context.generations[&lang],
                            &files,
                            &path_symbols,
                            &packages,
                            &package_files,
                            &package_edges,
                            &anchors,
                        )
                        .is_ok()
                    {
                        persisted = true;
                        break;
                    }
                    if attempt < STORE_WRITE_IMMEDIATE_RETRIES {
                        std::thread::sleep(Duration::from_millis(10 * (attempt + 1) as u64));
                    }
                }
            }
            if !persisted {
                package_inventory_complete = false;
                dirty.extend(
                    entries
                        .into_iter()
                        .filter_map(|(file, _, row)| row.map(|row| (file, (lang.clone(), row)))),
                );
            }
        }
        (dirty, package_inventory_complete)
    }

    /// Replace one storage language's complete workspace membership, including
    /// natural files and any additional content readings owned by this analyzer.
    ///
    /// A content reading is not a path-derived symbol mount and does not
    /// contribute package or anchor rows. Its definitions already carry
    /// content-stable structured names. C++ uses this for the distinct C
    /// reading of headers compiled by C translation units. The supplied set
    /// also includes ordinary `.c` files because snapshot replacement is
    /// atomic and complete. The ordinary
    /// `workspace_files` key naturally admits the same path once under `cpp`
    /// and once under `cpp:c`, so no parallel liveness relation is needed.
    pub(crate) fn sync_content_reading_workspace_files(
        &self,
        storage_lang: &str,
        files: &[ProjectFile],
    ) -> Result<(), StoreError> {
        let generation = self
            .store_context
            .generations
            .get(storage_lang)
            .copied()
            .ok_or_else(|| {
                StoreError::new(format!(
                    "analyzer does not own content-reading storage language {storage_lang}"
                ))
            })?;
        let snapshot = self.store_context.live_paths.snapshot();
        let rows = files
            .iter()
            .filter_map(|file| {
                snapshot
                    .validated_oid_for_path(file)
                    .map(|blob_oid| WorkspaceFileRow {
                        rel_path: crate::path_utils::rel_path_string(file),
                        blob_oid,
                    })
            })
            .collect::<Vec<_>>();

        let mut last_error = None;
        for attempt in 0..=STORE_WRITE_IMMEDIATE_RETRIES {
            match self
                .store_context
                .store
                .sync_workspace_snapshot_for_workspace(
                    &self.store_context.workspace_id,
                    storage_lang,
                    generation,
                    &rows,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                ) {
                Ok(snapshot) => {
                    let mut snapshots = self.selected_workspace_snapshots().as_ref().clone();
                    snapshots.insert(storage_lang.to_string(), snapshot);
                    self.relational_workspace_snapshots
                        .store(Arc::new(snapshots));
                    self.store_context.live_paths.replace_additional_mounts(
                        storage_lang,
                        files
                            .iter()
                            .filter(|file| {
                                self.adapter.storage_language_key_for_file(file) != storage_lang
                            })
                            .cloned(),
                    );
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
            if attempt < STORE_WRITE_IMMEDIATE_RETRIES {
                std::thread::sleep(Duration::from_millis(10 * (attempt + 1) as u64));
            }
        }
        Err(last_error.expect("at least one workspace snapshot write was attempted"))
    }

    fn refresh_path_symbol_units(
        adapter: &A,
        files: &BTreeSet<ProjectFile>,
        store_context: &AnalyzerStoreContext,
        workspace_snapshots: &mut WorkspaceSnapshots,
        dirty: &mut HashMap<ProjectFile, (String, PathSymbolRow)>,
        package_inventory_complete: &mut bool,
    ) {
        let storage_languages = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(lang, _)| lang)
            .collect::<Vec<_>>();
        let generations: HashMap<String, GenerationId> = storage_languages
            .iter()
            .map(|lang| (lang.clone(), store_context.generations[lang]))
            .collect();
        let snapshot = store_context.live_paths.snapshot();
        for file in files {
            dirty.remove(file);
            let rel_path = crate::path_utils::rel_path_string(file);
            let live_oid = snapshot.validated_oid_for_path(file);
            let file_replacement =
                live_oid.map(|oid| (adapter.storage_language_key_for_file(file), oid));
            let replacement = live_oid
                .and_then(|blob_oid| Self::path_symbol_row(adapter, file, blob_oid))
                .map(|row| (adapter.storage_language_key_for_file(file), row));
            let replacement_ref = replacement.as_ref().map(|&(lang, ref row)| (lang, row));
            let relations = if let Some((lang, blob_oid)) = file_replacement {
                let entry = (
                    file.clone(),
                    WorkspaceFileRow {
                        rel_path: rel_path.clone(),
                        blob_oid,
                    },
                    replacement.as_ref().map(|(_, row)| row.clone()),
                );
                store_context
                    .store
                    .workspace_content_package_facts(
                        lang,
                        generations[lang],
                        &[blob_oid],
                        adapter.workspace_file_package_anchor(),
                    )
                    .and_then(|facts| {
                        *package_inventory_complete &= facts.complete;
                        Self::workspace_snapshot_relations(adapter, &[entry], &facts.facts)
                    })
            } else {
                Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new()))
            };
            let mut persisted = false;
            if let Ok((packages, package_files, package_edges, anchors)) = relations {
                for attempt in 0..=STORE_WRITE_IMMEDIATE_RETRIES {
                    if let Ok(next) = store_context.store.replace_path_symbol_unit(
                        &store_context.workspace_id,
                        workspace_snapshots,
                        &storage_languages,
                        &generations,
                        &rel_path,
                        file_replacement,
                        replacement_ref,
                        &packages,
                        &package_files,
                        &package_edges,
                        &anchors,
                    ) {
                        workspace_snapshots.extend(next);
                        persisted = true;
                        break;
                    }
                    if attempt < STORE_WRITE_IMMEDIATE_RETRIES {
                        std::thread::sleep(Duration::from_millis(10 * (attempt + 1) as u64));
                    }
                }
            }
            if !persisted && let Some((lang, row)) = replacement {
                dirty.insert(file.clone(), (lang.to_string(), row));
            }
            *package_inventory_complete &= persisted;
        }
    }

    fn reconcile_file_states(
        project: &dyn Project,
        adapter: &A,
        config: &AnalyzerConfig,
        store_context: &AnalyzerStoreContext,
        input: ReconcileFileStates,
    ) -> AnalyzerRuntimeState {
        let ReconcileFileStates {
            files,
            replace_live_paths,
            progress,
            mut dirty_file_states,
            dirty_path_symbol_rows,
        } = input;
        // This pipeline parses and persists file STATES, so it only concerns
        // files this adapter's languages own. Change sets can legitimately
        // carry other files — java dependency discovery routes build-manifest
        // changes (pom.xml, build.gradle) through the analyzer update path for
        // invalidation, which happens elsewhere — and with per-file storage
        // keys (#1195) a foreign file would otherwise derive a key absent from
        // this adapter's generation map. Filter at the single entry instead of
        // guarding every downstream key derivation.
        let served_keys: HashSet<String> = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        let files: Vec<ProjectFile> = files
            .into_iter()
            .filter(|file| served_keys.contains(adapter.storage_language_key_for_file(file)))
            .collect();
        let mut fresh_parse_errors = HashMap::default();
        let mut seeded_file_states = Vec::new();
        let mut persistence_stats = PersistBatchStats::default();
        let mut workspace_package_inventory_complete = true;
        let oid_plan = {
            let _scope = profiling::scope("reconcile.resolve_live_oids");
            Self::resolve_live_oids(project, &files, store_context, replace_live_paths)
        };
        match oid_plan {
            Ok(file_oids) => {
                workspace_package_inventory_complete &= file_oids.len() == files.len();
                let all_blob_keys: Vec<_> = files
                    .iter()
                    .filter_map(|file| {
                        file_oids.get(file).map(|oid| {
                            (
                                *oid,
                                adapter.storage_language_key_for_file(file).to_string(),
                            )
                        })
                    })
                    .collect();
                let _missing_scope = profiling::scope("reconcile.find_missing_blobs");
                let missing_result = store_context
                    .store
                    .missing_published_parsed_blob_keys_at_generations(
                        &all_blob_keys,
                        store_context.generations.as_ref(),
                    );
                let missing = match missing_result {
                    Ok(missing) => missing,
                    Err(_) => {
                        let mut seen = HashSet::default();
                        all_blob_keys
                            .into_iter()
                            .filter(|key| seen.insert(key.clone()))
                            .collect()
                    }
                };
                let missing_blob_keys: HashSet<(Oid, String)> = missing.iter().cloned().collect();
                drop(_missing_scope);

                if let Some(progress) = progress.as_ref() {
                    progress(BuildProgressEvent::new(
                        adapter.language(),
                        BuildProgressPhase::Reconcile,
                        files.len().saturating_sub(missing_blob_keys.len()),
                        files.len(),
                        None,
                    ));
                }

                let mut representative_by_blob_key = HashMap::default();
                for file in &files {
                    let Some(oid) = file_oids.get(file).copied() else {
                        continue;
                    };
                    let storage_key = adapter.storage_language_key_for_file(file);
                    if missing_blob_keys.contains(&(oid, storage_key.to_string())) {
                        representative_by_blob_key
                            .entry((oid, storage_key.to_string()))
                            .or_insert_with(|| file.clone());
                    }
                }
                let parse_targets: Vec<_> = missing
                    .iter()
                    .map(|(oid, storage_key)| {
                        let file = representative_by_blob_key
                            .get(&(*oid, storage_key.clone()))
                            .expect("every missing blob key must have a representative")
                            .clone();
                        let generation = store_context.generations[storage_key];
                        (file, *oid, storage_key.clone(), generation)
                    })
                    .collect();
                let mut representative_blob_outcomes = HashMap::default();
                let mut parsed_files = HashSet::default();
                persistence_stats = Self::analyze_prepare_and_persist_files(
                    adapter,
                    project,
                    config,
                    parse_targets,
                    progress.clone(),
                    store_context,
                    |file, outcome| {
                        let Some(oid) = file_oids.get(&file).copied() else {
                            return;
                        };
                        let storage_key = adapter.storage_language_key_for_file(&file);
                        match outcome {
                            Some((state, error)) => {
                                workspace_package_inventory_complete &=
                                    error.is_none() && state.parse_complete;
                                let blob_outcome = if error.is_some() {
                                    RepresentativeBlobOutcome::Dirty
                                } else {
                                    RepresentativeBlobOutcome::Persisted
                                };
                                representative_blob_outcomes
                                    .insert((oid, storage_key.to_string()), blob_outcome);
                                let key = Self::transient_cache_key(oid, &file);
                                match error {
                                    Some(error) => {
                                        let status = dirty_file_state_status(&error);
                                        dirty_file_states.insert(
                                            key.clone(),
                                            Self::dirty_file_state(
                                                Arc::clone(&state),
                                                store_context.generations[storage_key],
                                                STORE_WRITE_IMMEDIATE_RETRIES + 1,
                                                error.to_string(),
                                                status,
                                            ),
                                        );
                                    }
                                    None => {
                                        dirty_file_states.remove(&key);
                                    }
                                }
                                if let Some(errors) = state.parse_errors.clone() {
                                    fresh_parse_errors.insert(file.clone(), errors);
                                }
                                if seeded_file_states.len()
                                    < SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY
                                {
                                    seeded_file_states.push((key, Arc::clone(&state)));
                                }
                                parsed_files.insert(file);
                            }
                            None => {
                                workspace_package_inventory_complete = false;
                                representative_blob_outcomes.insert(
                                    (oid, storage_key.to_string()),
                                    RepresentativeBlobOutcome::Unparseable,
                                );
                            }
                        }
                    },
                );

                // A sibling language panicked while this producer was active.
                // Its workers deliberately stop without manufacturing outcomes
                // for unclaimed targets. The whole delegate is about to be
                // discarded, so do not reinterpret those absent outcomes as a
                // reconcile invariant failure or continue into hydration.
                if store_context.build_abort.is_aborted() {
                    let mut state = AnalyzerRuntimeState::new(
                        fresh_parse_errors,
                        dirty_file_states,
                        dirty_path_symbol_rows,
                        seeded_file_states,
                    );
                    state.mark_workspace_package_inventory_incomplete();
                    state.persistence_stats = persistence_stats;
                    return state;
                }

                let mut hydrate_misses = Vec::new();
                for file in &files {
                    if parsed_files.contains(file) {
                        continue;
                    }
                    let Some(oid) = file_oids.get(file).copied() else {
                        continue;
                    };
                    let storage_key = adapter.storage_language_key_for_file(file);
                    let blob_key = (oid, storage_key.to_string());
                    if !missing_blob_keys.contains(&blob_key) {
                        continue;
                    }
                    match representative_blob_outcomes
                        .get(&blob_key)
                        .expect("every missing blob key must have a representative outcome")
                    {
                        RepresentativeBlobOutcome::Persisted
                        | RepresentativeBlobOutcome::Unparseable => {}
                        RepresentativeBlobOutcome::Dirty => hydrate_misses.push(file.clone()),
                    }
                }

                for (file, state) in Self::analyze_files(
                    adapter,
                    project,
                    config,
                    hydrate_misses,
                    progress,
                    store_context,
                ) {
                    let Some(state) = state else {
                        workspace_package_inventory_complete = false;
                        continue;
                    };
                    workspace_package_inventory_complete &= state.parse_complete;
                    let mut seed_key = None;
                    if let Some(oid) = file_oids.get(&file).copied() {
                        let storage_key = adapter.storage_language_key_for_file(&file);
                        let generation = store_context.generations[storage_key];
                        Self::persist_or_mark_dirty(
                            &mut dirty_file_states,
                            store_context,
                            adapter,
                            &file,
                            oid,
                            storage_key,
                            generation,
                            &state,
                        );
                        seed_key = Some(Self::transient_cache_key(oid, &file));
                    }
                    if let Some(errors) = state.parse_errors.clone() {
                        fresh_parse_errors.insert(file.clone(), errors);
                    }
                    if let Some(key) = seed_key
                        && seeded_file_states.len() < SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY
                    {
                        seeded_file_states.push((key, Arc::new(state)));
                    }
                }
            }
            Err(error) => {
                workspace_package_inventory_complete = false;
                profiling::note(format!(
                    "resolve_live_oids failed; reconciling {:?} without live identities: {error}",
                    adapter.language()
                ));
                for (file, state) in
                    Self::analyze_files(adapter, project, config, files, progress, store_context)
                {
                    let Some(state) = state else {
                        continue;
                    };
                    let seed_key = if let Ok(source) = project.read_source(&file)
                        && let Ok(oid) = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                    {
                        let storage_key = adapter.storage_language_key_for_file(&file);
                        let generation = store_context.generations[storage_key];
                        Self::persist_or_mark_dirty(
                            &mut dirty_file_states,
                            store_context,
                            adapter,
                            &file,
                            oid,
                            storage_key,
                            generation,
                            &state,
                        );
                        Some(Self::transient_cache_key(oid, &file))
                    } else {
                        None
                    };
                    if let Some(errors) = state.parse_errors.clone() {
                        fresh_parse_errors.insert(file.clone(), errors);
                    }
                    if let Some(key) = seed_key
                        && seeded_file_states.len() < SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY
                    {
                        seeded_file_states.push((key, Arc::new(state)));
                    }
                }
            }
        }

        let mut state = AnalyzerRuntimeState::new(
            fresh_parse_errors,
            dirty_file_states,
            dirty_path_symbol_rows,
            seeded_file_states,
        );
        if !workspace_package_inventory_complete {
            state.mark_workspace_package_inventory_incomplete();
        }
        state.persistence_stats = persistence_stats;
        state
    }

    fn source_snapshot_file_state(&self, file: &ProjectFile) -> Option<Arc<FileState>> {
        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        self.source_snapshot_file_states.get(&key).cloned()
    }

    /// The retained source text of an analyzed file. Structural search
    /// re-parses from this instead of touching disk.
    pub(crate) fn file_source(&self, file: &ProjectFile) -> Option<String> {
        if let Some(state) = self.source_snapshot_file_state(file) {
            return Some(state.source.clone());
        }
        if let Some(source) = self.analyzed_blob_source(file) {
            return Some(source);
        }
        self.fetch_file_state(file)
            .or_else(|| self.fetch_file_state_from_current_source(file))
            .map(|state| state.source.clone())
            .or_else(|| self.project.read_source(file).ok())
    }

    /// The analyzed blob's source text for `file`, without hydrating its
    /// parsed state.
    ///
    /// Every hydration path ends with `state.source = source_for_oid(file,
    /// oid)`, so the text a full fetch would hand back is exactly the blob
    /// this reads. Asking for the text through the fetch also pays a store
    /// transaction, unit-row and FQ-segment attachment, and a file-state cache
    /// insertion that evicts under a workspace-sized scan. A structural seed
    /// scan asks every file in the workspace for its source and then discards
    /// almost all of them on a literal prefilter, so that hydration was the
    /// whole cost of a warm `query_code` on this repository (#2642).
    ///
    /// `None` means the blob cannot answer and the caller must fall back:
    /// the file belongs to another adapter, a streaming read owns its state,
    /// no live blob identity exists, or the blob is unreadable.
    fn analyzed_blob_source(&self, file: &ProjectFile) -> Option<String> {
        let storage_key = self.adapter.storage_language_key_for_file(file);
        if !self.owns_storage_language_key(storage_key) {
            return None;
        }
        // A streaming read owns this file's state for the length of the read
        // and registers what it hydrates; leave that path to `fetch_file_state`.
        if self.streaming_file_read_active(file) {
            return None;
        }
        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.retry_dirty_file_state(&key, storage_key) {
            return Some(state.source.clone());
        }
        if let Some(state) = self.retained_file_state(&key) {
            return Some(state.source.clone());
        }
        self.source_for_oid(file, oid)
    }

    fn transient_cache_key(oid: Oid, file: &ProjectFile) -> FileStateCacheKey {
        FileStateCacheKey {
            oid,
            rel_path: file.rel_path().to_path_buf(),
        }
    }

    fn query_file_state_snapshot(&self, key: &FileStateCacheKey) -> Option<Arc<FileState>> {
        self.query_file_state_snapshot
            .load()
            .as_ref()
            .and_then(|snapshot| snapshot.get(key).cloned())
    }

    fn dirty_retry_delay(attempts: usize) -> Duration {
        let exponent = attempts.saturating_sub(1).min(7) as u32;
        let factor = 1u32 << exponent;
        STORE_WRITE_RETRY_BASE_DELAY
            .saturating_mul(factor)
            .min(STORE_WRITE_RETRY_MAX_DELAY)
    }

    fn dirty_file_state(
        state: Arc<FileState>,
        generation: GenerationId,
        attempts: usize,
        last_error: String,
        status: DirtyFileStateStatus,
    ) -> DirtyFileState {
        DirtyFileState {
            state,
            generation,
            attempts,
            next_retry_at: Instant::now() + Self::dirty_retry_delay(attempts),
            status,
            _last_error: last_error,
        }
    }

    fn write_parsed_blob_with_retries(
        store_context: &AnalyzerStoreContext,
        adapter: &A,
        oid: Oid,
        storage_key: &str,
        generation: GenerationId,
        state: &FileState,
    ) -> std::result::Result<usize, StoreError> {
        let mut last_error = None;
        for attempt in 1..=STORE_WRITE_IMMEDIATE_RETRIES + 1 {
            match store_context.store.write_parsed_blob_at_generation(
                oid,
                storage_key,
                generation,
                adapter,
                state,
            ) {
                Ok(()) => return Ok(attempt),
                Err(err) => {
                    let stale = err.is_stale_generation();
                    let resource_bound = err.is_resource_bound();
                    last_error = Some(err);
                    if stale || resource_bound {
                        break;
                    }
                    if attempt <= STORE_WRITE_IMMEDIATE_RETRIES {
                        std::thread::sleep(Duration::from_millis(10 * attempt as u64));
                    }
                }
            }
        }
        Err(last_error.expect("failed store write must retain its error"))
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_or_mark_dirty(
        dirty_file_states: &mut HashMap<FileStateCacheKey, DirtyFileState>,
        store_context: &AnalyzerStoreContext,
        adapter: &A,
        file: &ProjectFile,
        oid: Oid,
        storage_key: &str,
        generation: GenerationId,
        state: &FileState,
    ) {
        let key = Self::transient_cache_key(oid, file);
        match Self::write_parsed_blob_with_retries(
            store_context,
            adapter,
            oid,
            storage_key,
            generation,
            state,
        ) {
            Ok(_) => {
                dirty_file_states.remove(&key);
            }
            Err(err) => {
                let status = dirty_file_state_status(&err);
                dirty_file_states.insert(
                    key,
                    Self::dirty_file_state(
                        Arc::new(state.clone()),
                        generation,
                        STORE_WRITE_IMMEDIATE_RETRIES + 1,
                        err.to_string(),
                        status,
                    ),
                );
            }
        }
    }

    fn remove_dirty_for_file(
        dirty_file_states: &mut HashMap<FileStateCacheKey, DirtyFileState>,
        file: &ProjectFile,
    ) {
        let rel_path = file.rel_path();
        dirty_file_states.retain(|key, _| key.rel_path != rel_path);
    }

    fn retry_dirty_file_state(
        &self,
        key: &FileStateCacheKey,
        storage_key: &str,
    ) -> Option<Arc<FileState>> {
        let (state, generation) = {
            let dirty_file_states = self
                .state
                .dirty_file_states
                .lock()
                .expect("dirty file-state mutex poisoned");
            let dirty = dirty_file_states.get(key)?;
            if dirty.status != DirtyFileStateStatus::Retryable
                || Instant::now() < dirty.next_retry_at
            {
                return Some(Arc::clone(&dirty.state));
            }
            (Arc::clone(&dirty.state), dirty.generation)
        };

        // A bounded parse timeout intentionally retains a conservative state
        // for this analyzer snapshot. Retrying that same incomplete state can
        // never make it publishable; a later update or reopen must re-run the
        // parser against the unchanged source instead.
        if !state.parse_complete {
            return Some(state);
        }

        let repair = AnalyzerStore::prepare_parsed_blob(
            key.oid,
            storage_key,
            generation,
            self.adapter.as_ref(),
            Arc::clone(&state),
        )
        .and_then(|prepared| self.store_context.store.repair_prepared_blob(prepared));
        match repair {
            Ok(()) => {
                self.state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned")
                    .remove(key);
                self.transient_file_states
                    .lock()
                    .expect("transient file-state cache mutex poisoned")
                    .insert(key.clone(), Arc::clone(&state));
                Some(state)
            }
            Err(err) => {
                if !err.is_resource_bound() {
                    self.record_store_error(
                        err.clone().context("retrying a deferred parsed-blob write"),
                    );
                }
                let mut dirty_file_states = self
                    .state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned");
                if let Some(dirty) = dirty_file_states.get_mut(key) {
                    if err.is_stale_generation() {
                        dirty.status = DirtyFileStateStatus::TerminalStale;
                    } else if err.is_resource_bound() {
                        dirty.status = DirtyFileStateStatus::TerminalResourceBound;
                    }
                    dirty.attempts = dirty.attempts.saturating_add(1);
                    dirty.next_retry_at = Instant::now() + Self::dirty_retry_delay(dirty.attempts);
                    dirty._last_error = err.to_string();
                    return Some(Arc::clone(&dirty.state));
                }
                Some(state)
            }
        }
    }

    fn storage_language_keys_for_queries(&self) -> Vec<String> {
        self.adapter
            .storage_language_keys()
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    }

    fn owns_storage_language_key(&self, storage_key: &str) -> bool {
        self.adapter
            .storage_language_keys()
            .iter()
            .any(|(known, _)| known == storage_key)
    }

    /// The storage key and store generation this analyzer would serve `file`
    /// under, or `None` when `file` belongs to another language.
    ///
    /// [`LanguageAdapter::storage_language_key_for_file`] reports the FILE's
    /// own language rather than this adapter's, on purpose (see its doc), while
    /// `store_context.generations` is published once at construction from this
    /// adapter's own [`LanguageAdapter::storage_language_keys`]. The two agree
    /// only for files this analyzer owns, so a per-file query holding a foreign
    /// file must not index the map: that is the #1805 "no entry found for key"
    /// panic, hit by the Scala forward resolver, which asks its own analyzer
    /// about Java candidates on purpose
    /// (`ForwardScalaNameResolver::resolve_candidate_tier`), and reachable the
    /// same way from any multi-analyzer fan-out that asks every provider about
    /// an arbitrary file. This analyzer holds no rows for a file it never
    /// analyzed, so those callers answer empty instead.
    ///
    /// Construction-time paths do not need this: `reconcile_file_states` drops
    /// files outside its served keys at its single entry, and the sync and
    /// prefix-scan paths iterate the adapter's own declared keys.
    fn storage_key_and_generation(&self, file: &ProjectFile) -> Option<(String, GenerationId)> {
        let storage_key = self.adapter.storage_language_key_for_file(file);
        let generation = self.store_context.generations.get(storage_key).copied()?;
        Some((storage_key.to_string(), generation))
    }

    fn streaming_file_read_id(&self) -> usize {
        Arc::as_ptr(&self.adapter) as *const () as usize
    }

    fn begin_streaming_file_read(&self, file: &ProjectFile) {
        let id = self.streaming_file_read_id();
        STREAMING_FILE_READS.with(|reads| {
            let mut reads = reads.borrow_mut();
            match reads.get_mut(&id) {
                Some(active) => {
                    assert_eq!(
                        active.file, *file,
                        "nested streaming reads must use one file"
                    );
                    active.depth += 1;
                }
                None => {
                    reads.insert(
                        id,
                        StreamingFileRead {
                            depth: 1,
                            file: file.clone(),
                            state: None,
                        },
                    );
                }
            }
        });
        self.store_context.store.begin_streaming_read();
    }

    fn end_streaming_file_read(&self, file: &ProjectFile) {
        let id = self.streaming_file_read_id();
        STREAMING_FILE_READS.with(|reads| {
            let mut reads = reads.borrow_mut();
            let active = reads
                .get_mut(&id)
                .expect("streaming file read must be active");
            assert_eq!(active.file, *file, "streaming read ended for another file");
            active.depth = active
                .depth
                .checked_sub(1)
                .expect("streaming file read depth must be positive");
            if active.depth == 0 {
                reads.remove(&id);
            }
        });
        self.store_context.store.end_streaming_read();
    }

    fn streaming_file_read_active(&self, file: &ProjectFile) -> bool {
        let id = self.streaming_file_read_id();
        STREAMING_FILE_READS.with(|reads| {
            reads
                .borrow()
                .get(&id)
                .is_some_and(|active| active.file == *file)
        })
    }

    fn streaming_file_state(&self, file: &ProjectFile) -> Option<Arc<FileState>> {
        let id = self.streaming_file_read_id();
        if let Some(state) = STREAMING_FILE_READS.with(|reads| {
            reads
                .borrow()
                .get(&id)
                .and_then(|active| active.state.clone())
        }) {
            return Some(state);
        }

        let oid = self.resolve_live_oid_for_file(file)?;
        let (storage_key, generation) = self.storage_key_and_generation(file)?;
        self.full_hydration_count.fetch_add(1, Ordering::Relaxed);
        let source = self.source_for_oid(file, oid)?;
        let mut state = match self
            .store_query_or_record(
                |sink| sink.push(self.file_read_key(file, oid)),
                self.store_context.store.hydrate_file_state_with_source(
                    oid,
                    &storage_key,
                    generation,
                    self.adapter.as_ref(),
                    file,
                    &source,
                ),
                format!("streaming file-state hydration for `{file}`"),
            )
            .flatten()
        {
            Some(state) => state,
            None => self.parse_and_store_transient(file, oid, source.clone())?,
        };
        state.source = source;
        let state = Arc::new(state);
        STREAMING_FILE_READS.with(|reads| {
            let mut reads = reads.borrow_mut();
            let active = reads
                .get_mut(&id)
                .expect("streaming file read must remain active during hydration");
            assert_eq!(active.file, *file);
            active.state = Some(Arc::clone(&state));
        });
        Some(state)
    }

    pub(crate) fn fetch_file_state(&self, file: &ProjectFile) -> Option<Arc<FileState>> {
        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        self.fetch_file_state_for_key(file, &key)
    }

    /// The second reading of `file`'s blob stored under `storage_key`, when
    /// this adapter wrote one (see
    /// [`LanguageAdapter::parse_file_with_projections`]).
    ///
    /// `None` means no rows exist under that key for this blob, which by that
    /// method's contract means the reading is identical to the file's own
    /// row-set -- so a caller falls back to [`Self::fetch_file_state`] rather
    /// than treating the absence as an error.
    ///
    /// Deliberately not routed through the file-state caches: those are keyed
    /// by `(oid, path)` alone, which is exactly the identity a projection
    /// shares with the primary reading. The caller memoizes instead, on the
    /// analyzer that knows when a projection is worth asking for at all.
    pub(crate) fn projection_file_state(
        &self,
        file: &ProjectFile,
        storage_key: &str,
    ) -> Option<Arc<FileState>> {
        let generation = self.store_context.generations.get(storage_key).copied()?;
        let oid = self.resolve_live_oid_for_file(file)?;
        let source = self.source_for_oid(file, oid)?;
        self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context.store.hydrate_file_state_with_source(
                oid,
                storage_key,
                generation,
                self.adapter.as_ref(),
                file,
                &source,
            ),
            format!("hydrating the `{storage_key}` projection of `{file}`"),
        )
        .flatten()
        .map(Arc::new)
    }

    fn current_source(&self, file: &ProjectFile) -> Option<String> {
        let sources = self.active_query_cache_handle(|cache| &cache.current_sources);
        if let Some(sources) = sources.as_ref()
            && let Some(source) = sources
                .read()
                .expect("query current-source cache read lock poisoned")
                .get(file)
                .cloned()
        {
            return source;
        }
        let source = self.project.read_source(file).ok();
        if let Some(sources) = sources {
            sources
                .write()
                .expect("query current-source cache write lock poisoned")
                .insert(file.clone(), source.clone());
        }
        source
    }

    fn structural_file_state(&self, file: &ProjectFile) -> Option<Arc<FileState>> {
        let indexed = self
            .source_snapshot_file_state(file)
            .or_else(|| self.fetch_file_state(file));
        let Some(source) = self.current_source(file) else {
            return indexed.or_else(|| self.fetch_file_state_from_current_source(file));
        };
        self.fetch_file_state_from_source(file, source).or(indexed)
    }

    fn fetch_file_state_from_source(
        &self,
        file: &ProjectFile,
        source: String,
    ) -> Option<Arc<FileState>> {
        let oid = self.blob_oid_of(file, &source);
        let key = Self::transient_cache_key(oid, file);
        self.fetch_file_state_for_key_with_source(file, &key, Some(&source))
    }

    fn fetch_file_state_from_current_source(&self, file: &ProjectFile) -> Option<Arc<FileState>> {
        self.current_source(file)
            .and_then(|source| self.fetch_file_state_from_source(file, source))
    }

    /// The declaration-materialization provenance recorded for `file` by its
    /// language walk (issue #1476). Empty when the file has none or is not
    /// analyzed here.
    pub(crate) fn materialization_records_of(
        &self,
        file: &ProjectFile,
    ) -> Vec<MaterializationRecord> {
        self.fetch_file_state(file)
            .map(|state| state.materialization_records.clone())
            .unwrap_or_default()
    }

    fn fetch_file_state_for_key(
        &self,
        file: &ProjectFile,
        key: &FileStateCacheKey,
    ) -> Option<Arc<FileState>> {
        self.fetch_file_state_for_key_with_source(file, key, None)
    }

    /// `key`'s already-materialized state, from the query snapshot, the query
    /// read cache, or the transient cache. `None` means answering would cost a
    /// full hydration.
    fn retained_file_state(&self, key: &FileStateCacheKey) -> Option<Arc<FileState>> {
        if let Some(state) = self.query_file_state_snapshot(key) {
            return Some(state);
        }
        let file_states = self.active_query_cache_handle(|cache| &cache.file_states);
        if let Some(file_states) = file_states.as_ref()
            && let Some(state) = file_states
                .read()
                .expect("query file-state cache read lock poisoned")
                .get(key)
        {
            return Some(state);
        }
        let state = self
            .transient_file_states
            .lock()
            .expect("transient file-state cache mutex poisoned")
            .get(key)?;
        if let Some(file_states) = file_states.as_ref() {
            let mut file_states = file_states
                .write()
                .expect("query file-state cache write lock poisoned");
            file_states.retain(key.clone(), Arc::clone(&state));
        }
        Some(state)
    }

    fn fetch_file_state_for_key_with_source(
        &self,
        file: &ProjectFile,
        key: &FileStateCacheKey,
        exact_source: Option<&str>,
    ) -> Option<Arc<FileState>> {
        let storage_key = self.adapter.storage_language_key_for_file(file);
        // A file outside this adapter's own languages has no state here, and
        // must not acquire one: multi-analyzer fan-outs (e.g.
        // `ImportAnalysisProvider::referencing_files_of`) legitimately ask
        // every provider about arbitrary files. Without this refusal the
        // adapter would parse the foreign file as its own language — the
        // #1189 panic chain, where a rust hierarchy probe parsed a C++
        // header as rust and built a mixed-provenance `CodeUnit` — or, now
        // that `storage_language_key_for_file` derives the key from the
        // file itself (#1195), index a foreign key absent from
        // `store_context.generations`. Answer honestly: no state.
        if !self.owns_storage_language_key(storage_key) {
            return None;
        }
        if let Some(state) = self.retry_dirty_file_state(key, storage_key) {
            return Some(state);
        }
        if exact_source.is_none() && self.streaming_file_read_active(file) {
            return self.streaming_file_state(file);
        }
        if let Some(state) = self.retained_file_state(key) {
            return Some(state);
        }

        self.full_hydration_count.fetch_add(1, Ordering::Relaxed);
        let source = match exact_source {
            Some(source) => source.to_owned(),
            None => self.source_for_oid(file, key.oid)?,
        };
        let mut state = match self
            .store_query_or_record(
                |sink| sink.push(self.file_read_key(file, key.oid)),
                self.store_context.store.hydrate_file_state_with_source(
                    key.oid,
                    storage_key,
                    self.store_context.generations[storage_key],
                    self.adapter.as_ref(),
                    file,
                    &source,
                ),
                format!("hydrating file state for `{file}`"),
            )
            .flatten()
        {
            Some(state) => state,
            None => self.parse_and_store_transient(file, key.oid, source.clone())?,
        };
        state.source = source;
        let state = Arc::new(state);
        self.transient_file_states
            .lock()
            .expect("transient file-state cache mutex poisoned")
            .insert(key.clone(), Arc::clone(&state));
        if let Some(file_states) = self.active_query_cache_handle(|cache| &cache.file_states) {
            let mut file_states = file_states
                .write()
                .expect("query file-state cache write lock poisoned");
            file_states.retain(key.clone(), Arc::clone(&state));
        }
        Some(state)
    }

    fn prepared_syntax_cache_cell(
        &self,
        key: PreparedSyntaxCacheKey,
    ) -> Option<Arc<OnceLock<Option<Arc<PreparedSyntaxTree>>>>> {
        let prepared_syntax = self.active_query_cache_handle(|cache| &cache.prepared_syntax)?;
        if let Some(cell) = prepared_syntax
            .read()
            .expect("query prepared-syntax cache read lock poisoned")
            .get(&key)
            .cloned()
        {
            return Some(cell);
        }
        let mut prepared_syntax = prepared_syntax
            .write()
            .expect("query prepared-syntax cache write lock poisoned");
        if let Some(cell) = prepared_syntax.get(&key) {
            return Some(Arc::clone(cell));
        }
        if prepared_syntax.len() >= QUERY_PREPARED_SYNTAX_CACHE_CAPACITY {
            return None;
        }
        let cell = Arc::new(OnceLock::new());
        prepared_syntax.insert(key, Arc::clone(&cell));
        Some(cell)
    }

    /// The parsed tree and its source backing for `file`, from the query read
    /// cache.
    ///
    /// The [`QueryToken`] is proof that an [`AnalyzerQueryScope`] is open
    /// somewhere up the stack, so the memoization this reads is active and the
    /// call is a cache probe rather than a re-parse (issue #2414 step 3). The
    /// token carries no data; it is a compile-time obligation only.
    pub(crate) fn prepared_syntax(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<PreparedSyntaxTree>> {
        self.prepared_indexed_syntax(_token, file)
    }

    /// Capture the same request-scoped atomic source used by syntax
    /// preparation without parsing it. Semantic freshness checks need the
    /// source identity, but not a tree.
    pub(crate) fn source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<(Oid, ProjectSourceSnapshot)>, PreparedSyntaxLimitExceeded> {
        self.resolve_prepared_source(file, Some(max_source_bytes))
            .map(|resolved| resolved.map(|resolved| (resolved.oid, resolved.snapshot)))
    }

    /// Prepare syntax from one atomically captured project source snapshot,
    /// refusing snapshots larger than `max_source_bytes` before parsing.
    pub(crate) fn prepared_syntax_limited(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<(Oid, Arc<PreparedSyntaxTree>)>, PreparedSyntaxLimitExceeded> {
        match self.prepared_syntax_limited_cancellable(_token, file, max_source_bytes, None) {
            PreparedSyntaxLimitedOutcome::Available(oid, prepared) => Ok(Some((oid, prepared))),
            PreparedSyntaxLimitedOutcome::Exceeded(exceeded) => Err(exceeded),
            PreparedSyntaxLimitedOutcome::Cancelled => {
                unreachable!("no cancellation token supplied")
            }
            PreparedSyntaxLimitedOutcome::Unavailable => Ok(None),
        }
    }

    pub(crate) fn prepared_syntax_limited_cancellable(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> PreparedSyntaxLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return PreparedSyntaxLimitedOutcome::Cancelled;
        }
        let resolved = match self.resolve_prepared_source(file, Some(max_source_bytes)) {
            Ok(Some(resolved)) => resolved,
            Ok(None) => return PreparedSyntaxLimitedOutcome::Unavailable,
            Err(exceeded) => return PreparedSyntaxLimitedOutcome::Exceeded(exceeded),
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return PreparedSyntaxLimitedOutcome::Cancelled;
        }
        self.record_reads(|sink| sink.push(self.file_read_key(file, resolved.oid)));

        let key = Self::transient_cache_key(resolved.oid, file);
        let (origin, overlay_revision) = match resolved.snapshot.origin() {
            ProjectSourceOrigin::Disk => (PreparedSourceOrigin::Disk, None),
            ProjectSourceOrigin::Overlay(revision) => {
                (PreparedSourceOrigin::Overlay, Some(revision))
            }
        };
        let prepared_key = PreparedSyntaxCacheKey {
            file_state: key.clone(),
            origin,
            overlay_revision,
            flavor: PreparedSyntaxCacheFlavor::ExactSource,
        };
        let cell = self.prepared_syntax_cache_cell(prepared_key.clone());
        if let Some(cached) = cell.as_ref().and_then(|cell| cell.get()).cloned() {
            return cached.map_or(PreparedSyntaxLimitedOutcome::Unavailable, |prepared| {
                PreparedSyntaxLimitedOutcome::Available(resolved.oid, prepared)
            });
        }
        if let Some(retained) = self.prepared_syntax_store_get(&prepared_key) {
            if let Some(cell) = &cell {
                let _ = cell.set(Some(Arc::clone(&retained)));
            }
            return PreparedSyntaxLimitedOutcome::Available(resolved.oid, retained);
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return PreparedSyntaxLimitedOutcome::Cancelled;
        }

        let oid = resolved.oid;
        let prepared = match self.prepare_exact_syntax_cancellable(
            file,
            origin,
            overlay_revision,
            resolved.snapshot.into_source(),
            cancellation,
        ) {
            PreparedSyntaxPreparation::Complete(prepared) => prepared,
            PreparedSyntaxPreparation::Cancelled => {
                return PreparedSyntaxLimitedOutcome::Cancelled;
            }
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return PreparedSyntaxLimitedOutcome::Cancelled;
        }

        // A cancelled parse is deliberately never stored. Completed parse
        // failures retain the existing negative-cache behavior. If another
        // request won the race, its coherent result is authoritative.
        let prepared = if let Some(cell) = cell {
            let _ = cell.set(prepared.clone());
            cell.get().cloned().unwrap_or(prepared)
        } else {
            prepared
        };
        self.prepared_syntax_store_retain(prepared_key, prepared.as_ref());
        prepared.map_or(PreparedSyntaxLimitedOutcome::Unavailable, |prepared| {
            PreparedSyntaxLimitedOutcome::Available(oid, prepared)
        })
    }

    fn prepared_syntax_store_get(
        &self,
        key: &PreparedSyntaxCacheKey,
    ) -> Option<Arc<PreparedSyntaxTree>> {
        self.prepared_syntax_store
            .lock()
            .expect("prepared syntax store mutex poisoned")
            .get(key)
    }

    fn prepared_syntax_store_retain(
        &self,
        key: PreparedSyntaxCacheKey,
        prepared: Option<&Arc<PreparedSyntaxTree>>,
    ) {
        let Some(prepared) = prepared else {
            return;
        };
        self.prepared_syntax_store
            .lock()
            .expect("prepared syntax store mutex poisoned")
            .retain(key, Arc::clone(prepared));
    }

    fn prepared_indexed_syntax(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<PreparedSyntaxTree>> {
        let resolved = self.resolve_prepared_source(file, None).ok().flatten()?;
        // Recorded before the per-request cell answers, so a syntax read that
        // a memo serves still names the blob it was derived from.
        self.record_reads(|sink| sink.push(self.file_read_key(file, resolved.oid)));
        let key = Self::transient_cache_key(resolved.oid, file);
        let (origin, overlay_revision) = match resolved.snapshot.origin() {
            ProjectSourceOrigin::Disk => (PreparedSourceOrigin::Disk, None),
            ProjectSourceOrigin::Overlay(revision) => {
                (PreparedSourceOrigin::Overlay, Some(revision))
            }
        };
        let prepared_key = PreparedSyntaxCacheKey {
            file_state: key.clone(),
            origin,
            overlay_revision,
            flavor: PreparedSyntaxCacheFlavor::Indexed,
        };
        let cell = self.prepared_syntax_cache_cell(prepared_key.clone());
        let Some(cell) = cell else {
            return self.retained_or_prepared_syntax_for_key(
                prepared_key,
                file,
                &key,
                origin,
                overlay_revision,
                resolved.snapshot.source(),
            );
        };
        cell.get_or_init(|| {
            self.retained_or_prepared_syntax_for_key(
                prepared_key,
                file,
                &key,
                origin,
                overlay_revision,
                resolved.snapshot.source(),
            )
        })
        .clone()
    }

    /// Read-through against the cross-request store, which sits behind the
    /// per-request single-flight cell: hydrating and parsing is the cost #1450
    /// exists to stop repeating.
    fn retained_or_prepared_syntax_for_key(
        &self,
        prepared_key: PreparedSyntaxCacheKey,
        file: &ProjectFile,
        key: &FileStateCacheKey,
        origin: PreparedSourceOrigin,
        overlay_revision: Option<OverlayRevision>,
        exact_source: &str,
    ) -> Option<Arc<PreparedSyntaxTree>> {
        if let Some(retained) = self.prepared_syntax_store_get(&prepared_key) {
            return Some(retained);
        }
        let prepared =
            self.prepare_syntax_for_key(file, key, origin, overlay_revision, exact_source);
        self.prepared_syntax_store_retain(prepared_key, prepared.as_ref());
        prepared
    }

    fn prepare_syntax_for_key(
        &self,
        file: &ProjectFile,
        key: &FileStateCacheKey,
        origin: PreparedSourceOrigin,
        overlay_revision: Option<OverlayRevision>,
        exact_source: &str,
    ) -> Option<Arc<PreparedSyntaxTree>> {
        let file_state =
            self.fetch_file_state_for_key_with_source(file, key, Some(exact_source))?;
        match self.prepare_syntax_from_source_cancellable(
            file,
            PreparedSyntaxSource::Indexed(file_state),
            origin,
            overlay_revision,
            None,
        ) {
            PreparedSyntaxPreparation::Complete(prepared) => prepared,
            PreparedSyntaxPreparation::Cancelled => unreachable!("no cancellation token supplied"),
        }
    }

    fn prepare_exact_syntax_cancellable(
        &self,
        file: &ProjectFile,
        origin: PreparedSourceOrigin,
        overlay_revision: Option<OverlayRevision>,
        exact_source: Arc<str>,
        cancellation: Option<&CancellationToken>,
    ) -> PreparedSyntaxPreparation {
        self.prepare_syntax_from_source_cancellable(
            file,
            PreparedSyntaxSource::Exact(exact_source),
            origin,
            overlay_revision,
            cancellation,
        )
    }

    fn prepare_syntax_from_source_cancellable(
        &self,
        file: &ProjectFile,
        source: PreparedSyntaxSource,
        origin: PreparedSourceOrigin,
        overlay_revision: Option<OverlayRevision>,
        cancellation: Option<&CancellationToken>,
    ) -> PreparedSyntaxPreparation {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return PreparedSyntaxPreparation::Cancelled;
        }
        let mut parser = Parser::new();
        if !set_parser_for_file(&mut parser, self.adapter.as_ref(), file, source.source()) {
            return PreparedSyntaxPreparation::Complete(None);
        }
        self.record_file_tier_access(InformationTier::Syntax, file);
        let exact_source = source.source();
        let tree = match parse_complete_file_bounded(
            &mut parser,
            exact_source,
            cancellation,
            COMPLETE_FILE_PARSE_BUDGET,
        ) {
            BoundedParse::Complete(tree) => tree,
            BoundedParse::Cancelled => return PreparedSyntaxPreparation::Cancelled,
            BoundedParse::TimedOut | BoundedParse::Rejected => {
                return PreparedSyntaxPreparation::Complete(None);
            }
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return PreparedSyntaxPreparation::Cancelled;
        }
        let line_starts = compute_line_starts(exact_source);
        PreparedSyntaxPreparation::Complete(Some(Arc::new(PreparedSyntaxTree::new(
            source,
            tree,
            line_starts,
            LanguageDialect::for_path(self.adapter.language(), file.rel_path()),
            origin,
            overlay_revision,
        ))))
    }

    /// One crossing of `tier`'s storage funnel, attributed to `file`.
    fn record_file_tier_access(&self, tier: InformationTier, file: &ProjectFile) {
        *self
            .tier_access_counts
            .lock()
            .expect("tier access count mutex poisoned")
            .entry((tier, file.clone()))
            .or_default() += 1;
        self.record_tier_access(tier);
    }

    /// One crossing of `tier`'s storage funnel, counted for this analyzer and
    /// for every query scope that is open around it, and returning the new
    /// analyzer-wide total.
    ///
    /// The active contexts are cloned out from under the coarse
    /// `query_read_cache` read lock before they are touched, exactly as
    /// `record_store_error` does, so this adds no lock-order edge: the
    /// per-file map's mutex is never held while the cache lock is.
    fn record_tier_access(&self, tier: InformationTier) -> usize {
        let total = self.tier_access_totals[tier.index()].fetch_add(1, Ordering::Relaxed) + 1;
        let contexts = self.query_read_cache_lock().contexts.clone();
        for context in contexts {
            context.record_tier_access(tier);
        }
        total
    }

    /// Whether any open request boundary carries a read ledger.
    ///
    /// Read relaxed and consulted before any key is built: a run with no
    /// ledger must pay one load and allocate nothing.
    pub(crate) fn read_ledger_attached(&self) -> bool {
        self.attached_read_ledgers.load(Ordering::Relaxed) > 0
    }

    /// Record the inputs `build` names on every read ledger open around this
    /// analyzer, and nothing at all when none is.
    ///
    /// The active contexts are cloned out from under the coarse
    /// `query_read_cache` read lock before they are touched, exactly as
    /// `record_tier_access` and `record_store_error` do, so this adds no
    /// lock-order edge.
    pub(crate) fn record_reads(&self, build: impl FnOnce(&mut ReadKeySink<'_>)) {
        if !self.read_ledger_attached() {
            return;
        }
        let contexts = self.query_read_cache_lock().contexts.clone();
        let mut sink = ReadKeySink {
            contexts: &contexts,
        };
        build(&mut sink);
    }

    /// Record one already-built input. Callers that can avoid building the key
    /// use [`Self::record_reads`] instead.
    pub(crate) fn record_read_key(&self, key: crate::analyzer::read_ledger::ReadKey) {
        self.record_reads(move |sink| sink.push(key));
    }

    /// Record one crossing this analyzer could not name, on every ledger open
    /// around it. Broadcast exactly as [`Self::record_reads`] is, and just as
    /// free when no ledger is attached.
    pub(crate) fn record_unattributed_read(&self) {
        if !self.read_ledger_attached() {
            return;
        }
        let contexts = self.query_read_cache_lock().contexts.clone();
        for context in contexts {
            context.record_unattributed_read();
        }
    }

    /// The [`ReadKey::File`] naming `file`'s blob as this adapter reads it.
    pub(crate) fn file_read_key(
        &self,
        file: &ProjectFile,
        blob: Oid,
    ) -> crate::analyzer::read_ledger::ReadKey {
        crate::analyzer::read_ledger::ReadKey::file(
            self.adapter.language(),
            crate::path_utils::rel_path_string(file),
            blob,
        )
    }

    /// The [`ReadKey::File`] naming the exact source string a funnel is about
    /// to read facts from, whose blob identity is the hash of those bytes --
    /// the same identity [`Self::structural_snapshot_key`] persists under.
    pub(crate) fn source_file_read_key(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::read_ledger::ReadKey {
        self.file_read_key(file, self.blob_oid_of(file, source))
    }

    /// The [`ReadKey::Scope`] naming this analyzer's whole analyzed file set,
    /// for a read that no name or file can bound (a prefix, suffix, or pattern
    /// search over the name index; a workspace enumeration).
    pub(crate) fn scope_read_key(&self) -> crate::analyzer::read_ledger::ReadKey {
        IAnalyzer::workspace_scope_read_key(self, &[self.adapter.language()])
    }

    /// How many times `file` crossed `tier`'s funnel since the last reset.
    #[doc(hidden)]
    pub fn tier_access_count_for_test(&self, tier: InformationTier, file: &ProjectFile) -> usize {
        self.tier_access_counts
            .lock()
            .expect("tier access count mutex poisoned")
            .get(&(tier, file.clone()))
            .copied()
            .unwrap_or_default()
    }

    /// How many times `tier`'s funnel was crossed at all since the last reset.
    #[doc(hidden)]
    pub fn tier_access_total_for_test(&self, tier: InformationTier) -> usize {
        self.tier_access_totals[tier.index()].load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_tier_access_counts_for_test(&self) {
        self.tier_access_counts
            .lock()
            .expect("tier access count mutex poisoned")
            .clear();
        for total in self.tier_access_totals.iter() {
            total.store(0, Ordering::Relaxed);
        }
    }

    #[doc(hidden)]
    pub fn reset_tier_access_count_for_test(&self, tier: InformationTier) {
        self.tier_access_counts
            .lock()
            .expect("tier access count mutex poisoned")
            .retain(|(counted, _), _| *counted != tier);
        self.tier_access_totals[tier.index()].store(0, Ordering::Relaxed);
    }

    /// How many times `file` has been parsed since the last reset. Pins the
    /// per-query parse budget: a scan must parse each candidate file once, not
    /// once per candidate declaration it inspects.
    #[doc(hidden)]
    pub fn prepared_syntax_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.tier_access_count_for_test(InformationTier::Syntax, file)
    }

    #[doc(hidden)]
    pub fn reset_prepared_syntax_parse_counts_for_test(&self) {
        self.reset_tier_access_count_for_test(InformationTier::Syntax);
    }

    fn bulk_file_state_entries(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) -> HashMap<ProjectFile, (FileStateCacheKey, FileState)> {
        let live = self.live_snapshot();
        let mut entries = Vec::new();
        let mut seen = HashSet::default();
        for file in files {
            if !self.adapter_owns_file(&file, &live) {
                continue;
            }
            if !seen.insert(file.clone()) {
                continue;
            }
            let Some(oid) = self.resolve_live_oid_for_file(&file) else {
                continue;
            };
            let storage_key = self.adapter.storage_language_key_for_file(&file);
            entries.push((file, oid, storage_key.to_string()));
        }
        if entries.is_empty() {
            return HashMap::default();
        }

        let mut out = HashMap::default();
        let mut clean_entries = Vec::new();
        for (file, oid, storage_key) in entries {
            let key = Self::transient_cache_key(oid, &file);
            if let Some(state) = self.retry_dirty_file_state(&key, &storage_key) {
                out.insert(file, (key, state.as_ref().clone()));
            } else if live.is_overlay_path(&file)
                && let Some(state) = self
                    .transient_file_states
                    .lock()
                    .expect("transient file-state cache mutex poisoned")
                    .get(&key)
            {
                // Persisted FileState hydration deliberately omits source
                // text. That is correct for disk-backed files, whose source
                // can be read independently, but an overlay's parsed state is
                // the only authoritative source-and-facts pair for this
                // frozen generation. Keep ordinary workspace bulk reads
                // SQL-first while preserving that bounded overlay state.
                out.insert(file, (key, state.as_ref().clone()));
            } else {
                clean_entries.push((file, oid, storage_key.to_string()));
            }
        }
        let entries = clean_entries;
        if entries.is_empty() {
            return out;
        }

        let mut source_by_file = HashMap::default();
        if source_mode == BulkFileStateSource::Include {
            for (file, oid, _) in &entries {
                if let Some(source) = self.source_for_oid(file, *oid) {
                    source_by_file.insert(file.clone(), source);
                }
            }
        }

        let mut states = self
            .store_query_or_record(
                |sink| {
                    for (file, oid, _) in &entries {
                        sink.push(self.file_read_key(file, *oid));
                    }
                },
                self.store_context.store.hydrate_file_states_by_key(
                    &entries,
                    self.store_context.generations.as_ref(),
                    self.adapter.as_ref(),
                    &source_by_file,
                ),
                "hydrating file states",
            )
            .unwrap_or_default();
        self.bulk_hydration_count
            .fetch_add(states.len(), Ordering::Relaxed);
        for (file, oid, _) in entries {
            let key = Self::transient_cache_key(oid, &file);
            let state = states.remove(&file).or_else(|| {
                self.source_for_oid(&file, oid)
                    .and_then(|source| self.parse_and_store_transient(&file, oid, source))
            });
            if let Some(state) = state {
                out.insert(file, (key, state));
            }
        }
        out
    }

    pub(crate) fn bulk_file_states(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) -> HashMap<ProjectFile, FileState> {
        self.bulk_file_state_entries(files, source_mode)
            .into_iter()
            .map(|(file, (_, state))| (file, state))
            .collect()
    }

    /// Bulk-hydrate a request's fixed file set and publish the keyed states as
    /// an immutable snapshot for hot fetch/range lookups. The captured inner
    /// cache handle and outer-scope pointer check prevent a slow hydration from
    /// publishing into a later query generation.
    pub(crate) fn bulk_file_states_for_query(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) {
        let Some(query_file_states) = self.active_query_cache_handle(|cache| &cache.file_states)
        else {
            return;
        };
        let entries = self.bulk_file_state_entries(
            files.into_iter().take(BULK_FILE_STATE_QUERY_LIMIT),
            source_mode,
        );
        let mut snapshot = map_with_capacity(entries.len());
        let mut file_states = query_file_states
            .write()
            .expect("query file-state cache write lock poisoned");
        for (_, (key, state)) in entries {
            let state = Arc::new(state);
            if file_states.retain(key.clone(), Arc::clone(&state)) {
                snapshot.insert(key, state);
            }
        }
        drop(file_states);
        let cache = self.query_read_cache_lock();
        if cache.is_active() && Arc::ptr_eq(&query_file_states, &cache.file_states) {
            self.query_file_state_snapshot
                .store(Some(Arc::new(snapshot)));
        }
    }

    pub(crate) fn bulk_import_infos(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
    ) -> HashMap<ProjectFile, Vec<ImportInfo>> {
        self.bulk_import_facts(files)
            .into_iter()
            .map(|(file, facts)| (file, facts.imports))
            .collect()
    }

    pub(crate) fn bulk_file_dependency_facts(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
    ) -> HashMap<ProjectFile, crate::analyzer::FileDependencyFacts> {
        self.bulk_import_facts(files)
            .into_iter()
            .map(|(file, facts)| {
                (
                    file,
                    crate::analyzer::FileDependencyFacts {
                        imports: facts.imports,
                        contains_tests: Some(facts.contains_tests),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn bulk_import_facts(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
    ) -> HashMap<ProjectFile, ImportFileFacts> {
        let live = self.live_snapshot();
        let mut entries = Vec::new();
        let mut seen = HashSet::default();
        for file in files {
            if !self.adapter_owns_file(&file, &live) {
                continue;
            }
            if !seen.insert(file.clone()) {
                continue;
            }
            let Some(oid) = self.resolve_live_oid_for_file(&file) else {
                continue;
            };
            let storage_key = self.adapter.storage_language_key_for_file(&file);
            entries.push((file, oid, storage_key.to_string()));
        }
        if entries.is_empty() {
            return HashMap::default();
        }
        let mut out = HashMap::default();
        let mut clean_entries = Vec::new();
        for (file, oid, storage_key) in entries {
            let key = Self::transient_cache_key(oid, &file);
            if let Some(state) = self.retry_dirty_file_state(&key, &storage_key) {
                out.insert(
                    file,
                    ImportFileFacts {
                        package_name: state.package_name.clone(),
                        imports: state.imports.clone(),
                        contains_tests: state.contains_tests,
                    },
                );
            } else {
                clean_entries.push((file, oid, storage_key.to_string()));
            }
        }
        let entries = clean_entries;
        if entries.is_empty() {
            return out;
        }
        let mut facts: HashMap<ProjectFile, ImportFileFacts> = self
            .store_query_or_record(
                |sink| {
                    for (file, oid, _) in &entries {
                        sink.push(self.file_read_key(file, *oid));
                    }
                },
                self.store_context.store.hydrate_import_facts_by_key(
                    &entries,
                    self.store_context.generations.as_ref(),
                    self.adapter.as_ref(),
                ),
                "hydrating import facts",
            )
            .unwrap_or_default()
            .into_iter()
            .map(|(file, facts)| {
                (
                    file,
                    ImportFileFacts {
                        package_name: facts.package_name,
                        imports: facts.imports,
                        contains_tests: facts.contains_tests,
                    },
                )
            })
            .collect();
        self.bulk_hydration_count
            .fetch_add(facts.len(), Ordering::Relaxed);
        for (file, oid, _) in entries {
            if !facts.contains_key(&file)
                && let Some(source) = self.source_for_oid(&file, oid)
                && let Some(state) = self.parse_and_store_transient(&file, oid, source)
            {
                facts.insert(
                    file.clone(),
                    ImportFileFacts {
                        package_name: state.package_name,
                        imports: state.imports,
                        contains_tests: state.contains_tests,
                    },
                );
            }
            // Only the clean entries reach here -- the dirty ones went into
            // `out` above -- so these facts are keyed by the same content
            // identity `import_info_of` reads, and warm its per-file path.
            if let Some(facts) = facts.get(&file) {
                self.import_info_store_retain(
                    Self::transient_cache_key(oid, &file),
                    Arc::from(facts.imports.clone()),
                );
            }
        }
        out.extend(facts);
        out
    }

    /// Prefilter a broad reverse-reference universe with persisted structured
    /// import and lexical identifier indexes. The answer is intentionally a
    /// superset: the language provider hydrates and resolves these files to
    /// decide exact matches.
    pub(crate) fn reverse_reference_candidates(
        &self,
        explicit_import_segments: &HashSet<String>,
        wildcard_import_segments: &HashSet<String>,
        type_identifiers: &HashSet<String>,
        cancellation: &CancellationToken,
    ) -> HashSet<ProjectFile> {
        let live = self.live_snapshot();
        let mut result = HashSet::default();
        let mut clean_languages = HashSet::default();
        for file in live.all_paths().cloned() {
            if cancellation.is_cancelled() {
                return HashSet::default();
            }
            if !self.adapter_owns_file(&file, &live) {
                continue;
            }
            let Some(oid) = self.resolve_live_oid_for_file(&file) else {
                continue;
            };
            let storage_key = self.adapter.storage_language_key_for_file(&file);
            let key = Self::transient_cache_key(oid, &file);
            if self.retry_dirty_file_state(&key, storage_key).is_some() {
                // Dirty states are rare and have no guaranteed persisted row.
                // Admit them conservatively; the structured resolver below
                // performs the exact test from their in-memory facts.
                result.insert(file);
            } else {
                clean_languages.insert(storage_key.to_string());
            }
        }

        self.record_reads(|sink| {
            for segment in explicit_import_segments
                .iter()
                .chain(wildcard_import_segments)
            {
                sink.push(ReadKey::index(IndexFamily::ImportPathSegment, segment));
            }
            for identifier in type_identifiers {
                sink.push(ReadKey::index(IndexFamily::ReferenceIdentifier, identifier));
            }
        });
        for lang in clean_languages {
            if cancellation.is_cancelled() {
                return HashSet::default();
            }
            let Some(generation) = self.store_context.generations.get(&lang).copied() else {
                // A missing generation is an analyzer/store consistency error.
                // Conservatively retain the group so the optimization cannot
                // change a relevance answer.
                result.extend(
                    live.all_paths()
                        .filter(|file| self.adapter.storage_language_key_for_file(file) == lang)
                        .cloned(),
                );
                continue;
            };
            let matches = self.store_context.store.reverse_reference_candidate_paths(
                self.selected_workspace_snapshots().as_ref(),
                &lang,
                generation,
                explicit_import_segments,
                wildcard_import_segments,
                type_identifiers,
                cancellation,
            );
            match matches {
                Ok(matches) => {
                    result.extend(matches.into_iter().map(|rel_path| {
                        ProjectFile::new(self.project.root().to_path_buf(), rel_path)
                    }));
                }
                Err(error) => {
                    self.record_store_error(error.context("prefiltering reverse references"));
                    result.extend(
                        live.all_paths()
                            .filter(|file| self.adapter.storage_language_key_for_file(file) == lang)
                            .cloned(),
                    );
                }
            }
        }
        result
    }

    /// Seed-directed identifier candidates from the persisted live workspace.
    ///
    /// Unlike [`Self::reverse_reference_candidates`], this entry point does
    /// not need a caller-supplied file universe. It is the target-query path
    /// for languages whose parsed identifier facts are already a conservative
    /// reference prefilter.
    pub(crate) fn reverse_identifier_candidates(
        &self,
        identifiers: &HashSet<String>,
        cancellation: &CancellationToken,
    ) -> HashSet<ProjectFile> {
        let lang = self.adapter.language().config_label();
        let Some(generation) = self.store_context.generations.get(lang).copied() else {
            return self.all_files().into_iter().collect();
        };
        self.record_reads(|sink| {
            for identifier in identifiers {
                sink.push(ReadKey::index(IndexFamily::ReferenceIdentifier, identifier));
            }
        });
        let paths = match self.store_context.store.reverse_identifier_candidate_paths(
            self.selected_workspace_snapshots().as_ref(),
            lang,
            generation,
            identifiers,
            cancellation,
        ) {
            Ok(paths) => paths,
            Err(error) => {
                self.record_store_error(error.context("looking up reverse identifier paths"));
                return self.all_files().into_iter().collect();
            }
        };
        if cancellation.is_cancelled() {
            return HashSet::default();
        }
        let root = self.project.root();
        let mut result = paths
            .into_iter()
            .map(|path| ProjectFile::new(root, path))
            .collect::<HashSet<_>>();

        // A failed persistence leaves the current facts only in memory. These
        // entries are rare; inspect just that bounded dirty map so the SQL
        // optimization cannot turn a transient write error into a false
        // negative.
        for (key, dirty) in self.state.dirty_snapshot() {
            if cancellation.is_cancelled() {
                return HashSet::default();
            }
            if !dirty.state.type_identifiers.is_disjoint(identifiers) {
                result.insert(ProjectFile::new(root, key.rel_path));
            }
        }
        result
    }

    pub(crate) fn bulk_type_identifiers(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
    ) -> HashMap<ProjectFile, HashSet<String>> {
        let live = self.live_snapshot();
        let mut entries = Vec::new();
        let mut seen = HashSet::default();
        for file in files {
            if !self.adapter_owns_file(&file, &live) || !seen.insert(file.clone()) {
                continue;
            }
            let Some(oid) = self.resolve_live_oid_for_file(&file) else {
                continue;
            };
            let storage_key = self.adapter.storage_language_key_for_file(&file);
            entries.push((file, oid, storage_key.to_string()));
        }

        let mut out = HashMap::default();
        let mut clean_entries = Vec::new();
        for (file, oid, storage_key) in entries {
            let key = Self::transient_cache_key(oid, &file);
            if let Some(state) = self.retry_dirty_file_state(&key, &storage_key) {
                out.insert(file, state.type_identifiers.clone());
            } else {
                clean_entries.push((file, oid, storage_key));
            }
        }
        if clean_entries.is_empty() {
            return out;
        }
        let hydrated = self
            .store_query_or_record(
                |sink| {
                    for (file, oid, _) in &clean_entries {
                        sink.push(self.file_read_key(file, *oid));
                    }
                },
                self.store_context.store.hydrate_type_identifiers_by_key(
                    &clean_entries,
                    self.store_context.generations.as_ref(),
                ),
                "hydrating type identifiers",
            )
            .unwrap_or_default();
        self.bulk_hydration_count
            .fetch_add(hydrated.len(), Ordering::Relaxed);
        out.extend(hydrated);
        out
    }

    fn resolve_prepared_source(
        &self,
        file: &ProjectFile,
        max_source_bytes: Option<usize>,
    ) -> Result<Option<ResolvedPreparedSource>, PreparedSyntaxLimitExceeded> {
        let prepared_sources = self.active_query_cache_handle(|cache| &cache.prepared_sources);
        if let Some(prepared_sources) = prepared_sources.as_ref()
            && let Some(cached) = prepared_sources
                .read()
                .expect("query prepared-source cache read lock poisoned")
                .get(file)
                .cloned()
        {
            if let (Some(source), Some(max_source_bytes)) = (&cached, max_source_bytes)
                && source.snapshot.source().len() > max_source_bytes
            {
                return Err(PreparedSyntaxLimitExceeded {
                    minimum_source_bytes: source.snapshot.source().len(),
                });
            }
            return Ok(cached);
        }

        let snapshot = match max_source_bytes {
            Some(max_source_bytes) => {
                match self
                    .project
                    .read_source_snapshot_limited(file, max_source_bytes)
                {
                    Ok(Some(snapshot)) => Some(snapshot),
                    Ok(None) => {
                        return Err(PreparedSyntaxLimitExceeded {
                            minimum_source_bytes: max_source_bytes.saturating_add(1),
                        });
                    }
                    Err(_) => None,
                }
            }
            None => self.project.read_source_snapshot(file).ok(),
        };
        let resolved = snapshot.map(|snapshot| ResolvedPreparedSource {
            oid: self.blob_oid_of(file, snapshot.source()),
            snapshot,
        });

        if let Some(prepared_sources) = prepared_sources.as_ref() {
            let mut prepared_sources = prepared_sources
                .write()
                .expect("query prepared-source cache write lock poisoned");
            if prepared_sources.contains_key(file)
                || prepared_sources.len() < QUERY_PREPARED_SYNTAX_CACHE_CAPACITY
            {
                prepared_sources.insert(file.clone(), resolved.clone());
            }
        }
        Ok(resolved)
    }

    fn resolve_live_source_for_file(&self, file: &ProjectFile) -> Option<ResolvedLiveSource> {
        if let Some(snapshot) = self.live_source_snapshot.load().as_ref()
            && let Some(source) = snapshot.get(file).copied()
        {
            return Some(source);
        }
        let live_sources = self.active_query_cache_handle(|cache| &cache.live_sources);
        if let Some(live_sources) = live_sources.as_ref()
            && let Some(source) = live_sources
                .read()
                .expect("query live-source cache read lock poisoned")
                .get(file)
                .copied()
        {
            return source;
        }
        #[cfg(test)]
        if !self.project.has_overlay(file) {
            *self
                .live_oid_validation_counts
                .lock()
                .expect("live OID validation count mutex poisoned")
                .entry(file.clone())
                .or_default() += 1;
        }
        let source = if self.project.has_overlay(file) {
            let source = self.project.read_source(file).ok()?;
            Some(ResolvedLiveSource {
                oid: self.blob_oid_of(file, &source),
            })
        } else if let Some(oid) = self
            .store_context
            .live_paths
            .snapshot()
            .validated_oid_for_path(file)
        {
            Some(ResolvedLiveSource { oid })
        } else if let Some(liveness) = self.store_context.liveness.as_ref()
            && let Ok(Some(oid)) = liveness.oid_for_path(file)
        {
            Some(ResolvedLiveSource { oid })
        } else if file.exists()
            && let Ok(bytes) = std::fs::read(file.abs_path())
            && let Ok(oid) = Oid::hash_object(ObjectType::Blob, &bytes)
        {
            Some(ResolvedLiveSource { oid })
        } else {
            self.git_index_oid_for_file(file)
                .map(|oid| ResolvedLiveSource { oid })
        };
        if let Some(live_sources) = live_sources.as_ref() {
            live_sources
                .write()
                .expect("query live-source cache write lock poisoned")
                .insert(file.clone(), source);
        }
        source
    }

    fn resolve_live_oid_for_file(&self, file: &ProjectFile) -> Option<Oid> {
        self.resolve_live_source_for_file(file)
            .map(|source| source.oid)
    }

    #[cfg(test)]
    pub(crate) fn reset_live_oid_validation_counts_for_test(&self) {
        self.live_oid_validation_counts
            .lock()
            .expect("live OID validation count mutex poisoned")
            .clear();
    }

    #[cfg(test)]
    pub(crate) fn live_oid_validation_count_for_test(&self, file: &ProjectFile) -> usize {
        self.live_oid_validation_counts
            .lock()
            .expect("live OID validation count mutex poisoned")
            .get(file)
            .copied()
            .unwrap_or(0)
    }

    fn git_index_oid_for_file(&self, file: &ProjectFile) -> Option<Oid> {
        let repo = gitblob::discover(self.project.root())?;
        let index = repo.index().ok()?;
        index.get_path(file.rel_path(), 0).map(|entry| entry.id)
    }

    fn source_for_oid(&self, file: &ProjectFile, oid: Oid) -> Option<String> {
        if let Ok(source) = self.project.read_source(file)
            && self.blob_oid_of(file, &source) == oid
        {
            return Some(source);
        }
        if let Some(source) = self.source_from_git_blob(oid) {
            return Some(source);
        }
        None
    }

    fn source_from_git_blob(&self, oid: Oid) -> Option<String> {
        let repo = gitblob::discover(self.project.root())?;
        let bytes = gitblob::read_blob(&repo, &oid.to_string()).ok()?;
        String::from_utf8(bytes).ok()
    }

    fn parse_and_store_transient(
        &self,
        file: &ProjectFile,
        oid: Oid,
        source: String,
    ) -> Option<FileState> {
        // This parses `file` as this adapter's language and writes the result
        // under its storage key, so a foreign file must not reach the store at
        // all. See `storage_key_and_generation`. The owning guards all
        // discriminate on `storage_language_key_for_file`, so an adapter
        // override that answers its own key for a foreign file (the #2748
        // contract violation) slips past every one of them; assert the
        // contract itself here.
        debug_assert!(
            crate::analyzer::common::language_for_file(file) == self.adapter.language()
                || (self.adapter.claims_included_files()
                    && crate::analyzer::common::has_unclaimed_extension(file)),
            "parse_and_store_transient must not parse foreign file {} as {}",
            file.rel_path().display(),
            self.adapter.language().config_label(),
        );
        let (storage_key, generation) = self.storage_key_and_generation(file)?;
        let mut parser = Self::build_parser(self.adapter.parser_language());
        let state = Self::analyze_source(&mut parser, self.adapter.as_ref(), file, source)?;
        let key = Self::transient_cache_key(oid, file);
        match Self::write_parsed_blob_with_retries(
            &self.store_context,
            self.adapter.as_ref(),
            oid,
            &storage_key,
            generation,
            &state,
        ) {
            Ok(_) => {
                self.state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned")
                    .remove(&key);
            }
            Err(err) => {
                let status = dirty_file_state_status(&err);
                self.state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned")
                    .insert(
                        key,
                        Self::dirty_file_state(
                            Arc::new(state.clone()),
                            generation,
                            STORE_WRITE_IMMEDIATE_RETRIES + 1,
                            err.to_string(),
                            status,
                        ),
                    );
            }
        }
        self.store_context
            .live_paths
            .refresh([self.live_entry_for_source(file, oid)]);
        Some(state)
    }

    /// Classify the identity just derived for `file`'s current source.
    ///
    /// An unsaved overlay is an overlay entry: no disk stat describes it. A
    /// file read from disk with a Git identity source behind it is a
    /// filesystem entry, whose liveness that source can invalidate. Without
    /// that source the identity was hashed here, and nothing else will notice
    /// a later edit on this analyzer's behalf, so the entry stays live for the
    /// generation that indexed it while still carrying a capture stat for
    /// content reuse.
    fn live_entry_for_source(&self, file: &ProjectFile, oid: Oid) -> LivePathEntry {
        if self.project.has_overlay(file) {
            LivePathEntry::overlay(file.clone(), oid)
        } else if self.store_context.liveness.is_some() {
            LivePathEntry::filesystem(file.clone(), oid)
        } else {
            LivePathEntry::filesystem_hashed(file.clone(), oid)
        }
    }

    fn live_snapshot(&self) -> Arc<LiveSnapshot> {
        self.store_context.live_paths.snapshot()
    }

    /// Re-parse `files` and persist their blobs into the store, without
    /// producing a new analyzer generation.
    ///
    /// This is the catch-up half of ExecPlan Milestone 3
    /// (`.agents/plans/rust-usage-index-v2.md`): a store-backed query answers
    /// from a blob's rows, so a live file whose blob was never persisted -- a
    /// write that failed and left a dirty in-memory state, say -- is invisible
    /// to it. Running the whole reconcile to repair a handful of files would
    /// build a new analyzer and drop every memo on it, which is precisely what
    /// this plan exists to stop.
    ///
    /// A file whose current bytes no longer hash to its live oid is skipped:
    /// persisting it would file the new content's rows under the old blob, and
    /// blob rows are content-addressed and shared, so a row that lies is worse
    /// than a row that is missing. The next `update` reconciles those files
    /// with their real oid anyway.
    pub(crate) fn persist_live_blobs(&self, files: &[ProjectFile]) {
        let mut targets = Vec::with_capacity(files.len());
        // One target per blob key, not per file: byte-identical files share a
        // blob, and persisting the same key twice in one batch is a hard error
        // in the persistence layer. Reconcile picks a representative for the
        // same reason (`representative_by_blob_key`).
        let mut claimed = HashSet::default();
        for file in files {
            let Some(oid) = self.live_snapshot().oid_for_path(file) else {
                continue;
            };
            let Ok(source) = self.project.read_source(file) else {
                continue;
            };
            if !CodeUnitIndex::indexed_source_matches(self, file, &source) {
                continue;
            }
            let storage_key = self.adapter.storage_language_key_for_file(file);
            let Some(generation) = self.store_context.generations.get(storage_key).copied() else {
                continue;
            };
            if !claimed.insert((oid, storage_key)) {
                continue;
            }
            targets.push((file.clone(), oid, storage_key.to_string(), generation));
        }
        if targets.is_empty() {
            return;
        }
        Self::analyze_prepare_and_persist_files(
            self.adapter.as_ref(),
            self.project.as_ref(),
            &self.config,
            targets,
            None,
            &self.store_context,
            |_, _| {},
        );
    }

    /// The analyzer store, for a language module that answers a question from
    /// persisted rows rather than from a materialized in-heap index.
    ///
    /// The `IAnalyzer` surface deliberately does not carry it: only the store-
    /// backed Rust fact paths need it, and they reach it through their own
    /// analyzer shim.
    pub(crate) fn analyzer_store(&self) -> &Arc<AnalyzerStore> {
        &self.store_context.store
    }

    /// The analysis generation `lang`'s persisted rows belong to. Cache keys
    /// that mention it are invalidated for free when the generation moves.
    pub(crate) fn language_generation(&self, lang: &str) -> Option<GenerationId> {
        self.store_context.generations.get(lang).copied()
    }

    /// The current file-to-blob mapping, in both directions.
    ///
    /// This is how a caller turns a blob oid an inverted store lookup returned
    /// into the live `ProjectFile`s that currently have those bytes, and how it
    /// turns a file back into the blob whose rows describe it. Populated with
    /// or without a git-backed `Liveness` (see `resolve_live_oids`), so a
    /// store-backed query works in a plain directory too.
    pub(crate) fn live_path_snapshot(&self) -> Arc<LiveSnapshot> {
        self.live_snapshot()
    }

    /// Whether this adapter analyzes `file`.
    ///
    /// The extension registry is the rule. Include-driven inference (#1837)
    /// adds the second arm: a file whose extension no language owns belongs to
    /// this adapter once inference has adopted it, and membership in this
    /// analyzer's live path map is what records that adoption -- the map is
    /// per-language (`build_language_delegate` gives each delegate its own),
    /// and only `reconcile_claimed_files` puts an unclaimed-extension file in
    /// it. `live` is a parameter rather than a fresh snapshot because every
    /// caller is walking one already.
    fn adapter_owns_file(&self, file: &ProjectFile, live: &LiveSnapshot) -> bool {
        if crate::analyzer::common::language_for_file(file) == self.adapter.language() {
            return true;
        }
        self.adapter.claims_included_files()
            && crate::analyzer::common::has_unclaimed_extension(file)
            && live.oid_for_path(file).is_some()
    }

    /// The persisted half of [`CodeUnitIndex::parent_of`] — the owner unit named by
    /// popping `code_unit`'s last fq segment — memoized against the request's
    /// read-cache scope (#1230 item 6).
    ///
    /// Language analyzers whose `parent_of` is this lookup plus a structural
    /// fallback route through here so a request pays one
    /// `definition_candidates` query per distinct owner name instead of one per
    /// asking declaration. With no scope open there is no memo and the
    /// behaviour is exactly the unmemoized lookup.
    pub(crate) fn definition_parent_unit(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        let owner_fq_name = crate::analyzer::i_analyzer::default_parent_fq_name(code_unit)?;
        let parent_units = self.active_query_cache_handle(|cache| &cache.parent_units);
        let cached = parent_units.as_ref().and_then(|parent_units| {
            parent_units
                .read()
                .expect("query parent-unit cache read lock poisoned")
                .get(&owner_fq_name)
                .cloned()
        });
        if let Some(parent) = cached {
            return parent;
        }
        let parent = CodeUnitIndex::definitions(self, &owner_fq_name).next();
        if let Some(parent_units) = parent_units.as_ref() {
            parent_units
                .write()
                .expect("query parent-unit cache write lock poisoned")
                .insert(owner_fq_name, parent.clone());
        }
        parent
    }

    fn analyzed_live_files(&self) -> Vec<ProjectFile> {
        // Spanned because this is where #1738's missing time was: the worst
        // `searchtools::route_summary_targets` span in the incident trace was
        // 123.5 s with zero children, and all of it was this whole-workspace
        // scan run once per language delegate per request.
        let _scope = profiling::scope_with(|| {
            format!(
                "analyzer::analyzed_live_files[{:?}]",
                self.adapter.language()
            )
        });
        self.analyzed_file_listing_count
            .fetch_add(1, Ordering::Relaxed);
        // The answer is the analyzed file set itself, which nothing narrower
        // than the whole language scope can bound. Recorded before the request
        // memo answers, so a second call under the same ledger still names it.
        self.record_reads(|sink| sink.push(self.scope_read_key()));
        // Capture the two request handles together. `analyzed_live_files` is
        // also the one path that already validates every live filesystem entry;
        // publishing that same snapshot into `live_sources` before publishing
        // the file-list result makes later source/OID lookups read-only for the
        // rest of this request. Keeping both handles from one outer read also
        // means a concurrent outer-scope transition cannot pair a new file-list
        // handle with an old source handle.
        let (analyzed_live_files, live_sources) = {
            let cache = self.query_read_cache_lock();
            if cache.is_active() {
                (
                    Some(Arc::clone(&cache.analyzed_live_files)),
                    Some(Arc::clone(&cache.live_sources)),
                )
            } else {
                (None, None)
            }
        };
        if let Some(files) = analyzed_live_files
            .as_ref()
            .and_then(|analyzed_live_files| {
                analyzed_live_files
                    .read()
                    .expect("query analyzed-live cache read lock poisoned")
                    .clone()
            })
        {
            return files;
        }
        let snapshot = self.live_snapshot();
        let mut files = Vec::new();
        let mut persisted_candidates = Vec::new();
        let mut live_source_entries = HashMap::default();
        for file in snapshot.all_paths() {
            let Some(project_file) = self.rebase_live_file_to_project_root(file) else {
                continue;
            };
            if !self.adapter_owns_file(&project_file, &snapshot) {
                continue;
            }
            // Membership in the analyzed set is keyed on the snapshot's
            // validated OID: that is the content the store actually parsed. An
            // overlay's content hash must never be used here — it has no store
            // entry, so it would silently drop the file from the analyzed set
            // (the #1466 regression).
            let Some(oid) = snapshot.validated_oid_for_path(file) else {
                continue;
            };
            if live_sources.is_some() {
                // `resolve_live_source_for_file` gives overlays precedence over
                // the filesystem/live-path snapshot. Mirror that precedence in
                // the published live-source memo so the bulk seed cannot
                // publish a stale disk OID for an overlay that was installed
                // before this request began.
                let live_oid = if self.project.has_overlay(&project_file) {
                    self.project
                        .read_source(&project_file)
                        .ok()
                        .map(|source| self.blob_oid_of(&project_file, &source))
                } else {
                    None
                }
                .unwrap_or(oid);
                // The bulk seed is a fresh live-OID derivation: later
                // `resolve_live_source_for_file` calls hit the published memo
                // instead of re-deriving, so the validation count records the
                // derivation here or there, never both.
                #[cfg(test)]
                if !self.project.has_overlay(&project_file) {
                    *self
                        .live_oid_validation_counts
                        .lock()
                        .expect("live OID validation count mutex poisoned")
                        .entry(project_file.clone())
                        .or_default() += 1;
                }
                live_source_entries
                    .insert(project_file.clone(), ResolvedLiveSource { oid: live_oid });
            }
            let storage_key = self.adapter.storage_language_key_for_file(&project_file);
            let key = Self::transient_cache_key(oid, &project_file);
            if self.retry_dirty_file_state(&key, storage_key).is_some() {
                files.push(project_file);
                continue;
            }
            persisted_candidates.push((project_file, oid, storage_key));
        }
        let keys = persisted_candidates
            .iter()
            .map(|(_, oid, storage_key)| (*oid, storage_key.to_string()))
            .collect::<Vec<_>>();
        let present = {
            // The key set is the language's whole candidate list, so this one
            // query is workspace-scale; the span carries the count so a trace
            // shows what it was asked about (#1738).
            let _scope = profiling::scope_with(|| {
                format!(
                    "store::parsed_blob_keys_at_generations[{:?},{} keys]",
                    self.adapter.language(),
                    keys.len()
                )
            });
            self.store_query_or_record(
                |sink| sink.push(self.scope_read_key()),
                self.store_context.store.parsed_blob_keys_at_generations(
                    &keys,
                    self.store_context.generations.as_ref(),
                ),
                "checking analyzed live files",
            )
            .unwrap_or_default()
        };
        for (project_file, oid, storage_key) in persisted_candidates {
            if present.contains(&(oid, storage_key.to_string())) {
                files.push(project_file);
            }
        }
        files.sort();
        files.dedup();
        // Populate the captured inner handles without holding the outer lock.
        // If the scope ended during the liveness/store work, those handles are
        // detached and harmless. Recheck both identities under the outer lock
        // before publishing the generation-wide immutable snapshot so it can
        // never leak into a later request.
        if let (Some(analyzed_live_files), Some(live_sources)) =
            (analyzed_live_files.as_ref(), live_sources.as_ref())
        {
            live_sources
                .write()
                .expect("query live-source cache write lock poisoned")
                .extend(
                    live_source_entries
                        .iter()
                        .map(|(file, source)| (file.clone(), Some(*source))),
                );
            *analyzed_live_files
                .write()
                .expect("query analyzed-live cache write lock poisoned") = Some(files.clone());
            let cache = self.query_read_cache_lock();
            if cache.is_active()
                && Arc::ptr_eq(live_sources, &cache.live_sources)
                && Arc::ptr_eq(analyzed_live_files, &cache.analyzed_live_files)
            {
                self.live_source_snapshot
                    .store(Some(Arc::new(live_source_entries)));
            }
        }
        files
    }

    fn resolve_candidate_rows(&self, rows: Vec<HydratedCandidateRow>) -> Vec<CodeUnit> {
        QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        )
        .resolve_rows(rows)
    }

    fn resolve_mounted_candidate_rows(
        &self,
        rows: Vec<MountedCandidateRow>,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        let mut units = Vec::with_capacity(rows.len());
        for MountedCandidateRow {
            candidate: row,
            rel_path,
        } in rows
        {
            let file = ProjectFile::new(self.project.root().to_path_buf(), rel_path);
            let (fq, package_segment_count) = crate::analyzer::store::hydrate_unit_fq(
                self.adapter.as_ref(),
                row.fq.as_ref(),
                &row.content_qualifier,
                &file,
            )?;
            units.push(CodeUnit::from_fq(
                file,
                row.kind,
                fq,
                package_segment_count,
                row.signature,
                row.flags.synthetic,
            ));
        }
        units.sort();
        units.dedup();
        Ok(units)
    }

    fn resolve_candidate_rows_limited(
        &self,
        rows: Vec<HydratedCandidateRow>,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }

        let snapshot = self.live_snapshot();
        let mut resolved = Vec::new();
        let mut inspected = 0usize;
        for row in rows {
            if !continue_query() {
                return LimitedQueryRows::incomplete(resolved, inspected);
            }
            for file in snapshot.paths_for_oid(row.blob_oid) {
                if inspected == limit || !continue_query() {
                    return LimitedQueryRows::incomplete(resolved, inspected);
                }
                inspected += 1;
                let Some(file) = self.rebase_live_file_to_project_root(file) else {
                    continue;
                };
                if self.adapter.storage_language_key_for_file(&file) != row.lang
                    || snapshot.validated_oid_for_path(&file) != Some(row.blob_oid)
                {
                    continue;
                }
                let (fq, package_segment_count) = crate::analyzer::store::hydrate_unit_fq(
                    self.adapter.as_ref(),
                    row.fq.as_ref(),
                    &row.content_qualifier,
                    &file,
                )
                .expect("candidate row must contain a valid structured FqName");
                resolved.push(CodeUnit::from_fq(
                    file.clone(),
                    row.kind,
                    fq,
                    package_segment_count,
                    row.signature.clone(),
                    row.flags.synthetic,
                ));
            }
        }
        LimitedQueryRows::complete(resolved, inspected)
    }

    fn resolve_definition_order_candidate_rows(
        &self,
        rows: Vec<HydratedDefinitionOrderCandidateRow>,
    ) -> Vec<DefinitionSortCandidate> {
        QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        )
        .resolve_rows_with_payload(
            rows.into_iter()
                .map(|row| (row.candidate, row.first_start_byte)),
        )
        .into_iter()
        .map(|(unit, first_start_byte)| DefinitionSortCandidate {
            unit,
            range_start: DefinitionRangeStart::Persisted(first_start_byte),
        })
        .collect()
    }

    fn sql_path_symbol_units(
        &self,
        fq_name: &str,
        normalized: &str,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        if !self.adapter.has_path_synthetic_module_units() {
            return Ok(Vec::new());
        }

        self.record_reads(|sink| {
            sink.push(ReadKey::index(IndexFamily::PathSymbol, fq_name));
            sink.push(ReadKey::index(IndexFamily::PathSymbol, normalized));
        });
        let rows = self
            .store_context
            .store
            .path_symbol_rows_by_fqn_for_langs_at_snapshots(
                self.selected_workspace_snapshots().as_ref(),
                &self.storage_language_keys_for_queries(),
                self.store_context.generations.as_ref(),
                fq_name,
                normalized,
            )
            .map_err(|error| error.context("querying path-backed definition candidates"))?;
        let snapshot = self.live_snapshot();
        Ok(self.decode_path_symbol_rows(fq_name, normalized, rows, &snapshot))
    }

    /// Batched sibling of `forward_path_module_fqn`/`sql_path_symbol_units`: resolves every FQN's
    /// path-symbol rows in one store transaction instead of one per FQN. Row decoding (live-snapshot
    /// filtering, dirty-row merge, sort+dedup) is unchanged, just run once per FQN against a shared
    /// snapshot instead of re-fetching it per call.
    ///
    /// A whole-batch error (can't open the transaction) still returns `None` for every FQN, matching
    /// `forward_path_module_fqn`'s single-item error behavior. A per-FQN error (caught once inside the
    /// shared transaction) returns `None` for only that FQN -- the sibling FQNs in the same batch that
    /// resolved successfully keep their results instead of being discarded by a shared failure.
    pub(crate) fn forward_path_module_fqns_batch(
        &self,
        fq_names: &[String],
    ) -> Vec<Option<Vec<CodeUnit>>> {
        if !self.adapter.has_path_synthetic_module_units() {
            return fq_names.iter().map(|_| Some(Vec::new())).collect();
        }
        let pairs: Vec<(String, String)> = fq_names
            .iter()
            .map(|fq_name| (fq_name.clone(), self.adapter.normalize_full_name(fq_name)))
            .collect();
        self.record_reads(|sink| {
            for (fq_name, normalized) in &pairs {
                sink.push(ReadKey::index(IndexFamily::PathSymbol, fq_name));
                sink.push(ReadKey::index(IndexFamily::PathSymbol, normalized));
            }
        });
        match self
            .store_context
            .store
            .path_symbol_rows_by_fqns_for_langs_batch_at_snapshots(
                self.selected_workspace_snapshots().as_ref(),
                &self.storage_language_keys_for_queries(),
                self.store_context.generations.as_ref(),
                &pairs,
            ) {
            Ok(rows_per_fqn) => {
                let snapshot = self.live_snapshot();
                pairs
                    .iter()
                    .zip(rows_per_fqn)
                    .map(|((fq_name, normalized), rows)| match rows {
                        Ok(rows) => {
                            Some(self.decode_path_symbol_rows(fq_name, normalized, rows, &snapshot))
                        }
                        Err(error) => {
                            self.record_store_error(
                                error.context("querying path-backed definition candidates"),
                            );
                            None
                        }
                    })
                    .collect()
            }
            Err(error) => {
                self.record_store_error(
                    error.context("querying path-backed definition candidates (batch)"),
                );
                fq_names.iter().map(|_| None).collect()
            }
        }
    }

    fn decode_path_symbol_rows(
        &self,
        fq_name: &str,
        normalized: &str,
        rows: Vec<(String, PathSymbolRow)>,
        snapshot: &LiveSnapshot,
    ) -> Vec<CodeUnit> {
        let mut units = Vec::with_capacity(rows.len());
        for (lang, row) in rows {
            if let Some(unit) = self.live_path_symbol_unit(&lang, &row, snapshot)
                && (unit.fq_name() == fq_name
                    || self.adapter.normalize_full_name(&unit.fq_name()) == normalized)
            {
                units.push(unit);
            }
        }
        for (lang, row) in self
            .state
            .dirty_path_symbol_rows
            .lock()
            .expect("dirty path-symbol mutex poisoned")
            .values()
        {
            if let Some(unit) = self.live_path_symbol_unit(lang, row, snapshot)
                && (unit.fq_name() == fq_name
                    || self.adapter.normalize_full_name(&unit.fq_name()) == normalized)
            {
                units.push(unit);
            }
        }
        units.sort_by_cached_key(|unit| self.definition_sort_key_for_unit(unit));
        units.dedup();
        units
    }

    fn live_path_symbol_unit(
        &self,
        lang: &str,
        row: &PathSymbolRow,
        snapshot: &LiveSnapshot,
    ) -> Option<CodeUnit> {
        let file = ProjectFile::new(self.project.root().to_path_buf(), &row.rel_path);
        if self.adapter.storage_language_key_for_file(&file) != lang
            || snapshot.validated_oid_for_path(&file) != Some(row.blob_oid)
        {
            return None;
        }
        let unit = self.adapter.path_synthetic_module_unit(&file)?;
        (unit.kind() == row.kind
            && unit.package_name() == row.package_name
            && unit.short_name() == row.short_name
            && unit.fq_name() == row.exact_fqn
            && self.adapter.normalize_full_name(&unit.fq_name()) == row.normalized_fqn)
            .then_some(unit)
    }

    fn rebase_live_file_to_project_root(&self, file: &ProjectFile) -> Option<ProjectFile> {
        crate::analyzer::common::rebase_project_file_to_root(file, self.project.root())
    }

    fn sql_nonpersisted_workspace_declarations_vec_matching(
        &self,
        keep: impl FnMut(&CodeUnit) -> bool,
    ) -> Option<Vec<CodeUnit>> {
        self.store_query_or_record(
            |sink| sink.push(self.scope_read_key()),
            self.try_sql_nonpersisted_workspace_declarations_vec_matching(keep),
            "querying non-persisted workspace declarations",
        )
    }

    fn sql_nonpersisted_workspace_declarations_vec_matching_cancellable(
        &self,
        keep: impl FnMut(&CodeUnit) -> bool,
        cancellation: Option<&CancellationToken>,
    ) -> Option<LimitedQueryRows<CodeUnit>> {
        self.store_query_or_record(
            |sink| sink.push(self.scope_read_key()),
            self.try_sql_nonpersisted_workspace_declarations_vec_matching_limited(keep, || {
                !cancellation.is_some_and(CancellationToken::is_cancelled)
            }),
            "querying non-persisted workspace declarations with cancellation",
        )
    }

    fn try_sql_nonpersisted_workspace_declarations_vec_matching(
        &self,
        keep: impl FnMut(&CodeUnit) -> bool,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        Ok(self
            .try_sql_nonpersisted_workspace_declarations_vec_matching_limited(keep, || true)?
            .rows)
    }

    /// The live-path prefix shared by every non-persisted workspace
    /// declaration scan: one pass over the snapshot's paths that keeps the
    /// entries carrying a path-synthetic module unit for this analyzer's
    /// language, together with the snapshot it was taken from.
    ///
    /// Materialized at most once per request (#1774). Every caller of
    /// `sql_nonpersisted_workspace_declarations_vec_matching` used to pay this
    /// whole-workspace walk again, and the callers are per-name (short-name
    /// lookup, package-scoped class listings, identifier lookup), so a single
    /// query re-walked the workspace once per name it resolved. The narrowing
    /// `keep` predicate is deliberately *not* part of the memo: it runs after
    /// the walk, so the expensive tail (stat validation, the structured-import
    /// blob query, declaration hydration) stays scoped to the matching subset
    /// exactly as before.
    ///
    /// The snapshot travels with the walk so a memo hit and its tail read the
    /// same live-path state. `Err(inspected)` reports a cancelled walk and
    /// publishes nothing: a partial walk must never be served to a later
    /// caller as the workspace.
    fn workspace_module_walk(
        &self,
        continue_query: &mut impl FnMut() -> bool,
    ) -> std::result::Result<Arc<WorkspaceModuleWalk>, usize> {
        let memo = self.active_query_cache_handle(|cache| &cache.workspace_module_walk);
        let cached = memo.as_ref().and_then(|memo| {
            memo.read()
                .expect("query workspace-module walk cache read lock poisoned")
                .clone()
        });
        if let Some(walk) = cached {
            return Ok(walk);
        }

        self.workspace_path_scan_count
            .fetch_add(1, Ordering::Relaxed);
        let snapshot = self.live_snapshot();
        let mut entries = Vec::new();
        let mut inspected = 0usize;
        for file in snapshot.all_paths() {
            if !continue_query() {
                return Err(inspected);
            }
            inspected = inspected.saturating_add(1);
            let Some(project_file) = self.rebase_live_file_to_project_root(file) else {
                continue;
            };
            if !self.adapter_owns_file(&project_file, &snapshot) {
                continue;
            }
            let Some(module) = self.adapter.path_synthetic_module_unit(&project_file) else {
                continue;
            };
            let Some(oid) = snapshot.oid_for_path(file) else {
                continue;
            };
            entries.push((file.clone(), oid, module));
        }

        let walk = Arc::new(WorkspaceModuleWalk {
            snapshot,
            entries,
            inspected,
        });
        if let Some(memo) = memo.as_ref() {
            *memo
                .write()
                .expect("query workspace-module walk cache write lock poisoned") =
                Some(Arc::clone(&walk));
        }
        Ok(walk)
    }

    fn try_sql_nonpersisted_workspace_declarations_vec_matching_limited(
        &self,
        mut keep: impl FnMut(&CodeUnit) -> bool,
        mut continue_query: impl FnMut() -> bool,
    ) -> std::result::Result<LimitedQueryRows<CodeUnit>, StoreError> {
        if !self.adapter.has_path_synthetic_module_units() {
            return Ok(LimitedQueryRows::complete(Vec::new(), 0));
        }
        let walk = match self.workspace_module_walk(&mut continue_query) {
            Ok(walk) => walk,
            Err(inspected) => return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected)),
        };
        let snapshot = Arc::clone(&walk.snapshot);
        let mut candidates = Vec::new();
        let mut candidate_files = Vec::new();
        let mut inspected = walk.inspected;
        for (file, oid, module) in &walk.entries {
            if !continue_query() {
                return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
            }
            if !keep(module) {
                continue;
            }
            candidate_files.push(file.clone());
            candidates.push((file.clone(), *oid, module.clone()));
        }

        if !continue_query() {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
        }
        let stale: HashSet<_> = snapshot
            .validate(candidate_files.iter())
            .into_iter()
            .collect();
        if !continue_query() {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
        }

        let import_oids = if self.adapter.path_synthetic_module_requires_imports() {
            let mut blob_keys = Vec::with_capacity(candidates.len());
            for (file, oid, _) in &candidates {
                if !continue_query() {
                    return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
                }
                inspected = inspected.saturating_add(1);
                let project_file = self
                    .rebase_live_file_to_project_root(file)
                    .unwrap_or_else(|| file.clone());
                blob_keys.push((
                    *oid,
                    self.adapter
                        .storage_language_key_for_file(&project_file)
                        .to_string(),
                ));
            }
            blob_keys.sort();
            blob_keys.dedup();
            let import_oids = self
                .store_context
                .store
                .blobs_with_structured_imports_by_keys(
                    &blob_keys,
                    self.store_context.generations.as_ref(),
                )?;
            if !continue_query() {
                return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
            }
            Some(import_oids)
        } else {
            None
        };

        let mut declarations = Vec::new();
        for (file, oid, module) in candidates {
            if !continue_query() {
                return Ok(LimitedQueryRows::incomplete(declarations, inspected));
            }
            inspected = inspected.saturating_add(1);
            if stale.contains(&file) || module.is_file_scope() {
                continue;
            }
            if let Some(import_oids) = &import_oids {
                let project_file = self
                    .rebase_live_file_to_project_root(&file)
                    .unwrap_or_else(|| file.clone());
                if !self.adapter.include_path_synthetic_module(
                    import_oids.contains(&(
                        oid,
                        self.adapter
                            .storage_language_key_for_file(&project_file)
                            .to_string(),
                    )),
                ) {
                    continue;
                }
            }
            declarations.push(module);
        }
        declarations.sort();
        declarations.dedup();
        Ok(LimitedQueryRows::complete(declarations, inspected))
    }

    fn dirty_file_states_for_queries(&self) -> Vec<Arc<FileState>> {
        let snapshot = self.live_snapshot();
        let dirty = self.state.dirty_snapshot();
        let mut states = Vec::new();
        for (key, _) in dirty {
            let file = ProjectFile::new(self.project.root().to_path_buf(), key.rel_path.clone());
            if !self.adapter_owns_file(&file, &snapshot) {
                continue;
            }
            if snapshot.validated_oid_for_path(&file) != Some(key.oid) {
                continue;
            }
            let storage_key = self.adapter.storage_language_key_for_file(&file);
            if let Some(state) = self.retry_dirty_file_state(&key, storage_key) {
                states.push(state);
            }
        }
        states
    }

    /// File states that must override persisted relational rows for this
    /// analyzer snapshot.
    ///
    /// Failed writes live in `dirty_file_states`. Request overlays are
    /// different: they are parsed on demand and retained in the bounded query
    /// or transient file-state caches. A relational read must merge both kinds
    /// through the same path-authoritative rule or a cloned overlay can resolve
    /// its target from current syntax and then scan usages against the stale
    /// disk declaration.
    ///
    /// A relational lookup can be the first read of a frozen request overlay,
    /// so hydrate the project's explicit overlay set before taking the live
    /// snapshot. This is bounded by open buffers and never enumerates or parses
    /// the workspace. Without it an exact lookup has no in-memory facts to
    /// override the persisted disk row, especially when the overlay introduces
    /// a declaration name absent from disk.
    ///
    /// Only an overlay path can override a persisted row, and the live snapshot
    /// already knows which paths those are, so this walks that bounded set and
    /// asks the caches about each one. Walking the caches instead and filtering
    /// them down to overlays made every relational batch cost the number of
    /// file states the process had cached, and it deep-cloned each surviving
    /// `FileState` -- which is why a warm analyzer answered `scan_usages` more
    /// slowly than a cold one (#2883).
    fn authoritative_file_states_for_queries(&self) -> (Vec<Arc<FileState>>, HashSet<ProjectFile>) {
        let overlay_files = self
            .project
            .overlay_content()
            .map(|content| {
                content
                    .entries()
                    .iter()
                    .map(|(file, _)| file.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // Relational reads call this once per lookup, and a usage scan issues
        // thousands of lookups per request. Overlay-authoritative states can
        // only come from overlay-backed paths or dirty (unpersisted) states;
        // with neither present the walks below provably contribute nothing,
        // so skip the per-lookup cache iteration that rebuilt a `ProjectFile`
        // for every retained file-state entry just to discard it. The project
        // overlay registry is checked alongside the frozen snapshot's overlay
        // flags because either side can observe an overlay first.
        if overlay_files.is_empty()
            && !self.state.has_dirty_file_states()
            && !self.live_snapshot().has_overlay_paths()
        {
            return (Vec::new(), HashSet::default());
        }
        for file in &overlay_files {
            let _ = self.fetch_file_state(file);
        }
        let snapshot = self.live_snapshot();
        let mut states: HashMap<ProjectFile, Arc<FileState>> = HashMap::default();

        for state in self.dirty_file_states_for_queries() {
            if let Some(file) = state
                .declarations
                .iter()
                .next()
                .or_else(|| state.definition_lookup_units.iter().next())
                .map(|unit| unit.source().clone())
            {
                states.insert(file, state);
            }
        }

        for file in snapshot.overlay_files() {
            if states.contains_key(file) || !self.adapter_owns_file(file, &snapshot) {
                continue;
            }
            let Some(oid) = snapshot.validated_oid_for_path(file) else {
                continue;
            };
            let key = Self::transient_cache_key(oid, file);
            let Some(state) = self.retained_overlay_file_state(&key) else {
                continue;
            };
            states.insert(file.clone(), state);
        }

        self.authoritative_file_state_reads
            .fetch_add(states.len(), Ordering::Relaxed);
        let paths = states.keys().cloned().collect();
        (states.into_values().collect(), paths)
    }

    /// `key`'s already-materialized state in the two caches a request overlay
    /// can be retained in: the active query cache and the transient cache.
    ///
    /// Unlike [`Self::retained_file_state`] this never consults the generation
    /// snapshot index. That index holds the states the immutable generation was
    /// built from, which are the states the persisted rows already describe, so
    /// one found only there overrides nothing.
    fn retained_overlay_file_state(&self, key: &FileStateCacheKey) -> Option<Arc<FileState>> {
        if let Some(query_states) = self.active_query_cache_handle(|cache| &cache.file_states)
            && let Some(state) = query_states
                .read()
                .expect("query file-state cache read lock poisoned")
                .get(key)
        {
            return Some(state);
        }
        self.transient_file_states
            .lock()
            .expect("transient file-state cache mutex poisoned")
            .get(key)
    }

    fn dirty_units_matching(
        &self,
        include_definition_lookup_units: bool,
        mut keep: impl FnMut(&CodeUnit) -> bool,
    ) -> Vec<CodeUnit> {
        let mut out = Vec::new();
        for state in self.dirty_file_states_for_queries() {
            out.extend(
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope() && keep(unit))
                    .cloned(),
            );
            if include_definition_lookup_units {
                out.extend(
                    state
                        .definition_lookup_units
                        .iter()
                        .filter(|unit| !unit.is_file_scope() && keep(unit))
                        .cloned(),
                );
            }
        }
        out
    }

    fn dirty_units_matching_limited(
        &self,
        include_definition_lookup_units: bool,
        limit: usize,
        mut keep: impl FnMut(&CodeUnit) -> bool,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }

        let snapshot = self.live_snapshot();
        if !continue_query() {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let dirty = self
            .state
            .dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned");
        let mut rows = Vec::new();
        let mut inspected = 0usize;
        for (key, dirty) in dirty.iter() {
            // Scanning a dirty-state entry is real provider work even when the
            // entry belongs to another language or no longer matches the live
            // OID. Charge it so a small caller limit cannot hide an unbounded
            // workspace-wide map walk.
            if inspected == limit || !continue_query() {
                return LimitedQueryRows::incomplete(rows, inspected);
            }
            inspected += 1;
            let file = ProjectFile::new(self.project.root().to_path_buf(), key.rel_path.clone());
            if !self.adapter_owns_file(&file, &snapshot)
                || snapshot.validated_oid_for_path(&file) != Some(key.oid)
            {
                continue;
            }

            let declaration_sets = std::iter::once(&dirty.state.declarations).chain(
                include_definition_lookup_units.then_some(&dirty.state.definition_lookup_units),
            );
            for declarations in declaration_sets {
                for unit in declarations {
                    if inspected == limit || !continue_query() {
                        return LimitedQueryRows::incomplete(rows, inspected);
                    }
                    inspected += 1;
                    if !unit.is_file_scope() && keep(unit) {
                        rows.push(unit.clone());
                    }
                }
            }
        }
        LimitedQueryRows::complete(rows, inspected)
    }

    fn finish_limited_declaration_lookup(
        &self,
        persisted: LimitedQueryRows<HydratedCandidateRow>,
        include_definition_lookup_units: bool,
        include_path_synthetic_modules: bool,
        limit: usize,
        mut keep: impl FnMut(&CodeUnit) -> bool,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        let mut inspected = persisted.inspected;
        if !persisted.complete || inspected >= limit {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }

        let resolved = self.resolve_candidate_rows_limited(
            persisted.rows,
            limit - inspected,
            &mut continue_query,
        );
        inspected = inspected.saturating_add(resolved.inspected);
        if !resolved.complete || inspected >= limit {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }

        let dirty = self.dirty_units_matching_limited(
            include_definition_lookup_units,
            limit - inspected,
            &mut keep,
            &mut continue_query,
        );
        inspected = inspected.saturating_add(dirty.inspected);
        if !dirty.complete {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }

        // Path-synthetic modules are not represented by the declaration-row
        // query above. Callers that need modules cannot claim completeness
        // until a bounded path-unit visitor has also run. Callers whose
        // predicate explicitly excludes modules may soundly skip that source.
        if include_path_synthetic_modules && self.adapter.has_path_synthetic_module_units() {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }

        let mut rows: BTreeSet<_> = resolved.rows.into_iter().collect();
        rows.extend(dirty.rows);
        LimitedQueryRows::complete(rows.into_iter().collect(), inspected)
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.full_hydration_count.store(0, Ordering::Relaxed);
        self.bulk_hydration_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.full_hydration_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn bulk_hydration_count_for_test(&self) -> usize {
        self.bulk_hydration_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_authoritative_file_state_reads_for_test(&self) {
        self.authoritative_file_state_reads
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn authoritative_file_state_reads_for_test(&self) -> usize {
        self.authoritative_file_state_reads.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn import_info_hydration_count_for_test(&self) -> usize {
        self.tier_access_total_for_test(InformationTier::Imports)
    }

    /// Bulk import-fact store reads the include-claim derivation performed
    /// while producing *this* generation (#1865).
    ///
    /// Zero on an analyzer whose update saw no claim root, which is the
    /// locality property: a created file that answers no recorded demand must
    /// not cost a store read over the analyzed set.
    #[doc(hidden)]
    pub fn claim_import_hydration_count_for_test(&self) -> usize {
        self.state.claim_import_reads.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_enclosing_parent_query_counts_for_test(&self) {
        self.enclosing_code_unit_query_count
            .store(0, Ordering::Relaxed);
        self.sql_definitions_query_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn enclosing_code_unit_query_count_for_test(&self) -> usize {
        self.enclosing_code_unit_query_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn sql_definitions_query_count_for_test(&self) -> usize {
        self.sql_definitions_query_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_definition_candidates_query_count_for_test(&self) {
        self.definition_candidates_query_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn definition_candidates_query_count_for_test(&self) -> usize {
        self.definition_candidates_query_count
            .load(Ordering::Relaxed)
    }

    /// Batched definition-candidate store reads performed by
    /// [`Self::prefetch_definitions`]. Paired with
    /// `definition_candidates_query_count_for_test` it separates "one batch
    /// for the whole request" from "one point lookup per name".
    #[doc(hidden)]
    pub fn reset_definition_prefetch_batch_count_for_test(&self) {
        self.definition_prefetch_batch_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn definition_prefetch_batch_count_for_test(&self) -> usize {
        self.definition_prefetch_batch_count.load(Ordering::Relaxed)
    }

    /// Relational-store round trips issued by `RelationalDefinitionLookup::batch`,
    /// one per call regardless of how many requests it carried. A caller that
    /// resolves many distinct names one at a time drives this as high as the
    /// name count; a caller that batches them first keeps it flat (bifrost#15).
    #[doc(hidden)]
    pub fn reset_relational_definition_batch_call_count_for_test(&self) {
        self.relational_definition_batch_call_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn relational_definition_batch_call_count_for_test(&self) -> usize {
        self.relational_definition_batch_call_count
            .load(Ordering::Relaxed)
    }

    /// Persisted candidate-row reads that actually reached the store, one per
    /// (short name, ordering) the request has not already read. Paired with
    /// `definition_candidates_query_count_for_test` it separates "one read for
    /// every fq name that shares a short name" from "one read per fq name"
    /// (#1839).
    #[doc(hidden)]
    pub fn reset_definition_candidate_row_read_count_for_test(&self) {
        self.definition_candidate_row_read_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn definition_candidate_row_read_count_for_test(&self) -> usize {
        self.definition_candidate_row_read_count
            .load(Ordering::Relaxed)
    }

    /// Candidate spellings the structural-miss filter dropped, paired with the
    /// row-read count so a test can show that N dropped spellings cost N fewer
    /// seeks rather than merely being counted (#1748).
    #[doc(hidden)]
    pub fn reset_structural_miss_spelling_count_for_test(&self) {
        self.structural_miss_spelling_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn structural_miss_spelling_count_for_test(&self) -> usize {
        self.structural_miss_spelling_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_package_declaration_scan_count_for_test(&self) {
        self.package_declaration_scan_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn package_declaration_scan_count_for_test(&self) -> usize {
        self.package_declaration_scan_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_full_declaration_scan_count_for_test(&self) {
        self.full_declaration_scan_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn full_declaration_scan_count_for_test(&self) -> usize {
        self.full_declaration_scan_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_analyzed_file_listing_count_for_test(&self) {
        self.analyzed_file_listing_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn analyzed_file_listing_count_for_test(&self) -> usize {
        self.analyzed_file_listing_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_search_candidate_hydration_count_for_test(&self) {
        self.search_candidate_hydration_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn search_candidate_hydration_count_for_test(&self) -> usize {
        self.search_candidate_hydration_count
            .load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[doc(hidden)]
    #[doc(hidden)]
    pub fn reset_workspace_path_scan_count_for_test(&self) {
        self.workspace_path_scan_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn workspace_path_scan_count_for_test(&self) -> usize {
        self.workspace_path_scan_count.load(Ordering::Relaxed)
    }

    pub(crate) fn forward_definition_fqn(&self, fq_name: &str) -> Vec<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        match self.sql_bounded_definitions_vec(fq_name) {
            Ok(definitions) => definitions,
            Err(error) => {
                self.record_store_error(error);
                Vec::new()
            }
        }
    }

    pub(crate) fn normalize_rendered_name(&self, fq_name: &str) -> String {
        self.adapter.normalize_full_name(fq_name)
    }

    pub(crate) fn forward_path_module_fqn(&self, fq_name: &str) -> Option<Vec<CodeUnit>> {
        if !self.workspace_declaration_identities_authoritative() {
            return Some(Vec::new());
        }
        let normalized = self.adapter.normalize_full_name(fq_name);
        match self.sql_path_symbol_units(fq_name, &normalized) {
            Ok(units) => Some(units),
            Err(error) => {
                self.record_store_error(error);
                None
            }
        }
    }

    pub(crate) fn forward_file_identifier(
        &self,
        file: &ProjectFile,
        identifier: &str,
    ) -> Vec<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        let Some(state) = self.fetch_file_state(file) else {
            return Vec::new();
        };
        let mut matches = state
            .declarations
            .iter()
            .chain(&state.definition_lookup_units)
            .filter(|unit| !unit.is_file_scope() && unit.identifier() == identifier)
            .cloned()
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        matches
    }

    pub(crate) fn forward_direct_children(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        <Self as CodeUnitIndex>::direct_children(self, owner)
    }

    /// Return a provider-capped page of one declaration's direct children
    /// without hydrating the complete owning file state on a cold persisted
    /// analyzer.
    pub(crate) fn direct_children_limited(
        &self,
        owner: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        if limit == 0 || (owner.is_module() && self.adapter.language() == Language::Java) {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }

        let file = owner.source();
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return limited_projection_rows(state.children.get(owner).map(Vec::as_slice), limit);
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return limited_projection_rows(state.children.get(owner).map(Vec::as_slice), limit);
        }

        // See `storage_key_and_generation`: `owner` may come from another
        // language's file, which this analyzer holds no children for.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let persisted = self
            .store_query_or_record(
                |sink| sink.push(self.file_read_key(file, oid)),
                self.store_context.store.direct_children_for_unit_limited(
                    oid,
                    &storage_key,
                    generation,
                    owner,
                    limit,
                ),
                format!("querying bounded direct children for `{}`", owner.fq_name()),
            )
            .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0));
        let rows = persisted
            .rows
            .into_iter()
            .map(|row| {
                let (fq, package_segment_count) = crate::analyzer::store::hydrate_unit_fq(
                    self.adapter.as_ref(),
                    row.fq.as_ref(),
                    &row.content_qualifier,
                    file,
                )
                .expect("candidate row must contain a valid structured FqName");
                CodeUnit::from_fq(
                    file.clone(),
                    row.kind,
                    fq,
                    package_segment_count,
                    row.signature,
                    row.flags.synthetic,
                )
            })
            .collect();
        if persisted.complete {
            LimitedQueryRows::complete(rows, persisted.inspected)
        } else {
            LimitedQueryRows::incomplete(rows, persisted.inspected)
        }
    }

    pub(crate) fn forward_package_exists(&self, package: &str) -> bool {
        if !self.workspace_declaration_identities_authoritative() {
            return false;
        }
        self.persisted_package_exists(package)
    }

    pub(crate) fn forward_fqn_prefix_exists(&self, prefix: &str) -> bool {
        if !self.workspace_declaration_identities_authoritative() {
            return false;
        }
        let nested = format!("{prefix}.");
        let matches = |unit: &CodeUnit| {
            unit.package_name() == prefix
                || unit.package_name().starts_with(&nested)
                || unit.fq_name().starts_with(&nested)
        };
        if self
            .dirty_units_matching(false, matches)
            .into_iter()
            .any(|_| true)
        {
            return true;
        }

        const PAGE_SIZE: usize = 64;
        for lang in self.storage_language_keys_for_queries() {
            let mut after: Option<(String, Oid, i64)> = None;
            loop {
                let Some(rows) = self.store_query_or_record(
                    |sink| sink.push(self.scope_read_key()),
                    self.store_context
                        .store
                        .declaration_rows_by_package_prefix_page(
                            &lang,
                            self.store_context.generations[&lang],
                            prefix,
                            after.as_ref().map(|(qualifier, oid, unit_key)| {
                                (qualifier.as_str(), *oid, *unit_key)
                            }),
                            PAGE_SIZE,
                        ),
                    format!("querying declaration package prefix `{prefix}`"),
                ) else {
                    return false;
                };
                let Some(last) = rows.last() else {
                    break;
                };
                let next = (last.content_qualifier.clone(), last.blob_oid, last.unit_key);
                let complete = rows.len() < PAGE_SIZE;
                if self.resolve_candidate_rows(rows).iter().any(matches) {
                    return true;
                }
                if complete {
                    break;
                }
                after = Some(next);
            }
        }
        false
    }

    #[doc(hidden)]
    pub fn write_live_file_to_store_for_test(&self, file: &ProjectFile) -> Option<()> {
        if !file.exists() && !self.project.has_overlay(file) {
            return None;
        }
        let source = self.project.read_source(file).ok()?;
        let oid = self.blob_oid_of(file, &source);
        let live_entry = self.live_entry_for_source(file, oid);
        let mut parser = Self::build_parser(self.adapter.parser_language());
        let state = Self::analyze_source(&mut parser, self.adapter.as_ref(), file, source)?;
        let storage_key = self.adapter.storage_language_key_for_file(file);
        self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context.store.write_parsed_blob_at_generation(
                oid,
                storage_key,
                self.store_context.generations[storage_key],
                self.adapter.as_ref(),
                &state,
            ),
            format!(
                "persisting live analyzer state for {}",
                file.rel_path().display()
            ),
        )?;
        if let Some(liveness) = self.store_context.liveness.as_ref() {
            liveness.refresh_overlay([live_entry.clone()]).ok()?;
        }
        self.store_context.live_paths.refresh([live_entry]);
        Some(())
    }

    fn sql_all_declarations_vec(&self) -> Option<Vec<CodeUnit>> {
        self.full_declaration_scan_count
            .fetch_add(1, Ordering::Relaxed);
        let (authoritative_states, authoritative_paths) =
            self.authoritative_file_states_for_queries();
        let storage_languages = self.storage_language_keys_for_queries();
        let workspace_is_current = self.store_query_or_record(
            |sink| sink.push(self.scope_read_key()),
            self.relational_workspace_is_current(),
            "reading relational workspace identities",
        )?;
        let mut units = if workspace_is_current {
            let rows = self.store_query_or_record(
                |sink| sink.push(self.scope_read_key()),
                self.store_context.store.mounted_declaration_rows_for_langs(
                    self.selected_workspace_snapshots().as_ref(),
                    &storage_languages,
                    self.store_context.generations.as_ref(),
                ),
                "scanning all mounted declarations",
            )?;
            self.store_query_or_record(
                |sink| sink.push(self.scope_read_key()),
                self.resolve_mounted_candidate_rows(rows),
                "hydrating mounted declarations",
            )?
        } else {
            let rows = self.store_query_or_record(
                |sink| sink.push(self.scope_read_key()),
                self.store_context
                    .store
                    .declaration_candidate_rows_for_langs(
                        &storage_languages,
                        self.store_context.generations.as_ref(),
                    ),
                "scanning declarations for a retained workspace snapshot",
            )?;
            self.resolve_candidate_rows(rows)
        };
        units.retain(|unit| !authoritative_paths.contains(unit.source()));
        units.extend(authoritative_states.iter().flat_map(|state| {
            state
                .declarations
                .iter()
                .filter(|unit| !unit.is_file_scope())
                .cloned()
        }));
        units.extend(self.sql_nonpersisted_workspace_declarations_vec_matching(|_| true)?);
        units.retain(|unit| !unit.is_file_scope());
        units.sort();
        units.dedup();
        Some(units)
    }

    fn relational_workspace_is_current(&self) -> std::result::Result<bool, StoreError> {
        Ok(true)
    }

    fn selected_workspace_snapshots(&self) -> Arc<WorkspaceSnapshots> {
        self.relational_workspace_snapshots.load_full()
    }

    fn capture_relational_workspace_snapshots(&self) -> (Arc<WorkspaceSnapshots>, bool) {
        let storage_languages = self.storage_language_keys_for_queries();
        match self.store_query_or_record(
            |sink| sink.push(self.scope_read_key()),
            self.store_context.store.workspace_snapshots_for_langs(
                &self.store_context.workspace_id,
                &storage_languages,
                self.store_context.generations.as_ref(),
            ),
            "capturing relational workspace identities",
        ) {
            Some(snapshots) => (Arc::new(snapshots), true),
            None => (Arc::new(WorkspaceSnapshots::default()), false),
        }
    }

    fn sql_all_declarations_with_primary_ranges_vec(
        &self,
    ) -> Option<Vec<(CodeUnit, Option<Range>)>> {
        let (authoritative_states, authoritative_paths) =
            self.authoritative_file_states_for_queries();
        let rows = self.store_query_or_record(
            |sink| sink.push(self.scope_read_key()),
            self.store_context
                .store
                .declaration_candidate_rows_with_primary_ranges_for_langs(
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                ),
            "scanning declarations with primary ranges",
        )?;
        let resolver = QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        );
        let mut units = resolver.resolve_rows_with_payload(rows);
        units.retain(|(unit, _)| !authoritative_paths.contains(unit.source()));
        for state in authoritative_states {
            units.extend(
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope())
                    .cloned()
                    .map(|unit| {
                        let range = state.ranges.get(&unit).and_then(|ranges| {
                            ranges
                                .iter()
                                .copied()
                                .min_by_key(|range| (range.start_line, range.start_byte))
                        });
                        (unit, range)
                    }),
            );
        }
        units.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|_| true)?
                .into_iter()
                .map(|unit| (unit, None)),
        );
        units.retain(|(unit, _)| !unit.is_file_scope());
        units.sort_by(|(left, _), (right, _)| left.cmp(right));
        units.dedup_by(|(left, _), (right, _)| left == right);
        Some(units)
    }

    pub(crate) fn hierarchy_declaration_facts_by_kind(
        &self,
        kind: CodeUnitType,
    ) -> Option<Vec<HierarchyDeclarationFacts>> {
        if !self.workspace_declaration_identities_authoritative() {
            return Some(Vec::new());
        }
        let rows = self.store_query_or_record(
            |sink| sink.push(self.scope_read_key()),
            self.store_context
                .store
                .declaration_candidate_rows_with_primary_ranges_by_kind_for_langs(
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                    kind,
                ),
            format!("querying {kind:?} hierarchy declarations"),
        )?;
        let resolver = QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        );
        let mut facts = resolver
            .resolve_rows_with_payload(rows.into_iter().map(|row| {
                let storage_key = HierarchyStorageKey {
                    blob_oid: row.candidate.blob_oid,
                    lang: row.candidate.lang.clone(),
                    unit_key: row.candidate.unit_key,
                };
                (
                    row.candidate,
                    (row.primary_range, row.in_test_region, storage_key),
                )
            }))
            .into_iter()
            .map(
                |(declaration, (primary_range, in_test_region, storage_key))| {
                    HierarchyDeclarationFacts {
                        declaration,
                        primary_range,
                        in_test_region,
                        imports: Arc::default(),
                        raw_supertypes: Arc::default(),
                        storage_key: Some(storage_key),
                    }
                },
            )
            .collect::<Vec<_>>();
        for state in self.dirty_file_states_for_queries() {
            facts.extend(
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope() && unit.kind() == kind)
                    .cloned()
                    .map(|unit| {
                        let primary_range = state.ranges.get(&unit).and_then(|ranges| {
                            ranges
                                .iter()
                                .copied()
                                .min_by_key(|range| (range.start_line, range.start_byte))
                        });
                        let raw_supertypes =
                            state.raw_supertypes.get(&unit).cloned().unwrap_or_default();
                        let in_test_region = state.test_region_units.contains(&unit);
                        HierarchyDeclarationFacts {
                            declaration: unit,
                            primary_range,
                            in_test_region,
                            imports: Arc::from(state.imports.clone()),
                            raw_supertypes: Arc::from(raw_supertypes),
                            storage_key: None,
                        }
                    }),
            );
        }
        facts.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| unit.kind() == kind)?
                .into_iter()
                .map(|declaration| HierarchyDeclarationFacts {
                    declaration,
                    primary_range: None,
                    in_test_region: false,
                    imports: Arc::default(),
                    raw_supertypes: Arc::default(),
                    storage_key: None,
                }),
        );
        facts.sort_by(|left, right| left.declaration.cmp(&right.declaration));
        facts.dedup_by(|left, right| left.declaration == right.declaration);
        Some(facts)
    }

    pub(crate) fn hydrate_hierarchy_declaration_facts(
        &self,
        facts: &mut [HierarchyDeclarationFacts],
    ) -> Option<()> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        let keys = facts
            .iter()
            .filter_map(|facts| facts.storage_key.clone())
            .collect::<Vec<_>>();
        let persisted = self.store_query_or_record(
            |sink| sink.push(self.scope_read_key()),
            self.store_context
                .store
                .hierarchy_facts_by_keys(&keys, self.store_context.generations.as_ref()),
            "hydrating hierarchy declaration facts",
        )?;
        for facts in facts {
            let Some(storage_key) = facts.storage_key.as_ref() else {
                continue;
            };
            let Some(stored) = persisted.get(storage_key) else {
                continue;
            };
            facts.imports = Arc::clone(&stored.imports);
            facts.raw_supertypes = Arc::clone(&stored.raw_supertypes);
        }
        Some(())
    }

    /// The spellings one fq name is looked up under in the `(lang, short_name)`
    /// index.
    ///
    /// This is where the suffix expansion is minted -- 4.41 spellings per fq
    /// name on the rustc tree, each one a memo op and, on a miss, a pooled
    /// connection checkout plus an index probe. A spelling that carries a
    /// separator join [`absent_segment_separators`] reports for this adapter's
    /// language cannot match any stored `short_name` for it, so it is dropped
    /// here rather than seeking for a row the storage contract says is not
    /// there (issue #1748;
    /// `.agents/docs/graph-read-cost-investigation-2026-08.md`).
    ///
    /// Dropping is sound in exactly one direction: it removes probes that
    /// return no rows. It cannot remove a candidate, because a candidate is a
    /// row and there are none to return. The normalized spellings are minted
    /// first and filtered with the rest, so an adapter whose
    /// `normalize_full_name` rewrites `::` into its own vocabulary keeps every
    /// spelling that can match.
    pub(crate) fn definition_candidate_short_names(&self, fq_name: &str) -> Vec<String> {
        let mut names = self.adapter.lookup_candidate_short_names(fq_name);
        let normalized = self.adapter.normalize_full_name(fq_name);
        if normalized != fq_name {
            names.extend(self.adapter.lookup_candidate_short_names(&normalized));
        }
        // A separator is droppable only when both declarations agree: the
        // renderer never emits it for this language, and the adapter's own
        // lookup vocabulary treats it as a join rather than as name text.
        let joins = self.adapter.lookup_candidate_separators();
        let droppable = absent_segment_separators(self.adapter.language())
            .iter()
            .filter(|separator| joins.contains(*separator))
            .collect::<Vec<_>>();
        if !droppable.is_empty() {
            let before = names.len();
            names.retain(|name| !droppable.iter().any(|separator| name.contains(**separator)));
            self.structural_miss_spelling_count
                .fetch_add(before - names.len(), Ordering::Relaxed);
        }
        names.sort();
        names.dedup();
        names
    }

    fn definition_sort_key_for_candidate(
        &self,
        candidate: &DefinitionSortCandidate,
    ) -> (i32, usize, String, String, String, String) {
        self.definition_sort_key(&candidate.unit, candidate.range_start)
    }

    fn definition_sort_key_for_unit(
        &self,
        code_unit: &CodeUnit,
    ) -> (i32, usize, String, String, String, String) {
        self.definition_sort_key(code_unit, DefinitionRangeStart::FileState)
    }

    /// Restore the source-position ordering promised by
    /// `IAnalyzer::definitions` after a relational set query and any semantic
    /// identity projection have selected the answer.
    ///
    /// `candidates` pairs the published identity with the physical persisted
    /// identity that owns its ranges. One set-oriented exact-name query reads
    /// primary positions for all distinct physical names. Only transient or
    /// historical rows absent from the current relational snapshot fall back
    /// to their already-addressable file state.
    pub(crate) fn sort_definition_units_by_physical_identity(
        &self,
        candidates: &mut [(CodeUnit, CodeUnit)],
    ) {
        let mut names = candidates
            .iter()
            .map(|(_, physical)| self.relational_name_for_unit(physical))
            .collect::<Vec<_>>();
        names.sort_by_cached_key(|name| {
            name.full_name()
                .display(crate::analyzer::fq_name::segment_interner())
        });
        names.dedup();

        let cancellation = self.active_query_cancellation().unwrap_or_default();
        let storage_languages = self.storage_language_keys_for_queries();
        let ordered = self
            .store_query_or_record(
                |sink| {
                    for name in &names {
                        sink.push(ReadKey::index(
                            IndexFamily::DefinitionExact,
                            name.full_name()
                                .display(crate::analyzer::fq_name::segment_interner()),
                        ));
                    }
                },
                self.store_context
                    .store
                    .relational_exact_definition_order_rows(
                        self.adapter.as_ref(),
                        self.project.root(),
                        self.store_context.generations.as_ref(),
                        &storage_languages,
                        self.selected_workspace_snapshots().as_ref(),
                        &names,
                        &cancellation,
                    ),
                "reading relational definition ordering",
            )
            .flatten()
            .unwrap_or_default();
        let first_starts = ordered
            .into_iter()
            .flatten()
            .map(|row| (row.unit, row.first_start_byte))
            .collect::<HashMap<CodeUnit, Option<usize>>>();

        let mut keys = Vec::with_capacity(candidates.len());
        for (published, physical) in candidates.iter() {
            let first_start_byte = first_starts.get(physical).copied().flatten().or_else(|| {
                self.source_snapshot_file_state(physical.source())
                    .or_else(|| self.fetch_file_state(physical.source()))
                    .and_then(|state| {
                        state
                            .ranges
                            .get(physical)
                            .into_iter()
                            .flatten()
                            .map(|range| range.start_byte)
                            .min()
                    })
            });
            keys.push(
                self.definition_sort_key(
                    published,
                    DefinitionRangeStart::Persisted(first_start_byte),
                ),
            );
        }
        let mut order = (0..candidates.len()).collect::<Vec<_>>();
        order.sort_by(|left, right| keys[*left].cmp(&keys[*right]));
        let original = candidates.to_vec();
        for (destination, source) in order.into_iter().enumerate() {
            candidates[destination] = original[source].clone();
        }
    }

    fn definition_sort_key(
        &self,
        code_unit: &CodeUnit,
        range_start: DefinitionRangeStart,
    ) -> (i32, usize, String, String, String, String) {
        let first_start_byte = match range_start {
            DefinitionRangeStart::Persisted(first_start_byte) => {
                first_start_byte.unwrap_or(usize::MAX)
            }
            DefinitionRangeStart::FileState => self
                .ranges(code_unit)
                .into_iter()
                .map(|range| range.start_byte)
                .min()
                .unwrap_or(usize::MAX),
        };
        (
            self.adapter.definition_priority(code_unit),
            first_start_byte,
            code_unit.source().to_string().to_ascii_lowercase(),
            code_unit.fq_name().to_ascii_lowercase(),
            code_unit.signature().unwrap_or("").to_ascii_lowercase(),
            format!("{:?}", code_unit.kind()),
        )
    }

    /// Request-scoped memo behind [`IAnalyzer::definitions`]. With no query
    /// scope open there is no memo and the behaviour is exactly the unmemoized
    /// lookup, matching `definition_parent_unit` (#1230 item 6).
    fn sql_definitions_vec(&self, fq_name: &str) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        self.sql_definitions_query_count
            .fetch_add(1, Ordering::Relaxed);
        let Some(memo) = self.active_query_cache_handle(|cache| &cache.definition_units) else {
            return self.sql_definition_candidates_vec(fq_name, false);
        };
        let key = fq_name.to_string();
        let cell = memo.cell(&key);
        let Some(cancellation) = self.active_query_cancellation() else {
            return cell
                .get_or_try_build_pool_independent(|| {
                    self.sql_definition_candidates_vec(fq_name, false)
                })
                .map(|definitions| (*definitions).clone());
        };

        let keep_going = || !cancellation.is_cancelled();
        let definitions = cell.get_or_try_build_pool_independent_while(&keep_going, || {
            let definitions = self.sql_definition_candidates_vec(fq_name, false)?;
            Ok::<Option<Vec<CodeUnit>>, StoreError>(keep_going().then_some(definitions))
        })?;
        Ok(definitions
            .map(|definitions| (*definitions).clone())
            .unwrap_or_default())
    }

    fn sql_bounded_definitions_vec(
        &self,
        fq_name: &str,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        self.sql_definition_candidates_vec(fq_name, true)
    }

    fn sql_definition_candidates_vec(
        &self,
        fq_name: &str,
        include_definition_lookup_units: bool,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        self.definition_candidates_query_count
            .fetch_add(1, Ordering::Relaxed);
        // Two store reads and an assembly, all on behalf of a caller whose
        // budget is gone. `definition_candidate_rows` refuses the big one on
        // its own, and refusing the whole lookup here also spares the
        // path-symbol read (68 ms on the name that ended the run-10 window).
        if self
            .active_query_cancellation()
            .is_some_and(|cancellation| cancellation.is_cancelled())
        {
            return Ok(Vec::new());
        }
        let normalized = self.adapter.normalize_full_name(fq_name);
        let langs = self.storage_language_keys_for_queries();
        let seekable = !self.definition_candidate_short_names(fq_name).is_empty();
        // No per-name profiling scopes here: usage scans resolve thousands of
        // candidate names per request, and a BEGIN/END pair per name floods
        // stderr (an unbuffered global-locked write per line) faster than the
        // benchmark harness's bounded tail can retain anything else. The
        // `definition_candidates_query_count` counter remains the aggregate
        // signal.
        if seekable {
            self.definition_candidate_row_read_count
                .fetch_add(1, Ordering::Relaxed);
        }
        let requests = [RenderedDefinitionRequest {
            exact_name: fq_name.to_string(),
            normalized_name: normalized.clone(),
            seekable,
        }];
        let outcome = self
            .store_context
            .store
            .rendered_definition_order_candidate_rows_for_langs(
                &langs,
                self.store_context.generations.as_ref(),
                self.selected_workspace_snapshots().as_ref(),
                &requests,
                include_definition_lookup_units,
                self.active_query_cancellation().as_ref(),
            )
            .map_err(|error| {
                error.context(format!("querying definition candidates for `{fq_name}`"))
            })?;
        let mut rows = match outcome {
            RenderedDefinitionCandidateOutcome::Complete(rows) => rows,
            RenderedDefinitionCandidateOutcome::Cancelled => return Ok(Vec::new()),
        };
        let path_units = {
            let _path_scope = crate::profiling::scope(format!(
                "sql_definition_candidates.path_symbol[{fq_name}]"
            ));
            self.sql_path_symbol_units(fq_name, &normalized)?
        };
        Ok(self.assemble_definition_candidates(
            fq_name,
            &normalized,
            rows.pop()
                .expect("one rendered request returns one row group"),
            path_units,
            include_definition_lookup_units,
        ))
    }

    /// The store-independent half of [`Self::sql_definition_candidates_vec`]:
    /// merge persisted candidate rows, dirty units and path-symbol units for
    /// one fq name, then apply the exact/normalized precedence, definition
    /// ordering and single-module rule.
    ///
    /// Split out so the batched prefetch can assemble many names from one
    /// chunked row read without duplicating (or drifting from) this ordering.
    fn assemble_definition_candidates(
        &self,
        fq_name: &str,
        normalized: &str,
        rows: Vec<HydratedDefinitionOrderCandidateRow>,
        path_units: Vec<CodeUnit>,
        include_definition_lookup_units: bool,
    ) -> Vec<CodeUnit> {
        let candidates = {
            let _resolve_scope = crate::profiling::scope(format!(
                "sql_definition_candidates.resolve_rows[{fq_name}]"
            ));
            self.resolve_definition_order_candidate_rows(rows)
        };
        self.assemble_definition_candidates_from_units(
            fq_name,
            normalized,
            candidates,
            path_units,
            include_definition_lookup_units,
        )
    }

    fn assemble_definition_candidates_from_units(
        &self,
        fq_name: &str,
        normalized: &str,
        mut candidates: Vec<DefinitionSortCandidate>,
        path_units: Vec<CodeUnit>,
        include_definition_lookup_units: bool,
    ) -> Vec<CodeUnit> {
        {
            let _dirty_scope = crate::profiling::scope(format!(
                "sql_definition_candidates.dirty_units[{fq_name}]"
            ));
            let (authoritative_states, authoritative_paths) =
                self.authoritative_file_states_for_queries();
            candidates.retain(|candidate| !authoritative_paths.contains(candidate.unit.source()));
            for state in &authoritative_states {
                let units = state.declarations.iter().chain(
                    include_definition_lookup_units
                        .then_some(&state.definition_lookup_units)
                        .into_iter()
                        .flatten(),
                );
                candidates.extend(
                    units
                        .filter(|unit| {
                            !unit.is_file_scope()
                                && (unit.fq_name() == fq_name
                                    || self.adapter.normalize_full_name(&unit.fq_name())
                                        == normalized)
                        })
                        .map(|unit| DefinitionSortCandidate {
                            unit: unit.clone(),
                            range_start: DefinitionRangeStart::FileState,
                        }),
                );
            }
        }
        candidates.extend(path_units.into_iter().map(|unit| DefinitionSortCandidate {
            unit,
            range_start: DefinitionRangeStart::FileState,
        }));
        let has_exact = candidates
            .iter()
            .any(|candidate| candidate.unit.fq_name() == fq_name);
        let mut matches: Vec<_> = candidates
            .into_iter()
            .filter(|candidate| {
                if has_exact {
                    candidate.unit.fq_name() == fq_name
                } else {
                    self.adapter.normalize_full_name(&candidate.unit.fq_name()) == normalized
                }
            })
            .collect();
        matches.sort_by_cached_key(|candidate| self.definition_sort_key_for_candidate(candidate));
        matches.dedup_by(|left, right| left.unit == right.unit);

        let mut saw_module = false;
        matches.retain(|candidate| {
            if !candidate.unit.is_module() {
                return true;
            }
            if saw_module {
                false
            } else {
                saw_module = true;
                true
            }
        });
        matches
            .into_iter()
            .map(|candidate| candidate.unit)
            .collect()
    }

    /// Resolve many fq names into the request-scoped `definitions` memo using
    /// chunked `IN`-list seeks instead of one point lookup per name (#1748).
    ///
    /// The shared import-graph candidate walk enumerates every import target
    /// in the workspace before it inspects any file, so the keys are known up
    /// front. Asking per name cost one pooled reader checkout, one
    /// transaction and one generation check each -- on a 35k-file Rust
    /// workspace that was 397k-662k round trips inside a single
    /// `scan_usages` query. Here it is two batched reads: one chunked
    /// short-name seek for the persisted rows and one shared-transaction pass
    /// for the path-symbol rows.
    ///
    /// A no-op without an open query scope: with no memo to fill there is
    /// nothing to prefetch into, and every caller falls back to the point
    /// lookup with unchanged results. Prefetch failures are equally
    /// non-binding -- the name is simply left unmemoized. A request whose
    /// deadline has already expired is the same case: this is a whole-workspace
    /// read taken on behalf of work that will not happen.
    pub(crate) fn prefetch_definitions(&self, fq_names: &[String]) {
        let Some(memo) = self.active_query_cache_handle(|cache| &cache.definition_units) else {
            return;
        };
        let cancellation = self.active_query_cancellation();
        if cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return;
        }
        let _scope = crate::profiling::scope("TreeSitterAnalyzer::prefetch_definitions");
        let mut unique: BTreeSet<&str> = BTreeSet::new();
        let missing: Vec<String> = fq_names
            .iter()
            .filter(|fq_name| unique.insert(fq_name.as_str()))
            .filter(|fq_name| !memo.cell(*fq_name).is_ready())
            .cloned()
            .collect();
        if missing.is_empty() {
            return;
        }

        let normalized_names = missing
            .iter()
            .map(|name| self.adapter.normalize_full_name(name))
            .collect::<Vec<_>>();
        let requests = missing
            .iter()
            .zip(&normalized_names)
            .map(|(exact_name, normalized_name)| RenderedDefinitionRequest {
                exact_name: exact_name.clone(),
                normalized_name: normalized_name.clone(),
                seekable: !self.definition_candidate_short_names(exact_name).is_empty(),
            })
            .collect::<Vec<_>>();

        self.definition_prefetch_batch_count
            .fetch_add(1, Ordering::Relaxed);
        let rows = match self
            .store_context
            .store
            .rendered_definition_order_candidate_rows_for_langs(
                &self.storage_language_keys_for_queries(),
                self.store_context.generations.as_ref(),
                self.selected_workspace_snapshots().as_ref(),
                &requests,
                false,
                cancellation.as_ref(),
            ) {
            Ok(RenderedDefinitionCandidateOutcome::Complete(rows)) => rows,
            Ok(RenderedDefinitionCandidateOutcome::Cancelled) => return,
            Err(error) => {
                self.record_store_error(
                    error.context("prefetching definition candidates by short name"),
                );
                return;
            }
        };
        let path_units_by_name = self.forward_path_module_fqns_batch(&missing);
        let mut resolved = Vec::with_capacity(missing.len());
        for (((fq_name, normalized), name_rows), path_units) in missing
            .iter()
            .zip(normalized_names)
            .zip(rows)
            .zip(path_units_by_name)
        {
            // `None` means this name's path-symbol read failed on its own.
            // Leaving it unmemoized sends the next caller down the point
            // lookup, which is the honest answer rather than a short one.
            let Some(path_units) = path_units else {
                continue;
            };
            resolved.push((
                fq_name.clone(),
                self.assemble_definition_candidates(
                    fq_name,
                    &normalized,
                    name_rows,
                    path_units,
                    false,
                ),
            ));
        }

        for (fq_name, units) in resolved {
            memo.cell(&fq_name).get_or_build_pool_independent(|| units);
        }
    }

    fn sql_lookup_candidates_by_short_name(&self, symbol: &str) -> Option<BTreeSet<CodeUnit>> {
        let candidate_names = self.definition_candidate_short_names(symbol);
        if candidate_names.is_empty() {
            return Some(BTreeSet::new());
        }

        let candidate_name_set: HashSet<_> = candidate_names.iter().cloned().collect();
        let langs = self.storage_language_keys_for_queries();
        let mut rows = Vec::new();
        for short_name in &candidate_names {
            rows.extend(
                self.store_query_or_record(
                    |sink| {
                        sink.push(ReadKey::index(
                            IndexFamily::DefinitionIdentifier,
                            short_name,
                        ))
                    },
                    self.store_context
                        .store
                        .declaration_candidate_rows_by_short_name_for_langs(
                            &langs,
                            self.store_context.generations.as_ref(),
                            short_name,
                        ),
                    format!("querying declaration candidates for `{symbol}`"),
                )?,
            );
        }

        let mut matches: BTreeSet<_> = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(|unit| candidate_name_set.contains(unit.short_name()))
            .collect();
        matches.extend(
            self.dirty_units_matching(false, |unit| candidate_name_set.contains(unit.short_name())),
        );
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                candidate_name_set.contains(unit.short_name())
            })?,
        );
        Some(matches)
    }

    /// Declarations this analyzer indexes under `identifier`, where
    /// "indexes under" means the spelling a caller can address the declaration
    /// by -- `source_identifier_for_target`, not the raw persisted
    /// `identifier`. The two differ for C# generic arity and TypeScript
    /// `$static`, and the callers in `symbol_lookup` compare against lookup
    /// aliases built from the source spelling, so a raw-only lookup would miss
    /// exactly those declarations (#1063). `decorated_identifier_seeks`
    /// supplies the extra index keys; the row filter below stays authoritative
    /// because a prefix range also admits spellings that are not decorations.
    pub(crate) fn lookup_declarations_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return BTreeSet::new();
        }
        let langs = self.storage_language_keys_for_queries();
        let names = |unit: &CodeUnit| identifier_addresses_target(unit, identifier);
        let mut rows = self
            .store_query_or_record(
                |sink| {
                    sink.push(ReadKey::index(
                        IndexFamily::DefinitionIdentifier,
                        identifier,
                    ))
                },
                self.store_context
                    .store
                    .declaration_candidate_rows_by_identifier_for_langs(
                        &langs,
                        self.store_context.generations.as_ref(),
                        identifier,
                    ),
                format!("querying declarations by identifier `{identifier}`"),
            )
            .unwrap_or_default();
        for seek in decorated_identifier_seeks(self.adapter.language(), identifier) {
            let decorated = match &seek {
                IdentifierSeek::Exact(spelling) => self.store_query_or_record(
                    |sink| sink.push(ReadKey::index(IndexFamily::DefinitionIdentifier, spelling)),
                    self.store_context
                        .store
                        .declaration_candidate_rows_by_identifier_for_langs(
                            &langs,
                            self.store_context.generations.as_ref(),
                            spelling,
                        ),
                    format!("querying declarations by decorated identifier `{spelling}`"),
                ),
                IdentifierSeek::Prefix(prefix) => self.store_query_or_record(
                    |sink| sink.push(self.scope_read_key()),
                    self.store_context
                        .store
                        .declaration_candidate_rows_by_identifier_prefix_for_langs(
                            &langs,
                            self.store_context.generations.as_ref(),
                            prefix,
                        ),
                    format!("querying declarations by decorated identifier prefix `{prefix}`"),
                ),
            };
            rows.extend(decorated.unwrap_or_default());
        }
        let mut matches: BTreeSet<_> = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(&names)
            .collect();
        // `true`: dirty (edited-but-not-yet-persisted) file state must offer
        // the same membership as the widened SQL query above, or unsaved
        // edits to a definition-lookup-only unit would regress to invisible
        // while its persisted counterpart resolves.
        matches.extend(self.dirty_units_matching(true, &names));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(&names)
                .unwrap_or_default(),
        );
        matches
    }

    /// The file-scoped form of [`Self::lookup_declarations_by_identifier`].
    /// The persisted seek is narrowed by the live blob; the existing dirty and
    /// non-persisted merges retain the workspace lookup's membership rules.
    pub(crate) fn lookup_declarations_by_identifier_in_file(
        &self,
        file: &ProjectFile,
        identifier: &str,
    ) -> BTreeSet<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return BTreeSet::new();
        }
        let Some((storage_key, _generation)) = self.storage_key_and_generation(file) else {
            return BTreeSet::new();
        };
        let Some(blob_oid) = self.resolve_live_oid_for_file(file) else {
            return BTreeSet::new();
        };
        let rows = self
            .store_query_or_record(
                |sink| {
                    sink.push(self.file_read_key(file, blob_oid));
                    sink.push(ReadKey::index(
                        IndexFamily::DefinitionIdentifier,
                        identifier,
                    ));
                },
                self.store_context
                    .store
                    .declaration_candidate_rows_by_identifier_for_blob(
                        &storage_key,
                        self.store_context.generations.as_ref(),
                        blob_oid,
                        identifier,
                    ),
                format!("querying file-scoped declarations by identifier `{identifier}`"),
            )
            .unwrap_or_default();
        let mut matches = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(|unit| unit.source() == file)
            .collect::<BTreeSet<_>>();
        let keep = |unit: &CodeUnit| unit.source() == file && unit.identifier() == identifier;
        matches.extend(self.dirty_units_matching(true, keep));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(keep)
                .unwrap_or_default(),
        );
        matches
    }

    pub(crate) fn lookup_declarations_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        let langs = self.storage_language_keys_for_queries();
        let persisted = self
            .store_query_or_record(
                |sink| {
                    sink.push(ReadKey::index(
                        IndexFamily::DefinitionIdentifier,
                        identifier,
                    ))
                },
                self.store_context
                    .store
                    .declaration_candidate_rows_by_identifier_for_langs_limited(
                        &langs,
                        self.store_context.generations.as_ref(),
                        identifier,
                        limit,
                    ),
                format!("querying bounded declarations by identifier `{identifier}`"),
            )
            .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0));
        self.finish_limited_declaration_lookup(
            persisted,
            true,
            true,
            limit,
            |unit| unit.identifier() == identifier,
            continue_query,
        )
    }

    pub(crate) fn lookup_declarations_by_identifier_in_file_limited(
        &self,
        file: &ProjectFile,
        identifier: &str,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        if limit == 0 || !continue_query() {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::complete(Vec::new(), 0);
        };
        let Some(blob_oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::complete(Vec::new(), 0);
        };
        let generations = HashMap::from_iter([(storage_key.clone(), generation)]);
        let persisted = self
            .store_query_or_record(
                |sink| {
                    sink.push(self.file_read_key(file, blob_oid));
                    sink.push(ReadKey::index(
                        IndexFamily::DefinitionIdentifier,
                        identifier,
                    ));
                },
                self.store_context
                    .store
                    .declaration_candidate_rows_by_identifier_for_blob_limited(
                        &storage_key,
                        &generations,
                        blob_oid,
                        identifier,
                        limit,
                    ),
                format!("querying bounded file-scoped declarations by identifier `{identifier}`"),
            )
            .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0));
        let mut inspected = persisted.inspected;
        if !persisted.complete || inspected >= limit || !continue_query() {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }

        let resolved = self.resolve_candidate_rows_limited(
            persisted.rows,
            limit - inspected,
            &mut continue_query,
        );
        inspected = inspected.saturating_add(resolved.inspected);
        if !resolved.complete || inspected >= limit {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }
        let mut matches = resolved
            .rows
            .into_iter()
            .filter(|unit| unit.source() == file)
            .collect::<BTreeSet<_>>();
        let dirty = self.dirty_units_matching_limited(
            true,
            limit - inspected,
            |unit| unit.source() == file && unit.identifier() == identifier,
            &mut continue_query,
        );
        inspected = inspected.saturating_add(dirty.inspected);
        if !dirty.complete {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }
        matches.extend(dirty.rows);
        LimitedQueryRows::complete(matches.into_iter().collect(), inspected)
    }

    pub(crate) fn lookup_non_module_declarations_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        let langs = self.storage_language_keys_for_queries();
        let persisted = self
            .store_query_or_record(
                |sink| {
                    sink.push(ReadKey::index(
                        IndexFamily::DefinitionIdentifier,
                        identifier,
                    ))
                },
                self.store_context
                    .store
                    .declaration_candidate_rows_by_identifier_for_langs_limited(
                        &langs,
                        self.store_context.generations.as_ref(),
                        identifier,
                        limit,
                    ),
                format!("querying bounded non-module declarations by identifier `{identifier}`"),
            )
            .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0));
        self.finish_limited_declaration_lookup(
            persisted,
            true,
            false,
            limit,
            |unit| !unit.is_module() && unit.identifier() == identifier,
            continue_query,
        )
    }

    /// Persisted exact/normalized declaration lookup for a generation cache.
    /// A transient store failure is reported but never returned as an
    /// authoritative empty result, so callers can decline to publish it
    /// (#2795).
    pub(crate) fn try_lookup_declarations_by_persisted_fqn(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> Option<BTreeSet<CodeUnit>> {
        if !self.workspace_declaration_identities_authoritative() {
            return Some(BTreeSet::new());
        }
        use crate::analyzer::store::PersistedLookupKey;
        let key = if normalized {
            PersistedLookupKey::NormalizedFqn
        } else {
            PersistedLookupKey::ExactFqn
        };
        let lookup = if normalized {
            self.adapter.normalize_full_name(fqn)
        } else {
            fqn.to_string()
        };
        let rows = self.store_query_or_record(
            |sink| {
                sink.push(ReadKey::index(
                    if normalized {
                        IndexFamily::DefinitionNormalizedTail
                    } else {
                        IndexFamily::DefinitionExact
                    },
                    &lookup,
                ))
            },
            self.store_context
                .store
                .declaration_candidate_rows_by_lookup_key_for_langs(
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                    key,
                    &lookup,
                ),
            format!("querying declarations by persisted name `{lookup}`"),
        )?;
        let mut matches: BTreeSet<_> = self.resolve_candidate_rows(rows).into_iter().collect();
        matches.extend(self.dirty_units_matching(false, |unit| {
            let candidate = if normalized {
                self.adapter.normalize_full_name(&unit.fq_name())
            } else {
                unit.fq_name()
            };
            candidate == lookup
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                let candidate = if normalized {
                    self.adapter.normalize_full_name(&unit.fq_name())
                } else {
                    unit.fq_name()
                };
                candidate == lookup
            })?,
        );
        Some(matches)
    }

    pub(crate) fn lookup_declarations_by_persisted_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        use crate::analyzer::store::PersistedLookupKey;
        let key = if normalized {
            PersistedLookupKey::NormalizedFqn
        } else {
            PersistedLookupKey::ExactFqn
        };
        let lookup = if normalized {
            self.adapter.normalize_full_name(fqn)
        } else {
            fqn.to_string()
        };
        let persisted = self
            .store_query_or_record(
                |sink| {
                    sink.push(ReadKey::index(
                        if normalized {
                            IndexFamily::DefinitionNormalizedTail
                        } else {
                            IndexFamily::DefinitionExact
                        },
                        &lookup,
                    ))
                },
                self.store_context
                    .store
                    .declaration_candidate_rows_by_lookup_key_for_langs_limited(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                        key,
                        &lookup,
                        limit,
                    ),
                format!("querying bounded declarations by persisted name `{lookup}`"),
            )
            .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0));
        self.finish_limited_declaration_lookup(
            persisted,
            false,
            true,
            limit,
            |unit| {
                let candidate = if normalized {
                    self.adapter.normalize_full_name(&unit.fq_name())
                } else {
                    unit.fq_name()
                };
                candidate == lookup
            },
            continue_query,
        )
    }

    pub(crate) fn lookup_members_for_owner_name(
        &self,
        owner_fqn: &str,
        name: &str,
    ) -> BTreeSet<CodeUnit> {
        let exact_rows = self
            .store_query_or_record(
                |sink| sink.push(ReadKey::index(IndexFamily::DefinitionExact, owner_fqn)),
                self.store_context
                    .store
                    .declaration_member_rows_for_owner_for_langs(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                        owner_fqn,
                        false,
                        name,
                    ),
                format!("querying members named `{name}` for `{owner_fqn}`"),
            )
            .unwrap_or_default();
        let mut matches: BTreeSet<_> = self
            .resolve_candidate_rows(exact_rows)
            .into_iter()
            .collect();
        matches.extend(self.dirty_units_matching(false, |unit| {
            unit.identifier() == name && unit.fq_name() == format!("{owner_fqn}.{name}")
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                unit.identifier() == name && unit.fq_name() == format!("{owner_fqn}.{name}")
            })
            .unwrap_or_default(),
        );
        if !matches.is_empty() {
            return matches;
        }

        let normalized_owner = self.adapter.normalize_full_name(owner_fqn);
        let normalized_rows = self
            .store_query_or_record(
                |sink| {
                    sink.push(ReadKey::index(
                        IndexFamily::DefinitionNormalizedTail,
                        &normalized_owner,
                    ))
                },
                self.store_context
                    .store
                    .declaration_member_rows_for_owner_for_langs(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                        &normalized_owner,
                        true,
                        name,
                    ),
                format!("querying normalized members named `{name}` for `{owner_fqn}`"),
            )
            .unwrap_or_default();
        matches.extend(self.resolve_candidate_rows(normalized_rows));
        let normalized_member = self
            .adapter
            .normalize_full_name(&format!("{owner_fqn}.{name}"));
        matches.extend(self.dirty_units_matching(false, |unit| {
            unit.identifier() == name
                && self.adapter.normalize_full_name(&unit.fq_name()) == normalized_member
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                unit.identifier() == name
                    && self.adapter.normalize_full_name(&unit.fq_name()) == normalized_member
            })
            .unwrap_or_default(),
        );
        matches
    }

    pub(crate) fn lookup_members_for_owner_name_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        let langs = self.storage_language_keys_for_queries();
        let exact_persisted = self
            .store_query_or_record(
                |sink| sink.push(ReadKey::index(IndexFamily::DefinitionExact, owner_fqn)),
                self.store_context
                    .store
                    .declaration_member_rows_for_owner_for_langs_limited(
                        &langs,
                        self.store_context.generations.as_ref(),
                        owner_fqn,
                        false,
                        name,
                        limit,
                    ),
                format!("querying bounded members named `{name}` for `{owner_fqn}`"),
            )
            .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0));
        let exact_member = format!("{owner_fqn}.{name}");
        let exact = self.finish_limited_declaration_lookup(
            exact_persisted,
            false,
            true,
            limit,
            |unit| unit.identifier() == name && unit.fq_name() == exact_member,
            &mut continue_query,
        );
        if !exact.complete || !exact.rows.is_empty() {
            return exact;
        }
        if exact.inspected >= limit {
            return LimitedQueryRows::incomplete(Vec::new(), exact.inspected);
        }

        let normalized_owner = self.adapter.normalize_full_name(owner_fqn);
        let remaining = limit - exact.inspected;
        let normalized_persisted = self
            .store_query_or_record(
                |sink| {
                    sink.push(ReadKey::index(
                        IndexFamily::DefinitionNormalizedTail,
                        &normalized_owner,
                    ))
                },
                self.store_context
                    .store
                    .declaration_member_rows_for_owner_for_langs_limited(
                        &langs,
                        self.store_context.generations.as_ref(),
                        &normalized_owner,
                        true,
                        name,
                        remaining,
                    ),
                format!("querying bounded normalized members named `{name}` for `{owner_fqn}`"),
            )
            .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0));
        let normalized_member = self
            .adapter
            .normalize_full_name(&format!("{owner_fqn}.{name}"));
        let normalized = self.finish_limited_declaration_lookup(
            normalized_persisted,
            false,
            true,
            remaining,
            |unit| {
                unit.identifier() == name
                    && self.adapter.normalize_full_name(&unit.fq_name()) == normalized_member
            },
            continue_query,
        );
        let inspected = exact.inspected.saturating_add(normalized.inspected);
        if normalized.complete {
            LimitedQueryRows::complete(normalized.rows, inspected)
        } else {
            LimitedQueryRows::incomplete(Vec::new(), inspected)
        }
    }

    pub(crate) fn persisted_package_exists(&self, package: &str) -> bool {
        if !self
            .dirty_units_matching(false, |unit| unit.package_name() == package)
            .is_empty()
        {
            return true;
        }
        let rows = self
            .store_query_or_record(
                |sink| sink.push(ReadKey::index(IndexFamily::PackageMembership, package)),
                self.store_context
                    .store
                    .declaration_rows_by_package_for_langs(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                        package,
                    ),
                format!("querying declarations in package `{package}`"),
            )
            .unwrap_or_default();
        self.resolve_candidate_rows(rows)
            .into_iter()
            .any(|unit| unit.package_name() == package)
    }

    /// Conservatively gate a later exact C# FQN lookup without hydrating any
    /// declarations. The workspace membership view carries live-blob and
    /// generation filtering, and an unpublished declaration can add a true
    /// result. An overlay that removes the last declaration from a package can
    /// leave a stale `true` from the persisted snapshot; that is deliberately
    /// safe because this method only decides whether to perform the later
    /// structured FQN probe. It never turns a possible match into absence.
    ///
    /// A persisted miss is authoritative only when this analyzer accounts for
    /// every workspace package file. Partial package projection leaves the
    /// exact declaration indexes usable, so an incomplete inventory returns a
    /// conservative, cacheable `Some(true)` and lets C# perform the structured
    /// FQN probe. `None` is reserved for a store failure, which the generation
    /// cache must not publish as an answer (#2795). Callers that require exact
    /// overlay semantics use [`Self::persisted_package_exists`].
    pub(crate) fn try_persisted_package_may_exist(&self, package: &str) -> Option<bool> {
        let (authoritative_states, _) = self.authoritative_file_states_for_queries();
        if authoritative_states.iter().any(|state| {
            state
                .declarations
                .iter()
                .any(|unit| !unit.is_file_scope() && unit.package_name() == package)
        }) {
            return Some(true);
        }
        if !self.workspace_package_inventory_complete() {
            return Some(true);
        }
        self.store_query_or_record(
            |sink| sink.push(ReadKey::index(IndexFamily::PackageMembership, package)),
            self.store_context.store.workspace_package_exists_for_langs(
                &self.storage_language_keys_for_queries(),
                self.store_context.generations.as_ref(),
                self.selected_workspace_snapshots().as_ref(),
                package,
            ),
            format!("querying persisted package membership for `{package}`"),
        )
    }

    #[cfg(test)]
    pub(crate) fn delete_workspace_package_membership_for_test(&self, package: &str) {
        self.store_context
            .store
            .delete_workspace_package_membership_for_test(package);
    }

    /// The persisted path of `search_definitions_by_suffix_pattern`. Its
    /// contract (see `IAnalyzer`) is that every fully-qualified name `pattern`
    /// can match ends at the query path's tail, and that
    /// `terminal_identifiers` holds every way one persisted `identifier` can
    /// spell that tail. `idx_code_units_lang_identifier_lookup` indexes
    /// `(lang, identifier)`, so the candidate set is one seek per spelling
    /// rather than the whole-table walk
    /// `declaration_candidate_rows_by_pattern_for_langs` performs (#1688). On
    /// the CodeScale shared cache that walk reads 8.3 M `cpp` rows, each with a
    /// `WITHOUT ROWID` primary-key probe and a correlated active-blob EXISTS,
    /// once per workspace language, to return a handful of units: 194 s for one
    /// Go selector on Kubernetes, over 600 s on Firefox. The seeks answer the
    /// same selectors in 12.9 s and 0.55 s.
    ///
    /// The compiled regex stays authoritative over what is returned. Two
    /// candidate-set differences from the walk are deliberate:
    ///
    /// * `identifier IN (...)` is case sensitive while the regex is not, so the
    ///   tail must be spelled in its indexed case. Every other indexed lookup
    ///   `symbol_lookup` performs (`lookup_candidates_by_identifier`) already
    ///   requires that, and the stage that runs before this one is one of them.
    /// * The identifier index covers definition-lookup-only units as well as
    ///   declarations (#1088), so this stage now sees the same membership as
    ///   the short-name stage before it. `dirty_units_matching` widens to match,
    ///   for the reason `lookup_declarations_by_identifier` widens: an unsaved
    ///   edit must not make a unit less visible than its persisted counterpart.
    fn sql_search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
    ) -> Option<BTreeSet<CodeUnit>> {
        assert!(
            !pattern.is_empty() && !terminal_identifiers.is_empty(),
            "suffix search needs a pattern and its terminal identifiers, got {pattern:?} and {terminal_identifiers:?}"
        );
        let _scope = crate::profiling::scope(format!(
            "sql_search_definitions_by_suffix_pattern{terminal_identifiers:?}"
        ));
        let compiled = RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .ok()?;
        let spellings: Vec<&str> = terminal_identifiers.iter().map(String::as_str).collect();
        let rows = self.store_query_or_record(
            |sink| {
                for spelling in &spellings {
                    sink.push(ReadKey::index(IndexFamily::DefinitionIdentifier, spelling));
                }
            },
            self.store_context
                .store
                .declaration_candidate_rows_by_identifiers_for_langs(
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                    &spellings,
                ),
            format!("searching definitions with terminal identifiers {terminal_identifiers:?}"),
        )?;
        let mut out: BTreeSet<_> = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(|unit| self.fq_pattern_matches(unit, &compiled))
            .collect();
        out.extend(
            self.dirty_units_matching(true, |unit| self.fq_pattern_matches(unit, &compiled)),
        );
        out.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                self.fq_pattern_matches(unit, &compiled)
            })?,
        );
        Some(out)
    }

    fn sql_search_definitions(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Option<BTreeSet<CodeUnit>> {
        if pattern.is_empty() {
            return Some(BTreeSet::new());
        }

        let pattern = if auto_quote {
            if pattern.contains(".*") {
                pattern.to_string()
            } else {
                format!(".*?{}.*?", regex::escape(pattern))
            }
        } else {
            pattern.to_string()
        };
        let compiled = RegexBuilder::new(&pattern)
            .case_insensitive(true)
            .build()
            .ok()?;
        let storage_languages = self.storage_language_keys_for_queries();
        // A bare-literal pattern is its own substring prefilter (regex
        // filtering below stays authoritative either way).
        let substring_prefilter = literal_ascii_search_substring(&pattern);
        let _scope = crate::profiling::scope(format!(
            "sql_search_definitions[{pattern}][substring_prefilter={}]",
            substring_prefilter.is_some()
                && self
                    .adapter
                    .persisted_content_qualifier_supports_substring_search()
        ));
        let rows = if self
            .adapter
            .persisted_content_qualifier_supports_substring_search()
            && let Some(substring) = substring_prefilter
        {
            self.store_query_or_record(
                |sink| sink.push(self.scope_read_key()),
                self.store_context
                    .store
                    .declaration_candidate_rows_by_literal_substring_for_langs(
                        &storage_languages,
                        self.store_context.generations.as_ref(),
                        substring,
                    ),
                format!("searching definitions for `{pattern}`"),
            )?
        } else {
            // Nothing in the pattern narrows the store, so it can only answer
            // by reading every declaration of every language in play. Charge
            // that as the full scan it is: symbol lookup must never land here
            // (its suffix patterns carry their terminal identifiers and take
            // the indexed path above), so a test can pin that with the counter.
            self.full_declaration_scan_count
                .fetch_add(1, Ordering::Relaxed);
            self.store_query_or_record(
                |sink| sink.push(self.scope_read_key()),
                self.store_context
                    .store
                    .declaration_candidate_rows_by_pattern_for_langs(
                        &storage_languages,
                        self.store_context.generations.as_ref(),
                        &pattern,
                    ),
                format!("searching definitions for `{pattern}`"),
            )?
        };
        let mut out: BTreeSet<_> = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(|unit| self.fq_pattern_matches(unit, &compiled))
            .collect();
        out.extend(
            self.dirty_units_matching(false, |unit| self.fq_pattern_matches(unit, &compiled)),
        );
        out.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                self.fq_pattern_matches(unit, &compiled)
            })?,
        );
        Some(out)
    }

    /// fq-pattern match for search: adapters may normalize identifier sigils
    /// away (java maps `$` to `.` for nested-class display), so a literal
    /// sigil-suffixed name (`Foo$`, twitter's `javaGlobalNoDefault$`) is
    /// invisible when only the normalized fq is probed (#1127). Match the
    /// raw fq as well when it differs.
    fn fq_pattern_matches(&self, unit: &CodeUnit, compiled: &regex::Regex) -> bool {
        self.fq_matches(unit, |name| compiled.is_match(name))
    }

    fn fq_matches(&self, unit: &CodeUnit, matches: impl FnMut(&str) -> bool) -> bool {
        self.fq_name_matches(unit.package_name(), unit.short_name(), matches)
    }

    /// The authoritative symbol-search match predicate, expressed over the two
    /// fields `CodeUnit::fq_name` is built from.
    ///
    /// Taking the parts rather than a `CodeUnit` lets the persisted candidate
    /// scan decide matches before paying to construct a unit, without the
    /// bounded pre-pass and the final pass being able to disagree.
    fn fq_name_matches(
        &self,
        package_name: &str,
        short_name: &str,
        mut matches: impl FnMut(&str) -> bool,
    ) -> bool {
        // Mirrors `CodeUnit::fq_name`.
        let raw: Cow<'_, str> = if package_name.is_empty() {
            Cow::Borrowed(short_name)
        } else {
            Cow::Owned(format!("{package_name}.{short_name}"))
        };
        let fq_name = self.adapter.normalize_full_name(&raw);
        if self.adapter.is_anonymous_structure(&fq_name) {
            return false;
        }
        if matches(&fq_name) {
            return true;
        }
        fq_name != *raw && matches(&raw)
    }

    /// Carry the live half of a blob's fully-qualified names into the storage
    /// prefilter: which required literals its path-derived package prefixes
    /// supply, or that those prefixes cannot be enumerated at all.
    ///
    /// Without this the prefilter would drop declarations it must keep. A Rust
    /// declaration in `src/usages/finder.rs` has an empty persisted qualifier
    /// and the package `usages.finder` only after path hydration, so the pattern
    /// `usages.finder` requires the literals `usages` and `finder` that no
    /// persisted column of that row contains.
    fn active_search_blob(
        &self,
        snapshot: &LiveSnapshot,
        oid: Oid,
        per_pattern: &[Vec<String>],
    ) -> ActiveSearchBlob {
        let mut package_literals = String::new();
        let mut prefilter_exempt = false;
        for file in snapshot.paths_for_oid(oid) {
            let Some(package) = self.adapter.prefilter_path_package(file) else {
                prefilter_exempt = true;
                continue;
            };
            if package.is_empty() {
                continue;
            }
            let package = package.to_ascii_lowercase();
            // Required literals are already lowercase and cannot contain the
            // separator, so a hit is recorded as the literal itself rather than
            // as the whole prefix: the stored text stays empty for the blobs the
            // prefilter is meant to reject.
            for literal in per_pattern.iter().flatten() {
                if package.contains(literal.as_str())
                    && !package_literals.contains(literal.as_str())
                {
                    if !package_literals.is_empty() {
                        package_literals.push('\n');
                    }
                    package_literals.push_str(literal);
                }
            }
        }
        ActiveSearchBlob {
            oid,
            package_literals,
            prefilter_exempt,
        }
    }

    fn sql_search_symbol_candidates(
        &self,
        patterns: &SearchSymbolPatternBatch,
        cancellation: Option<&CancellationToken>,
    ) -> Option<SearchSymbolCandidates> {
        if patterns.patterns().is_empty() {
            return Some(SearchSymbolCandidates::complete(Vec::new(), 0));
        }
        if !patterns.complete() || cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Some(SearchSymbolCandidates::incomplete(Vec::new(), 0));
        }
        self.full_declaration_scan_count
            .fetch_add(1, Ordering::Relaxed);
        let langs = self.storage_language_keys_for_queries();
        let live_snapshot = self.live_snapshot();
        let required_literals = patterns.required_storage_literals();
        let active_blobs = {
            let _scope = profiling::scope("search_symbols.candidates.active_blobs");
            live_snapshot
                .oids()
                .map(|oid| match required_literals {
                    Some(per_pattern) => self.active_search_blob(&live_snapshot, oid, per_pattern),
                    None => ActiveSearchBlob::unfiltered(oid),
                })
                .collect::<Vec<_>>()
        };
        // Phase one enumerates only the names a pattern can match. Phase two
        // hydrates the full candidate projection for the keys that matched, so
        // signature text, primary ranges, and `CodeUnit` construction cost
        // proportionally to the answer instead of to the workspace (#1199).
        let name_rows = {
            let _scope = profiling::scope("search_symbols.candidates.load_names");
            self.store_query_or_record(
                |sink| sink.push(self.scope_read_key()),
                self.store_context
                    .store
                    .search_candidate_name_rows_for_langs(
                        &langs,
                        self.store_context.generations.as_ref(),
                        &active_blobs,
                        required_literals,
                        cancellation,
                    ),
                format!(
                    "searching symbol candidates for {} patterns",
                    patterns.patterns().len()
                ),
            )?
        };
        let resolver =
            QueryResolver::from_snapshot(self.adapter.as_ref(), self.project.root(), live_snapshot);
        let mut complete = name_rows.complete;
        let mut inspected = name_rows.inspected;
        let matched = {
            let _scope = profiling::scope("search_symbols.candidates.match_names");
            resolver.match_candidate_names_cancellable(
                &langs,
                &name_rows.rows,
                |package_name, short_name| {
                    self.fq_name_matches(package_name, short_name, |name| patterns.is_match(name))
                },
                cancellation,
            )
        };
        complete &= matched.complete;
        let rows = {
            let _scope = profiling::scope("search_symbols.candidates.hydrate_rows");
            self.store_query_or_record(
                |sink| sink.push(self.scope_read_key()),
                self.store_context.store.search_candidate_rows_for_keys(
                    &langs,
                    self.store_context.generations.as_ref(),
                    &matched.rows,
                    cancellation,
                ),
                format!("hydrating {} matched symbol candidates", matched.rows.len()),
            )?
        };
        complete &= rows.complete;
        self.search_candidate_hydration_count
            .fetch_add(rows.rows.len(), Ordering::Relaxed);
        let resolved = {
            let _scope = profiling::scope("search_symbols.candidates.resolve_rows");
            resolver.resolve_rows_with_payload_cancellable(
                rows.rows.into_iter().map(|row| {
                    let is_type_alias = row.candidate.flags.is_type_alias;
                    (
                        row.candidate,
                        (row.primary_range, row.in_test_region, is_type_alias),
                    )
                }),
                cancellation,
            )
        };
        inspected = inspected.saturating_add(resolved.inspected);
        complete &= resolved.complete;
        let mut candidates = BTreeMap::new();
        for (code_unit, (primary_range, in_test_region, is_type_alias)) in resolved.rows {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            inspected = inspected.saturating_add(1);
            if self.fq_matches(&code_unit, |name| patterns.is_match(name)) {
                candidates
                    .entry(code_unit.clone())
                    .or_insert(SearchSymbolCandidate {
                        code_unit,
                        primary_range,
                        in_test_region,
                        is_type_alias,
                    });
            }
        }

        let dirty = self.dirty_units_matching_limited(
            false,
            usize::MAX,
            |unit| self.fq_matches(unit, |name| patterns.is_match(name)),
            || !cancellation.is_some_and(CancellationToken::is_cancelled),
        );
        inspected = inspected.saturating_add(dirty.inspected);
        complete &= dirty.complete;
        for code_unit in dirty.rows {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            candidates
                .entry(code_unit.clone())
                .or_insert_with(|| SearchSymbolCandidate {
                    primary_range: self
                        .ranges(&code_unit)
                        .into_iter()
                        .min_by_key(|range| (range.start_line, range.start_byte)),
                    in_test_region: self.in_test_region(&code_unit),
                    is_type_alias: self.is_type_alias(&code_unit),
                    code_unit,
                });
        }

        let synthetic = self.sql_nonpersisted_workspace_declarations_vec_matching_cancellable(
            |unit| self.fq_matches(unit, |name| patterns.is_match(name)),
            cancellation,
        )?;
        inspected = inspected.saturating_add(synthetic.inspected);
        complete &= synthetic.complete;
        for code_unit in synthetic.rows {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            inspected = inspected.saturating_add(1);
            candidates
                .entry(code_unit.clone())
                .or_insert_with(|| SearchSymbolCandidate {
                    primary_range: self
                        .ranges(&code_unit)
                        .into_iter()
                        .min_by_key(|range| (range.start_line, range.start_byte)),
                    in_test_region: self.in_test_region(&code_unit),
                    is_type_alias: self.is_type_alias(&code_unit),
                    code_unit,
                });
        }

        let candidates = candidates.into_values().collect();
        if complete && !cancellation.is_some_and(CancellationToken::is_cancelled) {
            Some(SearchSymbolCandidates::complete(candidates, inspected))
        } else {
            Some(SearchSymbolCandidates::incomplete(candidates, inspected))
        }
    }

    pub(crate) fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.fetch_file_state(file)
            .map(|state| state.package_name.clone())
    }

    pub(crate) fn content_qualifier_of(&self, file: &ProjectFile) -> Option<String> {
        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        if let Some(content_qualifier) = self.state.dirty_content_qualifier(&key) {
            return Some(content_qualifier);
        }
        // See `storage_key_and_generation`: a foreign file has no persisted
        // qualifier here, and the snapshot fallbacks below refuse it too.
        let (storage_key, generation) = self.storage_key_and_generation(file)?;
        self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context
                .store
                .content_package(oid, &storage_key, generation),
            format!("querying the content qualifier for `{file}`"),
        )
        .flatten()
        .or_else(|| {
            self.source_snapshot_file_state(file)
                .map(|state| state.content_qualifier.clone())
        })
        .or_else(|| {
            self.fetch_file_state(file)
                .map(|state| state.content_qualifier.clone())
        })
    }

    pub(crate) fn relational_name_for_unit(
        &self,
        unit: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::RelationalName {
        let hydrated_qualifier = self.content_qualifier_of(unit.source()).unwrap_or_default();
        let stored_qualifier = self
            .adapter
            .storage_content_qualifier(unit, &hydrated_qualifier);
        crate::analyzer::store::relational_name_for_unit(
            self.adapter.as_ref(),
            unit,
            &stored_qualifier,
        )
    }

    pub(crate) fn file_namespace_hint_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        // One shared rule for every namespace-per-file spelling, bounded or not
        // (#1726): `declarations` is a HashSet and its persisted twin is keyed
        // by `unit_key`, so stopping at either one's first qualified unit makes
        // the answer depend on iteration order rather than on the source.
        fn from_state(state: &FileState, limit: usize) -> LimitedQueryRows<String> {
            file_namespace_from_top_level_declarations(
                &state.package_name,
                &state.top_level_declarations,
                limit,
            )
        }

        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return from_state(&state, limit);
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return from_state(&state, limit);
        }
        // See `storage_key_and_generation`.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let content_qualifier = self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context
                .store
                .content_package_limited(oid, &storage_key, generation, limit),
            format!("querying the bounded namespace qualifier for `{file}`"),
        );
        let Some(content_qualifier) = content_qualifier else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        if !content_qualifier.complete {
            return LimitedQueryRows::incomplete(Vec::new(), content_qualifier.inspected);
        }
        let inspected = content_qualifier.inspected;
        let Some(content_qualifier) = content_qualifier.rows.into_iter().next() else {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        };
        if !content_qualifier.is_empty() {
            return LimitedQueryRows::complete(vec![content_qualifier], inspected);
        }
        if inspected >= limit {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }
        let declaration_qualifier = self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context
                .store
                .first_declaration_content_qualifier_for_key_limited(
                    oid,
                    &storage_key,
                    generation,
                    limit - inspected,
                ),
            format!("querying a bounded declaration namespace for `{file}`"),
        );
        let Some(declaration_qualifier) = declaration_qualifier else {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        };
        let inspected = inspected.saturating_add(declaration_qualifier.inspected.max(1));
        if !declaration_qualifier.complete {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }
        LimitedQueryRows::complete(
            vec![
                declaration_qualifier
                    .rows
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
            ],
            inspected,
        )
    }

    pub(crate) fn ruby_method_dispatch_mode(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<RubyMethodDispatchMode> {
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.ruby_method_dispatch_modes.get(code_unit).copied())
    }

    pub(crate) fn ruby_method_dispatch_modes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<RubyMethodDispatchMode> {
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let file = code_unit.source();
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return limited_projection_rows(
                projection_value_for_unit(&state.ruby_method_dispatch_modes, code_unit)
                    .map(std::slice::from_ref),
                limit,
            );
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return limited_projection_rows(
                projection_value_for_unit(&state.ruby_method_dispatch_modes, code_unit)
                    .map(std::slice::from_ref),
                limit,
            );
        }
        // See `storage_key_and_generation`.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context
                .store
                .ruby_method_dispatch_modes_for_unit_limited(
                    oid,
                    &storage_key,
                    generation,
                    code_unit,
                    limit,
                ),
            format!(
                "querying Ruby method dispatch mode for `{}`",
                code_unit.fq_name()
            ),
        )
        .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0))
    }

    /// Every source of imports below is keyed by `(oid, rel_path)` -- the store
    /// hydration by oid and generation, both fallbacks by that exact cache key --
    /// so the result is a pure function of the retained key and can be served
    /// from `import_info_store` on any later request. The storage-language key
    /// is not part of it: every adapter derives it from the path alone, and the
    /// store lives on a per-adapter analyzer, so `(oid, rel_path)` already
    /// determines it.
    pub(crate) fn import_info_of(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Vec<ImportInfo> {
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return Vec::new();
        };
        let key = Self::transient_cache_key(oid, file);
        // The dirty overlay holds a parse the store has not accepted yet, and
        // is authoritative over anything retained.
        if let Some(imports) = self.state.dirty_imports(&key) {
            return imports;
        }
        if let Some(retained) = self.import_info_store_get(&key) {
            return retained.to_vec();
        }
        let storage_key = self.adapter.storage_language_key_for_file(file);
        // A file outside this adapter's own languages has no imports here, for
        // the same reason `fetch_file_state_for_key_with_source`,
        // `summary_file_projection` and the bounded
        // `import_info_for_oid_limited` refuse it: fan-outs legitimately ask
        // every provider about an arbitrary file, and this analyzer holds no
        // rows -- and no captured generation -- for a language it never built.
        // Without the refusal the foreign key reached `require_generation_map`,
        // whose `missing captured analyzer generation for <lang>` failure was
        // recorded on the request context and ended the whole tool call after
        // the scan had already produced its answer. On envoy the Kotlin
        // realm's descendant index resolves a Java peer's ancestors through
        // `kotlin_lexical_direct_ancestor_fqns`, which asks the Kotlin
        // analyzer for that Java file's imports, so a C++ scan returned no
        // JSON at all (#2913). The value was already empty on that path; only
        // the recorded failure is new.
        if !self.owns_storage_language_key(storage_key) {
            return Vec::new();
        }
        self.record_file_tier_access(InformationTier::Imports, file);
        let Some(imports) = self
            .store_query_or_record(
                |sink| sink.push(self.file_read_key(file, oid)),
                self.store_context.store.hydrate_import_infos_by_key(
                    &[(file.clone(), oid, storage_key.to_string())],
                    self.store_context.generations.as_ref(),
                    self.adapter.as_ref(),
                ),
                format!("hydrating imports for `{file}`"),
            )
            .and_then(|mut imports| imports.remove(file))
            .or_else(|| {
                self.source_snapshot_file_state(file)
                    .map(|state| state.imports.clone())
            })
            .or_else(|| {
                self.fetch_file_state(file)
                    .map(|state| state.imports.clone())
            })
        else {
            // A file with no answer at all keeps per-request-only negative
            // caching: retaining the empty vec would be indistinguishable from
            // a genuinely import-free file.
            return Vec::new();
        };
        let retained: Arc<[ImportInfo]> = Arc::from(imports);
        self.import_info_store_retain(key, Arc::clone(&retained));
        retained.to_vec()
    }

    fn import_info_store_get(&self, key: &FileStateCacheKey) -> Option<Arc<[ImportInfo]>> {
        self.import_info_store
            .lock()
            .expect("import info store mutex poisoned")
            .get(key)
    }

    fn import_info_store_retain(&self, key: FileStateCacheKey, imports: Arc<[ImportInfo]>) {
        self.import_info_store
            .lock()
            .expect("import info store mutex poisoned")
            .retain(key, imports);
    }

    fn import_info_for_oid_limited(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
        oid: Oid,
        limit: usize,
    ) -> LimitedQueryRows<ImportInfo> {
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return limited_projection_rows(Some(&state.imports), limit);
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return limited_projection_rows(Some(&state.imports), limit);
        }
        // Read through when the full vec happens to be retained, but never
        // populate from here: a bounded read returns `limit` rows, and
        // hydrating the full set instead would turn `workspace_import_info_
        // limited`'s budgeted sweep into a whole-workspace hydration.
        if let Some(retained) = self.import_info_store_get(&key) {
            return limited_projection_rows(Some(retained.as_ref()), limit);
        }
        // See `storage_key_and_generation`: `ImportAnalysisProvider` fan-outs
        // legitimately ask every provider about an arbitrary file.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context.store.import_infos_for_key_limited(
                oid,
                &storage_key,
                generation,
                limit,
            ),
            format!("querying bounded imports for `{file}`"),
        )
        .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0))
    }

    pub(crate) fn import_info_of_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<ImportInfo> {
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        self.import_info_for_oid_limited(token, file, oid, limit)
    }

    pub(crate) fn workspace_import_info_limited(
        &self,
        token: QueryToken<'_>,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<ImportInfo> {
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let snapshot = self.live_snapshot();
        let mut rows = Vec::new();
        let mut inspected = 0usize;
        for file in snapshot.all_paths() {
            if inspected == limit || !continue_query() {
                return LimitedQueryRows::incomplete(rows, inspected);
            }
            inspected += 1;
            let Some(oid) = snapshot.validated_oid_for_path(file) else {
                continue;
            };
            let Some(file) = self.rebase_live_file_to_project_root(file) else {
                continue;
            };
            if !self.adapter_owns_file(&file, &snapshot) {
                continue;
            }
            let imports = self.import_info_for_oid_limited(token, &file, oid, limit - inspected);
            inspected = inspected.saturating_add(imports.inspected);
            rows.extend(imports.rows);
            if !imports.complete {
                return LimitedQueryRows::incomplete(rows, inspected);
            }
        }
        LimitedQueryRows::complete(rows, inspected)
    }

    pub(crate) fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        let Some(state) = self.fetch_file_state(code_unit.source()) else {
            return Vec::new();
        };
        state
            .raw_supertypes
            .get(code_unit)
            .cloned()
            .or_else(|| {
                state
                    .raw_supertypes
                    .iter()
                    .find(|(owner, _)| {
                        owner.source() == code_unit.source()
                            && owner.kind() == code_unit.kind()
                            && owner.fq_name() == code_unit.fq_name()
                    })
                    .map(|(_, raw)| raw.clone())
            })
            .unwrap_or_default()
    }

    pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let file = code_unit.source();
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.raw_supertypes, code_unit),
                limit,
            );
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.raw_supertypes, code_unit),
                limit,
            );
        }
        // See `storage_key_and_generation`.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        self.record_file_tier_access(InformationTier::Supertypes, file);
        self.store_query_or_record(
            |sink| {
                sink.push(self.file_read_key(file, oid));
                sink.push(ReadKey::index(IndexFamily::Supertype, code_unit.fq_name()));
            },
            self.store_context.store.raw_supertypes_for_unit_limited(
                oid,
                &storage_key,
                generation,
                code_unit,
                limit,
            ),
            format!("querying raw supertypes for `{}`", code_unit.fq_name()),
        )
        .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0))
    }

    pub(crate) fn supertype_lookup_paths_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let file = code_unit.source();
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.supertype_lookup_paths, code_unit),
                limit,
            );
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.supertype_lookup_paths, code_unit),
                limit,
            );
        }
        // See `storage_key_and_generation`.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        self.store_query_or_record(
            |sink| {
                sink.push(self.file_read_key(file, oid));
                sink.push(ReadKey::index(
                    IndexFamily::SupertypeLookupPath,
                    code_unit.fq_name(),
                ));
            },
            self.store_context
                .store
                .supertype_lookup_paths_for_unit_limited(
                    oid,
                    &storage_key,
                    generation,
                    code_unit,
                    limit,
                ),
            format!(
                "querying structured supertype lookup paths for `{}`",
                code_unit.fq_name()
            ),
        )
        .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0))
    }

    pub(crate) fn is_scala_trait(&self, code_unit: &CodeUnit) -> bool {
        self.fetch_file_state(code_unit.source())
            .is_some_and(|state| state.scala_traits.contains(code_unit))
    }

    pub(crate) fn scala_traits(&self) -> Vec<CodeUnit> {
        self.sql_all_declarations_vec()
            .unwrap_or_default()
            .into_iter()
            .filter(|unit| self.is_scala_trait(unit))
            .collect()
    }

    pub(crate) fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.fetch_file_state(file)
            .map(|state| state.type_identifiers.clone())
    }

    pub(crate) fn all_files(&self) -> Vec<ProjectFile> {
        self.analyzed_live_files()
    }

    /// Every workspace file of this analyzer's language, taken from the
    /// project's shared file listing.
    ///
    /// This is deliberately not `all_files`/`analyzed_live_files`. That path
    /// validates every candidate blob key against the store -- on the #1758
    /// workspace, ~97 serial batched SQL round trips over ~38.6k C++ keys,
    /// 56.6s intrinsic and up to 227s under contention -- which only a caller
    /// that needs parse products can justify. A caller that needs file
    /// *identity* (a path -> `ProjectFile` map) reads the listing instead, and
    /// `all_files_shared` hands back the project's own cached `Arc` rather
    /// than deep-cloning the set.
    ///
    /// The result is a superset of the analyzed set: a file that exists in the
    /// workspace but has not been parsed yet is still a real workspace file.
    /// Every workspace file this adapter could own, from the workspace listing
    /// rather than from the analyzed set.
    ///
    /// The extension registry is the rule. A caller that also needs the files
    /// this adapter has *adopted* -- include-driven inference (#1837) gives an
    /// unclaimed-extension file to the adapter that includes it -- must union
    /// this with the analyzed set; adoption is not an extension property.
    pub(crate) fn workspace_language_files(&self) -> Vec<ProjectFile> {
        self.project
            .all_files_shared()
            .map(|files| {
                files
                    .iter()
                    .filter(|file| {
                        crate::analyzer::common::language_for_file(file) == self.adapter.language()
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn class_declarations_in_package(&self, package_name: &str) -> Vec<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        let mut matches = self.persisted_top_level_classes_in_package(package_name);
        matches.extend(self.dirty_units_matching(false, |unit| {
            unit.is_class() && unit.package_name() == package_name
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                unit.is_class() && unit.package_name() == package_name
            })
            .unwrap_or_default(),
        );

        matches.sort_by_cached_key(|code_unit| self.definition_sort_key_for_unit(code_unit));
        matches.dedup();
        matches
    }

    /// The persisted top-level class declarations whose hydrated package is
    /// exactly `package_name`.
    ///
    /// The store has no package-scoped predicate that agrees with the hydrated
    /// package identity (rows carry a persisted content qualifier; adapters may
    /// derive the live package from the path), so answering this needs the
    /// whole-workspace declaration scan followed by a hydrated filter. That is
    /// affordable once — not once per caller. C# import-graph candidate
    /// discovery asks it for every `using` directive of every workspace file,
    /// which turned one `scan_usages_by_reference` probe on StockSharp into
    /// tens of thousands of whole-workspace hydrations (#1194).
    ///
    /// So the scan is hoisted: one pass buckets *every* top-level class by its
    /// hydrated package, and the bucket map is retained for the active request
    /// through the same read cache that already holds hydrated file states. The
    /// rows, the hydration, and the package equality test are unchanged, so the
    /// returned set is identical either way; only the number of scans differs.
    /// Without an active query scope there is nothing to retain the map against,
    /// so the single-package path runs exactly as before.
    fn persisted_top_level_classes_in_package(&self, package_name: &str) -> Vec<CodeUnit> {
        let Some(cell) = self
            .query_read_cache_lock()
            .top_level_class_units_by_package_cell()
        else {
            return self
                .hydrated_persisted_top_level_classes(package_name)
                .into_iter()
                .filter(|unit| unit.package_name() == package_name)
                .collect();
        };

        // `get_or_init` runs on this thread's own `Arc` handle, not while the coarse
        // `query_read_cache` lock is held, and guarantees the hydration below runs at most once
        // even when many threads race here concurrently (#1194).
        let index = cell.get_or_init(|| {
            let units = self.hydrated_persisted_top_level_classes(package_name);
            let mut index: HashMap<String, Vec<CodeUnit>> = HashMap::default();
            for unit in units {
                index
                    .entry(unit.package_name().to_string())
                    .or_default()
                    .push(unit);
            }
            Arc::new(index)
        });
        index.get(package_name).cloned().unwrap_or_default()
    }

    fn hydrated_persisted_top_level_classes(&self, package_name: &str) -> Vec<CodeUnit> {
        self.package_declaration_scan_count
            .fetch_add(1, Ordering::Relaxed);
        let rows = self
            .store_query_or_record(
                |sink| sink.push(ReadKey::index(IndexFamily::PackageMembership, package_name)),
                self.store_context.store.mounted_declaration_rows_for_langs(
                    self.selected_workspace_snapshots().as_ref(),
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                ),
                format!("querying class declarations in package `{package_name}`"),
            )
            .unwrap_or_default()
            .into_iter()
            .filter(|row| {
                row.candidate.kind == CodeUnitType::Class && row.candidate.flags.is_top_level
            })
            .collect();
        self.store_query_or_record(
            |sink| sink.push(ReadKey::index(IndexFamily::PackageMembership, package_name)),
            self.resolve_mounted_candidate_rows(rows),
            format!("hydrating class declarations in package `{package_name}`"),
        )
        .unwrap_or_default()
    }

    fn query_read_cache_lock(&self) -> std::sync::RwLockReadGuard<'_, QueryReadCache> {
        self.query_read_cache
            .read()
            .expect("query read cache read lock poisoned")
    }

    /// Clone one request memo's handle out from under the coarse cache lock, or
    /// `None` with no request open. Generic over the handle's own type: most
    /// memos are `Arc<RwLock<Map>>`, the definition-candidate rows are an
    /// `Arc<KeyedPoolSafeMemo<..>>` that synchronizes itself.
    fn active_query_cache_handle<T: ?Sized>(
        &self,
        select: impl for<'a> FnOnce(&'a QueryReadCache) -> &'a Arc<T>,
    ) -> Option<Arc<T>> {
        let cache = self.query_read_cache_lock();
        cache.is_active().then(|| Arc::clone(select(&cache)))
    }

    /// The deadline of the request this read is running under, if its opener
    /// set one. Cloned once per read rather than consulted per row, so the
    /// coarse cache lock stays off the row loop.
    pub(crate) fn active_query_cancellation(&self) -> Option<CancellationToken> {
        self.query_read_cache_lock().active_cancellation()
    }

    pub(crate) fn active_query_semantic_model_overlay(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>> {
        self.query_read_cache_lock().active_semantic_model_overlay()
    }

    pub(crate) fn active_query_semantic_model_snapshot(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>> {
        self.query_read_cache_lock()
            .active_semantic_model_snapshot()
    }

    fn query_read_cache_write(&self) -> std::sync::RwLockWriteGuard<'_, QueryReadCache> {
        self.query_read_cache
            .write()
            .expect("query read cache write lock poisoned")
    }

    pub(crate) fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        let file = code_unit.source();
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return false;
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return state.type_aliases.contains(code_unit);
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return state.type_aliases.contains(code_unit);
        }
        if let Some(state) = self.query_file_state_snapshot(&key) {
            return state.type_aliases.contains(code_unit);
        }
        if !self.adapter.should_persist_code_unit(code_unit) {
            return self
                .fetch_file_state(file)
                .is_some_and(|state| state.type_aliases.contains(code_unit));
        }
        if let Some(aliases) = self.type_alias_store_get(&key) {
            return aliases.contains(code_unit);
        }
        // A unit from another language's file cannot be one of this analyzer's
        // type aliases, and its storage key is by design absent from this
        // adapter's generations (#1805). See `storage_key_and_generation`.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return false;
        };
        let aliases = self
            .store_query_or_record(
                |sink| sink.push(self.file_read_key(file, oid)),
                self.store_context.store.type_aliases_for_file(
                    oid,
                    &storage_key,
                    generation,
                    self.adapter.as_ref(),
                    file,
                ),
                format!("querying type aliases for `{file}`"),
            )
            .and_then(|aliases| aliases.map(Arc::<[CodeUnit]>::from))
            .or_else(|| {
                self.fetch_file_state(file)
                    .map(|state| Arc::from(state.type_aliases.iter().cloned().collect::<Vec<_>>()))
            });
        let Some(aliases) = aliases else {
            return false;
        };
        let is_alias = aliases.contains(code_unit);
        self.type_alias_store_retain(key, aliases);
        is_alias
    }

    fn type_alias_store_get(&self, key: &FileStateCacheKey) -> Option<Arc<[CodeUnit]>> {
        self.type_alias_store
            .lock()
            .expect("type alias store mutex poisoned")
            .get(key)
    }

    fn type_alias_store_retain(&self, key: FileStateCacheKey, aliases: Arc<[CodeUnit]>) {
        self.type_alias_store
            .lock()
            .expect("type alias store mutex poisoned")
            .retain(key, aliases);
    }

    /// The cached per-file enclosing-declaration index behind both the single
    /// and the batched enclosing queries: live file states first, then the
    /// index LRU, then one whole-file declaration-projection read. `None`
    /// means the store holds no projection for this reading, so the caller
    /// falls back to full hydration.
    fn enclosing_code_unit_index(
        &self,
        oid: Oid,
        key: &FileStateCacheKey,
        file: &ProjectFile,
    ) -> Option<Arc<EnclosingCodeUnitIndex>> {
        if let Some(state) = self.state.dirty_file_state(key) {
            return Some(self.enclosing_code_unit_index_from_state(key, &state));
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return Some(self.enclosing_code_unit_index_from_state(key, &state));
        }
        if let Some(state) = self.query_file_state_snapshot(key) {
            return Some(self.enclosing_code_unit_index_from_state(key, &state));
        }
        if let Some(index) = self
            .enclosing_code_unit_store
            .lock()
            .expect("enclosing code-unit store mutex poisoned")
            .get(key)
        {
            return Some(index);
        }
        // Keep this projection separate from any single-range query: it reads
        // only declaration identities and ranges, then the bounded index
        // answers every requested range.
        //
        // See `storage_key_and_generation`: `CodeUnitIndex` consumers fan a
        // file out to every provider, and this analyzer encloses nothing in a
        // file it never analyzed.
        let (storage_key, generation) = self.storage_key_and_generation(file)?;
        let declarations = self
            .store_query_or_record(
                |sink| sink.push(self.file_read_key(file, oid)),
                self.store_context.store.enclosing_declarations_for_file(
                    oid,
                    &storage_key,
                    generation,
                    self.adapter.as_ref(),
                    file,
                ),
                format!("querying enclosing declarations for `{file}`"),
            )
            .flatten()?;
        let index = Arc::new(EnclosingCodeUnitIndex::from_declaration_ranges(
            declarations,
        ));
        self.enclosing_code_unit_store
            .lock()
            .expect("enclosing code-unit store mutex poisoned")
            .retain(key.clone(), Arc::clone(&index));
        Some(index)
    }

    fn enclosing_code_unit_index_from_state(
        &self,
        key: &FileStateCacheKey,
        state: &FileState,
    ) -> Arc<EnclosingCodeUnitIndex> {
        if let Some(index) = self
            .enclosing_code_unit_store
            .lock()
            .expect("enclosing code-unit store mutex poisoned")
            .get(key)
        {
            return index;
        }
        let index = Arc::new(EnclosingCodeUnitIndex::from_file_state(state));
        self.enclosing_code_unit_store
            .lock()
            .expect("enclosing code-unit store mutex poisoned")
            .retain(key.clone(), Arc::clone(&index));
        index
    }

    pub(crate) fn enclosing_code_units_for_ranges(
        &self,
        file: &ProjectFile,
        ranges: &[Range],
    ) -> Option<Vec<Option<CodeUnit>>> {
        if !self.workspace_declaration_identities_authoritative() {
            return Some(vec![None; ranges.len()]);
        }
        self.enclosing_code_unit_query_count
            .fetch_add(ranges.len(), Ordering::Relaxed);
        if ranges.is_empty() {
            return Some(Vec::new());
        }

        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        let index = self.enclosing_code_unit_index(oid, &key, file)?;

        Some(
            ranges
                .iter()
                .map(|range| {
                    (range.start_byte < range.end_byte)
                        .then(|| index.enclosing_code_unit(range))
                        .flatten()
                })
                .collect(),
        )
    }

    pub(crate) fn signatures_vec_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        let signatures = self.signatures_limited(code_unit, usize::MAX);
        if signatures.complete {
            signatures.rows
        } else {
            self.fetch_file_state(code_unit.source())
                .and_then(|state| state.signatures.get(code_unit).cloned())
                .unwrap_or_default()
        }
    }

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let file = code_unit.source();
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.signatures, code_unit),
                limit,
            );
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.signatures, code_unit),
                limit,
            );
        }
        if let Some(state) = self.query_file_state_snapshot(&key) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.signatures, code_unit),
                limit,
            );
        }
        // See `storage_key_and_generation`.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context.store.signatures_for_unit_limited(
                oid,
                &storage_key,
                generation,
                code_unit,
                limit,
            ),
            format!("querying signatures for `{}`", code_unit.fq_name()),
        )
        .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0))
    }

    pub(crate) fn signature_metadata_vec_of(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.signature_metadata.get(code_unit).cloned())
            .unwrap_or_default()
    }

    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let file = code_unit.source();
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.signature_metadata, code_unit),
                limit,
            );
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.signature_metadata, code_unit),
                limit,
            );
        }
        if let Some(state) = self.query_file_state_snapshot(&key) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.signature_metadata, code_unit),
                limit,
            );
        }
        // See `storage_key_and_generation`.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context
                .store
                .signature_metadata_for_unit_limited(
                    oid,
                    &storage_key,
                    generation,
                    code_unit,
                    limit,
                ),
            format!("querying signature metadata for `{}`", code_unit.fq_name()),
        )
        .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0))
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<Range> {
        if !self.workspace_declaration_identities_authoritative() {
            return LimitedQueryRows::complete(Vec::new(), 0);
        }
        if limit == 0 {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        }
        let file = code_unit.source();
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(state) = self.state.dirty_file_state(&key) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.ranges, code_unit),
                limit,
            );
        }
        if let Some(state) = self.query_file_state_snapshot(&key) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.ranges, code_unit),
                limit,
            );
        }
        if let Some(state) = self.source_snapshot_file_state(file) {
            return limited_projection_rows(
                projection_rows_for_unit(&state.ranges, code_unit),
                limit,
            );
        }
        // See `storage_key_and_generation`.
        let Some((storage_key, generation)) = self.storage_key_and_generation(file) else {
            return LimitedQueryRows::incomplete(Vec::new(), 0);
        };
        self.store_query_or_record(
            |sink| sink.push(self.file_read_key(file, oid)),
            self.store_context.store.ranges_for_unit_limited(
                oid,
                &storage_key,
                generation,
                code_unit,
                limit,
            ),
            format!("querying ranges for `{}`", code_unit.fq_name()),
        )
        .unwrap_or_else(|| LimitedQueryRows::incomplete(Vec::new(), 0))
    }

    pub(crate) fn cpp_template_metadata_of(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<CppTemplateMetadata> {
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.cpp_template_metadata.get(code_unit).cloned())
    }

    fn source_slice(
        &self,
        code_unit: &CodeUnit,
        range: &Range,
        include_comments: bool,
    ) -> Option<String> {
        let file_state = self
            .source_snapshot_file_state(code_unit.source())
            .or_else(|| self.fetch_file_state(code_unit.source()))?;
        let start_byte = if include_comments {
            expanded_comment_start(
                self.adapter.language(),
                &file_state.source,
                range.start_byte,
            )
        } else {
            range.start_byte
        };
        file_state
            .source
            .get(start_byte..range.end_byte)
            .map(str::to_string)
    }

    fn render_skeleton_recursive(
        &self,
        code_unit: &CodeUnit,
        indent: &str,
        header_only: bool,
        out: &mut String,
    ) {
        for signature in self.signatures_vec_of(code_unit) {
            if signature.is_empty() {
                continue;
            }
            for line in signature.lines() {
                out.push_str(indent);
                out.push_str(line);
                out.push('\n');
            }
        }

        let all_children: Vec<_> =
            <Self as crate::analyzer::CodeUnitIndex>::direct_children(self, code_unit)
                .into_iter()
                .filter(|child| {
                    !child.is_synthetic()
                        || !<Self as crate::analyzer::CodeUnitIndex>::ranges(self, child).is_empty()
                })
                .collect();
        let field_children: Vec<_> = all_children
            .iter()
            .filter(|child| child.is_field())
            .cloned()
            .collect();
        let parent_start = <Self as crate::analyzer::CodeUnitIndex>::ranges(self, code_unit)
            .into_iter()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX);
        let non_field_children: Vec<_> = all_children
            .iter()
            .filter(|child| !child.is_field())
            .cloned()
            .collect();
        let children = if header_only {
            field_children.clone()
        } else {
            field_children
                .iter()
                .chain(
                    non_field_children
                        .iter()
                        .filter(|child| Self::child_first_start(self, child) >= parent_start),
                )
                .chain(
                    non_field_children
                        .iter()
                        .filter(|child| Self::child_first_start(self, child) < parent_start),
                )
                .cloned()
                .collect()
        };

        if !children.is_empty() || code_unit.is_class() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(&child, &child_indent, header_only, out);
            }
            if header_only && !non_field_children.is_empty() {
                out.push_str(&child_indent);
                out.push_str("[...]\n");
            }
            if code_unit.is_class() {
                out.push_str(indent);
                out.push_str("}\n");
            }
        }
    }
}

impl<A> TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    pub(crate) fn unit_matches_relational_request(
        &self,
        unit: &CodeUnit,
        request: &RelationalDefinitionRequest,
    ) -> bool {
        unit_matches_relational_request(self.adapter.as_ref(), unit, request)
    }

    pub(crate) fn record_store_error(&self, error: StoreError) {
        let contexts = self.query_read_cache_lock().contexts.clone();
        for context in contexts {
            context.record_store_error(error.clone());
        }
    }

    /// Route one analyzer-side store read through the request boundary: name
    /// the inputs it reads on every open read ledger, then record any failure.
    ///
    /// `reads` is a closure, not a key, so a run with no ledger attached never
    /// builds one. Every store call this analyzer makes goes through here and
    /// names its inputs; a store read that could not name them would record an
    /// unattributed read on the request context instead, and no such read
    /// exists today, which is what makes "the ledger saw every store read" a
    /// checked property rather than a claim.
    fn store_query_or_record<T>(
        &self,
        reads: impl FnOnce(&mut ReadKeySink<'_>),
        result: std::result::Result<T, StoreError>,
        operation: impl std::fmt::Display,
    ) -> Option<T> {
        self.record_reads(reads);
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.record_store_error(error.context(operation));
                None
            }
        }
    }

    fn child_first_start(&self, child: &CodeUnit) -> usize {
        <Self as crate::analyzer::CodeUnitIndex>::ranges(self, child)
            .into_iter()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RelationalRequestKey {
    language_scope: DefinitionLanguageScope,
    name: brokk_bifrost_core::analyzer::RelationalName,
    query: RelationalDefinitionQuery,
}

fn unit_matches_relational_request<A: LanguageAdapter>(
    adapter: &A,
    unit: &CodeUnit,
    request: &RelationalDefinitionRequest,
) -> bool {
    if unit.is_file_scope() {
        return false;
    }
    let full = request.name.full_name();
    let matches_name = |candidate: &crate::analyzer::FqName| {
        let interner = crate::analyzer::fq_name::segment_interner();
        if full.segments().iter().any(|&segment| {
            interner.resolve(segment).1 == crate::analyzer::fq_name::SegmentKind::Unknown
        }) {
            candidate.display_native(adapter.language(), interner)
                == full.display_native(adapter.language(), interner)
        } else {
            candidate == &full
        }
    };
    match &request.query {
        RelationalDefinitionQuery::ExactName | RelationalDefinitionQuery::CallableFacts => {
            matches_name(unit.fq())
        }
        RelationalDefinitionQuery::NormalizedName => {
            let normalized = adapter.normalize_fq_name(unit.fq());
            matches_name(&normalized)
        }
        RelationalDefinitionQuery::StructuralChildren => {
            unit.fq().parent().as_ref().is_some_and(matches_name)
        }
        RelationalDefinitionQuery::StructuralMembers { identifier } => {
            unit.fq().parent().as_ref().is_some_and(matches_name) && unit.identifier() == identifier
        }
        RelationalDefinitionQuery::VisibleMembers { identifier } => {
            (unit.fq().parent().as_ref().is_some_and(matches_name)
                || adapter.visibility_containers(unit).iter().any(matches_name))
                && unit.identifier() == identifier
        }
        RelationalDefinitionQuery::Identifier { file } => {
            let identifier = request
                .name
                .tail()
                .last()
                .map(|segment| {
                    crate::analyzer::fq_name::segment_interner()
                        .resolve(segment)
                        .0
                })
                .expect("RelationalName guarantees a non-empty tail");
            unit.identifier() == identifier
                && file
                    .as_ref()
                    .is_none_or(|expected| unit.source() == expected)
        }
        RelationalDefinitionQuery::IdentifierPrefix { file } => {
            let prefix = request
                .name
                .tail()
                .last()
                .map(|segment| {
                    crate::analyzer::fq_name::segment_interner()
                        .resolve(segment)
                        .0
                })
                .expect("RelationalName guarantees a non-empty tail");
            unit.identifier().starts_with(prefix)
                && file
                    .as_ref()
                    .is_none_or(|expected| unit.source() == expected)
        }
        RelationalDefinitionQuery::PackageTypes { simple_name } => {
            unit.is_class()
                && matches_name(&unit.package_fq())
                && adapter.simple_type_name(unit) == *simple_name
        }
        RelationalDefinitionQuery::PackageTypesInPackage => {
            unit.is_class() && matches_name(&unit.package_fq())
        }
        RelationalDefinitionQuery::PackageRelation(_) => false,
    }
}

fn merge_dirty_relational_value<A: LanguageAdapter>(
    adapter: &A,
    request: &RelationalDefinitionRequest,
    dirty_states: &[Arc<FileState>],
    dirty_paths: &HashSet<ProjectFile>,
    value: &mut RelationalDefinitionValue,
) {
    match value {
        RelationalDefinitionValue::Definitions(units) => {
            units.retain(|unit| !dirty_paths.contains(unit.source()));
            for state in dirty_states {
                units.extend(
                    state
                        .declarations
                        .iter()
                        .chain(&state.definition_lookup_units)
                        .filter(|unit| unit_matches_relational_request(adapter, unit, request))
                        .cloned(),
                );
            }
            crate::analyzer::sort_units(units);
            units.dedup();
        }
        RelationalDefinitionValue::CallableFacts(facts) => {
            facts.retain(|fact| !dirty_paths.contains(fact.declaration.source()));
            for state in dirty_states {
                for unit in state
                    .declarations
                    .iter()
                    .chain(&state.definition_lookup_units)
                    .filter(|unit| unit_matches_relational_request(adapter, unit, request))
                {
                    let signatures = state.signatures.get(unit);
                    let metadata = state.signature_metadata.get(unit);
                    let count = signatures
                        .map_or(0, Vec::len)
                        .max(metadata.map_or(0, Vec::len));
                    for ordinal in 0..count {
                        let signature = signatures
                            .and_then(|values| values.get(ordinal))
                            .cloned()
                            .or_else(|| unit.signature().map(str::to_string));
                        let Some(signature) = signature else {
                            continue;
                        };
                        facts.push(RelationalCallableFact {
                            declaration: unit.clone(),
                            signature_ordinal: ordinal,
                            signature,
                            metadata: metadata.and_then(|values| values.get(ordinal)).cloned(),
                        });
                    }
                }
            }
            facts.sort_by(|left, right| {
                crate::path_utils::rel_path_string(left.declaration.source())
                    .cmp(&crate::path_utils::rel_path_string(
                        right.declaration.source(),
                    ))
                    .then_with(|| left.declaration.fq_name().cmp(&right.declaration.fq_name()))
                    .then_with(|| left.signature_ordinal.cmp(&right.signature_ordinal))
            });
            facts.dedup();
        }
        RelationalDefinitionValue::PackageRelation(_) => {
            // Workspace package relations are reconciled from the same live
            // path snapshot as dirty file states. Milestone 3 parity tests own
            // the language-specific package overlay projections.
        }
    }
}

impl<A> RelationalDefinitionLookup for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn batch(
        &self,
        requests: &[RelationalDefinitionRequest],
        cancellation: &CancellationToken,
    ) -> RelationalBatchOutcome {
        if cancellation.is_cancelled() {
            return RelationalBatchOutcome::Cancelled;
        }

        let mut unique = Vec::new();
        let mut unique_by_key: HashMap<RelationalRequestKey, usize> = HashMap::default();
        let mut fanout = Vec::with_capacity(requests.len());
        for request in requests {
            let requires_named_subject = matches!(
                request.query,
                RelationalDefinitionQuery::ExactName
                    | RelationalDefinitionQuery::NormalizedName
                    | RelationalDefinitionQuery::Identifier { .. }
                    | RelationalDefinitionQuery::IdentifierPrefix { .. }
                    | RelationalDefinitionQuery::CallableFacts
            );
            if requires_named_subject && request.name.tail().is_empty() {
                return RelationalBatchOutcome::Failed(RelationalBatchError::new(format!(
                    "a definition or callable relational request requires a non-empty name tail: {request:?}"
                )));
            }
            let in_scope = match request.language_scope {
                DefinitionLanguageScope::Workspace => true,
                DefinitionLanguageScope::Language(language) => language == self.adapter.language(),
            };
            if !in_scope {
                fanout.push(None);
                continue;
            }
            let key = RelationalRequestKey {
                language_scope: request.language_scope.clone(),
                name: request.name.clone(),
                query: request.query.clone(),
            };
            let index = if let Some(index) = unique_by_key.get(&key) {
                *index
            } else {
                let index = unique.len();
                unique.push(request.clone());
                unique_by_key.insert(key, index);
                index
            };
            fanout.push(Some(index));
        }

        if !self.workspace_declaration_identities_authoritative() {
            return RelationalBatchOutcome::Complete(
                requests
                    .iter()
                    .map(|request| RelationalDefinitionResult {
                        ordinal: request.ordinal,
                        value: RelationalDefinitionValue::empty_for(&request.query),
                    })
                    .collect(),
            );
        }

        let storage_languages = self.storage_language_keys_for_queries();
        // Capture the mutable overlay once. The store applies it after all
        // relational rows have been hydrated but before committing the read
        // transaction, so a complete result has one snapshot boundary.
        let (dirty_states, dirty_paths) = self.authoritative_file_states_for_queries();
        self.record_reads(|sink| {
            for request in &unique {
                push_relational_request_reads(self, request, sink);
            }
        });
        let values = if unique.is_empty() {
            Vec::new()
        } else {
            self.relational_definition_batch_call_count
                .fetch_add(1, Ordering::Relaxed);
            let current = self.store_context.store.relational_definition_values(
                self.adapter.as_ref(),
                self.project.root(),
                self.store_context.generations.as_ref(),
                &storage_languages,
                self.selected_workspace_snapshots().as_ref(),
                &unique,
                cancellation,
                |values| {
                    assert_eq!(values.len(), unique.len());
                    for (request, value) in unique.iter().zip(values) {
                        merge_dirty_relational_value(
                            self.adapter.as_ref(),
                            request,
                            &dirty_states,
                            &dirty_paths,
                            value,
                        );
                    }
                },
            );
            match current {
                Ok(RelationalStoreOutcome::Complete(values)) => values,
                Ok(RelationalStoreOutcome::Cancelled) => {
                    return RelationalBatchOutcome::Cancelled;
                }
                Err(error) => {
                    self.record_store_error(error.clone());
                    return RelationalBatchOutcome::Failed(RelationalBatchError::new(
                        error.to_string(),
                    ));
                }
            }
        };
        assert_eq!(values.len(), unique.len());

        if cancellation.is_cancelled() {
            return RelationalBatchOutcome::Cancelled;
        }

        let results = requests
            .iter()
            .zip(fanout)
            .map(|(request, index)| RelationalDefinitionResult {
                ordinal: request.ordinal,
                value: index.map_or_else(
                    || RelationalDefinitionValue::empty_for(&request.query),
                    |index| values[index].clone(),
                ),
            })
            .collect();
        RelationalBatchOutcome::Complete(results)
    }
}

/// Record the inputs one relational definition question reads.
///
/// The family is the index the store probes to answer it. A members question
/// probes two: the owner by exact name and the member by identifier, so it
/// records both rather than folding one spelling under the other's family.
///
/// Two questions read the name index by *prefix* rather than by an exact key
/// -- an identifier prefix range, and the structural-children walk whose name
/// subject may be empty -- and an exact-key membership test can verify
/// neither, so those record the whole-language scope instead of an `Index` key
/// that would look precise and verify unsoundly.
fn push_relational_request_reads<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    request: &RelationalDefinitionRequest,
    sink: &mut ReadKeySink<'_>,
) {
    let name = request
        .name
        .full_name()
        .display(crate::analyzer::fq_name::segment_interner());
    match &request.query {
        RelationalDefinitionQuery::ExactName | RelationalDefinitionQuery::CallableFacts => {
            sink.push(ReadKey::index(IndexFamily::DefinitionExact, name));
        }
        RelationalDefinitionQuery::NormalizedName => {
            sink.push(ReadKey::index(IndexFamily::DefinitionNormalizedTail, name));
        }
        RelationalDefinitionQuery::Identifier { .. } => {
            sink.push(ReadKey::index(IndexFamily::DefinitionIdentifier, name));
        }
        RelationalDefinitionQuery::StructuralMembers { identifier }
        | RelationalDefinitionQuery::VisibleMembers { identifier } => {
            sink.push(ReadKey::index(IndexFamily::DefinitionExact, name));
            sink.push(ReadKey::index(
                IndexFamily::DefinitionIdentifier,
                identifier,
            ));
        }
        RelationalDefinitionQuery::PackageTypes { simple_name } => {
            sink.push(ReadKey::index(IndexFamily::PackageMembership, name));
            sink.push(ReadKey::index(
                IndexFamily::DefinitionIdentifier,
                simple_name,
            ));
        }
        RelationalDefinitionQuery::PackageTypesInPackage
        | RelationalDefinitionQuery::PackageRelation(_) => {
            sink.push(ReadKey::index(IndexFamily::PackageMembership, name));
        }
        RelationalDefinitionQuery::IdentifierPrefix { .. }
        | RelationalDefinitionQuery::StructuralChildren => sink.push(analyzer.scope_read_key()),
    }
}

impl<A> crate::analyzer::CodeUnitIndex for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    /// The request-memoized [`ClassRangeIndex`] (#2679). With no scope open
    /// there is no memo and the behaviour is exactly the unmemoized build,
    /// like `definition_parent_unit`.
    fn class_range_index(&self, file: &ProjectFile) -> Arc<ClassRangeIndex> {
        let class_ranges = self.active_query_cache_handle(|cache| &cache.class_ranges);
        let cached = class_ranges.as_ref().and_then(|class_ranges| {
            class_ranges
                .read()
                .expect("query class-range cache read lock poisoned")
                .get(file)
                .cloned()
        });
        if let Some(index) = cached {
            return index;
        }
        let index = Arc::new(ClassRangeIndex::build(self, file));
        if let Some(class_ranges) = class_ranges.as_ref() {
            class_ranges
                .write()
                .expect("query class-range cache write lock poisoned")
                .insert(file.clone(), Arc::clone(&index));
        }
        index
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        self.enclosing_code_unit_query_count
            .fetch_add(1, Ordering::Relaxed);
        if range.start_byte >= range.end_byte {
            return None;
        }

        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        // One bounded per-file index answers every range in this file. Usage
        // scans ask for the enclosing declaration of hundreds of occurrence
        // sites per file; a per-range store query here turned each site into
        // its own SQL round trip (54,890 point queries in one exposed-kotlin
        // `scan_usages` request), while the batched
        // `enclosing_code_units_for_ranges` path already built and cached this
        // exact index from one declaration-projection read.
        if let Some(index) = self.enclosing_code_unit_index(oid, &key, file)
            && let Some(unit) = index.enclosing_code_unit(range)
        {
            return Some(unit);
        }

        self.fetch_file_state(file)
            .and_then(|state| enclosing_code_unit_from_state(&state, range))
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        let line_range = Range {
            start_byte: 0,
            end_byte: usize::MAX,
            start_line,
            end_line,
        };
        self.declarations(file)
            .into_iter()
            .filter_map(|code_unit| {
                let best_range = self.ranges(&code_unit).into_iter().find(|candidate| {
                    candidate.start_line <= line_range.start_line
                        && candidate.end_line >= line_range.end_line
                })?;
                Some((best_range.end_line - best_range.start_line, code_unit))
            })
            .min_by_key(|(span, _)| *span)
            .map(|(_, code_unit)| code_unit)
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.fetch_file_state(file)
            .map(|state| {
                state
                    .top_level_declarations
                    .iter()
                    .filter(|code_unit| !code_unit.is_file_scope())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn summary_file_projection(&self, file: &ProjectFile) -> Option<Arc<SummaryFileProjection>> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        let _scope = profiling::scope(format!(
            "TreeSitterAnalyzer::{:?}::summary_file_projection",
            self.adapter.language()
        ));
        if self.project.has_overlay(file) {
            return None;
        }
        let storage_key = self.adapter.storage_language_key_for_file(file);
        // Multi-analyzer consumers may fan out a file to every provider. A
        // foreign file has no summary in this analyzer and, critically, no
        // generation entry in this analyzer's storage context.
        if !self.owns_storage_language_key(storage_key) {
            return None;
        }
        let oid = self.resolve_live_oid_for_file(file)?;
        let cache_key = Self::transient_cache_key(oid, file);
        if let Some(projection) = self
            .summary_file_projections
            .lock()
            .expect("summary file projection cache mutex poisoned")
            .get(&cache_key)
        {
            return Some(projection);
        }
        let generation = self.store_context.generations.get(storage_key).copied()?;
        let source = self.source_for_oid(file, oid)?;
        let mut projection = self
            .store_query_or_record(
                |sink| sink.push(self.file_read_key(file, oid)),
                self.store_context.store.summary_file_projection(
                    oid,
                    storage_key,
                    generation,
                    self.adapter.as_ref(),
                    file,
                    &source,
                ),
                format!("hydrating summary projection for `{file}`"),
            )
            .flatten()?;
        for children in projection.children.values_mut() {
            Self::canonicalize_children(children, &projection.ranges);
        }
        let projection = Arc::new(projection);
        self.summary_file_projections
            .lock()
            .expect("summary file projection cache mutex poisoned")
            .insert(cache_key, Arc::clone(&projection));
        Some(projection)
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.analyzed_live_files()
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.file_source(file)
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        let Some(indexed_oid) = self.indexed_live_snapshot.oid_for_path(file) else {
            return false;
        };
        self.blob_oid_of(file, source) == indexed_oid
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return false;
        };
        self.adapter_owns_file(file, &self.live_snapshot()) && {
            let storage_key = self.adapter.storage_language_key_for_file(file);
            let key = Self::transient_cache_key(oid, file);
            self.retry_dirty_file_state(&key, storage_key).is_some()
                || self
                    .store_query_or_record(
                        |sink| sink.push(self.file_read_key(file, oid)),
                        self.store_context.store.contains_parsed_blob_at_generation(
                            oid,
                            storage_key,
                            self.store_context.generations[storage_key],
                        ),
                        format!("checking whether `{file}` is analyzed"),
                    )
                    .unwrap_or(false)
        }
    }

    /// [`is_analyzed`] for a whole candidate set, spending one store query
    /// instead of one per candidate.
    ///
    /// Each candidate is filtered by the same ownership and live-identity rules
    /// `is_analyzed` applies, and the survivors that are not already answered by
    /// a retained dirty state are confirmed in a single
    /// `parsed_blob_keys_at_generations` call -- the same query
    /// [`Self::analyzed_live_files`] makes, over the candidates instead of over
    /// the whole workspace. That is the point: a glob target that matched three
    /// files must cost three files' worth of work, not a workspace scan per
    /// language (#1738).
    ///
    /// [`is_analyzed`]: CodeUnitIndex::is_analyzed
    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        if candidates.is_empty() {
            return Vec::new();
        }
        let _scope = profiling::scope_with(|| {
            format!(
                "analyzer::retain_analyzed[{:?},{} candidates]",
                self.adapter.language(),
                candidates.len()
            )
        });
        let snapshot = self.live_snapshot();
        let mut analyzed = Vec::new();
        // Candidates whose membership only the store can settle. Collected
        // first so they cost one query between them, not one each.
        let mut persisted_candidates = Vec::new();
        for candidate in candidates {
            if !self.adapter_owns_file(candidate, &snapshot) {
                continue;
            }
            let Some(oid) = self.resolve_live_oid_for_file(candidate) else {
                continue;
            };
            let storage_key = self.adapter.storage_language_key_for_file(candidate);
            let key = Self::transient_cache_key(oid, candidate);
            if self.retry_dirty_file_state(&key, storage_key).is_some() {
                analyzed.push(candidate.clone());
                continue;
            }
            persisted_candidates.push((candidate, oid, storage_key));
        }
        if persisted_candidates.is_empty() {
            analyzed.sort();
            return analyzed;
        }
        let keys = persisted_candidates
            .iter()
            .map(|(_, oid, storage_key)| (*oid, storage_key.to_string()))
            .collect::<Vec<_>>();
        let present = self
            .store_query_or_record(
                |sink| {
                    for (candidate, oid, _) in &persisted_candidates {
                        sink.push(self.file_read_key(candidate, *oid));
                    }
                },
                self.store_context.store.parsed_blob_keys_at_generations(
                    &keys,
                    self.store_context.generations.as_ref(),
                ),
                "checking whether matched files are analyzed",
            )
            .unwrap_or_default();
        for (candidate, oid, storage_key) in persisted_candidates {
            if present.contains(&(oid, storage_key.to_string())) {
                analyzed.push(candidate.clone());
            }
        }
        analyzed.sort();
        analyzed
    }

    fn languages(&self) -> BTreeSet<Language> {
        BTreeSet::from([self.adapter.language()])
    }

    fn project(&self) -> &dyn Project {
        self.project()
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        if !self.workspace_declaration_identities_authoritative() {
            return Box::new(std::iter::empty());
        }
        Box::new(
            self.sql_all_declarations_vec()
                .unwrap_or_default()
                .into_iter(),
        )
    }

    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.sql_all_declarations_with_primary_ranges_vec()
            .unwrap_or_default()
    }

    fn materialization_records(&self, file: &ProjectFile) -> Vec<MaterializationRecord> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.materialization_records_of(file)
    }

    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return BTreeSet::new();
        }
        self.structural_file_state(file)
            .map(|state| {
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return BTreeSet::new();
        }
        self.fetch_file_state(file)
            .or_else(|| self.fetch_file_state_from_current_source(file))
            .map(|state| {
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        if !self.workspace_declaration_identities_authoritative() {
            return Box::new(std::iter::empty());
        }
        let definitions = match self.sql_definitions_vec(fq_name) {
            Ok(definitions) => definitions,
            Err(error) => {
                self.record_store_error(error);
                Vec::new()
            }
        };
        Box::new(definitions.into_iter())
    }

    fn prefetch_definitions(&self, fq_names: &[String]) {
        TreeSitterAnalyzer::prefetch_definitions(self, fq_names);
    }

    /// Seek the terminal identifier, then compare whole names.
    ///
    /// The persisted `exact_fqn` column cannot answer this: an anchored
    /// identity stores only its tail plus the anchor, and the rendered name
    /// is reassembled from the declaring file at hydration time. The
    /// identifier index is the one the store keys on a segment the name
    /// carries verbatim, and it narrows a workspace scan to the declarations
    /// that can possibly match.
    fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
        let fq_name = unit.fq_name();
        self.lookup_declarations_by_identifier(unit.identifier())
            .into_iter()
            .filter(|candidate| candidate.fq_name() == fq_name)
            .collect()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        if code_unit.is_module() && self.adapter.language() == Language::Java {
            return self.class_declarations_in_package(&code_unit.fq_name());
        }

        self.direct_children_in_file(code_unit)
    }

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.fetch_file_state(code_unit.source())
            .and_then(|state| {
                let mut children = state.children.get(code_unit).cloned()?;
                Self::canonicalize_children(&mut children, &state.ranges);
                Some(children)
            })
            .unwrap_or_default()
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.source_snapshot_file_state(code_unit.source())
            .or_else(|| self.fetch_file_state(code_unit.source()))
            .and_then(|state| state.ranges.get(code_unit).cloned())
            .or_else(|| {
                self.fetch_file_state_from_current_source(code_unit.source())
                    .and_then(|state| state.ranges.get(code_unit).cloned())
            })
            .unwrap_or_default()
    }

    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.structural_file_state(code_unit.source())
            .and_then(|state| state.ranges.get(code_unit).cloned())
            .unwrap_or_default()
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<Range>, usize, bool) {
        if !self.workspace_declaration_identities_authoritative() {
            return (Vec::new(), 0, false);
        }
        if max_ranges == 0 || cancellation.is_cancelled() {
            return (Vec::new(), 0, true);
        }
        let limited = self.ranges_limited(code_unit, max_ranges);
        (
            limited.rows,
            limited.inspected,
            !limited.complete || cancellation.is_cancelled(),
        )
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", false, &mut rendered);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", true, &mut rendered);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        let sources = self.get_sources(code_unit, include_comments);
        if sources.is_empty() {
            None
        } else {
            Some(sources.into_iter().collect::<Vec<_>>().join("\n\n"))
        }
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return BTreeSet::new();
        }
        let mut ranges = if code_unit.is_function() {
            // A function's source merges every same-file definition that
            // renders the same fq name (overload groups, split definitions).
            // Those siblings all live in the file's own declaration state, so
            // read them there: a global definitions() name lookup resolves
            // arbitrary spellings through per-component rendered seeks, which
            // costs a multiple of this file-scoped read and adds nothing when
            // the request is a stored unit's own rendering.
            let _scope = profiling::scope("TreeSitterAnalyzer::get_sources::definitions");
            let fq_name = code_unit.fq_name();
            let mut grouped = Vec::new();
            for candidate in self.declarations(code_unit.source()) {
                if candidate.is_function() && candidate.fq_name() == fq_name {
                    grouped.extend(self.ranges(&candidate));
                }
            }
            grouped
        } else {
            self.ranges(code_unit)
        };

        ranges.sort_by_key(|range| range.start_byte);
        ranges
            .into_iter()
            .filter_map(|range| self.source_slice(code_unit, &range, include_comments))
            .collect()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return BTreeSet::new();
        }
        self.sql_search_definitions(pattern, auto_quote)
            .unwrap_or_default()
    }

    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        _language: Language,
    ) -> BTreeSet<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return BTreeSet::new();
        }
        self.sql_search_definitions_by_suffix_pattern(pattern, terminal_identifiers)
            .unwrap_or_default()
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        if !self.workspace_declaration_identities_authoritative() {
            return BTreeSet::new();
        }
        self.sql_lookup_candidates_by_short_name(symbol)
            .unwrap_or_default()
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.lookup_declarations_by_identifier(identifier)
    }

    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.workspace_declaration_identities_authoritative()
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.signatures_vec_of(code_unit)
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        self.signature_metadata_vec_of(code_unit)
    }
}

impl<A> crate::analyzer::IAnalyzer for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn claimed_files(&self) -> Vec<ProjectFile> {
        if !self.adapter.claims_included_files() {
            return Vec::new();
        }
        self.store_context
            .live_paths
            .files()
            .into_iter()
            .filter(|file| {
                crate::analyzer::common::language_for_file(file) != self.adapter.language()
            })
            .collect()
    }

    fn invalidate_cached_file_identities(&self) {
        if let Some(liveness) = self.store_context.liveness.as_ref() {
            liveness.invalidate_startup_oids();
        }
    }

    fn invalidate_cached_file_identities_for(&self, changed_files: &BTreeSet<ProjectFile>) {
        if let Some(liveness) = self.store_context.liveness.as_ref() {
            liveness
                .invalidate_startup_oids_for_files(changed_files)
                .unwrap_or_else(|error| {
                    panic!("failed to invalidate changed file identities: {error}")
                });
        }
    }

    fn working_tree_identity(&self) -> Option<Arc<gitblob::WorkingTreeIdentity>> {
        self.store_context
            .liveness
            .as_ref()
            .and_then(|liveness| liveness.taken_startup_identity())
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        let mut cache = self.query_read_cache_write();
        let was_active = cache.is_active();
        let registered = cache.begin(context);
        if registered && context.read_ledger().is_some() {
            self.attached_read_ledgers.fetch_add(1, Ordering::Relaxed);
        }
        if !was_active {
            self.live_source_snapshot.store(None);
            self.query_file_state_snapshot.store(None);
        }
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        let mut cache = self.query_read_cache_write();
        let was_active = cache.is_active();
        let retired = cache.end(context);
        if retired && context.read_ledger().is_some() {
            let before = self.attached_read_ledgers.fetch_sub(1, Ordering::Relaxed);
            debug_assert!(before > 0, "an attached read ledger was retired twice");
        }
        if was_active && !cache.is_active() {
            self.live_source_snapshot.store(None);
            self.query_file_state_snapshot.store(None);
        }
    }

    fn record_read(&self, key: crate::analyzer::read_ledger::ReadKey) {
        TreeSitterAnalyzer::record_read_key(self, key);
    }

    fn record_unattributed_read(&self) {
        TreeSitterAnalyzer::record_unattributed_read(self);
    }

    fn read_ledger_attached(&self) -> bool {
        TreeSitterAnalyzer::read_ledger_attached(self)
    }

    fn active_query_cancellation(&self) -> Option<CancellationToken> {
        TreeSitterAnalyzer::active_query_cancellation(self)
    }

    fn prefetch_definitions(&self, fq_names: &[String]) {
        TreeSitterAnalyzer::prefetch_definitions(self, fq_names);
    }

    fn active_query_semantic_model_overlay(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>> {
        TreeSitterAnalyzer::active_query_semantic_model_overlay(self)
    }

    fn active_query_semantic_model_snapshot(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>> {
        TreeSitterAnalyzer::active_query_semantic_model_snapshot(self)
    }

    fn begin_streaming_file_read(&self, file: &ProjectFile) {
        TreeSitterAnalyzer::begin_streaming_file_read(self, file);
    }

    fn end_streaming_file_read(&self, file: &ProjectFile) {
        TreeSitterAnalyzer::end_streaming_file_read(self, file);
    }

    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.query_read_cache_lock().workspace_file_index_cell()
    }

    fn definition_lookup_memo(&self) -> Option<Arc<crate::analyzer::DefinitionLookupMemo>> {
        self.active_query_cache_handle(|cache| &cache.definition_lookup)
    }

    fn record_query_failure(&self, error: StoreError) {
        TreeSitterAnalyzer::record_store_error(self, error);
    }

    fn declaration_syntax_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        if !self.workspace_declaration_identities_authoritative() {
            return None;
        }
        let scope = crate::analyzer::AnalyzerQueryScope::new(self);
        let syntax = self.prepared_syntax(scope.token(), code_unit.source())?;
        let mut node = syntax.declaration_node(code_unit)?;
        let fallback = node.kind();
        loop {
            if matches!(
                node.kind(),
                "class_declaration"
                    | "interface_declaration"
                    | "annotation_type_declaration"
                    | "enum_declaration"
                    | "record_declaration"
            ) {
                return Some(node.kind());
            }
            node = node.parent()?;
            if node.kind() == "program" {
                return Some(fallback);
            }
        }
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        if changed_files.is_empty() {
            return self.clone();
        }
        if changed_files
            .iter()
            .any(|file| self.adapter.workspace_package_identity_input(file))
        {
            return self.update_all();
        }

        let mut store_context = self.store_context.clone();
        store_context.live_paths = Arc::new(
            self.store_context
                .live_paths
                .fork_from_snapshot(Arc::clone(&self.indexed_live_snapshot)),
        );
        let mut relational_workspace_snapshots =
            self.selected_workspace_snapshots().as_ref().clone();
        let mut to_update = Vec::new();
        let mut claim_roots = Vec::new();
        let mut new_claimable_file_appeared = false;
        let mut dirty_file_states = self.state.dirty_snapshot();
        let mut dirty_path_symbol_rows = self.state.dirty_path_symbol_snapshot();
        let live = self.live_snapshot();

        for file in changed_files {
            Self::remove_dirty_for_file(&mut dirty_file_states, file);
            if !file.exists() && !self.project.has_overlay(file) {
                store_context
                    .live_paths
                    .remove(std::iter::once(file.clone()));
                if let Some(liveness) = store_context.liveness.as_ref() {
                    liveness.remove_overlay_paths(std::iter::once(file.clone()));
                }
                // A deleted file contributes no claim edges. Feeding it to the
                // inference roots is what retires the ones it used to own.
                claim_roots.push(file.clone());
                continue;
            }
            // A changed file whose extension names no language reaches this
            // adapter only once inference has claimed it (#1837); an unclaimed
            // one must not be parsed as this language.
            if !self.adapter_owns_file(file, &live) {
                // A claimable file that did not exist last generation can turn
                // an `#include` that resolved to nothing into a claim, and the
                // includer itself did not change. Re-deriving the whole relation
                // is the only way to find out -- but only for a file some
                // recorded import directive could actually name (#1865). Every
                // other creation (a `.md`, a `.txt`, a `.json` in a C++
                // workspace) is local to itself: the demand record is written
                // from the same import facts the derivation reads, so a miss is
                // proof that re-deriving would claim nothing new.
                new_claimable_file_appeared |= self.adapter.claims_included_files()
                    && crate::analyzer::common::has_unclaimed_extension(file)
                    && self
                        .state
                        .tier_demand
                        .is_demanded(InformationTier::Imports, file);
                continue;
            }
            to_update.push(file.clone());
            claim_roots.push(file.clone());
        }

        let mut state = Self::reconcile_file_states(
            self.project.as_ref(),
            self.adapter.as_ref(),
            &self.config,
            &store_context,
            ReconcileFileStates {
                files: to_update,
                replace_live_paths: false,
                progress: None,
                dirty_file_states,
                dirty_path_symbol_rows,
            },
        );
        state.workspace_package_inventory_complete &=
            self.state.workspace_package_inventory_complete;
        state.workspace_package_identity_input_digests =
            self.state.workspace_package_identity_input_digests.clone();
        if new_claimable_file_appeared {
            claim_roots.extend(
                live.all_paths()
                    .filter(|file| {
                        crate::analyzer::common::language_for_file(file) == self.adapter.language()
                    })
                    .cloned(),
            );
            claim_roots.sort();
            claim_roots.dedup();
        }
        let claim_delta = Self::reconcile_claimed_files(
            self.project.as_ref(),
            self.adapter.as_ref(),
            &self.config,
            &store_context,
            &claim_roots,
            RetainedClaimRelation {
                edges: self.state.claim_edges.clone(),
                demand: self.state.tier_demand.clone(),
            },
            &mut state,
        );
        let mut workspace_paths_to_refresh = changed_files.clone();
        workspace_paths_to_refresh.extend(claim_delta.added);
        workspace_paths_to_refresh.extend(claim_delta.dropped);
        dirty_path_symbol_rows = state.dirty_path_symbol_snapshot();
        Self::refresh_path_symbol_units(
            self.adapter.as_ref(),
            &workspace_paths_to_refresh,
            &store_context,
            &mut relational_workspace_snapshots,
            &mut dirty_path_symbol_rows,
            &mut state.workspace_package_inventory_complete,
        );
        *state
            .dirty_path_symbol_rows
            .lock()
            .expect("dirty path-symbol mutex poisoned") = dirty_path_symbol_rows;
        store_context
            .gc
            .schedule(self.project.root(), Arc::clone(&store_context.store));
        let relational_workspace_snapshots = Arc::new(relational_workspace_snapshots);
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
            Arc::clone(&self.structural_cache),
            Arc::clone(&self.structural_index_cache),
            Arc::new(self.snapshot_caches.carry_content_keyed_values_forward()),
            self.content_identity_base,
            self.semantic_cache.clone(),
            store_context,
            relational_workspace_snapshots,
        )
    }

    fn update_all(&self) -> Self {
        let mut store_context = self.store_context.clone();
        store_context.live_paths = Arc::new(
            self.store_context
                .live_paths
                .fork_from_snapshot(Arc::clone(&self.indexed_live_snapshot)),
        );
        store_context.workspace_snapshot = WorkspaceBuildSnapshot::capture(
            self.project.as_ref(),
            store_context.liveness.as_deref(),
            &[self.adapter.language()],
        );
        store_context.workspace_listing_complete = store_context.workspace_snapshot.is_some();
        let mut state = Self::build_state(
            self.project.as_ref(),
            self.adapter.as_ref(),
            &self.config,
            None,
            &store_context,
        );
        store_context.workspace_snapshot = None;
        let (relational_workspace_snapshots, snapshots_complete) =
            self.capture_relational_workspace_snapshots();
        if !snapshots_complete {
            state.mark_workspace_package_inventory_incomplete();
        }
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
            Arc::clone(&self.structural_cache),
            Arc::clone(&self.structural_index_cache),
            Arc::new(self.snapshot_caches.carry_content_keyed_values_forward()),
            self.content_identity_base,
            self.semantic_cache.clone(),
            store_context,
            relational_workspace_snapshots,
        )
    }

    fn relational_definition_batch(
        &self,
        requests: &[RelationalDefinitionRequest],
        cancellation: &CancellationToken,
    ) -> RelationalBatchOutcome {
        RelationalDefinitionLookup::batch(self, requests, cancellation)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.state.fresh_parse_errors.get(file).cloned()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.adapter.extract_call_receiver(reference)
    }

    /// The file's import statements in source order, one entry per statement.
    ///
    /// Since migration 0019 the store holds one row per import BINDING, and a
    /// declaration that binds several names (`import { A, B } from 'm'`) gives
    /// each binding the same snippet. Collapsing runs of equal adjacent
    /// snippets restores "one entry per statement" without keeping a second
    /// stored list: bindings of one declaration are always contiguous because
    /// every adapter emits them together while walking that declaration.
    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        let Some(state) = self.fetch_file_state(file) else {
            return Vec::new();
        };
        let mut statements: Vec<String> = Vec::with_capacity(state.imports.len());
        for import in &state.imports {
            if statements
                .last()
                .is_some_and(|last| last == &import.raw_snippet)
            {
                continue;
            }
            statements.push(import.raw_snippet.clone());
        }
        statements
    }

    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        if self.workspace_declaration_identities_authoritative()
            && self.adapter.structural_spec().is_some()
        {
            vec![self]
        } else {
            Vec::new()
        }
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.snapshot_caches())
    }

    fn workspace_content_identities(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentities> {
        Some(
            crate::analyzer::content_identity::WorkspaceContentIdentities::new([(
                self.adapter.language(),
                self.language_content_identity(),
            )]),
        )
    }

    fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex> {
        vec![self]
    }

    fn is_access_expression(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
    ) -> bool {
        true
    }

    fn find_nearest_declaration(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
        _ident: &str,
    ) -> Option<DeclarationInfo> {
        None
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        if !self.workspace_declaration_identities_authoritative() {
            return Vec::new();
        }
        let Some(config) = self.adapter.cognitive_complexity_config() else {
            return Vec::new();
        };
        let Some(file_state) = self.fetch_file_state(file) else {
            return Vec::new();
        };

        let source = file_state.source.as_str();
        if crate::analyzer::common::is_unparseable_source(source) {
            return Vec::new();
        }
        let mut parser = Parser::new();
        if !set_parser_for_file(&mut parser, self.adapter.as_ref(), file, source) {
            return Vec::new();
        }
        let Some(tree) = parser.parse(source, None) else {
            return Vec::new();
        };
        let root = tree.root_node();

        // Walk the declared code-unit hierarchy to enumerate every function
        // in this file in source order (top-level + nested under classes /
        // modules / impls). Mirrors brokk-shared's
        // `functionCodeUnitsInFile`.
        let mut functions: Vec<CodeUnit> = Vec::new();
        let mut work: VecDeque<CodeUnit> =
            file_state.top_level_declarations.iter().cloned().collect();
        while let Some(cu) = work.pop_front() {
            if cu.is_function() {
                functions.push(cu.clone());
            }
            if let Some(children) = file_state.children.get(&cu) {
                for child in children {
                    work.push_back(child.clone());
                }
            }
        }

        let mut result = Vec::with_capacity(functions.len());
        for cu in functions {
            let Some(ranges) = file_state.ranges.get(&cu) else {
                continue;
            };
            let Some(primary) = ranges.first() else {
                continue;
            };
            // `descendant_for_byte_range(start, end)` returns the smallest
            // node fully containing `[start, end)`. With the analyzer's
            // primary range for the function this lands on the
            // function/method node itself, which is what the scorer wants
            // as its root.
            let Some(node) = root.descendant_for_byte_range(primary.start_byte, primary.end_byte)
            else {
                continue;
            };
            let complexity = cognitive_complexity::compute(node, source, config);
            result.push((cu, complexity));
        }
        result
    }

    fn search_symbol_candidates(
        &self,
        patterns: &SearchSymbolPatternBatch,
        cancellation: Option<&CancellationToken>,
    ) -> SearchSymbolCandidates {
        if !self.workspace_declaration_identities_authoritative() {
            return SearchSymbolCandidates::complete(Vec::new(), 0);
        }
        self.sql_search_symbol_candidates(patterns, cancellation)
            .unwrap_or_else(|| SearchSymbolCandidates::complete(Vec::new(), 0))
    }

    fn metrics(&self) -> CodeBaseMetrics {
        CodeBaseMetrics::new(
            self.analyzed_live_files().len(),
            self.all_declarations().count(),
        )
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.fetch_file_state(file)
            .map(|state| state.contains_tests)
            .unwrap_or(false)
    }

    fn in_test_region(&self, code_unit: &CodeUnit) -> bool {
        self.fetch_file_state(code_unit.source())
            .is_some_and(|state| state.test_region_units.contains(code_unit))
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<A> crate::analyzer::AnalyzerTestHooks for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn arm_selector_continuation_semantic_cache_invalidation_for_test(&self) {
        self.semantic_cache
            .arm_selector_continuation_invalidation_for_test();
    }

    fn invalidate_selector_continuation_semantic_cache_if_armed_for_test(&self) {
        self.semantic_cache
            .invalidate_selector_continuation_if_armed_for_test();
    }

    fn selector_continuation_semantic_cache_revival_census_for_test(
        &self,
    ) -> crate::analyzer::semantic::SemanticCacheRevivalCensus {
        self.semantic_cache
            .selector_continuation_revival_census_for_test()
    }

    fn arm_evaluation_root_continuation_semantic_cache_invalidation_for_test(&self) {
        self.semantic_cache
            .arm_evaluation_root_continuation_invalidation_for_test();
    }

    fn invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test(&self) {
        self.semantic_cache
            .invalidate_evaluation_root_continuation_if_armed_for_test();
    }

    fn evaluation_root_continuation_semantic_cache_revival_census_for_test(
        &self,
    ) -> crate::analyzer::semantic::SemanticCacheRevivalCensus {
        self.semantic_cache
            .evaluation_root_continuation_revival_census_for_test()
    }

    fn semantic_materialization_census_for_test(
        &self,
    ) -> Vec<(
        crate::analyzer::semantic::WorkspaceRelativePath,
        crate::analyzer::semantic::SemanticMaterializationCensus,
    )> {
        self.semantic_cache.materialization_census_for_test()
    }

    fn reset_definition_candidates_query_count_for_test(&self) {
        TreeSitterAnalyzer::reset_definition_candidates_query_count_for_test(self);
    }

    fn reset_definition_prefetch_batch_count_for_test(&self) {
        TreeSitterAnalyzer::reset_definition_prefetch_batch_count_for_test(self);
    }

    fn definition_prefetch_batch_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::definition_prefetch_batch_count_for_test(self)
    }

    fn reset_relational_definition_batch_call_count_for_test(&self) {
        TreeSitterAnalyzer::reset_relational_definition_batch_call_count_for_test(self);
    }

    fn relational_definition_batch_call_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::relational_definition_batch_call_count_for_test(self)
    }

    fn reset_definition_candidate_row_read_count_for_test(&self) {
        TreeSitterAnalyzer::reset_definition_candidate_row_read_count_for_test(self);
    }

    fn definition_candidate_row_read_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::definition_candidate_row_read_count_for_test(self)
    }

    fn reset_search_candidate_hydration_count_for_test(&self) {
        TreeSitterAnalyzer::reset_search_candidate_hydration_count_for_test(self);
    }

    fn search_candidate_hydration_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::search_candidate_hydration_count_for_test(self)
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::definition_candidates_query_count_for_test(self)
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        TreeSitterAnalyzer::reset_full_declaration_scan_count_for_test(self);
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::full_declaration_scan_count_for_test(self)
    }

    fn reset_package_declaration_scan_count_for_test(&self) {
        TreeSitterAnalyzer::reset_package_declaration_scan_count_for_test(self);
    }

    fn package_declaration_scan_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::package_declaration_scan_count_for_test(self)
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        TreeSitterAnalyzer::reset_full_hydration_count_for_test(self);
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::full_hydration_count_for_test(self)
            + TreeSitterAnalyzer::bulk_hydration_count_for_test(self)
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::full_hydration_count_for_test(self)
    }

    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::bulk_hydration_count_for_test(self)
    }

    fn reset_java_usage_evidence_cache_stats_for_test(&self) {
        self.snapshot_caches()
            .java_usage_evidence()
            .reset_stats_for_test();
    }

    fn java_usage_evidence_cache_stats_for_test(
        &self,
    ) -> crate::analyzer::JavaUsageEvidenceCacheStats {
        self.snapshot_caches()
            .java_usage_evidence()
            .stats_for_test()
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        TreeSitterAnalyzer::reset_workspace_path_scan_count_for_test(self);
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::workspace_path_scan_count_for_test(self)
    }

    fn reset_blob_hash_count_for_test(&self) {
        TreeSitterAnalyzer::reset_blob_hash_count_for_test(self);
    }

    fn blob_hash_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::blob_hash_count_for_test(self)
    }
}

/// A raw regex containing only ASCII identifier characters is exactly a
/// case-insensitive literal substring search. It is safe to use as a storage
/// candidate filter; all other regex forms retain the complete row set.
fn literal_ascii_search_substring(pattern: &str) -> Option<&str> {
    (!pattern.is_empty()
        && pattern
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then_some(pattern)
}

fn enclosing_code_unit_rank(code_unit: &CodeUnit) -> usize {
    if code_unit.is_file_scope() { 1 } else { 0 }
}

fn select_enclosing_code_unit(
    candidates: impl IntoIterator<Item = (Range, CodeUnit)>,
) -> Option<CodeUnit> {
    candidates
        .into_iter()
        .min_by(|(left_range, left), (right_range, right)| {
            (left_range.end_byte - left_range.start_byte)
                .cmp(&(right_range.end_byte - right_range.start_byte))
                .then_with(|| enclosing_code_unit_rank(left).cmp(&enclosing_code_unit_rank(right)))
                .then_with(|| left.fq_name().cmp(&right.fq_name()))
                .then_with(|| left.kind().cmp(&right.kind()))
                .then_with(|| left.source().rel_path().cmp(right.source().rel_path()))
        })
        .map(|(_, code_unit)| code_unit)
}

fn enclosing_code_unit_from_state(state: &FileState, range: &Range) -> Option<CodeUnit> {
    enclosing_code_unit_from_declaration_ranges(&state.declarations, &state.ranges, range)
}

/// Select the innermost declaration from already hydrated per-file facts.
///
/// Graph scans that own a bulk [`FileState`] projection use this instead of
/// returning through [`CodeUnitIndex::enclosing_code_unit`], which would
/// redundantly reopen the store for facts already present in the request.
pub(crate) fn enclosing_code_unit_from_declaration_ranges(
    declarations: &HashSet<CodeUnit>,
    ranges: &HashMap<CodeUnit, Vec<Range>>,
    range: &Range,
) -> Option<CodeUnit> {
    select_enclosing_code_unit(declarations.iter().cloned().filter_map(|code_unit| {
        let best_range = ranges
            .get(&code_unit)
            .into_iter()
            .flatten()
            .copied()
            .find(|candidate| candidate.contains(range))?;
        Some((best_range, code_unit))
    }))
}

/// The producer side of the read ledger's per-file keys for this language.
///
/// Every key here is produced by the same code the publish path runs, never by
/// a second interpretation of a name: `PreparedParsedBlob::index_keys` reads
/// the rows `write_prepared_blob_rows_tx` writes, the supertype keys are the
/// declarations the file state actually recorded supertypes for,
/// `path_symbol_row` mints the path-symbol row the workspace projection
/// persists, and the package names come from `workspace_snapshot_relations`
/// over this blob's own content-package facts. A key spelled any other way
/// would not match the probe that reads it, and verification would pass a
/// changed input.
impl<A: LanguageAdapter> crate::analyzer::read_verification::WorkspaceFactIndex
    for TreeSitterAnalyzer<A>
{
    fn fact_index_language(&self) -> Language {
        self.adapter.language()
    }

    fn analyzed_blobs(&self) -> Vec<(ProjectFile, Oid)> {
        self.analyzed_live_files()
            .into_iter()
            .filter_map(|file| {
                let oid = self.resolve_live_oid_for_file(&file)?;
                Some((file, oid))
            })
            .collect()
    }

    fn blob_index_keys(
        &self,
        file: &ProjectFile,
        blob: Oid,
    ) -> Option<Vec<(crate::analyzer::read_ledger::IndexFamily, Box<[u8]>)>> {
        let state = self.fetch_file_state(file)?;
        self.index_keys_of_state(file, blob, state)
    }

    fn stored_blob_index_keys(
        &self,
        file: &ProjectFile,
        blob: Oid,
        source: &str,
    ) -> Option<Vec<(crate::analyzer::read_ledger::IndexFamily, Box<[u8]>)>> {
        let storage_key = self.adapter.storage_language_key_for_file(file);
        let generation = self.store_context.generations.get(storage_key).copied()?;
        let state = self
            .store_context
            .store
            .hydrate_file_state_with_source(
                blob,
                storage_key,
                generation,
                self.adapter.as_ref(),
                file,
                source,
            )
            .ok()??;
        self.index_keys_of_state(file, blob, Arc::new(state))
    }
}

/// The producer half of [`WorkspaceFactIndex`], shared by the mounted and the
/// store-fed enumerations so that one blob has one key set however it was
/// reached.
impl<A: LanguageAdapter> TreeSitterAnalyzer<A> {
    fn index_keys_of_state(
        &self,
        file: &ProjectFile,
        blob: Oid,
        state: Arc<FileState>,
    ) -> Option<Vec<(crate::analyzer::read_ledger::IndexFamily, Box<[u8]>)>> {
        use crate::analyzer::read_ledger::IndexFamily;

        let storage_key = self.adapter.storage_language_key_for_file(file);
        let generation = self.store_context.generations.get(storage_key).copied()?;
        let prepared = crate::analyzer::store::AnalyzerStore::prepare_parsed_blob(
            blob,
            storage_key,
            generation,
            self.adapter.as_ref(),
            Arc::clone(&state),
        )
        .ok()?;

        let mut keys = Vec::new();
        prepared.index_keys(self.adapter.as_ref(), &mut |family, key| {
            keys.push((family, Box::from(key)))
        });
        for unit in state.raw_supertypes.keys() {
            keys.push((IndexFamily::Supertype, Box::from(unit.fq_name().as_bytes())));
        }
        for unit in state.supertype_lookup_paths.keys() {
            keys.push((
                IndexFamily::SupertypeLookupPath,
                Box::from(unit.fq_name().as_bytes()),
            ));
        }
        let path_symbol = Self::path_symbol_row(&self.adapter, file, blob);
        if let Some(row) = &path_symbol {
            keys.push((IndexFamily::PathSymbol, Box::from(row.exact_fqn.as_bytes())));
            keys.push((
                IndexFamily::PathSymbol,
                Box::from(row.normalized_fqn.as_bytes()),
            ));
        }
        let facts = self
            .store_context
            .store
            .workspace_content_package_facts(
                storage_key,
                generation,
                &[blob],
                self.adapter.workspace_file_package_anchor(),
            )
            .ok()?;
        if !facts.complete {
            return None;
        }
        let entry = (
            file.clone(),
            WorkspaceFileRow {
                rel_path: crate::path_utils::rel_path_string(file),
                blob_oid: blob,
            },
            path_symbol,
        );
        let (packages, _, _, _) =
            Self::workspace_snapshot_relations(&self.adapter, &[entry], &facts.facts).ok()?;
        for package in packages {
            keys.push((
                IndexFamily::PackageMembership,
                Box::from(package.as_bytes()),
            ));
        }
        keys.sort();
        keys.dedup();
        Some(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitType;
    use crate::analyzer::cpp::CppAdapter;
    use crate::analyzer::csharp::CSharpAdapter;
    use crate::analyzer::go::GoAdapter;
    use crate::analyzer::java::JavaAdapter;
    use crate::analyzer::javascript::JavascriptAdapter;
    use crate::analyzer::python::PythonAdapter;
    use crate::analyzer::rust::RustAdapter;
    use crate::analyzer::scala::ScalaAdapter;
    use crate::analyzer::store::AnalyzerStore;
    use crate::analyzer::typescript::TypescriptAdapter;
    use crate::analyzer::{
        AnalyzerConfig, IAnalyzer, JavaAnalyzer, Language, OverlayProject, TestProject,
    };
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use git2::{ObjectType, Oid};
    use std::path::{Path, PathBuf};
    use std::sync::{Barrier, Condvar, RwLock};

    fn cache_key(name: &str) -> FileStateCacheKey {
        FileStateCacheKey {
            oid: Oid::zero(),
            rel_path: PathBuf::from(name),
        }
    }

    #[test]
    fn expanded_comment_start_walks_attached_lines_with_mixed_endings() {
        let source = "// license\r\n\r\n// docs\n#[attr]\rfn work() {}";
        let declaration = source.find("fn work").unwrap();

        assert_eq!(
            expanded_comment_start(Language::Rust, source, declaration),
            source.find("// docs").unwrap()
        );
    }

    #[test]
    fn expanded_comment_start_keeps_inline_comment_boundary() {
        let source = "const pi = \"pi\"; // nearby\nfn work() {}";
        let declaration = source.find("fn work").unwrap();

        assert_eq!(
            expanded_comment_start(Language::Rust, source, declaration),
            source.find("// nearby").unwrap()
        );
    }

    #[test]
    fn expanded_comment_start_ignores_non_boundary_offsets() {
        let source = "// docs\nfn café() {}";
        let non_boundary = source.find('é').unwrap() + 1;

        assert_eq!(
            expanded_comment_start(Language::Rust, source, non_boundary),
            non_boundary
        );
        assert_eq!(
            expanded_comment_start(Language::Rust, source, source.len() + 1),
            source.len()
        );
    }

    #[test]
    fn relational_batch_deduplicates_with_one_snapshot_and_point_is_arity_one() {
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionLookup,
            RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
            RelationalName, RelationalPointOutcome,
        };

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/Widget.java");
        file.write("package demo; public class Widget {}\n")
            .expect("write Java fixture");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        let widget = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_class() && unit.identifier() == "Widget")
            .expect("fixture declares demo.Widget");
        let exact = RelationalDefinitionRequest {
            ordinal: 11,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: RelationalName::stable(widget.fq().clone()),
            query: RelationalDefinitionQuery::ExactName,
        };
        let duplicate = RelationalDefinitionRequest {
            ordinal: 3,
            ..exact.clone()
        };
        let normalized = RelationalDefinitionRequest {
            ordinal: 7,
            name: RelationalName::stable(analyzer.adapter.normalize_fq_name(widget.fq())),
            query: RelationalDefinitionQuery::NormalizedName,
            ..exact.clone()
        };
        let rendered_name = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Java,
            "demo.Widget",
            crate::analyzer::fq_name::segment_interner(),
        );
        let rendered_exact = RelationalDefinitionRequest {
            ordinal: 13,
            name: RelationalName::stable(rendered_name.clone()),
            ..exact.clone()
        };
        let rendered_normalized = RelationalDefinitionRequest {
            ordinal: 17,
            name: RelationalName::stable(rendered_name),
            query: RelationalDefinitionQuery::NormalizedName,
            ..exact.clone()
        };

        let outcome = analyzer.batch(
            &[
                exact.clone(),
                duplicate,
                normalized.clone(),
                rendered_exact,
                rendered_normalized,
            ],
            &CancellationToken::new(),
        );
        let RelationalBatchOutcome::Complete(results) = outcome else {
            panic!("relational batch should complete: {outcome:?}");
        };
        assert_eq!(
            results
                .iter()
                .map(|result| result.ordinal)
                .collect::<Vec<_>>(),
            [11, 3, 7, 13, 17],
            "fanout preserves caller order and ordinals"
        );
        for result in &results {
            let RelationalDefinitionValue::Definitions(definitions) = &result.value else {
                panic!("name lookup must return definitions")
            };
            assert_eq!(definitions, std::slice::from_ref(&widget));
        }
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (1, 1, 4),
            "five inputs contain four distinct structured and rendered questions in one reader snapshot"
        );

        let point = analyzer.point(&exact, &CancellationToken::new());
        let RelationalPointOutcome::Complete(point_result) = point else {
            panic!("point lookup should complete: {point:?}");
        };
        assert_eq!(point_result, results[0]);
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (2, 2, 5),
            "point delegates through one additional arity-one batch"
        );

        let cancellation = CancellationToken::cancel_after_checks_for_test(4);
        assert_eq!(
            analyzer.batch(&[exact.clone(), normalized], &cancellation),
            RelationalBatchOutcome::Cancelled,
            "a stopped batch must not publish the completed prefix"
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (3, 3, 7)
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            analyzer.batch(std::slice::from_ref(&exact), &cancellation),
            RelationalBatchOutcome::Cancelled
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (3, 3, 7),
            "pre-cancelled batches publish no prefix and open no reader"
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_live_unit_count_queries_for_test(),
            0,
            "small relational batches never consult workspace cardinality"
        );
    }

    #[test]
    fn relational_batch_set_queries_preserve_point_results() {
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionLookup,
            RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
            RelationalName,
        };

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/Widget.java");
        file.write("package demo; public class Widget { public void run() {} }\n")
            .expect("write Java fixture");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        let declarations = analyzer.get_all_declarations();
        let widget = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier() == "Widget")
            .cloned()
            .expect("fixture declares demo.Widget");
        let run = declarations
            .iter()
            .find(|unit| unit.is_function() && unit.identifier() == "run")
            .cloned()
            .expect("fixture declares Widget.run");
        let scope = DefinitionLanguageScope::Language(Language::Java);
        let mut requests = Vec::new();
        for index in 0..64usize {
            let fq = if index == 0 {
                widget.fq().clone()
            } else {
                brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                    Language::Java,
                    &format!("demo.MissingExact{index}"),
                    crate::analyzer::fq_name::segment_interner(),
                )
            };
            requests.push(RelationalDefinitionRequest {
                ordinal: requests.len(),
                language_scope: scope.clone(),
                name: RelationalName::stable(fq),
                query: RelationalDefinitionQuery::ExactName,
            });
        }
        for index in 0..64usize {
            let fq = if index == 0 {
                analyzer.adapter.normalize_fq_name(widget.fq())
            } else {
                brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                    Language::Java,
                    &format!("demo.MissingNormalized{index}"),
                    crate::analyzer::fq_name::segment_interner(),
                )
            };
            requests.push(RelationalDefinitionRequest {
                ordinal: requests.len(),
                language_scope: scope.clone(),
                name: RelationalName::stable(fq),
                query: RelationalDefinitionQuery::NormalizedName,
            });
        }
        for index in 0..64usize {
            requests.push(RelationalDefinitionRequest {
                ordinal: requests.len(),
                language_scope: scope.clone(),
                name: RelationalName::stable(widget.fq().clone()),
                query: RelationalDefinitionQuery::StructuralMembers {
                    identifier: if index == 0 {
                        "run".to_string()
                    } else {
                        format!("missingMember{index}")
                    },
                },
            });
        }

        let RelationalBatchOutcome::Complete(results) =
            analyzer.batch(&requests, &CancellationToken::new())
        else {
            panic!("set-shaped relational batch should complete")
        };
        assert_eq!(results.len(), requests.len());
        for (index, result) in results.iter().enumerate() {
            assert_eq!(result.ordinal, index);
            let RelationalDefinitionValue::Definitions(definitions) = &result.value else {
                panic!("set query returned the wrong value shape")
            };
            match index {
                0 | 64 => assert_eq!(definitions, std::slice::from_ref(&widget)),
                128 => assert_eq!(definitions, std::slice::from_ref(&run)),
                _ => assert!(definitions.is_empty(), "unexpected definitions at {index}"),
            }
        }
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_live_unit_count_queries_for_test(),
            1,
            "all qualifying set-query shapes share one workspace cardinality read"
        );
    }

    #[test]
    fn relational_batch_executes_every_supported_view_shape() {
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, PackageRelationKind, PackageRelationValue,
            RelationalBatchOutcome, RelationalDefinitionLookup, RelationalDefinitionQuery,
            RelationalDefinitionRequest, RelationalDefinitionValue, RelationalName,
        };

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "Nested.cs");
        file.write(
            "namespace Demo { class Outer { public class Nested<T> { public int Run(int x) { return x; } } } }\n",
        )
        .expect("write C# fixture");
        let root_file = ProjectFile::new(root.clone(), "Root.cs");
        root_file
            .write("class Root {}\n")
            .expect("write root-package C# fixture");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::CSharp));
        let analyzer = TreeSitterAnalyzer::new(project, CSharpAdapter);
        let declarations = analyzer.get_all_declarations();
        let nested = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier().starts_with("Nested"))
            .cloned()
            .expect("fixture declares Nested<T>");
        let run = declarations
            .iter()
            .find(|unit| unit.is_function() && unit.identifier() == "Run")
            .cloned()
            .expect("fixture declares Run");
        let root_class = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier() == "Root")
            .cloned()
            .expect("fixture declares a root-package type");
        let nested_owner = nested.fq().parent().expect("nested owner");
        let package = nested.package_fq();
        let mut package_types = declarations
            .iter()
            .filter(|unit| unit.is_class() && unit.package_fq() == package)
            .cloned()
            .collect::<Vec<_>>();
        package_types.sort();
        let nested_leaf = nested.fq().suffix_from(nested.fq().len() - 1);
        let scope = DefinitionLanguageScope::Language(Language::CSharp);
        let request = |ordinal, name, query| RelationalDefinitionRequest {
            ordinal,
            language_scope: scope.clone(),
            name,
            query,
        };
        let requests = vec![
            request(
                1,
                RelationalName::stable(nested.fq().clone()),
                RelationalDefinitionQuery::ExactName,
            ),
            request(
                2,
                RelationalName::stable(analyzer.adapter.normalize_fq_name(nested.fq())),
                RelationalDefinitionQuery::NormalizedName,
            ),
            request(
                3,
                RelationalName::stable(nested_owner.clone()),
                RelationalDefinitionQuery::StructuralChildren,
            ),
            request(
                4,
                RelationalName::stable(nested_owner),
                RelationalDefinitionQuery::StructuralMembers {
                    identifier: nested.identifier().to_string(),
                },
            ),
            request(
                5,
                RelationalName::stable(package.clone()),
                RelationalDefinitionQuery::VisibleMembers {
                    identifier: nested.identifier().to_string(),
                },
            ),
            request(
                6,
                RelationalName::stable(nested_leaf),
                RelationalDefinitionQuery::Identifier {
                    file: Some(file.clone()),
                },
            ),
            request(
                7,
                RelationalName::stable(package.clone()),
                RelationalDefinitionQuery::PackageTypes {
                    simple_name: "Nested".to_string(),
                },
            ),
            request(
                8,
                RelationalName::stable(package.clone()),
                RelationalDefinitionQuery::PackageTypesInPackage,
            ),
            request(
                9,
                RelationalName::stable(package.clone()),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists),
            ),
            request(
                10,
                RelationalName::stable(package),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Files),
            ),
            request(
                11,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Children),
            ),
            request(
                12,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Descendants),
            ),
            request(
                13,
                RelationalName::stable(run.fq().clone()),
                RelationalDefinitionQuery::CallableFacts,
            ),
            request(
                14,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::StructuralChildren,
            ),
            request(
                15,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::PackageTypes {
                    simple_name: "Root".to_string(),
                },
            ),
            request(
                16,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::PackageTypesInPackage,
            ),
            request(
                17,
                RelationalName::stable(
                    brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                        Language::CSharp,
                        "Nested`",
                        crate::analyzer::fq_name::segment_interner(),
                    ),
                ),
                RelationalDefinitionQuery::IdentifierPrefix { file: None },
            ),
        ];

        let outcome = analyzer.batch(&requests, &CancellationToken::new());
        let RelationalBatchOutcome::Complete(results) = outcome else {
            panic!("all relational view shapes should complete: {outcome:?}");
        };
        for ordinal in 1..=7 {
            let RelationalDefinitionValue::Definitions(definitions) = &results[ordinal - 1].value
            else {
                panic!("request {ordinal} must return definitions")
            };
            assert_eq!(
                definitions,
                std::slice::from_ref(&nested),
                "request {ordinal}"
            );
        }
        assert_eq!(
            results[7].value,
            RelationalDefinitionValue::Definitions(package_types)
        );
        assert_eq!(
            results[8].value,
            RelationalDefinitionValue::PackageRelation(PackageRelationValue::Exists(true))
        );
        assert_eq!(
            results[9].value,
            RelationalDefinitionValue::PackageRelation(PackageRelationValue::Files(vec![
                file.clone()
            ]))
        );
        for result in &results[10..=11] {
            assert_eq!(
                result.value,
                RelationalDefinitionValue::PackageRelation(PackageRelationValue::Packages(vec![
                    "Demo".to_string()
                ]))
            );
        }
        let RelationalDefinitionValue::CallableFacts(facts) = &results[12].value else {
            panic!("callable request must return facts")
        };
        assert!(!facts.is_empty());
        assert!(facts.iter().all(|fact| fact.declaration == run));
        assert!(facts.iter().all(|fact| fact.metadata.is_some()));
        for result in &results[13..=15] {
            assert_eq!(
                result.value,
                RelationalDefinitionValue::Definitions(vec![root_class.clone()]),
                "root package is a valid structural and package query subject"
            );
        }
        assert_eq!(
            results[16].value,
            RelationalDefinitionValue::Definitions(vec![nested.clone()]),
            "the C# arity-free identifier spelling must use the indexed decoration range"
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (1, 1, requests.len())
        );
    }

    #[test]
    fn bounded_file_cache_respects_capacity_under_interleaved_touches() {
        let mut cache: BoundedFileCache<u32> = BoundedFileCache::new(2);
        cache.insert(cache_key("a"), Arc::new(1));
        cache.insert(cache_key("b"), Arc::new(2));
        // Interleave touches (get) with a fresh insert; capacity must never
        // be exceeded no matter how many stale `order` duplicates a touch
        // leaves behind.
        assert!(cache.get(&cache_key("a")).is_some());
        assert!(cache.get(&cache_key("a")).is_some());
        assert!(cache.get(&cache_key("b")).is_some());
        cache.insert(cache_key("c"), Arc::new(3));
        assert_eq!(cache.len(), 2, "capacity must be respected after eviction");
    }

    #[test]
    fn bounded_file_cache_most_recently_used_survives_eviction() {
        let mut cache: BoundedFileCache<u32> = BoundedFileCache::new(2);
        cache.insert(cache_key("a"), Arc::new(1));
        cache.insert(cache_key("b"), Arc::new(2));
        // Touch "a" so "b" becomes the least-recently-used entry.
        assert!(cache.get(&cache_key("a")).is_some());
        cache.insert(cache_key("c"), Arc::new(3));
        assert!(
            cache.get(&cache_key("a")).is_some(),
            "recently touched entry must survive eviction"
        );
        assert!(
            cache.get(&cache_key("c")).is_some(),
            "newly inserted entry must survive eviction"
        );
        assert!(
            cache.get(&cache_key("b")).is_none(),
            "least-recently-used entry must be evicted"
        );
    }

    #[test]
    fn bounded_file_cache_duplicate_touches_do_not_inflate_entry_count() {
        let mut cache: BoundedFileCache<u32> = BoundedFileCache::new(3);
        cache.insert(cache_key("a"), Arc::new(1));
        for _ in 0..50 {
            assert!(cache.get(&cache_key("a")).is_some());
        }
        assert_eq!(
            cache.len(),
            1,
            "repeated touches of one key must not create extra entries"
        );
        // Re-inserting the same key (e.g. re-hydrating after a dirty write)
        // must also not grow the entry count.
        cache.insert(cache_key("a"), Arc::new(2));
        assert_eq!(cache.len(), 1);
        assert_eq!(*cache.get(&cache_key("a")).unwrap(), 2);
    }

    #[test]
    fn bounded_file_cache_compacts_stale_order_duplicates() {
        let mut cache: BoundedFileCache<u32> = BoundedFileCache::new(2);
        cache.insert(cache_key("a"), Arc::new(1));
        cache.insert(cache_key("b"), Arc::new(2));
        // Touch "a" far past the compaction threshold; `order` must not grow
        // without bound even though `entries` stays fixed at capacity.
        for _ in 0..(CACHE_ORDER_COMPACT_FACTOR * 10) {
            assert!(cache.get(&cache_key("a")).is_some());
        }
        assert!(
            cache.order.len()
                <= cache.capacity * CACHE_ORDER_COMPACT_FACTOR + CACHE_ORDER_COMPACT_FACTOR,
            "order should be compacted instead of growing unboundedly, got {}",
            cache.order.len()
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn segmented_file_state_cache_keeps_reused_states_through_a_cold_scan() {
        let state = Arc::new(empty_file_state("x".repeat(512), false));
        let weight = state.estimated_retained_bytes();
        let mut cache = SegmentedFileStateCache::new(weight.saturating_mul(4));
        let hot_a = cache_key("hot-a");
        let hot_b = cache_key("hot-b");
        cache.insert(hot_a.clone(), Arc::clone(&state));
        cache.insert(hot_b.clone(), Arc::clone(&state));
        assert!(cache.get(&hot_a).is_some());
        assert!(cache.get(&hot_b).is_some());

        for index in 0..4 {
            cache.insert(cache_key(&format!("cold-{index}")), Arc::clone(&state));
        }

        assert!(cache.contains(&hot_a), "a second use protects hot state a");
        assert!(cache.contains(&hot_b), "a second use protects hot state b");
        assert!(cache.retained_bytes() <= cache.max_bytes);
        assert_eq!(cache.stats().promotions, 2);
        assert!(cache.stats().evictions > 0);
    }

    #[test]
    fn file_state_cache_budget_tracks_corpus_with_a_hard_ceiling() {
        let config = AnalyzerConfig::default();
        let ceiling = file_state_cache_ceiling_bytes(&config);
        assert_eq!(
            file_state_cache_budget_bytes(&config, None),
            ceiling,
            "an unavailable corpus estimate must preserve the safe ceiling"
        );
        assert_eq!(
            file_state_cache_budget_bytes(&config, Some(100 * 1024 * 1024)),
            40 * 1024 * 1024,
            "the target is ten percent of the expanded persisted corpus"
        );
        assert_eq!(
            file_state_cache_budget_bytes(&config, Some(usize::MAX)),
            ceiling,
            "a whale corpus cannot exceed the configured ceiling"
        );
    }

    #[derive(Clone)]
    struct CountingOverlayProject {
        delegate: TestProject,
        source: Arc<RwLock<(String, u64)>>,
        reads: Arc<AtomicUsize>,
    }

    impl CountingOverlayProject {
        fn new(root: impl Into<std::path::PathBuf>, source: impl Into<String>) -> Self {
            Self {
                delegate: TestProject::new(root, Language::Rust),
                source: Arc::new(RwLock::new((source.into(), 1))),
                reads: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_source(&self, source: impl Into<String>) {
            let mut current = self.source.write().expect("source lock poisoned");
            current.0 = source.into();
            current.1 = current
                .1
                .checked_add(1)
                .expect("test overlay revision space exhausted");
        }

        fn reset_reads(&self) {
            self.reads.store(0, Ordering::Relaxed);
        }

        fn read_count(&self) -> usize {
            self.reads.load(Ordering::Relaxed)
        }
    }

    impl Project for CountingOverlayProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, _file: &ProjectFile) -> std::io::Result<String> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.source.read().expect("source lock poisoned").0.clone())
        }

        fn read_source_snapshot(
            &self,
            _file: &ProjectFile,
        ) -> std::io::Result<ProjectSourceSnapshot> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let current = self.source.read().expect("source lock poisoned");
            Ok(ProjectSourceSnapshot::overlay(
                current.0.clone(),
                OverlayRevision::from_monotonic_counter(current.1),
            ))
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            true
        }
    }

    /// Records the thread each overlay OID read is billed to.
    #[derive(Clone)]
    struct OverlayReadThreadProject {
        delegate: TestProject,
        read_threads: Arc<Mutex<Vec<String>>>,
    }

    impl Project for OverlayReadThreadProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            self.read_threads
                .lock()
                .expect("overlay read thread log poisoned")
                .push(
                    std::thread::current()
                        .name()
                        .unwrap_or("<unnamed>")
                        .to_string(),
                );
            self.delegate.read_source(file)
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            true
        }
    }

    /// Every overlay OID read fails, naming the file that failed.
    #[derive(Clone)]
    struct FailingOverlayProject {
        delegate: TestProject,
    }

    impl Project for FailingOverlayProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            Err(std::io::Error::other(format!(
                "{} overlay OID failure",
                file.rel_path().display()
            )))
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct BlockingParseProject {
        delegate: TestProject,
        blocked_file: PathBuf,
        blocked_parse_started: std::sync::mpsc::SyncSender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Project for BlockingParseProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            if file.rel_path() == self.blocked_file {
                self.blocked_parse_started
                    .send(())
                    .expect("blocked parse observer should remain connected");
                let (released, wake) = &*self.release;
                let mut released = released.lock().expect("parse release mutex poisoned");
                while !*released {
                    released = wake.wait(released).expect("parse release mutex poisoned");
                }
            }
            self.delegate.read_source(file)
        }
    }

    /// The multi-file hashing burst runs on the process-shared dedicated build
    /// pool, so it is billed neither to the calling thread nor to a global-pool
    /// worker that an interactive request would otherwise be waiting for
    /// (#2115). The pool's width is a process setting, so the burst's own
    /// concurrency is not something one `AnalyzerConfig` can assert; that it
    /// runs off the caller and off the global pool is.
    #[test]
    fn live_oid_resolution_hashes_overlays_on_the_dedicated_build_pool() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let first = temp_file(&root, "src/First.java");
        let first_source = "package demo; class First {}\n";
        first.write(first_source).expect("first Java source");
        let second = temp_file(&root, "src/Second.java");
        let second_source = "package demo; class Second {}\n";
        second.write(second_source).expect("second Java source");

        let read_threads = Arc::new(Mutex::new(Vec::new()));
        let project = OverlayReadThreadProject {
            delegate: TestProject::new(&root, Language::Java),
            read_threads: Arc::clone(&read_threads),
        };
        let store_context = ephemeral_store_context(&project).unwrap();

        let resolved = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[first.clone(), second.clone()],
            &store_context,
            true,
        )
        .expect("both overlay identities resolve");

        for (file, source) in [(&first, first_source), (&second, second_source)] {
            let expected =
                Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("overlay OID");
            assert_eq!(resolved.get(file), Some(&expected));
        }

        let read_threads = read_threads.lock().expect("read thread log poisoned");
        assert_eq!(
            read_threads.len(),
            2,
            "both overlays hashed: {read_threads:?}"
        );
        assert!(
            read_threads
                .iter()
                .all(|name| name.starts_with("bifrost-index-build-")),
            "overlay hashing escaped the dedicated build pool: {read_threads:?}"
        );
    }

    /// A failed plan reports the first *input's* error, not the first error the
    /// burst happened to produce, so the same edit always reports the same file.
    #[test]
    fn live_oid_resolution_reports_the_first_input_error() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let first = temp_file(&root, "src/First.java");
        first.write("first\n").expect("first source");
        let expected_first_error = format!("{} overlay OID failure", first.rel_path().display());
        let second = temp_file(&root, "src/Second.java");
        second.write("second\n").expect("second source");

        let project = FailingOverlayProject {
            delegate: TestProject::new(&root, Language::Java),
        };
        let store_context = ephemeral_store_context(&project).unwrap();

        let error = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[first, second],
            &store_context,
            true,
        )
        .expect_err("both overlay reads fail");

        assert_eq!(error, expected_first_error);
    }

    #[test]
    fn empty_live_oid_planning_preserves_refresh_and_replace_semantics() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/Existing.java");
        let source = "package demo; class Existing {}\n";
        file.write(source).expect("existing Java source");
        let project = TestProject::new(&root, Language::Java);
        let store_context = ephemeral_store_context(&project).unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("source OID");
        store_context
            .live_paths
            .refresh([LivePathEntry::overlay(file.clone(), oid)]);

        let refreshed = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[],
            &store_context,
            false,
        )
        .expect("empty refresh");
        assert!(refreshed.is_empty());
        assert_eq!(
            store_context.live_paths.snapshot().oid_for_path(&file),
            Some(oid)
        );

        let replaced = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[],
            &store_context,
            true,
        )
        .expect("empty replacement");
        assert!(replaced.is_empty());
        assert_eq!(
            store_context.live_paths.snapshot().oid_for_path(&file),
            None
        );
    }

    #[test]
    fn indexed_source_match_is_anchored_to_the_analyzer_generation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/Widget.java");
        let indexed = "package demo; class Widget {}\n";
        let later = "package demo; class Widget { void later() {} }\n";
        file.write(indexed).expect("indexed Java source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        assert!(analyzer.indexed_source_matches(&file, indexed));
        let indexed_identity = analyzer.language_content_identity();

        file.write(later).expect("later Java source");
        let stale_query = analyzer.clone();
        stale_query
            .fetch_file_state_from_current_source(&file)
            .expect("stale query observes and parses the later source");
        let later_oid = Oid::hash_object(ObjectType::Blob, later.as_bytes()).expect("later OID");
        assert_eq!(
            analyzer.live_snapshot().oid_for_path(&file),
            Some(later_oid),
            "the query must exercise a refresh of the shared live projection"
        );
        assert!(analyzer.indexed_source_matches(&file, indexed));
        assert!(
            !analyzer.indexed_source_matches(&file, later),
            "a refreshed live projection must not redefine what this generation indexed"
        );
        assert_eq!(
            analyzer.language_content_identity(),
            indexed_identity,
            "query hydration must not move the analyzer generation's cache identity"
        );
    }

    #[test]
    fn incremental_update_retains_unmodified_identity_from_the_prior_generation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let first = temp_file(&root, "src/First.java");
        let second = temp_file(&root, "src/Second.java");
        let first_indexed = "package demo; class First {}\n";
        let first_later = "package demo; class First { void later() {} }\n";
        let second_indexed = "package demo; class Second {}\n";
        let second_later = "package demo; class Second { void later() {} }\n";
        first.write(first_indexed).expect("indexed first source");
        second.write(second_indexed).expect("indexed second source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        second.write(second_later).expect("later second source");
        analyzer
            .clone()
            .fetch_file_state_from_current_source(&second)
            .expect("stale query observes the later second source");
        first.write(first_later).expect("later first source");

        let updated = analyzer.update(&BTreeSet::from([first.clone()]));
        assert!(updated.indexed_source_matches(&first, first_later));
        assert!(updated.indexed_source_matches(&second, second_indexed));
        assert!(
            !updated.indexed_source_matches(&second, second_later),
            "updating another file must not bless a stale query's observation as indexed"
        );

        let fully_updated = updated.update(&BTreeSet::from([second.clone()]));
        assert!(fully_updated.indexed_source_matches(&second, second_later));
    }

    #[test]
    fn revision_supplied_blob_ids_replace_hashing_the_exported_bytes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        // `src/First.java` sorts first, so it is the entry the sampled debug
        // assertion checks, and its inventory id must therefore be the honest
        // hash of what is on disk. `src/Second.java` carries the proof: its
        // inventory id names bytes the file does not hold, so a resolution that
        // hashed the file would report the disk id instead.
        let first = temp_file(&root, "src/First.java");
        first.write("class First {}\n").expect("first source");
        let first_oid =
            Oid::hash_object(ObjectType::Blob, b"class First {}\n").expect("first blob id");
        let second = temp_file(&root, "src/Second.java");
        second.write("class OnDisk {}\n").expect("second source");
        let second_disk_oid =
            Oid::hash_object(ObjectType::Blob, b"class OnDisk {}\n").expect("disk blob id");
        let second_revision_oid =
            Oid::hash_object(ObjectType::Blob, b"class InTheRevision {}\n").expect("revision id");

        let project = TestProject::new(&root, Language::Java);
        let mut store_context = ephemeral_store_context(&project).unwrap();
        store_context.revision_blobs = Some(Arc::new(RevisionBlobIdentities::new(
            vec![
                (first.rel_path().to_path_buf(), first_oid),
                (second.rel_path().to_path_buf(), second_revision_oid),
            ],
            Vec::new(),
        )));

        let resolved = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[first.clone(), second.clone()],
            &store_context,
            true,
        )
        .expect("revision identities resolve");

        assert_eq!(resolved.get(&first), Some(&first_oid));
        assert_eq!(
            resolved.get(&second),
            Some(&second_revision_oid),
            "the revision's inventory decides identity; hashing would have reported \
             {second_disk_oid}"
        );
        // The identity is also what every later query reads, without a stat.
        assert_eq!(
            store_context
                .live_paths
                .snapshot()
                .validated_oid_for_path(&second),
            Some(second_revision_oid)
        );
    }

    /// The sampled re-hash is the only thing standing between a mis-assembled
    /// inventory and facts published under the wrong content key, so prove it
    /// fires. Debug-only: the assertion is compiled out of a release build by
    /// design, and this test would then never panic.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "exported bytes hash differently")]
    fn a_sampled_revision_blob_id_that_disagrees_with_the_export_is_rejected() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let only = temp_file(&root, "src/Only.java");
        only.write("class Only {}\n").expect("only source");
        let wrong = Oid::hash_object(ObjectType::Blob, b"class Other {}\n").expect("wrong blob id");

        let project = TestProject::new(&root, Language::Java);
        let mut store_context = ephemeral_store_context(&project).unwrap();
        store_context.revision_blobs = Some(Arc::new(RevisionBlobIdentities::new(
            vec![(only.rel_path().to_path_buf(), wrong)],
            Vec::new(),
        )));

        let _ = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[only],
            &store_context,
            true,
        );
    }

    #[test]
    fn persisted_epoch_publication_failure_is_returned_from_analyzer_construction() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let db = root.join("analyzer.db");
        let store =
            Arc::new(AnalyzerStore::open_persistent(&db).expect("initialize persistent store"));
        let conn = crate::cache_db::open_unified_connection(&db).expect("open test connection");
        conn.execute_batch(
            "CREATE TRIGGER fail_epoch_publication
             BEFORE INSERT ON analysis_epochs
             BEGIN
                 SELECT RAISE(FAIL, 'forced epoch publication failure');
             END;",
        )
        .expect("install epoch failure trigger");
        drop(conn);

        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store_context = AnalyzerStoreContext {
            store,
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
        };

        let error = match TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig::default(),
            store_context,
            None,
        ) {
            Ok(_) => panic!("epoch publication failure should be returned"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("publishing analyzer epochs"));
        assert!(
            error
                .to_string()
                .contains("forced epoch publication failure")
        );
    }

    #[test]
    fn reconcile_persists_fast_parse_before_blocked_slow_parse_is_released() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let fast = temp_file(&root, "src/Fast.java");
        fast.write("package demo; class Fast {}\n")
            .expect("fast Java source");
        let slow = temp_file(&root, "src/Slow.java");
        slow.write("package demo; class Slow {}\n")
            .expect("slow Java source");

        let (blocked_parse_started_tx, blocked_parse_started_rx) = std::sync::mpsc::sync_channel(1);
        let (persisted_tx, persisted_rx) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let project: Arc<dyn Project> = Arc::new(BlockingParseProject {
            delegate: TestProject::new(&root, Language::Java),
            blocked_file: slow.rel_path().to_path_buf(),
            blocked_parse_started: blocked_parse_started_tx,
            release: Arc::clone(&release),
        });
        let store_context = ephemeral_store_context(project.as_ref()).unwrap();
        let store = Arc::clone(&store_context.store);
        let progress: BuildProgress = Arc::new(move |event| {
            if event.phase == BuildProgressPhase::Persist && event.completed > 0 {
                let _ = persisted_tx.try_send(());
            }
        });

        let build = std::thread::spawn(move || {
            TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                project,
                JavaAdapter,
                AnalyzerConfig {
                    parallelism: Some(2),
                    ..AnalyzerConfig::default()
                },
                store_context,
                Some(progress),
            )
        });

        blocked_parse_started_rx
            .recv()
            .expect("slow parse should reach the injected block");
        persisted_rx
            .recv()
            .expect("fast parse should persist while slow parse is blocked");
        let persistence_starts_before_release = store.parsed_blob_transaction_starts_for_test();
        {
            let (released, wake) = &*release;
            *released.lock().expect("parse release mutex poisoned") = true;
            wake.notify_all();
        }
        build
            .join()
            .expect("analyzer build should finish")
            .expect("analyzer epochs should initialize");

        assert!(
            persistence_starts_before_release > 0,
            "the real reconcile pipeline should start persisting the prepared fast blob while the unrelated slow parser remains blocked"
        );
    }

    #[test]
    fn reconcile_batches_257_small_files_into_two_transactions() {
        const FILES: usize = 257;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for index in 0..FILES {
            let file = temp_file(&root, &format!("src/Type{index}.java"));
            file.write(format!("package demo; class Type{index} {{}}\n"))
                .expect("Java source");
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store_context = ephemeral_store_context(project.as_ref()).unwrap();
        let store = Arc::clone(&store_context.store);

        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            store_context,
            None,
        )
        .expect("analyzer epochs should initialize");

        assert_eq!(store.parsed_blob_transaction_starts_for_test(), 2);
        assert_eq!(analyzer.state.persistence_stats.transactions, 2);
        assert_eq!(analyzer.state.persistence_stats.committed_blobs, FILES);
        assert_eq!(analyzer.state.persistence_stats.failed_blobs, 0);
        assert!(analyzer.state.persistence_stats.peak_in_flight_items > 0);
        assert!(
            analyzer.state.persistence_stats.peak_in_flight_items
                <= analyzer
                    .state
                    .persistence_stats
                    .configured_max_in_flight_items
        );
        assert!(
            analyzer
                .state
                .persistence_stats
                .peak_in_flight_payload_bytes
                > 0
        );
    }

    #[test]
    fn preparation_failure_reaches_terminal_persist_progress_and_dirty_fallback() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for name in ["GoodA", "Bad", "GoodB"] {
            let file = temp_file(&root, &format!("src/{name}.java"));
            file.write(format!("package demo; class {name} {{}}\n"))
                .expect("Java source");
        }
        let bad = ProjectFile::new(root.clone(), "src/Bad.java");
        *PREPARATION_FAILURE_PATH
            .lock()
            .expect("preparation failure path mutex poisoned") = Some(bad.abs_path().to_path_buf());
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store_context = ephemeral_store_context(project.as_ref()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let progress_events = Arc::clone(&events);
        let progress: BuildProgress = Arc::new(move |event| {
            progress_events
                .lock()
                .expect("progress event mutex poisoned")
                .push(event);
        });

        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            store_context,
            Some(progress),
        )
        .expect("analyzer epochs should initialize");
        *PREPARATION_FAILURE_PATH
            .lock()
            .expect("preparation failure path mutex poisoned") = None;

        assert_eq!(analyzer.state.persistence_stats.committed_blobs, 2);
        assert_eq!(analyzer.state.persistence_stats.failed_blobs, 1);
        let dirty = analyzer.state.dirty_snapshot();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty.keys().next().unwrap().rel_path, bad.rel_path());
        let events = events.lock().expect("progress event mutex poisoned");
        let final_persist = events
            .iter()
            .rev()
            .find(|event| event.phase == BuildProgressPhase::Persist)
            .expect("persist progress event");
        assert_eq!(final_persist.completed, 3);
        assert_eq!(final_persist.total, 3);
    }

    /// Issue #2359. On microsoft/PowerToys a Cpp build worker panicked within
    /// seconds and the process then outlived a 1872-second timeout, because
    /// `std::thread::scope` joins every sibling before the panic can leave the
    /// fan-out and nothing told those siblings to stop.
    ///
    /// The fixture makes that shape deterministic: one language panics on its
    /// only file, the other blocks on its only file until the build abort
    /// reaches it. The sibling records that it observed the abort; this proves
    /// the synchronization contract directly without a wall-clock assertion
    /// that becomes flaky when the full test binary is CPU-saturated. Its
    /// 30-second internal safety timeout still prevents a broken signal from
    /// wedging the test process.
    #[test]
    fn a_panicking_build_worker_aborts_the_whole_build_promptly() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let panicking = temp_file(&root, "src/panics.cpp");
        panicking
            .write("void init_settings() {}\n")
            .expect("cpp source");
        let blocking = temp_file(&root, "src/blocks.py");
        blocking
            .write("def work():\n    return 1\n")
            .expect("py source");
        *PANICKING_ANALYSIS_PATH
            .lock()
            .expect("panicking analysis path mutex poisoned") = Some(panicking.abs_path());
        *BLOCK_UNTIL_BUILD_ABORT_PATH
            .lock()
            .expect("block until build abort path mutex poisoned") = Some(blocking.abs_path());
        BLOCKING_ANALYSIS_OBSERVED_ABORT.store(false, Ordering::Release);
        *BLOCKING_ANALYSIS_READY
            .0
            .lock()
            .expect("blocking analysis ready mutex poisoned") = false;

        let project: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            &root,
            BTreeSet::from([Language::Cpp, Language::Python]),
        ));
        // Two workers, not two thread pools the width of the machine: the
        // fixture needs one file in flight per language, and a CPU spike inside
        // a 1900-test binary perturbs timing-sensitive neighbours.
        let config = AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::analyzer::WorkspaceAnalyzer::build_persisted(project, config)
        }));

        *PANICKING_ANALYSIS_PATH
            .lock()
            .expect("panicking analysis path mutex poisoned") = None;
        *BLOCK_UNTIL_BUILD_ABORT_PATH
            .lock()
            .expect("block until build abort path mutex poisoned") = None;

        let payload = outcome
            .err()
            .expect("a panicking worker must fail the build");
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_else(|| "non-string panic payload".to_string());
        assert!(
            message.contains("injected analysis panic"),
            "the original panic message must survive propagation: {message}"
        );
        assert!(
            BLOCKING_ANALYSIS_OBSERVED_ABORT.load(Ordering::Acquire),
            "the blocked sibling must observe the shared build abort"
        );
    }

    #[test]
    fn reconcile_keeps_only_irreducible_prepared_failure_dirty() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let good_a = temp_file(&root, "src/GoodA.java");
        good_a
            .write("package demo; class GoodA {}\n")
            .expect("good Java source");
        let bad = temp_file(&root, "src/Bad.java");
        bad.write("package demo; class Bad {}\n")
            .expect("bad Java source");
        let good_b = temp_file(&root, "src/GoodB.java");
        good_b
            .write("package demo; class GoodB {}\n")
            .expect("good Java source");
        *PREPARED_FAILURE_PATH
            .lock()
            .expect("prepared failure path mutex poisoned") = Some(bad.abs_path().to_path_buf());

        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new_with_config(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(3),
                ..AnalyzerConfig::default()
            },
        );
        *PREPARED_FAILURE_PATH
            .lock()
            .expect("prepared failure path mutex poisoned") = None;

        let dirty = analyzer.state.dirty_snapshot();
        assert_eq!(dirty.len(), 1);
        let (dirty_key, dirty_state) = dirty.iter().next().unwrap();
        assert_eq!(dirty_key.rel_path, bad.rel_path());
        assert_eq!(dirty_state.attempts, STORE_WRITE_IMMEDIATE_RETRIES + 1);
        for file in [&good_a, &good_b] {
            let source = file.read_to_string().unwrap();
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            assert!(
                analyzer
                    .store_context
                    .store
                    .contains_parsed_blob(oid, "java")
                    .unwrap()
            );
        }
        let bad_oid =
            Oid::hash_object(ObjectType::Blob, bad.read_to_string().unwrap().as_bytes()).unwrap();
        assert!(
            !analyzer
                .store_context
                .store
                .contains_parsed_blob(bad_oid, "java")
                .unwrap()
        );
    }

    fn parse_javascript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("javascript parser");
        parser.parse(source, None).expect("parse javascript")
    }

    fn empty_file_state(source: impl Into<String>, contains_tests: bool) -> FileState {
        FileState {
            source: source.into(),
            package_name: String::new(),
            content_qualifier: String::new(),
            top_level_declarations: Vec::new(),
            declarations: HashSet::default(),
            definition_lookup_units: HashSet::default(),
            imports: Vec::new(),
            scala_exports: HashMap::default(),
            rust_usage_facts: Default::default(),
            raw_supertypes: HashMap::default(),
            supertype_lookup_paths: HashMap::default(),
            type_identifiers: HashSet::default(),
            signatures: HashMap::default(),
            signature_metadata: HashMap::default(),
            cpp_template_metadata: HashMap::default(),
            ruby_method_dispatch_modes: HashMap::default(),
            ranges: HashMap::default(),
            children: HashMap::default(),
            scala_traits: HashSet::default(),
            type_aliases: HashSet::default(),
            contains_tests,
            test_region_units: HashSet::default(),
            materialization_records: Vec::new(),
            parse_errors: None,
            parse_complete: true,
            additional_projections: Vec::new(),
        }
    }

    fn temp_file(root: &Path, rel_path: &str) -> ProjectFile {
        ProjectFile::new(root.to_path_buf(), rel_path)
    }

    /// #2883: only an open buffer can override a persisted row, so the
    /// authoritative read walks the live snapshot's overlay set instead of
    /// every cached file state. The buffer's declaration must still win, and
    /// the walk must materialize that one state -- with no buffer open it must
    /// materialize none at all, however many states the analyzer has cached.
    #[test]
    fn authoritative_reads_cost_the_open_buffers_not_the_cached_file_states() {
        const FILE_COUNT: usize = 8;

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let files = (0..FILE_COUNT)
            .map(|index| {
                let file = temp_file(&root, &format!("src/file{index}.rs"));
                file.write(format!("pub fn disk_{index}() {{}}\n"))
                    .expect("rust source");
                file
            })
            .collect::<Vec<_>>();
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&overlay) as Arc<dyn Project>, RustAdapter);
        for file in &files {
            analyzer.fetch_file_state(file).expect("warm file state");
        }

        analyzer.reset_authoritative_file_state_reads_for_test();
        let on_disk = analyzer.get_all_declarations();
        assert!(
            !on_disk
                .iter()
                .any(|unit| unit.fq_name().ends_with("buffer_only")),
            "the fixture declares this name only in the buffer: {on_disk:?}"
        );
        assert_eq!(
            analyzer.authoritative_file_state_reads_for_test(),
            0,
            "with no buffer open a read must materialize none of the {FILE_COUNT} cached states"
        );

        assert!(overlay.set(files[0].abs_path(), "pub fn buffer_only() {}\n".to_owned()));
        analyzer.reset_authoritative_file_state_reads_for_test();
        let with_buffer = analyzer.get_all_declarations();

        assert!(
            with_buffer
                .iter()
                .any(|unit| unit.fq_name().ends_with("buffer_only") && unit.source() == &files[0]),
            "the open buffer's declaration must override the disk row: {with_buffer:?}"
        );
        assert_eq!(
            analyzer.authoritative_file_state_reads_for_test(),
            1,
            "one open buffer is one materialized file state"
        );
    }

    #[test]
    fn tree_preorder_walk_preserves_source_order_without_recursion() {
        let tree = parse_javascript("const first = 1; function second() { return first; }\n");
        let mut declarations = Vec::new();

        walk_named_tree_preorder(tree.root_node(), false, |node| {
            if matches!(node.kind(), "lexical_declaration" | "function_declaration") {
                declarations.push(node.kind().to_string());
            }
            WalkControl::Continue
        });

        assert_eq!(
            declarations,
            vec!["lexical_declaration", "function_declaration"]
        );
    }

    #[test]
    fn parse_error_collection_skips_error_descendants_iteratively() {
        let tree = parse_javascript("function broken( { const value = ; }\n");
        let mut errors = Vec::new();

        collect_parse_errors(tree.root_node(), &mut errors);

        assert!(!errors.is_empty(), "expected parse errors");
        for index in 0..errors.len() {
            for other in 0..errors.len() {
                if index == other {
                    continue;
                }
                let left = &errors[index].range;
                let right = &errors[other].range;
                assert!(
                    !(left.start_byte <= right.start_byte
                        && right.end_byte <= left.end_byte
                        && (left.start_byte, left.end_byte) != (right.start_byte, right.end_byte)),
                    "error descendant should have been skipped: {errors:?}"
                );
            }
        }
    }

    #[test]
    fn parse_timeout_stays_transient_and_same_content_recovers_on_retry_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let retry = ProjectFile::new(root.clone(), "src/Retry.java");
        let reopen = ProjectFile::new(root.clone(), "src/Reopen.java");
        let healthy = ProjectFile::new(root.clone(), "src/Healthy.java");
        let retry_source = format!(
            "package demo; class Retry {{\n{}\n}}\n",
            "int generatedField;\n".repeat(10_000)
        );
        let reopen_source = format!(
            "package demo; class Reopen {{\n{}\n}}\n",
            "int generatedField;\n".repeat(10_000)
        );
        let healthy_source = "package demo; class Healthy {}\n";
        retry.write(&retry_source).expect("retry fixture");
        reopen.write(&reopen_source).expect("reopen fixture");
        healthy.write(healthy_source).expect("healthy fixture");

        *FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned") =
            vec![retry.abs_path(), reopen.abs_path()];

        let db = root.join("analyzer.db");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store = Arc::new(AnalyzerStore::open_persistent(&db).expect("persistent store"));
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
        };
        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            store_context,
            None,
        )
        .expect("initial timed-out reconciliation");
        FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned")
            .clear();

        assert_eq!(
            analyzer.state.dirty_snapshot().len(),
            2,
            "both timed-out states must remain transient and retryable"
        );
        for (file, source, missing_name) in [
            (&retry, retry_source.as_str(), "Retry"),
            (&reopen, reopen_source.as_str(), "Reopen"),
        ] {
            let state = analyzer
                .fetch_file_state(file)
                .expect("timed-out state remains available in memory");
            assert_eq!(state.source, source, "fixture bytes must participate");
            assert!(!state.parse_complete);
            assert_eq!(state.declarations.len(), 1);
            assert!(state.declarations.iter().all(CodeUnit::is_file_scope));
            assert!(
                !analyzer
                    .get_declarations(file)
                    .iter()
                    .any(|declaration| declaration.short_name() == missing_name)
            );
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            assert!(
                !store.contains_parsed_blob(oid, "java").unwrap(),
                "a timeout marker must not be published as a complete blob"
            );
        }

        let healthy_state = analyzer
            .fetch_file_state(&healthy)
            .expect("healthy peer state");
        assert_eq!(healthy_state.source, healthy_source);
        assert!(healthy_state.parse_complete);
        assert!(
            analyzer
                .get_declarations(&healthy)
                .iter()
                .any(|declaration| declaration.short_name() == "Healthy")
        );
        let healthy_oid = Oid::hash_object(ObjectType::Blob, healthy_source.as_bytes()).unwrap();
        assert!(store.contains_parsed_blob(healthy_oid, "java").unwrap());

        let retry_oid = Oid::hash_object(ObjectType::Blob, retry_source.as_bytes()).unwrap();
        let retry_generation = analyzer.store_context.generations["java"];
        let partial_retry_state = analyzer
            .fetch_file_state(&retry)
            .expect("partial retry state");
        let preparation_error = AnalyzerStore::prepare_parsed_blob(
            retry_oid,
            "java",
            retry_generation,
            &JavaAdapter,
            Arc::clone(&partial_retry_state),
        )
        .expect_err("prepared persistence must reject an incomplete parser result");
        assert!(
            preparation_error
                .to_string()
                .contains("timed-out file analysis")
        );
        let direct_error = store
            .write_parsed_blob_at_generation(
                retry_oid,
                "java",
                retry_generation,
                &JavaAdapter,
                partial_retry_state.as_ref(),
            )
            .expect_err("the direct write path must enforce the same completeness invariant");
        assert!(direct_error.to_string().contains("timed-out file analysis"));
        assert!(!store.contains_parsed_blob(retry_oid, "java").unwrap());

        let retried = analyzer.update(&BTreeSet::from([retry.clone()]));
        let retried_state = retried.fetch_file_state(&retry).expect("retried state");
        assert!(retried_state.parse_complete);
        let retried_declarations = retried.get_declarations(&retry);
        assert!(
            retried_declarations
                .iter()
                .any(|declaration| declaration.short_name() == "Retry")
        );
        assert!(store.contains_parsed_blob(retry_oid, "java").unwrap());

        drop(retried);
        drop(analyzer);
        drop(store);

        let reopened_store =
            Arc::new(AnalyzerStore::open_persistent(&db).expect("reopen persistent store"));
        let reopened_context = AnalyzerStoreContext {
            store: Arc::clone(&reopened_store),
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
        };
        let reopened = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            reopened_context,
            None,
        )
        .expect("reopen reparses the still-missing same-content blob");

        let reopened_state = reopened
            .fetch_file_state(&reopen)
            .expect("reopened complete state");
        assert_eq!(reopened_state.source, reopen_source);
        assert!(reopened_state.parse_complete);
        assert!(
            reopened
                .get_declarations(&reopen)
                .iter()
                .any(|declaration| declaration.short_name() == "Reopen")
        );
        for (file, source) in [(&retry, retry_source.as_str()), (&healthy, healthy_source)] {
            let state = reopened
                .fetch_file_state(file)
                .expect("reopened complete peer state");
            assert_eq!(state.source, source);
            assert!(state.parse_complete);
        }
        assert_eq!(
            reopened.get_declarations(&retry),
            retried_declarations,
            "same-content update and persisted reopen must converge"
        );
        let reopen_oid = Oid::hash_object(ObjectType::Blob, reopen_source.as_bytes()).unwrap();
        assert!(
            reopened_store
                .contains_parsed_blob(reopen_oid, "java")
                .unwrap()
        );
    }

    #[test]
    fn oversized_persistence_produces_queryable_resource_bound_dirty_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        let source = "class Dirty:\n    pass\n".to_string();
        std::fs::write(root.join("pkg/dirty.py"), &source).unwrap();
        let file = ProjectFile::new(root.clone(), "pkg/dirty.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let adapter = Arc::new(PythonAdapter);
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            adapter.parser_language_for_file(&file),
        );
        let mut parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            &*adapter,
            &file,
            source,
        )
        .expect("python file parses");
        // Keep this fixture small in source form while still exercising the
        // production writer's actual row-cap admission check. These are
        // structured reference identifiers, so preparation and persistence
        // account for them exactly like identifiers produced by the parser.
        for index in 0..=PersistBatchLimits::PRODUCTION.max_rows {
            parsed.type_identifiers.insert(format!("synthetic_{index}"));
        }
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);

        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([(
                "python".to_string(),
                GenerationId::BOOTSTRAP,
            )])),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
        };
        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "python",
            GenerationId::BOOTSTRAP,
            &*adapter,
            Arc::new(parsed.clone()),
        )
        .expect("oversized fixture must prepare");
        assert!(prepared.logical_rows() > PersistBatchLimits::PRODUCTION.max_rows);
        let mut dirty = HashMap::default();
        TreeSitterAnalyzer::<PythonAdapter>::persist_or_mark_dirty(
            &mut dirty,
            &store_context,
            &*adapter,
            &file,
            oid,
            "python",
            GenerationId::BOOTSTRAP,
            &parsed,
        );
        let dirty_state = dirty.get(&key).expect("resource-bound state is retained");
        assert_eq!(
            dirty_state.status,
            DirtyFileStateStatus::TerminalResourceBound
        );
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(HashMap::default(), dirty, HashMap::default(), Vec::new()),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_index_cache(&config)),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_snapshot_caches(
                &config,
            )),
            TreeSitterAnalyzer::build_content_identity_base(&config, &PythonAdapter),
            crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
                config.memo_cache_budget_bytes() / 8,
            ),
            store_context,
            Arc::new(HashMap::default()),
        );

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        assert!(
            analyzer
                .declarations(&file)
                .iter()
                .any(|unit| unit.fq_name() == "pkg.dirty.Dirty")
        );
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&context);
        let starts = store.parsed_blob_transaction_starts_for_test();
        assert_eq!(analyzer.get_definitions("pkg.dirty.Dirty").len(), 1);
        assert!(
            context.store_error().is_none(),
            "a resource-bound dirty state must not become request-fatal"
        );
        assert_eq!(store.parsed_blob_transaction_starts_for_test(), starts);
        analyzer.end_query(&context);
        assert!(
            analyzer
                .lookup_declarations_by_identifier("Dirty")
                .iter()
                .any(|unit| unit.fq_name() == "pkg.dirty.Dirty"),
            "exact identifier candidates must include dirty declarations"
        );
        assert!(
            analyzer
                .lookup_declarations_by_identifier("dirty")
                .iter()
                .any(|unit| unit.is_module() && unit.fq_name() == "pkg.dirty"),
            "exact identifier candidates must retain non-persisted path modules"
        );

        let exhausted =
            analyzer.lookup_non_module_declarations_by_identifier_limited("Dirty", 1, || true);
        assert!(
            !exhausted.complete && exhausted.rows.is_empty(),
            "the dirty-state entry itself must consume bounded provider work before declarations"
        );
        let bounded =
            analyzer.lookup_non_module_declarations_by_identifier_limited("Dirty", 64, || true);
        assert!(bounded.complete);
        assert!(
            bounded
                .rows
                .iter()
                .any(|unit| unit.fq_name() == "pkg.dirty.Dirty"),
            "a sufficient bounded lookup must retain dirty declarations"
        );
    }

    /// A Python workspace whose files each declare one distinctly named class,
    /// so every lookup below names a different identifier and cannot be
    /// answered from a name-keyed memo.
    fn workspace_scan_probe_project(file_count: usize) -> (tempfile::TempDir, Arc<dyn Project>) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("pkg")).expect("create pkg");
        std::fs::write(root.join("pkg/__init__.py"), "").expect("write package marker");
        for index in 0..file_count {
            std::fs::write(
                root.join(format!("pkg/mod_{index}.py")),
                format!("class Widget{index}:\n    pass\n"),
            )
            .expect("write module");
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        (temp, project)
    }

    /// One rust crate whose declarations live behind a module, so a scoped
    /// lookup expands into `::`-bearing spellings.
    fn rust_scoped_lookup_project() -> (tempfile::TempDir, Arc<dyn Project>) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n",
        )
        .expect("write manifest");
        std::fs::write(
            root.join("src/lib.rs"),
            "pub mod inner;\npub struct Outer;\n",
        )
        .expect("write lib");
        std::fs::write(
            root.join("src/inner.rs"),
            "pub struct Widget;\n\nimpl Widget {\n    pub fn make() -> Self {\n        Widget\n    }\n}\n",
        )
        .expect("write module");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        (temp, project)
    }

    /// #1748: `lookup_suffix_candidates` peels a rust lookup path on both `.`
    /// and `::`, so a `::`-spelled input mints spellings that carry `::` --
    /// and no rust `short_name` can contain one, because the FqName renderer
    /// emits `::` only between two C++ namespace segments. Every such spelling
    /// was still paying a pooled connection checkout, a generation check, a
    /// `prepare_cached` and an index probe to be told what the storage
    /// contract already says.
    ///
    /// Fails before the filter: all three spellings seek, so `row_reads` is 3
    /// and `dropped` is 0. After it, the two `::`-bearing spellings are
    /// dropped and only the one that can match seeks.
    #[test]
    fn issue_1748_double_colon_spellings_do_not_seek_for_rust() {
        let (_temp, project) = rust_scoped_lookup_project();
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        analyzer.reset_definition_candidate_row_read_count_for_test();
        analyzer.reset_structural_miss_spelling_count_for_test();
        // Spellings: `probe::inner::Widget`, `inner::Widget`, `Widget`. Only
        // the last can match a stored rust short name.
        let scoped: Vec<CodeUnit> =
            CodeUnitIndex::definitions(&analyzer, "probe::inner::Widget").collect();
        let row_reads = analyzer.definition_candidate_row_read_count_for_test();
        let dropped = analyzer.structural_miss_spelling_count_for_test();

        assert_eq!(
            2, dropped,
            "both `::`-bearing spellings are structurally guaranteed misses"
        );
        assert_eq!(
            1, row_reads,
            "only the spelling the persisted vocabulary can hold may seek"
        );
        // The drop removes probes, never answers. Measured before the filter,
        // this lookup resolved to nothing too, and structurally it cannot
        // resolve to anything: `assemble_definition_candidates` keeps a row
        // only on an exact or normalized fq match against the *input*
        // spelling, rust's `normalize_full_name` is the identity, and no
        // stored rust fq name carries `::`. The three spellings were three
        // seeks for an answer the storage contract had already refused.
        assert!(
            scoped.is_empty(),
            "a `::`-spelled rust fq name resolved to {scoped:?} before the filter too"
        );
        // The declaration itself is reachable, by the dotted name it is
        // actually stored under -- see the sibling test. This is the
        // difference the filter must not blur.
    }

    /// #1748: the filter drops a spelling only when *both* declarations agree
    /// -- the renderer never emits the separator for this language, and the
    /// adapter's own lookup vocabulary treats it as a join. Scala satisfies the
    /// first and not the second: its cons class is named `::`, so `::` and
    /// `Foo.::` are ordinary scala short names and `List.:::` is an ordinary
    /// scala method.
    ///
    /// Caught by the parity run rather than by review:
    /// `scala_colon_infix_dispatch_uses_the_right_receiver` and
    /// `scala_infix_right_associative_and_postfix_calls_have_icfg_and_source_order`
    /// both broke on an earlier substring-only filter that used
    /// `absent_segment_separators` alone. Scala's declining to peel on `::` is
    /// the same fact stated once, which is why the two can no longer drift.
    #[test]
    fn issue_1748_scala_colon_named_declarations_are_never_dropped() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(
            root.join("src/Cons.scala"),
            "package coll\n\
             class ::[A](head: A, tail: List[A]) {\n\
             \x20 def :::(other: List[A]): List[A] = other\n\
             }\n",
        )
        .expect("write scala source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Scala));
        let analyzer = TreeSitterAnalyzer::new(project, ScalaAdapter);

        analyzer.reset_structural_miss_spelling_count_for_test();
        for name in ["coll.::", "::", "coll.::.:::", "::.head"] {
            let _ = CodeUnitIndex::definitions(&analyzer, name).count();
        }

        assert_eq!(
            0,
            analyzer.structural_miss_spelling_count_for_test(),
            "scala declares `::` as name text, not as a join, so nothing may be dropped"
        );
    }

    /// The other side of the filter: a dotted rust lookup carries no excluded
    /// separator, so nothing is dropped and every spelling still seeks. This is
    /// what keeps the cut from being a blanket reduction in probes.
    #[test]
    fn issue_1748_dotted_rust_spellings_are_all_still_sought() {
        let (_temp, project) = rust_scoped_lookup_project();
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        analyzer.reset_definition_candidate_row_read_count_for_test();
        analyzer.reset_structural_miss_spelling_count_for_test();
        let dotted: Vec<CodeUnit> =
            CodeUnitIndex::definitions(&analyzer, "probe.inner.Widget").collect();

        assert_eq!(0, analyzer.structural_miss_spelling_count_for_test());
        assert_eq!(
            1,
            analyzer.definition_candidate_row_read_count_for_test(),
            "all seekable spellings belong to one arity-one request relation"
        );
        assert_eq!(
            vec!["probe.inner.Widget"],
            dotted
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn rendered_definition_lookup_reaches_an_empty_mounted_prefix() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "foo.rs");
        file.write(
            "pub struct Foo;\nimpl Foo {\n    pub fn target(&self) {}\n    pub fn other(&self) {}\n}\n",
        )
            .expect("write Rust fixture");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let target = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "target")
            .expect("fixture declares Foo.target");

        assert_eq!(target.fq_name(), "Foo.target");
        assert_eq!(
            vec![target.clone()],
            CodeUnitIndex::definitions(&analyzer, "Foo.target").collect::<Vec<_>>(),
            "an anchored declaration at an empty package prefix must remain addressable"
        );

        let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&scope);
        analyzer.prefetch_definitions(&["Foo.target".to_string(), "Foo.other".to_string()]);
        assert_eq!(
            vec![target],
            CodeUnitIndex::definitions(&analyzer, "Foo.target").collect::<Vec<_>>(),
            "batched lookup must retain the same empty-prefix declaration"
        );
        analyzer.end_query(&scope);
    }

    /// #1774: every caller of the non-persisted workspace declaration scan used
    /// to re-walk the whole live-path set, and the callers are per-name. One
    /// request that resolves several names therefore walked the workspace once
    /// per name. Fails at 3 (one per lookup) before the walk is memoized.
    #[test]
    fn issue_1774_one_request_walks_the_live_path_set_once_for_many_lookups() {
        let (_temp, project) = workspace_scan_probe_project(3);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);

        let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&scope);
        analyzer.reset_workspace_path_scan_count_for_test();
        for index in 0..3 {
            let _ = CodeUnitIndex::lookup_candidates_by_identifier(
                &analyzer,
                &format!("Widget{index}"),
            );
        }
        let scans_in_one_request = analyzer.workspace_path_scan_count_for_test();
        analyzer.end_query(&scope);

        assert_eq!(
            1, scans_in_one_request,
            "a request must materialize the workspace live-path set at most once"
        );
    }

    /// The memo is request scoped, not analyzer scoped: a second request must
    /// see the workspace again rather than inherit the first request's walk.
    #[test]
    fn issue_1774_a_later_request_walks_the_live_path_set_again() {
        let (_temp, project) = workspace_scan_probe_project(2);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);

        analyzer.reset_workspace_path_scan_count_for_test();
        for _ in 0..2 {
            let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
            analyzer.begin_query(&scope);
            let _ = CodeUnitIndex::lookup_candidates_by_identifier(&analyzer, "Widget0");
            analyzer.end_query(&scope);
        }

        assert_eq!(
            2,
            analyzer.workspace_path_scan_count_for_test(),
            "each request must re-read the workspace it was opened against"
        );
    }

    /// The `keep` predicate stays outside the memo, so the narrowed answer is
    /// the same whether the walk was just taken or served from the memo.
    #[test]
    fn issue_1774_memoized_walk_answers_each_name_with_its_own_narrowed_result() {
        let (_temp, project) = workspace_scan_probe_project(3);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);

        let unscoped: Vec<BTreeSet<CodeUnit>> = (0..3)
            .map(|index| {
                CodeUnitIndex::lookup_candidates_by_identifier(&analyzer, &format!("Widget{index}"))
            })
            .collect();

        let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&scope);
        let scoped: Vec<BTreeSet<CodeUnit>> = (0..3)
            .map(|index| {
                CodeUnitIndex::lookup_candidates_by_identifier(&analyzer, &format!("Widget{index}"))
            })
            .collect();
        analyzer.end_query(&scope);

        assert_eq!(unscoped, scoped);
        for (index, matches) in scoped.iter().enumerate() {
            assert!(
                matches
                    .iter()
                    .any(|unit| unit.identifier() == format!("Widget{index}")),
                "lookup {index} must still find its own declaration: {matches:?}"
            );
        }
    }

    /// #1748: `definitions` is asked the same name many times inside one
    /// candidate-discovery pass. Fails at 2 before the request-scoped memo.
    #[test]
    fn issue_1748_repeated_definition_lookups_in_one_request_charge_one_store_read() {
        let (_temp, project) = workspace_scan_probe_project(1);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);

        let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidates_query_count_for_test();
        let first: Vec<CodeUnit> =
            CodeUnitIndex::definitions(&analyzer, "pkg.mod_0.Widget0").collect();
        let second: Vec<CodeUnit> =
            CodeUnitIndex::definitions(&analyzer, "pkg.mod_0.Widget0").collect();
        let queries = analyzer.definition_candidates_query_count_for_test();
        analyzer.end_query(&scope);

        assert_eq!(first, second, "the memo must not change what is resolved");
        assert_eq!(
            1, queries,
            "a request must resolve one definition name with one store read"
        );
    }

    /// Parallel graph workers can reach one fq name before any worker has
    /// published its answer. The complete definition memo must single-flight
    /// that burst, not merely deduplicate its lower-level short-name row read.
    #[test]
    fn issue_1748_concurrent_definition_lookups_of_one_name_charge_one_query() {
        const WORKERS: usize = 8;

        let (_temp, project) = shared_short_name_project(64);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);
        let fq_name = "pkg.mod_0.Shared";
        let expected: Vec<CodeUnit> = CodeUnitIndex::definitions(&analyzer, fq_name).collect();

        let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidates_query_count_for_test();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(WORKERS)
            .build()
            .expect("rayon pool");
        let start = std::sync::Barrier::new(WORKERS);
        let concurrent = pool.broadcast(|_| {
            start.wait();
            CodeUnitIndex::definitions(&analyzer, fq_name).collect::<Vec<CodeUnit>>()
        });
        let queries = analyzer.definition_candidates_query_count_for_test();
        analyzer.end_query(&scope);

        assert!(
            concurrent.iter().all(|answer| answer == &expected),
            "single flight must preserve the definition answer: {concurrent:#?}"
        );
        assert_eq!(
            1, queries,
            "concurrent callers of one fq name must build one complete answer"
        );
    }

    /// With no request open there is no memo, so the behaviour is exactly the
    /// unmemoized lookup. This is what keeps direct-analyzer callers honest.
    #[test]
    fn issue_1748_definition_lookups_outside_a_request_are_not_memoized() {
        let (_temp, project) = workspace_scan_probe_project(1);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);

        analyzer.reset_definition_candidates_query_count_for_test();
        let _ = CodeUnitIndex::definitions(&analyzer, "pkg.mod_0.Widget0").count();
        let _ = CodeUnitIndex::definitions(&analyzer, "pkg.mod_0.Widget0").count();

        assert_eq!(2, analyzer.definition_candidates_query_count_for_test());
    }

    /// A workspace where one short name is shared by `count` distinct fq
    /// names -- the shape that defeated #1748's fq-keyed memo (#1839).
    fn shared_short_name_project(count: usize) -> (tempfile::TempDir, Arc<dyn Project>) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("pkg")).expect("create pkg");
        std::fs::write(root.join("pkg/__init__.py"), "").expect("write package marker");
        for index in 0..count {
            std::fs::write(
                root.join(format!("pkg/mod_{index}.py")),
                "class Shared:\n    pass\n",
            )
            .expect("write module");
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        (temp, project)
    }

    /// Release-only end-to-end definition benchmark for the late-hydration
    /// decision. Fixture construction and analyzer startup are outside the
    /// timed interval; every timed lookup is deliberately unscoped so the
    /// request memo cannot hide store and hydration cost.
    #[test]
    #[ignore = "release-only late FQ hydration benchmark"]
    fn benchmark_shared_short_name_definition_hydration() {
        let candidates = std::env::var("BIFROST_FQ_DEFINITION_CANDIDATES")
            .ok()
            .map(|value| value.parse::<usize>().expect("positive candidate count"))
            .unwrap_or(512);
        let iterations = std::env::var("BIFROST_FQ_DEFINITION_ITERATIONS")
            .ok()
            .map(|value| value.parse::<usize>().expect("positive iteration count"))
            .unwrap_or(20);
        assert!(candidates > 0 && iterations > 0);
        let (_temp, project) = shared_short_name_project(candidates);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);
        let storage_languages = analyzer.storage_language_keys_for_queries();
        let headers = analyzer
            .store_context
            .store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &storage_languages,
                analyzer.store_context.generations.as_ref(),
                "Shared",
                None,
            )
            .expect("read benchmark identity headers");
        assert_eq!(
            headers.rows.len(),
            candidates,
            "the timed lookup starts only after every mounted identity header is visible; fingerprints={:?}",
            analyzer.selected_workspace_snapshots()
        );
        let requested = "pkg.mod_0.Shared";
        let warm = CodeUnitIndex::definitions(&analyzer, requested).collect::<Vec<_>>();
        assert_eq!(warm.len(), 1);

        let started = Instant::now();
        let mut returned = 0usize;
        for _ in 0..iterations {
            let definitions = std::hint::black_box(
                CodeUnitIndex::definitions(&analyzer, requested).collect::<Vec<_>>(),
            );
            returned = returned.saturating_add(definitions.len());
            std::hint::black_box(definitions);
        }
        let elapsed = started.elapsed();
        eprintln!(
            "{{\"benchmark\":\"shared_short_name_definition_hydration\",\"candidates\":{candidates},\"iterations\":{iterations},\"returned\":{returned},\"wall_ns\":{}}}",
            elapsed.as_nanos()
        );
    }

    /// #1839: distinct fq names that share one short name must not transport
    /// the shared candidate page for every spelling. Each logical point is one
    /// mounted request whose SQL result contains only selected identities.
    #[test]
    fn issue_1839_distinct_fq_names_sharing_a_short_name_read_the_rows_once() {
        let (_temp, project) = shared_short_name_project(6);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);
        let names: Vec<String> = (0..6)
            .map(|index| format!("pkg.mod_{index}.Shared"))
            .collect();

        let point: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();

        let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidates_query_count_for_test();
        analyzer.reset_definition_candidate_row_read_count_for_test();
        let memoized: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();
        let row_reads = analyzer.definition_candidate_row_read_count_for_test();
        let point_lookups = analyzer.definition_candidates_query_count_for_test();
        analyzer.end_query(&scope);

        assert_eq!(point, memoized, "the memo must not change any answer");
        assert_eq!(
            6, point_lookups,
            "each distinct fq name is still its own question"
        );
        assert_eq!(
            6, row_reads,
            "each distinct logical point is one mounted SQL request"
        );
    }

    /// #1748 D4: parallel exact lookups sharing a hot short name must stay
    /// bounded by the number of logical points, not multiply that number by
    /// every candidate spelling or transport the shared candidate page.
    #[test]
    fn issue_1748_concurrent_lookups_of_one_short_name_read_the_rows_once() {
        const WORKERS: usize = 8;

        let (_temp, project) = shared_short_name_project(WORKERS);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);
        let names: Vec<String> = (0..WORKERS)
            .map(|index| format!("pkg.mod_{index}.Shared"))
            .collect();

        let sequential: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();

        let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidate_row_read_count_for_test();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(WORKERS)
            .build()
            .expect("rayon pool");
        // Every worker starts its lookup at the same instant: the fan-out
        // shape that originally multiplied each spelling's broad row read.
        let start = std::sync::Barrier::new(WORKERS);
        let concurrent = pool.broadcast(|context| {
            start.wait();
            CodeUnitIndex::definitions(&analyzer, &names[context.index()])
                .collect::<Vec<CodeUnit>>()
        });
        let row_reads = analyzer.definition_candidate_row_read_count_for_test();
        analyzer.end_query(&scope);

        assert_eq!(
            sequential, concurrent,
            "single flight must not change any answer"
        );
        assert_eq!(
            WORKERS, row_reads,
            "each concurrent logical point must issue one mounted request"
        );
    }

    /// The batched prefetch must fill the memo with the same answers the point
    /// lookups produce, in one store read for the whole key set.
    #[test]
    fn issue_1748_prefetched_definitions_match_the_point_lookups_they_replace() {
        let (_temp, project) = workspace_scan_probe_project(4);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);
        let names: Vec<String> = (0..4)
            .map(|index| format!("pkg.mod_{index}.Widget{index}"))
            .collect();

        let point: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();

        let scope = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidates_query_count_for_test();
        analyzer.reset_definition_prefetch_batch_count_for_test();
        analyzer.prefetch_definitions(&names);
        let batches = analyzer.definition_prefetch_batch_count_for_test();
        let prefetched: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();
        let point_lookups = analyzer.definition_candidates_query_count_for_test();
        analyzer.end_query(&scope);

        assert_eq!(point, prefetched, "batched rows must resolve identically");
        assert_eq!(1, batches, "one batched read serves the whole key set");
        assert_eq!(
            0, point_lookups,
            "a prefetched name must not fall back to a point lookup"
        );
    }

    #[test]
    fn terminal_stale_dirty_state_remains_authoritative_without_retrying() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = "class Dirty:\n    pass\n";
        std::fs::write(root.join("dirty.py"), source).unwrap();
        let file = ProjectFile::new(root.clone(), "dirty.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            analyzer.adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            analyzer.adapter.as_ref(),
            &file,
            source.to_string(),
        )
        .unwrap();
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);
        let generation = analyzer.store_context.generations["python"];
        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("python", "cutover-after-failure")
            .unwrap();
        analyzer.state.dirty_file_states.lock().unwrap().insert(
            key.clone(),
            TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
                Arc::new(parsed),
                generation,
                STORE_WRITE_IMMEDIATE_RETRIES + 1,
                "stale generation".to_string(),
                DirtyFileStateStatus::TerminalStale,
            ),
        );
        let starts = analyzer
            .store_context
            .store
            .parsed_blob_transaction_starts_for_test();

        let state = analyzer.retry_dirty_file_state(&key, "python").unwrap();

        assert!(
            state
                .declarations
                .iter()
                .any(|unit| unit.short_name() == "Dirty")
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .parsed_blob_transaction_starts_for_test(),
            starts,
            "terminal stale state must not schedule another obsolete write"
        );
        assert!(
            analyzer
                .state
                .dirty_file_states
                .lock()
                .unwrap()
                .get(&key)
                .unwrap()
                .status
                == DirtyFileStateStatus::TerminalStale
        );
    }

    #[test]
    fn dirty_path_projection_is_authoritative_for_exact_module_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        let source = "def helper():\n    pass\n";
        std::fs::write(root.join("pkg/util.py"), source).unwrap();
        let file = ProjectFile::new(root.clone(), "pkg/util.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let adapter = Arc::new(PythonAdapter);
        let row = TreeSitterAnalyzer::<PythonAdapter>::path_symbol_row(&*adapter, &file, oid)
            .expect("python path projection");
        let mut dirty_path_symbol_rows = HashMap::default();
        dirty_path_symbol_rows.insert(file.clone(), ("python".to_string(), row));

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store_context = AnalyzerStoreContext {
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([(
                "python".to_string(),
                GenerationId::BOOTSTRAP,
            )])),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(
                HashMap::default(),
                HashMap::default(),
                dirty_path_symbol_rows,
                Vec::new(),
            ),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_index_cache(&config)),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_snapshot_caches(
                &config,
            )),
            TreeSitterAnalyzer::build_content_identity_base(&config, &PythonAdapter),
            crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
                config.memo_cache_budget_bytes() / 8,
            ),
            store_context,
            Arc::new(HashMap::default()),
        );

        assert_eq!(
            analyzer
                .get_definitions("pkg.util")
                .into_iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>(),
            vec!["pkg.util".to_string()]
        );
    }

    #[test]
    fn dirty_file_state_is_authoritative_for_bulk_reads() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        let source = "import os\nclass Dirty:\n    pass\n".to_string();
        std::fs::write(root.join("pkg/dirty.py"), &source).unwrap();
        let file = ProjectFile::new(root.clone(), "pkg/dirty.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let adapter = Arc::new(PythonAdapter);
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            &*adapter,
            &file,
            source,
        )
        .expect("python file parses");
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);
        let mut dirty = HashMap::default();
        dirty.insert(
            key,
            TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
                Arc::new(parsed),
                GenerationId::BOOTSTRAP,
                32,
                "forced test persistence failure".to_string(),
                DirtyFileStateStatus::Retryable,
            ),
        );

        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([(
                "python".to_string(),
                GenerationId::BOOTSTRAP,
            )])),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(HashMap::default(), dirty, HashMap::default(), Vec::new()),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_index_cache(&config)),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_snapshot_caches(
                &config,
            )),
            TreeSitterAnalyzer::build_content_identity_base(&config, &PythonAdapter),
            crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
                config.memo_cache_budget_bytes() / 8,
            ),
            store_context,
            Arc::new(HashMap::default()),
        );

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        let states = analyzer.bulk_file_states([file.clone()], BulkFileStateSource::Omit);
        assert!(states.get(&file).is_some_and(|state| {
            state
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg.dirty.Dirty")
        }));
        let imports = analyzer.bulk_import_infos([file.clone()]);
        assert_eq!(
            imports
                .get(&file)
                .and_then(|imports| imports.first())
                .and_then(|import| import.identifier.as_deref()),
            Some("os")
        );

        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionLookup,
            RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
            RelationalName,
        };
        let rendered = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Python,
            "pkg.dirty.Dirty",
            crate::analyzer::fq_name::segment_interner(),
        );
        let requests = [
            RelationalDefinitionRequest {
                ordinal: 1,
                language_scope: DefinitionLanguageScope::Language(Language::Python),
                name: RelationalName::stable(rendered.clone()),
                query: RelationalDefinitionQuery::ExactName,
            },
            RelationalDefinitionRequest {
                ordinal: 2,
                language_scope: DefinitionLanguageScope::Language(Language::Python),
                name: RelationalName::stable(rendered),
                query: RelationalDefinitionQuery::NormalizedName,
            },
        ];
        let RelationalBatchOutcome::Complete(results) =
            analyzer.batch(&requests, &CancellationToken::new())
        else {
            panic!("dirty rendered-name batch must complete")
        };
        for result in results {
            let RelationalDefinitionValue::Definitions(units) = result.value else {
                panic!("rendered-name lookup returned the wrong value shape")
            };
            assert_eq!(
                units.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
                ["pkg.dirty.Dirty"],
                "rendered input must have the same kind-insensitive semantics in the dirty overlay"
            );
        }
    }

    #[test]
    fn storage_adapter_identity_defaults_preserve_in_memory_facts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/Service.java");
        let adapter = JavaAdapter;
        let unit = CodeUnit::new(file.clone(), CodeUnitType::Class, "example", "Service");
        let mut state = empty_file_state("class Service {}\n", true);
        state.declarations.insert(unit.clone());
        let before = state.clone();

        assert_eq!(adapter.storage_language_key_for_file(&file), "java");
        assert_eq!(adapter.storage_language_keys().len(), 1);
        assert_eq!(
            adapter.storage_content_qualifier(&unit, "example"),
            "example"
        );
        assert_eq!(adapter.storage_file_content_qualifier("example"), "example");
        assert_eq!(
            adapter.hydrate_content_qualifier("example", &file),
            "example"
        );
        assert!(adapter.should_persist_code_unit(&unit));
        assert!(!adapter.should_persist_code_unit(&CodeUnit::file_scope(file.clone())));
        assert!(adapter.storage_contains_tests(&state));
        assert!(adapter.hydrate_contains_tests(true, &file, &state.source));

        let source = state.source.clone();
        adapter.synthesize_hydrated_units(&file, &source, &mut state);
        assert_eq!(state.declarations, before.declarations);
        assert_eq!(state.top_level_declarations, before.top_level_declarations);
        assert_eq!(state.ranges, before.ranges);
    }

    #[test]
    fn storage_adapter_path_qualifiers_reconstruct_workspace_identity() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");

        let python_file = temp_file(&root, "pkg/service.py");
        python_file.write("class Service:\n    pass\n").unwrap();
        let python = PythonAdapter;
        let python_unit = CodeUnit::new(
            python_file.clone(),
            CodeUnitType::Class,
            "pkg.service",
            "Service",
        );
        assert_eq!(python.storage_content_qualifier(&python_unit, ""), "");
        assert_eq!(python.storage_file_content_qualifier("pkg.service"), "");
        assert_eq!(
            python.hydrate_content_qualifier("", &python_file),
            "pkg.service"
        );

        let rust_file = temp_file(&root, "src/net/mod.rs");
        let rust = RustAdapter;
        let rust_unit = CodeUnit::new(rust_file.clone(), CodeUnitType::Class, "net", "Client");
        assert_eq!(rust.storage_content_qualifier(&rust_unit, ""), "");
        assert_eq!(rust.hydrate_content_qualifier("", &rust_file), "net");
        let rust_impl_member = CodeUnit::with_signature(
            rust_file.clone(),
            CodeUnitType::Function,
            "model",
            "Writer.write",
            Some("impl Writer::fn write(&self) { ... }".to_string()),
            false,
        );
        // Rust names are persisted as an anchor plus a content-stable tail, so
        // no unit — however it is qualified — bakes package text into its row.
        assert_eq!(rust.storage_content_qualifier(&rust_impl_member, "net"), "");
        assert_eq!(rust.hydrate_content_qualifier("model", &rust_file), "model");
        let file_package = rust
            .resolve_package_anchor(PackageAnchor::OwnModule { pop: 0 }, "", &rust_file)
            .expect("Rust resolves its own-module anchor");
        assert_eq!(
            file_package.display(crate::analyzer::fq_name::segment_interner()),
            "net"
        );
        assert_eq!(
            rust.resolve_package_anchor(PackageAnchor::OwnModule { pop: 1 }, "", &rust_file)
                .expect("Rust resolves a popped own-module anchor")
                .display(crate::analyzer::fq_name::segment_interner()),
            ""
        );
        // A crate mounted at the repository root has an empty crate-root
        // prefix; that is a resolved empty prefix, not an unresolvable anchor.
        assert_eq!(
            rust.resolve_package_anchor(PackageAnchor::CrateRoot, "", &rust_file)
                .expect("Rust resolves its crate-root anchor")
                .display(crate::analyzer::fq_name::segment_interner()),
            ""
        );

        std::fs::write(root.join("go.mod"), "module example.com/demo\n").unwrap();
        let go_file = temp_file(&root, "internal/service/service.go");
        go_file
            .write("package service\n\ntype Service struct{}\n")
            .unwrap();
        let go = GoAdapter;
        let go_unit = CodeUnit::new(
            go_file.clone(),
            CodeUnitType::Class,
            "example.com/demo/internal/service",
            "Service",
        );
        assert_eq!(go.storage_content_qualifier(&go_unit, "service"), "service");
        assert_eq!(
            go.hydrate_content_qualifier("", &go_file),
            "example.com/demo/internal/service"
        );
    }

    #[test]
    fn storage_adapter_path_units_and_tests_reconstruct_after_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let tsx_file = temp_file(&root, "src/widget.test.tsx");
        let source = "import { value } from './value';\ntest('value', () => value());\n";
        let adapter = TypescriptAdapter;

        assert_eq!(
            adapter.storage_language_key_for_file(&tsx_file),
            "typescript:tsx"
        );
        assert_eq!(
            adapter
                .storage_language_keys()
                .into_iter()
                .map(|(key, _)| key)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["typescript:ts".to_string(), "typescript:tsx".to_string()])
        );

        let mut state = empty_file_state(source, true);
        state.imports.push(ImportInfo {
            raw_snippet: "import { value } from './value';".to_string(),
            is_wildcard: false,
            is_global: false,
            identifier: Some("value".to_string()),
            alias: None,
            path: None,
            binder_span: None,
        });
        assert!(adapter.storage_contains_tests(&state));
        assert!(adapter.hydrate_contains_tests(false, &tsx_file, ""));

        adapter.synthesize_hydrated_units(&tsx_file, source, &mut state);
        let module = state
            .top_level_declarations
            .iter()
            .find(|unit| unit.is_module())
            .expect("synthetic TypeScript module");
        assert!(!adapter.should_persist_code_unit(module));
        assert!(state.declarations.contains(module));
        assert_eq!(state.ranges.get(module).map(Vec::len), Some(1));

        let js_file = temp_file(&root, "src/widget.spec.js");
        let javascript = JavascriptAdapter;
        assert!(javascript.hydrate_contains_tests(false, &js_file, ""));
        let mut js_state = empty_file_state(source, true);
        js_state.imports = state.imports.clone();
        javascript.synthesize_hydrated_units(&js_file, source, &mut js_state);
        let js_module = js_state
            .top_level_declarations
            .iter()
            .find(|unit| unit.is_module())
            .expect("synthetic JavaScript module");
        assert!(!javascript.should_persist_code_unit(js_module));
        assert!(js_state.declarations.contains(js_module));
        assert_eq!(js_state.ranges.get(js_module).map(Vec::len), Some(1));
    }

    #[test]
    fn storage_adapter_python_synthesizes_path_module_and_children() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "pkg/service.py");
        let source = "class Service:\n    pass\n";
        let class = CodeUnit::new(file.clone(), CodeUnitType::Class, "pkg.service", "Service");
        let mut state = empty_file_state(source, false);
        state.top_level_declarations.push(class.clone());
        state.declarations.insert(class.clone());

        let adapter = PythonAdapter;
        adapter.synthesize_hydrated_units(&file, source, &mut state);
        let module = state
            .top_level_declarations
            .first()
            .expect("synthetic Python module");
        assert!(module.is_module());
        assert_eq!(module.fq_name(), "pkg.service");
        assert!(!adapter.should_persist_code_unit(module));
        assert_eq!(state.children.get(module), Some(&vec![class]));
        assert_eq!(state.ranges.get(module).map(Vec::len), Some(1));
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn type_alias_projection_avoids_full_file_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        for index in 0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY {
            std::fs::write(
                root.join(format!("src/Alias{index}.cpp")),
                format!("using Alias{index} = int;\n"),
            )
            .expect("write alias source");
        }

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let aliases = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.identifier().starts_with("Alias"))
            .collect::<Vec<_>>();
        assert_eq!(aliases.len(), SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1);

        analyzer.reset_full_hydration_count_for_test();
        assert!(aliases.iter().all(|alias| analyzer.is_type_alias(alias)));
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "persisted type-alias checks must not hydrate a FileState"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn signature_projection_avoids_full_file_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        for index in 0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY {
            std::fs::write(
                root.join(format!("src/Alias{index}.cpp")),
                format!("using Alias{index} = int;\n"),
            )
            .expect("write alias source");
        }

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let aliases = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.identifier().starts_with("Alias"))
            .collect::<Vec<_>>();
        assert_eq!(aliases.len(), SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1);

        analyzer.reset_full_hydration_count_for_test();
        for alias in &aliases {
            assert!(
                analyzer
                    .signatures(alias)
                    .iter()
                    .any(|signature| signature.contains(alias.identifier())),
                "persisted signature must include {}",
                alias.identifier()
            );
        }
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "persisted signature reads must not hydrate a FileState"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn enclosing_declaration_projection_avoids_full_file_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        for index in 0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY {
            std::fs::write(
                root.join(format!("src/Owner{index}.cpp")),
                format!(
                    "namespace demo {{ struct Owner{index} {{ int method{index}() {{ return {index}; }} }}; }}\n"
                ),
            )
            .expect("write C++ source");
        }

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let methods = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.identifier().starts_with("method"))
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1);

        analyzer.reset_full_hydration_count_for_test();
        for method in methods {
            let file = method.source().clone();
            let source = std::fs::read_to_string(file.abs_path()).expect("C++ source");
            let start_byte = source.find("return").expect("return statement");
            let range = Range {
                start_byte,
                end_byte: start_byte + "return".len(),
                start_line: 0,
                end_line: 0,
            };
            assert_eq!(analyzer.enclosing_code_unit(&file, &range), Some(method));
        }
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "persisted owner lookup must not hydrate a FileState"
        );
    }

    #[test]
    fn file_source_avoids_full_file_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let files: Vec<_> = (0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY)
            .map(|index| {
                let file = temp_file(&root, &format!("src/file{index}.rs"));
                file.write(format!("pub fn declared{index}() {{}}\n"))
                    .expect("write Rust source");
                file
            })
            .collect();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        analyzer.get_all_declarations();
        let outside = files
            .iter()
            .find(|file| analyzer.source_snapshot_file_state(file).is_none())
            .cloned()
            .expect("analyzed file outside the source snapshot index");
        // A structural seed scan asks every analyzed file for its source, long
        // after the build's own file states have turned over. Drop them so the
        // read below has only the blob or a full hydration to answer from.
        analyzer
            .transient_file_states
            .lock()
            .expect("transient file-state cache mutex poisoned")
            .clear();
        analyzer.reset_full_hydration_count_for_test();

        let expected = std::fs::read_to_string(outside.abs_path()).expect("Rust source");
        assert_eq!(analyzer.file_source(&outside).as_deref(), Some(&*expected));
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "a source read must not hydrate a FileState (#2642)"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn batched_enclosing_projection_matches_single_range_queries() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let mut files: Vec<_> = (0..SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY)
            .map(|index| {
                let file = temp_file(&root, &format!("src/Owner{index}.cpp"));
                file.write(format!(
                    "namespace demo {{ struct Owner{index} {{ int first() {{ return 1; }} int second() {{ return 2; }} }}; }}\n"
                ))
                .expect("write C++ source");
                file
            })
            .collect();
        let target = temp_file(&root, "src/ZOwner.cpp");
        target
            .write(
                "namespace demo { struct ZOwner { int first() { return 1; } int second() { return 2; } }; }\n",
            )
            .expect("write C++ source");
        files.push(target);

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        analyzer.get_all_declarations();
        let file = files
            .iter()
            .find(|file| analyzer.source_snapshot_file_state(file).is_none())
            .expect("analyzed file outside the source snapshot index");
        assert!(analyzer.source_snapshot_file_state(file).is_none());
        let source = std::fs::read_to_string(file.abs_path()).expect("C++ source");
        let mut ranges = ["return 1", "return 2"]
            .into_iter()
            .map(|needle| {
                let start_byte = source.find(needle).expect("range needle");
                Range {
                    start_byte,
                    end_byte: start_byte + needle.len(),
                    start_line: 0,
                    end_line: 0,
                }
            })
            .collect::<Vec<_>>();
        ranges.push(Range {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            end_line: 0,
        });

        analyzer.reset_full_hydration_count_for_test();
        let expected = ranges
            .iter()
            .map(|range| analyzer.enclosing_code_unit(file, range))
            .collect::<Vec<_>>();
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        analyzer
            .enclosing_code_unit_store
            .lock()
            .expect("enclosing code-unit store mutex poisoned")
            .clear();
        assert_eq!(
            analyzer
                .enclosing_code_unit_store
                .lock()
                .expect("enclosing code-unit store mutex poisoned")
                .entry_count(),
            0,
            "batch must build the persisted projection index rather than reuse point-query state"
        );

        analyzer.reset_enclosing_parent_query_counts_for_test();
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("C++ structural provider");
        let actual = provider
            .structural_enclosing_code_units(file, &ranges)
            .expect("C++ batch enclosure capability");

        assert_eq!(actual, expected);
        assert_eq!(
            analyzer.enclosing_code_unit_query_count_for_test(),
            ranges.len(),
            "batch enclosure should retain one logical query per requested range"
        );
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        assert_eq!(
            analyzer
                .enclosing_code_unit_store
                .lock()
                .expect("enclosing code-unit store mutex poisoned")
                .entry_count(),
            1,
            "all ranges should reuse one persisted declaration index"
        );
    }

    #[test]
    fn enclosing_code_unit_interval_index_reuses_large_file_ranges() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let source = (0..=ENCLOSING_CODE_UNIT_INDEX_MIN_DECLARATIONS)
            .map(|index| format!("int method{index}() {{ return {index}; }}\n"))
            .collect::<String>();
        let file = temp_file(&root, "src/methods.cpp");
        file.write(&source).expect("write C++ source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let methods = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.identifier().starts_with("method"))
            .collect::<Vec<_>>();
        assert_eq!(
            methods.len(),
            ENCLOSING_CODE_UNIT_INDEX_MIN_DECLARATIONS + 1
        );

        analyzer.reset_full_hydration_count_for_test();
        for method in methods {
            let index = method
                .identifier()
                .strip_prefix("method")
                .expect("method declaration")
                .parse::<usize>()
                .expect("method index");
            let needle = format!("return {index}");
            let start_byte = source.find(&needle).expect("return statement");
            let range = Range {
                start_byte,
                end_byte: start_byte + needle.len(),
                start_line: 0,
                end_line: 0,
            };
            assert_eq!(analyzer.enclosing_code_unit(&file, &range), Some(method));
        }
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        assert_eq!(
            analyzer
                .enclosing_code_unit_store
                .lock()
                .expect("enclosing code-unit store mutex poisoned")
                .entry_count(),
            1,
            "all large-file owner lookups must reuse one interval index"
        );
    }

    #[test]
    fn stale_definition_query_records_failure_while_healthy_miss_does_not() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        let healthy = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&healthy);
        assert!(analyzer.definitions("Missing").next().is_none());
        assert!(healthy.store_error().is_none());
        analyzer.end_query(&healthy);

        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("java", "cutover-before-definition-read")
            .unwrap();
        let stale = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&stale);
        assert!(analyzer.definitions("Model").next().is_none());
        let error = stale
            .store_error()
            .expect("stale definition query should report its store error");
        assert!(error.to_string().contains("querying definition candidates"));
        assert!(error.to_string().contains("stale analyzer generation"));
        analyzer.end_query(&stale);
    }

    #[test]
    fn bounded_regression_stale_candidate_queries_never_report_complete_misses() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::write(root.join("Model.java"), "class Model { void work() {} }\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("java", "cutover-before-bounded-candidate-read")
            .unwrap();
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&context);

        let by_identifier =
            analyzer.lookup_declarations_by_identifier_limited("Model", 16, || true);
        let non_module =
            analyzer.lookup_non_module_declarations_by_identifier_limited("Model", 16, || true);
        let by_fqn =
            analyzer.lookup_declarations_by_persisted_fqn_limited("Model", false, 16, || true);
        let members = analyzer.lookup_members_for_owner_name_limited("Model", "work", 16, || true);

        for batch in [by_identifier, non_module, by_fqn, members] {
            assert!(
                !batch.complete,
                "a failed bounded store read must not become an authoritative miss"
            );
            assert!(batch.rows.is_empty());
        }
        assert!(
            context
                .store_error()
                .expect("stale bounded reads should record their store error")
                .to_string()
                .contains("stale analyzer generation")
        );
        analyzer.end_query(&context);
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn query_read_cache_keeps_broad_traversals_out_of_the_lru_eviction_loop() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let files: Vec<_> = (0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY)
            .map(|index| {
                let file = temp_file(&root, &format!("src/Type{index}.java"));
                file.write(format!("package demo; class Type{index} {{}}\n"))
                    .expect("java source");
                file
            })
            .collect();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer.reset_full_hydration_count_for_test();

        let outer = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        let inner = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&outer);
        for file in &files {
            assert!(analyzer.fetch_file_state(file).is_some());
        }
        analyzer.begin_query(&inner);
        for file in &files {
            assert!(analyzer.fetch_file_state(file).is_some());
        }
        analyzer.end_query(&inner);

        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1
        );

        analyzer.end_query(&outer);
        assert!(analyzer.fetch_file_state(&files[0]).is_some());
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1,
            "the shared byte budget retains this small working set after the query ends"
        );
    }

    #[test]
    fn query_read_cache_does_not_retain_prepared_syntax_past_capacity() {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        let mut cache = QueryReadCache::default();
        cache.begin(&context);
        let first = PreparedSyntaxCacheKey {
            file_state: FileStateCacheKey {
                oid: Oid::hash_object(ObjectType::Blob, b"first").expect("first oid"),
                rel_path: PathBuf::from("first.cpp"),
            },
            origin: PreparedSourceOrigin::Disk,
            overlay_revision: None,
            flavor: PreparedSyntaxCacheFlavor::Indexed,
        };
        let second = PreparedSyntaxCacheKey {
            file_state: FileStateCacheKey {
                oid: Oid::hash_object(ObjectType::Blob, b"second").expect("second oid"),
                rel_path: PathBuf::from("second.cpp"),
            },
            origin: PreparedSourceOrigin::Disk,
            overlay_revision: None,
            flavor: PreparedSyntaxCacheFlavor::Indexed,
        };

        let first_cell = cache
            .prepared_syntax_cell_with_capacity(first.clone(), 1)
            .expect("first retained cell");
        let repeated = cache
            .prepared_syntax_cell_with_capacity(first, 1)
            .expect("existing retained cell");
        assert!(Arc::ptr_eq(&first_cell, &repeated));
        assert!(
            cache
                .prepared_syntax_cell_with_capacity(second, 1)
                .is_none(),
            "a new file must be prepared without retention at capacity"
        );
        assert_eq!(
            cache
                .prepared_syntax
                .read()
                .expect("query prepared-syntax cache read lock poisoned")
                .len(),
            1
        );
    }

    #[test]
    fn query_read_cache_reuses_analyzed_live_files_until_the_outer_scope_ends() {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        let mut cache = QueryReadCache::default();
        let files = vec![ProjectFile::new(std::env::temp_dir(), "src/lib.rs")];

        cache.begin(&context);
        assert!(cache.analyzed_live_files().is_none());
        cache.retain_analyzed_live_files(files.clone());
        assert_eq!(cache.analyzed_live_files(), Some(files));

        cache.end(&context);
        assert!(
            cache.analyzed_live_files().is_none(),
            "a later analyzer request must validate its own live-file snapshot"
        );
    }

    /// Direct analyzers keep a stable filesystem generation until callers
    /// explicitly report an edit with `update`.
    #[test]
    fn analyzed_live_files_refresh_only_after_explicit_update() {
        // Git-backed on purpose: `resolve_live_oids` only routes through
        // `LivePathValidation::Filesystem` (the `PathState.stat: Some(_)`
        // shape M3 memoizes) when `store_context.liveness` resolves a repo
        // for the project root; a non-git `TestProject` falls back to
        // treating every live path as an "overlay" with `stat: None`, which
        // never calls `fs::metadata` in the first place (unrelated to this
        // milestone) and so would not exercise the memoization at all.
        let temp = tempfile::TempDir::new().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(temp.path());
        std::fs::write(temp.path().join("A.java"), "public class A {}\n").unwrap();
        crate::gitblob::test_repo::commit_all(&repo, "init");
        let root = temp.path().to_path_buf();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        let first = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&first);
        let files_first = analyzer.analyzed_live_files();
        assert_eq!(files_first.len(), 1, "files: {files_first:?}");
        let stats_after_listing = crate::analyzer::store::liveness::stat_call_count_for_test();
        let oid_first = analyzer
            .resolve_live_oid_for_file(&files_first[0])
            .expect("initial live oid");
        assert_eq!(
            crate::analyzer::store::liveness::stat_call_count_for_test(),
            stats_after_listing,
            "the analyzed-file pass should seed live OIDs for the rest of its query scope"
        );
        analyzer.end_query(&first);

        // An out-of-band edit remains invisible until the caller reports it.
        std::fs::write(
            temp.path().join("A.java"),
            "public class A { void m() {} }\n",
        )
        .unwrap();
        crate::analyzer::store::liveness::reset_stat_call_count_for_test();
        let second = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&second);
        let files_second = analyzer.analyzed_live_files();
        let oid_before_update = analyzer
            .resolve_live_oid_for_file(&files_second[0])
            .expect("retained live oid");
        analyzer.end_query(&second);
        assert_eq!(files_second, files_first);
        assert_eq!(oid_before_update, oid_first);
        assert_eq!(
            crate::analyzer::store::liveness::stat_call_count_for_test(),
            0,
            "an unrelated query must trust the analyzer's current filesystem generation"
        );

        // The explicit update bumps the generation and records the new state.
        let file = ProjectFile::new(temp.path().to_path_buf(), PathBuf::from("A.java"));
        let updated = analyzer.update(&BTreeSet::from([file]));

        // The updated analyzer exposes the new identity without another sweep.
        crate::analyzer::store::liveness::reset_stat_call_count_for_test();
        let third = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        updated.begin_query(&third);
        let files_third = updated.analyzed_live_files();
        let oid_after_update = updated
            .resolve_live_oid_for_file(&files_third[0])
            .expect("updated live oid");
        updated.end_query(&third);
        assert_eq!(files_third.len(), 1, "files: {files_third:?}");
        assert_ne!(oid_after_update, oid_first);
        assert_eq!(
            crate::analyzer::store::liveness::stat_call_count_for_test(),
            0,
            "the explicit update already established the new filesystem generation"
        );

        // Later query contexts continue reusing that generation.
        crate::analyzer::store::liveness::reset_stat_call_count_for_test();
        let fourth = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        updated.begin_query(&fourth);
        let files_fourth = updated.analyzed_live_files();
        updated.end_query(&fourth);
        assert_eq!(files_fourth, files_third);
        assert_eq!(
            crate::analyzer::store::liveness::stat_call_count_for_test(),
            0,
            "a later query must not re-stat the updated filesystem generation"
        );
    }

    #[test]
    fn bulk_file_state_snapshot_reuses_and_resets_across_query_scopes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let project = Arc::new(CountingOverlayProject::new(&root, "fn target() {}\n"));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        let file = ProjectFile::new(&root, "src/main.rs");

        let first = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&first);
        analyzer.reset_full_hydration_count_for_test();
        analyzer.bulk_file_states_for_query([file.clone()], BulkFileStateSource::Include);

        let oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("overlay OID");
        let key = TreeSitterAnalyzer::<RustAdapter>::transient_cache_key(oid, &file);
        let snapshot_guard = analyzer.query_file_state_snapshot.load();
        let snapshot = snapshot_guard
            .as_ref()
            .expect("bulk hydration should publish a file-state snapshot");
        let query_budget = {
            let cache = analyzer.query_read_cache_lock();
            cache
                .file_states
                .read()
                .expect("query file-state cache read lock poisoned")
                .max_bytes
        };
        let snapshot_bytes = snapshot
            .values()
            .map(|state| state.estimated_retained_bytes())
            .fold(0usize, usize::saturating_add);
        assert!(
            snapshot_bytes <= query_budget,
            "snapshot must stay within its request budget"
        );
        assert!(snapshot.contains_key(&key));

        // Remove the ordinary request and transient entries so a successful
        // fetch below proves it came from the immutable bulk snapshot.
        let file_states = {
            let cache = analyzer.query_read_cache_lock();
            Arc::clone(&cache.file_states)
        };
        file_states
            .write()
            .expect("query file-state cache write lock poisoned")
            .clear();
        {
            let mut transient = analyzer
                .transient_file_states
                .lock()
                .expect("transient file-state cache mutex poisoned");
            transient.clear();
        }

        let state = analyzer
            .fetch_file_state(&file)
            .expect("snapshot-backed file state");
        assert_eq!(state.source.as_str(), "fn target() {}\n");
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "fetch should reuse the immutable bulk snapshot"
        );
        let unit = state
            .top_level_declarations
            .first()
            .cloned()
            .expect("function declaration");
        assert!(
            !analyzer.ranges_limited(&unit, 8).rows.is_empty(),
            "ranges should also read the snapshot-backed state"
        );
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);

        analyzer.end_query(&first);
        assert!(
            analyzer.query_file_state_snapshot.load().as_ref().is_none(),
            "ending the outer query must clear the immutable snapshot"
        );

        project.set_source("fn changed() {}\n");
        let second = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&second);
        analyzer.reset_full_hydration_count_for_test();
        let changed = analyzer
            .fetch_file_state(&file)
            .expect("changed overlay file state");
        assert_eq!(changed.source.as_str(), "fn changed() {}\n");
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            1,
            "a new query must hydrate the changed OID after snapshot reset"
        );
        analyzer.end_query(&second);
    }

    #[test]
    fn prepared_syntax_is_reused_sequentially_within_outer_query_scope() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);

        let first = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("first syntax");
        let second = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("reused syntax");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
        assert_eq!(
            first.source(),
            "fn target() {}\nfn consumer() { target(); }\n"
        );
    }

    /// #1450: the per-request cell above is dropped when the outer scope ends,
    /// so without a cross-request layer every later request re-parses. The
    /// retained tree is the *same* `Arc`, which is what makes the warm scan
    /// cost graph assembly rather than 662 parses.
    #[test]
    fn prepared_syntax_survives_across_outer_query_scopes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let first = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("first syntax")
        };
        let second = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("retained syntax")
        };

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    /// The `ExactSource` flavor shares the mechanism, and it is a distinct
    /// cache entry from `Indexed`, so it is pinned separately.
    #[test]
    fn prepared_exact_syntax_survives_across_outer_query_scopes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let exact = |label: &str| {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            match analyzer.prepared_syntax_limited(scope.token(), &file, 1 << 20) {
                Ok(Some((_, prepared))) => prepared,
                other => panic!("{label} exact syntax: {other:?}"),
            }
        };
        let first = exact("first");
        let second = exact("retained");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    /// The correctness claim behind retaining trees at all: entries are keyed
    /// by blob oid, so an out-of-band edit lands on a different key and the
    /// next request parses the new bytes. A path-keyed cache serves the stale
    /// tree here.
    #[test]
    fn prepared_syntax_reparses_after_the_file_changes_between_query_scopes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\n").expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let first = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("first syntax")
        };
        assert_eq!(first.source(), "fn target() {}\n");

        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("edited rust source");
        let second = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("edited syntax")
        };

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(
            second.source(),
            "fn target() {}\nfn consumer() { target(); }\n"
        );
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 2);

        // Restoring the original bytes restores the original key, and the
        // still-retained tree answers it without a third parse.
        file.write("fn target() {}\n")
            .expect("restored rust source");
        let restored = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("restored syntax")
        };
        assert!(Arc::ptr_eq(&first, &restored));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 2);
    }

    /// The store is bounded by estimated retained bytes, not entry count, so a
    /// workspace larger than the budget evicts by recency instead of growing.
    #[test]
    fn prepared_syntax_store_evicts_the_least_recently_used_entry_past_its_bound() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\n").expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let prepared = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("syntax");

        let key = |seed: u8| PreparedSyntaxCacheKey {
            file_state: FileStateCacheKey {
                oid: Oid::hash_object(ObjectType::Blob, &[seed]).expect("blob oid"),
                rel_path: PathBuf::from("src/main.rs"),
            },
            origin: PreparedSourceOrigin::Disk,
            overlay_revision: None,
            flavor: PreparedSyntaxCacheFlavor::Indexed,
        };
        let entry_bytes = prepared
            .source()
            .len()
            .saturating_mul(PREPARED_SYNTAX_BYTES_PER_SOURCE_BYTE)
            .saturating_add(PREPARED_SYNTAX_STORE_ENTRY_OVERHEAD_BYTES);
        // Holds two entries and not three: the third insert overflows, and the
        // 7/8 watermark is still above two entries, so exactly one is evicted.
        let mut store = PreparedSyntaxStore::new(entry_bytes * 5 / 2);

        store.retain(key(1), Arc::clone(&prepared));
        store.retain(key(2), Arc::clone(&prepared));
        // Touching the first entry makes the second the least recent.
        assert!(store.get(&key(1)).is_some());
        store.retain(key(3), Arc::clone(&prepared));

        assert!(store.get(&key(1)).is_some(), "recently used entry evicted");
        assert!(store.get(&key(2)).is_none(), "least recent entry retained");
        assert!(store.get(&key(3)).is_some(), "newest entry evicted");
        assert!(store.retained_bytes <= store.max_bytes);

        // An evicted key is simply a miss: the caller reparses and re-retains.
        store.retain(key(2), Arc::clone(&prepared));
        assert!(store.get(&key(2)).is_some());
        assert!(store.retained_bytes <= store.max_bytes);
    }

    /// A single tree larger than the whole budget is never retained: holding it
    /// would evict everything else and then be dropped by the next insert.
    #[test]
    fn prepared_syntax_store_refuses_an_entry_larger_than_its_bound() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\n").expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let prepared = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("syntax");

        let mut store = PreparedSyntaxStore::new(PREPARED_SYNTAX_STORE_ENTRY_OVERHEAD_BYTES);
        let key = PreparedSyntaxCacheKey {
            file_state: FileStateCacheKey {
                oid: Oid::hash_object(ObjectType::Blob, b"oversized").expect("blob oid"),
                rel_path: PathBuf::from("src/main.rs"),
            },
            origin: PreparedSourceOrigin::Disk,
            overlay_revision: None,
            flavor: PreparedSyntaxCacheFlavor::Indexed,
        };
        store.retain(key.clone(), prepared);

        assert!(store.get(&key).is_none());
        assert_eq!(store.retained_bytes, 0);
    }

    fn import_infos(snippets: &[&str]) -> Arc<[ImportInfo]> {
        snippets
            .iter()
            .map(|snippet| ImportInfo {
                raw_snippet: (*snippet).to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: None,
                alias: None,
                path: None,
                binder_span: None,
            })
            .collect()
    }

    fn import_key(seed: u8) -> FileStateCacheKey {
        FileStateCacheKey {
            oid: Oid::hash_object(ObjectType::Blob, &[seed]).expect("blob oid"),
            rel_path: PathBuf::from("src/main.rs"),
        }
    }

    /// The store is bounded by estimated retained bytes, not entry count, so a
    /// workspace larger than the budget evicts by recency instead of growing.
    #[test]
    fn import_info_store_evicts_the_least_recently_used_entry_past_its_bound() {
        let imports = import_infos(&["use crate::target::collect_it;"]);
        let entry_bytes = imports.estimated_bytes();
        // Holds two entries and not three: the third insert overflows, and the
        // 7/8 watermark is still above two entries, so exactly one is evicted.
        let mut store = ImportInfoStore::new(entry_bytes * 5 / 2);

        store.retain(import_key(1), Arc::clone(&imports));
        store.retain(import_key(2), Arc::clone(&imports));
        // Touching the first entry makes the second the least recent.
        assert!(store.get(&import_key(1)).is_some());
        store.retain(import_key(3), Arc::clone(&imports));

        assert!(
            store.get(&import_key(1)).is_some(),
            "recently used entry evicted"
        );
        assert!(
            store.get(&import_key(2)).is_none(),
            "least recent entry retained"
        );
        assert!(store.get(&import_key(3)).is_some(), "newest entry evicted");
        assert!(store.retained_bytes <= store.max_bytes);

        // An evicted key is simply a miss: the caller rehydrates and re-retains.
        store.retain(import_key(2), imports);
        assert!(store.get(&import_key(2)).is_some());
        assert!(store.retained_bytes <= store.max_bytes);
    }

    /// A file whose imports alone exceed the whole budget is never retained:
    /// holding it would evict everything else and then be dropped by the next
    /// insert.
    #[test]
    fn import_info_store_refuses_an_entry_larger_than_its_bound() {
        let mut store = ImportInfoStore::new(IMPORT_INFO_STORE_ENTRY_OVERHEAD_BYTES);
        let key = import_key(1);
        store.retain(
            key.clone(),
            import_infos(&["use crate::target::collect_it;"]),
        );

        assert!(store.get(&key).is_none());
        assert_eq!(store.retained_bytes, 0);
    }

    /// The dirty overlay holds a parse the store has not accepted yet, so it
    /// outranks anything the cross-request store retained for the same key.
    #[test]
    fn dirty_imports_outrank_a_retained_import_info_entry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = "import dirty_module\n".to_string();
        std::fs::write(root.join("dirty.py"), &source).unwrap();
        let file = ProjectFile::new(root.clone(), "dirty.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let adapter = Arc::new(PythonAdapter);
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            &*adapter,
            &file,
            source,
        )
        .expect("python file parses");
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);
        let mut dirty = HashMap::default();
        dirty.insert(
            key.clone(),
            TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
                Arc::new(parsed),
                GenerationId::BOOTSTRAP,
                32,
                "forced test persistence failure".to_string(),
                DirtyFileStateStatus::Retryable,
            ),
        );

        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let store_context = AnalyzerStoreContext {
            store,
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([(
                "python".to_string(),
                GenerationId::BOOTSTRAP,
            )])),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(HashMap::default(), dirty, HashMap::default(), Vec::new()),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_index_cache(&config)),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_snapshot_caches(
                &config,
            )),
            TreeSitterAnalyzer::build_content_identity_base(&config, &PythonAdapter),
            crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
                config.memo_cache_budget_bytes() / 8,
            ),
            store_context,
            Arc::new(HashMap::default()),
        );

        // Seed the cross-request store with a value the dirty state contradicts.
        analyzer.import_info_store_retain(key, import_infos(&["import stale_module"]));

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let imports = analyzer.import_info_of(token, &file);
        assert_eq!(
            vec!["dirty_module".to_string()],
            imports
                .iter()
                .filter_map(|import| import.identifier.clone())
                .collect::<Vec<_>>(),
            "dirty imports must outrank the retained entry; got {imports:#?}"
        );
        assert_eq!(analyzer.import_info_hydration_count_for_test(), 0);
    }

    #[test]
    fn prepared_syntax_initializes_once_for_concurrent_queries() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let barrier = Arc::new(Barrier::new(8));

        let prepared: Vec<_> = std::thread::scope(|threads| {
            let analyzer = &analyzer;
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let file = file.clone();
                    threads.spawn(move || {
                        barrier.wait();
                        let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
                        analyzer
                            .prepared_syntax(scope.token(), &file)
                            .expect("prepared syntax")
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("syntax worker"))
                .collect()
        });

        assert!(
            prepared
                .iter()
                .skip(1)
                .all(|syntax| Arc::ptr_eq(&prepared[0], syntax))
        );
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    #[test]
    fn prepared_syntax_refreshes_after_outer_scope_and_overlay_change() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        file.write("fn disk() {}\n").expect("rust source");
        let project = Arc::new(CountingOverlayProject::new(&root, "fn first() {}\n"));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);

        let first = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            let prepared = analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("first syntax");
            assert_eq!(prepared.source(), "fn first() {}\n");
            assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
            prepared
        };

        project.set_source("fn second() { first(); }\n");
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let second = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("updated syntax");

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.source(), "fn second() { first(); }\n");
        // Two revisions, one parse each: the counter totals every parse of the
        // file rather than bucketing by source identity, so "no revision was
        // parsed twice" reads as one parse per revision.
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 2);
        assert_ne!(
            first.tree().root_node().to_sexp(),
            second.tree().root_node().to_sexp()
        );
    }

    #[test]
    fn prepared_syntax_limited_rejects_oversized_source_before_parsing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        let source = "fn target() {}\nfn consumer() { target(); }\n";
        file.write(source).expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);

        let exceeded = analyzer
            .prepared_syntax_limited(scope.token(), &file, source.len() - 1)
            .expect_err("source larger than the caller cap must not be parsed");
        assert_eq!(exceeded.minimum_source_bytes(), source.len());
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let (_, prepared) = analyzer
            .prepared_syntax_limited(scope.token(), &file, source.len())
            .expect("exact source-size cap should be accepted")
            .expect("bounded source should prepare");
        assert_eq!(prepared.source(), source);
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    #[test]
    fn cancelled_cold_overlay_syntax_does_not_hydrate_or_initialize_cache() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn disk() {}\n").expect("rust source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&overlay) as Arc<dyn Project>, RustAdapter);
        let source = (0..20_000)
            .map(|index| format!("fn target_{index}() {{}}\n"))
            .collect::<String>();
        assert!(overlay.set(file.abs_path(), source.clone()));
        analyzer.reset_full_hydration_count_for_test();
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let cancellation = CancellationToken::cancel_after_checks_for_test(6);

        assert!(matches!(
            analyzer.prepared_syntax_limited_cancellable(
                scope.token(),
                &file,
                source.len(),
                Some(&cancellation)
            ),
            PreparedSyntaxLimitedOutcome::Cancelled
        ));
        assert_eq!(
            analyzer.prepared_syntax_parse_count_for_test(&file),
            1,
            "the cancellation should interrupt an admitted parse attempt"
        );
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "bounded cancellation must not hydrate or analyze the cold overlay revision"
        );

        let prepared =
            analyzer.prepared_syntax_limited_cancellable(scope.token(), &file, source.len(), None);
        let PreparedSyntaxLimitedOutcome::Available(_, prepared) = prepared else {
            panic!("a later uncancelled request must retry instead of reading cached failure");
        };
        assert_eq!(prepared.source(), source);
        assert_eq!(prepared.origin(), PreparedSourceOrigin::Overlay);
        assert!(prepared.overlay_revision().is_some());
        assert!(matches!(prepared.backing(), PreparedSyntaxSource::Exact(_)));
        assert_eq!(
            analyzer.prepared_syntax_parse_count_for_test(&file),
            2,
            "cancelled preparation must not initialize the syntax cache"
        );
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "successful bounded preparation must remain syntax-only"
        );

        let indexed = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("ordinary preparation should remain indexed");
        assert_eq!(indexed.source(), source);
        assert_eq!(indexed.origin(), prepared.origin());
        assert_eq!(indexed.overlay_revision(), prepared.overlay_revision());
        assert!(matches!(
            indexed.backing(),
            PreparedSyntaxSource::Indexed(_)
        ));
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            1,
            "ordinary preparation must not reuse the syntax-only cache entry"
        );
        assert_eq!(
            analyzer.prepared_syntax_parse_count_for_test(&file),
            3,
            "indexed and syntax-only cache entries are intentionally distinct"
        );
    }

    #[test]
    fn prepared_syntax_accepts_an_empty_source_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/empty.rs");
        file.write("").expect("empty rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);

        let (_, prepared) = analyzer
            .prepared_syntax_limited(scope.token(), &file, 0)
            .expect("empty source fits a zero-byte preparation cap")
            .expect("empty source remains valid syntax input");

        assert_eq!(prepared.source(), "");
        assert_eq!(prepared.origin(), PreparedSourceOrigin::Disk);
        assert_eq!(prepared.overlay_revision(), None);
    }

    #[test]
    fn prepared_syntax_cache_identity_distinguishes_repeated_overlay_content() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn disk() {}\n").expect("rust source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&overlay) as Arc<dyn Project>, RustAdapter);
        let repeated_source = "fn repeated() {}\n";

        assert!(overlay.set(file.abs_path(), repeated_source.to_owned()));
        let first = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("first overlay")
        };
        assert!(overlay.set(file.abs_path(), "fn middle() {}\n".to_owned()));
        let middle = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("middle overlay")
        };
        assert!(overlay.set(file.abs_path(), repeated_source.to_owned()));
        let repeated = {
            let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("repeated overlay")
        };

        assert_eq!(first.source(), repeated.source());
        assert_eq!(first.origin(), PreparedSourceOrigin::Overlay);
        assert_eq!(middle.origin(), PreparedSourceOrigin::Overlay);
        assert_eq!(repeated.origin(), PreparedSourceOrigin::Overlay);
        let first_revision = first.overlay_revision().expect("first overlay revision");
        let middle_revision = middle.overlay_revision().expect("middle overlay revision");
        let repeated_revision = repeated
            .overlay_revision()
            .expect("repeated overlay revision");
        assert!(first_revision < middle_revision);
        assert!(middle_revision < repeated_revision);
        assert_ne!(first_revision, repeated_revision);
        assert!(!Arc::ptr_eq(&first, &repeated));
    }

    #[test]
    fn query_read_cache_hashes_overlay_once_and_refreshes_after_outer_scope() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let source = "pub struct Example;\nimpl Example { pub fn value(&self) -> usize { 1 } }\n";
        file.write(source).expect("rust source");
        let project = Arc::new(CountingOverlayProject::new(root, source));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        project.reset_reads();

        let outer_scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let first_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("first overlay oid");
        assert_eq!(
            project.read_count(),
            1,
            "the first OID lookup reads the overlay"
        );
        assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
        assert_eq!(
            project.read_count(),
            1,
            "repeated OID lookup must use the query cache"
        );

        let declarations = analyzer.declarations(&file);
        let reads_after_hydration = project.read_count();
        for declaration in declarations {
            assert!(!analyzer.ranges(&declaration).is_empty());
        }
        assert_eq!(
            project.read_count(),
            reads_after_hydration,
            "range traversal must not reread the overlay"
        );

        {
            let _inner_scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
            assert_eq!(
                project.read_count(),
                reads_after_hydration,
                "nested scopes must reuse the outer cache"
            );
        }
        assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
        assert_eq!(
            project.read_count(),
            reads_after_hydration,
            "dropping the inner scope must retain the cache"
        );
        drop(outer_scope);

        project.set_source(format!("{source}\n"));
        let _next_scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let next_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("updated overlay oid");
        assert_ne!(
            next_oid, first_oid,
            "the next query must observe changed overlay text"
        );
        assert_eq!(
            project.read_count(),
            reads_after_hydration + 1,
            "the next query should read the overlay once"
        );
    }

    #[test]
    fn warm_rebuild_uses_bulk_presence_without_redundant_point_contains_queries() {
        const UNIQUE_FILES: usize = 10;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for index in 0..UNIQUE_FILES {
            let file = ProjectFile::new(root.clone(), format!("pkg{index}/type{index}.py"));
            file.write(format!("class Type{index}:\n    pass\n"))
                .unwrap();
        }
        let shared_source = "class Shared:\n    pass\n";
        for path in ["dup_a/shared.py", "dup_b/shared.py"] {
            ProjectFile::new(root.clone(), path)
                .write(shared_source)
                .unwrap();
        }
        for path in ["broken_a/binary.py", "broken_b/binary.py"] {
            ProjectFile::new(root.clone(), path)
                .write("\0not parseable source")
                .unwrap();
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Python));
        let store = Arc::new(
            AnalyzerStore::open_persistent(&temp.path().join("analyzer.db"))
                .expect("persistent analyzer store"),
        );
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(project.root()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
        };
        let config = AnalyzerConfig::default();

        let _cold = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            PythonAdapter,
            config.clone(),
            store_context.clone(),
            None,
        )
        .expect("analyzer epochs should initialize");
        store.reset_parsed_blob_point_contains_queries_for_test();
        let warm_parse_count = Arc::new(AtomicUsize::new(0));
        let warm_progress_count = Arc::clone(&warm_parse_count);
        let warm = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            PythonAdapter,
            config.clone(),
            store_context.clone(),
            Some(Arc::new(move |event| {
                if event.phase == BuildProgressPhase::Parse {
                    warm_progress_count.fetch_add(1, Ordering::Relaxed);
                }
            })),
        )
        .expect("analyzer epochs should initialize");
        let warm_point_queries = store.parsed_blob_point_contains_queries_for_test();
        assert_eq!(warm.get_definitions("dup_a.shared.Shared").len(), 1);
        assert_eq!(warm.get_definitions("dup_b.shared.Shared").len(), 1);

        let shared_oid = Oid::hash_object(ObjectType::Blob, shared_source.as_bytes()).unwrap();
        store.mark_parsed_blob_incomplete_for_test(shared_oid, "python");
        store.reset_parsed_blob_point_contains_queries_for_test();
        let parse_count = Arc::new(AtomicUsize::new(0));
        let progress_count = Arc::clone(&parse_count);
        let recovered = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            PythonAdapter,
            config,
            store_context,
            Some(Arc::new(move |event| {
                if event.phase == BuildProgressPhase::Parse {
                    progress_count.fetch_add(1, Ordering::Relaxed);
                }
            })),
        )
        .expect("analyzer epochs should initialize");
        let recovery_point_queries = store.parsed_blob_point_contains_queries_for_test();

        assert_eq!(
            warm_parse_count.load(Ordering::Relaxed),
            1,
            "one unparseable representative should cover both duplicate paths"
        );
        assert_eq!(
            parse_count.load(Ordering::Relaxed),
            2,
            "rebuild should parse one corrupt representative and retry the unparseable key once"
        );
        assert_eq!(recovered.get_definitions("dup_a.shared.Shared").len(), 1);
        assert_eq!(recovered.get_definitions("dup_b.shared.Shared").len(), 1);
        assert_eq!(
            (warm_point_queries, recovery_point_queries),
            (0, 0),
            "the authoritative bulk missing set should avoid per-file contains checks on warm and one-corrupt-key rebuilds"
        );
    }

    /// #2917: the memoized blob identity is the answer `git hash-object` gives
    /// for the bytes in hand -- for the indexed disk source, for a dirty
    /// rewrite of the same file, and for an unsaved overlay -- and a repeat
    /// question about unchanged bytes does not run SHA-1 again.
    #[test]
    fn blob_oid_of_matches_git_hash_object_and_hashes_each_source_once() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let disk_source = "fn disk() {}\n";
        file.write(disk_source).expect("disk source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(Arc::clone(&base), RustAdapter);
        let expected =
            |source: &str| Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("blob oid");

        analyzer.reset_blob_hash_count_for_test();
        assert_eq!(
            analyzer.blob_oid_of(&file, disk_source),
            expected(disk_source)
        );
        assert_eq!(analyzer.blob_hash_count_for_test(), 1);
        let reread = base.read_source(&file).expect("disk read");
        assert_eq!(analyzer.blob_oid_of(&file, &reread), expected(disk_source));
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            1,
            "the same bytes from a fresh read must be recognized without SHA-1"
        );

        let dirty_source = "fn disk() {}\nfn dirty() {}\n";
        file.write(dirty_source).expect("dirty source");
        assert_eq!(
            analyzer.blob_oid_of(&file, dirty_source),
            expected(dirty_source)
        );
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            2,
            "a dirty rewrite must miss the memo and get its own identity"
        );
        assert_eq!(
            analyzer.blob_oid_of(&file, dirty_source),
            expected(dirty_source)
        );
        assert_eq!(analyzer.blob_hash_count_for_test(), 2);

        let overlay_source = "fn unsaved() {}\n";
        let overlay = Arc::new(OverlayProject::new(Arc::clone(&base)));
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let frozen: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let request = analyzer.clone_with_project(frozen);
        assert_eq!(
            request.resolve_live_oid_for_file(&file),
            Some(expected(overlay_source)),
            "an overlay's live identity is the hash of its unsaved bytes"
        );
        assert_eq!(
            request.blob_oid_of(&file, overlay_source),
            expected(overlay_source)
        );
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            3,
            "the overlay is hashed once, through the memo the request clone shares"
        );
    }

    #[test]
    fn clone_with_project_has_an_independent_query_read_cache() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        file.write("fn disk() {}\n").expect("rust source");

        let live_project = Arc::new(CountingOverlayProject::new(&root, "fn live() {}\n"));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&live_project) as Arc<dyn Project>, RustAdapter);
        live_project.reset_reads();
        let _live_scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let live_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("live overlay oid");

        let snapshot_project = Arc::new(CountingOverlayProject::new(
            &root,
            "fn frozen_snapshot() {}\n",
        ));
        let snapshot =
            analyzer.clone_with_project(Arc::clone(&snapshot_project) as Arc<dyn Project>);
        snapshot_project.reset_reads();
        let _snapshot_scope = crate::analyzer::AnalyzerQueryScope::new(&snapshot);
        let snapshot_oid = snapshot
            .resolve_live_oid_for_file(&file)
            .expect("snapshot overlay oid");

        assert_ne!(
            snapshot_oid, live_oid,
            "project snapshots must not share live OIDs"
        );
        assert_eq!(
            snapshot_project.read_count(),
            1,
            "snapshot should read its own overlay"
        );
    }

    #[test]
    fn clone_with_project_isolates_transient_live_paths_from_disk_and_siblings() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let disk_source = "fn disk() {}\n";
        let overlay_source = "fn unsaved() { disk(); }\n";
        file.write(disk_source).expect("disk source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let disk = TreeSitterAnalyzer::new(Arc::clone(&base), RustAdapter);
        let sibling = disk.clone_with_project(Arc::clone(&base));
        let disk_oid = Oid::hash_object(ObjectType::Blob, disk_source.as_bytes()).unwrap();
        let overlay_oid = Oid::hash_object(ObjectType::Blob, overlay_source.as_bytes()).unwrap();

        let live_overlay = Arc::new(OverlayProject::new(Arc::clone(&base)));
        assert!(live_overlay.set(file.abs_path(), overlay_source.to_owned()));
        let frozen_overlay: Arc<dyn Project> = Arc::new(live_overlay.snapshot());
        let request = disk.clone_with_project(frozen_overlay);
        let state = request
            .fetch_file_state(&file)
            .expect("parse the transient overlay revision");
        assert_eq!(state.source, overlay_source);
        assert_eq!(request.resolve_live_oid_for_file(&file), Some(overlay_oid));

        assert_eq!(disk.resolve_live_oid_for_file(&file), Some(disk_oid));
        assert_eq!(sibling.resolve_live_oid_for_file(&file), Some(disk_oid));
        assert_eq!(disk.file_source(&file).as_deref(), Some(disk_source));
        assert_eq!(sibling.file_source(&file).as_deref(), Some(disk_source));

        assert!(live_overlay.clear(&file.abs_path()));
        let cleared_project: Arc<dyn Project> = Arc::new(live_overlay.snapshot());
        let cleared = disk.clone_with_project(cleared_project);
        assert_eq!(cleared.resolve_live_oid_for_file(&file), Some(disk_oid));
        assert_eq!(cleared.file_source(&file).as_deref(), Some(disk_source));
        assert_eq!(request.file_source(&file).as_deref(), Some(overlay_source));
    }

    #[test]
    fn file_summary_uses_persisted_projection_without_full_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/demo/Example.java");
        file.write(
            "package demo; public class Example { public String name; public void run() {} }\n",
        )
        .expect("java source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = JavaAnalyzer::new(project);
        analyzer.inner().reset_full_hydration_count_for_test();

        let first_projection = analyzer
            .summary_file_projection(&file)
            .expect("persisted summary projection");
        let second_projection = analyzer
            .summary_file_projection(&file)
            .expect("cached summary projection");
        assert!(Arc::ptr_eq(&first_projection, &second_projection));

        let result = crate::searchtools::summarize_files(&analyzer, vec![file]);

        assert_eq!(result.summaries.len(), 1);
        assert!(
            result.summaries[0]
                .elements
                .iter()
                .any(|element| element.symbol.contains("Example.run")),
            "persisted projection should render method summaries"
        );
        assert_eq!(analyzer.inner().full_hydration_count_for_test(), 0);
    }

    #[test]
    fn file_summary_refuses_files_owned_by_another_language_analyzer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let foreign_file = ProjectFile::new(root.clone(), "src/lib.rs");
        foreign_file
            .write("pub fn foreign() {}\n")
            .expect("rust source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = JavaAnalyzer::new(project);

        assert!(analyzer.summary_file_projection(&foreign_file).is_none());
    }

    /// #2913: the import tier obeys the same refusal every other per-file store
    /// read here does. `ImportAnalysisProvider` fan-outs legitimately ask every
    /// provider about an arbitrary file, and a foreign file's storage key has
    /// no entry in this analyzer's own generation map, so hydrating it recorded
    /// `missing captured analyzer generation for <lang>` on the request context
    /// -- which ends the whole tool call, after the work it was asked for
    /// already succeeded.
    #[test]
    fn import_hydration_refuses_files_owned_by_another_language_analyzer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::write(
            root.join("Demo.java"),
            "package demo;\n\nimport java.util.List;\n\nclass Demo {}\n",
        )
        .unwrap();
        std::fs::write(root.join("demo.rs"), "use std::fmt;\n\npub fn work() {}\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        let own_file = ProjectFile::new(root.clone(), "Demo.java");
        let foreign_file = ProjectFile::new(root, "demo.rs");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();

        assert!(
            analyzer.resolve_live_oid_for_file(&foreign_file).is_some(),
            "the shared live-path map must reach the foreign file, or the read \
             this pins would never be attempted and the test would pass vacuously"
        );
        assert_eq!(
            1,
            analyzer.import_info_of(token, &own_file).len(),
            "the analyzer must still answer for a file it owns"
        );
        assert!(
            analyzer.import_info_of(token, &foreign_file).is_empty(),
            "a file this analyzer never analyzed has no imports here"
        );
        assert!(
            scope.store_error().is_none(),
            "refusing a foreign file must not record a store failure: {:?}",
            scope.store_error()
        );
    }

    #[test]
    fn literal_symbol_search_keeps_members_of_matching_java_types() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/demo/Gson.java");
        file.write(
            "package demo; public class Gson { public void fromJson() {} } class Other { void unrelated() {} }\n",
        )
        .expect("java source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        let matches = analyzer.search_definitions("Gson", false);
        let patterns = SearchSymbolPatternBatch::compile(vec!["Gson".to_string()], false, None);
        let candidates = analyzer.search_symbol_candidates(&patterns, None).rows;

        assert!(matches.iter().any(|unit| unit.fq_name() == "demo.Gson"));
        assert!(
            matches
                .iter()
                .any(|unit| unit.fq_name() == "demo.Gson.fromJson")
        );
        assert!(!matches.iter().any(|unit| unit.short_name() == "unrelated"));
        assert!(candidates.iter().any(|candidate| {
            candidate.code_unit.fq_name() == "demo.Gson.fromJson"
                && candidate.primary_range.is_some()
                && !candidate.in_test_region
        }));
    }

    #[test]
    fn issue_1199_symbol_candidate_scan_honors_midstream_cancellation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/lib.rs");
        file.write(
            (0..32)
                .map(|index| format!("pub fn diagnostic_{index}() {{}}\n"))
                .collect::<String>(),
        )
        .expect("rust source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let cancellation = CancellationToken::cancel_after_checks_for_test(6);
        let patterns =
            SearchSymbolPatternBatch::compile(vec!["diagnostic_.*".to_string()], false, None);

        let candidates = analyzer.search_symbol_candidates(&patterns, Some(&cancellation));

        assert!(!candidates.complete, "{candidates:#?}");
        assert!(candidates.inspected > 0, "{candidates:#?}");
        assert!(cancellation.is_cancelled());
    }
}

#[cfg(test)]
mod sigil_anchor_tests {
    use crate::analyzer::SearchSymbolPatternBatch;

    #[test]
    fn trailing_sigil_is_escaped_as_identifier_text() {
        // #1127: `Foo$` (java/scala sigil-suffixed identifiers) must not
        // compile as an end-of-haystack anchor.
        for pattern in ["Foo$", "$L", "$$animate"] {
            let batch = SearchSymbolPatternBatch::compile(vec![pattern.to_string()], false, None);
            assert!(batch.is_match(pattern), "{pattern}");
        }
        // Word-free anchors stay anchors.
        let anchored = SearchSymbolPatternBatch::compile(vec!["foo.$".to_string()], false, None);
        assert!(anchored.is_match("foo."));
        assert!(!anchored.is_match("foo.$"));
    }

    #[test]
    fn dollar_after_dollar_is_identifier_text_not_end_anchor() {
        // #1059 (reopened): `next_is_word` counted `$` as word-ish but
        // `prev_is_word` did not, so the trailing `$` of `_$$` followed a
        // `$` and stayed a regex end-anchor. The compiled `_\$$` matched
        // `App._$` but never `App._$$` (bit on a JS class field
        // `_$$ = $$;`). The prev-side set now includes `$`.
        let batch = SearchSymbolPatternBatch::compile(vec!["_$$".to_string()], false, None);
        assert!(batch.is_match("_$$"));
        assert!(!batch.is_match("_$"));
        let longer = SearchSymbolPatternBatch::compile(vec!["_$_$$".to_string()], false, None);
        assert!(longer.is_match("_$_$$"));
        assert!(!longer.is_match("_$_$"));
    }
}
