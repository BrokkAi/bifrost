//! Deciding whether a recorded read set still holds on another workspace
//! (Milestone 2 of the impact-sliced `--diff-base` plan).
//!
//! The read ledger records what one evaluation unit read. This module answers
//! the only question that makes a recorded read set useful: does every one of
//! those inputs still denote the same content in the head workspace? A `Yes`
//! is what licenses reusing the unit's product without recomputing it; a `No`
//! names the key that moved and why.
//!
//! Three kinds of key need three different proofs, and each of them is exact
//! rather than approximate:
//!
//! * A [`ReadKey::File`] is proved by the head's own path map: the same
//!   workspace-relative path must resolve to the same blob in the same
//!   language.
//! * A [`ReadKey::Index`] is proved by [`ChangedFacts`], the set of index keys
//!   whose per-file published rows differ between the base and head. The set is built by the
//!   store's own row builders, so a key it holds is spelled exactly as the
//!   probe that reads it spells it.
//! * A [`ReadKey::Lookup`] cannot be proved from any per-file fact, because a
//!   cross-file answer moves when a file the reader never mentioned changes.
//!   It is proved by [`replay_lookup`]: re-running the same funnel on the head
//!   and comparing the answer digest the recording used.
//!
//! Everything else -- artifacts, scopes, models, policy, configuration, epoch
//! -- is an identity comparison against what the head publishes.

use crate::analyzer::semantic::read_ledger::{
    FactSubject, StoredSemanticIrPublicationAnswer, StoredSemanticIrPublicationQuestion,
    WorkspaceFactFamily,
};
use crate::analyzer::semantic::{StoredSemanticIrRead, classify};
use git2::Oid;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind, InvalidationReason};
use crate::analyzer::read_ledger::{
    IndexFamily, LookupKind, LookupQuestion, ReadKey, absent_declaration_facts_digest,
    absent_signature_metadata_digest,
};
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::semantic::read_ledger::{
    CertifiedDefinitionKind, DEFINITION_NORMALIZED_TAIL_VERSION,
};
use crate::analyzer::semantic::{
    CallSiteHandle, DispatchOracle, ProcedureHandle, SemanticBudget, SemanticRequest, SemanticWork,
    WorkspaceSemanticOracle,
};
use crate::analyzer::structural::index::StructuralIndexAcquisition;
use crate::analyzer::usages::call_relations::{CallRelationLimits, CallRelationService};
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageFinder};
use crate::analyzer::workspace::WorkspaceAnalyzer;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, DescendantIndexScope, IAnalyzer, Language, ProjectFile,
    QueryScope,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};

/// The producer side of the read ledger's per-file keys, for one language.
///
/// A `ReadKey::File` names a blob and a `ReadKey::Index` names a name-keyed
/// entry that some blob's facts published. Deciding whether either moved
/// between two workspaces needs both halves of that relation from the
/// analyzer that owns the language: which paths resolve to which blobs, and
/// which index keys one blob's facts contribute.
///
/// Reached through [`IAnalyzer::workspace_fact_indexes`], one per language,
/// exactly as `structural_fact_providers` reaches the per-language structural
/// providers.
pub trait WorkspaceFactIndex: Send + Sync {
    /// The language whose analyzed content this index describes.
    fn fact_index_language(&self) -> Language;

    /// Whether this analyzer still holds a workspace listing proof, which a
    /// listing omission that may hide source would withdraw. An update with no
    /// changed file needs to run only while there is a proof to withdraw.
    fn holds_workspace_listing_proof(&self) -> bool {
        false
    }

    /// Replay the shared declaration and structural-parent facts, before any
    /// language adapter adds its own parent interpretation.
    fn declaration_facts_digest(&self, declaration: &CodeUnit) -> StableDigest;

    /// Replay the shared signature projection before adapter-specific fallbacks.
    fn signature_metadata_digest(&self, declaration: &CodeUnit) -> StableDigest;

    /// Replay one complete name lookup, including an empty answer.
    fn definition_answer_digest(&self, name: &str) -> StableDigest;

    /// Look up an already normalized definition-tail key without normalizing it again.
    /// `None` means this delegate cannot certify the answer.
    fn normalized_tail_candidates(&self, _key: &str) -> Option<Vec<CodeUnit>> {
        None
    }

    /// Replay declarations addressed by a source identifier.
    fn identifier_candidate_answer_digest(&self, name: &str) -> StableDigest;

    /// Replay the complete short-name candidate set.
    fn short_name_candidate_answer_digest(&self, name: &str) -> StableDigest;

    /// Hydrate one path-backed module from this snapshot, including absence.
    /// An index without this authority cannot certify the question.
    fn path_synthetic_module_answer_digest(&self, _file: &ProjectFile) -> Option<StableDigest> {
        None
    }

    /// Complete eligible synthetic module set, before caller filtering.
    fn path_synthetic_modules_answer_digest(&self) -> Option<StableDigest> {
        None
    }

    /// A digest of everything this language's content identity folds except
    /// the analyzed file set: the language epoch, the analyzer configuration,
    /// the selected configuration, the package-identity inputs and the
    /// overlays.
    ///
    /// Two snapshots whose file sets agree on every path and blob can still
    /// mean different things when this digest differs, because those inputs
    /// rekey declarations in files whose blobs did not change. `None` when the
    /// index cannot state it, which a caller treats as "moved".
    fn identity_inputs_digest(&self) -> Option<StableDigest> {
        None
    }

    /// Every analyzed path of this language with the blob it resolves to, or
    /// None when the listing could not be read completely (a store failure):
    /// a partial list would read the missing files as absent.
    fn analyzed_blobs(&self) -> Option<Vec<(ProjectFile, Oid)>>;

    /// Whether this index reads package-identity inputs at all.
    fn has_workspace_package_identity_inputs(&self) -> bool {
        false
    }

    /// Whether `file`, which no analyzer parses, qualifies this language's
    /// declarations (`go.mod`, `Cargo.toml`). Answered from the path alone, so
    /// it also classifies a committed file the head no longer has.
    fn is_package_identity_input(&self, _path: &Path) -> bool {
        false
    }

    /// The package-identity inputs this language's head read, each with the
    /// blob of the bytes it read.
    ///
    /// These are not in [`Self::analyzed_blobs`], so a comparison of analyzed
    /// sources never sees them. `None` means the head cannot say what it read
    /// (the files moved since the generation was built, or a read failed),
    /// which is not an empty answer.
    fn package_identity_input_blobs(&self) -> Option<Vec<(ProjectFile, Oid)>> {
        Some(Vec::new())
    }

    /// Whether `file`, which this language reads as selected configuration but
    /// does not qualify its declarations with (`Cargo.lock`, `go.sum`,
    /// `package.json`), is such an input. Answered from the path alone, so it
    /// also classifies a committed file the head no longer has.
    fn is_selected_configuration_input(&self, _path: &Path) -> bool {
        false
    }

    /// The selected-configuration inputs this language's head was built
    /// against, each with the blob it read. A retained absence is not listed.
    /// Package-identity inputs are listed by
    /// [`Self::package_identity_input_blobs`] instead.
    ///
    /// `None` means the head cannot say what it read, which is not an empty
    /// answer.
    fn selected_configuration_input_blobs(&self) -> Option<Vec<(ProjectFile, Oid)>> {
        Some(Vec::new())
    }

    /// Every source-admission refusal persisted for the selected revision,
    /// with the blob identity recorded at admission time.
    fn refused_source_blobs(
        &self,
    ) -> Result<Vec<(ProjectFile, Oid)>, crate::analyzer::store::StoreError>;

    /// Every `(family, key, digest)` the facts of `file`'s `blob` contribute to the
    /// name-keyed indexes a [`ReadKey::Index`] probes.
    ///
    /// `None` when this analyzer cannot enumerate them -- an incomplete file
    /// state, a store that cannot answer for the blob. That is not an empty
    /// answer: an empty answer would say "this blob touches no index key",
    /// which would let a changed blob pass verification.
    fn blob_index_keys(
        &self,
        file: &ProjectFile,
        blob: Oid,
    ) -> Option<Vec<crate::analyzer::store::IndexEntryDigest>>;

    /// Test-only detail for a [`Self::blob_index_keys`] answer of `None`.
    ///
    /// The production answer is deliberately just `None`, because a warm base
    /// must fail closed when it cannot enumerate a blob's keys. A test that
    /// checks the enumerator succeeds needs the branch that refused, and the
    /// store error that refusal may have discarded.
    #[cfg(any(test, feature = "test-support"))]
    fn blob_index_keys_failure(&self, _file: &ProjectFile, _blob: Oid) -> Option<String> {
        None
    }

    /// Every `(family, key, digest)` the *persisted* facts of `blob` contribute, with
    /// `source` as that blob's own bytes.
    ///
    /// [`Self::blob_index_keys`] answers about a blob this analyzer has
    /// mounted; this answers about any blob the store holds facts for, which
    /// is what lets a run enumerate a committed revision's keys without
    /// building an analyzer over that revision. The keys are produced by the
    /// same code either way, so both spell a key the way the probe that reads
    /// it spells it.
    ///
    /// `None` when the store holds no complete facts for `blob` under this
    /// language, which is the honest answer that this blob's keys cannot be
    /// enumerated from here -- never an empty answer, which would claim the
    /// blob touches no index key at all.
    fn stored_blob_index_keys(
        &self,
        file: &ProjectFile,
        blob: Oid,
        source: &str,
    ) -> Option<Vec<crate::analyzer::store::IndexEntryDigest>>;

    /// Process-local identity of the fact store owning snapshot revisions.
    /// Clones share this identity; independent ephemeral stores do not.
    fn definition_inventory_owner(&self) -> Option<usize> {
        None
    }

    /// Exact selected snapshots covered by this delegate's listing proof.
    /// An empty or unknown proof cannot certify a definition inventory.
    fn definition_inventory_snapshots(&self) -> Option<crate::analyzer::store::ListedSnapshots> {
        None
    }

    /// Canonical per-file contributions to one definition bucket. Unknown
    /// inventory or incomplete per-file facts refuse the entire certificate.
    fn definition_inventory_entries(
        &self,
        _family: IndexFamily,
        _key: &[u8],
    ) -> Option<Vec<(String, String, StableDigest)>> {
        None
    }

    /// Query-local callable metrics from this language's structured AST.
    ///
    /// This is deliberately a fact-index seam rather than the authority-gated
    /// structural-search provider seam: metrics are source-local, but a stale
    /// overlay must never be presented as exact. Implementations return
    /// `None` when the current snapshot cannot prove that its prepared facts
    /// are authoritative; callers then publish an explicit `unrecorded` row.
    fn callable_metrics_for_file(
        &self,
        _file: &ProjectFile,
    ) -> Option<
        Vec<(
            CodeUnit,
            brokk_bifrost_core::analyzer::cognitive_complexity::CallableMetrics,
        )>,
    > {
        None
    }
}

/// Snapshot identity captured before a solve. Kept separate from the inventory
/// digest so an unrelated revision can verify the same bucket at head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionInventorySnapshot {
    delegates: Vec<(Language, usize, crate::analyzer::store::ListedSnapshots)>,
}

impl DefinitionInventorySnapshot {
    pub fn capture(analyzer: &dyn IAnalyzer) -> Option<Self> {
        let indexes = analyzer.workspace_fact_indexes();
        let mut delegates = Vec::new();
        for language in analyzer.languages() {
            let index = indexes
                .iter()
                .find(|index| index.fact_index_language() == language)?;
            let snapshots = index.definition_inventory_snapshots()?;
            if snapshots.snapshots().is_empty() {
                return None;
            }
            // Snapshot revision numbers are local to a store; distinct ephemeral
            // analyzers can reuse them. Bind the solve capability to its owner
            // as well as the selected workspace/generation/revision tuple.
            let owner = index.definition_inventory_owner()?;
            delegates.push((language, owner, snapshots));
        }
        if delegates.is_empty() {
            return None;
        }
        Some(Self { delegates })
    }

    pub fn languages(&self) -> Vec<Language> {
        self.delegates
            .iter()
            .map(|(language, _, _)| *language)
            .collect()
    }

    /// Recheck both before and after enumeration. No result may be attached to
    /// a solve if its exact selected workspace/generation/revision moved.
    pub fn digest(
        &self,
        analyzer: &dyn IAnalyzer,
        family: IndexFamily,
        key: &[u8],
    ) -> Option<StableDigest> {
        if Self::capture(analyzer).as_ref() != Some(self) {
            return None;
        }
        let normalization = match family {
            IndexFamily::DefinitionNormalizedTail => Some(DEFINITION_NORMALIZED_TAIL_VERSION),
            IndexFamily::DefinitionExact | IndexFamily::DefinitionIdentifier => None,
            _ => return None,
        };
        let mut hash = CanonicalHasher::new(b"bifrost:definition-index-inventory:v1");
        hash.field("family", family.stable_label().as_bytes());
        hash.field("key", key);
        hash.field(
            "normalization",
            &normalization
                .map(u32::to_le_bytes)
                .map(Vec::from)
                .unwrap_or_default(),
        );
        let languages = self.languages();
        hash.sequence("delegates", &languages, |hash, language| {
            hash.value(language.config_label().as_bytes());
        });
        let indexes = analyzer.workspace_fact_indexes();
        let mut entries = Vec::new();
        for language in languages {
            let index = indexes
                .iter()
                .find(|index| index.fact_index_language() == language)?;
            entries.extend(index.definition_inventory_entries(family, key)?);
            if entries.len() > 65_536 {
                return None;
            }
        }
        entries.sort_unstable();
        entries.dedup();
        hash.sequence("entries", &entries, |hash, (path, language, digest)| {
            hash.value(path.as_bytes());
            hash.value(language.as_bytes());
            hash.value(digest.as_bytes());
        });
        if Self::capture(analyzer).as_ref() != Some(self) {
            return None;
        }
        Some(StableDigest::from_array(hash.finish()))
    }
}

/// What moved between two workspaces, in the vocabulary a read key names.
///
/// Two sets, both computed once per head evaluation and then asked many
/// questions:
///
/// * the workspace-relative paths whose blob differs, was added, or was
///   removed, per language; and
/// * the `(family, key)` pairs whose per-file published row digests differ,
///   including keys present on only one side of a changed path.
///
/// The keys are produced by the store's own row builders, so a key here is
/// spelled the way the probe that reads it spells it. Nothing re-interprets a
/// qualified name, a short name, or an import segment.
///
/// [`Self::is_complete`] is the honest half. A blob whose facts could not be
/// enumerated, or a language with no fact index at all, leaves this set
/// smaller than the truth, and a smaller set would let a changed input pass
/// verification. A caller must widen rather than trust an incomplete answer.
#[derive(Debug)]
pub struct ChangedFacts {
    delta: ChangedDelta,
    /// The head's whole path map, retained because a `ReadKey::File` names the
    /// blob its reader saw, which need not be either side of this difference:
    /// a unit published by an earlier head run carries that run's blob. Only
    /// comparing against the head's own map answers exactly, and building it
    /// once here is what keeps verification linear in the number of units.
    head_blobs: HashMap<(Language, Box<str>), Oid>,
}

/// The head-independent half of [`ChangedFacts`]: what moved, without the
/// head's own path map.
///
/// A delta can be computed once, when a workspace advances from one snapshot
/// to the next, kept, [`Self::union`]ed with the deltas of later steps, and
/// attached to whichever head finally asks with [`ChangedFacts::at_head`]. The
/// union of the step deltas covers everything that moved between the first
/// snapshot and the last: a key whose published digest differs between the
/// two ends differs at some step. It can be larger than the direct
/// difference (a key that moved and moved back stays), and a larger set costs
/// only reuse.
///
/// [`Self::between`] is the guarded producer. Besides the file difference it
/// refuses to be [`Self::is_complete`] when an input that decides what a
/// snapshot means moved without a path moving: a package-identity input such as
/// `go.mod`, the selected configuration, the language epoch or the analyzer
/// configuration. Those rekey declarations in files whose blobs are unchanged,
/// so the path and key sets alone would understate what moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedDelta {
    paths: HashMap<Language, HashSet<Box<str>>>,
    keys: HashSet<(IndexFamily, Box<[u8]>)>,
    unenumerated: Vec<(Language, Box<str>)>,
    languages_without_index: Vec<Language>,
    /// The head's own record of what it read could not be retrieved: its
    /// source-admission refusals, or the identity inputs it read.
    refused_sources_incomplete: bool,
    /// Languages whose identity inputs other than the analyzed file set
    /// differ between the two ends, or cannot be compared.
    identity_inputs_moved: Vec<Language>,
    /// An end of a warm comparison is a project that layers request overlays,
    /// whether or not a buffer is open now. Two analyzers of one session can
    /// share a mutable overlay project, so both observe the buffers as they
    /// are now, including after the last one closed, rather than as the
    /// earlier snapshot saw them; the overlay state is not frozen per
    /// analyzer yet (#10493 slice 3).
    unfrozen_overlays: bool,
    /// No base was compared, so no index difference is known at all.
    without_base: bool,
}

impl ChangedDelta {
    fn empty() -> Self {
        Self {
            paths: HashMap::default(),
            keys: HashSet::default(),
            unenumerated: Vec::new(),
            languages_without_index: Vec::new(),
            refused_sources_incomplete: false,
            identity_inputs_moved: Vec::new(),
            unfrozen_overlays: false,
            without_base: false,
        }
    }

    /// What moved from `old` to `new`, complete only when no identity input
    /// moved with it.
    ///
    /// This is the producer for a warm base, which compares two analyzers of
    /// the same workspace at different times. [`ChangedFacts::between`] (the
    /// diff_base path) does not apply the guard: there, an identity input
    /// that moves is a file difference that the units' own recorded reads and
    /// the committed-tree package-identity differences already account for
    /// key by key, and the guard would turn every manifest edit into a full run.
    pub fn between(old: &WorkspaceAnalyzer, new: &WorkspaceAnalyzer) -> Self {
        let mut delta = compare_workspaces(old, new).0;
        delta.identity_inputs_moved = identity_inputs_moved(old, new);
        // A project with no overlay concept answers None; an overlay project
        // answers Some even with no buffer open.
        let layers_overlays = |analyzer: &WorkspaceAnalyzer| {
            analyzer.analyzer().project().overlay_content().is_some()
        };
        delta.unfrozen_overlays = layers_overlays(old) || layers_overlays(new);
        delta
    }

    /// Everything that moved in `self` or in `later`, for a chain of steps.
    pub fn union(mut self, later: &Self) -> Self {
        for (language, paths) in &later.paths {
            self.paths
                .entry(*language)
                .or_default()
                .extend(paths.iter().cloned());
        }
        self.keys.extend(later.keys.iter().cloned());
        self.unenumerated.extend(later.unenumerated.iter().cloned());
        self.languages_without_index
            .extend(later.languages_without_index.iter().copied());
        self.identity_inputs_moved
            .extend(later.identity_inputs_moved.iter().copied());
        self.refused_sources_incomplete |= later.refused_sources_incomplete;
        self.unfrozen_overlays |= later.unfrozen_overlays;
        self.without_base |= later.without_base;
        self.unenumerated.sort();
        self.unenumerated.dedup();
        self.languages_without_index.sort();
        self.languages_without_index.dedup();
        self.identity_inputs_moved.sort();
        self.identity_inputs_moved.dedup();
        self
    }

    /// Whether every changed blob's facts were enumerated, every language the
    /// two analyzers serve published a fact index, no identity input moved,
    /// and neither end is a project that layers request overlays.
    pub fn is_complete(&self) -> bool {
        self.unenumerated.is_empty()
            && self.languages_without_index.is_empty()
            && self.identity_inputs_moved.is_empty()
            && !self.unfrozen_overlays
            && !self.refused_sources_incomplete
            && !self.without_base
    }

    /// The languages whose identity inputs moved without a file difference
    /// accounting for it. See [`Self::between`].
    pub fn identity_inputs_moved(&self) -> &[Language] {
        &self.identity_inputs_moved
    }

    /// Whether a changed file has different published entries under this key.
    pub fn contains(&self, family: IndexFamily, key: &[u8]) -> bool {
        self.keys.contains(&(family, Box::from(key)))
    }

    /// Whether this path's blob differs between the two workspaces.
    pub fn path_changed(&self, language: Language, rel_path: &str) -> bool {
        self.paths
            .get(&language)
            .is_some_and(|paths| paths.contains(rel_path))
    }

    /// Every workspace-relative path whose blob differs, with its language.
    /// Carries files only: the difference holds no line ranges.
    pub fn changed_paths(&self) -> impl Iterator<Item = (Language, &str)> + '_ {
        self.paths
            .iter()
            .flat_map(|(language, paths)| paths.iter().map(move |path| (*language, path.as_ref())))
    }

    /// How many paths changed, over every language.
    pub fn changed_path_count(&self) -> usize {
        self.paths.values().map(HashSet::len).sum()
    }

    // Outer None is an absent file; inner None is a side whose facts
    // cannot be enumerated. Only two complete sides can prove equality.
    #[allow(clippy::type_complexity)]
    fn record_index_difference(
        &mut self,
        language: Language,
        rel_path: &str,
        base: Option<Option<Vec<crate::analyzer::store::IndexEntryDigest>>>,
        head: Option<Option<Vec<crate::analyzer::store::IndexEntryDigest>>>,
    ) {
        self.paths
            .entry(language)
            .or_default()
            .insert(Box::from(rel_path));
        if matches!(base, Some(None)) || matches!(head, Some(None)) {
            self.unenumerated.push((language, Box::from(rel_path)));
        }
        let to_map = |entries: Option<Option<Vec<crate::analyzer::store::IndexEntryDigest>>>| {
            entries
                .flatten()
                .unwrap_or_default()
                .into_iter()
                .map(|(family, key, digest)| ((family, key), digest))
                .collect::<HashMap<_, _>>()
        };
        let base = to_map(base);
        let head = to_map(head);
        for (key, digest) in &base {
            if head.get(key) != Some(digest) {
                self.keys.insert(key.clone());
            }
        }
        for (key, digest) in &head {
            if base.get(key) != Some(digest) {
                self.keys.insert(key.clone());
            }
        }
    }

    /// Compare retained inputs by blob in both directions, with one pass over
    /// the committed tree shared by all languages and input kinds.
    fn record_input_differences(
        &mut self,
        indexes: &HashMap<Language, &dyn WorkspaceFactIndex>,
        analyzed: &HashMap<Language, HashMap<Box<str>, (ProjectFile, Oid)>>,
        project: &dyn crate::Project,
        base_blobs: &[(Box<str>, Oid)],
        base_blob_by_path: &HashMap<Box<str>, Oid>,
    ) {
        enum InputKind {
            PackageIdentity,
            SelectedConfiguration,
        }
        let mut participating = Vec::new();
        for (&language, &index) in indexes {
            let mut kinds = vec![(
                InputKind::SelectedConfiguration,
                index.selected_configuration_input_blobs(),
            )];
            if index.has_workspace_package_identity_inputs() {
                kinds.push((
                    InputKind::PackageIdentity,
                    index.package_identity_input_blobs(),
                ));
            }
            for (kind, inputs) in kinds {
                let Some(inputs) = inputs else {
                    self.refused_sources_incomplete = true;
                    continue;
                };
                let inputs = inputs
                    .into_iter()
                    .map(|(file, blob)| {
                        (
                            Box::<str>::from(crate::path_utils::rel_path_string(&file).as_str()),
                            blob,
                        )
                    })
                    .collect::<HashMap<_, _>>();
                participating.push((language, index, kind, inputs));
            }
        }
        let mut record = |language, kind: &InputKind, path: &str| {
            self.paths
                .entry(language)
                .or_default()
                .insert(Box::from(path));
            // The normal source comparison above enumerates a path's changed
            // keys only for the language that analyzes it, so a configuration
            // input is enumerated only when its own language analyzes the path
            // (a build.gradle.kts that Kotlin analyzes says nothing about the
            // dependency evidence Java reads from it). Package identity can
            // also rekey declarations in unchanged files.
            if matches!(kind, InputKind::PackageIdentity)
                || !analyzed
                    .get(&language)
                    .is_some_and(|blobs| blobs.contains_key(path))
            {
                self.unenumerated.push((language, Box::from(path)));
            }
        };
        for (language, _, kind, inputs) in &participating {
            for (path, blob) in inputs {
                if base_blob_by_path.get(path) != Some(blob) {
                    record(*language, kind, path);
                }
            }
        }
        // A committed input the head did not read is a difference. Package
        // identity has no exemption: the head reads those inputs from the
        // whole listing, and Go naming reads manifests from disk directly. A
        // selected-configuration input exists only if the head's listing
        // selects it, so a committed file that is still on disk but outside
        // the listing (`is_gitignored`) was never an input on either side.
        for (rel_path, _) in base_blobs {
            let path = Path::new(rel_path.as_ref());
            let mut outside_listing = None;
            for (language, index, kind, inputs) in &participating {
                let is_input = match kind {
                    InputKind::PackageIdentity => index.is_package_identity_input(path),
                    InputKind::SelectedConfiguration => {
                        index.is_selected_configuration_input(path)
                            && !*outside_listing.get_or_insert_with(|| project.is_gitignored(path))
                    }
                };
                if !inputs.contains_key(rel_path) && is_input {
                    record(*language, kind, rel_path);
                }
            }
        }
        self.unenumerated.sort();
        self.unenumerated.dedup();
    }

    fn record_changed_blob(
        &mut self,
        language: Language,
        rel_path: &str,
        file: &ProjectFile,
        blob: Oid,
        index: Option<&dyn WorkspaceFactIndex>,
    ) {
        self.paths
            .entry(language)
            .or_default()
            .insert(Box::from(rel_path));
        match index.and_then(|index| index.blob_index_keys(file, blob)) {
            Some(keys) => self
                .keys
                .extend(keys.into_iter().map(|(family, key, _)| (family, key))),
            None => self.unenumerated.push((language, Box::from(rel_path))),
        }
    }
}

/// The file and key difference between two workspaces, with the head's own
/// path map, which the same pass already enumerated. Both
/// [`ChangedFacts::between`] and [`ChangedDelta::between`] start from this.
fn compare_workspaces(
    base: &WorkspaceAnalyzer,
    head: &WorkspaceAnalyzer,
) -> (ChangedDelta, HashMap<(Language, Box<str>), Oid>) {
    let mut delta = ChangedDelta::empty();
    let mut head_path_blobs = HashMap::default();
    let base_indexes = fact_indexes_by_language(base);
    let head_indexes = fact_indexes_by_language(head);
    for (analyzer, indexes) in [(base, &base_indexes), (head, &head_indexes)] {
        for language in analyzer.analyzer().languages() {
            if !indexes.contains_key(&language) {
                delta.languages_without_index.push(language);
            }
        }
    }
    delta.languages_without_index.sort();
    delta.languages_without_index.dedup();

    let mut languages = base_indexes.keys().copied().collect::<Vec<_>>();
    languages.extend(head_indexes.keys().copied());
    languages.sort();
    languages.dedup();
    for language in languages {
        // A side with no index for the language lists nothing; a side whose
        // listing failed cannot show which of its files are absent.
        let listed =
            |indexes: &HashMap<Language, &dyn WorkspaceFactIndex>| match indexes.get(&language) {
                Some(index) => blob_map(*index),
                None => Some(HashMap::default()),
            };
        let (Some(base_blobs), Some(head_blobs)) = (listed(&base_indexes), listed(&head_indexes))
        else {
            delta.languages_without_index.push(language);
            continue;
        };
        let mut paths = base_blobs
            .keys()
            .chain(head_blobs.keys())
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        for rel_path in paths {
            let base_blob = base_blobs.get(rel_path);
            let head_blob = head_blobs.get(rel_path);
            if base_blob.map(|(_, blob)| blob) == head_blob.map(|(_, blob)| blob) {
                continue;
            }
            let entries = |side: Option<&(ProjectFile, Oid)>,
                           index: Option<&&dyn WorkspaceFactIndex>| {
                side.map(|(file, blob)| index.and_then(|index| index.blob_index_keys(file, *blob)))
            };
            delta.record_index_difference(
                language,
                rel_path,
                entries(base_blob, base_indexes.get(&language)),
                entries(head_blob, head_indexes.get(&language)),
            );
        }
        for (rel_path, (_, blob)) in &head_blobs {
            head_path_blobs.insert((language, rel_path.clone()), *blob);
        }
    }
    delta.languages_without_index.sort();
    delta.languages_without_index.dedup();
    (delta, head_path_blobs)
}

/// The identity guard of [`ChangedDelta::between`]: per language, everything
/// the content identity folds except the file set. A language present on one
/// side only, or one whose digest cannot be stated, counts as moved.
fn identity_inputs_moved(base: &WorkspaceAnalyzer, head: &WorkspaceAnalyzer) -> Vec<Language> {
    let base_indexes = fact_indexes_by_language(base);
    let head_indexes = fact_indexes_by_language(head);
    let mut languages = base_indexes.keys().copied().collect::<Vec<_>>();
    languages.extend(head_indexes.keys().copied());
    languages.sort();
    languages.dedup();
    languages.retain(|language| {
        let digest = |indexes: &HashMap<Language, &dyn WorkspaceFactIndex>| {
            indexes
                .get(language)
                .and_then(|index| index.identity_inputs_digest())
        };
        let (base_digest, head_digest) = (digest(&base_indexes), digest(&head_indexes));
        base_digest.is_none() || base_digest != head_digest
    });
    languages
}

impl ChangedFacts {
    /// The difference between two workspaces for a diff_base run. Unlike
    /// [`ChangedDelta::between`] it applies no identity guard; see there.
    pub fn between(base: &WorkspaceAnalyzer, head: &WorkspaceAnalyzer) -> Self {
        let (delta, head_blobs) = compare_workspaces(base, head);
        Self { delta, head_blobs }
    }

    /// A delta computed earlier, attached to the head it leads to.
    ///
    /// The caller states that `delta` covers everything that moved from the
    /// snapshot it is compared against to `head`; this only reads the head's
    /// own path map, which a `ReadKey::File` is checked against.
    pub fn at_head(mut delta: ChangedDelta, head: &WorkspaceAnalyzer) -> Self {
        let mut head_blobs = HashMap::default();
        for (language, index) in fact_indexes_by_language(head) {
            let Some(blobs) = blob_map(index) else {
                delta.languages_without_index.push(language);
                continue;
            };
            for (rel_path, (_, blob)) in blobs {
                head_blobs.insert((language, rel_path), blob);
            }
        }
        delta.languages_without_index.sort();
        delta.languages_without_index.dedup();
        Self { delta, head_blobs }
    }

    /// The difference between a committed base subtree and `head`, with the
    /// base's facts read from the store instead of from a base analyzer.
    ///
    /// This is [`Self::between`] for a run that is not going to build the base
    /// at all. The base side is `base_blobs`, the `(workspace-relative path,
    /// blob)` listing of one committed tree, and the base blobs' index keys
    /// come from the facts the store already holds for them -- published by
    /// the run that evaluated that base, keyed by content, and therefore still
    /// the base's own facts. `base_source` supplies the bytes of the few blobs
    /// that moved, which hydration needs and which the object database can
    /// answer without materializing a tree.
    ///
    /// A base path is considered when the head serves its language and does
    /// not ignore it. A path whose keys cannot be enumerated leaves this set
    /// incomplete when the head analyzes that path too -- both sides published
    /// facts for it, so a failure there is missing evidence -- and is skipped
    /// when the head does not, because a blob no analyzer ever parsed
    /// published no index key to miss. (Reclamation cannot make that second
    /// case wrong: rows are reclaimed when a generation moves, and a
    /// generation move rotates the analysis epoch that every reusable unit's
    /// key carries.)
    ///
    /// The difference also covers the non-source inputs the head read: the
    /// package-identity inputs (`go.mod`, `Cargo.toml`) and the selected
    /// configuration (`Cargo.lock`, `go.sum`, `package.json`). They are
    /// compared by blob, because an uncommitted edit to one changes what the
    /// head means without changing any analyzed blob (see
    /// [`ChangedDelta::record_input_differences`]).
    pub fn from_committed_tree(
        head: &WorkspaceAnalyzer,
        base_blobs: &[(Box<str>, Oid)],
        base_source: &dyn Fn(Oid) -> Option<String>,
    ) -> Self {
        let mut facts = Self {
            delta: ChangedDelta::empty(),
            head_blobs: HashMap::default(),
        };
        let head_indexes = fact_indexes_by_language(head);
        for language in head.analyzer().languages() {
            if !head_indexes.contains_key(&language) {
                facts.delta.languages_without_index.push(language);
            }
        }
        let mut head_by_language: HashMap<Language, HashMap<Box<str>, (ProjectFile, Oid)>> =
            HashMap::default();
        let mut refused_by_language: HashMap<Language, HashMap<Box<str>, Oid>> = HashMap::default();
        for (language, index) in &head_indexes {
            let Some(blobs) = blob_map(*index) else {
                facts.delta.languages_without_index.push(*language);
                continue;
            };
            for (rel_path, (_, blob)) in &blobs {
                facts
                    .head_blobs
                    .insert((*language, rel_path.clone()), *blob);
            }
            head_by_language.insert(*language, blobs);
            match index.refused_source_blobs() {
                Ok(refusals) => {
                    refused_by_language.insert(
                        *language,
                        refusals
                            .into_iter()
                            .map(|(file, blob)| {
                                (
                                    Box::from(crate::path_utils::rel_path_string(&file).as_str()),
                                    blob,
                                )
                            })
                            .collect(),
                    );
                }
                Err(error) => {
                    head.analyzer().record_query_failure(error);
                    facts.delta.refused_sources_incomplete = true;
                }
            }
        }

        let project = head.analyzer().project();
        let root = project.root().to_path_buf();
        // One pass over the committed listing, so the head pass below is a
        // lookup per head file rather than a scan of the whole tree.
        let base_blob_by_path = base_blobs
            .iter()
            .map(|(rel_path, blob)| (rel_path.clone(), *blob))
            .collect::<HashMap<Box<str>, Oid>>();
        let mut base_by_language: HashMap<Language, HashSet<Box<str>>> = HashMap::default();
        for (rel_path, blob) in base_blobs {
            let file = ProjectFile::new(root.clone(), Path::new(rel_path.as_ref()).to_path_buf());
            let language = file.language();
            if language == Language::None || project.is_bifrostignored(Path::new(rel_path.as_ref()))
            {
                continue;
            }
            let Some(index) = head_indexes.get(&language) else {
                facts.delta.languages_without_index.push(language);
                continue;
            };
            base_by_language
                .entry(language)
                .or_default()
                .insert(rel_path.clone());
            let head_blob = head_by_language
                .get(&language)
                .and_then(|blobs| blobs.get(rel_path))
                .map(|(_, blob)| *blob)
                .or_else(|| {
                    refused_by_language
                        .get(&language)
                        .and_then(|blobs| blobs.get(rel_path).copied())
                });
            if head_blob == Some(*blob) {
                continue;
            }
            facts
                .delta
                .paths
                .entry(language)
                .or_default()
                .insert(rel_path.clone());
            let keys = base_source(*blob)
                .and_then(|source| index.stored_blob_index_keys(&file, *blob, &source));
            let head_entries = head_by_language
                .get(&language)
                .and_then(|blobs| blobs.get(rel_path))
                .map(|(head_file, head_blob)| index.blob_index_keys(head_file, *head_blob));
            // An absent deleted blob never published facts in this generation;
            // retain the existing reclamation/admission exception.
            let base_entries = if keys.is_none() && head_blob.is_none() {
                None
            } else {
                Some(keys)
            };
            facts
                .delta
                .record_index_difference(language, rel_path, base_entries, head_entries);
        }

        for (language, blobs) in &head_by_language {
            let base_paths = base_by_language.get(language);
            for (rel_path, (file, blob)) in blobs {
                let unchanged = base_blob_by_path.get(rel_path).copied() == Some(*blob)
                    && base_paths.is_some_and(|paths| paths.contains(rel_path));
                if unchanged {
                    continue;
                }
                if base_paths.is_some_and(|paths| paths.contains(rel_path)) {
                    continue;
                }
                facts.delta.record_changed_blob(
                    *language,
                    rel_path,
                    file,
                    *blob,
                    head_indexes.get(language).copied(),
                );
            }
        }
        facts.delta.record_input_differences(
            &head_indexes,
            &head_by_language,
            project,
            base_blobs,
            &base_blob_by_path,
        );
        for (language, refusals) in &refused_by_language {
            let base_paths = base_by_language.get(language);
            for (rel_path, blob) in refusals {
                let unchanged = base_blob_by_path.get(rel_path).copied() == Some(*blob)
                    && base_paths.is_some_and(|paths| paths.contains(rel_path));
                if !unchanged {
                    facts
                        .delta
                        .paths
                        .entry(*language)
                        .or_default()
                        .insert(rel_path.clone());
                }
            }
        }
        facts.delta.languages_without_index.sort();
        facts.delta.languages_without_index.dedup();
        facts
    }

    /// What moved between this comparison's head and itself: nothing.
    ///
    /// A [`ReadKey::Index`] is proved by membership in the set of names that
    /// moved between two workspaces, which is a statement about a read set
    /// recorded on the first of them. A read set the head itself recorded
    /// needs the difference between the head and the head, so its index
    /// probes hold because nothing moved, while its file keys are still
    /// checked against the same head path map. Built from this comparison's
    /// own map so that no second enumeration of the head is paid for.
    pub fn head_only(&self) -> Self {
        let mut delta = ChangedDelta::empty();
        delta.languages_without_index = self.delta.languages_without_index.clone();
        delta.refused_sources_incomplete = self.delta.refused_sources_incomplete;
        delta.without_base = self.delta.without_base;
        Self {
            delta,
            head_blobs: self.head_blobs.clone(),
        }
    }

    /// A comparison with no base, for a read set verified against the head
    /// alone, such as a protocol receipt checked against the request that
    /// serves it. No index difference can be proved, so the set is incomplete
    /// and every [`ReadKey::Index`] fails closed. It holds no head path map, so
    /// file keys read the head directly, once per path through the
    /// [`LookupMemo`]; nothing here enumerates the workspace.
    pub fn without_base() -> Self {
        let mut delta = ChangedDelta::empty();
        delta.without_base = true;
        Self {
            delta,
            head_blobs: HashMap::default(),
        }
    }

    /// Whether every changed blob's facts were enumerated and every language
    /// the two analyzers serve published a fact index.
    pub fn is_complete(&self) -> bool {
        self.delta.is_complete()
    }

    /// The changed blobs whose facts could not be enumerated, and the
    /// languages that published no fact index at all.
    pub fn incompleteness(&self) -> (&[(Language, Box<str>)], &[Language]) {
        (
            &self.delta.unenumerated,
            &self.delta.languages_without_index,
        )
    }

    /// Whether a changed file has different published entries under this key.
    pub fn contains(&self, family: IndexFamily, key: &[u8]) -> bool {
        self.delta.contains(family, key)
    }

    /// The blob the head resolves `rel_path` to in `language`, or `None` when
    /// the head does not analyze it.
    pub fn head_blob(&self, language: Language, rel_path: &str) -> Option<Oid> {
        self.head_blobs
            .get(&(language, Box::from(rel_path)))
            .copied()
    }

    /// Whether this path's blob differs between the two workspaces.
    pub fn path_changed(&self, language: Language, rel_path: &str) -> bool {
        self.delta.path_changed(language, rel_path)
    }

    /// Every workspace-relative path whose blob differs, with its language.
    /// Carries files only: the difference holds no line ranges.
    pub fn changed_paths(&self) -> impl Iterator<Item = (Language, &str)> + '_ {
        self.delta.changed_paths()
    }

    /// How many paths changed, over every language.
    pub fn changed_path_count(&self) -> usize {
        self.delta.changed_path_count()
    }
}

/// One fact index per language an analyzer publishes.
fn fact_indexes_by_language(
    analyzer: &WorkspaceAnalyzer,
) -> HashMap<Language, &dyn WorkspaceFactIndex> {
    analyzer
        .analyzer()
        .workspace_fact_indexes()
        .into_iter()
        .map(|index| (index.fact_index_language(), index))
        .collect()
}

/// One language's analyzed paths, by their normalized workspace-relative
/// spelling -- the one name a base export and a head checkout agree on.
/// None when the language's listing could not be read; see
/// [`WorkspaceFactIndex::analyzed_blobs`].
fn blob_map(index: &dyn WorkspaceFactIndex) -> Option<HashMap<Box<str>, (ProjectFile, Oid)>> {
    Some(
        index
            .analyzed_blobs()?
            .into_iter()
            .map(|(file, blob)| {
                (
                    Box::from(crate::path_utils::rel_path_string(&file).as_str()),
                    (file, blob),
                )
            })
            .collect(),
    )
}

/// The bounded limits a replayed lookup re-runs its funnel under.
///
/// A reusable unit only ever carries complete answers (the exhaustiveness rule
/// of the plan), so replaying under the caller's full limits reproduces the
/// recorded answer whenever the content did not move. A narrower replay would
/// truncate where the recording did not and report a change that is really a
/// budget artifact.
#[derive(Debug, Clone, Copy)]
pub struct LookupReplayLimits {
    /// The call-relation funnel's own limits, for `callers` and `callees`.
    pub call_relations: CallRelationLimits,
    /// How many files one usage query may reach.
    pub max_usage_files: usize,
    /// How many usages one usage query may retain.
    pub max_usages: usize,
    /// Caps the one-file source read proving a NoHead or StaleEpoch answer.
    pub stored_semantic_ir_source_bytes: usize,
    /// The semantic work one dispatch replay may charge.
    pub semantic: SemanticWork,
}

impl Default for LookupReplayLimits {
    /// The limits an interactive read runs under, which is the widest set the
    /// funnels publish as their own defaults.
    fn default() -> Self {
        Self {
            call_relations: CallRelationLimits {
                max_files: usize::MAX,
                max_source_bytes: usize::MAX,
                max_candidates: usize::MAX,
            },
            max_usage_files: DEFAULT_MAX_FILES,
            max_usages: DEFAULT_MAX_USAGES,
            stored_semantic_ir_source_bytes: usize::MAX,
            semantic: SemanticWork::default_limits(),
        }
    }
}

/// The head's answer to a recorded procedure-summary read.
///
/// The summary repository lives in `brokk-bifrost-flow`, which depends on this
/// crate, so verification cannot reach it from here. Whoever owns the head's
/// repository supplies this instead, and answers through the same lookup the
/// recording was announced from, so both sides fold the same digest.
pub trait SummaryAnswers {
    /// The head's workspace authority digest. None means the caller cannot
    /// answer, so verification must recompute rather than retain the product.
    fn workspace_fact(
        &self,
        _family: WorkspaceFactFamily,
        _language: Language,
        _subject: &FactSubject,
    ) -> Option<StableDigest> {
        None
    }

    /// The content digest the head retains under `identity`, or the ledger's
    /// absent digest when it retains nothing.
    ///
    /// `None` is not absence. It says this head cannot be asked the question
    /// at all -- no repository in hand, or more than one summary retained
    /// under one identity -- which makes every unit that recorded a summary
    /// read recompute, the sound direction.
    fn summary_content(&self, identity: StableDigest) -> Option<StableDigest>;
}

/// The answer source for a verification holding no summary repository.
///
/// Every summary read it is asked about is unanswerable, so a unit that
/// recorded one is recomputed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSummaryAnswers;

impl SummaryAnswers for NoSummaryAnswers {
    fn summary_content(&self, _identity: StableDigest) -> Option<StableDigest> {
        None
    }
}

/// Replayed lookup answers, keyed by the question that produced them.
///
/// Verification asks the same question once per unit that recorded it, and a
/// policy with many units asks it many times. The memo is the caller's, not a
/// global cache, so its lifetime is exactly one head evaluation and no answer
/// outlives the workspace it was computed against.
#[derive(Debug, Default)]
pub struct LookupMemo {
    answers: HashMap<(LookupKind, LookupQuestion), Option<StableDigest>>,
    replay_elapsed: Duration,
    selection_request:
        Option<std::sync::Arc<brokk_bifrost_core::analyzer::outer_request::OuterRequest>>,
    raw_blobs: HashMap<(Language, Box<str>), Result<Option<Oid>, ()>>,
}

impl LookupMemo {
    pub fn new() -> Self {
        Self::default()
    }

    fn external_selection_answer(
        &mut self,
        authorities: &[&dyn brokk_bifrost_core::analyzer::external_selection::ExternalSelectionAuthority],
        question: &LookupQuestion,
        cancellation: &CancellationToken,
    ) -> Option<StableDigest> {
        use brokk_bifrost_core::analyzer::external_selection::SelectionRetry;
        use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
        let key = (LookupKind::ExternalSelection, question.clone());
        if let Some(answer) = self.answers.get(&key) {
            return *answer;
        }
        let request = self.selection_request.get_or_insert_with(OuterRequest::new);
        let answer = if let LookupQuestion::ExternalSelection { question_digest } = question {
            authorities
                .iter()
                .find_map(|authority| {
                    authority
                        .questions()
                        .into_iter()
                        .find(|q| q.digest == *question_digest)
                        .map(|q| {
                            authority.answer(request, &q, &SelectionRetry::default(), cancellation)
                        })
                })
                .and_then(Result::ok)
                .filter(|a| a.complete && a.certified)
                .map(|a| StableDigest::from_array(a.answer_digest))
        } else {
            None
        };
        if cancellation.is_cancelled() {
            return None;
        }
        self.answers.insert(key, answer);
        answer
    }

    /// The head's blob at one recorded path, read at most once per head
    /// evaluation. Verification must not record its own project reads.
    fn head_blob(
        &mut self,
        head: &WorkspaceAnalyzer,
        changed: &ChangedFacts,
        language: Language,
        rel_path: &str,
    ) -> Result<Option<Oid>, ()> {
        if let Some(blob) = changed.head_blob(language, rel_path) {
            return Ok(Some(blob));
        }
        *self
            .raw_blobs
            .entry((language, rel_path.into()))
            .or_insert_with(|| {
                brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
                    head_path_blob(head, language, rel_path).map_err(|_| ())
                })
            })
    }

    /// How many distinct questions this memo has answered.
    pub fn len(&self) -> usize {
        self.answers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.answers.is_empty()
    }

    /// Time spent executing distinct lookup replays against the workspace.
    pub fn replay_elapsed(&self) -> Duration {
        self.replay_elapsed
    }

    /// The head's answer to one question, replaying it at most once.
    pub fn answer(
        &mut self,
        head: &WorkspaceAnalyzer,
        kind: LookupKind,
        question: &LookupQuestion,
        limits: LookupReplayLimits,
        summaries: &dyn SummaryAnswers,
    ) -> Option<StableDigest> {
        let read_ledger_attached = crate::analyzer::read_attribution_records_reads(|| {
            head.analyzer().read_ledger_attached()
        });
        if read_ledger_attached {
            head.analyzer().record_unattributed_read();
        }
        debug_assert!(
            !read_ledger_attached,
            "lookup verification is outside product captures"
        );
        if let Some(answer) = self.answers.get(&(kind, question.clone())) {
            return *answer;
        }
        let started = Instant::now();
        if kind == LookupKind::WorkspaceFact
            && let LookupQuestion::WorkspaceFact {
                family:
                    WorkspaceFactFamily::WorkspaceFileListing
                    | WorkspaceFactFamily::WorkspaceFileInventory,
                language: Language::None,
                subject: FactSubject::Whole,
            } = question
        {
            let pair =
                super::workspace_authority::workspace_file_set_answers(head.analyzer().project())
                    .ok();
            for (family, answer) in [
                (
                    WorkspaceFactFamily::WorkspaceFileListing,
                    pair.map(|pair| pair.listing),
                ),
                (
                    WorkspaceFactFamily::WorkspaceFileInventory,
                    pair.map(|pair| pair.inventory),
                ),
            ] {
                self.answers.insert(
                    (
                        kind,
                        LookupQuestion::WorkspaceFact {
                            family,
                            language: Language::None,
                            subject: FactSubject::Whole,
                        },
                    ),
                    answer,
                );
            }
            self.replay_elapsed += started.elapsed();
            return self.answers[&(kind, question.clone())];
        }
        let answer = replay_lookup(head, kind, question, limits, summaries);
        self.replay_elapsed += started.elapsed();
        self.answers.insert((kind, question.clone()), answer);
        answer
    }
}

/// Re-run one recorded lookup against `head` and return the digest of what it
/// answered, or `None` when the question no longer resolves there.
///
/// This is the same funnel the recording crossed, under an ordinary query
/// scope with no ledger attached, and the answer digest is computed by the
/// same helper the recording used -- never by a second rendering of the same
/// answer, which could disagree and would make every unit look changed.
///
/// `None` is a verdict, not an error: a declaration that no longer exists, a
/// file that left the analyzed set, or an artifact whose fingerprint moved are
/// all cases where the head has no answer to the question that was asked, and
/// a unit that depended on the old answer must be recomputed.
/// Replay a certified probe against every delegate named by its question.
/// Incomplete reads are deliberately not certified: their operational state
/// cannot be reconstructed from a partial declaration set alone.
pub fn certified_definition_answer_digest(
    analyzer: &dyn IAnalyzer,
    question: &LookupQuestion,
) -> Option<StableDigest> {
    let LookupQuestion::CertifiedDefinition {
        kind,
        name,
        delegates,
        normalization_version,
    } = question
    else {
        return None;
    };
    if delegates.is_empty() || !delegates.windows(2).all(|pair| pair[0] < pair[1]) {
        return None;
    }
    if (*kind == CertifiedDefinitionKind::NormalizedTail)
        != (*normalization_version == Some(DEFINITION_NORMALIZED_TAIL_VERSION))
    {
        return None;
    }
    let actual: Vec<_> = analyzer.languages().into_iter().collect();
    if actual != *delegates {
        return None;
    }
    if !analyzer.has_complete_symbol_lookup_index() {
        return None;
    }
    let answer = match kind {
        CertifiedDefinitionKind::Exact => analyzer.get_definitions(name),
        CertifiedDefinitionKind::NormalizedTail => {
            // The question already holds the normalized key; do not normalize it again.
            let indexes = analyzer.workspace_fact_indexes();
            let mut answer = Vec::new();
            for language in delegates {
                let index = indexes
                    .iter()
                    .find(|index| index.fact_index_language() == *language)?;
                answer.extend(index.normalized_tail_candidates(name)?);
            }
            answer
        }
        CertifiedDefinitionKind::Identifier => analyzer
            .lookup_candidates_by_identifier(name)
            .into_iter()
            .collect(),
    };
    analyzer.current_query_read_completion().ok()?;
    Some(certified_definition_complete_answer_digest(&answer))
}

/// Digest the answer already consumed by a definition funnel. Callers must
/// publish this only when that funnel established a complete answer.
pub fn certified_definition_complete_answer_digest(answer: &[CodeUnit]) -> StableDigest {
    let mut hasher = CanonicalHasher::new(b"certified_definition_answer:v1");
    hasher.field("completion", b"complete");
    hasher.field(
        "answer",
        crate::analyzer::read_ledger::declaration_set_digest(answer.iter()).as_bytes(),
    );
    StableDigest::from_array(hasher.finish())
}

pub fn replay_lookup(
    head: &WorkspaceAnalyzer,
    kind: LookupKind,
    question: &LookupQuestion,
    limits: LookupReplayLimits,
    summaries: &dyn SummaryAnswers,
) -> Option<StableDigest> {
    let analyzer = head.analyzer();
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    match kind {
        LookupKind::StoredSemanticIrPublication => {
            let LookupQuestion::StoredSemanticIrPublication(q) = question else {
                debug_assert!(
                    false,
                    "a stored semantic IR read needs a publication question"
                );
                return None;
            };
            let file = analyzed_file(analyzer, &q.rel_path)?;
            let cancellation = analyzer.active_query_cancellation().unwrap_or_default();
            let StoredSemanticIrRead::Observed(observation) = head
                .stored_semantic_ir_publication_read(
                    &file,
                    q.subject,
                    Some(limits.stored_semantic_ir_source_bytes),
                    &cancellation,
                )
                .ok()?
            else {
                return None;
            };
            let selection = &observation.selection;
            if StoredSemanticIrPublicationQuestion::new(
                selection.rel_path.clone(),
                selection.storage_language.clone(),
                q.subject,
                selection.variant,
            ) != *q
            {
                return None;
            }
            let answer = classify(&observation, q.subject);
            match &answer {
                StoredSemanticIrPublicationAnswer::Present { .. } => {}
                StoredSemanticIrPublicationAnswer::NoHead
                | StoredSemanticIrPublicationAnswer::StaleEpoch => {
                    if observation.source_content != Some(q.subject) {
                        return None;
                    }
                }
                StoredSemanticIrPublicationAnswer::ContentMismatch => return None,
            }
            Some(answer.canonical_digest())
        }
        // #9737 M3: derivation replay must verify through the selected engine.
        LookupKind::Derivation(_) => None,
        // #9559 M3a: the head has no external-selection verifier yet.
        LookupKind::ExternalSelection => None,
        LookupKind::RustBoundTraitImplInventory
        | LookupKind::RustTraitsImplementedByInventory
        | LookupKind::RustAliasBlobInventory
        | LookupKind::RustMacroExpansionInventory
        | LookupKind::RustUnresolvedTraitImplInventory
        | LookupKind::RustModuleImportCandidateInventory
        | LookupKind::RustIdentifierOccurrenceInventory
        | LookupKind::RustCopyAbsence => crate::analyzer::languages::language_support_for_hook(
            Language::Rust,
            "replay_owned_lookup",
        )?
        .replay_owned_lookup(head, kind, question, limits.semantic.nested_entries),
        LookupKind::StructuralNameInventory
        | LookupKind::StructuralRoleNameInventory
        | LookupKind::StructuralRecoveredInventory => {
            let workspace_before = analyzer.workspace_content_identity()?;
            let cancellation = analyzer.active_query_cancellation().unwrap_or_default();
            if cancellation.is_cancelled() {
                return None;
            }
            let (language, authority, name, role) = match (kind, question) {
                (
                    LookupKind::StructuralNameInventory,
                    LookupQuestion::StructuralName {
                        language,
                        name,
                        authority,
                    },
                ) => (*language, *authority, Some(name.as_ref()), None),
                (
                    LookupKind::StructuralRoleNameInventory,
                    LookupQuestion::StructuralRoleName {
                        language,
                        role,
                        name,
                        keyword,
                        authority,
                    },
                ) => (
                    *language,
                    *authority,
                    Some(name.as_ref()),
                    Some((*role, *keyword)),
                ),
                (
                    LookupKind::StructuralRecoveredInventory,
                    LookupQuestion::StructuralRecovered {
                        language,
                        authority,
                    },
                ) => (*language, *authority, None, None),
                _ => return None,
            };
            let provider = analyzer
                .structural_fact_providers()
                .into_iter()
                .find(|provider| provider.structural_language() == language)?;
            if !provider.structural_inventory_complete() {
                return None;
            }
            if provider.structural_selection_authority()? != authority {
                return None;
            }
            let before = provider.structural_content_identity()?;
            let cache = provider.snapshot_structural_index_cache()?;
            let StructuralIndexAcquisition::Ready { index, .. } =
                cache.inner().acquire(provider, &cancellation)
            else {
                return None;
            };
            if index.content_identity() != before
                || provider.structural_content_identity()? != before
                || provider.structural_selection_authority()? != authority
            {
                return None;
            }
            let digest = if let Some((role, keyword)) = role {
                index.role_name_inventory(role, name?, keyword).0
            } else if let Some(name) = name {
                index.exact_name_inventory(name).0
            } else {
                index.recovered_inventory().0
            };
            if cancellation.is_cancelled()
                || provider.structural_content_identity()? != before
                || analyzer.workspace_content_identity()? != workspace_before
            {
                return None;
            }
            Some(digest)
        }
        LookupKind::ResolvedName => {
            use crate::analyzer::BoundedDefinitionLookup;
            let LookupQuestion::Name { language, name } = question else {
                unreachable!("a resolved-name lookup records a name question")
            };
            let lookup = crate::analyzer::AnalyzerDefinitionLookup::new(analyzer, Language::None);
            let definitions = match language {
                Some(language) => lookup.fqn_in_language(name, *language),
                None => lookup.fqn_in_any_language(name),
            };
            lookup
                .can_publish()
                .then(|| crate::analyzer::read_ledger::declaration_set_digest(&definitions))
        }
        LookupKind::CertifiedDefinitionAnswer => {
            certified_definition_answer_digest(analyzer, question)
        }
        LookupKind::Definitions
        | LookupKind::IdentifierCandidates
        | LookupKind::ShortNameCandidates => {
            let LookupQuestion::Name { language, name } = question else {
                unreachable!("a definitions lookup records a name question")
            };
            Some(match language {
                Some(language) => {
                    let indexes = analyzer.workspace_fact_indexes();
                    let index = indexes
                        .into_iter()
                        .find(|index| index.fact_index_language() == *language)?;
                    match kind {
                        LookupKind::Definitions => index.definition_answer_digest(name),
                        LookupKind::IdentifierCandidates => {
                            index.identifier_candidate_answer_digest(name)
                        }
                        LookupKind::ShortNameCandidates => {
                            index.short_name_candidate_answer_digest(name)
                        }
                        _ => unreachable!("the match admits only name lookup kinds"),
                    }
                }
                None => match kind {
                    LookupKind::Definitions => {
                        crate::analyzer::read_ledger::declaration_set_digest(
                            &analyzer.get_definitions(name),
                        )
                    }
                    LookupKind::IdentifierCandidates => {
                        crate::analyzer::read_ledger::declaration_set_digest(
                            &analyzer.lookup_candidates_by_identifier(name),
                        )
                    }
                    LookupKind::ShortNameCandidates => {
                        crate::analyzer::read_ledger::declaration_set_digest(
                            &analyzer.lookup_candidates_by_short_name(name),
                        )
                    }
                    _ => unreachable!("the match admits only name lookup kinds"),
                },
            })
        }
        LookupKind::DeclarationFacts => Some(match replayed_declaration(analyzer, question) {
            Some(declaration) => analyzer
                .workspace_fact_indexes()
                .into_iter()
                .find(|index| index.fact_index_language() == declaration.source().language())?
                .declaration_facts_digest(&declaration),
            None => absent_declaration_facts_digest(),
        }),
        LookupKind::DeclarationCandidates => {
            let LookupQuestion::Declaration { rel_path, .. } = question else {
                unreachable!("declaration candidates require a declaration question")
            };
            let file = ProjectFile::new(analyzer.project().root(), Path::new(rel_path.as_ref()));
            let candidates = analyzer.declaration_candidates_for_question(&file, question)?;
            analyzer.current_query_read_completion().ok()?;
            Some(
                crate::analyzer::read_ledger::declaration_candidate_set_digest(
                    question,
                    &candidates,
                ),
            )
        }
        LookupKind::SignatureMetadata => Some(match replayed_declaration(analyzer, question) {
            Some(declaration) => analyzer
                .workspace_fact_indexes()
                .into_iter()
                .find(|index| index.fact_index_language() == declaration.source().language())?
                .signature_metadata_digest(&declaration),
            None => absent_signature_metadata_digest(),
        }),
        LookupKind::Callers => {
            let unit = replayed_declaration(analyzer, question)?;
            let result = CallRelationService::incoming_bounded(
                analyzer,
                token,
                &unit,
                limits.call_relations,
                None,
            );
            Some(crate::analyzer::usages::call_relations::call_relation_answer_digest(&result))
        }
        LookupKind::Callees => {
            let unit = replayed_declaration(analyzer, question)?;
            let result = CallRelationService::outgoing_bounded(
                analyzer,
                token,
                &unit,
                limits.call_relations,
                None,
            );
            Some(crate::analyzer::usages::call_relations::call_relation_answer_digest(&result))
        }
        LookupKind::Usages => {
            let unit = replayed_declaration(analyzer, question)?;
            let result = UsageFinder::new().find_usages(
                analyzer,
                std::slice::from_ref(&unit),
                limits.max_usage_files,
                limits.max_usages,
            );
            Some(crate::analyzer::i_analyzer::usage_answer_digest(
                &result, &unit,
            ))
        }
        LookupKind::ReferenceCandidates => {
            let unit = replayed_declaration(analyzer, question)?;
            let result =
                crate::analyzer::structural::reference_edges::inverse_edges_for_declaration(
                    analyzer, &unit, None,
                );
            Some(crate::analyzer::structural::reference_edges::inverse_edge_answer_digest(&result))
        }
        LookupKind::Descendants => {
            let unit = replayed_declaration(analyzer, question)?;
            let provider = analyzer.type_hierarchy_provider()?;
            let cancellation = CancellationToken::default();
            let descendants = provider
                .get_direct_descendants_within(
                    &unit,
                    &DescendantIndexScope::whole_workspace(&cancellation),
                )
                .ok()?;
            if !descendants.is_complete() {
                return None;
            }
            Some(crate::analyzer::read_ledger::declaration_set_digest(
                &descendants.edges,
            ))
        }
        LookupKind::Importers => {
            let file = replayed_file(analyzer, question)?;
            let provider = analyzer.import_analysis_provider()?;
            let referencing = provider
                .referencing_files_of(&file)
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            Some(crate::analyzer::read_ledger::file_set_digest(&referencing))
        }
        LookupKind::Dispatch | LookupKind::ProcedureDispatch => {
            replay_dispatch(head, kind, question, limits)
        }
        // The repository is not this crate's, so the answer comes from the
        // caller that holds the head's, through the same lookup the recording
        // was announced from.
        LookupKind::WorkspaceFact => {
            let LookupQuestion::WorkspaceFact {
                family,
                language,
                subject,
            } = question
            else {
                unreachable!("a workspace-fact lookup records a workspace-fact question");
            };
            answer_workspace_fact(head, summaries, *family, *language, subject, limits)
        }
        LookupKind::ProcedureSummary => {
            let LookupQuestion::Summary { identity } = question else {
                debug_assert!(
                    false,
                    "a procedure-summary lookup recorded a {} question: {question:?}",
                    question.stable_label()
                );
                return None;
            };
            summaries.summary_content(*identity)
        }
    }
}

/// The head's answer to one `WorkspaceFact` question.
///
/// Each family is answered by the code that owns its authority. The
/// field-slot index belongs to the flow crate, which this crate cannot name,
/// so its families go to the caller-supplied answers. A family whose authority
/// is computed in this crate gets an arm here. Every other family belongs to
/// a language adapter and is answered by that language's registered support.
/// `None` means unanswerable, which invalidates the recorded key.
fn answer_workspace_fact(
    head: &WorkspaceAnalyzer,
    summaries: &dyn SummaryAnswers,
    family: WorkspaceFactFamily,
    language: Language,
    subject: &FactSubject,
    limits: LookupReplayLimits,
) -> Option<StableDigest> {
    let analyzer = head.analyzer();
    match family {
        WorkspaceFactFamily::WorkspaceFileListing | WorkspaceFactFamily::WorkspaceFileInventory => {
            if language != Language::None || !matches!(subject, FactSubject::Whole) {
                return None;
            }
            let answers =
                super::workspace_authority::workspace_file_set_answers(analyzer.project()).ok()?;
            Some(if family == WorkspaceFactFamily::WorkspaceFileListing {
                answers.listing
            } else {
                answers.inventory
            })
        }
        WorkspaceFactFamily::WorkspaceAnalyzerLanguages => {
            if language != Language::None || !matches!(subject, FactSubject::Whole) {
                return None;
            }
            Some(
                super::workspace_authority::workspace_analyzer_languages_answer(analyzer.project()),
            )
        }
        WorkspaceFactFamily::WorkspaceIgnoreRules => {
            if language != Language::None || !matches!(subject, FactSubject::Whole) {
                return None;
            }
            super::workspace_authority::workspace_ignore_rules_answer(analyzer.project()).ok()
        }
        WorkspaceFactFamily::WorkspacePathKind => {
            if language != Language::None {
                return None;
            }
            let FactSubject::File { rel_path } = subject else {
                return None;
            };
            Some(super::workspace_authority::workspace_path_kind_answer(
                analyzer.project(),
                rel_path,
            ))
        }
        WorkspaceFactFamily::WorkspaceDirectory => {
            if language != Language::None {
                return None;
            }
            let FactSubject::File { rel_path } = subject else {
                return None;
            };
            Some(super::workspace_authority::workspace_directory_answer(
                analyzer.project(),
                rel_path,
            ))
        }
        WorkspaceFactFamily::WorkspaceOverlayMembership => {
            if language != Language::None {
                return None;
            }
            match subject {
                FactSubject::Whole => Some(
                    super::workspace_authority::workspace_overlay_set_answer(analyzer.project()),
                ),
                FactSubject::File { rel_path } => Some(
                    super::workspace_authority::workspace_overlay_membership_answer(
                        analyzer.project(),
                        rel_path,
                    ),
                ),
                _ => None,
            }
        }
        WorkspaceFactFamily::PathSyntheticModules => {
            let index = analyzer
                .workspace_fact_indexes()
                .into_iter()
                .find(|index| index.fact_index_language() == language)?;
            match subject {
                FactSubject::Whole => index.path_synthetic_modules_answer_digest(),
                FactSubject::File { rel_path } => {
                    let file = analyzed_file(analyzer, rel_path)?;
                    index.path_synthetic_module_answer_digest(&file)
                }
                _ => None,
            }
        }
        WorkspaceFactFamily::FieldSlots => summaries.workspace_fact(family, language, subject),
        WorkspaceFactFamily::JvmSelectedRootPresence => {
            if language != Language::None || !matches!(subject, FactSubject::Named { .. }) {
                return None;
            }
            crate::analyzer::languages::language_support(Language::Java)?
                .workspace_fact_answer(analyzer, family, language, subject)
        }
        // The unresolved-coordinate set of the JVM external index. It names no
        // workspace file: a jar that appears or disappears under a repository
        // root changes it with no workspace edit.
        WorkspaceFactFamily::JvmExternalGaps => {
            if language != Language::None || !matches!(subject, FactSubject::Whole) {
                return None;
            }
            crate::analyzer::languages::language_support(Language::Java)?
                .workspace_fact_answer(analyzer, family, language, subject)
        }
        WorkspaceFactFamily::RuntimeRootWriteFootprint => {
            let FactSubject::File { rel_path } = subject else {
                return None;
            };
            let file = ProjectFile::new(
                analyzer.project().root().to_path_buf(),
                Path::new(rel_path.as_ref()),
            );
            // This authority scans project source snapshots, not declaration
            // indexes. The current module must still belong to that source set.
            if file.language() != language
                || !analyzer.project().all_files_shared().ok()?.contains(&file)
            {
                return None;
            }
            crate::analyzer::semantic::workspace_oracle::runtime_values::runtime_footprint_answer(
                head,
                &file,
                limits.semantic,
            )
        }
        WorkspaceFactFamily::JsTsExternalModuleMemberMutation => {
            if !matches!(language, Language::JavaScript | Language::TypeScript) {
                return None;
            }
            let FactSubject::NamedMember { owner, member } = subject else {
                return None;
            };
            crate::analyzer::semantic::workspace_oracle::dispatch::js_ts_module_member_mutation_answer(analyzer, owner, member)
        }
        _ => crate::analyzer::languages::language_support(language)?
            .workspace_fact_answer(analyzer, family, language, subject),
    }
}

/// The head's declaration for a declaration question.
///
/// Resolved through the head's own declaration lookup for the file the
/// question names, never by re-parsing or by matching text: the question is a
/// workspace-relative path and declaration identity, and the analyzer is the only
/// thing that knows which declarations a file has.
///
/// Declarations still sharing all these fields (for example equal signatures in
/// two Rust impls) use the first source location. A different recorded answer
/// still disagrees and safely recomputes rather than granting reuse.
fn replayed_declaration(analyzer: &dyn IAnalyzer, question: &LookupQuestion) -> Option<CodeUnit> {
    let LookupQuestion::Declaration {
        rel_path,
        fq_name,
        kind,
        signature,
    } = question
    else {
        debug_assert!(
            false,
            "a declaration-shaped lookup recorded a {} question: {question:?}",
            question.stable_label()
        );
        return None;
    };
    let file = analyzed_file(analyzer, rel_path)?;
    analyzer
        .get_declarations(&file)
        .into_iter()
        .filter(|unit| {
            unit.fq_name() == **fq_name
                && unit.kind() == *kind
                && unit.signature() == signature.as_deref()
        })
        .min_by(|left, right| {
            let first_byte = |unit: &CodeUnit| {
                analyzer
                    .ranges(unit)
                    .iter()
                    .map(|range| range.start_byte)
                    .min()
                    .unwrap_or(usize::MAX)
            };
            first_byte(left).cmp(&first_byte(right))
        })
}

/// The head's file for a file question.
fn replayed_file(analyzer: &dyn IAnalyzer, question: &LookupQuestion) -> Option<ProjectFile> {
    let LookupQuestion::File { rel_path } = question else {
        debug_assert!(
            false,
            "a file-shaped lookup recorded a {} question: {question:?}",
            question.stable_label()
        );
        return None;
    };
    analyzed_file(analyzer, rel_path)
}

/// The head's `ProjectFile` for one workspace-relative path, when the head
/// analyzed it.
///
/// A path that left the analyzed set has no answer to give, which is a change
/// and not an error.
fn analyzed_file(analyzer: &dyn IAnalyzer, rel_path: &str) -> Option<ProjectFile> {
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), Path::new(rel_path));
    analyzer.is_analyzed(&file).then_some(file)
}

/// Replay one dispatch question through the address domain its kind names.
fn replay_dispatch(
    head: &WorkspaceAnalyzer,
    kind: LookupKind,
    question: &LookupQuestion,
    limits: LookupReplayLimits,
) -> Option<StableDigest> {
    if !matches!(
        (kind, question),
        (
            LookupKind::Dispatch | LookupKind::ProcedureDispatch,
            LookupQuestion::CallSite { .. }
        )
    ) {
        debug_assert!(false, "a dispatch read needs a ranked call question");
        return None;
    }
    replay_procedure_dispatch(head, question, limits)
}

fn replay_procedure_dispatch(
    head: &WorkspaceAnalyzer,
    question: &LookupQuestion,
    limits: LookupReplayLimits,
) -> Option<StableDigest> {
    let mut budget = SemanticBudget::new(limits.semantic).ok()?;
    let cancellation = CancellationToken::default();
    replay_procedure_dispatch_with_request(
        head,
        question,
        &head.semantic_oracle_provider(),
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
}

/// Replay one exact procedure-local dispatch read against `head` while
/// charging the caller's semantic request.
///
/// Class-set summary acquisition uses this before pruning a procedure's
/// descendants. Only the replayable procedure-dispatch shape is accepted;
/// an unnameable question, changed answer, cancellation, or exhausted budget
/// all return `false`, so the caller keeps the ordinary discovery path.
pub fn verify_procedure_dispatch_read(
    head: &WorkspaceAnalyzer,
    oracle: &WorkspaceSemanticOracle<'_>,
    key: &ReadKey,
    request: &mut SemanticRequest<'_>,
) -> bool {
    let ReadKey::Lookup {
        kind: LookupKind::ProcedureDispatch,
        question,
        digest,
    } = key
    else {
        return false;
    };
    replay_procedure_dispatch_with_request(head, question, oracle, request)
        .is_some_and(|replayed| replayed == *digest)
}

/// A resource interruption while resolving the structured address of a
/// procedure-dispatch read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureDispatchReadCallError {
    Cancelled,
}

/// Resolve a procedure-dispatch read to the one live call it names.
///
/// This is the structured addressing half of dispatch replay. It deliberately
/// accepts an already materialized procedure, so a caller that also needs the
/// live dispatch result can invoke its cached provider exactly once and retain
/// that outcome for coverage and boundary reconstruction. Whole-artifact
/// content is not an equality input: stable procedure lineage and call rank
/// admit an unchanged procedure after an unrelated sibling edit.
pub fn procedure_dispatch_read_call(
    procedure: &ProcedureHandle,
    key: &ReadKey,
    request: &mut SemanticRequest<'_>,
) -> Result<Option<(CallSiteHandle, StableDigest)>, ProcedureDispatchReadCallError> {
    let ReadKey::Lookup {
        kind: LookupKind::ProcedureDispatch,
        question:
            LookupQuestion::CallSite {
                rel_path,
                procedure: expected_procedure,
                site: expected_site,
            },
        digest,
    } = key
    else {
        return Ok(None);
    };
    if procedure.artifact().key().path().as_str() != rel_path.as_ref()
        || procedure
            .artifact()
            .key()
            .procedure_lineage_fingerprint(procedure.semantics().locator().declaration())
            != *expected_procedure
    {
        return Ok(None);
    }
    procedure_dispatch_call_at_relative_site(procedure, expected_site, request)
        .map(|call| call.map(|call| (call, *digest)))
}

fn replay_procedure_dispatch_with_request(
    head: &WorkspaceAnalyzer,
    question: &LookupQuestion,
    oracle: &WorkspaceSemanticOracle<'_>,
    request: &mut SemanticRequest<'_>,
) -> Option<StableDigest> {
    let LookupQuestion::CallSite {
        rel_path,
        procedure: expected_procedure,
        site: expected_site,
    } = question
    else {
        unreachable!("replay_procedure_dispatch is called only for a procedure call-site question")
    };
    let file = analyzed_file(head.analyzer(), rel_path)?;
    let materialized = head
        .materialize_program_semantics(&file, request)
        .ok()?
        .available_value()?
        .clone();
    let mut matched_procedure = None;
    for procedure in materialized.procedures() {
        if request.cancellation.is_cancelled() {
            return None;
        }
        request.budget.charge_work(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        });
        let lineage = materialized
            .key()
            .procedure_lineage_fingerprint(procedure.locator().declaration());
        if lineage != *expected_procedure {
            continue;
        }
        let candidate = materialized.procedure_handle(procedure.id())?;
        if matched_procedure.replace(candidate).is_some() {
            return None;
        }
    }
    let procedure = matched_procedure?;
    let call = match procedure_dispatch_call_at_relative_site(&procedure, expected_site, request) {
        Ok(Some(call)) => call,
        Ok(None) | Err(_) => return None,
    };
    let outcome = oracle.resolve_call(&call, request).ok()?;
    Some(
        crate::analyzer::semantic::workspace_oracle::one_call_dispatch_answer_digest(
            &call, &outcome,
        ),
    )
}

fn procedure_dispatch_call_at_relative_site(
    procedure: &ProcedureHandle,
    expected_site: &crate::analyzer::read_ledger::CallSiteLocator,
    request: &mut SemanticRequest<'_>,
) -> Result<Option<CallSiteHandle>, ProcedureDispatchReadCallError> {
    if request.cancellation.is_cancelled() {
        return Err(ProcedureDispatchReadCallError::Cancelled);
    }
    let calls =
        crate::analyzer::semantic::workspace_oracle::source::source_ordered_calls(procedure);
    request.budget.charge_work(SemanticWork {
        call_sites: calls.len(),
        source_mappings: calls.len(),
        ..SemanticWork::default()
    });
    Ok(calls
        .get(expected_site.ordinal)
        .and_then(|call| procedure.call_site_handle(call.id)))
}

/// The engine's analysis epoch: every grammar and query epoch it could derive
/// a fact under.
///
/// The epoch of one language is the fingerprint of every engine input that
/// invalidates previously derived facts for it: the store salt, the live
/// grammar's ABI and node tables, and the bundled query files. It is one value
/// per language -- a language's dialects share it, because
/// [`crate::analyzer::store::epoch::epoch_for`] memoizes per language.
///
/// Folded over every language the grammar registry serves, not over the
/// languages one workspace happens to hold: this is the third non-source input
/// a unit key carries, beside the configuration fingerprint and the active
/// model set hash, and all three describe the engine that would answer rather
/// than the content it would answer about. A workspace that gains its first
/// file of a new language has changed its content, which its content
/// identities already say; it has not changed the engine.
///
/// A unit published by one engine and looked up by another must not verify.
/// This digest is what says so, because every persisted fact such a unit read
/// was derived under these epochs.
pub fn analysis_epoch_digest() -> StableDigest {
    analysis_epoch_digest_with_authority(crate::analyzer::languages::graph_authority_digest())
}

/// [`analysis_epoch_digest`] with the graph authority supplied.
///
/// The seam exists so a test can ask what the same grammars would produce
/// under a different routing, which is the only way to observe that the epoch
/// is sensitive to a flip without owning a second engine.
#[doc(hidden)]
pub fn analysis_epoch_digest_with_authority(graph_authority: StableDigest) -> StableDigest {
    let mut hasher = CanonicalHasher::new(ANALYSIS_EPOCH_DOMAIN);
    // `Language::ALL` is sorted by declaration and the fold is order-sensitive,
    // so the entry order is fixed by that constant rather than by any caller.
    for language in Language::ALL {
        // A language the registry serves no parser for -- `Language::None` --
        // derives no fact, so it has no epoch to fold.
        let Some(parser) = crate::analyzer::parser_language_for(language) else {
            continue;
        };
        hasher.field(
            language.config_label(),
            crate::analyzer::store::epoch::epoch_for(language, &parser).as_bytes(),
        );
    }
    // The fourth engine input beside the grammars, the configuration
    // fingerprint and the model set: which implementation answers each
    // language's reference, call and graph questions. A unit recorded against
    // the legacy Rust resolver read answers this engine no longer derives, and
    // without this field the two engines' epochs are equal.
    hasher.field("graph_authority", graph_authority.as_bytes());
    StableDigest::from_array(hasher.finish())
}

/// Domain for [`analysis_epoch_digest`].
// Native Kotlin points change persisted policy consumers while graph authority
// stays incumbent. Do not reuse policy units derived from old point answers.
const ANALYSIS_EPOCH_DOMAIN: &[u8] = b"bifrost-policy-unit:analysis-epoch:v3";

/// The non-source inputs of the head evaluation, as the caller holds them.
///
/// A read set records what the base saw of each of these; verification is
/// equality against what the head publishes. They are supplied rather than
/// read here because the caller is the only thing that knows which policy is
/// being verified and which model activation the run pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadInputs {
    /// The head's active model set hash, digested as the ledger digests it.
    pub models: StableDigest,
    /// The semantic hash of the policy being verified.
    pub policy_semantic_hash: StableDigest,
    /// The digest of that policy's source text.
    pub policy_source: StableDigest,
    /// The head analyzer's configuration fingerprint.
    pub configuration: StableDigest,
    /// The head's engine epoch digest.
    pub epoch: StableDigest,
}

/// Whether a recorded read set still holds on the head workspace.
///
/// `Changed` names the key that failed as well as the reason, because a reason
/// alone cannot be acted on: the whole point of recording reads at funnel
/// granularity is that a verdict says which input moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadVerdict {
    Unchanged,
    /// Boxed because the reason and the key together are two hundred bytes,
    /// and the answer this returns is `Unchanged` for every key of every unit
    /// that is reused -- which is the case the whole plan exists to make cheap.
    Changed(Box<ChangedRead>),
}

/// Which recorded read no longer holds, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedRead {
    pub reason: InvalidationReason,
    pub key: ReadKey,
}

impl ReadVerdict {
    pub const fn is_unchanged(&self) -> bool {
        matches!(self, Self::Unchanged)
    }

    /// The read that moved, when one did.
    pub fn changed(&self) -> Option<&ChangedRead> {
        match self {
            Self::Unchanged => None,
            Self::Changed(changed) => Some(changed),
        }
    }
}

/// How many source bytes one artifact-currency check may read.
///
/// The check exists to avoid materializing: it derives the file's current
/// artifact identity from its source. Bounding it would turn "I could not
/// afford to look" into "the artifact moved", which is a widening the caller
/// cannot tell from a real change, so it is deliberately unbounded and the
/// caller's own verification budget decides how many units to verify.
const ARTIFACT_CURRENCY_SOURCE_BYTES: usize = usize::MAX;

/// Whether every key in `keys` still denotes the same content on `head`.
///
/// The first key that moved wins: a unit is reused only when every one of its
/// reads holds, so the remaining keys cannot change the answer and paying for
/// them would be verification work with no verdict to show for it.
///
/// The artifact every reason names is the unit itself, identified by the
/// digest of the read set being verified. That identity is checkout-
/// independent because every read key is, so the same unit verified against
/// two head workspaces reports the same artifact.
pub fn verify_read_set(
    head: &WorkspaceAnalyzer,
    changed: &ChangedFacts,
    inputs: &HeadInputs,
    keys: &[ReadKey],
    limits: LookupReplayLimits,
    summaries: &dyn SummaryAnswers,
    memo: &mut LookupMemo,
) -> ReadVerdict {
    let unit = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(keys).digest(),
    );
    verify_read_set_for_artifact(unit, head, changed, inputs, keys, limits, summaries, memo)
}

/// [`verify_read_set`] for a derived product that already has its own exact
/// identity.
///
/// The supplied `artifact` is used only in the resulting retention or
/// invalidation evidence; read replay is otherwise identical. Policy units use
/// [`verify_read_set`] to preserve their historical read-set-derived identity,
/// while procedure summaries and other persisted products can name the cache
/// artifact their callers actually hold.
#[allow(clippy::too_many_arguments)]
pub fn verify_read_set_for_artifact(
    artifact: DerivedArtifactId,
    head: &WorkspaceAnalyzer,
    changed: &ChangedFacts,
    inputs: &HeadInputs,
    keys: &[ReadKey],
    limits: LookupReplayLimits,
    summaries: &dyn SummaryAnswers,
    memo: &mut LookupMemo,
) -> ReadVerdict {
    for key in keys {
        match verify_read_key(
            artifact, head, changed, inputs, key, limits, summaries, memo,
        ) {
            KeyVerdict::Unchanged => {}
            KeyVerdict::Changed(reason) | KeyVerdict::MissingEvidence(reason) => {
                return ReadVerdict::Changed(Box::new(ChangedRead {
                    reason,
                    key: key.clone(),
                }));
            }
        }
    }
    ReadVerdict::Unchanged
}

/// The result of checking one recorded input against the selected head.
#[derive(Debug)]
pub enum KeyVerdict {
    Unchanged,
    Changed(InvalidationReason),
    MissingEvidence(InvalidationReason),
}

/// Verify one recorded input. The engine's base-input check will call this
/// routine against its selected snapshot when that binding is available.
#[allow(clippy::too_many_arguments)]
pub fn verify_read_key(
    artifact: DerivedArtifactId,
    head: &WorkspaceAnalyzer,
    changed: &ChangedFacts,
    inputs: &HeadInputs,
    key: &ReadKey,
    limits: LookupReplayLimits,
    summaries: &dyn SummaryAnswers,
    memo: &mut LookupMemo,
) -> KeyVerdict {
    let reason = match key {
        ReadKey::File {
            language,
            rel_path,
            blob,
            parse_variant,
        } => match memo.head_blob(head, changed, *language, rel_path) {
            Ok(after) => {
                let file = ProjectFile::new(
                    head.analyzer().project().root().to_path_buf(),
                    Path::new(rel_path.as_ref()),
                );
                if after == Some(*blob)
                    && brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
                        head.analyzer().selected_parse_variant(&file)
                    }) != Some(*parse_variant)
                {
                    return KeyVerdict::Changed(InvalidationReason::DependencyChanged {
                        artifact,
                        dependency: key.canonical_digest(),
                    });
                }
                (after != Some(*blob)).then(|| InvalidationReason::InputContentChanged {
                    artifact,
                    before: blob_identity(Some(*blob)),
                    after: blob_identity(after),
                })
            }
            Err(_) => Some(InvalidationReason::ContentIdentityEvidenceMissing { artifact }),
        },
        // Absence must include non-source inputs, whose paths never enter
        // the analyzed map (for example package.json and Gemfile).
        ReadKey::PathAbsent { language, rel_path } => {
            match memo.head_blob(head, changed, *language, rel_path) {
                Ok(after) => after.map(|blob| InvalidationReason::InputContentChanged {
                    artifact,
                    before: blob_identity(None),
                    after: blob_identity(Some(blob)),
                }),
                Err(_) => Some(InvalidationReason::ContentIdentityEvidenceMissing { artifact }),
            }
        }
        ReadKey::Index { family, key } => {
            if !changed.is_complete() {
                // A changed-key set that could not be completed is smaller
                // than the truth, and a smaller set would let a changed
                // name pass. The absence of evidence is not evidence.
                Some(InvalidationReason::ContentIdentityEvidenceMissing { artifact })
            } else {
                changed
                    .contains(*family, key)
                    .then_some(InvalidationReason::DependencyChanged {
                        artifact,
                        dependency: ReadKey::index(*family, key).canonical_digest(),
                    })
            }
        }
        // A procedure-summary read is the one lookup whose absence is not
        // evidence of a change. A head that has not solved anything
        // retains no summary at all, so replaying every recorded summary
        // read against a cold repository would answer absence for all of
        // them and recompute every unit that ever crossed the summary
        // funnel -- which is every typestate root. What carries the
        // dependency instead is the closure the recorder names beside the
        // summary: one `Artifact` key per member, verified by fingerprint
        // against what the head would derive from those files now. So an
        // absent or unanswerable summary lookup holds, and only a head
        // that does retain a summary under the recorded identity, with
        // different content, reports a change.
        ReadKey::Lookup {
            kind: LookupKind::ExternalSelection,
            question,
            digest,
        } => {
            let answer = memo.external_selection_answer(
                &head.analyzer().external_selection_authorities(),
                question,
                &head
                    .analyzer()
                    .active_query_cancellation()
                    .unwrap_or_default(),
            );
            (answer != Some(*digest)).then(|| InvalidationReason::DependencyChanged {
                artifact,
                dependency: key.canonical_digest(),
            })
        }
        ReadKey::Lookup {
            kind: LookupKind::ProcedureSummary,
            question,
            digest,
        } => match memo.answer(
            head,
            LookupKind::ProcedureSummary,
            question,
            limits,
            summaries,
        ) {
            None => None,
            Some(replayed) if replayed == crate::analyzer::read_ledger::absent_summary_digest() => {
                None
            }
            Some(replayed) if replayed != *digest => {
                Some(InvalidationReason::DependencyFingerprintChanged {
                    artifact,
                    before: *digest,
                    after: replayed,
                })
            }
            Some(_) => None,
        },
        ReadKey::Lookup {
            kind,
            question,
            digest,
        } => match kind {
            LookupKind::Derivation(_) => {
                let answer = if let Some(Some(answer)) =
                    memo.answers.get(&(*kind, question.clone()))
                {
                    Some(*answer)
                } else {
                    let started = Instant::now();
                    let answer = match (kind, question) {
                        (LookupKind::Derivation(kind), LookupQuestion::Derivation(question)) => {
                            match head.replay_derivation(*kind, question) {
                                crate::analyzer::derivation_host::ReplayResult::Identity(
                                    identity,
                                ) => Some(identity.0),
                                crate::analyzer::derivation_host::ReplayResult::Missing(_) => None,
                            }
                        }
                        _ => None,
                    };
                    memo.replay_elapsed += started.elapsed();
                    if let Some(identity) = answer {
                        memo.answers
                            .insert((*kind, question.clone()), Some(identity));
                    }
                    answer
                };
                match answer {
                    Some(after) if after != *digest => {
                        Some(InvalidationReason::DependencyFingerprintChanged {
                            artifact,
                            before: *digest,
                            after,
                        })
                    }
                    Some(_) => None,
                    None => Some(InvalidationReason::ReverseDependencyEvidenceMissing { artifact }),
                }
            }
            LookupKind::StoredSemanticIrPublication
            | LookupKind::RustCopyAbsence
            | LookupKind::RustBoundTraitImplInventory
            | LookupKind::RustTraitsImplementedByInventory
            | LookupKind::RustAliasBlobInventory
            | LookupKind::RustMacroExpansionInventory
            | LookupKind::RustUnresolvedTraitImplInventory
            | LookupKind::RustModuleImportCandidateInventory
            | LookupKind::RustIdentifierOccurrenceInventory
            | LookupKind::StructuralNameInventory
            | LookupKind::StructuralRoleNameInventory
            | LookupKind::StructuralRecoveredInventory
            | LookupKind::ResolvedName
            | LookupKind::CertifiedDefinitionAnswer
            | LookupKind::Definitions
            | LookupKind::IdentifierCandidates
            | LookupKind::ShortNameCandidates
            | LookupKind::DeclarationFacts
            | LookupKind::DeclarationCandidates
            | LookupKind::SignatureMetadata
            | LookupKind::Callers
            | LookupKind::Callees
            | LookupKind::Usages
            | LookupKind::ReferenceCandidates
            | LookupKind::Descendants
            | LookupKind::Importers
            | LookupKind::Dispatch
            | LookupKind::ProcedureDispatch
            | LookupKind::WorkspaceFact => {
                match memo.answer(head, *kind, question, limits, summaries) {
                    None => Some(InvalidationReason::ReverseDependencyEvidenceMissing { artifact }),
                    Some(replayed) if replayed != *digest => {
                        Some(InvalidationReason::DependencyFingerprintChanged {
                            artifact,
                            before: *digest,
                            after: replayed,
                        })
                    }
                    Some(_) => None,
                }
            }
            LookupKind::ProcedureSummary | LookupKind::ExternalSelection => {
                unreachable!("handled by preceding arm")
            }
        },
        ReadKey::Artifact { id, rel_path } => {
            verify_artifact(head, artifact, *id, rel_path.as_deref())
        }
        ReadKey::Scope {
            languages,
            identity,
        } => match head
            .analyzer()
            .workspace_content_identities()
            .and_then(|identities| identities.scope(|language| languages.contains(&language)))
        {
            None => Some(InvalidationReason::ContentIdentityEvidenceMissing { artifact }),
            Some(head_identity) if head_identity != *identity => {
                Some(InvalidationReason::DependencyChanged {
                    artifact,
                    dependency: key.canonical_digest(),
                })
            }
            Some(_) => None,
        },
        ReadKey::Models(models) => {
            (*models != inputs.models).then_some(InvalidationReason::DependencyFingerprintChanged {
                artifact,
                before: *models,
                after: inputs.models,
            })
        }
        ReadKey::Policy {
            semantic_hash,
            source,
        } => (*semantic_hash != inputs.policy_semantic_hash || *source != inputs.policy_source)
            .then(|| InvalidationReason::DependencyFingerprintChanged {
                artifact,
                before: key.canonical_digest(),
                after: ReadKey::Policy {
                    semantic_hash: inputs.policy_semantic_hash,
                    source: inputs.policy_source,
                }
                .canonical_digest(),
            }),
        ReadKey::Configuration(configuration) => (*configuration != inputs.configuration)
            .then_some(InvalidationReason::DependencyFingerprintChanged {
                artifact,
                before: *configuration,
                after: inputs.configuration,
            }),
        ReadKey::Epoch(epoch) => {
            (*epoch != inputs.epoch).then_some(InvalidationReason::EpochChanged {
                artifact,
                before: *epoch,
                after: inputs.epoch,
            })
        }
    };
    match reason {
        None => KeyVerdict::Unchanged,
        Some(reason @ InvalidationReason::ContentIdentityEvidenceMissing { .. })
        | Some(reason @ InvalidationReason::ReverseDependencyEvidenceMissing { .. }) => {
            KeyVerdict::MissingEvidence(reason)
        }
        Some(reason) => KeyVerdict::Changed(reason),
    }
}

/// Whether the head still derives the artifact a unit consumed.
///
/// Only a semantic artifact is recorded today, and only with the file it is
/// derived from; the head's identity for that file is derived from its source
/// without materializing anything. An artifact key that names no file, or
/// names a family with no recomputation, cannot be checked at all -- that is a
/// missing proof, not a proof of sameness.
fn verify_artifact(
    head: &WorkspaceAnalyzer,
    unit: DerivedArtifactId,
    recorded: DerivedArtifactId,
    rel_path: Option<&str>,
) -> Option<InvalidationReason> {
    if recorded.kind() != DerivedArtifactKind::SemanticArtifact {
        return Some(InvalidationReason::ReverseDependencyEvidenceMissing { artifact: unit });
    }
    let Some(rel_path) = rel_path else {
        return Some(InvalidationReason::ReverseDependencyEvidenceMissing { artifact: unit });
    };
    let Some(file) = analyzed_file(head.analyzer(), rel_path) else {
        return Some(InvalidationReason::ReverseDependencyEvidenceMissing { artifact: unit });
    };
    let current = head
        .current_semantic_artifact_fingerprint(&file, ARTIFACT_CURRENCY_SOURCE_BYTES)
        .ok()
        .flatten();
    match current {
        None => Some(InvalidationReason::ReverseDependencyEvidenceMissing { artifact: unit }),
        Some(fingerprint) if fingerprint != recorded.fingerprint() => {
            Some(InvalidationReason::DependencyArtifactChanged {
                artifact: unit,
                dependency: recorded,
                recomputed: DerivedArtifactId::semantic_artifact(fingerprint),
            })
        }
        Some(_) => None,
    }
}

/// Ask the project for a path the analyzed source map does not cover. Project
/// snapshots retain raw-byte blob identity and honor selected configuration
/// revisions and unsaved overlays.
fn head_path_blob(
    head: &WorkspaceAnalyzer,
    language: Language,
    rel_path: &str,
) -> std::io::Result<Option<Oid>> {
    let analyzer = match head {
        WorkspaceAnalyzer::Multi(multi) => multi
            .delegates()
            .get(&language)
            .map_or_else(|| head.analyzer(), |delegate| delegate.analyzer()),
        WorkspaceAnalyzer::Empty(_) => head.analyzer(),
    };
    let project = analyzer.project();
    let Some(file) = project.file_by_rel_path(Path::new(rel_path)) else {
        return Ok(None);
    };
    project
        .read_file_snapshot(&file)
        .map(|source| Some(source.oid()))
}

/// A blob identity as a `StableDigest`, so an absent blob and a present one
/// are different values a reason can print.
fn blob_identity(blob: Option<Oid>) -> StableDigest {
    match blob {
        Some(blob) => StableDigest::sha256(blob.as_bytes()),
        None => StableDigest::sha256(b"bifrost-read-ledger:absent-blob:v1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::read_ledger::read_set_digest;
    use crate::analyzer::store::AnalyzerStore;
    use crate::analyzer::store::policy_units::{
        PolicyUnitPartitionRow, PolicyUnitRow, PolicyUnitRowKey,
    };
    use crate::analyzer::workspace::EmptyAnalyzer;
    use crate::analyzer::{FilesystemProject, Project};
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    type IndexKeys = Vec<(IndexFamily, Box<[u8]>)>;

    #[derive(Clone)]
    struct FactIndex {
        language: Language,
        normalized: Vec<CodeUnit>,
        file: ProjectFile,
        blob: Oid,
        rows: Vec<(Oid, IndexKeys)>,
    }
    impl WorkspaceFactIndex for FactIndex {
        fn fact_index_language(&self) -> Language {
            self.language
        }
        fn identity_inputs_digest(&self) -> Option<StableDigest> {
            Some(StableDigest::sha256(b"fake identity inputs"))
        }
        fn declaration_facts_digest(&self, _: &CodeUnit) -> StableDigest {
            unimplemented!()
        }
        fn signature_metadata_digest(&self, _: &CodeUnit) -> StableDigest {
            unimplemented!()
        }
        fn definition_answer_digest(&self, _: &str) -> StableDigest {
            unimplemented!()
        }
        fn normalized_tail_candidates(&self, key: &str) -> Option<Vec<CodeUnit>> {
            Some(
                self.normalized
                    .iter()
                    .filter(|unit| unit.fq_name() == key)
                    .cloned()
                    .collect(),
            )
        }
        fn identifier_candidate_answer_digest(&self, _: &str) -> StableDigest {
            unimplemented!()
        }
        fn short_name_candidate_answer_digest(&self, _: &str) -> StableDigest {
            unimplemented!()
        }
        fn analyzed_blobs(&self) -> Option<Vec<(ProjectFile, Oid)>> {
            Some(vec![(self.file.clone(), self.blob)])
        }
        fn is_selected_configuration_input(&self, path: &Path) -> bool {
            path == Path::new("pyproject.toml")
        }
        fn selected_configuration_input_blobs(&self) -> Option<Vec<(ProjectFile, Oid)>> {
            Some(
                if self.is_selected_configuration_input(self.file.rel_path()) {
                    vec![(self.file.clone(), self.blob)]
                } else {
                    Vec::new()
                },
            )
        }
        fn refused_source_blobs(
            &self,
        ) -> Result<Vec<(ProjectFile, Oid)>, crate::analyzer::store::StoreError> {
            Ok(Vec::new())
        }
        fn blob_index_keys(
            &self,
            _: &ProjectFile,
            blob: Oid,
        ) -> Option<Vec<crate::analyzer::store::IndexEntryDigest>> {
            self.rows
                .iter()
                .find(|(id, _)| *id == blob)
                .map(|(_, keys)| {
                    keys.iter()
                        .map(|(family, key)| (*family, key.clone(), StableDigest::sha256(key)))
                        .collect()
                })
        }
        fn stored_blob_index_keys(
            &self,
            file: &ProjectFile,
            blob: Oid,
            _: &str,
        ) -> Option<Vec<crate::analyzer::store::IndexEntryDigest>> {
            self.blob_index_keys(file, blob)
        }
    }
    fn fixture_index(root: &Path, source: &str) -> FactIndex {
        let blob = |text: &str| Oid::hash_object(git2::ObjectType::Blob, text.as_bytes()).unwrap();
        let file = ProjectFile::new(root.to_path_buf(), "app.py");
        file.write(source).unwrap();
        FactIndex {
            language: Language::Python,
            normalized: Vec::new(),
            file,
            blob: blob(source),
            // An independent, handwritten fact-store oracle. No parsing or
            // fact production is under test at this replay boundary.
            rows: vec![
                (
                    blob("def before():\n    pass\n"),
                    vec![(
                        IndexFamily::DefinitionExact,
                        Box::from(b"before".as_slice()),
                    )],
                ),
                (
                    blob("def after():\n    pass\n"),
                    vec![(IndexFamily::DefinitionExact, Box::from(b"after".as_slice()))],
                ),
            ],
        }
    }
    fn workspace(root: &Path, index: Option<FactIndex>) -> WorkspaceAnalyzer {
        use crate::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
        let analyzer = crate::analyzer::packs_document::tests::CatalogWorkspace {
            project: std::sync::Arc::new(crate::TestProject::new(root, Language::Python)),
            language: Language::Python,
            index: index
                .map(|index| std::sync::Arc::new(index) as std::sync::Arc<dyn WorkspaceFactIndex>),
            definitions: Vec::new(),
            complete_symbol_index: true,
        };
        WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(
            std::collections::BTreeMap::from([(Language::Python, AnalyzerDelegate::new(analyzer))]),
        )))
    }
    fn workspace_fixture(source: &str) -> (tempfile::TempDir, WorkspaceAnalyzer) {
        let root = tempfile::tempdir().unwrap();
        let index = fixture_index(root.path(), source);
        let head = workspace(root.path(), Some(index));
        (root, head)
    }

    #[test]
    fn claimed_configuration_differences_keep_the_enumerated_keys_complete() {
        let (root, head) = workspace_fixture("def before():\n    pass\n");
        let mut index = fixture_index(root.path(), "def before():\n    pass\n");
        index.file = ProjectFile::new(root.path(), "pyproject.toml");
        let indexes = [(Language::Python, &index as &dyn WorkspaceFactIndex)]
            .into_iter()
            .collect::<HashMap<_, _>>();
        let path = Box::<str>::from("pyproject.toml");
        let base_blob = Oid::hash_object(git2::ObjectType::Blob, b"old configuration").unwrap();
        let base = vec![(path.clone(), base_blob)];
        let base_map = [(path.clone(), base_blob)]
            .into_iter()
            .collect::<HashMap<_, _>>();
        // Only the input's own language enumerates its keys: an analysis of
        // the same path by another language leaves this input unenumerated.
        for (owner, claimed) in [
            (None, false),
            (Some(Language::TypeScript), false),
            (Some(Language::Python), true),
        ] {
            let analyzed = owner
                .map(|owner| {
                    (
                        owner,
                        [(path.clone(), (index.file.clone(), index.blob))]
                            .into_iter()
                            .collect::<HashMap<_, _>>(),
                    )
                })
                .into_iter()
                .collect::<HashMap<_, _>>();
            let mut facts = ChangedFacts::between(&head, &head);
            facts.delta.record_input_differences(
                &indexes,
                &analyzed,
                head.analyzer().project(),
                &base,
                &base_map,
            );
            assert_eq!(facts.is_complete(), claimed);
            assert!(
                facts
                    .changed_paths()
                    .any(|(_, path)| path == "pyproject.toml")
            );
            // Repeated input observations are a set, including unenumerated paths.
            facts.delta.record_input_differences(
                &indexes,
                &analyzed,
                head.analyzer().project(),
                &base,
                &base_map,
            );
            assert_eq!(facts.delta.unenumerated.len(), usize::from(!claimed));
        }
    }

    fn inputs() -> HeadInputs {
        let digest = StableDigest::sha256(b"test non-source inputs");
        HeadInputs {
            models: digest,
            policy_semantic_hash: digest,
            policy_source: digest,
            configuration: digest,
            epoch: digest,
        }
    }

    #[test]
    fn certified_definition_questions_refuse_changed_normalization_and_delegate_sets() {
        let (_root, head) = workspace_fixture("def before():\n    pass\n");
        let scope = AnalyzerQueryScope::new(head.analyzer());
        let _token = scope.token();
        for kind in [
            CertifiedDefinitionKind::Exact,
            CertifiedDefinitionKind::NormalizedTail,
            CertifiedDefinitionKind::Identifier,
        ] {
            let question = LookupQuestion::CertifiedDefinition {
                kind,
                name: "missing".into(),
                delegates: vec![Language::Python],
                normalization_version: (kind == CertifiedDefinitionKind::NormalizedTail)
                    .then_some(DEFINITION_NORMALIZED_TAIL_VERSION),
            };
            assert!(
                certified_definition_answer_digest(head.analyzer(), &question).is_some(),
                "{kind:?}"
            );
            let LookupQuestion::CertifiedDefinition { delegates, .. } = &question else {
                unreachable!()
            };
            assert_eq!(delegates.as_slice(), &[Language::Python]);
            let mut changed_delegates = question.clone();
            if let LookupQuestion::CertifiedDefinition { delegates, .. } = &mut changed_delegates {
                delegates.push(Language::Rust);
            }
            assert!(
                certified_definition_answer_digest(head.analyzer(), &changed_delegates).is_none()
            );
            if kind == CertifiedDefinitionKind::NormalizedTail {
                let mut stale = question;
                if let LookupQuestion::CertifiedDefinition {
                    normalization_version,
                    ..
                } = &mut stale
                {
                    *normalization_version = Some(DEFINITION_NORMALIZED_TAIL_VERSION + 1);
                }
                assert!(certified_definition_answer_digest(head.analyzer(), &stale).is_none());
            }
        }
    }

    #[test]
    fn certified_exact_and_identifier_answers_detect_new_definition_in_another_file() {
        use crate::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
        let root = tempfile::tempdir().unwrap();
        let project = std::sync::Arc::new(crate::TestProject::new(root.path(), Language::Python));
        let build = |definitions: Vec<CodeUnit>| {
            let delegate = crate::analyzer::packs_document::tests::CatalogWorkspace {
                project: project.clone(),
                language: Language::Python,
                index: Some(std::sync::Arc::new(fixture_index(root.path(), ""))),
                definitions,
                complete_symbol_index: true,
            };
            WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(
                std::collections::BTreeMap::from([(
                    Language::Python,
                    AnalyzerDelegate::new(delegate),
                )]),
            )))
        };
        let base = build(Vec::new());
        let added = CodeUnit::new(
            ProjectFile::new(root.path(), "other.py"),
            crate::analyzer::CodeUnitType::Function,
            "",
            "target",
        );
        let head = build(vec![added]);
        let normalized_added = CodeUnit::new(
            ProjectFile::new(root.path(), "normalized.py"),
            crate::analyzer::CodeUnitType::Function,
            "",
            "target",
        );
        let normalized_head = workspace(
            root.path(),
            Some(FactIndex {
                normalized: vec![normalized_added],
                ..fixture_index(root.path(), "")
            }),
        );
        let normalized_question = LookupQuestion::CertifiedDefinition {
            kind: CertifiedDefinitionKind::NormalizedTail,
            name: "target".into(),
            delegates: vec![Language::Python],
            normalization_version: Some(DEFINITION_NORMALIZED_TAIL_VERSION),
        };
        assert_ne!(
            certified_definition_answer_digest(base.analyzer(), &normalized_question),
            certified_definition_answer_digest(normalized_head.analyzer(), &normalized_question),
            "a normalized-tail negative answer survived an added definition"
        );
        let normalized_key = ReadKey::lookup(
            LookupKind::CertifiedDefinitionAnswer,
            normalized_question,
            certified_definition_answer_digest(
                base.analyzer(),
                &LookupQuestion::certified_definition(
                    CertifiedDefinitionKind::NormalizedTail,
                    "target",
                    [Language::Python],
                ),
            )
            .unwrap(),
        );
        assert!(
            verify_read_set(
                &base,
                &ChangedFacts::between(&base, &base),
                &inputs(),
                std::slice::from_ref(&normalized_key),
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
            .is_unchanged()
        );
        assert!(
            !verify_read_set(
                &normalized_head,
                &ChangedFacts::between(&base, &normalized_head),
                &inputs(),
                &[normalized_key],
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
            .is_unchanged()
        );
        let foreign = crate::analyzer::packs_document::tests::CatalogWorkspace {
            project: project.clone(),
            language: Language::Rust,
            index: Some(std::sync::Arc::new(FactIndex {
                language: Language::Rust,
                ..fixture_index(root.path(), "")
            })),
            complete_symbol_index: true,
            definitions: vec![CodeUnit::new(
                ProjectFile::new(root.path(), "foreign.rs"),
                crate::analyzer::CodeUnitType::Function,
                "",
                "target",
            )],
        };
        let mut foreign_empty = foreign.clone();
        foreign_empty.definitions.clear();
        let cross_base = WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(
            std::collections::BTreeMap::from([
                (
                    Language::Python,
                    AnalyzerDelegate::new(
                        crate::analyzer::packs_document::tests::CatalogWorkspace {
                            project: project.clone(),
                            language: Language::Python,
                            index: Some(std::sync::Arc::new(fixture_index(root.path(), ""))),
                            definitions: Vec::new(),
                            complete_symbol_index: true,
                        },
                    ),
                ),
                (Language::Rust, AnalyzerDelegate::new(foreign_empty)),
            ]),
        )));
        let cross_language = WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(
            std::collections::BTreeMap::from([
                (
                    Language::Python,
                    AnalyzerDelegate::new(
                        crate::analyzer::packs_document::tests::CatalogWorkspace {
                            project: project.clone(),
                            language: Language::Python,
                            index: Some(std::sync::Arc::new(fixture_index(root.path(), ""))),
                            definitions: Vec::new(),
                            complete_symbol_index: true,
                        },
                    ),
                ),
                (Language::Rust, AnalyzerDelegate::new(foreign)),
            ]),
        )));
        let cross_normalized = WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(
            std::collections::BTreeMap::from([
                (
                    Language::Python,
                    AnalyzerDelegate::new(
                        crate::analyzer::packs_document::tests::CatalogWorkspace {
                            project: project.clone(),
                            language: Language::Python,
                            index: Some(std::sync::Arc::new(fixture_index(root.path(), ""))),
                            definitions: Vec::new(),
                            complete_symbol_index: true,
                        },
                    ),
                ),
                (
                    Language::Rust,
                    AnalyzerDelegate::new(
                        crate::analyzer::packs_document::tests::CatalogWorkspace {
                            project: project.clone(),
                            language: Language::Rust,
                            index: Some(std::sync::Arc::new(FactIndex {
                                language: Language::Rust,
                                normalized: vec![CodeUnit::new(
                                    ProjectFile::new(root.path(), "foreign_normalized.rs"),
                                    crate::analyzer::CodeUnitType::Function,
                                    "",
                                    "target",
                                )],
                                ..fixture_index(root.path(), "")
                            })),
                            definitions: Vec::new(),
                            complete_symbol_index: true,
                        },
                    ),
                ),
            ]),
        )));
        let cross_normalized_question = LookupQuestion::certified_definition(
            CertifiedDefinitionKind::NormalizedTail,
            "target",
            [Language::Python, Language::Rust],
        );
        assert_ne!(
            certified_definition_answer_digest(cross_base.analyzer(), &cross_normalized_question),
            certified_definition_answer_digest(
                cross_normalized.analyzer(),
                &cross_normalized_question
            ),
            "normalized-tail missed an added definition in an existing foreign delegate"
        );
        for kind in [
            CertifiedDefinitionKind::Exact,
            CertifiedDefinitionKind::Identifier,
        ] {
            let question = LookupQuestion::CertifiedDefinition {
                kind,
                name: "target".into(),
                delegates: vec![Language::Python],
                normalization_version: None,
            };
            let digest = certified_definition_answer_digest(base.analyzer(), &question).unwrap();
            let changed = certified_definition_answer_digest(head.analyzer(), &question).unwrap();
            assert_ne!(
                digest, changed,
                "{kind:?} negative answer survived an added definition"
            );
            let key = ReadKey::lookup(
                LookupKind::CertifiedDefinitionAnswer,
                question.clone(),
                digest,
            );
            assert!(
                verify_read_set(
                    &base,
                    &ChangedFacts::between(&base, &base),
                    &inputs(),
                    std::slice::from_ref(&key),
                    LookupReplayLimits::default(),
                    &NoSummaryAnswers,
                    &mut LookupMemo::new(),
                )
                .is_unchanged(),
                "{kind:?} unchanged certified read did not verify"
            );
            let verdict = verify_read_set(
                &head,
                &ChangedFacts::between(&base, &head),
                &inputs(),
                &[key],
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            );
            assert!(
                !verdict.is_unchanged(),
                "{kind:?} certified read was reused after an added definition"
            );
            assert!(
                certified_definition_answer_digest(cross_language.analyzer(), &question).is_none(),
                "{kind:?} must refuse a newly added delegate"
            );
            let cross_question = LookupQuestion::certified_definition(
                kind,
                "target",
                [Language::Python, Language::Rust],
            );
            assert_ne!(
                certified_definition_answer_digest(cross_base.analyzer(), &cross_question),
                certified_definition_answer_digest(cross_language.analyzer(), &cross_question),
                "{kind:?} missed an added definition in an existing foreign delegate"
            );
        }
    }

    #[test]
    #[hardwon("#8180: index verification invalidated unchanged entries of changed files")]
    fn changed_index_entries_compare_both_complete_sides() {
        let (_root, head) = workspace_fixture("def before():\n    pass\n");
        let entry = |name: &str, bytes: &[u8]| {
            (
                IndexFamily::DefinitionExact,
                Box::<[u8]>::from(name.as_bytes()),
                StableDigest::sha256(bytes),
            )
        };
        for (base, current, expected, complete) in [
            (
                Some(Some(vec![entry("same", b"row")])),
                Some(Some(vec![entry("same", b"row")])),
                vec![],
                true,
            ),
            (
                Some(Some(vec![entry("same", b"old")])),
                Some(Some(vec![entry("same", b"new")])),
                vec!["same"],
                true,
            ),
            (
                Some(Some(vec![entry("removed", b"row")])),
                Some(Some(vec![entry("added", b"row")])),
                vec!["removed", "added"],
                true,
            ),
            (
                None,
                Some(Some(vec![entry("added", b"row")])),
                vec!["added"],
                true,
            ),
            (
                Some(Some(vec![entry("removed", b"row")])),
                None,
                vec!["removed"],
                true,
            ),
            (
                Some(None),
                Some(Some(vec![entry("same", b"row")])),
                vec!["same"],
                false,
            ),
        ] {
            let mut changed = ChangedFacts::between(&head, &head);
            changed
                .delta
                .record_index_difference(Language::Python, "app.py", base, current);
            assert_eq!(
                changed.delta.keys,
                expected
                    .into_iter()
                    .map(|name| (IndexFamily::DefinitionExact, Box::from(name.as_bytes())))
                    .collect()
            );
            assert_eq!(changed.is_complete(), complete);
            assert_eq!(changed.changed_path_count(), 1);
        }
    }

    #[test]
    fn external_selection_replay_requires_certified_complete_current_answers() {
        use brokk_bifrost_core::analyzer::external_selection::{
            ExternalSelectionAuthority, ExternalSelectionQuestion, ExternalSelectionQuestionKind,
            SelectionRefused, SelectionRetry, VerifiedSelection,
        };
        use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Authority {
            complete: bool,
            certified: bool,
            stale: bool,
            calls: AtomicUsize,
        }
        impl ExternalSelectionAuthority for Authority {
            fn questions(&self) -> Vec<ExternalSelectionQuestion> {
                vec![ExternalSelectionQuestion {
                    kind: ExternalSelectionQuestionKind::Dependencies,
                    digest: [3; 32],
                    uncertified: false,
                }]
            }
            fn answer(
                &self,
                _: &OuterRequest,
                _: &ExternalSelectionQuestion,
                _: &SelectionRetry,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.stale {
                    return Err(SelectionRefused::Stale);
                }
                Ok(Arc::new(VerifiedSelection {
                    question_digest: [3; 32],
                    answer_digest: [4; 32],
                    view_stamp: None,
                    complete: self.complete,
                    certified: self.certified,
                    records: Arc::new(()),
                }))
            }
        }
        let question = LookupQuestion::ExternalSelection {
            question_digest: [3; 32],
        };
        for (complete, certified, stale) in [
            (true, true, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            let authority = Authority {
                complete,
                certified,
                stale,
                calls: AtomicUsize::new(0),
            };
            let mut memo = LookupMemo::new();
            let expected =
                (complete && certified && !stale).then(|| StableDigest::from_array([4; 32]));
            for _ in 0..2 {
                assert_eq!(
                    memo.external_selection_answer(
                        &[&authority],
                        &question,
                        &CancellationToken::default()
                    ),
                    expected
                );
            }
            assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
            assert_ne!(expected, Some(StableDigest::from_array([5; 32])));
        }
        assert_eq!(
            LookupMemo::new().external_selection_answer(
                &[],
                &question,
                &CancellationToken::default()
            ),
            None
        );
    }

    #[test]
    fn a_missing_external_selection_question_verifies_as_changed() {
        let (_root, head) = workspace_fixture("def before():\n    pass\n");
        let key = ReadKey::lookup(
            LookupKind::ExternalSelection,
            LookupQuestion::ExternalSelection {
                question_digest: [3; 32],
            },
            StableDigest::sha256(b"answer"),
        );
        let artifact = DerivedArtifactId::semantic_artifact(StableDigest::sha256(b"artifact"));
        let verdict = verify_read_set_for_artifact(
            artifact,
            &head,
            &ChangedFacts::between(&head, &head),
            &inputs(),
            std::slice::from_ref(&key),
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        );
        let changed = verdict
            .changed()
            .expect("an unverifiable external selection must not verify as unchanged");
        assert_eq!(changed.key, key);
        assert_eq!(
            changed.reason,
            InvalidationReason::DependencyChanged {
                artifact,
                dependency: key.canonical_digest(),
            }
        );
    }

    #[test]
    fn summary_read_replay_is_independent_of_unit_order_and_multiplicity() {
        struct Answers(StableDigest);
        impl SummaryAnswers for Answers {
            fn summary_content(&self, _identity: StableDigest) -> Option<StableDigest> {
                Some(self.0)
            }
        }
        let (_base_root, base) = workspace_fixture("def target():\n    return 1\n");
        let recorded = StableDigest::sha256(b"return 1");
        for (source, current) in [
            ("def target():\n    return 1\n", recorded),
            (
                "def target():\n    return 2\n",
                StableDigest::sha256(b"return 2"),
            ),
        ] {
            let (_root, head) = workspace_fixture(source);
            let changed = ChangedFacts::between(&base, &head);
            let answers = Answers(current);
            for order in [[0, 0, 1], [0, 1, 0], [1, 0, 0]] {
                let mut shared = LookupMemo::new();
                for identity in order {
                    let keys = [ReadKey::Lookup {
                        kind: LookupKind::ProcedureSummary,
                        question: LookupQuestion::Summary {
                            identity: StableDigest::sha256([identity]),
                        },
                        digest: recorded,
                    }];
                    let replay = |memo: &mut LookupMemo| {
                        verify_read_set(
                            &head,
                            &changed,
                            &inputs(),
                            &keys,
                            LookupReplayLimits::default(),
                            &answers,
                            memo,
                        )
                    };
                    let independent = replay(&mut LookupMemo::new());
                    assert_eq!(independent.is_unchanged(), current == recorded);
                    assert_eq!(replay(&mut shared), independent, "unit order {order:?}");
                }
            }
        }
    }

    #[test]
    fn index_replay_requires_both_evidence_channels_for_changed_and_unchanged_heads() {
        let (base_root, base) = workspace_fixture("def before():\n    pass\n");
        let base_blobs = fact_indexes_by_language(&base)[&Language::Python]
            .analyzed_blobs()
            .expect("the fixture listing reads")
            .into_iter()
            .map(|(file, blob)| {
                (
                    Box::<str>::from(crate::path_utils::rel_path_string(&file)),
                    blob,
                )
            })
            .collect::<Vec<_>>();
        for (source, unchanged) in [
            ("def before():\n    pass\n", true),
            ("def after():\n    pass\n", false),
        ] {
            let (root, head) = workspace_fixture(source);
            let keys = [ReadKey::index(IndexFamily::DefinitionExact, b"before")];
            let replay = |facts: &ChangedFacts| {
                verify_read_set(
                    &head,
                    facts,
                    &inputs(),
                    &keys,
                    LookupReplayLimits::default(),
                    &NoSummaryAnswers,
                    &mut LookupMemo::new(),
                )
            };
            let facts = ChangedFacts::between(&base, &head);
            assert_eq!(replay(&facts).is_unchanged(), unchanged);
            let committed = ChangedFacts::from_committed_tree(&head, &base_blobs, &|_| {
                Some(std::fs::read_to_string(base_root.path().join("app.py")).unwrap())
            });
            assert_eq!(replay(&committed), replay(&facts));
            // A negative probe cannot be licensed by either partial channel,
            // even when every available store row omits the requested name.
            let negative = [ReadKey::index(
                IndexFamily::DefinitionExact,
                b"not_yet_defined",
            )];
            let missing_language = workspace(root.path(), None);
            let mut missing_blob_index = fixture_index(root.path(), source);
            missing_blob_index.rows.clear();
            let missing_blob = workspace(root.path(), Some(missing_blob_index));
            for (incomplete_head, expected) in
                [(&missing_language, false), (&missing_blob, unchanged)]
            {
                let facts = ChangedFacts::between(&base, incomplete_head);
                let verdict = verify_read_set(
                    incomplete_head,
                    &facts,
                    &inputs(),
                    &negative,
                    LookupReplayLimits::default(),
                    &NoSummaryAnswers,
                    &mut LookupMemo::new(),
                );
                // Byte-identical blobs need no enumeration. A missing index
                // cannot prove even the file inventory, so it still widens.
                assert_eq!(verdict.is_unchanged(), expected, "{verdict:?}; {facts:?}");
                if !expected {
                    assert!(
                        matches!(
                            verdict.changed().map(|read| &read.reason),
                            Some(InvalidationReason::ContentIdentityEvidenceMissing { .. })
                        ),
                        "{verdict:?}"
                    );
                }
            }
        }
    }

    #[test]
    #[hardwon("#2445: non-source file reads always invalidated and absent paths missed additions")]
    fn persisted_non_source_reads_verify_content_and_absence_on_another_root() {
        let base_root = tempfile::tempdir().unwrap();
        let head_root = tempfile::tempdir().unwrap();
        let relative = "config/pyproject.toml";
        for root in [base_root.path(), head_root.path()] {
            std::fs::create_dir(root.join("config")).unwrap();
            std::fs::write(root.join(relative), b"[project]\nname='example'\n").unwrap();
            std::fs::write(root.join("Shared.cs"), "class Shared {}\n").unwrap();
        }
        let base_project = FilesystemProject::new(base_root.path()).unwrap();
        let base_file = base_project.file_by_rel_path(Path::new(relative)).unwrap();
        let blob = base_project.read_source_snapshot(&base_file).unwrap().oid();
        // The language identifies the authority that read the file, rather
        // than the configuration file's syntax (TOML).
        use brokk_bifrost_core::gitblob::ParseVariant;
        let source_file = base_project
            .file_by_rel_path(Path::new("Shared.cs"))
            .unwrap();
        let source_blob = base_project
            .read_source_snapshot(&source_file)
            .unwrap()
            .oid();
        let selected = ReadKey::file(
            Language::CSharp,
            "Shared.cs",
            source_blob,
            ParseVariant::Digest([7; 32]),
        );
        let reads = vec![
            selected.clone(),
            ReadKey::file(
                Language::Python,
                crate::path_utils::rel_path_string(&base_file),
                blob,
                brokk_bifrost_core::gitblob::ParseVariant::Empty,
            ),
            ReadKey::path_absent(Language::Python, "config/package.json"),
        ];
        let digest = StableDigest::sha256(b"non-source read verification");
        let key = PolicyUnitRowKey {
            policy_semantic_hash: digest.to_string(),
            family: "match".into(),
            partition: PolicyUnitPartitionRow::Whole,
            configuration_fingerprint: digest.to_string(),
            active_model_set_hash: digest.to_string(),
            engine_epoch: digest.to_string(),
        };
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .publish_policy_units(vec![PolicyUnitRow {
                seed_parse_variant: None,
                key: key.clone(),
                product_kind: "rows".into(),
                product: "{\"rows\":[]}".into(),
                read_set_digest: *read_set_digest(&reads).digest().as_bytes(),
                reads: reads.clone(),
                snapshots: vec![[1; 32]],
            }])
            .unwrap();
        let loaded = store
            .policy_units_for_keys(&[key])
            .unwrap()
            .pop()
            .unwrap()
            .unwrap();
        assert_eq!(loaded.reads.len(), 3);
        let persisted_selected = loaded
            .reads
            .iter()
            .find(|key| **key == selected)
            .expect("persisted non-NULL variant round-trips");
        let head_with_variant = |variant| {
            WorkspaceAnalyzer::Empty(
                EmptyAnalyzer::new(Arc::new(FilesystemProject::new(head_root.path()).unwrap()))
                    .with_csharp_parse_variant_for_test(variant),
            )
        };
        let head = head_with_variant(ParseVariant::Digest([7; 32]));
        let base = WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(Arc::new(base_project)));
        let changed = ChangedFacts::between(&base, &head);
        let inputs = HeadInputs {
            models: digest,
            policy_semantic_hash: digest,
            policy_source: digest,
            configuration: digest,
            epoch: digest,
        };
        let verify = |head: &WorkspaceAnalyzer, key: &ReadKey| {
            verify_read_set_for_artifact(
                DerivedArtifactId::semantic_artifact(digest),
                head,
                &changed,
                &inputs,
                std::slice::from_ref(key),
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        for key in &loaded.reads {
            assert_eq!(verify(&head, key), ReadVerdict::Unchanged, "{key:?}");
        }
        // Both comparisons use the decoded persisted row and the same source OID.
        assert_eq!(verify(&head, persisted_selected), ReadVerdict::Unchanged);
        let changed_variant_head = head_with_variant(ParseVariant::Digest([8; 32]));
        let variant_verdict = verify(&changed_variant_head, persisted_selected);
        assert_eq!(
            variant_verdict
                .changed()
                .expect("different selected decision")
                .key,
            *persisted_selected
        );
        std::fs::write(head_root.path().join("Shared.cs"), "class Changed {}\n").unwrap();
        std::fs::write(
            head_root.path().join(relative),
            "[project]\nname='changed'\n",
        )
        .unwrap();
        std::fs::write(head_root.path().join("config/package.json"), "{}").unwrap();
        for key in &loaded.reads {
            let verdict = verify(&head, key);
            assert_eq!(verdict.changed().expect("changed input").key, *key);
        }
    }
}

#[cfg(test)]
pub(crate) mod workspace_fact_test_support {
    use super::*;

    // These authorities depend on project snapshots and real syntax parsing,
    // independently of a language analyzer or semantic-pack registration.
    pub(crate) fn source_workspace(
        project: &crate::inline_project::BuiltInlineTestProject,
    ) -> WorkspaceAnalyzer {
        WorkspaceAnalyzer::Empty(crate::analyzer::workspace::EmptyAnalyzer::new(
            project.project_dyn(),
        ))
    }

    /// Exercise the verifier with field-slot certificates removed, so a broad
    /// companion certificate cannot mask a missing authority fact.
    pub(crate) fn verdict_without_field_slots(
        base: &WorkspaceAnalyzer,
        head: &WorkspaceAnalyzer,
        keys: &[ReadKey],
    ) -> ReadVerdict {
        let keys: Vec<_> = keys
            .iter()
            .filter(|key| {
                !matches!(
                    key,
                    ReadKey::Lookup {
                        question: LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::FieldSlots,
                            ..
                        },
                        ..
                    }
                )
            })
            .cloned()
            .collect();
        assert!(
            !keys.is_empty(),
            "family certificate must survive the field-slot filter"
        );
        assert!(
            keys.iter().all(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::WorkspaceFact,
                    ..
                }
            )),
            "isolate authority replay: {keys:?}"
        );
        let zero = StableDigest::sha256(b"unused verifier inputs");
        verify_read_set(
            head,
            &ChangedFacts::between(base, head),
            &HeadInputs {
                models: zero,
                policy_semantic_hash: zero,
                policy_source: zero,
                configuration: zero,
                epoch: zero,
            },
            &keys,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::default(),
        )
    }
}
