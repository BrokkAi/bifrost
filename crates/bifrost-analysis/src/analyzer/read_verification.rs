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
//!   every changed blob on either side contributes. The set is built by the
//!   store's own row builders, so a key it holds is spelled exactly as the
//!   probe that reads it spells it.
//! * A [`ReadKey::Lookup`] cannot be proved from any per-file fact, because a
//!   cross-file answer moves when a file the reader never mentioned changes.
//!   It is proved by [`replay_lookup`]: re-running the same funnel on the head
//!   and comparing the answer digest the recording used.
//!
//! Everything else -- artifacts, scopes, models, policy, configuration, epoch
//! -- is an identity comparison against what the head publishes.

use git2::Oid;
use std::path::Path;

use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind, InvalidationReason};
use crate::analyzer::read_ledger::{IndexFamily, LookupKind, LookupQuestion, ReadKey};
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::semantic::{SemanticBudget, SemanticRequest, SemanticWork};
use crate::analyzer::usages::call_relations::{CallRelationLimits, CallRelationService};
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageFinder};
use crate::analyzer::workspace::WorkspaceAnalyzer;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, DescendantIndexScope, IAnalyzer, Language, ProjectFile,
    QueryScope, Range,
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

    /// Every analyzed path of this language with the blob it resolves to.
    fn analyzed_blobs(&self) -> Vec<(ProjectFile, Oid)>;

    /// Every `(family, key)` the facts of `file`'s `blob` contribute to the
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
    ) -> Option<Vec<(IndexFamily, Box<[u8]>)>>;

    /// Every `(family, key)` the *persisted* facts of `blob` contribute, with
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
    ) -> Option<Vec<(IndexFamily, Box<[u8]>)>>;
}

/// What moved between two workspaces, in the vocabulary a read key names.
///
/// Two sets, both computed once per head evaluation and then asked many
/// questions:
///
/// * the workspace-relative paths whose blob differs, was added, or was
///   removed, per language; and
/// * the `(family, key)` pairs every changed blob on *either* side
///   contributes, so a name a deleted declaration used to publish is in the
///   set exactly as a name a new one publishes is.
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
    paths: HashMap<Language, HashSet<Box<str>>>,
    keys: HashSet<(IndexFamily, Box<[u8]>)>,
    /// The head's whole path map, retained because a `ReadKey::File` names the
    /// blob its reader saw, which need not be either side of this difference:
    /// a unit published by an earlier head run carries that run's blob. Only
    /// comparing against the head's own map answers exactly, and building it
    /// once here is what keeps verification linear in the number of units.
    head_blobs: HashMap<(Language, Box<str>), Oid>,
    unenumerated: Vec<(Language, Box<str>)>,
    languages_without_index: Vec<Language>,
}

impl ChangedFacts {
    /// The difference between two workspaces.
    pub fn between(base: &WorkspaceAnalyzer, head: &WorkspaceAnalyzer) -> Self {
        let mut facts = Self {
            paths: HashMap::default(),
            keys: HashSet::default(),
            head_blobs: HashMap::default(),
            unenumerated: Vec::new(),
            languages_without_index: Vec::new(),
        };
        let base_indexes = fact_indexes_by_language(base);
        let head_indexes = fact_indexes_by_language(head);
        for (analyzer, indexes) in [(base, &base_indexes), (head, &head_indexes)] {
            for language in analyzer.analyzer().languages() {
                if !indexes.contains_key(&language) {
                    facts.languages_without_index.push(language);
                }
            }
        }
        facts.languages_without_index.sort();
        facts.languages_without_index.dedup();

        let mut languages = base_indexes.keys().copied().collect::<Vec<_>>();
        languages.extend(head_indexes.keys().copied());
        languages.sort();
        languages.dedup();
        for language in languages {
            let base_blobs = base_indexes
                .get(&language)
                .map(|index| blob_map(*index))
                .unwrap_or_default();
            let head_blobs = head_indexes
                .get(&language)
                .map(|index| blob_map(*index))
                .unwrap_or_default();
            for (rel_path, (file, blob)) in &base_blobs {
                if head_blobs.get(rel_path).map(|(_, oid)| *oid) == Some(*blob) {
                    continue;
                }
                facts.record_changed_blob(
                    language,
                    rel_path,
                    file,
                    *blob,
                    base_indexes.get(&language).copied(),
                );
            }
            for (rel_path, (_, blob)) in &head_blobs {
                facts.head_blobs.insert((language, rel_path.clone()), *blob);
            }
            for (rel_path, (file, blob)) in &head_blobs {
                if base_blobs.get(rel_path).map(|(_, oid)| *oid) == Some(*blob) {
                    continue;
                }
                facts.record_changed_blob(
                    language,
                    rel_path,
                    file,
                    *blob,
                    head_indexes.get(&language).copied(),
                );
            }
        }
        facts
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
    pub fn from_committed_tree(
        head: &WorkspaceAnalyzer,
        base_blobs: &[(Box<str>, Oid)],
        base_source: &dyn Fn(Oid) -> Option<String>,
    ) -> Self {
        let mut facts = Self {
            paths: HashMap::default(),
            keys: HashSet::default(),
            head_blobs: HashMap::default(),
            unenumerated: Vec::new(),
            languages_without_index: Vec::new(),
        };
        let head_indexes = fact_indexes_by_language(head);
        for language in head.analyzer().languages() {
            if !head_indexes.contains_key(&language) {
                facts.languages_without_index.push(language);
            }
        }
        let mut head_by_language: HashMap<Language, HashMap<Box<str>, (ProjectFile, Oid)>> =
            HashMap::default();
        for (language, index) in &head_indexes {
            let blobs = blob_map(*index);
            for (rel_path, (_, blob)) in &blobs {
                facts
                    .head_blobs
                    .insert((*language, rel_path.clone()), *blob);
            }
            head_by_language.insert(*language, blobs);
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
                facts.languages_without_index.push(language);
                continue;
            };
            base_by_language
                .entry(language)
                .or_default()
                .insert(rel_path.clone());
            let head_blob = head_by_language
                .get(&language)
                .and_then(|blobs| blobs.get(rel_path))
                .map(|(_, blob)| *blob);
            if head_blob == Some(*blob) {
                continue;
            }
            facts
                .paths
                .entry(language)
                .or_default()
                .insert(rel_path.clone());
            let keys = base_source(*blob)
                .and_then(|source| index.stored_blob_index_keys(&file, *blob, &source));
            match keys {
                Some(keys) => facts.keys.extend(keys),
                None if head_blob.is_none() => {}
                None => facts.unenumerated.push((language, rel_path.clone())),
            }
        }

        for (language, blobs) in &head_by_language {
            let base_paths = base_by_language.get(language);
            for (rel_path, (file, blob)) in blobs {
                let unchanged = base_blob_by_path.get(rel_path).copied() == Some(*blob)
                    && base_paths.is_some_and(|paths| paths.contains(rel_path));
                if unchanged {
                    continue;
                }
                facts.record_changed_blob(
                    *language,
                    rel_path,
                    file,
                    *blob,
                    head_indexes.get(language).copied(),
                );
            }
        }
        facts.languages_without_index.sort();
        facts.languages_without_index.dedup();
        facts
    }

    /// Whether every changed blob's facts were enumerated and every language
    /// the two analyzers serve published a fact index.
    pub fn is_complete(&self) -> bool {
        self.unenumerated.is_empty() && self.languages_without_index.is_empty()
    }

    /// The changed blobs whose facts could not be enumerated, and the
    /// languages that published no fact index at all.
    pub fn incompleteness(&self) -> (&[(Language, Box<str>)], &[Language]) {
        (&self.unenumerated, &self.languages_without_index)
    }

    /// Whether any changed blob contributes this exact index key.
    pub fn contains(&self, family: IndexFamily, key: &[u8]) -> bool {
        self.keys.contains(&(family, Box::from(key)))
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
        self.paths
            .get(&language)
            .is_some_and(|paths| paths.contains(rel_path))
    }

    /// How many paths changed, over every language.
    pub fn changed_path_count(&self) -> usize {
        self.paths.values().map(HashSet::len).sum()
    }

    /// How many distinct index keys the changed blobs contribute.
    pub fn changed_key_count(&self) -> usize {
        self.keys.len()
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
            Some(keys) => self.keys.extend(keys),
            None => self.unenumerated.push((language, Box::from(rel_path))),
        }
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
fn blob_map(index: &dyn WorkspaceFactIndex) -> HashMap<Box<str>, (ProjectFile, Oid)> {
    index
        .analyzed_blobs()
        .into_iter()
        .map(|(file, blob)| {
            (
                Box::from(crate::path_utils::rel_path_string(&file).as_str()),
                (file, blob),
            )
        })
        .collect()
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
}

impl LookupMemo {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many distinct questions this memo has answered.
    pub fn len(&self) -> usize {
        self.answers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.answers.is_empty()
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
        if let Some(answer) = self.answers.get(&(kind, question.clone())) {
            return *answer;
        }
        let answer = replay_lookup(head, kind, question, limits, summaries);
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
            let descendants = provider.get_direct_descendants_within(
                &unit,
                &DescendantIndexScope::whole_workspace(&cancellation),
            )?;
            Some(crate::analyzer::read_ledger::declaration_set_digest(
                &descendants,
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
        LookupKind::Dispatch => replay_dispatch(head, question, limits),
        // The repository is not this crate's, so the answer comes from the
        // caller that holds the head's, through the same lookup the recording
        // was announced from.
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

/// The head's declaration for a declaration question.
///
/// Resolved through the head's own declaration lookup for the file the
/// question names, never by re-parsing or by matching text: the question is a
/// workspace-relative path and a qualified name, and the analyzer is the only
/// thing that knows which declarations a file has.
///
/// Two overloads that share a file and a qualified name are one question with
/// two recorded answers. Replay answers one of them, so at least one recorded
/// digest disagrees and the unit is recomputed. That is the sound direction:
/// the conflation can cost reuse, never grant it.
fn replayed_declaration(analyzer: &dyn IAnalyzer, question: &LookupQuestion) -> Option<CodeUnit> {
    let LookupQuestion::Declaration { rel_path, fq_name } = question else {
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
        .find(|unit| unit.fq_name() == **fq_name)
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

/// Replay one dispatch question: materialize the head's artifact for the
/// call site's file and resolve dispatch at the same source range.
///
/// The recorded artifact fingerprint is part of the question, so a head whose
/// artifact for that file moved has no answer to it. That is exactly right:
/// "dispatch at this range of this artifact" and "dispatch at this range of
/// whatever artifact the file has now" are different questions.
fn replay_dispatch(
    head: &WorkspaceAnalyzer,
    question: &LookupQuestion,
    limits: LookupReplayLimits,
) -> Option<StableDigest> {
    let LookupQuestion::CallSite {
        rel_path,
        artifact,
        site,
    } = question
    else {
        debug_assert!(
            false,
            "a dispatch lookup recorded a {} question: {question:?}",
            question.stable_label()
        );
        return None;
    };
    let file = analyzed_file(head.analyzer(), rel_path)?;
    let mut budget = SemanticBudget::new(limits.semantic).ok()?;
    let cancellation = CancellationToken::default();
    let mut request = SemanticRequest::new(&mut budget, &cancellation);
    let materialized = head
        .materialize_program_semantics(&file, &mut request)
        .ok()?;
    if materialized.available_value()?.key().public_fingerprint() != *artifact {
        return None;
    }
    // Only the byte range addresses a call site: the source projection selects
    // by span containment and never reads the line coordinates.
    let range = Range {
        start_byte: site.start_byte,
        end_byte: site.end_byte,
        start_line: 0,
        end_line: 0,
    };
    let outcome = head
        .semantic_oracle_provider()
        .dispatch_at_source_in_artifact(materialized, range, &mut request)
        .ok()?;
    Some(
        crate::analyzer::semantic::workspace_oracle::dispatch_answer_digest(
            outcome.available_value(),
        ),
    )
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
    StableDigest::from_array(hasher.finish())
}

/// Domain for [`analysis_epoch_digest`].
const ANALYSIS_EPOCH_DOMAIN: &[u8] = b"bifrost-policy-unit:analysis-epoch:v1";

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
#[allow(clippy::too_many_arguments)]
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
    for key in keys {
        let reason = match key {
            ReadKey::File {
                language,
                rel_path,
                blob,
            } => (changed.head_blob(*language, rel_path) != Some(*blob)).then(|| {
                InvalidationReason::InputContentChanged {
                    artifact: unit,
                    before: blob_identity(Some(*blob)),
                    after: blob_identity(changed.head_blob(*language, rel_path)),
                }
            }),
            // The negative half of the path map, and the exact counterpart of
            // the `File` arm: the probe found nothing at this path, so the
            // head still answers the same question only while it finds
            // nothing there either.
            ReadKey::PathAbsent { language, rel_path } => changed
                .head_blob(*language, rel_path)
                .map(|blob| InvalidationReason::InputContentChanged {
                    artifact: unit,
                    before: blob_identity(None),
                    after: blob_identity(Some(blob)),
                }),
            ReadKey::Index { family, key } => {
                if !changed.is_complete() {
                    // A changed-key set that could not be completed is smaller
                    // than the truth, and a smaller set would let a changed
                    // name pass. The absence of evidence is not evidence.
                    Some(InvalidationReason::ContentIdentityEvidenceMissing { artifact: unit })
                } else {
                    changed.contains(*family, key).then_some(
                        InvalidationReason::DependencyChanged {
                            artifact: unit,
                            dependency: ReadKey::index(*family, key).canonical_digest(),
                        },
                    )
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
            // different content, reports a change
            // (`.agents/plans/impact-sliced-diff-base.md`, Decision Log (5b)).
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
                Some(replayed)
                    if replayed == crate::analyzer::read_ledger::absent_summary_digest() =>
                {
                    None
                }
                Some(replayed) if replayed != *digest => {
                    Some(InvalidationReason::DependencyFingerprintChanged {
                        artifact: unit,
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
            } => match memo.answer(head, *kind, question, limits, summaries) {
                // The head has no answer to the question that was asked, so
                // nothing about it can be reused.
                None => {
                    Some(InvalidationReason::ReverseDependencyEvidenceMissing { artifact: unit })
                }
                Some(replayed) if replayed != *digest => {
                    Some(InvalidationReason::DependencyFingerprintChanged {
                        artifact: unit,
                        before: *digest,
                        after: replayed,
                    })
                }
                Some(_) => None,
            },
            ReadKey::Artifact { id, rel_path } => {
                verify_artifact(head, unit, *id, rel_path.as_deref())
            }
            ReadKey::Scope {
                languages,
                identity,
            } => match head
                .analyzer()
                .workspace_content_identities()
                .and_then(|identities| identities.scope(|language| languages.contains(&language)))
            {
                None => Some(InvalidationReason::ContentIdentityEvidenceMissing { artifact: unit }),
                Some(head_identity) if head_identity != *identity => {
                    Some(InvalidationReason::DependencyChanged {
                        artifact: unit,
                        dependency: key.canonical_digest(),
                    })
                }
                Some(_) => None,
            },
            ReadKey::Models(models) => (*models != inputs.models).then_some(
                InvalidationReason::DependencyFingerprintChanged {
                    artifact: unit,
                    before: *models,
                    after: inputs.models,
                },
            ),
            ReadKey::Policy {
                semantic_hash,
                source,
            } => (*semantic_hash != inputs.policy_semantic_hash || *source != inputs.policy_source)
                .then(|| InvalidationReason::DependencyFingerprintChanged {
                    artifact: unit,
                    before: key.canonical_digest(),
                    after: ReadKey::Policy {
                        semantic_hash: inputs.policy_semantic_hash,
                        source: inputs.policy_source,
                    }
                    .canonical_digest(),
                }),
            ReadKey::Configuration(configuration) => (*configuration != inputs.configuration)
                .then_some(InvalidationReason::DependencyFingerprintChanged {
                    artifact: unit,
                    before: *configuration,
                    after: inputs.configuration,
                }),
            ReadKey::Epoch(epoch) => {
                (*epoch != inputs.epoch).then_some(InvalidationReason::EpochChanged {
                    artifact: unit,
                    before: *epoch,
                    after: inputs.epoch,
                })
            }
        };
        if let Some(reason) = reason {
            return ReadVerdict::Changed(Box::new(ChangedRead {
                reason,
                key: key.clone(),
            }));
        }
    }
    ReadVerdict::Unchanged
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
    use crate::analyzer::AnalyzerConfig;
    use crate::inline_project::InlineTestProject;

    fn workspace(alpha: &str) -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::TypeScript)
            .file("src/alpha.ts", alpha)
            .file("src/beta.ts", "export function beta() {\n  return 2;\n}\n")
            .build()
    }

    const ORIGINAL: &str = "export function alpha() {\n  return 1;\n}\n";

    #[test]
    fn an_identical_workspace_changes_nothing() {
        let base = workspace(ORIGINAL);
        let head = workspace(ORIGINAL);
        let changed = ChangedFacts::between(
            &base.workspace_analyzer(AnalyzerConfig::default()),
            &head.workspace_analyzer(AnalyzerConfig::default()),
        );
        assert!(changed.is_complete(), "{:?}", changed.incompleteness());
        assert_eq!(changed.changed_path_count(), 0);
        assert_eq!(changed.changed_key_count(), 0);
    }

    #[test]
    fn a_rename_changes_the_names_of_both_the_old_and_the_new_blob() {
        let base = workspace(ORIGINAL);
        let head = workspace("export function renamed() {\n  return 1;\n}\n");
        let changed = ChangedFacts::between(
            &base.workspace_analyzer(AnalyzerConfig::default()),
            &head.workspace_analyzer(AnalyzerConfig::default()),
        );

        assert!(changed.is_complete(), "{:?}", changed.incompleteness());
        assert!(changed.path_changed(Language::TypeScript, "src/alpha.ts"));
        assert!(!changed.path_changed(Language::TypeScript, "src/beta.ts"));
        for name in ["alpha", "renamed"] {
            assert!(
                changed.contains(IndexFamily::DefinitionExact, name.as_bytes()),
                "the exact name `{name}` must be in the changed set"
            );
            assert!(
                changed.contains(IndexFamily::DefinitionNormalizedTail, name.as_bytes()),
                "the normalized tail `{name}` must be in the changed set"
            );
            assert!(
                changed.contains(IndexFamily::DefinitionIdentifier, name.as_bytes()),
                "the identifier `{name}` must be in the changed set"
            );
        }
        assert!(
            !changed.contains(IndexFamily::DefinitionExact, b"beta"),
            "an untouched file's names must stay out of the changed set"
        );
    }

    /// A file the base did not have contributes every name-keyed spelling its
    /// declarations publish, which is what makes a negative name answer
    /// recorded on the base verifiable against the head.
    ///
    /// The three families are pinned together because the definition batch
    /// records a probe under all three, and a probe whose family the changed
    /// set never fills would verify unchanged against the file that answers
    /// it.
    #[test]
    fn an_added_file_contributes_every_definition_name_key_it_declares() {
        let base = workspace(ORIGINAL);
        let head = InlineTestProject::with_language(Language::TypeScript)
            .file("src/alpha.ts", ORIGINAL)
            .file("src/beta.ts", "export function beta() {\n  return 2;\n}\n")
            .file(
                "src/gamma.ts",
                "export function gamma() {\n  return 3;\n}\n",
            )
            .build();
        let changed = ChangedFacts::between(
            &base.workspace_analyzer(AnalyzerConfig::default()),
            &head.workspace_analyzer(AnalyzerConfig::default()),
        );

        assert!(changed.is_complete(), "{:?}", changed.incompleteness());
        assert!(changed.path_changed(Language::TypeScript, "src/gamma.ts"));
        for family in [
            IndexFamily::DefinitionExact,
            IndexFamily::DefinitionNormalizedTail,
            IndexFamily::DefinitionIdentifier,
        ] {
            assert!(
                changed.contains(family, b"gamma"),
                "an added declaration must publish its `{}` key",
                family.stable_label()
            );
        }
        assert!(
            !changed.contains(IndexFamily::DefinitionIdentifier, b"beta"),
            "an untouched file's names must stay out of the changed set"
        );
    }

    /// A probe that found no file at a path is verified by the head's own path
    /// map: still nothing there is still the same answer, and a file there now
    /// is the content change that answers it.
    #[test]
    fn an_absent_path_that_the_head_fills_invalidates_the_unit_that_probed_it() {
        let base = workspace(ORIGINAL);
        let base_analyzer = base.workspace_analyzer(AnalyzerConfig::default());
        let keys = [ReadKey::path_absent(Language::TypeScript, "src/gamma.ts")];
        let inputs = HeadInputs {
            models: StableDigest::sha256("models"),
            policy_semantic_hash: StableDigest::sha256("policy-semantic"),
            policy_source: StableDigest::sha256("policy-source"),
            configuration: StableDigest::sha256("configuration"),
            epoch: StableDigest::sha256("epoch"),
        };

        let unchanged_head = workspace(ORIGINAL);
        let unchanged_analyzer = unchanged_head.workspace_analyzer(AnalyzerConfig::default());
        let unchanged = ChangedFacts::between(&base_analyzer, &unchanged_analyzer);
        assert_eq!(
            verify_read_set(
                &unchanged_analyzer,
                &unchanged,
                &inputs,
                &keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            ),
            ReadVerdict::Unchanged,
            "a head that still has no file there answers the probe the same way"
        );

        let filled_head = InlineTestProject::with_language(Language::TypeScript)
            .file("src/alpha.ts", ORIGINAL)
            .file("src/beta.ts", "export function beta() {\n  return 2;\n}\n")
            .file(
                "src/gamma.ts",
                "export function gamma() {\n  return 3;\n}\n",
            )
            .build();
        let filled_analyzer = filled_head.workspace_analyzer(AnalyzerConfig::default());
        let filled = ChangedFacts::between(&base_analyzer, &filled_analyzer);
        let verdict = verify_read_set(
            &filled_analyzer,
            &filled,
            &inputs,
            &keys,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        );
        let changed = verdict
            .changed()
            .expect("a path the head now has invalidates the probe that found nothing there");
        assert_eq!(
            (changed.reason.stable_label(), changed.key.stable_label()),
            ("input_content_changed", "path_absent"),
            "unexpected verdict {changed:#?}"
        );
    }

    #[test]
    fn a_comment_only_edit_changes_the_blob_and_no_index_key() {
        let base = workspace(ORIGINAL);
        let head = workspace("// a note\nexport function alpha() {\n  return 1;\n}\n");
        let changed = ChangedFacts::between(
            &base.workspace_analyzer(AnalyzerConfig::default()),
            &head.workspace_analyzer(AnalyzerConfig::default()),
        );

        assert!(changed.is_complete(), "{:?}", changed.incompleteness());
        assert!(
            changed.path_changed(Language::TypeScript, "src/alpha.ts"),
            "the blob moved, so the path is changed"
        );
        // Every key the edited blob publishes it published before: the two
        // sides contribute the same names, so the changed-key set holds them
        // -- but no key of the *other* file enters, and the names are the same
        // ones on both sides rather than a new spelling.
        assert!(changed.contains(IndexFamily::DefinitionExact, b"alpha"));
        assert!(
            !changed.contains(IndexFamily::DefinitionExact, b"beta"),
            "an untouched file's names must stay out of the changed set"
        );
    }
}
