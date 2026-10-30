//! The analyzer read ledger: what one request actually read, in a closed,
//! mount-free vocabulary (Milestone 1 of the impact-sliced `--diff-base` plan).
//!
//! A policy evaluation is reusable only when every input it read is provably
//! unchanged. "Every input it read" has to be a recorded fact, not an argument
//! about which files a policy *should* depend on, because findings move across
//! files through analyzer derivation funnels (dispatch, reference candidates,
//! the usage-ranking graph, the import topology, the descendant index) and not
//! through import edges alone. A [`ReadLedger`] attached to one
//! [`crate::analyzer::AnalyzerQueryContext`] collects one [`ReadKey`] per
//! funnel crossing while the request runs, and counts the crossings it could
//! not attribute. A ledger with a nonzero unattributed count describes an
//! execution whose inputs are not completely known, so nothing derived under it
//! may be reused.
//!
//! Three rules govern the vocabulary:
//!
//! * **Mount-free.** Every identity is comparable across two checkouts of the
//!   same content. Paths are workspace-relative; whole artifacts use
//!   [`crate::analyzer::semantic::ids::SemanticArtifactKey::public_fingerprint`]
//!   and procedure-local questions use stable declaration lineage. No key
//!   carries a [`crate::analyzer::ProjectFile`] (which knows its root), a
//!   `WorkspaceMountId`, or a process-local generation counter. The base half
//!   of a `--diff-base` run is analyzed at a temporary root, so a mount-bearing
//!   key could never equal its head counterpart.
//! * **Exactly keyed, or coarse and honest.** A funnel whose answer is keyed by
//!   an exact name records [`ReadKey::Index`] with that name. A funnel that
//!   searches the whole name index by prefix, suffix, or pattern cannot be
//!   verified by exact-key membership, so it records [`ReadKey::Scope`] -- the
//!   whole-language dependency -- instead of an `Index` key that would look
//!   precise and verify unsoundly.
//! * **A superset is sound; a subset is not.** Recording more than a unit truly
//!   read can only cost reuse. Recording less would let a changed input pass
//!   verification. Every judgement call here goes the over-recording way.
//!
//! An answer of "nothing" is an answer, and it is keyed the same way. A name
//! that resolved to no declaration read exactly the index keys a resolved name
//! would have read, so it records them; a specifier that resolved to no file
//! read the absence of each path it probed, so it records one
//! [`ReadKey::PathAbsent`] per path. Without those, a unit that found nothing
//! would carry no dependency on the file that later answers it, which is the
//! one direction the third rule forbids.
//!
//! The digest is over the sorted canonical encodings of the keys, so two
//! executions over byte-equal content at different roots produce the same
//! [`ReadSetDigest`]. That equality is the property the whole plan rests on: it
//! is what lets a unit published from the exported base match a unit the head
//! would have computed.
pub use brokk_bifrost_store::analyzer::read_ledger::{ReadSetDigest, read_set_digest};

use crate::hash::{HashMap, HashSet};
use std::borrow::Cow;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{CodeUnit, Language, ProjectFile, SignatureMetadata};
use crate::path_utils::rel_path_string;

pub use crate::analyzer::semantic::read_ledger::IndexFamily;
#[allow(unused_imports)]
pub(crate) use crate::analyzer::semantic::read_ledger::READ_KEY_DOMAIN;
/// Domain for the digest of a whole read set.
pub use crate::analyzer::semantic::read_ledger::{FactSubject, WorkspaceFactFamily};

pub use crate::analyzer::semantic::read_ledger::LookupKind;

pub use crate::analyzer::semantic::read_ledger::ReadKey;

/// Domain for the digest of an answer that is a set of declarations.
const DECLARATION_SET_DOMAIN: &[u8] = b"bifrost-read-ledger:declaration-set:v1";
/// Domain for the exact declaration facts consumed by a language resolver.
const DECLARATION_FACTS_DOMAIN: &[u8] = b"bifrost-read-ledger:declaration-facts:v1";
/// Domain for a declaration-facts question whose declaration is absent.
const ABSENT_DECLARATION_FACTS_DOMAIN: &[u8] = b"bifrost-read-ledger:absent-declaration-facts:v1";
/// Domain for the structured signature metadata of one declaration.
const SIGNATURE_METADATA_DOMAIN: &[u8] = b"bifrost-read-ledger:signature-metadata:v1";
/// Domain for a signature-metadata question whose declaration is absent.
const ABSENT_SIGNATURE_METADATA_DOMAIN: &[u8] = b"bifrost-read-ledger:absent-signature-metadata:v1";
/// Domain for the answer digest of a summary lookup that found nothing.
const ABSENT_SUMMARY_DOMAIN: &[u8] = b"bifrost-read-ledger:absent-summary:v1";
/// Domain for the digest of an answer that is a set of files.
const FILE_SET_DOMAIN: &[u8] = b"bifrost-read-ledger:file-set:v1";

pub use crate::analyzer::semantic::read_ledger::LookupQuestion;

pub use crate::analyzer::semantic::read_ledger::CallSiteLocator;

pub use crate::analyzer::semantic::read_ledger::ProcedureCallSiteLocator;

/// The canonical digest of an answer that is a set of declarations.
///
/// Sorted by mount-free identity, so it is a function of the set and not of the
/// order the producer happened to enumerate it in, and equal across checkouts.
pub fn declaration_set_digest<'a>(units: impl IntoIterator<Item = &'a CodeUnit>) -> StableDigest {
    let mut identities = units
        .into_iter()
        .map(|unit| (rel_path_string(unit.source()), unit.fq_name()))
        .collect::<Vec<_>>();
    identities.sort();
    identities.dedup();
    let mut hasher = CanonicalHasher::new(DECLARATION_SET_DOMAIN);
    hasher.value(
        &u64::try_from(identities.len())
            .expect("usize fits u64 on supported targets")
            .to_be_bytes(),
    );
    for (path, fq_name) in identities {
        hasher.field(&path, fq_name.as_bytes());
    }
    StableDigest::from_array(hasher.finish())
}

pub(crate) fn declaration_candidates_lookup_key<'a>(
    kind: LookupKind,
    language: Option<Language>,
    name: impl Into<String>,
    declarations: impl IntoIterator<Item = &'a CodeUnit>,
) -> ReadKey {
    ReadKey::lookup(
        kind,
        LookupQuestion::Name {
            language,
            name: name.into().into(),
        },
        declaration_set_digest(declarations),
    )
}

/// The canonical digest of the exact declaration facts a resolver consumed.
///
/// A declaration identity includes the normalized source path, structured
/// qualified name, kind, synthetic bit, and signature. The optional parent is
/// folded separately so a target whose owner changes cannot retain the old
/// answer even when the target's own identity is unchanged.
pub fn declaration_facts_digest(declaration: &CodeUnit, parent: Option<&CodeUnit>) -> StableDigest {
    let mut hasher = CanonicalHasher::new(DECLARATION_FACTS_DOMAIN);
    hasher.field(
        "declaration",
        declaration.declaration_id().as_str().as_bytes(),
    );
    match parent {
        Some(parent) => hasher.field("parent", parent.declaration_id().as_str().as_bytes()),
        None => hasher.field("parent", b"absent"),
    }
    StableDigest::from_array(hasher.finish())
}

/// The answer digest of a declaration-facts lookup whose declaration is absent.
pub fn absent_declaration_facts_digest() -> StableDigest {
    absent_answer_digest(ABSENT_DECLARATION_FACTS_DOMAIN)
}

/// The exact answer of hydrating one path-backed module, including absence.
pub(crate) fn path_synthetic_module_digest(module: Option<&CodeUnit>) -> StableDigest {
    module.map_or_else(absent_declaration_facts_digest, |module| {
        declaration_facts_digest(module, None)
    })
}

/// Complete eligible path-symbol set, without hydrated declaration facts.
pub(crate) fn path_synthetic_modules_digest(
    language: Language,
    modules: &[(String, crate::analyzer::store::PathSymbolRow, bool)],
) -> StableDigest {
    let mut facts = modules
        .iter()
        .map(|(storage_language, row, has_imports)| {
            (
                storage_language.as_str(),
                row.rel_path.as_str(),
                row.exact_fqn.as_str(),
                crate::analyzer::store::code_unit_kind_to_i64(row.kind),
                row.requires_imports,
                row.requires_imports && *has_imports,
            )
        })
        .collect::<Vec<_>>();
    facts.sort();
    facts.dedup();
    let mut hash = CanonicalHasher::new(b"path-synthetic-modules-set-v2");
    hash.value(language.config_label().as_bytes());
    hash.sequence(
        "modules",
        &facts,
        |hash, (storage, path, identity, kind, requires, present)| {
            hash.value(storage.as_bytes());
            hash.value(path.as_bytes());
            hash.value(identity.as_bytes());
            hash.value(&kind.to_be_bytes());
            hash.value(&[u8::from(*requires), u8::from(*present)]);
        },
    );
    StableDigest::from_array(hash.finish())
}

fn absent_answer_digest(domain: &[u8]) -> StableDigest {
    StableDigest::from_array(CanonicalHasher::new(domain).finish())
}

/// The canonical digest of one declaration's structured signature metadata.
pub fn signature_metadata_digest(
    declaration: &CodeUnit,
    metadata: &[SignatureMetadata],
) -> StableDigest {
    let mut hasher = CanonicalHasher::new(SIGNATURE_METADATA_DOMAIN);
    hasher.field(
        "declaration",
        declaration.declaration_id().as_str().as_bytes(),
    );
    hasher.sequence("metadata", metadata, |hasher, metadata| {
        hasher.value(
            &serde_json::to_vec(metadata)
                .expect("signature metadata has a deterministic serialization"),
        );
    });
    StableDigest::from_array(hasher.finish())
}

/// The answer digest of a signature-metadata lookup whose declaration is absent.
pub fn absent_signature_metadata_digest() -> StableDigest {
    absent_answer_digest(ABSENT_SIGNATURE_METADATA_DOMAIN)
}

/// The answer digest of a procedure-summary lookup that found nothing.
///
/// Absence is an answer, and it is keyed the same way a hit is: a solve that
/// read "no summary is retained under this identity" depends on the head still
/// holding none, exactly as a solve that read a summary depends on the head
/// holding the same one. One fixed digest is enough because the identity that
/// was asked about is already in the question.
pub fn absent_summary_digest() -> StableDigest {
    absent_answer_digest(ABSENT_SUMMARY_DOMAIN)
}

/// The canonical digest of an answer that is a set of files.
pub fn file_set_digest<'a>(files: impl IntoIterator<Item = &'a ProjectFile>) -> StableDigest {
    let mut paths = files.into_iter().map(rel_path_string).collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    let mut hasher = CanonicalHasher::new(FILE_SET_DOMAIN);
    hasher.value(
        &u64::try_from(paths.len())
            .expect("usize fits u64 on supported targets")
            .to_be_bytes(),
    );
    for path in paths {
        hasher.value(path.as_bytes());
    }
    StableDigest::from_array(hasher.finish())
}

/// Operational causes carried by producer-owned derivation reason values.
/// These labels describe outcomes, never source syntax or rendered messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationExecutionCause {
    Cancelled,
    Budget,
    Snapshot,
    Provider,
}

impl DerivationExecutionCause {
    /// Unknown labels are operational until their producer's cause is audited.
    pub fn from_reason(reason: &str) -> Option<Self> {
        reason::classify_known(reason).unwrap_or(Some(Self::Provider))
    }

    pub fn from_cfg_error<Node: std::fmt::Debug>(
        error: &crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError<Node>,
    ) -> Self {
        use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;
        match error {
            CfgAlgorithmError::Cancelled { .. } => Self::Cancelled,
            CfgAlgorithmError::ExceededBudget(_) => Self::Budget,
            CfgAlgorithmError::InvalidNode(node) => {
                panic!("validated procedure has invalid CFG point {node:?}")
            }
        }
    }
}

/// Producer-owned labels. One table also generates the regression inventory.
pub mod reason {
    use super::DerivationExecutionCause;
    macro_rules! reasons {
        ($($name:ident = $label:expr => $cause:expr),* $(,)?) => {
            $(pub const $name: &str = $label;)*
            pub fn classify_known(label: &str) -> Option<Option<DerivationExecutionCause>> {
                match label {
                    $($name => Some($cause),)*
                    _ => None,
                }
            }
            #[cfg(test)]
            const ALL: &[(&str, Option<DerivationExecutionCause>)] = &[$(($name, $cause)),*];
        };
    }
    reasons! {
        PREPROCESSING_PRESENT = "preprocessing_present" => None,
        MACRO_POSSIBLE = "macro_possible" => None,
        CPP_ANALYZER_UNAVAILABLE = "cpp_analyzer_unavailable" => Some(DerivationExecutionCause::Provider),
        NOT_CPP = "not_cpp" => None,
        ANCHOR_SYNTAX_MISSING = "anchor_syntax_missing" => None,
        RETURN_SEMANTICS_MISSING = "return_semantics_missing" => None,
        ASSIGNMENT_SEMANTICS_MISSING = "assignment_semantics_missing" => None,
        RESOLVED_CALL_IDENTITY_UNAVAILABLE = "resolved_call_identity_unavailable" => None,
        CALL_FUNCTION_MISSING = "call_function_missing" => None,
        RESOLVED_CALL_NAME_MISSING = "resolved_call_name_missing" => None,
        RESOLVED_CALL_IDENTITY_MISMATCH = "resolved_call_identity_mismatch" => None,
        CALL_SEMANTICS_MISSING = "call_semantics_missing" => None,
        RESOLVED_CALL_HEADER_OWNER_MISSING = "resolved_call_header_owner_missing" => None,
        CALL_ARGUMENTS_MISSING = "call_arguments_missing" => None,
        CALL_ARGUMENT_MISSING = "call_argument_missing" => None,
        CALL_ARGUMENT_UNREADABLE = "call_argument_unreadable" => None,
        CALL_ARGUMENT_ALIAS_UNKNOWN = "call_argument_alias_unknown" => None,
        // An external boundary depends on the selected external inventory, which
        // is neither a unit-key dimension nor a ledgered read yet. Promote these
        // reasons to content only when #7633 (and its per-language siblings) ledger it.
        // Selected C# configuration is neither a demonstrated unit-key dimension
        // nor a ledgered read, so compilation disagreement is operational.
        CSHARP_COMPILATION_ACCESS_UNKNOWN = "csharp-compilation-access-unknown" => Some(DerivationExecutionCause::Provider),
        OPEN_BOUNDARY = "OpenBoundary" => Some(DerivationExecutionCause::Provider),
        EXTERNAL_DECLARED_UNINDEXED = "external_declared_unindexed" => Some(DerivationExecutionCause::Provider),
        // A Go import is incomplete when its package rows are missing or
        // unconfirmed, which also depends on the selected external inventory.
        GO_IMPORT_INCOMPLETE = "go-import-incomplete" => Some(DerivationExecutionCause::Provider),
        OWNER_INVENTORY_OPEN = "OwnerInventoryOpen" => Some(DerivationExecutionCause::Provider),
        AMBIGUOUS_MEMBER = "ambiguous_member" => None,
        AMBIGUOUS_PROCEDURE = "ambiguous_procedure" => None,
        AMBIGUOUS_STATEMENT_SPAN = "ambiguous_statement_span" => None,
        ASSESSMENT_INCOMPLETE = "assessment_incomplete" => Some(DerivationExecutionCause::Provider),
        BODY_FIELD_MISSING = "body_field_missing" => None,
        CANCELLED = brokk_bifrost_semantic::analyzer::semantic::statement_entries::reason::CANCELLED => Some(DerivationExecutionCause::Cancelled),
        CAUGHT_TYPE_UNRESOLVED = "caught_type_unresolved" => None,
        CLEANUP_KIND_UNRECOGNIZED = "cleanup_kind_unrecognized" => None,
        CLEANUP_OUTCOME_UNPROVEN = "cleanup_outcome_unproven" => None,
        CLEANUP_SEMANTICS_UNPUBLISHED = "cleanup_semantics_unpublished" => None,
        CLEANUP_SOURCE_MAPPING_MISSING = "cleanup_source_mapping_missing" => None,
        COMPARISON_BUDGET = "comparison_budget" => Some(DerivationExecutionCause::Budget),
        CONDITION_FIELD_MISSING = "condition_field_missing" => None,
        CONTROL_BUDGET_EXHAUSTED = brokk_bifrost_semantic::analyzer::semantic::statement_entries::reason::CONTROL_BUDGET_EXHAUSTED => Some(DerivationExecutionCause::Budget),
        CONTROL_EVIDENCE_INCOMPLETE = brokk_bifrost_semantic::analyzer::semantic::statement_entries::reason::CONTROL_EVIDENCE_INCOMPLETE => None,
        CONTROL_FRONTIER_INCOMPLETE = brokk_bifrost_semantic::analyzer::semantic::statement_entries::reason::CONTROL_FRONTIER_INCOMPLETE => None,
        DEFERRED_BODY = "deferred_body" => None,
        EFFECTFUL_BODY = "effectful_body" => None,
        EFFECTFUL_CONDITION = "effectful_condition" => None,
        HANDLER_IDENTITY_UNPROVEN = "handler_identity_unproven" => None,
        LEXICAL_BINDING_UNAVAILABLE = "lexical_binding_unavailable" => None,
        LEXICAL_ENVIRONMENT_INCOMPLETE = "lexical_environment_incomplete" => None,
        MEMBER_RESOLUTION_UNAVAILABLE = "member_resolution_unavailable" => None,
        MISSING_BODY = "missing_body" => None,
        MISSING_BRANCH_FIELD = "missing_branch_field" => None,
        MISSING_STATEMENT_ENTRY = "missing_statement_entry" => None,
        MISSING_TRY_BODY = "missing_try_body" => None,
        NO_ENCLOSING_PROCEDURE = "no_enclosing_procedure" => None,
        NON_LOCAL_REFERENCE = "non_local_reference" => None,
        PARTIAL_PROCEDURE = "partial_procedure" => None,
        PARTIAL_PRODUCER = "partial_producer" => None,
        PENDING_CLEANUP_STATE_BUDGET_EXHAUSTED = "pending_cleanup_state_budget_exhausted" => Some(DerivationExecutionCause::Budget),
        PREPARED_SYNTAX_UNAVAILABLE = "prepared_syntax_unavailable" => Some(DerivationExecutionCause::Provider),
        PROCEDURE_MAPPING_INEXACT = "procedure_mapping_inexact" => None,
        PROCEDURE_MAPPING_MISSING = "procedure_mapping_missing" => None,
        PROCEDURE_SEMANTIC_QUALITY_INCOMPLETE = "procedure_semantic_quality_incomplete" => None,
        PROCEDURE_SYNTAX_AMBIGUOUS = "procedure_syntax_ambiguous" => None,
        PROCEDURE_SYNTAX_INEXACT = "procedure_syntax_inexact" => None,
        PROCEDURE_SYNTAX_MISSING = "procedure_syntax_missing" => None,
        PROCEDURE_SYNTAX_RECOVERY = "procedure_syntax_recovery" => None,
        QUERY_INCOMPLETE = "query_incomplete" => Some(DerivationExecutionCause::Provider),
        SNAPSHOT_MISMATCH = "snapshot_mismatch" => Some(DerivationExecutionCause::Snapshot),
        SOURCE_BUDGET_EXHAUSTED = "source_budget_exhausted" => Some(DerivationExecutionCause::Budget),
        SOURCE_IDENTITY_MISMATCH = "source_identity_mismatch" => Some(DerivationExecutionCause::Snapshot),
        SOURCE_LIMIT = "source_limit" => Some(DerivationExecutionCause::Budget),
        STALE_SOURCE = "stale_source" => Some(DerivationExecutionCause::Snapshot),
        SYNTAX_RECOVERY = "syntax_recovery" => None,
        SYNTAX_UNAVAILABLE = "syntax_unavailable" => Some(DerivationExecutionCause::Provider),
        UNKNOWN = "unknown" => Some(DerivationExecutionCause::Provider),
        UNPROVEN_ACTIVATION = "unproven_activation" => None,
        UNSUPPORTED_CALLABLE_KIND = "unsupported_callable_kind" => None,
        UNSUPPORTED_CASE_FACT = "unsupported_case_fact" => None,
        UNSUPPORTED_CONDITION = "unsupported_condition" => None,
        UNSUPPORTED_LANGUAGE = "unsupported_language" => None,
        UNSUPPORTED_RELATION = "unsupported_relation" => None,
        WORK_LIMIT = "work_limit" => Some(DerivationExecutionCause::Budget),
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7278: unrecognized operational reason labels defaulted to content"
    )]
    fn every_registered_reason_constant_is_classified_and_unknowns_fail_closed() {
        // This inventories declared constants, not arbitrary future literals
        // outside the table. Producer regressions must also exercise their
        // emitted reasons, since their public result fields remain strings.
        for &(label, expected) in ALL {
            assert_eq!(classify_known(label), Some(expected), "{label}");
            assert_eq!(
                DerivationExecutionCause::from_reason(label),
                expected,
                "{label}"
            );
        }
        assert_eq!(
            DerivationExecutionCause::from_reason("future_execution_stop"),
            Some(DerivationExecutionCause::Provider)
        );
    }
}

// Hash once per routed read, including when several ledgers consume it.
// Equality still compares the entire key; the hash is never an identity.
fn read_key_hash(key: &ReadKey) -> u64 {
    #[cfg(not(feature = "randomized-hash"))]
    {
        rustc_hash::FxBuildHasher.hash_one(key)
    }
    #[cfg(feature = "randomized-hash")]
    {
        static HASHER: std::sync::OnceLock<std::collections::hash_map::RandomState> =
            std::sync::OnceLock::new();
        HASHER.get_or_init(Default::default).hash_one(key)
    }
}

#[derive(Debug, Default, Clone)]
struct LocalReadKeys {
    table: hashbrown::HashTable<(u64, ReadKey)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReadInputIdentity {
    Receipt(usize),
    Capture(u64),
}

#[derive(Debug, Clone)]
enum ReadInput {
    Receipt(Arc<[ReadKey]>),
    Capture(Arc<ReadSnapshot>),
}

impl ReadInput {
    fn key_entries(&self) -> usize {
        match self {
            Self::Receipt(keys) => keys.len(),
            Self::Capture(snapshot) => snapshot.key_entries,
        }
    }

    fn nodes(&self) -> usize {
        match self {
            Self::Receipt(_) => 1,
            Self::Capture(snapshot) => snapshot.nodes,
        }
    }
}

// Bound transitive reference metadata and Arc drop depth, even for repeated
// captures of the same one-key answer. Crossing the bound compacts into the
// existing owned key table; the recorded set never changes.
const MAX_READ_SNAPSHOT_NODES: usize = 256;
// Referenced payloads are bounded too: overlapping wide receipts must not
// retain many copies of a workspace-sized input set. Larger inputs compact
// into the one owned set the ledger would have held without deferred replay.
const MAX_REFERENCED_READ_KEYS: usize = 16_384;

#[derive(Debug)]
struct ReadSnapshot {
    capture: u64,
    generation: u64,
    local: Arc<LocalReadKeys>,
    inputs: Vec<ReadInput>,
    nodes: usize,
    key_entries: usize,
    // At most one canonical publication per immutable snapshot.
    canonical: OnceLock<Arc<[ReadKey]>>,
}

impl ReadSnapshot {
    fn unique_keys(&self) -> hashbrown::HashTable<(u64, &ReadKey)> {
        let mut unique = hashbrown::HashTable::new();
        let mut stack = vec![self];
        let mut visited = HashSet::default();
        let mut receipts = HashSet::default();
        while let Some(snapshot) = stack.pop() {
            if !visited.insert(std::ptr::from_ref(snapshot)) {
                continue;
            }
            for (hash, key) in &snapshot.local.table {
                unique
                    .entry(*hash, |(_, previous)| *previous == key, |(hash, _)| *hash)
                    .or_insert((*hash, key));
            }
            for input in &snapshot.inputs {
                match input {
                    ReadInput::Capture(child) => stack.push(child),
                    ReadInput::Receipt(keys) => {
                        if !receipts.insert(keys.as_ptr()) {
                            continue;
                        }
                        for key in keys.iter() {
                            let hash = read_key_hash(key);
                            unique
                                .entry(hash, |(_, previous)| *previous == key, |(hash, _)| *hash)
                                .or_insert((hash, key));
                        }
                    }
                }
            }
        }
        unique
    }

    fn unordered_keys(&self) -> Vec<ReadKey> {
        self.unique_keys()
            .iter()
            .map(|(_, key)| (*key).clone())
            .collect()
    }

    fn contains(&self, key: &ReadKey) -> bool {
        let hash = read_key_hash(key);
        let mut stack = vec![self];
        let mut visited = HashSet::default();
        while let Some(snapshot) = stack.pop() {
            if !visited.insert(std::ptr::from_ref(snapshot)) {
                continue;
            }
            if snapshot
                .local
                .table
                .find(hash, |(_, previous)| previous == key)
                .is_some()
            {
                return true;
            }
            for input in &snapshot.inputs {
                match input {
                    ReadInput::Capture(child) => stack.push(child),
                    ReadInput::Receipt(keys) if keys.contains(key) => return true,
                    ReadInput::Receipt(_) => {}
                }
            }
        }
        false
    }
}

#[derive(Debug, Default)]
struct RecordedKeys {
    generation: u64,
    local: Arc<LocalReadKeys>,
    last: Option<usize>,
    inputs: HashMap<ReadInputIdentity, ReadInput>,
    nodes: usize,
    referenced_keys: usize,
    // One immutable snapshot of this ledger's current named set. Clear it only
    // when that set changes; diagnostic counts have independent event semantics.
    snapshot: Option<Arc<ReadSnapshot>>,
}

/// The set of inputs one request read, plus the crossings it could not name.
///
/// Shared behind an `Arc` and written from every thread the analyzer spends the
/// request's work on. A replayable funnel's nested capture shadows only its
/// explicitly linked enclosing ledger. Reads follow request attribution carried
/// to each helper task; explicit Broadcast records background inputs on all
/// active ledgers. Ordinary nested scopes carry no ledger and leave
/// their enclosing ledger visible.
#[derive(Debug)]
pub struct ReadLedger {
    identity: brokk_bifrost_core::analyzer::memo_attribution::CaptureIdentity,
    keys: Mutex<RecordedKeys>,
    unattributed_reads: AtomicUsize,
    execution_dependences: AtomicUsize,
}

impl Default for ReadLedger {
    fn default() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "read-ledger capture identity exhausted");
        Self {
            identity: brokk_bifrost_core::analyzer::memo_attribution::CaptureIdentity(id),
            keys: Mutex::default(),
            unattributed_reads: AtomicUsize::default(),
            execution_dependences: AtomicUsize::default(),
        }
    }
}

impl ReadLedger {
    pub const fn capture_identity(
        &self,
    ) -> brokk_bifrost_core::analyzer::memo_attribution::CaptureIdentity {
        self.identity
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Record one named input.
    pub fn record(&self, key: ReadKey) {
        self.record_key(Cow::Owned(key), &mut None);
    }

    pub(crate) fn record_borrowed(&self, key: &ReadKey, hash: &mut Option<u64>) {
        self.record_key(Cow::Borrowed(key), hash);
    }

    fn record_key(&self, key: Cow<'_, ReadKey>, hash: &mut Option<u64>) {
        let mut keys = self.keys.lock().expect("read ledger mutex poisoned");
        if keys
            .last
            .and_then(|index| keys.local.table.get_bucket(index))
            .is_some_and(|(_, previous)| previous == key.as_ref())
        {
            return;
        }
        let hash = *hash.get_or_insert_with(|| read_key_hash(&key));
        if let Some(index) = keys
            .local
            .table
            .find_bucket_index(hash, |(_, previous)| previous == key.as_ref())
        {
            keys.last = Some(index);
            return;
        }
        keys.snapshot = None;
        keys.generation = keys
            .generation
            .checked_add(1)
            .expect("read ledger generation exhausted");
        let index = Arc::make_mut(&mut keys.local)
            .table
            .insert_unique(hash, (hash, key.into_owned()), |(hash, _)| *hash)
            .bucket_index();
        keys.last = Some(index);
    }

    fn snapshot(&self) -> Arc<ReadSnapshot> {
        let mut keys = self.keys.lock().expect("read ledger mutex poisoned");
        if let Some(snapshot) = &keys.snapshot {
            return Arc::clone(snapshot);
        }
        let snapshot = Arc::new(ReadSnapshot {
            capture: self.identity.0,
            generation: keys.generation,
            local: Arc::clone(&keys.local),
            inputs: keys.inputs.values().cloned().collect(),
            nodes: 1 + keys.nodes,
            key_entries: keys.local.table.len().saturating_add(keys.referenced_keys),
            canonical: OnceLock::new(),
        });
        debug_assert!(snapshot.nodes <= MAX_READ_SNAPSHOT_NODES);
        keys.snapshot = Some(Arc::clone(&snapshot));
        snapshot
    }

    pub(crate) fn absorb_receipt(&self, receipt: &Arc<[ReadKey]>) {
        if receipt.is_empty() {
            return;
        }
        self.absorb(
            ReadInputIdentity::Receipt(receipt.as_ptr() as usize),
            ReadInput::Receipt(Arc::clone(receipt)),
        );
    }

    pub(crate) fn absorb_capture(&self, capture: &ReadLedger) {
        if self.identity == capture.identity || capture.is_empty() {
            return;
        }
        let snapshot = capture.snapshot();
        self.absorb(
            ReadInputIdentity::Capture(snapshot.capture),
            ReadInput::Capture(snapshot),
        );
    }

    fn absorb(&self, identity: ReadInputIdentity, input: ReadInput) {
        let mut keys = self.keys.lock().expect("read ledger mutex poisoned");
        if let Some(previous) = keys.inputs.get(&identity) {
            let same = match (previous, &input) {
                (ReadInput::Receipt(a), ReadInput::Receipt(b)) => Arc::ptr_eq(a, b),
                // Captures grow monotonically, but concurrent forwards may
                // arrive out of order. An older version cannot withdraw keys.
                (ReadInput::Capture(a), ReadInput::Capture(b)) => a.generation >= b.generation,
                _ => unreachable!("input identity determines its kind"),
            };
            if same {
                return;
            }
        }
        keys.snapshot = None;
        keys.generation = keys
            .generation
            .checked_add(1)
            .expect("read ledger generation exhausted");
        let added = input.nodes();
        let added_keys = input.key_entries();
        if let Some(previous) = keys.inputs.insert(identity, input) {
            keys.nodes -= previous.nodes();
            keys.referenced_keys -= previous.key_entries();
        }
        keys.nodes += added;
        keys.referenced_keys = keys.referenced_keys.saturating_add(added_keys);
        if 1 + keys.nodes > MAX_READ_SNAPSHOT_NODES
            || keys.referenced_keys > MAX_REFERENCED_READ_KEYS
        {
            let snapshot = ReadSnapshot {
                capture: self.identity.0,
                generation: keys.generation,
                local: Arc::clone(&keys.local),
                inputs: keys.inputs.values().cloned().collect(),
                nodes: 1 + keys.nodes,
                key_entries: keys.local.table.len().saturating_add(keys.referenced_keys),
                canonical: OnceLock::new(),
            };
            let mut local = LocalReadKeys::default();
            for (hash, key) in snapshot.unique_keys() {
                local
                    .table
                    .insert_unique(hash, (hash, key.clone()), |(hash, _)| *hash);
            }
            keys.local = Arc::new(local);
            keys.inputs.clear();
            keys.nodes = 0;
            keys.referenced_keys = 0;
            keys.last = None;
        }
    }

    /// Record one funnel crossing whose input could not be named.
    ///
    /// This is the self-check that makes the reuse claim sound: a unit whose
    /// ledger counted one of these read something the ledger cannot verify, so
    /// the unit is `Unbounded` and is never reused.
    pub fn record_unattributed(&self) {
        self.record_unattributed_reads(1);
    }

    pub fn record_unattributed_reads(&self, count: usize) {
        self.unattributed_reads.fetch_add(count, Ordering::Relaxed);
    }

    /// Execution depended on state that named content reads cannot reproduce.
    /// Use the same admission rule as an unattributable read.
    pub fn mark_execution_dependent(&self) {
        self.mark_execution_dependent_reads(1);
    }

    pub fn mark_execution_dependent_reads(&self, count: usize) {
        self.execution_dependences
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Execution events survive resolver narrowing: they are not input reads.
    pub fn execution_dependences(&self) -> usize {
        self.execution_dependences.load(Ordering::Relaxed)
    }

    /// Whether every read this ledger observed was named.
    pub fn is_bounded(&self) -> bool {
        self.unattributed_reads() == 0 && self.execution_dependences() == 0
    }

    /// How many funnel crossings could not be attributed to a key.
    pub fn unattributed_reads(&self) -> usize {
        self.unattributed_reads.load(Ordering::Relaxed)
    }

    /// How many distinct inputs were recorded.
    pub fn len(&self) -> usize {
        let keys = self.keys.lock().expect("read ledger mutex poisoned");
        if keys.inputs.is_empty() {
            return keys.local.table.len();
        }
        drop(keys);
        self.snapshot().unique_keys().len()
    }

    pub fn is_empty(&self) -> bool {
        let keys = self.keys.lock().expect("read ledger mutex poisoned");
        keys.local.table.is_empty() && keys.inputs.is_empty()
    }

    /// Search immutable inputs without flattening them or cloning their keys.
    pub(crate) fn contains_read_key(&self, key: &ReadKey) -> bool {
        self.snapshot().contains(key)
    }

    /// Set-valued receipts and internal forwarding do not require ordering.
    #[doc(hidden)]
    pub fn unordered_keys(&self) -> Vec<ReadKey> {
        self.snapshot().unordered_keys()
    }

    /// Inspect a completed read set by reference, without cloning or ordering
    /// its keys. Used to certify that a memo hit replayed its named inputs.
    #[doc(hidden)]
    pub fn keys_satisfy(&self, mut predicate: impl FnMut(&ReadKey) -> bool) -> bool {
        let snapshot = self.snapshot();
        snapshot.unique_keys().iter().all(|(_, key)| predicate(key))
    }

    /// Share the one canonical publication of this immutable read snapshot.
    #[doc(hidden)]
    pub fn canonical_keys(&self) -> Arc<[ReadKey]> {
        let snapshot = self.snapshot();
        Arc::clone(snapshot.canonical.get_or_init(|| {
            let mut keys = snapshot.unordered_keys();
            keys.sort();
            keys.into()
        }))
    }

    /// Every recorded key, in canonical order.
    pub fn keys(&self) -> Vec<ReadKey> {
        self.canonical_keys().to_vec()
    }

    /// The digest of this read set: the sorted canonical encodings of its keys,
    /// folded in order under one domain.
    ///
    /// Deliberately independent of insertion order and of the set's hash seed,
    /// and, because every key is mount-free, of the workspace root.
    pub fn digest(&self) -> ReadSetDigest {
        read_set_digest(&self.unordered_keys())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::synthetic_oid as oid;

    fn file_key(path: &str, byte: u8) -> ReadKey {
        ReadKey::file(Language::Rust, path, oid(byte))
    }

    #[test]
    fn a_read_set_digest_is_a_function_of_the_set_and_not_of_its_insertion_order() {
        let forward = ReadLedger::new();
        forward.record(file_key("src/a.rs", 1));
        forward.record(ReadKey::index(IndexFamily::DefinitionExact, "crate::a::f"));
        forward.record(file_key("src/b.rs", 2));

        let backward = ReadLedger::new();
        backward.record(file_key("src/b.rs", 2));
        backward.record(ReadKey::index(IndexFamily::DefinitionExact, "crate::a::f"));
        backward.record(file_key("src/a.rs", 1));

        assert_eq!(forward.digest(), backward.digest());
        let keys = forward.keys();
        assert_eq!(keys, backward.keys());
        assert_eq!(read_set_digest(&keys), forward.digest());
        let mut reversed = keys.clone();
        reversed.reverse();
        assert_eq!(read_set_digest(&reversed), forward.digest());
    }

    #[test]
    fn absorbed_snapshots_freeze_keys_and_keep_later_versions() {
        let source = ReadLedger::new();
        source.record(file_key("first.rs", 1));
        let target = ReadLedger::new();
        target.absorb_capture(&source);
        target.absorb_capture(&source);
        let first = target.keys();
        assert_eq!(first, vec![file_key("first.rs", 1)]);
        source.record(file_key("later.rs", 2));
        assert_eq!(target.keys(), first);
        target.absorb_capture(&source);
        let mut expected = vec![file_key("first.rs", 1), file_key("later.rs", 2)];
        expected.sort();
        assert_eq!(target.keys(), expected);
        assert!(target.contains_read_key(&expected[0]));
        assert_eq!(target.digest(), read_set_digest(&expected));
        let receipt: Arc<[ReadKey]> = vec![file_key("receipt.rs", 3)].into();
        target.absorb_receipt(&receipt);
        target.absorb_receipt(&receipt);
        assert_eq!(target.len(), 3);
        target.absorb_capture(&target);
        assert_eq!(target.len(), 3);
    }

    #[test]
    fn out_of_order_capture_versions_cannot_withdraw_inputs() {
        let source = ReadLedger::new();
        source.record(file_key("first.rs", 1));
        let older = source.snapshot();
        source.record(file_key("second.rs", 2));
        let newer = source.snapshot();
        let target = ReadLedger::new();
        let identity = ReadInputIdentity::Capture(source.capture_identity().0);
        target.absorb(identity, ReadInput::Capture(newer));
        target.absorb(identity, ReadInput::Capture(older));
        assert_eq!(target.keys(), source.keys());
        assert_eq!(target.len(), 2);
    }

    #[test]
    fn long_capture_chains_compact_without_losing_inputs() {
        let mut previous = ReadLedger::new();
        let mut expected = Vec::new();
        for index in 0..1024 {
            let next = ReadLedger::new();
            next.absorb_capture(&previous);
            let key = ReadKey::index(IndexFamily::DefinitionExact, format!("item{index}"));
            next.record(key.clone());
            expected.push(key);
            assert!(next.snapshot().nodes <= MAX_READ_SNAPSHOT_NODES);
            previous = next;
        }
        expected.sort();
        assert_eq!(previous.keys(), expected);
        assert_eq!(previous.digest(), read_set_digest(&expected));
    }

    #[test]
    fn wide_receipts_compact_instead_of_retaining_duplicate_payloads() {
        let receipt: Arc<[ReadKey]> = (0..=MAX_REFERENCED_READ_KEYS)
            .map(|index| ReadKey::index(IndexFamily::DefinitionExact, format!("wide{index}")))
            .collect::<Vec<_>>()
            .into();
        let ledger = ReadLedger::new();
        ledger.absorb_receipt(&receipt);
        assert!(ledger.keys.lock().unwrap().inputs.is_empty());
        assert_eq!(ledger.len(), receipt.len());
        assert_eq!(ledger.digest(), read_set_digest(&receipt));
    }

    #[test]
    fn repeated_keys_and_snapshots_preserve_the_set_across_table_growth() {
        let ledger = ReadLedger::new();
        let mut expected = Vec::new();
        for index in 0..512 {
            let key = ReadKey::index(IndexFamily::DefinitionExact, format!("item{index}"));
            // Both owned and borrowed recording must keep the one-entry repeat
            // shortcut valid after insertion grows and rehashes the table.
            ledger.record(key.clone());
            ledger.record_borrowed(&key, &mut None);
            expected.push(key);
            if index % 31 == 0 {
                let mut sorted = expected.clone();
                sorted.sort();
                assert_eq!(ledger.keys(), sorted);
            }
        }
        for key in expected.iter().rev() {
            ledger.record_borrowed(key, &mut None);
            ledger.record(key.clone());
            assert!(ledger.contains_read_key(key));
        }
        expected.sort();
        assert_eq!(ledger.keys(), expected);
        assert_eq!(ledger.len(), expected.len());
        assert_eq!(ledger.digest(), read_set_digest(&expected));
    }

    #[test]
    fn keys_of_different_shapes_cannot_share_an_encoding() {
        let digests = [
            file_key("src/a.rs", 1),
            ReadKey::index(IndexFamily::DefinitionExact, "src/a.rs"),
            ReadKey::index(IndexFamily::DefinitionIdentifier, "src/a.rs"),
            ReadKey::path_absent(Language::Rust, "src/a.rs"),
            ReadKey::path_absent(Language::TypeScript, "src/a.rs"),
            ReadKey::lookup(
                LookupKind::Callers,
                LookupQuestion::File {
                    rel_path: Box::from("src/a.rs"),
                },
                StableDigest::sha256("answer"),
            ),
            ReadKey::lookup(
                LookupKind::Usages,
                LookupQuestion::File {
                    rel_path: Box::from("src/a.rs"),
                },
                StableDigest::sha256("answer"),
            ),
            ReadKey::Models(StableDigest::sha256("models")),
            ReadKey::Configuration(StableDigest::sha256("models")),
            ReadKey::Epoch(StableDigest::sha256("models")),
        ]
        .map(|key| key.canonical_digest());
        let unique = digests.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), digests.len(), "{digests:?}");
    }

    #[test]
    fn an_absent_path_is_not_the_same_input_as_the_file_at_that_path() {
        let absent = ReadKey::path_absent(Language::Rust, "src/a.rs");
        assert_ne!(
            absent.canonical_digest(),
            file_key("src/a.rs", 1).canonical_digest(),
            "`no file here` and `this blob here` are opposite answers about one path"
        );
        assert_ne!(
            absent.canonical_digest(),
            ReadKey::path_absent(Language::Rust, "src/b.rs").canonical_digest(),
        );
        assert_eq!(absent.stable_label(), "path_absent");
    }

    #[test]
    fn an_absent_path_key_carries_no_root() {
        let working_directory =
            std::env::current_dir().expect("test working directory must be available");
        let base = ProjectFile::new(working_directory.join("bifrost-base-export"), "src/a.rs");
        let head = ProjectFile::new(working_directory.join("checkout"), "src/a.rs");
        assert_eq!(
            ReadKey::path_absent(Language::Rust, rel_path_string(&base).as_str()),
            ReadKey::path_absent(Language::Rust, rel_path_string(&head).as_str()),
        );
    }

    #[test]
    fn a_composite_name_question_is_distinct_from_each_delegate_question() {
        let answer = StableDigest::sha256("answer");
        let composite = ReadKey::lookup(
            LookupKind::Definitions,
            LookupQuestion::Name {
                language: None,
                name: Box::from("crate::a::f"),
            },
            answer,
        );
        let rust = ReadKey::lookup(
            LookupKind::Definitions,
            LookupQuestion::Name {
                language: Some(Language::Rust),
                name: Box::from("crate::a::f"),
            },
            answer,
        );
        let java = ReadKey::lookup(
            LookupKind::Definitions,
            LookupQuestion::Name {
                language: Some(Language::Java),
                name: Box::from("crate::a::f"),
            },
            answer,
        );
        assert_ne!(composite.canonical_digest(), rust.canonical_digest());
        assert_ne!(rust.canonical_digest(), java.canonical_digest());
    }

    #[test]
    fn the_same_question_at_two_roots_encodes_identically() {
        let working_directory =
            std::env::current_dir().expect("test working directory must be available");
        let base = ProjectFile::new(working_directory.join("bifrost-base-export"), "src/a.rs");
        let head = ProjectFile::new(working_directory.join("checkout"), "src/a.rs");
        assert_eq!(LookupQuestion::file(&base), LookupQuestion::file(&head));
        assert_eq!(
            ReadKey::lookup(
                LookupKind::Importers,
                LookupQuestion::file(&base),
                StableDigest::sha256("answer"),
            )
            .canonical_digest(),
            ReadKey::lookup(
                LookupKind::Importers,
                LookupQuestion::file(&head),
                StableDigest::sha256("answer"),
            )
            .canonical_digest(),
        );
    }

    #[test]
    fn questions_of_different_shapes_cannot_share_an_encoding() {
        let digests = [
            LookupQuestion::Declaration {
                rel_path: Box::from("src/a.rs"),
                fq_name: Box::from("f"),
                kind: brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
                signature: None,
            },
            LookupQuestion::File {
                rel_path: Box::from("src/a.rs"),
            },
            LookupQuestion::CallSite {
                rel_path: Box::from("src/a.rs"),
                artifact: StableDigest::sha256("artifact"),
                site: CallSiteLocator {
                    start_byte: 0,
                    end_byte: 0,
                },
            },
            LookupQuestion::Summary {
                identity: StableDigest::sha256("artifact"),
            },
        ]
        .map(|question| {
            ReadKey::lookup(
                LookupKind::Callers,
                question,
                StableDigest::sha256("answer"),
            )
            .canonical_digest()
        });
        let unique = digests.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), digests.len(), "{digests:?}");
    }

    #[test]
    fn a_kind_names_exactly_one_funnel() {
        let question = LookupQuestion::File {
            rel_path: Box::from("src/a.rs"),
        };
        let answer = StableDigest::sha256("answer");
        assert_ne!(
            ReadKey::lookup(LookupKind::Callers, question.clone(), answer).canonical_digest(),
            ReadKey::lookup(LookupKind::Callees, question.clone(), answer).canonical_digest(),
        );
        assert_ne!(
            ReadKey::lookup(LookupKind::Callees, question.clone(), answer).canonical_digest(),
            ReadKey::lookup(LookupKind::Usages, question, answer).canonical_digest(),
        );
        let subject = StableDigest::sha256("subject");
        assert_ne!(
            ReadKey::lookup(
                LookupKind::Dispatch,
                LookupQuestion::CallSite {
                    rel_path: Box::from("src/a.rs"),
                    artifact: subject,
                    site: CallSiteLocator {
                        start_byte: 10,
                        end_byte: 20,
                    },
                },
                answer,
            )
            .canonical_digest(),
            ReadKey::lookup(
                LookupKind::ProcedureDispatch,
                LookupQuestion::ProcedureCallSite {
                    rel_path: Box::from("src/a.rs"),
                    procedure: subject,
                    site: ProcedureCallSiteLocator {
                        start_byte: 10,
                        end_byte: 20,
                        ordinal: 0,
                    },
                },
                answer,
            )
            .canonical_digest(),
        );
    }

    #[test]
    fn an_unattributed_read_does_not_enter_the_digest() {
        let bounded = ReadLedger::new();
        bounded.record(file_key("src/a.rs", 1));
        let unbounded = ReadLedger::new();
        unbounded.record(file_key("src/a.rs", 1));
        unbounded.record_unattributed();
        assert_eq!(bounded.digest(), unbounded.digest());
        assert!(!unbounded.is_bounded());
    }

    #[test]
    fn recording_one_key_twice_records_one_input() {
        let ledger = ReadLedger::new();
        ledger.record(file_key("src/a.rs", 1));
        ledger.record(file_key("src/a.rs", 1));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn an_unattributed_read_makes_the_ledger_unbounded() {
        let ledger = ReadLedger::new();
        assert!(ledger.is_bounded());
        ledger.record_unattributed();
        assert!(!ledger.is_bounded());
        assert_eq!(ledger.unattributed_reads(), 1);
    }

    #[test]
    fn a_lookup_question_round_trips_through_serde() {
        let questions = [
            LookupQuestion::Name {
                language: Some(Language::Rust),
                name: Box::from("crate::a::f"),
            },
            LookupQuestion::Name {
                language: None,
                name: Box::from("crate::a::f"),
            },
            LookupQuestion::Declaration {
                rel_path: Box::from("src/a.rs"),
                fq_name: Box::from("crate::a::f"),
                kind: brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
                signature: None,
            },
            LookupQuestion::File {
                rel_path: Box::from("src/a.rs"),
            },
            LookupQuestion::CallSite {
                rel_path: Box::from("src/a.rs"),
                artifact: StableDigest::sha256("artifact"),
                site: CallSiteLocator {
                    start_byte: 10,
                    end_byte: 20,
                },
            },
            LookupQuestion::ProcedureCallSite {
                rel_path: Box::from("src/a.rs"),
                procedure: StableDigest::sha256("procedure"),
                site: ProcedureCallSiteLocator {
                    start_byte: 3,
                    end_byte: 13,
                    ordinal: 1,
                },
            },
            LookupQuestion::ProcedureCallSite {
                rel_path: Box::from("src/a.rs"),
                procedure: StableDigest::sha256("artifact"),
                site: ProcedureCallSiteLocator {
                    start_byte: 0,
                    end_byte: 0,
                    ordinal: 0,
                },
            },
            LookupQuestion::Summary {
                identity: StableDigest::sha256("summary"),
            },
        ];
        for question in questions {
            let encoded = serde_json::to_string(&question).expect("question serializes");
            let decoded: LookupQuestion =
                serde_json::from_str(&encoded).expect("question deserializes");
            assert_eq!(decoded, question, "{encoded}");
        }
    }
}
