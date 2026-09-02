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
//!   same content. Paths are workspace-relative, semantic items are named by
//!   [`crate::analyzer::semantic::ids::SemanticArtifactKey::public_fingerprint`],
//!   and no key carries a [`crate::analyzer::ProjectFile`] (which knows its
//!   root), a `WorkspaceMountId`, or a process-local generation counter. The
//!   base half of a `--diff-base` run is analyzed at a temporary root, so a
//!   mount-bearing key could never equal its head counterpart.
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

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use git2::Oid;

use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::invalidation::DerivedArtifactId;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{CodeUnit, Language, ProjectFile, Range};
use crate::hash::HashSet;
use crate::path_utils::rel_path_string;

/// Domain for one read key's canonical encoding.
const READ_KEY_DOMAIN: &[u8] = b"bifrost-read-ledger:key:v1";
/// Domain for the digest of a whole read set.
const READ_SET_DOMAIN: &[u8] = b"bifrost-read-ledger:set:v1";

/// The per-file fact index families a name-keyed store lookup can consult.
///
/// Closed on purpose: a new family is a new funnel, and a funnel nobody named
/// is a funnel nobody verifies. The variants are exactly the analyzer-side
/// store funnels of the funnel map
/// (`.agents/docs/read-ledger-funnel-map-2026-09.md`, section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndexFamily {
    /// A definition looked up by its exact qualified name.
    DefinitionExact,
    /// A definition looked up by the normalized tail of its qualified name.
    DefinitionNormalizedTail,
    /// A declaration looked up by a parsed identifier or short name.
    DefinitionIdentifier,
    /// A file looked up by an identifier its parsed references mention.
    ReferenceIdentifier,
    /// A file looked up by a structured segment of one of its import paths.
    ImportPathSegment,
    /// The existence of a package name in the workspace.
    PackageMembership,
    /// The raw supertypes recorded for one code unit.
    Supertype,
    /// The supertype lookup paths recorded for one code unit.
    SupertypeLookupPath,
    /// A path-addressed module or symbol looked up by its qualified name.
    PathSymbol,
}

impl IndexFamily {
    /// The label used in the canonical encoding and in diagnostics. Changing a
    /// label rotates every digest that contains it, which is why it is stated
    /// once here rather than derived from the variant name.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::DefinitionExact => "definition_exact",
            Self::DefinitionNormalizedTail => "definition_normalized_tail",
            Self::DefinitionIdentifier => "definition_identifier",
            Self::ReferenceIdentifier => "reference_identifier",
            Self::ImportPathSegment => "import_path_segment",
            Self::PackageMembership => "package_membership",
            Self::Supertype => "supertype",
            Self::SupertypeLookupPath => "supertype_lookup_path",
            Self::PathSymbol => "path_symbol",
        }
    }
}

/// The derived-value lookups whose answers are not index probes.
///
/// These are the cross-file channels: an answer can change because a file the
/// reader never mentions gained a caller, an override, or an importer. Each
/// records the canonical digest of its answer, so re-executing the lookup
/// against another workspace and comparing digests is what detects the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LookupKind {
    /// The callers of one declaration, from the call relation.
    Callers,
    /// The callees of one declaration, from the call relation.
    ///
    /// Separate from [`Self::Usages`] even though both are answers about the
    /// same relation: verification re-executes the funnel a kind names, and
    /// the call relation and the usage finder answer with different digests
    /// over the same subject. A kind that named two funnels could never be
    /// replayed.
    Callees,
    /// The usages of one declaration, from the usage finder.
    Usages,
    /// The files that import one file, from the import topology.
    Importers,
    /// The candidate reference sites of one declaration.
    ReferenceCandidates,
    /// The direct descendants of one type.
    Descendants,
    /// The dispatch targets of one call site.
    Dispatch,
    /// One procedure summary, by its mount-free identity.
    ProcedureSummary,
}

impl LookupKind {
    /// The label used in the canonical encoding and in diagnostics.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Callers => "callers",
            Self::Callees => "callees",
            Self::Usages => "usages",
            Self::Importers => "importers",
            Self::ReferenceCandidates => "reference_candidates",
            Self::Descendants => "descendants",
            Self::Dispatch => "dispatch",
            Self::ProcedureSummary => "procedure_summary",
        }
    }
}

/// One input a request read, named so that another workspace can be asked
/// whether it still denotes the same content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadKey {
    /// Any per-file fact read -- declarations, occurrences, structural facts,
    /// syntax, imports, the semantic artifact -- keyed by the language, the
    /// workspace-relative path, and the blob the path resolved to.
    File {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
    },
    /// A name-keyed lookup served by a per-file fact index.
    Index { family: IndexFamily, key: Box<[u8]> },
    /// One workspace-relative path a module-path or import-specifier probe
    /// stat'ed and did not find.
    ///
    /// The negative half of [`Self::File`]. A resolver that asks "is there a
    /// file at `./helper`" probes a fixed list of candidate paths and, when
    /// none of them exists, returns without reading anything -- so the answer
    /// depends on every one of those paths staying absent, and on nothing
    /// else. Naming each probed path is what lets another workspace be asked
    /// the same question: it has the path, or it does not.
    PathAbsent {
        language: Language,
        rel_path: Box<str>,
    },
    /// A lookup served by an in-memory derived value: the question that was
    /// asked, in a form another workspace can be asked the same question in,
    /// and the canonical digest of the answer it returned.
    Lookup {
        kind: LookupKind,
        question: LookupQuestion,
        digest: StableDigest,
    },
    /// A whole derived artifact consumed as a unit.
    ///
    /// `rel_path` is the file the artifact is derived from, when it has one.
    /// The identity alone cannot be recomputed on another workspace -- a
    /// public fingerprint folds the path, the content, the adapter and the
    /// configuration into 32 bytes and nothing can be read back out -- so a
    /// per-file artifact key carries the locator verification needs to ask the
    /// head what it would derive there now.
    Artifact {
        id: DerivedArtifactId,
        rel_path: Option<Box<str>>,
    },
    /// A whole-language or whole-workspace dependency: the coarse, honest key
    /// for a read that cannot be narrowed to a name or a file.
    ///
    /// `languages` is the exact scope the identity was folded over, sorted, so
    /// another workspace can fold the same scope and compare. A bare digest
    /// could not be recomputed: nothing in it says whether it spans one
    /// language, one ecosystem, or the whole workspace.
    Scope {
        languages: Box<[Language]>,
        identity: WorkspaceContentIdentity,
    },
    /// The active semantic-model set.
    Models(StableDigest),
    /// The policy text itself.
    Policy {
        semantic_hash: StableDigest,
        source: StableDigest,
    },
    /// The analyzer configuration fingerprint.
    Configuration(StableDigest),
    /// The engine epoch.
    Epoch(StableDigest),
}

impl ReadKey {
    /// One per-file fact read of `rel_path`'s `blob`.
    ///
    /// `rel_path` must already be the normalized workspace-relative spelling
    /// (`brokk_bifrost_core::path_utils::rel_path_string`); the caller owns
    /// that conversion because it holds the `ProjectFile` this type refuses to
    /// carry.
    pub fn file(language: Language, rel_path: impl Into<Box<str>>, blob: Oid) -> Self {
        Self::File {
            language,
            rel_path: rel_path.into(),
            blob,
        }
    }

    /// One name-keyed index probe.
    pub fn index(family: IndexFamily, key: impl AsRef<[u8]>) -> Self {
        Self::Index {
            family,
            key: Box::from(key.as_ref()),
        }
    }

    /// One candidate path a probe found nothing at.
    ///
    /// `rel_path` must already be the normalized workspace-relative spelling,
    /// for the same reason [`Self::file`] requires it: the key must compare
    /// equal across two checkouts of the same content.
    pub fn path_absent(language: Language, rel_path: impl Into<Box<str>>) -> Self {
        Self::PathAbsent {
            language,
            rel_path: rel_path.into(),
        }
    }

    /// One derived-value lookup and the digest of the answer it returned.
    pub const fn lookup(kind: LookupKind, question: LookupQuestion, digest: StableDigest) -> Self {
        Self::Lookup {
            kind,
            question,
            digest,
        }
    }

    /// One whole derived artifact, with the file it is derived from.
    pub fn artifact(id: DerivedArtifactId, rel_path: Option<&str>) -> Self {
        Self::Artifact {
            id,
            rel_path: rel_path.map(Box::from),
        }
    }

    /// One whole-scope dependency over exactly `languages`.
    pub fn scope(
        languages: impl IntoIterator<Item = Language>,
        identity: WorkspaceContentIdentity,
    ) -> Self {
        let mut languages = languages.into_iter().collect::<Vec<_>>();
        languages.sort();
        languages.dedup();
        debug_assert!(
            !languages.is_empty(),
            "a scope over no language would compare equal across unrelated workspaces"
        );
        Self::Scope {
            languages: languages.into_boxed_slice(),
            identity,
        }
    }

    /// The stable label of this key's variant.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Index { .. } => "index",
            Self::PathAbsent { .. } => "path_absent",
            Self::Lookup { .. } => "lookup",
            Self::Artifact { .. } => "artifact",
            Self::Scope { .. } => "scope",
            Self::Models(_) => "models",
            Self::Policy { .. } => "policy",
            Self::Configuration(_) => "configuration",
            Self::Epoch(_) => "epoch",
        }
    }

    /// Push this key's canonical encoding into `hasher`.
    ///
    /// Every field is length-delimited and named, so no two keys of different
    /// shapes can encode to the same bytes.
    fn push_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.value(self.stable_label().as_bytes());
        match self {
            Self::File {
                language,
                rel_path,
                blob,
            } => {
                hasher.field("language", language.config_label().as_bytes());
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("blob", blob.as_bytes());
            }
            Self::Index { family, key } => {
                hasher.field("family", family.stable_label().as_bytes());
                hasher.field("key", key);
            }
            Self::PathAbsent { language, rel_path } => {
                hasher.field("language", language.config_label().as_bytes());
                hasher.field("rel_path", rel_path.as_bytes());
            }
            Self::Lookup {
                kind,
                question,
                digest,
            } => {
                hasher.field("kind", kind.stable_label().as_bytes());
                question.push_canonical(hasher);
                hasher.field("digest", digest.as_bytes());
            }
            Self::Artifact { id, rel_path } => {
                hasher.field("kind", id.kind().stable_label().as_bytes());
                hasher.field("fingerprint", id.fingerprint().as_bytes());
                hasher.field(
                    "rel_path",
                    rel_path
                        .as_ref()
                        .map_or(b"".as_slice(), |path| path.as_bytes()),
                );
            }
            Self::Scope {
                languages,
                identity,
            } => {
                for language in languages.iter() {
                    hasher.field("language", language.config_label().as_bytes());
                }
                hasher.field("content", identity.digest().as_bytes());
            }
            Self::Models(hash) => hasher.field("models", hash.as_bytes()),
            Self::Policy {
                semantic_hash,
                source,
            } => {
                hasher.field("semantic_hash", semantic_hash.as_bytes());
                hasher.field("source", source.as_bytes());
            }
            Self::Configuration(fingerprint) => {
                hasher.field("configuration", fingerprint.as_bytes())
            }
            Self::Epoch(epoch) => hasher.field("epoch", epoch.as_bytes()),
        }
    }

    /// This key's canonical encoding as a standalone digest, for callers that
    /// need to name one key (a persisted row, a diagnostic) rather than a set.
    pub fn canonical_digest(&self) -> StableDigest {
        let mut hasher = CanonicalHasher::new(READ_KEY_DOMAIN);
        self.push_canonical(&mut hasher);
        StableDigest::from_array(hasher.finish())
    }
}

/// Domain for the digest of an answer that is a set of declarations.
const DECLARATION_SET_DOMAIN: &[u8] = b"bifrost-read-ledger:declaration-set:v1";
/// Domain for the digest of an answer that is a set of files.
const FILE_SET_DOMAIN: &[u8] = b"bifrost-read-ledger:file-set:v1";

/// What a derived-value lookup was asked, in a form another workspace can be
/// asked the same thing in.
///
/// A digest of the question would name it but could not re-execute it, and
/// verification against a head workspace is exactly re-execution: resolve the
/// same declaration, the same file, or the same call site there, run the same
/// funnel, and compare the answer digests. So the question is structured, and
/// every field of it is mount-free -- a workspace-relative path, a qualified
/// name, a public artifact fingerprint, a byte range -- because the base half
/// of a `--diff-base` run is analyzed at a temporary root.
///
/// Deliberately not a declaration's byte range or its `DeclarationId`: the
/// same question asked of two checkouts of the same content must be the same
/// question even when the declaration moved within its file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "question", rename_all = "snake_case")]
pub enum LookupQuestion {
    /// One declaration, by the file it is declared in and its qualified name.
    Declaration {
        rel_path: Box<str>,
        fq_name: Box<str>,
    },
    /// One file.
    File { rel_path: Box<str> },
    /// One call site: the file it sits in, the public fingerprint of the
    /// semantic artifact it was resolved against, and its source range.
    ///
    /// The artifact fingerprint is part of the question rather than of the
    /// answer: "dispatch at this range of this artifact" is a different
    /// question from "dispatch at this range of the artifact that file has
    /// now", and a head whose artifact moved has no answer to the first.
    CallSite {
        rel_path: Box<str>,
        artifact: StableDigest,
        site: CallSiteLocator,
    },
    /// One procedure summary, by its mount-free identity.
    Summary { identity: StableDigest },
}

/// Where in its file one call site sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CallSiteLocator {
    pub start_byte: usize,
    pub end_byte: usize,
}

impl LookupQuestion {
    /// The question "what does the workspace answer about this declaration?".
    pub fn declaration(unit: &CodeUnit) -> Self {
        Self::Declaration {
            rel_path: Box::from(rel_path_string(unit.source()).as_str()),
            fq_name: Box::from(unit.fq_name().as_str()),
        }
    }

    /// The question "what does the workspace answer about this file?".
    pub fn file(file: &ProjectFile) -> Self {
        Self::File {
            rel_path: Box::from(rel_path_string(file).as_str()),
        }
    }

    /// The question "what does the workspace answer about this call site?".
    ///
    /// `rel_path` is the artifact's own workspace-relative path, which the
    /// semantic artifact key already carries in normalized form; nothing here
    /// re-derives it from a rooted `ProjectFile`.
    pub fn call_site(rel_path: &str, artifact: StableDigest, range: Range) -> Self {
        Self::CallSite {
            rel_path: Box::from(rel_path),
            artifact,
            site: CallSiteLocator {
                start_byte: range.start_byte,
                end_byte: range.end_byte,
            },
        }
    }

    /// The label used in the canonical encoding and in diagnostics.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::Declaration { .. } => "declaration",
            Self::File { .. } => "file",
            Self::CallSite { .. } => "call_site",
            Self::Summary { .. } => "summary",
        }
    }

    /// The workspace-relative path this question is about, when it names one.
    pub fn rel_path(&self) -> Option<&str> {
        match self {
            Self::Declaration { rel_path, .. }
            | Self::File { rel_path }
            | Self::CallSite { rel_path, .. } => Some(rel_path),
            Self::Summary { .. } => None,
        }
    }

    /// Push this question's canonical encoding into `hasher`.
    fn push_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.field("question", self.stable_label().as_bytes());
        match self {
            Self::Declaration { rel_path, fq_name } => {
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("fq_name", fq_name.as_bytes());
            }
            Self::File { rel_path } => hasher.field("rel_path", rel_path.as_bytes()),
            Self::CallSite {
                rel_path,
                artifact,
                site,
            } => {
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("artifact", artifact.as_bytes());
                hasher.field("start_byte", &(site.start_byte as u64).to_be_bytes());
                hasher.field("end_byte", &(site.end_byte as u64).to_be_bytes());
            }
            Self::Summary { identity } => hasher.field("identity", identity.as_bytes()),
        }
    }
}

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

/// The digest of one complete read set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadSetDigest(StableDigest);

impl ReadSetDigest {
    pub const fn from_digest(digest: StableDigest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> StableDigest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for ReadSetDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The set of inputs one request read, plus the crossings it could not name.
///
/// Shared behind an `Arc` and written from every thread the analyzer spends the
/// request's work on: the registry of open query contexts broadcasts a funnel
/// crossing to every open ledger whichever thread crossed it, exactly as it
/// broadcasts information-tier crossings. Under a host that serves concurrent
/// requests a ledger therefore over-records, which makes a read set a superset
/// of its true reads: sound, never unsound.
#[derive(Debug, Default)]
pub struct ReadLedger {
    keys: Mutex<HashSet<ReadKey>>,
    unattributed_reads: AtomicUsize,
}

impl ReadLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one named input.
    pub fn record(&self, key: ReadKey) {
        self.keys
            .lock()
            .expect("read ledger mutex poisoned")
            .insert(key);
    }

    /// Record one funnel crossing whose input could not be named.
    ///
    /// This is the self-check that makes the reuse claim sound: a unit whose
    /// ledger counted one of these read something the ledger cannot verify, so
    /// the unit is `Unbounded` and is never reused.
    pub fn record_unattributed(&self) {
        self.unattributed_reads.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether every read this ledger observed was named.
    pub fn is_bounded(&self) -> bool {
        self.unattributed_reads() == 0
    }

    /// How many funnel crossings could not be attributed to a key.
    pub fn unattributed_reads(&self) -> usize {
        self.unattributed_reads.load(Ordering::Relaxed)
    }

    /// How many distinct inputs were recorded.
    pub fn len(&self) -> usize {
        self.keys.lock().expect("read ledger mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every recorded key, in canonical order.
    pub fn keys(&self) -> Vec<ReadKey> {
        let mut keys = self
            .keys
            .lock()
            .expect("read ledger mutex poisoned")
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    /// The digest of this read set: the sorted canonical encodings of its keys,
    /// folded in order under one domain.
    ///
    /// Deliberately independent of insertion order and of the set's hash seed,
    /// and, because every key is mount-free, of the workspace root.
    pub fn digest(&self) -> ReadSetDigest {
        read_set_digest(&self.keys())
    }
}

/// The digest of one read set held as a slice rather than as a live ledger.
///
/// A verifier holds a published unit's keys, not the ledger that recorded
/// them, and still has to name the unit by what it read; a persisted row does
/// the same. Sorting here rather than trusting the caller's order is what
/// makes the two digests equal.
pub fn read_set_digest(keys: &[ReadKey]) -> ReadSetDigest {
    let mut sorted = keys.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut hasher = CanonicalHasher::new(READ_SET_DOMAIN);
    hasher.value(
        &u64::try_from(sorted.len())
            .expect("usize fits u64 on supported targets")
            .to_be_bytes(),
    );
    for key in &sorted {
        key.push_canonical(&mut hasher);
    }
    ReadSetDigest::from_digest(StableDigest::from_array(hasher.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(byte: u8) -> Oid {
        Oid::from_bytes(&[byte; 20]).expect("twenty bytes is a valid object id")
    }

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
        assert_eq!(forward.keys(), backward.keys());
    }

    #[test]
    fn recording_one_key_twice_records_one_input() {
        let ledger = ReadLedger::new();
        ledger.record(file_key("src/a.rs", 1));
        ledger.record(file_key("src/a.rs", 1));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn a_changed_blob_changes_the_digest() {
        let before = ReadLedger::new();
        before.record(file_key("src/a.rs", 1));
        let after = ReadLedger::new();
        after.record(file_key("src/a.rs", 2));
        assert_ne!(before.digest(), after.digest());
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
        let base = ProjectFile::new(
            std::path::Path::new("/tmp/bifrost-base-export").to_path_buf(),
            "src/a.rs",
        );
        let head = ProjectFile::new(
            std::path::Path::new("/home/someone/checkout").to_path_buf(),
            "src/a.rs",
        );
        assert_eq!(
            ReadKey::path_absent(Language::Rust, rel_path_string(&base).as_str()),
            ReadKey::path_absent(Language::Rust, rel_path_string(&head).as_str()),
        );
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
            LookupQuestion::Declaration {
                rel_path: Box::from("src/a.rs"),
                fq_name: Box::from("crate::a::f"),
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
    }

    #[test]
    fn a_read_set_digest_over_keys_equals_the_ledger_that_recorded_them() {
        let ledger = ReadLedger::new();
        ledger.record(file_key("src/b.rs", 2));
        ledger.record(file_key("src/a.rs", 1));
        assert_eq!(read_set_digest(&ledger.keys()), ledger.digest());
        let mut reversed = ledger.keys();
        reversed.reverse();
        assert_eq!(read_set_digest(&reversed), ledger.digest());
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
}
