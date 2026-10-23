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

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{CodeUnit, Language, ProjectFile, SignatureMetadata};
use crate::hash::HashSet;
use crate::path_utils::rel_path_string;

/// Domain for the digest of a whole read set.
pub use crate::analyzer::semantic::read_ledger::IndexFamily;
#[allow(unused_imports)]
pub(crate) use crate::analyzer::semantic::read_ledger::READ_KEY_DOMAIN;

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

/// The set of inputs one request read, plus the crossings it could not name.
///
/// Shared behind an `Arc` and written from every thread the analyzer spends the
/// request's work on. A replayable funnel's nested capture shadows only its
/// explicitly linked enclosing ledger; unrelated concurrent request ledgers
/// still receive the read. Ordinary nested scopes carry no ledger and leave
/// their enclosing ledger visible.
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
                },
            },
            LookupQuestion::ProcedureCallSite {
                rel_path: Box::from("src/a.rs"),
                procedure: StableDigest::sha256("artifact"),
                site: ProcedureCallSiteLocator {
                    start_byte: 0,
                    end_byte: 0,
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
