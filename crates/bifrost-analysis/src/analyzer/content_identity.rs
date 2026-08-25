//! The workspace-content identity the snapshot-scoped caches are keyed by (#2449).
//!
//! Three workspace-scope caches -- the derived query layers, the workspace
//! usage-ranking graphs, and the structural posting index -- used to key on
//! `snapshot_source_generations()`, a vector of process-local counters that the
//! project bumps on every accepted change. That scalar is a change *detector*
//! and not an identity: it moves when nothing a cache reads moved, it moves for
//! a language the cache does not serve, and it can never match across two
//! checkouts of the same content. Every edit therefore threw away every
//! workspace relation in the process.
//!
//! A [`WorkspaceContentIdentity`] answers the question the caches actually ask:
//! "is the analyzed content this value was derived from still exactly the
//! content in front of me?". It is a digest over the analyzed file set's
//! (workspace-relative path, content identity) pairs, folded together with the
//! per-language analysis epoch and the analyzer configuration fingerprint, and
//! it carries no absolute path and no generation counter. Two byte-equal
//! checkouts at different roots produce the same identity, an edit to a
//! JavaScript file leaves the Python identity untouched, and a no-op update
//! leaves every identity untouched.
//!
//! The identity is per language, and a cache asks for the scope it serves:
//!
//! * the structural index serves one language and takes that language's entry;
//! * a usage-ranking graph serves the ecosystems its seeds belong to and takes
//!   the entries of the languages in those ecosystems;
//! * the direct-import topology is whole-workspace and takes every entry.
//!
//! A scope with no entries is not an error and not an empty digest: it is
//! `None`, and a cache that cannot obtain an identity must rebuild and record
//! [`crate::analyzer::invalidation::InvalidationReason::ContentIdentityEvidenceMissing`]
//! rather than reuse a value it cannot prove current.

use std::fmt;

use crate::analyzer::Language;
use crate::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use git2::Oid;

/// Domain for the per-language digest of one analyzed file set.
const FILE_SET_DOMAIN: &[u8] = b"bifrost-workspace-content:file-set:v1";
/// Domain for the per-language identity that folds the file set together with
/// the language epoch and the analyzer configuration.
const LANGUAGE_DOMAIN: &[u8] = b"bifrost-workspace-content:language:v1";
/// Domain for a multi-language scope identity.
const SCOPE_DOMAIN: &[u8] = b"bifrost-workspace-content:scope:v1";

/// The content identity of one analyzed-file scope.
///
/// This type is public only because [`crate::analyzer::IAnalyzer`] is an
/// extension boundary; it is an opaque comparison token with no accessible
/// structure beyond its digest.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceContentIdentity {
    digest: StableDigest,
}

impl WorkspaceContentIdentity {
    pub(crate) const fn from_digest(digest: StableDigest) -> Self {
        Self { digest }
    }

    pub(crate) const fn digest(self) -> StableDigest {
        self.digest
    }

    /// The stand-in identity used when a cache has to name an artifact whose
    /// content identity the analyzer could not state.
    ///
    /// It is a digest of a fixed domain string, so it names "no evidence" and
    /// can never be produced by an analyzed file set. It exists only so that
    /// [`crate::analyzer::invalidation::InvalidationReason::ContentIdentityEvidenceMissing`]
    /// can carry a well-formed artifact identity; nothing is ever keyed by it.
    pub(crate) fn unattested() -> Self {
        Self::from_digest(StableDigest::sha256(
            b"bifrost-workspace-content:unattested:v1",
        ))
    }

    /// A synthetic identity for tests that exercise cache mechanics without an
    /// analyzer behind them.
    #[cfg(test)]
    pub(crate) fn for_test(seed: u64) -> Self {
        let mut hasher = CanonicalHasher::new(b"bifrost-workspace-content:test:v1");
        hasher.value(&seed.to_be_bytes());
        Self::from_digest(StableDigest::from_array(hasher.finish()))
    }
}

impl fmt::Display for WorkspaceContentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.digest.fmt(formatter)
    }
}

/// Every language scope one analyzer snapshot can answer for, in language
/// order.
///
/// A composite analyzer publishes one entry per delegate; a single-language
/// analyzer publishes exactly one. The ordering is the enum's own, so a scope
/// digest does not depend on the order delegates happened to be built in.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceContentIdentities {
    entries: Box<[(Language, StableDigest)]>,
}

impl WorkspaceContentIdentities {
    pub(crate) fn new(entries: impl IntoIterator<Item = (Language, StableDigest)>) -> Self {
        let mut entries = entries.into_iter().collect::<Vec<_>>();
        entries.sort_by_key(|(language, _)| *language);
        entries.dedup_by_key(|(language, _)| *language);
        Self {
            entries: entries.into_boxed_slice(),
        }
    }

    /// The identity of every language this analyzer serves.
    pub(crate) fn whole_workspace(&self) -> Option<WorkspaceContentIdentity> {
        self.scope(|_| true)
    }

    /// The identity of exactly one language's analyzed file set.
    pub(crate) fn language(&self, language: Language) -> Option<WorkspaceContentIdentity> {
        self.scope(|candidate| candidate == language)
    }

    /// The identity of the languages `accept` selects.
    ///
    /// `None` when the analyzer holds no entry the predicate accepts: a cache
    /// keyed on an empty scope would compare equal across unrelated workspaces,
    /// which is precisely the undersized reuse this milestone forbids.
    pub(crate) fn scope(
        &self,
        accept: impl Fn(Language) -> bool,
    ) -> Option<WorkspaceContentIdentity> {
        let mut hasher = CanonicalHasher::new(SCOPE_DOMAIN);
        let mut selected = 0_u64;
        for (language, digest) in self.entries.iter() {
            if !accept(*language) {
                continue;
            }
            selected = selected.saturating_add(1);
            hasher.field(language.config_label(), digest.as_bytes());
        }
        (selected > 0).then(|| {
            WorkspaceContentIdentity::from_digest(StableDigest::from_array(hasher.finish()))
        })
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[(Language, StableDigest)] {
        &self.entries
    }
}

/// Fold one analyzed file set into a digest.
///
/// `entries` are (workspace-relative path, content identity) pairs. The caller
/// supplies them in any order; this sorts by the normalized relative path so
/// the digest is a function of the set and not of the map's iteration order.
/// No absolute path enters the digest.
pub(crate) fn analyzed_file_set_digest(
    entries: impl IntoIterator<Item = (String, Oid)>,
) -> StableDigest {
    analyzed_file_set_digest_with_overlays(
        entries
            .into_iter()
            .map(|(path, content)| (path, content, false)),
    )
}

/// The marker an overlaid path contributes instead of its blob identity.
const OVERLAID_BY_PROJECT: &[u8] = b"overlaid-by-project";

/// [`analyzed_file_set_digest`], with the third element of each entry saying
/// that the caller takes this path's content from the project's overlay set
/// rather than from the analyzed file set. See
/// [`crate::analyzer::store::liveness::LiveSnapshot::content_digest`].
pub(crate) fn analyzed_file_set_digest_with_overlays(
    entries: impl IntoIterator<Item = (String, Oid, bool)>,
) -> StableDigest {
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut hasher = CanonicalHasher::new(FILE_SET_DOMAIN);
    hasher.value(
        &u64::try_from(entries.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (path, content, overlaid) in entries {
        if overlaid {
            hasher.field(&path, OVERLAID_BY_PROJECT);
        } else {
            hasher.field(&path, content.as_bytes());
        }
    }
    StableDigest::from_array(hasher.finish())
}

/// Everything except the file set that decides what a derived value over one
/// language's analyzed content means.
///
/// `epoch` is the language's analysis epoch (grammar fingerprint plus query
/// files plus store salt), so a grammar upgrade rotates every identity built
/// on this base even though no file changed. `configuration` is the analyzer
/// configuration fingerprint, so a configuration change can never be answered
/// from a value derived under the previous one.
///
/// This half is derived once per analyzer because formatting a configuration
/// is not free; [`language_content_identity`] folds in the file set, which is
/// the half that moves.
pub(crate) fn language_identity_base(
    language: Language,
    epoch: &[u8],
    configuration: StableDigest,
) -> StableDigest {
    let mut hasher = CanonicalHasher::new(LANGUAGE_DOMAIN);
    hasher.field("language", language.config_label().as_bytes());
    hasher.field("epoch", epoch);
    hasher.field("configuration", configuration.as_bytes());
    StableDigest::from_array(hasher.finish())
}

/// One language's content identity: its [`language_identity_base`] folded with
/// the digest of the exact file set the analyzer indexed, and with the unsaved
/// buffers the project layers over this language's files.
///
/// `overlays` are the project's overlay entries for this language only, in
/// workspace-relative path order, so an unsaved edit to a TypeScript buffer
/// does not rotate the Java identity. They are folded in separately from the
/// file set because the project knows them immediately and the analyzer's live
/// path map learns them lazily.
pub(crate) fn language_content_identity<'a>(
    base: StableDigest,
    file_set: StableDigest,
    overlays: impl IntoIterator<Item = (&'a str, &'a [u8; 32])>,
) -> StableDigest {
    let mut hasher = CanonicalHasher::new(LANGUAGE_DOMAIN);
    hasher.field("base", base.as_bytes());
    hasher.field("file_set", file_set.as_bytes());
    hasher.value(b"overlays");
    for (path, digest) in overlays {
        hasher.field(path, digest);
    }
    StableDigest::from_array(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(byte: u8) -> Oid {
        Oid::from_bytes(&[byte; 20]).expect("twenty bytes is a valid object id")
    }

    #[test]
    fn a_file_set_digest_is_a_function_of_the_set_and_not_of_its_order() {
        let forward = analyzed_file_set_digest([
            ("src/a.rs".to_string(), oid(1)),
            ("src/b.rs".to_string(), oid(2)),
        ]);
        let reversed = analyzed_file_set_digest([
            ("src/b.rs".to_string(), oid(2)),
            ("src/a.rs".to_string(), oid(1)),
        ]);
        assert_eq!(forward, reversed);
    }

    #[test]
    fn moving_content_between_two_paths_changes_the_file_set_digest() {
        let before = analyzed_file_set_digest([
            ("src/a.rs".to_string(), oid(1)),
            ("src/b.rs".to_string(), oid(2)),
        ]);
        let after = analyzed_file_set_digest([
            ("src/a.rs".to_string(), oid(2)),
            ("src/b.rs".to_string(), oid(1)),
        ]);
        assert_ne!(before, after);
    }

    #[test]
    fn an_epoch_or_configuration_change_rotates_a_language_identity() {
        let file_set = analyzed_file_set_digest([("src/a.rs".to_string(), oid(1))]);
        let configuration = StableDigest::sha256(b"configuration");
        let identity_for = |language, epoch: &[u8], configuration| {
            language_content_identity(
                language_identity_base(language, epoch, configuration),
                file_set,
                [],
            )
        };

        let identity = identity_for(Language::Rust, b"epoch-1", configuration);
        assert_ne!(
            identity,
            identity_for(Language::Rust, b"epoch-2", configuration)
        );
        assert_ne!(
            identity,
            identity_for(
                Language::Rust,
                b"epoch-1",
                StableDigest::sha256(b"other-configuration"),
            )
        );
        assert_ne!(
            identity,
            identity_for(Language::Go, b"epoch-1", configuration)
        );
        assert_ne!(
            identity,
            language_content_identity(
                language_identity_base(Language::Rust, b"epoch-1", configuration),
                analyzed_file_set_digest([("src/a.rs".to_string(), oid(2))]),
                [],
            ),
            "a content change must rotate the identity"
        );
    }

    #[test]
    fn a_scope_reads_only_the_languages_it_names() {
        let identities = WorkspaceContentIdentities::new([
            (Language::Rust, StableDigest::sha256(b"rust")),
            (Language::Python, StableDigest::sha256(b"python")),
        ]);
        let edited = WorkspaceContentIdentities::new([
            (Language::Rust, StableDigest::sha256(b"rust-edited")),
            (Language::Python, StableDigest::sha256(b"python")),
        ]);

        assert_eq!(
            identities.language(Language::Python),
            edited.language(Language::Python)
        );
        assert_ne!(
            identities.language(Language::Rust),
            edited.language(Language::Rust)
        );
        assert_ne!(identities.whole_workspace(), edited.whole_workspace());
    }

    #[test]
    fn an_empty_scope_has_no_identity() {
        let identities =
            WorkspaceContentIdentities::new([(Language::Rust, StableDigest::sha256(b"rust"))]);
        assert_eq!(None, identities.language(Language::Java));
        assert_eq!(
            None,
            WorkspaceContentIdentities::new([]).whole_workspace(),
            "an analyzer with no language scope cannot prove any reuse"
        );
    }

    #[test]
    fn a_single_language_analyzer_scopes_its_whole_workspace_to_that_language() {
        let identities =
            WorkspaceContentIdentities::new([(Language::Rust, StableDigest::sha256(b"rust"))]);
        assert_eq!(
            identities.language(Language::Rust),
            identities.whole_workspace()
        );
    }
}
