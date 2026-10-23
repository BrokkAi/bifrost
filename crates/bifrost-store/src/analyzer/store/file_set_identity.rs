use crate::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use git2::Oid;

/// Domain for the per-language digest of one analyzed file set.
pub const FILE_SET_DOMAIN: &[u8] = b"bifrost-workspace-content:file-set:v1";

/// Fold one analyzed file set into a digest.
///
/// `entries` are (workspace-relative path, content identity) pairs. The caller
/// supplies them in any order; this sorts by the normalized relative path so
/// the digest is a function of the set and not of the map's iteration order.
/// No absolute path enters the digest.
pub fn analyzed_file_set_digest(entries: impl IntoIterator<Item = (String, Oid)>) -> StableDigest {
    analyzed_file_set_digest_with_overlays(
        entries
            .into_iter()
            .map(|(path, content)| (path, content, false)),
    )
}

/// The marker an overlaid path contributes instead of its blob identity.
pub const OVERLAID_BY_PROJECT: &[u8] = b"overlaid-by-project";

/// [`analyzed_file_set_digest`], with the third element of each entry saying
/// that the caller takes this path's content from the project's overlay set
/// rather than from the analyzed file set. See
/// [`crate::analyzer::store::liveness::LiveSnapshot::content_digest`].
pub fn analyzed_file_set_digest_with_overlays(
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
