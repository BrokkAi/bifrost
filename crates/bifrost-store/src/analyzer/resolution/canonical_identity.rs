//! Content keys behind query-local runtime aliases.

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use crate::hash::HashMap;

use super::model::{BindingFragmentId, BindingNodeId, PartialPathId, SemanticId};

/// A demand for the content behind one typed runtime alias. The kind is
/// explicit: the same integer may name a semantic, a node and a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolutionIdentityDigestKey {
    Semantic(SemanticId),
    Node(BindingNodeId),
    Path(PartialPathId),
    Fragment(BindingFragmentId),
}

macro_rules! identity_digest_key {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for ResolutionIdentityDigestKey {
            fn from(identity: $ty) -> Self {
                Self::$variant(identity)
            }
        }
        impl From<&$ty> for ResolutionIdentityDigestKey {
            fn from(identity: &$ty) -> Self {
                Self::$variant(*identity)
            }
        }
    };
}
identity_digest_key!(SemanticId, Semantic);
identity_digest_key!(BindingNodeId, Node);
identity_digest_key!(PartialPathId, Path);
identity_digest_key!(BindingFragmentId, Fragment);

impl ResolutionIdentityDigestKey {
    pub(crate) fn context_number(self) -> Option<u64> {
        match self {
            Self::Semantic(value) if value.is_context_local() => value.operation_local_number(),
            Self::Node(value) if value.is_context_local() => value.operation_local_number(),
            Self::Path(value) if value.is_context_local() => value.operation_local_number(),
            _ => None,
        }
        .map(|number| number & !super::model::CONTEXT_OPERATION_BASE)
    }

    pub(crate) fn operation_number(self) -> Option<u64> {
        match self {
            Self::Semantic(value) if !value.is_context_local() => value.operation_local_number(),
            Self::Node(value) if !value.is_context_local() => value.operation_local_number(),
            Self::Path(value) if !value.is_context_local() => value.operation_local_number(),
            _ => None,
        }
    }
}

/// Hash identity-bearing fields through their content authority. Raw byte
/// fields are for content, never the encounter-order alias naming that content.
pub(crate) trait CanonicalIdentityHasher {
    fn identity_field(
        &mut self,
        name: &str,
        identity: impl Into<ResolutionIdentityDigestKey>,
        resolve: impl FnMut(ResolutionIdentityDigestKey) -> crate::analyzer::store::Result<[u8; 32]>,
    ) -> crate::analyzer::store::Result<()>;
}

impl CanonicalIdentityHasher for CanonicalHasher {
    fn identity_field(
        &mut self,
        name: &str,
        identity: impl Into<ResolutionIdentityDigestKey>,
        mut resolve: impl FnMut(ResolutionIdentityDigestKey) -> crate::analyzer::store::Result<[u8; 32]>,
    ) -> crate::analyzer::store::Result<()> {
        self.field(name, &resolve(identity.into())?);
        Ok(())
    }
}

/// A descriptor or reason input. Identity aliases require their content
/// authority; labels and producer-owned content never name runtime aliases.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CanonicalIdentityPart<'a> {
    Identity(ResolutionIdentityDigestKey),
    Label(&'a str),
    Content(&'a [u8]),
}

impl CanonicalIdentityPart<'_> {
    pub(crate) fn identity(identity: impl Into<ResolutionIdentityDigestKey>) -> Self {
        Self::Identity(identity.into())
    }
}

/// Shared hashing for selected bridges, context descriptors and reasons.
/// Language hooks supply typed fields; this builder owns their interpretation.
pub(crate) struct CanonicalIdentityDescriptor<R> {
    hash: CanonicalHasher,
    resolve: R,
}

impl<R> CanonicalIdentityDescriptor<R>
where
    R: FnMut(ResolutionIdentityDigestKey) -> crate::analyzer::store::Result<[u8; 32]>,
{
    pub(crate) fn new(domain: &[u8], resolve: R) -> Self {
        Self {
            hash: CanonicalHasher::new(domain),
            resolve,
        }
    }

    pub(crate) fn field(
        &mut self,
        name: &str,
        part: CanonicalIdentityPart<'_>,
    ) -> crate::analyzer::store::Result<()> {
        match part {
            CanonicalIdentityPart::Identity(key) => {
                self.hash.identity_field(name, key, &mut self.resolve)?;
            }
            CanonicalIdentityPart::Label(label) => self.hash.field(name, label.as_bytes()),
            CanonicalIdentityPart::Content(content) => self.hash.field(name, content),
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.hash.finish()
    }
}

/// Resolve selected bridge inputs through the shared context/source authority.
pub(crate) fn selected_identity_content_digest(
    identities: &super::selected_context::SelectedContextIdentities,
    source: &dyn super::batch::BatchResolutionFragmentSource,
    key: ResolutionIdentityDigestKey,
    cancellation: &crate::CancellationToken,
) -> crate::analyzer::store::Result<[u8; 32]> {
    if let Some(number) = key.context_number() {
        return Ok(identities
            .content_digest(number)
            .expect("context aliases are minted in this registry"));
    }
    source
        .identity_content_digest(key, cancellation)?
        .ok_or_else(|| {
            crate::analyzer::store::StoreError::new(format!(
                "selected bridge identity has no content authority: {key:?}"
            ))
        })
}

/// A query's encounter-order aliases, with their canonical keys in both
/// directions. Digests are canonical before admission, so resolving an alias
/// recursively reaches the already-resolved content of its dependencies.
#[derive(Clone, Debug, Default)]
pub(crate) struct CanonicalIdentityNumbers {
    numbers: HashMap<[u8; 32], u64>,
    digests: Vec<[u8; 32]>,
}

impl CanonicalIdentityNumbers {
    pub(crate) fn number(&mut self, digest: [u8; 32]) -> u64 {
        if let Some(&number) = self.numbers.get(&digest) {
            return number;
        }
        let number = u64::try_from(self.digests.len()).expect("a query's identity count fits u64");
        assert_eq!(self.numbers.len(), self.digests.len());
        self.digests.push(digest);
        assert!(self.numbers.insert(digest, number).is_none());
        number
    }

    pub(crate) fn digest(&self, number: u64) -> Option<[u8; 32]> {
        self.digests.get(usize::try_from(number).ok()?).copied()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }
}

/// Local content at one selected placement. Neither the mount ordinal nor
/// the catalog's runtime position belongs in this preimage.
pub(crate) fn mounted_identity_digest(
    kind: &[u8],
    mount: [u8; 32],
    identity: [u8; 32],
) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-resolution-mounted-content:v1");
    hash.field("kind", kind);
    hash.field("mount", &mount);
    hash.field("identity", &identity);
    hash.finish()
}
