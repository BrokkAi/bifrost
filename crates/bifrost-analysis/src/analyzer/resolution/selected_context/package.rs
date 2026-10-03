//! Selected package membership connects protected source stacks. It cannot
//! produce an external import/export bridge or bypass lexical scope choices.

use super::*;
use crate::analyzer::resolution::{LoweredPackageMember, LoweredPackageReference};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedPackageBridgeDescriptor {
    pub(super) source_fragment: BindingFragmentId,
    pub(super) target_fragment: BindingFragmentId,
    pub(super) language: Language,
    source_token: SemanticId,
    target_token: SemanticId,
    domain: SemanticId,
    lookup: SemanticId,
    completion: ResolutionCompletion,
}

impl SelectedPackageBridgeDescriptor {
    /// Both metadata rows must come from the operation's selected catalogs.
    /// Package identity and visibility are established by the language's SQL
    /// context reader before this constructor is called.
    pub(crate) fn new(
        source_fragment: BindingFragmentId,
        target_fragment: BindingFragmentId,
        language: Language,
        reference: &LoweredPackageReference,
        member: &LoweredPackageMember,
        completion: ResolutionCompletion,
    ) -> Self {
        assert_eq!(reference.domain, member.domain);
        assert_eq!(reference.lookup, member.lookup);
        assert_eq!(reference.namespace, member.namespace);
        assert!(reference.domain.shared_name_id().is_some());
        assert!(reference.lookup.shared_name_id().is_some());
        assert_ne!(language, Language::None);
        assert!(!completion.contains_reason(ResolutionIncompleteReason::Cancelled));
        Self {
            source_fragment,
            target_fragment,
            language,
            source_token: reference.token,
            target_token: member.token,
            domain: reference.domain,
            lookup: reference.lookup,
            completion,
        }
    }

    fn digest(&self, domain: &[u8]) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(domain);
        hash.field("source", &self.source_fragment.as_bytes());
        hash.field("target", &self.target_fragment.as_bytes());
        hash.field("language", self.language.config_label().as_bytes());
        hash.field("source_token", &self.source_token.as_bytes());
        hash.field("target_token", &self.target_token.as_bytes());
        hash.field("domain", &self.domain.as_bytes());
        hash.field("lookup", &self.lookup.as_bytes());
        hash.finish()
    }

    pub(crate) fn shared_identities(&self) -> [ResolutionSemanticIdentity; 2] {
        [self.domain, self.lookup].map(|semantic| {
            ResolutionSemanticIdentity::Shared(
                semantic.shared_name_id().expect("shared package symbol"),
            )
        })
    }

    /// The bridge changes only the protected stack. Source paths own lexical
    /// precedence, namespace admission, target identity and omitted-binder gaps.
    pub(crate) fn compile(
        &self,
        identities: &SelectedContextIdentities,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Option<(CandidatePathIdentity, PartialPath)> {
        if cancellation.is_cancelled() || !session.scope_step() {
            return None;
        }
        let path = identities.path(self.digest(b"bifrost-selected-package-path:v1"));
        let tail = identities.stack_variable(self.digest(b"bifrost-selected-package-tail:v1"));
        let root = BindingNodeId::universal_root();
        Some((
            CandidatePathIdentity::new(self.source_fragment, path),
            PartialPath::new(
                EndpointSignature::new(
                    root,
                    StackPattern::open([self.domain, self.source_token, self.lookup], tail),
                    StackPattern::closed([]),
                ),
                EndpointSignature::new(
                    root,
                    StackPattern::open([self.lookup, self.domain, self.target_token], tail),
                    StackPattern::closed([]),
                ),
                [],
                [],
                self.completion.clone(),
            ),
        ))
    }
}
