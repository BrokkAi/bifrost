use std::fmt;

use serde::{Serialize, Serializer};

use crate::analyzer::canonical_hash::{hash_domain_bytes, write_lower_hex};

const TYPESTATE_PROTOCOL_DOMAIN: &[u8] = b"bifrost-typestate-protocol/v1";
const TYPESTATE_BINDING_PLAN_DOMAIN: &[u8] = b"bifrost-typestate-binding-plan/v1";
const TYPESTATE_BINDING_SUMMARY_DOMAIN: &[u8] = b"bifrost-typestate-binding-summary/v1";

macro_rules! define_typestate_hash {
    ($(#[$attribute:meta])* $name:ident, $domain:ident) => {
        $(#[$attribute])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap a digest already produced by the owning compiler.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Hash canonical schema-version-1 bytes under this identity's
            /// distinct domain.
            pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
                Self(hash_domain_bytes($domain, bytes))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_lower_hex(&self.0, formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }
    }
}

define_typestate_hash!(
    /// Canonical identity of one compiled internal finite-state protocol.
    ///
    /// The digest excludes policy presentation, language, selected program
    /// bindings, and run-local dense IDs. It is safe to use in downstream
    /// protocol-summary and policy-projection keys.
    TypestateProtocolHash,
    TYPESTATE_PROTOCOL_DOMAIN
);

define_typestate_hash!(
    /// Canonical identity of one pre-resolved semantic binding plan.
    ///
    /// The digest includes stable semantic subject and observation identities
    /// but excludes policy presentation and run-local dense IDs.
    TypestateBindingPlanHash,
    TYPESTATE_BINDING_PLAN_DOMAIN
);

define_typestate_hash!(
    /// Procedure-scoped propagation identity for reusable protocol summaries.
    ///
    /// This excludes bindings owned exclusively by unrelated procedures while
    /// retaining every local seed, event, terminal, subject, and quality that
    /// can change the summarized procedure's transfer or observations.
    TypestateBindingSummaryHash,
    TYPESTATE_BINDING_SUMMARY_DOMAIN
);
