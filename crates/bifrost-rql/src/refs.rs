//! Bounded names for host-registered query inputs.

use brokk_bifrost_core::analyzer::identifier::IdentifierError;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

pub const MAX_PROTOCOL_REF_BYTES: usize = 192;
pub const MAX_PROTOCOL_NAMESPACE_BYTES: usize = 63;
pub const MAX_PROTOCOL_NAME_BYTES: usize = 128;
pub const MAX_VALUE_FLOW_PLAN_REF_BYTES: usize = 192;
pub const MAX_VALUE_FLOW_PLAN_NAMESPACE_BYTES: usize = 63;
pub const MAX_VALUE_FLOW_PLAN_NAME_BYTES: usize = 128;
pub const MAX_TAINT_RESULT_REF_BYTES: usize = 192;
pub const MAX_TAINT_RESULT_NAMESPACE_BYTES: usize = 63;
pub const MAX_TAINT_RESULT_NAME_BYTES: usize = 128;

pub type ProtocolNamespaceError = IdentifierError;
pub type ProtocolNameError = IdentifierError;
pub type ValueFlowPlanNamespaceError = IdentifierError;
pub type ValueFlowPlanNameError = IdentifierError;
pub type TaintResultNamespaceError = IdentifierError;
pub type TaintResultNameError = IdentifierError;

macro_rules! define_identifier {
    ($name:ident, $max_bytes:expr, $error:ty) => {
        brokk_bifrost_core::define_identifier! {
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            struct $name {
                max_bytes: $max_bytes,
                allow_dot: true,
                error: $error,
            }
        }
    };
}

define_identifier!(
    ProtocolNamespace,
    MAX_PROTOCOL_NAMESPACE_BYTES,
    ProtocolNamespaceError
);
define_identifier!(
    TaintResultNamespace,
    MAX_TAINT_RESULT_NAMESPACE_BYTES,
    TaintResultNamespaceError
);
define_identifier!(
    TaintResultName,
    MAX_TAINT_RESULT_NAME_BYTES,
    TaintResultNameError
);
define_identifier!(
    ValueFlowPlanNamespace,
    MAX_VALUE_FLOW_PLAN_NAMESPACE_BYTES,
    ValueFlowPlanNamespaceError
);
define_identifier!(
    ValueFlowPlanName,
    MAX_VALUE_FLOW_PLAN_NAME_BYTES,
    ValueFlowPlanNameError
);
define_identifier!(ProtocolName, MAX_PROTOCOL_NAME_BYTES, ProtocolNameError);

macro_rules! define_bounded_registration_ref {
    (
        $(#[$meta:meta])*
        $ref_type:ident,
        $error_type:ident,
        $namespace_type:ident,
        $namespace_error:ty,
        $name_type:ident,
        $name_error:ty,
        $max_ref_bytes:expr,
        $label:literal,
        $expecting:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $ref_type {
            namespace: $namespace_type,
            name: $name_type,
        }

        impl $ref_type {
            pub fn new(
                namespace: impl AsRef<str>,
                name: impl AsRef<str>,
            ) -> Result<Self, $error_type> {
                let namespace = $namespace_type::new(namespace).map_err($error_type::Namespace)?;
                let name = $name_type::new(name).map_err($error_type::Name)?;
                let total = namespace
                    .as_str()
                    .len()
                    .checked_add(1)
                    .and_then(|length| length.checked_add(name.as_str().len()))
                    .ok_or($error_type::TooLong {
                        max_bytes: $max_ref_bytes,
                    })?;
                if total > $max_ref_bytes {
                    return Err($error_type::TooLong {
                        max_bytes: $max_ref_bytes,
                    });
                }
                Ok(Self { namespace, name })
            }

            pub fn namespace(&self) -> &str {
                self.namespace.as_str()
            }

            pub fn name(&self) -> &str {
                self.name.as_str()
            }
        }

        impl fmt::Display for $ref_type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}:{}", self.namespace, self.name)
            }
        }

        impl FromStr for $ref_type {
            type Err = $error_type;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() > $max_ref_bytes {
                    return Err($error_type::TooLong {
                        max_bytes: $max_ref_bytes,
                    });
                }
                let (namespace, name) = value
                    .split_once(':')
                    .ok_or($error_type::MissingSeparator)?;
                Self::new(namespace, name)
            }
        }

        impl Serialize for $ref_type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ref_type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct RefVisitor;

                impl Visitor<'_> for RefVisitor {
                    type Value = $ref_type;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $ref_type::from_str(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(RefVisitor)
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $error_type {
            MissingSeparator,
            TooLong { max_bytes: usize },
            Namespace($namespace_error),
            Name($name_error),
        }

        impl fmt::Display for $error_type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::MissingSeparator => write!(
                        formatter,
                        "{} reference must use namespace:name form",
                        $label
                    ),
                    Self::TooLong { max_bytes } => write!(
                        formatter,
                        "{} reference must be at most {max_bytes} bytes",
                        $label
                    ),
                    Self::Namespace(error) => {
                        write!(formatter, "invalid {} namespace: {error}", $label)
                    }
                    Self::Name(error) => write!(formatter, "invalid {} name: {error}", $label),
                }
            }
        }

        impl std::error::Error for $error_type {}
    };
}

define_bounded_registration_ref! {
    /// A bounded host-defined alias for one pre-resolved protocol registration.
    ProtocolRef,
    ProtocolRefError,
    ProtocolNamespace,
    ProtocolNamespaceError,
    ProtocolName,
    ProtocolNameError,
    MAX_PROTOCOL_REF_BYTES,
    "protocol",
    "a bounded protocol reference in namespace:name form"
}

define_bounded_registration_ref! {
    /// A bounded host-defined alias for retained production taint results.
    TaintResultRef,
    TaintResultRefError,
    TaintResultNamespace,
    TaintResultNamespaceError,
    TaintResultName,
    TaintResultNameError,
    MAX_TAINT_RESULT_REF_BYTES,
    "taint result",
    "a bounded taint result reference in namespace:name form"
}

define_bounded_registration_ref! {
    /// A bounded host-defined alias for one immutable value-flow plan.
    ValueFlowPlanRef,
    ValueFlowPlanRefError,
    ValueFlowPlanNamespace,
    ValueFlowPlanNamespaceError,
    ValueFlowPlanName,
    ValueFlowPlanNameError,
    MAX_VALUE_FLOW_PLAN_REF_BYTES,
    "value-flow plan",
    "a bounded value-flow plan reference in namespace:name form"
}
