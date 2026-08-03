//! Host-owned semantic-analysis registrations and execution-local query capabilities.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::NonZeroU64;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::identifier::define_identifier;
use crate::analyzer::taint::ProductionTaintAnalysisResult;
use crate::analyzer::semantic::{
    LengthDelimitedDigest, ProcedureHandle, SemanticArtifact, SemanticArtifactKey,
};
use crate::analyzer::typestate::{
    CompiledProtocol, ProductionTypestateSummaryLease, ProductionTypestateSummaryRepository,
    TypestateBindingPlan, TypestateBindingPlanHash, TypestateProtocolHash,
};
use crate::analyzer::value_flow::ValueFlowPlan;
use crate::cancellation::CancellationToken;

pub const MAX_PROTOCOL_REFS: usize = 256;
pub const MAX_PROTOCOL_REGISTRATIONS: usize = 128;
pub const MAX_RETAINED_PROTOCOL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RETAINED_BINDING_PLAN_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RETAINED_REGISTRATION_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PROTOCOL_REF_BYTES: usize = 192;
pub const MAX_PROTOCOL_NAMESPACE_BYTES: usize = 63;
pub const MAX_PROTOCOL_NAME_BYTES: usize = 128;
pub const MAX_REGISTRATION_ARTIFACT_SOURCE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_QUERY_REGISTRATION_VALIDATION_ARTIFACTS: usize = 256;
pub const MAX_QUERY_REGISTRATION_VALIDATION_SOURCE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_VALUE_FLOW_PLAN_REFS: usize = 256;
pub const MAX_VALUE_FLOW_PLAN_REGISTRATIONS: usize = 128;
pub const MAX_RETAINED_VALUE_FLOW_PLAN_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RETAINED_VALUE_FLOW_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_VALUE_FLOW_PLAN_REF_BYTES: usize = 192;
pub const MAX_VALUE_FLOW_PLAN_NAMESPACE_BYTES: usize = 63;
pub const MAX_VALUE_FLOW_PLAN_NAME_BYTES: usize = 128;
pub const MAX_TAINT_RESULT_REFS: usize = 256;
pub const MAX_TAINT_RESULT_REGISTRATIONS: usize = 128;
pub const MAX_TAINT_RESULTS_PER_REGISTRATION: usize = 256;
pub const MAX_RETAINED_TAINT_PLAN_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RETAINED_TAINT_REPORT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RETAINED_TAINT_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TAINT_RESULT_REF_BYTES: usize = 192;
pub const MAX_TAINT_RESULT_NAMESPACE_BYTES: usize = 63;
pub const MAX_TAINT_RESULT_NAME_BYTES: usize = 128;

pub type ProtocolNamespaceError = crate::analyzer::identifier::IdentifierError;
pub type ProtocolNameError = crate::analyzer::identifier::IdentifierError;
pub type ValueFlowPlanNamespaceError = crate::analyzer::identifier::IdentifierError;
pub type ValueFlowPlanNameError = crate::analyzer::identifier::IdentifierError;
pub type TaintResultNamespaceError = crate::analyzer::identifier::IdentifierError;
pub type TaintResultNameError = crate::analyzer::identifier::IdentifierError;

define_identifier! {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct ProtocolNamespace {
        max_bytes: MAX_PROTOCOL_NAMESPACE_BYTES,
        allow_dot: true,
        error: ProtocolNamespaceError,
    }
}

define_identifier! {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct TaintResultNamespace {
        max_bytes: MAX_TAINT_RESULT_NAMESPACE_BYTES,
        allow_dot: true,
        error: TaintResultNamespaceError,
    }
}

define_identifier! {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct TaintResultName {
        max_bytes: MAX_TAINT_RESULT_NAME_BYTES,
        allow_dot: true,
        error: TaintResultNameError,
    }
}

define_identifier! {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct ValueFlowPlanNamespace {
        max_bytes: MAX_VALUE_FLOW_PLAN_NAMESPACE_BYTES,
        allow_dot: true,
        error: ValueFlowPlanNamespaceError,
    }
}

define_identifier! {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct ValueFlowPlanName {
        max_bytes: MAX_VALUE_FLOW_PLAN_NAME_BYTES,
        allow_dot: true,
        error: ValueFlowPlanNameError,
    }
}

define_identifier! {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct ProtocolName {
        max_bytes: MAX_PROTOCOL_NAME_BYTES,
        allow_dot: true,
        error: ProtocolNameError,
    }
}

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

/// One immutable host registration. Semantic handles never cross the wire.
#[derive(Debug)]
pub struct ProtocolRegistration {
    workspace_generation: u64,
    expected_root: ProcedureHandle,
    protocol: Arc<CompiledProtocol>,
    bindings: Arc<TypestateBindingPlan>,
    artifact_keys: Box<[SemanticArtifactKey]>,
    retained_artifact_bytes: usize,
}

impl ProtocolRegistration {
    pub fn new(
        workspace_generation: u64,
        expected_root: ProcedureHandle,
        protocol: Arc<CompiledProtocol>,
        bindings: Arc<TypestateBindingPlan>,
    ) -> Result<Self, ProtocolRegistrationError> {
        if bindings.protocol_hash() != protocol.hash() {
            return Err(ProtocolRegistrationError::ProtocolHashMismatch {
                protocol: protocol.hash(),
                bindings: bindings.protocol_hash(),
            });
        }
        let mut artifact_keys = HashSet::new();
        let mut artifact_allocations = HashSet::<*const SemanticArtifact>::new();
        let mut retained_artifact_bytes = 0u64;
        {
            let mut retain_artifact = |artifact: &Arc<SemanticArtifact>| {
                artifact_keys.insert(artifact.key().clone());
                if artifact_allocations.insert(Arc::as_ptr(artifact)) {
                    retained_artifact_bytes = retained_artifact_bytes.saturating_add(
                        crate::analyzer::semantic::service::semantic_artifact_retained_bytes(
                            artifact,
                        ),
                    );
                }
            };
            retain_artifact(expected_root.artifact());
            bindings.for_each_retained_artifact(&mut retain_artifact);
        }
        bindings.for_each_retained_artifact_key(|key| {
            artifact_keys.insert(key.clone());
        });
        let mut artifact_keys = artifact_keys.into_iter().collect::<Vec<_>>();
        artifact_keys.sort_unstable();
        Ok(Self {
            workspace_generation,
            expected_root,
            protocol,
            bindings,
            artifact_keys: artifact_keys.into_boxed_slice(),
            retained_artifact_bytes: usize::try_from(retained_artifact_bytes).unwrap_or(usize::MAX),
        })
    }

    pub const fn workspace_generation(&self) -> u64 {
        self.workspace_generation
    }

    pub fn expected_root(&self) -> &ProcedureHandle {
        &self.expected_root
    }

    pub fn protocol(&self) -> &Arc<CompiledProtocol> {
        &self.protocol
    }

    pub fn bindings(&self) -> &Arc<TypestateBindingPlan> {
        &self.bindings
    }

    pub fn artifact_keys(&self) -> &[SemanticArtifactKey] {
        &self.artifact_keys
    }

    pub const fn retained_artifact_bytes(&self) -> usize {
        self.retained_artifact_bytes
    }

    fn identity(&self) -> ProtocolRegistrationIdentity {
        ProtocolRegistrationIdentity {
            workspace_generation: self.workspace_generation,
            expected_root: self.expected_root.clone(),
            protocol_hash: self.protocol.hash(),
            binding_plan_hash: self.bindings.hash(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProtocolRegistrationIdentity {
    workspace_generation: u64,
    expected_root: ProcedureHandle,
    protocol_hash: TypestateProtocolHash,
    binding_plan_hash: TypestateBindingPlanHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRegistrationError {
    ProtocolHashMismatch {
        protocol: TypestateProtocolHash,
        bindings: TypestateProtocolHash,
    },
}

impl fmt::Display for ProtocolRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolHashMismatch { protocol, bindings } => write!(
                formatter,
                "binding plan protocol hash {bindings} does not match compiled protocol {protocol}"
            ),
        }
    }
}

impl std::error::Error for ProtocolRegistrationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolRegistrationOutcome {
    Inserted,
    Aliased,
    Unchanged,
}

/// Per-host limits that may only tighten the public hard maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolRegistrationLimits {
    references: usize,
    registrations: usize,
    protocol_bytes: usize,
    binding_plan_bytes: usize,
    artifact_bytes: usize,
}

impl ProtocolRegistrationLimits {
    pub const fn bounded(
        references: usize,
        registrations: usize,
        protocol_bytes: usize,
        binding_plan_bytes: usize,
    ) -> Self {
        Self::bounded_with_artifact_bytes(
            references,
            registrations,
            protocol_bytes,
            binding_plan_bytes,
            MAX_RETAINED_REGISTRATION_ARTIFACT_BYTES,
        )
    }

    pub const fn bounded_with_artifact_bytes(
        references: usize,
        registrations: usize,
        protocol_bytes: usize,
        binding_plan_bytes: usize,
        artifact_bytes: usize,
    ) -> Self {
        Self {
            references: if references < MAX_PROTOCOL_REFS {
                references
            } else {
                MAX_PROTOCOL_REFS
            },
            registrations: if registrations < MAX_PROTOCOL_REGISTRATIONS {
                registrations
            } else {
                MAX_PROTOCOL_REGISTRATIONS
            },
            protocol_bytes: if protocol_bytes < MAX_RETAINED_PROTOCOL_BYTES {
                protocol_bytes
            } else {
                MAX_RETAINED_PROTOCOL_BYTES
            },
            binding_plan_bytes: if binding_plan_bytes < MAX_RETAINED_BINDING_PLAN_BYTES {
                binding_plan_bytes
            } else {
                MAX_RETAINED_BINDING_PLAN_BYTES
            },
            artifact_bytes: if artifact_bytes < MAX_RETAINED_REGISTRATION_ARTIFACT_BYTES {
                artifact_bytes
            } else {
                MAX_RETAINED_REGISTRATION_ARTIFACT_BYTES
            },
        }
    }
}

impl Default for ProtocolRegistrationLimits {
    fn default() -> Self {
        Self::bounded(
            MAX_PROTOCOL_REFS,
            MAX_PROTOCOL_REGISTRATIONS,
            MAX_RETAINED_PROTOCOL_BYTES,
            MAX_RETAINED_BINDING_PLAN_BYTES,
        )
    }
}

/// A bounded, cheaply clonable source for immutable execution snapshots.
#[derive(Debug, Clone)]
pub struct ProtocolRegistrationSet {
    by_ref: HashMap<ProtocolRef, Arc<ProtocolRegistration>>,
    by_identity: HashMap<ProtocolRegistrationIdentity, Arc<ProtocolRegistration>>,
    retained_protocol_bytes: usize,
    retained_binding_plan_bytes: usize,
    retained_artifact_bytes: usize,
    limits: ProtocolRegistrationLimits,
}

impl Default for ProtocolRegistrationSet {
    fn default() -> Self {
        Self::with_limits(ProtocolRegistrationLimits::default())
    }
}

impl ProtocolRegistrationSet {
    pub fn with_limits(limits: ProtocolRegistrationLimits) -> Self {
        Self {
            by_ref: HashMap::new(),
            by_identity: HashMap::new(),
            retained_protocol_bytes: 0,
            retained_binding_plan_bytes: 0,
            retained_artifact_bytes: 0,
            limits,
        }
    }

    pub fn register(
        &mut self,
        protocol_ref: ProtocolRef,
        registration: ProtocolRegistration,
    ) -> Result<ProtocolRegistrationOutcome, ProtocolRegistrationSetError> {
        let identity = registration.identity();
        if let Some(existing) = self.by_ref.get(&protocol_ref) {
            return if existing.identity() == identity {
                Ok(ProtocolRegistrationOutcome::Unchanged)
            } else {
                Err(ProtocolRegistrationSetError::ReferenceConflict { protocol_ref })
            };
        }
        if self.by_ref.len() >= self.limits.references {
            return Err(ProtocolRegistrationSetError::TooManyReferences {
                maximum: self.limits.references,
            });
        }
        if let Some(existing) = self.by_identity.get(&identity) {
            self.by_ref.insert(protocol_ref, Arc::clone(existing));
            return Ok(ProtocolRegistrationOutcome::Aliased);
        }
        if self.by_identity.len() >= self.limits.registrations {
            return Err(ProtocolRegistrationSetError::TooManyRegistrations {
                maximum: self.limits.registrations,
            });
        }
        let protocol_bytes = registration.protocol.canonical_bytes().len();
        let binding_bytes = registration.bindings.canonical_bytes().len();
        let retained_protocol_bytes = self
            .retained_protocol_bytes
            .checked_add(protocol_bytes)
            .ok_or(ProtocolRegistrationSetError::RetainedProtocolBytes {
                maximum: self.limits.protocol_bytes,
            })?;
        if retained_protocol_bytes > self.limits.protocol_bytes {
            return Err(ProtocolRegistrationSetError::RetainedProtocolBytes {
                maximum: self.limits.protocol_bytes,
            });
        }
        let retained_binding_plan_bytes = self
            .retained_binding_plan_bytes
            .checked_add(binding_bytes)
            .ok_or(ProtocolRegistrationSetError::RetainedBindingPlanBytes {
                maximum: self.limits.binding_plan_bytes,
            })?;
        if retained_binding_plan_bytes > self.limits.binding_plan_bytes {
            return Err(ProtocolRegistrationSetError::RetainedBindingPlanBytes {
                maximum: self.limits.binding_plan_bytes,
            });
        }
        let retained_artifact_bytes = self
            .retained_artifact_bytes
            .checked_add(registration.retained_artifact_bytes())
            .ok_or(ProtocolRegistrationSetError::RetainedArtifactBytes {
                maximum: self.limits.artifact_bytes,
            })?;
        if retained_artifact_bytes > self.limits.artifact_bytes {
            return Err(ProtocolRegistrationSetError::RetainedArtifactBytes {
                maximum: self.limits.artifact_bytes,
            });
        }

        let registration = Arc::new(registration);
        self.by_ref.insert(protocol_ref, Arc::clone(&registration));
        self.by_identity.insert(identity, registration);
        self.retained_protocol_bytes = retained_protocol_bytes;
        self.retained_binding_plan_bytes = retained_binding_plan_bytes;
        self.retained_artifact_bytes = retained_artifact_bytes;
        Ok(ProtocolRegistrationOutcome::Inserted)
    }

    pub fn get(&self, protocol_ref: &ProtocolRef) -> Option<&Arc<ProtocolRegistration>> {
        self.by_ref.get(protocol_ref)
    }

    /// Remove one authored alias and release its unique retained registration
    /// once the final alias is gone.
    pub fn unregister(&mut self, protocol_ref: &ProtocolRef) -> bool {
        let Some(registration) = self.by_ref.remove(protocol_ref) else {
            return false;
        };
        if self
            .by_ref
            .values()
            .any(|candidate| Arc::ptr_eq(candidate, &registration))
        {
            return true;
        }

        let identity = registration.identity();
        let removed = self
            .by_identity
            .remove(&identity)
            .expect("registered alias must retain its identity entry");
        self.retained_protocol_bytes = self
            .retained_protocol_bytes
            .checked_sub(removed.protocol.canonical_bytes().len())
            .expect("retained protocol bytes must cover every unique registration");
        self.retained_binding_plan_bytes = self
            .retained_binding_plan_bytes
            .checked_sub(removed.bindings.canonical_bytes().len())
            .expect("retained binding bytes must cover every unique registration");
        self.retained_artifact_bytes = self
            .retained_artifact_bytes
            .checked_sub(removed.retained_artifact_bytes())
            .expect("retained artifact bytes must cover every unique registration");
        true
    }

    pub fn clear(&mut self) {
        self.by_ref.clear();
        self.by_identity.clear();
        self.retained_protocol_bytes = 0;
        self.retained_binding_plan_bytes = 0;
        self.retained_artifact_bytes = 0;
    }

    pub fn reference_count(&self) -> usize {
        self.by_ref.len()
    }

    pub fn registration_count(&self) -> usize {
        self.by_identity.len()
    }

    pub const fn retained_protocol_bytes(&self) -> usize {
        self.retained_protocol_bytes
    }

    pub const fn retained_binding_plan_bytes(&self) -> usize {
        self.retained_binding_plan_bytes
    }

    pub const fn retained_artifact_bytes(&self) -> usize {
        self.retained_artifact_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRegistrationSetError {
    ReferenceConflict { protocol_ref: ProtocolRef },
    TooManyReferences { maximum: usize },
    TooManyRegistrations { maximum: usize },
    RetainedProtocolBytes { maximum: usize },
    RetainedBindingPlanBytes { maximum: usize },
    RetainedArtifactBytes { maximum: usize },
}

impl fmt::Display for ProtocolRegistrationSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceConflict { protocol_ref } => {
                write!(
                    formatter,
                    "protocol reference `{protocol_ref}` is already registered"
                )
            }
            Self::TooManyReferences { maximum } => {
                write!(
                    formatter,
                    "protocol registration set exceeds {maximum} references"
                )
            }
            Self::TooManyRegistrations { maximum } => write!(
                formatter,
                "protocol registration set exceeds {maximum} unique registrations"
            ),
            Self::RetainedProtocolBytes { maximum } => write!(
                formatter,
                "protocol registration set exceeds {maximum} retained protocol bytes"
            ),
            Self::RetainedBindingPlanBytes { maximum } => write!(
                formatter,
                "protocol registration set exceeds {maximum} retained binding-plan bytes"
            ),
            Self::RetainedArtifactBytes { maximum } => write!(
                formatter,
                "protocol registration set exceeds {maximum} retained semantic-artifact bytes"
            ),
        }
    }
}

impl std::error::Error for ProtocolRegistrationSetError {}

/// One immutable host registration for an already-resolved value-flow plan.
#[derive(Debug)]
pub struct ValueFlowPlanRegistration {
    workspace_generation: u64,
    plan: Arc<ValueFlowPlan>,
    identity: ValueFlowPlanRegistrationIdentity,
    artifact_keys: Box<[SemanticArtifactKey]>,
    retained_artifact_bytes: usize,
}

impl ValueFlowPlanRegistration {
    pub fn new(workspace_generation: u64, plan: Arc<ValueFlowPlan>) -> Self {
        let identity = ValueFlowPlanRegistrationIdentity {
            workspace_generation,
            plan_digest: value_flow_plan_digest(&plan),
        };
        let mut artifact_keys = HashSet::new();
        let mut artifact_allocations = HashSet::<*const SemanticArtifact>::new();
        let mut retained_artifact_bytes = 0u64;
        plan.for_each_retained_artifact(|artifact| {
            artifact_keys.insert(artifact.key().clone());
            if artifact_allocations.insert(Arc::as_ptr(artifact)) {
                retained_artifact_bytes = retained_artifact_bytes.saturating_add(
                    crate::analyzer::semantic::service::semantic_artifact_retained_bytes(artifact),
                );
            }
        });
        plan.for_each_retained_artifact_key(|key| {
            artifact_keys.insert(key.clone());
        });
        let mut artifact_keys = artifact_keys.into_iter().collect::<Vec<_>>();
        artifact_keys.sort_unstable();
        Self {
            workspace_generation,
            plan,
            identity,
            artifact_keys: artifact_keys.into_boxed_slice(),
            retained_artifact_bytes: usize::try_from(retained_artifact_bytes).unwrap_or(usize::MAX),
        }
    }

    pub const fn workspace_generation(&self) -> u64 {
        self.workspace_generation
    }

    pub fn expected_root(&self) -> &ProcedureHandle {
        self.plan.root()
    }

    pub fn plan(&self) -> &Arc<ValueFlowPlan> {
        &self.plan
    }

    pub fn artifact_keys(&self) -> &[SemanticArtifactKey] {
        &self.artifact_keys
    }

    pub const fn retained_artifact_bytes(&self) -> usize {
        self.retained_artifact_bytes
    }

    fn identity(&self) -> &ValueFlowPlanRegistrationIdentity {
        &self.identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ValueFlowPlanRegistrationIdentity {
    workspace_generation: u64,
    plan_digest: String,
}

#[derive(Default)]
struct ValueFlowPlanDigestHasher {
    bytes: Vec<u8>,
}

impl Hasher for ValueFlowPlanDigestHasher {
    fn finish(&self) -> u64 {
        let mut digest = LengthDelimitedDigest::new(b"bifrost.value_flow_plan.finish.v1");
        digest.push(&self.bytes);
        let rendered = digest.finish().to_string();
        u64::from_le_bytes(
            rendered.as_bytes()[..8]
                .try_into()
                .expect("rendered digest has at least eight bytes"),
        )
    }

    fn write(&mut self, bytes: &[u8]) {
        self.bytes
            .extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(bytes);
    }
}

fn value_flow_plan_digest(plan: &ValueFlowPlan) -> String {
    let mut hasher = ValueFlowPlanDigestHasher::default();
    plan.hash(&mut hasher);
    let mut digest = LengthDelimitedDigest::new(b"bifrost.value_flow_plan.registration.v1");
    digest.push(&hasher.bytes);
    digest.finish().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueFlowPlanRegistrationOutcome {
    Inserted,
    Aliased,
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueFlowPlanRegistrationLimits {
    references: usize,
    registrations: usize,
    plan_bytes: usize,
    artifact_bytes: usize,
}

impl ValueFlowPlanRegistrationLimits {
    pub const fn bounded(
        references: usize,
        registrations: usize,
        plan_bytes: usize,
        artifact_bytes: usize,
    ) -> Self {
        Self {
            references: if references < MAX_VALUE_FLOW_PLAN_REFS {
                references
            } else {
                MAX_VALUE_FLOW_PLAN_REFS
            },
            registrations: if registrations < MAX_VALUE_FLOW_PLAN_REGISTRATIONS {
                registrations
            } else {
                MAX_VALUE_FLOW_PLAN_REGISTRATIONS
            },
            plan_bytes: if plan_bytes < MAX_RETAINED_VALUE_FLOW_PLAN_BYTES {
                plan_bytes
            } else {
                MAX_RETAINED_VALUE_FLOW_PLAN_BYTES
            },
            artifact_bytes: if artifact_bytes < MAX_RETAINED_VALUE_FLOW_ARTIFACT_BYTES {
                artifact_bytes
            } else {
                MAX_RETAINED_VALUE_FLOW_ARTIFACT_BYTES
            },
        }
    }
}

impl Default for ValueFlowPlanRegistrationLimits {
    fn default() -> Self {
        Self::bounded(
            MAX_VALUE_FLOW_PLAN_REFS,
            MAX_VALUE_FLOW_PLAN_REGISTRATIONS,
            MAX_RETAINED_VALUE_FLOW_PLAN_BYTES,
            MAX_RETAINED_VALUE_FLOW_ARTIFACT_BYTES,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ValueFlowPlanRegistrationSet {
    by_ref: HashMap<ValueFlowPlanRef, Arc<ValueFlowPlanRegistration>>,
    by_identity: HashMap<ValueFlowPlanRegistrationIdentity, Arc<ValueFlowPlanRegistration>>,
    retained_plan_bytes: usize,
    retained_artifact_bytes: usize,
    limits: ValueFlowPlanRegistrationLimits,
}

impl Default for ValueFlowPlanRegistrationSet {
    fn default() -> Self {
        Self::with_limits(ValueFlowPlanRegistrationLimits::default())
    }
}

impl ValueFlowPlanRegistrationSet {
    pub fn with_limits(limits: ValueFlowPlanRegistrationLimits) -> Self {
        Self {
            by_ref: HashMap::new(),
            by_identity: HashMap::new(),
            retained_plan_bytes: 0,
            retained_artifact_bytes: 0,
            limits,
        }
    }

    pub fn register(
        &mut self,
        plan_ref: ValueFlowPlanRef,
        registration: ValueFlowPlanRegistration,
    ) -> Result<ValueFlowPlanRegistrationOutcome, ValueFlowPlanRegistrationSetError> {
        let identity = registration.identity().clone();
        if let Some(existing) = self.by_ref.get(&plan_ref) {
            return if existing.identity() == &identity {
                Ok(ValueFlowPlanRegistrationOutcome::Unchanged)
            } else {
                Err(ValueFlowPlanRegistrationSetError::ReferenceConflict { plan_ref })
            };
        }
        if self.by_ref.len() >= self.limits.references {
            return Err(ValueFlowPlanRegistrationSetError::TooManyReferences {
                maximum: self.limits.references,
            });
        }
        if let Some(existing) = self.by_identity.get(&identity) {
            self.by_ref.insert(plan_ref, Arc::clone(existing));
            return Ok(ValueFlowPlanRegistrationOutcome::Aliased);
        }
        if self.by_identity.len() >= self.limits.registrations {
            return Err(ValueFlowPlanRegistrationSetError::TooManyRegistrations {
                maximum: self.limits.registrations,
            });
        }
        let retained_plan_bytes = self
            .retained_plan_bytes
            .checked_add(registration.plan.retained_bytes())
            .ok_or(ValueFlowPlanRegistrationSetError::RetainedPlanBytes {
                maximum: self.limits.plan_bytes,
            })?;
        if retained_plan_bytes > self.limits.plan_bytes {
            return Err(ValueFlowPlanRegistrationSetError::RetainedPlanBytes {
                maximum: self.limits.plan_bytes,
            });
        }
        let retained_artifact_bytes = self
            .retained_artifact_bytes
            .checked_add(registration.retained_artifact_bytes())
            .ok_or(ValueFlowPlanRegistrationSetError::RetainedArtifactBytes {
                maximum: self.limits.artifact_bytes,
            })?;
        if retained_artifact_bytes > self.limits.artifact_bytes {
            return Err(ValueFlowPlanRegistrationSetError::RetainedArtifactBytes {
                maximum: self.limits.artifact_bytes,
            });
        }
        let registration = Arc::new(registration);
        self.by_ref.insert(plan_ref, Arc::clone(&registration));
        self.by_identity.insert(identity, registration);
        self.retained_plan_bytes = retained_plan_bytes;
        self.retained_artifact_bytes = retained_artifact_bytes;
        Ok(ValueFlowPlanRegistrationOutcome::Inserted)
    }

    pub fn get(&self, plan_ref: &ValueFlowPlanRef) -> Option<&Arc<ValueFlowPlanRegistration>> {
        self.by_ref.get(plan_ref)
    }

    pub fn unregister(&mut self, plan_ref: &ValueFlowPlanRef) -> bool {
        let Some(registration) = self.by_ref.remove(plan_ref) else {
            return false;
        };
        if self
            .by_ref
            .values()
            .any(|candidate| Arc::ptr_eq(candidate, &registration))
        {
            return true;
        }
        let removed = self
            .by_identity
            .remove(registration.identity())
            .expect("registered value-flow alias retains its identity entry");
        self.retained_plan_bytes = self
            .retained_plan_bytes
            .checked_sub(removed.plan.retained_bytes())
            .expect("retained plan bytes cover every unique registration");
        self.retained_artifact_bytes = self
            .retained_artifact_bytes
            .checked_sub(removed.retained_artifact_bytes())
            .expect("retained artifact bytes cover every unique flow registration");
        true
    }

    pub fn clear(&mut self) {
        self.by_ref.clear();
        self.by_identity.clear();
        self.retained_plan_bytes = 0;
        self.retained_artifact_bytes = 0;
    }

    pub fn reference_count(&self) -> usize {
        self.by_ref.len()
    }

    pub fn registration_count(&self) -> usize {
        self.by_identity.len()
    }

    pub const fn retained_plan_bytes(&self) -> usize {
        self.retained_plan_bytes
    }

    pub const fn retained_artifact_bytes(&self) -> usize {
        self.retained_artifact_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowPlanRegistrationSetError {
    ReferenceConflict { plan_ref: ValueFlowPlanRef },
    TooManyReferences { maximum: usize },
    TooManyRegistrations { maximum: usize },
    RetainedPlanBytes { maximum: usize },
    RetainedArtifactBytes { maximum: usize },
}

impl fmt::Display for ValueFlowPlanRegistrationSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceConflict { plan_ref } => {
                write!(
                    formatter,
                    "value-flow plan reference `{plan_ref}` is already registered"
                )
            }
            Self::TooManyReferences { maximum } => write!(
                formatter,
                "value-flow plan registration set exceeds {maximum} references"
            ),
            Self::TooManyRegistrations { maximum } => write!(
                formatter,
                "value-flow plan registration set exceeds {maximum} unique registrations"
            ),
            Self::RetainedPlanBytes { maximum } => write!(
                formatter,
                "value-flow plan registration set exceeds {maximum} retained plan bytes"
            ),
            Self::RetainedArtifactBytes { maximum } => write!(
                formatter,
                "value-flow plan registration set exceeds {maximum} retained semantic-artifact bytes"
            ),
        }
    }
}

impl std::error::Error for ValueFlowPlanRegistrationSetError {}

/// One immutable host registration containing retained production taint
/// results for one or more exact procedure roots.
#[derive(Debug)]
pub struct TaintResultRegistration {
    workspace_generation: u64,
    results: Box<[Arc<ProductionTaintAnalysisResult>]>,
    identity: TaintResultRegistrationIdentity,
    artifact_keys: Box<[SemanticArtifactKey]>,
    retained_plan_bytes: usize,
    retained_report_bytes: usize,
    retained_artifact_bytes: usize,
}

impl TaintResultRegistration {
    pub fn new(
        workspace_generation: u64,
        mut results: Vec<Arc<ProductionTaintAnalysisResult>>,
    ) -> Result<Self, TaintResultRegistrationError> {
        if results.is_empty() {
            return Err(TaintResultRegistrationError::Empty);
        }
        if results.len() > MAX_TAINT_RESULTS_PER_REGISTRATION {
            return Err(TaintResultRegistrationError::TooManyResults {
                maximum: MAX_TAINT_RESULTS_PER_REGISTRATION,
            });
        }
        if results.iter().any(|result| !result.plan_report_match()) {
            return Err(TaintResultRegistrationError::PlanReportMismatch);
        }
        results.sort_unstable_by(|left, right| {
            procedure_identity_cmp(left.expected_root(), right.expected_root())
        });
        if results
            .windows(2)
            .any(|pair| same_procedure_identity(pair[0].expected_root(), pair[1].expected_root()))
        {
            return Err(TaintResultRegistrationError::DuplicateRoot);
        }

        let mut artifact_keys = results
            .iter()
            .flat_map(|result| result.artifact_keys().iter().cloned())
            .collect::<Vec<_>>();
        artifact_keys.sort_unstable();
        artifact_keys.dedup();
        let retained_plan_bytes =
            checked_sum(results.iter().map(|result| result.retained_plan_bytes()))?;
        let retained_report_bytes =
            checked_sum(results.iter().map(|result| result.retained_report_bytes()))?;
        let retained_artifact_bytes = checked_sum(
            results
                .iter()
                .map(|result| result.retained_artifact_bytes()),
        )?;
        let identity = TaintResultRegistrationIdentity {
            workspace_generation,
            results: results
                .iter()
                .map(|result| result.registration_digest().to_owned().into_boxed_str())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        };
        Ok(Self {
            workspace_generation,
            results: results.into_boxed_slice(),
            identity,
            artifact_keys: artifact_keys.into_boxed_slice(),
            retained_plan_bytes,
            retained_report_bytes,
            retained_artifact_bytes,
        })
    }

    pub const fn workspace_generation(&self) -> u64 {
        self.workspace_generation
    }

    pub fn results(&self) -> &[Arc<ProductionTaintAnalysisResult>] {
        &self.results
    }

    pub fn artifact_keys(&self) -> &[SemanticArtifactKey] {
        &self.artifact_keys
    }

    pub const fn retained_plan_bytes(&self) -> usize {
        self.retained_plan_bytes
    }

    pub const fn retained_report_bytes(&self) -> usize {
        self.retained_report_bytes
    }

    pub const fn retained_artifact_bytes(&self) -> usize {
        self.retained_artifact_bytes
    }

    fn identity(&self) -> &TaintResultRegistrationIdentity {
        &self.identity
    }

    fn result_for_root(
        &self,
        expected_root: &ProcedureHandle,
    ) -> Option<&ProductionTaintAnalysisResult> {
        self.results
            .iter()
            .find(|result| same_procedure_identity(result.expected_root(), expected_root))
            .map(Arc::as_ref)
    }
}

fn checked_sum(
    mut values: impl Iterator<Item = usize>,
) -> Result<usize, TaintResultRegistrationError> {
    values.try_fold(0usize, |total, value| {
        total
            .checked_add(value)
            .ok_or(TaintResultRegistrationError::RetainedBytesOverflow)
    })
}

fn procedure_identity_cmp(left: &ProcedureHandle, right: &ProcedureHandle) -> std::cmp::Ordering {
    left.artifact()
        .key()
        .cmp(right.artifact().key())
        .then_with(|| left.semantics().locator().cmp(right.semantics().locator()))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TaintResultRegistrationIdentity {
    workspace_generation: u64,
    results: Box<[Box<str>]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintResultRegistrationError {
    Empty,
    TooManyResults { maximum: usize },
    DuplicateRoot,
    PlanReportMismatch,
    RetainedBytesOverflow,
}

impl fmt::Display for TaintResultRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("taint result registration must not be empty"),
            Self::TooManyResults { maximum } => write!(
                formatter,
                "taint result registration exceeds {maximum} procedure results"
            ),
            Self::DuplicateRoot => {
                formatter.write_str("taint result registration contains a duplicate procedure root")
            }
            Self::PlanReportMismatch => formatter
                .write_str("taint result registration contains a mismatched plan and report"),
            Self::RetainedBytesOverflow => {
                formatter.write_str("taint result retained-byte accounting overflowed")
            }
        }
    }
}

impl std::error::Error for TaintResultRegistrationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintResultRegistrationOutcome {
    Inserted,
    Aliased,
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaintResultRegistrationLimits {
    references: usize,
    registrations: usize,
    plan_bytes: usize,
    report_bytes: usize,
    artifact_bytes: usize,
}

impl TaintResultRegistrationLimits {
    pub const fn bounded(
        references: usize,
        registrations: usize,
        plan_bytes: usize,
        report_bytes: usize,
        artifact_bytes: usize,
    ) -> Self {
        Self {
            references: if references < MAX_TAINT_RESULT_REFS {
                references
            } else {
                MAX_TAINT_RESULT_REFS
            },
            registrations: if registrations < MAX_TAINT_RESULT_REGISTRATIONS {
                registrations
            } else {
                MAX_TAINT_RESULT_REGISTRATIONS
            },
            plan_bytes: if plan_bytes < MAX_RETAINED_TAINT_PLAN_BYTES {
                plan_bytes
            } else {
                MAX_RETAINED_TAINT_PLAN_BYTES
            },
            report_bytes: if report_bytes < MAX_RETAINED_TAINT_REPORT_BYTES {
                report_bytes
            } else {
                MAX_RETAINED_TAINT_REPORT_BYTES
            },
            artifact_bytes: if artifact_bytes < MAX_RETAINED_TAINT_ARTIFACT_BYTES {
                artifact_bytes
            } else {
                MAX_RETAINED_TAINT_ARTIFACT_BYTES
            },
        }
    }
}

impl Default for TaintResultRegistrationLimits {
    fn default() -> Self {
        Self::bounded(
            MAX_TAINT_RESULT_REFS,
            MAX_TAINT_RESULT_REGISTRATIONS,
            MAX_RETAINED_TAINT_PLAN_BYTES,
            MAX_RETAINED_TAINT_REPORT_BYTES,
            MAX_RETAINED_TAINT_ARTIFACT_BYTES,
        )
    }
}

#[derive(Debug, Clone)]
pub struct TaintResultRegistrationSet {
    by_ref: HashMap<TaintResultRef, Arc<TaintResultRegistration>>,
    by_identity: HashMap<TaintResultRegistrationIdentity, Arc<TaintResultRegistration>>,
    retained_plan_bytes: usize,
    retained_report_bytes: usize,
    retained_artifact_bytes: usize,
    limits: TaintResultRegistrationLimits,
}

impl Default for TaintResultRegistrationSet {
    fn default() -> Self {
        Self::with_limits(TaintResultRegistrationLimits::default())
    }
}

impl TaintResultRegistrationSet {
    pub fn with_limits(limits: TaintResultRegistrationLimits) -> Self {
        Self {
            by_ref: HashMap::new(),
            by_identity: HashMap::new(),
            retained_plan_bytes: 0,
            retained_report_bytes: 0,
            retained_artifact_bytes: 0,
            limits,
        }
    }

    pub fn register(
        &mut self,
        taint_ref: TaintResultRef,
        registration: TaintResultRegistration,
    ) -> Result<TaintResultRegistrationOutcome, TaintResultRegistrationSetError> {
        let identity = registration.identity().clone();
        if let Some(existing) = self.by_ref.get(&taint_ref) {
            return if existing.identity() == &identity {
                Ok(TaintResultRegistrationOutcome::Unchanged)
            } else {
                Err(TaintResultRegistrationSetError::ReferenceConflict { taint_ref })
            };
        }
        if self.by_ref.len() >= self.limits.references {
            return Err(TaintResultRegistrationSetError::TooManyReferences {
                maximum: self.limits.references,
            });
        }
        if let Some(existing) = self.by_identity.get(&identity) {
            self.by_ref.insert(taint_ref, Arc::clone(existing));
            return Ok(TaintResultRegistrationOutcome::Aliased);
        }
        if self.by_identity.len() >= self.limits.registrations {
            return Err(TaintResultRegistrationSetError::TooManyRegistrations {
                maximum: self.limits.registrations,
            });
        }
        let retained_plan_bytes = checked_registration_total(
            self.retained_plan_bytes,
            registration.retained_plan_bytes(),
            self.limits.plan_bytes,
            TaintResultRegistrationSetError::RetainedPlanBytes,
        )?;
        let retained_report_bytes = checked_registration_total(
            self.retained_report_bytes,
            registration.retained_report_bytes(),
            self.limits.report_bytes,
            TaintResultRegistrationSetError::RetainedReportBytes,
        )?;
        let retained_artifact_bytes = checked_registration_total(
            self.retained_artifact_bytes,
            registration.retained_artifact_bytes(),
            self.limits.artifact_bytes,
            TaintResultRegistrationSetError::RetainedArtifactBytes,
        )?;
        let registration = Arc::new(registration);
        self.by_ref.insert(taint_ref, Arc::clone(&registration));
        self.by_identity.insert(identity, registration);
        self.retained_plan_bytes = retained_plan_bytes;
        self.retained_report_bytes = retained_report_bytes;
        self.retained_artifact_bytes = retained_artifact_bytes;
        Ok(TaintResultRegistrationOutcome::Inserted)
    }

    pub fn get(&self, taint_ref: &TaintResultRef) -> Option<&Arc<TaintResultRegistration>> {
        self.by_ref.get(taint_ref)
    }

    pub fn unregister(&mut self, taint_ref: &TaintResultRef) -> bool {
        let Some(registration) = self.by_ref.remove(taint_ref) else {
            return false;
        };
        if self
            .by_ref
            .values()
            .any(|candidate| Arc::ptr_eq(candidate, &registration))
        {
            return true;
        }
        let removed = self
            .by_identity
            .remove(registration.identity())
            .expect("registered taint alias retains its identity entry");
        self.retained_plan_bytes = self
            .retained_plan_bytes
            .checked_sub(removed.retained_plan_bytes())
            .expect("retained plan bytes cover every taint registration");
        self.retained_report_bytes = self
            .retained_report_bytes
            .checked_sub(removed.retained_report_bytes())
            .expect("retained report bytes cover every taint registration");
        self.retained_artifact_bytes = self
            .retained_artifact_bytes
            .checked_sub(removed.retained_artifact_bytes())
            .expect("retained artifact bytes cover every taint registration");
        true
    }

    pub fn clear(&mut self) {
        self.by_ref.clear();
        self.by_identity.clear();
        self.retained_plan_bytes = 0;
        self.retained_report_bytes = 0;
        self.retained_artifact_bytes = 0;
    }

    pub fn reference_count(&self) -> usize {
        self.by_ref.len()
    }

    pub fn registration_count(&self) -> usize {
        self.by_identity.len()
    }

    pub const fn retained_plan_bytes(&self) -> usize {
        self.retained_plan_bytes
    }

    pub const fn retained_report_bytes(&self) -> usize {
        self.retained_report_bytes
    }

    pub const fn retained_artifact_bytes(&self) -> usize {
        self.retained_artifact_bytes
    }
}

fn checked_registration_total(
    current: usize,
    additional: usize,
    maximum: usize,
    error: fn(usize) -> TaintResultRegistrationSetError,
) -> Result<usize, TaintResultRegistrationSetError> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| error(maximum))?;
    if total > maximum {
        return Err(error(maximum));
    }
    Ok(total)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintResultRegistrationSetError {
    ReferenceConflict { taint_ref: TaintResultRef },
    TooManyReferences { maximum: usize },
    TooManyRegistrations { maximum: usize },
    RetainedPlanBytes(usize),
    RetainedReportBytes(usize),
    RetainedArtifactBytes(usize),
}

impl fmt::Display for TaintResultRegistrationSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceConflict { taint_ref } => {
                write!(
                    formatter,
                    "taint result reference `{taint_ref}` is already registered"
                )
            }
            Self::TooManyReferences { maximum } => write!(
                formatter,
                "taint result registration set exceeds {maximum} references"
            ),
            Self::TooManyRegistrations { maximum } => write!(
                formatter,
                "taint result registration set exceeds {maximum} unique registrations"
            ),
            Self::RetainedPlanBytes(maximum) => write!(
                formatter,
                "taint result registration set exceeds {maximum} retained plan bytes"
            ),
            Self::RetainedReportBytes(maximum) => write!(
                formatter,
                "taint result registration set exceeds {maximum} retained report bytes"
            ),
            Self::RetainedArtifactBytes(maximum) => write!(
                formatter,
                "taint result registration set exceeds {maximum} retained semantic-artifact bytes"
            ),
        }
    }
}

impl std::error::Error for TaintResultRegistrationSetError {}

/// An opaque value-flow capability valid only inside its issuing query context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueFlowPlanHandle {
    context_generation: NonZeroU64,
    slot: u32,
}

/// An opaque retained-taint capability valid only inside its issuing query context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaintResultHandle {
    context_generation: NonZeroU64,
    slot: u32,
}

/// An opaque capability that is valid only inside its issuing query context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolHandle {
    context_generation: NonZeroU64,
    slot: u32,
    protocol_hash: TypestateProtocolHash,
    binding_plan_hash: TypestateBindingPlanHash,
}

#[derive(Debug)]
pub struct QueryAnalysisContext {
    generation: NonZeroU64,
    workspace_generation: u64,
    by_ref: HashMap<ProtocolRef, ProtocolHandle>,
    registrations: Box<[Arc<ProtocolRegistration>]>,
    value_flow_by_ref: HashMap<ValueFlowPlanRef, ValueFlowPlanHandle>,
    value_flow_registrations: Box<[Arc<ValueFlowPlanRegistration>]>,
    taint_by_ref: HashMap<TaintResultRef, TaintResultHandle>,
    taint_registrations: Box<[Arc<TaintResultRegistration>]>,
    summary_lease: ProductionTypestateSummaryLease,
}

static NEXT_QUERY_ANALYSIS_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryAnalysisValidationLimits {
    max_artifacts: usize,
    max_source_bytes: usize,
}

impl QueryAnalysisValidationLimits {
    pub const fn new(max_artifacts: usize, max_source_bytes: usize) -> Self {
        Self {
            max_artifacts,
            max_source_bytes,
        }
    }
}

impl Default for QueryAnalysisValidationLimits {
    fn default() -> Self {
        Self::new(
            MAX_QUERY_REGISTRATION_VALIDATION_ARTIFACTS,
            MAX_QUERY_REGISTRATION_VALIDATION_SOURCE_BYTES,
        )
    }
}

struct QueryAnalysisValidationBudget {
    limits: QueryAnalysisValidationLimits,
    artifacts: usize,
    source_bytes: usize,
}

impl QueryAnalysisValidationBudget {
    const fn new(limits: QueryAnalysisValidationLimits) -> Self {
        Self {
            limits,
            artifacts: 0,
            source_bytes: 0,
        }
    }

    fn reserve_artifact(&mut self) -> Result<usize, QueryAnalysisContextError> {
        if self.artifacts >= self.limits.max_artifacts {
            return Err(QueryAnalysisContextError::ValidationBudgetExceeded {
                resource: "semantic artifacts",
                maximum: self.limits.max_artifacts,
            });
        }
        self.artifacts += 1;
        let remaining = self
            .limits
            .max_source_bytes
            .saturating_sub(self.source_bytes);
        if remaining == 0 {
            return Err(QueryAnalysisContextError::ValidationBudgetExceeded {
                resource: "semantic artifact source bytes",
                maximum: self.limits.max_source_bytes,
            });
        }
        Ok(remaining.min(MAX_REGISTRATION_ARTIFACT_SOURCE_BYTES))
    }

    fn charge_source_bytes(&mut self, bytes: usize) -> Result<(), QueryAnalysisContextError> {
        let source_bytes = self.source_bytes.checked_add(bytes).ok_or(
            QueryAnalysisContextError::ValidationBudgetExceeded {
                resource: "semantic artifact source bytes",
                maximum: self.limits.max_source_bytes,
            },
        )?;
        if source_bytes > self.limits.max_source_bytes {
            return Err(QueryAnalysisContextError::ValidationBudgetExceeded {
                resource: "semantic artifact source bytes",
                maximum: self.limits.max_source_bytes,
            });
        }
        self.source_bytes = source_bytes;
        Ok(())
    }
}

impl QueryAnalysisContext {
    pub fn new(
        workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        requested: &[ProtocolRef],
    ) -> Result<Self, QueryAnalysisContextError> {
        Self::new_with_validation(
            workspace,
            workspace_generation,
            registrations,
            requested,
            QueryAnalysisValidationLimits::default(),
            None,
        )
    }

    pub fn new_with_validation(
        workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        requested: &[ProtocolRef],
        validation_limits: QueryAnalysisValidationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, QueryAnalysisContextError> {
        let summaries = Arc::new(ProductionTypestateSummaryRepository::new());
        let summary_lease = summaries.lease(workspace_generation).map_err(|_| {
            QueryAnalysisContextError::WorkspaceGenerationMismatch {
                registered: summaries.generation().unwrap_or(workspace_generation),
                current: workspace_generation,
            }
        })?;
        Self::new_with_validation_and_summaries(
            workspace,
            workspace_generation,
            registrations,
            requested,
            validation_limits,
            cancellation,
            summary_lease,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_validation_and_summaries(
        workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        requested: &[ProtocolRef],
        validation_limits: QueryAnalysisValidationLimits,
        cancellation: Option<&CancellationToken>,
        summary_lease: ProductionTypestateSummaryLease,
    ) -> Result<Self, QueryAnalysisContextError> {
        let value_flow_registrations = ValueFlowPlanRegistrationSet::default();
        let taint_registrations = TaintResultRegistrationSet::default();
        Self::new_with_all_registrations_and_summaries(
            workspace,
            workspace_generation,
            registrations,
            requested,
            &value_flow_registrations,
            &[],
            &taint_registrations,
            &[],
            validation_limits,
            cancellation,
            summary_lease,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_all_registrations_and_summaries(
        workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        requested: &[ProtocolRef],
        value_flow_registrations: &ValueFlowPlanRegistrationSet,
        requested_value_flows: &[ValueFlowPlanRef],
        taint_registrations: &TaintResultRegistrationSet,
        requested_taint_results: &[TaintResultRef],
        validation_limits: QueryAnalysisValidationLimits,
        cancellation: Option<&CancellationToken>,
        summary_lease: ProductionTypestateSummaryLease,
    ) -> Result<Self, QueryAnalysisContextError> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(QueryAnalysisContextError::Cancelled);
        }
        if summary_lease.generation() != workspace_generation {
            return Err(QueryAnalysisContextError::WorkspaceGenerationMismatch {
                registered: summary_lease.generation(),
                current: workspace_generation,
            });
        }
        let generation = NEXT_QUERY_ANALYSIS_GENERATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| QueryAnalysisContextError::GenerationExhausted)
            .and_then(|value| {
                NonZeroU64::new(value).ok_or(QueryAnalysisContextError::GenerationExhausted)
            })?;
        let mut by_ref = HashMap::with_capacity(requested.len());
        let mut dense_by_registration = HashMap::<*const ProtocolRegistration, u32>::new();
        let mut imported = Vec::new();
        let mut validation_budget = QueryAnalysisValidationBudget::new(validation_limits);
        for protocol_ref in requested {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(QueryAnalysisContextError::Cancelled);
            }
            if by_ref.contains_key(protocol_ref) {
                continue;
            }
            let registration = registrations.get(protocol_ref).ok_or_else(|| {
                QueryAnalysisContextError::UnresolvedReference {
                    protocol_ref: protocol_ref.clone(),
                }
            })?;
            let pointer = Arc::as_ptr(registration);
            let slot = match dense_by_registration.get(&pointer).copied() {
                Some(slot) => slot,
                None => {
                    validate_registration(
                        workspace,
                        workspace_generation,
                        registration,
                        &mut validation_budget,
                        cancellation,
                    )?;
                    let slot = u32::try_from(imported.len())
                        .map_err(|_| QueryAnalysisContextError::TooManyResolvedProtocols)?;
                    imported.push(Arc::clone(registration));
                    dense_by_registration.insert(pointer, slot);
                    slot
                }
            };
            by_ref.insert(
                protocol_ref.clone(),
                ProtocolHandle {
                    context_generation: generation,
                    slot,
                    protocol_hash: registration.protocol.hash(),
                    binding_plan_hash: registration.bindings.hash(),
                },
            );
        }
        let mut value_flow_by_ref = HashMap::with_capacity(requested_value_flows.len());
        let mut dense_value_flows = HashMap::<*const ValueFlowPlanRegistration, u32>::new();
        let mut imported_value_flows = Vec::new();
        for plan_ref in requested_value_flows {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(QueryAnalysisContextError::Cancelled);
            }
            if value_flow_by_ref.contains_key(plan_ref) {
                continue;
            }
            let registration = value_flow_registrations.get(plan_ref).ok_or_else(|| {
                QueryAnalysisContextError::UnresolvedValueFlowPlanReference {
                    plan_ref: plan_ref.clone(),
                }
            })?;
            let pointer = Arc::as_ptr(registration);
            let slot = match dense_value_flows.get(&pointer).copied() {
                Some(slot) => slot,
                None => {
                    validate_value_flow_registration(
                        workspace,
                        workspace_generation,
                        registration,
                        &mut validation_budget,
                        cancellation,
                    )
                    .map_err(value_flow_registration_error)?;
                    let slot = u32::try_from(imported_value_flows.len())
                        .map_err(|_| QueryAnalysisContextError::TooManyResolvedValueFlowPlans)?;
                    imported_value_flows.push(Arc::clone(registration));
                    dense_value_flows.insert(pointer, slot);
                    slot
                }
            };
            value_flow_by_ref.insert(
                plan_ref.clone(),
                ValueFlowPlanHandle {
                    context_generation: generation,
                    slot,
                },
            );
        }
        let mut taint_by_ref = HashMap::with_capacity(requested_taint_results.len());
        let mut dense_taint_results = HashMap::<*const TaintResultRegistration, u32>::new();
        let mut imported_taint_results = Vec::new();
        for taint_ref in requested_taint_results {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(QueryAnalysisContextError::Cancelled);
            }
            if taint_by_ref.contains_key(taint_ref) {
                continue;
            }
            let registration = taint_registrations.get(taint_ref).ok_or_else(|| {
                QueryAnalysisContextError::UnresolvedTaintResultReference {
                    taint_ref: taint_ref.clone(),
                }
            })?;
            let pointer = Arc::as_ptr(registration);
            let slot = match dense_taint_results.get(&pointer).copied() {
                Some(slot) => slot,
                None => {
                    validate_taint_registration(
                        workspace,
                        workspace_generation,
                        registration,
                        &mut validation_budget,
                        cancellation,
                    )
                    .map_err(taint_registration_error)?;
                    let slot = u32::try_from(imported_taint_results.len())
                        .map_err(|_| QueryAnalysisContextError::TooManyResolvedTaintResults)?;
                    imported_taint_results.push(Arc::clone(registration));
                    dense_taint_results.insert(pointer, slot);
                    slot
                }
            };
            taint_by_ref.insert(
                taint_ref.clone(),
                TaintResultHandle {
                    context_generation: generation,
                    slot,
                },
            );
        }
        Ok(Self {
            generation,
            workspace_generation,
            by_ref,
            registrations: imported.into_boxed_slice(),
            value_flow_by_ref,
            value_flow_registrations: imported_value_flows.into_boxed_slice(),
            taint_by_ref,
            taint_registrations: imported_taint_results.into_boxed_slice(),
            summary_lease,
        })
    }

    pub fn handle(&self, protocol_ref: &ProtocolRef) -> Option<ProtocolHandle> {
        self.by_ref.get(protocol_ref).copied()
    }

    pub(crate) const fn summary_lease(&self) -> &ProductionTypestateSummaryLease {
        &self.summary_lease
    }

    pub fn resolve<'a>(
        &'a self,
        _workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        expected_root: &ProcedureHandle,
        handle: ProtocolHandle,
    ) -> Result<&'a ProtocolRegistration, QueryAnalysisContextError> {
        if handle.context_generation != self.generation {
            return Err(QueryAnalysisContextError::StaleHandle);
        }
        if workspace_generation != self.workspace_generation {
            return Err(QueryAnalysisContextError::WorkspaceGenerationMismatch {
                registered: self.workspace_generation,
                current: workspace_generation,
            });
        }
        let registration = self
            .registrations
            .get(handle.slot as usize)
            .ok_or(QueryAnalysisContextError::StaleHandle)?;
        if registration.protocol.hash() != handle.protocol_hash
            || registration.bindings.hash() != handle.binding_plan_hash
        {
            return Err(QueryAnalysisContextError::StaleHandle);
        }
        if !same_procedure_identity(registration.expected_root(), expected_root) {
            return Err(QueryAnalysisContextError::AnalysisRootMismatch);
        }
        Ok(registration)
    }

    pub fn value_flow_handle(&self, plan_ref: &ValueFlowPlanRef) -> Option<ValueFlowPlanHandle> {
        self.value_flow_by_ref.get(plan_ref).copied()
    }

    pub fn resolve_value_flow<'a>(
        &'a self,
        workspace_generation: u64,
        expected_root: &ProcedureHandle,
        handle: ValueFlowPlanHandle,
    ) -> Result<&'a ValueFlowPlanRegistration, QueryAnalysisContextError> {
        if handle.context_generation != self.generation {
            return Err(QueryAnalysisContextError::StaleValueFlowPlanHandle);
        }
        if workspace_generation != self.workspace_generation {
            return Err(QueryAnalysisContextError::WorkspaceGenerationMismatch {
                registered: self.workspace_generation,
                current: workspace_generation,
            });
        }
        let registration = self
            .value_flow_registrations
            .get(handle.slot as usize)
            .ok_or(QueryAnalysisContextError::StaleValueFlowPlanHandle)?;
        if !same_procedure_identity(registration.expected_root(), expected_root) {
            return Err(QueryAnalysisContextError::ValueFlowRootMismatch);
        }
        Ok(registration)
    }

    pub fn taint_result_handle(&self, taint_ref: &TaintResultRef) -> Option<TaintResultHandle> {
        self.taint_by_ref.get(taint_ref).copied()
    }

    pub fn resolve_taint_result(
        &self,
        workspace_generation: u64,
        expected_root: &ProcedureHandle,
        handle: TaintResultHandle,
    ) -> Result<&ProductionTaintAnalysisResult, QueryAnalysisContextError> {
        if handle.context_generation != self.generation {
            return Err(QueryAnalysisContextError::StaleTaintResultHandle);
        }
        if workspace_generation != self.workspace_generation {
            return Err(QueryAnalysisContextError::WorkspaceGenerationMismatch {
                registered: self.workspace_generation,
                current: workspace_generation,
            });
        }
        let registration = self
            .taint_registrations
            .get(handle.slot as usize)
            .ok_or(QueryAnalysisContextError::StaleTaintResultHandle)?;
        let result = registration
            .result_for_root(expected_root)
            .ok_or(QueryAnalysisContextError::TaintResultRootMismatch)?;
        if !result.plan_report_match() {
            return Err(QueryAnalysisContextError::TaintPlanReportMismatch);
        }
        Ok(result)
    }
}

fn same_procedure_identity(left: &ProcedureHandle, right: &ProcedureHandle) -> bool {
    left.artifact().key() == right.artifact().key()
        && left.semantics().locator() == right.semantics().locator()
}

fn validate_registration(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registration: &ProtocolRegistration,
    validation_budget: &mut QueryAnalysisValidationBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<(), QueryAnalysisContextError> {
    if registration.workspace_generation != workspace_generation {
        return Err(QueryAnalysisContextError::WorkspaceGenerationMismatch {
            registered: registration.workspace_generation,
            current: workspace_generation,
        });
    }
    validate_artifact_keys(
        workspace,
        registration.artifact_keys(),
        validation_budget,
        cancellation,
    )
}

fn validate_artifact_keys(
    workspace: &WorkspaceAnalyzer,
    artifact_keys: &[SemanticArtifactKey],
    validation_budget: &mut QueryAnalysisValidationBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<(), QueryAnalysisContextError> {
    for key in artifact_keys {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(QueryAnalysisContextError::Cancelled);
        }
        let max_source_bytes = validation_budget.reserve_artifact()?;
        match workspace.semantic_artifact_key_is_current_with_source_bytes(key, max_source_bytes) {
            Ok(Some((true, source_bytes))) => {
                validation_budget.charge_source_bytes(source_bytes)?;
            }
            Ok(Some((false, source_bytes))) => {
                validation_budget.charge_source_bytes(source_bytes)?;
                return Err(QueryAnalysisContextError::StaleArtifact {
                    path: key.path().as_str().into(),
                });
            }
            Ok(None) => {
                if max_source_bytes < MAX_REGISTRATION_ARTIFACT_SOURCE_BYTES {
                    return Err(QueryAnalysisContextError::ValidationBudgetExceeded {
                        resource: "semantic artifact source bytes",
                        maximum: validation_budget.limits.max_source_bytes,
                    });
                }
                return Err(QueryAnalysisContextError::ArtifactIdentityUnavailable {
                    path: key.path().as_str().into(),
                    maximum_source_bytes: max_source_bytes,
                });
            }
            Err(error) => {
                return Err(QueryAnalysisContextError::ArtifactValidationFailed {
                    path: key.path().as_str().into(),
                    detail: error.to_string().into_boxed_str(),
                });
            }
        }
    }
    Ok(())
}

fn validate_value_flow_registration(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registration: &ValueFlowPlanRegistration,
    validation_budget: &mut QueryAnalysisValidationBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<(), QueryAnalysisContextError> {
    if registration.workspace_generation != workspace_generation {
        return Err(QueryAnalysisContextError::WorkspaceGenerationMismatch {
            registered: registration.workspace_generation,
            current: workspace_generation,
        });
    }
    validate_artifact_keys(
        workspace,
        registration.artifact_keys(),
        validation_budget,
        cancellation,
    )
}

fn value_flow_registration_error(error: QueryAnalysisContextError) -> QueryAnalysisContextError {
    match error {
        QueryAnalysisContextError::Cancelled
        | QueryAnalysisContextError::ValidationBudgetExceeded { .. } => error,
        _ => QueryAnalysisContextError::ValueFlowRegistrationInvalid {
            detail: Box::new(error),
        },
    }
}

fn validate_taint_registration(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registration: &TaintResultRegistration,
    validation_budget: &mut QueryAnalysisValidationBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<(), QueryAnalysisContextError> {
    if registration.workspace_generation() != workspace_generation {
        return Err(QueryAnalysisContextError::WorkspaceGenerationMismatch {
            registered: registration.workspace_generation(),
            current: workspace_generation,
        });
    }
    if registration
        .results()
        .iter()
        .any(|result| !result.plan_report_match())
    {
        return Err(QueryAnalysisContextError::TaintPlanReportMismatch);
    }
    validate_artifact_keys(
        workspace,
        registration.artifact_keys(),
        validation_budget,
        cancellation,
    )
}

fn taint_registration_error(error: QueryAnalysisContextError) -> QueryAnalysisContextError {
    match error {
        QueryAnalysisContextError::Cancelled
        | QueryAnalysisContextError::ValidationBudgetExceeded { .. } => error,
        _ => QueryAnalysisContextError::TaintRegistrationInvalid {
            detail: Box::new(error),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryAnalysisContextError {
    GenerationExhausted,
    Cancelled,
    TooManyResolvedProtocols,
    TooManyResolvedValueFlowPlans,
    TooManyResolvedTaintResults,
    ValidationBudgetExceeded {
        resource: &'static str,
        maximum: usize,
    },
    UnresolvedReference {
        protocol_ref: ProtocolRef,
    },
    UnresolvedValueFlowPlanReference {
        plan_ref: ValueFlowPlanRef,
    },
    UnresolvedTaintResultReference {
        taint_ref: TaintResultRef,
    },
    WorkspaceGenerationMismatch {
        registered: u64,
        current: u64,
    },
    StaleArtifact {
        path: Box<str>,
    },
    ArtifactIdentityUnavailable {
        path: Box<str>,
        maximum_source_bytes: usize,
    },
    ArtifactValidationFailed {
        path: Box<str>,
        detail: Box<str>,
    },
    ValueFlowRegistrationInvalid {
        detail: Box<QueryAnalysisContextError>,
    },
    TaintRegistrationInvalid {
        detail: Box<QueryAnalysisContextError>,
    },
    AnalysisRootMismatch,
    StaleHandle,
    ValueFlowRootMismatch,
    StaleValueFlowPlanHandle,
    TaintResultRootMismatch,
    TaintPlanReportMismatch,
    StaleTaintResultHandle,
}

impl fmt::Display for QueryAnalysisContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerationExhausted => {
                formatter.write_str("query analysis context generation is exhausted")
            }
            Self::Cancelled => {
                formatter.write_str("query analysis context construction was cancelled")
            }
            Self::TooManyResolvedProtocols => {
                formatter.write_str("query resolved too many protocols for dense handles")
            }
            Self::TooManyResolvedValueFlowPlans => {
                formatter.write_str("query resolved too many value-flow plans for dense handles")
            }
            Self::TooManyResolvedTaintResults => {
                formatter.write_str("query resolved too many taint results for dense handles")
            }
            Self::ValidationBudgetExceeded { resource, maximum } => {
                write!(
                    formatter,
                    "query analysis context validation exceeds {maximum} {resource}"
                )
            }
            Self::UnresolvedReference { protocol_ref } => {
                write!(
                    formatter,
                    "protocol reference `{protocol_ref}` is not registered"
                )
            }
            Self::UnresolvedValueFlowPlanReference { plan_ref } => write!(
                formatter,
                "value-flow plan reference `{plan_ref}` is not registered"
            ),
            Self::UnresolvedTaintResultReference { taint_ref } => write!(
                formatter,
                "taint result reference `{taint_ref}` is not registered"
            ),
            Self::WorkspaceGenerationMismatch {
                registered,
                current,
            } => write!(
                formatter,
                "query registration targets workspace generation {registered}, current generation is {current}"
            ),
            Self::StaleArtifact { path } => {
                write!(
                    formatter,
                    "query registration retains stale artifact `{path}`"
                )
            }
            Self::ArtifactIdentityUnavailable {
                path,
                maximum_source_bytes,
            } => write!(
                formatter,
                "cannot validate query artifact `{path}` within {maximum_source_bytes} source bytes"
            ),
            Self::ArtifactValidationFailed { path, detail } => {
                write!(
                    formatter,
                    "failed to validate query artifact `{path}`: {detail}"
                )
            }
            Self::ValueFlowRegistrationInvalid { detail } => {
                write!(formatter, "invalid value-flow registration: {detail}")
            }
            Self::TaintRegistrationInvalid { detail } => {
                write!(formatter, "invalid taint result registration: {detail}")
            }
            Self::AnalysisRootMismatch => {
                formatter.write_str("typestate query procedure is not the registered analysis root")
            }
            Self::StaleHandle => formatter.write_str("protocol handle belongs to another context"),
            Self::ValueFlowRootMismatch => formatter
                .write_str("value-flow query procedure is not the registered analysis root"),
            Self::StaleValueFlowPlanHandle => {
                formatter.write_str("value-flow plan handle belongs to another context")
            }
            Self::TaintResultRootMismatch => {
                formatter.write_str("taint query procedure is not a registered analysis root")
            }
            Self::TaintPlanReportMismatch => {
                formatter.write_str("taint result report does not belong to its analysis plan")
            }
            Self::StaleTaintResultHandle => {
                formatter.write_str("taint result handle belongs to another context")
            }
        }
    }
}

impl std::error::Error for QueryAnalysisContextError {}
