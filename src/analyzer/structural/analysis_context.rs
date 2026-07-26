//! Host-owned typestate registrations and execution-local query capabilities.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::identifier::define_identifier;
use crate::analyzer::semantic::{ProcedureHandle, SemanticArtifactKey};
use crate::analyzer::typestate::{
    CompiledProtocol, TypestateBindingPlan, TypestateBindingPlanHash, TypestateProtocolHash,
};

pub const MAX_PROTOCOL_REFS: usize = 256;
pub const MAX_PROTOCOL_REGISTRATIONS: usize = 128;
pub const MAX_RETAINED_PROTOCOL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RETAINED_BINDING_PLAN_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROTOCOL_REF_BYTES: usize = 192;
pub const MAX_PROTOCOL_NAMESPACE_BYTES: usize = 63;
pub const MAX_PROTOCOL_NAME_BYTES: usize = 128;
pub const MAX_REGISTRATION_ARTIFACT_SOURCE_BYTES: usize = 32 * 1024 * 1024;

pub type ProtocolNamespaceError = crate::analyzer::identifier::IdentifierError;
pub type ProtocolNameError = crate::analyzer::identifier::IdentifierError;

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
    struct ProtocolName {
        max_bytes: MAX_PROTOCOL_NAME_BYTES,
        allow_dot: true,
        error: ProtocolNameError,
    }
}

/// A bounded host-defined alias for one pre-resolved protocol registration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolRef {
    namespace: ProtocolNamespace,
    name: ProtocolName,
}

impl ProtocolRef {
    pub fn new(
        namespace: impl AsRef<str>,
        name: impl AsRef<str>,
    ) -> Result<Self, ProtocolRefError> {
        let namespace = ProtocolNamespace::new(namespace).map_err(ProtocolRefError::Namespace)?;
        let name = ProtocolName::new(name).map_err(ProtocolRefError::Name)?;
        let total = namespace
            .as_str()
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(name.as_str().len()))
            .ok_or(ProtocolRefError::TooLong {
                max_bytes: MAX_PROTOCOL_REF_BYTES,
            })?;
        if total > MAX_PROTOCOL_REF_BYTES {
            return Err(ProtocolRefError::TooLong {
                max_bytes: MAX_PROTOCOL_REF_BYTES,
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

impl fmt::Display for ProtocolRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.namespace, self.name)
    }
}

impl FromStr for ProtocolRef {
    type Err = ProtocolRefError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_PROTOCOL_REF_BYTES {
            return Err(ProtocolRefError::TooLong {
                max_bytes: MAX_PROTOCOL_REF_BYTES,
            });
        }
        let (namespace, name) = value
            .split_once(':')
            .ok_or(ProtocolRefError::MissingSeparator)?;
        Self::new(namespace, name)
    }
}

impl Serialize for ProtocolRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProtocolRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProtocolRefVisitor;

        impl Visitor<'_> for ProtocolRefVisitor {
            type Value = ProtocolRef;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded protocol reference in namespace:name form")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                ProtocolRef::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ProtocolRefVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRefError {
    MissingSeparator,
    TooLong { max_bytes: usize },
    Namespace(ProtocolNamespaceError),
    Name(ProtocolNameError),
}

impl fmt::Display for ProtocolRefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator => {
                formatter.write_str("protocol reference must use namespace:name form")
            }
            Self::TooLong { max_bytes } => {
                write!(
                    formatter,
                    "protocol reference must be at most {max_bytes} bytes"
                )
            }
            Self::Namespace(error) => write!(formatter, "invalid protocol namespace: {error}"),
            Self::Name(error) => write!(formatter, "invalid protocol name: {error}"),
        }
    }
}

impl std::error::Error for ProtocolRefError {}

/// One immutable host registration. Semantic handles never cross the wire.
#[derive(Debug)]
pub struct ProtocolRegistration {
    workspace_generation: u64,
    expected_root: ProcedureHandle,
    protocol: Arc<CompiledProtocol>,
    bindings: Arc<TypestateBindingPlan>,
    artifact_keys: Box<[SemanticArtifactKey]>,
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
        artifact_keys.insert(expected_root.artifact().key().clone());
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
}

impl ProtocolRegistrationLimits {
    pub const fn bounded(
        references: usize,
        registrations: usize,
        protocol_bytes: usize,
        binding_plan_bytes: usize,
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

        let registration = Arc::new(registration);
        self.by_ref.insert(protocol_ref, Arc::clone(&registration));
        self.by_identity.insert(identity, registration);
        self.retained_protocol_bytes = retained_protocol_bytes;
        self.retained_binding_plan_bytes = retained_binding_plan_bytes;
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
        true
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRegistrationSetError {
    ReferenceConflict { protocol_ref: ProtocolRef },
    TooManyReferences { maximum: usize },
    TooManyRegistrations { maximum: usize },
    RetainedProtocolBytes { maximum: usize },
    RetainedBindingPlanBytes { maximum: usize },
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
        }
    }
}

impl std::error::Error for ProtocolRegistrationSetError {}

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
}

static NEXT_QUERY_ANALYSIS_GENERATION: AtomicU64 = AtomicU64::new(1);

impl QueryAnalysisContext {
    pub fn new(
        workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        requested: &[ProtocolRef],
    ) -> Result<Self, QueryAnalysisContextError> {
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
        for protocol_ref in requested {
            if by_ref.contains_key(protocol_ref) {
                continue;
            }
            let registration = registrations.get(protocol_ref).ok_or_else(|| {
                QueryAnalysisContextError::UnresolvedReference {
                    protocol_ref: protocol_ref.clone(),
                }
            })?;
            validate_registration(workspace, workspace_generation, registration)?;
            let pointer = Arc::as_ptr(registration);
            let slot = match dense_by_registration.get(&pointer).copied() {
                Some(slot) => slot,
                None => {
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
        Ok(Self {
            generation,
            workspace_generation,
            by_ref,
            registrations: imported.into_boxed_slice(),
        })
    }

    pub fn handle(&self, protocol_ref: &ProtocolRef) -> Option<ProtocolHandle> {
        self.by_ref.get(protocol_ref).copied()
    }

    pub fn resolve<'a>(
        &'a self,
        workspace: &WorkspaceAnalyzer,
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
        if registration.expected_root() != expected_root {
            return Err(QueryAnalysisContextError::AnalysisRootMismatch);
        }
        validate_registration(workspace, workspace_generation, registration)?;
        Ok(registration)
    }
}

fn validate_registration(
    workspace: &WorkspaceAnalyzer,
    workspace_generation: u64,
    registration: &ProtocolRegistration,
) -> Result<(), QueryAnalysisContextError> {
    if registration.workspace_generation != workspace_generation {
        return Err(QueryAnalysisContextError::WorkspaceGenerationMismatch {
            registered: registration.workspace_generation,
            current: workspace_generation,
        });
    }
    for key in registration.artifact_keys() {
        match workspace
            .semantic_artifact_key_is_current(key, MAX_REGISTRATION_ARTIFACT_SOURCE_BYTES)
        {
            Ok(Some(true)) => {}
            Ok(Some(false)) => {
                return Err(QueryAnalysisContextError::StaleArtifact {
                    path: key.path().as_str().into(),
                });
            }
            Ok(None) => {
                return Err(QueryAnalysisContextError::ArtifactIdentityUnavailable {
                    path: key.path().as_str().into(),
                    maximum_source_bytes: MAX_REGISTRATION_ARTIFACT_SOURCE_BYTES,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryAnalysisContextError {
    GenerationExhausted,
    TooManyResolvedProtocols,
    UnresolvedReference {
        protocol_ref: ProtocolRef,
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
    AnalysisRootMismatch,
    StaleHandle,
}

impl fmt::Display for QueryAnalysisContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerationExhausted => {
                formatter.write_str("query analysis context generation is exhausted")
            }
            Self::TooManyResolvedProtocols => {
                formatter.write_str("query resolved too many protocols for dense handles")
            }
            Self::UnresolvedReference { protocol_ref } => {
                write!(
                    formatter,
                    "protocol reference `{protocol_ref}` is not registered"
                )
            }
            Self::WorkspaceGenerationMismatch {
                registered,
                current,
            } => write!(
                formatter,
                "protocol registration targets workspace generation {registered}, current generation is {current}"
            ),
            Self::StaleArtifact { path } => {
                write!(
                    formatter,
                    "protocol registration retains stale artifact `{path}`"
                )
            }
            Self::ArtifactIdentityUnavailable {
                path,
                maximum_source_bytes,
            } => write!(
                formatter,
                "cannot validate protocol artifact `{path}` within {maximum_source_bytes} source bytes"
            ),
            Self::ArtifactValidationFailed { path, detail } => {
                write!(
                    formatter,
                    "failed to validate protocol artifact `{path}`: {detail}"
                )
            }
            Self::AnalysisRootMismatch => {
                formatter.write_str("typestate query procedure is not the registered analysis root")
            }
            Self::StaleHandle => formatter.write_str("protocol handle belongs to another context"),
        }
    }
}

impl std::error::Error for QueryAnalysisContextError {}
