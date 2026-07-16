//! Total per-language semantic capability discovery.

/// One independently discoverable execution-semantic feature.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SemanticCapability {
    Procedures,
    EntryBoundary,
    NormalExitBoundary,
    ExceptionalExitBoundary,
    BasicBlocks,
    ProgramPoints,
    NormalControlFlow,
    ExceptionalControlFlow,
    CleanupControlFlow,
    Assignments,
    Values,
    Allocations,
    LocalFlow,
    ParameterFlow,
    ReceiverFlow,
    ReturnFlow,
    FieldMemory,
    StaticMemory,
    IndexMemory,
    Calls,
    NormalCallContinuation,
    ExceptionalCallContinuation,
    Captures,
    CallableReferences,
    AsyncSuspendResume,
}

impl SemanticCapability {
    pub const ALL: [Self; 25] = [
        Self::Procedures,
        Self::EntryBoundary,
        Self::NormalExitBoundary,
        Self::ExceptionalExitBoundary,
        Self::BasicBlocks,
        Self::ProgramPoints,
        Self::NormalControlFlow,
        Self::ExceptionalControlFlow,
        Self::CleanupControlFlow,
        Self::Assignments,
        Self::Values,
        Self::Allocations,
        Self::LocalFlow,
        Self::ParameterFlow,
        Self::ReceiverFlow,
        Self::ReturnFlow,
        Self::FieldMemory,
        Self::StaticMemory,
        Self::IndexMemory,
        Self::Calls,
        Self::NormalCallContinuation,
        Self::ExceptionalCallContinuation,
        Self::Captures,
        Self::CallableReferences,
        Self::AsyncSuspendResume,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Procedures => "procedures",
            Self::EntryBoundary => "entry_boundary",
            Self::NormalExitBoundary => "normal_exit_boundary",
            Self::ExceptionalExitBoundary => "exceptional_exit_boundary",
            Self::BasicBlocks => "basic_blocks",
            Self::ProgramPoints => "program_points",
            Self::NormalControlFlow => "normal_control_flow",
            Self::ExceptionalControlFlow => "exceptional_control_flow",
            Self::CleanupControlFlow => "cleanup_control_flow",
            Self::Assignments => "assignments",
            Self::Values => "values",
            Self::Allocations => "allocations",
            Self::LocalFlow => "local_flow",
            Self::ParameterFlow => "parameter_flow",
            Self::ReceiverFlow => "receiver_flow",
            Self::ReturnFlow => "return_flow",
            Self::FieldMemory => "field_memory",
            Self::StaticMemory => "static_memory",
            Self::IndexMemory => "index_memory",
            Self::Calls => "calls",
            Self::NormalCallContinuation => "normal_call_continuation",
            Self::ExceptionalCallContinuation => "exceptional_call_continuation",
            Self::Captures => "captures",
            Self::CallableReferences => "callable_references",
            Self::AsyncSuspendResume => "async_suspend_resume",
        }
    }
}

/// Whether an adapter completely, partially, or not at all supports a feature.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilitySupport {
    Complete,
    Partial,
    #[default]
    Unsupported,
}

impl CapabilitySupport {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_available(self) -> bool {
        !matches!(self, Self::Unsupported)
    }
}

/// A total capability table. Every undeclared feature is explicitly unsupported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticCapabilities {
    support: [CapabilitySupport; SemanticCapability::ALL.len()],
}

impl Default for SemanticCapabilities {
    fn default() -> Self {
        Self {
            support: [CapabilitySupport::Unsupported; SemanticCapability::ALL.len()],
        }
    }
}

impl SemanticCapabilities {
    pub fn builder() -> SemanticCapabilitiesBuilder {
        SemanticCapabilitiesBuilder::default()
    }

    pub const fn support(&self, capability: SemanticCapability) -> CapabilitySupport {
        self.support[capability.index()]
    }

    pub const fn is_complete(&self, capability: SemanticCapability) -> bool {
        self.support(capability).is_complete()
    }

    pub const fn is_available(&self, capability: SemanticCapability) -> bool {
        self.support(capability).is_available()
    }

    /// Iterate in the stable order declared by [`SemanticCapability::ALL`].
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (SemanticCapability, CapabilitySupport)> + '_ {
        SemanticCapability::ALL
            .into_iter()
            .map(|capability| (capability, self.support(capability)))
    }
}

#[derive(Debug, Clone, Default)]
pub struct SemanticCapabilitiesBuilder {
    capabilities: SemanticCapabilities,
}

impl SemanticCapabilitiesBuilder {
    pub fn support(mut self, capability: SemanticCapability, support: CapabilitySupport) -> Self {
        self.capabilities.support[capability.index()] = support;
        self
    }

    pub fn complete(self, capability: SemanticCapability) -> Self {
        self.support(capability, CapabilitySupport::Complete)
    }

    pub fn partial(self, capability: SemanticCapability) -> Self {
        self.support(capability, CapabilitySupport::Partial)
    }

    pub fn unsupported(self, capability: SemanticCapability) -> Self {
        self.support(capability, CapabilitySupport::Unsupported)
    }

    pub fn build(self) -> SemanticCapabilities {
        self.capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_total_and_defaults_to_unsupported() {
        let capabilities = SemanticCapabilities::default();
        assert_eq!(capabilities.iter().count(), SemanticCapability::ALL.len());
        for capability in SemanticCapability::ALL {
            assert_eq!(
                capabilities.support(capability),
                CapabilitySupport::Unsupported
            );
        }
    }

    #[test]
    fn builder_preserves_complete_partial_and_unsupported() {
        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .partial(SemanticCapability::ExceptionalControlFlow)
            .unsupported(SemanticCapability::AsyncSuspendResume)
            .build();

        assert!(capabilities.is_complete(SemanticCapability::Procedures));
        assert_eq!(
            capabilities.support(SemanticCapability::ExceptionalControlFlow),
            CapabilitySupport::Partial
        );
        assert!(!capabilities.is_available(SemanticCapability::AsyncSuspendResume));
        assert_eq!(
            capabilities.support(SemanticCapability::Calls),
            CapabilitySupport::Unsupported
        );
    }

    #[test]
    fn iteration_order_is_deterministic_and_labels_are_unique() {
        let capabilities = SemanticCapabilities::default();
        let iterated = capabilities
            .iter()
            .map(|(capability, _)| capability)
            .collect::<Vec<_>>();
        assert_eq!(iterated, SemanticCapability::ALL);

        let mut labels = SemanticCapability::ALL
            .into_iter()
            .map(SemanticCapability::label)
            .collect::<Vec<_>>();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), SemanticCapability::ALL.len());
    }
}
