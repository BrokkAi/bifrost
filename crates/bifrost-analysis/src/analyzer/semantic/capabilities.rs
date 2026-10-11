//! Total per-language semantic capability discovery.

/// Declare the capability enum, stable order, ordinal mapping, and labels once.
///
/// The generated count also sizes the total support table, so adding a variant
/// cannot silently omit it from iteration or leave it outside table storage.
macro_rules! semantic_capabilities {
    ($($capability:ident => $label:literal),+ $(,)?) => {
        /// One independently discoverable execution-semantic feature.
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum SemanticCapability {
            $($capability),+
        }

        impl SemanticCapability {
            pub const COUNT: usize = count_idents!($($capability),+);

            pub const ALL: [Self; Self::COUNT] = [
                $(Self::$capability),+
            ];

            /// Every capability label, in declaration order: the value domain
            /// the `semantic_unsupported` row fields publish (issue #2515).
            pub const LABELS: &'static [&'static str] = &[$($label),+];

            pub const fn index(self) -> usize {
                self as usize
            }

            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$capability => $label),+
                }
            }
        }
    };
}

semantic_capabilities! {
    Procedures => "procedures",
    EntryBoundary => "entry_boundary",
    NormalExitBoundary => "normal_exit_boundary",
    ExceptionalExitBoundary => "exceptional_exit_boundary",
    BasicBlocks => "basic_blocks",
    ProgramPoints => "program_points",
    NormalControlFlow => "normal_control_flow",
    ExceptionalControlFlow => "exceptional_control_flow",
    CleanupControlFlow => "cleanup_control_flow",
    Assignments => "assignments",
    Values => "values",
    Allocations => "allocations",
    LocalFlow => "local_flow",
    ParameterFlow => "parameter_flow",
    ReceiverFlow => "receiver_flow",
    ReturnFlow => "return_flow",
    FieldMemory => "field_memory",
    StaticMemory => "static_memory",
    IndexMemory => "index_memory",
    Calls => "calls",
    DynamicDispatch => "dynamic_dispatch",
    NormalCallContinuation => "normal_call_continuation",
    ExceptionalCallContinuation => "exceptional_call_continuation",
    Captures => "captures",
    CallableReferences => "callable_references",
    AsyncSuspendResume => "async_suspend_resume",
    GeneratorSuspension => "generator_suspension",
    DeferredExecution => "deferred_execution",
    ConcurrentSpawn => "concurrent_spawn",
    Synchronization => "synchronization",
    NonLocalControl => "non_local_control",
    ResourceManagement => "resource_management",
    GuardFacts => "guard_facts",
    SwitchFacts => "switch_facts",
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
    support: [CapabilitySupport; SemanticCapability::COUNT],
}

impl Default for SemanticCapabilities {
    fn default() -> Self {
        Self {
            support: [CapabilitySupport::Unsupported; SemanticCapability::COUNT],
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

pub(crate) fn tree_sitter_adapter_capabilities() -> SemanticCapabilitiesBuilder {
    let mut builder = SemanticCapabilities::builder();
    for capability in [
        SemanticCapability::Procedures,
        SemanticCapability::EntryBoundary,
        SemanticCapability::NormalExitBoundary,
        SemanticCapability::ExceptionalExitBoundary,
        SemanticCapability::BasicBlocks,
        SemanticCapability::ProgramPoints,
        SemanticCapability::ReturnFlow,
        SemanticCapability::NormalCallContinuation,
        SemanticCapability::ExceptionalCallContinuation,
    ] {
        builder = builder.complete(capability);
    }
    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Assignments,
        SemanticCapability::Values,
        SemanticCapability::Allocations,
        SemanticCapability::FieldMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::Calls,
        SemanticCapability::DynamicDispatch,
        SemanticCapability::CallableReferences,
        SemanticCapability::Captures,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        SemanticCapability::DeferredExecution,
        SemanticCapability::GuardFacts,
    ] {
        builder = builder.partial(capability);
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
