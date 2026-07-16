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
    NormalCallContinuation => "normal_call_continuation",
    ExceptionalCallContinuation => "exceptional_call_continuation",
    Captures => "captures",
    CallableReferences => "callable_references",
    AsyncSuspendResume => "async_suspend_resume",
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
    fn registry_ordinals_labels_and_storage_are_exhaustive() {
        let expected = [
            (SemanticCapability::Procedures, "procedures"),
            (SemanticCapability::EntryBoundary, "entry_boundary"),
            (
                SemanticCapability::NormalExitBoundary,
                "normal_exit_boundary",
            ),
            (
                SemanticCapability::ExceptionalExitBoundary,
                "exceptional_exit_boundary",
            ),
            (SemanticCapability::BasicBlocks, "basic_blocks"),
            (SemanticCapability::ProgramPoints, "program_points"),
            (SemanticCapability::NormalControlFlow, "normal_control_flow"),
            (
                SemanticCapability::ExceptionalControlFlow,
                "exceptional_control_flow",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                "cleanup_control_flow",
            ),
            (SemanticCapability::Assignments, "assignments"),
            (SemanticCapability::Values, "values"),
            (SemanticCapability::Allocations, "allocations"),
            (SemanticCapability::LocalFlow, "local_flow"),
            (SemanticCapability::ParameterFlow, "parameter_flow"),
            (SemanticCapability::ReceiverFlow, "receiver_flow"),
            (SemanticCapability::ReturnFlow, "return_flow"),
            (SemanticCapability::FieldMemory, "field_memory"),
            (SemanticCapability::StaticMemory, "static_memory"),
            (SemanticCapability::IndexMemory, "index_memory"),
            (SemanticCapability::Calls, "calls"),
            (
                SemanticCapability::NormalCallContinuation,
                "normal_call_continuation",
            ),
            (
                SemanticCapability::ExceptionalCallContinuation,
                "exceptional_call_continuation",
            ),
            (SemanticCapability::Captures, "captures"),
            (
                SemanticCapability::CallableReferences,
                "callable_references",
            ),
            (
                SemanticCapability::AsyncSuspendResume,
                "async_suspend_resume",
            ),
        ];
        let capabilities = SemanticCapabilities::default();
        let iterated = capabilities
            .iter()
            .map(|(capability, _)| capability)
            .collect::<Vec<_>>();
        assert_eq!(iterated, SemanticCapability::ALL);
        assert_eq!(expected.len(), SemanticCapability::COUNT);
        assert_eq!(SemanticCapability::ALL.len(), SemanticCapability::COUNT);
        assert_eq!(capabilities.support.len(), SemanticCapability::COUNT);

        for (ordinal, (capability, label)) in expected.into_iter().enumerate() {
            assert_eq!(capability.index(), ordinal);
            assert_eq!(SemanticCapability::ALL[capability.index()], capability);
            assert_eq!(capability.label(), label);
        }

        let mut labels = SemanticCapability::ALL
            .into_iter()
            .map(SemanticCapability::label)
            .collect::<Vec<_>>();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), SemanticCapability::ALL.len());
    }
}
