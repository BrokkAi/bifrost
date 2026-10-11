//! Direct, procedure-local C/C++ provenance observations.
//!
//! These rows are query products, not persisted source facts.  They retain
//! only the typed observation a C/C++ adapter proved for one source range;
//! callers own the row for the lifetime of their query.

use super::Range;

/// One of the direct C/C++ provenance slices exposed to RQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CppProvenanceRule {
    IncorrectPointerScalingChar,
    ReturnStackAllocatedMemory,
    StackAddressEscape,
    SuspiciousPointerScaling,
    SuspiciousPointerScalingVoid,
    ImproperNullTermination,
}

impl CppProvenanceRule {
    pub const ALL: [Self; 6] = [
        Self::IncorrectPointerScalingChar,
        Self::ReturnStackAllocatedMemory,
        Self::StackAddressEscape,
        Self::SuspiciousPointerScaling,
        Self::SuspiciousPointerScalingVoid,
        Self::ImproperNullTermination,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::IncorrectPointerScalingChar => "incorrect_pointer_scaling_char",
            Self::ReturnStackAllocatedMemory => "return_stack_allocated_memory",
            Self::StackAddressEscape => "stack_address_escape",
            Self::SuspiciousPointerScaling => "suspicious_pointer_scaling",
            Self::SuspiciousPointerScalingVoid => "suspicious_pointer_scaling_void",
            Self::ImproperNullTermination => "improper_null_termination",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.label() == label)
    }
}

/// Storage class proved for a direct provenance endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CppProvenanceStorage {
    Stack,
    Parameter,
    Heap,
    Global,
    Unknown,
}

/// One source-backed direct provenance observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppProvenanceFact {
    pub rule: CppProvenanceRule,
    pub range: Range,
    pub source_width: Option<u64>,
    pub destination_width: Option<u64>,
    pub offset: Option<i128>,
    pub source_storage: CppProvenanceStorage,
    pub destination_storage: CppProvenanceStorage,
}
