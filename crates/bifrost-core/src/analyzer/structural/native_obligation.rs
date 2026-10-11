//! Language-neutral native result obligations.
//!
//! A language adapter may prove an obligation from its own declaration and
//! language semantics without consulting a reviewed semantic model. The
//! query layer publishes these values with the `native` provenance, while
//! keeping the proof basis explicit for consumers that need to distinguish a
//! static-signature fact from a dispatch agreement.

/// The small shared vocabulary of obligations produced by language-native
/// declaration facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeResultObligationKind {
    /// A result whose failure/status value must not be silently discarded.
    FallibleStatus,
    /// A value marked by the language as requiring deliberate use.
    MustUseValue,
}

impl NativeResultObligationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::FallibleStatus => "fallible_status",
            Self::MustUseValue => "must_use_value",
        }
    }
}

/// Evidence basis for a native obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeResultObligationBasis {
    /// The declaration's static result type is sufficient to establish the
    /// obligation for the selected call target.
    StaticSignature,
    /// Every retained dispatch arm independently established the same native
    /// obligation.
    DispatchAgreement,
}

impl NativeResultObligationBasis {
    pub const fn label(self) -> &'static str {
        match self {
            Self::StaticSignature => "static_signature",
            Self::DispatchAgreement => "dispatch_agreement",
        }
    }
}

/// One native obligation on one ordered result port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NativeResultObligation {
    pub result_ordinal: u32,
    pub kind: NativeResultObligationKind,
    pub basis: NativeResultObligationBasis,
}

impl NativeResultObligation {
    pub const fn fallible_status(result_ordinal: u32, basis: NativeResultObligationBasis) -> Self {
        Self {
            result_ordinal,
            kind: NativeResultObligationKind::FallibleStatus,
            basis,
        }
    }

    pub const fn must_use_value(result_ordinal: u32, basis: NativeResultObligationBasis) -> Self {
        Self {
            result_ordinal,
            kind: NativeResultObligationKind::MustUseValue,
            basis,
        }
    }
}
