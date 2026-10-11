//! Language-neutral exact result-use facts for call sites.
//!
//! Language adapters classify the syntax around a call, while the query layer
//! joins that classification to semantic result ports.  A site therefore has
//! one default classification and may override individual result ordinals
//! (for example, Go's blank assignments).  The index is source-snapshot local;
//! callers must not retain it across queries or source identities.

/// How one normal result port is used at its exact call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallResultUse {
    /// The syntax drops the value without an explicit discard marker.
    Discarded,
    /// The source explicitly handles dropping the value.  This is visible
    /// evidence, but it is never a B4/B5 finding.
    IntentionalDiscard(IntentionalDiscardKind),
    /// The value is in another valid syntax context.  This says nothing about
    /// whether later execution observes the value.
    Consumed,
    /// The adapter could not establish the result-use role.
    Open(CallResultUseOpenReason),
}

impl CallResultUse {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Discarded => "discarded",
            Self::IntentionalDiscard(_) => "intentional_discard",
            Self::Consumed => "consumed",
            Self::Open(_) => "open",
        }
    }

    /// The typed detail carried by an intentional discard or an open result.
    pub const fn detail(self) -> Option<&'static str> {
        match self {
            Self::Discarded | Self::Consumed => None,
            Self::IntentionalDiscard(kind) => Some(kind.label()),
            Self::Open(reason) => Some(reason.label()),
        }
    }
}

/// Explicit syntax that tells the reader the result was intentionally
/// discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentionalDiscardKind {
    GoBlankAssignment,
    RustLetUnderscore,
    RustDrop,
    CppVoidCast,
    JavaScriptVoid,
    CSharpDiscardAssignment,
}

impl IntentionalDiscardKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::GoBlankAssignment => "go_blank_assignment",
            Self::RustLetUnderscore => "rust_let_underscore",
            Self::RustDrop => "rust_drop",
            Self::CppVoidCast => "cpp_void_cast",
            Self::JavaScriptVoid => "javascript_void",
            Self::CSharpDiscardAssignment => "csharp_discard_assignment",
        }
    }
}

/// Why syntax or the exact source-site lookup remains open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallResultUseOpenReason {
    MissingCall,
    AmbiguousCall,
    RecoveredSyntax,
    DeferredContext,
    UnsupportedSyntax,
    UnclassifiedSyntax,
    MissingResultPort,
}

impl CallResultUseOpenReason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::MissingCall => "missing_call",
            Self::AmbiguousCall => "ambiguous_call",
            Self::RecoveredSyntax => "recovered_syntax",
            Self::DeferredContext => "deferred_context",
            Self::UnsupportedSyntax => "unsupported_syntax",
            Self::UnclassifiedSyntax => "unclassified_syntax",
            Self::MissingResultPort => "missing_result_port",
        }
    }
}

/// One result-port override at an exact call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallResultUseFact {
    pub result_ordinal: u32,
    pub result_use: CallResultUse,
}

/// The syntax classification for one exact call span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResultUseSite {
    pub start_byte: usize,
    pub end_byte: usize,
    default: CallResultUse,
    overrides: Vec<CallResultUseFact>,
}

impl CallResultUseSite {
    pub fn new(start_byte: usize, end_byte: usize, default: CallResultUse) -> Self {
        Self {
            start_byte,
            end_byte,
            default,
            overrides: Vec::new(),
        }
    }

    pub fn with_overrides(mut self, mut overrides: Vec<CallResultUseFact>) -> Self {
        overrides.sort_unstable_by_key(|fact| fact.result_ordinal);
        assert!(
            overrides
                .windows(2)
                .all(|pair| pair[0].result_ordinal != pair[1].result_ordinal),
            "result-use overrides have duplicate ordinals"
        );
        self.overrides = overrides;
        self
    }

    pub fn default_use(&self) -> CallResultUse {
        self.default
    }

    pub fn overrides(&self) -> &[CallResultUseFact] {
        &self.overrides
    }

    /// Resolve one semantic result ordinal without inventing a result count.
    /// An adapter's default applies to ports it did not need to spell out.
    pub fn for_port(&self, result_ordinal: u32) -> CallResultUse {
        self.overrides
            .binary_search_by_key(&result_ordinal, |fact| fact.result_ordinal)
            .map(|index| self.overrides[index].result_use)
            .unwrap_or(self.default)
    }
}

/// Exact call-span lookup for one immutable source snapshot.
#[derive(Debug, Clone, Default)]
pub struct CallResultUseIndex {
    sites: Vec<CallResultUseSite>,
}

impl CallResultUseIndex {
    pub fn new(mut sites: Vec<CallResultUseSite>) -> Self {
        sites.sort_unstable_by_key(|site| (site.start_byte, site.end_byte));
        Self { sites }
    }

    pub fn at_span(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<&CallResultUseSite, CallResultUseOpenReason> {
        let key = (start_byte, end_byte);
        let start = self
            .sites
            .partition_point(|site| (site.start_byte, site.end_byte) < key);
        let end = self
            .sites
            .partition_point(|site| (site.start_byte, site.end_byte) <= key);
        match &self.sites[start..end] {
            [] => Err(CallResultUseOpenReason::MissingCall),
            [site] => Ok(site),
            _ => Err(CallResultUseOpenReason::AmbiguousCall),
        }
    }

    pub fn sites(&self) -> &[CallResultUseSite] {
        &self.sites
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_port_overrides_leave_other_ports_at_the_site_default() {
        let site = CallResultUseSite::new(4, 8, CallResultUse::Discarded).with_overrides(vec![
            CallResultUseFact {
                result_ordinal: 0,
                result_use: CallResultUse::IntentionalDiscard(
                    IntentionalDiscardKind::GoBlankAssignment,
                ),
            },
        ]);
        assert!(matches!(
            site.for_port(0),
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::GoBlankAssignment)
        ));
        assert_eq!(site.for_port(1), CallResultUse::Discarded);
    }

    #[test]
    fn exact_span_lookup_preserves_missing_and_ambiguous_open_reasons() {
        let index = CallResultUseIndex::new(vec![
            CallResultUseSite::new(1, 4, CallResultUse::Consumed),
            CallResultUseSite::new(1, 4, CallResultUse::Discarded),
        ]);
        assert_eq!(
            index.at_span(1, 4),
            Err(CallResultUseOpenReason::AmbiguousCall)
        );
        assert_eq!(
            index.at_span(7, 8),
            Err(CallResultUseOpenReason::MissingCall)
        );
    }
}
