//! Immutable incomplete-read causes and lookup attribution.

use super::ProjectFile;
use super::store_error::StoreError;
use std::sync::Arc;

/// Plain source provenance for one incomplete lookup (#10984).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryLookupProvenance {
    pub file: ProjectFile,
    pub byte_span: std::ops::Range<usize>,
    pub name: Box<str>,
    pub tier: &'static str,
}

/// Immutable data only; no query capability is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributedQueryReadIncomplete {
    lookup: QueryLookupProvenance,
    cause: QueryReadIncomplete,
}

impl AttributedQueryReadIncomplete {
    pub fn lookup(&self) -> &QueryLookupProvenance {
        &self.lookup
    }

    pub fn cause(&self) -> &QueryReadIncomplete {
        &self.cause
    }
}

/// The selected Rust formal alias walk has a fixed code-defined bound.
pub const SELECTED_PATTERN_ALIAS_LIMIT_REASON: &str = "formal type exceeds the alias budget";

/// Registered deterministic proof-stop labels, shared by producers and receipt replay.
pub const DETERMINISTIC_PROOF_STOP_LABELS: &[&str] = &[
    SELECTED_PATTERN_ALIAS_LIMIT_REASON,
    "resolution_unprojected_definition",
    "fixed_limit",
    "resolution_cyclic_expansion",
    "depth_limit",
    "unsupported_language",
    "invalid_location",
    "not_found",
    "external_receiver_type_arguments_unknown",
    "drop_review_scope_admission_pending",
    "drop_inventory_not_absent",
    "drop_inventory_unavailable",
    "overlay_inventory_unavailable",
    "semantic_model_content_open",
    "binding_value_may_be_replaced",
    "external_receiver_generic_arity_mismatch",
    "supertrait_hierarchy_open",
    "lexical_bound_hierarchy_unknown",
    "model_alias_missing_target",
    "model_alias_unresolvable_target",
    "model_alias_cycle",
    "model_alias_arity_mismatch",
    "closure_capture_unresolved",
    "closure_macro_environment",
];

/// A typed reason a request could not establish a complete read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryReadIncomplete {
    /// One source provenance layer around the original cause.
    Attributed(Arc<AttributedQueryReadIncomplete>),
    /// Cooperative cancellation stopped a read before it could establish a
    /// complete answer.
    Cancelled,
    /// An engine producer violated an internal contract. Never content or reusable.
    InternalInvariant(&'static str),
    /// A language proof stopped before establishing its result. The optional
    /// cause distinguishes operational failure from a deterministic semantic gap.
    ProofStopped {
        reason: &'static str,
        cause: Option<crate::analyzer::derivation_cause::DerivationExecutionCause>,
    },
    /// The structured source needed by a read was unavailable.
    StructureUnavailable(ProjectFile),
    /// Structured semantic evidence required for a complete answer was
    /// unavailable or incomplete.
    SemanticEvidenceUnavailable(Box<str>),
    /// Semantic models were selected but their overlay has not been published.
    SemanticModelsPending,
    /// A dependency's content or declared configuration deterministically
    /// prevents a complete external surface. Retained entries replay this gap.
    ArtifactUnavailable(Box<str>),
    /// Snapshot-deterministic unknown or unsupported semantics. The partial
    /// answer remains incomplete, but its named inputs can be replayed.
    SemanticEvidenceGap(Box<str>),
    /// A store failure prevented a read from establishing a complete answer.
    StoreFailure(StoreError),
}

impl QueryReadIncomplete {
    /// Whether a read gap invalidates positive evidence as well as absence.
    pub fn invalidates_positive_evidence(&self) -> bool {
        self.execution_cause().is_some()
            || matches!(self.base_cause(), Self::StructureUnavailable(_))
    }

    /// Attach one layer, rejecting accidental nested annotations.
    pub fn attributed(self, lookup: QueryLookupProvenance) -> Self {
        assert!(
            !matches!(self, Self::Attributed(_)),
            "nested lookup provenance"
        );
        Self::Attributed(Arc::new(AttributedQueryReadIncomplete {
            lookup,
            cause: self,
        }))
    }

    pub fn lookup_provenance(&self) -> Option<&QueryLookupProvenance> {
        match self {
            Self::Attributed(data) => Some(&data.lookup),
            _ => None,
        }
    }

    /// Inspect classification without discarding provenance from receipts.
    pub fn base_cause(&self) -> &Self {
        match self {
            Self::Attributed(data) => &data.cause,
            _ => self,
        }
    }

    /// Requested retained payload layout, excluding this inline enum value.
    pub fn retained_payload_bytes(&self) -> usize {
        use crate::retention_budget::RetainedBytes;
        match self {
            Self::Attributed(data) => {
                // Follow RetainedBytes for Arc<str>: payload plus both counters.
                2 * std::mem::size_of::<usize>()
                    + std::mem::size_of::<AttributedQueryReadIncomplete>()
                    + data.lookup.file.retained_heap_bytes()
                    + data.lookup.name.len()
                    + data.cause.retained_payload_bytes()
            }
            Self::ArtifactUnavailable(text)
            | Self::SemanticEvidenceGap(text)
            | Self::SemanticEvidenceUnavailable(text) => text.len(),
            Self::StructureUnavailable(file) => file.retained_heap_bytes(),
            Self::StoreFailure(error) => error.retained_bytes() - std::mem::size_of::<StoreError>(),
            Self::Cancelled
            | Self::InternalInvariant(_)
            | Self::SemanticModelsPending
            | Self::ProofStopped { .. } => 0,
        }
    }

    /// [`Self::retained_payload_bytes`] with every owned buffer rounded to its
    /// allocation, for pure evictable caches. Refusing admission checks keep
    /// the requested-byte form.
    pub fn allocated_payload_bytes(&self) -> usize {
        use crate::allocation_size::allocation_size;
        match self {
            Self::Attributed(data) => {
                allocation_size(
                    2 * std::mem::size_of::<usize>()
                        + std::mem::size_of::<AttributedQueryReadIncomplete>(),
                ) + data.lookup.file.allocated_heap_bytes()
                    + allocation_size(data.lookup.name.len())
                    + data.cause.allocated_payload_bytes()
            }
            Self::ArtifactUnavailable(text)
            | Self::SemanticEvidenceGap(text)
            | Self::SemanticEvidenceUnavailable(text) => allocation_size(text.len()),
            Self::StructureUnavailable(file) => file.allocated_heap_bytes(),
            Self::StoreFailure(error) => allocation_size(error.retained_message_capacity()),
            Self::Cancelled
            | Self::InternalInvariant(_)
            | Self::SemanticModelsPending
            | Self::ProofStopped { .. } => 0,
        }
    }

    /// Lossless identity of a returned deterministic cause, including lookup
    /// attribution. Operational or unregistered stops cannot authorize reuse.
    #[doc(hidden)]
    pub fn canonical_replay_key(&self) -> Option<Vec<u8>> {
        let (cause, lookup) = match self {
            Self::Attributed(data) => {
                let AttributedQueryReadIncomplete { lookup, cause } = data.as_ref();
                let QueryLookupProvenance {
                    file,
                    byte_span,
                    name,
                    tier,
                } = lookup;
                let lookup = (
                    // Memory-only identity: preserve native root and relative
                    // path bytes, including Unix non-UTF-8 and Windows WTF-8.
                    file.root().as_os_str().as_encoded_bytes(),
                    file.rel_path().as_os_str().as_encoded_bytes(),
                    byte_span.start as u64,
                    byte_span.end as u64,
                    name.as_ref(),
                    *tier,
                );
                (cause, Some(lookup))
            }
            cause => (cause, None),
        };
        let (kind, body) = match cause {
            Self::ArtifactUnavailable(body) => ("artifact", body.as_ref()),
            Self::SemanticEvidenceGap(body) => ("gap", body.as_ref()),
            Self::ProofStopped {
                reason,
                cause: None,
            } if DETERMINISTIC_PROOF_STOP_LABELS.contains(reason) => ("proof", *reason),
            Self::Attributed(_)
            | Self::Cancelled
            | Self::InternalInvariant(_)
            | Self::ProofStopped { .. }
            | Self::StructureUnavailable(_)
            | Self::SemanticEvidenceUnavailable(_)
            | Self::SemanticModelsPending
            | Self::StoreFailure(_) => return None,
        };
        Some(serde_json::to_vec(&(kind, body, lookup)).expect("typed cause fields serialize"))
    }

    /// Stable presentation order for completion reasons, independent of capture
    /// and memo replay order. Execution failures sort before content gaps, as in
    /// `merge_optional`. Specific causes precede registered empty-unit gaps;
    /// content and lookup provenance then break ties without changing the cause.
    /// This is an answer presentation key, never a cache-admission certificate.
    #[doc(hidden)]
    pub fn answer_order_key(&self) -> Vec<u8> {
        // These registered empty-unit causes carry less evidence than a
        // concrete lookup, unit identity or other specific refusal. Classify
        // exact producer values only: never parse IDs out of diagnostic prose.
        // Keep this specificity order here, shared by selection and rendering.
        const EMPTY_UNIT_GAPS: &[&str] = &[
            "Rust route evidence is incomplete for units []",
            "selected Rust crate membership is incomplete: []",
        ];
        let specificity = match self.base_cause() {
            Self::SemanticEvidenceGap(body) if EMPTY_UNIT_GAPS.contains(&body.as_ref()) => 1,
            _ => 0,
        };
        let (kind, body) = match self.base_cause() {
            Self::Attributed(_) => unreachable!("lookup provenance cannot nest"),
            Self::Cancelled => ("cancelled", String::new()),
            Self::InternalInvariant(detail) => ("internal_invariant", (*detail).to_owned()),
            Self::ProofStopped { reason, cause } => ("proof", format!("{reason}\0{cause:?}")),
            Self::StructureUnavailable(file) => ("structure", format!("{file:?}")),
            Self::SemanticEvidenceUnavailable(text) => ("unavailable", text.to_string()),
            Self::SemanticModelsPending => ("models_pending", String::new()),
            Self::ArtifactUnavailable(text) => ("artifact", text.to_string()),
            Self::SemanticEvidenceGap(text) => ("gap", text.to_string()),
            Self::StoreFailure(error) => ("store", format!("{error:?}")),
        };
        let lookup = self.lookup_provenance().map(|lookup| {
            (
                // Debug renders both root and relative path, including
                // non-UTF-8 path bytes. Equal display keys must not hide a
                // different file when completion is rendered with Debug.
                format!("{:?}", lookup.file),
                lookup.byte_span.start as u64,
                lookup.byte_span.end as u64,
                lookup.name.as_ref(),
                lookup.tier,
            )
        });
        serde_json::to_vec(&(
            !self.is_execution_dependent(),
            specificity,
            kind,
            body,
            lookup,
        ))
        .expect("typed presentation fields serialize")
    }

    /// Stable replay representation. Unknown typed stops fail closed.
    pub fn stable_replay_reason(&self) -> Option<String> {
        self.replay_reason_parts()
            .map(|(kind, reason)| format!("{kind}\0{reason}"))
    }

    /// Inspect registered replay provenance without allocating rendered prose.
    pub fn has_stable_replay_reason(&self) -> bool {
        self.replay_reason_parts().is_some()
    }

    fn replay_reason_parts(&self) -> Option<(&'static str, &str)> {
        match self.base_cause() {
            Self::ArtifactUnavailable(value) => Some(("artifact", value)),
            Self::SemanticEvidenceGap(value) => Some(("gap", value)),
            Self::ProofStopped {
                reason,
                cause: None,
            } if DETERMINISTIC_PROOF_STOP_LABELS.contains(reason) => Some(("proof", reason)),
            _ => None,
        }
    }

    /// Registered reason label shared by query consumers.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Attributed(data) => data.cause.label(),
            Self::ProofStopped { .. } => match self.execution_cause() {
                None => "semantic_evidence_gap",
                Some(crate::analyzer::derivation_cause::DerivationExecutionCause::Cancelled) => {
                    "cancelled"
                }
                Some(_) => "semantic_evidence_unavailable",
            },
            Self::SemanticModelsPending => "semantic_models_pending",
            Self::Cancelled => "cancelled",
            Self::InternalInvariant(_) => "internal_invariant",
            Self::StructureUnavailable(_) => "structure_unavailable",
            Self::SemanticEvidenceUnavailable(_) => "semantic_evidence_unavailable",
            Self::ArtifactUnavailable(_) => "artifact_unavailable",
            Self::SemanticEvidenceGap(_) => "semantic_evidence_gap",
            Self::StoreFailure(_) => "store_failure",
        }
    }

    /// Combine two reasons observed for one lookup. An execution-dependent
    /// reason (cancellation, a store failure, or a provider failure) is not
    /// hidden by an earlier stable content gap.
    pub fn merge_optional(first: Option<Self>, second: Option<Self>) -> Option<Self> {
        match (first, second) {
            (Some(first), Some(second))
                if !first.is_execution_dependent() && second.is_execution_dependent() =>
            {
                Some(second)
            }
            (Some(first), Some(second)) => Some(
                if first == second || first.answer_order_key() <= second.answer_order_key() {
                    first
                } else {
                    second
                },
            ),
            (first, second) => first.or(second),
        }
    }

    /// Structural admission refusals and typed semantic gaps are properties of
    /// recorded inputs. Unclassified semantic failures remain conservative;
    /// typed producers use SemanticEvidenceGap only for deterministic gaps.
    pub fn is_execution_dependent(&self) -> bool {
        self.execution_cause().is_some()
    }

    /// Whether this reason concerns the request that recorded it, not the
    /// question that request asked (cancellation). Another request sharing the
    /// answer must not adopt it; it recomputes.
    pub fn belongs_to_leader_request(&self) -> bool {
        self.execution_cause()
            == Some(crate::analyzer::derivation_cause::DerivationExecutionCause::Cancelled)
    }

    /// Operational provenance of an incomplete read, independent of its value.
    pub fn execution_cause(
        &self,
    ) -> Option<crate::analyzer::derivation_cause::DerivationExecutionCause> {
        use crate::analyzer::derivation_cause::DerivationExecutionCause;
        match self {
            Self::Attributed(data) => data.cause.execution_cause(),
            Self::ProofStopped { reason, cause } => cause.or_else(|| {
                (!DETERMINISTIC_PROOF_STOP_LABELS.contains(reason))
                    .then_some(DerivationExecutionCause::Provider)
            }),
            Self::StructureUnavailable(_)
            | Self::ArtifactUnavailable(_)
            | Self::SemanticEvidenceGap(_) => None,
            Self::Cancelled => Some(DerivationExecutionCause::Cancelled),
            Self::StoreFailure(_)
            | Self::InternalInvariant(_)
            | Self::SemanticEvidenceUnavailable(_)
            | Self::SemanticModelsPending => Some(DerivationExecutionCause::Provider),
        }
    }
}

/// A lookup distinguishes established absence from an incomplete read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome<T> {
    Found(T),
    NotFound,
    Incomplete(QueryReadIncomplete),
}

impl<T> LookupOutcome<T> {
    /// Convert a set-valued inventory answer. Even an empty inventory is Found;
    /// NotFound is a contract violation at this boundary.
    pub fn into_inventory_result(self) -> Result<T, QueryReadIncomplete> {
        match self {
            Self::Found(value) => Ok(value),
            Self::Incomplete(reason) => Err(reason),
            Self::NotFound => unreachable!("an inventory always has a set answer"),
        }
    }
}

/// Converts a lookup's plain answer, treating None as established absence.
/// Sound only where read failures cannot hide behind None: inside
/// `capture_lookup_answer`, which turns any captured read failure into
/// Incomplete, or for a fixed in-memory index that is complete by
/// construction. Never use it to wrap an uncaptured store-backed lookup.
impl<T> From<Option<T>> for LookupOutcome<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => Self::Found(value),
            None => Self::NotFound,
        }
    }
}

impl From<StoreError> for QueryReadIncomplete {
    fn from(error: StoreError) -> Self {
        Self::StoreFailure(error)
    }
}

impl std::fmt::Display for QueryReadIncomplete {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for QueryReadIncomplete {}
