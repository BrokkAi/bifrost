#[doc(hidden)]
pub mod java_functional;
#[doc(hidden)]
pub mod java_hierarchy;

pub use crate::analyzer::semantic_model::overlay::java_hierarchy::JavaHierarchyAnswer;

pub use crate::analyzer::semantic_model::overlay::java_hierarchy::JavaHierarchyIncomplete;

pub use crate::analyzer::semantic_model::overlay::java_hierarchy::JavaHierarchyWitness;

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::analyzer::semantic_model::ActivePackExtractionGap;

use brokk_bifrost_core::analyzer::model::AmbientUseRole;

use crate::analyzer::semantic_model::AsciiTransform;

use crate::analyzer::semantic_model::Completeness;

use crate::analyzer::semantic_model::EmbeddedTypeFact;

use crate::analyzer::semantic_model::ExplicitValueOperation;

use crate::analyzer::semantic_model::HierarchyFact;

use crate::analyzer::semantic_model::HierarchyKind;

use crate::analyzer::semantic_model::ImplicitOperation;

use crate::analyzer::semantic_model::KeyedReadBehavior;

use crate::analyzer::semantic_model::KeyedReadObservation;

use crate::analyzer::semantic_model::Locator;

use crate::analyzer::semantic_model::MemberFact;

use crate::analyzer::semantic_model::MemberKind;

use crate::analyzer::semantic_model::ReceiverFact;

use crate::analyzer::semantic_model::RelationKind;

use crate::analyzer::semantic_model::RuleTrigger;

use crate::analyzer::semantic_model::RuntimeGlobalBindingEvidence;

use crate::analyzer::semantic_model::RuntimeGlobalExposure;

use crate::analyzer::semantic_model::RuntimeValuesPayload;

use crate::analyzer::semantic_model::Signature;

use crate::analyzer::semantic_model::StructuredTypeExpression;

use crate::analyzer::semantic_model::TemplateExpression;

use crate::analyzer::semantic_model::TemplateParameter;

use crate::analyzer::semantic_model::TemplateSignature;

use crate::analyzer::semantic_model::TemplateTypeRef;

use crate::analyzer::semantic_model::TypeFact;

use crate::analyzer::semantic_model::TypeKind;

use crate::analyzer::semantic_model::TypeParameterConstraint;

use crate::analyzer::semantic_model::TypeRef;

use crate::analyzer::semantic_model::TypeRefReferenceKind;

use crate::analyzer::semantic_model::TypeValueSemantics;

use crate::analyzer::semantic_model::Visibility;

use crate::analyzer::semantic::LengthDelimitedDigest;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

#[doc(hidden)]
pub const MODEL_URI_BASE: &str = "bifrost-model://v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelOriginKind {
    WorkspaceSource,
    ExactGeneratedOutput,
    DependencySource,
    DependencyBinary,
    PrebuiltApiIndex,
    DeclarativeModel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelProof {
    AuthoredAnchor,
    ExactArtifact,
    PackFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelCompleteness {
    Partial,
    Complete,
}

impl SemanticModelCompleteness {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Partial => "partial",
            Self::Complete => "complete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelSymbolKind {
    Class,
    Annotation,
    Delegate,
    Interface,
    Trait,
    Struct,
    Union,
    Enum,
    Record,
    Module,
    TypeAlias,
    Constructor,
    Method,
    Function,
    Field,
    Property,
    Constant,
    Static,
    Macro,
    Event,
}

impl SemanticModelSymbolKind {
    /// Whether this kind is a type declaration, the only shape a hierarchy
    /// edge can cross to. Members and values never are, so a pack that
    /// publishes a constant beside a same-named class cannot answer a base
    /// clause with the constant.
    #[doc(hidden)]
    pub fn is_type_declaration(self) -> bool {
        matches!(
            self,
            Self::Class
                | Self::Annotation
                | Self::Delegate
                | Self::Interface
                | Self::Trait
                | Self::Struct
                | Self::Union
                | Self::Enum
                | Self::Record
                | Self::Module
                | Self::TypeAlias
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelRange {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
}

impl From<Range> for SemanticModelRange {
    fn from(range: Range) -> Self {
        Self {
            start_byte: range.start_byte,
            end_byte: range.end_byte,
            start_line: range.start_line,
            end_line: range.end_line,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelAuthoredAnchor {
    pub path: String,
    pub symbol: String,
    pub range: SemanticModelRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelVirtualLocation {
    pub uri: String,
    pub range: SemanticModelRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticModelLocation {
    Authored(SemanticModelAuthoredAnchor),
    Model(SemanticModelVirtualLocation),
}

impl SemanticModelLocation {
    pub fn identity(&self) -> &str {
        match self {
            Self::Authored(anchor) => &anchor.path,
            Self::Model(location) => &location.uri,
        }
    }

    pub fn range(&self) -> &SemanticModelRange {
        match self {
            Self::Authored(anchor) => &anchor.range,
            Self::Model(location) => &location.range,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SemanticModelActivationProvenance {
    /// The pack was selected without exact toolchain evidence.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub approximate: bool,
    pub status: String,
    pub reason: String,
    pub source_kind: String,
    pub source_id: String,
    pub matched_evidence: SemanticModelMatchedEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SemanticModelMatchedCoordinate {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SemanticModelMatchedEvidence {
    pub language: String,
    pub ecosystem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<SemanticModelMatchedCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<SemanticModelMatchedCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<SemanticModelMatchedCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SemanticModelProvenance {
    pub active_model_set_hash: String,
    pub pack_digest: String,
    pub pack_id: String,
    pub pack_version: String,
    pub producer: String,
    pub producer_version: String,
    pub record_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub origin: SemanticModelOriginKind,
    pub activation: SemanticModelActivationProvenance,
    pub proof: SemanticModelProof,
    pub completeness: SemanticModelCompleteness,
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct GeneratedFunctionScope {
    #[doc(hidden)]
    pub file: String,
    #[doc(hidden)]
    pub module: String,
    #[doc(hidden)]
    pub local: Option<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelSymbol {
    /// Current activation authority, distinct from this positive declaration.
    #[serde(skip)]
    #[doc(hidden)]
    pub jvm_owner_family_enumerated: bool,
    #[serde(skip)]
    #[doc(hidden)]
    pub rust_generated_scope: Option<Box<GeneratedFunctionScope>>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    pub name: String,
    pub qualified_name: String,
    pub language: String,
    pub kind: SemanticModelSymbolKind,
    pub visibility: Visibility,
    #[serde(skip)]
    #[doc(hidden)]
    pub is_static: bool,
    #[serde(skip)]
    #[doc(hidden)]
    pub non_overridable: Option<crate::analyzer::semantic_model::NonOverridableEvidence>,
    #[serde(skip)]
    #[doc(hidden)]
    pub declaration_is_abstract: bool,
    #[serde(skip)]
    #[doc(hidden)]
    pub declaration_is_sealed: bool,
    #[serde(skip)]
    #[doc(hidden)]
    pub callable_surface_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip)]
    #[doc(hidden)]
    pub structured_signature: Option<Signature>,
    #[serde(skip)]
    #[doc(hidden)]
    pub has_explicit_type_terms: bool,
    #[serde(skip)]
    #[doc(hidden)]
    pub callable_shape: Option<String>,
    #[serde(skip)]
    #[doc(hidden)]
    pub callable_shape_evidence_complete: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub callable_family_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exact_return_classes: Vec<TypeRef>,
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub type_parameter_constraints: Vec<TypeParameterConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub underlying_type: Option<StructuredTypeExpression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_semantics: Option<TypeValueSemantics>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub embedded_types: Vec<EmbeddedTypeFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<ReceiverFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implicit_operation: Option<ImplicitOperation>,
    /// The declaration's reviewed role in a value operation the call site
    /// spells, carried through from the pack record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_operation: Option<ExplicitValueOperation>,
    /// The declaration's reviewed contextual role, carried through from the
    /// pack record. `None` means the producer did not review it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ambient_use: Option<AmbientUseRole>,
    #[serde(skip)]
    #[doc(hidden)]
    pub value_type: Option<TypeRef>,
    #[serde(skip)]
    #[doc(hidden)]
    pub proxied_type: Option<TypeRef>,
    #[serde(skip)]
    #[doc(hidden)]
    pub extension_receiver: Option<TypeRef>,
    #[serde(skip)]
    #[doc(hidden)]
    pub extension_receiver_constraints: Vec<TypeRef>,
    #[serde(skip)]
    #[doc(hidden)]
    pub locator_path: Option<String>,
    #[serde(skip)]
    #[doc(hidden)]
    pub locator_symbol: Option<String>,
    pub location: SemanticModelLocation,
    pub provenance: SemanticModelProvenance,
}

/// The structured identity of a callable that the semantic oracle resolved
/// without materializing a declaration.
///
/// This is deliberately the same shape as the oracle's unmaterialized target
/// key. Callers should populate it from that typed target, rather than deriving
/// it from a rendered signature or a source spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticModelCallableKey<'a> {
    pub language: &'a str,
    pub owner: &'a str,
    pub member: &'a str,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

impl<'a> SemanticModelCallableKey<'a> {
    pub const fn new(
        language: &'a str,
        owner: &'a str,
        member: &'a str,
        has_receiver: bool,
        parameter_count: u32,
    ) -> Self {
        Self {
            language,
            owner,
            member,
            has_receiver,
            parameter_count,
        }
    }
}

/// The structured application facts for one call to a modeled callable.
///
/// These facts come from the shared call-shape relation, not from a reparsed
/// call expression. They are necessary because written-argument count is not
/// callable applicability: named actuals, defaults, and unexpanded spreads all
/// change which declaration can accept the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticModelCallApplication {
    Unknown,
    Written {
        positional_count: u32,
        named_labels: Vec<String>,
        has_spread: bool,
    },
}

impl SemanticModelCallApplication {
    pub fn positional(parameter_count: u32) -> Self {
        Self::Written {
            positional_count: parameter_count,
            named_labels: Vec::new(),
            has_spread: false,
        }
    }

    pub fn structured(
        positional_count: usize,
        named_labels: Vec<String>,
        has_spread: bool,
    ) -> Self {
        let positional_count =
            u32::try_from(positional_count).expect("structured argument counts fit u32");
        Self::Written {
            positional_count,
            named_labels,
            has_spread,
        }
    }

    #[doc(hidden)]
    pub fn written(&self) -> Option<(usize, &[String], bool)> {
        match self {
            Self::Unknown => None,
            Self::Written {
                positional_count,
                named_labels,
                has_spread,
            } => Some((
                usize::try_from(*positional_count).expect("u32 argument count fits usize"),
                named_labels,
                *has_spread,
            )),
        }
    }
}

/// Why a model record cannot provide an exact formal layout for one external
/// call target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelCallableIncompleteReason {
    /// The owner or member came from a partial active model.
    PartialModel,
    /// The active model explicitly marked this record as ambiguous.
    AmbiguousModel,
    /// The model did not publish a structured signature.
    MissingSignature,
    /// The model published a signature but omitted one formal name.
    MissingFormalName { ordinal: usize },
    /// The call shape did not enumerate an exact application.
    ApplicationUnavailable,
    /// The written positional and named actuals match no declaration.
    ApplicationMismatch,
    /// A spread or splat prevents exact application and formal mapping.
    UnexpandedSpread,
}

/// Typed result of resolving an unmaterialized external target against the
/// activated declaration-model overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelCallableDisposition {
    Empty,
    Unique,
    /// Multiple overloads remain applicable but share one exact binding
    /// layout. Their overload identity remains unresolved.
    CompatibleLayout,
    Conflict,
    Incomplete(SemanticModelCallableIncompleteReason),
}

#[derive(Debug)]
pub struct SemanticModelCallableMatch<'a> {
    pub records: Vec<&'a SemanticModelSymbol>,
    pub disposition: SemanticModelCallableDisposition,
}

impl<'a> SemanticModelCallableMatch<'a> {
    pub fn unique(&self) -> Option<&'a SemanticModelSymbol> {
        (self.disposition == SemanticModelCallableDisposition::Unique)
            .then(|| self.records.first().copied())
            .flatten()
    }

    /// Stable identity of the exact declared callable family represented by
    /// this match. A unique declaration keeps its authored record identity;
    /// a complete overload family receives a domain-separated identity over
    /// its exact record identities. The latter names the callable without
    /// pretending that one overload record was selected.
    pub fn callable_family_id(&self) -> Option<String> {
        semantic_model_callable_family_id(&self.records)
    }
}

/// Derive one exact callable-family identity from active model records.
///
/// Every overload must belong to a complete model or explicitly certify
/// complete family coverage, and share one structured owner/name/call shape
/// plus one activation provenance. This is deliberately unavailable for
/// partial, ambiguous, cross-pack, or merely same-named records.
pub fn semantic_model_callable_family_id(records: &[&SemanticModelSymbol]) -> Option<String> {
    let first = *records.first()?;
    if !member_is_callable(first) {
        return None;
    }
    if records.len() == 1 {
        // A generated C function has no overload family within its header
        // owner. Keep its authored owner/member locator as the family
        // identity even when the variadic signature deliberately cannot
        // certify complete callable-family coverage. The signature remains
        // incomplete for binding purposes; this only gives policy locators a
        // stable identity to resolve.
        if first.language == "cpp"
            && first.kind == SemanticModelSymbolKind::Function
            && first.owner_id.is_some()
            && !first.has_receiver()
            && !first.callable_family_complete
            && !first.provenance.ambiguous
            && first.provenance.origin == SemanticModelOriginKind::ExactGeneratedOutput
            && first
                .structured_signature
                .as_ref()
                .is_some_and(|signature| {
                    signature
                        .parameters
                        .last()
                        .is_some_and(|parameter| parameter.variadic)
                })
        {
            return Some(first.qualified_name.clone());
        }
        return (!first.provenance.ambiguous
            && (first.provenance.completeness == SemanticModelCompleteness::Complete
                || first.callable_family_complete))
            .then(|| first.id.clone());
    }
    let first_provenance = &first.provenance;
    let same_family = records.iter().all(|record| {
        !record.provenance.ambiguous
            && (record.provenance.completeness == SemanticModelCompleteness::Complete
                || record.callable_family_complete)
            && record.owner_id == first.owner_id
            && record.name == first.name
            && record.language == first.language
            && record.kind == first.kind
            && record.has_receiver() == first.has_receiver()
            && record.provenance.active_model_set_hash == first_provenance.active_model_set_hash
            && record.provenance.pack_digest == first_provenance.pack_digest
            && record.provenance.pack_id == first_provenance.pack_id
            && record.provenance.pack_version == first_provenance.pack_version
            && record.provenance.producer == first_provenance.producer
            && record.provenance.producer_version == first_provenance.producer_version
            && record.provenance.origin == first_provenance.origin
            && record.provenance.activation == first_provenance.activation
            && record.provenance.proof == first_provenance.proof
    });
    if !same_family {
        return None;
    }
    let mut record_ids = records
        .iter()
        .map(|record| record.id.as_str())
        .collect::<Vec<_>>();
    record_ids.sort_unstable();
    record_ids.dedup();
    if record_ids.len() != records.len() {
        return None;
    }
    let mut digest = LengthDelimitedDigest::new(b"bifrost.semantic_model.callable_family.v1");
    for record_id in record_ids {
        digest.push(record_id.as_bytes());
    }
    Some(digest.finish().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelRelation {
    pub id: String,
    pub kind: String,
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_ordinal: Option<u32>,
    pub provenance: SemanticModelProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelOverlayDisposition {
    Empty,
    Unique,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SemanticModelOverlayBuildError {
    Cancelled,
    RetainedBytesExceeded,
    GoSurfaceTraversalExceeded,
}

#[derive(Debug)]
pub struct SemanticModelOverlayMatch<'a, T> {
    pub records: Vec<&'a T>,
    pub disposition: SemanticModelOverlayDisposition,
}

impl<'a, T> SemanticModelOverlayMatch<'a, T> {
    #[doc(hidden)]
    pub fn unique(&self) -> Option<&'a T> {
        (self.disposition == SemanticModelOverlayDisposition::Unique)
            .then(|| self.records.first().copied())
            .flatten()
    }
}

/// Result of resolving one static member from one exact modeled owner.
///
/// `Unique` is the only disposition that proves an exact target. `Absent`
/// means the active model proves the complete owner surface and the member is
/// not on it. `Incomplete` preserves a missing/partial owner or hierarchy;
/// `Conflict` preserves competing owner or member records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelMemberTargetDisposition {
    Unique,
    Absent,
    Incomplete,
    Conflict,
}

#[derive(Debug)]
pub struct SemanticModelMemberTargetMatch<'a> {
    pub records: Vec<&'a SemanticModelSymbol>,
    pub disposition: SemanticModelMemberTargetDisposition,
}

/// The value operation an owner performs for one written member name and
/// argument count, together with every declaration that performs it.
///
/// `operation` is present only on a `Unique` disposition. The records are
/// retained on every disposition so a caller can report exactly which
/// declarations disagreed or were incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticModelExplicitOperationMatch<'a> {
    pub operation: Option<ExplicitValueOperation>,
    pub records: Vec<&'a SemanticModelSymbol>,
    pub disposition: SemanticModelMemberTargetDisposition,
}

/// Why one hierarchy edge does not reach exactly one published declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelEdgeDefect {
    /// No active pack published the target at all. A base class nothing
    /// indexed is indistinguishable from no base class without this fact.
    Unpublished,
    /// The target matched only a simple-name or alias posting, never a
    /// declaration identity and never a qualified name. A bare `Widget` can
    /// match `com.acme.Widget` that way, so the match is a guess.
    NameResolved,
    /// More than one published declaration answers the target.
    Ambiguous,
}

/// One hierarchy edge an ancestor walk could not cross cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticModelUnresolvedEdge {
    /// Qualified name of the type that declares the edge.
    pub from: String,
    /// The target the pack recorded: a declaration identity, a qualified
    /// name, or the language's implicit universal root.
    pub to: String,
    pub defect: SemanticModelEdgeDefect,
}

impl std::fmt::Display for SemanticModelUnresolvedEdge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { from, to, defect } = self;
        match defect {
            SemanticModelEdgeDefect::Unpublished => write!(
                formatter,
                "`{from}` inherits `{to}`, which no active semantic pack published"
            ),
            SemanticModelEdgeDefect::NameResolved => write!(
                formatter,
                "`{from}` inherits `{to}`, which matched only by simple name"
            ),
            SemanticModelEdgeDefect::Ambiguous => write!(
                formatter,
                "`{from}` inherits `{to}`, which more than one active semantic pack declares"
            ),
        }
    }
}

/// A model type's ancestors, plus every hierarchy edge the walk could not
/// cross cleanly.
///
/// `records` stays best effort so navigation keeps every ancestor candidate it
/// had before. `defects` is what a proof must consult: it is the complete list
/// of edges whose target the overlay could not pin to one published
/// declaration, which is exactly the difference between "this type has no base"
/// and "nothing published this type's base".
#[derive(Debug)]
pub struct SemanticModelAncestry<'a> {
    pub records: Vec<&'a SemanticModelSymbol>,
    pub disposition: SemanticModelOverlayDisposition,
    pub defects: Vec<SemanticModelUnresolvedEdge>,
}

/// What one hierarchy edge target resolved to, and whether the resolution is
/// clean. Produced only by `SemanticModelOverlay::resolve_edge_target`.
#[doc(hidden)]
pub struct ResolvedEdgeTarget<'a> {
    #[doc(hidden)]
    pub records: Vec<&'a SemanticModelSymbol>,
    #[doc(hidden)]
    pub defect: Option<SemanticModelEdgeDefect>,
}

/// What declaration kinds a hierarchy edge may name.
///
/// The edge label alone does not fix the target's kind, because each producer
/// spends the label vocabulary its own way: the JVM external packs record every
/// supertype as `extends`, whether it names a class, an interface or a trait,
/// and Rust records a trait implementation as `implements`, naming a trait.
/// A pack that records a supertype by name does not record its kind at all, so
/// [`HierarchyTargetShape::Type`] admits every type declaration and still
/// rejects a same-named method, field or constant, which is what keeps a value
/// from answering a class base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum HierarchyTargetShape {
    /// One specific declaration kind, where the caller knows it. Java
    /// `implements` always names an interface, so the widening walk asks for
    /// that kind and not merely for a type.
    Kind(SemanticModelSymbolKind),
    /// Any type declaration.
    Type,
}

impl HierarchyTargetShape {
    #[doc(hidden)]
    pub fn admits(self, record: &SemanticModelSymbol) -> bool {
        match self {
            Self::Kind(kind) => record.kind == kind,
            Self::Type => record.kind.is_type_declaration(),
        }
    }
}

/// A reason one owner's inherited surface may not be all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticModelSurfaceGap {
    /// An edge in the closure did not reach one published declaration.
    UnresolvedEdge(SemanticModelUnresolvedEdge),
    /// The pack that published this type claims only a partial surface, so a
    /// member it does not list may still exist.
    PartialType { qualified_name: String },
    /// More than one active pack publishes this type.
    AmbiguousType { qualified_name: String },
}

impl std::fmt::Display for SemanticModelSurfaceGap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnresolvedEdge(edge) => edge.fmt(formatter),
            Self::PartialType { qualified_name } => write!(
                formatter,
                "the active semantic pack for `{qualified_name}` is partial"
            ),
            Self::AmbiguousType { qualified_name } => write!(
                formatter,
                "more than one active semantic pack declares `{qualified_name}`"
            ),
        }
    }
}

/// One type's whole inherited surface, and every reason that surface may be
/// incomplete.
///
/// This is the three-layer gate a member-absence proof needs: every recorded
/// edge in the closure resolves cleanly, every type in the closure comes from a
/// pack that claims a complete surface, and the closure bottoms out either at a
/// type that declares no supertype or at the language's published universal
/// root. A gap in any layer means a member missing from `closure` may still
/// exist, so the caller must suppress rather than prove.
#[derive(Debug)]
pub struct SemanticModelOwnerSurface<'a> {
    /// The owner first, then every ancestor whose members belong to the
    /// owner's surface.
    pub closure: Vec<&'a SemanticModelSymbol>,
    /// Empty exactly when the closure is provably the whole surface. Otherwise
    /// the gaps in gate order: unresolved edges first, then the types whose own
    /// provenance does not support a proof.
    pub gaps: Vec<SemanticModelSurfaceGap>,
}

/// One callable's declaring owner and the typed hierarchy path from its receiver.
/// This is a query result; no candidate or path survives the query.
#[derive(Debug)]
#[doc(hidden)]
pub struct SemanticModelCallableOwner<'a> {
    pub owner: &'a SemanticModelSymbol,
    pub hierarchy: Vec<HierarchyFact>,
}

impl SemanticModelOwnerSurface<'_> {
    /// Whether a member absent from every type in `closure` is absent from the
    /// owner.
    pub fn proves_absence(&self) -> bool {
        self.gaps.is_empty()
    }
}

#[derive(Debug)]
pub struct RuntimeValueContracts {
    pub provenance: SemanticModelProvenance,
    pub payload: RuntimeValuesPayload,
}

impl RuntimeValueContracts {
    pub fn exposures(&self) -> &[RuntimeGlobalExposure] {
        &self.payload.exposures
    }

    pub fn behaviors(&self) -> &[KeyedReadBehavior] {
        &self.payload.behaviors
    }

    pub fn binding_evidence(&self) -> &[RuntimeGlobalBindingEvidence] {
        &self.payload.binding_evidence
    }

    pub fn observations(&self) -> &[KeyedReadObservation] {
        &self.payload.observations
    }
}

/// One typed collection-flow fact retained with the activation evidence of the
/// shard that published it.
#[derive(Debug)]
pub struct CollectionFlowContract {
    pub provenance: SemanticModelProvenance,
    pub callable: String,
    pub payload: crate::analyzer::semantic_model::csmi::CsmiCollectionFlowPayload,
    pub coverage: Option<Completeness>,
}

/// A standard refinement scoped to the exact activated publishing pack.
#[derive(Debug)]
pub struct ConditionalTypeRefinementContract {
    pub provenance: SemanticModelProvenance,
    pub payload: crate::analyzer::semantic_model::csmi::CsmiConditionalTypeRefinement,
    pub coverage: Option<crate::analyzer::semantic_model::csmi::CsmiCoverageStatus>,
}

impl ConditionalTypeRefinementContract {
    pub fn is_complete(&self) -> bool {
        self.coverage == Some(crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Complete)
            && !self.provenance.ambiguous
    }
}

/// One deferred-yield fact retained with the activation evidence of its
/// publishing shard. Endpoint IDs remain linked scope, rather than being
/// reduced to names or a factory-only index.
#[derive(Debug)]
pub struct DeferredYieldContract {
    pub provenance: SemanticModelProvenance,
    pub factory: String,
    pub resume: String,
    pub handle_type: String,
    pub payload: crate::analyzer::semantic_model::csmi::CsmiDeferredYieldPayload,
    pub coverage: Option<Completeness>,
}

impl DeferredYieldContract {
    pub fn is_complete(&self) -> bool {
        self.coverage == Some(Completeness::Complete)
            && self.provenance.is_complete_and_unambiguous()
    }
}

impl CollectionFlowContract {
    pub fn is_complete(&self) -> bool {
        self.coverage == Some(Completeness::Complete)
            && self.provenance.is_complete_and_unambiguous()
    }
}

#[doc(hidden)]
pub fn extraction_gap_index(gaps: &[ActivePackExtractionGap]) -> HashMap<String, usize> {
    let mut index = HashMap::default();
    for (ordinal, gap) in gaps.iter().enumerate() {
        index.entry(gap.declaration.clone()).or_insert(ordinal);
    }
    index
}

/// Exact written argument positions map to signature parameter ordinals.
/// Positions are positional arguments followed by named arguments in their
/// written order. A spread never establishes an exact binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticModelArgumentBinding {
    Exact { parameter_ordinals: Vec<usize> },
    PossibleSpread,
    Mismatch,
}

pub fn bind_semantic_model_arguments(
    signature: &Signature,
    application: &SemanticModelCallApplication,
) -> SemanticModelArgumentBinding {
    let Some((positional_count, named_labels, has_spread)) = application.written() else {
        return SemanticModelArgumentBinding::Mismatch;
    };
    let mut bound = vec![false; signature.parameters.len()];
    let mut parameter_ordinals = Vec::with_capacity(positional_count + named_labels.len());

    for position in 0..positional_count {
        let matched = signature
            .parameters
            .iter()
            .enumerate()
            .filter(|(_, parameter)| parameter.passing_mode.accepts_positional())
            .nth(position)
            .map(|(ordinal, _)| ordinal)
            .or_else(|| {
                signature
                    .parameters
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(_, parameter)| {
                        parameter.variadic && parameter.passing_mode.accepts_positional()
                    })
                    .map(|(ordinal, _)| ordinal)
            });
        let Some(ordinal) = matched else {
            return SemanticModelArgumentBinding::Mismatch;
        };
        bound[ordinal] = true;
        parameter_ordinals.push(ordinal);
    }

    for label in named_labels {
        let declared = signature
            .parameters
            .iter()
            .enumerate()
            .find(|(_, parameter)| {
                parameter.passing_mode.accepts_named()
                    && parameter.name.as_deref() == Some(label.as_str())
            })
            .map(|(ordinal, _)| ordinal);
        let matched = match declared {
            Some(ordinal) if bound[ordinal] => return SemanticModelArgumentBinding::Mismatch,
            Some(ordinal) => Some(ordinal),
            None => signature
                .parameters
                .iter()
                .enumerate()
                .rev()
                .find(|(_, parameter)| {
                    parameter
                        .variadic_kind()
                        .is_some_and(|kind| kind.accepts_keyword())
                })
                .map(|(ordinal, _)| ordinal),
        };
        let Some(ordinal) = matched else {
            return SemanticModelArgumentBinding::Mismatch;
        };
        if bound[ordinal] && !signature.parameters[ordinal].variadic {
            return SemanticModelArgumentBinding::Mismatch;
        }
        bound[ordinal] = true;
        parameter_ordinals.push(ordinal);
    }

    if has_spread {
        return SemanticModelArgumentBinding::PossibleSpread;
    }
    if signature
        .parameters
        .iter()
        .zip(bound)
        .all(|(parameter, bound)| parameter.optional || parameter.variadic || bound)
    {
        SemanticModelArgumentBinding::Exact { parameter_ordinals }
    } else {
        SemanticModelArgumentBinding::Mismatch
    }
}

#[doc(hidden)]
pub fn binding_layouts_match(left: &Signature, right: &Signature) -> bool {
    left.parameters.len() == right.parameters.len()
        && left
            .parameters
            .iter()
            .zip(&right.parameters)
            .all(|(left, right)| {
                left.optional == right.optional
                    && left.variadic == right.variadic
                    && left.passing_mode == right.passing_mode
            })
}

impl SemanticModelSymbol {
    pub fn is_rule_generated_function(&self) -> bool {
        self.kind == SemanticModelSymbolKind::Function && self.provenance.rule_id.is_some()
    }

    /// Whether the active declaration carries enough validated evidence to
    /// bind one exact callable shape. Python CSMI shape evidence is independent
    /// of native callable-family completeness.
    pub fn has_complete_callable_shape_evidence(&self) -> bool {
        self.callable_shape_evidence_complete
    }

    /// Abstractness published by the declaration producer. Consumers must
    /// separately require complete, unambiguous declaration provenance.
    pub fn declaration_is_abstract(&self) -> bool {
        self.declaration_is_abstract
    }

    /// Whether the producer records restricted or closed inheritance. In Java
    /// this includes both `sealed` and `final`; it does not enumerate permitted
    /// subclasses or prove that a class has no descendants.
    pub fn declaration_is_sealed(&self) -> bool {
        self.declaration_is_sealed
    }

    /// Positive coverage of this declaration's own externally visible
    /// callables and direct hierarchy edges, independently of pack coverage.
    pub fn callable_surface_complete(&self) -> bool {
        self.callable_surface_complete
    }

    pub fn externally_visible(&self) -> bool {
        self.visibility.is_externally_visible()
    }

    /// The structured callable signature, when the model published one.
    pub fn structured_signature(&self) -> Option<&Signature> {
        self.structured_signature.as_ref()
    }

    /// Whether the declaration model record names this exact artifact
    /// declaration. Both values come from structured locators retained by
    /// their producers; callers must not reconstruct either from display
    /// names or rendered signatures.
    pub fn has_exact_artifact_locator(&self, path: &str, symbol: &str) -> bool {
        self.locator_path.as_deref() == Some(path) && self.locator_symbol.as_deref() == Some(symbol)
    }

    /// Whether this model member is static according to the authored fact.
    pub const fn is_static(&self) -> bool {
        self.is_static
    }

    /// Whether the model's structured member identity includes an instance
    /// receiver. A non-static method is an instance callable even when the
    /// declaration model omits a separate receiver fact; explicit receiver
    /// facts cover languages that model extension or value receivers directly.
    pub fn has_receiver(&self) -> bool {
        self.receiver.is_some()
            || (matches!(self.kind, SemanticModelSymbolKind::Method) && !self.is_static)
    }
}

#[doc(hidden)]
pub fn symbol_kind_is_callable(kind: SemanticModelSymbolKind) -> bool {
    matches!(
        kind,
        SemanticModelSymbolKind::Constructor
            | SemanticModelSymbolKind::Method
            | SemanticModelSymbolKind::Function
    )
}

#[doc(hidden)]
pub fn member_is_callable(symbol: &SemanticModelSymbol) -> bool {
    symbol_kind_is_callable(symbol.kind)
}

#[doc(hidden)]
pub fn member_has_receiver(symbol: &SemanticModelSymbol) -> bool {
    symbol.has_receiver()
}

/// The qualified name every declaration of `language` implicitly inherits,
/// when the language has such a root.
///
/// Python's `builtins.object` is here because a Python class with no written
/// base still inherits `object`'s members, so an absence claim that has not
/// seen `object`'s surface is not a proof.
pub fn universal_root_name_for_language(language: &str) -> Option<&'static str> {
    match language {
        "java" => Some("java.lang.Object"),
        "scala" => Some("scala.Any"),
        "python" => Some("builtins.object"),
        _ => None,
    }
}

#[doc(hidden)]
pub fn universal_root_name(symbol: &SemanticModelSymbol) -> Option<&'static str> {
    if symbol.owner_id.is_some() {
        return None;
    }
    let inherits_root = match symbol.language.as_str() {
        "java" => matches!(
            symbol.kind,
            SemanticModelSymbolKind::Class
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Record
        ),
        "scala" => matches!(
            symbol.kind,
            SemanticModelSymbolKind::Class
                | SemanticModelSymbolKind::Interface
                | SemanticModelSymbolKind::Trait
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Record
                | SemanticModelSymbolKind::Module
        ),
        // A Python module is a namespace, not a class, so only class-shaped
        // declarations inherit `object`.
        "python" => matches!(
            symbol.kind,
            SemanticModelSymbolKind::Class | SemanticModelSymbolKind::Enum
        ),
        _ => false,
    };
    inherits_root.then(|| universal_root_name_for_language(&symbol.language))?
}

impl SemanticModelProvenance {
    fn is_complete_and_unambiguous(&self) -> bool {
        self.completeness == SemanticModelCompleteness::Complete && !self.ambiguous
    }

    #[doc(hidden)]
    pub fn retained_string_bytes(&self) -> usize {
        let evidence = &self.activation.matched_evidence;
        self.active_model_set_hash
            .capacity()
            .saturating_add(self.pack_digest.capacity())
            .saturating_add(self.pack_id.capacity())
            .saturating_add(self.pack_version.capacity())
            .saturating_add(self.producer.capacity())
            .saturating_add(self.producer_version.capacity())
            .saturating_add(self.record_id.capacity())
            .saturating_add(self.rule_id.as_ref().map_or(0, String::capacity))
            .saturating_add(self.activation.status.capacity())
            .saturating_add(self.activation.reason.capacity())
            .saturating_add(self.activation.source_kind.capacity())
            .saturating_add(self.activation.source_id.capacity())
            .saturating_add(evidence.language.capacity())
            .saturating_add(evidence.ecosystem.capacity())
            .saturating_add(coordinate_string_bytes(evidence.package.as_ref()))
            .saturating_add(coordinate_string_bytes(evidence.module.as_ref()))
            .saturating_add(coordinate_string_bytes(evidence.toolchain.as_ref()))
            .saturating_add(evidence.target.as_ref().map_or(0, String::capacity))
            .saturating_add(evidence.configuration.as_ref().map_or(0, String::capacity))
            .saturating_add(
                evidence
                    .artifact_sha256
                    .as_ref()
                    .map_or(0, String::capacity),
            )
    }
}

fn coordinate_string_bytes(coordinate: Option<&SemanticModelMatchedCoordinate>) -> usize {
    coordinate.map_or(0, |coordinate| {
        coordinate
            .name
            .capacity()
            .saturating_add(coordinate.version.as_ref().map_or(0, String::capacity))
    })
}

#[doc(hidden)]
pub fn disposition<T>(
    records: &[&T],
    ambiguous: impl Fn(&T) -> bool,
) -> SemanticModelOverlayDisposition {
    if records.is_empty() {
        SemanticModelOverlayDisposition::Empty
    } else if records.len() == 1 && !ambiguous(records[0]) {
        SemanticModelOverlayDisposition::Unique
    } else {
        SemanticModelOverlayDisposition::Conflict
    }
}

#[doc(hidden)]
pub fn push_unique_posting(postings: &mut HashMap<String, Vec<usize>>, key: &str, index: usize) {
    let posting = postings.entry(key.to_string()).or_default();
    if posting.last() != Some(&index) {
        posting.push(index);
    }
}

/// Runtime ancestry is an independently adjudicated claim, not declaration
/// identity. Keep TypeFact Eq, normalization, and artifact identities exact.
#[doc(hidden)]
pub fn type_declarations_equivalent(left: &TypeFact, right: &TypeFact) -> bool {
    if left.runtime_bases == right.runtime_bases {
        return left == right;
    }
    // Construction-time temporary, bounded by the validated declaration
    // artifact. No serialized shape comparison or retained projection cache.
    let mut declaration = left.clone();
    declaration.runtime_bases.clone_from(&right.runtime_bases);
    declaration == *right
}

#[doc(hidden)]
pub fn mark_symbol_identity_conflicts(symbols: &mut [SemanticModelSymbol]) {
    let mut identities: HashMap<String, Vec<usize>> = HashMap::default();
    for (index, symbol) in symbols.iter().enumerate() {
        identities.entry(symbol.id.clone()).or_default().push(index);
    }
    for posting in identities.values().filter(|posting| posting.len() > 1) {
        let mut artifacts = HashSet::default();
        let distinct_jdk_artifacts = posting.iter().all(|&index| {
            let evidence = &symbols[index].provenance.activation.matched_evidence;
            evidence.ecosystem == "jdk"
                && evidence
                    .artifact_sha256
                    .as_ref()
                    .is_some_and(|digest| artifacts.insert(digest.as_str()))
        });
        if distinct_jdk_artifacts {
            continue;
        }
        for &index in posting {
            symbols[index].provenance.ambiguous = true;
        }
    }
}

#[doc(hidden)]
pub fn augment_go_overlay_surface(
    symbols: &mut Vec<SemanticModelSymbol>,
    relations: &mut Vec<SemanticModelRelation>,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<(), SemanticModelOverlayBuildError> {
    const MAX_GO_OVERLAY_TRAVERSAL_STEPS: usize = 2_000_000;

    let mut qualified_counts = HashMap::<String, usize>::default();
    for symbol in symbols.iter().filter(|symbol| symbol.language == "go") {
        *qualified_counts
            .entry(symbol.qualified_name.clone())
            .or_default() += 1;
    }
    let type_indices = symbols
        .iter()
        .enumerate()
        .filter(|(_, symbol)| {
            symbol.language == "go"
                && symbol.owner_id.is_none()
                && symbol.externally_visible()
                && !symbol.provenance.ambiguous
                && qualified_counts.get(&symbol.qualified_name) == Some(&1)
        })
        .map(|(index, symbol)| (symbol.id.clone(), index))
        .collect::<HashMap<_, _>>();
    let qualified_type_ids = type_indices
        .iter()
        .map(|(id, index)| (symbols[*index].qualified_name.clone(), id.clone()))
        .collect::<HashMap<_, _>>();
    let direct_members = symbols
        .iter()
        .enumerate()
        .filter_map(|(index, symbol)| symbol.owner_id.as_ref().map(|owner| (owner.clone(), index)))
        .fold(
            HashMap::<String, Vec<usize>>::default(),
            |mut grouped, (owner, index)| {
                grouped.entry(owner).or_default().push(index);
                grouped
            },
        );

    let mut promoted = Vec::new();
    let mut traversal_steps = 0usize;
    for &owner_index in type_indices.values() {
        let owner = &symbols[owner_index];
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        let mut incomplete_embedded_surface = false;
        let mut resolved_names = direct_members
            .get(&owner.id)
            .into_iter()
            .flatten()
            .map(|index| symbols[*index].name.clone())
            .collect::<HashSet<_>>();
        let mut current = HashMap::<(String, bool), u8>::default();
        for embedded in &owner.embedded_types {
            if let Some(target) = overlay_declared_type_id(&embedded.target, &qualified_type_ids) {
                if let Some(&target_index) = type_indices.get(&target) {
                    if symbols[target_index].provenance.completeness
                        != SemanticModelCompleteness::Complete
                    {
                        incomplete_embedded_surface = true;
                    }
                } else {
                    incomplete_embedded_surface = true;
                }
                current
                    .entry((target, embedded.pointer))
                    .and_modify(|count| *count = 2)
                    .or_insert(1);
            } else {
                incomplete_embedded_surface = true;
            }
        }
        let mut seen_depth = HashMap::<(String, bool), usize>::default();
        seen_depth.insert((owner.id.clone(), false), 0);
        let mut depth = 1usize;
        while !current.is_empty() {
            let mut candidates = HashMap::<String, (Option<(usize, bool)>, u8)>::default();
            let mut next = HashMap::<(String, bool), u8>::default();
            for ((type_id, pointer_available), multiplicity) in current {
                traversal_steps = traversal_steps.saturating_add(1);
                if traversal_steps > MAX_GO_OVERLAY_TRAVERSAL_STEPS {
                    return Err(SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded);
                }
                if let Some(member_indices) = direct_members.get(&type_id) {
                    for &member_index in member_indices {
                        let member = &symbols[member_index];
                        if !member.externally_visible()
                            || member.provenance.ambiguous
                            || resolved_names.contains(&member.name)
                        {
                            continue;
                        }
                        let entry = candidates.entry(member.name.clone()).or_insert((None, 0));
                        entry.1 = entry.1.saturating_add(multiplicity).min(2);
                        if entry.1 == 1 {
                            entry.0 = Some((member_index, pointer_available));
                        } else {
                            entry.0 = None;
                        }
                    }
                }
                let Some(&embedded_index) = type_indices.get(&type_id) else {
                    incomplete_embedded_surface = true;
                    continue;
                };
                for embedded in &symbols[embedded_index].embedded_types {
                    let Some(target) =
                        overlay_declared_type_id(&embedded.target, &qualified_type_ids)
                    else {
                        incomplete_embedded_surface = true;
                        continue;
                    };
                    let Some(&target_index) = type_indices.get(&target) else {
                        incomplete_embedded_surface = true;
                        continue;
                    };
                    if symbols[target_index].provenance.completeness
                        != SemanticModelCompleteness::Complete
                    {
                        incomplete_embedded_surface = true;
                    }
                    let state = (target, pointer_available || embedded.pointer);
                    match seen_depth.get(&state).copied() {
                        Some(previous) if previous < depth + 1 => continue,
                        Some(_) => {}
                        None => {
                            seen_depth.insert(state.clone(), depth + 1);
                        }
                    }
                    next.entry(state)
                        .and_modify(|count| *count = count.saturating_add(multiplicity).min(2))
                        .or_insert(multiplicity);
                }
            }
            let mut candidate_names = candidates.into_iter().collect::<Vec<_>>();
            candidate_names.sort_by(|left, right| left.0.cmp(&right.0));
            for (name, (member, multiplicity)) in candidate_names {
                resolved_names.insert(name);
                if multiplicity != 1 {
                    continue;
                }
                let (member_index, pointer_available) = member.expect("unique member has an index");
                let mut member = symbols[member_index].clone();
                member.id = format!("go-promoted:{}:{}", owner.id, member.id);
                member.owner_id = Some(owner.id.clone());
                member.qualified_name = format!("{}.{}", owner.qualified_name, member.name);
                if member.receiver.is_some_and(|receiver| receiver.pointer) && pointer_available {
                    member.receiver = Some(ReceiverFact { pointer: false });
                }
                promoted.push(member);
            }
            current = next;
            depth += 1;
        }
        if incomplete_embedded_surface {
            symbols[owner_index].provenance.completeness = SemanticModelCompleteness::Partial;
        }
    }
    symbols.extend(promoted);

    let methods_by_owner = symbols
        .iter()
        .filter(|symbol| {
            symbol.language == "go"
                && symbol.kind == SemanticModelSymbolKind::Method
                && symbol.externally_visible()
                && !symbol.provenance.ambiguous
        })
        .filter_map(|symbol| {
            symbol
                .owner_id
                .as_ref()
                .map(|owner| (owner.clone(), symbol))
        })
        .fold(
            HashMap::<String, Vec<&SemanticModelSymbol>>::default(),
            |mut grouped, (owner, symbol)| {
                grouped.entry(owner).or_default().push(symbol);
                grouped
            },
        );
    let interfaces = type_indices
        .values()
        .map(|index| &symbols[*index])
        .filter(|symbol| {
            symbol.kind == SemanticModelSymbolKind::Interface && !symbol.has_explicit_type_terms
        })
        .filter_map(|symbol| {
            let methods = methods_by_owner.get(&symbol.id)?;
            (!methods.is_empty()).then_some((symbol, methods.as_slice()))
        })
        .collect::<Vec<_>>();
    let candidates = type_indices
        .values()
        .map(|index| &symbols[*index])
        .filter(|symbol| {
            !matches!(
                symbol.kind,
                SemanticModelSymbolKind::Module | SemanticModelSymbolKind::TypeAlias
            )
        })
        .collect::<Vec<_>>();
    if interfaces.len().saturating_mul(candidates.len()) > MAX_GO_OVERLAY_TRAVERSAL_STEPS {
        return Err(SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded);
    }
    let existing = relations
        .iter()
        .map(|relation| {
            (
                relation.from.clone(),
                relation.to.clone(),
                relation.kind.clone(),
            )
        })
        .collect::<HashSet<_>>();
    for candidate in candidates {
        let candidate_methods = methods_by_owner
            .get(&candidate.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for (interface, required_methods) in &interfaces {
            if candidate.id == interface.id
                || existing.contains(&(
                    candidate.id.clone(),
                    interface.id.clone(),
                    "implements".to_owned(),
                ))
                || !required_methods.iter().all(|required| {
                    candidate_methods.iter().any(|method| {
                        !method.receiver.is_some_and(|receiver| receiver.pointer)
                            && go_method_signatures_match(
                                &method.name,
                                method.structured_signature.as_ref(),
                                &required.name,
                                required.structured_signature.as_ref(),
                            )
                    })
                })
            {
                continue;
            }
            let id = format!("hierarchy:{}:implements:{}", candidate.id, interface.id);
            let mut provenance = candidate.provenance.clone();
            provenance.record_id = id.clone();
            relations.push(SemanticModelRelation {
                id,
                kind: "implements".to_owned(),
                from: candidate.id.clone(),
                to: interface.id.clone(),
                declaration_ordinal: None,
                provenance,
            });
        }
    }
    Ok(())
}

fn overlay_declared_type_id(
    reference: &TypeRef,
    qualified_type_ids: &HashMap<String, String>,
) -> Option<String> {
    if reference.contains_unknown() {
        return None;
    }
    match reference {
        TypeRef::Declared { id, .. } => Some(id.clone()),
        TypeRef::Named { name, .. } => qualified_type_ids.get(name).cloned(),
        TypeRef::Pointer { element } => overlay_declared_type_id(element, qualified_type_ids),
        _ => None,
    }
}

#[doc(hidden)]
pub fn go_method_signatures_match(
    candidate_name: &str,
    candidate: Option<&Signature>,
    required_name: &str,
    required: Option<&Signature>,
) -> bool {
    if candidate_name != required_name {
        return false;
    }
    let (Some(candidate), Some(required)) = (candidate, required) else {
        return false;
    };
    if candidate.contains_unknown_types() || required.contains_unknown_types() {
        return false;
    }
    candidate.type_parameters.len() == required.type_parameters.len()
        && candidate.parameters.len() == required.parameters.len()
        && candidate
            .parameters
            .iter()
            .zip(&required.parameters)
            .all(|(candidate, required)| {
                candidate.r#type == required.r#type && candidate.variadic == required.variadic
            })
        && candidate.returns == required.returns
}

pub const SEMANTIC_MODEL_MATCH_EXPLANATION_FORMAT: &str =
    "bifrost_semantic_model_match_explanation/v1";
pub const SEMANTIC_MODEL_EMISSION_PREVIEW_FORMAT: &str =
    "bifrost_semantic_model_emission_preview/v1";
pub const SEMANTIC_MODEL_UNMAPPED_SCAN_FORMAT: &str = "bifrost_semantic_model_unmapped_scan/v1";
pub const SEMANTIC_MODEL_CONFORMANCE_FORMAT: &str = "bifrost_semantic_model_conformance/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelSite {
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelEmittedAlias {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelRuleExplanation {
    pub pack_id: String,
    pub pack_version: String,
    pub shard_id: String,
    pub rule_id: String,
    pub source_kind: String,
    pub source_id: String,
    pub shadowing: String,
    pub matched: bool,
    pub activation_evidence: SemanticModelMatchedEvidence,
    pub captures: BTreeMap<String, String>,
    pub emitted_symbols: Vec<SemanticModelSymbol>,
    pub emitted_relations: Vec<SemanticModelRelation>,
    pub emitted_aliases: Vec<SemanticModelEmittedAlias>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_failed_predicate: Option<SemanticModelPredicateFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelMatchExplanationReport {
    pub format: &'static str,
    pub site: SemanticModelSite,
    pub complete: bool,
    pub explanations: Vec<SemanticModelRuleExplanation>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelEmissionPreview {
    pub format: &'static str,
    pub complete: bool,
    pub pack_id: Option<String>,
    pub rule_id: String,
    pub shadowing: String,
    pub captures: BTreeMap<String, String>,
    pub emitted_symbols: Vec<SemanticModelSymbol>,
    pub emitted_relations: Vec<SemanticModelRelation>,
    pub emitted_aliases: Vec<SemanticModelEmittedAlias>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelGeneratorSiteKind {
    ModelEligibleGenerator,
    InspectableSourceMacro,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelGeneratorSelector {
    pub language: String,
    pub trigger: RuleTrigger,
    pub site_kind: SemanticModelGeneratorSiteKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelUnmappedScanLimits {
    pub max_files: usize,
    pub max_nodes: usize,
    pub max_sites: usize,
}

impl Default for SemanticModelUnmappedScanLimits {
    fn default() -> Self {
        Self {
            max_files: 1_024,
            max_nodes: 1_000_000,
            max_sites: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelUnmappedSite {
    pub path: String,
    pub line: usize,
    pub name: Option<String>,
    pub site_kind: SemanticModelGeneratorSiteKind,
    pub requested_trigger: RuleTrigger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelUnmappedScanReport {
    pub format: &'static str,
    pub complete: bool,
    pub scanned_files: usize,
    pub scanned_nodes: usize,
    pub sites: Vec<SemanticModelUnmappedSite>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceSymbol {
    pub id: String,
    #[serde(default)]
    pub owner_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub signature: Option<String>,
    pub location_prefix: String,
    pub pack_id: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    pub completeness: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceRelationship {
    pub id: String,
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceLink {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceMatch {
    pub site: SemanticModelSite,
    pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceFixture {
    pub schema_version: u32,
    #[serde(default)]
    pub symbols: Vec<SemanticModelConformanceSymbol>,
    #[serde(default)]
    pub relationships: Vec<SemanticModelConformanceRelationship>,
    #[serde(default)]
    pub forward_definitions: Vec<SemanticModelConformanceLink>,
    #[serde(default)]
    pub inverse_usages: Vec<SemanticModelConformanceLink>,
    #[serde(default)]
    pub positive_matches: Vec<SemanticModelConformanceMatch>,
    #[serde(default)]
    pub negative_matches: Vec<SemanticModelConformanceMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceReport {
    pub format: &'static str,
    pub complete: bool,
    pub passed: bool,
    pub checked_assertions: usize,
    pub failures: Vec<String>,
}

#[doc(hidden)]
pub struct GeneratedOverlayFacts {
    #[doc(hidden)]
    pub symbols: Vec<SemanticModelSymbol>,
    #[doc(hidden)]
    pub relations: Vec<SemanticModelRelation>,
}

#[doc(hidden)]
pub struct GeneratedFileFacts {
    #[doc(hidden)]
    pub symbols: Vec<SemanticModelSymbol>,
    #[doc(hidden)]
    pub relations: Vec<SemanticModelRelation>,
    #[doc(hidden)]
    pub aliases: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelPredicateFailure {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct CapturedValue {
    #[doc(hidden)]
    pub value: String,
    #[doc(hidden)]
    pub anchor: Option<SemanticModelAuthoredAnchor>,
}

#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct GeneratorRuleMatch {
    #[doc(hidden)]
    pub values: HashMap<String, CapturedValue>,
    #[doc(hidden)]
    pub groups: HashMap<String, Vec<CapturedValue>>,
}

impl GeneratorRuleMatch {
    fn get(&self, name: &str) -> Option<&CapturedValue> {
        self.values.get(name)
    }
}

#[doc(hidden)]
pub fn qualified_decorator_matches(expected: &str, decorator_source: &str) -> bool {
    if !expected.contains('.') && !expected.contains("::") {
        return false;
    }
    let source = decorator_source.trim();
    let body = source.strip_prefix('@').unwrap_or(source);
    body == expected
        || body
            .strip_prefix(expected)
            .is_some_and(|suffix| suffix.starts_with('('))
}

#[doc(hidden)]
pub fn exact_trigger_name_matches(expected: &str, actual: &str) -> bool {
    if expected.contains('.') || expected.contains("::") {
        actual == expected
    } else {
        terminal_name(actual.trim_end_matches('!')) == expected
    }
}

#[doc(hidden)]
pub fn make_authored_anchor(
    path: &Path,
    symbol: String,
    range: SemanticModelRange,
) -> SemanticModelAuthoredAnchor {
    SemanticModelAuthoredAnchor {
        path: path.to_string_lossy().replace('\\', "/"),
        symbol,
        range,
    }
}

#[doc(hidden)]
pub fn evaluate_template(
    expression: &TemplateExpression,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    match expression {
        TemplateExpression::Literal { value } => Some(value.clone()),
        TemplateExpression::Capture { name } => captures.get(name).map(|value| value.value.clone()),
        TemplateExpression::Concat { values } => {
            let mut rendered = String::new();
            for value in values {
                rendered.push_str(&evaluate_template(value, captures)?);
            }
            Some(rendered)
        }
        TemplateExpression::Transform { transform, value } => {
            evaluate_template(value, captures).map(|value| ascii_transform(*transform, &value))
        }
        TemplateExpression::Conditional {
            condition,
            then_value,
            else_value,
        } => {
            let matches = match condition {
                crate::analyzer::semantic_model::TemplateCondition::Equals { left, right } => {
                    evaluate_template(left, captures)? == evaluate_template(right, captures)?
                }
                crate::analyzer::semantic_model::TemplateCondition::StartsWith {
                    value,
                    prefix,
                } => evaluate_template(value, captures)?
                    .starts_with(&evaluate_template(prefix, captures)?),
            };
            let branch = if matches { then_value } else { else_value };
            evaluate_template(branch, captures)
        }
    }
}

#[doc(hidden)]
pub fn capture_anchor(
    expression: &TemplateExpression,
    captures: &GeneratorRuleMatch,
) -> Option<SemanticModelAuthoredAnchor> {
    match expression {
        TemplateExpression::Capture { name } => captures.get(name)?.anchor.clone(),
        _ => None,
    }
}

fn ascii_transform(transform: AsciiTransform, value: &str) -> String {
    match transform {
        AsciiTransform::Lowercase => value.to_ascii_lowercase(),
        AsciiTransform::Uppercase => value.to_ascii_uppercase(),
        AsciiTransform::SnakeCase => ascii_words(value).join("_"),
        AsciiTransform::KebabCase => ascii_words(value).join("-"),
        AsciiTransform::PascalCase => ascii_words(value)
            .into_iter()
            .map(|word| capitalize_ascii(&word))
            .collect(),
        AsciiTransform::CamelCase => {
            let mut words = ascii_words(value).into_iter();
            let Some(first) = words.next() else {
                return String::new();
            };
            first
                + &words
                    .map(|word| capitalize_ascii(&word))
                    .collect::<String>()
        }
    }
}

fn ascii_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for character in value.chars() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current).to_ascii_lowercase());
            }
            previous_lower = false;
            continue;
        }
        if character.is_ascii_uppercase() && previous_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current).to_ascii_lowercase());
        }
        previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
        current.push(character);
    }
    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }
    words
}

fn capitalize_ascii(value: &str) -> String {
    let mut characters = value.chars();
    characters
        .next()
        .map(|first| first.to_ascii_uppercase().to_string() + characters.as_str())
        .unwrap_or_default()
}

#[doc(hidden)]
pub fn render_template_signature(
    name: &str,
    signature: &TemplateSignature,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    let mut parameters = signature
        .parameters
        .iter()
        .map(|parameter| render_template_parameter(parameter, captures))
        .collect::<Option<Vec<_>>>()?;
    parameters.extend(render_repeated_parameters(signature, captures)?);
    let returns = match &signature.returns {
        Some(returns) => format!(" -> {}", render_template_type(returns, captures)?),
        None => String::new(),
    };
    Some(format!("{name}({}){returns}", parameters.join(", ")))
}

fn render_template_parameter(
    parameter: &TemplateParameter,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    Some(format!(
        "{}: {}",
        evaluate_template(&parameter.name, captures)?,
        render_template_parameter_type(parameter, captures)?,
    ))
}

fn render_template_parameter_type(
    parameter: &TemplateParameter,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    Some(format!(
        "{}{}{}",
        render_template_type(&parameter.r#type, captures)?,
        if parameter.optional { "?" } else { "" },
        if parameter.variadic { "..." } else { "" },
    ))
}

#[doc(hidden)]
pub fn evaluate_template_signature(
    signature: &TemplateSignature,
    captures: &GeneratorRuleMatch,
) -> Option<Signature> {
    let mut parameters = signature
        .parameters
        .iter()
        .map(|parameter| {
            Some(crate::analyzer::semantic_model::Parameter {
                name: Some(evaluate_template(&parameter.name, captures)?),
                r#type: evaluate_template_type(&parameter.r#type, captures)?,
                optional: parameter.optional,
                variadic: parameter.variadic,
                role: None,
                passing_mode: Default::default(),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    for row in repeated_parameter_rows(signature, captures)? {
        for parameter in &signature.repeated_parameters {
            parameters.push(crate::analyzer::semantic_model::Parameter {
                name: Some(evaluate_template(&parameter.name, &row)?),
                r#type: evaluate_template_type(&parameter.r#type, &row)?,
                optional: parameter.optional,
                variadic: parameter.variadic,
                role: None,
                passing_mode: Default::default(),
            });
        }
    }
    Some(Signature {
        type_parameters: signature
            .type_parameters
            .iter()
            .map(|parameter| evaluate_template(parameter, captures))
            .collect::<Option<Vec<_>>>()?,
        parameters,
        returns: match &signature.returns {
            Some(returns) => Some(evaluate_template_type(returns, captures)?),
            None => None,
        },
    })
}

fn evaluate_template_type(
    reference: &TemplateTypeRef,
    captures: &GeneratorRuleMatch,
) -> Option<TypeRef> {
    match reference {
        TemplateTypeRef::Named {
            name,
            arguments,
            nullable,
        } => Some(TypeRef::Named {
            name: evaluate_template(name, captures)?,
            arguments: arguments
                .iter()
                .map(|argument| evaluate_template_type(argument, captures))
                .collect::<Option<Vec<_>>>()?,
            nullable: *nullable,
        }),
        TemplateTypeRef::Capture { name } => Some(TypeRef::Named {
            name: captures.get(name)?.value.clone(),
            arguments: Vec::new(),
            nullable: false,
        }),
        TemplateTypeRef::Array { element } => Some(TypeRef::Array {
            element: Box::new(evaluate_template_type(element, captures)?),
        }),
        TemplateTypeRef::ByRef { element } => Some(TypeRef::ByRef {
            element: Box::new(evaluate_template_type(element, captures)?),
            reference_kind: TypeRefReferenceKind::Lvalue,
        }),
    }
}

#[doc(hidden)]
pub fn render_template_callable_shape(
    signature: &TemplateSignature,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    let mut parameters = signature
        .parameters
        .iter()
        .map(|parameter| render_template_parameter_type(parameter, captures))
        .collect::<Option<Vec<_>>>()?;
    for row in repeated_parameter_rows(signature, captures)? {
        for parameter in &signature.repeated_parameters {
            parameters.push(render_template_parameter_type(parameter, &row)?);
        }
    }
    Some(render_callable_shape_from_parts(
        signature.type_parameters.len(),
        parameters,
    ))
}

fn repeated_parameter_rows(
    signature: &TemplateSignature,
    captures: &GeneratorRuleMatch,
) -> Option<Vec<GeneratorRuleMatch>> {
    if signature.repeated_parameters.is_empty() {
        return Some(Vec::new());
    }
    let row_count = captures.groups.values().next()?.len();
    if captures
        .groups
        .values()
        .any(|values| values.len() != row_count)
    {
        return None;
    }
    Some(
        (0..row_count)
            .map(|index| {
                let mut values = captures.values.clone();
                for (name, group) in &captures.groups {
                    values.insert(name.clone(), group[index].clone());
                }
                GeneratorRuleMatch {
                    values,
                    groups: HashMap::default(),
                }
            })
            .collect(),
    )
}

fn render_repeated_parameters(
    signature: &TemplateSignature,
    captures: &GeneratorRuleMatch,
) -> Option<Vec<String>> {
    let mut rendered = Vec::new();
    for row in repeated_parameter_rows(signature, captures)? {
        for parameter in &signature.repeated_parameters {
            rendered.push(render_template_parameter(parameter, &row)?);
        }
    }
    Some(rendered)
}

fn render_template_type(
    reference: &TemplateTypeRef,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    match reference {
        TemplateTypeRef::Named {
            name,
            arguments,
            nullable,
        } => {
            let mut rendered = evaluate_template(name, captures)?;
            if !arguments.is_empty() {
                rendered.push('<');
                rendered.push_str(
                    &arguments
                        .iter()
                        .map(|argument| render_template_type(argument, captures))
                        .collect::<Option<Vec<_>>>()?
                        .join(", "),
                );
                rendered.push('>');
            }
            if *nullable {
                rendered.push('?');
            }
            Some(rendered)
        }
        TemplateTypeRef::Capture { name } => captures.get(name).map(|value| value.value.clone()),
        TemplateTypeRef::Array { element } => {
            render_template_type(element, captures).map(|element| format!("{element}[]"))
        }
        TemplateTypeRef::ByRef { element } => {
            render_template_type(element, captures).map(|element| format!("ref {element}"))
        }
    }
}

#[doc(hidden)]
pub fn member_callable_shape_evidence_complete(record: &MemberFact) -> bool {
    let Some(signature) = record.signature.as_ref() else {
        return false;
    };
    if !signature_has_complete_callable_shape(signature) {
        return false;
    }
    match &record.locator {
        Locator::Interchange {
            symbol,
            callable_shape_evidence: Some(evidence),
            ..
        } => {
            evidence.statement.family == "declaration-aspects"
                && evidence.statement.status
                    == crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Complete
                && evidence
                    .statement
                    .scope
                    .get("symbol")
                    .and_then(serde_json::Value::as_str)
                    == Some(symbol.as_str())
                && evidence
                    .statement
                    .scope
                    .get("aspect")
                    .and_then(serde_json::Value::as_str)
                    == Some("callable-shape")
                && evidence.statement.limitations.is_empty()
                && evidence.statement.extensions.is_empty()
        }
        Locator::Interchange {
            callable_shape_evidence: None,
            ..
        } => false,
        _ => true,
    }
}

#[doc(hidden)]
pub fn signature_has_complete_callable_shape(signature: &Signature) -> bool {
    signature
        .parameters
        .iter()
        .all(|parameter| parameter.name.is_some())
}

#[doc(hidden)]
pub fn locator_symbol(locator: &Locator) -> Option<&str> {
    match locator {
        Locator::Source { symbol, .. } => symbol.as_deref(),
        Locator::Artifact { symbol, .. } | Locator::Interchange { symbol, .. } => Some(symbol),
    }
}

#[doc(hidden)]
pub fn relation_kind_label(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::NavigatesTo => "navigates_to",
        RelationKind::References => "references",
    }
}

#[doc(hidden)]
pub fn hierarchy_kind_label(kind: HierarchyKind) -> &'static str {
    match kind {
        HierarchyKind::Extends => "extends",
        HierarchyKind::Implements => "implements",
        HierarchyKind::UsesTrait => "uses_trait",
        HierarchyKind::MixinInclude => "mixin_include",
        HierarchyKind::MixinPrepend => "mixin_prepend",
        HierarchyKind::MixinExtend => "mixin_extend",
    }
}

#[doc(hidden)]
pub fn matched_evidence(
    evidence: &crate::analyzer::semantic_model::SemanticModelActivationEvidence,
) -> SemanticModelMatchedEvidence {
    SemanticModelMatchedEvidence {
        language: evidence.language.clone(),
        ecosystem: evidence.ecosystem.clone(),
        package: evidence.package.as_ref().map(matched_coordinate),
        module: evidence.module.as_ref().map(matched_coordinate),
        toolchain: evidence.toolchain.as_ref().map(matched_coordinate),
        target: evidence.target.clone(),
        configuration: evidence.configuration.clone(),
        artifact_sha256: evidence.artifact_sha256.clone(),
    }
}

fn matched_coordinate(
    coordinate: &crate::analyzer::semantic_model::CatalogCoordinate,
) -> SemanticModelMatchedCoordinate {
    SemanticModelMatchedCoordinate {
        name: coordinate.name.clone(),
        version: coordinate.version.as_ref().map(ToString::to_string),
    }
}

#[doc(hidden)]
pub fn type_kind(kind: TypeKind) -> SemanticModelSymbolKind {
    match kind {
        TypeKind::Class => SemanticModelSymbolKind::Class,
        TypeKind::Annotation => SemanticModelSymbolKind::Annotation,
        TypeKind::Delegate => SemanticModelSymbolKind::Delegate,
        TypeKind::Interface => SemanticModelSymbolKind::Interface,
        TypeKind::Trait => SemanticModelSymbolKind::Trait,
        TypeKind::Struct => SemanticModelSymbolKind::Struct,
        TypeKind::Union => SemanticModelSymbolKind::Union,
        TypeKind::Enum => SemanticModelSymbolKind::Enum,
        TypeKind::Record => SemanticModelSymbolKind::Record,
        TypeKind::Module => SemanticModelSymbolKind::Module,
        TypeKind::TypeAlias => SemanticModelSymbolKind::TypeAlias,
    }
}

#[doc(hidden)]
pub fn member_kind(kind: MemberKind) -> SemanticModelSymbolKind {
    match kind {
        MemberKind::Constructor => SemanticModelSymbolKind::Constructor,
        MemberKind::Method => SemanticModelSymbolKind::Method,
        MemberKind::Function => SemanticModelSymbolKind::Function,
        MemberKind::Field => SemanticModelSymbolKind::Field,
        MemberKind::Property => SemanticModelSymbolKind::Property,
        MemberKind::Constant => SemanticModelSymbolKind::Constant,
        MemberKind::Static => SemanticModelSymbolKind::Static,
        MemberKind::Macro => SemanticModelSymbolKind::Macro,
        MemberKind::Event => SemanticModelSymbolKind::Event,
    }
}

#[doc(hidden)]
pub fn terminal_name(name: &str) -> &str {
    name.rsplit(['.', ':', '$']) // fqname-M4: declarative model and AST trigger names have no CodeUnit/FqName at this boundary
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

#[doc(hidden)]
pub fn render_signature(
    name: &str,
    signature: &crate::analyzer::semantic_model::Signature,
) -> String {
    let parameters = signature
        .parameters
        .iter()
        .map(|parameter| {
            let ty = render_type_ref(&parameter.r#type);
            parameter
                .name
                .as_deref()
                .map(|name| format!("{name}: {ty}"))
                .unwrap_or(ty)
        })
        .collect::<Vec<_>>()
        .join(", ");
    match &signature.returns {
        Some(result) => format!("{name}({parameters}) -> {}", render_type_ref(result)),
        None => format!("{name}({parameters})"),
    }
}

#[doc(hidden)]
pub fn render_callable_shape(signature: &crate::analyzer::semantic_model::Signature) -> String {
    let parameters = signature
        .parameters
        .iter()
        .map(|parameter| {
            format!(
                "{}{}{}",
                render_type_ref(&parameter.r#type),
                if parameter.optional { "?" } else { "" },
                if parameter.variadic { "..." } else { "" },
            )
        })
        .collect::<Vec<_>>();
    render_callable_shape_from_parts(signature.type_parameters.len(), parameters)
}

fn render_callable_shape_from_parts(
    type_parameter_count: usize,
    parameters: Vec<String>,
) -> String {
    format!("{type_parameter_count}<{}>", parameters.join(","))
}

#[doc(hidden)]
pub fn render_type_ref(reference: &TypeRef) -> String {
    match reference {
        TypeRef::Projection {
            owner,
            trait_type,
            name,
            arguments,
        } => {
            let owner = render_type_ref(owner);
            let prefix = trait_type.as_ref().map_or(owner.clone(), |trait_| {
                format!("<{owner} as {}>", render_type_ref(trait_))
            });
            format!("{prefix}::{}", render_named_type(name, arguments, false))
        }
        TypeRef::Unknown => "<unknown>".to_owned(),
        TypeRef::Named {
            name,
            arguments,
            nullable,
        } => render_named_type(name, arguments, *nullable),
        TypeRef::Declared {
            id,
            arguments,
            nullable,
        } => render_named_type(id, arguments, *nullable),
        TypeRef::TypeParameter { name } => name.clone(),
        TypeRef::Array { element } => format!("{}[]", render_type_ref(element)),
        TypeRef::ByRef { element, .. } => format!("ref {}", render_type_ref(element)),
        TypeRef::Pointer { element } => format!("*{}", render_type_ref(element)),
        TypeRef::Slice { element } => format!("[]{}", render_type_ref(element)),
        TypeRef::FixedArray { element, length } => {
            format!("[{length}]{}", render_type_ref(element))
        }
        TypeRef::Map { key, value } => {
            format!("map[{}]{}", render_type_ref(key), render_type_ref(value))
        }
        TypeRef::Channel { element, direction } => match direction {
            crate::analyzer::semantic_model::ChannelDirection::Bidirectional => {
                format!("chan {}", render_type_ref(element))
            }
            crate::analyzer::semantic_model::ChannelDirection::Receive => {
                format!("<-chan {}", render_type_ref(element))
            }
            crate::analyzer::semantic_model::ChannelDirection::Send => {
                format!("chan<- {}", render_type_ref(element))
            }
        },
        TypeRef::Wildcard { variance, bound } => match bound {
            Some(bound) => {
                format!("{:?} {}", variance, render_type_ref(bound)).to_ascii_lowercase()
            }
            None => "?".to_string(),
        },
        TypeRef::Tuple { elements } => format!(
            "({})",
            elements
                .iter()
                .map(render_type_ref)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        TypeRef::Function { parameters, result } => {
            let parameters = parameters
                .iter()
                .map(|parameter| {
                    let rendered = render_type_ref(&parameter.r#type);
                    if parameter.variadic {
                        format!("...{rendered}")
                    } else {
                        rendered
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            match result {
                Some(result) => format!("({parameters}) -> {}", render_type_ref(result)),
                None => format!("({parameters})"),
            }
        }
    }
}

fn render_named_type(name: &str, arguments: &[TypeRef], nullable: bool) -> String {
    let mut rendered = name.to_string();
    if !arguments.is_empty() {
        rendered.push('<');
        rendered.push_str(
            &arguments
                .iter()
                .map(render_type_ref)
                .collect::<Vec<_>>()
                .join(", "),
        );
        rendered.push('>');
    }
    if nullable {
        rendered.push('?');
    }
    rendered
}
