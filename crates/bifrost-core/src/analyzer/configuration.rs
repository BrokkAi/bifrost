//! Format-neutral authored facts and bounded effective-configuration evidence.

use crate::CancellationToken;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

/// The canonical registry of structured configuration formats.
///
/// Configuration formats are deliberately separate from programming
/// [`Language`](crate::analyzer::Language). Membership here does not mean that
/// an ingestion adapter is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfigurationFormat {
    Yaml,
    Toml,
    Json,
    Xml,
    Properties,
}

impl ConfigurationFormat {
    pub const ALL: [Self; 5] = [
        Self::Yaml,
        Self::Toml,
        Self::Json,
        Self::Xml,
        Self::Properties,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Toml => "toml",
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Properties => "properties",
        }
    }

    pub const fn discovery_extensions(self) -> &'static [&'static str] {
        match self {
            Self::Yaml => &["yaml", "yml"],
            Self::Toml => &["toml"],
            Self::Json => &["json"],
            Self::Xml => &["xml"],
            Self::Properties => &["properties"],
        }
    }

    pub fn from_discovery_extension(extension: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|format| {
            format
                .discovery_extensions()
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
    }
}

impl fmt::Display for ConfigurationFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The canonical result of classifying a file path as configuration input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigurationPathClassification {
    Supported(ConfigurationFormat),
    Unsupported,
}

/// Classify a file path independently of programming-language discovery.
///
/// Non-UTF-8 extensions and unknown extensions are `Unsupported`. `Path`
/// performs the platform-specific final-component and extension lookup; this
/// function never splits path text.
pub fn classify_configuration_path(path: &Path) -> ConfigurationPathClassification {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return ConfigurationPathClassification::Unsupported;
    };
    match ConfigurationFormat::from_discovery_extension(extension) {
        Some(format) => ConfigurationPathClassification::Supported(format),
        None => ConfigurationPathClassification::Unsupported,
    }
}

/// An exact, half-open byte range in one document snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationSourceRange {
    start_byte: usize,
    end_byte: usize,
}

impl ConfigurationSourceRange {
    pub fn new(start_byte: usize, end_byte: usize) -> Result<Self, ConfigurationModelError> {
        if start_byte > end_byte {
            return Err(ConfigurationModelError::InvalidRange {
                start_byte,
                end_byte,
            });
        }
        Ok(Self {
            start_byte,
            end_byte,
        })
    }

    pub const fn start_byte(&self) -> usize {
        self.start_byte
    }

    pub const fn end_byte(&self) -> usize {
        self.end_byte
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigurationModelError {
    InvalidRange { start_byte: usize, end_byte: usize },
    InvalidRouteSegment,
    InvalidFactArena,
    InvalidIdentifier { kind: &'static str },
    InvalidPrecedenceEdge,
    DuplicateLayerId,
    UnknownLayerId,
    PrecedenceCycle,
    DuplicateProfileId,
}

impl fmt::Display for ConfigurationModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange {
                start_byte,
                end_byte,
            } => write!(
                formatter,
                "invalid configuration source range {start_byte}..{end_byte}"
            ),
            Self::InvalidRouteSegment => {
                write!(formatter, "invalid configuration route segment")
            }
            Self::InvalidFactArena => {
                write!(formatter, "invalid configuration fact arena")
            }
            Self::InvalidIdentifier { kind } => {
                write!(formatter, "empty configuration {kind} identifier")
            }
            Self::InvalidPrecedenceEdge => {
                write!(formatter, "invalid configuration precedence edge")
            }
            Self::DuplicateLayerId => write!(formatter, "duplicate configuration layer id"),
            Self::UnknownLayerId => write!(formatter, "unknown configuration layer id"),
            Self::PrecedenceCycle => {
                write!(formatter, "configuration precedence graph has a cycle")
            }
            Self::DuplicateProfileId => write!(formatter, "duplicate configuration profile id"),
        }
    }
}

/// One ordered element of a stable structural route.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfigurationRouteSelector {
    Key { name: String, occurrence: usize },
    Index(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationRouteSegment {
    selector: ConfigurationRouteSelector,
    evidence: ConfigurationSourceRange,
}

impl ConfigurationRouteSegment {
    pub fn key(
        name: impl Into<String>,
        occurrence: usize,
        evidence: ConfigurationSourceRange,
    ) -> Result<Self, ConfigurationModelError> {
        let name = name.into();
        if name.is_empty() || occurrence == 0 {
            return Err(ConfigurationModelError::InvalidRouteSegment);
        }
        Ok(Self {
            selector: ConfigurationRouteSelector::Key { name, occurrence },
            evidence,
        })
    }

    pub fn index(
        index: usize,
        evidence: ConfigurationSourceRange,
    ) -> Result<Self, ConfigurationModelError> {
        Ok(Self {
            selector: ConfigurationRouteSelector::Index(index),
            evidence,
        })
    }

    pub const fn selector(&self) -> &ConfigurationRouteSelector {
        &self.selector
    }

    pub const fn evidence(&self) -> ConfigurationSourceRange {
        self.evidence
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationRoute {
    segments: Vec<ConfigurationRouteSegment>,
}

impl ConfigurationRoute {
    pub const fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn child(mut self, segment: ConfigurationRouteSegment) -> Self {
        self.segments.push(segment);
        self
    }

    pub fn segments(&self) -> &[ConfigurationRouteSegment] {
        &self.segments
    }
}

/// A range-independent structural key used to correlate the same setting
/// across configuration layers.
///
/// [`ConfigurationRoute`] retains exact source evidence for an authored fact.
/// That evidence commonly differs between files, so effective resolution uses
/// only the ordered key/index selectors rather than comparing source ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationResolutionKey {
    selectors: Vec<ConfigurationRouteSelector>,
}

impl ConfigurationResolutionKey {
    pub fn from_route(route: &ConfigurationRoute) -> Self {
        Self {
            selectors: route
                .segments()
                .iter()
                .map(|segment| segment.selector().clone())
                .collect(),
        }
    }

    pub fn selectors(&self) -> &[ConfigurationRouteSelector] {
        &self.selectors
    }
}

/// A content-independent identity that is scoped to one document snapshot.
///
/// The route and node kind fully determine the value. Exact ranges and
/// unrelated sibling facts deliberately do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationStableId([u8; 32]);

impl ConfigurationStableId {
    const DOMAIN: &'static [u8] = b"bifrost.configuration.stable-id.v1";

    pub fn new(
        format: ConfigurationFormat,
        kind: &ConfigurationNodeKind,
        route: &ConfigurationRoute,
    ) -> Self {
        let mut hasher = CanonicalHasher::new(Self::DOMAIN);
        hasher.field("format", format.label().as_bytes());
        hasher.field(
            "node_kind",
            match kind {
                ConfigurationNodeKind::Document { .. } => b"document".as_slice(),
                ConfigurationNodeKind::Object { .. } => b"object".as_slice(),
                ConfigurationNodeKind::Section { .. } => b"section".as_slice(),
                ConfigurationNodeKind::Sequence { .. } => b"sequence".as_slice(),
                ConfigurationNodeKind::Member { role, .. } => {
                    let role_label = match role {
                        ConfigurationMemberRole::ObjectMember => "object-member",
                        ConfigurationMemberRole::TableEntry => "table-entry",
                        ConfigurationMemberRole::Property => "property",
                        ConfigurationMemberRole::XmlAttribute => "xml-attribute",
                        ConfigurationMemberRole::XmlElement => "xml-element",
                    };
                    role_label.as_bytes()
                }
                ConfigurationNodeKind::Scalar { .. } => b"scalar".as_slice(),
            },
        );
        hasher.sequence("route", route.segments(), |hasher, segment| {
            match segment.selector() {
                ConfigurationRouteSelector::Key { name, occurrence } => {
                    hasher.field("route.kind", b"key");
                    hasher.field("route.key", name.as_bytes());
                    hasher.field("route.occurrence", &occurrence.to_be_bytes());
                }
                ConfigurationRouteSelector::Index(index) => {
                    hasher.field("route.kind", b"index");
                    hasher.field("route.index", &index.to_be_bytes());
                }
            }
        });
        if let ConfigurationNodeKind::Scalar { scalar_kind } = kind {
            let scalar_kind = match scalar_kind {
                ConfigurationScalarKind::String => "string",
                ConfigurationScalarKind::Boolean => "boolean",
                ConfigurationScalarKind::Integer => "integer",
                ConfigurationScalarKind::Decimal => "decimal",
                ConfigurationScalarKind::Null => "null",
                ConfigurationScalarKind::Url => "url",
                ConfigurationScalarKind::Duration => "duration",
                ConfigurationScalarKind::Opaque => "opaque",
            };
            hasher.field("scalar_kind", scalar_kind.as_bytes());
        }
        Self(hasher.finish())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ConfigurationStableId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&lower_hex_string(&self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigurationMemberRole {
    ObjectMember,
    TableEntry,
    Property,
    XmlAttribute,
    XmlElement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigurationScalarKind {
    String,
    Boolean,
    Integer,
    Decimal,
    Null,
    Url,
    Duration,
    Opaque,
}

/// Provenance of a value represented by this phase-one fact boundary.
///
/// Only authored source is admitted here. Effective, expanded, defaulted, or
/// externally supplied values belong to the later precedence/evidence layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigurationValueProvenance {
    Authored,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigurationKey {
    text: String,
    evidence: ConfigurationSourceRange,
}

impl ConfigurationKey {
    pub fn new(
        text: impl Into<String>,
        evidence: ConfigurationSourceRange,
    ) -> Result<Self, ConfigurationModelError> {
        let text = text.into();
        if text.is_empty() {
            return Err(ConfigurationModelError::InvalidRouteSegment);
        }
        Ok(Self { text, evidence })
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub const fn evidence(&self) -> ConfigurationSourceRange {
        self.evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigurationNodeKind {
    Document {
        root: Option<ConfigurationFactId>,
    },
    Object {
        members: Vec<ConfigurationFactId>,
    },
    Section {
        header: Option<ConfigurationFactId>,
        members: Vec<ConfigurationFactId>,
    },
    Sequence {
        items: Vec<ConfigurationFactId>,
    },
    Member {
        role: ConfigurationMemberRole,
        key: ConfigurationKey,
        value: Option<ConfigurationFactId>,
    },
    Scalar {
        scalar_kind: ConfigurationScalarKind,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigurationFact {
    parent: Option<ConfigurationFactId>,
    route: ConfigurationRoute,
    evidence: ConfigurationSourceRange,
    provenance: ConfigurationValueProvenance,
    kind: ConfigurationNodeKind,
}

impl ConfigurationFact {
    /// Construct an unvalidated arena entry.
    ///
    /// [`ConfigurationDocumentFacts::new`] validates parent links and child
    /// ordering before the entry can become part of a public document model.
    pub fn new(
        parent: Option<ConfigurationFactId>,
        route: ConfigurationRoute,
        evidence: ConfigurationSourceRange,
        kind: ConfigurationNodeKind,
    ) -> Self {
        Self {
            parent,
            route,
            evidence,
            provenance: ConfigurationValueProvenance::Authored,
            kind,
        }
    }

    pub const fn parent(&self) -> Option<ConfigurationFactId> {
        self.parent
    }

    pub const fn route(&self) -> &ConfigurationRoute {
        &self.route
    }

    pub const fn evidence(&self) -> ConfigurationSourceRange {
        self.evidence
    }

    pub const fn provenance(&self) -> ConfigurationValueProvenance {
        self.provenance
    }

    pub const fn kind(&self) -> &ConfigurationNodeKind {
        &self.kind
    }

    pub fn stable_id(&self, format: ConfigurationFormat) -> ConfigurationStableId {
        ConfigurationStableId::new(format, &self.kind, &self.route)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationFactId(usize);

impl ConfigurationFactId {
    pub fn new(index: usize) -> Option<Self> {
        if index == usize::MAX {
            None
        } else {
            Some(Self(index))
        }
    }

    pub const fn index(&self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigurationFeatureState {
    NotApplicable,
    Authored {
        evidence: Vec<ConfigurationSourceRange>,
    },
    Unresolved {
        evidence: Vec<ConfigurationSourceRange>,
    },
}

impl ConfigurationFeatureState {
    pub const fn is_resolved(&self) -> bool {
        matches!(self, Self::NotApplicable | Self::Authored { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationFeatureSemantics {
    anchors: ConfigurationFeatureState,
    aliases: ConfigurationFeatureState,
    includes: ConfigurationFeatureState,
    interpolation: ConfigurationFeatureState,
    format_merge: ConfigurationFeatureState,
}

impl ConfigurationFeatureSemantics {
    pub const fn new(
        anchors: ConfigurationFeatureState,
        aliases: ConfigurationFeatureState,
        includes: ConfigurationFeatureState,
        interpolation: ConfigurationFeatureState,
        format_merge: ConfigurationFeatureState,
    ) -> Self {
        Self {
            anchors,
            aliases,
            includes,
            interpolation,
            format_merge,
        }
    }

    /// States for a format in which the feature is absent by definition.
    pub const fn not_applicable() -> Self {
        Self::new(
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
        )
    }

    pub const fn anchors(&self) -> &ConfigurationFeatureState {
        &self.anchors
    }

    pub const fn aliases(&self) -> &ConfigurationFeatureState {
        &self.aliases
    }

    pub const fn includes(&self) -> &ConfigurationFeatureState {
        &self.includes
    }

    pub const fn interpolation(&self) -> &ConfigurationFeatureState {
        &self.interpolation
    }

    pub const fn format_merge(&self) -> &ConfigurationFeatureState {
        &self.format_merge
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigurationRecoveryReason {
    MalformedSyntax,
    InvalidUtf8,
    BudgetExhausted,
    ParserLimit,
    UnsupportedScalar,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationRecovery {
    reason: ConfigurationRecoveryReason,
    evidence: ConfigurationSourceRange,
}

impl ConfigurationRecovery {
    pub fn new(reason: ConfigurationRecoveryReason, evidence: ConfigurationSourceRange) -> Self {
        Self { reason, evidence }
    }

    pub const fn reason(&self) -> ConfigurationRecoveryReason {
        self.reason
    }

    pub const fn evidence(&self) -> ConfigurationSourceRange {
        self.evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigurationCompleteness {
    Complete,
    Incomplete {
        recoveries: Vec<ConfigurationRecovery>,
    },
}

impl ConfigurationCompleteness {
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationDocumentFacts {
    format: ConfigurationFormat,
    document: ConfigurationFactId,
    facts: Vec<ConfigurationFact>,
    completeness: ConfigurationCompleteness,
    features: ConfigurationFeatureSemantics,
}

/// A non-empty, caller-defined stable identity for a configuration layer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationLayerId(String);

impl ConfigurationLayerId {
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigurationModelError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ConfigurationModelError::InvalidIdentifier { kind: "layer" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-empty stable identity for the provider of external evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationProviderId(String);

impl ConfigurationProviderId {
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigurationModelError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ConfigurationModelError::InvalidIdentifier { kind: "provider" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-empty stable identity for a provider's versioned evidence snapshot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationVersionId(String);

impl ConfigurationVersionId {
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigurationModelError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ConfigurationModelError::InvalidIdentifier { kind: "version" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-empty stable identity for the exact source snapshot or external
/// observation that supplied a contribution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationSourceId(String);

impl ConfigurationSourceId {
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigurationModelError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ConfigurationModelError::InvalidIdentifier { kind: "source" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-empty identity for a selectable configuration profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationProfileId(String);

impl ConfigurationProfileId {
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigurationModelError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ConfigurationModelError::InvalidIdentifier { kind: "profile" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The provider and immutable version that support a supplied value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationEvidenceIdentity {
    source: ConfigurationSourceId,
    provider: ConfigurationProviderId,
    version: ConfigurationVersionId,
}

impl ConfigurationEvidenceIdentity {
    pub fn new(
        source: ConfigurationSourceId,
        provider: ConfigurationProviderId,
        version: ConfigurationVersionId,
    ) -> Self {
        Self {
            source,
            provider,
            version,
        }
    }

    pub const fn source(&self) -> &ConfigurationSourceId {
        &self.source
    }

    pub const fn provider(&self) -> &ConfigurationProviderId {
        &self.provider
    }

    pub const fn version(&self) -> &ConfigurationVersionId {
        &self.version
    }
}

/// Where a contribution came from. The resolver attaches no semantics to
/// these labels; callers supply any required parsing, expansion, or runtime
/// evidence explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfigurationSourceKind {
    AuthoredFile,
    Profile,
    Include,
    DeploymentOverride,
    PlaceholderExpansion,
    ExternalEnvironmentEvidence,
    FrameworkBinding,
}

/// A syntax-neutral, verbatim configuration value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationOpaqueValue(String);

impl ConfigurationOpaqueValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for ConfigurationOpaqueValue {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for ConfigurationOpaqueValue {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// One value supplied for a structural configuration route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigurationContribution {
    layer: ConfigurationLayerId,
    key: ConfigurationResolutionKey,
    value: ConfigurationOpaqueValue,
    evidence: ConfigurationEvidenceIdentity,
    source_kind: ConfigurationSourceKind,
}

impl ConfigurationContribution {
    pub fn new(
        layer: ConfigurationLayerId,
        key: ConfigurationResolutionKey,
        value: ConfigurationOpaqueValue,
        evidence: ConfigurationEvidenceIdentity,
        source_kind: ConfigurationSourceKind,
    ) -> Self {
        Self {
            layer,
            key,
            value,
            evidence,
            source_kind,
        }
    }

    pub const fn layer(&self) -> &ConfigurationLayerId {
        &self.layer
    }

    pub const fn key(&self) -> &ConfigurationResolutionKey {
        &self.key
    }

    pub const fn value(&self) -> &ConfigurationOpaqueValue {
        &self.value
    }

    pub const fn evidence(&self) -> &ConfigurationEvidenceIdentity {
        &self.evidence
    }

    pub const fn source_kind(&self) -> ConfigurationSourceKind {
        self.source_kind
    }
}

/// Metadata for a layer, including its optional profile scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationLayer {
    id: ConfigurationLayerId,
    profile: Option<ConfigurationProfileId>,
}

impl ConfigurationLayer {
    pub fn new(id: ConfigurationLayerId) -> Self {
        Self { id, profile: None }
    }

    pub fn for_profile(id: ConfigurationLayerId, profile: ConfigurationProfileId) -> Self {
        Self {
            id,
            profile: Some(profile),
        }
    }

    pub const fn id(&self) -> &ConfigurationLayerId {
        &self.id
    }

    pub const fn profile(&self) -> Option<&ConfigurationProfileId> {
        self.profile.as_ref()
    }
}

/// A directed, explicit lower-to-higher precedence relation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConfigurationPrecedenceEdge {
    lower: ConfigurationLayerId,
    higher: ConfigurationLayerId,
    explanation: ConfigurationPrecedenceExplanation,
}

impl ConfigurationPrecedenceEdge {
    pub fn new(
        lower: ConfigurationLayerId,
        higher: ConfigurationLayerId,
        explanation: ConfigurationPrecedenceExplanation,
    ) -> Result<Self, ConfigurationModelError> {
        if lower == higher {
            return Err(ConfigurationModelError::InvalidPrecedenceEdge);
        }
        Ok(Self {
            lower,
            higher,
            explanation,
        })
    }

    pub const fn lower(&self) -> &ConfigurationLayerId {
        &self.lower
    }

    pub const fn higher(&self) -> &ConfigurationLayerId {
        &self.higher
    }

    pub const fn explanation(&self) -> ConfigurationPrecedenceExplanation {
        self.explanation
    }
}

/// Typed explanation for an explicit precedence edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfigurationPrecedenceExplanation {
    ExplicitOverride,
    ProfileSelection,
    IncludeOrder,
    DeploymentOverride,
    PlaceholderExpansion,
    ExternalEnvironmentEvidence,
}

/// Typed reasons why a resolution cannot be called complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfigurationIncompleteReason {
    Conflict,
    UnresolvedInterpolation,
    UnavailableEnvironment,
    UnknownProfile,
    MissingInclude,
    ParserLimitation,
    Cancellation,
    ContributionBudgetExhausted,
    PrecedenceBudgetExhausted,
}

/// Hard deterministic work limits for effective configuration resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationResolutionBounds {
    max_contributions: usize,
    max_precedence_steps: usize,
}

impl ConfigurationResolutionBounds {
    pub const fn new(max_contributions: usize, max_precedence_steps: usize) -> Self {
        Self {
            max_contributions,
            max_precedence_steps,
        }
    }

    pub const fn max_contributions(&self) -> usize {
        self.max_contributions
    }

    pub const fn max_precedence_steps(&self) -> usize {
        self.max_precedence_steps
    }
}

impl Default for ConfigurationResolutionBounds {
    fn default() -> Self {
        Self::new(usize::MAX, usize::MAX)
    }
}

/// A structural request. No key parsing or string-based name joining occurs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigurationResolutionRequest {
    key: ConfigurationResolutionKey,
    profile: Option<ConfigurationProfileId>,
}

impl ConfigurationResolutionRequest {
    pub fn new(key: ConfigurationResolutionKey) -> Self {
        Self { key, profile: None }
    }

    pub fn for_profile(key: ConfigurationResolutionKey, profile: ConfigurationProfileId) -> Self {
        Self {
            key,
            profile: Some(profile),
        }
    }

    pub const fn key(&self) -> &ConfigurationResolutionKey {
        &self.key
    }

    pub const fn profile(&self) -> Option<&ConfigurationProfileId> {
        self.profile.as_ref()
    }
}

/// Explicit evidence and precedence supplied to the pure resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationResolutionInput {
    layers: Vec<ConfigurationLayer>,
    contributions: Vec<ConfigurationContribution>,
    precedence: Vec<ConfigurationPrecedenceEdge>,
    profiles: BTreeSet<ConfigurationProfileId>,
    incomplete_reasons: Vec<ConfigurationIncompleteReason>,
}

impl ConfigurationResolutionInput {
    pub fn new(
        layers: Vec<ConfigurationLayer>,
        contributions: Vec<ConfigurationContribution>,
        precedence: Vec<ConfigurationPrecedenceEdge>,
    ) -> Result<Self, ConfigurationModelError> {
        let mut layer_ids = BTreeSet::new();
        let mut profiles = BTreeSet::new();
        for layer in &layers {
            if !layer_ids.insert(layer.id.clone()) {
                return Err(ConfigurationModelError::DuplicateLayerId);
            }
            if let Some(profile) = &layer.profile {
                profiles.insert(profile.clone());
            }
        }
        for contribution in &contributions {
            if !layer_ids.contains(&contribution.layer) {
                return Err(ConfigurationModelError::UnknownLayerId);
            }
        }
        let mut indegree = BTreeMap::from_iter(layer_ids.iter().cloned().map(|id| (id, 0usize)));
        let mut adjacency = BTreeMap::<ConfigurationLayerId, BTreeSet<ConfigurationLayerId>>::new();
        for edge in &precedence {
            if !layer_ids.contains(&edge.lower) || !layer_ids.contains(&edge.higher) {
                return Err(ConfigurationModelError::UnknownLayerId);
            }
            if !adjacency
                .entry(edge.lower.clone())
                .or_default()
                .insert(edge.higher.clone())
            {
                return Err(ConfigurationModelError::InvalidPrecedenceEdge);
            }
            *indegree
                .get_mut(&edge.higher)
                .expect("precedence endpoint was validated") += 1;
        }
        let mut ready = indegree
            .iter()
            .filter_map(|(id, degree)| (*degree == 0).then_some(id.clone()))
            .collect::<BTreeSet<_>>();
        let mut visited = 0usize;
        while let Some(id) = ready.pop_first() {
            visited += 1;
            if let Some(next_layers) = adjacency.get(&id) {
                for next in next_layers {
                    let degree = indegree
                        .get_mut(next)
                        .expect("precedence endpoint was validated");
                    *degree -= 1;
                    if *degree == 0 {
                        ready.insert(next.clone());
                    }
                }
            }
        }
        if visited != layer_ids.len() {
            return Err(ConfigurationModelError::PrecedenceCycle);
        }
        Ok(Self {
            layers,
            contributions,
            precedence,
            profiles,
            incomplete_reasons: Vec::new(),
        })
    }

    pub fn with_incomplete_reason(mut self, reason: ConfigurationIncompleteReason) -> Self {
        if !self.incomplete_reasons.contains(&reason) {
            self.incomplete_reasons.push(reason);
        }
        self
    }

    pub fn with_profile(
        mut self,
        profile: ConfigurationProfileId,
    ) -> Result<Self, ConfigurationModelError> {
        if !self.profiles.insert(profile) {
            return Err(ConfigurationModelError::DuplicateProfileId);
        }
        Ok(self)
    }

    pub fn layers(&self) -> &[ConfigurationLayer] {
        &self.layers
    }

    pub fn contributions(&self) -> &[ConfigurationContribution] {
        &self.contributions
    }

    pub fn precedence(&self) -> &[ConfigurationPrecedenceEdge] {
        &self.precedence
    }

    pub fn profiles(&self) -> impl Iterator<Item = &ConfigurationProfileId> {
        self.profiles.iter()
    }

    pub fn incomplete_reasons(&self) -> &[ConfigurationIncompleteReason] {
        &self.incomplete_reasons
    }
}

/// What the supplied evidence proves about the selected value, independent of
/// whether all declared inputs were available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigurationResolutionProof {
    NoContribution,
    Selected {
        layer: ConfigurationLayerId,
    },
    Unresolved {
        candidates: Vec<ConfigurationLayerId>,
    },
    Conflict {
        layers: Vec<ConfigurationLayerId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigurationResolutionCompleteness {
    Complete,
    Incomplete {
        reasons: Vec<ConfigurationIncompleteReason>,
    },
}

impl ConfigurationResolutionCompleteness {
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn reasons(&self) -> &[ConfigurationIncompleteReason] {
        match self {
            Self::Complete => &[],
            Self::Incomplete { reasons } => reasons,
        }
    }
}

/// Canonical effective configuration evidence for one structural key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationResolutionResult {
    key: ConfigurationResolutionKey,
    value: Option<ConfigurationOpaqueValue>,
    contributions: Vec<ConfigurationContribution>,
    precedence: Vec<ConfigurationPrecedenceEdge>,
    proof: ConfigurationResolutionProof,
    completeness: ConfigurationResolutionCompleteness,
}

impl ConfigurationResolutionResult {
    pub const fn key(&self) -> &ConfigurationResolutionKey {
        &self.key
    }

    pub const fn value(&self) -> Option<&ConfigurationOpaqueValue> {
        self.value.as_ref()
    }

    pub fn contributions(&self) -> &[ConfigurationContribution] {
        &self.contributions
    }

    pub fn precedence(&self) -> &[ConfigurationPrecedenceEdge] {
        &self.precedence
    }

    pub const fn proof(&self) -> &ConfigurationResolutionProof {
        &self.proof
    }

    pub const fn completeness(&self) -> &ConfigurationResolutionCompleteness {
        &self.completeness
    }
}

/// Resolve one key from explicit structured evidence. The input is never
/// supplemented from process state, environment variables, secrets, or an
/// expression evaluator.
pub fn resolve_effective_configuration(
    request: &ConfigurationResolutionRequest,
    input: &ConfigurationResolutionInput,
    bounds: ConfigurationResolutionBounds,
    cancellation: &CancellationToken,
) -> ConfigurationResolutionResult {
    let mut reasons = input.incomplete_reasons.clone();
    reasons.sort_unstable();
    reasons.dedup();
    if request
        .profile
        .as_ref()
        .is_some_and(|profile| !input.profiles.contains(profile))
    {
        reasons.push(ConfigurationIncompleteReason::UnknownProfile);
    }
    if cancellation.is_cancelled() {
        reasons.push(ConfigurationIncompleteReason::Cancellation);
        reasons.sort_unstable();
        reasons.dedup();
        return ConfigurationResolutionResult {
            key: request.key.clone(),
            value: None,
            contributions: Vec::new(),
            precedence: Vec::new(),
            proof: ConfigurationResolutionProof::Unresolved {
                candidates: Vec::new(),
            },
            completeness: ConfigurationResolutionCompleteness::Incomplete { reasons },
        };
    }

    let mut layer_by_id = BTreeMap::new();
    let mut indegree = BTreeMap::new();
    let mut adjacency = BTreeMap::<ConfigurationLayerId, BTreeSet<ConfigurationLayerId>>::new();
    for layer in &input.layers {
        layer_by_id.insert(layer.id.clone(), layer);
        indegree.insert(layer.id.clone(), 0usize);
    }
    for edge in &input.precedence {
        adjacency
            .entry(edge.lower.clone())
            .or_default()
            .insert(edge.higher.clone());
        *indegree
            .get_mut(&edge.higher)
            .expect("validated precedence endpoint") += 1;
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(id.clone()))
        .collect::<BTreeSet<_>>();
    let mut rank = BTreeMap::new();
    while let Some(id) = ready.pop_first() {
        let next_rank = rank.len();
        rank.insert(id.clone(), next_rank);
        if let Some(next_layers) = adjacency.get(&id) {
            for next in next_layers {
                let degree = indegree
                    .get_mut(next)
                    .expect("validated precedence endpoint");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(next.clone());
                }
            }
        }
    }

    let profile_matches = |layer: &ConfigurationLayer| match &request.profile {
        Some(profile) => layer.profile.is_none() || layer.profile.as_ref() == Some(profile),
        None => layer.profile.is_none(),
    };
    let mut contributions = input
        .contributions
        .iter()
        .filter(|contribution| contribution.key == request.key)
        .filter(|contribution| {
            layer_by_id
                .get(&contribution.layer)
                .is_some_and(|layer| profile_matches(layer))
        })
        .cloned()
        .collect::<Vec<_>>();
    contributions.sort_by(|left, right| {
        rank[&left.layer]
            .cmp(&rank[&right.layer])
            .then_with(|| left.layer.cmp(&right.layer))
            .then_with(|| left.value.cmp(&right.value))
            .then_with(|| left.evidence.cmp(&right.evidence))
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.key.cmp(&right.key))
    });
    let contribution_budget_exhausted = contributions.len() > bounds.max_contributions;
    if contribution_budget_exhausted {
        contributions.truncate(bounds.max_contributions);
        reasons.push(ConfigurationIncompleteReason::ContributionBudgetExhausted);
    }

    let mut step_count = 0usize;
    let mut maxima = Vec::new();
    let mut stopped_reason = None;
    for candidate in &contributions {
        let mut dominated = false;
        for other in &contributions {
            if candidate.layer == other.layer {
                continue;
            }
            match reaches(
                &candidate.layer,
                &other.layer,
                &adjacency,
                bounds.max_precedence_steps,
                &mut step_count,
                cancellation,
            ) {
                Reachability::Reached => {
                    dominated = true;
                    break;
                }
                Reachability::NotReached => {}
                Reachability::Stopped(reason) => {
                    stopped_reason = Some(reason);
                    break;
                }
            }
        }
        if stopped_reason.is_some() {
            break;
        }
        if !dominated {
            maxima.push(candidate);
        }
    }
    if let Some(reason) = stopped_reason {
        reasons.push(reason);
    }

    let resolution_stopped = contribution_budget_exhausted || stopped_reason.is_some();
    let (value, proof) = if resolution_stopped {
        (
            None,
            ConfigurationResolutionProof::Unresolved {
                candidates: contributions
                    .iter()
                    .map(|contribution| contribution.layer.clone())
                    .collect(),
            },
        )
    } else if maxima.is_empty() {
        (None, ConfigurationResolutionProof::NoContribution)
    } else if maxima.len() > 1 {
        reasons.push(ConfigurationIncompleteReason::Conflict);
        (
            None,
            ConfigurationResolutionProof::Conflict {
                layers: maxima
                    .iter()
                    .map(|contribution| contribution.layer.clone())
                    .collect(),
            },
        )
    } else {
        let selected = maxima[0];
        (
            Some(selected.value.clone()),
            ConfigurationResolutionProof::Selected {
                layer: selected.layer.clone(),
            },
        )
    };

    let candidate_layers = contributions
        .iter()
        .map(|contribution| contribution.layer.clone())
        .collect::<BTreeSet<_>>();
    let mut precedence = input
        .precedence
        .iter()
        .filter(|edge| {
            candidate_layers.contains(&edge.lower) && candidate_layers.contains(&edge.higher)
        })
        .cloned()
        .collect::<Vec<_>>();
    precedence.sort_by(|left, right| {
        rank[&left.lower]
            .cmp(&rank[&right.lower])
            .then_with(|| rank[&left.higher].cmp(&rank[&right.higher]))
            .then_with(|| left.explanation.cmp(&right.explanation))
    });

    reasons.sort_unstable();
    reasons.dedup();
    let completeness = if reasons.is_empty() {
        ConfigurationResolutionCompleteness::Complete
    } else {
        ConfigurationResolutionCompleteness::Incomplete { reasons }
    };
    ConfigurationResolutionResult {
        key: request.key.clone(),
        value,
        contributions,
        precedence,
        proof,
        completeness,
    }
}

enum Reachability {
    Reached,
    NotReached,
    Stopped(ConfigurationIncompleteReason),
}

fn reaches(
    start: &ConfigurationLayerId,
    target: &ConfigurationLayerId,
    adjacency: &BTreeMap<ConfigurationLayerId, BTreeSet<ConfigurationLayerId>>,
    max_steps: usize,
    step_count: &mut usize,
    cancellation: &CancellationToken,
) -> Reachability {
    let mut stack = vec![start.clone()];
    let mut visited = BTreeSet::new();
    while let Some(current) = stack.pop() {
        if cancellation.is_cancelled() {
            return Reachability::Stopped(ConfigurationIncompleteReason::Cancellation);
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        if &current == target {
            return Reachability::Reached;
        }
        if let Some(next_layers) = adjacency.get(&current) {
            for next in next_layers.iter().rev() {
                if *step_count >= max_steps {
                    return Reachability::Stopped(
                        ConfigurationIncompleteReason::PrecedenceBudgetExhausted,
                    );
                }
                *step_count += 1;
                stack.push(next.clone());
            }
        }
    }
    Reachability::NotReached
}

impl ConfigurationDocumentFacts {
    /// Build the immutable fact arena.
    ///
    /// Fact IDs are arena indexes. The document is fact zero, every child has a
    /// greater ID than its parent, and every referenced child records that
    /// parent. These invariants keep the public model acyclic without relying
    /// on parser behavior.
    pub fn new(
        format: ConfigurationFormat,
        facts: Vec<ConfigurationFact>,
        completeness: ConfigurationCompleteness,
        features: ConfigurationFeatureSemantics,
    ) -> Result<Self, ConfigurationModelError> {
        if facts.is_empty() || facts[0].parent.is_some() {
            return Err(ConfigurationModelError::InvalidFactArena);
        }
        if !matches!(facts[0].kind, ConfigurationNodeKind::Document { .. }) {
            return Err(ConfigurationModelError::InvalidFactArena);
        }
        for (fact_id, fact) in facts.iter().enumerate() {
            let fact_id = ConfigurationFactId(fact_id);
            validate_children(fact_id, &facts, &fact.kind)?;
        }
        let ConfigurationNodeKind::Document { root } = &facts[0].kind else {
            return Err(ConfigurationModelError::InvalidFactArena);
        };
        if let Some(root) = root {
            let index = root.0;
            if index == 0
                || index >= facts.len()
                || facts[index].parent != Some(ConfigurationFactId(0))
            {
                return Err(ConfigurationModelError::InvalidFactArena);
            }
        } else if completeness.is_complete() {
            return Err(ConfigurationModelError::InvalidFactArena);
        }
        Ok(Self {
            format,
            document: ConfigurationFactId(0),
            facts,
            completeness,
            features,
        })
    }

    pub const fn format(&self) -> ConfigurationFormat {
        self.format
    }

    pub const fn document(&self) -> ConfigurationFactId {
        self.document
    }

    pub fn fact(&self, fact_id: ConfigurationFactId) -> Option<&ConfigurationFact> {
        self.facts.get(fact_id.0)
    }

    pub fn facts(&self) -> &[ConfigurationFact] {
        &self.facts
    }

    pub const fn completeness(&self) -> &ConfigurationCompleteness {
        &self.completeness
    }

    pub const fn features(&self) -> &ConfigurationFeatureSemantics {
        &self.features
    }
}

fn validate_children(
    parent: ConfigurationFactId,
    facts: &[ConfigurationFact],
    kind: &ConfigurationNodeKind,
) -> Result<(), ConfigurationModelError> {
    let children = match kind {
        ConfigurationNodeKind::Document { root } => root.iter().collect::<Vec<_>>(),
        ConfigurationNodeKind::Object { members } => members.iter().collect(),
        ConfigurationNodeKind::Section { header, members } => {
            header.iter().chain(members.iter()).collect::<Vec<_>>()
        }
        ConfigurationNodeKind::Sequence { items } => items.iter().collect(),
        ConfigurationNodeKind::Member { value, .. } => value.iter().collect(),
        ConfigurationNodeKind::Scalar { .. } => Vec::new(),
    };
    for child in children {
        let index = child.0;
        if index <= parent.0 || index >= facts.len() || facts[index].parent != Some(parent) {
            return Err(ConfigurationModelError::InvalidFactArena);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigurationCompleteness, ConfigurationContribution, ConfigurationDocumentFacts,
        ConfigurationEvidenceIdentity, ConfigurationFact, ConfigurationFeatureSemantics,
        ConfigurationFormat, ConfigurationIncompleteReason, ConfigurationKey, ConfigurationLayer,
        ConfigurationLayerId, ConfigurationMemberRole, ConfigurationModelError,
        ConfigurationNodeKind, ConfigurationOpaqueValue, ConfigurationPrecedenceEdge,
        ConfigurationPrecedenceExplanation, ConfigurationProfileId, ConfigurationProviderId,
        ConfigurationRecovery, ConfigurationRecoveryReason, ConfigurationResolutionBounds,
        ConfigurationResolutionInput, ConfigurationResolutionKey, ConfigurationResolutionProof,
        ConfigurationResolutionRequest, ConfigurationRoute, ConfigurationRouteSegment,
        ConfigurationRouteSelector, ConfigurationScalarKind, ConfigurationSourceId,
        ConfigurationSourceKind, ConfigurationSourceRange, ConfigurationStableId,
        ConfigurationVersionId, classify_configuration_path, resolve_effective_configuration,
    };
    use crate::analyzer::Language;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn range(start: usize, end: usize) -> ConfigurationSourceRange {
        ConfigurationSourceRange::new(start, end).expect("valid range")
    }

    #[test]
    fn canonical_path_classification_is_separate_from_language() {
        assert_eq!(
            classify_configuration_path(&PathBuf::from("config").join("Settings.YAML")),
            super::ConfigurationPathClassification::Supported(ConfigurationFormat::Yaml)
        );
        assert_eq!(
            classify_configuration_path(Path::new(r"C:\app\application.json")),
            super::ConfigurationPathClassification::Supported(ConfigurationFormat::Json)
        );
        assert_eq!(
            classify_configuration_path(Path::new("server.properties")),
            super::ConfigurationPathClassification::Supported(ConfigurationFormat::Properties)
        );
        assert_eq!(
            classify_configuration_path(Path::new("main.rs")),
            super::ConfigurationPathClassification::Unsupported
        );
        assert_eq!(
            classify_configuration_path(Path::new("data.toml.bak")),
            super::ConfigurationPathClassification::Unsupported
        );
        assert_eq!(Language::from_extension("json"), Language::None);
    }

    #[test]
    fn non_utf8_and_hidden_paths_are_unsupported() {
        #[cfg(unix)]
        let path = {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;

            Path::new("config").join(OsStr::from_bytes(b"file.\xffjson"))
        };
        #[cfg(windows)]
        let path = {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;

            let file_name = "file."
                .encode_utf16()
                .chain([0xd800])
                .chain("json".encode_utf16())
                .collect::<Vec<_>>();
            Path::new("config").join(OsString::from_wide(&file_name))
        };
        #[cfg(any(unix, windows))]
        assert_eq!(
            classify_configuration_path(&path),
            super::ConfigurationPathClassification::Unsupported
        );
        assert_eq!(
            classify_configuration_path(Path::new(".json")),
            super::ConfigurationPathClassification::Unsupported
        );
    }

    #[test]
    fn stable_ids_ignore_unrelated_siblings_and_ranges() {
        let route = ConfigurationRoute::root().child(
            ConfigurationRouteSegment::key("timeout", 1, range(10, 17)).expect("valid key segment"),
        );
        let member = |value_range: ConfigurationSourceRange| {
            ConfigurationFact::new(
                None,
                route.clone(),
                value_range,
                ConfigurationNodeKind::Member {
                    role: ConfigurationMemberRole::ObjectMember,
                    key: ConfigurationKey::new("timeout", range(10, 17)).expect("valid key"),
                    value: None,
                },
            )
        };
        let before = member(range(18, 21));
        let after = member(range(100, 103));
        assert_eq!(
            before.stable_id(ConfigurationFormat::Json),
            after.stable_id(ConfigurationFormat::Json)
        );
    }

    #[test]
    fn duplicate_occurrences_are_distinct_but_ordered() {
        let make_id = |occurrence: usize| {
            let route = ConfigurationRoute::root().child(
                ConfigurationRouteSegment::key("name", occurrence, range(0, 4))
                    .expect("valid duplicate segment"),
            );
            ConfigurationStableId::new(
                ConfigurationFormat::Json,
                &ConfigurationNodeKind::Member {
                    role: ConfigurationMemberRole::ObjectMember,
                    key: ConfigurationKey::new("name", range(0, 4)).expect("valid key"),
                    value: None,
                },
                &route,
            )
        };
        let first = make_id(1);
        let second = make_id(2);
        assert_ne!(first, second);
        assert_eq!(first, make_id(1));
    }

    #[test]
    fn json_feature_vocabulary_is_explicitly_not_applicable() {
        let features = ConfigurationFeatureSemantics::not_applicable();
        assert!(features.aliases().is_resolved());
        assert_eq!(
            features.anchors(),
            &super::ConfigurationFeatureState::NotApplicable
        );
        assert_eq!(
            features.includes(),
            &super::ConfigurationFeatureState::NotApplicable
        );
        assert_eq!(
            features.interpolation(),
            &super::ConfigurationFeatureState::NotApplicable
        );
        assert_eq!(
            features.format_merge(),
            &super::ConfigurationFeatureState::NotApplicable
        );
    }

    #[test]
    fn malformed_facts_remain_in_an_incomplete_document() {
        let document = ConfigurationDocumentFacts::new(
            ConfigurationFormat::Json,
            vec![ConfigurationFact::new(
                None,
                ConfigurationRoute::root(),
                range(0, 9),
                ConfigurationNodeKind::Document { root: None },
            )],
            ConfigurationCompleteness::Incomplete {
                recoveries: vec![ConfigurationRecovery::new(
                    ConfigurationRecoveryReason::MalformedSyntax,
                    range(0, 9),
                )],
            },
            ConfigurationFeatureSemantics::not_applicable(),
        )
        .expect("incomplete document with no root");

        assert!(!document.completeness().is_complete());
        assert_eq!(document.facts().len(), 1);
        assert_eq!(
            document.completeness(),
            &ConfigurationCompleteness::Incomplete {
                recoveries: vec![ConfigurationRecovery::new(
                    ConfigurationRecoveryReason::MalformedSyntax,
                    range(0, 9)
                )]
            }
        );
    }

    #[test]
    fn invalid_models_fail_closed() {
        assert_eq!(
            ConfigurationSourceRange::new(2, 1),
            Err(ConfigurationModelError::InvalidRange {
                start_byte: 2,
                end_byte: 1
            })
        );
        assert_eq!(
            ConfigurationRouteSegment::key("", 1, range(0, 1)),
            Err(ConfigurationModelError::InvalidRouteSegment)
        );
        let document = ConfigurationDocumentFacts::new(
            ConfigurationFormat::Json,
            Vec::new(),
            ConfigurationCompleteness::Complete,
            ConfigurationFeatureSemantics::not_applicable(),
        );
        assert_eq!(document, Err(ConfigurationModelError::InvalidFactArena));
        assert_eq!(
            ConfigurationRoute::root()
                .segments()
                .first()
                .map(|segment| segment.selector()),
            None
        );
        let route = ConfigurationRoute::root()
            .child(ConfigurationRouteSegment::key("x", 1, range(0, 1)).expect("valid segment"));
        assert_eq!(
            route.segments()[0].selector(),
            &ConfigurationRouteSelector::Key {
                name: "x".to_string(),
                occurrence: 1
            }
        );
        assert_eq!(
            ConfigurationStableId::new(
                ConfigurationFormat::Json,
                &ConfigurationNodeKind::Scalar {
                    scalar_kind: ConfigurationScalarKind::Integer
                },
                &ConfigurationRoute::root(),
            ),
            ConfigurationStableId::new(
                ConfigurationFormat::Json,
                &ConfigurationNodeKind::Scalar {
                    scalar_kind: ConfigurationScalarKind::Integer
                },
                &ConfigurationRoute::root(),
            )
        );
    }

    fn layer_id(name: &str) -> ConfigurationLayerId {
        ConfigurationLayerId::new(name).expect("non-empty layer id")
    }

    fn evidence() -> ConfigurationEvidenceIdentity {
        ConfigurationEvidenceIdentity::new(
            ConfigurationSourceId::new("fixture.json@sha256:fixture").expect("non-empty source id"),
            ConfigurationProviderId::new("fixture").expect("non-empty provider id"),
            ConfigurationVersionId::new("v1").expect("non-empty version id"),
        )
    }

    fn contribution(layer: &str, value: &str) -> ConfigurationContribution {
        ConfigurationContribution::new(
            layer_id(layer),
            ConfigurationResolutionKey::default(),
            ConfigurationOpaqueValue::new(value),
            evidence(),
            ConfigurationSourceKind::AuthoredFile,
        )
    }

    fn edge(lower: &str, higher: &str) -> ConfigurationPrecedenceEdge {
        ConfigurationPrecedenceEdge::new(
            layer_id(lower),
            layer_id(higher),
            ConfigurationPrecedenceExplanation::ExplicitOverride,
        )
        .expect("distinct layer ids")
    }

    fn input(
        layers: &[&str],
        contributions: Vec<ConfigurationContribution>,
        precedence: Vec<ConfigurationPrecedenceEdge>,
    ) -> ConfigurationResolutionInput {
        ConfigurationResolutionInput::new(
            layers
                .iter()
                .map(|name| ConfigurationLayer::new(layer_id(name)))
                .collect(),
            contributions,
            precedence,
        )
        .expect("valid configuration input")
    }

    #[test]
    fn effective_configuration_keeps_a_layered_override_and_proof_separate() {
        let input = input(
            &["authored", "deployment"],
            vec![
                contribution("deployment", "prod"),
                contribution("authored", "dev"),
            ],
            vec![edge("authored", "deployment")],
        );
        let result = resolve_effective_configuration(
            &ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default()),
            &input,
            ConfigurationResolutionBounds::default(),
            &crate::CancellationToken::new(),
        );

        assert_eq!(result.value().expect("selected value").as_str(), "prod");
        assert_eq!(
            result
                .contributions()
                .iter()
                .map(|item| item.layer().as_str())
                .collect::<Vec<_>>(),
            vec!["authored", "deployment"]
        );
        assert_eq!(result.precedence(), input.precedence());
        assert!(result.completeness().is_complete());
        assert!(matches!(
            result.proof(),
            ConfigurationResolutionProof::Selected { layer } if layer.as_str() == "deployment"
        ));
    }

    #[test]
    fn effective_key_ignores_authored_ranges_but_not_structural_selectors() {
        let authored_route = ConfigurationRoute::root()
            .child(ConfigurationRouteSegment::key("port", 1, range(1, 5)).expect("authored key"));
        let deployment_route = ConfigurationRoute::root().child(
            ConfigurationRouteSegment::key("port", 1, range(40, 44)).expect("deployment key"),
        );
        let other_route = ConfigurationRoute::root()
            .child(ConfigurationRouteSegment::key("host", 1, range(40, 44)).expect("other key"));
        assert_eq!(
            ConfigurationResolutionKey::from_route(&authored_route),
            ConfigurationResolutionKey::from_route(&deployment_route)
        );
        assert_ne!(
            ConfigurationResolutionKey::from_route(&authored_route),
            ConfigurationResolutionKey::from_route(&other_route)
        );
    }

    #[test]
    fn effective_configuration_is_independent_of_input_permutation() {
        let first = input(
            &["base", "profile", "deployment"],
            vec![
                contribution("deployment", "three"),
                contribution("base", "one"),
                contribution("profile", "two"),
            ],
            vec![edge("profile", "deployment"), edge("base", "profile")],
        );
        let second = input(
            &["deployment", "profile", "base"],
            vec![
                contribution("profile", "two"),
                contribution("deployment", "three"),
                contribution("base", "one"),
            ],
            vec![edge("base", "profile"), edge("profile", "deployment")],
        );
        let request = ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default());
        let bounds = ConfigurationResolutionBounds::default();
        let first_result = resolve_effective_configuration(
            &request,
            &first,
            bounds,
            &crate::CancellationToken::new(),
        );
        let second_result = resolve_effective_configuration(
            &request,
            &second,
            bounds,
            &crate::CancellationToken::new(),
        );
        assert_eq!(first_result, second_result);
    }

    #[test]
    fn incomparable_maxima_are_a_typed_conflict() {
        let result = resolve_effective_configuration(
            &ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default()),
            &input(
                &["left", "right"],
                vec![contribution("right", "r"), contribution("left", "l")],
                Vec::new(),
            ),
            ConfigurationResolutionBounds::default(),
            &crate::CancellationToken::new(),
        );
        assert!(result.value().is_none());
        assert!(
            result
                .completeness()
                .reasons()
                .contains(&ConfigurationIncompleteReason::Conflict)
        );
        assert!(matches!(
            result.proof(),
            ConfigurationResolutionProof::Conflict { .. }
        ));
    }

    #[test]
    fn supplied_incomplete_reasons_are_not_flattened() {
        let base = input(&["base"], vec![contribution("base", "known")], Vec::new());
        for reason in [
            ConfigurationIncompleteReason::UnresolvedInterpolation,
            ConfigurationIncompleteReason::UnavailableEnvironment,
            ConfigurationIncompleteReason::UnknownProfile,
            ConfigurationIncompleteReason::MissingInclude,
            ConfigurationIncompleteReason::ParserLimitation,
        ] {
            let result = resolve_effective_configuration(
                &ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default()),
                &base.clone().with_incomplete_reason(reason),
                ConfigurationResolutionBounds::default(),
                &crate::CancellationToken::new(),
            );
            assert_eq!(result.value().expect("known value").as_str(), "known");
            assert!(!result.completeness().is_complete());
            assert!(result.completeness().reasons().contains(&reason));
        }
        let unknown_profile = resolve_effective_configuration(
            &ConfigurationResolutionRequest::for_profile(
                ConfigurationResolutionKey::default(),
                ConfigurationProfileId::new("missing").expect("profile id"),
            ),
            &base,
            ConfigurationResolutionBounds::default(),
            &crate::CancellationToken::new(),
        );
        assert!(
            unknown_profile
                .completeness()
                .reasons()
                .contains(&ConfigurationIncompleteReason::UnknownProfile)
        );
    }

    #[test]
    fn cancellation_and_budgets_are_typed_lanes() {
        let base = input(
            &["base", "deployment"],
            vec![
                contribution("base", "dev"),
                contribution("deployment", "prod"),
            ],
            vec![edge("base", "deployment")],
        );
        let cancellation = crate::CancellationToken::new();
        cancellation.cancel();
        let cancelled = resolve_effective_configuration(
            &ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default()),
            &base,
            ConfigurationResolutionBounds::default(),
            &cancellation,
        );
        assert!(
            cancelled
                .completeness()
                .reasons()
                .contains(&ConfigurationIncompleteReason::Cancellation)
        );

        let contribution_limited = resolve_effective_configuration(
            &ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default()),
            &base,
            ConfigurationResolutionBounds::new(1, usize::MAX),
            &crate::CancellationToken::new(),
        );
        assert!(
            contribution_limited
                .completeness()
                .reasons()
                .contains(&ConfigurationIncompleteReason::ContributionBudgetExhausted)
        );
        assert!(contribution_limited.value().is_none());
        assert!(matches!(
            contribution_limited.proof(),
            ConfigurationResolutionProof::Unresolved { .. }
        ));
        let precedence_limited = resolve_effective_configuration(
            &ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default()),
            &base,
            ConfigurationResolutionBounds::new(usize::MAX, 0),
            &crate::CancellationToken::new(),
        );
        assert!(
            precedence_limited
                .completeness()
                .reasons()
                .contains(&ConfigurationIncompleteReason::PrecedenceBudgetExhausted)
        );
        assert!(precedence_limited.value().is_none());
        assert!(matches!(
            precedence_limited.proof(),
            ConfigurationResolutionProof::Unresolved { .. }
        ));

        let cancelled_during_precedence = resolve_effective_configuration(
            &ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default()),
            &base,
            ConfigurationResolutionBounds::default(),
            &crate::CancellationToken::cancel_after_checks_for_test(2),
        );
        assert!(
            cancelled_during_precedence
                .completeness()
                .reasons()
                .contains(&ConfigurationIncompleteReason::Cancellation)
        );
        assert!(cancelled_during_precedence.value().is_none());
    }

    #[derive(Debug, PartialEq, Eq)]
    enum OracleValue {
        None,
        Value(String),
        Conflict,
    }

    // This intentionally computes reachability independently of `reaches`.
    fn oracle_value(input: &ConfigurationResolutionInput) -> OracleValue {
        let mut adjacency = BTreeMap::<ConfigurationLayerId, BTreeSet<ConfigurationLayerId>>::new();
        for edge in input.precedence() {
            adjacency
                .entry(edge.lower().clone())
                .or_default()
                .insert(edge.higher().clone());
        }
        let mut maximal = Vec::new();
        for candidate in input.contributions() {
            let mut dominated = false;
            for other in input.contributions() {
                if candidate.layer() == other.layer() {
                    continue;
                }
                let mut stack = vec![candidate.layer().clone()];
                let mut visited = BTreeSet::new();
                while let Some(current) = stack.pop() {
                    if !visited.insert(current.clone()) {
                        continue;
                    }
                    if &current == other.layer() {
                        dominated = true;
                        break;
                    }
                    if let Some(next) = adjacency.get(&current) {
                        stack.extend(next.iter().cloned());
                    }
                }
                if dominated {
                    break;
                }
            }
            if !dominated {
                maximal.push(candidate.value().as_str().to_string());
            }
        }
        match maximal.as_slice() {
            [] => OracleValue::None,
            [value] => OracleValue::Value(value.clone()),
            _ => OracleValue::Conflict,
        }
    }

    #[test]
    fn resolver_matches_an_independent_oracle_on_small_dags() {
        let cases = [
            input(
                &["a", "b", "c"],
                vec![
                    contribution("c", "c"),
                    contribution("a", "a"),
                    contribution("b", "b"),
                ],
                vec![edge("a", "b"), edge("b", "c")],
            ),
            input(
                &["a", "b", "c"],
                vec![
                    contribution("a", "a"),
                    contribution("b", "b"),
                    contribution("c", "c"),
                ],
                vec![edge("a", "b"), edge("a", "c")],
            ),
            input(
                &["a", "b"],
                vec![contribution("a", "same"), contribution("b", "same")],
                Vec::new(),
            ),
        ];
        let request = ConfigurationResolutionRequest::new(ConfigurationResolutionKey::default());
        for input in &cases {
            let result = resolve_effective_configuration(
                &request,
                input,
                ConfigurationResolutionBounds::default(),
                &crate::CancellationToken::new(),
            );
            match oracle_value(input) {
                OracleValue::None => assert!(result.value().is_none()),
                OracleValue::Value(value) => {
                    assert_eq!(
                        result.value().expect("oracle selected value").as_str(),
                        value
                    )
                }
                OracleValue::Conflict => {
                    assert!(matches!(
                        result.proof(),
                        ConfigurationResolutionProof::Conflict { .. }
                    ))
                }
            }
        }
    }
}
