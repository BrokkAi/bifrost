//! Format-neutral facts about authored configuration documents.

use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use serde::{Deserialize, Serialize};
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
        }
    }
}

/// One ordered element of a stable structural route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigurationRouteSelector {
    Key { name: String, occurrence: usize },
    Index(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// States for a format in which the feature is absent by definition.
    pub const fn not_applicable() -> Self {
        Self {
            anchors: ConfigurationFeatureState::NotApplicable,
            aliases: ConfigurationFeatureState::NotApplicable,
            includes: ConfigurationFeatureState::NotApplicable,
            interpolation: ConfigurationFeatureState::NotApplicable,
            format_merge: ConfigurationFeatureState::NotApplicable,
        }
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
        ConfigurationCompleteness, ConfigurationDocumentFacts, ConfigurationFact,
        ConfigurationFeatureSemantics, ConfigurationFormat, ConfigurationKey,
        ConfigurationMemberRole, ConfigurationModelError, ConfigurationNodeKind,
        ConfigurationRecovery, ConfigurationRecoveryReason, ConfigurationRoute,
        ConfigurationRouteSegment, ConfigurationRouteSelector, ConfigurationScalarKind,
        ConfigurationSourceRange, ConfigurationStableId, classify_configuration_path,
    };
    use crate::analyzer::Language;
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
}
