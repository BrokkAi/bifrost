//! Syntax-neutral query-domain capability contracts.
//!
//! This module deliberately describes requirements and evidence only.  It does
//! not discover files, parse configuration formats, or make claims about
//! effective configuration values.  The types are shared by CodeQuery and
//! policy adapters so that unsupported and incomplete analysis cannot be
//! accidentally presented as a clean result.

use brokk_bifrost_core::analyzer::Language;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 1024;
const MAX_VERSION_BYTES: usize = 128;
const MAX_PACK_REQUIREMENTS: usize = 128;
const MAX_CAPABILITY_REQUIREMENTS: usize = 128;
const MAX_OPERATOR_INPUTS: usize = 8;
const MAX_DOMAIN_SELECTIONS: usize = 64;

/// The closed initial registry of structured configuration formats.
///
/// This is intentionally separate from [`Language`].  A configuration format
/// is an input representation, not a programming-language analyzer front end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// Additional labels accepted by the registry, not by a parser.
    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::Yaml => &["yml"],
            Self::Toml => &[],
            Self::Json => &[],
            Self::Xml => &[],
            Self::Properties => &["props", "property"],
        }
    }

    /// Extensions used by a future source-discovery adapter.
    pub const fn discovery_extensions(self) -> &'static [&'static str] {
        match self {
            Self::Yaml => &["yaml", "yml"],
            Self::Toml => &["toml"],
            Self::Json => &["json"],
            Self::Xml => &["xml"],
            Self::Properties => &["properties", "props"],
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        let normalized = label.trim().trim_start_matches('.').to_ascii_lowercase();
        Self::ALL.into_iter().find(|format| {
            format.label() == normalized || format.aliases().contains(&normalized.as_str())
        })
    }

    pub fn from_discovery_extension(extension: &str) -> Option<Self> {
        let normalized = extension
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|format| format.discovery_extensions().contains(&normalized.as_str()))
    }
}

impl fmt::Display for ConfigurationFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

impl Serialize for ConfigurationFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.label())
    }
}

impl<'de> Deserialize<'de> for ConfigurationFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let label = String::deserialize(deserializer)?;
        Self::from_label(&label).ok_or_else(|| D::Error::custom("unknown configuration format"))
    }
}

/// A validated, stable identifier used by the capability and provider
/// registries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct StableIdentifier(String);

impl StableIdentifier {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainValidationError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StableIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! identifier_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        pub struct $name(StableIdentifier);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, DomainValidationError> {
                Ok(Self(StableIdentifier::new(value)?))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

identifier_type!(
    /// A typed analyzer capability identity.
    CapabilityId
);
identifier_type!(
    /// A typed semantic or policy pack identity.
    PackId
);
identifier_type!(
    /// A typed provider identity.
    ProviderId
);
identifier_type!(
    /// A typed cross-domain operator identity.
    OperatorId
);

/// A provider or capability version.  Version interpretation belongs to the
/// provider registry; the contract retains it exactly and never guesses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Version(String);

impl Version {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainValidationError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_VERSION_BYTES {
            return Err(DomainValidationError::InvalidVersion);
        }
        if value.chars().any(char::is_whitespace) || value.chars().any(char::is_control) {
            return Err(DomainValidationError::InvalidVersion);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A provider-defined version requirement retained as a typed value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum VersionRequirement {
    Any,
    Exact(Version),
    AtLeast(Version),
}

impl VersionRequirement {
    pub const fn any() -> Self {
        Self::Any
    }

    pub fn exact(version: Version) -> Self {
        Self::Exact(version)
    }

    pub fn at_least(version: Version) -> Self {
        Self::AtLeast(version)
    }
}

impl fmt::Display for VersionRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => formatter.write_str("*"),
            Self::Exact(version) => version.fmt(formatter),
            Self::AtLeast(version) => write!(formatter, ">={version}"),
        }
    }
}

/// A code or configuration selection.  The inner sets are always non-empty
/// and canonicalized by their constructors.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum QueryDomain {
    Code { languages: Vec<Language> },
    Configuration { formats: Vec<ConfigurationFormat> },
}

pub type InputDomain = QueryDomain;

impl QueryDomain {
    pub fn code<I>(languages: I) -> Result<Self, DomainValidationError>
    where
        I: IntoIterator<Item = Language>,
    {
        let languages = canonical_languages(languages)?;
        Ok(Self::Code { languages })
    }

    pub fn configuration<I>(formats: I) -> Result<Self, DomainValidationError>
    where
        I: IntoIterator<Item = ConfigurationFormat>,
    {
        let formats = canonical_formats(formats)?;
        Ok(Self::Configuration { formats })
    }

    pub fn kind(&self) -> DomainKind {
        match self {
            Self::Code { .. } => DomainKind::Code,
            Self::Configuration { .. } => DomainKind::Configuration,
        }
    }

    pub fn languages(&self) -> Option<&[Language]> {
        match self {
            Self::Code { languages } => Some(languages),
            Self::Configuration { .. } => None,
        }
    }

    pub fn formats(&self) -> Option<&[ConfigurationFormat]> {
        match self {
            Self::Code { .. } => None,
            Self::Configuration { formats } => Some(formats),
        }
    }

    pub fn intersect(&self, other: &Self) -> Result<Self, DomainCompositionError> {
        match (self, other) {
            (Self::Code { languages: left }, Self::Code { languages: right }) => {
                let shared = left
                    .iter()
                    .copied()
                    .filter(|language| right.contains(language))
                    .collect::<Vec<_>>();
                if shared.is_empty() {
                    return Err(DomainCompositionError::DisjointIntersection);
                }
                Ok(Self::Code { languages: shared })
            }
            (Self::Configuration { formats: left }, Self::Configuration { formats: right }) => {
                let shared = left
                    .iter()
                    .copied()
                    .filter(|format| right.contains(format))
                    .collect::<Vec<_>>();
                if shared.is_empty() {
                    return Err(DomainCompositionError::DisjointIntersection);
                }
                Ok(Self::Configuration { formats: shared })
            }
            _ => Err(DomainCompositionError::CrossDomainConjunction),
        }
    }
}

/// The row side of a query.  A heterogeneous row explicitly records both the
/// discriminator and the retained provenance required to interpret each row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum RowDomain {
    Code { languages: Vec<Language> },
    Configuration { formats: Vec<ConfigurationFormat> },
    Heterogeneous(HeterogeneousRowDomain),
}

impl RowDomain {
    pub fn code<I>(languages: I) -> Result<Self, DomainValidationError>
    where
        I: IntoIterator<Item = Language>,
    {
        let domain = QueryDomain::code(languages)?;
        let QueryDomain::Code { languages } = domain else {
            unreachable!()
        };
        Ok(Self::Code { languages })
    }

    pub fn configuration<I>(formats: I) -> Result<Self, DomainValidationError>
    where
        I: IntoIterator<Item = ConfigurationFormat>,
    {
        let domain = QueryDomain::configuration(formats)?;
        let QueryDomain::Configuration { formats } = domain else {
            unreachable!()
        };
        Ok(Self::Configuration { formats })
    }

    pub fn heterogeneous(
        alternatives: impl IntoIterator<Item = QueryDomain>,
        discriminator: DomainDiscriminator,
        retains_provenance: bool,
    ) -> Result<Self, DomainCompositionError> {
        HeterogeneousRowDomain::new(alternatives, discriminator, retains_provenance)
            .map(Self::Heterogeneous)
    }

    pub fn kind(&self) -> RowDomainKind {
        match self {
            Self::Code { .. } => RowDomainKind::Code,
            Self::Configuration { .. } => RowDomainKind::Configuration,
            Self::Heterogeneous(_) => RowDomainKind::Heterogeneous,
        }
    }

    pub fn as_query_domain(&self) -> Option<QueryDomain> {
        match self {
            Self::Code { languages } => Some(QueryDomain::Code {
                languages: languages.clone(),
            }),
            Self::Configuration { formats } => Some(QueryDomain::Configuration {
                formats: formats.clone(),
            }),
            Self::Heterogeneous(_) => None,
        }
    }

    pub fn intersect(&self, other: &Self) -> Result<Self, DomainCompositionError> {
        match (self.as_query_domain(), other.as_query_domain()) {
            (Some(left), Some(right)) => match left.intersect(&right)? {
                QueryDomain::Code { languages } => Ok(Self::Code { languages }),
                QueryDomain::Configuration { formats } => Ok(Self::Configuration { formats }),
            },
            _ => Err(DomainCompositionError::HeterogeneousIntersection),
        }
    }

    /// Union rows.  Heterogeneous unions require a domain discriminator and
    /// retained provenance; omitting either is a construction error.
    pub fn union(
        &self,
        other: &Self,
        discriminator: Option<DomainDiscriminator>,
        retains_provenance: bool,
    ) -> Result<Self, DomainCompositionError> {
        let (Some(left), Some(right)) = (self.as_query_domain(), other.as_query_domain()) else {
            return Err(DomainCompositionError::NestedHeterogeneousUnion);
        };
        if left.kind() == right.kind() {
            return match (left, right) {
                (
                    QueryDomain::Code {
                        languages: mut left,
                    },
                    QueryDomain::Code { languages: right },
                ) => {
                    left.extend(right);
                    left.sort_unstable();
                    left.dedup();
                    Ok(Self::Code { languages: left })
                }
                (
                    QueryDomain::Configuration { formats: mut left },
                    QueryDomain::Configuration { formats: right },
                ) => {
                    left.extend(right);
                    left.sort_unstable();
                    left.dedup();
                    Ok(Self::Configuration { formats: left })
                }
                _ => unreachable!(),
            };
        }
        let discriminator = discriminator.ok_or(DomainCompositionError::MissingDiscriminator)?;
        if !retains_provenance {
            return Err(DomainCompositionError::MissingProvenance);
        }
        Self::heterogeneous([left, right], discriminator, true)
    }
}

/// A domain-tagged heterogeneous row set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct HeterogeneousRowDomain {
    alternatives: Vec<QueryDomain>,
    discriminator: DomainDiscriminator,
    retains_provenance: bool,
}

impl HeterogeneousRowDomain {
    pub fn new(
        alternatives: impl IntoIterator<Item = QueryDomain>,
        discriminator: DomainDiscriminator,
        retains_provenance: bool,
    ) -> Result<Self, DomainCompositionError> {
        let mut alternatives = alternatives.into_iter().collect::<Vec<_>>();
        if alternatives.len() < 2 {
            return Err(DomainCompositionError::HeterogeneousNeedsAlternatives);
        }
        if !retains_provenance {
            return Err(DomainCompositionError::MissingProvenance);
        }
        alternatives.sort_unstable();
        alternatives.dedup();
        if alternatives.len() < 2 {
            return Err(DomainCompositionError::HeterogeneousNeedsAlternatives);
        }
        Ok(Self {
            alternatives,
            discriminator,
            retains_provenance,
        })
    }

    pub fn alternatives(&self) -> &[QueryDomain] {
        &self.alternatives
    }

    pub const fn discriminator(&self) -> DomainDiscriminator {
        self.discriminator
    }

    pub const fn retains_provenance(&self) -> bool {
        self.retains_provenance
    }
}

/// The discriminator required for a heterogeneous result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum DomainDiscriminator {
    Domain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum DomainKind {
    Code,
    Configuration,
}

impl DomainKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Configuration => "configuration",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum RowDomainKind {
    Code,
    Configuration,
    Heterogeneous,
}

/// A versioned capability required by a query.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct CapabilityRequirement {
    capability: CapabilityId,
    version: VersionRequirement,
}

impl CapabilityRequirement {
    pub fn new(capability: CapabilityId, version: VersionRequirement) -> Self {
        Self {
            capability,
            version,
        }
    }

    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    pub fn version(&self) -> &VersionRequirement {
        &self.version
    }
}

/// A stable semantic or policy pack namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PackIdentity {
    kind: PackKind,
    id: PackId,
}

impl PackIdentity {
    pub fn semantic(id: PackId) -> Self {
        Self {
            kind: PackKind::Semantic,
            id,
        }
    }

    pub fn policy(id: PackId) -> Self {
        Self {
            kind: PackKind::Policy,
            id,
        }
    }

    pub const fn kind(&self) -> PackKind {
        self.kind
    }

    pub fn id(&self) -> &PackId {
        &self.id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum PackKind {
    Semantic,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum RequirementStrength {
    Optional,
    Mandatory,
}

impl RequirementStrength {
    const fn rank(self) -> u8 {
        match self {
            Self::Optional => 0,
            Self::Mandatory => 1,
        }
    }
}

impl Ord for RequirementStrength {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for RequirementStrength {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One pack requirement.  Mandatory dominates optional when requirements are
/// unioned for the same pack identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PackRequirement {
    identity: PackIdentity,
    version: VersionRequirement,
    strength: RequirementStrength,
}

impl PackRequirement {
    pub fn mandatory(identity: PackIdentity) -> Self {
        Self {
            identity,
            version: VersionRequirement::any(),
            strength: RequirementStrength::Mandatory,
        }
    }

    pub fn optional(identity: PackIdentity) -> Self {
        Self {
            identity,
            version: VersionRequirement::any(),
            strength: RequirementStrength::Optional,
        }
    }

    pub fn with_version(mut self, version: VersionRequirement) -> Self {
        self.version = version;
        self
    }

    pub fn identity(&self) -> &PackIdentity {
        &self.identity
    }

    pub fn version(&self) -> &VersionRequirement {
        &self.version
    }

    pub const fn strength(&self) -> RequirementStrength {
        self.strength
    }
}

/// Canonical sorted pack requirements with mandatory-union dominance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PackRequirementSet(Vec<PackRequirement>);

impl PackRequirementSet {
    pub fn new(
        requirements: impl IntoIterator<Item = PackRequirement>,
    ) -> Result<Self, DomainValidationError> {
        let mut by_requirement =
            BTreeMap::<(PackIdentity, VersionRequirement), PackRequirement>::new();
        for requirement in requirements {
            let key = (requirement.identity.clone(), requirement.version.clone());
            if by_requirement.len() >= MAX_PACK_REQUIREMENTS && !by_requirement.contains_key(&key) {
                return Err(DomainValidationError::TooManyRequirements);
            }
            match by_requirement.get_mut(&key) {
                Some(existing) => {
                    if requirement.strength > existing.strength {
                        *existing = requirement;
                    }
                }
                None => {
                    by_requirement.insert(key, requirement);
                }
            }
        }
        Ok(Self(by_requirement.into_values().collect()))
    }

    pub fn union(&self, other: &Self) -> Result<Self, DomainValidationError> {
        Self::new(self.0.iter().cloned().chain(other.0.iter().cloned()))
    }

    pub fn as_slice(&self) -> &[PackRequirement] {
        &self.0
    }
}

/// Canonical capability requirements.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CapabilityRequirementSet(Vec<CapabilityRequirement>);

impl CapabilityRequirementSet {
    pub fn new(
        requirements: impl IntoIterator<Item = CapabilityRequirement>,
    ) -> Result<Self, DomainValidationError> {
        let mut requirements = requirements.into_iter().collect::<Vec<_>>();
        requirements.sort_unstable();
        requirements.dedup();
        if requirements.len() > MAX_CAPABILITY_REQUIREMENTS {
            return Err(DomainValidationError::TooManyRequirements);
        }
        Ok(Self(requirements))
    }

    pub fn as_slice(&self) -> &[CapabilityRequirement] {
        &self.0
    }
}

/// A typed relation that explicitly consumes more than one domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrossDomainOperator {
    id: OperatorId,
    inputs: Vec<QueryDomain>,
    output: RowDomain,
}

impl CrossDomainOperator {
    pub fn new(
        id: OperatorId,
        inputs: impl IntoIterator<Item = QueryDomain>,
        output: RowDomain,
    ) -> Result<Self, DomainCompositionError> {
        let mut inputs = inputs.into_iter().collect::<Vec<_>>();
        if inputs.len() < 2 || inputs.len() > MAX_OPERATOR_INPUTS {
            return Err(DomainCompositionError::InvalidOperatorInputs);
        }
        inputs.sort_unstable();
        inputs.dedup();
        let has_code = inputs.iter().any(|input| input.kind() == DomainKind::Code);
        let has_configuration = inputs
            .iter()
            .any(|input| input.kind() == DomainKind::Configuration);
        if !has_code || !has_configuration {
            return Err(DomainCompositionError::OperatorIsNotCrossDomain);
        }
        Ok(Self { id, inputs, output })
    }

    pub fn id(&self) -> &OperatorId {
        &self.id
    }

    pub fn inputs(&self) -> &[QueryDomain] {
        &self.inputs
    }

    pub const fn output(&self) -> &RowDomain {
        &self.output
    }

    pub fn accepts(&self, input: &QueryDomain) -> bool {
        self.inputs.iter().any(|candidate| candidate == input)
    }
}

/// A complete syntax-neutral requirement for a query branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryRequirement {
    input: QueryInputDomain,
    row: RowDomain,
    capabilities: CapabilityRequirementSet,
    packs: PackRequirementSet,
}

impl QueryRequirement {
    pub fn new(
        input: QueryDomain,
        row: RowDomain,
        capabilities: CapabilityRequirementSet,
        packs: PackRequirementSet,
    ) -> Self {
        Self {
            input: QueryInputDomain::single(input),
            row,
            capabilities,
            packs,
        }
    }

    pub fn input(&self) -> &QueryInputDomain {
        &self.input
    }

    pub fn row(&self) -> &RowDomain {
        &self.row
    }

    pub fn capabilities(&self) -> &CapabilityRequirementSet {
        &self.capabilities
    }

    pub fn packs(&self) -> &PackRequirementSet {
        &self.packs
    }

    /// Ordinary composition is conjunctive.  It intersects only like domains
    /// and refuses code/configuration mixing unless an operator is supplied.
    pub fn conjoin(&self, other: &Self) -> Result<Self, DomainCompositionError> {
        let (QueryInputDomain::Single(left), QueryInputDomain::Single(right)) =
            (&self.input, &other.input)
        else {
            return Err(DomainCompositionError::CrossDomainConjunction);
        };
        let input = left.intersect(right)?;
        let row = self.row.intersect(&other.row)?;
        let packs = self
            .packs
            .union(&other.packs)
            .map_err(DomainCompositionError::Validation)?;
        let mut capabilities = self.capabilities.0.clone();
        capabilities.extend(other.capabilities.0.iter().cloned());
        let capabilities = CapabilityRequirementSet::new(capabilities)
            .map_err(DomainCompositionError::Validation)?;
        Ok(Self::new(input, row, capabilities, packs))
    }

    /// Compose heterogeneous inputs only through the operator's declared,
    /// typed relation.
    pub fn through_cross_domain_operator(
        &self,
        other: &Self,
        operator: &CrossDomainOperator,
    ) -> Result<Self, DomainCompositionError> {
        let (QueryInputDomain::Single(left), QueryInputDomain::Single(right)) =
            (&self.input, &other.input)
        else {
            return Err(DomainCompositionError::OperatorInputMismatch);
        };
        if !operator.accepts(left) || !operator.accepts(right) {
            return Err(DomainCompositionError::OperatorInputMismatch);
        }
        if left.kind() == right.kind() {
            return Err(DomainCompositionError::OperatorNeedsHeterogeneousInputs);
        }
        let packs = self
            .packs
            .union(&other.packs)
            .map_err(DomainCompositionError::Validation)?;
        let mut capabilities = self.capabilities.0.clone();
        capabilities.extend(other.capabilities.0.iter().cloned());
        let capabilities = CapabilityRequirementSet::new(capabilities)
            .map_err(DomainCompositionError::Validation)?;
        Ok(
            Self::new(left.clone(), operator.output().clone(), capabilities, packs).with_input(
                QueryInputDomain::cross_domain(operator.id.clone(), [left.clone(), right.clone()])?,
            ),
        )
    }

    fn with_input(mut self, input: QueryInputDomain) -> Self {
        self.input = input;
        self
    }
}

/// The input side of a requirement.  A cross-domain operator retains both
/// typed input domains rather than erasing one after composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum QueryInputDomain {
    Single(QueryDomain),
    CrossDomain {
        operator: OperatorId,
        inputs: Vec<QueryDomain>,
    },
}

impl QueryInputDomain {
    pub fn single(domain: QueryDomain) -> Self {
        Self::Single(domain)
    }

    pub fn cross_domain(
        operator: OperatorId,
        inputs: impl IntoIterator<Item = QueryDomain>,
    ) -> Result<Self, DomainCompositionError> {
        let mut inputs = inputs.into_iter().collect::<Vec<_>>();
        if inputs.len() < 2 {
            return Err(DomainCompositionError::InvalidOperatorInputs);
        }
        inputs.sort_unstable();
        inputs.dedup();
        if inputs.len() < 2 {
            return Err(DomainCompositionError::InvalidOperatorInputs);
        }
        Ok(Self::CrossDomain { operator, inputs })
    }

    pub fn domains(&self) -> &[QueryDomain] {
        match self {
            Self::Single(domain) => std::slice::from_ref(domain),
            Self::CrossDomain { inputs, .. } => inputs,
        }
    }

    pub fn operator(&self) -> Option<&OperatorId> {
        match self {
            Self::Single(_) => None,
            Self::CrossDomain { operator, .. } => Some(operator),
        }
    }
}

/// Provenance for one support decision.  All outcome variants carry this
/// structure, including invalid decisions, so diagnostics never lose where a
/// requirement came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluationEvidence {
    authored_path: String,
    selected_input: QueryInputDomain,
    provider: Option<ProviderId>,
    provider_version: Option<Version>,
    capability: Option<CapabilityId>,
    capability_version: Option<Version>,
    pack_activation: Vec<PackActivationEvidence>,
}

impl EvaluationEvidence {
    pub fn new(
        authored_path: impl Into<String>,
        selected_input: impl Into<QueryInputDomain>,
        provider: ProviderId,
        provider_version: Version,
        capability: CapabilityId,
        capability_version: Version,
        pack_activation: impl IntoIterator<Item = PackActivationEvidence>,
    ) -> Result<Self, DomainValidationError> {
        Self::new_with_optional(
            authored_path,
            selected_input,
            Some(provider),
            Some(provider_version),
            Some(capability),
            Some(capability_version),
            pack_activation,
        )
    }

    pub fn new_with_optional(
        authored_path: impl Into<String>,
        selected_input: impl Into<QueryInputDomain>,
        provider: Option<ProviderId>,
        provider_version: Option<Version>,
        capability: Option<CapabilityId>,
        capability_version: Option<Version>,
        pack_activation: impl IntoIterator<Item = PackActivationEvidence>,
    ) -> Result<Self, DomainValidationError> {
        let authored_path = authored_path.into();
        if authored_path.is_empty() || authored_path.len() > MAX_PATH_BYTES {
            return Err(DomainValidationError::InvalidAuthoredPath);
        }
        let pack_activation = pack_activation.into_iter().collect::<Vec<_>>();
        Ok(Self {
            authored_path,
            selected_input: selected_input.into(),
            provider,
            provider_version,
            capability,
            capability_version,
            pack_activation,
        })
    }

    pub fn authored_path(&self) -> &str {
        &self.authored_path
    }

    pub const fn selected_input(&self) -> &QueryInputDomain {
        &self.selected_input
    }

    pub fn provider(&self) -> Option<&ProviderId> {
        self.provider.as_ref()
    }

    pub fn provider_version(&self) -> Option<&Version> {
        self.provider_version.as_ref()
    }

    pub fn capability(&self) -> Option<&CapabilityId> {
        self.capability.as_ref()
    }

    pub fn capability_version(&self) -> Option<&Version> {
        self.capability_version.as_ref()
    }

    pub fn pack_activation(&self) -> &[PackActivationEvidence] {
        &self.pack_activation
    }
}

impl From<QueryDomain> for QueryInputDomain {
    fn from(domain: QueryDomain) -> Self {
        Self::Single(domain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackActivationEvidence {
    pack: PackIdentity,
    provider: ProviderId,
    version: Version,
    state: PackActivationState,
}

impl PackActivationEvidence {
    pub fn new(
        pack: PackIdentity,
        provider: ProviderId,
        version: Version,
        state: PackActivationState,
    ) -> Self {
        Self {
            pack,
            provider,
            version,
            state,
        }
    }

    pub fn pack(&self) -> &PackIdentity {
        &self.pack
    }

    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub const fn state(&self) -> PackActivationState {
        self.state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PackActivationState {
    Activated,
    Unavailable,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CapabilityEvaluation {
    Supported {
        evidence: EvaluationEvidence,
    },
    Unsupported {
        evidence: EvaluationEvidence,
        reason: UnsupportedReason,
    },
    Incomplete {
        evidence: EvaluationEvidence,
        reason: IncompleteReason,
    },
    Invalid {
        evidence: EvaluationEvidence,
        reason: InvalidReason,
    },
}

impl CapabilityEvaluation {
    pub fn supported(evidence: EvaluationEvidence) -> Result<Self, DomainValidationError> {
        if evidence.provider.is_none()
            || evidence.provider_version.is_none()
            || evidence.capability.is_none()
            || evidence.capability_version.is_none()
        {
            return Err(DomainValidationError::MissingEvaluationEvidence);
        }
        Ok(Self::Supported { evidence })
    }

    pub fn unsupported(evidence: EvaluationEvidence, reason: UnsupportedReason) -> Self {
        Self::Unsupported { evidence, reason }
    }

    pub fn incomplete(evidence: EvaluationEvidence, reason: IncompleteReason) -> Self {
        Self::Incomplete { evidence, reason }
    }

    pub fn invalid(evidence: EvaluationEvidence, reason: InvalidReason) -> Self {
        Self::Invalid { evidence, reason }
    }

    pub fn evidence(&self) -> &EvaluationEvidence {
        match self {
            Self::Supported { evidence }
            | Self::Unsupported { evidence, .. }
            | Self::Incomplete { evidence, .. }
            | Self::Invalid { evidence, .. } => evidence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UnsupportedReason {
    CapabilityUnavailable,
    ProviderUnavailable,
    PackUnavailable,
    CrossDomainOperatorUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IncompleteReason {
    CapabilityCoverageIncomplete,
    PackActivationIncomplete,
    BudgetExhausted,
    DiscoveryIncomplete,
    ParsingIncomplete,
    Cancellation,
    ArtifactUnavailable,
    PartialFormatSemantics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InvalidReason {
    ContradictoryDomainRequirements,
    MissingDomainDiscriminator,
    MissingProvenance,
    InvalidOperatorComposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainValidationError {
    EmptySelection,
    InvalidLanguage,
    InvalidIdentifier,
    InvalidVersion,
    InvalidVersionRequirement,
    InvalidAuthoredPath,
    MissingEvaluationEvidence,
    TooManyRequirements,
}

impl fmt::Display for DomainValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptySelection => "domain selection must not be empty",
            Self::InvalidLanguage => "language is not an analyzable programming language",
            Self::InvalidIdentifier => "identifier is invalid",
            Self::InvalidVersion => "version is invalid",
            Self::InvalidVersionRequirement => "version requirement is invalid",
            Self::InvalidAuthoredPath => "authored path is invalid",
            Self::MissingEvaluationEvidence => {
                "supported evaluation requires provider and capability observations"
            }
            Self::TooManyRequirements => "too many requirements",
        })
    }
}

impl std::error::Error for DomainValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainCompositionError {
    DisjointIntersection,
    CrossDomainConjunction,
    HeterogeneousIntersection,
    MissingDiscriminator,
    MissingProvenance,
    NestedHeterogeneousUnion,
    HeterogeneousNeedsAlternatives,
    InvalidOperatorInputs,
    OperatorIsNotCrossDomain,
    OperatorInputMismatch,
    OperatorNeedsHeterogeneousInputs,
    Validation(DomainValidationError),
}

impl fmt::Display for DomainCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DisjointIntersection => "domain intersection is disjoint",
            Self::CrossDomainConjunction => {
                "code and configuration domains require an explicit cross-domain operator"
            }
            Self::HeterogeneousIntersection => "heterogeneous rows cannot be intersected",
            Self::MissingDiscriminator => "heterogeneous union requires a domain discriminator",
            Self::MissingProvenance => "heterogeneous union requires retained provenance",
            Self::NestedHeterogeneousUnion => "nested heterogeneous unions are not supported",
            Self::HeterogeneousNeedsAlternatives => {
                "heterogeneous rows require at least two distinct alternatives"
            }
            Self::InvalidOperatorInputs => "cross-domain operator input count is invalid",
            Self::OperatorIsNotCrossDomain => {
                "cross-domain operator must accept code and configuration inputs"
            }
            Self::OperatorInputMismatch => "operator inputs do not match its typed declaration",
            Self::OperatorNeedsHeterogeneousInputs => {
                "cross-domain operator requires unlike input domains"
            }
            Self::Validation(error) => return error.fmt(formatter),
        })
    }
}

impl std::error::Error for DomainCompositionError {}

fn validate_identifier(value: &str) -> Result<(), DomainValidationError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(DomainValidationError::InvalidIdentifier);
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(DomainValidationError::InvalidIdentifier);
    };
    if !first.is_ascii_alphanumeric() {
        return Err(DomainValidationError::InvalidIdentifier);
    }
    if chars.any(|character| {
        !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    }) {
        return Err(DomainValidationError::InvalidIdentifier);
    }
    Ok(())
}

fn canonical_languages<I>(languages: I) -> Result<Vec<Language>, DomainValidationError>
where
    I: IntoIterator<Item = Language>,
{
    let mut languages = languages.into_iter().collect::<Vec<_>>();
    if languages.is_empty() {
        return Err(DomainValidationError::EmptySelection);
    }
    if languages.contains(&Language::None) {
        return Err(DomainValidationError::InvalidLanguage);
    }
    languages.sort_unstable();
    languages.dedup();
    if languages.len() > MAX_DOMAIN_SELECTIONS {
        return Err(DomainValidationError::TooManyRequirements);
    }
    Ok(languages)
}

fn canonical_formats<I>(formats: I) -> Result<Vec<ConfigurationFormat>, DomainValidationError>
where
    I: IntoIterator<Item = ConfigurationFormat>,
{
    let mut formats = formats.into_iter().collect::<Vec<_>>();
    if formats.is_empty() {
        return Err(DomainValidationError::EmptySelection);
    }
    formats.sort_unstable();
    formats.dedup();
    if formats.len() > MAX_DOMAIN_SELECTIONS {
        return Err(DomainValidationError::TooManyRequirements);
    }
    Ok(formats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn language_domain(language: Language) -> QueryDomain {
        QueryDomain::code([language]).expect("valid language domain")
    }

    fn format_domain(format: ConfigurationFormat) -> QueryDomain {
        QueryDomain::configuration([format]).expect("valid format domain")
    }

    fn evidence(domain: QueryDomain) -> EvaluationEvidence {
        EvaluationEvidence::new(
            "query.steps[0]",
            domain,
            ProviderId::new("provider").expect("provider"),
            Version::new("1.2.3").expect("provider version"),
            CapabilityId::new("query.code").expect("capability"),
            Version::new("2.0.0").expect("capability version"),
            [PackActivationEvidence::new(
                PackIdentity::semantic(PackId::new("stdlib").expect("pack")),
                ProviderId::new("pack-provider").expect("pack provider"),
                Version::new("4").expect("pack version"),
                PackActivationState::Activated,
            )],
        )
        .expect("evidence")
    }

    #[test]
    fn configuration_registry_round_trips_canonical_labels_and_aliases() {
        for format in ConfigurationFormat::ALL {
            assert_eq!(
                ConfigurationFormat::from_label(format.label()),
                Some(format)
            );
            assert_eq!(
                ConfigurationFormat::from_discovery_extension(format.label()),
                Some(format)
            );
            for alias in format.aliases() {
                assert_eq!(ConfigurationFormat::from_label(alias), Some(format));
            }
            for extension in format.discovery_extensions() {
                assert_eq!(
                    ConfigurationFormat::from_discovery_extension(extension),
                    Some(format)
                );
            }
            let json = serde_json::to_string(&format).expect("serialize format");
            let decoded: ConfigurationFormat = serde_json::from_str(&json).expect("decode format");
            assert_eq!(decoded, format);
        }
    }

    #[test]
    fn language_and_configuration_domains_are_distinct_and_intersect_conjunctively() {
        let left = QueryDomain::code([Language::Rust, Language::Python]).expect("left");
        let right = QueryDomain::code([Language::Rust]).expect("right");
        assert_eq!(
            left.intersect(&right).expect("intersection").languages(),
            Some([Language::Rust].as_slice())
        );
        assert_eq!(
            left.intersect(&format_domain(ConfigurationFormat::Json)),
            Err(DomainCompositionError::CrossDomainConjunction)
        );
        assert_eq!(
            left.intersect(&QueryDomain::code([Language::Go]).expect("go")),
            Err(DomainCompositionError::DisjointIntersection)
        );
    }

    #[test]
    fn pack_union_preserves_mandatory_strength() {
        let identity = PackIdentity::policy(PackId::new("security").expect("pack"));
        let optional = PackRequirementSet::new([PackRequirement::optional(identity.clone())])
            .expect("optional");
        let mandatory =
            PackRequirementSet::new([PackRequirement::mandatory(identity)]).expect("mandatory");
        let union = optional.union(&mandatory).expect("union");
        assert_eq!(union.as_slice().len(), 1);
        assert_eq!(
            union.as_slice()[0].strength(),
            RequirementStrength::Mandatory
        );
    }

    #[test]
    fn heterogeneous_union_requires_discriminator_and_provenance() {
        let code = RowDomain::code([Language::Rust]).expect("code");
        let config = RowDomain::configuration([ConfigurationFormat::Yaml]).expect("config");
        assert_eq!(
            code.union(&config, None, true),
            Err(DomainCompositionError::MissingDiscriminator)
        );
        assert_eq!(
            code.union(&config, Some(DomainDiscriminator::Domain), false),
            Err(DomainCompositionError::MissingProvenance)
        );
        let union = code
            .union(&config, Some(DomainDiscriminator::Domain), true)
            .expect("heterogeneous union");
        assert!(matches!(union, RowDomain::Heterogeneous(_)));
    }

    #[test]
    fn explicit_cross_domain_operator_is_typed() {
        let code = language_domain(Language::Rust);
        let config = format_domain(ConfigurationFormat::Toml);
        let row = RowDomain::heterogeneous(
            [code.clone(), config.clone()],
            DomainDiscriminator::Domain,
            true,
        )
        .expect("row");
        let operator = CrossDomainOperator::new(
            OperatorId::new("join.config-code").expect("operator"),
            [code.clone(), config.clone()],
            row,
        )
        .expect("operator");
        let empty_capabilities = CapabilityRequirementSet::default();
        let empty_packs = PackRequirementSet::default();
        let code_requirement = QueryRequirement::new(
            code,
            RowDomain::code([Language::Rust]).expect("row"),
            empty_capabilities.clone(),
            empty_packs.clone(),
        );
        let config_requirement = QueryRequirement::new(
            config,
            RowDomain::configuration([ConfigurationFormat::Toml]).expect("row"),
            empty_capabilities,
            empty_packs,
        );
        assert!(code_requirement.conjoin(&config_requirement).is_err());
        assert!(
            code_requirement
                .through_cross_domain_operator(&config_requirement, &operator)
                .is_ok()
        );
    }

    #[test]
    fn all_evaluation_outcomes_retain_provenance() {
        let evidence = evidence(language_domain(Language::Rust));
        let supported =
            CapabilityEvaluation::supported(evidence.clone()).expect("supported evidence");
        let unsupported = CapabilityEvaluation::unsupported(
            evidence.clone(),
            UnsupportedReason::CapabilityUnavailable,
        );
        let incomplete = CapabilityEvaluation::incomplete(
            evidence.clone(),
            IncompleteReason::CapabilityCoverageIncomplete,
        );
        let invalid =
            CapabilityEvaluation::invalid(evidence, InvalidReason::ContradictoryDomainRequirements);
        for outcome in [supported, unsupported, incomplete, invalid] {
            assert_eq!(outcome.evidence().authored_path(), "query.steps[0]");
            assert_eq!(
                outcome.evidence().provider().expect("provider").as_str(),
                "provider"
            );
            assert_eq!(
                outcome
                    .evidence()
                    .provider_version()
                    .expect("provider version")
                    .as_str(),
                "1.2.3"
            );
            assert_eq!(
                outcome
                    .evidence()
                    .capability()
                    .expect("capability")
                    .as_str(),
                "query.code"
            );
            assert_eq!(
                outcome
                    .evidence()
                    .capability_version()
                    .expect("capability version")
                    .as_str(),
                "2.0.0"
            );
            assert_eq!(outcome.evidence().pack_activation().len(), 1);
        }
    }
}
