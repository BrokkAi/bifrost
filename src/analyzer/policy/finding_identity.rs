//! Stable, domain-separated public finding identity primitives.

use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::analyzer::semantic::WorkspaceRelativePath;

use super::definition::{PolicyAnalysisType, PolicyId};
use super::retained::{RetainedSize, retained_extra};

const POLICY_FINDING_DOMAIN: &[u8] = b"bifrost-policy-finding/v1";
const POLICY_VULNERABILITY_DOMAIN: &[u8] = b"bifrost-policy-vulnerability/v1";
const MAX_ADAPTER_NAMESPACE_BYTES: usize = 128;
const MAX_OPAQUE_ID_BYTES: usize = 256;
const MAX_SEMANTIC_KEY_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingIdentityStability {
    Strong,
    Weak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchResultDomain {
    StructuralMatch,
    Declaration,
    ReferenceSite,
    CallSite,
    ExpressionSite,
    File,
}

impl MatchResultDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StructuralMatch => "structural_match",
            Self::Declaration => "declaration",
            Self::ReferenceSite => "reference_site",
            Self::CallSite => "call_site",
            Self::ExpressionSite => "expression_site",
            Self::File => "file",
        }
    }

    pub const fn is_span_bearing(self) -> bool {
        !matches!(self, Self::File)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StableIdentityDerivation {
    AnalyzerDeclarationId,
    CanonicalAstIdentity,
    CatalogEntry,
    ProtocolSubject,
    ProtocolViolationSite,
}

impl StableIdentityDerivation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnalyzerDeclarationId => "analyzer_declaration_id",
            Self::CanonicalAstIdentity => "canonical_ast_identity",
            Self::CatalogEntry => "catalog_entry",
            Self::ProtocolSubject => "protocol_subject",
            Self::ProtocolViolationSite => "protocol_violation_site",
        }
    }
}

/// A stable semantic identity whose producer contract excludes coordinates and
/// snapshot-local handles.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct StableSemanticIdentity {
    namespace: String,
    #[serde(serialize_with = "serialize_workspace_path")]
    path: WorkspaceRelativePath,
    derivation: StableIdentityDerivation,
    semantic_key: String,
}

impl StableSemanticIdentity {
    pub fn try_new(
        namespace: impl AsRef<str>,
        path: WorkspaceRelativePath,
        derivation: StableIdentityDerivation,
        semantic_key: impl AsRef<str>,
    ) -> Result<Self, StableSemanticIdentityError> {
        Self::try_new_for_derivation(namespace, path, derivation, semantic_key)
    }

    pub(crate) fn analyzer_declaration_id(
        namespace: impl AsRef<str>,
        path: WorkspaceRelativePath,
        semantic_key: impl AsRef<str>,
    ) -> Result<Self, StableSemanticIdentityError> {
        Self::try_new_for_derivation(
            namespace,
            path,
            StableIdentityDerivation::AnalyzerDeclarationId,
            semantic_key,
        )
    }

    pub(crate) fn canonical_ast_identity(
        namespace: impl AsRef<str>,
        path: WorkspaceRelativePath,
        semantic_key: impl AsRef<str>,
    ) -> Result<Self, StableSemanticIdentityError> {
        Self::try_new_for_derivation(
            namespace,
            path,
            StableIdentityDerivation::CanonicalAstIdentity,
            semantic_key,
        )
    }

    /// Construct a stable identity for a catalog entry.
    pub fn catalog_entry(
        namespace: impl AsRef<str>,
        path: WorkspaceRelativePath,
        semantic_key: impl AsRef<str>,
    ) -> Result<Self, StableSemanticIdentityError> {
        Self::try_new_for_derivation(
            namespace,
            path,
            StableIdentityDerivation::CatalogEntry,
            semantic_key,
        )
    }

    /// Construct a stable identity for a compiled protocol subject.
    pub fn protocol_subject(
        namespace: impl AsRef<str>,
        path: WorkspaceRelativePath,
        semantic_key: impl AsRef<str>,
    ) -> Result<Self, StableSemanticIdentityError> {
        Self::try_new_for_derivation(
            namespace,
            path,
            StableIdentityDerivation::ProtocolSubject,
            semantic_key,
        )
    }

    /// Construct a stable identity for a compiled protocol violation site.
    pub fn protocol_violation_site(
        namespace: impl AsRef<str>,
        path: WorkspaceRelativePath,
        semantic_key: impl AsRef<str>,
    ) -> Result<Self, StableSemanticIdentityError> {
        Self::try_new_for_derivation(
            namespace,
            path,
            StableIdentityDerivation::ProtocolViolationSite,
            semantic_key,
        )
    }

    fn try_new_for_derivation(
        namespace: impl AsRef<str>,
        path: WorkspaceRelativePath,
        derivation: StableIdentityDerivation,
        semantic_key: impl AsRef<str>,
    ) -> Result<Self, StableSemanticIdentityError> {
        let namespace = namespace.as_ref();
        validate_namespace(namespace).map_err(StableSemanticIdentityError::Namespace)?;
        let semantic_key = semantic_key.as_ref();
        validate_semantic_key(semantic_key)?;
        validate_derivation_shape(derivation, semantic_key)?;
        Ok(Self {
            namespace: namespace.to_string().into_boxed_str().into_string(),
            path,
            derivation,
            semantic_key: semantic_key.to_string().into_boxed_str().into_string(),
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn derivation(&self) -> StableIdentityDerivation {
        self.derivation
    }

    pub fn semantic_key(&self) -> &str {
        &self.semantic_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StableSemanticIdentityError {
    Namespace(AdapterNamespaceError),
    EmptySemanticKey,
    SemanticKeyTooLong {
        max_bytes: usize,
    },
    UnsafeSemanticKeyCharacter,
    AbsoluteOrNativePathPrefix,
    CoordinateOrOffsetEncoding,
    DenseOrRunLocalHandle,
    InvalidDerivationShape {
        derivation: StableIdentityDerivation,
    },
}

impl fmt::Display for StableSemanticIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Namespace(error) => write!(formatter, "invalid semantic namespace: {error}"),
            Self::EmptySemanticKey => formatter.write_str("semantic key must not be empty"),
            Self::SemanticKeyTooLong { max_bytes } => {
                write!(formatter, "semantic key must be at most {max_bytes} bytes")
            }
            Self::UnsafeSemanticKeyCharacter => {
                formatter.write_str("semantic key must not contain control or bidi characters")
            }
            Self::AbsoluteOrNativePathPrefix => formatter.write_str(
                "semantic key must not contain an absolute or native filesystem path prefix",
            ),
            Self::CoordinateOrOffsetEncoding => formatter
                .write_str("semantic key must not encode source coordinates or byte offsets"),
            Self::DenseOrRunLocalHandle => formatter
                .write_str("semantic key must not be a dense, snapshot-local, or run-local handle"),
            Self::InvalidDerivationShape { derivation } => write!(
                formatter,
                "semantic key does not satisfy the {} producer contract",
                derivation.as_str()
            ),
        }
    }
}

impl std::error::Error for StableSemanticIdentityError {}

fn validate_semantic_key(value: &str) -> Result<(), StableSemanticIdentityError> {
    if value.is_empty() {
        return Err(StableSemanticIdentityError::EmptySemanticKey);
    }
    if value.len() > MAX_SEMANTIC_KEY_BYTES {
        return Err(StableSemanticIdentityError::SemanticKeyTooLong {
            max_bytes: MAX_SEMANTIC_KEY_BYTES,
        });
    }
    if value.chars().any(is_unsafe_identifier_character) {
        return Err(StableSemanticIdentityError::UnsafeSemanticKeyCharacter);
    }
    if has_absolute_or_native_path_prefix(value) {
        return Err(StableSemanticIdentityError::AbsoluteOrNativePathPrefix);
    }
    if has_coordinate_or_offset_encoding(value) {
        return Err(StableSemanticIdentityError::CoordinateOrOffsetEncoding);
    }
    if has_dense_or_run_local_handle(value) {
        return Err(StableSemanticIdentityError::DenseOrRunLocalHandle);
    }
    Ok(())
}

fn validate_derivation_shape(
    derivation: StableIdentityDerivation,
    semantic_key: &str,
) -> Result<(), StableSemanticIdentityError> {
    if derivation == StableIdentityDerivation::CanonicalAstIdentity {
        return validate_canonical_ast_key(semantic_key, derivation);
    }
    let valid = match derivation {
        StableIdentityDerivation::AnalyzerDeclarationId => {
            let Some((kind, declaration)) = semantic_key.split_once(':') else {
                return Err(StableSemanticIdentityError::InvalidDerivationShape { derivation });
            };
            !kind.is_empty()
                && kind.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
                && !declaration.is_empty()
                && !declaration.bytes().all(|byte| byte.is_ascii_digit())
        }
        StableIdentityDerivation::CanonicalAstIdentity => unreachable!("handled above"),
        StableIdentityDerivation::CatalogEntry
        | StableIdentityDerivation::ProtocolSubject
        | StableIdentityDerivation::ProtocolViolationSite => true,
    };
    if !valid {
        return Err(StableSemanticIdentityError::InvalidDerivationShape { derivation });
    }
    Ok(())
}

fn validate_canonical_ast_key(
    value: &str,
    derivation: StableIdentityDerivation,
) -> Result<(), StableSemanticIdentityError> {
    let segments = serde_json::from_str::<Vec<(String, Option<String>)>>(value)
        .map_err(|_| StableSemanticIdentityError::InvalidDerivationShape { derivation })?;
    if segments.is_empty() {
        return Err(StableSemanticIdentityError::InvalidDerivationShape { derivation });
    }
    for (kind, name) in &segments {
        if kind.is_empty()
            || !kind.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(StableSemanticIdentityError::InvalidDerivationShape { derivation });
        }
        validate_semantic_key(kind)?;
        if let Some(name) = name {
            validate_semantic_key(name)?;
        }
    }
    if !matches!(serde_json::to_string(&segments), Ok(canonical) if canonical == value) {
        return Err(StableSemanticIdentityError::InvalidDerivationShape { derivation });
    }
    Ok(())
}

fn has_absolute_or_native_path_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes
        .first()
        .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
    {
        return true;
    }
    if value.to_ascii_lowercase().contains("file://")
        || bytes
            .windows(2)
            .any(|window| matches!(window, [b':', b'/'] | [b':', b'\\'] | [b'\\', b'\\']))
    {
        return true;
    }
    bytes.windows(3).any(|window| {
        window[0].is_ascii_alphabetic() && window[1] == b':' && matches!(window[2], b'/' | b'\\')
    })
}

fn has_coordinate_or_offset_encoding(value: &str) -> bool {
    if let Some((prefix, column)) = value.rsplit_once(':')
        && is_ascii_decimal(column)
        && let Some((file, line)) = prefix.rsplit_once(':')
        && !file.is_empty()
        && is_ascii_decimal(line)
    {
        return true;
    }

    let lowercase = value.to_ascii_lowercase();
    for separator in [':', '=', '@', '#'] {
        if let Some((label, number)) = lowercase.rsplit_once(separator)
            && is_ascii_decimal(number)
            && matches!(
                label.rsplit([':', '/', '\\']).next().unwrap_or(label),
                "offset" | "byte" | "byte-offset" | "byte_offset" | "line" | "column"
            )
        {
            return true;
        }
    }
    false
}

fn has_dense_or_run_local_handle(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    if is_ascii_decimal(&lowercase) {
        return true;
    }
    let tokens = lowercase
        .split([':', '=', '@', '#', '/', '\\'])
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    for pair in tokens.windows(2) {
        let dense_label = matches!(
            pair[0],
            "node"
                | "node-id"
                | "node_id"
                | "fact"
                | "row"
                | "slot"
                | "arena"
                | "handle"
                | "dense"
                | "run"
                | "snapshot"
        );
        let run_local_label = matches!(
            pair[0],
            "run-local" | "run_local" | "snapshot-local" | "snapshot_local"
        );
        if (dense_label && is_ascii_decimal(pair[1])) || run_local_label {
            return true;
        }
    }
    false
}

fn is_ascii_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterNamespaceError {
    Empty,
    TooLong { max_bytes: usize },
    InvalidStart,
    InvalidEnd,
    InvalidCharacter { index: usize },
}

impl fmt::Display for AdapterNamespaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("namespace must not be empty"),
            Self::TooLong { max_bytes } => {
                write!(formatter, "namespace must be at most {max_bytes} bytes")
            }
            Self::InvalidStart => {
                formatter.write_str("namespace must begin with a lowercase ASCII alphanumeric")
            }
            Self::InvalidEnd => {
                formatter.write_str("namespace must end with a lowercase ASCII alphanumeric")
            }
            Self::InvalidCharacter { index } => write!(
                formatter,
                "namespace has an invalid character at byte {index}"
            ),
        }
    }
}

impl std::error::Error for AdapterNamespaceError {}

fn validate_namespace(value: &str) -> Result<(), AdapterNamespaceError> {
    if value.is_empty() {
        return Err(AdapterNamespaceError::Empty);
    }
    if value.len() > MAX_ADAPTER_NAMESPACE_BYTES {
        return Err(AdapterNamespaceError::TooLong {
            max_bytes: MAX_ADAPTER_NAMESPACE_BYTES,
        });
    }
    let bytes = value.as_bytes();
    if !is_lower_alphanumeric(bytes[0]) {
        return Err(AdapterNamespaceError::InvalidStart);
    }
    if !is_lower_alphanumeric(bytes[bytes.len() - 1]) {
        return Err(AdapterNamespaceError::InvalidEnd);
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if !(is_lower_alphanumeric(byte) || matches!(byte, b'.' | b'-' | b'_')) {
            return Err(AdapterNamespaceError::InvalidCharacter { index });
        }
    }
    Ok(())
}

const fn is_lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

const fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn is_unsafe_identifier_character(character: char) -> bool {
    character.is_control() || is_bidi_control(character)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterOpaqueIdError {
    Namespace(AdapterNamespaceError),
    EmptyValue,
    TooLong { max_bytes: usize },
    UnsafeCharacter,
}

impl fmt::Display for AdapterOpaqueIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Namespace(error) => write!(formatter, "invalid adapter namespace: {error}"),
            Self::EmptyValue => formatter.write_str("opaque identifier value must not be empty"),
            Self::TooLong { max_bytes } => {
                write!(
                    formatter,
                    "opaque identifier must be at most {max_bytes} bytes"
                )
            }
            Self::UnsafeCharacter => {
                formatter.write_str("opaque identifier must not contain control or bidi characters")
            }
        }
    }
}

impl std::error::Error for AdapterOpaqueIdError {}

fn namespaced_opaque_id(
    namespace: impl AsRef<str>,
    value: impl AsRef<str>,
) -> Result<Box<str>, AdapterOpaqueIdError> {
    let namespace = namespace.as_ref();
    validate_namespace(namespace).map_err(AdapterOpaqueIdError::Namespace)?;
    let value = value.as_ref();
    if value.is_empty() {
        return Err(AdapterOpaqueIdError::EmptyValue);
    }
    if value.chars().any(is_unsafe_identifier_character) {
        return Err(AdapterOpaqueIdError::UnsafeCharacter);
    }
    let length = namespace
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or(AdapterOpaqueIdError::TooLong {
            max_bytes: MAX_OPAQUE_ID_BYTES,
        })?;
    if length > MAX_OPAQUE_ID_BYTES {
        return Err(AdapterOpaqueIdError::TooLong {
            max_bytes: MAX_OPAQUE_ID_BYTES,
        });
    }
    Ok(format!("{namespace}:{value}").into_boxed_str())
}

macro_rules! define_adapter_opaque_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Box<str>);

        impl $name {
            pub fn try_new(
                namespace: impl AsRef<str>,
                value: impl AsRef<str>,
            ) -> Result<Self, AdapterOpaqueIdError> {
                namespaced_opaque_id(namespace, value).map(Self)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl RetainedSize for $name {
            fn retained_size(&self) -> usize {
                std::mem::size_of::<Self>().saturating_add(self.0.len())
            }
        }
    };
}

define_adapter_opaque_id!(OpaqueFindingKey);
define_adapter_opaque_id!(EvidenceRef);
define_adapter_opaque_id!(WitnessId);
define_adapter_opaque_id!(AnalysisFindingId);
define_adapter_opaque_id!(AnalysisEventRef);
define_adapter_opaque_id!(AnalysisSubjectRef);
define_adapter_opaque_id!(SourceScenarioId);
define_adapter_opaque_id!(TypestateScenarioId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceSliceHash([u8; 32]);

impl SourceSliceHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SourceSliceHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lower_hex(&self.0, formatter)
    }
}

impl Serialize for SourceSliceHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl RetainedSize for SourceSliceHash {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchStrongAnchor {
    result_domain: MatchResultDomain,
    path: WorkspaceRelativePath,
    semantic_owner: Option<StableSemanticIdentity>,
    selected_source_sha256: Option<SourceSliceHash>,
    occurrence_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchWeakAnchor {
    result_domain: MatchResultDomain,
    path: WorkspaceRelativePath,
    typed_key: OpaqueFindingKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchFindingAnchor {
    Strong(MatchStrongAnchor),
    Weak(MatchWeakAnchor),
}

impl MatchFindingAnchor {
    pub fn strong(
        result_domain: MatchResultDomain,
        path: WorkspaceRelativePath,
        semantic_owner: Option<StableSemanticIdentity>,
        selected_source_sha256: Option<SourceSliceHash>,
        occurrence_ordinal: u32,
    ) -> Result<Self, MatchFindingAnchorError> {
        if semantic_owner
            .as_ref()
            .is_some_and(|owner| owner.path() != &path)
        {
            return Err(MatchFindingAnchorError::SemanticOwnerPathMismatch);
        }
        if result_domain.is_span_bearing() {
            if selected_source_sha256.is_none() {
                return Err(MatchFindingAnchorError::MissingSelectedSourceHash);
            }
        } else if semantic_owner.is_some()
            || selected_source_sha256.is_some()
            || occurrence_ordinal != 0
        {
            return Err(MatchFindingAnchorError::FileAnchorMustUseOnlyPath);
        }
        Ok(Self::Strong(MatchStrongAnchor {
            result_domain,
            path,
            semantic_owner,
            selected_source_sha256,
            occurrence_ordinal,
        }))
    }

    pub fn weak(
        result_domain: MatchResultDomain,
        path: WorkspaceRelativePath,
        typed_key: OpaqueFindingKey,
    ) -> Self {
        Self::Weak(MatchWeakAnchor {
            result_domain,
            path,
            typed_key,
        })
    }

    pub const fn stability(&self) -> FindingIdentityStability {
        match self {
            Self::Strong(_) => FindingIdentityStability::Strong,
            Self::Weak(_) => FindingIdentityStability::Weak,
        }
    }

    pub const fn result_domain(&self) -> MatchResultDomain {
        match self {
            Self::Strong(anchor) => anchor.result_domain,
            Self::Weak(anchor) => anchor.result_domain,
        }
    }

    pub const fn path(&self) -> &WorkspaceRelativePath {
        match self {
            Self::Strong(anchor) => &anchor.path,
            Self::Weak(anchor) => &anchor.path,
        }
    }
}

impl RetainedSize for StableSemanticIdentity {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.namespace.capacity())
            .saturating_add(self.path.as_str().len())
            .saturating_add(self.semantic_key.capacity())
    }
}

impl RetainedSize for MatchStrongAnchor {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.path.as_str().len())
            .saturating_add(self.semantic_owner.as_ref().map_or(0, retained_extra))
    }
}

impl RetainedSize for MatchWeakAnchor {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.path.as_str().len())
            .saturating_add(retained_extra(&self.typed_key))
    }
}

impl RetainedSize for MatchFindingAnchor {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::Strong(anchor) => retained_extra(anchor),
            Self::Weak(anchor) => retained_extra(anchor),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchFindingAnchorError {
    MissingSelectedSourceHash,
    FileAnchorMustUseOnlyPath,
    SemanticOwnerPathMismatch,
}

impl fmt::Display for MatchFindingAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSelectedSourceHash => formatter
                .write_str("a span-bearing strong match anchor requires selected source bytes"),
            Self::FileAnchorMustUseOnlyPath => formatter.write_str(
                "a strong file anchor is identified only by its normalized workspace path",
            ),
            Self::SemanticOwnerPathMismatch => formatter
                .write_str("a strong match anchor semantic owner must belong to the anchor path"),
        }
    }
}

impl std::error::Error for MatchFindingAnchorError {}

impl Serialize for MatchFindingAnchor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Strong(anchor) => {
                let mut state = serializer.serialize_struct("MatchFindingAnchor", 6)?;
                state.serialize_field("type", "strong")?;
                state.serialize_field("result_domain", &anchor.result_domain)?;
                state.serialize_field("path", anchor.path.as_str())?;
                state.serialize_field("semantic_owner", &anchor.semantic_owner)?;
                state.serialize_field("selected_source_sha256", &anchor.selected_source_sha256)?;
                state.serialize_field("occurrence_ordinal", &anchor.occurrence_ordinal)?;
                state.end()
            }
            Self::Weak(anchor) => {
                let mut state = serializer.serialize_struct("MatchFindingAnchor", 4)?;
                state.serialize_field("type", "weak")?;
                state.serialize_field("result_domain", &anchor.result_domain)?;
                state.serialize_field("path", anchor.path.as_str())?;
                state.serialize_field("typed_key", &anchor.typed_key)?;
                state.end()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyFindingId([u8; 32]);

impl PolicyFindingId {
    pub fn from_match_anchor(policy_id: &PolicyId, anchor: &MatchFindingAnchor) -> Self {
        let mut hasher = Sha256::new();
        update_length_prefixed(&mut hasher, POLICY_FINDING_DOMAIN);
        update_analysis_kind(&mut hasher, PolicyAnalysisType::Match);
        update_length_prefixed(&mut hasher, policy_id.as_str().as_bytes());
        match anchor {
            MatchFindingAnchor::Strong(anchor) => {
                update_length_prefixed(&mut hasher, b"strong");
                update_length_prefixed(&mut hasher, anchor.result_domain.as_str().as_bytes());
                update_length_prefixed(&mut hasher, anchor.path.as_str().as_bytes());
                if let Some(owner) = &anchor.semantic_owner {
                    update_length_prefixed(&mut hasher, b"owner");
                    update_length_prefixed(&mut hasher, owner.namespace.as_bytes());
                    update_length_prefixed(&mut hasher, owner.path.as_str().as_bytes());
                    update_length_prefixed(&mut hasher, owner.derivation.as_str().as_bytes());
                    update_length_prefixed(&mut hasher, owner.semantic_key.as_bytes());
                } else {
                    update_length_prefixed(&mut hasher, b"no-owner");
                }
                if let Some(source_hash) = anchor.selected_source_sha256 {
                    update_length_prefixed(&mut hasher, b"source-slice");
                    update_length_prefixed(&mut hasher, source_hash.as_bytes());
                } else {
                    update_length_prefixed(&mut hasher, b"no-source-slice");
                }
                update_length_prefixed(&mut hasher, &anchor.occurrence_ordinal.to_be_bytes());
            }
            MatchFindingAnchor::Weak(anchor) => {
                update_length_prefixed(&mut hasher, b"weak");
                update_length_prefixed(&mut hasher, anchor.result_domain.as_str().as_bytes());
                update_length_prefixed(&mut hasher, anchor.path.as_str().as_bytes());
                update_length_prefixed(&mut hasher, anchor.typed_key.as_str().as_bytes());
            }
        }
        Self(hasher.finalize().into())
    }

    pub fn from_taint_anchor(
        policy_id: &PolicyId,
        anchor: &super::future_evidence::TaintFindingAnchor,
    ) -> Self {
        Self(super::future_evidence::taint_policy_finding_digest(
            policy_id, anchor,
        ))
    }

    pub fn from_typestate_anchor(
        policy_id: &PolicyId,
        anchor: &super::future_evidence::TypestateFindingAnchor,
    ) -> Self {
        Self(super::future_evidence::typestate_policy_finding_digest(
            policy_id, anchor,
        ))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn match_vulnerability_digest(anchor: &MatchFindingAnchor) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_length_prefixed(&mut hasher, POLICY_VULNERABILITY_DOMAIN);
    update_analysis_kind(&mut hasher, PolicyAnalysisType::Match);
    match anchor {
        MatchFindingAnchor::Strong(anchor) => {
            update_length_prefixed(&mut hasher, b"strong");
            update_length_prefixed(&mut hasher, anchor.result_domain.as_str().as_bytes());
            update_length_prefixed(&mut hasher, anchor.path.as_str().as_bytes());
            if let Some(owner) = &anchor.semantic_owner {
                update_length_prefixed(&mut hasher, b"owner");
                update_length_prefixed(&mut hasher, owner.namespace.as_bytes());
                update_length_prefixed(&mut hasher, owner.path.as_str().as_bytes());
                update_length_prefixed(&mut hasher, owner.derivation.as_str().as_bytes());
                update_length_prefixed(&mut hasher, owner.semantic_key.as_bytes());
            } else {
                update_length_prefixed(&mut hasher, b"no-owner");
            }
            if let Some(source_hash) = anchor.selected_source_sha256 {
                update_length_prefixed(&mut hasher, b"source-slice");
                update_length_prefixed(&mut hasher, source_hash.as_bytes());
            } else {
                update_length_prefixed(&mut hasher, b"no-source-slice");
            }
            update_length_prefixed(&mut hasher, &anchor.occurrence_ordinal.to_be_bytes());
        }
        MatchFindingAnchor::Weak(anchor) => {
            update_length_prefixed(&mut hasher, b"weak");
            update_length_prefixed(&mut hasher, anchor.result_domain.as_str().as_bytes());
            update_length_prefixed(&mut hasher, anchor.path.as_str().as_bytes());
            update_length_prefixed(&mut hasher, anchor.typed_key.as_str().as_bytes());
        }
    }
    hasher.finalize().into()
}

impl fmt::Display for PolicyFindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lower_hex(&self.0, formatter)
    }
}

impl Serialize for PolicyFindingId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl RetainedSize for PolicyFindingId {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

fn update_analysis_kind(hasher: &mut Sha256, analysis_type: PolicyAnalysisType) {
    let value = match analysis_type {
        PolicyAnalysisType::Match => b"match".as_slice(),
        PolicyAnalysisType::Taint => b"taint".as_slice(),
        PolicyAnalysisType::Typestate => b"typestate".as_slice(),
    };
    update_length_prefixed(hasher, value);
}

fn serialize_workspace_path<S>(
    path: &WorkspaceRelativePath,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(path.as_str())
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("usize fits in u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn write_lower_hex(bytes: &[u8; 32], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn path() -> WorkspaceRelativePath {
        WorkspaceRelativePath::new("src/app.rs").unwrap()
    }

    #[test]
    fn stable_semantic_identity_accepts_producer_contract_keys() {
        let identity = StableSemanticIdentity::try_new(
            "rust",
            path(),
            StableIdentityDerivation::AnalyzerDeclarationId,
            "function:crate::Service::run(str)",
        )
        .unwrap();
        assert_eq!(identity.semantic_key(), "function:crate::Service::run(str)");

        let canonical = StableSemanticIdentity::canonical_ast_identity(
            "rust",
            path(),
            r#"[["function_item","run"],["call_expression","sink"]]"#,
        )
        .unwrap();
        assert_eq!(
            canonical.derivation(),
            StableIdentityDerivation::CanonicalAstIdentity
        );
    }

    #[test]
    fn stable_semantic_identity_rejects_paths_coordinates_and_local_handles() {
        for key in [
            "/abs/path.rs",
            r"C:\\repo\\src\\app.rs",
            r"\\server\share\app.rs",
            r"\\?\C:\repo\app.rs",
            r"\\.\device",
            "function:/Users/x",
            "catalog:file://host/x",
            r"kind:C:\repo",
        ] {
            assert_eq!(
                StableSemanticIdentity::catalog_entry("catalog", path(), key).unwrap_err(),
                StableSemanticIdentityError::AbsoluteOrNativePathPrefix,
                "key: {key}"
            );
        }

        for key in ["src/app.rs:12:34", "offset:42", "byte_offset=9"] {
            assert_eq!(
                StableSemanticIdentity::catalog_entry("catalog", path(), key).unwrap_err(),
                StableSemanticIdentityError::CoordinateOrOffsetEncoding,
                "key: {key}"
            );
        }

        for key in [
            "42",
            "node:42",
            "node_id=42",
            "arena#7",
            "run-local:abc",
            "snapshot@19",
            "adapter:node:42",
        ] {
            assert_eq!(
                StableSemanticIdentity::catalog_entry("catalog", path(), key).unwrap_err(),
                StableSemanticIdentityError::DenseOrRunLocalHandle,
                "key: {key}"
            );
        }

        for (key, expected) in [
            (
                r#"[["node","42"]]"#,
                StableSemanticIdentityError::DenseOrRunLocalHandle,
            ),
            (
                r#"[["function","/Users/x"]]"#,
                StableSemanticIdentityError::AbsoluteOrNativePathPrefix,
            ),
            (
                r#"[["call","src/app.rs:12:34"]]"#,
                StableSemanticIdentityError::CoordinateOrOffsetEncoding,
            ),
        ] {
            assert_eq!(
                StableSemanticIdentity::canonical_ast_identity("rust", path(), key).unwrap_err(),
                expected,
                "key: {key}"
            );
        }
    }

    #[test]
    fn strong_anchor_requires_bytes_and_file_anchor_is_path_only() {
        assert_eq!(
            MatchFindingAnchor::strong(MatchResultDomain::CallSite, path(), None, None, 0,)
                .unwrap_err(),
            MatchFindingAnchorError::MissingSelectedSourceHash
        );
        assert_eq!(
            MatchFindingAnchor::strong(
                MatchResultDomain::File,
                path(),
                None,
                Some(SourceSliceHash::from_bytes([1; 32])),
                0,
            )
            .unwrap_err(),
            MatchFindingAnchorError::FileAnchorMustUseOnlyPath
        );
        MatchFindingAnchor::strong(MatchResultDomain::File, path(), None, None, 0).unwrap();

        let cross_file_owner = StableSemanticIdentity::analyzer_declaration_id(
            "rust",
            WorkspaceRelativePath::new("src/other.rs").unwrap(),
            "function:crate::Other::run",
        )
        .unwrap();
        assert_eq!(
            MatchFindingAnchor::strong(
                MatchResultDomain::CallSite,
                path(),
                Some(cross_file_owner),
                Some(SourceSliceHash::from_bytes([1; 32])),
                0,
            )
            .unwrap_err(),
            MatchFindingAnchorError::SemanticOwnerPathMismatch
        );
    }

    #[test]
    fn finding_id_uses_semantic_anchor_not_coordinates_or_presentation() {
        let policy_id = PolicyId::new("security.dynamic-eval").unwrap();
        let anchor = MatchFindingAnchor::strong(
            MatchResultDomain::StructuralMatch,
            path(),
            None,
            Some(SourceSliceHash::from_bytes([7; 32])),
            0,
        )
        .unwrap();
        let same_anchor = anchor.clone();
        let changed_slice = MatchFindingAnchor::strong(
            MatchResultDomain::StructuralMatch,
            path(),
            None,
            Some(SourceSliceHash::from_bytes([8; 32])),
            0,
        )
        .unwrap();
        let changed_ordinal = MatchFindingAnchor::strong(
            MatchResultDomain::StructuralMatch,
            path(),
            None,
            Some(SourceSliceHash::from_bytes([7; 32])),
            1,
        )
        .unwrap();

        let id = PolicyFindingId::from_match_anchor(&policy_id, &anchor);
        assert_eq!(
            id,
            PolicyFindingId::from_match_anchor(&policy_id, &same_anchor)
        );
        assert_ne!(
            id,
            PolicyFindingId::from_match_anchor(&policy_id, &changed_slice)
        );
        assert_ne!(
            id,
            PolicyFindingId::from_match_anchor(&policy_id, &changed_ordinal)
        );
        assert_eq!(id.to_string().len(), 64);
        assert!(id.to_string().bytes().all(|byte| byte.is_ascii_hexdigit()));

        let file_anchor =
            MatchFindingAnchor::strong(MatchResultDomain::File, path(), None, None, 0).unwrap();
        assert_eq!(
            PolicyFindingId::from_match_anchor(&policy_id, &file_anchor).to_string(),
            "ecc560daa8640be23c53c93ad906a27bf978dcf6e0b13948d0dbbace13a1e47b"
        );
    }

    #[test]
    fn weak_anchor_is_namespaced_and_serializes_without_fake_stable_fields() {
        let key = OpaqueFindingKey::try_new("test-adapter", "snapshot-key-7").unwrap();
        let anchor = MatchFindingAnchor::weak(MatchResultDomain::CallSite, path(), key);
        assert_eq!(anchor.stability(), FindingIdentityStability::Weak);
        assert_eq!(
            serde_json::to_value(anchor).unwrap(),
            json!({
                "type": "weak",
                "result_domain": "call_site",
                "path": "src/app.rs",
                "typed_key": "test-adapter:snapshot-key-7",
            })
        );
    }

    #[test]
    fn opaque_ids_are_bounded_and_reject_unsafe_text() {
        assert!(OpaqueFindingKey::try_new("Adapter", "key").is_err());
        assert!(OpaqueFindingKey::try_new("adapter", "").is_err());
        assert!(OpaqueFindingKey::try_new("adapter", "bad\nkey").is_err());
        assert!(OpaqueFindingKey::try_new("adapter", "x".repeat(256)).is_err());
        assert_eq!(
            EvidenceRef::try_new("query", "proof-1").unwrap().as_str(),
            "query:proof-1"
        );
    }
}
