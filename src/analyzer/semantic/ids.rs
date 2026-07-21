//! Durable semantic identities and artifact-local dense IDs.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

pub use crate::analyzer::LanguageDialect as SemanticLanguage;

/// A failed conversion from a collection index to a fixed-width dense ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenseIdOverflow {
    id_type: &'static str,
    index: usize,
}

impl DenseIdOverflow {
    pub const fn id_type(self) -> &'static str {
        self.id_type
    }

    pub const fn index(self) -> usize {
        self.index
    }
}

impl fmt::Display for DenseIdOverflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} index {} does not fit in a u32",
            self.id_type, self.index
        )
    }
}

impl std::error::Error for DenseIdOverflow {}

macro_rules! dense_ids {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(u32);

            impl $name {
                pub const fn new(raw: u32) -> Self {
                    Self(raw)
                }

                pub const fn get(self) -> u32 {
                    self.0
                }

                pub const fn index(self) -> usize {
                    self.0 as usize
                }

                pub fn try_from_index(index: usize) -> Result<Self, DenseIdOverflow> {
                    u32::try_from(index).map(Self).map_err(|_| DenseIdOverflow {
                        id_type: stringify!($name),
                        index,
                    })
                }
            }

            impl TryFrom<usize> for $name {
                type Error = DenseIdOverflow;

                fn try_from(index: usize) -> Result<Self, Self::Error> {
                    Self::try_from_index(index)
                }
            }

            impl From<$name> for u32 {
                fn from(id: $name) -> Self {
                    id.get()
                }
            }

            impl From<$name> for usize {
                fn from(id: $name) -> Self {
                    id.index()
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    self.0.fmt(formatter)
                }
            }
        )+
    };
}

dense_ids! {
    ProcedureId,
    BlockId,
    ProgramPointId,
    ControlEdgeId,
    ValueId,
    AllocationId,
    CallSiteId,
    MemoryLocationId,
    CaptureId,
    SourceMappingId,
    EvidenceId,
    SemanticGapId,
}

/// One stable SHA-256 digest. Domain-specific wrappers prevent accidental key mixing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableDigest([u8; 32]);

impl StableDigest {
    pub const fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        let digest = Sha256::digest(bytes.as_ref());
        let mut value = [0_u8; 32];
        value.copy_from_slice(&digest);
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for StableDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

macro_rules! typed_digests {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(StableDigest);

            impl $name {
                pub const fn from_digest(digest: StableDigest) -> Self {
                    Self(digest)
                }

                pub fn hash_bytes(bytes: impl AsRef<[u8]>) -> Self {
                    Self(StableDigest::sha256(bytes))
                }

                pub const fn digest(self) -> StableDigest {
                    self.0
                }

                pub const fn as_bytes(&self) -> &[u8; 32] {
                    self.0.as_bytes()
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    self.0.fmt(formatter)
                }
            }
        )+
    };
}

typed_digests! {
    ContentIdentity,
    OverlaySnapshotId,
    SemanticIrVersion,
    ConfigurationFingerprint,
    DependencyFingerprint,
    WorkspaceMountId,
}

impl WorkspaceMountId {
    /// Derive the mount identity used by every semantic producer for one
    /// normalized workspace root.
    pub fn from_root(root: &Path) -> Self {
        Self::hash_bytes(root.as_os_str().as_encoded_bytes())
    }
}

/// Domain separator for the language-neutral semantic IR schema fingerprint.
pub const SEMANTIC_IR_SCHEMA_DOMAIN: &[u8] = b"bifrost-language-neutral-semantic-ir";

/// Current language-neutral semantic IR schema revision.
pub const SEMANTIC_IR_SCHEMA_VERSION: u32 = 6;

impl SemanticIrVersion {
    /// The contract-owned fingerprint shared by every language adapter that
    /// emits the current semantic IR schema.
    pub fn current() -> Self {
        let mut digest = LengthDelimitedDigest::new(SEMANTIC_IR_SCHEMA_DOMAIN);
        digest.push(&SEMANTIC_IR_SCHEMA_VERSION.to_le_bytes());
        Self::from_digest(digest.finish())
    }
}

/// The version of one language adapter's execution semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdapterSemanticsVersion {
    name: Box<str>,
    fingerprint: StableDigest,
}

/// Adapter names are part of artifact identity and therefore cannot be empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyAdapterName;

impl fmt::Display for EmptyAdapterName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("adapter semantics name must not be empty")
    }
}

impl std::error::Error for EmptyAdapterName {}

impl AdapterSemanticsVersion {
    pub fn new(
        name: impl Into<String>,
        fingerprint: StableDigest,
    ) -> Result<Self, EmptyAdapterName> {
        let name = name.into();
        if name.is_empty() {
            return Err(EmptyAdapterName);
        }
        Ok(Self {
            name: name.into_boxed_str(),
            fingerprint,
        })
    }

    pub fn hash_bytes(
        name: impl Into<String>,
        semantics: impl AsRef<[u8]>,
    ) -> Result<Self, EmptyAdapterName> {
        Self::new(name, StableDigest::sha256(semantics))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn fingerprint(&self) -> StableDigest {
        self.fingerprint
    }
}

/// A portable, canonical path relative to one workspace mount.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceRelativePath(Box<str>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRelativePathError {
    Empty,
    Absolute,
    Prefix,
    ParentComponent,
    CurrentComponent,
    EmptyComponent,
    NonUtf8,
    InvalidCharacter,
    TrailingDotOrSpace,
    ReservedDeviceName,
}

impl fmt::Display for WorkspaceRelativePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "workspace-relative path must not be empty",
            Self::Absolute => "workspace-relative path must not be absolute",
            Self::Prefix => "workspace-relative path must not have a platform prefix",
            Self::ParentComponent => "workspace-relative path must not contain `..`",
            Self::CurrentComponent => "workspace-relative path must not contain `.`",
            Self::EmptyComponent => "workspace-relative path must not contain empty components",
            Self::NonUtf8 => "workspace-relative path must be valid UTF-8",
            Self::InvalidCharacter => {
                "workspace-relative path contains a character that is not portable to Windows"
            }
            Self::TrailingDotOrSpace => {
                "workspace-relative path component must not end in a dot or space"
            }
            Self::ReservedDeviceName => {
                "workspace-relative path contains a reserved Windows device name"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WorkspaceRelativePathError {}

impl WorkspaceRelativePath {
    /// Parse an already portable slash-canonical path.
    pub fn new(path: impl AsRef<str>) -> Result<Self, WorkspaceRelativePathError> {
        let path = path.as_ref();
        if path.is_empty() {
            return Err(WorkspaceRelativePathError::Empty);
        }
        if path.starts_with('/') {
            return Err(WorkspaceRelativePathError::Absolute);
        }
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(WorkspaceRelativePathError::Prefix);
        }

        let mut normalized = String::with_capacity(path.len());
        for component in path.split('/') {
            push_portable_component(&mut normalized, component)?;
        }
        Ok(Self(normalized.into_boxed_str()))
    }

    /// Convert a native relative path through platform-aware components, then
    /// store it in the portable slash-canonical form.
    pub fn try_from_path(path: &Path) -> Result<Self, WorkspaceRelativePathError> {
        if path.as_os_str().is_empty() {
            return Err(WorkspaceRelativePathError::Empty);
        }

        let mut normalized = String::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) => return Err(WorkspaceRelativePathError::Prefix),
                Component::RootDir => return Err(WorkspaceRelativePathError::Absolute),
                Component::ParentDir => {
                    return Err(WorkspaceRelativePathError::ParentComponent);
                }
                Component::CurDir => return Err(WorkspaceRelativePathError::CurrentComponent),
                Component::Normal(component) => {
                    let component = component
                        .to_str()
                        .ok_or(WorkspaceRelativePathError::NonUtf8)?;
                    push_portable_component(&mut normalized, component)?;
                }
            }
        }
        if normalized.is_empty() {
            return Err(WorkspaceRelativePathError::Empty);
        }
        Ok(Self(normalized.into_boxed_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_path(&self) -> &Path {
        Path::new(self.as_str())
    }
}

fn push_portable_component(
    normalized: &mut String,
    component: &str,
) -> Result<(), WorkspaceRelativePathError> {
    validate_portable_component(component)?;
    if !normalized.is_empty() {
        normalized.push('/');
    }
    normalized.push_str(component);
    Ok(())
}

fn validate_portable_component(component: &str) -> Result<(), WorkspaceRelativePathError> {
    if component.is_empty() {
        return Err(WorkspaceRelativePathError::EmptyComponent);
    }
    match component {
        "." => return Err(WorkspaceRelativePathError::CurrentComponent),
        ".." => return Err(WorkspaceRelativePathError::ParentComponent),
        _ => {}
    }

    if component.chars().any(|character| {
        character <= '\u{1f}' || matches!(character, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
    }) {
        return Err(WorkspaceRelativePathError::InvalidCharacter);
    }
    if component.ends_with('.') || component.ends_with(' ') {
        return Err(WorkspaceRelativePathError::TrailingDotOrSpace);
    }
    if is_reserved_windows_device_name(component) {
        return Err(WorkspaceRelativePathError::ReservedDeviceName);
    }
    Ok(())
}

fn is_reserved_windows_device_name(component: &str) -> bool {
    let basename = component
        .split_once('.')
        .map_or(component, |(basename, _)| basename)
        .trim_end_matches(['.', ' ']);
    let basename = basename.to_ascii_uppercase();
    if matches!(
        basename.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    ["COM", "LPT"].into_iter().any(|prefix| {
        basename.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

impl TryFrom<&Path> for WorkspaceRelativePath {
    type Error = WorkspaceRelativePathError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Self::try_from_path(path)
    }
}

impl TryFrom<PathBuf> for WorkspaceRelativePath {
    type Error = WorkspaceRelativePathError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::try_from_path(&path)
    }
}

impl AsRef<str> for WorkspaceRelativePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<Path> for WorkspaceRelativePath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl fmt::Display for WorkspaceRelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The exact disk or overlay source snapshot interpreted by an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceRevision {
    Disk {
        content: ContentIdentity,
    },
    Overlay {
        content: ContentIdentity,
        snapshot: OverlaySnapshotId,
    },
}

impl SourceRevision {
    pub const fn content(self) -> ContentIdentity {
        match self {
            Self::Disk { content } | Self::Overlay { content, .. } => content,
        }
    }

    pub const fn overlay_snapshot(self) -> Option<OverlaySnapshotId> {
        match self {
            Self::Disk { .. } => None,
            Self::Overlay { snapshot, .. } => Some(snapshot),
        }
    }
}

/// A zero-based source position. `byte_offset` is authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourcePosition {
    byte_offset: u32,
    line: u32,
    byte_column: u32,
}

impl SourcePosition {
    pub const fn new(byte_offset: u32, line: u32, byte_column: u32) -> Self {
        Self {
            byte_offset,
            line,
            byte_column,
        }
    }

    pub const fn byte_offset(self) -> u32 {
        self.byte_offset
    }

    pub const fn line(self) -> u32 {
        self.line
    }

    pub const fn byte_column(self) -> u32 {
        self.byte_column
    }
}

/// A half-open byte-authoritative source span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceSpan {
    start: SourcePosition,
    end: SourcePosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSpanError {
    ReversedBytes,
    ReversedLines,
    ReversedColumn,
    InconsistentCoordinates,
}

impl fmt::Display for SourceSpanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ReversedBytes => "source span end byte precedes its start byte",
            Self::ReversedLines => "source span end line precedes its start line",
            Self::ReversedColumn => "single-line source span end column precedes its start column",
            Self::InconsistentCoordinates => {
                "source span byte offsets disagree with its zero-based line and UTF-8 byte-column coordinates"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SourceSpanError {}

impl SourceSpan {
    pub fn new(start: SourcePosition, end: SourcePosition) -> Result<Self, SourceSpanError> {
        if end.byte_offset < start.byte_offset {
            return Err(SourceSpanError::ReversedBytes);
        }
        if end.byte_offset == start.byte_offset
            && (end.line != start.line || end.byte_column != start.byte_column)
        {
            return Err(SourceSpanError::InconsistentCoordinates);
        }
        if end.line < start.line {
            return Err(SourceSpanError::ReversedLines);
        }
        if end.line == start.line && end.byte_column < start.byte_column {
            return Err(SourceSpanError::ReversedColumn);
        }
        if end.line == start.line
            && end.byte_offset - start.byte_offset != end.byte_column - start.byte_column
        {
            return Err(SourceSpanError::InconsistentCoordinates);
        }
        Ok(Self { start, end })
    }

    pub const fn start(self) -> SourcePosition {
        self.start
    }

    pub const fn end(self) -> SourcePosition {
        self.end
    }

    pub const fn start_byte(self) -> u32 {
        self.start.byte_offset
    }

    pub const fn end_byte(self) -> u32 {
        self.end.byte_offset
    }
}

/// A span plus a deterministic occurrence number for equal or zero-width spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceAnchor {
    span: SourceSpan,
    occurrence: u32,
}

impl SourceAnchor {
    pub const fn new(span: SourceSpan, occurrence: u32) -> Self {
        Self { span, occurrence }
    }

    pub const fn span(self) -> SourceSpan {
        self.span
    }

    pub const fn occurrence(self) -> u32 {
        self.occurrence
    }
}

/// A normalized declaration-path segment kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeclarationSegmentKind {
    File,
    Namespace,
    Type,
    Function,
    Method,
    Constructor,
    Initializer,
    LocalFunction,
    Lambda,
    Closure,
    AnonymousCallable,
}

/// One named or anonymous declaration in a lexical nesting path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclarationSegment {
    kind: DeclarationSegmentKind,
    name: Option<Box<str>>,
    anchor: SourceAnchor,
    sibling_ordinal: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationLocatorError {
    Empty,
    EmptySegmentName,
}

impl fmt::Display for DeclarationLocatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("declaration locator must contain a segment"),
            Self::EmptySegmentName => {
                formatter.write_str("named declaration segment must not have an empty name")
            }
        }
    }
}

impl std::error::Error for DeclarationLocatorError {}

impl DeclarationSegment {
    pub fn named(
        kind: DeclarationSegmentKind,
        name: impl Into<String>,
        anchor: SourceAnchor,
        sibling_ordinal: u32,
    ) -> Result<Self, DeclarationLocatorError> {
        let name = name.into();
        if name.is_empty() {
            return Err(DeclarationLocatorError::EmptySegmentName);
        }
        Ok(Self {
            kind,
            name: Some(name.into_boxed_str()),
            anchor,
            sibling_ordinal,
        })
    }

    pub const fn anonymous(
        kind: DeclarationSegmentKind,
        anchor: SourceAnchor,
        sibling_ordinal: u32,
    ) -> Self {
        Self {
            kind,
            name: None,
            anchor,
            sibling_ordinal,
        }
    }

    pub const fn kind(&self) -> DeclarationSegmentKind {
        self.kind
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub const fn anchor(&self) -> SourceAnchor {
        self.anchor
    }

    pub const fn sibling_ordinal(&self) -> u32 {
        self.sibling_ordinal
    }
}

/// The complete lexical declaration path enclosing a semantic locator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclarationLocator(Box<[DeclarationSegment]>);

impl DeclarationLocator {
    pub fn new(segments: Vec<DeclarationSegment>) -> Result<Self, DeclarationLocatorError> {
        if segments.is_empty() {
            return Err(DeclarationLocatorError::Empty);
        }
        Ok(Self(segments.into_boxed_slice()))
    }

    pub fn segments(&self) -> &[DeclarationSegment] {
        &self.0
    }
}

/// The source-facing role of a semantic locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SemanticRole {
    Artifact,
    Procedure,
    Block,
    ProgramPoint,
    Value,
    Allocation,
    CallSite,
    MemoryLocation,
    Capture,
    SourceMapping,
    Evidence,
    Gap,
}

impl SemanticRole {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::Procedure => "procedure",
            Self::Block => "block",
            Self::ProgramPoint => "program_point",
            Self::Value => "value",
            Self::Allocation => "allocation",
            Self::CallSite => "call_site",
            Self::MemoryLocation => "memory_location",
            Self::Capture => "capture",
            Self::SourceMapping => "source_mapping",
            Self::Evidence => "evidence",
            Self::Gap => "gap",
        }
    }
}

/// A remappable source-facing semantic locator. It is not a cache-validity key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticLocator {
    mount: WorkspaceMountId,
    path: WorkspaceRelativePath,
    language: SemanticLanguage,
    declaration: DeclarationLocator,
    role: SemanticRole,
    anchor: SourceAnchor,
}

impl SemanticLocator {
    pub fn new(
        mount: WorkspaceMountId,
        path: WorkspaceRelativePath,
        language: SemanticLanguage,
        declaration: DeclarationLocator,
        role: SemanticRole,
        anchor: SourceAnchor,
    ) -> Self {
        Self {
            mount,
            path,
            language,
            declaration,
            role,
            anchor,
        }
    }

    pub const fn mount(&self) -> WorkspaceMountId {
        self.mount
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn language(&self) -> SemanticLanguage {
        self.language
    }

    pub fn declaration(&self) -> &DeclarationLocator {
        &self.declaration
    }

    pub const fn role(&self) -> SemanticRole {
        self.role
    }

    pub const fn anchor(&self) -> SourceAnchor {
        self.anchor
    }
}

/// The complete validity identity for one mounted immutable semantic artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticArtifactKey {
    mount: WorkspaceMountId,
    path: WorkspaceRelativePath,
    language: SemanticLanguage,
    revision: SourceRevision,
    adapter: AdapterSemanticsVersion,
    ir_version: SemanticIrVersion,
    configuration: ConfigurationFingerprint,
    dependencies: DependencyFingerprint,
}

impl SemanticArtifactKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mount: WorkspaceMountId,
        path: WorkspaceRelativePath,
        language: SemanticLanguage,
        revision: SourceRevision,
        adapter: AdapterSemanticsVersion,
        ir_version: SemanticIrVersion,
        configuration: ConfigurationFingerprint,
        dependencies: DependencyFingerprint,
    ) -> Self {
        Self {
            mount,
            path,
            language,
            revision,
            adapter,
            ir_version,
            configuration,
            dependencies,
        }
    }

    pub const fn mount(&self) -> WorkspaceMountId {
        self.mount
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn language(&self) -> SemanticLanguage {
        self.language
    }

    pub const fn revision(&self) -> SourceRevision {
        self.revision
    }

    pub fn adapter(&self) -> &AdapterSemanticsVersion {
        &self.adapter
    }

    pub const fn ir_version(&self) -> SemanticIrVersion {
        self.ir_version
    }

    pub const fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    pub const fn dependencies(&self) -> DependencyFingerprint {
        self.dependencies
    }

    /// A deterministic length-delimited SHA-256 fingerprint of every validity input.
    pub fn fingerprint(&self) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"bifrost-semantic-artifact-key-v1");
        digest.push(self.mount.as_bytes());
        digest.push(self.path.as_str().as_bytes());
        digest.push(self.language.stable_label().as_bytes());
        match self.revision {
            SourceRevision::Disk { content } => {
                digest.push(b"disk");
                digest.push(content.as_bytes());
            }
            SourceRevision::Overlay { content, snapshot } => {
                digest.push(b"overlay");
                digest.push(content.as_bytes());
                digest.push(snapshot.as_bytes());
            }
        }
        digest.push(self.adapter.name().as_bytes());
        digest.push(self.adapter.fingerprint().as_bytes());
        digest.push(self.ir_version.as_bytes());
        digest.push(self.configuration.as_bytes());
        digest.push(self.dependencies.as_bytes());
        digest.finish()
    }
}

struct LengthDelimitedDigest(Sha256);

impl LengthDelimitedDigest {
    fn new(domain: &[u8]) -> Self {
        let mut value = Self(Sha256::new());
        value.push(domain);
        value
    }

    fn push(&mut self, value: &[u8]) {
        let length =
            u64::try_from(value.len()).expect("semantic identity input length fits in u64");
        self.0.update(length.to_le_bytes());
        self.0.update(value);
    }

    fn finish(self) -> StableDigest {
        let digest = self.0.finalize();
        let mut value = [0_u8; 32];
        value.copy_from_slice(&digest);
        StableDigest::from_array(value)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::Path;

    use super::*;
    use crate::analyzer::Language;

    #[test]
    fn dense_ids_are_fixed_width_checked_and_not_interchangeable() {
        let procedure = ProcedureId::try_from_index(17).unwrap();
        let control_edge = ControlEdgeId::try_from_index(17).unwrap();
        assert_eq!(procedure.get(), 17);
        assert_eq!(procedure.index(), 17);
        assert_eq!(procedure.to_string(), "17");
        assert_eq!(std::mem::size_of::<ProcedureId>(), 4);
        assert_eq!(std::mem::size_of::<ControlEdgeId>(), 4);
        assert_ne!(format!("{procedure:?}"), format!("{:?}", BlockId::new(17)));
        assert_ne!(
            format!("{control_edge:?}"),
            format!("{:?}", ProgramPointId::new(17))
        );

        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            ProcedureId::try_from_index(u32::MAX as usize + 1),
            Err(DenseIdOverflow {
                id_type: "ProcedureId",
                index: u32::MAX as usize + 1,
            })
        );
    }

    #[test]
    fn workspace_path_strings_are_slash_canonical_and_relative() {
        let path = WorkspaceRelativePath::new("src/nested/main.ts").unwrap();
        assert_eq!(path.as_str(), "src/nested/main.ts");

        for invalid in [
            "",
            "/src/main.ts",
            r"\src\main.ts",
            "C:/src/main.ts",
            "C:main.ts",
        ] {
            assert!(WorkspaceRelativePath::new(invalid).is_err(), "{invalid:?}");
        }
        for invalid in ["src/../main.ts", "src/./main.ts", "src//main.ts", "src/"] {
            assert!(WorkspaceRelativePath::new(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(
            WorkspaceRelativePath::new(r"src\nested\main.ts"),
            Err(WorkspaceRelativePathError::InvalidCharacter)
        );
    }

    #[test]
    fn native_paths_use_platform_components_without_aliasing_unix_backslashes() {
        let native = Path::new("src").join("nested").join("main.ts");
        assert_eq!(
            WorkspaceRelativePath::try_from_path(&native)
                .unwrap()
                .as_str(),
            "src/nested/main.ts"
        );

        #[cfg(windows)]
        assert_eq!(
            WorkspaceRelativePath::try_from_path(Path::new(r"src\nested\main.ts"))
                .unwrap()
                .as_str(),
            "src/nested/main.ts"
        );
        #[cfg(not(windows))]
        assert_eq!(
            WorkspaceRelativePath::try_from_path(Path::new(r"src\nested\main.ts")),
            Err(WorkspaceRelativePathError::InvalidCharacter)
        );
    }

    #[test]
    fn workspace_paths_reject_windows_unsafe_components() {
        for (invalid, expected) in [
            (
                "src/main.ts:stream",
                WorkspaceRelativePathError::InvalidCharacter,
            ),
            ("src/name?.ts", WorkspaceRelativePathError::InvalidCharacter),
            ("src/name*.ts", WorkspaceRelativePathError::InvalidCharacter),
            (
                "src/name|pipe.ts",
                WorkspaceRelativePathError::InvalidCharacter,
            ),
            (
                "src/control\u{1f}.ts",
                WorkspaceRelativePathError::InvalidCharacter,
            ),
            (
                "src/trailing.",
                WorkspaceRelativePathError::TrailingDotOrSpace,
            ),
            (
                "src/trailing ",
                WorkspaceRelativePathError::TrailingDotOrSpace,
            ),
            ("src/CON", WorkspaceRelativePathError::ReservedDeviceName),
            (
                "src/con.txt",
                WorkspaceRelativePathError::ReservedDeviceName,
            ),
            (
                "src/AUX .md",
                WorkspaceRelativePathError::ReservedDeviceName,
            ),
            (
                "src/lPt9.log",
                WorkspaceRelativePathError::ReservedDeviceName,
            ),
            (
                "src/COM¹.log",
                WorkspaceRelativePathError::ReservedDeviceName,
            ),
        ] {
            assert_eq!(
                WorkspaceRelativePath::new(invalid),
                Err(expected),
                "{invalid:?}"
            );
        }

        for valid in [
            "src/console.rs",
            "src/com10.txt",
            "src/auxiliary",
            "src/trailing .txt",
        ] {
            assert!(WorkspaceRelativePath::new(valid).is_ok(), "{valid:?}");
        }
    }

    #[test]
    fn current_semantic_ir_version_is_stable_and_nonzero() {
        let current = SemanticIrVersion::current();
        assert_eq!(
            current.to_string(),
            "b962895821730977967b60c508eb6c2cd98b3e3caefdf446bf93641cbbbdd6f3"
        );
        assert_ne!(current.as_bytes(), &[0_u8; 32]);
        assert_eq!(SEMANTIC_IR_SCHEMA_VERSION, 6);
    }

    fn digest(label: &str) -> StableDigest {
        StableDigest::sha256(label)
    }

    #[allow(clippy::too_many_arguments)]
    fn key(
        mount: &str,
        path: &str,
        language: SemanticLanguage,
        revision: SourceRevision,
        adapter_name: &str,
        adapter: &str,
        ir: &str,
        configuration: &str,
        dependencies: &str,
    ) -> SemanticArtifactKey {
        SemanticArtifactKey::new(
            WorkspaceMountId::from_digest(digest(mount)),
            WorkspaceRelativePath::new(path).unwrap(),
            language,
            revision,
            AdapterSemanticsVersion::new(adapter_name, digest(adapter)).unwrap(),
            SemanticIrVersion::from_digest(digest(ir)),
            ConfigurationFingerprint::from_digest(digest(configuration)),
            DependencyFingerprint::from_digest(digest(dependencies)),
        )
    }

    #[test]
    fn artifact_fingerprint_changes_for_every_validity_input() {
        let disk = |content: &str| SourceRevision::Disk {
            content: ContentIdentity::from_digest(digest(content)),
        };
        let overlay = |content: &str, snapshot: &str| SourceRevision::Overlay {
            content: ContentIdentity::from_digest(digest(content)),
            snapshot: OverlaySnapshotId::from_digest(digest(snapshot)),
        };
        let base = key(
            "mount-a",
            "src/main.ts",
            SemanticLanguage::Standard(Language::TypeScript),
            disk("content-a"),
            "typescript",
            "adapter-a",
            "ir-a",
            "config-a",
            "deps-a",
        );
        let variants = [
            key(
                "mount-b",
                "src/main.ts",
                base.language(),
                base.revision(),
                "typescript",
                "adapter-a",
                "ir-a",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/copy.ts",
                base.language(),
                base.revision(),
                "typescript",
                "adapter-a",
                "ir-a",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                SemanticLanguage::TypeScriptTsx,
                base.revision(),
                "typescript",
                "adapter-a",
                "ir-a",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                base.language(),
                disk("content-b"),
                "typescript",
                "adapter-a",
                "ir-a",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                base.language(),
                overlay("content-a", "overlay-a"),
                "typescript",
                "adapter-a",
                "ir-a",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                base.language(),
                overlay("content-a", "overlay-b"),
                "typescript",
                "adapter-a",
                "ir-a",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                base.language(),
                base.revision(),
                "typescript-next",
                "adapter-a",
                "ir-a",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                base.language(),
                base.revision(),
                "typescript",
                "adapter-b",
                "ir-a",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                base.language(),
                base.revision(),
                "typescript",
                "adapter-a",
                "ir-b",
                "config-a",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                base.language(),
                base.revision(),
                "typescript",
                "adapter-a",
                "ir-a",
                "config-b",
                "deps-a",
            ),
            key(
                "mount-a",
                "src/main.ts",
                base.language(),
                base.revision(),
                "typescript",
                "adapter-a",
                "ir-a",
                "config-a",
                "deps-b",
            ),
        ];

        let mut fingerprints = HashSet::from([base.fingerprint()]);
        for variant in variants {
            assert_ne!(base, variant);
            assert!(fingerprints.insert(variant.fingerprint()));
        }
    }

    #[test]
    fn declaration_locator_preserves_nested_anonymous_segments() {
        let span = SourceSpan::new(
            SourcePosition::new(10, 1, 2),
            SourcePosition::new(20, 1, 12),
        )
        .unwrap();
        let anchor = SourceAnchor::new(span, 0);
        let outer =
            DeclarationSegment::named(DeclarationSegmentKind::Method, "outer", anchor, 0).unwrap();
        let lambda = DeclarationSegment::anonymous(DeclarationSegmentKind::Lambda, anchor, 1);
        let locator = DeclarationLocator::new(vec![outer, lambda]).unwrap();

        assert_eq!(locator.segments().len(), 2);
        assert_eq!(locator.segments()[1].name(), None);
        assert_eq!(locator.segments()[1].sibling_ordinal(), 1);
    }

    #[test]
    fn semantic_locator_distinguishes_duplicate_paths_across_mounts() {
        let span =
            SourceSpan::new(SourcePosition::new(0, 0, 0), SourcePosition::new(1, 0, 1)).unwrap();
        let anchor = SourceAnchor::new(span, 0);
        let declaration = || {
            DeclarationLocator::new(vec![
                DeclarationSegment::named(DeclarationSegmentKind::Function, "run", anchor, 0)
                    .unwrap(),
            ])
            .unwrap()
        };
        let locator = |mount: &str| {
            SemanticLocator::new(
                WorkspaceMountId::hash_bytes(mount),
                WorkspaceRelativePath::new("src/main.ts").unwrap(),
                SemanticLanguage::Standard(Language::TypeScript),
                declaration(),
                SemanticRole::Procedure,
                anchor,
            )
        };

        assert_ne!(locator("mount-a"), locator("mount-b"));
    }

    #[test]
    fn source_spans_are_half_open_and_monotonic() {
        let start = SourcePosition::new(4, 0, 4);
        let end = SourcePosition::new(9, 0, 9);
        let span = SourceSpan::new(start, end).unwrap();
        assert_eq!(span.start_byte(), 4);
        assert_eq!(span.end_byte(), 9);
        assert_eq!(
            SourceSpan::new(end, start),
            Err(SourceSpanError::ReversedBytes)
        );
    }

    #[test]
    fn source_spans_require_coordinate_consistency() {
        let start = SourcePosition::new(4, 2, 4);
        for end in [
            SourcePosition::new(4, 2, 5),
            SourcePosition::new(4, 3, 0),
            SourcePosition::new(9, 2, 8),
        ] {
            assert_eq!(
                SourceSpan::new(start, end),
                Err(SourceSpanError::InconsistentCoordinates)
            );
        }

        assert!(SourceSpan::new(start, SourcePosition::new(6, 2, 6)).is_ok());
        assert!(SourceSpan::new(start, SourcePosition::new(9, 3, 1)).is_ok());
    }
}
