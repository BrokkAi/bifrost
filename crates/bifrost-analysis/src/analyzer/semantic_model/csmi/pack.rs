//! Logical CSMI pack resources and byte-level integrity.
//!
//! CSMI v0.1 specifies a manifest plus a content-addressed set of resources;
//! it intentionally does not prescribe ZIP, TAR, or registry transport.  The
//! resolver abstraction keeps validation independent of whichever transport a
//! caller uses.

use super::canonical::{CsmiCanonicalError, canonical_pack_manifest, sha256_hex};
use super::model::{CsmiPackManifest, CsmiResourceDescriptor};
use std::collections::BTreeMap;
use std::fmt;

pub trait CsmiResourceResolver {
    fn read_resource(&self, path: &str, expected_size: u64) -> Result<Vec<u8>, CsmiResourceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsmiResourceError {
    Missing {
        path: String,
    },
    InvalidPath {
        path: String,
        reason: String,
    },
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    DuplicatePath {
        path: String,
    },
    UnexpectedPath {
        path: String,
    },
}

impl fmt::Display for CsmiResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { path } => write!(formatter, "resource is missing: {path}"),
            Self::InvalidPath { path, reason } => {
                write!(formatter, "invalid resource path {path:?}: {reason}")
            }
            Self::SizeMismatch {
                path,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "resource {path:?} has size {actual}, expected {expected}"
                )
            }
            Self::DigestMismatch {
                path,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "resource {path:?} has digest {actual}, expected {expected}"
                )
            }
            Self::DuplicatePath { path } => write!(formatter, "duplicate resource path: {path}"),
            Self::UnexpectedPath { path } => {
                write!(formatter, "resource is not listed by manifest: {path}")
            }
        }
    }
}

impl std::error::Error for CsmiResourceError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryCsmiResourceResolver {
    resources: BTreeMap<String, Vec<u8>>,
}

pub type CsmiInMemoryResourceResolver = InMemoryCsmiResourceResolver;

impl InMemoryCsmiResourceResolver {
    pub fn new<I, P>(resources: I) -> Result<Self, CsmiResourceError>
    where
        I: IntoIterator<Item = (P, Vec<u8>)>,
        P: Into<String>,
    {
        let mut resolver = Self::default();
        for (path, bytes) in resources {
            resolver.insert(path.into(), bytes)?;
        }
        Ok(resolver)
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: String, bytes: Vec<u8>) -> Result<(), CsmiResourceError> {
        validate_resource_path(&path).map_err(|reason| CsmiResourceError::InvalidPath {
            path: path.clone(),
            reason,
        })?;
        if self.resources.insert(path.clone(), bytes).is_some() {
            return Err(CsmiResourceError::DuplicatePath { path });
        }
        Ok(())
    }

    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.resources.get(path).map(Vec::as_slice)
    }

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.resources.keys().map(String::as_str)
    }

    pub fn into_resources(self) -> BTreeMap<String, Vec<u8>> {
        self.resources
    }
}

impl CsmiResourceResolver for InMemoryCsmiResourceResolver {
    fn read_resource(&self, path: &str, expected_size: u64) -> Result<Vec<u8>, CsmiResourceError> {
        validate_resource_path(path).map_err(|reason| CsmiResourceError::InvalidPath {
            path: path.to_owned(),
            reason,
        })?;
        let bytes = self
            .resources
            .get(path)
            .ok_or_else(|| CsmiResourceError::Missing {
                path: path.to_owned(),
            })?;
        let actual = u64::try_from(bytes.len()).expect("resource length fits u64");
        if actual != expected_size {
            return Err(CsmiResourceError::SizeMismatch {
                path: path.to_owned(),
                expected: expected_size,
                actual,
            });
        }
        Ok(bytes.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiLogicalPack {
    pub manifest: CsmiPackManifest,
    pub resources: InMemoryCsmiResourceResolver,
}

impl CsmiLogicalPack {
    pub fn new(manifest: CsmiPackManifest, resources: InMemoryCsmiResourceResolver) -> Self {
        Self {
            manifest,
            resources,
        }
    }

    pub fn canonical_manifest_bytes(&self) -> Result<Vec<u8>, CsmiCanonicalError> {
        canonical_pack_manifest(&self.manifest)
    }

    pub fn pack_digest(&self) -> Result<String, CsmiCanonicalError> {
        Ok(sha256_hex(&self.canonical_manifest_bytes()?))
    }

    pub fn verify_resources(&self) -> Result<(), Vec<CsmiResourceError>> {
        verify_resources(&self.manifest, &self.resources)
    }

    pub fn resource_bytes(
        &self,
        descriptor: &CsmiResourceDescriptor,
    ) -> Result<Vec<u8>, CsmiResourceError> {
        let bytes = self
            .resources
            .read_resource(&descriptor.path, descriptor.size)?;
        let actual = sha256_hex(&bytes);
        if actual != descriptor.digest.value {
            return Err(CsmiResourceError::DigestMismatch {
                path: descriptor.path.clone(),
                expected: descriptor.digest.value.clone(),
                actual,
            });
        }
        Ok(bytes)
    }
}

pub fn verify_resources(
    manifest: &CsmiPackManifest,
    resources: &dyn CsmiResourceResolver,
) -> Result<(), Vec<CsmiResourceError>> {
    let mut errors = Vec::new();
    let mut listed = BTreeMap::new();
    for descriptor in &manifest.resources {
        if let Err(reason) = validate_resource_path(&descriptor.path) {
            errors.push(CsmiResourceError::InvalidPath {
                path: descriptor.path.clone(),
                reason,
            });
            continue;
        }
        if listed.insert(descriptor.path.clone(), ()).is_some() {
            errors.push(CsmiResourceError::DuplicatePath {
                path: descriptor.path.clone(),
            });
            continue;
        }
        match resources.read_resource(&descriptor.path, descriptor.size) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                if actual != descriptor.digest.value {
                    errors.push(CsmiResourceError::DigestMismatch {
                        path: descriptor.path.clone(),
                        expected: descriptor.digest.value.clone(),
                        actual,
                    });
                }
            }
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate the path restrictions from the CSMI resource-path schema without
/// accepting platform-specific path syntax or URI aliases.
pub fn validate_resource_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("path is empty".to_owned());
    }
    if path.bytes().any(|byte| byte == 0) {
        return Err("path contains NUL".to_owned());
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err("path must be relative and must not end in '/'".to_owned());
    }
    if path.contains('\\') {
        return Err("path must use '/' separators".to_owned());
    }
    if path.contains("//") {
        return Err("path contains an empty component".to_owned());
    }
    if path.len() >= 2 && path.as_bytes()[1] == b':' && path.as_bytes()[0].is_ascii_alphabetic() {
        return Err("drive-qualified paths are not allowed".to_owned());
    }
    if path
        .as_bytes()
        .get(0..1)
        .is_some_and(|first| first[0].is_ascii_alphabetic())
        && path.contains(":")
        && path.find(':').is_some_and(|colon| {
            path[..colon]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
        })
    {
        return Err("URI schemes are not allowed".to_owned());
    }
    for component in path.split('/') {
        if component == "." || component == ".." {
            return Err("dot path components are not allowed".to_owned());
        }
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%5c") {
        return Err("encoded dot or separator is not allowed".to_owned());
    }
    Ok(())
}
