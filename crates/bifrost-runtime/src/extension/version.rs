use serde::{Deserialize, Serialize};
use std::fmt;

pub const EXTENSION_API_VERSION: ExtensionApiVersion = ExtensionApiVersion { major: 1, minor: 0 };

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionApiVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExtensionCapabilityId(Box<str>);

impl ExtensionCapabilityId {
    pub fn new(value: impl Into<String>) -> Result<Self, ExtensionCompatibilityError> {
        let value = value.into();
        if value.is_empty()
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(ExtensionCompatibilityError::InvalidCapability(
                value.into_boxed_str(),
            ));
        }
        Ok(Self(value.into_boxed_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApiStability {
    Stable,
    Experimental { since_minor: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Complete,
    Partial,
    Unsupported,
}
impl CapabilitySupport {
    pub(crate) const fn unsupported() -> Self {
        Self::Unsupported
    }
    /// Whether this surface serves the capability at all. `Partial` bounds
    /// coverage, not availability, so it negotiates exactly like `Complete`;
    /// only `Unsupported` refuses.
    pub const fn is_served(self) -> bool {
        matches!(self, Self::Complete | Self::Partial)
    }
}

/// One row of the published extension surface.
///
/// This table is the single definition of what the surface offers.
/// `ExtensionWorkspace::open` projects it onto the wire capability report
/// (`OperationCapability`), and `negotiate_extension_api` accepts exactly the
/// rows whose support is served. Two hand-maintained lists are what went wrong
/// before: the report advertised `experimental.semantic.value_dependence` while
/// negotiation rejected it as a missing capability (#2328).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedOperation {
    pub id: &'static str,
    pub stability: ApiStability,
    pub support: CapabilitySupport,
}

pub const PUBLISHED_OPERATIONS: &[PublishedOperation] = &[
    PublishedOperation {
        id: "structural.query",
        stability: ApiStability::Stable,
        support: CapabilitySupport::Complete,
    },
    PublishedOperation {
        id: "experimental.semantic.control_flow",
        stability: ApiStability::Experimental { since_minor: 0 },
        support: CapabilitySupport::Complete,
    },
    PublishedOperation {
        id: "experimental.semantic.value_dependence",
        stability: ApiStability::Experimental { since_minor: 0 },
        support: CapabilitySupport::Partial,
    },
    // Typestate machinery exists in the engine but has no route on this
    // surface yet. Advertising the operation as `Unsupported` rather than
    // omitting it lets extensions distinguish "unsupported here" from "does
    // not exist", while negotiation still refuses a client that requires it.
    // Design: .agents/docs/extension-typestate-design-2026-08.md.
    PublishedOperation {
        id: "experimental.semantic.typestate",
        stability: ApiStability::Experimental { since_minor: 0 },
        support: CapabilitySupport::Unsupported,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionCompatibility {
    pub major: u16,
    pub minimum_minor: u16,
    pub maximum_minor: u16,
    #[serde(default)]
    pub required_capabilities: Box<[ExtensionCapabilityId]>,
}

impl Default for ExtensionCompatibility {
    fn default() -> Self {
        Self {
            major: 1,
            minimum_minor: 0,
            maximum_minor: 0,
            required_capabilities: Box::new([]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionCompatibilityError {
    UnsupportedMajor { requested: u16, supported: u16 },
    InvalidMinorRange { minimum: u16, maximum: u16 },
    TooNewMinor { requested: u16, supported: u16 },
    MissingCapability(ExtensionCapabilityId),
    DuplicateCapability(ExtensionCapabilityId),
    InvalidCapability(Box<str>),
}

impl fmt::Display for ExtensionCompatibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ExtensionCompatibilityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedExtensionApi {
    pub version: ExtensionApiVersion,
    pub capabilities: Box<[ExtensionCapabilityId]>,
}

pub fn negotiate_extension_api(
    requested: &ExtensionCompatibility,
) -> Result<NegotiatedExtensionApi, ExtensionCompatibilityError> {
    if requested.major != EXTENSION_API_VERSION.major {
        return Err(ExtensionCompatibilityError::UnsupportedMajor {
            requested: requested.major,
            supported: EXTENSION_API_VERSION.major,
        });
    }
    if requested.minimum_minor > requested.maximum_minor {
        return Err(ExtensionCompatibilityError::InvalidMinorRange {
            minimum: requested.minimum_minor,
            maximum: requested.maximum_minor,
        });
    }
    if requested.minimum_minor > EXTENSION_API_VERSION.minor {
        return Err(ExtensionCompatibilityError::TooNewMinor {
            requested: requested.minimum_minor,
            supported: EXTENSION_API_VERSION.minor,
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for capability in &requested.required_capabilities {
        if !seen.insert(capability.clone()) {
            return Err(ExtensionCompatibilityError::DuplicateCapability(
                capability.clone(),
            ));
        }
        let served = PUBLISHED_OPERATIONS
            .iter()
            .any(|operation| operation.id == capability.as_str() && operation.support.is_served());
        if !served {
            return Err(ExtensionCompatibilityError::MissingCapability(
                capability.clone(),
            ));
        }
    }
    Ok(NegotiatedExtensionApi {
        version: EXTENSION_API_VERSION,
        capabilities: requested.required_capabilities.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_current_version() {
        assert!(negotiate_extension_api(&ExtensionCompatibility::default()).is_ok());
    }
    #[test]
    fn accepts_every_served_capability() {
        let required: Box<[ExtensionCapabilityId]> = PUBLISHED_OPERATIONS
            .iter()
            .filter(|operation| operation.support.is_served())
            .map(|operation| ExtensionCapabilityId::new(operation.id).unwrap())
            .collect();
        assert!(
            !required.is_empty(),
            "the surface must publish at least one served operation: {PUBLISHED_OPERATIONS:?}"
        );
        let request = ExtensionCompatibility {
            required_capabilities: required.clone(),
            ..Default::default()
        };
        let negotiated = negotiate_extension_api(&request).unwrap();
        assert_eq!(negotiated.capabilities, required);
    }
    #[test]
    fn rejects_advertised_but_unsupported_capability() {
        for operation in PUBLISHED_OPERATIONS
            .iter()
            .filter(|operation| !operation.support.is_served())
        {
            let request = ExtensionCompatibility {
                required_capabilities: Box::new(
                    [ExtensionCapabilityId::new(operation.id).unwrap()],
                ),
                ..Default::default()
            };
            assert!(
                matches!(
                    negotiate_extension_api(&request),
                    Err(ExtensionCompatibilityError::MissingCapability(ref id))
                        if id.as_str() == operation.id
                ),
                "{operation:?} is advertised as unsupported and must not negotiate"
            );
        }
    }
    #[test]
    fn rejects_unknown_capability() {
        let request = ExtensionCompatibility {
            required_capabilities: Box::new([ExtensionCapabilityId::new(
                "experimental.semantic.unknown",
            )
            .unwrap()]),
            ..Default::default()
        };
        assert!(matches!(
            negotiate_extension_api(&request),
            Err(ExtensionCompatibilityError::MissingCapability(id))
                if id.as_str() == "experimental.semantic.unknown"
        ));
    }
    #[test]
    fn rejects_unknown_major() {
        let request = ExtensionCompatibility {
            major: 2,
            ..Default::default()
        };
        assert!(matches!(
            negotiate_extension_api(&request),
            Err(ExtensionCompatibilityError::UnsupportedMajor { .. })
        ));
    }
}
