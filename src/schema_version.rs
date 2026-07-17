//! Shared compatibility-lineage mechanics for versioned source formats.
//!
//! Each source format owns its descriptors. This module only validates those
//! descriptors and resolves an omitted version to the single compatible head
//! or an authored version to that exact descriptor. It deliberately contains
//! no policy- or query-specific vocabulary.

use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SchemaVersionDescriptor {
    pub(crate) version: u32,
    pub(crate) implicit_predecessor: Option<u32>,
    pub(crate) inference: SchemaInference,
}

impl SchemaVersionDescriptor {
    pub(crate) const fn new(
        version: u32,
        implicit_predecessor: Option<u32>,
        inference: SchemaInference,
    ) -> Self {
        Self {
            version,
            implicit_predecessor,
            inference,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaInference {
    /// Omitted sources may advance to this version from its predecessor.
    AutoCompatible,
    /// The version is supported only when the source pins it explicitly.
    ExplicitOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaVersionOrigin {
    Explicit,
    ImplicitCompatible,
    ReferencedDocumentExplicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaVersionResolution {
    pub version: u32,
    pub origin: SchemaVersionOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SchemaVersionRegistryError {
    DuplicateVersion { version: u32 },
    MissingPredecessor { version: u32, predecessor: u32 },
    PredecessorCycle { version: u32 },
    IncompatibleImplicitPredecessor { version: u32, predecessor: u32 },
    NoImplicitHead,
    MultipleImplicitHeads { versions: Vec<u32> },
}

impl fmt::Display for SchemaVersionRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateVersion { version } => {
                write!(formatter, "duplicate schema version {version}")
            }
            Self::MissingPredecessor {
                version,
                predecessor,
            } => write!(
                formatter,
                "schema version {version} names missing predecessor {predecessor}"
            ),
            Self::PredecessorCycle { version } => write!(
                formatter,
                "schema version predecessor cycle includes version {version}"
            ),
            Self::IncompatibleImplicitPredecessor {
                version,
                predecessor,
            } => write!(
                formatter,
                "auto-compatible schema version {version} cannot follow explicit-only version {predecessor}"
            ),
            Self::NoImplicitHead => {
                formatter.write_str("schema registry has no implicit compatible head")
            }
            Self::MultipleImplicitHeads { versions } => write!(
                formatter,
                "schema registry has multiple implicit compatible heads: {}",
                display_versions(versions)
            ),
        }
    }
}

impl std::error::Error for SchemaVersionRegistryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnsupportedSchemaVersion {
    pub(crate) requested: u32,
    pub(crate) supported: Vec<u32>,
}

impl fmt::Display for UnsupportedSchemaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported schema version {}; supported exact versions: {}",
            self.requested,
            display_versions(&self.supported)
        )
    }
}

impl std::error::Error for UnsupportedSchemaVersion {}

#[derive(Debug)]
pub(crate) struct SchemaVersionRegistry {
    descriptors: HashMap<u32, SchemaVersionDescriptor>,
    implicit_head: u32,
    supported_versions: Vec<u32>,
}

impl SchemaVersionRegistry {
    pub(crate) fn new(
        descriptors: &[SchemaVersionDescriptor],
    ) -> Result<Self, SchemaVersionRegistryError> {
        let mut descriptors_by_version = HashMap::with_capacity(descriptors.len());
        for descriptor in descriptors {
            if descriptors_by_version
                .insert(descriptor.version, *descriptor)
                .is_some()
            {
                return Err(SchemaVersionRegistryError::DuplicateVersion {
                    version: descriptor.version,
                });
            }
        }

        for descriptor in descriptors {
            let Some(predecessor) = descriptor.implicit_predecessor else {
                continue;
            };
            if !descriptors_by_version.contains_key(&predecessor) {
                return Err(SchemaVersionRegistryError::MissingPredecessor {
                    version: descriptor.version,
                    predecessor,
                });
            }
        }

        validate_acyclic_predecessors(&descriptors_by_version)?;

        for descriptor in descriptors {
            let Some(predecessor) = descriptor.implicit_predecessor else {
                continue;
            };
            let predecessor_descriptor = descriptors_by_version
                .get(&predecessor)
                .expect("predecessor existence was validated above");
            if descriptor.inference == SchemaInference::AutoCompatible
                && predecessor_descriptor.inference != SchemaInference::AutoCompatible
            {
                return Err(
                    SchemaVersionRegistryError::IncompatibleImplicitPredecessor {
                        version: descriptor.version,
                        predecessor,
                    },
                );
            }
        }

        let implicit_predecessors = descriptors
            .iter()
            .filter(|descriptor| descriptor.inference == SchemaInference::AutoCompatible)
            .filter_map(|descriptor| descriptor.implicit_predecessor)
            .collect::<HashSet<_>>();
        let mut implicit_heads = descriptors
            .iter()
            .filter(|descriptor| {
                descriptor.inference == SchemaInference::AutoCompatible
                    && !implicit_predecessors.contains(&descriptor.version)
            })
            .map(|descriptor| descriptor.version)
            .collect::<Vec<_>>();
        implicit_heads.sort_unstable();
        let implicit_head = match implicit_heads.as_slice() {
            [] => return Err(SchemaVersionRegistryError::NoImplicitHead),
            [head] => *head,
            _ => {
                return Err(SchemaVersionRegistryError::MultipleImplicitHeads {
                    versions: implicit_heads,
                });
            }
        };

        let mut supported_versions = descriptors_by_version.keys().copied().collect::<Vec<_>>();
        supported_versions.sort_unstable();

        Ok(Self {
            descriptors: descriptors_by_version,
            implicit_head,
            supported_versions,
        })
    }

    pub(crate) fn resolve(
        &self,
        authored_version: Option<u32>,
    ) -> Result<SchemaVersionResolution, UnsupportedSchemaVersion> {
        match authored_version {
            Some(version) if self.descriptors.contains_key(&version) => {
                Ok(SchemaVersionResolution {
                    version,
                    origin: SchemaVersionOrigin::Explicit,
                })
            }
            Some(requested) => Err(UnsupportedSchemaVersion {
                requested,
                supported: self.supported_versions.clone(),
            }),
            None => Ok(SchemaVersionResolution {
                version: self.implicit_head,
                origin: SchemaVersionOrigin::ImplicitCompatible,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Complete,
}

fn validate_acyclic_predecessors(
    descriptors: &HashMap<u32, SchemaVersionDescriptor>,
) -> Result<(), SchemaVersionRegistryError> {
    let mut states = HashMap::with_capacity(descriptors.len());
    let mut starts = descriptors.keys().copied().collect::<Vec<_>>();
    starts.sort_unstable();
    for start in starts {
        let mut chain = Vec::new();
        let mut current = Some(start);
        while let Some(version) = current {
            match states.get(&version) {
                Some(VisitState::Complete) => break,
                Some(VisitState::Visiting) => {
                    let cycle_start = chain
                        .iter()
                        .position(|candidate| *candidate == version)
                        .expect("a visiting version belongs to the current chain");
                    let version = chain[cycle_start..]
                        .iter()
                        .copied()
                        .min()
                        .expect("a predecessor cycle is non-empty");
                    return Err(SchemaVersionRegistryError::PredecessorCycle { version });
                }
                None => {
                    states.insert(version, VisitState::Visiting);
                    chain.push(version);
                    current = descriptors
                        .get(&version)
                        .and_then(|descriptor| descriptor.implicit_predecessor);
                }
            }
        }
        for version in chain {
            states.insert(version, VisitState::Complete);
        }
    }
    Ok(())
}

fn display_versions(versions: &[u32]) -> String {
    versions
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: SchemaVersionDescriptor =
        SchemaVersionDescriptor::new(2, None, SchemaInference::AutoCompatible);

    fn descriptor(
        version: u32,
        predecessor: Option<u32>,
        inference: SchemaInference,
    ) -> SchemaVersionDescriptor {
        SchemaVersionDescriptor::new(version, predecessor, inference)
    }

    #[test]
    fn omitted_and_explicit_versions_have_distinct_origins() {
        let registry = SchemaVersionRegistry::new(&[ROOT]).unwrap();

        assert_eq!(
            registry.resolve(None).unwrap(),
            SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::ImplicitCompatible,
            }
        );
        assert_eq!(
            registry.resolve(Some(2)).unwrap(),
            SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::Explicit,
            }
        );
    }

    #[test]
    fn compatible_successor_becomes_the_implicit_head() {
        let registry = SchemaVersionRegistry::new(&[
            ROOT,
            descriptor(3, Some(2), SchemaInference::AutoCompatible),
        ])
        .unwrap();

        assert_eq!(registry.resolve(None).unwrap().version, 3);
        assert_eq!(registry.resolve(Some(2)).unwrap().version, 2);
    }

    #[test]
    fn explicit_only_successor_never_becomes_the_implicit_head() {
        let registry = SchemaVersionRegistry::new(&[
            ROOT,
            descriptor(3, Some(2), SchemaInference::AutoCompatible),
            descriptor(4, Some(3), SchemaInference::ExplicitOnly),
        ])
        .unwrap();

        assert_eq!(registry.resolve(None).unwrap().version, 3);
        assert_eq!(registry.resolve(Some(4)).unwrap().version, 4);
    }

    #[test]
    fn unsupported_explicit_version_does_not_fall_back() {
        let registry = SchemaVersionRegistry::new(&[
            ROOT,
            descriptor(3, Some(2), SchemaInference::ExplicitOnly),
        ])
        .unwrap();

        let error = registry.resolve(Some(99)).unwrap_err();

        assert_eq!(error.requested, 99);
        assert_eq!(error.supported, vec![2, 3]);
    }

    #[test]
    fn duplicate_versions_are_rejected() {
        let error = SchemaVersionRegistry::new(&[ROOT, ROOT]).unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::DuplicateVersion { version: 2 }
        );
    }

    #[test]
    fn missing_predecessors_are_rejected() {
        let error =
            SchemaVersionRegistry::new(&[descriptor(2, Some(1), SchemaInference::AutoCompatible)])
                .unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::MissingPredecessor {
                version: 2,
                predecessor: 1,
            }
        );
    }

    #[test]
    fn predecessor_cycles_are_rejected_before_head_selection() {
        let error = SchemaVersionRegistry::new(&[
            descriptor(1, Some(2), SchemaInference::AutoCompatible),
            descriptor(2, Some(1), SchemaInference::AutoCompatible),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::PredecessorCycle { version: 1 }
        );
    }

    #[test]
    fn explicit_only_nodes_do_not_hide_predecessor_cycles() {
        let error = SchemaVersionRegistry::new(&[
            descriptor(1, None, SchemaInference::AutoCompatible),
            descriptor(2, Some(3), SchemaInference::ExplicitOnly),
            descriptor(3, Some(2), SchemaInference::AutoCompatible),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::PredecessorCycle { version: 2 }
        );
    }

    #[test]
    fn registry_requires_an_implicit_head() {
        let error =
            SchemaVersionRegistry::new(&[descriptor(2, None, SchemaInference::ExplicitOnly)])
                .unwrap_err();

        assert_eq!(error, SchemaVersionRegistryError::NoImplicitHead);
    }

    #[test]
    fn independent_implicit_lineages_are_rejected() {
        let error = SchemaVersionRegistry::new(&[
            ROOT,
            descriptor(3, None, SchemaInference::AutoCompatible),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::MultipleImplicitHeads {
                versions: vec![2, 3],
            }
        );
    }

    #[test]
    fn forked_implicit_lineages_are_rejected() {
        let error = SchemaVersionRegistry::new(&[
            ROOT,
            descriptor(3, Some(2), SchemaInference::AutoCompatible),
            descriptor(4, Some(2), SchemaInference::AutoCompatible),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::MultipleImplicitHeads {
                versions: vec![3, 4],
            }
        );
    }

    #[test]
    fn compatible_lineage_cannot_cross_an_explicit_only_version() {
        let error = SchemaVersionRegistry::new(&[
            ROOT,
            descriptor(3, Some(2), SchemaInference::ExplicitOnly),
            descriptor(4, Some(3), SchemaInference::AutoCompatible),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::IncompatibleImplicitPredecessor {
                version: 4,
                predecessor: 3,
            }
        );
    }
}
