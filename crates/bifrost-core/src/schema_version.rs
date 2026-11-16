//! Shared compatibility-lineage mechanics for versioned source formats.
//!
//! Each source format owns its descriptors. This module only validates those
//! descriptors and resolves authored versions exactly. Formats can infer the
//! lowest version admitting their constructs without crossing a semantic
//! change; the compatible head remains available for decoding. This module
//! contains no policy- or query-specific vocabulary.

use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaVersionDescriptor {
    pub version: u32,
    pub(crate) implicit_predecessor: Option<u32>,
    /// `true` permits omitted sources to advance through this descriptor's
    /// compatibility lineage. `false` keeps the version available only to an
    /// exact authored pin.
    pub(crate) auto_compatible: bool,
}

impl SchemaVersionDescriptor {
    pub const fn new(
        version: u32,
        implicit_predecessor: Option<u32>,
        auto_compatible: bool,
    ) -> Self {
        Self {
            version,
            implicit_predecessor,
            auto_compatible,
        }
    }
}

/// Whether a version adds vocabulary or changes an existing construct's meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaVersionChange {
    Additive,
    Semantic,
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
pub enum SchemaVersionRegistryError {
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
pub struct UnsupportedSchemaVersion {
    pub requested: u32,
    pub supported: Vec<u32>,
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
pub struct SchemaVersionRegistry {
    descriptors: HashMap<u32, SchemaVersionDescriptor>,
    implicit_head: u32,
    changes: HashMap<u32, SchemaVersionChange>,
    supported_versions: Vec<u32>,
}

impl SchemaVersionRegistry {
    pub fn new(
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
            if descriptor.auto_compatible && !predecessor_descriptor.auto_compatible {
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
            .filter(|descriptor| descriptor.auto_compatible)
            .filter_map(|descriptor| descriptor.implicit_predecessor)
            .collect::<HashSet<_>>();
        let mut implicit_heads = descriptors
            .iter()
            .filter(|descriptor| {
                descriptor.auto_compatible && !implicit_predecessors.contains(&descriptor.version)
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
            // Formats that do not opt into construct-based inference retain
            // their existing latest-compatible behavior.
            changes: descriptors
                .iter()
                .map(|d| (d.version, SchemaVersionChange::Semantic))
                .collect(),
            supported_versions,
        })
    }

    /// Declare every version's inference effect at registry construction.
    /// This immutable format metadata is shared by all documents; it stores
    /// no workspace facts or per-document results.
    pub fn with_changes(mut self, changes: &[(u32, SchemaVersionChange)]) -> Self {
        assert_eq!(
            changes.len(),
            self.descriptors.len(),
            "every schema version needs one change declaration: changes={changes:?}, versions={:?}",
            self.supported_versions
        );
        let mut declared = HashMap::with_capacity(changes.len());
        for &(version, change) in changes {
            assert!(
                self.descriptors.contains_key(&version),
                "unknown schema version {version}"
            );
            assert!(
                declared.insert(version, change).is_none(),
                "duplicate schema change declaration for {version}"
            );
        }
        self.changes = declared;
        self
    }

    /// Infer the lowest compatible version admitting a document's constructs,
    /// without crossing the last change to existing semantics. Exact authored
    /// pins still use `resolve` and are checked by the format's decoder.
    pub fn infer_for_constructs(
        &self,
        required_version: u32,
    ) -> Result<SchemaVersionResolution, UnsupportedSchemaVersion> {
        let mut lineage = Vec::new();
        let mut semantic_floor = None;
        let mut version = self.implicit_head;
        loop {
            if semantic_floor.is_none() && self.changes[&version] == SchemaVersionChange::Semantic {
                semantic_floor = Some(lineage.len());
            }
            lineage.push(version);
            let Some(predecessor) = self.descriptors[&version].implicit_predecessor else {
                break;
            };
            version = predecessor;
        }
        // Numeric ordering alone cannot prove vocabulary inheritance: an
        // explicit-only sibling may have a smaller number than this head.
        // Keep the full lineage so constructs predating the semantic floor
        // still admit a descendant at that floor.
        let required_position = lineage
            .iter()
            .position(|version| *version == required_version)
            .ok_or_else(|| UnsupportedSchemaVersion {
                requested: required_version,
                supported: self.supported_versions.clone(),
            })?;
        let floor_position = semantic_floor.unwrap_or(lineage.len() - 1);
        let version = *lineage[..=required_position.min(floor_position)]
            .iter()
            .min()
            .expect("the implicit lineage contains at least its head");
        Ok(SchemaVersionResolution {
            version,
            origin: SchemaVersionOrigin::ImplicitCompatible,
        })
    }

    pub fn resolve(
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

    const ROOT: SchemaVersionDescriptor = SchemaVersionDescriptor::new(2, None, true);

    fn descriptor(
        version: u32,
        predecessor: Option<u32>,
        auto_compatible: bool,
    ) -> SchemaVersionDescriptor {
        SchemaVersionDescriptor::new(version, predecessor, auto_compatible)
    }

    #[test]
    fn explicit_only_nodes_do_not_hide_predecessor_cycles() {
        let error = SchemaVersionRegistry::new(&[
            descriptor(1, None, true),
            descriptor(2, Some(3), false),
            descriptor(3, Some(2), true),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::PredecessorCycle { version: 2 }
        );
    }

    #[test]
    fn forked_implicit_lineages_are_rejected() {
        let error = SchemaVersionRegistry::new(&[
            ROOT,
            descriptor(3, Some(2), true),
            descriptor(4, Some(2), true),
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
            descriptor(3, Some(2), false),
            descriptor(4, Some(3), true),
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
        let registry = SchemaVersionRegistry::new(&[ROOT, descriptor(3, Some(2), true)]).unwrap();

        assert_eq!(registry.resolve(None).unwrap().version, 3);
        assert_eq!(registry.resolve(Some(2)).unwrap().version, 2);
    }

    #[test]
    fn explicit_only_successor_never_becomes_the_implicit_head() {
        let registry = SchemaVersionRegistry::new(&[
            ROOT,
            descriptor(3, Some(2), true),
            descriptor(4, Some(3), false),
        ])
        .unwrap();

        assert_eq!(registry.resolve(None).unwrap().version, 3);
        assert_eq!(registry.resolve(Some(4)).unwrap().version, 4);
    }

    #[test]
    fn unsupported_explicit_version_does_not_fall_back() {
        let registry = SchemaVersionRegistry::new(&[ROOT, descriptor(3, Some(2), false)]).unwrap();

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
        let error = SchemaVersionRegistry::new(&[descriptor(2, Some(1), true)]).unwrap_err();

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
            descriptor(1, Some(2), true),
            descriptor(2, Some(1), true),
        ])
        .unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::PredecessorCycle { version: 1 }
        );
    }

    #[test]
    fn registry_requires_an_implicit_head() {
        let error = SchemaVersionRegistry::new(&[descriptor(2, None, false)]).unwrap_err();

        assert_eq!(error, SchemaVersionRegistryError::NoImplicitHead);
    }

    #[test]
    fn independent_implicit_lineages_are_rejected() {
        let error = SchemaVersionRegistry::new(&[ROOT, descriptor(3, None, true)]).unwrap_err();

        assert_eq!(
            error,
            SchemaVersionRegistryError::MultipleImplicitHeads {
                versions: vec![2, 3],
            }
        );
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11466: additive schema bumps rotated untouched unpinned policy identities"
    )]
    fn construct_inference_preserves_additive_identity_and_respects_semantic_floors() {
        let descriptors = [descriptor(1, None, true), descriptor(2, Some(1), true)];
        let additive = SchemaVersionRegistry::new(&descriptors)
            .unwrap()
            .with_changes(&[
                (1, SchemaVersionChange::Additive),
                (2, SchemaVersionChange::Additive),
            ]);
        assert_eq!(additive.infer_for_constructs(1).unwrap().version, 1);
        assert_eq!(additive.infer_for_constructs(2).unwrap().version, 2);
        assert_eq!(
            additive.resolve(Some(1)).unwrap().origin,
            SchemaVersionOrigin::Explicit
        );
        assert_eq!(additive.resolve(Some(1)).unwrap().version, 1);
        assert_eq!(additive.infer_for_constructs(3).unwrap_err().requested, 3);
        // The ordinary resolver remains available to decode new vocabulary
        // before the format determines which constructs a document uses.
        assert_eq!(additive.resolve(None).unwrap().version, 2);
        let semantic = SchemaVersionRegistry::new(&[
            descriptor(1, None, true),
            descriptor(2, Some(1), true),
            descriptor(3, Some(2), true),
            descriptor(4, Some(3), true),
            descriptor(5, Some(4), false),
        ])
        .unwrap()
        .with_changes(&[
            (1, SchemaVersionChange::Additive),
            (2, SchemaVersionChange::Additive),
            (3, SchemaVersionChange::Semantic),
            (4, SchemaVersionChange::Additive),
            (5, SchemaVersionChange::Semantic),
        ]);
        assert_eq!(semantic.infer_for_constructs(1).unwrap().version, 3);
        assert_eq!(semantic.infer_for_constructs(4).unwrap().version, 4);
        assert_eq!(semantic.infer_for_constructs(5).unwrap_err().requested, 5);
        assert_eq!(semantic.resolve(Some(1)).unwrap().version, 1);
        assert_eq!(semantic.resolve(Some(5)).unwrap().version, 5);
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0a7a9bf724bd: numeric inference admitted constructs from an explicit-only sibling"
    )]
    fn construct_inference_requires_vocabulary_on_the_compatible_lineage() {
        let registry = SchemaVersionRegistry::new(&[
            descriptor(1, None, true),
            descriptor(2, Some(1), false),
            descriptor(3, Some(1), true),
            descriptor(4, Some(3), true),
        ])
        .unwrap()
        .with_changes(&[
            (1, SchemaVersionChange::Additive),
            (2, SchemaVersionChange::Additive),
            (3, SchemaVersionChange::Additive),
            (4, SchemaVersionChange::Additive),
        ]);
        assert_eq!(registry.infer_for_constructs(1).unwrap().version, 1);
        assert_eq!(registry.infer_for_constructs(2).unwrap_err().requested, 2);
        assert_eq!(registry.infer_for_constructs(3).unwrap().version, 3);
        assert_eq!(registry.infer_for_constructs(4).unwrap().version, 4);
        assert_eq!(registry.resolve(Some(2)).unwrap().version, 2);
    }
}
