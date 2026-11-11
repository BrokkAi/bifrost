//! Resolved Cargo identities retained only for one in-memory activation.
//! The sole production caller of `from_cargo_resolve` is Rust dependency discovery.

use std::collections::{BTreeMap, BTreeSet};

use super::SemanticModelActivationEvidence;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CargoPackageId(pub String);

impl CargoPackageId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CargoSelectedPackageIdentity {
    pub package_id: CargoPackageId,
    pub configuration: Option<String>,
    pub target: Option<String>,
}

impl CargoSelectedPackageIdentity {
    pub fn as_str(&self) -> &str {
        self.package_id.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ScopedEdge {
    source: CargoSelectedPackageIdentity,
    dependency_name: String,
    target: CargoSelectedPackageIdentity,
    target_crate_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RustCargoArtifactTuple {
    pub version: String,
    pub resolved_features: Vec<String>,
    pub artifact_features: Vec<String>,
    pub target: String,
    pub toolchain: String,
    pub format_version: u32,
    pub sha256: String,
    pub exact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CargoResolveEdge {
    pub source: CargoPackageId,
    pub dependency_name: String,
    pub target: CargoPackageId,
}

#[derive(Clone, Debug)]
pub struct CargoSelectedPackage {
    pub evidence: SemanticModelActivationEvidence,
    pub package_id: CargoPackageId,
    pub artifact: RustCargoArtifactTuple,
}

/// A typed, non-deserializable view supplied by Cargo metadata discovery.
#[derive(Clone, Debug)]
pub struct CargoResolveView {
    selected: Vec<CargoSelectedPackage>,
    edges: Vec<ScopedEdge>,
}

impl CargoResolveView {
    pub fn from_rows(selected: Vec<CargoSelectedPackage>, edges: Vec<CargoResolveEdge>) -> Self {
        let crate_names = selected
            .iter()
            .filter_map(|row| {
                row.evidence
                    .module
                    .as_ref()
                    .map(|module| (row.package_id.clone(), module.name.clone()))
            })
            .collect();
        Self::from_rows_with_crate_names(selected, edges, crate_names)
    }

    pub fn from_rows_with_crate_names(
        selected: Vec<CargoSelectedPackage>,
        edges: Vec<CargoResolveEdge>,
        crate_names: BTreeMap<CargoPackageId, String>,
    ) -> Self {
        let scopes: BTreeSet<_> = selected
            .iter()
            .map(|row| {
                (
                    row.evidence.configuration.clone(),
                    row.evidence.target.clone(),
                )
            })
            .collect();
        assert!(
            scopes.len() <= 1,
            "one Cargo resolve view must describe one selected graph"
        );
        let edges = scopes
            .into_iter()
            .flat_map(|(configuration, target)| {
                let crate_names = &crate_names;
                edges.iter().map(move |edge| ScopedEdge {
                    source: CargoSelectedPackageIdentity {
                        package_id: edge.source.clone(),
                        configuration: configuration.clone(),
                        target: target.clone(),
                    },
                    dependency_name: edge.dependency_name.clone(),
                    target_crate_name: crate_names.get(&edge.target).cloned(),
                    target: CargoSelectedPackageIdentity {
                        package_id: edge.target.clone(),
                        configuration: configuration.clone(),
                        target: target.clone(),
                    },
                })
            })
            .collect();
        Self { selected, edges }
    }

    pub fn extend(&mut self, mut other: Self) {
        self.selected.append(&mut other.selected);
        self.edges.append(&mut other.edges);
    }

    pub fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CargoGraphError {
    OrphanEvidence,
    AmbiguousEvidence,
    MissingDependency,
    AmbiguousDependency,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedCargoGraph {
    selected: BTreeMap<
        SemanticModelActivationEvidence,
        (CargoSelectedPackageIdentity, RustCargoArtifactTuple),
    >,
    edges: Vec<ScopedEdge>,
}

impl RustSelectedCargoGraph {
    /// Discovery-only constructor. Config, packs, and MCP payloads cannot deserialize this type.
    pub fn from_cargo_resolve(mut view: CargoResolveView) -> Result<Self, CargoGraphError> {
        let mut selected = BTreeMap::new();
        for mut row in view.selected.drain(..) {
            row.artifact.resolved_features.sort();
            row.artifact.resolved_features.dedup();
            row.artifact.artifact_features.sort();
            row.artifact.artifact_features.dedup();
            let key = evidence_graph_key(&row.evidence);
            let value = (
                CargoSelectedPackageIdentity {
                    package_id: row.package_id,
                    configuration: row.evidence.configuration.clone(),
                    target: row.evidence.target.clone(),
                },
                row.artifact,
            );
            match selected.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(value);
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &value => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(CargoGraphError::AmbiguousEvidence);
                }
            }
        }
        let mut by_package = BTreeMap::new();
        for (package_id, tuple) in selected.values() {
            if by_package
                .insert(package_id, tuple)
                .is_some_and(|prior| prior != tuple)
            {
                return Err(CargoGraphError::AmbiguousEvidence);
            }
        }
        view.edges.sort();
        view.edges.dedup();
        Ok(Self {
            selected,
            edges: view.edges,
        })
    }

    #[cfg(test)]
    fn project_edges(edges: &[ScopedEdge]) -> Vec<CargoResolveEdge> {
        let mut projected: Vec<_> = edges
            .iter()
            .map(|edge| CargoResolveEdge {
                source: edge.source.package_id.clone(),
                dependency_name: edge.dependency_name.clone(),
                target: edge.target.package_id.clone(),
            })
            .collect();
        projected.sort();
        projected.dedup();
        projected
    }

    /// Retain only packs admitted by preparation. Missing hops then abstain.
    pub fn retain_evidence(&mut self, evidence: &[SemanticModelActivationEvidence]) {
        let present: BTreeSet<_> = evidence.iter().map(evidence_graph_key).collect();
        self.selected.retain(|key, _| present.contains(key));
        // Keep all selected resolve edges, including an unavailable target:
        // it may be a competing platform-specific version of the crate.
    }

    pub fn validate_evidence(
        &self,
        evidence: &[SemanticModelActivationEvidence],
    ) -> Result<(), CargoGraphError> {
        let present: BTreeSet<_> = evidence.iter().map(evidence_graph_key).collect();
        if self.selected.keys().any(|key| !present.contains(key)) {
            return Err(CargoGraphError::OrphanEvidence);
        }
        Ok(())
    }

    pub fn package_for_evidence(
        &self,
        evidence: &SemanticModelActivationEvidence,
    ) -> Option<&CargoSelectedPackageIdentity> {
        self.selected
            .get(&evidence_graph_key(evidence))
            .map(|(id, _)| id)
    }

    #[cfg(test)]
    fn defining_package(
        &self,
        source: &CargoSelectedPackageIdentity,
        dependency_name: &str,
    ) -> Result<&CargoSelectedPackageIdentity, CargoGraphError> {
        if self.artifact_tuple(source).is_none() {
            return Err(CargoGraphError::MissingDependency);
        }
        let mut targets = self
            .edges
            .iter()
            .filter(|edge| &edge.source == source && edge.dependency_name == dependency_name)
            .map(|edge| &edge.target);
        let target = targets.next().ok_or(CargoGraphError::MissingDependency)?;
        if targets.any(|other| other != target) {
            return Err(CargoGraphError::AmbiguousDependency);
        }
        self.selected
            .values()
            .find(|(id, _)| id == target)
            .map(|(id, _)| id)
            .ok_or(CargoGraphError::MissingDependency)
    }

    pub fn defining_package_for_crate(
        &self,
        source: &CargoSelectedPackageIdentity,
        external_crate_name: &str,
    ) -> Result<&CargoSelectedPackageIdentity, CargoGraphError> {
        if !self.selected.values().any(|(id, _)| id == source) {
            return Err(CargoGraphError::MissingDependency);
        }
        let mut matches = self
            .edges
            .iter()
            .filter(|edge| &edge.source == source)
            .filter_map(|edge| {
                self.selected
                    .iter()
                    .find(|(evidence, (id, _))| {
                        id == &edge.target
                            && evidence
                                .module
                                .as_ref()
                                .is_some_and(|module| module.name == external_crate_name)
                    })
                    .map(|(_, (id, _))| id)
            });
        let result = matches.next().ok_or(CargoGraphError::MissingDependency)?;
        if matches.next().is_some() {
            return Err(CargoGraphError::AmbiguousDependency);
        }
        if self.edges.iter().any(|edge| {
            &edge.source == source
                && self.artifact_tuple(&edge.target).is_none()
                && edge
                    .target_crate_name
                    .as_deref()
                    .is_none_or(|name| name == external_crate_name)
        }) {
            return Err(CargoGraphError::AmbiguousDependency);
        }
        Ok(result)
    }

    pub fn artifact_tuple(
        &self,
        package: &CargoSelectedPackageIdentity,
    ) -> Option<&RustCargoArtifactTuple> {
        self.selected
            .values()
            .find(|(id, _)| id == package)
            .map(|(_, tuple)| tuple)
    }

    /// Cargo aliases into one selected target, including workspace consumer edges.
    pub fn incoming_dependency_names(&self, target: &CargoSelectedPackageIdentity) -> Vec<&str> {
        if self.artifact_tuple(target).is_none() {
            return Vec::new();
        }
        let mut names: Vec<_> = self
            .edges
            .iter()
            .filter(|edge| &edge.target == target)
            .map(|edge| edge.dependency_name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    #[cfg(test)]
    fn canonical_edges_for(&self, package: &CargoSelectedPackageIdentity) -> Vec<CargoResolveEdge> {
        let edges: Vec<_> = self
            .edges
            .iter()
            .filter(|edge| &edge.source == package)
            .cloned()
            .collect();
        Self::project_edges(&edges)
    }

    /// Sorted scoped edges; identity hashing can merge-walk them with packages.
    pub fn scoped_edge_names(
        &self,
    ) -> impl Iterator<Item = (&CargoSelectedPackageIdentity, &str, &str, Option<&str>)> {
        self.edges.iter().map(|edge| {
            (
                &edge.source,
                edge.dependency_name.as_str(),
                edge.target.as_str(),
                edge.target_crate_name.as_deref(),
            )
        })
    }

    #[cfg(test)]
    pub fn canonical_edges(&self) -> Vec<CargoResolveEdge> {
        Self::project_edges(&self.edges)
    }

    /// Lower bound for the graph's owned allocations retained by an overlay.
    pub fn retained_bytes_lower_bound(&self) -> usize {
        let mut bytes = std::mem::size_of::<Self>()
            .saturating_add(self.selected.len().saturating_mul(std::mem::size_of::<(
                SemanticModelActivationEvidence,
                (CargoSelectedPackageIdentity, RustCargoArtifactTuple),
            )>()))
            .saturating_add(
                self.edges
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScopedEdge>()),
            );
        for (evidence, (id, tuple)) in &self.selected {
            bytes = bytes
                .saturating_add(evidence.language.capacity())
                .saturating_add(evidence.ecosystem.capacity())
                .saturating_add(
                    evidence
                        .package
                        .as_ref()
                        .map_or(0, |coordinate| coordinate.name.capacity()),
                )
                .saturating_add(
                    evidence
                        .module
                        .as_ref()
                        .map_or(0, |coordinate| coordinate.name.capacity()),
                )
                .saturating_add(
                    evidence
                        .toolchain
                        .as_ref()
                        .map_or(0, |coordinate| coordinate.name.capacity()),
                )
                .saturating_add(evidence.target.as_ref().map_or(0, String::capacity))
                .saturating_add(evidence.configuration.as_ref().map_or(0, String::capacity))
                .saturating_add(
                    evidence
                        .artifact_sha256
                        .as_ref()
                        .map_or(0, String::capacity),
                )
                .saturating_add(id.package_id.0.capacity())
                .saturating_add(id.configuration.as_ref().map_or(0, String::capacity))
                .saturating_add(id.target.as_ref().map_or(0, String::capacity))
                .saturating_add(tuple.version.capacity())
                .saturating_add(tuple.target.capacity())
                .saturating_add(tuple.toolchain.capacity())
                .saturating_add(tuple.sha256.capacity())
                .saturating_add(
                    tuple
                        .resolved_features
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>()),
                )
                .saturating_add(
                    tuple
                        .artifact_features
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>()),
                );
            for feature in tuple
                .resolved_features
                .iter()
                .chain(&tuple.artifact_features)
            {
                bytes = bytes.saturating_add(feature.capacity());
            }
        }
        for edge in &self.edges {
            bytes = bytes
                .saturating_add(edge.source.package_id.0.capacity())
                .saturating_add(
                    edge.source
                        .configuration
                        .as_ref()
                        .map_or(0, String::capacity),
                )
                .saturating_add(edge.source.target.as_ref().map_or(0, String::capacity))
                .saturating_add(edge.dependency_name.capacity())
                .saturating_add(edge.target_crate_name.as_ref().map_or(0, String::capacity))
                .saturating_add(edge.target.package_id.0.capacity())
                .saturating_add(
                    edge.target
                        .configuration
                        .as_ref()
                        .map_or(0, String::capacity),
                )
                .saturating_add(edge.target.target.as_ref().map_or(0, String::capacity));
        }
        bytes
    }
}

fn evidence_graph_key(
    evidence: &SemanticModelActivationEvidence,
) -> SemanticModelActivationEvidence {
    let mut key = evidence.clone();
    // Preparation adds the generated pack's input digest after Cargo discovery.
    // Every other component of the discovery row remains the exact lookup identity.
    key.artifact_sha256 = None;
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> SemanticModelActivationEvidence {
        SemanticModelActivationEvidence {
            language: "rust".into(),
            ecosystem: "cargo".into(),
            package: None,
            module: None,
            toolchain: None,
            target: Some("x86_64-unknown-linux-gnu".into()),
            configuration: None,
            artifact_sha256: None,
        }
    }

    fn tuple() -> RustCargoArtifactTuple {
        RustCargoArtifactTuple {
            version: "1.0.0".into(),
            resolved_features: vec!["z".into(), "a".into(), "a".into()],
            artifact_features: vec!["b".into(), "a".into()],
            target: "x86_64-unknown-linux-gnu".into(),
            toolchain: "nightly".into(),
            format_version: 61,
            sha256: "abc".into(),
            exact: true,
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: canonical edges are derived from scoped edges without retained duplicate storage"
    )]
    fn canonical_edges_keep_cargo_rename_and_orphans_refuse() {
        let edge = CargoResolveEdge {
            source: CargoPackageId("facade".into()),
            dependency_name: "sqlx".into(),
            target: CargoPackageId("sqlx-core".into()),
        };
        let graph = RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
            vec![CargoSelectedPackage {
                evidence: evidence(),
                package_id: CargoPackageId("facade".into()),
                artifact: tuple(),
            }],
            vec![edge.clone(), edge],
        ))
        .unwrap();
        assert_eq!(graph.canonical_edges().len(), 1);
        assert!(graph.retained_bytes_lower_bound() > std::mem::size_of::<RustSelectedCargoGraph>());
        assert_eq!(
            graph
                .artifact_tuple(&CargoSelectedPackageIdentity {
                    package_id: CargoPackageId("facade".into()),
                    configuration: None,
                    target: evidence().target
                })
                .unwrap()
                .resolved_features,
            ["a", "z"]
        );
        assert_eq!(
            graph.validate_evidence(&[]),
            Err(CargoGraphError::OrphanEvidence)
        );
    }

    #[test]
    fn digest_projection_rejects_distinct_package_ids() {
        let mut first = evidence();
        first.artifact_sha256 = Some("a".into());
        let mut second = evidence();
        second.artifact_sha256 = Some("b".into());
        let graph = RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
            vec![
                CargoSelectedPackage {
                    evidence: first,
                    package_id: CargoPackageId("one".into()),
                    artifact: tuple(),
                },
                CargoSelectedPackage {
                    evidence: second,
                    package_id: CargoPackageId("two".into()),
                    artifact: tuple(),
                },
            ],
            Vec::new(),
        ));
        assert_eq!(graph, Err(CargoGraphError::AmbiguousEvidence));
    }

    #[test]
    fn duplicate_identical_evidence_is_canonicalized() {
        let row = CargoSelectedPackage {
            evidence: evidence(),
            package_id: CargoPackageId("same".into()),
            artifact: tuple(),
        };
        let graph = RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
            vec![row.clone(), row],
            Vec::new(),
        ))
        .unwrap();
        assert_eq!(
            graph.package_for_evidence(&evidence()).unwrap().as_str(),
            "same"
        );
    }

    #[test]
    fn duplicate_dependency_name_refuses_ambiguity() {
        let graph = RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
            vec![CargoSelectedPackage {
                evidence: evidence(),
                package_id: CargoPackageId("facade".into()),
                artifact: tuple(),
            }],
            vec![
                CargoResolveEdge {
                    source: CargoPackageId("facade".into()),
                    dependency_name: "sqlx".into(),
                    target: CargoPackageId("one".into()),
                },
                CargoResolveEdge {
                    source: CargoPackageId("facade".into()),
                    dependency_name: "sqlx".into(),
                    target: CargoPackageId("two".into()),
                },
            ],
        ))
        .unwrap();
        assert_eq!(
            graph.defining_package(
                &CargoSelectedPackageIdentity {
                    package_id: CargoPackageId("facade".into()),
                    configuration: None,
                    target: evidence().target
                },
                "sqlx"
            ),
            Err(CargoGraphError::AmbiguousDependency)
        );
    }

    fn row(configuration: &str, package: &str, crate_name: &str) -> CargoSelectedPackage {
        let mut evidence = evidence();
        evidence.configuration = Some(configuration.into());
        evidence.module = Some(super::super::CatalogCoordinate {
            name: crate_name.into(),
            version: Some(semver::Version::new(1, 0, 0)),
        });
        CargoSelectedPackage {
            evidence,
            package_id: CargoPackageId(package.into()),
            artifact: tuple(),
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: Cargo edges leaked between evidence configurations"
    )]
    fn configurations_cannot_borrow_edges_and_renames_use_selected_crate_identity() {
        let facade_a = row("A", "facade", "sqlx");
        let core_a = row("A", "core", "sqlx_core");
        let facade_b = row("B", "facade", "sqlx");
        let core_b = row("B", "core", "sqlx_core");
        let edge = CargoResolveEdge {
            source: facade_a.package_id.clone(),
            dependency_name: "renamed_core".into(),
            target: core_a.package_id.clone(),
        };
        let mut view =
            CargoResolveView::from_rows(vec![facade_a.clone(), core_a], vec![edge.clone()]);
        view.extend(CargoResolveView::from_rows(
            vec![facade_b.clone(), core_b],
            vec![],
        ));
        let graph = RustSelectedCargoGraph::from_cargo_resolve(view).unwrap();
        let a = graph.package_for_evidence(&facade_a.evidence).unwrap();
        let b = graph.package_for_evidence(&facade_b.evidence).unwrap();
        let target = graph.defining_package_for_crate(a, "sqlx_core").unwrap();
        assert_eq!(graph.incoming_dependency_names(target), ["renamed_core"]);
        assert!(graph.canonical_edges_for(b).is_empty());
        assert_eq!(target.as_str(), "core");
        assert_eq!(
            graph.defining_package_for_crate(b, "sqlx_core"),
            Err(CargoGraphError::MissingDependency)
        );
        assert_eq!(
            graph.defining_package_for_crate(a, "absent"),
            Err(CargoGraphError::MissingDependency)
        );
        let mut other = edge;
        other.dependency_name = "another_alias".into();
        let ambiguous = RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
            vec![facade_a, row("A", "core", "sqlx_core")],
            vec![
                other.clone(),
                CargoResolveEdge {
                    dependency_name: "renamed_core".into(),
                    ..other
                },
            ],
        ))
        .unwrap();
        let source = ambiguous
            .package_for_evidence(&row("A", "facade", "sqlx").evidence)
            .unwrap();
        assert_eq!(
            ambiguous.defining_package_for_crate(source, "sqlx_core"),
            Err(CargoGraphError::AmbiguousDependency)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: pending or failed Rust packs rejected unrelated available activation evidence"
    )]
    fn pending_and_failed_packs_are_pruned_without_losing_available_ecosystems() {
        for missing in ["installed-only pending", "production failed"] {
            let facade = row("A", "facade", "sqlx");
            let core = row("A", "core", "sqlx_core");
            let mut graph =
                RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
                    vec![facade.clone(), core.clone()],
                    vec![CargoResolveEdge {
                        source: facade.package_id.clone(),
                        dependency_name: "sqlx_core".into(),
                        target: core.package_id,
                    }],
                ))
                .unwrap();
            let mut unrelated = evidence();
            unrelated.language = "python".into();
            unrelated.ecosystem = "pypi".into();
            let available = vec![facade.evidence.clone(), unrelated];
            graph.retain_evidence(&available);
            assert_eq!(graph.validate_evidence(&available), Ok(()), "{missing}");
            let source = graph.package_for_evidence(&facade.evidence).unwrap();
            assert!(graph.artifact_tuple(source).is_some());
            assert_eq!(
                graph.defining_package_for_crate(source, "sqlx_core"),
                Err(CargoGraphError::MissingDependency)
            );
            assert_eq!(graph.canonical_edges().len(), 1);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#10258: a missing version of the same crate competes")]
    fn unavailable_competing_version_abstains() {
        let facade = row("A", "facade", "sqlx");
        let core_v1 = row("A", "core-v1", "sqlx_core");
        let mut core_v2 = row("A", "core-v2", "sqlx_core");
        core_v2.evidence.module.as_mut().unwrap().version = Some(semver::Version::new(2, 0, 0));
        core_v2.artifact.version = "2.0.0".into();
        let mut graph = RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
            vec![facade.clone(), core_v1.clone(), core_v2.clone()],
            [core_v1.package_id.clone(), core_v2.package_id.clone()]
                .into_iter()
                .map(|target| CargoResolveEdge {
                    source: facade.package_id.clone(),
                    dependency_name: "sqlx_core".into(),
                    target,
                })
                .collect(),
        ))
        .unwrap();
        graph.retain_evidence(&[facade.evidence.clone(), core_v1.evidence.clone()]);
        let source = graph.package_for_evidence(&facade.evidence).unwrap();
        assert_eq!(
            graph.defining_package_for_crate(source, "sqlx_core"),
            Err(CargoGraphError::AmbiguousDependency)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: unrelated missing Cargo artifacts do not block the facade"
    )]
    fn unrelated_missing_dependencies_do_not_compete() {
        let facade = row("A", "facade", "sqlx");
        let core = row("A", "core", "sqlx_core");
        let mut edges = vec![CargoResolveEdge {
            source: facade.package_id.clone(),
            dependency_name: "core".into(),
            target: core.package_id.clone(),
        }];
        let mut names = BTreeMap::from([(core.package_id.clone(), "sqlx_core".into())]);
        for index in 0..64 {
            let id = CargoPackageId(format!("unrelated-{index}"));
            names.insert(id.clone(), format!("other_{index}"));
            edges.push(CargoResolveEdge {
                source: facade.package_id.clone(),
                dependency_name: format!("other_{index}"),
                target: id,
            });
        }
        let graph = RustSelectedCargoGraph::from_cargo_resolve(
            CargoResolveView::from_rows_with_crate_names(
                vec![facade.clone(), core.clone()],
                edges,
                names,
            ),
        )
        .unwrap();
        let source = graph.package_for_evidence(&facade.evidence).unwrap();
        assert_eq!(
            graph
                .defining_package_for_crate(source, "sqlx_core")
                .unwrap()
                .package_id,
            core.package_id
        );
    }

    #[test]
    fn retained_bytes_charge_scoped_and_canonical_edge_allocations() {
        let make = |scope: &str, name: &str| {
            let facade = row(scope, "facade", "sqlx");
            let core = row(scope, "core", "sqlx_core");
            RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
                vec![facade.clone(), core.clone()],
                vec![CargoResolveEdge {
                    source: facade.package_id,
                    dependency_name: name.into(),
                    target: core.package_id,
                }],
            ))
            .unwrap()
        };
        let small = make("A", "x");
        let large = make(&"C".repeat(512), &"n".repeat(1024));
        assert!(
            large.retained_bytes_lower_bound()
                >= small.retained_bytes_lower_bound() + 2046 + 512 * 3,
            "both edge copies and scoped identities must be charged"
        );
    }

    #[test]
    fn graph_constructor_is_only_called_from_rust_discovery() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut callers = Vec::new();
        fn scan(path: &std::path::Path, callers: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    scan(&path, callers);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let content = std::fs::read_to_string(&path).unwrap();
                    let call = "RustSelectedCargoGraph::from_cargo_resolve(";
                    let count = content.matches(call).count();
                    if path.ends_with("rust_cargo_graph.rs") {
                        continue; // Constructor unit tests live here.
                    }
                    if path.ends_with("bifrost-analysis/src/analyzer/semantic_model/runtime.rs") {
                        // Four test fixtures exercise carried and hashed graphs.
                        assert_eq!(count, 4);
                        let first = content.find(call).expect("test constructor calls exist");
                        assert!(content[..first].contains("#[cfg(test)]"));
                        continue;
                    }
                    for _ in 0..count {
                        callers.push(path.clone());
                    }
                }
            }
        }
        for entry in std::fs::read_dir(root).unwrap() {
            let src = entry.unwrap().path().join("src");
            if src.is_dir() {
                scan(&src, &mut callers);
            }
        }
        assert_eq!(callers.len(), 1, "constructor callers: {callers:?}");
        assert!(
            callers[0].ends_with("rust/dependency_discovery.rs"),
            "{callers:?}"
        );
    }
}
