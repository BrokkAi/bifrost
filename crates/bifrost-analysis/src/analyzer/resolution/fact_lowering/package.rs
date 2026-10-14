//! Protected package membership paths. These stacks cannot match external exports.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoweredPackageReference {
    pub(crate) token: SemanticId,
    pub(crate) domain: SemanticId,
    pub(crate) reference: SemanticId,
    pub(crate) source_site: ResolutionSiteId,
    pub(crate) root_scope: BindingNodeId,
    pub(crate) choice: Option<SemanticId>,
    pub(crate) namespace: ResolutionNamespace,
    pub(crate) lookup: SemanticId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoweredPackageMember {
    pub(crate) token: SemanticId,
    pub(crate) domain: SemanticId,
    pub(crate) definition: SemanticId,
    pub(crate) source_site: ResolutionSiteId,
    pub(crate) root_scope: BindingNodeId,
    pub(crate) namespace: ResolutionNamespace,
    pub(crate) lookup: SemanticId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoweredGoPackageImport {
    pub(crate) definition: SemanticId,
    pub(crate) source_site: ResolutionSiteId,
    pub(crate) file_scope: BindingNodeId,
    pub(crate) spelling_choice: SemanticId,
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionGoPackageImportKind,
}

pub(crate) fn lower_import_metadata(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
) -> Vec<LoweredGoPackageImport> {
    facts
        .go_package_imports
        .iter()
        .map(|import| {
            assert_eq!(language, Language::Go);
            let site = facts.sites[import.import_site.index()];
            LoweredGoPackageImport {
                definition: identities.source_definition_semantic(import.import_site),
                source_site: import.import_site,
                file_scope: identities.source_scope_node(import.file_scope),
                // This semantic is already used by the file's outward rank-one
                // path. Metadata does not register an un-emitted rank-zero step.
                spelling_choice: identities
                    .semantic(go_spelling_choice_identity(import.file_scope, None)),
                start_byte: site.start_byte,
                end_byte: site.end_byte,
                kind: import.kind,
            }
        })
        .collect()
}

pub(super) fn lower_import_definitions(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
    nodes: &mut Vec<(BindingNodeId, BindingNodeKind)>,
    semantics: &mut Vec<LoweredSemanticSite>,
) {
    for import in &facts.go_package_imports {
        assert_eq!(language, Language::Go);
        let definition = identities.source_definition_semantic(import.import_site);
        let node = identities.source_definition_node(import.import_site);
        nodes.push((node, BindingNodeKind::Definition(definition)));
        semantics.push(
            LoweredSemanticSite::new(
                import.import_site,
                ResolutionNamespace::Package,
                LoweredSemanticRole::Definition,
                definition,
                node,
                None,
            )
            .with_go_definition_namespaces(Some(
                super::super::model::GoDefinitionNamespaces::from_bits(8),
            )),
        );
    }
}

fn domain(identities: &mut ResolutionIdentityCatalogBuilder, language: Language) -> SemanticId {
    identities.shared_name(package_domain_digest(language))
}

pub(crate) fn package_domain_semantic(
    language: Language,
    names: &dyn super::super::local_identity::SharedNameInterner,
) -> SemanticId {
    SemanticId::shared_name(names.intern(package_domain_digest(language)))
}

fn package_domain_digest(language: Language) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-package-domain:v1");
    hasher.field("language", language.config_label().as_bytes());
    hasher.finish()
}

fn token(
    identities: &mut ResolutionIdentityCatalogBuilder,
    domain: &[u8],
    coordinate: u32,
    namespace: ResolutionNamespace,
) -> SemanticId {
    identities.semantic(ResolutionSemanticIdentity::fragment_local(local_digest(
        domain,
        &[
            ("coordinate", &u32_bytes(coordinate)),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    )))
}

fn package_reference_group_digest(
    domain: &[u8],
    root_scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
    lookup_digest: [u8; 32],
) -> [u8; 32] {
    let root_scope = super::scope_head_node_identity(root_scope).digest();
    local_digest(
        domain,
        &[
            ("root_scope", &root_scope),
            ("namespace", namespace.identity_label().as_bytes()),
            ("lookup", &lookup_digest),
        ],
    )
}

fn package_reference_path_group_digest(
    root_scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
    lookup_digest: [u8; 32],
    choice_digest: [u8; 32],
    precedence_ordinal: u32,
) -> [u8; 32] {
    let root_scope = super::scope_head_node_identity(root_scope).digest();
    local_digest(
        b"bifrost-resolution-package-reference-path-group:v3",
        &[
            ("root_scope", &root_scope),
            ("namespace", namespace.identity_label().as_bytes()),
            ("lookup", &lookup_digest),
            ("choice", &choice_digest),
            ("precedence", &u32_bytes(precedence_ordinal)),
        ],
    )
}

pub(crate) fn lower_metadata(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
) -> (Vec<LoweredPackageReference>, Vec<LoweredPackageMember>) {
    if facts.package_references.is_empty()
        && facts.package_members.is_empty()
        && facts.package_object_exports.is_empty()
    {
        return (Vec::new(), Vec::new());
    }
    facts.validate_package_relations();
    let index = FactIndex::new(language, facts);
    let domain = domain(identities, language);
    let mut references = Vec::new();
    for fact in &facts.package_references {
        let identifier = index.identifiers_by_site[&fact.reference]
            .iter()
            .find(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .expect("validated package reference");
        for &namespace in namespaces(language, identifier.namespace) {
            let spelling = index.name(identifier.name);
            references.push(LoweredPackageReference {
                token: identities.semantic(ResolutionSemanticIdentity::fragment_local(
                    package_reference_group_digest(
                        b"bifrost-resolution-package-reference-token:v2",
                        fact.root_scope,
                        namespace,
                        ResolutionLookupSemanticRecipe::new(language, namespace, spelling)
                            .name_digest(),
                    ),
                )),
                domain,
                reference: identities.source_reference_semantic(fact.reference),
                source_site: fact.reference,
                root_scope: identities.source_scope_node(fact.root_scope),
                choice: Some(
                    identities.semantic(scope_choice_identity(fact.root_scope, namespace)),
                ),
                namespace,
                lookup: identities.lookup_semantic(language, namespace, spelling),
            });
        }
    }
    let mut members: Vec<LoweredPackageMember> = facts
        .package_members
        .iter()
        .map(|fact| {
            let identifier = index.declaration_identifier(fact.declaration);
            LoweredPackageMember {
                token: token(
                    identities,
                    b"bifrost-resolution-package-member-token:v1",
                    fact.root_scope.get(),
                    fact.namespace,
                ),
                domain,
                definition: identities.source_definition_semantic(fact.declaration),
                source_site: fact.declaration,
                root_scope: identities.source_scope_node(fact.root_scope),
                namespace: fact.namespace,
                lookup: identities.lookup_semantic(
                    language,
                    fact.namespace,
                    index.name(identifier.name),
                ),
            }
        })
        .collect();
    for export in &facts.package_object_exports {
        assert_eq!(
            facts.scopes[export.package_scope.index()].kind,
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind::Package,
            "package-object exports attach to a package scope"
        );
        assert!(
            facts
                .identifiers
                .iter()
                .any(|identifier| identifier.site == export.package_object
                    && identifier.role == ResolutionIdentifierRole::Declaration),
            "package-object exports identify their package object declaration"
        );
        let member = index.declaration_identifier(export.member);
        let mut namespaces = vec![member.namespace];
        namespaces.extend(
            facts
                .additional_definition_namespaces
                .iter()
                .filter(|fact| fact.declaration == export.member)
                .map(|fact| fact.namespace),
        );
        if index.value_aliased_callables.contains(&export.member) {
            namespaces.push(ResolutionNamespace::Value);
        }
        namespaces.sort_unstable();
        namespaces.dedup();
        for namespace in namespaces {
            assert!(matches!(
                namespace,
                ResolutionNamespace::Type
                    | ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
            ));
            let lookup = identities.lookup_semantic(language, namespace, index.name(member.name));
            if members.iter().any(|row: &LoweredPackageMember| {
                row.source_site == export.member && row.namespace == namespace
            }) {
                continue;
            }
            members.push(LoweredPackageMember {
                token: token(
                    identities,
                    b"bifrost-resolution-package-member-token:v1",
                    export.package_scope.get(),
                    namespace,
                ),
                domain,
                definition: identities.source_definition_semantic(export.member),
                source_site: export.member,
                root_scope: identities.source_scope_node(export.package_scope),
                namespace,
                lookup,
            });
        }
    }
    (references, members)
}

fn namespaces(
    language: Language,
    reference_namespace: ResolutionNamespace,
) -> &'static [ResolutionNamespace] {
    match (language, reference_namespace) {
        (Language::Java, ResolutionNamespace::TypeOrValue) => {
            &[ResolutionNamespace::Value, ResolutionNamespace::Type]
        }
        (Language::Java, _) => &[ResolutionNamespace::Type],
        (Language::Go, _) => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ],
        (Language::Kotlin | Language::Scala, _) => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ],
        _ => panic!("package path precedence is undefined for {language:?}"),
    }
}

pub(super) fn lower_paths(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
    reasons_by_site: &HashMap<ResolutionSiteId, Vec<(LoweringGapOrigin, SemanticId)>>,
    gap_sources: &[GapSource],
    paths: &mut Vec<(PartialPathId, PartialPath)>,
) {
    if facts.package_references.is_empty()
        && facts.package_members.is_empty()
        && facts.package_object_exports.is_empty()
    {
        return;
    }
    let (references, members) = lower_metadata(identities, language, facts);
    let index = FactIndex::new(language, facts);
    let scope_reasons = root_scope_gap_reasons(identities, &index, gap_sources);
    let mut emitted_reference_groups = HashSet::default();
    let mut reference_rows = references.iter();
    for fact in &facts.package_references {
        let identifier = index.identifiers_by_site[&fact.reference]
            .iter()
            .find(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .expect("validated package reference");
        let reference_namespaces = namespaces(language, identifier.namespace);
        for row in reference_rows.by_ref().take(reference_namespaces.len()) {
            let precedence_ordinal = if language == Language::Java
                && identifier.namespace == ResolutionNamespace::TypeOrValue
            {
                u32::try_from(
                    reference_namespaces
                        .iter()
                        .position(|namespace| *namespace == row.namespace)
                        .expect("Java type/value package route has its effective namespace"),
                )
                .expect("Java type/value package precedence fits u32")
            } else {
                0
            };
            let choice = row.choice.expect("package references have a scope choice");
            if !emitted_reference_groups.insert((
                row.root_scope,
                row.namespace,
                row.lookup,
                choice,
                precedence_ordinal,
            )) {
                continue;
            }
            let lookup_identity = identities
                .semantic_identity(row.lookup)
                .expect("package lookup has a registered identity");
            let choice_identity = identities
                .semantic_identity(choice)
                .expect("package choice has a registered identity");
            let path_digest = package_reference_path_group_digest(
                fact.root_scope,
                row.namespace,
                identities.identity_hash_bytes(lookup_identity),
                identities.identity_hash_bytes(choice_identity),
                precedence_ordinal,
            );
            let id = identities.path(ResolutionPathIdentity::new(path_digest));
            let tail = passthrough_variable(identities, id);
            paths.push((
                id,
                PartialPath::new(
                    symbol_open_endpoint(row.root_scope, [row.lookup], tail),
                    symbol_open_endpoint(
                        BindingNodeId::universal_root(),
                        [row.domain, row.token, row.lookup],
                        tail,
                    ),
                    package_precedence(
                        identities,
                        language,
                        fact.root_scope,
                        row.namespace,
                        choice,
                        precedence_ordinal,
                    ),
                    [WitnessStep::Node(row.root_scope)],
                    ResolutionCompletion::Complete,
                ),
            ));
        }
    }
    assert!(reference_rows.next().is_none());
    for row in members {
        let id = identities.path(ResolutionPathIdentity::new(local_digest(
            b"bifrost-resolution-package-member-path:v1",
            &[
                ("site", &u32_bytes(row.source_site.get())),
                ("namespace", row.namespace.identity_label().as_bytes()),
            ],
        )));
        let tail = passthrough_variable(identities, id);
        let definition = identities.source_definition_node(row.source_site);
        paths.push((
            id,
            PartialPath::new(
                symbol_open_endpoint(
                    BindingNodeId::universal_root(),
                    [row.lookup, row.domain, row.token],
                    tail,
                ),
                symbol_open_endpoint(definition, [], tail),
                [],
                [WitnessStep::Node(definition)],
                // Package membership establishes the same lexical declaration
                // as its ordinary binder. Constructor, hierarchy and access
                // obligations belong to their typed/contextual consumers, not
                // every auxiliary reverse walk through this package member.
                completion_for_site(reasons_by_site, row.source_site, lexical_declaration_gap)
                    .combine(
                        &scope_reasons
                            .get(&index.site(row.source_site).scope)
                            .map_or(ResolutionCompletion::Complete, |reasons| {
                                ResolutionCompletion::incomplete(reasons.iter().copied())
                            }),
                    ),
            ),
        ));
    }
}

fn package_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
    choice: SemanticId,
    ordinal: u32,
) -> Vec<PrecedenceStep> {
    let mut precedence = match language {
        Language::Go => {
            assert_eq!(ordinal, 0);
            go_spelling_precedence(identities, scope, None, 0)
        }
        Language::Java => {
            vec![identities.register_precedence_namespace(
                PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal,
                    semantic: choice,
                },
                namespace,
            )]
        }
        Language::Kotlin => {
            assert_eq!(ordinal, 0);
            vec![identities.register_precedence_namespace(
                PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal: 0,
                    semantic: choice,
                },
                namespace,
            )]
        }
        Language::Scala => {
            assert_eq!(ordinal, 0);
            vec![identities.register_precedence_namespace(
                PrecedenceStep {
                    tier: PrecedenceTier::OtherCompilationUnitPackage,
                    ordinal: 0,
                    semantic: choice,
                },
                namespace,
            )]
        }
        _ => panic!("package path precedence is undefined for {language:?}"),
    };
    let origin = if language == Language::Scala {
        BindingOrigin::OtherCompilationUnitPackage
    } else {
        BindingOrigin::SameCompilationUnitPackage
    };
    if let Some(ordinal) = binding_origin_rank(language, origin) {
        precedence.push(identities.register_precedence_namespace(
            PrecedenceStep {
                tier: PrecedenceTier::CandidateOriginRank,
                ordinal,
                semantic: choice,
            },
            namespace,
        ));
    }
    precedence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::go::GoAdapter;
    use crate::analyzer::kotlin::KotlinAdapter;
    use crate::analyzer::resolution::{
        BatchResolutionEngine, LoweredResolutionFactsWithIdentityCatalog, PreloadedFragmentSource,
        ResolutionQuery, lower_for_test,
    };
    use crate::analyzer::scala::ScalaAdapter;
    use crate::analyzer::{LanguageAdapter, ProjectFile};
    use std::collections::{BTreeMap, BTreeSet};

    fn parsed(
        label: &str,
        source: &str,
    ) -> (
        FileResolutionFacts,
        LoweredResolutionFactsWithIdentityCatalog,
    ) {
        let file = ProjectFile::new(std::env::temp_dir(), format!("{label}.go"));
        let adapter = GoAdapter;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = adapter.parse_file(&file, source, &tree).resolution_facts;
        let artifact = lower_for_test(BindingFragmentId::for_test(label), Language::Go, &facts);
        (facts, artifact)
    }

    fn parsed_scala(
        label: &str,
        source: &str,
    ) -> (
        FileResolutionFacts,
        LoweredResolutionFactsWithIdentityCatalog,
    ) {
        let file = ProjectFile::new(std::env::temp_dir(), format!("{label}.scala"));
        let adapter = ScalaAdapter;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = adapter.parse_file(&file, source, &tree).resolution_facts;
        let artifact = lower_for_test(BindingFragmentId::for_test(label), Language::Scala, &facts);
        (facts, artifact)
    }

    fn parsed_kotlin(
        label: &str,
        source: &str,
    ) -> (
        FileResolutionFacts,
        LoweredResolutionFactsWithIdentityCatalog,
    ) {
        let file = ProjectFile::new(std::env::temp_dir(), format!("{label}.kt"));
        let adapter = KotlinAdapter;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = adapter.parse_file(&file, source, &tree).resolution_facts;
        let artifact = lower_for_test(BindingFragmentId::for_test(label), Language::Kotlin, &facts);
        (facts, artifact)
    }

    /// A context's independent assertion that two files share one selected
    /// package. No language spelling, visibility or precedence is added here.
    fn bridge(
        caller: &mut LoweredResolutionFactsWithIdentityCatalog,
        provider: &LoweredResolutionFactsWithIdentityCatalog,
    ) {
        for reference in &caller.common.package_references {
            for member in &provider.common.package_members {
                if reference.lookup != member.lookup {
                    continue;
                }
                assert_eq!(reference.domain, member.domain);
                let label = format!("package-bridge-{}-{}", reference.token, member.definition);
                let tail = StackVariableId::for_test(label.as_bytes());
                caller.lexical.paths.push((
                    PartialPathId::for_test(label),
                    PartialPath::new(
                        symbol_open_endpoint(
                            BindingNodeId::universal_root(),
                            [reference.domain, reference.token, reference.lookup],
                            tail,
                        ),
                        symbol_open_endpoint(
                            BindingNodeId::universal_root(),
                            [member.lookup, member.domain, member.token],
                            tail,
                        ),
                        [],
                        [],
                        ResolutionCompletion::Complete,
                    ),
                ));
            }
        }
    }

    fn spelling_site(
        facts: &FileResolutionFacts,
        role: ResolutionIdentifierRole,
    ) -> ResolutionSiteId {
        facts
            .identifiers
            .iter()
            .find(|id| id.role == role && facts.names[id.name.index()].spelling == "private")
            .unwrap()
            .site
    }

    #[test]
    fn repeated_go_package_references_share_one_path_per_lookup() {
        let uses = (0..20)
            .flat_map(|_| ["_ = c", "_ = x"])
            .collect::<Vec<_>>()
            .join("\n");
        let source = format!("package p\nfunc use() {{\n{uses}\n}}\n");
        let (facts, lowered) = parsed("go-shared-package-reference", &source);
        let index = FactIndex::new(Language::Go, &facts);
        let mut names = BTreeMap::<String, usize>::new();
        for fact in &facts.package_references {
            let identifier = index.identifiers_by_site[&fact.reference]
                .iter()
                .find(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                .expect("Go package reference has a source identifier");
            let name = index.name(identifier.name);
            if name != "_" {
                *names.entry(name.to_owned()).or_default() += 1;
            }
        }
        assert_eq!(
            names,
            BTreeMap::from([("c".to_owned(), 20), ("x".to_owned(), 20)])
        );

        let references = &lowered.common.package_references;
        assert_eq!(
            references.len(),
            facts.package_references.len()
                * namespaces(Language::Go, ResolutionNamespace::Value).len()
        );
        let mut sites_by_group = BTreeMap::<
            (BindingNodeId, ResolutionNamespace, SemanticId),
            (SemanticId, BTreeSet<SemanticId>, BTreeSet<ResolutionSiteId>),
        >::new();
        let mut per_site = BTreeSet::new();
        for reference in references {
            let identifier = index.identifiers_by_site[&reference.source_site]
                .iter()
                .find(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                .expect("Go package reference has a source identifier");
            if index.name(identifier.name) == "_" {
                continue;
            }
            assert!(per_site.insert((reference.reference, reference.namespace)));
            let group = (reference.root_scope, reference.namespace, reference.lookup);
            let (token, source_references, source_sites) = sites_by_group
                .entry(group)
                .or_insert_with(|| (reference.token, BTreeSet::new(), BTreeSet::new()));
            assert_eq!(*token, reference.token);
            source_references.insert(reference.reference);
            source_sites.insert(reference.source_site);
        }
        assert_eq!(sites_by_group.len(), 6);
        for (group, (_, source_references, source_sites)) in &sites_by_group {
            assert_eq!(source_references.len(), 20, "group {group:?}");
            assert_eq!(source_sites.len(), 20, "group {group:?}");
        }

        let path_groups = references
            .iter()
            .map(|reference| {
                (
                    reference.root_scope,
                    reference.domain,
                    reference.token,
                    reference.lookup,
                )
            })
            .collect::<BTreeSet<_>>();
        let package_paths = lowered
            .lexical
            .paths()
            .iter()
            .filter(|(_, path)| {
                let symbols = path.end().symbols().fixed();
                path.end().node() == BindingNodeId::universal_root()
                    && symbols.len() == 3
                    && path_groups.contains(&(
                        path.start().node(),
                        symbols[0].symbol(),
                        symbols[1].symbol(),
                        symbols[2].symbol(),
                    ))
            })
            .collect::<Vec<_>>();
        assert_eq!(package_paths.len(), path_groups.len());
        assert!(
            package_paths
                .iter()
                .all(|(_, path)| { path.completion() == &ResolutionCompletion::Complete })
        );
    }

    #[test]
    fn kotlin_and_scala_package_references_publish_all_jvm_namespaces() {
        let (facts, _) = parsed(
            "jvm-package-reference",
            "package p\nfunc use(){ _ = remote }\n",
        );
        let reference_site = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "remote"
            })
            .unwrap()
            .site;
        for language in [Language::Kotlin, Language::Scala] {
            let lowered = lower_for_test(
                BindingFragmentId::for_test(language.config_label()),
                language,
                &facts,
            );
            let namespaces = lowered
                .common
                .package_references
                .iter()
                .filter(|reference| reference.source_site == reference_site)
                .map(|reference| reference.namespace)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                namespaces,
                BTreeSet::from([
                    ResolutionNamespace::Callable,
                    ResolutionNamespace::Type,
                    ResolutionNamespace::Value,
                ])
            );
        }
    }

    #[test]
    fn kotlin_source_package_lookups_cover_placement_when_every_root_name_is_requested() {
        let (facts, lowered) = parsed_kotlin(
            "kotlin-package-placement-covered",
            "package sample\nfun use() { missing() }\n",
        );
        let placement = facts
            .gaps
            .iter()
            .find(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
            .expect("Kotlin source records its package placement endpoint")
            .site;
        assert!(facts.package_references.iter().any(|reference| {
            facts.identifiers.iter().any(|identifier| {
                identifier.site == reference.reference
                    && facts.names[identifier.name.index()].spelling == "missing"
            })
        }));
        assert!(!lowered.lexical.gaps().iter().any(|gap| {
            gap.site() == placement
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
                && gap.frontier()
                    == LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
        }));
    }

    #[test]
    fn kotlin_placement_closes_without_any_package_lookup() {
        let (facts, lowered) = parsed_kotlin(
            "kotlin-package-placement-closed",
            "package sample\nclass Box\n",
        );
        let placement = facts
            .gaps
            .iter()
            .find(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
            .expect("Kotlin source records its package placement endpoint")
            .site;
        assert!(facts.package_references.is_empty());
        // An empty set of package lookups is complete when every root
        // reference is covered, so no placement frontier remains open.
        assert!(!lowered.lexical.gaps().iter().any(|gap| {
            gap.site() == placement
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
        }));
    }

    #[test]
    fn scala_package_reference_uses_other_compilation_unit_precedence() {
        let (facts, lowered) = parsed_scala(
            "scala-package-precedence",
            "package sample\nobject Consumer { val value: Remote = null }\n",
        );
        let reference = lowered
            .common
            .package_references
            .iter()
            .find(|reference| reference.namespace == ResolutionNamespace::Type)
            .expect("unresolved Scala type reference publishes package membership lookup");
        assert!(
            facts
                .identifiers
                .iter()
                .any(|identifier| identifier.site == reference.source_site)
        );

        let path = lowered
            .lexical
            .paths()
            .iter()
            .map(|(_, path)| path)
            .find(|path| {
                path.start().node() == reference.root_scope
                    && path.end().node() == BindingNodeId::universal_root()
                    && path
                        .precedence()
                        .iter()
                        .any(|step| step.tier == PrecedenceTier::OtherCompilationUnitPackage)
            })
            .expect("Scala package lookup path is lowered");
        assert_eq!(
            path.precedence()
                .iter()
                .find(|step| step.tier == PrecedenceTier::OtherCompilationUnitPackage)
                .expect("Scala package lookup keeps its existing package tier")
                .ordinal,
            0
        );
        assert_eq!(
            path.precedence()
                .iter()
                .find(|step| step.tier == PrecedenceTier::CandidateOriginRank)
                .expect("Scala package lookup records its candidate origin")
                .ordinal,
            3
        );
        assert!(PrecedenceTier::LexicalBinding < PrecedenceTier::ExplicitImport);
        assert!(PrecedenceTier::ExplicitImport < PrecedenceTier::WildcardImport);
        assert!(PrecedenceTier::WildcardImport < path.precedence()[0].tier);
    }

    #[test]
    fn scala_named_import_precedes_wildcard_and_other_unit_package_lookup() {
        let (_, lowered) = parsed_scala(
            "scala-import-precedence",
            "package sample\n\
             import named.Remote\n\
             import wildcard.*\n\
             object Consumer { val named: Remote = null; val wildcard: Wild = null }\n",
        );
        let tiers = lowered
            .lexical
            .paths()
            .iter()
            .flat_map(|(_, path)| path.precedence().iter().map(|step| step.tier))
            .collect::<BTreeSet<_>>();
        assert!(tiers.contains(&PrecedenceTier::ExplicitImport), "{tiers:?}");
        assert!(tiers.contains(&PrecedenceTier::WildcardImport), "{tiers:?}");
        assert!(
            tiers.contains(&PrecedenceTier::OtherCompilationUnitPackage),
            "{tiers:?}"
        );
        assert!(PrecedenceTier::ExplicitImport < PrecedenceTier::WildcardImport);
        assert!(PrecedenceTier::WildcardImport < PrecedenceTier::OtherCompilationUnitPackage);
    }

    #[test]
    fn scala_package_object_export_becomes_package_membership() {
        let (mut facts, _) = parsed(
            "scala-package-object-export",
            "package p\ntype Box struct {}\nvar Exported int\n",
        );
        let declaration_site = |spelling: &str| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == spelling
                })
                .expect("hand-built package-object export declaration")
                .site
        };
        let package_object = declaration_site("Box");
        let member = declaration_site("Exported");
        let package_scope =
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(1);
        facts.packages.push(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionPackageFact {
                root_scope: package_scope,
                declaration: None,
                placement_gap_site: package_object,
            },
        );
        facts.package_object_exports.push(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionPackageObjectExportFact {
                package_object,
                package_scope,
                member,
            },
        );

        let lowered = lower_for_test(
            BindingFragmentId::for_test("scala-package-object-export"),
            Language::Scala,
            &facts,
        );
        let package_root = lowered
            .common
            .package_members
            .iter()
            .find(|row| row.source_site == package_object)
            .unwrap()
            .root_scope;
        assert!(lowered.common.package_members.iter().any(|row| {
            row.source_site == member
                && row.root_scope == package_root
                && row.namespace == ResolutionNamespace::Value
        }));
        assert!(
            lowered
                .common
                .shared_language
                .package_object_exports
                .iter()
                .any(|row| {
                    row.package_object == package_object
                        && row.package_scope == package_root
                        && row.member == member
                })
        );
    }
}
