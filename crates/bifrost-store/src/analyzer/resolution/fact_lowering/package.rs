//! Protected package membership paths. These stacks cannot match external exports.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct LoweredPackageReference {
    #[doc(hidden)]
    pub token: SemanticId,
    #[doc(hidden)]
    pub domain: SemanticId,
    #[doc(hidden)]
    pub reference: SemanticId,
    #[doc(hidden)]
    pub source_site: ResolutionSiteId,
    #[doc(hidden)]
    pub root_scope: BindingNodeId,
    #[doc(hidden)]
    pub choice: Option<SemanticId>,
    #[doc(hidden)]
    pub namespace: ResolutionNamespace,
    #[doc(hidden)]
    pub lookup: SemanticId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct LoweredPackageMember {
    #[doc(hidden)]
    pub token: SemanticId,
    #[doc(hidden)]
    pub domain: SemanticId,
    #[doc(hidden)]
    pub definition: SemanticId,
    #[doc(hidden)]
    pub source_site: ResolutionSiteId,
    #[doc(hidden)]
    pub root_scope: BindingNodeId,
    #[doc(hidden)]
    pub namespace: ResolutionNamespace,
    #[doc(hidden)]
    pub lookup: SemanticId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct LoweredGoPackageImport {
    #[doc(hidden)]
    pub definition: SemanticId,
    #[doc(hidden)]
    pub source_site: ResolutionSiteId,
    #[doc(hidden)]
    pub file_scope: BindingNodeId,
    #[doc(hidden)]
    pub spelling_choice: SemanticId,
    #[doc(hidden)]
    pub start_byte: usize,
    #[doc(hidden)]
    pub end_byte: usize,
    #[doc(hidden)]
    pub kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionGoPackageImportKind,
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

#[doc(hidden)]
pub fn package_domain_semantic(
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

#[doc(hidden)]
pub fn token(
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

#[doc(hidden)]
pub fn namespaces(
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
                    .combine(&route_publication_completion(
                        identities,
                        language,
                        &index,
                        index.site(row.source_site).scope,
                        index.declaration_identifier(row.source_site).name,
                        row.namespace,
                    ))
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
