//! Protected package membership paths. These stacks cannot match external exports.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoweredPackageReference {
    pub(crate) token: SemanticId,
    pub(crate) domain: SemanticId,
    pub(crate) reference: SemanticId,
    pub(crate) source_site: ResolutionSiteId,
    pub(crate) root_scope: BindingNodeId,
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
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-package-domain:v1");
    hasher.field("language", language.config_label().as_bytes());
    identities.shared_name(hasher.finish())
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

pub(crate) fn lower_metadata(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
) -> (Vec<LoweredPackageReference>, Vec<LoweredPackageMember>) {
    if facts.package_references.is_empty() && facts.package_members.is_empty() {
        return (Vec::new(), Vec::new());
    }
    facts.validate_package_relations();
    let index = FactIndex::new(facts);
    let domain = domain(identities, language);
    let mut references = Vec::new();
    for fact in &facts.package_references {
        let identifier = index.identifiers_by_site[&fact.reference]
            .iter()
            .find(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .expect("validated package reference");
        for &namespace in namespaces(language) {
            references.push(LoweredPackageReference {
                token: token(
                    identities,
                    b"bifrost-resolution-package-reference-token:v1",
                    fact.reference.get(),
                    namespace,
                ),
                domain,
                reference: identities.source_reference_semantic(fact.reference),
                source_site: fact.reference,
                root_scope: identities.source_scope_node(fact.root_scope),
                namespace,
                lookup: identities.lookup_semantic(
                    language,
                    namespace,
                    index.name(identifier.name),
                ),
            });
        }
    }
    let members = facts
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
    (references, members)
}

fn namespaces(language: Language) -> &'static [ResolutionNamespace] {
    match language {
        Language::Go => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ],
        Language::Java => &[ResolutionNamespace::Type],
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
    if facts.package_references.is_empty() && facts.package_members.is_empty() {
        return;
    }
    let (references, members) = lower_metadata(identities, language, facts);
    let index = FactIndex::new(facts);
    let scope_reasons = root_scope_gap_reasons(identities, &index, gap_sources);
    for (fact, rows) in facts
        .package_references
        .iter()
        .zip(references.chunks(namespaces(language).len()))
    {
        for row in rows {
            let id = identities.path(ResolutionPathIdentity::new(local_digest(
                b"bifrost-resolution-package-reference-path:v1",
                &[
                    ("site", &u32_bytes(row.source_site.get())),
                    ("namespace", row.namespace.identity_label().as_bytes()),
                ],
            )));
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
                    package_precedence(identities, language, fact.root_scope, row.namespace),
                    [WitnessStep::Node(row.root_scope)],
                    completion_for_site(reasons_by_site, row.source_site, |_| true),
                ),
            ));
        }
    }
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
) -> Vec<PrecedenceStep> {
    match language {
        Language::Go => go_spelling_precedence(identities, scope, None, 0),
        Language::Java => {
            let semantic = identities.semantic(scope_choice_identity(scope, namespace));
            vec![identities.register_precedence_namespace(
                PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal: 0,
                    semantic,
                },
                namespace,
            )]
        }
        _ => panic!("package path precedence is undefined for {language:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::go::GoAdapter;
    use crate::analyzer::resolution::{
        BatchResolutionEngine, LoweredResolutionFactsWithIdentityCatalog, PreloadedFragmentSource,
        ResolutionQuery, lower_for_test,
    };
    use crate::analyzer::{LanguageAdapter, ProjectFile};

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
    fn protected_package_peers_preserve_local_shadowing_and_duplicate_ambiguity() {
        for (label, source, expected) in [
            ("sibling", "package p\nfunc use(){ _ = private }\n", 1),
            (
                "peer",
                "package p\nvar private int\nfunc use(){ _ = private }\n",
                2,
            ),
            (
                "local",
                "package p\nfunc use(){ private := 1; _ = private }\n",
                1,
            ),
        ] {
            let (facts, mut caller) = parsed(label, source);
            let (_, provider) = parsed("provider", "package p\nvar private int\n");
            let reference_site = spelling_site(&facts, ResolutionIdentifierRole::Reference);
            let reference = caller
                .common
                .package_references
                .iter()
                .find(|row| row.source_site == reference_site)
                .unwrap()
                .reference;
            let own_target = if label == "sibling" {
                None
            } else {
                let site = spelling_site(&facts, ResolutionIdentifierRole::Declaration);
                caller
                    .lexical
                    .semantics()
                    .iter()
                    .find(|row| row.role() == LoweredSemanticRole::Definition && row.site() == site)
                    .map(|row| row.semantic())
            };
            bridge(&mut caller, &provider);
            let source =
                PreloadedFragmentSource::from_lowered_fragments([caller.lexical, provider.lexical]);
            let answer = BatchResolutionEngine::new(&source)
                .resolve_reference(
                    ResolutionQuery::new(reference),
                    &CancellationToken::default(),
                )
                .unwrap();
            assert_eq!(answer.targets().len(), expected, "{label}: {answer:?}");
            if let Some(own_target) = own_target {
                assert!(answer.targets().contains(&own_target), "{label}");
            }
        }
    }

    #[test]
    fn protected_package_members_do_not_enter_external_export_domain() {
        let (facts, caller) = parsed("unconnected", "package p\nfunc use(){ _ = private }\n");
        let (provider_facts, provider) = parsed("private-provider", "package p\nvar private int\n");
        assert!(!provider.common.package_members.is_empty());
        assert!(provider_facts.root_exports.is_empty());
        let site = spelling_site(&facts, ResolutionIdentifierRole::Reference);
        let reference = caller
            .common
            .package_references
            .iter()
            .find(|row| row.source_site == site)
            .unwrap()
            .reference;
        let source =
            PreloadedFragmentSource::from_lowered_fragments([caller.lexical, provider.lexical]);
        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(
                ResolutionQuery::new(reference),
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(answer.targets().is_empty());
    }

    #[test]
    fn protected_package_wrong_namespace_winner_is_a_blocker() {
        let (facts, mut caller) = parsed(
            "type-request",
            "package p\nfunc use(){ var value private; _ = value }\n",
        );
        let (_, provider) = parsed("value-provider", "package p\nvar private int\n");
        let site = spelling_site(&facts, ResolutionIdentifierRole::Reference);
        let reference = caller
            .common
            .package_references
            .iter()
            .find(|row| row.source_site == site)
            .unwrap()
            .reference;
        bridge(&mut caller, &provider);
        let source =
            PreloadedFragmentSource::from_lowered_fragments([caller.lexical, provider.lexical]);
        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(
                ResolutionQuery::new(reference),
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(answer.targets().is_empty());
    }
}
