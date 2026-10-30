//! Reached Go model declarations, never a provider-wide inventory.
use super::external_owners::{TypeTermHooks, lower_type_term};
use super::*;
use crate::analyzer::resolution::fact_source::{
    GoInterfaceMethod, GoMemberDeclaration, GoMemberDeclarationKind, GoModelMemberDeclaration,
    GoModelOwnerDeclarations, GoStructField,
};
use crate::analyzer::resolution::{
    ExternalOwnerIdentity, ExternalOwnerLanguage, ResolutionLookupSemanticRecipe,
};
use crate::analyzer::semantic_model::TypeRef;
use crate::analyzer::semantic_model::overlay::{
    ModelOwnerAnswer, ModelProviderSelection, ModelSymbolRef, ModelTypeOwnerAnswer,
    SemanticModelSymbolKind as Kind,
};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{IntrinsicTypeKind, ResolutionNamespace};

fn member_digest(member: &ModelSymbolRef, domain: &'static [u8]) -> CanonicalHasher {
    let mut hash = CanonicalHasher::new(domain);
    hash.field("pack-id", member.provider.pack_id.as_bytes());
    hash.field("pack-version", member.provider.pack_version.as_bytes());
    hash.field("pack-digest", member.provider.pack_digest.as_bytes());
    hash.field("symbol-id", member.symbol_id.as_bytes());
    hash
}

struct GoTypeTermHooks<'a, 'selection, 'store> {
    source: &'a SelectedResolutionTypedSource<'selection, 'store>,
    owner: &'a ExternalOwnerIdentity,
    member: &'a ModelSymbolRef,
    selection: &'a ModelProviderSelection,
    purpose: &'static str,
    position: usize,
    next_slot: u32,
    nominal_name: Option<String>,
    cancellation: &'a CancellationToken,
}
impl TypeTermHooks for GoTypeTermHooks<'_, '_, '_> {
    fn allocate(&mut self) -> (SemanticId, [u8; 32]) {
        let mut hash = member_digest(self.member, b"bifrost-go-model-type-slot:v1");
        hash.field("purpose", self.purpose.as_bytes());
        hash.field("position", &(self.position as u64).to_be_bytes());
        hash.field("slot", &self.next_slot.to_be_bytes());
        self.next_slot = self
            .next_slot
            .checked_add(1)
            .expect("model type slots fit u32");
        let digest = hash.finish();
        (
            SemanticId::shared_name(self.source.selection.shared_names().intern(digest)),
            digest,
        )
    }
    fn wrap<T>(&self, row: T) -> SelectedTypedRow<T> {
        SelectedTypedRow::external_owner(self.owner.clone(), row)
    }
    fn nominal(
        &mut self,
        term: &TypeRef,
        _owners: &crate::hash::HashMap<String, Option<ExternalOwnerIdentity>>,
    ) -> StoreResult<Option<(SemanticId, IntrinsicTypeKind, String)>> {
        if let TypeRef::Named { name, .. } = term
            && let Some(entry) = crate::analyzer::resolution::universe::lookup(
                Language::Go,
                ResolutionNamespace::Type,
                name,
            )
            && let crate::analyzer::resolution::universe::UniverseIdentityKind::Type(kind) =
                entry.identity_kind
        {
            self.nominal_name = Some(name.clone());
            return Ok(Some((
                SemanticId::shared_name(self.source.selection.shared_names().intern(
                    crate::analyzer::resolution::universe::identity_digest(entry),
                )),
                kind,
                name.clone(),
            )));
        }
        if !matches!(term, TypeRef::Named { .. } | TypeRef::Declared { .. }) {
            return Ok(None);
        }
        let Some(authority) = self.source.model_authority.as_deref() else {
            return Ok(None);
        };
        let result = authority.model_type_owner("go", term, self.selection, self.cancellation);
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        let result =
            result.map_err(|error| StoreError::new(format!("Go model field type: {error:?}")))?;
        let ModelTypeOwnerAnswer::Unique { owner, declaration } = result else {
            return Ok(None);
        };
        let identity = self
            .source
            .context_identities
            .external_owner_semantic_for_language(
                ExternalOwnerLanguage::Go,
                &ExternalOwnerIdentity {
                    provider_id: owner.provider.pack_digest.into(),
                    owner_fqn: declaration.qualified_name.clone().into(),
                },
                &self.source.selection.shared_names(),
            );
        self.nominal_name = Some(declaration.name);
        Ok(Some((
            identity,
            IntrinsicTypeKind::LanguageBuiltin,
            declaration.qualified_name,
        )))
    }
    fn exact_nominal(&self, term: &TypeRef) -> bool {
        matches!(term, TypeRef::Named { arguments, nullable, .. } | TypeRef::Declared { arguments, nullable, .. } if arguments.is_empty() && !nullable)
    }
    fn pointer_element<'a>(&self, term: &'a TypeRef) -> Option<&'a TypeRef> {
        if let TypeRef::Pointer { element } = term {
            Some(element)
        } else {
            None
        }
    }
}

impl SelectedResolutionTypedSource<'_, '_> {
    pub(super) fn read_unindexed_model_callable_result(
        &self,
        frontier: &crate::analyzer::resolution::UnindexedExternalFrontier,
        cancellation: &CancellationToken,
        session: Option<
            &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
        >,
    ) -> StoreResult<Option<Option<String>>> {
        use super::super::resolution_lexical::{
            SelectedLookupRecipeReadOutcome, SelectedLookupRecipeRequest,
            SelectedResolutionLexicalSource,
        };
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let (Some(authority), Some(models), Some((fragment, semantic))) = (
            self.model_authority.as_deref(),
            self.external_models.as_deref(),
            frontier.member,
        ) else {
            return Ok(Some(None));
        };
        if authority
            .modeled_external_package_identity(Language::Go, &frontier.provider_path)
            .is_none()
        {
            return Ok(Some(None));
        }
        let lexical = SelectedResolutionLexicalSource::with_authority(
            self.selection,
            Rc::clone(&self.authority),
        );
        let SelectedLookupRecipeReadOutcome::Ready(recipes) = lexical.lookup_semantic_recipes(
            &[SelectedLookupRecipeRequest { fragment, semantic }],
            cancellation,
            session,
        )?
        else {
            return Ok(None);
        };
        let Some(recipe) = recipes[0].as_ref() else {
            return Ok(Some(None));
        };
        let canonical = format!("{}.{}", frontier.provider_path, recipe.spelling());
        let selection = models.model_provider_selection();
        let groups = authority.model_selected_groups(
            "go",
            &TypeRef::Named {
                name: frontier.provider_path.to_string(),
                arguments: Vec::new(),
                nullable: false,
            },
            &selection,
            cancellation,
        );
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let groups = groups.map_err(|error| {
            StoreError::new(format!("model callable owner declaration: {error:?}"))
        })?;
        let [group] = groups.as_slice() else {
            return Ok(Some(None));
        };
        let modules = group
            .iter()
            .filter(|symbol| {
                symbol.kind == Kind::Module
                    && symbol.qualified_name == frontier.provider_path.as_ref()
            })
            .collect::<Vec<_>>();
        let [module] = modules.as_slice() else {
            return Ok(Some(None));
        };
        if module.provenance.ambiguous {
            return Ok(Some(None));
        }
        let owner = ModelSymbolRef {
            symbol_id: module.id.clone(),
            provider: crate::analyzer::semantic_model::overlay::ModelProvider::from(
                &module.provenance,
            ),
        };
        let declarations = authority.model_member_declarations(&owner, &selection, cancellation);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let declarations = declarations
            .map_err(|error| StoreError::new(format!("model callable declarations: {error:?}")))?;
        let Some(ModelOwnerAnswer::Declared(declarations)) = declarations else {
            return Ok(Some(None));
        };
        let matching = declarations
            .members
            .iter()
            .filter(|member| member.declaration.name == recipe.spelling())
            .collect::<Vec<_>>();
        let [member] = matching.as_slice() else {
            return Ok(Some(None));
        };
        let symbol = &member.declaration;
        Ok(Some(
            (symbol.kind == Kind::Function
                && !symbol.provenance.ambiguous
                && symbol
                    .structured_signature
                    .as_ref()
                    .is_some_and(|signature| signature.returns.is_some()))
            .then(|| format!("{canonical} from {}", symbol.provenance.pack_digest)),
        ))
    }

    pub(super) fn read_go_model_owner_declarations(
        &self,
        definition: SemanticId,
        identity: &ExternalOwnerIdentity,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<GoModelOwnerDeclarations>>> {
        let source = self;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let (Some(authority), Some(models)) = (
            source.model_authority.as_deref(),
            source.external_models.as_deref(),
        ) else {
            return Ok(Some(None));
        };
        // Composition uses the request's active provider selection. Root owner
        // recovery is additionally pinned to the minted defining provider, just
        // as the qualified import proof was; unrelated providers cannot replace it.
        let selection = models.model_provider_selection();
        let owner_selection = ModelProviderSelection::new(
            models
                .shards()
                .iter()
                .filter(|shard| shard.manifest.semantic_sha256 == identity.provider_id.as_ref())
                .map(
                    |shard| crate::analyzer::semantic_model::overlay::ModelProvider {
                        pack_id: shard.manifest.pack_id.clone(),
                        pack_version: shard.manifest.version.clone(),
                        pack_digest: shard.manifest.semantic_sha256.clone(),
                    },
                ),
        );
        let selected = authority.model_type_owner(
            "go",
            &TypeRef::Named {
                name: identity.owner_fqn.to_string(),
                arguments: Vec::new(),
                nullable: false,
            },
            &owner_selection,
            cancellation,
        );
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let selected =
            selected.map_err(|error| StoreError::new(format!("Go model owner: {error:?}")))?;
        let ModelTypeOwnerAnswer::Unique { owner, declaration } = selected else {
            return Ok(Some(None));
        };
        if owner.provider.pack_digest != identity.provider_id.as_ref()
            || declaration.qualified_name != identity.owner_fqn.as_ref()
        {
            return Ok(Some(None));
        }
        let declarations = authority.model_member_declarations(&owner, &selection, cancellation);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let declarations = declarations
            .map_err(|error| StoreError::new(format!("Go model members: {error:?}")))?;
        let Some(ModelOwnerAnswer::Declared(declarations)) = declarations else {
            return Ok(Some(None));
        };
        let names = source.selection.shared_names();
        let mut completion = ResolutionCompletion::Complete;
        let mut fields = Vec::new();
        let mut field_names = Vec::new();
        let mut methods = Vec::new();
        let mut interface_methods = Vec::new();
        let mut memo = source.external_signatures.borrow_mut();
        // The Go artifact producer authors kind (Struct/Interface/Class), Field
        // structured_signature.returns (not value_type), owner.embedded_types,
        // and Method.receiver (ReceiverFact). No source or model field memory
        // slot exists here; field stays None (#7556).
        for member in &declarations.members {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let callable_lookup = ResolutionLookupSemanticRecipe::new(
                Language::Go,
                ResolutionNamespace::Callable,
                &member.declaration.name,
            )
            .semantic(&names);
            match member.declaration.kind {
                Kind::Method => {
                    let token = SemanticId::shared_name(names.intern(
                        member_digest(&member.member, b"bifrost-go-model-member:v1").finish(),
                    ));
                    self.context_identities
                        .record_model_member_identity(token, &member.member);
                    methods.push(GoModelMemberDeclaration {
                        member: member.member.clone(),
                        owner: definition,
                        definition: token,
                        callable_lookup,
                        declaration: member.declaration.clone(),
                    });
                    interface_methods.push(GoInterfaceMethod {
                        callable_lookup,
                        definition: Some(token),
                    });
                }
                Kind::Field => {
                    let term = member
                        .declaration
                        .structured_signature
                        .as_ref()
                        .and_then(|signature| signature.returns.as_ref())
                        .unwrap_or(&TypeRef::Unknown);
                    let mut hooks = GoTypeTermHooks {
                        source,
                        owner: identity,
                        member: &member.member,
                        selection: &selection,
                        purpose: "field",
                        position: 0,
                        next_slot: 0,
                        nominal_name: None,
                        cancellation,
                    };
                    let Some(slot) = lower_type_term(
                        &mut memo,
                        term,
                        &mut hooks,
                        &source.context_identities,
                        cancellation,
                    )?
                    else {
                        return Ok(None);
                    };
                    fields.push(GoStructField {
                        callable_lookup,
                        embedded: false,
                        field: None,
                        value_type: Some(slot),
                    });
                    field_names.push(member.declaration.name.clone());
                }
                _ => {}
            }
        }
        let mut embedded = Vec::new();
        for (position, edge) in declarations.declaration.embedded_types.iter().enumerate() {
            let mut hooks = GoTypeTermHooks {
                source,
                owner: identity,
                member: &owner,
                selection: &selection,
                purpose: "embedded",
                position,
                next_slot: 0,
                nominal_name: None,
                cancellation,
            };
            // The producer's edge pointer bit and a structured pointer are the
            // same embedding layer, not two pointer layers.
            let pointer;
            let term = if edge.pointer && !matches!(edge.target, TypeRef::Pointer { .. }) {
                pointer = TypeRef::Pointer {
                    element: Box::new(edge.target.clone()),
                };
                &pointer
            } else {
                &edge.target
            };
            let Some(slot) = lower_type_term(
                &mut memo,
                term,
                &mut hooks,
                &source.context_identities,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let frontier = memo.type_frontier(slot);
            completion = completion.combine(frontier.completion());
            let [value] = frontier.possible_values() else {
                continue;
            };
            let ty = value.ty();
            embedded.push(ty);
            let Some(implicit_name) = hooks.nominal_name else {
                continue;
            };
            let matches = fields
                .iter()
                .enumerate()
                .filter(|(index, field)| {
                    field_names[*index] == implicit_name
                        && field.value_type.is_some_and(|slot| {
                            memo.type_frontier(slot)
                                .possible_values()
                                .iter()
                                .any(|value| value.ty().identity() == ty.identity())
                        })
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if let [index] = matches.as_slice() {
                fields[*index].embedded = true;
                fields[*index].value_type = Some(slot);
            } else {
                // A private embedding can lack a retained Field record. Preserve
                // its authored edge rather than silently closing an empty surface.
                if matches.len() > 1 {
                    let reason = source.context_identities.named_semantic(
                        member_digest(&owner, b"bifrost-go-model-embedding-unproven:v1").finish(),
                        "GoModelEmbeddingUnproven",
                        "go-model-embedding-field-join-unproven",
                    );
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(reason),
                    ]));
                }
                fields.push(GoStructField {
                    callable_lookup: ResolutionLookupSemanticRecipe::new(
                        Language::Go,
                        ResolutionNamespace::Callable,
                        &implicit_name,
                    )
                    .semantic(&names),
                    embedded: true,
                    field: None,
                    value_type: Some(slot),
                });
                field_names.push(implicit_name);
            }
        }
        let kind = match declarations.declaration.kind {
            Kind::Struct => GoMemberDeclarationKind::Struct { fields },
            Kind::Interface => GoMemberDeclarationKind::Interface {
                methods: interface_methods,
            },
            Kind::Class => GoMemberDeclarationKind::Defined,
            _ => return Ok(Some(None)),
        };
        Ok(
            (!cancellation.is_cancelled()).then_some(Some(GoModelOwnerDeclarations {
                owner,
                declaration: GoMemberDeclaration { definition, kind },
                members_state: declarations.members_state,
                embedded,
                methods,
                completion,
            })),
        )
    }
}
