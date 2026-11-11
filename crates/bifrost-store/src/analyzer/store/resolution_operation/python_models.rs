//! Query-local model reads. The overlay owns composition; Python owns meaning.
use super::demand_closure::SelectedMemberTarget;
use super::*;
use crate::analyzer::resolution::{ResolutionSlotValue, ResolutionTypeRef};
use crate::analyzer::semantic_model::{
    ModelOwnerAnswer, ModelOwnerDeclarations, ModelProvider, ModelSymbolRef, ModelTypeOwnerAnswer,
    SemanticModelSymbol, SemanticModelSymbolKind, TypeRef,
};

pub(in crate::analyzer::store) fn symbol_ref(symbol: &SemanticModelSymbol) -> ModelSymbolRef {
    ModelSymbolRef {
        symbol_id: symbol.id.clone(),
        provider: ModelProvider::from(&symbol.provenance),
    }
}
pub(in crate::analyzer::store) fn hash_model_symbol(
    hash: &mut CanonicalHasher,
    model: &ModelSymbolRef,
) {
    hash.field("pack_id", model.provider.pack_id.as_bytes());
    hash.field("pack_version", model.provider.pack_version.as_bytes());
    hash.field("pack_digest", model.provider.pack_digest.as_bytes());
    hash.field("symbol", model.symbol_id.as_bytes());
}
pub(in crate::analyzer::store) fn declaration(
    authority: &dyn SelectedModelAuthority,
    active: &super::super::active_models::ResolvedActiveSemanticModels,
    symbol: &ModelSymbolRef,
    cancellation: &CancellationToken,
) -> Result<Option<ModelOwnerDeclarations>> {
    let answer = authority.model_member_declarations(
        symbol,
        &active.model_provider_selection(),
        cancellation,
    );
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    match answer.map_err(|error| StoreError::new(format!("model declarations: {error:?}")))? {
        Some(ModelOwnerAnswer::Declared(declaration)) => Ok(Some(declaration)),
        Some(ModelOwnerAnswer::UnresolvedForward { .. }) | None => Ok(None),
    }
}
pub(in crate::analyzer::store) fn type_owner(
    authority: &dyn SelectedModelAuthority,
    active: &super::super::active_models::ResolvedActiveSemanticModels,
    ty: &TypeRef,
    cancellation: &CancellationToken,
) -> Result<Option<SemanticModelSymbol>> {
    let answer = authority.model_type_owner(
        "python",
        ty,
        &active.model_provider_selection(),
        cancellation,
    );
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(
        match answer.map_err(|error| StoreError::new(format!("model type owner: {error:?}")))? {
            ModelTypeOwnerAnswer::Unique { declaration, .. }
                if declaration.kind == SemanticModelSymbolKind::Class =>
            {
                Some(declaration)
            }
            _ => None,
        },
    )
}
impl super::SelectedResolutionOperation<'_, '_> {
    /// Return only an exact, complete class owner in this operation's selected
    /// model authority. An overlay spelling alone cannot establish ownership.
    pub fn python_exact_model_type_owner(
        &self,
        fqn: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticModelSymbol>> {
        let Some(analyzer) = self.ready.analyzer else {
            return Ok(None);
        };
        let (Some(authority), Some(active)) =
            (analyzer.model_authority(), analyzer.active_models())
        else {
            return Ok(None);
        };
        let ty = TypeRef::Named {
            name: fqn.to_owned(),
            arguments: Vec::new(),
            nullable: false,
        };
        let owner = type_owner(&*authority, &active, &ty, cancellation)?;
        Ok(owner.filter(|owner| {
            owner.qualified_name == fqn
                && !owner.provenance.ambiguous
                && owner.provenance.completeness
                    == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
        }))
    }
}
impl super::SelectedResolutionOperation<'_, '_> {
    /// The exact, complete class owner behind a selected value-type identity.
    /// Only an identity that this operation admitted as a model member has one;
    /// a workspace class that happens to share the owner's spelling does not.
    pub fn python_model_value_owner(
        &self,
        identity: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticModelSymbol>> {
        let Some(symbol) = self
            .ready
            .context_identities
            .model_member_identity(identity)
        else {
            return Ok(None);
        };
        let Some(analyzer) = self.ready.analyzer else {
            return Ok(None);
        };
        let (Some(authority), Some(active)) =
            (analyzer.model_authority(), analyzer.active_models())
        else {
            return Ok(None);
        };
        Ok(declaration(&*authority, &active, &symbol, cancellation)?
            .map(|owner| owner.declaration)
            .filter(|owner| {
                owner.kind == SemanticModelSymbolKind::Class
                    && !owner.provenance.ambiguous
                    && owner.provenance.completeness
                        == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
            }))
    }
}
impl super::python_demand::PythonRules<'_, '_, '_> {
    pub(super) fn model_token(&self, symbol: &SemanticModelSymbol) -> SemanticId {
        self.ready
            .context_identities
            .model_member_semantic(&symbol_ref(symbol), &self.ready.shared_names())
    }
    pub(super) fn model_declaration(
        &self,
        token: SemanticId,
    ) -> Result<Option<ModelOwnerDeclarations>> {
        let Some(symbol) = self.ready.context_identities.model_member_identity(token) else {
            return Ok(None);
        };
        let Some(analyzer) = self.ready.analyzer else {
            return Ok(None);
        };
        let (Some(authority), Some(active)) =
            (analyzer.model_authority(), analyzer.active_models())
        else {
            return Ok(None);
        };
        declaration(&*authority, &active, &symbol, self.cancellation)
    }
    pub(super) fn admit_model(
        &self,
        reference: SemanticId,
        selected: &[super::PythonSelectedExternalImport],
    ) -> Result<Option<SemanticId>> {
        let [selected] = selected else {
            return Ok(None);
        };
        let (Some(analyzer), Some(snapshot)) =
            (self.ready.analyzer, self.ready.snapshots.get("python"))
        else {
            return Ok(None);
        };
        let Some(ordinal) = reference.ordinal() else {
            return Ok(None);
        };
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let file = ProjectFile::new(self.ready.project.root(), mount.persisted_relative_path());
        let mut path = selected
            .boundary
            .bound_name
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        path.extend_from_slice(&selected.remaining_member_path);
        match self
            .ready
            .store
            .lend_selected_reader(self.ready.inventory.connection(), || {
                analyzer.admit_selected_external_binding(
                    &SelectedExternalBindingRequest {
                        file: &file,
                        language: Language::Python,
                        snapshot,
                        selected,
                        path: &path,
                    },
                    self.cancellation,
                )
            }) {
            SelectedExternalBindingRead::Admitted(symbol) => Ok(Some(self.model_token(&symbol))),
            SelectedExternalBindingRead::Refused { code, detail } => {
                self.observations
                    .borrow_mut()
                    .push(format!("{code}: {detail}"));
                Ok(None)
            }
            SelectedExternalBindingRead::Cancelled => Ok(None),
        }
    }
    pub(super) fn model_target(
        &self,
        token: SemanticId,
        lookup: &ResolutionLookupSemanticRecipe,
        fragment: BindingFragmentId,
    ) -> SelectedMemberTarget {
        let mut hash = CanonicalHasher::new(b"python-model-definition-node:v1");
        let model = self
            .ready
            .context_identities
            .model_member_identity(token)
            .expect("selected model token");
        hash_model_symbol(&mut hash, &model);
        let definition = self.ready.context_identities.node(hash.finish());
        self.ready
            .inventory
            .mount_rebaser()
            .borrow_mut()
            .register_model_definition(definition, token);
        SelectedMemberTarget {
            fragment,
            token,
            definition,
            lookup: lookup.clone(),
            completion: ResolutionCompletion::Complete,
        }
    }
    pub(super) fn model_construction(
        &self,
        token: SemanticId,
    ) -> Result<Option<crate::analyzer::resolution::TypedConstructionResult>> {
        let Some(owner) = self.model_declaration(token)? else {
            return Ok(None);
        };
        if owner.declaration.kind != SemanticModelSymbolKind::Class {
            return Ok(None);
        }
        let allocators = owner
            .members
            .iter()
            .filter(|member| member.declaration.name == "__new__")
            .collect::<Vec<_>>();
        let (constructed_class, exact) = if allocators.is_empty() {
            (Some(token), true)
        } else if let [allocator] = allocators.as_slice() {
            let analyzer = self.ready.analyzer.expect("model authority");
            let authority = analyzer.model_authority().expect("model authority");
            let active = analyzer.active_models().expect("active models");
            let results = authority
                .model_callable_results(
                    &allocator.member,
                    &active.model_provider_selection(),
                    self.cancellation,
                )
                .map_err(|error| StoreError::new(format!("model allocator results: {error:?}")))?;
            match results.as_deref() {
                Some([Some(TypeRef::TypeParameter { name })]) if name == "Self" => {
                    (Some(token), true)
                }
                Some([Some(TypeRef::Named { name, .. })])
                    if name == "Self" || name == "typing.Self" =>
                {
                    (Some(token), true)
                }
                Some([Some(ty)]) => {
                    match type_owner(&*authority, &active, ty, self.cancellation)? {
                        Some(target) => (
                            Some(self.model_token(&target)),
                            symbol_ref(&target) == owner.owner,
                        ),
                        None => (None, false),
                    }
                }
                _ => (None, false),
            }
        } else {
            (None, false)
        };
        Ok(Some(crate::analyzer::resolution::TypedConstructionResult {
            value: constructed_class
                .map(|class| ResolutionSlotValue::runtime(ResolutionTypeRef::new(class, 0), false)),
            completion: if exact {
                ResolutionCompletion::Complete
            } else {
                super::python_demand::model_open(
                    self,
                    token,
                    "python_model_allocator_result_unknown",
                )
            },
        }))
    }
}

#[derive(Debug)]
pub(super) struct ModelMemberRow {
    pub symbol: SemanticModelSymbol,
    pub owner: SemanticId,
    pub receiver: ResolutionSlotValue,
    pub provider: crate::analyzer::resolution::HierarchyProviderKey,
}
impl super::python_demand::PythonRules<'_, '_, '_> {
    pub(super) fn own_model_dictionaries(
        &self,
        values: &[ResolutionSlotValue],
        lookup: &str,
    ) -> Result<Option<Vec<SemanticId>>> {
        if values.is_empty() {
            return Ok(None);
        }
        let mut owners = Vec::new();
        for value in values {
            let token = value.ty().identity();
            let Some(owner) = self.model_declaration(token)? else {
                return Ok(None);
            };
            if owner.declaration.kind != SemanticModelSymbolKind::Class
                || !owner
                    .members
                    .iter()
                    .any(|member| member.declaration.name == lookup)
            {
                return Ok(None);
            }
            owners.push(token);
        }
        owners.sort_unstable();
        owners.dedup();
        Ok(Some(owners))
    }
}
pub(super) fn member_rows(
    context: &super::python_members::PythonMemberContext<'_, '_, '_>,
    route: &super::python_members::PythonMemberRoute<'_>,
    token: SemanticId,
) -> Result<Option<super::demand_closure::Read<Vec<super::python_members::PythonMemberRow>>>> {
    use crate::analyzer::resolution::*;
    let Some(owner) = context.rules.model_declaration(token)? else {
        return Ok(None);
    };
    let members = owner
        .members
        .into_iter()
        .filter(|member| member.declaration.name == route.lookup.spelling())
        .collect::<Vec<_>>();
    let known = !members.is_empty()
        || owner.declaration.provenance.completeness
            == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete;
    let completion = if known {
        ResolutionCompletion::Complete
    } else {
        super::python_demand::model_open(context.rules, token, "python_model_member_inventory_open")
    };
    let provider = HierarchyProviderKey::source(
        token,
        route.lookup.semantic(&context.rules.ready.shared_names()),
        route.namespace,
        HierarchyProviderAuthority::Declaration(token),
        HierarchyProviderOperand::CandidateInventory,
        context.reference,
        route.step as u32,
    );
    context
        .member_observations
        .borrow_mut()
        .push(HierarchyProviderObservation {
            provider: provider.clone(),
            visit: HierarchyProviderVisit::Observed,
            completion: completion.clone(),
            inventory_complete: Some(known),
        });
    let mut rows = Vec::new();
    for member in members {
        for &receiver in context.member_values {
            rows.push(super::python_members::PythonMemberRow::Model(Box::new(
                ModelMemberRow {
                    symbol: member.declaration.clone(),
                    owner: token,
                    receiver,
                    provider: provider.clone(),
                },
            )));
        }
    }
    Ok(Some(super::demand_closure::Read::Ready {
        value: rows,
        completion,
    }))
}
pub(super) fn classify(
    context: &super::python_members::PythonMemberContext<'_, '_, '_>,
    access: &super::member_access::MemberAccessContext<'_>,
    row: &ModelMemberRow,
) -> Result<super::member_access::AccessRowPoll> {
    use super::member_access::*;
    let root = row.receiver.ty().identity();
    let token = context.rules.model_token(&row.symbol);
    let binding = if row.symbol.has_receiver() && !row.symbol.is_static {
        match row.receiver {
            ResolutionSlotValue::Runtime { .. } => {
                let mut hash = CanonicalHasher::new(b"python-model-receiver-parameter:v1");
                hash_model_symbol(&mut hash, &symbol_ref(&row.symbol));
                MemberBinding::Receiver {
                    parameter: context
                        .rules
                        .ready
                        .context_identities
                        .semantic(hash.finish()),
                    value: row.receiver,
                }
            }
            ResolutionSlotValue::TypeObject(_, _) => MemberBinding::Unknown,
        }
    } else {
        MemberBinding::Unchanged
    };
    let completion = if matches!(binding, MemberBinding::Unknown) {
        super::python_demand::model_open(
            context.rules,
            token,
            "python_model_descriptor_role_unknown",
        )
    } else {
        ResolutionCompletion::Complete
    };
    let key = if access.selection.own_dictionary {
        AccessKey::Fixed(0)
    } else {
        access
            .selection
            .order
            .map_or(AccessKey::Unknown, |order| AccessKey::Owner {
                order,
                root,
                owner: row.owner,
            })
    };
    Ok(AccessRowPoll::Ready(super::demand_closure::Read::ready(
        Box::new(AccessFacts {
            member_owner: None,
            ordered_range: None,
            alternative: AccessAlternativeId(root),
            group: AccessGroupId(0),
            within_group: Box::new([key]),
            between_groups: Box::new([AccessKey::Fixed(0)]),
            provider: row.provider.clone(),
            occurrence: row.provider.occurrence(),
            binding,
            completion,
            coverage: Box::new([row.provider.clone()]),
            witnesses: Box::new([]),
        }),
    )))
}
