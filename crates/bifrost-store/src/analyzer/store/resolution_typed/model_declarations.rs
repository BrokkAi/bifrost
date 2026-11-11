//! Model records are query inputs to the same typed/hierarchy algorithms as source.
use super::super::resolution_operation::ModelRuntimeBases;
use super::*;
use crate::analyzer::resolution::ClassCreationKind;
use crate::analyzer::resolution::{
    ImplicitBaseAuthority, ImplicitBaseInputs, ResolutionSlotValue, ResolutionTypeRef,
};
use crate::analyzer::semantic_model::{
    ModelOwnerDeclarations, ModelSymbolRef, SemanticModelSymbolKind, TypeRef,
};
use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;

impl SelectedResolutionTypedSource<'_, '_> {
    pub(super) fn model_declaration(
        &self,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ModelOwnerDeclarations>> {
        let Some(key) = self.context_identities.model_member_identity(token) else {
            return Ok(None);
        };
        let (Some(authority), Some(active)) = (
            self.model_authority.as_deref(),
            self.external_models.as_deref(),
        ) else {
            return Ok(None);
        };
        super::super::resolution_operation::python_models::declaration(
            authority,
            active,
            &key,
            cancellation,
        )
    }
    pub(super) fn model_type_value(
        &self,
        ty: &TypeRef,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionSlotValue>> {
        let (Some(authority), Some(active)) = (
            self.model_authority.as_deref(),
            self.external_models.as_deref(),
        ) else {
            return Ok(None);
        };
        let Some(owner) = super::super::resolution_operation::python_models::type_owner(
            authority,
            active,
            ty,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let token = self.context_identities.model_member_semantic(
            &super::super::resolution_operation::python_models::symbol_ref(&owner),
            &names,
        );
        Ok(Some(ResolutionSlotValue::runtime(
            ResolutionTypeRef::new(token, 0),
            false,
        )))
    }
    pub(super) fn project_model_value(
        &self,
        token: SemanticId,
        kind: BindingProjectionKind,
        receivers: &[ResolutionSlotValue],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<(Vec<ResolutionSlotValue>, ResolutionCompletion)>> {
        let Some(owner) = self.model_declaration(token, cancellation)? else {
            return Ok(None);
        };
        let symbol = owner.declaration;
        if !model_language_knowledge(&symbol.language)
            .is_some_and(|rules| rules.model_declarations_project_runtime_values())
        {
            return Ok(None);
        }
        if symbol.kind == SemanticModelSymbolKind::Class {
            return Ok(matches!(
                kind,
                BindingProjectionKind::TargetDeclaredValueType
                    | BindingProjectionKind::TargetTypeIdentity
                    | BindingProjectionKind::TargetNominalTypeIdentity
                    | BindingProjectionKind::TargetTypeOrDeclaredValueType
                    | BindingProjectionKind::TargetMemberOwnerType
            )
            .then(|| {
                (
                    vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                        token, 0,
                    ))],
                    ResolutionCompletion::Complete,
                )
            }));
        }
        // A property is evaluated only through an instance. Through a class
        // the descriptor remains a value; it is not the property's result.
        let property_result = symbol.kind == SemanticModelSymbolKind::Property
            && matches!(
                kind,
                BindingProjectionKind::TargetTypeOrDeclaredValueType
                    | BindingProjectionKind::TargetDeclaredValueType
            )
            && !receivers.is_empty()
            && receivers
                .iter()
                .all(|receiver| matches!(receiver, ResolutionSlotValue::Runtime { .. }));
        if symbol.kind == SemanticModelSymbolKind::Property
            && matches!(
                kind,
                BindingProjectionKind::TargetTypeOrDeclaredValueType
                    | BindingProjectionKind::TargetDeclaredValueType
            )
            && !property_result
        {
            return Ok(Some((
                Vec::new(),
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(token),
                ]),
            )));
        }
        if symbol.kind == SemanticModelSymbolKind::Property
            && matches!(
                kind,
                BindingProjectionKind::TargetCallableResultType
                    | BindingProjectionKind::TargetCallableLaterResultType
            )
        {
            // Calling a property value would invoke that value's callable
            // protocol, not call the property's getter a second time.
            return Ok(Some((
                Vec::new(),
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(token),
                ]),
            )));
        }
        let mut terms = Vec::new();
        match if property_result {
            BindingProjectionKind::TargetCallableResultType
        } else {
            kind
        } {
            BindingProjectionKind::TargetTypeOrDeclaredValueType
            | BindingProjectionKind::TargetDeclaredValueType => {
                if let Some(ty) = symbol.proxied_type.or(symbol.value_type) {
                    terms.push(ty);
                }
            }
            BindingProjectionKind::TargetCallableResultType
            | BindingProjectionKind::TargetCallableLaterResultType => {
                let (Some(authority), Some(active)) = (
                    self.model_authority.as_deref(),
                    self.external_models.as_deref(),
                ) else {
                    return Ok(None);
                };
                let results = authority
                    .model_callable_results(
                        &owner.owner,
                        &active.model_provider_selection(),
                        cancellation,
                    )
                    .map_err(|error| {
                        StoreError::new(format!("model callable results: {error:?}"))
                    })?;
                if !symbol.exact_return_classes.is_empty() {
                    terms = symbol.exact_return_classes;
                } else if let Some(results) = results
                    && results.len() == 1
                    // A Python tuple remains one aggregate value even though
                    // the model service exposes its components by ordinal.
                    && !matches!(symbol.structured_signature.as_ref().and_then(|signature| signature.returns.as_ref()), Some(TypeRef::Tuple { .. }))
                {
                    terms.extend(results.into_iter().flatten());
                }
            }
            _ => return Ok(None),
        }
        let mut values = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        for ty in &terms {
            if matches!(ty, TypeRef::TypeParameter { name } | TypeRef::Named { name, .. } if name == "Self" || name == "typing.Self")
            {
                values.extend(
                    receivers
                        .iter()
                        .map(|receiver| ResolutionSlotValue::runtime(receiver.ty(), false)),
                );
                if receivers.is_empty() {
                    completion = ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(token),
                    ]);
                }
            } else if let Some(value) = self.model_type_value(ty, cancellation)? {
                values.push(value);
            } else {
                completion = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(token),
                ]);
            }
        }
        if terms.is_empty() {
            completion = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(token),
            ]);
        }
        Ok(Some((values, completion)))
    }
    pub(super) fn model_implicit_inputs(
        &self,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ImplicitBaseInputs>> {
        let Some(owner) = self.model_declaration(token, cancellation)? else {
            return Ok(None);
        };
        if !model_language_knowledge(&owner.declaration.language)
            .is_some_and(|rules| rules.model_declarations_supply_runtime_bases())
            || owner.declaration.kind != SemanticModelSymbolKind::Class
        {
            return Ok(None);
        }
        let verdict =
            self.model_authority
                .as_deref()
                .map_or(ModelRuntimeBases::Unproven, |authority| {
                    authority.python_runtime_bases(
                        &owner.declaration.qualified_name,
                        &owner.declaration.id,
                        cancellation,
                    )
                });
        let (bases, cancelled) = match verdict {
            ModelRuntimeBases::Agreed(bases) => (Some(bases), false),
            ModelRuntimeBases::Unproven => (None, false),
            ModelRuntimeBases::Cancelled => (None, true),
        };
        let mut complete = bases.is_some() && !cancelled;
        for base in bases.iter().flatten() {
            let resolved = self.model_type_value(base, cancellation)?;
            if cancellation.is_cancelled() {
                complete = false;
                break;
            }
            complete &= resolved.is_some();
        }
        let cancelled = cancelled || cancellation.is_cancelled();
        complete &= !cancelled;
        Ok(Some(ImplicitBaseInputs {
            written_inventory_complete: complete,
            written_base_count: bases.as_ref().map_or(0, |bases| {
                u32::try_from(bases.len()).expect("model bases fit u32")
            }),
            creation: ClassCreationKind::Ordinary,
            root_object: None,
            authority: ImplicitBaseAuthority::Intrinsic { descriptor: token },
            completion: if cancelled {
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled])
            } else if complete {
                ResolutionCompletion::Complete
            } else {
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                    token,
                )])
            },
        }))
    }
    pub(super) fn visit_model_supertypes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        // Walk keys are local to this read, never retained as memo or persisted keys.
        enum Owner {
            Source(SemanticId),
            Model(ModelSymbolRef),
        }
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let mut completion = ResolutionCompletion::Complete;
        for &token in definitions {
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(completion));
            }
            let owner = self
                .context_identities
                .model_member_identity(token)
                .map_or(Owner::Source(token), Owner::Model);
            let Owner::Model(key) = owner else {
                let Owner::Source(source) = owner else {
                    unreachable!()
                };
                debug_assert_eq!(source, token);
                continue;
            };
            let Some(owner) = self.model_declaration(token, cancellation)? else {
                continue;
            };
            if !model_language_knowledge(&owner.declaration.language)
                .is_some_and(|rules| rules.model_declarations_supply_runtime_bases())
            {
                continue;
            }
            let verdict =
                self.model_authority
                    .as_deref()
                    .map_or(ModelRuntimeBases::Unproven, |authority| {
                        authority.python_runtime_bases(
                            &owner.declaration.qualified_name,
                            &owner.declaration.id,
                            cancellation,
                        )
                    });
            let bases = match verdict {
                ModelRuntimeBases::Agreed(bases) => bases,
                ModelRuntimeBases::Unproven => {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(token),
                    ]));
                    continue;
                }
                ModelRuntimeBases::Cancelled => {
                    return Ok(TypedFactReadOutcome::cancelled(completion));
                }
            };
            let mut rows = Vec::new();
            for (ordinal, base) in bases.iter().enumerate() {
                let value = self.model_type_value(base, cancellation)?;
                if cancellation.is_cancelled() {
                    return Ok(TypedFactReadOutcome::cancelled(completion));
                }
                let Some(value) = value else {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(token),
                    ]));
                    continue;
                };
                let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                    b"python-model-base:v1",
                );
                super::super::resolution_operation::python_models::hash_model_symbol(
                    &mut hash, &key,
                );
                hash.field("ordinal", &(ordinal as u64).to_be_bytes());
                let reference = SemanticId::shared_name(names.intern(hash.finish()));
                let row = LoweredSupertypeProperty::resolved(
                    token,
                    reference,
                    reference,
                    ordinal as u32,
                    value.ty().identity(),
                );
                rows.push(SelectedTypedRow::external_owner(
                    crate::analyzer::resolution::ExternalOwnerIdentity {
                        provider_id: key.provider.pack_digest.clone().into(),
                        owner_fqn: owner.declaration.qualified_name.clone().into(),
                    },
                    row,
                ));
            }
            for page in rows.chunks(visitor.maximum_rows()) {
                if cancellation.is_cancelled() {
                    return Ok(TypedFactReadOutcome::cancelled(completion));
                }
                if !visitor.visit_page(page)? {
                    return Ok(TypedFactReadOutcome::stopped(completion));
                }
            }
        }
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(completion));
        }
        Ok(TypedFactReadOutcome::exhausted(completion))
    }
}

fn model_language_knowledge(
    language: &str,
) -> Option<&'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge> {
    let parsed = Language::from_config_label(language)?;
    // Model declarations carry canonical labels, not configuration aliases.
    if parsed.config_label() != language {
        return None;
    }
    crate::analyzer::semantic::languages::language_knowledge(parsed)
}
