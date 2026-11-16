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
    /// The admission point for written class objects used by the Generic rule.
    /// A source declaration alone cannot prove what decorators or metaclasses
    /// returned. The future shared class-object admission proof belongs here.
    pub(super) fn implicit_generic_written_objects(
        &self,
        targets: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<crate::analyzer::resolution::ImplicitWrittenBaseObjects> {
        use crate::analyzer::resolution::ImplicitWrittenBaseObjects as Proof;
        let mut proof = Proof::Proven;
        for &target in targets {
            if let Some(owner) = self.model_declaration(target, cancellation)? {
                if owner.declaration.kind != SemanticModelSymbolKind::Class {
                    return Ok(Proof::Unproven);
                }
            } else if let Some(entry) = self.intrinsic_entry(target) {
                if entry.language != Language::Python
                    || !matches!(
                        entry.identity_kind,
                        crate::analyzer::resolution::universe::UniverseIdentityKind::Type(_)
                    )
                {
                    return Ok(Proof::Unproven);
                }
            } else if target.ordinal().is_some()
                && self.implicit_base_inputs(target, cancellation)?.is_some()
            {
                // Shared source-side object admission owns this proof. A class
                // declaration alone cannot decide Protocol suppression here.
                proof = Proof::UnprovenSource;
            } else {
                return Ok(Proof::Unproven);
            }
        }
        Ok(proof)
    }

    pub(super) fn implicit_model_class(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SemanticId>> {
        let ty = TypeRef::Named {
            name: name.to_owned(),
            arguments: Vec::new(),
            nullable: false,
        };
        Ok(self
            .model_hierarchy_type_value(&ty, cancellation)?
            .map(|value| value.ty().identity()))
    }

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
    /// The selected model's declaration of a language-fixed Python class other
    /// than `object`. The fixed table names the class and nothing about its
    /// bases; the selected model is the only authority for them. With no model
    /// selected, or none declaring the class, there is no declaration and the
    /// class stays open.
    pub(super) fn fixed_class_model(
        &self,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<(ModelSymbolRef, ModelOwnerDeclarations)>> {
        if self
            .context_identities
            .model_member_identity(token)
            .is_some()
        {
            return Ok(None);
        }
        let Some(entry) = self.intrinsic_entry(token) else {
            return Ok(None);
        };
        if !self.fixed_python_class(&entry) || entry.identity_spelling == "builtins.object" {
            return Ok(None);
        }
        let (Some(authority), Some(active)) = (
            self.model_authority.as_deref(),
            self.external_models.as_deref(),
        ) else {
            return Ok(None);
        };
        let ty = TypeRef::Named {
            name: entry.identity_spelling.to_owned(),
            arguments: Vec::new(),
            nullable: false,
        };
        let Some(symbol) = super::super::resolution_operation::python_models::agreed_class_owner(
            authority,
            active,
            &ty,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        // The model may declare the class under another name and list this
        // spelling as an alias (`IOError` and `EnvironmentError` are `OSError`).
        // The alias is that class, so it takes that declaration's bases.
        if (symbol.qualified_name != entry.identity_spelling
            && !symbol
                .aliases
                .iter()
                .any(|alias| alias == entry.identity_spelling))
            || symbol.provenance.ambiguous
        {
            return Ok(None);
        }
        let key = super::super::resolution_operation::python_models::symbol_ref(&symbol);
        Ok(
            super::super::resolution_operation::python_models::declaration(
                authority,
                active,
                &key,
                cancellation,
            )?
            .map(|owner| (key, owner)),
        )
    }

    fn fixed_python_class(
        &self,
        entry: &crate::analyzer::resolution::universe::UniverseEntry,
    ) -> bool {
        use brokk_bifrost_python::intrinsics::{self, BuiltinKind};
        entry.language == crate::analyzer::Language::Python
            && intrinsics::builtin(entry.spelling)
                .is_some_and(|builtin| matches!(builtin.kind, BuiltinKind::Type))
    }

    /// The language-fixed identity of a model class the fixed table also names,
    /// so a base reached through a fixed class and the same base reached
    /// through source name one owner.
    fn fixed_class_token(&self, qualified_name: &str) -> Option<SemanticId> {
        let short = qualified_name.strip_prefix("builtins.")?;
        let entry = crate::analyzer::resolution::universe::lookup(
            crate::analyzer::Language::Python,
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::TypeOrValue,
            short,
        )?;
        self.fixed_python_class(&entry).then(|| {
            SemanticId::shared_name(
                self.selection
                    .shared_name_table()
                    .interner(self.selection.connection())
                    .intern(crate::analyzer::resolution::universe::identity_digest(
                        entry,
                    )),
            )
        })
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
    /// As `model_type_value`, for a base in a hierarchy: a class two providers
    /// declare identically is one owner (see `agreed_class_owner`).
    fn model_hierarchy_type_value(
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
        let Some(owner) = super::super::resolution_operation::python_models::agreed_class_owner(
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
    /// A base of a model class as a value. The language root `object` is one
    /// owner however it was reached, so it always takes its language-fixed
    /// identity. Any other base the fixed table names takes it only below a
    /// language-fixed class; below an ordinary model class the base keeps the
    /// model identity, which is the only owner of that class's model members.
    fn model_base_value(
        &self,
        ty: &TypeRef,
        fixed_owner: bool,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionSlotValue>> {
        if let (Some(authority), Some(active)) = (
            self.model_authority.as_deref(),
            self.external_models.as_deref(),
        ) && let Some(owner) =
            super::super::resolution_operation::python_models::agreed_class_owner(
                authority,
                active,
                ty,
                cancellation,
            )?
            && (fixed_owner || owner.qualified_name == "builtins.object")
            && let Some(token) = self.fixed_class_token(&owner.qualified_name)
        {
            return Ok(Some(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(token, 0),
                false,
            )));
        }
        self.model_hierarchy_type_value(ty, cancellation)
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
        let owner = match self.model_declaration(token, cancellation)? {
            Some(owner) => owner,
            None => match self.fixed_class_model(token, cancellation)? {
                Some((_, owner)) => owner,
                None => return Ok(None),
            },
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
            let resolved = self.model_hierarchy_type_value(base, cancellation)?;
            if cancellation.is_cancelled() {
                complete = false;
                break;
            }
            complete &= resolved.is_some();
        }
        let cancelled = cancelled || cancellation.is_cancelled();
        complete &= !cancelled;
        Ok(Some(ImplicitBaseInputs {
            base_preservation: None,
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
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let mut completion = ResolutionCompletion::Complete;
        for &token in definitions {
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(completion));
            }
            // A model class, or a language-fixed class the selected model
            // declares. Source owners have no model supertypes.
            let (key, owner, fixed) =
                if let Some(key) = self.context_identities.model_member_identity(token) {
                    let Some(owner) = self.model_declaration(token, cancellation)? else {
                        continue;
                    };
                    (key, owner, false)
                } else if let Some((key, owner)) = self.fixed_class_model(token, cancellation)? {
                    (key, owner, true)
                } else {
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
                let value = self.model_base_value(base, fixed, cancellation)?;
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
