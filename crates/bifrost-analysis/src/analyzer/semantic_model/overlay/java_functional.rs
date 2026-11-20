//! Positive Java functional-method proof over the selected declaration model.

use super::*;
use brokk_bifrost_jvm::java::functional::{
    CallableInventory, CallableType, ErasedElement, ErasedReference, FunctionalInventory,
    FunctionalType,
};
use brokk_bifrost_jvm::java::primitives::primitive_for_name;
pub use brokk_bifrost_semantic::analyzer::semantic_model::overlay::java_functional::*;
impl SemanticModelOverlay {
    /// Prove one method representing the functional contract (JLS 9.8). The caller
    /// resolves both the target interface and Object in the current source's
    /// selected artifact context. This does not prove lambda execution or
    /// expression compatibility. Unsupported substitution/override cases stay
    /// unknown. Every traversal and pair comparison spends the caller's work.
    pub fn java_functional_method(
        &self,
        owner: &Arc<SemanticModelSymbol>,
        object: &SemanticModelSymbol,
        remaining_work: &mut usize,
        cancellation: &crate::CancellationToken,
    ) -> Option<Arc<SemanticModelSymbol>> {
        use brokk_bifrost_jvm::java::functional::functional_method;
        let mut inventory = OverlayFunctionalInventory {
            overlay: self,
            object: Some(object),
            remaining_work,
            cancellation,
            members: std::collections::HashMap::new(),
        };
        let selected = functional_method(&mut inventory, owner.id.clone())?;
        if !selected.signature_ground {
            return None;
        }
        inventory.member(&selected.method)
    }

    /// Read one complete Java callable type for functional-interface adapters.
    #[doc(hidden)]
    pub fn java_callable_type_inventory(
        &self,
        id: &str,
        remaining_work: &mut usize,
        cancellation: &crate::CancellationToken,
    ) -> Option<CallableType<String>> {
        OverlayFunctionalInventory {
            overlay: self,
            object: None,
            remaining_work,
            cancellation,
            members: std::collections::HashMap::new(),
        }
        .callable_type(&id.to_owned())
    }
    /// Enumerate visible instance methods, charging every inspected member.
    #[doc(hidden)]
    pub fn java_functional_members(
        &self,
        id: &str,
        remaining_work: &mut usize,
        cancellation: &crate::CancellationToken,
    ) -> Option<Vec<String>> {
        OverlayFunctionalInventory {
            overlay: self,
            object: None,
            remaining_work,
            cancellation,
            members: std::collections::HashMap::new(),
        }
        .methods(&id.to_owned())
    }
    /// Ordered variables recorded by the selected owner declaration.
    #[doc(hidden)]
    pub fn java_declared_type_parameters(&self, id: &str) -> Option<Vec<String>> {
        let selected = self.symbols_with_id_in_family(id, "java");
        if matches!(
            selected.disposition,
            SemanticModelOverlayDisposition::Open(_)
        ) {
            return None;
        }
        let [owner] = selected.records.as_slice() else {
            return None;
        };
        let active = self.active_models.as_ref()?;
        Some(owner_declaration(active, owner)?.type_parameters.clone())
    }
    fn java_callable_inventory(
        &self,
        owner: &Arc<SemanticModelSymbol>,
        remaining_work: &mut usize,
        cancellation: &crate::CancellationToken,
    ) -> Option<JavaCallableInventory> {
        let mut inventory = OverlayFunctionalInventory {
            overlay: self,
            object: None,
            remaining_work,
            cancellation,
            members: std::collections::HashMap::new(),
        };
        let hierarchy = brokk_bifrost_jvm::java::functional::callable_inventory(
            &mut inventory,
            owner.id.clone(),
        )?;
        let mut types = HashMap::default();
        let mut ancestry = HashMap::default();
        for ((id, _), parents) in hierarchy.types.into_iter().zip(hierarchy.ancestry) {
            types.insert(id.clone(), inventory.member(&id)?);
            ancestry.insert(id, parents.into_iter().collect());
        }
        Some(JavaCallableInventory { types, ancestry })
    }

    /// Classify a structured Java signature type in its selected model family.
    #[doc(hidden)]
    pub fn java_functional_type(
        &self,
        ty: &TypeRef,
        context: &SemanticModelSymbol,
    ) -> FunctionalType<ErasedReference<String>, (String, String, usize)> {
        let mut ty = ty;
        let mut dimensions = 0;
        while let TypeRef::Array { element } = ty {
            dimensions += 1;
            ty = element;
        }
        if let TypeRef::TypeParameter { name } = ty {
            let scope = if context
                .structured_signature
                .as_ref()
                .is_some_and(|signature| signature.type_parameters.contains(name))
            {
                context.id.clone()
            } else {
                let Some(owner) = &context.owner_id else {
                    return FunctionalType::Unknown;
                };
                owner.clone()
            };
            return FunctionalType::TypeVariable((scope, name.clone(), dimensions));
        }
        let candidates = match ty {
            TypeRef::Named { name, .. } => {
                if let Some(kind) = primitive_for_name(name) {
                    return if dimensions == 0 {
                        FunctionalType::Primitive(kind)
                    } else {
                        FunctionalType::Reference(ErasedReference {
                            element: ErasedElement::Primitive(kind),
                            dimensions,
                        })
                    };
                }
                self.symbols_named_for(name, "java")
            }
            TypeRef::Declared { id, .. } => self.symbols_with_id_in_family(id, "java"),
            _ => return FunctionalType::Unknown,
        };
        // An open lookup may hide the declaration that decides this type.
        if matches!(
            candidates.disposition,
            SemanticModelOverlayDisposition::Open(_)
        ) {
            return FunctionalType::Unknown;
        }
        // A named type may live in a dependency pack. Prefer a declaration in
        // the referring family; otherwise require one active Java declaration.
        let has_local = candidates
            .records
            .iter()
            .any(|symbol| symbol.provenance.pack_id == context.provenance.pack_id);
        let mut candidates = candidates
            .records
            .iter()
            .filter(|symbol| !has_local || symbol.provenance.pack_id == context.provenance.pack_id);
        let Some(symbol) = candidates.next() else {
            return FunctionalType::NonPrimitive {
                simple_name: None,
                dimensions,
            };
        };
        if candidates.next().is_some() || symbol.provenance.ambiguous || symbol.language != "java" {
            return FunctionalType::NonPrimitive {
                simple_name: None,
                dimensions,
            };
        }
        FunctionalType::Reference(ErasedReference {
            element: ErasedElement::Declared(symbol.id.clone()),
            dimensions,
        })
    }

    #[doc(hidden)]
    /// Return an unambiguous public instance declaration only when its entire
    /// inherited name family has one member. Overloaded and overridden families
    /// require applicability/override proof and stay unknown at this boundary.
    pub fn java_single_instance_method(
        &self,
        owner: &Arc<SemanticModelSymbol>,
        name: &str,
        remaining_work: &mut usize,
        cancellation: &crate::CancellationToken,
    ) -> Option<Arc<SemanticModelSymbol>> {
        let JavaCallableInventory { types, .. } =
            self.java_callable_inventory(owner, remaining_work, cancellation)?;
        let mut selected = None;
        for id in types.keys() {
            // Charge the row-backed read before it runs, so an exhausted budget
            // performs no member-row query.
            spend(remaining_work, cancellation, 1)?;
            let inventory = self.members_of_in_family(id, "java");
            if matches!(
                inventory.disposition,
                SemanticModelOverlayDisposition::Open(_)
            ) {
                return None;
            }
            for member in &inventory.records {
                spend(remaining_work, cancellation, 1)?;
                if member.kind != SemanticModelSymbolKind::Method || member.name != name {
                    continue;
                }
                if member.provenance.ambiguous
                    || member.is_static
                    || member.visibility != Visibility::Public
                    || selected.is_some()
                {
                    return None;
                }
                member.structured_signature.as_ref()?;
                selected = Some(Arc::clone(member));
            }
        }
        selected
    }
}

struct OverlayFunctionalInventory<'a> {
    overlay: &'a SemanticModelOverlay,
    object: Option<&'a SemanticModelSymbol>,
    remaining_work: &'a mut usize,
    cancellation: &'a crate::CancellationToken,
    /// Member lookups already read during this one proof. A proof compares the
    /// same members repeatedly; each row-backed read is charged once.
    members: std::collections::HashMap<String, Option<Arc<SemanticModelSymbol>>>,
}

impl CallableInventory for OverlayFunctionalInventory<'_> {
    type Type = String;
    fn spend(&mut self) -> Option<()> {
        spend(self.remaining_work, self.cancellation, 1)
    }
    fn callable_type(&mut self, id: &String) -> Option<CallableType<String>> {
        // Charge the row-backed read before it runs.
        spend(self.remaining_work, self.cancellation, 1)?;
        let records = self.overlay.symbols_with_id_in_family(id, "java");
        // An open lookup may have unread contributors that change the owner.
        if matches!(
            records.disposition,
            SemanticModelOverlayDisposition::Open(_)
        ) {
            return None;
        }
        let [owner] = records.records.as_slice() else {
            return None;
        };
        if owner.language != "java"
            || !matches!(
                owner.kind,
                SemanticModelSymbolKind::Interface | SemanticModelSymbolKind::Class
            )
            || !owner.callable_surface_complete
            || owner.provenance.ambiguous
        {
            return None;
        }
        // Charge one per ancestor read, equally for decoded and row-backed types.
        // #11212 tracks charging non-hierarchy relations or indexing edge kinds.
        spend(self.remaining_work, self.cancellation, 1)?;
        let direct = self.overlay.direct_ancestors_of(owner);
        if !direct.defects.is_empty()
            || matches!(
                direct.disposition,
                SemanticModelOverlayDisposition::Open(_)
                    | SemanticModelOverlayDisposition::Conflict
            )
        {
            return None;
        }
        spend(self.remaining_work, self.cancellation, direct.records.len())?;
        Some(CallableType {
            is_interface: owner.kind == SemanticModelSymbolKind::Interface,
            sealed: owner.declaration_is_sealed,
            parents: direct
                .records
                .iter()
                .map(|symbol| symbol.id.clone())
                .collect(),
        })
    }
}
impl FunctionalInventory for OverlayFunctionalInventory<'_> {
    type Method = String;
    type Reference = ErasedReference<String>;
    type Variable = (String, String, usize);
    type ClosedArgument = ();
    fn type_parameters(&mut self, id: &String) -> Option<Vec<Self::Variable>> {
        // The owner and declaration reads are row-backed; charge them first.
        spend(self.remaining_work, self.cancellation, 1)?;
        Some(
            self.overlay
                .java_declared_type_parameters(id)?
                .into_iter()
                .map(|name| (id.clone(), name, 0))
                .collect(),
        )
    }
    fn methods(&mut self, id: &String) -> Option<Vec<String>> {
        let mut methods = Vec::new();
        spend(self.remaining_work, self.cancellation, 1)?;
        let inventory = self.overlay.members_of_in_family(id, "java");
        if matches!(
            inventory.disposition,
            SemanticModelOverlayDisposition::Open(_)
        ) {
            return None;
        }
        for member in &inventory.records {
            spend(self.remaining_work, self.cancellation, 1)?;
            if member.kind == SemanticModelSymbolKind::Method
                && !member.is_static
                && member.externally_visible()
            {
                methods.push(member.id.clone());
            }
        }
        Some(methods)
    }
    fn object_methods(&mut self) -> Option<Vec<String>> {
        let object = self.object?;
        if object.language != "java"
            || object.kind != SemanticModelSymbolKind::Class
            || object.qualified_name != "java.lang.Object"
            || !object.callable_surface_complete
            || object.provenance.ambiguous
        {
            return None;
        }
        let mut result = Vec::new();
        spend(self.remaining_work, self.cancellation, 1)?;
        let inventory = self.overlay.members_of_in_family(&object.id, "java");
        if matches!(
            inventory.disposition,
            SemanticModelOverlayDisposition::Open(_)
        ) {
            return None;
        }
        for member in &inventory.records {
            spend(self.remaining_work, self.cancellation, 1)?;
            if member.kind == SemanticModelSymbolKind::Method
                && !member.is_static
                && member.visibility == Visibility::Public
            {
                if member.provenance.ambiguous {
                    return None;
                }
                member.structured_signature.as_ref()?;
                result.push(member.id.clone());
            }
        }
        Some(result)
    }

    fn method(
        &mut self,
        id: &String,
    ) -> Option<brokk_bifrost_jvm::java::functional::FunctionalMethod> {
        let member = self.member(id)?;
        let signature = member.structured_signature.as_ref()?;
        if member.provenance.ambiguous || signature.contains_unknown_types() {
            return None;
        }
        Some(brokk_bifrost_jvm::java::functional::FunctionalMethod {
            is_abstract: member.declaration_is_abstract,
            has_type_parameters: !signature.type_parameters.is_empty(),
        })
    }
    fn name_and_arity(&mut self, id: &String) -> Option<(String, usize)> {
        let member = self.member(id)?;
        Some((
            member.name.clone(),
            member.structured_signature.as_ref()?.parameters.len(),
        ))
    }
    fn parameter_type(
        &mut self,
        id: &String,
        ordinal: usize,
    ) -> Option<FunctionalType<Self::Reference, Self::Variable>> {
        let member = self.member(id)?;
        let ty = &member
            .structured_signature
            .as_ref()?
            .parameters
            .get(ordinal)?
            .r#type;
        Some(self.overlay.java_functional_type(ty, &member))
    }
    fn return_type(
        &mut self,
        id: &String,
    ) -> Option<Option<FunctionalType<Self::Reference, Self::Variable>>> {
        let member = self.member(id)?;
        Some(
            member
                .structured_signature
                .as_ref()?
                .returns
                .as_ref()
                .map(|ty| self.overlay.java_functional_type(ty, &member)),
        )
    }
    fn parameter_agreement(
        &mut self,
        left: &String,
        right: &String,
        ordinal: usize,
    ) -> Option<bool> {
        let left_member = self.member(left)?;
        let right_member = self.member(right)?;
        let left = left_member
            .structured_signature
            .as_ref()?
            .parameters
            .get(ordinal)?;
        let right = right_member
            .structured_signature
            .as_ref()?
            .parameters
            .get(ordinal)?;
        if !ground_types(
            [&left.r#type, &right.r#type],
            self.remaining_work,
            self.cancellation,
        )? {
            return None;
        }
        Some(left.r#type == right.r#type && left.variadic == right.variadic)
    }
    fn return_agreement(&mut self, left: &String, right: &String) -> Option<bool> {
        let left = self.member(left)?;
        let right = self.member(right)?;
        let left = &left.structured_signature.as_ref()?.returns;
        let right = &right.structured_signature.as_ref()?.returns;
        if !ground_types(
            left.iter().chain(right.iter()),
            self.remaining_work,
            self.cancellation,
        )? {
            return None;
        }
        Some(left == right)
    }
    fn method_variable_position(&mut self, variable: &Self::Variable) -> Option<(usize, usize)> {
        let (scope, name, rank) = variable;
        self.member(scope)?
            .structured_signature
            .as_ref()?
            .type_parameters
            .iter()
            .position(|parameter| parameter == name)
            .map(|position| (position, *rank))
    }
    fn reference_name(&mut self, reference: &Self::Reference) -> Option<(String, usize)> {
        let ErasedElement::Declared(id) = &reference.element else {
            return None;
        };
        Some((self.member(id)?.name.clone(), reference.dimensions))
    }
    fn ground(&mut self, id: &String) -> Option<bool> {
        let member = self.member(id)?;
        let signature = member.structured_signature.as_ref()?;
        brokk_bifrost_semantic::analyzer::semantic_model::overlay::java_functional::ground_types_with_variables(
            signature.parameters.iter().map(|parameter| &parameter.r#type).chain(signature.returns.iter()),
            self.remaining_work, self.cancellation,
            |name| signature.type_parameters.iter().any(|parameter| parameter == name),
        )
    }
}
impl OverlayFunctionalInventory<'_> {
    fn member(&mut self, id: &str) -> Option<Arc<SemanticModelSymbol>> {
        if let Some(member) = self.members.get(id) {
            return member.clone();
        }
        // Charge the row-backed read before it runs.
        spend(self.remaining_work, self.cancellation, 1)?;
        let inventory = self.overlay.symbols_with_id_in_family(id, "java");
        let member = if matches!(
            inventory.disposition,
            SemanticModelOverlayDisposition::Open(_)
        ) {
            None
        } else if let [member] = inventory.records.as_slice() {
            Some(Arc::clone(member))
        } else {
            None
        };
        self.members.insert(id.to_owned(), member.clone());
        member
    }
}
