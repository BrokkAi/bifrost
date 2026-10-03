//! Positive Java functional-method proof over the selected declaration model.

use super::*;

struct JavaCallableInventory<'a> {
    types: HashMap<&'a str, &'a SemanticModelSymbol>,
    ancestry: HashMap<&'a str, HashSet<&'a str>>,
}

impl SemanticModelOverlay {
    /// Prove one method representing the functional contract (JLS 9.8). The caller
    /// resolves both the target interface and Object in the current source's
    /// selected artifact context. This does not prove lambda execution or
    /// expression compatibility. Unsupported substitution/override cases stay
    /// unknown. Every traversal and pair comparison spends the caller's work.
    pub fn java_functional_method<'a>(
        &'a self,
        owner: &'a SemanticModelSymbol,
        object: &SemanticModelSymbol,
        remaining_work: &mut usize,
        cancellation: &crate::CancellationToken,
    ) -> Option<&'a SemanticModelSymbol> {
        if owner.language != "java"
            || owner.kind != SemanticModelSymbolKind::Interface
            || owner.declaration_is_sealed
            || object.language != "java"
            || object.kind != SemanticModelSymbolKind::Class
            || object.qualified_name != "java.lang.Object"
            || !object.callable_surface_complete
            || object.provenance.ambiguous
        {
            return None;
        }
        let mut object_methods = Vec::new();
        for index in self.symbols_by_owner.get(&object.id).into_iter().flatten() {
            spend(remaining_work, cancellation, 1)?;
            let member = &self.symbols[*index];
            if member.kind == SemanticModelSymbolKind::Method
                && !member.is_static
                && member.visibility == Visibility::Public
            {
                if member.provenance.ambiguous {
                    return None;
                }
                member.structured_signature.as_ref()?;
                object_methods.push(member);
            }
        }
        let JavaCallableInventory {
            types: interfaces,
            ancestry,
        } = self.java_callable_inventory(owner, remaining_work, cancellation)?;
        if interfaces
            .values()
            .any(|ty| ty.kind != SemanticModelSymbolKind::Interface)
        {
            return None;
        }
        let mut methods = Vec::new();
        for (id, interface) in interfaces {
            for index in self.symbols_by_owner.get(id).into_iter().flatten() {
                spend(remaining_work, cancellation, 1)?;
                let member = &self.symbols[*index];
                if member.kind != SemanticModelSymbolKind::Method
                    || member.is_static
                    || !member.externally_visible()
                {
                    continue;
                }
                if member.provenance.ambiguous {
                    return None;
                }
                let signature = member.structured_signature.as_ref()?;
                // A generic function type cannot be implemented by a lambda.
                // Inherited type-variable substitution is not yet retained by
                // overlay hierarchy edges, so do not merge those signatures.
                if member.declaration_is_abstract && !signature.type_parameters.is_empty() {
                    return None;
                }
                if interface.id != owner.id
                    && !ground_signature(signature, remaining_work, cancellation)?
                {
                    return None;
                }
                let mut is_object_method = false;
                for object_method in &object_methods {
                    spend(remaining_work, cancellation, 1)?;
                    if same_signature(member, object_method) {
                        if signature.returns != object_method.structured_signature.as_ref()?.returns
                        {
                            return None;
                        }
                        is_object_method = true;
                    }
                }
                if is_object_method {
                    if !member.declaration_is_abstract {
                        return None;
                    }
                } else {
                    methods.push((id, member));
                }
            }
        }
        let mut effective = Vec::new();
        for (id, member) in &methods {
            let mut overridden = false;
            for (other_id, other) in &methods {
                spend(remaining_work, cancellation, 1)?;
                if member.id == other.id {
                    continue;
                }
                if id == other_id && same_signature(member, other) {
                    return None;
                }
                if same_signature(member, other) && ancestry[other_id].contains(id) {
                    // Covariant returns and generic substitution need their
                    // own proof; mere agreement on void/value is insufficient.
                    if member.structured_signature.as_ref()?.returns
                        != other.structured_signature.as_ref()?.returns
                    {
                        return None;
                    }
                    overridden = true;
                }
            }
            if !overridden {
                effective.push(*member);
            }
        }
        let mut contract: Option<&SemanticModelSymbol> = None;
        for (index, member) in effective.iter().enumerate() {
            for other in &effective[index + 1..] {
                spend(remaining_work, cancellation, 1)?;
                if same_signature(member, other)
                    && (!member.declaration_is_abstract || !other.declaration_is_abstract)
                {
                    return None;
                }
            }
            if !member.declaration_is_abstract {
                continue;
            }
            if let Some(prior) = contract {
                if !same_signature(prior, member)
                    || prior.structured_signature.as_ref()?.returns
                        != member.structured_signature.as_ref()?.returns
                {
                    return None;
                }
            } else {
                contract = Some(member);
            }
        }
        contract
    }
    // Retained source inventories prove declaration families independently of
    // global pack completeness. This is not executable dispatch/effect proof.
    fn java_callable_inventory<'a>(
        &'a self,
        owner: &'a SemanticModelSymbol,
        remaining_work: &mut usize,
        cancellation: &crate::CancellationToken,
    ) -> Option<JavaCallableInventory<'a>> {
        let mut pending = vec![owner];
        let mut types = HashMap::default();
        let mut parents = HashMap::default();
        while let Some(current) = pending.pop() {
            spend(remaining_work, cancellation, 1)?;
            if types.contains_key(current.id.as_str()) {
                continue;
            }
            if !matches!(
                current.kind,
                SemanticModelSymbolKind::Interface | SemanticModelSymbolKind::Class
            ) || current.language != "java"
                || !current.callable_surface_complete
                || current.provenance.ambiguous
            {
                return None;
            }
            spend(
                remaining_work,
                cancellation,
                self.relations_from.get(&current.id).map_or(0, Vec::len),
            )?;
            let direct = self.direct_ancestors_of(current);
            if !direct.defects.is_empty()
                || direct.disposition == SemanticModelOverlayDisposition::Conflict
            {
                return None;
            }
            spend(remaining_work, cancellation, direct.records.len())?;
            parents.insert(
                current.id.as_str(),
                direct
                    .records
                    .iter()
                    .map(|record| record.id.as_str())
                    .collect::<Vec<_>>(),
            );
            pending.extend(direct.records);
            types.insert(current.id.as_str(), current);
        }
        let mut ancestry = HashMap::default();
        for id in types.keys().copied() {
            let mut seen = HashSet::default();
            let mut pending = parents[id].clone();
            while let Some(parent) = pending.pop() {
                spend(remaining_work, cancellation, 1)?;
                if parent == id {
                    return None;
                }
                if seen.insert(parent) {
                    pending.extend(parents[parent].iter().copied());
                }
            }
            ancestry.insert(id, seen);
        }
        Some(JavaCallableInventory { types, ancestry })
    }

    /// Return an unambiguous public instance declaration only when its entire
    /// inherited name family has one member. Overloaded and overridden families
    /// require applicability/override proof and stay unknown at this boundary.
    pub(crate) fn java_single_instance_method<'a>(
        &'a self,
        owner: &'a SemanticModelSymbol,
        name: &str,
        remaining_work: &mut usize,
        cancellation: &crate::CancellationToken,
    ) -> Option<&'a SemanticModelSymbol> {
        let JavaCallableInventory { types, .. } =
            self.java_callable_inventory(owner, remaining_work, cancellation)?;
        let mut selected = None;
        for id in types.keys() {
            for index in self.symbols_by_owner.get(*id).into_iter().flatten() {
                spend(remaining_work, cancellation, 1)?;
                let member = &self.symbols[*index];
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
                selected = Some(member);
            }
        }
        selected
    }
}

fn spend(
    remaining: &mut usize,
    cancellation: &crate::CancellationToken,
    amount: usize,
) -> Option<()> {
    if cancellation.is_cancelled() {
        return None;
    }
    let Some(next) = remaining.checked_sub(amount) else {
        *remaining = 0;
        return None;
    };
    *remaining = next;
    Some(())
}

fn same_signature(left: &SemanticModelSymbol, right: &SemanticModelSymbol) -> bool {
    let (Some(left_signature), Some(right_signature)) =
        (&left.structured_signature, &right.structured_signature)
    else {
        return false;
    };
    left.name == right.name
        && left_signature.type_parameters == right_signature.type_parameters
        && left_signature.parameters.len() == right_signature.parameters.len()
        && left_signature
            .parameters
            .iter()
            .zip(&right_signature.parameters)
            .all(|(left, right)| left.r#type == right.r#type && left.variadic == right.variadic)
}

fn ground_signature(
    signature: &Signature,
    remaining: &mut usize,
    cancellation: &crate::CancellationToken,
) -> Option<bool> {
    let mut pending: Vec<_> = signature
        .parameters
        .iter()
        .map(|parameter| &parameter.r#type)
        .chain(signature.returns.iter())
        .collect();
    while let Some(ty) = pending.pop() {
        spend(remaining, cancellation, 1)?;
        match ty {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments)
            }
            TypeRef::Array { element } => pending.push(element),
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.iter().map(Box::as_ref)),
            _ => return Some(false),
        }
    }
    Some(true)
}
