//! Java functional-interface proof shared by declaration inventories.

use super::primitives::JavaPrimitive;
use super::type_projection::{JavaArgument, compose_java_positions};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// A complete and unambiguous type's direct callable hierarchy.
pub struct CallableType<T> {
    pub is_interface: bool,
    pub sealed: bool,
    pub parents: Vec<T>,
}

/// Reads and work accounting for the shared iterative hierarchy walk.
pub trait CallableInventory {
    type Type: Clone + Eq + Hash;
    fn spend(&mut self) -> Option<()>;
    fn callable_type(&mut self, owner: &Self::Type) -> Option<CallableType<Self::Type>>;
}

/// Traversal order and transitive ancestry, aligned by index.
pub struct CallableHierarchy<T> {
    pub types: Vec<(T, CallableType<T>)>,
    pub ancestry: Vec<HashSet<T>>,
}

/// Read a bounded callable hierarchy and reject cycles. Neither this walk nor
/// its caller retains an inventory beyond the request.
pub fn callable_inventory<I: CallableInventory>(
    inventory: &mut I,
    owner: I::Type,
) -> Option<CallableHierarchy<I::Type>> {
    let mut types = Vec::new();
    let mut indices = HashMap::new();
    let mut pending = vec![owner];
    while let Some(current) = pending.pop() {
        inventory.spend()?;
        if indices.contains_key(&current) {
            continue;
        }
        let facts = inventory.callable_type(&current)?;
        pending.extend(facts.parents.iter().cloned());
        indices.insert(current.clone(), types.len());
        types.push((current, facts));
    }
    let mut ancestry = Vec::new();
    for (id, facts) in &types {
        let mut seen = HashSet::new();
        let mut pending = facts.parents.clone();
        while let Some(parent) = pending.pop() {
            inventory.spend()?;
            if parent == *id {
                return None;
            }
            if seen.insert(parent.clone()) {
                let (_, facts) = &types[*indices.get(&parent)?];
                pending.extend(facts.parents.iter().cloned());
            }
        }
        ancestry.push(seen);
    }
    Some(CallableHierarchy { types, ancestry })
}

/// Erased reference identity, including array rank and primitive array elements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasedReference<I> {
    pub element: ErasedElement<I>,
    pub dimensions: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErasedElement<I> {
    Primitive(JavaPrimitive),
    Declared(I),
}

/// Parameter/return information whose equality can be proved under substitution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FunctionalType<R, V> {
    Primitive(JavaPrimitive),
    TypeVariable(V),
    /// A structurally resolved erased identity, independent of substitution.
    Reference(R),
    /// Syntax proves a reference type, but its declaration is unavailable.
    NonPrimitive {
        simple_name: Option<String>,
        dimensions: usize,
    },
    Unknown,
}

/// Facts about a visible instance method. Adapters omit static and invisible
/// declarations and return unknown for an incomplete or ambiguous signature.
pub struct FunctionalMethod {
    pub is_abstract: bool,
    pub has_type_parameters: bool,
}

/// Inventory and structured signature operations. Unknown facts fail closed.
pub trait FunctionalInventory: CallableInventory {
    type Method: Clone + Eq;
    type Reference: Clone + Eq;
    type Variable: Clone + Eq;
    type ClosedArgument: Clone + Eq;
    fn type_parameters(&mut self, _owner: &Self::Type) -> Option<Vec<Self::Variable>> {
        None
    }
    fn edge_arguments(
        &mut self,
        _owner: &Self::Type,
        _parent: &Self::Type,
    ) -> Option<Vec<JavaArgument<Self::ClosedArgument>>> {
        None
    }
    fn project_method(
        &mut self,
        method: &Self::Method,
        _parameters: Option<&[Self::Variable]>,
        _arguments: Option<&[JavaArgument<Self::ClosedArgument>]>,
        _target_parameters: Option<&[Self::Variable]>,
    ) -> Option<Self::Method> {
        Some(method.clone())
    }

    /// Charge every member visited, including skipped static/private members.
    fn methods(&mut self, owner: &Self::Type) -> Option<Vec<Self::Method>>;
    fn object_methods(&mut self) -> Option<Vec<Self::Method>>;
    fn method(&mut self, method: &Self::Method) -> Option<FunctionalMethod>;
    fn name_and_arity(&mut self, method: &Self::Method) -> Option<(String, usize)>;
    fn parameter_type(
        &mut self,
        method: &Self::Method,
        ordinal: usize,
    ) -> Option<FunctionalType<Self::Reference, Self::Variable>>;
    /// An absent return type denotes void; Unknown denotes an unreadable type.
    fn return_type(
        &mut self,
        method: &Self::Method,
    ) -> Option<Option<FunctionalType<Self::Reference, Self::Variable>>>;
    /// Preserve structured signature agreement beyond erasure (for example,
    /// List<String> and List<Integer> must not become one contract). Called
    /// only after the position's erased types have proved equal.
    fn parameter_agreement(
        &mut self,
        left: &Self::Method,
        right: &Self::Method,
        ordinal: usize,
    ) -> Option<bool>;
    fn return_agreement(&mut self, left: &Self::Method, right: &Self::Method) -> Option<bool>;
    /// A method variable is ground even on an inherited declaration.
    fn method_variable_position(&mut self, _variable: &Self::Variable) -> Option<(usize, usize)> {
        None
    }
    fn reference_name(&mut self, _reference: &Self::Reference) -> Option<(String, usize)> {
        None
    }
    /// The leftmost bound's erased identity; absent means unrecorded.
    fn variable_erasure(&mut self, _variable: &Self::Variable) -> Option<Self::Reference> {
        None
    }
    /// Structural terminal name of an erased class bound when identity is open.
    fn variable_erasure_name(&mut self, _variable: &Self::Variable) -> Option<(String, usize)> {
        None
    }
    /// Method formals and their bounds must agree by position. Unknown bounds
    /// cannot establish equality, including for a zero-argument method.
    fn method_parameters_agree(
        &mut self,
        left: &Self::Method,
        right: &Self::Method,
    ) -> Option<bool> {
        let left = self.method(left)?;
        let right = self.method(right)?;
        if left.has_type_parameters || right.has_type_parameters {
            None
        } else {
            Some(true)
        }
    }
    fn ground(&mut self, method: &Self::Method) -> Option<bool>;
}

/// A selected contract, including whether its types need inherited substitution.
pub struct JavaFunctionalMethod<M> {
    pub method: M,
    pub signature_ground: bool,
}

/// Compare two classified types using recorded variable coordinates and erasures.
#[doc(hidden)]
pub fn same_type<I: FunctionalInventory>(
    inventory: &mut I,
    left: FunctionalType<I::Reference, I::Variable>,
    left_ground: bool,
    right: FunctionalType<I::Reference, I::Variable>,
    right_ground: bool,
) -> Option<bool> {
    use FunctionalType::*;
    match (left, right) {
        (Unknown, _) | (_, Unknown) => None,
        (Primitive(left), Primitive(right)) => Some(left == right),
        (Primitive(_), _) | (_, Primitive(_)) => Some(false),
        (Reference(left), Reference(right)) => Some(left == right),
        (
            NonPrimitive {
                simple_name: Some(left),
                dimensions: ld,
            },
            NonPrimitive {
                simple_name: Some(right),
                dimensions: rd,
            },
        ) => {
            if left != right || ld != rd {
                Some(false)
            } else {
                None
            }
        }
        (
            NonPrimitive {
                simple_name: Some(name),
                dimensions,
            },
            Reference(reference),
        )
        | (
            Reference(reference),
            NonPrimitive {
                simple_name: Some(name),
                dimensions,
            },
        ) => {
            let (other, rank) = inventory.reference_name(&reference)?;
            if name != other || dimensions != rank {
                Some(false)
            } else {
                None
            }
        }
        (
            TypeVariable(variable),
            NonPrimitive {
                simple_name: Some(name),
                dimensions,
            },
        ) if left_ground || inventory.method_variable_position(&variable).is_some() => {
            if inventory.variable_erasure_name(&variable)? != (name, dimensions) {
                Some(false)
            } else {
                None
            }
        }
        (
            NonPrimitive {
                simple_name: Some(name),
                dimensions,
            },
            TypeVariable(variable),
        ) if right_ground || inventory.method_variable_position(&variable).is_some() => {
            if (name, dimensions) != inventory.variable_erasure_name(&variable)? {
                Some(false)
            } else {
                None
            }
        }
        (TypeVariable(left), TypeVariable(right)) => {
            let lp = inventory.method_variable_position(&left);
            let rp = inventory.method_variable_position(&right);
            if (left_ground || lp.is_some()) && (right_ground || rp.is_some()) {
                if let (Some(left), Some(right)) = (
                    inventory.variable_erasure(&left),
                    inventory.variable_erasure(&right),
                ) {
                    if left != right {
                        return Some(false);
                    }
                } else if let (Some(left), Some(right)) = (
                    inventory.variable_erasure_name(&left),
                    inventory.variable_erasure_name(&right),
                ) && left != right
                {
                    return Some(false);
                }
                if (lp.is_some() && lp == rp) || (lp.is_none() && rp.is_none() && left == right) {
                    return Some(true);
                }
            }
            None
        }
        (TypeVariable(variable), Reference(reference))
            if left_ground || inventory.method_variable_position(&variable).is_some() =>
        {
            if let Some(erasure) = inventory.variable_erasure(&variable) {
                if erasure != reference {
                    return Some(false);
                }
            } else if let (Some(left), Some(right)) = (
                inventory.variable_erasure_name(&variable),
                inventory.reference_name(&reference),
            ) && left != right
            {
                return Some(false);
            }
            None
        }
        (Reference(reference), TypeVariable(variable))
            if right_ground || inventory.method_variable_position(&variable).is_some() =>
        {
            if let Some(erasure) = inventory.variable_erasure(&variable) {
                if reference != erasure {
                    return Some(false);
                }
            } else if let (Some(left), Some(right)) = (
                inventory.reference_name(&reference),
                inventory.variable_erasure_name(&variable),
            ) && left != right
            {
                return Some(false);
            }
            None
        }
        _ => None,
    }
}

fn same_signature<I: FunctionalInventory>(
    inventory: &mut I,
    left: &I::Method,
    left_ground: bool,
    right: &I::Method,
    right_ground: bool,
) -> Option<bool> {
    let (left_name, count) = inventory.name_and_arity(left)?;
    if (left_name, count) != inventory.name_and_arity(right)? {
        return Some(false);
    }
    let mut unknown = inventory.method_parameters_agree(left, right) != Some(true);
    for ordinal in 0..count {
        inventory.spend()?;
        let left_type = inventory.parameter_type(left, ordinal)?;
        let right_type = inventory.parameter_type(right, ordinal)?;
        let references = matches!(
            (&left_type, &right_type),
            (FunctionalType::Reference(_), FunctionalType::Reference(_))
        );
        let agreement = match same_type(inventory, left_type, left_ground, right_type, right_ground)
        {
            Some(true) if references => inventory
                .parameter_agreement(left, right, ordinal)
                .filter(|same| *same),
            result => result,
        };
        match agreement {
            Some(false) => return Some(false),
            None => unknown = true,
            Some(true) => {}
        }
    }
    if unknown { None } else { Some(true) }
}

fn same_return<I: FunctionalInventory>(
    inventory: &mut I,
    left: &I::Method,
    left_ground: bool,
    right: &I::Method,
    right_ground: bool,
) -> Option<bool> {
    match (inventory.return_type(left)?, inventory.return_type(right)?) {
        (None, None) => Some(true),
        (Some(_), None) | (None, Some(_)) => Some(false),
        (Some(left_type), Some(right_type)) => {
            let references = matches!(
                (&left_type, &right_type),
                (FunctionalType::Reference(_), FunctionalType::Reference(_))
            );
            match same_type(inventory, left_type, left_ground, right_type, right_ground) {
                Some(true) if references => {
                    inventory.return_agreement(left, right).filter(|same| *same)
                }
                result => result,
            }
        }
    }
}

/// Prove a single abstract method under JLS 9.8. Traversal is iterative;
/// incomplete inventories, cycles, generic abstract methods, unknown inherited
/// substitutions and unproved override return agreement fail closed.
pub fn functional_method<I: FunctionalInventory>(
    inventory: &mut I,
    owner: I::Type,
) -> Option<JavaFunctionalMethod<I::Method>> {
    let object = inventory.object_methods()?;
    let CallableHierarchy { types, ancestry } = callable_inventory(inventory, owner.clone())?;
    if types
        .iter()
        .any(|(id, facts)| !facts.is_interface || (*id == owner && facts.sealed))
    {
        return None;
    }
    let parameters = types
        .iter()
        .map(|(id, _)| inventory.type_parameters(id))
        .collect::<Vec<_>>();
    let indices = types
        .iter()
        .enumerate()
        .map(|(index, (id, _))| (id.clone(), index))
        .collect::<HashMap<_, _>>();
    let root_index = *indices.get(&owner)?;
    let target_parameters = parameters[root_index].as_deref();
    let mut projections = HashMap::new();
    projections.insert(
        owner.clone(),
        target_parameters.map(|parameters| {
            (0..parameters.len())
                .map(JavaArgument::Position)
                .collect::<Vec<_>>()
        }),
    );
    let mut pending = vec![owner.clone()];
    while let Some(current) = pending.pop() {
        inventory.spend()?;
        let index = *indices.get(&current)?;
        let current_arguments = projections.get(&current)?.clone();
        for parent in &types[index].1.parents {
            inventory.spend()?;
            let parent_index = *indices.get(parent)?;
            let edge = inventory.edge_arguments(&current, parent);
            let next = parameters[parent_index].as_ref().map(|parent_parameters| {
                let composed = current_arguments.as_ref().and_then(|arguments| {
                    compose_java_positions(
                        arguments.clone(),
                        [(parameters[index].as_ref().map(Vec::len), edge.as_deref())],
                        Some(parent_parameters.len()),
                    )
                });
                composed.unwrap_or_else(|| vec![JavaArgument::Open; parent_parameters.len()])
            });
            if let Some(prior) = projections.get(parent) {
                // JLS 8.1.5 forbids inconsistent inherited instantiations. An
                // open path cannot prove the two instantiations agree.
                if prior != &next
                    || next.as_ref().is_none_or(|arguments| {
                        arguments
                            .iter()
                            .any(|argument| matches!(argument, JavaArgument::Open))
                    })
                {
                    return None;
                }
            } else {
                projections.insert(parent.clone(), next);
                pending.push(parent.clone());
            }
        }
    }
    let mut methods = Vec::new();
    for (index, (id, _interface)) in types.iter().enumerate() {
        for original in &inventory.methods(id)? {
            inventory.spend()?;
            let member = inventory.project_method(
                original,
                parameters[index].as_deref(),
                projections.get(id)?.as_deref(),
                target_parameters,
            )?;
            let member = &member;
            let facts = inventory.method(member)?;
            if facts.is_abstract && facts.has_type_parameters {
                return None;
            }
            let ground = *id == owner || inventory.ground(member)?;
            let mut is_object = false;
            for candidate in &object {
                inventory.spend()?;
                if same_signature(inventory, member, ground, candidate, true)? {
                    if !same_return(inventory, member, ground, candidate, true)? {
                        return None;
                    }
                    is_object = true;
                }
            }
            if is_object {
                if !facts.is_abstract {
                    return None;
                }
            } else {
                methods.push((index, member.clone(), facts.is_abstract, ground));
            }
        }
    }
    let mut effective = Vec::new();
    for (id, member, abstract_method, ground) in &methods {
        let mut overridden = false;
        for (other_id, other, _, other_ground) in &methods {
            inventory.spend()?;
            if member == other {
                continue;
            }
            if same_signature(inventory, member, *ground, other, *other_ground)? {
                if id == other_id {
                    return None;
                }
                if ancestry[*other_id].contains(&types[*id].0) {
                    if !same_return(inventory, member, *ground, other, *other_ground)? {
                        return None;
                    }
                    overridden = true;
                }
            }
        }
        if !overridden {
            effective.push((member, *abstract_method, *ground));
        }
    }
    let mut contract: Option<JavaFunctionalMethod<I::Method>> = None;
    for (index, (member, abstract_method, ground)) in effective.iter().enumerate() {
        for (other, other_abstract, other_ground) in &effective[index + 1..] {
            inventory.spend()?;
            if same_signature(inventory, member, *ground, other, *other_ground)?
                && (!abstract_method || !other_abstract)
            {
                return None;
            }
        }
        if !abstract_method {
            continue;
        }
        if let Some(prior) = &contract {
            if !same_signature(
                inventory,
                &prior.method,
                prior.signature_ground,
                member,
                *ground,
            )? || !same_return(
                inventory,
                &prior.method,
                prior.signature_ground,
                member,
                *ground,
            )? {
                return None;
            }
        } else {
            contract = Some(JavaFunctionalMethod {
                method: (*member).clone(),
                signature_ground: *ground,
            });
        }
    }
    contract
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_comparison_is_three_valued() {
        struct Inventory;
        impl CallableInventory for Inventory {
            type Type = ();
            fn spend(&mut self) -> Option<()> {
                Some(())
            }
            fn callable_type(&mut self, _: &()) -> Option<CallableType<()>> {
                None
            }
        }
        impl FunctionalInventory for Inventory {
            type Method = ();
            type Reference = &'static str;
            type Variable = &'static str;
            type ClosedArgument = ();
            fn methods(&mut self, _: &()) -> Option<Vec<()>> {
                None
            }
            fn object_methods(&mut self) -> Option<Vec<()>> {
                None
            }
            fn method(&mut self, _: &()) -> Option<FunctionalMethod> {
                None
            }
            fn name_and_arity(&mut self, _: &()) -> Option<(String, usize)> {
                None
            }
            fn parameter_type(
                &mut self,
                _: &(),
                _: usize,
            ) -> Option<FunctionalType<Self::Reference, Self::Variable>> {
                None
            }
            fn return_type(
                &mut self,
                _: &(),
            ) -> Option<Option<FunctionalType<Self::Reference, Self::Variable>>> {
                None
            }
            fn parameter_agreement(&mut self, _: &(), _: &(), _: usize) -> Option<bool> {
                None
            }
            fn return_agreement(&mut self, _: &(), _: &()) -> Option<bool> {
                None
            }
            fn ground(&mut self, _: &()) -> Option<bool> {
                None
            }
            fn reference_name(&mut self, reference: &&'static str) -> Option<(String, usize)> {
                Some(((*reference).to_owned(), 0))
            }
            fn variable_erasure_name(
                &mut self,
                variable: &&'static str,
            ) -> Option<(String, usize)> {
                (*variable == "V").then(|| ("CharSequence".to_owned(), 0))
            }
            fn variable_erasure(&mut self, variable: &&'static str) -> Option<Self::Reference> {
                match *variable {
                    "T" => Some("Object"),
                    "U" => Some("CharSequence"),
                    _ => None,
                }
            }
        }
        use FunctionalType::*;
        for (left, ground, right, expected) in [
            (TypeVariable("T"), true, Reference("Object"), None),
            (TypeVariable("U"), true, Reference("Object"), Some(false)),
            (
                TypeVariable("T"),
                false,
                Primitive(JavaPrimitive::Long),
                Some(false),
            ),
            (TypeVariable("U"), false, Reference("Object"), None),
            (Reference("String"), true, Reference("Object"), Some(false)),
            (Reference("String"), true, Reference("String"), Some(true)),
            (Unknown, true, Reference("Object"), None),
            (TypeVariable("V"), true, Reference("Object"), Some(false)),
            (TypeVariable("V"), false, Reference("Object"), None),
            (
                TypeVariable("V"),
                true,
                NonPrimitive {
                    simple_name: Some("Object".to_owned()),
                    dimensions: 0,
                },
                Some(false),
            ),
            (
                NonPrimitive {
                    simple_name: Some("Instant".to_owned()),
                    dimensions: 0,
                },
                true,
                Primitive(JavaPrimitive::Long),
                Some(false),
            ),
        ] {
            assert_eq!(
                same_type(&mut Inventory, left, ground, right, true),
                expected
            );
        }
    }
}
