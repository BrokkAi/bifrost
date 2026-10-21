//! Positive Java functional-method proof over the selected declaration model.

use crate::analyzer::semantic_model::overlay::*;

#[doc(hidden)]
pub struct JavaCallableInventory<'a> {
    #[doc(hidden)]
    pub types: HashMap<&'a str, &'a SemanticModelSymbol>,
    #[doc(hidden)]
    pub ancestry: HashMap<&'a str, HashSet<&'a str>>,
}

#[doc(hidden)]
pub fn spend(
    remaining: &mut usize,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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

#[doc(hidden)]
pub fn same_signature(left: &SemanticModelSymbol, right: &SemanticModelSymbol) -> bool {
    let (Some(left_signature), Some(right_signature)) =
        (&left.structured_signature, &right.structured_signature)
    else {
        return false;
    };
    !left_signature.contains_unknown_types()
        && !right_signature.contains_unknown_types()
        && left.name == right.name
        && left_signature.type_parameters == right_signature.type_parameters
        && left_signature.parameters.len() == right_signature.parameters.len()
        && left_signature
            .parameters
            .iter()
            .zip(&right_signature.parameters)
            .all(|(left, right)| left.r#type == right.r#type && left.variadic == right.variadic)
}

#[doc(hidden)]
pub fn ground_signature(
    signature: &Signature,
    remaining: &mut usize,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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
