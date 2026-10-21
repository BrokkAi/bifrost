#[doc(hidden)]
pub fn bounded_message(mut message: String, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message;
    }
    let mut end = max_bytes;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message
}

#[doc(hidden)]
pub fn visit_declared_type_refs<'a>(
    types: impl IntoIterator<Item = &'a crate::analyzer::semantic_model::TypeRef>,
    mut visit: impl FnMut(&str),
) {
    use crate::analyzer::semantic_model::TypeRef;

    let mut pending = types.into_iter().collect::<Vec<_>>();
    while let Some(reference) = pending.pop() {
        match reference {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                if let TypeRef::Declared { id, .. } = reference {
                    visit(id);
                }
                pending.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::Map { key, value } => {
                pending.push(key);
                pending.push(value);
            }
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.as_deref()),
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter().map(|parameter| &parameter.r#type));
                pending.extend(result.as_deref());
            }
            TypeRef::TypeParameter { .. } | TypeRef::Unknown => {}
        }
    }
}
