//! Structured PHPDoc type facts used by PHP receiver analysis.
//!
//! The external parser owns the docblock and type grammars. This module only
//! projects the small facts Bifrost can currently prove safely: one nominal
//! return type, or one nominal element type for an array/iterable annotation.

use mago_allocator::LocalArena;
use mago_database::file::FileId;
use mago_phpdoc_syntax::PHPDocParser;
use mago_phpdoc_syntax::cst::r#type::{GenericParameters, ReferenceKind, Type};
use mago_phpdoc_syntax::cst::{Document, TagValue};

fn unique_phpdoc_type(types: impl Iterator<Item = Option<String>>) -> Option<String> {
    let mut types = types;
    let value = types.next()??;
    types.next().is_none().then_some(value)
}

pub fn return_nominal_type(comment: &str) -> Option<String> {
    with_document(comment, |document| {
        unique_phpdoc_type(document.tags().filter_map(|tag| match &tag.value {
            TagValue::Return(value) | TagValue::RealReturn(value) => {
                Some(nominal_type(value.r#type))
            }
            _ => None,
        }))
    })
}

pub fn return_element_type(comment: &str) -> Option<String> {
    with_document(comment, |document| {
        unique_phpdoc_type(document.tags().filter_map(|tag| match &tag.value {
            TagValue::Return(value) | TagValue::RealReturn(value) => {
                Some(collection_element_type(value.r#type))
            }
            _ => None,
        }))
    })
}

pub fn parameter_element_type(comment: &str, parameter: &str) -> Option<String> {
    with_document(comment, |document| {
        unique_phpdoc_type(document.tags().filter_map(|tag| match &tag.value {
            TagValue::Param(value)
                if value.parameter.as_ref().is_some_and(|variable| {
                    variable.value.strip_prefix(b"$") == Some(parameter.as_bytes())
                }) =>
            {
                Some(collection_element_type(value.r#type))
            }
            _ => None,
        }))
    })
}

pub fn var_element_type(comment: &str) -> Option<String> {
    with_document(comment, |document| {
        unique_phpdoc_type(document.tags().filter_map(|tag| match &tag.value {
            TagValue::Var(value) => Some(collection_element_type(value.r#type)),
            _ => None,
        }))
    })
}

pub fn var_nominal_type(comment: &str) -> Option<String> {
    with_document(comment, |document| {
        unique_phpdoc_type(document.tags().filter_map(|tag| match &tag.value {
            TagValue::Var(value) => Some(nominal_type(value.r#type)),
            _ => None,
        }))
    })
}

fn with_document<T>(comment: &str, read: impl FnOnce(&Document<'_>) -> Option<T>) -> Option<T> {
    let arena = LocalArena::new();
    let document = PHPDocParser::parse(&arena, FileId::zero(), comment.as_bytes());
    (!document.has_errors()).then(|| read(&document)).flatten()
}

// Mago unions are binary trees. Flatten before projection: an unsupported or
// ambiguous subtree must never disappear and leave a falsely unique owner.
fn single_non_null_type<'a, 'arena>(ty: &'a Type<'arena>) -> Option<&'a Type<'arena>> {
    let mut stack = vec![ty];
    let mut only = None;
    while let Some(ty) = stack.pop() {
        match ty {
            Type::Parenthesized(value) => stack.push(value.inner),
            Type::Nullable(value) => stack.push(value.inner),
            Type::Union(value) => {
                stack.push(value.right);
                stack.push(value.left);
            }
            Type::Null(_) => {}
            _ => {
                if only.replace(ty).is_some() {
                    return None;
                }
            }
        }
    }
    only
}

fn nominal_type(ty: &Type<'_>) -> Option<String> {
    match single_non_null_type(ty)? {
        Type::Reference(reference) if reference.parameters.is_none() => {
            reference_identifier(&reference.kind)
        }
        _ => None,
    }
}

fn collection_element_type(ty: &Type<'_>) -> Option<String> {
    match single_non_null_type(ty)? {
        Type::Slice(slice) => nominal_type(slice.inner),
        Type::Array(array) => generic_element_type(array.parameters.as_ref()),
        Type::NonEmptyArray(array) => generic_element_type(array.parameters.as_ref()),
        Type::AssociativeArray(array) => generic_element_type(array.parameters.as_ref()),
        Type::List(list) => generic_element_type(list.parameters.as_ref()),
        Type::NonEmptyList(list) => generic_element_type(list.parameters.as_ref()),
        Type::Iterable(iterable) => generic_element_type(iterable.parameters.as_ref()),
        Type::Reference(reference) => generic_element_type(reference.parameters.as_ref()),
        _ => None,
    }
}

fn generic_element_type(parameters: Option<&GenericParameters<'_>>) -> Option<String> {
    let parameters = parameters?;
    let entries = parameters.entries.as_slice();
    let element = match entries {
        [element] | [_, element] => &element.inner,
        _ => return None,
    };
    nominal_type(element)
}

fn reference_identifier(kind: &ReferenceKind<'_>) -> Option<String> {
    let ReferenceKind::Identifier(identifier) = kind else {
        return None;
    };
    std::str::from_utf8(identifier.value)
        .ok()
        .map(str::to_string)
}

/// Whether a docblock states members that no PHP declaration states:
/// `@method`, `@property`, `@property-read`, or `@property-write`.
///
/// Bifrost synthesizes no declaration from these tags. A caller that publishes
/// a type carrying them must therefore report the type's surface as read
/// incompletely, so that a name's absence from the published surface is never
/// mistaken for proof that the type does not declare it.
pub fn declares_docblock_only_members(comment: &str) -> bool {
    with_document(comment, |document| {
        document
            .tags()
            .any(|tag| {
                matches!(
                    tag.value,
                    TagValue::Method(_)
                        | TagValue::Property(_)
                        | TagValue::PropertyRead(_)
                        | TagValue::PropertyWrite(_)
                )
            })
            .then_some(())
    })
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_single_nominal_phpdoc_facts() {
        assert_eq!(
            Some("App\\OAuth2".to_string()),
            return_nominal_type("/** @return App\\OAuth2 */")
        );
        assert_eq!(
            Some("App\\Mapper".to_string()),
            parameter_element_type("/** @param App\\Mapper[] $mappers */", "mappers")
        );
        assert_eq!(
            Some("App\\Source".to_string()),
            parameter_element_type("/** @param list<App\\Source> $sources */", "sources")
        );
        assert_eq!(
            Some("App\\Reason".to_string()),
            var_element_type("/** @var array<string, App\\Reason> */")
        );
        assert_eq!(
            Some("App\\Cache".to_string()),
            var_nominal_type("/** @var App\\Cache */")
        );
        assert_eq!(None, return_nominal_type("/** @return A|B */"));
        assert_eq!(None, var_nominal_type("/** @var A|B */"));
        assert_eq!(None, var_element_type("/** @var array<A|B> */"));
        assert_eq!(None, return_nominal_type("/** @return mixed */"));
    }
}

#[cfg(test)]
mod phpdoc_regression_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: nested unions and unsupported tags invented unique owners"
    )]
    fn union_projection_never_discards_unknown_arms() {
        for ty in ["A|B|C", "A|mixed", "A|int", "(A|B)|C"] {
            assert_eq!(
                return_nominal_type(&format!("/** @return {ty} */")),
                None,
                "{ty}"
            );
        }
        for ty in ["A[]|B[]|C[]", "A[]|mixed", "A[]|int"] {
            assert_eq!(
                return_element_type(&format!("/** @return {ty} */")),
                None,
                "{ty}"
            );
        }
        assert_eq!(
            return_nominal_type("/**\n * @return A\n * @real-return mixed\n */"),
            None
        );
    }

    // Mago's distinct return tags, nullable/slice/generic CST nodes and
    // synthetic-member tag variants must retain the same projection contract.
    #[test]
    fn phpdoc_parser_boundary_table() {
        for tag in ["return", "real-return"] {
            assert_eq!(
                return_nominal_type(&format!("/** @{tag} Widget */")),
                Some("Widget".into())
            );
            for ty in [
                "?Widget[]",
                "Widget[]|null",
                "null|Widget[]",
                "array<string, Widget>|null",
            ] {
                assert_eq!(
                    return_element_type(&format!("/** @{tag} {ty} */")),
                    Some("Widget".into()),
                    "{tag}: {ty}"
                );
            }
        }
        assert_eq!(
            parameter_element_type("/** @param ?Widget[] $items */", "items"),
            Some("Widget".into())
        );
        assert_eq!(
            var_element_type("/** @var Widget[]|null */"),
            Some("Widget".into())
        );
        assert!(declares_docblock_only_members(
            "/**\n * @method Widget make()\n * @deprecated\n */"
        ));
        assert!(!declares_docblock_only_members("/** plain prose */"));
    }
}
