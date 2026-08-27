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

pub fn return_nominal_type(comment: &str) -> Option<String> {
    with_document(comment, |document| {
        let mut types = document.tags().filter_map(|tag| match &tag.value {
            TagValue::Return(value) | TagValue::RealReturn(value) => nominal_type(value.r#type),
            _ => None,
        });
        let nominal = types.next()?;
        types.next().is_none().then_some(nominal)
    })
}

pub fn return_element_type(comment: &str) -> Option<String> {
    with_document(comment, |document| {
        let mut types = document.tags().filter_map(|tag| match &tag.value {
            TagValue::Return(value) | TagValue::RealReturn(value) => {
                collection_element_type(value.r#type)
            }
            _ => None,
        });
        let nominal = types.next()?;
        types.next().is_none().then_some(nominal)
    })
}

pub fn parameter_element_type(comment: &str, parameter: &str) -> Option<String> {
    with_document(comment, |document| {
        let mut types = document.tags().filter_map(|tag| match &tag.value {
            TagValue::Param(value)
                if value.parameter.as_ref().is_some_and(|variable| {
                    variable.value.strip_prefix(b"$") == Some(parameter.as_bytes())
                }) =>
            {
                collection_element_type(value.r#type)
            }
            _ => None,
        });
        let nominal = types.next()?;
        types.next().is_none().then_some(nominal)
    })
}

pub fn var_element_type(comment: &str) -> Option<String> {
    with_document(comment, |document| {
        let mut types = document.tags().filter_map(|tag| match &tag.value {
            TagValue::Var(value) => collection_element_type(value.r#type),
            _ => None,
        });
        let nominal = types.next()?;
        types.next().is_none().then_some(nominal)
    })
}

pub fn var_nominal_type(comment: &str) -> Option<String> {
    with_document(comment, |document| {
        let mut types = document.tags().filter_map(|tag| match &tag.value {
            TagValue::Var(value) => nominal_type(value.r#type),
            _ => None,
        });
        let nominal = types.next()?;
        types.next().is_none().then_some(nominal)
    })
}

fn with_document<T>(comment: &str, read: impl FnOnce(&Document<'_>) -> Option<T>) -> Option<T> {
    let arena = LocalArena::new();
    let document = PHPDocParser::parse(&arena, FileId::zero(), comment.as_bytes());
    (!document.has_errors()).then(|| read(&document)).flatten()
}

fn nominal_type(ty: &Type<'_>) -> Option<String> {
    match ty {
        Type::Reference(reference) if reference.parameters.is_none() => {
            reference_identifier(&reference.kind)
        }
        Type::Parenthesized(parenthesized) => nominal_type(parenthesized.inner),
        Type::Nullable(nullable) => nominal_type(nullable.inner),
        Type::Union(union) => {
            let mut names = [union.left, union.right]
                .into_iter()
                .filter(|arm| !matches!(arm, Type::Null(_)))
                .filter_map(nominal_type);
            let nominal = names.next()?;
            names.next().is_none().then_some(nominal)
        }
        _ => None,
    }
}

fn collection_element_type(ty: &Type<'_>) -> Option<String> {
    match ty {
        Type::Slice(slice) => nominal_type(slice.inner),
        Type::Array(array) => generic_element_type(array.parameters.as_ref()),
        Type::NonEmptyArray(array) => generic_element_type(array.parameters.as_ref()),
        Type::AssociativeArray(array) => generic_element_type(array.parameters.as_ref()),
        Type::List(list) => generic_element_type(list.parameters.as_ref()),
        Type::NonEmptyList(list) => generic_element_type(list.parameters.as_ref()),
        Type::Iterable(iterable) => generic_element_type(iterable.parameters.as_ref()),
        Type::Reference(reference) => generic_element_type(reference.parameters.as_ref()),
        Type::Parenthesized(parenthesized) => collection_element_type(parenthesized.inner),
        Type::Nullable(nullable) => collection_element_type(nullable.inner),
        Type::Union(union) => {
            let mut names = [union.left, union.right]
                .into_iter()
                .filter(|arm| !matches!(arm, Type::Null(_)))
                .filter_map(collection_element_type);
            let nominal = names.next()?;
            names.next().is_none().then_some(nominal)
        }
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
