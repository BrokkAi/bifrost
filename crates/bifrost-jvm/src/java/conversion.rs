//! Java invocation/initializer conversion over language-neutral selected types.
//! Readers supply identity, structure and hierarchy evidence; this algorithm
//! retains no graph and never substitutes an absent hierarchy proof.

use super::primitives::{JavaPrimitive, primitive_converts};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaConversion {
    Strict,
    Loose,
    Inapplicable,
    Unknown,
}

pub trait JavaConversionTypes {
    type Type: Copy;
    type Error;
    fn ground(&self, ty: Self::Type) -> bool;
    fn same(&self, left: Self::Type, right: Self::Type) -> bool;
    fn primitive(&self, ty: Self::Type) -> Option<JavaPrimitive>;
    fn element(&self, ty: Self::Type) -> Option<Self::Type>;
    fn name(&self, ty: Self::Type) -> Option<&str>;
    fn named(&self, ty: Self::Type) -> bool;
    fn nominal_widening(
        &mut self,
        source: Self::Type,
        target: Self::Type,
    ) -> Result<Option<bool>, Self::Error>;
    fn boxed_widening(
        &mut self,
        source: JavaPrimitive,
        target: Self::Type,
    ) -> Result<Option<bool>, Self::Error>;
}

pub fn wrapper_name(primitive: JavaPrimitive) -> &'static str {
    match primitive {
        JavaPrimitive::Boolean => "java.lang.Boolean",
        JavaPrimitive::Byte => "java.lang.Byte",
        JavaPrimitive::Short => "java.lang.Short",
        JavaPrimitive::Char => "java.lang.Character",
        JavaPrimitive::Int => "java.lang.Integer",
        JavaPrimitive::Long => "java.lang.Long",
        JavaPrimitive::Float => "java.lang.Float",
        JavaPrimitive::Double => "java.lang.Double",
    }
}

pub fn wrapper_primitive(name: &str) -> Option<JavaPrimitive> {
    Some(match name {
        "java.lang.Boolean" => JavaPrimitive::Boolean,
        "java.lang.Byte" => JavaPrimitive::Byte,
        "java.lang.Short" => JavaPrimitive::Short,
        "java.lang.Character" => JavaPrimitive::Char,
        "java.lang.Integer" => JavaPrimitive::Int,
        "java.lang.Long" => JavaPrimitive::Long,
        "java.lang.Float" => JavaPrimitive::Float,
        "java.lang.Double" => JavaPrimitive::Double,
        _ => return None,
    })
}

pub fn classify<T: JavaConversionTypes>(
    types: &mut T,
    mut actual: T::Type,
    mut formal: T::Type,
) -> Result<JavaConversion, T::Error> {
    use JavaConversion::*;
    if (types.element(actual).is_some() && types.primitive(formal).is_some())
        || (types.primitive(actual).is_some() && types.element(formal).is_some())
    {
        return Ok(Inapplicable);
    }
    if !types.ground(actual) || !types.ground(formal) {
        return Ok(Unknown);
    }
    match (types.primitive(actual), types.primitive(formal)) {
        (Some(a), Some(b)) => {
            return Ok(if primitive_converts(a, b) {
                Strict
            } else {
                Inapplicable
            });
        }
        (Some(a), None) => {
            let Some(name) = types.name(formal) else {
                return Ok(Unknown);
            };
            if name == wrapper_name(a) || name == "java.lang.Object" {
                return Ok(Loose);
            }
            if name == "java.lang.String" {
                return Ok(Inapplicable);
            }
            return Ok(match types.boxed_widening(a, formal)? {
                Some(true) => Loose,
                Some(false) => Inapplicable,
                None => Unknown,
            });
        }
        (None, Some(b)) => {
            let Some(name) = types.name(actual) else {
                return Ok(Unknown);
            };
            if name == "<null>" {
                return Ok(Inapplicable);
            }
            return Ok(if let Some(a) = wrapper_primitive(name) {
                if primitive_converts(a, b) {
                    Loose
                } else {
                    Inapplicable
                }
            } else if types.named(actual) {
                Inapplicable
            } else {
                Unknown
            });
        }
        _ => {}
    }
    loop {
        if types.same(actual, formal) || types.name(actual) == Some("<null>") {
            return Ok(Strict);
        }
        match (types.element(actual), types.element(formal)) {
            (Some(a), Some(b)) => {
                if types.primitive(a).is_some() || types.primitive(b).is_some() {
                    return Ok(if types.same(a, b) {
                        Strict
                    } else {
                        Inapplicable
                    });
                }
                actual = a;
                formal = b;
            }
            (Some(_), None) => {
                return Ok(
                    if matches!(
                        types.name(formal),
                        Some("java.lang.Object" | "java.lang.Cloneable" | "java.io.Serializable")
                    ) {
                        Strict
                    } else {
                        Inapplicable
                    },
                );
            }
            (None, Some(_)) => return Ok(Inapplicable),
            _ => {
                return Ok(
                    if types.name(formal) == Some("java.lang.Object")
                        && types.name(actual).is_some()
                    {
                        Strict
                    } else {
                        match types.nominal_widening(actual, formal)? {
                            Some(true) => Strict,
                            Some(false) => Inapplicable,
                            None => Unknown,
                        }
                    },
                );
            }
        }
    }
}
