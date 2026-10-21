//! Java primitive types and identity/widening conversion rules.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaPrimitive {
    Boolean,
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
}

pub fn primitive_for_name(name: &str) -> Option<JavaPrimitive> {
    match name {
        "boolean" => Some(JavaPrimitive::Boolean),
        "byte" => Some(JavaPrimitive::Byte),
        "short" => Some(JavaPrimitive::Short),
        "char" => Some(JavaPrimitive::Char),
        "int" => Some(JavaPrimitive::Int),
        "long" => Some(JavaPrimitive::Long),
        "float" => Some(JavaPrimitive::Float),
        "double" => Some(JavaPrimitive::Double),
        _ => None,
    }
}

pub fn primitive_converts(source: JavaPrimitive, target: JavaPrimitive) -> bool {
    source == target || primitive_widens(source, target)
}

pub fn primitive_widens(source: JavaPrimitive, target: JavaPrimitive) -> bool {
    match source {
        JavaPrimitive::Byte => matches!(
            target,
            JavaPrimitive::Short
                | JavaPrimitive::Int
                | JavaPrimitive::Long
                | JavaPrimitive::Float
                | JavaPrimitive::Double
        ),
        JavaPrimitive::Short => matches!(
            target,
            JavaPrimitive::Int | JavaPrimitive::Long | JavaPrimitive::Float | JavaPrimitive::Double
        ),
        JavaPrimitive::Char => matches!(
            target,
            JavaPrimitive::Int | JavaPrimitive::Long | JavaPrimitive::Float | JavaPrimitive::Double
        ),
        JavaPrimitive::Int => matches!(
            target,
            JavaPrimitive::Long | JavaPrimitive::Float | JavaPrimitive::Double
        ),
        JavaPrimitive::Long => matches!(target, JavaPrimitive::Float | JavaPrimitive::Double),
        JavaPrimitive::Float => target == JavaPrimitive::Double,
        JavaPrimitive::Boolean | JavaPrimitive::Double => false,
    }
}
