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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaWildcard<T> {
    Any,
    Extends(T),
    Super(T),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaDifferentOwner {
    Incompatible,
    Projected(Vec<usize>),
    Open,
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
    /// None means argument provenance is unavailable; an empty list is a raw
    /// type and cannot establish containment either.
    fn arguments(&self, _ty: Self::Type) -> Option<Vec<Self::Type>> {
        None
    }
    fn wildcard(&self, _ty: Self::Type) -> Option<JavaWildcard<Self::Type>> {
        None
    }
    /// Some(false) requires conclusive incompatibility, not an exhausted
    /// search over absent or incomplete hierarchy rows. Missing proof is None.
    fn nominal_widening(
        &mut self,
        source: Self::Type,
        target: Self::Type,
    ) -> Result<Option<bool>, Self::Error>;
    fn different_owner_arguments(
        &mut self,
        actual: Self::Type,
        formal: Self::Type,
    ) -> Result<JavaDifferentOwner, Self::Error> {
        Ok(match self.nominal_widening(actual, formal)? {
            Some(false) => JavaDifferentOwner::Incompatible,
            Some(true) | None => JavaDifferentOwner::Open,
        })
    }
    fn boxed_widening(
        &mut self,
        source: JavaPrimitive,
        target: Self::Type,
    ) -> Result<Option<bool>, Self::Error>;
}

/// JLS 4.5.1 containment of each actual type argument by the formal's
/// argument at the same position, for two applications of one erased owner.
fn contains_arguments<T: JavaConversionTypes>(
    types: &mut T,
    actual: &[T::Type],
    formal: &[T::Type],
) -> Result<JavaConversion, T::Error> {
    use JavaConversion::*;
    assert_eq!(
        actual.len(),
        formal.len(),
        "one owner's applications have one arity"
    );
    let mut uncertain = false;
    let mut rejected = false;
    for (&actual, &formal) in actual.iter().zip(formal) {
        // Without capture conversion, a wildcard or variable actual decides nothing.
        if types.wildcard(actual).is_some() || !types.ground(actual) {
            uncertain = true;
            continue;
        }
        let argument_free = |types: &T, ty| types.arguments(ty).is_some_and(|a| a.is_empty());
        let Some(wildcard) = types.wildcard(formal) else {
            // A non-wildcard argument contains only the same type, so nested
            // arguments are compared for equality, never for containment.
            if types.same(actual, formal) && types.ground(formal) {
                continue;
            }
            // Two argument-free class types are proven different when
            // widening fails conclusively in either direction. `same` alone
            // cannot prove a difference: one class can have two spellings.
            if argument_free(types, actual) && argument_free(types, formal) {
                match (
                    types.nominal_widening(actual, formal)?,
                    types.nominal_widening(formal, actual)?,
                ) {
                    (Some(false), _) | (_, Some(false)) => rejected = true,
                    _ => uncertain = true,
                }
            } else {
                uncertain = true;
            }
            continue;
        };
        let widening = match wildcard {
            JavaWildcard::Any => {
                if types.primitive(actual).is_none()
                    && (types.name(actual).is_some() || types.element(actual).is_some())
                {
                    Some(true)
                } else {
                    None
                }
            }
            // Nominal widening compares erased owners, so it decides a bound
            // only between two argument-free class types.
            JavaWildcard::Extends(bound)
                if argument_free(types, actual) && argument_free(types, bound) =>
            {
                types.nominal_widening(actual, bound)?
            }
            JavaWildcard::Super(bound)
                if argument_free(types, actual) && argument_free(types, bound) =>
            {
                types.nominal_widening(bound, actual)?
            }
            JavaWildcard::Extends(_) | JavaWildcard::Super(_) => None,
        };
        match widening {
            Some(false) => rejected = true,
            None => uncertain = true,
            Some(true) => {}
        }
    }
    // Every argument must be contained, so one conclusive rejection decides
    // the conversion whatever the other arguments are.
    Ok(if rejected {
        Inapplicable
    } else if uncertain {
        Unknown
    } else {
        Strict
    })
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
    // #7620: known erased shapes can decide a conversion even when nested
    // arguments are not ground. An unknown outer kind supplies no such proof.
    match (types.element(actual), types.element(formal)) {
        (Some(_), None)
            if types.name(formal).is_some_and(|name| {
                !matches!(
                    name,
                    "java.lang.Object" | "java.lang.Cloneable" | "java.io.Serializable"
                )
            }) =>
        {
            return Ok(Inapplicable);
        }
        (None, Some(_)) if types.name(actual).is_some_and(|name| name != "<null>") => {
            return Ok(Inapplicable);
        }
        (None, None)
            if types.primitive(actual).is_none()
                && types.primitive(formal).is_none()
                && types.name(actual).is_some_and(|name| name != "<null>")
                && types.name(formal).is_some_and(|name| name != "<null>") =>
        {
            // Containment needs arguments on both sides. A raw formal falls
            // through to erased widening (a parameterized type is a subtype of
            // its raw type, JLS 4.10.2), and so does an actual without
            // arguments: a raw actual reaches a parameterized formal by
            // unchecked conversion (JLS 5.3), and an actual whose arguments
            // are unknown keeps the erased decision it had before arguments
            // were transported.
            if let (Some(a), Some(b)) = (types.arguments(actual), types.arguments(formal))
                && !a.is_empty()
                && !b.is_empty()
            {
                if types.name(actual) == types.name(formal) && a.len() == b.len() {
                    return contains_arguments(types, &a, &b);
                }
                return Ok(match types.different_owner_arguments(actual, formal)? {
                    JavaDifferentOwner::Incompatible => Inapplicable,
                    JavaDifferentOwner::Projected(positions) if positions.len() == b.len() => {
                        let projected: Vec<_> = positions
                            .into_iter()
                            .map(|position| {
                                assert!(
                                    position < a.len(),
                                    "projection position within actual arguments"
                                );
                                a[position]
                            })
                            .collect();
                        return contains_arguments(types, &projected, &b);
                    }
                    JavaDifferentOwner::Projected(_) | JavaDifferentOwner::Open => Unknown,
                });
            }
            match types.nominal_widening(actual, formal)? {
                Some(false) => return Ok(Inapplicable),
                // Different erased owners still need generic substitution.
                Some(true) if types.ground(actual) && types.ground(formal) => {
                    return Ok(Strict);
                }
                Some(true) | None => {}
            }
        }
        _ => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    enum Ty {
        Named(&'static str, Vec<usize>),
        Wild(JavaWildcard<usize>),
        Variable,
    }
    struct Types(Vec<Ty>);
    impl JavaConversionTypes for Types {
        type Type = usize;
        type Error = std::convert::Infallible;
        fn ground(&self, ty: usize) -> bool {
            matches!(&self.0[ty], Ty::Named(_, args) if args.iter().all(|arg| matches!(self.0[*arg], Ty::Named(_, _))))
        }
        fn same(&self, a: usize, b: usize) -> bool {
            match (&self.0[a], &self.0[b]) {
                (Ty::Named(a, aa), Ty::Named(b, bb)) => a == b && aa == bb,
                _ => false,
            }
        }
        fn primitive(&self, _: usize) -> Option<JavaPrimitive> {
            None
        }
        fn element(&self, _: usize) -> Option<usize> {
            None
        }
        fn name(&self, ty: usize) -> Option<&str> {
            match &self.0[ty] {
                Ty::Named(name, _) => Some(name),
                _ => None,
            }
        }
        fn named(&self, ty: usize) -> bool {
            matches!(self.0[ty], Ty::Named(_, _))
        }
        fn arguments(&self, ty: usize) -> Option<Vec<usize>> {
            match &self.0[ty] {
                Ty::Named(_, args) => Some(args.clone()),
                _ => None,
            }
        }
        fn wildcard(&self, ty: usize) -> Option<JavaWildcard<usize>> {
            match self.0[ty] {
                Ty::Wild(w) => Some(w),
                _ => None,
            }
        }
        fn nominal_widening(&mut self, a: usize, b: usize) -> Result<Option<bool>, Self::Error> {
            let answer = match (self.name(a), self.name(b)) {
                (Some(a), Some(b)) => Some(
                    a == b
                        || a == "String" && matches!(b, "CharSeq" | "Object")
                        || a == "CharSeq" && b == "Object",
                ),
                _ => None,
            };
            Ok(answer)
        }
        fn different_owner_arguments(
            &mut self,
            a: usize,
            b: usize,
        ) -> Result<JavaDifferentOwner, Self::Error> {
            match (self.name(a), self.name(b)) {
                (Some("ArrayList"), Some("Iterable")) => Ok(JavaDifferentOwner::Projected(vec![0])),
                (Some("List"), Some("Iterable")) => Ok(JavaDifferentOwner::Projected(vec![0])),
                (Some("OpenList"), Some("Iterable")) => Ok(JavaDifferentOwner::Open),
                (Some("BadList"), Some("Iterable")) => Ok(JavaDifferentOwner::Incompatible),
                (Some("ShortList"), Some("Iterable")) => Ok(JavaDifferentOwner::Projected(vec![])),
                _ => Ok(match self.nominal_widening(a, b)? {
                    Some(false) => JavaDifferentOwner::Incompatible,
                    _ => JavaDifferentOwner::Open,
                }),
            }
        }
        fn boxed_widening(
            &mut self,
            _: JavaPrimitive,
            _: usize,
        ) -> Result<Option<bool>, Self::Error> {
            Ok(None)
        }
    }

    #[test]
    fn classify_same_owner_containment() {
        let mut types = Types(vec![
            Ty::Named("String", vec![]),         // 0
            Ty::Named("CharSeq", vec![]),        // 1
            Ty::Named("Object", vec![]),         // 2
            Ty::Wild(JavaWildcard::Extends(1)),  // 3
            Ty::Wild(JavaWildcard::Extends(0)),  // 4
            Ty::Wild(JavaWildcard::Super(0)),    // 5
            Ty::Wild(JavaWildcard::Super(1)),    // 6
            Ty::Wild(JavaWildcard::Any),         // 7
            Ty::Variable,                        // 8
            Ty::Named("Box", vec![0]),           // 9
            Ty::Named("Box", vec![3]),           // 10
            Ty::Named("Box", vec![4]),           // 11
            Ty::Named("Box", vec![5]),           // 12
            Ty::Named("Box", vec![6]),           // 13
            Ty::Named("Box", vec![7]),           // 14
            Ty::Named("Box", vec![8]),           // 15
            Ty::Named("Box", vec![]),            // 16 raw
            Ty::Named("Other", vec![3]),         // 17
            Ty::Named("Box", vec![1]),           // 18
            Ty::Named("Box", vec![9]),           // 19 Box<Box<String>>
            Ty::Named("Box", vec![10]),          // 20 Box<Box<? extends CharSeq>>
            Ty::Wild(JavaWildcard::Extends(10)), // 21 ? extends Box<? extends CharSeq>
            Ty::Named("Box", vec![21]),          // 22
            Ty::Named("Box", vec![2]),           // 23 Box<Object>
            Ty::Named("Box", vec![23]),          // 24 Box<Box<Object>>
            Ty::Named("Pair", vec![1, 8]),       // 25 Pair<CharSeq, T>
            Ty::Named("Pair", vec![4, 7]),       // 26 Pair<? extends String, ?>
            Ty::Named("String", vec![1]),        // 27 String<CharSeq> (an owner with arguments)
            Ty::Named("CharSeq", vec![1]),       // 28 CharSeq<CharSeq>
        ]);
        for (actual, formal, expected) in [
            (9, 9, JavaConversion::Strict),
            (9, 10, JavaConversion::Strict),
            (18, 11, JavaConversion::Inapplicable),
            (18, 12, JavaConversion::Strict),
            (9, 13, JavaConversion::Inapplicable),
            (9, 14, JavaConversion::Strict),
            (10, 9, JavaConversion::Unknown),
            (15, 10, JavaConversion::Unknown),
            (16, 10, JavaConversion::Unknown),
            // Incompatible erased owners reject whatever the arguments are.
            (9, 17, JavaConversion::Inapplicable),
            // Compatible erased owners with arguments need supertype projection.
            (27, 28, JavaConversion::Unknown),
            // A non-wildcard argument requires the same type, not a subtype.
            (9, 18, JavaConversion::Inapplicable),
            // One conclusive rejection decides despite another open argument.
            (25, 26, JavaConversion::Inapplicable),
            // Nested arguments under a non-wildcard argument are not contained.
            (19, 20, JavaConversion::Unknown),
            // Erased widening cannot decide a parameterized wildcard bound.
            (24, 22, JavaConversion::Unknown),
            // A parameterized type widens to its raw type.
            (9, 16, JavaConversion::Strict),
            // A raw actual reaches a parameterized formal by unchecked conversion.
            (16, 9, JavaConversion::Strict),
        ] {
            assert_eq!(
                classify(&mut types, actual, formal),
                Ok(expected),
                "{actual} -> {formal}"
            );
        }
    }

    #[test]
    fn classify_projected_owner_containment() {
        let mut types = Types(vec![
            Ty::Named("String", vec![]),
            Ty::Named("Integer", vec![]),
            Ty::Named("CharSeq", vec![]),
            Ty::Wild(JavaWildcard::Extends(2)),
            Ty::Named("ArrayList", vec![0]),
            Ty::Named("ArrayList", vec![1]),
            Ty::Named("Iterable", vec![3]),
            Ty::Wild(JavaWildcard::Extends(0)),
            Ty::Named("List", vec![7]),
            Ty::Named("OpenList", vec![0]),
            Ty::Named("BadList", vec![0]),
            Ty::Named("ShortList", vec![0]),
        ]);
        for (actual, expected) in [
            (4, JavaConversion::Strict),
            (5, JavaConversion::Inapplicable),
            (8, JavaConversion::Unknown),
            (9, JavaConversion::Unknown),
            (10, JavaConversion::Inapplicable),
            (11, JavaConversion::Unknown),
        ] {
            assert_eq!(classify(&mut types, actual, 6), Ok(expected), "{actual}");
        }
    }
}
