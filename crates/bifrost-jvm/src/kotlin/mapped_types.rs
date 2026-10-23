// Kotlin's mapped-types rule: https://kotlinlang.org/docs/java-interop.html#mapped-types
// Recipe v1: retain both Kotlin and mapped Java names, including inaccessible names.
pub const KOTLIN_JAVA_MAPPINGS: &[(&str, &str)] = &[
    ("kotlin.Any", "java.lang.Object"),
    ("kotlin.CharSequence", "java.lang.CharSequence"),
    ("kotlin.Comparable", "java.lang.Comparable"),
    ("kotlin.String", "java.lang.String"),
    ("kotlin.collections.Iterable", "java.lang.Iterable"),
    ("kotlin.collections.MutableIterable", "java.lang.Iterable"),
    ("kotlin.collections.Collection", "java.util.Collection"),
    (
        "kotlin.collections.MutableCollection",
        "java.util.Collection",
    ),
    ("kotlin.collections.List", "java.util.List"),
    ("kotlin.collections.MutableList", "java.util.List"),
    ("kotlin.collections.Set", "java.util.Set"),
    ("kotlin.collections.MutableSet", "java.util.Set"),
    ("kotlin.collections.Map", "java.util.Map"),
    ("kotlin.collections.MutableMap", "java.util.Map"),
    ("kotlin.collections.Map.Entry", "java.util.Map$Entry"),
    (
        "kotlin.collections.MutableMap.MutableEntry",
        "java.util.Map$Entry",
    ),
    ("kotlin.collections.Iterator", "java.util.Iterator"),
    ("kotlin.collections.MutableIterator", "java.util.Iterator"),
    ("kotlin.collections.ListIterator", "java.util.ListIterator"),
    (
        "kotlin.collections.MutableListIterator",
        "java.util.ListIterator",
    ),
];
