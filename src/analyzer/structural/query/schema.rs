//! Declarative metadata for the public CodeQuery/RQL vocabulary.
//!
//! The registries in this module are deliberately executable metadata: parser
//! and validator dispatch use the generated enums, while the REPL and editor
//! use the same signatures and descriptions. Adding an entry without help or
//! a value shape is therefore a macro error, and every handler must match the
//! generated enum exhaustively.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueShape {
    Pattern,
    PatternList,
    PatternMap,
    String,
    StringList,
    StringPredicate,
    KindList,
    LanguageList,
    PositiveInteger,
    ResultDetail,
    SchemaVersion,
}

impl ValueShape {
    pub fn description(self) -> &'static str {
        match self {
            Self::Pattern => "a pattern",
            Self::PatternList => "a list/vector of patterns",
            Self::PatternMap => "a map of names to patterns",
            Self::String => "a string",
            Self::StringList => "one or more strings",
            Self::StringPredicate => "an exact string or regex predicate",
            Self::KindList => "a normalized kind or list of kinds",
            Self::LanguageList => "one or more language labels",
            Self::PositiveInteger => "a positive integer",
            Self::ResultDetail => "compact or full",
            Self::SchemaVersion => "schema version 1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RqlFormClass {
    Wrapper,
    Predicate,
}

macro_rules! rql_forms {
    ($($variant:ident {
        labels: [$primary:literal $(, $alias:literal)* $(,)?],
        class: $class:ident,
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RqlForm {
            $($variant,)+
        }

        pub const ALL_RQL_FORMS: &[RqlForm] = &[
            $(RqlForm::$variant,)+
        ];

        impl RqlForm {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($primary $(| $alias)* => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $primary,)+
                }
            }

            pub fn labels(self) -> &'static [&'static str] {
                match self {
                    $(Self::$variant => &[$primary $(, $alias)*],)+
                }
            }

            pub fn class(self) -> RqlFormClass {
                match self {
                    $(Self::$variant => RqlFormClass::$class,)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }
        }
    };
}

rql_forms! {
    Where {
        labels: ["where"],
        class: Wrapper,
        shape: StringList,
        signature: "(where \"glob\" ... query)",
        description: "Restrict the query to workspace-relative path globs.",
    }
    Language {
        labels: ["language", "languages"],
        class: Wrapper,
        shape: LanguageList,
        signature: "(language label ... query)",
        description: "Restrict the query to one or more analyzer languages.",
    }
    Limit {
        labels: ["limit"],
        class: Wrapper,
        shape: PositiveInteger,
        signature: "(limit count query)",
        description: "Set the maximum number of matches returned by query_code.",
    }
    ResultDetail {
        labels: ["result-detail", "result_detail"],
        class: Wrapper,
        shape: ResultDetail,
        signature: "(result-detail compact|full query)",
        description: "Choose compact output or full capture and source details.",
    }
    Inside {
        labels: ["inside"],
        class: Wrapper,
        shape: Pattern,
        signature: "(inside container-pattern query)",
        description: "Require the root match to be lexically inside a matching container.",
    }
    NotInside {
        labels: ["not-inside"],
        class: Wrapper,
        shape: Pattern,
        signature: "(not-inside container-pattern query)",
        description: "Exclude root matches lexically inside a matching container.",
    }
    Name {
        labels: ["name"],
        class: Predicate,
        shape: String,
        signature: "(name \"exactName\")",
        description: "Match a node's normalized name exactly.",
    }
    NameRegex {
        labels: ["name/regex"],
        class: Predicate,
        shape: String,
        signature: "(name/regex \"pattern\")",
        description: "Match a node's normalized name with a regular expression.",
    }
    TextRegex {
        labels: ["text/regex"],
        class: Predicate,
        shape: String,
        signature: "(text/regex \"pattern\")",
        description: "Match a node's source text with a regular expression.",
    }
    Capture {
        labels: ["capture"],
        class: Predicate,
        shape: String,
        signature: "(capture \"label\")",
        description: "Capture the matching node under a result label.",
    }
    Has {
        labels: ["has"],
        class: Predicate,
        shape: Pattern,
        signature: "(has descendant-pattern)",
        description: "Require a matching descendant somewhere below this pattern.",
    }
    NotHas {
        labels: ["not-has", "not_has"],
        class: Predicate,
        shape: Pattern,
        signature: "(not-has descendant-pattern)",
        description: "Exclude nodes that contain a matching descendant.",
    }
    NotKind {
        labels: ["not-kind", "not_kind"],
        class: Predicate,
        shape: KindList,
        signature: "(not-kind kind|[kinds...])",
        description: "Exclude one or more normalized kinds using subtype-aware matching.",
    }
}

macro_rules! rql_properties {
    ($($variant:ident {
        labels: [$primary:literal $(, $alias:literal)* $(,)?],
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:literal,
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RqlProperty {
            $($variant,)+
        }

        pub const ALL_RQL_PROPERTIES: &[RqlProperty] = &[
            $(RqlProperty::$variant,)+
        ];

        impl RqlProperty {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($primary $(| $alias)* => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $primary,)+
                }
            }

            pub fn labels(self) -> &'static [&'static str] {
                match self {
                    $(Self::$variant => &[$primary $(, $alias)*],)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }
        }
    };
}

rql_properties! {
    Name {
        labels: ["name"],
        shape: String,
        signature: ":name \"exactName\"",
        description: "Match the normalized name exactly.",
    }
    NameRegex {
        labels: ["name/regex"],
        shape: String,
        signature: ":name/regex \"pattern\"",
        description: "Match the normalized name with a regular expression.",
    }
    TextRegex {
        labels: ["text/regex"],
        shape: String,
        signature: ":text/regex \"pattern\"",
        description: "Match source text with a regular expression.",
    }
    Capture {
        labels: ["capture"],
        shape: String,
        signature: ":capture \"label\"",
        description: "Capture the matching node under a result label.",
    }
    NotKind {
        labels: ["not-kind", "not_kind"],
        shape: KindList,
        signature: ":not-kind kind|[kinds...]",
        description: "Exclude one or more normalized kinds.",
    }
    Has {
        labels: ["has"],
        shape: Pattern,
        signature: ":has pattern",
        description: "Require a matching descendant.",
    }
    NotHas {
        labels: ["not-has", "not_has"],
        shape: Pattern,
        signature: ":not-has pattern",
        description: "Exclude nodes containing a matching descendant.",
    }
}

macro_rules! json_fields {
    ($name:ident, $all:ident, $($variant:ident {
        label: $label:literal,
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant,)+
        }

        pub const $all: &[$name] = &[
            $($name::$variant,)+
        ];

        impl $name {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($label => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }
        }
    };
}

json_fields! {
    QueryField,
    ALL_QUERY_FIELDS,
    Where { label: "where", shape: StringList, signature: "\"where\": [\"glob\", ...]", description: "Restrict the query to workspace-relative path globs." }
    Languages { label: "languages", shape: LanguageList, signature: "\"languages\": [\"rust\", ...]", description: "Restrict the query to analyzer languages." }
    Match { label: "match", shape: Pattern, signature: "\"match\": { pattern }", description: "Define the required root structural pattern." }
    Inside { label: "inside", shape: Pattern, signature: "\"inside\": { pattern }", description: "Require the root match to be inside a matching container." }
    NotInside { label: "not_inside", shape: Pattern, signature: "\"not_inside\": { pattern }", description: "Exclude root matches inside a matching container." }
    Limit { label: "limit", shape: PositiveInteger, signature: "\"limit\": positive integer", description: "Set the maximum number of matches returned." }
    ResultDetail { label: "result_detail", shape: ResultDetail, signature: "\"result_detail\": \"compact\" | \"full\"", description: "Choose compact output or full capture and source details." }
    SchemaVersion { label: "schema_version", shape: SchemaVersion, signature: "\"schema_version\": 1", description: "Select the CodeQuery schema version." }
}

json_fields! {
    StringPredicateField,
    ALL_STRING_PREDICATE_FIELDS,
    Regex { label: "regex", shape: String, signature: "\"regex\": \"pattern\"", description: "Match the value with a regular expression." }
}

json_fields! {
    PatternField,
    ALL_PATTERN_FIELDS,
    Kind { label: "kind", shape: KindList, signature: "\"kind\": \"kind\" | [\"kinds\", ...]", description: "Match one or more normalized node kinds." }
    NotKind { label: "not_kind", shape: KindList, signature: "\"not_kind\": \"kind\" | [\"kinds\", ...]", description: "Exclude one or more normalized node kinds." }
    Name { label: "name", shape: StringPredicate, signature: "\"name\": \"exact\" | { \"regex\": \"pattern\" }", description: "Match the node's normalized name." }
    Text { label: "text", shape: StringPredicate, signature: "\"text\": \"exact\" | { \"regex\": \"pattern\" }", description: "Match the node's source text." }
    Capture { label: "capture", shape: String, signature: "\"capture\": \"label\"", description: "Capture the matching node under a result label." }
    Has { label: "has", shape: Pattern, signature: "\"has\": { pattern }", description: "Require a matching descendant." }
    NotHas { label: "not_has", shape: Pattern, signature: "\"not_has\": { pattern }", description: "Exclude nodes containing a matching descendant." }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn schema_metadata_has_unique_spellings_and_help() {
        let mut forms = HashSet::new();
        for form in ALL_RQL_FORMS {
            assert!(!form.signature().is_empty());
            assert!(!form.description().is_empty());
            for label in form.labels() {
                assert!(forms.insert(*label), "duplicate form label {label}");
                assert_eq!(RqlForm::from_label(label), Some(*form));
            }
        }

        let mut properties = HashSet::new();
        for property in ALL_RQL_PROPERTIES {
            assert!(!property.signature().is_empty());
            assert!(!property.description().is_empty());
            for label in property.labels() {
                assert!(
                    properties.insert(*label),
                    "duplicate property label {label}"
                );
                assert_eq!(RqlProperty::from_label(label), Some(*property));
            }
        }

        for field in ALL_QUERY_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(QueryField::from_label(field.label()), Some(*field));
        }
        for field in ALL_PATTERN_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(PatternField::from_label(field.label()), Some(*field));
        }
        for field in ALL_STRING_PREDICATE_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(
                StringPredicateField::from_label(field.label()),
                Some(*field)
            );
        }
    }
}
