//! The normalized, language-neutral node vocabulary for structural search
//! (issue #328). Each language adapter maps its tree-sitter node types onto
//! these kinds; queries are written against this vocabulary and never against
//! grammar-specific node names.
//!
//! Kinds form an explicit subtype hierarchy (see [`NormalizedKind::parent`]).
//! Kind matching is subtype-aware by default: a query for `literal` matches a
//! `string_literal` fact. The hierarchy is deliberately shallow — new
//! subtypes are added only when they unlock useful queries, and orthogonal
//! properties (anonymity, closure-ness, class-like form) belong in predicate
//! fields, not the kind chain.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! normalized_kinds {
    ($($variant:ident => $label:literal,)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum NormalizedKind {
            $($variant,)+
        }

        /// Every kind, for iteration in validation and docs/tests.
        pub const ALL_KINDS: &[NormalizedKind] = &[
            $(NormalizedKind::$variant,)+
        ];

        impl NormalizedKind {
            /// The snake_case label used in query JSON and rendered output. Kept in
            /// lock-step with the serde representation (asserted by test).
            pub fn label(self) -> &'static str {
                match self {
                    $(NormalizedKind::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<NormalizedKind> {
                ALL_KINDS.iter().copied().find(|kind| kind.label() == label)
            }
        }
    };
}

normalized_kinds! {
    // declaration branch
    Declaration => "declaration",
    Callable => "callable",
    Function => "function",
    Method => "method",
    Constructor => "constructor",
    Lambda => "lambda",
    Class => "class",
    Import => "import",
    // expression-ish kinds (kept flat; see ExecPlan decision log)
    Call => "call",
    Assignment => "assignment",
    FieldAccess => "field_access",
    Identifier => "identifier",
    Literal => "literal",
    StringLiteral => "string_literal",
    NumericLiteral => "numeric_literal",
    BooleanLiteral => "boolean_literal",
    NullLiteral => "null_literal",
    // statement-ish kinds
    Return => "return",
    Throw => "throw",
    Catch => "catch",
    If => "if",
    Loop => "loop",
    Decorator => "decorator",
}

impl NormalizedKind {
    /// The immediate supertype in the normalized hierarchy, or `None` for
    /// kinds that hang directly off the implicit root.
    pub fn parent(self) -> Option<NormalizedKind> {
        use NormalizedKind::*;
        match self {
            Callable | Class | Import => Some(Declaration),
            Function | Method | Constructor | Lambda => Some(Callable),
            StringLiteral | NumericLiteral | BooleanLiteral | NullLiteral => Some(Literal),
            Declaration | Call | Assignment | FieldAccess | Identifier | Literal | Return
            | Throw | Catch | If | Loop | Decorator => None,
        }
    }

    /// Subtype-aware kind matching: `self` satisfies `query_kind` when it is
    /// `query_kind` or a (transitive) subtype of it. The parent chain is at
    /// most two links deep today, but this walks generically.
    pub fn satisfies(self, query_kind: NormalizedKind) -> bool {
        let mut current = Some(self);
        while let Some(kind) = current {
            if kind == query_kind {
                return true;
            }
            current = kind.parent();
        }
        false
    }
}

impl fmt::Display for NormalizedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A named edge from a matched node to a sub-node, extracted from tree-sitter
/// AST fields by each language's structural spec. Which roles a pattern may
/// constrain depends on its kind — see [`Role::valid_for`].
macro_rules! roles {
    ($($variant:ident => $label:literal,)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Role {
            $($variant,)+
        }

        pub const ALL_ROLES: &[Role] = &[
            $(Role::$variant,)+
        ];

        impl Role {
            /// The JSON field name this role appears under in a pattern object.
            /// `Arg`/`Kwarg` use the plural spellings from the issue's query shape.
            pub fn label(self) -> &'static str {
                match self {
                    $(Role::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<Role> {
                ALL_ROLES.iter().copied().find(|role| role.label() == label)
            }
        }
    };
}

roles! {
    Callee => "callee",
    Receiver => "receiver",
    Arg => "args",
    Kwarg => "kwargs",
    Left => "left",
    Right => "right",
    Module => "module",
    Decorator => "decorators",
    Object => "object",
    Field => "field",
}

pub const SINGLE_TARGET_ROLES: &[Role] = &[
    Role::Callee,
    Role::Receiver,
    Role::Left,
    Role::Right,
    Role::Module,
    Role::Object,
    Role::Field,
];

pub const LIST_TARGET_ROLES: &[Role] = &[Role::Arg, Role::Decorator];

pub const MAP_TARGET_ROLES: &[Role] = &[Role::Kwarg];

impl Role {
    pub fn single_target_roles() -> &'static [Role] {
        SINGLE_TARGET_ROLES
    }

    pub fn list_target_roles() -> &'static [Role] {
        LIST_TARGET_ROLES
    }

    pub fn map_target_roles() -> &'static [Role] {
        MAP_TARGET_ROLES
    }

    /// Whether a pattern of kind `kind` may constrain this role. Validation
    /// is deliberately based on the *query* kind: constraining `callee` on a
    /// pattern whose kind is `assignment` is a query error, while a broad
    /// kind such as `declaration` accepts the union of its subtypes' roles.
    pub fn valid_for(self, kind: NormalizedKind) -> bool {
        use NormalizedKind::*;
        match self {
            Role::Callee | Role::Receiver | Role::Arg | Role::Kwarg => kind == Call,
            Role::Left | Role::Right => kind == Assignment,
            Role::Module => matches!(kind, Import | Declaration),
            Role::Decorator => matches!(
                kind,
                Function | Method | Constructor | Lambda | Callable | Class | Declaration
            ),
            Role::Object | Role::Field => kind == FieldAccess,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_labels_round_trip_and_match_label() {
        for &kind in ALL_KINDS {
            let json = serde_json::to_value(kind).expect("serialize kind");
            assert_eq!(
                json,
                serde_json::Value::String(kind.label().to_string()),
                "serde label diverges from label() for {kind:?}"
            );
            let back: NormalizedKind = serde_json::from_value(json).expect("deserialize kind");
            assert_eq!(back, kind);
            assert_eq!(NormalizedKind::from_label(kind.label()), Some(kind));
        }
    }

    #[test]
    fn subtype_matching_walks_the_hierarchy() {
        use NormalizedKind::*;
        assert!(StringLiteral.satisfies(Literal));
        assert!(StringLiteral.satisfies(StringLiteral));
        assert!(Function.satisfies(Callable));
        assert!(Function.satisfies(Declaration));
        assert!(Lambda.satisfies(Callable));
        assert!(Class.satisfies(Declaration));
        assert!(Import.satisfies(Declaration));

        assert!(!Literal.satisfies(StringLiteral));
        assert!(!Callable.satisfies(Function));
        assert!(!Call.satisfies(Declaration));
        assert!(!Identifier.satisfies(Literal));
    }

    #[test]
    fn parent_chains_terminate() {
        for &kind in ALL_KINDS {
            let mut depth = 0;
            let mut current = kind.parent();
            while let Some(parent) = current {
                depth += 1;
                assert!(depth <= 8, "cycle or runaway parent chain at {kind:?}");
                current = parent.parent();
            }
        }
    }

    #[test]
    fn role_validity_is_kind_scoped() {
        use NormalizedKind::*;
        assert!(Role::Callee.valid_for(Call));
        assert!(!Role::Callee.valid_for(Assignment));
        assert!(Role::Left.valid_for(Assignment));
        assert!(!Role::Left.valid_for(Call));
        assert!(Role::Decorator.valid_for(Function));
        assert!(Role::Decorator.valid_for(Class));
        assert!(Role::Decorator.valid_for(Declaration));
        assert!(!Role::Decorator.valid_for(Call));
        assert!(Role::Module.valid_for(Import));
        assert!(Role::Object.valid_for(FieldAccess));
        assert!(!Role::Object.valid_for(Identifier));
    }

    #[test]
    fn role_metadata_covers_unique_labels() {
        let mut labels = std::collections::HashSet::new();
        for role in ALL_ROLES {
            assert!(labels.insert(role.label()), "duplicate label for {role:?}");
            assert_eq!(Role::from_label(role.label()), Some(*role));
        }
        assert_eq!(
            Role::single_target_roles().len()
                + Role::list_target_roles().len()
                + Role::map_target_roles().len(),
            ALL_ROLES.len()
        );
    }
}
