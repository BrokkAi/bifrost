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
    ($($variant:ident => $label:literal: $description:literal,)+) => {
        #[repr(u8)]
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
            /// Every kind label, in declaration order: the value domain the
            /// `kind` row fields publish (issue #2515).
            pub const LABELS: &'static [&'static str] = &[$($label,)+];

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

            pub fn signature(self) -> &'static str {
                self.label()
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(NormalizedKind::$variant => $description,)+
                }
            }
        }

        impl crate::analyzer::structural::code::VocabularyCode for NormalizedKind {
            /// The declaration ordinal. `#[repr(u8)]` on the enum makes the
            /// cast the ordinal itself.
            fn code(self) -> u8 {
                self as u8
            }

            fn from_code(code: u8) -> Option<NormalizedKind> {
                ALL_KINDS.get(code as usize).copied()
            }
        }
    };
}

normalized_kinds! {
    // declaration branch
    Declaration => "declaration": "Match any declaration, including callable, class, and import declarations.",
    Callable => "callable": "Match any callable declaration, including functions, methods, constructors, and lambdas.",
    Function => "function": "Match a named free-standing function declaration.",
    Method => "method": "Match a method declared on a class or similar container.",
    Constructor => "constructor": "Match a constructor declaration.",
    Lambda => "lambda": "Match an anonymous function or lambda expression.",
    Class => "class": "Match a class-like declaration.",
    Import => "import": "Match an import declaration.",
    Parameter => "parameter": "Match a formal parameter declaration.",
    Module => "module": "Match a module or namespace declaration.",
    // expression-ish kinds
    Call => "call": "Match call expressions for functions, methods, or constructors.",
    ConcurrentSpawn => "concurrent_spawn": "Match a structured operation that starts a callable in a distinct concurrent task.",
    ResourceRelease => "resource_release": "Match a language construct that releases a resource at its own exit, such as a Java try-with-resources statement or a Python with statement.",
    Assignment => "assignment": "Match an assignment expression or statement.",
    FieldAccess => "field_access": "Match member or field access.",
    Identifier => "identifier": "Match an identifier reference.",
    Literal => "literal": "Match any literal value.",
    StringLiteral => "string_literal": "Match a string literal.",
    NumericLiteral => "numeric_literal": "Match a numeric literal.",
    BooleanLiteral => "boolean_literal": "Match a boolean literal.",
    NullLiteral => "null_literal": "Match a null-like literal.",
    CollectionLiteral => "collection_literal": "Match a collection display literal such as an array, list, set, dictionary, or tuple literal.",
    // JSX and object-property facts. These kinds describe syntax only; JSX
    // intrinsic/component identity is a resolver-backed projection, not a
    // normalized kind.
    JsxElement => "jsx_element": "Match a JSX element, including a self-closing element.",
    JsxAttribute => "jsx_attribute": "Match a named JSX attribute.",
    JsxSpreadAttribute => "jsx_spread_attribute": "Match a JSX spread attribute expression.",
    ObjectProperty => "object_property": "Match a named object-literal property pair.",
    ComputedProperty => "computed_property": "Match a computed object-property key.",
    SpreadElement => "spread_element": "Match a structured spread expression in an object, array, or argument list.",
    // statement-ish kinds
    Return => "return": "Match a return statement.",
    Throw => "throw": "Match a throw or raise statement.",
    Catch => "catch": "Match a catch or exception-handler clause.",
    If => "if": "Match a conditional statement or expression.",
    Loop => "loop": "Match a loop construct.",
    ForLoop => "for_loop": "Match a loop that iterates a collection, iterator, or range (the for-each family).",
    WhileLoop => "while_loop": "Match a condition-controlled loop (while, do-while, or until).",
    Decorator => "decorator": "Match a decorator or annotation.",
    Block => "block": "Match a statement list that forms a lexical scope of its own, such as a method body, a bare block, or a switch body.",
    // Origin appended Await before this branch appended its local-only kinds.
    Await => "await": "Match an await expression that suspends asynchronous execution.",
    // Keep additions at the end: normalized kind ordinals are persisted.
    Comment => "comment": "Match a source comment token.",
    SyntaxError => "syntax_error": "Match a source span reported by parser error recovery.",
    // Comparison is a subtype of BinaryExpression; ComparisonChain is a
    // subtype of Comparison so queries can select chains without pair roles.
    BinaryExpression => "binary_expression": "Match a binary expression with grammar-backed left, right, and operator roles.",
    Comparison => "comparison": "Match a comparison expression, including a pairwise comparison in a comparison chain.",
    ComparisonChain => "comparison_chain": "Match a chained comparison whose pairwise operands and operators are not exposed as singular roles.",
    Assertion => "assertion": "Match an assertion statement.",
    // These synthetic facts describe a decoded Python regex value selected
    // from a recognized `re` call. Appending them preserves existing ordinals.
    RegexPattern => "regex_pattern": "Match a decoded Python regular-expression pattern value.",
    RegexSequence => "regex_sequence": "Match a sequence of Python regular-expression terms.",
    RegexGroup => "regex_group": "Match a group in a Python regular-expression pattern.",
    RegexAlternation => "regex_alternation": "Match an alternation in a Python regular-expression pattern.",
    RegexCharacterClass => "regex_character_class": "Match a character class in a Python regular-expression pattern.",
    RegexCharacterRange => "regex_character_range": "Match a character range in a Python regular-expression class.",
    RegexQuantifier => "regex_quantifier": "Match a quantifier in a Python regular-expression pattern.",
    RegexAnchor => "regex_anchor": "Match an anchor or boundary escape in a Python regular-expression pattern.",
    RegexEscape => "regex_escape": "Match an escape in a Python regular-expression pattern.",
    RegexLiteral => "regex_literal": "Match a literal character in a Python regular-expression pattern.",
    RegexWildcard => "regex_wildcard": "Match a wildcard atom in a Python regular-expression pattern.",
    RegexRiskHostname => "regex_risk_hostname": "Match an unescaped-dot fact in a hostname-like regex pattern.",
    RegexRiskRange => "regex_risk_range": "Match an overly broad ASCII character-range fact.",
    RegexRiskBadTag => "regex_risk_bad_tag": "Match a bounded HTML tag-filter language-coverage risk.",
    RegexRiskExponential => "regex_risk_exponential": "Match a statically identified exponential backtracking risk.",
    RegexIncomplete => "regex_incomplete": "Match a regex analysis that could not establish a complete result.",
    RegexRiskBackspaceEscape => "regex_risk_backspace_escape": "Match a backspace escape inside a Python regex character class.",
    RegexRiskDuplicateClassCharacter => "regex_risk_duplicate_class_character": "Match a duplicate literal member in a Python regex character class.",
    RegexRiskUnmatchableCaret => "regex_risk_unmatchable_caret": "Match a caret anchor that follows a consuming term in one regex branch.",
    RegexRiskUnmatchableDollar => "regex_risk_unmatchable_dollar": "Match a dollar anchor that precedes a consuming term in one regex branch.",
    RegexRiskIncompleteSpecialGroup => "regex_risk_incomplete_special_group": "Match an unsupported or incomplete Python regex special group.",
    // Appended because kind ordinals are persisted.
    TupleLiteral => "tuple_literal": "Match a tuple display literal, preserving tuple identity and ordered elements.",
    ListLiteral => "list_literal": "Match a list display literal, preserving its ordered direct elements.",
    RegexRiskPolynomial => "regex_risk_polynomial": "Match a statically identified polynomial-time Python regex backtracking risk.",
    // Keep C and C++ statement kinds after the origin additions: normalized
    // kind ordinals are persisted.
    Switch => "switch": "Match a switch statement.",
    Case => "case": "Match a switch case or default label.",
    Label => "label": "Match a labeled statement target.",
    Goto => "goto": "Match a goto statement.",
    Break => "break": "Match a break statement.",
    Continue => "continue": "Match a continue statement.",
    CharacterLiteral => "character_literal": "Match a character literal.",
    Yield => "yield": "Match a yield expression or statement that controls generator execution.",
    Cast => "cast": "Match a cast expression.",
    InstanceOf => "instance_of": "Match a type-test expression.",
    Subscript => "subscript": "Match a subscript expression.",
    ArrayCreation => "array_creation": "Match an array creation expression.",
    UnaryExpression => "unary_expression": "Match a unary expression.",
    Lock => "lock": "Match a synchronized or lock statement.",
}

impl NormalizedKind {
    /// The immediate supertype in the normalized hierarchy, or `None` for
    /// kinds that hang directly off the implicit root.
    pub fn parent(self) -> Option<NormalizedKind> {
        use NormalizedKind::*;
        match self {
            Callable | Class | Import | Parameter | Module => Some(Declaration),
            Function | Method | Constructor | Lambda => Some(Callable),
            StringLiteral | NumericLiteral | BooleanLiteral | NullLiteral | CharacterLiteral
            | CollectionLiteral => Some(Literal),
            TupleLiteral | ListLiteral => Some(CollectionLiteral),
            ForLoop | WhileLoop => Some(Loop),
            ConcurrentSpawn => Some(Call),
            Comparison => Some(BinaryExpression),
            ComparisonChain => Some(Comparison),
            RegexSequence | RegexGroup | RegexAlternation | RegexCharacterClass
            | RegexCharacterRange | RegexQuantifier | RegexAnchor | RegexEscape | RegexLiteral
            | RegexWildcard => Some(RegexPattern),
            Declaration
            | Call
            | Assignment
            | FieldAccess
            | Identifier
            | Literal
            | ResourceRelease
            | Return
            | Throw
            | Catch
            | If
            | Loop
            | Decorator
            | Block
            | JsxElement
            | JsxAttribute
            | JsxSpreadAttribute
            | ObjectProperty
            | ComputedProperty
            | SpreadElement
            | Comment
            | SyntaxError
            | BinaryExpression
            | Assertion
            | RegexPattern
            | RegexRiskHostname
            | RegexRiskRange
            | RegexRiskBadTag
            | RegexRiskExponential
            | RegexIncomplete
            | RegexRiskBackspaceEscape
            | RegexRiskDuplicateClassCharacter
            | RegexRiskUnmatchableCaret
            | RegexRiskUnmatchableDollar
            | RegexRiskIncompleteSpecialGroup
            | RegexRiskPolynomial
            | Await
            | Switch
            | Case
            | Label
            | Goto
            | Break
            | Continue => None,
            Yield | Cast | InstanceOf | Subscript | ArrayCreation | UnaryExpression | Lock => None,
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

    /// Whether a fact of this kind is a statement-level construct, which
    /// occurs only in executable code: a conditional, a loop, a return, a
    /// throw, a handler or a resource release.
    ///
    /// Syntax recovery that removes such a node can only hide it inside a
    /// callable, so a recovered region outside every callable leaves a
    /// selection of these kinds complete (#3777). Every other kind can also
    /// occur in an initializer, an annotation, a default value or a
    /// declaration list, so any recovered region in the file can hide it.
    /// The subtypes of `loop` are statement-level with it.
    pub fn is_statement_level(self) -> bool {
        use NormalizedKind::*;
        match self {
            If | Loop | ForLoop | WhileLoop | Return | Throw | Catch | ResourceRelease
            | Assertion | Switch | Case | Label | Goto | Break | Continue => true,
            Declaration | Callable | Function | Method | Constructor | Lambda | Class | Import
            | Parameter | Module | Call | ConcurrentSpawn | Assignment | FieldAccess
            | Identifier | Literal | StringLiteral | NumericLiteral | BooleanLiteral
            | NullLiteral | CharacterLiteral | CollectionLiteral | TupleLiteral | ListLiteral
            | JsxElement | JsxAttribute | JsxSpreadAttribute | ObjectProperty
            | ComputedProperty | SpreadElement | Decorator | Block | RegexPattern
            | RegexSequence | RegexGroup | RegexAlternation | RegexCharacterClass
            | RegexCharacterRange | RegexQuantifier | RegexAnchor | RegexEscape | RegexLiteral
            | RegexWildcard | RegexRiskHostname | RegexRiskRange | RegexRiskBadTag
            | RegexRiskExponential | RegexIncomplete => false,
            RegexRiskBackspaceEscape
            | RegexRiskDuplicateClassCharacter
            | RegexRiskUnmatchableCaret
            | RegexRiskUnmatchableDollar
            | RegexRiskIncompleteSpecialGroup
            | RegexRiskPolynomial
            | Comment
            | SyntaxError
            | BinaryExpression
            | Comparison
            | ComparisonChain => false,
            Lock => true,
            Await | Yield | Cast | InstanceOf | Subscript | ArrayCreation | UnaryExpression => {
                false
            }
        }
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
    ($($variant:ident => $label:literal: $shape:ident, $description:literal,)+) => {
        #[repr(u8)]
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

            pub fn value_shape(self) -> RoleValueShape {
                match self {
                    $(Role::$variant => RoleValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self.value_shape() {
                    RoleValueShape::Pattern => "pattern",
                    RoleValueShape::PatternList => "[pattern ...]",
                    RoleValueShape::PatternMap => "[(name pattern) ...]",
                }
            }

            pub fn rql_signature(self) -> &'static str {
                match self.value_shape() {
                    RoleValueShape::Pattern => r#"pattern | "name""#,
                    RoleValueShape::PatternList => "[pattern ...]",
                    RoleValueShape::PatternMap => "[(name pattern) ...]",
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Role::$variant => $description,)+
                }
            }
        }

        impl crate::analyzer::structural::code::VocabularyCode for Role {
            /// The declaration ordinal. `#[repr(u8)]` on the enum makes the
            /// cast the ordinal itself.
            fn code(self) -> u8 {
                self as u8
            }

            fn from_code(code: u8) -> Option<Role> {
                ALL_ROLES.get(code as usize).copied()
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleValueShape {
    Pattern,
    PatternList,
    PatternMap,
}

roles! {
    Callee => "callee": Pattern, "Constrain the call target name or expression.",
    Receiver => "receiver": Pattern, "Constrain the receiver of a method call.",
    Arg => "args": PatternList, "Constrain positional arguments in order.",
    Kwarg => "kwargs": PatternMap, "Constrain named arguments by argument name.",
    Left => "left": Pattern, "Constrain the left-hand side of an assignment or binary expression.",
    Right => "right": Pattern, "Constrain the right-hand side of an assignment or binary expression.",
    Operator => "operator": Pattern, "Constrain the grammar-backed assignment or binary operator token.",
    Module => "module": Pattern, "Constrain the module referenced by an import.",
    Decorator => "decorators": PatternList, "Constrain decorators or annotations in order.",
    Object => "object": Pattern, "Constrain the object of a field access.",
    Field => "field": Pattern, "Constrain the field portion of a field access.",
    Iterable => "iterable": Pattern, "Constrain the expression a for-each loop iterates.",
    Element => "elements": PatternList, "Constrain the elements of a collection literal in order.",
    Tag => "tag": Pattern, "Constrain the tag expression of a JSX element.",
    Attributes => "attributes": PatternList, "Constrain the attributes of a JSX element in source order.",
    Children => "children": PatternList, "Constrain the source children of a JSX element in source order.",
    Value => "value": Pattern, "Constrain the exact value expression of an attribute, property, or spread.",
    Key => "key": Pattern, "Constrain the static key of an object property.",
    TypeArguments => "type-arguments": PatternList, "Constrain the written generic type arguments of a call callee.",
    Part => "parts": PatternList, "Constrain implicitly concatenated literals or interpolated expressions in source order.",
    // Appended to preserve persisted role ordinals.
    Test => "test": Pattern, "Constrain the expression tested by an assertion or conditional.",
    Type => "type": Pattern, "Constrain the type of a construct.",
    Operand => "operand": Pattern, "Constrain the operand of a construct.",
    Consequence => "consequence": Pattern, "Constrain the consequence of a construct.",
    Alternative => "alternative": Pattern, "Constrain the alternative of a construct.",
    Body => "body": Pattern, "Constrain the body of a construct.",
    Label => "label": Pattern, "Constrain the label of a construct.",
    Binding => "binding": Pattern, "Constrain the binding of a construct.",
    Indices => "indices": PatternList, "Constrain the indices in source order.",
    Dimensions => "dimensions": PatternList, "Constrain the dimensions in source order.",
}

pub const SINGLE_TARGET_ROLES: &[Role] = &[
    Role::Callee,
    Role::Receiver,
    Role::Left,
    Role::Right,
    Role::Operator,
    Role::Module,
    Role::Object,
    Role::Field,
    Role::Iterable,
    Role::Tag,
    Role::Value,
    Role::Key,
    Role::Test,
    Role::Type,
    Role::Operand,
    Role::Consequence,
    Role::Alternative,
    Role::Body,
    Role::Label,
    Role::Binding,
];

pub const LIST_TARGET_ROLES: &[Role] = &[
    Role::Arg,
    Role::Decorator,
    Role::Element,
    Role::Attributes,
    Role::Children,
    Role::TypeArguments,
    Role::Part,
    Role::Indices,
    Role::Dimensions,
];

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
            Role::Callee | Role::Receiver | Role::Arg | Role::Kwarg => {
                matches!(kind, Call | ConcurrentSpawn)
            }
            Role::Left | Role::Right | Role::Operator => matches!(
                kind,
                Assignment | BinaryExpression | Comparison | ComparisonChain | UnaryExpression
            ),
            Role::Module => matches!(kind, Import | Declaration),
            Role::Decorator => matches!(
                kind,
                Function
                    | Method
                    | Constructor
                    | Lambda
                    | Callable
                    | Class
                    | Parameter
                    | Declaration
            ),
            Role::Object => matches!(kind, FieldAccess | Subscript),
            Role::Field => kind == FieldAccess,
            // `iterable` is deliberately not valid for the broader `loop`
            // kind: only the for-each family has an iterated expression, and
            // constraining it on `loop`/`while_loop` would silently narrow a
            // query to for-loops while reading as if it covered every loop.
            Role::Iterable => kind == ForLoop,
            Role::Element => matches!(kind, CollectionLiteral | TupleLiteral | ListLiteral),
            Role::Part => kind == StringLiteral,
            Role::Tag | Role::Attributes | Role::Children => kind == JsxElement,
            // Type arguments are written on a call callee, including a
            // turbofish on a scoped type path.
            Role::TypeArguments => matches!(kind, Call | ConcurrentSpawn),
            Role::Value => matches!(
                kind,
                JsxAttribute
                    | JsxSpreadAttribute
                    | ObjectProperty
                    | ComputedProperty
                    | SpreadElement
                    | Return
                    | Throw
                    | Cast
                    | ArrayCreation
                    | Lock
            ),
            Role::Key => kind == ObjectProperty,
            Role::Test => matches!(kind, Assertion | If | Switch | Case),
            Role::Type => matches!(kind, Cast | InstanceOf | ArrayCreation),
            Role::Operand => matches!(kind, InstanceOf | UnaryExpression),
            Role::Consequence | Role::Alternative => kind == If,
            Role::Body => matches!(kind, Lock | Switch | Case | Label),
            Role::Label => matches!(kind, Label | Break | Continue),
            Role::Binding => kind == InstanceOf,
            Role::Indices => kind == Subscript,
            Role::Dimensions => kind == ArrayCreation,
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
        assert!(Comparison.satisfies(BinaryExpression));
        assert!(ComparisonChain.satisfies(Comparison));
        assert!(ComparisonChain.satisfies(BinaryExpression));
        assert!(Parameter.satisfies(Declaration));
        assert!(Module.satisfies(Declaration));
        assert!(!Module.satisfies(Class));
        assert!(!Class.satisfies(Module));

        assert!(ForLoop.satisfies(Loop));
        assert!(WhileLoop.satisfies(Loop));
        assert!(ForLoop.satisfies(ForLoop));

        assert!(!Literal.satisfies(StringLiteral));
        assert!(!Callable.satisfies(Function));
        assert!(!Call.satisfies(Declaration));
        assert!(ConcurrentSpawn.satisfies(Call));
        assert!(ConcurrentSpawn.satisfies(ConcurrentSpawn));
        assert!(!Identifier.satisfies(Literal));
        assert!(!Loop.satisfies(ForLoop));
        assert!(!ForLoop.satisfies(WhileLoop));
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
    fn assertions_are_statement_level_comparisons_are_not() {
        assert!(NormalizedKind::Assertion.is_statement_level());
        assert!(!NormalizedKind::Comparison.is_statement_level());
    }

    #[test]
    fn role_validity_is_kind_scoped() {
        use NormalizedKind::*;
        assert!(Role::Callee.valid_for(Call));
        assert!(!Role::Callee.valid_for(Assignment));
        assert!(Role::Left.valid_for(Assignment));
        assert!(Role::Left.valid_for(BinaryExpression));
        assert!(Role::Right.valid_for(Comparison));
        assert!(Role::Operator.valid_for(ComparisonChain));
        assert!(Role::Test.valid_for(Assertion));
        assert!(Role::Test.valid_for(If));
        assert!(Role::Value.valid_for(Return));
        assert!(!Role::Left.valid_for(Call));
        assert!(Role::Decorator.valid_for(Function));
        assert!(Role::Decorator.valid_for(Class));
        assert!(Role::Decorator.valid_for(Parameter));
        assert!(Role::Decorator.valid_for(Declaration));
        assert!(!Role::Decorator.valid_for(Call));
        assert!(Role::TypeArguments.valid_for(Call));
        assert!(!Role::TypeArguments.valid_for(Assignment));
        assert!(Role::Module.valid_for(Import));
        assert!(Role::Object.valid_for(FieldAccess));
        assert!(!Role::Object.valid_for(Identifier));
        assert!(Role::Tag.valid_for(JsxElement));
        assert!(Role::Attributes.valid_for(JsxElement));
        assert!(Role::Children.valid_for(JsxElement));
        assert!(Role::Value.valid_for(JsxAttribute));
        assert!(Role::Value.valid_for(ObjectProperty));
        assert!(Role::Value.valid_for(ComputedProperty));
        assert!(Role::Key.valid_for(ObjectProperty));
        assert!(!Role::Tag.valid_for(Call));
        assert!(!Role::Key.valid_for(ComputedProperty));
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
