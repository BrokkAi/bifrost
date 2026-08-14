//! Where a BARE PHP call can bind to a declaration this file publishes.
//!
//! The reference census grades a forward-unresolvable occurrence by asking
//! whether the file declares the name, and a bare CALL of a name the file
//! declares somewhere is its highest-confidence gap signal (#1783). "Somewhere"
//! is wrong for PHP, because PHP has no implicit-receiver call: `foo()` inside a
//! class NEVER means `$this->foo()`. It binds to a function in the current
//! namespace, to a `use function` alias, or -- failing both -- to the global
//! function (#1866). A same-file METHOD or PROPERTY of the same name is
//! therefore not evidence that the bare call could have bound to it (#1867).
//!
//! The model is deliberately about DECLARATIONS the analyzer publishes, in the
//! sense `declarations.rs` publishes them: a `function_definition` reached
//! without crossing a class, interface, trait or enum body, or an anonymous or
//! arrow function. A method is a `method_declaration` and never appears here; a
//! property, a promoted constructor parameter, a class constant, an enum case
//! and a class itself are all unreachable from a bare call and are likewise
//! absent.
//!
//! Reach is over-approximated on purpose, exactly as Scala's index is. A
//! published free function is treated as reachable from every bare call in the
//! file. That is exact for the single-namespace file, which is what real PHP
//! writes: the call reaches the function through the current namespace, or --
//! for a file whose functions sit in the global namespace -- through the global
//! fallback. It over-reaches only across the sibling blocks of a multi-namespace
//! `namespace A { ... } namespace B { ... }` file. Missing evidence costs an
//! actionable tier-1 finding; extra evidence only leaves a site in the triage
//! queue.

use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

use crate::graph::resolver::node_text;

/// Declaration kinds whose bodies publish members rather than free functions. A
/// `function_definition` inside one of these is not a CodeUnit, so it was never
/// the same-file declaration the census matched.
const MEMBER_CONTAINER_KINDS: [&str; 6] = [
    "class_declaration",
    "interface_declaration",
    "trait_declaration",
    "enum_declaration",
    "anonymous_function",
    "arrow_function",
];

/// The free-function names a bare PHP call in this file can bind to.
#[derive(Debug, Default)]
pub struct PhpBareNameFunctionScopes {
    free_functions: HashSet<String>,
}

impl PhpBareNameFunctionScopes {
    pub fn build(root: Node<'_>, source: &str) -> Self {
        let mut free_functions = HashSet::default();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if MEMBER_CONTAINER_KINDS.contains(&node.kind()) {
                continue;
            }
            if node.kind() == "function_definition"
                && let Some(name) = node
                    .child_by_field_name("name")
                    .map(|name| node_text(name, source).trim())
                && !name.is_empty()
            {
                free_functions.insert(name.to_string());
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        Self { free_functions }
    }

    /// Whether a bare call of `name` can bind to a declaration this file
    /// publishes.
    ///
    /// `byte` is not consulted: a PHP function declaration is visible in its
    /// whole namespace regardless of where in the file it is written, including
    /// before its own declaration and from inside a `function_exists` guard, so
    /// there is no position at which a published free function of the file is
    /// out of reach. The parameter stays because the census asks every language
    /// the same question; the languages whose answer depends on position use it.
    pub fn is_bound_at(&self, name: &str, _byte: usize) -> bool {
        self.free_functions.contains(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn build(source: &str) -> PhpBareNameFunctionScopes {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("PHP grammar");
        let tree = parser.parse(source, None).expect("PHP tree");
        PhpBareNameFunctionScopes::build(tree.root_node(), source)
    }

    fn byte_of(source: &str, needle: &str) -> usize {
        source.find(needle).expect("witness site")
    }

    /// The positive control: a same-file free function in the file's namespace
    /// really is reachable from a bare call, so the grading fix must keep
    /// answering `true` here.
    #[test]
    fn a_same_file_free_function_binds_a_bare_call() {
        let source = concat!(
            "<?php\n",
            "namespace Demo\\Mixed;\n",
            "function local_helper(string $name): string { return $name; }\n",
            "class Mixed {\n",
            "    public function go(): string { return local_helper('a'); }\n",
            "}\n",
        );
        assert!(
            build(source).is_bound_at("local_helper", byte_of(source, "local_helper('a')")),
            "a published free function is reachable from a bare call in the same file"
        );
    }

    /// The monolog `Utils::substr` and Carbon `CarbonInterval::round` shape: a
    /// method of the enclosing class shadows nothing, because PHP has no
    /// implicit-receiver call.
    #[test]
    fn a_method_never_binds_a_bare_call() {
        let source = concat!(
            "<?php\n",
            "namespace Demo\\Support;\n",
            "class Utils {\n",
            "    public static function substr(string $s): string { return substr($s, 0, 2); }\n",
            "    public function other(string $s): string { return substr($s, 0, 2); }\n",
            "}\n",
        );
        let scopes = build(source);
        assert!(
            !scopes.is_bound_at("substr", byte_of(source, "substr($s, 0, 2)")),
            "a bare call cannot reach a method of the enclosing class"
        );
    }

    /// The tenancy `protected Tenancy $tenancy` shape: the census credited a
    /// PROPERTY, which is not even callable.
    #[test]
    fn a_property_or_promoted_parameter_never_binds_a_bare_call() {
        let source = concat!(
            "<?php\n",
            "namespace Demo\\Support;\n",
            "class Handler {\n",
            "    private $time = 0;\n",
            "    public function __construct(private int $max = 1) {}\n",
            "    public function go(): int { return time() + max(1, $this->max); }\n",
            "}\n",
        );
        let scopes = build(source);
        assert!(
            !scopes.is_bound_at("time", byte_of(source, "time()")),
            "a property is not callable, so it is not bare-call evidence"
        );
        assert!(
            !scopes.is_bound_at("max", byte_of(source, "max(1,")),
            "a promoted constructor parameter is not bare-call evidence"
        );
    }

    /// A trait member is a member: `use Roundable` does not put `floor` in the
    /// term scope a bare call binds in.
    #[test]
    fn a_trait_method_never_binds_a_bare_call() {
        let source = concat!(
            "<?php\n",
            "namespace Demo\\Mixed;\n",
            "trait Roundable {\n",
            "    public function floor(float $value): float { return floor($value); }\n",
            "}\n",
            "class Mixed {\n",
            "    use Roundable;\n",
            "    public function go(float $v): float { return floor($v); }\n",
            "}\n",
        );
        let scopes = build(source);
        assert!(
            !scopes.is_bound_at("floor", byte_of(source, "floor($value)")),
            "a trait's own method is unreachable from a bare call inside the trait"
        );
        assert!(
            !scopes.is_bound_at("floor", byte_of(source, "floor($v)")),
            "a used trait's method is unreachable from a bare call in the using class"
        );
    }

    /// A conditionally declared helper -- the Laravel/CodeIgniter idiom -- is an
    /// ordinary published free function, and a call written above it still
    /// binds.
    #[test]
    fn a_guarded_or_later_free_function_still_binds() {
        let source = concat!(
            "<?php\n",
            "namespace Demo\\App;\n",
            "function caller(): string { return guarded_helper('a'); }\n",
            "if (! function_exists('guarded_helper')) {\n",
            "    function guarded_helper(string $name): string { return $name; }\n",
            "}\n",
        );
        assert!(
            build(source).is_bound_at("guarded_helper", byte_of(source, "guarded_helper('a')")),
            "a function is visible in its whole namespace, before and inside a guard"
        );
    }

    /// A function nested in a method body is not a CodeUnit -- the declaration
    /// walk does not descend into a class -- so it is not the same-file
    /// declaration the census matched.
    #[test]
    fn a_function_nested_in_a_class_body_is_not_published() {
        let source = concat!(
            "<?php\n",
            "namespace Demo\\App;\n",
            "class Host {\n",
            "    public function go(): int {\n",
            "        function nested(): int { return 1; }\n",
            "        return nested();\n",
            "    }\n",
            "}\n",
        );
        assert!(
            !build(source).is_bound_at("nested", byte_of(source, "nested();")),
            "the declaration walk does not publish a function declared inside a class"
        );
    }
}
