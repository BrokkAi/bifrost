use crate::syntax::{
    clause_binding_names, clause_statement_list, declared_names, is_clause,
    is_definition_identifier, parameter_names, selector_parts,
};
use brokk_bifrost_core::analyzer::common::node_source_text as node_text;
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::analyzer::usages::reference_site::{
    ResolvedReferenceSite, smallest_named_node_covering_with_scope,
};
use tree_sitter::Node;

#[derive(Debug, Clone)]
pub struct GoSelectorDescriptor<'tree> {
    pub base: Node<'tree>,
    pub members: Vec<Node<'tree>>,
    pub focus_segment: usize,
}

impl GoSelectorDescriptor<'_> {
    pub fn focused_node(&self) -> Node<'_> {
        if self.focus_segment == 0 {
            self.base
        } else {
            self.members[self.focus_segment - 1]
        }
    }

    pub fn base_identifier<'source>(&self, source: &'source str) -> Option<&'source str> {
        matches!(
            self.base.kind(),
            "identifier" | "package_identifier" | "type_identifier"
        )
        .then(|| node_text(self.base, source))
    }

    pub fn member_name<'source>(&self, source: &'source str, index: usize) -> Option<&'source str> {
        let member = *self.members.get(index)?;
        matches!(
            member.kind(),
            "field_identifier" | "type_identifier" | "identifier"
        )
        .then(|| node_text(member, source))
    }
}

pub fn go_selector_descriptor<'tree>(
    root: Node<'tree>,
    site: &ResolvedReferenceSite,
) -> Option<GoSelectorDescriptor<'tree>> {
    go_selector_descriptor_with_scope(root, site, || true)
}

pub fn go_selector_descriptor_with_scope<'tree>(
    root: Node<'tree>,
    site: &ResolvedReferenceSite,
    mut scope_step: impl FnMut() -> bool,
) -> Option<GoSelectorDescriptor<'tree>> {
    let selected = smallest_named_node_covering_with_scope(
        root,
        site.focus_start_byte,
        site.focus_end_byte,
        &mut scope_step,
    )?;
    let mut top = selected;
    while let Some(parent) = top.parent() {
        if !scope_step() {
            return None;
        }
        if matches!(parent.kind(), "selector_expression" | "qualified_type") {
            top = parent;
        } else {
            break;
        }
    }
    if !matches!(top.kind(), "selector_expression" | "qualified_type") {
        return None;
    }

    let mut base = top;
    let mut members = Vec::new();
    while matches!(base.kind(), "selector_expression" | "qualified_type") {
        if !scope_step() {
            return None;
        }
        let member = base
            .child_by_field_name("field")
            .or_else(|| base.child_by_field_name("name"))?;
        members.push(member);
        base = base
            .child_by_field_name("operand")
            .or_else(|| base.child_by_field_name("package"))?;
    }
    members.reverse();

    let contains_focus = |node: Node<'_>| {
        node.start_byte() <= site.focus_start_byte && node.end_byte() >= site.focus_end_byte
    };
    let focus_segment = if contains_focus(base)
        && matches!(
            base.kind(),
            "identifier" | "package_identifier" | "type_identifier"
        ) {
        0
    } else {
        members.iter().position(|member| contains_focus(*member))? + 1
    };

    Some(GoSelectorDescriptor {
        base,
        members,
        focus_segment,
    })
}

/// Whether `node` is a top-level declaration (a direct child of the source file),
/// i.e. package scope rather than a function/block-local binding.
pub fn go_is_top_level_decl(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "source_file")
}

enum GoShadowFrame<'tree> {
    Visit(Node<'tree>),
    ExitScope,
}

/// Whether a lexical Go declaration hides `name` at `byte`.
///
/// Package and import declarations are resolved by their own namespaces. This
/// walk owns parameters, block locals, local types and range-variable scope.
///
/// The walk is iterative even for arbitrarily nested blocks and expressions.
/// `scope_step` is charged for visited and enumerated syntax nodes; denial
/// returns `None`, allowing an exactness consumer to abstain rather than turn
/// an incomplete prefix walk into a negative shadow fact.
pub fn go_name_shadowed_at_with_scope(
    root: Node<'_>,
    source: &str,
    byte: usize,
    name: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut frames = vec![GoShadowFrame::Visit(root)];
    while let Some(frame) = frames.pop() {
        match frame {
            GoShadowFrame::ExitScope => {
                locals.exit_scope();
                continue;
            }
            GoShadowFrame::Visit(node) => {
                if !scope_step() {
                    return None;
                }
                if node.start_byte() >= byte {
                    if node.start_byte() == byte {
                        return Some(locals.is_shadowed(name));
                    }
                    continue;
                }

                match node.kind() {
                    "import_declaration" => continue,
                    "func_literal" | "function_declaration" | "method_declaration" => {
                        if !(node.start_byte() <= byte && byte < node.end_byte()) {
                            continue;
                        }
                        locals.enter_scope();
                        if node
                            .child_by_field_name("body")
                            .is_some_and(|body| body.start_byte() <= byte && byte < body.end_byte())
                        {
                            seed_go_parameters(node, source, &mut locals, &mut scope_step)?;
                        }
                        frames.push(GoShadowFrame::ExitScope);
                        push_go_children_before(node, byte, &mut frames, &mut scope_step)?;
                        continue;
                    }
                    "for_statement" | "block" | "block_statement" => {
                        if !(node.start_byte() <= byte && byte < node.end_byte()) {
                            continue;
                        }
                        // Go's implicit ForStmt block owns both its initializer
                        // and a RangeClause `:=`; an explicit block owns its
                        // preceding declarations. Only scopes containing the
                        // cutoff are entered.
                        locals.enter_scope();
                        frames.push(GoShadowFrame::ExitScope);
                        push_go_children_before(node, byte, &mut frames, &mut scope_step)?;
                        continue;
                    }
                    _ if is_clause(node) => {
                        let body = clause_statement_list(node);
                        if let Some(body) = body
                            && body.start_byte() <= byte
                            && byte < body.end_byte()
                        {
                            locals.enter_scope();
                            declare_shadow_names(
                                &mut locals,
                                clause_binding_names(node, source),
                                &mut scope_step,
                            )?;
                            frames.push(GoShadowFrame::ExitScope);
                            frames.push(GoShadowFrame::Visit(body));
                            continue;
                        }
                        if node.start_byte() <= byte && byte < node.end_byte() {
                            let mut cursor = node.walk();
                            let mut header_children = Vec::new();
                            for child in node.named_children(&mut cursor) {
                                if !scope_step() {
                                    return None;
                                }
                                if child.start_byte() <= byte && Some(child) != body {
                                    header_children.push(child);
                                }
                            }
                            frames.extend(
                                header_children.into_iter().rev().map(GoShadowFrame::Visit),
                            );
                        }
                        // Clause bodies are implicit lexical blocks. A clause
                        // that does not contain the cutoff cannot contribute
                        // declarations to a sibling or the post-switch scope.
                        continue;
                    }
                    "short_var_declaration"
                        if node.end_byte() <= byte && !go_is_top_level_decl(node) =>
                    {
                        declare_shadow_names(
                            &mut locals,
                            declared_names(node, source),
                            &mut scope_step,
                        )?;
                    }
                    "range_clause" if node.end_byte() <= byte => {
                        declare_shadow_names(
                            &mut locals,
                            declared_names(node, source),
                            &mut scope_step,
                        )?;
                    }
                    "var_declaration" if !go_is_top_level_decl(node) => {
                        declare_shadow_names(
                            &mut locals,
                            local_value_declaration_names(
                                node,
                                "var_spec",
                                source,
                                byte,
                                &mut scope_step,
                            )?,
                            &mut scope_step,
                        )?;
                    }
                    "const_declaration" if !go_is_top_level_decl(node) => {
                        declare_shadow_names(
                            &mut locals,
                            local_value_declaration_names(
                                node,
                                "const_spec",
                                source,
                                byte,
                                &mut scope_step,
                            )?,
                            &mut scope_step,
                        )?;
                    }
                    "type_declaration" if !go_is_top_level_decl(node) => {
                        declare_shadow_names(
                            &mut locals,
                            local_type_declaration_names(node, source, byte, &mut scope_step)?,
                            &mut scope_step,
                        )?;
                    }
                    "selector_expression" | "qualified_type" => {
                        if selector_is_lookup_target(node, source, byte) {
                            return Some(locals.is_shadowed(name));
                        }
                    }
                    "identifier" | "type_identifier" | "package_identifier"
                        if node.start_byte() == byte || is_definition_identifier(node, source) =>
                    {
                        if node.start_byte() == byte {
                            return Some(locals.is_shadowed(name));
                        }
                        continue;
                    }
                    _ => {}
                }
                push_go_children_before(node, byte, &mut frames, &mut scope_step)?;
            }
        }
    }
    Some(locals.is_shadowed(name))
}

fn push_go_children_before<'tree>(
    node: Node<'tree>,
    cutoff_start: usize,
    frames: &mut Vec<GoShadowFrame<'tree>>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    let mut cursor = node.walk();
    let mut children = Vec::new();
    for child in node.named_children(&mut cursor) {
        if !scope_step() {
            return None;
        }
        if child.start_byte() <= cutoff_start {
            children.push(child);
        }
    }
    frames.extend(children.into_iter().rev().map(GoShadowFrame::Visit));
    Some(())
}

fn declare_shadow_names(
    locals: &mut LocalInferenceEngine<String>,
    names: Vec<String>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    for name in names {
        if !scope_step() {
            return None;
        }
        locals.declare_shadow(name);
    }
    Some(())
}

fn local_value_declaration_names(
    node: Node<'_>,
    spec_kind: &str,
    source: &str,
    cutoff_start: usize,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<Vec<String>> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if !scope_step() {
            return None;
        }
        if current.kind() == spec_kind {
            if current.end_byte() <= cutoff_start {
                let mut cursor = current.walk();
                for name in current.children_by_field_name("name", &mut cursor) {
                    if !scope_step() {
                        return None;
                    }
                    names.push(node_text(name, source).to_owned());
                }
            }
            continue;
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if !scope_step() {
                return None;
            }
            stack.push(child);
        }
    }
    Some(names)
}

fn local_type_declaration_names(
    node: Node<'_>,
    source: &str,
    cutoff_start: usize,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<Vec<String>> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if !scope_step() {
            return None;
        }
        if matches!(current.kind(), "type_spec" | "type_alias") {
            if let Some(name) = current
                .child_by_field_name("name")
                .filter(|name| name.start_byte() <= cutoff_start)
            {
                names.push(node_text(name, source).to_owned());
            }
            continue;
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if !scope_step() {
                return None;
            }
            stack.push(child);
        }
    }
    Some(names)
}

fn seed_go_parameters(
    node: Node<'_>,
    source: &str,
    locals: &mut LocalInferenceEngine<String>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    if node.kind() == "method_declaration"
        && let Some(receiver) = node.child_by_field_name("receiver")
    {
        let mut stack = vec![(receiver, false)];
        while let Some((current, inside_type_arguments)) = stack.pop() {
            if !scope_step() {
                return None;
            }
            let inside_type_arguments = inside_type_arguments || current.kind() == "type_arguments";
            if inside_type_arguments && matches!(current.kind(), "identifier" | "type_identifier") {
                locals.declare_shadow(node_text(current, source).to_owned());
                continue;
            }
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                if !scope_step() {
                    return None;
                }
                stack.push((child, inside_type_arguments));
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !scope_step() {
            return None;
        }
        match child.kind() {
            "parameter_list" | "type_parameter_list" => {
                let mut params = child.walk();
                for parameter in child.named_children(&mut params) {
                    if !scope_step() {
                        return None;
                    }
                    if matches!(
                        parameter.kind(),
                        "parameter_declaration"
                            | "variadic_parameter_declaration"
                            | "type_parameter_declaration"
                    ) {
                        declare_shadow_names(
                            locals,
                            parameter_names(parameter, source),
                            scope_step,
                        )?;
                    }
                }
            }
            _ => {}
        }
    }
    Some(())
}

fn selector_is_lookup_target(node: Node<'_>, source: &str, cutoff_start: usize) -> bool {
    selector_parts(node, source)
        .map(|(_, _, field)| field.start_byte() == cutoff_start)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "aa501216592e: A declaration in a grouped Go type spec becomes visible only after the earlier RHS is resolved."
    )]
    fn later_local_type_spec_does_not_shadow_an_earlier_spec_rhs() {
        let source = r#"package main
import embedded "embed"
func f() {
    type (
        earlier = embedded.FS
        embedded = earlier
    )
    _ = embedded.Open
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar loads");
        let tree = parser.parse(source, None).expect("source parses");
        let import_use = source.find("embedded.FS").expect("earlier spec RHS");
        let method_use = source.rfind("embedded.Open").expect("later type use");

        assert!(
            !go_name_shadowed_at_with_scope(
                tree.root_node(),
                source,
                import_use,
                "embedded",
                || true,
            )
            .expect("unmetered shadow check")
        );
        assert!(
            go_name_shadowed_at_with_scope(
                tree.root_node(),
                source,
                method_use,
                "embedded",
                || true,
            )
            .expect("unmetered shadow check")
        );
    }

    #[test]
    #[hardwon(
        "aa501216592e: A receiver type parameter named like an import shadows that package inside the method."
    )]
    fn generic_method_receiver_type_argument_shadows_an_import() {
        let source = r#"package main
import T "embed"
var _ T.FS
type Generic[U interface { Open(string) (int, error) }] struct{}
func (generic Generic[T]) openTheme(receiver T) {
    _, _ = T.Open(receiver, "theme.xml")
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar loads");
        let tree = parser.parse(source, None).expect("source parses");
        let method_use = source.rfind("T.Open").expect("method expression");

        assert!(
            go_name_shadowed_at_with_scope(tree.root_node(), source, method_use, "T", || true,)
                .expect("unmetered shadow check")
        );
    }

    #[test]
    #[hardwon(
        "499616c60cc3: Range := binders activate after the clause and stay confined to the loop body."
    )]
    fn range_short_declarations_shadow_only_after_the_clause_and_inside_the_loop() {
        let source = r#"package main
import T "embed"
func f() {
    for _, T := range []T.FS{} {
        _, _ = T.Open("theme.xml")
    }
    _ = T.FS{}
    for T.Slot = range []int{} {
        _ = T.Open
    }
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar loads");
        let tree = parser.parse(source, None).expect("source parses");
        let range_rhs = source.find("T.FS{}").expect("range RHS import use");
        let range_body = source
            .find("T.Open(\"theme.xml\")")
            .expect("range local use");
        let after_loop = source.rfind("T.FS{}").expect("post-loop import use");
        let assignment_body = source.rfind("T.Open").expect("assignment-range import use");

        assert!(
            !go_name_shadowed_at_with_scope(tree.root_node(), source, range_rhs, "T", || true,)
                .expect("unmetered shadow check")
        );
        assert!(
            go_name_shadowed_at_with_scope(tree.root_node(), source, range_body, "T", || true,)
                .expect("unmetered shadow check")
        );
        assert!(
            !go_name_shadowed_at_with_scope(tree.root_node(), source, after_loop, "T", || true,)
                .expect("unmetered shadow check")
        );
        assert!(
            !go_name_shadowed_at_with_scope(tree.root_node(), source, assignment_body, "T", || {
                true
            },)
            .expect("unmetered shadow check")
        );

        let mut ranges = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "range_clause" {
                ranges.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        ranges.sort_by_key(Node::start_byte);
        assert_eq!(declared_names(ranges[0], source), ["T"]);
        assert!(declared_names(ranges[1], source).is_empty());
    }
}
