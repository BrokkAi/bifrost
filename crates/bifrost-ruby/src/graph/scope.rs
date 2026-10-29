use crate::graph::resolver::ReceiverMode;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;

pub enum RubyScopeExit {
    Type {
        has_lexical_owner: bool,
        locals: LocalInferenceEngine<String>,
    },
    Method {
        locals: LocalInferenceEngine<String>,
    },
    SingletonClass {
        locals: LocalInferenceEngine<String>,
    },
    LocalScope,
}

pub fn exit_scope(
    exit: Option<RubyScopeExit>,
    receiver_context: &mut Vec<ReceiverMode>,
    lexical_stack: &mut Vec<String>,
    method_stack: &mut Vec<ReceiverMode>,
    locals: &mut LocalInferenceEngine<String>,
) {
    match exit {
        Some(RubyScopeExit::Type {
            has_lexical_owner,
            locals: enclosing,
        }) => {
            assert!(
                matches!(receiver_context.pop(), Some(ReceiverMode::Instance)),
                "type receiver context must match its exit"
            );
            *locals = enclosing;
            if has_lexical_owner {
                lexical_stack.pop();
            }
        }
        Some(RubyScopeExit::Method { locals: enclosing }) => {
            method_stack.pop();
            *locals = enclosing;
        }
        Some(RubyScopeExit::SingletonClass { locals: enclosing }) => {
            assert!(
                matches!(receiver_context.pop(), Some(ReceiverMode::Class)),
                "singleton-class receiver context must match its exit"
            );
            method_stack.pop();
            *locals = enclosing;
        }
        Some(RubyScopeExit::LocalScope) => locals.exit_scope(),
        None => {}
    }
}

// Ruby evaluates a type declaration's header in the enclosing scope. Its body
// starts the new lexical owner and isolates local bindings.
pub(crate) fn ruby_type_body_declaration(
    node: tree_sitter::Node<'_>,
) -> Option<tree_sitter::Node<'_>> {
    let declaration = node.parent()?;
    (matches!(declaration.kind(), "class" | "module")
        && declaration.child_by_field_name("body") == Some(node))
    .then_some(declaration)
}
