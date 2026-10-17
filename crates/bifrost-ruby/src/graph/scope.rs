use crate::graph::resolver::ReceiverMode;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use std::hash::Hash;

pub enum RubyScopeExit {
    Type { has_lexical_owner: bool },
    Method,
    SingletonClass,
    LocalScope,
}

pub fn exit_scope<T: Clone + Eq + Hash>(
    exit: Option<RubyScopeExit>,
    receiver_context: &mut Vec<ReceiverMode>,
    lexical_stack: &mut Vec<String>,
    method_stack: &mut Vec<ReceiverMode>,
    locals: &mut LocalInferenceEngine<T>,
) {
    match exit {
        Some(RubyScopeExit::Type { has_lexical_owner }) => {
            assert!(
                matches!(receiver_context.pop(), Some(ReceiverMode::Instance)),
                "type receiver context must match its exit"
            );
            if has_lexical_owner {
                lexical_stack.pop();
            }
        }
        Some(RubyScopeExit::Method) => {
            method_stack.pop();
            locals.exit_scope();
        }
        Some(RubyScopeExit::SingletonClass) => {
            assert!(
                matches!(receiver_context.pop(), Some(ReceiverMode::Class)),
                "singleton-class receiver context must match its exit"
            );
            method_stack.pop();
            locals.exit_scope();
        }
        Some(RubyScopeExit::LocalScope) => locals.exit_scope(),
        None => {}
    }
}
