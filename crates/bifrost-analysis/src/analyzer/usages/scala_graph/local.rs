use crate::analyzer::CodeUnit;
use crate::analyzer::usages::local_inference::LocalInferenceEngine;

/// The two independent facts known about a Scala local or member binding.
///
/// `receiver_type` drives member lookup on the value. `declaration_owner`
/// identifies a source-backed field declaration when the binding name itself
/// is referenced. Keeping them separate prevents a field's enclosing class
/// from being mistaken for the type of the value stored in that field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(in crate::analyzer::usages) struct ScalaLocalBinding {
    pub(in crate::analyzer::usages) receiver_type: Option<String>,
    /// Parser-proven physical declaration for `receiver_type`, when the type
    /// name resolved in this binding's lexical declaration context.
    ///
    /// Keeping this beside the logical FQN lets member dispatch remain exact
    /// when a workspace contains multiple source replicas with the same FQN.
    /// Bindings inferred only from logical return types intentionally leave it
    /// absent so those ambiguous lookups continue to fail closed.
    pub(in crate::analyzer::usages) receiver_declaration: Option<CodeUnit>,
    pub(in crate::analyzer::usages) declaration_owner: Option<CodeUnit>,
}

pub(in crate::analyzer::usages) fn seed_scala_binding(
    name: &str,
    receiver_type: Option<String>,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    if receiver_type.is_none() && declaration_owner.is_none() {
        bindings.declare_shadow(name.to_string());
        return;
    }
    bindings.seed_symbol(
        name.to_string(),
        ScalaLocalBinding {
            receiver_type,
            receiver_declaration: None,
            declaration_owner,
        },
    );
}

pub(in crate::analyzer::usages) fn seed_scala_binding_with_receiver_declaration(
    name: &str,
    receiver_declaration: CodeUnit,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    bindings.seed_symbol(
        name.to_string(),
        ScalaLocalBinding {
            receiver_type: Some(receiver_declaration.fq_name()),
            receiver_declaration: Some(receiver_declaration),
            declaration_owner,
        },
    );
}

pub(in crate::analyzer::usages) fn precise_scala_binding(
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
    name: &str,
) -> Option<ScalaLocalBinding> {
    let precise = bindings.resolve_symbol_ref(name)?.as_precise()?;
    (precise.len() == 1)
        .then(|| precise.iter().next().cloned())
        .flatten()
}
