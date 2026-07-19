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
