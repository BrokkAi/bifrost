use crate::analyzer::semantic_model::csmi::model::CsmiDeferredYieldLocation;

use crate::analyzer::semantic_model::csmi::model::CsmiDeferredYieldPayload;

use crate::analyzer::semantic_model::csmi::model::CsmiDeferredYieldShape;

use crate::analyzer::semantic_model::csmi::model::CsmiDeferredYieldTypeExpression;

pub(in crate::analyzer::semantic_model::csmi) fn remap_payload<E>(
    payload: &mut CsmiDeferredYieldPayload,
    path: &str,
    mut map_member: impl FnMut(&str, &str) -> Result<String, E>,
    mut map_type: impl FnMut(&str, &str) -> Result<String, E>,
    mut map_location: impl FnMut(&mut CsmiDeferredYieldLocation, &str) -> Result<(), E>,
    mut map_shape: impl FnMut(&mut CsmiDeferredYieldShape, &str) -> Result<(), E>,
) -> Result<(), E> {
    payload.factory = map_member(&payload.factory, &format!("{path}.factory"))?;
    payload.resume = map_member(&payload.resume, &format!("{path}.resume"))?;
    payload.handle_type = map_type(&payload.handle_type, &format!("{path}.handleType"))?;
    if let Some(crate::analyzer::semantic_model::csmi::model::CsmiDeferredYieldSubstitution::ReceiverArguments { declaration }) =
        &mut payload.receiver_substitution
    {
        *declaration = map_type(
            declaration,
            &format!("{path}.receiverSubstitution.declaration"),
        )?;
    }
    for (position, root) in payload.roots.iter_mut().enumerate() {
        let root_path = format!("{path}.roots[{position}]");
        root.callable = map_member(&root.callable, &format!("{root_path}.callable"))?;
        map_shape(&mut root.shape, &format!("{root_path}.shape"))?;
    }
    map_location(
        &mut payload.construction.source,
        &format!("{path}.construction.source"),
    )?;
    map_location(
        &mut payload.construction.handle,
        &format!("{path}.construction.handle"),
    )?;
    map_location(
        &mut payload.resume_contract.handle_input,
        &format!("{path}.resumeContract.handleInput"),
    )?;
    map_location(
        &mut payload.resume_contract.yielded_result,
        &format!("{path}.resumeContract.yieldedResult"),
    )?;
    map_location(
        &mut payload.resume_contract.factory_result_flow.factory_result,
        &format!("{path}.resumeContract.factoryResultFlow.factoryResult"),
    )?;
    map_location(
        &mut payload.resume_contract.factory_result_flow.resume_input,
        &format!("{path}.resumeContract.factoryResultFlow.resumeInput"),
    )?;
    for (position, member) in payload.yield_contract.members.iter_mut().enumerate() {
        map_location(
            &mut member.source,
            &format!("{path}.yield.members[{position}].source"),
        )?;
    }
    Ok(())
}

pub(in crate::analyzer::semantic_model::csmi) fn visit_shape<E>(
    shape: &mut CsmiDeferredYieldShape,
    path: &str,
    mut map_type: impl FnMut(&mut CsmiDeferredYieldTypeExpression, &str) -> Result<(), E>,
) -> Result<(), E> {
    let mut stack = vec![(shape, path.to_owned())];
    while let Some((shape, path)) = stack.pop() {
        match shape {
            CsmiDeferredYieldShape::Value { r#type } => {
                map_type(r#type, &format!("{path}.type"))?;
            }
            CsmiDeferredYieldShape::Product { components } => {
                for (position, component) in components.iter_mut().enumerate().rev() {
                    stack.push((component, format!("{path}.components[{position}]")));
                }
            }
            CsmiDeferredYieldShape::Keyed { key, value, .. } => {
                stack.push((value, format!("{path}.value")));
                stack.push((key, format!("{path}.key")));
            }
            CsmiDeferredYieldShape::Unknown { .. } => {}
        }
    }
    Ok(())
}
