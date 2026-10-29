//! Structured proxy-call context. Names and candidate roles never prove identity.
use super::*;

pub(super) type SuperContextRow = (u32, u32, Option<u32>, Option<u32>, bool, bool);

#[derive(Clone)]
pub(super) struct SuperContext {
    callee: Option<SemanticId>,
    class_cell: Option<SemanticId>,
    first_parameter: bool,
    method: bool,
    arguments: Vec<Option<SemanticId>>,
    positional: bool,
    decorators: Vec<Option<SemanticId>>,
}
#[derive(Clone)]
pub(in crate::analyzer::store::resolution_operation) struct SuperCursor {
    pub start_after: SemanticId,
    pub receiver: ResolutionSlotValue,
}

impl SuperContext {
    pub fn read(rules: &PythonRules<'_, '_, '_>, reference: SemanticId) -> Result<Option<Self>> {
        let Some(ordinal) = reference.ordinal() else {
            return Ok(None);
        };
        let mount = rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let conn = rules.ready.inventory.connection();
        if rules.cancellation.is_cancelled() || !rules.session.scope_step() {
            return Ok(None);
        }
        let key = (mount.blob_id(), reference.local_key());
        let cached = rules.super_context_rows.borrow().get(&key).copied();
        let context = if let Some(context) = cached {
            context
        } else {
            let context: Option<SuperContextRow> = conn.query_row(
            "SELECT context.call,context.callee,context.callable,context.class_cell,
                context.first_parameter IS NOT NULL,
                EXISTS(SELECT 1 FROM python_member_member_roles role WHERE role.blob_id=context.blob_id AND role.member=context.callable AND role.receiver_parameter=context.first_parameter)
             FROM resolution_semantic_sites semantic
             JOIN python_member_super_members member ON member.blob_id=semantic.blob_id AND member.member=semantic.source_site
             JOIN python_member_super_contexts context ON context.blob_id=member.blob_id AND context.call=member.call
             WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='reference'",
            rusqlite::params![mount.blob_id(),reference.local_key()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?))).optional()?;
            assert!(
                rules
                    .super_context_rows
                    .borrow_mut()
                    .insert(key, context)
                    .is_none()
            );
            context
        };
        let Some((call, callee, callable, class_cell, first_parameter, method)) = context else {
            return Ok(None);
        };
        // Only an exact retained role/site correspondence can supply a demand.
        let semantic = |site: u32, role: &str| -> Result<Option<SemanticId>> {
            let keys = conn.prepare_cached("SELECT semantic_key FROM resolution_semantic_sites WHERE blob_id=?1 AND source_site=?2 AND semantic_role=?3")?
                .query_map(rusqlite::params![mount.blob_id(),site,role], |row| row.get::<_,u32>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(match keys.as_slice() {
                [key] => Some(SemanticId::local(ordinal, *key)),
                _ => None,
            })
        };
        let args = conn.prepare_cached("SELECT argument.kind,slot.site FROM python_member_call_arguments argument JOIN python_member_type_slots slot ON slot.blob_id=argument.blob_id AND slot.slot=argument.value WHERE argument.blob_id=?1 AND argument.call=?2 ORDER BY argument.ordinal")?
            .query_map(rusqlite::params![mount.blob_id(),call], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,u32>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut arguments = Vec::new();
        let mut positional = true;
        for (kind, site) in args {
            if rules.cancellation.is_cancelled() || !rules.session.scope_step() {
                return Ok(None);
            }
            positional &= kind == 0;
            arguments.push(semantic(site, "reference")?);
        }
        let sites = conn.prepare_cached("SELECT expression_site FROM python_member_decorators WHERE blob_id=?1 AND declaration=?2 ORDER BY ordinal")?
            .query_map(rusqlite::params![mount.blob_id(),callable], |row| row.get::<_,u32>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut decorators = Vec::new();
        for site in sites {
            if rules.cancellation.is_cancelled() || !rules.session.scope_step() {
                return Ok(None);
            }
            decorators.push(semantic(site, "reference")?);
        }
        Ok(Some(Self {
            callee: semantic(callee, "reference")?,
            class_cell: class_cell
                .map(|site| semantic(site, "definition"))
                .transpose()?
                .flatten(),
            first_parameter,
            method,
            arguments,
            positional,
            decorators,
        }))
    }

    pub fn prerequisites(&self) -> impl Iterator<Item = SemanticId> + '_ {
        self.callee
            .into_iter()
            .chain(self.arguments.iter().copied().flatten())
            .chain(self.decorators.iter().copied().flatten())
    }

    pub fn selected(
        &self,
        rules: &PythonRules<'_, '_, '_>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<SuperCursor>> {
        let answer = |reference: SemanticId| {
            inputs
                .iter()
                .find(|(key, _)| key.reference == reference)
                .map(|(_, answer)| *answer)
        };
        let selected = |reference: SemanticId| {
            answer(reference).and_then(|answer| {
                let binding = answer.binding();
                (binding.completion() == &ResolutionCompletion::Complete
                    && binding.targets().len() == 1)
                    .then(|| binding.targets()[0])
            })
        };
        let Some(callee) = self.callee.and_then(selected) else {
            return Ok(None);
        };
        if Some(callee) != super::super::python_members::builtin(rules.ready, "super")
            || !self.positional
        {
            return Ok(None);
        }
        let type_object = |identity| {
            ResolutionSlotValue::type_object(crate::analyzer::resolution::ResolutionTypeRef::new(
                identity, 0,
            ))
        };
        if self.arguments.is_empty() {
            let Some(class) = self.class_cell else {
                return Ok(None);
            };
            if !self.first_parameter || !self.method {
                return Ok(None);
            }
            let mut class_method = false;
            for reference in self.decorators.iter().rev() {
                let Some(decorator) = reference.and_then(selected) else {
                    return Ok(None);
                };
                if Some(decorator)
                    == super::super::python_members::builtin(rules.ready, "classmethod")
                    && !class_method
                {
                    class_method = true;
                } else {
                    return Ok(None);
                }
            }
            let receiver = if class_method {
                type_object(class)
            } else {
                ResolutionSlotValue::runtime(
                    crate::analyzer::resolution::ResolutionTypeRef::new(class, 0),
                    false,
                )
            };
            return Ok(Some(SuperCursor {
                start_after: class,
                receiver: receiver.with_receiver_subclass_obligation(),
            }));
        }
        if self.arguments.len() != 2 {
            return Ok(None);
        }
        // A completed Reference can retain binding incompleteness while naming
        // an authored class candidate. The shared prerequisite pump preserves
        // that completion; only builtin/decorator identity above requires an
        // exhaustive binding. Never substitute a class for an unknown target.
        let class_candidate = |reference: SemanticId| -> Result<Option<SemanticId>> {
            let Some(answer) = answer(reference) else {
                return Ok(None);
            };
            let [target] = answer.binding().targets() else {
                return Ok(None);
            };
            Ok(super::super::python_members::is_class(rules.ready, *target)?.then_some(*target))
        };
        let Some(start_reference) = self.arguments[0] else {
            return Ok(None);
        };
        let Some(start_after) = class_candidate(start_reference)? else {
            return Ok(None);
        };
        if !super::super::python_members::is_class(rules.ready, start_after)? {
            return Ok(None);
        }
        let Some(receiver_reference) = self.arguments[1] else {
            return Ok(None);
        };
        if let Some(receiver) = class_candidate(receiver_reference)? {
            return Ok(Some(SuperCursor {
                start_after,
                receiver: type_object(receiver),
            }));
        }
        let Some(answer) = answer(receiver_reference) else {
            return Ok(None);
        };
        let mut values = Vec::new();
        for projection in answer
            .projections()
            .iter()
            .filter(|projection| projection.reference() == receiver_reference)
        {
            for frontier in answer
                .projected_frontiers()
                .iter()
                .filter(|frontier| frontier.slot() == projection.output_slot())
            {
                values.extend(frontier.possible_values().iter().copied());
            }
        }
        values.sort_unstable();
        values.dedup();
        if let [receiver] = values.as_slice() {
            // A declared instance type is a subclass bound, not exact allocation proof.
            return Ok(Some(SuperCursor {
                start_after,
                receiver: if !answer.projections().iter().any(|projection| {
                    projection.reference() == receiver_reference
                        && projection.kind() == brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetConstructorOwnerType
                }) || answer.completion() != &ResolutionCompletion::Complete {
                    receiver.with_receiver_subclass_obligation()
                } else {
                    *receiver
                },
            }));
        }
        Ok(None)
    }
}
