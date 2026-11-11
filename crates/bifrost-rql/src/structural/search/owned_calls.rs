//! Narrow only selectors whose rows keep the identity of one seed call.
use super::*;

/// Source call anchors owned by one procedure and the full artifact's range
/// inventory. This request-local filter preserves the binder's global
/// exact-before-shortest-enclosing ranking; it never decides uniqueness.
#[derive(Debug)]
#[doc(hidden)]
pub struct OwnedCallAnchors {
    file: ProjectFile,
    anchors: Box<[(usize, usize)]>,
    // Shared sorted (start, end, prefix maximum end) enclosure index.
    all_anchors: Arc<[(usize, usize, usize)]>,
}

/// Immutable per-file range inventory shared by request-local ownership views.
#[derive(Debug)]
#[doc(hidden)]
pub struct CallAnchorInventory {
    file: ProjectFile,
    all_anchors: Arc<[(usize, usize, usize)]>,
}

impl CallAnchorInventory {
    pub fn new(file: ProjectFile, all_anchors: Vec<std::ops::Range<usize>>) -> Self {
        let mut all_anchors = all_anchors
            .into_iter()
            .map(|span| (span.start, span.end, 0))
            .collect::<Vec<_>>();
        all_anchors.sort_unstable();
        all_anchors.dedup();
        let mut maximum_end = 0;
        for (_, end, prefix_end) in &mut all_anchors {
            maximum_end = maximum_end.max(*end);
            *prefix_end = maximum_end;
        }
        Self {
            file,
            all_anchors: all_anchors.into(),
        }
    }

    pub fn owned(&self, anchors: Vec<std::ops::Range<usize>>) -> OwnedCallAnchors {
        let mut anchors = anchors
            .into_iter()
            .map(|span| (span.start, span.end))
            .collect::<Vec<_>>();
        anchors.sort_unstable();
        anchors.dedup();
        OwnedCallAnchors {
            file: self.file.clone(),
            anchors: anchors.into_boxed_slice(),
            all_anchors: Arc::clone(&self.all_anchors),
        }
    }
}

impl OwnedCallAnchors {
    pub fn new(
        file: ProjectFile,
        anchors: Vec<std::ops::Range<usize>>,
        all_anchors: Vec<std::ops::Range<usize>>,
    ) -> Self {
        CallAnchorInventory::new(file, all_anchors).owned(anchors)
    }

    /// Covers input and conversion vectors for both owned and global ranges.
    /// `calls` counts the full artifact, including calls in other procedures.
    pub fn allocation_upper_bound(file: &ProjectFile, calls: usize) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(2 * std::mem::size_of::<usize>())
            .saturating_add(file.retained_bytes())
            .saturating_add(calls.saturating_mul(12 * std::mem::size_of::<usize>()))
    }

    pub fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(2 * std::mem::size_of::<usize>())
            .saturating_add(self.file.retained_bytes())
            .saturating_add(
                self.anchors
                    .len()
                    .saturating_mul(std::mem::size_of::<(usize, usize)>()),
            )
            .saturating_add(self.all_anchors.len().saturating_mul(std::mem::size_of::<(
                usize,
                usize,
                usize,
            )>()))
    }

    pub(super) fn contains(&self, file: &ProjectFile, span: Range) -> bool {
        if self.file != *file {
            return false;
        }
        let range = (span.start_byte, span.end_byte);
        if self
            .all_anchors
            .binary_search_by_key(&range, |&(start, end, _)| (start, end))
            .is_ok()
        {
            return self.anchors.binary_search(&range).is_ok();
        }
        let mut cursor = self
            .all_anchors
            .partition_point(|&(start, _, _)| start <= span.start_byte);
        let mut best_length = usize::MAX;
        let mut owned_best = false;
        while cursor > 0 {
            cursor -= 1;
            let (start, end, prefix_end) = self.all_anchors[cursor];
            if prefix_end < span.end_byte {
                break;
            }
            if end < span.end_byte {
                continue;
            }
            let length = end - start;
            if length <= best_length {
                let owned = self.anchors.binary_search(&(start, end)).is_ok();
                if length < best_length {
                    owned_best = owned;
                } else {
                    owned_best |= owned;
                }
                best_length = length;
            }
        }
        // Retain every tied best range if any is owned. The binder still sees
        // ALL calls and rejects distinct tied ranges rather than inventing uniqueness.
        // No semantic anchor means ownership is unattributed, not foreign.
        // Retain that candidate so missing-locator/model uncertainty reaches
        // every visit instead of being silently lost when the scope moves.
        best_length == usize::MAX || owned_best
    }
}

/// Conservative proof over the compiled selector, not its authored spelling.
/// Unknown sources, steps or structural relations keep legacy file selection.
#[doc(hidden)]
pub fn conditional_selector_is_site_local(plan: &CodeQueryPlan) -> bool {
    let CodeQueryPlanSource::Seed(seed) = &plan.source else {
        return false;
    };
    seed.inside.is_none()
        && seed.inside_decl.is_none()
        && seed.not_inside.is_none()
        && seed.root.kinds.as_slice() == [NormalizedKind::Call]
        && local_pattern(&seed.root)
        && plan.steps.iter().all(|step| {
            matches!(
                step,
                QueryStep::CallShape
                    | QueryStep::CallBindings
                    | QueryStep::ResolvedCall(_)
                    | QueryStep::CallArgument(_)
            )
        })
}

fn local_pattern(pattern: &crate::query::Pattern) -> bool {
    use crate::query::Pattern;
    // Exhaustive destructuring forces new pattern vocabulary through this
    // gate. Descendant/sibling-dependent relations are deliberately absent.
    let Pattern {
        kinds: _,
        not_kinds: _,
        name: _,
        text: _,
        comment_block_text,
        boolean_value: _,
        is_async,
        unsafe_context,
        modifier,
        type_kind,
        string_value: _,
        language_rule,
        body_state,
        body_owner,
        parenthesized,
        integer_value: _,
        duplicate_key,
        integer_has_any_bits,
        integer_has_all_bits,
        integer_has_no_bits,
        assignment_target_kind,
        assignment_value_kind,
        assignment_target_unstarred_count,
        assignment_value_unstarred_count,
        assignment_target_starred,
        assignment_value_starred,
        assignment_unstarred_count_mismatch,
        index: _,
        arity: _,
        count,
        visibility,
        parameter_type,
        capture: _,
        has,
        each,
        argument_modes,
        local_value,
        initializer_of,
        not_has,
        not,
        all,
        any,
        type_operand,
        operand,
        consequence,
        alternative,
        body,
        label,
        binding,
        indices,
        dimensions,
        parameters,
        members,
        callee,
        receiver,
        args,
        kwargs,
        left,
        right,
        operator,
        module,
        decorators,
        object,
        field,
        iterable,
        elements,
        tag,
        attributes,
        children,
        parts,
        value,
        key,
        test,
        type_arguments,
        qualifying_type,
    } = pattern;
    qualifying_type.is_none()
        && comment_block_text.is_none()
        && is_async.is_none()
        && unsafe_context.is_none()
        && modifier.is_none()
        && type_kind.is_none()
        && language_rule.is_none()
        && body_state.is_none()
        && body_owner.is_none()
        && parenthesized.is_none()
        && duplicate_key.is_none()
        && integer_has_any_bits.is_none()
        && integer_has_all_bits.is_none()
        && integer_has_no_bits.is_none()
        && assignment_target_kind.is_none()
        && assignment_value_kind.is_none()
        && assignment_target_unstarred_count.is_none()
        && assignment_value_unstarred_count.is_none()
        && assignment_target_starred.is_none()
        && assignment_value_starred.is_none()
        && assignment_unstarred_count_mismatch.is_none()
        && count.is_none()
        && visibility.is_empty()
        && parameter_type.is_none()
        && has.is_none()
        && each.is_none()
        && argument_modes.is_empty()
        && local_value.is_none()
        && initializer_of.is_none()
        && not_has.is_none()
        && not.is_none()
        && all.is_empty()
        && any.is_empty()
        && type_operand.is_none()
        && operand.is_none()
        && consequence.is_none()
        && alternative.is_none()
        && body.is_none()
        && label.is_none()
        && binding.is_none()
        && indices.is_empty()
        && dimensions.is_empty()
        && parameters.is_empty()
        && members.is_empty()
        && left.is_none()
        && right.is_none()
        && operator.is_none()
        && module.is_none()
        && decorators.is_empty()
        && object.is_none()
        && field.is_none()
        && iterable.is_none()
        && elements.is_empty()
        && tag.is_none()
        && attributes.is_empty()
        && children.is_empty()
        && parts.is_empty()
        && value.is_none()
        && key.is_none()
        && test.is_none()
        && callee.as_deref().is_none_or(local_pattern)
        && receiver.as_deref().is_none_or(local_pattern)
        && args.iter().all(local_pattern)
        && kwargs.iter().all(|(_, pattern)| local_pattern(pattern))
        && type_arguments.iter().all(local_pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{CodeQuerySeed, Pattern, SetOperator};
    use brokk_bifrost_core::analyzer::structural::facts::ArgumentMode;

    fn one(span: std::ops::Range<usize>) -> Vec<std::ops::Range<usize>> {
        std::iter::once(span).collect()
    }

    fn selected(
        owned: Vec<std::ops::Range<usize>>,
        all: Vec<std::ops::Range<usize>>,
        span: std::ops::Range<usize>,
    ) -> bool {
        let file = ProjectFile::new(std::env::temp_dir(), "owned-call-test.rs");
        OwnedCallAnchors::new(file.clone(), owned, all).contains(
            &file,
            Range {
                start_byte: span.start,
                end_byte: span.end,
                start_line: 0,
                end_line: 0,
            },
        )
    }

    #[test]
    fn enclosing_anchor_is_retained_without_stealing_a_closure_call() {
        assert!(selected(one(10..30), one(10..30), 12..28));
        assert!(!selected(one(0..100), vec![0..100, 10..30], 10..30));
        assert!(!selected(one(0..100), vec![0..100, 10..30], 12..28));
        assert!(selected(one(10..30), vec![0..100, 10..30], 12..28));
    }

    #[test]
    fn tied_enclosing_ranges_survive_for_global_ambiguity_check() {
        assert!(selected(one(10..30), vec![10..30, 12..32], 14..28));
        assert!(selected(one(12..32), vec![10..30, 12..32], 14..28));
        assert!(selected(one(10..30), vec![10..30, 10..30], 10..30));
        assert!(!selected(one(0..100), vec![0..100, 10..30, 12..32], 14..28));
    }

    #[test]
    fn unattributed_call_anchor_is_retained_for_every_visit() {
        assert!(selected(one(10..30), one(10..30), 50..60));
        assert!(selected(Vec::new(), one(10..30), 50..60));
        assert!(!selected(Vec::new(), one(10..30), 12..28));
    }

    fn call_plan() -> CodeQueryPlan {
        CodeQueryPlan {
            source: CodeQueryPlanSource::Seed(Box::new(CodeQuerySeed {
                where_globs: Default::default(),
                languages: vec![],
                root: Pattern {
                    kinds: vec![NormalizedKind::Call],
                    ..Pattern::default()
                },
                inside: None,
                inside_decl: None,
                not_inside: None,
            })),
            steps: vec![QueryStep::CallShape, QueryStep::CallBindings],
        }
    }

    #[test]
    fn site_local_gate_rejects_sibling_sets_and_unknown_steps() {
        let plan = call_plan();
        assert!(conditional_selector_is_site_local(&plan));
        for op in [SetOperator::Except, SetOperator::Intersect] {
            let set = CodeQueryPlan {
                source: CodeQueryPlanSource::Set {
                    op,
                    branches: vec![plan.clone(), plan.clone()],
                },
                steps: vec![],
            };
            assert!(!conditional_selector_is_site_local(&set));
        }
        let mut relation = plan;
        relation.steps.push(QueryStep::EnclosingDecl);
        assert!(!conditional_selector_is_site_local(&relation));
    }

    #[test]
    fn site_local_gate_rejects_unrecognized_pattern_relations() {
        let mut plan = call_plan();
        let CodeQueryPlanSource::Seed(seed) = &mut plan.source else {
            unreachable!()
        };
        seed.root.has = Some(Box::new(Pattern::default()));
        assert!(!conditional_selector_is_site_local(&plan));

        let mut plan = call_plan();
        let CodeQueryPlanSource::Seed(seed) = &mut plan.source else {
            unreachable!()
        };
        seed.root.each = Some(Box::new(Pattern::default()));
        assert!(!conditional_selector_is_site_local(&plan));

        let mut plan = call_plan();
        let CodeQueryPlanSource::Seed(seed) = &mut plan.source else {
            unreachable!()
        };
        seed.root.argument_modes = vec![ArgumentMode::Ref];
        assert!(!conditional_selector_is_site_local(&plan));
    }
}
