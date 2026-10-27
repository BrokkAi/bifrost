use super::*;

pub(super) fn child_guards(
    p: &mut Producer<'_, '_>,
    node: Node<'_>,
    scope: ResolutionScopeId,
    parent: Option<u32>,
) -> HashMap<usize, u32> {
    let mut children = HashMap::default();
    if matches!(
        node.kind(),
        "conditional_expression" | "boolean_operator" | "assert_statement"
    ) {
        let site = p.site(node, scope, ResolutionSiteKind::UnsupportedExpression);
        let operands = if node.kind() == "conditional_expression" {
            crate::syntax::python_conditional_expression_operands(node)
        } else {
            None
        };
        if node.has_error()
            || node.kind() == "assert_statement"
            || (node.kind() == "conditional_expression" && operands.is_none())
        {
            let id = dense_ordinal(p.facts.python_guards.len(), "conditional activation guards");
            p.facts.python_guards.push(PythonNativeGuardFact {
                id,
                parent,
                site,
                execution_scope: scope,
                kind: PythonNativeGuardKind::UnknownControl,
                arm_ordinal: 0,
                predicate: None,
            });
            for child in named_children_iter(node) {
                children.insert(child.id(), id);
            }
            return children;
        }
        let (condition, branches) = if let Some([consequence, condition, alternative]) = operands {
            (condition, vec![(consequence, true), (alternative, false)])
        } else {
            let operator = node
                .child_by_field_name("operator")
                .expect("boolean operator");
            (
                node.child_by_field_name("left")
                    .expect("boolean left operand"),
                vec![(
                    node.child_by_field_name("right")
                        .expect("boolean right operand"),
                    operator.kind() == "and",
                )],
            )
        };
        let predicate = p.site(condition, scope, ResolutionSiteKind::UnsupportedExpression);
        temporal::predicate(p, condition, predicate);
        for (arm, (branch, truth)) in branches.into_iter().enumerate() {
            let id = dense_ordinal(p.facts.python_guards.len(), "expression branch guards");
            p.facts.python_guards.push(PythonNativeGuardFact {
                id,
                parent,
                site,
                execution_scope: scope,
                kind: if truth {
                    PythonNativeGuardKind::IfTrue
                } else {
                    PythonNativeGuardKind::IfFalse
                },
                arm_ordinal: dense_ordinal(arm, "expression branch"),
                predicate: Some(predicate),
            });
            children.insert(branch.id(), id);
        }
        return children;
    }
    if is_comprehension(node.kind()) {
        let mut previous = parent;
        for clause in named_children_iter(node).filter(|child| child.kind() == "for_in_clause") {
            if let Some(previous) = previous {
                children.insert(clause.id(), previous);
            }
            let site = p.site(clause, scope, ResolutionSiteKind::UnsupportedExpression);
            let id = dense_ordinal(
                p.facts.python_guards.len(),
                "comprehension iteration guards",
            );
            p.facts.python_guards.push(PythonNativeGuardFact {
                id,
                parent: previous,
                site,
                execution_scope: scope,
                kind: PythonNativeGuardKind::LoopBody,
                arm_ordinal: 0,
                predicate: None,
            });
            assert!(p.iteration_guards.insert(clause.id(), id).is_none());
            previous = Some(id);
        }
        if let (Some(body), Some(last)) = (node.child_by_field_name("body"), previous) {
            children.insert(body.id(), last);
        }
        // Filters after a clause execute after that clause's target binding.
        let mut active = parent;
        for child in named_children_iter(node) {
            if child.kind() == "for_in_clause" {
                active = p.iteration_guards.get(&child.id()).copied();
            } else if child.kind() == "if_clause"
                && let Some(active) = active
            {
                children.insert(child.id(), active);
            }
        }
        return children;
    }
    if node.kind() == "for_in_clause" {
        let guard = *p
            .iteration_guards
            .get(&node.id())
            .expect("comprehension clause guard");
        if let Some(left) = node.child_by_field_name("left") {
            children.insert(left.id(), guard);
        }
        return children;
    }

    if !matches!(
        node.kind(),
        "if_statement"
            | "elif_clause"
            | "try_statement"
            | "for_statement"
            | "while_statement"
            | "with_statement"
            | "case_clause"
    ) {
        return children;
    }
    let site = p.site(node, scope, ResolutionSiteKind::UnsupportedExpression);
    let predicate = node
        .child_by_field_name("condition")
        .or_else(|| node.child_by_field_name("guard"))
        .map(|condition| {
            let site = p.site(condition, scope, ResolutionSiteKind::UnsupportedExpression);
            temporal::predicate(p, condition, site);
            site
        });
    let mut arm = 0;
    let mut alternative_parent = parent;
    for child in named_children_iter(node) {
        let kind = match (node.kind(), child.kind()) {
            ("if_statement" | "elif_clause", _) if is_field_child(node, child, "consequence") => {
                PythonNativeGuardKind::IfTrue
            }
            ("if_statement" | "elif_clause", "elif_clause" | "else_clause") => {
                PythonNativeGuardKind::IfFalse
            }
            ("try_statement", "block") => PythonNativeGuardKind::TryBody,
            ("try_statement", "except_clause" | "except_group_clause") => {
                PythonNativeGuardKind::ExceptArm
            }
            ("try_statement", "else_clause") => PythonNativeGuardKind::TryElse,
            ("try_statement", "finally_clause") => PythonNativeGuardKind::Finally,
            ("for_statement" | "while_statement", "block") => PythonNativeGuardKind::LoopBody,
            ("for_statement" | "while_statement", "else_clause") => PythonNativeGuardKind::LoopElse,
            ("with_statement", "block") => PythonNativeGuardKind::UnknownControl,
            ("case_clause", "block") => PythonNativeGuardKind::MatchArm,
            _ => continue,
        };
        let id = dense_ordinal(p.facts.python_guards.len(), "Python guards");
        let exception = if kind == PythonNativeGuardKind::ExceptArm {
            child
                .child_by_field_name("value")
                .map(|value| p.site(value, scope, ResolutionSiteKind::UnsupportedExpression))
        } else {
            predicate
        };
        p.facts.python_guards.push(PythonNativeGuardFact {
            id,
            parent: alternative_parent,
            site,
            execution_scope: scope,
            kind,
            arm_ordinal: arm,
            predicate: exception,
        });
        children.insert(child.id(), id);
        if kind == PythonNativeGuardKind::LoopBody
            && node.kind() == "for_statement"
            && let Some(left) = node.child_by_field_name("left")
        {
            children.insert(left.id(), id);
        }
        if kind == PythonNativeGuardKind::MatchArm {
            for pattern in named_children_iter(node).filter(|child| {
                matches!(
                    child.kind(),
                    "case_pattern" | "as_pattern" | "union_pattern"
                )
            }) {
                children.insert(pattern.id(), id);
            }
            if let Some(predicate) = node.child_by_field_name("guard") {
                children.insert(predicate.id(), id);
            }
        }
        arm += 1;
        // Each later elif/else also requires the earlier elif predicates to
        // have failed. Preserve that chain without evaluating their bindings.
        if kind == PythonNativeGuardKind::IfFalse && child.kind() == "elif_clause" {
            let false_id = dense_ordinal(p.facts.python_guards.len(), "Python elif guards");
            let condition = child
                .child_by_field_name("condition")
                .map(|value| p.site(value, scope, ResolutionSiteKind::UnsupportedExpression));
            let elif_site = p.site(child, scope, ResolutionSiteKind::UnsupportedExpression);
            p.facts.python_guards.push(PythonNativeGuardFact {
                id: false_id,
                parent: Some(id),
                site: elif_site,
                execution_scope: scope,
                kind: PythonNativeGuardKind::IfFalse,
                arm_ordinal: arm,
                predicate: condition,
            });
            alternative_parent = Some(false_id);
        }
    }
    children
}

pub(super) fn validate(facts: &FileResolutionFacts) {
    for (ordinal, guard) in facts.python_guards.iter().enumerate() {
        assert_eq!(guard.id as usize, ordinal);
        assert!(
            guard
                .parent
                .is_none_or(|parent| (parent as usize) < ordinal)
        );
        assert!(guard.site.index() < facts.sites.len());
        assert!(guard.execution_scope.index() < facts.scopes.len());
        assert!(
            guard
                .predicate
                .is_none_or(|site| site.index() < facts.sites.len())
        );
    }
    let mut sites = HashSet::default();
    for guarded in &facts.python_site_guards {
        assert!(sites.insert(guarded.site));
        assert!(guarded.site.index() < facts.sites.len());
        assert!((guarded.guard as usize) < facts.python_guards.len());
    }
    for import in &facts.python_imports {
        assert_eq!(
            facts.sites[import.import_site.index()].kind,
            ResolutionSiteKind::ImportDeclaration
        );
        let count = facts
            .import_route_segments
            .iter()
            .filter(|segment| segment.import_site == import.import_site)
            .count();
        assert!(import.module_segment_count as usize <= count);
        if let Some(event) = import.binding_event {
            assert_eq!(
                facts.binding_events[event as usize].kind,
                ResolutionBindingEventKind::Import
            );
        } else {
            assert_eq!(import.form, PythonNativeImportForm::Star);
        }
    }
    for (ordinal, operation) in facts.python_export_operations.iter().enumerate() {
        assert_eq!(operation.ordinal as usize, ordinal);
        assert_eq!(
            facts.scopes[operation.module_scope.index()].kind,
            ResolutionScopeKind::CompilationUnit
        );
    }
    for member in &facts.python_export_members {
        assert!((member.operation_ordinal as usize) < facts.python_export_operations.len());
        assert!(member.literal_site.index() < facts.sites.len());
        assert!(member.name.index() < facts.names.len());
    }
}
