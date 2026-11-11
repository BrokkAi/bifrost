use super::ir::{CodeQuerySeed, Pattern};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};

impl CodeQuerySeed {
    pub fn referenced_kinds(&self) -> Vec<NormalizedKind> {
        let mut kinds = Vec::new();
        self.walk_patterns(|pattern, _, _| {
            kinds.extend(pattern.kinds.iter().copied());
            kinds.extend(pattern.not_kinds.iter().copied());
        });
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    }

    pub fn used_roles(&self) -> Vec<Role> {
        let mut roles = Vec::new();
        self.walk_patterns(|_, role, _| {
            if let Some(role) = role {
                roles.push(role);
            }
        });
        roles.sort_unstable();
        roles.dedup();
        roles
    }

    pub(crate) fn walk_patterns(
        &self,
        mut visit: impl FnMut(&Pattern, Option<Role>, &[NormalizedKind]),
    ) {
        for root in [
            Some(&self.root),
            self.inside.as_ref(),
            self.inside_decl.as_ref(),
            self.not_inside.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            walk_patterns(root, &mut visit);
        }
    }
}

fn walk_patterns(
    pattern: &Pattern,
    visit: &mut impl FnMut(&Pattern, Option<Role>, &[NormalizedKind]),
) {
    let mut pending = vec![(pattern, None, Vec::new())];
    while let Some((pattern, role, inherited_kinds)) = pending.pop() {
        let effective_kinds = if pattern.kinds.is_empty() {
            &inherited_kinds
        } else {
            &pattern.kinds
        };
        visit(pattern, role, effective_kinds);
        pending.extend(
            pattern
                .not
                .iter()
                .map(|child| (child.as_ref(), None, effective_kinds.clone())),
        );
        pending.extend(
            pattern
                .all
                .iter()
                .map(|child| (child, None, effective_kinds.clone())),
        );
        pending.extend(
            pattern
                .any
                .iter()
                .map(|child| (child, None, effective_kinds.clone())),
        );
        if let Some(child) = &pattern.has {
            pending.push((child, None, Vec::new()));
        }
        if let Some(child) = &pattern.each {
            pending.push((child, None, Vec::new()));
        }
        if let Some(child) = &pattern.not_has {
            pending.push((child, None, Vec::new()));
        }
        if let Some(child) = &pattern.local_value {
            pending.push((child, None, Vec::new()));
        }
        if let Some(count) = &pattern.count {
            visit(pattern, Some(count.role), effective_kinds);
            pending.push((&count.pattern, None, Vec::new()));
        }
        for &role in Role::single_target_roles() {
            if let Some(child) = pattern.single_role_pattern(role) {
                pending.push((child, Some(role), Vec::new()));
            }
        }
        for &role in Role::list_target_roles() {
            for child in pattern.list_role_patterns(role) {
                pending.push((child, Some(role), Vec::new()));
            }
        }
        for (_, child) in &pattern.kwargs {
            pending.push((child, Some(Role::Kwarg), Vec::new()));
        }
    }
}
