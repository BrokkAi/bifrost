use super::ir::{CodeQuerySeed, Pattern};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};

impl CodeQuerySeed {
    pub fn referenced_kinds(&self) -> Vec<NormalizedKind> {
        let mut kinds = Vec::new();
        collect_referenced_kinds(&self.root, &mut kinds);
        if let Some(pattern) = &self.inside {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        if let Some(pattern) = &self.inside_decl {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        if let Some(pattern) = &self.not_inside {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    }

    pub fn used_roles(&self) -> Vec<Role> {
        let mut roles = Vec::new();
        collect_used_roles(&self.root, &mut roles);
        if let Some(pattern) = &self.inside {
            collect_used_roles(pattern, &mut roles);
        }
        if let Some(pattern) = &self.inside_decl {
            collect_used_roles(pattern, &mut roles);
        }
        if let Some(pattern) = &self.not_inside {
            collect_used_roles(pattern, &mut roles);
        }
        roles.sort_unstable();
        roles.dedup();
        roles
    }
}

fn collect_referenced_kinds(pattern: &Pattern, out: &mut Vec<NormalizedKind>) {
    walk_patterns(pattern, |pattern, _| {
        out.extend(pattern.kinds.iter().copied());
        out.extend(pattern.not_kinds.iter().copied());
    });
}

fn collect_used_roles(pattern: &Pattern, out: &mut Vec<Role>) {
    walk_patterns(pattern, |_, role| {
        if let Some(role) = role {
            out.push(role);
        }
    });
}

fn walk_patterns(pattern: &Pattern, mut visit: impl FnMut(&Pattern, Option<Role>)) {
    let mut pending = vec![(pattern, None)];
    while let Some((pattern, role)) = pending.pop() {
        visit(pattern, role);
        if let Some(child) = &pattern.has {
            pending.push((child, None));
        }
        if let Some(child) = &pattern.not_has {
            pending.push((child, None));
        }
        if let Some(child) = &pattern.local_value {
            pending.push((child, None));
        }
        for &role in Role::single_target_roles() {
            if let Some(child) = pattern.single_role_pattern(role) {
                pending.push((child, Some(role)));
            }
        }
        for &role in Role::list_target_roles() {
            for child in pattern.list_role_patterns(role) {
                pending.push((child, Some(role)));
            }
        }
        for (_, child) in &pattern.kwargs {
            pending.push((child, Some(Role::Kwarg)));
        }
    }
}
