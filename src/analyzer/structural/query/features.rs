use super::ir::{AstQuery, Pattern};
use crate::analyzer::structural::kinds::{NormalizedKind, Role};

impl AstQuery {
    pub(crate) fn referenced_kinds(&self) -> Vec<NormalizedKind> {
        let mut kinds = Vec::new();
        collect_referenced_kinds(&self.root, &mut kinds);
        if let Some(pattern) = &self.inside {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        if let Some(pattern) = &self.not_inside {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    }

    pub(crate) fn used_roles(&self) -> Vec<Role> {
        let mut roles = Vec::new();
        collect_used_roles(&self.root, &mut roles);
        if let Some(pattern) = &self.inside {
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
    out.extend(pattern.kinds.iter().copied());
    out.extend(pattern.not_kinds.iter().copied());
    if let Some(pattern) = &pattern.has {
        collect_referenced_kinds(pattern, out);
    }
    if let Some(pattern) = &pattern.not_has {
        collect_referenced_kinds(pattern, out);
    }
    for &role in Role::single_target_roles() {
        if let Some(pattern) = pattern.single_role_pattern(role) {
            collect_referenced_kinds(pattern, out);
        }
    }
    for &role in Role::list_target_roles() {
        for pattern in pattern.list_role_patterns(role) {
            collect_referenced_kinds(pattern, out);
        }
    }
    for (_, pattern) in &pattern.kwargs {
        collect_referenced_kinds(pattern, out);
    }
}

fn collect_used_roles(pattern: &Pattern, out: &mut Vec<Role>) {
    if let Some(pattern) = &pattern.has {
        collect_used_roles(pattern, out);
    }
    if let Some(pattern) = &pattern.not_has {
        collect_used_roles(pattern, out);
    }
    for &role in Role::single_target_roles() {
        if let Some(pattern) = pattern.single_role_pattern(role) {
            out.push(role);
            collect_used_roles(pattern, out);
        }
    }
    for &role in Role::list_target_roles() {
        for pattern in pattern.list_role_patterns(role) {
            out.push(role);
            collect_used_roles(pattern, out);
        }
    }
    for (_, pattern) in &pattern.kwargs {
        out.push(Role::Kwarg);
        collect_used_roles(pattern, out);
    }
}
