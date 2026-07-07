use crate::hash::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TypeDecl {
    pub(crate) fqn: String,
    pub(crate) package: String,
    pub(crate) simple: String,
    pub(crate) normalized_fqn: String,
}

impl TypeDecl {
    pub(crate) fn new(
        package: impl Into<String>,
        simple: impl Into<String>,
        fqn: impl Into<String>,
        normalized_fqn: impl Into<String>,
    ) -> Self {
        Self {
            fqn: fqn.into(),
            package: package.into(),
            simple: simple.into(),
            normalized_fqn: normalized_fqn.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MemberDecl {
    pub(crate) fqn: String,
    pub(crate) normalized_fqn: String,
    pub(crate) owner_fqn: String,
    pub(crate) normalized_owner_fqn: String,
    pub(crate) name: String,
    pub(crate) arity: Option<usize>,
    pub(crate) return_type_fqn: Option<String>,
    pub(crate) is_function: bool,
}

impl MemberDecl {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        fqn: impl Into<String>,
        normalized_fqn: impl Into<String>,
        owner_fqn: impl Into<String>,
        normalized_owner_fqn: impl Into<String>,
        name: impl Into<String>,
        arity: Option<usize>,
        return_type_fqn: Option<String>,
        is_function: bool,
    ) -> Self {
        Self {
            fqn: fqn.into(),
            normalized_fqn: normalized_fqn.into(),
            owner_fqn: owner_fqn.into(),
            normalized_owner_fqn: normalized_owner_fqn.into(),
            name: name.into(),
            arity,
            return_type_fqn,
            is_function,
        }
    }
}

#[derive(Default)]
pub(crate) struct WorkspaceSymbolIndexBuilder {
    types: Vec<TypeDecl>,
    members: Vec<MemberDecl>,
}

impl WorkspaceSymbolIndexBuilder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_type(&mut self, decl: TypeDecl) {
        self.types.push(decl);
    }

    pub(crate) fn add_member(&mut self, decl: MemberDecl) {
        self.members.push(decl);
    }

    pub(crate) fn build(self) -> WorkspaceSymbolIndex {
        WorkspaceSymbolIndex::from_declarations(self.types, self.members)
    }
}

pub(crate) struct WorkspaceSymbolIndex {
    members: Vec<MemberDecl>,
    types_by_fqn: HashMap<String, TypeDecl>,
    types_by_normalized_fqn: HashMap<String, TypeDecl>,
    types_by_package_simple: HashMap<(String, String), TypeDecl>,
    members_by_normalized_fqn: HashMap<String, MemberDecl>,
    members_by_owner_name: HashMap<(String, String), Vec<MemberDecl>>,
    members_by_normalized_owner_name: HashMap<(String, String), Vec<MemberDecl>>,
    callable_return_types: HashMap<String, Option<String>>,
}

impl WorkspaceSymbolIndex {
    pub(crate) fn from_declarations(types: Vec<TypeDecl>, members: Vec<MemberDecl>) -> Self {
        let mut types_by_fqn = HashMap::default();
        let mut types_by_normalized_fqn = HashMap::default();
        let mut types_by_package_simple = HashMap::default();
        for decl in types {
            insert_package_type(&mut types_by_package_simple, decl.clone());
            types_by_normalized_fqn.insert(decl.normalized_fqn.clone(), decl.clone());
            types_by_fqn.insert(decl.fqn.clone(), decl);
        }

        let mut all_members = Vec::new();
        let mut members_by_normalized_fqn = HashMap::default();
        let mut members_by_owner_name: HashMap<(String, String), Vec<MemberDecl>> =
            HashMap::default();
        let mut members_by_normalized_owner_name: HashMap<(String, String), Vec<MemberDecl>> =
            HashMap::default();
        let mut callable_return_types = HashMap::default();
        for decl in members {
            if let Some(return_type_fqn) = &decl.return_type_fqn {
                insert_callable_return_type(
                    &mut callable_return_types,
                    decl.fqn.clone(),
                    return_type_fqn.clone(),
                );
            }
            members_by_owner_name
                .entry((decl.owner_fqn.clone(), decl.name.clone()))
                .or_default()
                .push(decl.clone());
            members_by_normalized_owner_name
                .entry((decl.normalized_owner_fqn.clone(), decl.name.clone()))
                .or_default()
                .push(decl.clone());
            members_by_normalized_fqn.insert(decl.normalized_fqn.clone(), decl.clone());
            all_members.push(decl);
        }

        Self {
            members: all_members,
            types_by_fqn,
            types_by_normalized_fqn,
            types_by_package_simple,
            members_by_normalized_fqn,
            members_by_owner_name,
            members_by_normalized_owner_name,
            callable_return_types,
        }
    }

    pub(crate) fn package_types(&self) -> impl Iterator<Item = (&(String, String), &TypeDecl)> {
        self.types_by_package_simple.iter()
    }

    pub(crate) fn type_by_fqn(&self, fqn: &str) -> Option<&TypeDecl> {
        self.types_by_fqn.get(fqn)
    }

    pub(crate) fn type_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<&TypeDecl> {
        self.types_by_normalized_fqn.get(normalized_fqn)
    }

    pub(crate) fn type_by_package_simple(&self, package: &str, simple: &str) -> Option<&TypeDecl> {
        self.types_by_package_simple
            .get(&(package.to_string(), simple.to_string()))
    }

    pub(crate) fn member_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<&MemberDecl> {
        self.members_by_normalized_fqn.get(normalized_fqn)
    }

    pub(crate) fn members(&self) -> impl Iterator<Item = &MemberDecl> {
        self.members.iter()
    }

    pub(crate) fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> &[MemberDecl] {
        if let Some(members) = self
            .members_by_owner_name
            .get(&(owner_fqn.to_string(), name.to_string()))
        {
            return members;
        }
        self.members_by_normalized_owner_name
            .get(&(normalized_owner_fqn.to_string(), name.to_string()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn callable_return_type(&self, fqn: &str) -> Option<&str> {
        self.callable_return_types
            .get(fqn)
            .and_then(|value| value.as_deref())
    }
}

fn insert_callable_return_type(
    callable_return_types: &mut HashMap<String, Option<String>>,
    fqn: String,
    return_type_fqn: String,
) {
    match callable_return_types.get_mut(&fqn) {
        Some(existing) => {
            if existing
                .as_ref()
                .is_some_and(|value| *value != return_type_fqn)
            {
                *existing = None;
            }
        }
        None => {
            callable_return_types.insert(fqn, Some(return_type_fqn));
        }
    }
}

fn insert_package_type(
    types_by_package_simple: &mut HashMap<(String, String), TypeDecl>,
    decl: TypeDecl,
) {
    let key = (decl.package.clone(), decl.simple.clone());
    let prefer_existing = decl.fqn.ends_with('$')
        && types_by_package_simple
            .get(&key)
            .is_some_and(|existing| !existing.fqn.ends_with('$'));
    if prefer_existing {
        return;
    }
    types_by_package_simple.insert(key, decl);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_types_by_keyed_package_fqn_and_normalized_names() {
        let mut builder = WorkspaceSymbolIndexBuilder::new();
        builder.add_type(TypeDecl::new(
            "example",
            "Service",
            "example.Service",
            "example.Service",
        ));
        builder.add_type(TypeDecl::new(
            "example",
            "Helpers",
            "example.Helpers$",
            "example.Helpers",
        ));
        let index = builder.build();

        assert_eq!(
            index
                .type_by_package_simple("example", "Service")
                .map(|decl| decl.fqn.as_str()),
            Some("example.Service")
        );
        assert_eq!(
            index
                .type_by_fqn("example.Service")
                .map(|decl| decl.fqn.as_str()),
            Some("example.Service")
        );
        assert_eq!(
            index
                .type_by_normalized_fqn("example.Helpers")
                .map(|decl| decl.fqn.as_str()),
            Some("example.Helpers$")
        );
    }

    #[test]
    fn resolves_members_and_callable_return_types_by_keyed_owner_name() {
        let mut builder = WorkspaceSymbolIndexBuilder::new();
        builder.add_member(MemberDecl::new(
            "example.Service.make",
            "example.Service.make",
            "example.Service",
            "example.Service",
            "make",
            Some(1),
            Some("example.Result".to_string()),
            true,
        ));
        let index = builder.build();

        let members = index.members_for_owner_name("example.Service", "example.Service", "make");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].fqn, "example.Service.make");
        assert_eq!(
            index.callable_return_type("example.Service.make"),
            Some("example.Result")
        );
    }

    #[test]
    fn ambiguous_callable_return_types_do_not_pick_one() {
        let mut builder = WorkspaceSymbolIndexBuilder::new();
        builder.add_member(MemberDecl::new(
            "example.Factory.make",
            "example.Factory.make",
            "example.Factory",
            "example.Factory",
            "make",
            Some(1),
            Some("example.Service".to_string()),
            true,
        ));
        builder.add_member(MemberDecl::new(
            "example.Factory.make",
            "example.Factory.make",
            "example.Factory",
            "example.Factory",
            "make",
            Some(1),
            Some("example.Other".to_string()),
            true,
        ));
        let index = builder.build();

        assert_eq!(index.callable_return_type("example.Factory.make"), None);
    }
}
