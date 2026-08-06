use crate::analyzer::CodeUnit;
use crate::hash::HashSet;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TypeRelationKind {
    NominalInheritance,
    StructuralSatisfaction,
    Embedding,
    TraitImplementation,
    MixinInclude,
    MixinPrepend,
    MixinExtend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeRelation {
    pub from: CodeUnit,
    pub to: CodeUnit,
    pub kind: TypeRelationKind,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MethodKey {
    pub name: String,
    pub signature: Option<String>,
}

impl MethodKey {
    pub fn new(name: impl Into<String>, signature: Option<String>) -> Self {
        Self {
            name: name.into(),
            signature,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MethodSet {
    pub methods: HashSet<MethodKey>,
}

impl MethodSet {
    pub fn new(_owner: CodeUnit) -> Self {
        Self {
            methods: HashSet::default(),
        }
    }

    pub fn insert(&mut self, method: MethodKey) {
        self.methods.insert(method);
    }

    pub fn satisfies_with(
        &self,
        required: &MethodSet,
        mut compatible: impl FnMut(&MethodKey, &MethodKey) -> bool,
    ) -> bool {
        required.methods.iter().all(|required_method| {
            self.methods
                .iter()
                .any(|candidate| compatible(candidate, required_method))
        })
    }

    pub fn extend(&mut self, other: &MethodSet) {
        self.methods.extend(other.methods.iter().cloned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::model::{CodeUnitType, ProjectFile};

    fn unit(name: &str) -> CodeUnit {
        CodeUnit::new(
            ProjectFile::new(
                std::env::temp_dir().join("bifrost-type-relations-test"),
                "main.go",
            ),
            CodeUnitType::Class,
            "example.com/app".to_string(),
            name.to_string(),
        )
    }

    #[test]
    fn method_set_satisfaction_requires_all_required_methods() {
        let mut concrete = MethodSet::new(unit("Worker"));
        concrete.insert(MethodKey::new(
            "Run",
            Some("(ctx Context) error".to_string()),
        ));
        concrete.insert(MethodKey::new("Stop", Some("()".to_string())));

        let mut required = MethodSet::new(unit("Runner"));
        required.insert(MethodKey::new(
            "Run",
            Some("(ctx Context) error".to_string()),
        ));

        assert!(concrete.satisfies_with(&required, |candidate, required| candidate == required));

        required.insert(MethodKey::new("Missing", Some("()".to_string())));
        assert!(!concrete.satisfies_with(&required, |candidate, required| candidate == required));
    }

    #[test]
    fn method_key_keeps_signature_opaque_for_language_specific_compatibility() {
        assert_ne!(
            MethodKey::new("Run", Some("(ctx   Context)   error".to_string())),
            MethodKey::new("Run", Some("(ctx Context) error".to_string()))
        );
        assert_ne!(
            MethodKey::new("Run", Some("(ctx Context) error".to_string())),
            MethodKey::new("Run", Some("() error".to_string()))
        );
    }
}
