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
