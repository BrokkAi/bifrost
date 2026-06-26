use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;

#[derive(Debug, Clone, Default)]
pub struct DefinitionLookupIndex {
    by_fqn: HashMap<String, Vec<CodeUnit>>,
    direct_children_by_fqn: HashMap<String, Vec<CodeUnit>>,
    by_file_identifier: HashMap<(ProjectFile, String), Vec<CodeUnit>>,
    packages: HashSet<String>,
    normalized_fqns: HashSet<String>,
}

impl DefinitionLookupIndex {
    pub(crate) fn from_declarations<'a>(
        declarations: impl IntoIterator<Item = &'a CodeUnit>,
    ) -> Self {
        let mut index = Self::default();
        for unit in declarations {
            index.insert(unit);
        }
        index.sort_entries();
        index
    }

    pub(crate) fn insert(&mut self, unit: &CodeUnit) {
        let fqn = unit.fq_name();
        self.packages.insert(unit.package_name().to_string());
        self.normalized_fqns
            .insert(fqn.replace("$.", ".").trim_end_matches('$').to_string());
        if let Some((parent_fqn, _)) = fqn.rsplit_once('.') {
            self.direct_children_by_fqn
                .entry(parent_fqn.to_string())
                .or_default()
                .push(unit.clone());
        }
        self.by_fqn.entry(fqn).or_default().push(unit.clone());
        self.by_file_identifier
            .entry((unit.source().clone(), unit.identifier().to_string()))
            .or_default()
            .push(unit.clone());
    }

    pub(crate) fn sort_entries(&mut self) {
        for units in self.by_fqn.values_mut() {
            sort_units(units);
        }
        for units in self.by_file_identifier.values_mut() {
            sort_units(units);
        }
        for units in self.direct_children_by_fqn.values_mut() {
            sort_units(units);
            units.dedup();
        }
    }

    pub(crate) fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.by_fqn.get(fqn).cloned().unwrap_or_default()
    }

    pub(crate) fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        self.direct_children_by_fqn
            .get(fqn)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.by_file_identifier
            .get(&(file.clone(), ident.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn fqn_exists(&self, fqn: &str) -> bool {
        self.by_fqn.contains_key(fqn)
    }

    pub(crate) fn normalized_fqn_exists(&self, fqn: &str) -> bool {
        self.normalized_fqns.contains(fqn)
    }

    pub(crate) fn package_exists(&self, package: &str) -> bool {
        self.packages.contains(package)
    }

    pub(crate) fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        let prefix = format!("{prefix}.");
        self.by_fqn.keys().any(|fqn| fqn.starts_with(&prefix))
    }

    pub(crate) fn file_identifier_in_files(
        &self,
        files: &[ProjectFile],
        ident: &str,
    ) -> Vec<CodeUnit> {
        let mut out = Vec::new();
        for file in files {
            out.extend(self.file_identifier(file, ident));
        }
        sort_units(&mut out);
        out.dedup();
        out
    }

    pub(crate) fn fqn_candidates(&self, fqns: impl IntoIterator<Item = String>) -> Vec<CodeUnit> {
        let mut out = Vec::new();
        for fqn in fqns {
            out.extend(self.fqn(&fqn));
        }
        sort_units(&mut out);
        out.dedup();
        out
    }
}

fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        rel_path_string(left.source())
            .cmp(&rel_path_string(right.source()))
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
            .then_with(|| left.signature().cmp(&right.signature()))
    });
}
