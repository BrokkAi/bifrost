use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;

#[derive(Debug, Clone, Default)]
pub struct DefinitionLookupIndex {
    by_fqn: HashMap<String, Vec<CodeUnit>>,
    direct_children_by_fqn: HashMap<String, Vec<CodeUnit>>,
    direct_children_by_normalized_fqn: HashMap<String, Vec<CodeUnit>>,
    by_file_identifier: HashMap<(ProjectFile, String), Vec<CodeUnit>>,
    packages: HashSet<String>,
    files_by_package: HashMap<String, Vec<ProjectFile>>,
    by_normalized_fqn: HashMap<String, Vec<CodeUnit>>,
    types_by_package_simple: HashMap<(String, String), Vec<CodeUnit>>,
}

impl DefinitionLookupIndex {
    pub(crate) fn from_declarations<'a, N, S>(
        declarations: impl IntoIterator<Item = &'a CodeUnit>,
        normalize: N,
        simple_type_name: S,
    ) -> Self
    where
        N: Fn(&str) -> String,
        S: Fn(&CodeUnit) -> String,
    {
        let mut index = Self::default();
        for unit in declarations {
            index.insert(unit, &normalize, &simple_type_name);
        }
        index.sort_entries();
        index
    }

    pub(crate) fn insert<N, S>(&mut self, unit: &CodeUnit, normalize: &N, simple_type_name: &S)
    where
        N: Fn(&str) -> String,
        S: Fn(&CodeUnit) -> String,
    {
        let fqn = unit.fq_name();
        let normalized_fqn = normalize(&fqn);
        self.packages.insert(unit.package_name().to_string());
        self.files_by_package
            .entry(unit.package_name().to_string())
            .or_default()
            .push(unit.source().clone());
        self.by_normalized_fqn
            .entry(normalized_fqn.clone())
            .or_default()
            .push(unit.clone());
        if unit.is_class() {
            self.types_by_package_simple
                .entry((unit.package_name().to_string(), simple_type_name(unit)))
                .or_default()
                .push(unit.clone());
        }
        if let Some((parent_fqn, _)) = fqn.rsplit_once('.') {
            self.direct_children_by_fqn
                .entry(parent_fqn.to_string())
                .or_default()
                .push(unit.clone());
            self.direct_children_by_normalized_fqn
                .entry(normalize(parent_fqn))
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
        for units in self.by_normalized_fqn.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for units in self.types_by_package_simple.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for units in self.direct_children_by_fqn.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for units in self.direct_children_by_normalized_fqn.values_mut() {
            sort_units(units);
            units.dedup();
        }
        for files in self.files_by_package.values_mut() {
            files.sort_by_key(rel_path_string);
            files.dedup();
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
        self.by_normalized_fqn.contains_key(fqn)
    }

    pub(crate) fn by_normalized_fqn(&self, normalized: &str) -> &[CodeUnit] {
        self.by_normalized_fqn
            .get(normalized)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn types_in_package(&self, package: &str, simple: &str) -> &[CodeUnit] {
        self.types_by_package_simple
            .get(&(package.to_string(), simple.to_string()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn package_types(&self) -> impl Iterator<Item = (&(String, String), &[CodeUnit])> {
        self.types_by_package_simple
            .iter()
            .map(|(key, units)| (key, units.as_slice()))
    }

    pub(crate) fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<&CodeUnit> {
        let exact = self
            .direct_children_by_fqn
            .get(owner_fqn)
            .into_iter()
            .flat_map(|units| units.iter())
            .filter(|unit| unit.identifier() == name)
            .collect::<Vec<_>>();
        if !exact.is_empty() {
            return exact;
        }
        self.direct_children_by_normalized_fqn
            .get(normalized_owner_fqn)
            .into_iter()
            .flat_map(|units| units.iter())
            .filter(|unit| unit.identifier() == name)
            .collect()
    }

    pub(crate) fn package_exists(&self, package: &str) -> bool {
        self.packages.contains(package)
    }

    /// Files belonging to the package `prefix` exactly, or to any package nested
    /// under `prefix/` (slash-separated, mirroring the recursion of a filesystem
    /// directory target). Lets an import path such as
    /// `github.com/cli/cli/v2/internal/skills/discovery` resolve to its package's
    /// files. Returns sorted, deduped files.
    pub(crate) fn package_files_with_prefix(&self, prefix: &str) -> Vec<ProjectFile> {
        let nested = format!("{prefix}/");
        let mut out = Vec::new();
        for (package, files) in &self.files_by_package {
            if package == prefix || package.starts_with(&nested) {
                out.extend(files.iter().cloned());
            }
        }
        out.sort_by_key(rel_path_string);
        out.dedup();
        out
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitType;
    use std::path::Path;

    fn unit(root: &Path, file: &str, package: &str, name: &str) -> CodeUnit {
        CodeUnit::new(
            ProjectFile::new(root, file),
            CodeUnitType::Class,
            package.to_string(),
            name.to_string(),
        )
    }

    #[test]
    fn package_files_with_prefix_matches_exact_and_nested_packages() {
        let root = std::env::temp_dir().join("bifrost-defindex-test");
        let units = vec![
            unit(
                &root,
                "internal/skills/discovery/a.go",
                "github.com/cli/cli/v2/internal/skills/discovery",
                "Foo",
            ),
            unit(
                &root,
                "internal/skills/discovery/b.go",
                "github.com/cli/cli/v2/internal/skills/discovery",
                "Bar",
            ),
            unit(
                &root,
                "internal/skills/registry/c.go",
                "github.com/cli/cli/v2/internal/skills/registry",
                "Baz",
            ),
            unit(
                &root,
                "internal/other/d.go",
                "github.com/cli/cli/v2/internal/other",
                "Qux",
            ),
        ];
        let index = DefinitionLookupIndex::from_declarations(&units, str::to_string, |unit| {
            unit.identifier().to_string()
        });

        // Exact package match returns only that package's files, deduped.
        let exact =
            index.package_files_with_prefix("github.com/cli/cli/v2/internal/skills/discovery");
        let exact_paths: Vec<_> = exact.iter().map(rel_path_string).collect();
        assert_eq!(
            exact_paths,
            vec![
                "internal/skills/discovery/a.go".to_string(),
                "internal/skills/discovery/b.go".to_string(),
            ]
        );

        // Parent prefix recurses into nested packages (discovery + registry), not `other`.
        let nested = index.package_files_with_prefix("github.com/cli/cli/v2/internal/skills");
        let nested_paths: Vec<_> = nested.iter().map(rel_path_string).collect();
        assert_eq!(
            nested_paths,
            vec![
                "internal/skills/discovery/a.go".to_string(),
                "internal/skills/discovery/b.go".to_string(),
                "internal/skills/registry/c.go".to_string(),
            ]
        );

        // A non-package string resolves to nothing.
        assert!(index.package_files_with_prefix("does/not/exist").is_empty());
    }

    #[test]
    fn resolves_types_by_package_and_normalized_fqn() {
        let root = std::env::temp_dir().join("bifrost-defindex-normalized-test");
        let units = vec![
            unit(&root, "src/Foo.scala", "example", "Foo"),
            unit(&root, "src/Helpers.scala", "example", "Helpers$"),
        ];
        let index = DefinitionLookupIndex::from_declarations(
            &units,
            |fqn| fqn.replace("$.", ".").trim_end_matches('$').to_string(),
            |unit| unit.identifier().trim_end_matches('$').to_string(),
        );

        assert_eq!(
            index.types_in_package("example", "Foo")[0].fq_name(),
            "example.Foo"
        );
        assert_eq!(
            index.types_in_package("example", "Helpers")[0].fq_name(),
            "example.Helpers$"
        );
        assert_eq!(
            index.by_normalized_fqn("example.Helpers")[0].fq_name(),
            "example.Helpers$"
        );
        assert!(index.normalized_fqn_exists("example.Helpers"));
    }

    #[test]
    fn resolves_members_by_exact_owner_then_normalized_owner() {
        let root = std::env::temp_dir().join("bifrost-defindex-members-test");
        let units = vec![
            CodeUnit::new(
                ProjectFile::new(&root, "src/Foo.scala"),
                CodeUnitType::Function,
                "example".to_string(),
                "Foo.run".to_string(),
            ),
            CodeUnit::new(
                ProjectFile::new(&root, "src/Helpers.scala"),
                CodeUnitType::Function,
                "example".to_string(),
                "Helpers$.run".to_string(),
            ),
        ];
        let index = DefinitionLookupIndex::from_declarations(
            &units,
            |fqn| fqn.replace("$.", ".").trim_end_matches('$').to_string(),
            |unit| unit.identifier().trim_end_matches('$').to_string(),
        );

        let exact = index.members_for_owner_name("example.Foo", "example.Foo", "run");
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].fq_name(), "example.Foo.run");

        let normalized = index.members_for_owner_name("example.Helpers", "example.Helpers", "run");
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].fq_name(), "example.Helpers$.run");
    }
}
