use crate::analyzer::{ImportInfo, StructuredImportScope};
use crate::hash::HashSet;
use tree_sitter::Node;

use super::scala_type_lookup_segments;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ScalaWildcardOwnerKind {
    Package,
    StableSingleton,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScalaWildcardOwnerFacts {
    pub(crate) package: bool,
    pub(crate) stable_singleton: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ScalaWildcardImportOwner {
    pub(crate) import_index: usize,
    pub(crate) fqn: String,
    pub(crate) kind: ScalaWildcardOwnerKind,
}

impl ScalaWildcardImportOwner {
    pub(crate) fn is_singleton(&self) -> bool {
        self.kind == ScalaWildcardOwnerKind::StableSingleton
    }

    pub(crate) fn declaration_fqn(&self) -> String {
        match self.kind {
            ScalaWildcardOwnerKind::Package => self.fqn.clone(),
            ScalaWildcardOwnerKind::StableSingleton => format!("{}$", self.fqn),
        }
    }
}

/// Ordered interpretation of the wildcard imports visible at one Scala site.
///
/// `owners` includes the possible owners at the first ambiguous import. This
/// lets candidate discovery conservatively retain every source file, while a
/// name binder can reject the environment when `ambiguous` is true.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ScalaWildcardImportEnvironment {
    pub(crate) owners: Vec<ScalaWildcardImportOwner>,
    pub(crate) ambiguous: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScalaExplicitImportFacts {
    pub(crate) declaration: bool,
    pub(crate) package: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScalaExplicitImportTier {
    pub(crate) candidate: String,
    pub(crate) declaration: bool,
    pub(crate) package: bool,
}

/// Select the first relative/global candidate tier that denotes either a
/// declaration or a package. Both namespaces are retained when the same
/// candidate denotes both so semantic binders can fail closed while candidate
/// discovery remains conservative.
pub(crate) fn resolve_scala_explicit_import_tier(
    path: &str,
    package_prefixes: &[String],
    mut facts: impl FnMut(&str) -> ScalaExplicitImportFacts,
) -> Option<ScalaExplicitImportTier> {
    for candidate in scala_import_path_candidates(path, package_prefixes) {
        let facts = facts(&candidate);
        if facts.declaration || facts.package {
            return Some(ScalaExplicitImportTier {
                candidate,
                declaration: facts.declaration,
                package: facts.package,
            });
        }
    }
    None
}

/// Resolve wildcard owners in source order. A later relative owner may be
/// exposed by an earlier package wildcard (`core.*; Annotations.*`) or stable
/// singleton wildcard. Direct lexical/package paths take precedence over such
/// chained paths. Multiple owners at the selected tier are kept as ambiguity.
pub(crate) fn resolve_scala_wildcard_import_environment(
    imports: &[ImportInfo],
    package_prefixes: &[String],
    mut owner_facts: impl FnMut(&str) -> ScalaWildcardOwnerFacts,
) -> ScalaWildcardImportEnvironment {
    let mut environment = ScalaWildcardImportEnvironment::default();

    for (import_index, import) in imports.iter().enumerate() {
        if !import.is_wildcard {
            continue;
        }
        let Some(path) = scala_import_path(import) else {
            continue;
        };

        let import_prefixes = import
            .path
            .as_ref()
            .map(|path| path.lexical_prefixes.as_slice())
            .filter(|prefixes| !prefixes.is_empty())
            .unwrap_or(package_prefixes);
        let mut selected = Vec::new();
        for candidate in scala_import_path_candidates(&path, import_prefixes) {
            selected = owners_for_candidate(import_index, candidate, &mut owner_facts);
            if !selected.is_empty() {
                break;
            }
        }

        if selected.is_empty() {
            for root in environment.owners.iter().filter(|root| {
                same_lexical_import_context(imports, root.import_index, import_index)
            }) {
                let candidate = match root.kind {
                    ScalaWildcardOwnerKind::Package => format!("{}.{}", root.fqn, path),
                    ScalaWildcardOwnerKind::StableSingleton => {
                        format!("{}$.{}", root.fqn, path)
                    }
                };
                selected.extend(owners_for_candidate(
                    import_index,
                    candidate,
                    &mut owner_facts,
                ));
            }
            selected.sort();
            selected.dedup();
        }

        if selected.len() > 1 {
            environment.owners.extend(selected);
            environment.owners.sort();
            environment.owners.dedup();
            environment.ambiguous = true;
            break;
        }
        if let Some(owner) = selected.pop() {
            environment.owners.push(owner);
        }
    }

    environment
}

fn same_active_lexical_context(import: &[String], active: &[String]) -> bool {
    import == active
        || import
            .last()
            .zip(active.last())
            .is_some_and(|(import, active)| import == active)
}

fn is_visible_lexical_scope(
    import: &[StructuredImportScope],
    active: &[StructuredImportScope],
) -> bool {
    import.len() <= active.len()
        && import
            .iter()
            .zip(active)
            .all(|(import, active)| import == active)
}

pub(crate) fn scala_import_visible_at(
    import: &ImportInfo,
    active_lexical_prefixes: &[String],
    active_lexical_scopes: &[StructuredImportScope],
    reference_byte: usize,
) -> bool {
    let Some(path) = import.path.as_ref() else {
        return true;
    };
    (path.lexical_prefixes.is_empty()
        || same_active_lexical_context(&path.lexical_prefixes, active_lexical_prefixes))
        && is_visible_lexical_scope(&path.lexical_scopes, active_lexical_scopes)
        && path.declaration_start_byte <= reference_byte
}

fn same_lexical_import_context(imports: &[ImportInfo], left: usize, right: usize) -> bool {
    let path = |index: usize| imports.get(index).and_then(|import| import.path.as_ref());
    path(left).map(|path| (&path.lexical_prefixes, &path.lexical_scopes))
        == path(right).map(|path| (&path.lexical_prefixes, &path.lexical_scopes))
}

fn owners_for_candidate(
    import_index: usize,
    candidate: String,
    owner_facts: &mut impl FnMut(&str) -> ScalaWildcardOwnerFacts,
) -> Vec<ScalaWildcardImportOwner> {
    let facts = owner_facts(&candidate);
    let mut owners = Vec::with_capacity(2);
    if facts.package {
        owners.push(ScalaWildcardImportOwner {
            import_index,
            fqn: candidate.clone(),
            kind: ScalaWildcardOwnerKind::Package,
        });
    }
    if facts.stable_singleton {
        owners.push(ScalaWildcardImportOwner {
            import_index,
            fqn: candidate.trim_end_matches('$').to_string(),
            kind: ScalaWildcardOwnerKind::StableSingleton,
        });
    }
    owners
}

pub(crate) fn scala_import_path_candidates(path: &str, package_prefixes: &[String]) -> Vec<String> {
    let mut candidates = Vec::new();
    for prefix in package_prefixes.iter().rev() {
        if prefix.is_empty() || path.starts_with(&format!("{prefix}.")) {
            continue;
        }
        candidates.push(format!("{prefix}.{path}"));
    }
    candidates.push(path.to_string());
    let mut seen = HashSet::default();
    candidates.retain(|candidate| seen.insert(candidate.clone()));
    candidates
}

/// Candidate package namespaces denoted by a qualified root from an active
/// Scala package context.
///
/// A single dotted package clause establishes only its complete package for
/// ordinary unqualified lookup. Qualified paths are different: from
/// `package akka.stream.javadsl`, the root of `javadsl.Flow` may name the
/// direct child `javadsl` of the enclosing `akka.stream` package. Keep these
/// candidates separate from [`scala_package_prefixes_at`] so parent packages
/// do not leak into ordinary lexical lookup.
pub(crate) fn scala_enclosing_package_root_candidates(
    package_prefixes: &[String],
    root: &str,
) -> Vec<String> {
    let mut candidates = Vec::new();
    for package in package_prefixes.iter().rev() {
        let mut enclosing = package.as_str();
        loop {
            let candidate = if enclosing.is_empty() {
                root.to_string()
            } else {
                format!("{enclosing}.{root}")
            };
            candidates.push(candidate);
            let Some((parent, _)) = enclosing.rsplit_once('.') else {
                break;
            };
            enclosing = parent;
        }
    }
    candidates.push(root.to_string());
    let mut seen = HashSet::default();
    candidates.retain(|candidate| seen.insert(candidate.clone()));
    candidates
}

pub(crate) fn scala_import_path(info: &ImportInfo) -> Option<String> {
    info.path
        .as_ref()
        .filter(|path| !path.segments.is_empty())
        .map(|path| path.segments.join("."))
}

pub(crate) fn scala_package_prefixes_at(
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut segments = Vec::new();
    let mut container = root;
    loop {
        let mut nested_body = None;
        let mut cursor = container.walk();
        for child in container.named_children(&mut cursor) {
            if child.start_byte() > reference_byte {
                break;
            }
            if child.kind() != "package_clause" {
                continue;
            }
            let Some(name) = child.child_by_field_name("name") else {
                continue;
            };
            let clause_segments = scala_type_lookup_segments(name, source);
            if clause_segments.is_empty() {
                continue;
            }
            if let Some(body) = child.child_by_field_name("body") {
                if body.start_byte() <= reference_byte && reference_byte < body.end_byte() {
                    segments.extend(clause_segments);
                    prefixes.push(segments.join("."));
                    nested_body = Some(body);
                    break;
                }
                continue;
            }
            segments.extend(clause_segments);
            prefixes.push(segments.join("."));
        }
        let Some(body) = nested_body else {
            break;
        };
        container = body;
    }
    prefixes
}
