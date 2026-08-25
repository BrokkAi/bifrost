use brokk_bifrost_core::analyzer::capabilities::ImportReachability;
use brokk_bifrost_core::analyzer::model::{ImportInfo, StructuredImportScope};
use brokk_bifrost_core::analyzer::{CodeUnit, Language};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

use crate::scala::imports::is_scala_importable_direct_member;
use crate::scala::supertypes::scala_type_lookup_segments;
use crate::scala::{scala_nested_type_candidates, scala_normalize_full_name};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScalaWildcardOwnerKind {
    Package,
    StableSingleton,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScalaWildcardOwnerFacts {
    pub package: bool,
    pub stable_singleton: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScalaWildcardImportOwner {
    pub import_index: usize,
    pub fqn: String,
    pub kind: ScalaWildcardOwnerKind,
}

impl ScalaWildcardImportOwner {
    pub fn is_singleton(&self) -> bool {
        self.kind == ScalaWildcardOwnerKind::StableSingleton
    }

    pub fn declaration_fqn(&self) -> String {
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
pub struct ScalaWildcardImportEnvironment {
    pub owners: Vec<ScalaWildcardImportOwner>,
    pub ambiguous: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScalaExplicitImportFacts {
    pub declaration: bool,
    pub package: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalaExplicitImportTier {
    pub candidate: String,
    pub declaration: bool,
    pub package: bool,
}

/// Decide whether one Scala file's structured imports can reach declarations
/// from another file without materializing every imported declaration.
///
/// Candidate discovery needs a conservative file edge, not a resolved binder.
/// It therefore considers every package-relative spelling the ordinary import
/// resolver can select, including spellings shadowed by an earlier tier. That
/// may admit an extra file, but it cannot lose one. Returning `DoesNotReach`
/// is safe because the same candidate and chained-wildcard expansion is a
/// superset of the resolver's paths; malformed legacy facts remain `Unknown`
/// and retain the caller's declaration-expansion backstop.
pub fn scala_import_reachability<'a>(
    imports: &[ImportInfo],
    source_package: &str,
    target_package: &str,
    target_declarations: impl IntoIterator<Item = &'a CodeUnit>,
    mut explicit_candidate_facts: impl FnMut(&str) -> ScalaExplicitImportFacts,
) -> ImportReachability {
    if source_package == target_package {
        return ImportReachability::Reaches;
    }

    let interner = brokk_bifrost_core::analyzer::fq_name::segment_interner();
    let mut target_names = HashSet::default();
    let mut target_owners = HashSet::default();
    for declaration in target_declarations
        .into_iter()
        .filter(|declaration| is_scala_importable_direct_member(declaration))
    {
        target_names.insert(scala_normalize_full_name(&declaration.fq_name()));
        if let Some(parent) = declaration.fq().parent() {
            target_owners.insert(scala_normalize_full_name(
                &parent.display_native(Language::Scala, interner),
            ));
        }
    }
    if target_names.is_empty() && target_owners.is_empty() {
        return ImportReachability::Unknown;
    }

    let mut wildcard_roots: Vec<(usize, String)> = Vec::new();
    for (import_index, import) in imports.iter().enumerate() {
        let Some(path) = import.path.as_ref() else {
            return ImportReachability::Unknown;
        };
        if path.segments.is_empty() {
            return ImportReachability::Unknown;
        }
        let rendered_path = path.segments.join(".");
        let fallback_prefixes = [source_package.to_string()];
        let package_prefixes = if path.lexical_prefixes.is_empty() {
            fallback_prefixes.as_slice()
        } else {
            path.lexical_prefixes.as_slice()
        };
        let mut candidates = scala_import_path_candidates(&rendered_path, package_prefixes);
        if import.is_wildcard {
            let chained = wildcard_roots
                .iter()
                .filter(|(root_index, _)| {
                    same_lexical_import_context(imports, *root_index, import_index)
                })
                .map(|(_, root)| format!("{root}.{rendered_path}"))
                .collect::<Vec<_>>();
            candidates.extend(chained);
            let mut seen = HashSet::default();
            candidates.retain(|candidate| seen.insert(candidate.clone()));
            if candidates.iter().any(|candidate| {
                candidate == target_package
                    || target_owners.contains(&scala_normalize_full_name(candidate))
            }) {
                return ImportReachability::Reaches;
            }
            wildcard_roots.extend(
                candidates
                    .into_iter()
                    .map(|candidate| (import_index, candidate)),
            );
            continue;
        }

        let Some(tier) = resolve_scala_explicit_import_tier(
            &rendered_path,
            package_prefixes,
            &mut explicit_candidate_facts,
        ) else {
            continue;
        };
        let candidate = &tier.candidate;
        let normalized = scala_normalize_full_name(candidate);
        let reaches_target = target_names.contains(&normalized)
            || candidate == target_package
            || target_package
                .strip_prefix(candidate)
                .is_some_and(|suffix| suffix.starts_with('.'));
        if reaches_target {
            return ImportReachability::Reaches;
        }
    }
    ImportReachability::DoesNotReach
}

/// Select the first relative/global candidate tier that denotes either a
/// declaration or a package. Both namespaces are retained when the same
/// candidate denotes both so semantic binders can fail closed while candidate
/// discovery remains conservative.
pub fn resolve_scala_explicit_import_tier(
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
///
/// `enclosing_owner_fq_names` maps an import declaration's start byte to the
/// fqns of its lexically enclosing object/class/trait scopes (innermost
/// first, as produced by `scala::scala_enclosing_template_owner_fq_names`).
/// A relative wildcard base (`import Registry._` nested in a template)
/// resolves against those enclosing scopes before the package, so its
/// owner-qualified spellings are tried first. Callers without analyzer
/// access to compute that chain (e.g. the type-hierarchy-only resolver,
/// which never sees a live `ScalaAnalyzer`) pass `|_| Vec::new()` and keep
/// today's package-only behavior.
pub fn resolve_scala_wildcard_import_environment(
    imports: &[ImportInfo],
    package_prefixes: &[String],
    mut enclosing_owner_fq_names: impl FnMut(usize) -> Vec<String>,
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

        let mut selected = Vec::new();
        if let Some(structured_path) = import.path.as_ref() {
            let owners = enclosing_owner_fq_names(structured_path.declaration_start_byte);
            'owner: for owner in &owners {
                let owner_candidates = scala_nested_type_candidates(
                    owner.trim_end_matches('$').to_string(),
                    &structured_path.segments,
                    true,
                );
                for candidate in owner_candidates {
                    selected = owners_for_candidate(import_index, candidate, &mut owner_facts);
                    if !selected.is_empty() {
                        break 'owner;
                    }
                }
            }
        }

        if selected.is_empty() {
            let import_prefixes = import
                .path
                .as_ref()
                .map(|path| path.lexical_prefixes.as_slice())
                .filter(|prefixes| !prefixes.is_empty())
                .unwrap_or(package_prefixes);
            'candidate: for candidate in scala_import_path_candidates(&path, import_prefixes) {
                for spelling in scala_owner_split_spellings(&candidate) {
                    selected = owners_for_candidate(import_index, spelling, &mut owner_facts);
                    if !selected.is_empty() {
                        break 'candidate;
                    }
                }
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

pub fn scala_import_visible_at(
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

/// Every way one flat dotted candidate may split into a package prefix and a
/// chain of nested singleton objects, longest package first.
///
/// A Scala object's indexed fq name carries a `$` on each object segment, so
/// `object Envelope { object Payloads { ... } }` in `package fx` is indexed
/// under `fx.Envelope$.Payloads$`. `import fx.Envelope.Payloads._` spells that
/// owner flat, and the flat spelling matches nothing. The terminal segment is
/// left bare here because [`owners_for_candidate`] decides the terminal
/// namespace itself: `ScalaWildcardOwnerFacts::package` tests the bare
/// spelling and `stable_singleton` appends the terminal `$`.
fn scala_owner_split_spellings(candidate: &str) -> Vec<String> {
    let segments = candidate.split('.').collect::<Vec<_>>();
    // With one segment there is no interior boundary to decorate, and the
    // flat spelling below is the only spelling.
    (0..segments.len())
        .rev()
        .map(|package_len| {
            let mut spelling = String::with_capacity(candidate.len() + segments.len());
            for (index, segment) in segments.iter().enumerate() {
                if index > 0 {
                    spelling.push('.');
                }
                spelling.push_str(segment);
                if index >= package_len && index + 1 < segments.len() {
                    spelling.push('$');
                }
            }
            spelling
        })
        .collect()
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

/// The fully qualified paths an import path may denote from an active Scala
/// package context.
///
/// `package a.b.c` nests the compilation unit in `a`, `a.b` and `a.b.c`, so a
/// relative import resolves against every enclosing package and not only the
/// complete clause: `import syntax.equal._` written under `package a.b` names
/// `a.syntax.equal` just as readily as `a.b.syntax.equal` (#2082). This is the
/// same rule [`scala_enclosing_package_root_candidates`] applies to a
/// qualified root, so both read it from one place.
pub fn scala_import_path_candidates(path: &str, package_prefixes: &[String]) -> Vec<String> {
    scala_enclosing_package_root_candidates(package_prefixes, path)
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
pub fn scala_enclosing_package_root_candidates(
    package_prefixes: &[String],
    root: &str,
) -> Vec<String> {
    let mut candidates = Vec::new();
    for package in package_prefixes.iter().rev() {
        let mut enclosing = package.as_str();
        loop {
            // A path that already spells the enclosing package is absolute
            // here; qualifying it again would only invent `a.b.a.b.C`.
            if !enclosing.is_empty() && !root.starts_with(&format!("{enclosing}.")) {
                candidates.push(format!("{enclosing}.{root}"));
            }
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

pub fn scala_import_path(info: &ImportInfo) -> Option<String> {
    info.path
        .as_ref()
        .filter(|path| !path.segments.is_empty())
        .map(|path| path.segments.join("."))
}

pub fn scala_package_prefixes_at(
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
) -> Vec<String> {
    scala_package_prefixes_at_impl(root, source, reference_byte, None)
        .expect("unbounded Scala package traversal cannot stop")
}

pub fn scala_package_prefixes_at_checked(
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    inspect: &mut dyn FnMut(Node<'_>) -> bool,
) -> Option<Vec<String>> {
    scala_package_prefixes_at_impl(root, source, reference_byte, Some(inspect))
}

fn scala_package_prefixes_at_impl(
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    mut inspect: Option<&mut dyn FnMut(Node<'_>) -> bool>,
) -> Option<Vec<String>> {
    let mut prefixes = Vec::new();
    let mut segments = Vec::new();
    let mut container = root;
    loop {
        if !inspect_node(&mut inspect, container) {
            return None;
        }
        let mut nested_body = None;
        let mut cursor = container.walk();
        for child in container.named_children(&mut cursor) {
            if !inspect_node(&mut inspect, child) {
                return None;
            }
            if child.start_byte() > reference_byte {
                break;
            }
            // `package object p` declares its members in package `p`, exactly
            // as a `package p` clause does (#2082). Its body is therefore a
            // package scope, and a reference inside it sees the package the
            // package object completes.
            if !matches!(child.kind(), "package_clause" | "package_object") {
                continue;
            }
            let Some(name) = child.child_by_field_name("name") else {
                continue;
            };
            if !inspect_named_subtree(&mut inspect, name) {
                return None;
            }
            let clause_segments = scala_type_lookup_segments(name, source);
            if clause_segments.is_empty() {
                continue;
            }
            if let Some(body) = child.child_by_field_name("body") {
                if body.start_byte() <= reference_byte && reference_byte < body.end_byte() {
                    segments.extend(clause_segments);
                    prefixes.push(segments.join("."));
                    // A package object's body is the innermost package scope:
                    // no further package clause can open inside it.
                    nested_body = (child.kind() == "package_clause").then_some(body);
                    break;
                }
                continue;
            }
            if child.kind() == "package_clause" {
                segments.extend(clause_segments);
                prefixes.push(segments.join("."));
            }
        }
        let Some(body) = nested_body else {
            break;
        };
        container = body;
    }
    Some(prefixes)
}

fn inspect_named_subtree(
    inspect: &mut Option<&mut dyn FnMut(Node<'_>) -> bool>,
    root: Node<'_>,
) -> bool {
    if inspect.is_none() {
        return true;
    }
    if !inspect_node(inspect, root) {
        return false;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !inspect_node(inspect, child) {
                return false;
            }
            stack.push(child);
        }
    }
    true
}

fn inspect_node(inspect: &mut Option<&mut dyn FnMut(Node<'_>) -> bool>, node: Node<'_>) -> bool {
    inspect.as_mut().is_none_or(|inspect| inspect(node))
}
