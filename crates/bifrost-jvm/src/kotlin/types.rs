//! Kotlin type-name resolution (#1237).
//!
//! Turns a name as *spelled* in Kotlin source (`Base`, `Outer.Inner`,
//! `lib.Base`, an aliased `Parent`) into the fully-qualified name it denotes,
//! then into a workspace declaration or an entry in the shared JVM dependency
//! index.
//!
//! # How Kotlin resolves a name
//!
//! For a dotted name, Kotlin resolves the *first* segment as a name in scope
//! and descends from there; only if that fails is the whole name treated as
//! absolute. This is the one place Kotlin differs sharply from Scala, which
//! also searches enclosing packages — `lib.Base` written inside package `app`
//! never means `app.lib.Base` in Kotlin.
//!
//! A single segment is looked for, in order:
//!
//! 1. the enclosing declarations of the reference site (a class can name its
//!    own nested types without qualification), and the nested types those
//!    declarations inherit;
//! 2. an explicit import, under its alias when it has one;
//! 3. the file's own package;
//! 4. star imports — and if two star imports bind the same simple name to
//!    different owners the reference is *ambiguous*, which Kotlin rejects, so
//!    resolution reports the ambiguity instead of picking a winner;
//! 5. Kotlin's default imports (`kotlin.*`, `java.lang.*`, …).
//!
//! Every tier is a lookup against a caller-supplied "does this fully-qualified
//! name exist" predicate, so the same ladder serves workspace-source
//! resolution, hierarchy resolution, and jar-backed dependency resolution
//! without three copies of the precedence rules.

use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};

use crate::kotlin::graph_support::KotlinSource;
use crate::kotlin::imports::{KOTLIN_DEFAULT_IMPORT_PACKAGES, kotlin_import_path};
use crate::realm::JvmSourceRealm;

/// How many levels of inherited scope a nested-type lookup will walk.
///
/// Inherited nested types are rare and deep chains rarer still; a small cap
/// keeps a cyclic or pathological hierarchy from turning one name lookup into
/// an unbounded traversal.
const MAX_INHERITED_SCOPE_DEPTH: usize = 4;

/// What a spelled Kotlin type name denotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KotlinTypeName {
    /// Exactly one fully-qualified name is in scope for this spelling.
    Resolved(String),
    /// Several star imports bind the spelling to different owners. Kotlin
    /// rejects such a reference, so this is a real answer, not a failure to
    /// look hard enough.
    Ambiguous,
    /// Nothing in scope spells this name.
    Unresolved,
}

impl KotlinTypeName {
    pub fn resolved(self) -> Option<String> {
        match self {
            Self::Resolved(fqn) => Some(fqn),
            Self::Ambiguous | Self::Unresolved => None,
        }
    }
}

/// Everything about a reference site that affects which names it can see.
pub struct KotlinNameScope<'a> {
    /// The package the referencing file declares.
    pub package_name: &'a str,
    /// The file's imports, in source order.
    pub imports: &'a [ImportInfo],
    /// Fully-qualified names of declarations enclosing the reference site plus
    /// any they inherit from, innermost first.
    pub scope_owners: Vec<String>,
}

/// Resolve `name` against `scope`, asking `exists` whether a candidate
/// fully-qualified name is real.
pub fn resolve_kotlin_type_name(
    name: &str,
    scope: &KotlinNameScope<'_>,
    mut exists: impl FnMut(&str) -> bool,
) -> KotlinTypeName {
    let name = name.trim();
    if name.is_empty() {
        return KotlinTypeName::Unresolved;
    }

    let (head, rest) = match name.split_once('.') {
        Some((head, rest)) => (head, Some(rest)),
        None => (name, None),
    };

    match resolve_kotlin_head_segment(head, scope, &mut exists) {
        KotlinTypeName::Ambiguous => return KotlinTypeName::Ambiguous,
        KotlinTypeName::Resolved(head_fqn) => {
            let candidate = match rest {
                Some(rest) => format!("{head_fqn}.{rest}"),
                None => head_fqn,
            };
            if exists(&candidate) {
                return KotlinTypeName::Resolved(candidate);
            }
        }
        KotlinTypeName::Unresolved => {}
    }

    // Nothing in scope claimed the leading segment, so the name can only be
    // absolute.
    if exists(name) {
        return KotlinTypeName::Resolved(name.to_string());
    }
    KotlinTypeName::Unresolved
}

/// Resolve one unqualified segment through Kotlin's visibility tiers.
fn resolve_kotlin_head_segment(
    head: &str,
    scope: &KotlinNameScope<'_>,
    exists: &mut impl FnMut(&str) -> bool,
) -> KotlinTypeName {
    for owner in &scope.scope_owners {
        let candidate = format!("{owner}.{head}");
        if exists(&candidate) {
            return KotlinTypeName::Resolved(candidate);
        }
    }

    for import in scope.imports {
        if import.is_wildcard {
            continue;
        }
        if import.local_name() != Some(head) {
            continue;
        }
        let Some(path) = kotlin_import_path(import) else {
            continue;
        };
        // An explicit import binds the name whether or not the workspace can
        // see the target, so this tier is terminal: falling through to the
        // package tier would resolve a name the import has already claimed.
        return if exists(&path) {
            KotlinTypeName::Resolved(path)
        } else {
            KotlinTypeName::Unresolved
        };
    }

    let same_package = qualify(scope.package_name, head);
    if exists(&same_package) {
        return KotlinTypeName::Resolved(same_package);
    }

    let mut star_match: Option<String> = None;
    for import in scope.imports {
        if !import.is_wildcard {
            continue;
        }
        let Some(path) = kotlin_import_path(import) else {
            continue;
        };
        let candidate = qualify(&path, head);
        if !exists(&candidate) {
            continue;
        }
        match star_match.as_deref() {
            Some(existing) if existing != candidate => return KotlinTypeName::Ambiguous,
            _ => star_match = Some(candidate),
        }
    }
    if let Some(candidate) = star_match {
        return KotlinTypeName::Resolved(candidate);
    }

    for package in KOTLIN_DEFAULT_IMPORT_PACKAGES {
        let candidate = qualify(package, head);
        if exists(&candidate) {
            return KotlinTypeName::Resolved(candidate);
        }
    }

    KotlinTypeName::Unresolved
}

fn qualify(package_name: &str, name: &str) -> String {
    if package_name.is_empty() {
        name.to_string()
    } else {
        format!("{package_name}.{name}")
    }
}

/// A resolved Kotlin type: either a declaration in the workspace or a type
/// known only through the shared JVM dependency realm.
///
/// The external arm carries no payload. The only thing Kotlin's ladder does
/// with it is discard it -- [`resolve_kotlin_type_name_in_file`] answers `None`
/// for a name that is not a workspace declaration, and
/// [`kotlin_type_name_is_known_in_file`] answers `true` for either arm -- and
/// the type it would carry, `JvmExternalType`, is parked in
/// `brokk-bifrost-analysis` with `analyzer/jvm/`. See
/// [`crate::kotlin::graph_support`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KotlinTypeResolution {
    Source(CodeUnit),
    External,
}

/// The workspace declaration a spelled type name denotes, if any.
///
/// Returns `None` for a name that only exists in a dependency jar: external
/// types are not workspace declarations and must never be fabricated as
/// `CodeUnit`s. Use [`kotlin_type_name_is_known_in_file`] to ask the weaker
/// question "does this name exist at all".
pub fn resolve_kotlin_type_name_in_file(
    source: &dyn KotlinSource,
    file: &ProjectFile,
    raw_name: &str,
) -> Option<CodeUnit> {
    match resolve_kotlin_type_name_with_external(source, file, raw_name)? {
        KotlinTypeResolution::Source(unit) => Some(unit),
        KotlinTypeResolution::External => None,
    }
}

/// Whether a spelled type name resolves to anything the analyzer knows: a
/// workspace declaration or a type from the shared JVM dependency realm.
pub fn kotlin_type_name_is_known_in_file(
    source: &dyn KotlinSource,
    file: &ProjectFile,
    raw_name: &str,
) -> bool {
    resolve_kotlin_type_name_with_external(source, file, raw_name).is_some()
}

pub fn resolve_kotlin_type_name_with_external(
    source: &dyn KotlinSource,
    file: &ProjectFile,
    raw_name: &str,
) -> Option<KotlinTypeResolution> {
    resolve_kotlin_type_name_with_external_in_realm(source, file, raw_name, None)
}

pub fn resolve_kotlin_type_name_with_external_in_realm(
    source: &dyn KotlinSource,
    file: &ProjectFile,
    raw_name: &str,
    realm: Option<&JvmSourceRealm<'_>>,
) -> Option<KotlinTypeResolution> {
    let package_name = source.package_name_of(file).unwrap_or_default();
    let imports = source.import_info_of(file);
    let scope = KotlinNameScope {
        package_name: &package_name,
        imports: &imports,
        // A name spelled at file level sees no enclosing declaration.
        scope_owners: Vec::new(),
    };
    resolve_kotlin_type_name_in_scope(source, raw_name, &scope, realm)
}

/// Whether `raw_name`, looked up against a caller-supplied `scope`, is
/// unambiguously unknown to every tier of Kotlin's resolution ladder: the
/// scope's imports, the file's own package, star imports, default imports, the
/// wider JVM source realm (when `realm` is supplied), and the external
/// dependency index.
///
/// Returns `false` for anything the ladder resolves *or* for a genuinely
/// ambiguous star-import collision — [`KotlinTypeName::Ambiguous`] is a real
/// answer (Kotlin itself rejects the reference), not evidence that a
/// declaration is missing, so it must never be reported as unrecognized. This
/// is the tri-state-preserving sibling of [`resolve_kotlin_type_name_in_scope`]:
/// that function folds `Ambiguous` into `None` because a caller just wants
/// "the" resolved unit, but a diagnostic collector must not conflate the two.
pub fn kotlin_type_name_definitely_unresolved_in_realm(
    source: &dyn KotlinSource,
    scope: &KotlinNameScope<'_>,
    raw_name: &str,
    realm: Option<&JvmSourceRealm<'_>>,
) -> bool {
    let source_first = resolve_kotlin_type_name(raw_name, scope, |candidate| {
        kotlin_realm_type_exists(source, candidate, realm)
    });
    if !matches!(source_first, KotlinTypeName::Unresolved) {
        return false;
    }

    if source.external_index_is_empty() {
        return true;
    }
    let access_package = scope.package_name;
    matches!(
        resolve_kotlin_type_name(raw_name, scope, |candidate| {
            source.external_qualified_name_exists(candidate, access_package)
        }),
        KotlinTypeName::Unresolved
    )
}

fn resolve_kotlin_type_name_in_scope(
    source: &dyn KotlinSource,
    raw_name: &str,
    scope: &KotlinNameScope<'_>,
    realm: Option<&JvmSourceRealm<'_>>,
) -> Option<KotlinTypeResolution> {
    let external_is_empty = source.external_index_is_empty();
    let source_first = resolve_kotlin_type_name(raw_name, scope, |candidate| {
        kotlin_realm_type_exists(source, candidate, realm)
    });
    if let KotlinTypeName::Resolved(fqn) = source_first
        && let Some(unit) = kotlin_realm_type_by_fqn(source, &fqn, realm)
    {
        return Some(KotlinTypeResolution::Source(unit));
    }

    if external_is_empty {
        return None;
    }
    let access_package = scope.package_name;
    resolve_kotlin_type_name(raw_name, scope, |candidate| {
        source.external_qualified_name_exists(candidate, access_package)
    })
    .resolved()
    .filter(|fqn| source.external_qualified_name_exists(fqn, access_package))
    .map(|_| KotlinTypeResolution::External)
}

pub fn kotlin_source_type_exists(source: &dyn KotlinSource, fqn: &str) -> bool {
    kotlin_source_type_by_fqn(source, fqn).is_some()
}

pub fn kotlin_source_type_by_fqn(source: &dyn KotlinSource, fqn: &str) -> Option<CodeUnit> {
    source
        .usage_definitions()
        .fqn(fqn)
        .into_iter()
        .find(|unit| unit.is_class() && unit.fq_name() == fqn && !unit.is_synthetic())
}

/// A type named `fqn` anywhere in the JVM realm: Kotlin's own declarations
/// first, then the Java and Scala members when a realm view is supplied.
///
/// Kotlin's own index is consulted first so a same-language declaration always
/// wins a tie, and so a realm-less caller pays nothing.
pub fn kotlin_realm_type_by_fqn(
    source: &dyn KotlinSource,
    fqn: &str,
    realm: Option<&JvmSourceRealm<'_>>,
) -> Option<CodeUnit> {
    if let Some(unit) = kotlin_source_type_by_fqn(source, fqn) {
        return Some(unit);
    }
    realm?
        .peer_types_by_fqn(fqn, Language::Kotlin)
        .into_iter()
        .next()
}

pub fn kotlin_realm_type_exists(
    source: &dyn KotlinSource,
    fqn: &str,
    realm: Option<&JvmSourceRealm<'_>>,
) -> bool {
    kotlin_realm_type_by_fqn(source, fqn, realm).is_some()
}

/// The scope owners visible inside `owner`: the declaration itself, each of its
/// lexical owners, and the nested-type scopes each of those inherits.
pub fn kotlin_scope_owners_for(source: &dyn KotlinSource, owner: &CodeUnit) -> Vec<String> {
    let mut owners = Vec::new();
    let mut current = Some(owner.clone());
    while let Some(unit) = current {
        owners.push(unit.fq_name());
        current = CodeUnitIndex::parent_of(source, &unit);
    }

    // Inherited nested types: a class can name a type its superclass declares.
    // Resolving those supertypes uses the lexical scope only, so this cannot
    // re-enter itself; the depth cap bounds a chain that a malformed or cyclic
    // hierarchy could otherwise make unbounded.
    let lexical = owners.clone();
    let mut frontier = lexical.clone();
    for _ in 0..MAX_INHERITED_SCOPE_DEPTH {
        let mut next = Vec::new();
        for fqn in &frontier {
            for ancestor in kotlin_lexical_direct_ancestor_fqns(source, fqn) {
                if !owners.contains(&ancestor) {
                    owners.push(ancestor.clone());
                    next.push(ancestor);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    owners
}

/// Direct supertype fully-qualified names of `fqn`, resolved with lexical scope
/// only so inherited-scope discovery cannot recurse into itself.
fn kotlin_lexical_direct_ancestor_fqns(source: &dyn KotlinSource, fqn: &str) -> Vec<String> {
    let Some(owner) = kotlin_source_type_by_fqn(source, fqn) else {
        return Vec::new();
    };
    let mut lexical_owners = Vec::new();
    let mut current = Some(owner.clone());
    while let Some(unit) = current {
        lexical_owners.push(unit.fq_name());
        current = CodeUnitIndex::parent_of(source, &unit);
    }
    let imports = source.import_info_of(owner.source());
    let scope = KotlinNameScope {
        package_name: owner.package_name(),
        imports: &imports,
        scope_owners: lexical_owners,
    };
    source
        .raw_supertypes_of(&owner)
        .iter()
        .filter_map(|spelled| {
            resolve_kotlin_type_name(spelled, &scope, |candidate| {
                kotlin_source_type_exists(source, candidate)
            })
            .resolved()
        })
        .collect()
}
