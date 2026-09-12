//! Unused-import findings for one file (issue #40, Milestone 1).
//!
//! An import introduces a *local name* into the importing file. The name is
//! a candidate for an unused-import finding when nothing in that file spells
//! it. This module derives candidates from two existing analyzer products:
//!
//! - the file's lexical environment
//!   ([`crate::analyzer::structural::lexical_environment::environment_for_file`]),
//!   whose `ImportBinder` binding rows are the set of local names the file's
//!   imports introduce, each anchored on the token that spells it; and
//! - the file's occurrence rows
//!   ([`crate::analyzer::structural::occurrence_rows::occurrences_for_file_with_options`]),
//!   which classify every identifier-bearing token of the file.
//!
//! A local name counts as *spelled* when any occurrence row spells it outside
//! the file's own import declarations. Every occurrence class counts, not only
//! the reference classes: an adapter that classifies a default-value token in
//! a destructuring pattern as a binder rather than a read still proves that
//! the file mentions the name, and over-counting uses can only suppress a
//! finding, never invent one.
//!
//! For Rust and Scala, absence of a spelling alone is not proof. The import
//! binder must resolve to declarations whose syntax or activated dependency
//! facts rule out ambient use. Unknown targets retain their named doubt.
//!
//! Nothing is guessed. A language reports only when its adapter derives import
//! binders *and* keeps every occurrence row it classifies; an adapter that
//! drops reference rows whose namespace it cannot state leaves tokens with no
//! row at all, and absence of a row would then not be absence of a use. Java,
//! Rust, Scala and PHP failed that test until #3064 taught the occurrence
//! layer that the head of a qualified path resolves in
//! `Namespace::PathPrefix`, so `HashMap::new()` and `Map.Entry` now carry a
//! row for `HashMap` and `Map`. See [`unused_import_support`].

use std::borrow::Cow;
use std::path::Path;

use crate::analyzer::semantic_model::{
    AmbientUseRole, SemanticModelCompleteness, SemanticModelOverlay, SemanticModelSymbolKind,
};
use crate::analyzer::structural::StructuralSpec;
use crate::analyzer::structural::facts::FileFacts;
use crate::analyzer::structural::kinds::NormalizedKind;
use crate::analyzer::structural::lexical_environment::{BindingRow, environment_for_file};
use crate::analyzer::structural::occurrence_rows::{
    OccurrenceCompleteness, OccurrenceDerivationOptions, OccurrenceIncompleteReason,
    occurrences_for_file_with_options,
};
use crate::analyzer::structural::occurrences::{OccurrenceClass, OccurrenceRole};
use crate::analyzer::structural::resolution::{BindingKind, EnvironmentAxis};
use crate::analyzer::structural::routes::{CuratedExportSurface, RouteHopKind};
use crate::analyzer::structural_spec_for;
use crate::analyzer::tree_walk::{node_for_exact_range, subtree_contains};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, parse_tree_for_language,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{IAnalyzer, Language, ProjectFile, Range, RustOverlayCrates};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::cancellation::CancellationToken;
use tree_sitter::Node;

/// Whether this derivation reports findings for a language, and why not when
/// it does not.
///
/// This is the explicit per-language decision. It is deliberately a hand
/// written table rather than a computation over the adapters' support tables,
/// so that adding a language is a review step; a test in this module asserts
/// that every `Reports` entry still matches what its adapter actually derives,
/// so the table cannot silently outlive the reason it was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnusedImportSupport {
    /// The derivation reports findings for this language.
    Reports,
    /// The language's structural adapter derives no import binders at all
    /// (`EnvironmentAxis::ImportBinders` is unsupported), so the file's import
    /// set is unknown and there is nothing to decide.
    NoImportBinders,
}

/// The per-language decision. See [`UnusedImportSupport`].
pub const fn unused_import_support(language: Language) -> UnusedImportSupport {
    match language {
        // Their adapters derive import binders and state a namespace for every
        // occurrence role they classify, so every identifier-bearing token of
        // the file carries a row.
        //
        // Java, Rust, Scala and PHP joined them in #3064, which gave the head
        // of a qualified path the namespace it resolves in. Rust and Scala
        // retain `AmbientUsePossible` unless resolved declaration facts rule
        // out that form; the LSP publishes only proofs.
        Language::Python
        | Language::JavaScript
        | Language::TypeScript
        | Language::Java
        | Language::Rust
        | Language::Scala
        | Language::Php => UnusedImportSupport::Reports,
        // No import binders: Go, Kotlin, C#, C/C++ derive no lexical
        // environment beyond callable applicability, and Ruby has no import
        // binder to derive (`require` binds no name).
        Language::Go
        | Language::Kotlin
        | Language::CSharp
        | Language::Cpp
        | Language::Ruby
        | Language::None => UnusedImportSupport::NoImportBinders,
    }
}

/// Reference-class occurrence roles a reporting language's adapter does not
/// emit, together with the reason that costs the file nothing.
///
/// A reference role the adapter never emits would normally make absence
/// meaningless. It does not here when the adapter routes the tokens of that
/// role to a role it does emit, so the token still carries a row. Each entry
/// records a checked claim; a role that is merely absent must not be added.
///
/// `PatternPosition` is the only such role for the reporting languages.
/// Python classifies `case Color.RED` as a `PathSegment` plus a
/// `ValueReference`, and `case Shape()` as a `ValueReference`; JavaScript and
/// TypeScript classify a destructuring pattern's tokens as binders; Java
/// classifies a `case RED ->` label and a record deconstruction's type as a
/// `ValueReference` or a `TypeOperand`, and PHP has no pattern syntax at all,
/// so its `match` arms are ordinary expressions. In every case the token that
/// spells an imported name still has a row. Rust and Scala emit the role
/// themselves and need no entry.
const ROUTED_ELSEWHERE: &[OccurrenceRole] = &[OccurrenceRole::PatternPosition];

/// One import binder whose local name the file never spells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusedImport {
    /// The token that spells the bound name: the alias when the import is
    /// renamed, the imported name's own token otherwise.
    pub range: Range,
    /// The name the import introduces into the file.
    pub local_name: String,
    /// The import target's path segments as the parser recorded them, for a
    /// message that can name what is unused without re-reading the source.
    pub target_segments: Vec<String>,
    pub certainty: UnusedImportCertainty,
}

/// How strong the evidence behind one finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnusedImportCertainty {
    /// Every position in the file that could spell the bound name carries an
    /// occurrence row, and none of them spells it. The import is provably
    /// unreferenced by this file.
    Unreferenced,
    /// No occurrence row spells the bound name, but this language can consume
    /// the import without spelling it here, so the absence is not a proof.
    /// The form that could not be ruled out is named.
    AmbientUsePossible(AmbientImportUse),
}

/// A way a file can consume an import without spelling its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbientImportUse {
    /// The file contains JSX. A JSX element compiles to a call of a *factory*
    /// whose name is a build setting (`jsxFactory`, the `@jsx` pragma, or the
    /// automatic runtime, which needs no import at all). This derivation reads
    /// no build configuration, so it cannot say which import (if any) the
    /// factory names, and every unreferenced import in such a file inherits
    /// the doubt.
    JsxFactory,
    /// A Rust `use` can name a trait, and a trait is brought into scope for
    /// its *methods*: `use std::io::Write;` followed by `file.write_all(..)`
    /// spells the method and never the trait. Whether the target is a trait is
    /// a property of the declaration, which for the common case (`std`, any
    /// dependency) is not in this workspace at all, so no intra-file
    /// derivation can rule it out. Resolved workspace syntax or an activated
    /// dependency pack can establish a non-trait declaration; otherwise the
    /// import retains this doubt. Macros, modules and unclassified aliases
    /// retain it too.
    RustTraitMethodScope,
    /// A Scala import can name an implicit value, an implicit conversion or a
    /// `given`, which the compiler selects *by type* from the imported scope
    /// and which is used without ever being spelled:
    /// `import scala.concurrent.ExecutionContext.Implicits.global` followed by
    /// a `Future { .. }` spells nothing. Scala 2 imports such a definition by
    /// its plain name, so the import site does not mark it either. Whether the
    /// target is one of these is a property of the declaration, which for an
    /// import that leaves the workspace is not in this workspace at all.
    /// Resolved workspace syntax rules it out for an ordinary declaration, and
    /// an activated dependency pack's `ambient_use` fact rules it out for one
    /// outside; a target with neither retains this doubt.
    ScalaImplicitScope,
    /// The file carries a documentation comment, and this language resolves
    /// the type names written inside one against the file's imports: Java's
    /// javadoc `{@link Map}` and `@throws`, PHP's docblock `@var Gadget` and
    /// `@param`, and JavaScript/TypeScript JSDoc `@type`, `@param` and
    /// `{@link Widget}`. Removing the import breaks the documentation build and the
    /// IDE's navigation, so the reference is a use -- but it is spelled inside
    /// a comment token, which carries no occurrence row. A corpus probe found
    /// this to be the *only* thing either language's findings were: every one
    /// of `antlr/stringtemplate4`'s ten Java findings and both of
    /// `LaravelDaily/laravel-invoices`' PHP findings were referenced from a
    /// documentation comment and from nowhere else.
    ///
    /// The JS/TS grammars also expose documentation as opaque comment tokens;
    /// no JSDoc grammar is currently included. This deliberately downgrades
    /// every finding in a documented file, including unrelated unused imports,
    /// until structured documentation references are available.
    DocumentationReference,
}

/// Why a file produced no findings.
///
/// Reported instead of an empty finding list so a consumer can tell "this file
/// has no unused import" from "this file was not decided".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnusedImportsIncompleteReason {
    /// The file's language is not on the support table.
    LanguageUnsupported(UnusedImportSupport),
    /// No structural adapter is registered for the file's language.
    NoStructuralAdapter,
    /// The analyzer holds no structural facts for the file.
    FactsUnavailable,
    /// The file's environment does not cover its import binders, so the set of
    /// local names its imports introduce is not the whole set.
    ImportBindersUncovered,
    /// A reference-class occurrence role the adapter classifies was dropped
    /// for this file, so a token spelling a bound name can be missing.
    ReferenceRowsDropped(OccurrenceRole),
    /// A reference-class occurrence role is unsupported and is not one this
    /// module has established the adapter routes elsewhere.
    ReferenceRoleUnsupported(OccurrenceRole),
    /// The file's source did not parse, so no import token could be located in
    /// the syntax the re-export classification reads.
    SyntaxUnavailable,
    /// The adapter could not say whether at least one import re-exports, so an
    /// unreferenced import cannot be told from a deliberate re-export.
    IndirectionUnclassified,
    /// A Python package initializer (`__init__.py`) that names no `__all__`.
    /// An import it never references is the conventional re-export idiom
    /// there, and this file alone cannot tell that from a mistake.
    PythonPackageInitializerWithoutAll,
    /// Occurrence derivation was cancelled before the rows were complete.
    Cancelled,
}

/// One file's unused imports, with an explicit account of what was decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusedImportsFileResult {
    /// Findings in source order. Empty and `Complete` means the file has no
    /// unused import; empty and `Incomplete` means nothing was decided.
    pub findings: Vec<UnusedImport>,
    pub completeness: UnusedImportsCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnusedImportsCompleteness {
    Complete,
    Incomplete(UnusedImportsIncompleteReason),
}

impl UnusedImportsCompleteness {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

impl UnusedImportsFileResult {
    fn incomplete(reason: UnusedImportsIncompleteReason) -> Self {
        Self {
            findings: Vec::new(),
            completeness: UnusedImportsCompleteness::Incomplete(reason),
        }
    }
}

/// Every import binder of `file` whose local name the file never spells.
pub fn unused_imports_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> UnusedImportsFileResult {
    let language = language_for_file(file);
    let support = unused_import_support(language);
    if support != UnusedImportSupport::Reports {
        return UnusedImportsFileResult::incomplete(
            UnusedImportsIncompleteReason::LanguageUnsupported(support),
        );
    }
    let Some(spec) = structural_spec_for(language) else {
        return UnusedImportsFileResult::incomplete(
            UnusedImportsIncompleteReason::NoStructuralAdapter,
        );
    };
    let facts = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .and_then(|provider| provider.structural_facts(file));
    let Some(facts) = facts else {
        return UnusedImportsFileResult::incomplete(
            UnusedImportsIncompleteReason::FactsUnavailable,
        );
    };

    let environment = environment_for_file(analyzer, file);
    if !environment
        .completeness
        .covers(EnvironmentAxis::ImportBinders)
    {
        return UnusedImportsFileResult::incomplete(
            UnusedImportsIncompleteReason::ImportBindersUncovered,
        );
    }

    let occurrences = match occurrences_for_file_with_options(
        analyzer,
        file,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        &CancellationToken::new(),
    ) {
        Ok(occurrences) => occurrences,
        Err(_) => {
            return UnusedImportsFileResult::incomplete(UnusedImportsIncompleteReason::Cancelled);
        }
    };
    if let Some(reason) = reference_rows_missing(&occurrences.completeness) {
        return UnusedImportsFileResult::incomplete(reason);
    }

    let Some(tree) = parse_tree_for_language(file, language, facts.source()) else {
        return UnusedImportsFileResult::incomplete(
            UnusedImportsIncompleteReason::SyntaxUnavailable,
        );
    };
    let root = tree.root_node();
    let surface = spec.curated_export_surface(root, facts.source());
    if language == Language::Python
        && is_python_package_initializer(file)
        && surface == CuratedExportSurface::Absent
    {
        return UnusedImportsFileResult::incomplete(
            UnusedImportsIncompleteReason::PythonPackageInitializerWithoutAll,
        );
    }

    // Every token inside an import declaration is part of the import's own
    // spelling, never a use of what it binds. The declarations are the arena's
    // `Import` facts: an `export ... from` re-export is a different kind, so
    // `export { Widget }` still counts as a use of the imported `Widget`.
    let import_declarations: Vec<Range> = facts
        .nodes()
        .iter()
        .filter(|node| node.kind == NormalizedKind::Import)
        .map(|node| node.range)
        .collect();
    let spelled: HashSet<Cow<'_, str>> = occurrences
        .rows
        .iter()
        .filter(|row| {
            !import_declarations
                .iter()
                .any(|declaration| contains(*declaration, row.range))
        })
        .map(|row| fold_name(language, row.effective_spelling()))
        .collect();

    // Another import can consume this import's local name: an enum's
    // variants via `use E::*`, or Scala members via `import settings._`.
    // Keep each mention's containing declaration so only the binder's own
    // spelling is excluded. Rust and Scala now use absence as a proof.
    let mut import_mentions: HashMap<Cow<'_, str>, Vec<Range>> = HashMap::default();
    if matches!(language, Language::Rust | Language::Scala) {
        for row in &occurrences.rows {
            if let Some(declaration) = import_declarations
                .iter()
                .find(|declaration| contains(**declaration, row.range))
            {
                import_mentions
                    .entry(fold_name(language, row.effective_spelling()))
                    .or_default()
                    .push(*declaration);
            }
        }
    }

    let certainty = match ambient_use(language, &facts, root, facts.source()) {
        Some(form) => UnusedImportCertainty::AmbientUsePossible(form),
        None => UnusedImportCertainty::Unreferenced,
    };

    let mut findings = Vec::new();
    for binding in &environment.bindings {
        if binding.kind != BindingKind::ImportBinder {
            continue;
        }
        let Some(import) = &binding.import else {
            continue;
        };
        // A wildcard binds an unspecified set of names, so there is no single
        // name whose absence could prove anything. JavaScript's `import * as
        // ns` is recorded as one of these too.
        if import.wildcard {
            continue;
        }
        // No binder token in this file: a JavaScript side-effect import
        // (`import './setup.js'`), or a form whose bound name the adapter
        // cannot point at (Python's `import a.b.c` binds `a`, which is a path
        // segment of the declaration rather than its target). The row's range
        // is then its whole scope, which is not a span to report.
        if binding.node.is_none() {
            continue;
        }
        let name = fold_name(language, &binding.name);
        if spelled.contains(&name)
            || import_mentions.get(&name).is_some_and(|declarations| {
                declarations
                    .iter()
                    .any(|declaration| !contains(*declaration, binding.range))
            })
        {
            continue;
        }
        let Some(token) =
            root.descendant_for_byte_range(binding.range.start_byte, binding.range.end_byte)
        else {
            return UnusedImportsFileResult::incomplete(
                UnusedImportsIncompleteReason::SyntaxUnavailable,
            );
        };
        match spec.indirection_relation(token, facts.source(), &surface) {
            // A re-export forwards the name onward, which is a use.
            Some(RouteHopKind::ReExport | RouteHopKind::Export) => continue,
            Some(_) => {}
            None => {
                return UnusedImportsFileResult::incomplete(
                    UnusedImportsIncompleteReason::IndirectionUnclassified,
                );
            }
        }
        findings.push(UnusedImport {
            range: binding.range,
            local_name: binding.name.clone(),
            target_segments: import.target_segments.clone(),
            certainty,
        });
    }
    if matches!(language, Language::Rust | Language::Scala) {
        refine_import_certainties(
            analyzer,
            file,
            facts.source(),
            language,
            spec,
            &environment.bindings,
            &mut findings,
        );
    }
    findings.sort_by_key(|finding| finding.range.start_byte);

    UnusedImportsFileResult {
        findings,
        completeness: UnusedImportsCompleteness::Complete,
    }
}

/// Refine the language-wide doubt only after resolving the actual import
/// binder. A same-spelled declaration elsewhere is never negative evidence.
fn refine_import_certainties(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    language: Language,
    spec: &dyn StructuralSpec,
    bindings: &[BindingRow],
    findings: &mut [UnusedImport],
) {
    if findings.is_empty() {
        return;
    }
    let requests = findings
        .iter()
        .map(|finding| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(finding.range.start_byte),
            end_byte: Some(finding.range.end_byte),
        })
        .collect();
    let outcomes =
        resolve_definition_batch_with_source(analyzer, requests, file.clone(), source.into());
    assert_eq!(outcomes.len(), findings.len());
    let overlay = analyzer.semantic_model_overlay();
    let crates = RustOverlayCrates::new(overlay.as_deref());
    let mut syntax = HashMap::default();
    for (finding, outcome) in findings.iter_mut().zip(outcomes) {
        if language == Language::Rust
            && outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary
            && outcome.definitions.is_empty()
            && finding.target_segments.first().is_some_and(|root| {
                !matches!(root.as_str(), "crate" | "self" | "super")
                        // A lexical root can rename a different crate or
                        // module to this spelling. The pack resolver handles
                        // Cargo renames, but not these lexical substitutions.
                        && !bindings.iter().any(|binding| {
                            binding.name == *root && contains(binding.activation, finding.range)
                        })
            })
            && let Some(symbol) =
                crates.referenceable_symbol(&RustOverlayCrates::pack_name(&finding.target_segments))
            && symbol.provenance.completeness == SemanticModelCompleteness::Complete
            && matches!(
                symbol.kind,
                SemanticModelSymbolKind::Struct
                    | SemanticModelSymbolKind::Enum
                    | SemanticModelSymbolKind::Union
                    | SemanticModelSymbolKind::Function
                    | SemanticModelSymbolKind::Constant
                    | SemanticModelSymbolKind::Static
            )
        {
            finding.certainty = UnusedImportCertainty::Unreferenced;
            continue;
        }
        if language == Language::Scala
            && outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary
            && outcome.definitions.is_empty()
            && scala_pack_rules_out_ambient_use(
                overlay.as_deref(),
                &finding.target_segments,
                bindings,
                finding.range,
            )
        {
            finding.certainty = UnusedImportCertainty::Unreferenced;
            continue;
        }
        if outcome.status != DefinitionLookupStatus::Resolved
            || outcome.definitions.is_empty()
            || !outcome.diagnostics.is_empty()
        {
            continue;
        }
        let nonambient = outcome.definitions.iter().all(|definition| {
            let tree = syntax
                .entry(definition.source().clone())
                .or_insert_with(|| {
                    analyzer
                        .structural_fact_providers()
                        .into_iter()
                        .find(|provider| provider.structural_language() == language)
                        .and_then(|provider| provider.structural_facts(definition.source()))
                        .and_then(|facts| {
                            parse_tree_for_language(definition.source(), language, facts.source())
                        })
                });
            let Some(tree) = tree else {
                return false;
            };
            let ranges = analyzer.ranges(definition);
            !ranges.is_empty()
                && ranges.iter().all(|range| {
                    let Some(node) = node_for_exact_range(tree.root_node(), range) else {
                        return false;
                    };
                    !node.has_error()
                        && spec.declaration_ambient_use(node) == Some(AmbientUseRole::NotAmbient)
                })
        });
        if nonambient {
            finding.certainty = UnusedImportCertainty::Unreferenced;
        }
    }
}

/// Whether the activated dependency packs prove that this Scala import names an
/// ordinary declaration.
///
/// The import path is the lookup key. A Scala pack publishes each declaration
/// under its dotted qualified name, and the parser's structured path segments
/// join to exactly that spelling, so nothing here re-reads source text. Only an
/// explicit [`AmbientUseRole::NotAmbient`] proves anything: a missing fact is a
/// producer that did not review the declaration, and a `Method`, `Property` or
/// `Class` kind is not negative evidence, because Scala records an implicit
/// `val`, `def`, `class` and `object` under exactly those kinds.
///
/// Every record the name publishes has to answer `NotAmbient`. One Scala import
/// binds a whole overload set, and a class together with its companion object,
/// so a single ordinary record among them is not a claim about the name.
fn scala_pack_rules_out_ambient_use(
    overlay: Option<&SemanticModelOverlay>,
    target_segments: &[String],
    bindings: &[BindingRow],
    range: Range,
) -> bool {
    // A one-segment path names something already in scope rather than a path a
    // pack publishes, and the pack index would answer for a bare terminal name.
    let [root, _, ..] = target_segments else {
        return false;
    };
    // A local binder can rename a different target to this leading spelling,
    // which would make a same-spelled published path the wrong declaration.
    if bindings
        .iter()
        .any(|binding| binding.name == *root && contains(binding.activation, range))
    {
        return false;
    }
    let Some(overlay) = overlay else {
        return false;
    };
    let matched = overlay.symbols_named(&target_segments.join("."));
    !matched.records.is_empty()
        && matched.records.iter().all(|symbol| {
            symbol.language == "scala" && symbol.ambient_use == Some(AmbientUseRole::NotAmbient)
        })
}

/// The spelling under which a name is compared with the tokens of its file.
///
/// PHP resolves class, interface, trait, enum and function names
/// case-insensitively, so `new gadget()` uses `use App\Model\Gadget;`.
/// Folding the comparison there can only *suppress* a finding, never invent
/// one, which is also why folding PHP's case-sensitive constants and
/// variables with them costs nothing but a missed finding. Every other
/// language on the table compares names exactly.
fn fold_name(language: Language, name: &str) -> Cow<'_, str> {
    match language {
        Language::Php => Cow::Owned(name.to_ascii_lowercase()),
        _ => Cow::Borrowed(name),
    }
}

/// The way this file could consume an import without spelling its name, or
/// `None` when the language and the file rule every one of them out.
///
/// This is the initial file-wide doubt. Rust and Scala can refine it for an
/// individual import using resolved declaration evidence after collecting
/// candidates. See [`AmbientImportUse`].
fn ambient_use(
    language: Language,
    facts: &FileFacts,
    root: Node<'_>,
    source: &str,
) -> Option<AmbientImportUse> {
    if facts
        .nodes()
        .iter()
        .any(|node| node.kind == NormalizedKind::JsxElement)
    {
        return Some(AmbientImportUse::JsxFactory);
    }
    match language {
        Language::Rust => Some(AmbientImportUse::RustTraitMethodScope),
        Language::Scala => Some(AmbientImportUse::ScalaImplicitScope),
        Language::Java | Language::Php | Language::JavaScript | Language::TypeScript
            if has_documentation_comment(language, root, source) =>
        {
            Some(AmbientImportUse::DocumentationReference)
        }
        _ => None,
    }
}

/// The grammar's spelling of a comment token, for the languages whose
/// documentation comments carry type references.
const fn documentation_comment_kind(language: Language) -> &'static str {
    match language {
        Language::Java => "block_comment",
        _ => "comment",
    }
}

/// Whether the file carries a documentation comment.
///
/// This reads whether a comment token *is* a documentation comment -- its
/// first three bytes -- and never what the comment says: the name a
/// `{@link Map}` or an `@var Gadget` spells stays unread, which is why the
/// answer is a doubt rather than a use. Naming the doubt is what keeps the
/// derivation from claiming a proof it does not have.
fn has_documentation_comment(language: Language, root: Node<'_>, source: &str) -> bool {
    let kind = documentation_comment_kind(language);
    subtree_contains(root, |node| {
        node.kind() == kind && source[node.start_byte()..node.end_byte()].starts_with("/**")
    })
}

fn contains(outer: Range, inner: Range) -> bool {
    outer.start_byte <= inner.start_byte && inner.end_byte <= outer.end_byte
}

/// Whether a Python file is a package initializer, whose unreferenced imports
/// are the language's conventional re-export.
fn is_python_package_initializer(file: &ProjectFile) -> bool {
    file.rel_path().file_name() == Some(Path::new("__init__.py").as_os_str())
}

/// The reason a file's occurrence rows cannot support an absence claim, or
/// `None` when every identifier-bearing token of the file carries a row.
fn reference_rows_missing(
    completeness: &OccurrenceCompleteness,
) -> Option<UnusedImportsIncompleteReason> {
    let OccurrenceCompleteness::Incomplete { reasons, .. } = completeness else {
        return None;
    };
    for reason in reasons {
        match reason {
            // The adapter classified tokens with this role and then dropped
            // them, so those tokens have no row at all.
            OccurrenceIncompleteReason::NamespaceUnknown(role)
                if role.class() == OccurrenceClass::Reference =>
            {
                return Some(UnusedImportsIncompleteReason::ReferenceRowsDropped(*role));
            }
            OccurrenceIncompleteReason::RoleUnsupported(role)
                if role.class() == OccurrenceClass::Reference
                    && !ROUTED_ELSEWHERE.contains(role) =>
            {
                return Some(UnusedImportsIncompleteReason::ReferenceRoleUnsupported(
                    *role,
                ));
            }
            OccurrenceIncompleteReason::NoStructuralAdapter => {
                return Some(UnusedImportsIncompleteReason::NoStructuralAdapter);
            }
            OccurrenceIncompleteReason::FactsUnavailable => {
                return Some(UnusedImportsIncompleteReason::FactsUnavailable);
            }
            OccurrenceIncompleteReason::NamespaceUnknown(_)
            | OccurrenceIncompleteReason::RoleUnsupported(_) => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::resolution::ALL_ENVIRONMENT_AXES;
    use crate::analyzer::{AnalyzerConfig, Project, TestProject, WorkspaceAnalyzer};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        file: ProjectFile,
        source: String,
    }

    impl Fixture {
        fn new(language: Language, relative_path: &str, source: &str) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let file = ProjectFile::new(root.clone(), relative_path);
            file.write(source).expect("write fixture source");
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            )
            .expect("ephemeral workspace should build");
            Self {
                _temp: temp,
                workspace,
                file,
                source: source.to_owned(),
            }
        }

        fn result(&self) -> UnusedImportsFileResult {
            unused_imports_for_file(self.workspace.analyzer(), &self.file)
        }

        /// The findings' local names in source order, asserting the file was
        /// decided at all.
        fn unused_names(&self) -> Vec<String> {
            let result = self.result();
            assert!(
                result.completeness.is_complete(),
                "file was not decided: {:?}",
                result.completeness
            );
            result
                .findings
                .into_iter()
                .map(|finding| finding.local_name)
                .collect()
        }

        fn at(&self, needle: &str) -> usize {
            self.source
                .find(needle)
                .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"))
        }
    }

    /// The hand-written support table must keep matching what the adapters
    /// actually derive: a language reports only when its adapter declares the
    /// import-binder axis, and every language that does not is recorded with
    /// the reason it does not.
    #[test]
    fn the_support_table_matches_every_adapter_import_binder_axis() {
        for language in [
            Language::None,
            Language::Java,
            Language::Go,
            Language::Cpp,
            Language::JavaScript,
            Language::TypeScript,
            Language::Python,
            Language::Rust,
            Language::Php,
            Language::Scala,
            Language::CSharp,
            Language::Ruby,
            Language::Kotlin,
        ] {
            let derives_binders = structural_spec_for(language).is_some_and(|spec| {
                spec.lexical_environment_support()
                    .is_supported(EnvironmentAxis::ImportBinders)
            });
            let support = unused_import_support(language);
            assert_eq!(
                support == UnusedImportSupport::NoImportBinders,
                !derives_binders,
                "{language:?} declares import binders = {derives_binders}, table says {support:?}"
            );
            assert!(
                ALL_ENVIRONMENT_AXES.contains(&EnvironmentAxis::ImportBinders),
                "the axis this table is keyed on must exist"
            );
        }
    }

    /// Python: one unused import, one used import, a `__all__` re-export that
    /// is a use, and a wildcard that binds no single name.
    #[test]
    fn python_reports_the_unused_import_and_spares_the_reexport() {
        let fixture = Fixture::new(
            Language::Python,
            "src/app.py",
            concat!(
                "from pkg import used_thing, unused_thing\n",
                "from pkg import exported\n",
                "from other import *\n",
                "import os\n",
                "__all__ = [\"exported\"]\n",
                "print(os.path, used_thing)\n",
            ),
        );
        assert_eq!(fixture.unused_names(), vec!["unused_thing".to_string()]);
        let finding = &fixture.result().findings[0];
        assert_eq!(finding.range.start_byte, fixture.at("unused_thing"));
        assert_eq!(finding.certainty, UnusedImportCertainty::Unreferenced);
        assert_eq!(
            finding.target_segments,
            vec!["pkg".to_string(), "unused_thing".to_string()]
        );
    }

    /// A Python package initializer that states no `__all__` is not decided:
    /// an import it never references there is the language's conventional
    /// re-export, and the file alone cannot tell that from a mistake.
    #[test]
    fn a_python_package_initializer_without_all_is_not_decided() {
        let fixture = Fixture::new(
            Language::Python,
            "pkg/__init__.py",
            "from .impl import Widget\n",
        );
        assert_eq!(
            fixture.result().completeness,
            UnusedImportsCompleteness::Incomplete(
                UnusedImportsIncompleteReason::PythonPackageInitializerWithoutAll
            )
        );
    }

    /// The same initializer with an `__all__` is decided, and the listed name
    /// is a re-export rather than an unused import.
    #[test]
    fn a_python_package_initializer_with_all_reports_only_the_unlisted_import() {
        let fixture = Fixture::new(
            Language::Python,
            "pkg/__init__.py",
            concat!(
                "from .impl import Widget\n",
                "from .other import Gadget\n",
                "__all__ = [\"Widget\"]\n",
            ),
        );
        assert_eq!(fixture.unused_names(), vec!["Gadget".to_string()]);
    }

    /// JavaScript: a side-effect import binds no name and is never reported, a
    /// namespace import binds an unspecified set, an `export { x }` of an
    /// imported name is a use, and only the genuinely unreferenced specifier
    /// is reported.
    #[test]
    fn javascript_reports_only_the_unreferenced_specifier() {
        let fixture = Fixture::new(
            Language::JavaScript,
            "src/app.js",
            concat!(
                "import './setup.js';\n",
                "import * as ns from './ns.js';\n",
                "import used from './used.js';\n",
                "import unusedDefault from './unused.js';\n",
                "import { forwarded, alpha, beta as bee } from './named.js';\n",
                "export { forwarded };\n",
                "export { passthrough } from './passthrough.js';\n",
                "used(alpha);\n",
            ),
        );
        assert_eq!(
            fixture.unused_names(),
            vec!["unusedDefault".to_string(), "bee".to_string()]
        );
        assert!(
            fixture
                .result()
                .findings
                .iter()
                .all(|finding| finding.certainty == UnusedImportCertainty::Unreferenced),
            "a file without JSX proves the absence"
        );
    }

    /// A default-value token inside a destructuring pattern is classified as a
    /// binder rather than as a read. It still spells the name, so the import
    /// it names is not reported (issue #40: over-counting uses may only
    /// suppress a finding).
    #[test]
    fn javascript_counts_a_pattern_default_value_as_a_use() {
        let fixture = Fixture::new(
            Language::JavaScript,
            "src/pattern.js",
            concat!(
                "import { Color, Shape } from './c.js';\n",
                "export const { x = Color } = obj;\n",
                "export function f({ y = Shape }) {}\n",
            ),
        );
        assert_eq!(fixture.unused_names(), Vec::<String>::new());
    }

    /// TypeScript: a type-only import used in a type position is used, and an
    /// unreferenced one is reported.
    #[test]
    fn typescript_reports_the_unreferenced_type_import() {
        let fixture = Fixture::new(
            Language::TypeScript,
            "src/app.ts",
            concat!(
                "import type { Props } from './props';\n",
                "import type { Unused } from './unused';\n",
                "export function app(p: Props): Props { return p; }\n",
            ),
        );
        assert_eq!(fixture.unused_names(), vec!["Unused".to_string()]);
    }

    /// A file containing JSX cannot prove any import unused: the JSX factory's
    /// name is a build setting this derivation does not read.
    #[test]
    fn a_jsx_file_downgrades_every_finding_to_an_ambient_use() {
        let fixture = Fixture::new(
            Language::TypeScript,
            "src/app.tsx",
            concat!(
                "import React from 'react';\n",
                "import { Widget } from './widget';\n",
                "import { Unused } from './unused';\n",
                "export function App() { return <Widget />; }\n",
            ),
        );
        let result = fixture.result();
        assert!(result.completeness.is_complete(), "{:?}", result);
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| (finding.local_name.as_str(), finding.certainty))
                .collect::<Vec<_>>(),
            vec![
                (
                    "React",
                    UnusedImportCertainty::AmbientUsePossible(AmbientImportUse::JsxFactory)
                ),
                (
                    "Unused",
                    UnusedImportCertainty::AmbientUsePossible(AmbientImportUse::JsxFactory)
                ),
            ]
        );
    }

    #[test]
    fn rust_resolved_struct_is_unused_while_trait_method_scope_is_preserved() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "mod definitions; mod consumer;\n")
            .file(
                "src/definitions.rs",
                "pub struct Widget; pub trait Touch { fn touch(&self) {} } impl Touch for Widget {}\n",
            )
            .file(
                "src/consumer.rs",
                "use crate::definitions::{Widget as Unused, Touch};\nfn run() { crate::definitions::Widget.touch(); }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result =
            unused_imports_for_file(workspace.analyzer(), &project.file("src/consumer.rs"));
        assert!(result.completeness.is_complete(), "{result:?}");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| (finding.local_name.as_str(), finding.certainty))
                .collect::<Vec<_>>(),
            vec![
                ("Unused", UnusedImportCertainty::Unreferenced),
                (
                    "Touch",
                    UnusedImportCertainty::AmbientUsePossible(
                        AmbientImportUse::RustTraitMethodScope
                    )
                ),
            ],
        );
    }

    /// Grammar 0.24.3 nests item attributes in a `declaration_with_attribute`
    /// wrapper. An attribute macro can turn an apparent concrete struct into
    /// arbitrary syntax, so the same attribute must preserve ambient-use doubt
    /// in the new layout that a preceding-sibling attribute preserved before.
    #[test]
    fn rust_grouped_outer_attributes_keep_a_resolved_struct_ambient() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "mod definitions; mod consumer;\n")
            .file(
                "src/definitions.rs",
                "#[cfg_attr(unix, derive(Debug))]\npub struct Widget;\n",
            )
            .file(
                "src/consumer.rs",
                "use crate::definitions::Widget as Unused;\nfn run() { crate::definitions::Widget; }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result =
            unused_imports_for_file(workspace.analyzer(), &project.file("src/consumer.rs"));
        assert!(result.completeness.is_complete(), "{result:?}");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| (finding.local_name.as_str(), finding.certainty))
                .collect::<Vec<_>>(),
            [(
                "Unused",
                UnusedImportCertainty::AmbientUsePossible(AmbientImportUse::RustTraitMethodScope)
            )]
        );
    }

    /// `HashMap::new()` spells the imported `HashMap` through a path head,
    /// which carried no occurrence row until #3064. The import is used, and
    /// the file is decided rather than undecided.
    #[test]
    fn rust_counts_a_scoped_path_head_as_a_use() {
        let fixture = Fixture::new(
            Language::Rust,
            "src/app.rs",
            concat!(
                "use std::collections::HashMap;\n",
                "use std::collections::BTreeMap;\n",
                "fn go() { let _ = HashMap::new(); }\n",
            ),
        );
        assert_eq!(fixture.unused_names(), ["BTreeMap"]);
    }

    /// Rust's findings name the doubt they cannot rule out: a `use` can name a
    /// trait, whose methods are reachable without the trait being spelled.
    #[test]
    fn rust_findings_carry_the_trait_method_scope_doubt() {
        let fixture = Fixture::new(
            Language::Rust,
            "src/app.rs",
            concat!("use std::collections::BTreeMap;\n", "fn go() {}\n"),
        );
        let findings = fixture.result().findings;
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.certainty)
                .collect::<Vec<_>>(),
            [UnusedImportCertainty::AmbientUsePossible(
                AmbientImportUse::RustTraitMethodScope
            )],
        );
    }

    /// Java is in the same position, and for the same reason: `Map.Entry`
    /// spells `Map`. Java has no ambient import use, so its findings are
    /// proofs.
    #[test]
    fn java_counts_a_qualified_type_head_as_a_use() {
        let fixture = Fixture::new(
            Language::Java,
            "app/Widget.java",
            concat!(
                "package app;\n",
                "import java.util.Map;\n",
                "import java.util.List;\n",
                "class Widget { Map.Entry<String,String> go() { return null; } }\n",
            ),
        );
        let result = fixture.result();
        assert!(result.completeness.is_complete());
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| (finding.local_name.as_str(), finding.certainty))
                .collect::<Vec<_>>(),
            [("List", UnusedImportCertainty::Unreferenced)],
        );
    }

    /// A Java wildcard binds an unspecified set of names, so it is never
    /// reported even when nothing else in the file spells anything from it.
    #[test]
    fn java_wildcard_imports_are_never_reported() {
        let fixture = Fixture::new(
            Language::Java,
            "app/Widget.java",
            concat!(
                "package app;\n",
                "import java.util.*;\n",
                "class Widget { int go() { return 1; } }\n",
            ),
        );
        assert!(fixture.unused_names().is_empty());
    }

    /// `mutable.Buffer` spells the imported `mutable` through a path head.
    /// Scala's findings name the doubt they cannot rule out: an import can
    /// name a given or an implicit selected by type, never by name.
    #[test]
    fn scala_counts_a_stable_identifier_head_as_a_use() {
        let fixture = Fixture::new(
            Language::Scala,
            "src/main/scala/app/Widget.scala",
            concat!(
                "package app\n",
                "import scala.collection.mutable\n",
                "import scala.collection.immutable\n",
                "class Widget { def rows: mutable.Buffer[String] = mutable.Buffer.empty }\n",
            ),
        );
        let result = fixture.result();
        assert!(result.completeness.is_complete());
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| (finding.local_name.as_str(), finding.certainty))
                .collect::<Vec<_>>(),
            [(
                "immutable",
                UnusedImportCertainty::AmbientUsePossible(AmbientImportUse::ScalaImplicitScope)
            )],
        );
    }

    /// A Scala 3 `export` re-publishes the name as a member of the enclosing
    /// template, so it is a use even though nothing else in the file spells
    /// it. A wildcard import binds an unspecified set and is never reported.
    #[test]
    fn scala_exports_and_wildcards_are_not_unused_imports() {
        let fixture = Fixture::new(
            Language::Scala,
            "src/main/scala/app/Widget.scala",
            concat!(
                "package app\n",
                "import scala.collection.mutable.*\n",
                "class Widget:\n",
                "  export scala.collection.immutable.Seq\n",
            ),
        );
        assert!(fixture.unused_names().is_empty());
    }

    /// A javadoc `{@link Map}` keeps `import java.util.Map;` alive while
    /// spelling the name only inside a comment token, so a Java file that
    /// carries a documentation comment cannot prove any of its imports
    /// unreferenced. A file with only ordinary comments still can.
    #[test]
    fn a_java_documentation_comment_downgrades_every_finding() {
        let documented = Fixture::new(
            Language::Java,
            "app/Widget.java",
            concat!(
                "package app;\n",
                "import java.util.Map;\n",
                "/** Uses {@link Map} in prose only. */\n",
                "class Widget { int go() { return 1; } }\n",
            ),
        );
        assert_eq!(
            documented
                .result()
                .findings
                .iter()
                .map(|finding| (finding.local_name.as_str(), finding.certainty))
                .collect::<Vec<_>>(),
            [(
                "Map",
                UnusedImportCertainty::AmbientUsePossible(AmbientImportUse::DocumentationReference)
            )],
        );

        let plain = Fixture::new(
            Language::Java,
            "app/Widget.java",
            concat!(
                "package app;\n",
                "import java.util.Map;\n",
                "// an ordinary comment carries no type reference\n",
                "class Widget { int go() { return 1; } }\n",
            ),
        );
        assert_eq!(
            plain
                .result()
                .findings
                .iter()
                .map(|finding| (finding.local_name.as_str(), finding.certainty))
                .collect::<Vec<_>>(),
            [("Map", UnusedImportCertainty::Unreferenced)],
        );
    }

    /// PHP docblocks reference imported types the same way, through `@var`,
    /// `@param` and `@throws`.
    #[test]
    fn a_php_docblock_downgrades_every_finding() {
        let fixture = Fixture::new(
            Language::Php,
            "src/Runner.php",
            concat!(
                "<?php\n",
                "namespace App;\n",
                "use App\\Model\\Gadget;\n",
                "class Runner {\n",
                "    /** @var Gadget */\n",
                "    private $part;\n",
                "}\n",
            ),
        );
        assert_eq!(
            fixture
                .result()
                .findings
                .iter()
                .map(|finding| finding.certainty)
                .collect::<Vec<_>>(),
            [UnusedImportCertainty::AmbientUsePossible(
                AmbientImportUse::DocumentationReference
            )],
        );
    }

    /// PHP compares class and function names case-insensitively, so
    /// `new gadget()` uses `use App\Model\Gadget;`.
    #[test]
    fn php_class_names_compare_case_insensitively() {
        let fixture = Fixture::new(
            Language::Php,
            "src/Runner.php",
            concat!(
                "<?php\n",
                "namespace App;\n",
                "use App\\Model\\Gadget;\n",
                "use App\\Model\\Widget;\n",
                "class Runner { public function run() { return new gadget(); } }\n",
            ),
        );
        assert_eq!(fixture.unused_names(), ["Widget"]);
    }

    /// A language whose adapter derives no import binders reports nothing for
    /// the same shape, and says so.
    #[test]
    fn go_reports_nothing_because_it_derives_no_import_binders() {
        let fixture = Fixture::new(
            Language::Go,
            "app/main.go",
            concat!(
                "package main\n",
                "import (\n",
                "\t\"fmt\"\n",
                "\t_ \"embed\"\n",
                "\t\"os\"\n",
                ")\n",
                "func main() { fmt.Println(\"hi\") }\n",
            ),
        );
        assert_eq!(
            fixture.result().completeness,
            UnusedImportsCompleteness::Incomplete(
                UnusedImportsIncompleteReason::LanguageUnsupported(
                    UnusedImportSupport::NoImportBinders
                )
            )
        );
    }
}
