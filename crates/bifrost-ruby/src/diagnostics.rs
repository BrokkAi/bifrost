//! Ruby's semantic diagnostics: proof-gated unresolved-constant reporting.
//!
//! Every candidate this pass reaches leaves one typed outcome in the
//! [`SemanticDiagnosticReport`]: a resolution, a complete absence proof, or a
//! typed reason why absence could not be proven. A candidate is never dropped
//! in silence, and an error is only ever published behind a
//! [`SemanticAbsenceProof`] over a surface that was complete.
//!
//! Unlike Go's, Python's and PHP's, Ruby's pass routes through the *graph*
//! semantic index rather than a `BoundedDefinitionLookup`, so it follows
//! `graph::resolver` across the crate line rather than being independently
//! movable. `analyzer/ruby/diagnostics.rs` in `brokk-bifrost-analysis` keeps the
//! downcast that produces the arguments and implements [`RubyGemSurface`], which
//! is what this crate cannot name: the activated semantic-model overlay and the
//! retained gem-discovery evidence.
//!
//! # What this pass judges
//!
//! Exactly one candidate shape: the terminal of an explicit constant path
//! (`Widget::Config`). Each terminal is checked against two surfaces, the
//! visible workspace closure and the activated gem packs, and reported absent
//! only when the surface that owns it was complete.
//!
//! # What this pass does not judge, and why
//!
//! A **bare constant** (`Widget`, `String`) is not a candidate. Ruby's top-level
//! constant surface includes the core library, everything `Object` inherits, and
//! whatever every loaded gem defined as a side effect. Bifrost publishes no core
//! Ruby surface, so a miss against the surfaces this pass can see would prove
//! nothing about a name that Ruby itself supplies.
//!
//! A **method** is not a candidate either, and this is not a temporary gap. Gem
//! packs publish a gem's own declarations and nothing above them: there is no
//! published `Object`, `Module`, `Class`, `Kernel` or `BasicObject`, and
//! `SemanticModelOverlay::universal_root_for_language` supplies an implicit root
//! only for Java and Scala. So even a gem whose surface is fully RBS-complete is
//! missing `new`, `name`, `send`, `freeze` and every other inherited member, and
//! a member miss against it would be a false positive on the very first line of
//! ordinary code (`Widget.new`). `method_missing`, `define_method`,
//! `class << self` and `extend` widen the same surface further at run time.
//! Proving a Ruby member absent needs a published core ancestry that does not
//! exist yet, so this pass never asks the question. See #1624.

use crate::declarations::{extract_name_path, parse_ruby_tree};
use crate::graph::RubyGraphSource;
use crate::graph::extractor::ruby_type_owner;
use crate::graph::resolver::RubySemanticIndex;
use crate::graph::syntax::is_declaration_constant;
use crate::graph_support::RubySource;
use crate::imports::{parse_ruby_require_call, ruby_symbol_name, ruby_zeitwerk_visible_files_for};
use crate::syntax::single_static_string_content_node;
use brokk_bifrost_core::analyzer::model::{
    Range, SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::compute_line_starts;
use std::borrow::Cow;
use tree_sitter::Node;

pub const RUBY_UNRECOGNIZED_SYMBOL: &str = "ruby_unrecognized_symbol";
pub const RUBY_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-ruby";
const MAX_RUBY_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
pub const MAX_RUBY_SEMANTIC_DIAGNOSTICS: usize = 200;
pub const MAX_RUBY_DIAGNOSTIC_VISIBLE_FILES: usize = 64;
pub const MAX_RUBY_DIAGNOSTIC_VISIBLE_SOURCE_BYTES: usize = 2 * 1024 * 1024;

/// What the analyzer's retained gem evidence proves about one name a Ruby file
/// reaches outside the visible workspace closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RubyGemBoundary {
    /// An activated gem pack publishes the name.
    Indexed,
    /// An activated gem pack owns the name's namespace, claims that surface
    /// complete, and does not publish the name. The absence is therefore proven
    /// at [`BoundaryStatus::ExternalIndexed`], in the carried domain.
    Absent(SemanticDiagnosticDomain),
    /// No activated pack owns the namespace at all, so the packs say nothing
    /// either way. The reason states how far retained discovery could see, so a
    /// caller with its own complete surface can still prove absence on that one.
    Unpublished(SemanticDiagnosticIncompleteReason),
    /// A pack owns the namespace but retained state cannot decide, for this
    /// typed reason.
    Incomplete(SemanticDiagnosticIncompleteReason),
}

/// The retained gem surface a Ruby diagnostic request may read.
///
/// Every method answers only from state a host already published. An
/// implementation must never run Bundler, read a gem archive, walk a gem
/// directory, or start dependency discovery: a missing answer is
/// [`RubyGemBoundary::Unpublished`] or [`RubyGemBoundary::Incomplete`], never a
/// blocking call.
pub trait RubyGemSurface {
    /// Classify `terminal` under the constant path `owner_path`, which is the
    /// AST-derived segment list of the reference's `scope` (`["Widget"]` for
    /// `Widget::Config`) and is never empty.
    fn constant_boundary(&self, owner_path: &[String], terminal: &str) -> RubyGemBoundary;

    /// Classify the gem that a `require` argument loads. Never `Absent`: a load
    /// path that no pack covers is a boundary this pass cannot see past, not a
    /// missing file.
    fn require_boundary(&self, require_path: &str) -> RubyGemBoundary;
}

/// A surface that has acquired nothing. Every boundary is unknown, which is the
/// honest answer for an analyzer no host has activated gem packs on.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnacquiredRubyGems;

impl RubyGemSurface for UnacquiredRubyGems {
    fn constant_boundary(&self, _owner_path: &[String], _terminal: &str) -> RubyGemBoundary {
        RubyGemBoundary::Unpublished(unknown_dependency_reason())
    }

    fn require_boundary(&self, _require_path: &str) -> RubyGemBoundary {
        RubyGemBoundary::Unpublished(unknown_dependency_reason())
    }
}

fn unknown_dependency_reason() -> SemanticDiagnosticIncompleteReason {
    SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
        boundary: BoundaryStatus::ExternalUnknown,
    }
}

/// Collect Ruby semantic diagnostics and the proof or suppression behind each.
pub fn collect_ruby_semantic_diagnostics(
    graph: RubyGraphSource<'_>,
    ruby: &dyn RubySource,
    gems: &dyn RubyGemSurface,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_RUBY_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let Some(tree) = parse_ruby_tree(source) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Ruby source did not parse".to_string(),
            }],
        );
        return report;
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        // The parse errors themselves reach the host through the analyzer's
        // parse-diagnostic path. What the semantic report records is that the
        // tree this pass would have judged is not trustworthy, so no name in
        // the file was checked at all.
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Ruby source has parse errors".to_string(),
            }],
        );
        return report;
    }
    if let Some(detail) = open_runtime_boundary_detail(tree.root_node(), source) {
        // A run-time constant boundary makes every constant in the file
        // unjudgeable: the set of bindings is decided while the program runs.
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::DynamicBehavior { detail }],
        );
        return report;
    }
    if let Some(reason) = unresolved_load_directive_reason(ruby, gems, file) {
        report.push_incomplete(None, vec![reason]);
        return report;
    }

    let semantic = RubySemanticIndex::build_for_lookup(graph, ruby);
    let Some(mut visible_files) =
        semantic.visible_files_from_bounded(file, MAX_RUBY_DIAGNOSTIC_VISIBLE_FILES)
    else {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    };
    // Zeitwerk widens what the file can see rather than blinding the pass: the
    // autoloaded tree is visible to every consumer, so its declarations resolve.
    // What it also does is let the *file tree* define a constant this pass never
    // reads, through an inflection or a custom loader root Bifrost does not
    // model, so a miss under Zeitwerk stays unproven (`zeitwerk_open`).
    let zeitwerk_open = match ruby_zeitwerk_visible_files_for(ruby, file) {
        Some(zeitwerk_files) => {
            visible_files.extend(zeitwerk_files.iter().cloned());
            if visible_files.len() > MAX_RUBY_DIAGNOSTIC_VISIBLE_FILES {
                report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                return report;
            }
            true
        }
        None => false,
    };
    if let Some(reason) = visible_surface_reason(graph, ruby, gems, file, source, &visible_files) {
        report.push_incomplete(None, vec![reason]);
        return report;
    }

    let line_starts = compute_line_starts(source);
    let mut collector = RubyDiagnosticCollector {
        semantic,
        ruby,
        gems,
        file,
        source,
        line_starts: &line_starts,
        visible_files,
        zeitwerk_open,
        report,
    };
    collector.scan_tree(tree.root_node());
    collector.report
}

struct RubyDiagnosticCollector<'a> {
    semantic: RubySemanticIndex<'a>,
    ruby: &'a dyn RubySource,
    gems: &'a dyn RubyGemSurface,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    visible_files: HashSet<ProjectFile>,
    /// Whether Zeitwerk can define a constant from the project file tree that
    /// this pass did not read, which downgrades every absence to unproven.
    zeitwerk_open: bool,
    report: SemanticDiagnosticReport,
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitNamespace(usize),
}

impl RubyDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut lexical_stack = Vec::new();
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.report.diagnostics().len() >= MAX_RUBY_SEMANTIC_DIAGNOSTICS {
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                return;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(node, &mut lexical_stack, &mut stack),
                ScanFrame::ExitNamespace(len) => lexical_stack.truncate(len),
            }
        }
    }

    fn scan_node<'tree>(
        &mut self,
        node: Node<'tree>,
        lexical_stack: &mut Vec<String>,
        stack: &mut Vec<ScanFrame<'tree>>,
    ) {
        match node.kind() {
            "class" | "module" => {
                let Some(owner) = ruby_type_owner(
                    &self.semantic,
                    self.file,
                    &self.visible_files,
                    lexical_stack,
                    node,
                    self.source,
                ) else {
                    // The declaration's own owner did not resolve, so no
                    // constant inside it can be placed in a namespace.
                    self.report.push_incomplete(
                        Some(node_range(node, self.line_starts)),
                        vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                            detail: "declaration namespace did not resolve".to_string(),
                        }],
                    );
                    return;
                };
                let previous_len = lexical_stack.len();
                lexical_stack.push(owner);
                stack.push(ScanFrame::ExitNamespace(previous_len));
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push(ScanFrame::Node(body));
                }
            }
            "scope_resolution" => self.check_explicit_path(node, lexical_stack),
            // A bare constant is not a candidate: see this module's header.
            "constant" => {}
            "assignment" | "operator_assignment" => {
                if let Some(right) = node.child_by_field_name("right") {
                    stack.push(ScanFrame::Node(right));
                }
            }
            "string" | "comment" => {}
            _ => push_named_children(stack, node),
        }
    }

    fn check_explicit_path(&mut self, node: Node<'_>, lexical_stack: &[String]) {
        if is_declaration_constant(node) {
            return;
        }
        let Some(owner_node) = node.child_by_field_name("scope") else {
            return;
        };
        let Some(terminal_node) = node.child_by_field_name("name") else {
            return;
        };
        let terminal = node_text(terminal_node, self.source);
        if terminal.is_empty() {
            return;
        }
        let range = node_range(terminal_node, self.line_starts);

        // The visible workspace closure is checked first: a project file that
        // declares the whole path settles the question at the strongest
        // boundary there is, whatever the packs also publish.
        if self
            .semantic
            .resolve_project_local_constant(
                self.file,
                &self.visible_files,
                lexical_stack,
                node,
                self.source,
            )
            .is_some()
        {
            self.report
                .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }

        let owner_path = extract_name_path(owner_node, self.source);
        let owner_unit = self.semantic.resolve_project_local_constant(
            self.file,
            &self.visible_files,
            lexical_stack,
            owner_node,
            self.source,
        );
        match self.gems.constant_boundary(&owner_path.segments, terminal) {
            RubyGemBoundary::Indexed => self
                .report
                .push_resolved(range, BoundaryStatus::ExternalIndexed),
            RubyGemBoundary::Absent(domain) => {
                // A pack proved its own namespace complete and does not
                // publish the terminal. A workspace file that reopens the same
                // namespace can still add it, so the workspace surface has to
                // be complete too before the two agree.
                if let Some(detail) = self.workspace_reopen_detail(owner_unit.as_ref()) {
                    self.report.push_incomplete(
                        Some(range),
                        vec![SemanticDiagnosticIncompleteReason::DynamicBehavior { detail }],
                    );
                    return;
                }
                self.push_absent(range, domain, terminal, BoundaryStatus::ExternalIndexed);
            }
            RubyGemBoundary::Unpublished(reason) => {
                // No pack owns the namespace, so the visible workspace closure
                // is the only surface that can answer.
                match owner_unit {
                    Some(owner) => match self.owner_escape_detail(&owner) {
                        Some(detail) => self.report.push_incomplete(
                            Some(range),
                            vec![SemanticDiagnosticIncompleteReason::DynamicBehavior { detail }],
                        ),
                        None => self.push_absent(
                            range,
                            SemanticDiagnosticDomain::LexicalScope {
                                file: self.file.rel_path().to_path_buf(),
                                range,
                            },
                            terminal,
                            BoundaryStatus::WorkspaceLocal,
                        ),
                    },
                    None => self.report.push_incomplete(Some(range), vec![reason]),
                }
            }
            RubyGemBoundary::Incomplete(reason) => {
                self.report.push_incomplete(Some(range), vec![reason])
            }
        }
    }

    /// Publish one absence, unless Zeitwerk can still define the constant from a
    /// project file this pass did not read.
    fn push_absent(
        &mut self,
        range: Range,
        domain: SemanticDiagnosticDomain,
        terminal: &str,
        boundary: BoundaryStatus,
    ) {
        if self.zeitwerk_open {
            self.report.push_incomplete(
                Some(range),
                vec![SemanticDiagnosticIncompleteReason::DynamicBehavior {
                    detail:
                        "Zeitwerk autoloading can define this constant from the project file tree"
                            .to_string(),
                }],
            );
            return;
        }
        self.report.push_absent(
            SemanticAbsenceProof {
                range,
                domain,
                boundary,
            },
            SemanticDiagnostic {
                range,
                source: RUBY_SEMANTIC_DIAGNOSTIC_SOURCE,
                kind: RUBY_UNRECOGNIZED_SYMBOL,
                message: format!("Unrecognized Ruby constant `{terminal}`"),
            },
        );
    }

    /// Why a workspace declaration of the same namespace keeps a pack's
    /// complete surface from settling the question.
    ///
    /// Ruby classes are open: a project file that reopens a gem's class or
    /// module adds to the surface the pack described, so the pack's completeness
    /// covers only what the gem itself declared.
    fn workspace_reopen_detail(&self, owner: Option<&CodeUnit>) -> Option<String> {
        let owner = owner?;
        Some(self.owner_escape_detail(owner).unwrap_or_else(|| {
            format!(
                "a workspace file reopens `{}`, which an activated gem pack also declares",
                owner.fq_name()
            )
        }))
    }

    /// Why a workspace owner's constant surface is not complete, if it is not.
    fn owner_escape_detail(&self, owner: &CodeUnit) -> Option<String> {
        let fq_name = owner.fq_name();
        if !owner.is_module() {
            return Some(format!(
                "class `{fq_name}` can inherit constants from ancestors this pass does not enumerate"
            ));
        }
        let facts = self.ruby.semantic_facts();
        if facts
            .ancestors
            .get(&fq_name)
            .is_some_and(|ancestors| !ancestors.is_empty())
        {
            return Some(format!(
                "`{fq_name}` has ancestors that can supply constants"
            ));
        }
        if facts.mixin_included_owners.contains_key(&fq_name) {
            return Some(format!(
                "`{fq_name}` includes a module that can supply constants"
            ));
        }
        if facts.mixin_prepended_owners.contains_key(&fq_name) {
            return Some(format!(
                "`{fq_name}` prepends a module that can supply constants"
            ));
        }
        if facts.mixin_class_owners.contains_key(&fq_name) {
            return Some(format!(
                "`{fq_name}` extends a module that can supply constants"
            ));
        }
        None
    }
}

fn push_named_children<'tree>(stack: &mut Vec<ScanFrame<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        stack.push(ScanFrame::Node(child));
    }
}

/// The run-time constant boundary this file opens, named, if it opens one.
fn open_runtime_boundary_detail(root: Node<'_>, source: &str) -> Option<String> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call"
            && let Some(method) = node.child_by_field_name("method")
        {
            let name = node_text(method, source);
            match name {
                "const_get" | "const_set" | "remove_const" | "const_missing" | "class_eval"
                | "module_eval" | "eval" => {
                    return Some(format!(
                        "`{name}` can define or read a constant at run time"
                    ));
                }
                "autoload" => {
                    return Some("`autoload` defers a constant to a run-time load".to_string());
                }
                "require" | "require_relative" | "load"
                    if parse_ruby_require_call(node, source).is_none() =>
                {
                    return Some(format!(
                        "`{name}` takes an argument this pass cannot resolve statically"
                    ));
                }
                _ => {}
            }
        }
        if defines_const_missing_dynamically(node, source) {
            return Some("`const_missing` is defined dynamically".to_string());
        }
        if matches!(node.kind(), "method" | "singleton_method")
            && node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "const_missing")
        {
            return Some("`const_missing` is defined in this file".to_string());
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

fn defines_const_missing_dynamically(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "call" {
        return false;
    }
    let Some(method) = node.child_by_field_name("method") else {
        return false;
    };
    if !matches!(
        node_text(method, source),
        "define_method" | "define_singleton_method"
    ) {
        return false;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let Some(name) = arguments.named_children(&mut cursor).next() else {
        return false;
    };
    ruby_symbol_name(name, source).as_deref() == Some("const_missing")
        || single_static_string_content_node(name)
            .is_some_and(|content| node_text(content, source) == "const_missing")
}

/// Why a load directive this file issues keeps its constant surface open.
///
/// A `require` that names no project file loads a gem or a caller-supplied load
/// path. When an activated pack covers that gem the boundary is closed and the
/// gem's declarations answer for it; otherwise the reason states how far
/// retained discovery could see.
fn unresolved_load_directive_reason(
    ruby: &dyn RubySource,
    gems: &dyn RubyGemSurface,
    file: &ProjectFile,
) -> Option<SemanticDiagnosticIncompleteReason> {
    for import in ruby.import_info_of(file).iter() {
        if crate::imports::resolve_required_file(file, import).is_some() {
            continue;
        }
        let Some(load_path) = import.identifier.as_deref() else {
            return Some(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("load directive `{}` names no path", import.raw_snippet),
            });
        };
        if import.raw_snippet.starts_with("require_relative") {
            return Some(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("`require_relative \"{load_path}\"` names no project file"),
            });
        }
        match gems.require_boundary(load_path) {
            RubyGemBoundary::Indexed => {}
            RubyGemBoundary::Unpublished(reason) | RubyGemBoundary::Incomplete(reason) => {
                return Some(reason);
            }
            RubyGemBoundary::Absent(_) => {
                unreachable!("require_boundary never proves a load path absent")
            }
        }
    }
    None
}

/// Why the visible closure this file resolves against is not a surface absence
/// can be proven on, if it is not.
fn visible_surface_reason(
    graph: RubyGraphSource<'_>,
    ruby: &dyn RubySource,
    gems: &dyn RubyGemSurface,
    file: &ProjectFile,
    source: &str,
    visible_files: &HashSet<ProjectFile>,
) -> Option<SemanticDiagnosticIncompleteReason> {
    let mut remaining_bytes = MAX_RUBY_DIAGNOSTIC_VISIBLE_SOURCE_BYTES;
    for visible_file in visible_files {
        // The requested file's own directives were classified before the
        // closure was built; every other visible file is classified here
        // against the same activated packs.
        if visible_file != file
            && let Some(reason) = unresolved_load_directive_reason(ruby, gems, visible_file)
        {
            return Some(reason);
        }
        let visible_source = if visible_file == file {
            (source.len() <= remaining_bytes).then_some(Cow::Borrowed(source))
        } else {
            graph
                .index
                .project()
                .read_source_limited(visible_file, remaining_bytes)
                .ok()
                .flatten()
                .map(Cow::Owned)
        };
        let Some(visible_source) = visible_source else {
            return Some(SemanticDiagnosticIncompleteReason::Truncated);
        };
        let Some(next_remaining_bytes) = remaining_bytes.checked_sub(visible_source.len()) else {
            return Some(SemanticDiagnosticIncompleteReason::Truncated);
        };
        remaining_bytes = next_remaining_bytes;
        let Some(tree) = parse_ruby_tree(&visible_source) else {
            return Some(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!(
                    "visible file {} did not parse",
                    visible_file.rel_path().display()
                ),
            });
        };
        let mut parse_errors = Vec::new();
        collect_parse_errors(tree.root_node(), &mut parse_errors);
        if !parse_errors.is_empty() {
            return Some(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!(
                    "visible file {} has parse errors",
                    visible_file.rel_path().display()
                ),
            });
        }
        if let Some(detail) = open_runtime_boundary_detail(tree.root_node(), &visible_source) {
            return Some(SemanticDiagnosticIncompleteReason::DynamicBehavior {
                detail: format!(
                    "visible file {}: {detail}",
                    visible_file.rel_path().display()
                ),
            });
        }
    }
    None
}
