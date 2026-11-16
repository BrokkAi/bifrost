//! Query-owned no-access proofs for reviewed standard macro expansions.

use crate::RustAnalyzer;
use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
use brokk_bifrost_analysis::analyzer::{IAnalyzer, resolve_analyzer};
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_rust::format_args::{
    RustFormatArgumentReference, RustMacroRuntimeArgument, parse_rust_format_string,
    rust_formatting_macro, rust_macro_runtime_layout,
};
pub use brokk_bifrost_rust::macro_matcher::MacroDefinitionInventory;
use brokk_bifrost_rust::macro_matcher::{
    StandardMacroIdentity, parse_macro_operands, standard_macro_identity,
};
use brokk_bifrost_rust::usage_walks::RustUsageWalks;

/// An over-approximation of all call-site local names a proved expansion can
/// access. `None` from the producer is an opaque expansion, never NoAccess.
#[derive(Debug)]
pub struct RustMacroBindingAccess {
    names: HashSet<String>,
}

impl RustMacroBindingAccess {
    /// ASCII names whose call-site access could not be excluded by the proof.
    pub fn accessed_names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }

    pub fn may_access(&self, name: &str) -> bool {
        let name = strip_raw_identifier_prefix(name);
        // NFC is the identity operation on ASCII. Until a Unicode normalizer
        // is available here, every non-ASCII name or token keeps access open.
        !name.is_ascii() || self.names.contains(name)
    }
}

/// Prove one invocation using the native macro namespace and operand grammar.
/// Callers must keep this result query-local and capture the resolution reads.
/// The definition inventory is prepared once per file by the caller. The lazy
/// walk wrapper borrows this call's query scope and cancellation predicate; its
/// construction does not scan the file, and its shared caches replay reads.
pub fn rust_macro_binding_access(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    inventory: &MacroDefinitionInventory,
    range: std::ops::Range<usize>,
    keep_going: &dyn Fn() -> bool,
) -> Option<RustMacroBindingAccess> {
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
    let scope = AnalyzerQueryScope::new(analyzer);
    brokk_bifrost_rust::graph_support::with_usage_read_frame(rust, || {
        let walks = RustUsageWalks::new_while(rust, scope.token(), keep_going).ok()?;
        let source = syntax.source();
        let root = syntax.tree().root_node();
        let exported = inventory.exported();
        let requested = range;
        let mut lexical_context = root.descendant_for_byte_range(requested.start, requested.end)?;
        // Structural facts can anchor invocations inside opaque token trees.
        // Prove the enclosing invocation and its parsed operands, then require
        // that the requested exact invocation was among those certified below.
        while lexical_context.kind() != "macro_invocation" {
            lexical_context = lexical_context.parent()?;
        }
        let mut requested_proved = false;
        let mut names = HashSet::default();
        let mut fragments: Vec<tree_sitter::Tree> = Vec::new();
        let mut pending = vec![(None, lexical_context.byte_range())];
        while let Some((fragment, range)) = pending.pop() {
            if !keep_going() {
                return None;
            }
            let tree = fragment.map_or(syntax.tree(), |index: usize| &fragments[index]);
            let invocation = tree
                .root_node()
                .descendant_for_byte_range(range.start, range.end)?;
            if invocation.kind() != "macro_invocation" || invocation.byte_range() != range {
                return None;
            }
            let StandardMacroIdentity::Standard {
                owner,
                member: name,
            } = standard_macro_identity(
                rust,
                &walks,
                file,
                invocation,
                source,
                Some(&exported),
                lexical_context,
                &fragments,
            )
            else {
                return None;
            };
            // This is a resolved identity allowlist, never a spelling gate.
            if !matches!(
                owner,
                brokk_bifrost_rust::macro_matcher::StandardMacroOwner::Std
                    | brokk_bifrost_rust::macro_matcher::StandardMacroOwner::Core
                    | brokk_bifrost_rust::macro_matcher::StandardMacroOwner::Alloc
            ) || !matches!(
                name.as_ref(),
                "format"
                    | "print"
                    | "println"
                    | "eprint"
                    | "eprintln"
                    | "write"
                    | "writeln"
                    | "panic"
                    | "format_args"
                    | "assert"
                    | "assert_eq"
                    | "assert_ne"
                    | "debug_assert"
                    | "debug_assert_eq"
                    | "debug_assert_ne"
            ) {
                return None;
            }
            requested_proved |= invocation.byte_range() == requested;
            let tokens =
                brokk_bifrost_rust::declarations::rust_macro_invocation_arguments(invocation)?;
            let mut stack = vec![tokens];
            while let Some(node) = stack.pop() {
                if !keep_going() || node.has_error() || node.is_missing() {
                    return None;
                }
                match node.kind() {
                    kind if brokk_bifrost_rust::declarations::rust_identifier_like_node_kind(
                        kind,
                    ) || matches!(
                        kind,
                        "primitive_type" | "self" | "reserved_identifier" | "_reserved_identifier"
                    ) =>
                    {
                        let name = strip_raw_identifier_prefix(
                            brokk_bifrost_rust::declarations::rust_node_text(node, source),
                        );
                        if !name.is_ascii() {
                            return None;
                        }
                        names.insert(name.to_owned());
                    }
                    "string_literal" | "raw_string_literal" => continue,
                    _ => {}
                }
                let mut cursor = node.walk();
                stack.extend(node.children(&mut cursor));
            }
            let operands = parse_macro_operands(invocation, source)?;
            let format_index = rust_macro_runtime_layout(owner.as_str(), &name)
                .and_then(|layout| {
                    layout.arguments.iter().find_map(|argument| match argument {
                        RustMacroRuntimeArgument::Message { first_operand }
                        | RustMacroRuntimeArgument::OptionalMessage { first_operand } => {
                            Some(*first_operand)
                        }
                        _ => None,
                    })
                })
                .or_else(|| {
                    rust_formatting_macro(&name)
                        .map(|format| usize::from(format.has_writer_receiver()))
                })?;
            // Optional messages are absent on assertions and zero-argument
            // println!/panic!. When present, a message must be a literal.
            if let Some(format) = operands.get(format_index) {
                if !matches!(
                    format.node().kind(),
                    "string_literal" | "raw_string_literal"
                ) {
                    return None;
                }
                let literal = brokk_bifrost_rust::cargo_routes::rust_static_string_literal(
                    format.node(),
                    source,
                )?;
                let format = parse_rust_format_string(&literal).ok()?;
                for reference in &format.references {
                    if let RustFormatArgumentReference::Name(name) = reference {
                        if !name.is_ascii() {
                            return None;
                        }
                        names.insert(name.to_string());
                    }
                }
            }
            // Token trees do not expose nested invocation syntax. The shared
            // fragment parser does; retain its trees and certify each nested
            // invocation with the same lexical context and enclosing fragments.
            for operand in operands {
                let mut nested = Vec::new();
                let mut stack = vec![operand.node()];
                while let Some(node) = stack.pop() {
                    if !keep_going() || node.has_error() || node.is_missing() {
                        return None;
                    }
                    if node.kind() == "macro_invocation" {
                        nested.push(node.byte_range());
                        continue;
                    }
                    let mut cursor = node.walk();
                    stack.extend(node.children(&mut cursor));
                }
                let index = fragments.len();
                fragments.push(operand.tree);
                pending.extend(nested.into_iter().map(|range| (Some(index), range)));
            }
        }
        requested_proved.then_some(RustMacroBindingAccess { names })
    })
}
