//! The byte regions a C# file-scoped `namespace X;` governs.
//!
//! A file-scoped namespace declaration has no body: the grammar makes it a
//! compilation-unit child, and the declarations it governs are its following
//! siblings. Every reader that asks "which file-scoped namespace governs this
//! byte" reads this one index instead of re-walking the compilation unit.
//!
//! A valid C# file has at most one file-scoped namespace (CS8954), and it
//! precedes every member, so for valid code the queries below agree. Parser
//! recovery and editor input can produce repeated declarations, and there the
//! readers answer under different named policies (#8957):
//!
//! - [`CSharpFileScopedNamespaces::nearest_at`]: the nearest preceding
//!   declaration. Transient lookup contexts and semantic declarations use it.
//! - [`CSharpFileScopedNamespaces::governing_at`]: every preceding declaration
//!   in source order. Persisted CodeUnit naming joins them, which is also how
//!   Roslyn nests a repeated declaration inside the previous one.
//! - [`CSharpFileScopedNamespaces::first`]: the file's first declaration,
//!   whatever the byte. Extension-method visibility and the semantic
//!   procedure inventory's root path use it.
//!
//! Alternative declarations in one `#if`/`#else` chain never reach these
//! policies. Every C# parse hides directive lines and every branch the
//! preprocessor did not keep (`preprocessor::parse_csharp`), so the tree holds
//! one declaration: the active branch's when the chain is decided, and the
//! earliest possibly active branch's when it is undecided. The undecided case
//! records the `csharp_conditional_branch_unseen` read obligation for the file,
//! which is how a consumer learns the other reading exists.
//!
//! The resolution-fact producer (`resolution::produce`) is a fifth reader that
//! does not use this index: it allocates one lexical scope per namespace while
//! it streams the whole tree, so it carries the governing declaration as walk
//! state. It joins repeated declarations as persisted naming does. It also
//! treats a `preproc_if` container as transparent and skips the scan's
//! excluded branches, which matters only for a tree parsed without included
//! ranges; on the production tree it sees the same declarations as this index.
//!
//! Converging these policies changes persisted names or resolver answers for
//! malformed input, so it needs an owner decision and the matching cache
//! identity levers; until then the policies are stated here, once.

use brokk_bifrost_core::analyzer::scope_regions::{ScopeRegions, ScopeRegionsBuilder};
use tree_sitter::Node;

/// The file-scoped namespace declarations that are direct children of one
/// compilation unit, and the byte regions each governs.
#[derive(Debug, Clone)]
pub struct CSharpFileScopedNamespaces<'tree> {
    declarations: Vec<Node<'tree>>,
    /// `[declaration_i.end, declaration_{i+1}.end)` maps to `i`; the last
    /// region runs past the end of the source. A byte inside the next
    /// declaration's own header is still governed by the previous one.
    regions: ScopeRegions<usize>,
}

impl<'tree> CSharpFileScopedNamespaces<'tree> {
    /// Index the file-scoped namespace declarations among `root`'s children.
    /// `step` is polled once per child; `None` means the caller's bounded
    /// query stopped first.
    pub fn from_root(root: Node<'tree>, step: impl FnMut() -> bool) -> Option<Self> {
        Self::through(root, usize::MAX, step)
    }

    /// Index only the children that start at or before `through`: enough to
    /// answer [`Self::nearest_at`] and [`Self::governing_at`] for any byte at
    /// or before it, while a bounded lookup near the top of a large file polls
    /// `step` for the prefix alone.
    pub fn through(
        root: Node<'tree>,
        through: usize,
        mut step: impl FnMut() -> bool,
    ) -> Option<Self> {
        debug_assert!(root.parent().is_none(), "a compilation unit has no parent");
        let mut declarations = Vec::new();
        let mut cursor = root.walk();
        for child in root.named_children(&mut cursor) {
            if !step() {
                return None;
            }
            if child.start_byte() > through {
                break;
            }
            if child.kind() == "file_scoped_namespace_declaration" {
                declarations.push(child);
            }
        }
        let mut regions = ScopeRegionsBuilder::default();
        for (index, declaration) in declarations.iter().enumerate() {
            let end = declarations
                .get(index + 1)
                .map_or(usize::MAX, Node::end_byte);
            regions.push(declaration.end_byte()..end, index);
        }
        Some(Self {
            declarations,
            regions: regions.finish(),
        })
    }

    /// Index the compilation unit that contains `node`.
    pub fn of_node(node: Node<'tree>) -> Self {
        let mut root = node;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        Self::from_root(root, || true).expect("an unbounded walk completes")
    }

    /// The nearest declaration that ends at or before `byte`.
    pub fn nearest_at(&self, byte: usize) -> Option<Node<'tree>> {
        self.governing_at(byte).last().copied()
    }

    /// Every declaration that ends at or before `byte`, in source order.
    pub fn governing_at(&self, byte: usize) -> &[Node<'tree>] {
        self.regions
            .value_at(byte)
            .map_or(&[], |index| &self.declarations[..=*index])
    }

    /// The first declaration in the compilation unit, whatever the byte.
    pub fn first(&self) -> Option<Node<'tree>> {
        self.declarations.first().copied()
    }
}
