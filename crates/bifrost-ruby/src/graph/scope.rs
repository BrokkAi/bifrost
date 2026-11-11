use crate::graph::resolver::ReceiverMode;
use crate::graph::syntax::method_receiver_mode;
use tree_sitter::Node;

/// The lexical and receiver scopes a Ruby tree walk is inside.
///
/// Every walker enters and leaves the same four scope kinds, so one frame
/// stack owns both sides of each transition. The receiver context and the
/// method receiver mode are read off the frames; only the lexical owners are
/// kept as a slice because constant lookup consumes them that way. `S` is the
/// walker's saved local-binding state, returned on exit so the walker can
/// restore it.
pub struct RubyScopeStack<S> {
    frames: Vec<RubyScopeFrame<S>>,
    lexical: Vec<String>,
}

/// One entered scope, returned by [`RubyScopeStack::exit`] with the state the
/// walker saved when it entered.
pub enum RubyScopeFrame<S> {
    /// A class or module body. `owner` is false when the declaration did not
    /// resolve to an owner, so it pushed no lexical scope.
    Type {
        owner: bool,
        saved: S,
    },
    Method {
        mode: ReceiverMode,
        saved: S,
    },
    SingletonClass {
        saved: S,
    },
    Block,
}

impl<S> RubyScopeFrame<S> {
    /// The state saved on entry, or `None` for a block, which shares its
    /// enclosing local bindings.
    pub fn into_saved(self) -> Option<S> {
        match self {
            Self::Type { saved, .. }
            | Self::Method { saved, .. }
            | Self::SingletonClass { saved } => Some(saved),
            Self::Block => None,
        }
    }
}

impl<S> Default for RubyScopeStack<S> {
    fn default() -> Self {
        Self {
            frames: Vec::new(),
            lexical: Vec::new(),
        }
    }
}

impl<S> RubyScopeStack<S> {
    pub fn enter_type(&mut self, owner: Option<String>, saved: S) {
        let resolved = owner.is_some();
        self.lexical.extend(owner);
        self.frames.push(RubyScopeFrame::Type {
            owner: resolved,
            saved,
        });
    }

    pub fn enter_method(&mut self, node: Node<'_>, saved: S) {
        let mode = method_receiver_mode(node, self.receiver_context());
        self.frames.push(RubyScopeFrame::Method { mode, saved });
    }

    pub fn enter_singleton_class(&mut self, saved: S) {
        self.frames.push(RubyScopeFrame::SingletonClass { saved });
    }

    pub fn enter_block(&mut self) {
        self.frames.push(RubyScopeFrame::Block);
    }

    pub fn exit(&mut self) -> RubyScopeFrame<S> {
        let frame = self
            .frames
            .pop()
            .expect("a Ruby scope exit must follow its enter");
        if let RubyScopeFrame::Type { owner: true, .. } = frame {
            self.lexical.pop();
        }
        frame
    }

    /// Enclosing resolved class and module owners, outermost first.
    pub fn lexical(&self) -> &[String] {
        &self.lexical
    }

    /// The implicit receiver of the innermost class-like body: instance side
    /// in a class or module body, class side in `class << self`.
    pub fn receiver_context(&self) -> Option<ReceiverMode> {
        self.frames.iter().rev().find_map(|frame| match frame {
            RubyScopeFrame::Type { .. } => Some(ReceiverMode::Instance),
            RubyScopeFrame::SingletonClass { .. } => Some(ReceiverMode::Class),
            RubyScopeFrame::Method { .. } | RubyScopeFrame::Block => None,
        })
    }

    /// The receiver side of the innermost method body; a `class << self` body
    /// counts as class side.
    pub fn method_mode(&self) -> Option<ReceiverMode> {
        self.frames.iter().rev().find_map(|frame| match frame {
            RubyScopeFrame::Method { mode, .. } => Some(*mode),
            RubyScopeFrame::SingletonClass { .. } => Some(ReceiverMode::Class),
            RubyScopeFrame::Type { .. } | RubyScopeFrame::Block => None,
        })
    }
}

// Ruby evaluates a type declaration's header in the enclosing scope. Its body
// starts the new lexical owner and isolates local bindings.
pub(crate) fn ruby_type_body_declaration(
    node: tree_sitter::Node<'_>,
) -> Option<tree_sitter::Node<'_>> {
    let declaration = node.parent()?;
    (matches!(declaration.kind(), "class" | "module")
        && declaration.child_by_field_name("body") == Some(node))
    .then_some(declaration)
}
