use super::syntax::*;
use super::*;

pub(super) struct ProcedureSpec<'tree> {
    pub(super) id: ProcedureId,
    pub(super) body: Node<'tree>,
    pub(super) locator: SemanticLocator,
    pub(super) lexical_parent: Option<ProcedureId>,
    pub(super) kind: ProcedureKind,
    pub(super) properties: ProcedureProperties,
    pub(super) callable: Node<'tree>,
    pub(super) captures_receiver: bool,
    /// Whether this procedure publishes a `this` receiver formal: the body
    /// reads `this` directly, or a nested callable captures the receiver from
    /// it (propagated in `lower` after capture demand is settled). A plain
    /// function whose `this` is dead has no receiver formal, so a receiverless
    /// call to it binds completely.
    pub(super) owns_receiver: bool,
}

impl ReceiverCaptureSpec for ProcedureSpec<'_> {
    fn lexical_parent(&self) -> Option<ProcedureId> {
        self.lexical_parent
    }

    fn relays_receiver_capture(&self) -> bool {
        self.kind == ProcedureKind::Lambda
    }

    fn captures_receiver(&self) -> bool {
        self.captures_receiver
    }

    fn require_receiver_capture(&mut self) {
        self.captures_receiver = true;
    }
}

#[derive(Clone, Copy)]
pub(super) struct NestedProcedureTarget {
    pub(super) id: ProcedureId,
    pub(super) receiver_capture_destination: Option<MemoryLocationId>,
}

pub(super) type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<Vec<ProcedureSpec<'tree>>>;

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
}

pub(super) fn enumerate_procedures<'tree>(
    file: &ProjectFile,
    prepared: &'tree PreparedSyntaxTree,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureEnumeration<'tree>, SemanticProviderError> {
    let language = prepared.dialect();
    let fallback_file_name = match language.language() {
        Language::JavaScript => "javascript-source",
        Language::TypeScript => "typescript-source",
        _ => unreachable!("the shared lowerer validates a JavaScript or TypeScript dialect"),
    };
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, language, root, fallback_file_name, budget)?;
    let mut specs: Vec<ProcedureSpec<'tree>> = Vec::new();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: inventory.root_path(),
    }];
    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(inventory.cancelled());
        }
        if let Err(stop) = inventory.charge_traversal_entry() {
            return Ok(stop.into_outcome());
        }
        let ProcedureEnumerationFrame {
            node,
            lexical_parent,
            declaration_path,
        } = frame;
        let mut outer_path = declaration_path;
        if let Some(segment_kind) = declaration_container_kind(node) {
            let name = declaration_container_name(prepared.source(), node);
            let anchor = source_anchor(node, 0).map_err(SemanticProviderError::invalid_identity)?;
            outer_path = inventory.push_container(
                declaration_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )?;
        }

        let mut procedure_context = None;
        if let Some((mut kind, mut segment_kind, body, mut properties)) = callable_shape(node) {
            let name = callable_name(prepared.source(), node);
            if name.as_deref() == Some("constructor") {
                kind = ProcedureKind::Constructor;
                segment_kind = DeclarationSegmentKind::Constructor;
            }
            // A private constructor is TypeScript's closed-dispatch statement:
            // the class cannot be extended, so no override of its members
            // exists (#2717). JavaScript has no accessibility modifiers, so
            // the dialect gate is exact, not conservative.
            if language.language() == Language::TypeScript
                && node.kind() == "method_definition"
                && enclosing_class_has_private_constructor(prepared.source(), node)
            {
                properties.dispatch_extensibility = DispatchExtensibility::Closed;
            }
            let anchor = source_anchor(node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let identity = match inventory.allocate_procedure(
                outer_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )? {
                Ok(identity) => identity,
                Err(stop) => return Ok(stop.into_outcome()),
            };
            let receiver_eligible =
                kind == ProcedureKind::Lambda || procedure_owns_receiver(kind, properties);
            let direct_free_this = if receiver_eligible {
                match body_contains_free_this(body, cancellation) {
                    Ok(direct_free_this) => direct_free_this,
                    Err(LoweringCancelled) => return Ok(inventory.cancelled()),
                }
            } else {
                false
            };
            specs.push(ProcedureSpec {
                id: identity.id,
                body,
                locator: identity.locator,
                lexical_parent,
                kind,
                properties,
                callable: node,
                captures_receiver: kind == ProcedureKind::Lambda && direct_free_this,
                owns_receiver: kind != ProcedureKind::Lambda
                    && receiver_eligible
                    && direct_free_this,
            });
            procedure_context = Some((identity.id, identity.declaration_path));
        }

        if node.kind() == "decorator" {
            continue;
        }

        let mut cursor = node.walk();
        let children = node
            .children(&mut cursor)
            .enumerate()
            .filter(|(_, child)| child.is_named())
            .map(|(index, child)| (child, node.field_name_for_child(index as u32)))
            .collect::<Vec<_>>();
        for (child, field) in children.into_iter().rev() {
            let (child_parent, child_path) = match procedure_context {
                Some((procedure, procedure_path))
                    if callable_field_belongs_to_procedure(node.kind(), field) =>
                {
                    (Some(procedure), procedure_path)
                }
                _ => (lexical_parent, outer_path),
            };
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent: child_parent,
                declaration_path: child_path,
            });
        }
    }
    Ok(inventory.complete(specs))
}
