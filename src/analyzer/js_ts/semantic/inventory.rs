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

pub(super) enum ProcedureEnumeration<'tree> {
    Complete(Vec<ProcedureSpec<'tree>>),
    ExceededBudget {
        exceeded: SemanticBudgetExceeded,
        work: SemanticWork,
    },
    Cancelled,
}

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
    let mount = WorkspaceMountId::from_root(file.root());
    let path = WorkspaceRelativePath::try_from_path(file.rel_path())
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let language = prepared.dialect();
    let file_anchor = source_anchor(prepared.tree().root_node(), 0)
        .map_err(SemanticProviderError::invalid_identity)?;
    let fallback_file_name = match language.language() {
        Language::JavaScript => "javascript-source",
        Language::TypeScript => "typescript-source",
        _ => unreachable!("the shared lowerer validates a JavaScript or TypeScript dialect"),
    };
    let file_name = file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback_file_name);
    let file_segment =
        DeclarationSegment::named(DeclarationSegmentKind::File, file_name, file_anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;

    type SiblingKey = (usize, DeclarationSegmentKind, Option<Box<str>>);
    let mut specs: Vec<ProcedureSpec<'tree>> = Vec::new();
    let mut siblings: HashMap<SiblingKey, u32> = HashMap::default();
    let mut declaration_paths = vec![DeclarationPathEntry {
        parent: None,
        segment: file_segment,
    }];
    let mut preflight = SemanticWork::default();
    let root = prepared.tree().root_node();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: 0,
    }];
    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(ProcedureEnumeration::Cancelled);
        }
        let ProcedureEnumerationFrame {
            node,
            lexical_parent,
            declaration_path,
        } = frame;
        let mut outer_path = declaration_path;
        if let Some(segment_kind) = declaration_container_kind(node) {
            let name = declaration_container_name(prepared.source(), node);
            let sibling_ordinal = next_sibling_ordinal(
                &mut siblings,
                declaration_path,
                segment_kind,
                name.as_deref(),
            );
            let anchor = source_anchor(node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let segment =
                declaration_segment(segment_kind, name.as_deref(), anchor, sibling_ordinal)
                    .map_err(SemanticProviderError::invalid_identity)?;
            outer_path = push_declaration_path(&mut declaration_paths, declaration_path, segment);
        }

        let mut procedure_context = None;
        if let Some((mut kind, mut segment_kind, body, properties)) = callable_shape(node) {
            let id = ProcedureId::try_from_index(specs.len())
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let name = callable_name(prepared.source(), node);
            if name.as_deref() == Some("constructor") {
                kind = ProcedureKind::Constructor;
                segment_kind = DeclarationSegmentKind::Constructor;
            }
            let sibling_ordinal =
                next_sibling_ordinal(&mut siblings, outer_path, segment_kind, name.as_deref());
            let anchor = source_anchor(node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let segment =
                declaration_segment(segment_kind, name.as_deref(), anchor, sibling_ordinal)
                    .map_err(SemanticProviderError::invalid_identity)?;
            let mut segments = collect_declaration_path(&declaration_paths, outer_path);
            segments.push(segment.clone());
            let declaration = DeclarationLocator::new(segments)
                .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
            let locator = SemanticLocator::new(
                mount,
                path.clone(),
                language,
                declaration,
                SemanticRole::Procedure,
                anchor,
            );
            let candidate = sum_lowering_work(preflight, procedure_identity_preflight(&locator));
            if let Err(exceeded) = budget.check(candidate) {
                return Ok(ProcedureEnumeration::ExceededBudget {
                    exceeded,
                    work: candidate,
                });
            }
            preflight = candidate;
            let captures_receiver = if kind == ProcedureKind::Lambda {
                match body_contains_free_this(body, cancellation) {
                    Ok(captures_receiver) => captures_receiver,
                    Err(LoweringCancelled) => return Ok(ProcedureEnumeration::Cancelled),
                }
            } else {
                false
            };
            specs.push(ProcedureSpec {
                id,
                body,
                locator,
                lexical_parent,
                kind,
                properties,
                callable: node,
                captures_receiver,
            });
            let procedure_path = push_declaration_path(&mut declaration_paths, outer_path, segment);
            procedure_context = Some((id, procedure_path));
        }

        if node.kind() == "decorator" {
            continue;
        }

        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            let (child_parent, child_path) = match procedure_context {
                Some((procedure, procedure_path))
                    if callable_child_belongs_to_procedure(node, child) =>
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
    Ok(ProcedureEnumeration::Complete(specs))
}
