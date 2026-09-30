//! Bounded, class-owned instance-field evidence from structured writes.
use super::*;
use std::collections::hash_map::Entry;

impl BoundedRubyLookupContext<'_, '_> {
    /// Infer a cross-method postcondition, never a value before initialization.
    /// Reopened bodies in this source are scanned in full. Other source files,
    /// inheritance, mixins and dynamic writers leave this domain unsupported.
    pub(super) fn infer_instance_fields(&self) -> HashMap<Box<str>, Option<RubyReceiverType>> {
        let Some(receiver) = self.enclosing_receiver() else {
            return HashMap::default();
        };
        if receiver.mode != RubyReceiverMode::Instance
            || self.provider.overlay.is_none()
            || self.root.has_error()
        {
            return HashMap::default();
        }
        let owners = self.provider.fqn(&receiver.owner_fq_name);
        let [owner] = owners.as_slice() else {
            return HashMap::default();
        };
        if !owner.is_class() || owner.source() != self.file {
            return HashMap::default();
        }
        let Some(mut focus) = ruby_smallest_named_node_covering_bounded(
            self.provider,
            self.root,
            self.focus_start,
            self.focus_start.saturating_add(1),
        ) else {
            return HashMap::default();
        };
        loop {
            if !self.provider.scope_step() {
                return HashMap::default();
            }
            if matches!(focus.kind(), "method" | "singleton_method") {
                if focus
                    .child_by_field_name("name")
                    .is_none_or(|name| ruby_node_text(name, self.source) == "initialize")
                {
                    return HashMap::default();
                }
                break;
            }
            let Some(parent) = focus.parent() else {
                return HashMap::default();
            };
            focus = parent;
        }

        struct Field {
            value: Option<RubyReceiverType>,
            initialized: bool,
        }
        let mut fields: HashMap<Box<str>, Field> = HashMap::default();
        let mut initializers = 0;
        // A method node identifies instance scope; None is the class body.
        let mut pending = vec![(self.root, false, None::<Node<'_>>)];
        while let Some((node, mut target_owner, mut method)) = pending.pop() {
            if !self.provider.scope_step() {
                return HashMap::default();
            }
            match node.kind() {
                "class" | "module" => {
                    let context = Self::build(
                        self.provider,
                        self.file,
                        self.source,
                        self.root,
                        node.start_byte(),
                    );
                    target_owner = node
                        .child_by_field_name("name")
                        .and_then(|name| context.resolve_constant_owner(name))
                        .as_ref()
                        == Some(&receiver.owner_fq_name);
                    method = None;
                    if target_owner
                        && (node.kind() != "class"
                            || node.child_by_field_name("superclass").is_some())
                    {
                        return HashMap::default();
                    }
                }
                "singleton_class" | "singleton_method" => continue,
                "method" if target_owner => {
                    if method.is_some() {
                        return HashMap::default();
                    }
                    if node
                        .child_by_field_name("name")
                        .is_some_and(|name| ruby_node_text(name, self.source) == "initialize")
                    {
                        initializers += 1;
                        if initializers > 1 {
                            return HashMap::default();
                        }
                    }
                    method = Some(node);
                }
                "return" | "rescue" | "rescue_modifier" if target_owner => {
                    if method.is_some_and(|method| {
                        method
                            .child_by_field_name("name")
                            .is_some_and(|name| ruby_node_text(name, self.source) == "initialize")
                    }) {
                        return HashMap::default();
                    }
                }
                "alias" | "undef" if target_owner => return HashMap::default(),
                "call" if target_owner => {
                    let Some(name) = node.child_by_field_name("method") else {
                        return HashMap::default();
                    };
                    let name = ruby_node_text(name, self.source);
                    if matches!(
                        name,
                        "eval"
                            | "instance_eval"
                            | "instance_exec"
                            | "class_eval"
                            | "class_exec"
                            | "module_eval"
                            | "module_exec"
                            | "define_method"
                            | "define_singleton_method"
                            | "send"
                            | "public_send"
                            | "__send__"
                            | "instance_variable_set"
                            | "remove_instance_variable"
                            | "include"
                            | "prepend"
                            | "extend"
                    ) {
                        return HashMap::default();
                    }
                    if method.is_none()
                        && node
                            .child_by_field_name("receiver")
                            .is_none_or(|receiver| receiver.kind() == "self")
                    {
                        match name {
                            "public" | "private" | "protected" => {}
                            "attr_reader" | "attr_writer" | "attr_accessor" => {
                                let writes_field = name != "attr_reader";
                                let Some(arguments) = node.child_by_field_name("arguments") else {
                                    return HashMap::default();
                                };
                                let mut cursor = arguments.walk();
                                for argument in arguments.named_children(&mut cursor) {
                                    if !self.provider.scope_step() {
                                        return HashMap::default();
                                    }
                                    let Some(name) = crate::analyzer::ruby::ruby_symbol_name(
                                        argument,
                                        self.source,
                                    ) else {
                                        return HashMap::default();
                                    };
                                    if name == "initialize" {
                                        return HashMap::default();
                                    }
                                    if writes_field {
                                        fields.insert(
                                            format!("@{name}").into(),
                                            Field {
                                                value: None,
                                                initialized: false,
                                            },
                                        );
                                    }
                                }
                                continue;
                            }
                            _ => return HashMap::default(),
                        }
                    }
                }
                "assignment" | "operator_assignment" | "for" | "exception_variable"
                    if target_owner && method.is_some() =>
                {
                    let Some(left) = node
                        .child_by_field_name("left")
                        .or_else(|| node.child_by_field_name("pattern"))
                        .or_else(|| {
                            (node.kind() == "exception_variable")
                                .then(|| node.named_child(0))
                                .flatten()
                        })
                    else {
                        return HashMap::default();
                    };
                    let method = method.unwrap();
                    let direct = method.child_by_field_name("body") == node.parent();
                    let initializes = direct
                        && method
                            .child_by_field_name("name")
                            .is_some_and(|name| ruby_node_text(name, self.source) == "initialize");
                    let mut targets = vec![left];
                    while let Some(target) = targets.pop() {
                        if !self.provider.scope_step() {
                            return HashMap::default();
                        }
                        if target.kind() == "instance_variable" {
                            let value = if direct && node.kind() == "assignment" && left == target {
                                let context = Self::build(
                                    self.provider,
                                    self.file,
                                    self.source,
                                    self.root,
                                    node.start_byte(),
                                );
                                node.child_by_field_name("right")
                                    .and_then(|right| context.expression_receiver_type(right))
                                    .filter(|value| {
                                        value.mode == RubyReceiverMode::Instance
                                            && RubyOverlayConstants::new(self.provider.overlay)
                                                .unique_type(&value.owner_fq_name)
                                                .is_some()
                                            && self.provider.fqn(&value.owner_fq_name).is_empty()
                                    })
                            } else {
                                None
                            };
                            let name: Box<str> = ruby_node_text(target, self.source).into();
                            match fields.entry(name) {
                                Entry::Vacant(entry) => {
                                    entry.insert(Field {
                                        value,
                                        initialized: initializes,
                                    });
                                }
                                Entry::Occupied(mut entry) => {
                                    let field = entry.get_mut();
                                    if !matches!((&field.value, &value), (Some(a), Some(b))
                                        if a.owner_fq_name == b.owner_fq_name && a.mode == b.mode)
                                    {
                                        field.value = None;
                                    }
                                    field.initialized |= initializes;
                                }
                            }
                        } else if matches!(
                            target.kind(),
                            "left_assignment_list"
                                | "destructured_left_assignment"
                                | "rest_assignment"
                        ) {
                            let mut cursor = target.walk();
                            for child in target.named_children(&mut cursor) {
                                if !self.provider.scope_step() {
                                    return HashMap::default();
                                }
                                targets.push(child);
                            }
                        }
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if !self.provider.scope_step() {
                    return HashMap::default();
                }
                pending.push((child, target_owner, method));
            }
        }
        if initializers != 1 {
            return HashMap::default();
        }
        fields
            .into_iter()
            .map(|(name, field)| (name, field.initialized.then_some(field.value).flatten()))
            .collect()
    }
}
