//! The one place that turns a Go import path into a package identity in the
//! activated semantic-model overlay, and a package member into the overlay
//! symbol that proves it.
//!
//! `get_definition` (`usages::get_definition::go`) and semantic diagnostics
//! (`go::diagnostics`) must answer "which package is this, and does it publish
//! this member" identically. Two parallel implementations would agree only by
//! accident, so both consume this resolver: the import-path lookup, the
//! `Unique`-disposition rule, the `language == "go"` and public-visibility
//! filters, and the two-name member candidate shape all live here once.
//!
//! Every method reads retained overlay state. None of them starts dependency
//! discovery, runs the Go toolchain, or touches a module cache.

use crate::analyzer::GO_MODULE_SCOPE_SEGMENT;
use crate::analyzer::semantic_model::{
    SemanticModelCompleteness, SemanticModelOverlay, SemanticModelOverlayDisposition,
    SemanticModelSymbol, SemanticModelSymbolKind, Signature, TypeRef, Visibility,
};
use brokk_bifrost_go::diagnostics::GoPackageSurface;

/// One exact nominal Go result type published by declaration facts.
///
/// This is intentionally not a general type expression. The caller can use it
/// only as the direct receiver of another modeled call; containers, aliases
/// that would need textual interpretation, and other wrappers never enter the
/// result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoModeledNominalType {
    pub(crate) declaration_id: String,
    pub(crate) qualified_name: String,
    pub(crate) pointer: bool,
}

/// What one activated declaration fact proves about a package-qualified Go
/// expression used as a call target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoModeledPackageCallResolution {
    /// One public package function has a structured signature applicable to
    /// the exact source argument count.
    ExactFunction,
    /// The package publishes the selected name, but it is not that exact
    /// callable (for example a type conversion, constant, or wrong-arity
    /// function call).
    DefinitelyNotApplicable,
    /// Declaration facts mention the selected name, but conflicts or missing
    /// structural facts prevent either a positive or negative call proof.
    Unproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoSignatureApplicability {
    Applicable,
    NotApplicable,
    Unproven,
}

fn go_declared_type_kind(kind: SemanticModelSymbolKind) -> bool {
    matches!(
        kind,
        SemanticModelSymbolKind::Class
            | SemanticModelSymbolKind::Interface
            | SemanticModelSymbolKind::Struct
            | SemanticModelSymbolKind::TypeAlias
    )
}

fn go_signature_applicability(
    signature: &Signature,
    argument_count: usize,
) -> GoSignatureApplicability {
    if signature
        .parameters
        .iter()
        .any(|parameter| parameter.optional)
        || signature
            .parameters
            .iter()
            .take(signature.parameters.len().saturating_sub(1))
            .any(|parameter| parameter.variadic)
    {
        return GoSignatureApplicability::Unproven;
    }

    let applicable = if signature
        .parameters
        .last()
        .is_some_and(|parameter| parameter.variadic)
    {
        argument_count >= signature.parameters.len() - 1
    } else {
        argument_count == signature.parameters.len()
    };
    if applicable {
        GoSignatureApplicability::Applicable
    } else {
        GoSignatureApplicability::NotApplicable
    }
}

/// The activated overlay, read as a Go package index.
#[derive(Clone, Copy)]
pub(crate) struct GoOverlayPackages<'a> {
    overlay: Option<&'a SemanticModelOverlay>,
}

impl<'a> GoOverlayPackages<'a> {
    pub(crate) fn new(overlay: Option<&'a SemanticModelOverlay>) -> Self {
        Self { overlay }
    }

    /// The two qualified names an exact Go API pack can publish `member` of
    /// `import_path` under: the canonical `<path>.<Name>` a type carries, and
    /// the `<path>.<module scope>.<Name>` a package-scope function, variable,
    /// or constant carries.
    ///
    /// Both consumers must search the same pair, otherwise a definition could
    /// resolve a package function that a diagnostic then calls absent.
    pub(crate) fn member_candidates(import_path: &str, member: &str) -> [String; 2] {
        [
            format!("{import_path}.{member}"),
            format!("{import_path}.{GO_MODULE_SCOPE_SEGMENT}.{member}"),
        ]
    }

    fn unique_symbol_across_names<'b>(
        &self,
        qualified_names: impl IntoIterator<Item = &'b str>,
    ) -> Option<&'a SemanticModelSymbol> {
        let overlay = self.overlay?;
        let mut selected = None;
        for qualified_name in qualified_names {
            let matched = overlay.symbols_named(qualified_name);
            match matched.disposition {
                SemanticModelOverlayDisposition::Empty => {}
                SemanticModelOverlayDisposition::Conflict => return None,
                SemanticModelOverlayDisposition::Unique => {
                    let candidate = matched
                        .records
                        .first()
                        .copied()
                        .expect("a unique overlay match contains one record");
                    match selected {
                        None => selected = Some(candidate),
                        Some(existing) if std::ptr::eq(existing, candidate) => {}
                        Some(_) => return None,
                    }
                }
            }
        }
        selected
    }

    /// The unique symbol the overlay publishes under `qualified_name`.
    ///
    /// A name that more than one activated pack claims is deliberately not
    /// unique: the overlay marks it `Conflict` and this returns `None`, so
    /// neither navigation nor a diagnostic picks an arbitrary winner.
    pub(crate) fn unique_symbol(&self, qualified_name: &str) -> Option<&'a SemanticModelSymbol> {
        self.unique_symbol_across_names(std::iter::once(qualified_name))
    }

    /// The sole active Go member with this exact direct owner and name.
    ///
    /// Validate uniqueness before interpreting kind, visibility, receiver, or
    /// signature. Go has no overload sets, so a competing wrong-shape record is
    /// a declaration conflict rather than something a caller may filter away.
    fn unique_go_owner_member(
        &self,
        owner: &SemanticModelSymbol,
        member: &str,
    ) -> Option<&'a SemanticModelSymbol> {
        let mut candidates = self
            .overlay?
            .members_of(&owner.id)
            .records
            .into_iter()
            .filter(|candidate| {
                candidate.language == "go"
                    && candidate.owner_id.as_deref() == Some(owner.id.as_str())
                    && candidate.name == member
            });
        let candidate = candidates.next()?;
        (candidates.next().is_none() && !candidate.provenance.ambiguous).then_some(candidate)
    }

    /// The unique symbol a Go reference may resolve to: one visible, public Go
    /// declaration. A name several packs publish, or one whose only records
    /// are unexported, resolves to nothing.
    pub(crate) fn visible_symbol(&self, qualified_name: &str) -> Option<&'a SemanticModelSymbol> {
        let symbol = self.unique_symbol(qualified_name)?;
        (symbol.language == "go" && symbol.visibility == Visibility::Public).then_some(symbol)
    }

    /// The exact public Go type published under one declaration id.
    ///
    /// Both the id and qualified-name indexes must select the same record.
    /// This prevents a conflicting pack from turning a structured Declared
    /// result reference into an arbitrary source type identity.
    pub(crate) fn declared_type_qualified_name(&self, id: &str) -> Option<&'a str> {
        let matched = self.overlay?.symbols_with_id(id);
        if matched.disposition != SemanticModelOverlayDisposition::Unique {
            return None;
        }
        let declared = matched.records.first().copied()?;
        let named = self.unique_symbol(&declared.qualified_name)?;
        (named.id == declared.id
            && declared.language == "go"
            && declared.owner_id.is_none()
            && go_declared_type_kind(declared.kind)
            && declared.visibility == Visibility::Public
            && !declared.provenance.ambiguous)
            .then_some(declared.qualified_name.as_str())
    }

    /// The `package` clause name an exact API pack records for `import_path`.
    ///
    /// The Go producer emits one module-kind symbol named exactly the import
    /// path whose first alias is the package clause name, which is how an
    /// unaliased `import "example.com/m/postgres"` of `package pg` binds `pg`
    /// rather than `postgres`.
    pub(crate) fn declared_package_name(&self, import_path: &str) -> Option<String> {
        self.unique_symbol(import_path)?.aliases.first().cloned()
    }

    /// How completely the activated packs describe `import_path`.
    pub(crate) fn package_surface(&self, import_path: &str) -> GoPackageSurface {
        let Some(symbol) = self.unique_symbol(import_path) else {
            return GoPackageSurface::Unpublished;
        };
        match symbol.provenance.completeness {
            SemanticModelCompleteness::Complete => GoPackageSurface::Complete,
            SemanticModelCompleteness::Partial => GoPackageSurface::Partial,
        }
    }

    /// The unique visible, public declaration published for one package
    /// member, searching both names a Go pack can store it under.
    pub(crate) fn visible_member(
        &self,
        import_path: &str,
        member: &str,
    ) -> Option<&'a SemanticModelSymbol> {
        let qualified_names = Self::member_candidates(import_path, member);
        let symbol = self.unique_symbol_across_names(qualified_names.iter().map(String::as_str))?;
        self.visible_symbol(&symbol.qualified_name)
            .filter(|visible| std::ptr::eq(*visible, symbol))
    }

    /// Whether the packs publish `member` as a visible, public declaration of
    /// `import_path`, searching both names a Go pack can publish it under.
    pub(crate) fn publishes_member(&self, import_path: &str, member: &str) -> bool {
        self.visible_member(import_path, member).is_some()
    }

    /// Whether any activated Go declaration fact publishes this package name,
    /// including private, ambiguous, or conflicting records. Call resolution
    /// uses this only as a barrier: once a model says the name is some known
    /// declaration, an unsupported call shape must not fall through and mint a
    /// generic external procedure for it.
    pub(crate) fn publishes_any_member_fact(&self, import_path: &str, member: &str) -> bool {
        let Some(overlay) = self.overlay else {
            return false;
        };
        Self::member_candidates(import_path, member)
            .iter()
            .any(|candidate| {
                overlay
                    .symbols_named(candidate)
                    .records
                    .iter()
                    .any(|symbol| symbol.language == "go")
            })
    }

    /// Resolve one package-qualified Go call against positive declaration
    /// facts without turning non-callable package members into procedures.
    ///
    /// The two supported storage names are considered together. If competing
    /// records publish both names, or any required owner/signature fact is
    /// ambiguous, the result stays explicitly unproven. A unique type,
    /// constant, private function, or wrong-arity function is stronger:
    /// positive declaration facts prove that this invocation is not one public
    /// package function, preventing a generic procedure target from being
    /// minted for that name.
    pub(crate) fn package_call_resolution(
        &self,
        import_path: &str,
        member: &str,
        parameter_count: usize,
    ) -> Option<GoModeledPackageCallResolution> {
        let symbol = match self.package_function_symbol(import_path, member)? {
            Ok(symbol) => symbol,
            Err(resolution) => return Some(resolution),
        };
        let signature = symbol
            .structured_signature()
            .expect("package_function_symbol retains a structured signature");
        Some(
            match go_signature_applicability(signature, parameter_count) {
                GoSignatureApplicability::Applicable => {
                    GoModeledPackageCallResolution::ExactFunction
                }
                GoSignatureApplicability::NotApplicable => {
                    GoModeledPackageCallResolution::DefinitelyNotApplicable
                }
                GoSignatureApplicability::Unproven => GoModeledPackageCallResolution::Unproven,
            },
        )
    }

    /// Exact normal-result arity for one applicable modeled package call.
    ///
    /// This is intentionally positive-only. It lets a caller adjudicate Go's
    /// sole-call argument expansion only when the inner package function and
    /// its structured signature are both exact. Missing, conflicting, spread,
    /// or otherwise unsupported inner calls remain unknown.
    pub(crate) fn package_call_result_count(
        &self,
        import_path: &str,
        member: &str,
        parameter_count: usize,
    ) -> Option<usize> {
        let symbol = self.package_function_symbol(import_path, member)?.ok()?;
        let signature = symbol
            .structured_signature()
            .expect("package_function_symbol retains a structured signature");
        (go_signature_applicability(signature, parameter_count)
            == GoSignatureApplicability::Applicable)
            .then_some(match signature.returns.as_ref() {
                None => 0,
                Some(TypeRef::Tuple { elements }) => elements.len(),
                Some(_) => 1,
            })
    }

    fn package_function_symbol(
        &self,
        import_path: &str,
        member: &str,
    ) -> Option<Result<&'a SemanticModelSymbol, GoModeledPackageCallResolution>> {
        let overlay = self.overlay?;
        let symbols = Self::member_candidates(import_path, member)
            .iter()
            .flat_map(|candidate| overlay.symbols_named(candidate).records)
            .filter(|symbol| symbol.language == "go")
            .collect::<Vec<_>>();
        let [symbol] = symbols.as_slice() else {
            return (!symbols.is_empty()).then_some(Err(GoModeledPackageCallResolution::Unproven));
        };
        if symbol.provenance.ambiguous {
            return Some(Err(GoModeledPackageCallResolution::Unproven));
        }
        if symbol.visibility != Visibility::Public
            || symbol.kind != SemanticModelSymbolKind::Function
        {
            return Some(Err(GoModeledPackageCallResolution::DefinitelyNotApplicable));
        }
        if !symbol.is_static() || symbol.has_receiver() {
            return Some(Err(GoModeledPackageCallResolution::Unproven));
        }
        let Some(owner) = self.unique_symbol(import_path) else {
            return Some(Err(GoModeledPackageCallResolution::Unproven));
        };
        if owner.language != "go"
            || owner.owner_id.is_some()
            || owner.kind != SemanticModelSymbolKind::Module
            || owner.provenance.ambiguous
            || symbol.owner_id.as_deref() != Some(owner.id.as_str())
            || symbol.structured_signature().is_none()
        {
            return Some(Err(GoModeledPackageCallResolution::Unproven));
        }
        Some(Ok(symbol))
    }

    /// The unique modeled method selected by one exact concrete Go receiver.
    ///
    /// A positive declaration fact remains useful when its pack is partial:
    /// partiality prevents absence claims, but does not make a published type
    /// or method speculative. The owner must nevertheless be a concrete public
    /// struct, and the method must be a direct public instance member with an
    /// explicit receiver fact. Interfaces, promoted wrapper surfaces, missing
    /// receiver metadata, and competing packs all fail closed.
    pub(crate) fn concrete_receiver_method(
        &self,
        owner_fqn: &str,
        member: &str,
        pointer_receivers: bool,
        parameter_count: usize,
    ) -> Option<&'a SemanticModelSymbol> {
        let owner = self.unique_symbol(owner_fqn)?;
        if owner.language != "go"
            || owner.owner_id.is_some()
            || owner.kind != SemanticModelSymbolKind::Struct
            || owner.visibility != Visibility::Public
        {
            return None;
        }

        let method = self.unique_symbol(&format!("{owner_fqn}.{member}"))?;
        let receiver = method.receiver?;
        (method.language == "go"
            && method.owner_id.as_deref() == Some(owner.id.as_str())
            && method.kind == SemanticModelSymbolKind::Method
            && method.visibility == Visibility::Public
            && !method.is_static()
            && method.structured_signature().is_some_and(|signature| {
                go_signature_applicability(signature, parameter_count)
                    == GoSignatureApplicability::Applicable
            })
            && (!receiver.pointer || pointer_receivers))
            .then_some(method)
    }

    /// The unique public field published directly on one concrete Go struct.
    ///
    /// This is a positive-only lookup. A partial pack may prove a field it
    /// publishes, but a missing field in that pack proves nothing. Competing
    /// declarations, aliases that do not resolve to one nominal owner, and a
    /// method or property with the same spelling all make the lookup abstain.
    pub(crate) fn concrete_receiver_field(
        &self,
        owner_fqn: &str,
        member: &str,
    ) -> Option<&'a SemanticModelSymbol> {
        let owner = self.unique_symbol(owner_fqn)?;
        if owner.language != "go"
            || owner.owner_id.is_some()
            || owner.kind != SemanticModelSymbolKind::Struct
            || owner.visibility != Visibility::Public
            || owner.provenance.ambiguous
        {
            return None;
        }

        let field = self.unique_go_owner_member(owner, member)?;
        (field.kind == SemanticModelSymbolKind::Field
            && field.visibility == Visibility::Public
            && !field.is_static()
            && !field.has_receiver())
        .then_some(field)
    }

    /// The exact nominal result selected from one exact modeled Go callable.
    ///
    /// This is a positive-only declaration-fact lookup. A partial pack may
    /// prove a declaration it publishes, while any missing, competing, or
    /// structurally incomplete fact makes the lookup abstain. Go's multi-value
    /// result is retained as a structured tuple, so `result_ordinal` selects
    /// one exact element rather than conflating the first and later results.
    pub(crate) fn callable_result_nominal_type(
        &self,
        owner_fqn: &str,
        member: &str,
        has_receiver: bool,
        parameter_count: usize,
        result_ordinal: usize,
    ) -> Option<GoModeledNominalType> {
        let overlay = self.overlay?;
        let result = self.callable_result_type_ref(
            owner_fqn,
            member,
            has_receiver,
            parameter_count,
            result_ordinal,
        )?;
        let (declared_id, pointer) = match result {
            TypeRef::Declared {
                id,
                arguments,
                nullable,
            } if arguments.is_empty() && !*nullable => (id, false),
            TypeRef::Pointer { element } => match element.as_ref() {
                TypeRef::Declared {
                    id,
                    arguments,
                    nullable,
                } if arguments.is_empty() && !*nullable => (id, true),
                _ => return None,
            },
            _ => return None,
        };
        let matched = overlay.symbols_with_id(declared_id);
        if matched.disposition != SemanticModelOverlayDisposition::Unique {
            return None;
        }
        let declared = matched.records.first().copied()?;
        if self
            .unique_symbol(&declared.qualified_name)
            .is_none_or(|named| named.id != declared.id)
        {
            return None;
        }
        (declared.language == "go"
            && declared.owner_id.is_none()
            && go_declared_type_kind(declared.kind)
            && declared.visibility == Visibility::Public)
            .then(|| GoModeledNominalType {
                declaration_id: declared.id.clone(),
                qualified_name: declared.qualified_name.clone(),
                pointer,
            })
    }

    /// The exact result type selected from one positive modeled Go callable.
    ///
    /// A partial package may still prove a member it publishes. Selection
    /// therefore rejects conflicts, ambiguous records, missing structure, and
    /// inapplicable signatures without interpreting absence from the package
    /// as a negative fact. The returned reference remains tied to the retained
    /// overlay and preserves every structured wrapper for identity consumers.
    pub(crate) fn callable_result_type_ref(
        &self,
        owner_fqn: &str,
        member: &str,
        has_receiver: bool,
        parameter_count: usize,
        result_ordinal: usize,
    ) -> Option<&'a TypeRef> {
        let owner = self.unique_symbol(owner_fqn)?;
        if owner.language != "go"
            || owner.owner_id.is_some()
            || owner.provenance.ambiguous
            || (has_receiver && owner.kind == SemanticModelSymbolKind::Module)
            || (!has_receiver && owner.kind != SemanticModelSymbolKind::Module)
        {
            return None;
        }

        let callable = self.unique_go_owner_member(owner, member)?;
        if callable.visibility != Visibility::Public
            || callable.has_receiver() != has_receiver
            || callable.is_static() == has_receiver
            || !matches!(
                (has_receiver, callable.kind),
                (true, SemanticModelSymbolKind::Method)
                    | (false, SemanticModelSymbolKind::Function)
            )
            || callable.structured_signature().is_none_or(|signature| {
                go_signature_applicability(signature, parameter_count)
                    != GoSignatureApplicability::Applicable
            })
        {
            return None;
        }
        let signature = callable.structured_signature()?;
        Some(match signature.returns.as_ref()? {
            TypeRef::Tuple { elements } => elements.get(result_ordinal)?,
            result if result_ordinal == 0 => result,
            _ => return None,
        })
    }
}

/// Whether positive declaration facts prove that one exact modeled Go call
/// result is a pointer to a struct that owns the selected public field.
///
/// The call identity and result ordinal are structured inputs from dispatch;
/// the field name must come from a grammar-backed member locator. This helper
/// deliberately does not interpret a callee string, treat a value-struct field
/// as nil-requiring, or use a partial pack's missing members as negative
/// evidence.
pub fn modeled_go_callable_result_pointer_field(
    overlay: Option<&SemanticModelOverlay>,
    owner_fqn: &str,
    callable: &str,
    has_receiver: bool,
    parameter_count: usize,
    result_ordinal: usize,
    field: &str,
) -> bool {
    let packages = GoOverlayPackages::new(overlay);
    packages
        .callable_result_nominal_type(
            owner_fqn,
            callable,
            has_receiver,
            parameter_count,
            result_ordinal,
        )
        .filter(|result| result.pointer)
        .and_then(|result| packages.concrete_receiver_field(&result.qualified_name, field))
        .is_some()
}
