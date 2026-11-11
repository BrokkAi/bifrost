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

use brokk_bifrost_analysis::analyzer::semantic::MemoryValueCopy;
use brokk_bifrost_go::packages::GO_MODULE_SCOPE_SEGMENT;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind;

use brokk_bifrost_analysis::analyzer::semantic_model::Signature;

use brokk_bifrost_analysis::analyzer::semantic_model::Visibility;
use brokk_bifrost_go::diagnostics::GoPackageSurface;

use crate::analyzer::go::GoOuterTypeShape;

use crate::analyzer::go::GoStructFieldIdentity;

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

/// Resolve one structurally selected member path with provider-supplied
/// postings. Native and incumbent navigation share the walk, including the
/// rule that an absent segment cannot be bypassed by a later matching name.
pub(crate) struct GoVisibleMemberPath {
    pub(crate) symbol_name: String,
    pub(crate) reference_name: String,
}

pub(crate) fn go_visible_member_path<'a>(
    package: &str,
    mut members: impl Iterator<Item = &'a str>,
    package_member: impl Fn(&str, &str) -> Option<String>,
    symbol: impl Fn(&str) -> Option<String>,
    mut step: impl FnMut() -> bool,
) -> Option<GoVisibleMemberPath> {
    if !step() {
        return None;
    }
    let first = members.next()?;
    let mut target = package_member(package, first)?;
    let mut reference = format!("{package}.{first}");
    for member in members {
        if !step() {
            return None;
        }
        target = symbol(&format!("{target}.{member}"))?;
        reference.push('.');
        reference.push_str(member);
    }
    Some(GoVisibleMemberPath {
        symbol_name: target,
        reference_name: reference,
    })
}

/// The activated overlay, read as a Go package index.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct GoOverlayPackages<'a> {
    overlay: Option<&'a SemanticModelOverlay>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GoModeledPackageIdentity {
    pub(crate) package_name: String,
    pub(crate) symbol_id: String,
    pub(crate) pack_id: String,
    pub(crate) pack_digest: String,
    pub(crate) record_id: String,
}

impl<'a> GoOverlayPackages<'a> {
    #[doc(hidden)]
    pub fn new(overlay: Option<&'a SemanticModelOverlay>) -> Self {
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
    ) -> Option<Arc<SemanticModelSymbol>> {
        let overlay = self.overlay?;
        let mut selected = None;
        for qualified_name in qualified_names {
            let matched = overlay.symbols_named_for(qualified_name, "go");
            match matched.disposition {
                SemanticModelOverlayDisposition::Empty => {}
                SemanticModelOverlayDisposition::Conflict
                | SemanticModelOverlayDisposition::Open(_) => return None,
                SemanticModelOverlayDisposition::Unique => {
                    let candidate = matched
                        .unique()
                        .expect("a unique overlay match contains one record");
                    match selected {
                        None => selected = Some(candidate),
                        Some(ref existing) if Arc::ptr_eq(existing, &candidate) => {}
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
    pub(crate) fn unique_symbol(&self, qualified_name: &str) -> Option<Arc<SemanticModelSymbol>> {
        self.overlay?
            .symbols_named_in_family(qualified_name, "go")
            .unique()
    }

    /// The unique symbol a Go reference may resolve to: one visible, public Go
    /// declaration. A name several packs publish, or one whose only records
    /// are unexported, resolves to nothing.
    #[doc(hidden)]
    pub fn visible_symbol(&self, qualified_name: &str) -> Option<Arc<SemanticModelSymbol>> {
        self.overlay?.visible_public_symbol(qualified_name, "go")
    }

    /// The `package` clause name an exact API pack records for `import_path`.
    ///
    /// The Go producer emits one module-kind symbol named exactly the import
    /// path whose first alias is the package clause name, which is how an
    /// unaliased `import "example.com/m/postgres"` of `package pg` binds `pg`
    /// rather than `postgres`.
    pub(crate) fn declared_package_name(&self, import_path: &str) -> Option<String> {
        self.modeled_package_identity(import_path)
            .map(|identity| identity.package_name)
    }

    /// Exact file-less package identity from one unambiguous Go module record.
    /// The package clause name comes from the record alias; import-path
    /// components are never used to infer it.
    pub(crate) fn modeled_package_identity(
        &self,
        import_path: &str,
    ) -> Option<GoModeledPackageIdentity> {
        let symbol = self.unique_symbol(import_path)?;
        if symbol.qualified_name != import_path
            || symbol.language != "go"
            || symbol.kind != SemanticModelSymbolKind::Module
            || symbol.owner_id.is_some()
            || symbol.visibility == Visibility::Private
            || symbol.provenance.ambiguous
        {
            return None;
        }
        let package_name = symbol.aliases.first()?.clone();
        if package_name.is_empty() || matches!(package_name.as_str(), "_" | ".") {
            return None;
        }
        Some(GoModeledPackageIdentity {
            package_name,
            symbol_id: symbol.id.clone(),
            pack_id: symbol.provenance.pack_id.clone(),
            pack_digest: symbol.provenance.pack_digest.clone(),
            record_id: symbol.provenance.record_id.clone(),
        })
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
    ) -> Option<Arc<SemanticModelSymbol>> {
        let qualified_names = Self::member_candidates(import_path, member);
        let symbol = self.unique_symbol_across_names(qualified_names.iter().map(String::as_str))?;
        self.visible_symbol(&symbol.qualified_name)
            .filter(|visible| Arc::ptr_eq(visible, &symbol))
    }

    /// Whether the packs publish `member` as a visible, public declaration of
    /// `import_path`, searching both names a Go pack can publish it under.
    #[doc(hidden)]
    pub fn publishes_member(&self, import_path: &str, member: &str) -> bool {
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
                    .symbols_named_for(candidate, "go")
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

    fn package_function_symbol(
        &self,
        import_path: &str,
        member: &str,
    ) -> Option<Result<Arc<SemanticModelSymbol>, GoModeledPackageCallResolution>> {
        let overlay = self.overlay?;
        let symbols = Self::member_candidates(import_path, member)
            .iter()
            .flat_map(|candidate| overlay.symbols_named_for(candidate, "go").records)
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
        Some(Ok(Arc::clone(symbol)))
    }
}

/// Classify a field after its selected source artifact has resolved the outer
/// named type. The declaration model's `TypeRef` intentionally does not retain
/// the alias chain's outer shape, so a declared Go function type can only be
/// admitted from the exact AST-backed `GoOuterTypeShape`.
pub(crate) fn go_field_value_copy_from_source(field: &GoStructFieldIdentity) -> MemoryValueCopy {
    match &field.outer_type_shape {
        GoOuterTypeShape::Function(_) => MemoryValueCopy::Reference,
        GoOuterTypeShape::Other { .. } | GoOuterTypeShape::Unknown { .. } => {
            MemoryValueCopy::Unknown
        }
    }
}
