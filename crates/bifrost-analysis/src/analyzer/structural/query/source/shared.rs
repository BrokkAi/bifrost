use super::*;

/// Validate the `:class` / `:role` / `:namespace` option block shared by the
/// occurrence seed and the two occurrence steps, against the registries rather
/// than a hand-maintained keyword list.
/// Which lexical-environment filter vocabulary a form accepts (#1474).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnvironmentOptionKind {
    Scope,
    Binding,
    Candidate,
    ReachingBinding,
    GenerationSite,
    Export,
    DeclarationState,
}

impl EnvironmentOptionKind {
    pub(super) fn accepted(self) -> &'static str {
        match self {
            Self::Scope => ":kind",
            Self::Binding => ":kind, :name, and :hoisting",
            Self::Candidate => ":tier, :outcome, and :boundary",
            Self::ReachingBinding => ":include-shadowed",
            Self::GenerationSite => ":kind and :input",
            Self::Export => ":form and :name",
            Self::DeclarationState => ":origin, :declaration-only, and :config-gated",
        }
    }

    /// The registry field one RQL option label names, or `None` when the label
    /// is not part of this vocabulary.
    pub(super) fn field_for(self, label: &str) -> Option<EnvironmentOptionField> {
        match self {
            Self::Scope => SCOPE_SEED_RQL_LABELS
                .contains(&label)
                .then_some(EnvironmentOptionField::ScopeKinds),
            Self::Binding => binding_option_for_rql_label(label)
                .map(|option| EnvironmentOptionField::Step(option.field())),
            Self::Candidate => candidate_option_for_rql_label(label)
                .map(|option| EnvironmentOptionField::Step(option.field())),
            Self::ReachingBinding => REACHING_BINDING_STEP_OPTIONS
                .iter()
                .find(|option| option.accepts_rql_label(label))
                .map(|option| EnvironmentOptionField::Step(option.field())),
            Self::GenerationSite => generation_site_field_for_rql_label(label)
                .map(EnvironmentOptionField::GenerationSite),
            Self::Export => export_field_for_rql_label(label).map(EnvironmentOptionField::Export),
            Self::DeclarationState => declaration_state_option_for_rql_label(label)
                .map(|option| EnvironmentOptionField::Step(option.field())),
        }
    }
}

/// The scope filter's one axis lives in its own registry (its JSON key `kind`
/// collides with the binding filter's), so an option field is one of two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum EnvironmentOptionField {
    ScopeKinds,
    GenerationSite(GenerationSiteFilterField),
    Export(ExportFilterField),
    Step(QueryStepField),
}

impl EnvironmentOptionField {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::ScopeKinds => ScopeFilterField::ScopeKinds.label(),
            Self::GenerationSite(field) => field.label(),
            Self::Export(field) => field.label(),
            Self::Step(field) => field.label(),
        }
    }

    pub(super) fn signature(self) -> &'static str {
        match self {
            Self::ScopeKinds => ScopeFilterField::ScopeKinds.signature(),
            Self::GenerationSite(field) => field.signature(),
            Self::Export(field) => field.signature(),
            Self::Step(field) => field.signature(),
        }
    }

    pub(super) fn description(self) -> &'static str {
        match self {
            Self::ScopeKinds => ScopeFilterField::ScopeKinds.description(),
            Self::GenerationSite(field) => field.description(),
            Self::Export(field) => field.description(),
            Self::Step(field) => field.description(),
        }
    }

    /// The constrained vocabulary this axis accepts, or `None` for axes whose
    /// values are not a closed set (the binding `:name` axis) or are the
    /// boolean marker (`:include-shadowed`).
    pub(super) fn accepted_values(self) -> Option<Vec<&'static str>> {
        match self {
            Self::ScopeKinds => Some(ALL_KINDS.iter().map(|kind| kind.label()).collect()),
            Self::GenerationSite(GenerationSiteFilterField::Kinds) => Some(
                ALL_GENERATION_KINDS
                    .iter()
                    .map(|kind| kind.label())
                    .collect(),
            ),
            Self::GenerationSite(GenerationSiteFilterField::Inputs) => Some(
                ALL_GENERATION_INPUT_CLASSES
                    .iter()
                    .map(|input| input.label())
                    .collect(),
            ),
            Self::Export(ExportFilterField::Forms) => {
                Some(ALL_EXPORT_FORMS.iter().map(|form| form.label()).collect())
            }
            Self::Export(ExportFilterField::Names) => None,
            Self::Step(QueryStepField::BindingNames) => None,
            Self::Step(QueryStepField::IncludeShadowed) => Some(vec!["true"]),
            Self::Step(QueryStepField::DeclarationOnly | QueryStepField::ConfigGated) => {
                Some(vec!["true", "false"])
            }
            Self::Step(field) => Some(environment_filter_labels(field)),
        }
    }
}

pub(super) fn validate_regex(
    source: &str,
    range: Range<usize>,
    path: &str,
    analysis: &mut Analysis,
) {
    if source.len() > MAX_STRING_PREDICATE_LENGTH {
        analysis.error(
            range,
            "invalid-query",
            format!("regex must be at most {MAX_STRING_PREDICATE_LENGTH} bytes"),
        );
    } else if let Err(error) = Regex::new(source) {
        analysis.error(range, "invalid-query", format!("invalid regex: {error}"));
    } else {
        analysis.path(path, range);
    }
}

pub(super) fn validate_capture_name(
    name: &str,
    range: Range<usize>,
    code: &'static str,
    label: &str,
    analysis: &mut Analysis,
) {
    let shape = QueryStepField::Capture.value_shape();
    if !shape.accepts_string(name) {
        let (minimum, maximum) = shape
            .string_length_bounds()
            .expect("capture-name shape has string bounds");
        analysis.error(
            range,
            code,
            format!("{label} must be between {minimum} and {maximum} bytes"),
        );
    }
}

pub(super) fn validate_parameter_name(name: &str, range: Range<usize>, analysis: &mut Analysis) {
    let shape = QueryStepField::ParameterName.value_shape();
    if !shape.accepts_string(name) {
        let (minimum, maximum) = shape
            .string_length_bounds()
            .expect("parameter-name shape has string bounds");
        analysis.error(
            range,
            "invalid-query",
            format!("parameter name must be between {minimum} and {maximum} bytes"),
        );
    }
}
