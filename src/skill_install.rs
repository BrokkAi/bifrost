use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    Auto,
    Symlink,
    Copy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallTarget {
    Project,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillSet {
    Code,
    All,
}

#[derive(Debug)]
pub struct InstallSkillsOptions {
    pub root: PathBuf,
    pub target: Option<InstallTarget>,
    pub skills_root: Option<PathBuf>,
    pub mode: InstallMode,
    pub skill_set: SkillSet,
    pub force: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationKind {
    Project,
    Global,
    Custom,
}

#[derive(Debug, Clone)]
struct Destination {
    kind: DestinationKind,
    root: PathBuf,
    label: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct EmbeddedSkill {
    name: &'static str,
    content: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectiveMode {
    Symlink,
    Copy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkillAction {
    UpToDate,
    Copy,
    ReplaceManagedCopy,
    Symlink,
}

#[derive(Debug)]
struct SkillPlan<'a> {
    skill: &'a EmbeddedSkill,
    destination: PathBuf,
    action: SkillAction,
}

const MANAGED_BY: &str = "bifrost";
const MARKER_FILE: &str = ".bifrost-install.json";
const SKILLS_PACKAGE_ROOT: &str = "plugins/bifrost-agent/skills";

const CODE_SKILL_NAMES: &[&str] = &[
    "bifrost-code-navigation",
    "bifrost-code-reading",
    "bifrost-codebase-search",
];

const EMBEDDED_SKILLS: &[EmbeddedSkill] = &[
    EmbeddedSkill {
        name: "adversarial-test-sweep",
        content: include_str!("../plugins/bifrost-agent/skills/adversarial-test-sweep/SKILL.md"),
    },
    EmbeddedSkill {
        name: "bifrost-code-navigation",
        content: include_str!("../plugins/bifrost-agent/skills/bifrost-code-navigation/SKILL.md"),
    },
    EmbeddedSkill {
        name: "bifrost-code-reading",
        content: include_str!("../plugins/bifrost-agent/skills/bifrost-code-reading/SKILL.md"),
    },
    EmbeddedSkill {
        name: "bifrost-codebase-search",
        content: include_str!("../plugins/bifrost-agent/skills/bifrost-codebase-search/SKILL.md"),
    },
    EmbeddedSkill {
        name: "git-exploration",
        content: include_str!("../plugins/bifrost-agent/skills/git-exploration/SKILL.md"),
    },
    EmbeddedSkill {
        name: "guided-issue",
        content: include_str!("../plugins/bifrost-agent/skills/guided-issue/SKILL.md"),
    },
    EmbeddedSkill {
        name: "guided-review",
        content: include_str!("../plugins/bifrost-agent/skills/guided-review/SKILL.md"),
    },
    EmbeddedSkill {
        name: "review-pr",
        content: include_str!("../plugins/bifrost-agent/skills/review-pr/SKILL.md"),
    },
    EmbeddedSkill {
        name: "review",
        content: include_str!("../plugins/bifrost-agent/skills/review/SKILL.md"),
    },
    EmbeddedSkill {
        name: "today",
        content: include_str!("../plugins/bifrost-agent/skills/today/SKILL.md"),
    },
    EmbeddedSkill {
        name: "write-issue",
        content: include_str!("../plugins/bifrost-agent/skills/write-issue/SKILL.md"),
    },
];

pub fn install_skills(options: InstallSkillsOptions) -> Result<(), String> {
    if options.skills_root.is_some() && options.target.is_some() {
        return Err("--skills-root cannot be combined with --target".to_string());
    }

    let destination = resolve_destination(&options)?;
    let skills = selected_skills(options.skill_set);
    let effective_mode = resolve_mode(options.mode, destination.kind, &skills)?;
    let plans = plan_install(&destination.root, &skills, effective_mode, options.force)?;

    print_install_header(&destination, effective_mode, options.dry_run);
    if options.dry_run {
        for plan in &plans {
            println!("Would {}", action_phrase(plan));
        }
        println!("No files written.");
        print_mcp_note();
        return Ok(());
    }

    ensure_skills_root(&destination.root)?;
    for plan in &plans {
        execute_plan(plan)?;
        println!("{}", completed_phrase(plan));
    }
    print_mcp_note();
    Ok(())
}

fn resolve_destination(options: &InstallSkillsOptions) -> Result<Destination, String> {
    if let Some(root) = &options.skills_root {
        return Ok(Destination {
            kind: DestinationKind::Custom,
            root: root.clone(),
            label: "custom",
        });
    }

    match options.target {
        Some(InstallTarget::Project) => Ok(project_destination(&options.root)),
        Some(InstallTarget::Global) => global_destination(),
        None => prompt_destination(&options.root),
    }
}

fn project_destination(root: &Path) -> Destination {
    Destination {
        kind: DestinationKind::Project,
        root: root.join(".agents").join("skills"),
        label: "project",
    }
}

fn global_destination() -> Result<Destination, String> {
    let home = home_dir().ok_or_else(|| {
        "--target global requires HOME, USERPROFILE, or HOMEDRIVE/HOMEPATH".to_string()
    })?;
    Ok(Destination {
        kind: DestinationKind::Global,
        root: home.join(".agents").join("skills"),
        label: "global",
    })
}

fn prompt_destination(root: &Path) -> Result<Destination, String> {
    let mut choices = vec![project_destination(root)];
    if let Ok(global) = global_destination() {
        choices.push(global);
    }

    println!("Bifrost can install generic Agent Skills into:");
    for (index, choice) in choices.iter().enumerate() {
        println!(
            "  {}) {} skill root: {}",
            index + 1,
            choice.label,
            choice.root.display()
        );
    }
    let hosts = detected_host_labels();
    if !hosts.is_empty() {
        println!("Detected agent host state: {}", hosts.join(", "));
    }
    print!("Select install destination [1-{}]: ", choices.len());
    io::stdout()
        .flush()
        .map_err(|err| format!("Failed to flush prompt: {err}"))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| format!("Failed to read install selection: {err}"))?;
    let selected = input
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("Invalid install selection: {}", input.trim()))?;
    choices
        .get(selected.saturating_sub(1))
        .cloned()
        .ok_or_else(|| format!("Install selection out of range: {selected}"))
}

fn detected_host_labels() -> Vec<&'static str> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let mut labels = Vec::new();
    if home.join(".config").join("zed").is_dir() {
        labels.push("Zed");
    }
    if home.join(".gemini").join("antigravity").is_dir() {
        labels.push("Antigravity");
    }
    if home.join(".codex").is_dir() {
        labels.push("Codex");
    }
    if home.join(".claude").is_dir() {
        labels.push("Claude Code");
    }
    if home.join(".config").join("amp").is_dir() {
        labels.push("Amp");
    }
    labels
}

fn selected_skills(skill_set: SkillSet) -> Vec<&'static EmbeddedSkill> {
    match skill_set {
        SkillSet::Code => EMBEDDED_SKILLS
            .iter()
            .filter(|skill| CODE_SKILL_NAMES.contains(&skill.name))
            .collect(),
        SkillSet::All => EMBEDDED_SKILLS.iter().collect(),
    }
}

fn resolve_mode(
    requested: InstallMode,
    destination: DestinationKind,
    skills: &[&EmbeddedSkill],
) -> Result<EffectiveMode, String> {
    match requested {
        InstallMode::Copy => Ok(EffectiveMode::Copy),
        InstallMode::Symlink => {
            ensure_checkout_sources_exist(skills)?;
            Ok(EffectiveMode::Symlink)
        }
        InstallMode::Auto => {
            if destination == DestinationKind::Project && checkout_sources_exist(skills) {
                Ok(EffectiveMode::Symlink)
            } else {
                Ok(EffectiveMode::Copy)
            }
        }
    }
}

fn checkout_sources_exist(skills: &[&EmbeddedSkill]) -> bool {
    skills
        .iter()
        .all(|skill| checkout_skill_dir(skill).join("SKILL.md").is_file())
}

fn ensure_checkout_sources_exist(skills: &[&EmbeddedSkill]) -> Result<(), String> {
    let missing: Vec<&str> = skills
        .iter()
        .filter(|skill| !checkout_skill_dir(skill).join("SKILL.md").is_file())
        .map(|skill| skill.name)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "--mode symlink requires checkout skill sources; missing: {}",
            missing.join(", ")
        ))
    }
}

fn checkout_skill_dir(skill: &EmbeddedSkill) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SKILLS_PACKAGE_ROOT)
        .join(skill.name)
}

fn plan_install<'a>(
    root: &Path,
    skills: &[&'a EmbeddedSkill],
    mode: EffectiveMode,
    force: bool,
) -> Result<Vec<SkillPlan<'a>>, String> {
    if root.exists() && !root.is_dir() {
        return Err(format!(
            "Skills root exists but is not a directory: {}",
            root.display()
        ));
    }

    skills
        .iter()
        .map(|skill| plan_skill(root, skill, mode, force))
        .collect()
}

fn plan_skill<'a>(
    root: &Path,
    skill: &'a EmbeddedSkill,
    mode: EffectiveMode,
    force: bool,
) -> Result<SkillPlan<'a>, String> {
    let destination = root.join(skill.name);
    let action = match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if symlink_points_to_checkout(&destination, skill) {
                SkillAction::UpToDate
            } else {
                return Err(format!(
                    "Refusing to replace existing unmanaged symlink: {}",
                    destination.display()
                ));
            }
        }
        Ok(metadata) if metadata.is_dir() => plan_existing_directory(&destination, skill, force)?,
        Ok(_) => {
            return Err(format!(
                "Refusing to replace existing unmanaged file: {}",
                destination.display()
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => match mode {
            EffectiveMode::Copy => SkillAction::Copy,
            EffectiveMode::Symlink => SkillAction::Symlink,
        },
        Err(err) => {
            return Err(format!(
                "Failed to inspect existing skill {}: {err}",
                destination.display()
            ));
        }
    };

    Ok(SkillPlan {
        skill,
        destination,
        action,
    })
}

fn plan_existing_directory(
    destination: &Path,
    skill: &EmbeddedSkill,
    force: bool,
) -> Result<SkillAction, String> {
    match read_marker(destination)? {
        Some(marker) if marker.get("managedBy").and_then(Value::as_str) == Some(MANAGED_BY) => {
            if marker.get("skill").and_then(Value::as_str) != Some(skill.name) {
                return Err(format!(
                    "Refusing to replace managed skill with mismatched marker: {}",
                    destination.display()
                ));
            }
            let current = fs::read_to_string(destination.join("SKILL.md")).map_err(|err| {
                format!(
                    "Failed to read existing managed skill {}: {err}",
                    destination.join("SKILL.md").display()
                )
            })?;
            if current == skill.content {
                Ok(SkillAction::UpToDate)
            } else if force {
                Ok(SkillAction::ReplaceManagedCopy)
            } else {
                Err(format!(
                    "Existing Bifrost-managed skill has local changes: {}. Rerun with --force to replace it.",
                    destination.display()
                ))
            }
        }
        Some(_) => Err(format!(
            "Refusing to replace existing directory with non-Bifrost marker: {}",
            destination.display()
        )),
        None => Err(format!(
            "Refusing to replace existing unmanaged skill directory: {}",
            destination.display()
        )),
    }
}

fn read_marker(destination: &Path) -> Result<Option<Value>, String> {
    let marker_path = destination.join(MARKER_FILE);
    match fs::read_to_string(&marker_path) {
        Ok(contents) => serde_json::from_str(&contents).map(Some).map_err(|err| {
            format!(
                "Invalid Bifrost install marker {}: {err}",
                marker_path.display()
            )
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "Failed to read Bifrost install marker {}: {err}",
            marker_path.display()
        )),
    }
}

fn symlink_points_to_checkout(destination: &Path, skill: &EmbeddedSkill) -> bool {
    let Ok(target) = fs::read_link(destination) else {
        return false;
    };
    let absolute_target = if target.is_absolute() {
        target
    } else {
        destination
            .parent()
            .map(|parent| parent.join(&target))
            .unwrap_or(target)
    };
    paths_equivalent(&absolute_target, &checkout_skill_dir(skill))
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn ensure_skills_root(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root)
        .map_err(|err| format!("Failed to create skills root {}: {err}", root.display()))
}

fn execute_plan(plan: &SkillPlan<'_>) -> Result<(), String> {
    match plan.action {
        SkillAction::UpToDate => Ok(()),
        SkillAction::Copy => write_managed_copy(plan),
        SkillAction::ReplaceManagedCopy => {
            fs::remove_dir_all(&plan.destination).map_err(|err| {
                format!(
                    "Failed to remove existing managed skill {}: {err}",
                    plan.destination.display()
                )
            })?;
            write_managed_copy(plan)
        }
        SkillAction::Symlink => create_skill_symlink(plan),
    }
}

fn write_managed_copy(plan: &SkillPlan<'_>) -> Result<(), String> {
    fs::create_dir_all(&plan.destination).map_err(|err| {
        format!(
            "Failed to create skill directory {}: {err}",
            plan.destination.display()
        )
    })?;
    fs::write(plan.destination.join("SKILL.md"), plan.skill.content).map_err(|err| {
        format!(
            "Failed to write skill file {}: {err}",
            plan.destination.join("SKILL.md").display()
        )
    })?;
    fs::write(
        plan.destination.join(MARKER_FILE),
        managed_marker(plan.skill).to_string() + "\n",
    )
    .map_err(|err| {
        format!(
            "Failed to write install marker {}: {err}",
            plan.destination.join(MARKER_FILE).display()
        )
    })
}

fn managed_marker(skill: &EmbeddedSkill) -> Value {
    json!({
        "managedBy": MANAGED_BY,
        "package": "brokk-bifrost",
        "version": env!("CARGO_PKG_VERSION"),
        "skill": skill.name,
        "source": format!("{SKILLS_PACKAGE_ROOT}/{}/SKILL.md", skill.name),
        "format": "generic-agents-skills-v1"
    })
}

fn create_skill_symlink(plan: &SkillPlan<'_>) -> Result<(), String> {
    let source = checkout_skill_dir(plan.skill);
    create_dir_symlink(&source, &plan.destination).map_err(|err| {
        format!(
            "Failed to create symlink {} -> {}: {err}",
            plan.destination.display(),
            source.display()
        )
    })
}

#[cfg(unix)]
fn create_dir_symlink(source: &Path, destination: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(source, destination)
}

#[cfg(windows)]
fn create_dir_symlink(source: &Path, destination: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(source, destination)
}

fn print_install_header(destination: &Destination, mode: EffectiveMode, dry_run: bool) {
    let verb = if dry_run { "Planning" } else { "Installing" };
    println!(
        "{verb} Bifrost skills into {} root: {}",
        destination.label,
        destination.root.display()
    );
    println!(
        "Install mode: {}",
        match mode {
            EffectiveMode::Symlink => "symlink",
            EffectiveMode::Copy => "copy",
        }
    );
}

fn action_phrase(plan: &SkillPlan<'_>) -> String {
    match plan.action {
        SkillAction::UpToDate => {
            format!(
                "leave {} unchanged; it is already up to date",
                plan.skill.name
            )
        }
        SkillAction::Copy => format!("copy {}", plan.skill.name),
        SkillAction::ReplaceManagedCopy => format!("replace managed copy of {}", plan.skill.name),
        SkillAction::Symlink => format!(
            "symlink {} -> {}",
            plan.skill.name,
            checkout_skill_dir(plan.skill).display()
        ),
    }
}

fn completed_phrase(plan: &SkillPlan<'_>) -> String {
    match plan.action {
        SkillAction::UpToDate => format!("Up to date: {}", plan.skill.name),
        SkillAction::Copy => format!("Installed: {}", plan.skill.name),
        SkillAction::ReplaceManagedCopy => format!("Replaced: {}", plan.skill.name),
        SkillAction::Symlink => format!("Linked: {}", plan.skill.name),
    }
}

fn print_mcp_note() {
    println!(
        "Note: skills provide agent instructions only. Configure the Bifrost MCP server separately; see plugins/bifrost-agent/README.md."
    );
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("USERPROFILE")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            let drive = env::var_os("HOMEDRIVE")?;
            let path = env::var_os("HOMEPATH")?;
            if drive.is_empty() || path.is_empty() {
                None
            } else {
                Some(PathBuf::from(format!(
                    "{}{}",
                    drive.to_string_lossy(),
                    path.to_string_lossy()
                )))
            }
        })
}
