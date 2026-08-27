//! User-scoped registration of the Bifrost MCP server with coding hosts.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Map, Value, json};
use tempfile::NamedTempFile;

const SERVER_NAME: &str = "brokk";
const TOOLSETS: &str = "core";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Host {
    Codex,
    ClaudeCode,
    OpenCode,
    KimiCode,
    Hermes,
    OhMyPi,
}

impl Host {
    const ALL: [Self; 6] = [
        Self::Codex,
        Self::ClaudeCode,
        Self::OpenCode,
        Self::KimiCode,
        Self::Hermes,
        Self::OhMyPi,
    ];

    fn display_name(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::OpenCode => "OpenCode",
            Self::KimiCode => "Kimi Code",
            Self::Hermes => "Hermes",
            Self::OhMyPi => "Oh My Pi",
        }
    }

    fn command_names(self) -> &'static [&'static str] {
        match self {
            Self::Codex => &["codex"],
            Self::ClaudeCode => &["claude"],
            Self::OpenCode => &["opencode2", "opencode"],
            Self::KimiCode => &["kimi"],
            Self::Hermes => &["hermes"],
            Self::OhMyPi => &["omp"],
        }
    }

    fn registration_args(self, executable: &Path) -> Vec<OsString> {
        let executable = executable.as_os_str().to_owned();
        let common = || {
            vec![
                executable.clone(),
                OsString::from("--mcp"),
                OsString::from(TOOLSETS),
            ]
        };
        match self {
            Self::Codex => prefixed(&["mcp", "add", SERVER_NAME, "--"], common()),
            Self::ClaudeCode => prefixed(
                &[
                    "mcp",
                    "add",
                    "--transport",
                    "stdio",
                    "--scope",
                    "user",
                    SERVER_NAME,
                    "--",
                ],
                common(),
            ),
            Self::OpenCode => prefixed(&["mcp", "add", SERVER_NAME, "--global", "--"], common()),
            Self::KimiCode => prefixed(&["mcp", "add", SERVER_NAME, "--"], common()),
            Self::Hermes => prefixed(
                &["mcp", "add", SERVER_NAME, "--command"],
                prefixed(
                    &[executable.as_os_str(), OsStr::new("--args")],
                    vec![OsString::from("--mcp"), OsString::from(TOOLSETS)],
                ),
            ),
            Self::OhMyPi => Vec::new(),
        }
    }
}

fn prefixed<T: AsRef<OsStr>>(prefix: &[T], mut suffix: Vec<OsString>) -> Vec<OsString> {
    let mut args = prefix
        .iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    args.append(&mut suffix);
    args
}

/// Register this executable as the `brokk` MCP server in each installed host.
pub fn install_mcp_hosts() -> Result<(), String> {
    let executable = env::current_exe()
        .map_err(|error| format!("Failed to locate the Bifrost executable: {error}"))?;
    install_mcp_hosts_with(&executable, &environment())
}

#[derive(Debug)]
struct InstallEnvironment {
    path: OsString,
    path_extensions: Vec<OsString>,
    home: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    appdata: Option<PathBuf>,
}

fn environment() -> InstallEnvironment {
    InstallEnvironment {
        path: env::var_os("PATH").unwrap_or_default(),
        path_extensions: env::var_os("PATHEXT")
            .map(|value| {
                env::split_paths(&value)
                    .map(PathBuf::into_os_string)
                    .collect()
            })
            .unwrap_or_default(),
        home: env::var_os("HOME")
            .or_else(|| env::var_os("USERPROFILE"))
            .map(PathBuf::from),
        xdg_config_home: env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        appdata: env::var_os("APPDATA").map(PathBuf::from),
    }
}

fn install_mcp_hosts_with(
    executable: &Path,
    environment: &InstallEnvironment,
) -> Result<(), String> {
    let mut installed = Vec::new();
    let mut failures = Vec::new();

    for host in Host::ALL {
        let Some((command_name, command)) = host
            .command_names()
            .iter()
            .find_map(|name| find_command(name, environment).map(|command| (*name, command)))
        else {
            continue;
        };

        let result = if host == Host::OhMyPi {
            install_oh_my_pi(&command, executable)
        } else if host == Host::OpenCode && command_name == "opencode" {
            install_stable_opencode(executable, environment)
        } else {
            run_registration(host, &command, executable)
        };
        match result {
            Ok(()) => {
                println!("Registered {SERVER_NAME} with {}.", host.display_name());
                installed.push(host.display_name());
            }
            Err(error) => failures.push(format!("{}: {error}", host.display_name())),
        }
    }

    if installed.is_empty() && failures.is_empty() {
        return Err(
            "No supported coding host was found. Install Codex, Claude Code, OpenCode, Kimi Code, Hermes, or Oh My Pi, then run bifrost --install again."
                .to_string(),
        );
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "MCP registration failed for: {}",
            failures.join("; ")
        ))
    }
}

fn run_registration(host: Host, command: &Path, executable: &Path) -> Result<(), String> {
    let args = host.registration_args(executable);
    let output = if host == Host::Hermes {
        run_command(command, &args, Some(b"y\n"))?
    } else {
        run_command(command, &args, None)?
    };
    if output.status.success() {
        if host == Host::Hermes {
            return verify_hermes_registration(command);
        }
        return Ok(());
    }
    if host == Host::ClaudeCode
        && String::from_utf8_lossy(&output.stderr).contains("already exists in user config")
    {
        let remove_args = prefixed(&["mcp", "remove", SERVER_NAME, "--scope", "user"], vec![]);
        checked_output(run_command(command, &remove_args, None)?)?;
        return checked_output(run_command(command, &args, None)?);
    }

    checked_output(output)
}

fn run_command(command: &Path, args: &[OsString], input: Option<&[u8]>) -> Result<Output, String> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", command.display()))?;
    if let Some(input) = input {
        child
            .stdin
            .as_mut()
            .expect("piped stdin must be available")
            .write_all(input)
            .map_err(|error| format!("failed to answer {}: {error}", command.display()))?;
    }
    child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for {}: {error}", command.display()))
}

fn verify_hermes_registration(command: &Path) -> Result<(), String> {
    let output = run_command(command, &prefixed(&["mcp", "list"], Vec::new()), None)?;
    if !output.status.success() {
        return checked_output(output);
    }
    if String::from_utf8_lossy(&output.stdout).contains(SERVER_NAME) {
        Ok(())
    } else {
        Err("registration command did not save the server".to_string())
    }
}

fn checked_output(output: Output) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    if detail.is_empty() {
        Err(format!(
            "registration command exited with {}",
            output.status
        ))
    } else {
        Err(detail)
    }
}

fn find_command(name: &str, environment: &InstallEnvironment) -> Option<PathBuf> {
    let extensions = if cfg!(windows) {
        environment.path_extensions.as_slice()
    } else {
        &[]
    };
    for directory in env::split_paths(&environment.path) {
        let plain = directory.join(name);
        if plain.is_file() {
            return Some(plain);
        }
        for extension in extensions {
            let mut candidate = plain.as_os_str().to_owned();
            candidate.push(extension);
            let candidate = PathBuf::from(candidate);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn install_oh_my_pi(command: &Path, executable: &Path) -> Result<(), String> {
    let output = Command::new(command)
        .args(["config", "path"])
        .output()
        .map_err(|error| format!("failed to get the active configuration path: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "omp config path failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let agent_directory = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    if !agent_directory.is_absolute() {
        return Err("omp config path did not return an absolute path".to_string());
    }
    let config_path = agent_directory.join("mcp.json");

    let mut document = if config_path.exists() {
        let source = fs::read_to_string(&config_path)
            .map_err(|error| format!("failed to read {}: {error}", config_path.display()))?;
        serde_json::from_str::<Value>(&source)
            .map_err(|error| format!("invalid JSON in {}: {error}", config_path.display()))?
    } else {
        json!({
            "$schema": "https://raw.githubusercontent.com/can1357/oh-my-pi/main/packages/coding-agent/src/config/mcp-schema.json"
        })
    };
    let object = document
        .as_object_mut()
        .ok_or_else(|| format!("{} must contain a JSON object", config_path.display()))?;
    let servers = object
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            format!(
                "mcpServers in {} must be a JSON object",
                config_path.display()
            )
        })?;
    servers.insert(
        SERVER_NAME.to_string(),
        json!({
            "type": "stdio",
            "command": executable,
            "args": ["--mcp", TOOLSETS]
        }),
    );

    write_json_atomic(&config_path, &document)
}

fn install_stable_opencode(
    executable: &Path,
    environment: &InstallEnvironment,
) -> Result<(), String> {
    let config_root = if let Some(root) = environment.xdg_config_home.as_deref() {
        root.to_owned()
    } else if cfg!(windows) {
        environment
            .appdata
            .clone()
            .ok_or_else(|| "APPDATA is not set".to_string())?
    } else {
        environment
            .home
            .as_deref()
            .ok_or_else(|| "HOME is not set".to_string())?
            .join(".config")
    };
    let config_path = config_root.join("opencode").join("opencode.json");
    let mut document = if config_path.exists() {
        let source = fs::read_to_string(&config_path)
            .map_err(|error| format!("failed to read {}: {error}", config_path.display()))?;
        serde_json::from_str::<Value>(&source)
            .map_err(|error| format!("invalid JSON in {}: {error}", config_path.display()))?
    } else {
        json!({ "$schema": "https://opencode.ai/config.json" })
    };
    let object = document
        .as_object_mut()
        .ok_or_else(|| format!("{} must contain a JSON object", config_path.display()))?;
    let servers = object
        .entry("mcp")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| format!("mcp in {} must be a JSON object", config_path.display()))?;
    servers.insert(
        SERVER_NAME.to_string(),
        json!({
            "type": "local",
            "command": [executable, "--mcp", TOOLSETS],
            "enabled": true
        }),
    );
    write_json_atomic(&config_path, &document)
}

fn write_json_atomic(config_path: &Path, document: &Value) -> Result<(), String> {
    let directory = config_path
        .parent()
        .expect("configuration file must have a parent directory");
    fs::create_dir_all(directory)
        .map_err(|error| format!("failed to create {}: {error}", directory.display()))?;
    let mut temporary = NamedTempFile::new_in(directory)
        .map_err(|error| format!("failed to create an MCP config file: {error}"))?;
    serde_json::to_writer_pretty(&mut temporary, &document)
        .map_err(|error| format!("failed to encode {}: {error}", config_path.display()))?;
    temporary
        .write_all(b"\n")
        .map_err(|error| format!("failed to write {}: {error}", config_path.display()))?;
    temporary.persist(config_path).map_err(|error| {
        format!(
            "failed to replace {}: {}",
            config_path.display(),
            error.error
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_commands_register_the_expected_server() {
        let executable = Path::new("/opt/bifrost/bin/bifrost");
        assert_eq!(
            Host::Codex.registration_args(executable),
            strings(&[
                "mcp",
                "add",
                "brokk",
                "--",
                "/opt/bifrost/bin/bifrost",
                "--mcp",
                "core",
            ])
        );
        assert_eq!(
            Host::ClaudeCode.registration_args(executable),
            strings(&[
                "mcp",
                "add",
                "--transport",
                "stdio",
                "--scope",
                "user",
                "brokk",
                "--",
                "/opt/bifrost/bin/bifrost",
                "--mcp",
                "core",
            ])
        );
        assert_eq!(
            Host::OpenCode.registration_args(executable),
            strings(&[
                "mcp",
                "add",
                "brokk",
                "--global",
                "--",
                "/opt/bifrost/bin/bifrost",
                "--mcp",
                "core",
            ])
        );
        assert_eq!(
            Host::KimiCode.registration_args(executable),
            strings(&[
                "mcp",
                "add",
                "brokk",
                "--",
                "/opt/bifrost/bin/bifrost",
                "--mcp",
                "core",
            ])
        );
        assert_eq!(
            Host::Hermes.registration_args(executable),
            strings(&[
                "mcp",
                "add",
                "brokk",
                "--command",
                "/opt/bifrost/bin/bifrost",
                "--args",
                "--mcp",
                "core",
            ])
        );
    }

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
}
