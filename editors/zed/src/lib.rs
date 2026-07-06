use std::path::Path;

use zed_extension_api::{self as zed, settings::LspSettings, Result};

struct BifrostExtension;

impl BifrostExtension {
    fn server_command(
        &self,
        language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let settings = LspSettings::for_worktree(language_server_id.as_ref(), worktree)
            .or_else(|_| LspSettings::for_worktree("bifrost", worktree))
            .ok();
        let binary = settings
            .as_ref()
            .and_then(|settings| settings.binary.as_ref());
        let command = binary
            .and_then(|binary| binary.path.clone())
            .or_else(|| local_dev_binary(worktree))
            .or_else(|| worktree.which("bifrost"))
            .unwrap_or_else(|| "bifrost".to_string());

        let mut args = vec![
            "--root".to_string(),
            worktree.root_path(),
            "--lsp".to_string(),
        ];
        if let Some(extra_args) = binary.and_then(|binary| binary.arguments.clone()) {
            args.extend(extra_args);
        }

        Ok(zed::Command {
            command,
            args,
            env: worktree.shell_env(),
        })
    }
}

impl zed::Extension for BifrostExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        self.server_command(language_server_id, worktree)
    }
}

fn local_dev_binary(worktree: &zed::Worktree) -> Option<String> {
    let executable = if zed::current_platform().0 == zed::Os::Windows {
        "bifrost.exe"
    } else {
        "bifrost"
    };
    let candidate = Path::new(&worktree.root_path())
        .join("target")
        .join("debug")
        .join(executable);
    candidate
        .is_file()
        .then(|| candidate.to_string_lossy().into_owned())
}

zed::register_extension!(BifrostExtension);
