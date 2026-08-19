// Shared by every integration binary in this crate; each one uses a subset.
#![allow(dead_code)]

pub mod lsp_client;

pub const RUST_ASSOCIATED_PATH_MAIN: &str = r#"
pub mod state;

use state::AppState;

pub struct Repositories;
pub struct Environment;
pub struct Router;

fn app_with_state(_state: AppState) -> Router {
    Router
}

fn app_with_environment(repositories: Repositories, environment: Environment) -> Router {
    let _ = state::AppState::with_environment(Repositories, Environment);
    app_with_state(AppState::with_environment(repositories, environment))
}
"#;

pub const RUST_ASSOCIATED_PATH_STATE: &str = r#"
use crate::{Environment, Repositories};

pub struct AppState;

impl AppState {
    pub fn with_environment(_repositories: Repositories, _environment: Environment) -> Self {
        Self
    }
}
"#;
