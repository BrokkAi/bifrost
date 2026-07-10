//! LSP server entry point. The server is a hand-rolled dispatcher built on the
//! `lsp-server` crate (Content-Length framed JSON-RPC over stdio) and
//! `lsp-types` for protocol message shapes.
//!
//! `bifrost --server lsp` launches the server. The initial workspace is
//! bootstrapped from every usable `initialize.workspaceFolders` entry when
//! present; otherwise legacy root params and finally the `--root` path are used
//! as fallbacks.

mod capabilities;
pub mod conversion;
pub(crate) mod handlers;
mod server;
mod text_sync;

pub use server::run_lsp_stdio_server;
