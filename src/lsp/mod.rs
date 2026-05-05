//! LSP server entry point. The server is a hand-rolled dispatcher built on the
//! `lsp-server` crate (Content-Length framed JSON-RPC over stdio) and
//! `lsp-types` for protocol message shapes.
//!
//! `bifrost --server lsp` launches the server. The initial workspace is
//! bootstrapped from `initialize.workspaceFolders[0]` when present; otherwise
//! the `--root` path is used as a fallback.

mod capabilities;
pub mod conversion;
mod server;

pub use server::run_lsp_stdio_server;
