---
title: Neovim LSP
description: Configure Neovim to run Bifrost as a stdio language server.
---

Neovim can run Bifrost directly through its built-in LSP client. No Bifrost-specific Neovim plugin is required.

Use Neovim 0.11 or newer for `vim.lsp.config`. Put this in `~/.config/nvim/after/plugin/bifrost.lua`, start Neovim from the workspace root, and open a supported source file:

```lua
local root = vim.fn.getcwd()

vim.lsp.config('bifrost', {
  cmd = { 'bifrost', '--root', root, '--lsp' },
  filetypes = {
    'c',
    'cpp',
    'cs',
    'go',
    'java',
    'javascript',
    'javascriptreact',
    'php',
    'python',
    'ruby',
    'rust',
    'scala',
    'typescript',
    'typescriptreact',
  },
  root_dir = root,
})

vim.lsp.enable('bifrost')
```

This assumes `bifrost` is installed on `PATH`:

```bash
cargo install brokk-bifrost --locked --force
```

For local development, build this checkout and use an absolute binary path:

```bash
cargo build --bin bifrost
```

Then update the Neovim config:

```lua
local root = vim.fn.getcwd()
local bifrost = '/path/to/bifrost/target/debug/bifrost'

vim.lsp.config('bifrost', {
  cmd = { bifrost, '--root', root, '--lsp' },
  filetypes = {
    'c',
    'cpp',
    'cs',
    'go',
    'java',
    'javascript',
    'javascriptreact',
    'php',
    'python',
    'ruby',
    'rust',
    'scala',
    'typescript',
    'typescriptreact',
  },
  root_dir = root,
})

vim.lsp.enable('bifrost')
```

## Large Workspaces

Bifrost also accepts the same LSP initialization options used by the VS Code extension for scoped indexing. Paths are resolved from the `--root` directory:

```lua
local root = vim.fn.getcwd()

vim.lsp.config('bifrost', {
  cmd = { 'bifrost', '--root', root, '--lsp' },
  filetypes = {
    'c',
    'cpp',
    'cs',
    'go',
    'java',
    'javascript',
    'javascriptreact',
    'php',
    'python',
    'ruby',
    'rust',
    'scala',
    'typescript',
    'typescriptreact',
  },
  root_dir = root,
  init_options = {
    roots = { 'src', 'tests' },
    exclude = { 'target', 'vendor/generated' },
  },
})

vim.lsp.enable('bifrost')
```

Use `roots` when a repository has a small set of directories that should be indexed. Use `exclude` for generated output, dependency caches, or other directories that should not participate in workspace symbols or document-level lookups.

## Dynamic Roots

If you do not always start Neovim from the workspace root, use an autocmd and `vim.lsp.start` so the Bifrost command can include the root found for each buffer:

```lua
local bifrost = 'bifrost'
local filetypes = {
  c = true,
  cpp = true,
  cs = true,
  go = true,
  java = true,
  javascript = true,
  javascriptreact = true,
  php = true,
  python = true,
  ruby = true,
  rust = true,
  scala = true,
  typescript = true,
  typescriptreact = true,
}

vim.api.nvim_create_autocmd('FileType', {
  callback = function(args)
    if not filetypes[vim.bo[args.buf].filetype] then
      return
    end

    local root = vim.fs.root(args.buf, { '.git' }) or vim.fn.getcwd()

    vim.lsp.start({
      name = 'bifrost',
      cmd = { bifrost, '--root', root, '--lsp' },
      root_dir = root,
      init_options = {
        roots = { 'src', 'tests' },
        exclude = { 'target', 'vendor/generated' },
      },
    }, { bufnr = args.buf })
  end,
})
```

## Confirm Bifrost Is Running

Open a supported file and run:

```vim
:lua =vim.lsp.get_clients({ bufnr = 0, name = 'bifrost' })
```

The result should contain one client named `bifrost`. To confirm Neovim is asking Bifrost for navigation, place the cursor on a reference and run `vim.lsp.buf.definition()` or `vim.lsp.buf.references()`.

For deeper debugging, inspect Neovim's LSP log path:

```vim
:lua print(vim.lsp.log.get_filename())
```
