---
title: Neovim and Vim LSP
description: Configure Neovim or classic Vim to run Bifrost as a stdio language server.
---

Neovim can run Bifrost directly through its built-in LSP client. No Bifrost-specific Neovim plugin is required. Classic Vim works too through a generic LSP client such as [vim-lsp](https://github.com/prabirshrestha/vim-lsp) or [coc.nvim](https://github.com/neoclide/coc.nvim): every client on this page starts the same stdio server with `bifrost --root <project> --lsp`.

## Neovim 0.11 or Newer (Built-In Client)

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
    'kotlin',
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
    'kotlin',
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
    'kotlin',
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
  kotlin = true,
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

## Older Neovim with nvim-lspconfig

On Neovim releases before 0.11, `vim.lsp.config` does not exist. Use [nvim-lspconfig](https://github.com/neovim/nvim-lspconfig) instead. It ships no Bifrost entry, so define the server before calling `setup`:

```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

if not configs.bifrost then
  configs.bifrost = {
    default_config = {
      cmd = { 'bifrost', '--root', vim.fn.getcwd(), '--lsp' },
      filetypes = {
        'c',
        'cpp',
        'cs',
        'go',
        'java',
        'javascript',
        'javascriptreact',
        'kotlin',
        'php',
        'python',
        'ruby',
        'rust',
        'scala',
        'typescript',
        'typescriptreact',
      },
      root_dir = lspconfig.util.root_pattern('.git'),
      init_options = {
        roots = { 'src', 'tests' },
        exclude = { 'target', 'vendor/generated' },
      },
    },
  }
end

lspconfig.bifrost.setup({})
```

`root_dir` finds the Git root per buffer, but `cmd` is fixed when the server starts, so start Neovim from the workspace root or replace `vim.fn.getcwd()` with your project's absolute path. The `init_options` block is optional; drop it when you want the whole workspace indexed.

## Classic Vim with vim-lsp

Install [vim-lsp](https://github.com/prabirshrestha/vim-lsp) with your Vim plugin manager, then register Bifrost. The helper below resolves the nearest Git root, including worktrees, and falls back to the current directory outside Git:

```vim
function! s:bifrost_lsp_root() abort
  let l:root = lsp#utils#find_nearest_parent_file_directory(lsp#utils#get_buffer_path(), ['.git', '.git/'])
  return empty(l:root) ? getcwd() : l:root
endfunction

if executable('bifrost')
  augroup BifrostLsp
    autocmd!
    autocmd User lsp_setup call lsp#register_server({
      \ 'name': 'bifrost',
      \ 'cmd': {server_info->['bifrost', '--root', s:bifrost_lsp_root(), '--lsp']},
      \ 'root_uri': {server_info->lsp#utils#path_to_uri(s:bifrost_lsp_root())},
      \ 'allowlist': ['c', 'cpp', 'cs', 'go', 'java', 'javascript', 'javascriptreact', 'kotlin', 'php', 'python', 'ruby', 'rust', 'scala', 'typescript', 'typescriptreact'],
      \ 'initialization_options': {
      \   'roots': ['src', 'tests'],
      \   'exclude': ['target', 'vendor/generated'],
      \ },
      \ })
  augroup END
endif
```

Check the server with `:LspStatus` after opening a supported file. Remove the `initialization_options` block when you want the whole workspace indexed.

## Classic Vim or Neovim with coc.nvim

Install [coc.nvim](https://github.com/neoclide/coc.nvim), then run `:CocConfig` and add a `bifrost` language server entry:

```json
{
  "languageserver": {
    "bifrost": {
      "command": "bifrost",
      "args": ["--root", "/path/to/project", "--lsp"],
      "filetypes": ["c", "cpp", "cs", "go", "java", "javascript", "javascriptreact", "kotlin", "php", "python", "ruby", "rust", "scala", "typescript", "typescriptreact"],
      "rootPatterns": [".git"],
      "initializationOptions": {
        "roots": ["src", "tests"],
        "exclude": ["target", "vendor/generated"]
      }
    }
  }
}
```

Replace `/path/to/project` with your workspace root. coc.nvim sends the workspace folder at initialization, so `--root` acts as the fallback there; keep it pointed at the project you open most often. The `initializationOptions` block is optional. Verify with `:CocInfo` and look for a running `bifrost` service after opening a supported file.

## Classic Vim or Neovim with ALE

[ALE](https://github.com/dense-analysis/ale) can start Bifrost as a stdio LSP linter. This configuration derives both ALE's process directory and Bifrost's fallback root from the current buffer, so it works across repositories without a project list:

```vim
function! s:bifrost_root(buffer) abort
  let l:start = expand('#' . a:buffer . ':p:h')
  let l:gitdir = finddir('.git', l:start . ';')
  if empty(l:gitdir)
    let l:gitdir = findfile('.git', l:start . ';')
  endif
  return empty(l:gitdir) ? getcwd() : fnamemodify(l:gitdir . '/..', ':p')
endfunction

let s:bifrost_filetypes = ['c', 'cpp', 'cs', 'go', 'java', 'javascript', 'javascriptreact', 'kotlin', 'php', 'python', 'ruby', 'rust', 'scala', 'typescript', 'typescriptreact']

for s:ft in s:bifrost_filetypes
  call ale#linter#Define(s:ft, {
  \ 'name': 'bifrost',
  \ 'lsp': 'stdio',
  \ 'executable': 'bifrost',
  \ 'command': 'bifrost --root . --lsp',
  \ 'cwd': function('s:bifrost_root'),
  \ 'project_root': function('s:bifrost_root'),
  \ })
endfor

let g:ale_linters = get(g:, 'ale_linters', {})
for s:ft in s:bifrost_filetypes
  let g:ale_linters[s:ft] = ['bifrost']
endfor
```

`project_root` finds the Git root per buffer and ALE sends it as the LSP workspace root. The `cwd` setting makes the relative `--root .` fallback resolve to that same directory. For completion, also set `let g:ale_completion_enabled = 1`, `let g:ale_completion_timeout = 10`, and `set omnifunc=ale#completion#OmniFunc`; trigger it manually with `CTRL-X CTRL-O` if your Vim does not show automatic suggestions. The longer timeout allows Bifrost's initial workspace index to finish before ALE gives up. Bifrost's current completion support is intentionally limited to simple identifier prefixes; completion after `.` or `::` is not supported yet. Navigation uses ALE's LSP commands, such as `:ALEGoToDefinition`, `:ALEFindReferences`, and `:ALEHover`.

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
