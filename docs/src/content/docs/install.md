---
title: Install Bifrost
description: Install the released Bifrost binary or build it from source.
---

## uv and pipx

Install the native Bifrost CLI into an isolated environment with
[uv](https://docs.astral.sh/uv/):

```bash
uv tool install brokk-bifrost
bifrost --version
```

Or install it with [pipx](https://pipx.pypa.io/):

```bash
pipx install brokk-bifrost
bifrost --version
```

The PyPI package contains the compiled Rust executable; it does not run through
Python and does not download another Bifrost binary. Published wheels support
macOS on Apple Silicon and Intel, glibc Linux on x86-64 and ARM64, and x64
Windows. Use the install script or Cargo on the other platforms listed below.

Run a released CLI without installing it persistently:

```bash
uvx brokk-bifrost --version
```

Upgrade or remove a uv installation with `uv tool upgrade brokk-bifrost` or
`uv tool uninstall brokk-bifrost`. For pipx, use `pipx upgrade brokk-bifrost`
or `pipx uninstall brokk-bifrost`. The distribution name is `brokk-bifrost`,
while the command it installs is `bifrost`.

## npm and npx

Install the native CLI with npm:

```bash
npm install -g @brokkai/bifrost
bifrost --version
```

Run it one time without a persistent install:

```bash
npx -y @brokkai/bifrost --version
```

The root package installs one checksum-verified native package for the current
operating system, CPU, and Linux C library. It does not download or build
Bifrost during installation. Upgrade it with `npm update -g
@brokkai/bifrost`. Remove it with `npm uninstall -g @brokkai/bifrost`.

The CLI package is `@brokkai/bifrost`. The separate
`@brokk/bifrost-agent` package contains the Pi extension and agent skills.

## Homebrew

Install from the [BrokkAi Homebrew tap](https://github.com/BrokkAi/homebrew-tap)
on macOS (Apple Silicon and Intel) or Linux (x86-64 and ARM64 glibc):

```bash
brew install brokkai/tap/bifrost
bifrost --version
```

The formula installs the `bifrost` CLI from the release archive for your
platform and verifies its published SHA-256 checksum. Upgrade with `brew
upgrade bifrost` and uninstall with `brew uninstall bifrost`. The tap
regenerates its formulae from tagged releases on a schedule, so upgrades
follow new Bifrost releases automatically. For Windows, ARM64 musl Linux, or
Android, use the methods below.

## Install Script

Install the released binary with the install script:

```bash
curl -fsSL https://raw.githubusercontent.com/BrokkAi/bifrost/refs/heads/master/install.sh | bash
```

The script detects your platform, downloads the matching release archive from
GitHub, verifies its published SHA-256 checksum, and installs `bifrost` into
`~/.local/bin`. It offers to add that directory to your `PATH` when it is
missing and the terminal is interactive.

### Supported Platforms

| Platform | Architecture | Install script | Release target |
| --- | --- | --- | --- |
| macOS | Apple Silicon and Intel | Yes | `universal-apple-darwin` |
| Linux (glibc) | x86-64 | Yes | `x86_64-unknown-linux-gnu` |
| Linux (musl, such as Alpine) | x86-64 | Yes | `x86_64-unknown-linux-musl` |
| Linux (glibc) | ARM64 | Yes | `aarch64-unknown-linux-gnu` |
| Linux (musl, such as Alpine) | ARM64 | No, use Cargo | none published |
| WSL 1 and WSL 2 | x86-64 and ARM64 | Yes, as Linux | Linux targets above |
| Android (Termux) | ARM64 | Yes | `aarch64-linux-android` |
| Windows | x64 and ARM64 | No, use Cargo | `.zip` on the release page |

On x86-64 Linux the script picks the archive matching your C library and falls
back to the statically linked musl build, which runs on any x86-64 Linux. On
ARM64 there is no musl archive, so the script stops with an explanation rather
than installing a glibc binary that cannot run.

### WSL

WSL is Linux, so run the same command inside your WSL shell. It installs the
Linux binary, which runs inside WSL only. Windows-native tools, such as an
editor or agent installed on the Windows side, cannot execute it, so install
the Windows build separately when something outside WSL needs to spawn
`bifrost`.

### Windows

The install script does not cover Windows, whose release assets are `.zip`
archives. Use [Cargo](#cargo), which works on Windows and builds the same
version from source, or download the archive for your architecture from the
[release page](https://github.com/BrokkAi/bifrost/releases) and place
`bifrost.exe` on your `PATH` yourself. Running the script from Git Bash, MSYS2,
or Cygwin does not work either, and it will say so rather than installing a
binary Windows cannot run.

Pipe-to-shell installs run remote code. To read the script before running it,
download it first:

```bash
curl -fsSL -O https://raw.githubusercontent.com/BrokkAi/bifrost/refs/heads/master/install.sh
less install.sh
bash install.sh
```

The script accepts these environment variables:

| Variable | Purpose |
| --- | --- |
| `INSTALL_DIR` | Install directory. Defaults to `~/.local/bin`. |
| `BIFROST_INSTALL_DIR` | Same as `INSTALL_DIR`, with higher precedence. |
| `BIFROST_VERSION` | Release tag to install, for example `v0.8.17`. Defaults to the latest release. |
| `BIFROST_GITHUB_OWNER` | GitHub owner to download from. Defaults to `BrokkAi`. |
| `GITHUB_TOKEN` | Token used for GitHub API rate limits. |
| `PROFILE` | Shell profile to update when the install directory is not on `PATH`. |

Pin a version and choose the directory like this:

```bash
BIFROST_VERSION=v0.8.17 INSTALL_DIR=/usr/local/bin \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/BrokkAi/bifrost/refs/heads/master/install.sh)"
```

Re-running the script installs over the existing binary, so it also serves as
the upgrade path.

## Cargo

Cargo builds the CLI from source and works on any platform with a Rust
toolchain, including Windows:

```bash
cargo install brokk-bifrost --locked --force
```

For local development, build this checkout:

```bash
cargo build --bin bifrost
```

## Verify The Install

Check that the binary is available, whichever method you used:

```bash
bifrost --help
```

When configuring tools that spawn Bifrost, prefer an absolute binary path unless `bifrost` is intentionally installed on the host `PATH`.

The packaged agent plugin uses a separate launcher that can download its pinned, checksum-verified Bifrost release into a user cache. See [Data and Trust Boundaries](/data-boundaries/#plugin-launcher-downloads-and-cache) for resolution order, cache locations, and the controls that disable or relocate downloads.

## Python Package

The Python API is a separate distribution from the CLI. Add the native Python
client to a uv project with:

```bash
uv add brokk-bifrost-searchtools
```

Or install it with pip:

```bash
pip install brokk-bifrost-searchtools
```

Import it as `bifrost_searchtools`. See [Python Client](../python-client/) for the API surface and local development workflow.

## Optional Semantic Search

Semantic search is not part of the default Rust feature set. Build with `--features nlp` and enable it at runtime:

```bash
cargo build --features nlp --bin bifrost
BIFROST_SEMANTIC_INDEX=auto bifrost --root /path/to/project --mcp core
```

This `core` example is intentionally scoped to symbol navigation plus optional semantic search; it does not expose `query_code`. Use `--mcp "symbol|extended"` for a structural-query-capable agent, or add `extended` to the composition when semantic search and structural queries are both required.

See [Semantic Search](../semantic-search/) for model, accelerator, and index details.
