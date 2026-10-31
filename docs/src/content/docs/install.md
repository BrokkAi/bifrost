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

The PyPI package contains the compiled Rust executable, xz-compressed to stay
under PyPI's upload limit; it does not download another Bifrost binary. The
first `bifrost` run unpacks and verifies the executable, which takes a few
seconds, and every run after that replaces a short Python launcher with the
native process. The unpacked copy sits beside the package, or in your user
cache directory when the installation is read-only. Uninstalling leaves the
unpacked copy (a `bin-*` directory in the `brokk_bifrost_cli` package
directory) behind. Published wheels support
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
operating system and CPU. It does not download or build Bifrost during
installation. Native packages exist for these platforms:

| Operating system | CPU |
| --- | --- |
| macOS | Apple Silicon and Intel |
| Linux with glibc | x64 and ARM64 |
| Android | ARM64 |
| Windows | x64 and ARM64 |

Linux with musl, such as Alpine, is not supported.
Upgrade it with `npm update -g @brokkai/bifrost`. Remove it with
`npm uninstall -g @brokkai/bifrost`.

The CLI package is `@brokkai/bifrost`. The separate
`@brokk/bifrost-agent` package contains the Pi extension and host MCP integration.

## Connect Coding Hosts

After Bifrost and one or more coding hosts are installed, register a user-level
MCP server named `brokk`:

```bash
bifrost --install
```

The command registers the current Bifrost executable with installed Codex,
Claude Code, OpenCode, Kimi Code, Hermes, and Oh My Pi clients. It starts
Bifrost with the `core` toolset. The server starts without a fixed
project and uses the workspace root that the client supplies for each session.

The command finds clients by these command names on `PATH`:

| Client | Command | How Bifrost registers the server |
| --- | --- | --- |
| Codex | `codex` | Runs `codex mcp add`. |
| Claude Code | `claude` | Runs `claude mcp add` with user scope. If a user-level `brokk` entry already exists, Bifrost removes it and adds it again. |
| OpenCode | `opencode2`, or else `opencode` | Runs `opencode2 mcp add`. For `opencode`, writes the `brokk` entry into `opencode/opencode.json` in the user configuration directory. |
| Kimi Code | `kimi` | Runs `kimi mcp add`. |
| Hermes | `hermes` | Runs `hermes mcp add` and checks the result. |
| Oh My Pi | `omp` | Writes the `brokk` entry into `mcp.json` in the directory that `omp config path` prints. |

The command skips clients that are not installed. If it finds no client, it
prints `No supported coding host was found` and exits 1. If registration fails
for a client, the command still tries the others, then reports every failure
and exits 1. It does not install client applications, skills, instruction
files, or extensions. Run it again after the Bifrost executable moves to a
different path. `--install` cannot be combined with any other flag.

Oh My Pi receives a native user MCP entry. It reads Bifrost's standard MCP instructions and adds them to its model prompt.

Original Pi uses the separate
`@brokk/bifrost-agent` extension described on the [Pi page](/pi/). The command
does not install or change that extension.

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
follow new Bifrost releases automatically. For Windows, musl Linux, or Android,
use the methods below.

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
| macOS | Apple Silicon and Intel | Yes | `universal-apple-darwin` (also published per CPU as `aarch64-apple-darwin` and `x86_64-apple-darwin`) |
| Linux (glibc 2.28+) | x86-64 | Yes | `x86_64-unknown-linux-gnu` |
| Linux (musl, such as Alpine) | x86-64 | No, unsupported | none published |
| Linux (glibc 2.28+) | ARM64 | Yes | `aarch64-unknown-linux-gnu` |
| Linux (musl, such as Alpine) | ARM64 | No, unsupported | none published |
| WSL 1 and WSL 2 | x86-64 and ARM64 | Yes, as Linux | Linux targets above |
| Android (Termux) | ARM64 | Yes | `aarch64-linux-android` |
| Windows | x64 and ARM64 | No, use Cargo | `.zip` on the release page |

On Linux the script installs the GNU archive for your architecture. Both GNU
archives require glibc 2.28 or newer. On a musl system the script stops before
downloading and explains that no supported prebuilt release is available,
rather than installing a glibc binary that cannot run.

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

The script reads `BIFROST_VERSION` to choose a release and `INSTALL_DIR` or
`BIFROST_INSTALL_DIR` to choose the directory. It also reads
`BIFROST_GITHUB_OWNER`, `GITHUB_TOKEN`, and `PROFILE`. See
[Environment Variables](/reference/environment/#install-script) for each
variable's values and default.

Pin a version and choose the directory like this:

```bash
BIFROST_VERSION=v0.8.17 INSTALL_DIR=/usr/local/bin \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/BrokkAi/bifrost/refs/heads/master/install.sh)"
```

Re-running the script installs over the existing binary, so it also serves as
the upgrade path.

## Cargo

Cargo builds the CLI from source and works on supported platforms with a Rust
toolchain, including Windows. Musl builds are not tested or supported, but
users may attempt the same source installation command:

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

Import it as `bifrost_searchtools`. See [Python Client](/python-client/) for the API surface and local development workflow.
