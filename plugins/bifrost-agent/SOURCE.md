# Corresponding Source

Each official Bifrost artifact identifies its version as `X.Y.Z`. The complete
corresponding source for that artifact, including the build and installation
scripts, is the Git tag `vX.Y.Z` in the Bifrost repository:

https://github.com/BrokkAi/bifrost/releases/tag/vX.Y.Z

Replace `X.Y.Z` with the version printed by `bifrost --version`, recorded in the
Python package metadata, or displayed by the editor extension. The release page
provides source archives for that exact tag. The repository history is also
available at:

https://github.com/BrokkAi/bifrost

Bifrost is licensed under `LGPL-3.0-or-later`. `LICENSE.md` contains the GNU
LGPL version 3 text, and `GPL-3.0.md` contains the incorporated GNU GPL version
3 text. In binary and wheel artifacts,
`THIRD_PARTY_LICENSES.html` and `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` contain
license information, standalone notices, and exact source-package links for
incorporated Rust and vendored native dependencies. An artifact-specific
third-party notice file covers other bundled dependencies, such as the
production npm packages inside the VS Code extension.
