# C# external metadata fixture

`ExternalLibrary.dll` is a checked-in deterministic .NET 8 fixture for the
C# assembly metadata reader. Normal Rust tests consume the committed binary and
do not require the .NET SDK.

With .NET SDK 8.0.418 installed, run `bash scripts/verify-csharp-external-fixture.sh`
from the repository root to reproduce and verify it. To intentionally rewrite
only the committed DLL and its hash manifest, run
`bash scripts/regenerate-csharp-external-fixture.sh`, then rerun the verifier.
