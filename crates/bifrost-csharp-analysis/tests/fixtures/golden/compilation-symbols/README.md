# Compiler oracle

SDK: .NET 10.0.403. Each project was built in Debug with a Probe.cs containing
#if SYMBOL / #warning DEFINED_SYMBOL / #endif for every entry in candidates.txt.
compiler-symbols.txt records the compiler warnings, deduplicated. The golden
compares the discovered closed set to that oracle over the probed symbols;
open sets must be subsets. Loose files and Unrestored have no build oracle.

Multi declares net10.0-windows;net10.0. Restore writes originalTargetFrameworks
as [net10.0, net10.0-windows], sorted rather than declaration order. The selected
build probe uses -f net10.0. Its selected environment equals Console's.
The retained assets fixtures retain only the consumed restore framework array.
Generated imports retain their XML structure; machine-specific package roots
are replaced with MSBuild properties. These paths are never evaluated.

WithBuild references Oracle.WithBuild 1.0.0, a test package with build/Oracle.WithBuild.props
that appends PACKAGE. WithoutBuild references Oracle.WithoutBuild 1.0.0, containing
only its nuspec. Both were restored from a controlled local package source.
NuGet network access was available; local packages isolate the build-asset
classification from future package releases. Neither is product pack content.
Intermediate sets BaseIntermediateOutputPath=generated/ in Directory.Build.props.

SDK rules: Microsoft.NET.Sdk.CSharp.props:21-22 adds TRACE after Directory.Build.props;
Microsoft.NET.Sdk.CSharp.targets:16-31 adds DEBUG after project/Directory.Build.targets;
Microsoft.NET.Sdk.BeforeCommon.targets:188-207 generates framework names,
234-247 compatible versions, 290-295 appends them before compilation.
Microsoft.NET.SupportedTargetFrameworks.props supplies the version tables.
Open environments list no symbols because unevaluated targets may overwrite defines.

The comparison probes every implicit-table symbol for the selected framework
plus every DefineConstants token, so closed-set equality is full-set equality
over that candidate set. The golden also asserts that every listed symbol is
in the candidate universe (there is no filtering of unexpected actual symbols).
Unsupported uses the SDK-supported net10.0-windows form with implicit defines
disabled, which Bifrost deliberately leaves open as unsupported_framework.
SdkImport contains a local Extras.props decoy and an unresolved custom SDK; it
has no build oracle because the SDK is intentionally unavailable. UnusedDynamic
pins conservative openness for a property function even when not referenced.
The test hides every Directory.Build/Packages file from enumeration. It changes
an ignored ancestor props file, then adds a nearer one, checking new selected
set digests and the expected replacement of ANCESTOR_EDIT by NEARER.
