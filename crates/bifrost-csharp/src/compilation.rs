//! SDK-owned compilation-wide imports (not source syntax).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplicitUsingCondition {
    Always,
    NotNetFramework,
    WindowsForms,
    WpfRemove,
}

use ImplicitUsingCondition::*;

/// Implicit import additions after Microsoft.NET.Sdk's C# props.
///
/// dotnet/sdk v8.0.418, d9ba08558d003ffd8730a44d2da9bd5fb128576d:
/// src/Tasks/Microsoft.NET.Build.Tasks/targets/Microsoft.NET.Sdk.CSharp.props,
/// src/WebSdk/Web/Targets/Sdk.Server.props,
/// src/WebSdk/Worker/Targets/Microsoft.NET.Sdk.Worker.props,
/// src/BlazorWasmSdk/Sdk/Sdk.props. Props lists and conditions also checked at
/// v9.0.300 (15606fe0a89a80cd2cc3a905913588c95dd4a26c) and
/// v10.0.100 (e6bc966cc3d1348265b0831c6daca23267169d8f).
/// .NET 10 additionally adds a using in RazorSdk/Targets/Sdk.Razor.CurrentVersion.targets,
/// in _AddEmbeddedValidationAttribute; the configuration evaluator flags that
/// input-dependent target separately, rather than claiming the props list complete.
/// All require ImplicitUsings=true/enable; extension SDKs also require C#.
/// Props imports follow Directory.Build.props and precede project items.
/// The base System.Net.Http entry additionally excludes .NETFramework.
/// WindowsDesktop props (also imported by the base SDK when installed) apply
/// UseWindowsForms/UseWPF conditions after the base C# props. WPF removes
/// System.IO and System.Net.Http; Windows Forms adds Drawing and Forms.
/// Sources: dotnet/wpf 738c1f8ff725ea0fee44f11947a40fe0b6b7df07 (SDK-pinned 8.0.24)
/// packaging/Microsoft.NET.Sdk.WindowsDesktop/targets/
/// Microsoft.NET.Sdk.WindowsDesktop.{props,WPF.props}; dotnet/winforms
/// 464883c66de7fc35195fbc06193ef8ee351491f9 (SDK-pinned 8.0.24)
/// pkg/Microsoft.Private.Winforms/sdk/dotnet-wpf/
/// Microsoft.NET.Sdk.WindowsDesktop.WindowsForms.props.
/// Tuple positions: SDK name, ordered (namespace, condition) items. Base namespaces appear in the
/// first row; all supported SDKs import that row before their extras.
/// Web/Sdk/Sdk.props delegates browser TargetFrameworks to the Blazor SDK.
pub const SDK_IMPLICIT_USINGS: &[(&str, &[(&str, ImplicitUsingCondition)])] = &[
    (
        "Microsoft.NET.Sdk",
        &[
            ("System", Always),
            ("System.Collections.Generic", Always),
            ("System.IO", Always),
            ("System.Linq", Always),
            ("System.Net.Http", NotNetFramework),
            ("System.Threading", Always),
            ("System.Threading.Tasks", Always),
            ("System.Drawing", WindowsForms),
            ("System.Windows.Forms", WindowsForms),
            ("System.IO", WpfRemove),
            ("System.Net.Http", WpfRemove),
        ],
    ),
    (
        "Microsoft.NET.Sdk.Web",
        &[
            ("System.Net.Http.Json", Always),
            ("Microsoft.AspNetCore.Builder", Always),
            ("Microsoft.AspNetCore.Hosting", Always),
            ("Microsoft.AspNetCore.Http", Always),
            ("Microsoft.AspNetCore.Routing", Always),
            ("Microsoft.Extensions.Configuration", Always),
            ("Microsoft.Extensions.DependencyInjection", Always),
            ("Microsoft.Extensions.Hosting", Always),
            ("Microsoft.Extensions.Logging", Always),
        ],
    ),
    (
        "Microsoft.NET.Sdk.Worker",
        &[
            ("Microsoft.Extensions.Configuration", Always),
            ("Microsoft.Extensions.DependencyInjection", Always),
            ("Microsoft.Extensions.Hosting", Always),
            ("Microsoft.Extensions.Logging", Always),
        ],
    ),
    ("Microsoft.NET.Sdk.Razor", &[]),
    (
        "Microsoft.NET.Sdk.BlazorWebAssembly",
        &[
            ("Microsoft.Extensions.Configuration", Always),
            ("Microsoft.Extensions.DependencyInjection", Always),
            ("Microsoft.Extensions.Logging", Always),
        ],
    ),
    ("Microsoft.NET.Sdk.WindowsDesktop", &[]),
];
