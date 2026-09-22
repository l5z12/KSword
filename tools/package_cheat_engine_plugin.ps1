[CmdletBinding()]
param(
    [string]$CheatEngineDirectory = '',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$sourceRoot = Join-Path $repositoryRoot 'integrations/cheat_engine_launcher'
$pluginRoot = Join-Path $repositoryRoot 'plugin\cheat-engine'

# If not explicitly specified, resolve the CE directory from system installation info to avoid hardcoding paths for personal machines.
if ([string]::IsNullOrWhiteSpace($CheatEngineDirectory)) {
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $installation = Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq 'Cheat Engine 7.6' } |
        Select-Object -First 1
    $CheatEngineDirectory = [string]$installation.InstallLocation
}

# All input artifacts must exist; missing any one stops the process to avoid generating a seemingly complete but broken plugin.
$ceDirectory = [IO.Path]::GetFullPath($CheatEngineDirectory)
$launcher = Join-Path $sourceRoot "x64\$Configuration\KswordCheatEngineLauncher.exe"
$bridgeX64 = Join-Path $repositoryRoot "integrations/cheat_engine_plugin\x64\$Configuration\KswordCheatEnginePlugin.dll"
$bridgeWin32 = Join-Path $repositoryRoot "integrations/cheat_engine_plugin\Win32\$Configuration\KswordCheatEnginePlugin.dll"
$requiredFiles = @(
    (Join-Path $ceDirectory 'cheatengine-x86_64.exe'),
    $launcher,
    $bridgeX64,
    $bridgeWin32
)
foreach ($requiredFile in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required file is missing: $requiredFile"
    }
}

# Only clean up the exact plugin directory owned by the script and verify it is located under the repository's plugin root.
$expectedPluginRoot = [IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot 'plugin\cheat-engine'))
if ([IO.Path]::GetFullPath($pluginRoot) -ne $expectedPluginRoot) {
    throw "Refusing to replace unexpected path: $pluginRoot"
}
if (Test-Path -LiteralPath $pluginRoot) {
    Remove-Item -LiteralPath $pluginRoot -Recurse -Force
}

$payloadRoot = Join-Path $pluginRoot 'payload\Cheat Engine'
$bridgeRoot = Join-Path $pluginRoot 'bridge'
New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $bridgeRoot 'x64') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $bridgeRoot 'Win32') -Force | Out-Null

# Preserve the original CE user-mode directory layout, then remove its DBK/DBVM kernel payloads and uninstaller.
Copy-Item -Path (Join-Path $ceDirectory '*') -Destination $payloadRoot -Recurse -Force
$excludedPayloads = @(
    'dbk32.cepack',
    'dbk64.cepack',
    'dbk64.sys',
    'Kernelmoduleunloader.exe',
    'vmdisk.img',
    'vmdisk.img.sig',
    'unins000.dat',
    'unins000.exe',
    'unins000.msg'
)
foreach ($relativePath in $excludedPayloads) {
    $candidate = Join-Path $payloadRoot $relativePath
    if (Test-Path -LiteralPath $candidate) {
        Remove-Item -LiteralPath $candidate -Force
    }
}

# Overwrite KSword's own entry point, manifest, notification, auto-load script, and dual-architecture bridge DLL.
Copy-Item -LiteralPath $launcher -Destination (
    Join-Path $pluginRoot 'KswordCheatEngineLauncher.exe') -Force
Copy-Item -LiteralPath $bridgeX64 -Destination (
    Join-Path $bridgeRoot 'x64\KswordCheatEnginePlugin.dll') -Force
Copy-Item -LiteralPath $bridgeWin32 -Destination (
    Join-Path $bridgeRoot 'Win32\KswordCheatEnginePlugin.dll') -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'plugin.json') -Destination $pluginRoot -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'README.md') -Destination $pluginRoot -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'SOURCE.md') -Destination $pluginRoot -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'LICENSE') -Destination (
    Join-Path $pluginRoot 'LICENSE.txt') -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'NOTICE.md') -Destination (
    Join-Path $pluginRoot 'NOTICE') -Force
Copy-Item -LiteralPath (
    Join-Path $sourceRoot 'integration\00_ksword_theme.lua') -Destination (
    Join-Path $payloadRoot 'autorun\00_ksword_theme.lua') -Force
Copy-Item -LiteralPath (
    Join-Path $sourceRoot 'integration\10_ksword_bridge.lua') -Destination (
    Join-Path $payloadRoot 'autorun\10_ksword_bridge.lua') -Force

# Output machine-readable summary to facilitate build log verification that plugin files truly contain the expected content.
$allFiles = Get-ChildItem -LiteralPath $pluginRoot -Recurse -File
[pscustomobject]@{
    PluginRoot = $pluginRoot
    FileCount = $allFiles.Count
    TotalBytes = [int64](($allFiles | Measure-Object Length -Sum).Sum)
    LauncherSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (
        Join-Path $pluginRoot 'KswordCheatEngineLauncher.exe')).Hash
    BridgeX64Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (
        Join-Path $bridgeRoot 'x64\KswordCheatEnginePlugin.dll')).Hash
    BridgeWin32Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (
        Join-Path $bridgeRoot 'Win32\KswordCheatEnginePlugin.dll')).Hash
} | ConvertTo-Json
