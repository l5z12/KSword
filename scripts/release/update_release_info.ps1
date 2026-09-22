$ErrorActionPreference = 'Stop'

# Write-Stage:
# - Output stage logs in a unified format to facilitate observation of script execution.
# - Usage: Write-Stage "text".
function Write-Stage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    Write-Host "[ReleaseInfo] $Message"
}

# Escape-CppStringLiteral:
# - Convert input text into content safe for writing to QStringLiteral("...").
# - Usage: Escape-CppStringLiteral -RawText "v1.2.3";
# - Input parameter RawText: the raw text to be written;
# - Output: escaped C++ string literal.
function Escape-CppStringLiteral {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RawText
    )

    # escapedText purpose: Stores the progressively escaped text, processing backslashes before double quotes.
    $escapedText = $RawText.Replace('\', '\\')
    $escapedText = $escapedText.Replace('"', '\"')
    return $escapedText
}

# Resolve-ReleaseType:
# - Map user input to standardized release types (normal/preview/dev);
# - Usage: Resolve-ReleaseType -InputText "Preview";
# - Input parameter InputText: The release type text entered by the user;
# - Output parameter: A standardized type string; throws an error if unrecognized.
function Resolve-ReleaseType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputText
    )

    # normalizedText: Normalizes case and whitespace to reduce input format variance.
    $normalizedText = $InputText.Trim().ToLower()
    switch ($normalizedText) {
        '1' { return 'normal' }
        '2' { return 'preview' }
        '3' { return 'dev' }
        'normal' { return 'normal' }
        'release' { return 'normal' }
        '正式' { return 'normal' }
        '正式版' { return 'normal' }
        '普通' { return 'normal' }
        '普通版' { return 'normal' }
        'preview' { return 'preview' }
        'pre' { return 'preview' }
        '预览' { return 'preview' }
        '预览版' { return 'preview' }
        'dev' { return 'dev' }
        'debug' { return 'dev' }
        '开发' { return 'dev' }
        '开发版' { return 'dev' }
        default {
            throw ("Unrecognized release type: {0}. Valid values: normal / preview / dev; Chinese aliases are also accepted." -f $InputText)
        }
    }
}

# Invoke-GitOrThrow:
# - Execute Git commands in the specified repository directory and convert failures into explicit errors containing the command content;
# - Invocation: Invoke-GitOrThrow -RepositoryRootPath $path -Arguments @('tag', '--annotate', ...).
# - Input parameter RepositoryRootPath: Root directory of the Git repository.
# - Input Arguments: The array of parameters passed to git.
# - Output: none; throws an error if Git returns a non-zero value.
function Invoke-GitOrThrow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRootPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & git -C $RepositoryRootPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("Git command failed (exit code {0}): git -C `"{1}`" {2}" -f $LASTEXITCODE, $RepositoryRootPath, ($Arguments -join ' '))
    }
}

# Update-QStringLiteralByMarker:
# - Locate and replace the content of QStringLiteral("...") using "same-line comment markers".
# - Usage: Update-QStringLiteralByMarker -FilePath xxx -Marker xxx -NewValue xxx;
# - Input parameter FilePath: Target file path;
# - Input parameter Marker: comment marker text;
# - Input parameter NewValue: the new value to be written (automatically escaped internally by the script);
# - Output: None (directly writes back to the file).
function Update-QStringLiteralByMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$Marker,
        [Parameter(Mandatory = $true)]
        [string]$NewValue
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "File does not exist: $FilePath"
    }

    # fileLines purpose: load file text line by line to locate the target line for replacement based on the marker.
    $fileLines = [System.Collections.Generic.List[string]]::new()
    $fileLines.AddRange([string[]](Get-Content -LiteralPath $FilePath))

    # targetLineIndex: Records the index of the target line containing the marker; remains -1 if not found.
    $targetLineIndex = -1
    for ($lineIndex = 0; $lineIndex -lt $fileLines.Count; $lineIndex++) {
        if ($fileLines[$lineIndex].Contains($Marker)) {
            $targetLineIndex = $lineIndex
            break
        }
    }
    if ($targetLineIndex -lt 0) {
        throw "Marker not found: $Marker (file: $FilePath)"
    }

    # sourceLine: Reads the original target line for regex replacement and subsequent write-back.
    $sourceLine = $fileLines[$targetLineIndex]
    # patternText purpose: Matches a single QStringLiteral("...") fragment.
    $patternText = 'QStringLiteral\("([^"\\]|\\.)*"\)'
    if (-not [System.Text.RegularExpressions.Regex]::IsMatch($sourceLine, $patternText)) {
        throw ("Marker line not found with replaceable QStringLiteral literal: {0} (file: {1})" -f $Marker, $FilePath)
    }

    # escapedValue purpose: Store the escaped new value to avoid breaking C++ string syntax.
    $escapedValue = Escape-CppStringLiteral -RawText $NewValue
    # replacementText: Constructs the complete QStringLiteral("...") snippet for replacement.
    $replacementText = "QStringLiteral(`"$escapedValue`")"
    $updatedLine = [System.Text.RegularExpressions.Regex]::Replace(
        $sourceLine,
        $patternText,
        [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $replacementText },
        [System.Text.RegularExpressions.RegexOptions]::None,
        [TimeSpan]::FromSeconds(2))

    $fileLines[$targetLineIndex] = $updatedLine
    try {
        Set-Content -LiteralPath $FilePath -Value $fileLines -Encoding UTF8
    }
    catch {
        throw "Failed to write file (possibly occupied by IDE): $FilePath; Original error: $($_.Exception.Message)"
    }
}

# Update-NextLineByMarker:
# - Replaces the target text using the line immediately following the marked line.
# - Usage: Update-NextLineByMarker -FilePath xxx -Marker xxx -NewLine xxx;
# - Input parameter FilePath: Target file path;
# - Input parameter Marker: comment marker text;
# - Input: NewLine - the complete line text to replace with;
# - Output: None (directly writes back to the file).
function Update-NextLineByMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$Marker,
        [Parameter(Mandatory = $true)]
        [string]$NewLine
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "File does not exist: $FilePath"
    }

    # fileLines purpose: load file text line by line to locate the next line based on the marker for replacement.
    $fileLines = [System.Collections.Generic.List[string]]::new()
    $fileLines.AddRange([string[]](Get-Content -LiteralPath $FilePath))

    # markerLineIndex: Records the line index containing the marker to calculate the next line position.
    $markerLineIndex = -1
    for ($lineIndex = 0; $lineIndex -lt $fileLines.Count; $lineIndex++) {
        if ($fileLines[$lineIndex].Contains($Marker)) {
            $markerLineIndex = $lineIndex
            break
        }
    }
    if ($markerLineIndex -lt 0) {
        throw "Marker not found: $Marker (file: $FilePath)"
    }
    if ($markerLineIndex + 1 -ge $fileLines.Count) {
        throw "No replaceable line exists after marking: $Marker (file: $FilePath)"
    }

    $fileLines[$markerLineIndex + 1] = $NewLine
    try {
        Set-Content -LiteralPath $FilePath -Value $fileLines -Encoding UTF8
    }
    catch {
        throw "Failed to write file (possibly occupied by IDE): $FilePath; Original error: $($_.Exception.Message)"
    }
}

# ===================== Main flow =====================

# scriptRootPath: Directory containing the script (project root), used for concatenating relative paths.
$scriptRootPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# gitRepositoryRootPath: Absolute root directory of the Git repository containing the current release script.
$gitRepositoryRootPath = (& git -C $scriptRootPath rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitRepositoryRootPath)) {
    throw "The directory containing the release script is not within an available Git repository: $scriptRootPath"
}

# Resolve the desktop sources from the repository, independent of this script's folder.
$sourceRootPath = Join-Path $gitRepositoryRootPath 'apps/desktop'

# Purpose of gitHeadCommitHash: the latest commit at the start of the release; new tags always point precisely to this commit.
$gitHeadCommitHash = (& git -C $gitRepositoryRootPath rev-parse --verify HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitHeadCommitHash)) {
    throw "Unable to determine the latest Git commit (HEAD): $gitRepositoryRootPath"
}

# welcomeDockFilePath: Target file for the welcome page source code.
$welcomeDockFilePath = Join-Path $sourceRootPath 'welcome_dock\WelcomeDock.cpp'
# appIconRcFilePath purpose: native Win32 resource script file (used to replace the EXE icon).
$appIconRcFilePath = Join-Path $sourceRootPath 'AppIcon.rc'

Write-Stage "Preparing to update release information."
Write-Stage "Target directory: $sourceRootPath"

# Purpose of versionInputText: Stores the version string input by the user (e.g., v5.1.0-preview1).
$versionInputText = Read-Host 'Please enter the current version number (string)'
if ([string]::IsNullOrWhiteSpace($versionInputText)) {
    throw 'Version number cannot be empty.'
}

# releaseTypeInputText: Stores the user's input text for the release type.
$releaseTypeInputText = Read-Host 'Please enter the release type (1=Normal, 2=Preview, 3=Development; also supports normal/preview/dev)'
# releaseTypeKey: The normalized result of the release type, taking only one of normal/preview/dev.
$releaseTypeKey = Resolve-ReleaseType -InputText $releaseTypeInputText

# gitTagName purpose: Publishes the Git tag name by directly reusing the version number to ensure consistency between the release version and the commit tag.
$gitTagName = $versionInputText.Trim()
Invoke-GitOrThrow `
    -RepositoryRootPath $gitRepositoryRootPath `
    -Arguments @('check-ref-format', '--allow-onelevel', "refs/tags/$gitTagName")

# Check for existing tag with the same name to prevent the release script from overwriting it.
& git -C $gitRepositoryRootPath show-ref --verify --quiet "refs/tags/$gitTagName"
if ($LASTEXITCODE -eq 0) {
    throw "Git tag already exists, release stopped to avoid overwrite: $gitTagName"
}
if ($LASTEXITCODE -ne 1) {
    throw "Failed to check if Git tag already exists: $gitTagName"
}

# buildTimeText purpose: Records the precise build time text (including milliseconds and time zone) when the script executes.
$buildTimeText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff K')

# appIconRelativePath purpose: Select the ICO resource path corresponding to the EXE icon based on the release type.
$appIconRelativePath = switch ($releaseTypeKey) {
    'normal' { 'Resource/Logo/KswordLogo.ico' }
    'preview' { 'Resource/Logo/KswordLogo_PRE.ico' }
    'dev' { 'Resource/Logo/KswordLogo_DEV.ico' }
    default { throw "Internal error: Unknown release type $releaseTypeKey" }
}

# appIconAbsolutePath purpose: Maps the relative path to the project's absolute path and validates the existence of the ICO file in advance.
$appIconAbsolutePath = Join-Path $sourceRootPath $appIconRelativePath
if (-not (Test-Path -LiteralPath $appIconAbsolutePath)) {
    throw "Target application icon file does not exist: $appIconAbsolutePath"
}

Write-Stage "Version number: $versionInputText"
Write-Stage "Release type: $releaseTypeKey"
Write-Stage "Build time: $buildTimeText"
Write-Stage "Application icon: $appIconRelativePath"
Write-Stage "Git tag：$gitTagName -> $gitHeadCommitHash"

# 1) Updates the welcome page version number (displayed in larger font; source text located at the marker line in WelcomeDock.cpp).
Update-QStringLiteralByMarker `
    -FilePath $welcomeDockFilePath `
    -Marker 'RELEASE_META_VERSION_MARKER' `
    -NewValue $versionInputText

# 2) Update the welcome page build time note (precise to milliseconds).
Update-QStringLiteralByMarker `
    -FilePath $welcomeDockFilePath `
    -Marker 'RELEASE_META_BUILD_TIME_MARKER' `
    -NewValue $buildTimeText

# 3) Update native Win32 resource icons (switch to different ICO files based on release type).
$appIconResourceLine = "IDI_APP_ICON ICON `"$appIconRelativePath`""
Update-NextLineByMarker `
    -FilePath $appIconRcFilePath `
    -Marker 'RELEASE_APP_ICON_FILE_MARKER' `
    -NewLine $appIconResourceLine

# 4) Create an annotated tag for the latest commit at the start of the release; do not push. The publisher executes 'git push origin <tag>' as needed.
$gitTagMessage = "Release $gitTagName ($releaseTypeKey)"
Invoke-GitOrThrow `
    -RepositoryRootPath $gitRepositoryRootPath `
    -Arguments @('tag', '--annotate', $gitTagName, $gitHeadCommitHash, '--message', $gitTagMessage)

Write-Stage 'Release information update completed.'
Write-Stage "Updated: $welcomeDockFilePath"
Write-Stage "Updated: $appIconRcFilePath"
Write-Stage "Created Git tag: $gitTagName -> $gitHeadCommitHash"
