<#
.SYNOPSIS
    Generate or reuse a local test signing certificate for KswordARK.sys and perform test signing on drivers in the development output directory.

.DESCRIPTION
    Windows x64 test mode does not mean "fully allow unsigned drivers".
    Even if bcdedit /set testsigning on has been executed, the kernel still requires .sys files to have at least a test signature,
    and the signing certificate must be trusted by the local machine. Otherwise, StartServiceW/NtLoadDriver will still return 577.

    This script defaults to handling common KswordARK.sys output locations in the repository:
    - drivers/ark\x64\Release\KswordARK.sys
    - drivers/ark\x64\Debug\KswordARK.sys
    - artifacts/bin\x64\Release\KswordARK.sys
    - artifacts/bin\x64\Debug\KswordARK.sys
    - artifacts/bin\x64\Release\KswordARKDriver\KswordARK.sys
    - artifacts/bin\x64\Debug\KswordARKDriver\KswordARK.sys

    Alternatively, explicitly specify the main executable, DLL, or other final artifacts via -TargetPath.
    This mode reuses the same .cert\KswordARK-TestSigning.pfx/.cer and does not generate a second set of signing certificates.

    Recommended to run with an Administrator PowerShell. When run as Administrator, the test certificate is imported into
    LocalMachine\Root and TrustedPublisher; when run without Administrator privileges, it is imported only into CurrentUser.
    The file will be signed, but kernel loading may still fail with error 577 due to missing machine-level trust.
#>

[CmdletBinding()]
param(
    # DriverPath: Explicitly specifies one or more .sys file paths; if not specified, automatically signs the existing KswordARK.sys in the repository.
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]] $DriverPath,

    # TargetPath: explicitly specifies one or more files to be signed; the main program ultimately reuses the driver test certificate for signing via this parameter.
    [string[]] $TargetPath,

    # Subject: Test certificate subject; keeping it stable allows subsequent builds to reuse the same certificate.
    [string] $Subject = 'CN=KswordARK Test Signing Certificate',

    # PfxPassword: Password to protect the local .pfx file; the default value is for development and testing certificates in this repository only.
    [string] $PfxPassword = 'KswordARK-TestSigning-LocalOnly',

    # EnableTestSigning: Conveniently enables Windows test signing mode; requires administrator privileges and takes effect after a reboot.
    [switch] $EnableTestSigning,

    # SkipMachineTrust: do not import the LocalMachine trust store even if running as administrator; used only for troubleshooting certificate contamination.
    [switch] $SkipMachineTrust,

    # NonFatal: Used for VS/MSBuild post-build steps; signature failures output warnings and return 0 to prevent build interruption by the signing environment.
    [switch] $NonFatal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 may use legacy CSPs to create file-based self-signed certificates on some machines, triggering NTE_NOT_FOUND.
# PowerShell 7 uses the newer .NET certificate API for better stability; if available, automatically delegate to pwsh to execute the same script.
if ($PSVersionTable.PSVersion.Major -lt 7 -and -not $env:KSWORD_SIGN_SCRIPT_PWSH_BOOTSTRAPPED) {
    $pwshCommand = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($pwshCommand -and (Test-Path -LiteralPath $pwshCommand.Source)) {
        $env:KSWORD_SIGN_SCRIPT_PWSH_BOOTSTRAPPED = '1'
        $forwardArgs = @(
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $PSCommandPath,
            '-Subject',
            $Subject,
            '-PfxPassword',
            $PfxPassword
        )
        if ($DriverPath) {
            foreach ($pathItem in $DriverPath) {
                $forwardArgs += @('-DriverPath', $pathItem)
            }
        }
        if ($TargetPath) {
            foreach ($pathItem in $TargetPath) {
                $forwardArgs += @('-TargetPath', $pathItem)
            }
        }
        if ($EnableTestSigning) {
            $forwardArgs += '-EnableTestSigning'
        }
        if ($SkipMachineTrust) {
            $forwardArgs += '-SkipMachineTrust'
        }
        if ($NonFatal) {
            $forwardArgs += '-NonFatal'
        }

        & $pwshCommand.Source @forwardArgs
        $exitCode = $LASTEXITCODE
        Remove-Item Env:\KSWORD_SIGN_SCRIPT_PWSH_BOOTSTRAPPED -ErrorAction SilentlyContinue
        exit $exitCode
    }

    Write-Warning 'pwsh.exe not found, continuing with Windows PowerShell; if certificate generation fails, please install PowerShell 7 and retry.'
}

# Resolve-RepoRoot：
# - Inputs: None;
# - Handling: Locate the repository root directory by traversing up from the script path.
# - Returns: Absolute path to the repository root.
function Resolve-RepoRoot {
    $scriptDirectory = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDirectory '..')).Path
}

# Test-Admin：
# - Inputs: None;
# - Processing: Check if the current token belongs to the Administrators group.
# - Returns: true indicates an administrator PowerShell session; false indicates standard user permissions.
function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Find-SignTool：
# - Inputs: None;
# - Handling: Prioritize KSWORD_SIGNTOOL/PATH, then scan common Windows Kits directories;
# - Returns: the absolute path to signtool.exe.
function Find-SignTool {
    if ($env:KSWORD_SIGNTOOL -and (Test-Path -LiteralPath $env:KSWORD_SIGNTOOL)) {
        return (Resolve-Path -LiteralPath $env:KSWORD_SIGNTOOL).Path
    }

    $pathCommand = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($pathCommand -and (Test-Path -LiteralPath $pathCommand.Source)) {
        return $pathCommand.Source
    }

    $candidateRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin",
        'E:\Windows Kits\10\bin'
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $candidateTools = foreach ($root in $candidateRoots) {
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $x64Tool = Join-Path $_.FullName 'x64\signtool.exe'
                $x86Tool = Join-Path $_.FullName 'x86\signtool.exe'
                if (Test-Path -LiteralPath $x64Tool) { Get-Item -LiteralPath $x64Tool }
                elseif (Test-Path -LiteralPath $x86Tool) { Get-Item -LiteralPath $x86Tool }
            }
    }

    $bestTool = $candidateTools | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $bestTool) {
        throw 'signtool.exe not found. Please install Windows SDK/WDK, or set the KSWORD_SIGNTOOL environment variable.'
    }

    return $bestTool.FullName
}

# New-FileBackedCertificate：
# - Input: Certificate subject, PFX path, CER path, and PFX password;
# - Processing: Generate a Code Signing certificate using .NET CertificateRequest that does not rely on the system certificate store.
# - Returns: an X509Certificate2 object containing the private key.
function New-FileBackedCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string] $CertificateSubject,

        [Parameter(Mandatory = $true)]
        [string] $PfxPath,

        [Parameter(Mandatory = $true)]
        [string] $CerPath,

        [Parameter(Mandatory = $true)]
        [securestring] $SecurePassword
    )

    $rsaKey = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256
        $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $CertificateSubject,
            $rsaKey,
            $hashAlgorithm,
            $padding)

        $basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
            $true,
            $false,
            0,
            $true)
        $request.CertificateExtensions.Add($basicConstraints)

        $keyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true)
        $request.CertificateExtensions.Add($keyUsage)

        $enhancedUsages = [System.Security.Cryptography.OidCollection]::new()
        [void]$enhancedUsages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        $enhancedKeyUsage = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
            $enhancedUsages,
            $false)
        $request.CertificateExtensions.Add($enhancedKeyUsage)

        $notBefore = [System.DateTimeOffset]::Now.AddDays(-1)
        $notAfter = [System.DateTimeOffset]::Now.AddYears(10)
        $certificate = $request.CreateSelfSigned($notBefore, $notAfter)

        $pfxBytes = $certificate.Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
            $SecurePassword)
        [System.IO.File]::WriteAllBytes($PfxPath, $pfxBytes)

        $cerBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes($CerPath, $cerBytes)

        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfxBytes,
            $SecurePassword,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    }
    finally {
        if ($rsaKey) {
            $rsaKey.Dispose()
        }
    }
}

# Get-OrCreate-TestCertificate：
# - Input: Certificate subject, repository root directory, and PFX password;
# - Handling: Prioritize reusing .cert\KswordARK-TestSigning.pfx; regenerate if missing or expired;
# - Return: A hashtable containing the certificate object, PFX path, and CER path.
function Get-OrCreate-TestCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string] $CertificateSubject,

        [Parameter(Mandatory = $true)]
        [string] $RepoRoot,

        [Parameter(Mandatory = $true)]
        [string] $PlainPassword
    )

    $certificateDirectory = Join-Path $RepoRoot '.cert'
    New-Item -ItemType Directory -Path $certificateDirectory -Force | Out-Null

    $pfxPath = Join-Path $certificateDirectory 'KswordARK-TestSigning.pfx'
    $cerPath = Join-Path $certificateDirectory 'KswordARK-TestSigning.cer'
    $securePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force

    if (Test-Path -LiteralPath $pfxPath) {
        try {
            $existingCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $pfxPath,
                $securePassword,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
            if ($existingCertificate.Subject -eq $CertificateSubject -and
                $existingCertificate.NotAfter -gt (Get-Date).AddDays(30)) {
                if (-not (Test-Path -LiteralPath $cerPath)) {
                    $cerBytes = $existingCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    [System.IO.File]::WriteAllBytes($cerPath, $cerBytes)
                }
                Write-Host "Reusing file-based test certificate: $($existingCertificate.Thumbprint)"
                return @{
                    Certificate = $existingCertificate
                    PfxPath = $pfxPath
                    CerPath = $cerPath
                    Password = $PlainPassword
                }
            }
        }
        catch {
            Write-Warning "Existing PFX cannot be reused, will regenerate: $($_.Exception.Message)"
        }
    }

    Write-Host "Creating file-type test certificate: $CertificateSubject"
    $newCertificate = New-FileBackedCertificate `
        -CertificateSubject $CertificateSubject `
        -PfxPath $pfxPath `
        -CerPath $cerPath `
        -SecurePassword $securePassword
    Write-Host "PFX：$pfxPath"
    Write-Host "CER：$cerPath"

    return @{
        Certificate = $newCertificate
        PfxPath = $pfxPath
        CerPath = $cerPath
        Password = $PlainPassword
    }
}

# Import-TestCertificateTrust：
# - Input: certificate path, skip machine trust flag;
# - Processing: Import into CurrentUser/LocalMachine trust stores.
# - Returns: Nothing.
function Import-TestCertificateTrust {
    param(
        [Parameter(Mandatory = $true)]
        [string] $CerPath,

        [Parameter(Mandatory = $true)]
        [bool] $SkipMachine
    )

    Write-Host "Certificate file: $CerPath"
    try {
        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\CurrentUser\TrustedPublisher | Out-Null
        Write-Host 'Imported CurrentUser\Root and CurrentUser\TrustedPublisher.'
    }
    catch {
        Write-Warning "Failed to import CurrentUser certificate trust: $($_.Exception.Message)"
    }

    if ((Test-Admin) -and -not $SkipMachine) {
        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
        Write-Host 'Imported LocalMachine\Root and LocalMachine\TrustedPublisher.'
        return
    }

    if (-not $SkipMachine) {
        Write-Warning 'Not running as administrator: cannot import LocalMachine trust store. Kernel loading may still report 577.'
        Write-Warning 'Please re-run this script with Administrator PowerShell, or manually import .cert\KswordARK-TestSigning.cer into "Local Computer\Trusted Root Certification Authorities" and "Trusted Publishers".'
    }
}

# Resolve-SignTargets：
# - Input: repository root directory, explicit final artifact path, and driver path for legacy parameter compatibility;
# - Processing: Prefer normalizing explicit paths; fall back to scanning the default driver output directory if no explicit path is provided.
# - Returns: An array of absolute paths for deduplicated signing targets.
function Resolve-SignTargets {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepoRoot,

        [string[]] $ExplicitTargetPaths,

        [string[]] $ExplicitDriverPaths
    )

    $combinedExplicitPaths = @()
    if ($ExplicitTargetPaths) {
        $combinedExplicitPaths += $ExplicitTargetPaths
    }
    if ($ExplicitDriverPaths) {
        $combinedExplicitPaths += $ExplicitDriverPaths
    }
    $combinedExplicitPaths = @($combinedExplicitPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($combinedExplicitPaths.Count -gt 0) {
        return Resolve-DriverTargets -RepoRoot $RepoRoot -ExplicitPaths $combinedExplicitPaths
    }

    return Resolve-DriverTargets -RepoRoot $RepoRoot
}

# Resolve-DriverTargets：
# - Input: Repository root directory and user-specified explicit path;
# - Handling: Explicit paths take precedence; otherwise, collect common output paths within the repository.
# - Returns: an array of unique absolute driver paths.
function Resolve-DriverTargets {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepoRoot,

        [string[]] $ExplicitPaths
    )

    $explicitPathList = @($ExplicitPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($explicitPathList.Count -gt 0) {
        return $explicitPathList |
            ForEach-Object {
                if ([System.IO.Path]::IsPathRooted($_)) { $_ }
                else { Join-Path $RepoRoot $_ }
            } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
            Sort-Object -Unique
    }

    $relativeCandidates = @(
        'drivers/ark\x64\Release\KswordARK.sys',
        'drivers/ark\x64\Debug\KswordARK.sys',
        'artifacts/bin\x64\Release\KswordARK.sys',
        'artifacts/bin\x64\Debug\KswordARK.sys',
        'artifacts/bin\x64\Release\KswordARKDriver\KswordARK.sys',
        'artifacts/bin\x64\Debug\KswordARKDriver\KswordARK.sys'
    )

    return $relativeCandidates |
        ForEach-Object { Join-Path $RepoRoot $_ } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
        Sort-Object -Unique
}

# Enable-TestSigningIfRequested：
# - Input: Whether to request enabling;
# - Processing: Execute 'bcdedit /set testsigning on'.
# - Returns: Nothing.
function Enable-TestSigningIfRequested {
    param(
        [Parameter(Mandatory = $true)]
        [bool] $Requested
    )

    if (-not $Requested) {
        return
    }

    if (-not (Test-Admin)) {
        throw 'Enable test mode requires administrator PowerShell.'
    }

    & bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) {
        throw "bcdedit /set testsigning on failed, exit code: $LASTEXITCODE"
    }

    Write-Host 'Test signing has been enabled; a system restart is required for it to take effect.'
}

# Invoke-SignTool：
# - Input: signtool path, certificate information, and paths of files to be signed;
# - Processing: Perform embedded signing of the main executable, DLL, or driver using a file-based PFX.
# - Returns: Nothing.
function Invoke-SignTool {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SignToolPath,

        [Parameter(Mandatory = $true)]
        [hashtable] $CertificateInfo,

        [Parameter(Mandatory = $true)]
        [string] $TargetPath
    )

    Write-Host "Sign target: $TargetPath"
    $signOutput = & $SignToolPath sign /v /fd SHA256 /f $CertificateInfo.PfxPath /p $CertificateInfo.Password $TargetPath 2>&1
    $signExitCode = $LASTEXITCODE
    $signOutput | ForEach-Object { Write-Host $_ }
    if ($signExitCode -ne 0) {
        $joinedOutput = ($signOutput | Out-String).Trim()
        if ($joinedOutput -match 'ImportCertObject|0x80090011|NTE_NOT_FOUND|Access is denied|拒绝访问|找不到对象') {
            throw (
                "signtool cannot temporarily import the PFX private key, usually because the current PowerShell lacks write permissions to the certificate store/key container." +
                "Please re-run this script with Administrator PowerShell; Current target: $TargetPath; Exit code: $signExitCode")
        }
        throw "signtool sign failed: $TargetPath, exit code: $signExitCode"
    }

    $verifyOutput = & $SignToolPath verify /pa /v $TargetPath 2>&1
    $verifyExitCode = $LASTEXITCODE
    $verifyOutput | ForEach-Object { Write-Host $_ }
    if ($verifyExitCode -ne 0) {
        Write-Warning "signtool verify /pa failed: $TargetPath, exit code: $verifyExitCode."
        Write-Warning 'This usually indicates the certificate has not been imported into the local machine trust store; the signature has been written to the file, but an administrator must still import it into the LocalMachine trust store before the kernel loads.'
    }

    $signature = Get-AuthenticodeSignature -FilePath $TargetPath
    Write-Host "Signature status: $($signature.Status); Signer: $($signature.SignerCertificate.Subject)"
}

try {
    $repoRoot = Resolve-RepoRoot
    $isAdmin = Test-Admin
    Write-Host "Repository root directory: $repoRoot"
    Write-Host "Administrator privileges: $isAdmin"

    Enable-TestSigningIfRequested -Requested ([bool]$EnableTestSigning)

    $signTool = Find-SignTool
    Write-Host "signtool：$signTool"

    $certificateInfo = Get-OrCreate-TestCertificate `
        -CertificateSubject $Subject `
        -RepoRoot $repoRoot `
        -PlainPassword $PfxPassword
    Import-TestCertificateTrust -CerPath $certificateInfo.CerPath -SkipMachine ([bool]$SkipMachineTrust)

    $targets = @(Resolve-SignTargets -RepoRoot $repoRoot -ExplicitTargetPaths $TargetPath -ExplicitDriverPaths $DriverPath)
if (-not $targets -or $targets.Count -eq 0) {
        throw 'No signable target file found. Please compile the driver/main program first, or specify the path via -TargetPath/-DriverPath.'
    }

    foreach ($target in $targets) {
        Invoke-SignTool -SignToolPath $signTool -CertificateInfo $certificateInfo -TargetPath $target
    }

    Write-Host ''
    Write-Host 'Done.'
    if (-not $TargetPath) {
        Write-Host 'If loading still returns 577, please confirm:'
        Write-Host '1. In bcdedit /enum, testsigning is Yes, and the system has already restarted;'
        Write-Host '2. The certificate has been installed in LocalMachine\Root and LocalMachine\TrustedPublisher;'
        Write-Host '3. The service ImagePath points exactly to the just-signed KswordARK.sys.'
    }
}
catch {
    if ($NonFatal) {
        Write-Warning "KswordARK automatic signature test failed, but continuing build in NonFatal mode: $($_.Exception.Message)"
        Write-Warning 'To generate a loadable driver, please manually run with administrator PowerShell: powershell -ExecutionPolicy Bypass -File scripts\Sign-KswordArkDriverTest.ps1 -EnableTestSigning'
        exit 0
    }

    throw
}
