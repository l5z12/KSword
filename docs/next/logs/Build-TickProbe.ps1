# Convert tickprobe.asm into a bootable 1.44MB floppy disk image.
#
# Why not hand-write bytes: a misaligned relative jump in the boot sector causes a black screen, and a black screen looks identical to 'interrupts never arrived'
# On screenshots, they appear identical—if the fixture under test fails, it is mistaken for the phenomenon under test. Therefore, every instruction is handled by the assembler.
# Generate output; here, perform only three mechanical steps: extract the code section, fill in two relocations, and append the boot signature.
#
# Relocations must be filled manually: MASM leaves the immediate value for `OFFSET msg_spin` as 0000 and records a DIR16 entry,
# Normally filled by the linker. Since we skip the linking step (we need a flat binary), we directly follow COFF conventions.
# The relocation table writes back symbol addresses. If not filled, the two labels will fetch strings from 0000:0000.
# Garbled characters appear on screen—**another case of "the fixture is broken but it looks like the DUT is broken"**.
param(
    [string] $Asm,
    [string] $OutImage,
    [string] $WorkDir
)

$ErrorActionPreference = 'Stop'

$ml = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" `
        -Filter 'ml.exe' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like '*Hostx64\x86*' } | Select-Object -First 1
if (-not $ml) { throw 'ml.exe not found' }

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$obj = Join-Path $WorkDir 'tickprobe.obj'
Push-Location $WorkDir
try {
    & $ml.FullName /c /nologo /Fo $obj $Asm
    if ($LASTEXITCODE -ne 0) { throw "ml failed, exit code $LASTEXITCODE" }
} finally { Pop-Location }

# --- Parse COFF: locate the .text section and its relocations.
$raw = [IO.File]::ReadAllBytes($obj)
$numSections = [BitConverter]::ToUInt16($raw, 2)
$symTab      = [BitConverter]::ToUInt32($raw, 8)
$numSymbols  = [BitConverter]::ToUInt32($raw, 12)
$strTab      = $symTab + 18 * $numSymbols

$textPtr = 0; $textSize = 0; $relPtr = 0; $relCount = 0
for ($i = 0; $i -lt $numSections; $i++) {
    $h = 20 + $i * 40
    $name = ([Text.Encoding]::ASCII.GetString($raw, $h, 8)).TrimEnd([char]0)
    if ($name -notlike '.text*') { continue }
    $textSize = [BitConverter]::ToUInt32($raw, $h + 16)
    $textPtr  = [BitConverter]::ToUInt32($raw, $h + 20)
    $relPtr   = [BitConverter]::ToUInt32($raw, $h + 24)
    $relCount = [BitConverter]::ToUInt16($raw, $h + 32)
    break
}
if ($textSize -eq 0) { throw 'No .text section found' }

# ORG 7C00h causes MASM to prepend 0x7C00 bytes of zeros; the actual code follows.
$ORG = 0x7C00
if ($textSize -le $ORG) { throw "Section too small ($textSize), did ORG take effect?" }
$codeLen = $textSize - $ORG
$code = New-Object byte[] $codeLen
[Array]::Copy($raw, $textPtr + $ORG, $code, 0, $codeLen)
Write-Output ("Code length = $codeLen bytes")

# --- Fill relocations ---
function SymbolName($index) {
    $o = $symTab + 18 * $index
    if ([BitConverter]::ToUInt32($raw, $o) -eq 0) {
        $off = [BitConverter]::ToUInt32($raw, $o + 4)
        $end = $strTab + $off
        while ($raw[$end] -ne 0) { $end++ }
        return [Text.Encoding]::ASCII.GetString($raw, $strTab + $off, $end - ($strTab + $off))
    }
    return ([Text.Encoding]::ASCII.GetString($raw, $o, 8)).TrimEnd([char]0)
}
function SymbolValue($index) { return [BitConverter]::ToUInt32($raw, $symTab + 18 * $index + 8) }

for ($r = 0; $r -lt $relCount; $r++) {
    $o = $relPtr + $r * 10
    $va   = [BitConverter]::ToUInt32($raw, $o)
    $sym  = [BitConverter]::ToUInt32($raw, $o + 4)
    $type = [BitConverter]::ToUInt16($raw, $o + 8)
    # 0x0001 = IMAGE_REL_I386_DIR16, 16-bit absolute address. Only this type is supported.
    # Other types indicate code references in forms I didn't expect; better to throw an error than to write a single byte incorrectly.
    if ($type -ne 1) { throw ("Unknown relocation type 0x{0:X} @ 0x{1:X}" -f $type, $va) }
    $target = SymbolValue $sym
    $at = $va - $ORG
    $code[$at]     = [byte]($target -band 0xFF)
    $code[$at + 1] = [byte](($target -shr 8) -band 0xFF)
    Write-Output ("  Relocating {0} -> 0x{1:X4}  Writing at code offset 0x{2:X}" -f (SymbolName $sym), $target, $at)
}

if ($codeLen -gt 510) { throw "Code is $codeLen bytes, cannot fit into boot sector" }

# --- Assemble a 1.44MB floppy disk image ---
$img = New-Object byte[] (1474560)
[Array]::Copy($code, 0, $img, 0, $codeLen)
$img[510] = 0x55
$img[511] = 0xAA
[IO.File]::WriteAllBytes($OutImage, $img)
Write-Output ("Image = $OutImage  " + (Get-Item $OutImage).Length + "  bytes, boot signature 55 AA written")
