# Capture Hyper-V guest screen from the host side.
#
# Why not take a screenshot inside the guest: PowerShell Direct runs in session 0, and CopyFromScreen captures the host's session.
# Black screen; bringing the window to the foreground causes VMware to steal input, making the entire machine appear frozen from the host's perspective.
# Msvm_VirtualSystemManagementService::GetVirtualSystemThumbnailImage operates entirely on the host.
# Reading video memory on one side has no impact on the guest.
param(
    [string] $VMName = 'KSword-HVM-Target',
    [int]    $Width  = 1024,
    [int]    $Height = 768,
    [string] $OutFile
)

$ErrorActionPreference = 'Stop'

$vm = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem `
        -Filter "ElementName='$VMName'"
if (-not $vm) { throw "Virtual machine not found: $VMName" }

$settings = Get-CimAssociatedInstance -InputObject $vm `
    -ResultClassName Msvm_VirtualSystemSettingData |
    Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }

$svc = Get-CimInstance -Namespace root\virtualization\v2 `
    -ClassName Msvm_VirtualSystemManagementService

$result = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage `
    -Arguments @{
        TargetSystem = [CimInstance]$settings
        WidthPixels  = [uint16]$Width
        HeightPixels = [uint16]$Height
    }

if ($result.ReturnValue -ne 0) { throw "GetVirtualSystemThumbnailImage returned $($result.ReturnValue)" }

# Returns RGB565 little-endian, 2 bytes per pixel, row-major order, with a 4-byte header at the beginning.
#
# Both facts are measured, not guessed: array length is 1,572,868, while 1024×768×2 = 1,572,864,
# Exactly 4 extra bytes. Checking the original bytes—the start `79 85` repeats (0x8579 → RGB565 →
# (132,174,206) Light blue (the wallpaper); the ending `7D EF` repeats (0xEF7D → (238,239,238))
# Light gray is the taskbar; the toolbar row is `FF FF` pure white. All three known references match.
#
# Previously, swapping R and B without any measurements changed the blue tint to a red tint, merely reversing the error.
# The real error is this 4-byte offset, and **I mistakenly treated the correct blue offset as a fault**: the wallpaper is indeed blue.
$HEADER = 4
$raw = $result.ImageData
if ($raw.Length -ne ($HEADER + $Width * $Height * 2)) {
    # Stop if dimensions do not match; do not render a plausible-looking image based on incorrect assumptions.
    throw ("ImageData length {0} does not match RGB565+{3} header for {1}x{2} (expected {4})" -f `
        $raw.Length, $Width, $Height, $HEADER, ($HEADER + $Width * $Height * 2))
}
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$rect = New-Object System.Drawing.Rectangle(0, 0, $Width, $Height)
$data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly,
    [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$stride = $data.Stride
$buffer = New-Object byte[] ($stride * $Height)
for ($y = 0; $y -lt $Height; $y++) {
    $srcRow = $HEADER + $y * $Width * 2
    $dstRow = $y * $stride
    for ($x = 0; $x -lt $Width; $x++) {
        # **Must convert to int before shifting.**
        #
        # Elements of $raw are [byte], and PowerShell's -shl calculates based on the width of the left operand:
        # [byte] 0xAE -shl 8 results in **0**, not 0xAE00. Thus, each pixel retains only its low byte,
        # Red component is always 0, green has only a few bits, and blue is full — the entire image will inevitably appear blue.
        #
        # I previously mistook this 'bluish' artifact for a channel order swap (swapping R and B), but the result was just a constant red.
        # The root cause is on this line: the source bytes `5C AE` in the same frame were incorrectly calculated as v=0x005C.
        $lo = [int]$raw[$srcRow + $x * 2]
        $hi = [int]$raw[$srcRow + $x * 2 + 1]
        $v  = ($hi -shl 8) -bor $lo
        # 5:6:5 -> 8:8:8: Copy lower bits to higher bits to prevent the maximum brightness value from failing to reach 255.
        $r = (($v -shr 11) -band 0x1F); $r = ($r -shl 3) -bor ($r -shr 2)
        $g = (($v -shr 5)  -band 0x3F); $g = ($g -shl 2) -bor ($g -shr 4)
        $b = ( $v          -band 0x1F); $b = ($b -shl 3) -bor ($b -shr 2)
        # Format24bppRgb is stored in memory as B,G,R order, while the source is RGB565, so this mapping applies.
        $o = $dstRow + $x * 3
        $buffer[$o]     = [byte]$b
        $buffer[$o + 1] = [byte]$g
        $buffer[$o + 2] = [byte]$r
    }
}
[System.Runtime.InteropServices.Marshal]::Copy($buffer, 0, $data.Scan0, $buffer.Length)
$bmp.UnlockBits($data)
$bmp.Save($OutFile, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "saved=$OutFile bytes=$((Get-Item $OutFile).Length)"
