# Capture the VM screen via VMware's built-in VNC service and support sending keystrokes.
#
# Why not use screenshots:
#   - Hyper-V's thumbnail captures the **target machine's desktop**; a VMware window must be visible on it to see the VM.
#     VMware started through PowerShell Direct (session 0) opens its window on a non-visible desktop,
#     The thumbnail is completely empty. Interactive scheduled tasks also fail to start (schtasks /Run reports
#     "Element not found"）。
#   - `vmrun captureScreen` requires the guest to have VMware Tools installed and logged in, which is problematic for a 512-byte
#     Neither a boot sector nor a TinyCore disc is applicable.
#
# The VNC path bypasses the entire session issue: frame buffers come directly from the vmware-vmx process, regardless of window focus.
# It does not matter who has focus. Sending key events is the same — previously, key events could not enter VMware because they had to first
# Pass through window focus.
#
# The protocol uses only the minimal subset of RFB 3.8: no authentication, Raw encoding, and a single full-screen update.
# All multi-byte fields are **big-endian**, which is the difference between RFB and x86; writing incorrectly will not trigger an error.
# This will only produce an absurdly sized image — hence the upper bound check on width and height below.
param(
    [string] $VncHost = '127.0.0.1',
    [int]    $Port = 5900,
    [string] $OutFile,
    # X11 keysym sequence; fetch image after sending. If empty, fetch only the image.
    [int[]]  $Keys = @(),
    [int]    $KeyDelayMs = 120,
    # On the same connection, fetch multiple frames with an interval of FrameGapMs.
    #
    # Why this exists: when connecting, fetching one frame and then disconnecting may return stale data—VMware only updates the buffer when there is a client
    # Track dirty regions of the VGA text buffer only when the client is looking. This causes "the screen to freeze at line N".
    # It becomes a fake reading, which looks exactly like 'guest paused at line N'.
    # Capture at least two frames; the second frame represents the current state after the connection is established.
    [int]    $Frames = 1,
    [int]    $FrameGapMs = 4000
)

$ErrorActionPreference = 'Stop'

function Read-Exact([IO.Stream] $s, [int] $n) {
    $buf = New-Object byte[] $n
    $got = 0
    while ($got -lt $n) {
        $r = $s.Read($buf, $got, $n - $got)
        if ($r -le 0) { throw "Connection broke before reading $n bytes (read $got)" }
        $got += $r
    }
    return $buf
}
function BE16([byte[]] $b, [int] $o) { return ([int]$b[$o] -shl 8) -bor [int]$b[$o+1] }
function BE32([byte[]] $b, [int] $o) {
    return ([int64]$b[$o] -shl 24) -bor ([int64]$b[$o+1] -shl 16) -bor `
           ([int64]$b[$o+2] -shl 8) -bor [int64]$b[$o+3]
}
function Put16([byte[]] $b, [int] $o, [int] $v) {
    $b[$o] = [byte](($v -shr 8) -band 0xFF); $b[$o+1] = [byte]($v -band 0xFF)
}
function Put32([byte[]] $b, [int] $o, [int64] $v) {
    $b[$o]   = [byte](($v -shr 24) -band 0xFF); $b[$o+1] = [byte](($v -shr 16) -band 0xFF)
    $b[$o+2] = [byte](($v -shr 8)  -band 0xFF); $b[$o+3] = [byte]($v -band 0xFF)
}

$client = New-Object Net.Sockets.TcpClient
$client.Connect($VncHost, $Port)
$client.NoDelay = $true
$ns = $client.GetStream()
# A read timeout is required.
#
# After requesting a full frame, the server may return nothing if the screen has not changed at all, causing the client to block indefinitely.
# There, a 'script hang' and a 'guest hang' look identical from the outside. Once the timeout expires, report no change.
# This is also a read operation.
$ns.ReadTimeout = 20000

# --- Handshake ---
$ver = [Text.Encoding]::ASCII.GetString((Read-Exact $ns 12))
Write-Output ("Server version = " + $ver.Trim())
$mine = [Text.Encoding]::ASCII.GetBytes("RFB 003.008`n")
$ns.Write($mine, 0, 12)

$n = (Read-Exact $ns 1)[0]
if ($n -eq 0) {
    $len = BE32 (Read-Exact $ns 4) 0
    throw ("Server rejected: " + [Text.Encoding]::ASCII.GetString((Read-Exact $ns $len)))
}
$types = Read-Exact $ns $n
Write-Output ("Security Type = " + (($types | ForEach-Object { $_ }) -join ','))
if ($types -notcontains 1) { throw "The server does not accept unauthenticated (type 1) connections; VNC password authentication is not implemented here" }
$ns.Write([byte[]]@(1), 0, 1)
$res = BE32 (Read-Exact $ns 4) 0
if ($res -ne 0) { throw "Secure handshake failed, SecurityResult = $res" }

# ClientInit: 1 = shared; do not kick off other connected clients.
$ns.Write([byte[]]@(1), 0, 1)

$init = Read-Exact $ns 24
$w = BE16 $init 0
$h = BE16 $init 2
$nameLen = BE32 $init 20
$name = [Text.Encoding]::UTF8.GetString((Read-Exact $ns $nameLen))
Write-Output ("Frame buffer = ${w}x${h}   Name = $name")
if ($w -le 0 -or $h -le 0 -or $w -gt 8192 -or $h -gt 8192) {
    throw "Frame buffer size ${w}x${h} is unreasonable—likely due to reversed byte order"
}

# --- Specify pixel format: 32bpp, little-endian, true color, R/G/B shifts 16/8/0 ---
# This ensures each pixel maps to four bytes (B, G, R, X) in memory, aligning with the Format24bppRgb access pattern.
$pf = New-Object byte[] 16
$pf[0] = 32; $pf[1] = 24; $pf[2] = 0; $pf[3] = 1
Put16 $pf 4 255; Put16 $pf 6 255; Put16 $pf 8 255
$pf[10] = 16; $pf[11] = 8; $pf[12] = 0
$msg = New-Object byte[] 20
$msg[0] = 0
[Array]::Copy($pf, 0, $msg, 4, 16)
$ns.Write($msg, 0, 20)

# --- Use Raw encoding only: skip the entire decoder at the cost of a few MB per frame; negligible for local loopback ---
$msg = New-Object byte[] 8
$msg[0] = 2; Put16 $msg 2 1; Put32 $msg 4 0
$ns.Write($msg, 0, 8)

# --- Keys ---
# Bit 0x10000 = 'This key requires holding Shift'.
#
# RFB keysyms are case-sensitive, but VMware's server converts keysyms to scan codes when
# Does not synthesize Shift: sending 'S' (0x53) results in the guest receiving 's'. Measured cost is one full round.
# — The isolinux edit line shows console=ttys0, but Linux has no such console name; there is only one serial port.
# No bytes present, yet the corresponding line on the screen appears completely normal.
$shiftL = 0xFFE1
foreach ($k in $Keys) {
    $shifted = ($k -band 0x10000) -ne 0
    $code = $k -band 0xFFFF
    if ($shifted) {
        $km = New-Object byte[] 8
        $km[0] = 4; $km[1] = 1; Put32 $km 4 $shiftL; $ns.Write($km, 0, 8)
    }
    foreach ($down in 1, 0) {
        $km = New-Object byte[] 8
        $km[0] = 4; $km[1] = [byte]$down
        Put32 $km 4 $code
        $ns.Write($km, 0, 8)
    }
    if ($shifted) {
        $km = New-Object byte[] 8
        $km[0] = 4; $km[1] = 0; Put32 $km 4 $shiftL; $ns.Write($km, 0, 8)
    }
    Start-Sleep -Milliseconds $KeyDelayMs
}
if ($Keys.Count -gt 0) {
    Write-Output ("Sent " + $Keys.Count + " keys")
    Start-Sleep -Milliseconds 600
}

if (-not $OutFile) { $client.Close(); return }

Add-Type -AssemblyName System.Drawing

# **Reuse a single bitmap across frames.**
#
# In the first version, a new bitmap was created for each frame, drawing only the rectangles sent by the server — while the server sends changes only from the second frame onwards.
# The region (even if the request writes non-incremental data), so frames 2..N are all black, appearing as if the guest cleared the screen.
# Another instrument failure manifested as the measured phenomenon. Accumulating frames causes missing parts to retain content from the previous frame.
$bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)

for ($frame = 1; $frame -le $Frames; $frame++) {
    if ($frame -gt 1) { Start-Sleep -Milliseconds $FrameGapMs }

    # Non-incremental: Requires the full frame, not 'what changed since last time'.
    $req = New-Object byte[] 10
    $req[0] = 3; $req[1] = 0
    Put16 $req 2 0; Put16 $req 4 0; Put16 $req 6 $w; Put16 $req 8 $h
    $ns.Write($req, 0, 10)

    $hdr = $null
    try { $hdr = Read-Exact $ns 4 }
    catch [IO.IOException] {
        Write-Output ("Frame $frame - No update within {0} ms (screen unchanged)" -f $ns.ReadTimeout)
        continue
    }
    if ($hdr[0] -ne 0) { throw "Expected FramebufferUpdate(0), received message type $($hdr[0])" }
    $rects = BE16 $hdr 2

    $rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
    # ReadWrite, not WriteOnly: This frame may cover only a small portion of the screen; the rest must be preserved.
    $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadWrite,
        [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $stride = $data.Stride
    $buffer = New-Object byte[] ($stride * $h)
    [Runtime.InteropServices.Marshal]::Copy($data.Scan0, $buffer, 0, $buffer.Length)
    try {
        for ($r = 0; $r -lt $rects; $r++) {
            $rh = Read-Exact $ns 12
            $rx = BE16 $rh 0; $ry = BE16 $rh 2; $rw = BE16 $rh 4; $rht = BE16 $rh 6
            $enc = BE32 $rh 8
            if ($enc -ne 0) { throw "Rectangle $r uses encoding $enc, only Raw(0) is implemented here" }
            $px = Read-Exact $ns ($rw * $rht * 4)
            for ($y = 0; $y -lt $rht; $y++) {
                $src = $y * $rw * 4
                $dst = ($ry + $y) * $stride + $rx * 3
                for ($x = 0; $x -lt $rw; $x++) {
                    $buffer[$dst + $x*3]     = $px[$src + $x*4]      # B
                    $buffer[$dst + $x*3 + 1] = $px[$src + $x*4 + 1]  # G
                    $buffer[$dst + $x*3 + 2] = $px[$src + $x*4 + 2]  # R
                }
            }
        }
        [Runtime.InteropServices.Marshal]::Copy($buffer, 0, $data.Scan0, $buffer.Length)
    } finally {
        $bmp.UnlockBits($data)
    }
    $name = if ($Frames -eq 1) { $OutFile }
            else {
                $dir = [IO.Path]::GetDirectoryName($OutFile)
                $base = [IO.Path]::GetFileNameWithoutExtension($OutFile)
                [IO.Path]::Combine($dir, "$base-f$frame.png")
            }
    $bmp.Save($name, [System.Drawing.Imaging.ImageFormat]::Png)
    Write-Output ("saved=$name rectangle count=$rects bytes=" + (Get-Item $name).Length)
}
$bmp.Dispose()
$client.Close()
