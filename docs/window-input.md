# Window input and ordering

[简体中文](zh-CN/window-input.md) · [Documentation index](README.md)

Both **Window → Window input and order** and **Miscellaneous → DWM / Win32k
injection** expose the complete controls. The former acts on the current window;
the latter accepts a list selection or HWND. Both reuse input, UIAccess-band,
DWM-order, and restore panels and can load/query/restore DWM without visiting the other page.

## Operations

| Setting | Behavior | Limit |
| --- | --- | --- |
| Not clickable | `EnableWindow(FALSE)` disables mouse/keyboard input; restoration preserves the previous enabled state. | Not click-through; system permissions can reject it. |
| Mouse click-through | Adds `WS_EX_LAYERED` and `WS_EX_TRANSPARENT`; a previously non-layered window starts fully opaque. | Existing alpha, color key, and per-pixel contents are preserved. Own/class-DC windows cannot gain layered styling. |
| Click while visually covered, original band | `SetWindowPos(HWND_TOPMOST)` changes real order; the loaded DWM agent keeps the visual at the end of composition. | Cannot cross higher input bands, including UIAccess. Requires a visible, enabled, non-minimized, non-transparent, unowned top-level window and the single continuous DWM hold slot. |
| UIAccess: front | A native Win32k transaction moves the window to band 2 and its front. | Backend checked on every apply; no DWM injection required. One-time change, not continuous order enforcement. |
| UIAccess: back of band | Moves to band 2 behind its other windows. | Still above normal-band windows. |
| UIAccess: click while covered | Real order at the front of band 2, with the DWM visual continuously last. | Requires the matching R0 driver and loaded DWM agent; later window actions may change real order. |
| Restore this session | Restores saved enabled state, added style bits, original band/topmost state; DWM returns to current Windows order. | Does not reconstruct historical neighboring positions. Records live only in this process; restore before exit. |

No `WM_MOUSE*` forwarding or click simulation is used. The system handles input
according to the modified native band/list. Hit testing, transparent regions,
mouse capture, and application state still affect the receiver. Readback alone
is not click acceptance. `EnableWindow` returns the previous disabled state, not
a conventional success Boolean; the implementation verifies styles. Merely setting
`WS_EX_TRANSPARENT` is not universal top-level click-through.

## Identity, concurrency, and recovery

Before mutation, verify HWND, PID, TID, and process creation time and attach a
session-specific property to the target. The property disappears with the window,
preventing a reused HWND from receiving an old restore. Restore only this operation's
style bits and preserve unrelated changes, including newly adopted layered content.

Combined native/DWM failures attempt rollback and retain incomplete records for
retry. A DWM request timeout does not cancel the remote thread; the client blocks
subsequent requests until it finishes, preventing a late apply from overwriting
restoration. Covered-click mode and manual DWM ordering are mutually exclusive.
Restore the existing hold first; global stop restores input before stopping DWM
callbacks. Ordinary disable/click-through needs neither DWM nor R0, and the current
implementation does not apply input restrictions to KSword itself.

## Native transaction and version binding

Both pages use `WindowInputControl` / `ArkDriverClient::controlWindowBand` for
query/apply/restore. Compatibility query is optional and read-only; it does not set
a global enable flag. Every apply validates again. The sole shared protocol is
`shared/driver/KswordArkWindowBandIoctl.h`, IOCTL function `0x898`, dispatched through
the registry. `EvtIoInCallerContext` retains the originating GUI thread. The device
requires read/write access; changes also pass the existing Safety policy.

The documented supported `win32kfull.sys` sample is bound to:

| Identity | Value |
| --- | --- |
| Version | `10.0.26100.9022` |
| SHA-256 | `a8c75a11c28e54b62bc86e5566872241a94d6c485e0a93de1b39d89d57d40445` |
| PE timestamp | `0x5CD0A4AF` |
| Image size | `0x428000` |
| RSDS / age | `80DB0813-4711-330D-D706-8D826FF8E1B0` / `1` |

Runtime checks include PE/RSDS, function prefixes, and executable sections. Other
versions do not use nearby-version or guessed offsets. Windows 10 DWM support is
not Windows 10 Win32k support. Caller and target must share a desktop, the original
band must be 1 or 2, and owned window groups are rejected. CoreWindow is not guessed
from unverified THREADINFO offsets.

| Location in the verified sample | Observed role |
| --- | --- |
| `NtUserSetWindowBand`, RVA `0x259060` | Acquires the GUI session critical section, validates/locks the window, then calls internal ordering. |
| `xxxSetWindowBand`, `0x203010` | Existing wrapper used to verify parameters and component hierarchy; not called directly. |
| `_DeferWindowPosAndBand`, `0x985E8` | Existing caller-permission checks; no IAM, token, or process-capability patching. |
| `InternalBeginDeferWindowPos`, `0x980D0` | Creates the native SMWP transaction. |
| `_DeferWindowPos`, `0x98894` | Nine-argument ABI, band in argument nine; native band mask with no-move/no-size/no-activate flags `0x60013`. |
| `xxxEndDeferWindowPosEx`, `0x9731C` | Two-argument ABI; async permission is zero here, followed by readback. Includes group-band update, list reordering, DWM notification, and mouse-move generation. |
| `Win32HM_LockIntoThread<0>` / `UnlockFromThread<0>`, `0x26DE0` / `0x26170` | USER thread lock, with a two-pointer stack lock record. |
| `NtUserGetWindowBand`, `0x2A8650` | Indirect band read; evidence for reading, not permission to write the field directly. |

The sample's `GetBandOrdinal` table is
`1,15,12,9,8,11,10,5,6,13,4,7,16,17,18,3,14,2`. Band 2 is highest in this table;
moving forward orders within UIAccess rather than inventing a higher band.

The driver does not directly write bands, lists, or system code. Within USER's
exclusive critical section it verifies window/thread objects, PID/TID, creation
time, caller desktop, and top-level/owner relationships, then uses the verified
native transaction. The window lock spans native callbacks that may release the
critical section; identity is rechecked afterward. Success requires band and
boundary-neighbor readback even if the native transaction returned TRUE. Failure
attempts the original band, retaining incomplete restore records and restoring
topmost state affected by the band transition.

These private functions are absent from this sample's GFIDS. Only the small
non-inlined wrappers calling precisely verified addresses use `guard(nocf)`.
Addresses come from the current kernel-stack image binding, never an R3 pointer;
system CFG tables are unchanged and all other driver code retains project CFG settings.

## Validation

`tests/native/dwm_z_order/WindowInputTests.vcxproj` creates offscreen windows in its own
child process and tests real Win32 disable/click-through/restore, child windows,
existing alpha/color keys, unrelated styles, invalid identity, and rollback after
native-topmost/DWM-receipt failures. DWM and R0 acknowledgments are doubles: no
driver is opened, no DWM injection occurs, and Win32k is not modified.

Cases include apply without prior enabling, read-only compatibility checks,
query-before-set identity, original-band restoration, rollback on DWM failure,
and retained records when restoration fails. They do not establish real UIAccess
click acceptance.

On an isolated machine with the matching driver, overlap normal and UIAccess
windows on the same desktop and verify front/back ordering, both covered-click
modes, queries after another window becomes topmost, and band/topmost restoration.
Also test target closure during a transaction and rejection of owned popups,
other desktops, and mismatched versions. Visual DWM changes alone do not establish
correct input ordering.

```powershell
& $msbuild tests/native/dwm_z_order/WindowInputTests.vcxproj /p:Configuration=Release /p:Platform=x64 /m:1
& tests/native/dwm_z_order/x64/Release/WindowInputTests.exe
```
