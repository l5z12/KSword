"""Static gate for per-processor private EPT.

This change affects the VM-exit path, which has no runtime verification: loading drivers requires signature testing,
and the host cannot be the target. Therefore, invariants that must be fixed on the build machine must be fixed.

The access control checks only two specific cases: both are locations where omitting a single character would silently degrade to a shared hierarchy:

1. The INVEPT operand on the flipped path must be the one from the transient context, not the shared pointer directly.
   Use an operand whitelist instead of 'forbid runtime->eptPointer'—the latter would incorrectly
   flag legitimate references in the same file and can be bypassed by adding a single space.

2. Both ARM sites must still receive the local parameter. Cases exist where the signature is reverted but the
   call site still compiles (parameters can be silently discarded), so we directly compare the signature text here.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HVM = REPO / 'drivers/ark/src/features/hvm'

# Allowed INVEPT operands on the flip path: must prioritize the level recorded in the transient record.
ALLOWED_OPERAND = re.compile(
    r"transient->eptPointer\s*!=\s*0ULL\s*\?\s*"
    r"transient->eptPointer\s*:\s*runtime->eptPointer",
    re.S,
)

# Invalidation of the private root before its first use is another valid usage; the operand is eptLocal's own pointer.
ALLOWED_PRIVATE_ROOT = re.compile(r"context->eptLocal->eptPointer", re.S)

# Fix path for first access monitoring.
#
# Isomorphic to ALLOWED_OPERAND, but the first term of the ternary expression resides in a local variable rather than
# transient->eptPointer — because this path does not create a transient record: after a monitor hit, the permission is
# Permanently restored with no 'pending reclaim' items. Copying that form would cause it to permanently fail the shared root at the private level.
# This is exactly the degenerate case that this guard is designed to prevent.
#
# Tightly coupled with the previous line: both operands of the ternary must be the same local variable and shared root; a typo in either breaks the match.
ALLOWED_WATCH_RESTORE = re.compile(
    r"invalidatePointer\s*!=\s*0ULL\s*\?\s*"
    r"invalidatePointer\s*:\s*runtime->eptPointer",
    re.S,
)

# That local variable must originate from a private-level pointer. Without this rule, the whitelist above merely recognizes a name.
# The name, which can be assigned anything.
REQUIRED_WATCH_RESTORE_SOURCE = re.compile(
    r"invalidatePointer\s*=\s*local->eptPointer\s*;",
    re.S,
)

# The resident entry invalidates "the level that will actually be loaded upon entry," which has a different shape than the flip path:
# One check covers the EPTP about to be written to the VMCS; the other covers every secondary hierarchy this resident session might switch to.
# Using the flip path's shape to constrain the entry path would incorrectly flag these two valid checks as violations—they are exactly
# The fix for the shared root stale tag defect itself.
ALLOWED_ENTRY_ROOT = re.compile(r"\binput\.eptPointer\b", re.S)
ALLOWED_ENTRY_SECONDARY = re.compile(r"\bsecondary\b", re.S)

INVEPT_CALL = re.compile(r"kswordArkHvmAsmInveptSingle\s*\(([^;]*?)\)\s*", re.S)

# Only inspect function bodies that execute INVEPT during residency. Installation and unloading also invoke INVEPT, but they run outside
# They run at PASSIVE and are rejected during resident operation. They modify shared leaf entries, so shared pointers are correct there. Including them
# Including it would turn the access control into a source of false positives. An access control prone to false positives will eventually be disabled, which is worse than having no access control at all.
#
# Whitelist is per-function, not global: each site's 'valid operands' are different things; merging them into one set is incorrect.
# A global whitelist allows any valid form at one location to be permitted everywhere else, reducing the access control to 'allowed if used'.
# These names pass the check.
CHECKED_FUNCTIONS = [
    ("hvm_ept.c", "kswordArkHvmEptRestoreTransient",
     [ALLOWED_OPERAND, ALLOWED_PRIVATE_ROOT]),
    ("hvm_ept.c", "kswordArkHvmEptHandleViolation",
     [ALLOWED_OPERAND, ALLOWED_PRIVATE_ROOT, ALLOWED_WATCH_RESTORE]),
    ("hvm_ept_view.c", "kswordArkHvmEptViewHandleViolation",
     [ALLOWED_OPERAND, ALLOWED_PRIVATE_ROOT]),
    ("hvm_resident.c", "KswordARKHvmConfigureResidentVmcsFromAsm",
     [ALLOWED_ENTRY_ROOT, ALLOWED_ENTRY_SECONDARY, ALLOWED_PRIVATE_ROOT]),
]

REQUIRED_SIGNATURES = [
    ("hvm_ept.c", "kswordArkHvmEptHandleViolation"),
    ("hvm_ept.h", "kswordArkHvmEptHandleViolation"),
    ("hvm_ept_view.c", "kswordArkHvmEptViewHandleViolation"),
    ("hvm_ept_view.h", "kswordArkHvmEptViewHandleViolation"),
]

NEWLINE = chr(10)


def function_bodies(text, symbol):
    """Extract each function body of a top-level function along with its offset in the file.

    In C source code, the closing brace marking function end is always in column 0. This convention is stable in
    this repository, making it far simpler than brace matching and immune to parentheses inside strings or comments.
    """
    bodies = []
    marker = NEWLINE + symbol + "("
    start = text.find(marker)
    while start != -1:
        opening = text.find(NEWLINE + "{", start)
        if opening == -1:
            break
        end = text.find(NEWLINE + "}", opening)
        if end == -1:
            break
        bodies.append((opening, text[opening:end]))
        start = text.find(marker, end)
    return bodies


def check_invept_operands():
    """Every INVEPT on each checked path must be named with the correct hierarchy."""
    failures = []
    for name, symbol, allowed in CHECKED_FUNCTIONS:
        text = (HVM / name).read_text(encoding="utf-8")
        bodies = function_bodies(text, symbol)
        if not bodies:
            failures.append("{}: Function body for {} not found".format(name, symbol))
            continue
        call_count = 0
        for offset, body in bodies:
            for match in INVEPT_CALL.finditer(body):
                call_count += 1
                operand = match.group(1)
                if any(pattern.search(operand) for pattern in allowed):
                    continue
                line = text[: offset + match.start()].count(NEWLINE) + 1
                failures.append(
                    "{}:{} {} INVEPT operand not in whitelist: {}".format(
                        name, line, symbol, " ".join(operand.split())
                    )
                )
            # If the invalidatePointer form is used, it must be proven that it originates from the private hierarchy.
            # Otherwise, the whitelist merely recognizes a name, which can be assigned to anything.
            if ALLOWED_WATCH_RESTORE.search(body) and not (
                REQUIRED_WATCH_RESTORE_SOURCE.search(body)
            ):
                failures.append(
                    "{}: {} used invalidatePointer as INVEPT operand,"
                    "But it was not assigned to local->eptPointer".format(name, symbol)
                )
        if call_count == 0:
            failures.append(f"{name}: {symbol} has no recognized INVEPT call")
    return failures


def check_arm_site_signatures():
    """Both ARM sites must still receive the local descriptor."""
    failures = []
    for name, symbol in REQUIRED_SIGNATURES:
        text = (HVM / name).read_text(encoding="utf-8")
        found = False
        index = text.find(symbol + "(")
        while index != -1:
            end = text.find(")", index)
            if end != -1 and "_In_opt_ const KswHvmEptLocal* local" in text[index:end]:
                found = True
                break
            index = text.find(symbol + "(", index + 1)
        if not found:
            failures.append(
                "{}: {}'s signature lacks the local parameter; the private hierarchy will be silently bypassed".format(
                    name, symbol
                )
            )
    return failures


def main():
    # On GitHub's Windows runner, sys.stdout encoding is cp1252; writing Chinese directly throws an error.
    # UnicodeEncodeError. The consequence of encountering this once is more severe than it sounds: no printing occurs when the access control gate passes.
    # Since it is not in Chinese, it was never exposed; once a violation is actually detected, it will appear on the first line of the failed print list.
    # Crash; what appears in CI is a charmap traceback, not a detection of what was found. That is,
    # The error channel fails exactly when it is needed.
    #
    # Use reconfigure instead of try/except: Deliver messages as-is rather than downgrading them to question marks.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

    failures = check_invept_operands() + check_arm_site_signatures()
    if failures:
        sys.stdout.write("Per-CPU private EPT gate failure:" + NEWLINE)
        for failure in failures:
            sys.stdout.write("  - {}".format(failure) + NEWLINE)
        return 1
    sys.stdout.write("Per-CPU private EPT gate passed." + NEWLINE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
