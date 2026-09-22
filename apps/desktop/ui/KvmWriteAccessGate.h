// KvmWriteAccessGate.h
//
// R-1: The sole entry point to open the write access gate.
//
// The reason for extracting this is that the scope must be unique: the confirmation dialog for enabling write access has a persistent
// suppressionKey. Once a user checks 'Do not show again', their choice is remembered by this key. If a second location independently
// constructs its own confirmation text, a user who checked the box elsewhere will be prompted again at that entry point. Moreover, if the
// text differs by even a single character, it becomes impossible to determine what the user actually agreed to. Therefore, both the KVM menu
// in the title bar and the inline enablement in the dialog must use this single function, ensuring the text and key exist in only one place.

#pragma once

class QWidget;

namespace ks::ui
{
    // requestKvmWriteAccess: Ensure R-1 write access is enabled and report whether the caller may proceed.
    //
    // If access is already enabled, return true without prompting. Otherwise, show the standard high-risk
    // confirmation and persist the enabled setting only after confirmation. A false return means the user
    // declined: write access stays disabled, and the caller must stop without sending any state-changing request.
    //
    // Only accesses QSettings and does not issue IOCTLs, so it can be called directly from the
    // UI thread. It must also be called from the UI thread because it displays a modal dialog.
    bool requestKvmWriteAccess(QWidget* parent);
}
