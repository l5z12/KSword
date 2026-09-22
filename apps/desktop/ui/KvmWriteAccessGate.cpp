#include "KvmWriteAccessGate.h"

#include "KvmControl.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../internationalization/LanguageManager.h"

bool ks::ui::requestKvmWriteAccess(QWidget* const parent)
{
    // If already enabled, skip prompts: asking for confirmation to unlock a capability
    // class when it's already unlocked only teaches users to click confirm blindly.
    if (ksword::kvm::isWriteAccessEnabled())
    {
        return true;
    }

    // Opening write access unlocks a whole class of capabilities to modify system state; explicit confirmation is required.
    //
    // These four segments match the write-access toggle in the KVM menu's title bar verbatim; this is not a coincidence but a requirement.
    // suppressionKey determines the persistent entry for "Do not show again"; both locations must use the same key,
    // otherwise a user who checked the box in one dialog will be blocked again when accessing via a different entry point.
    const bool kConfirmed = ks::ui::confirmDestructiveAction(
        parent,
        QStringLiteral("KvmWriteAccess"),
        ks::i18n::sourceText(QStringLiteral("开启 KSwordVM 写权限")),
        ks::i18n::sourceText(QStringLiteral("本机物理内存与 EPT 映射")),
        ks::i18n::sourceText(QStringLiteral("开启后 KVM 的 R-1 改写能力（EPT 强制权限、隐蔽 Hook、内存隐藏、物理内存写入）将可用。这些操作绕过内核层保护，误用会直接损坏运行中的系统。")));
    ksword::kvm::setWriteAccessEnabled(kConfirmed);
    return kConfirmed;
}
