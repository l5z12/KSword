#include "KernelDockAtomWorker.h"

// ============================================================
// KernelDockAtomWorker.cpp
// Purpose:
// 1) Iterate through the global atom range [0xC000, 0xFFFF].
// 2) Output entries visible via GlobalGetAtomNameW / GetClipboardFormatNameW;
// 3) Provide a GlobalFindAtomW validation tool.
// ============================================================

#include "../Framework.h"

#include <algorithm> // std::sort: Sort by Atom value.
#include <array>     // std::array: Fixed stack buffer.
#include <vector>    // std::vector: Result container.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // Atom range constants:
    // - Windows string atoms typically reside in the 0xC000~0xFFFF range.
    constexpr unsigned int kAtomStartValue = 0xC000U;
    constexpr unsigned int kAtomEndValue = 0xFFFFU;

    // formatAtomHexText：
    // - Purpose: Format the atom value into a unified 0xXXXX text string.
    QString formatAtomHexText(const std::uint16_t atomValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(atomValue), 4, 16, QChar('0'))
            .toUpper();
    }
}

bool runAtomTableSnapshotTask(std::vector<KernelAtomEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    KLogEvent taskEvent;
    info << taskEvent << "[KernelDockAtomWorker] 开始遍历原子表。" << eol;

    std::vector<KernelAtomEntry> resultRows;
    resultRows.reserve(2048);

    for (unsigned int atomValueRaw = kAtomStartValue; atomValueRaw <= kAtomEndValue; ++atomValueRaw)
    {
        const ATOM kAtomValue = static_cast<ATOM>(atomValueRaw);

        std::array<wchar_t, 512> globalNameBuffer{};
        const UINT kGlobalNameLength = ::GlobalGetAtomNameW(
            kAtomValue,
            globalNameBuffer.data(),
            static_cast<int>(globalNameBuffer.size()));

        std::array<wchar_t, 512> clipboardNameBuffer{};
        const int kClipboardNameLength = ::GetClipboardFormatNameW(
            static_cast<UINT>(kAtomValue),
            clipboardNameBuffer.data(),
            static_cast<int>(clipboardNameBuffer.size()));

        if (kGlobalNameLength == 0 && kClipboardNameLength <= 0)
        {
            continue;
        }

        const QString kGlobalNameText = kGlobalNameLength > 0
            ? QString::fromWCharArray(globalNameBuffer.data(), static_cast<int>(kGlobalNameLength)).trimmed()
            : QString();

        const QString kClipboardNameText = kClipboardNameLength > 0
            ? QString::fromWCharArray(clipboardNameBuffer.data(), kClipboardNameLength).trimmed()
            : QString();

        KernelAtomEntry entry;
        entry.atomValue = static_cast<std::uint16_t>(kAtomValue);
        entry.atomNameText = !kGlobalNameText.isEmpty() ? kGlobalNameText : kClipboardNameText;
        entry.statusText = QStringLiteral("SUCCESS");
        entry.querySucceeded = true;

        if (!kGlobalNameText.isEmpty() && !kClipboardNameText.isEmpty())
        {
            entry.sourceText = QStringLiteral("GlobalGetAtomNameW + GetClipboardFormatNameW");
            if (QString::compare(kGlobalNameText, kClipboardNameText, Qt::CaseInsensitive) == 0)
            {
                entry.detailText = QStringLiteral(
                    "Atom值: %1 (%2)\n"
                    "名称: %3\n"
                    "来源: Global + ClipboardFormat（同名）")
                    .arg(entry.atomValue)
                    .arg(formatAtomHexText(entry.atomValue))
                    .arg(entry.atomNameText);
            }
            else
            {
                entry.detailText = QStringLiteral(
                    "Atom值: %1 (%2)\n"
                    "Global名称: %3\n"
                    "ClipboardFormat名称: %4\n"
                    "来源: Global + ClipboardFormat（名称不同）")
                    .arg(entry.atomValue)
                    .arg(formatAtomHexText(entry.atomValue))
                    .arg(kGlobalNameText)
                    .arg(kClipboardNameText);
            }
        }
        else if (!kGlobalNameText.isEmpty())
        {
            entry.sourceText = QStringLiteral("GlobalGetAtomNameW");
            entry.detailText = QStringLiteral(
                "Atom值: %1 (%2)\n"
                "名称: %3\n"
                "来源: GlobalGetAtomNameW")
                .arg(entry.atomValue)
                .arg(formatAtomHexText(entry.atomValue))
                .arg(entry.atomNameText);
        }
        else
        {
            entry.sourceText = QStringLiteral("GetClipboardFormatNameW");
            entry.detailText = QStringLiteral(
                "Atom值: %1 (%2)\n"
                "名称: %3\n"
                "来源: GetClipboardFormatNameW")
                .arg(entry.atomValue)
                .arg(formatAtomHexText(entry.atomValue))
                .arg(entry.atomNameText);
        }

        resultRows.push_back(std::move(entry));
    }

    std::sort(resultRows.begin(), resultRows.end(), [](const KernelAtomEntry& left, const KernelAtomEntry& right) {
        if (left.atomValue == right.atomValue)
        {
            return QString::compare(left.atomNameText, right.atomNameText, Qt::CaseInsensitive) < 0;
        }
        return left.atomValue < right.atomValue;
    });

    rowsOut = std::move(resultRows);

    info << taskEvent
        << "[KernelDockAtomWorker] 原子表遍历完成, count="
        << rowsOut.size()
        << eol;
    return true;
}

bool verifyGlobalAtomByName(
    const QString& atomNameText,
    std::uint16_t& atomValueOut,
    QString& detailTextOut)
{
    atomValueOut = 0;
    detailTextOut.clear();

    const QString kTrimmedAtomNameText = atomNameText.trimmed();
    if (kTrimmedAtomNameText.isEmpty())
    {
        detailTextOut = QStringLiteral("校验失败：原子名称为空。");
        return false;
    }

    const ATOM kFoundAtomValue = ::GlobalFindAtomW(reinterpret_cast<LPCWSTR>(kTrimmedAtomNameText.utf16()));
    if (kFoundAtomValue == 0)
    {
        detailTextOut = QStringLiteral(
            "GlobalFindAtomW 未命中。\n"
            "名称: %1")
            .arg(kTrimmedAtomNameText);
        return false;
    }

    atomValueOut = static_cast<std::uint16_t>(kFoundAtomValue);
    detailTextOut = QStringLiteral(
        "GlobalFindAtomW 命中。\n"
        "名称: %1\n"
        "Atom值: %2 (%3)")
        .arg(kTrimmedAtomNameText)
        .arg(atomValueOut)
        .arg(formatAtomHexText(atomValueOut));
    return true;
}
