#include "ServiceDock.Internal.h"

#include "../Theme.h"

#include <QPainter>
#include <QPixmap>

namespace service_dock_detail
{
    QIcon createBlueIcon(const char* resourcePath, const QSize& iconSize)
    {
        const QString kIconPath = QString::fromUtf8(resourcePath);
        QSvgRenderer renderer(kIconPath);
        if (!renderer.isValid())
        {
            return QIcon(kIconPath);
        }

        QPixmap pixmap(iconSize);
        pixmap.fill(Qt::transparent);

        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        renderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(pixmap.rect(), ksword_theme::primaryBlueColor);
        painter.end();

        return QIcon(pixmap);
    }

    QTableWidgetItem* createReadOnlyItem(const QString& textValue)
    {
        QTableWidgetItem* itemPointer = new QTableWidgetItem(textValue);
        itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
        itemPointer->setToolTip(textValue);
        return itemPointer;
    }

    QString winErrorText(const DWORD errorCode)
    {
        // ServiceDock keeps only QString presentation here:
        // - input: raw Win32 error code from UI-adjacent callers;
        // - processing: ks::service owns FormatMessageW and UTF-8 conversion;
        // - return: localized QString text for message boxes and logs.
        return QString::fromUtf8(ks::service::formatWin32ErrorText(errorCode).c_str());
    }

    QString serviceStateToText(const DWORD stateValue)
    {
        switch (stateValue)
        {
        case SERVICE_STOPPED:
            return QStringLiteral("已停止");
        case SERVICE_START_PENDING:
            return QStringLiteral("启动中");
        case SERVICE_STOP_PENDING:
            return QStringLiteral("停止中");
        case SERVICE_RUNNING:
            return QStringLiteral("运行中");
        case SERVICE_CONTINUE_PENDING:
            return QStringLiteral("继续中");
        case SERVICE_PAUSE_PENDING:
            return QStringLiteral("暂停中");
        case SERVICE_PAUSED:
            return QStringLiteral("已暂停");
        default:
            return QStringLiteral("未知");
        }
    }

    QString startTypeToText(const DWORD startTypeValue, const bool delayedAutoStart)
    {
        switch (startTypeValue)
        {
        case SERVICE_BOOT_START:
            return QStringLiteral("引导启动");
        case SERVICE_SYSTEM_START:
            return QStringLiteral("系统启动");
        case SERVICE_AUTO_START:
            return delayedAutoStart ? QStringLiteral("自动(延迟)") : QStringLiteral("自动");
        case SERVICE_DEMAND_START:
            return QStringLiteral("手动");
        case SERVICE_DISABLED:
            return QStringLiteral("禁用");
        default:
            return QStringLiteral("未知");
        }
    }

    QString serviceTypeToText(const DWORD serviceTypeValue)
    {
        QStringList segmentList;

        if ((serviceTypeValue & SERVICE_WIN32_OWN_PROCESS) != 0)
        {
            segmentList.push_back(QStringLiteral("Win32独立进程"));
        }
        if ((serviceTypeValue & SERVICE_WIN32_SHARE_PROCESS) != 0)
        {
            segmentList.push_back(QStringLiteral("Win32共享进程"));
        }
        if ((serviceTypeValue & SERVICE_KERNEL_DRIVER) != 0)
        {
            segmentList.push_back(QStringLiteral("内核驱动"));
        }
        if ((serviceTypeValue & SERVICE_FILE_SYSTEM_DRIVER) != 0)
        {
            segmentList.push_back(QStringLiteral("文件系统驱动"));
        }
        if ((serviceTypeValue & SERVICE_INTERACTIVE_PROCESS) != 0)
        {
            segmentList.push_back(QStringLiteral("可交互"));
        }

        if (segmentList.isEmpty())
        {
            return QStringLiteral("未知");
        }
        return segmentList.join(QStringLiteral(" | "));
    }

    QString errorControlToText(const DWORD errorControlValue)
    {
        switch (errorControlValue)
        {
        case SERVICE_ERROR_IGNORE:
            return QStringLiteral("忽略");
        case SERVICE_ERROR_NORMAL:
            return QStringLiteral("正常");
        case SERVICE_ERROR_SEVERE:
            return QStringLiteral("严重");
        case SERVICE_ERROR_CRITICAL:
            return QStringLiteral("关键");
        default:
            return QStringLiteral("未知");
        }
    }

    bool isServiceStatePending(const DWORD stateValue)
    {
        return stateValue == SERVICE_START_PENDING
            || stateValue == SERVICE_STOP_PENDING
            || stateValue == SERVICE_CONTINUE_PENDING
            || stateValue == SERVICE_PAUSE_PENDING;
    }

    QString normalizeServiceImagePath(const QString& rawBinaryPathText)
    {
        QString normalizedText = rawBinaryPathText.trimmed();
        if (normalizedText.isEmpty())
        {
            return QString();
        }

        // First, expand all environment variables in the entire command line; both drivers and Win32 services may place variables inside quotes.
        const std::wstring kRawTextWide = normalizedText.toStdWString();
        const DWORD kExpandedLength = ::ExpandEnvironmentStringsW(
            kRawTextWide.c_str(),
            nullptr,
            0);
        if (kExpandedLength > 0 && kExpandedLength < 32768)
        {
            std::vector<wchar_t> expandedBuffer(kExpandedLength + 1, L'\0');
            if (::ExpandEnvironmentStringsW(
                kRawTextWide.c_str(),
                expandedBuffer.data(),
                static_cast<DWORD>(expandedBuffer.size())) > 0)
            {
                normalizedText = QString::fromWCharArray(expandedBuffer.data()).trimmed();
            }
        }

        if (normalizedText.startsWith('"'))
        {
            const int kEndQuoteIndex = normalizedText.indexOf('"', 1);
            if (kEndQuoteIndex > 1)
            {
                normalizedText = normalizedText.mid(1, kEndQuoteIndex - 1);
            }
        }
        else
        {
            const QStringList kSuffixList{
                QStringLiteral(".exe"),
                QStringLiteral(".dll"),
                QStringLiteral(".sys")
            };
            bool suffixMatched = false;
            for (const QString& suffixText : kSuffixList)
            {
                const int kSuffixIndex = normalizedText.indexOf(
                    suffixText,
                    0,
                    Qt::CaseInsensitive);
                if (kSuffixIndex > 0)
                {
                    normalizedText = normalizedText.left(kSuffixIndex + suffixText.size());
                    suffixMatched = true;
                    break;
                }
            }
            if (!suffixMatched)
            {
                const int kFirstSpaceIndex = normalizedText.indexOf(QLatin1Char(' '));
                if (kFirstSpaceIndex > 0)
                {
                    normalizedText = normalizedText.left(kFirstSpaceIndex);
                }
            }
        }

        // Driver ImagePath commonly uses three kernel/relative formats; unify them into absolute paths usable by QFile/DeleteFileW.
        if (normalizedText.startsWith(QStringLiteral("\\??\\")))
        {
            normalizedText = normalizedText.mid(4);
        }
        else if (normalizedText.startsWith(QStringLiteral("\\\\?\\")))
        {
            normalizedText = normalizedText.mid(4);
        }

        const QString kSystemRootText = qEnvironmentVariable(
            "SystemRoot",
            QStringLiteral("C:\\Windows"));
        if (normalizedText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
        {
            normalizedText = kSystemRootText + normalizedText.mid(QStringLiteral("\\SystemRoot").size());
        }
        else if (normalizedText.startsWith(QStringLiteral("SystemRoot\\"), Qt::CaseInsensitive))
        {
            normalizedText = kSystemRootText + QLatin1Char('\\')
                + normalizedText.mid(QStringLiteral("SystemRoot\\").size());
        }
        else if (normalizedText.startsWith(QStringLiteral("System32\\"), Qt::CaseInsensitive))
        {
            normalizedText = kSystemRootText + QLatin1Char('\\') + normalizedText;
        }

        return QDir::cleanPath(QDir::toNativeSeparators(normalizedText));
    }
}
